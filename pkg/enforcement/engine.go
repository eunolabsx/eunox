// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Package enforcement implements the capability enforcement engine that evaluates
// conditions against incoming requests and produces allow/deny decisions.
package enforcement

import (
	"context"
	"fmt"
	"path"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/eunolabs/eunox/pkg/capability"
)

// ConditionHandler evaluates a single condition against an enforcement request,
// returning nil if satisfied or a non-nil *ConditionError if not. It is an
// interface rather than a func type so stateful implementations (e.g. an OPA
// client with connection pooling) can carry their own state; use
// ConditionHandlerFunc to adapt a plain function.
type ConditionHandler interface {
	Handle(ctx context.Context, condition capability.Condition, req *capability.EnforceRequest) *ConditionError
}

// ConditionHandlerFunc adapts a plain function to [ConditionHandler].
type ConditionHandlerFunc func(ctx context.Context, condition capability.Condition, req *capability.EnforceRequest) *ConditionError

// Handle implements [ConditionHandler].
func (f ConditionHandlerFunc) Handle(ctx context.Context, condition capability.Condition, req *capability.EnforceRequest) *ConditionError {
	return f(ctx, condition, req)
}

// SubsystemDependent is the optional interface a [ConditionHandler] (or a [PolicyEvaluator])
// implements to declare which OPTIONAL engine facilities its enforcement reads or writes.
//
// The token type is only the same object as its handler for the built-ins:
// [WithConditionHandler] can replace ANY registered type, including one whose shipped
// handler touches nothing, so an override closing over a store the token's built-in never
// used needs a way to keep that facility wired.
//
// A handler that does NOT implement it is read from the built-in declaration it replaced, or
// is otherwise UNCLASSIFIED (depends on every subsystem) — the conservative default, so the
// interface is only ever needed to declare LESS. Declare capability.SubsystemNone (not an
// empty slice) to state a handler depends on nothing: "declared none" and "declared nothing"
// must not be the same statement.
type SubsystemDependent interface {
	UsesEngineSubsystems() []capability.EngineSubsystem
}

// registeredHandler is one entry in the condition-handler registry: the handler plus what the
// engine knows about which optional facilities it depends on. The declaration travels WITH
// the handler rather than in a parallel map, so replacing a handler for a type replaces its
// declaration in the same write.
//
// A type is either PURE or COMMITTING, never both: exactly one of the two handler fields is
// set. That is what makes "a committing condition has one entry point" structural — the
// committing shape has no Handle to be reached by, so there is no second implementation of
// its semantics to keep in agreement with the one the engine runs.
type registeredHandler struct {
	// pure is the handler for a condition that commits nothing; nil on a committing entry.
	pure ConditionHandler
	// committing is the handler for a condition that consumes quota on admit; nil on a pure
	// entry. Its presence is what defers the type to the atomic multi-condition commit.
	committing CommittingConditionHandler
	// uses is the declaration recorded at registration: the prototype registry's `Uses` for a
	// built-in, or nil for an override that declared nothing (UNCLASSIFIED). Not consulted
	// when the handler implements SubsystemDependent and answers for itself.
	uses []capability.EngineSubsystem
	// builtin records that this entry came from this build's own registry rather than from
	// WithConditionHandler, recorded at registration since a ConditionHandlerFunc is not
	// comparable — nothing downstream could otherwise tell a built-in from a replacement.
	builtin bool
}

// commits reports whether this entry's condition consumes quota on admit, which is exactly
// what defers it to the atomic multi-condition commit.
//
// isTypedNil: a nil POINTER boxed in the interface survives == nil and would panic the
// enforcement goroutine on PrepareCommit. Reporting it as "not committing" routes it to
// evalCondition's guard, which denies fail-closed on the nil pure handler it also has.
func (r registeredHandler) commits() bool {
	return r.committing != nil && !isTypedNil(r.committing)
}

// dependsOn reports whether this entry's handler depends on subsystem s. A handler that
// declares for itself wins over the recorded declaration unconditionally, even for a
// built-in — the two extension points use it to ask their evaluator rather than answer
// conservatively.
func (r registeredHandler) dependsOn(s capability.EngineSubsystem) bool {
	var handler interface{} = r.pure
	if r.commits() {
		handler = r.committing
	}
	// isTypedNil for commits' reason, on the arm that reaches a METHOD rather than a decision:
	// the assertion below succeeds for a typed nil (the itab belongs to the type, not the
	// value), so an unset handler would panic inside New. Falling through answers from the
	// recorded declaration, whose unclassified case is "depends on everything" — the
	// conservative direction, and the entry denies fail-closed at the request either way.
	if d, ok := handler.(SubsystemDependent); ok && !isTypedNil(d) {
		return capability.DeclarationUsesSubsystem(d.UsesEngineSubsystems(), s)
	}
	return capability.DeclarationUsesSubsystem(r.uses, s)
}

// DeferredCommit is one deferred (quota-consuming) condition's admission plan, derived
// WITHOUT yet consuming anything, so the engine can admit every such condition on a
// constraint in ONE atomic backend call. It carries the bucket rather than a flag the
// engine interprets, so nothing here requires the engine to know which CONDITION TYPE
// produced it — an earlier shape did, stamping one built-in's discriminator onto a refusal
// a third-party handler could equally have produced.
//
// Deny builds the denial for this bucket when it is the one that lacked headroom, given the
// observed total and the backend's retry-after hint.
type DeferredCommit struct {
	Bucket capability.QuotaBucket
	Deny   func(total float64, retryAfter time.Duration) *ConditionError
}

// Commits reports whether this prepared commit names a bucket at all. A handler whose
// condition commits only in SOME configurations (blastRadius, only with a cumulative
// bound) returns a zero DeferredCommit for the non-committing case, since deferral is keyed
// by condition TYPE and the per-call-only shape reaches PrepareCommit too.
func (d DeferredCommit) Commits() bool { return d.Bucket.Key != "" }

// CommittingConditionHandler evaluates a condition that commits state (consumes a quota slot)
// on admit, so it must run after all pure predicates and participate in the engine's atomic
// multi-condition commit instead of committing per-bucket (a check->commit TOCTOU across
// buckets).
//
// It deliberately does NOT embed [ConditionHandler]. PrepareCommit is the condition's WHOLE
// evaluation minus the commit — every pure check plus bucket derivation — and the engine
// defers every committing type, so a Handle on this interface could only ever be a second
// implementation of the same semantics that nothing runs and nothing can test through the
// engine. Register one of these with [WithCommittingConditionHandler].
//
// The engine skips the commit under observe mode ([WithSkipQuota]) but still runs
// PrepareCommit, which is why the pure checks belong there: an operator's observe run must
// predict what enforce mode decides, and a check living anywhere else would be skipped on
// exactly that run.
//
// The skip/commit contract, asserted in BOTH directions at the single site that consumes a
// PrepareCommit result. A handler breaking it is a plugin bug either way; what differs is
// whether the engine can repair it without inventing a verdict:
//
//   - Outside SkipQuota(ctx), skip MUST be false. The atomic commit treats a skip as skipping
//     the whole deferred set, so a handler skipping for its OWN reason (its config, its
//     arguments) fails the buckets it never checked open. Nothing can stand in for the
//     verdicts that never ran, so this direction is a HardDeny.
//   - Under SkipQuota(ctx), a handler MUST NOT return a bucket: it either reports skip, or
//     reports a zero DeferredCommit because this configuration consumes nothing (a per-call
//     only blastRadius). A bucket here is dropped and REPORTED rather than refused; the
//     reasoning lives on [capability.EnforceResponse.HandlerFaults].
//
// A condition type is "deferred" precisely when it was registered as committing, so an
// embedder's committing handler participates in the atomic commit automatically.
type CommittingConditionHandler interface {
	PrepareCommit(ctx context.Context, condition capability.Condition, req *capability.EnforceRequest) (commit DeferredCommit, skip bool, condErr *ConditionError)
}

// ConditionError describes a condition evaluation failure.
//
// HardDeny marks a failure that must block even under an audit-mode constraint, for the
// engine/plugin BUGS a policy verdict cannot be downgraded from — without it the shared
// error type could not express what the deferred path's own refusals already needed, so a
// refusal moved onto this type silently became forwardable.
type ConditionError struct {
	Code          string
	ConditionType string
	Message       string
	HardDeny      bool
	Details       map[string]interface{}
}

func (e *ConditionError) Error() string {
	return e.Message
}

// Clock provides the current time for condition evaluation. It is satisfied by
// a trivial fake in tests and by the system clock in production.
type Clock interface {
	Now() time.Time
}

// sequenceHistoryWindowSec bounds how long a session's per-tool call markers are retained
// for sequenceBlock lookups. This is a REAL bound on the guarantee, not just storage: it is
// wall-clock, so a session idle past the window loses its antecedent marker and a later
// blocked call is allowed. RecordSessionCall re-records on each fresh antecedent call and
// handleSequenceBlock re-arms on each blocked probe, so the window measures INACTIVITY of
// the pair rather than age since the antecedent — a multi-day-idle session still loses the
// gate (documented in docs/capability-manifest-guide.md).
const sequenceHistoryWindowSec = 86400 // 24h

// compositeCounterKey joins prefix and the variadic parts into one counter key,
// length-prefixing each part so it is injective for arbitrary byte content — no ":" or NUL a
// part contains can forge a different tuple's key. Delegates to capability.CompositeKey, the
// repo's one anti-forgery key encoding, under this counter-side name.
func compositeCounterKey(prefix string, parts ...string) string {
	return capability.CompositeKey(prefix, parts...)
}

// sequenceHistoryMaxEntries caps how many per-(session, tool) call markers the history
// retains. sequenceBlock only asks "did this tool run at least once?", so one marker
// suffices; more would grow the slice unboundedly for a one-bit question.
const sequenceHistoryMaxEntries = 1

// PolicyEvaluator evaluates a policy condition against an enforce request by calling an
// external policy decision point (e.g. OPA, Cedar). Return nil to allow, non-nil to deny.
//
// The input value MUST be treated as read-only: its nested claim objects may be shared by
// pointer across concurrent requests on the same token, so mutating input races other
// in-flight evaluations and can poison the cached claims for every later request.
type PolicyEvaluator interface {
	Evaluate(ctx context.Context, backend string, config, input interface{}, req *capability.EnforceRequest) *ConditionError
}

// Engine is the enforcement decision engine. It evaluates enforce requests
// against a set of capabilities and registered condition handlers.
type Engine struct {
	// handlers is the condition-handler registry. It is fully populated during
	// New (built-ins plus any WithConditionHandler options) and never written
	// again, so the hot path reads it concurrently without a lock.
	handlers        map[string]registeredHandler
	clock           Clock
	counter         capability.CallCounter
	policyEvaluator PolicyEvaluator

	// policyTokens is the set of condition/directive discriminators the policy this engine
	// will decide actually carries, as declared by WithPolicyTokens, and policyTokensKnown
	// records whether it was declared AT ALL — the two are not the same statement. An empty
	// set means "this policy carries no tokens", which skips both optional subsystems; an
	// undeclared one means the engine knows nothing about the policy and wires everything.
	// Read once in New to derive the two skips, never on the hot path.
	policyTokens      map[string]struct{}
	policyTokensKnown bool

	// flowStore holds per-session information-flow-control label state, a seam distinct
	// from counter because provenance is a monotonic session-lifetime SET, not a decaying
	// sliding-window count. nil fails a flowLabel/labelOutput constraint closed. See
	// pkg/flowlabelstore.
	flowStore capability.FlowLabelStore

	// skipAntecedentRecording is set when nothing on this engine reads the antecedent
	// history, sparing the counter round-trip and — more importantly — the
	// RecordSessionCall fail-closed deny path a counter-write fault would otherwise trigger
	// for a marker nothing reads. DERIVED in New, never set by a caller; see WithPolicyTokens.
	skipAntecedentRecording bool

	// skipFlow mirrors skipAntecedentRecording for the flow-label set: spares a non-flow
	// policy the per-call scan and the recordLabels fail-closed deny path.
	skipFlow bool

	// effectCeiling is the policy's tool-agnostic consequence bound, applied to EVERY
	// allowed action (see checkEffectCeiling). Engine-level rather than per-constraint on
	// purpose: it catches the target nobody wrote a gate for, including an unannotated one
	// (which resolves to irreversible). nil skips the check entirely.
	effectCeiling *capability.EffectCeiling

	// counterKeyNamespace is folded into every maxCalls/sequenceBlock counter key. The
	// binary wires each route's name here so every route addresses a disjoint counter
	// namespace even when they share one CallCounter — a fail-closed backstop against a
	// session-id collision or cross-route binding regression, not resting solely on the
	// transport keeping session IDs per-route unique.
	counterKeyNamespace string

	// taskAnchored keys accumulated state (flow labels, sequenceBlock antecedents, maxCalls
	// and cumulative blastRadius budgets — NOT the single-use declassify ledger, which is
	// deliberately un-anchored) on the request's VALIDATED mcp.task_id claim instead of its
	// session, so state survives a hop across enforcement points. Opt-in and fail-safe: a
	// request with no token falls back to session keying; an authenticated one with no
	// task_id is refused rather than split across both. See anchor.go.
	taskAnchored bool
}

// Option configures the Engine.
type Option func(*Engine)

// WithClock sets a custom clock for time-based condition evaluation.
func WithClock(clock Clock) Option {
	return func(e *Engine) {
		e.clock = clock
	}
}

// Clock returns the engine's clock so callers that build deny responses outside
// the engine (the ManifestPDP hand-built deny paths) can stamp DecidedAt from the
// same source — a frozen test clock is then honored on every deny path.
func (e *Engine) Clock() Clock {
	return e.clock
}

// WithCallCounter sets the call counter backend for maxCalls evaluation.
func WithCallCounter(counter capability.CallCounter) Option {
	return func(e *Engine) {
		e.counter = counter
	}
}

// WithFlowLabelStore sets the session-scoped flow-label store backing information-flow
// control. Distinct from the CallCounter, since provenance is a monotonic per-session set,
// not a decaying sliding-window count. Leave unset only for a policy known to carry no flow
// control (see WithPolicyTokens); a flow constraint with no store wired fails closed.
func WithFlowLabelStore(store capability.FlowLabelStore) Option {
	return func(e *Engine) {
		e.flowStore = store
	}
}

// WithPolicyTokens declares which condition and directive discriminators the policy this
// engine will decide actually carries. The engine intersects them with its own handler
// registry to decide which optional subsystems to wire, so a facility is skipped only when
// nothing that can run reads it — a decision the engine must make, not the caller, since
// WithConditionHandler can replace a type's handler with one that reads a store the token's
// shipped handler never touched. See SubsystemDependent.
//
// Not calling it at all wires every subsystem (the fail-closed default). Calling it with an
// empty set is the distinct statement that the policy carries no tokens. A token this build
// has no handler for is UNCLASSIFIED and depends on everything.
func WithPolicyTokens(tokens []string) Option {
	return func(e *Engine) {
		e.policyTokens = make(map[string]struct{}, len(tokens))
		for _, t := range tokens {
			e.policyTokens[t] = struct{}{}
		}
		e.policyTokensKnown = true
	}
}

// WithCounterKeyNamespace sets a namespace folded into every maxCalls/sequenceBlock
// counter key, so engines sharing one CallCounter (gateway routes) address disjoint
// buckets. Set to a value unique per route so a session-id collision cannot drain or
// interfere with another route's quota. Leave unset in single-upstream mode.
func WithCounterKeyNamespace(ns string) Option {
	return func(e *Engine) {
		e.counterKeyNamespace = ns
	}
}

// WithTaskAnchoredState keys accumulated enforcement state on the request's VALIDATED
// mcp.task_id claim instead of on its session, so taint, sequenceBlock antecedents, and
// quota/blast-radius budgets survive a hop across enforcement points (a delegated
// sub-agent, or the same task re-entering through a fresh session).
//
// The single-use declassify ledger is NOT among them: it is keyed on the grant alone, since
// a per-anchor ledger would make "approve clearing this once" mean once per task.
//
// Changes what every budget MEANS (maxCalls: 20 becomes 20 per task, not per connection), so
// it is opt-in. An unauthenticated request still anchors on its session; an authenticated
// request with no task_id is REFUSED rather than session-keyed, since one caller alternating
// token shapes would otherwise split its own state across two buckets.
//
// Task-anchored state deliberately OUTLIVES the session that wrote it. Pair this with the
// Redis backends' idle TTL, or bound the in-memory store with flowlabelstore.WithMaxKeys.
func WithTaskAnchoredState() Option {
	return func(e *Engine) {
		e.taskAnchored = true
	}
}

// WithEffectCeiling sets the policy's tool-agnostic consequence bound, checked on every
// allow after the matched constraint's conditions have passed. Leave it unset for a
// policy that declares no ceiling (see config.LocalManifest.HasEffectCeiling): the
// ceiling can only ever narrow, so an absent one changes nothing, and an unset one skips
// the check entirely.
func WithEffectCeiling(ceiling *capability.EffectCeiling) Option {
	return func(e *Engine) {
		e.effectCeiling = ceiling
	}
}

// WithPolicyEvaluator sets the evaluator used to resolve policy conditions.
// When no evaluator is configured, any capability that contains a policy
// condition is denied (fail-closed). Set this option to connect the engine to
// an external policy decision point such as OPA or Cedar.
func WithPolicyEvaluator(pe PolicyEvaluator) Option {
	return func(e *Engine) {
		e.policyEvaluator = pe
	}
}

// ctxRequestIDKey is the unexported context key for the per-request ID.
type ctxRequestIDKey struct{}

// RequestIDFromContext retrieves the request ID stored in ctx by the
// enforcement engine. Returns an empty string when none is set.
// PolicyEvaluator implementations should include this in input.context.request_id.
func RequestIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(ctxRequestIDKey{}).(string)
	return id
}

// ctxTimestampKey is the unexported context key for the per-request timestamp.
type ctxTimestampKey struct{}

// TimestampFromContext retrieves the request timestamp stored in ctx by the
// engine — the same instant (RFC3339Nano, UTC) stamped on DecidedAt. Returns ""
// when none is set. PolicyEvaluator implementations should surface it as
// input.context.timestamp so time-based Rego rules see the real request time.
func TimestampFromContext(ctx context.Context) string {
	ts, _ := ctx.Value(ctxTimestampKey{}).(string)
	return ts
}

// ctxDirectivesKey is the unexported context key carrying the matched
// constraint's directives.
type ctxDirectivesKey struct{}

// withDirectives returns a context carrying the matched constraint's directives
// so BuildRegoInput can expose them as input.directives without the engine
// mutating the caller's EnforceRequest.
func withDirectives(ctx context.Context, dirs []capability.Directive) context.Context {
	return context.WithValue(ctx, ctxDirectivesKey{}, dirs)
}

// directivesFromContext returns the directives threaded by withDirectives. The
// boolean is false only when withDirectives was never called (a direct
// BuildRegoInput caller), in which case the caller falls back to req.Directives.
func directivesFromContext(ctx context.Context) ([]capability.Directive, bool) {
	dirs, ok := ctx.Value(ctxDirectivesKey{}).([]capability.Directive)
	return dirs, ok
}

// ctxCarriedLabelsKey carries the session's accumulated flow-label set that
// evaluateMatched peeked for this decision, so handleFlowLabel reads the same snapshot
// instead of Peeking the vocabulary a second time.
type ctxCarriedLabelsKey struct{}

// withCarriedLabels threads the already-peeked accumulated flow-label set (which may be
// nil for a clean session) so a flowLabel sink reuses it. The value is stored even when
// nil so carriedLabelsFromContext can distinguish "threaded, empty set" (ok=true) from
// "never threaded" (ok=false, a direct handler caller that must Peek itself).
func withCarriedLabels(ctx context.Context, labels []string) context.Context {
	return context.WithValue(ctx, ctxCarriedLabelsKey{}, labels)
}

// carriedLabelsFromContext returns the threaded accumulated set and whether one was
// threaded at all.
func carriedLabelsFromContext(ctx context.Context) ([]string, bool) {
	labels, ok := ctx.Value(ctxCarriedLabelsKey{}).([]string)
	return labels, ok
}

// ctxSkipQuotaKey is the unexported context key used by WithSkipQuota.
type ctxSkipQuotaKey struct{}

// WithSkipQuota returns a context that signals the engine to skip ONLY the
// quota-consuming MaxCalls side effect, leaving every other condition — notably
// sequenceBlock — fully evaluated and RecordSessionCall recording as normal.
//
// This is the proxy's --audit (observe) mode flag: it forwards every request and
// logs the would-be decision, so it must not consume MaxCalls quota, but it must
// still observe sequenceBlock denials accurately, which requires evaluating the
// condition and recording the history that arms it. MaxCalls observation in audit
// mode is intentionally inexact (skipped), since observing it accurately would
// consume the quota it is meant to leave untouched.
func WithSkipQuota(ctx context.Context) context.Context {
	return context.WithValue(ctx, ctxSkipQuotaKey{}, true)
}

// SkipQuota reports whether ctx carries the proxy's --audit (observe) posture set by
// WithSkipQuota. Exported so the PDP's audit-mode antecedent recorder can gate on the
// SAME route-level observe signal the transport's downgrade uses: a route running under
// --audit forwards a would-be deny, so that call's sequenceBlock antecedent must still be
// recorded — otherwise a later enforced sequenceBlock Peeks empty history and fails open.
// Covers the whole-route case; per-constraint enforcement:audit is Constraint.IsAuditOnly().
func SkipQuota(ctx context.Context) bool {
	v, _ := ctx.Value(ctxSkipQuotaKey{}).(bool)
	return v
}

// WillForwardDeny reports whether a deny for this constraint will be downgraded to a
// forwarded call rather than blocking. The ONE spelling of the observe-mode union
// (per-constraint `enforcement: audit` OR whole-route --audit) that every layer reads, so
// three call sites cannot drift into three slightly different answers where the narrowest
// one silently forwards unredacted.
//
// It is also the ONE statement of the fact every [ConditionError.HardDeny] in this package is
// justified by, so no site re-derives it: where this answers yes, the transport delivers the
// call to the upstream and records the verdict instead of blocking. Two verdicts are exempt
// there and neither is expressible here — a HardDeny, and a kill-switch denial (which carries
// no HardDeny and is recognized by its CODE) — so this reports the POSTURE and the transport
// owns the exemptions. That half is pinned by a test there
// (TestObserveDowngrade_EngineVerdictsFollowWillForwardDeny) rather than only asserted here:
// a comment justifying a hard deny by a fact nothing checks becomes false silently.
//
// matched may be nil (a no-match deny), which only a route-level --audit forwards.
func WillForwardDeny(ctx context.Context, matched *capability.Constraint) bool {
	if matched != nil && matched.IsAuditOnly() {
		return true
	}
	return SkipQuota(ctx)
}

// systemClock is the default Clock backed by the real system time.
type systemClock struct{}

// Now returns the current system time.
func (systemClock) Now() time.Time { return time.Now() }

// New creates a new enforcement Engine with all built-in condition handlers registered.
func New(opts ...Option) *Engine {
	e := &Engine{
		handlers: make(map[string]registeredHandler),
		clock:    systemClock{},
	}
	// Register built-ins first so a WithConditionHandler option can override one. The map
	// is fully populated here and never mutated, so Decide reads it lock-free.
	e.registerBuiltins()
	for _, opt := range opts {
		opt(e)
	}
	e.deriveSubsystemSkips()
	return e
}

// deriveSubsystemSkips decides which optional facilities this engine wires, by asking the
// REGISTRY what the policy's tokens will actually run. Runs after every option so the
// handler registry is final and the answer is a derived property of the fully-built engine.
//
// Both skips are OPTIMIZATIONS, never authority: over-wiring costs work per call, while
// under-wiring runs a handler against a facility nothing populates. Every uncertain path —
// an undeclared policy, an unhandled token, a handler declaring nothing — resolves to "wired".
func (e *Engine) deriveSubsystemSkips() {
	e.skipAntecedentRecording = !e.policyUses(capability.SubsystemAntecedentHistory)
	e.skipFlow = !e.policyUses(capability.SubsystemFlowLabels)
}

// policyUses reports whether anything this engine will run depends on subsystem s.
// Directives are covered by the token declaration alone (no registration seam to override
// them); conditions go through the registry, since the same token can name a different
// handler there.
func (e *Engine) policyUses(s capability.EngineSubsystem) bool {
	if !e.policyTokensKnown {
		return true
	}
	for token := range e.policyTokens {
		if h, ok := e.handlers[token]; ok {
			if h.dependsOn(s) {
				return true
			}
			continue
		}
		// A directive discriminator, or a token this build does not model; both answer from
		// capability's own declaration.
		if capability.TokenUsesEngineSubsystem(token, s) {
			return true
		}
	}
	return false
}

// RecordSessionCall notes that an allowed call to req.TargetName occurred in this session,
// so a later sequenceBlock condition on a different tool can detect it.
//
// A non-nil error means the counter write itself failed, and callers MUST treat that as a
// fail-closed deny: a missing marker would let a later sequenceBlock Peek fail OPEN.
//
// Recording is indiscriminate among the policy's targets (EvaluateConditions sees only the
// matched constraint, so it cannot bound recording to known antecedents), so a write fault
// denies every allowed call in the session while the backend faults. The one bound applied
// is policy-wide: with NO sequenceBlock at all (skipAntecedentRecording), recording is
// skipped entirely, which also keeps a maxCalls-only policy from burning an already-committed
// slot on a record-fault deny.
//
// Exported for callers that must record an antecedent on a path EvaluateConditions does not
// reach: in audit (observe) mode a constraint with a failing condition returns a deny
// without recording, yet the transport still forwards the request and the tool runs.
func (e *Engine) RecordSessionCall(ctx context.Context, req *capability.EnforceRequest) error {
	if e.skipAntecedentRecording || e.counter == nil || req.SessionID == "" {
		return nil
	}
	// Prefer the explicit target type set by every ManifestPDP entry point; the
	// prefix-derived type is only a fallback for direct ValidateAction callers that leave
	// req.Target nil. sessionTargetKey derives the same (type, name) pair maxCallsBucket
	// keys on.
	targetType, tool := sessionTargetKey(req)
	if tool == "" {
		return nil
	}
	// Record a secondary marker keyed the way handleSequenceBlock parses a bare afterTools
	// spelling, so a target whose NAME itself begins with a recognized namespace token
	// still trips the gate when referenced naturally: a tool literally named "system:foo"
	// would otherwise NEVER match the bare "system:foo" afterTools spelling — a silent
	// fail-OPEN. Skipped when the name carries no recognized prefix. Both keys are
	// sequenceBlock history only; neither touches a maxCalls bucket.
	//
	// The secondary (bare-spelling) marker is written BEFORE the primary verbatim marker,
	// so a partial write (the two are separate, non-atomic backend calls on every backend)
	// leaves at most the alias key, never the canonical one the explicit afterTools
	// spelling resolves to — this NARROWS the partial-write fail-open rather than closing
	// it fully (a surviving alias can still arm a bare spelling for a denied antecedent).
	//
	// Cross-namespace false-trip caveat: the alias key discards the target's REAL type (the
	// same collapse the bare-spelling lookup performs), so a resource "tool:reboot" and a
	// tool "reboot" write the same alias and either can arm a bare afterTools spelling.
	// Conservative direction (spurious deny, never fail-OPEN); disambiguate by naming the
	// antecedent with its explicit, fully-qualified spelling.
	if altType, altName := splitEnginePrefix(tool); altName != tool {
		if _, err := e.counter.IncrementAndGet(ctx, e.sequenceHistoryKey(req, altType, altName), sequenceHistoryWindowSec, sequenceHistoryMaxEntries); err != nil {
			return err
		}
	}
	if _, err := e.counter.IncrementAndGet(ctx, e.sequenceHistoryKey(req, targetType, tool), sequenceHistoryWindowSec, sequenceHistoryMaxEntries); err != nil {
		return err
	}
	return nil
}

// sessionTargetName derives the bare target name used as the identity component of
// sequenceBlock-history and maxCalls bucket keys. When req.Target is set, Target.Name is
// used VERBATIM (trimmed, never prefix-stripped): a target whose name itself begins with a
// recognized namespace token (a resource "system:foo") must keep that token here, or it
// silently fails the sequenceBlock gate OPEN and collapses two distinct targets onto one
// maxCalls bucket. Falls back to the prefix-stripped req.TargetName when req.Target is nil.
//
// RecordSessionCall additionally writes a secondary marker keyed the bare/natural way, so
// both spellings resolve; that marker is confined to sequenceBlock history, so this
// verbatim recording remains authoritative for maxCalls.
func sessionTargetName(req *capability.EnforceRequest) string {
	if req.Target != nil {
		if n := strings.TrimSpace(req.Target.Name); n != "" {
			return n
		}
	}
	return strings.TrimSpace(StripEnginePrefix(req.TargetName))
}

// sessionTargetKey derives the (targetType, name) pair that identifies a target in both
// the sequenceBlock-history and maxCalls counter buckets. RecordSessionCall and
// maxCallsBucket both key through it so they land on the SAME bucket under the SAME
// derivation. handleSequenceBlock deliberately does NOT use this: it keeps a display-name
// fallback that reports "(unknown)" for an unnamed blocked target.
func sessionTargetKey(req *capability.EnforceRequest) (targetType, name string) {
	targetType, _ = splitEnginePrefix(req.TargetName)
	if req.Target != nil && req.Target.Type != "" {
		targetType = req.Target.Type
	}
	return targetType, sessionTargetName(req)
}

// recordFailureDenial builds the fail-closed response returned when RecordSessionCall
// cannot persist a marker. Attributed to sequenceBlock (the only feature the marker
// backs), with a Details "phase":"record" marker distinguishing it from an actual hit.
// auditOnly logs-and-forwards a transient recording failure under an audit-mode
// constraint (an infrastructure fault, not a policy verdict). obligations MUST be
// preserved: dropping them on a forwarded audit-mode response would leak fields the
// manifest marked for redaction.
func recordFailureDenial(requestID, now string, auditOnly bool, obligations []capability.Obligation) capability.EnforceResponse {
	return denyResponse(requestID, now, auditOnly, obligations, capability.DenialInfo{
		Code:          capability.ErrCodeConditionFailed,
		ConditionType: capability.ConditionTypeSequenceBlock,
		Message:       "session history recording failed; sequenceBlock state is unreliable",
		Details:       map[string]interface{}{"phase": "record"},
	})
}

// denyResponse builds a deny EnforceResponse from the shared envelope, the single shape
// for a blocking or audit-mode denial. Every deny path routes through it, so auditing a
// new top-level EnforceResponse field means checking this one constructor, not every
// deny site.
func denyResponse(requestID, now string, auditOnly bool, obligations []capability.Obligation, denial capability.DenialInfo) capability.EnforceResponse {
	// Every deny passes through here, so this is the one place that can bound the
	// caller-controlled values condition handlers echo, without asking each handler's
	// Details literal to remember. See BoundDenialDetails.
	denial.Details = BoundDenialDetails(denial.Details)
	return capability.EnforceResponse{
		RequestID:   requestID,
		Decision:    capability.DecisionDeny,
		AuditOnly:   auditOnly,
		Obligations: obligations,
		DecidedAt:   now,
		Denial:      &denial,
	}
}

// escalateResponse builds an escalate EnforceResponse — the effect ceiling's
// needs-human-approval outcome — from the same BoundDenialDetails-bound envelope
// denyResponse builds, so the escalate decision is not the one refusal shape exempt from it.
//
// AuditOnly and Obligations are deliberately absent: an escalation is not a policy verdict
// being staged (unlike a DENY, which an audit-mode constraint may downgrade to a forward),
// it is "a human has not approved this yet" — forwarding it would perform exactly the
// consequential action the ceiling flagged. Leaving AuditOnly unset keeps it unforwardable.
func escalateResponse(requestID, now string, denial capability.DenialInfo) capability.EnforceResponse {
	denial.Details = BoundDenialDetails(denial.Details)
	return capability.EnforceResponse{
		RequestID: requestID,
		Decision:  capability.DecisionEscalate,
		DecidedAt: now,
		Denial:    &denial,
	}
}

// WithConditionHandler registers a custom PURE condition handler under name. Applied after
// the built-ins (see New), it overwrites one of the same type whichever shape that one had.
// The map is frozen by the time New returns, so the engine reads it lock-free on the hot path.
//
// A handler that COMMITS state on admit belongs in [WithCommittingConditionHandler]. One that
// carries PrepareCommit is registered as committing wherever it is passed, including here, so
// an embedder cannot lose deferral by reaching for the wrong option — and cannot force the
// pure shape on a type that has both. What no registration can detect is a handler that
// consumes quota inside Handle without a PrepareCommit: that one is treated as a pure
// predicate and burns its slot on a call a later condition then denies.
//
// An override is UNCLASSIFIED for the optional-subsystem gates unless it implements
// [SubsystemDependent]: the built-in's declaration is not evidence about a replacement.
func WithConditionHandler(name string, handler ConditionHandler) Option {
	return func(e *Engine) {
		if ch, commits := handler.(CommittingConditionHandler); commits {
			e.registerCommitting(name, ch, nil, false)
			return
		}
		e.registerPure(name, handler, nil, false)
	}
}

// WithCommittingConditionHandler registers a custom handler for a condition that consumes
// quota on admit (see [CommittingConditionHandler]), so it runs after every pure predicate and
// commits through the engine's atomic multi-condition admission.
//
// Separate from [WithConditionHandler] because the two shapes are separate: a committing
// handler has exactly one entry point, and there is no Handle for the engine to call or for a
// reader to mistake for the path that runs.
func WithCommittingConditionHandler(name string, handler CommittingConditionHandler) Option {
	return func(e *Engine) {
		e.registerCommitting(name, handler, nil, false)
	}
}

// registerPure and registerCommitting are the ONLY writes to the registry. Two funnels rather
// than one taking a whole entry: each sets exactly one handler field, so "an entry holds one
// shape, never both, never neither" is a property of the writes rather than an invariant three
// readers have to defend.
func (e *Engine) registerPure(name string, handler ConditionHandler, uses []capability.EngineSubsystem, builtin bool) {
	e.handlers[name] = registeredHandler{pure: handler, uses: uses, builtin: builtin}
}

func (e *Engine) registerCommitting(name string, handler CommittingConditionHandler, uses []capability.EngineSubsystem, builtin bool) {
	e.handlers[name] = registeredHandler{committing: handler, uses: uses, builtin: builtin}
}

// ConditionHandlerOverridden reports whether the handler this engine dispatches for condType
// came from [WithConditionHandler] rather than from this build's own registry.
//
// It exists for a composing layer that CANNOT route through the override and must refuse
// rather than diverge — e.g. the JWT `op=` shorthand, which has no way to NAME the operation
// argument and so cannot dispatch through the engine's own hard-deny-on-empty-argument
// handler. Such a layer asks whether an override exists and fails closed if it does, loudly
// at startup and again at the request.
//
// A nil engine has overridden nothing (an embedder legitimately holds an unwired *Engine),
// and neither has a type nothing registered.
func (e *Engine) ConditionHandlerOverridden(condType string) bool {
	if e == nil {
		return false
	}
	h, ok := e.handlers[condType]
	return ok && !h.builtin
}

// registerBuiltin installs one of this build's own pure handlers, taking its subsystem
// declaration from the token's prototype-registry entry — the entry every condition and
// directive discriminator must declare (see capability/subsystem.go), and which describes
// exactly the handler being registered here.
func (e *Engine) registerBuiltin(name string, handler ConditionHandler) {
	e.registerPure(name, handler, builtinUses(name), true)
}

// registerBuiltinCommitting is registerBuiltin for one of this build's own quota-consuming
// handlers.
func (e *Engine) registerBuiltinCommitting(name string, handler CommittingConditionHandler) {
	e.registerCommitting(name, handler, builtinUses(name), true)
}

// builtinUses reads a built-in's subsystem declaration off the token's prototype-registry
// entry. A missing or malformed one resolves to nil, which dependsOn reads as "depends on
// everything" — the conservative direction.
func builtinUses(name string) []capability.EngineSubsystem {
	uses, _ := capability.TokenEngineSubsystems(name)
	return uses
}

// deferredCondition is a condition the first pass resolved and set aside for the atomic commit,
// carrying what that resolution produced. The commit pass therefore asks the registry nothing:
// re-resolving there was a second map lookup and a second ConditionType call per quota-carrying
// condition per request, and it needed a fail-closed guard for a registry that cannot change
// (New populates it and never writes again) — a branch no test could reach.
type deferredCondition struct {
	cond     capability.Condition
	condType string
	handler  CommittingConditionHandler
}

// runPureConditions evaluates every PURE (non-committing) condition on matched in order
// and returns the deferred (quota-consuming) ones for the caller to commit later. Returns
// a non-nil deny response on the first condition with an unknown type or a Handle failure
// (fail closed). Extracted so ValidateAction and EvaluateConditions share one dispatch
// path and cannot diverge.
func (e *Engine) runPureConditions(ctx context.Context, req *capability.EnforceRequest, matched *capability.Constraint, requestID, now string) ([]deferredCondition, *capability.EnforceResponse) {
	// Two passes over matched.Conditions so a consuming condition never burns its quota for
	// a call a later condition denies: this first pass evaluates every pure-predicate
	// condition immediately while collecting each deferred (consuming) one into deferred
	// for the second pass to commit, so a pure predicate that denies is always checked first.
	//
	// One residual case escapes this guarantee: RecordSessionCall runs AFTER this (it must,
	// so an antecedent marker is not written for a call CollectObligations may still
	// hard-deny), and on a counter-write fault it denies a call whose maxCalls slot was
	// already committed here, not rolled back. Bounded to policies using sequenceBlock —
	// with none, RecordSessionCall is skipped entirely (skipAntecedentRecording).
	var deferred []deferredCondition
	for _, cond := range matched.Conditions {
		// Defense in depth: a null condition is rejected at manifest load, so a nil here
		// means a programmatically built constraint. Fail closed rather than panic in
		// ConditionType() — a typed-nil pointer survives `cond == nil` as a non-nil
		// interface but panics a value/pointer-receiver method, the same guard
		// CollectObligations applies to directives.
		if cond == nil || isTypedNil(cond) {
			resp := denyResponse(requestID, now, matched.IsAuditOnly(), nil, capability.DenialInfo{
				Code: capability.ErrCodeConditionFailed,
				// HardDeny, like the deferred pass's unauthorized-skip refusal: an unevaluable
				// condition leaves a declared restriction unchecked, and the flag is what blocks
				// it on the postures WillForwardDeny answers yes for, which reach this too.
				HardDeny: true,
				Message:  "constraint carries a null condition that cannot be evaluated",
			})
			return nil, &resp
		}
		// ONE registry lookup (and one ConditionType call) per condition, its result handed to
		// evalCondition: resolving the entry here to ask whether the type defers and resolving
		// it again to run it charged every pure condition on the constraint a second
		// string-keyed lookup and a second interface call, per request, for values already in
		// hand. The two fail-closed shapes stay distinct — an unknown TYPE here, an entry with
		// no usable pure handler inside evalCondition — since a merged lookup must not merge
		// them into one ambiguous cause.
		condType := cond.ConditionType()
		handler, known := e.handlers[condType]
		switch {
		case !known:
			// Fail closed on unknown condition types.
			resp := denyResponse(requestID, now, matched.IsAuditOnly(), nil, capability.DenialInfo{
				Code:          capability.ErrCodeConditionFailed,
				ConditionType: condType,
				Message:       fmt.Sprintf("unknown condition type: %s", condType),
			})
			return nil, &resp
		case handler.commits():
			deferred = append(deferred, deferredCondition{cond: cond, condType: condType, handler: handler.committing})
		default:
			if deny := e.evalCondition(ctx, cond, condType, handler.pure, req, matched, requestID, now); deny != nil {
				return nil, deny
			}
		}
	}

	return deferred, nil
}

// isTypedNil reports whether v is a non-nil interface value wrapping a nil pointer, which
// survives a plain `v == nil` check but would panic a value/pointer-receiver method that
// dereferences it. Delegates to capability.IsTypedNil, shared by runPureConditions'
// condition check, CollectObligations' directive check, and the config-loader guards.
func isTypedNil(v interface{}) bool {
	return capability.IsTypedNil(v)
}

// commitDeferredConditions runs the SECOND pass: prepares every deferred condition — running
// its pure checks — and admits the resulting buckets in ONE atomic backend call. Reached
// only after every check that can refuse the call without state has passed, so nothing here
// is charged to a call that is then refused.
//
// One path for one and for many, and now the ONLY one: a committing handler has no Handle to
// commit through, so this is the single place a PrepareCommit result is consumed and the
// single place its contract is enforced.
//
// The two halves of that contract are answered differently because only one is repairable
// here: an unauthorized skip leaves the rest of the deferred set unevaluated and denies, while
// a bucket derived under SkipQuota is dropped and named in faults (see
// [capability.EnforceResponse.HandlerFaults]). faults rides EVERY exit, since a fault is a
// fact about the decision rather than about its verdict.
//
// Buckets may MIX accountings (a maxCalls count beside a cumulative blastRadius magnitude)
// since the backend admits them together; the engine has no compatibility table to maintain.
func (e *Engine) commitDeferredConditions(ctx context.Context, req *capability.EnforceRequest, matched *capability.Constraint, deferred []deferredCondition, requestID, now string) (faults []string, deny *capability.EnforceResponse) {
	var (
		buckets []capability.QuotaBucket
		denies  []func(total float64, retryAfter time.Duration) *ConditionError
		// bucketTypes[i] is the condition type that produced buckets[i], kept so a fault
		// spanning the WHOLE commit can still be attributed when every bucket came from one
		// condition type (see attributableType).
		bucketTypes []string
	)
	// skipQuota is loop-invariant: read once rather than per condition, on a path every
	// quota-carrying policy takes.
	skipQuota := SkipQuota(ctx)
	for _, d := range deferred {
		condType := d.condType
		commit, skip, condErr := d.handler.PrepareCommit(ctx, d.cond, req)
		// condErr is checked BEFORE skip is honored: a handler may legitimately report
		// both, and honoring skip first would discard the verdict, letting every condition
		// skipping ALLOW under observe where enforce denies.
		if condErr != nil {
			return faults, denyFromConditionError(condErr, matched, requestID, now)
		}
		// The skip/commit contract, asserted in both directions HERE because this is the only
		// place a PrepareCommit result is consumed.
		if skip {
			if !skipQuota {
				// A handler skipping for its OWN reason (config, arguments) leaves the remaining
				// committing conditions unchecked while the whole set reads as skipped: a
				// fail-open. Nothing here can repair that — a skipped condition produced no
				// verdict to stand in for — so this half denies where its mirror below absorbs.
				return faults, denyFromConditionError(unauthorizedSkipError(condType), matched, requestID, now)
			}
			// An authorized skip consumes nothing whatever the handler also prepared, so honor it
			// before inspecting the commit: a handler reporting both is stating the outcome this
			// posture requires, not violating the contract's other half.
			continue
		}
		if !commit.Commits() {
			// This particular condition consumes nothing — its configuration has no cumulative
			// bound. Its pure checks ran inside PrepareCommit and passed, so there is no bucket.
			continue
		}
		if skipQuota {
			// The absorbed half of the contract; see [capability.EnforceResponse.HandlerFaults]
			// for why dropping the bucket is the repair rather than the tolerance.
			//
			// The loop still prepares EVERY remaining condition: a later one's condErr is a real
			// verdict and must win over this report, or an observe run would allow where enforce
			// denies. Deduped by type, since the report names the misbehaving handler and a
			// constraint may carry it twice.
			if !slices.Contains(faults, condType) {
				faults = append(faults, condType)
			}
			continue
		}
		buckets = append(buckets, commit.Bucket)
		denies = append(denies, commit.Deny)
		bucketTypes = append(bucketTypes, condType)
	}

	// No bucket to admit: under observe nothing may produce one, and outside it a condition
	// whose configuration has no cumulative bound produces none.
	if len(buckets) == 0 {
		return faults, nil
	}

	// Every in-tree handler's nil-counter guard already surfaced as a PrepareCommit
	// condErr above, but a custom CommittingConditionHandler need not, so guard here
	// rather than panicking the enforcement goroutine.
	if e.counter == nil {
		return faults, denyFromConditionError(&ConditionError{
			Code:    capability.ErrCodeConditionFailed,
			Message: "call counter not configured",
		}, matched, requestID, now)
	}

	admitted, deniedIndex, total, retryAfter, err := e.counter.AdmitAll(ctx, buckets)
	if err != nil {
		// Infrastructure fault across the WHOLE atomic commit, so it belongs to no single
		// condition's verdict. It is still attributable when every bucket came from one
		// condition type, which is the ordinary case; a genuinely mixed batch leaves the
		// field empty rather than naming an arbitrary one of the two, and Code+Message carry
		// the fault either way.
		return faults, denyFromConditionError(&ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: attributableType(bucketTypes),
			Message:       fmt.Sprintf("call counter error: %v", err),
		}, matched, requestID, now)
	}
	if !admitted {
		// deniedIndex comes from the CallCounter backend; validate it before using it as a
		// slice index. A non-conforming backend could return an out-of-range value, which
		// would panic the enforcement goroutine instead of failing closed.
		if deniedIndex < 0 || deniedIndex >= len(denies) {
			return faults, denyFromConditionError(&ConditionError{
				Code:          capability.ErrCodeConditionFailed,
				ConditionType: attributableType(bucketTypes),
				Message:       fmt.Sprintf("call counter returned out-of-range denied bucket index %d (have %d buckets)", deniedIndex, len(denies)),
			}, matched, requestID, now)
		}
		if denies[deniedIndex] == nil {
			// A committing handler's PrepareCommit populated a bucket but left Deny nil — a
			// handler bug. The bucket IS attributable here, unlike the batch-wide fault above.
			return faults, denyFromConditionError(&ConditionError{
				Code:          capability.ErrCodeConditionFailed,
				ConditionType: bucketTypes[deniedIndex],
				Message:       fmt.Sprintf("committing condition handler for bucket index %d supplied a nil Deny callback", deniedIndex),
			}, matched, requestID, now)
		}
		condErr := denies[deniedIndex](total, retryAfter)
		if condErr == nil {
			// A refused admission whose Deny callback returned nil would otherwise report the
			// over-quota call as satisfied — a policy bypass — or, worse, panic
			// denyFromConditionError's unconditional dereference of condErr.Code. Fail closed.
			condErr = &ConditionError{
				Code:          capability.ErrCodeConditionFailed,
				ConditionType: bucketTypes[deniedIndex],
				Message:       fmt.Sprintf("committing condition handler for bucket index %d's Deny callback returned nil for a refused admission", deniedIndex),
			}
		}
		return faults, denyFromConditionError(condErr, matched, requestID, now)
	}
	return faults, nil
}

// attributableType reports the one condition type every bucket in a commit came from, or ""
// when the batch mixes types — naming a type on a mixed batch would be a guess, and a
// structured audit field must never carry one.
func attributableType(types []string) string {
	if len(types) == 0 {
		return ""
	}
	for _, t := range types[1:] {
		if t != types[0] {
			return ""
		}
	}
	return types[0]
}

// denyFromConditionError wraps a handler's *ConditionError into a deny
// EnforceResponse, stamping the surrounding decision's requestID/now and the
// matched constraint's audit-only flag. Shared by evalCondition and
// commitDeferredConditions so a condition denial has one canonical response shape.
func denyFromConditionError(condErr *ConditionError, matched *capability.Constraint, requestID, now string) *capability.EnforceResponse {
	resp := denyResponse(requestID, now, matched.IsAuditOnly(), nil, capability.DenialInfo{
		Code:          condErr.Code,
		ConditionType: condErr.ConditionType,
		Message:       condErr.Message,
		HardDeny:      condErr.HardDeny,
		Details:       condErr.Details,
	})
	return &resp
}

// unauthorizedSkipError refuses a committing handler's skip that the request context did
// not authorize.
//
// HardDeny because the call must not be forwarded with its declared budget neither checked nor
// spent. The flag is load-bearing on the postures [WillForwardDeny] answers yes for — here,
// a per-constraint `enforcement: audit` entry, since a route-level --audit sets SkipQuota and
// would have AUTHORIZED the skip. An enforce constraint on an enforce route reaches this
// refusal too and blocks either way.
func unauthorizedSkipError(condType string) *ConditionError {
	return &ConditionError{
		Code:          capability.ErrCodeConditionFailed,
		ConditionType: condType,
		HardDeny:      true,
		Message:       fmt.Sprintf("committing condition %q reported a skip the request context did not authorize; skip must be derived solely from request context", condType),
	}
}

// evalCondition runs a single PURE condition through the handler runPureConditions already
// resolved for it — the one field of the registry entry this reads, so the merged lookup hands
// down 16 bytes rather than the whole entry. It returns a deny response when the condition
// fails (or fail-closed when there is no usable handler) and nil when it passes.
func (e *Engine) evalCondition(ctx context.Context, cond capability.Condition, condType string, pure ConditionHandler, req *capability.EnforceRequest, matched *capability.Constraint, requestID, now string) *capability.EnforceResponse {
	if pure == nil || isTypedNil(pure) {
		// Reachable for a nil registration AND for a committing entry holding a typed nil, which
		// registeredHandler.commits deliberately routes here rather than to the commit pass. The
		// message says what is true of both rather than naming a commit path a nil handler does
		// not have: a structured denial must not fabricate a cause. isTypedNil because a nil
		// POINTER in the interface passes == nil and then panics
		// the enforcement goroutine on Handle, the guard this file already applies to conditions
		// and directives.
		resp := denyResponse(requestID, now, matched.IsAuditOnly(), nil, capability.DenialInfo{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: condType,
			HardDeny:      true,
			Message:       fmt.Sprintf("condition type %q has no usable handler to evaluate it", condType),
		})
		return &resp
	}

	if condErr := pure.Handle(ctx, cond, req); condErr != nil {
		return denyFromConditionError(condErr, matched, requestID, now)
	}
	return nil
}

// evaluateMatched runs the shared allow tail once a winning constraint is selected: exposes
// the constraint's directives via ctx (not req, which would race concurrent readers), then
// evaluates every condition and — on allow — collects obligations BEFORE recording the call
// in session history (recording first would let a later sequenceBlock Peek treat a
// hard-denied call as "run"). Conditions run in TWO passes with the effect ceiling between
// them: pure predicates, then the ceiling, then quota-consuming commits, so nothing is
// charged to a call a later check still refuses. Shared by ValidateAction and
// EvaluateConditions so the two cannot diverge on this security-critical ordering.
func (e *Engine) evaluateMatched(ctx context.Context, req *capability.EnforceRequest, matched *capability.Constraint, requestID, now string) (resp capability.EnforceResponse) {
	// Done before conditions run so a policy condition can inspect the obligations
	// that will apply on allow.
	ctx = withDirectives(ctx, matched.Directives)

	// Resolve the constraint's effect contract once and thread it: the effectClass and
	// blastRadius conditions and the ceiling below all read this one value, so they cannot
	// disagree about what the call's effect was. No contract resolves to the fail-closed
	// default (irreversible, unquantified).
	effect := capability.ResolveEffect(matched.Effect, req.Arguments)
	ctx = withResolvedEffect(ctx, effect)

	// Collect the matched constraint's obligations UP FRONT and stamp them onto every deny
	// this function returns that will be FORWARDED rather than blocked: an audit-mode
	// downgrade still applies redaction only when the response carries obligations, so a
	// deny built with nil obligations would let the fields the manifest marked for
	// redaction reach the host intact.
	//
	// The deny CollectObligations can itself return (an unwired directive — an engine bug)
	// is held back to where the original ordering returned it, after runConditions below:
	// returning it here would preempt the condition verdict, and its HardDeny would BLOCK
	// a call an audit route should have denied-and-forwarded instead.
	obligations, obligDeny := e.CollectObligations(req.Delegation, matched, requestID, now)
	if WillForwardDeny(ctx, matched) {
		defer func() {
			// `!= DecisionAllow`, not `== DecisionDeny`: an unset Decision is FORWARDED
			// elsewhere, so gating on `== DecisionDeny` would let that shape through unredacted.
			if resp.Decision == capability.DecisionAllow || resp.Obligations != nil {
				return
			}
			// A HardDeny is never downgraded to a forward, so it has no response to redact.
			if resp.Denial != nil && resp.Denial.HardDeny {
				return
			}
			resp.Obligations = obligations
		}()
	}

	// An authenticated caller this engine cannot anchor as configured. Runs FIRST of the
	// three request-shaped gates below, ahead of the flow-label peek, because with no task
	// id the anchor falls back to the SESSION key: peeking first would read the very
	// session-keyed bucket this refusal exists to reject, and stamp that snapshot onto the
	// record as if it were evidence. Falling back to session keying here would let one
	// caller split its own taint, budgets and antecedents across two buckets by
	// alternating tokens — see anchorUnresolved.
	if e.anchorUnresolved(req) {
		return denyResponse(requestID, now, matched.IsAuditOnly(), nil, capability.DenialInfo{
			Code:          capability.ErrCodeMissingContext,
			ConditionType: string(AnchorKindTask),
			// HardDeny: a downgradable refusal is FORWARDED on an audit-only constraint, and
			// the observe path's antecedent recorder would then key this call's labels and
			// sequence marker on the SESSION anyway — the very split this check exists to
			// refuse.
			HardDeny: true,
			Message:  "this route anchors enforcement state on the task, but the presented token carries no mcp.task_id; refusing rather than accounting this call against a second, session-keyed bucket (fail closed)",
			Details:  map[string]interface{}{"anchor": string(AnchorKindTask), "reason": "no_task_id"},
		})
	}

	// Peek the incoming accumulated flow-label set up front (only for flow-relevant
	// constraints; skipped entirely under skipFlow). Reflects what flowed IN, before this
	// call's own output is recorded below. peekSessionLabels fails closed on unreadable state.
	flowRelevant := !e.skipFlow && constraintHasFlow(matched)
	var carriedLabels []string
	if flowRelevant {
		var err error
		carriedLabels, err = e.peekSessionLabels(ctx, req)
		if err != nil {
			return denyResponse(requestID, now, matched.IsAuditOnly(), nil, capability.DenialInfo{
				Code:          capability.ErrCodeConditionFailed,
				ConditionType: capability.ConditionTypeFlowLabel,
				Message:       fmt.Sprintf("flow-label state lookup failed: %v", err),
			})
		}
		// Thread the snapshot so handleFlowLabel reuses it, and stamp it onto EVERY deny
		// exit via one defer so no hand-stamped exit can be forgotten.
		ctx = withCarriedLabels(ctx, carriedLabels)
		defer func() {
			// `!= DecisionAllow`, not `== DecisionDeny`: an escalation is also a
			// non-forwarded exit, and its record must carry the same accumulated-label
			// snapshot every other non-allow exit carries.
			if resp.Decision != capability.DecisionAllow && resp.CarriedLabels == nil {
				resp.CarriedLabels = carriedLabels
			}
		}()
	}

	// The delegation authority gate. Sits after the obligation/carried-label defers, so a
	// downgraded refusal still carries redactions and the label snapshot, and before the
	// conditions, since it does not depend on them: the manifest may permit this target and
	// every condition may pass while this delegate was never handed the call.
	if delegDeny := e.checkDelegationTarget(req, matched.IsAuditOnly(), requestID, now); delegDeny != nil {
		return *delegDeny
	}

	// PASS ONE: the pure predicates. The deferred (quota-consuming) conditions are
	// collected but NOT committed here — the ceiling below has to be able to refuse the
	// call before anything is charged to it.
	deferred, deny := e.runPureConditions(ctx, req, matched, requestID, now)
	if deny != nil {
		return *deny
	}

	// Both positions are load-bearing: after the conditions so an engine bug in a directive
	// cannot preempt (and, on an audit route, harden) a condition verdict; before the
	// history write so a hard deny does not leave a phantom antecedent a later
	// sequenceBlock Peek would see as "run".
	if obligDeny != nil {
		return *obligDeny
	}

	// The tool-agnostic consequence bound, applied to an action the conditions have already
	// allowed. Runs BEFORE the state commit, so an over-ceiling call leaves neither a
	// phantom antecedent nor a stranded flow label.
	if ceilingDeny := e.checkEffectCeiling(effect, matched, carriedLabels, requestID, now); ceilingDeny != nil {
		return *ceilingDeny
	}

	// The delegated consequence bound, reading the SAME resolved effect, after the policy's
	// own ceiling so an action over both reports the more fundamental refusal.
	if delegDeny := e.checkDelegationEffectClass(req, effect, matched.IsAuditOnly(), requestID, now); delegDeny != nil {
		return *delegDeny
	}

	// The approval gate for the one directive that REMOVES a flow label, on the same
	// pre-commit side of the line: an unapproved declassification must not spend a quota
	// slot, write an antecedent, or touch the session's label set. Runs AFTER the ceiling so
	// an over-bound call reports that first.
	decl, declDeny := e.checkDeclassify(ctx, req, matched, carriedLabels, requestID, now)
	if declDeny != nil {
		return *declDeny
	}

	// PASS TWO: commit the deferred conditions, now that nothing left can refuse the call
	// without state. Load-bearing ordering: committing inside the first pass let an
	// over-ceiling call spend its cumulative blastRadius budget before the ceiling ran, so
	// several never-forwarded escalations could exhaust a session's whole budget.
	faults, deny := e.commitDeferredConditions(ctx, req, matched, deferred, requestID, now)
	if len(faults) > 0 {
		// Stamped by defer rather than on the allow literal, so the report survives the exits
		// BELOW this point too. On the only posture that produces a fault the route runs
		// --audit, where a soft deny is forwarded and its record is the one an operator reads —
		// so a fault attached to the allow alone would go unreported for exactly the calls whose
		// constraint also carries a condition that denies.
		defer func() { resp.HandlerFaults = faults }()
	}
	if deny != nil {
		return *deny
	}

	// Commit this call's sequenceBlock antecedent and flow labels as a single all-or-nothing
	// unit: the flow write goes first (the FlowLabelStore supports targeted rollback), the
	// seq antecedent second, and a fault on the second rolls the first back — so a
	// hard-denied call leaves NEITHER a phantom antecedent nor a stranded flow label. A
	// transport that serializes its decision phase orders this against other decisions on
	// the same anchor; see rollbackLabels for when no such ordering can be assumed.
	labelsOut, cerr := e.recordSourceCall(ctx, req, matched, flowRelevant, carriedLabels, decl)
	if cerr != nil {
		if cerr.Declassify {
			// Reached AFTER the burn on the antecedent-fault path, so the grant may already
			// be spent for a call about to hard-deny. Naming it here is the only way that
			// reaches the tape; the id rides only when the commit got past the burn.
			return declassifyRecordFailureDenial(requestID, now, matched.IsAuditOnly(), cerr.SpentApprovalID)
		}
		if cerr.Flow {
			// No obligations: this sets HardDeny, never downgraded to a forward, so there is
			// no response to redact.
			return labelRecordFailureDenial(requestID, now, matched.IsAuditOnly(), nil)
		}
		return recordFailureDenial(requestID, now, matched.IsAuditOnly(), obligations)
	}

	// The clear itself is NOT applied here; it is handed to the caller to commit once the
	// call has run (see EnforceResponse.Declassification / CommitDeclassification).
	//
	// What is handed over is the INTERSECTION with what the anchor carries as of THIS
	// decision, resolved inside the decision's critical section and never re-derived at
	// commit time — a source read decided after this point is not in this set, so the
	// commit cannot remove it. Re-reading at commit time would let one call's approved
	// clear launder a concurrent read's brand-new taint.
	//
	// The handle's set is empty for a no-op clear (nothing to remove, so the commit is
	// skipped and the tape records no declassification), but the grant is still spent —
	// SpentApprovalID reports that, non-empty only for a single-use grant, minted only here
	// past the burn.
	//
	// The handle is nil when the constraint carries no declassify directive, the caller's
	// presence test.
	return capability.EnforceResponse{
		RequestID:   requestID,
		Decision:    capability.DecisionAllow,
		Obligations: obligations,
		DecidedAt:   now,
		AuditOnly:   matched.IsAuditOnly(),
		LabelsOut:   labelsOut,

		Declassification: decl.handle(carriedLabels, labelsOut),
		// The SAME resolution the two effect conditions and the ceiling read, handed on to
		// the post-hoc receipt check rather than re-resolved there — one resolution per
		// call, so the decision and the check cannot disagree about what the effect was.
		Effect:        effect,
		CarriedLabels: carriedLabels,
	}
}

// ValidateAction evaluates an enforce request against the provided capabilities.
// It returns an EnforceResponse with the decision and any obligations. Every outcome
// (no-match deny, argumentSchema deny, evaluated verdict) is carried in the response
// itself — there is no separate error channel, so a deny is always a structured
// EnforceResponse, never a Go error a caller must branch on.
func (e *Engine) ValidateAction(ctx context.Context, req *capability.EnforceRequest, capabilities []capability.Constraint) capability.EnforceResponse {
	requestID := NewRequestID()
	now := e.clock.Now().UTC().Format(time.RFC3339Nano)

	// Store the request ID and timestamp in ctx so condition handlers (e.g. policy)
	// can surface them as input.context.request_id / input.context.timestamp. The
	// timestamp is the same instant stamped on DecidedAt.
	ctx = context.WithValue(ctx, ctxRequestIDKey{}, requestID)
	ctx = context.WithValue(ctx, ctxTimestampKey{}, now)

	matched := e.FindMatchingCapability(req, capabilities)
	if matched == nil {
		// A plain block — UNLESS the route runs --audit (SkipQuota), which forwards even a
		// no-match deny. A forwarded response must carry redact obligations or it reaches
		// the host unmasked, so fill them from every capability NAMING this target
		// regardless of principal scoping — deliberately wider than FindMatchingCapability's
		// own selection, since any entry declaring the target redactable is reason to mask it.
		var obligations []capability.Obligation
		if WillForwardDeny(ctx, nil) {
			obs, obligDeny := e.CollectObligations(req.Delegation, namingTargetConstraint(req, capabilities), requestID, now)
			if obligDeny != nil {
				return *obligDeny
			}
			obligations = obs
		}
		return denyResponse(requestID, now, false, obligations, capability.DenialInfo{
			Code:    capability.ErrCodeAuthorizationFailed,
			Message: "no matching capability for requested action",
		})
	}

	// argumentSchema is evaluated before conditions; a structural failure takes
	// precedence over any condition failure. It does not consult ctx directives, so
	// evaluateMatched threads them (via withDirectives) after this check.
	if matched.ArgumentSchema != nil {
		if err := ValidateArgumentSchema(req.Arguments, matched.ArgumentSchema); err != nil {
			// A downgradable deny is FORWARDED, so it must carry the constraint's
			// obligations or the response reaches the host with fields the manifest marked
			// for redaction intact — restated here since this site returns before
			// evaluateMatched applies the same rule.
			var obligations []capability.Obligation
			if WillForwardDeny(ctx, matched) {
				obs, obligDeny := e.CollectObligations(req.Delegation, matched, requestID, now)
				if obligDeny != nil {
					return *obligDeny
				}
				obligations = obs
			}
			// Stamp AuditOnly so a direct engine caller gets the constraint's mode
			// without re-deriving it.
			return denyResponse(requestID, now, matched.IsAuditOnly(), obligations, capability.DenialInfo{
				Code:          capability.ErrCodeInvalidParams,
				ConditionType: "argumentSchema",
				Message:       err.Error(),
			})
		}
	}

	return e.evaluateMatched(ctx, req, matched, requestID, now)
}

// resolveRequestTarget resolves a request's namespace type and bare target name: the type
// from an explicit req.Target.Type when present, else from the req.TargetName prefix (bare
// defaults to "tool"). Target.Name is preferred VERBATIM over the prefix-split bare name: a
// resource or prompt named with a leading recognized token (e.g. "system:config") would
// otherwise have that token wrongly stripped, so the covering constraint never matches.
// Mirrors the PDP selection path so the engine and proxy agree on what a policy means.
func resolveRequestTarget(req *capability.EnforceRequest) (reqType, bareName string) {
	reqType, bareName = splitEnginePrefix(req.TargetName)
	if req.Target == nil {
		return reqType, bareName
	}
	if req.Target.Type != "" {
		reqType = req.Target.Type
	}
	if n := strings.TrimSpace(req.Target.Name); n != "" {
		bareName = n
	}
	return reqType, bareName
}

// NoMatchScore is the sentinel for "no matching capability found yet", below any real
// ResourceSpecificity score. Exported so other scans (e.g. internal/drift's
// coveringMatches) reuse this floor rather than re-deriving their own sentinel.
const NoMatchScore = -1 << 30

// ConstraintScorer tracks the best-scoring constraint index seen so far under the
// project's single constraint-selection tiebreak. Selection order, most to least
// decisive:
//
//  1. higher target specificity wins;
//  2. at equal specificity, a principal-scoped entry beats a general one,
//     regardless of declaration order;
//  3. at equal specificity within the same principal class, declaration order wins
//     (Offer's strict `>` keeps the incumbent). Documented in
//     docs/capability-manifest-guide.md.
//
// Exported because this predicate is security-relevant and has two consumers — the
// engine's FindMatchingCapability and the proxy's internal/pdp.findConstraint — which were
// character-for-character copies whose precedence could silently drift apart. Scores need
// only be mutually comparable across consumers, not equal.
type ConstraintScorer struct {
	best      int
	bestScore int
	bestPrin  bool
}

// NewConstraintScorer returns a scorer with no candidate yet (Best() == -1).
func NewConstraintScorer() ConstraintScorer {
	return ConstraintScorer{best: -1, bestScore: NoMatchScore}
}

// Offer submits candidate index i with the given specificity score and whether it is
// principal-scoped, keeping it only if it wins the tiebreak above.
func (cs *ConstraintScorer) Offer(i, score int, hasPrincipal bool) {
	if score > cs.bestScore || (score == cs.bestScore && hasPrincipal && !cs.bestPrin) {
		cs.bestScore, cs.best, cs.bestPrin = score, i, hasPrincipal
	}
}

// Best returns the winning candidate index, or -1 when nothing was offered.
func (cs *ConstraintScorer) Best() int { return cs.best }

// resourceScoreWeight scales the resource-specificity score, reserving the low-order range
// [0, resourceScoreWeight) as headroom for a possible future per-action score that could
// break ties only between equal-resource capabilities, never reorder differing ones.
const resourceScoreWeight = 10

// FindMatchingCapability returns the most specific capability that matches the request, or
// nil if none match. Tie-breaking is stable: at equal specificity, the first in the list
// wins. The proxy does NOT route through this — internal/pdp.findConstraint runs its own
// scan, sharing only the tiebreak (ConstraintScorer) and the match/specificity primitives.
// Change the precedence rule there, not here.
func (e *Engine) FindMatchingCapability(req *capability.EnforceRequest, capabilities []capability.Constraint) *capability.Constraint {
	reqType, bareToolName := resolveRequestTarget(req)
	scorer := NewConstraintScorer()
	for i := range capabilities {
		constraint := &capabilities[i]
		// Namespace type must match on both sides; bare names alone would let a
		// "resource:*" constraint approve any tool call.
		constraintType, bare := splitEnginePrefix(constraint.Target)
		if constraintType != reqType {
			continue
		}
		if !MatchesResource(bare, bareToolName) {
			continue
		}
		if !actionPermitted(constraint.Actions, capability.TargetType(reqType)) {
			continue
		}
		// A principal-scoped constraint applies only when the request's claims
		// satisfy it; otherwise skip, like a target mismatch.
		if !constraint.PrincipalMatches(req.Claims) {
			continue
		}
		// The selection tiebreak lives in ConstraintScorer, shared with the proxy's
		// internal/pdp.findConstraint so the two cannot disagree on precedence.
		scorer.Offer(i, ResourceSpecificity(bare, bareToolName)*resourceScoreWeight, constraint.HasPrincipal())
	}
	if scorer.Best() < 0 {
		return nil
	}
	return &capabilities[scorer.Best()]
}

// namingTargetConstraint builds a synthetic constraint carrying the directives of every
// capability whose namespace type and target pattern match the request, IGNORING principal
// scoping and the action check — "what did the manifest declare about this target", the
// right question when no entry governs the caller yet the deny is about to be forwarded
// under --audit. Carries no enforcement mode or conditions; exists only for CollectObligations.
func namingTargetConstraint(req *capability.EnforceRequest, capabilities []capability.Constraint) *capability.Constraint {
	reqType, bareName := resolveRequestTarget(req)
	out := &capability.Constraint{Target: reqType + ":" + bareName}
	for i := range capabilities {
		constraintType, bare := splitEnginePrefix(capabilities[i].Target)
		if constraintType != reqType || !MatchesResource(bare, bareName) {
			continue
		}
		out.Directives = append(out.Directives, capabilities[i].Directives...)
	}
	return out
}

// splitEnginePrefix splits a constraint Target or afterTools entry into its
// namespace type and bare name/pattern. Recognized prefixes are "tool",
// "resource", "prompt", "system"; an unprefixed value defaults to "tool" type
// with its bare half returned unchanged. Returning the type lets sequenceBlock
// history keys keep a same-named tool and prompt in separate buckets.
func splitEnginePrefix(s string) (targetType, bare string) {
	if idx := strings.Index(s, ":"); idx >= 0 {
		// capability.IsTargetType is the single source of truth for the recognized
		// namespace set, so the engine and the manifest loader cannot disagree.
		if capability.IsTargetType(s[:idx]) {
			return s[:idx], s[idx+1:]
		}
	}
	return "tool", s
}

// StripEnginePrefix removes the leading "type:" prefix ("tool", "resource", "prompt",
// "system") from a constraint Target field, returning the bare name/pattern unchanged if
// none matches. Exported so manifest validation recognizes the same prefixes the engine
// applies at runtime — an unrecognized prefix passing through unchanged is the signal
// load-time validation uses to reject an afterTools entry that would fail open at lookup.
func StripEnginePrefix(s string) string {
	_, bare := splitEnginePrefix(s)
	return bare
}

// EvaluateConditions evaluates the conditions on a pre-matched constraint without
// resource/action matching or argumentSchema validation. The caller must have
// selected the winning constraint (e.g. via FindMatchingCapability) and, if
// structural argument validation is needed, run ValidateArgumentSchema first
// (ValidateAction does both for you; this does neither). Obligations are collected
// from the constraint's Directives after all conditions pass.
func (e *Engine) EvaluateConditions(ctx context.Context, req *capability.EnforceRequest, matched *capability.Constraint) capability.EnforceResponse {
	requestID := NewRequestID()
	now := e.clock.Now().UTC().Format(time.RFC3339Nano)
	ctx = context.WithValue(ctx, ctxRequestIDKey{}, requestID)
	ctx = context.WithValue(ctx, ctxTimestampKey{}, now)

	return e.evaluateMatched(ctx, req, matched, requestID, now)
}

// knownObligationTypes is the set of obligation types the forward core handles.
// CollectObligations fails closed (ENFORCEMENT_ERROR, deliberately NOT AuditOnly even
// under an audit-mode constraint) for any type not listed here, catching a new directive's
// unrecognized ToObligation type at policy-evaluation time rather than silently forwarding
// the response without its declared post-processing (e.g. an un-applied redaction).
// Register both the type AND its handler in ApplyRedactObligs when adding a new directive.
var knownObligationTypes = map[string]bool{
	capability.DirectiveTypeRedactFields: true,
}

// CollectObligations turns the matched constraint's directives into the post-allow
// obligations the transport applies to the upstream response. Runs only on the allow
// path; a directive MUST NOT change the allow/deny decision.
//
// Exported for the external decision layer (the PDP), which stamps these onto an
// audit-mode deny it downgrades to a forwarded call — a downgraded deny is still
// forwarded to the host, so it must carry the same redactFields obligations a genuine
// allow would, or the transport forwards the response unredacted. The allow path and the
// downgrade path therefore call the SAME function, so they cannot drift on which
// directives translate to which obligations.
//
// On the error return, the obligations slice carries whatever was VALIDLY collected
// BEFORE the offending directive, not nil: evaluateMatched calls this up front and stamps
// the result onto a later, unrelated forwarded deny via a deferred closure — a pure
// condition can deny (and get downgraded/forwarded under audit mode) without ever
// consulting the error return at all, ordered deliberately so an engine bug in one
// directive cannot preempt that condition's own verdict. Discarding the partial
// obligations there would silently forward that unrelated deny with a real redactFields
// obligation dropped, reaching the host unmasked. A caller that DOES act on the error
// return (returning it as a hard block) simply ignores the accompanying slice, so this
// costs those callers nothing.
func (e *Engine) CollectObligations(chain *capability.DelegationChain, matched *capability.Constraint, requestID, now string) ([]capability.Obligation, *capability.EnforceResponse) {
	var obligations []capability.Obligation
	// The delegation chain's composed redactFields, first so it applies even to a
	// constraint carrying no directives at all. A parameter rather than a read of
	// req.Delegation, since one call site (the no-match fill) synthesizes a constraint
	// from the target alone with no request to read from — a signature that cannot be
	// called without deciding what the chain contributes makes forgetting it impossible.
	if ob := delegatedRedaction(chain); ob != nil {
		obligations = append(obligations, *ob)
	}
	for _, dir := range matched.Directives {
		if dir == nil {
			continue
		}
		// A typed-nil pointer survives the `dir == nil` check but ToObligation's
		// value-receiver dereference would panic. Skip it.
		if isTypedNil(dir) {
			continue
		}
		// labelOutput and declassify are enforce-time state directives, not response
		// obligations (their effect is the session-label write the engine performs on
		// allow), so skip them before ToObligation.
		switch dir.DirectiveType() {
		case capability.DirectiveTypeLabelOutput, capability.DirectiveTypeDeclassify:
			continue
		}
		ob := dir.ToObligation()
		if !knownObligationTypes[ob.Type] {
			resp := denyResponse(requestID, now, false, nil, capability.DenialInfo{
				Code: capability.ErrCodeEnforcementError,
				// HardDeny so the verdict survives isObserveDeny: an unwired directive is an
				// engine bug, not a downgradable policy verdict, and must block even under
				// an audit-mode constraint.
				HardDeny: true,
				Message:  fmt.Sprintf("unhandled obligation type %q from directive %T; register it in knownObligationTypes and implement its consumer", ob.Type, dir),
			})
			return obligations, &resp
		}
		obligations = append(obligations, ob)
	}
	return obligations, nil
}

// MatchesResource reports whether a capability resource pattern matches the tool name,
// using [path.Match] glob semantics; "*" matches any name and crosses ':' (the namespace
// separator) but NOT '/' — there is no '**' for targets, so "file:///data/*" matches
// "file:///data/report.csv" but not a nested path. Errs deny, never wrongly allows; cover
// deeper levels with an explicit per-level entry. Documented in
// docs/capability-manifest-guide.md.
func MatchesResource(resource, toolName string) bool {
	if resource == "*" || resource == toolName {
		return true
	}
	// A malformed pattern (unclosed '[') should have been rejected at load time;
	// treat it as non-matching rather than propagating an error on the hot path.
	matched, err := path.Match(resource, toolName)
	if err != nil {
		return false
	}
	return matched
}

// ValidateResourcePattern returns an error if resource is not a valid [path.Match]
// glob. Callers should reject invalid patterns at load time.
func ValidateResourcePattern(resource string) error {
	if _, err := path.Match(resource, ""); err != nil {
		return fmt.Errorf("enforcement: invalid resource pattern %q: %w", resource, err)
	}
	return nil
}

// actionPermitted reports whether the actions list permits the call for the given target
// type, via capability.ValidateActionForTargetType (shared with the loader). An empty
// actions list fails closed.
func actionPermitted(actions []string, targetType capability.TargetType) bool {
	for _, a := range actions {
		if capability.ValidateActionForTargetType(targetType, a) == nil {
			return true
		}
	}
	return false
}

// resourceSpecificityLiteralWeight is the per-literal-rune weight in the specificity
// score, deliberately exceeding maxWildcardTiebreak so a pattern with one more literal
// rune always outranks one with fewer, regardless of wildcard count.
const resourceSpecificityLiteralWeight = 10

// maxWildcardTiebreak clamps the wildcard tiebreaker strictly below one literal step, so
// a pattern with many metacharacters cannot subtract a full literal step and outrank a
// more-specific one.
const maxWildcardTiebreak = resourceSpecificityLiteralWeight - 1

// exactMatchSpecificity is the score for an exact match, dominating every glob's uncapped
// formula score. 1<<27 is far above any realistic glob score yet small enough that
// exactMatchSpecificity * resourceScoreWeight stays within a 32-bit int (GOARCH=386, arm,
// mips), matching the 32-bit safety pkg/callcounter already engineers for.
const exactMatchSpecificity = 1 << 27

// ResourceSpecificity scores how specifically a capability's resource pattern matches
// toolName, so FindMatchingCapability can select the most specific of several matching
// capabilities. Exported alongside MatchesResource for callers needing the engine's own
// selection ordering. Callers must have established a match first.
func ResourceSpecificity(resource, toolName string) int {
	if resource == toolName {
		return exactMatchSpecificity
	}
	// literalCount counts EVERY non-wildcard rune, not just the leading run: a
	// prefix-only count would score "*" and "*_admin" identically, losing the
	// more-specific pattern to a catch-all on manifest order alone. wildcardCount counts
	// each matcher ('*'/'?' one each; a whole "[...]" class also one). A utf8 cursor walks
	// the string in place rather than materializing []rune — this scorer runs for every
	// candidate constraint on the hot path.
	literalCount := 0
	wildcardCount := 0
	for i := 0; i < len(resource); {
		r, size := utf8.DecodeRuneInString(resource[i:])
		switch r {
		case '*', '?':
			wildcardCount++
			i += size
		case '\\':
			// A backslash escapes the next rune: "\x" consumes two pattern bytes but
			// matches exactly ONE input character, so only the escaped rune counts as a
			// literal. Without this arm an escaped '[' would be misparsed as opening a class.
			i += size
			if i < len(resource) {
				_, sz := utf8.DecodeRuneInString(resource[i:])
				i += sz
				literalCount++ // one literal rune matched (the escaped character)
			}
		case '[':
			// One class = one wildcard; advance past it to the closing ']'. Inside,
			// a leading '^' negates and '\' escapes. The pattern already passed
			// path.Match validation (which rejects a leading ']'), so the first
			// unescaped ']' is always the terminator and the class is well-formed.
			wildcardCount++
			i += size
			if i < len(resource) {
				if r2, sz := utf8.DecodeRuneInString(resource[i:]); r2 == '^' {
					i += sz
				}
			}
			for i < len(resource) {
				r2, sz := utf8.DecodeRuneInString(resource[i:])
				i += sz // consume this class rune (including the closing ']')
				if r2 == ']' {
					break
				}
				if r2 == '\\' && i < len(resource) {
					_, sz2 := utf8.DecodeRuneInString(resource[i:])
					i += sz2 // skip the escaped rune
				}
			}
			// An unterminated class (no ']' before end-of-string) is rejected by
			// validation; defensively, the loop simply consumes to the end.
		default:
			literalCount++
			i += size
		}
	}
	if wildcardCount > maxWildcardTiebreak {
		wildcardCount = maxWildcardTiebreak
	}
	return literalCount*resourceSpecificityLiteralWeight - wildcardCount
}
