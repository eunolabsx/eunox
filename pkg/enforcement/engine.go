// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Package enforcement implements the capability enforcement engine that evaluates
// conditions against incoming requests and produces allow/deny decisions.
package enforcement

import (
	"context"
	"fmt"
	"path"
	"strconv"
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

// DeferredCommit is one deferred (quota-consuming) condition's admission plan, derived
// WITHOUT yet consuming anything, so the engine can admit every such condition on a
// constraint in ONE atomic backend call.
//
// It carries the bucket rather than a flag the engine interprets: a handler states which
// accounting its bucket uses (QuotaBucket.Counted), what this call contributes, and what
// bound applies, and the backend admits the whole mixed set. Nothing here requires the
// engine to know which CONDITION TYPE produced a bucket — an earlier shape did, and the
// branch it needed stamped one built-in's discriminator onto a refusal that a third-party
// handler could equally have produced, which is exactly the free-form-text-in-a-structured-
// field mistake the audit taxonomy forbids.
//
// Deny builds the denial for this bucket when it is the one that lacked headroom, given the
// observed total and the backend's retry-after hint.
type DeferredCommit struct {
	Bucket capability.QuotaBucket
	Deny   func(total float64, retryAfter time.Duration) *ConditionError
}

// Commits reports whether this prepared commit names a bucket at all.
//
// A handler whose condition commits only in SOME configurations returns a zero
// DeferredCommit for the non-committing case: blastRadius consumes a weighted budget only
// when the condition declares a cumulative bound, but deferral is keyed by condition TYPE,
// so the per-call-only shape reaches PrepareCommit too and has to be able to say "nothing
// to commit". Its PURE checks have already run by then — PrepareCommit performs them — so
// the engine simply has no bucket to admit for it.
func (d DeferredCommit) Commits() bool { return d.Bucket.Key != "" }

// CommittingConditionHandler is a ConditionHandler whose condition commits state
// (consumes a quota slot) on admit, so it must run after all pure predicates and
// participate in the engine's atomic multi-condition commit instead of committing
// per-bucket (which would leave a check->commit TOCTOU across the buckets).
//
// PrepareCommit is the condition's WHOLE evaluation minus the commit: it performs every
// pure check the condition makes and derives the bucket without consuming it, and the
// engine then admits every prepared bucket in one atomic call. Putting the pure checks here
// rather than in Handle is load-bearing — under observe mode the commit is skipped, and a
// handler that carried its pure checks only in Handle had them silently skipped too, so a
// per-call bound went unevaluated on exactly the run an operator makes to predict
// enforcement.
//
// skip is true when quota must not be consumed (observe mode), in which case no bucket is
// committed — but the pure checks have still run and may still have returned condErr.
//
// skip MUST be uniform across the whole constraint: it must be derived solely from
// the request context (as the built-in maxCalls does via SkipQuota(ctx)), never from
// this condition's own configuration or arguments. The atomic multi-condition commit
// treats one bucket's skip as skipping the entire deferred set — admitting the call
// without limit-checking the remaining committing conditions — so a per-condition skip
// would be a fail-open for the buckets it never checked. commitDeferredConditions asserts
// skip == SkipQuota(ctx) and fails closed on a violation, but a conforming handler must
// keep skip context-derived so the whole set skips or none does.
//
// A condition type is "deferred" precisely when its registered handler implements
// this interface, so a custom WithConditionHandler that commits state participates
// automatically and there is no hardcoded type switch to drift from the registry.
type CommittingConditionHandler interface {
	ConditionHandler
	PrepareCommit(ctx context.Context, condition capability.Condition, req *capability.EnforceRequest) (commit DeferredCommit, skip bool, condErr *ConditionError)
}

// ConditionError describes a condition evaluation failure.
type ConditionError struct {
	Code          string
	ConditionType string
	Message       string
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

// sequenceHistoryWindowSec bounds how long a session's per-tool call markers are
// retained for sequenceBlock lookups: long enough to cover any realistic MCP
// session, short enough that abandoned-session state is reclaimed. Recording and
// Peek use the same value so they address the same window bucket in windowed
// backends. A nil counter still fails maxCalls and sequenceBlock closed.
//
// This retention is a REAL bound on the guarantee, not just a storage detail: it is
// wall-clock, so a session idle past the window loses its antecedent marker and a
// later blocked call is allowed. Two things keep that narrow. Each fresh call to the
// antecedent re-records the marker (RecordSessionCall), and each blocked call that
// finds the marker re-arms it (handleSequenceBlock), so the window measures
// INACTIVITY of the whole antecedent/blocked pair rather than age since the
// antecedent. A session that goes quiet for longer than this on both legs — a
// multi-day agent session, say — does lose the gate; that residue is documented as a
// sequenceBlock limitation in docs/capability-manifest-guide.md. Raising the value
// trades a longer guarantee against retaining abandoned-session state for as long.
const sequenceHistoryWindowSec = 86400 // 24h

// compositeCounterKey joins prefix and the variadic parts into one counter key.
// Each part is emitted length-prefixed (":" + decimal byte length + ":" + raw
// bytes), so the key is injective for arbitrary byte content — no ":" or NUL a
// part contains can forge a different tuple's key, which a plain delimiter join
// ("seq:"+sessionID+":"+tool) cannot guarantee since SessionID and tool names are
// caller/host-supplied with no enforced format. The prefix is emitted verbatim
// (no length tag), preserving the disjoint "seq:" / "maxcalls:" namespaces the
// callcounter backends rely on; both call sites pass distinct colon-free literals
// at a fixed arity.
func compositeCounterKey(prefix string, parts ...string) string {
	// Pre-size the buffer (this runs on every recorded call and maxCalls check).
	// Over-estimating only sizes the backing array slightly large.
	size := len(prefix)
	for _, p := range parts {
		size += len(p) + 8
	}
	var b strings.Builder
	b.Grow(size)
	b.WriteString(prefix)
	for _, p := range parts {
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(len(p)))
		b.WriteByte(':')
		b.WriteString(p)
	}
	return b.String()
}

// sequenceHistoryMaxEntries caps how many per-(session, tool) call markers the
// history retains. sequenceBlock only asks "did this tool run at least once?",
// so a single marker suffices; retaining more would grow the slice by one entry
// per call across the 24h window — an unbounded heap sink for a one-bit question.
const sequenceHistoryMaxEntries = 1

// PolicyEvaluator evaluates a policy condition against an enforce request by
// calling an external policy decision point (e.g. OPA, Cedar). Implementations
// must return nil to allow or a non-nil [*ConditionError] to deny.
//
// The input value MUST be treated as read-only. Its nested claim objects may be
// shared by pointer across concurrent requests presenting the same token (the JWT
// claims cache hands out one *JWTClaims per token within its TTL), so mutating input
// — or anything reachable from it — races other in-flight evaluations and can poison
// the cached claims for every later request on that token. Copy out anything you need
// to modify.
type PolicyEvaluator interface {
	Evaluate(ctx context.Context, backend string, config, input interface{}, req *capability.EnforceRequest) *ConditionError
}

// Engine is the enforcement decision engine. It evaluates enforce requests
// against a set of capabilities and registered condition handlers.
type Engine struct {
	// handlers is the condition-handler registry. It is fully populated during
	// New (built-ins plus any WithConditionHandler options) and never written
	// again, so the hot path reads it concurrently without a lock.
	handlers        map[string]ConditionHandler
	clock           Clock
	counter         capability.CallCounter
	policyEvaluator PolicyEvaluator

	// flowStore holds per-session information-flow-control label state (the source's
	// labelOutput write, the sink's flowLabel read). It is a seam distinct from
	// counter because provenance is a monotonic, session-lifetime SET, not a decaying
	// sliding-window count: keeping flow state in the windowed counter aged a taint out
	// mid-session (a fail-open). nil disables flow recording — a flowLabel/labelOutput
	// constraint then fails closed exactly as a nil counter fails maxCalls closed. See
	// pkg/flowlabelstore.
	flowStore capability.FlowLabelStore

	// skipAntecedentRecording is set when the policy provably contains no
	// sequenceBlock condition, so the per-call antecedent marker RecordSessionCall
	// writes is never read. Skipping the write avoids a needless counter round-trip
	// and, more importantly, removes the RecordSessionCall fail-closed deny path —
	// which, on a counter-write fault, would otherwise deny a call whose maxCalls
	// slot runConditions already committed, burning quota for a marker nothing reads.
	skipAntecedentRecording bool

	// skipFlow is set when the policy provably contains no flowLabel condition and no
	// labelOutput directive, so evaluateMatched skips the per-call flow-relevance scan
	// and the peek/record path entirely. Mirrors skipAntecedentRecording: it spares a
	// non-flow policy the scan on every allow, and removes the recordLabels fail-closed
	// deny path for a source-only policy whose markers no sink reads.
	skipFlow bool

	// effectCeiling is the policy's tool-agnostic consequence bound, applied to EVERY
	// action the conditions allowed (see checkEffectCeiling). It is engine-level rather
	// than per-constraint on purpose: a per-target gate only guards the targets someone
	// wrote one for, while the ceiling is what catches the target nobody thought about —
	// including the unannotated one, which resolves to irreversible and so exceeds any
	// ceiling. nil (the default) means the policy sets no consequence bound and the whole
	// check is skipped.
	effectCeiling *capability.EffectCeiling

	// counterKeyNamespace is folded into every maxCalls/sequenceBlock counter key
	// (compositeCounterKey's first component). The binary wires each route's name here
	// so every route's engine addresses a disjoint counter namespace even when they
	// share one CallCounter — a fail-closed backstop in the key itself against a
	// session-id collision or a cross-route session-binding regression, rather than
	// relying solely on the transport to keep session IDs per-route unique. A
	// single-upstream deployment has one route (its synthesized name), so cross-route
	// collision is impossible regardless; the name still namespaces the key. When left
	// empty (a directly-constructed Engine) the leading component is still emitted (a
	// length-prefixed empty part), so the key differs from a pre-namespace key either way.
	counterKeyNamespace string

	// taskAnchored keys accumulated state (flow labels, sequenceBlock antecedents,
	// maxCalls and cumulative blastRadius budgets, the single-use declassify ledger) on
	// the request's VALIDATED mcp.task_id claim rather than on its session, so the state
	// survives a hop across enforcement points. Opt-in (WithTaskAnchoredState) and
	// fail-safe: a request with NO TOKEN falls back to session keying rather than to a
	// shared bucket, and an authenticated one whose token carries no task_id is refused
	// rather than split across both. See anchor.go for why each property is required.
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
// control (the flowLabel condition and the labelOutput directive). It is distinct from
// the CallCounter: flow-label provenance is a monotonic per-session set with a
// session-scoped lifetime, so it must not live in the sliding-window counter that
// backs maxCalls/sequenceBlock. Leave it unset only for a policy known to use no flow
// control (see config.LocalManifest.HasFlowLabel); a flow constraint with no store
// wired fails closed. See pkg/flowlabelstore.
func WithFlowLabelStore(store capability.FlowLabelStore) Option {
	return func(e *Engine) {
		e.flowStore = store
	}
}

// WithoutAntecedentRecording tells the engine the policy contains no sequenceBlock
// condition, so it skips writing the per-call sequenceBlock-history marker. The
// marker exists only to be read by a later sequenceBlock; with none in the policy
// the write is pure overhead, and skipping it also removes the RecordSessionCall
// fail-closed deny path that could burn a just-committed maxCalls slot on a
// counter-write fault. Only set this when the policy is known to use no
// sequenceBlock (see config.LocalManifest.HasSequenceBlock); leaving it unset
// preserves the always-record fail-closed behavior.
func WithoutAntecedentRecording() Option {
	return func(e *Engine) {
		e.skipAntecedentRecording = true
	}
}

// WithoutFlowLabels tells the engine the policy contains no flowLabel condition and no
// labelOutput directive, so it skips the per-call flow-relevance scan and the flow
// peek/record path. Only set this when the policy is known to use neither (see
// config.LocalManifest.HasFlowLabel); leaving it unset preserves the always-check
// behavior. Mirrors WithoutAntecedentRecording.
func WithoutFlowLabels() Option {
	return func(e *Engine) {
		e.skipFlow = true
	}
}

// WithCounterKeyNamespace sets a namespace folded into every maxCalls/sequenceBlock
// counter key, so engines that share one CallCounter (gateway routes) address
// disjoint counter buckets. Set it to a value unique per route (the route name) so a
// session-id collision or a cross-route session-binding regression cannot drain or
// interfere with another route's quota — the fail-closed backstop lives in the key
// itself, not only in the transport's session/route binding. Leave it unset in
// single-upstream mode.
func WithCounterKeyNamespace(ns string) Option {
	return func(e *Engine) {
		e.counterKeyNamespace = ns
	}
}

// WithTaskAnchoredState keys accumulated enforcement state on the request's VALIDATED
// mcp.task_id claim instead of on its session, so information-flow taint, sequenceBlock
// antecedents, quota and blast-radius budgets, and single-use declassify grants survive a
// hop across enforcement points — a sub-agent delegated to a second PEP, or the same task
// re-entering through a fresh session, continues the task's state rather than starting
// clean.
//
// It changes what every budget in the policy MEANS (a maxCalls of 20 becomes 20 per task,
// not 20 per connection), which is why it is opt-in rather than derived. An UNAUTHENTICATED
// request is anchored on its session exactly as it is without this option, so enabling it can
// never make two callers share state on the strength of something neither of them proved; an
// authenticated request whose token carries no task_id is REFUSED rather than session-keyed
// (anchorUnresolved), because one caller alternating token shapes would otherwise split its
// own taint, budgets and antecedents across two buckets.
//
// Task-anchored state deliberately OUTLIVES the session that wrote it, so the transport's
// teardown does not reclaim it (see ClearSessionLabels). Pair this with the Redis backends,
// whose idle TTL reclaims an abandoned task, or bound the in-memory store with
// flowlabelstore.WithMaxKeys.
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
// SAME route-level observe signal the transport's downgrade uses (isObserveDeny via
// fp.audit): a route running under --audit forwards a would-be deny, so that call's
// sequenceBlock antecedent must still be recorded — otherwise a later enforced
// sequenceBlock naming the forwarded tool Peeks empty history and fails open. This
// mirrors WithSkipQuota's own contract ("must still observe sequenceBlock denials
// accurately, which requires ... recording the history that arms it"). A per-constraint
// enforcement:audit is already covered by Constraint.IsAuditOnly(); this adds the
// whole-route --audit case, which never reaches the constraint flag.
func SkipQuota(ctx context.Context) bool {
	v, _ := ctx.Value(ctxSkipQuotaKey{}).(bool)
	return v
}

// WillForwardDeny reports whether a deny for this constraint will be downgraded to a
// forwarded call rather than blocking, so the response still reaches the host.
//
// It is the ONE spelling of the observe-mode union — per-constraint `enforcement: audit`
// OR the whole-route --audit posture (which arrives as SkipQuota on the ctx) — that every
// layer reads: the engine's own obligation stamping, the PDP's willForwardDeny, and the
// transport's isObserveDeny. Gating only on the per-constraint flag would miss the
// standard whole-route --audit deployment, where individual constraints are NOT marked
// audit-only; single-sourcing it here keeps three layers from drifting into three
// slightly different answers, where the narrowest one silently forwards unredacted.
//
// matched may be nil (a no-match deny), which only a route-level --audit forwards. The
// kill-switch and HardDeny exclusions the transport also applies are handled at each call
// site, which has the response in hand.
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
		handlers: make(map[string]ConditionHandler),
		clock:    systemClock{},
	}
	// Register built-ins first so a WithConditionHandler option can override one.
	// The map is fully populated here and never mutated, so Decide reads it
	// lock-free.
	e.registerBuiltins()
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// RecordSessionCall notes that an allowed call to req.TargetName occurred in this
// session, so a later sequenceBlock condition on a different tool can detect it.
//
// It returns a non-nil error only when the counter write itself fails, and
// callers MUST treat that as a fail-closed deny: a missing marker would let a
// later sequenceBlock Peek conclude the antecedent never ran and fail OPEN, so an
// attacker able to induce a transient counter-backend fault could bypass the
// constraint. Surfacing the error keeps this path consistent with every other
// stateful condition.
//
// Recording is indiscriminate among the policy's targets — it marks every allowed
// call whether or not the tool is ever named in an afterTools set — because
// EvaluateConditions sees only the matched constraint and so cannot bound recording
// to known antecedents. A write fault therefore denies every allowed call in a
// session while the backend faults, the deliberate cost of one consistent
// fail-closed rule. The one bound applied is policy-wide: when the policy contains
// NO sequenceBlock at all (WithoutAntecedentRecording), the marker is never read,
// so recording is skipped entirely — which also keeps a counter-write fault on a
// maxCalls-only policy from denying a call whose maxCalls slot runConditions already
// committed (the only case where the fail-closed deny would burn quota for nothing).
//
// A nil return means the write succeeded or there was nothing to record. The
// guards below are legitimate "nothing to record" states: no sequenceBlock in the
// policy, no session ID (history would merge across anonymous callers), no counter,
// and no derivable tool name.
//
// Exported for callers that must record an antecedent on a path EvaluateConditions
// does not reach: in audit (observe) mode a constraint with a failing condition
// returns a deny without recording, yet the transport still forwards the request and
// the tool runs, so a later sequenceBlock would fail OPEN.
func (e *Engine) RecordSessionCall(ctx context.Context, req *capability.EnforceRequest) error {
	if e.skipAntecedentRecording || e.counter == nil || req.SessionID == "" {
		return nil
	}
	// Prefer the explicit target type set by every ManifestPDP entry point; the
	// prefix-derived type is only a fallback for direct ValidateAction callers that
	// leave req.Target nil. Recording the type keeps each namespace's afterTools
	// lookup distinct so a same-named target in another namespace cannot trip it.
	// sessionTargetKey derives the same (type, name) pair maxCallsBucket keys on.
	targetType, tool := sessionTargetKey(req)
	if tool == "" {
		return nil
	}
	// Record a secondary marker keyed the way handleSequenceBlock parses a bare
	// afterTools spelling, so a target whose NAME itself begins with a recognized
	// namespace token still trips the gate when referenced naturally. The lookup runs
	// each afterTools entry through splitEnginePrefix, stripping one token: a tool
	// literally named "system:foo" (recorded verbatim under (tool, "system:foo") below,
	// matched by the explicit "tool:system:foo") would otherwise NEVER match the bare
	// "system:foo", which the lookup resolves to (system, foo) — a silent fail-OPEN of a
	// security gate. Recording both keys makes the explicit and bare spellings symmetric.
	// Skipped when the name carries no recognized prefix (splitEnginePrefix returns it
	// unchanged), so the common case writes exactly one marker. This key is sequenceBlock
	// history only ("seq:"-namespaced); it does not touch any maxCalls bucket.
	//
	// The secondary (bare-spelling) marker is written BEFORE the primary verbatim
	// marker. On the Redis backend the two writes are separate round-trips that can fail
	// independently; if the first succeeds and the second faults, RecordSessionCall
	// returns the error and the call is denied fail-closed — but whichever marker already
	// committed survives. Writing the alias first means a partial write leaves at most the
	// bare-spelling alias key, never the primary verbatim key (the canonical key the
	// explicit, fully-qualified afterTools spelling resolves to), so the explicit spelling
	// stays conservative. This NARROWS the partial-write fail-open rather than closing it:
	// a surviving alias key can still arm the bare afterTools spelling for a denied
	// antecedent; only an atomic multi-key write would close the window fully. Both keys
	// are sequenceBlock history ("seq:"-namespaced) and never touch a maxCalls bucket
	// (those are "maxcalls:"-namespaced, committed separately), so maxCalls accounting is
	// unaffected by this ordering. This holds on EVERY backend, in-memory included: the
	// two writes are two separate calls, each taking the backend's lock on its own, so
	// nothing makes the pair atomic — the ordering above is the whole mitigation.
	//
	// Cross-namespace false-trip caveat: this alias key is derived by splitting the
	// target's NAME on its leading recognized token, which discards the target's REAL
	// type — the same collapse the lookup performs on a bare afterTools spelling. So a
	// resource named "tool:reboot" and a tool named "reboot" both write the alias key
	// (tool, "reboot"): a bare afterTools spelling that resolves to (tool, "reboot") is
	// armed by EITHER. Keying the alias with the target's real type as an extra component
	// cannot fix this without breaking the alias feature — the bare afterTools spelling
	// carries no antecedent type, so the lookup has nothing to match that component
	// against. The direction is conservative (a spurious deny of the blocked call, never
	// a fail-OPEN of the gate), so this is documented rather than "fixed" into a break of
	// the bare-spelling match. Disambiguate by naming the antecedent with its explicit,
	// fully-qualified spelling ("resource:tool:reboot" vs "tool:reboot"), which resolves
	// to the primary verbatim marker and never touches this alias key.
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
// sequenceBlock-history and maxCalls bucket keys. When req.Target is set (every
// ManifestPDP entry point sets it), Target.Name is used VERBATIM — only
// whitespace-trimmed, never engine-prefix-stripped. The afterTools lookup in
// handleSequenceBlock strips exactly one namespace token off the operator-named
// antecedent ("resource:system:foo" -> "system:foo") and keys on the remaining
// name verbatim, so a target whose name itself begins with a recognized namespace
// token (a resource URI "system:foo", or a tool literally named "tool:reboot")
// must keep that token here too. Stripping it (the old splitEnginePrefix path)
// recorded "system:foo" under bare "foo" while the lookup probed "system:foo",
// silently failing the sequenceBlock gate OPEN; it also collapsed two distinct
// targets "foo" and "system:foo" onto one maxCalls bucket. For direct
// ValidateAction callers that leave req.Target nil, fall back to the
// prefix-stripped req.TargetName.
//
// RecordSessionCall additionally writes a secondary sequenceBlock-history marker
// keyed the way the lookup parses the bare/natural spelling (split on the leading
// recognized token), so both the explicit "tool:system:foo" and the bare
// "system:foo" afterTools spellings resolve. That secondary marker is confined to
// sequenceBlock history and never reaches a maxCalls bucket, so this verbatim
// recording remains authoritative for maxCalls.
func sessionTargetName(req *capability.EnforceRequest) string {
	if req.Target != nil {
		if n := strings.TrimSpace(req.Target.Name); n != "" {
			return n
		}
	}
	return strings.TrimSpace(StripEnginePrefix(req.TargetName))
}

// sessionTargetKey derives the (targetType, name) pair that identifies a target in
// both the sequenceBlock-history and maxCalls counter buckets. The type prefers the
// explicit req.Target.Type, falling back to the req.TargetName prefix (bare defaults to
// "tool"); the name comes from sessionTargetName (Target.Name verbatim, else the
// prefix-stripped TargetName). RecordSessionCall and maxCallsBucket both key their
// buckets through it so a direct ValidateAction caller that leaves req.Target nil and
// the antecedent record land on the SAME bucket under the SAME derivation.
// handleSequenceBlock deliberately does NOT use this: it keeps a display-name fallback
// that reports "(unknown)" for an unnamed blocked target.
func sessionTargetKey(req *capability.EnforceRequest) (targetType, name string) {
	targetType, _ = splitEnginePrefix(req.TargetName)
	if req.Target != nil && req.Target.Type != "" {
		targetType = req.Target.Type
	}
	return targetType, sessionTargetName(req)
}

// recordFailureDenial builds the fail-closed response returned when
// RecordSessionCall cannot persist a marker; ValidateAction and
// EvaluateConditions both return it verbatim.
//
// The denial is attributed to sequenceBlock (the only feature the marker backs)
// even though the calling tool need not carry one, with a Details
// "phase":"record" marker to distinguish it from an actual sequenceBlock hit
// (which populates afterTool/blockedTool). auditOnly carries the constraint's
// mode so a transient recording failure under an audit-mode constraint is
// logged-and-forwarded rather than hard-blocked — a backend hiccup is an
// infrastructure fault, not a policy verdict. (CollectObligations deliberately
// ignores AuditOnly, since an unwired directive is an engine bug, not a fault.)
//
// obligations (e.g. redactFields) MUST be preserved: under an audit-mode
// constraint the transport still forwards and applies them, so dropping them
// would leak fields the manifest marked for redaction. For a blocking deny they
// are ignored — harmless either way.
func recordFailureDenial(requestID, now string, auditOnly bool, obligations []capability.Obligation) capability.EnforceResponse {
	return denyResponse(requestID, now, auditOnly, obligations, capability.DenialInfo{
		Code:          capability.ErrCodeConditionFailed,
		ConditionType: capability.ConditionTypeSequenceBlock,
		Message:       "session history recording failed; sequenceBlock state is unreliable",
		Details:       map[string]interface{}{"phase": "record"},
	})
}

// denyResponse builds a deny EnforceResponse from the shared envelope — requestID,
// DecisionDeny, auditOnly, DecidedAt, and optional obligations — wrapping denial. It
// is the single shape for a blocking or audit-mode denial, so a new top-level
// EnforceResponse field (load-bearing per the threat model) is stamped here once
// rather than at every deny site. Every deny path routes through it — recordFailureDenial,
// denyFromConditionError, the unknown-condition-type and argumentSchema denials, the
// no-matching-capability denial, and the unhandled-directive denial — so auditing a
// new field means checking this one constructor, not six call sites. obligations may
// be nil (only recordFailureDenial passes any today).
func denyResponse(requestID, now string, auditOnly bool, obligations []capability.Obligation, denial capability.DenialInfo) capability.EnforceResponse {
	// Every deny the engine produces passes through here, and denial.Details is what
	// the transport hands verbatim to RecordDeny — so this is the one place that can
	// bound the caller-controlled values condition handlers echo without asking each
	// handler's Details literal to remember. See boundDenialDetails.
	denial.Details = boundDenialDetails(denial.Details)
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
// needs-human-approval outcome — from the same envelope denyResponse builds, including
// the boundDenialDetails pass every refusal's details must go through before they reach
// the signed tape. It exists so the escalate decision does not become the one refusal
// shape assembled as a struct literal, silently exempt from a bound the other twenty-odd
// sites inherit by construction.
//
// AuditOnly and Obligations are deliberately absent rather than parameters. An audit-mode
// constraint downgrades a DENY to an observed forward, which is coherent for a policy
// verdict being staged; an escalation is not a verdict being staged, it is "a human has
// not approved this yet", and forwarding it because the target is in observe mode would
// perform exactly the consequential action the ceiling flagged. The transport's
// isObserveDeny consults AuditOnly, so leaving it unset is what keeps an escalation
// unforwardable on an audit route — and an unforwardable refusal has no response to
// redact, so obligations would have nothing to apply to.
func escalateResponse(requestID, now string, denial capability.DenialInfo) capability.EnforceResponse {
	denial.Details = boundDenialDetails(denial.Details)
	return capability.EnforceResponse{
		RequestID: requestID,
		Decision:  capability.DecisionEscalate,
		DecidedAt: now,
		Denial:    &denial,
	}
}

// WithConditionHandler registers a custom condition handler under name. Applied
// after the built-ins (see New), it overwrites one of the same type. The map is
// frozen by the time New returns, so the engine reads it lock-free on the hot path.
//
// A handler that COMMITS state on admit (consumes a sliding-window slot, as the
// built-in maxCalls does) MUST implement CommittingConditionHandler. Deferral is
// keyed off that interface: a plain ConditionHandler (e.g. a ConditionHandlerFunc)
// is treated as a pure predicate and run in the first evaluation pass, so a
// committing handler that does not implement CommittingConditionHandler would burn
// its slot on a call a later condition then denies. Overriding a committing built-in
// (maxCalls) with a plain func therefore changes its evaluation ordering and opts it
// out of the atomic multi-condition commit — implement the interface to preserve
// deferred semantics.
func WithConditionHandler(name string, handler ConditionHandler) Option {
	return func(e *Engine) {
		e.handlers[name] = handler
	}
}

// runPureConditions evaluates every PURE (non-committing) condition on matched in order
// and returns the deferred (quota-consuming) ones for the caller to commit later. It
// returns a non-nil deny response on the first condition with an unknown type or a Handle
// failure (fail closed). requestID and now
// stamp the returned response so it matches the surrounding decision; AuditOnly
// mirrors the matched constraint. Extracted so ValidateAction and
// EvaluateConditions share one dispatch path and cannot diverge.
func (e *Engine) runPureConditions(ctx context.Context, req *capability.EnforceRequest, matched *capability.Constraint, requestID, now string) ([]capability.Condition, *capability.EnforceResponse) {
	// Two passes over matched.Conditions so a consuming condition never burns its
	// quota for a call a later condition denies. The loop just below is the first
	// pass: it walks matched.Conditions once, evaluating every pure-predicate
	// condition (allowedValues, timeWindow, ipRange, sequenceBlock — which only
	// Peeks here) immediately, in declared order, while collecting each deferred
	// (consuming) condition into deferred instead of evaluating it yet — one walk
	// does both the classifying and the evaluating, so there is no second loop that
	// could re-derive the classification differently. The code after the loop is the
	// second pass: it evaluates the collected deferred conditions and commits them.
	// The maxCalls handler commits a sliding-window slot the instant it admits, and that
	// commit is not rolled back on a later failure, so keeping commit in the second
	// pass means a pure predicate that denies is always checked first.
	//
	// One residual case escapes this guarantee: RecordSessionCall runs AFTER
	// runConditions (it must, so a sequenceBlock antecedent marker is not written for
	// a call CollectObligations may still hard-deny), and on a counter-write fault it
	// denies a call whose maxCalls slot was already committed here. It is not rolled
	// back, so that denied call has spent a slot. This is bounded to policies that
	// actually use sequenceBlock: with none, RecordSessionCall is skipped entirely
	// (WithoutAntecedentRecording), so a maxCalls-only policy never burns a slot on a
	// record-fault deny.
	var deferred []capability.Condition
	for _, cond := range matched.Conditions {
		// Defense in depth: a null condition is rejected at manifest load (config
		// validation), so a nil here means a programmatically built constraint. Fail
		// closed rather than panic in ConditionType() — an unevaluable condition must
		// deny, never silently pass (which would drop a restriction the policy declared).
		//
		// A typed-nil pointer — e.g. a (*MaxCallsCondition)(nil) placed into a
		// programmatically built Constraint — is a non-nil interface, so it survives
		// `cond == nil` above, but ConditionType() has a value/pointer receiver that
		// would dereference the nil pointer and panic. Catch it the same way
		// CollectObligations' identical typed-nil guard does.
		if cond == nil || isTypedNil(cond) {
			resp := denyResponse(requestID, now, matched.IsAuditOnly(), nil, capability.DenialInfo{
				Code: capability.ErrCodeConditionFailed,
				// HardDeny, matching the two sibling engine-bug denies in this function: an
				// unevaluable condition is a construction fault, not a downgradable policy
				// verdict. Without it an audit-mode constraint (or a route under --audit)
				// forwards a call whose declared restriction was never checked even once —
				// the same fail-open shape as admitting a committing bucket unchecked,
				// which is precisely why those two carry the flag.
				HardDeny: true,
				Message:  "constraint carries a null condition that cannot be evaluated",
			})
			return nil, &resp
		}
		if e.isDeferredCondition(cond.ConditionType()) {
			deferred = append(deferred, cond)
			continue
		}
		if deny := e.evalCondition(ctx, cond, req, matched, requestID, now); deny != nil {
			return nil, deny
		}
	}

	return deferred, nil
}

// prepareAndAdmit evaluates ONE committing condition end to end: its pure checks and bucket
// derivation (PrepareCommit), then the admission of that single bucket. It is the
// ConditionHandler path every committing handler's Handle delegates to, so a handler has one
// implementation of its own semantics rather than two that can drift — which they had, with
// observe mode skipping a pure check on one path and evaluating it on the other.
//
// The engine's own deferred pass does NOT come through here: it prepares every condition and
// admits the whole set atomically, which is the only way a multi-condition constraint gets a
// TOCTOU-free commit.
func (e *Engine) prepareAndAdmit(ctx context.Context, h CommittingConditionHandler, cond capability.Condition, req *capability.EnforceRequest) *ConditionError {
	commit, skip, condErr := h.PrepareCommit(ctx, cond, req)
	if condErr != nil {
		return condErr
	}
	if skip || !commit.Commits() {
		return nil
	}
	if e.counter == nil {
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: cond.ConditionType(),
			Message:       "call counter not configured",
		}
	}
	admitted, _, total, retryAfter, err := e.counter.AdmitAll(ctx, []capability.QuotaBucket{commit.Bucket})
	if err != nil {
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: cond.ConditionType(),
			Message:       fmt.Sprintf("call counter error: %v", err),
		}
	}
	if admitted {
		return nil
	}
	if commit.Deny == nil {
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: cond.ConditionType(),
			Message:       "committing condition handler supplied a nil Deny callback",
		}
	}
	return commit.Deny(total, retryAfter)
}

// isTypedNil reports whether v is a non-nil interface value wrapping a nil pointer — e.g. a
// (*MaxCallsCondition)(nil) boxed into a capability.Condition, or a
// (*RedactFieldsDirective)(nil) boxed into a capability.Directive. Such a value survives a
// plain `v == nil` check (the interface itself is non-nil) but would panic a
// value/pointer-receiver method that dereferences it (e.g. ConditionType(), ToObligation()).
// Delegates to capability.IsTypedNil, the single source of truth for this guard, shared by
// runPureConditions' condition check, CollectObligations' directive check, and the
// config-loader validation guards, so the copies cannot drift.
func isTypedNil(v interface{}) bool {
	return capability.IsTypedNil(v)
}

// commitDeferredConditions runs the SECOND pass: it prepares every deferred condition —
// which runs that condition's pure checks — and admits the resulting buckets in ONE atomic
// backend call. It is reached only after every check that can refuse the call without state
// has passed (the pure predicates, the obligation collection, and the EFFECT CEILING), so
// nothing here is charged to a call that is then refused.
//
// One path for one and for many. The single-deferred case used to bypass this and commit
// through the handler's own Handle, and the two paths had already diverged: under observe
// mode this one skipped a condition ENTIRELY, including the pure per-call bound Handle
// still evaluated, so the same policy was enforced differently depending on how many
// deferred conditions a constraint happened to carry.
//
// The buckets may MIX accountings — a maxCalls count beside a cumulative blastRadius
// magnitude — because the backend admits them together (capability.CallCounter.AdmitAll).
// The engine therefore has no compatibility table to maintain and no combination to refuse:
// "can these be admitted together" is answered once, by the layer that does the admitting.
func (e *Engine) commitDeferredConditions(ctx context.Context, req *capability.EnforceRequest, matched *capability.Constraint, deferred []capability.Condition, requestID, now string) *capability.EnforceResponse {
	var (
		buckets []capability.QuotaBucket
		denies  []func(total float64, retryAfter time.Duration) *ConditionError
		// bucketTypes[i] is the condition type that produced buckets[i], kept so a fault
		// spanning the WHOLE commit can still be attributed when every bucket came from one
		// condition type (see attributableType).
		bucketTypes []string
		// committing counts the conditions that actually consume quota, which is NOT
		// len(deferred): deferral is keyed by condition TYPE, so a condition whose type can
		// commit but whose configuration does not (a per-call-only blastRadius) arrives here
		// too and reports no bucket.
		committing int
	)
	// Track buckets skipped under SkipQuota so a PARTIAL skip (some skipped, some
	// committing) can be caught after the loop. The loop prepares EVERY condition so a later
	// one's validation condErr surfaces even when an earlier one skipped — returning on the
	// first skip let an observe-mode call mask a later committing condition's error as an
	// allow where enforce mode would deny.
	skipped := 0
	for _, cond := range deferred {
		condType := cond.ConditionType()
		ch, ok := e.committingHandler(condType)
		if !ok {
			// Defensive: deferred was gathered via isDeferredCondition, which reports true
			// only for a registered CommittingConditionHandler, so this is unreachable.
			// Fail closed if the registry changed under us.
			resp := denyResponse(requestID, now, matched.IsAuditOnly(), nil, capability.DenialInfo{
				Code:          capability.ErrCodeConditionFailed,
				ConditionType: condType,
				Message:       fmt.Sprintf("deferred condition %q has no committing handler", condType),
			})
			return &resp
		}
		commit, skip, condErr := ch.PrepareCommit(ctx, cond, req)
		// A condErr is checked BEFORE skip is honored. PrepareCommit's contract puts no
		// exclusion between the two, so a handler may legitimately report both — a pure
		// check that failed on a condition that also skips its commit under SkipQuota.
		// Honoring skip first would discard that verdict, and if every condition skipped the
		// call would then be ALLOWED under observe while enforce denies it: precisely the
		// observe/enforce divergence this function exists to prevent.
		if condErr != nil {
			return denyFromConditionError(condErr, matched, requestID, now)
		}
		if skip {
			// skip must be uniform across the constraint — the contract requires it to be
			// derived solely from ctx (SkipQuota). A handler that reports skip for some other
			// reason (its own config/arguments) would leave the remaining committing
			// conditions unchecked: a fail-open. Assert the contract and fail closed on a
			// per-bucket violation.
			if !SkipQuota(ctx) {
				resp := denyResponse(requestID, now, matched.IsAuditOnly(), nil, capability.DenialInfo{
					Code:          capability.ErrCodeConditionFailed,
					ConditionType: condType,
					// HardDeny: a handler violating the skip contract is an engine/plugin bug,
					// not a downgradable policy verdict, so it must block even under an
					// audit-mode constraint rather than being forwarded with quota unconsumed.
					HardDeny: true,
					Message:  fmt.Sprintf("committing condition %q reported a non-uniform skip; deferred commit requires skip to be derived solely from request context", condType),
				})
				return &resp
			}
			skipped++
			committing++
			continue
		}
		if !commit.Commits() {
			// This particular condition consumes nothing. Its pure checks ran inside
			// PrepareCommit and passed, so there is simply no bucket to admit.
			continue
		}
		committing++
		buckets = append(buckets, commit.Bucket)
		denies = append(denies, commit.Deny)
		bucketTypes = append(bucketTypes, condType)
	}

	// Nothing on this constraint actually consumes quota (every deferred condition was a
	// pure predicate of a committing type), so there is no commit to make.
	if committing == 0 {
		return nil
	}
	// Every bucket skipped under SkipQuota (audit/observe): quota must not be consumed, so
	// record nothing and allow — the ctx-driven skip held for all of them.
	if skipped == committing {
		return nil
	}
	// A PARTIAL skip — some skipped, others produced a bucket — is a non-uniform skip the
	// per-condition assertion above cannot catch (each skipping one individually satisfied
	// SkipQuota). Admitting the committing buckets while silently dropping the skipped ones
	// is a fail-open, so fail closed.
	if skipped > 0 {
		resp := denyResponse(requestID, now, matched.IsAuditOnly(), nil, capability.DenialInfo{
			Code: capability.ErrCodeConditionFailed,
			// HardDeny, or this guard can never actually block: a partial skip is reachable
			// only when SkipQuota(ctx) is set, which the binary sets only on a route running
			// --audit — and on that route the transport downgrades and FORWARDS any
			// non-HardDeny verdict.
			HardDeny: true,
			Message:  "deferred commit received a non-uniform skip across buckets; skip must hold for every committing condition or none",
		})
		return &resp
	}

	// A committing condition needs the call-counter backend. Every in-tree handler funnels
	// through a bucket derivation whose nil-counter guard already surfaced as a
	// PrepareCommit condErr above, but a custom CommittingConditionHandler need not, so
	// guard here rather than dereferencing a nil counter and panicking the enforcement
	// goroutine.
	if e.counter == nil {
		return denyFromConditionError(&ConditionError{
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
		return denyFromConditionError(&ConditionError{
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
			return denyFromConditionError(&ConditionError{
				Code:          capability.ErrCodeConditionFailed,
				ConditionType: attributableType(bucketTypes),
				Message:       fmt.Sprintf("call counter returned out-of-range denied bucket index %d (have %d buckets)", deniedIndex, len(denies)),
			}, matched, requestID, now)
		}
		if denies[deniedIndex] == nil {
			// A committing handler's PrepareCommit populated a bucket but left Deny nil — a
			// handler bug. The bucket IS attributable here, unlike the batch-wide fault above.
			return denyFromConditionError(&ConditionError{
				Code:          capability.ErrCodeConditionFailed,
				ConditionType: bucketTypes[deniedIndex],
				Message:       fmt.Sprintf("committing condition handler for bucket index %d supplied a nil Deny callback", deniedIndex),
			}, matched, requestID, now)
		}
		return denyFromConditionError(denies[deniedIndex](total, retryAfter), matched, requestID, now)
	}
	return nil
}

// attributableType reports the one condition type every bucket in a commit came from, or
// "" when the batch mixes types. It exists for the failures that belong to the COMMIT
// rather than to a bucket — a backend fault, a malformed reply — which still deserve a
// structured condition type whenever there is an unambiguous one to give. Naming a type on
// a mixed batch would be a guess, and a structured audit field must never carry a guess.
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
		Details:       condErr.Details,
	})
	return &resp
}

// committingHandler returns the registered handler for condType when it commits
// state on admit (implements CommittingConditionHandler), so both the deferred
// ordering in runConditions and the atomic multi-condition commit dispatch through
// the same registry. A custom WithConditionHandler that commits state participates
// automatically; there is no separate list of "deferred" types to keep in sync.
func (e *Engine) committingHandler(condType string) (CommittingConditionHandler, bool) {
	h, ok := e.handlers[condType]
	if !ok {
		return nil, false
	}
	ch, ok := h.(CommittingConditionHandler)
	return ch, ok
}

// isDeferredCondition reports whether a condition must run after all pure
// predicates because its handler commits state on admit (with no rollback on a
// later denial), which would otherwise let a later denial waste the consumed slot.
func (e *Engine) isDeferredCondition(condType string) bool {
	_, ok := e.committingHandler(condType)
	return ok
}

// evalCondition looks up and runs a single condition handler. It returns a deny
// response when the condition fails (or fail-closed when the type is unknown) and
// nil when it passes.
func (e *Engine) evalCondition(ctx context.Context, cond capability.Condition, req *capability.EnforceRequest, matched *capability.Constraint, requestID, now string) *capability.EnforceResponse {
	condType := cond.ConditionType()

	handler, exists := e.handlers[condType]

	if !exists {
		// Fail closed on unknown condition types.
		resp := denyResponse(requestID, now, matched.IsAuditOnly(), nil, capability.DenialInfo{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: condType,
			Message:       fmt.Sprintf("unknown condition type: %s", condType),
		})
		return &resp
	}

	if condErr := handler.Handle(ctx, cond, req); condErr != nil {
		return denyFromConditionError(condErr, matched, requestID, now)
	}
	return nil
}

// evaluateMatched runs the shared allow tail once a winning constraint is selected:
// it exposes the constraint's directives via ctx (not written onto req, which would
// race concurrent readers) so a policy condition and BuildRegoInput see them, then
// evaluates every condition and — on allow — collects obligations BEFORE recording the
// call in session history. That ordering is load-bearing: recording first would let a
// later sequenceBlock Peek treat a hard-denied (never-forwarded) call as "run".
// The condition evaluation is TWO passes with the ceiling between them: every pure
// predicate runs first, then the ceiling, then the quota-consuming commits — so no budget,
// slot or label is charged to a call that a later check still refuses. runPureConditions,
// CollectObligations, checkEffectCeiling, commitDeferredConditions and RecordSessionCall
// each short-circuit to their own deny.
// Shared by ValidateAction and EvaluateConditions so the two cannot diverge on this
// security-critical ordering.
func (e *Engine) evaluateMatched(ctx context.Context, req *capability.EnforceRequest, matched *capability.Constraint, requestID, now string) (resp capability.EnforceResponse) {
	// Done before conditions run so a policy condition can inspect the obligations
	// that will apply on allow.
	ctx = withDirectives(ctx, matched.Directives)

	// Resolve the constraint's effect contract against THIS call's arguments once, and
	// thread it: the effectClass condition, the blastRadius condition, and the ceiling
	// below all read this one value, so they cannot disagree about what the call's effect
	// was. A constraint with no contract resolves to the fail-closed default
	// (irreversible, unquantified) — the flywheel that makes an unannotated target
	// escalate under any ceiling.
	effect := capability.ResolveEffect(matched.Effect, req.Arguments)
	ctx = withResolvedEffect(ctx, effect)

	// Collect the matched constraint's obligations UP FRONT and stamp them onto every
	// deny this function returns that will be FORWARDED rather than blocked.
	//
	// An obligation (redactFields) is a property of the matched CONSTRAINT, not of the
	// allow decision: under an audit-mode constraint — or a route running --audit — a
	// deny is downgraded to a forwarded call, and the transport applies redaction only
	// when the response carries obligations. A downgradable deny built with nil
	// obligations therefore gives a request whose condition FAILED strictly fewer
	// protections than one that passed: the upstream response reaches the host with the
	// fields the manifest marked for redaction intact. Stamping at the single point every
	// matched-constraint deny funnels through makes that structural rather than per-site —
	// the ManifestPDP fills the same gap one layer up, but a direct caller of the exported
	// ValidateAction / EvaluateConditions never reaches that layer.
	//
	// The deny CollectObligations can itself return (an unwired directive — an engine
	// bug) is deliberately held back to the point the original ordering returned it,
	// after runConditions below. Returning it here would preempt the condition verdict,
	// and that deny sets HardDeny: on an audit route a call a condition would have
	// denied-and-forwarded would instead be BLOCKED, because isObserveDeny refuses to
	// downgrade a HardDeny. A wiretap route documented never to block must not start
	// blocking over an engine bug in a directive it was going to apply post-allow.
	obligations, obligDeny := e.CollectObligations(req.Delegation, matched, requestID, now)
	if WillForwardDeny(ctx, matched) {
		defer func() {
			// The test is `!= DecisionAllow`, not `== DecisionDeny`, matching the transport's
			// own fail-closed gate and the PDP's withForwardObligationsFor: a response with an
			// unset Decision is FORWARDED there, so gating on `== DecisionDeny` here would let
			// exactly that shape through unredacted — the fail-open direction.
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

	// Peek the incoming accumulated flow-label set up front (only for flow-relevant
	// constraints, and skipped entirely when the whole policy has no flow — skipFlow —
	// so a non-flow policy pays no scan or round-trip). It reflects what flowed IN,
	// before this call's own output is recorded below. peekSessionLabels fails closed on
	// an unreadable state, so a source-only constraint cannot silently under-report it.
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
		// Thread the snapshot so handleFlowLabel reuses it (one atomic read, not two),
		// and stamp it onto EVERY deny exit below via one defer so no hand-stamped exit
		// can be forgotten. The allow return sets CarriedLabels explicitly, so the
		// defer's deny-only guard skips it.
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

	// The delegation authority gate. It sits here — after the obligation and carried-label
	// defers are installed, so a downgraded (observe-mode) refusal still carries the
	// redactions and the label snapshot every other non-allow exit carries, and before the
	// conditions, because it does not depend on them: the manifest may permit this target and
	// every condition may pass, and the call is still one this delegate was never handed.
	if delegDeny := e.checkDelegationTarget(req, matched.IsAuditOnly(), requestID, now); delegDeny != nil {
		return *delegDeny
	}

	// An authenticated caller this engine cannot anchor as configured. It sits beside the
	// delegation gate for the same reason: it is a property of the request rather than of the
	// conditions, and a call that cannot be accounted must not reach the state commits below.
	// Falling back to session keying here would let one caller split its own taint, budgets
	// and antecedents across two buckets by alternating tokens — see anchorUnresolved.
	if e.anchorUnresolved(req) {
		return denyResponse(requestID, now, matched.IsAuditOnly(), nil, capability.DenialInfo{
			Code:          capability.ErrCodeMissingContext,
			ConditionType: anchorKindTask,
			// HardDeny, which puts this beside the unapproved declassification and the
			// over-ceiling effect rather than beside an ordinary authorization verdict. A
			// downgradable refusal is FORWARDED on an audit-only constraint, and the observe
			// path's own antecedent recorder then writes this call's labels and sequence marker
			// through stateAnchor — which, with no task id to resolve, keys them on the SESSION.
			// So the very state split this check exists to refuse is what the downgrade
			// performs, on a route whose other constraints are reading the task-keyed bucket.
			// It is a failed state write, not a verdict being staged, and an operator staging
			// task anchoring still gets the diagnostic: the refusal is on the tape either way,
			// carrying the reason.
			HardDeny: true,
			Message:  "this route anchors enforcement state on the task, but the presented token carries no mcp.task_id; refusing rather than accounting this call against a second, session-keyed bucket (fail closed)",
			Details:  map[string]interface{}{"anchor": anchorKindTask, "reason": "no_task_id"},
		})
	}

	// PASS ONE: the pure predicates. The deferred (quota-consuming) conditions are
	// collected but NOT committed here — the ceiling below has to be able to refuse the
	// call before anything is charged to it.
	deferred, deny := e.runPureConditions(ctx, req, matched, requestID, now)
	if deny != nil {
		return *deny
	}

	// The held-back CollectObligations deny is returned HERE, exactly where the
	// pre-stamping ordering returned it: after the conditions, before the session-history
	// write. Both positions are load-bearing — after the conditions so an engine bug in a
	// directive cannot preempt (and, on an audit route, harden) a condition verdict;
	// before the history write so a hard deny does not leave a phantom antecedent a later
	// sequenceBlock Peek would see as "run".
	if obligDeny != nil {
		return *obligDeny
	}

	// The tool-agnostic consequence bound, applied to an action the conditions have
	// already allowed. It runs BEFORE the state commit below, for the same reason the
	// obligation deny does: an over-ceiling call is not forwarded, so it must leave
	// neither a phantom sequenceBlock antecedent nor a stranded flow label behind.
	if ceilingDeny := e.checkEffectCeiling(effect, matched, carriedLabels, requestID, now); ceilingDeny != nil {
		return *ceilingDeny
	}

	// The delegated consequence bound, on the same pre-commit side of the line and reading
	// the SAME resolved effect. It runs after the policy's own ceiling so an action over both
	// reports the ceiling: the ceiling is the operator's bound on what may happen at all,
	// while this one is about who was allowed to ask for it, and fixing the second while the
	// first still refuses would be wasted work.
	if delegDeny := e.checkDelegationEffectClass(req, effect, matched.IsAuditOnly(), requestID, now); delegDeny != nil {
		return *delegDeny
	}

	// The approval gate for the one directive that REMOVES a flow label. It sits with the
	// ceiling on the pre-commit side of the line for the same reason: an unapproved
	// declassification is refused and never forwarded, so it must not spend a quota slot,
	// write an antecedent, or touch the session's label set. It runs AFTER the ceiling so a
	// call that is over the consequence bound reports that — the bound is the more
	// fundamental refusal, and an operator who fixes the approval first would otherwise
	// discover the ceiling second.
	decl, declDeny := e.checkDeclassify(ctx, req, matched, carriedLabels, requestID, now)
	if declDeny != nil {
		return *declDeny
	}

	// PASS TWO: commit the deferred conditions, now that nothing left can refuse the call
	// without state. This ordering is load-bearing and was wrong: with the commit inside
	// the first pass, an over-ceiling call spent its cumulative blastRadius budget before
	// the ceiling ever ran, so four never-forwarded escalations could exhaust a session's
	// whole hourly budget and deny the legal calls that followed — the same phantom state
	// the antecedent and flow-label ordering below exists to prevent, in a third currency.
	if deny := e.commitDeferredConditions(ctx, req, matched, deferred, requestID, now); deny != nil {
		return *deny
	}

	// Commit this call's sequenceBlock antecedent and flow labels as a single
	// all-or-nothing unit (recordSourceCall): the flow write goes first (the
	// FlowLabelStore supports targeted rollback), the seq antecedent second, and a fault
	// on the second write rolls the first back — so a hard-denied call that is never
	// forwarded leaves NEITHER a phantom seq antecedent nor a stranded flow label.
	// Each half still fails closed on its
	// own fault: a flow-write fault is a HARD deny (labelRecordFailureDenial, so an
	// audit-mode source whose label did not persist is not forwarded unlabeled); a
	// seq-write fault denies via recordFailureDenial. The per-session decision lock
	// serializes this critical section, so the
	// rollback removes exactly this call's additions with no concurrent writer.
	labelsOut, cerr := e.recordSourceCall(ctx, req, matched, flowRelevant, carriedLabels, decl)
	if cerr != nil {
		if cerr.Declassify {
			// decl.LedgerID, not the outcome: this arm is reached AFTER the burn on the
			// antecedent-fault path, so the grant may already be spent for a call that is
			// about to hard-deny and never run. Naming it here is the only way that fact
			// reaches the tape — the refusal carries no LabelsPendingClear, so nothing
			// downstream could infer it, and an operator reconciling one-shot approvals
			// would believe this one was still live. The burn arm itself reaches here too,
			// where the grant was NOT spent (the losing side of a race records nothing), so
			// the id rides only when the commit got past the burn.
			return declassifyRecordFailureDenial(requestID, now, matched.IsAuditOnly(), cerr.SpentApprovalID)
		}
		if cerr.Flow {
			// No obligations: this one sets HardDeny, so it is never downgraded to a
			// forward and has no response to redact. Passing them would break the invariant
			// the stamping defer above upholds — that obligations on a deny mean "this one
			// is really a forward" — and contradict the threat model's "a hard deny carries
			// no obligations".
			return labelRecordFailureDenial(requestID, now, matched.IsAuditOnly(), nil)
		}
		return recordFailureDenial(requestID, now, matched.IsAuditOnly(), obligations)
	}

	// The clear itself is NOT applied here; it is handed to the caller to commit once the
	// call has actually run (see LabelsPendingClear and CommitDeclassification).
	//
	// What is handed over is the INTERSECTION with what the anchor is carrying as of this
	// decision — resolved here, inside the decision's critical section, never re-derived at
	// commit time. That is what bounds the clear to the taint the sanitizing call actually
	// observed: a source read decided AFTER this point contributes a label that is not in
	// this set, so the commit cannot remove it. Re-reading the anchor at commit time instead
	// let one call's approved clear launder a concurrent read's brand-new taint, which is the
	// mirror of the fail-open the deferral exists to close, and a set store cannot tell the
	// two occurrences of a label apart afterwards.
	//
	// It is also why the set is empty for a no-op clear: nothing to remove, so the commit is
	// skipped entirely and the tape records no declassification. The grant is spent all the
	// same, which is what SpentApprovalID is for — populated only for a single-use grant, and
	// only here, past the burn, so it names a grant this call really did spend. That is a
	// distinct fact from ApprovalID: the grant is spent whether or not a label moves, and
	// whether or not the clear happens at all.
	pendingClear := intersectLabels(decl.Labels, unionLabels(carriedLabels, labelsOut))
	var spentApprovalID string
	if decl.LedgerID != "" {
		spentApprovalID = decl.ApprovalID
	}

	return capability.EnforceResponse{
		RequestID:   requestID,
		Decision:    capability.DecisionAllow,
		Obligations: obligations,
		DecidedAt:   now,
		AuditOnly:   matched.IsAuditOnly(),
		LabelsOut:   labelsOut,

		LabelsPendingClear: pendingClear,
		Approver:           decl.Approver,
		ApprovalID:         decl.ApprovalID,
		SpentApprovalID:    spentApprovalID,
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
		// No matched constraint, so no audit-mode posture to inherit: a plain block —
		// UNLESS the route runs --audit (SkipQuota), which forwards even a no-match deny.
		// A forwarded response must carry the redact obligations or it reaches the host
		// unmasked, so fill them from every capability NAMING this target, regardless of
		// principal scoping. That is deliberately wider than FindMatchingCapability's
		// selection: no entry governs this caller, and any entry declaring a field of this
		// target redactable is reason enough to mask it on a response about to be
		// forwarded. On an enforce route this is skipped and the deny blocks with nothing.
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
			// obligations or the forwarded response reaches the host with the fields the
			// manifest marked for redaction intact — the same rule evaluateMatched applies
			// to every deny it produces, restated here because this site returns before
			// reaching it. A blocking deny stays free of obligations (nothing is
			// forwarded); an unwired directive discovered while collecting is an engine
			// bug, so its hard deny wins rather than forwarding unredacted.
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

// resolveRequestTarget resolves a request's namespace type and bare target name: the
// type from an explicit req.Target.Type when present, else from the req.TargetName
// prefix (a bare name defaults to "tool"). Splitting the prefix lets a
// "tool:read_file" manifest entry match a bare TargetName "read_file" while a prefixed
// TargetName still works.
//
// The verbatim Target.Name is preferred over the prefix-split bare name, and that rule
// is the reason this is a function rather than eight inline lines repeated per caller.
// A resource or prompt may itself be named with a leading recognized token (a resource
// "system:config", a prompt "tool:reboot"): splitEnginePrefix would wrongly strip the
// token and leave "config", so the covering "resource:system:config" constraint (bare
// name "system:config") never matches and legitimate access is denied. The PDP
// selection path derives the bare name from Target.Name verbatim; this mirrors it so
// the engine and proxy agree on what a policy means. It was copy-pasted at two call
// sites with the rationale written out at only one of them.
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

// NoMatchScore is the sentinel for "no matching capability found yet" — below
// any real resSpecificity/ResourceSpecificity score. Exported so a caller that
// needs the same "nothing has matched" floor for its own scan (internal/drift's
// coveringMatches, computing the unscoped-match cutoff) uses this value rather
// than re-deriving its own sentinel literal.
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
// Exported because this predicate is security-relevant and has two consumers: the
// engine's FindMatchingCapability and the proxy's internal/pdp.findConstraint. They
// were character-for-character copies, so a precedence change applied to one would
// have left the proxy and the engine silently selecting different constraints for
// the same request. Scores need only be mutually comparable, not equal, across
// consumers — the engine scales by resourceScoreWeight and the PDP does not, which
// is a monotonic transform and so preserves every comparison this makes.
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

// resourceScoreWeight scales the resource-specificity score, reserving the
// low-order range [0, resourceScoreWeight) as headroom for a possible future
// additive per-action score that could break ties only between equal-resource
// capabilities, never reorder ones whose specificity already differs.
const resourceScoreWeight = 10

// FindMatchingCapability returns the most specific capability that matches the
// request, or nil if none match. Tie-breaking is stable: at equal specificity, the
// first in the list wins.
//
// Exported so a caller that needs the matched constraint rather than a decision can
// reuse the engine's selection logic — today that is pkg/enforcement's own
// schema/obligation helpers and external embedders. The proxy does NOT route through
// it: internal/pdp.findConstraint runs its own scan over pre-split targets, sharing
// only the tiebreak (see ConstraintScorer) and the match/specificity primitives
// (MatchesResource, ResourceSpecificity). Change the precedence rule in
// ConstraintScorer, not here.
func (e *Engine) FindMatchingCapability(req *capability.EnforceRequest, capabilities []capability.Constraint) *capability.Constraint {
	reqType, bareToolName := resolveRequestTarget(req)
	scorer := NewConstraintScorer()
	for i := range capabilities {
		constraint := &capabilities[i]
		// The namespace type must match on both sides; comparing only bare names
		// would let a "resource:*" constraint approve any tool call. A bare untyped
		// req.TargetName defaults to "tool".
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
// capability whose namespace type and target pattern match the request, IGNORING
// principal scoping and the action check.
//
// It answers "what did the manifest declare about this target", as opposed to
// FindMatchingCapability's "which entry governs this caller" — the right question when no
// entry governs the caller at all yet the deny is about to be forwarded under --audit.
// The returned constraint carries no enforcement mode and no conditions: it exists only
// to be handed to CollectObligations.
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

// StripEnginePrefix removes the leading "type:" prefix from a constraint
// Target field, returning the bare name/pattern. Recognized prefixes are
// "tool", "resource", "prompt", "system". Bare patterns (no prefix) are
// returned unchanged. Exported so manifest validation recognizes the same prefixes
// the engine applies at runtime: an entry whose prefix is not a recognized namespace
// is returned unchanged — the signal load-time validation uses to reject an afterTools
// entry that would otherwise fail open at lookup.
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
// CollectObligations fails closed (ENFORCEMENT_ERROR) for any obligation type not
// listed here, so a new directive whose ToObligation returns an unrecognized type is
// caught at policy-evaluation time rather than silently passing through to an
// unhandled path — silently dropping it would forward the response without a declared
// post-processing step (e.g. an un-applied redaction leaks the field). Register both
// the obligation type AND its handler in ApplyRedactObligs (or the analogous consumer)
// when adding a new directive.
//
// That deny is a hard ENFORCEMENT_ERROR and deliberately NOT AuditOnly even under an
// audit-mode constraint: an unwired directive is an engine bug, not a policy verdict,
// so "fail closed on ambiguity" wins over "audit never blocks".
var knownObligationTypes = map[string]bool{
	capability.DirectiveTypeRedactFields: true,
}

// CollectObligations turns the matched constraint's directives into the post-allow
// obligations the transport applies to the upstream response. It runs only on the
// allow path; a directive MUST NOT change the allow/deny decision.
//
// It is exported for the external decision layer (the PDP), which stamps these onto an
// audit-mode deny it downgrades to a forwarded call. A downgraded (observe-mode) deny
// is still forwarded to the host, so it must carry the same redactFields obligations a
// genuine allow of this constraint would — otherwise the transport forwards the
// upstream response unredacted (redaction runs only when resp.Obligations is non-empty),
// silently dropping the manifest's declared redaction on the deny-then-observe path.
// The allow path and the downgrade path therefore call the SAME function — the
// labelOutput skip, the typed-nil-directive skip, and the fail-closed HardDeny for an
// unwired directive type — so they cannot drift on which directives translate to which
// obligations. requestID and now stamp the fail-closed response the unwired-directive
// guard returns, so it matches the surrounding decision.
func (e *Engine) CollectObligations(chain *capability.DelegationChain, matched *capability.Constraint, requestID, now string) ([]capability.Obligation, *capability.EnforceResponse) {
	var obligations []capability.Obligation
	// The delegation chain's composed redactFields, first so it applies even to a constraint
	// carrying no directives at all. It is a parameter rather than something the caller
	// unions on afterwards because there are five call sites — the allow path, two no-match/
	// schema deny paths, and the PDP's two audit-downgrade paths — and the ones that matter
	// most for a leak are the downgrades, which are exactly the ones easiest to forget. A
	// signature that cannot be called without deciding what the chain contributes makes
	// forgetting impossible.
	if ob := delegatedRedaction(chain); ob != nil {
		obligations = append(obligations, *ob)
	}
	for _, dir := range matched.Directives {
		if dir == nil {
			continue
		}
		// A typed-nil pointer — e.g. a (*RedactFieldsDirective)(nil) placed into a
		// programmatically built Constraint — is a non-nil interface, so it survives
		// the `dir == nil` check above, but ToObligation has a value receiver and would
		// dereference the nil pointer and panic. Skip it (the manifest loader never
		// produces one; this preserves the prior type switch's explicit nil-pointer
		// guard so a constructed Constraint cannot crash the engine on a fail-closed path).
		if isTypedNil(dir) {
			continue
		}
		// labelOutput and declassify are enforce-time state directives, not response
		// obligations: their effect is the session-label write (recordLabels' Add and
		// clearLabels' Remove) the engine performs on allow, so they produce no post-allow
		// response action. Skip them before ToObligation so they are neither applied to the
		// response nor tripped by the unknown-obligation guard.
		switch dir.DirectiveType() {
		case capability.DirectiveTypeLabelOutput, capability.DirectiveTypeDeclassify:
			continue
		}
		ob := dir.ToObligation()
		if !knownObligationTypes[ob.Type] {
			resp := denyResponse(requestID, now, false, nil, capability.DenialInfo{
				Code: capability.ErrCodeEnforcementError,
				// HardDeny so the verdict survives both decideTarget's stamp() and the
				// transport's isObserveDeny gate: an unwired directive is an engine bug, not
				// a downgradable policy verdict, so it must block even under an audit-mode
				// constraint (without this, stamp would re-flip AuditOnly to true and the
				// call would be forwarded — re-opening the fail-closed deny this returns).
				HardDeny: true,
				Message:  fmt.Sprintf("unhandled obligation type %q from directive %T; register it in knownObligationTypes and implement its consumer", ob.Type, dir),
			})
			return nil, &resp
		}
		obligations = append(obligations, ob)
	}
	return obligations, nil
}

// MatchesResource reports whether a capability resource pattern matches the tool
// name, using [path.Match] glob semantics (*, ?, [abc]); "*" matches any name.
// Resources use ':' as a namespace separator (not '/'), so '*' matches across
// colons (e.g. "file:*.csv" matches "file:data.csv").
//
// '/' is the one separator '*' does NOT cross: [path.Match] treats it as a path
// separator, and there is no '**' for targets. A URI-path target therefore covers
// exactly one level — "file:///data/*" matches "file:///data/report.csv" but NOT
// "file:///data/2026/report.csv". That errs deny (a nested resource is refused, never
// wrongly allowed), but it is the operator trap on the most common resource-target
// shape: cover deeper levels with an explicit per-level entry
// ("file:///data/*/*"). Documented for operators in
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

// actionPermitted reports whether the actions list permits the call for the given
// target type. Accepted verbs are the namespace's canonical action ("call"/tool,
// "read"/resource, "get"/prompt, "allow"/system) plus "*";
// capability.ValidateActionForTargetType is the single source of truth, shared
// with the loader. An empty actions list fails closed, so a programmatically
// built or bypass-loaded constraint cannot accidentally grant access.
func actionPermitted(actions []string, targetType capability.TargetType) bool {
	for _, a := range actions {
		if capability.ValidateActionForTargetType(targetType, a) == nil {
			return true
		}
	}
	return false
}

// resourceSpecificityLiteralWeight is the per-literal-rune weight in the
// specificity score. It deliberately exceeds maxWildcardTiebreak so a pattern
// with one more literal rune always outranks one with fewer literals regardless
// of either pattern's wildcard count.
const resourceSpecificityLiteralWeight = 10

// maxWildcardTiebreak clamps the wildcard tiebreaker strictly below one literal
// step. wildcardCount is otherwise unbounded (each '*', '?', "[...]" adds 1), so a
// pattern with >= 10 metacharacters could subtract a full literal step and let a
// looser pattern outrank a more-specific one. Clamping keeps "fewer wildcards" a
// pure tiebreaker between patterns of equal literal count.
const maxWildcardTiebreak = resourceSpecificityLiteralWeight - 1

// exactMatchSpecificity is the score for an exact (resource == toolName) match. It
// must dominate every glob's formula score, which is uncapped and grows with
// literal-rune count, so a smaller sentinel would be beaten by a long-literal
// glob. 1<<27 is far above any realistic literalCount*10 (a glob would need ~13M
// literal runes to reach it) yet small enough that exactMatchSpecificity *
// resourceScoreWeight (10) stays well within a 32-bit int — ResourceSpecificity
// returns int, so the sentinel and the FindMatchingCapability multiply must both
// be representable on 32-bit targets (GOARCH=386, arm, mips), matching the 32-bit
// safety pkg/callcounter already engineers for.
const exactMatchSpecificity = 1 << 27

// ResourceSpecificity scores how specifically a capability's resource pattern matches
// toolName, so FindMatchingCapability can select the most specific of several matching
// capabilities. An exact literal match scores exactMatchSpecificity; glob patterns rank
// below it by how much of the name they pin. Exported alongside MatchesResource for
// packages that need the engine's own selection ordering rather than a reimplementation
// of it. Callers must have established a match first (see MatchesResource).
func ResourceSpecificity(resource, toolName string) int {
	if resource == toolName {
		return exactMatchSpecificity
	}
	// Scoring is always guarded by a prior MatchesResource check, so the formula
	// below effectively ranks glob patterns (an exact literal hits the case above).
	//
	// literalCount counts EVERY non-wildcard rune, not just the leading run: counting
	// only the prefix scored "*" and "*_admin" identically (-1), losing the
	// more-specific "*_admin" to a catch-all "*" on manifest order alone. Counting
	// all literals gives "*_admin" 6*10-1=59 over "*" at -1.
	//
	// One pass with direct rune comparisons. wildcardCount counts each matcher: '*'
	// and '?' are one each, and a whole "[...]" class is also one (it matches a
	// single character), so its members and closing ']' are skipped rather than
	// over-weighted as literals.
	//
	// A utf8 cursor walks the string in place rather than materializing []rune(resource)
	// on every call — this scorer runs for every candidate constraint on the hot path.
	// Every structural metacharacter is ASCII and multi-byte runes count once at their
	// lead, so the semantics are identical with no allocation.
	literalCount := 0
	wildcardCount := 0
	for i := 0; i < len(resource); {
		r, size := utf8.DecodeRuneInString(resource[i:])
		switch r {
		case '*', '?':
			wildcardCount++
			i += size
		case '\\':
			// A backslash escapes the next rune: in path.Match "\x" consumes two
			// pattern bytes but matches exactly ONE input character (the literal x).
			// The backslash is a control character, not a matchable rune, so it must
			// not be counted as a literal — counting it would inflate specificity by
			// one for every escape. Skip the backslash and count only the escaped rune.
			// Without this arm an escaped '[' would be misparsed as opening a class.
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
