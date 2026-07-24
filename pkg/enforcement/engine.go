// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Package enforcement implements the capability enforcement engine that evaluates
// conditions against incoming requests and produces allow/deny decisions.
package enforcement

import (
	"context"
	"fmt"
	"path"
	"reflect"
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

// DeferredCommit describes one deferred (quota-consuming) condition's counter
// bucket, derived WITHOUT yet consuming the slot, so the engine can admit several
// deferred conditions across a constraint in a single atomic backend call
// (IncrementIfAllBelow). Deny builds the denial for this bucket when it is the one
// that lacked headroom, given the observed count and the backend's retry-after
// hint.
type DeferredCommit struct {
	Key        string
	WindowSecs int
	Limit      int64
	Deny       func(count int64, retryAfter time.Duration) *ConditionError
}

// CommittingConditionHandler is a ConditionHandler whose condition commits state
// (consumes a quota slot) on admit, so it must run after all pure predicates and,
// when a constraint carries more than one such condition, participate in the
// engine's atomic multi-condition commit instead of committing per-bucket (which
// would leave a check->commit TOCTOU across the buckets). PrepareCommit derives the
// bucket without consuming it; the engine then commits every prepared bucket in one
// atomic call. skip is true when quota must not be consumed (observe mode), in
// which case the condition is treated as satisfied and no bucket is committed.
//
// skip MUST be uniform across the whole constraint: it must be derived solely from
// the request context (as the built-in maxCalls does via skipQuota(ctx)), never from
// this condition's own configuration or arguments. The atomic multi-condition commit
// treats one bucket's skip as skipping the entire deferred set — admitting the call
// without limit-checking the remaining committing conditions — so a per-condition skip
// would be a fail-open for the buckets it never checked. commitDeferredAtomic asserts
// skip == skipQuota(ctx) and fails closed on a violation, but a conforming handler must
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

// sequenceHistoryKey builds the per-session, per-target key under which an
// allowed call is recorded for sequenceBlock lookups. namespace (the engine's
// counterKeyNamespace) is the leading component so routes sharing one CallCounter
// address disjoint history. The target type is part of the key because the bare name
// alone is ambiguous — a tool "export" and a prompt "export" would otherwise collide
// on one bucket and cross-trip each other's sequenceBlocks. Recording and Peek must
// pass the same namespace and type (see recordSessionCall and handleSequenceBlock).
func sequenceHistoryKey(namespace, sessionID, targetType, target string) string {
	return compositeCounterKey("seq", namespace, sessionID, targetType, target)
}

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

	// skipAntecedentRecording is set when the policy provably contains no
	// sequenceBlock condition, so the per-call antecedent marker recordSessionCall
	// writes is never read. Skipping the write avoids a needless counter round-trip
	// and, more importantly, removes the recordSessionCall fail-closed deny path —
	// which, on a counter-write fault, would otherwise deny a call whose maxCalls
	// slot runConditions already committed, burning quota for a marker nothing reads.
	skipAntecedentRecording bool

	// skipFlow is set when the policy provably contains no flowLabel condition and no
	// labelOutput directive, so evaluateMatched skips the per-call flow-relevance scan
	// and the peek/record path entirely. Mirrors skipAntecedentRecording: it spares a
	// non-flow policy the scan on every allow, and removes the recordLabels fail-closed
	// deny path for a source-only policy whose markers no sink reads.
	skipFlow bool

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

// WithoutAntecedentRecording tells the engine the policy contains no sequenceBlock
// condition, so it skips writing the per-call sequenceBlock-history marker. The
// marker exists only to be read by a later sequenceBlock; with none in the policy
// the write is pure overhead, and skipping it also removes the recordSessionCall
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
// sequenceBlock — fully evaluated and recordSessionCall recording as normal.
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

// skipQuota reports whether ctx was decorated with WithSkipQuota.
func skipQuota(ctx context.Context) bool {
	v, _ := ctx.Value(ctxSkipQuotaKey{}).(bool)
	return v
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

// recordSessionCall notes that an allowed call to req.ToolName occurred in this
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
func (e *Engine) recordSessionCall(ctx context.Context, req *capability.EnforceRequest) error {
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
	// independently; if the first succeeds and the second faults, recordSessionCall
	// returns the error and the call is denied fail-closed — but whichever marker already
	// committed survives. Writing the alias first means a partial write leaves at most the
	// bare-spelling alias key, never the primary verbatim key (the canonical key the
	// explicit, fully-qualified afterTools spelling resolves to), so the explicit spelling
	// stays conservative. This NARROWS the partial-write fail-open rather than closing it:
	// a surviving alias key can still arm the bare afterTools spelling for a denied
	// antecedent; only an atomic multi-key write would close the window fully. Both keys
	// are sequenceBlock history ("seq:"-namespaced) and never touch a maxCalls bucket
	// (those are "maxcalls:"-namespaced, committed separately), so maxCalls accounting is
	// unaffected by this ordering. The in-memory backend runs both writes under one lock,
	// so both commit or neither does.
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
		if _, err := e.counter.IncrementAndGet(ctx, sequenceHistoryKey(e.counterKeyNamespace, req.SessionID, altType, altName), sequenceHistoryWindowSec, sequenceHistoryMaxEntries); err != nil {
			return err
		}
	}
	if _, err := e.counter.IncrementAndGet(ctx, sequenceHistoryKey(e.counterKeyNamespace, req.SessionID, targetType, tool), sequenceHistoryWindowSec, sequenceHistoryMaxEntries); err != nil {
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
// prefix-stripped req.ToolName.
//
// recordSessionCall additionally writes a secondary sequenceBlock-history marker
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
	return strings.TrimSpace(stripEnginePrefix(req.ToolName))
}

// sessionTargetKey derives the (targetType, name) pair that identifies a target in
// both the sequenceBlock-history and maxCalls counter buckets. The type prefers the
// explicit req.Target.Type, falling back to the req.ToolName prefix (bare defaults to
// "tool"); the name comes from sessionTargetName (Target.Name verbatim, else the
// prefix-stripped ToolName). recordSessionCall and maxCallsBucket both key their
// buckets through it so a direct ValidateAction caller that leaves req.Target nil and
// the antecedent record land on the SAME bucket under the SAME derivation.
// handleSequenceBlock deliberately does NOT use this: it keeps a display-name fallback
// that reports "(unknown)" for an unnamed blocked target.
func sessionTargetKey(req *capability.EnforceRequest) (targetType, name string) {
	targetType, _ = splitEnginePrefix(req.ToolName)
	if req.Target != nil && req.Target.Type != "" {
		targetType = req.Target.Type
	}
	return targetType, sessionTargetName(req)
}

// RecordSessionCall is the exported form of recordSessionCall, for callers that
// must record an antecedent on a path EvaluateConditions does not reach: in audit
// (observe) mode a constraint with a failing condition returns a deny without
// recording, yet the transport still forwards the request and the tool runs, so a
// later sequenceBlock would fail OPEN. The audit-mode PDP calls this after such a
// deny. It honors the same guards as recordSessionCall.
func (e *Engine) RecordSessionCall(ctx context.Context, req *capability.EnforceRequest) error {
	return e.recordSessionCall(ctx, req)
}

// recordFailureDenial builds the fail-closed response returned when
// recordSessionCall cannot persist a marker; ValidateAction and
// EvaluateConditions both return it verbatim.
//
// The denial is attributed to sequenceBlock (the only feature the marker backs)
// even though the calling tool need not carry one, with a Details
// "phase":"record" marker to distinguish it from an actual sequenceBlock hit
// (which populates afterTool/blockedTool). auditOnly carries the constraint's
// mode so a transient recording failure under an audit-mode constraint is
// logged-and-forwarded rather than hard-blocked — a backend hiccup is an
// infrastructure fault, not a policy verdict. (collectObligations deliberately
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
	return capability.EnforceResponse{
		RequestID:   requestID,
		Decision:    capability.DecisionDeny,
		AuditOnly:   auditOnly,
		Obligations: obligations,
		DecidedAt:   now,
		Denial:      &denial,
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

// runConditions evaluates every condition on matched in order. It returns a
// non-nil deny response on the first condition with an unknown type or a Handle
// failure (fail closed), and nil when all conditions pass. requestID and now
// stamp the returned response so it matches the surrounding decision; AuditOnly
// mirrors the matched constraint. Extracted so ValidateAction and
// EvaluateConditions share one dispatch path and cannot diverge.
func (e *Engine) runConditions(ctx context.Context, req *capability.EnforceRequest, matched *capability.Constraint, requestID, now string) *capability.EnforceResponse {
	// Two passes over matched.Conditions so a consuming condition never burns its
	// quota for a call a later condition denies. The loop just below is the first
	// pass: it walks matched.Conditions once, evaluating every pure-predicate
	// condition (allowedValues, timeWindow, ipRange, sequenceBlock — which only
	// Peeks here) immediately, in declared order, while collecting each deferred
	// (consuming) condition into deferred instead of evaluating it yet — one walk
	// does both the classifying and the evaluating, so there is no second loop that
	// could re-derive the classification differently. The code after the loop is the
	// second pass: it evaluates the collected deferred conditions and commits them.
	// handleMaxCalls commits a sliding-window slot the instant it admits, and that
	// commit is not rolled back on a later failure, so keeping commit in the second
	// pass means a pure predicate that denies is always checked first.
	//
	// One residual case escapes this guarantee: recordSessionCall runs AFTER
	// runConditions (it must, so a sequenceBlock antecedent marker is not written for
	// a call collectObligations may still hard-deny), and on a counter-write fault it
	// denies a call whose maxCalls slot was already committed here. It is not rolled
	// back, so that denied call has spent a slot. This is bounded to policies that
	// actually use sequenceBlock: with none, recordSessionCall is skipped entirely
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
		// collectObligations' identical typed-nil guard does.
		if cond == nil || isTypedNil(cond) {
			resp := denyResponse(requestID, now, matched.IsAuditOnly(), nil, capability.DenialInfo{
				Code:    capability.ErrCodeConditionFailed,
				Message: "constraint carries a null condition that cannot be evaluated",
			})
			return &resp
		}
		if e.isDeferredCondition(cond.ConditionType()) {
			deferred = append(deferred, cond)
			continue
		}
		if deny := e.evalCondition(ctx, cond, req, matched, requestID, now); deny != nil {
			return deny
		}
	}

	// More than one consuming condition: commit atomically across all buckets so
	// two concurrent same-session requests cannot both observe headroom and both
	// commit (a per-bucket commit leaves a check→commit TOCTOU). A single deferred
	// condition has no cross-bucket race — its IncrementIfBelow is already atomic.
	if len(deferred) > 1 {
		return e.commitDeferredAtomic(ctx, req, matched, deferred, requestID, now)
	}

	// Commit pass for the single (or zero) deferred condition.
	for _, cond := range deferred {
		if deny := e.evalCondition(ctx, cond, req, matched, requestID, now); deny != nil {
			return deny
		}
	}
	return nil
}

// isTypedNil reports whether v is a non-nil interface value wrapping a nil
// pointer — e.g. a (*MaxCallsCondition)(nil) boxed into a capability.Condition,
// or a (*RedactFieldsDirective)(nil) boxed into a capability.Directive. Such a
// value survives a plain `v == nil` check (the interface itself is non-nil) but
// would panic a value/pointer-receiver method that dereferences it (e.g.
// ConditionType(), ToObligation()). The single source of truth for this guard,
// shared by runConditions' condition check and collectObligations' directive
// check, so the two cannot drift.
func isTypedNil(v interface{}) bool {
	rv := reflect.ValueOf(v)
	return rv.Kind() == reflect.Pointer && rv.IsNil()
}

// commitDeferredAtomic admits a constraint's deferred (quota-consuming) conditions
// in one atomic backend call (IncrementIfAllBelow): the call is recorded in every
// bucket only if every bucket has headroom, closing the per-bucket check→commit
// TOCTOU. Used only when a constraint carries more than one deferred condition. It
// derives each bucket through the registered CommittingConditionHandler
// (PrepareCommit) rather than a hardcoded maxCalls type switch, so a custom
// WithConditionHandler that commits state is honored here exactly as on the
// single-condition path.
func (e *Engine) commitDeferredAtomic(ctx context.Context, req *capability.EnforceRequest, matched *capability.Constraint, deferred []capability.Condition, requestID, now string) *capability.EnforceResponse {
	keys := make([]string, len(deferred))
	windowSecs := make([]int, len(deferred))
	limits := make([]int64, len(deferred))
	denies := make([]func(count int64, retryAfter time.Duration) *ConditionError, len(deferred))
	for i, cond := range deferred {
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
		if skip {
			// Treating one bucket's skip as skipping the whole deferred set is only sound
			// when skip is uniform across the constraint — the contract requires it to be
			// derived solely from ctx (skipQuota). A handler that reports skip for some
			// other reason (its own config/arguments) would leave the remaining committing
			// conditions unchecked: a fail-open. Assert the contract and fail closed on a
			// violation rather than admit the call. The built-in maxCalls always derives
			// skip from skipQuota(ctx), so this never trips for it.
			if !skipQuota(ctx) {
				resp := denyResponse(requestID, now, matched.IsAuditOnly(), nil, capability.DenialInfo{
					Code:          capability.ErrCodeConditionFailed,
					ConditionType: condType,
					Message:       fmt.Sprintf("committing condition %q reported a non-uniform skip; deferred commit requires skip to be derived solely from request context", condType),
				})
				return &resp
			}
			// Quota must not be consumed (audit / skip-quota); the ctx-driven skip
			// holds for every bucket, so record nothing and allow.
			return nil
		}
		if condErr != nil {
			return denyFromConditionError(condErr, matched, requestID, now)
		}
		keys[i], windowSecs[i], limits[i], denies[i] = commit.Key, commit.WindowSecs, commit.Limit, commit.Deny
	}

	admitted, deniedIndex, count, retryAfter, err := e.counter.IncrementIfAllBelow(ctx, keys, windowSecs, limits)
	if err != nil {
		// Infrastructure fault across the whole atomic commit, not any single
		// condition's verdict — this function dispatches through the registry and may
		// mix condition types, so do not misattribute it to maxCalls. Leave
		// ConditionType empty and let Code+Message carry the fault.
		return denyFromConditionError(&ConditionError{
			Code:    capability.ErrCodeConditionFailed,
			Message: fmt.Sprintf("call counter error: %v", err),
		}, matched, requestID, now)
	}
	if !admitted {
		// deniedIndex comes from the CallCounter backend; validate it before using it
		// as a slice index. A non-conforming backend (or Redis-compatible server whose
		// reply deviates from the script contract) could return an out-of-range value,
		// which would panic the enforcement goroutine instead of failing closed. Fail
		// closed with a structured deny, consistent with the parse layer's intent.
		if deniedIndex < 0 || deniedIndex >= len(denies) {
			// A bad-index fault is not any single condition's verdict; leave
			// ConditionType empty (see the backend-error deny above).
			return denyFromConditionError(&ConditionError{
				Code:    capability.ErrCodeConditionFailed,
				Message: fmt.Sprintf("call counter returned out-of-range denied bucket index %d (have %d buckets)", deniedIndex, len(denies)),
			}, matched, requestID, now)
		}
		if denies[deniedIndex] == nil {
			// A committing handler's PrepareCommit populated commit.Key/WindowSecs/Limit
			// but left Deny nil — a handler bug, not any single condition's verdict (the
			// registry may mix condition types here, as commitDeferredAtomic's doc
			// explains). Fail closed with a structured error instead of panicking the
			// enforcement goroutine on a nil-func call.
			return denyFromConditionError(&ConditionError{
				Code:    capability.ErrCodeConditionFailed,
				Message: fmt.Sprintf("committing condition handler for bucket index %d supplied a nil Deny callback", deniedIndex),
			}, matched, requestID, now)
		}
		return denyFromConditionError(denies[deniedIndex](count, retryAfter), matched, requestID, now)
	}
	return nil
}

// denyFromConditionError wraps a handler's *ConditionError into a deny
// EnforceResponse, stamping the surrounding decision's requestID/now and the
// matched constraint's audit-only flag. Shared by evalCondition and
// commitDeferredAtomic so a condition denial has one canonical response shape.
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
// runConditions, collectObligations, and recordSessionCall each short-circuit to their
// own deny (a failing condition, an unhandled directive, or a history-write fault).
// Shared by ValidateAction and EvaluateConditions so the two cannot diverge on this
// security-critical ordering.
func (e *Engine) evaluateMatched(ctx context.Context, req *capability.EnforceRequest, matched *capability.Constraint, requestID, now string) (resp capability.EnforceResponse) {
	// Done before conditions run so a policy condition can inspect the obligations
	// that will apply on allow.
	ctx = withDirectives(ctx, matched.Directives)

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
			if resp.Decision == capability.DecisionDeny && resp.CarriedLabels == nil {
				resp.CarriedLabels = carriedLabels
			}
		}()
	}

	if deny := e.runConditions(ctx, req, matched, requestID, now); deny != nil {
		return *deny
	}

	// Collect obligations BEFORE recording in session history. Recording first would
	// poison history: a later sequenceBlock Peek would see this tool as "run" even
	// though collectObligations' hard deny means it was never forwarded.
	// collectObligations is a pure translation, so reordering it is safe.
	obligations, denyResp := e.collectObligations(matched, requestID, now)
	if denyResp != nil {
		return *denyResp
	}

	// Record the sequenceBlock antecedent BEFORE the flow labels: a recordSessionCall
	// fault then denies with no labels yet committed, so a blocked call never taints the
	// session with flow labels. For a pure flow policy recordSessionCall is skipped (no
	// sequenceBlock), so recordLabels below is the only state write and this ordering has
	// no residual. RESIDUAL (both labelOutput AND sequenceBlock present): the two state
	// writes span the disjoint "seq:"/"flow:" namespaces and are not atomic, so if
	// recordSessionCall commits and recordLabels then HARD-denies, the seq marker persists
	// for a call that never ran (a phantom antecedent). This is fail-closed (over-block,
	// never a leak) and symmetric with the reverse ordering; the atomic-commit fix is
	// tracked in docs/flow-label-hardening.md, mirroring the analogous sequenceBlock note.
	if err := e.recordSessionCall(ctx, req); err != nil {
		return recordFailureDenial(requestID, now, matched.IsAuditOnly(), obligations)
	}

	// This call's own emitted labels (from labelOutput directives). A recordLabels fault
	// fails closed as a HARD deny (see labelRecordFailureDenial), so an audit-mode source
	// whose label failed to persist is not forwarded unlabeled.
	var labelsOut []string
	if flowRelevant {
		var err error
		labelsOut, err = e.recordLabels(ctx, req, matched)
		if err != nil {
			return labelRecordFailureDenial(requestID, now, matched.IsAuditOnly(), obligations)
		}
	}

	return capability.EnforceResponse{
		RequestID:     requestID,
		Decision:      capability.DecisionAllow,
		Obligations:   obligations,
		DecidedAt:     now,
		AuditOnly:     matched.IsAuditOnly(),
		LabelsOut:     labelsOut,
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

	matched := e.findMatchingCapability(req, capabilities)
	if matched == nil {
		// No matched constraint, so no audit-mode posture to inherit: a plain block.
		return denyResponse(requestID, now, false, nil, capability.DenialInfo{
			Code:    capability.ErrCodeAuthorizationFailed,
			Message: "no matching capability for requested action",
		})
	}

	// argumentSchema is evaluated before conditions; a structural failure takes
	// precedence over any condition failure. It does not consult ctx directives, so
	// evaluateMatched threads them (via withDirectives) after this check.
	if matched.ArgumentSchema != nil {
		if err := ValidateArgumentSchema(req.Arguments, matched.ArgumentSchema); err != nil {
			// Stamp AuditOnly so a direct engine caller gets the constraint's mode
			// without re-deriving it.
			return denyResponse(requestID, now, matched.IsAuditOnly(), nil, capability.DenialInfo{
				Code:          capability.ErrCodeInvalidParams,
				ConditionType: "argumentSchema",
				Message:       err.Error(),
			})
		}
	}

	return e.evaluateMatched(ctx, req, matched, requestID, now)
}

// FindMatchingCapability returns the most specific capability that matches the
// request, or nil if none match. Exported so callers that need the matched
// constraint (e.g. the validate endpoint) can reuse the engine's selection logic.
func (e *Engine) FindMatchingCapability(req *capability.EnforceRequest, capabilities []capability.Constraint) *capability.Constraint {
	return e.findMatchingCapability(req, capabilities)
}

// noMatchScore is the sentinel for "no matching capability found yet".
const noMatchScore = -1 << 30

// resourceScoreWeight scales the resource-specificity score, reserving the
// low-order range [0, resourceScoreWeight) as headroom for a possible future
// additive per-action score that could break ties only between equal-resource
// capabilities, never reorder ones whose specificity already differs.
const resourceScoreWeight = 10

// findMatchingCapability finds the most specific matching capability. Tie-breaking
// is stable: at equal specificity, the first in the list wins.
func (e *Engine) findMatchingCapability(req *capability.EnforceRequest, capabilities []capability.Constraint) *capability.Constraint {
	bestIndex := -1
	bestScore := noMatchScore
	// Resolve the request's namespace type and bare name: type from explicit
	// req.Target.Type when present, else the req.ToolName prefix (bare defaults to
	// "tool"). Splitting the prefix lets a "tool:read_file" manifest entry match a
	// bare ToolName "read_file" while a prefixed ToolName still works.
	reqType, bareToolName := splitEnginePrefix(req.ToolName)
	if req.Target != nil {
		if req.Target.Type != "" {
			reqType = req.Target.Type
		}
		// Prefer the verbatim target name over the prefix-split bare name. A
		// resource/prompt may itself be named with a leading recognized token (e.g. a
		// resource "system:config" or a prompt "tool:reboot"): splitEnginePrefix would
		// wrongly strip the token and leave "config", so the covering
		// "resource:system:config" constraint (bare name "system:config") never matches
		// and legitimate access is denied. The PDP selection path derives the bare name
		// from Target.Name verbatim; mirror it so the engine and proxy agree.
		if n := strings.TrimSpace(req.Target.Name); n != "" {
			bareToolName = n
		}
	}
	bestPrincipal := false
	for i := range capabilities {
		constraint := &capabilities[i]
		// The namespace type must match on both sides; comparing only bare names
		// would let a "resource:*" constraint approve any tool call. A bare untyped
		// req.ToolName defaults to "tool".
		constraintType, bare := splitEnginePrefix(constraint.Target)
		if constraintType != reqType {
			continue
		}
		if !matchesResource(bare, bareToolName) {
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
		score := resourceSpecificity(bare, bareToolName) * resourceScoreWeight
		hasPrincipal := constraint.HasPrincipal()
		// Selection order, most to least decisive: (1) higher target specificity;
		// (2) at equal specificity, a principal-scoped entry beats a general one
		// regardless of order; (3) at equal specificity within the same principal
		// class, declaration order wins (the `!bestPrincipal` guard keeps the first
		// principal-scoped entry from being displaced). The first-wins rule for
		// equal-class ties is documented in docs/capability-manifest-guide.md.
		if score > bestScore || (score == bestScore && hasPrincipal && !bestPrincipal) {
			bestIndex = i
			bestScore = score
			bestPrincipal = hasPrincipal
		}
	}
	if bestIndex < 0 {
		return nil
	}
	return &capabilities[bestIndex]
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

// stripEnginePrefix removes the leading "type:" prefix from a constraint
// Target field, returning the bare name/pattern. Recognized prefixes are
// "tool", "resource", "prompt", "system". Bare patterns (no prefix) are
// returned unchanged.
func stripEnginePrefix(s string) string {
	_, bare := splitEnginePrefix(s)
	return bare
}

// MatchesResource is the exported form of matchesResource, for packages needing
// the engine's glob-matching semantics.
func MatchesResource(resource, toolName string) bool {
	return matchesResource(resource, toolName)
}

// ResourceSpecificity is the exported form of resourceSpecificity.
func ResourceSpecificity(resource, toolName string) int {
	return resourceSpecificity(resource, toolName)
}

// StripEnginePrefix is the exported form of stripEnginePrefix, so manifest
// validation recognizes the same prefixes (tool:, resource:, prompt:, system:)
// the engine applies at runtime. An entry whose prefix is not a recognized
// namespace is returned unchanged — the signal load-time validation uses to
// reject an afterTools entry that would otherwise fail open at lookup.
func StripEnginePrefix(s string) string {
	return stripEnginePrefix(s)
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

// collectObligations turns the matched constraint's directives into the
// post-allow obligations the transport applies to the upstream response. It runs
// only on the allow path; a directive MUST NOT change the allow/deny decision.
//
// It returns a fail-closed deny when it meets a directive type it cannot translate
// into an obligation, since silently dropping it would forward the response
// without a declared post-processing step (e.g. an un-applied redaction leaks the
// field). redactFields is the only type today and the loader rejects any other,
// so this is a maintenance guard surfacing a new unwired directive as a hard deny.
//
// The deny is a hard ENFORCEMENT_ERROR and deliberately NOT AuditOnly even under
// an audit-mode constraint: an unwired directive is an engine bug, not a policy
// verdict, so "fail closed on ambiguity" wins over "audit never blocks".
// knownObligationTypes is the set of obligation types the forward core handles.
// collectObligations fails closed (ENFORCEMENT_ERROR) for any obligation type
// not listed here, so a new directive whose ToObligation returns an unrecognized
// type is caught at policy-evaluation time rather than silently passing through
// to an unhandled path. Register both the obligation type AND its handler in
// ApplyRedactObligs (or the analogous consumer) when adding a new directive.
var knownObligationTypes = map[string]bool{
	capability.DirectiveTypeRedactFields: true,
}

func (e *Engine) collectObligations(matched *capability.Constraint, requestID, now string) ([]capability.Obligation, *capability.EnforceResponse) {
	var obligations []capability.Obligation
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
		// labelOutput is an enforce-time state directive, not a response obligation:
		// its effect is the session-label write recordLabels performs on allow, so it
		// produces no post-allow response action. Skip it before ToObligation so it is
		// neither applied to the response nor tripped by the unknown-obligation guard.
		if dir.DirectiveType() == capability.DirectiveTypeLabelOutput {
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

// matchesResource reports whether a capability resource pattern matches the tool
// name, using [path.Match] glob semantics (*, ?, [abc]); "*" matches any name.
// Resources use ':' as a namespace separator (not '/'), so '*' matches across
// colons (e.g. "file:*.csv" matches "file:data.csv").
func matchesResource(resource, toolName string) bool {
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
// resourceScoreWeight (10) stays well within a 32-bit int — resourceSpecificity
// returns int, so the sentinel and the findMatchingCapability multiply must both
// be representable on 32-bit targets (GOARCH=386, arm, mips), matching the 32-bit
// safety pkg/callcounter already engineers for.
const exactMatchSpecificity = 1 << 27

func resourceSpecificity(resource, toolName string) int {
	if resource == toolName {
		return exactMatchSpecificity
	}
	// Scoring is always guarded by a prior matchesResource check, so the formula
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
