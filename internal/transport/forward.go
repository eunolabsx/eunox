// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
)

// auditRecorder is the subset of the audit sink the enforced-forward path needs. Both
// *audit.Sink (stdio) and *routeSink (HTTP/gateway) satisfy it, letting the shared forward
// core record without knowing its transport.
//
// A missing sink must yield a genuine nil INTERFACE, never a non-nil interface wrapping a nil
// pointer — the typed-nil trap that would turn `rec != nil` into a lie. asRecorder and
// StdioProxy.rec both uphold this; never assign a concrete sink pointer directly.
type auditRecorder interface {
	RecordAllow(ctx context.Context, sessionID, identifier, method string, details map[string]interface{}, obligs []string, auditOnly bool, labelsOut, carriedLabels []string)
	RecordDeny(ctx context.Context, sessionID, identifier, method, denialCode, condType string, details map[string]interface{}, observe bool)
	// AuditDegraded reports whether the audit trail has lost coverage. reason is prose for the
	// host-facing error/stderr warning; detail is discrete counts for the structured record.
	// Retrospective: the boundary call whose own record is the first lost is still forwarded;
	// the next call is the first denied.
	AuditDegraded() (degraded bool, reason string, detail map[string]interface{})
}

// asRecorder converts a possibly-nil concrete sink pointer into the auditRecorder interface,
// returning a genuine nil interface for a nil pointer rather than one wrapping a nil pointer
// (the typed-nil trap), so `rec != nil` stays a true "no sink configured" test everywhere.
func asRecorder[T interface {
	auditRecorder
	comparable
}](s T) auditRecorder {
	var zero T
	if s == zero {
		return nil
	}
	return s
}

// killSubject names WHOSE session a kill-switch record describes and whether this proxy can
// VOUCH for that name. Only two things can produce one:
//
//   - verifiedSession: an id this proxy actually established. Safe to stamp as fact into the
//     structured, signed session_id field.
//   - claimedSession: the raw, client-supplied Mcp-Session-Id header of an UNRESOLVED
//     session. Not safe — a caller holding any unrelated valid credential could put an
//     arbitrary (including a victim's) id in the header. session_id stays EMPTY; the value
//     survives only as details.claimed_session_id, clearly marked unverified.
//
// A type rather than a `sessionID string` param because picking wrong fails SILENTLY — a
// well-formed signed record asserting a session this proxy never established. The zero value
// is the safe one, so a hand-written composite literal degrades to recording less, never
// forging more. An AST test (guardedStructs) fails the build if a composite literal of this
// type appears outside the file holding its constructors.
//
// Scope: covers the ~10 kill-record call sites only; the general RecordAllow/RecordDeny
// surface keeps plain-string sessionIDs, where "verified" stays a control-flow fact rather
// than a type guarantee — safe because no dispatchParams constructor can even receive a raw
// header.
type killSubject struct {
	// verified is the registry-resolved session id, stamped into session_id. Empty for a
	// claimed subject.
	verified string
	// claimed is the (not yet sanitized) Mcp-Session-Id header value for a claimed
	// subject, read once at construction; empty for a verified subject AND for a claimed
	// one whose header was absent — auditDetails treats both identically (no detail
	// added), so the two cases need no separate tag. Held as the already-extracted string
	// rather than the *http.Request: every claimedSession(r) call site already reads this
	// exact header into its own local sessionID before constructing the subject, so
	// storing the request would only defer a second, redundant read to record time.
	claimed string
}

// verifiedSession names a session THIS proxy established, safe to stamp into the signed
// session_id field. Pass an id from session state, never one read back off the request.
func verifiedSession(id string) killSubject { return killSubject{verified: id} }

// claimedSession names the session id a client claimed in r's Mcp-Session-Id header at a
// call site that has NOT resolved it against the registry. Its id never reaches session_id;
// see killSubject. Takes *http.Request (read immediately, not retained), not a bare string,
// so a call site cannot spell "this header is verified" by handing it something that merely
// looks like a session id.
func claimedSession(r *http.Request) killSubject {
	return killSubject{claimed: r.Header.Get(SessionHeader)}
}

// auditSessionID is the value for the record's structured, signed session_id field: the
// verified id, or empty for a claimed subject.
func (k killSubject) auditSessionID() string { return k.verified }

// auditDetails folds a claimed subject's unverified id into base as details.claimed_session_id
// (bounded and sanitized by addClaimedSessionIDValue); a no-op for a verified subject or an
// empty header, through the same call so no branch is needed to distinguish them.
func (k killSubject) auditDetails(base map[string]interface{}) map[string]interface{} {
	return addClaimedSessionIDValue(base, k.claimed)
}

// recordKillDenial records a kill-switch denial and builds the host-facing denial response.
// Non-enforced paths call CheckKill themselves then funnel the deny here so the record shape
// and response envelope are defined once. rec may be nil (skipped then). subj decides whether
// the session id is recorded as fact or an unverified claim — see killSubject.
//
// It takes the MESSAGE rather than a method name so the record's identifier comes from
// auditIdentity: a kill is a refusal with no policy decision behind it, exactly the class that
// rule governs. A method name passed straight through made the sink synthesize target_type and
// target from it, stamping a tool literally named `tools/list` onto the signed tape. The
// host-facing error still names the method — that field is a diagnostic for the caller, not a
// claim about a target that exists.
func recordKillDenial(ctx context.Context, rec auditRecorder, deny *capability.EnforceResponse, msg mcp.RPCMsg, subj killSubject) mcp.RPCMsg {
	denial := normalizeDenial(deny.Denial)
	identifier, method := auditIdentity(msg)
	if rec != nil {
		rec.RecordDeny(ctx, subj.auditSessionID(), identifier, method, denial.Code, denial.ConditionType, subj.auditDetails(nil), false)
	}
	return denialResult(msg.ID, denial.Code, denial.ConditionType, method, "")
}

// Fixed labels for the two host framings that carry no method of their own. An empty method
// field names nothing an operator can correlate on, and deriveTargetFields collapses a record
// with no method to no target fields at all.
const (
	methodLabelServerResponse = "server-response"
	// methodLabelUnframed covers a message that is neither request, notification nor response
	// (no id AND no method). Both serve loops discard it, but a gate ahead of that discard can
	// still record one.
	methodLabelUnframed = "unframed-message"
)

// auditIdentity names a message on the tape for a refusal taken with no policy decision behind
// it: the identifier such a record may honestly claim, and the method field beside it.
//
// ONE answer for every such refusal, because the two halves are one question. The identifier is
// dropped for a method that RESOLVES a target type — the sink derives target_type/target from
// it, so recording `resources/subscribe` stamps a resource literally named after the method
// onto the signed tape, and a notification-framed `tools/list` stamps a tool. It survives only
// where it fabricates nothing, which is also the only case it is the sole place the name
// reaches an operator.
func auditIdentity(msg mcp.RPCMsg) (identifier, method string) {
	switch {
	case msg.IsResponse():
		return methodLabelServerResponse, methodLabelServerResponse
	case msg.Method == "":
		return methodLabelUnframed, methodLabelUnframed
	}
	if _, resolvesTarget := capability.MethodTargetType(msg.Method); resolvesTarget {
		return "", msg.Method
	}
	return msg.Method, msg.Method
}

// transportLeg names, in a record's `transport` audit detail, WHICH leg of which transport produced
// it, so an operator can tell drop sites apart during an incident.
//
// ONE type for the field, not one enum per producer beside a bare string parameter: three
// vocabularies in one key kept each producer's spelling honest and none kept the FIELD honest, so
// "sse-get" was already spelled twice for the same leg and a SIEM filter had no closed set to match.
type transportLeg string

// detailTransport is the details key every transportLeg is written under. One constant so the field
// and its vocabulary are edited together — the guard that keeps the set closed is a source walk for
// this key, which cannot find a second producer spelling the literal itself.
const detailTransport = "transport"

// The kill-drop legs (recordKillDrop).
const (
	legHTTPNotification          transportLeg = "http-notification"
	legHTTPServerResponse        transportLeg = "http-server-response"
	legHTTPUpstreamNotification  transportLeg = "http-upstream-notification"
	legSSEGet                    transportLeg = "sse-get"
	legStdioNotification         transportLeg = "stdio-notification"
	legStdioServerResponse       transportLeg = "stdio-server-response"
	legStdioUpstreamNotification transportLeg = "stdio-upstream-notification"
)

// The session-gate legs (recordSessionGateDeny). legSSEGet serves that gate too — one leg, so one
// constant, which is the collision the shared type makes visible rather than merely tolerable.
const (
	legHTTPPost   transportLeg = "http-post"
	legHTTPDelete transportLeg = "http-delete"
)

// recordKillDrop records a kill-switch denial for a message that is DROPPED rather than
// answered with a host-facing error — a notification or a server-initiated message with no
// response envelope to deny into. Mirrors recordKillDenial's record shape and stamps the
// originating transport leg into the audit detail, but returns nothing to send — the caller
// owns the drop control flow. rec may be nil (skipped). Folds ~8 hand-mirrored sites so the
// record shape can't drift apart.
func recordKillDrop(ctx context.Context, rec auditRecorder, deny *capability.EnforceResponse, subj killSubject, msg mcp.RPCMsg, leg transportLeg) {
	if rec == nil {
		return
	}
	// The MESSAGE rather than a name, so auditIdentity decides — a kill drop is a refusal with
	// no policy decision behind it, exactly the class that rule governs, and every site passing
	// its own method name meant a notification-framed `tools/list` stamped a tool literally
	// named `tools/list` onto the signed tape. Six call sites, one of which is reached with no
	// JSON-RPC message at all (an SSE GET): a ZERO message names neither field, which
	// deriveTargetFields collapses to no target at all, leaving the leg to identify the site.
	var identifier, method string
	if !msg.IsZero() {
		identifier, method = auditIdentity(msg)
	}
	denial := normalizeDenial(deny.Denial)
	details := subj.auditDetails(map[string]interface{}{detailTransport: string(leg)})
	rec.RecordDeny(ctx, subj.auditSessionID(), identifier, method, denial.Code, denial.ConditionType, details, false)
}

// recordResourceExhausted records a host request refused because a concurrency pool was
// saturated, so a DoS-probe flood against either transport leaves a trace on the tape rather
// than only a JSON-RPC server-busy reply. Shared by every saturation site so they can't
// record divergent shapes. The identifier is left EMPTY (no target parsed yet) so
// deriveTargetFields can't synthesize a phantom target. rec may be nil (skipped).
//
// gate is the saturated pool's own admission control (required), collapsing an episode of
// saturation to one record carrying a suppressed-refusal count — see saturationGate for why a
// per-refusal record is a lever on --require-audit=strict.
func recordResourceExhausted(ctx context.Context, rec auditRecorder, gate *saturationGate, sessionID, method string) {
	if rec == nil {
		return
	}
	ok, suppressed := gate.admit()
	if !ok {
		return
	}
	var details map[string]interface{}
	if suppressed > 0 {
		details = map[string]interface{}{
			detailSuppressedRefusalCount: suppressed,
			detailSuppressedRefusalScope: suppressedScopeSession,
		}
	}
	rec.RecordDeny(ctx, sessionID, "", method, codeResourceExhausted, "", details, false)
}

// suppressedScopeSession qualifies a saturation gate's rollup (see recordResourceExhausted):
// the count spans only the one session (indeed one pool within it) whose refusals fed the
// gate. Written at this call site rather than carried on saturationGate — a per-scope field
// would be generality with a single caller.
const suppressedScopeSession = "session"

// recordDriftRefused writes the startup manifest-drift refusal record. Both transports refuse
// a session on this condition; folding the previously hand-mirrored sites here keeps the
// record shape from drifting apart between transports.
//
// The raw drift reason (naming the drifted tools) deliberately stays on stderr; the tape
// carries only the stable DRIFT_REFUSED category.
func recordDriftRefused(ctx context.Context, rec auditRecorder, sessionID string) {
	if rec == nil {
		return
	}
	rec.RecordDeny(ctx, sessionID, mcp.MethodInitialize, mcp.MethodInitialize, codeDriftRefused, "drift", nil, false)
}

// forwardParams bundles the per-transport bits the shared enforced-forward core
// needs (HTTP fills these from sess.route + the session; stdio from the proxy),
// keeping the policy/audit/forward logic in one place rather than hand-mirrored.
type forwardParams struct {
	rec            auditRecorder
	audit          bool
	sessionID      string
	upstreamTimeMs int
	// callUpstream forwards the decided message. nil is a MODE: this leg has NO upstream, so the
	// observe downgrade (which IS a forward) is unavailable and the refusal stays hard with the code
	// naming the real cause. A stub that FAILED on use is not equivalent — its error reached
	// recordUpstreamFailure, writing an UPSTREAM_ERROR deny for an upstream never contacted.
	callUpstream func(context.Context, mcp.RPCMsg) (mcp.RPCMsg, error)
	// endDecision closes the decision critical section a serialize-relevant transport opened
	// around this enforced request, idempotent. Decide* handlers call it immediately after the
	// PDP decision so the forward runs OUTSIDE the turn.
	//
	// Lives on these params (not beside the dispatcher's pdp) because releasing at handler
	// return would hold the turn across the client-facing response write, which is bounded by
	// a client that may simply stop reading. nil for a non-serialized request. The transports
	// also defer the same release as a backstop for paths that return before deciding.
	endDecision func()
	strictAuditState
	// refusalLimits (embedded) is this leg's admission control over the writes its refusals make:
	// the record buckets the fail-closed ROUTING refusal resolves against, and the notice bucket
	// bounding the per-frame diagnostics this path writes (the observe-mode "would be denied" line,
	// one per denied call under --audit). The sink is rec, above: a refusal pairs the two rather
	// than carrying a second copy of the sink that could name a different tape.
	//
	// It sits HERE rather than one level up on dispatchParams because enforcedForwardCore is handed
	// only these params, and a second copy of the notice bucket beside it is exactly the wiring
	// fault refusalLimits' own doc argues against. Zero on a leg that meters nothing (the
	// notification gate's, which resolves both halves from the refusalRecorders it is handed).
	//
	// NAMED, not embedded, for the reason refusalRecorders holds its own that way: this struct
	// carries the sink (rec) too, and embedding would promote recorders() onto it — so
	// `fp.recorders(someOtherSink)` would compile and mint a wiring keeping this leg's buckets
	// while pointing at a different tape, beside call sites that idiomatically write
	// `.recorders(...)` already.
	//
	// Its notices field is also where this forward's diagnostic (SECURITY/AUDIT) lines GO, not
	// just what bounds them — one channel rather than a writer field beside a bucket field, which
	// a leg can set half of. Unset (the default, and what every test literal that doesn't set it
	// gets) means os.Stderr, mirroring StdioProxyOptions.Stderr/HTTPGatewayOptions.Stderr: a
	// caller that wants to capture these lines (or avoid racing a concurrently-read os.Stderr)
	// configures the proxy's writer, which flows down to here, instead of reassigning the
	// process-global os.Stderr.
	limits refusalLimits
}

// errOutOrStderr returns this leg's diagnostic destination, os.Stderr when unset — the one place
// every dispatch/forward line resolves it, so a proxy's configured Stderr writer actually reaches
// them instead of being bypassed by a direct os.Stderr write.
func (fp forwardParams) errOutOrStderr() io.Writer {
	return fp.limits.notices.errOut()
}

// resolvedErrOut returns w when set, else os.Stderr — the package's ONE nil-writer fallback.
// The params structs (forwardParams, serverRequestParams) don't embed one another, the two
// proxies' errOut() read a struct field, and several helpers take the writer as a parameter
// because they run with no proxy in scope; all of them must resolve an unset writer
// identically, and a second copy of this three-line function is how one of them ends up
// writing to the process-global instead.
func resolvedErrOut(w io.Writer) io.Writer {
	if w == nil {
		return os.Stderr
	}
	return w
}

// strictAuditState is the --require-audit=strict configuration shared by the host-facing
// forward path (forwardParams) and the server-initiated sampling path (serverRequestParams).
// Embedded in both so a future field is declared once instead of mirrored; fields are
// promoted, so call sites still read fp.requireAuditStrict / fp.strictAuditWarned unchanged.
type strictAuditState struct {
	// requireAuditStrict is the --require-audit=strict gate: once a prior record
	// has been lost, an otherwise-authorized forward is denied fail-closed
	// (AUDIT_UNAVAILABLE) so no further privileged call reaches the upstream
	// unaudited. Retrospective (see auditRecorder.AuditDegraded). Off by default.
	requireAuditStrict bool
	// strictAuditWarned makes the strict-gate stderr warning one-shot — the gate is sticky, so
	// it would otherwise log on every forward. nil disables the warning (tests).
	strictAuditWarned *noticeLatch
}

// auditGateTripped reports whether --require-audit=strict should fail a forward closed.
// reason is prose for the host-facing error/stderr warning; detail is discrete counts for
// the structured deny record. Shared by the forward core, */list dispatch, and sampling.
func auditGateTripped(rec auditRecorder, strict bool) (tripped bool, reason string, detail map[string]interface{}) {
	if !strict || rec == nil {
		return false, "", nil
	}
	return rec.AuditDegraded()
}

// warnStrictAuditOnce emits the "strict mode is now denying forwards" diagnostic line once
// per process, on the first trip; later denials remain visible as AUDIT_UNAVAILABLE records.
func warnStrictAuditOnce(w io.Writer, warned *noticeLatch, reason string) {
	if warned.admitOnce() {
		_, _ = fmt.Fprintf(w,
			"[eunox] SECURITY: --require-audit=strict is now denying forwards (AUDIT_UNAVAILABLE) until restart — %s. "+
				"Each denied call is recorded as an AUDIT_UNAVAILABLE audit record.\n",
			reason,
		)
	}
}

// warnIfStrictAuditJustDegraded runs recordFn (a RecordAllow/RecordDeny for a call already
// forwarded) and, under strict mode, emits an immediate SECURITY warning if the trail
// transitioned healthy-to-degraded across that exact call.
//
// Narrows, but doesn't close, the strict gate's retrospective window: the gate check runs
// BEFORE callUpstream using counters that only reflect prior calls, so the boundary call
// whose own record is the first lost is still forwarded. Closing it fully would require a
// synchronous record under strict mode; this stays non-blocking, adding only a diagnostic.
//
// Best-effort, not exact attribution: concurrent in-flight requests at the transition instant
// may each warn, which is acceptable — each is a genuine boundary-call candidate.
func warnIfStrictAuditJustDegraded(w io.Writer, strict bool, rec auditRecorder, kind, target string, recordFn func()) {
	if !strict || rec == nil {
		recordFn()
		return
	}
	preDegraded, _, _ := rec.AuditDegraded()
	recordFn()
	if preDegraded {
		return
	}
	if postDegraded, reason, _ := rec.AuditDegraded(); postDegraded {
		_, _ = fmt.Fprintf(w,
			"[eunox] SECURITY: --require-audit=strict: the audit record for the %s %q request just forwarded to the upstream may itself have been lost (%s) — that call could be unaudited; every subsequent forward is now denied.\n",
			kind, target, reason,
		)
	}
}

// recordUpstreamFailure records the deny for a callUpstream error and returns the host-facing
// JSON-RPC error response. Shared by the forward core and */list dispatch so both produce
// byte-identical records for the same physical outage. dispatchList passes the method as
// both auditID and method (no sub-target); the forward core passes the per-target audit id.
func (fp forwardParams) recordUpstreamFailure(ctx context.Context, msg mcp.RPCMsg, err error, auditID, method string, detail map[string]interface{}) mcp.RPCMsg {
	code, reason, rpcCode := upstreamErrInfo(fp.limits.notices, err, fp.upstreamTimeMs)
	// This deny records a call already forwarded to (and answered, however badly, by)
	// the upstream — the same boundary-call shape warnIfStrictAuditJustDegraded exists
	// for, so it gets the same immediate diagnostic under strict mode.
	warnIfStrictAuditJustDegraded(fp.errOutOrStderr(), fp.requireAuditStrict, fp.rec, method, auditID, func() {
		if fp.rec != nil {
			fp.rec.RecordDeny(ctx, fp.sessionID, auditID, method, code, "", detail, false)
		}
	})
	return refusalError(msg.ID, rpcCode, reason)
}

// handlerFaultDetail is the annotation for a decision that repaired a condition handler's
// contract violation, or nil for the healthy call every deployment makes. The engine decided
// the call as if the handler had conformed (see capability.EnforceResponse.HandlerFaults), so
// the record is the only place the plugin bug is reported at all.
//
// Rendered into the plain map/slice shapes the audit layer's value bounder recurses into
// rather than handed over as the typed slice: that bounder clones and caps what it recognizes
// and passes anything else through untouched, so a typed value would ride the tape neither
// bounded nor detached from the decision that produced it.
func handlerFaultDetail(dec capability.EnforceResponse) map[string]interface{} {
	if len(dec.HandlerFaults) == 0 {
		return nil
	}
	faults := make([]interface{}, 0, len(dec.HandlerFaults))
	for _, f := range dec.HandlerFaults {
		faults = append(faults, map[string]interface{}{
			"type":     f.Type,
			"contract": string(f.Contract),
		})
	}
	return map[string]interface{}{audit.HandlerFaultKey: faults}
}

// mergeAuditDetails folds extra into base and returns a map the caller OWNS, without mutating
// either input. The package's one "fold extra keys into an audit details map" primitive.
//
// Always allocating is load-bearing: base is routinely a map the record is supposed to
// DESCRIBE rather than one this package owns (the request's own parsed argument map, or the
// engine's denial.Details) — handing one of those back would let a later-written key (an
// effect receipt annotation) silently corrupt the request on the signed tape.
//
// nil base with no extra returns nil (preserving nil-vs-empty for the sink); an EMPTY non-nil
// base does NOT take that shortcut — returning it would hand back an input.
func mergeAuditDetails(base, extra map[string]interface{}) map[string]interface{} {
	if base == nil && len(extra) == 0 {
		return nil
	}
	out := make(map[string]interface{}, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// refuseUpstreamless is the fail-closed answer for a call the core would have to FORWARD on a leg
// with no upstream to forward to (see forwardParams.callUpstream).
//
// ENFORCEMENT_ERROR, not an upstream code: nothing was contacted, so blaming a transport would put
// a fabricated outage on the tamper-evident tape — the failure mode the substituted sink this mode
// replaced actually produced. The refusal is hard whatever the posture, since an observing route
// downgrades a verdict into a forward and there is nothing here to forward through.
func (fp forwardParams) refuseUpstreamless(ctx context.Context, msg mcp.RPCMsg, auditID, method, denialTarget string, dec capability.EnforceResponse) mcp.RPCMsg {
	if fp.rec != nil {
		fp.rec.RecordDeny(ctx, fp.sessionID, auditID, method, capability.ErrCodeEnforcementError, "",
			handlerFaultDetail(dec), false)
	}
	// Admitted before the arguments are built: a wiring fault refuses every request on this leg, so
	// the line is drivable per frame, and what a discarded one costs is the sanitizing walk plus the
	// variadic boxing that heap-allocates every argument (see admitNotice).
	if line, ok := fp.limits.notices.admitNotice(siteUpstreamlessForward); ok {
		line.writef("[eunox] SECURITY: %q was authorized but this path has no upstream to forward it to; refused (ENFORCEMENT_ERROR) — a proxy wiring fault, not an upstream failure\n",
			audit.SanitizeAuditField(method))
	}
	return refusalResponse(msg.ID, capability.ErrCodeEnforcementError, "", denialTarget, "")
}

// strictAuditDenial implements the --require-audit=strict gate for the host-facing path: when
// strict mode is active and the trail has degraded, it records a fail-closed AUDIT_UNAVAILABLE
// deny and returns the host-facing denial (ok=true); otherwise ok=false and the caller proceeds.
//
// dec is the decision this gate refuses below, zero for paths that run no decision at all. Its
// decision-side annotations ride the deny record.
//
// dec (not a pre-built details map) is the parameter because the gate returns without reading
// it whenever the trail is healthy — every call in a healthy deployment — so building the map
// at the call site would allocate for a value nothing reads. A value, not a callback: nothing
// below the decision mutates state, unlike the compensating version this replaced.
func (fp forwardParams) strictAuditDenial(ctx context.Context, msg mcp.RPCMsg, auditID, method, denialTarget string, dec capability.EnforceResponse) (mcp.RPCMsg, bool) {
	tripped, reason, detail := auditGateTripped(fp.rec, fp.requireAuditStrict)
	if !tripped {
		return mcp.RPCMsg{}, false
	}
	detail = mergeAuditDetails(detail, handlerFaultDetail(dec))
	// detail carries discrete counts (dropped_count/write_failure_count); the prose
	// reason is for the host-facing error and the stderr warning only, never the
	// structured audit field.
	fp.rec.RecordDeny(ctx, fp.sessionID, auditID, method, capability.ErrCodeAuditUnavailable, "", detail, false)
	warnStrictAuditOnce(fp.errOutOrStderr(), fp.strictAuditWarned, reason)
	return refusalResponse(msg.ID, capability.ErrCodeAuditUnavailable, "", denialTarget, ""), true
}

// refusalResponse builds the host-facing denial, or the zero message for a message that has no
// reply channel — one with no id, which JSON-RPC forbids answering and which is exactly the
// notification framing the fail-closed routing refusal shares this core with.
//
// Keyed on the id rather than on a threaded flag so the property is structural: every refusal exit
// passes msg.ID, so none of them can build an envelope for a caller that must discard it, and a
// second no-reply caller inherits that rather than having to wire a field. What it skips is a
// reflection-based json.Marshal of the denial data, a fmt chain and a heap RPCError, per frame, on
// the cheapest message an unauthenticated peer can drive.
func refusalResponse(id *json.RawMessage, code, conditionType, target, argument string) mcp.RPCMsg {
	if id == nil {
		return mcp.RPCMsg{}
	}
	return denialResult(id, code, conditionType, target, argument)
}

// refusalError applies refusalResponse's rule (stated there) to the core's two plain-JSON-RPC-error
// refusals. They are unreachable for a no-id message only because the one caller that passes one
// also removes the upstream — two facts nothing couples. The ALLOW tail builds no envelope of its
// own and so has neither helper; enforcedForwardCore's boundary is what covers it.
func refusalError(id *json.RawMessage, code int, message string) mcp.RPCMsg {
	if id == nil {
		return mcp.RPCMsg{}
	}
	return mcp.ErrorResponse(id, code, message)
}

// normalizeDenial returns a non-nil DenialInfo for a deny decision. A third-party PDP could
// implement PolicyDecisionPoint with a nil Denial; dereferencing it would panic the request
// goroutine (fail-open-via-crash), so substitute a generic AUTHORIZATION_FAILED denial.
func normalizeDenial(d *capability.DenialInfo) *capability.DenialInfo {
	if d == nil {
		return &capability.DenialInfo{Code: capability.ErrCodeAuthorizationFailed}
	}
	return d
}

// isObserveDeny reports whether a deny decision should be downgraded to a logged forward
// (audit/observe mode) instead of hard-blocked. Shared by the forward core and the sampling
// leg so their observe gates agree.
//
// WHICH denials resist the downgrade is not this function's question and never was: it is a
// property of the refusal, answered by [capability.DenialInfo.Downgradable] from the class its
// code names, plus the producer's BlockOverride override. What used to sit here was one conjunct
// per reason — a code test for the kill switch, a bool for everything else — so a third
// reason (the engine faults, which carried the policy-verdict code and remembered the bool
// only sometimes) had nowhere to go. This side now contributes only the POSTURE.
func isObserveDeny(denial *capability.DenialInfo, auditMode, auditOnly bool) bool {
	return denial.Downgradable() && (auditMode || auditOnly)
}

// enforcedForwardCore is the shared deny/observe/forward/record decision both transports apply
// to every enforced method. Returns the JSON-RPC message to deliver to the host — a denial, an
// upstream transport error, or the (possibly redacted) response. Transports differ only in
// delivery.
//
// Sequence: a hard deny records and returns without calling upstream; observe downgrades a
// deny to a logged forward (kill-switch always hard-blocks); a transport failure records the
// upstream error code; success applies redactFields obligations (fail closed) and records an
// allow with obligation tokens and allowDetails.
func enforcedForwardCore(ctx context.Context, fp forwardParams, msg mcp.RPCMsg, dec capability.EnforceResponse, method, auditID, denialTarget, kind string, recordObligations bool, allowDetails func(context.Context, mcp.RPCMsg) map[string]interface{}) (reply mcp.RPCMsg) {
	// A message with NO ID has no reply channel — JSON-RPC forbids answering it — and the zero
	// RPCMsg is how this package spells "nothing to send" (see refusalResponse).
	//
	// Applied at the BOUNDARY rather than per exit, so the rule is structural for all six of them
	// rather than a property of which helper each reached for: refusalResponse and refusalError
	// already zero the two payload shapes they build, the two remaining refusals inherit it here,
	// and the ALLOW tail — which relays the upstream's own response — stops being an exception a
	// comment has to remember. Unreachable today (both transports gate on IsRequest before
	// dispatching), and refusalError's own doc anticipates folding in a caller that is not.
	defer func() {
		if msg.ID == nil {
			reply = mcp.RPCMsg{}
		}
	}()
	// Normalized at the boundary for the same reason the msg.ID rule above is: refuseUnroutable
	// passes nil and is safe only because it also nils callUpstream, and coupling this call's
	// safety to that separate fact in a separate function is the shape refusalError's doc warns
	// about — a future nil-passing caller would panic on the allow path AFTER the quota commit.
	if allowDetails == nil {
		allowDetails = func(context.Context, mcp.RPCMsg) map[string]interface{} { return nil }
	}
	observe := false
	var denial *capability.DenialInfo // set on the deny path; reused by the observe branch below
	// Fail closed on anything that is not an explicit allow, not just the literal
	// "deny". A PDP that returns a zero-value EnforceResponse (Decision == "") — a
	// buggy custom PDP, or a future in-tree error path that forgets to set Decision —
	// must be treated as a denial, never silently forwarded to the upstream with an
	// allow record. Gating on `== DecisionDeny` would let a "" decision slip past the
	// deny block as an unaudited fail-open; `!= DecisionAllow` is the fail-closed form.
	if dec.Decision != capability.DecisionAllow {
		denial = normalizeDenial(dec.Denial)
		// The observe downgrade IS a forward, so a leg with no upstream cannot take it: the
		// refusal stays hard and keeps its own code, which names the real cause. See
		// forwardParams.callUpstream for why that is a mode here rather than a sink that fails.
		observe = isObserveDeny(denial, fp.audit, dec.AuditOnly) && fp.callUpstream != nil
		if !observe {
			// A genuine hard deny: record it (upstream never called) and return.
			if fp.rec != nil {
				fp.rec.RecordDeny(ctx, fp.sessionID, auditID, method, denial.Code, denial.ConditionType,
					mergeAuditDetails(denial.Details, handlerFaultDetail(dec)), false)
			}
			return refusalResponse(msg.ID, denial.Code, denial.ConditionType, denialTarget, denialArgument(denial))
		}
		// observe: downgrade to a forwarded call. The audit_only=true record is
		// written below, AFTER the strict-audit gate, so a gate-blocked call never
		// leaves a stale "forwarded" deny record for a call that was hard-blocked.
	}

	// --require-audit=strict: don't forward an authorized call once the trail has degraded.
	// Runs BEFORE the observe deny is recorded so a gate block doesn't leave a stale
	// audit_only=true record contradicting the AUDIT_UNAVAILABLE hard-block.
	//
	// The FIRST of three exits below the decision.
	if denied, blocked := fp.strictAuditDenial(ctx, msg, auditID, method, denialTarget, dec); blocked {
		return denied
	}

	// Gate passed: record the observed (audit_only=true) deny and log the downgrade.
	// denial was set on the deny path above (observe is only true there), so non-nil.
	if observe {
		// The same annotation merge the hard-deny arm makes: no exit below the decision may
		// silently drop a decision-side fact.
		observeDetail := mergeAuditDetails(denial.Details, handlerFaultDetail(dec))
		warnIfStrictAuditJustDegraded(fp.errOutOrStderr(), fp.requireAuditStrict, fp.rec, kind, denialTarget, func() {
			if fp.rec != nil {
				fp.rec.RecordDeny(ctx, fp.sessionID, auditID, method, denial.Code, denial.ConditionType, observeDetail, true)
			}
		})
		if line, ok := fp.limits.notices.admitNotice(siteObserveDowngrade); ok {
			line.writef(
				"[eunox] AUDIT: %s %q would be denied (%s) — forwarding (audit mode)\n",
				kind, denialTarget, denial.Code,
			)
		}
	}

	if fp.callUpstream == nil {
		// An ALLOW (or an observe downgrade, which the gate above already refused) on a leg with no
		// upstream. No in-tree caller produces one — refuseUnroutable is the only upstream-less
		// caller and it always denies — but a nil call here would be a crash where the honest
		// answer is a fail-closed refusal NAMING the wiring fault, rather than a transport failure
		// blamed on an upstream nothing contacted.
		return fp.refuseUpstreamless(ctx, msg, auditID, method, denialTarget, dec)
	}
	upResp, fwdErr := fp.callUpstream(ctx, msg)
	if fwdErr != nil {
		// The maxCalls quota slot this call consumed is INTENTIONALLY NOT refunded here. Decide
		// committed the counter atomically WITH the decision, and the upstream may have
		// executed the call before the failure (a write timeout means the bytes were already
		// sent), so a compensating decrement would hand back quota for calls that did run.
		// Accepted cost: an upstream that stops draining stdin can burn a caller's whole
		// budget on calls that never executed — the fail-closed direction (over-count, never
		// under-count), visible on the tape via this deny's upstream error code.

		return fp.recordUpstreamFailure(ctx, msg, fwdErr, auditID, method, handlerFaultDetail(dec))
	}

	// Apply post-allow obligations (redactFields) before the response reaches the host. Only
	// tools carry directives. Fail closed: a redaction error must never forward unredacted data.
	if len(dec.Obligations) > 0 && upResp.Result != nil {
		redacted, redactErr := pdp.ApplyRedactObligs(upResp.Result, dec.Obligations)
		if redactErr != nil {
			if line, ok := fp.limits.notices.admitNotice(siteRedactionFault); ok {
				line.writef("[eunox] SECURITY: redaction failed for %s %q: %v\n", kind, denialTarget, redactErr)
			}
			// Record a deny so the call stays visible on the tape — otherwise an adversarial
			// upstream could return a redaction-failing response to make every redactFields-
			// guarded call vanish from the audit trail.
			//
			// The third exit below the decision, and the only one the upstream may have
			// ANSWERED before it was taken.
			redactDetail := handlerFaultDetail(dec)
			warnIfStrictAuditJustDegraded(fp.errOutOrStderr(), fp.requireAuditStrict, fp.rec, kind, denialTarget, func() {
				if fp.rec != nil {
					fp.rec.RecordDeny(ctx, fp.sessionID, auditID, method, capability.ErrCodeEnforcementError, "", redactDetail, false)
				}
			})
			return refusalError(msg.ID, jsonRPCCodeInternalError, "internal error: response redaction failed")
		}
		upResp.Result = redacted
	}
	// Independently of the result branch (separate `if`, not `else if`): a malformed/hostile
	// upstream returning BOTH a result and an error (which JSON-RPC forbids) must not forward
	// a redactable value through error.data, a free-form channel the redact paths can't verify.
	if upResp.Error != nil && upResp.Error.Data != nil && hasRedactFieldsObligation(dec.Obligations) {
		if line, ok := fp.limits.notices.admitNotice(siteRedactionFault); ok {
			line.writef("[eunox] SECURITY: dropping error.data on %s %q — a redactFields obligation cannot be verified against the free-form JSON-RPC error channel\n", kind, denialTarget)
		}
		upResp.Error.Data = nil
	}

	var oblNames []string
	// Only record obligation tokens when there was a result body to redact — a JSON-RPC error
	// response skips the redaction block above, so listing fields here would overstate what
	// happened.
	if recordObligations && upResp.Result != nil {
		oblNames = auditObligationNames(dec.Obligations)
	}
	declDetail := handlerFaultDetail(dec)
	// Released HERE rather than at handler return — the audit enqueue and response write that follow
	// don't touch the turn's state, and under task anchoring holding it would let one
	// client's backpressure stall another session's decisions. Idempotent; a no-op for a
	// call that already released after its decision or a non-serialized request.
	if fp.endDecision != nil {
		fp.endDecision()
	}

	// Carry dec.AuditOnly so a per-entry audit-mode forward is not logged as a
	// genuine allow. allowDetails supplies the structured details.
	warnIfStrictAuditJustDegraded(fp.errOutOrStderr(), fp.requireAuditStrict, fp.rec, kind, denialTarget, func() {
		if fp.rec == nil {
			return
		}
		// Through mergeAuditDetails, never a write into allowDetails' return: the tools/call
		// closure's base under --audit is the caller's live parsed argument map, so writing
		// into whatever that chain hands back would rewrite the request being described.
		details := mergeAuditDetails(allowDetails(ctx, upResp), declDetail)
		fp.rec.RecordAllow(ctx, fp.sessionID, auditID, method, details, oblNames, fp.audit || dec.AuditOnly, dec.LabelsOut, dec.CarriedLabels)
	})
	upResp.ID = msg.ID
	return upResp
}

// The two framings' wording for the fail-closed routing refusal's stderr notice. Only the noun
// differs: a request-framed refusal and a notification-framed one are the same refusal for the
// same reason, which is why they share one producer — and whether either may be ANSWERED is read
// off the message's own id (see refusalResponse) rather than declared here, so no framing can
// carry a wrong answer to that question.
const (
	unroutableFramingRequest      = "MCP method"
	unroutableFramingNotification = "notification method"
)

// refusalForwardParams builds the forward params for a refusal that has no dispatchParams behind
// it — the notification gate's, which runs before any dispatcher.
//
// It takes a killSubject rather than a session id for the reason the dispatchParams constructors
// do: forwardParams.sessionID is signed into the record as the session that PERFORMED an action,
// and auditSessionID is the one function that decides whether a leg's id may be claimed as fact or
// must stay an unverified detail. A bare string parameter here is exactly the shape that lets a
// raw Mcp-Session-Id header become a signed assertion.
//
// It carries no recorder and no diagnostic channel: refuseUnroutable resolves BOTH from the
// refusalRecorders it is handed, which is what keeps one producer from having two provenances for
// one record — and, since the channel now carries its own writer, from writing the two framings'
// identical line to two different places.
//
// strict is threaded rather than left zero even though the routing refusal hard-denies above the
// strict-audit gate today. The whole point of routing both framings through one producer is that
// they cannot diverge; a params struct that silently drops the field re-introduces the divergence
// one zero value at a time, and the request-framed twin carries the leg's real state.
func refusalForwardParams(subj killSubject, auditMode bool, strict strictAuditState) forwardParams {
	return forwardParams{
		audit:            auditMode,
		sessionID:        subj.auditSessionID(),
		strictAuditState: strict,
	}
}

// refuseUnroutable is the fail-closed routing default for BOTH framings: a message no routing
// table can route is denied UNROUTABLE_METHOD and never forwarded to the upstream. The method name
// is logged so operators can detect protocol drift or novel MCP extensions.
//
// It goes through the shared deny path like every other refusal in the tree, which is where the
// observe gate, the strict-audit gate and the record shape live once. The pair of hand-rolled
// records this replaced differed only in the subject's audit details — carried here on the
// denial's own Details, the one input the core does not derive.
//
// The code is what makes the refusal resist an observing route's downgrade: it classifies as a
// FAULT, so [capability.DenialInfo.Downgradable] is false for it whoever asks, and the core's
// hard-deny arm is the only one reachable. That is the load-bearing encoding now rather than a
// decoration beside a bypass — the property used to hold only because this path built no
// DenialInfo and so never reached isObserveDeny at all.
//
// callUpstream is REMOVED rather than inherited or substituted: a request-framed caller's is a live
// sink, and this path exists precisely because nothing can route the message, so the one arm of the
// core that would forward it must have nowhere to forward to. That makes "never forwarded"
// structural rather than a consequence of a classification a later edit could change;
// assertRoutingRefusalCode pins the classification itself.
//
// A nil sink is a MODE the core understands, where a stub that FAILED on use only looked
// equivalent: the stub's error was consumed by the observe arm, which turned it into an
// UPSTREAM_ERROR deny for an upstream that was never contacted. See forwardParams.callUpstream.
//
// recs is the leg's refusal wiring, and BOTH halves of this refusal come out of it: the record's
// recorder (resolved against catUnroutable's declaration) and the admission verdict on the stderr
// notice. The two used to be reasoned about with one standard — the record's exemption, argued from
// a policy verdict never being metered, was read as covering a diagnostic line that is not a verdict
// and that no policy DENY writes. fp's own rec is REPLACED rather than read, because this producer
// has two entry points and letting each supply an already-resolved sink is what left the
// request-framed one ungoverned by the exemption declaration entirely.
func refuseUnroutable(ctx context.Context, fp forwardParams, recs refusalRecorders, subj killSubject, msg mcp.RPCMsg, framing string) mcp.RPCMsg {
	// Kill-switch checks run at each caller's boundary, so a killed session is reported as
	// KILL_SWITCH before reaching here. msg.Method is attacker-controlled; sanitize once and reuse
	// for both the stderr line and the host-facing denial. The structured audit field stays raw
	// (JSON-encoding already escapes control runes).
	// Bounded before the scan: sanitizing an unbounded attacker-controlled method is a full UTF-8
	// walk (and a fresh 4 MiB string when it rewrites anything) per frame, above the gate that bounds
	// the write it feeds. msg is this function's own copy.
	msg.Method = audit.BoundEnvelopeField(msg.Method)
	sanitizedMethod := audit.SanitizeAuditField(msg.Method)
	identifier, method := auditIdentity(msg)
	fp.rec = recs.forCategory(catUnroutable)
	// Both halves of this leg's admission control come from recs, so a diagnostic the core writes
	// below charges the same bucket the notice at the bottom of this function does. The
	// notification gate's params carry none of their own (refusalForwardParams), which is exactly
	// how one producer with two entry points ends up bounded on one of them.
	fp.limits = recs.limits
	fp.callUpstream = nil
	dec := capability.EnforceResponse{
		Decision: capability.DecisionDeny,
		Denial:   &capability.DenialInfo{Code: capability.ErrCodeUnroutableMethod},
	}
	// Everything the RECORD carries is built inside this guard: with no sink wired the marker is
	// pure garbage, and this is the cheapest message an unauthenticated peer can drive — a
	// registry lookup and two maps per frame, at the peer's send rate, for a record nobody writes.
	if fp.rec != nil {
		rev := requestRevision(ctx)
		// The marker rides the denial rather than a call-site map so the core's own merge carries
		// it, and subject.auditDetails folds in a claimed session id where the leg has one — the
		// only difference the two framings ever had.
		dec.Denial.Details = subj.auditDetails(unroutableDetail(rev, unroutableReason(rev, msg.Method)))
	}
	// Record-before-act: the core writes the audit record, then the stderr notice follows, so a
	// crash between the two never leaves a SIEM alert with no corresponding audit trail entry.
	resp := enforcedForwardCore(ctx, fp, msg, dec, method, identifier, sanitizedMethod, "method", false, nil)
	// The BOUNDED half. An unbuffered write syscall per refused frame is what a peer looping
	// `{"jsonrpc":"2.0","method":"x/bogus"}` drives at its full send rate — no id, no handler slot,
	// no upstream round trip — and nothing bounded it: it is the same order of cost as the whole
	// denial envelope this path stopped building for that framing (~600ns to /dev/null, more to a
	// pipe or a terminal), spent per frame at the peer's rate. Elided lines are counted into the
	// next one rather than lost, so an operator watching stderr still sees the rate; the RECORD
	// above is unbounded by declaration, so nothing a SIEM reads is elided either way.
	// Pre-gated like the other per-frame sites: this is the loudest of them — the peer described
	// above drives one per frame at its full send rate — and while the method name is already bound
	// once above for the record, boxing it and the framing for a discarded line is not (admitNotice).
	if line, ok := recs.notices().admitNotice(siteUnmappedMethod); ok {
		line.writef("[eunox] SECURITY: unmapped %s %q denied (UNROUTABLE_METHOD) — not forwarded\n",
			framing, sanitizedMethod)
	}
	return resp
}

// hasRedactFieldsObligation reports whether obligs carries a redactFields directive with at
// least one path — gates the fail-closed error.data strip against an upstream error carrying
// free-form data eunox cannot verify.
func hasRedactFieldsObligation(obligs []capability.Obligation) bool {
	for _, ob := range obligs {
		if ob.Type == capability.DirectiveTypeRedactFields && len(ob.Paths) > 0 {
			return true
		}
	}
	return false
}

// auditObligationNames flattens the obligations applied to an allowed response into the
// obligations[] tokens: one "type:path" entry per matched redact path, so the tape captures
// WHICH fields were masked, never the redacted values (docs/threat-model-mcp.md §6.3).
// Consumers split a token on its FIRST ':'. The audit sink bounds the returned slice before
// enqueue (boundAuditObligations).
func auditObligationNames(obligs []capability.Obligation) []string {
	if len(obligs) == 0 {
		return nil
	}
	// Capacity is the total token count — one per path, or one bare-type token for an
	// obligation with no paths — not len(obligs), since one obligation can carry several.
	total := 0
	for _, ob := range obligs {
		if len(ob.Paths) == 0 {
			total++
			continue
		}
		total += len(ob.Paths)
	}
	names := make([]string, 0, total)
	for _, ob := range obligs {
		if len(ob.Paths) == 0 {
			names = append(names, ob.Type)
			continue
		}
		for _, p := range ob.Paths {
			names = append(names, ob.Type+":"+p)
		}
	}
	return names
}

// upstreamErrorDetail returns a structured audit detail noting that the upstream returned a
// JSON-RPC error on an otherwise-allowed call, or nil for a clean success. The numeric code
// is recorded — never the message, which can carry sensitive content.
func upstreamErrorDetail(ctx context.Context, upResp mcp.RPCMsg) map[string]interface{} {
	if upResp.Error == nil {
		return nil
	}
	return map[string]interface{}{audit.UpstreamErrorCodeKey: auditedUpstreamErrorCode(ctx, upResp)}
}

// auditedUpstreamErrorCode is the code the UPSTREAM sent, which is what a field named for the
// upstream must carry.
//
// upResp.Error.Code is the code bound for the HOST, and on a mismatched revision pair the two can
// differ: the boundary re-spells resource-not-found, below this record and on the same object.
// Recording the forwarded value made the tape state something the upstream never said, with
// nothing on the record to distinguish it from an upstream that really said it. See
// upstreamCodeRewrite for why the fact travels by context rather than by moving the rewrite.
func auditedUpstreamErrorCode(ctx context.Context, upResp mcp.RPCMsg) int {
	if original, rewritten := upstreamCodeBeforeRewrite(ctx); rewritten {
		return original
	}
	return upResp.Error.Code
}

// serverRequestParams bundles the per-transport bits the shared server-initiated request core
// needs. forward delivers msg to the host and reports whether a client received it — taking the
// ctx this core has already stamped with the session's claims and revision, since tracking the
// request can force an eviction whose own record has to carry both; writeUpstream sends a
// response back to the upstream initiator; claims carries the session's JWT identity (HTTP only).
// The rest mirror forwardParams.
type serverRequestParams struct {
	rec       auditRecorder
	audit     bool
	sessionID string
	sourceIP  string
	claims    *pdp.JWTClaims
	// pdp is the decision point this leg decides with. Nothing here is DERIVED from it, so a
	// plain field is enough.
	pdp pdp.PolicyDecisionPoint
	// revision is the revision this session's HOST context negotiated. This leg has no host
	// request to read one from, so each transport supplies the fact and forwardServerRequest
	// stamps it — a new server-initiated entry point inherits the stamp rather than needing it
	// re-placed, which is how this leg came to record every sampling decision on a negotiated
	// session as though no revision had been resolved.
	//
	// Empty means the host context has not PINNED one, which is NOT "none was resolved" — a
	// message can resolve a revision, be recorded under it, and still not pin because the proxy
	// discarded it. So it is resolved through resolveRevision rather than left absent.
	revision capability.Revision
	forward  func(context.Context, mcp.RPCMsg) bool
	// unblocker answers the blocked initiator and records an answer that did not land. A zero one
	// (a params struct built by hand in a test) has no upstream sink, which every arm below
	// reaches via answerInitiator so the case is REPORTED rather than nil-called — never a closure
	// over a concrete writer, since a nil *mcp.MsgWriter panics on use. See writeToInitiator.
	//
	// ONE field rather than the writer, the record buckets and the leg threaded separately: the
	// three are one obligation, and holding them apart is what let two hand-mirrored constructors
	// zero-fill whichever a caller missed. Its notices field is also this leg's diagnostic CHANNEL
	// — the writer AND its bound — which is why there is no errOut beside it: the two used to be
	// independent fields feeding one line, so a leg that wired one and not the other wrote
	// unbounded with the call-site walk still green.
	unblocker serverRequestUnblocker
	// decideLock serializes the sampling decision against host-path decisions on the same
	// anchor when the policy is flow-relevant, since this path runs on the upstream-reader
	// goroutine outside the host decision turn and could otherwise peek the flow set
	// mid-commit of a host source's write. Wraps ONLY the decision, never the forward. nil
	// disables serialization.
	//
	// ok is false when the turn could not be entered within its bound: this runs on the
	// session's single upstream-reader goroutine, so blocking it for another call's turn
	// stalls every in-flight request on the session. Failing closed costs one deny-by-default
	// request; waiting costs the whole response path.
	decideLock func() (end func(), ok bool)
	// anchorSplit reports whether this session's host leg has resolved MORE THAN ONE state
	// anchor, in which case this leg cannot decide at all — it has no host request in scope,
	// so deciding against the captured claims' anchor would peek one bucket while the host leg
	// taints another. nil where the question cannot arise (stdio, or non-task-anchored routes).
	anchorSplit func() bool
	// strictAuditState (embedded) carries the --require-audit=strict gate, which also
	// covers the enforced sampling/createMessage path below. See forwardParams.
	strictAuditState
}

// errOutOrStderr resolves this leg's diagnostic destination from the unblocker's own channel,
// which is what makes the writer and its bound one field rather than two a leg can set half of.
// The struct carries no writer of its own for that reason.
func (fp serverRequestParams) errOutOrStderr() io.Writer {
	return fp.unblocker.notices.errOut()
}

// answerInitiator sends reply to the blocked upstream initiator through the shared answering seam,
// which reports a destroyed answer to the tape as well as to stderr. Every denial arm below answers
// AFTER its audit record, which is what makes a nil-receiver panic here worse than a lost answer: it
// leaves a tape recording a denial the process died delivering.
//
// method rides along because the drop record names the REQUEST rather than the refusal — see
// serverRequestUnblocker.answer for why the refusal's own record is not that account.
func (fp serverRequestParams) answerInitiator(ctx context.Context, reply mcp.RPCMsg, what, method string) {
	fp.unblocker.answer(ctx, reply, what, method)
}

// samplingTurnWait bounds how long the server-initiated leg waits for the decision turn. BOTH
// transports bound it here since the hazard is a property of where this leg runs, not of
// which gate it waits on. Each server-initiated request runs on its own goroutine
// (serverRequestPool), so a handler parked here blocks only itself — the bound below is on an
// unbounded WAIT, not a wedge.
//
//   - perHolder (2s) bounds ONE turn holder, which under task anchoring may be a different
//     session. Bounding the HOLDER (not the waiter's own arrival) is what keeps a batch of
//     waiters from being refused together for one slow turn.
//   - total (8s) is the absolute ceiling, since "the queue is moving" must not mean "forever" —
//     a parked handler holds a pool slot, so a steady stream of sub-2s holders would otherwise
//     pin slots indefinitely.
//
// The refusal on give-up stays HARD (see samplingTurnDenial), not the pool's retryable -32000:
// forwarding a sampling request whose decision never ran is exactly what serialization exists
// to prevent, so transience buys a retry, not a forward.
var samplingTurnWait = turnWait{perHolder: 2 * time.Second, total: 8 * time.Second}

// decideSampling runs the sampling decision under the decision turn when configured (see
// decideLock), releasing it BEFORE the caller forwards to the host.
//
// A turn this leg cannot enter within samplingTurnWait produces a DENY rather than an
// unserialized decision — the peek would race a host source's label write, the exact fail-open
// serialization exists to close. HARD: an --audit route must not downgrade it into the forward
// it exists to prevent.
func (fp serverRequestParams) decideSampling(ctx context.Context) capability.EnforceResponse {
	// Asked BEFORE the turn, so a decision that cannot be made correctly does not queue for
	// the right to make it.
	if fp.anchorSplit != nil && fp.anchorSplit() {
		return samplingAnchorSplitDenial()
	}
	if fp.decideLock != nil {
		end, ok := fp.decideLock()
		if !ok {
			return samplingTurnDenial()
		}
		defer end()
		// And AGAIN once the turn is held: the two anchors take DIFFERENT gates (why this
		// refusal exists), so without the re-check a taint committed under the other anchor
		// during the wait would be invisible to the peek that follows. A lock-free atomic read.
		if fp.anchorSplit != nil && fp.anchorSplit() {
			return samplingAnchorSplitDenial()
		}
	}
	return fp.pdp.DecideSampling(ctx, fp.sessionID, fp.sourceIP)
}

// samplingTurnDenial is the fail-closed response for a sampling request whose decision could
// not be serialized against the anchor's host-path decisions.
func samplingTurnDenial() capability.EnforceResponse {
	return samplingFlowDenial(
		"the sampling decision could not be serialized against concurrent decisions on this anchor; refusing rather than reading flow state mid-write",
		"turn_unavailable")
}

// samplingAnchorSplitDenial is the fail-closed response for a server-initiated request on a
// session whose host leg has resolved more than one state anchor.
//
// A session on a task-anchored route may span tasks, each decided on its own anchor — correct
// for the host leg, but this leg has no host request in scope, so which task a
// sampling/createMessage belongs to is undetermined. Attributing it to the captured claims'
// anchor would let the sink peek one bucket while a source taints another.
//
// HARD (forwarding would perform an egress whose authorization couldn't be evaluated) and
// STICKY for the session's life (see noteRequestAnchor) — a client needing sampling on a
// task-anchored route keeps one session per task.
func samplingAnchorSplitDenial() capability.EnforceResponse {
	return samplingFlowDenial(
		"this session has issued requests under more than one state anchor, so which task a server-initiated request belongs to is undetermined; refusing rather than reading one task's flow state for another",
		"session_spans_anchors")
}

// samplingFlowDenial builds this leg's flow-layer refusals. Both are HARD: an --audit route
// downgrades a policy verdict being staged, and neither of these is one — forwarding either
// would perform the very thing the refusal exists to prevent.
func samplingFlowDenial(message, reason string) capability.EnforceResponse {
	return capability.EnforceResponse{
		Decision: capability.DecisionDeny,
		Denial: &capability.DenialInfo{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeFlowLabel,
			Message:       message,
			BlockOverride: true,
			Details:       map[string]interface{}{capability.FlowAuditDetailKey: true, "reason": reason},
		},
	}
}

// strictServerRequestAuditDenial applies the --require-audit=strict gate to a server-initiated
// (upstream -> host) request, sampling and non-sampling alike: when tripped it records the
// deny, replies AUDIT_UNAVAILABLE to the upstream initiator, warns once, and returns true. The
// server-initiated analogue of strictAuditDenial, failing closed toward the initiator.
//
// dec is the decision this gate refuses below, zero for the non-sampling leg. Its
// decision-side annotations ride the deny record exactly as on the host path.
func (fp serverRequestParams) strictServerRequestAuditDenial(ctx context.Context, msg mcp.RPCMsg, method string, dec capability.EnforceResponse) bool {
	tripped, reason, detail := auditGateTripped(fp.rec, fp.requireAuditStrict)
	if !tripped {
		return false
	}
	// Record BEFORE replying to the upstream (record-before-act), matching the other legs, so
	// a crash between the two can't leave the upstream answered with no matching record.
	fp.rec.RecordDeny(ctx, fp.sessionID, method, method, capability.ErrCodeAuditUnavailable, "",
		mergeAuditDetails(detail, handlerFaultDetail(dec)), false)
	fp.answerInitiator(ctx, mcp.ErrorResponse(msg.ID, capability.JSONRPCCodeEnforcementError, capability.ErrCodeAuditUnavailable), answerStrictAuditRefusal, method)
	warnStrictAuditOnce(fp.errOutOrStderr(), fp.strictAuditWarned, reason)
	return true
}

// recordForwardOutcome writes the audit record for a forwarded server-initiated request: an
// allow when a client accepted it, or an ENFORCEMENT_ERROR deny when none could. Shared by all
// three forwardServerRequest legs so the record shape cannot drift between them.
//
// On HTTP, "delivered" means buffered onto an SSE subscriber channel, not that the host's
// socket received it — httpSession.failServerRequestDelivery appends a correction deny if
// async delivery later fails. On stdio, forward always reports delivered.
//
// dec supplies the record's flow fields; the non-sampling leg passes the zero decision. detail
// carries the decision-side annotations, such as a repaired handler fault.
//
// The not-delivered arm is a REFUSAL record and resolves its recorder like every other one on this
// leg. It used to write straight through fp.rec, reaching neither the declaration nor the walk that
// keeps refusals honest — while being drivable by an HTTP upstream alone, at one audit deny per
// request with no host cooperation (outrun the SSE buffer, or hold no GET stream open), which is the
// very axis catDisplaced and catServerRequestFailed's writers are metered on.
//
// On catUndeliveredForward rather than the catServerRequestFailed its async counterpart charges,
// because that flood would otherwise spend the tokens bounding failServerRequestDelivery's
// correction — the record that repairs a standing ALLOW, without which that allow stands on the
// tamper-evident tape claiming a delivery that never happened.
func (fp serverRequestParams) recordForwardOutcome(ctx context.Context, method string, delivered, auditOnly bool, dec capability.EnforceResponse, detail map[string]interface{}) {
	warnIfStrictAuditJustDegraded(fp.errOutOrStderr(), fp.requireAuditStrict, fp.rec, method, method, func() {
		if !delivered {
			// Through the unblocker's own wiring — this leg's tape paired with its buckets — rather
			// than fp.rec beside a bucket looked up separately, which is the two-copies-of-the-sink
			// fault refusalLimits exists to prevent. Nil when the leg has no tape, or when the
			// bucket suppressed this record.
			if rec := fp.unblocker.report.recs.forCategory(catUndeliveredForward); rec != nil {
				rec.RecordDeny(ctx, fp.sessionID, method, method, capability.ErrCodeEnforcementError, "", detail, false)
			}
			return
		}
		if fp.rec == nil {
			return
		}
		fp.rec.RecordAllow(ctx, fp.sessionID, method, method, detail, nil, auditOnly, dec.LabelsOut, dec.CarriedLabels)
	})
}

// forwardServerRequest is the shared handling both transports apply to an upstream-initiated
// (server→client) request. Non-sampling methods (roots/list, elicitation/create, …) are not
// policy-enforced — always forwarded, still audited, and still gated by --require-audit=strict.
// sampling/createMessage is deny-by-default (pdp.DecideSampling checks the kill switch and the
// manifest opt-in); a denial returns the denial code unless route-level audit mode
// observes-and-forwards it (kill-switch always hard-blocks). Transports differ only in
// fp.forward, fp.unblocker, and fp.claims.
//
// Caller contract: msg is a REQUEST (mcp.RPCMsg.IsRequest) — every denial below answers the
// initiator unconditionally, with no notification arm to skip.
func forwardServerRequest(ctx context.Context, msg mcp.RPCMsg, fp serverRequestParams) {
	const samplingMethod = capability.MethodSamplingCreateMessage
	// Attach JWT claims BEFORE the method split so both branches' kill checks see the
	// per-agent dimension (ShouldBlock only consults killedAgents when agentID != "").
	// Without this, the non-sampling kill check would silently forward a killed agent's
	// roots/list, elicitation/create, etc. Inert for stdio (claims always nil).
	if fp.claims != nil {
		ctx = pdp.WithJWTClaims(ctx, fp.claims)
	}
	// Stamped here for the same reason the claims are: both branches record, and a stamp
	// placed in one transport's caller is a stamp the other transport (or the next entry
	// point) can be written without. Unconditional: an absent protocol_revision is reserved for
	// a record written before any revision could be resolved, and this leg only runs on a
	// session whose upstream handshake is complete.
	ctx = capability.WithProtocolRevision(ctx, resolveRevision(fp.revision))
	// The translation boundary, taken before the method split because it is about the LEG and
	// not about what was asked for: a server-initiated request has no meaning for a host whose
	// revision removed the whole mechanism, so every method on this leg is refused when the
	// host is on such a revision, not just the ones policy would have weighed.
	//
	// Refused rather than bridged. Bridging would mean eunox answering on the host's behalf —
	// inventing a sampling result, a roots list, an elicitation the user never saw — which is
	// fabricating exactly the statefulness ADR-0006 refuses to fabricate, and doing it with
	// content rather than bookkeeping.
	//
	// The initiator is ANSWERED rather than left hanging, per this leg's one rule: eunox may
	// answer a blocked initiator wherever it can do so without acting on a second identity's
	// behalf, and a refusal of its own says nothing about the host.
	if refused := refuseServerRequestAcrossRevisions(msg.Method, resolveRevision(fp.revision)); refused != nil {
		if fp.rec != nil {
			// auditIdentity, not msg.Method twice: no policy evaluated this request, and a
			// target-resolving method (sampling/createMessage resolves TargetTypeSystem) would
			// stamp a fabricated target onto the signed tape — the same rule the host-side
			// spelling (refuseHostRevision) and recordServerRequestDropped already follow.
			identifier, method := auditIdentity(msg)
			fp.rec.RecordDeny(ctx, fp.sessionID, identifier, method,
				capability.ErrCodeUntranslatableAcrossRevisions, "", nil, false)
		}
		fp.answerInitiator(ctx, mcp.ErrorResponse(msg.ID,
			capability.JSONRPCCodeUnsupportedProtocolVersion, refused.Error()), answerUntranslatableLeg, msg.Method)
		return
	}
	if msg.Method != samplingMethod {
		if deny := fp.pdp.CheckKill(ctx, fp.sessionID); deny != nil {
			denial := normalizeDenial(deny.Denial)
			if fp.rec != nil {
				fp.rec.RecordDeny(ctx, fp.sessionID, msg.Method, msg.Method, denial.Code, denial.ConditionType, nil, false)
			}
			fp.answerInitiator(ctx, mcp.ErrorResponse(msg.ID, denialToJSONRPCCode(denial.Code), denial.Code), answerRevokedServerRequest, msg.Method)
			return
		}
		// --require-audit=strict gates non-sampling server-initiated requests too: a degraded
		// trail must fail closed here too, mirroring the sampling branch's gate below.
		if fp.strictServerRequestAuditDenial(ctx, msg, msg.Method, capability.EnforceResponse{}) {
			return
		}
		delivered := fp.forward(ctx, msg)
		// Non-sampling methods are not policy-enforced, so there is no flow decision to record.
		fp.recordForwardOutcome(ctx, msg.Method, delivered, fp.audit, capability.EnforceResponse{}, nil)
		return
	}

	// Claims were attached above the method split; the sampling decision reads them from ctx.
	if fp.audit {
		ctx = enforcement.WithSkipQuota(ctx)
	}
	// Serialized against host-path decisions for a flow-relevant session, so a flowLabel sink
	// cannot read the flow set concurrently with a host source's write. Covers only the
	// decision's flow peek; the forward below runs unlocked.
	dec := fp.decideSampling(ctx)
	if dec.Decision == capability.DecisionAllow {
		// --require-audit=strict gates this enforced method too. Scope: sampling needs the
		// system:sampling opt-in, rejected at startup for HTTP upstreams, so this only bites
		// stdio subprocess upstreams.
		if fp.strictServerRequestAuditDenial(ctx, msg, samplingMethod, dec) {
			return
		}
		delivered := fp.forward(ctx, msg)
		// Carry the sampling decision's flow labels onto the tape, or the tape and state
		// disagree for the sampling leg.
		fp.recordForwardOutcome(ctx, samplingMethod, delivered, fp.audit, dec, handlerFaultDetail(dec))
		return
	}

	// Same observe gate as enforcedForwardCore, via the shared isObserveDeny — a future
	// audit-only system: entry can't silently lose observe-mode behavior here.
	denial := normalizeDenial(dec.Denial)
	observe := isObserveDeny(denial, fp.audit, dec.AuditOnly)
	if !observe {
		// Hard deny. Record BEFORE replying (record-before-act). Reply with the REAL denial code
		// as both JSON-RPC code and message — derived via denialToJSONRPCCode rather than a
		// literal, and sending denial.Code as the message so an upstream sees the actual
		// reason instead of a hardcoded "AUTHORIZATION_FAILED".
		if fp.rec != nil {
			// Pass denial.Details: a flowLabel deny on system:sampling names the blocked
			// provenance class there, which dropping details would leave absent from the tape.
			fp.rec.RecordDeny(ctx, fp.sessionID, samplingMethod, samplingMethod, denial.Code, denial.ConditionType,
				mergeAuditDetails(denial.Details, handlerFaultDetail(dec)), false)
		}
		fp.answerInitiator(ctx, mcp.ErrorResponse(msg.ID, denialToJSONRPCCode(denial.Code), denial.Code), answerPolicyRefusal, samplingMethod)
		return
	}
	// Strict mode gates the audit-mode observe forward too — an unrecorded observation has no
	// audit value. Runs after the kill-switch hard-deny above so a kill still surfaces
	// AUTHORIZATION_FAILED.
	if fp.strictServerRequestAuditDenial(ctx, msg, samplingMethod, dec) {
		return
	}
	// Record-before-act: recorded before both the stderr notice and the forward, so a crash
	// between them can't leave a SIEM alert with no corresponding audit record.
	if fp.rec != nil {
		// Carry denial.Details here too: the would-be flowLabel deny's blocked label must
		// reach the tape.
		fp.rec.RecordDeny(ctx, fp.sessionID, samplingMethod, samplingMethod, denial.Code, denial.ConditionType,
			mergeAuditDetails(denial.Details, handlerFaultDetail(dec)), true)
	}
	if line, ok := fp.unblocker.notices.admitNotice(siteSamplingDowngrade); ok {
		line.writef(
			"[eunox] AUDIT: sampling/createMessage would be denied (%s) — forwarding (audit mode)\n",
			denial.Code,
		)
	}
	delivered := fp.forward(ctx, msg)
	// audit=true: the observe path. dec (the downgraded deny) still carries carried_labels, so
	// the record shows the flow that was let through.
	//
	// No commit: a downgraded deny is still a deny, and untainting on one would drop a label
	// for a call policy refused (the same rule enforcedForwardCore's DecisionAllow gate states).
	fp.recordForwardOutcome(ctx, samplingMethod, delivered, true, dec, handlerFaultDetail(dec))
}
