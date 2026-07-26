// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync/atomic"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
)

// auditRecorder is the subset of the audit sink the enforced-forward path needs.
// Both *audit.Sink (stdio) and *routeSink (HTTP/gateway) satisfy it, letting the
// shared forward core record without knowing its transport. Construct it ONLY via
// asRecorder, never by assigning a concrete sink pointer directly: asRecorder maps a
// nil pointer to a nil interface, so the core's `rec != nil` stays a true "no sink"
// test; a direct assignment of a nil concrete pointer would reintroduce the typed-nil
// interface trap.
type auditRecorder interface {
	RecordAllow(ctx context.Context, sessionID, identifier, method string, details map[string]interface{}, obligs []string, auditOnly bool, labelsOut, carriedLabels []string)
	RecordDeny(ctx context.Context, sessionID, identifier, method, denialCode, condType string, details map[string]interface{}, observe bool)
	// AuditDegraded reports whether the audit trail has lost coverage (a dropped or
	// failed-to-write record). reason is a short prose note for the host-facing
	// error and the stderr warning; detail is the discrete counts to stamp into the
	// structured audit record (nil when healthy, never prose). The
	// --require-audit=strict gate consults it to fail subsequent forwards closed.
	// It is retrospective: the loss counters reflect only completed calls, so the
	// boundary call whose own record is the first lost is still forwarded; the next
	// call is the first denied.
	AuditDegraded() (degraded bool, reason string, detail map[string]interface{})
}

// asRecorder converts a possibly-nil concrete sink pointer (*audit.Sink for stdio,
// *routeSink for HTTP/gateway) into the auditRecorder interface, returning a genuine
// nil interface for a nil pointer rather than a non-nil interface wrapping a nil
// pointer — the typed-nil trap. Every params-construction site routes its sink
// through this so the core's `rec != nil` stays a true "no sink configured" test
// (the rule lives here once instead of an inline `var rec; if s != nil` at each).
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

// recordKillDenial records a kill-switch denial and builds the host-facing denial
// response. The non-enforced paths — */list, the unmapped-method default, and each
// transport's local initialize answer — call CheckKill themselves (they do not flow
// through enforcedForwardCore's embedded kill check), then funnel the deny here so
// the record shape (the KILL_SWITCH code from normalizeDenial, no condition mutation)
// and the response envelope are defined once alongside normalizeDenial/denialResult.
// rec may be nil (no sink configured); the record is skipped then. A kill addresses no
// sub-target, so the one method name serves as the audit identifier, the method, and
// the denial target alike (unlike the enforced path, where they can differ); id shapes
// the response.
func recordKillDenial(ctx context.Context, rec auditRecorder, deny *capability.EnforceResponse, id *json.RawMessage, sessionID, method string) mcp.RPCMsg {
	denial := normalizeDenial(deny.Denial)
	if rec != nil {
		rec.RecordDeny(ctx, sessionID, method, method, denial.Code, denial.ConditionType, nil, false)
	}
	return denialResult(id, denial.Code, denial.ConditionType, method, "")
}

// killDropLeg identifies the transport leg a recordKillDrop call site drops a message
// on, stamped into the audit detail so an operator can distinguish drop sites during an
// incident. A typed enum (rather than a bare string at each of the 8 call sites) makes a
// typo'd or duplicated leg a compile error there instead of a silently corrupted
// "transport" detail — before this type existed, only 3 of those call sites had a test
// asserting the exact string value, so a mistake would have gone uncaught. This covers the
// recordKillDrop family only: the "transport" detail has two other producers
// (recordSessionGateDeny's transportTag, and the server-request-undelivered literal in
// http_session.go) that stay bare strings, so this narrows the typo surface rather than
// eliminating it across the whole field.
type killDropLeg string

const (
	legHTTPNotification          killDropLeg = "http-notification"
	legHTTPServerResponse        killDropLeg = "http-server-response"
	legHTTPUpstreamNotification  killDropLeg = "http-upstream-notification"
	legSSEGet                    killDropLeg = "sse-get"
	legStdioNotification         killDropLeg = "stdio-notification"
	legStdioServerResponse       killDropLeg = "stdio-server-response"
	legStdioUpstreamNotification killDropLeg = "stdio-upstream-notification"
)

// recordKillDrop records a kill-switch denial for a message that is DROPPED rather
// than answered with a host-facing error — a fire-and-forget notification or a
// server-initiated message that carries no response envelope to deny into. It mirrors
// recordKillDenial's record shape (normalizeDenial's KILL_SWITCH code, no condition
// mutation) and stamps the originating transport leg into the audit detail so the
// dropped-message provenance stays visible, but returns nothing to send — the caller
// still owns the drop control flow (ack, continue, return). rec may be nil (record
// skipped), matching recordKillDenial; construct it via asRecorder so a nil sink is a
// genuine nil interface. Folding the ~8 hand-mirrored drop-and-record sites here keeps
// the record shape (identifier/method, the "transport" detail key) from drifting apart.
// transportLeg is recorded as a plain string (converted from killDropLeg), matching the
// detail value's shape before this type existed.
func recordKillDrop(ctx context.Context, rec auditRecorder, deny *capability.EnforceResponse, sessionID, identifier, method string, transportLeg killDropLeg) {
	if rec == nil {
		return
	}
	denial := normalizeDenial(deny.Denial)
	rec.RecordDeny(ctx, sessionID, identifier, method, denial.Code, denial.ConditionType, map[string]interface{}{"transport": string(transportLeg)}, false)
}

// recordResourceExhausted records a host request refused because the concurrent-handler
// pool was saturated — the stdio hostSem or the HTTP per-session in-flight cap — so a
// DoS-probe flood against EITHER transport leaves a trace on the tamper-evident tape
// rather than only a JSON-RPC server-busy reply. Shared by both saturation sites so they
// cannot record divergent shapes, or one silently forget to record at all. The refused
// method is recorded (which method starved), but the identifier is left EMPTY on purpose:
// the request is refused before its arguments are parsed, so there is no target, and
// passing the method as the identifier would make deriveTargetFields synthesize a phantom
// target from a mapped method (tools/call -> target "tools/call", prompts/get -> "get"),
// polluting target-based audit aggregation. rec may be nil (no sink configured); skipped
// then, matching recordKillDrop.
func recordResourceExhausted(ctx context.Context, rec auditRecorder, sessionID, method string) {
	if rec == nil {
		return
	}
	rec.RecordDeny(ctx, sessionID, "", method, codeResourceExhausted, "", nil, false)
}

// recordDriftRefused writes the startup manifest-drift refusal record, for the same reason
// recordResourceExhausted exists: both transports refuse a session on this condition, and
// the record was hand-mirrored at the two sites with already-divergent nil handling (stdio
// guarded its recorder, the HTTP path relied on routeSink's nil-receiver safety) and
// different plumbing. Two copies of one record shape is how the same security event ends
// up with two shapes depending on transport, which breaks any aggregation keyed on it --
// and how one site silently forgets to record at all when a detail is added later.
//
// The raw drift reason (which names the drifted tools) deliberately stays on stderr; the
// tape carries only the stable DRIFT_REFUSED category, keeping the fixed-code discipline
// the other refusal records follow.
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
	callUpstream   func(context.Context, mcp.RPCMsg) (mcp.RPCMsg, error)
	strictAuditState
}

// strictAuditState is the --require-audit=strict configuration shared by the
// host-facing forward path (forwardParams) and the server-initiated sampling path
// (serverRequestParams). Embedded in both so a future field driving the strict gate
// is declared once instead of mirrored across the two parameter structs; the fields
// are promoted, so call sites still read fp.requireAuditStrict / fp.strictAuditWarned
// unchanged. The gate condition (auditGateTripped) and the one-shot warning
// (warnStrictAuditOnce) are package functions the two parents' denial methods share —
// this groups only the configuration both carry.
type strictAuditState struct {
	// requireAuditStrict is the --require-audit=strict gate: once a prior record
	// has been lost, an otherwise-authorized forward is denied fail-closed
	// (AUDIT_UNAVAILABLE) so no further privileged call reaches the upstream
	// unaudited. Retrospective (see auditRecorder.AuditDegraded). Off by default.
	requireAuditStrict bool
	// strictAuditWarned makes the strict-gate stderr warning one-shot — the gate is
	// sticky, so it would otherwise log on every forward. The durable per-call
	// signal is the AUDIT_UNAVAILABLE deny record. nil disables the warning (tests).
	strictAuditWarned *atomic.Bool
}

// auditGateTripped reports whether the --require-audit=strict gate should fail a
// forward closed (strict on, sink present, trail degraded). reason is the prose
// degradation note (host-facing error + stderr warning); detail is the discrete
// counts for the structured deny record (nil when not tripped). Shared by the
// forward core, */list dispatch, and the sampling leg so the gate condition lives
// once.
func auditGateTripped(rec auditRecorder, strict bool) (tripped bool, reason string, detail map[string]interface{}) {
	if !strict || rec == nil {
		return false, "", nil
	}
	return rec.AuditDegraded()
}

// warnStrictAuditOnce emits the "strict mode is now denying forwards" stderr line
// exactly once per process, on the first trip. Subsequent denials remain visible
// as AUDIT_UNAVAILABLE records. A nil guard (tests) suppresses it entirely.
func warnStrictAuditOnce(warned *atomic.Bool, reason string) {
	if warned != nil && warned.CompareAndSwap(false, true) {
		fmt.Fprintf(os.Stderr,
			"[eunox] SECURITY: --require-audit=strict is now denying forwards (AUDIT_UNAVAILABLE) until restart — %s. "+
				"Each denied call is recorded as an AUDIT_UNAVAILABLE audit record.\n",
			reason,
		)
	}
}

// warnIfStrictAuditJustDegraded runs recordFn (a RecordAllow/RecordDeny call for a
// call already forwarded to the upstream) and, under strict mode, emits an
// immediate, call-scoped SECURITY warning if the trail transitioned from healthy to
// degraded across that exact call — i.e., this record's own enqueue is plausibly
// the one that tripped the gate.
//
// This narrows, but does not close, the strict gate's documented retrospective
// window (auditRecorder.AuditDegraded): the gate check in strictAuditDenial runs
// BEFORE callUpstream, using degradation counters that only reflect prior calls, so
// the boundary call whose own record is the first lost is still forwarded — the
// next call is the first one denied. Without this, an operator learns about that
// boundary call's possible loss only indirectly, once a later request trips
// AUDIT_UNAVAILABLE. Closing the window fully would require making the record
// synchronous/blocking under strict mode, trading forward latency for the
// guarantee; this stays non-blocking and only adds an immediate diagnostic.
//
// Best-effort, not exact attribution: concurrent in-flight requests at the exact
// transition instant may each observe the healthy-to-degraded flip and each warn.
// That is acceptable — every such call is a genuine candidate for the boundary
// call, not an unrelated false positive.
func warnIfStrictAuditJustDegraded(strict bool, rec auditRecorder, kind, target string, recordFn func()) {
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
		fmt.Fprintf(os.Stderr,
			"[eunox] SECURITY: --require-audit=strict: the audit record for the %s %q request just forwarded to the upstream may itself have been lost (%s) — that call could be unaudited; every subsequent forward is now denied.\n",
			kind, target, reason,
		)
	}
}

// recordUpstreamFailure records the deny for a callUpstream error and returns the
// host-facing JSON-RPC error response. Shared by the enforced-forward core and the
// */list dispatch path (via promotion to dispatchParams) so both produce byte-identical
// audit records and responses for the same physical upstream outage — a change to the
// failure record's shape (e.g. stamping a timeout budget) then cannot land on one path
// and silently drift the other. dispatchList passes the method as both auditID and
// method (a */list request has no sub-target); the forward core passes the per-target
// audit id.
func (fp forwardParams) recordUpstreamFailure(ctx context.Context, msg mcp.RPCMsg, err error, auditID, method string) mcp.RPCMsg {
	code, reason, rpcCode := upstreamErrInfo(err, fp.upstreamTimeMs)
	// This deny records a call already forwarded to (and answered, however badly, by)
	// the upstream — the same boundary-call shape warnIfStrictAuditJustDegraded exists
	// for, so it gets the same immediate diagnostic under strict mode.
	warnIfStrictAuditJustDegraded(fp.requireAuditStrict, fp.rec, method, auditID, func() {
		if fp.rec != nil {
			fp.rec.RecordDeny(ctx, fp.sessionID, auditID, method, code, "", nil, false)
		}
	})
	return mcp.ErrorResponse(msg.ID, rpcCode, reason)
}

// strictAuditDenial implements the --require-audit=strict gate for the
// host-facing path. When strict mode is active and the trail has degraded, it
// records a fail-closed AUDIT_UNAVAILABLE deny and returns the host-facing denial
// (ok=true); otherwise ok=false and the caller proceeds. The deny record here may
// itself be dropped, which is fine — the call is denied either way, so no
// unaudited privileged call reaches the upstream. Only the forward path needs
// gating; a hard deny already returns without contacting the upstream.
func (fp forwardParams) strictAuditDenial(ctx context.Context, msg mcp.RPCMsg, auditID, method, denialTarget string) (mcp.RPCMsg, bool) {
	tripped, reason, detail := auditGateTripped(fp.rec, fp.requireAuditStrict)
	if !tripped {
		return mcp.RPCMsg{}, false
	}
	// detail carries discrete counts (dropped_count/write_failure_count); the prose
	// reason is for the host-facing error and the stderr warning only, never the
	// structured audit field.
	fp.rec.RecordDeny(ctx, fp.sessionID, auditID, method, capability.ErrCodeAuditUnavailable, "", detail, false)
	warnStrictAuditOnce(fp.strictAuditWarned, reason)
	return denialResult(msg.ID, capability.ErrCodeAuditUnavailable, "", denialTarget, ""), true
}

// normalizeDenial returns a non-nil DenialInfo for a deny decision. A deny is
// contractually expected to populate Denial, but PolicyDecisionPoint is an
// exported seam a third-party PDP could implement with a nil Denial; dereferencing
// it would panic the request goroutine (fail-open-via-crash). Substitute a generic
// AUTHORIZATION_FAILED denial so every deny path has structured fields. Shared by
// the forward core, sampling path, */list dispatch, and the initialize kill-check.
func normalizeDenial(d *capability.DenialInfo) *capability.DenialInfo {
	if d == nil {
		return &capability.DenialInfo{Code: capability.ErrCodeAuthorizationFailed}
	}
	return d
}

// isObserveDeny reports whether a deny decision should be downgraded to a logged
// forward (audit/observe mode) instead of hard-blocked. Kill-switch denials and
// hard denials (denial.HardDeny==true, e.g. antecedent record failure) are never
// downgraded: both block even in audit mode and even on a route running under --audit.
// The enforced forward core and the sampling leg share this so their two observe
// gates cannot drift: audit is the route-level --audit posture, auditOnly the
// per-entry enforcement decision.
func isObserveDeny(denial *capability.DenialInfo, auditMode, auditOnly bool) bool {
	// denial is always non-nil here: both callers normalize via normalizeDenial
	// first. A nil denial must not be treated as safe-to-downgrade, so this
	// intentionally omits a nil guard rather than defaulting nil to observable.
	return !pdp.IsKillSwitchDenial(denial) && !denial.HardDeny && (auditMode || auditOnly)
}

// enforcedForwardCore is the shared deny/observe/forward/record decision both
// transports apply to every enforced method (tools/call, resources/read,
// resources/subscribe, prompts/get). It returns the JSON-RPC message to deliver
// to the host — a denial, an upstream transport error, or the upstream's
// (possibly redacted) response. The transports differ only in delivery.
//
// Sequence: a hard deny records and returns a structured denial (upstream never
// called); audit-mode/route-level observe downgrades a deny to a logged forward
// (but a kill-switch deny always hard-blocks); an upstream transport error records
// a deny with the upstream error code; on success, redactFields obligations are
// applied (fail closed) and an allow is recorded with the obligation tokens (one
// "type:path" per matched redact path; see auditObligationNames) and allowDetails.
//
// allowDetails computes the allow record's structured details (resources/prompts
// pass upstreamErrorDetail; tools/call passes its audit-mode argument map).
// recordObligations controls whether obligation tokens are recorded (resources/subscribe
// records none).
func enforcedForwardCore(ctx context.Context, fp forwardParams, msg mcp.RPCMsg, dec capability.EnforceResponse, method, auditID, denialTarget, kind string, recordObligations bool, allowDetails func(mcp.RPCMsg) map[string]interface{}) mcp.RPCMsg {
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
		observe = isObserveDeny(denial, fp.audit, dec.AuditOnly)
		if !observe {
			// A genuine hard deny: record it (upstream never called) and return.
			if fp.rec != nil {
				fp.rec.RecordDeny(ctx, fp.sessionID, auditID, method, denial.Code, denial.ConditionType, denial.Details, false)
			}
			return denialResult(msg.ID, denial.Code, denial.ConditionType, denialTarget, denialArgument(denial))
		}
		// observe: downgrade to a forwarded call. The audit_only=true record is
		// written below, AFTER the strict-audit gate, so a gate-blocked call never
		// leaves a stale "forwarded" deny record for a call that was hard-blocked.
	}

	// --require-audit=strict: once the audit trail has degraded, do not forward an
	// authorized call (clean allow or audit-mode observe). Fail closed so audit
	// coverage gates the upstream side effect. Runs BEFORE the observe deny is
	// recorded so a gate block does not leave an audit_only=true record
	// contradicting the AUDIT_UNAVAILABLE hard-block.
	if denied, blocked := fp.strictAuditDenial(ctx, msg, auditID, method, denialTarget); blocked {
		return denied
	}

	// Gate passed: record the observed (audit_only=true) deny and log the downgrade.
	// denial was set on the deny path above (observe is only true there), so non-nil.
	if observe {
		warnIfStrictAuditJustDegraded(fp.requireAuditStrict, fp.rec, kind, denialTarget, func() {
			if fp.rec != nil {
				fp.rec.RecordDeny(ctx, fp.sessionID, auditID, method, denial.Code, denial.ConditionType, denial.Details, true)
			}
		})
		fmt.Fprintf(os.Stderr,
			"[eunox] AUDIT: %s %q would be denied (%s) — forwarding (audit mode)\n",
			kind, denialTarget, denial.Code,
		)
	}

	upResp, fwdErr := fp.callUpstream(ctx, msg)
	if fwdErr != nil {
		// The maxCalls quota slot this call consumed is INTENTIONALLY NOT refunded here.
		// Decide committed the counter atomically WITH the decision (that atomicity is
		// what makes the limit exact under concurrent requests), and the upstream may
		// have executed the call before the failure: a write timeout means the request
		// bytes were already handed to the upstream, and a read/transport failure can
		// follow a side effect that already happened. A compensating decrement would
		// therefore hand back quota for calls that did run, and would itself need
		// double-refund protection across the retry the host is free to make.
		//
		// The accepted cost is the converse: an upstream that stops draining stdin under
		// a tight --upstream-timeout can burn a caller's whole maxCalls budget on calls
		// that never executed. That is the fail-closed direction (the quota over-counts,
		// never under-counts), and every consumed slot is on the tape — this branch
		// records a deny carrying the upstream error code, so an operator reconstructing
		// a budget can tell executed calls from failed forwards.
		return fp.recordUpstreamFailure(ctx, msg, fwdErr, auditID, method)
	}

	// Apply post-allow obligations (redactFields) before the response reaches the
	// host. Only tools carry directives, so this is a no-op for other methods. Fail
	// closed: a redaction error must never forward unredacted data.
	if len(dec.Obligations) > 0 && upResp.Result != nil {
		redacted, redactErr := pdp.ApplyRedactObligs(upResp.Result, dec.Obligations)
		if redactErr != nil {
			fmt.Fprintf(os.Stderr, "[eunox] SECURITY: redaction failed for %s %q: %v\n", kind, denialTarget, redactErr)
			// Record a deny so the call stays visible on the tape — otherwise an
			// adversarial upstream could return a redaction-failing response to make
			// every redactFields-guarded call vanish from the audit trail. Also a
			// forwarded-then-recorded boundary call, so it gets the same diagnostic.
			warnIfStrictAuditJustDegraded(fp.requireAuditStrict, fp.rec, kind, denialTarget, func() {
				if fp.rec != nil {
					fp.rec.RecordDeny(ctx, fp.sessionID, auditID, method, capability.ErrCodeEnforcementError, "", nil, false)
				}
			})
			return mcp.ErrorResponse(msg.ID, jsonRPCCodeInternalError, "internal error: response redaction failed")
		}
		upResp.Result = redacted
	}
	// Independently of the result branch: an error.data payload alongside a redactFields
	// obligation must be stripped fail-closed. This is a separate `if` (not `else if`) so a
	// malformed/adversarial upstream that returns BOTH a result and an error — which
	// JSON-RPC forbids, but a hostile upstream may still emit — cannot forward a
	// declared-redactable value through error.data by also attaching a (redacted) result.
	// error.data is a free-form channel (mcp.RPCError.Data, preserved as raw bytes) the
	// result-shaped redact paths cannot verify, so drop it rather than forward it
	// unredacted. The obligation is NOT stamped as discharged (oblNames is gated on
	// upResp.Result != nil below), so the tape does not falsely claim a redaction ran.
	if upResp.Error != nil && upResp.Error.Data != nil && hasRedactFieldsObligation(dec.Obligations) {
		fmt.Fprintf(os.Stderr, "[eunox] SECURITY: dropping error.data on %s %q — a redactFields obligation cannot be verified against the free-form JSON-RPC error channel\n", kind, denialTarget)
		upResp.Error.Data = nil
	}

	var oblNames []string
	// Only record obligation tokens when there was a result body to redact. On an
	// allowed call whose upstream returned a JSON-RPC error (upResp.Error != nil,
	// upResp.Result == nil) the redaction block above is skipped — nothing was
	// masked — so listing the directive's fields would overstate what happened: the
	// obligations[] tokens record WHICH fields a redactFields obligation masked, not
	// merely that one was attached (see auditObligationNames).
	if recordObligations && upResp.Result != nil {
		oblNames = auditObligationNames(dec.Obligations)
	}
	// Carry dec.AuditOnly so a per-entry audit-mode forward is not logged as a
	// genuine allow. allowDetails supplies the structured details.
	warnIfStrictAuditJustDegraded(fp.requireAuditStrict, fp.rec, kind, denialTarget, func() {
		if fp.rec != nil {
			fp.rec.RecordAllow(ctx, fp.sessionID, auditID, method, allowDetails(upResp), oblNames, fp.audit || dec.AuditOnly, dec.LabelsOut, dec.CarriedLabels)
		}
	})
	upResp.ID = msg.ID
	return upResp
}

// hasRedactFieldsObligation reports whether obligs carries a redactFields directive
// with at least one path. It gates the fail-closed error.data strip: a redactFields
// obligation means the manifest declared some field redactable, so an upstream error
// carrying free-form data cannot be forwarded unverified. A non-redact obligation (or a
// redactFields with no paths) redacts nothing, so it must not trigger the strip.
func hasRedactFieldsObligation(obligs []capability.Obligation) bool {
	for _, ob := range obligs {
		if ob.Type == capability.DirectiveTypeRedactFields && len(ob.Paths) > 0 {
			return true
		}
	}
	return false
}

// auditObligationNames flattens the obligations applied to an allowed response into
// the tokens recorded in the audit record's obligations[] field: one "type:path"
// entry per matched redact path, so the tape captures WHICH fields a redactFields
// obligation masked, not merely that one ran. The paths are the operator-defined
// field names from the manifest directive (e.g. "$.ssn", "nested.token"), never the
// redacted values, so this discloses nothing the masked response does not already
// reveal to the host (docs/threat-model-mcp.md §6.3). An obligation carrying no
// paths contributes a bare "type" token so its presence still lands on the tape.
// Consumers split a token on its FIRST ':' — the prefix is a known obligation type,
// the remainder the path (which may itself contain ':'). Two forms don't fit that
// "type:path" shape: the bare-type token (no colon), and the sink's appended
// "obligations_truncated:N" sentinel (which has a colon but whose prefix is not an
// obligation type). The audit sink bounds the returned slice before enqueue
// (boundAuditObligations), so a manifest with many or long redact paths cannot push
// the record past the scanner window.
func auditObligationNames(obligs []capability.Obligation) []string {
	if len(obligs) == 0 {
		return nil
	}
	// Capacity is the total token count — one per path, or one bare-type token for an
	// obligation that carries no paths — not len(obligs), since a single obligation
	// can carry several paths.
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

// upstreamErrorDetail returns a structured audit detail noting that the upstream
// returned a JSON-RPC error result on an otherwise-allowed call, or nil for a
// clean success. The proxy's verdict stays "allow", but a forwarded upstream error
// should not look identical to a success on the tape, so the numeric code is
// recorded — never the upstream's error message, which can carry sensitive content.
func upstreamErrorDetail(upResp mcp.RPCMsg) map[string]interface{} {
	if upResp.Error == nil {
		return nil
	}
	return map[string]interface{}{audit.UpstreamErrorCodeKey: upResp.Error.Code}
}

// serverRequestParams bundles the per-transport bits the shared server-initiated
// request core needs. forward delivers msg to the host and reports whether a
// client received it; writeUpstream sends a response back to the upstream
// initiator; claims carries the session's JWT identity (HTTP only) for the
// sampling decision and its records. The rest mirror forwardParams.
type serverRequestParams struct {
	rec           auditRecorder
	audit         bool
	sessionID     string
	sourceIP      string
	claims        *pdp.JWTClaims
	pdp           pdp.PolicyDecisionPoint
	forward       func(mcp.RPCMsg) bool
	writeUpstream func(mcp.RPCMsg)
	// decideLock serializes the sampling decision against the session's host-path
	// decisions when the policy is flow-/sequenceBlock-relevant. A flowLabel sink on
	// system:sampling reads the same per-session flow state a host source writes, and this
	// path runs on the upstream-reader goroutine — outside the host decideGate/decideMu —
	// so without it a sampling sink could peek the flow set mid-commit of a host source's
	// Add and slip the taint. Calling it enters the
	// per-session decision critical section and returns the end func; nil disables
	// serialization (a non-flow policy, or a direct test caller). It wraps ONLY the
	// decision, never the forward. labelOutput on system:sampling is rejected at manifest
	// load, so sampling is only ever a sink here, never a concurrent writer.
	decideLock func() (end func())
	// strictAuditState (embedded) carries the --require-audit=strict gate, which also
	// covers the enforced sampling/createMessage path below. See forwardParams.
	strictAuditState
}

// decideSampling runs the sampling decision under the per-session decision lock when one
// is configured (see decideLock), releasing it (defer, panic-safe) BEFORE the caller
// forwards to the host — so the flow peek is serialized with host-path label writes while
// the forward stays concurrent. A no-op wrapper when serialization is off.
func (fp serverRequestParams) decideSampling(ctx context.Context) capability.EnforceResponse {
	if fp.decideLock != nil {
		end := fp.decideLock()
		defer end()
	}
	return fp.pdp.DecideSampling(ctx, fp.sessionID, fp.sourceIP)
}

// strictServerRequestAuditDenial applies the --require-audit=strict gate to a
// server-initiated (upstream -> host) request, sampling and non-sampling alike.
// When tripped it records the deny, replies AUDIT_UNAVAILABLE to the upstream
// initiator, warns once, and returns true so the caller returns without
// forwarding to the host. The server-initiated analogue of strictAuditDenial,
// failing closed toward the upstream initiator rather than the host.
// auditGateTripped guarantees fp.rec is non-nil here.
func (fp serverRequestParams) strictServerRequestAuditDenial(ctx context.Context, msg mcp.RPCMsg, method string) bool {
	tripped, reason, detail := auditGateTripped(fp.rec, fp.requireAuditStrict)
	if !tripped {
		return false
	}
	// Record BEFORE replying to the upstream (record-before-act), matching the
	// hard-deny and observe branches of forwardServerRequest and the host-facing
	// strictAuditDenial, so a crash between the two cannot leave the upstream answered
	// with no matching audit record. detail carries discrete counts only; reason prose
	// stays out of the structured audit field (see strictAuditDenial).
	fp.rec.RecordDeny(ctx, fp.sessionID, method, method, capability.ErrCodeAuditUnavailable, "", detail, false)
	fp.writeUpstream(mcp.ErrorResponse(msg.ID, capability.JSONRPCCodeEnforcementError, capability.ErrCodeAuditUnavailable))
	warnStrictAuditOnce(fp.strictAuditWarned, reason)
	return true
}

// recordForwardOutcome writes the audit record for a forwarded server-initiated
// request: an allow when a client accepted it, or an ENFORCEMENT_ERROR deny when
// none could. auditOnly marks the allow as an observe-mode (audit) record. Shared by
// all three forwardServerRequest legs (non-sampling, sampling-allow, sampling-observe)
// so the record shape cannot drift between them. No-op when rec is nil.
//
// On HTTP, "delivered" means the message was buffered onto an SSE subscriber channel,
// not that the host's socket received it. If that async delivery later fails (client
// disconnect, SSE write error), httpSession.failServerRequestDelivery appends a
// correction deny so the tape does not stand as claiming the host received a request
// it never did. On stdio, forward always reports delivered.
//
// Each of the three call sites gates its own forward on strictServerRequestAuditDenial
// beforehand, the same gate-before/record-after shape as enforcedForwardCore, so this
// record call gets the same immediate boundary-call diagnostic under strict mode.
func recordForwardOutcome(ctx context.Context, strict bool, rec auditRecorder, sessionID, method string, delivered, auditOnly bool, labelsOut, carriedLabels []string) {
	warnIfStrictAuditJustDegraded(strict, rec, method, method, func() {
		if rec == nil {
			return
		}
		if delivered {
			rec.RecordAllow(ctx, sessionID, method, method, nil, nil, auditOnly, labelsOut, carriedLabels)
		} else {
			rec.RecordDeny(ctx, sessionID, method, method, capability.ErrCodeEnforcementError, "", nil, false)
		}
	})
}

// forwardServerRequest is the shared handling both transports apply to an
// upstream-initiated (server→client) request. Non-sampling methods (roots/list,
// elicitation/create, …) are not policy-enforced — always forwarded, still
// audited, and still gated by --require-audit=strict (a degraded trail denies
// them the same as sampling, since they are just as unaudited otherwise).
// sampling/createMessage is deny-by-default (pdp.DecideSampling checks the
// kill switch and the manifest opt-in); a denial returns the denial code
// (SAMPLING_DENIED, CONDITION_FAILED, MAX_CALLS_EXCEEDED, …) to the upstream
// initiator unless route-level audit mode observes-and-forwards it (a
// kill-switch denial hard-blocks even then), leaving the two-record
// deny-then-forward pattern. The transports differ only in fp.forward,
// fp.writeUpstream, and fp.claims.
//
// Caller contract: msg is a REQUEST (both id and method — mcp.RPCMsg.IsRequest).
// Both readUpstream loops reach this only inside that gate, and upstream
// notifications take their own broadcast path there rather than arriving here. Every
// denial below therefore answers the initiator unconditionally, with no
// notification arm to skip the reply.
func forwardServerRequest(ctx context.Context, msg mcp.RPCMsg, fp serverRequestParams) {
	const samplingMethod = capability.MethodSamplingCreateMessage
	// Attach the session's JWT claims BEFORE the method split so both branches'
	// kill checks (and the sampling decision) see the per-agent dimension:
	// agentIDFromContext reads the agent_id from these claims, and InMemory/Redis
	// ShouldBlock only consults killedAgents when agentID != "". Without this the
	// non-sampling kill check below would silently skip the agent dimension and
	// forward a killed agent's roots/list, elicitation/create, etc. The records
	// also carry agent_id/task_id from here. Inert for stdio (claims is always nil
	// — no JWT identity).
	if fp.claims != nil {
		ctx = pdp.WithJWTClaims(ctx, fp.claims)
	}
	if msg.Method != samplingMethod {
		if deny := fp.pdp.CheckKill(ctx, fp.sessionID); deny != nil {
			denial := normalizeDenial(deny.Denial)
			if fp.rec != nil {
				fp.rec.RecordDeny(ctx, fp.sessionID, msg.Method, msg.Method, denial.Code, denial.ConditionType, nil, false)
			}
			fp.writeUpstream(mcp.ErrorResponse(msg.ID, denialToJSONRPCCode(denial.Code), denial.Code))
			return
		}
		// --require-audit=strict gates non-sampling server-initiated requests too: a
		// degraded trail leaves this forward just as unaudited as an enforced one, so
		// it must fail closed (AUDIT_UNAVAILABLE to the upstream initiator) rather
		// than forward it silently. Mirrors the sampling branch's identical gate below.
		if fp.strictServerRequestAuditDenial(ctx, msg, msg.Method) {
			return
		}
		delivered := fp.forward(msg)
		// Non-sampling methods are not policy-enforced, so there is no flow decision and
		// no labels to record.
		recordForwardOutcome(ctx, fp.requireAuditStrict, fp.rec, fp.sessionID, msg.Method, delivered, fp.audit, nil, nil)
		return
	}

	// Claims were attached above the method split (so the agent dimension is honored
	// on both branches); the sampling decision and its records read them from ctx.
	if fp.audit {
		ctx = enforcement.WithSkipQuota(ctx)
	}
	// Serialized against host-path decisions for a flow-/sequenceBlock-relevant session,
	// so a flowLabel sink on system:sampling cannot read the flow set concurrently with a
	// host source's label write. The lock covers only the decision's flow peek;
	// the forward below runs unlocked.
	dec := fp.decideSampling(ctx)
	if dec.Decision == capability.DecisionAllow {
		// --require-audit=strict gates this enforced method too: a degraded trail
		// fails an allowed sampling request closed (AUDIT_UNAVAILABLE to the upstream
		// initiator) rather than forwarding it unaudited. Scope: sampling needs the
		// system:sampling opt-in, rejected at startup for HTTP upstreams, so this only
		// bites stdio subprocess upstreams.
		if fp.strictServerRequestAuditDenial(ctx, msg, samplingMethod) {
			return
		}
		delivered := fp.forward(msg)
		// Carry the sampling decision's flow labels onto the tape: a flowLabel/labelOutput
		// on the system:sampling constraint mutated session flow-state, so the record must
		// show labels_out/carried_labels or the tape and state disagree for the sampling leg.
		recordForwardOutcome(ctx, fp.requireAuditStrict, fp.rec, fp.sessionID, samplingMethod, delivered, fp.audit, dec.LabelsOut, dec.CarriedLabels)
		return
	}

	// Same observe gate as enforcedForwardCore, via the shared isObserveDeny.
	// dec.AuditOnly is always false for sampling today (manifest validation rejects
	// enforcement: audit on system: targets), but routing through the shared helper
	// means a future audit-only system: entry can't silently lose observe-mode
	// behavior here.
	denial := normalizeDenial(dec.Denial)
	observe := isObserveDeny(denial, fp.audit, dec.AuditOnly)
	if !observe {
		// Hard deny. Record BEFORE replying to the upstream (record-before-act, matching
		// enforcedForwardCore's hard-deny branch) so a crash between the two cannot leave
		// the upstream answered with no matching audit record. Reply with the REAL denial
		// code as both the JSON-RPC code and the message: derive the integer from
		// denialToJSONRPCCode(denial.Code) rather than a literal so the wire code can never
		// drift from the mapping table / docs (SAMPLING_DENIED maps to -32001), and send
		// denial.Code as the message — matching the audit record written just above and the
		// kill-switch path earlier — so an upstream inspecting the message for diagnostics
		// sees the actual reason (CONDITION_FAILED, MAX_CALLS_EXCEEDED, …) instead of a
		// hardcoded "AUTHORIZATION_FAILED" that contradicts the recorded code.
		if fp.rec != nil {
			// Pass denial.Details (as the tool/resource/prompt path does): a flowLabel deny
			// on the system:sampling constraint names the blocked provenance class there, and
			// the deny record carries no carried_labels precisely because details does — so
			// dropping details would leave the offending label absent from the signed tape.
			fp.rec.RecordDeny(ctx, fp.sessionID, samplingMethod, samplingMethod, denial.Code, denial.ConditionType, denial.Details, false)
		}
		fp.writeUpstream(mcp.ErrorResponse(msg.ID, denialToJSONRPCCode(denial.Code), denial.Code))
		return
	}
	// Strict mode gates the audit-mode observe forward too: an observation that
	// can't be recorded has no audit value, so fail it closed. Runs after the
	// kill-switch hard-deny above so a kill still surfaces AUTHORIZATION_FAILED.
	if fp.strictServerRequestAuditDenial(ctx, msg, samplingMethod) {
		return
	}
	// Record-before-act: the would-be deny is recorded before both the stderr notice
	// and the forward (matching enforcedForwardCore's observe branch), so a crash
	// between the two can never leave a SIEM-visible alert with no corresponding
	// tamper-evident audit record.
	if fp.rec != nil {
		// Carry denial.Details on the observe path too, for the same reason as the hard-deny
		// branch above: the would-be flowLabel deny's blocked label must reach the tape.
		fp.rec.RecordDeny(ctx, fp.sessionID, samplingMethod, samplingMethod, denial.Code, denial.ConditionType, denial.Details, true)
	}
	fmt.Fprintf(os.Stderr,
		"[eunox] AUDIT: sampling/createMessage would be denied (%s) — forwarding (audit mode)\n",
		denial.Code,
	)
	delivered := fp.forward(msg)
	// audit=true: this is the audit-mode observe path. dec is the (downgraded) deny, which
	// still carries carried_labels (stamped by the engine on flow-relevant denies), so the
	// observed-forward record shows the accumulated set of the flow that was let through.
	recordForwardOutcome(ctx, fp.requireAuditStrict, fp.rec, fp.sessionID, samplingMethod, delivered, true, dec.LabelsOut, dec.CarriedLabels)
}
