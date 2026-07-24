// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Per-method MCP enforcement handlers (tools/call, resources/*, prompts/*,
// and server-initiated requests) with their upstream-timeout and denial helpers.

package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// sessionStartTimeout bounds session-establishment work (the upstream initialize
// handshake and the startup drift tools/list probe). It is deliberately
// independent of --upstream-timeout so a tight per-request value cannot fail
// startup when the manifest pins descriptionHash (a probe failure is fatal then)
// even though the upstream answers within the start budget. Shared by the HTTP
// session-start path and the stdio remote-HTTP drift probe so the two agree.
const sessionStartTimeout = 20 * time.Second

// noUpstreamTimeoutCtxKey marks a context that must NOT be bounded by
// --upstream-timeout. Session-start work carries it so that knob cannot gate
// session establishment; that work is bounded by sessionStartTimeout instead.
type noUpstreamTimeoutCtxKey struct{}

// withoutUpstreamTimeout marks ctx so boundUpstreamCall leaves it unbounded by
// --upstream-timeout. Mirrors enforcement.WithSkipQuota's context-flag pattern.
func withoutUpstreamTimeout(ctx context.Context) context.Context {
	return context.WithValue(ctx, noUpstreamTimeoutCtxKey{}, struct{}{})
}

// boundUpstreamCall returns a child context limited by --upstream-timeout (timeMs)
// when configured, and a no-op cancel when the timeout is unset or ctx is marked
// withoutUpstreamTimeout. Both transports' withUpstreamTimeout delegate here so
// the timeout and its opt-out mean the same on each. Applied once per upstream
// round-trip, so handler forwards and notification forwarding are bounded without
// each call site wrapping.
func boundUpstreamCall(ctx context.Context, timeMs int) (context.Context, context.CancelFunc) {
	if timeMs <= 0 || ctx.Value(noUpstreamTimeoutCtxKey{}) != nil {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, msToDuration(timeMs))
}

// withUpstreamTimeout bounds an HTTPProxy upstream round-trip (see boundUpstreamCall).
func (p *HTTPProxy) withUpstreamTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return boundUpstreamCall(ctx, p.upstreamTimeMs)
}

// Infrastructure denial codes stamped on audit records when the upstream call
// itself fails, as distinct from policy denial codes produced by a PDP.
const (
	codeUpstreamError   = "UPSTREAM_ERROR"
	codeUpstreamTimeout = "UPSTREAM_TIMEOUT"
	codeRequestCanceled = "REQUEST_CANCELED"
	// codeInvalidRequest marks a HOST protocol fault (not an upstream failure), e.g.
	// a duplicate in-flight JSON-RPC id. Non-infra: the upstream never failed, so it
	// must not be blamed via UPSTREAM_ERROR.
	codeInvalidRequest = "INVALID_REQUEST"
)

// Non-policy refusal codes for requests denied BEFORE (or independent of) a PDP
// decision: a failed transport-auth credential, a saturated handler pool, or a
// startup drift refusal. They are recorded so an off-host bearer/control-token
// brute-force, a pool-saturation flood, or a tool-poisoning drift refusal leaves a
// trace on the tamper-evident tape rather than a silent 401/503/500. All are
// non-policy (no target to mine), so IsInfraDenialCode returns true for each and the
// suggest subcommand skips them.
const (
	// codeAuthFailed marks a missing/invalid static Authorization bearer token
	// (--listen-auth-token). The presented credential is NEVER recorded.
	codeAuthFailed = "AUTH_FAILED"
	// codeControlAuthFailed marks a missing/invalid X-Eunox-Control-Token on the
	// loopback emergency-stop endpoint (SEC-07). The presented token is NEVER recorded.
	codeControlAuthFailed = "CONTROL_AUTH_FAILED"
	// codeResourceExhausted marks a host request refused because the concurrent-handler
	// pool was saturated (server-busy), so a DoS-probe flood is visible on the tape.
	codeResourceExhausted = "RESOURCE_EXHAUSTED"
	// codeDriftRefused marks a session refused at startup because the manifest-drift
	// check failed (FM-5 descriptionHash rug-pull / strict-drift refusal) — the security
	// event this feature exists to catch, otherwise invisible to the audit trail.
	codeDriftRefused = "DRIFT_REFUSED"
)

// JSON-RPC 2.0 error codes used for callUpstream-error responses.
const (
	jsonRPCCodeInvalidRequest = -32600
	jsonRPCCodeInternalError  = -32603
)

// IsInfraDenialCode reports whether code marks an infrastructure failure rather
// than a policy decision. Consumers that mine the audit tape for policy signals
// (the suggest subcommand) skip these records.
func IsInfraDenialCode(code string) bool {
	switch code {
	case codeUpstreamError, codeUpstreamTimeout, codeRequestCanceled, codeInvalidRequest:
		// codeInvalidRequest is a host protocol fault — a duplicate in-flight JSON-RPC id,
		// or a malformed / empty-target enforced request (dispatchParams.malformedDeny) —
		// not a policy decision, so suggest must skip it: mining it would fabricate a
		// phantom target named after the MCP method (e.g. "tool:tools/call"). It is
		// deliberately NOT keyed on capability.ErrCodeInvalidParams, which the manifest's
		// argumentSchema check ALSO emits (pdp.go) as a real policy denial against a real
		// target that suggest must keep seeing.
		return true
	case capability.ErrCodeKillSwitch, capability.ErrCodeKillSwitchError, capability.ErrCodeAuditUnavailable:
		// Operator/infra denials, not policy decisions: KILL_SWITCH[_ERROR] is an operator
		// emergency stop (pdp.IsKillSwitchDenial classifies the same two codes as
		// hard-blocking non-policy denials), and AUDIT_UNAVAILABLE is the --require-audit=
		// strict gate tripping after an audit-queue overflow. Mining any of these would let
		// suggest fabricate a deny-only allowlist suggestion for a target that policy never
		// actually denied.
		return true
	case codeAuthFailed, codeControlAuthFailed, codeResourceExhausted, codeDriftRefused:
		// Non-policy refusals recorded before/independent of a PDP decision: a failed
		// transport-auth credential, a saturated handler pool, or a startup drift refusal.
		// None names a policy target, so mining them would fabricate a phantom-target
		// suggestion; suggest must skip them like the other infra denials.
		return true
	}
	return false
}

// upstreamErrInfo maps a callUpstream error to an audit code, a HOST-SAFE reason
// string, and the JSON-RPC error code to return, so both transports emit the same
// classification per failure class: UPSTREAM_TIMEOUT (deadline expired),
// REQUEST_CANCELED (host abandoned first), INVALID_REQUEST (a host protocol fault
// such as a duplicate in-flight id — the upstream was never called), UPSTREAM_ERROR
// (everything else).
//
// The reason never embeds the underlying error text: for a remote HTTP upstream
// that text can carry the upstream's internal hostname/path or response body, and
// the host should only ever see the failure class.
//
// The generic (UPSTREAM_ERROR) branch logs the full error to operator stderr so
// operators keep the diagnosability the host is denied. Only that branch logs: the
// timeout/canceled/invalid-request reasons carry no upstream text and are already in
// the audit trail, so re-logging them would spam stderr under a sustained outage.
func upstreamErrInfo(err error, upstreamTimeMs int) (code, reason string, rpcCode int) {
	switch {
	case errors.Is(err, errDuplicateID):
		// A host pipelined a request reusing an in-flight JSON-RPC id: a client fault,
		// not an upstream failure. Report invalid-request so the host is not told the
		// upstream errored (and so the record is not mined as an upstream outage).
		return codeInvalidRequest, "duplicate JSON-RPC request id already in flight", jsonRPCCodeInvalidRequest
	case errors.Is(err, mcp.ErrUpstreamWriteTimeout):
		// The bounded upstream stdin write timed out (a subprocess that stopped draining its
		// stdin). It is a genuine upstream timeout, so classify it as UPSTREAM_TIMEOUT rather
		// than the generic UPSTREAM_ERROR — otherwise the same physical failure is recorded as
		// UPSTREAM_TIMEOUT on the read side and UPSTREAM_ERROR on the write side depending on
		// which bound wins. Its sentinel text carries no upstream host/path, but routing it
		// here also keeps it out of the default branch's stderr dump.
		return codeUpstreamTimeout, upstreamTimeoutReason(upstreamTimeMs), jsonRPCCodeInternalError
	case errors.Is(err, context.DeadlineExceeded):
		return codeUpstreamTimeout, upstreamTimeoutReason(upstreamTimeMs), jsonRPCCodeInternalError
	case errors.Is(err, context.Canceled):
		return codeRequestCanceled, "request canceled before the upstream responded", jsonRPCCodeInternalError
	default:
		// A remote HTTP upstream's transport-level ResponseHeaderTimeout fires as a
		// *url.Error that is a net.Error with Timeout()==true but does NOT wrap
		// context.DeadlineExceeded, so the errors.Is check above misses it. Classify it
		// as UPSTREAM_TIMEOUT too (it is a genuine timeout) so the same physical failure
		// is not recorded sometimes as UPSTREAM_TIMEOUT and sometimes as UPSTREAM_ERROR
		// depending on which timer wins, and so its raw text (which can carry the
		// upstream's internal host/path) is not dumped to operator stderr.
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return codeUpstreamTimeout, upstreamTimeoutReason(upstreamTimeMs), jsonRPCCodeInternalError
		}
		fmt.Fprintf(os.Stderr, "[eunox] upstream error: %v\n", err)
		return codeUpstreamError, "upstream error", jsonRPCCodeInternalError
	}
}

// upstreamTimeoutReason builds the host-safe reason string for an upstream timeout,
// naming the configured --upstream-timeout when one is set and otherwise attributing
// the expiry to the inherited request deadline (no misleading duration).
func upstreamTimeoutReason(upstreamTimeMs int) string {
	if upstreamTimeMs <= 0 {
		return "upstream did not respond before the request deadline"
	}
	return fmt.Sprintf("upstream did not respond within %d ms", upstreamTimeMs)
}

// strictAudit builds the --require-audit=strict configuration from the proxy's own
// fields, so the five call sites that thread it into dispatchParams/serverRequestParams
// share one construction and a new strictAuditState field cannot be silently dropped
// from a subset of them (which would disable the gate on that path).
func (p *HTTPProxy) strictAudit() strictAuditState {
	return strictAuditState{
		requireAuditStrict: p.requireAuditStrict,
		strictAuditWarned:  &p.strictAuditWarned,
	}
}

// dispatchParams bundles this session's policy/audit/upstream wiring for the
// shared request dispatcher. The route sink is routed through asRecorder so a nil
// sink becomes a true nil interface, keeping the core's nil check a real "no sink"
// test.
func (p *HTTPProxy) dispatchParams(sess *httpSession, sourceIP string) dispatchParams {
	rt := sess.route
	return dispatchParams{
		forwardParams: forwardParams{
			rec:              asRecorder(rt.sink),
			audit:            rt.audit,
			sessionID:        sess.id,
			upstreamTimeMs:   p.upstreamTimeMs,
			callUpstream:     sess.callUpstream,
			strictAuditState: p.strictAudit(),
		},
		pdp:       rt.pdp,
		sourceIP:  sourceIP,
		buildInit: sess.buildInitResponse,
	}
}

// initStrictAuditDenial applies the --require-audit=strict gate to the
// session-creating initialize branch. Creating a session is a privileged side
// effect (it spawns/contacts an upstream), so once the audit trail degrades it is
// refused fail-closed with a recorded AUDIT_UNAVAILABLE deny, mirroring the gate
// on the enforced-forward, */list, and sampling paths. Returns the JSON-RPC denial
// and true when the gate blocks; (zero, false) when the caller should proceed. The
// route sink is routed through asRecorder so a nil sink becomes a true nil interface,
// keeping the nil check a real "no sink" test.
func (p *HTTPProxy) initStrictAuditDenial(ctx context.Context, route *UpstreamRoute, msg mcp.RPCMsg) (mcp.RPCMsg, bool) {
	fp := forwardParams{
		rec:              asRecorder(route.sink),
		sessionID:        "", // no session exists yet on the creating initialize
		strictAuditState: p.strictAudit(),
	}
	// initialize addresses no sub-target, so the audit id, method, and denial
	// target all collapse to "initialize" (see dispatchList for the same pattern).
	return fp.strictAuditDenial(ctx, msg, "initialize", "initialize", "initialize")
}

// initAudienceDenial applies the per-route JWT audience pin to the session-creating
// initialize, before any upstream is spawned/contacted: a token valid only for another
// route's audience (accepted by the gateway's shared union validator) must not create a
// session on this route. Returns the host-facing denial and true when the gate blocks;
// (zero, false) when the caller should proceed. Mirrors initStrictAuditDenial and the
// kill-switch pre-spawn gate; non-JWT routes return a nil CheckAudience and never block.
// The route sink is routed through asRecorder so a nil sink becomes a true nil interface.
func (p *HTTPProxy) initAudienceDenial(ctx context.Context, route *UpstreamRoute, msg mcp.RPCMsg) (mcp.RPCMsg, bool) {
	deny := route.pdp.CheckAudience(ctx)
	if deny == nil {
		return mcp.RPCMsg{}, false
	}
	d := normalizeDenial(deny.Denial)
	if rec := asRecorder(route.sink); rec != nil {
		rec.RecordDeny(ctx, "", "initialize", "initialize", d.Code, d.ConditionType, d.Details, false)
	}
	return denialResult(msg.ID, d.Code, d.ConditionType, "initialize", ""), true
}

// handleHTTPUpstreamRequest handles server-initiated JSON-RPC requests from
// the upstream subprocess (local mode only; remote mode has no background
// reader).  sampling/createMessage is denied by default unless the manifest
// explicitly permits it and the session is not killed; all other
// server-initiated requests are broadcast to SSE subscribers.
func (p *HTTPProxy) handleHTTPUpstreamRequest(ctx context.Context, sess *httpSession, msg mcp.RPCMsg) {
	rt := sess.route
	// Serialize the sampling decision against this session's host-path decisions for a
	// flow-/sequenceBlock-relevant route, so a flowLabel sink on system:sampling cannot
	// peek the flow set concurrently with a host source's label write. Same per-session
	// decideMu the host path uses; released before
	// the forward. nil (no serialization) for a non-flow route.
	var decideLock func() (end func())
	if rt != nil && rt.serializeDecisions {
		decideLock = func() func() {
			sess.decideMu.Lock()
			return sync.OnceFunc(sess.decideMu.Unlock)
		}
	}
	// sess.broadcastServerRequest reports whether an SSE subscriber received the
	// request; sess.claims (captured at initialize) is attached for the sampling
	// decision so per-agent kills are honored and the record carries agent_id/task_id.
	forwardServerRequest(ctx, msg, serverRequestParams{
		rec:              asRecorder(rt.sink),
		audit:            rt.audit,
		sessionID:        sess.id,
		sourceIP:         sess.clientIP,
		claims:           sess.claims,
		pdp:              rt.pdp,
		forward:          sess.broadcastServerRequest,
		writeUpstream:    func(m mcp.RPCMsg) { _ = sess.upWriter.Write(m) },
		decideLock:       decideLock,
		strictAuditState: p.strictAudit(),
	})
}
