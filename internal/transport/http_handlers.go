// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The upstream-timeout and denial helpers shared by the enforcement path, plus the
// server-initiated request leg. Per-method handlers live in dispatch.go.

package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// sessionStartTimeout bounds session-establishment work (initialize handshake + drift probe),
// deliberately independent of --upstream-timeout so a tight per-request value cannot fail
// startup when the manifest pins descriptionHash. Shared by HTTP and stdio so the two agree.
const sessionStartTimeout = 20 * time.Second

// noUpstreamTimeoutCtxKey marks a context that must NOT be bounded by --upstream-timeout.
// Session-start work carries it, bounded by sessionStartTimeout instead.
type noUpstreamTimeoutCtxKey struct{}

// withoutUpstreamTimeout marks ctx so boundUpstreamCall leaves it unbounded by
// --upstream-timeout. Mirrors enforcement.WithSkipQuota's context-flag pattern.
func withoutUpstreamTimeout(ctx context.Context) context.Context {
	return context.WithValue(ctx, noUpstreamTimeoutCtxKey{}, struct{}{})
}

// boundUpstreamCall returns a child context limited by --upstream-timeout (timeMs) when
// configured, and a no-op cancel when unset or ctx is marked withoutUpstreamTimeout. Both
// transports delegate here so the timeout and its opt-out mean the same on each.
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

// Non-policy refusal codes for requests denied BEFORE (or independent of) a PDP decision, so
// a brute-force/saturation/drift-refusal probe leaves a trace on the tape rather than only a
// silent 401/500/server-busy reply. All non-policy (no target to mine), so IsInfraDenialCode
// returns true and suggest skips them.
const (
	// codeAuthFailed marks a missing/invalid static Authorization bearer token
	// (--listen-auth-token). The presented credential is NEVER recorded.
	codeAuthFailed = "AUTH_FAILED"
	// codeControlAuthFailed marks a missing/invalid X-Eunox-Control-Token on the
	// loopback emergency-stop endpoint (SEC-07). The presented token is NEVER recorded.
	codeControlAuthFailed = "CONTROL_AUTH_FAILED"
	// codeResourceExhausted marks a host request refused because the concurrent-handler pool
	// was saturated, so a DoS-probe flood is visible on the tape.
	codeResourceExhausted = "RESOURCE_EXHAUSTED"
	// codeDriftRefused marks a session refused at startup because the manifest-drift check
	// failed (descriptionHash rug-pull / strict-drift refusal).
	codeDriftRefused = "DRIFT_REFUSED"
	// codeLoopbackRejected marks a request refused by the loopback-only gate fronting
	// /control/kill, /healthz and /metrics. Runs BEFORE checkControlToken, so without its
	// own code an off-host probe of the emergency stop left no trace.
	codeLoopbackRejected = "LOOPBACK_REJECTED"
	// codeUnsupportedMediaType marks a POST body refused because its Content-Type was absent,
	// duplicated, or not application/json — a content-type sweep is attack signal.
	codeUnsupportedMediaType = "UNSUPPORTED_MEDIA_TYPE"
	// codeOriginRejected marks a request refused by the Origin allowlist (DNS-rebinding gate),
	// and codeJWTInvalid a request whose bearer token failed validation. Both were bare literals
	// at their one call site each, which is how they came to be the two members of this family
	// IsInfraDenialCode did not answer for: `eunox suggest` skips them only because their target
	// is blank, the same accident the routing refusal's own code was split off to remove.
	codeOriginRejected = "ORIGIN_REJECTED"
	codeJWTInvalid     = "JWT_INVALID"
)

// MethodControlKill is the audit `method` stamped on a successful /control/kill activation.
// Deliberately NOT an MCP method, so deriveTargetFields fabricates no target type.
const MethodControlKill = "control/kill"

// JSON-RPC 2.0 error codes this package returns to the host. Named constants rather than
// bare literals: a transposed digit would otherwise produce a valid-looking wrong error class.
const (
	jsonRPCCodeInvalidRequest = -32600
	jsonRPCCodeInvalidParams  = -32602
	jsonRPCCodeInternalError  = -32603
)

// IsInfraDenialCode reports whether code marks an infrastructure failure rather than a
// policy decision. Consumers mining the audit tape for policy signals skip these.
func IsInfraDenialCode(code string) bool {
	// The codes the DENIAL VOCABULARY itself classifies as non-policy — an emergency stop, the
	// strict-audit gate, a revision that could not be established, a message nothing could
	// route, an engine/backend fault — are asked of it rather than listed again here. Several
	// were listed by hand, which is how one came to be missing: an engine fault names the target
	// of a call policy never decided, and mining it fabricates a deny-only suggestion for a
	// capability nothing refused. The routing refusal was the mirror case, skipped only because
	// its target happens to be blank rather than because any code said it was non-policy.
	if capability.ClassifyDenialCode(code) != capability.DenialClassPolicy {
		return true
	}
	switch code {
	case codeUpstreamError, codeUpstreamTimeout, codeRequestCanceled, codeInvalidRequest:
		// codeInvalidRequest is a host protocol fault, not a policy decision — mining it
		// would fabricate a phantom target like "tool:tools/call". Deliberately NOT keyed on
		// capability.ErrCodeInvalidParams, which is a real policy denial suggest must keep seeing.
		return true
	case codeAuthFailed, codeControlAuthFailed, codeResourceExhausted, codeDriftRefused, codeLoopbackRejected, codeUnsupportedMediaType,
		codeOriginRejected, codeJWTInvalid:
		// Non-policy refusals recorded before/independent of a PDP decision. None names a
		// policy target, so mining them would fabricate a phantom-target suggestion.
		return true
	}
	return false
}

// upstreamErrInfo maps a callUpstream error to an audit code, a HOST-SAFE reason string, and
// the JSON-RPC error code to return, so both transports classify failures identically.
//
// The reason never embeds the underlying error text (which can carry a remote upstream's
// internal hostname/path), so the host only ever sees the failure class. Only the generic
// UPSTREAM_ERROR branch logs the full error to w — the others are already on the tape, so
// re-logging them would spam it under a sustained outage.
func upstreamErrInfo(notices noticeWriter, err error, upstreamTimeMs int) (code, reason string, rpcCode int) {
	switch {
	case errors.Is(err, errDuplicateID):
		// A host pipelined a request reusing an in-flight JSON-RPC id: a client fault, not an
		// upstream failure — the record must not be mined as an upstream outage.
		return codeInvalidRequest, "duplicate JSON-RPC request id already in flight", jsonRPCCodeInvalidRequest
	case errors.Is(err, errUntranslatableAcrossRevisions):
		// Produced AT the upstream call but not BY the upstream: the pair's revisions cannot
		// carry this message, and the server never saw it. Recording it as an outage would
		// report a healthy upstream as failing, which is the same reason errDuplicateID above
		// is classified as a client fault rather than one.
		//
		// The reason is the error's own text, which revisionRefusalReason also echoes: every
		// part of it comes from a closed set (two published revisions, a routed method, and a
		// reason declared in this build), so none of it is peer-supplied.
		return capability.ErrCodeUntranslatableAcrossRevisions, err.Error(), capability.JSONRPCCodeUnsupportedProtocolVersion
	case errors.Is(err, mcp.ErrFrameDesync):
		// A partial frame from a NON-deadline cause (EPIPE, ENOSPC, an interrupted write). Not a
		// timeout: reporting it as one would fabricate a "did not respond within N ms" for an
		// upstream that crashed. Falls to the generic upstream-error class.
		return codeUpstreamError, "upstream connection failed", jsonRPCCodeInternalError
	case errors.Is(err, mcp.ErrUpstreamWriteTimeout):
		// The bounded upstream stdin write timed out (subprocess stopped draining stdin) — a
		// genuine timeout, classified as UPSTREAM_TIMEOUT rather than the generic UPSTREAM_ERROR
		// so the same physical failure doesn't get two different codes depending on which side.
		return codeUpstreamTimeout, upstreamTimeoutReason(upstreamTimeMs), jsonRPCCodeInternalError
	case errors.Is(err, context.DeadlineExceeded):
		return codeUpstreamTimeout, upstreamTimeoutReason(upstreamTimeMs), jsonRPCCodeInternalError
	case errors.Is(err, context.Canceled):
		return codeRequestCanceled, "request canceled before the upstream responded", jsonRPCCodeInternalError
	default:
		// A remote HTTP upstream's ResponseHeaderTimeout fires as a *url.Error that is a
		// net.Error with Timeout()==true but does NOT wrap context.DeadlineExceeded, so the
		// errors.Is check above misses it. Classify it as UPSTREAM_TIMEOUT too.
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return codeUpstreamTimeout, upstreamTimeoutReason(upstreamTimeMs), jsonRPCCodeInternalError
		}
		if line, ok := notices.admitNotice(siteUpstreamError); ok {
			line.writef("[eunox] upstream error: %v\n", err)
		}
		return codeUpstreamError, "upstream error", jsonRPCCodeInternalError
	}
}

// upstreamTimeoutReason builds the host-safe reason string for an upstream timeout, naming
// the configured --upstream-timeout when set, else the inherited request deadline.
func upstreamTimeoutReason(upstreamTimeMs int) string {
	if upstreamTimeMs <= 0 {
		return "upstream did not respond before the request deadline"
	}
	return fmt.Sprintf("upstream did not respond within %d ms", upstreamTimeMs)
}

// strictAudit builds the --require-audit=strict configuration from the proxy's own fields, so
// the five call sites threading it into dispatchParams/serverRequestParams share one
// construction and can't silently drop a new field on a subset of them.
func (p *HTTPProxy) strictAudit() strictAuditState {
	return strictAuditState{
		requireAuditStrict: p.requireAuditStrict,
		strictAuditWarned:  &p.strictAuditWarned,
	}
}

// dispatchParams bundles this session's policy/audit/upstream wiring for the shared request
// dispatcher. The route sink is routed through asRecorder so a nil sink becomes a true nil
// interface. The request's revision is NOT among them — it rides the context; see
// requestRevision.
func (p *HTTPProxy) dispatchParams(sess *httpSession, sourceIP string) dispatchParams {
	rt := sess.route
	return dispatchParams{
		forwardParams: forwardParams{
			rec:              asRecorder(rt.sink),
			audit:            rt.audit,
			sessionID:        sess.id,
			upstreamTimeMs:   p.upstreamTimeMs,
			callUpstream:     withCrossRevisionTranslation(sess.upstreamRev, sess.callUpstream),
			strictAuditState: p.strictAudit(),
			limits:           p.routeRefusalLimits(sess, rt),
		},
		pdp:              rt.pdp,
		sourceIP:         sourceIP,
		buildInit:        sess.buildInitResponse,
		receipts:         rt.receipts,
		honorAttribution: rt.honorAttribution,
	}
}

// initStrictAuditDenial applies the --require-audit=strict gate to the session-creating
// initialize branch. Creating a session is a privileged side effect (spawns/contacts an
// upstream), so a degraded trail refuses it fail-closed, mirroring the other enforced paths.
// Returns the JSON-RPC denial and true when the gate blocks.
func (p *HTTPProxy) initStrictAuditDenial(ctx context.Context, route *UpstreamRoute, msg mcp.RPCMsg) (mcp.RPCMsg, bool) {
	fp := forwardParams{
		rec:              asRecorder(route.sink),
		sessionID:        "", // no session exists yet on the creating initialize
		strictAuditState: p.strictAudit(),
		limits:           refusalLimits{notices: p.routeNoticeWriter(route)},
	}
	// initialize addresses no sub-target, so audit id/method/denial target all collapse to
	// "initialize" (see dispatchList for the same pattern). Zero decision: nothing exists yet
	// to have cleared a flow label.
	return fp.strictAuditDenial(ctx, msg, mcp.MethodInitialize, mcp.MethodInitialize, mcp.MethodInitialize, capability.EnforceResponse{})
}

// initAudienceDenial applies the per-route JWT audience pin to the session-creating
// initialize, before any upstream is spawned/contacted: a token valid only for another
// route's audience (accepted by the gateway's shared union validator) must not create a
// session here. Mirrors initStrictAuditDenial; non-JWT routes never block.
//
// The record is rate-limited via preSessionAudienceRecorder (catAudience): a caller
// holding one valid token for any sibling route's audience reaches this on every route
// its own audience fails, with no session ever created — an unbounded write here would be
// the same audit-queue-flooding primitive the pre-session kill records are bounded
// against, degrading the sink and, under --require-audit=strict, denying every route.
func (p *HTTPProxy) initAudienceDenial(ctx context.Context, route *UpstreamRoute, msg mcp.RPCMsg) (mcp.RPCMsg, bool) {
	deny := route.pdp.CheckAudience(ctx)
	if deny == nil {
		return mcp.RPCMsg{}, false
	}
	d := normalizeDenial(deny.Denial)
	if rec := p.preSessionAudienceRecorder(route); rec != nil {
		rec.RecordDeny(ctx, "", mcp.MethodInitialize, mcp.MethodInitialize, d.Code, d.ConditionType, d.Details, false)
	}
	return denialResult(msg.ID, d.Code, d.ConditionType, mcp.MethodInitialize, ""), true
}

// handleHTTPUpstreamRequest handles server-initiated JSON-RPC requests from the upstream
// subprocess (local mode only). sampling/createMessage is denied by default unless the
// manifest explicitly permits it; all other server-initiated requests broadcast to SSE.
func (p *HTTPProxy) handleHTTPUpstreamRequest(ctx context.Context, sess *httpSession, msg mcp.RPCMsg) {
	// rt is dereferenced unconditionally, matching dispatchParams and the GET/DELETE paths: a
	// session always carries the route it was established on.
	rt := sess.route
	// Serialize the sampling decision against host-path decisions on the same anchor, so a
	// flowLabel sink on system:sampling cannot peek the flow set concurrently with a host
	// source's write. Same anchor-keyed gate the host path uses; nil for a non-flow route.
	//
	// The anchor comes from the SESSION's claims captured at initialize (see
	// serverRequestParams.claims), so the turn and the state key agree. Agreeing with each
	// other is not enough — a task-anchored session may span anchors, so this leg refuses
	// outright once the session has resolved a second one (anchorSplit below), rather than
	// risk peeking a bucket the host leg taints under a different anchor.
	//
	// Bounded (see samplingTurnWait): runs on its own goroutine, up to
	// maxConcurrentServerRequests per session, not the reader — see decideSampling.
	var decideLock func() (end func(), ok bool)
	if rt.serializes() {
		decideLock = func() (func(), bool) { return sess.beginDecisionTurnWithin(samplingTurnWait) }
	}
	// sess.broadcastServerRequest reports whether an SSE subscriber received the request;
	// sess.claims is attached so per-agent kills are honored and records carry agent_id.
	forwardServerRequest(ctx, msg, serverRequestParams{
		rec:       asRecorder(rt.sink),
		audit:     rt.audit,
		sessionID: sess.id,
		sourceIP:  sess.clientIP,
		claims:    sess.claims,
		// The session's revision is known here, so the leg's records must name it — without
		// it a sampling decision on a fully negotiated session was indistinguishable on the
		// tape from a pre-session refusal, the one case an absent field is supposed to mean.
		// forwardServerRequest does the stamping; this supplies the fact.
		revision: sess.hostRev,
		forward: func(ctx context.Context, m mcp.RPCMsg) bool {
			return sess.broadcastServerRequest(ctx, m)
		},
		// Through the seam, not a bare closure over the concrete writer: remote-upstream mode
		// leaves upWriter nil, and every denial arm below answers the initiator AFTER its audit
		// record — a nil-receiver panic there leaves a tape recording a denial the process died
		// delivering. See writeToInitiator.
		unblocker:  sess.unblocker(),
		decideLock: decideLock,
		// A session that has spanned two state anchors cannot decide on this leg at all; see
		// samplingAnchorSplitDenial. Always wired: the session answers false unless it
		// actually spanned, so the question is asked in one place.
		anchorSplit:      sess.spansAnchors,
		strictAuditState: p.strictAudit(),
		pdp:              rt.pdp,
	})
}
