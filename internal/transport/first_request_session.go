// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Session creation without `initialize`: what mints the internal worker for a 2026-07-28 host,
// and what it is keyed on.
//
// # Why there is anything to mint at all
//
// 2026-07-28 is stateless on the wire, but eunox's `httpSession` is not a protocol session and
// never was — it is the thing that OWNS one upstream (a subprocess, or a remote HTTP bridge) and
// its in-flight bookkeeping, plus the decision-turn pin, the identity capture and the reaper. A
// stdio upstream is a stateful subprocess and cannot be forked per request. So the worker
// survives the revision that removed the session; what changes is what CREATES it and what it is
// keyed BY (ADR-0004, and its addendum on session creation).
//
// # What it is keyed by, and why not a minted id
//
// The old path mints a UUID and hands it back in `Mcp-Session-Id`. A declaring peer echoes no
// such header, so a minted id would have nothing to arrive on: every request would mint a new
// worker, fork a new upstream, and accumulate its policy state in a bucket nothing else ever
// reaches — quotas that never bind, `sequenceBlock` antecedents that never correlate.
//
// So the key is the RESOLVED STATE ANCHOR — the same subject stateful policy keys on, through
// the same `enforcement.ResolveStateAnchor` the engine's own key builder uses, so the worker map
// and the accumulated state cannot come to disagree about a request. The stable caller identity
// (`agent_id`) is what fills the anchor's session slot, per the ADR's scope-key/revocation-key
// split: `jti` is the finest REVOCABLE unit and would fragment cross-request state under token
// rotation, so it stays revocation-only.
//
// The key is namespaced by ROUTE because `p.sessions` is one flat map across a gateway's
// upstreams and `handleSessionPost` answers 409 on a route mismatch. A UUID could never collide;
// a stable identity reaching two routes would, and the second route would be refused a worker it
// is entitled to.
//
// # What is deliberately NOT here
//
// An UNAUTHENTICATED declaring request is refused, on both upstream kinds. With no handshake and
// no credential there is no stable identity to key a worker on, so each request would fork its
// own upstream — a resource-exhaustion vector rather than a session model. ADR-0004 also permits
// serving such traffic per-request against a REMOTE upstream, which costs no subprocess; that is
// a separate shape (an ephemeral worker owned by one request) and is not built here. Refusing it
// meanwhile takes nothing away — no declaring peer was served over HTTP at all before this — and
// it is the fail-closed direction.

package transport

import (
	"context"
	"net/http"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
)

// firstRequestWorkerKey names the worker a declaring peer's request maps to, and reports whether
// the caller presented the stable identity one can be keyed on.
//
// Resolved through the route's own anchor resolver, so a task-anchored route keys its workers on
// the task exactly as it keys the decision turn and the engine keys its state — one resolution,
// three consumers, no chance of two of them disagreeing about which subject this request belongs
// to.
func firstRequestWorkerKey(route *UpstreamRoute, ctx context.Context) (string, bool) {
	claims := pdp.JWTClaimsPtr(ctx)
	identity := stableCallerIdentity(claims)
	anchor := route.decisionAnchor(identity, claims)
	// A task-anchored route resolving to the task needs no agent id; every other case does.
	if anchor.ID == "" {
		return "", false
	}
	return workerKey(route.name, anchor), true
}

// workerKey renders a route and an anchor as one map key, printably.
//
// NOT enforcement.StateAnchor.Key(), which separates with NUL. This string becomes the worker's
// id, and a worker's id is signed into the audit record's `session_id` — through
// SanitizeAuditField, which rewrites control runes. A NUL key would therefore be recorded as
// something other than itself, and two distinct workers could sanitize onto one recorded id.
//
// Unambiguous without escaping because only the LAST component is free: a route name matches
// `^[a-zA-Z0-9_-]+$` so it carries no colon, the anchor kind is a closed vocabulary, and the
// caller-supplied id is terminal — so no two (route, kind, id) triples can render alike however
// the id is spelled.
func workerKey(routeName string, anchor enforcement.StateAnchor) string {
	return routeName + ":" + string(anchor.Kind) + ":" + anchor.ID
}

// stableCallerIdentity is the correlator a worker and its policy state are keyed on: the agent
// the token speaks for, never the token instance.
//
// `jti` is deliberately not it. Revocation wants the finest revocable thing and cross-request
// policy wants the most stable correlator; under short-lived rotating credentials a jti-keyed
// worker would be a new upstream per token, and a jti-keyed `sequenceBlock` could never correlate
// a read with the write that followed it (ADR-0004).
func stableCallerIdentity(claims *pdp.JWTClaims) string {
	if claims == nil {
		return ""
	}
	return claims.AgentID
}

// firstRequestSession resolves the worker a declaring peer's enforced request runs on, creating
// it when this is the first request that reached it. It writes the refusal and returns nil when
// the request may not have one.
//
// The gate order mirrors handleSessionCreatingInitialize's exactly, and for its reasons: the reap
// generation is captured BEFORE anything that can block, the kill switch is consulted before an
// upstream is spawned, the audience pin before that spawn is a side effect a cross-audience token
// caused, and `--require-audit=strict` before a privileged action runs untraceably. What differs
// is only that the identity is required first — with no credential there is no worker key, so
// there is nothing for the later gates to be about.
func (p *HTTPProxy) firstRequestSession(w http.ResponseWriter, r *http.Request, route *UpstreamRoute, rev capability.Revision, msg mcp.RPCMsg) *httpSession {
	// Captured before anything that can block, for registerSession's reason: a kill sweep
	// landing inside the creation window must not let this worker register into the fresh map.
	startGen := p.currentReapGen()
	ctx := capability.WithProtocolRevision(r.Context(), rev)

	key, ok := firstRequestWorkerKey(route, ctx)
	if !ok {
		p.refuseUnkeyableFirstRequest(ctx, w, r, route, rev, msg)
		return nil
	}
	// The common case by far: every request after the first on this identity.
	if sess := p.getSession(key); sess != nil && sess.route == route {
		return sess
	}
	if deny := route.pdp.CheckKill(ctx, key); deny != nil {
		// verifiedSession, not claimedSession: the key is eunox's OWN derivation from claims a
		// signature already validated, never a string read back off the request — which is the
		// hazard that field guards against. It names a worker about to exist rather than one
		// that does, and it is the subject the kill check just consulted, so stamping it as fact
		// is honest and is what makes the record correlate with the traffic that follows.
		writeJSONMsg(w, recordKillDenial(ctx, p.preSessionKillRecorder(route), deny, msg, verifiedSession(key)))
		return nil
	}
	identifier, method := auditIdentity(msg)
	if denied, blocked := p.creationAudienceDenial(ctx, route, msg, identifier, method); blocked {
		writeJSONMsg(w, denied)
		return nil
	}
	if denied, blocked := p.creationStrictAuditDenial(ctx, route, msg, identifier, method); blocked {
		writeJSONMsg(w, denied)
		return nil
	}
	return p.createFirstRequestSession(ctx, w, r, route, key, rev, startGen)
}

// createFirstRequestSession spawns the upstream and registers the worker under key, or writes the
// creation failure. A concurrent request that won the race is adopted rather than displaced.
func (p *HTTPProxy) createFirstRequestSession(ctx context.Context, w http.ResponseWriter, r *http.Request, route *UpstreamRoute, key string, rev capability.Revision, startGen uint64) *httpSession {
	if !p.tryReserveSessionSlot() {
		p.recordSessionCapDeny(ctx, r, route)
		http.Error(w, "session limit reached", http.StatusServiceUnavailable)
		return nil
	}
	// One owner, one release — success included. See handleSessionCreatingInitialize.
	defer p.releaseSessionSlot()

	startBudget := sessionStartTimeout
	if b := msToDuration(p.upstreamTimeMs); p.upstreamTimeMs > 0 && b > startBudget {
		startBudget = b
	}
	rearmWriteDeadlineFor(w, startBudget)
	initCtx, cancel := context.WithTimeout(ctx, sessionStartTimeout)
	defer cancel()

	// Captured before creation: upstream-initiated sampling carries no request of its own and is
	// evaluated against this address, and setting it after would race the reader goroutine.
	clientIP := p.sourceIP(r)
	var (
		sess *httpSession
		err  error
	)
	if route.transport == "http" {
		sess, err = p.newRemoteSession(initCtx, route, clientIP, startGen, firstRequestSeed(key, rev))
	} else {
		sess, err = p.newSession(initCtx, route, clientIP, startGen, firstRequestSeed(key, rev))
	}
	if err != nil {
		// A concurrent first request on the same identity already registered one. Adopt it:
		// both requests are the same subject by construction, so the loser has nothing of its
		// own to preserve, and its upstream is already torn down by the failed create.
		if existing := p.getSession(key); existing != nil && existing.route == route {
			return existing
		}
		p.writeSessionCreateError(ctx, w, r, route, err)
		return nil
	}
	return sess
}

// refuseUnkeyableFirstRequest answers a declaring request that presented no stable identity.
//
// 401 rather than the JSON-RPC denial the gates below it write: this is authentication, not a
// policy verdict — the same distinction handleMCP's own JWT pre-validation makes when it answers
// 401 even in audit mode — and there is no session, no anchor and no decision to report.
//
// Recorded for the reason every pre-session refusal is: it is reachable by an unauthenticated
// off-host caller at one record per frame, and it is the record that says someone is probing the
// declaring surface. Metered on the same bucket, under ENFORCEMENT_ERROR — eunox reached no
// verdict, and the reason is the deployment's shape rather than the request's content.
func (p *HTTPProxy) refuseUnkeyableFirstRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, route *UpstreamRoute, rev capability.Revision, msg mcp.RPCMsg) {
	if rec := p.routeRefusalLimits(nil, route).recorders(refusalSink(p, route)).forCategory(catUnservable); rec != nil {
		identifier, method := auditIdentity(msg)
		rec.RecordDeny(ctx, "", identifier, method,
			capability.ErrCodeEnforcementError, "", unservableDetail(rev, unservableUnauthenticated), false)
	}
	w.Header().Set("WWW-Authenticate", buildWWWAuthenticate(r.Header.Get("Authorization") != "", p.oauthMetaURL))
	http.Error(w, "a "+rev.String()+" host must present a credential carrying a stable agent identity: "+
		"the revision has no handshake to establish one, and an unidentified request has no worker to run on",
		http.StatusUnauthorized)
}
