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
// So the key is the STABLE CALLER IDENTITY, resolved under the route's own STATE ANCHOR — the
// same subject stateful policy keys on, through the same `enforcement.ResolveStateAnchor` the
// engine's own key builder uses, so the worker map and the accumulated state cannot come to
// disagree about which subject a request belongs to. On the default session arm the identity IS
// the anchor; the task arm adds the task beside it, one worker per (identity, task), because the
// anchor alone is coarser than the owner binding every request on that worker must clear — see
// stableCallerIdentity and workerKey. Per the ADR's scope-key/revocation-key split, `jti` is the
// finest REVOCABLE unit and would fragment cross-request state under token rotation, so it stays
// revocation-only.
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
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
)

// firstRequestWorkerKey names the worker a declaring peer's request maps to, and reports whether
// the caller presented the identity one can be keyed on.
//
// The ANCHOR is resolved through the route's own resolver, so a task-anchored route separates its
// workers by task exactly as it keys the decision turn and the engine keys its state — one
// resolution, three consumers, no chance of two of them disagreeing about which subject a request
// belongs to.
//
// The IDENTITY rides alongside it rather than being folded into it, because the anchor is not
// always as fine as the gates every request on the worker must clear: the task arm resolves the
// validated `task_id` ALONE, and two identities sharing one — the shape task anchoring exists for
// ("two sessions sharing a task share a turn") — would otherwise resolve one key, letting the
// first mint a worker whose ownerMismatch then refuses every request from the second for that
// worker's whole life. Sharing an anchor is sharing STATE, which the engine keys on the anchor
// itself; it was never sharing the upstream and the captured claims a worker owns.
func firstRequestWorkerKey(route *UpstreamRoute, ctx context.Context) (string, bool) {
	claims := pdp.JWTClaimsPtr(ctx)
	identity, ok := stableCallerIdentity(claims)
	if !ok {
		return "", false
	}
	anchor := route.decisionAnchor(identity, claims)
	if anchor.ID == "" {
		return "", false
	}
	return workerKey(route.name, anchor, identity), true
}

// stableCallerIdentity is the correlator a worker and its policy state are keyed on.
//
// It is the OWNER BINDING's tuple — issuer and subject — plus the agent the token speaks for.
// Not `agent_id` alone, and that is a correctness requirement rather than a preference: every
// request on a worker passes ownerMismatch, which compares (iss, sub) against the claims the
// worker was created with. A key coarser than that binding hands the first caller a worker every
// OTHER caller sharing its agent id is then permanently refused on — an `AUTHORIZATION_FAILED`
// per attempt, forever, for traffic that is entirely legitimate. So the key is at least as fine
// as every per-session gate applied to it, which is the invariant to preserve if a gate is added
// — and it is workerKey that HOLDS it, by carrying this tuple on an arm whose anchor does not.
//
// `jti` is deliberately absent. Revocation wants the finest revocable thing and cross-request
// policy wants the most stable correlator; under short-lived rotating credentials a jti-keyed
// worker would be a new upstream per refresh, and a jti-keyed `sequenceBlock` could never
// correlate a read with the write that followed it (ADR-0004). Issuer, subject and agent id all
// survive rotation.
func stableCallerIdentity(claims *pdp.JWTClaims) (string, bool) {
	if claims == nil {
		return "", false
	}
	if claims.AgentID == "" && claims.Subject == "" {
		return "", false
	}
	// Components joined with a separator each one's own encoding cannot produce, so the tuple is
	// injective before workerKey encodes the whole. Encoding here AND there would be lossless but
	// doubly escaped, and unreadable in a log for no gain.
	return safeKeyComponent(claims.Issuer) + "/" +
		safeKeyComponent(claims.Subject) + "/" +
		safeKeyComponent(claims.AgentID), true
}

// workerKey renders a route, an anchor and the caller identity as one map key.
//
// NOT enforcement.StateAnchor.Key(), which separates with NUL. This string becomes the worker's
// id, and a worker's id is both PRINTED to an operator's console and signed into the audit
// record's `session_id` — the latter through SanitizeAuditField, which maps every control rune
// and invalid UTF-8 byte to a space. A key carrying either would be recorded as something other
// than itself, and two distinct workers could collapse onto one recorded id.
//
// The anchor id is encoded HERE rather than only in stableCallerIdentity, because the anchor has
// two arms and only one of them came through that function: a task-anchored route resolves to the
// validated `task_id` claim verbatim, which is as caller-supplied as the rest. Encoding at the one
// point every worker id is built is what makes "a worker id is printable and injective" a property
// of the type rather than of remembering which arm produced it.
//
// The identity is APPENDED for an anchor that is not already the identity, which today is the task
// arm: the anchor alone is coarser than the owner binding every request on the worker must clear.
// The predicate is the REDUNDANCY itself rather than the anchor kind, which is only a proxy for it
// (firstRequestWorkerKey resolves the session arm's anchor FROM this identity, so the two coincide
// today): a kind whose id is something else — a minted id, a second caller, an anchor kind that
// does not exist yet — would silently drop the identity again under a kind test, which is the
// lockout this composition exists to close, reintroduced on whichever arm went unexamined.
//
// Unambiguous without escaping the other components: a route name matches `^[a-zA-Z0-9_-]+$` and
// the anchor kind is a closed vocabulary, so neither can carry the `:` they are joined on.
func workerKey(routeName string, anchor enforcement.StateAnchor, identity string) string {
	key := routeName + ":" + string(anchor.Kind) + ":" + safeKeyComponent(anchor.ID)
	if anchor.ID != identity {
		key += ":" + safeKeyComponent(identity)
	}
	return boundWorkerKey(key)
}

// maxWorkerKeyBytes bounds a WHOLE worker id, as maxKeyComponentBytes bounds one component of it.
//
// Tied to maxClaimedSessionIDLen because that is the tighter of the two caps this id must survive
// downstream, and the consequence of crossing it is silent: /control/kill refuses a session id over
// that bound, on the premise that "an over-length id names no session this proxy ever minted" — so
// a worker whose own derived id exceeds it is one the TARGETED emergency stop cannot name, leaving
// only the global, agent and token dimensions. It is also under the audit tape's own
// auditSessionIDCap, so the recorded session_id is the id rather than a truncation of it — and a
// truncation is worse than long here, since the per-component digest that separates two callers is
// at the END of the component the cut would land in.
//
// A per-component budget alone cannot hold this: the key is a route name plus up to two bounded
// components, and one identity on one task already reaches 214 bytes with ordinary enterprise
// claims (a tenant-scoped issuer, a UUID subject, a dated task id).
const maxWorkerKeyBytes = maxClaimedSessionIDLen

// boundWorkerKey cuts an over-length worker id and appends a digest of the WHOLE key, so two
// workers whose ids share a prefix stay distinct across the cut — safeKeyComponent's rule one level
// up, applied to the joined result rather than to one component, and kept separate from it because
// the two budgets answer different questions (what one caller-supplied claim may cost, versus what
// the id as a whole must fit in).
func boundWorkerKey(key string) string {
	if len(key) <= maxWorkerKeyBytes {
		return key
	}
	sum := sha256.Sum256([]byte(key))
	tail := "~" + hex.EncodeToString(sum[:8])
	return key[:maxWorkerKeyBytes-len(tail)] + tail
}

// maxKeyComponentBytes bounds one caller-supplied component of a worker key.
//
// The claims are validated, but "validated" says the IdP signed them — not that it bounded them.
// The key becomes a map key, an audit field and a log line, so an unbounded component is an
// unbounded allocation per identity on all three.
const maxKeyComponentBytes = 128

// safeKeyComponent renders a caller-supplied claim so it can be a worker id: printable, bounded,
// and INJECTIVE, so two identities can never become one worker or one recorded session_id.
//
// Percent-encoded rather than sanitized. Sanitizing is what the audit writer does on the way out
// and it is lossy by design — `"a\tb"` and `"a\x01b"` both become `"a b"` — so a key that relied
// on it would let two distinct callers share a worker, its accumulated quota and its upstream.
// Encoding is reversible, so distinct inputs stay distinct, and it removes the log-injection
// surface at the same time: an `agent_id` of `"x\n[eunox] ..."` cannot forge a console line
// because no byte outside the unreserved set survives to be printed.
//
// Over the length bound the encoding is truncated and a digest of the WHOLE input appended, so
// injectivity survives truncation. `~` is outside the unreserved set, so it cannot appear in the
// encoded prefix and cannot be confused for one.
func safeKeyComponent(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '.', c == '_':
			b.WriteByte(c)
		default:
			const hexDigits = "0123456789ABCDEF"
			b.WriteByte('%')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&0x0F])
		}
	}
	out := b.String()
	if len(out) <= maxKeyComponentBytes {
		return out
	}
	sum := sha256.Sum256([]byte(s))
	return out[:maxKeyComponentBytes] + "~" + hex.EncodeToString(sum[:8])
}

// firstRequestSession resolves the worker a declaring peer's enforced request runs on, creating
// it when this is the first request that reached it. It returns nil when the request may not have
// one, having written the refusal — except for a caller whose own context ended, which is
// answered nothing because there is nobody left to answer.
//
// msg must be a REQUEST — its caller drops every other framing before reaching here, since a
// message that cannot be answered must not fork an upstream. The refusals below still route
// through writeDispatchResult rather than writeJSONMsg so that precondition is not the only
// thing standing between a framing and a reply JSON-RPC forbids.
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
	// The common case by far: every request after the first on this identity. A worker still
	// COMING UP is waited for rather than joined — registerSession publishes before the
	// session-start drift check runs, and this id is derivable from the caller's own claims, so
	// without the wait a second request could be served on a worker whose FM-5 check has not
	// compared the upstream's tools against the manifest and whose Tier-2 baseline is unset.
	if sess := p.getSession(key); sess != nil && sess.route == route {
		switch p.awaitEstablished(ctx, sess) {
		case workerServable:
			return sess
		case waiterGone:
			// The CALLER went away while its worker was coming up, which says nothing about that
			// worker. Falling through here would CREATE one for a request nobody is waiting on:
			// newSession forks the upstream before anything reads the context (exec.Command, not
			// CommandContext), so the process is spawned and then SIGKILLed a moment later when
			// initUpstream fails on the same dead context — one fork-and-kill per aborted
			// request, and the key is derived from the caller's own claims, so an authenticated
			// caller knows exactly when this window is open. Nothing is written either: there is
			// no one left to answer.
			return nil
		case workerGone:
			// Torn down while coming up (a failed drift check does that). Fall through and try
			// to create one, exactly as if it had never been there.
		}
	}
	if deny := route.pdp.CheckKill(ctx, key); deny != nil {
		// verifiedSession, not claimedSession: the key is eunox's OWN derivation from claims a
		// signature already validated, never a string read back off the request — which is the
		// hazard that field guards against. It names a worker about to exist rather than one
		// that does, and it is the subject the kill check just consulted, so stamping it as fact
		// is honest and is what makes the record correlate with the traffic that follows.
		writeDispatchResult(w, recordKillDenial(ctx, p.preSessionKillRecorder(route), deny, msg, verifiedSession(key)))
		return nil
	}
	identifier, method := auditIdentity(msg)
	if denied, blocked := p.creationAudienceDenial(ctx, route, msg, identifier, method); blocked {
		writeDispatchResult(w, denied)
		return nil
	}
	if denied, blocked := p.creationStrictAuditDenial(ctx, route, msg, identifier, method); blocked {
		writeDispatchResult(w, denied)
		return nil
	}
	return p.createFirstRequestSession(ctx, w, r, route, key, rev, startGen)
}

// createFirstRequestSession spawns the upstream and registers the worker under key, or writes the
// creation failure. A concurrent request that won the race is adopted rather than displaced.
func (p *HTTPProxy) createFirstRequestSession(ctx context.Context, w http.ResponseWriter, r *http.Request, route *UpstreamRoute, key string, rev capability.Revision, startGen uint64) *httpSession {
	// Spawning an upstream is the privileged side effect this whole path exists to gate, so a
	// caller that is already gone gets none of it. Checked HERE rather than only where the wait
	// reports waiterGone, because the wait is not the only way to arrive with a dead context: the
	// gates above run a kill lookup that is a network round trip on a Redis-backed switch, and a
	// client that hangs up across it would otherwise still fork and immediately kill a process.
	if ctx.Err() != nil {
		return nil
	}
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
			switch p.awaitEstablished(ctx, existing) {
			case workerServable:
				return existing
			case waiterGone:
				return nil // nobody left to adopt it for, and nobody left to answer
			case workerGone:
			}
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
	if rec := p.routeRefusalLimits().recorders(refusalSink(p, route)).forCategory(catUnservable); rec != nil {
		identifier, method := auditIdentity(msg)
		rec.RecordDeny(ctx, "", identifier, method,
			capability.ErrCodeEnforcementError, "", unservableDetail(rev, unservableUnauthenticated), false)
	}
	w.Header().Set("WWW-Authenticate", buildWWWAuthenticate(r.Header.Get("Authorization") != "", p.oauthMetaURL))
	http.Error(w, "a "+rev.String()+" host must present a credential carrying a stable agent identity: "+
		"the revision has no handshake to establish one, and an unidentified request has no worker to run on",
		http.StatusUnauthorized)
}
