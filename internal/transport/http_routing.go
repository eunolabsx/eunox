// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// HTTP request routing: the /mcp POST / GET / DELETE handlers and the
// loopback-only /control/kill endpoint.

package transport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// writeJSONMsg sets the JSON content type and encodes v as the response body. Status-less:
// no call site interleaves a WriteHeader between the header and the body, so this collapses
// the copy-pasted idiom into one place a future site can't forget the header on.
// writeKillResponse uses json.Marshal + w.Write instead — folding it in here would add the
// Encoder's trailing newline to that response body.
func writeJSONMsg(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", CTJSON)
	_ = json.NewEncoder(w).Encode(v)
}

// handleMCP dispatches POST / GET / DELETE requests to /mcp.
func (p *HTTPProxy) handleMCP(w http.ResponseWriter, r *http.Request) {
	if !p.checkAuth(w, r) {
		return
	}
	// JWT pre-validation: authentication, not policy — 401 even in audit mode. Runs BEFORE
	// route lookup so an unauthenticated caller gets a uniform 401 regardless of whether
	// the route exists; resolving the route first would turn 404-vs-401 into a route-name
	// enumeration oracle.
	if p.jwtPDP != nil {
		authHeader := r.Header.Get("Authorization")
		ctx, err := p.jwtPDP.ValidateToken(r.Context(), authHeader)
		if err != nil {
			// Record a stable error_type CATEGORY, never the raw err.Error(): the go-jose
			// message can disclose claim values, the accepted algorithm, or key-rotation
			// state, and audit logs are commonly forwarded to third-party SIEMs.
			p.recordPreSessionDeny(r, "JWT_INVALID", catJWT, map[string]interface{}{"error_type": pdp.ClassifyJWTError(err)})
			w.Header().Set("WWW-Authenticate", buildWWWAuthenticate(authHeader != "", p.oauthMetaURL))
			// Do not echo the validation error to the caller for the same fingerprinting
			// reason; the category is preserved in the JWT_INVALID record above instead.
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		r = r.WithContext(ctx)
	}
	// Resolve the upstream route from the path segment. PathValue is "" for the
	// "/mcp" pattern (single-upstream mode → route key "").
	route := p.routes[r.PathValue("upstream")]
	if route == nil {
		http.Error(w, "unknown upstream route", http.StatusNotFound)
		return
	}
	switch r.Method {
	case http.MethodPost:
		p.handleMCPPost(w, r, route)
	case http.MethodGet:
		p.handleMCPGet(w, r, route)
	case http.MethodDelete:
		p.handleMCPDelete(w, r, route) //nolint:contextcheck // teardown path: the upstream session-termination DELETE intentionally uses a detached, bounded background context — close/reaper/signal/shutdown carry no request context.
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// decodeStrictJSON is the single safe way to read a JSON POST body in this package. It
// gates the Content-Type (415), then decodes exactly one JSON value into v, requiring
// io.EOF after it: a body carrying a trailing token is rejected with 400 rather than
// silently truncated — otherwise a multi-token /mcp body could 202-ack an invalid
// initialize notification, or a /control/kill body could execute a narrower kill while
// ignoring a smuggled trailing {"all":true}. On a refused content type, a decode failure,
// or trailing data it writes the response itself and returns false; the caller must return
// immediately. The 400 legs are recorded via recordRefusal (codeInvalidRequest) through
// the same rate-limited pre-session path as the 415 leg, so a malformed body leaves the
// same trace other transport-level refusals do; the 413 leg is not recorded since
// MaxBytesReader already bounds that flood's cost.
//
// route is threaded to requireJSONContentType and recordRefusal so the /mcp caller's
// records carry its route stamp; /control/kill has no route and passes nil, which
// recordRefusal treats as "write through the proxy-wide sink".
//
// The content-type gate lives HERE rather than at each handler so every JSON POST body in
// this package gets it by construction — a mux wrapper is the wrong shape since GET/DELETE
// carry no body.
func (p *HTTPProxy) decodeStrictJSON(w http.ResponseWriter, r *http.Request, v interface{}, invalidBodyMsg string, route *UpstreamRoute) bool {
	if !p.requireJSONContentType(w, r, route) {
		return false
	}
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return false
		}
		// The raw decode error and body are NOT recorded — either can carry
		// attacker-controlled free text; only the fixed reason string is kept.
		p.recordRefusal(r, route, codeInvalidRequest, catBody, map[string]interface{}{
			"reason": "malformed_json",
		})
		http.Error(w, invalidBodyMsg, http.StatusBadRequest)
		return false
	}
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return false
		}
		p.recordRefusal(r, route, codeInvalidRequest, catBody, map[string]interface{}{
			"reason": "trailing_data",
		})
		http.Error(w, invalidBodyMsg+": trailing data after JSON message", http.StatusBadRequest)
		return false
	}
	return true
}

// writeSessionCreateError maps a newSession/newRemoteSession failure to the right HTTP
// status. Transient/retryable conditions get a 503: errSessionLimit (concurrent-session
// cap), errRacedReap (a global kill swept the registry mid-handshake; the upstream this
// initialize started was already torn down), errShuttingDown (proxy draining). Anything
// else is an upstream-start failure — the raw error may carry a command path, IP:port, or
// TLS detail, so it's logged to stderr and returned as a generic 500.
//
// errSessionLimit is additionally recorded via recordSessionCapDeny, the same helper the
// pre-spawn slot reservation uses, so the two ways to hit one cap can't produce two record
// shapes — it's reachable WITHOUT an established session, so it's the cheaper flood and was
// the one leaving no trace. The other two legs are benign lifecycle races, not attack
// signal, so they stay status-only.
func (p *HTTPProxy) writeSessionCreateError(w http.ResponseWriter, r *http.Request, route *UpstreamRoute, err error) {
	switch {
	case errors.Is(err, errSessionLimit):
		p.recordSessionCapDeny(r, route)
		http.Error(w, "session limit reached", http.StatusServiceUnavailable)
	case errors.Is(err, errRacedReap):
		http.Error(w, "session raced a kill-switch reap; retry", http.StatusServiceUnavailable)
	case errors.Is(err, errShuttingDown):
		http.Error(w, "server shutting down; retry", http.StatusServiceUnavailable)
	default:
		_, _ = fmt.Fprintf(p.errOut(), "[eunox] failed to start upstream: %v\n", err)
		http.Error(w, "upstream unavailable", http.StatusInternalServerError)
	}
}

// handleMCPPost processes a JSON-RPC request from the MCP host for the given
// upstream route.
func (p *HTTPProxy) handleMCPPost(w http.ResponseWriter, r *http.Request, route *UpstreamRoute) {
	// SEC-04: cap request body to prevent memory exhaustion from large payloads.
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	var msg mcp.RPCMsg
	// A single JSON-RPC POST body is exactly one JSON value; decodeStrictJSON fails closed
	// on any trailing token BEFORE dispatching, so a multi-token body can't 202-ack an
	// invalid initialize notification with the trailer silently dropped.
	if !p.decodeStrictJSON(w, r, &msg, "invalid JSON-RPC body", route) {
		return
	}

	// Slowloris backstop over the pre-dispatch writes (202-ack, early 4xx). This does NOT
	// bound the response write: the actual encode always re-arms a fresh httpWriteTimeout
	// window right before writing, so a legitimately slow upstream near its full budget
	// can't leave the entry deadline already past by encode time and drop an already-served
	// response. Through the shared helper so this site can't drift from the response-write
	// one, which also FLOORS the window at httpWriteTimeout regardless of --upstream-timeout.
	rearmWriteDeadline(w, p.upstreamTimeMs)

	sessionID := r.Header.Get(SessionHeader)

	// An initialize request with no session ID creates a new session.
	//
	// Require msg.IsRequest(): an initialize *notification* (no id) must never start an
	// upstream or consume a session slot — handled as a stateless notification below.
	if msg.Method == mcp.MethodInitialize && sessionID == "" && msg.IsRequest() {
		// Captured BEFORE the kill gate below: that gate does a kill-store round-trip that
		// may do I/O, and a kill activating/sweeping inside that window would otherwise
		// yield a startGen equal to the post-sweep generation, letting registerSession admit
		// a kill-denied session that then pins a subprocess/slot until process exit (with no
		// idle reaper configured, that leak never self-heals).
		startGen := p.currentReapGen()
		// Kill-switch check BEFORE spawning anything. This is the one initialize answered
		// outside dispatchRequest (no session/dispatchParams yet), so it repeats the kill
		// gate dispatchRequest applies to every other locally-answered method.
		if deny := route.pdp.CheckKill(r.Context(), ""); deny != nil {
			// No session exists yet, so claimedSession is the honest subject rather than fact.
			// Rate-limited: an unauthenticated caller reaches this record, so an unbounded
			// write here is an audit-queue flooding primitive; a suppressed record elides
			// only the RECORD, the request is denied either way.
			resp := recordKillDenial(r.Context(), p.preSessionKillRecorder(route), deny, msg.ID, claimedSession(r), mcp.MethodInitialize)
			writeJSONMsg(w, resp)
			return
		}
		// Per-route audience pin BEFORE spawning: a token valid only for ANOTHER route's
		// audience (accepted by the gateway's shared union validator) must not create a
		// session on this route. Initialize doesn't flow through the Decide*/list/sampling
		// paths that embed the same pin, so without this gate a cross-audience token could
		// spin up this route's upstream and read its serverInfo.
		if denied, blocked := p.initAudienceDenial(r.Context(), route, msg); blocked {
			writeJSONMsg(w, denied)
			return
		}
		// --require-audit=strict: creating a session spawns/contacts an upstream — a
		// privileged side effect — so once the audit trail has degraded, refuse new sessions
		// fail-closed rather than run traffic that can't be fully recorded.
		if denied, blocked := p.initStrictAuditDenial(r.Context(), route, msg); blocked {
			writeJSONMsg(w, denied)
			return
		}
		// Pre-spawn capacity RESERVATION, not just a check: the slot is taken now and held
		// across establishment, so concurrent initializes can't all pass a registry-only
		// check and each spawn an upstream before any registers. The defer below drops it.
		if !p.tryReserveSessionSlot() {
			// Recorded for the same reason as writeSessionCreateError's errSessionLimit leg:
			// this is its cheap pre-spawn twin, and both go through the one route-stamped
			// helper so the two ways to hit the same cap can't produce two record shapes.
			p.recordSessionCapDeny(r, route)
			http.Error(w, "session limit reached", http.StatusServiceUnavailable)
			return
		}
		// Released unconditionally — success included. One owner, one release: letting
		// registerSession convert the reservation on success instead would double-free it on
		// any failure AFTER registration (a drift refusal is one).
		defer p.releaseSessionSlot()
		// Establishment runs under sessionStartTimeout, independent of --upstream-timeout.
		// Cover the larger of the two so the write deadline can't fire mid-handshake when
		// --upstream-timeout is below sessionStartTimeout.
		startBudget := sessionStartTimeout
		if b := msToDuration(p.upstreamTimeMs); p.upstreamTimeMs > 0 && b > startBudget {
			startBudget = b
		}
		rearmWriteDeadlineFor(w, startBudget)
		initCtx, initCancel := context.WithTimeout(r.Context(), sessionStartTimeout)
		defer initCancel()

		var (
			sess *httpSession
			err  error
		)
		// Capture before session creation: upstream-initiated sampling carries no request
		// of its own and is evaluated against this address. Setting it after creation would
		// race the reader goroutine.
		clientIP := p.sourceIP(r)
		if route.transport == "http" {
			sess, err = p.newRemoteSession(initCtx, route, clientIP, startGen)
		} else {
			sess, err = p.newSession(initCtx, route, clientIP, startGen)
		}
		if err != nil {
			p.writeSessionCreateError(w, r, route, err)
			return
		}
		w.Header().Set(SessionHeader, sess.id)
		// Answered directly, not through dispatchInitialize's kill gate: the global-dimension
		// CheckKill already ran above, and the session id minted here is brand new, so it
		// can't yet be a per-session kill target.
		resp := sess.buildInitResponse(msg)
		writeJSONMsg(w, resp)
		return
	}

	if sessionID == "" {
		// An initialize notification (excluded from the session-creation branch above)
		// expects no response: accept and drop it without allocating session state.
		if msg.Method == mcp.MethodInitialize && msg.IsNotification() {
			// Consult the kill switch BEFORE the 202 ack: a 202 to an initialize
			// notification is a readiness acknowledgement, so returning it during a global
			// emergency stop would tell the client the server is ready, unaudited.
			if deny := route.pdp.CheckKill(r.Context(), ""); deny != nil {
				// A notification MUST NOT receive a JSON-RPC response: msg.ID is nil, so
				// recordKillDenial's response would carry "id":null and, with no prior
				// WriteHeader, send an implicit 200 indistinguishable from a successful
				// readiness ack. Record the deny directly and ack the drop with a bodyless 202.
				recordKillDrop(r.Context(), p.preSessionKillRecorder(route), deny, claimedSession(r), msg.Method, msg.Method, legHTTPNotification)
				w.WriteHeader(http.StatusAccepted)
				return
			}
			w.WriteHeader(http.StatusAccepted)
			return
		}
		http.Error(w, "Mcp-Session-Id header required", http.StatusBadRequest)
		return
	}
	p.handleSessionPost(w, r, route, sessionID, msg)
}

// handleSessionPost handles a host POST carrying an existing Mcp-Session-Id: it validates
// the session/route binding and the per-route audience pin, then forwards a notification,
// routes a host response back to the upstream, answers a re-initialize echo, or dispatches
// an enforced request. Split out of handleMCPPost so the session-creating initialize path
// and the existing-session path each stay within complexity bounds.
func (p *HTTPProxy) handleSessionPost(w http.ResponseWriter, r *http.Request, route *UpstreamRoute, sessionID string, msg mcp.RPCMsg) {
	sess := p.getSession(sessionID)
	if sess == nil {
		// A killed session is proactively torn out of the registry, so its id no longer
		// resolves — but the kill contract is that its requests are DENIED with
		// KILL_SWITCH, not a bare 404 hiding why the session vanished. The kill store
		// outlives the reaped registry entry, so consult it: a killed id (or an active
		// global kill) renders the deny the dispatcher's kill gate would have given had the
		// session still existed. A genuinely unknown, unkilled id still 404s. Handled here
		// rather than via resolveSessionForRoute (the GET/SSE path) because only this
		// request/notification framing can carry a JSON-RPC KILL_SWITCH body.
		//
		// sessionID is the raw, unverified client-supplied header (unlike every other
		// CheckKill call site's, which comes from an established session). Stamping it into
		// the signed session_id field would let anyone forge kill records against an
		// arbitrary session id; claimedSession(r) keeps session_id empty and preserves it
		// only as details.claimed_session_id.
		if deny := route.pdp.CheckKill(r.Context(), sessionID); deny != nil {
			if msg.IsRequest() {
				writeJSONMsg(w, recordKillDenial(r.Context(), p.preSessionKillRecorder(route), deny, msg.ID, claimedSession(r), msg.Method))
			} else {
				// Fire-and-forget: record the drop and ack with a bodyless 202. A response
				// carries no method, so it's identified as "server-response" (distinct from
				// "http-notification") so an operator can tell the two drop SITES apart.
				label, leg := msg.Method, legHTTPNotification
				if msg.IsResponse() {
					label, leg = "server-response", legHTTPServerResponse
				}
				recordKillDrop(r.Context(), p.preSessionKillRecorder(route), deny, claimedSession(r), label, label, leg)
				w.WriteHeader(http.StatusAccepted)
			}
			return
		}
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	if sess.route != route {
		http.Error(w, "session does not belong to this upstream route", http.StatusConflict)
		return
	}
	// Run the session-scoped security gates — the per-route audience pin AND the
	// session-owner binding — on EVERY host-initiated action on this existing session, not
	// just the enforced (Decide) methods: a same-audience SECOND identity that learned this
	// session's id could otherwise reach the forwarded notification, response routing, the
	// re-initialize echo, or an enforced request against a victim's upstream. Runs before
	// touchRequest so a refused request doesn't defer the victim session's idle reaping.
	if gate, denied := route.enforceSessionGates(r.Context(), sess, sessionID, msg.Method, "http-post"); denied {
		if msg.IsRequest() {
			writeJSONMsg(w, denialResult(msg.ID, gate.code, gate.conditionType, msg.Method, ""))
		} else {
			// Fire-and-forget (notification / response, including an id-less initialize
			// notification carrying a victim's Mcp-Session-Id): ack the drop with a bodyless
			// 202, matching the kill-switch notification path — the host cannot act on a body,
			// and a JSON-RPC error body would omit the id (RPCMsg.ID is json:"id,omitempty")
			// under an implicit 200, indistinguishable from success to a status-only client.
			w.WriteHeader(http.StatusAccepted)
		}
		return
	}
	// Note which state anchor this request resolved. On a task-anchored route a session may
	// legitimately span tasks, and every host request is decided, keyed and serialized on
	// its OWN anchor — but the server-initiated leg has no host request in scope, so the
	// session records the span here and that leg refuses for the rest of its life. See
	// httpSession.noteRequestAnchor. Placed here (a write) rather than in the check-only
	// session-gate verdict, one of whose callers runs under the session-registry lock.
	sess.noteRequestAnchor(pdp.JWTClaimsPtr(r.Context()))
	// Check the kill switch BEFORE touchRequest so a killed session's denied POSTs can't
	// keep deferring idle reaping (a request may race reapKilledSession's proactive
	// teardown). Gate ONLY touchRequest on it: enforced requests and re-initialize still
	// flow through the dispatcher below, which re-checks the kill with the precise
	// per-target audit identifier rather than this coarse method-only check.
	kill := route.pdp.CheckKill(r.Context(), sessionID)
	if kill == nil {
		// A live POST is active host-initiated traffic (distinct from passively holding
		// an SSE GET open): it defers both the idle reaper and the hard idle ceiling.
		sess.touchRequest()
	}
	// Host notifications are forwarded verbatim only when allowlisted, after the swallowed
	// set (notifications/initialized, and a mid-session id-less "initialize" — forwarding it
	// verbatim would let a client re-trigger the upstream's handshake outside the
	// dispatcher's kill gate) and the enforced-method fail-closed reject. These don't flow
	// through the dispatcher, so the kill is enforced here.
	if msg.IsNotification() {
		if !isSwallowedHostNotification(msg.Method) {
			if kill != nil {
				recordKillDrop(r.Context(), asRecorder(route.sink), kill, verifiedSession(sess.id), msg.Method, msg.Method, legHTTPNotification)
				w.WriteHeader(http.StatusAccepted)
				return
			}
			// An enforced method framed as a notification (no id) is a fail-closed reject —
			// shared with the stdio transport's equivalent guard so the check and its audit
			// record can't drift between transports. Checked before the notify-slot
			// acquisition below: no point reserving a slot for a notification about to be denied.
			if denyEnforcedMethodNotification(r.Context(), asRecorder(route.sink), sessionID, msg) {
				w.WriteHeader(http.StatusAccepted)
				return
			}
			// Any notification method outside the forwardable allowlist is a fail-closed
			// reject too, so a notification-framed novel/unmapped method can't reach the
			// upstream invisibly while its request-framed twin would be denied and logged.
			if denyUnmappedHostNotification(r.Context(), asRecorder(route.sink), sessionID, msg) {
				w.WriteHeader(http.StatusAccepted)
				return
			}
			// Bound concurrent in-flight notification forwards on this session — its own
			// pool, deliberately separate from the enforced-request slot below, so a burst of
			// tool calls blocked on the upstream can never exhaust it and start dropping
			// notifications/cancelled, leaving the very call the host meant to abort running
			// to completion. Non-blocking: on saturation drop and log rather than block.
			if !sess.tryAcquireNotifySlot() {
				// Record the drop on the tape: an incident responder asking why a call the
				// host tried to abort ran to completion needs this as a record, not a stderr
				// line rotation may have discarded. Gated on this pool's own saturationGate so
				// a flooding session writes one record per saturation EPISODE, not per frame —
				// ungated this was the cheapest audit-write flooding primitive available (no
				// upstream round trip, a 202 identical to success) and enough records latch
				// AuditDegraded(), which under --require-audit=strict denies every route.
				recordResourceExhausted(r.Context(), asRecorder(route.sink), &sess.notifySaturation, sessionID, msg.Method)
				_, _ = fmt.Fprintf(p.errOut(), "[eunox] HTTP session %s: notification %q dropped: too many concurrent notifications in flight\n", sessionID, msg.Method)
				w.WriteHeader(http.StatusAccepted)
				return
			}
			// A plain function-scoped defer suffices: the notification branch always returns
			// two lines below, so it fires effectively immediately.
			defer sess.releaseNotifySlot()
			// Re-arm before the forward: this runs against the entry deadline, so a slow
			// upstream can leave it past by 202-write time and drop a connection for a
			// notification that was in fact delivered.
			rearmWriteDeadline(w, p.upstreamTimeMs)
			sess.forwardNotification(r.Context(), msg)
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}

	if !msg.IsRequest() {
		// A host response to a server-initiated request the proxy broadcast must be routed
		// back to the blocked upstream. Only responses whose ID we forwarded are routed
		// (take consumes the tracked ID); any other non-request POST is acked and ignored.
		if msg.IsResponse() && sess.serverReqs.take(mcp.MsgKey(msg.ID)) {
			switch {
			case kill != nil:
				// A kill doesn't tear the upstream down; its blocked server-initiated
				// request is intentionally left unanswered and reclaimed later by the idle
				// reaper's hard ceiling. Record the dropped reply so it's visible on the tape.
				recordKillDrop(r.Context(), asRecorder(route.sink), kill, verifiedSession(sess.id), "server-response", "server-response", legHTTPServerResponse)
			case sess.upWriter != nil:
				_ = sess.upWriter.Write(msg)
			default:
				// Remote-upstream mode has no upWriter to route the response back. Unreachable
				// today (remote sessions issue no server-initiated requests), pending a fix.
				_, _ = fmt.Fprintf(p.errOut(),
					"[eunox] WARNING: dropped host response to a server-initiated request: no upstream writer in remote-upstream mode\n")
			}
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}

	ctx := r.Context()
	var resp mcp.RPCMsg
	if msg.Method == mcp.MethodInitialize {
		// Re-initialize is answered locally from capabilities captured at session start
		// (ownership binding already enforced above). Routes through the shared dispatcher
		// so its kill gate lives once in dispatchInitialize rather than being copy-maintained
		// here, and is not subject to the in-flight cap below since it contacts no upstream.
		// dispatchInitialize skips strictAuditDenial intentionally: this is a pure local
		// echo of already-captured state, not a fresh decision against upstream state.
		resp = dispatchRequest(ctx, p.dispatchParams(sess, p.sourceIP(r)), msg)
	} else {
		// Bound concurrent in-flight enforced requests on this session (the HTTP analogue
		// of stdio's hostSem). Non-blocking acquire: on saturation reject with a retryable
		// busy error rather than dispatch a handler that blocks in the upstream round-trip.
		if !sess.tryAcquireRequestSlot() {
			// Record the saturation refusal, mirroring the stdio hostSem path, so the
			// network-exposed transport — the surface a DoS probe actually reaches — isn't
			// the one left with no trace while its local stdio twin has one. Episode-gated
			// on this pool's own gate so one flooding pool doesn't elide the other's record.
			recordResourceExhausted(ctx, asRecorder(route.sink), &sess.reqSaturation, sess.id, msg.Method)
			writeJSONMsg(w, mcp.ErrorResponse(msg.ID, jsonRPCCodeServerBusy, "eunox: too many concurrent requests in flight; retry"))
			return
		}
		// Count the request as in-flight so the idle reaper doesn't tear the session down
		// while this call blocks on the upstream. Release via defer so a net/http-recovered
		// panic in dispatchRequest can't leave inFlight stuck (pinning against the reaper)
		// or leak a slot. Mirrors stdio's deferred hostSem release.
		sess.inFlight.Add(1)
		defer func() {
			sess.inFlight.Add(-1)
			sess.releaseRequestSlot()
		}()
		d := p.dispatchParams(sess, p.sourceIP(r))
		// Serialize the decision phase for a flow-/sequenceBlock-relevant route, so a
		// source's state write isn't raced ahead of by a later sink's read on the same
		// ANCHOR. Only enforced methods take the turn; the Decide* handler releases it via
		// finishDecision right after the decision, so this defer is the idempotent backstop
		// for the malformed-params path (which returns before the decision).
		//
		// Keyed on the anchor rather than the session: under task-anchored state two
		// sessions share one key, and a per-session lock would leave them unserialized
		// against state they share. sess.route is dereferenced unconditionally by
		// dispatchParams above, so a nil-route session can't reach here.
		if sess.route.serializes() && isEnforcedMethod(msg.Method) {
			// The release is idempotent, so finishDecision and this deferred backstop
			// advance the turn exactly once between them.
			end := sess.beginDecisionTurn(ctx)
			d.endDecision = end
			defer end()
		}
		resp = dispatchRequest(ctx, d, msg)
	}

	// Re-arm a bounded write deadline for the response write, ALWAYS — the entry deadline
	// is measured from handler entry, so with the budget enabled a slow-but-legitimate
	// upstream near its full window could leave it already past by encode time, dropping an
	// already-executed response. A fresh window here bounds only the client-facing flush, so
	// a client that stops reading can't block json.Encode (and the deferred cleanup) indefinitely.
	rearmWriteDeadline(w, 0)
	writeJSONMsg(w, resp)
}

// SSE frame byte fragments, hoisted so the hot delivery path allocates no
// per-frame strings: writeSSE streams a data frame as prefix + payload + end.
var (
	sseDataPrefix     = []byte("data: ")
	sseFrameEnd       = []byte("\n\n")
	sseKeepaliveFrame = []byte(": keepalive\n\n")
)

// resolveSessionForRoute looks up the session for sessionID and verifies it is bound to
// route, writing the canonical 404/409 and returning nil on a mismatch. The caller must
// have already required a non-empty sessionID (the 400-on-missing handling differs per
// method). Used by the GET/SSE path; POST inlines the same handling but first renders a
// KILL_SWITCH deny for a reaped killed session, and DELETE resolves under p.mu for an
// atomic check-and-delete with 409-before-404 — both different shapes a shared helper
// would obscure.
func (p *HTTPProxy) resolveSessionForRoute(w http.ResponseWriter, sessionID string, route *UpstreamRoute) *httpSession {
	sess := p.getSession(sessionID)
	if sess == nil {
		http.Error(w, "session not found", http.StatusNotFound)
		return nil
	}
	if sess.route != route {
		http.Error(w, "session does not belong to this upstream route", http.StatusConflict)
		return nil
	}
	return sess
}

// sessionGate carries a denied session-gate outcome so the caller can render the
// transport-appropriate response: a JSON-RPC denial for a POST request, an HTTP 403 for
// the envelope-less GET/DELETE, or a bodyless 202 for a POST notification/response.
type sessionGate struct {
	code          string
	conditionType string
	// reason, when non-empty, is an extra structured detail for the deny record. Carried
	// on the verdict so recordSessionGateDeny renders the identical record for every
	// transport, DELETE included.
	reason string
}

// sessionGateVerdict runs the two security checks every host-initiated action on an
// EXISTING session must clear: the per-route audience pin and the session-owner binding
// (see httpSession.ownerMismatch). Applying both to EVERY action is what stops a
// same-audience second identity that learned a victim's Mcp-Session-Id from driving,
// notifying, reading, or tearing down that session (the audience pin alone can't).
//
// CHECK-ONLY: no lock, no record — the single source of truth for WHICH gates run, shared
// by enforceSessionGates (POST/GET) and handleMCPDelete (which needs the two halves
// separately, see below). Split by what they depend on: handleMCPDelete holds the session
// registry lock across its check-and-delete, and contextGateVerdict is the half that must
// not run under it.
func (route *UpstreamRoute) sessionGateVerdict(ctx context.Context, sess *httpSession) (sessionGate, bool) {
	if gate, denied := route.contextGateVerdict(ctx); denied {
		return gate, true
	}
	return sessionOnlyGateVerdict(ctx, sess)
}

// contextGateVerdict runs the session gate that depends ONLY on the request context — the
// per-route audience pin. Separated so a caller that must hold a lock can run this half
// BEFORE acquiring it: PolicyDecisionPoint is an exported seam third parties may implement,
// and a CheckAudience that touched the network while the global session-registry write lock
// was held would stall every lookup, registration, and reap in the proxy.
func (route *UpstreamRoute) contextGateVerdict(ctx context.Context) (sessionGate, bool) {
	if deny := route.pdp.CheckAudience(ctx); deny != nil {
		d := normalizeDenial(deny.Denial)
		return sessionGate{code: d.Code, conditionType: d.ConditionType}, true
	}
	return sessionGate{}, false
}

// sessionOnlyGateVerdict runs the session gate that needs the session object — the
// session-owner binding. An in-process comparison over already-validated claims, so it's
// safe to run under the registry lock, letting handleMCPDelete keep its check-and-delete atomic.
func sessionOnlyGateVerdict(ctx context.Context, sess *httpSession) (sessionGate, bool) {
	// The reason comes back FROM the check rather than being restated here, so a gate added
	// to the binding names itself on the record instead of inheriting a caller's assumption.
	if reason, mismatch := sess.ownerMismatch(pdp.JWTClaimsPtr(ctx)); mismatch {
		return sessionGate{code: capability.ErrCodeAuthorizationFailed, reason: reason}, true
	}
	return sessionGate{}, false
}

// recordSessionGateDeny writes the fail-closed deny record for a failed session gate,
// tagged transportTag. Shared by enforceSessionGates and handleMCPDelete so the record
// shape lives once alongside the shared verdict.
func (route *UpstreamRoute) recordSessionGateDeny(ctx context.Context, sessionID, method, transportTag string, gate sessionGate) {
	details := map[string]interface{}{"transport": transportTag}
	if gate.reason != "" {
		details["reason"] = gate.reason
	}
	route.sink.RecordDeny(ctx, sessionID, method, method, gate.code, gate.conditionType, details, false)
}

// enforceSessionGates is the verdict-plus-record half used by the POST and SSE-GET
// paths: runs sessionGateVerdict and, on denial, writes the record and returns the gate.
// Kept separate from the check-only verdict so DELETE can run it under p.mu and render its
// own 403 + record off the same predicate.
func (route *UpstreamRoute) enforceSessionGates(ctx context.Context, sess *httpSession, sessionID, method, transportTag string) (sessionGate, bool) {
	gate, denied := route.sessionGateVerdict(ctx, sess)
	if denied {
		route.recordSessionGateDeny(ctx, sessionID, method, transportTag, gate)
	}
	return gate, denied
}

// handleMCPGet opens a server-sent events stream for upstream notifications.
func (p *HTTPProxy) handleMCPGet(w http.ResponseWriter, r *http.Request, route *UpstreamRoute) {
	sessionID := r.Header.Get(SessionHeader)
	if sessionID == "" {
		http.Error(w, "Mcp-Session-Id header required", http.StatusBadRequest)
		return
	}
	sess := p.resolveSessionForRoute(w, sessionID, route)
	if sess == nil {
		return
	}
	// Opening an SSE stream is a host-initiated action on an existing session: it delivers
	// that session's server-initiated requests and notifications, so it must clear the SAME
	// per-route audience pin and session-owner binding a POST does, or a same-audience
	// identity that learned the victim's Mcp-Session-Id could read another client's
	// server->client traffic. A GET carries no JSON-RPC envelope, so a refusal is an HTTP
	// 403 with a transport-tagged deny record. Runs before sess.touch() so a refusal
	// doesn't defer the victim session's idle reaping.
	//
	// route is dereferenced unconditionally: handleMCP 404s an unknown route before
	// dispatch, so a defensive nil guard here would be a fail-OPEN branch silently skipping
	// the security gates for whatever construction reached this point without a route.
	if _, denied := route.enforceSessionGates(r.Context(), sess, sessionID, "", "sse-get"); denied {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// Kill-switch check before serving: a killed (or globally emergency-stopped) session
	// must not OPEN an SSE stream. A targeted kill tears the session down proactively, but
	// this still matters for a GLOBAL stop (no session named) and a re-open racing teardown.
	if deny := route.pdp.CheckKill(r.Context(), sessionID); deny != nil {
		recordKillDrop(r.Context(), asRecorder(route.sink), deny, verifiedSession(sess.id), "", "", legSSEGet)
		http.Error(w, "session terminated", http.StatusForbidden)
		return
	}
	sess.touch() // opening/holding an SSE stream counts as activity

	if _, ok := w.(http.Flusher); !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	// Register the SSE subscriber BEFORE writing the 200 + headers, so a session
	// already at maxSubsPerSession is rejected with an error status (not a 200 stream
	// that delivers nothing). Bounds concurrent GET streams per session.
	ch := make(chan mcp.RPCMsg, sseSubscriberBufferSize)
	if !sess.addSub(ch) {
		http.Error(w, "too many concurrent SSE streams for this session", http.StatusTooManyRequests)
		return
	}
	// On stream exit, unsubscribe AND drain: broadcastServerRequest may have buffered a
	// server-initiated request into ch that the loop never read, leaving its upstream
	// blocked; the drain replies an error upstream so it unblocks immediately. r.Context()
	// is captured now (defer evaluates arguments immediately) since it carries the JWT
	// claims for the correction record, and reading it after later cancellation is safe.
	defer sess.removeSubAndDrain(r.Context(), ch)

	// SEC-03: SSE is long-lived, so the fixed httpWriteTimeout Slowloris backstop must not
	// kill it after one budget — but a permanently cleared deadline lets a stuck reader park
	// this goroutine in a blocked Write forever, past kill and idle-reap. So re-arm a
	// bounded deadline before every write via writeSSE instead: a wedged write trips it,
	// ends the stream, and runs the removeSubAndDrain defer.
	rc := http.NewResponseController(w)

	// writeSSE writes one SSE frame, re-arming the deadline before each sseWriteChunk-sized
	// write so it measures per-chunk progress — a slow-but-progressing reader isn't killed
	// mid-frame, a stuck one still trips it. Returns false on any write/flush error.
	writeSSE := func(parts ...[]byte) bool {
		for _, part := range parts {
			for len(part) > 0 {
				n := len(part)
				if n > sseWriteChunk {
					n = sseWriteChunk
				}
				_ = rc.SetWriteDeadline(time.Now().Add(sseWriteTimeout))
				if _, err := w.Write(part[:n]); err != nil {
					return false
				}
				part = part[n:]
			}
		}
		_ = rc.SetWriteDeadline(time.Now().Add(sseWriteTimeout))
		return rc.Flush() == nil
	}

	w.Header().Set("Content-Type", ctSSE)
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	// Emit an initial keepalive so the liveness clock starts at stream open, with no
	// unguarded gap before the first interval — writeSSE's deadline detects an
	// already-wedged reader within sseWriteTimeout rather than never.
	if !writeSSE(sseKeepaliveFrame) {
		return
	}

	// Periodic comment frame on an otherwise-idle stream: keeps intermediaries from idling
	// the connection out and re-arms the deadline to detect a stopped-draining reader.
	keepalive := time.NewTicker(sseKeepaliveInterval)
	defer keepalive.Stop()

	// Bound the stream to the presenting token's exp: without this an expired — or
	// IdP-revoked but not kill-switched — client keeps receiving traffic until disconnect or
	// idle-reap. A nil channel (no JWT) never fires; time.NewTimer fires immediately for an
	// already-elapsed exp (fail closed). sess.evicted covers revocation; this covers expiry.
	var tokenExpiry <-chan time.Time
	var tokenExpiresAt time.Time
	if claims := pdp.JWTClaimsPtr(r.Context()); claims != nil && !claims.ExpiresAt.IsZero() {
		tokenExpiresAt = claims.ExpiresAt
		expTimer := time.NewTimer(time.Until(tokenExpiresAt))
		defer expTimer.Stop()
		tokenExpiry = expTimer.C
	}

	for {
		select {
		case msg := <-ch:
			data, err := json.Marshal(msg)
			if err != nil {
				// Unserializable. If it's a server-initiated request, the upstream is now
				// blocked awaiting a response the host will never receive, so unblock it
				// with an error reply. A notification expects no response, so dropping is correct.
				sess.failServerRequestDelivery(r.Context(), msg, "proxy: failed to serialize server-initiated request for SSE delivery")
				continue
			}
			if !writeSSE(sseDataPrefix, data, sseFrameEnd) {
				// removeSubAndDrain only recovers messages STILL buffered in ch, not this
				// already-consumed one, so it would otherwise hang until the idle reaper.
				sess.failServerRequestDelivery(r.Context(), msg, "proxy: SSE write failed before delivering server-initiated request")
				return
			}
		case <-keepalive.C:
			// Re-anchor to the wall clock: the timer runs on the monotonic clock, which
			// doesn't advance while the host is suspended, so a suspended laptop/VM would
			// otherwise extend the authorized window past exp by the suspend duration.
			if !tokenExpiresAt.IsZero() && !time.Now().Before(tokenExpiresAt) {
				return
			}
			if !writeSSE(sseKeepaliveFrame) {
				return
			}
		case <-sess.evicted:
			// The session was killed while this stream was open; a reopen attempt is
			// refused by the kill-switch check at the top of handleMCPGet.
			return
		case <-sess.done:
			return
		case <-tokenExpiry:
			// The presenting token's lifetime elapsed; end the stream so a re-open must
			// carry a fresh token.
			return
		case <-r.Context().Done():
			return
		}
	}
}

// handleMCPDelete closes an existing session.
func (p *HTTPProxy) handleMCPDelete(w http.ResponseWriter, r *http.Request, route *UpstreamRoute) {
	sessionID := r.Header.Get(SessionHeader)
	if sessionID == "" {
		http.Error(w, "Mcp-Session-Id header required", http.StatusBadRequest)
		return
	}
	// Run the context-only gate (audience pin) BEFORE taking p.mu, carrying its verdict
	// into the locked region: it depends only on request claims, so evaluating it early
	// changes no decision, but keeps the PolicyDecisionPoint call — an exported seam — off
	// the global session-registry write lock. Applied below only once the session is
	// confirmed to exist and belong to this route, preserving the 403-vs-404 shape.
	audienceGate, audienceDenied := route.contextGateVerdict(r.Context())

	p.mu.Lock()
	sess, ok := p.sessions[sessionID]
	if ok && sess.route != route {
		// A session may only be torn down via the route it was opened on.
		p.mu.Unlock()
		http.Error(w, "session does not belong to this upstream route", http.StatusConflict)
		return
	}
	if ok {
		// Per-route audience pin + session-owner binding before teardown, mirroring the
		// SSE-GET and POST paths: without these a sibling-audience token (or a same-audience
		// different identity that learned the victim's Mcp-Session-Id) could tear down
		// another client's session. Enforced only once the session is confirmed to exist AND
		// belong to this route, ordering responses 404/409/403 — a weak existence oracle
		// (a 403 confirms a live session id on this route), but session ids are unguessable
		// UUIDs, and an unauthenticated caller never gets past the auth check upstream of
		// this handler anyway. The kill switch is deliberately NOT consulted: tearing a
		// session down is always permitted (a killed session's cleanup must still succeed).
		//
		// route is dereferenced unconditionally: handleMCP 404s an unknown route before
		// dispatch, so a defensive nil guard would be a fail-OPEN branch here too.
		gate, denied := audienceGate, audienceDenied
		if !denied {
			gate, denied = sessionOnlyGateVerdict(r.Context(), sess)
		}
		if denied {
			p.mu.Unlock()
			route.recordSessionGateDeny(r.Context(), sessionID, "", "http-delete", gate)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		delete(p.sessions, sessionID)
	}
	p.mu.Unlock()
	if !ok {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	// Re-arm the write deadline around the teardown: sess.close waits on upstream
	// termination bounded by --shutdown-timeout, and with a budget above the entry window
	// the deadline would already be past by 204-write time for a teardown that in fact
	// succeeded. A fresh window bounds only the client-facing write.
	rearmWriteDeadlineForTeardown(w, p.shutdownMs)
	sess.close(p.shutdownMs) //nolint:contextcheck // teardown path: close()'s upstream session-termination DELETE intentionally runs on a detached, bounded background context — binding it to r.Context() would cancel the teardown the instant this 204 is written, leaking the upstream session. Same rationale as the handleMCPDelete dispatch site.
	w.WriteHeader(http.StatusNoContent)
}

// handleKill processes POST /control/kill (loopback only).
//
// Kill-only, deliberately: this endpoint issues revocations and has no undo. Lifting one is
// done where the kill state lives (`eunox kill --revive`, Redis-only), because a same-host
// process holding the control token can already halt the proxy, and an undo here would let
// it lift the revocation issued against it. See killActivator before adding a verb here.
func (p *HTTPProxy) handleKill(w http.ResponseWriter, r *http.Request) {
	// Loopback guard runs first — before the control-token check — so an off-host caller
	// is rejected by the security boundary rather than learning the endpoint exists via a 401.
	if !p.loopbackOnly(w, r) {
		return
	}

	// SEC-07: the loopback check stops remote access, but a same-host process (e.g. a
	// compromised tool subprocess) could still reach this endpoint. Require the
	// auto-generated control token so the emergency stop is never reachable without it.
	//
	// Runs BEFORE the method check on purpose: a method check first would answer a bare
	// GET/PUT with an unrecorded 405, confirming the endpoint exists to a caller who never
	// proved they hold the token, while the same caller with a wrong token on POST is fully
	// recorded below. Checking the token first collapses every unauthenticated verb to the
	// same recorded 401.
	if !p.checkControlToken(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// SEC-04: cap request body to prevent memory exhaustion.
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	var body struct {
		SessionID string `json:"sessionId"`
		All       bool   `json:"all"`
	}
	// Reject a body carrying a trailing JSON token (e.g. a smuggled {"all":true} after a
	// legitimate {"sessionId":"..."}): without this the kill actually executed could differ
	// from what a body-only reviewer would expect. /control/kill has no route concept, so
	// nil: its refusal stays on the proxy-wide sink.
	if !p.decodeStrictJSON(w, r, &body, "invalid request body", nil) {
		return
	}
	if body.All {
		// Propagate a kill-store write failure (fail closed): returning {"ok":true} on a
		// failed emergency stop would leave the operator believing the system is safe.
		if err := p.ks.ActivateGlobal(r.Context()); err != nil {
			_, _ = fmt.Fprintf(p.errOut(), "[eunox] kill switch activation failed: %v\n", err)
			http.Error(w, "kill switch activation failed", http.StatusInternalServerError)
			return
		}
		// Record BEFORE the teardown: the stop takes effect the moment the store write
		// returns, but the teardown below is bounded by the shutdown budget — recording
		// after it left a window where a crash produced KILL_SWITCH denials with no
		// activation record to explain them.
		p.recordKillActivated(r, killScopeAll, killDimensionGlobal)
		// Evict every open SSE stream too: a stream opened before the kill is long-lived
		// and would otherwise keep delivering notifications until the idle ceiling.
		// Re-arm the write deadline before the sweep: it waits on EVERY session's close, so
		// with a non-trivial shutdown budget the entry deadline would otherwise be long past
		// by success-body time, making `eunox kill` look like it failed on a stop that
		// actually took effect.
		rearmWriteDeadlineForTeardown(w, p.shutdownMs)
		p.evictAllSessionStreams()
		// Proactively tear every session down rather than leaving reclamation to the idle
		// reaper, which does not run when sessionIdleTimeoutMs is 0 — otherwise
		// killed-but-undead sessions would pin capacity and 503 new initializes.
		p.reapAllKilledSessions() //nolint:contextcheck // teardown path: close()'s upstream session-termination DELETE intentionally uses a detached, bounded background context — binding it to r.Context() would cancel the teardown the instant this response is written. Same rationale as the handleMCPDelete close() site.
		p.writeKillResponse(w, killScopeAll, killDimensionGlobal)
		return
	}
	if body.SessionID == "" {
		http.Error(w, "sessionId or all required", http.StatusBadRequest)
		return
	}
	if err := p.ks.KillSession(r.Context(), body.SessionID); err != nil {
		_, _ = fmt.Fprintf(p.errOut(), "[eunox] kill switch session kill failed: %v\n", err)
		http.Error(w, "kill switch session kill failed", http.StatusInternalServerError)
		return
	}
	// Recorded before the teardown, same ordering as the global path above.
	p.recordKillActivated(r, body.SessionID, killDimensionSession)
	rearmWriteDeadlineForTeardown(w, p.shutdownMs)
	p.evictSessionStreams(body.SessionID)
	// Proactively tear the killed session down instead of relying on the idle reaper,
	// which does not run when sessionIdleTimeoutMs is 0 — see reapKilledSession.
	p.reapKilledSession(body.SessionID) //nolint:contextcheck // teardown path: close()'s upstream session-termination DELETE intentionally uses a detached, bounded background context. Same rationale as the handleMCPDelete close() site.
	p.writeKillResponse(w, body.SessionID, killDimensionSession)
}

// killScopeAll is the scope recorded (and returned) for a whole-proxy emergency stop,
// distinguishing it from a targeted kill, whose scope is the killed session id.
const killScopeAll = "all"

// recordKillActivated writes the audit record for a SUCCESSFUL /control/kill activation.
// Every refusal of this endpoint already lands on the tape, and every request the
// activation blocks lands as a KILL_SWITCH denial — but the activation itself, the single
// administrative act explaining that whole run of denials, otherwise left no trace.
//
// Recorded as an ALLOW (authenticated and performed, not a refusal), emitted after the
// kill-store write succeeds and BEFORE stream eviction/session teardown: the kill is in
// force the moment the store write returns, while teardown is bounded only by the shutdown
// budget, so recording after it left a window where a crash produced KILL_SWITCH denials
// with no activation record. scope goes in details rather than the structured target
// field, which is reserved for MCP tool/resource/prompt targets. No credential and no
// session_id are recorded (a global stop addresses no single session).
//
// dimension is a separate field from scope because their VALUES collide: a session id is
// operator-settable and could literally be "all", so `{"sessionId":"all"}` would otherwise
// be indistinguishable from a deployment-wide stop.
func (p *HTTPProxy) recordKillActivated(r *http.Request, scope, dimension string) {
	if p.sink == nil {
		return
	}
	p.sink.RecordAllow(r.Context(), "", "", MethodControlKill, map[string]interface{}{
		"scope":     scope,
		"dimension": dimension,
		"source_ip": p.sourceIP(r),
	}, nil, false, nil, nil)
}

// writeKillResponse writes the kill endpoint's
// {"ok":true,"killed":<target>,"dimension":<global|session>} success body. Every route
// honors the kill switch, so the response carries no partial-coverage caveat.
//
// dimension is reported for the same reason the audit record carries it: a session whose
// id is "all" would otherwise produce a response indistinguishable from the deployment-wide
// stop, and `eunox kill` prints this body verbatim.
func (p *HTTPProxy) writeKillResponse(w http.ResponseWriter, killed, dimension string) {
	w.Header().Set("Content-Type", CTJSON)
	resp := map[string]interface{}{"ok": true, "killed": killed, "dimension": dimension}
	b, _ := json.Marshal(resp)
	_, _ = w.Write(b)
}

// Kill dimensions as they appear in the control endpoint's audit record and response.
// Spelled the same as the CLI's Redis-transport result line so one vocabulary describes
// both transports.
const (
	killDimensionGlobal  = "global"
	killDimensionSession = "session"
)
