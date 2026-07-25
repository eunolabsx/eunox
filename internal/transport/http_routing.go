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
	"os"
	"sync"
	"time"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// writeJSONMsg sets the JSON content type and encodes v as the response body. It
// is a status-less helper: none of its call sites in this file interleave a
// WriteHeader between setting the header and encoding the body (each sits on its
// own bodyless-response branch), so a single helper is a drop-in replacement —
// collapsing the copy-pasted two-line idiom at every enforced-response site into
// one, so a future site cannot forget the Content-Type header or set a different
// one. writeKillResponse uses json.Marshal + w.Write instead (folding it in here
// would add the Encoder's trailing newline to that response body — a harmless
// but observable byte-level change kept out of scope).
func writeJSONMsg(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", CTJSON)
	_ = json.NewEncoder(w).Encode(v)
}

// handleMCP dispatches POST / GET / DELETE requests to /mcp.
func (p *HTTPProxy) handleMCP(w http.ResponseWriter, r *http.Request) {
	if !p.checkAuth(w, r) {
		return
	}
	// JWT pre-validation: validate the Bearer token and attach claims to ctx. This
	// is authentication, not policy — 401 even in audit mode. It runs BEFORE the
	// route lookup so all handlers see the claims and an unauthenticated caller gets
	// a uniform 401 regardless of whether the route exists: resolving the route first
	// would turn a 404-vs-401 split into an oracle for enumerating route names (only
	// reachable in JWT-only mode, since a static token already gates route disclosure
	// behind the bearer token in checkAuth).
	if p.jwtPDP != nil {
		authHeader := r.Header.Get("Authorization")
		ctx, err := p.jwtPDP.ValidateToken(r.Context(), authHeader)
		if err != nil {
			// Record a stable error_type CATEGORY, never the raw err.Error(): the go-jose /
			// validation message can disclose claim values, the accepted algorithm, the
			// configured issuer, or key-rotation state, and audit logs are commonly forwarded
			// to third-party SIEMs — the same disclosure the opaque-401 response below avoids.
			// pdp.ClassifyJWTError maps the failure to one of a fixed set of codes (expired,
			// invalid_signature, missing_claims, …). recordPreSessionDeny keeps the unverified
			// Mcp-Session-Id out of the structured session_id (forgery guard).
			p.recordPreSessionDeny(r, "JWT_INVALID", "jwt", map[string]interface{}{"error_type": pdp.ClassifyJWTError(err)})
			w.Header().Set("WWW-Authenticate", buildWWWAuthenticate(authHeader != "", p.oauthMetaURL))
			// Do not echo the JWT validation error to the caller: the library message
			// can disclose claim values, the accepted algorithm, or key-rotation state,
			// letting an unauthenticated client fingerprint the validator. The failure
			// category is preserved as error_type in the JWT_INVALID audit record above;
			// the client gets an opaque 401.
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

// decodeStrictJSON decodes exactly one JSON value from r.Body into v, then requires
// io.EOF: a body carrying a second JSON value (or any other trailing non-whitespace
// token) is malformed and must be rejected with 400 before any dispatch, rather than
// silently truncated to its first value — otherwise a multi-token /mcp body could
// 202-ack an invalid initialize notification, or a /control/kill body could execute
// a narrower kill while silently ignoring a smuggled trailing {"all":true}. On a
// decode failure or trailing data this writes the response itself (400, or 413 for a
// body that exceeds the MaxBytesReader cap the caller installed on r.Body) and
// returns false; the caller must return immediately without proceeding.
func decodeStrictJSON(w http.ResponseWriter, r *http.Request, v interface{}, invalidBodyMsg string) bool {
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return false
		}
		http.Error(w, invalidBodyMsg, http.StatusBadRequest)
		return false
	}
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return false
		}
		http.Error(w, invalidBodyMsg+": trailing data after JSON message", http.StatusBadRequest)
		return false
	}
	return true
}

// writeSessionCreateError maps a newSession/newRemoteSession failure to the right HTTP
// status. The transient/retryable conditions get a 503 so a client racing a graceful
// restart or a full/racing proxy retries rather than treating it as a hard failure:
//   - errSessionLimit — the proxy is at its concurrent-session cap.
//   - errRacedReap — a global kill swept the registry mid-handshake (see reapGen); the
//     upstream this initialize started was already torn down, so a retry is safe.
//   - errShuttingDown — registration was refused because the proxy is draining for a
//     graceful shutdown (the upstream itself started fine).
//
// Anything else is an upstream-start failure: the raw error can carry the upstream
// command path, an internal IP:port, or TLS detail, so it is logged to stderr for the
// operator and returned to the client as a generic 500. Extracted from handleMCPPost so
// the session-creating initialize branch stays within the nested-complexity budget.
//
// errSessionLimit is additionally recorded on the tape. It is a saturation refusal exactly
// like the per-session in-flight cap that recordResourceExhausted covers, but reachable
// WITHOUT an established session, so it is the cheaper flood for an attacker and was the
// one leaving no trace — an incident responder reconstructing an outage saw
// RESOURCE_EXHAUSTED for in-flight floods and a blank for session-cap floods. The other
// two legs are benign lifecycle races (a kill sweep, a graceful drain), not attack signal,
// so they stay status-only.
func (p *HTTPProxy) writeSessionCreateError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, errSessionLimit):
		p.recordPreSessionDeny(r, codeResourceExhausted, "saturation", map[string]interface{}{
			"source_ip": p.sourceIP(r),
			"reason":    "session_limit_reached",
		})
		http.Error(w, "session limit reached", http.StatusServiceUnavailable)
	case errors.Is(err, errRacedReap):
		http.Error(w, "session raced a kill-switch reset; retry", http.StatusServiceUnavailable)
	case errors.Is(err, errShuttingDown):
		http.Error(w, "server shutting down; retry", http.StatusServiceUnavailable)
	default:
		fmt.Fprintf(os.Stderr, "[eunox] failed to start upstream: %v\n", err)
		http.Error(w, "upstream unavailable", http.StatusInternalServerError)
	}
}

// handleMCPPost processes a JSON-RPC request from the MCP host for the given
// upstream route.
func (p *HTTPProxy) handleMCPPost(w http.ResponseWriter, r *http.Request, route *UpstreamRoute) {
	// SEC-04: cap request body to prevent memory exhaustion from large payloads.
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	var msg mcp.RPCMsg
	// A single JSON-RPC POST body is exactly one JSON value (a batch is a single JSON
	// array, still one value); decodeStrictJSON fails closed with 400 on any trailing
	// token BEFORE dispatching — otherwise a multi-token body could 202-ack an invalid
	// initialize notification or run its first request on an existing session while
	// the trailer is silently dropped.
	if !decodeStrictJSON(w, r, &msg, "invalid JSON-RPC body") {
		return
	}

	// Arm an entry write deadline as a Slowloris backstop over the pre-dispatch writes
	// (the 202-ack, an early 4xx). Errors ignored: not every ResponseWriter supports a
	// write deadline, and the worst case is the prior fixed-timeout behavior.
	//
	// This deadline does NOT bound the response write: the actual response encode always
	// re-arms a fresh httpWriteTimeout window immediately before writing (after the
	// upstream returns). That decoupling matters most with the budget enabled — the entry
	// deadline is measured from entry, so all pre-forward work (session gates, CheckKill,
	// the PDP Decide's counter/kill round-trips) plus the upstream call itself run against
	// it, and a legitimately slow upstream near its full budget could otherwise leave the
	// entry deadline already past by encode time, dropping a response for a call that
	// already executed upstream. With the budget disabled the upstream may take
	// arbitrarily long, so the entry deadline stays at the fixed backstop and the
	// pre-encode re-arm is what bounds the client-facing write.
	rc := http.NewResponseController(w)
	if p.upstreamTimeMs > 0 {
		_ = rc.SetWriteDeadline(time.Now().Add(addSlack(msToDuration(p.upstreamTimeMs))))
	} else {
		_ = rc.SetWriteDeadline(time.Now().Add(httpWriteTimeout))
	}

	sessionID := r.Header.Get(SessionHeader)

	// An initialize request with no session ID creates a new session.
	//
	// Require msg.IsRequest(): an initialize *notification* (no id) must never start
	// an upstream or consume a session slot — a flood would otherwise spawn unbounded
	// upstreams. It is handled as a stateless notification below.
	if msg.Method == "initialize" && sessionID == "" && msg.IsRequest() {
		// Kill-switch check BEFORE spawning anything: a session-creating initialize
		// must not start an upstream while a global kill (emergency stop) is active.
		// The empty session id means only the global dimension can match. This is the one
		// initialize answered outside dispatchRequest (there is no session or
		// dispatchParams yet), so it repeats the kill gate dispatchRequest applies to
		// every other locally-answered method.
		if deny := route.pdp.CheckKill(r.Context(), ""); deny != nil {
			resp := recordKillDenial(r.Context(), asRecorder(route.sink), deny, msg.ID, "", "initialize")
			writeJSONMsg(w, resp)
			return
		}
		// Per-route audience pin BEFORE spawning: a token valid only for ANOTHER route's
		// audience (accepted by the gateway's shared union validator) must not create a
		// session on, or contact, this route's upstream. The Decide*/list/sampling paths
		// embed the same pin, but initialize does not flow through them; without this gate
		// a cross-audience token could spin up this route's upstream and read its
		// serverInfo. Mirrors the kill-switch pre-spawn gate above.
		if denied, blocked := p.initAudienceDenial(r.Context(), route, msg); blocked {
			writeJSONMsg(w, denied)
			return
		}
		// --require-audit=strict: creating a session spawns/contacts an upstream — a
		// privileged side effect. Once the audit trail has degraded, refuse new
		// sessions fail-closed rather than spin up an upstream whose traffic cannot be
		// fully recorded. Mirrors the gate on the enforced-forward, */list, and
		// sampling paths. (stdio has no equivalent: its single upstream starts before
		// any traffic.)
		if denied, blocked := p.initStrictAuditDenial(r.Context(), route, msg); blocked {
			writeJSONMsg(w, denied)
			return
		}
		// Cheap pre-spawn capacity check so a full proxy refuses a new session without
		// starting an upstream. registerSession re-checks under the lock to make the
		// cap authoritative against concurrent initializes.
		if p.atSessionCap() {
			// Recorded for the same reason as the errSessionLimit leg of
			// writeSessionCreateError: this is the cheap pre-spawn twin of that refusal and
			// the surface an unauthenticated saturation flood reaches first.
			p.recordPreSessionDeny(r, codeResourceExhausted, "saturation", map[string]interface{}{
				"source_ip": p.sourceIP(r),
				"reason":    "session_limit_reached",
			})
			http.Error(w, "session limit reached", http.StatusServiceUnavailable)
			return
		}
		// Session establishment (initialize handshake + drift tools/list probe) runs
		// under sessionStartTimeout, independent of --upstream-timeout. Cover the larger
		// of the two budgets so the write deadline set above can't fire mid-handshake
		// when --upstream-timeout is below sessionStartTimeout.
		startBudget := sessionStartTimeout
		if b := msToDuration(p.upstreamTimeMs); p.upstreamTimeMs > 0 && b > startBudget {
			startBudget = b
		}
		_ = rc.SetWriteDeadline(time.Now().Add(addSlack(startBudget)))
		initCtx, initCancel := context.WithTimeout(r.Context(), sessionStartTimeout)
		defer initCancel()

		var (
			sess *httpSession
			err  error
		)
		// Capture the client IP before session creation: upstream-initiated sampling
		// carries no request of its own, so an ipRange condition is evaluated against
		// this address. Setting it after creation would race the reader goroutine.
		clientIP := p.sourceIP(r)
		if route.transport == "http" {
			sess, err = p.newRemoteSession(initCtx, route, clientIP)
		} else {
			sess, err = p.newSession(initCtx, route, clientIP)
		}
		if err != nil {
			p.writeSessionCreateError(w, r, err)
			return
		}
		w.Header().Set(SessionHeader, sess.id)
		// Answered directly, not through the shared dispatchInitialize kill gate: the
		// pre-spawn global-dimension CheckKill already ran above, and the session id
		// minted here is brand new, so it cannot yet be a per-session/agent kill target.
		// Every other initialize site routes through the dispatcher for that gate.
		resp := sess.buildInitResponse(msg)
		writeJSONMsg(w, resp)
		return
	}

	if sessionID == "" {
		// An initialize notification (excluded from the session-creation branch above)
		// expects no response: accept and drop it without allocating session state.
		if msg.Method == "initialize" && msg.IsNotification() {
			// Consult the kill switch BEFORE the 202 ack. Under the MCP Streamable HTTP
			// spec a 202 to an initialize notification is a readiness acknowledgement, so
			// returning it while a global emergency stop is active would tell the client
			// the server is ready, and the acceptance would go unaudited. The empty
			// session id means only the global dimension can match. Mirrors the
			// session-creating initialize POST branch above and the dispatchList path.
			if deny := route.pdp.CheckKill(r.Context(), ""); deny != nil {
				// A notification is fire-and-forget and MUST NOT receive a JSON-RPC
				// response: msg.ID is nil here, so recordKillDenial's response would
				// carry the invalid "id":null, and encoding it with no prior
				// WriteHeader sends an implicit 200 — indistinguishable from a
				// successful readiness ack to a client that only checks status.
				// Record the deny directly, exactly like the existing-session
				// notification kill path below, and ack the drop with a bodyless 202.
				recordKillDrop(r.Context(), asRecorder(route.sink), deny, "", msg.Method, msg.Method, legHTTPNotification)
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
		// A killed session is proactively torn out of the registry (reapKilledSession /
		// reapAllKilledSessions), so its id no longer resolves — but the documented kill
		// contract is that a killed session's requests are DENIED with KILL_SWITCH, not a
		// bare 404 that hides why the session vanished. The kill store outlives the reaped
		// registry entry, so consult it here: a killed session id (or an active global
		// kill) renders the same KILL_SWITCH deny the request would have gotten had the
		// session still been present and reached the dispatcher's kill gate below. A
		// genuinely unknown session id (no kill) still 404s. The POST path handles this
		// itself rather than via resolveSessionForRoute (used by the GET/SSE path) because
		// only the request/notification framing here can carry a JSON-RPC KILL_SWITCH body.
		if deny := route.pdp.CheckKill(r.Context(), sessionID); deny != nil {
			if msg.IsRequest() {
				writeJSONMsg(w, recordKillDenial(r.Context(), asRecorder(route.sink), deny, msg.ID, sessionID, msg.Method))
			} else {
				// Fire-and-forget (notification / response): record the drop and ack with a
				// bodyless 202, matching the existing-session notification kill path below.
				recordKillDrop(r.Context(), asRecorder(route.sink), deny, sessionID, msg.Method, msg.Method, legHTTPNotification)
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
	// just the enforced (Decide) methods and not just the initialize echo. The per-request
	// bearer is re-validated against the gateway's shared union, so a token minted for a
	// sibling route's audience, or a same-audience SECOND identity that learned this
	// session's id, would otherwise reach the verbatim-forwarded notification (pushed to
	// this session's upstream), the response-routing path, the re-initialize echo (which
	// returns the creating client's captured capabilities), OR an enforced request
	// dispatched against this session's upstream — none of which the audience pin alone
	// distinguishes for a same-audience identity. Applying the owner binding here (rather
	// than only on initialize, the prior scope, which let enforced POSTs drive a victim's
	// upstream) closes that cross-identity session hijack. Runs before touchRequest so a
	// refused request does not defer the victim session's idle reaping.
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
	// Check the kill switch BEFORE touchRequest, so a killed session's denied POSTs
	// cannot keep deferring its idle reaping. handleKill now tears the session down
	// proactively (reapKilledSession), but a request racing that teardown could still
	// arrive first, and gating touchRequest on the kill keeps such a POST from advancing
	// lastActive/lastRequest and re-deferring reclamation. Gate ONLY touchRequest on the
	// kill: enforced requests and re-initialize still flow through
	// the shared dispatcher below, which re-checks the kill (Decide / dispatchInitialize)
	// and records the precise per-target audit identifier (the tool name for a
	// tools/call), rather than the coarse method-only record a blanket pre-dispatch
	// gate would emit. A killed request's Decide denies immediately with no upstream
	// call, so it does not linger in inFlight and cannot re-defer the reaper.
	kill := route.pdp.CheckKill(r.Context(), sessionID)
	if kill == nil {
		// A live POST is active host-initiated traffic (distinct from passively holding
		// an SSE GET open): it defers both the idle reaper and the hard idle ceiling.
		sess.touchRequest()
	}
	// Host notifications are forwarded verbatim only when allowlisted
	// (isForwardableHostNotification), after the swallowed set
	// (isSwallowedHostNotification: notifications/initialized, and a mid-session
	// id-less "initialize" that IsNotification() classifies as a notification even
	// though the method is ordinarily a request — forwarding it verbatim would let a
	// client re-trigger the upstream's handshake outside the dispatcher's kill gate
	// and audit trail, the same swallow the sessionless path above already applies)
	// and the enforced-method fail-closed reject. These do not flow through the
	// dispatcher, so the kill is enforced here.
	if msg.IsNotification() {
		if !isSwallowedHostNotification(msg.Method) {
			if kill != nil {
				recordKillDrop(r.Context(), asRecorder(route.sink), kill, sessionID, msg.Method, msg.Method, legHTTPNotification)
				w.WriteHeader(http.StatusAccepted)
				return
			}
			// An enforced method (tools/call, resources/read, resources/subscribe,
			// prompts/get) framed as a notification (no id) is a fail-closed reject —
			// see denyEnforcedMethodNotification, shared with the stdio transport's
			// equivalent guard so the check and its audit record cannot drift between
			// the two transports. Checked before the notify-slot acquisition below: no
			// point reserving a slot for a notification that's about to be denied.
			if denyEnforcedMethodNotification(r.Context(), asRecorder(route.sink), sessionID, msg) {
				w.WriteHeader(http.StatusAccepted)
				return
			}
			// Any notification method outside the forwardable allowlist (notifications/
			// cancelled, notifications/progress, notifications/roots/list_changed) is a
			// fail-closed reject — see denyUnmappedHostNotification, shared with the
			// stdio transport's equivalent guard so a notification-framed novel/unmapped
			// method cannot reach the upstream invisibly while its request-framed twin
			// would be denied and logged by dispatchUnmapped. Checked before the
			// notify-slot acquisition below, mirroring the enforced-method check above.
			if denyUnmappedHostNotification(r.Context(), asRecorder(route.sink), sessionID, msg) {
				w.WriteHeader(http.StatusAccepted)
				return
			}
			// Bound concurrent in-flight notification forwards on this session — its own
			// pool (tryAcquireNotifySlot), deliberately separate from the enforced-request
			// slot below, so a burst of enforced tool calls (each possibly blocked on the
			// upstream for the full --upstream-timeout) can never exhaust the notification
			// pool and start dropping notifications/cancelled, which would leave the very
			// call the host meant to abort running to completion. Non-blocking: on
			// saturation drop the notification and log it rather than block the handler
			// goroutine indefinitely.
			if !sess.tryAcquireNotifySlot() {
				fmt.Fprintf(os.Stderr, "[eunox] HTTP session %s: notification %q dropped: too many concurrent notifications in flight\n", sessionID, msg.Method)
				w.WriteHeader(http.StatusAccepted)
				return
			}
			// A plain function-scoped defer suffices here (matching the enforced-request
			// slot release below): the notification branch always returns two lines below,
			// so the defer fires effectively immediately, without the allocation of an
			// immediately-invoked closure to scope an inner defer.
			defer sess.releaseNotifySlot()
			sess.forwardNotification(r.Context(), msg)
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}

	if !msg.IsRequest() {
		// A host response to a server-initiated request the proxy broadcast (e.g. the
		// sampling/createMessage result) must be routed back to the upstream, which is
		// blocked awaiting it. Only responses whose ID we forwarded are routed (take
		// consumes the tracked ID); any other non-request POST is acked and ignored.
		if msg.IsResponse() && sess.serverReqs.take(mcp.MsgKey(msg.ID)) {
			switch {
			case kill != nil:
				// Killed: the tracked id is consumed above (no leak), but the response is
				// NOT routed. A kill does not tear the upstream down; its blocked
				// server-initiated request is intentionally left unanswered and the upstream
				// is reclaimed later by the idle reaper's hard ceiling. Record the dropped
				// host reply so a killed session's suppressed server-response is visible on
				// the tape, mirroring the notification kill record above; a response carries
				// no method, so use a fixed "server-response" identifier.
				recordKillDrop(r.Context(), asRecorder(route.sink), kill, sessionID, "server-response", "server-response", legHTTPServerResponse)
			case sess.upWriter != nil:
				_ = sess.upWriter.Write(msg)
			default:
				// Remote-upstream mode has no upWriter to route the response back. take()
				// already untracked the ID (no leak, no misroute); warn so the drop is
				// observable. Unreachable today — remote sessions issue no server-initiated
				// requests, so take returns false — pending a remote-upstream bridge fix.
				fmt.Fprintf(os.Stderr,
					"[eunox] WARNING: dropped host response to a server-initiated request: no upstream writer in remote-upstream mode\n")
			}
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}

	ctx := r.Context()
	var resp mcp.RPCMsg
	if msg.Method == "initialize" {
		// Re-initialize is answered locally from capabilities captured at session start
		// (the session-ownership binding was already enforced above, before touchRequest).
		// It routes through the shared dispatcher like every other enforced method, so its
		// kill gate (a killed session must not re-fetch the full capability set — every
		// other action on the session is already kill-gated) lives once in
		// dispatchInitialize instead of being copy-maintained here. It contacts no
		// upstream, so it is not subject to the in-flight cap below. dispatchInitialize
		// does not consult strictAuditDenial (unlike the enforced Decide* handlers) —
		// intentionally: this is a pure local echo of the session's already-captured
		// capabilities, bound to the already-authenticated owner, not a fresh decision
		// against upstream state, so there is nothing here for the strict-audit gate to
		// protect.
		resp = dispatchRequest(ctx, p.dispatchParams(sess, p.sourceIP(r)), msg)
	} else {
		// Bound concurrent in-flight enforced requests on this session (the HTTP analogue
		// of stdio's hostSem). Non-blocking acquire: on saturation reject with a
		// retryable JSON-RPC busy error rather than dispatch an unbounded handler that
		// would allocate a reply channel and pending-map entries and block in the
		// upstream round-trip.
		if !sess.tryAcquireRequestSlot() {
			// Record the saturation refusal so a pool-saturation flood against the
			// network-exposed transport is visible on the tamper-evident tape, mirroring the
			// stdio hostSem path through the same helper. Without it the exposed transport —
			// the surface a DoS probe actually reaches — would leave no trace while the local
			// stdio twin does, backwards from the threat. route.sink carries the route
			// provenance; asRecorder yields a genuine nil interface when no sink is configured.
			recordResourceExhausted(ctx, asRecorder(route.sink), sess.id, msg.Method)
			writeJSONMsg(w, mcp.ErrorResponse(msg.ID, jsonRPCCodeServerBusy, "eunox: too many concurrent requests in flight; retry"))
			return
		}
		// Count the request as in-flight so the idle reaper does not tear the session
		// down while this call blocks on the upstream (lastActive is not refreshed
		// during the call). Release the counter AND the semaphore slot via defer so a
		// panic in dispatchRequest — which net/http recovers at the connection level,
		// skipping any non-deferred cleanup — cannot leave inFlight stuck > 0 (pinning
		// the session against the reaper forever) or leak a slot (exhausting the cap
		// after enough panics). Mirrors stdio's deferred hostSem release.
		sess.inFlight.Add(1)
		defer func() {
			sess.inFlight.Add(-1)
			sess.releaseRequestSlot()
		}()
		d := p.dispatchParams(sess, p.sourceIP(r))
		// Serialize the per-session decision phase for a flow-/sequenceBlock-relevant
		// route, so a source's state write is not
		// raced ahead of by a later sink's read on the same session. Only enforced methods
		// take the lock (only they run a PDP decision + state write); the Decide* handler
		// releases it via finishDecision right after the decision, so the upstream forward
		// runs outside it, and this defer is the idempotent backstop for the
		// malformed-params path (which returns before the decision).
		if sess.route != nil && sess.route.serializeDecisions && isEnforcedMethod(msg.Method) {
			sess.decideMu.Lock()
			// sync.OnceFunc so the handler's release-after-decision (finishDecision) and this
			// deferred backstop unlock exactly once between them.
			end := sync.OnceFunc(sess.decideMu.Unlock)
			d.endDecision = end
			defer end()
		}
		resp = dispatchRequest(ctx, d, msg)
	}

	// Re-arm a bounded write deadline for the actual response write, ALWAYS — the
	// upstream call has returned, so this deadline only bounds the client-facing flush.
	// The deadline armed at handler entry (handleMCPPost) is measured from entry, so all
	// pre-forward work (session gates, CheckKill, the PDP Decide's counter/kill
	// round-trips) plus the upstream call itself run against it; with the budget enabled
	// a slow-but-legitimate upstream near its full window could leave the entry deadline
	// already past by the time we encode, dropping a response for a call that already
	// executed (and was already recorded) upstream. A fresh httpWriteTimeout window here
	// bounds only the client-facing write — so a client that stops reading (TCP zero
	// window) still cannot block json.Encode, and thus the deferred inFlight/reqSem
	// release, indefinitely — while decoupling that write from however long pre-forward
	// work and the upstream took.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(httpWriteTimeout))
	writeJSONMsg(w, resp)
}

// SSE frame byte fragments, hoisted so the hot delivery path allocates no
// per-frame strings: writeSSE streams a data frame as prefix + payload + end.
var (
	sseDataPrefix     = []byte("data: ")
	sseFrameEnd       = []byte("\n\n")
	sseKeepaliveFrame = []byte(": keepalive\n\n")
)

// resolveSessionForRoute looks up the session for sessionID and verifies it is
// bound to route, writing the canonical 404 (not found) or 409 (wrong route)
// response and returning nil on a mismatch. The caller must have already required
// a non-empty sessionID: the 400-on-missing handling differs per method (POST
// treats a missing id as a session-creating initialize, GET/DELETE reject it), so
// it stays in each caller. Used by the GET/SSE existing-session path; the POST path
// inlines the same not-found/wrong-route handling but first renders a KILL_SWITCH
// JSON-RPC deny for a reaped killed session (which only the POST's request framing can
// carry — see handleSessionPost). The DELETE path is deliberately NOT routed through
// here either: it resolves the session under p.mu for an atomic check-and-delete and
// reports 409 before 404, a different shape that a shared helper would obscure.
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
	// reason, when non-empty, is an extra structured detail for the deny record (e.g.
	// "session_owner_mismatch"). Carried on the verdict so recordSessionGateDeny renders
	// the identical record for every transport, DELETE included.
	reason string
}

// sessionGateVerdict runs the two security checks every host-initiated action on an
// EXISTING session must clear: the per-route audience pin (a token minted for a sibling
// route's audience, accepted by the gateway's shared union validator, must not act on
// this route's session) and the session-owner binding (only the JWT identity — issuer+sub
// — that created the session may act on it; see httpSession.ownerMismatch). Both are
// properties of the session, so applying them to EVERY host-initiated action is what stops
// a second same-audience identity that learned a victim's Mcp-Session-Id from driving,
// notifying, reading, or tearing down the victim's upstream session (the audience pin alone
// cannot: both share the audience).
//
// It is CHECK-ONLY: no lock, no record — the single source of truth for WHICH gates run,
// shared by enforceSessionGates (POST/GET: verdict + record) and handleMCPDelete (which
// needs the two halves separately, see below, then renders its own 403 + record). A gate
// added to the appropriate half below protects all three transports at once, closing the
// drift the previous hand-mirrored DELETE copy invited. Returns the denied gate + true on
// failure, or (_, false) when both pass (a no-pin route and an unbound no-JWT session are
// no-ops).
//
// The gates are split by what they depend on, NOT merely for tidiness: handleMCPDelete
// must hold the session registry lock across its check-and-delete, and contextGateVerdict
// is the half that must not run under a lock.
func (route *UpstreamRoute) sessionGateVerdict(ctx context.Context, sess *httpSession) (sessionGate, bool) {
	if gate, denied := route.contextGateVerdict(ctx); denied {
		return gate, true
	}
	return sessionOnlyGateVerdict(ctx, sess)
}

// contextGateVerdict runs the session gates that depend ONLY on the request context — the
// per-route audience pin — and not on the session object.
//
// It is separated so a caller that must hold a lock can run this half BEFORE acquiring it.
// CheckAudience is a PolicyDecisionPoint method, and PolicyDecisionPoint is an exported
// seam third parties may implement: every in-tree implementation compares claims and
// returns, but the contract cannot assume that of an out-of-tree one, and a CheckAudience
// that touched the network while the global session-registry write lock was held would
// stall every session lookup, registration, and reap in the proxy. Keeping this half
// lock-free means the transport never imposes that risk regardless of implementation.
func (route *UpstreamRoute) contextGateVerdict(ctx context.Context) (sessionGate, bool) {
	if deny := route.pdp.CheckAudience(ctx); deny != nil {
		d := normalizeDenial(deny.Denial)
		return sessionGate{code: d.Code, conditionType: d.ConditionType}, true
	}
	return sessionGate{}, false
}

// sessionOnlyGateVerdict runs the session gates that need the session object — the
// session-owner binding. This half is a pure in-process field comparison with no interface
// dispatch outside the package, so it is safe to run under the registry lock, which is
// what lets handleMCPDelete keep its check-and-delete atomic.
func sessionOnlyGateVerdict(ctx context.Context, sess *httpSession) (sessionGate, bool) {
	if sess.ownerMismatch(pdp.JWTClaimsPtr(ctx)) {
		return sessionGate{code: capability.ErrCodeAuthorizationFailed, reason: "session_owner_mismatch"}, true
	}
	return sessionGate{}, false
}

// recordSessionGateDeny writes the fail-closed deny record for a failed session gate,
// tagged transportTag. method fills the record's method/identifier ("" for the
// envelope-less GET/DELETE, the request method for a POST). Shared by enforceSessionGates
// and handleMCPDelete so the record shape lives once alongside the shared verdict.
func (route *UpstreamRoute) recordSessionGateDeny(ctx context.Context, sessionID, method, transportTag string, gate sessionGate) {
	details := map[string]interface{}{"transport": transportTag}
	if gate.reason != "" {
		details["reason"] = gate.reason
	}
	route.sink.RecordDeny(ctx, sessionID, method, method, gate.code, gate.conditionType, details, false)
}

// enforceSessionGates is the verdict-plus-record half used by the POST and SSE-GET
// existing-session paths: it runs sessionGateVerdict and, on a denial, writes the record
// and returns the gate plus true. Kept separate from the check-only verdict so DELETE can
// run the verdict under p.mu (its atomic check-and-delete) and render its own 403 + record
// off the same predicate — "which checks run" stays in sessionGateVerdict alone.
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
	// Opening an SSE stream is a host-initiated action on an existing session: it
	// delivers that session's upstream server-initiated requests (sampling/createMessage,
	// elicitation) and notifications, so it must clear the SAME per-route audience pin and
	// session-owner binding a POST on that session does. Without these a cross-audience
	// token (gateway union validator) or a same-audience different-sub identity that
	// learned the victim's Mcp-Session-Id could open the stream and read another client's
	// server->client traffic — the exact leak the audience pin and owner binding exist to
	// prevent. A GET carries no JSON-RPC envelope, so a refusal is an HTTP 403 with a
	// transport-tagged deny record (method/identifier empty), mirroring the kill-switch
	// refusal. All three checks run before sess.touch() so a refused open does not defer
	// the victim session's idle reaping.
	//
	// route is always non-nil in production; the nil guard only covers the test-only
	// construction that wires no route. route.pdp is non-nil whenever route is (every
	// route constructor substitutes a concrete PDP).
	if route != nil {
		// Per-route audience pin + session-owner binding, via the same helper the POST path
		// uses: a token minted for a sibling route's audience (accepted by the shared union
		// validator), or a same-audience second identity that learned the victim's
		// Mcp-Session-Id, must not open this route's session stream and read another client's
		// server->client traffic. An unbound, no-JWT session is a no-op.
		if _, denied := route.enforceSessionGates(r.Context(), sess, sessionID, "", "sse-get"); denied {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		// Kill-switch check before serving: a killed (or globally emergency-stopped)
		// session must not OPEN (or re-open) an SSE stream. This guards stream opens only.
		// A targeted kill now tears the session down proactively (reapKilledSession, which
		// closes the session and so ends its stream), but this check still matters for the
		// cases teardown does not cover — a GLOBAL emergency stop, which writes the kill
		// store without naming a session, and a re-open attempt racing that teardown. A
		// kill-store error fails closed via CheckKill.
		if deny := route.pdp.CheckKill(r.Context(), sessionID); deny != nil {
			recordKillDrop(r.Context(), asRecorder(route.sink), deny, sessionID, "", "", legSSEGet)
			http.Error(w, "session terminated", http.StatusForbidden)
			return
		}
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
	// On stream exit, unsubscribe AND drain: broadcastServerRequest may have buffered
	// a server-initiated request into ch that the loop never read, leaving its upstream
	// blocked on a response this departed client will never send. The drain replies an
	// error upstream for each so it unblocks immediately. r.Context() is captured now
	// (defer evaluates its arguments immediately): it carries the JWT claims handleMCP
	// attached before dispatch, for the correction record's agent_id/task_id. Reading
	// context.Value after r.Context() is later canceled by client disconnect is safe.
	defer sess.removeSubAndDrain(r.Context(), ch)

	// SEC-03: SSE is long-lived, so the fixed server-level httpWriteTimeout (a
	// per-call Slowloris backstop) must not kill the stream after one budget. But a
	// permanently cleared deadline lets a stuck reader (a TCP zero/tiny receive
	// window that never drains) park this goroutine inside a blocked Write forever,
	// pinning the goroutine and its maxSubsPerSession slot past kill and idle-reap
	// (none of those teardown paths break a blocked write). So re-arm a bounded
	// deadline before every write via writeSSE instead: a wedged write trips the
	// deadline, returns an error, and ends the stream (running the removeSubAndDrain
	// defer that frees the slot and unblocks any buffered server-initiated request).
	// r.Context() still enforces clean disconnects.
	rc := http.NewResponseController(w)

	// writeSSE writes one SSE frame from its byte-slice parts, re-arming the bounded
	// write deadline before each sseWriteChunk-sized write so the deadline measures
	// per-chunk forward progress — a slow-but-progressing reader is not killed
	// mid-frame, a stuck (no-progress) reader still trips it — then flushing once.
	// Returns false on any write or flush error so the caller ends the stream. Taking
	// []byte parts lets the data path stream the marshaled payload without copying it
	// into a new string.
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
	// Flush the response headers and emit an initial keepalive comment so the liveness
	// clock starts at stream open — there is no unguarded gap before the first
	// keepalive interval, and an intermediary with a sub-interval idle timeout sees
	// traffic immediately. writeSSE arms the bounded deadline, so a reader already
	// wedged at open is detected within sseWriteTimeout rather than never.
	if !writeSSE(sseKeepaliveFrame) {
		return
	}

	// Periodic comment frame on an otherwise-idle stream (after the initial one
	// above): re-arms the bounded write deadline so a reader that has stopped draining
	// is detected within sseKeepaliveInterval + sseWriteTimeout, and keeps
	// intermediaries from idling the connection out.
	keepalive := time.NewTicker(sseKeepaliveInterval)
	defer keepalive.Stop()

	// Bound the stream to the presenting token's exp. The Bearer was validated once, at
	// stream open (in handleMCP); without this an expired — or IdP-revoked but not
	// kill-switched — client keeps receiving server->client traffic until it disconnects
	// or the idle reaper runs. When the token's lifetime elapses, end the stream so the
	// client must re-open (and thus re-validate) with a fresh token. A nil channel (no
	// JWT on this session) never fires, so the non-JWT path is unaffected;
	// time.NewTimer fires immediately for an already-elapsed exp (fail closed). Bound to
	// this GET's own token, matching what handleMCP validated. Kill-switch eviction
	// (sess.evicted) already covers administrative revocation; this covers plain expiry.
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
				// Consumed from ch but unserializable. If it is a server-initiated
				// request, the upstream is now blocked awaiting a response the host will
				// never receive, so unblock it with an error reply. A notification (no ID)
				// expects no response, so dropping it is correct.
				sess.failServerRequestDelivery(r.Context(), msg, "proxy: failed to serialize server-initiated request for SSE delivery")
				continue
			}
			if !writeSSE(sseDataPrefix, data, sseFrameEnd) {
				// The frame was consumed from ch but the write failed (stuck reader or
				// disconnect). If it is a server-initiated request, unblock the upstream
				// the same way the serialize-error and drain paths do: removeSubAndDrain
				// only recovers messages STILL buffered in ch, not this already-consumed
				// one, so it would otherwise hang until the idle reaper.
				sess.failServerRequestDelivery(r.Context(), msg, "proxy: SSE write failed before delivering server-initiated request")
				return
			}
		case <-keepalive.C:
			// Re-anchor the expiry bound to the wall clock. time.Until sampled the wall
			// clock once at stream open, but the resulting timer runs on the monotonic
			// clock, which does not advance while the host is suspended — so a laptop or
			// VM suspended mid-stream would otherwise extend the authorized window past
			// exp by the suspend duration. This tick already fires every few seconds, so
			// the check is free and bounds the overshoot to one keepalive interval.
			if !tokenExpiresAt.IsZero() && !time.Now().Before(tokenExpiresAt) {
				return
			}
			if !writeSSE(sseKeepaliveFrame) {
				return
			}
		case <-sess.evicted:
			// The session was killed while this stream was open. End it now so a killed
			// session stops receiving notifications immediately. A reopen attempt is
			// refused by the kill-switch check at the top of handleMCPGet.
			return
		case <-sess.done:
			return
		case <-tokenExpiry:
			// The presenting token's lifetime elapsed; end the stream so a re-open must
			// carry a fresh token (see the tokenExpiry setup above).
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
	// Run the context-only gate (the audience pin) BEFORE taking p.mu, and carry its
	// verdict into the locked region. It depends only on the request's claims, never on
	// the session, so evaluating it early changes no decision — but it keeps the
	// PolicyDecisionPoint call, whose implementation is an exported seam, off the global
	// session-registry write lock that serializes every lookup, register, and reap.
	// The verdict is APPLIED below only once the session is confirmed to exist and to
	// belong to this route, preserving the 403-vs-404 shape exactly.
	var audienceGate sessionGate
	var audienceDenied bool
	if route != nil {
		audienceGate, audienceDenied = route.contextGateVerdict(r.Context())
	}

	p.mu.Lock()
	sess, ok := p.sessions[sessionID]
	if ok && sess.route != route {
		// A session may only be torn down via the route it was opened on, so a
		// cross-route DELETE cannot close another upstream's session.
		p.mu.Unlock()
		http.Error(w, "session does not belong to this upstream route", http.StatusConflict)
		return
	}
	if ok {
		// Per-route audience pin + session-owner binding before teardown, mirroring the
		// SSE-GET stream-open and existing-session POST paths. A DELETE is a host-initiated
		// action on an existing session, so it must clear the SAME gates: the gateway's
		// shared union validator accepts a token minted for ANY route's audience, so a
		// sibling-audience token (or a same-audience different identity that learned the
		// victim's Mcp-Session-Id) could otherwise tear down another client's session — a
		// cross-audience teardown / tenant DoS. Enforced only once the session is confirmed
		// to exist AND belong to this route, so a refusal cannot probe which session ids
		// exist (a not-found id still falls through to 404 below); a no-pin /
		// --jwt-allow-any-audience route and an unbound (no-JWT) session are no-ops. A DELETE
		// carries no JSON-RPC envelope, so a refusal is an HTTP 403 plus a transport-tagged
		// deny record (method/identifier empty), matching the GET refusal convention. The
		// kill switch is deliberately NOT consulted: tearing a session down is always
		// permitted (cleanup of a killed session must still succeed).
		//
		// route is always non-nil in production (handleMCP 404s an unknown route before
		// dispatch); the nil guard only covers the test-only construction that wires no
		// route, matching handleMCPGet. The two gate halves are applied in the same order
		// sessionGateVerdict applies them — audience first, already computed above the lock;
		// owner second, a pure field compare cheap enough to run here — so DELETE clears
		// exactly the gates POST/GET clear, and a gate added to either half cannot silently
		// skip it. Only the record + 403 render happen after unlocking.
		if route != nil {
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
		}
		delete(p.sessions, sessionID)
	}
	p.mu.Unlock()
	if !ok {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	sess.close(p.shutdownMs) //nolint:contextcheck // teardown path: close()'s upstream session-termination DELETE intentionally runs on a detached, bounded background context — binding it to r.Context() would cancel the teardown the instant this 204 is written, leaking the upstream session. Same rationale as the handleMCPDelete dispatch site.
	w.WriteHeader(http.StatusNoContent)
}

// handleKill processes POST /control/kill (loopback only).
func (p *HTTPProxy) handleKill(w http.ResponseWriter, r *http.Request) {
	// Loopback guard runs first — before the method check — so an off-host caller is
	// rejected by the security boundary rather than learning the endpoint exists via a
	// 405. Matches handleHealth/handleMetrics.
	if !p.loopbackOnly(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// SEC-07: the loopback check stops remote access, but a same-host process (e.g. a
	// compromised tool subprocess) could reach this endpoint over loopback. Require the
	// auto-generated control token (written to a 0600 file at startup, independently of
	// authToken/JWT mode) so the emergency stop is never reachable without it.
	if !p.checkControlToken(w, r) {
		return
	}

	// SEC-04: cap request body to prevent memory exhaustion.
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	var body struct {
		SessionID string `json:"sessionId"`
		All       bool   `json:"all"`
	}
	// Reject a body carrying a trailing JSON token (e.g. a legitimate
	// {"sessionId":"..."} followed by a smuggled {"all":true}): without this, only
	// the first value is decoded and the second is silently dropped, so the kill
	// actually executed could differ from what a body-only reviewer would expect.
	if !decodeStrictJSON(w, r, &body, "invalid request body") {
		return
	}
	if body.All {
		// Propagate a kill-store write failure (fail closed): returning {"ok":true} on
		// a failed emergency stop would leave the operator believing the system is safe
		// while requests keep being served. The in-memory backend always returns nil.
		if err := p.ks.ActivateGlobal(r.Context()); err != nil {
			// Log the backend detail (e.g. a Redis error carrying an internal host:port)
			// for the operator; return a generic message.
			fmt.Fprintf(os.Stderr, "[eunox] kill switch activation failed: %v\n", err)
			http.Error(w, "kill switch activation failed", http.StatusInternalServerError)
			return
		}
		// Evict every open SSE stream: writing the kill state stops future operations,
		// but a stream opened before the kill is long-lived and would keep delivering
		// notifications until the idle ceiling. This makes the stop total for the
		// server->client channel too.
		p.evictAllSessionStreams()
		// Proactively tear every session down (close upstreams, free maxSessions slots)
		// rather than leaving reclamation to the idle reaper, which does not run when
		// sessionIdleTimeoutMs is 0 — otherwise killed-but-undead sessions would pin
		// capacity and 503 new initializes.
		p.reapAllKilledSessions() //nolint:contextcheck // teardown path: close()'s upstream session-termination DELETE intentionally uses a detached, bounded background context — binding it to r.Context() would cancel the teardown the instant this response is written. Same rationale as the handleMCPDelete close() site.
		p.recordKillActivated(r, killScopeAll)
		p.writeKillResponse(w, "all")
		return
	}
	if body.SessionID == "" {
		http.Error(w, "sessionId or all required", http.StatusBadRequest)
		return
	}
	if err := p.ks.KillSession(r.Context(), body.SessionID); err != nil {
		fmt.Fprintf(os.Stderr, "[eunox] kill switch session kill failed: %v\n", err)
		http.Error(w, "kill switch session kill failed", http.StatusInternalServerError)
		return
	}
	// End this session's open SSE stream(s), same reason as the global path above.
	p.evictSessionStreams(body.SessionID)
	// Proactively tear the killed session down (close its upstream, free its
	// maxSessions slot) instead of relying on the idle reaper, which does not run when
	// sessionIdleTimeoutMs is 0 — see reapKilledSession.
	p.reapKilledSession(body.SessionID) //nolint:contextcheck // teardown path: close()'s upstream session-termination DELETE intentionally uses a detached, bounded background context. Same rationale as the handleMCPDelete close() site.
	p.recordKillActivated(r, body.SessionID)
	p.writeKillResponse(w, body.SessionID)
}

// killScopeAll is the scope recorded (and returned) for a whole-proxy emergency stop,
// distinguishing it from a targeted kill, whose scope is the killed session id.
const killScopeAll = "all"

// recordKillActivated writes the audit record for a SUCCESSFUL /control/kill
// activation. Every refusal of this endpoint already lands on the tape
// (CONTROL_AUTH_FAILED, LOOPBACK_REJECTED, ORIGIN_REJECTED), and every request the
// activation goes on to block lands as a KILL_SWITCH denial — but the activation
// itself, the single administrative act that explains the whole run of denials that
// follows, left no trace at all. An auditor reconstructing an incident could see the
// proxy stop serving without any signed evidence of when it was stopped or that the
// stop was authorized.
//
// Recorded as an ALLOW: the request was authenticated by the control token and
// performed, so it is a permitted action, not a refusal. It is emitted AFTER the
// kill-store write and session teardown succeed, so the tape never claims a stop that
// did not take effect (a failed ActivateGlobal/KillSession returns 500 before reaching
// here). scope is the killed session id, or killScopeAll for a whole-proxy stop; it
// goes in details rather than the structured target field, which is reserved for MCP
// tool/resource/prompt targets this administrative action has none of.
//
// The record carries no credential — the control token is never recorded, matching the
// CONTROL_AUTH_FAILED refusal path — and no session_id: a global stop addresses no
// single session, and a targeted one names its session in details.scope, where it
// cannot be confused with an authenticated session binding.
func (p *HTTPProxy) recordKillActivated(r *http.Request, scope string) {
	if p.sink == nil {
		return
	}
	p.sink.RecordAllow(r.Context(), "", "", MethodControlKill, map[string]interface{}{
		"scope":     scope,
		"source_ip": p.sourceIP(r),
	}, nil, false, nil, nil)
}

// writeKillResponse writes the kill endpoint's {"ok":true,"killed":<target>}
// success body. Every route honors the kill switch (including wiretap), so the
// response carries no partial-coverage caveat.
func (p *HTTPProxy) writeKillResponse(w http.ResponseWriter, killed string) {
	w.Header().Set("Content-Type", CTJSON)
	resp := map[string]interface{}{"ok": true, "killed": killed}
	b, _ := json.Marshal(resp)
	_, _ = w.Write(b)
}
