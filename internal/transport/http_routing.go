// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// HTTP request routing: the /mcp POST / GET / DELETE handlers and the
// loopback-only /control/kill endpoint.

package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/killswitch"
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

// writeDispatchResult writes the shared dispatcher's reply, or acks with 202 when it produced none.
//
// The enforced-forward core returns the ZERO message for a request with no reply channel (see
// refusalResponse), and RPCMsg.JSONRPC has no omitempty — so writing it unconditionally would send
// the malformed frame `{"jsonrpc":""}` where nothing should have been sent. 202 is what this
// transport already answers a POST carrying nothing to reply to. Unreachable while the POST arm
// gates on IsRequest before dispatching; the guard is what keeps that from being the only reason.
func writeDispatchResult(w http.ResponseWriter, resp mcp.RPCMsg) {
	if resp.IsZero() {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	writeJSONMsg(w, resp)
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
			p.recordPreSessionDeny(r, codeJWTInvalid, catJWT, map[string]interface{}{"error_type": pdp.ClassifyJWTError(err)})
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

// jsonSchemaShape declares whether the body being decoded is one whose every member this
// package defines, or one belonging to a protocol that may carry members eunox does not
// model. It is a parameter rather than a per-endpoint default so a new POST body has to
// answer the question rather than inherit whichever answer its neighbour happened to need.
type jsonSchemaShape bool

const (
	// openSchema is the JSON-RPC envelope on /mcp. MCP may add members this build does not
	// model and those bytes are forwarded to the upstream verbatim, so refusing an unknown
	// or repeated member here would refuse traffic a conforming peer is entitled to send —
	// and the enforcement-versus-upstream differential that WOULD matter is closed where the
	// forwarded bytes are re-read (DecodeParams), not by narrowing the envelope.
	openSchema jsonSchemaShape = false
	// closedSchema is a body this package defines end to end — today /control/kill's alone.
	// Its members select WHICH kill runs, so a member resolved by a rule the reviewer of the
	// body cannot see is the substitution the trailing-token guard already refuses one value
	// out: encoding/json matches names case-insensitively and keeps the LAST duplicate, so
	// {"sessionId":"s1","all":true,"sessionId":""} reads as a targeted kill and executes a
	// deployment-wide one, and a misspelled "session_id" is dropped in silence with "all"
	// left standing.
	closedSchema jsonSchemaShape = true
)

// decodeStrictJSON is the single safe way to read a JSON POST body in this package. It
// gates the Content-Type (415), then decodes exactly one JSON value into v, requiring
// io.EOF after it: a body carrying a trailing token is rejected with 400 rather than
// silently truncated — otherwise a multi-token /mcp body could 202-ack an invalid
// initialize notification, or a /control/kill body could execute a narrower kill while
// ignoring a smuggled trailing {"all":true}. Under closedSchema it additionally refuses an
// ambiguous member name (capability.RefuseAmbiguousJSONKeys, the same primitive the two
// reviewed-document loaders use) and an unrecognized one, closing the two shapes that
// express that same smuggled value INSIDE one valid JSON object rather than after it. On a
// refused content type, a decode failure, or trailing data it writes the response itself
// and returns false; the caller must return immediately. The 400 legs are recorded via
// recordRefusal (codeInvalidRequest) through the same rate-limited pre-session path as the
// 415 leg, so a malformed body leaves the same trace other transport-level refusals do;
// the 413 leg is not recorded since MaxBytesReader already bounds that flood's cost.
//
// route is threaded to requireJSONContentType and recordRefusal so the /mcp caller's
// records carry its route stamp; /control/kill has no route and passes nil, which
// recordRefusal treats as "write through the proxy-wide sink".
//
// The content-type gate lives HERE rather than at each handler so every JSON POST body in
// this package gets it by construction — a mux wrapper is the wrong shape since GET/DELETE
// carry no body.
func (p *HTTPProxy) decodeStrictJSON(w http.ResponseWriter, r *http.Request, v interface{}, invalidBodyMsg string, route *UpstreamRoute, shape jsonSchemaShape) bool {
	if !p.requireJSONContentType(w, r, route) {
		return false
	}
	body := io.Reader(r.Body)
	if shape == closedSchema {
		// Buffered rather than streamed because the ambiguity walk needs the whole document:
		// it reads member names the decode then RESOLVES, so it cannot share the decoder that
		// consumes them. Bounded by the caller's MaxBytesReader exactly as the stream is, and
		// only on this shape, so /mcp keeps its streaming profile.
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return false
			}
			p.recordRefusal(r.Context(), r, route, codeInvalidRequest, catBody, map[string]interface{}{
				"reason": "unreadable_body",
			})
			http.Error(w, invalidBodyMsg, http.StatusBadRequest)
			return false
		}
		// Deliberately BEFORE the decode: the walk's whole point is that the decoder resolves
		// what it refuses, so a verdict taken from the decoded struct is the resolution.
		if err := capability.RefuseAmbiguousJSONKeys(raw); err != nil {
			p.recordRefusal(r.Context(), r, route, codeInvalidRequest, catBody, map[string]interface{}{
				"reason": "ambiguous_member_name",
			})
			http.Error(w, invalidBodyMsg+": ambiguous member name", http.StatusBadRequest)
			return false
		}
		body = bytes.NewReader(raw)
	}
	dec := json.NewDecoder(body)
	if shape == closedSchema {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return false
		}
		// The raw decode error and body are NOT recorded — either can carry
		// attacker-controlled free text; only the fixed reason string is kept.
		p.recordRefusal(r.Context(), r, route, codeInvalidRequest, catBody, map[string]interface{}{
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
		p.recordRefusal(r.Context(), r, route, codeInvalidRequest, catBody, map[string]interface{}{
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
// initialize started was already torn down), errShuttingDown (proxy draining),
// errSessionExists (a concurrent first request on the same identity won the race and its
// worker was gone again before this one could adopt it). Anything
// else is an upstream-start failure — the raw error may carry a command path, IP:port, or
// TLS detail, so it's logged to stderr and returned as a generic 500.
//
// errSessionExists reaches here only when the ADOPTION that normally absorbs it failed — see
// createFirstRequestSession — which is the same benign lifecycle race as its two siblings and
// wants the same answer. Falling to the default arm told the caller "failed to start upstream"
// about an upstream that started fine, on a 500 no client retries, for a race a retry resolves.
//
// errSessionLimit is additionally recorded via recordSessionCapDeny, the same helper the
// pre-spawn slot reservation uses, so the two ways to hit one cap can't produce two record
// shapes — it's reachable WITHOUT an established session, so it's the cheaper flood and was
// the one leaving no trace. The other three legs are benign lifecycle races, not attack
// signal, so they stay status-only.
func (p *HTTPProxy) writeSessionCreateError(ctx context.Context, w http.ResponseWriter, r *http.Request, route *UpstreamRoute, err error) {
	// Re-arm before ANY of the writes below. The initialize arm armed one window covering
	// establishment, but a failure path spends time that window does not budget for: a drift
	// refusal runs sess.close synchronously, whose worst case is two sequential shutdown
	// budgets, and the ctx-expiry arm adds another bounded wait on top. At a large
	// --shutdown-timeout against a SIGTERM-ignoring subprocess the deadline is already past by
	// the time the 500 carrying the drift refusal is written, so the one outcome the startup
	// drift check exists to deliver reaches the host as a connection error instead. This is the
	// teardown-shaped write the teardown re-arm (built for DELETE and /control/kill) missed.
	rearmWriteDeadlineForTeardown(w, p.shutdownMs)
	switch {
	case errors.Is(err, errSessionLimit):
		p.recordSessionCapDeny(ctx, r, route)
		http.Error(w, "session limit reached", http.StatusServiceUnavailable)
	case errors.Is(err, errRacedReap):
		http.Error(w, "session raced a kill-switch reap; retry", http.StatusServiceUnavailable)
	case errors.Is(err, errShuttingDown):
		http.Error(w, "server shutting down; retry", http.StatusServiceUnavailable)
	case errors.Is(err, errSessionExists):
		http.Error(w, "a concurrent request's worker for this identity was torn down before this one could join it; retry",
			http.StatusServiceUnavailable)
	default:
		_, _ = fmt.Fprintf(p.errOut(), "[eunox] failed to start upstream: %v\n", err)
		http.Error(w, "upstream unavailable", http.StatusInternalServerError)
	}
}

// handleSessionCreatingInitialize answers the one `initialize` that runs OUTSIDE
// dispatchRequest: the request with no session id, which creates the session the shared
// dispatcher needs in order to run at all.
//
// It is a named function for the reason the existing-session path was split out — complexity
// bounds — and for a second one this arm alone has: it carries EIGHT ordered gates that
// gate_order_test.go asserts on, and an order asserted by a test three files away should be
// stated once, here, beside the code that implements it:
//
//  1. revision negotiation, so every refusal below records under a resolved revision and a
//     declaration this build cannot honor is refused before anything is spawned;
//  2. the kill switch, before any privileged side effect;
//  3. the per-route audience pin, so a token valid only for a SIBLING route's audience
//     cannot spin up this route's upstream and read its serverInfo;
//  4. --require-audit=strict, since creating a session is itself a privileged side effect;
//  5. the session-slot RESERVATION, taken pre-spawn and held across establishment;
//  6. establishment (subprocess or remote), under the session-start budget;
//  7. the drift check, inside establishment, which tears the session back down on a refusal;
//  8. the response, answered directly rather than through dispatchInitialize's kill gate.
//
// Gates 5-7 are establishSession's, shared with the declaring peer's first request; 1-4 and the
// response are this arm's. The declaring arm's own pre-tail gates are neither the same list nor
// in this order — it is handed an already-resolved revision, and it requires a stable identity
// and waits on an existing worker before the kill/audience/strict-audit trio — so this numbering
// describes this arm alone.
//
// startGen is captured ahead of all of it — see the comment at its assignment.
//
// Returns nothing: every exit has already written its own response.
func (p *HTTPProxy) handleSessionCreatingInitialize(w http.ResponseWriter, r *http.Request, route *UpstreamRoute, msg mcp.RPCMsg) {
	// Captured BEFORE the kill gate below: that gate does a kill-store round-trip that
	// may do I/O, and a kill activating/sweeping inside that window would otherwise
	// yield a startGen equal to the post-sweep generation, letting registerSession admit
	// a kill-denied session that then pins a subprocess/slot until process exit (with no
	// idle reaper configured, that leak never self-heals).
	startGen := p.currentReapGen()
	// Negotiate FIRST, ahead of the kill gate — dispatch.go's canonical order, which
	// stdio applies to these same bytes: a probe declaring an unhonorable revision must
	// record the same code on both transports, kill active or not. Also before anything
	// privileged: creating a session spawns or contacts an upstream, and a declaration
	// this build cannot honor (or one naming a revision that has no `initialize` at all)
	// must be refused without that side effect. Answering initialize is itself the
	// negotiation, so the only admissible declaration here is the revision that defines
	// the method.
	rev, ok := p.negotiateHostRevision(w, r, route, nil, msg)
	if !ok {
		return
	}
	// The refusals below and the establishment itself all decide under the revision just
	// resolved; stamping it is what puts protocol_revision on their records, the same
	// "absent means pre-negotiation" convention every dispatched record follows.
	ctx := capability.WithProtocolRevision(r.Context(), rev)
	// Kill-switch check BEFORE spawning anything. This is the one initialize answered
	// outside dispatchRequest (no session/dispatchParams yet), so it repeats the kill
	// gate dispatchRequest applies to every other locally-answered method.
	if deny := route.pdp.CheckKill(ctx, ""); deny != nil {
		// No session exists yet, so claimedSession is the honest subject rather than fact.
		// Rate-limited: an unauthenticated caller reaches this record, so an unbounded
		// write here is an audit-queue flooding primitive; a suppressed record elides
		// only the RECORD, the request is denied either way.
		resp := recordKillDenial(ctx, p.preSessionKillRecorder(route), deny, msg, claimedSession(r))
		writeJSONMsg(w, resp)
		return
	}
	// Per-route audience pin BEFORE spawning: a token valid only for ANOTHER route's
	// audience (accepted by the gateway's shared union validator) must not create a
	// session on this route. Initialize doesn't flow through the Decide*/list/sampling
	// paths that embed the same pin, so without this gate a cross-audience token could
	// spin up this route's upstream and read its serverInfo.
	if denied, blocked := p.creationAudienceDenial(ctx, route, msg, mcp.MethodInitialize, mcp.MethodInitialize); blocked {
		writeJSONMsg(w, denied)
		return
	}
	// --require-audit=strict: creating a session spawns/contacts an upstream — a
	// privileged side effect — so once the audit trail has degraded, refuse new sessions
	// fail-closed rather than run traffic that can't be fully recorded.
	if denied, blocked := p.creationStrictAuditDenial(ctx, route, msg, mcp.MethodInitialize, mcp.MethodInitialize); blocked {
		writeJSONMsg(w, denied)
		return
	}
	// The reservation, the start budget, and the spawn itself are establishSession's — the
	// tail this arm shares with the declaring peer's first request. The cap refusal comes back
	// as errSessionLimit and is answered by the same helper as its post-registration twin.
	sess, err := p.establishSession(ctx, w, r, route, handshakeSeed, startGen)
	if err != nil {
		p.writeSessionCreateError(ctx, w, r, route, err)
		return
	}
	w.Header().Set(SessionHeader, sess.id)
	// Re-arm before the success write too, so the entry arm's claim that the actual encode
	// always arms a fresh window holds for this arm as well: establishment may have spent
	// the whole start budget, leaving the window armed for it exhausted at encode time.
	rearmWriteDeadlineFor(w, sessionStartBudget(p.upstreamTimeMs))
	// Answered directly, not through dispatchInitialize's kill gate: the global-dimension
	// CheckKill already ran above, and the session id minted here is brand new, so it
	// can't yet be a per-session kill target.
	resp := sess.buildInitResponse(msg)
	writeJSONMsg(w, resp)
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
	if !p.decodeStrictJSON(w, r, &msg, "invalid JSON-RPC body", route, openSchema) {
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
		p.handleSessionCreatingInitialize(w, r, route, msg)
		return
	}

	if sessionID == "" {
		// An initialize notification (excluded from the session-creation branch above)
		// expects no response: accept and drop it without allocating session state.
		if msg.Method == mcp.MethodInitialize && msg.IsNotification() {
			// The same two gates every other host message passes, in the same order, from the
			// same two helpers: negotiation first (a refusal is recorded and acked bodyless,
			// which is what negotiateHostRevision does for a notification), then the shared
			// notification gate. Hand-placing them here is what left this arm negotiating
			// nothing at all while stdio recorded UNSUPPORTED_PROTOCOL_VERSION for identical
			// bytes.
			rev, ok := p.negotiateHostRevision(w, r, route, nil, msg)
			if !ok {
				return
			}
			ctx := capability.WithProtocolRevision(r.Context(), rev)
			// established:false is the one thing this arm answers differently, and it is a
			// FACT rather than a reordering: the swallowed set is what the proxy has already
			// handled, and pre-session it has handled nothing — so revocation still sees this
			// message and a 202 during an emergency stop is recorded rather than being a
			// silent readiness ack.
			gate := hostNotificationGate{
				recorders:   p.preSessionRefusalRecorders(route),
				subject:     claimedSession(r),
				audit:       route.audit,
				strictAudit: p.strictAudit(),
				checkKill:   func() *capability.EnforceResponse { return route.pdp.CheckKill(ctx, "") },
				leg:         legHTTPNotification,
			}
			if gate.admit(ctx, msg) == notificationForward {
				// Unreachable: `initialize` is a swallowed notification and this arm handles no
				// other method. Answered as the drop it must be anyway — there is no session
				// here, so nothing to forward it on — rather than discarding the verdict and
				// letting a future forwardable pre-session method be dropped in silence.
				if line, ok := p.noticeWriter().admitNotice(siteUpstreamlessNotification); ok {
					line.writef(
						"[eunox] SECURITY: pre-session notification %q was admitted for forwarding with no upstream to forward it to; dropped\n",
						BoundConsoleDetail(msg.Method))
				}
			}
			w.WriteHeader(http.StatusAccepted)
			return
		}
		p.handleSessionlessPost(w, r, route, msg)
		return
	}
	// Past both early returns above, so this is the one arm whose forwards are made on a host's
	// behalf — and therefore the only one that carries a grant (client_headers.go). Derived here,
	// at the call site, because contextcheck requires an r.Context() derivation to be visible
	// where it happens rather than buried in the callee.
	p.handleSessionPost(w, grantHostHeaders(r, route), route, sessionID, msg)
}

// handleSessionlessPost answers a host POST that carries no session id.
//
// Negotiated FIRST, as every other arm on this transport is: this was the one host-leg refusal
// taken ahead of the revision, so a peer whose declaration this build cannot honor got a bare
// 400 and nothing on the tape while the identical bytes on every other path were recorded as
// UNSUPPORTED_PROTOCOL_VERSION.
//
// The revision then decides what a sessionless POST MEANS, which is the whole of D3. On
// 2025-11-25 the session header is real and the peer simply omitted it, so the 400 naming it is
// the right answer and this release's regression invariant. On a declaring revision there is no
// such header to omit: the request is a FIRST REQUEST, and it mints or joins the worker it runs
// on (first_request_session.go).
func (p *HTTPProxy) handleSessionlessPost(w http.ResponseWriter, r *http.Request, route *UpstreamRoute, msg mcp.RPCMsg) {
	rev, ok := p.negotiateHostRevision(w, r, route, nil, msg)
	if !ok {
		return
	}
	if !declaresPerRequestRevision(rev) {
		http.Error(w, SessionHeader+" header required", http.StatusBadRequest)
		return
	}
	// Only a REQUEST may mint a worker. The `initialize` arm has always guarded this — "a
	// notification must never start an upstream or consume a session slot" — and a declaring
	// peer's sessionless notification, host response or unframed message is the same hazard
	// with no handshake to hang the guard off: each would fork an upstream for a message that
	// can never be answered and whose sender it does not identify. There is no worker for one
	// to run on either way, so it is dropped, recorded, and acked bodyless as JSON-RPC requires.
	if !msg.IsRequest() {
		p.dropUnworkableSessionlessMessage(r, route, rev, msg)
		w.WriteHeader(http.StatusAccepted)
		return
	}
	sess := p.firstRequestSession(w, r, route, rev, msg)
	if sess == nil {
		return // the refusal is written by whichever gate refused
	}
	// Re-entered through the ESTABLISHED-session arm rather than dispatched here, so a first
	// request runs every per-request gate a second request runs — the audience pin, the owner
	// binding, the in-flight accounting, the decision turn — instead of a creating path growing
	// its own copy of them. Its negotiation runs a second time and resolves identically: the
	// worker is pinned to the revision this request just declared.
	p.handleSessionPost(w, grantHostHeaders(r, route), route, sess.id, msg)
}

// unservableDetail names WHY a negotiated peer could not be served, in the shape unroutableDetail
// uses for the same class of refusal: eunox's own, with no policy behind it.
func unservableDetail(rev capability.Revision, reason string) map[string]interface{} {
	return map[string]interface{}{
		detailUnservable: map[string]interface{}{
			"reason":   reason,
			"revision": rev.String(),
		},
	}
}

const (
	// detailUnservable is the audit detail key naming a refusal eunox made because this
	// DEPLOYMENT cannot serve the peer, as distinct from one the peer's own message earned.
	detailUnservable = "unservable"
	// unservableUnauthenticated: a declaring request presented no credential carrying a stable
	// agent identity, so there is no subject to key a worker on and each request would fork its
	// own upstream. See first_request_session.go.
	unservableUnauthenticated = "unauthenticated_first_request"
	// unservableNotARequest: a declaring peer sent a sessionless message that is not a request
	// — a notification, a host response, or a frame that is neither. It can mint no worker and
	// there is none for it to join, so it is dropped.
	unservableNotARequest = "sessionless_message_is_not_a_request"
)

// dropUnworkableSessionlessMessage records a declaring peer's sessionless non-request before it
// is acked bodyless.
//
// Recorded rather than silently dropped, and metered on the same bucket as the other unservable
// refusals: it is reachable pre-session by an unauthenticated peer at one frame per record, and a
// message that vanishes with no trace is the one an operator most needs to see when a host is
// mysteriously getting nothing done.
func (p *HTTPProxy) dropUnworkableSessionlessMessage(r *http.Request, route *UpstreamRoute, rev capability.Revision, msg mcp.RPCMsg) {
	rec := p.routeRefusalLimits().recorders(refusalSink(p, route)).forCategory(catUnservable)
	if rec == nil {
		return
	}
	identifier, method := auditIdentity(msg)
	rec.RecordDeny(capability.WithProtocolRevision(r.Context(), rev), "", identifier, method,
		capability.ErrCodeEnforcementError, "", unservableDetail(rev, unservableNotARequest), false)
}

// handleSessionPost handles a host POST carrying an existing Mcp-Session-Id: it validates
// the session/route binding and the per-route audience pin, then forwards a notification,
// routes a host response back to the upstream, answers a re-initialize echo, or dispatches
// an enforced request. Split out of handleMCPPost so the session-creating initialize path
// and the existing-session path each stay within complexity bounds.
func (p *HTTPProxy) handleSessionPost(w http.ResponseWriter, r *http.Request, route *UpstreamRoute, sessionID string, msg mcp.RPCMsg) {
	sess := p.getSession(sessionID)
	if sess == nil {
		p.denyUnresolvedSession(w, r, route, sessionID, msg)
		return
	}
	if sess.route != route {
		http.Error(w, "session does not belong to this upstream route", http.StatusConflict)
		return
	}
	// Count the request as in-flight for the WHOLE handler from here — right after the
	// route-binding check confirms sess is a live registration this request may act on —
	// not just the enforced-dispatch branch's upstream round trip. Mirrors stdio's own
	// discipline (it counts in the reader, before dispatch): a request that's denied by a
	// session gate, forwards a notification, or routes a host response back to the upstream
	// is real in-flight work too, and previously none of it held inFlight, so the idle
	// reaper could tear the session down (and teardown drop its decision gate + flow state)
	// out from under any of those paths, not just a blocked enforced call. Release via defer
	// so every return below — including a net/http-recovered panic — decrements it exactly
	// once; the reaper's arms only get MORE conservative by counting more work as active.
	sess.inFlight.Add(1)
	defer sess.inFlight.Add(-1)
	// Run the session-scoped security gates — the per-route audience pin AND the
	// session-owner binding — on EVERY host-initiated action on this existing session, not
	// just the enforced (Decide) methods: a same-audience SECOND identity that learned this
	// session's id could otherwise reach the forwarded notification, response routing, the
	// re-initialize echo, or an enforced request against a victim's upstream. Runs before
	// touchRequest so a refused request doesn't defer the victim session's idle reaping.
	// auditIdentity, not msg.Method: this gate runs above dispatch and above every PDP, so its
	// record may name no policy target. See recordSessionGateDeny.
	gateID, gateMethod := auditIdentity(msg)
	if gate, denied := p.enforceSessionGates(r.Context(), route, sess, sessionID, gateID, gateMethod, legHTTPPost); denied {
		answerSessionGateRefusal(r.Context(), w, sess, gate, msg)
		return
	}
	// BELOW the session gates and ABOVE everything that reads this worker's negotiated state.
	// Below, because the gates decide from this request's own claims and the ones captured at
	// construction — neither of which establishment produces — so a caller who may not act on
	// this session at all is refused at once rather than parking for the establishment budget.
	// Above negotiation and dispatch, so the revocation lookup they take is FRESH past the wait.
	if !p.awaitServableWorker(w, r, route, sess, msg, legHTTPPost) {
		return
	}
	// Negotiate FIRST: every table below is revision-scoped, so resolving after the lookup
	// would route by one table and record under another.
	// A refused host RESPONSE also unblocks the upstream request it would have answered; that
	// is the shared prologue's, reached by handing it the SESSION rather than the session's leg.
	rev, ok := p.negotiateHostRevision(w, r, route, sess, msg)
	if !ok {
		return
	}
	// The stamped context is the ONE carrier of the decided revision from here down: the
	// tables route by it and the tape records it, so neither can name a revision the other
	// did not. Stamped inline rather than returned already-stamped because contextcheck
	// requires the derivation from r.Context() to be visible at the site; that the pairing
	// holds is pinned by TestGateOrder_RevisionRidesOneCarrier and its HTTP sibling.
	ctx := capability.WithProtocolRevision(r.Context(), rev)
	// ONE revocation lookup for this POST, resolved on FIRST use and shared by the gates below
	// that ask about this message: the notification gate and the server-response leg.
	//
	// LAZY for the reason hostNotificationGate.checkKill is a thunk — on a Redis-backed kill
	// switch this is a network round trip, and the swallowed set is dropped before revocation
	// is even a question. Computing it here unconditionally is what made that thunk save
	// nothing on this leg: every `notifications/initialized` the gate exists to drop for free
	// paid a round trip first.
	//
	// A plain memo, not sync.OnceValue: every reader runs on THIS goroutine (the gate, the
	// response leg and the touch below are all synchronous), so the atomics and the two extra
	// heap objects a Once costs would buy nothing on a per-request path.
	//
	// Deliberately NOT threaded into the dispatcher. Its boundary gate can be reached after an
	// unbounded wait for the decision turn, and a kill landing during that wait must be recorded
	// as KILL_SWITCH — an answer from before the wait would record the method's own refusal
	// instead. Sharing ends where waiting begins.
	var (
		killVerdict *capability.EnforceResponse
		killAsked   bool
	)
	kill := func() *capability.EnforceResponse {
		if !killAsked {
			killVerdict, killAsked = route.pdp.CheckKill(ctx, sessionID), true
		}
		return killVerdict
	}
	// A live POST is active host-initiated traffic (distinct from passively holding an SSE GET
	// open): it defers both the idle reaper and the hard idle ceiling. Gated on the kill so a
	// revoked session's denied POSTs can't keep deferring their own reaping (a request may race
	// teardownSessionByID's proactive teardown, and the reaper's killed arm is the backstop that
	// would otherwise never fire). Called from each branch below rather than here, so a message
	// the proxy does NOT act on neither defers reaping nor pays for the answer.
	touchIfLive := func() {
		if kill() == nil {
			sess.touchRequest()
		}
	}
	// Host notifications don't flow through the dispatcher, so they take the swallowed set,
	// the kill, and the two fail-closed rejects from the shared gate instead — one call, in
	// the one canonical order (see dispatch.go). Everything it admits is allowlisted for
	// verbatim forwarding on a live session. The gate runs before the notify-slot acquisition
	// below: no point reserving a slot for a notification about to be dropped.
	if msg.IsNotification() {
		gate := hostNotificationGate{
			recorders:   p.routeRefusalRecorders(route),
			subject:     verifiedSession(sessionID),
			established: true,
			audit:       route.audit,
			strictAudit: p.strictAudit(),
			checkKill:   kill,
			leg:         legHTTPNotification,
		}
		outcome := gate.admit(ctx, msg)
		// Anything the gate did NOT swallow is work done on this session's behalf — a forward,
		// or a refusal written to the tamper-evident tape — so it is host activity and defers
		// idle reaping exactly as before. Only the swallowed set defers nothing: it is dropped
		// for free, before revocation is even asked, so there is no answer to gate a touch on
		// and nothing the proxy did. The gate has already resolved the memo on every other
		// outcome, so this costs no second lookup.
		if outcome != notificationSwallowed {
			touchIfLive()
		}
		if outcome == notificationForward {
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
				recordResourceExhausted(ctx, asRecorder(route.sink), &sess.notifySaturation, sessionID, msg.Method)
				// Bounded for the reason the routing refusal's notice is: the record above is
				// collapsed to one per saturation EPISODE while this line ran once per refused
				// frame, so the diagnostic was the cheaper flood of the two. Admitted BEFORE its
				// arguments are built: this is the flood path the bucket exists for, and both the
				// method-name bound and the variadic boxing of its arguments are spent per refused
				// frame on a line that is then thrown away (see admitNotice).
				if line, ok := sess.noticeWriter().admitNotice(siteNotifyPoolSaturated); ok {
					line.writef("[eunox] HTTP session %s: notification %q dropped: too many concurrent notifications in flight\n",
						sessionID, audit.BoundEnvelopeField(msg.Method))
				}
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
			sess.forwardNotification(ctx, msg)
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}

	if !msg.IsRequest() {
		// Touch only if the leg ACTED on it: a reply whose id this proxy never issued (or a
		// message that is neither request, notification nor response) is discarded, and a
		// discarded message must not keep a session — and its upstream subprocess — alive past
		// its idle timeout. That is the same rule the notification arm above applies, and it is
		// what lets the leg ask nothing of the kill store for a message it drops.
		if p.routeHostServerResponse(ctx, route, sess, kill, msg) {
			touchIfLive()
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}
	touchIfLive()

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
		// Release the request slot via defer so a net/http-recovered panic in dispatchRequest
		// can't leak it. inFlight itself is now held for the whole handler (see the top of
		// this function), not just this branch.
		defer sess.releaseRequestSlot()
		if p.getSession(sess.id) != sess {
			// inFlight is now incremented immediately after the route-binding check at the
			// top of this function — right after sess was resolved via getSession, with
			// nothing blocking in between — so the window this re-validates is only that
			// handful of non-blocking statements, not the session gates, kill checks, and
			// notification handling this used to run through first. Kept anyway as a
			// fail-closed backstop rather than removed: async goroutine preemption means even
			// a gap with no blocking call is not provably zero-width, and every teardown drain
			// (awaitInFlightDrained, the inFlight.Load()==0 check before dropDecideGate,
			// awaitAndDropDecideGate) counts only requests that already incremented inFlight —
			// a straggler the drain missed would otherwise take its turn on a gate the registry
			// no longer owns, or decide against flow state ReleaseSession already cleared. Every
			// teardown path deletes from p.sessions before finishSessionCleanup releases that
			// state, so a straggler whose Add(1) the drain missed observes the deletion here
			// and fails closed instead.
			writeJSONMsg(w, mcp.ErrorResponse(msg.ID, jsonRPCCodeServerBusy, "eunox: session torn down; retry"))
			return
		}
		// Note the state anchor this request resolves, on the same predicate the turn below
		// takes: an ENFORCED method is the only one that commits anchored state for the
		// server-initiated leg to peek past, and this is the last point before the decision
		// where the request can still be refused without one. See httpSession.noteRequestAnchor
		// — the latch is sticky for the session's life, so every gate that can still refuse
		// must sit above it. It is a write, which is why it is not in the check-only
		// session-gate verdict, one of whose callers runs under the session-registry lock.
		if isEnforcedMethod(ctx, msg.Method) {
			sess.noteRequestAnchor(pdp.JWTClaimsPtr(r.Context()))
		}
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
		if sess.route.serializes() && isEnforcedMethod(ctx, msg.Method) {
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
	writeDispatchResult(w, resp)
}

// SSE frame byte fragments, hoisted so the hot delivery path allocates no
// per-frame strings: writeSSE streams a data frame as prefix + payload + end.
var (
	sseDataPrefix     = []byte("data: ")
	sseFrameEnd       = []byte("\n\n")
	sseKeepaliveFrame = []byte(": keepalive\n\n")
)

// denyUnresolvedSession answers a POST naming a session id this proxy does not have.
//
// A killed session is proactively torn out of the registry, so its id no longer resolves — but
// the kill contract is that its requests are DENIED with KILL_SWITCH, not a bare 404 hiding why
// the session vanished. The kill store outlives the reaped registry entry, so consult it: a
// killed id (or an active global kill) renders the deny the dispatcher's kill gate would have
// given had the session still existed. A genuinely unknown, unkilled id still 404s. Handled
// here rather than via resolveSessionForRoute (the GET/SSE path) because only this
// request/notification framing can carry a JSON-RPC KILL_SWITCH body.
//
// It is the ONE host-message arm that negotiates no protocol revision, and its own function so
// that exception is named in the entry-point table rather than hidden inside a branch of a
// longer one (see hostMessageDispositions in gate_order_test.go). There is nothing to negotiate
// AGAINST: the leg it would check the declaration against is a session this proxy never
// established, so the record it writes carries no protocol_revision — the same "absent means
// nothing was negotiated" convention every pre-session record follows.
//
// sessionID is the raw, unverified client-supplied header (unlike every other CheckKill call
// site's, which comes from an established session). Stamping it into the signed session_id
// field would let anyone forge kill records against an arbitrary session id; claimedSession(r)
// keeps session_id empty and preserves it only as details.claimed_session_id.
//
// It is also the only CheckKill argument bounded by nothing but Go's ~1 MiB header cap, and the
// value flows into the kill store's key, so an unauthenticated POST on an open bind would mint a
// ~1 MiB Redis key per request. An over-length id is therefore BLANKED rather than skipping the
// check: the session is the only dimension this id names, while the global, agent and token
// dimensions are resolved from the request's own claims (killSubjectFromContext) and must still
// answer — skipping would let a caller pad the header to turn an emergency stop's KILL_SWITCH deny
// into a silent 404 and write nothing on the tape, during the incident the tape exists for.
// Blanking is the shape the sessionless arms already pass (CheckKill(ctx, "")), and it loses no
// session kill: an id over maxClaimedSessionIDLen names no worker this proxy can mint, which
// maxWorkerKeyBytes holds by construction rather than by assumption.
func (p *HTTPProxy) denyUnresolvedSession(w http.ResponseWriter, r *http.Request, route *UpstreamRoute, sessionID string, msg mcp.RPCMsg) {
	killSubject := sessionID
	if len(killSubject) > maxClaimedSessionIDLen {
		killSubject = ""
	}
	deny := route.pdp.CheckKill(r.Context(), killSubject)
	if deny == nil {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	if msg.IsRequest() {
		writeJSONMsg(w, recordKillDenial(r.Context(), p.preSessionKillRecorder(route), deny, msg, claimedSession(r)))
		return
	}
	// Fire-and-forget: record the drop and ack with a bodyless 202. Only the LEG is chosen
	// here — recordKillDrop names the message itself through auditIdentity, which already
	// labels a response "server-response"; the leg is what an operator tells the two drop
	// SITES apart by, and it is the half a message cannot carry.
	recordKillDrop(r.Context(), p.preSessionKillRecorder(route), deny, claimedSession(r), msg, killDropLeg(msg))
	w.WriteHeader(http.StatusAccepted)
}

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

// recordSessionGateDeny writes the fail-closed deny record for a failed session gate, tagged with
// the leg it was taken on. Shared by enforceSessionGates and handleMCPDelete so the record shape
// lives once alongside the shared verdict.
//
// The leg is a transportLeg, not the bare string it used to be: it lands in the same `transport`
// detail two typed enums already wrote to, and a bare parameter is what let one leg be spelled
// twice for what an operator filters as one value.
//
// Rate-limited, which it did not used to be. The exemption rested on session ids being
// unguessable per-session UUIDs handed only to their creator, so driving this record needed a
// live victim id — a materially higher bar than the zero-session flood catAudience closes.
// Session creation on the first enforced request ended that: a declaring peer's worker id is
// DERIVED from its own claims (issuer, subject, agent id), so a caller who can name those for a
// victim can address that worker and drive one record per attempt holding no session at all. The
// premise was true when it was written and was falsified by a change three files away, which is
// why the reasoning is kept here rather than replaced — the next id scheme has to re-argue it.
//
// rec is the metered recorder; a nil one means the bucket refused this write, and the refusal
// still happens either way. What the bucket bounds is the tape.
//
// identifier is what the record may CLAIM, and it is the caller's to supply: this gate runs before
// dispatch and before any PDP, so the POST leg passes auditIdentity's answer while the GET and
// DELETE legs — which carry no method at all — name nothing. Threading the method into both fields
// let a caller who can address a victim's worker choose the target: the worker id is DERIVED from
// claims (issuer, subject, agent id), so a POST body naming `tools/call` planted
// `target_type: tool, target: tools/call` on the signed tape under that session's id, for a refusal
// no policy produced — and AUTHORIZATION_FAILED is a policy class, so `eunox suggest` mines it.
func recordSessionGateDeny(ctx context.Context, rec auditRecorder, sessionID, identifier, method string, leg transportLeg, gate sessionGate) {
	if rec == nil {
		return
	}
	// Through mergeAuditDetails rather than assigning in: transportLegDetail answers nil for an
	// unset leg, and a nil map is a panic to write into on a refusal path.
	details := transportLegDetail(leg)
	if gate.reason != "" {
		details = mergeAuditDetails(details, map[string]interface{}{"reason": gate.reason})
	}
	rec.RecordDeny(ctx, sessionID, identifier, method, gate.code, gate.conditionType, details, false)
}

// enforceSessionGates is the verdict-plus-record half used by the POST and SSE-GET
// paths: runs sessionGateVerdict and, on denial, writes the record and returns the gate; on
// admission it notes the credential the message presented for the revocation-reclaim sweep.
// Kept separate from the check-only verdict so DELETE can run it under p.mu and render its
// own 403 + record off the same predicate.
//
// It runs BEFORE revision negotiation, so its record names none (the exception is declared in
// dispatch.go's gate order and in gate_order_test.go's dispositionPrologue). Negotiating first
// would read and refuse against the VICTIM session's revision for a caller who has not cleared
// the binding — an oracle for that revision, recorded under that session's id as fact.
func (p *HTTPProxy) enforceSessionGates(ctx context.Context, route *UpstreamRoute, sess *httpSession, sessionID, identifier, method string, leg transportLeg) (sessionGate, bool) {
	gate, denied := route.sessionGateVerdict(ctx, sess)
	if denied {
		recordSessionGateDeny(ctx, p.sessionGateRecorder(route), sessionID, identifier, method, leg, gate)
		return gate, true
	}
	// An ADMITTED message's credential joins the session's reclaim set here rather than at each
	// leg, because this function's caller set IS the rule: it is what the POST and SSE-GET legs
	// call and what handleMCPDelete deliberately does not (it runs the two verdict halves itself
	// under p.mu), so "every admitted host message, below the gates, never a DELETE" holds by
	// construction instead of by two call sites remembering it. See httpSession.noteLiveTokenID.
	sess.noteLiveTokenID(pdp.JWTClaimsPtr(ctx))
	return gate, false
}

// answerSessionGateRefusal renders a refused session gate on the POST leg, in the framing the
// message allows.
//
// Fire-and-forget (a notification or response, including an id-less initialize notification
// carrying a victim's Mcp-Session-Id): ack the drop with a bodyless 202, matching the kill-switch
// notification path — the host cannot act on a body, and a JSON-RPC error body would omit the id
// (RPCMsg.ID is json:"id,omitempty") under an implicit 200, indistinguishable from success to a
// status-only client.
//
// A dropped RESPONSE unblocks its initiator only when the sender is this session's own owner:
// this gate refuses the SENDER, and answering on an unauthorized one's message would abort the
// real owner's pending reply. See unblockGateRefusedServerReply for both halves of that rule.
func answerSessionGateRefusal(ctx context.Context, w http.ResponseWriter, sess *httpSession, gate sessionGate, msg mcp.RPCMsg) {
	if msg.IsRequest() {
		writeJSONMsg(w, denialResult(msg.ID, gate.code, gate.conditionType, msg.Method, ""))
		return
	}
	sess.unblockGateRefusedServerReply(ctx, msg)
	w.WriteHeader(http.StatusAccepted)
}

// awaitServableWorker holds a host-initiated action until the worker it names has stopped
// COMING UP, and reports whether it may be served on. A false answer means the leg is finished
// with this request: the caller has been answered, or — when the caller's own context ended —
// there is nobody left to answer and nothing to say (see refuseUnestablishedWorker).
//
// The wait itself is awaitEstablished's; this adds the two things a SERVING leg owes around it,
// so neither leg has to remember either. The refusal is shared so the legs cannot disagree about
// what a worker that did not survive establishment costs a caller, or about what its id is on the
// tape. And the write deadline is re-armed HERE when the wait actually blocked, covering both
// outcomes because the time was spent either way: the entry window was armed before a wait that
// spans the establishment budget — plus, on the teardown that makes it fail, that teardown's own
// two sequential --shutdown-timeout bounds — so every exit below it was writing against a window
// already spent, and the host got a reset instead of its answer. Skipped when nothing was waited
// for, which is every request on an established worker: a syscall per request to re-arm a window
// that has not moved.
func (p *HTTPProxy) awaitServableWorker(w http.ResponseWriter, r *http.Request, route *UpstreamRoute, sess *httpSession, msg mcp.RPCMsg, leg transportLeg) bool {
	waited := sess.initInProgress.Load()
	outcome := p.awaitEstablished(r.Context(), sess)
	if waited && outcome != waiterGone {
		rearmWriteDeadlineForTeardown(w, p.shutdownMs)
	}
	switch outcome {
	case workerServable:
		return true
	case workerGone:
		p.refuseUnestablishedWorker(r.Context(), w, route, sess, msg, leg)
	case waiterGone:
		// Answered nothing and recorded nothing: see establishmentOutcome.
	}
	return false
}

// refuseUnestablishedWorker answers a leg whose worker stopped coming up without staying
// servable — a failed startup drift check tears it down, and a kill landing in the window
// reclaims it at the establishment edge.
//
// NOT denyUnresolvedSession, whose subject is claimedSession(r) because its id resolved nothing:
// here the id RESOLVED a live registration and cleared both session gates, so verifiedSession is
// the honest subject, and stamping it is what lets an operator join this refusal to the traffic
// that preceded it. That helper would also have named nothing at all on the declaring re-entry,
// which carries no session header for a claim to be read out of.
//
// Reached only for workerGone. A waiter whose own context ended never arrives here at all — that
// rule rides establishmentOutcome rather than being re-asked as a guard on this side, since a
// second reading of "is the caller still there" is where the two answers drift apart.
//
// Each leg gives the answer it ALREADY gives for a worker that is gone, rather than a new one:
// the POST the retryable JSON-RPC error its teardown race produces one gate further on, the GET
// resolveSessionForRoute's 404 — which is also the re-initialize signal an old-revision host
// reads, and inventing a retryable status there would have told it to keep dialling a UUID that
// can never be registered again.
//
// No server-initiated request is unblocked here. This shares the kill drop's exception: the
// worker is being torn down and its tracked ids go with it, so the answer is owed by that
// teardown rather than by this refusal.
func (p *HTTPProxy) refuseUnestablishedWorker(ctx context.Context, w http.ResponseWriter, route *UpstreamRoute, sess *httpSession, msg mcp.RPCMsg, leg transportLeg) {
	// An established session's kill record is unmetered, as its sibling arms are: this caller
	// cleared the route binding and both session gates, so it is not the zero-session flood the
	// pre-session bucket bounds.
	rec := asRecorder(route.sink)
	deny := route.pdp.CheckKill(ctx, sess.id)
	if leg == legSSEGet {
		if deny != nil {
			recordKillDrop(ctx, rec, deny, verifiedSession(sess.id), msg, leg)
			http.Error(w, "session terminated", http.StatusForbidden)
			return
		}
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	if !msg.IsRequest() {
		// Fire-and-forget: acked bodyless, for the reason every other drop on this leg is —
		// the host cannot act on a body it is not allowed to be sent. The leg recorded is the
		// DROP-leg vocabulary's, never the session-gate constant this function was reached
		// under: the drop leg is what an operator tells a dropped notification from a dropped
		// server response by, and it is the half a message cannot carry.
		if deny != nil {
			recordKillDrop(ctx, rec, deny, verifiedSession(sess.id), msg, killDropLeg(msg))
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if deny != nil {
		writeJSONMsg(w, recordKillDenial(ctx, rec, deny, msg, verifiedSession(sess.id)))
		return
	}
	// Word for word the answer the teardown race below gives: it is the same fact — the worker
	// went away under a request that had already resolved it — and a JSON-RPC client dispatching
	// on the envelope can correlate it to its own request id.
	writeJSONMsg(w, mcp.ErrorResponse(msg.ID, jsonRPCCodeServerBusy, "eunox: session torn down; retry"))
}

// killDropLeg names the HTTP drop site for a fire-and-forget host message, in the vocabulary
// recordKillDrop's records are read in. Shared by every arm that drops one, so the two sites
// cannot label the same framing differently.
func killDropLeg(msg mcp.RPCMsg) transportLeg {
	if msg.IsResponse() {
		return legHTTPServerResponse
	}
	return legHTTPNotification
}

// sessionGateRecorder resolves the metered recorder for a session-gate refusal.
//
// Bounded on the ROUTE's bucket, not the addressed session's: the session named here is the
// caller's TARGET rather than the caller's own — that is the whole point of the gate — so
// charging it would let an attacker spend a victim's share and silence the victim's own records.
func (p *HTTPProxy) sessionGateRecorder(route *UpstreamRoute) auditRecorder {
	return p.routeRefusalLimits().recorders(refusalSink(p, route)).forCategory(catSessionGate)
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
	if _, denied := p.enforceSessionGates(r.Context(), route, sess, sessionID, "", "", legSSEGet); denied {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// readUpstream is started BEFORE the session-start drift check runs, so a subscriber
	// registered mid-establishment receives the not-yet-vetted upstream's notifications — the
	// FM-5 rug-pull this proxy exists to catch, delivered as though it had been checked. Below
	// the gates and above the kill check for handleSessionPost's reasons; the refusal consults
	// the kill store itself, so this placement costs the leg no kill record.
	if !p.awaitServableWorker(w, r, route, sess, mcp.RPCMsg{}, legSSEGet) {
		return
	}
	// Kill-switch check before serving: a killed (or globally emergency-stopped) session
	// must not OPEN an SSE stream. A targeted kill tears the session down proactively, but
	// this still matters for a GLOBAL stop (no session named) and a re-open racing teardown.
	if deny := route.pdp.CheckKill(r.Context(), sessionID); deny != nil {
		recordKillDrop(r.Context(), asRecorder(route.sink), deny, verifiedSession(sess.id), mcp.RPCMsg{}, legSSEGet)
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
			// The same wall-clock re-anchor the keepalive arm applies, on the arm that moves
			// DATA: expTimer is monotonic, so after a host suspend this arm would otherwise keep
			// delivering to an expired token until the next keepalive tick. Fail the delivery
			// rather than dropping it, for the reason the write-failure arm below does: this
			// message is already consumed, so removeSubAndDrain will not recover it.
			if !tokenExpiresAt.IsZero() && !time.Now().Before(tokenExpiresAt) {
				sess.failServerRequestDelivery(r.Context(), msg, "proxy: token expired before delivering server-initiated request")
				return
			}
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
			recordSessionGateDeny(r.Context(), p.sessionGateRecorder(route), sessionID, "", "", legHTTPDelete, gate)
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
		JTI       string `json:"jti"`
		All       bool   `json:"all"`
	}
	// closedSchema, because this body's members select WHICH kill runs: it rejects a trailing
	// JSON token (a smuggled {"all":true} after a legitimate {"sessionId":"..."}) and the two
	// ways the same smuggling fits INSIDE one valid object — an ambiguous member name, and an
	// unmodelled one. Without all three the kill actually executed could differ from what a
	// body-only reviewer would expect. /control/kill has no route concept, so nil: its
	// refusal stays on the proxy-wide sink.
	if !p.decodeStrictJSON(w, r, &body, "invalid request body", nil, closedSchema) {
		return
	}
	// Same rationale as the trailing-token refusal one object out: running the All arm and
	// discarding sessionId turns a body a reviewer reads as a targeted kill into a
	// deployment-wide stop, and the record then names a scope the body only half-describes.
	// Fail-safe in effect, but the endpoint's contract is that the kill executed is the one
	// the body names, so an incoherent body is refused rather than resolved by field order.
	//
	// Counted rather than compared pairwise: with three targets the pairwise form is three
	// conditions that must agree, and the one somebody forgets is a body naming two
	// dimensions that silently runs whichever arm sorts first.
	named := 0
	for _, present := range []bool{body.All, body.SessionID != "", body.JTI != ""} {
		if present {
			named++
		}
	}
	if named > 1 {
		http.Error(w, "sessionId, jti and all are mutually exclusive; pass exactly one", http.StatusBadRequest)
		return
	}
	if body.All {
		// Propagate a kill-store write failure (fail closed): returning {"ok":true} on a
		// failed emergency stop would leave the operator believing the system is safe. Which
		// errors are that failure, and which mean the stop landed and only its notification
		// did not, is killWriteLanded's question.
		if err := p.ks.ActivateGlobal(r.Context()); !p.killWriteLanded("activation", err) {
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
		p.teardownAllSessionsForGlobalKill() //nolint:contextcheck // teardown path: close()'s upstream session-termination DELETE intentionally uses a detached, bounded background context — binding it to r.Context() would cancel the teardown the instant this response is written. Same rationale as the handleMCPDelete close() site.
		p.writeKillResponse(w, killScopeAll, killDimensionGlobal)
		return
	}
	if body.JTI != "" {
		// Bounded for maxClaimedSessionIDLen's reason one field over: an uncapped id flows
		// into the Redis key, the signed record's scope, and the response echo.
		if len(body.JTI) > maxClaimedSessionIDLen {
			http.Error(w, "jti is too long to name a token", http.StatusBadRequest)
			return
		}
		if err := p.ks.RevokeJTI(r.Context(), body.JTI); !p.killWriteLanded("token revocation", err) {
			http.Error(w, "kill switch token revocation failed", http.StatusInternalServerError)
			return
		}
		p.recordKillActivated(r, body.JTI, killDimensionJTI)
		// No local teardown to do, and that is the dimension's nature rather than an
		// omission: a token id names a CREDENTIAL, not a connection, so which of this
		// proxy's sessions presented it is not a question the endpoint can answer without
		// re-deciding every one. The kill switch's own revocation delivery does it instead
		// — reclaimOnRevocation re-asks ShouldBlock about each held session, which is
		// exactly the "revocation is a trigger, not a work list" contract, and it covers
		// sessions on sibling instances that this handler could never reach.
		p.writeKillResponse(w, body.JTI, killDimensionJTI)
		return
	}
	if body.SessionID == "" {
		http.Error(w, "sessionId, jti or all required", http.StatusBadRequest)
		return
	}
	// Refused rather than sanitized, and refused HERE rather than at each consumer. The body is
	// capped at maxRequestBodyBytes, so without this an id of ~4 MiB flows into the Redis key,
	// the signed RecordAllow's details.scope, and the response echo — the rule
	// maxClaimedSessionIDLen states for the header form of exactly this value, which is
	// attacker-influenceable there and merely absurd here. A control-token holder is trusted to
	// stop the proxy, not to choose how many megabytes land on the tape; and an over-length id
	// names no session this proxy ever minted, so refusing loses nothing a kill could have done.
	if len(body.SessionID) > maxClaimedSessionIDLen {
		http.Error(w, "sessionId is too long to name a session", http.StatusBadRequest)
		return
	}
	if err := p.ks.KillSession(r.Context(), body.SessionID); !p.killWriteLanded("session kill", err) {
		http.Error(w, "kill switch session kill failed", http.StatusInternalServerError)
		return
	}
	// Recorded before the teardown, same ordering as the global path above.
	p.recordKillActivated(r, body.SessionID, killDimensionSession)
	rearmWriteDeadlineForTeardown(w, p.shutdownMs)
	p.evictSessionStreams(body.SessionID)
	// Proactively tear the killed session down instead of relying on the idle reaper,
	// which does not run when sessionIdleTimeoutMs is 0 — see teardownSessionByID.
	p.teardownSessionByID(body.SessionID) //nolint:contextcheck // teardown path: close()'s upstream session-termination DELETE intentionally uses a detached, bounded background context. Same rationale as the handleMCPDelete close() site.
	p.writeKillResponse(w, body.SessionID, killDimensionSession)
}

// killWriteLanded reports whether a kill-store write took effect, and writes the operator
// line for the two ways it may not have fully done so.
//
// killswitch.ErrPublishFailed is the reason this is not a plain err != nil: the durable write
// LANDED and only the real-time notification to other instances was lost, so the stop is in
// force on this proxy and every replica converges on its next reconcile tick. Answering 500
// there would tell the operator their emergency stop failed when it did not — the same
// mis-report `eunox kill --redis-addr` made, reached through the other transport, and the
// direction that invites concluding the system is unstopped. The teardown below still runs,
// which is the local half of the kill and the half this response is really about.
//
// The line stays unmetered for the reason its declaration states: /control/kill requires the
// control token, so no peer can drive it.
func (p *HTTPProxy) killWriteLanded(what string, err error) bool {
	switch {
	case err == nil:
		return true
	case errors.Is(err, killswitch.ErrPublishFailed):
		// The tick is named by its FLAG, not by a duration: convergence happens on each OTHER
		// instance's own --killswitch-reconcile-interval, which this process does not know and
		// which is not this process's default merely because the default is what it would print.
		_, _ = fmt.Fprintf(p.errOut(), "[eunox] kill switch %s is written durably, but real-time propagation to other instances failed: %v. Each converges on its next reconcile tick (--killswitch-reconcile-interval).\n", what, err)
		return true
	default:
		_, _ = fmt.Fprintf(p.errOut(), "[eunox] kill switch %s failed: %v\n", what, err)
		return false
	}
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
// {"ok":true,"killed":<target>,"dimension":<global|session|jti>} success body. Every route
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
	// killDimensionJTI is the per-credential dimension. Unlike a session tombstone it does
	// not expire, so it is the one dimension this endpoint writes that an operator must
	// explicitly lift (`eunox kill --revive --jti`, Redis only).
	killDimensionJTI = "jti"
)

// sessionlessLeg is the leg a pre-session arm negotiates against. Nothing these arms answer
// reaches an upstream, so the only question is what CONTEXT the message is held to — and that
// is per-arm rather than a property of being sessionless (ADR-0004 §Addendum 2026-08-23).
//
// An `initialize` arm asserts the handshake revision, because answering `initialize` IS the
// negotiation: a declaration naming any other revision there genuinely contradicts the context
// the message is establishing, and is refused UNSUPPORTED_PROTOCOL_VERSION.
//
// Every OTHER pre-session message asserts nothing, and its declaration ESTABLISHES the context
// instead of being checked against one. A first message cannot FLIP a context — it opens one —
// so holding it to the handshake revision refused a declaring peer for contradicting a context
// it had never opened, which is why a 2026-07-28 host was unservable over HTTP at all: the
// refusal landed above session creation, so nothing could reach the path that would mint it.
// The mid-context flip refusal is untouched and governs from the second message on, which is
// where a peer probing for the more permissive table actually lives; and omission still
// resolves to capability.DefaultRevision, so nothing widens by leaving a declaration out.
//
// This is also what narrows a divergence between the transports to the `initialize` arms alone:
// stdio has no pre-session context to assert (a peer there need never handshake), so the same
// stray bytes resolve, are dropped by the fail-closed routing default as UNROUTABLE_METHOD, and
// (see StdioProxy.negotiateHostRevision) do not pin the connection on their way out.
func sessionlessLeg(msg mcp.RPCMsg) hostLeg {
	if msg.Method == mcp.MethodInitialize {
		return hostLeg{contextRev: handshakeRevision}
	}
	return hostLeg{}
}

// leg is the established session's answer to the same question.
func (s *httpSession) leg() hostLeg {
	return hostLeg{contextRev: s.hostRev, upstreamRev: s.upstreamRev, sessionID: s.id}
}

// negotiateHostRevision resolves the MCP protocol revision one host message is dispatched
// under, checked against the revision the leg's context was opened at. Its caller stamps the
// result onto the request context immediately, and that context is the ONE carrier from there
// down — nothing else threads the revision. ok=false means the refusal has already been
// written: -32022 plus its record for a request, and for a notification a recorded drop with a
// bodyless 202, since JSON-RPC forbids replying to one.
//
// This is the first gate every DISPATCHED host message passes — ahead of the kill check,
// deliberately; see the gate order in dispatch.go for why, for the labelling exception it costs,
// and for the two session gates on the established-POST leg that precede it without dispatching
// anything.
//
// Every arm that DISPATCHES a host message calls it — the established session, the
// session-creating `initialize`, and the id-less one — because the two sessionless arms
// previously restated the same three lines each, and a restated gate is one that drifts: the
// id-less arm did not negotiate at all until it was noticed, and recorded either the wrong
// code or nothing while stdio recorded UNSUPPORTED_PROTOCOL_VERSION for the same bytes.
//
// denyUnresolvedSession is the one refusal that does not: it answers a session id this proxy
// never established, so there is no context to negotiate against and it records KILL_SWITCH
// with no revision. That exception is declared in gate_order_test.go's dispositionPrologue,
// which enumerates the arms rather than the calls — a guard phrased as "who may call the
// primitives" is blind to an arm that calls neither, which is how an entry point came to
// negotiate nothing at all.
func (p *HTTPProxy) negotiateHostRevision(w http.ResponseWriter, r *http.Request, route *UpstreamRoute, sess *httpSession, msg mcp.RPCMsg) (capability.Revision, bool) {
	// One value for both halves — the leg's revisions and the leg's peer — so a caller cannot
	// supply a session's facts while its blocked initiator goes unanswered. An established
	// session IS its own peer, which is what keeps this off the allocating path: it holds the
	// route and the proxy the recorder resolves through, and it is what answers the upstream
	// request a refused host RESPONSE would have completed (a protocol refusal is not an
	// emergency stop, and eunox can answer at its own revision without relaying anything the
	// host said).
	//
	// The pre-session arms pass a nil session; what context they hold the message to is
	// sessionlessLeg's question, and it depends on the message rather than on the arm. Branched
	// rather than built unconditionally, since evaluating the sessionless peer's literal would
	// put its allocation back on every established request.
	leg, peer := sessionlessLeg(msg), hostGatePeer(nil)
	if sess != nil {
		leg, peer = sess.leg(), sess
	} else {
		peer = &sessionlessGatePeer{proxy: p, route: route}
	}
	rev, refusal, ok := hostMessageGate{leg: leg, peer: peer}.negotiate(r.Context(), msg)
	if !ok {
		// writeDispatchResult, not a second spelling of it: "a zero RPCMsg is acked bodyless,
		// never written as a `{"jsonrpc":""}` frame" is one rule on this transport, and the
		// refusal is one more caller of it.
		writeDispatchResult(w, refusal)
		return rev, false
	}
	// The routing headers are checked HERE — inside the adapter every POST arm already calls —
	// rather than at those three call sites, so a fourth arm cannot forward a request whose
	// halves disagree by forgetting to ask. It runs AFTER negotiation because the check is
	// revision-gated and the revision is what negotiation resolves; it runs BEFORE the
	// dispatcher's own gates because a disagreeing pair is a fact about the HTTP envelope, not
	// a verdict about the call, and the message must not reach an upstream to find out.
	if err := checkRoutingHeaders(rev, r, msg); err != nil {
		ctx := capability.WithProtocolRevision(r.Context(), rev)
		writeDispatchResult(w, refuseHeaderMismatch(ctx,
			p.headerMismatchRecorder(route), headerRefusalSessionID(sess), msg, err))
		return rev, false
	}
	return rev, true
}

// headerRefusalSessionID names the session a header refusal is recorded against, or "" for a
// POST that has not resolved one. Read off the SESSION rather than the header the peer sent:
// this refusal is about a peer's headers disagreeing with its body, so a claimed-but-unresolved
// session id on the record would be one more caller-supplied string in a refusal that already
// exists because the caller's strings disagreed.
func headerRefusalSessionID(sess *httpSession) string {
	if sess == nil {
		return ""
	}
	return sess.id
}

// headerMismatchRecorder returns the route's sink when the header-mismatch bucket admits a
// record now, and nil when it does not — refuseHeaderMismatch writes nothing for a nil recorder,
// so the wire refusal is unaffected and only the tape write is bounded.
//
// Bounded for catRevision's reason and at the same cheapness: a POST carrying a disagreeing
// `Mcp-Method` is refused at the envelope, before the kill check, holding no session slot and
// contacting no upstream, so an unauthenticated peer drives one record per frame. Suppressed
// refusals fold into the next admitted record rather than vanishing.
func (p *HTTPProxy) headerMismatchRecorder(route *UpstreamRoute) auditRecorder {
	return p.routeRefusalLimits().recorders(refusalSink(p, route)).forCategory(catHeaderMismatch)
}

// refusalSink picks the tape an envelope-level refusal is written to: the route's, which stamps
// the route name and policy version, falling back to the proxy's for a refusal with no route in
// scope.
//
// One home because two refusals now need it and a third will: a per-site copy of this selection
// is how a record comes to name a different tape than its own leg's other records do.
func refusalSink(p *HTTPProxy, route *UpstreamRoute) auditRecorder {
	switch {
	case route != nil:
		return asRecorder(route.sink)
	case p != nil:
		return asRecorder(p.sink)
	}
	return nil
}

// sessionlessGatePeer is the shared prologue's peer for HTTP's two PRE-SESSION arms — the
// session-creating `initialize` and the id-less POST — which address a route but have no session.
//
// The one place this wiring allocates, and deliberately: those arms have no long-lived value that
// knows both the proxy and the route, and a message that establishes a session is not on the path
// the per-request cost is measured on. See hostGatePeer.
type sessionlessGatePeer struct {
	proxy *HTTPProxy
	route *UpstreamRoute
}

// revisionRefusalRecorder resolves the refusal's recorder with no session to name, which is the
// honest subject here: nothing has been established for this message to belong to.
func (s *sessionlessGatePeer) revisionRefusalRecorder() auditRecorder {
	return s.proxy.revisionRefusalRecorder(s.route)
}

// unblockRefusedServerReply answers nothing: a pre-session message reaches no upstream, so there
// is no blocked initiator for its refusal to owe.
func (*sessionlessGatePeer) unblockRefusedServerReply(context.Context, mcp.RPCMsg) {}

// routeHostServerResponse routes a host POST that is neither request nor notification: a
// response to a server-initiated request the proxy broadcast, which must reach the blocked
// upstream. Only responses whose ID the proxy forwarded are routed (take consumes the
// tracked ID); anything else is ignored, and the caller acks either way.
//
// Split out of handleSessionPost to keep that function within its complexity bound.
//
// Reports whether it ACTED on the message — routed it, or recorded its drop. False means the id
// was never one this proxy issued and nothing happened, which is what lets the caller neither
// defer idle reaping nor pay a revocation lookup for it: kill is taken as the caller's THUNK
// for that reason, and is resolved only past the take below.
func (p *HTTPProxy) routeHostServerResponse(ctx context.Context, route *UpstreamRoute, sess *httpSession, kill func() *capability.EnforceResponse, msg mcp.RPCMsg) bool {
	if !msg.IsResponse() {
		return false
	}
	if _, held := sess.serverReqs.take(mcp.MsgKey(msg.ID)); !held {
		return false
	}
	if deny := kill(); deny != nil {
		// A kill doesn't tear the upstream down; its blocked server-initiated request is
		// intentionally left unanswered and reclaimed later by the idle reaper's hard
		// ceiling. Record the dropped reply so it's visible on the tape.
		recordKillDrop(ctx, asRecorder(route.sink), deny, verifiedSession(sess.id), msg, legHTTPServerResponse)
		return true
	}
	// Through the shared seam for the nil-writer disposition alone: this relays the host's OWN
	// reply, having already taken the id that made it routable.
	//
	// The take is also what makes a FAILED relay final — no later path can route this reply, and no
	// second one is coming — so it destroys a reply the host actually produced. That is the one
	// disposition on this leg whose entire account used to be a stderr line; the take stays above
	// the writer check for the reason unblock's does (an entry nothing can reclaim eventually
	// displaces a live request), so the debt is paid on the tape instead — by the seam itself.
	//
	// The session's claims, as failServerRequestDelivery attaches them: the sink reads agent / task
	// / user identity off the context, and this POST's context never carried them — so without this
	// the destroyed-reply records drop out of any per-agent grouping their undelivered siblings
	// appear in.
	sess.unblocker().relay(sess.withSessionClaims(ctx), msg)
	return true
}

// revisionRefusalRecorder returns the route's sink when the revision-refusal bucket admits a
// record now, and nil when it does not — refuseHostRevision writes nothing for a nil
// recorder, so the wire refusal is unaffected and only the tape write is bounded. Suppressed
// refusals fold into the next admitted record via rolledUpRecorder, mirroring the two
// pre-session siblings: catRevision is the cheapest refusal an attacker can force, so a
// dropped tally here is exactly the flood volume an incident responder would under-count.
//
// Nil-limiter tolerance mirrors recordRefusal's: a proxy built without one (tests) records
// unbounded rather than not at all.
func (p *HTTPProxy) revisionRefusalRecorder(route *UpstreamRoute) auditRecorder {
	// p is nil only on a bare-struct-literal session (as tests build) reaching this through
	// httpSession.revisionRefusalRecorder; the limits below already tolerate one, and a refusal
	// with no recorder still reaches its peer on the wire.
	var rec auditRecorder
	switch {
	case route != nil:
		rec = asRecorder(route.sink)
	case p != nil:
		rec = asRecorder(p.sink)
	}
	// The route selects the SINK above (it stamps the route name and policy version); the
	// BUDGET below is the proxy's, since routeRefusalLimits takes neither a route nor a session
	// — one notice table and one category table serve every leg.
	return p.routeRefusalLimits().recorders(rec).forCategory(catRevision)
}
