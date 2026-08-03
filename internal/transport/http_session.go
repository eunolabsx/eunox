// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// httpSession lifecycle: creation, the session registry and idle reaper,
// upstream I/O, and SSE notification broadcast.

package transport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
)

// httpSession is one client session.  In local mode it owns an upstream
// subprocess; in remote mode it communicates with a remote MCP HTTP server.
type httpSession struct {
	id    string
	proxy *HTTPProxy
	// route is the upstream this session is bound to. Immutable after creation: set
	// once in the newSession/newRemoteSession struct literal BEFORE the session is
	// published into p.sessions under p.mu, and never reassigned or zeroed (close()
	// does not touch it). The publish-under-lock establishes a happens-before with
	// every getSession read, and the write-once-then-immutable discipline makes the
	// lock-free cross-route ownership checks in handleMCPPost/handleMCPGet
	// (sess.route != route) safe by construction — a concurrent DELETE can remove the
	// session and close() it, but cannot mutate route out from under the comparison.
	// Keep it immutable: making it mutable would reintroduce a lock-free read race.
	route *UpstreamRoute

	// Local subprocess fields (nil in remote mode).
	upCmd    *exec.Cmd
	upIn     io.WriteCloser
	upWriter *mcp.MsgWriter
	upReader *mcp.MsgReader

	// Remote HTTP upstream fields (nil in local mode). upHTTPClient is set only by
	// newRemoteSession, so a non-nil upHTTPClient is the authoritative "this session
	// is remote" test; the endpoint itself is read from the immutable
	// route.upstreamURL (see mcpEndpointURL), never copied onto the session.
	upHTTPClient   *http.Client
	upstreamSessID string // Mcp-Session-Id returned by the remote upstream

	// pendingMu guards byUpstreamID, hostToUp, and upstreamSeq.
	pendingMu sync.Mutex
	// byUpstreamID routes subprocess-upstream responses back to the waiting caller,
	// keyed by the proxy-generated nonce. A response with a stale nonce (its caller
	// already timed out and removed the entry) has nowhere to land, so a late
	// response can never be misrouted into a later request reusing the same host ID.
	byUpstreamID map[string]chan upstreamResult
	// hostToUp maps a live subprocess-upstream request's host ID to the nonce the
	// proxy put on the wire, so a host notifications/cancelled can translate its
	// params.requestId to the id the upstream saw (a verbatim cancel would name an
	// id the upstream never received and be a no-op). Only the subprocess path
	// nonce-rewrites; the remote-HTTP path forwards host ids unchanged.
	hostToUp map[string]*json.RawMessage
	// upstreamSeq is the monotonic nonce source for upstream IDs.
	upstreamSeq uint64

	// serverReqs tracks the IDs of server-initiated requests (e.g.
	// sampling/createMessage, roots/list) broadcast to the host over SSE and
	// awaiting a response. The host POSTs its response (same ID) back to /mcp;
	// handleMCPPost consults the tracker to route it to the upstream rather than
	// drop it (which would hang the upstream).
	serverReqs serverReqTracker

	upstreamCaps          map[string]interface{}
	upstreamServerVersion string // version from the upstream initialize serverInfo response
	upstreamInstructions  string // instructions from the upstream initialize response
	idCounter             int64

	// claims holds the JWT claims validated on the session's initialize request,
	// or nil when no JWT was presented. Server-initiated decisions (e.g.
	// sampling/createMessage) arrive on the upstream reader with no host request in
	// scope, so they are attributed to these claims and their audit records carry
	// the session's agent_id/task_id.
	claims *pdp.JWTClaims

	// clientIP is the IP of the client that opened the session, captured at
	// initialize. It is the source IP an ipRange condition on the sampling opt-in
	// evaluates against, since server-initiated sampling has no host request in scope.
	clientIP string

	// There is deliberately no per-session decision mutex here. The decision turn is keyed
	// on the state ANCHOR and handed out by the route (UpstreamRoute.decideGates), because
	// under task-anchored state two sessions share one key and a per-session lock would not
	// span it. Under the default session anchoring the route's gate for this session's key
	// IS a per-session mutex, so nothing changed for that deployment. See anchor_gate.go.
	//
	// The registry is the ALWAYS-CORRECT path and the gate below is a CACHE of one entry in
	// it: going back through the route's registry per request cost a route-wide mutex, a map
	// insert and a map delete on every enforced call — the refcount fell to zero the moment a
	// non-overlapping request finished, so ordinary sequential traffic re-created the same
	// entry per call on the microsecond decision path.
	//
	// decideAnchor is the anchor decideGate was resolved for, and it is what makes the cache
	// USABLE: every request resolves its own anchor and compares it to this one, taking the
	// cached gate on a hit and falling through to the registry on a miss. That comparison is
	// the whole of the correctness argument. The alternative — deciding from the route's
	// taskAnchored bit that the anchor "cannot change" — is a second, independent reading of
	// the question enforcement.ResolveStateAnchor exists to answer: a third anchor kind
	// (an agent id, a conversation, a delegation chain) breaks every caller of the resolver at
	// compile time, but a hand-written restatement of its outcome compiles untouched and the
	// session then keeps serving turns on a gate the per-request resolver no longer reaches.
	// Comparing the resolutions is correct for any number of anchor kinds by construction, and
	// it extends the fast path to a task-anchored session that stays on one task — which the
	// bool could not do.
	//
	// nil on a non-serialized route (no registry at all) and on a test-assembled session that
	// never registered; both fall back to the registry path, which is a no-op for the former.
	decideAnchor enforcement.StateAnchor
	decideGate   *anchorGate
	// dropDecideGate releases the reference above at teardown, so a long-lived gateway does
	// not accumulate one gate per session it has ever served. nil when none is held, and
	// idempotent. Called from releaseSessionState — the funnel that runs on EVERY teardown,
	// including the natural upstream exit that close() deliberately does not cover.
	dropDecideGate func()

	notifMu   sync.Mutex
	notifSubs []chan mcp.RPCMsg

	// droppedNotifs counts notifications dropped because a slow subscriber's SSE
	// channel was full. Dropping is correct for a notification, but doing it silently
	// hides lost tools/list_changed and similar events, so the count is tracked and a
	// warning logged on the first drop. Atomic so broadcast (under notifMu) needs no
	// extra locking.
	droppedNotifs atomic.Uint64

	closeOnce sync.Once
	// done signals the upstream's LIFECYCLE end (distinct from sessCtx, which signals
	// teardown-cancellation): it is closed by readUpstream() on subprocess exit (local
	// mode) or by close() (remote mode), and the cleanup goroutine waits on it to reap the
	// subprocess / delete the session-map entry. It is no longer the in-flight-call
	// cancellation signal — that is sessCtx.
	done chan struct{}

	// handshakeStopped is closed once runInitHandshake's goroutine returns, whether or
	// not initUpstream itself was still waiting for it. initUpstream's post-kill wait is
	// BOUNDED (a descendant that escaped the process group can hold the stdout pipe open
	// past that bound), but os/exec documents that calling cmd.Wait after a bounded give-up
	// is not enough on its own: "it is incorrect to call Wait before all reads from the
	// [StdoutPipe] have completed" — Wait closes that same pipe, racing the handshake
	// goroutine's still-in-flight Read. newSession's failed-initialize reap therefore joins
	// this (in a background goroutine, so it does not itself hang) before calling cmd.Wait,
	// rather than assuming initUpstream's own join already happened.
	handshakeStopped chan struct{}

	// sessCtx is the session's single teardown-cancellation signal, canceled by close().
	// Both transports derive their in-flight-call cancellation from it, so teardown flows
	// through ONE primitive instead of two:
	//   - remote: callRemoteUpstream hangs each call's teardown dimension off it via
	//     context.AfterFunc (registers on the session-context tree, spawning no goroutine
	//     on the completed-call path);
	//   - local: awaitNonced selects on sessCtx.Done() (see teardownDone), and readUpstream
	//     ALSO cancels it on subprocess exit so a crash cancels in-flight calls even when
	//     close() is never called.
	// It descends from Background (not the request ctx that created the session — that ends
	// when initialize returns and must not cancel later per-call teardown). Always live:
	// set in newSession and newRemoteSession, and in tests by newTestSession, so every code
	// path can read it without a nil-guard.
	sessCtx    context.Context
	sessCancel context.CancelFunc

	// evictOnce/evicted end this session's open SSE notification stream(s) when the
	// session is killed (per-session or global emergency stop), without the full
	// teardown done drives. Closing evicted makes every open handleMCPGet loop for
	// this session return at once, so a killed session stops receiving upstream
	// notifications immediately. Kept distinct from done because done drives upstream
	// teardown (the cleanup goroutine reaps the subprocess); eviction only detaches
	// listeners, never reaps. Idempotent: a session can be killed more than once.
	evictOnce sync.Once
	evicted   chan struct{}

	// lastActive is the Unix-nanosecond time of the most recent host interaction,
	// updated on every POST and when a GET (SSE) stream is OPENED — not while one is
	// held. A long-lived stream is spared by the reaper's hasSubscribers() check
	// instead, so an editor who "fixed" the reaper to trust lastActive alone would tear
	// down every held stream after one idle window. The reaper compares it against
	// sessionIdleMs. Atomic so the reaper reads it without the proxy lock.
	lastActive atomic.Int64

	// lastRequest is the Unix-nanosecond time of the most recent host *request* (an
	// /mcp POST), unlike lastActive which also advances when an SSE stream is opened.
	// It backs the
	// hard idle ceiling: a session holding an SSE stream open but sending no host
	// request is still reaped once lastRequest is older than hardIdleMultiplier x the
	// idle window, so an initialize + GET client that goes silent cannot pin its
	// upstream indefinitely. Atomic; seeded at creation so a new SSE-only session is
	// not eligible for the ceiling until the full window has elapsed.
	lastRequest atomic.Int64

	// initInProgress is true from before registration until initialization (handshake
	// + synchronous startup drift check) completes. The drift check can block for up
	// to sessionStartTimeout while the session is registered with no subscribers and a
	// stale lastActive, which the idle reaper would otherwise read as idle and tear
	// down mid-init under a short --session-idle; reapOnce skips a session while this
	// is set. Atomic, matching lastActive/lastRequest.
	initInProgress atomic.Bool

	// reqSem bounds concurrent in-flight enforced-request handlers on this session,
	// the HTTP analogue of the stdio transport's hostSem. Without it a pipelining
	// host — or a silent upstream under --upstream-timeout=0, where handlers never
	// return — grows goroutines and the byUpstreamID / hostToUp maps without bound on
	// the network-exposed transport. Lazily created (reqSemOnce) so directly
	// constructed sessions (tests) get a real cap on first use; acquired non-blocking
	// in handleSessionPost, rejected with a retryable busy error on saturation.
	reqSemOnce sync.Once
	reqSem     chan struct{}

	// inFlight counts enforced requests currently blocked on the upstream. An
	// in-flight request is genuine activity, but lastActive is advanced only at POST
	// entry (touchRequest), not while the upstream call blocks — so a call outliving
	// sessionIdleMs would leave lastActive stale and let the idle reaper tear the
	// session down mid-call. reapOnce's NORMAL arm spares a session with inFlight > 0,
	// analogous to the initInProgress / hasSubscribers() spares (the hard ceiling still
	// reaps, so a never-returning call cannot pin the session forever).
	//
	// This is deliberately a separate atomic, not derived from len(reqSem): the reaper
	// reads it lock-free, and reqSem is lazily assigned under reqSemOnce, so a lock-free
	// len(reqSem) would race that one-time field write. The atomic gives the reaper a
	// race-free count that reqSem (a concurrency CAP, released via defer) cannot.
	inFlight atomic.Int64

	// notifySemOnce/notifySem bound concurrent in-flight notification forwards
	// (handleSessionPost's msg.IsNotification() branch) on this session — its own
	// pool, deliberately NOT shared with reqSem. Sharing reqSem would let a burst of
	// enforced tool-call requests (which can each block on the upstream for the full
	// --upstream-timeout) exhaust the pool and start dropping notifications, including
	// notifications/cancelled: a host meaning to abort one of those very calls could
	// then have its cancel silently dropped instead of forwarded, leaving the call to
	// run to completion against the host's intent. A separate pool means enforced-call
	// load can never starve notification delivery. Lazily created, mirroring reqSem.
	notifySemOnce sync.Once
	notifySem     chan struct{}

	// reqSaturation / notifySaturation gate the RESOURCE_EXHAUSTED record each pool writes
	// when it refuses — one gate per pool, so a notification flood cannot elide the request
	// pool's saturation record or the reverse. Each collapses an episode of saturation into
	// a single record carrying the count of refusals elided since; see saturationGate. Zero
	// value usable, so a session built by a struct literal is gated too — the same reason
	// the semaphores they guard are created lazily.
	reqSaturation    saturationGate
	notifySaturation saturationGate

	// serverPool bounds, dispatches and drains this session's SERVER-initiated request
	// handlers (sampling/createMessage, roots/list, elicitation) — a third pool beside the two
	// above, and the same one the stdio proxy keeps for its single upstream. readUpstream hands
	// each server-initiated request to it rather than running the handler inline; see
	// serverRequestPool for why that is a correctness property of the reader rather than a
	// latency preference. Per SESSION, so one session's flood cannot consume another's slots,
	// and its saturation record cannot be elided by another's episode. Zero value usable.
	serverPool serverRequestPool
}

// maxConcurrentSessionRequests bounds in-flight enforced-request handlers per HTTP
// session (see httpSession.reqSem), mirroring the stdio transport's
// maxConcurrentHostRequests. Generous enough that honest pipelining never trips it.
const maxConcurrentSessionRequests = 256

// maxConcurrentSessionNotifications bounds in-flight notification forwards per HTTP
// session (see httpSession.notifySem). Notifications are fire-and-forget and each
// POST is now bounded at notifyPostTimeout (forwardNotification), so this only needs
// to be generous enough that a legitimate burst never trips it — mirroring the
// stdio-bridge's maxInflightPosts, scaled down since this pool is per-session rather
// than bridge-wide.
const maxConcurrentSessionNotifications = 64

// tryAcquireNotifySlot attempts a non-blocking acquire of the session's in-flight
// notification semaphore, returning false when the session is already at
// maxConcurrentSessionNotifications. Deliberately a separate pool from
// tryAcquireRequestSlot (see notifySem's doc comment). Paired with
// releaseNotifySlot.
func (s *httpSession) tryAcquireNotifySlot() bool {
	s.notifySemOnce.Do(func() { s.notifySem = make(chan struct{}, maxConcurrentSessionNotifications) })
	select {
	case s.notifySem <- struct{}{}:
		// The pool had a free slot, so any saturation episode is over: re-arm the gate so
		// the next drop is recorded as a new episode rather than folded into the last one.
		s.notifySaturation.clear()
		return true
	default:
		return false
	}
}

// releaseNotifySlot releases one in-flight notification slot acquired via
// tryAcquireNotifySlot. Must be called exactly once per successful acquire.
func (s *httpSession) releaseNotifySlot() { <-s.notifySem }

// tryAcquireRequestSlot attempts a non-blocking acquire of the session's in-flight
// request semaphore, returning false when the session is already at
// maxConcurrentSessionRequests. The semaphore is created on first use so sessions
// built directly (in tests) still get a real cap. Paired with releaseRequestSlot.
func (s *httpSession) tryAcquireRequestSlot() bool {
	s.reqSemOnce.Do(func() { s.reqSem = make(chan struct{}, maxConcurrentSessionRequests) })
	select {
	case s.reqSem <- struct{}{}:
		// Ends any saturation episode, exactly as the notification pool's acquire does.
		s.reqSaturation.clear()
		return true
	default:
		return false
	}
}

// releaseRequestSlot releases one in-flight request slot acquired via
// tryAcquireRequestSlot. Must be called exactly once per successful acquire.
func (s *httpSession) releaseRequestSlot() { <-s.reqSem }

// touch records host interaction — today, opening an SSE stream — deferring the normal
// idle reaper. It fires once per open, NOT continuously while a stream is held; a held
// stream is kept alive by the reaper's hasSubscribers() spare instead. It advances
// lastActive only, NOT lastRequest, so SSE liveness alone cannot defer the hard idle
// ceiling. Goroutine-safe.
func (s *httpSession) touch() {
	s.lastActive.Store(time.Now().UnixNano())
}

// touchRequest records a host request (an /mcp POST), advancing both lastActive
// (deferring the normal idle reaper) and lastRequest (deferring the hard idle
// ceiling). Goroutine-safe.
func (s *httpSession) touchRequest() {
	now := time.Now().UnixNano()
	s.lastActive.Store(now)
	s.lastRequest.Store(now)
}

// buildInitResponse builds an initialize response for the host using the
// upstream capabilities gathered during session startup.
func (s *httpSession) buildInitResponse(msg mcp.RPCMsg) mcp.RPCMsg {
	return buildInitializeResponse(msg.ID, s.upstreamCaps, s.upstreamInstructions)
}

// ownerMismatch reports whether cur (the JWT identity on the CURRENT request) differs
// from the identity that created this session, so an action from it must be
// refused, and names WHICH pin failed for the deny record. The re-initialize echo returns the
// upstream capabilities and serverInfo captured at creation, so only the creating client may
// receive them; a second identity authenticated to the same route (same audience pin,
// different sub) that learns the session id must not read another client's captured state.
//
// A session created without a JWT identity (claims nil or no subject) is UNBOUND —
// there is no per-client identity to enforce (e.g. a no-JWT route where every client is
// anonymous) — so it never mismatches on the principal. Identity is the (issuer, subject)
// pair: sub is unique only within an issuer, so both are compared, and as separate fields
// (never a concatenation, which could collide across values). A refreshed token from the same
// principal (new jti/exp, same iss+sub) still matches; a different principal does not.
//
// The ANCHOR pin runs first and runs even on an unbound session, because it is not about the
// principal — see anchorMismatch.
func (s *httpSession) ownerMismatch(cur *pdp.JWTClaims) (string, bool) {
	if s.anchorMismatch(cur) {
		return "session_anchor_mismatch", true
	}
	if s.claims == nil || s.claims.Subject == "" {
		return "", false // unbound: no creating identity to enforce
	}
	if cur == nil {
		return "session_owner_mismatch", true // bound session, but the request carries no identity
	}
	if cur.Issuer != s.claims.Issuer || cur.Subject != s.claims.Subject {
		return "session_owner_mismatch", true
	}
	return "", false
}

// anchorMismatch reports whether cur resolves a DIFFERENT state anchor than the one this
// session is bound to. It is a no-op on a route that does not anchor state on the task, where
// every request on a session resolves that session and the check is vacuous.
//
// It exists because the session has TWO legs that decide, and only one of them has a request in
// scope. The host leg reads the current request's validated claims — for its decision, its
// state key, and its turn. The server-initiated (sampling) leg has no host request at all, so
// it reads the claims captured at initialize, for all three. Under task anchoring those are two
// different task ids for the same session as soon as a caller sends requests with a second
// token, since sub/iss alone accepted it: a labelOutput source then records its taint under the
// request's task while the sampling sink peeks the session's, finds it clean, and forwards the
// egress the label existed to stop. The anchor-keyed decision turn cannot catch that — the
// sampling leg's turn and its state key agree with each other and both disagree with the host
// leg. The turn's guarantee holds; it is the wrong key.
//
// So a session on a task-anchored route is bound to its ANCHOR, and a request resolving another
// one is refused rather than silently accounted against a bucket this session's other leg
// cannot see. That is the fail-closed direction, and it is what makes the captured claims an
// honest stand-in for "this session's identity". It also refuses an authenticated request whose
// token carries NO task id — which the engine refuses on its own (a task-anchored request must
// not be session-keyed), just with its own denial rather than this one.
//
// The comparison goes through the route's resolver, the same one the engine's key builder uses,
// so it cannot come to a different answer about which anchor a request has — and so a third
// anchor kind is covered by construction rather than by a second reading of the claims here.
func (s *httpSession) anchorMismatch(cur *pdp.JWTClaims) bool {
	rt := s.route
	if rt == nil || !rt.taskAnchored {
		return false
	}
	return rt.decisionAnchor(s.id, cur) != rt.decisionAnchor(s.id, s.claims)
}

// newSession spawns an upstream subprocess and performs the MCP initialize
// handshake. The session is registered in p.sessions before readUpstream starts so
// the cleanup goroutine finds it even if the subprocess exits immediately.
// startGen is the reap generation the CALLER observed before its pre-spawn kill gate (see
// handleMCPPost); it is not captured here, because everything between that gate and this
// point — the gate's own kill-store round-trip included — is inside the window
// registerSession has to detect.
func (p *HTTPProxy) newSession(ctx context.Context, route *UpstreamRoute, clientIP string, startGen uint64) (*httpSession, error) {
	// Session-scoped teardown context, mirroring newRemoteSession so both transports share
	// one cancellation primitive. Built into the struct literal BEFORE registerSession
	// publishes the session into p.sessions, so a concurrent close() (server shutdown / kill)
	// never races the write of sessCancel — the field is fully initialized before the session
	// becomes reachable. Descends from Background: the request ctx ends when this handshake
	// returns. If newSession returns an error before wiring up teardown, the uncanceled cancel
	// leaks only a bare context (no goroutine, no AfterFunc registered), which is benign.
	sessCtx, sessCancel := context.WithCancel(context.Background())
	sess := &httpSession{
		id:           uuid.New().String(),
		proxy:        p,
		route:        route,
		byUpstreamID: make(map[string]chan upstreamResult),
		hostToUp:     make(map[string]*json.RawMessage),
		done:         make(chan struct{}),
		evicted:      make(chan struct{}),
		sessCtx:      sessCtx,
		sessCancel:   sessCancel,
		claims:       pdp.JWTClaimsPtr(ctx),
		clientIP:     clientIP,
	}
	// Mark initializing until newSession returns (after the synchronous drift check)
	// so the idle reaper does not tear the session down during the drift-check window.
	// See the initInProgress field comment.
	sess.initInProgress.Store(true)
	defer sess.initInProgress.Store(false)

	cmd := exec.Command(route.command, route.args...) //nolint:gosec,noctx // G204: args are user-supplied CLI arguments; session lifecycle managed via done channel, not ctx
	ConfigureUpstreamCmd(cmd)

	upIn, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("upstream stdin: %w", err)
	}
	upOut, err := cmd.StdoutPipe()
	if err != nil {
		// Start is never reached on this path, so Cmd.Start's deferred pipe cleanup
		// never runs. Close the parent write end we hold. (The child read end stashed
		// in cmd is only reclaimed by its *os.File finalizer, so this frees one of the
		// two FDs, not both.)
		_ = upIn.Close()
		return nil, fmt.Errorf("upstream stdout: %w", err)
	}
	sess.upCmd = cmd
	sess.upIn = upIn
	// Bound each proxy->upstream pipe write by --upstream-timeout so a subprocess that
	// stops draining its stdin cannot wedge a request handler indefinitely on the write
	// (holding the MsgWriter mutex). On a write timeout the writer poisons and invokes the
	// onPoison hook, which kills the subprocess so readUpstream EOFs, close(done) fires, and
	// the cleanup goroutine reaps the session rather than leaving it pinned with a desynced
	// stream — and this fires for ANY wedging write path (request, notification, server-reply
	// relay), not only the request path. --upstream-timeout=0 leaves the write unbounded.
	sess.upWriter = mcp.NewMsgWriterWithTimeout(upIn, msToDuration(p.upstreamTimeMs), sess.killSubprocess)
	sess.upReader = mcp.NewMsgReader(upOut)

	if err := cmd.Start(); err != nil {
		// No pipe cleanup here: a failed Cmd.Start closes both the parent ends
		// (upIn/upOut) and the child ends via its own deferred cleanup.
		return nil, fmt.Errorf("starting upstream %q: %w", route.command, err)
	}

	if err := sess.initUpstream(ctx); err != nil {
		killUpstreamProcess(cmd.Process)
		// Reap so a failed initialize leaves no zombie — but NOT synchronously: unlike
		// the registerSession failure arm below (which is reached only after initUpstream
		// has already returned nil, meaning runInitHandshake genuinely completed),
		// initUpstream can return here having only bounded its wait for the handshake
		// goroutine, not joined it — a descendant that escaped the process group can still
		// be holding the stdout pipe open. Calling cmd.Wait while that goroutine's Read on
		// the same pipe is still in flight is exactly what os/exec documents as incorrect
		// (Wait closes the pipe out from under it). Join s.handshakeStopped first, in the
		// background so a still-escaped descendant cannot hang newSession itself; the
		// resulting zombie is reaped whenever that eventually resolves.
		go func() {
			// Bounded, like every other wait on this channel: unbounded, this goroutine
			// (and the zombie it exists to reap) outlives the process whenever a
			// descendant that escaped the process group keeps the pipe open forever. It
			// runs BEFORE registerSession, so --max-sessions does not bound how many can
			// accumulate — a repeatedly-failing upstream would leak one per attempt.
			// Abandoning the wait leaks the same zombie the unbounded version was trying
			// to avoid, but it leaks exactly one goroutine's worth of nothing instead of
			// one goroutine forever, and it says so on stderr.
			waitBounded(sess.handshakeStopped, sess.shutdownBudget(), "upstream handshake reader")
			_ = cmd.Wait()
		}()
		return nil, fmt.Errorf("upstream initialize: %w", err)
	}

	// Register before starting readUpstream. readUpstream closes sess.done on
	// subprocess exit and the cleanup goroutine then deletes the entry; registering
	// after would risk the subprocess exiting, the cleanup firing (no-op delete), and
	// the map assignment leaking the entry permanently.
	//
	// registerSession also enforces the maxSessions cap. On a race over the cap, kill
	// the subprocess directly (readUpstream is not yet running, so sess.done would
	// never close) and surface the limit error; Wait reaps it (safe — the cleanup
	// goroutine starts only after registration, and initUpstream has joined).
	if err := p.registerSession(sess, startGen); err != nil {
		killUpstreamProcess(cmd.Process)
		_ = cmd.Wait()
		return nil, err
	}

	// Cleanup goroutine: wait for the upstream to exit, then remove the session.
	//
	// sess.done closes on ANY readUpstream exit, not only a clean process exit — an
	// oversized frame (bufio.ErrTooLong, the MsgReader's 4 MiB cap) or a parse error
	// leaves the subprocess running with only its stdout torn down. Close stdin first
	// so a well-behaved child sees EOF and exits on its own; if it does not, escalate
	// to SIGKILL after a bounded grace period instead of blocking Wait() forever,
	// which would otherwise leak the session slot/subprocess/FDs/goroutine. This
	// mirrors close()'s close-then-bounded-kill pattern, but timed independently of
	// sess.done (already closed at this point, so reusing close()'s select on it
	// would return immediately without ever killing a still-running process) — the
	// two are not merged into one shared helper because they wait on genuinely
	// different completion signals (s.done vs. a Wait()-derived channel) with
	// different bound counts (close() bounds twice, since readUpstream can itself
	// wedge on a slow PDP/kill-store call; this goroutine bounds once, since by the
	// time it runs readUpstream has already exited).
	//
	// This can run concurrently with an explicit sess.close() (e.g. a failed drift
	// check, an idle-reaper sweep, or a client DELETE) racing to close upIn or kill
	// the process at the same time. That is benign: both close upIn and kill the
	// process idempotently (a double-close/double-kill just returns an ignored
	// error), and closeOnce only guards close()'s own body, not this goroutine's.
	go func() { //nolint:contextcheck // teardown path: releaseSessionState uses a detached, bounded context by design (the session is gone; no request context), matching the other teardown steps.
		<-sess.done
		if sess.upIn != nil {
			_ = sess.upIn.Close()
		}
		waited := make(chan struct{})
		go func() {
			_ = sess.upCmd.Wait()
			close(waited)
		}()
		select {
		case <-waited:
		case <-time.After(msToDuration(p.shutdownMs)):
			killUpstreamCmd(sess.upCmd)
			<-waited
		}
		p.mu.Lock()
		delete(p.sessions, sess.id)
		p.mu.Unlock()
		// Release this session's per-session flow-label state now it is gone from the
		// registry. This cleanup block runs on EVERY
		// teardown — idle reap, DELETE, kill, shutdown, AND natural subprocess exit (which
		// close() does not cover) — so it is the one place that reclaims state for all of
		// them, co-located with the registry delete.
		releaseSessionState(sess)
		fmt.Fprintf(os.Stderr, "[eunox] HTTP session %s ended.\n", sess.id)
	}()

	// The reader outlives the initialize request: pass the proxy's serve context, not
	// the request-scoped ctx, so kill-switch lookups on the upstream-initiated path
	// are not canceled when this request completes. Sampling decisions attribute the
	// session identity captured at initialize (httpSession.claims).
	go sess.readUpstream(p.serveCtx()) //nolint:contextcheck // deliberate: session lifetime != request lifetime

	// Drift check runs after readUpstream is started (so callUpstream works). Always
	// synchronous: the session is not returned until FM-5 verification completes;
	// --strict-drift additionally gates FM-1/2/4. On failure delete synchronously so
	// the failed session stops counting against maxSessions immediately (the cleanup
	// goroutine deletes only asynchronously, after the upstream exits) and a
	// concurrent initialize is not spuriously rejected with errSessionLimit. The
	// goroutine's later delete is then a benign no-op.
	if err := p.runDriftCheckOrTeardown(ctx, sess, route); err != nil {
		return nil, err
	}

	// Re-stamp the activity clocks now that establishment is complete, so idle is
	// measured from readiness rather than from registration. registerSession seeded
	// them before the initialize handshake and drift probe ran (up to
	// sessionStartTimeout ago); the initInProgress guard spares the session DURING
	// init, but without this re-stamp a just-ready session whose --session-idle is
	// smaller than its startup duration is eligible for reaping on the very next
	// sweep, before the client sends its first post-init request.
	sess.touchRequest()

	fmt.Fprintf(os.Stderr, "[eunox] HTTP session %s started.\n", sess.id)
	return sess, nil
}

// runDriftCheckOrTeardown runs the route's session-start drift check (if configured)
// against a freshly-probed upstream tools/list. On a drift failure it tears the
// session down synchronously — close() plus an immediate delete from p.sessions so the
// failed session stops counting against maxSessions at once (the cleanup goroutine's
// later delete, gated on done, is then a no-op) — and returns the error. A nil
// driftCheck or a passing check returns nil. Shared by newSession (local subprocess)
// and newRemoteSession (remote HTTP), whose teardown ordering must stay identical.
func (p *HTTPProxy) runDriftCheckOrTeardown(ctx context.Context, sess *httpSession, route *UpstreamRoute) error {
	if route.driftCheck == nil {
		return nil
	}
	raw, probeErr := sess.fetchUpstreamToolsRaw(ctx)
	// Take this session's Tier-2 interface baseline from the same probe (see the stdio
	// path for why the session-start view is the right one). Keyed by session id, so each
	// HTTP session on this shared per-route PDP baselines its own upstream independently.
	if probeErr == nil {
		route.pdp.RecordObservedToolHashes(pdp.WithCompleteToolListing(pdp.WithSessionID(ctx, sess.id)), raw)
	}
	if err := route.driftCheck(raw, sess.upstreamServerVersion, probeErr); err != nil {
		// Record the refusal before teardown: a startup drift failure is the FM-5
		// tool-poisoning / rug-pull event this check exists to catch, so it must land on
		// the tamper-evident tape (route-stamped), not only stderr and a generic 500. The
		// raw drift reason (which names drifted tools) stays on stderr; the tape carries
		// the stable DRIFT_REFUSED category.
		recordDriftRefused(ctx, asRecorder(route.sink), sess.id)
		sess.close(p.shutdownMs) //nolint:contextcheck // teardown path: the upstream session-termination DELETE intentionally uses a detached, bounded background context — close/reaper/signal/shutdown carry no request context.
		p.mu.Lock()
		delete(p.sessions, sess.id)
		p.mu.Unlock()
		return err
	}
	return nil
}

// errSessionLimit is returned by registerSession when maxSessions is reached. The
// POST handler maps it to 503 Service Unavailable rather than 500 so a host can
// distinguish "at capacity, retry later" from an upstream start failure.
var errSessionLimit = errors.New("session limit reached")

// errShuttingDown is returned by registerSession once closeAllSessions has begun, so a
// session establishing concurrently with shutdown does not register into a registry that
// will never be reaped again. newSession/newRemoteSession tear down their upstream on it.
var errShuttingDown = errors.New("server shutting down")

// errRacedReap is returned by registerSession when a global kill-switch reap
// (reapAllKilledSessions) swept the registry after this session began establishing but
// before it registered — see the reapGen field comment and currentReapGen.
// newSession/newRemoteSession handle it exactly like errShuttingDown/errSessionLimit:
// tear down the upstream they just started, so the late arrival cleans up after itself.
var errRacedReap = errors.New("session raced a kill-switch reap; retry")

// currentReapGen returns the kill-switch reap generation in force right now. A
// session-creating initialize calls this once, before starting its (possibly slow)
// upstream handshake, and passes the result to registerSession as startGen — see
// registerSession and the reapGen field comment.
func (p *HTTPProxy) currentReapGen() uint64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.reapGen
}

// registerSession inserts sess under the proxy lock after an authoritative
// capacity check, stamping its initial activity time. It is the single insertion
// point so the maxSessions cap holds even when concurrent initialize requests race
// past the cheap pre-spawn check in handleMCPPost.
//
// startGen is the reapGen the caller observed via currentReapGen before it began
// establishing sess (the handshake/drift probe can take up to sessionStartTimeout).
// If a global kill's reapAllKilledSessions swept the registry during that window,
// p.reapGen will have advanced past startGen by the time we get here, and the insert
// is rejected — otherwise this session would register into the fresh (post-sweep) map
// with a live upstream the sweep never saw and had no chance to tear down, reopening
// the kill-triggered session-exhaustion DoS the reap exists to close (see reapGen).
func (p *HTTPProxy) registerSession(sess *httpSession, startGen uint64) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Fail closed once shutdown has begun. srv.Shutdown is bounded by shutdownMs but a
	// session-creating initialize can spend up to sessionStartTimeout inside initUpstream
	// (a slow upstream handshake/drift probe), so its registerSession can land AFTER
	// closeAllSessions has snapshotted and emptied the registry and the reaper was
	// canceled — leaking the subprocess and its goroutines with nothing left to reap it.
	// newSession/newRemoteSession handle this error by tearing down the upstream they
	// just started, so the late arrival cleans up after itself instead.
	if p.shuttingDown {
		return errShuttingDown
	}
	if p.reapGen != startGen {
		return errRacedReap
	}
	if p.maxSessions > 0 && len(p.sessions) >= p.maxSessions {
		return errSessionLimit
	}
	// Deliberately does NOT touch p.establishing. The reservation has exactly one owner
	// — the handler that took it — and it is released exactly once, unconditionally, when
	// that handler returns. An earlier shape converted the reservation here on success,
	// which double-freed it whenever establishment failed AFTER registering (the drift
	// refusal in runDriftCheckOrTeardown is such a path): the handler's release then
	// decremented a counter this function had already decremented, silently consuming a
	// CONCURRENT session's reservation and letting more upstreams spawn than the cap
	// allows — the exact over-admission the counter exists to prevent. Between this
	// insert and the handler's release the session is counted twice (registered AND
	// establishing), which errs toward refusing one extra initialize rather than
	// admitting one too many.
	now := time.Now().UnixNano()
	sess.lastActive.Store(now)
	// Seed lastRequest so the hard idle ceiling is measured from creation: the
	// initialize POST counts as the first host request.
	sess.lastRequest.Store(now)
	// Resolve the session's decision gate here, on the one path every session that will
	// ever serve a request passes through, and only after the checks above — a session
	// this call refuses is never registered and must not leave a reference behind. The
	// gate registry is leaf-level (it locks nothing under its own mutex), so entering it
	// under p.mu introduces no ordering hazard.
	sess.holdDecisionGate()
	p.sessions[sess.id] = sess
	return nil
}

// holdDecisionGate resolves this session's anchor once and caches the registry gate for it,
// for the session's life. The reference is released by releaseSessionState.
//
// The anchor is resolved from the session's OWN claims — the identity every request on the
// session carries, which the session gate pins (ownerMismatch) — so on a well-formed session
// this is the gate every request resolves. It is a cache, not a decision that the anchor
// cannot change: each request resolves its own and compares (see gateFor), so a request that
// lands on a different anchor reaches the registry rather than the wrong turn.
//
// A non-serialized route has no registry and caches nothing; hold is a no-op on a nil registry,
// so this needs no branch of its own for that case.
func (s *httpSession) holdDecisionGate() {
	rt := s.route
	if !rt.serializes() {
		return
	}
	s.decideAnchor = rt.decisionAnchor(s.id, s.claims)
	s.decideGate, s.dropDecideGate = rt.decideGates.hold(s.decideAnchor.Key())
}

// gateFor returns this session's cached gate when it is the gate anchor resolves to, or nil to
// send the caller through the registry.
//
// The comparison is on the RESOLVED anchor (a comparable two-string struct, so it allocates
// nothing and renders no key), never on a restatement of how the resolver decides. That is what
// makes the cache correct for any anchor kind rather than for the two that exist today.
func (s *httpSession) gateFor(anchor enforcement.StateAnchor) *anchorGate {
	if s.decideGate == nil || s.decideAnchor != anchor {
		return nil
	}
	return s.decideGate
}

// beginDecisionTurn enters this request's decision turn and returns the idempotent release,
// or nil when the route is not serialized. The host path holds the turn on its own request
// goroutine, so it waits without a bound.
//
// ctx supplies the request's VALIDATED claims, which decide the anchor on a task-anchored
// route.
func (s *httpSession) beginDecisionTurn(ctx context.Context) func() {
	anchor := s.route.decisionAnchorFromContext(ctx, s.id)
	if gate := s.gateFor(anchor); gate != nil {
		end, _ := gate.take(nil)
		return end
	}
	end, _ := s.route.decideGates.acquire(anchor.Key(), nil)
	return end
}

// beginDecisionTurnWithin is beginDecisionTurn for the server-initiated leg, bounded by d and
// anchored on the SESSION's claims (captured at initialize) because that leg has no host
// request in scope. ok is false when the turn could not be entered in time, which the caller
// must turn into a refusal — see samplingTurnWait.
//
// Those captured claims are the same ones holdDecisionGate resolved from, so this hits the
// cache; it still resolves and compares rather than reaching for s.decideGate directly, because
// "the two agree" is a property to check, not one to assume. What makes the captured claims an
// honest stand-in for the request identity in the first place is the session gate: on a route
// that anchors state on the task, a request whose token resolves a DIFFERENT anchor is refused
// rather than accounted against a bucket this leg cannot see (see ownerMismatch).
func (s *httpSession) beginDecisionTurnWithin(d time.Duration) (func(), bool) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	anchor := s.route.decisionAnchor(s.id, s.claims)
	if gate := s.gateFor(anchor); gate != nil {
		return gate.take(timer.C)
	}
	return s.route.decideGates.acquire(anchor.Key(), timer.C)
}

// getSession returns the session for id, or nil.
func (p *HTTPProxy) getSession(id string) *httpSession {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.sessions[id]
}

// sessionCount returns the number of REGISTERED sessions, for the health/metrics
// endpoints. Deliberately not the capacity predicate: the cap also counts sessions still
// establishing (see tryReserveSessionSlot), so a caller deciding whether to admit one
// must not reach for this.
func (p *HTTPProxy) sessionCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.sessions)
}

// tryReserveSessionSlot reserves one maxSessions slot for a session that is about to be
// established, counting sessions already registered PLUS those still establishing. It
// returns false when the cap is reached, in which case the caller must refuse the
// initialize (503) without spawning anything.
//
// A registry-only pre-check is not enough: establishment (upstream spawn + initialize
// handshake + drift probe) runs for up to sessionStartTimeout before registerSession
// makes the count authoritative, so concurrent initializes would all pass a registry-only
// check and all spawn upstreams. See the establishing field.
//
// Every successful reservation is released exactly once, by the caller that took it, on
// every path — success included. Nothing else may touch p.establishing: a second releaser
// cannot know whether the reservation it is dropping is its own, and dropping someone
// else's is indistinguishable from a correct release. maxSessions <= 0 (unlimited)
// reserves nothing, so its release is a no-op too.
func (p *HTTPProxy) tryReserveSessionSlot() bool {
	if p.maxSessions <= 0 {
		return true
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.sessions)+p.establishing >= p.maxSessions {
		return false
	}
	p.establishing++
	return true
}

// releaseSessionSlot drops the reservation taken by tryReserveSessionSlot, whatever the
// outcome of establishment was. A no-op against an unlimited cap (which reserves
// nothing).
//
// The p.establishing > 0 guard is a backstop against a negative counter, NOT a licence to
// release twice: with other sessions establishing, a spurious release does not go
// negative — it silently consumes THEIR reservation, which is why the counter has exactly
// one releaser (see tryReserveSessionSlot).
func (p *HTTPProxy) releaseSessionSlot() {
	if p.maxSessions <= 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.establishing > 0 {
		p.establishing--
	}
}

// hardIdleMultiplier sets the hard idle ceiling as a multiple of the idle window.
// A session holding an open SSE stream is normally spared the idle reaper, but an
// initialize + GET client that goes silent would pin its upstream indefinitely;
// once it has sent NO host request for hardIdleMultiplier x the idle window the
// reaper closes it anyway. Conservative: any host that polls or calls tools, even
// infrequently, keeps resetting lastRequest and is never hard-reaped. A constant,
// not a config knob, to keep the safety net's scope small.
const hardIdleMultiplier = 4

// reapIdleSessions periodically closes sessions whose host has sent no request
// within sessionIdleMs. A session holding an open SSE stream is spared UNLESS it
// has also sent no host request for the hard idle ceiling (hardIdleMultiplier x the
// idle window). Closing a reaped session signals its done channel, which the
// per-session cleanup goroutine observes to remove it and reclaim the upstream.
// Runs until ctx (the serve-lifetime context) is cancelled.
func (p *HTTPProxy) reapIdleSessions(ctx context.Context) {
	idle := msToDuration(p.sessionIdleMs)
	// Sweep at half the idle window, clamped to [1s, 30s].
	interval := idle / 2
	if interval < time.Second {
		interval = time.Second
	}
	if interval > 30*time.Second {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.reapOnce(idle) //nolint:contextcheck // teardown path: the upstream session-termination DELETE intentionally uses a detached, bounded background context — close/reaper/signal/shutdown carry no request context.
		}
	}
}

// reapOnce closes, in a single sweep, every session idle longer than idle and not
// holding an open SSE stream (or past the hard ceiling). Factored out of the reaper
// loop for deterministic testing. Sessions are collected under the lock and closed
// outside it (close -> done -> cleanup goroutine deletes the map entry).
//
// Closed concurrently: close() blocks up to shutdownMs on an unresponsive upstream,
// so a serial loop would let one slow upstream stall the whole sweep. The batch is
// awaited so every reaped session is closed on return (deterministic for tests).
func (p *HTTPProxy) reapOnce(idle time.Duration) {
	now := time.Now()
	cutoff := now.Add(-idle).UnixNano()
	// hardCutoff: a session with no host request since this instant is reaped even
	// with an open SSE stream. Saturate idle x hardIdleMultiplier rather than
	// multiplying a raw Duration: a large-but-valid idle window (up to ~292 years)
	// would overflow int64 and wrap negative, putting hardCutoff in the future so
	// every session trips the ceiling on the first sweep.
	hard := idle
	if idle > math.MaxInt64/hardIdleMultiplier {
		hard = math.MaxInt64
	} else {
		hard *= hardIdleMultiplier
	}
	hardCutoff := now.Add(-hard).UnixNano()
	// staleSession pairs a reaped session with WHY it is being reaped, so the log line
	// can name the reason; all three arms share the close path.
	type staleSession struct {
		s      *httpSession
		hard   bool
		killed bool
	}
	// Snapshot under p.mu, then release it BEFORE the idle/subscriber checks:
	// hasSubscribers takes s.notifMu, so checking under p.mu would establish the lock
	// order p.mu -> s.notifMu. Keeping the acquisitions disjoint is preventive — no
	// path takes them in reverse today (broadcast/hasSubscribers/addSub/removeSub hold
	// s.notifMu as a leaf), and this stops a future one from deadlocking against this
	// loop. The re-check below spares a session that becomes active before its
	// teardown goroutine runs; the residual window between re-check and close() itself
	// is narrowed, not eliminated — an accepted trade-off for a nearly-idle session.
	p.mu.RLock()
	snapshot := make([]*httpSession, 0, len(p.sessions))
	for _, s := range p.sessions {
		snapshot = append(snapshot, s)
	}
	p.mu.RUnlock()
	var stale []staleSession
	for _, s := range snapshot {
		// A session still initializing (handshake + synchronous drift check) is not
		// eligible for reaping on ANY arm: it is registered but has no subscribers and a
		// stale lastActive while the drift check blocks, which would otherwise read as
		// idle — and tearing one down would race the establishment path's own teardown,
		// which no reap arm does today. A session killed while it establishes is denied
		// throughout and reclaimed by the next sweep.
		if s.initInProgress.Load() {
			continue
		}
		// A KILLED session is reaped whatever its idle state, because a kill this
		// instance did not itself serve has nothing else that reclaims it. The local
		// /control/kill path calls reapKilledSession inline, but a kill delivered through
		// Redis — `eunox kill --redis-addr`, or a sibling instance's /control/kill, the
		// multi-instance deployments the Redis backend exists for — reaches this proxy
		// only through CheckKill. Its traffic is denied either way (fail-closed holds),
		// but without this sweep its subprocess and its maxSessions slot stay pinned and
		// its SSE stream is never evicted: accumulated killed-but-undead sessions
		// eventually 503 every new initialize, the session-exhaustion DoS the kill switch
		// would then be triggering itself.
		//
		// The read is a local cache lookup, not a kill-store round trip (the Redis backend
		// serves ShouldBlock from the cache its pub/sub and reconcile loops refresh), so
		// this costs one map read per session per sweep.
		//
		// NOTE: this sweep is the idle reaper's, so it does not run at all under
		// sessionIdleTimeoutMs: 0. A deployment taking kills through Redis wants a
		// non-zero idle timeout — see the field's documentation.
		if p.sessionKilled(s) {
			stale = append(stale, staleSession{s: s, killed: true})
			continue
		}
		switch {
		case s.lastRequest.Load() < hardCutoff && p.hardReapEligible(s):
			// Hard ceiling: no host request for hardIdleMultiplier x idle, even though
			// an SSE stream may still be open. Checked FIRST so a session past the hard
			// ceiling is always tagged hard — otherwise a session that is also normally
			// idle would match the normal arm and could escape reaping by opening an SSE
			// stream in the re-check window, defeating the ceiling the hard reap exists
			// to enforce. The ceiling exists to reclaim a session whose upstream call
			// never returns (a silent upstream under --upstream-timeout=0), which would
			// otherwise pin the session and its subprocess forever. When the per-call
			// budget is FINITE, an in-flight call is already bounded by that timeout, so
			// hardReapEligible keeps it — otherwise a legal call within its configured
			// budget is killed whenever upstreamTimeout >= hardIdleMultiplier x idle. Only
			// when the budget is disabled (unbounded) does the hard arm reclaim an
			// in-flight call, its whole reason for existing.
			stale = append(stale, staleSession{s: s, hard: true})
		case s.lastActive.Load() < cutoff && !s.hasSubscribers() && s.inFlight.Load() == 0:
			// Normal idle: quiet, not holding an SSE stream, and no enforced request in
			// flight. The in-flight spare is on the NORMAL arm only: lastActive is not
			// refreshed while the upstream call blocks, so a call outliving sessionIdleMs
			// (but still within the hard ceiling) must not be torn down mid-flight.
			// Re-checked in the teardown goroutine below.
			stale = append(stale, staleSession{s: s})
		}
	}
	var wg sync.WaitGroup
	for _, ss := range stale {
		s := ss.s
		hardReap := ss.hard
		killed := ss.killed
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Re-check liveness immediately before teardown: a host request may have
			// advanced lastActive (or opened an SSE stream) since the snapshot's check,
			// so reading the same atomics spares a session that became active again,
			// narrowing the spurious-reap race to the close() call itself. The "reaped"
			// log line is emitted only AFTER the re-check passes and inside this
			// goroutine — printing it before (for every stale-snapshot entry) produced
			// false "reaped" messages for sessions the re-check then spared.
			if killed {
				p.reclaimKilledSession(s)
				return
			}
			if hardReap {
				if s.lastRequest.Load() >= hardCutoff || !p.hardReapEligible(s) {
					return
				}
				fmt.Fprintf(os.Stderr, "[eunox] HTTP session %s reaped (no host request > %s, hard idle ceiling; SSE stream may have been open).\n", s.id, hard)
			} else {
				// An enforced request that started after the snapshot spares the NORMAL
				// arm: tearing it down would kill the upstream out from under the in-flight
				// callUpstream. The hard arm above intentionally does not consult inFlight
				// (it is the backstop for a call that never returns).
				if s.lastActive.Load() >= cutoff || s.hasSubscribers() || s.inFlight.Load() > 0 {
					return
				}
				fmt.Fprintf(os.Stderr, "[eunox] HTTP session %s reaped (idle > %s).\n", s.id, idle)
			}
			s.close(p.shutdownMs)
		}()
	}
	wg.Wait()
}

// sessionKilled reports whether the kill switch currently names this session — its own
// id, its agent, or a global emergency stop. It is the reaper's read of the same
// authority the request path consults, so a session the data plane is already denying is
// one the reaper reclaims, however the kill arrived (locally through /control/kill, or
// through Redis from another instance).
//
// It answers ONLY on an actual kill. CheckKill also denies on a kill-store ERROR
// (KILL_SWITCH_ERROR — the fail-closed answer to, say, a Redis blip under the default
// posture), and that is the right answer for a REQUEST: deny now, serve again when the
// store recovers, seconds later. It is the wrong answer HERE, because this sweep's
// response is not a denial but a teardown — every live session on the instance would
// lose its upstream and its stream over a store that was briefly unreachable, and no
// recovery undoes that. A store fault is not evidence that anyone was killed.
//
// The session's own claims ride the check, so an AGENT-scoped kill reclaims its sessions
// too: the store matches on (agent, session), and a background sweep has no request
// context to take an agent id from. Same source the upstream-notification gate uses.
//
// A session assembled without a route or PDP (an in-package test literal) is never
// killed: there is no authority to ask. That is not a security-gate fail-open — the
// gates that DENY traffic are elsewhere and unconditional — only a reclaim this sweep
// cannot perform.
func (p *HTTPProxy) sessionKilled(s *httpSession) bool {
	if s.route == nil || s.route.pdp == nil {
		return false
	}
	ctx := context.Background()
	if s.claims != nil {
		ctx = pdp.WithJWTClaims(ctx, s.claims)
	}
	deny := s.route.pdp.CheckKill(ctx, s.id)
	return deny != nil && deny.Denial != nil && deny.Denial.Code == capability.ErrCodeKillSwitch
}

// reapKilledSessions closes every registered session the kill switch NOW names, freeing its
// upstream, its maxSessions slot and its SSE stream. It is the on-DELIVERY reclaim
// (reclaimOnRevocation), and the idle reaper's killed arm is the same sweep on a timer.
//
// Two paths rather than one because they answer different failures. The reaper's arm is the
// backstop for a revocation whose notification never arrived — a dropped publish, a
// subscription being retried — and it does not run at all under sessionIdleTimeoutMs: 0. This
// one is the timely path: it reclaims when the kill lands rather than up to one sweep interval
// (<=30s) later, and it is the ONLY reclaim on a proxy with idle reaping off, where a
// Redis-delivered kill previously denied all traffic (fail-closed held) but left the
// subprocess, the session slot and the stream pinned until the process exited.
//
// Both go through reclaimKilledSession, so what "reclaiming a killed session" means has one
// definition, and both ask p.sessionKilled, so what "killed" means does too — including the
// agent dimension, which each session answers from its own claims.
//
// Sessions are snapshotted under the lock and closed outside it, concurrently: close() blocks
// up to shutdownMs on an unresponsive upstream, so a serial loop would let one slow upstream
// stall the reclaim of every other killed session. The batch is awaited so the sweep is
// complete on return.
func (p *HTTPProxy) reapKilledSessions() {
	p.mu.RLock()
	snapshot := make([]*httpSession, 0, len(p.sessions))
	for _, s := range p.sessions {
		snapshot = append(snapshot, s)
	}
	p.mu.RUnlock()
	var wg sync.WaitGroup
	for _, s := range snapshot {
		// Same spare the sweep applies: a session still inside its handshake + drift check
		// is not eligible on ANY arm, because tearing one down would race the establishment
		// path's own teardown. It is denied throughout, and reclaimed by the next trigger or
		// sweep once established.
		if s.initInProgress.Load() || !p.sessionKilled(s) {
			continue
		}
		wg.Add(1)
		go func(s *httpSession) {
			defer wg.Done()
			p.reclaimKilledSession(s)
		}(s)
	}
	wg.Wait()
}

// reclaimKilledSession tears down one session the kill switch names. Shared by the idle
// reaper's killed arm and the on-delivery sweep so a change to what reclaiming entails — the
// re-check, the stream eviction, the log line — cannot land on one and not the other.
func (p *HTTPProxy) reclaimKilledSession(s *httpSession) {
	// Re-checked immediately before teardown, for the same reason the idle arms re-check:
	// an operator who revived the kill between the snapshot and now should not lose the
	// session to this sweep.
	if !p.sessionKilled(s) {
		return
	}
	fmt.Fprintf(os.Stderr, "[eunox] HTTP session %s reaped (kill switch active for this session).\n", s.id)
	// Evict the SSE stream explicitly: the GET keepalive arm is not kill-gated, so a killed
	// session's open stream would otherwise survive its own teardown. The local kill path
	// evicts through the same call.
	s.evictStreams()
	s.close(p.shutdownMs)
}

// hardReapEligible reports whether a session past the hard idle ceiling may be torn
// down now. The hard ceiling exists to reclaim a session whose upstream call never
// returns. A call bounded by a finite --upstream-timeout ends on its own, so an
// in-flight call is spared here (returns false) to avoid killing a call within its
// configured budget — the failure mode when upstreamTimeout >= hardIdleMultiplier x
// idle. Only when the per-call budget is disabled (upstreamTimeMs <= 0, unbounded) is
// an in-flight call eligible, which is the ceiling's reason for existing. A session
// with no call in flight is always eligible.
func (p *HTTPProxy) hardReapEligible(s *httpSession) bool {
	return p.upstreamTimeMs <= 0 || s.inFlight.Load() == 0
}

// hasSubscribers reports whether the session has at least one active SSE
// subscriber (an open GET stream). The idle reaper uses it to spare sessions a host
// is actively listening on — a well-behaved host holds its GET open for the whole
// session to receive server-initiated requests. Such a session is spared the normal
// idle reaper but still subject to the hard idle ceiling (see reapOnce).
func (s *httpSession) hasSubscribers() bool {
	s.notifMu.Lock()
	defer s.notifMu.Unlock()
	return len(s.notifSubs) > 0
}

// closeAllSessions closes every active session (called during server shutdown).
func (p *HTTPProxy) closeAllSessions() {
	p.mu.Lock()
	// Latch shutdown BEFORE the snapshot/swap so any registerSession that has not yet
	// taken the lock fails closed (errShuttingDown) rather than inserting into the fresh
	// map after this reap. Set under the same lock the snapshot takes, so there is no
	// window between "empty the registry" and "reject new entries".
	p.shuttingDown = true
	sessions := make([]*httpSession, 0, len(p.sessions))
	for _, s := range p.sessions {
		sessions = append(sessions, s)
	}
	p.sessions = make(map[string]*httpSession)
	p.mu.Unlock()
	// Close concurrently: each s.close blocks up to shutdownMs on an unresponsive
	// upstream, so a serial loop would make shutdown O(N * shutdownMs). The WaitGroup
	// fan-out keeps it bounded to a single shutdownMs.
	var wg sync.WaitGroup
	for _, s := range sessions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.close(p.shutdownMs)
		}()
	}
	wg.Wait()
}

// reapKilledSession tears down a killed session's upstream and frees its maxSessions
// slot immediately, instead of relying on the idle reaper — which is not even running
// when sessionIdleTimeoutMs is 0 (a documented, valid config). Without this a killed
// session's subprocess/connection and its registry slot linger until process exit, and
// accumulated killed-but-undead sessions eventually exhaust maxSessions and make
// tryReserveSessionSlot 503 EVERY new initialize — a session-exhaustion DoS triggered by
// the kill switch itself. Mirrors handleMCPDelete's registry-delete-then-close teardown; a
// session already gone is a no-op. The kill store still independently blocks the session,
// so this only reclaims resources.
//
// Unlike reapAllKilledSessions, this has no analogous race with a session still
// establishing: sessionID is a freshly minted UUID an operator can only have learned by
// naming an ALREADY-registered session (registerSession publishes it, and only then does
// handleMCPPost return it in the Mcp-Session-Id response header) — there is no channel to
// leak an in-flight, not-yet-registered id for an operator to target here.
func (p *HTTPProxy) reapKilledSession(sessionID string) {
	p.mu.Lock()
	sess, ok := p.sessions[sessionID]
	if ok {
		delete(p.sessions, sessionID)
	}
	p.mu.Unlock()
	if ok {
		sess.close(p.shutdownMs)
	}
}

// reapAllKilledSessions tears down every active session after a global (emergency-stop)
// kill, freeing all upstreams and maxSessions slots without waiting on the idle reaper.
// Unlike closeAllSessions (server shutdown) it deliberately does NOT latch shuttingDown:
// the proxy keeps serving, so the registry stays usable (e.g. if the kill is later
// cleared) rather than being closed forever.
//
// CheckKill's pre-spawn gate is NOT sufficient on its own to prevent a registration
// racing this sweep: a session-creating initialize that passed CheckKill BEFORE this
// kill was activated can still be inside its (possibly slow, up to sessionStartTimeout)
// upstream handshake when this sweep runs, and would otherwise register into the fresh
// map afterward with a live upstream this sweep never saw — leaking an undead session
// (kill-store-denied but never torn down) exactly like the bug this reap fixes. Bumping
// reapGen here, under the same lock as the snapshot/swap, closes that window:
// registerSession compares against the startGen a session captured before its handshake
// began and rejects the insert if a sweep happened in between (see registerSession).
func (p *HTTPProxy) reapAllKilledSessions() {
	p.mu.Lock()
	p.reapGen++
	sessions := make([]*httpSession, 0, len(p.sessions))
	for _, s := range p.sessions {
		sessions = append(sessions, s)
	}
	p.sessions = make(map[string]*httpSession)
	p.mu.Unlock()
	var wg sync.WaitGroup
	for _, s := range sessions {
		wg.Add(1)
		go func(s *httpSession) {
			defer wg.Done()
			s.close(p.shutdownMs)
		}(s)
	}
	wg.Wait()
}

// evictStreams ends this session's open SSE notification stream(s) by closing the
// evicted signal, which every handleMCPGet loop selects on, so a killed session
// stops receiving upstream notifications immediately. Idempotent, and a no-op on a
// session assembled without the channel (minimal test constructions).
func (s *httpSession) evictStreams() {
	s.evictOnce.Do(func() {
		if s.evicted != nil {
			close(s.evicted)
		}
	})
}

// evictSessionStreams ends any open SSE notification stream on the named session so a
// per-session kill stops upstream notifications immediately, not just on the next
// (re)open attempt. A session that is already gone is a no-op.
func (p *HTTPProxy) evictSessionStreams(sessionID string) {
	if sess := p.getSession(sessionID); sess != nil {
		sess.evictStreams()
	}
}

// evictAllSessionStreams ends every session's open SSE notification stream, used by
// the global emergency stop. Sessions are snapshotted under the lock and evicted
// outside it; evictStreams only closes a channel and the woken SSE loops take
// s.notifMu (never p.mu), so this adds no new lock ordering.
func (p *HTTPProxy) evictAllSessionStreams() {
	p.mu.RLock()
	sessions := make([]*httpSession, 0, len(p.sessions))
	for _, s := range p.sessions {
		sessions = append(sessions, s)
	}
	p.mu.RUnlock()
	for _, s := range sessions {
		s.evictStreams()
	}
}

// initUpstream performs the MCP initialize handshake, bounded by ctx (the
// session-start deadline). The blocking pipe reads cannot observe ctx, so the
// handshake runs in a goroutine; on ctx expiry the subprocess is killed, which
// closes the pipe, unblocks the reader, and lets the goroutine exit.
func (s *httpSession) initUpstream(ctx context.Context) error {
	// handshakeStopped is closed by the goroutine below when runInitHandshake actually
	// returns — unconditionally, regardless of which arm of the select below fires — so a
	// caller that needs to know the pipe read has genuinely stopped (newSession's
	// failed-initialize reap, which must not call cmd.Wait while it hasn't) can join it
	// instead of assuming this function's own bounded wait covered that.
	s.handshakeStopped = make(chan struct{})
	done := make(chan error, 1)
	go func() {
		defer close(s.handshakeStopped)
		done <- s.runInitHandshake()
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		killUpstreamCmd(s.upCmd)
		// Bound the join independently, exactly as close() bounds its post-kill wait: the
		// kill EOFs the pipe almost immediately in the ordinary case, but a descendant that
		// escaped the process group (a double-fork, an explicit setsid, or a platform with
		// no process-group teardown at all) can still hold it open indefinitely, and an
		// unbounded join here would hang session establishment forever instead of failing
		// it — the grandchild-holds-the-pipe hang the other teardown paths in this package
		// are bounded against. THIS wait giving up does not mean the goroutine has stopped
		// reading the pipe — s.handshakeStopped, not this return, is what callers must join
		// before it is safe to reap the subprocess (see its doc).
		waitBounded(done, s.shutdownBudget(), "upstream initialize output stream")
		return fmt.Errorf("upstream did not complete initialize: %w", ctx.Err())
	}
}

// runInitHandshake writes the initialize request, waits for the matching
// response, and sends notifications/initialized.
func (s *httpSession) runInitHandshake() error {
	s.idCounter++
	req, initID := buildInitializeRequest(s.idCounter)
	if err := s.upWriter.Write(req); err != nil {
		return fmt.Errorf("sending initialize: %w", err)
	}

	resp, err := awaitStartupReply(s.upReader.Read, initID, s.upWriter, nil)
	if err != nil {
		return fmt.Errorf("reading initialize response: %w", err)
	}
	caps, sv, instructions, err := applyInitializeResult(resp)
	if err != nil {
		return err
	}
	s.upstreamCaps, s.upstreamServerVersion, s.upstreamInstructions = caps, sv, instructions

	notif, err := mcp.NotificationMsg(mcp.MethodNotificationsInitialized, nil)
	if err != nil {
		return err
	}
	return s.upWriter.Write(notif)
}

// readUpstream continuously reads from the upstream and routes messages: responses
// to waiting callUpstream callers, notifications and server-initiated requests to
// their handlers.
func (s *httpSession) readUpstream(ctx context.Context) {
	// On subprocess exit, cancel the teardown context BEFORE closing done, so an in-flight
	// awaitNonced (which selects on sessCtx via teardownDone) unblocks on a crash even when
	// close() is never called — the crash-cancellation s.done used to provide directly.
	defer close(s.done)
	defer s.sessCancel()
	for {
		msg, err := s.upReader.Read()
		if err != nil {
			// io.EOF is a normal stream end. Any other error (oversized message, JSON-RPC
			// parse failure) is abnormal; log it so an operator can tell it from a clean exit.
			if !errors.Is(err, io.EOF) {
				fmt.Fprintf(os.Stderr, "[eunox] HTTP session %s: upstream read error: %v\n", s.id, err)
			}
			return
		}
		if msg.IsNotification() {
			// A killed session must not keep receiving the upstream->host relay. The local
			// /control/kill path evicts SSE streams via handleKill, but a Redis-backed kill
			// (eunox kill --redis-addr) never calls handleKill on this instance — it learns
			// of the kill only through CheckKill/pubsub — so gate the broadcast here too,
			// mirroring the stdio transport. CheckKill reads the local cache (cheap) and
			// denies on a store error (fail closed); the drop is recorded for auditability.
			//
			// Dereferenced unconditionally, with no `s.route != nil` guard. handleMCPGet
			// rejects exactly that pattern in gate code for the reason it applies here:
			// production never builds a route-less session, so the branch can only ever be
			// taken by a test — and what it does when taken is SKIP a kill check and
			// broadcast, i.e. fail open in the one place this block exists to close. A
			// route-less session reaching here should panic like the construction bug it is.
			killCtx := ctx
			if s.claims != nil {
				killCtx = pdp.WithJWTClaims(killCtx, s.claims)
			}
			if deny := s.route.pdp.CheckKill(killCtx, s.id); deny != nil {
				recordKillDrop(killCtx, asRecorder(s.route.sink), deny, verifiedSession(s.id), msg.Method, msg.Method, legHTTPUpstreamNotification)
				continue
			}
			s.broadcast(msg)
			continue
		}
		// Server-initiated requests (e.g. sampling/createMessage, roots/list). A
		// message carrying BOTH an id and a method (IsRequest()) that echoes a LIVE
		// outstanding upstream nonce is NOT a server-initiated request — it is a
		// forged/confused reply to that in-flight call, and must be refused rather
		// than reclassified and relayed to the host. Route it to the waiting caller,
		// which refuses a method-bearing reply (awaitNonced's response-shape check),
		// mirroring the stdio transport's identical guard (stdio.go readUpstream).
		if msg.IsRequest() {
			s.pendingMu.Lock()
			_, liveNonce := s.byUpstreamID[mcp.MsgKey(msg.ID)]
			s.pendingMu.Unlock()
			if liveNonce {
				deliverUpstreamResponse(&s.pendingMu, s.byUpstreamID, msg)
				continue
			}
			s.dispatchUpstreamRequest(ctx, msg)
			continue
		}
		if msg.IsResponse() {
			// Route by the proxy-generated nonce the upstream echoes, not the host ID, so
			// a late response for a timed-out call (whose nonce entry was already removed)
			// cannot be misrouted into a later request reusing the same host ID.
			deliverUpstreamResponse(&s.pendingMu, s.byUpstreamID, msg)
		}
	}
}

// dispatchUpstreamRequest hands one server-initiated request to this session's
// serverRequestPool, which runs its handler on its own goroutine or refuses it when the pool is
// saturated. See serverRequestPool for why the handler must not run inline on readUpstream, and
// for the ordering guarantee this path deliberately gives up.
//
// The blast radius the move closes is one session rather than the whole proxy — readUpstream is
// this session's only response-delivery and SSE-relay goroutine, not the proxy's — which is why
// it landed after the stdio half, not why it was acceptable. Under a task-anchored route the
// turn holder can be a DIFFERENT session sharing the anchor, so the stall was not even bounded
// by its own session's traffic.
//
// The writer this leg reaches on refusal is the upstream subprocess pipe, already written from
// every host handler goroutine, and mcp.MsgWriter serializes whole frames under its own mutex.
// The forward path (broadcastServerRequest) was already called off this goroutine — the SSE
// write loop's failure path reaches the same tracker — and takes notifMu for the delivery plus
// the tracker's own lock for the id; the delivery-failure correction stays single-writer
// because serverReqTracker.take is what decides who writes it, and only one caller can take a
// given id.
//
// route is dereferenced unconditionally for the refusal record's sink, matching this file's
// notification leg and handleHTTPUpstreamRequest: production never builds a route-less session,
// and what a guard would buy when taken is a SKIPPED audit record.
func (s *httpSession) dispatchUpstreamRequest(ctx context.Context, msg mcp.RPCMsg) {
	s.serverPool.dispatch(ctx, msg, serverRequestDispatch{
		rec:           asRecorder(s.route.sink),
		sessionID:     s.id,
		writeUpstream: func(m mcp.RPCMsg) { _ = s.upWriter.Write(m) },
		handle:        func(hctx context.Context, m mcp.RPCMsg) { s.proxy.handleHTTPUpstreamRequest(hctx, s, m) },
	})
}

// callUpstream sends msg to the upstream and waits for the response: remote mode
// delegates to callRemoteUpstream, local mode uses the stdio framed-JSON pipe.
func (s *httpSession) callUpstream(ctx context.Context, msg mcp.RPCMsg) (mcp.RPCMsg, error) {
	if s.upHTTPClient != nil {
		return s.callRemoteUpstream(ctx, msg)
	}
	return s.callSubprocessUpstream(ctx, msg)
}

// withUpstreamTimeout bounds an upstream call with the proxy's
// --upstream-timeout.  The nil-proxy guard keeps zero-value sessions in tests
// working; production sessions always carry the proxy pointer.
func (s *httpSession) withUpstreamTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if s.proxy == nil {
		return ctx, func() {}
	}
	return s.proxy.withUpstreamTimeout(ctx)
}

// shutdownBudget is this session's configured teardown budget (the proxy's
// --shutdown-grace, shared with close()'s bound), or a 5s fallback for a
// proxy-less test-assembled session — the same default killDelay uses on the
// stdio side. initUpstream's post-kill wait uses it since, unlike close(), it is
// not handed shutdownMs by its caller.
func (s *httpSession) shutdownBudget() time.Duration {
	// Mirrors killDelay's clamp (stdio.go): shutdownMs <= 0 means "use the default"
	// (--shutdown-timeout=0 is documented as exactly that), not "wait zero time". A
	// proxy-less test-assembled session (nil proxy) falls back the same way.
	if s.proxy == nil || s.proxy.shutdownMs <= 0 {
		return 5 * time.Second
	}
	return msToDuration(s.proxy.shutdownMs)
}

// callSubprocessUpstream sends msg to the upstream subprocess via the stdio pipe
// and waits for the matching response, bounded by --upstream-timeout. The outbound
// message carries a nonce; the response is routed back through byUpstreamID so a
// late response for a timed-out call cannot be misrouted into a later request.
func (s *httpSession) callSubprocessUpstream(ctx context.Context, msg mcp.RPCMsg) (mcp.RPCMsg, error) {
	ctx, cancel := s.withUpstreamTimeout(ctx)
	defer cancel()
	// newSession initializes these, so this lazy init only fires for a session
	// assembled directly in a test; do it under pendingMu so the map-header write
	// cannot race the off-lock read in readUpstream/deliverUpstreamResponse.
	// hostToUp is initialized here too: awaitNonced receives the maps BY VALUE, and it
	// now both writes the correlation and reads the duplicate-ID set from it, so a nil
	// map would panic on exactly the test-assembled session this block accommodates.
	s.pendingMu.Lock()
	if s.byUpstreamID == nil {
		s.byUpstreamID = make(map[string]chan upstreamResult)
	}
	if s.hostToUp == nil {
		s.hostToUp = make(map[string]*json.RawMessage)
	}
	s.pendingMu.Unlock()
	// A write timeout (ErrUpstreamWriteTimeout) has already killed the subprocess via the
	// writer's onPoison hook (killSubprocess), which EOFs readUpstream and reaps the session;
	// awaitNonced just returns the error to the caller. The nonce-keyed transport-error
	// delivery path (deliverUpstreamError) is stdio-bridge-only and simply never fires here:
	// an HTTP session's remote-upstream failures already surface as callUpstream errors
	// (callRemoteUpstream), recorded as deny/UPSTREAM_ERROR.
	return awaitNonced(ctx, &s.pendingMu, s.byUpstreamID, s.hostToUp, &s.upstreamSeq, s.teardownDone(), mcp.MsgKey(msg.ID),
		func(id *json.RawMessage) { msg.ID = id },
		func() error { return s.upWriter.Write(msg) })
}

// killSubprocess force-kills the session's upstream subprocess. It is the MsgWriter's
// onPoison hook: when a bounded pipe write times out (the upstream stopped draining its
// stdin), the desynced stream cannot be reused, so killing the subprocess EOFs readUpstream,
// fires close(done), and lets the cleanup goroutine reap the session (sessCancel, via
// readUpstream's defer, then unblocks any other in-flight call). A no-op for a remote-HTTP
// session (nil upCmd) or a not-yet-started one; idempotent, because killUpstreamProcess
// signals the direct child through os.Process first and aborts if that reports the process
// already reaped — so a call racing a completed Wait sends nothing at all.
func (s *httpSession) killSubprocess() {
	killUpstreamCmd(s.upCmd)
}

// teardownDone returns the session's teardown-cancellation channel for awaitNonced: the
// sessCtx.Done() channel that close() cancels (and readUpstream cancels on subprocess
// exit), unifying local in-flight-call cancellation with the remote path onto sessCtx.
// sessCtx is always live — newSession/newRemoteSession set it, and tests build sessions
// through newTestSession — so this reads it unconditionally.
func (s *httpSession) teardownDone() <-chan struct{} {
	return s.sessCtx.Done()
}

// forwardNotification sends a notification to the upstream.
// Remote mode: HTTP POST. Local mode: stdio write.
func (s *httpSession) forwardNotification(ctx context.Context, msg mcp.RPCMsg) {
	if s.upHTTPClient != nil {
		// Remote-HTTP upstream: host ids are forwarded unchanged, so a cancel already
		// correlates -- do not rewrite it.
		//
		// Bound the POST at notifyPostTimeout independent of --upstream-timeout, which
		// callRemoteUpstream already applies via withUpstreamTimeout but is a no-op
		// under --upstream-timeout=0. This forward now holds one of the session's
		// notifySem slots (http_routing.go's tryAcquireNotifySlot) while it runs, so
		// with the per-call timeout disabled a stalling upstream could otherwise pin
		// that slot indefinitely and starve OTHER notifications on the same session
		// (notifySem is its own pool, deliberately not shared with enforced-request
		// capacity — see notifySem's doc comment — so this cannot starve enforced
		// requests, only further notification delivery). Mirrors the stdio bridge's
		// identical notifyPostTimeout bound (stdio_http_upstream.go), which exists for
		// the same reason.
		notifyCtx, cancel := context.WithTimeout(ctx, notifyPostTimeout)
		defer cancel()
		if _, err := s.callRemoteUpstream(notifyCtx, msg); err != nil {
			// Notification: no response to deliver to the host. Log the POST failure so
			// a dropped notifications/cancelled or other forwarded notification is not
			// silent, mirroring the stdio-bridge's httpUpstream.post logging.
			fmt.Fprintf(os.Stderr, "[eunox] HTTP session %s: notification %q POST to upstream failed: %v\n", s.id, msg.Method, err)
		}
		return
	}
	// Subprocess upstream: the request id was nonce-rewritten, so translate a
	// cancel's params.requestId to that nonce; drop it if the target request is no
	// longer in flight.
	//
	// Cancellation is best-effort on HTTP. Unlike stdio's single serve loop (which
	// orders a cancel behind the request it targets via the fwdHostWrites barrier),
	// each HTTP POST is an independent handler goroutine, so a cancel delivered on a
	// separate concurrent connection can be processed before the target request's
	// handler has run awaitNonced to populate hostToUp. In that (narrow, client-driven)
	// race the mapping is absent and the cancel is dropped — matching the MCP spec,
	// which treats notifications/cancelled as inherently racy (it may arrive after the
	// request already completed). A real client sends the request, then later cancels
	// it over the same keep-alive connection, which serializes the two; the race needs
	// genuinely-concurrent delivery of a request and its own cancel.
	if msg.Method == methodNotificationsCancelled {
		rewritten, ok := rewriteCancelToNonce(&s.pendingMu, s.hostToUp, msg)
		if !ok {
			return
		}
		msg = rewritten
	}
	_ = s.upWriter.Write(msg)
}

// inFlightDrainPoll is how often releaseSessionState re-checks the in-flight counter
// while waiting for enforced decisions to drain before it releases flow state.
const inFlightDrainPoll = 2 * time.Millisecond

// releaseSessionState releases a torn-down session's per-session enforcement state (its
// accumulated flow-label set) via the route's PDP, so an ended session retains nothing
// and a reused session id starts clean. It is called
// from the cleanup goroutine that runs after <-sess.done on EVERY teardown — idle reap,
// DELETE, kill, shutdown, and natural subprocess exit — so it covers the paths
// httpSession.close() alone does not (close() is skipped on a natural upstream exit).
//
// It first waits for in-flight enforced decisions to finish (bounded), so a teardown
// Clear cannot empty the session's taint BETWEEN a source's committed Add and a sink
// still deciding on the same session — the fail-open a teardown racing live decisions
// would otherwise open. The wait is bounded by the session shutdown budget so a
// wedged handler cannot pin teardown; a Redis store reclaims an orphaned key by idle TTL
// if we time out. The Clear itself uses a detached, bounded context (teardown must not
// block on a slow store). A no-op when the policy uses no flow control (ReleaseSession
// self-guards) or the route is unset (defensive).
func releaseSessionState(sess *httpSession) {
	if sess.route == nil {
		return
	}
	// shutdownBudget, not a second inline derivation: it is the nil-proxy-safe,
	// zero-means-default clamp this file already defines, and re-deriving it here
	// dereferenced sess.proxy unconditionally (a nil-proxy test session panics) and read
	// shutdownMs <= 0 as "wait zero time" — a teardown that skips the in-flight drain
	// entirely, which is the fail-open the drain exists to close.
	budget := sess.shutdownBudget()
	sess.awaitInFlightDrained(budget)
	// And for the server-initiated handlers, which run on their own goroutines rather than on
	// the reader whose exit got us here: one still in flight would write its audit record into
	// a sink whose route may already be shutting down, and could read flow state the release
	// below has just cleared. Same concern as the host-decision drain above, same bound; the
	// stdio transport does this at its own teardown (awaitServerRequestsDrained).
	sess.serverPool.drain(budget)
	// The decision gate held for this session's life goes back here, beside the flow-state
	// release and AFTER the in-flight drain, for both of this function's reasons. It has to
	// be on the funnel that covers every teardown — a session whose upstream exits on its own
	// never reaches close(), so releasing there retained one gate per such session for the
	// proxy's life, which is exactly the accumulation the registry's refcounting exists to
	// prevent. And it has to be after the drain: dropping the last reference deletes the gate
	// from the registry, so a request still taking turns on it would be holding a gate a later
	// caller under the same key could no longer reach.
	if sess.dropDecideGate != nil {
		sess.dropDecideGate()
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	sess.route.pdp.ReleaseSession(ctx, sess.id)
}

// awaitInFlightDrained blocks until this session has no enforced request in flight, or
// until timeout elapses. In-flight enforced requests may still be mid-decision when
// teardown begins (sess.done is closed for the session, but a request that already passed
// getSession runs to completion against its own request context), so releasing flow state
// before they finish could drop a live taint (see releaseSessionState). Bounded and
// poll-based: teardown is off the hot path, and the wait must never be unbounded on a
// wedged handler.
//
// Residual (bounded, accepted): inFlight is incremented in handleSessionPost only AFTER
// getSession, the session-security gates, and the request-slot acquire (http_routing.go),
// so a request in that pre-count window is invisible here and the drain could observe zero
// and Clear before it runs its decision. The window contains no flow read or write (the
// PDP Decide, hence any peek/Add, happens after the increment), and it is only reachable
// while the session is already tearing down (DELETE, idle reap, or upstream exit) — so the
// worst case is one audit-fidelity false-allow on a session whose forward target is itself
// going away, never a taint stranded for a live session. Closing it fully would mean
// counting the request before the gates, entangling this with the idle reaper's inFlight
// read; not worth that lifecycle risk for a dying-session edge. stdio has no analogue: its
// counter is bumped in the single-threaded reader before dispatch (StdioProxy.awaitHostDecisionsDrained).
func (s *httpSession) awaitInFlightDrained(timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for s.inFlight.Load() > 0 {
		if !time.Now().Before(deadline) {
			return
		}
		time.Sleep(inFlightDrainPoll)
	}
}

// close shuts down the session.
// Remote mode: signals the done channel directly (no subprocess).
// Local mode: closes the subprocess stdin pipe and waits for it to exit,
// sending SIGKILL after shutdownMs milliseconds if it has not.
func (s *httpSession) close(shutdownMs int) {
	s.closeOnce.Do(func() {
		// Cancel the session-scoped teardown context first, so every in-flight call —
		// remote (callRemoteUpstream's context.AfterFunc) and local (awaitNonced's select on
		// teardownDone) — unblocks at once as the session tears down, through the one shared
		// primitive. The done-channel handling below is now purely lifecycle: reap the
		// subprocess (local) or release the connection pool (remote).
		s.sessCancel()
		if s.upHTTPClient != nil {
			// Remote mode: no subprocess. Terminate the upstream MCP session with a bounded
			// DELETE so the remote frees its session state rather than leaking it, only when
			// a session was actually established (route set and an upstream session ID
			// captured). The *http.Transport (connection pool) is SHARED across the route's
			// sessions, so it is deliberately NOT closed here — dropping it on one session's
			// teardown would evict warm connections other sessions are using. Idle
			// connections are bounded by the transport's IdleConnTimeout/MaxIdleConnsPerHost
			// and released wholesale at proxy shutdown (UpstreamRoute.closeIdleUpstreamConns).
			if s.upstreamSessID != "" && s.route != nil {
				DeleteMCPHTTPSession(s.upHTTPClient, s.mcpEndpointURL(), s.upstreamSessID, s.route.upstreamAuthHeader)
			}
			close(s.done)
			return
		}
		// nil-guarded like every sibling teardown path: a test-assembled session may
		// carry no upstream stdin pipe.
		if s.upIn != nil {
			_ = s.upIn.Close()
		}
		t := time.NewTimer(msToDuration(shutdownMs))
		defer t.Stop()
		select {
		case <-s.done:
		case <-t.C:
			killUpstreamCmd(s.upCmd)
			// Bound the post-kill wait independently. readUpstream closes done on pipe
			// EOF, which follows the SIGKILL almost immediately — unless it is wedged in
			// a slow PDP/kill-store call (those carry their own timeouts and will return
			// on their own). Without this second bound a wedged reader would hold the
			// session registry, the idle reaper, and any in-flight DELETE hostage well
			// past the shutdown deadline. The subprocess is already killed; abandoning
			// the wait only leaves the reader goroutine to drain and exit on its own.
			waitBounded(s.done, msToDuration(shutdownMs), "upstream output stream")
		}
	})
}

// broadcast delivers a notification to all active SSE subscribers (true fan-out).
// A slow subscriber (full buffer) is skipped — dropping is correct for a
// notification. Server-initiated requests use deliverToOne instead (single
// recipient).
func (s *httpSession) broadcast(msg mcp.RPCMsg) {
	s.notifMu.Lock()
	defer s.notifMu.Unlock()
	for _, ch := range s.notifSubs {
		select {
		case ch <- msg:
		default:
			// Slow subscriber: channel full, notification dropped. Track and warn on the
			// first drop so a lost tools/list_changed is observable, not silent.
			if s.droppedNotifs.Add(1) == 1 {
				fmt.Fprintf(os.Stderr,
					"[eunox] WARNING: HTTP session %s dropped a notification (method=%q) to a slow SSE subscriber; further drops counted but not individually logged.\n",
					s.id, msg.Method)
			}
		}
	}
}

// broadcastServerRequest tracks a server-initiated request's ID and delivers it to
// one SSE subscriber, reporting whether the host can service it. The host's
// response (same ID) is later routed back to the upstream by handleMCPPost.
//
// Such a request (sampling/createMessage, roots/list, …) blocks the upstream until
// the host responds, so if no subscriber can receive it the upstream would hang
// until teardown. Dropping is fine for a notification but a silent fail-open for a
// request, so fail closed: untrack the ID, reply a JSON-RPC error to the upstream
// so it unblocks, and return false so the caller audits a delivery failure.
func (s *httpSession) broadcastServerRequest(msg mcp.RPCMsg) bool {
	if msg.ID != nil {
		s.serverReqs.track(mcp.MsgKey(msg.ID))
	}
	if s.deliverToOne(msg) {
		return true
	}
	if msg.ID != nil {
		s.serverReqs.take(mcp.MsgKey(msg.ID))
		if s.upWriter != nil {
			_ = s.upWriter.Write(mcp.ErrorResponse(msg.ID, capability.JSONRPCCodeEnforcementError,
				"no client stream available to service server-initiated request"))
		}
	}
	return false
}

// deliverToOne delivers a message to exactly one active SSE subscriber, reporting
// whether one accepted it. A server-initiated request expects a single recipient
// and a single response; broadcasting it would copy the sampling payload to
// unintended streams and let multiple clients race to answer the same JSON-RPC id.
// It sends to the first subscriber with buffer room; on none, returns false so
// broadcastServerRequest fails closed.
func (s *httpSession) deliverToOne(msg mcp.RPCMsg) bool {
	s.notifMu.Lock()
	defer s.notifMu.Unlock()
	for _, ch := range s.notifSubs {
		select {
		case ch <- msg:
			return true
		default:
			// Buffer full; try the next subscriber rather than drop, so one slow stream
			// does not starve the upstream.
		}
	}
	return false
}

// sseSubscriberBufferSize is the buffer depth of one SSE subscriber's delivery
// channel. It bounds how many server-initiated requests / notifications may queue
// for a single open GET stream before back-pressure applies: broadcast() drops an
// excess notification (counted via droppedNotifs), while deliverToOne /
// broadcastServerRequest fail an excess server-initiated request closed (an error
// reply to the upstream) rather than block the reader. Sized for a well-behaved
// single-stream host with slack for short bursts; a constant, not a config knob, to
// keep the back-pressure model small.
const sseSubscriberBufferSize = 16

// maxSubsPerSession caps concurrent SSE subscribers (open GET streams) on one
// session. A well-behaved host opens a single stream; the cap bounds per-session
// subscriber-list and channel-buffer memory against a client that opens many.
const maxSubsPerSession = 8

// addSub registers an SSE subscriber channel, returning false (and registering
// nothing) when the session is already at maxSubsPerSession so the caller can
// reject the stream.
func (s *httpSession) addSub(ch chan mcp.RPCMsg) bool {
	s.notifMu.Lock()
	defer s.notifMu.Unlock()
	if len(s.notifSubs) >= maxSubsPerSession {
		return false
	}
	s.notifSubs = append(s.notifSubs, ch)
	return true
}

func (s *httpSession) removeSub(ch chan mcp.RPCMsg) {
	s.notifMu.Lock()
	defer s.notifMu.Unlock()
	for i, c := range s.notifSubs {
		if c != ch {
			continue
		}
		// Shift left and zero the stale tail slot before reslicing: a plain
		// append(s[:i], s[i+1:]...) would leave the last channel double-referenced in
		// the backing array, holding it (and the session) off GC.
		n := len(s.notifSubs)
		copy(s.notifSubs[i:], s.notifSubs[i+1:])
		s.notifSubs[n-1] = nil
		s.notifSubs = s.notifSubs[:n-1]
		return
	}
}

// removeSubAndDrain unsubscribes ch, then replies an error upstream for any
// server-initiated request still buffered in ch. handleMCPGet defers this when an
// SSE stream exits (client disconnect or teardown). removeSub runs first to stop new
// deliveries; since both take notifMu, once it returns the buffer holds the complete
// set of missed messages.
//
// Each buffered request holds a tracked ID whose upstream is blocked awaiting a
// response the departed client will never POST; without this drain the upstream
// stays wedged until the idle reaper. take() untracks the ID and the error reply
// unblocks the upstream, mirroring broadcastServerRequest's fail-closed path.
// Buffered notifications (no ID) are dropped. Remote-upstream sessions have a nil
// upWriter and issue no server-initiated requests, so the arms are inert there.
//
// Only requests still buffered in ch are recovered. One already streamed to the
// client and then abandoned keeps its tracked ID and relies on the idle reaper.
//
// ctx is the caller's ambient request context (handleMCPGet's r.Context()), captured
// at defer time so it is not stale by the time this runs. It is used only to carry
// JWT claims onto the correction audit record (context.Value survives cancellation),
// never for cancellation/deadline control here — draining a buffered channel and
// writing a bounded local record cannot block on an external resource.
func (s *httpSession) removeSubAndDrain(ctx context.Context, ch chan mcp.RPCMsg) {
	s.removeSub(ch)
	for {
		select {
		case msg := <-ch:
			s.failServerRequestDelivery(ctx, msg, "client disconnected before responding to server-initiated request")
		default:
			return
		}
	}
}

// failServerRequestDelivery unblocks the upstream when a server-initiated request
// already consumed from a subscriber channel cannot be relayed to the host (client
// disconnected with it buffered, or it failed to serialize). It untracks the ID and
// replies an error so the upstream does not hang. A notification (msg.ID == nil) and
// a remote-upstream session (no upWriter) are no-ops. Shared by the SSE write loop
// and the drain path so a tracked server request always eventually gets a response.
//
// ctx is the caller's ambient request context, used only as the claims carrier for
// the correction audit record below (see removeSubAndDrain); it is not used for
// cancellation here, so a context already canceled by client disconnect is fine.
func (s *httpSession) failServerRequestDelivery(ctx context.Context, msg mcp.RPCMsg, reason string) {
	if msg.ID == nil || !s.serverReqs.take(mcp.MsgKey(msg.ID)) {
		return
	}
	if s.upWriter != nil {
		_ = s.upWriter.Write(mcp.ErrorResponse(msg.ID, capability.JSONRPCCodeEnforcementError, reason))
	}
	// This request was recorded as an allow when deliverToOne buffered it onto a
	// subscriber channel (recordForwardOutcome, forward.go), but it never reached the
	// host. Append a correction so the tamper-evident tape does not stand as claiming
	// delivery that did not happen — the record-before-act legs write records eagerly,
	// and this is the matching correction on the async delivery-failure path. Attach
	// the session's claims (the same pattern forwardServerRequest uses in forward.go)
	// so agent_id/task_id match the original allow; s.route is non-nil in production,
	// the guard covers a test-assembled session.
	if s.route != nil {
		if s.claims != nil {
			ctx = pdp.WithJWTClaims(ctx, s.claims)
		}
		s.route.sink.RecordDeny(ctx, s.id, msg.Method, msg.Method, capability.ErrCodeEnforcementError, "",
			map[string]interface{}{"transport": "http-server-request-undelivered"}, false)
	}
}
