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

	// pendingMu guards pending, byUpstreamID, hostToUp, and upstreamSeq.
	pendingMu sync.Mutex
	// pending is keyed by the host's JSON-RPC ID solely to reject a duplicate
	// in-flight host ID. It does NOT route upstream responses (byUpstreamID's job).
	pending map[string]chan upstreamResult
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
	// updated on every POST and on opening/holding a GET (SSE) stream. The idle
	// reaper compares it against sessionIdleMs. Atomic so the reaper reads it without
	// the proxy lock.
	lastActive atomic.Int64

	// lastRequest is the Unix-nanosecond time of the most recent host *request* (an
	// /mcp POST), unlike lastActive which also advances on SSE liveness. It backs the
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
	// return — grows goroutines and the pending / byUpstreamID maps without bound on
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
		return true
	default:
		return false
	}
}

// releaseRequestSlot releases one in-flight request slot acquired via
// tryAcquireRequestSlot. Must be called exactly once per successful acquire.
func (s *httpSession) releaseRequestSlot() { <-s.reqSem }

// touch records host interaction (e.g. opening or holding an SSE stream),
// deferring the normal idle reaper. It advances lastActive only, NOT lastRequest,
// so SSE liveness alone cannot defer the hard idle ceiling. Goroutine-safe.
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
// from the identity that created this session, so a re-initialize from it must be
// refused. The re-initialize echo returns the upstream capabilities and serverInfo
// captured at creation, so only the creating client may receive them; a second identity
// authenticated to the same route (same audience pin, different sub) that learns the
// session id must not read another client's captured state.
//
// A session created without a JWT identity (claims nil or no subject) is UNBOUND —
// there is no per-client identity to enforce (e.g. a no-JWT route where every client is
// anonymous) — so it never mismatches. Identity is the (issuer, subject) pair: sub is
// unique only within an issuer, so both are compared, and as separate fields (never a
// concatenation, which could collide across values). A refreshed token from the same
// principal (new jti/exp, same iss+sub) still matches; a different principal does not.
func (s *httpSession) ownerMismatch(cur *pdp.JWTClaims) bool {
	if s.claims == nil || s.claims.Subject == "" {
		return false // unbound: no creating identity to enforce
	}
	if cur == nil {
		return true // bound session, but the request carries no identity
	}
	return cur.Issuer != s.claims.Issuer || cur.Subject != s.claims.Subject
}

// newSession spawns an upstream subprocess and performs the MCP initialize
// handshake. The session is registered in p.sessions before readUpstream starts so
// the cleanup goroutine finds it even if the subprocess exits immediately.
func (p *HTTPProxy) newSession(ctx context.Context, route *UpstreamRoute, clientIP string) (*httpSession, error) {
	// Captured BEFORE the (possibly slow) subprocess spawn + handshake below, so
	// registerSession can detect a global kill's reapAllKilledSessions sweeping the
	// registry during that window — see the reapGen field comment.
	startGen := p.currentReapGen()
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
		pending:      make(map[string]chan upstreamResult),
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
	cmd.Stderr = os.Stderr

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
		_ = cmd.Process.Kill()
		// Reap so a failed initialize leaves no zombie. initUpstream has joined its
		// handshake goroutine, so all pipe reads are done and Wait is safe.
		_ = cmd.Wait()
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
		_ = cmd.Process.Kill()
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
	go func() {
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
			if sess.upCmd.Process != nil {
				_ = sess.upCmd.Process.Kill()
			}
			<-waited
		}
		p.mu.Lock()
		delete(p.sessions, sess.id)
		p.mu.Unlock()
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
	if err := route.driftCheck(raw, sess.upstreamServerVersion, probeErr); err != nil {
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
	now := time.Now().UnixNano()
	sess.lastActive.Store(now)
	// Seed lastRequest so the hard idle ceiling is measured from creation: the
	// initialize POST counts as the first host request.
	sess.lastRequest.Store(now)
	p.sessions[sess.id] = sess
	return nil
}

// getSession returns the session for id, or nil.
func (p *HTTPProxy) getSession(id string) *httpSession {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.sessions[id]
}

// sessionCount returns the number of active sessions (for the health/metrics
// endpoints and the cheap pre-spawn capacity check).
func (p *HTTPProxy) sessionCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.sessions)
}

// atSessionCap reports whether the session cap is currently reached. Best-effort:
// used to refuse an initialize before spawning an upstream. registerSession makes
// the cap authoritative against races.
func (p *HTTPProxy) atSessionCap() bool {
	if p.maxSessions <= 0 {
		return false
	}
	return p.sessionCount() >= p.maxSessions
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
	// staleSession pairs a reaped session with whether it tripped the hard ceiling,
	// so the log line can name the reason; both share the close path.
	type staleSession struct {
		s    *httpSession
		hard bool
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
		// eligible for reaping: it is registered but has no subscribers and a stale
		// lastActive while the drift check blocks, which would otherwise read as idle.
		if s.initInProgress.Load() {
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
				fmt.Fprintf(os.Stderr, "[eunox] HTTP session %s reaped (idle > %s).\n", s.id, time.Duration(p.sessionIdleMs)*time.Millisecond)
			}
			s.close(p.shutdownMs)
		}()
	}
	wg.Wait()
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
// atSessionCap 503 EVERY new initialize — a session-exhaustion DoS triggered by the kill
// switch itself. Mirrors handleMCPDelete's registry-delete-then-close teardown; a
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
	done := make(chan error, 1)
	go func() { done <- s.runInitHandshake() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		if s.upCmd != nil && s.upCmd.Process != nil {
			_ = s.upCmd.Process.Kill()
		}
		<-done // join the handshake goroutine; its pipe read fails after the kill
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

	for {
		msg, err := s.upReader.Read()
		if err != nil {
			return fmt.Errorf("reading initialize response: %w", err)
		}
		if msg.IsResponse() && mcp.MsgKey(msg.ID) == mcp.MsgKey(initID) {
			caps, sv, instructions, err := applyInitializeResult(msg)
			if err != nil {
				return err
			}
			s.upstreamCaps, s.upstreamServerVersion, s.upstreamInstructions = caps, sv, instructions
			break
		}
		// A discarded server-initiated REQUEST (sampling/createMessage, roots/list,
		// elicitation/create) arriving before the initialize response would leave the
		// upstream blocked awaiting a response: runInitHandshake runs before
		// readUpstream starts, so nothing else will answer it.
		RejectPreInitServerRequest(s.upWriter, msg)
	}

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
			// s.route is non-nil in production; the guard covers a test-assembled session.
			if s.route != nil && s.route.pdp != nil {
				killCtx := ctx
				if s.claims != nil {
					killCtx = pdp.WithJWTClaims(killCtx, s.claims)
				}
				if deny := s.route.pdp.CheckKill(killCtx, s.id); deny != nil {
					recordKillDrop(killCtx, asRecorder(s.route.sink), deny, s.id, msg.Method, msg.Method, legHTTPUpstreamNotification)
					continue
				}
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
			s.proxy.handleHTTPUpstreamRequest(ctx, s, msg)
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

// callSubprocessUpstream sends msg to the upstream subprocess via the stdio pipe
// and waits for the matching response, bounded by --upstream-timeout. The outbound
// message carries a nonce; the response is routed back through byUpstreamID so a
// late response for a timed-out call cannot be misrouted into a later request.
func (s *httpSession) callSubprocessUpstream(ctx context.Context, msg mcp.RPCMsg) (mcp.RPCMsg, error) {
	ctx, cancel := s.withUpstreamTimeout(ctx)
	defer cancel()
	// newSession initializes byUpstreamID, so this lazy init only fires for a session
	// assembled directly in a test; do it under pendingMu so the map-header write
	// cannot race the off-lock read in readUpstream/deliverUpstreamResponse.
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
	return awaitNonced(ctx, &s.pendingMu, s.pending, s.byUpstreamID, s.hostToUp, &s.upstreamSeq, s.teardownDone(), mcp.MsgKey(msg.ID),
		func(id *json.RawMessage) { msg.ID = id },
		func() error { return s.upWriter.Write(msg) })
}

// killSubprocess force-kills the session's upstream subprocess. It is the MsgWriter's
// onPoison hook: when a bounded pipe write times out (the upstream stopped draining its
// stdin), the desynced stream cannot be reused, so killing the subprocess EOFs readUpstream,
// fires close(done), and lets the cleanup goroutine reap the session (sessCancel, via
// readUpstream's defer, then unblocks any other in-flight call). A no-op for a remote-HTTP
// session (nil upCmd) or a not-yet-started one; idempotent (Process.Kill on a reaped process
// just returns an ignored error).
func (s *httpSession) killSubprocess() {
	if s.upCmd != nil && s.upCmd.Process != nil {
		_ = s.upCmd.Process.Kill()
	}
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
		_ = s.upIn.Close()
		t := time.NewTimer(msToDuration(shutdownMs))
		defer t.Stop()
		select {
		case <-s.done:
		case <-t.C:
			if s.upCmd != nil && s.upCmd.Process != nil {
				_ = s.upCmd.Process.Kill()
			}
			// Bound the post-kill wait independently. readUpstream closes done on pipe
			// EOF, which follows the SIGKILL almost immediately — unless it is wedged in
			// a slow PDP/kill-store call (those carry their own timeouts and will return
			// on their own). Without this second bound a wedged reader would hold the
			// session registry, the idle reaper, and any in-flight DELETE hostage well
			// past the shutdown deadline. The subprocess is already killed; abandoning
			// the wait only leaves the reader goroutine to drain and exit on its own.
			t2 := time.NewTimer(msToDuration(shutdownMs))
			defer t2.Stop()
			select {
			case <-s.done:
			case <-t2.C:
			}
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
