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
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/eunolabs/eunox/internal/audit"
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
	// route is set once before the session is published into p.sessions and never
	// reassigned, which is what makes the lock-free sess.route != route checks in
	// handleMCPPost/handleMCPGet race-free.
	route *UpstreamRoute

	// Local subprocess fields (nil in remote mode).
	upCmd    *exec.Cmd
	upIn     io.WriteCloser
	upWriter *mcp.MsgWriter
	upReader *mcp.MsgReader

	// Remote HTTP upstream fields (nil in local mode). A non-nil upHTTPClient is the
	// authoritative "this session is remote" test; the endpoint is read from
	// route.upstreamURL (see mcpEndpointURL), never copied onto the session.
	upHTTPClient   *http.Client
	upstreamSessID string // Mcp-Session-Id returned by the remote upstream

	// pendingMu guards byUpstreamID, hostToUp, and upstreamSeq.
	pendingMu sync.Mutex
	// byUpstreamID routes upstream responses back to the waiting caller, keyed by the
	// proxy-generated nonce, so a late response for a timed-out call can't be
	// misrouted into a later request reusing the same host ID.
	byUpstreamID map[string]chan upstreamResult
	// hostToUp maps a live request's host ID to the nonce on the wire, so a host
	// notifications/cancelled can translate params.requestId. Only the subprocess
	// path nonce-rewrites; the remote-HTTP path forwards host ids unchanged.
	hostToUp map[string]*json.RawMessage
	// upstreamSeq is the monotonic nonce source for upstream IDs.
	upstreamSeq uint64

	// serverReqs tracks server-initiated requests broadcast over SSE, so
	// handleMCPPost can route the host's POSTed response back to the upstream
	// instead of dropping it (which would hang the upstream).
	serverReqs serverReqTracker

	// upstreamDenies bounds the refusal records THIS session's upstream can drive (see
	// newUpstreamRefusalLimiter). Per session because each session has its own upstream, and the
	// proxy-wide table let one dead subprocess drain a category's share and suppress a sibling
	// session's record that a live in-flight request was lost. nil on a bare-struct-literal
	// session (as tests build), which records unbounded rather than panicking.
	upstreamDenies *categoryRecordLimiter

	// noticeFloor is this session's reserved diagnostic line per notice class, spent only where
	// the ROUTE's bucket refuses (see noticeReserve). The notice half's answer to the same
	// question upstreamDenies answers for records, one mechanism weaker on purpose: a session gets
	// an arrival rather than a rate, since what a sibling's flood takes from an operator is the
	// first line saying this session's upstream is down too. Zero value ready.
	noticeFloor noticeReserve

	upstreamCaps          map[string]interface{}
	upstreamServerVersion string // version from the upstream initialize serverInfo response
	upstreamInstructions  string // instructions from the upstream initialize response
	idCounter             int64

	// upstreamRev is the protocol revision this session speaks to its upstream, decided at
	// CONSTRUCTION from the route's pin (UpstreamOpenRevision) and read-only after — it picks
	// the opener, so it cannot be a conclusion drawn from the opener's own reply. hostRev is
	// the revision the HOST context was opened at. The two are separate because host and
	// upstream migrate independently, and bridging that gap is what a proxy is for.
	//
	// Copied from the route rather than read through it, so the open has no route dependency
	// and a bare upstream leg stays exercisable on its own.
	upstreamRev capability.Revision
	hostRev     capability.Revision

	// claims holds the JWT claims validated at initialize, or nil if none. Server-initiated
	// decisions (e.g. sampling/createMessage) have no host request in scope, so they're
	// attributed to these claims instead.
	claims *pdp.JWTClaims

	// clientIP is captured at initialize; it's what an ipRange condition on the sampling
	// opt-in evaluates against, since server-initiated sampling has no host request in scope.
	clientIP string

	// No per-session decision mutex: the turn is keyed on the state ANCHOR and handed out by
	// the route (UpstreamRoute.decideGates), since task-anchored state can have two sessions
	// share one key. decideGate is a lock-free CACHE of one registry entry (round-tripping the
	// route's mutex/map per call was too costly on the hot path); decideAnchor is the anchor
	// it was resolved for, compared by every request to detect a cache hit vs. miss.
	//
	// The pin is written once at registration and never re-pointed: moving it would let the
	// registry reclaim and rebuild the gate under a request that read the old pointer and
	// hasn't taken its turn yet — two gates for one anchor is not slow, it's unserialized.
	//
	// nil on a non-serialized route or an unregistered test session; both fall back to the
	// registry path.
	decideAnchor enforcement.StateAnchor
	decideGate   *anchorGate
	// decideCache holds gates for anchors OTHER than the pinned one, needed when a
	// task-anchored session spans tasks (the pin can't be re-pointed to chase that — see
	// session_gate_cache.go for the reference counting that makes eviction safe).
	// Zero value ready; allocates nothing for a session that never spans.
	decideCache gateCache
	// dropDecideGate releases the pinned gate at teardown so a long-lived gateway doesn't
	// accumulate one gate per session ever served. nil when none held; idempotent.
	dropDecideGate func()

	// spanned records that a host request on this session resolved a state anchor OTHER than
	// the one its server-initiated leg decides against. Sticky and one-way, since the taint
	// outlives the request that set it. Only ever true on a task-anchored route; see
	// noteRequestAnchor.
	spanned atomic.Bool

	notifMu   sync.Mutex
	notifSubs []chan mcp.RPCMsg

	// droppedNotifs counts notifications dropped by a full subscriber SSE channel, so a lost
	// tools/list_changed etc. is observable rather than silent. Atomic: no extra locking under
	// broadcast's notifMu.
	droppedNotifs atomic.Uint64

	closeOnce sync.Once
	// done signals the upstream's lifecycle end (distinct from sessCtx's teardown-cancellation):
	// closed by readUpstream on exit (local) or close() (remote); the cleanup goroutine waits
	// on it to reap the subprocess and delete the session-map entry.
	done chan struct{}

	// handshakeStopped closes once runInitHandshake's goroutine actually returns.
	// initUpstream's post-kill wait is bounded, but os/exec forbids calling cmd.Wait while a
	// StdoutPipe read is still in flight (Wait closes the same pipe), so newSession's
	// failed-initialize reap joins this first, in the background, before calling cmd.Wait.
	handshakeStopped chan struct{}

	// sessCtx is the session's single teardown-cancellation signal, canceled by close(); both
	// transports derive their in-flight-call cancellation from it (remote via
	// context.AfterFunc, local via awaitNonced's select, and readUpstream also cancels it on
	// subprocess exit so a crash unblocks in-flight calls even without close()). Descends from
	// Background, not the request ctx that created the session, so it outlives initialize.
	sessCtx    context.Context
	sessCancel context.CancelFunc

	// evictOnce/evicted end open SSE streams on kill without the full done-driven teardown, so
	// a killed session stops receiving upstream notifications immediately. Idempotent: a
	// session can be killed more than once.
	evictOnce sync.Once
	evicted   chan struct{}

	// lastActive updates on every POST and when an SSE stream is OPENED, not while one is held
	// (a long-lived stream is spared by hasSubscribers() instead). Atomic so the reaper reads
	// it without the proxy lock.
	lastActive atomic.Int64

	// lastRequest advances only on a host POST, unlike lastActive which also advances on SSE
	// open. It backs the hard idle ceiling: an initialize+GET client gone silent is reaped once
	// lastRequest is older than hardIdleMultiplier x the idle window even with a stream open.
	lastRequest atomic.Int64

	// initInProgress is true from before registration until the handshake + synchronous drift
	// check completes, since that check can block up to sessionStartTimeout with a stale
	// lastActive that would otherwise read as idle; reapOnce skips a session while this is set.
	initInProgress atomic.Bool

	// reqSem bounds concurrent in-flight enforced-request handlers per session (HTTP analogue
	// of stdio's hostSem), so a pipelining host or a silent upstream (--upstream-timeout=0)
	// can't grow goroutines and the byUpstreamID/hostToUp maps without bound. Lazily created so
	// directly constructed test sessions still get a real cap.
	reqSemOnce sync.Once
	reqSem     chan struct{}

	// inFlight counts requests anywhere in handleSessionPost, not only ones blocked on the
	// upstream — incremented right after the route-binding check, released when the handler
	// returns. lastActive isn't advanced while a call blocks, so reapOnce's normal arm spares
	// a session with inFlight > 0 (the hard ceiling still reaps it). A separate atomic rather
	// than len(reqSem): reqSem is lazily assigned, so a lock-free len() would race that
	// one-time write.
	inFlight atomic.Int64

	// notifySemOnce/notifySem bound in-flight notification forwards, deliberately its own pool
	// and NOT shared with reqSem: a burst of enforced calls each blocking for the full
	// upstream-timeout must not exhaust the pool and silently drop a notifications/cancelled
	// meant to abort one of those very calls.
	notifySemOnce sync.Once
	notifySem     chan struct{}

	// reqSaturation / notifySaturation gate the RESOURCE_EXHAUSTED record each pool writes on
	// refusal — one gate per pool, so a flood on one can't elide the other's record. Each
	// collapses an episode into a single record; see saturationGate. Zero value usable.
	reqSaturation    saturationGate
	notifySaturation saturationGate

	// serverPool bounds, dispatches and drains this session's SERVER-initiated request handlers
	// (sampling/createMessage, roots/list, elicitation). readUpstream hands work to it rather
	// than running inline; see serverRequestPool for why. Per session, so one session's flood
	// can't consume another's slots. Zero value usable.
	serverPool serverRequestPool
}

// maxConcurrentSessionRequests bounds in-flight enforced-request handlers per HTTP
// session (see httpSession.reqSem), mirroring the stdio transport's
// maxConcurrentHostRequests. Generous enough that honest pipelining never trips it.
const maxConcurrentSessionRequests = 256

// maxConcurrentSessionNotifications bounds in-flight notification forwards per HTTP session,
// mirroring the stdio bridge's maxInflightPosts but scaled down since this pool is per-session.
const maxConcurrentSessionNotifications = 64

// tryAcquireNotifySlot non-blocking-acquires the session's notification semaphore, false at
// maxConcurrentSessionNotifications. Paired with releaseNotifySlot.
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

// releaseNotifySlot releases a slot acquired via tryAcquireNotifySlot. Must be called
// exactly once per successful acquire.
func (s *httpSession) releaseNotifySlot() { <-s.notifySem }

// tryAcquireRequestSlot non-blocking-acquires the session's request semaphore, false at
// maxConcurrentSessionRequests. Paired with releaseRequestSlot.
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

// releaseRequestSlot releases a slot acquired via tryAcquireRequestSlot. Must be called
// exactly once per successful acquire.
func (s *httpSession) releaseRequestSlot() { <-s.reqSem }

// touch records host interaction (opening an SSE stream) once per open, not continuously
// while held — a held stream is kept alive by hasSubscribers() instead. Advances lastActive
// only, so SSE liveness alone can't defer the hard idle ceiling.
func (s *httpSession) touch() {
	s.lastActive.Store(time.Now().UnixNano())
}

// touchRequest records a host POST, advancing both lastActive and lastRequest.
func (s *httpSession) touchRequest() {
	now := time.Now().UnixNano()
	s.lastActive.Store(now)
	s.lastRequest.Store(now)
}

// buildInitResponse builds an initialize response for the host using the
// upstream capabilities gathered during session startup.
func (s *httpSession) buildInitResponse(msg mcp.RPCMsg) mcp.RPCMsg {
	if resp, refused := refuseInitializeAcrossRevisions(msg.ID, s.upstreamRev); refused {
		return resp
	}
	return buildInitializeResponse(msg.ID, s.upstreamCaps, s.upstreamInstructions)
}

// ownerMismatch reports whether cur (the current request's JWT identity) differs from the
// identity that created this session, so a second identity on the same route can't read the
// creating client's captured upstream capabilities via re-initialize. Compares issuer+subject
// as separate fields (never concatenated, to avoid cross-value collisions); a claims-less
// session is unbound and never mismatches.
func (s *httpSession) ownerMismatch(cur *pdp.JWTClaims) (string, bool) {
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

// noteRequestAnchor records when a host request's state anchor differs from the one the
// session's sampling leg decides against (captured at initialize, no host request in scope) —
// otherwise a session spanning two task anchors could let a source tag one task's taint while
// sampling peeks the other, clean. See spansAnchors for the refusal this feeds.
//
// Called for an ENFORCED request only, past every gate that could still refuse it: the latch is
// sticky for the session's life, so only a message that actually commits anchored state under an
// anchor may set it. Anything else — a framing the leg discards, a notification forwarded with no
// decision, a locally-answered ping or re-initialize, a request the in-flight cap refuses — writes
// no anchored state, so latching for one costs the session its sampling leg on the strength of a
// decision that never happened. It is the same predicate the decision turn takes, so "which
// requests are keyed on an anchor" is one answer rather than two.
//
// cur is the request's own validated claims, the same input the engine's key builder resolves its
// anchor from — so for a request that reaches dispatch, "the claims present at POST time" and
// "the anchor the request resolved" are one answer, not two that could disagree.
func (s *httpSession) noteRequestAnchor(cur *pdp.JWTClaims) {
	rt := s.route
	if rt == nil || !rt.taskAnchored {
		return
	}
	if rt.decisionAnchor(s.id, cur) != rt.decisionAnchor(s.id, s.claims) {
		s.spanned.Store(true)
	}
}

// spansAnchors reports whether this session has resolved a state anchor other than the one its
// server-initiated leg decides against; it is the predicate that leg refuses on.
func (s *httpSession) spansAnchors() bool { return s != nil && s.spanned.Load() }

// unblocker is this session's wiring for every site that answers a blocked server-initiated
// initiator. The sink is a nil *mcp.MsgWriter in remote-upstream mode — the typed nil the seam's
// disposition resolves at ANSWER time, so the tracker-only holders (every forwarded request) pay
// nothing for a writer they never call.
func (s *httpSession) unblocker() serverRequestUnblocker {
	// One resolution feeding both fields, rather than two: they must name the same channel, and
	// asking twice both costs a second resolution on a per-request leg and makes disagreement
	// representable.
	recs := s.refusalRecorders()
	return serverRequestUnblocker{
		reqs:    &s.serverReqs,
		sink:    s.upWriter,
		notices: recs.notices(),
		report: dropReport{
			recs: recs,
			subj: verifiedSession(s.id),
			legs: httpServerRequestLegs,
		},
	}
}

// unblockRefusedServerReply answers the upstream request a revision-refused host reply would
// have completed, so it does not stay blocked until this session's idle ceiling reclaims it.
//
// A PROTOCOL refusal: eunox has nothing to relay, but it can say so at its own revision, and the
// initiator learns its request failed instead of hanging. No revocation lookup is interposed, so a
// revoked session's refused reply may still unblock its initiator — that costs nothing the kill
// protects, since what a kill forbids is DELIVERING the host's reply and this answer is eunox's
// own. See this file's package-level rule for the drops that deliberately do not answer.
func (s *httpSession) unblockRefusedServerReply(ctx context.Context, msg mcp.RPCMsg) {
	if !msg.IsResponse() {
		return
	}
	s.unblocker().unblock(s.withSessionClaims(ctx), msg.ID, refusedReplyUpstreamError)
}

// senderIsProvenOwner reports whether cur is the identity that CREATED this session — PROVEN,
// not merely un-refused.
//
// Deliberately not ownerMismatch, whose negation is the weaker question. That check answers "no
// mismatch" for a session with no bound identity, which is right for a GATE (there is nothing to
// enforce, so nothing to refuse) and wrong for any decision that ACTS on the sender's behalf: an
// unbound session cannot distinguish its owner from anyone else, so nobody is proven.
func (s *httpSession) senderIsProvenOwner(cur *pdp.JWTClaims) bool {
	if s.claims == nil || s.claims.Subject == "" || cur == nil {
		return false
	}
	_, mismatch := s.ownerMismatch(cur)
	return !mismatch
}

// unblockGateRefusedServerReply answers the upstream request a host reply the SESSION GATES
// refused would have completed — but only when the sender is PROVABLY this session's own owner.
//
// Whether this arm may answer turns on WHO sent the reply, not on which gate refused it, and not
// on the fact of a refusal:
//
//   - The sender is the session's own owner: no second identity is involved and nobody else's
//     reply is being consumed. The refusal is one the owner caused themselves (their token no
//     longer clears the route's audience pin), and leaving it costs one wedged upstream request
//     for the session's remaining life for no protection at all.
//   - Anyone else, including a sender nothing can place: the real owner's reply may still be
//     coming, and answering the initiator completes its request whether or not the tracked id is
//     consumed — so "answer without untracking" does not separate the two. Doing it would hand any
//     second identity that learned this session id a way to abort the owner's pending reply, gated
//     only on knowing the id. Left blocked for the owner's reply, or for teardown.
//
// The gate's two arms are NOT interchangeable evidence here, which is why this asks its own
// question rather than reading the verdict. sessionGateVerdict short-circuits on the audience pin
// and never runs the owner binding, so a refusal that is not "owner mismatch" says nothing about
// whether the sender is the owner — an unbound session made that gap reachable, since the binding
// is vacuous there and every sender read as the owner.
//
// Revocation is deliberately not consulted, for the reason unblockRefusedServerReply gives: what a
// kill forbids is DELIVERING the host's reply, and this answer is eunox's own.
func (s *httpSession) unblockGateRefusedServerReply(ctx context.Context, msg mcp.RPCMsg) {
	if !msg.IsResponse() || !s.senderIsProvenOwner(pdp.JWTClaimsPtr(ctx)) {
		return
	}
	s.unblocker().unblock(s.withSessionClaims(ctx), msg.ID, gateRefusedReplyUpstreamError)
}

// newSession spawns an upstream subprocess and performs the MCP initialize handshake. The
// session registers before readUpstream starts so cleanup finds it even on immediate exit.
// startGen is the reap generation observed before the caller's pre-spawn kill gate, since
// everything from there through registerSession is inside the window it must detect.
func (p *HTTPProxy) newSession(ctx context.Context, route *UpstreamRoute, clientIP string, startGen uint64) (*httpSession, error) {
	// Built before registerSession publishes the session, so a concurrent close() never races
	// the write of sessCancel. Descends from Background, not the request ctx which ends when
	// this handshake returns.
	sessCtx, sessCancel := context.WithCancel(context.Background())
	sess := &httpSession{
		id:             uuid.New().String(),
		proxy:          p,
		route:          route,
		byUpstreamID:   make(map[string]chan upstreamResult),
		hostToUp:       make(map[string]*json.RawMessage),
		upstreamDenies: newUpstreamRefusalLimiter(p.preSessionDenies, upstreamRefusalCategories),
		done:           make(chan struct{}),
		evicted:        make(chan struct{}),
		sessCtx:        sessCtx,
		sessCancel:     sessCancel,
		claims:         pdp.JWTClaimsPtr(ctx),
		clientIP:       clientIP,
		// Every session is minted by a host `initialize` today, and that method exists only
		// in the older revision — so opening one IS negotiating it. Each request is checked
		// against this pin, so one declaring a different revision is refused rather than
		// switching method tables mid-context.
		hostRev:     handshakeRevision,
		upstreamRev: UpstreamOpenRevision(route.upstreamProtocolVersion),
	}
	// Cleared only when newSession returns, so the idle reaper spares the drift-check window.
	sess.initInProgress.Store(true)
	defer p.finishEstablishing(sess) //nolint:contextcheck // deliberately detached: binding this reclaim to the finishing request ctx would cancel the teardown the moment the handler returns.

	cmd := exec.Command(route.command, route.args...) //nolint:gosec,noctx // G204: args are user-supplied CLI arguments; session lifecycle managed via done channel, not ctx
	ConfigureUpstreamCmd(cmd)

	upIn, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("upstream stdin: %w", err)
	}
	upOut, err := cmd.StdoutPipe()
	if err != nil {
		// Start was never reached, so Cmd.Start's deferred pipe cleanup never runs; close the
		// parent write end ourselves (the child read end is reclaimed by its finalizer).
		_ = upIn.Close()
		return nil, fmt.Errorf("upstream stdout: %w", err)
	}
	sess.upCmd = cmd
	sess.upIn = upIn
	// Bound each write by --upstream-timeout so a subprocess that stops draining stdin can't
	// wedge a handler on the write. A timeout poisons the writer and kills the subprocess via
	// onPoison, so readUpstream EOFs and the session is reaped rather than left desynced.
	sess.upWriter = mcp.NewMsgWriterWithTimeout(upIn, msToDuration(p.upstreamTimeMs), sess.killSubprocess)
	sess.upReader = mcp.NewMsgReader(upOut)

	if err := cmd.Start(); err != nil {
		// No pipe cleanup here: a failed Cmd.Start closes both parent ends itself.
		return nil, fmt.Errorf("starting upstream %q: %w", route.command, err)
	}

	if err := sess.initUpstream(ctx); err != nil {
		killUpstreamProcess(cmd.Process)
		// Not a synchronous reap: initUpstream may have only bounded its wait for the
		// handshake goroutine, not joined it, and os/exec forbids calling Wait while a
		// StdoutPipe read is still in flight. Join handshakeStopped first, in the background
		// so a descendant holding the pipe open can't hang newSession itself.
		go func() {
			// Bounded like every other wait on this channel, so a runaway descendant leaks one
			// goroutine instead of hanging forever; runs before registerSession so a
			// repeatedly-failing upstream isn't bounded by --max-sessions.
			waitBounded(sess.handshakeStopped, sess.shutdownBudget(), "upstream handshake reader", sess.errOut())
			_ = cmd.Wait()
		}()
		return nil, fmt.Errorf("upstream initialize: %w", err)
	}

	// Register before starting readUpstream: readUpstream closes sess.done on exit and the
	// cleanup goroutine deletes the map entry, so registering after risks a leaked entry if
	// the subprocess exits first. Also enforces maxSessions; on a race over the cap, kill the
	// subprocess directly since readUpstream isn't running yet to close sess.done.
	if err := p.registerSession(sess, startGen); err != nil {
		killUpstreamProcess(cmd.Process)
		_ = cmd.Wait()
		return nil, err
	}

	// Cleanup goroutine: waits for the upstream to exit, then removes the session. sess.done
	// closes on ANY readUpstream exit (not only a clean one — an oversized frame or parse
	// error leaves the subprocess running with just stdout torn down), so close stdin first
	// and escalate to SIGKILL after a bounded grace period rather than blocking Wait() forever.
	// May run concurrently with an explicit sess.close() racing to close upIn/kill the process;
	// benign, since both operations are idempotent.
	go func() { //nolint:contextcheck // teardown path: uses a detached, bounded context by design (session is gone; no request context).
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
		// Runs on EVERY teardown path (idle reap, DELETE, kill, shutdown, natural exit), so
		// it's the one place that reclaims this session's flow-label state.
		releaseSessionState(sess)
		_, _ = fmt.Fprintf(p.errOut(), "[eunox] HTTP session %s ended.\n", sess.id)
	}()

	// Pass the proxy's serve context, not the request-scoped ctx, so kill-switch lookups on
	// the upstream-initiated path outlive this initialize request.
	go sess.readUpstream(p.serveCtx()) //nolint:contextcheck // deliberate: session lifetime != request lifetime

	// Always synchronous: the session isn't returned until drift verification completes. On
	// failure, delete synchronously so the failed session stops counting against maxSessions
	// at once rather than waiting on the cleanup goroutine's async delete.
	if err := p.runDriftCheckOrTeardown(ctx, sess, route); err != nil {
		return nil, err
	}

	// Re-stamp now that establishment is complete, so idle is measured from readiness, not
	// registration — otherwise a session whose --session-idle is shorter than its startup
	// duration is reap-eligible before the client's first post-init request.
	sess.touchRequest()

	_, _ = fmt.Fprintf(p.errOut(), "[eunox] HTTP session %s started.\n", sess.id)
	return sess, nil
}

// runDriftCheckOrTeardown runs the route's session-start drift check (if configured) against a
// freshly-probed upstream tools/list, tearing the session down synchronously on failure — so
// the failed session stops counting against maxSessions at once — and returning the error.
// Shared by newSession and newRemoteSession, whose teardown ordering must stay identical.
func (p *HTTPProxy) runDriftCheckOrTeardown(ctx context.Context, sess *httpSession, route *UpstreamRoute) error {
	if route.driftCheck == nil {
		return nil
	}
	raw, probeErr := sess.fetchUpstreamToolsRaw(ctx)
	// Tier-2 interface baseline from the same probe, keyed by session id so each HTTP session
	// on a shared per-route PDP baselines its own upstream independently.
	if probeErr == nil {
		route.pdp.RecordObservedToolHashes(pdp.WithCompleteToolListing(pdp.WithSessionID(ctx, sess.id)), raw)
	}
	if err := route.driftCheck(raw, sess.upstreamServerVersion, probeErr); err != nil {
		// A startup drift failure is the FM-5 tool-poisoning/rug-pull event this check exists
		// to catch, so record it on the tamper-evident tape, not only stderr.
		recordDriftRefused(ctx, asRecorder(route.sink), sess.id)
		sess.close(p.shutdownMs) //nolint:contextcheck // teardown path: detached, bounded context by design.
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

// errRacedReap is returned by registerSession when a global kill-switch reap swept the registry
// after this session began establishing but before it registered — see reapGen and
// currentReapGen. Handled like errShuttingDown/errSessionLimit: tear the upstream back down.
var errRacedReap = errors.New("session raced a kill-switch reap; retry")

// currentReapGen returns the reap generation in force now. A session-creating initialize calls
// this once before its upstream handshake and passes the result to registerSession as startGen.
func (p *HTTPProxy) currentReapGen() uint64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.reapGen
}

// registerSession inserts sess under the proxy lock after an authoritative capacity check, the
// single insertion point so maxSessions holds even when concurrent initializes race past the
// cheap pre-spawn check in handleMCPPost.
//
// startGen is the reapGen the caller observed before establishing sess. If a global kill's
// teardownAllSessionsForGlobalKill swept the registry during that (possibly long) window, p.reapGen will
// have advanced past startGen and the insert is rejected — otherwise the session would register
// into the post-sweep map with a live upstream the sweep never saw, reopening the
// kill-triggered session-exhaustion DoS the reap exists to close.
func (p *HTTPProxy) registerSession(sess *httpSession, startGen uint64) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	// A session-creating initialize can spend up to sessionStartTimeout inside initUpstream, so
	// registerSession can land after closeAllSessions has already emptied the registry; fail
	// closed here rather than leak the subprocess with nothing left to reap it.
	if p.shuttingDown {
		return errShuttingDown
	}
	if p.reapGen != startGen {
		return errRacedReap
	}
	if p.maxSessions > 0 && len(p.sessions) >= p.maxSessions {
		return errSessionLimit
	}
	// Deliberately does NOT touch p.establishing: the reservation has exactly one owner (the
	// handler that took it), released exactly once when that handler returns. Converting it
	// here double-freed it whenever establishment failed after registering, silently consuming
	// a concurrent session's reservation and admitting more upstreams than the cap allows.
	now := time.Now().UnixNano()
	sess.lastActive.Store(now)
	// Seeds the hard idle ceiling from creation: the initialize POST counts as the first
	// host request.
	sess.lastRequest.Store(now)
	// Resolved here, after the checks above, so a refused session leaves no gate reference
	// behind. The gate registry is leaf-level, so entering it under p.mu is no ordering hazard.
	sess.holdDecisionGate()
	p.sessions[sess.id] = sess
	return nil
}

// holdDecisionGate resolves this session's anchor once and pins the registry gate for it, for
// the session's life; the reference is released by releaseSessionState. It's a cache, not a
// decision the anchor can't change: each request resolves its own anchor and compares (gateFor).
// No-op on a non-serialized route (no registry to hold).
func (s *httpSession) holdDecisionGate() {
	rt := s.route
	if !rt.serializes() {
		return
	}
	s.decideAnchor = rt.decisionAnchor(s.id, s.claims)
	s.decideGate, s.dropDecideGate = rt.decideGates.hold(s.decideAnchor.Key())
}

// gateFor returns this session's pinned gate when anchor is the one it was resolved for, or nil
// to send the caller on to the cache and then the registry. Compares the resolved anchor
// (allocates nothing), never a restatement of how the resolver decides.
func (s *httpSession) gateFor(anchor enforcement.StateAnchor) *anchorGate {
	if s.decideGate == nil || s.decideAnchor != anchor {
		return nil
	}
	return s.decideGate
}

// beginTurn enters anchor's decision turn under w's give-up rule and returns the idempotent
// release. ok is false only when a bounded w gave up.
//
// Three tiers reach the same turn, in cost order: the session's lock-free PIN (covers almost
// every request), the session's CACHE for other anchors a spanning session resolves (see
// session_gate_cache.go), and the route REGISTRY, the always-correct fallback. All three compare
// the resolved enforcement.StateAnchor, never a restatement of the resolver's logic.
func (s *httpSession) beginTurn(anchor enforcement.StateAnchor, w turnWait) (func(), bool) {
	if gate := s.gateFor(anchor); gate != nil {
		return gate.take(w)
	}
	if gate, release, ok := s.decideCache.acquire(anchor, s.route.decideGates); ok {
		end, taken := gate.take(w)
		if !taken {
			// Nothing to release but this caller's cache-entry use, so an abandoned wait
			// doesn't pin the entry against eviction.
			release()
			return nil, false
		}
		return func() { end(); release() }, true
	}
	return s.route.decideGates.acquire(anchor.Key(), w)
}

// beginDecisionTurn enters this request's decision turn and returns the idempotent release, or
// nil when the route isn't serialized. Unbounded: the host path holds the turn on its own
// request goroutine.
func (s *httpSession) beginDecisionTurn(ctx context.Context) func() {
	end, _ := s.beginTurn(s.route.decisionAnchorFromContext(ctx, s.id), turnWait{})
	return end
}

// beginDecisionTurnWithin is beginDecisionTurn for the server-initiated leg, bounded by w and
// anchored on the session's claims captured at initialize (that leg has no host request in
// scope). ok is false when the turn couldn't be entered under w — see samplingTurnWait.
func (s *httpSession) beginDecisionTurnWithin(w turnWait) (func(), bool) {
	return s.beginTurn(s.route.decisionAnchor(s.id, s.claims), w)
}

// getSession returns the session for id, or nil.
func (p *HTTPProxy) getSession(id string) *httpSession {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.sessions[id]
}

// sessionCount returns the number of REGISTERED sessions, for health/metrics. Not the capacity
// predicate: the cap also counts sessions still establishing (see tryReserveSessionSlot).
func (p *HTTPProxy) sessionCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.sessions)
}

// tryReserveSessionSlot reserves one maxSessions slot for a session about to be established,
// counting registered sessions PLUS those still establishing, since establishment can run for
// up to sessionStartTimeout before registerSession makes the count authoritative. Every
// successful reservation must be released exactly once by its caller, on every path.
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

// releaseSessionSlot drops the reservation taken by tryReserveSessionSlot. A no-op against an
// unlimited cap. The establishing > 0 guard is a backstop against going negative, not a
// license to release twice — a spurious release would silently consume another session's slot.
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

// hardIdleMultiplier sets the hard idle ceiling as a multiple of the idle window, so an
// initialize+GET client gone silent can't pin its upstream forever even with an SSE stream
// open. A constant, not a config knob, to keep the safety net's scope small.
const hardIdleMultiplier = 4

// reapIdleSessions periodically closes sessions whose host has sent no request within
// sessionIdleMs (an open SSE stream spares it unless past the hard idle ceiling too). Runs
// until ctx (serve-lifetime) is cancelled.
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

// reapOnce closes, in a single sweep, every session idle longer than idle and not holding an
// open SSE stream (or past the hard ceiling). Factored out for deterministic testing; sessions
// are collected under the lock and closed outside it, concurrently and awaited, so one slow
// upstream can't stall the whole sweep.
func (p *HTTPProxy) reapOnce(idle time.Duration) {
	now := time.Now()
	cutoff := now.Add(-idle).UnixNano()
	// Saturate idle x hardIdleMultiplier rather than multiplying a raw Duration: an
	// extreme-but-valid idle window would overflow int64 and wrap hardCutoff into the future.
	hard := idle
	if idle > math.MaxInt64/hardIdleMultiplier {
		hard = math.MaxInt64
	} else {
		hard *= hardIdleMultiplier
	}
	hardCutoff := now.Add(-hard).UnixNano()
	// staleSession pairs a reaped session with WHY it's being reaped, for the log line.
	type staleSession struct {
		s      *httpSession
		hard   bool
		killed bool
	}
	// Snapshot under p.mu, released before the idle/subscriber checks: hasSubscribers takes
	// s.notifMu, and keeping the two locks disjoint here prevents a future p.mu->notifMu
	// ordering from deadlocking against this loop.
	snapshot := p.snapshotSessions()
	var stale []staleSession
	for _, s := range snapshot {
		// A session still initializing has a stale lastActive that would misread as idle;
		// tearing it down here would also race the establishment path's own teardown.
		if s.initInProgress.Load() {
			continue
		}
		// A killed session is reaped regardless of idle state: a kill delivered through Redis
		// (rather than this instance's own /control/kill) has nothing else that reclaims its
		// subprocess/slot/stream, and left unreaped they eventually 503 every new initialize —
		// the exhaustion DoS the kill switch would then be causing itself. Cheap: a local
		// cache lookup, not a kill-store round trip. NOTE: this sweep doesn't run at all
		// under sessionIdleTimeoutMs: 0.
		if p.sessionKilled(s) {
			stale = append(stale, staleSession{s: s, killed: true})
			continue
		}
		switch {
		case s.lastRequest.Load() < hardCutoff && p.hardReapEligible(s):
			// Checked first so a session past the hard ceiling is always tagged hard, rather
			// than escaping via the normal arm by opening an SSE stream in the re-check
			// window. hardReapEligible spares an in-flight call bounded by a finite
			// --upstream-timeout; only an unbounded budget lets the ceiling reclaim it.
			stale = append(stale, staleSession{s: s, hard: true})
		case s.lastActive.Load() < cutoff && !s.hasSubscribers() && s.inFlight.Load() == 0:
			// The in-flight spare is on this arm only: lastActive isn't refreshed while the
			// upstream call blocks, so a call outliving sessionIdleMs must not be torn down
			// mid-flight. Re-checked in the teardown goroutine below.
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
			// Re-check immediately before teardown, so a session that became active again
			// since the snapshot is spared; the "reaped" log line is only emitted after the
			// re-check passes.
			if killed {
				p.reclaimKilledSession(s)
				return
			}
			if hardReap {
				if s.lastRequest.Load() >= hardCutoff || !p.hardReapEligible(s) {
					return
				}
				_, _ = fmt.Fprintf(p.errOut(), "[eunox] HTTP session %s reaped (no host request > %s, hard idle ceiling; SSE stream may have been open).\n", s.id, hard)
			} else {
				// An enforced request started after the snapshot also spares this arm: tearing
				// down would kill the upstream out from under the in-flight callUpstream.
				if s.lastActive.Load() >= cutoff || s.hasSubscribers() || s.inFlight.Load() > 0 {
					return
				}
				_, _ = fmt.Fprintf(p.errOut(), "[eunox] HTTP session %s reaped (idle > %s).\n", s.id, idle)
			}
			s.close(p.shutdownMs)
		}()
	}
	wg.Wait()
}

// sessionKilled reports whether the kill switch currently names this session, its agent, or a
// global stop — same authority the request path consults, so a session already denied on the
// data plane is one the reaper reclaims. Answers ONLY on an actual kill, not a kill-store error
// (fail-closed there is right for a request but wrong for a sweep, which would tear down every
// live session over a transient store blip). A route/PDP-less test session is never killed.
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

// sweepKilledSessions closes every registered session the kill switch NOW names, freeing its
// upstream, maxSessions slot, and SSE stream. This is the on-DELIVERY reclaim
// (reclaimOnRevocation); the idle reaper's killed arm is the same logic on a timer as the
// backstop for a revocation notification that never arrived (and it's the ONLY reclaim on a
// proxy with idle reaping off). Both go through reclaimKilledSession/p.sessionKilled so
// "reclaiming a killed session" has one definition. Snapshotted and closed concurrently.
func (p *HTTPProxy) sweepKilledSessions() {
	snapshot := p.snapshotSessions()
	var wg sync.WaitGroup
	for _, s := range snapshot {
		// Same spare as the idle sweep: a session mid-handshake would race its own
		// establishment teardown; it's denied throughout and reclaimed once established.
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

// finishEstablishing ends a session's initializing window and reclaims it if a kill landed while
// it was establishing. Both constructors defer it. Every sweep spares a session mid-handshake
// (to avoid racing establishment's own teardown), and a revocation fires once — so a kill
// delivered during that window would otherwise go unreclaimed forever with idle reaping off.
// Checking here, on the edge where the spare ends, closes that gap. A session whose
// establishment failed is skipped (already torn down); the identity comparison also skips a
// stale id a later session reused.
func (p *HTTPProxy) finishEstablishing(sess *httpSession) {
	sess.initInProgress.Store(false)
	if p.getSession(sess.id) != sess {
		return
	}
	if p.sessionKilled(sess) {
		p.reclaimKilledSession(sess)
	}
}

// reclaimKilledSession tears down one session the kill switch names. Shared by the idle
// reaper's killed arm and the on-delivery sweep so a change to what reclaiming entails can't
// land on one and not the other.
func (p *HTTPProxy) reclaimKilledSession(s *httpSession) {
	// Re-checked immediately before teardown: an operator who revived the kill between the
	// snapshot and now should not lose the session to this sweep.
	if !p.sessionKilled(s) {
		return
	}
	_, _ = fmt.Fprintf(p.errOut(), "[eunox] HTTP session %s reaped (kill switch active for this session).\n", s.id)
	// Explicit eviction: the GET keepalive arm isn't kill-gated, so the stream would
	// otherwise survive its own session's teardown.
	s.evictStreams()
	s.close(p.shutdownMs)
}

// hardReapEligible reports whether a session past the hard idle ceiling may be torn down now.
// An in-flight call under a finite --upstream-timeout is already bounded by it and is spared
// here; only an unbounded budget makes it eligible, which is the ceiling's reason for existing.
func (p *HTTPProxy) hardReapEligible(s *httpSession) bool {
	return p.upstreamTimeMs <= 0 || s.inFlight.Load() == 0
}

// hasSubscribers reports whether the session has an active SSE subscriber (open GET stream),
// used by the idle reaper to spare a session a host is actively listening on (still subject to
// the hard idle ceiling).
func (s *httpSession) hasSubscribers() bool {
	s.notifMu.Lock()
	defer s.notifMu.Unlock()
	return len(s.notifSubs) > 0
}

// snapshotSessions returns a copy of every currently registered session, taken under a read
// lock that is released before the caller iterates. Every sweep that acts on "the sessions
// registered right now" (the idle reaper, sweepKilledSessions, evictAllSessionStreams) needs
// this same shape, so it is written once rather than hand-rolled per call site.
func (p *HTTPProxy) snapshotSessions() []*httpSession {
	p.mu.RLock()
	defer p.mu.RUnlock()
	sessions := make([]*httpSession, 0, len(p.sessions))
	for _, s := range p.sessions {
		sessions = append(sessions, s)
	}
	return sessions
}

// drainAllSessions runs underLock (to latch whatever state, e.g. shuttingDown or reapGen,
// must change atomically with the swap), replaces p.sessions with a fresh empty map, then
// closes every previously-registered session concurrently and waits for them all. Shared by
// closeAllSessions and teardownAllSessionsForGlobalKill, which differ only in underLock.
func (p *HTTPProxy) drainAllSessions(underLock func()) {
	p.mu.Lock()
	underLock()
	sessions := make([]*httpSession, 0, len(p.sessions))
	for _, s := range p.sessions {
		sessions = append(sessions, s)
	}
	p.sessions = make(map[string]*httpSession)
	p.mu.Unlock()
	// Concurrent, so one slow upstream doesn't make this O(N * shutdownMs).
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

// closeAllSessions closes every active session (called during server shutdown).
func (p *HTTPProxy) closeAllSessions() {
	// Latch shutdown before the snapshot/swap so a racing registerSession fails closed
	// (errShuttingDown) instead of inserting into the fresh map after this reap.
	p.drainAllSessions(func() { p.shuttingDown = true })
}

// teardownSessionByID tears down a killed session's upstream and frees its maxSessions slot
// immediately, instead of relying on the idle reaper — which doesn't run at all when
// sessionIdleTimeoutMs is 0, and without this a killed session lingers until process exit and
// eventually exhausts maxSessions, a DoS triggered by the kill switch itself. Mirrors
// handleMCPDelete's teardown rather than reclaimKilledSession's re-check-then-evict-then-close:
// the caller already knows this id was just killed, so there is nothing left to re-verify.
// A session already gone is a no-op.
func (p *HTTPProxy) teardownSessionByID(sessionID string) {
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

// teardownAllSessionsForGlobalKill tears down every active session after a global
// (emergency-stop) kill. Unlike closeAllSessions it does NOT latch shuttingDown: the proxy
// keeps serving. Bumps reapGen under the snapshot/swap lock so a registration racing this
// sweep (a session already past CheckKill but still mid-handshake) is rejected by
// registerSession's startGen check rather than registering into the fresh map with a live,
// unreclaimed upstream.
func (p *HTTPProxy) teardownAllSessionsForGlobalKill() {
	p.drainAllSessions(func() { p.reapGen++ })
}

// evictStreams closes the evicted signal every handleMCPGet loop selects on, so a killed
// session stops receiving upstream notifications immediately. Idempotent.
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

// evictAllSessionStreams ends every session's open SSE stream, used by the global emergency
// stop. Snapshotted under the lock and evicted outside it; adds no new lock ordering since
// evictStreams only closes a channel.
func (p *HTTPProxy) evictAllSessionStreams() {
	sessions := p.snapshotSessions()
	for _, s := range sessions {
		s.evictStreams()
	}
}

// initUpstream performs the MCP initialize handshake, bounded by ctx (the
// session-start deadline). The blocking pipe reads cannot observe ctx, so the
// handshake runs in a goroutine; on ctx expiry the subprocess is killed, which
// closes the pipe, unblocks the reader, and lets the goroutine exit.
func (s *httpSession) initUpstream(ctx context.Context) error {
	// handshakeStopped closes unconditionally when runInitHandshake actually returns, so a
	// caller needing proof the pipe read has stopped (newSession's failed-initialize reap)
	// can join it rather than assume this function's own bounded wait covered that.
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
		// Bounded independently: a descendant that escaped the process group can hold the
		// pipe open indefinitely, and this giving up does not mean the goroutine stopped
		// reading it — handshakeStopped, not this return, is what callers must join.
		waitBounded(done, s.shutdownBudget(), "upstream initialize output stream", s.errOut())
		return fmt.Errorf("upstream did not complete its opener: %w", ctx.Err())
	}
}

// runInitHandshake opens the upstream leg at the revision this session speaks, waits for the
// matching response, and completes the open on the revision that has a completion.
func (s *httpSession) runInitHandshake() error {
	s.idCounter++
	req, initID, err := buildUpstreamOpener(s.upstreamRev, s.idCounter)
	if err != nil {
		return err
	}
	if err := s.upWriter.Write(req); err != nil {
		return fmt.Errorf("sending %s: %w", req.Method, err)
	}

	resp, err := awaitStartupReply(s.upReader.Read, initID, s.upWriter, nil)
	if err != nil {
		return fmt.Errorf("reading %s response: %w", req.Method, err)
	}
	hs, err := ApplyUpstreamOpenerResult(s.upstreamRev, resp)
	if err != nil {
		return err
	}
	reportUpstreamOpenNotice(s.errOut(), hs)
	s.upstreamCaps, s.upstreamServerVersion, s.upstreamInstructions = hs.Capabilities, hs.ServerVersion, hs.Instructions

	notif, wanted := UpstreamOpenerCompletion(s.upstreamRev)
	if !wanted {
		return nil
	}
	return s.upWriter.Write(notif)
}

// readUpstream continuously reads from the upstream and routes messages: responses
// to waiting callUpstream callers, notifications and server-initiated requests to
// their handlers.
func (s *httpSession) readUpstream(ctx context.Context) {
	// Cancel the teardown context before closing done, so an in-flight awaitNonced unblocks
	// on a crash even when close() is never called.
	defer close(s.done)
	defer s.sessCancel()
	for {
		msg, err := s.upReader.Read()
		if err != nil {
			// io.EOF is a normal stream end. Any other error (oversized message, JSON-RPC
			// parse failure) is abnormal; log it so an operator can tell it from a clean exit.
			if !errors.Is(err, io.EOF) {
				_, _ = fmt.Fprintf(s.errOut(), "[eunox] HTTP session %s: upstream read error: %v\n", s.id, err)
			}
			return
		}
		if msg.IsNotification() {
			// A Redis-backed kill never calls handleKill on this instance (it learns of the
			// kill only through CheckKill/pubsub), so gate the broadcast here too rather than
			// rely solely on the local /control/kill path's SSE eviction. s.route is
			// dereferenced unconditionally: production never builds a route-less session, and
			// a guard here would mean silently failing open instead.
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
		// A message with both an id and a method that echoes a LIVE outstanding upstream
		// nonce is not a genuine server-initiated request — route it to the waiting caller,
		// which refuses a method-bearing reply, mirroring the stdio transport's guard.
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

// dispatchUpstreamRequest hands one server-initiated request to this session's serverRequestPool
// rather than running the handler inline on readUpstream (see serverRequestPool for why) — this
// session's only response-delivery/SSE-relay goroutine must not stall on it, which matters more
// under task anchoring, where the turn holder can be a different session sharing the anchor.
func (s *httpSession) dispatchUpstreamRequest(ctx context.Context, msg mcp.RPCMsg) {
	// readUpstream's context never carried the session's claims, so without this the refusals below
	// — the entry gate's, the pool's saturation record, and a destroyed answer's — drop out of the
	// per-agent grouping the sampling leg's own refusals appear in, for one transport leg value.
	ctx = s.withSessionClaims(ctx)
	dispatchServerRequest(ctx, &s.serverPool, msg, serverRequestDispatch{
		rec:       asRecorder(s.route.sink),
		sessionID: s.id,
		// Through the seam rather than a closure over the concrete writer: remote-upstream mode
		// leaves upWriter nil, and (*mcp.MsgWriter).Write locks its mutex on a nil receiver — so
		// the saturation path would panic after its record rather than report. See writeToInitiator.
		unblocker: s.unblocker(),
		handle:    func(hctx context.Context, m mcp.RPCMsg) { s.proxy.handleHTTPUpstreamRequest(hctx, s, m) },
		revision:  s.hostRev,
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

// withUpstreamTimeout bounds an upstream call with the proxy's --upstream-timeout. The
// nil-proxy guard keeps zero-value test sessions working.
func (s *httpSession) withUpstreamTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if s.proxy == nil {
		return ctx, func() {}
	}
	return s.proxy.withUpstreamTimeout(ctx)
}

// errOut returns this session's diagnostic writer — its proxy's, or os.Stderr for a
// proxy-less test session — mirroring shutdownBudget's nil-safe fallback.
func (s *httpSession) errOut() io.Writer {
	return s.proxy.errOut()
}

// noticeWriter is this session's diagnostic channel: the proxy's writer, bounded by this session's
// ROUTE table rather than the proxy-wide aggregate, so one tenant's flood cannot silence another's
// lines — and under it this session's own reserved floor, so a SIBLING session's dead upstream
// cannot elide this one's first line of a class. Nil-safe throughout for a bare-struct-literal
// session.
func (s *httpSession) noticeWriter() noticeWriter {
	return s.proxy.sessionNoticeWriter(s, s.route)
}

// shutdownBudget is this session's configured teardown budget (--shutdown-grace), or a 5s
// fallback for a proxy-less test session — mirroring stdio's killDelay default.
func (s *httpSession) shutdownBudget() time.Duration {
	// shutdownMs <= 0 means "use the default", not "wait zero time" (mirrors killDelay's clamp).
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
	// Lazy init only fires for a test-assembled session (newSession initializes these); done
	// under pendingMu so the map-header write can't race the off-lock read elsewhere.
	s.pendingMu.Lock()
	if s.byUpstreamID == nil {
		s.byUpstreamID = make(map[string]chan upstreamResult)
	}
	if s.hostToUp == nil {
		s.hostToUp = make(map[string]*json.RawMessage)
	}
	s.pendingMu.Unlock()
	// A write timeout has already killed the subprocess via onPoison, which EOFs readUpstream
	// and reaps the session; awaitNonced just returns the error to the caller.
	return awaitNonced(ctx, &s.pendingMu, s.byUpstreamID, s.hostToUp, &s.upstreamSeq, s.teardownDone(), mcp.MsgKey(msg.ID),
		func(id *json.RawMessage) { msg.ID = id },
		func() error { return s.upWriter.Write(msg) })
}

// killSubprocess force-kills the session's upstream subprocess. It's the MsgWriter's onPoison
// hook: a desynced stream after a write timeout can't be reused, so killing it EOFs
// readUpstream and lets the cleanup goroutine reap the session. No-op for remote-HTTP; idempotent.
func (s *httpSession) killSubprocess() {
	killUpstreamCmd(s.upCmd)
}

// teardownDone returns sessCtx.Done(), unifying local and remote in-flight-call cancellation
// onto one primitive. Always live, so this reads it unconditionally.
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
		// Bound at notifyPostTimeout independent of --upstream-timeout (a no-op when
		// disabled), since this forward holds a notifySem slot for its duration and a
		// stalling upstream could otherwise pin it and starve other notifications. Mirrors
		// the stdio bridge's identical bound.
		notifyCtx, cancel := context.WithTimeout(ctx, notifyPostTimeout)
		defer cancel()
		if _, err := s.callRemoteUpstream(notifyCtx, msg); err != nil {
			// No response to deliver to the host; log so a dropped notification isn't silent.
			// Pre-gated: a down remote upstream fails every POST, so this is a per-frame line whose
			// arguments (a bounded method name, three boxed values) are pure waste when the bucket
			// discards it — see admitNotice.
			if line, ok := s.noticeWriter().admitNotice(siteUpstreamNotifyFailed); ok {
				line.writef("[eunox] HTTP session %s: notification %q POST to upstream failed: %v\n",
					s.id, audit.BoundEnvelopeField(msg.Method), err)
			}
		}
		return
	}
	// Subprocess upstream: the request id was nonce-rewritten, so translate a cancel's
	// params.requestId to that nonce; drop it if the target request is no longer in flight.
	//
	// Best-effort on HTTP: unlike stdio's single serve loop, each HTTP POST is an independent
	// goroutine, so a cancel on a concurrent connection can arrive before the target request's
	// handler has populated hostToUp. That narrow race drops the cancel, matching the MCP
	// spec's treatment of notifications/cancelled as inherently racy.
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
// accumulated flow-label set) via the route's PDP, so a reused session id starts clean. Called
// from the cleanup goroutine after <-sess.done on EVERY teardown path, including the natural
// upstream exit that close() alone does not cover.
//
// Waits for in-flight enforced decisions first (bounded by the shutdown budget), so a Clear
// can't empty the session's taint between a source's committed Add and a sink still deciding on
// the same session — the fail-open a teardown racing live decisions would otherwise open.
func releaseSessionState(sess *httpSession) {
	if sess.route == nil {
		return
	}
	budget := sess.shutdownBudget()
	sess.awaitInFlightDrained(budget)
	// Also drain server-initiated handlers, which run on their own goroutines rather than the
	// reader whose exit got us here; one still in flight could read flow state this release
	// is about to clear.
	sess.serverPool.drain(budget)
	// Must be on this every-teardown funnel (a session whose upstream exits on its own never
	// reaches close()) and after the drain (dropping the last reference deletes the gate from
	// the registry, so a still-turn-taking request must not find it gone first).
	if sess.dropDecideGate != nil {
		if sess.inFlight.Load() == 0 && sess.serverPool.inFlight.Load() == 0 {
			sess.dropDecideGate()
		} else {
			// The bounded drain above gave up on a handler still holding this session's pinned
			// turn. Dropping now anyway would delete the gate out from under it: the registry
			// would reap the entry and hand the next caller on the same anchor a FRESH gate with
			// an empty channel — two gates for one anchor, unserialized for as long as the
			// wedged handler runs. Hand the drop off to a waiter that keeps polling past the
			// budget instead of forcing it: one goroutine per timed-out teardown (a path that
			// already means something is wrong), unbounded in time, resolving whenever the
			// wedged handler finally returns.
			go awaitAndDropDecideGate(sess)
		}
	}
	// Gates cached for other anchors a spanning session resolved; see gateCache.close.
	sess.decideCache.close()
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	sess.route.pdp.ReleaseSession(ctx, sess.id)
}

// awaitAndDropDecideGate is releaseSessionState's fallback when its bounded drain gave up with
// a handler still holding the session's pinned decision gate. It polls past the budget — the
// same counters awaitInFlightDrained and serverPool.drain already watch, so this is not a
// second notion of "idle" — and drops the gate the instant both read zero, closing the window
// during which a request sharing this session's anchor could be handed a second, unserialized
// gate.
func awaitAndDropDecideGate(sess *httpSession) {
	for sess.inFlight.Load() > 0 || sess.serverPool.inFlight.Load() > 0 {
		time.Sleep(inFlightDrainPoll)
	}
	sess.dropDecideGate()
}

// awaitInFlightDrained blocks until this session has no enforced request in flight, or until
// timeout elapses. In-flight requests may still be mid-decision when teardown begins, so
// releasing flow state before they finish could drop a live taint. Bounded and poll-based: the
// wait must never be unbounded on a wedged handler.
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
		// Cancel the teardown context first, so every in-flight call (remote via
		// context.AfterFunc, local via awaitNonced's select on teardownDone) unblocks at once
		// through the one shared primitive; what follows is purely subprocess/connection reap.
		s.sessCancel()
		if s.upHTTPClient != nil {
			// Terminate the upstream MCP session with a bounded DELETE so the remote frees its
			// state. The *http.Transport connection pool is SHARED across the route's sessions,
			// so it is deliberately NOT closed here — released wholesale at proxy shutdown
			// instead (UpstreamRoute.closeIdleUpstreamConns).
			if s.upstreamSessID != "" && s.route != nil {
				DeleteMCPHTTPSession(s.upHTTPClient, s.mcpEndpointURL(), s.upstreamSessID, s.route.upstreamAuthHeader, s.upstreamRev, s.errOut())
			}
			close(s.done)
			return
		}
		if s.upIn != nil {
			_ = s.upIn.Close()
		}
		t := time.NewTimer(msToDuration(shutdownMs))
		defer t.Stop()
		select {
		case <-s.done:
		case <-t.C:
			killUpstreamCmd(s.upCmd)
			// Bound the post-kill wait independently: readUpstream normally closes done
			// almost immediately after the SIGKILL, but a reader wedged in a slow PDP/kill-
			// store call could otherwise hold teardown hostage past the shutdown deadline.
			waitBounded(s.done, msToDuration(shutdownMs), "upstream output stream", s.errOut())
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
				_, _ = fmt.Fprintf(s.errOut(),
					"[eunox] WARNING: HTTP session %s dropped a notification (method=%q) to a slow SSE subscriber; further drops counted but not individually logged.\n",
					s.id, msg.Method)
			}
		}
	}
}

// broadcastServerRequest tracks a server-initiated request's ID and delivers it to one SSE
// subscriber, reporting whether the host can service it (the host's response is later routed
// back by handleMCPPost). Such a request blocks the upstream until answered, so with no
// subscriber able to receive it, fail closed: untrack the ID and reply an error so the upstream
// unblocks, rather than let it hang until teardown.
// The refusal wiring is the SESSION's own (see newUpstreamRefusalLimiter): every category charged
// below is driven by this session's upstream, so the buckets it charges are per session and the
// caller no longer has to carry them in from the proxy.
func (s *httpSession) broadcastServerRequest(ctx context.Context, msg mcp.RPCMsg) bool {
	u := s.unblocker()
	// See forwardServerRequestToHost: an id the tracker will not retain must be REFUSED here, never
	// delivered untracked to a host whose answer nothing could route back.
	if !admitAndTrackServerRequest(ctx, u, msg) {
		return false
	}
	if s.deliverToOne(msg) {
		return true
	}
	u.unblock(ctx, msg.ID, "no client stream available to service server-initiated request")
	return false
}

// deliverToOne delivers a message to exactly one active SSE subscriber, reporting whether one
// accepted it. Broadcasting a server-initiated request would copy the payload to unintended
// streams and let multiple clients race to answer the same JSON-RPC id.
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

// sseSubscriberBufferSize bounds how many messages may queue for one open GET stream before
// back-pressure applies: broadcast() drops an excess notification, deliverToOne fails an excess
// server-initiated request closed. Sized for a well-behaved host with slack for short bursts.
const sseSubscriberBufferSize = 16

// maxSubsPerSession caps concurrent SSE subscribers on one session, bounding per-session memory
// against a client that opens many streams.
const maxSubsPerSession = 8

// addSub registers an SSE subscriber channel, returning false at maxSubsPerSession so the
// caller can reject the stream.
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

// removeSubAndDrain unsubscribes ch, then replies an error upstream for any server-initiated
// request still buffered in ch, so a client disconnect doesn't leave the upstream wedged until
// the idle reaper. removeSub runs first (both under notifMu) so the buffer is complete by the
// time this drains it. A request already streamed to the client before disconnect is not
// recovered here and relies on the idle reaper instead.
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

// failServerRequestDelivery unblocks the upstream when a server-initiated request already
// consumed from a subscriber channel cannot be relayed to the host. Untracks the ID and replies
// an error so the upstream doesn't hang. Shared by the SSE write loop and the drain path.
//
// The audit correction is the only per-caller difference from the shared unblock, and it is gated
// on the unblock having actually CONSUMED the request. That is what makes it exactly-once: both
// callers (the SSE write loop and the drain) can see the same message, and only one take succeeds.
func (s *httpSession) failServerRequestDelivery(ctx context.Context, msg mcp.RPCMsg, reason string) {
	ctx = s.withSessionClaims(ctx)
	if !s.unblocker().unblock(ctx, msg.ID, reason) {
		return
	}
	// This request was recorded as an allow when deliverToOne buffered it, but it never
	// reached the host — append a correction so the tamper-evident tape doesn't stand as
	// claiming delivery that didn't happen.
	s.unblocker().report.recordDrop(ctx, catServerRequestFailed, dropHTTPUndelivered, msg.Method)
}

// refusalRecorders is this session's wiring for a refusal record's recorder: the route's sink and
// this session's OWN upstream-driven bucket table, with forCategory applying each category's own
// declaration.
//
// Per session rather than the proxy-wide pre-session table: every category this leg charges is
// driven by this session's upstream, and a shared table let one dead subprocess suppress another
// session's record that a live in-flight request was lost. See newUpstreamRefusalLimiter.
func (s *httpSession) refusalRecorders() refusalRecorders {
	// Nil-route tolerant like every other accessor a bare-struct-literal session reaches
	// (noticeWriter, upstreamDenies): every unblocker() now resolves this, including the
	// tracker-only holders, so a routeless test session must degrade to recording nothing rather
	// than crash a leg that used to touch no route at all.
	var rec auditRecorder
	if s.route != nil {
		rec = asRecorder(s.route.sink)
	}
	return refusalLimits{records: s.upstreamDenies, notices: s.noticeWriter()}.recorders(rec)
}

// withSessionClaims stamps this session's captured JWT identity onto ctx, for a record written on a
// leg that has no request of its own to carry one. The sink reads agent / task / user off the
// context, so a record written without it is attributable to the session id alone.
func (s *httpSession) withSessionClaims(ctx context.Context) context.Context {
	if s.claims == nil {
		return ctx
	}
	return pdp.WithJWTClaims(ctx, s.claims)
}
