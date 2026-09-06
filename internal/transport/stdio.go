// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Package transport — stdio proxy transport.
//
//	MCP host  ──stdin/stdout──►  StdioProxy  ──►  upstream MCP server (subprocess)
//
// Enforced requests pass a PDP decision before forwarding; unmapped requests deny
// fail-closed. One goroutine reads the host, one reads the upstream.

package transport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/internal/drift"
	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/capability"
)

const (
	// proxyName is the clientInfo.name the proxy presents to upstreams. The CLI's
	// live-upstream probe reuses it via BuildUpstreamOpenerWithID rather than a second spelling.
	proxyName = "eunox-proxy"
)

// proxyVersion is the version reported in MCP initialize responses; set via SetProxyVersion.
var proxyVersion = "dev"

// SetProxyVersion sets the version string the proxy reports in MCP initialize
// responses. main.go's init calls it with the -ldflags build version, keeping
// the dependency one-directional (package main never writes this var directly).
func SetProxyVersion(v string) { proxyVersion = v }

// StdioProxy proxies MCP messages between the host (stdin/stdout) and an upstream MCP
// server, applying PDP enforcement to every enforced method plus the */list filters.
// Five wire methods map to four Decide* entry points: resources/subscribe is authorized
// through DecideResourceRead, while resources/unsubscribe has its own.
type StdioProxy struct {
	// Upstream wiring. A non-empty command selects a local subprocess upstream
	// (stdio); a non-empty upstreamURL selects a remote HTTP upstream. Exactly
	// one is set.
	command               string
	args                  []string
	upstreamURL           string
	upstreamAuthHeader    string
	upstreamTLSSkipVerify bool

	pdp  pdp.PolicyDecisionPoint
	sink *audit.Sink
	// policyVersion and policySHA256 are stamped onto every audit record via rec().
	policyVersion string
	policySHA256  string
	// recOnce/recCached cache rec()'s auditRecorder, built once from sink/policyVersion/
	// policySHA256. recCached stays the untyped nil auditRecorder when sink is nil, so
	// rec() returns a genuine nil rather than a non-nil interface wrapping a nil sink.
	recOnce            sync.Once
	recCached          auditRecorder
	sessionID          string
	shutdownMs         int
	upstreamTimeMs     int  // 0 = no timeout
	audit              bool // observe mode: evaluate and log, but forward instead of block
	requireAuditStrict bool // --require-audit=strict: deny forwards once the audit trail degrades
	// strictAuditWarned makes the strict-gate stderr warning one-shot (the gate is
	// sticky); the durable per-call signal is the AUDIT_UNAVAILABLE record.
	strictAuditWarned noticeLatch
	driftCheck        drift.CheckFunc

	// startupTimeout bounds the inline initialize + drift work in runBoundedStartup;
	// zero means sessionStartTimeout. Overridable so tests can exercise the watchdog
	// without a 20s wait.
	startupTimeout time.Duration

	// runtime (set in Start)
	upCmd    *exec.Cmd      // subprocess upstream only
	upIn     io.WriteCloser // subprocess upstream only
	upHTTP   *httpUpstream  // remote HTTP upstream only
	upReader mcp.MsgSource

	// killTimer is the SIGKILL fallback armed by signalUpstream during a graceful
	// shutdown; Start's teardown stops it once the upstream has exited, suppressing a
	// spurious "sending SIGKILL" log line. killMu: signalUpstream writes, teardown reads.
	killMu    sync.Mutex
	killTimer *time.Timer

	hostReader *mcp.MsgReader
	hostWriter *mcp.MsgWriter

	upWriter mcp.MsgSink // subprocess pipe or HTTP bridge; concurrency-safe

	// pendingMu guards byUpstreamID, hostToUp, and upstreamSeq.
	pendingMu sync.Mutex
	// byUpstreamID routes upstream responses back to the waiting caller, keyed by the
	// proxy-generated nonce, so a late response for a timed-out call can never be
	// misrouted into a later request that reused the same host ID.
	byUpstreamID map[string]chan upstreamResult
	// hostToUp maps a live request's host ID to the upstream nonce, so a
	// notifications/cancelled can have its params.requestId translated to the id the
	// upstream actually saw. Also doubles as the in-flight host-ID set the duplicate-ID
	// rejection in awaitNonced reads, rather than keeping a separate `pending` set.
	hostToUp map[string]*json.RawMessage
	// upstreamSeq is the monotonically increasing nonce source for upstream IDs.
	upstreamSeq uint64

	// serverReqs tracks server-initiated request IDs forwarded to the host, so serveHost
	// can route the host's response back to the upstream instead of dropping it.
	serverReqs serverReqTracker

	// upstreamDone is closed by readUpstream when the upstream exits, so pending
	// callUpstream callers return immediately rather than waiting for ctx cancel.
	upstreamDone chan struct{}

	upstreamCaps          map[string]interface{}
	upstreamServerVersion string
	upstreamInstructions  string

	// upstreamRev is the protocol revision this proxy speaks to its upstream, decided at
	// CONSTRUCTION from the operator's pin (UpstreamOpenRevision) and read-only after — it
	// selects the opener, so it cannot be a conclusion drawn from the opener's own reply. It
	// is tracked apart from the host side because the two peers migrate independently —
	// standing between a pair that disagrees is the whole reason a proxy exists.
	upstreamRev capability.Revision

	// hostRev is the revision this host connection's context resolved, pinned from its first
	// message the resolved revision DISPATCHES in the framing it arrived in (see
	// negotiateHostRevision for why the second half is load-bearing) and checked against every
	// later one (resolveHostRevision), so a mid-context flip is refused rather than silently
	// switching method tables.
	//
	// WRITTEN only by serveHost, inline on the loop that reads host messages, before the
	// per-request handler is spawned. Pinning it from the initialize RESPONSE instead was the
	// obvious placement and was wrong twice over: that runs on a handler goroutine, so the loop
	// could read it stale for a pipelined follow-up request — a check-then-act window -race
	// cannot see, since the value itself is atomic — and a context that never sends initialize,
	// which is every peer on a revision that removed it, would never pin at all, leaving the
	// flip refusal permanently inert for exactly the revision that mandates per-request
	// declarations.
	//
	// Atomic because the SERVER-initiated leg reads it from its own goroutine to stamp the
	// revision on records that leg writes; the single writer is what makes the pin correct,
	// the atomic only makes that read safe.
	hostRev atomic.Value // capability.Revision

	// idCounter is used for the proxy→upstream initialize request ID.
	idCounter int64

	// hostSem bounds concurrent in-flight host-request handler goroutines. serveHost
	// acquires a slot non-blockingly and rejects with a structured error on saturation, so
	// a pipelining host — or a silent upstream under --upstream-timeout=0, where handlers
	// never return — cannot grow goroutines or the pending maps without bound. Sized
	// lazily on serveHost entry, the sole initialization site, before any handler dispatch.
	hostSem chan struct{}

	// hostSaturation gates the RESOURCE_EXHAUSTED record hostSem writes on refusal, the
	// stdio counterpart of the HTTP transport's per-session gates; collapses a saturation
	// episode into one record carrying the elided-refusal count. Zero value usable.
	hostSaturation saturationGate

	// refusalLimiter bounds the refusal records this transport's host can drive directly — the
	// categories stdioRefusalCategories declares, and buckets for those alone rather than the
	// whole table. nil (a proxy assembled by a bare struct literal) records unbounded, as the
	// HTTP sibling's nil does.
	refusalLimiter *categoryRecordLimiter

	// notices is this transport's stderr-diagnostic table, one bucket per notice CLASS. Separate
	// from the record buckets above because this transport meters almost no record its host drives
	// (an established session's are deliberately unbounded) and still owes a bound on a write
	// syscall per frame — the cheapest thing a peer pipelining `{"jsonrpc":"2.0","method":"x/bogus"}`
	// down one pipe can make this process do. No parent: stdio serves ONE upstream, so this table
	// is both the tenant's and the aggregate. See noticeLimiter.
	notices *noticeLimiter

	// serverPool bounds, dispatches and drains this proxy's SERVER-initiated request
	// handlers, the upstream-facing twin of hostSem/hostSaturation. readUpstream hands each
	// server-initiated request to it rather than running the handler inline — see
	// serverRequestPool for why that is a correctness property of the reader, not a latency
	// preference. Zero value usable.
	serverPool serverRequestPool

	// fwdHostWrites preserves host wire order across the request/notification boundary: it
	// counts requests dispatched but not yet written upstream, and serveHost waits on it
	// before forwarding a notification so it cannot overtake requests sent before it.
	// callUpstream releases a request's slot the instant it reaches the wire — not when its
	// response arrives — so cancelling a slow call never deadlocks the barrier.
	fwdHostWrites sync.WaitGroup
	// fwdHostInFlight mirrors fwdHostWrites' counter as a readable atomic so
	// waitHostForwardOrShutdown can skip the waiter goroutine when the barrier is already
	// drained — the common case for a notification-heavy host.
	fwdHostInFlight atomic.Int64
	// hostHandlers counts dispatched host handlers that have not RETURNED, which is a
	// different span from the barrier above: that one is released at the wire, so it reads
	// zero while a handler is still processing the upstream's reply. Teardown needs the
	// longer span — the list leg touches the Tier-2 baseline after callUpstream returns —
	// so this is what awaitHostDecisionsDrained waits on. The stdio counterpart of
	// httpSession.inFlight, which HTTP likewise holds for the whole handler.
	hostHandlers atomic.Int64

	// upstreamTornDown marks that teardown has begun forcing the upstream down, so the
	// reader can tell an upstream fault from the consequence of this proxy's own shutdown.
	// Set only after the graceful drain has already given up: os/exec's cmd.Wait closes the
	// StdoutPipe under a reader still parked in a read, so on that branch the reader's next
	// error IS the teardown, and reporting it as an upstream read error is a line an
	// operator has to rule out on every forced shutdown.
	upstreamTornDown atomic.Bool

	// decideGate serializes this proxy's enforced-request decisions in proxy-receipt order,
	// per state anchor, when the policy accumulates state one call writes and a later one
	// reads. nil keeps full intra-session decision parallelism.
	decideGate *decisionSerializer

	// taskAnchored is the operator's WithTaskAnchoredState setting for this upstream (the
	// same bit the PDP's engine was built with), carried so the proxy can resolve a
	// request's decision-turn anchor through the same resolver the engine's key builder
	// uses. See decisionAnchor.
	taskAnchored bool

	// claims are the validated JWT claims this host connection carries, captured ONCE in
	// Start. A stdio host has one connection and no per-request token channel, so a
	// connection-level identity is the only identity there is; both legs resolve their
	// anchor from this one field so they cannot land on different turns. nil in every
	// shipped configuration (--jwks-uri is refused on stdio), resolving every request to
	// the session anchor.
	claims *pdp.JWTClaims

	// decideQueue is this proxy's pinned ticket queue; dropDecideQueue releases it. The
	// anchor is a per-proxy constant (see claims), so the queue is resolved once at startup
	// rather than re-rendering the key and re-entering the registry on every enforced
	// request on the hot read loop.
	decideQueue     *ticketQueue
	dropDecideQueue func()

	// receipts verifies signed effect receipts published by this proxy's single upstream,
	// against the key domain the operator configured for it. nil disables the surface.
	receipts *capability.EffectReceiptVerifier

	// honorAttribution admits the client-supplied attribution interface. Set from
	// StdioProxyOptions.HonorAttribution at construction.
	honorAttribution bool

	// onReady is the post-startup hook, run once the session is live. Set from
	// StdioProxyOptions.OnReady at construction.
	onReady func(ctx context.Context)

	// stderr is where this proxy writes its diagnostic lines. Read through errOut(), never
	// referenced directly — see HTTPProxy.stderr for why: a caller that wants to capture
	// output configures the writer here rather than reassigning the process-global os.Stderr.
	stderr io.Writer
}

// errOut returns p's diagnostic writer, falling back to os.Stderr for a nil proxy or one
// assembled by a bare struct literal (stderr left unset).
func (p *StdioProxy) errOut() io.Writer {
	if p == nil {
		return os.Stderr
	}
	return resolvedErrOut(p.stderr)
}

// StdioProxyOptions configures a StdioProxy. The upstream is either a local
// subprocess (set Command/Args) or a remote HTTP server (set UpstreamURL).
type StdioProxyOptions struct {
	Command               string
	Args                  []string
	UpstreamURL           string // remote HTTP upstream; mutually exclusive with Command
	UpstreamAuthHeader    string // "Name: Value" header injected on every upstream request
	UpstreamTLSSkipVerify bool   // skip TLS verification for the remote upstream (dev only)
	PDP                   pdp.PolicyDecisionPoint
	Sink                  *audit.Sink
	// PolicyVersion and PolicySHA256 are the merged manifest's provenance, stamped onto
	// every audit record the same way the gateway's routeSink stamps them per route.
	PolicyVersion      string
	PolicySHA256       string
	SessionID          string
	ShutdownMs         int
	UpstreamTimeMs     int
	Audit              bool // observe mode: evaluate and log, but forward instead of block
	RequireAuditStrict bool // --require-audit=strict: deny forwards once the audit trail degrades

	// SerializeDecisions serializes this proxy's enforced-request decisions in
	// proxy-receipt order, per state anchor, so a source's flow-label write is ordered
	// before a later sink's read even under a pipelining client. The binary sets it from
	// config.LocalManifest.NeedsDecisionTurn, the same predicate the gateway route builder
	// uses, so the two transports cannot disagree about which policies need a turn.
	SerializeDecisions bool

	// TaskAnchoredState reports that this upstream's engine keys accumulated state on the
	// validated mcp.task_id claim rather than on the session; the proxy keys each request's
	// decision turn on the same anchor. Inert on a stdio host as shipped (nothing on this
	// path attaches validated claims, so every request anchors on the session) but wired
	// anyway so a token-aware PDP handed in through the PDP seam gets anchor-keyed
	// serialization by construction.
	TaskAnchoredState bool

	// HonorAttribution admits the client-supplied attribution interface (the
	// io.eunolabs.context-manifest block in a request's _meta). The binary sets it only
	// under the flow+effect draft schemaVersion, so a policy on the published grammar
	// ignores a block that grammar does not contain.
	HonorAttribution bool

	// EffectReceipts verifies signed effect receipts this upstream publishes in a tool
	// result's `_meta`. nil (the default) disables the surface entirely.
	EffectReceipts *capability.EffectReceiptVerifier

	// DriftCheck is the injected drift hook; nil = no drift checking.
	DriftCheck drift.CheckFunc

	// UpstreamProtocolVersion pins the protocol revision this proxy speaks to its upstream,
	// which SELECTS the opener rather than relabelling a leg opened some other way. Empty
	// (the default) opens with the handshake, and the upstream's reported version must then
	// agree with it — see UpstreamOpenRevision and checkNegotiatedRevision.
	UpstreamProtocolVersion capability.Revision

	// OnReady, when non-nil, runs inside Start once the session is live and before the host
	// serve loop begins — the stdio analogue of HTTPGatewayOptions.AfterListen. It runs
	// after every fallible startup step so a process that never comes up cannot clobber
	// shared, last-writer-wins state (e.g. the session-kill TTL) a running proxy owns.
	// Bounded by Start's context; unlike AfterListen it returns no error since its callers
	// are advisory-only. Called exactly once, on the success path.
	OnReady func(ctx context.Context)

	// Stderr is where this proxy writes its diagnostic lines. Nil (the default) means
	// os.Stderr; a caller that wants to capture them passes its own writer here instead of
	// reassigning the process-global os.Stderr, which races any other goroutine reading it.
	Stderr io.Writer
}

// NewStdioProxy creates a StdioProxy ready to call Start.
//
// It panics on an options field that is WIRED but holds a typed nil — see requireUsableOptions.
// That is not the same fault as an omitted one: a nil PDP is answered below by denying everything,
// which is the fail-closed answer to "no policy was supplied", while a PDP interface holding a nil
// pointer would dereference a nil receiver on the first request rather than deny it.
func NewStdioProxy(opts StdioProxyOptions) *StdioProxy {
	requireUsableOptions(opts)
	// Fail closed: a caller that omits a PDP denies every request. Production
	// always wires a concrete PDP; this guards the exported library seam.
	// Wiretap/audit mode opts in explicitly with AlwaysAllowPDP.
	if opts.PDP == nil {
		opts.PDP = pdp.DenyAllPDP{}
	}
	if opts.ShutdownMs <= 0 {
		opts.ShutdownMs = 5000
	}
	// No Stderr default: every read resolves through errOut(). See resolvedErrOut.
	p := &StdioProxy{
		command:               opts.Command,
		args:                  opts.Args,
		upstreamURL:           opts.UpstreamURL,
		upstreamAuthHeader:    opts.UpstreamAuthHeader,
		upstreamTLSSkipVerify: opts.UpstreamTLSSkipVerify,
		pdp:                   opts.PDP,
		sink:                  opts.Sink,
		policyVersion:         opts.PolicyVersion,
		policySHA256:          opts.PolicySHA256,
		sessionID:             opts.SessionID,
		shutdownMs:            opts.ShutdownMs,
		upstreamTimeMs:        opts.UpstreamTimeMs,
		audit:                 opts.Audit,
		requireAuditStrict:    opts.RequireAuditStrict,
		taskAnchored:          opts.TaskAnchoredState,
		driftCheck:            opts.DriftCheck,
		upstreamRev:           UpstreamOpenRevision(opts.UpstreamProtocolVersion),
		honorAttribution:      opts.HonorAttribution,
		receipts:              opts.EffectReceipts,
		onReady:               opts.OnReady,
		stderr:                opts.Stderr,
		byUpstreamID:          make(map[string]chan upstreamResult),
		hostToUp:              make(map[string]*json.RawMessage),
		hostReader:            mcp.NewMsgReader(os.Stdin),
		hostWriter:            mcp.NewMsgWriter(os.Stdout),
		refusalLimiter:        newRefusalRecordLimiterFor(stdioRefusalCategories),
		notices:               newNoticeLimiter(1),
	}
	if opts.SerializeDecisions {
		p.decideGate = newDecisionSerializer()
	}
	return p
}

// rec returns the auditRecorder every enforcement/notification path in this file records
// through, wrapping p.sink in a routeSink (upstream "" — single-upstream mode) so
// policyVersion/policySHA256 are stamped exactly as the gateway's routeSink stamps them
// per route. Cached once (recOnce/recCached) rather than rebuilt per call, both to avoid
// a per-request allocation and because a freshly-wrapped &routeSink{} is never the nil
// pointer callers' `rec() != nil` / `d.rec != nil` guards look for — returning the
// untyped nil interface directly when p.sink is nil keeps those guards a real "no sink"
// test rather than the typed-nil trap.
func (p *StdioProxy) rec() auditRecorder {
	p.recOnce.Do(func() {
		if p.sink != nil {
			// Bound once here, matching BuildRoutes' gateway routeSink construction: these
			// fields are fixed for the process's lifetime. See audit.BoundEnvelopeField.
			p.recCached = &routeSink{
				sink:          p.sink,
				policyVersion: audit.BoundEnvelopeField(p.policyVersion),
				policySHA256:  audit.BoundEnvelopeField(p.policySHA256),
			}
		}
	})
	return p.recCached
}

// Start runs the proxy until the host closes stdin or the upstream exits.
// It returns when the session ends.
func (p *StdioProxy) Start(ctx context.Context) error {
	// Arm the host stdout writer's desync teardown before anything can write to it: writes
	// are fire-and-forget, so without a hook a single partial write latches the writer and
	// the proxy keeps enforcing and forwarding while every response is silently discarded.
	// No deadline is armed — a slow host is not a policy failure — so this covers only the
	// desync case.
	//nolint:contextcheck // teardown: detached, bounded background context; this hook fires from inside a framed write, which carries no request context.
	p.hostWriter.SetPoisonHook(func() {
		_, _ = fmt.Fprintf(p.errOut(), "[eunox] FATAL: host stdout framing desynced (partial write); tearing down the upstream — no further responses can be delivered.\n")
		p.killUpstream()
	})
	// Captured once: a stdio host has one connection, so these are the claims every request
	// on it carries. Both legs' decision turns resolve from this field so they cannot
	// disagree about which subject this proxy's state accrues to.
	p.claims = pdp.JWTClaimsPtr(ctx)
	// The anchor follows from that identity and is therefore a constant, so the ticket queue
	// is resolved now rather than on every enforced request. Released in Start's teardown.
	p.pinDecisionQueue()
	if p.dropDecideQueue != nil {
		defer p.dropDecideQueue()
	}

	// ── 1. Connect to upstream (subprocess or remote HTTP) ─────────────────────
	if err := p.connectUpstream(ctx); err != nil {
		return err
	}

	// ── 2-3. Initialize handshake + drift check, bounded by sessionStartTimeout ──
	// Both run blocking upstream pipe reads inline, before readUpstream owns the reader.
	// A subprocess that launches but never answers has no internal read deadline, so
	// without this watchdog Start hangs indefinitely until an operator signals it.
	if err := p.runBoundedStartup(ctx, func() error {
		if err := p.initUpstream(ctx); err != nil {
			return wrapUpstreamOpenFailure(p.upstreamRev, err)
		}
		if p.driftCheck != nil {
			raw, probeErr := p.fetchUpstreamToolsRaw(ctx)
			// Take the Tier-2 interface baseline from the earliest view of the advertised
			// surface this session has, so a rewrite before the host's first tools/list
			// already trips a pin break. Runs before the drift check so a refused session
			// leaves no half-baselined state (ReleaseSession clears it either way). A probe
			// failure records nothing; the first host tools/list establishes the baseline.
			if probeErr == nil {
				p.pdp.RecordObservedToolHashes(pdp.WithCompleteToolListing(pdp.WithSessionID(ctx, p.sessionID)), raw)
			}
			if err := p.driftCheck(raw, p.upstreamServerVersion, probeErr); err != nil {
				// A startup drift failure is the FM-5 tool-poisoning / rug-pull event this
				// check exists to catch, so it belongs on the tamper-evident tape, not only
				// stderr (which keeps the raw, tool-naming reason).
				recordDriftRefused(ctx, p.rec(), p.sessionID)
				// Release the Tier-2 baseline just recorded above: a startup refusal returns
				// straight out of Start, so the normal teardown release never runs this path.
				// Detached and bounded like the teardown release below, since a drift refusal
				// is routinely reached with ctx already done (e.g. a Ctrl-C during startup).
				releaseCtx, releaseCancel := context.WithTimeout(context.Background(), msToDuration(p.shutdownMs))
				p.pdp.ReleaseSession(releaseCtx, p.sessionID) //nolint:contextcheck // startup-refusal teardown: detached and bounded, matching Start's own release path.
				releaseCancel()
				return err
			}
		}
		return nil
	}); err != nil {
		p.killUpstream() //nolint:contextcheck // teardown: detached, bounded background context; no request context here.
		// Reap the killed subprocess: killUpstream only signals, so without Wait the child
		// stays a zombie and os/exec never closes the stdin/stdout pipe FDs. No reader races
		// Wait since the inline startup fn has returned; a no-op for a remote HTTP upstream.
		p.waitUpstream()
		return err
	}

	// ── 4. Read upstream messages in background ────────────────────────────────
	p.upstreamDone = make(chan struct{})
	//nolint:contextcheck // readUpstream is a background reader for server-initiated
	// messages that carry no request context; the stdio transport has no JWT, so
	// sampling decisions are audited with a background context (no agent/task).
	go func() {
		defer close(p.upstreamDone)
		p.readUpstream(ctx)
	}()

	// ── 5. Install signal handler → graceful upstream shutdown ─────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() { //nolint:contextcheck // teardown: detached, bounded background context; no request context here.
		sig, ok := <-sigCh
		if !ok {
			return
		}
		_, _ = fmt.Fprintf(p.errOut(), "[eunox] Received %s; shutting down upstream.\n", sig)
		p.signalUpstream(sig)
	}()

	_, _ = fmt.Fprintf(p.errOut(), "[eunox] Session %s initialized; proxying to %q.\n", p.sessionID, p.upstreamLabel())

	// Post-startup effects (see StdioProxyOptions.OnReady), placed after every fallible
	// startup step so a proxy that never comes up cannot overwrite shared state a running
	// one owns. Nothing between this line and the serve loop can fail.
	if p.onReady != nil {
		p.onReady(ctx)
	}

	// ── 6. Serve host until stdin closes ───────────────────────────────────────
	p.serveHost(ctx)

	// ── 7. Drain upstream reader ──────────────────────────────────────────────
	signal.Stop(sigCh)
	close(sigCh)
	p.closeUpstreamInput() //nolint:contextcheck // teardown: detached, bounded background context; no request context here.
	p.awaitUpstreamDrain() //nolint:contextcheck // teardown: detached, bounded background context; no request context here.
	// Upstream has exited: stop the SIGKILL fallback (if armed) so a clean shutdown
	// emits no spurious "sending SIGKILL" line and the timer is freed promptly.
	p.stopKillTimer()
	// The invariant newSession states — never Wait while a StdoutPipe read is in flight — scopes
	// to a reader that can still make progress. On awaitUpstreamDrain's give-up path the
	// subprocess is already SIGKILLed and the drain timed out, so Wait's pipe close is what
	// unwedges the reader rather than a race with it.
	p.waitUpstream()

	// ── 8. Release this session's per-session enforcement state ─────────────────
	// Ordered last and gated behind a bounded drain of in-flight host decisions: on the
	// signal/upstream-exit paths serveHost returns WITHOUT waiting for handlers, and
	// draining the upstream reader does not cover a handler still mid-decision (a sink
	// peeking the flow set touches no upstream) — without the drain, a release here could
	// empty the taint between a source's committed write and a sink still deciding.
	p.awaitHostDecisionsDrained(msToDuration(p.shutdownMs))
	// Same concern for server-initiated handlers, which run on their own goroutines rather
	// than the reader step 7 just drained.
	p.awaitServerRequestsDrained(msToDuration(p.shutdownMs))
	releaseCtx, releaseCancel := context.WithTimeout(context.Background(), msToDuration(p.shutdownMs))
	p.pdp.ReleaseSession(releaseCtx, p.sessionID) //nolint:contextcheck // teardown: the host is gone; detached, bounded context is correct here too.
	releaseCancel()

	return nil
}

// awaitHostDecisionsDrained blocks until no dispatched host request is still mid-decision, or
// until timeout elapses, so teardown does not clear per-session state out from under a handler
// still deciding (the stdio analogue of httpSession.awaitInFlightDrained). Bounded and
// poll-based: teardown must never hang on a wedged handler.
//
// Runs for every session, not just a flow-serialized one, and waits on hostHandlers rather than
// on the wire-order barrier. Two premises were wrong. ReleaseSession is not a no-op without a
// decision gate: it also drops the Tier-2 interface baseline, which exists independently of
// NeedsDecisionTurn. And fwdHostInFlight is released at the WIRE (see releaseHostForward), so it
// reads zero while a handler is still processing the reply — where the list leg re-reads and
// rewrites that baseline. Between them, teardown could clear the baseline under a live tools/list,
// whose filter then re-baselines the surface it was supposed to diff against: a changed surface
// neither hidden nor denied, the fail-open direction. On an already-drained counter this costs one
// atomic load.
func (p *StdioProxy) awaitHostDecisionsDrained(timeout time.Duration) {
	awaitDrained(&p.hostHandlers, timeout)
}

// awaitServerRequestsDrained blocks until every dispatched SERVER-initiated handler has
// returned, or until timeout elapses — the proxy-scoped name for the pool's own drain, which
// the HTTP transport calls per session. See serverRequestPool.drain for the teardown concern
// it answers.
func (p *StdioProxy) awaitServerRequestsDrained(timeout time.Duration) {
	p.serverPool.drain(timeout)
}

// awaitDrained polls counter to zero, giving up after timeout. Shared by the two teardown
// drains since both counters' increment sites have stopped by the time Start calls these, so
// a counter only falls and nothing can slip in uncounted.
func awaitDrained(counter *atomic.Int64, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for counter.Load() > 0 {
		if !time.Now().Before(deadline) {
			return
		}
		time.Sleep(inFlightDrainPoll)
	}
}

// connectUpstream establishes the upstream connection and wires upWriter/upReader:
// a remote HTTP bridge when upstreamURL is set, otherwise a local subprocess.
func (p *StdioProxy) connectUpstream(ctx context.Context) error {
	if p.upstreamURL != "" {
		up := newHTTPUpstream(ctx, p.upstreamURL, p.upstreamAuthHeader, p.upstreamTLSSkipVerify, p.upstreamTimeMs)
		// The bridge's diagnostic channel — writer AND bucket — in ONE assignment: its
		// notification-POST failure line is per frame, driven by the host's send rate against an
		// unreachable upstream, so a channel wired half at construction and half here is one
		// reorder away from unbounded.
		up.notices = p.noticeWriter()
		// A transport-level POST failure is reported back through upErr so the waiting
		// caller records a deny/UPSTREAM_ERROR (matching the gateway) rather than an allow.
		up.reportErr = p.reportUpstreamErr
		// Pinned HERE, before the opener runs, not after it returns: on a declaring leg the
		// opener is an ordinary request and carries the MCP-Protocol-Version header like any
		// other, so a bridge still holding the empty revision would open the leg naming a
		// version this proxy is not speaking.
		up.setRevision(p.upstreamRev)
		p.upHTTP = up
		p.upWriter = up
		p.upReader = up
		// A remote HTTP upstream has no inbound stream, so its own server-initiated requests
		// are never read or replied to; surface that so an operator isn't left debugging a
		// silent hang. Redact the URL — no route name here to label the notice with instead —
		// so a userinfo/query credential never reaches stderr.
		printRemoteUpstreamNotice(p.errOut(), capability.RedactURLForLog(p.upstreamURL), "")
		return nil
	}

	// Deliberately exec.Command, NOT exec.CommandContext: Go's default CommandContext
	// Cancel is Process.Kill() (SIGKILL), so binding the subprocess to ctx would SIGKILL
	// it the instant the first SIGINT/SIGTERM cancels ctx — pre-empting the graceful
	// SIGTERM-then-SIGKILL-after-shutdownMs escalation signalUpstream implements. The
	// subprocess lifecycle is instead managed explicitly (signalUpstream on a signal,
	// runBoundedStartup's watchdog on startup, awaitUpstreamDrain's force-kill on host
	// EOF), matching the HTTP transport's deliberate exec.Command choice in
	// http_session.go's newSession.
	p.upCmd = exec.Command(p.command, p.args...) //nolint:gosec,noctx // G204: args are user-supplied CLI arguments; lifecycle managed by signalUpstream/awaitUpstreamDrain, not ctx (matches http_session.go)
	ConfigureUpstreamCmd(p.upCmd)

	upIn, err := p.upCmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("upstream stdin: %w", err)
	}
	p.upIn = upIn

	upOut, err := p.upCmd.StdoutPipe()
	if err != nil {
		// Start is never reached on this path, so Cmd.Start's deferred pipe cleanup
		// never runs. Close the parent write end we hold. (The child read end stashed
		// in upCmd is only reclaimed by its *os.File finalizer, so this frees one of
		// the two FDs, not both.)
		_ = upIn.Close()
		return fmt.Errorf("upstream stdout: %w", err)
	}
	// Bound each host->upstream pipe write by --upstream-timeout so a subprocess that stops
	// draining its stdin cannot wedge the write — and, through the MsgWriter mutex and the
	// serve loop's ordering barrier, the whole session — until SIGINT. A write timeout
	// poisons the writer and kills the upstream, unblocking readUpstream and the serve loop;
	// --upstream-timeout=0 leaves the write unbounded (the operator's opt-out).
	p.upWriter = mcp.NewMsgWriterWithTimeout(upIn, msToDuration(p.upstreamTimeMs), p.killUpstream)
	p.upReader = mcp.NewMsgReader(upOut)

	if err := p.upCmd.Start(); err != nil {
		// No pipe cleanup here: a failed Cmd.Start closes both the parent ends
		// (upIn/upOut) and the child ends via its own deferred cleanup.
		return fmt.Errorf("starting upstream %q: %w", p.command, err)
	}
	return nil
}

// upstreamLabel describes the upstream for log lines: the subprocess command or
// the remote URL.
func (p *StdioProxy) upstreamLabel() string {
	if p.upHTTP != nil {
		// Redact before it reaches a log line: a remote upstreamUrl may carry a userinfo
		// or ?api_key= credential that must not leak to stderr — the same consolidated
		// redactor the live probe and doctor bundle use.
		return capability.RedactURLForLog(p.upstreamURL)
	}
	return p.command
}

// killUpstream forcibly stops the upstream, used when startup (initialize or
// drift) fails.
//
// The whole process GROUP is killed, not just the direct child: an upstream launched
// through a wrapper (`npx`, `uvx`, a shell script) execs or forks the real server as a
// grandchild holding the same stdout pipe, and killing only the wrapper leaves that
// pipe open forever — so the EOF every post-kill wait here is waiting for never
// arrives. The direct child is signalled first regardless, so an upstream for which no
// group was established is still killed (see procgroup_unix.go).
func (p *StdioProxy) killUpstream() {
	if p.upHTTP != nil {
		p.upHTTP.close()
		return
	}
	killUpstreamCmd(p.upCmd)
}

// signalUpstream begins a graceful upstream shutdown in response to sig: a
// subprocess is sent the signal with a SIGKILL fallback after shutdownMs; a
// remote HTTP upstream is closed (canceling in-flight requests).
func (p *StdioProxy) signalUpstream(sig os.Signal) {
	if p.upHTTP != nil {
		p.upHTTP.close()
		return
	}
	// The whole tree, so a wrapper's grandchild gets the chance to shut down gracefully
	// too rather than only being reaped by the SIGKILL fallback below.
	signalUpstreamProcess(p.upCmd.Process, sig)
	t := time.AfterFunc(p.killDelay(), func() {
		if p.upCmd.Process != nil {
			_, _ = fmt.Fprintf(p.errOut(), "[eunox] Upstream did not exit; sending SIGKILL.\n")
			killUpstreamProcess(p.upCmd.Process)
		}
	})
	p.killMu.Lock()
	p.killTimer = t
	p.killMu.Unlock()
}

// awaitUpstreamDrain waits for readUpstream to finish after the proxy→upstream input has
// been closed, but bounds the wait: a daemon-style subprocess that ignores stdin EOF and
// holds its stdout open would otherwise hang Start forever on a host disconnect, defeating
// graceful shutdown and skipping the deferred audit-sink flush. Force-kills after shutdownMs
// and waits, mirroring httpSession.close's bounded teardown.
func (p *StdioProxy) awaitUpstreamDrain() {
	select {
	case <-p.upstreamDone:
		return
	case <-time.After(p.killDelay()):
		_, _ = fmt.Fprintf(p.errOut(), "[eunox] Upstream did not exit after host disconnect; forcing shutdown.\n")
		// Set BEFORE the kill: from here the reader's pipe can be closed by this teardown
		// (the kill, or the cmd.Wait that follows a timed-out drain), and the line it would
		// write about that names no fault of the upstream's. This one line already says the
		// shutdown was forced.
		p.upstreamTornDown.Store(true)
		p.killUpstream()
		// Bound the post-kill wait independently: the kill EOFs the pipe almost immediately
		// in the ordinary case, but a descendant that escaped the process group can still
		// hold it open, and an unbounded wait here would leave the proxy never exiting and
		// never flushing its audit sink.
		waitBounded(p.upstreamDone, p.killDelay(), "upstream output stream", p.errOut())
	}
}

// stopKillTimer cancels the SIGKILL fallback signalUpstream armed, if any, and reports
// whether it was cancelled before firing. Every teardown that has already reaped the
// upstream must call it: an uncancelled time.AfterFunc logs a spurious "sending SIGKILL"
// and signals an already-reaped process at an arbitrary later point.
//
// A false return means the timer had already fired; Stop does not wait for a started
// AfterFunc, and this deliberately does not either — waiting would block teardown on that
// goroutine's stderr write, the same stall the audit sink avoids by keeping stderr off its lock.
func (p *StdioProxy) stopKillTimer() bool {
	p.killMu.Lock()
	t := p.killTimer
	p.killMu.Unlock()
	if t == nil {
		return true
	}
	return t.Stop()
}

// killDelay is the grace period before a graceful upstream shutdown escalates to a
// force-kill: the configured shutdownMs, or a 5s fallback for a zero-value proxy. Shared by
// the signal and host-EOF teardown paths so both bound a wedged upstream identically.
func (p *StdioProxy) killDelay() time.Duration {
	killMs := p.shutdownMs
	if killMs <= 0 {
		killMs = 5000
	}
	return msToDuration(killMs)
}

// closeUpstreamInput closes the proxy→upstream channel so the upstream sees EOF
// (subprocess) or in-flight requests are canceled (HTTP), draining readUpstream.
func (p *StdioProxy) closeUpstreamInput() {
	if p.upHTTP != nil {
		p.upHTTP.close()
		return
	}
	// upIn is nil when no subprocess pipe was wired (e.g. a unit test driving
	// serveHost directly without connectUpstream), so guard the nil dereference.
	if p.upIn != nil {
		_ = p.upIn.Close()
	}
}

// waitUpstream waits for a subprocess upstream to exit; a no-op for HTTP.
func (p *StdioProxy) waitUpstream() {
	if p.upCmd != nil {
		_ = p.upCmd.Wait()
	}
}

// runBoundedStartup runs the blocking session-start work fn under a sessionStartTimeout
// deadline: on expiry the subprocess is killed (EOF-ing the pipe) to unblock fn's read, then
// fn is awaited — mirroring httpSession.initUpstream. Without this, a subprocess that never
// answers initialize (or the drift probe) hangs Start until an operator signals it. The
// remote-HTTP bridge already bounds its own reads via per-request timeouts, so the watchdog
// applies only to the subprocess path.
func (p *StdioProxy) runBoundedStartup(ctx context.Context, fn func() error) error {
	if p.upHTTP != nil {
		return fn()
	}
	timeout := p.startupBudget()
	startCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		return err
	case <-startCtx.Done():
		p.killUpstream() //nolint:contextcheck // teardown: detached, bounded background context; no request context here.
		// Bound the post-kill wait too: an escaped-process-group descendant can hold the
		// pipe open indefinitely, and this watchdog's whole job is to bound a wedged upstream.
		waitBounded(done, p.killDelay(), "upstream startup output stream", p.errOut())
		return fmt.Errorf("upstream did not complete startup within %s: %w", timeout, startCtx.Err())
	}
}

// startupBudget is the session-start deadline: the configured startupTimeout, or the
// sessionStartTimeout default when unset. It bounds both the subprocess watchdog
// (runBoundedStartup) and the remote-HTTP-bridge startup steps (httpBridgeStartCtx), so
// stdio and HTTP hosts reach the same start success/failure for a given upstream.
func (p *StdioProxy) startupBudget() time.Duration {
	if p.startupTimeout > 0 {
		return p.startupTimeout
	}
	return sessionStartTimeout
}

// httpBridgeStartCtx bounds a remote-HTTP-bridge startup step (the initialize handshake,
// the tools/list drift probe) by the session-start budget, and returns ctx unchanged on
// the subprocess path (whose bound is runBoundedStartup's child-kill watchdog instead). The
// budget is deliberately independent of --upstream-timeout in both directions. Caller must
// invoke the returned cancel.
func (p *StdioProxy) httpBridgeStartCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	if p.upHTTP == nil {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, p.startupBudget())
}

// initUpstream opens the upstream leg at the revision this proxy speaks (p.upstreamRev): the
// MCP initialize handshake, or `server/discover` on a declaring leg. ctx bounds the
// synchronous notifications/initialized delivery on the remote-HTTP bridge path.
func (p *StdioProxy) initUpstream(ctx context.Context) error {
	// Bound the whole remote-HTTP-bridge handshake by the session-start budget (a no-op on
	// the subprocess path): runBoundedStartup does not wrap the HTTP path with a deadline,
	// so without this a hung upstream plus a disabled --upstream-timeout would wedge startup
	// indefinitely.
	ctx, cancel := p.httpBridgeStartCtx(ctx)
	defer cancel()

	p.idCounter++
	initReq, initID, err := buildUpstreamOpener(p.upstreamRev, p.idCounter)
	if err != nil {
		return err
	}
	// POST via the context-aware path and read via readProbeReply so the handshake honors
	// ctx.Done(): the bridge's plain Read selects only on incoming/done, and a POST can be
	// dropped on an already-canceled ctx, so a signal during a slow handshake would otherwise
	// wedge Start until SIGKILL. The subprocess path's blocking pipe Write/Read is instead
	// bounded by runBoundedStartup's child-kill watchdog.
	if p.upHTTP != nil {
		p.upHTTP.postWithCtx(ctx, initReq)
	} else if err := p.upWriter.Write(initReq); err != nil {
		return fmt.Errorf("sending %s: %w", initReq.Method, err)
	}

	// Read messages until the initialize response arrives, discarding any
	// notifications that precede it. Each discard is logged so a stuck init (upstream
	// chattering notifications but never answering) is observable.
	resp, err := awaitStartupReply(
		func() (mcp.RPCMsg, error) { return p.readProbeReply(ctx) },
		initID,
		p.upWriter,
		func(msg mcp.RPCMsg) {
			_, _ = fmt.Fprintf(p.errOut(),
				"[eunox] debug: discarding upstream message while opening the upstream leg with %q (method=%q).\n",
				initReq.Method, msg.Method)
		},
	)
	if err != nil {
		return fmt.Errorf("reading %s response: %w", initReq.Method, err)
	}
	hs, err := ApplyUpstreamOpenerResult(p.upstreamRev, resp)
	if err != nil {
		return err
	}
	reportUpstreamOpenNotice(p.errOut(), hs)
	p.upstreamCaps, p.upstreamServerVersion, p.upstreamInstructions = hs.Capabilities, hs.ServerVersion, hs.Instructions

	// Close the handshake, on the one revision that has one to close.
	notif, wanted := UpstreamOpenerCompletion(p.upstreamRev)
	if !wanted {
		return nil
	}
	// For the remote-HTTP bridge, Write is fire-and-forget, so the host's first request
	// could race notifications/initialized and trip strict upstreams; deliver it
	// synchronously instead. The subprocess path's Write is already synchronous.
	if p.upHTTP != nil {
		return p.upHTTP.writeSync(ctx, notif)
	}
	return p.upWriter.Write(notif)
}

// maxConcurrentHostRequests bounds the in-flight host-request handler goroutines serveHost
// spawns. Each handler can block on the upstream round-trip unboundedly under
// --upstream-timeout=0, so an uncapped goroutine-per-request lets a pipelining host exhaust
// memory and FDs; on saturation serveHost rejects with a structured error instead of
// spawning. The remote-HTTP bridge caps its own POSTs separately (maxInflightPosts).
const maxConcurrentHostRequests = 256

// jsonRPCCodeServerBusy is returned to the host when serveHost's in-flight cap is
// saturated — and to the UPSTREAM when the server-initiated cap above is. -32000 is the
// JSON-RPC implementation-defined server-error range; it signals a transient, retryable
// overload, distinct from a policy denial.
const jsonRPCCodeServerBusy = -32000

// jsonRPCCodeParseError is the JSON-RPC 2.0 code for a message that could not be
// parsed. Returned (with a null id, per the spec) for a malformed host line so one
// bad frame is answered and skipped rather than tearing down the whole session.
const jsonRPCCodeParseError = -32700

// fwdReleaseKey keys the host-forward ordering-barrier release function carried on a
// host request's context (see serveHost / fwdHostWrites). An empty struct keeps the
// key unexported and collision-free.
type fwdReleaseKey struct{}

// releaseHostForward invokes the ordering-barrier release stashed on ctx by
// serveHost, marking that this host request has reached the upstream wire so a host
// notification waiting on the barrier may proceed. A no-op when ctx carries no
// release — every caller of callUpstream that is not a host-request forward (the
// release is set only in serveHost's request branch).
func releaseHostForward(ctx context.Context) {
	if release, ok := ctx.Value(fwdReleaseKey{}).(func()); ok {
		release()
	}
}

// waitHostForwardOrShutdown blocks until the host-forward ordering barrier (fwdHostWrites)
// drains — every host request received before the current notification has reached the
// upstream — or the session is shutting down. True means the barrier drained and the caller
// forwards in wire order; false means stop. The wait must stay interruptible: a request's
// upstream write can wedge under --upstream-timeout=0, and a blocking WaitGroup.Wait there
// would pin the serve loop past a signal.
//
// Interruptibility here also bounds a former sampling + write-wedge deadlock: a handler
// wedged in a raw upstream write (holding both a fwdHostWrites slot and the MsgWriter mutex,
// e.g. against a sampling-capable upstream that stopped draining stdin) used to park the
// serve loop on this barrier forever, with the sampling reply that would unblock the
// upstream stuck behind it. That is now resolved at the write itself (NewMsgWriterWithTimeout
// poisons and tears the upstream down on a wedged write), so this wait is the residual
// "recoverable by shutdown" backstop for the --upstream-timeout=0 opt-out.
func (p *StdioProxy) waitHostForwardOrShutdown(ctx context.Context) bool {
	// Fast path: skip the waiter goroutine when nothing is in flight (the common case for a
	// notification-heavy host). Only serveHost increments the counter and it is the sole
	// caller here, so a zero read here cannot race with a concurrent Add.
	if p.fwdHostInFlight.Load() == 0 {
		return true
	}
	drained := make(chan struct{})
	// On a shutdown wake this returns while the goroutine is still blocked in Wait(), ending
	// only once the barrier eventually drains — safe because the sole caller stops serving on
	// a false return (never issues another Add while this waiter is registered) and the
	// process exits on shutdown, so the leaked goroutine dies with it.
	go func() { p.fwdHostWrites.Wait(); close(drained) }()
	select {
	case <-drained:
		return true
	case <-ctx.Done():
		return false
	case <-p.upstreamDone:
		return false
	}
}

// serveHost reads from host stdin and dispatches messages until stdin closes (EOF),
// the session context is cancelled (a received SIGINT/SIGTERM cancels it in
// main.go), or the upstream exits. The blocking stdin read runs in its own
// goroutine so the serve loop can also wake on cancellation or upstream exit:
// os.Stdin is the host's pipe and is not closed by ctx cancellation, so a bare
// in-loop Read would block forever after a signal killed the upstream, leaving the
// proxy alive and effectively ignoring the signal.
func (p *StdioProxy) serveHost(ctx context.Context) {
	// Size the concurrency cap lazily on serve entry: this is the ONLY place hostSem is
	// initialized (NewStdioProxy does not), so it must run before any handler goroutine
	// is dispatched. serveHost is the sole writer and runs first, so this cannot race.
	if p.hostSem == nil {
		p.hostSem = make(chan struct{}, maxConcurrentHostRequests)
	}

	var wg sync.WaitGroup

	// Run the blocking host read off the serve loop so the loop can also select on
	// ctx.Done()/upstreamDone. A reader parked inside the os.Stdin syscall (not
	// context-cancelable) is reclaimed only when the process exits — the one leak the binary
	// accepts, since its sole caller is a one-shot leaf. The hand-off select mirrors the
	// serve loop's arms, including upstreamDone, so a reader finishing just as the loop
	// exits via upstreamDone does not block the hand-off until ctx cancels.
	type hostRead struct {
		msg mcp.RPCMsg
		err error
	}
	reads := make(chan hostRead)
	go func() {
		for {
			msg, err := p.hostReader.Read()
			select {
			case reads <- hostRead{msg: msg, err: err}:
			case <-ctx.Done():
				return
			case <-p.upstreamDone:
				return
			}
			// A malformed line (mcp.ErrParse) framed correctly, so keep reading — the
			// serve loop answers -32700 and continues. Any other error (EOF, a scanner
			// error such as bufio.ErrTooLong, or I/O) loses framing and is terminal.
			if err != nil && !errors.Is(err, mcp.ErrParse) {
				return
			}
		}
	}()

	for {
		var r hostRead
		select {
		case r = <-reads:
		case <-ctx.Done():
			// Stop serving immediately; do NOT wait for in-flight handlers here — that
			// would re-couple shutdown latency to a stuck upstream. Each handler unblocks
			// on the shared ctx, or on Start's teardown kill if wedged in a raw write.
			return
		case <-p.upstreamDone:
			// Upstream exited on its own: further requests would just fail, so stop and let
			// Start tear down; handlers already observe upstreamDone and return.
			return
		}
		if r.err != nil {
			// A malformed line is recoverable: framing is intact, so answer -32700 and keep
			// serving. Any other error (EOF, bufio.ErrTooLong, I/O) loses framing and ends
			// the session.
			if errors.Is(r.err, mcp.ErrParse) {
				// Explicit "null" id, per the JSON-RPC 2.0 spec: RPCMsg.ID is
				// `json:"id,omitempty"`, so a nil id would drop the member entirely.
				_ = p.hostWriter.Write(mcp.ErrorResponse(mcp.RawJSON("null"), jsonRPCCodeParseError, "Parse error"))
				continue
			}
			// EOF is the ordinary host-closed-stdin case and stays silent; anything else is
			// a session that died mid-stream for a reason otherwise invisible to the operator.
			if !errors.Is(r.err, io.EOF) {
				_, _ = fmt.Fprintf(p.errOut(), "[eunox] host read error: %v; ending session\n", r.err)
			}
			break // host stdin closed (EOF) or an unrecoverable read error
		}
		msg := r.msg

		// Negotiate first — the head of the shared gate order (dispatch.go) — and route the
		// rest of this iteration on the context it returns: every table below (notification
		// disposition, enforced/local for a request) is revision-scoped, so resolving after
		// the lookup would route by one revision's table and record under another's.
		ctx, ok := p.negotiateHostRevision(ctx, msg)
		if !ok {
			continue
		}

		if msg.IsNotification() {
			// forwardHostNotification returns true only when a shutdown woke the
			// wire-ordering barrier, matching the ctx.Done/upstreamDone cases above.
			if p.forwardHostNotification(ctx, msg) {
				return
			}
			continue
		}
		if msg.IsRequest() {
			// Acquire is non-blocking: the read loop must keep routing host replies to
			// server-initiated requests (the IsResponse branch below), so it must never stall
			// on a saturated pool.
			select {
			case p.hostSem <- struct{}{}:
				// A free slot means any saturation episode is over; re-arm the gate so the
				// next refusal is recorded as a new episode rather than folded into the last.
				p.hostSaturation.clear()
			default:
				// Record the refusal so a host saturating the handler pool leaves a trace on
				// the tamper-evident tape rather than only a server-busy reply.
				recordResourceExhausted(ctx, p.rec(), &p.hostSaturation, p.sessionID, msg.Method)
				_ = p.hostWriter.Write(mcp.ErrorResponse(msg.ID, jsonRPCCodeServerBusy, "eunox: too many concurrent requests in flight; retry"))
				continue
			}
			// Reserve the decision ticket HERE, in the single-threaded read loop, so it
			// reflects proxy-RECEIPT order — the handler goroutines then run their decisions
			// in that order regardless of scheduling. Only enforced methods take one, and
			// only after the hostSem acquire above, so a server-busy rejection never strands
			// an un-begun ticket that would stall every later one.
			serialized := p.decideGate != nil && isEnforcedMethod(ctx, msg.Method)
			var ticket decisionTicket
			if serialized {
				ticket = p.takeDecisionTicket()
			}
			// One goroutine per request: the read loop must not block, since it is also the
			// only path routing host replies to server-initiated requests back to the
			// upstream — blocking here would deadlock a sampling/roots-capable upstream. The
			// ordering barrier releases when the request reaches the upstream or, for a
			// denied/errored request that never does, when the handler returns.
			p.fwdHostWrites.Add(1)
			p.fwdHostInFlight.Add(1)
			release := sync.OnceFunc(func() {
				p.fwdHostInFlight.Add(-1)
				p.fwdHostWrites.Done()
			})
			wg.Add(1)
			p.hostHandlers.Add(1)
			go func(m mcp.RPCMsg, serialized bool, ticket decisionTicket) {
				defer wg.Done()
				defer p.hostHandlers.Add(-1)
				defer func() { <-p.hostSem }()
				defer release()
				hctx := context.WithValue(ctx, fwdReleaseKey{}, release)
				// Wait this ticket's turn before the decision runs and advance it afterward.
				// The Decide* handler releases early via finishDecision (before the upstream
				// forward); this defer is the idempotent backstop for the malformed-params
				// path, which returns before the decision.
				if serialized {
					end := p.decideGate.begin(ticket)
					defer end()
					hctx = withDecisionEnd(hctx, end)
				}
				p.handleHostRequest(hctx, m)
			}(msg, serialized, ticket)
			continue
		}
		if msg.IsResponse() {
			// A response from the host to a server-initiated request the proxy
			// forwarded (e.g. the LLM result for sampling/createMessage). Route it back
			// to the waiting upstream; an untracked ID is ignored.
			//
			// Written VERBATIM, `_meta` included — which is why negotiation above has to reach
			// this framing (paramsReachUpstream): these bytes are the one class that travels to
			// the upstream with no dispatch decision behind it.
			if _, held := p.serverReqs.take(mcp.MsgKey(msg.ID)); held {
				// A kill landing after the request was forwarded but before the host's reply
				// arrives must not deliver that reply to a killed session's upstream; a kill
				// does not tear the upstream down, so the blocked request is simply left
				// unanswered and reclaimed on teardown.
				if deny := p.pdp.CheckKill(ctx, p.sessionID); deny != nil {
					recordKillDrop(ctx, p.rec(), deny, verifiedSession(p.sessionID), msg, legStdioServerResponse)
				} else {
					// Through the shared seam, like its HTTP twin: this is the fifth site of the
					// take-then-write sequence, and leaving it bare is how the two transports came
					// to disagree about the identical no-upstream-writer case.
					//
					// The take above is what made this reply unroutable by any later path, so a
					// failed relay DESTROYS a reply the host actually produced — recorded by the
					// seam itself, since every sibling disposition there appends one and this is
					// the one an operator is least likely to guess at.
					p.unblocker().relay(ctx, msg)
				}
			}
			continue
		}
		// Ignore malformed messages.
	}
	// Host stdin closed (EOF). Wait for in-flight handlers before returning; the upstream
	// input stays open here so a request pipelined just before stdin closed can still be
	// forwarded and answered. Unbounded only under --upstream-timeout=0 with an upstream
	// that never responds; the default timeout cancels a stuck handler.
	wg.Wait()
}

// forwardHostNotification forwards one host->upstream notification: the shared
// hostNotificationGate first (swallowed set, revocation, fail-closed routing — see the gate
// order in dispatch.go), then this transport's own wire-ordering barrier and the
// notifications/cancelled id translation. Returns stop=true ONLY when a shutdown woke the
// ordering barrier, signalling serveHost to return immediately.
//
// An id-less "initialize" is swallowed by the gate: IsNotification()'s classification is
// purely structural, so a client can send "initialize" with no id and have it classified as a
// notification — forwarding that verbatim would re-trigger the upstream's handshake outside
// dispatchRequest's kill gate and audit trail.
//
// The wire-ordering barrier waits for every request the host sent before this notification to
// reach the upstream first, so on a subprocess upstream a notifications/cancelled cannot be
// delivered ahead of the tools/call it cancels; on a remote HTTP upstream cancellation is
// best-effort, as on the gateway. It releases on the upstream WRITE, not the response, so
// cancelling a slow in-flight call does not block it. On a shutdown wake it returns stop=true
// rather than looping: a leaked waiter is still registered on fwdHostWrites, so reading
// further requests would be Add-concurrent-with-Wait, a WaitGroup misuse that panics.
func (p *StdioProxy) forwardHostNotification(ctx context.Context, msg mcp.RPCMsg) (stop bool) {
	gate := hostNotificationGate{
		// This transport meters neither the kill record (an established session's, deliberately
		// unbounded) nor the two declared-exempt refusals, so this leg carries no record bucket at
		// all. The notice bucket is supplied all the same: metering no RECORD here is an argument
		// about verdicts, and the routing refusal's stderr line is not one.
		recorders:   refusalLimits{notices: p.noticeWriter()}.recorders(p.rec()),
		subject:     verifiedSession(p.sessionID),
		established: true,
		audit:       p.audit,
		strictAudit: p.strictAudit(),
		checkKill:   func() *capability.EnforceResponse { return p.pdp.CheckKill(ctx, p.sessionID) },
		leg:         legStdioNotification,
	}
	if gate.admit(ctx, msg) != notificationForward {
		return false
	}
	if !p.waitHostForwardOrShutdown(ctx) {
		return true
	}
	// Revocation, AGAIN, after the barrier. The gate order's justification for letting the
	// notification framing take its kill check in the prologue is that this framing "waits for
	// nothing" — true on the gateway, false here: the wire-ordering barrier below parks this
	// notification behind every request the host already sent, and that wait is unbounded under
	// --upstream-timeout=0. A kill landing inside it was never re-observed, so host-controlled
	// bytes reached a revoked session's upstream with no KILL_SWITCH record — a one-message
	// window, and the same "take it FRESH past the wait" rule the REQUEST framing already
	// follows for exactly this reason. Recorded through the gate's own producer so the two
	// observations are one record shape.
	if kill := gate.checkKill(); kill != nil {
		recordKillDrop(ctx, gate.recorders.forCategory(catKill), kill, gate.subject, msg, gate.leg)
		return false
	}
	// Translate a cancel's params.requestId from the host id to the nonce the upstream
	// saw; drop it if the target request is no longer in flight. Others forward verbatim.
	if msg.Method == methodNotificationsCancelled {
		rewritten, ok := rewriteCancelToNonce(&p.pendingMu, p.hostToUp, msg)
		if !ok {
			return false
		}
		msg = rewritten
	}
	// The boundary applies to notifications too, and they do not reach it through the upstream
	// call — this write IS the leg's outbound seam for them. See translateNotificationForLeg.
	outbound, err := translateNotificationForLeg(msg, requestRevision(ctx), p.upstreamRev)
	if err != nil {
		// A drop with no diagnostic: the peer cannot be answered (JSON-RPC forbids it) and the
		// fault is this build's translation layer rather than the message, so an operator's only
		// evidence would otherwise be a notification that never arrived.
		if line, ok := p.noticeWriter().admitNotice(siteNotifyUntranslatable); ok {
			line.writef("[eunox] notification %q could not be translated for the upstream leg, dropped: %v\n",
				audit.BoundEnvelopeField(msg.Method), err)
		}
		return false
	}
	// The same obligation HTTP's two arms carry, on the same declared site: once a write timeout
	// has poisoned the writer, or the child has closed stdin, every forward is dropped -- a
	// notifications/cancelled aborting an in-flight call included -- and this leg is the last
	// place that can say so.
	if err := p.upWriter.Write(outbound); err != nil {
		if line, ok := p.noticeWriter().admitNotice(siteUpstreamNotifyFailed); ok {
			line.writef("[eunox] notification %q write to upstream failed: %v\n",
				audit.BoundEnvelopeField(outbound.Method), err)
		}
	}
	return false
}

// handleHostRequest processes a single request from the host. Every enforced
// method — including initialize — routes through the transport-shared
// dispatchRequest so the method->handler mapping, the fail-closed default, and the
// cross-cutting kill gate cannot drift from the HTTP transport. initialize's local
// response is supplied by p.buildInitResponse (wired into dispatchParams).
func (p *StdioProxy) handleHostRequest(ctx context.Context, msg mcp.RPCMsg) {
	d := p.dispatchParams()
	// nil unless the serve loop threaded a decision-lock release for a serialized enforced
	// request; the Decide* handlers call it right after the decision so the upstream forward
	// runs outside the lock.
	d.endDecision = decisionEndFromContext(ctx)
	resp := dispatchRequest(ctx, d, msg)
	// The dispatcher returns the ZERO message for one with no reply channel, and RPCMsg.JSONRPC
	// has no omitempty — so an unconditional write puts the malformed frame `{"jsonrpc":""}` on the
	// wire to the host where nothing should have been sent. Unreachable while serveHost gates on
	// IsRequest; the guard is what keeps that from being the only reason.
	if resp.IsZero() {
		return
	}
	_ = p.hostWriter.Write(resp)
}

// strictAudit builds the --require-audit=strict configuration from the proxy's own
// fields, shared by the two stdio call sites so a new strictAuditState field cannot be
// silently dropped from one path (see the HTTPProxy counterpart).
func (p *StdioProxy) strictAudit() strictAuditState {
	return strictAuditState{
		requireAuditStrict: p.requireAuditStrict,
		strictAuditWarned:  &p.strictAuditWarned,
	}
}

// dispatchParams bundles the proxy's policy/audit/upstream wiring for the shared request
// dispatcher. stdio carries no per-request client address, so sourceIP is empty. The
// request's revision is NOT among them — it rides the context; see requestRevision.
func (p *StdioProxy) dispatchParams() dispatchParams {
	return dispatchParams{
		forwardParams: forwardParams{
			rec:              p.rec(),
			audit:            p.audit,
			sessionID:        p.sessionID,
			upstreamTimeMs:   p.upstreamTimeMs,
			callUpstream:     withResultShape(p.audit, withCrossRevisionTranslation(p.upstreamRev, p.callUpstream)),
			strictAuditState: p.strictAudit(),
			limits:           p.refusalLimits(),
		},
		pdp:              p.pdp,
		sourceIP:         "", // stdio has no per-request client address
		buildInit:        p.buildInitResponse,
		receipts:         p.receipts,
		honorAttribution: p.honorAttribution,
	}
}

// refusalLimits is this transport's admission control over the writes a refusal makes: the record
// buckets for the categories stdioRefusalCategories declares, and the stderr-notice bucket.
func (p *StdioProxy) refusalLimits() refusalLimits {
	return refusalLimits{records: p.refusalLimiter, notices: p.noticeWriter()}
}

// noticeWriter is this transport's diagnostic channel: the configured stderr writer and the class
// table that bounds it, as one value — so a leg cannot carry the writer without the bound.
func (p *StdioProxy) noticeWriter() noticeWriter {
	return noticeWriter{out: p.errOut(), limits: p.notices}
}

// negotiateHostRevision resolves one host message's revision and pins the context from its
// first resolved message that the resolved revision actually DISPATCHES, so every later message
// is checked against it — which is what makes the mid-context-flip refusal reachable for a
// peer that never sends initialize.
//
// The "dispatches it" half is what keeps that pin from being a wedge. A message the resolved
// revision's tables have no handler for is about to be dropped by the fail-closed routing
// default, so it is not evidence about which revision this conversation is on — and latching
// from one ends the connection: a single id-less `initialize` declaring the revision that
// REMOVED `initialize` pinned that revision, and the host's real handshake was then denied
// under a table with no `initialize` in it, with a re-declaration refused as a mid-context flip
// and an omission inheriting the pin. There is no way back; the peer's only recourse is a new
// process.
//
// The predicate is dispatchesMessage; its doc holds the reasoning. Pinning HERE rather than
// after dispatch resolves a handler — which would make the property structural — keeps hostRev
// single-writer: serveHost dispatches each request on its own goroutine, and this call runs on
// the reader.
//
// It returns the STAMPED context rather than the bare revision: that context is the one
// carrier of the decided revision (the tables route by it, the tape records it), so a caller
// cannot route a message without also giving its records the revision they were routed by.
// This is the first gate every host message passes; see the gate order in dispatch.go.
//
// ok=false means the message was refused: the record is written either way, and a REQUEST
// also gets its -32022 reply (JSON-RPC forbids replying to a notification). Called only from
// serveHost, the single goroutine that owns the pin.
//
// The negotiation itself, its record, and the debt a refused host RESPONSE owes its blocked
// initiator are hostMessageGate's — shared with the HTTP prologue, so this transport holds only
// what is genuinely its own: the pin, the stamp, and what a stream peer is sent when JSON-RPC
// forbids a reply. That last one is why the gate hands the refusal BACK rather than writing it;
// see negotiate.
func (p *StdioProxy) negotiateHostRevision(ctx context.Context, msg mcp.RPCMsg) (context.Context, bool) {
	pinned := p.hostRevision()
	rev, refusal, ok := hostMessageGate{
		leg: hostLeg{contextRev: pinned, upstreamRev: p.upstreamRev, sessionID: p.sessionID},
		// This proxy IS the peer: both hooks the refusal path needs are methods on it, so the
		// prologue's wiring costs an admitted message nothing at all.
		peer: p,
	}.negotiate(ctx, msg)
	if !ok {
		// A zero response is one JSON-RPC forbids replying to, and this transport's peer reads a
		// stream: there is nothing to send in its place, so silence IS the disposition.
		if !refusal.IsZero() {
			_ = p.hostWriter.Write(refusal)
		}
		return ctx, false
	}
	// Guarded on the pin being UNSET. It is write-once by construction — resolveHostRevision
	// above returns early unless rev equals the pinned value — so re-answering the predicate and
	// re-Storing costs a runtime.convTstring boxing per host message for no effect.
	if pinned == "" && dispatchesMessage(rev, msg) {
		p.hostRev.Store(rev)
	}
	return capability.WithProtocolRevision(ctx, rev), true
}

// unblocker is this proxy's wiring for every site that answers a blocked server-initiated
// initiator. The sink is nil only before connectUpstream has run, which is the case the seam's
// nil-writer disposition tests for — resolved through initiatorWriter at ANSWER time, since
// upWriter is an INTERFACE here and a bare `!= nil` on one is the typed-nil trap the seam exists to
// close. Building the unblocker itself allocates nothing, which is what makes it free for the
// holders that only ever want the tracker.
func (p *StdioProxy) unblocker() serverRequestUnblocker {
	// See httpSession.unblocker: one resolution feeds both fields.
	recs := p.refusalRecorders()
	return serverRequestUnblocker{
		reqs:    &p.serverReqs,
		sink:    p.upWriter,
		notices: recs.notices(),
		report: dropReport{
			recs: recs,
			subj: verifiedSession(p.sessionID),
			legs: stdioServerRequestLegs,
		},
	}
}

// unblockRefusedServerReply answers the upstream request a revision-refused host reply would have
// completed, so it does not stay blocked until the host disconnects — this transport has no idle
// reaper to reclaim it. See server_request_unblock.go for the leg's rule and its two exceptions.
func (p *StdioProxy) unblockRefusedServerReply(ctx context.Context, msg mcp.RPCMsg) {
	if !msg.IsResponse() {
		return
	}
	p.unblocker().unblock(ctx, msg.ID, refusedReplyUpstreamError)
}

// revisionRefusalRecorder returns the recorder the -32022 refusal writes through, or nil when
// the catRevision bucket suppressed this one — refuseHostRevision writes nothing for a nil
// recorder, so the peer is refused either way and only the tape write is bounded.
//
// Bounded here at all because this transport has no bucket of its own otherwise; why THIS
// refusal and not the routing one is argued once, on catRevision. Through the same resolver every
// other refusal takes, so a category's declaration is what decides here too — the one fact local to
// stdio is that both the recorder and the limiter are nil in a bare-struct-literal proxy, which
// records unbounded rather than not at all.
func (p *StdioProxy) revisionRefusalRecorder() auditRecorder {
	return p.refusalRecorders().forCategory(catRevision)
}

// hostRevision returns the revision this connection's context resolved, or "" before a message
// this proxy could act on has been negotiated — a connection whose traffic so far is messages
// its declared revision dispatches nowhere stays unpinned, which is the point. See
// StdioProxy.hostRev for the single-writer rule.
func (p *StdioProxy) hostRevision() capability.Revision {
	rev, _ := p.hostRev.Load().(capability.Revision)
	return rev
}

// buildInitResponse builds the host-facing initialize response from the upstream
// capabilities gathered during proxy startup. It is the per-transport responder
// dispatchInitialize calls after the shared kill gate passes; the caller writes the
// returned message to the host.
func (p *StdioProxy) buildInitResponse(msg mcp.RPCMsg) mcp.RPCMsg {
	resp := buildInitializeResponse(msg.ID, initializeCapabilitiesFor(p.upstreamCaps, p.upstreamRev), p.upstreamInstructions)
	// The context pin is serveHost's, not this handler's — see StdioProxy.hostRev. Reaching
	// this method at all means the request resolved to the revision that defines initialize.
	// Bounded: a host may re-initialize as often as it likes and this answer is LOCAL — no session
	// created, no upstream contacted — so an unbounded line here is one write syscall per frame at
	// the host's send rate, the same shape the routing refusal's notice was bounded for.
	if line, ok := p.noticeWriter().admitNotice(siteHostInitialized); ok {
		line.writef(
			"[eunox] Session %s: host initialized (protocol %s).\n",
			p.sessionID, handshakeRevision,
		)
	}
	return resp
}

// forwardServerRequestToHost tracks msg's ID and forwards the server-initiated request to the
// host, reporting what it did with it. The host's response (same ID) is later routed back to the
// upstream by serveHost, and a request this one displaces from the bounded tracker is answered and
// recorded rather than left to hang — see trackServerRequest. A request whose id the tracker will
// not retain does not reach here on the shipped path: admitServerRequestID refuses it at this
// leg's entry.
//
// It is serverRequestParams.forward itself rather than a body a closure answers over: a caller that
// reported "delivered" across the refusing branch below put a contradicting ALLOW on the signed
// tape beside that branch's own refusal record.
func (p *StdioProxy) forwardServerRequestToHost(ctx context.Context, msg mcp.RPCMsg) forwardOutcome {
	u := p.unblocker()
	// The tracker refuses an id it will not retain, and that refusal must not degrade into a
	// SILENT untracked forward: the host would answer, the routing arm would drop the answer as
	// untracked, and the upstream would block with nothing on the tape. Asked here rather than
	// inferred from track's return, which cannot distinguish "displaced nothing" from "tracked
	// nothing". Normally the leg's entry gate has already refused it and this admits for free.
	if !admitAndTrackServerRequest(ctx, u, msg) {
		return forwardRefused
	}
	// The write's error is REPORTED, not discarded. Two of its failures are neither fire-and-forget
	// nor covered by the poison teardown, and both return having written nothing: a writer already
	// poisoned by an earlier frame refuses this one for as long as that teardown takes, and a
	// whole-frame failure (ENOSPC on a redirected stdout, EIO on a detached tty) never poisons at
	// all, since NewMsgWriter(os.Stdout) arms no deadline and only a PARTIAL write latches. Reported
	// delivered, each wrote an allow claiming the host had a request that never left the process.
	if err := p.hostWriter.Write(msg); err != nil {
		// The initiator is answered on the upstream's own sink, which a broken stdout says nothing
		// about — the leg's rule, and what HTTP's counterpart already does when no stream takes it.
		u.unblock(ctx, msg.ID, "host stream unavailable: "+err.Error())
		return forwardUndelivered
	}
	return forwardDelivered
}

// refusalRecorders is this proxy's wiring for a refusal record's recorder. stdio meters only the
// categories stdioRefusalCategories declares; forCategory reads each category's own declaration, so
// the ones this leg does not charge cost nothing to name.
func (p *StdioProxy) refusalRecorders() refusalRecorders {
	return p.refusalLimits().recorders(p.rec())
}

// dispatchUpstreamRequest hands one server-initiated request to the proxy's serverRequestPool,
// which runs its handler on its own goroutine or refuses it when saturated. See
// serverRequestPool for why the handler must not run inline on the read loop, and for the
// ordering guarantee this path gives up. The two writers it reaches are both safe to share:
// mcp.MsgWriter serializes whole frames under its own mutex, and the upstream sink is
// documented concurrency-safe. Host-initiated traffic's ordering guarantees (ticket
// reservation, fwdHostWrites) are untouched by this path.
func (p *StdioProxy) dispatchUpstreamRequest(ctx context.Context, msg mcp.RPCMsg) {
	dispatchServerRequest(ctx, &p.serverPool, msg, serverRequestDispatch{
		sessionID: p.sessionID,
		// Through the seam for the reason handleUpstreamRequest's is: the saturation path answers
		// the initiator after recording, and a bare closure over a nil concrete writer panics there
		// rather than reporting. See writeToInitiator.
		unblocker: p.unblocker(),
		handle:    p.handleUpstreamRequest,
		revision:  p.hostRevision(),
	})
}

// handleUpstreamRequest handles one server-initiated JSON-RPC request from the
// upstream subprocess (e.g. sampling/createMessage, roots/list).
// sampling/createMessage is denied by default unless the manifest explicitly
// permits it and the session is not killed; all other server-initiated
// requests are forwarded to the host.
//
// It is called on a per-request goroutine (dispatchUpstreamRequest), never on the read loop.
// Tests call it directly and synchronously. That is this body without the POOL, not without the
// dispatch: dispatchServerRequest also runs the id-admission gate, so a direct call is the one way
// to reach the forward's own refusing branch — which is what makes that branch testable, and why
// what it reports may not rest on the gate having run.
func (p *StdioProxy) handleUpstreamRequest(ctx context.Context, msg mcp.RPCMsg) {
	// No network client on this transport: no source IP to gate sampling on, no JWT identity.
	forwardServerRequest(ctx, msg, serverRequestParams{
		audit:     p.audit,
		sessionID: p.sessionID,
		// The raw PIN, not a resolution of it: forwardServerRequest resolves the empty carrier
		// the one way requestRevision does, so a connection that has resolved a revision but not
		// pinned one (a message the proxy discarded) records the surface it is routed by rather
		// than claiming nothing was ever negotiated. This supplies the fact; that leg stamps it.
		revision: p.hostRevision(),
		forward:  p.forwardServerRequestToHost,
		// Through the seam, not a bare closure over the concrete writer: a nil *mcp.MsgWriter locks
		// its mutex on a nil receiver, so the four denial arms below would panic where the seam
		// reports — after their audit record. See writeToInitiator.
		unblocker:        p.unblocker(),
		decideLock:       p.samplingDecideLock(),
		strictAuditState: p.strictAudit(),
		pdp:              p.pdp,
	})
}

// samplingDecideLock returns the entry into this session's decision serializer for a
// server-initiated (sampling) decision, or nil when not serialize-relevant. It reserves a
// ticket on the SAME decideGate the host path uses, so a sampling flowLabel sink cannot read
// the flow set concurrently with a host source's write. A sampling request has no
// proxy-receipt order, so it simply takes the next ticket: mutual exclusion, not ordering.
//
// The wait is BOUNDED (samplingTurnWait), and the reason is no longer the deadlock this comment
// used to describe: that account — a turn taken INLINE on the upstream reader, the only
// goroutine that delivers responses to waiting host handlers — was true before
// serverRequestPool, which is exactly what that pool was introduced to remove. This leg now runs
// on its own goroutine, so a parked turn stalls no other in-flight call.
//
// What the bound is for now is serverRequestPool's own admission: a parked waiter holds one of
// maxConcurrentServerRequests slots, so an unbounded wait converts a slow turn into a saturated
// pool that refuses every later server-initiated request. samplingTurnWait's PAIR is what makes
// that affordable — perHolder refuses only a waiter whose turn-holder has not handed off for a
// whole window, so a moving queue is not refused, and total keeps "the queue is moving" from
// meaning forever. The bound applies even when sampling is denied, since the turn is taken
// before DecideSampling runs.
//
// A plain FIFO made bounding this unsafe: an abandoned ticket stalled every later ticket behind
// it. beginWithin abandons the ticket properly (the turn skips it), so a give-up costs only
// this one request.
func (p *StdioProxy) samplingDecideLock() func() (end func(), ok bool) {
	if p.decideGate == nil {
		return nil
	}
	return func() (func(), bool) {
		// The SAME queue the host leg takes its tickets from — not a second anchor
		// resolution. A server-initiated request has no host request to derive claims from,
		// so landing on a different queue would defeat the serialization this lock exists for.
		return p.decideGate.beginWithin(p.takeDecisionTicket(), samplingTurnWait)
	}
}

// takeDecisionTicket reserves this proxy's next decision ticket in receipt order, preferring
// the queue pinned at startup and falling back to resolving the anchor through the registry.
//
// The fallback is the always-correct path and the pin is the optimization. It is not a
// formality: a caller that drives serveHost directly without going through Start holds no
// pin, and a nil pin that quietly produced the zero ticket would run every decision on that
// proxy unserialized while every test still passed.
func (p *StdioProxy) takeDecisionTicket() decisionTicket {
	if p.decideQueue != nil {
		return p.decideGate.takeOn(p.decideQueue)
	}
	return p.decideGate.take(p.decisionAnchorKey())
}

// pinDecisionQueue resolves this connection's anchor once and pins its ticket queue for the
// proxy's life. Called from Start once the serve context (and so any claims attached to it)
// is in hand. The anchor is a per-proxy constant because one host connection carries one
// claims set — giving this transport per-request tokens would break that premise, and this
// function is where it would break.
func (p *StdioProxy) pinDecisionQueue() {
	if p.decideGate == nil {
		return
	}
	p.decideQueue, p.dropDecideQueue = p.decideGate.hold(p.decisionAnchorKey())
}

// decisionAnchorKey is the key this proxy serializes its decisions on: the validated task when
// the operator anchors state on the task and this connection presented one, the session
// otherwise. Goes through resolveDecisionAnchor — the same builder the gateway route uses,
// over the same enforcement.ResolveStateAnchor the engine's key builder resolves through — so
// the turn and the state key cannot come to different answers.
func (p *StdioProxy) decisionAnchorKey() string {
	return resolveDecisionAnchor(p.taskAnchored, p.claims, p.sessionID).Key()
}

// withUpstreamTimeout bounds a StdioProxy upstream round-trip (see boundUpstreamCall).
func (p *StdioProxy) withUpstreamTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return boundUpstreamCall(ctx, p.upstreamTimeMs)
}

// upstreamNonceID returns a fresh, process-unique upstream JSON-RPC ID from a
// monotonic counter. The proxy substitutes it for the host's ID on the wire so
// the upstream's echoed response carries a nonce the proxy controls. seq must be
// guarded by the caller's pendingMu.
func upstreamNonceID(seq uint64) (id *json.RawMessage, key string) {
	// json.Marshal, not fmt's %q: the wire id must be valid JSON, and %q's Go-quoting only
	// coincidentally matches for the current fixed-ASCII format. Marshaling a string never errors.
	raw, _ := json.Marshal(fmt.Sprintf("eunox-up-%d", seq))
	id = mcp.RawJSON(string(raw))
	// Key by the canonical MsgKey, not the raw wire bytes: deliverUpstreamResponse looks the
	// channel up under mcp.MsgKey(resp.ID), so a mismatch would drop the response.
	return id, mcp.MsgKey(id)
}

// methodNotificationsCancelled is the JSON-RPC method a host sends to abort an
// in-flight request (params.requestId names the request's id).
const methodNotificationsCancelled = "notifications/cancelled"

// rewriteCancelToNonce translates a host notifications/cancelled's params.requestId to the
// upstream nonce the proxy substituted for the target request on the wire. Every host request
// to a nonce-rewriting upstream has its id replaced (awaitNonced), but a cancel notification
// is forwarded verbatim, so without this its requestId would name an id the upstream never
// saw and the cancel would be a permanent no-op.
//
// Returns the message with params.requestId swapped and true when an in-flight request
// matches; false when the notification is malformed or nothing is in flight. Only the
// nonce-rewriting upstream paths call this; the gateway remote-HTTP path forwards host ids
// unchanged and must NOT rewrite.
func rewriteCancelToNonce(mu *sync.Mutex, hostToUp map[string]*json.RawMessage, msg mcp.RPCMsg) (mcp.RPCMsg, bool) {
	if msg.Method != methodNotificationsCancelled || len(msg.Params) == 0 {
		return msg, false
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(msg.Params, &fields); err != nil {
		return msg, false
	}
	rawID, ok := fields["requestId"]
	if !ok {
		return msg, false
	}
	id := rawID
	hostKey := mcp.MsgKey(&id)
	mu.Lock()
	upID := hostToUp[hostKey]
	mu.Unlock()
	if upID == nil {
		return msg, false // no in-flight request under this id: drop the cancel
	}
	fields["requestId"] = *upID
	newParams, err := json.Marshal(fields)
	if err != nil {
		return msg, false
	}
	msg.Params = newParams
	return msg, true
}

// awaitNonced correlates one request/response round-trip while defending against
// timed-out-response misrouting. hostToUp (keyed by host ID) is the duplicate-ID guard, and
// byUpstreamID (keyed by proxy-generated nonce) is the response router: on timeout the nonce
// entry is removed so a late response lands nowhere rather than leaking into a later request
// that reused the same host ID. rewrite installs the nonce ID; send transmits it.
func awaitNonced(
	ctx context.Context,
	mu *sync.Mutex,
	byUpstreamID map[string]chan upstreamResult,
	hostToUp map[string]*json.RawMessage,
	seq *uint64,
	done <-chan struct{},
	hostKey string,
	rewrite func(id *json.RawMessage),
	send func() error,
) (mcp.RPCMsg, error) {
	ch := make(chan upstreamResult, 1)
	mu.Lock()
	// hostToUp IS the in-flight host-ID set: an entry exists for exactly the window a
	// request is in flight. Must not be nil, or a duplicate host ID would be silently admitted.
	if _, exists := hostToUp[hostKey]; exists {
		mu.Unlock()
		return mcp.RPCMsg{}, fmt.Errorf("%w %q: request already pending", errDuplicateID, hostKey)
	}
	*seq++
	upID, upKey := upstreamNonceID(*seq)
	byUpstreamID[upKey] = ch
	// Record host-id -> nonce so a later notifications/cancelled can translate its
	// params.requestId to the id the upstream actually saw.
	hostToUp[hostKey] = upID
	mu.Unlock()
	defer func() {
		mu.Lock()
		delete(byUpstreamID, upKey)
		delete(hostToUp, hostKey)
		mu.Unlock()
	}()

	rewrite(upID)
	if err := send(); err != nil {
		return mcp.RPCMsg{}, err
	}

	select {
	case result := <-ch:
		// A remote-HTTP-bridge transport failure rides result.err, not the response body:
		// deliverUpstreamError sends it directly on this same channel. dispatch then classifies
		// it and records a deny/UPSTREAM_ERROR instead of an allow. Never set on the subprocess
		// path (no bridge).
		if result.err != nil {
			return mcp.RPCMsg{}, result.err
		}
		resp := result.msg
		// A valid response carries an id, no method, and exactly one of result/error.
		// !IsResponse() refuses a method-bearing reply (a forged/confused upstream message
		// echoing a live nonce) and isMalformedResponse refuses one carrying neither or both,
		// matching correlateUpstreamReply's refusal on the HTTP-upstream bridge.
		if !resp.IsResponse() || isMalformedResponse(resp) {
			return mcp.RPCMsg{}, fmt.Errorf("upstream reply was not a valid JSON-RPC response (method-bearing, or carrying neither result nor error, or both)")
		}
		return resp, nil
	case <-ctx.Done():
		return mcp.RPCMsg{}, ctx.Err()
	case <-done:
		return mcp.RPCMsg{}, errUpstreamExited
	}
}

// callUpstream sends msg to the upstream and waits for the matching response,
// bounded by --upstream-timeout. The outbound message carries a proxy-generated
// nonce; the response is routed back through byUpstreamID (its ID is the
// upstream's echo of the nonce — the shared forward path restores the host ID
// before replying). Returns immediately with an error if the upstream exits first
// (p.upstreamDone closed by readUpstream).
func (p *StdioProxy) callUpstream(ctx context.Context, msg mcp.RPCMsg) (mcp.RPCMsg, error) {
	ctx, cancel := p.withUpstreamTimeout(ctx)
	defer cancel()
	// NewStdioProxy initializes these; this lazy init only fires for a test-assembled proxy,
	// under pendingMu so it cannot race awaitNonced/readUpstream. Both must be non-nil since
	// awaitNonced both writes the correlation and reads the duplicate-ID set from hostToUp.
	p.pendingMu.Lock()
	if p.byUpstreamID == nil {
		p.byUpstreamID = make(map[string]chan upstreamResult)
	}
	if p.hostToUp == nil {
		p.hostToUp = make(map[string]*json.RawMessage)
	}
	p.pendingMu.Unlock()
	return awaitNonced(ctx, &p.pendingMu, p.byUpstreamID, p.hostToUp, &p.upstreamSeq, p.upstreamDone, mcp.MsgKey(msg.ID),
		func(id *json.RawMessage) { msg.ID = id },
		func() error {
			// For HTTP upstreams, use the per-call ctx so --upstream-timeout cancels
			// the in-flight POST; Write (fire-and-forget) uses the bridge-lifetime ctx
			// and would bypass per-call deadlines.
			if p.upHTTP != nil {
				p.upHTTP.postWithCtx(ctx, msg)
				// Release the host-forward ordering barrier now that the request is on its way.
				// On this arm the barrier only orders the proxy's own dispatch, not the wire:
				// each call is an independent POST, so cancellation is best-effort here, as on
				// the gateway. Only the subprocess arm below, writing through one MsgWriter,
				// orders the bytes.
				releaseHostForward(ctx)
				return nil
			}
			err := p.upWriter.Write(msg)
			if err == nil {
				releaseHostForward(ctx)
			}
			// A write timeout has already torn the upstream down via the writer's onPoison
			// hook, so this only returns the error; the handler's deferred release() then
			// drains the barrier and readUpstream's EOF unblocks the serve loop.
			return err
		})
}

// reportUpstreamErr delivers a remote-HTTP-bridge transport failure directly to the in-flight
// call identified by the upstream nonce upKey, so awaitNonced returns it as the call's error,
// and reports whether a live caller was found. A caller no longer registered in byUpstreamID
// (the bridge's POST runs fire-and-forget and may deliver its failure after the caller already
// gave up) is simply a no-op reporting false; the bridge's post() then falls back to its
// synthesized in-band response.
func (p *StdioProxy) reportUpstreamErr(upKey string, err error) bool {
	if err == nil {
		return false
	}
	return deliverUpstreamError(&p.pendingMu, p.byUpstreamID, upKey, err)
}

// readUpstream reads from the upstream and routes each message: responses to the
// waiting caller, notifications to the host, server-initiated requests for
// enforcement.
func (p *StdioProxy) readUpstream(ctx context.Context) {
	for {
		msg, err := p.upReader.Read()
		if err != nil {
			// io.EOF is a normal upstream exit. Any other error (oversized or
			// malformed message) is abnormal; log it so it is diagnosable rather
			// than a silent reader exit — unless this proxy is already forcing the
			// upstream down, where the error is this teardown's own doing.
			if !errors.Is(err, io.EOF) && !p.upstreamTornDown.Load() {
				_, _ = fmt.Fprintf(p.errOut(), "[eunox] upstream read error: %v\n", err)
			}
			return
		}

		if msg.IsNotification() {
			// A killed session must not keep receiving the upstream->host notification relay,
			// stdio's equivalent of the HTTP transport gating its SSE relay on the kill.
			// Recording the drop keeps a killed session's suppressed notifications visible on
			// the tape rather than silently swallowed.
			// Stamped with this connection's pin: the sink OMITS protocol_revision for a
			// context that carries none, which on this tape means "written before a revision
			// could be resolved" — false for a connection that has already negotiated one.
			killCtx := ensureProtocolRevision(ctx, p.hostRevision())
			if deny := p.pdp.CheckKill(killCtx, p.sessionID); deny != nil {
				recordKillDrop(killCtx, p.rec(), deny, verifiedSession(p.sessionID), msg, legStdioUpstreamNotification)
				continue
			}
			_ = p.hostWriter.Write(msg)
			continue
		}

		// A message carrying both an id and a method that echoes a LIVE outstanding upstream
		// nonce is NOT a server-initiated request — it is a forged/confused reply to that
		// in-flight call, and must be routed to the waiting caller (which refuses a
		// method-bearing reply), mirroring correlateUpstreamReply's refusal on the
		// HTTP-upstream bridge. A method-bearing message whose id is not a live nonce is a
		// genuine server-initiated request (e.g. sampling/createMessage, roots/list).
		if msg.IsRequest() {
			p.pendingMu.Lock()
			_, liveNonce := p.byUpstreamID[mcp.MsgKey(msg.ID)]
			p.pendingMu.Unlock()
			if liveNonce {
				deliverUpstreamResponse(&p.pendingMu, p.byUpstreamID, msg)
				continue
			}
			p.dispatchUpstreamRequest(ctx, msg)
			continue
		}

		if msg.IsResponse() {
			// Route by the nonce the upstream echoes, not the host ID, so a late
			// response for a timed-out call (nonce entry already removed) cannot be
			// misrouted into a later request that reused the same host ID.
			deliverUpstreamResponse(&p.pendingMu, p.byUpstreamID, msg)
		}
	}
}
