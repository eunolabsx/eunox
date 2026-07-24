// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Package main — stdio proxy transport.
//
//	MCP host  ──stdin/stdout──►  StdioProxy  ──►  upstream MCP server (subprocess)
//
// Enforced host requests pass through a PDP decision before reaching the
// upstream; everything else (other requests, notifications both directions) is
// forwarded verbatim. One goroutine reads from the host, one from the upstream;
// upstream responses are routed back to the matching pending request.

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
)

const (
	// ProxyName is the clientInfo.name the proxy presents to upstreams; exported
	// so the CLI's live-upstream probe identifies itself identically.
	ProxyName = "eunox-proxy"

	// MCPProtocolVersion is the MCP protocol version the proxy advertises;
	// exported for the CLI's live-upstream probe.
	MCPProtocolVersion = "2025-11-25"
)

// proxyVersion is the version string reported in MCP initialize responses,
// kept in sync with the build version via SetProxyVersion.
var proxyVersion = "dev"

// SetProxyVersion sets the version string the proxy reports in MCP initialize
// responses. main.go's init calls it with the -ldflags build version, keeping
// the dependency one-directional (package main never writes this var directly).
func SetProxyVersion(v string) { proxyVersion = v }

// StdioProxy proxies MCP messages between the host (stdin/stdout) and an
// upstream MCP server subprocess, applying PDP enforcement to tools/call.
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
	// policyVersion and policySHA256 are stamped onto every audit record via rec()
	// (see StdioProxyOptions.PolicyVersion/PolicySHA256).
	policyVersion string
	policySHA256  string
	// recOnce/recCached lazily build and cache rec()'s auditRecorder exactly once,
	// from whatever sink/policyVersion/policySHA256 hold at the first call — every
	// production path sets those three fields once at construction (NewStdioProxy)
	// before any request flows, and test helpers that build a StdioProxy via a bare
	// struct literal set them once immediately after, before exercising any call
	// path that reaches rec(). recCached stays the untyped nil auditRecorder value
	// when sink is nil, so rec() returns a genuine nil (not a non-nil interface
	// wrapping a nil sink) — see rec()'s doc comment.
	recOnce            sync.Once
	recCached          auditRecorder
	sessionID          string
	shutdownMs         int
	upstreamTimeMs     int  // 0 = no timeout
	audit              bool // observe mode: evaluate and log, but forward instead of block
	requireAuditStrict bool // --require-audit=strict: deny forwards once the audit trail degrades
	// strictAuditWarned makes the strict-gate stderr warning one-shot (the gate is
	// sticky, so it would otherwise log per request); the durable per-call signal is
	// the AUDIT_UNAVAILABLE record.
	strictAuditWarned atomic.Bool
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
	// shutdown; Start's teardown stops it once the upstream has exited. Stopping it
	// is harmless after the process is reaped (the callback is a no-op then) but
	// suppresses a spurious "sending SIGKILL" log line and frees the timer promptly.
	// killMu guards it: signalUpstream (signal goroutine) writes, teardown reads.
	killMu    sync.Mutex
	killTimer *time.Timer

	hostReader *mcp.MsgReader
	hostWriter *mcp.MsgWriter

	upWriter mcp.MsgSink // subprocess pipe or HTTP bridge; concurrency-safe

	// pendingMu guards pending, byUpstreamID, hostToUp, and upstreamSeq.
	pendingMu sync.Mutex
	// pending is keyed by the host's JSON-RPC ID and exists solely to reject a
	// duplicate in-flight host ID. It does NOT route upstream responses; that is
	// byUpstreamID's job.
	pending map[string]chan upstreamResult
	// byUpstreamID routes upstream responses (and remote-HTTP-bridge transport
	// failures — see deliverUpstreamError) back to the waiting caller, keyed by the
	// proxy-generated upstream ID (the nonce). A result carrying a stale nonce (its
	// caller already timed out and removed the entry) lands nowhere, so a late
	// response for a timed-out request can never be misrouted into a later request
	// that reused the same host ID.
	byUpstreamID map[string]chan upstreamResult
	// hostToUp maps a live request's host ID (canonical MsgKey) to the upstream
	// nonce the proxy put on the wire, so a host notifications/cancelled can have
	// its params.requestId translated to the nonce the upstream actually saw --
	// otherwise the cancel names an id the upstream never received and is a no-op.
	// Populated and cleared alongside pending/byUpstreamID under pendingMu.
	hostToUp map[string]*json.RawMessage
	// upstreamSeq is the monotonically increasing nonce source for upstream IDs.
	upstreamSeq uint64

	// serverReqs tracks the IDs of server-initiated requests (e.g.
	// sampling/createMessage, roots/list) the proxy forwarded to the host. serveHost
	// consults it to route the host's response (same ID) back to the upstream rather
	// than dropping it, which would hang the upstream.
	serverReqs serverReqTracker

	// upstreamDone is closed by readUpstream when the upstream exits, so pending
	// callUpstream callers return immediately rather than waiting for ctx cancel.
	upstreamDone chan struct{}

	// upstreamCaps holds the server capabilities from the upstream initialize response.
	upstreamCaps map[string]interface{}
	// upstreamServerVersion holds the version string from the upstream serverInfo.
	upstreamServerVersion string
	// upstreamInstructions holds the instructions field from the upstream initialize response.
	upstreamInstructions string

	// idCounter is used for the proxy→upstream initialize request ID.
	idCounter int64

	// hostSem bounds concurrent in-flight host-request handler goroutines (and the
	// pending/byUpstreamID entries each one holds). serveHost acquires a slot
	// non-blockingly before dispatching a request goroutine and releases it when the
	// handler returns; on saturation the request is rejected with a structured error
	// instead of spawning, so a pipelining host — or a silent upstream under
	// --upstream-timeout=0, where handlers never return — cannot grow goroutines or
	// the pending maps without bound. serveHost sizes it lazily on entry (the sole
	// initialization site), before dispatching any handler goroutine, so it is always
	// sized by the time a request is handled.
	hostSem chan struct{}

	// fwdHostWrites preserves host wire order across the request/notification
	// boundary. It counts host requests that have been dispatched but not yet written
	// to the upstream; serveHost waits on it before forwarding a host notification, so
	// a notification (e.g. notifications/cancelled targeting an in-flight request)
	// cannot overtake the requests the host sent before it. callUpstream releases a
	// request's slot the instant the request reaches the wire — not when its response
	// arrives — so cancelling a slow call never deadlocks the barrier.
	fwdHostWrites sync.WaitGroup
	// fwdHostInFlight mirrors fwdHostWrites' counter as a readable atomic so
	// waitHostForwardOrShutdown can take a zero-cost fast path (no waiter goroutine +
	// channel) when the barrier is already drained — the common case for a
	// notification-heavy host. Incremented in serveHost (the sole Add site) alongside
	// fwdHostWrites.Add, decremented in the same OnceFunc release as fwdHostWrites.Done.
	fwdHostInFlight atomic.Int64

	// decideGate serializes this session's enforced-request decisions in proxy-receipt
	// order when the policy is flow- or sequenceBlock-relevant (docs/flow-label-hardening.md
	// piece B); the serve loop gates on decideGate != nil. nil keeps full intra-session
	// decision parallelism. Set from StdioProxyOptions.SerializeDecisions at construction.
	decideGate *decisionSerializer
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
	// PolicyVersion and PolicySHA256 are the merged manifest's provenance
	// (config.LocalManifest.Version and its digest), stamped onto every audit
	// record the same way the gateway's routeSink stamps them for each route —
	// so a stdio-host deployment's audit trail carries the same provenance a
	// gateway route's does, instead of leaving policy_version/policy_sha256 empty.
	PolicyVersion      string
	PolicySHA256       string
	SessionID          string
	ShutdownMs         int
	UpstreamTimeMs     int
	Audit              bool // observe mode: evaluate and log, but forward instead of block
	RequireAuditStrict bool // --require-audit=strict: deny forwards once the audit trail degrades

	// SerializeDecisions serializes this session's enforced-request decisions in
	// proxy-receipt order when the policy is flow- or sequenceBlock-relevant, so a
	// source's flow-label write is ordered before a later sink's read even under a
	// pipelining client (docs/flow-label-hardening.md piece B). The binary sets it from
	// manifest.HasFlowLabel() || manifest.HasSequenceBlock().
	SerializeDecisions bool

	// DriftCheck is the injected drift hook; nil = no drift checking.
	DriftCheck drift.CheckFunc
}

// NewStdioProxy creates a StdioProxy ready to call Start.
func NewStdioProxy(opts StdioProxyOptions) *StdioProxy {
	// Fail closed: a caller that omits a PDP denies every request. Production
	// always wires a concrete PDP; this guards the exported library seam.
	// Wiretap/audit mode opts in explicitly with AlwaysAllowPDP.
	if opts.PDP == nil {
		opts.PDP = pdp.DenyAllPDP{}
	}
	if opts.ShutdownMs <= 0 {
		opts.ShutdownMs = 5000
	}
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
		driftCheck:            opts.DriftCheck,
		pending:               make(map[string]chan upstreamResult),
		byUpstreamID:          make(map[string]chan upstreamResult),
		hostToUp:              make(map[string]*json.RawMessage),
		hostReader:            mcp.NewMsgReader(os.Stdin),
		hostWriter:            mcp.NewMsgWriter(os.Stdout),
	}
	if opts.SerializeDecisions {
		p.decideGate = newDecisionSerializer()
	}
	return p
}

// rec returns the auditRecorder every enforcement/notification path in this file
// records through, wrapping p.sink in a routeSink (upstream "" — single-upstream
// mode, matching Record's own doc comment) so policyVersion/policySHA256 are
// stamped onto every stdio audit record exactly as the gateway's routeSink stamps
// them for each route. Built and cached once (recOnce/recCached): unlike the
// prior asRecorder(p.sink) call at each site, wrapping a non-nil *routeSink in the
// auditRecorder interface every call would (a) allocate on every enforced
// request/notification/kill-drop for no reason, since sink/policyVersion/
// policySHA256 never change after construction, and (b) — the correctness issue —
// always yield a NON-nil auditRecorder even when p.sink is nil (a &routeSink{} is
// never the nil pointer asRecorder's zero-value check looks for), silently
// defeating every "no sink configured" fast path that tests `rec() != nil`
// (e.g. dispatchList's list-decode skip). Returning the untyped nil interface
// directly when p.sink is nil — rather than asRecorder(&routeSink{...}) — fixes
// that: recCached stays nil, so rec() itself is nil, and every existing
// `d.rec != nil` guard behaves exactly as it did when call sites held
// asRecorder(p.sink) directly. routeSink's own RecordAllow/RecordDeny/
// AuditDegraded also no-op on a nil inner sink, so a caller that ignores the nil
// and calls through it anyway (there are none today) stays safe either way.
func (p *StdioProxy) rec() auditRecorder {
	p.recOnce.Do(func() {
		if p.sink != nil {
			p.recCached = &routeSink{sink: p.sink, policyVersion: p.policyVersion, policySHA256: p.policySHA256}
		}
	})
	return p.recCached
}

// Start runs the proxy until the host closes stdin or the upstream exits.
// It returns when the session ends.
func (p *StdioProxy) Start(ctx context.Context) error {
	// ── 1. Connect to upstream (subprocess or remote HTTP) ─────────────────────
	if err := p.connectUpstream(ctx); err != nil {
		return err
	}

	// ── 2-3. Initialize handshake + drift check, bounded by sessionStartTimeout ──
	// Both run blocking upstream pipe reads inline, before readUpstream owns the
	// reader. A subprocess that launches but never answers initialize (or the drift
	// tools/list probe) has no internal read deadline, so without this watchdog Start
	// hangs indefinitely until an operator signals the process — the HTTP path bounds
	// the same work with sessionStartTimeout, and this backports it. The drift check
	// runs before readUpstream so we own upReader exclusively.
	if err := p.runBoundedStartup(ctx, func() error {
		if err := p.initUpstream(ctx); err != nil {
			return fmt.Errorf("upstream initialize: %w", err)
		}
		if p.driftCheck != nil {
			raw, probeErr := p.fetchUpstreamToolsRaw(ctx)
			if err := p.driftCheck(raw, p.upstreamServerVersion, probeErr); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		p.killUpstream() //nolint:contextcheck // teardown path: the upstream session-termination DELETE intentionally uses a detached, bounded background context — close/reaper/signal/shutdown carry no request context.
		// Reap the killed subprocess, mirroring the normal-shutdown step 7 and the HTTP
		// transport's failed-initialize reap: killUpstream only signals, so without Wait
		// the child stays a zombie and os/exec never closes the stdin/stdout pipe FDs (it
		// does so inside Wait). The inline startup fn has returned, so no reader races Wait;
		// waitUpstream is a no-op for a remote HTTP upstream (nil upCmd).
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
	go func() { //nolint:contextcheck // teardown path: the upstream session-termination DELETE intentionally uses a detached, bounded background context — close/reaper/signal/shutdown carry no request context.
		sig, ok := <-sigCh
		if !ok {
			return
		}
		fmt.Fprintf(os.Stderr, "[eunox] Received %s; shutting down upstream.\n", sig)
		p.signalUpstream(sig)
	}()

	fmt.Fprintf(os.Stderr, "[eunox] Session %s initialized; proxying to %q.\n", p.sessionID, p.upstreamLabel())

	// ── 6. Serve host until stdin closes ───────────────────────────────────────
	p.serveHost(ctx)

	// ── 6.5 Release this session's per-session enforcement state ────────────────
	// The host is gone, so free the session's accumulated flow-label set: an ended
	// session must retain no state, and a reused session id starts clean
	// (docs/flow-label-hardening.md FR-H2). Detached, bounded context — teardown must
	// not block on a slow store, and a Redis store reclaims an orphaned key by idle TTL
	// regardless. A no-op when the policy uses no flow control.
	releaseCtx, releaseCancel := context.WithTimeout(context.Background(), time.Duration(p.shutdownMs)*time.Millisecond)
	p.pdp.ReleaseSession(releaseCtx, p.sessionID) //nolint:contextcheck // teardown path: the host is gone; a detached, bounded context is correct here as for the other teardown steps.
	releaseCancel()

	// ── 7. Drain upstream reader ──────────────────────────────────────────────
	signal.Stop(sigCh)
	close(sigCh)
	p.closeUpstreamInput() //nolint:contextcheck // teardown path: the upstream session-termination DELETE intentionally uses a detached, bounded background context — close/reaper/signal/shutdown carry no request context.
	p.awaitUpstreamDrain() //nolint:contextcheck // teardown path: the force-kill's upstream session-termination DELETE intentionally uses a detached, bounded background context — close/reaper/signal/shutdown carry no request context.
	// Upstream has exited: stop the SIGKILL fallback (if armed) so a clean shutdown
	// emits no spurious "sending SIGKILL" line and the timer is freed promptly.
	p.killMu.Lock()
	if p.killTimer != nil {
		p.killTimer.Stop()
	}
	p.killMu.Unlock()
	p.waitUpstream()

	return nil
}

// connectUpstream establishes the upstream connection and wires upWriter/upReader:
// a remote HTTP bridge when upstreamURL is set, otherwise a local subprocess.
func (p *StdioProxy) connectUpstream(ctx context.Context) error {
	if p.upstreamURL != "" {
		up := newHTTPUpstream(ctx, p.upstreamURL, p.upstreamAuthHeader, p.upstreamTLSSkipVerify, p.upstreamTimeMs)
		// A transport-level POST failure is reported back through upErr so the waiting
		// caller records a deny/UPSTREAM_ERROR (matching the gateway) rather than an
		// allow. reportUpstreamErr only stashes while the caller is still registered, so
		// a handshake/probe POST (no byUpstreamID entry) is unaffected and still surfaces
		// its error through the synthesized in-band response.
		up.reportErr = p.reportUpstreamErr
		p.upHTTP = up
		p.upWriter = up
		p.upReader = up
		// Same limitation as the gateway path (see printRemoteUpstreamNotice in
		// route.go): a remote HTTP upstream has no inbound stream, so server-initiated
		// requests it issues are never read or replied to. Surface it so an operator is
		// not left debugging a silent hang.
		printRemoteUpstreamNotice(os.Stderr, p.upstreamURL, "")
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
	p.upCmd.Stderr = os.Stderr

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
	// Bound each host->upstream pipe write by --upstream-timeout so a subprocess that
	// stops draining its stdin (e.g. a sampling-capable upstream awaiting its reply) cannot
	// wedge a write — and, through the MsgWriter mutex + the serve loop's ordering barrier,
	// the whole session — until SIGINT. On a write timeout the writer poisons and invokes the
	// onPoison hook (killUpstream), so ANY wedging write path — request, notification, or the
	// serve loop's server-reply relay — tears the upstream down (readUpstream then EOFs and
	// the serve loop unblocks) rather than only the request path. --upstream-timeout=0 leaves
	// the write unbounded (the operator's opt-out).
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
		return p.upstreamURL
	}
	return p.command
}

// killUpstream forcibly stops the upstream, used when startup (initialize or
// drift) fails.
func (p *StdioProxy) killUpstream() {
	if p.upHTTP != nil {
		p.upHTTP.close()
		return
	}
	if p.upCmd != nil && p.upCmd.Process != nil {
		_ = p.upCmd.Process.Kill()
	}
}

// signalUpstream begins a graceful upstream shutdown in response to sig: a
// subprocess is sent the signal with a SIGKILL fallback after shutdownMs; a
// remote HTTP upstream is closed (canceling in-flight requests).
func (p *StdioProxy) signalUpstream(sig os.Signal) {
	if p.upHTTP != nil {
		p.upHTTP.close()
		return
	}
	if p.upCmd.Process != nil {
		_ = p.upCmd.Process.Signal(sig)
	}
	t := time.AfterFunc(p.killDelay(), func() {
		if p.upCmd.Process != nil {
			fmt.Fprintf(os.Stderr, "[eunox] Upstream did not exit; sending SIGKILL.\n")
			_ = p.upCmd.Process.Kill()
		}
	})
	p.killMu.Lock()
	p.killTimer = t
	p.killMu.Unlock()
}

// awaitUpstreamDrain waits for readUpstream to finish (upstreamDone) after the
// proxy→upstream input has been closed, but bounds the wait: a daemon-style subprocess
// that ignores stdin EOF and holds its stdout open never lets readUpstream error, so a
// plain <-upstreamDone would hang Start forever on a host disconnect — defeating graceful
// shutdown and skipping the deferred audit-sink flush. On the signal path signalUpstream
// already armed a SIGKILL fallback; the host-EOF path has none, so this force-kills the
// upstream after shutdownMs and then waits, mirroring httpSession.close's bounded
// teardown. killUpstream and the drain are idempotent, so the two paths converge safely.
func (p *StdioProxy) awaitUpstreamDrain() {
	select {
	case <-p.upstreamDone:
		return
	case <-time.After(p.killDelay()):
		fmt.Fprintf(os.Stderr, "[eunox] Upstream did not exit after host disconnect; forcing shutdown.\n")
		p.killUpstream()
		<-p.upstreamDone
	}
}

// killDelay is the grace period before a graceful upstream shutdown escalates to a
// force-kill: the configured shutdownMs, or a 5s fallback for a zero-value proxy. Shared
// by the signal path (signalUpstream's SIGKILL timer) and the host-EOF path
// (awaitUpstreamDrain) so both bound a wedged upstream identically.
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

// runBoundedStartup runs the blocking session-start work fn under a
// sessionStartTimeout deadline. fn blocks on upstream pipe reads that carry no
// internal deadline, so on expiry the subprocess is killed (EOF-ing the pipe) to
// unblock the Read, then fn is awaited — mirroring httpSession.initUpstream.
// Without this, a subprocess that launches but never writes the initialize
// response (or never answers the drift tools/list probe) hangs Start until an
// operator signals it. The remote-HTTP bridge already bounds its own reads
// (per-request HTTP timeouts), and a second watchdog could kill a slow-but-valid
// remote, so the watchdog applies only to the subprocess path.
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
		p.killUpstream() //nolint:contextcheck // teardown path: the upstream session-termination DELETE intentionally uses a detached, bounded background context — close/reaper/signal/shutdown carry no request context.
		<-done           // fn observes the pipe EOF the kill produced and returns
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
// the subprocess path (whose overall bound is runBoundedStartup's child-kill watchdog).
// The budget is deliberately independent of --upstream-timeout in BOTH directions: a tight
// value must not fail startup, and a generous one must not widen it. The caller must
// invoke the returned cancel.
func (p *StdioProxy) httpBridgeStartCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	if p.upHTTP == nil {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, p.startupBudget())
}

// initUpstream performs the MCP initialize handshake with the upstream server.
// ctx bounds the synchronous notifications/initialized delivery on the remote-
// HTTP bridge path.
func (p *StdioProxy) initUpstream(ctx context.Context) error {
	// Bound the whole remote-HTTP-bridge handshake by the session-start budget (a no-op on
	// the subprocess path). runBoundedStartup does NOT wrap the HTTP path with a deadline,
	// and postWithCtx passes bound=0, so without this a hung upstream + a disabled
	// --upstream-timeout (no http.Client header timeout) would wedge startup indefinitely.
	// The old upWriter.Write path bounded this at notifyPostTimeout; this restores a bound
	// and matches how the drift probe bounds its own tools/list read.
	ctx, cancel := p.httpBridgeStartCtx(ctx)
	defer cancel()

	p.idCounter++
	initReq, initID := buildInitializeRequest(p.idCounter)
	// On the remote-HTTP bridge, POST the initialize via the context-aware path and read
	// the response via readProbeReply (readCtx) so the handshake honors ctx.Done(). The
	// bridge's plain Read selects only on incoming/done, and spawnPost can drop the POST
	// on an already-canceled ctx (leaving nothing in-flight to feed incoming), so a
	// SIGINT/SIGTERM during a slow handshake — or an expired budget above — would otherwise
	// wedge Start until SIGKILL. The subprocess path keeps the blocking pipe Write/Read,
	// which runBoundedStartup's child-kill watchdog bounds via pipe EOF.
	if p.upHTTP != nil {
		p.upHTTP.postWithCtx(ctx, initReq)
	} else if err := p.upWriter.Write(initReq); err != nil {
		return fmt.Errorf("sending initialize: %w", err)
	}

	// Read messages until the initialize response arrives, discarding any
	// notifications that precede it.
	for {
		msg, err := p.readProbeReply(ctx)
		if err != nil {
			return fmt.Errorf("reading initialize response: %w", err)
		}
		if msg.IsResponse() && mcp.MsgKey(msg.ID) == mcp.MsgKey(initID) {
			caps, sv, instructions, err := applyInitializeResult(msg)
			if err != nil {
				return err
			}
			p.upstreamCaps, p.upstreamServerVersion, p.upstreamInstructions = caps, sv, instructions
			break
		}
		// Anything else during the handshake is discarded; log it so a stuck init
		// (upstream chattering notifications but never answering) is observable.
		fmt.Fprintf(os.Stderr,
			"[eunox] debug: discarding upstream message during initialize handshake (method=%q).\n",
			msg.Method)
		// A discarded server-initiated REQUEST would leave the upstream blocked
		// awaiting a response; reply with a JSON-RPC error so it unblocks.
		RejectPreInitServerRequest(p.upWriter, msg)
	}

	// Send `initialized` notification to upstream.
	notif, err := mcp.NotificationMsg(mcp.MethodNotificationsInitialized, nil)
	if err != nil {
		return err
	}
	// For the remote-HTTP bridge, Write is fire-and-forget, so the host's first
	// request could race notifications/initialized and trip strict upstreams.
	// Deliver it synchronously so the handshake is not reported complete until the
	// notification has been POSTed. The subprocess path's Write is already a
	// synchronous pipe write.
	if p.upHTTP != nil {
		return p.upHTTP.writeSync(ctx, notif)
	}
	return p.upWriter.Write(notif)
}

// maxConcurrentHostRequests bounds the in-flight host-request handler goroutines
// serveHost spawns. Each handler can block on the upstream round-trip (unboundedly
// under --upstream-timeout=0 with a silent upstream) and holds a pending /
// byUpstreamID entry, so an uncapped goroutine-per-request lets a pipelining host
// exhaust memory and FDs. On saturation serveHost rejects further requests with a
// structured error rather than spawning. Generous enough that honest pipelining
// never trips it; the remote-HTTP bridge caps its own POSTs separately
// (maxInflightPosts).
const maxConcurrentHostRequests = 256

// jsonRPCCodeServerBusy is returned to the host when serveHost's in-flight cap is
// saturated. -32000 is the JSON-RPC implementation-defined server-error range; it
// signals a transient, retryable overload, distinct from a policy denial.
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

// waitHostForwardOrShutdown blocks until the host-forward ordering barrier
// (fwdHostWrites) drains — every host request received before the current
// notification has reached the upstream — or the session is shutting down (ctx
// cancelled or the upstream exited). It returns true only when the barrier drained,
// so the caller forwards the notification in wire order; false means stop. Keeping
// the wait interruptible matters because a request's upstream write can wedge under
// --upstream-timeout=0 against an upstream that stops draining its stdin; a blocking
// WaitGroup.Wait there would pin the serve loop past a signal. The waiter goroutine
// outlives a shutdown-cancelled wait until the barrier eventually drains, which is
// fine on the teardown path (the process is exiting).
//
// Interruptibility on the shutdown legs also bounds the former sampling + write-wedge
// deadlock: the serve loop is the sole router of host responses to server-initiated
// requests (serveHost's IsResponse branch), so a handler wedged in a raw upstream stdin
// write — holding both a fwdHostWrites slot and the MsgWriter mutex because a
// sampling-capable upstream stopped draining its stdin — used to park this loop on the
// barrier forever, with the sampling reply that would unblock the upstream stuck behind
// it. That is now resolved at the write itself: the subprocess MsgWriter carries a
// per-write deadline of --upstream-timeout (NewMsgWriterWithTimeout), so a wedged write
// returns ErrUpstreamWriteTimeout instead of blocking indefinitely; callUpstream then
// tears the upstream down, which drains this barrier and unblocks the loop. Under
// --upstream-timeout=0 the write is intentionally unbounded (the operator's opt-out), so
// the interruptible wait here remains the residual "recoverable by shutdown" backstop.
func (p *StdioProxy) waitHostForwardOrShutdown(ctx context.Context) bool {
	// Fast path: no host request is in flight ahead of this notification, so the
	// wire-order barrier is already drained — skip the throwaway waiter goroutine and
	// channel entirely (the common case for a notification-heavy host, and it also
	// avoids the documented shutdown-time leak of that goroutine in that case). The
	// counter is incremented only by serveHost, the same single-threaded loop that
	// calls this, so a zero read here cannot race with a concurrent Add; a concurrent
	// decrement (a handler releasing) only ever makes the count smaller, so a 0 read is
	// never a false "drained".
	if p.fwdHostInFlight.Load() == 0 {
		return true
	}
	drained := make(chan struct{})
	// On a shutdown wake (ctx.Done / upstreamDone) this returns while the goroutine is
	// still blocked in Wait(); it ends only once the barrier eventually drains. That is
	// safe because the sole caller stops serving on a false return (it does not loop
	// back and issue another fwdHostWrites.Add while this waiter is still registered —
	// Add-concurrent-with-Wait is documented WaitGroup misuse and panics), and because
	// StdioProxy runs in a binary that exits on shutdown, so the leaked goroutine dies
	// with the process. If StdioProxy is ever reused as a long-lived library component,
	// replace this with a sync.OnceFunc-posted channel so the waiter cannot accumulate.
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

	// Run the blocking host read off the serve loop so the loop can select on
	// ctx.Done()/upstreamDone too. The reader exits on the first read error (EOF) or
	// when ctx is cancelled while it is parked trying to hand off a message; a reader
	// still parked inside the syscall on os.Stdin is reclaimed when the process exits.
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
			// Signal / parent cancellation: stop serving immediately so the proxy
			// self-terminates. Do NOT wait for in-flight handlers here — that would
			// re-couple shutdown latency to a stuck upstream, the very signal-deafness
			// this loop was restructured to fix. Each handler unblocks on the shared ctx
			// or, if wedged in a raw upstream-pipe write, when Start's teardown kills the
			// upstream; their deferred cleanup then runs. Start drains the upstream next.
			return
		case <-p.upstreamDone:
			// Upstream exited on its own: every further request would just fail with
			// errUpstreamExited, so stop serving and let Start tear down. Handlers
			// awaiting the upstream already observe upstreamDone and return; nothing
			// remains to forward, so do not block on them either.
			return
		}
		if r.err != nil {
			// A malformed line is recoverable: the newline framing is intact, so answer
			// JSON-RPC -32700 (id null, per the spec — a parse error has no reliable id)
			// and keep serving, matching how MCP stdio transports handle bad input. Any
			// other error (EOF, bufio.ErrTooLong, I/O) loses framing and ends the session.
			if errors.Is(r.err, mcp.ErrParse) {
				// id null, per the JSON-RPC 2.0 spec: pass an explicit "null" rather than
				// nil so the marshaled response carries "id":null. RPCMsg.ID is
				// `json:"id,omitempty"`, so a nil id would drop the member entirely and a
				// spec-strict client could reject the reply as neither response nor
				// notification.
				_ = p.hostWriter.Write(mcp.ErrorResponse(mcp.RawJSON("null"), jsonRPCCodeParseError, "Parse error"))
				continue
			}
			break // host stdin closed (EOF) or an unrecoverable read error
		}
		msg := r.msg

		if msg.IsNotification() {
			// forwardHostNotification returns true only when a shutdown woke the
			// wire-ordering barrier, in which case serveHost must stop immediately
			// (matching the ctx.Done / upstreamDone cases in the select above).
			if p.forwardHostNotification(ctx, msg) {
				return
			}
			continue
		}
		if msg.IsRequest() {
			// Bound concurrent handlers (see maxConcurrentHostRequests). Acquire is
			// non-blocking: the read loop must keep routing the host's replies to
			// server-initiated requests (the IsResponse branch below), so it must never
			// stall on a saturated pool. On saturation, reject with a structured,
			// retryable error instead of spawning an unbounded goroutine.
			select {
			case p.hostSem <- struct{}{}:
			default:
				_ = p.hostWriter.Write(mcp.ErrorResponse(msg.ID, jsonRPCCodeServerBusy, "eunox: too many concurrent requests in flight; retry"))
				continue
			}
			// Reserve the decision ticket HERE, in the single-threaded read loop, so it
			// reflects proxy-RECEIPT order — the handler goroutines then run their
			// decisions in that order regardless of scheduling (docs/flow-label-hardening.md
			// piece B). Only enforced methods take a ticket (only they run a PDP decision +
			// state write), and only after the hostSem acquire above, so a server-busy
			// rejection never strands an un-begun ticket that would stall every later one.
			// A non-serialized session (non-flow/non-sequenceBlock policy) reserves none.
			serialized := p.decideGate != nil && isEnforcedMethod(msg.Method)
			var ticket uint64
			if serialized {
				ticket = p.decideGate.take()
			}
			// One goroutine per request. The read loop must NOT block on a request: it
			// is also the only path that routes the host's replies to server-initiated
			// requests back to the upstream, so blocking dispatch here would deadlock a
			// sampling/roots-capable upstream (the loop stalls, and handlers waiting on
			// those replies never progress). The ordering barrier (fwdHostWrites) is
			// released when the request reaches the upstream (callUpstream, via the ctx
			// value) or — for a denied/errored request that never does — when the handler
			// returns; sync.OnceFunc makes the double call a single Done.
			p.fwdHostWrites.Add(1)
			p.fwdHostInFlight.Add(1)
			release := sync.OnceFunc(func() {
				p.fwdHostInFlight.Add(-1)
				p.fwdHostWrites.Done()
			})
			wg.Add(1)
			go func(m mcp.RPCMsg, serialized bool, ticket uint64) {
				defer wg.Done()
				defer func() { <-p.hostSem }()
				defer release()
				hctx := context.WithValue(ctx, fwdReleaseKey{}, release)
				// For a serialized enforced request, wait this ticket's turn before the
				// decision runs (begin blocks until the earlier tickets' decisions
				// commit), and advance the turn afterward. The Decide* handler releases
				// early via finishDecision (before the upstream forward); this defer is
				// the idempotent backstop for the malformed-params path, which returns
				// before the decision. The end func is threaded to the handler via ctx.
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
			if p.serverReqs.take(mcp.MsgKey(msg.ID)) {
				// Mirror the HTTP transport's kill gate on this leg (http_routing.go): a
				// kill that lands after the request was forwarded but before the host's
				// reply arrives must not deliver that reply to a killed session's upstream.
				// The tracked id is consumed above (no leak); a kill does not tear the
				// upstream down, so its blocked server-initiated request is left unanswered
				// and the upstream is reclaimed on teardown.
				if deny := p.pdp.CheckKill(ctx, p.sessionID); deny != nil {
					// Record the dropped host reply so a killed session's suppressed
					// server-response is visible on the tape, mirroring the host-notification
					// kill record (forwardHostNotification). A response carries no method, so
					// use a fixed "server-response" identifier.
					recordKillDrop(ctx, p.rec(), deny, p.sessionID, "server-response", "server-response", legStdioServerResponse)
				} else {
					_ = p.upWriter.Write(msg)
				}
			}
			continue
		}
		// Ignore malformed messages.
	}
	// Host stdin closed (EOF). Wait for in-flight handlers to finish their upstream
	// round-trip before returning; the upstream input stays OPEN here so a request
	// the host pipelined just before closing stdin can still be forwarded and
	// answered (closing it first would race the handler's outbound write). Start
	// closes the upstream input only after this returns.
	//
	// This is unbounded only under --upstream-timeout=0 with an upstream that never
	// responds — inherent to opting out of per-call timeouts; the default timeout
	// cancels a stuck handler and lets wg.Wait return.
	wg.Wait()
}

// forwardHostNotification forwards one host->upstream notification, enforcing (in
// order) the swallow of notifications/initialized (and a mid-session "initialize"
// sent as a notification), the session kill switch, the host wire-ordering barrier,
// and the notifications/cancelled id translation. It returns stop=true ONLY when a
// shutdown woke the ordering barrier, signalling serveHost to return immediately;
// false to continue the serve loop.
//
// notifications/initialized is swallowed (the proxy already sent its own to the
// upstream during its client handshake). An id-less "initialize" is swallowed too:
// IsNotification()'s classification is purely structural, so a client can send
// "initialize" with no id and have it classified as a notification even though the
// method is ordinarily a request — forwarding that verbatim would let it re-trigger
// the upstream's handshake outside dispatchRequest's kill gate and audit trail,
// mirroring the HTTP transport's sessionless-initialize-notification drop. A killed
// session must not push notifications upstream either — mirror the HTTP transport's
// notification kill check so the kill is enforced identically on both transports; a
// notification is fire-and-forget, so the kill is recorded and the message dropped
// (p.pdp is non-nil: NewStdioProxy defaults an omitted PDP).
//
// The wire-ordering barrier waits for every request the host sent before this
// notification to reach the upstream first, so a notifications/cancelled cannot be
// delivered ahead of the tools/call it cancels. It releases on the upstream WRITE,
// not the response, so cancelling a slow in-flight call does not block it. On a
// shutdown wake it returns stop=true rather than looping: a leaked waiter is still
// registered on fwdHostWrites, so reading further requests (each fwdHostWrites.Add)
// would be Add-concurrent-with-Wait, a WaitGroup misuse that panics on teardown.
func (p *StdioProxy) forwardHostNotification(ctx context.Context, msg mcp.RPCMsg) (stop bool) {
	if isSwallowedHostNotification(msg.Method) {
		return false
	}
	if deny := p.pdp.CheckKill(ctx, p.sessionID); deny != nil {
		recordKillDrop(ctx, p.rec(), deny, p.sessionID, msg.Method, msg.Method, legStdioNotification)
		return false
	}
	// An enforced method (tools/call, resources/read, resources/subscribe,
	// prompts/get) framed as a notification (no id) is a fail-closed reject —
	// see denyEnforcedMethodNotification, shared with the HTTP transport's
	// equivalent guard so the check and its audit record cannot drift between
	// the two transports.
	if denyEnforcedMethodNotification(ctx, p.rec(), p.sessionID, msg) {
		return false
	}
	// Any notification method outside the forwardable allowlist (notifications/
	// cancelled, notifications/progress, notifications/roots/list_changed) is a
	// fail-closed reject — see denyUnmappedHostNotification, shared with the HTTP
	// transport's equivalent guard so a notification-framed novel/unmapped method
	// cannot reach the upstream invisibly while its request-framed twin would be
	// denied and logged by dispatchUnmapped.
	if denyUnmappedHostNotification(ctx, p.rec(), p.sessionID, msg) {
		return false
	}
	if !p.waitHostForwardOrShutdown(ctx) {
		return true
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
	_ = p.upWriter.Write(msg)
	return false
}

// handleHostRequest processes a single request from the host. Every enforced
// method — including initialize — routes through the transport-shared
// dispatchRequest so the method->handler mapping, the fail-closed default, and the
// cross-cutting kill gate cannot drift from the HTTP transport. initialize's local
// response is supplied by p.buildInitResponse (wired into dispatchParams).
func (p *StdioProxy) handleHostRequest(ctx context.Context, msg mcp.RPCMsg) {
	d := p.dispatchParams()
	// decisionEndFromContext is the per-session decision-lock release (nil unless the
	// serve loop threaded one for a serialized enforced request); the Decide* handlers
	// call it right after the PDP decision so the upstream forward runs outside the lock
	// (piece B). A direct test caller of handleHostRequest threads none, so it is nil.
	d.endDecision = decisionEndFromContext(ctx)
	_ = p.hostWriter.Write(dispatchRequest(ctx, d, msg))
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

// dispatchParams bundles the proxy's policy/audit/upstream wiring for the shared
// request dispatcher. stdio carries no per-request client address, so sourceIP is
// empty; the sink is routed through asRecorder so a nil sink becomes a true nil
// interface, keeping the core's nil check a real "no sink" test (not the typed-nil
// trap).
func (p *StdioProxy) dispatchParams() dispatchParams {
	return dispatchParams{
		forwardParams: forwardParams{
			rec:              p.rec(),
			audit:            p.audit,
			sessionID:        p.sessionID,
			upstreamTimeMs:   p.upstreamTimeMs,
			callUpstream:     p.callUpstream,
			strictAuditState: p.strictAudit(),
		},
		pdp:       p.pdp,
		sourceIP:  "", // stdio has no per-request client address
		buildInit: p.buildInitResponse,
	}
}

// buildInitResponse builds the host-facing initialize response from the upstream
// capabilities gathered during proxy startup. It is the per-transport responder
// dispatchInitialize calls after the shared kill gate passes; the caller writes the
// returned message to the host.
func (p *StdioProxy) buildInitResponse(msg mcp.RPCMsg) mcp.RPCMsg {
	resp := buildInitializeResponse(msg.ID, p.upstreamCaps, p.upstreamInstructions)
	fmt.Fprintf(os.Stderr,
		"[eunox] Session %s: host initialized (protocol %s).\n",
		p.sessionID, MCPProtocolVersion,
	)
	return resp
}

// trackServerRequest records the ID of a server-initiated request being forwarded
// to the host, so serveHost can route the host's response back to the upstream.
func (p *StdioProxy) trackServerRequest(id *json.RawMessage) {
	if id == nil {
		return
	}
	p.serverReqs.track(mcp.MsgKey(id))
}

// forwardServerRequestToHost tracks msg's ID and forwards the server-initiated
// request to the host. The host's response (same ID) is later routed back to the
// upstream by serveHost.
func (p *StdioProxy) forwardServerRequestToHost(msg mcp.RPCMsg) {
	p.trackServerRequest(msg.ID)
	_ = p.hostWriter.Write(msg)
}

// handleUpstreamRequest handles server-initiated JSON-RPC requests from the
// upstream subprocess (e.g. sampling/createMessage, roots/list).
// sampling/createMessage is denied by default unless the manifest explicitly
// permits it and the session is not killed; all other server-initiated
// requests are forwarded to the host.
func (p *StdioProxy) handleUpstreamRequest(ctx context.Context, msg mcp.RPCMsg) {
	// The stdio transport has no network client: no source IP to gate sampling on
	// (an ipRange condition fails closed here) and no JWT identity. The host writer
	// cannot fail to deliver, so forward always reports true.
	forwardServerRequest(ctx, msg, serverRequestParams{
		rec:              p.rec(),
		audit:            p.audit,
		sessionID:        p.sessionID,
		pdp:              p.pdp,
		forward:          func(m mcp.RPCMsg) bool { p.forwardServerRequestToHost(m); return true },
		writeUpstream:    func(m mcp.RPCMsg) { _ = p.upWriter.Write(m) },
		strictAuditState: p.strictAudit(),
	})
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
	// Encode the nonce as a JSON string via json.Marshal, not fmt's %q: the wire id must
	// be valid JSON, and %q produces Go-quoted strings that only COINCIDENTALLY equal
	// JSON strings for the current fixed-ASCII "eunox-up-<n>" format. Marshal makes the
	// JSON-encoding contract explicit, so a future format change (a path, a hostname, a
	// non-ASCII byte) cannot silently emit a Go-escaped string that is not valid JSON.
	// Marshaling a string never errors.
	raw, _ := json.Marshal(fmt.Sprintf("eunox-up-%d", seq))
	id = mcp.RawJSON(string(raw))
	// Key by the canonical MsgKey, not the raw wire bytes: deliverUpstreamResponse
	// looks the channel up under mcp.MsgKey(resp.ID), so the raw spelling would not
	// match and the response would never be delivered.
	return id, mcp.MsgKey(id)
}

// methodNotificationsCancelled is the JSON-RPC method a host sends to abort an
// in-flight request (params.requestId names the request's id).
const methodNotificationsCancelled = "notifications/cancelled"

// rewriteCancelToNonce translates a host notifications/cancelled's
// params.requestId to the upstream nonce the proxy substituted for the target
// request on the wire. Every host request to a nonce-rewriting upstream has its
// id replaced by a proxy nonce (awaitNonced), but a cancel notification is
// forwarded verbatim, so its requestId names an id the upstream never saw --
// upstream finds no matching in-flight request and ignores the cancel (per
// spec), making cancellation a permanent no-op through the proxy.
//
// It returns the message with params.requestId swapped to the live nonce and
// true when an in-flight request matches; false when the notification is not a
// well-formed cancel or nothing is in flight (the caller drops it -- an upstream
// ignores a cancel for an unknown/completed request anyway). Only the
// nonce-rewriting upstream paths (subprocess, stdio HTTP bridge) call this; the
// gateway remote-HTTP path forwards host ids unchanged, so its cancels already
// correlate and must NOT be rewritten.
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
// timed-out-response misrouting.
//
// pending (keyed by host ID) is the duplicate-ID guard: a second in-flight
// request reusing a host ID is rejected rather than overwriting the first
// caller's entry. byUpstreamID (keyed by a proxy-generated nonce) is the response
// router: the request goes upstream carrying the nonce, the reader delivers the
// matching response through byUpstreamID, and on timeout the nonce entry is
// removed so a late response lands nowhere (it cannot leak into a later request
// reusing the same host ID).
//
// rewrite installs the nonce ID on the outbound message; send transmits it.
func awaitNonced(
	ctx context.Context,
	mu *sync.Mutex,
	pending, byUpstreamID map[string]chan upstreamResult,
	hostToUp map[string]*json.RawMessage,
	seq *uint64,
	done <-chan struct{},
	hostKey string,
	rewrite func(id *json.RawMessage),
	send func() error,
) (mcp.RPCMsg, error) {
	ch := make(chan upstreamResult, 1)
	mu.Lock()
	if _, exists := pending[hostKey]; exists {
		mu.Unlock()
		return mcp.RPCMsg{}, fmt.Errorf("%w %q: request already pending", errDuplicateID, hostKey)
	}
	*seq++
	upID, upKey := upstreamNonceID(*seq)
	pending[hostKey] = ch
	byUpstreamID[upKey] = ch
	// Record host-id -> nonce so a later notifications/cancelled can translate its
	// params.requestId to the id the upstream actually saw. hostToUp is nil only
	// for a legacy test-assembled proxy; guard so the correlation degrades to the
	// pre-fix verbatim forward rather than panicking.
	if hostToUp != nil {
		hostToUp[hostKey] = upID
	}
	mu.Unlock()
	defer func() {
		mu.Lock()
		delete(pending, hostKey)
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
		// A remote-HTTP-bridge transport failure (connection refused, DNS, non-2xx,
		// per-call timeout) rides result.err, not the response body: deliverUpstreamError
		// (the bridge's fire-and-forget POST failure path) sends it directly on this same
		// channel, so surface it as the call's error. enforcedForwardCore/dispatch then
		// classify it through upstreamErrInfo and record a deny/UPSTREAM_ERROR (matching
		// the gateway) instead of an allow carrying upstream_error_code. Never set on the
		// subprocess path (no bridge).
		if result.err != nil {
			return mcp.RPCMsg{}, result.err
		}
		resp := result.msg
		// A valid response carries an id, NO method, and exactly one of result/error.
		// readUpstream delivers a message-bearing reply here when it echoes a live nonce (a
		// forged/confused upstream message), and IsResponse()/isMalformedResponse alone check
		// only part of the shape, so enforce BOTH: !IsResponse() refuses a method-bearing
		// reply (a response has no method) and isMalformedResponse refuses one carrying
		// neither result/error (an empty {"jsonrpc":"2.0","id":...}) or both. Together they
		// match correlateUpstreamReply's !IsResponse()+malformed refusal on the HTTP-upstream
		// bridge (see jsonrpc.go), so a method-bearing or malformed reply is never fed to the
		// host as a response and the rule cannot drift between the two transports.
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
	// NewStdioProxy initializes byUpstreamID, so this lazy init only fires for a
	// test-assembled proxy; under pendingMu so it cannot race awaitNonced/readUpstream.
	p.pendingMu.Lock()
	if p.byUpstreamID == nil {
		p.byUpstreamID = make(map[string]chan upstreamResult)
	}
	if p.hostToUp == nil {
		p.hostToUp = make(map[string]*json.RawMessage)
	}
	p.pendingMu.Unlock()
	return awaitNonced(ctx, &p.pendingMu, p.pending, p.byUpstreamID, p.hostToUp, &p.upstreamSeq, p.upstreamDone, mcp.MsgKey(msg.ID),
		func(id *json.RawMessage) { msg.ID = id },
		func() error {
			// For HTTP upstreams, use the per-call ctx so --upstream-timeout cancels
			// the in-flight POST; Write (fire-and-forget) uses the bridge-lifetime ctx
			// and would bypass per-call deadlines.
			if p.upHTTP != nil {
				p.upHTTP.postWithCtx(ctx, msg)
				// The request is on its way to the upstream: release the host-forward
				// ordering barrier so a host notification queued behind it may proceed.
				releaseHostForward(ctx)
				return nil
			}
			err := p.upWriter.Write(msg)
			if err == nil {
				releaseHostForward(ctx)
			}
			// A write timeout (ErrUpstreamWriteTimeout) has already torn the upstream down via
			// the writer's onPoison hook (killUpstream), so this only returns the error; the
			// handler's deferred release() then drains the ordering barrier so a parked host
			// notification proceeds, and readUpstream's EOF unblocks the serve loop.
			return err
		})
}

// reportUpstreamErr delivers a remote-HTTP-bridge transport failure directly to the
// in-flight call identified by the upstream nonce upKey, so awaitNonced returns it
// as the call's error, and reports whether a live caller was found. It is a thin
// wrapper over deliverUpstreamError: a caller no longer registered in byUpstreamID
// (the bridge's POST goroutine runs fire-and-forget and may deliver its failure
// after the caller already gave up — per-call timeout, upstream exit) is simply a
// no-op reporting false, with no separate map entry to leak. A handshake/probe POST
// (no byUpstreamID entry) likewise reports false; either way the bridge's post()
// falls back to its synthesized in-band response instead.
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
			// than a silent reader exit.
			if !errors.Is(err, io.EOF) {
				fmt.Fprintf(os.Stderr, "[eunox] upstream read error: %v\n", err)
			}
			return
		}

		if msg.IsNotification() {
			// A killed session must not keep receiving the upstream->host notification
			// relay: stdio's equivalent of the HTTP transport gating its SSE relay on the
			// kill (http_session.readUpstream). CheckKill reads the local cache (cheap
			// even for the Redis backend), so this does not add a round-trip per
			// notification, and it denies on a kill-store error too (fail closed).
			// Recording the drop keeps a killed session's suppressed notifications visible
			// on the tape, mirroring serveHost's host-notification kill record (so a
			// transient store outage drops-and-records rather than silently swallowing).
			// p.pdp is non-nil in production (NewStdioProxy defaults an omitted PDP); the
			// guard covers a test-assembled proxy that wires no PDP.
			if p.pdp != nil {
				if deny := p.pdp.CheckKill(ctx, p.sessionID); deny != nil {
					recordKillDrop(ctx, p.rec(), deny, p.sessionID, msg.Method, msg.Method, legStdioUpstreamNotification)
					continue
				}
			}
			_ = p.hostWriter.Write(msg)
			continue
		}

		// Server-initiated requests (e.g. sampling/createMessage, roots/list). A message
		// carrying BOTH an id and a method (IsRequest()) that echoes a LIVE outstanding
		// upstream nonce is NOT a server-initiated request — it is a forged/confused reply to
		// that in-flight call, and must be refused rather than reclassified and forwarded to
		// the host. Route it to the waiting caller, which refuses a method-bearing reply
		// (awaitNonced's response-shape check), mirroring correlateUpstreamReply's
		// !IsResponse() refusal on the HTTP-upstream bridge so the nonce-correlation invariant
		// holds symmetrically. A method-bearing message whose id is NOT a live nonce is a
		// genuine server-initiated request. Scoping the nonce lookup to the method-bearing
		// case keeps a normal response (below, no method) on a single lock/lookup.
		if msg.IsRequest() {
			p.pendingMu.Lock()
			_, liveNonce := p.byUpstreamID[mcp.MsgKey(msg.ID)]
			p.pendingMu.Unlock()
			if liveNonce {
				deliverUpstreamResponse(&p.pendingMu, p.byUpstreamID, msg)
				continue
			}
			p.handleUpstreamRequest(ctx, msg)
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
