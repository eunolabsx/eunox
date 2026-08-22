// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// HTTP proxy transport (MCP Streamable HTTP / SSE).
//
// Architecture:
//
//	MCP client ──HTTP──► HTTPProxy (one httpSession per client session)
//	                          │
//	                    upstream subprocess (stdio JSON-RPC)
//
// Session lifecycle:
//
//	POST /mcp (initialize, no session ID) → spawn upstream → initialize handshake → mint session ID
//	POST /mcp (session ID)               → route request to session's upstream
//	GET  /mcp (session ID)               → SSE stream of upstream notifications
//	DELETE /mcp (session ID)             → close session and upstream
//
// POST /control/kill (loopback only) → kill a session or all sessions.

package transport

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/internal/config"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

const (
	// SessionHeader is the MCP Streamable HTTP session header. It is exported so
	// the CLI's live-upstream probe can read the upstream's session id.
	SessionHeader = "Mcp-Session-Id"
	// CTJSON is the application/json content type, exported for the kill subcommand.
	CTJSON = "application/json"
	ctSSE  = "text/event-stream"

	// httpWriteTimeout is a Slowloris backstop, not the response budget: it is the FLOOR of
	// the window rearmWriteDeadline arms before a POST-path leg writes its response (widened
	// to the upstream budget + writeSlack when that is larger, never cleared), and the SSE
	// path re-arms a bounded per-chunk sseWriteTimeout around every frame (handleMCPGet) — a
	// long-lived stream must outlive any single-call budget, but one write must still never
	// block forever.
	httpReadTimeout  = 30 * time.Second
	httpWriteTimeout = 30 * time.Second

	// writeSlack pads the per-call upstream budget when extending the POST write
	// deadline, so encoding/flushing a response that arrives at the edge of the
	// upstream timeout is not itself raced by the connection write deadline.
	writeSlack = 5 * time.Second

	// sseWriteTimeout bounds one chunk of an SSE frame write. The stream is long-lived
	// (it outlives any single-call budget), but a single write must not block forever:
	// a stuck reader (a TCP zero/tiny receive window that never drains) would otherwise
	// park the delivery goroutine inside Write past kill and idle-reap, pinning the
	// goroutine and its maxSubsPerSession slot. handleMCPGet re-arms it before each
	// sseWriteChunk-sized write, so the deadline measures forward progress rather than
	// whole-frame wall-clock — a slow-but-progressing reader is not killed mid-frame.
	sseWriteTimeout = 10 * time.Second

	// sseWriteChunk bounds a single Write so sseWriteTimeout measures per-chunk
	// progress: a reader draining slower than sseWriteChunk/sseWriteTimeout trips the
	// deadline, while a faster one streams arbitrarily large frames uninterrupted.
	sseWriteChunk = 16 << 10 // 16 KiB

	// sseKeepaliveInterval is how often an otherwise-idle SSE stream emits a comment
	// frame, both to keep intermediaries from idling the connection out and to re-arm
	// the bounded write deadline so a reader that has stopped draining is detected.
	// handleMCPGet also emits one keepalive immediately at stream open, so there is no
	// unguarded gap before the first interval. Worst-case slot-hold for a wedged reader
	// on an idle stream is therefore bounded by sseKeepaliveInterval + sseWriteTimeout.
	sseKeepaliveInterval = 15 * time.Second

	// maxRequestBodyBytes caps the POST body; larger requests get 413.
	maxRequestBodyBytes = 4 << 20 // 4 MiB

	// UpstreamTimeoutUnset is the --upstream-timeout flag default (the "unset"
	// sentinel, so ResolveUpstreamTimeout applies the built-in default). An explicit
	// 0 disables the timeout entirely.
	UpstreamTimeoutUnset = -1
	// defaultUpstreamTimeoutMs bounds every upstream call when neither flag nor
	// config set a value, so a hung upstream cannot pin a handler goroutine forever.
	defaultUpstreamTimeoutMs = 30000
)

// ResolveUpstreamTimeout folds the --upstream-timeout flag and the config's
// defaults.upstreamTimeoutMs into the effective per-call upstream timeout.
//
// CLI-over-config precedence: a non-negative flag wins (so --upstream-timeout=0
// disables the timeout regardless of config); a negative flag is "unset", so a
// positive config value applies; with neither set, the built-in default bounds
// every call.
func ResolveUpstreamTimeout(flagVal, cfgVal int) int {
	if flagVal >= 0 {
		return flagVal
	}
	if cfgVal > 0 {
		return cfgVal
	}
	return defaultUpstreamTimeoutMs
}

// msToDuration converts milliseconds to a time.Duration, saturating at math.MaxInt64 instead
// of overflowing. Without this, ms*time.Millisecond wraps past config.MaxDurationMs into a
// negative/tiny value that expires calls instantly. Callers guard ms <= 0 ("disabled").
func msToDuration(ms int) time.Duration {
	if int64(ms) > config.MaxDurationMs {
		return time.Duration(math.MaxInt64)
	}
	return time.Duration(ms) * time.Millisecond
}

// addSlack adds writeSlack to d, saturating at math.MaxInt64 instead of overflowing. At the
// documented-max upstream timeout, a bare `d + writeSlack` would wrap negative — a write
// deadline in the PAST that fails every response write.
func addSlack(d time.Duration) time.Duration {
	if d > time.Duration(math.MaxInt64)-writeSlack {
		return time.Duration(math.MaxInt64)
	}
	return d + writeSlack
}

// rearmWriteDeadline resets the connection's write deadline to a fresh window before a handler
// leg does slow work and then writes its response.
//
// The deadline armed at handler entry is measured FROM entry, so a leg whose work approaches
// it (a --shutdown-timeout teardown, a slow-upstream notification) can reach its write with
// the deadline already past — dropping a response for an operation that in fact succeeded,
// worst on the kill endpoint: `eunox kill` reporting failure for a stop that took effect.
//
// budgetMs is the leg's own budget (0 = none); window is budget+writeSlack, floored at
// httpWriteTimeout. Every response-write deadline in this package goes through this helper (or
// its Duration/teardown spellings) so the floor rule lives once. The SSE delivery loop is the
// deliberate exception — a per-chunk forward-progress deadline, a different policy on purpose.
func rearmWriteDeadline(w http.ResponseWriter, budgetMs int) {
	var budget time.Duration
	if budgetMs > 0 {
		budget = msToDuration(budgetMs)
	}
	rearmWriteDeadlineFor(w, budget)
}

// rearmWriteDeadlineFor is rearmWriteDeadline's core, taking the leg's budget as a Duration
// for the one caller that computes one directly (session establishment). Routing that caller
// through the millisecond spelling would truncate and could overflow int at the saturated
// budget msToDuration produces.
//
// budget <= 0 means "no configured budget"; see rearmWriteDeadline for the floor rule.
func rearmWriteDeadlineFor(w http.ResponseWriter, budget time.Duration) {
	window := httpWriteTimeout
	if budget > 0 {
		if b := addSlack(budget); b > window {
			window = b
		}
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(window))
}

// rearmWriteDeadlineForTeardown re-arms for a leg that waits on httpSession.close, whose worst
// case is TWO sequential --shutdown-timeout bounds: close waits that long for the subprocess
// to exit, then SIGKILLs it and waits again. Arming a single budget left the deadline past at
// exactly the setting the re-arm exists for. The global kill sweeps sessions in parallel, so
// its wall clock is that same per-session worst case, not N times it.
func rearmWriteDeadlineForTeardown(w http.ResponseWriter, shutdownMs int) {
	if shutdownMs > 0 && shutdownMs <= math.MaxInt/2 {
		shutdownMs *= 2
	}
	rearmWriteDeadline(w, shutdownMs)
}

// ResolveMaxSessions folds the --max-sessions flag and the config's listen.maxSessions into
// the effective concurrent-session cap. A present config value wins, including 0 (unlimited):
// cfgVal is a pointer, so an absent key (nil) leaves the flag's value in force.
func ResolveMaxSessions(flagVal int, cfgVal *int) int {
	return config.ResolveInt(cfgVal, flagVal)
}

// ResolveSessionIdleTimeout folds the --session-idle-timeout flag and the config's
// listen.sessionIdleTimeoutMs into the effective idle-reap window. Mirrors ResolveMaxSessions:
// a present config value wins, including 0 (no idle reaping).
func ResolveSessionIdleTimeout(flagVal int, cfgVal *int) int {
	return config.ResolveInt(cfgVal, flagVal)
}

// killActivator is the one-way half of the kill switch: the loopback control endpoint can
// ISSUE a revocation and can never lift one — structural, not documentary.
//
// A same-host process holding the control token can already halt this proxy (a documented
// residual); giving that reach an undo would let it lift the very revocation issued against
// it, which is why `eunox kill --revive` is deliberately Redis-only.
//
// Keep this interface narrow: widening it back to killswitch.Manager re-opens the undo path
// this type exists to keep shut. The CLI's reviveViaRedis holds itself to the same bar.
type killActivator interface {
	// ActivateGlobal stops the whole deployment. There is no DeactivateGlobal here.
	ActivateGlobal(ctx context.Context) error
	// KillSession revokes one session. There is no ReviveSession here.
	KillSession(ctx context.Context, sessionID string) error
}

// HTTPProxy implements the MCP Streamable HTTP transport.
// Each client session gets its own upstream subprocess (local mode) or connects
// to a remote MCP HTTP server (remote mode, enabled by UpstreamURL).
type HTTPProxy struct {
	jwtPDP       *pdp.JWTPDP            // non-nil when --jwks-uri is configured
	oauthMeta    *OAuthResourceMetadata // non-nil when --oauth-resource / listen.oauthResource is set (which the CLI admits only alongside bearer-token validation)
	oauthMetaURL string                 // absolute metadata URL for WWW-Authenticate; empty when --oauth-resource is not set
	sink         *audit.Sink
	// stderr is where this proxy writes its diagnostic lines (startup banners, SECURITY/WARNING
	// notices, session lifecycle lines) — read through errOut(), never referenced directly, so a
	// bare struct-literal test proxy (stderr left nil) still gets a writer. Never swapped after
	// construction: a caller that wants to capture output builds the proxy with a pipe/buffer
	// here instead of reassigning the process-global os.Stderr, which raced concurrent tests
	// reading it.
	stderr io.Writer
	// ks is deliberately the kill-ONLY interface, not killswitch.Manager: see killActivator.
	ks                 killActivator
	shutdownMs         int
	upstreamTimeMs     int
	requireAuditStrict bool // --require-audit=strict: deny forwards once the audit trail degrades
	// strictAuditWarned makes the sticky strict-gate stderr warning one-shot.
	strictAuditWarned noticeLatch
	authToken         string
	// controlToken authenticates POST /control/kill (loopback only) so a same-host process is
	// not automatically trusted merely for being on loopback (SEC-07). Empty means fail closed.
	controlToken string
	// afterListen runs once the listener has bound and before any request is served, for
	// startup work that must not happen when the bind fails. See HTTPGatewayOptions.
	afterListen func(context.Context) error
	// afterListenBudget bounds that hook. Per-proxy (not a package constant) so a test can
	// shorten it without racing other parallel tests. Zero means afterListenTimeout.
	afterListenBudget time.Duration
	// authTimingKey is a per-process random HMAC key folding presented/expected tokens to a
	// fixed-length MAC before the constant-time comparison. See constantTimeTokenEqual.
	authTimingKey []byte
	// preSessionDenies is the PROXY-WIDE refusal-record table. The name is historical and now
	// undersells it: it is charged by three different sources, not one.
	//
	//   - the pre-session refusals it was built for — the only audit writes an UNAUTHENTICATED
	//     caller can trigger, and so a lever on --require-audit=strict;
	//   - the -32022 revision refusal, which an ESTABLISHED session's traffic reaches;
	//   - and every session's own upstream-driven table, for which this is the aggregate parent
	//     holding the total at the pre-split ceiling (see newUpstreamRefusalLimiter).
	//
	// Left named for the first because the field is threaded through the leg wiring in a dozen
	// places and a rename buys nothing the doc does not; what mattered was that the doc claimed
	// a scope two of its three charge sources fall outside.
	preSessionDenies *categoryRecordLimiter
	// notices is the AGGREGATE stderr-diagnostic table: one bucket per notice CLASS, charged
	// directly by every leg with no route in scope and as the parent of each route's own table.
	// Separate from the record buckets above because a leg that meters no record (an established
	// session's kill records are deliberately unbounded) still owes a bound on a write syscall per
	// refused frame. See noticeLimiter.
	notices     *noticeLimiter
	trustFwdFor bool
	// trustedProxyNets is the compiled listen.trustedProxyCIDRs allowlist: under trustFwdFor,
	// the immediate TCP peer must match one before X-Forwarded-For is honored — see sourceIP.
	trustedProxyNets []*net.IPNet
	// trustedProxyHops is listen.trustedProxyHops: how many right-most X-Forwarded-For
	// entries are proxy-written. 0 means unset; sourceIP applies the single-proxy default.
	trustedProxyHops int
	bind             string
	port             int

	// maxSessions caps concurrent sessions (0 = unlimited); sessionIdleMs reaps sessions idle
	// for that many milliseconds (0 = no reaping) — bounding the per-session subprocess footprint.
	maxSessions   int
	sessionIdleMs int

	// DNS-rebinding defense (see checkOrigin): allowedOrigins holds operator-configured
	// full origins matched exactly; allowedOriginHosts is the set of host names always
	// accepted (loopback names plus the non-wildcard bind host).
	allowedOrigins []string
	// loopbackPinHosts holds the hostnames of allowedOrigins entries, read ONLY by the
	// DNS-rebinding Host pin on the loopback endpoints. Not merged into allowedOriginHosts:
	// see buildLoopbackPinHosts.
	loopbackPinHosts   map[string]bool
	allowedOriginHosts map[string]bool

	// routes maps a route name (the /mcp/<name> path segment) to its upstream wiring and
	// enforcement state. Single-upstream mode keys one route by "" (served at /mcp).
	routes map[string]*UpstreamRoute

	// baseCtx is the serve-lifetime context. Session reader goroutines outlive the HTTP
	// request that created the session, so they inherit this rather than the request's
	// context, for kill-switch lookups on the upstream-initiated path. Guarded by p.mu since
	// Serve writes it once while handler goroutines read it concurrently (a plain
	// interface-field write/read is a data race under -race).
	baseCtx context.Context

	// mu guards sessions, baseCtx, and shuttingDown. An RWMutex so read-only per-request paths
	// (getSession, sessionCount, serveCtx) take RLock and run concurrently; check-then-write
	// paths (registerSession's cap check, handleMCPDelete, closeAllSessions) keep Lock.
	mu       sync.RWMutex
	sessions map[string]*httpSession
	// shuttingDown is set under mu at the start of closeAllSessions so a slow in-flight
	// initialize registering AFTER the registry is emptied fails closed instead of leaking
	// its upstream subprocess. See registerSession.
	shuttingDown bool
	// reapGen is incremented under mu by teardownAllSessionsForGlobalKill each sweep. registerSession
	// rejects an insert if the generation has advanced since the session began establishing —
	// closing the race where an initialize that started before a global kill would otherwise
	// register into the fresh map after the sweep, leaking an undead upstream. Unlike
	// shuttingDown this is not a permanent latch: a raced registration is simply rejected
	// (the caller retries). See teardownAllSessionsForGlobalKill and registerSession.
	reapGen uint64
	// revoked wakes the reclaim worker (reclaimOnRevocation). One buffered slot, so a burst
	// coalesces into one sweep and nothing raised before the worker starts is lost.
	revoked chan struct{}
	// unobserveRevocations releases this proxy's registration on the shared kill switch. nil
	// for a proxy assembled by a struct literal (tests), which registered nothing.
	unobserveRevocations func()
	// establishing counts sessions that have RESERVED a maxSessions slot but have not
	// registered yet — between tryReserveSessionSlot and registerSession, spending up to
	// sessionStartTimeout on an upstream spawn, handshake, and drift probe. Guarded by mu.
	//
	// The cap must count them: registerSession alone would let N concurrent initialize POSTs
	// against an empty registry all pass a registry-only pre-check and all spawn an
	// upstream, repeatable every window — PID/FD/memory exhaustion despite the cap.
	establishing int
}

// errOut returns p's diagnostic writer, falling back to os.Stderr for a nil proxy or one
// assembled by a bare struct literal (stderr left unset) — the same nil-tolerant shape as
// shutdownBudget's proxy-less test session. Every stderr write in this file goes through it
// rather than os.Stderr directly, so a caller wanting to capture output configures the writer
// at construction instead of reassigning the process-global.
func (p *HTTPProxy) errOut() io.Writer {
	if p == nil {
		return os.Stderr
	}
	return resolvedErrOut(p.stderr)
}

// HTTPGatewayOptions configures a multi-upstream gateway HTTPProxy: one process fronting N
// upstreams, one per route, sharing a single audit sink and kill-switch.
type HTTPGatewayOptions struct {
	Routes         map[string]*UpstreamRoute
	Sink           *audit.Sink
	KS             killswitch.Manager
	JWTPDP         *pdp.JWTPDP
	OAuthMeta      *OAuthResourceMetadata // RFC 9728 metadata document; nil when no resource URI is configured
	OAuthMetaURL   string                 // absolute URL for resource_metadata in challenges
	ShutdownMs     int
	UpstreamTimeMs int
	AuthToken      string
	// Stderr is where this proxy writes its diagnostic lines. Nil (the default) means
	// os.Stderr; a caller that wants to capture them (a test asserting on a startup banner)
	// passes its own writer here instead of reassigning the process-global os.Stderr, which
	// races any other goroutine reading it concurrently.
	Stderr io.Writer
	// ControlToken authenticates POST /control/kill (loopback only), required independently
	// of AuthToken/JWT mode.
	ControlToken string
	// AfterListen, when non-nil, runs inside Serve immediately after the listener binds and
	// before the server accepts anything — startup effects that must not happen when the bind
	// fails: persisting the control token before the bind would let a second proxy that dies
	// on "address already in use" replace the RUNNING proxy's token on disk.
	//
	// The context it receives is bounded (afterListenTimeout) and cancels on Serve's own ctx.
	// A hook MUST honour it: the socket is already accepting into the kernel backlog while
	// this runs but nothing answers yet, so every second here is a client racing startup
	// spending it hung. Expiry must abort the hook's effect, not merely be reported — see
	// WriteControlTokenFile, which checks it immediately before its publishing rename.
	AfterListen func(ctx context.Context) error
	TrustFwdFor bool
	// TrustedProxyCIDRs is listen.trustedProxyCIDRs: reverse-proxy peers trusted to set
	// X-Forwarded-For under TrustFwdFor. An entry that fails to parse here is skipped (never
	// trusted) and logged, rather than silently narrowing the allowlist.
	TrustedProxyCIDRs []string
	// TrustedProxyHops is listen.trustedProxyHops: how many right-most X-Forwarded-For
	// entries were written by trusted hops. 0 (unset) is normalized to 1. See sourceIP.
	TrustedProxyHops int
	Bind             string
	Port             int

	// RequireAuditStrict is the --require-audit=strict gate: deny enforced forwards (and
	// */list enumeration) fail-closed once the shared audit trail degrades.
	RequireAuditStrict bool

	// MaxSessions caps concurrent sessions (0 = unlimited); SessionIdleMs reaps
	// sessions idle for that many milliseconds (0 = no reaping).
	MaxSessions   int
	SessionIdleMs int

	// AllowedOrigins is the operator-configured full-origin allowlist, accepted in
	// addition to the built-in loopback names and bind host. See checkOrigin.
	AllowedOrigins []string
}

// NewHTTPProxyGateway creates a gateway HTTPProxy from pre-built routes.
//
// It panics on an options field that is WIRED but holds a typed nil — see requireUsableOptions for
// why that is refused here rather than substituted or reported later. Every normalization below
// treats a nil field as ABSENT, which is a different fact and stays the caller's own.
func NewHTTPProxyGateway(opts HTTPGatewayOptions) *HTTPProxy {
	requireUsableOptions(opts)
	if opts.KS == nil {
		opts.KS = killswitch.NewInMemory()
	}
	if opts.ShutdownMs <= 0 {
		opts.ShutdownMs = 5000
	}
	if opts.Bind == "" {
		opts.Bind = "127.0.0.1"
	}
	if opts.Port <= 0 {
		opts.Port = 3000
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	var trustedProxyNets []*net.IPNet
	for _, cidr := range opts.TrustedProxyCIDRs {
		if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
			trustedProxyNets = append(trustedProxyNets, ipNet)
		} else {
			// GatewayConfig.Validate rejects a malformed entry before the CLI reaches here, but
			// this is an exported constructor a caller could invoke directly, so warn rather
			// than silently trust fewer peers than configured.
			_, _ = fmt.Fprintf(opts.Stderr, "[eunox] WARNING: listen.trustedProxyCIDRs entry %q is not a valid CIDR and will never be trusted: %v\n", cidr, err)
		}
	}
	p := &HTTPProxy{
		jwtPDP:             opts.JWTPDP,
		oauthMeta:          opts.OAuthMeta,
		oauthMetaURL:       opts.OAuthMetaURL,
		sink:               opts.Sink,
		stderr:             opts.Stderr,
		ks:                 opts.KS,
		shutdownMs:         opts.ShutdownMs,
		upstreamTimeMs:     opts.UpstreamTimeMs,
		requireAuditStrict: opts.RequireAuditStrict,
		authToken:          opts.AuthToken,
		controlToken:       opts.ControlToken,
		afterListen:        opts.AfterListen,
		authTimingKey:      newAuthTimingKey(),
		preSessionDenies:   newRefusalRecordLimiter(),
		notices:            newNoticeLimiter(len(opts.Routes)),
		trustFwdFor:        opts.TrustFwdFor,
		trustedProxyNets:   trustedProxyNets,
		trustedProxyHops:   opts.TrustedProxyHops,
		bind:               opts.Bind,
		port:               opts.Port,
		maxSessions:        opts.MaxSessions,
		sessionIdleMs:      opts.SessionIdleMs,
		allowedOrigins:     opts.AllowedOrigins,
		allowedOriginHosts: buildAllowedOriginHosts(opts.Bind),
		loopbackPinHosts:   buildLoopbackPinHosts(opts.AllowedOrigins),
		routes:             opts.Routes,
		sessions:           make(map[string]*httpSession),
		revoked:            make(chan struct{}, 1),
	}
	// Each route's diagnostic table is RE-PARENTED onto this proxy's aggregate, so a peer looping
	// an unmapped method against one route cannot silence another's lines. BuildRoutes already
	// built each one (parentless, so a route that never reaches a proxy is still bounded); what it
	// could not do is name the aggregate, which belongs to a proxy that did not exist yet.
	// Both per-route diagnostic facilities are assigned here, not just the one that needs the
	// aggregate: a route arriving through the exported Routes seam from somewhere other than
	// BuildRoutes would otherwise get a repaired bucket table beside nil collapse windows, which
	// reads as correctly wired and silently restores the per-frame flood.
	// Validated over the WHOLE map before anything is mutated. The loop below writes in place
	// on values the caller still holds, so validating and mutating in one pass left the routes
	// ahead of a rejected one already bound and re-pointed — a panic the caller cannot act on
	// without knowing which half of its map this constructor got through.
	for name, route := range p.routes {
		// requireUsableOptions descends into a container's elements, but this one's are POINTERS
		// and that is its stop: what a caller-built subsystem holds inside itself is its own
		// package's business. So the nil value this map may hold is refused here rather than
		// dereferenced on the next line — a diagnosis-free constructor panic three lines under the
		// guard that exists to replace one.
		requireUsable(fmt.Sprintf("HTTPGatewayOptions.Routes[%q]", name), route)
		// The one interface held INSIDE a route, and the last one in either options graph outside a
		// check. It used to be closed by visibility alone — UpstreamRoute's fields are unexported,
		// so only BuildRoutes and WrapRoutesWithJWT can populate them and neither produces a typed
		// nil today — which is an argument about the callers that exist rather than a rule. Named
		// here for the reason above, and held to it by the declaration in wiring_test.go: a second
		// pointer-element container option fails the build rather than inheriting these two lines.
		requireUsable(fmt.Sprintf("HTTPGatewayOptions.Routes[%q].pdp", name), route.pdp)
		// And a route already claimed by another proxy is refused rather than taken over: the
		// assignments below are IN PLACE on a value the caller still holds, so a second proxy over
		// the same map silently repoints the first's diagnostics and re-arms its collapse windows.
		// See UpstreamRoute.boundProxy. Build a fresh set (BuildRoutes) per proxy.
		if route.boundProxy {
			panic(fmt.Sprintf(
				"eunox: HTTPGatewayOptions.Routes[%q] is already bound to another HTTPProxy: a route holds "+
					"per-upstream diagnostic state that a second proxy would take over, silencing the first's "+
					"lines and re-arming its collapse windows. Build routes per proxy.", name))
		}
	}
	for _, route := range p.routes {
		route.boundProxy = true
		route.notices = newRouteNoticeLimiter(p.notices)
		route.noticeCollapse = newNoticeCollapse()
	}
	// Registered at construction (not Serve) so a kill delivered during startup is not lost —
	// the buffered slot coalesces it, served by the worker's first tick. Unregister is kept
	// because the kill switch OUTLIVES this proxy and may be handed to a second one.
	p.unobserveRevocations = opts.KS.ObserveRevocations(p.onRevocation)
	return p
}

// onRevocation is the kill switch's callback (killswitch.Manager.ObserveRevocations): it wakes
// the reclaim worker and returns.
//
// Must not block: the send is non-blocking onto a one-slot channel, so a burst of revocations
// coalesces into a single sweep instead of stalling the backend's real-time kill-event consumer.
//
// The event's fields are deliberately unused. A Revocation is a trigger, not a work list: the
// sweep re-asks the kill switch about each session it actually holds, through the same
// predicate the idle reaper uses, so an AGENT-scoped kill needs no agent→session map here.
func (p *HTTPProxy) onRevocation(killswitch.Revocation) {
	select {
	case p.revoked <- struct{}{}:
	default: // a sweep is already pending; it will observe this kill too
	}
}

// reclaimOnRevocation runs until ctx is done, sweeping for killed sessions each time the kill
// switch reports a revocation. One worker, so concurrent revocations produce one sweep, not a
// fan-out that could close the same session from N goroutines.
func (p *HTTPProxy) reclaimOnRevocation(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.revoked:
			p.sweepKilledSessions() //nolint:contextcheck // teardown path: close()'s upstream session-termination DELETE intentionally uses a detached, bounded background context, as every other reap site does.
		}
	}
}

// warnForwardedForPosture emits the startup SECURITY lines describing how this proxy will
// resolve a client IP from X-Forwarded-For. Split out of Serve so the posture rules read as
// one unit. Warns even though a direct-connecting client cannot spoof an ipRange source (see
// sourceIP): an empty allowlist makes the flag a no-op, and a configured one is only as
// strong as how tightly it is scoped.
func (p *HTTPProxy) warnForwardedForPosture() {
	if !p.trustFwdFor {
		return
	}
	if len(p.trustedProxyNets) == 0 {
		_, _ = fmt.Fprintf(p.errOut(),
			"[eunox] SECURITY: --trust-forwarded-for is enabled but listen.trustedProxyCIDRs is empty, "+
				"so no peer can ever match — X-Forwarded-For is never trusted and every request's source IP "+
				"is its own connection address. Set listen.trustedProxyCIDRs to the reverse proxy's address(es) "+
				"to enable X-Forwarded-For trust.\n",
		)
		return
	}
	if !bindIsLoopbackOnly(p.bind) {
		_, _ = fmt.Fprintf(p.errOut(),
			"[eunox] SECURITY: --trust-forwarded-for is enabled on a non-loopback bind (%q). "+
				"X-Forwarded-For is honored only from a peer matching listen.trustedProxyCIDRs; "+
				"scope that allowlist tightly to the real reverse proxy's address; a broader range "+
				"(e.g. a shared or NATed subnet) would let another host on it spoof an ipRange source.\n",
			p.bind,
		)
	}
	// The declared hop count is trusted verbatim, and the two ways to get it wrong are not
	// symmetric: under-declaring is safe, but OVER-declaring points the read at a
	// client-supplied entry, letting a client behind the proxy forge its own ipRange source.
	if hops := p.proxyHops(); hops > 1 {
		_, _ = fmt.Fprintf(p.errOut(),
			"[eunox] SECURITY: listen.trustedProxyHops is %d, so the client is read %d entries from the right "+
				"of X-Forwarded-For. This MUST equal the number of trusted proxies that append to the header in "+
				"front of eunox — declaring more than actually run lets a client behind them forge its own source "+
				"IP for ipRange conditions.\n",
			hops, hops,
		)
	}
}

// runAfterListen runs the post-bind startup hook under a bound, closing ln and returning an
// error if it cannot complete. Split out of Serve so the bound and its abandonment rules sit
// together in one readable unit.
//
// Between net.Listen returning and srv.Serve starting the accept loop, the kernel completes
// handshakes into the backlog for a socket no userspace is reading, so a request arriving in
// this window HANGS rather than being refused. The hook's slowest step (an fsync) has no
// upper bound, so it runs on its own goroutine and the select ABANDONS it on expiry — Go
// cannot interrupt a blocked fsync, so a synchronous call would not bound anything. Safe
// because WriteControlTokenFile re-checks the context immediately before its publishing
// rename: an abandoned write cannot land later and clobber a running proxy's token.
func (p *HTTPProxy) runAfterListen(ctx context.Context, ln net.Listener) error {
	if p.afterListen == nil {
		return nil
	}
	hook := p.afterListen
	// Drop the reference before running it, not after: Serve blocks for the life of the
	// process, so a hook that never returns would otherwise pin its closed-over state in the
	// heap forever.
	p.afterListen = nil

	budget := p.afterListenBudget
	if budget <= 0 {
		budget = afterListenTimeout
	}
	hookCtx, cancelHook := context.WithTimeout(ctx, budget)
	defer cancelHook()
	hookDone := make(chan error, 1) // buffered: an abandoned hook must never block on send
	go func() { hookDone <- hook(hookCtx) }()

	var hookErr error
	select {
	case hookErr = <-hookDone:
	case <-hookCtx.Done():
		hookErr = fmt.Errorf("post-bind startup did not complete within %s: %w", budget, hookCtx.Err())
	}
	if hookErr == nil {
		return nil
	}
	_ = ln.Close()
	// A hook cut short by SHUTDOWN is not a startup failure: Serve's ctx is cancelled by the
	// signal handler and hookCtx inherits that, so without this an operator stopping the
	// proxy during startup would get a fatal error on a clean shutdown. A genuine expiry
	// (ctx still live) still fails Serve — a proxy whose emergency stop can't be
	// authenticated should not come up.
	if ctx.Err() != nil {
		return nil
	}
	return hookErr
}

// Serve starts the HTTP server and blocks until ctx is canceled or a fatal
// error occurs.
func (p *HTTPProxy) Serve(ctx context.Context) error {
	// Hand the registration back on EVERY Serve return, listen/bind failure and post-bind
	// startup-hook failure included — not only the success path past srv.Serve. This
	// registration happened at CONSTRUCTION (NewHTTPProxyGateway), not here, specifically
	// so a kill delivered during startup is not lost; a Serve that never reaches its own
	// mid-function teardown (an early `return err` from net.Listen or runAfterListen, or
	// the ctx-already-canceled short-circuit below) must not leave the kill switch — which
	// OUTLIVES this proxy and may be handed to a second one — calling into a proxy that
	// will never serve anything. nil only for a struct-literal proxy, which registered
	// nothing.
	if p.unobserveRevocations != nil {
		defer p.unobserveRevocations()
	}

	// Publish the serve-lifetime context under p.mu so the concurrent reads in serveCtx are
	// synchronized. Happens before srv.Serve accepts any connection.
	p.mu.Lock()
	p.baseCtx = ctx
	p.mu.Unlock()

	mux := http.NewServeMux()
	// "/mcp" serves the single-upstream route (key ""); "/mcp/{upstream}" serves
	// named gateway routes. Both dispatch through handleMCP.
	mux.HandleFunc("/mcp", p.handleMCP)
	mux.HandleFunc("/mcp/{upstream}", p.handleMCP)
	mux.HandleFunc("/control/kill", p.handleKill)
	// Loopback-only operational endpoints (same guard as /control/kill).
	mux.HandleFunc("/healthz", p.handleHealth)
	mux.HandleFunc("/metrics", p.handleMetrics)
	// RFC 9728: serve the protected-resource metadata document at the well-known base path
	// and, in gateway mode, at each route's path-inserted variant. Track registered paths so
	// the path-bearing-resource registration below cannot double-register (mux.HandleFunc
	// panics on a duplicate).
	registeredMeta := map[string]struct{}{metadataBasePath: {}}
	mux.HandleFunc(metadataBasePath, p.serveOAuthMetadata)
	for name := range p.routes {
		if name != "" {
			path := metadataBasePath + "/mcp/" + name
			registeredMeta[path] = struct{}{}
			mux.HandleFunc(path, p.serveOAuthMetadata)
		}
	}
	// A path-bearing --oauth-resource: BuildOAuthMetadataURL inserts the resource path after
	// the well-known base (RFC 9728 §3.1), which every 401's WWW-Authenticate challenge
	// advertises — register it so a client following the challenge doesn't get a 404. Covers
	// gateway mode where the resource path is not one of the /mcp/<name> routes above. Skip
	// when already registered, since a duplicate mux.HandleFunc panics.
	if p.oauthMetaURL != "" {
		if suffix := oauthMetadataPathSuffix(p.oauthMetaURL); suffix != "" {
			path := metadataBasePath + suffix
			if _, dup := registeredMeta[path]; !dup {
				registeredMeta[path] = struct{}{}
				mux.HandleFunc(path, p.serveOAuthMetadata)
			}
		}
	}

	// net.JoinHostPort, not fmt.Sprintf("%s:%d"): an IPv6 literal must be bracketed before
	// ":port" or net.Listen rejects it — plain interpolation breaks every IPv6 bind.
	addr := net.JoinHostPort(p.bind, strconv.Itoa(p.port))
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", addr, err)
	}
	// Post-bind startup effects (see HTTPGatewayOptions.AfterListen). Runs only once the
	// address is actually held, so a proxy that loses the bind race leaves the running
	// instance's on-disk state alone.
	if err := p.runAfterListen(ctx, ln); err != nil {
		return err
	}
	// A shutdown that lands in the post-bind window ends startup here. Without this, srv.Serve
	// gets a listener that is closed or about to be, and its immediate "use of closed network
	// connection" races the ctx.Done() arm of the select below — select picks uniformly among
	// ready cases, so a graceful stop would surface a fatal error roughly half the time.
	if ctx.Err() != nil {
		_ = ln.Close()
		return nil
	}

	for name := range p.routes {
		path := "/mcp"
		if name != "" {
			path = "/mcp/" + name
		}
		_, _ = fmt.Fprintf(p.errOut(), "[eunox] HTTP proxy listening on http://%s%s\n", ln.Addr(), path)
	}

	p.warnForwardedForPosture()

	// A non-loopback bind with neither an auth token nor JWT leaves the enforced /mcp endpoint
	// open to any off-host client: checkAuth is a no-op without a token/JWKS, and the Origin
	// guard passes any request that simply omits the Origin header (any non-browser client can).
	if openNonLoopbackBind(p.bind, p.authToken, p.jwtPDP != nil) {
		_, _ = fmt.Fprintf(p.errOut(),
			"[eunox] SECURITY: proxy is bound to a non-loopback address (%q) with no listen.authToken and no --jwks-uri. "+
				"The enforced /mcp endpoint is reachable by any off-host client — the Origin check does not gate a "+
				"non-browser client that omits the Origin header. Configure listen.authToken (or --jwks-uri) and restrict "+
				"ingress with network controls.\n",
			p.bind,
		)
	}

	// SEC-03: read/write timeouts prevent Slowloris-style DoS. Long-lived SSE GET streams
	// re-arm a bounded per-chunk sseWriteTimeout instead of being bound by this fixed one.
	srv := &http.Server{
		// requireValidOrigin wraps every route so the DNS-rebinding Origin check
		// applies uniformly at one choke point — no handler can forget it.
		Handler:           p.requireValidOrigin(mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       httpReadTimeout,
		WriteTimeout:      httpWriteTimeout,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()

	// Idle-session reaper: close sessions whose host has gone silent so idle upstreams cannot
	// pin resources. Runs on a cancelable child of ctx so it stops on EVERY Serve return, not
	// only an external ctx cancel.
	reaperCtx, cancelReaper := context.WithCancel(ctx)
	defer cancelReaper()
	if p.sessionIdleMs > 0 {
		go p.reapIdleSessions(reaperCtx)
	}
	// Reclaim on a kill's own DELIVERY, on the same cancelable child. Deliberately NOT gated on
	// sessionIdleMs: the idle reaper's killed arm is the backstop, and it does not run at all
	// under sessionIdleTimeoutMs: 0, where a Redis-delivered kill would otherwise deny traffic
	// but reclaim nothing until the process exited.
	go p.reclaimOnRevocation(reaperCtx)

	// Teardown for EVERY Serve return path, as a single defer so no return arm can forget it.
	// Order: srv.Shutdown drains in-flight handlers FIRST (so a handler cannot complete
	// registerSession and leak a session AFTER closeAllSessions empties the registry), then
	// closeAllSessions reaps every live session. Fresh background context since ctx may
	// already be canceled.
	defer func() { //nolint:contextcheck // teardown path: closeAllSessions's upstream session-termination DELETE intentionally uses a detached, bounded background context — close/reaper/signal/shutdown carry no request context.
		// Evict open SSE GET streams FIRST. srv.Shutdown does not cancel in-flight request
		// contexts, and an SSE handler holds its response open indefinitely, so any connected
		// stream would otherwise pin srv.Shutdown for the full shutdownMs.
		p.evictAllSessionStreams()
		shutCtx, cancel := context.WithTimeout(context.Background(), msToDuration(p.shutdownMs))
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		p.closeAllSessions()
		// Release each route's shared upstream connection pool now that every session is torn
		// down — per-session close() no longer does this since the pool is shared.
		for _, rt := range p.routes {
			rt.closeIdleUpstreamConns()
		}
	}()

	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		return err
	}
}

// serveCtx returns the serve-lifetime context, falling back to context.Background() in
// tests that bypass Serve.
func (p *HTTPProxy) serveCtx() context.Context {
	// Read baseCtx under p.mu (RLock) to pair with the synchronized publish in Serve.
	// Callers must not hold p.mu (not reentrant).
	p.mu.RLock()
	ctx := p.baseCtx
	p.mu.RUnlock()
	if ctx != nil {
		return ctx
	}
	return context.Background()
}

// routeNoticeWriter is the diagnostic channel for a leg serving route: the configured stderr writer
// and the route's OWN class table, which charges this proxy's aggregate as its parent (see
// newRouteNoticeLimiter) — one tenant's flood must not silence another's, which is the whole reason
// that table exists.
//
// ONE accessor taking a nilable route rather than a route-less twin beside it: every HTTP leg that
// writes a diagnostic has its route in hand, so a second spelling had no caller left once they were
// all converted, and the pair could only drift. A nil route (a leg that genuinely has none) falls
// back to the aggregate directly, and a nil receiver to an unbounded channel, which is what a proxy
// assembled by a bare struct literal in a test gets.
func (p *HTTPProxy) routeNoticeWriter(route *UpstreamRoute) noticeWriter {
	if p == nil {
		return noticeWriter{}
	}
	if route == nil || route.notices == nil {
		// No collapse windows on this arm, deliberately: the faults they collapse are a route's own
		// (its upstream's receipt pin, its policy engine's flow store), and a leg with no route has
		// no source to attribute one to. Nothing on this arm writes a collapsed line.
		return noticeWriter{out: p.errOut(), limits: p.notices}
	}
	return noticeWriter{out: p.errOut(), limits: route.notices, collapse: route.noticeCollapse}
}

// sessionNoticeWriter is routeNoticeWriter for a leg holding the SESSION: the same route table,
// plus that session's reserved floor under it (see noticeReserve).
//
// One accessor taking a nilable session rather than the reserve being attached wherever a session
// happens to be in scope: which floor a line may fall back on is a property of the leg's wiring,
// and a leg that has a session but resolves its channel from the route alone loses the floor
// silently. A nil session is a pre-session leg — it has no floor and needs none, since a refusal
// taken before a session exists is attributable to no session.
//
// A session's table comes from the SESSION's own route, not from the caller's, so the pair cannot
// be mismatched: reserving against one tenant's floor while charging another's bucket is a fault
// nothing downstream could detect, and taking two arguments is what would make it expressible.
// route is consulted only for a leg that has no session to ask.
func (p *HTTPProxy) sessionNoticeWriter(sess *httpSession, route *UpstreamRoute) noticeWriter {
	if sess == nil {
		return p.routeNoticeWriter(route)
	}
	w := p.routeNoticeWriter(sess.route)
	w.reserve = sess.noticeFloor
	return w
}

// routeRefusalLimits pairs this proxy's two admission controls for a leg serving route: the
// proxy-wide category buckets its refusal RECORDS charge, and that route's own diagnostic table.
// The leg that meters no record (routeRefusalRecorders) takes the notice channel alone, and an
// established session's upstream-driven refusals charge its own per-session table instead (see
// newUpstreamRefusalLimiter).
//
// Nilable route for the reason routeNoticeWriter takes one, and nilable session for the reason
// sessionNoticeWriter does: a leg that has one names it, so the per-session floor is not lost by a
// leg resolving its channel from the route alone.
func (p *HTTPProxy) routeRefusalLimits(sess *httpSession, route *UpstreamRoute) refusalLimits {
	if p == nil {
		return refusalLimits{}
	}
	return refusalLimits{records: p.preSessionDenies, notices: p.sessionNoticeWriter(sess, route)}
}
