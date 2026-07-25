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
	"math"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
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

	// httpWriteTimeout is a Slowloris backstop, not the response budget: the POST
	// path extends it per-request to the upstream budget + writeSlack (or clears it
	// when the budget is disabled), and the SSE path re-arms a bounded per-chunk
	// sseWriteTimeout around every frame (handleMCPGet) — a long-lived stream must
	// outlive any single-call budget, but one write must still never block forever.
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

// msToDuration converts milliseconds to a time.Duration, saturating at
// math.MaxInt64 (~292 years) instead of overflowing. Without this, ms*time.Millisecond
// wraps past config.MaxDurationMs into a negative/tiny value that would expire calls
// instantly and make the idle reaper treat every session as already stale. Callers
// guard ms <= 0 ("disabled") before calling.
func msToDuration(ms int) time.Duration {
	if int64(ms) > config.MaxDurationMs {
		return time.Duration(math.MaxInt64)
	}
	return time.Duration(ms) * time.Millisecond
}

// addSlack adds writeSlack to d, saturating at math.MaxInt64 instead of overflowing.
// msToDuration saturates the ms->Duration conversion, but at the documented-max
// upstream timeout (config.MaxDurationMs) the in-range product sits within a few
// hundred microseconds of math.MaxInt64, so a bare `d + writeSlack` would wrap to a
// large negative value — a write deadline in the PAST that fails every response write.
// d is assumed non-negative (it comes from msToDuration or a positive constant budget).
func addSlack(d time.Duration) time.Duration {
	if d > time.Duration(math.MaxInt64)-writeSlack {
		return time.Duration(math.MaxInt64)
	}
	return d + writeSlack
}

// ResolveMaxSessions folds the --max-sessions flag and the config's
// listen.maxSessions into the effective concurrent-session cap.
//
// A present config value wins, including 0 (unlimited): cfgVal is a pointer, so a
// present key overrides the flag while an absent key (nil) leaves the flag's value
// in force. This keeps "0 = unlimited" expressible from config. Delegates to the
// shared config.ResolveInt pointer-override resolver.
func ResolveMaxSessions(flagVal int, cfgVal *int) int {
	return config.ResolveInt(cfgVal, flagVal)
}

// ResolveSessionIdleTimeout folds the --session-idle-timeout flag and the config's
// listen.sessionIdleTimeoutMs into the effective idle-reap window (milliseconds).
//
// A present config value wins, including 0 (no idle reaping): cfgVal is a pointer, so a
// present key overrides the flag while an absent key (nil) leaves the flag's value in
// force. This keeps "0 = no idle reaping" expressible from config even when the flag is
// non-zero. Mirrors ResolveMaxSessions; both delegate to config.ResolveInt.
func ResolveSessionIdleTimeout(flagVal int, cfgVal *int) int {
	return config.ResolveInt(cfgVal, flagVal)
}

// HTTPProxy implements the MCP Streamable HTTP transport.
// Each client session gets its own upstream subprocess (local mode) or connects
// to a remote MCP HTTP server (remote mode, enabled by UpstreamURL).
type HTTPProxy struct {
	jwtPDP             *pdp.JWTPDP            // non-nil when --jwks-uri is configured
	oauthMeta          *OAuthResourceMetadata // non-nil when JWT auth is configured
	oauthMetaURL       string                 // absolute metadata URL for WWW-Authenticate; empty when --oauth-resource is not set
	sink               *audit.Sink
	ks                 killswitch.Manager
	shutdownMs         int
	upstreamTimeMs     int
	requireAuditStrict bool // --require-audit=strict: deny forwards once the audit trail degrades
	// strictAuditWarned makes the sticky strict-gate stderr warning one-shot; the
	// durable per-call signal is the AUDIT_UNAVAILABLE audit record.
	strictAuditWarned atomic.Bool
	authToken         string
	// controlToken authenticates POST /control/kill (loopback only). Generated at
	// startup so the emergency-stop endpoint is never reachable by a same-host
	// process merely because it is on loopback (SEC-07). Empty ⟹ refuse all requests
	// (fail closed).
	controlToken string
	// authTimingKey is a per-process random HMAC key folding presented/expected
	// tokens to a fixed-length MAC before the constant-time comparison in checkAuth /
	// checkControlToken. See constantTimeTokenEqual for the timing rationale.
	authTimingKey []byte
	trustFwdFor   bool
	// trustedProxyNets is the compiled listen.trustedProxyCIDRs allowlist: under
	// trustFwdFor, the immediate TCP peer (RemoteAddr) must match one of these
	// networks before X-Forwarded-For is honored — see sourceIP. Empty means no peer
	// can ever match, so trustFwdFor alone has no effect until CIDRs are configured.
	trustedProxyNets []*net.IPNet
	// trustedProxyHops is listen.trustedProxyHops: the number of trusted proxies in
	// front of eunox, and so how many right-most X-Forwarded-For entries are
	// proxy-written. 0 means unset; sourceIP reads it through proxyHops, which supplies
	// the single-proxy default, so the zero value is the common production case rather
	// than an invalid one.
	trustedProxyHops int
	bind             string
	port             int

	// maxSessions caps concurrent sessions (0 = unlimited); sessionIdleMs reaps
	// sessions idle for that many milliseconds (0 = no reaping). Both bound the
	// otherwise-unbounded subprocess-per-session resource footprint.
	maxSessions   int
	sessionIdleMs int

	// DNS-rebinding defense (see checkOrigin): allowedOrigins holds operator-configured
	// full origins matched exactly; allowedOriginHosts is the set of host names always
	// accepted (loopback names plus the non-wildcard bind host).
	allowedOrigins     []string
	allowedOriginHosts map[string]bool

	// routes maps a route name (the /mcp/<name> path segment) to its upstream wiring
	// and enforcement state. Single-upstream mode keys one route by "" (served at
	// /mcp); gateway mode holds one route per upstream.
	routes map[string]*UpstreamRoute

	// baseCtx is the serve-lifetime context. Session reader goroutines outlive the
	// HTTP request that created the session, so they inherit this — not the request's
	// context — for kill-switch lookups on the upstream-initiated path. Guarded by
	// p.mu: Serve writes it once at startup while handler goroutines (via serveCtx)
	// read it concurrently, so the publish must be synchronized (a plain
	// interface-field write/read is a data race under -race, and a torn read could
	// surface a nil context to a downstream ctx.Done()). serveCtx must never be called
	// while already holding p.mu (p.mu is not reentrant); today its sole caller,
	// newSession, evaluates it after registerSession has released the lock.
	baseCtx context.Context

	// mu guards sessions, baseCtx, and shuttingDown. An RWMutex so the read-only
	// per-request paths (getSession, sessionCount, serveCtx) take RLock and run
	// concurrently with each other and the reaper instead of serializing on an
	// exclusive lock; the check-then-write paths (registerSession's cap check-then-
	// insert, handleMCPDelete, closeAllSessions, the remote cleanup delete) keep Lock.
	mu       sync.RWMutex
	sessions map[string]*httpSession
	// shuttingDown is set under mu at the start of closeAllSessions so a slow
	// in-flight initialize whose registerSession lands AFTER the registry is emptied
	// fails closed instead of leaking its upstream subprocess + goroutines into a map
	// nothing will ever reap. See registerSession.
	shuttingDown bool
	// reapGen is incremented under mu by reapAllKilledSessions each time it sweeps the
	// registry. newSession/newRemoteSession capture the generation in force when they
	// begin (currentReapGen), and registerSession rejects the insert if the generation
	// has since advanced — closing the race where a session-creating initialize that
	// started before a global kill finishes its (possibly slow) handshake and would
	// otherwise register into the fresh map AFTER the sweep, leaking an undead upstream
	// and its maxSessions slot. Unlike shuttingDown this is not a permanent latch: the
	// registry keeps serving new registrations (e.g. once the kill is later cleared),
	// so a raced registration is simply rejected (the caller retries) rather than the
	// registry being closed forever. See reapAllKilledSessions and registerSession.
	reapGen uint64
}

// HTTPGatewayOptions configures a multi-upstream gateway HTTPProxy: one process
// fronting N upstreams, one per route, sharing a single audit sink and
// kill-switch. Routes are built by BuildRoutes from a gateway config.
type HTTPGatewayOptions struct {
	Routes         map[string]*UpstreamRoute
	Sink           *audit.Sink
	KS             killswitch.Manager
	JWTPDP         *pdp.JWTPDP
	OAuthMeta      *OAuthResourceMetadata // RFC 9728 metadata document; nil when JWT auth is not configured
	OAuthMetaURL   string                 // absolute URL for resource_metadata in challenges
	ShutdownMs     int
	UpstreamTimeMs int
	AuthToken      string
	// ControlToken authenticates POST /control/kill (loopback only). Generated at
	// startup by the proxy command; required independently of AuthToken/JWT mode.
	ControlToken string
	TrustFwdFor  bool
	// TrustedProxyCIDRs is listen.trustedProxyCIDRs: the reverse-proxy peer addresses
	// trusted to set X-Forwarded-For under TrustFwdFor. Entries must already be valid
	// CIDRs (GatewayConfig.Validate parses and rejects malformed ones at config load);
	// an entry that still fails to parse here is skipped (never trusted) and logged,
	// rather than silently narrowing the allowlist.
	TrustedProxyCIDRs []string
	// TrustedProxyHops is listen.trustedProxyHops: how many trusted proxies sit in
	// front of eunox, i.e. how many right-most X-Forwarded-For entries were written by
	// trusted hops. 0 (unset) is normalized to 1. See sourceIP.
	TrustedProxyHops int
	Bind             string
	Port             int

	// RequireAuditStrict is the --require-audit=strict gate: deny enforced forwards
	// (and */list enumeration) fail-closed once the shared audit trail degrades.
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
func NewHTTPProxyGateway(opts HTTPGatewayOptions) *HTTPProxy {
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
	var trustedProxyNets []*net.IPNet
	for _, cidr := range opts.TrustedProxyCIDRs {
		if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
			trustedProxyNets = append(trustedProxyNets, ipNet)
		} else {
			// GatewayConfig.Validate rejects a malformed entry before the CLI ever
			// reaches here, so this should be unreachable on that path — but
			// NewHTTPProxyGateway is an exported constructor a caller could invoke
			// directly with an unvalidated list, so warn rather than silently trust
			// fewer peers than configured.
			fmt.Fprintf(os.Stderr, "[eunox] WARNING: listen.trustedProxyCIDRs entry %q is not a valid CIDR and will never be trusted: %v\n", cidr, err)
		}
	}
	return &HTTPProxy{
		jwtPDP:             opts.JWTPDP,
		oauthMeta:          opts.OAuthMeta,
		oauthMetaURL:       opts.OAuthMetaURL,
		sink:               opts.Sink,
		ks:                 opts.KS,
		shutdownMs:         opts.ShutdownMs,
		upstreamTimeMs:     opts.UpstreamTimeMs,
		requireAuditStrict: opts.RequireAuditStrict,
		authToken:          opts.AuthToken,
		controlToken:       opts.ControlToken,
		authTimingKey:      newAuthTimingKey(),
		trustFwdFor:        opts.TrustFwdFor,
		trustedProxyNets:   trustedProxyNets,
		trustedProxyHops:   opts.TrustedProxyHops,
		bind:               opts.Bind,
		port:               opts.Port,
		maxSessions:        opts.MaxSessions,
		sessionIdleMs:      opts.SessionIdleMs,
		allowedOrigins:     opts.AllowedOrigins,
		allowedOriginHosts: buildAllowedOriginHosts(opts.Bind),
		routes:             opts.Routes,
		sessions:           make(map[string]*httpSession),
	}
}

// Serve starts the HTTP server and blocks until ctx is canceled or a fatal
// error occurs.
func (p *HTTPProxy) Serve(ctx context.Context) error {
	// Publish the serve-lifetime context under p.mu so the concurrent reads in
	// serveCtx (from session reader goroutines) are synchronized. The write happens
	// before srv.Serve accepts any connection, so no handler can observe the zero value.
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
	// RFC 9728: serve the protected-resource metadata document at the well-known
	// base path and, in gateway mode, at the per-route path-inserted variant for
	// each route. All paths serve the same global document. Track every registered
	// metadata path so the path-bearing-resource registration below cannot
	// double-register one (a duplicate mux.HandleFunc panics).
	registeredMeta := map[string]struct{}{metadataBasePath: {}}
	mux.HandleFunc(metadataBasePath, p.serveOAuthMetadata)
	for name := range p.routes {
		if name != "" {
			path := metadataBasePath + "/mcp/" + name
			registeredMeta[path] = struct{}{}
			mux.HandleFunc(path, p.serveOAuthMetadata)
		}
	}
	// A path-bearing --oauth-resource: BuildOAuthMetadataURL inserts the resource path
	// after the well-known base (RFC 9728 §3.1), and that inserted path is what every
	// 401's WWW-Authenticate challenge advertises. Register it so a client following the
	// challenge does not get a 404. This covers BOTH single-upstream mode (the "" route)
	// AND gateway mode where the resource path is not one of the /mcp/<name> routes
	// registered above — the gateway loop only enumerates route names, so without this a
	// path-bearing resource that is not a route path advertises an unserved URL. Skip
	// when the suffix is empty (the base path is already registered) or already
	// registered as a route path, since a duplicate mux.HandleFunc panics. The suffix is
	// derived from the served URL so it stays in lockstep with what is advertised.
	if p.oauthMetaURL != "" {
		if suffix := oauthMetadataPathSuffix(p.oauthMetaURL); suffix != "" {
			path := metadataBasePath + suffix
			if _, dup := registeredMeta[path]; !dup {
				registeredMeta[path] = struct{}{}
				mux.HandleFunc(path, p.serveOAuthMetadata)
			}
		}
	}

	// net.JoinHostPort, not fmt.Sprintf("%s:%d"): an IPv6 literal must be bracketed
	// before ":port" or net.Listen rejects it ("too many colons in address"). Plain
	// interpolation breaks every IPv6 bind, including the explicitly-supported
	// bind-all "::" (which would become ":::<port>").
	addr := net.JoinHostPort(p.bind, strconv.Itoa(p.port))
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", addr, err)
	}
	for name := range p.routes {
		path := "/mcp"
		if name != "" {
			path = "/mcp/" + name
		}
		fmt.Fprintf(os.Stderr, "[eunox] HTTP proxy listening on http://%s%s\n", ln.Addr(), path)
	}

	// --trust-forwarded-for only honors X-Forwarded-For from a peer whose RemoteAddr
	// matches listen.trustedProxyCIDRs (see sourceIP); a request from any other peer
	// falls back to its own RemoteAddr, so a client that connects directly can no
	// longer spoof an ipRange source purely by setting the header. Still warn: an
	// empty allowlist makes the flag a no-op, and even a configured allowlist is only
	// as strong as how tightly it is scoped to the real reverse proxy's address.
	if p.trustFwdFor {
		if len(p.trustedProxyNets) == 0 {
			fmt.Fprintf(os.Stderr,
				"[eunox] SECURITY: --trust-forwarded-for is enabled but listen.trustedProxyCIDRs is empty, "+
					"so no peer can ever match — X-Forwarded-For is never trusted and every request's source IP "+
					"is its own connection address. Set listen.trustedProxyCIDRs to the reverse proxy's address(es) "+
					"to enable X-Forwarded-For trust.\n",
			)
		} else if !bindIsLoopbackOnly(p.bind) {
			fmt.Fprintf(os.Stderr,
				"[eunox] SECURITY: --trust-forwarded-for is enabled on a non-loopback bind (%q). "+
					"X-Forwarded-For is honored only from a peer matching listen.trustedProxyCIDRs; "+
					"scope that allowlist tightly to the real reverse proxy's address; a broader range "+
					"(e.g. a shared or NATed subnet) would let another host on it spoof an ipRange source.\n",
				p.bind,
			)
		}
	}

	// A non-loopback bind with neither an auth token nor JWT leaves the enforced /mcp
	// endpoint open to any off-host client: checkAuth is a no-op without a token/JWKS,
	// and the Origin guard passes any request that simply omits the Origin header (which
	// any non-browser client can). Surface this open posture the same way the other
	// open-posture warnings are, so an operator pairs a non-loopback bind with auth and
	// network controls deliberately rather than by omission.
	if openNonLoopbackBind(p.bind, p.authToken, p.jwtPDP != nil) {
		fmt.Fprintf(os.Stderr,
			"[eunox] SECURITY: proxy is bound to a non-loopback address (%q) with no listen.authToken and no --jwks-uri. "+
				"The enforced /mcp endpoint is reachable by any off-host client — the Origin check does not gate a "+
				"non-browser client that omits the Origin header. Configure listen.authToken (or --jwks-uri) and restrict "+
				"ingress with network controls.\n",
			p.bind,
		)
	}

	// SEC-03: read/write timeouts prevent Slowloris-style DoS from slow clients.
	// Long-lived SSE GET streams (handleMCPGet) re-arm a bounded per-chunk
	// sseWriteTimeout per frame instead of being bound by this fixed WriteTimeout.
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

	// Idle-session reaper: close sessions whose host has gone silent so idle
	// upstreams cannot pin resources. Disabled when sessionIdleMs is 0. It runs on a
	// cancelable child of ctx so it stops on EVERY Serve return — a srv.Serve error,
	// not only an external ctx cancel — rather than being stranded against a dead server.
	reaperCtx, cancelReaper := context.WithCancel(ctx)
	defer cancelReaper()
	if p.sessionIdleMs > 0 {
		go p.reapIdleSessions(reaperCtx)
	}

	// Teardown for EVERY Serve return path — a graceful ctx cancel OR a srv.Serve
	// error (listener failure) — as a single defer so no return arm can forget it
	// (the leak this replaces was exactly an error arm that skipped the reap). Order
	// on return: srv.Shutdown drains in-flight handlers FIRST — it waits for active
	// requests, so a handler cannot complete registerSession and leak a session AFTER
	// closeAllSessions empties the registry — then closeAllSessions reaps every live
	// session's upstream subprocess/connection. cancelReaper (deferred above, so it
	// runs last) then stops the reaper. A fresh background context is required because
	// ctx may already be canceled.
	defer func() { //nolint:contextcheck // teardown path: closeAllSessions's upstream session-termination DELETE intentionally uses a detached, bounded background context — close/reaper/signal/shutdown carry no request context.
		// Evict open SSE GET streams FIRST. srv.Shutdown does not cancel in-flight
		// request contexts, and an SSE handler holds its response open indefinitely
		// (it selects on the subscriber channel, keepalive, evicted, done, and the
		// request context — none of which Shutdown fires), so any connected stream would
		// otherwise pin srv.Shutdown for the full shutdownMs. Closing the evicted signal
		// wakes every handleMCPGet loop so it returns, letting Shutdown drain promptly.
		p.evictAllSessionStreams()
		shutCtx, cancel := context.WithTimeout(context.Background(), msToDuration(p.shutdownMs))
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		p.closeAllSessions()
		// Release each route's shared upstream connection pool now that every session is
		// torn down — per-session close() no longer does this (the pool is shared), so the
		// wholesale release happens once here at shutdown.
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

// serveCtx returns the serve-lifetime context, falling back to
// context.Background() in tests that bypass Serve.
func (p *HTTPProxy) serveCtx() context.Context {
	// Read baseCtx under p.mu (RLock — read-only) to pair with the synchronized publish
	// in Serve. Callers must not hold p.mu (it is not reentrant); newSession calls this
	// only after registerSession has released the lock.
	p.mu.RLock()
	ctx := p.baseCtx
	p.mu.RUnlock()
	if ctx != nil {
		return ctx
	}
	return context.Background()
}
