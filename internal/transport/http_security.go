// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// HTTP transport security middleware: bearer / control-token auth, Origin
// (DNS-rebinding) validation, source-IP extraction, and loopback gating.

package transport

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/eunolabs/eunox/pkg/capability"
)

// newAuthTimingKey returns a 32-byte per-process random key for the MAC folding in
// constantTimeTokenEqual. crypto/rand failure is fatal: without an unpredictable key
// the timing protection degrades to a precomputable fixed-key MAC, so refuse to start.
func newAuthTimingKey() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(fmt.Sprintf("eunox: cannot generate auth timing key: %v", err))
	}
	return key
}

// constantTimeTokenEqual reports whether presented equals want without leaking
// either operand's length through timing. ConstantTimeCompare (via hmac.Equal)
// returns early in non-constant time when its inputs differ in length, so comparing
// raw tokens would let an attacker binary-search the secret's length by timing 401s.
// Folding both sides to a fixed-length keyed MAC first guarantees equal-length inputs,
// and the per-process random key makes the MACs unpredictable so candidates cannot be
// precomputed. Both MACs are computed per call so a struct-literal-constructed proxy
// stays valid.
func constantTimeTokenEqual(key []byte, presented, want string) bool {
	pm := hmac.New(sha256.New, key)
	pm.Write([]byte(presented))
	wm := hmac.New(sha256.New, key)
	wm.Write([]byte(want))
	return hmac.Equal(pm.Sum(nil), wm.Sum(nil))
}

// checkAuth validates the Authorization header when an auth token is configured.
// Returns true if the request is authorized; false if not (response already written).
//
// The constant-time comparison prevents timing side-channel attacks where an
// attacker can deduce the token byte-by-byte by measuring response latency.
func (p *HTTPProxy) checkAuth(w http.ResponseWriter, r *http.Request) bool {
	if p.authToken == "" {
		return true
	}
	auth := r.Header.Get("Authorization")
	credPresented := auth != ""
	// RFC 7235 §2.1: the auth-scheme is case-insensitive, so match "Bearer "
	// case-insensitively (mirroring JWTPDP.ValidateToken). The token comparison stays
	// constant-time and case-sensitive.
	const prefix = "Bearer "
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) ||
		!constantTimeTokenEqual(p.authTimingKey, auth[len(prefix):], p.authToken) {
		// Record the refusal so an off-host bearer-token brute-force leaves a trace on the
		// tamper-evident tape, mirroring the ORIGIN_REJECTED / JWT_INVALID pre-session
		// records. recordPreSessionDeny never records the presented credential — only the
		// source and the unverified claimed session id — and keeps session_id empty.
		p.recordPreSessionDeny(r, codeAuthFailed, "auth", map[string]interface{}{"source_ip": p.sourceIP(r)})
		w.Header().Set("WWW-Authenticate", buildWWWAuthenticate(credPresented, p.oauthMetaURL))
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

// checkControlToken authorizes a POST /control/kill request against the loopback
// control token (header ControlTokenHeader) via constant-time comparison. Returns
// true if authorized; writes the response and returns false otherwise.
//
// Unlike checkAuth, the control token is generated at startup and ALWAYS required
// (SEC-07): a same-host process must not trigger the emergency stop merely by
// reaching the loopback endpoint. An empty controlToken refuses every request (fail
// closed) rather than reverting to no-auth.
func (p *HTTPProxy) checkControlToken(w http.ResponseWriter, r *http.Request) bool {
	if p.controlToken == "" {
		http.Error(w, "control endpoint not configured", http.StatusServiceUnavailable)
		return false
	}
	presented := r.Header.Get(ControlTokenHeader)
	if presented == "" || !constantTimeTokenEqual(p.authTimingKey, presented, p.controlToken) {
		// Record the refusal: /control/kill is the emergency-stop endpoint (SEC-07), so a
		// same-host process probing it with a wrong/missing token is exactly the threat the
		// token defends, and must not be invisible on the tape. recordPreSessionDeny never
		// records the presented token — only the source and the unverified claimed session id.
		p.recordPreSessionDeny(r, codeControlAuthFailed, "control", map[string]interface{}{"source_ip": p.sourceIP(r)})
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

// buildAllowedOriginHosts returns the set of host names whose Origin is always
// accepted: the loopback names plus the configured bind host (unless it is a
// wildcard, which is not a meaningful Origin host). Hosts are lower-cased so the
// lookup in originAllowed is case-insensitive.
func buildAllowedOriginHosts(bind string) map[string]bool {
	hosts := map[string]bool{
		"localhost": true,
		"127.0.0.1": true,
		"::1":       true,
	}
	// Strip the surrounding brackets from a bracketed IPv6 bind literal so the key
	// matches url.Hostname() (which returns the host without brackets); otherwise a
	// legitimate IPv6 Origin is rejected. On a valid bind literal the brackets are a
	// matched pair ("[::1]"), so trimming the "[]" set strips exactly the wrapper.
	b := strings.ToLower(strings.TrimSpace(bind))
	b = strings.Trim(b, "[]")
	// Exclude every spelling of the unspecified (all-interfaces) address — "0.0.0.0",
	// "::", "::0", "0:0:0:0:0:0:0:0" — via IsUnspecified() rather than a brittle
	// string match, so an alternate wildcard spelling is not added to the
	// DNS-rebinding Origin allowlist. A non-wildcard bind host is added as before.
	if b != "" {
		if ip := net.ParseIP(b); ip == nil || !ip.IsUnspecified() {
			hosts[b] = true
		}
	}
	return hosts
}

// requireValidOrigin wraps next so that every request passes the Origin check
// before reaching a handler. A rejected request never reaches next.
func (p *HTTPProxy) requireValidOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !p.checkOrigin(w, r) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

// checkOrigin enforces the MCP Streamable HTTP Origin check that prevents
// DNS-rebinding: without it a same-machine browser tab can use a rebound DNS name to
// reach the loopback listener. Only a truly absent Origin passes unconditionally
// (non-browser hosts send none; browsers always attach Origin to the cross-site
// requests rebinding exploits). Any present value — including "" and the opaque "null"
// origin — must satisfy originAllowed or the request is rejected with 403. More than
// one Origin header (forbidden by RFC 6454 §7.1; a header-smuggling vector) is rejected
// outright. Returns true if the request may proceed; on rejection the response is written.
func (p *HTTPProxy) checkOrigin(w http.ResponseWriter, r *http.Request) bool {
	// Distinguish an absent header from a present-but-empty value: Header.Get collapses
	// both to "", but only a missing header passes freely.
	vals := r.Header.Values("Origin")
	if len(vals) == 0 {
		return true
	}
	// RFC 6454 §7.1 permits at most one Origin header. Multiple headers let a client
	// that can set arbitrary headers smuggle an allowed origin alongside a disallowed
	// one, validating only the first while the host may act on another. Reject outright
	// when more than one is present.
	multiple := len(vals) > 1
	origin := vals[0]
	if !multiple && p.originAllowed(origin) {
		return true
	}
	// Record every value when several were sent so the smuggled header leaves a trace.
	recordedOrigin := origin
	if multiple {
		recordedOrigin = strings.Join(vals, ", ")
	}
	p.recordPreSessionDeny(r, "ORIGIN_REJECTED", "origin", map[string]interface{}{"origin": recordedOrigin})
	if multiple {
		fmt.Fprintf(os.Stderr,
			"[eunox] SECURITY: rejected request carrying %d Origin headers (%q); RFC 6454 permits only one (DNS-rebinding guard)\n",
			len(vals), recordedOrigin,
		)
	} else {
		fmt.Fprintf(os.Stderr,
			"[eunox] SECURITY: rejected request with disallowed Origin %q (DNS-rebinding guard)\n",
			origin,
		)
	}
	http.Error(w, "Forbidden: Origin not allowed", http.StatusForbidden)
	return false
}

// addClaimedSessionID records the client-supplied Mcp-Session-Id header into a
// pre-session deny's details under claimed_session_id, never as the structured
// session_id. The transport-level denials that use it (origin rejection, JWT
// rejection) fire BEFORE any session lookup, so the header is unverified and
// attacker-controlled; stamping it as session_id would let an unauthenticated caller
// forge those records against a victim's session. The claimed value is kept as a
// clearly-unverified detail for correlation, and only when present so a missing
// header leaves no empty key. Centralizing the rule keeps every pre-session deny
// path consistent — a new one cannot reintroduce the forgery by hand-rolling it.
func addClaimedSessionID(details map[string]interface{}, r *http.Request) map[string]interface{} {
	if claimed := r.Header.Get(SessionHeader); claimed != "" {
		details["claimed_session_id"] = claimed
	}
	return details
}

// recordPreSessionDeny writes a transport-level deny that fires BEFORE any session
// lookup — a rejected Origin, JWT, static bearer, or control token. It centralizes the
// forgery guard those four share: the structured session_id is left EMPTY (at this point
// the client-supplied Mcp-Session-Id is unverified and attacker-controlled, so stamping
// it as session_id would let anyone forge these records against a victim's session),
// while the claimed value is preserved as the clearly-unverified details.claimed_session_id
// via addClaimedSessionID. The presented credential is NEVER passed in — callers supply
// only non-secret context (source_ip, origin, error_type) in extra. A nil sink skips the
// record. Folding the four sites here keeps the empty-session_id rule from being
// re-hand-rolled — and re-broken — at each new pre-session refusal path.
func (p *HTTPProxy) recordPreSessionDeny(r *http.Request, code, category string, extra map[string]interface{}) {
	if p.sink == nil {
		return
	}
	p.sink.RecordDeny(r.Context(), "", "", "", code, category, addClaimedSessionID(extra, r), false)
}

// originAllowed reports whether a present Origin value is permitted. The origin must
// match a configured allowlist entry exactly (case-insensitively), or its host must be
// a loopback name or the bind host. Nothing is implicit: "null" and an empty value are
// accepted only if listed in listen.allowedOrigins. An unparseable or hostless Origin
// fails closed.
//
// Deliberate port asymmetry: allowedOrigins entries match exactly (scheme + port),
// while the host-set path matches hostname only and accepts ANY port on a loopback or
// bind host. DNS rebinding is host-based, not port-based, and any local port on a
// loopback host is equally local; operators who must pin a port list the exact origin.
func (p *HTTPProxy) originAllowed(origin string) bool {
	for _, a := range p.allowedOrigins {
		if strings.EqualFold(origin, a) {
			return true
		}
	}
	// A valid RFC 6454 web origin (scheme "://" host[:port]) has no query component, so
	// any '?' is malformed. Reject it before parsing: url.Parse consumes a trailing bare
	// '?' as an empty query delimiter, leaving u.RawQuery == "" so the structural guard
	// below would not catch "http://localhost?". This pre-parse check closes that gap.
	if strings.Contains(origin, "?") {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil {
		// url.Parse returns a nil *URL on error, so this must short-circuit before
		// any field of u is read below.
		return false
	}
	// A valid Origin is exactly scheme://host[:port] (RFC 6454 §6.1). url.Parse
	// retains the scheme, userinfo, fragment, query, and path as struct fields
	// rather than stripping them, so each is checked explicitly. The host-set path
	// admits only the http(s) web-origin schemes (case-folded): without the scheme
	// check a non-web scheme ("file://localhost") or a scheme-relative reference
	// ("//localhost", empty scheme) would still yield a trusted u.Hostname() and
	// slip past the guard, and without the userinfo/fragment checks
	// "http://evil@localhost" or "http://localhost#@evil.com" would too. A trailing
	// "/" path ("http://localhost/") is accepted: some browsers include it and it
	// carries no injection risk. Opaque "null"/"file://…" front-ends opt in
	// explicitly through the exact-match allowedOrigins loop above.
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "http" && scheme != "https") || u.Host == "" || u.User != nil ||
		u.Fragment != "" || u.RawQuery != "" || (u.Path != "" && u.Path != "/") {
		return false
	}
	return p.allowedOriginHosts[strings.ToLower(u.Hostname())]
}

// sourceIP extracts the client IP address for PDP evaluation.
//
// Under --trust-forwarded-for the proxy trusts X-Forwarded-For — but only when the
// immediate peer (RemoteAddr) itself matches listen.trustedProxyCIDRs. Without this
// check, --trust-forwarded-for alone would trust the header from ANY directly-connecting
// client, letting it spoof an ipRange source; requiring the peer to be a configured
// trusted hop closes that gap.
//
// The client is resolved by COUNTING hops, not by inspecting addresses. With N trusted
// proxies in front (listen.trustedProxyHops, default 1), each hop appends the address it
// saw — client → p1 → p2 → eunox yields [client, p1] — so the right-most N entries are
// exactly the ones trusted proxies wrote and the client's real address is the N-th from
// the right. Everything further left is client-supplied and ignored, so a client cannot
// spoof an ipRange source by prepending forged hops.
//
// The count is declared rather than inferred by testing each entry against
// trustedProxyCIDRs. Inference cannot distinguish a proxy hop from a client whose OWN
// address falls inside that range — a plausible internal deployment where clients and
// proxies share a private supernet — and would then skip the client's real (proxy-
// written) entry and return a forged one to its left, exactly the spoof the peer gate
// exists to prevent.
//
// A chain that carries entries but FEWER than N does not match the declared topology, so
// no entry is provably proxy-written. Falling back to RemoteAddr there would be a silent
// fail-OPEN: the enclosing branch has already established the peer is a trusted proxy, so
// RemoteAddr is by construction inside listen.trustedProxyCIDRs, and an ipRange condition
// allowing the internal supernet those proxies sit in would then match every request
// regardless of its real client. Such a request instead yields an empty source IP, which
// an ipRange condition denies with MISSING_CONTEXT — the mismatch is loud rather than
// permissive. A header that carries no entries at all is treated as "no XFF" and uses
// RemoteAddr, exactly as a request without the header does.
func (p *HTTPProxy) sourceIP(r *http.Request) string {
	if p.trustFwdFor && p.peerIsTrustedProxy(r.RemoteAddr) {
		// Flatten ALL X-Forwarded-For lines, not just the first: an intermediary that
		// adds its own line would otherwise let an attacker-controlled first line shadow
		// the trusted right-most hop.
		if vals := r.Header.Values("X-Forwarded-For"); len(vals) > 0 {
			var all []string
			for _, v := range vals {
				for _, part := range strings.Split(v, ",") {
					if part = strings.TrimSpace(part); part != "" {
						all = append(all, part)
					}
				}
			}
			if len(all) > 0 {
				// proxyHops() is always >= 1, so idx is at most len(all)-1.
				idx := len(all) - p.proxyHops()
				if idx < 0 {
					return "" // chain shorter than declared: fail closed, see above
				}
				// Normalize like the RemoteAddr path below: proxies may append the client as
				// IP:port or a bracketed IPv6 literal, and the downstream ipRange condition
				// runs net.ParseIP, which returns nil for either form. An entry that
				// normalizes to nothing (":8080", "[]") is returned RAW so it still fails
				// net.ParseIP downstream and denies, rather than falling back to the peer.
				if host := normalizeHost(all[idx]); host != "" {
					return host
				}
				return all[idx]
			}
		}
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

// normalizeHost strips an optional port and IPv6 brackets from a host-ish value, yielding
// the bare host net.ParseIP accepts. Shared by sourceIP's X-Forwarded-For read (a proxy
// may append the client as a bare address, IP:port, or a bracketed IPv6 literal) and
// loopbackOnly's Host pin, so the two agree on what a host string reduces to rather than
// each carrying its own copy of the rule. Empty in, empty out.
func normalizeHost(entry string) string {
	if host, _, err := net.SplitHostPort(entry); err == nil {
		return host
	}
	return strings.TrimSuffix(strings.TrimPrefix(entry, "["), "]")
}

// proxyHops is the effective listen.trustedProxyHops: the declared count, or 1 when the
// key is unset (the zero value). A single trusted proxy is the overwhelmingly common
// topology and makes the read the plain right-most X-Forwarded-For entry, so an absent
// key resolves to that rather than to a chain depth nobody declared. Config validation
// already rejects an explicit value below 1, so the clamp only supplies the default.
func (p *HTTPProxy) proxyHops() int {
	if p.trustedProxyHops < 1 {
		return 1
	}
	return p.trustedProxyHops
}

// hostInTrustedProxyNets reports whether a bare host (no port, no brackets) parses to an
// IP inside listen.trustedProxyCIDRs. Backs peerIsTrustedProxy, the immediate-peer gate.
// Deliberately NOT applied to X-Forwarded-For entries: membership in this range does not
// prove an entry was written by a proxy rather than by a client that happens to share the
// range, so sourceIP counts declared hops instead. An empty CIDR set matches nothing.
func (p *HTTPProxy) hostInTrustedProxyNets(host string) bool {
	if len(p.trustedProxyNets) == 0 {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range p.trustedProxyNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// peerIsTrustedProxy reports whether remoteAddr's host is a configured
// listen.trustedProxyCIDRs entry — the gate sourceIP applies before trusting
// X-Forwarded-For at all. An empty allowlist matches nothing, so
// --trust-forwarded-for alone (no CIDRs configured) never trusts the header.
func (p *HTTPProxy) peerIsTrustedProxy(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	return p.hostInTrustedProxyNets(host)
}

// bindIsLoopbackOnly reports whether the bind host accepts connections only from
// the local loopback interface. A wildcard bind ("" / 0.0.0.0 / ::), or any routable
// address or non-loopback hostname, is NOT loopback-only — it may be reachable
// directly, which matters for the --trust-forwarded-for warning in Serve. Delegates
// to capability.IsLoopbackHost (case-insensitive, trailing-FQDN-dot-tolerant) rather
// than keeping a second, independently-maintained loopback check, which had drifted
// from it (case-sensitive, no trailing-dot handling) before this fix.
func bindIsLoopbackOnly(host string) bool {
	if host == "" {
		return false // empty == wildcard (all interfaces)
	}
	// Strip a bracketed IPv6 literal ("[::1]") before checking: capability.IsLoopbackHost's
	// net.ParseIP call rejects the bracketed form and would otherwise misclassify a
	// loopback bind as non-loopback, firing a spurious --trust-forwarded-for SECURITY
	// warning. Mirrors buildAllowedOriginHosts, which keys on the unbracketed host.
	h := strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	return capability.IsLoopbackHost(h)
}

// openNonLoopbackBind reports whether the proxy is bound to a non-loopback address with
// neither an auth token nor JWT configured — the open posture in which the enforced /mcp
// endpoint is reachable by any off-host client (checkAuth is a no-op without a
// token/JWKS, and checkOrigin passes any request that omits the Origin header). Serve
// emits a startup SECURITY warning when this holds; factored out so the condition is
// unit-tested rather than only exercised through a live listener.
func openNonLoopbackBind(bind, authToken string, jwtConfigured bool) bool {
	return !bindIsLoopbackOnly(bind) && authToken == "" && !jwtConfigured
}

// loopbackOnly reports whether the request originates from a loopback address AND
// carries a trusted Host, writing a 403 and returning false otherwise. Shared by the
// control, health, and metrics endpoints so none of them is reachable off-host.
//
// The Host check is the DNS-rebinding guard: a loopback RemoteAddr alone is satisfied
// by the victim's OWN browser after a rebind (attacker.com → 127.0.0.1), because the
// TCP connection still originates on the local machine. Without also pinning the Host
// to a trusted name, attacker JS on a rebound page could read /healthz and /metrics
// operational state (session/route counts, audit-degradation and kill-switch health)
// cross-site — the checkOrigin path already applies exactly this Host allowlist to
// /mcp, but these endpoints are gated by loopbackOnly alone.
func (p *HTTPProxy) loopbackOnly(w http.ResponseWriter, r *http.Request) bool {
	// Under --trust-forwarded-for a reverse proxy may sit in front of the listener and
	// forward these loopback-only control/health/metrics paths: it then connects from a
	// loopback RemoteAddr on behalf of an OFF-HOST client, so RemoteAddr alone would admit
	// that client. A directly-connecting local caller never sends X-Forwarded-For, so when
	// the trust flag is set treat the presence of that header as "this arrived via the
	// proxy" and fail closed. This can only DENY (never admit) — an attacker who reaches a
	// directly-exposed listener and injects a spurious X-Forwarded-For merely self-blocks
	// these endpoints, so the failure mode is safe.
	if p.trustFwdFor && len(r.Header.Values("X-Forwarded-For")) > 0 {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return false
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return false
	}
	// DNS-rebinding guard: also require a trusted Host. normalizeHost reduces r.Host to
	// a bare hostname the same way originAllowed's url.Hostname() reduces an Origin, so
	// the two checks agree on what they are comparing. A rebound request carries the
	// attacker's name (Host: attacker.com) and is rejected; a legitimate loopback scrape
	// uses localhost / 127.0.0.1 / ::1 / the non-wildcard bind host, all of which
	// buildAllowedOriginHosts seeds.
	reqHost := strings.ToLower(normalizeHost(r.Host))
	if !p.hostAllowedForLoopbackEndpoint(reqHost) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return false
	}
	return true
}

// hostAllowedForLoopbackEndpoint reports whether reqHost (already normalized to a bare,
// lower-cased hostname) is a trusted name for a loopback-only endpoint.
//
// What the guard must stop is a DNS rebind, and a rebind always presents a NAME the
// attacker controls (Host: attacker.com) — that is the mechanism: the victim's browser
// still believes it is talking to the attacker's hostname, which is what makes the
// response same-origin readable. So the rule is "reject foreign names", not "reject
// everything unlisted", and three things are admitted:
//
//   - The origin-host allowlist the constructor seeds (loopback names plus any
//     non-wildcard bind host) — the same set checkOrigin applies to /mcp.
//   - Any loopback host, name or literal. A caller reaching a loopback endpoint over
//     127.0.0.2 or an alternate loopback alias is local by construction, and a browser
//     cannot be steered into sending a loopback LITERAL as the Host of a rebound page:
//     fetching the literal directly is cross-origin, so it carries an Origin and
//     requireValidOrigin (which wraps every route) rejects it first.
//   - An absent Host. HTTP/1.1 requires the header and every browser sends it, so an
//     empty value is a non-browser local caller (an HTTP/1.0 liveness probe, a
//     hand-rolled client) and cannot be a rebind.
//
// The source-IP loopback check remains the primary gate; this is the rebinding layer on
// top of it.
func (p *HTTPProxy) hostAllowedForLoopbackEndpoint(reqHost string) bool {
	if reqHost == "" {
		return true
	}
	if p.allowedOriginHosts[reqHost] {
		return true
	}
	return capability.IsLoopbackHost(reqHost)
}
