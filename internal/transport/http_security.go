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
	if p.sink != nil {
		details := addClaimedSessionID(map[string]interface{}{"origin": recordedOrigin}, r)
		p.sink.RecordDeny(r.Context(), "", "", "", "ORIGIN_REJECTED", "origin", details, false)
	}
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
// Under --trust-forwarded-for the proxy trusts the immediate reverse proxy to have
// appended the real client address as the RIGHT-MOST X-Forwarded-For entry — but only
// when that immediate peer (RemoteAddr) itself matches listen.trustedProxyCIDRs.
// Without this check, --trust-forwarded-for alone would trust the header from ANY
// directly-connecting client, letting it spoof an ipRange source; requiring the peer to
// be an actual configured trusted hop closes that gap. Left-most XFF entries are
// client-controlled (a client can forge a trusted ipRange source), so reading the
// right-most appended hop is what resists spoofing through a single trusted proxy.
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
			if n := len(all); n > 0 {
				// Right-most across the whole chain: only the address our trusted edge
				// appended is reliable; every entry to its left could be forged.
				entry := all[n-1]
				// Normalize like the RemoteAddr path below: some proxies append the client
				// as IP:port or as a bracketed IPv6 literal, and the downstream ipRange
				// condition runs net.ParseIP, which returns nil for a port-suffixed or a
				// bracketed value — wrongly denying every request with CONDITION_FAILED.
				if host, _, err := net.SplitHostPort(entry); err == nil {
					return host
				}
				// SplitHostPort failed: the entry carries no port. It is either a bare
				// address (returned unchanged) or a bracketed IPv6 literal with no port
				// ("[2001:db8::1]"), which net.ParseIP also rejects — strip the surrounding
				// brackets so it parses. Mirrors bindIsLoopbackOnly, which keys on the
				// unbracketed host.
				return strings.TrimSuffix(strings.TrimPrefix(entry, "["), "]")
			}
		}
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

// peerIsTrustedProxy reports whether remoteAddr's host is a configured
// listen.trustedProxyCIDRs entry — the gate sourceIP applies before trusting
// X-Forwarded-For at all. An empty allowlist matches nothing, so
// --trust-forwarded-for alone (no CIDRs configured) never trusts the header.
func (p *HTTPProxy) peerIsTrustedProxy(remoteAddr string) bool {
	if len(p.trustedProxyNets) == 0 {
		return false
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
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

// loopbackOnly reports whether the request originates from a loopback address,
// writing a 403 and returning false otherwise. Shared by the control, health, and
// metrics endpoints so none of them is reachable off-host.
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
	return true
}
