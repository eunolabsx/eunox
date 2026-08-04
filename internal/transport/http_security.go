// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// HTTP transport security middleware: bearer / control-token auth, Origin
// (DNS-rebinding) validation, source-IP extraction, and loopback gating.

package transport

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/eunolabs/eunox/pkg/capability"
)

// requireJSONContentType admits only a request body labelled application/json, failing
// closed on an absent, unparseable, or duplicated Content-Type header. Every POST this
// proxy serves is JSON per the MCP spec, so no honest caller is turned away.
//
// It's a CSRF hardening measure, not merely conformance: checkOrigin already rejects the
// cross-origin browser case, but a body sent with the default text/plain content type is a
// CORS SIMPLE request dispatched with no preflight — requiring JSON forces a preflight on
// exactly the sessionless initialize POST that could otherwise reach a handler without one
// (session-bound POSTs are already preflighted by their Mcp-Session-Id header).
//
// A refusal IS recorded, through the same rate-limited pre-session path checkOrigin uses —
// leaving it unrecorded made a content-type sweep of the initialize POST and the emergency
// stop the one transport refusal invisible to an incident responder. route is whichever
// route the caller already resolved (nil for /control/kill), passed to recordRefusal so
// the record is stamped exactly when known. The header value itself is never recorded,
// only the count.
//
// More than one Content-Type header is rejected outright, mirroring checkOrigin's
// duplicated-Origin rule: Header.Get would validate the first while a downstream proxy may
// act on another. That leg also prints a stderr line since a reverse proxy re-adding the
// header is an operator-caused failure mode worth diagnosing directly. The duplicate rule
// is HEADER-level: Go's mime accepts a repeated identical *parameter*, so only the count
// check below enforces it.
func (p *HTTPProxy) requireJSONContentType(w http.ResponseWriter, r *http.Request, route *UpstreamRoute) bool {
	vals := r.Header.Values("Content-Type")
	if len(vals) == 1 && isJSONMediaType(vals[0]) {
		return true
	}
	admitted := p.recordRefusal(r, route, codeUnsupportedMediaType, catContentType, map[string]interface{}{
		"header_count": len(vals),
	})
	// Bounded AND gated on the same admission verdict as the record, mirroring checkOrigin:
	// an unbounded, ungated stderr line here would be the cheapest half of the flooding
	// primitive checkOrigin already closed for its twin. A suppressed burst is still
	// visible, as the rollup count on the next admitted record.
	if admitted && len(vals) > 1 {
		_, _ = fmt.Fprintf(p.errOut(),
			"[eunox] SECURITY: rejected request carrying %d Content-Type headers (%q); exactly one is required (a reverse proxy that re-adds the header will trip this)\n",
			len(vals), boundedRefusalDetail(strings.Join(vals, ", ")))
	}
	http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
	return false
}

// isJSONMediaType reports whether a Content-Type header value denotes application/json.
//
// The common bare "application/json" (and ASCII-case variants) is answered without
// touching mime.ParseMediaType, which allocates its parameter map unconditionally on a
// gate that now precedes every enforced MCP call (~290ns/48B vs ~55ns/no-alloc here).
// Anything carrying a parameter falls through to the real parser.
//
// The fold is ASCII-only ON PURPOSE: strings.EqualFold's Unicode folding maps U+017F
// (LATIN SMALL LETTER LONG S) to 's', so "application/jſon" would pass this fast path
// while ParseMediaType rejects it — making the two paths disagree about the same header.
func isJSONMediaType(v string) bool {
	if !strings.Contains(v, ";") && asciiEqualFold(strings.TrimSpace(v), CTJSON) {
		return true
	}
	// ParseMediaType lower-cases the media type and strips parameters, so
	// "Application/JSON; charset=utf-8" is admitted. The error check must come FIRST and
	// must not be dropped: a malformed parameter list ("application/json;;",
	// `application/json; x="unterminated`) returns a NON-EMPTY media type alongside its
	// error, so comparing mt alone would admit it.
	mt, _, err := mime.ParseMediaType(v)
	return err == nil && mt == CTJSON
}

// asciiEqualFold is strings.EqualFold restricted to ASCII case folding — no Unicode
// special cases (see isJSONMediaType for why that distinction is load-bearing). want
// must already be lower-case ASCII.
func asciiEqualFold(got, want string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := 0; i < len(got); i++ {
		c := got[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != want[i] {
			return false
		}
	}
	return true
}

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

// constantTimeTokenEqual reports whether presented equals want without leaking either
// operand's length through timing: hmac.Equal returns early when inputs differ in length,
// so comparing raw tokens would let an attacker binary-search the secret's length. Folding
// both sides to a fixed-length keyed MAC first guarantees equal-length inputs, with the
// per-process random key making the MACs unpredictable so candidates can't be precomputed.
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
		p.recordPreSessionDeny(r, codeAuthFailed, catAuth, nil)
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
		// Record this refusal too. It is the same probe of the same emergency-stop endpoint
		// as the wrong-token leg below, and the deployment that reaches it — one whose
		// token was never configured or whose token-file write failed — is the one most
		// worth probing, so leaving it as an HTTP status only meant an operator reviewing
		// the tape saw no evidence the endpoint was ever touched.
		p.recordPreSessionDeny(r, codeControlAuthFailed, catControl, map[string]interface{}{
			"reason": "control_token_unconfigured",
		})
		http.Error(w, "control endpoint not configured", http.StatusServiceUnavailable)
		return false
	}
	presented := r.Header.Get(ControlTokenHeader)
	if presented == "" || !constantTimeTokenEqual(p.authTimingKey, presented, p.controlToken) {
		// Record the refusal: /control/kill is the emergency-stop endpoint (SEC-07), so a
		// same-host process probing it with a wrong/missing token is exactly the threat the
		// token defends, and must not be invisible on the tape. recordPreSessionDeny never
		// records the presented token — only the source and the unverified claimed session id.
		p.recordPreSessionDeny(r, codeControlAuthFailed, catControl, nil)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

// buildLoopbackPinHosts returns the extra host NAMES the DNS-rebinding pin on the
// loopback-only endpoints accepts, derived from listen.allowedOrigins.
//
// It exists because the pin was strictly STRICTER than the /mcp gate it mirrors: checkOrigin
// admits an origin by exact allowedOrigins match OR by hostname in the seeded host set, but
// the pin only consulted the second, so an allowlisted origin could reach /mcp but 403 on
// the more sensitive /healthz, /metrics, /control/kill.
//
// A SEPARATE set on purpose: folding these names into allowedOriginHosts (matched on
// hostname alone, any scheme/port) would widen /mcp itself — a real weakening. A configured
// origin that isn't a parseable http(s) web origin contributes no hostname here.
func buildLoopbackPinHosts(allowedOrigins []string) map[string]bool {
	hosts := make(map[string]bool, len(allowedOrigins))
	for _, o := range allowedOrigins {
		u, err := url.Parse(strings.TrimSpace(o))
		if err != nil {
			continue
		}
		switch strings.ToLower(u.Scheme) {
		case "http", "https":
		default:
			continue
		}
		if h := strings.ToLower(u.Hostname()); h != "" {
			hosts[h] = true
		}
	}
	return hosts
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
	// Strip bracketed-IPv6-literal brackets so the key matches url.Hostname() (which
	// returns the host without them); otherwise a legitimate IPv6 Origin is rejected.
	b := strings.ToLower(strings.TrimSpace(bind))
	b = strings.Trim(b, "[]")
	// Exclude every spelling of the unspecified address via IsUnspecified() rather than a
	// brittle string match, so an alternate wildcard spelling isn't added to the allowlist.
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

// checkOrigin enforces the MCP Streamable HTTP Origin check that prevents DNS-rebinding:
// without it a same-machine browser tab can use a rebound DNS name to reach the loopback
// listener. Only a truly absent Origin passes unconditionally (browsers always attach
// Origin to the cross-site requests rebinding exploits); any present value must satisfy
// originAllowed. More than one Origin header (RFC 6454 §7.1 forbids it; a smuggling
// vector) is rejected outright.
func (p *HTTPProxy) checkOrigin(w http.ResponseWriter, r *http.Request) bool {
	// Distinguish an absent header from a present-but-empty value: Header.Get collapses
	// both to "", but only a missing header passes freely.
	vals := r.Header.Values("Origin")
	if len(vals) == 0 {
		return true
	}
	// RFC 6454 §7.1 permits at most one Origin header; multiple headers let a client
	// smuggle an allowed origin alongside a disallowed one that a downstream host acts on.
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
	// Bound it before it reaches the tape or stderr: an unauthenticated client can put
	// ~1 MiB (Go's default MaxHeaderBytes) in an Origin header otherwise.
	bounded := boundedRefusalDetail(recordedOrigin)
	details := map[string]interface{}{"origin": bounded}
	if bounded != recordedOrigin {
		// Flag it so a reader knows the field is not the header verbatim, mirroring
		// claimed_session_id_truncated.
		details["origin_truncated"] = true
	}
	recordedOrigin = bounded
	// Unstamped by design (no route/policy fields): the Origin gate runs before route
	// resolution — see recordPreSessionDeny. The stderr line is gated on the SAME admission
	// verdict as the record, for the reason given on requireJSONContentType's stderr gate above.
	if admitted := p.recordPreSessionDeny(r, "ORIGIN_REJECTED", catOrigin, details); admitted {
		if multiple {
			_, _ = fmt.Fprintf(p.errOut(),
				"[eunox] SECURITY: rejected request carrying %d Origin headers (%q); RFC 6454 permits only one (DNS-rebinding guard)\n",
				len(vals), recordedOrigin,
			)
		} else {
			_, _ = fmt.Fprintf(p.errOut(),
				"[eunox] SECURITY: rejected request with disallowed Origin %q (DNS-rebinding guard)\n",
				recordedOrigin,
			)
		}
	}
	http.Error(w, "Forbidden: Origin not allowed", http.StatusForbidden)
	return false
}

// addClaimedSessionID records the client-supplied Mcp-Session-Id header into a deny's
// details under claimed_session_id, never as the structured session_id: the transport-level
// denials that use it fire BEFORE any session lookup, so the header is unverified and
// attacker-controlled, and stamping it as session_id would let a caller forge records
// against a victim's session. killSubject's claimedSession (forward.go) is the other caller
// family, for the identical risk at a different lifecycle stage. Kept only when present so
// a missing header leaves no empty key.
// maxClaimedSessionIDLen bounds the attacker-controlled header this stamps into a record. A
// session id is a UUID; anything longer isn't a real id, and without a bound a request
// could append most of a 1 MiB header to the tape as a log-flooding primitive.
const maxClaimedSessionIDLen = 200

// sanitizeClaimedID makes an attacker-controlled header value safe to put in a signed audit
// field: replaces invalid UTF-8 with the replacement character, then cuts to at most limit
// BYTES without splitting a rune. Both halves are load-bearing: without the UTF-8 pass,
// json.Marshal silently rewrites bytes >= 0x80 (a raw Mcp-Session-Id may carry them) to
// U+FFFD at serialize time, diverging the signed field from what a SIEM holds; without the
// rune-safe cut, truncation alone can land mid-rune for the same silent rewrite. Order
// matters: sanitizing FIRST bounds the walk-back to at most 3 real continuation bytes,
// where cutting first could walk a run of attacker-chosen 0x80 bytes to zero and stamp an
// empty field, discarding the correlation evidence it exists for.
//
// The logic itself lives in capability.TruncateUTF8, shared with internal/audit and
// pkg/enforcement's own bounds so it exists once.
func sanitizeClaimedID(s string, limit int) string {
	return capability.TruncateUTF8(s, limit)
}

// maxRefusalDetailLen bounds the OTHER attacker-controlled strings a pre-session refusal
// stamps into its details: the rejected Origin and the requested path. Larger than the
// session-id bound because a URL or an allowlist-adjacent origin can legitimately run a
// few hundred bytes, but no legitimate value approaches 512.
const maxRefusalDetailLen = 512

// boundedRefusalDetail sanitizes and cuts an attacker-controlled refusal detail to
// maxRefusalDetailLen, using the same rune-safe, valid-UTF-8 treatment as sanitizeClaimedID.
func boundedRefusalDetail(s string) string {
	return sanitizeClaimedID(s, maxRefusalDetailLen)
}

func addClaimedSessionID(details map[string]interface{}, r *http.Request) map[string]interface{} {
	return addClaimedSessionIDValue(details, r.Header.Get(SessionHeader))
}

// addClaimedSessionIDValue is addClaimedSessionID's request-independent core, so a caller
// that already holds the extracted header value (killSubject) gets identical treatment
// through one call instead of a second implementation.
func addClaimedSessionIDValue(details map[string]interface{}, claimed string) map[string]interface{} {
	if claimed == "" {
		return details
	}
	// A caller with no extra context may pass nil, so allocate rather than assigning into a
	// nil map and panicking inside an HTTP handler on a security-refusal path.
	if details == nil {
		details = make(map[string]interface{}, 1)
	}
	if sanitized := sanitizeClaimedID(claimed, maxClaimedSessionIDLen); sanitized != claimed {
		// The value was invalid UTF-8, over the bound, or both. Flag it so a reader knows
		// the field is not the header verbatim; sanitizeClaimedID documents which
		// substitutions it makes.
		claimed = sanitized
		details["claimed_session_id_truncated"] = true
	}
	details["claimed_session_id"] = claimed
	return details
}

// recordPreSessionDeny writes a transport-level deny that fires BEFORE any session
// lookup — a rejected Origin, JWT, static bearer, or control token. Centralizes the
// forgery guard those four share: session_id is left EMPTY (the client-supplied
// Mcp-Session-Id is unverified at this point), with the claimed value preserved only as
// details.claimed_session_id. The presented credential is NEVER passed in. Writes are
// rate-limited: unauthenticated callers can trigger these, so an unbounded write lets an
// attacker drive the audit queue's drop counter and permanently trip
// --require-audit=strict. A suppressed refusal is folded into the next admitted record of
// the SAME category rather than vanishing.
//
// These records carry NO route/policy stamp on purpose: resolving the route first would
// turn the 404-vs-401 split into a route-name enumeration oracle. The one refusal that DOES
// know its route by firing time — the session cap — goes through recordSessionCapDeny
// instead, which keeps this rate limiter but writes through the route's sink.
// Returns the rate limiter's verdict so a caller can gate its own stderr diagnostic on the
// same decision.
func (p *HTTPProxy) recordPreSessionDeny(r *http.Request, code string, category refusalCategory, extra map[string]interface{}) bool {
	return p.recordRefusal(r, nil, code, category, extra)
}

// preSessionKillRecorder returns the recorder a PRE-SESSION kill-switch site must write
// its record through, or nil when the bucket suppressed this one (the site still denies
// the request either way — only the RECORD is elided).
//
// Those sites fire for raw, unauthenticated requests and are otherwise an audit-queue
// flooding primitive: one dropped record latches AuditDegraded() for the process lifetime,
// which under --require-audit=strict strict-denies every route until restart — turning an
// emergency stop into an outage that outlives it. It does NOT bound kill records for an
// established session (see catKill): those describe an already-admitted caller.
func (p *HTTPProxy) preSessionKillRecorder(route *UpstreamRoute) auditRecorder {
	rec := asRecorder(route.sink)
	if rec == nil {
		// Nothing to write, so nothing to bound: leave the bucket's tokens for a site
		// that has a tape. (Unlike recordRefusal, no stderr line rides on this verdict.)
		return nil
	}
	// A nil limiter beside a live sink is a construction bug and panics like one, exactly
	// as in recordRefusal: a "defensive" fallback here would write kill records with no
	// bound at all, which is the fail-open this function exists to close.
	admitted, suppressed := p.preSessionDenies.admit(catKill)
	if !admitted {
		return nil
	}
	if suppressed == 0 {
		return rec
	}
	return rolledUpRecorder{auditRecorder: rec, suppressed: suppressed}
}

// rolledUpRecorder folds a suppressed-refusal rollup into the details of the one record it
// passes through, so a bounded record still reports how much was elided. It wraps rather
// than widening recordKillDenial/recordKillDrop with a details parameter: those two are the
// single source of the kill record's SHAPE, shared with verified-session sites that take no
// rollup, and threading an always-nil argument through them to serve three is how a shape
// grows a hole.
type rolledUpRecorder struct {
	auditRecorder
	suppressed uint64
}

// RecordDeny stamps the rollup into this record's details and delegates. Only RecordDeny
// is overridden: a rollup describes SUPPRESSED REFUSALS, and refusals are denies.
func (r rolledUpRecorder) RecordDeny(ctx context.Context, sessionID, identifier, method, denialCode, condType string, details map[string]interface{}, observe bool) {
	if details == nil {
		details = make(map[string]interface{}, 2)
	}
	// Always paired: a count whose scope a reader has to infer from the stamp beside it
	// is a count that gets misread.
	details[detailSuppressedRefusalCount] = r.suppressed
	details[detailSuppressedRefusalScope] = suppressedScopeProxyCategory
	r.auditRecorder.RecordDeny(ctx, sessionID, identifier, method, denialCode, condType, details, observe)
}

// recordSessionCapDeny records a session-cap refusal — the pre-spawn slot reservation and
// the errSessionLimit leg of writeSessionCreateError, the two halves of one condition.
//
// Writes RESOURCE_EXHAUSTED through the ROUTE's sink so the record carries the route
// stamp like the per-session in-flight cap's record, but keeps the rate limit since —
// unlike that cap — this refusal is reachable WITHOUT an established session.
//
// It is therefore the one refusal that is route-stamped AND can carry a rollup from a
// bucket whose tally spans every route. The rollup names its own scope
// (suppressedScopeProxyCategory) so `upstream: github` with a count of 5000 is read as
// 5000 saturation refusals across every route, not 5000 against github specifically.
func (p *HTTPProxy) recordSessionCapDeny(r *http.Request, route *UpstreamRoute) {
	p.recordRefusal(r, route, codeResourceExhausted, catSaturation, map[string]interface{}{
		"reason": "session_limit_reached",
	})
}

// recordRefusal is the shared body of the two above: rate-limit, fold any suppressed count
// in, stamp the source IP and the unverified claimed_session_id, and write through route's
// sink when known (nil ⟹ the proxy-wide sink). Returns whether the refusal was ADMITTED by
// the rate limiter, so a caller whose own stderr diagnostic is part of the same flood
// (checkOrigin's SECURITY line) can gate it on the same verdict.
func (p *HTTPProxy) recordRefusal(r *http.Request, route *UpstreamRoute, code string, category refusalCategory, extra map[string]interface{}) bool {
	rec := asRecorder(p.sink)
	if route != nil {
		rec = asRecorder(route.sink)
	}
	// Charged BEFORE the sink is consulted, so the verdict bounds the caller's stderr line
	// whether or not a tape exists — a nil sink is reachable in production
	// (--require-audit=off with an unopenable path), and short-circuiting to "admitted"
	// there would leave stderr, the only surviving signal, completely unbounded.
	//
	// No nil-limiter fallback for a proxy that HAS a tape: NewHTTPProxyGateway always
	// builds the limiter, so a nil one alongside a sink is a construction bug that panics
	// like one rather than silently disabling the DoS bound.
	if rec == nil && p.preSessionDenies == nil {
		return true
	}
	ok, suppressed := p.preSessionDenies.admit(category)
	if !ok {
		return false
	}
	if rec == nil {
		// No sink configured: nothing to write, but the caller's stderr line is admitted
		// (and rate-limited) as the refusal's only surviving signal.
		return true
	}
	if suppressed > 0 {
		if extra == nil {
			extra = make(map[string]interface{}, 2)
		}
		extra[detailSuppressedRefusalCount] = suppressed
		extra[detailSuppressedRefusalScope] = suppressedScopeProxyCategory
	}
	rec.RecordDeny(r.Context(), "", "", "", code, string(category), p.addRefusalContext(extra, r), false)
	return true
}

// addRefusalContext stamps the two details EVERY refusal record carries: the resolved
// source IP and the unverified claimed_session_id. Centralized here rather than at each
// call site because that is how it got lost before — hand-added by each of eight callers,
// with the two that forgot being an unauthenticated Origin probe and a JWT rejection,
// precisely the records an incident responder reads to find where an attack came from.
func (p *HTTPProxy) addRefusalContext(details map[string]interface{}, r *http.Request) map[string]interface{} {
	if details == nil {
		details = make(map[string]interface{}, 2)
	}
	details["source_ip"] = p.sourceIP(r)
	return addClaimedSessionID(details, r)
}

// originAllowed reports whether a present Origin value is permitted. The origin must
// match a configured allowlist entry exactly (case-insensitively), or its host must be a
// loopback name or the bind host. Nothing is implicit: "null" and an empty value are
// accepted only if listed. An unparseable or hostless Origin fails closed.
//
// Deliberate port asymmetry: allowedOrigins entries match exactly (scheme + port), while
// the host-set path accepts ANY port on a loopback or bind host — DNS rebinding is
// host-based, not port-based, so any local port on a loopback host is equally local.
func (p *HTTPProxy) originAllowed(origin string) bool {
	for _, a := range p.allowedOrigins {
		if strings.EqualFold(origin, a) {
			return true
		}
	}
	// A valid RFC 6454 web origin has no query component, so any '?' is malformed. Reject
	// before parsing: url.Parse consumes a trailing bare '?' as an empty query delimiter,
	// leaving u.RawQuery == "" so the structural guard below would miss "http://localhost?".
	if strings.Contains(origin, "?") {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil {
		// url.Parse returns a nil *URL on error, so this must short-circuit before
		// any field of u is read below.
		return false
	}
	// A valid Origin is exactly scheme://host[:port] (RFC 6454 §6.1). url.Parse retains
	// scheme, userinfo, fragment, query, and path as struct fields, so each is checked
	// explicitly: without the scheme check "file://localhost" or a scheme-relative
	// "//localhost" would still yield a trusted Hostname() and slip past, and without the
	// userinfo/fragment checks "http://evil@localhost" or "...#@evil.com" would too. A
	// trailing "/" path is accepted (some browsers include it, no injection risk).
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "http" && scheme != "https") || u.Host == "" || u.User != nil ||
		u.Fragment != "" || u.RawQuery != "" || (u.Path != "" && u.Path != "/") {
		return false
	}
	return p.allowedOriginHosts[strings.ToLower(u.Hostname())]
}

// sourceIP extracts the client IP address for PDP evaluation.
//
// Under --trust-forwarded-for the proxy trusts X-Forwarded-For only when the immediate
// peer (RemoteAddr) itself matches listen.trustedProxyCIDRs — otherwise the flag alone
// would trust the header from ANY directly-connecting client, letting it spoof an ipRange source.
//
// The client is resolved by COUNTING hops, not inspecting addresses: with N trusted
// proxies (listen.trustedProxyHops), each appends the address it saw, so the right-most N
// entries are exactly proxy-written and the client's real address is the N-th from the
// right. The count is declared rather than inferred by testing each entry against
// trustedProxyCIDRs, because inference can't distinguish a proxy hop from a client whose
// OWN address falls inside that range (a plausible shared-supernet deployment) and would
// then return a forged entry to its left.
//
// A chain with FEWER than N entries doesn't match the declared topology, so no entry is
// provably proxy-written; falling back to RemoteAddr there would be a silent fail-OPEN
// (RemoteAddr is by construction inside trustedProxyCIDRs on this branch, so an ipRange
// condition allowing that supernet would match every request). Such a request instead
// yields an empty source IP, which an ipRange condition denies loudly with MISSING_CONTEXT.
func (p *HTTPProxy) sourceIP(r *http.Request) string {
	if p.trustFwdFor && p.peerIsTrustedProxy(r.RemoteAddr) {
		// Flatten ALL X-Forwarded-For lines, not just the first: an intermediary adding
		// its own line would otherwise let an attacker-controlled first line shadow the
		// trusted right-most hop.
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
				// Normalize like the RemoteAddr path below (proxies may append IP:port or a
				// bracketed IPv6 literal). An entry normalizing to nothing (":8080", "[]") is
				// returned RAW so it still fails net.ParseIP downstream and denies, rather
				// than falling back to the peer.
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
// the bare host net.ParseIP accepts. Shared by sourceIP's X-Forwarded-For read and
// loopbackOnly's Host pin, so the two agree on what a host string reduces to. Empty in,
// empty out.
func normalizeHost(entry string) string {
	if host, _, err := net.SplitHostPort(entry); err == nil {
		return host
	}
	return strings.TrimSuffix(strings.TrimPrefix(entry, "["), "]")
}

// proxyHops is the effective listen.trustedProxyHops: the declared count, or 1 when unset,
// since a single trusted proxy is the overwhelmingly common topology. Config validation
// already rejects an explicit value below 1, so the clamp only supplies the default.
func (p *HTTPProxy) proxyHops() int {
	if p.trustedProxyHops < 1 {
		return 1
	}
	return p.trustedProxyHops
}

// hostInTrustedProxyNets reports whether a bare host parses to an IP inside
// listen.trustedProxyCIDRs. Backs peerIsTrustedProxy. Deliberately NOT applied to
// X-Forwarded-For entries: membership doesn't prove an entry was proxy-written rather than
// client-supplied from a shared range, so sourceIP counts declared hops instead.
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

// bindIsLoopbackOnly reports whether the bind host accepts connections only from the local
// loopback interface — matters for the --trust-forwarded-for warning in Serve. Delegates to
// capability.IsLoopbackHost rather than a second, independently-maintained check, which had
// drifted from it (case-sensitive, no trailing-dot handling) before this fix.
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

// loopbackOnly reports whether the request originates from a loopback address AND carries
// a trusted Host, writing a 403 and returning false otherwise. Shared by the control,
// health, and metrics endpoints so none is reachable off-host.
//
// The Host check is the DNS-rebinding guard: a loopback RemoteAddr alone is satisfied by
// the victim's OWN browser after a rebind, since the TCP connection still originates
// locally. Without pinning the Host too, attacker JS on a rebound page could read
// /healthz and /metrics cross-site — checkOrigin applies this same allowlist to /mcp, but
// these endpoints are gated by loopbackOnly alone.
func (p *HTTPProxy) loopbackOnly(w http.ResponseWriter, r *http.Request) bool {
	// Under --trust-forwarded-for a reverse proxy may forward these paths, connecting from
	// a loopback RemoteAddr on behalf of an OFF-HOST client. A directly-connecting local
	// caller never sends X-Forwarded-For, so treat its presence as "arrived via the proxy"
	// and fail closed — this can only DENY, so an attacker injecting a spurious header
	// merely self-blocks.
	// Each refusal below is recorded: loopbackOnly is the FIRST gate here, before
	// checkControlToken, so an off-host probe must not be the one attack that leaves
	// nothing on the tape while a same-host wrong-token attempt is fully logged.
	if p.trustFwdFor && len(r.Header.Values("X-Forwarded-For")) > 0 {
		p.recordPreSessionDeny(r, codeLoopbackRejected, catLoopback, map[string]interface{}{
			"reason": "forwarded_for_present",
			"path":   boundedRefusalDetail(r.URL.Path),
		})
		http.Error(w, "Forbidden", http.StatusForbidden)
		return false
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		p.recordPreSessionDeny(r, codeLoopbackRejected, catLoopback, map[string]interface{}{
			"reason": "non_loopback_source",
			"path":   boundedRefusalDetail(r.URL.Path),
		})
		http.Error(w, "Forbidden", http.StatusForbidden)
		return false
	}
	// DNS-rebinding guard: also require a trusted Host. normalizeHost reduces r.Host the
	// same way originAllowed's url.Hostname() reduces an Origin, so the two checks agree.
	// A rebound request carries the attacker's name and is rejected; a legitimate loopback
	// scrape uses localhost/127.0.0.1/::1/the bind host, all seeded by buildAllowedOriginHosts.
	reqHost := strings.ToLower(normalizeHost(r.Host))
	if !p.hostAllowedForLoopbackEndpoint(r.Host, reqHost) {
		p.recordPreSessionDeny(r, codeLoopbackRejected, catLoopback, map[string]interface{}{
			"reason": "untrusted_host",
			"path":   boundedRefusalDetail(r.URL.Path),
		})
		http.Error(w, "Forbidden", http.StatusForbidden)
		return false
	}
	return true
}

// hostAllowedForLoopbackEndpoint reports whether reqHost (already normalized to a bare,
// lower-cased hostname) is a trusted name for a loopback-only endpoint.
//
// A DNS rebind always presents a NAME the attacker controls, so the rule is "reject
// foreign names", not "reject everything unlisted", and three things are admitted: the
// origin-host allowlist plus any listen.allowedOrigins hostnames (every name checkOrigin
// would accept on /mcp); any loopback host, name or literal (local by construction, and a
// browser can't be steered into sending a loopback literal as a rebound page's Host —
// fetching it directly is cross-origin and requireValidOrigin rejects it first); and a
// genuinely ABSENT Host (every browser sends one, so no value means a non-browser local
// caller).
//
// The absent-Host allowance keys off rawHost, NOT the normalized value: normalizeHost
// reduces a present-but-host-less value like ":8080" to "", so gating on the normalized
// value would have let `Host: :8080` (a header that WAS sent) skip the whole rebinding pin.
//
// The source-IP loopback check remains the primary gate; this is the rebinding layer on top.
func (p *HTTPProxy) hostAllowedForLoopbackEndpoint(rawHost, reqHost string) bool {
	if rawHost == "" {
		return true
	}
	if reqHost == "" {
		// Present but carrying no host part (":8080", "[]"): not a name we can trust, and
		// not the absent-header case. Fail closed.
		return false
	}
	if p.allowedOriginHosts[reqHost] {
		return true
	}
	// An operator-allowlisted Origin host is, by definition, not a foreign name — the same
	// trust decision checkOrigin makes for the more sensitive /mcp route.
	if p.loopbackPinHosts[reqHost] {
		return true
	}
	return capability.IsLoopbackHost(reqHost)
}
