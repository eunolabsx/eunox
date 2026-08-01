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
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/pkg/capability"
)

// requireJSONContentType admits only a request body labelled application/json, failing
// closed on an absent, unparseable, or duplicated Content-Type header. Every POST this
// proxy serves — the /mcp JSON-RPC body and the /control/kill body — is JSON, and the
// MCP Streamable HTTP spec already requires conformant clients to say so, so no honest
// caller is turned away.
//
// It is a CSRF hardening measure, not merely conformance. checkOrigin is the primary
// control and already rejects the cross-origin browser POST (browsers attach Origin to
// every cross-origin POST, and both a foreign origin and the opaque "null" are refused).
// This gate covers the class from the other side: a body sent with the default
// text/plain (or a form/multipart) content type is a CORS SIMPLE request, dispatched
// with no preflight, and the sessionless initialize POST is the one /mcp entry point
// that needs no custom header — so requiring a JSON content type forces a preflight on
// exactly the request that could otherwise reach a handler without one. Session-bound
// POSTs are already preflighted by their Mcp-Session-Id header.
//
// A refusal IS recorded on the tape, through the same rate-limited pre-session path
// checkOrigin uses. The gate sits behind the transport credential on both endpoints —
// checkAuth/ValidateToken for /mcp, checkControlToken for /control/kill — so on a
// deployment that configures either one this is an AUTHENTICATED caller's refusal, not
// an anonymous one; and where no credential is configured, the pre-session bucket is
// exactly the bucket that makes an anonymous caller's refusals safe to write. Leaving
// it unrecorded made a content-type sweep of the sessionless initialize POST and the
// emergency stop the one transport refusal invisible to an incident responder, while
// the same actor's wrong-Origin attempts were fully logged.
//
// route is whichever route the caller has already resolved — the gateway's /mcp path
// always has one by the time it reaches here (handleMCP 404s first), /control/kill has
// none — and is passed straight to recordRefusal, mirroring recordSessionCapDeny: the
// record is route-stamped exactly when a route is already known, never inferred. The
// header value is NOT recorded either way — it is attacker-controlled free text, and the
// count is the only part worth keeping.
//
// More than one Content-Type header is rejected outright, for the reason checkOrigin
// rejects a duplicated Origin: Header.Get would validate the first while a proxy or host
// downstream may act on another. That leg also prints a stderr line, because it is the
// one refusal an operator can hit through no fault of their client — a reverse proxy
// that re-adds the header duplicates it — and a silent total-outage 415 is the hardest
// possible thing to diagnose. Note the duplicate rule is a HEADER-level one: Go's mime
// accepts a repeated *parameter* whose value is identical, so only the count check below
// enforces it.
func (p *HTTPProxy) requireJSONContentType(w http.ResponseWriter, r *http.Request, route *UpstreamRoute) bool {
	vals := r.Header.Values("Content-Type")
	switch {
	case len(vals) > 1:
		fmt.Fprintf(os.Stderr,
			"[eunox] SECURITY: rejected request carrying %d Content-Type headers (%q); exactly one is required (a reverse proxy that re-adds the header will trip this)\n",
			len(vals), strings.Join(vals, ", "))
	case len(vals) == 1 && isJSONMediaType(vals[0]):
		return true
	}
	p.recordRefusal(r, route, codeUnsupportedMediaType, catContentType, map[string]interface{}{
		"header_count": len(vals),
	})
	http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
	return false
}

// isJSONMediaType reports whether a Content-Type header value denotes application/json.
//
// The common shapes — a bare "application/json" and any ASCII-case variant of it — are
// answered without touching mime.ParseMediaType, which allocates its parameter map
// unconditionally (measurably: ~290ns/48B for the bare form, ~800ns/336B with a charset
// parameter, against ~55ns and no allocation here) on a gate that now precedes every
// enforced MCP call. Anything carrying a parameter falls through to the real parser, so
// the accept/reject set is unchanged.
//
// The fold is ASCII-only ON PURPOSE: strings.EqualFold applies Unicode simple folding,
// under which U+017F (LATIN SMALL LETTER LONG S) folds to 's' — so "application/jſon"
// would pass a fold-based fast path while ParseMediaType rejects it, making the fast and
// slow paths disagree about the same header.
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

// buildAllowedOriginHosts returns the set of host names whose Origin is always
// accepted: the loopback names plus the configured bind host (unless it is a
// wildcard, which is not a meaningful Origin host). Hosts are lower-cased so the
// lookup in originAllowed is case-insensitive.
// buildLoopbackPinHosts returns the extra host NAMES the DNS-rebinding pin on the
// loopback-only endpoints accepts, derived from the operator's listen.allowedOrigins.
//
// It exists because the pin was strictly STRICTER than the /mcp gate it claims to mirror.
// checkOrigin admits an Origin two ways: an exact allowedOrigins match, or a hostname in
// the constructor-seeded host set. The pin consulted only the second, so an operator who
// allowlisted "http://eunox.internal:8080" could reach /mcp from that origin but got a 403
// on /healthz, /metrics and /control/kill from the same host — the more sensitive endpoint
// was the permissive one.
//
// This is a SEPARATE set rather than more entries in allowedOriginHosts on purpose. That
// set is matched on hostname alone with any scheme and port, so folding these names into it
// would widen /mcp from "exactly http://eunox.internal:8080" to "eunox.internal on any
// scheme and port" — a real weakening of the Origin check. Only the Host pin, which
// compares bare hostnames by construction, reads this.
//
// A configured origin that is not a parseable http(s) web origin (the opaque "null", a
// file:// front-end) contributes no hostname: those opt into /mcp through the exact-match
// path only, and a Host header cannot carry a scheme to match exactly against.
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
	// Bound it before it reaches either the tape or stderr: an unauthenticated client can
	// put ~1 MiB (Go's default MaxHeaderBytes) in an Origin header, and both destinations
	// wrote it whole. That made every rejected request a kilobyte-per-byte amplifier for
	// signed-log growth and for a stderr line the rate limiter does not gate.
	bounded := boundedRefusalDetail(recordedOrigin)
	details := map[string]interface{}{"origin": bounded}
	if bounded != recordedOrigin {
		// Flag it so a reader knows the field is not the header verbatim, mirroring
		// claimed_session_id_truncated.
		details["origin_truncated"] = true
	}
	recordedOrigin = bounded
	// Unstamped by design (no route/policy fields): the Origin gate runs before route
	// resolution — see recordPreSessionDeny.
	// The stderr line is gated on the SAME admission verdict as the record. It is ~600
	// bytes per rejected request and reachable with no credential at all, so leaving it
	// ungated left the cheapest half of the flooding primitive open while the tape beside
	// it was carefully bounded; a suppressed burst is still visible, as the rollup count
	// on the next admitted record.
	if admitted := p.recordPreSessionDeny(r, "ORIGIN_REJECTED", catOrigin, details); admitted {
		if multiple {
			fmt.Fprintf(os.Stderr,
				"[eunox] SECURITY: rejected request carrying %d Origin headers (%q); RFC 6454 permits only one (DNS-rebinding guard)\n",
				len(vals), recordedOrigin,
			)
		} else {
			fmt.Fprintf(os.Stderr,
				"[eunox] SECURITY: rejected request with disallowed Origin %q (DNS-rebinding guard)\n",
				recordedOrigin,
			)
		}
	}
	http.Error(w, "Forbidden: Origin not allowed", http.StatusForbidden)
	return false
}

// addClaimedSessionID records the client-supplied Mcp-Session-Id header into a
// deny's details under claimed_session_id, never as the structured session_id. The
// transport-level denials that use it directly (origin rejection, JWT rejection) fire
// BEFORE any session lookup, so the header is unverified and attacker-controlled;
// stamping it as session_id would let an unauthenticated caller forge those records
// against a victim's session. killSubject's claimedSession (forward.go) is the other
// caller family, reached via auditDetails for a kill-switch record: there a lookup DID
// run — against the session registry — and failed to resolve, which is a different
// lifecycle stage but the identical unverified-header risk, so the same treatment
// applies. The claimed value is kept as a clearly-unverified detail for correlation,
// and only when present so a missing header leaves no empty key. Centralizing the rule
// keeps every claimed-but-unresolved-session path consistent — a new one cannot
// reintroduce the forgery by hand-rolling it.
// maxClaimedSessionIDLen bounds the attacker-controlled header this stamps into a record.
// A session id is a UUID; anything longer is not a real id, and without a bound a single
// unauthenticated request could append most of a 1 MiB header (Go's default
// MaxHeaderBytes) to the tape, turning the refusal record into a log-flooding primitive.
const maxClaimedSessionIDLen = 200

// sanitizeClaimedID makes an attacker-controlled header value safe to put in a signed
// audit field: it replaces any invalid UTF-8 with the replacement character, then cuts to
// at most limit BYTES without splitting a rune.
//
// Both halves are load-bearing, and the byte cut alone is not enough. Go's net/http
// admits bytes >= 0x80 in a header value, so the raw Mcp-Session-Id can be arbitrary
// bytes:
//
//   - Without the ToValidUTF8 pass, json.Marshal silently rewrites those bytes to U+FFFD
//     when the record is serialized, so the signed field diverges from the header a SIEM
//     holds — with or without truncation, since a short invalid header is never cut at
//     all. Replacing them here makes the substitution explicit and identical on both
//     sides of the wire instead of an artifact of the encoder.
//   - Without the rune-boundary walk, the cut lands mid-rune and produces the same
//     silent U+FFFD rewrite for a perfectly valid multi-byte header.
//
// Order matters: sanitizing FIRST means the walk-back only ever skips real continuation
// bytes and so drops at most 3, where cutting first could walk a run of attacker-chosen
// 0x80 bytes all the way to zero and stamp an EMPTY claimed_session_id on a request that
// carried a 300-byte header — discarding the correlation evidence the field exists for.
//
// The bound stays a BYTE bound: it exists to cap what an unauthenticated caller can
// append to a record, and that is a byte budget.
//
// The normalize-then-rune-safe-cut logic itself lives in audit.TruncateUTF8 (this
// package already depends on internal/audit for SanitizeAuditField, a different,
// control-character-stripping helper) so it exists once rather than as an
// independently-maintained second copy of internal/audit's identical boundFieldTo
// logic; this wrapper keeps the threat-model documentation above local to the callers
// that need it.
func sanitizeClaimedID(s string, limit int) string {
	return audit.TruncateUTF8(s, limit)
}

// maxRefusalDetailLen bounds the OTHER attacker-controlled strings a pre-session refusal
// stamps into its details: the rejected Origin and the requested path. Both are
// client-chosen and, unlike a session id, have no fixed shape to bound them by — but no
// legitimate value approaches 512 bytes, while Go's default MaxHeaderBytes lets an
// unauthenticated caller put ~1 MiB in either. Unbounded, one refused request per
// connection is a multi-megabyte-per-second lever on both signed-log growth and the
// stderr stream, from a caller holding no credential. Larger than the session-id bound
// because a URL or an allowlist-adjacent origin can legitimately be a few hundred bytes.
const maxRefusalDetailLen = 512

// boundedRefusalDetail sanitizes and cuts an attacker-controlled refusal detail to
// maxRefusalDetailLen, using the same rune-safe, valid-UTF-8 treatment the claimed session
// id gets (see sanitizeClaimedID) so the signed field matches what the caller actually sent
// rather than an encoder artifact. Compare the result against the input to detect that a
// value was altered.
func boundedRefusalDetail(s string) string {
	return sanitizeClaimedID(s, maxRefusalDetailLen)
}

func addClaimedSessionID(details map[string]interface{}, r *http.Request) map[string]interface{} {
	return addClaimedSessionIDValue(details, r.Header.Get(SessionHeader))
}

// addClaimedSessionIDValue is addClaimedSessionID's request-independent core: every rule
// (empty-header no-op, nil-details allocation, sanitize/bound, the truncated flag) lives
// here once, so a caller that already holds the extracted header value — killSubject,
// which stores the string rather than the *http.Request precisely to avoid re-deriving it
// — gets the identical treatment through one call instead of a second implementation.
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
// lookup — a rejected Origin, JWT, static bearer, or control token. It centralizes the
// forgery guard those four share: the structured session_id is left EMPTY (at this point
// the client-supplied Mcp-Session-Id is unverified and attacker-controlled, so stamping
// it as session_id would let anyone forge these records against a victim's session),
// while the claimed value is preserved as the clearly-unverified details.claimed_session_id
// via addClaimedSessionID. The presented credential is NEVER passed in — callers supply
// only non-secret context (source_ip, origin, error_type) in extra. A nil sink skips the
// record. Folding the four sites here keeps the empty-session_id rule from being
// re-hand-rolled — and re-broken — at each new pre-session refusal path.
// Writes are rate-limited (see newPreSessionDenyLimiter): these are the only audit records an
// unauthenticated caller can trigger, so an unbounded one-per-refusal write lets a remote
// attacker drive the audit queue into its monotonic drop counter and permanently trip
// --require-audit=strict against every legitimate client. A suppressed refusal is folded
// into the next admitted record's suppressed_refusal_count rather than vanishing — into
// whichever record of the SAME category is admitted next, which need not be on the same
// route, hence the suppressed_refusal_scope that ships beside it.
//
// These records deliberately carry NO route name and no policy_version/policy_sha256
// stamp: they are written through the proxy-wide p.sink rather than a route's
// routeSink, because these callers fire before route resolution — and stay there on
// purpose, since resolving the route first would turn the 404-vs-401 split into an
// oracle for enumerating route names. An auditor diffing record shapes should read
// the missing stamp as "refused before any route was chosen", not as a stamping bug.
// The one refusal that DOES know its route by the time it fires — the session cap —
// goes through recordSessionCapDeny instead, which keeps this rate limiter and this
// claimed_session_id rule but writes through the route's sink so its record carries the
// same route stamp as its in-flight-cap sibling.
// It returns the rate limiter's verdict (see recordRefusal), which a caller pairs its own
// stderr diagnostic with so both halves of a refusal are bounded by one decision.
func (p *HTTPProxy) recordPreSessionDeny(r *http.Request, code string, category refusalCategory, extra map[string]interface{}) bool {
	return p.recordRefusal(r, nil, code, category, extra)
}

// recordSessionCapDeny records a session-cap refusal — the pre-spawn slot reservation and
// the errSessionLimit leg of writeSessionCreateError, the two halves of one condition.
//
// It writes RESOURCE_EXHAUSTED through the ROUTE's sink, so the record carries the route
// name and policy stamp exactly like the per-session in-flight cap's record: one denial
// code, one record shape, whichever cap the flood hit. What it does NOT drop is the rate
// limit — unlike the in-flight cap, this refusal is reachable WITHOUT an established
// session, so an unbounded write here would hand a remote caller the audit-queue flooding
// primitive the pre-session bucket exists to deny.
//
// It is therefore the one refusal that can be route-stamped AND carry a rollup from a
// bucket whose tally spans every route. The rollup names its own scope
// (detailSuppressedRefusalScope: suppressedScopeProxyCategory) precisely so this record's
// stamp is not read as qualifying the number: `upstream: github` with a count of 5000
// means 5000 saturation refusals across every route, not 5000 against github. The count
// covers only this record's own CATEGORY, which is what the per-category buckets made
// true — it is not a tally of the Origin/JWT/auth floods a reader of the old shared-bucket
// wording would have folded in.
func (p *HTTPProxy) recordSessionCapDeny(r *http.Request, route *UpstreamRoute) {
	p.recordRefusal(r, route, codeResourceExhausted, catSaturation, map[string]interface{}{
		"reason": "session_limit_reached",
	})
}

// recordRefusal is the shared body of the two above: rate-limit, fold any suppressed
// count in, stamp the source IP and the unverified claimed_session_id, and write through
// route's sink when the route is already known (nil ⟹ the proxy-wide sink).
// It returns whether the refusal was ADMITTED by the rate limiter, so a caller whose own
// stderr diagnostic is part of the same flood (checkOrigin's ~600-byte SECURITY line) can
// gate it on the same verdict. Rate-limiting the tape while leaving the log line per-request
// left the cheapest half of the primitive open: an unauthenticated caller could still drive
// unbounded log volume through a rejected Origin.
func (p *HTTPProxy) recordRefusal(r *http.Request, route *UpstreamRoute, code string, category refusalCategory, extra map[string]interface{}) bool {
	rec := asRecorder(p.sink)
	if route != nil {
		rec = asRecorder(route.sink)
	}
	if rec == nil {
		// No sink configured: there is no tape to flood and no bucket to charge, and the
		// caller's stderr line is the only surviving signal of the refusal, so it is
		// admitted. (The record-side limit is equally inert here for the same reason.)
		return true
	}
	// No nil-limiter fallback: a "defensive" branch here wrote the refusal record with
	// NO rate limit at all, which is a fail-open on the exact DoS bound this file exists
	// to enforce — and it was reachable only from an in-package test literal, since
	// NewHTTPProxyGateway always builds the limiter. A nil here is a construction bug and
	// panics like one.
	ok, suppressed := p.preSessionDenies.admit(category)
	if !ok {
		return false
	}
	if suppressed > 0 {
		if extra == nil {
			extra = make(map[string]interface{}, 2)
		}
		// Always paired: the count is meaningless to a reader who has to infer its scope
		// from the stamp beside it, and this record may well carry a route stamp the count
		// does not respect. See the key constants for the misreading this closes.
		extra[detailSuppressedRefusalCount] = suppressed
		extra[detailSuppressedRefusalScope] = suppressedScopeProxyCategory
	}
	rec.RecordDeny(r.Context(), "", "", "", code, string(category), p.addRefusalContext(extra, r), false)
	return true
}

// addRefusalContext stamps the two details EVERY refusal record carries about its caller:
// the resolved source IP and the unverified claimed_session_id.
//
// source_ip lives here rather than at each call site because that is how it got lost. It
// was hand-added by each of the eight callers, and the two that forgot were an
// unauthenticated Origin probe and a JWT rejection — precisely the records an incident
// responder reads to find where an attack came from. Centralizing it makes a refusal path
// added later carry the source by construction, the same way it inherits the empty
// session_id rule and the rate limit.
func (p *HTTPProxy) addRefusalContext(details map[string]interface{}, r *http.Request) map[string]interface{} {
	if details == nil {
		details = make(map[string]interface{}, 2)
	}
	details["source_ip"] = p.sourceIP(r)
	return addClaimedSessionID(details, r)
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
	// Each refusal below is recorded. loopbackOnly is the FIRST gate on /control/kill,
	// /healthz and /metrics — it runs before checkControlToken, which does record — so an
	// OFF-HOST probe of the emergency stop was the one attack against the transport surface
	// that left nothing on the tape, while the same-host caller who merely got the token
	// wrong was fully logged. The more remote attacker must not be the invisible one.
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
	// DNS-rebinding guard: also require a trusted Host. normalizeHost reduces r.Host to
	// a bare hostname the same way originAllowed's url.Hostname() reduces an Origin, so
	// the two checks agree on what they are comparing. A rebound request carries the
	// attacker's name (Host: attacker.com) and is rejected; a legitimate loopback scrape
	// uses localhost / 127.0.0.1 / ::1 / the non-wildcard bind host, all of which
	// buildAllowedOriginHosts seeds.
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
// What the guard must stop is a DNS rebind, and a rebind always presents a NAME the
// attacker controls (Host: attacker.com) — that is the mechanism: the victim's browser
// still believes it is talking to the attacker's hostname, which is what makes the
// response same-origin readable. So the rule is "reject foreign names", not "reject
// everything unlisted", and three things are admitted:
//
//   - The origin-host allowlist the constructor seeds (loopback names plus any
//     non-wildcard bind host), plus the hostnames of any listen.allowedOrigins entries —
//     together, every name checkOrigin would accept an Origin from on /mcp.
//   - Any loopback host, name or literal. A caller reaching a loopback endpoint over
//     127.0.0.2 or an alternate loopback alias is local by construction, and a browser
//     cannot be steered into sending a loopback LITERAL as the Host of a rebound page:
//     fetching the literal directly is cross-origin, so it carries an Origin and
//     requireValidOrigin (which wraps every route) rejects it first.
//   - A genuinely ABSENT Host. HTTP/1.1 requires the header and every browser sends it, so
//     no value at all is a non-browser local caller (an HTTP/1.0 liveness probe, a
//     hand-rolled client) and cannot be a rebind.
//
// The absent-Host allowance keys off rawHost — the header as received — NOT off the
// normalized value. normalizeHost reduces a PRESENT but host-less value to the empty
// string: net.SplitHostPort succeeds on ":8080" and returns host "", and "[]" reduces the
// same way. Gating on the normalized value therefore admitted `Host: :8080`, which is a
// header that was sent, so the "no value means non-browser caller" reasoning does not hold
// for it and the whole rebinding pin was skippable by any caller able to set a raw Host
// line.
//
// The source-IP loopback check remains the primary gate; this is the rebinding layer on
// top of it.
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
	// A host the operator explicitly allowlisted as a trusted Origin is, by definition, not
	// a foreign name — it is the same trust decision checkOrigin already makes for the more
	// sensitive /mcp route. Omitting it made these endpoints stricter than /mcp, contrary to
	// this function's own contract.
	if p.loopbackPinHosts[reqHost] {
		return true
	}
	return capability.IsLoopbackHost(reqHost)
}
