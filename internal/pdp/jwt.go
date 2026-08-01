// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// JWT PDP mode for IdP-issued capability claims (--jwks-uri).
//
// When --jwks-uri is set the proxy validates the Authorization: Bearer token on
// every HTTP request, extracts MCP capability claims, translates them into
// capability.Constraint values, and evaluates them on each MCP call.
//
// Claim schema (JWT schema v0.2 — Keycloak and most IdPs nest on dots):
//
//	{
//	  "mcp": {
//	    "v":             "0.2",
//	    "capabilities": ["tool:read_file?path=/reports/*", "tool:query_db?op=SELECT"],
//	    "task_id":       "task-abc123",
//	    "agent_id":      "agent-xyz"
//	  }
//	}
//
// Claim shorthand (v0.2): "<namespace>:<name>[?<key>=<value>[&<key>=<value>…]]"
//
//	"tool:read_file"                       → tools/call for read_file, no conditions
//	"tool:read_file?path=/reports/*"       → AllowedValues(path=/reports/*)
//	"tool:query_db?op=SELECT"              → AllowedOperations=[SELECT] (scan-all-args)
//	"tool:query_db?op=SELECT&table=sales"  → op=SELECT AND table=sales
//	"resource:file:///data/*"              → resources/read for file:///data/*
//	"resource:https://api/data?format=json"→ resources/read; the "?…" is the URI's
//	                                          query string, NOT a condition suffix
//	"prompt:code_review"                   → prompts/get for code_review
//
// The optional "?…" suffix follows the form-urlencoded convention (§ 4.2): pairs
// split on '&', key from value on '=', combined with logical AND; each value is
// percent-decoded ('+' → space) before matching. Keys MUST NOT be percent-encoded;
// an encoded key, a pair missing '=', or any unparseable suffix rejects the token
// (HTTP 401).
//
// Exception for http(s) resources: when the value is an http(s) URL, '?' begins the
// URL's query component, not a condition list, so the whole URL is kept as the
// resource name (otherwise the URL is truncated and misread as a never-satisfiable
// condition). Other schemes still treat '?' as the condition separator. When
// matching (matchClaimBare) a query-bearing claim pins the query exactly; a
// query-less claim is a path-only wildcard accepting any target query — there is no
// glob syntax for the query component.
//
// Condition keys: "op" → AllowedOperationsCondition (scan-all-args); any other key
// → AllowedValuesCondition on the named argument. "op=" is best-effort first-word
// matching that does NOT parse SQL (stacked/CTE-wrapped statements escape it) — pair
// it with a least-privilege database role; the manifest form (Pattern C) names the
// argument and is preferred.
//
// EXPERIMENTAL: the mcp.capabilities claim schema (the whole "capabilities"
// feature described above) is experimental and OFF by default. Enforcement requires
// --jwt-experimental-capabilities (JWTPDPOptions.ExperimentalCapabilities). With the
// flag unset, a token carrying mcp.capabilities is rejected at validation (HTTP 401,
// fail closed) rather than admitted with its capability restriction silently dropped
// — the latter would fail open. JWT signature/exp/iss/aud verification and the
// identity claims (sub, mcp.task_id, mcp.agent_id) are stable and always active,
// independent of the flag. The claim format may change before 1.0.
//
// When both --jwks-uri and --policy are set AND the flag is on, the intersection is
// taken: JWT claims can only restrict what the manifest allows, never expand it.
//
// Breaking change from v0.1: tokens with mcp.v other than "0.2" are rejected
// (HTTP 401); the v0.1 colon-only shorthand is not accepted.

package pdp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/circuitbreaker"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// jwtClaimsKey is the unexported context key type for JWT claims.
type jwtClaimsKey struct{}

// JWTClaims holds the MCP capability claims extracted from an IdP JWT.
type JWTClaims struct {
	Capabilities []string
	// HasCapabilities is true when the JWT contained the mcp.capabilities
	// array (even if it was empty).  When false, the JWT carries no
	// capability restriction and decisions fall through to the manifest PDP.
	HasCapabilities bool
	TaskID          string
	AgentID         string
	Subject         string
	Issuer          string
	// Audiences is the token's verified `aud` claim (always a list; a scalar aud
	// decodes to a one-element slice). Captured so a per-route JWTPDP wrapper can pin
	// its own audience after the shared validator has accepted the token — see
	// JWTPDP.routeAudience and WrapRoutesWithJWT. Empty when the token carried no aud.
	Audiences []string
	// ExpiresAt is the verified token's `exp` as a wall-clock time. ValidateToken
	// rejects a token with no exp, so this is always set on a validated JWTClaims; it is
	// the zero Time for a JWTClaims built without ValidateToken (e.g. tests). A long-lived
	// server->client stream (an SSE GET) is validated only once at open, so the transport
	// arms a timer at this instant to end the stream when the token's lifetime elapses —
	// otherwise an expired (or IdP-revoked but not kill-switched) client keeps receiving
	// traffic until it disconnects or the idle reaper runs. Kill-switch eviction covers
	// administrative revocation; this covers plain expiry.
	ExpiresAt time.Time
	// Extra holds every raw top-level claim from the verified token, keyed exactly
	// as the IdP emitted it (standard fields, the nested mcp object, custom claims).
	// It is the source of input.claims (see jwtClaimsAsMap), so a policy can
	// reference any IdP claim. Populated only after signature verification; nil when
	// no token was parsed.
	Extra map[string]interface{}

	// parsedCaps caches the cheap-phase parse of Capabilities (parseCapHeads),
	// computed once at validation, so later Decides skip re-parsing each claim's head.
	// Nil for a JWTClaims built without ValidateToken (e.g. tests), where Decide falls
	// back to parsing Capabilities directly.
	parsedCaps []capHead

	// flatClaims caches the flattened input.claims map (see buildFlatClaims / the
	// jwtClaimsAsMap doc), computed ONCE at validation. Every enforced request, list
	// filter, and sampling decision consumes it read-only, so rebuilding it per call
	// (copying every Extra entry each time) was pure repeated work — JWTClaims is
	// immutable after validation. Populated eagerly at validation (not lazily) because
	// the *JWTClaims is shared across a session's requests, so a lazy write would race
	// concurrent readers. Nil for a JWTClaims built without ValidateToken, where
	// jwtClaimsAsMap falls back to computing the map on the fly (never storing it).
	// MUST be treated as read-only by every consumer (it is handed to third-party
	// PolicyEvaluators).
	flatClaims map[string]interface{}
}

// WithJWTClaims returns a child context carrying the given JWT claims.
func WithJWTClaims(ctx context.Context, claims *JWTClaims) context.Context {
	return context.WithValue(ctx, jwtClaimsKey{}, claims)
}

// jwtClaimsFromContext retrieves JWT claims from the context.
func jwtClaimsFromContext(ctx context.Context) (*JWTClaims, bool) {
	c, ok := ctx.Value(jwtClaimsKey{}).(*JWTClaims)
	return c, ok && c != nil
}

// AuditIdentityFromContext returns the agent/task/user identity from any validated
// JWT claims in ctx (empty strings when none). The user identity is the token
// subject (sub), the human/principal the agent acts for. Wired into the audit sink
// via audit.WithIdentity so it stamps IdP identity without importing the JWT layer.
func AuditIdentityFromContext(ctx context.Context) (agentID, taskID, userID string) {
	if c, ok := jwtClaimsFromContext(ctx); ok {
		return c.AgentID, c.TaskID, c.Subject
	}
	return "", "", ""
}

// mcpClaimVersion is the only accepted value for the mcp claim set's "v" field.
// Other versions (including the legacy "0.1") are rejected so a schema change is
// caught early rather than silently misinterpreted.
const mcpClaimVersion = "0.2"

// mcpClaimSet holds the MCP-specific fields nested under the "mcp" key (IdPs treat
// dots in a claim name as path separators, so "mcp.capabilities" nests).
//
// Capabilities is a pointer to distinguish "field absent" (nil) from "present but
// empty" (&[]string{}): per the exhaustive-allowlist rule (§ 5.2) a present-empty
// array denies everything, whereas an absent field defers to the manifest.
type mcpClaimSet struct {
	Version      string    `json:"v"`
	Capabilities *[]string `json:"capabilities,omitempty"` // nil ⟹ field absent
	TaskID       string    `json:"task_id"`
	AgentID      string    `json:"agent_id"`
}

// idpJWTPayload is the subset of IdP JWT claims relevant to MCP enforcement.
// Standard JWT fields (iss, sub, exp, iat, aud) are parsed separately by
// jwt.Claims; this struct handles only the MCP-specific custom claims.
type idpJWTPayload struct {
	MCP mcpClaimSet `json:"mcp"`
}

// JWTPDP validates IdP-issued JWTs and enforces capability claims.
//
// When inner is non-nil (i.e. --policy is also set), the JWTPDP computes the
// intersection: a call is allowed only if both the JWT claims and the manifest
// policy allow it.
type JWTPDP struct {
	cache            *capability.JWKSCache
	issuer           string
	audience         string
	allowAnyAudience bool // --jwt-allow-any-audience: skip audience pinning entirely
	allowAnyIssuer   bool // --jwt-allow-any-issuer: skip issuer pinning entirely
	// acceptedAudiences is the set of audiences ValidateToken accepts (go-jose
	// "at least one of"). Empty falls back to []string{audience}, so a single-upstream
	// JWTPDP keeps its existing single-audience pin. The gateway's shared validator sets
	// it to the UNION of every route's effective audience, so a token minted for ANY
	// route clears validation; each route wrapper then narrows to its own audience via
	// routeAudience. Unused by route wrappers (they read already-validated claims).
	acceptedAudiences []string
	// routeAudience is this wrapper's required audience for the per-route check in
	// Decide/filterList: the route's manifest 'audience' when it declares one, else the
	// global --jwt-audience fallback. A token is authorized on this route only if its
	// aud claim carries routeAudience. Empty (the single-upstream/shared-validator case)
	// or --jwt-allow-any-audience disables the per-route check. Set by WrapRoutesWithJWT.
	routeAudience string
	inner         PolicyDecisionPoint // optional manifest PDP for intersection
	ks            killswitch.Checker  // kill switch enforced even in JWT-only mode
	// leeway is the clock-skew grace for standard-claim (exp/nbf/iat) validation,
	// resolved from JWTPDPOptions.Leeway at construction (effectiveLeeway).
	leeway time.Duration
	// clock supplies "now" for JWT exp/nbf validation; nil falls back to the wall
	// clock. enforcement.Clock is shared with the engine and the JWKS cache so a
	// frozen test clock stays consistent across all three.
	clock enforcement.Clock
	// experimentalCapabilities gates the EXPERIMENTAL mcp.capabilities claim schema
	// (JWT v0.2). When false (the default) ValidateToken rejects any token carrying
	// mcp.capabilities (fail closed) rather than dropping its restriction (fail open);
	// identity claims and signature/exp/iss/aud verification are unaffected. Set from
	// the --jwt-experimental-capabilities flag.
	experimentalCapabilities bool
	// tokenCache memoizes verified *JWTClaims by token hash so a repeat bearer token
	// skips signature re-verification and the two claim decodes (see newJWTTokenCache).
	// Consulted only by ValidateToken (the shared validator); per-route wrappers call
	// Decide, not ValidateToken, so their cache stays empty. The kill switch, route
	// audience, and policy are still checked per call in Decide.
	tokenCache *capability.PayloadCache[*JWTClaims]
}

// JWTPDPOptions configures a JWTPDP.
type JWTPDPOptions struct {
	JWKSURI  string
	Issuer   string
	Audience string
	// AllowAnyAudience disables audience pinning (--jwt-allow-any-audience): a token
	// is accepted regardless of aud. When false (default) the audience is always
	// pinned to Audience — and when Audience (and AcceptedAudiences) is empty, EVERY
	// token is rejected regardless of its aud, including one whose aud is the literal
	// empty string. validateStandardClaims refuses outright there rather than falling
	// back to jwt.Expected{AnyAudience: [""]}, whose set-intersection match would have
	// admitted exactly those empty-aud tokens.
	AllowAnyAudience bool
	// AcceptedAudiences widens the validator's accepted-audience set beyond the single
	// Audience: a token is valid if its aud carries AT LEAST ONE entry. Empty falls back
	// to {Audience}. The gateway's shared validator sets it to the union of every route's
	// effective audience so a token for any route clears validation; each route wrapper
	// then narrows via RouteAudience. Leave empty for single-upstream (single-audience)
	// mode. Ignored when AllowAnyAudience is set.
	AcceptedAudiences []string
	// RouteAudience is the per-route required audience enforced in Decide/filterList
	// (the route's manifest 'audience', else the global Audience fallback). A token is
	// authorized on this route only if its aud carries RouteAudience. Empty disables the
	// per-route check (single-upstream, or the shared validator). Set by WrapRoutesWithJWT;
	// ignored when AllowAnyAudience is set.
	RouteAudience string
	// AllowAnyIssuer disables issuer pinning (--jwt-allow-any-issuer): a token is
	// accepted regardless of iss. When false (default) the issuer is always pinned to
	// Issuer — even when Issuer is empty, which rejects every token with a non-empty
	// iss (fail closed) rather than accepting any issuer that shares the JWKS.
	AllowAnyIssuer bool
	// Inner is the manifest PDP for intersection when both --jwks-uri and --policy
	// are set. When nil, only JWT claims are enforced.
	Inner PolicyDecisionPoint
	// KillSwitch is consulted at the top of every Decide so global and
	// per-session/per-agent kills take effect even in JWT-only mode.
	KillSwitch killswitch.Checker
	// CacheTTL is how long a fetched JWKS is served from cache (default 5 minutes,
	// see capability.JWKSCacheConfig). It governs KEY freshness only.
	//
	// It does NOT govern the verified-token claim cache, which memoizes an
	// already-verified token's claims for a FIXED window (jwtTokenCacheTTL, 30s) that
	// no option exposes — so lowering CacheTTL to tighten key-rotation latency does not
	// tighten how long a token stays trusted. That window is deliberately not
	// operator-tunable: it is capped by the token's own exp, and the kill switch,
	// per-route audience, and manifest policy are re-checked on every call, so the
	// cache skips only the signature/exp/iss/aud re-verification. Revocation latency
	// is therefore bounded by the kill switch, not by this TTL.
	CacheTTL time.Duration
	Client   *http.Client
	// Breaker optionally guards JWKS fetches. When nil, NewJWTPDP installs one with
	// circuitbreaker.DefaultConfig; supply one to override the config or clock.
	Breaker *circuitbreaker.Breaker
	// Clock supplies "now" for JWT exp/nbf validation; nil uses the wall clock,
	// tests inject a frozen clock.
	Clock enforcement.Clock
	// Leeway is the clock-skew grace for standard JWT claim validation. Zero selects
	// DefaultJWTLeeway; a negative value disables leeway (exp must be strictly future).
	Leeway time.Duration
	// ExperimentalCapabilities enables enforcement of the EXPERIMENTAL mcp.capabilities
	// claim schema (JWT v0.2). When false (the default), ValidateToken rejects a token
	// carrying mcp.capabilities (HTTP 401, fail closed) instead of silently ignoring its
	// capability restriction; identity-only tokens and all signature/exp/iss/aud checks
	// are unaffected. Wired from the --jwt-experimental-capabilities flag.
	ExperimentalCapabilities bool
}

// DefaultJWTLeeway is the clock-skew grace applied to standard JWT claim
// validation when JWTPDPOptions.Leeway is left at its zero value. It aliases
// capability.DefaultTokenLeeway, the one source of truth for every JWKS-verified
// token-validation path in the binary.
const DefaultJWTLeeway = capability.DefaultTokenLeeway

// effectiveLeeway resolves the configured leeway (zero → default, negative →
// disabled, positive → as-is) via capability.EffectiveLeeway so the two token
// paths cannot diverge.
func effectiveLeeway(configured time.Duration) time.Duration {
	return capability.EffectiveLeeway(configured)
}

// jwtLogger pins JWT/JWKS logging to stderr: stdout is the JSON-RPC channel in stdio
// mode, so logging must never inherit a slog default that could corrupt the framing.
// Package-level so the constructor's misconfiguration warnings and the parser-drift
// warnings in parseCapHeads (which has no receiver to reach a field) emit through the
// SAME handler — those drift warnings used to be raw fmt.Fprintf lines, unstructured
// and impossible to correlate in a SIEM alongside every other line this package emits.
var jwtLogger = slog.New(slog.NewTextHandler(os.Stderr, nil))

// NewJWTPDP creates a JWTPDP ready to validate tokens.
func NewJWTPDP(opts JWTPDPOptions) *JWTPDP {
	// Default breaker so the shipped proxy always has JWKS-fetch protection;
	// capability.NewJWKSCache leaves it opt-in, so apply it here.
	breaker := opts.Breaker
	if breaker == nil {
		breaker = circuitbreaker.New(circuitbreaker.DefaultConfig())
	}
	logger := jwtLogger
	if normalizeAudience(opts.Audience) == "" && len(sanitizeAudiences(opts.AcceptedAudiences)) == 0 && !opts.AllowAnyAudience {
		// No audience pinned but not opted out: EVERY token is rejected regardless of
		// its aud claim (fail closed), mirroring the issuer check below — there is no
		// pinned audience to trust, so a token cannot clear validation, including one
		// that sets aud to the literal empty string (or a whitespace-only pin, which
		// normalizeAudience collapses to none). Likely a misconfiguration, so surface it.
		logger.Warn("JWTPDP created without an Audience and without AllowAnyAudience; all tokens will be rejected regardless of aud because no audience is pinned (set --jwt-audience, or --jwt-allow-any-audience to accept any)")
	}
	if opts.Issuer == "" && !opts.AllowAnyIssuer {
		// No issuer pinned but not opted out: EVERY token is rejected regardless of its
		// iss claim (fail closed) — unlike the audience check, an empty p.issuer makes
		// the comparison reject even a token with no iss at all, so identity-only tokens
		// do not slip through. Likely a misconfiguration, so surface it.
		logger.Warn("JWTPDP created without an Issuer and without AllowAnyIssuer; all tokens will be rejected regardless of iss because no issuer is pinned (set --jwt-issuer, or --jwt-allow-any-issuer to accept any)")
	}
	cacheConfig := capability.JWKSCacheConfig{
		JWKSURL:  opts.JWKSURI,
		CacheTTL: opts.CacheTTL,
		Client:   opts.Client,
		Breaker:  breaker,
		Logger:   logger,
	}
	// Wire the injected clock into the cache so a frozen clock stays consistent
	// across exp/nbf validation, the engine, and the cache TTL. A nil clock leaves
	// Now unset (the cache defaults to time.Now).
	if opts.Clock != nil {
		cacheConfig.Now = opts.Clock.Now
	}
	p := newJWTPDP(opts, capability.NewJWKSCache(cacheConfig))
	// Wire the verified-token cache to the PDP's clock so a frozen test clock stays
	// consistent with exp/nbf validation and the cache TTL. Only a VALIDATOR gets one:
	// the cache is written solely by ValidateToken, which the transport calls on the
	// shared validator alone. A gateway route wrapper (NewJWTPDPWithCache) only
	// intersects already-validated claims, so its cache could never hold an entry —
	// N-1 caches allocated to stay empty for the process lifetime. PayloadCache's
	// Get/Put are nil-receiver safe, so leaving it nil there is simply the miss path.
	p.tokenCache = newJWTTokenCache(p.now)
	return p
}

// normalizeAudience collapses a whitespace-only audience to the empty string so the
// single-audience fail-closed guard in validateStandardClaims (which tests == "")
// rejects every token when no real audience is pinned. A non-empty audience is
// returned byte-for-byte unchanged, so an audience with surrounding spaces (unusual
// but the operator's choice) still matches exactly.
func normalizeAudience(aud string) string {
	if strings.TrimSpace(aud) == "" {
		return ""
	}
	return aud
}

// sanitizeAudiences drops empty and whitespace-only entries from an accepted-audience
// list. An empty ("" or "   ") entry is a fail-open hole: go-jose matches audiences by
// set intersection, so an expected AnyAudience carrying "" ACCEPTS a token whose own
// aud is the literal empty string — the empty sentinel does not reject everything as
// intended, it silently admits empty-aud tokens. Non-empty entries are left unchanged
// so real audiences keep matching exactly. Returns a fresh slice (never aliases the
// caller's). When every entry is dropped the result is empty, so validateStandardClaims
// falls back to the single-audience path and its == "" guard fails closed.
func sanitizeAudiences(auds []string) []string {
	if len(auds) == 0 {
		return auds
	}
	out := make([]string, 0, len(auds))
	for _, a := range auds {
		if strings.TrimSpace(a) != "" {
			out = append(out, a)
		}
	}
	return out
}

// newJWTPDP assembles a JWTPDP from opts and an already-resolved JWKS cache. Both
// NewJWTPDP (which builds its own cache) and NewJWTPDPWithCache (which shares an
// existing one) route through this, so the field set is defined once and the two
// constructors cannot drift when a field is added.
func newJWTPDP(opts JWTPDPOptions, cache *capability.JWKSCache) *JWTPDP {
	p := &JWTPDP{
		cache:  cache,
		issuer: opts.Issuer,
		// Normalize a whitespace-only audience to "" so the fail-closed guard in
		// validateStandardClaims (which tests p.audience == "") catches it, and drop any
		// empty/whitespace entry from acceptedAudiences: go-jose matches audiences by set
		// intersection, so an AnyAudience carrying "" would ACCEPT a token whose own aud is
		// the literal empty string (see sanitizeAudiences). The shipped wiring already
		// rejects an empty effective audience one seam away (transport/route.go + the CLI),
		// so this is defense in depth for a direct JWTPDPOptions consumer and for the
		// whitespace case == "" misses.
		audience:                 normalizeAudience(opts.Audience),
		allowAnyAudience:         opts.AllowAnyAudience,
		acceptedAudiences:        sanitizeAudiences(opts.AcceptedAudiences),
		routeAudience:            opts.RouteAudience,
		allowAnyIssuer:           opts.AllowAnyIssuer,
		inner:                    opts.Inner,
		ks:                       opts.KillSwitch,
		clock:                    opts.Clock,
		leeway:                   effectiveLeeway(opts.Leeway),
		experimentalCapabilities: opts.ExperimentalCapabilities,
	}
	return p
}

// NewJWTPDPWithCache builds a per-route JWTPDP sharing an already-constructed JWKS
// cache instead of allocating its own. The gateway wraps every route in a JWTPDP
// that only intersects already-validated claims against that route's manifest;
// route wrappers never fetch keys, so building a fresh JWKSCache per route would
// waste N-1 allocations. No audience warning here — the shared validator (built via
// NewJWTPDP) already warns once.
func NewJWTPDPWithCache(opts JWTPDPOptions, cache *capability.JWKSCache) *JWTPDP {
	return newJWTPDP(opts, cache)
}

// Cache returns the JWKS cache this validator owns, so a gateway can build
// per-route wrappers (NewJWTPDPWithCache) that share one key-fetching cache.
func (p *JWTPDP) Cache() *capability.JWKSCache {
	return p.cache
}

// innerEnforces reports whether p.inner is a real policy backstop able to decide an
// identity-only (no mcp.capabilities) request. A nil inner or an AlwaysAllowPDP
// (value or pointer form) is not: in JWT mode the JWTPDP must fail closed rather
// than inherit alwaysAllow's allow-everything. A ManifestPDP (even a deny-all one)
// is a backstop. Derived from p.inner rather than cached so every construction path
// is consistent.
func (p *JWTPDP) innerEnforces() bool {
	switch p.inner.(type) {
	case nil:
		return false
	case AlwaysAllowPDP, *AlwaysAllowPDP:
		return false
	default:
		return true
	}
}

// decodeJWTClaimsPreservingNumbers decodes the top-level claim map from a compact
// JWS (header.payload.signature) using json.Number, so integer claims above 2^53
// are preserved exactly instead of rounded through float64 (which go-jose's
// UnsafeClaimsWithoutVerification does). The caller verifies the signature first,
// so the payload is authentic; this re-decodes those bytes only to keep numeric
// precision for input.claims.
func decodeJWTClaimsPreservingNumbers(tokenStr string) (map[string]interface{}, error) {
	parts := strings.Split(tokenStr, ".")
	// A JWS compact serialization has exactly three segments. Reject anything else
	// (fail closed) in case a future caller invokes this before verification.
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed JWT: expected 3 segments (header.payload.signature), got %d", len(parts))
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding JWT payload segment: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(payloadBytes))
	dec.UseNumber()
	var claims map[string]interface{}
	if err := dec.Decode(&claims); err != nil {
		return nil, fmt.Errorf("decoding claims: %w", err)
	}
	// Reject trailing bytes after the JSON object (fail closed), matching the
	// trailing-data guard the audit decoders use. A well-formed JWT payload is a
	// single JSON object; trailer bytes signal a non-conforming issuer.
	if dec.More() {
		return nil, fmt.Errorf("trailing data in JWT claims payload")
	}
	return claims, nil
}

// Stable JWT-failure category codes recorded as the JWT_INVALID audit record's
// error_type detail. They are a closed set so a record never carries the raw
// go-jose / validation message (which can disclose claim values, the accepted
// algorithm, the configured issuer, or key-rotation state to a SIEM downstream).
const (
	jwtErrMalformedHeader      = "malformed_authorization_header"
	jwtErrMalformedToken       = "malformed_token"
	jwtErrSignature            = "invalid_signature"
	jwtErrExpired              = "expired"
	jwtErrNotYetValid          = "not_yet_valid"
	jwtErrIssuedInFuture       = "issued_in_future"
	jwtErrInvalidAudience      = "invalid_audience"
	jwtErrInvalidIssuer        = "invalid_issuer"
	jwtErrMissingClaims        = "missing_claims"
	jwtErrUnsupportedVersion   = "unsupported_version"
	jwtErrCapabilitiesDisabled = "capabilities_disabled"
	jwtErrInvalidCapabilities  = "invalid_capabilities"
	jwtErrSenderConstrained    = "sender_constrained"
	// jwtErrJWKSUnavailable marks a validation that failed because the key set could
	// not be fetched (network error, non-200, empty/oversized set, open breaker), not
	// because the token was bad — the token was never checked against a key. Keeping it
	// distinct from "invalid" stops an IdP/JWKS outage from being recorded identically
	// to a forged token in the fail-closed audit trail.
	jwtErrJWKSUnavailable = "jwks_unavailable"
	jwtErrUnknown         = "invalid"
)

// jwtValidationError tags a ValidateToken failure with a stable category code while
// preserving the descriptive message for the validator's own logs and tests.
// ClassifyJWTError reads the code via errors.As, so the wrapping order through
// capability.Terminal (which Unwraps) does not matter.
type jwtValidationError struct {
	code string
	err  error
}

func (e *jwtValidationError) Error() string { return e.err.Error() }
func (e *jwtValidationError) Unwrap() error { return e.err }

// jwtErr tags err with a stable classification code (see ClassifyJWTError). The
// returned error prints exactly as err, so existing message-substring tests and
// the terminal-error detection in VerifyWithKeyRotation are unaffected.
func jwtErr(code string, err error) error { return &jwtValidationError{code: code, err: err} }

// ClassifyJWTError maps a ValidateToken error to a small, stable category code for
// the JWT_INVALID audit record. It NEVER returns the raw error text: the underlying
// go-jose / validation message can disclose claim values, the accepted algorithm,
// the configured issuer, or key-rotation state, and audit logs are routinely
// forwarded to third-party SIEMs — the same disclosure the opaque-401 HTTP response
// avoids. Operators get the failure category; the verbose message stays with the
// validator. An empty error yields "" and an unrecognized one yields "invalid".
func ClassifyJWTError(err error) string {
	if err == nil {
		return ""
	}
	// An eunox-tagged site states its category explicitly; honor it first.
	var ve *jwtValidationError
	if errors.As(err, &ve) {
		return ve.code
	}
	// The untagged standard-claim path (stdClaims.ValidateWithLeeway) emits only
	// these sentinels under eunox's Expected{Time, AnyAudience}: expiry, not-before,
	// future-iat, and audience. Issuer and subject failures do NOT arrive here — eunox
	// runs its own iss/sub checks and tags them (caught by errors.As above), and go-jose
	// skips its built-in iss/sub validation because Expected leaves those fields unset.
	// A signature mismatch surfaces as jose.ErrCryptoFailure from the verify closure.
	switch {
	case errors.Is(err, capability.ErrJWKSUnavailable):
		// A fetch/refresh failure (network, non-200, empty/oversized set, open breaker)
		// propagated up through VerifyWithKeyRotation's "fetch JWKS"/"refresh JWKS" wraps.
		// The token was never checked against a key, so this is an infrastructure outage,
		// not an invalid token — classify it as such rather than collapsing to "invalid".
		return jwtErrJWKSUnavailable
	case errors.Is(err, jwt.ErrExpired):
		return jwtErrExpired
	case errors.Is(err, jwt.ErrNotValidYet):
		return jwtErrNotYetValid
	case errors.Is(err, jwt.ErrIssuedInTheFuture):
		return jwtErrIssuedInFuture
	case errors.Is(err, jwt.ErrInvalidAudience):
		return jwtErrInvalidAudience
	case errors.Is(err, jose.ErrCryptoFailure):
		return jwtErrSignature
	default:
		return jwtErrUnknown
	}
}

// newValidatedClaims assembles the *JWTClaims a successful ValidateToken returns,
// memoizing at validation the two derived views later per-request decisions reuse:
// the parsed capability heads (parsedCaps) and the flattened input.claims map
// (flatClaims). Both are computed once here so decide/list-filter/sampling calls hand
// out precomputed values instead of re-parsing/re-building per request.
func newValidatedClaims(capsList []string, capsPresent bool, payload idpJWTPayload, std jwt.Claims, rawClaims map[string]interface{}) *JWTClaims {
	claims := &JWTClaims{
		Capabilities:    capsList,
		HasCapabilities: capsPresent,
		TaskID:          payload.MCP.TaskID,
		AgentID:         payload.MCP.AgentID,
		Subject:         std.Subject,
		Issuer:          std.Issuer,
		// Carry the verified aud so a per-route wrapper can pin its own audience
		// (routeAudience) after the shared validator accepted the token.
		Audiences:  []string(std.Audience),
		Extra:      rawClaims,
		parsedCaps: parseCapHeads(capsList),
	}
	// Capture the verified exp as wall-clock time so a long-lived SSE stream can bound
	// itself to the token lifetime. validateStandardClaims (run before this) rejects a
	// token with no exp, so std.Expiry is non-nil on the ValidateToken path; guard anyway
	// for any other caller.
	if std.Expiry != nil {
		claims.ExpiresAt = std.Expiry.Time()
	}
	claims.flatClaims = buildFlatClaims(claims)
	return claims
}

// validateStandardClaims enforces the RFC 7519 standard claims on an already
// signature-verified token and returns the token's exp (Unix seconds) so the caller
// can cap the verified-token cache TTL at it. now is the single lazily-sampled
// validation clock, so exp/nbf are deterministic across key-rotation retries. Every
// returned error is capability.Terminal-wrapped (verified-but-invalid, not a
// retryable signature failure). Extracted from ValidateToken so that hot path stays
// under the cyclomatic-complexity budget.
func (p *JWTPDP) validateStandardClaims(stdClaims jwt.Claims, now time.Time) (int64, error) {
	// Require iat explicitly: go-jose validates it only when present, so an iat-absent
	// token has no lower temporal bound. Reject before the exp check.
	if stdClaims.IssuedAt == nil {
		return 0, capability.Terminal(jwtErr(jwtErrMissingClaims, fmt.Errorf("token has no iat claim; tokens without an issued-at time are rejected")))
	}
	// Require exp explicitly: go-jose checks Expiry only when present, so an exp-absent
	// token would never expire, defeating expiry and revocation.
	if stdClaims.Expiry == nil {
		return 0, capability.Terminal(jwtErr(jwtErrMissingClaims, fmt.Errorf("token has no exp claim; non-expiring tokens are rejected")))
	}
	// Pin the audience unless --jwt-allow-any-audience. go-jose skips the audience check
	// when AnyAudience is nil, so the default path always sets it. acceptedAudiences
	// widens the set for the gateway shared validator (the UNION of every route's
	// effective audience) so a token minted for ANY route clears validation here; the
	// per-route wrapper then narrows to its own audience (routeAudience) in Decide.
	//
	// When neither is configured (p.audience == "" and no acceptedAudiences — the
	// misconfigured case NewJWTPDP warns about), reject explicitly here rather than
	// falling back to jwt.Expected{AnyAudience: [""]}: go-jose's audience check matches
	// by set intersection, so an AnyAudience of [""] accepts a token whose own aud claim
	// is the literal empty string — the sentinel does NOT reject everything as intended,
	// only tokens with a non-empty aud. Mirror the issuer check just below (an explicit
	// Go comparison, not a library sentinel) so misconfiguration means a real total
	// rejection regardless of the token's aud claim.
	if !p.allowAnyAudience && len(p.acceptedAudiences) == 0 && p.audience == "" {
		return 0, capability.Terminal(jwtErr(jwtErrInvalidAudience, fmt.Errorf("no audience is pinned (jwt-audience unset and jwt-allow-any-audience not set); all tokens are rejected regardless of aud")))
	}
	expected := jwt.Expected{Time: now}
	if !p.allowAnyAudience {
		if len(p.acceptedAudiences) > 0 {
			expected.AnyAudience = p.acceptedAudiences
		} else {
			expected.AnyAudience = []string{p.audience}
		}
	}
	if err := stdClaims.ValidateWithLeeway(expected, p.leeway); err != nil {
		return 0, capability.Terminal(fmt.Errorf("token claims invalid: %w", err))
	}
	// Pin the issuer unless --jwt-allow-any-issuer. Mirroring the audience check, the
	// default path always enforces it — even when p.issuer is empty, where the
	// `p.issuer == ""` disjunct rejects EVERY token regardless of its iss (there is no
	// pinned issuer to trust; leaving it unchecked would accept any issuer whose signing
	// key happens to be in the shared JWKS). Only the deliberate opt-out skips it.
	if !p.allowAnyIssuer && (p.issuer == "" || stdClaims.Issuer != p.issuer) {
		return 0, capability.Terminal(jwtErr(jwtErrInvalidIssuer, fmt.Errorf("token issuer %q does not match expected %q", stdClaims.Issuer, p.issuer)))
	}
	return stdClaims.Expiry.Time().Unix(), nil
}

// ValidateToken validates the Authorization: Bearer token in the request,
// extracts eunox claims, and returns a new context carrying the claims.
// On failure it returns an error whose message is safe to surface as HTTP 401.
func (p *JWTPDP) ValidateToken(ctx context.Context, authHeader string) (context.Context, error) {
	// RFC 7235 §2.1: the auth-scheme is case-insensitive, so match it with
	// EqualFold (the length guard keeps the slice in range); the token stays
	// case-sensitive.
	const prefix = "Bearer "
	if len(authHeader) < len(prefix) || !strings.EqualFold(authHeader[:len(prefix)], prefix) {
		return ctx, jwtErr(jwtErrMalformedHeader, fmt.Errorf("missing or malformed Authorization header"))
	}
	tokenStr := authHeader[len(prefix):]

	// Fast path: a token verified within the cache TTL skips signature re-verification
	// and the two claim decodes below. A miss (or a nil cache on a bare test literal)
	// falls through to full verification. The kill switch, route audience, and policy
	// are still checked per call in Decide, so this only elides the crypto + decode.
	// Hash the token once and reuse the key for the get here and the put on success,
	// so a cache miss (the cold-cache / high-churn common case) hashes only once.
	cacheKey := capability.HashTokenKey(tokenStr)
	if cached, ok := p.tokenCache.Get(cacheKey); ok {
		return WithJWTClaims(ctx, cached), nil
	}

	tok, err := jwt.ParseSigned(tokenStr, capability.JWKSAlgorithms())
	if err != nil {
		return ctx, jwtErr(jwtErrMalformedToken, fmt.Errorf("invalid JWT: %w", err))
	}

	// Select the signing key from EVERY header's kid, not a hard-coded headers[0],
	// removing the foot-gun should a multi-signature token ever reach this path.
	// A kid-less token keeps the "" (try-all-keys) sentinel: this path enforces no
	// kid-required policy.
	kids, err := capability.CandidateKIDs(tok.Headers)
	if err != nil {
		return ctx, jwtErr(jwtErrMalformedToken, err)
	}

	// The per-key verifier is the only IdP-specific part; the key-selection and
	// rotation-retry choreography lives in capability.VerifyWithKeyRotation, out of
	// this function. Per its contract the closure returns
	// (claims, nil) on success, (nil, Terminal(err)) for a verified-but-invalid
	// failure that must not be retried, and (nil, err) for a signature failure.
	//
	// Sample the validation clock lazily on the first verify call (nowSampled), and
	// re-sample once per genuine JWKS refresh (freshKeySet). Three properties:
	//   - After the key fetch, not before: sampling up front captured now ahead of a
	//     potentially slow JWKS round-trip, widening the exp window by the fetch
	//     duration — a fail-open letting a token that expires during the fetch verify.
	//     nowSampled defers the first sample until the closure runs, after GetKeys.
	//   - Pinned across a cached set: a set served from cache (including every cached
	//     kid of a multi-signature token) passes freshKeySet=false, so the exp+leeway
	//     verdict cannot flip between sibling/cached keys on network latency. nowSampled
	//     is load-bearing, not redundant: it samples on the first cached-set call where
	//     freshKeySet is false.
	//   - Re-sampled across a genuine refresh: freshKeySet is true on the first call
	//     against a set fetched mid-verify (a forced-refresh rotation retry), so a token
	//     that expires DURING a slow forced refresh is checked against the post-refresh
	//     clock, not a stale pre-refresh one. Re-sampling only moves now forward, the
	//     fail-closed direction.
	var now time.Time
	var nowSampled bool
	// tokenExpUnix captures the verified token's exp so the cache entry's TTL can be
	// capped at the token's remaining lifetime (never serving a structurally expired
	// token). Set inside the closure once exp is validated non-nil.
	var tokenExpUnix int64
	validated, err := capability.VerifyWithKeyRotationMultiKID[JWTClaims](ctx, p.cache, kids, func(key *jose.JSONWebKey, freshKeySet bool) (*JWTClaims, error) {
		if !nowSampled || freshKeySet {
			now = p.now()
			nowSampled = true
		}
		var stdClaims jwt.Claims

		// Step 1: verify the signature only. Passing just &stdClaims keeps a
		// signature mismatch reported as such (not conflated with a payload unmarshal
		// failure). A plain (un-Terminal) error marks a retryable signature failure.
		if err := tok.Claims(key, &stdClaims); err != nil {
			return nil, err
		}

		// Step 2 (signature verified): unmarshal the IdP payload and the raw
		// top-level claim map (so non-standard claims reach policies). The token bytes
		// are key-independent, so a parse failure here is terminal — retrying other
		// keys would report a later key's error over the real payload problem.
		var payload idpJWTPayload
		if err := tok.UnsafeClaimsWithoutVerification(&payload); err != nil {
			return nil, capability.Terminal(jwtErr(jwtErrMalformedToken, fmt.Errorf("jwt payload unmarshal: %w", err)))
		}
		// Re-decode the raw claims with json.Number so a custom integer claim above
		// 2^53 survives intact for input.claims instead of rounding through float64
		// (which could flip an OPA/Cedar comparison). The signature was verified, so
		// the payload bytes are authentic.
		rawClaims, rawErr := decodeJWTClaimsPreservingNumbers(tokenStr)
		if rawErr != nil {
			return nil, capability.Terminal(jwtErr(jwtErrMalformedToken, fmt.Errorf("jwt raw claims decode: %w", rawErr)))
		}

		// Standard claims (iat/exp/audience/issuer). Returns the token's exp so the
		// verified-token cache TTL can be capped at it; now is the single lazy sample.
		exp, stdErr := p.validateStandardClaims(stdClaims, now)
		if stdErr != nil {
			return nil, stdErr
		}
		tokenExpUnix = exp

		// Distinguish an absent mcp claim (zero-value Version "") from a wrong
		// version, since the absent block is the most common IdP-template
		// misconfiguration — give it an actionable message before the version check.
		if payload.MCP.Version == "" {
			return nil, capability.Terminal(jwtErr(jwtErrMissingClaims, fmt.Errorf("jwt is missing the required mcp capability claim (expected mcp.v=%q); the token has no mcp claim block", mcpClaimVersion)))
		}
		if payload.MCP.Version != mcpClaimVersion {
			return nil, capability.Terminal(jwtErr(jwtErrUnsupportedVersion, fmt.Errorf("unsupported mcp claim version %q (want %q)", payload.MCP.Version, mcpClaimVersion)))
		}

		// A present `mcp.capabilities` of JSON null must be REJECTED, not treated as
		// absent: the *[]string pointer cannot tell absent from explicit null (both
		// decode to nil), so a `"capabilities": null` token would otherwise be
		// identity-only and bypass the exhaustive allowlist. Probe the raw claims for
		// the literal key. (Non-array values already fail the typed unmarshal above,
		// so null is the only gap.)
		if mcpRaw, ok := rawClaims["mcp"].(map[string]interface{}); ok {
			if capRaw, present := mcpRaw["capabilities"]; present && capRaw == nil {
				return nil, capability.Terminal(jwtErr(jwtErrInvalidCapabilities, fmt.Errorf("mcp.capabilities is present but null; a null capability claim is rejected — use [] for an empty (deny-all) allowlist or omit the field to defer to the manifest")))
			}
		}

		// A nil Capabilities pointer means the field was absent; a non-nil pointer
		// (even to an empty slice) means present.
		capabilitiesPresent := payload.MCP.Capabilities != nil

		// EXPERIMENTAL-feature gate. The mcp.capabilities claim schema (JWT v0.2) is
		// experimental and enforced only under --jwt-experimental-capabilities. When the
		// flag is off (the default), a token that carries the claim is rejected here (fail
		// closed) rather than admitted with its restriction silently dropped — dropping it
		// would fail open, widening access past what the token issuer intended. A token
		// that omits the claim is identity-only and unaffected, as are all the
		// signature/exp/iss/aud checks above and the identity claims below.
		if capabilitiesPresent && !p.experimentalCapabilities {
			return nil, capability.Terminal(jwtErr(jwtErrCapabilitiesDisabled, fmt.Errorf("mcp.capabilities is present but experimental capability-claim enforcement is disabled; pass --jwt-experimental-capabilities to enable the experimental JWT capability-claim intersection (JWT schema v0.2), or omit the claim to use the token for identity only")))
		}

		var capsList []string
		if capabilitiesPresent {
			capsList = *payload.MCP.Capabilities
		}

		// Every capability claim must have the v0.2 format; reject the token on any
		// malformed entry (fail closed) rather than silently ignoring it.
		for _, claim := range capsList {
			if _, _, _, err := parseV2Claim(claim); err != nil {
				return nil, capability.Terminal(jwtErr(jwtErrInvalidCapabilities, fmt.Errorf("JWT capability claim has invalid format: %w", err)))
			}
		}

		// Sub is the primary identity anchor; without it a token cannot be attributed
		// in audit records or matched against principal-scoped constraints. Reject
		// (fail closed).
		if stdClaims.Subject == "" {
			return nil, capability.Terminal(jwtErr(jwtErrMissingClaims, fmt.Errorf("JWT missing required sub claim")))
		}

		// A sender-constrained token (RFC 7800 cnf: a DPoP jkt, embedded jwk, kid
		// reference, or an RFC 8705 mTLS x5t#S256 binding) is bound to a proof-of-possession
		// key and MUST NOT be honored as a plain bearer token — the proxy has no PoP
		// verification path, so accepting one would let anyone who captured it replay it.
		// The predicate is capability.CnfIsSenderConstrained, which decodes through
		// Confirmation.IsSenderConstrained — the one canonical sender-constrained rule
		// every JWT-verification path in the binary shares. A present non-object cnf is
		// malformed and rejected as a malformed token (not mislabeled sender_constrained);
		// either way we fail closed. An explicit `"cnf": null` is the one exception: it
		// decodes to a nil value, which CnfIsSenderConstrained treats as absent — neither
		// constraining nor malformed — so it passes through like a token carrying no cnf.
		if constrained, malformed := capability.CnfIsSenderConstrained(rawClaims["cnf"]); malformed {
			return nil, capability.Terminal(jwtErr(jwtErrMalformedToken, fmt.Errorf("cnf claim is present but not a JSON object (RFC 7800 requires an object); rejecting (fail closed)")))
		} else if constrained {
			return nil, capability.Terminal(jwtErr(jwtErrSenderConstrained, fmt.Errorf("sender-constrained token (cnf) requires proof-of-possession, which the proxy does not verify; refusing to accept it as a plain bearer token (fail closed)")))
		}

		return newValidatedClaims(capsList, capabilitiesPresent, payload, stdClaims, rawClaims), nil
	})
	if err != nil {
		return ctx, err
	}
	// Cache the verified claims so a repeat of this exact token skips the work above.
	// TTL is capped at the token's remaining lifetime inside Put. Reuses the key hashed
	// once at entry. Consumers must treat the returned claims as read-only (see
	// newJWTTokenCache): the cache hands the same pointer to concurrent sessions.
	p.tokenCache.Put(cacheKey, validated, tokenExpUnix)
	return WithJWTClaims(ctx, validated), nil
}

// CheckKill consults the JWTPDP's kill switch, returning a non-nil deny when the
// session is killed (or the kill store errors, fail closed). The */list handlers
// call it before contacting the upstream so a killed session cannot enumerate the
// catalog even in JWT mode.
func (p *JWTPDP) CheckKill(ctx context.Context, sessionID string) *capability.EnforceResponse {
	return killCheck(ctx, p.clock, p.ks, sessionID)
}

// CheckAudience enforces this route's per-route audience pin at session creation, before
// any upstream is spawned or contacted. The shared validator accepts the UNION of every
// route's effective audience, so a token minted for another route clears token
// validation; this narrows to THIS route so a cross-audience token cannot spin up this
// route's upstream or read its serverInfo via the initialize handshake. The
// Decide/filterList/DecideSampling paths embed the same pin for enforced actions; this
// covers the session-creating initialize, which does not flow through them. Returns nil
// when no audience is pinned (routeAudience unset, e.g. single-upstream) or
// --jwt-allow-any-audience; a missing claim under a set pin fails closed.
func (p *JWTPDP) CheckAudience(ctx context.Context) *capability.EnforceResponse {
	if p.routeAudience == "" || p.allowAnyAudience {
		return nil
	}
	claims, ok := jwtClaimsFromContext(ctx)
	if !ok || !p.routeAudienceSatisfied(claims) {
		resp := p.audienceDeny("token audience does not satisfy the route's required audience")
		return &resp
	}
	return nil
}

// DecideResourceRead delegates to Decide with a resource target so JWT claims gate
// resource reads like tool calls.
func (p *JWTPDP) DecideResourceRead(ctx context.Context, sessionID, uri, sourceIP string) capability.EnforceResponse {
	return p.Decide(ctx, sessionID, EnforceTarget{Type: capability.TargetTypeResource, Name: uri}, nil, sourceIP)
}

// DecidePromptGet delegates to Decide with a prompt target so JWT claims gate
// prompt gets like tool calls.
func (p *JWTPDP) DecidePromptGet(ctx context.Context, sessionID, promptName, sourceIP string) capability.EnforceResponse {
	return p.Decide(ctx, sessionID, EnforceTarget{Type: capability.TargetTypePrompt, Name: promptName}, nil, sourceIP)
}

// DecideSampling implements SamplingAuthorizer. The kill switch is enforced first.
// The session's validated JWT claims ARE in scope here — they drive the per-route
// audience pin and the agent-kill dimension enforced just below. What is NOT in scope
// is a per-request bearer token attributable to this upstream-initiated request (per
// ADR-0001 sampling originates from the upstream, not a host call carrying a token),
// so the JWT layer does not intersect capability claims for it: the capability decision
// delegates to the inner PDP, whose manifest "system:sampling/createMessage" opt-in is
// authoritative. With no inner authorizer (JWT-only, or an unpoliced route wrapped by
// JWT), sampling stays denied (fail closed).
func (p *JWTPDP) DecideSampling(ctx context.Context, sessionID, sourceIP string) capability.EnforceResponse {
	// Always run the wrapper's own kill check FIRST — before the audience pin below and
	// before any delegation to the inner PDP. Previously this was skipped when the inner
	// ManifestPDP shared the same manager (deferring to the inner's own check), but the
	// audience pin runs before that delegation, so a session that is BOTH killed and
	// cross-audience was denied with AUTHORIZATION_FAILED/jwtAudience instead of
	// KILL_SWITCH — flipping the audit denial code on wiring rather than session state and
	// hiding the kill from any monitoring keyed on KILL_SWITCH. Kill takes precedence over
	// audience (as this method's contract states), so the check is unconditional; the
	// possible redundant inner re-check is the accepted price of a correct, wiring-
	// independent denial code, matching the Decide path.
	if deny := killCheck(ctx, p.clock, p.ks, sessionID); deny != nil {
		return *deny
	}
	// Per-route audience pin (mirrors Decide/filterList): a session whose token does not
	// carry this route's audience gets NO enforced action on the route, including a
	// server-initiated sampling forward to the host. Reuse CheckAudience so the pin
	// logic lives once; claims are attached by forwardServerRequest, and when
	// routeAudience is unset (single-upstream, or stdio with no JWT) it is a no-op.
	if deny := p.CheckAudience(ctx); deny != nil {
		return *deny
	}
	// A present mcp.capabilities field is an EXHAUSTIVE allowlist: Decide denies any
	// target the claim does not list, even an empty array. Sampling was the one enforced
	// method that ignored it — DecideSampling delegated straight to the manifest — and
	// because parseV2Claim refuses system: claims, a token can never LIST sampling. So a
	// deny-all token ("capabilities": []) still got server-initiated sampling forwarded on
	// its session wherever the route's manifest opted into system:sampling/createMessage:
	// the one place "the token can only restrict, never expand" failed in the
	// exhaustive-deny direction. Deny instead, so the claim's contract holds for every
	// enforced method.
	if claims, ok := jwtClaimsFromContext(ctx); ok && claims.HasCapabilities {
		return denyResponse(p.clock, capability.ErrCodeSamplingDenied, "",
			"the token carries an mcp.capabilities claim, which is an exhaustive allowlist, and sampling cannot be listed in it (system: targets are not expressible as capability claims); server-initiated sampling is therefore denied for this token")
	}
	// innerEnforces gates the delegation so an AlwaysAllowPDP inner is NOT a sampling
	// backstop (matching the identity-only Decide path): without it
	// AlwaysAllowPDP.DecideSampling would be reached and silently grant sampling on a
	// JWT route carrying no sampling policy.
	if p.innerEnforces() {
		return p.inner.DecideSampling(ctx, sessionID, sourceIP)
	}
	return denyResponse(p.clock, capability.ErrCodeSamplingDenied, "",
		"server-initiated sampling requires a manifest with an explicit system:sampling/createMessage opt-in")
}

// routeAudienceSatisfied reports whether a token whose verified aud is auds is
// authorized on a route requiring routeAudience. It is the per-route narrowing that
// composes with the shared validator: the validator already accepted the token for
// SOME route's audience (the union), and this asserts it carries THIS route's. An
// empty routeAudience (single-upstream, or the shared validator itself) or
// --jwt-allow-any-audience disables the check (returns true). Otherwise the token must
// carry routeAudience among its aud values — the natural per-route extension of
// go-jose's "at least one of" semantics, so a multi-audience token issued for both
// svc-a and svc-b is accepted on either route.
func (p *JWTPDP) routeAudienceSatisfied(claims *JWTClaims) bool {
	if p.allowAnyAudience || p.routeAudience == "" {
		return true
	}
	for _, a := range claims.Audiences {
		if a == p.routeAudience {
			return true
		}
	}
	return false
}

// audienceDeny builds the per-route audience denial used by Decide, DecideSampling, and
// CheckAudience. It is marked HardDeny so a route running under --audit (observe) posture
// does NOT downgrade it to a logged forward: a token's audience is an authentication /
// tenancy boundary (like the kill switch, which is likewise never downgraded), not a
// per-call policy decision, so a cross-audience request is refused outright even in
// observe mode — matching the unconditional initialize-time pre-spawn gate.
func (p *JWTPDP) audienceDeny(message string) capability.EnforceResponse {
	resp := denyResponse(p.clock, capability.ErrCodeAuthorizationFailed, "jwtAudience", message)
	resp.Denial.HardDeny = true
	return resp
}

// withInnerForwardObligations fills r with the inner manifest's redaction obligations when
// r is one of JWTPDP's OWN denies and a route-level --audit will forward it anyway.
//
// This is the wrapper-shaped half of the observe-mode fail-open the ManifestPDP path closes
// with withForwardObligations. JWTPDP short-circuits above the inner PDP on three
// non-HardDeny paths — target absent from mcp.capabilities, a JWT condition failure, and
// no-capabilities-with-no-backstop — so the inner PDP never runs, never collects
// obligations, and the response reaches the transport with Obligations empty. On a route
// running --audit the transport downgrades that deny to a forwarded call and gates
// redaction on len(Obligations) > 0, so a manifest declaring redactFields on the target was
// silently skipped: the identical request WITHOUT the JWT wrapper redacted, and turning JWT
// on removed the guarantee.
//
// The inner is consulted through a *ManifestPDP assertion because obligation collection
// needs the engine and the capability list, neither of which is on the PolicyDecisionPoint
// contract. A non-manifest inner (AlwaysAllowPDP, nil, or a third-party implementation)
// declares no directives, so there is nothing to stamp and r is returned unchanged.
// withForwardObligations itself no-ops unless the route is running --audit, so an enforce
// route pays a nil check.
//
// HardDeny responses are excluded: the transport never downgrades them, so there is no
// forwarded response to redact.
//
// It ALSO carries the inner's interface-pin verdict, which is the other half of the same
// fail-open — see hardenOnBrokenInterface. Both live here because this is the one function
// every short-circuiting JWT deny already passes through on its way to being forwarded.
func (p *JWTPDP) withInnerForwardObligations(ctx context.Context, sessionID string, r capability.EnforceResponse, target EnforceTarget) capability.EnforceResponse {
	if r.Decision == capability.DecisionAllow || len(r.Obligations) > 0 {
		return r
	}
	if r.Denial != nil && r.Denial.HardDeny {
		return r
	}
	mdp, ok := p.inner.(*ManifestPDP)
	if !ok {
		return r
	}
	if hardened, broke := mdp.hardenOnBrokenInterface(sessionID, r, target); broke {
		// A broken pin means "must not be forwarded", which outranks "may be forwarded with
		// obligations" — so return before stamping them. A HardDeny is never downgraded, so
		// it has no forwarded response to redact.
		return hardened
	}
	return mdp.withForwardObligations(ctx, r, target)
}

// Decide reads JWT claims from the context (populated by ValidateToken), builds
// constraints from the capability strings, and evaluates them; when inner is set,
// the decision is the AND of both PDPs (intersection).
//
// Exhaustive-allowlist rule: a present mcp.capabilities field (even an empty array)
// is an exhaustive allowlist — any unlisted target is denied with
// AUTHORIZATION_FAILED. When absent the JWT imposes no restriction and decisions
// fall through to the inner manifest PDP.
//
// Cross-argument intersection: when manifest and JWT constrain different arguments
// of the same target, BOTH must pass — achieved by evaluating JWT conditions here
// then delegating to the inner PDP, so neither side can waive the other's.
func (p *JWTPDP) Decide(ctx context.Context, sessionID string, target EnforceTarget, args map[string]interface{}, sourceIP string) capability.EnforceResponse {
	// Check the kill switch first so kills take effect even without --policy. This
	// is unconditional (not skipped when the inner shares the manager, as
	// DecideSampling can): Decide has early-return paths that never reach decideInner
	// — an unlisted target, or failing JWT conditions — so deferring to the inner
	// would leave the kill unconsulted there, denying with the wrong code and no
	// kill-switch observability. DecideResourceRead/DecidePromptGet delegate here, so
	// this covers all three host-initiated paths.
	if deny := killCheck(ctx, p.clock, p.ks, sessionID); deny != nil {
		return *deny
	}

	claims, ok := jwtClaimsFromContext(ctx)
	if !ok {
		// No validated JWT claims in scope at all — the token was never validated. That
		// is an authentication boundary, an even stronger failure than the cross-audience
		// deny below (which is HardDeny), so it must not be downgraded to a logged forward
		// under a route running --audit. Hard-deny it, mirroring the audience deny.
		return hardDenyResponse(p.clock, capability.ErrCodeNoJWTClaims, "no JWT claims in context — token was not validated")
	}

	// Per-route audience pin: the shared validator accepted this token for SOME route's
	// audience (the union); narrow it to THIS route's. A token minted for route A's
	// audience is denied on route B. Runs before the capability/manifest logic so a
	// cross-audience token cannot reach either side. No-op for single-upstream (no
	// routeAudience) or --jwt-allow-any-audience.
	if !p.routeAudienceSatisfied(claims) {
		return p.audienceDeny(fmt.Sprintf("token audience %v does not satisfy the route's required audience %q", claims.Audiences, p.routeAudience))
	}

	// No mcp.capabilities field: the JWT provides identity only and the decision
	// defers to the inner manifest PDP. That is safe only with a real backstop —
	// with no manifest (an AlwaysAllowPDP or nil inner) a token omitting
	// mcp.capabilities would be granted every target, making enforcement an
	// issuer-controlled opt-in. JWT mode fails closed instead.
	if !claims.HasCapabilities {
		if p.innerEnforces() {
			return p.decideInner(ctx, sessionID, target, args, sourceIP)
		}
		return p.withInnerForwardObligations(ctx, sessionID, denyResponse(p.clock, capability.ErrCodeAuthorizationFailed, "jwtCapability",
			"token carries no mcp.capabilities claim and the route has no manifest policy to fall back on; "+
				"JWT mode denies by default — issue a token with capability claims or add a manifest policy to the route"), target)
	}

	// mcp.capabilities present → exhaustive allowlist; an unlisted target is denied
	// regardless of the manifest. Use the heads parsed at validation time (cached hot
	// path) when available, else parse the raw claims.
	var constraints []capability.Constraint
	if claims.parsedCaps != nil {
		constraints = buildConstraintsFromParsed(claims.parsedCaps, target)
	} else {
		constraints = buildConstraintsFromClaims(claims.Capabilities, target)
	}
	if len(constraints) == 0 {
		return p.withInnerForwardObligations(ctx, sessionID, denyResponse(p.clock, capability.ErrCodeAuthorizationFailed, "jwtCapability",
			fmt.Sprintf("%s %q is not in the JWT capability claims", target.Type, target.Name)), target)
	}

	// mcp.capabilities is an OR-list: the call is permitted if ANY matching entry's
	// conditions pass. Evaluate every matching entry and allow on the first that
	// passes, avoiding an order-dependent first-match deny (e.g. separate
	// op=SELECT / op=INSERT grants for one tool). Conditions evaluate against the
	// same arg map the inner manifest sees — tools/call carries real args, while
	// resources/read and prompts/get synthesize the name under "uri"/"name" — so a
	// resource:/prompt: allowedValues claim does not always deny with MISSING_CONTEXT.
	condArgs := jwtConditionArgs(target, args)
	var lastDeny *capability.EnforceResponse
	for i := range constraints {
		matched := constraints[i]
		if len(matched.Conditions) == 0 {
			lastDeny = nil
			break
		}
		if resp := evaluateJWTConditions(p.clock, matched.Conditions, target.Name, condArgs); resp != nil {
			lastDeny = resp
			continue
		}
		// This entry's conditions all passed.
		lastDeny = nil
		break
	}
	if lastDeny != nil {
		return p.withInnerForwardObligations(ctx, sessionID, *lastDeny, target)
	}

	// JWT allows — intersect with the inner manifest PDP if configured (both sides
	// must pass, § 5.2.1). The inner PDP stamps its own correlation fields.
	//
	// This gate is the plain p.inner != nil, deliberately weaker than the
	// innerEnforces() gate the no-capabilities branch above uses — and that asymmetry is
	// safe here. The two branches face opposite risks: there the JWT ABSTAINS (no
	// mcp.capabilities), so an AlwaysAllow/nil inner would fail OPEN, which innerEnforces()
	// prevents; here the JWT has ALREADY authorized this target against its exhaustive
	// allowlist, so delegating to a permissive inner (an AlwaysAllowPDP) can only
	// re-affirm the allow — a weaker gate cannot fail open. Using innerEnforces() here too
	// would yield the identical decision (only the audit-stamping helper differs:
	// AlwaysAllowPDP.Decide vs. newAllowResponse below), so the plain nil check is kept.
	if p.inner != nil {
		return p.decideInner(ctx, sessionID, target, args, sourceIP)
	}

	// JWT-only allow (no inner): stamp the audit-correlation fields the
	// engine-bypassing allow paths share (newAllowResponse).
	return newAllowResponse(p.clock)
}

// now returns the injected clock's instant (or the wall clock), via the shared
// clockNow so the JWT and AlwaysAllowPDP paths honor a frozen test clock identically.
func (p *JWTPDP) now() time.Time {
	return clockNow(p.clock)
}

// decideInner delegates the post-JWT decision to the inner PDP, dispatching by
// target type so resources/read and prompts/get reach the inner methods that
// synthesize the {"uri"}/{"name"} argument maps. Routing every type through
// inner.Decide (the tools/call path) would evaluate a resource/prompt entry's
// conditions against an empty map and deny with MISSING_CONTEXT.
func (p *JWTPDP) decideInner(ctx context.Context, sessionID string, target EnforceTarget, args map[string]interface{}, sourceIP string) capability.EnforceResponse {
	switch target.Type {
	case capability.TargetTypeResource:
		return p.inner.DecideResourceRead(ctx, sessionID, target.Name, sourceIP)
	case capability.TargetTypePrompt:
		return p.inner.DecidePromptGet(ctx, sessionID, target.Name, sourceIP)
	case capability.TargetTypeTool:
		// tools/call carries real arguments, so inner.Decide evaluates against them
		// directly. system targets do NOT come through here: sampling is enforced via
		// the separate DecideSampling path, and inner.Decide does not check the
		// sampling opt-in, so a system target falls to the deny below.
		return p.inner.Decide(ctx, sessionID, target, args, sourceIP)
	default:
		// Fail closed on any unhandled type: a new type, or one needing name-to-arg
		// synthesis (like resource/prompt), would re-introduce the empty-arg
		// MISSING_CONTEXT regression if it silently fell through to inner.Decide.
		// system lands here on purpose (see the tool case).
		return hardDenyResponse(p.clock, capability.ErrCodeEnforcementError,
			fmt.Sprintf("decideInner: unhandled target type %q — update decideInner", target.Type))
	}
}

// jwtConditionArgs returns the argument map JWT shorthand conditions evaluate
// against. tools/call carries real arguments; resources/read and prompts/get carry
// none, so the target name is synthesized under "uri"/"name" to match the inner
// manifest's synthesis. Keep these keys in lockstep with
// DecideResourceRead/DecidePromptGet.
func jwtConditionArgs(target EnforceTarget, args map[string]interface{}) map[string]interface{} {
	switch target.Type {
	case capability.TargetTypeResource:
		return map[string]interface{}{"uri": target.Name}
	case capability.TargetTypePrompt:
		return map[string]interface{}{"name": target.Name}
	default:
		// tools/call: real arguments. A new target type delegating here with nil args
		// MUST get its own case above, else its conditions deny with MISSING_CONTEXT.
		return args
	}
}

// jwtCondPair is a single (argument, value) condition parsed from a v0.2 JWT
// capability shorthand suffix.  The value is already percent-decoded (§ 4.2).
type jwtCondPair struct {
	key   string
	value string
}

// parseV2Claim parses a v0.2 JWT capability shorthand entry.
//
// The format is: "<namespace>:<name>[?<key>=<value>[&<key>=<value>…]]"
//
//	"tool:read_file"                      → (TargetTypeTool,     "read_file",      nil)
//	"tool:read_file?path=/reports/*"      → (TargetTypeTool,     "read_file",      [{path,/reports/*}])
//	"tool:query_db?op=SELECT&table=sales" → (TargetTypeTool,     "query_db",       [{op,SELECT},{table,sales}])
//	"resource:file:///data/*"             → (TargetTypeResource, "file:///data/*", nil)
//	"prompt:code_review"                  → (TargetTypePrompt,   "code_review",    nil)
//
// An absent or unrecognized namespace prefix, or an unparseable condition
// suffix, returns a non-nil error.  The v0.1 colon-only shorthand
// ("read_file:/reports/*") is rejected because it lacks a recognized prefix.
func parseV2Claim(claim string) (prefix capability.TargetType, bareName string, conds []jwtCondPair, err error) {
	// Split off the optional condition suffix, leaving a resource URI's query string
	// attached to the name (see splitV2Claim).
	namepart, condpart, hadSep := splitV2Claim(claim)

	// A '?' separator with no pairs after it ("tool:read_file?") is malformed;
	// reject the token (fail closed) rather than treat it as an unconditioned
	// (maximally permissive) grant.
	if hadSep && condpart == "" {
		return "", "", nil, fmt.Errorf("JWT capability claim %q: trailing '?' with no condition pairs", claim)
	}

	// Parse the namespace prefix and bare name using the shared parser.
	p, bare, parseErr := capability.ParseTarget(namepart)
	if parseErr != nil {
		return "", "", nil, fmt.Errorf("JWT capability claim %q: %w", claim, parseErr)
	}

	// A system: claim validates through ParseTarget but is consulted by nothing: Decide
	// never sees a system target (sampling is decided by the inner manifest per ADR-0001,
	// and decideInner deliberately drops system to the fail-closed default). Admitting one
	// would be an inert grant — the same silently-ineffective grammar this parser already
	// rejects for a non-SQL op= or a trailing '?'. Reject it so the token surfaces the
	// misconfiguration up front; a system-level capability (sampling) is granted via the
	// manifest's system:sampling/createMessage opt-in, not a JWT claim. This path is only
	// reached under --jwt-experimental-capabilities (ValidateToken rejects mcp.capabilities
	// outright otherwise), so a normal token is unaffected.
	if p == capability.TargetTypeSystem {
		return "", "", nil, fmt.Errorf("JWT capability claim %q: the system: namespace is not grantable from a JWT capability claim; system capabilities such as sampling are authorized by the manifest's system:sampling/createMessage opt-in, not a token claim", claim)
	}

	// Validate the bare target as a path.Match glob, mirroring the manifest loader
	// (enforcement.ValidateResourcePattern, called from internal/config) so a malformed
	// target glob is rejected identically whether it arrives in a manifest or a JWT claim:
	// the manifest layer already forbids these patterns at load, and this keeps the JWT
	// claim path at parity rather than admitting a grant the manifest could not express.
	// For a glob-intended target (e.g. "tool:read_[*") a malformed pattern would otherwise
	// reach enforce time and path.Match would swallow the ErrBadPattern to a silent
	// non-match (matchesResource), an inert deny-all surfacing only as an opaque
	// AUTHORIZATION_FAILED. (A target whose literal string merely contains a metachar —
	// e.g. a tool named exactly "read_[file" — could instead match via matchesResource's
	// exact-name fast path, so such a grant is not necessarily inert; rejecting it here
	// still fails closed and preserves manifest/JWT parity, at the cost that this unusual
	// literal is no longer grantable from a token — the manifest cannot grant it either.)
	// claimGlobParts owns which substring is the glob (an http(s)-resource '?query' is
	// compared literally, so only the path before '?' is validated), shared with
	// matchClaimBare so validation and enforcement stay in lockstep.
	globPart, _, _ := claimGlobParts(p, bare)
	if err := enforcement.ValidateResourcePattern(globPart); err != nil {
		return "", "", nil, fmt.Errorf("JWT capability claim %q: invalid target pattern: %w", claim, err)
	}

	// Parse the optional condition suffix.
	if condpart != "" {
		conds, parseErr = parseCondSuffix(condpart)
		if parseErr != nil {
			return "", "", nil, fmt.Errorf("JWT capability claim %q: %w", claim, parseErr)
		}
		// Every non-"op" condition pair becomes an AllowedValues glob at runtime
		// (buildV2Constraint). A malformed pattern (e.g. unclosed class "[invalid")
		// silently matches nothing, turning the grant into a deny-all that surfaces
		// only as a misleading VALUE_NOT_PERMITTED. Validate here, as the manifest path
		// does, so a misconfigured claim is rejected up front. ("op" pairs become
		// AllowedOperations, not value globs, so they are exempt.)
		for _, cp := range conds {
			if cp.key == "op" {
				// An "op=" pair has no explicit argument name (buildV2Constraint emits
				// Argument: ""), so it runs in scan-all-args mode, which only supports
				// SQL verbs — a non-SQL verb fails closed on every tools/call at
				// evaluation time. Reject it here so the misconfiguration surfaces as a
				// token-validation error instead of an opaque CONDITION_FAILED on every
				// subsequent call. Non-SQL operations require the manifest form with an
				// explicit argument naming the operation parameter.
				if !isSQLVerb(cp.value) {
					return "", "", nil, fmt.Errorf("JWT capability claim %q: op= value %q is not a recognised SQL verb; non-SQL operations require the manifest form with an explicit argument naming the operation parameter", claim, cp.value)
				}
				continue
			}
			if err := enforcement.ValidateValueGlob(cp.value); err != nil {
				return "", "", nil, fmt.Errorf("JWT capability claim %q: argument %q has an invalid glob value %q: %w", claim, cp.key, cp.value, err)
			}
		}
	}

	return p, bare, conds, nil
}

// splitV2Claim splits a v0.2 capability claim into its name part and optional raw
// condition suffix (everything after the separating '?').
//
// It splits at the FIRST '?' EXCEPT for an http(s) resource claim, where '?' begins
// the URL's query component rather than a condition list, so the whole URL is kept
// as the name (otherwise it is truncated and the query misread as a never-satisfiable
// condition). The exception is scoped to http(s) only — other schemes (file://, urn:)
// and the tool/prompt/system shorthands keep '?' as the condition separator. The
// tradeoff: an http(s) resource claim cannot also carry conditions.
//
// hadSep reports whether a '?' separator was present, distinguishing an
// unconditioned claim ("tool:read_file") from a malformed trailing-'?' one
// ("tool:read_file?", hadSep=true, condpart="") that must be rejected.
func splitV2Claim(claim string) (namepart, condpart string, hadSep bool) {
	if i := strings.IndexByte(claim, '?'); i >= 0 && !isHTTPResourceClaim(claim[:i]) {
		return claim[:i], claim[i+1:], true
	}
	return claim, "", false
}

// isHTTPResourceClaim reports whether head (a claim with any condition suffix
// already removed) is a resource claim whose value is an http(s) URL — i.e.
// "resource:http://…" or "resource:https://…".
func isHTTPResourceClaim(head string) bool {
	const ns = "resource:"
	if !strings.HasPrefix(head, ns) {
		return false
	}
	// URI schemes are case-insensitive (RFC 3986 §3.1), so detect on a lowercased
	// copy ("resource:HTTPS://…" still counts). Only detection is lowercased;
	// splitV2Claim keeps the original-case namepart for manifest lookup.
	return isHTTPResourceValue(head[len(ns):])
}

// isHTTPResourceValue reports whether a bare resource value (the part after the
// "resource:" prefix) is an http(s) URL. URI schemes are case-insensitive
// (RFC 3986 §3.1), so detection is on a lowercased copy.
func isHTTPResourceValue(bareName string) bool {
	v := strings.ToLower(bareName)
	return strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://")
}

// claimGlobParts decomposes a capability claim's bare target into the substring matched
// as a path.Match glob and, for an http(s)-resource claim carrying a query, the literal
// query tail. An http(s) resource's query is compared literally (there is no glob syntax
// for a query), so there the glob is only the path before '?'; every other claim (a
// non-resource target, a non-http resource, or a query-less one) globs its whole bare
// name. This is the single source of the glob/literal split that parseV2Claim validates
// and matchClaimBare enforces, so validation and enforcement cannot drift apart.
func claimGlobParts(prefix capability.TargetType, bareName string) (globPart, query string, hasQuery bool) {
	if prefix == capability.TargetTypeResource && isHTTPResourceValue(bareName) {
		if pPath, pQuery, pHasQuery := strings.Cut(bareName, "?"); pHasQuery {
			return pPath, pQuery, true
		}
	}
	return bareName, "", false
}

// matchClaimBare matches a JWT capability claim's bare name (prefix stripped)
// against a request target name with the right semantics for the namespace.
//
// For http(s) resource claims the query component is only special-cased when the CLAIM
// carries one. splitV2Claim keeps a resource URI's "?query" on the bare name, but
// matchBare's path.Match would read a structural '?' in the claim as a single-char
// wildcard (".../search?q=widget" matching ".../searchXq=widget"). So a query-BEARING
// claim is split at the first '?': the path keeps glob semantics while the query is
// compared literally (there is no glob syntax for the query), and it grants only a
// target with that exact query. A query-LESS claim carries no '?' to misread, so it is
// matched as one whole string via matchBare — identical to the manifest's whole-URI
// matchesResource (matchBare IS enforcement.MatchesResource). That keeps the two paths
// consistent: an exact query-less claim (".../export") grants only its exact URI and
// NOT an arbitrary target query (".../export?scope=all"), closing a fail-open widening,
// while a path-glob query-less claim (".../search/*") still absorbs a target query
// exactly as the manifest's glob does. Every other namespace keeps plain matchBare.
func matchClaimBare(prefix capability.TargetType, bareName, targetName string) bool {
	// claimGlobParts owns the glob/literal split (shared with parseV2Claim's validation),
	// so what is globbed here is exactly what was validated at token verification.
	globPart, claimQuery, hasQuery := claimGlobParts(prefix, bareName)
	if hasQuery {
		tPath, tQuery, tHasQuery := strings.Cut(targetName, "?")
		// A query-bearing claim pins its query: the target must carry the same one.
		if !tHasQuery || claimQuery != tQuery {
			return false
		}
		return matchBare(globPart, tPath)
	}
	// Query-less claim (or any non-http-resource target): whole-string match, exactly as
	// the manifest does.
	return matchBare(globPart, targetName)
}

// parseCondSuffix parses the condition suffix of a v0.2 shorthand entry per the
// form-urlencoded convention (§ 4.2): pairs split on '&', key from value on '=',
// combined with logical AND; each value percent-decoded ('+' → space). Keys MUST
// NOT be percent-encoded. Fail-closed: a missing '=', empty/duplicate/encoded key,
// or malformed value encoding rejects the token.
func parseCondSuffix(condpart string) ([]jwtCondPair, error) {
	pairs := strings.Split(condpart, "&")
	conds := make([]jwtCondPair, 0, len(pairs))
	seen := make(map[string]bool, len(pairs))
	for _, pair := range pairs {
		key, val, ok := strings.Cut(pair, "=")
		if !ok {
			return nil, fmt.Errorf("condition %q is missing '=' separator", pair)
		}
		if key == "" {
			return nil, fmt.Errorf("condition %q has an empty key", pair)
		}
		// Keys are matched literally against argument names; encoding them is not
		// permitted (§ 4.2). '+' form-decodes to a space, so it counts as encoding.
		if strings.ContainsAny(key, "%+") {
			return nil, fmt.Errorf("condition key %q must not be percent-encoded", key)
		}
		if seen[key] {
			return nil, fmt.Errorf("condition key %q appears more than once", key)
		}
		seen[key] = true
		// Percent-decode the value ('+' → space); an unparseable escape rejects the token.
		decoded, decErr := url.QueryUnescape(val)
		if decErr != nil {
			return nil, fmt.Errorf("condition value %q is not valid URL encoding: %w", val, decErr)
		}
		conds = append(conds, jwtCondPair{key: key, value: decoded})
	}
	return conds, nil
}

// buildV2Constraint converts a parsed v0.2 claim into a capability.Constraint, one
// condition per pair (pairs AND together). "op" → AllowedOperationsCondition
// (scan-all-args; a non-SQL op in this bare form fails closed at evaluation); any
// other key → AllowedValuesCondition on that argument.
func buildV2Constraint(prefix capability.TargetType, bareName string, conds []jwtCondPair) capability.Constraint {
	c := capability.Constraint{
		Target:  string(prefix) + ":" + bareName,
		Actions: []string{requiredActionFor(prefix)},
	}
	for _, cp := range conds {
		if cp.key == "op" {
			c.Conditions = append(c.Conditions, capability.AllowedOperationsCondition{
				Argument:   "",
				Operations: []string{cp.value},
			})
			continue
		}
		// Any other key is the argument name for an AllowedValues condition.
		c.Conditions = append(c.Conditions, capability.AllowedValuesCondition{
			Argument: cp.key,
			Values:   jwtShorthandValues(cp.value),
		})
	}
	return c
}

// jwtShorthandValues returns the allowed-value set for one v0.2 shorthand condition
// value. The grammar carries every value as a percent-decoded STRING, but a tool
// argument arrives with its native JSON type, and MatchAllowedValue treats a string
// allowed-value as a glob that cannot match a non-string argument — so a string-only
// value would silently deny every numeric/boolean call.
//
// When raw parses as a whole JSON number/boolean/null, ONLY the typed scalar is
// returned — not the raw string too — so e.g. "?id=42" grants the numeric argument
// 42 and does not ALSO grant a string argument "42" the claim never typed. A number
// is kept as a json.Number holding the exact lexeme so a large integer compares
// exactly against the argument side (which decodes with UseNumber), not rounded
// through float64. Anything else (a bare string, a glob pattern, a JSON string or
// container literal) keeps the raw string as-is, matching a string argument and
// preserving glob patterns.
func jwtShorthandValues(raw string) []interface{} {
	// Validate raw as a single, whole JSON value before deriving a typed scalar.
	// json.Unmarshal (unlike Decoder.Decode) rejects trailing bytes natively, so
	// "100abc" fails here rather than yielding a numeric grant from the leading
	// "100". A parse failure means raw is not JSON at all (a bare string) and only
	// the raw string value is kept.
	var msg json.RawMessage
	if err := json.Unmarshal([]byte(raw), &msg); err != nil {
		return []interface{}{raw}
	}
	tok := strings.TrimSpace(string(msg))
	if tok == "" {
		return []interface{}{raw}
	}
	// Classify off the first byte of the validated token rather than a second
	// Decode whose io.EOF result is an encoding/json buffering detail, not a
	// guarantee. A container ('{'/'[') or string ('"') keeps the raw string
	// unchanged: it already matches a string argument and preserves glob patterns.
	switch tok[0] {
	case 't', 'f':
		// json.Unmarshal already proved the token is a well-formed boolean.
		return []interface{}{tok[0] == 't'}
	case 'n':
		// JSON null → Go nil, matching an argument explicitly set to null;
		// otherwise MatchAllowedValue would glob nil against "null" and never match.
		return []interface{}{nil}
	case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		// Keep the exact lexeme as json.Number so an integer above 2^53 is exact,
		// not rounded through float64 (which would let amount=9007199254740993
		// match the adjacent argument 9007199254740992).
		return []interface{}{json.Number(tok)}
	}
	return []interface{}{raw}
}

// capHead is one JWT capability claim pre-parsed into its namespace prefix,
// bare-name pattern, and raw "?<conditions>" suffix. Cached on JWTClaims
// (parseCapHeads, populated once per token) so repeated decisions skip the per-claim
// splitV2Claim/ParseTarget work that otherwise scales O(claims x requests).
type capHead struct {
	prefix   capability.TargetType
	bareName string
	condpart string // raw condition suffix; "" => no conditions
}

// parseCapHeads runs the cheap phase of claim parsing — splitting off the optional
// "?<conditions>" suffix and parsing only the namespace+bare-name head — dropping
// malformed entries so they grant nothing (fail closed). The expensive
// parseCondSuffix stays lazy in buildConstraintsFromParsed so a non-matching claim
// never pays for it.
//
// A drop here "should not occur": ValidateToken structurally validates every claim
// before it reaches this function. So a drop means the validator and this parser have
// diverged (e.g. a future grammar extension landed in one but not the other), which
// would silently grant fewer capabilities than the token encodes — fail-closed in
// result, but invisible. Each drop is logged through jwtLogger — the same structured
// stderr handler the rest of this package uses, so the drop is greppable and
// correlatable in a SIEM — rather than surfacing only as unexplained
// AUTHORIZATION_FAILED denials downstream.
func parseCapHeads(caps []string) []capHead {
	heads := make([]capHead, 0, len(caps))
	for _, claim := range caps {
		namepart, condpart, hadSep := splitV2Claim(claim)
		if hadSep && condpart == "" {
			// Trailing '?' with no pairs: malformed (ValidateToken already rejects it).
			jwtLogger.Warn("JWT capability claim passed validation but failed to parse; dropping (this is a bug)",
				"claim", claim, "reason", "trailing '?' with no conditions")
			continue
		}
		prefix, bareName, err := capability.ParseTarget(namepart)
		if err != nil {
			// Claims were validated at token-validation time; should not occur.
			jwtLogger.Warn("JWT capability claim passed validation but failed to parse; dropping (this is a bug)",
				"claim", claim, "reason", err.Error())
			continue
		}
		heads = append(heads, capHead{prefix: prefix, bareName: bareName, condpart: condpart})
	}
	return heads
}

// buildConstraintsFromClaims returns the constraint for every JWT capability claim
// matching target, in claim order (mcp.capabilities is an OR-list). The fallback for
// callers holding only raw claim strings; the hot path uses
// buildConstraintsFromParsed against the cached heads.
func buildConstraintsFromClaims(caps []string, target EnforceTarget) []capability.Constraint {
	return buildConstraintsFromParsed(parseCapHeads(caps), target)
}

// buildConstraintsFromParsed is the matching/condition phase shared by the hot path
// and buildConstraintsFromClaims. The expensive parseCondSuffix runs only for claims
// that actually match this target.
//
// A condition-suffix parse failure here is the same validator/parser divergence
// parseCapHeads logs for the head phase — ValidateToken already accepted the whole
// claim, suffix included — so it is reported the same way rather than dropped
// silently, which would surface only as an unexplained AUTHORIZATION_FAILED.
func buildConstraintsFromParsed(heads []capHead, target EnforceTarget) []capability.Constraint {
	var out []capability.Constraint
	for _, h := range heads {
		if h.prefix != target.Type || !matchClaimBare(h.prefix, h.bareName, target.Name) {
			continue
		}
		var conds []jwtCondPair
		if h.condpart != "" {
			c, err := parseCondSuffix(h.condpart)
			if err != nil {
				// A malformed suffix on a matching claim grants nothing (fail closed).
				// Logged through jwtLogger, like its head-phase twin in parseCapHeads: the
				// two halves report the same validator/parser divergence, so they must be
				// greppable and correlatable the same way in a SIEM.
				jwtLogger.Warn("JWT capability claim passed validation but its condition suffix failed to parse; dropping (this is a bug)",
					"claim", fmt.Sprintf("%s:%s?%s", h.prefix, h.bareName, h.condpart), "reason", err.Error())
				continue
			}
			conds = c
		}
		out = append(out, buildV2Constraint(h.prefix, h.bareName, conds))
	}
	return out
}

// anyCapCovers reports whether any pre-parsed claim head covers target. Conditions
// are not consulted — a list response carries no arguments — so a target is retained
// whenever a claim matches its namespace and bare name. It takes the same []capHead
// the Decide path caches (JWTClaims.parsedCaps) so list filtering and Decide share
// one claim parser instead of maintaining a second name-only variant.
func anyCapCovers(parsed []capHead, target EnforceTarget) bool {
	for _, c := range parsed {
		if c.prefix == target.Type && matchClaimBare(c.prefix, c.bareName, target.Name) {
			return true
		}
	}
	return false
}

// listTypeDesc describes one */list flavor so filterList can handle all three
// without per-kind branching or seven parameters.
type listTypeDesc struct {
	key        string
	idField    string
	targetType capability.TargetType
	filter     func(ListFilterer, context.Context, json.RawMessage) ListFilterResult
}

var (
	toolsDesc = listTypeDesc{
		key: listKeyTools, idField: "name", targetType: capability.TargetTypeTool,
		filter: ListFilterer.FilterToolsList,
	}
	resourcesDesc = listTypeDesc{
		key: listKeyResources, idField: "uri", targetType: capability.TargetTypeResource,
		filter: ListFilterer.FilterResourcesList,
	}
	promptsDesc = listTypeDesc{
		key: listKeyPrompts, idField: "name", targetType: capability.TargetTypePrompt,
		filter: ListFilterer.FilterPromptsList,
	}
)

// anyCapCoversName is the fast path for filterList when the entry ID was already
// decoded by the inner PDP's keep func, avoiding a second JSON unmarshal.
func anyCapCoversName(name string, targetType capability.TargetType, parsed []capHead) bool {
	return anyCapCovers(parsed, EnforceTarget{Type: targetType, Name: name})
}

// filterList is the shared body of the three JWT ListFilterer methods.
//
// No JWT claims at all: fail closed like Decide's ErrCodeNoJWTClaims — empty the
// listing without consulting the inner PDP. No mcp.capabilities field: delegate to
// the inner PDP if present, else empty the listing.
//
// mcp.capabilities present (intersection): run the inner PDP ONCE — it parses and
// prunes the list and exposes the survivors pre-parsed (ListFilterResult.Entries)
// — then apply the JWT claim filter to those entries in memory and splice the
// result back into the inner PDP's already-ordered envelope. The response is parsed
// once instead of twice (the inner re-parsing an emptyListing-marshaled
// intermediate). Intersection is commutative, so the final entry set, the true
// upstream count (inner.Upstream), and the post-filter count are identical to an
// empty-then-inner order. emptyListing is used for the no-claims / no-capabilities
// branches, where the listing is emptied while still reporting the upstream count.
func (p *JWTPDP) filterList(ctx context.Context, result json.RawMessage, desc listTypeDesc) ListFilterResult {
	claims, ok := jwtClaimsFromContext(ctx)
	if !ok {
		// No JWT claims: mirror Decide's hard-deny by emptying the listing without
		// deferring to the inner PDP's OUTPUT (filterList has no error channel).
		return p.emptyListingArmingPins(ctx, result, desc)
	}
	// Per-route audience pin (mirrors Decide): a token minted for a different route's
	// audience must not enumerate this route's catalog. Fail closed to an empty listing.
	if !p.routeAudienceSatisfied(claims) {
		return p.emptyListingArmingPins(ctx, result, desc)
	}
	if !claims.HasCapabilities {
		if p.innerEnforces() {
			return p.innerFilter(ctx, result, desc.filter, desc.key)
		}
		return emptyListing(result, desc.key)
	}
	innerRes := p.innerFilter(ctx, result, desc.filter, desc.key)
	// Reuse the claim heads parsed once at token validation (parsedCaps); fall back to
	// parsing here for a test-built JWTClaims that set Capabilities directly. Mirrors
	// Decide's use of parsedCaps so list filtering never re-parses on the hot path.
	parsed := claims.parsedCaps
	if parsed == nil {
		parsed = parseCapHeads(claims.Capabilities)
	}
	kept := make([]json.RawMessage, 0, len(innerRes.Entries))
	for i, raw := range innerRes.Entries {
		var covered bool
		if i < len(innerRes.entryIDs) && innerRes.entryIDs[i] != "" {
			// ID already decoded by inner PDP's keep func — skip re-unmarshal. An empty
			// ID means the inner decoded none (e.g. the byClaims path), so fall back to
			// decoding the entry rather than treating "" as the identifier.
			covered = anyCapCoversName(innerRes.entryIDs[i], desc.targetType, parsed)
		} else {
			covered = entryCoveredByClaims(raw, parsed, desc.idField, desc.targetType)
		}
		if covered {
			kept = append(kept, raw)
		}
	}
	// Use pre-parsed envelope when available to avoid re-parsing.
	var (
		out []byte
		err error
	)
	if innerRes.envKeys != nil {
		out, err = encodeOrderedObjectWithList(innerRes.envKeys, innerRes.envValues, desc.key, kept)
	} else {
		out, err = replaceOrderedListField(innerRes.Result, desc.key, kept)
	}
	if err != nil {
		// A ManifestPDP inner always emits a clean {listKey:[...]} envelope, but a
		// passthrough inner (nil/AlwaysAllow) forwards the upstream bytes verbatim, so a
		// malformed upstream body can land here. Fail closed to an empty listing rather
		// than forward whatever the splice could not re-emit.
		return emptyListing(result, desc.key)
	}
	return ListFilterResult{Result: out, Entries: kept, Upstream: innerRes.Upstream}
}

// FilterToolsList implements ListFilterer for the JWT PDP.
func (p *JWTPDP) FilterToolsList(ctx context.Context, result json.RawMessage) ListFilterResult {
	return p.filterList(ctx, result, toolsDesc)
}

// FilterResourcesList implements ListFilterer for the JWT PDP.
func (p *JWTPDP) FilterResourcesList(ctx context.Context, result json.RawMessage) ListFilterResult {
	return p.filterList(ctx, result, resourcesDesc)
}

// FilterPromptsList implements ListFilterer for the JWT PDP.
func (p *JWTPDP) FilterPromptsList(ctx context.Context, result json.RawMessage) ListFilterResult {
	return p.filterList(ctx, result, promptsDesc)
}

// RecordObservedToolHashes delegates to the inner PDP, which holds any description-hash
// pins — the JWT layer pins no tool descriptions of its own. A nil inner records nothing
// but still reports an accurate entry count, so the caller need not decode result again.
//
// The count comes from the length-only countListEntries rather than passThroughList: the
// caller wants a NUMBER, and passThroughList builds an ordered envelope nothing here
// reads. AlwaysAllowPDP's twin already documents choosing countListEntries for exactly
// this case.
func (p *JWTPDP) RecordObservedToolHashes(ctx context.Context, result json.RawMessage) int {
	if p.inner != nil {
		return p.inner.RecordObservedToolHashes(ctx, result)
	}
	return countListEntries(result, listKeyTools)
}

// ReleaseSession delegates to the inner PDP so a wrapped ManifestPDP releases the
// session's flow-label state on teardown. The JWT wrapper holds no per-session flow
// state of its own (claims live in the request context, not per-session), so a nil inner
// is a no-op.
func (p *JWTPDP) ReleaseSession(ctx context.Context, sessionID string) {
	if p.inner != nil {
		p.inner.ReleaseSession(ctx, sessionID)
	}
}

// innerFilter applies the inner PDP's list filter (selected by sel) to intersect
// with the JWT claim filter. A nil inner passes the result through (counting its
// entries via fieldName so the composed counts stay accurate), so the JWT claim
// filter alone applies. (An AlwaysAllowPDP inner also passes through, via its own
// ListFilterer methods.)
func (p *JWTPDP) innerFilter(
	ctx context.Context,
	result json.RawMessage,
	sel func(ListFilterer, context.Context, json.RawMessage) ListFilterResult,
	fieldName string,
) ListFilterResult {
	if p.inner == nil {
		return passThroughList(result, fieldName)
	}
	return sel(p.inner, ctx, result)
}

// emptyListingArmingPins is emptyListing for the two branches that reject the CALLER
// rather than the catalog — no JWT claims, and a token minted for another route's
// audience. The host sees the same empty listing either way; what differs is that the
// descriptionHash pin is still armed from the bytes the upstream returned.
//
// Without it the pin went un-refreshed for that caller's tools/list, so a catalog the
// upstream had already poisoned was observed by nobody. Distinct from a
// catalog-integrity break — Decide still hard-denies the actual call — but the pin should
// not go stale merely because the caller's token was rejected. The bytes come from the
// UPSTREAM, not the caller, so this arms from the genuine catalog: a rejected caller
// controls only WHEN the observation happens, never what is observed.
//
// It calls RecordObservedToolHashes — the contract's named method for exactly this, whose
// whole contract is "record the pinned tools' live hashes WITHOUT filtering the catalog"
// — rather than running the inner list filter and discarding its output. That matters for
// more than tidiness: the filter decodes every entry and scores it against every manifest
// constraint, so on a large catalog the discarded pass cost a rejected caller MORE than a
// fully authorized one, on the branch whose entire purpose is cheap fail-closed rejection.
//
// Tools only. Pins exist for tools alone, so running the resources or prompts filter here
// armed nothing and was pure waste. RecordObservedToolHashes self-gates on the pinned set,
// so a manifest declaring no descriptionHash pays nothing at all.
func (p *JWTPDP) emptyListingArmingPins(ctx context.Context, result json.RawMessage, desc listTypeDesc) ListFilterResult {
	if desc.key == listKeyTools && p.innerEnforces() {
		_ = p.inner.RecordObservedToolHashes(ctx, result)
	}
	return emptyListing(result, desc.key)
}

// emptyListing empties every entry of one list kind (listKey, e.g. "tools") while
// still reporting the upstream (pre-filter) count. filterList's no-claims,
// no-route-audience-match, and no-capabilities branches all fail closed to this:
// none of them has any capability claim to filter by, so the correct result is
// always "keep nothing," never a claim-based filter (that generality was dead —
// every production call site passed a nil claim list, which anyCapCovers/
// entryCoveredByClaims always resolves to false for).
func emptyListing(resultBytes json.RawMessage, listKey string) ListFilterResult {
	return filterListResult(resultBytes, listKey, func(json.RawMessage) (bool, string) {
		return false, ""
	})
}

// entryCoveredByClaims reports whether a single list entry's identifier — the JSON
// field idField, "name" for tools/prompts or "uri" for resources — is covered by a
// capability claim of targetType. Conditions are not evaluated (list methods carry
// no arguments) and it fails closed (false) on a decode error. Both id fields are
// decoded and the requested one selected, so an entry missing idField yields the
// empty-name target. Used by the JWT intersection's in-memory second pass
// (filterList) to match entries against real, non-empty parsed claim heads.
//
// entryKeysAmbiguous is checked first and fails closed (false) on an ambiguous entry —
// a duplicate or case-variant top-level key (e.g. "name"/"Name", "uri"/"URI") — for the
// same reason ManifestPDP's list filters apply it: an entry Go decodes one way here can
// render a different name/uri to a case-sensitive host, and this path (reached whenever
// the inner PDP is nil or AlwaysAllowPDP, i.e. its result comes from an unfiltered
// passThroughList) is the one list-filter path that had no per-entry gate at all.
func entryCoveredByClaims(raw json.RawMessage, parsed []capHead, idField string, targetType capability.TargetType) bool {
	if entryKeysAmbiguous(raw) {
		return false
	}
	var entry struct {
		Name string `json:"name"`
		URI  string `json:"uri"`
	}
	if err := json.Unmarshal(raw, &entry); err != nil {
		return false
	}
	name := entry.Name
	if idField == "uri" {
		name = entry.URI
	}
	return anyCapCovers(parsed, EnforceTarget{Type: targetType, Name: name})
}

// sqlVerbs is the set of SQL statement verbs the op= scan-all-args evaluator
// recognizes. A token granting op=<X> permits a call only if some argument begins
// with X; any other argument whose first word is one of these verbs but is NOT the
// granted op is a hard denial — this stops a dangerous statement (COPY ... TO
// PROGRAM) riding along behind a benign SELECT. It aims to cover dangerous
// DML/DDL/DCL/admin verbs comprehensively, omitting read-CTE prefixes (WITH, EXPLAIN,
// …) that legitimately lead a read query.
//
// Best-effort first-word matching: it does NOT parse SQL, so stacked or CTE-wrapped
// mutations escape it. For hard enforcement use a least-privilege database role (see
// examples/policies/postgres.yaml).
//
// The set intentionally reaches past query openers into session/admin verbs that are
// not DML — SET, RESET, USE, and the MySQL-specific KILL and HANDLER — because in
// scan-all-args mode (op= shorthand, empty Argument) the first word of EVERY string
// argument is checked, and any of these appearing outside the granted op is a hard
// deny. The trade-off is deliberate but operator-visible: a legitimate call that
// passes a session-config string such as "SET search_path TO public" in some argument
// is denied with OPERATION_NOT_PERMITTED unless that verb is the granted op. An
// operator who needs to allow such verbs alongside a query should use the manifest
// form (Pattern C) with an explicit argument: naming the operation parameter, which
// scopes the check to that one argument instead of scanning all of them. The set
// stays conservative by design: it denies unrecognized verbs, never widens a grant.
var sqlVerbs = map[string]bool{
	// DML
	"SELECT": true, "INSERT": true, "UPDATE": true, "DELETE": true,
	"MERGE": true, "UPSERT": true, "REPLACE": true,
	// DDL
	"CREATE": true, "ALTER": true, "DROP": true, "TRUNCATE": true,
	"RENAME": true, "COMMENT": true,
	// DCL
	"GRANT": true, "REVOKE": true,
	// Routines / dynamic execution
	"CALL": true, "DO": true, "EXECUTE": true, "EXEC": true, "PREPARE": true,
	"DEALLOCATE": true,
	// PostgreSQL / engine-specific data movement and admin (the COPY … TO PROGRAM
	// class is the one that turns a read grant into remote code execution).
	"COPY": true, "VACUUM": true, "ANALYZE": true, "REINDEX": true,
	"CLUSTER": true, "REFRESH": true, "LOCK": true, "SET": true, "RESET": true,
	"LOAD": true, "INSTALL": true, "ATTACH": true, "DETACH": true,
	"IMPORT": true, "BACKUP": true, "RESTORE": true, "SHUTDOWN": true,
	"KILL": true, "USE": true, "HANDLER": true,
}

// isSQLVerb reports whether s is a recognized SQL statement verb,
// case-insensitively, so a caller passing a raw mixed-case token still detects
// smuggled lowercase SQL.
func isSQLVerb(s string) bool {
	return sqlVerbs[strings.ToUpper(s)]
}

// maxArgStringDepth bounds the recursion in collectArgStrings. A host-supplied
// tool-call argument can nest objects/arrays arbitrarily deep; without a limit a
// deeply nested payload would exhaust the goroutine stack and crash the proxy.
const maxArgStringDepth = 64

// collectArgStrings appends every string scalar reachable from v — including those
// nested inside objects and arrays — to out. The scan-all allowedOperations path
// inspects the first word of each, so a SQL verb hidden in a nested object or array
// value is caught rather than skipped. Maps are visited in sorted-key order and
// slices in index order so the result (and therefore any matched operation or
// denial message) is deterministic regardless of Go's randomized map iteration.
//
// It returns false (fail closed) if the argument nesting exceeds maxArgStringDepth,
// so the caller denies rather than recursing without bound.
func collectArgStrings(v interface{}, out *[]string) bool {
	return collectArgStringsDepth(v, out, 0)
}

func collectArgStringsDepth(v interface{}, out *[]string, depth int) bool {
	if depth > maxArgStringDepth {
		return false
	}
	switch t := v.(type) {
	case string:
		*out = append(*out, t)
	case map[string]interface{}:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if !collectArgStringsDepth(t[k], out, depth+1) {
				return false
			}
		}
	case []interface{}:
		for _, e := range t {
			if !collectArgStringsDepth(e, out, depth+1) {
				return false
			}
		}
	}
	return true
}

// evaluateJWTConditions checks JWT-derived conditions against the call arguments.
// Returns a non-nil denial response if any condition fails.
func evaluateJWTConditions(clock enforcement.Clock, conditions []capability.Condition, name string, args map[string]interface{}) *capability.EnforceResponse {
	for _, cond := range conditions {
		switch c := cond.(type) {
		case capability.AllowedOperationsCondition:
			if c.Argument != "" {
				// Intentional fail-closed guard, NOT dead code: this capability-claim grammar
				// has no way to name the operation argument (buildV2Constraint always emits
				// Argument: "" for an "op=" pair), so a validated claim never reaches here. A
				// named argument can only appear on a programmatically built constraint. Keep
				// the guard rather than let it fall to the scan-all-args else branch below: a
				// named argument means "match THIS argument", and scanning all args instead
				// would silently match an alternative — the "never silently match alternatives"
				// invariant. Fail closed rather than re-implement the engine's per-argument
				// taxonomy for this claim-unreachable form.
				resp := denyResponse(clock, capability.ErrCodeConditionFailed, capability.ConditionTypeAllowedOperations,
					fmt.Sprintf("%q: allowedOperations with a named argument is not supported from a capability claim", name))
				return &resp
			} else {
				// Scan-all-args mode: the first word of each string argument is checked
				// against the permitted set. This is sound only for SQL ops, where the
				// isSQLVerb hard-deny below catches a disallowed statement smuggled into
				// any argument. For a non-SQL op there is no "disallowed verbs" set, so
				// fail closed and require the manifest form (Pattern C) that names the
				// operation argument.
				for _, op := range c.Operations {
					if !isSQLVerb(op) {
						resp := denyResponse(clock, capability.ErrCodeConditionFailed, capability.ConditionTypeAllowedOperations,
							fmt.Sprintf("%q: non-SQL operation %q cannot be safely enforced without an explicit argument naming the operation parameter; use the manifest form that names the argument", name, op))
						return &resp
					}
				}
				// All granted ops are SQL verbs: scan ALL arguments (do not break on the
				// first match) and deny if any argument's first word is a SQL verb
				// outside the allowed set. This closes the multi-argument bypass (e.g.
				// op=SELECT granted, but {"sql":"DROP TABLE x","note":"SELECT 1"}).
				var matchedOp string
				// Scan every string scalar reachable from the arguments, including those
				// nested inside objects and arrays: a SQL verb smuggled into a nested
				// value (e.g. {"query":{"sql":"DROP TABLE x"}}) would otherwise be skipped,
				// letting a disallowed statement through while a benign sibling string
				// matched a permitted op. collectArgStrings walks maps in sorted-key order
				// and slices in index order, so matchedOp and any denial message stay
				// deterministic (independent of Go's randomized map iteration).
				var argStrings []string
				if !collectArgStrings(args, &argStrings) {
					// Argument nesting exceeded the depth bound; fail closed rather
					// than risk stack exhaustion or an incomplete (and therefore
					// unsound) scan.
					resp := denyResponse(clock, capability.ErrCodeConditionFailed, capability.ConditionTypeAllowedOperations,
						fmt.Sprintf("%q: arguments nested too deeply to scan for operations", name))
					return &resp
				}
				for _, s := range argStrings {
					word := enforcement.OperationVerb(s)
					if word == "" {
						continue
					}
					if capability.MatchOperation(c.Operations, word) {
						matchedOp = word
						continue
					}
					// A disallowed SQL statement in any argument is a hard denial.
					if isSQLVerb(word) {
						resp := denyResponse(clock, capability.ErrCodeOperationNotPermitted, capability.ConditionTypeAllowedOperations,
							fmt.Sprintf("%q: operation %q is not in the permitted set %v", name, word, c.Operations))
						return &resp
					}
				}
				// matchedOp is non-empty only if some argument matched a permitted
				// operation, so the only failure left is "no argument matched any".
				if matchedOp == "" {
					resp := denyResponse(clock, capability.ErrCodeMissingContext, capability.ConditionTypeAllowedOperations,
						fmt.Sprintf("%q: no matching operation found in arguments", name))
					return &resp
				}
			}
		case capability.AllowedValuesCondition:
			// Distinguish "argument absent" from "present but not a string" (collapsing
			// both would let a "*" pattern match an absent arg), mirroring the engine's
			// handleAllowedValues MISSING_CONTEXT. ResolveArgument keeps "$.nested.key"
			// resolution identical to the engine's.
			rawVal, argExists := enforcement.ResolveArgument(args, c.Argument)
			if !argExists {
				resp := denyResponse(clock, capability.ErrCodeMissingContext, capability.ConditionTypeAllowedValues,
					fmt.Sprintf("%q: argument %q is absent", name, c.Argument))
				return &resp
			}
			// One enforcement point for both shapes: the shared MatchAllowedValue treats a
			// string allowed-value as a glob (which cannot match a non-string argument) and
			// a non-string allowed-value as an exact match with numeric coercion, so the
			// string and non-string cases differ only in how the DENIAL reads — a string
			// value is quoted into the message, a non-string one is not (its Go rendering
			// would be neither the wire form nor useful).
			if !enforcement.MatchAllowedValue(rawVal, c.Values) {
				detail := fmt.Sprintf("%q: argument %q value is not in the permitted set", name, c.Argument)
				if val, isStr := rawVal.(string); isStr {
					detail = fmt.Sprintf("%q: argument %q value %q is not permitted", name, c.Argument, val)
				}
				resp := denyResponse(clock, capability.ErrCodeValueNotPermitted, capability.ConditionTypeAllowedValues, detail)
				return &resp
			}
		default:
			// Fail closed on any condition type without an evaluator. buildV2Constraint
			// emits only AllowedOperations/AllowedValues today, so this is unreachable —
			// but a new type added there without a case here must deny, not be skipped.
			resp := denyResponse(clock, capability.ErrCodeConditionFailed, cond.ConditionType(),
				fmt.Sprintf("%q: JWT condition type %q has no evaluator; deny (fail closed)", name, cond.ConditionType()))
			return &resp
		}
	}
	return nil
}
