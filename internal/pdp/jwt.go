// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// JWT PDP mode for IdP-issued capability claims (--jwks-uri).
//
// The proxy validates the Authorization: Bearer token on every HTTP request,
// extracts MCP capability claims (schema v0.2, nested under "mcp" since IdPs treat
// claim-name dots as path separators), and evaluates them per call as
// capability.Constraint values.
//
// Shorthand: "<namespace>:<name>[?<key>=<value>&…]", e.g.
// "tool:read_file?path=/reports/*" or "resource:https://api/data?format=json" (the
// "?" there is the URL's own query, not a condition suffix). See parseV2Claim and
// evaluateJWTConditions for the full grammar and condition semantics.
//
// EXPERIMENTAL: mcp.capabilities enforcement is off by default
// (--jwt-experimental-capabilities); a token carrying it is rejected, not silently
// admitted with its restriction dropped, until the flag is set. Identity claims and
// signature/exp/iss/aud verification are always active regardless.
//
// With --policy also set, JWT and manifest are intersected: a token can only
// restrict what the manifest allows, never expand it.
//
// Breaking change from v0.1: only mcp.v="0.2" is accepted; the v0.1 colon-only
// shorthand is rejected.

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

type jwtClaimsKey struct{}

// JWTClaims holds the MCP capability claims extracted from an IdP JWT.
type JWTClaims struct {
	Capabilities []string
	// HasCapabilities distinguishes "field absent" from "present but empty": true
	// means the token carries an exhaustive allowlist even if it lists nothing;
	// false means the JWT imposes no restriction and defers to the manifest PDP.
	HasCapabilities bool
	TaskID          string
	AgentID         string
	Subject         string
	Issuer          string
	// Audiences is the verified `aud` claim (always a list). Lets a per-route
	// wrapper pin its own audience after the shared validator accepts the token
	// for the union of all routes — see routeAudience / WrapRoutesWithJWT.
	Audiences []string
	// Declassify holds validated human approvals from `mcp.declassify`, parsed and
	// checked at the token boundary (not read from Extra) because it is the only
	// thing that lets a declassify directive clear a flow label instead of escalating.
	Declassify []capability.DeclassifyApproval
	// Delegation holds the validated RFC 8693 `act` chain plus `mcp.delegation`
	// grants, already asserted to narrow at every hop — a widening chain is a
	// rejected token at ValidateToken, not a decision-time surprise.
	Delegation *capability.DelegationChain
	// ExpiresAt is the verified `exp`. A long-lived SSE stream is validated once at
	// open, so the transport arms a timer at this instant to cut the stream at token
	// expiry — the idle reaper alone would let an expired client keep reading.
	ExpiresAt time.Time
	// Extra holds every raw top-level claim as the IdP emitted it, feeding
	// input.claims (jwtClaimsAsMap) so a policy can reference any IdP claim.
	Extra map[string]interface{}

	// parsedCaps caches parseCapHeads's output from validation time, so later
	// Decides skip re-parsing each claim head. Nil for a JWTClaims built without
	// ValidateToken (tests), where Decide parses Capabilities directly.
	parsedCaps []capHead

	// flatClaims caches the flattened input.claims map, built once at validation
	// since every request against this token reuses it read-only (rebuilding per
	// call copied every Extra entry each time). Populated eagerly rather than
	// lazily because the *JWTClaims is shared across a session's requests and a
	// lazy write would race concurrent readers. MUST stay read-only — it is handed
	// to third-party PolicyEvaluators.
	flatClaims map[string]interface{}
}

// WithJWTClaims returns a child context carrying the given JWT claims.
func WithJWTClaims(ctx context.Context, claims *JWTClaims) context.Context {
	return context.WithValue(ctx, jwtClaimsKey{}, claims)
}

// declassifyApprovalsFromContext returns the token's granted declassify approvals, or
// nil (the default, without a token or approval) — which makes a deployment with no
// approval integration escalate a declassify directive rather than silently perform it.
// Reads the typed, validated JWTClaims rather than the flat input.claims map, since a
// security-critical decision should not depend on the third-party-evaluator convenience view.
func declassifyApprovalsFromContext(ctx context.Context) []capability.DeclassifyApproval {
	if c, ok := jwtClaimsFromContext(ctx); ok {
		return c.Declassify
	}
	return nil
}

// delegationFromContext returns the token's validated delegation chain, or nil (the
// default) when there is none — reads the typed JWTClaims for the same reason
// declassifyApprovalsFromContext does.
func delegationFromContext(ctx context.Context) *capability.DelegationChain {
	if c, ok := jwtClaimsFromContext(ctx); ok {
		return c.Delegation
	}
	return nil
}

// jwtClaimsFromContext retrieves JWT claims from the context.
func jwtClaimsFromContext(ctx context.Context) (*JWTClaims, bool) {
	c, ok := ctx.Value(jwtClaimsKey{}).(*JWTClaims)
	return c, ok && c != nil
}

// The caller identity a record is stamped with is deliberately NOT built here: returning
// the audit writer's own struct would have linked internal/pdp to the audit writer for
// every consumer. The adapter lives at cmd/eunox/audit_identity.go, the one place that
// imports both, over the exported JWTClaimsPtr.

// mcpClaimVersion is the only accepted value for the mcp claim set's "v" field —
// other versions (including "0.1") are rejected rather than silently misinterpreted.
const mcpClaimVersion = "0.2"

// mcpClaimSet holds the MCP-specific fields nested under "mcp" (IdPs treat dots in a
// claim name as path separators).
//
// Capabilities is a pointer to distinguish absent (nil, defers to the manifest) from
// present-but-empty (&[]string{}, denies everything per the exhaustive-allowlist rule).
type mcpClaimSet struct {
	Version      string    `json:"v"`
	Capabilities *[]string `json:"capabilities,omitempty"`
	TaskID       string    `json:"task_id"`
	AgentID      string    `json:"agent_id"`
	// Declassify is held raw and decoded via capability.ParseDeclassifyApprovals so
	// the grammar, validation, and unknown-field rejection live in that package.
	Declassify json.RawMessage `json:"declassify,omitempty"`
	// Delegation is held raw and decoded via capability.ParseDelegationGrants, for
	// the same reason Declassify is.
	Delegation json.RawMessage `json:"delegation,omitempty"`
}

// idpJWTPayload is the subset of IdP JWT claims relevant to MCP enforcement.
// Standard fields (iss, sub, exp, iat, aud) are parsed separately by jwt.Claims.
type idpJWTPayload struct {
	MCP mcpClaimSet `json:"mcp"`
	// Act is top-level rather than nested under mcp because it is a standard RFC
	// 8693 §4.1 OAuth claim an IdP emits on its own terms; walked by ParseActorChain.
	Act json.RawMessage `json:"act,omitempty"`
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
	allowAnyAudience bool
	allowAnyIssuer   bool
	// acceptedAudiences is the set ValidateToken accepts (go-jose "at least one
	// of"); empty falls back to {audience}. The gateway's shared validator sets it to
	// the UNION of every route's audience so any route's token clears validation,
	// then each route wrapper narrows via routeAudience. Unused by route wrappers.
	acceptedAudiences []string
	// routeAudience is this wrapper's per-route audience check in Decide/filterList:
	// the route's manifest 'audience', else the global --jwt-audience fallback. Empty
	// (single-upstream/shared-validator) or --jwt-allow-any-audience disables it.
	routeAudience string
	inner         PolicyDecisionPoint // optional manifest PDP for intersection
	ks            killswitch.Checker  // kill switch enforced even in JWT-only mode
	leeway        time.Duration       // clock-skew grace, resolved via effectiveLeeway
	// clock supplies "now"; nil falls back to the wall clock. Shared type with the
	// engine and JWKS cache so a frozen test clock stays consistent across all three.
	clock enforcement.Clock
	// experimentalCapabilities gates mcp.capabilities enforcement (--jwt-experimental-capabilities).
	// False rejects a token carrying the claim (fail closed) rather than admitting it
	// with the restriction silently dropped (fail open).
	experimentalCapabilities bool
	// tokenCache memoizes verified *JWTClaims by token hash so a repeat bearer token
	// skips signature re-verification and claim decoding. Consulted only by
	// ValidateToken (the shared validator) — route wrappers call Decide and leave
	// their cache empty. Kill switch, route audience, and policy are still per-call.
	tokenCache *capability.PayloadCache[*JWTClaims]
}

// JWTPDPOptions configures a JWTPDP.
type JWTPDPOptions struct {
	JWKSURI  string
	Issuer   string
	Audience string
	// AllowAnyAudience disables audience pinning. When false (default) and Audience
	// (and AcceptedAudiences) is empty, EVERY token is rejected regardless of aud —
	// including a literal empty aud — rather than falling back to
	// jwt.Expected{AnyAudience: [""]}, whose set-intersection match would admit it.
	AllowAnyAudience bool
	// AcceptedAudiences widens validation beyond the single Audience: valid if aud
	// carries at least one entry. Empty falls back to {Audience}. The gateway's shared
	// validator sets this to the union of every route's audience; each route wrapper
	// then narrows via RouteAudience. Ignored when AllowAnyAudience is set.
	AcceptedAudiences []string
	// RouteAudience is the per-route audience required in Decide/filterList (the
	// route's manifest 'audience', else Audience). Empty disables the per-route
	// check. Set by WrapRoutesWithJWT; ignored when AllowAnyAudience is set.
	RouteAudience string
	// AllowAnyIssuer disables issuer pinning. When false (default), Issuer is always
	// pinned — even empty, which fail-closed rejects every non-empty-iss token
	// rather than accepting any issuer that happens to share the JWKS.
	AllowAnyIssuer bool
	// Inner is the manifest PDP for intersection when both --jwks-uri and --policy
	// are set. When nil, only JWT claims are enforced.
	Inner PolicyDecisionPoint
	// KillSwitch is consulted at the top of every Decide so global and
	// per-session/per-agent kills take effect even in JWT-only mode.
	KillSwitch killswitch.Checker
	// CacheTTL is how long a fetched JWKS is served from cache (default 5 minutes).
	// It governs KEY freshness only — NOT the separate verified-token claim cache
	// (fixed 30s, not operator-tunable, capped by the token's own exp). The kill
	// switch, route audience, and policy are still re-checked every call, so
	// revocation latency is bounded by the kill switch, not this TTL.
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
	// ExperimentalCapabilities enables mcp.capabilities enforcement (--jwt-experimental-capabilities);
	// false rejects a carrying token rather than silently dropping its restriction.
	ExperimentalCapabilities bool
}

// DefaultJWTLeeway is the clock-skew grace used when JWTPDPOptions.Leeway is zero.
// Aliases capability.DefaultTokenLeeway, the source of truth for every JWKS-verified
// token-validation path in the binary.
const DefaultJWTLeeway = capability.DefaultTokenLeeway

// effectiveLeeway resolves configured leeway (zero -> default, negative -> disabled,
// positive -> as-is) via capability.EffectiveLeeway so the two token paths agree.
func effectiveLeeway(configured time.Duration) time.Duration {
	return capability.EffectiveLeeway(configured)
}

// jwtLogger pins JWT/JWKS logging to stderr, since stdout is the JSON-RPC channel in
// stdio mode. Package-level so parseCapHeads (which has no receiver) and the
// constructor's warnings emit through the same structured, SIEM-correlatable handler.
var jwtLogger = slog.New(slog.NewTextHandler(os.Stderr, nil))

// NewJWTPDP creates a JWTPDP ready to validate tokens.
func NewJWTPDP(opts JWTPDPOptions) *JWTPDP {
	// capability.NewJWKSCache leaves the breaker opt-in; default one here so the
	// shipped proxy always has JWKS-fetch protection.
	breaker := opts.Breaker
	if breaker == nil {
		breaker = circuitbreaker.New(circuitbreaker.DefaultConfig())
	}
	logger := jwtLogger
	if normalizeAudience(opts.Audience) == "" && len(sanitizeAudiences(opts.AcceptedAudiences)) == 0 && !opts.AllowAnyAudience {
		// No audience pinned and no opt-out: every token will be rejected regardless
		// of aud. Likely a misconfiguration, so surface it.
		logger.Warn("JWTPDP created without an Audience and without AllowAnyAudience; all tokens will be rejected regardless of aud because no audience is pinned (set --jwt-audience, or --jwt-allow-any-audience to accept any)")
	}
	if opts.Issuer == "" && !opts.AllowAnyIssuer {
		// No issuer pinned and no opt-out: every token will be rejected regardless of
		// iss (even one with no iss at all). Likely a misconfiguration, so surface it.
		logger.Warn("JWTPDP created without an Issuer and without AllowAnyIssuer; all tokens will be rejected regardless of iss because no issuer is pinned (set --jwt-issuer, or --jwt-allow-any-issuer to accept any)")
	}
	cacheConfig := capability.JWKSCacheConfig{
		JWKSURL:  opts.JWKSURI,
		CacheTTL: opts.CacheTTL,
		Client:   opts.Client,
		Breaker:  breaker,
		Logger:   logger,
	}
	// Wire the injected clock in so a frozen test clock stays consistent across
	// exp/nbf validation, the engine, and the cache TTL.
	if opts.Clock != nil {
		cacheConfig.Now = opts.Clock.Now
	}
	p := newJWTPDP(opts, capability.NewJWKSCache(cacheConfig))
	// Only a shared VALIDATOR gets a token cache: it is written solely by
	// ValidateToken, and a per-route wrapper (NewJWTPDPWithCache) only intersects
	// already-validated claims, so its cache would stay empty for the process
	// lifetime — PayloadCache's Get/Put are nil-receiver safe, so leaving it nil
	// there is simply the miss path.
	p.tokenCache = newJWTTokenCache(p.now)
	return p
}

// normalizeAudience collapses a whitespace-only audience to "" so the fail-closed
// guard in validateStandardClaims (which tests == "") catches it. A non-empty
// audience is returned unchanged, byte-for-byte.
func normalizeAudience(aud string) string {
	if strings.TrimSpace(aud) == "" {
		return ""
	}
	return aud
}

// sanitizeAudiences drops empty/whitespace-only entries from an accepted-audience
// list. go-jose matches audiences by set intersection, so an AnyAudience carrying ""
// would ACCEPT a token whose own aud is the literal empty string instead of rejecting
// everything as intended. Returns a fresh slice, except for an already-empty input
// (nothing to drop, so the original — itself empty — is handed back unmodified);
// dropping every entry falls back to validateStandardClaims' single-audience
// fail-closed path.
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
// NewJWTPDP and NewJWTPDPWithCache route through this so the field set is defined
// once and the two constructors cannot drift when a field is added.
func newJWTPDP(opts JWTPDPOptions, cache *capability.JWKSCache) *JWTPDP {
	p := &JWTPDP{
		cache:  cache,
		issuer: opts.Issuer,
		// normalizeAudience/sanitizeAudiences guard the fail-closed empty-audience
		// checks below; kept here too as defense in depth for a direct
		// JWTPDPOptions consumer bypassing the transport/CLI wiring.
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
// cache. Route wrappers never fetch keys themselves, so a fresh JWKSCache per route
// would waste N-1 allocations. No audience warning here — the shared validator
// (NewJWTPDP) already warns once.
func NewJWTPDPWithCache(opts JWTPDPOptions, cache *capability.JWKSCache) *JWTPDP {
	return newJWTPDP(opts, cache)
}

// Cache returns the JWKS cache this validator owns, so a gateway can build
// per-route wrappers (NewJWTPDPWithCache) that share one key-fetching cache — and so a
// health endpoint can read that one cache's key-fetch state (BreakerStats) knowing every
// route answers from it.
func (p *JWTPDP) Cache() *capability.JWKSCache {
	return p.cache
}

// innerEnforces reports whether p.inner is a real policy backstop for an
// identity-only (no mcp.capabilities) request. Neither nil nor AlwaysAllowPDP
// qualify — in JWT mode the wrapper must fail closed, not inherit allow-everything.
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

// jwtPayloadSegment base64url-decodes a compact JWS's middle (payload) segment, for a
// caller needing the raw bytes rather than a value decoded from them.
func jwtPayloadSegment(tokenStr string) ([]byte, error) {
	parts := strings.Split(tokenStr, ".")
	// Reject anything but the standard three segments (fail closed), in case a
	// future caller invokes this before verification.
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed JWT: expected 3 segments (header.payload.signature), got %d", len(parts))
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding JWT payload segment: %w", err)
	}
	return payloadBytes, nil
}

// decodeJWTClaimsPreservingNumbers re-decodes the claim map with json.Number so
// integers above 2^53 survive exactly for input.claims, instead of rounding through
// float64 as go-jose's UnsafeClaimsWithoutVerification would. The signature is
// already verified by the caller, so these bytes are known authentic.
func decodeJWTClaimsPreservingNumbers(tokenStr string) (map[string]interface{}, error) {
	payloadBytes, err := jwtPayloadSegment(tokenStr)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(payloadBytes))
	dec.UseNumber()
	var claims map[string]interface{}
	if err := dec.Decode(&claims); err != nil {
		return nil, fmt.Errorf("decoding claims: %w", err)
	}
	// Reject trailing bytes (fail closed): a well-formed payload is one JSON object,
	// and trailer bytes signal a non-conforming issuer.
	if dec.More() {
		return nil, fmt.Errorf("trailing data in JWT claims payload")
	}
	return claims, nil
}

// Stable JWT-failure category codes for the JWT_INVALID audit record's error_type
// detail — a closed set so a record never carries the raw go-jose/validation
// message, which can disclose claim values, algorithm, issuer, or key-rotation state.
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
	jwtErrInvalidDeclassify    = "invalid_declassify"
	jwtErrInvalidDelegation    = "invalid_delegation"
	// jwtErrAmbiguousClaims marks a top-level `mcp`/`act` claim, or an `mcp` member,
	// spelled more than one way (see capability.ClaimMembers) — the payload IS valid
	// JSON, but which spelling wins is invisible to the token's own author.
	jwtErrAmbiguousClaims   = "ambiguous_claims"
	jwtErrSenderConstrained = "sender_constrained"
	// jwtErrJWKSUnavailable marks a key-fetch failure rather than a bad token, so an
	// IdP/JWKS outage is not recorded identically to a forged token in the audit trail.
	jwtErrJWKSUnavailable = "jwks_unavailable"
	jwtErrUnknown         = "invalid"
)

// jwtValidationError tags a ValidateToken failure with a stable category code while
// preserving the message for logs/tests. ClassifyJWTError reads the code via
// errors.As, so wrapping through capability.Terminal (which Unwraps) is safe.
type jwtValidationError struct {
	code string
	err  error
}

func (e *jwtValidationError) Error() string { return e.err.Error() }
func (e *jwtValidationError) Unwrap() error { return e.err }

// jwtErr tags err with a stable classification code (see ClassifyJWTError). Prints
// exactly as err, so existing message-substring tests are unaffected.
func jwtErr(code string, err error) error { return &jwtValidationError{code: code, err: err} }

// ClassifyJWTError maps a ValidateToken error to a small, stable category code for
// the JWT_INVALID audit record. It NEVER returns the raw error text, since the
// underlying message can disclose claim values, algorithm, issuer, or key-rotation
// state to a SIEM the audit log is forwarded to. Empty error yields ""; unrecognized
// yields "invalid".
func ClassifyJWTError(err error) string {
	if err == nil {
		return ""
	}
	// An eunox-tagged site states its category explicitly; honor it first.
	var ve *jwtValidationError
	if errors.As(err, &ve) {
		return ve.code
	}
	// The untagged standard-claim path emits only these sentinels under eunox's
	// Expected{Time, AnyAudience}. Issuer/subject failures don't arrive here — eunox
	// runs its own checks (caught above) — and go-jose skips its built-in iss/sub
	// validation since Expected leaves those fields unset.
	switch {
	case errors.Is(err, capability.ErrJWKSUnavailable):
		// The key set could not be fetched — an infrastructure outage, not a bad
		// token, so classify it distinctly rather than collapsing to "invalid".
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

// parseDelegationChain decodes and asserts a token's delegation state (the RFC 8693
// `act` chain plus `mcp.delegation` grants) at the TOKEN boundary, like the declassify
// approvals: a chain this build cannot read, or whose hops WIDEN, is a rejected token
// rather than a silently-clamped one — clamping would leave the token meaning
// something other than what it says. Unlike mcp.capabilities this is not behind the
// experimental gate: every axis only narrows, so there is no fail-open direction to
// gate against.
//
// Returns (nil, nil) for tokens declaring neither claim. Errors are Terminal-wrapped.
func parseDelegationChain(payload idpJWTPayload) (*capability.DelegationChain, error) {
	actors, err := capability.ParseActorChain(payload.Act)
	if err != nil {
		return nil, capability.Terminal(jwtErr(jwtErrInvalidDelegation, err))
	}
	grants, err := capability.ParseDelegationGrants(payload.MCP.Delegation)
	if err != nil {
		return nil, capability.Terminal(jwtErr(jwtErrInvalidDelegation, err))
	}
	chain, err := capability.ValidateDelegationChain(actors, grants)
	if err != nil {
		return nil, capability.Terminal(jwtErr(jwtErrInvalidDelegation, err))
	}
	return chain, nil
}

// watchedTopLevelClaims is every top-level claim THIS BUILD READS — one list rather
// than a var plus a spliced call-site literal, so a claim can't be added to one and
// missed in the other. Membership is "does this build read it", not "is it a
// registered claim" (ClaimMembers' own criterion):
//
//   - `jti` is deliberately ABSENT — nothing here decodes it, so watching it would
//     reject tokens over a spelling collision in a claim eunox never reads.
//   - `cnf` is deliberately PRESENT despite not being a go-jose std claim: it is read
//     from the raw map (last-member-wins), and an ambiguous `cnf` fails OPEN —
//     `{"cnf":{"jkt":…},"cnf":null}` resolves to null, which CnfIsSenderConstrained
//     reads as absent, silently downgrading a PoP-bound token to a plain bearer token.
//
// Listed explicitly rather than reflected off jwt.Claims, so a go-jose release that
// adds or renames a field can't silently widen or narrow this check.
var watchedTopLevelClaims = []string{
	// The proxy's own claim blocks.
	"mcp", "act",
	// Identity and audience: `sub` is what a manifest's principal: scoping reads.
	"sub", "iss", "aud",
	// Temporal bounds: whether the token is live at all.
	"exp", "nbf", "iat",
	// Proof-of-possession: read from the raw claim map, and the one that fails open.
	"cnf",
}

// rejectAmbiguousTopLevelClaims confirms the payload names each watched claim, and the
// `mcp` block each of its own members, at most once — before anything decoded from
// them is trusted.
//
// The earlier struct unmarshals resolve any collision silently: encoding/json folds
// field names case-insensitively and keeps the last one, so e.g. both "act" and "Act"
// bind to whichever spelling was written LAST with no signal a sibling ever existed.
// Not externally forgeable (the JWT is signed), but an IdP template mistake or a
// migration that left two spellings live should be a rejected token, not a
// silently-resolved one — matching the per-grant decoders one layer in.
//
// `sub` matters most: a payload with both "sub" and "Sub" would be enforced under
// whichever identity sorts last, a value neither side of the exchange controls,
// potentially widening a narrowly-scoped agent's token to a broader identity's
// constraints.
func rejectAmbiguousTopLevelClaims(tokenStr string) error {
	payloadBytes, err := jwtPayloadSegment(tokenStr)
	if err != nil {
		return capability.Terminal(jwtErr(jwtErrMalformedToken, err))
	}
	top, err := capability.ClaimMembers(payloadBytes, "jwt payload", watchedTopLevelClaims...)
	if err != nil {
		return capability.Terminal(jwtErr(jwtErrAmbiguousClaims, err))
	}
	mcpBytes, ok := top[capability.FoldJSONKey("mcp")]
	if !ok {
		return nil
	}
	if _, err := capability.ClaimMembers(mcpBytes, "jwt mcp claim",
		"v", "capabilities", "task_id", "agent_id", "declassify", "delegation"); err != nil {
		return capability.Terminal(jwtErr(jwtErrAmbiguousClaims, err))
	}
	return nil
}

// newValidatedClaims assembles the *JWTClaims ValidateToken returns, memoizing the
// two derived views later requests reuse (parsedCaps, flatClaims) so decide/list-filter/
// sampling calls hand out precomputed values instead of rebuilding them per request.
func newValidatedClaims(capsList []string, capsPresent bool, declassify []capability.DeclassifyApproval, delegation *capability.DelegationChain, payload idpJWTPayload, std jwt.Claims, rawClaims map[string]interface{}) *JWTClaims {
	claims := &JWTClaims{
		Capabilities:    capsList,
		HasCapabilities: capsPresent,
		Declassify:      declassify,
		Delegation:      delegation,
		TaskID:          payload.MCP.TaskID,
		AgentID:         payload.MCP.AgentID,
		Subject:         std.Subject,
		Issuer:          std.Issuer,
		Audiences:       []string(std.Audience),
		Extra:           rawClaims,
		parsedCaps:      parseCapHeads(capsList),
	}
	// validateStandardClaims (run before this) rejects a token with no exp, so
	// std.Expiry is non-nil here on the ValidateToken path; guard anyway for callers
	// that build claims directly.
	if std.Expiry != nil {
		claims.ExpiresAt = std.Expiry.Time()
	}
	claims.flatClaims = buildFlatClaims(claims)
	return claims
}

// validateStandardClaims enforces the RFC 7519 standard claims on an already
// signature-verified token and returns exp (Unix seconds) so the caller can cap the
// verified-token cache TTL at it. now is the single lazily-sampled validation clock,
// so exp/nbf are deterministic across key-rotation retries. Extracted from
// ValidateToken to keep that function under the complexity budget.
func (p *JWTPDP) validateStandardClaims(stdClaims jwt.Claims, now time.Time) (int64, error) {
	// go-jose validates iat/exp only when present, so require both explicitly —
	// otherwise an absent one imposes no bound (no lower bound, or never expires).
	if stdClaims.IssuedAt == nil {
		return 0, capability.Terminal(jwtErr(jwtErrMissingClaims, fmt.Errorf("token has no iat claim; tokens without an issued-at time are rejected")))
	}
	if stdClaims.Expiry == nil {
		return 0, capability.Terminal(jwtErr(jwtErrMissingClaims, fmt.Errorf("token has no exp claim; non-expiring tokens are rejected")))
	}
	// acceptedAudiences widens validation to the UNION of every route's audience (the
	// gateway's shared validator); the per-route wrapper narrows via routeAudience later.
	//
	// When neither audience nor acceptedAudiences is configured, reject explicitly
	// here rather than fall back to jwt.Expected{AnyAudience: [""]}: go-jose's
	// set-intersection match would admit a token whose own aud is the literal empty
	// string instead of rejecting everything as the sentinel intends.
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
	// Mirrors the audience check: enforced even when p.issuer is empty, so there is
	// no pinned issuer to silently trust an arbitrary JWKS-sharing signer under.
	if !p.allowAnyIssuer && (p.issuer == "" || stdClaims.Issuer != p.issuer) {
		return 0, capability.Terminal(jwtErr(jwtErrInvalidIssuer, fmt.Errorf("token issuer %q does not match expected %q", stdClaims.Issuer, p.issuer)))
	}
	return stdClaims.Expiry.Time().Unix(), nil
}

// parseDeclassifyApprovals decodes mcp.declassify and refuses a token whose single-use
// grants would outlive the burn ledger's WINDOW — otherwise a long-lived token could
// present the same grant again after the burn aged out and clear a second time on one
// human approval. Refusing bounds the token's remaining lifetime against the same exp
// validateStandardClaims just accepted, so a later burn always outlives any token that
// could replay it. Runs at the token boundary for the same reason every claim-borne
// narrowing does: an unenforceable grant is a rejected token, not a decision-time surprise.
//
// expUnix reuses validateStandardClaims' already-accepted exp rather than a second
// dereference of stdClaims.Expiry, which is non-nil only because that check ran first.
//
// A non-positive expUnix stays the ZERO time rather than time.Unix(0, 0): the latter is
// a real (non-zero) 1970 instant that would sail through the window check as a lifetime
// decades in the past, admitting a `once` grant on a token with no established expiry.
func (p *JWTPDP) parseDeclassifyApprovals(raw json.RawMessage, expUnix int64, now time.Time) ([]capability.DeclassifyApproval, error) {
	approvals, err := capability.ParseDeclassifyApprovals(raw)
	if err != nil {
		return nil, capability.Terminal(jwtErr(jwtErrInvalidDeclassify, err))
	}
	var exp time.Time
	if expUnix > 0 {
		exp = time.Unix(expUnix, 0)
	}
	if err := capability.CheckDeclassifyApprovalLifetime(approvals, exp, now, p.leeway); err != nil {
		return nil, capability.Terminal(jwtErr(jwtErrInvalidDeclassify, err))
	}
	return approvals, nil
}

// ValidateToken validates the Authorization: Bearer token in the request,
// extracts eunox claims, and returns a new context carrying the claims.
// On failure it returns an error whose message is safe to surface as HTTP 401.
func (p *JWTPDP) ValidateToken(ctx context.Context, authHeader string) (context.Context, error) {
	// RFC 7235 §2.1: the auth-scheme is case-insensitive, matched with EqualFold;
	// the token itself stays case-sensitive.
	const prefix = "Bearer "
	if len(authHeader) < len(prefix) || !strings.EqualFold(authHeader[:len(prefix)], prefix) {
		return ctx, jwtErr(jwtErrMalformedHeader, fmt.Errorf("missing or malformed Authorization header"))
	}
	tokenStr := authHeader[len(prefix):]

	// Fast path: a token verified within the cache TTL skips re-verification and
	// re-decoding. Kill switch, route audience, and policy are still checked per call
	// in Decide, so this only elides the crypto + decode.
	cacheKey := capability.HashTokenKey(tokenStr)
	if cached, ok := p.tokenCache.Get(cacheKey); ok {
		return WithJWTClaims(ctx, cached), nil
	}

	tok, err := jwt.ParseSigned(tokenStr, capability.JWKSAlgorithms())
	if err != nil {
		return ctx, jwtErr(jwtErrMalformedToken, fmt.Errorf("invalid JWT: %w", err))
	}

	// Select the signing key from EVERY header's kid, not a hard-coded headers[0], so
	// a multi-signature token is handled correctly. A kid-less token keeps the ""
	// (try-all-keys) sentinel; this enforces no kid-required policy.
	kids, err := capability.CandidateKIDs(tok.Headers)
	if err != nil {
		return ctx, jwtErr(jwtErrMalformedToken, err)
	}

	// capability.VerifyWithKeyRotation owns key-selection and rotation-retry
	// choreography; the closure returns (claims, nil) on success, (nil,
	// Terminal(err)) for a verified-but-invalid failure that must not be retried,
	// and (nil, err) for a signature failure.
	//
	// now is sampled lazily on first use (nowSampled) rather than up front, so a
	// slow JWKS round-trip doesn't widen the exp window (fail-open). It is
	// re-sampled only on a genuine refresh (freshKeySet) — never on a cache hit, so
	// the exp+leeway verdict can't flip between sibling/cached keys on network
	// latency — and re-sampling only ever moves now forward, the fail-closed direction.
	var now time.Time
	var nowSampled bool
	// tokenExpUnix caps the cache entry's TTL at the token's remaining lifetime, so
	// a structurally expired token is never served from cache.
	var tokenExpUnix int64
	validated, err := capability.VerifyWithKeyRotationMultiKID[JWTClaims](ctx, p.cache, kids, func(key *jose.JSONWebKey, freshKeySet bool) (*JWTClaims, error) {
		if !nowSampled || freshKeySet {
			now = p.now()
			nowSampled = true
		}
		var stdClaims jwt.Claims

		// Step 1: verify the signature only, so a mismatch is reported as such and
		// not conflated with a payload unmarshal failure. A plain (un-Terminal)
		// error marks a retryable signature failure.
		if err := tok.Claims(key, &stdClaims); err != nil {
			return nil, err
		}

		// Step 2 (signature verified): the token bytes are key-independent, so a
		// parse failure here is terminal — retrying other keys would report a later
		// key's error over the real payload problem.
		var payload idpJWTPayload
		if err := tok.UnsafeClaimsWithoutVerification(&payload); err != nil {
			return nil, capability.Terminal(jwtErr(jwtErrMalformedToken, fmt.Errorf("jwt payload unmarshal: %w", err)))
		}
		rawClaims, rawErr := decodeJWTClaimsPreservingNumbers(tokenStr)
		if rawErr != nil {
			return nil, capability.Terminal(jwtErr(jwtErrMalformedToken, fmt.Errorf("jwt raw claims decode: %w", rawErr)))
		}
		// The struct unmarshal above resolves an "act"/"Act" (or mcp-block) collision
		// silently; confirm there was only one candidate before trusting either.
		if err := rejectAmbiguousTopLevelClaims(tokenStr); err != nil {
			return nil, err
		}
		exp, stdErr := p.validateStandardClaims(stdClaims, now)
		if stdErr != nil {
			return nil, stdErr
		}
		tokenExpUnix = exp

		// An absent mcp claim block is the most common IdP-template
		// misconfiguration; give it an actionable message before the version check.
		if payload.MCP.Version == "" {
			return nil, capability.Terminal(jwtErr(jwtErrMissingClaims, fmt.Errorf("jwt is missing the required mcp capability claim (expected mcp.v=%q); the token has no mcp claim block", mcpClaimVersion)))
		}
		if payload.MCP.Version != mcpClaimVersion {
			return nil, capability.Terminal(jwtErr(jwtErrUnsupportedVersion, fmt.Errorf("unsupported mcp claim version %q (want %q)", payload.MCP.Version, mcpClaimVersion)))
		}

		// A present `mcp.capabilities` of JSON null must be REJECTED, not treated as
		// absent: the *[]string pointer can't tell absent from explicit null (both
		// decode to nil), so a null token would otherwise bypass the exhaustive
		// allowlist as identity-only. Probe the raw claims for the literal key.
		if mcpRaw, ok := rawClaims["mcp"].(map[string]interface{}); ok {
			if capRaw, present := mcpRaw["capabilities"]; present && capRaw == nil {
				return nil, capability.Terminal(jwtErr(jwtErrInvalidCapabilities, fmt.Errorf("mcp.capabilities is present but null; a null capability claim is rejected — use [] for an empty (deny-all) allowlist or omit the field to defer to the manifest")))
			}
		}

		capabilitiesPresent := payload.MCP.Capabilities != nil

		// EXPERIMENTAL gate: off by default, a carrying token is rejected here rather
		// than admitted with its restriction silently dropped (which would fail open,
		// widening access past what the issuer intended).
		if capabilitiesPresent && !p.experimentalCapabilities {
			return nil, capability.Terminal(jwtErr(jwtErrCapabilitiesDisabled, fmt.Errorf("mcp.capabilities is present but experimental capability-claim enforcement is disabled; pass --jwt-experimental-capabilities to enable the experimental JWT capability-claim intersection (JWT schema v0.2), or omit the claim to use the token for identity only")))
		}

		var capsList []string
		if capabilitiesPresent {
			capsList = *payload.MCP.Capabilities
		}

		// Reject the token on any malformed entry (fail closed) rather than
		// silently ignoring it.
		for _, claim := range capsList {
			if _, _, _, err := parseV2Claim(claim); err != nil {
				return nil, capability.Terminal(jwtErr(jwtErrInvalidCapabilities, fmt.Errorf("JWT capability claim has invalid format: %w", err)))
			}
		}

		// Parsed HERE, at the token boundary, so a grant this build cannot enforce
		// rejects the TOKEN rather than evaluating later to "covers nothing" — which
		// would turn an IdP template mistake into a permanent, invisible escalation
		// loop with no error to grep for. Unlike mcp.capabilities this is NOT behind
		// the experimental gate: it can only narrow, and it is already gated by the
		// manifest carrying a declassify directive at all.
		declassify, declErr := p.parseDeclassifyApprovals(payload.MCP.Declassify, tokenExpUnix, now)
		if declErr != nil {
			return nil, declErr
		}

		delegation, delegErr := parseDelegationChain(payload)
		if delegErr != nil {
			return nil, delegErr
		}

		// Sub is the primary identity anchor; without it a token cannot be
		// attributed in audit records or matched against principal-scoped
		// constraints.
		if stdClaims.Subject == "" {
			return nil, capability.Terminal(jwtErr(jwtErrMissingClaims, fmt.Errorf("JWT missing required sub claim")))
		}

		// A sender-constrained token (RFC 7800 cnf: DPoP jkt, embedded jwk, or an
		// RFC 8705 mTLS binding) is bound to a proof-of-possession key the proxy
		// cannot verify, so it must not be honored as a plain bearer token — anyone
		// who captured it could replay it. An explicit `"cnf": null` is the one
		// exception: CnfIsSenderConstrained treats it as absent, so it passes
		// through like a token carrying no cnf at all.
		if constrained, malformed := capability.CnfIsSenderConstrained(rawClaims["cnf"]); malformed {
			return nil, capability.Terminal(jwtErr(jwtErrMalformedToken, fmt.Errorf("cnf claim is present but not a JSON object (RFC 7800 requires an object); rejecting (fail closed)")))
		} else if constrained {
			return nil, capability.Terminal(jwtErr(jwtErrSenderConstrained, fmt.Errorf("sender-constrained token (cnf) requires proof-of-possession, which the proxy does not verify; refusing to accept it as a plain bearer token (fail closed)")))
		}

		return newValidatedClaims(capsList, capabilitiesPresent, declassify, delegation, payload, stdClaims, rawClaims), nil
	})
	if err != nil {
		return ctx, err
	}
	// TTL is capped at the token's remaining lifetime inside Put. Consumers must
	// treat the returned claims as read-only: the cache hands the same pointer to
	// concurrent sessions.
	p.tokenCache.Put(cacheKey, validated, tokenExpUnix)
	return WithJWTClaims(ctx, validated), nil
}

// CheckKill consults the kill switch, returning non-nil when the session is killed
// (or the kill store errors, fail closed). The */list handlers call it before
// contacting the upstream so a killed session cannot enumerate the catalog.
func (p *JWTPDP) CheckKill(ctx context.Context, sessionID string) *capability.EnforceResponse {
	return killCheck(ctx, p.clock, p.ks, sessionID)
}

// CheckAudience enforces this route's audience pin at session creation, before any
// upstream is spawned — the shared validator accepts the UNION of every route's
// audience, so this narrows to THIS route so a cross-audience token can't spin up
// this route's upstream via initialize. Decide/filterList/DecideSampling embed the
// same pin for enforced actions; this covers the session-creating initialize, which
// doesn't flow through them. Returns nil when no audience is pinned.
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

// DecideResourceCancel authorizes a resources/unsubscribe without routing through
// Decide, since Decide is the READ decision and a cancel must not be metered by it.
// The token still only RESTRICTS: kill, the audience pin, and (when the token carries
// an exhaustive mcp.capabilities claim) coverage of this resource all apply before the
// inner PDP's match-only decision.
//
// Denials here skip withInnerVerdicts: its interface-pin hardening is tool-only, and
// its redaction obligations don't apply — an unsubscribe result carries no data to
// redact even when downgraded to a forward.
func (p *JWTPDP) DecideResourceCancel(ctx context.Context, sessionID, uri, sourceIP string) capability.EnforceResponse {
	if deny := killCheck(ctx, p.clock, p.ks, sessionID); deny != nil {
		return *deny
	}
	claims, ok := jwtClaimsFromContext(ctx)
	if !ok {
		// An authentication boundary, exactly as in Decide: the token was never validated.
		return hardDenyResponse(p.clock, capability.ErrCodeNoJWTClaims, "no JWT claims in context — token was not validated")
	}
	if !p.routeAudienceSatisfied(claims) {
		return p.audienceDeny(fmt.Sprintf("token audience %v does not satisfy the route's required audience %q", claims.Audiences, p.routeAudience))
	}
	target := EnforceTarget{Type: capability.TargetTypeResource, Name: uri}
	// Mirrors Decide's delegation gate: this method can resolve entirely inside the
	// wrapper (exhaustive claim + nil/wiretap inner), so without it the chain would
	// bound the subscribe but not the cancel.
	if deny := delegationTargetDenial(ctx, p.clock, target, false); deny != nil {
		return *deny
	}
	if claims.HasCapabilities {
		// Matching only (no conditions) — anyCapCovers is the same predicate the
		// list filter uses.
		if !anyCapCovers(parsedCapHeads(claims), target) {
			return denyResponse(p.clock, capability.ErrCodeAuthorizationFailed, "jwtCapability",
				fmt.Sprintf("resource %q is not in the JWT capability claims, so this token holds no subscription to it to cancel", uri))
		}
		// Plain nil check, not innerEnforces(): the token already authorized this URI
		// against its exhaustive allowlist, so a permissive inner can only re-affirm.
		// innerEnforces() here made a wiretap route disagree between its own subscribe
		// (allowed) and unsubscribe (denied) for the same token.
		if p.inner != nil {
			return p.inner.DecideResourceCancel(ctx, sessionID, uri, sourceIP)
		}
		return newAllowResponse(p.clock)
	}
	// No mcp.capabilities claim: the JWT abstains, so only a real backstop
	// (innerEnforces) can authorize — same asymmetry Decide documents.
	if p.innerEnforces() {
		return p.inner.DecideResourceCancel(ctx, sessionID, uri, sourceIP)
	}
	// Identity-only token, no route policy: the token authenticates, not authorizes.
	return denyResponse(p.clock, capability.ErrCodeAuthorizationFailed, "",
		"no capability policy is configured for this route, so no subscription was authorized to cancel")
}

// DecidePromptGet delegates to Decide with a prompt target so JWT claims gate
// prompt gets like tool calls.
func (p *JWTPDP) DecidePromptGet(ctx context.Context, sessionID, promptName, sourceIP string) capability.EnforceResponse {
	return p.Decide(ctx, sessionID, EnforceTarget{Type: capability.TargetTypePrompt, Name: promptName}, nil, sourceIP)
}

// DecideSampling implements SamplingAuthorizer. Per ADR-0001 sampling originates
// from the upstream, not a host call carrying a bearer token, so the JWT layer does
// not intersect capability claims for it — the decision delegates to the inner PDP's
// manifest "system:sampling/createMessage" opt-in. With no inner authorizer, sampling
// stays denied (fail closed).
func (p *JWTPDP) DecideSampling(ctx context.Context, sessionID, sourceIP string) capability.EnforceResponse {
	// Kill runs unconditionally, before the audience pin: previously this was
	// skipped when the inner PDP shared the kill manager (deferring to its own
	// check), but the audience pin runs before that delegation — so a session both
	// killed and cross-audience was denied with the wrong code, hiding the kill
	// from KILL_SWITCH-keyed monitoring.
	if deny := killCheck(ctx, p.clock, p.ks, sessionID); deny != nil {
		return *deny
	}
	// No validated claims at all: hard-deny (an authentication boundary), mirroring
	// Decide/filterList. The transport wiring only reaches here with claims already
	// attached (forwardServerRequest), so this documents the invariant rather than
	// closing a live hole — stating it is what keeps a later wiring change from
	// silently reopening it.
	claims, ok := jwtClaimsFromContext(ctx)
	if !ok {
		return hardDenyResponse(p.clock, capability.ErrCodeNoJWTClaims, "no JWT claims in context — token was not validated")
	}
	// Per-route audience pin, mirroring Decide/filterList: a no-op when
	// routeAudience is unset (single-upstream, or stdio with no JWT).
	if deny := p.CheckAudience(ctx); deny != nil {
		return *deny
	}
	// mcp.capabilities is an EXHAUSTIVE allowlist even when empty, but sampling was
	// the one enforced method that ignored it (delegated straight to the manifest) —
	// and since parseV2Claim refuses system: claims, a token could never LIST
	// sampling, so a deny-all token still got sampling forwarded wherever the
	// manifest opted in. Deny here instead, closing that exhaustive-deny gap.
	if claims.HasCapabilities {
		return denyResponse(p.clock, capability.ErrCodeSamplingDenied, "",
			"the token carries an mcp.capabilities claim, which is an exhaustive allowlist, and sampling cannot be listed in it (system: targets are not expressible as capability claims); server-initiated sampling is therefore denied for this token")
	}
	// innerEnforces (not a nil check) so an AlwaysAllowPDP inner is not a sampling
	// backstop, matching the identity-only Decide path.
	if p.innerEnforces() {
		return p.inner.DecideSampling(ctx, sessionID, sourceIP)
	}
	return denyResponse(p.clock, capability.ErrCodeSamplingDenied, "",
		"server-initiated sampling requires a manifest with an explicit system:sampling/createMessage opt-in")
}

// routeAudienceSatisfied is the per-route narrowing on top of the shared validator,
// which already accepted the token for SOME route's audience (the union): this
// asserts it carries THIS route's, so a multi-audience token issued for both svc-a
// and svc-b is accepted on either route.
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

// audienceDeny carries the producer's BlockOverride override so a route running under --audit does
// NOT downgrade it to a logged forward: audience is an authentication/tenancy boundary (like
// the kill switch), not the per-call policy decision its AUTHORIZATION_FAILED code names.
func (p *JWTPDP) audienceDeny(message string) capability.EnforceResponse {
	resp := denyResponse(p.clock, capability.ErrCodeAuthorizationFailed, "jwtAudience", message)
	resp.Denial.BlockOverride = true
	return resp
}

// withInnerVerdicts composes the inner PDP's own verdicts onto one of JWTPDP's own
// denies produced by short-circuiting above the inner PDP.
//
// JWTPDP short-circuits on three DOWNGRADABLE paths (unlisted target, a JWT
// condition failure, no-capabilities-with-no-backstop), so the inner PDP never
// contributes the redaction obligations a --audit route needs on downgrade, the
// interface-pin break, or the effect ceiling — each omission made the composed
// refusal WEAKER than the same request without the JWT, inverting "a JWT may only
// restrict".
//
// Goes through the PolicyDecisionPoint contract (HardenRefusal), not a type
// assertion to *ManifestPDP, so a third-party inner PDP's own pin/ceiling composes
// correctly instead of silently doing nothing.
func (p *JWTPDP) withInnerVerdicts(ctx context.Context, sessionID string, r capability.EnforceResponse, target EnforceTarget, args map[string]interface{}) capability.EnforceResponse {
	if p.inner == nil || r.Decision == capability.DecisionAllow || len(r.Obligations) > 0 {
		return r
	}
	if r.Denial != nil && !r.Denial.Downgradable() {
		// Never downgraded to a forward, so nothing to redact or harden.
		return r
	}
	return p.inner.HardenRefusal(ctx, sessionID, r, target, args)
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
	// Unconditional (not skipped when the inner shares the kill manager, as
	// DecideSampling can be): Decide has early-return paths that never reach
	// decideInner (unlisted target, failing JWT conditions), so deferring to the
	// inner would leave the kill unconsulted there.
	if deny := killCheck(ctx, p.clock, p.ks, sessionID); deny != nil {
		return *deny
	}

	claims, ok := jwtClaimsFromContext(ctx)
	if !ok {
		// An authentication boundary, stronger than the cross-audience deny below,
		// so it must not be downgraded to a logged forward under --audit.
		return hardDenyResponse(p.clock, capability.ErrCodeNoJWTClaims, "no JWT claims in context — token was not validated")
	}

	// Per-route audience pin: the shared validator accepted this token for SOME
	// route's audience (the union); narrow to THIS route's before the
	// capability/manifest logic runs at all.
	if !p.routeAudienceSatisfied(claims) {
		return p.audienceDeny(fmt.Sprintf("token audience %v does not satisfy the route's required audience %q", claims.Audiences, p.routeAudience))
	}

	// Applied HERE rather than left to the inner PDP: a JWT-only route has no
	// manifest engine, and a policyless route's inner is the wiretap
	// AlwaysAllowPDP, so on those routes the chain was validated at the token
	// boundary and then applied to nothing — a delegate whose grant reaches no
	// target was still allowed.
	//
	// Composed through withInnerVerdicts because the refusal is downgradable by
	// design: on an --audit route it becomes a forward, and without composing it
	// would carry none of the redaction/pin/ceiling the inner PDP would have added.
	if deny := delegationTargetDenial(ctx, p.clock, target, false); deny != nil {
		return p.withInnerVerdicts(ctx, sessionID, *deny, target, args)
	}

	// No mcp.capabilities field: identity-only, deferring to the inner manifest
	// PDP — safe only with a real backstop (innerEnforces), since an
	// AlwaysAllowPDP/nil inner would grant every target to an identity-only token.
	if !claims.HasCapabilities {
		if p.innerEnforces() {
			return p.decideInner(ctx, sessionID, target, args, sourceIP)
		}
		return p.withInnerVerdicts(ctx, sessionID, denyResponse(p.clock, capability.ErrCodeAuthorizationFailed, "jwtCapability",
			"token carries no mcp.capabilities claim and the route has no manifest policy to fall back on; "+
				"JWT mode denies by default — issue a token with capability claims or add a manifest policy to the route"), target, args)
	}

	// Exhaustive allowlist: an unlisted target is denied regardless of the
	// manifest. Use the heads parsed at validation time when available.
	constraints := buildConstraintsFromParsed(parsedCapHeads(claims), target)
	if len(constraints) == 0 {
		// A claim that NAMES this target but whose condition suffix failed to parse
		// also lands here (it grants nothing) — distinguish it so the operator isn't
		// sent looking for a claim that's right in front of them.
		msg := fmt.Sprintf("%s %q is not in the JWT capability claims", target.Type, target.Name)
		if claimNamesTargetButFailedToParse(claims, target) {
			msg = fmt.Sprintf("a JWT capability claim names %s %q, but its condition suffix could not be parsed, so it grants nothing (see the eunox log for the parse error)", target.Type, target.Name)
		}
		return p.withInnerVerdicts(ctx, sessionID, denyResponse(p.clock, capability.ErrCodeAuthorizationFailed, "jwtCapability", msg), target, args)
	}

	// OR-list: permitted if ANY matching entry's conditions pass. Evaluate every
	// matching entry rather than stopping at the first, avoiding an order-dependent
	// deny (e.g. separate op=SELECT / op=INSERT grants for one tool).
	condArgs := jwtConditionArgs(target, args)
	// Hoisted beside condArgs since both are loop-invariant: flatMap falls back to
	// rebuilding the flat claim map for a test-built JWTClaims, which inside the
	// loop would allocate once per candidate grant instead of once total.
	condReq := jwtClaimEnforceRequest(sessionID, target, condArgs, claims.flatMap())
	var lastDeny *capability.EnforceResponse
	for i := range constraints {
		matched := constraints[i]
		if len(matched.Conditions) == 0 {
			lastDeny = nil
			break
		}
		if resp := evaluateJWTConditions(ctx, p.clock, p.inner, matched.Conditions, condReq); resp != nil {
			// A FAULT survives a later grant's policy verdict. Both refuse, so the call is
			// denied either way — but only a policy verdict is downgradable, so overwriting
			// "this grant's condition could never be evaluated" with "that grant's condition
			// says no" hands an observing route a forward for a restriction nothing checked,
			// decided by the order the grants happen to sit in the claim.
			if lastDeny == nil || lastDeny.Denial == nil || lastDeny.Denial.Downgradable() {
				lastDeny = resp
			}
			continue
		}
		// This entry's conditions all passed.
		lastDeny = nil
		break
	}
	if lastDeny != nil {
		return p.withInnerVerdicts(ctx, sessionID, *lastDeny, target, args)
	}

	// Plain p.inner != nil, deliberately weaker than the no-capabilities branch's
	// innerEnforces(): here the JWT already authorized this target against its
	// exhaustive allowlist, so a permissive inner can only re-affirm the allow — it
	// cannot fail open the way it could when the JWT abstains entirely.
	if p.inner != nil {
		return p.decideInner(ctx, sessionID, target, args, sourceIP)
	}

	return newAllowResponse(p.clock)
}

// now returns the injected clock's instant via the shared clockNow, so the JWT and
// AlwaysAllowPDP paths honor a frozen test clock identically.
func (p *JWTPDP) now() time.Time {
	return clockNow(p.clock)
}

// decideInner dispatches by target type so resources/read and prompts/get reach the
// inner methods that synthesize the {"uri"}/{"name"} argument maps — routing every
// type through inner.Decide would deny a resource/prompt with MISSING_CONTEXT.
func (p *JWTPDP) decideInner(ctx context.Context, sessionID string, target EnforceTarget, args map[string]interface{}, sourceIP string) capability.EnforceResponse {
	switch target.Type {
	case capability.TargetTypeResource:
		return p.inner.DecideResourceRead(ctx, sessionID, target.Name, sourceIP)
	case capability.TargetTypePrompt:
		return p.inner.DecidePromptGet(ctx, sessionID, target.Name, sourceIP)
	case capability.TargetTypeTool:
		// system targets do NOT come through here: sampling is decided via the
		// separate DecideSampling path, so a system target falls to the deny below.
		return p.inner.Decide(ctx, sessionID, target, args, sourceIP)
	default:
		// Fail closed on any unhandled type: falling through to inner.Decide would
		// re-introduce the empty-arg MISSING_CONTEXT regression for a type needing
		// name-to-arg synthesis. system lands here on purpose.
		return hardDenyResponse(p.clock, capability.ErrCodeEnforcementError,
			fmt.Sprintf("decideInner: unhandled target type %q — update decideInner", target.Type))
	}
}

// claimConditionEvaluator is the narrow view evaluateJWTConditions needs of the
// deciding PDP, named separately so the evaluator can be nil (a JWT-only route)
// without the caller holding a full PolicyDecisionPoint implementation.
type claimConditionEvaluator interface {
	EvaluateClaimCondition(ctx context.Context, cond capability.Condition, req *capability.EnforceRequest) (*enforcement.ConditionError, bool)
	ConditionHandlerOverridden(condType string) bool
}

// claimConditionVerdict asks the deciding PDP, or the built-ins when there is none.
// nil means a route with no wrapped PDP at all (so nothing could be overridden) —
// it must never stand in for "the PDP is there but did not answer" (ok=false).
func claimConditionVerdict(eval claimConditionEvaluator, ctx context.Context, cond capability.Condition, req *capability.EnforceRequest) (*enforcement.ConditionError, bool) {
	if eval == nil {
		return enforcement.NonCommittingConditionVerdict(ctx, cond, req)
	}
	return eval.EvaluateClaimCondition(ctx, cond, req)
}

// claimConditionOverridden asks the deciding PDP whether an embedder replaced
// condType's semantics — for the one claim-side arm (allowedOperations) that can't
// dispatch through the replacement. nil means no wrapped PDP, so nothing overridden.
func claimConditionOverridden(eval claimConditionEvaluator, condType string) bool {
	return eval != nil && eval.ConditionHandlerOverridden(condType)
}

// EvaluateClaimCondition delegates to the PDP this one wraps, so a stack of wrappers
// resolves to whatever is actually deciding. No inner PDP means no engine, so the
// built-ins are the route's semantics.
func (p *JWTPDP) EvaluateClaimCondition(ctx context.Context, cond capability.Condition, req *capability.EnforceRequest) (*enforcement.ConditionError, bool) {
	return claimConditionVerdict(p.inner, ctx, cond, req)
}

// ConditionHandlerOverridden delegates to the PDP this one wraps, for the same
// reason EvaluateClaimCondition does.
func (p *JWTPDP) ConditionHandlerOverridden(condType string) bool {
	return claimConditionOverridden(p.inner, condType)
}

// jwtClaimEnforceRequest builds the EnforceRequest a capability claim's conditions
// evaluate against. SessionID/TargetName/Target/Arguments/Claims are populated, since
// they are the call's identity and already in scope; Context, Directives,
// DeclaredLabels, DeclassifyApprovals, and Delegation stay zero deliberately — each
// is authoritative on a different path (manifest, matched constraint, flow layer,
// declassify seam, delegation gate) that runs one frame later with the real value,
// so populating a partial view here would let a claim condition see a second,
// stale one. A test fails when a field is added to EnforceRequest, so the next
// addition is a deliberate choice, not a silent omission.
func jwtClaimEnforceRequest(sessionID string, target EnforceTarget, args, claims map[string]interface{}) *capability.EnforceRequest {
	return &capability.EnforceRequest{
		SessionID:  sessionID,
		TargetName: target.Name,
		Arguments:  args,
		Target: &capability.EnforceRequestTarget{
			Type: string(target.Type),
			Name: target.Name,
		},
		Claims: claims,
	}
}

// jwtConditionArgs returns the argument map JWT shorthand conditions evaluate
// against. resources/read and prompts/get carry no real args, so the target name is
// synthesized under "uri"/"name" to match the inner manifest's synthesis — keep
// these keys in lockstep with DecideResourceRead/DecidePromptGet.
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
	// A resource URI's own query string stays attached to the name (see splitV2Claim).
	namepart, condpart, hadSep := splitV2Claim(claim)

	// A '?' with no pairs after it ("tool:read_file?") is malformed; reject rather
	// than treat it as an unconditioned (maximally permissive) grant.
	if hadSep && condpart == "" {
		return "", "", nil, fmt.Errorf("JWT capability claim %q: trailing '?' with no condition pairs", claim)
	}

	p, bare, parseErr := capability.ParseTarget(namepart)
	if parseErr != nil {
		return "", "", nil, fmt.Errorf("JWT capability claim %q: %w", claim, parseErr)
	}

	// A system: claim validates through ParseTarget but is consulted by nothing —
	// Decide never sees a system target (sampling is decided by the inner manifest
	// per ADR-0001) — so admitting one would be an inert grant. Reject it so the
	// token surfaces the misconfiguration up front.
	if p == capability.TargetTypeSystem {
		return "", "", nil, fmt.Errorf("JWT capability claim %q: the system: namespace is not grantable from a JWT capability claim; system capabilities such as sampling are authorized by the manifest's system:sampling/createMessage opt-in, not a token claim", claim)
	}

	// Mirrors the manifest loader's glob validation so a malformed pattern (e.g.
	// "tool:read_[*") is rejected here rather than reaching enforce time, where
	// path.Match would swallow ErrBadPattern into a silent, opaque deny-all.
	// claimGlobParts owns the glob/literal split, shared with matchClaimBare so
	// validation and enforcement stay in lockstep.
	globPart, _, _ := claimGlobParts(p, bare)
	if err := enforcement.ValidateResourcePattern(globPart); err != nil {
		return "", "", nil, fmt.Errorf("JWT capability claim %q: invalid target pattern: %w", claim, err)
	}

	if condpart != "" {
		conds, parseErr = parseCondSuffix(condpart)
		if parseErr != nil {
			return "", "", nil, fmt.Errorf("JWT capability claim %q: %w", claim, parseErr)
		}
		// Every non-"op" pair becomes an AllowedValues glob at runtime; validate it
		// here (as the manifest path does) so a malformed pattern is rejected up
		// front instead of silently matching nothing (VALUE_NOT_PERMITTED).
		for _, cp := range conds {
			if cp.key == "op" {
				// "op=" has no explicit argument name, so it runs in scan-all-args
				// mode, which only supports SQL verbs. Reject a non-SQL verb here so
				// the misconfiguration surfaces at validation, not as an opaque
				// CONDITION_FAILED on every subsequent call.
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

// splitV2Claim splits a v0.2 claim at the first '?', except for an http(s) resource
// claim, where '?' begins the URL's own query rather than a condition list — such a
// claim cannot also carry conditions. hadSep distinguishes an unconditioned claim
// from a malformed trailing-'?' one ("tool:read_file?", hadSep=true, condpart="").
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
	return isHTTPResourceValue(head[len(ns):])
}

// isHTTPResourceValue reports whether a bare resource value (the part after the
// "resource:" prefix) is an http(s) URL. URI schemes are case-insensitive
// (RFC 3986 §3.1), so detection is on a lowercased copy.
func isHTTPResourceValue(bareName string) bool {
	v := strings.ToLower(bareName)
	return strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://")
}

// claimGlobParts is the single source of the glob/literal split parseV2Claim
// validates and matchClaimBare enforces (so the two cannot drift): an http(s)
// resource's query is compared literally, so there the glob is only the path
// before '?'; every other claim globs its whole bare name.
func claimGlobParts(prefix capability.TargetType, bareName string) (globPart, query string, hasQuery bool) {
	if prefix == capability.TargetTypeResource && isHTTPResourceValue(bareName) {
		if pPath, pQuery, pHasQuery := strings.Cut(bareName, "?"); pHasQuery {
			return pPath, pQuery, true
		}
	}
	return bareName, "", false
}

// matchClaimBare matches a JWT capability claim's bare name against a target name.
//
// A query-bearing http(s) resource claim would otherwise have its '?' misread by
// matchBare's path.Match as a single-char wildcard (".../search?q=widget" matching
// ".../searchXq=widget"), so it is split: the path keeps glob semantics, the query is
// compared literally. A query-less claim matches as one whole string, identical to the
// manifest's matchesResource — so an exact claim (".../export") does not also grant an
// arbitrary target query (".../export?scope=all"), while a path-glob claim still
// absorbs one, matching the manifest's glob behavior.
func matchClaimBare(prefix capability.TargetType, bareName, targetName string) bool {
	globPart, claimQuery, hasQuery := claimGlobParts(prefix, bareName)
	if hasQuery {
		tPath, tQuery, tHasQuery := strings.Cut(targetName, "?")
		// A query-bearing claim pins its query via an EXACT, order-sensitive byte
		// comparison — not a normalized one. "?a=1&b=2" does not match "?b=2&a=1" even
		// though the two are semantically identical query strings; this is a documented
		// pin (docs/capability-manifest-guide.md § 3), not an oversight, so a caller
		// whose client reorders or re-encodes query parameters gets an opaque
		// AUTHORIZATION_FAILED rather than a silently normalized match.
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

// jwtShorthandValues types one v0.2 shorthand condition value: the grammar carries
// every value as a STRING, but MatchAllowedValue treats a string allowed-value as a
// glob that cannot match a non-string argument, so a string-only value would
// silently deny every numeric/boolean call. When raw parses as a whole JSON
// number/boolean/null, only the typed scalar is returned (not the raw string too),
// with a number kept as json.Number so a large integer compares exactly rather than
// rounding through float64. Everything else keeps the raw string, preserving globs.
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

// parseCapHeads runs the cheap phase of claim parsing (split + namespace/bare-name
// only), dropping malformed entries so they grant nothing. The expensive
// parseCondSuffix stays lazy in buildConstraintsFromParsed. A drop here "should not
// occur" — ValidateToken already validated every claim — so it means the validator
// and this parser have diverged; logged via jwtLogger so it's greppable rather than
// surfacing only as an unexplained AUTHORIZATION_FAILED downstream.
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

// claimNamesTargetButFailedToParse reports whether some claim MATCHES target but
// contributed no constraint because its condition suffix would not parse — so the
// deny message can distinguish "not in your token" from "malformed in your token",
// two different operator actions behind one identical denial.
func claimNamesTargetButFailedToParse(claims *JWTClaims, target EnforceTarget) bool {
	for _, h := range parsedCapHeads(claims) {
		if h.prefix != target.Type || !matchClaimBare(h.prefix, h.bareName, target.Name) {
			continue
		}
		if h.condpart == "" {
			continue
		}
		if _, err := parseCondSuffix(h.condpart); err != nil {
			return true
		}
	}
	return false
}

// buildConstraintsFromParsed is the matching/condition phase of claim evaluation; the
// expensive parseCondSuffix runs only for claims that actually match target.
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
				// A malformed suffix on a matching claim grants nothing (fail closed);
				// same validator/parser divergence parseCapHeads logs for the head phase.
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

// parsedCapHeads returns the heads parsed once at token validation, falling back to
// parsing here for a JWTClaims built directly (tests, callers bypassing
// ValidateToken). Four call sites need the same fallback, so it is written once.
func parsedCapHeads(claims *JWTClaims) []capHead {
	if claims.parsedCaps != nil {
		return claims.parsedCaps
	}
	return parseCapHeads(claims.Capabilities)
}

// anyCapCovers reports whether any pre-parsed head covers target, ignoring
// conditions — the right predicate for DecideResourceCancel's match-only decision
// and for list filtering, since a list/cancel response carries no arguments to
// evaluate conditions against.
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
// No claims, or no route-audience match: fail closed to an empty listing without
// consulting the inner PDP. No mcp.capabilities: delegate to the inner PDP if it's a
// real backstop, else empty.
//
// mcp.capabilities present: run the inner PDP ONCE — it prunes the list and exposes
// pre-parsed survivors (Entries) — then apply the JWT claim filter to those in memory
// and splice back into the inner's already-ordered envelope, so the response is
// parsed once instead of twice. Intersection is commutative, so this yields the same
// result as filtering in the other order.
func (p *JWTPDP) filterList(ctx context.Context, result json.RawMessage, desc listTypeDesc) ListFilterResult {
	claims, ok := jwtClaimsFromContext(ctx)
	if !ok {
		return p.emptyListingArmingPins(ctx, result, desc)
	}
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
	// Reuse the heads parsed once at validation, mirroring Decide, so list
	// filtering never re-parses on the hot path.
	parsed := parsedCapHeads(claims)
	// The delegation chain narrows the catalog here too, mirroring the ManifestPDP
	// filters — on a JWT-only/wiretap route the inner filter is a passthrough, so
	// without this the listing would advertise more than the chain lets the
	// delegate actually call.
	chain := claims.Delegation
	kept := make([]json.RawMessage, 0, len(innerRes.Entries))
	for i, raw := range innerRes.Entries {
		var covered bool
		var id string
		if i < len(innerRes.entryIDs) && innerRes.entryIDs[i] != "" {
			// ID already decoded by the inner PDP's keep func — skip re-unmarshal.
			// An empty ID means the inner decoded none, so fall back below.
			id = innerRes.entryIDs[i]
			covered = anyCapCoversName(id, desc.targetType, parsed)
		} else {
			id, covered = entryCoveredByClaims(raw, parsed, desc.idField, desc.targetType)
		}
		if covered && !chain.IsEmpty() {
			// An entry whose id couldn't be decoded can't be scoped against the
			// chain, so drop rather than admit it (fail closed).
			if id == "" {
				covered = false
			} else if permitted, _ := chain.PermitsTarget(string(desc.targetType) + ":" + id); !permitted {
				covered = false
			}
		}
		if covered {
			kept = append(kept, raw)
		}
	}
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
		// A passthrough inner (nil/AlwaysAllow) forwards the upstream bytes
		// verbatim, so a malformed upstream body can land here. Fail closed rather
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

// HardenRefusal delegates to the inner PDP: JWTPDP holds no pin, ceiling, or
// directives of its own. A JWT-only route returns the refusal unchanged.
func (p *JWTPDP) HardenRefusal(ctx context.Context, sessionID string, r capability.EnforceResponse, target EnforceTarget, args map[string]interface{}) capability.EnforceResponse {
	if p.inner == nil {
		return r
	}
	return p.inner.HardenRefusal(ctx, sessionID, r, target, args)
}

// RecordObservedToolHashes delegates to the inner PDP, which holds any
// description-hash pins. A nil inner records nothing but still reports an accurate
// count via countListEntries rather than passThroughList, whose envelope nothing
// here reads.
func (p *JWTPDP) RecordObservedToolHashes(ctx context.Context, result json.RawMessage) int {
	if p.inner != nil {
		return p.inner.RecordObservedToolHashes(ctx, result)
	}
	return countListEntries(result, listKeyTools)
}

// ReleaseSession delegates to the inner PDP so a wrapped ManifestPDP releases
// per-session flow-label state on teardown; a nil inner is a no-op.
func (p *JWTPDP) ReleaseSession(ctx context.Context, sessionID string) {
	if p.inner != nil {
		p.inner.ReleaseSession(ctx, sessionID)
	}
}

// CommitDeclassified delegates to the inner PDP, which owns the flow store the clear
// applies to — a token can only restrict, so the JWT layer clears no label of its
// own. p == nil guards the typed-nil case, since this runs through the transport's
// committer interface after the upstream call, where a panic is a crash with the
// response already in hand.
func (p *JWTPDP) CommitDeclassified(ctx context.Context, sessionID string, decl *capability.Declassification) ([]string, error) {
	if p == nil || p.inner == nil {
		return nil, noFlowStateErr(decl, "JWT decision point with no inner policy")
	}
	return p.inner.CommitDeclassified(ctx, sessionID, decl)
}

// innerFilter intersects the inner PDP's list filter with the JWT claim filter. A
// nil inner passes the result through (still counting entries via fieldName).
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
// rather than the catalog (no JWT claims, or wrong route audience), but still arms
// the descriptionHash pin from the genuine upstream bytes — otherwise a rejected
// caller's tools/list would leave a poisoned catalog unobserved by anyone. Uses
// RecordObservedToolHashes rather than running the (discarded) inner filter, which
// would cost a rejected caller MORE than an authorized one on this fail-closed path.
// Tools only, since pins exist for tools alone.
func (p *JWTPDP) emptyListingArmingPins(ctx context.Context, result json.RawMessage, desc listTypeDesc) ListFilterResult {
	if desc.key == listKeyTools && p.innerEnforces() {
		_ = p.inner.RecordObservedToolHashes(ctx, result)
	}
	return emptyListing(result, desc.key)
}

// emptyListing empties every entry of one list kind while still reporting the
// upstream (pre-filter) count. filterList's no-claims, no-audience-match, and
// no-capabilities branches all fail closed to this rather than a claim-based filter.
func emptyListing(resultBytes json.RawMessage, listKey string) ListFilterResult {
	return filterListResult(resultBytes, listKey, func(json.RawMessage) (bool, string) {
		return false, ""
	})
}

// entryCoveredByClaims reports one list entry's identifier (idField: "name" or
// "uri") and whether it is covered by a claim of targetType. Conditions are not
// evaluated (list entries carry no arguments), and it fails closed on a decode
// error or on an ambiguous entry (entryKeysAmbiguous — a duplicate/case-variant key
// like "name"/"Name" that Go and a case-sensitive host could decode differently).
// Returns id alongside the verdict since the caller also needs it to scope against a
// delegation chain, sparing a second unmarshal of the same bytes per entry.
func entryCoveredByClaims(raw json.RawMessage, parsed []capHead, idField string, targetType capability.TargetType) (id string, covered bool) {
	if entryKeysAmbiguous(raw) {
		return "", false
	}
	var entry struct {
		Name string `json:"name"`
		URI  string `json:"uri"`
	}
	if err := json.Unmarshal(raw, &entry); err != nil {
		return "", false
	}
	id = entry.Name
	if idField == "uri" {
		id = entry.URI
	}
	return id, anyCapCovers(parsed, EnforceTarget{Type: targetType, Name: id})
}

// sqlVerbs is the set the op= scan-all-args evaluator recognizes. A token granting
// op=<X> permits a call only if some argument begins with X; any argument whose
// first word is a DIFFERENT verb in this set is a hard denial, stopping a dangerous
// statement (COPY ... TO PROGRAM) riding along behind a benign SELECT.
//
// Best-effort first-word matching only — it does NOT parse SQL, so stacked or
// CTE-wrapped mutations escape it; pair with a least-privilege database role.
//
// Deliberately includes non-DML session/admin verbs (SET, RESET, USE, KILL,
// HANDLER): since scan-all-args checks every string argument's first word, a
// legitimate "SET search_path TO public" elsewhere in the call is denied unless SET
// is the granted op. An operator needing that should use the manifest form (Pattern
// C) naming the operation argument instead, scoping the check to just that argument.
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

// collectArgStrings appends every string scalar reachable from v, including those
// nested in objects/arrays, so a SQL verb hidden in a nested value is caught. Maps
// are visited in sorted-key order (slices in index order) so the result is
// deterministic despite Go's randomized map iteration. Returns false (fail closed)
// if nesting exceeds maxArgStringDepth.
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

// evaluateJWTConditions checks JWT-derived conditions against the call req
// describes, returning a non-nil denial if any fails.
//
// req.Claims carries the caller's flat input.claims (the same map the manifest path
// threads into the engine) so a `${task.*}` reference in a capability claim resolves
// here exactly as it does there — without it, such a grant matched nothing and
// denied every call under it. See jwtClaimEnforceRequest for the rest.
//
// eval is a parameter rather than assumed, because enforcement.WithConditionHandler
// can replace a condition TYPE's meaning for an embedder's engine: calling the
// built-in directly here would enforce the override on the manifest path and the
// shipped predicate here, for the same condition on the same call. nil means a
// JWT-only route with no engine, where the built-ins ARE the semantics.
//
// # Which denial CODE each refusal mints
//
// One rule, because the code is the sole encoding of the refusal's class and an observing
// route may downgrade only a policy verdict: a refusal here is CONDITION_FAILED-family only
// when the condition was actually EVALUATED and the call failed it (OPERATION_NOT_PERMITTED
// for a scanned verb outside the set, MISSING_CONTEXT for a scan that found no operation, and
// whatever denyFromCondition carries up from the shared evaluator). Every arm that refuses
// WITHOUT completing the check mints ENFORCEMENT_ERROR — no request to check against, a
// handler that cannot be run ahead of the decision, a grant shape this build cannot enforce,
// a condition type with no evaluator, or an argument tree too deep to scan. Those leave the
// restriction guarding the call unchecked, so there is no verdict for --audit to stand in for.
func evaluateJWTConditions(ctx context.Context, clock enforcement.Clock, eval claimConditionEvaluator, conditions []capability.Condition, req *capability.EnforceRequest) *capability.EnforceResponse {
	if req == nil {
		// Unreachable from Decide (which always builds one), but a nil request must
		// DENY rather than read as a grant whose conditions all passed.
		resp := denyResponse(clock, capability.ErrCodeEnforcementError, "",
			"JWT capability-claim conditions were evaluated with no request to check against; deny (fail closed)")
		return &resp
	}
	name, args := req.TargetName, req.Arguments
	for _, cond := range conditions {
		switch c := cond.(type) {
		case capability.AllowedOperationsCondition:
			// The one arm that cannot dispatch through the deciding PDP's own handler:
			// the claim grammar cannot name the operation argument, so this always
			// scans every argument, while the engine's handler hard-denies exactly
			// that empty-argument form. Sound only while both sides are this build's
			// shipped semantics — an embedder who redefines allowedOperations would
			// otherwise get silently divergent verdicts on the manifest vs. claim
			// path. Startup refuses that wiring outright (WrapRoutesWithJWT); this is
			// the backstop for a JWTPDP built directly.
			if claimConditionOverridden(eval, capability.ConditionTypeAllowedOperations) {
				resp := denyResponseWithDetails(clock, capability.ErrCodeEnforcementError, capability.ConditionTypeAllowedOperations,
					fmt.Sprintf("%q: the deciding policy redefines %s, and this capability claim's argument-less op= form cannot be judged by that handler; deny (fail closed) — grant the operation through a manifest constraint that names the operation argument instead",
						name, capability.ConditionTypeAllowedOperations),
					map[string]interface{}{"conditionType": capability.ConditionTypeAllowedOperations, "reason": "handler_override_unsupported"})
				return &resp
			}
			if c.Argument != "" {
				// Fail-closed guard, not dead code: buildV2Constraint always emits
				// Argument: "" for an op= pair, so a validated claim never reaches
				// here — only a programmatically built constraint could. Kept rather
				// than falling to scan-all-args below, since a named argument means
				// "match THIS one" and scanning all would silently match an
				// alternative (the "never silently match alternatives" invariant).
				resp := denyResponseWithDetails(clock, capability.ErrCodeEnforcementError, capability.ConditionTypeAllowedOperations,
					fmt.Sprintf("%q: allowedOperations with a named argument is not supported from a capability claim", name),
					map[string]interface{}{"argument": c.Argument, "allowedOperations": c.Operations})
				return &resp
			}
			// Sound only for SQL ops, where the isSQLVerb hard-deny below catches a
			// disallowed statement smuggled into any argument; a non-SQL op has no
			// "disallowed verbs" set to check against, so fail closed instead.
			for _, op := range c.Operations {
				if !isSQLVerb(op) {
					resp := denyResponseWithDetails(clock, capability.ErrCodeEnforcementError, capability.ConditionTypeAllowedOperations,
						fmt.Sprintf("%q: non-SQL operation %q cannot be safely enforced without an explicit argument naming the operation parameter; use the manifest form that names the argument", name, op),
						map[string]interface{}{"operation": op, "allowedOperations": c.Operations})
					return &resp
				}
			}
			// Scan ALL arguments (not just until the first match) and deny if any
			// argument's first word is a SQL verb outside the allowed set — closes
			// the multi-argument bypass (op=SELECT granted, but
			// {"sql":"DROP TABLE x","note":"SELECT 1"}).
			var matchedOp string
			// collectArgStrings walks nested objects/arrays too, so a verb smuggled
			// into e.g. {"query":{"sql":"DROP TABLE x"}} isn't skipped; sorted-key
			// order keeps the result deterministic despite map iteration order.
			var argStrings []string
			if !collectArgStrings(args, &argStrings) {
				resp := denyResponseWithDetails(clock, capability.ErrCodeEnforcementError, capability.ConditionTypeAllowedOperations,
					fmt.Sprintf("%q: arguments nested too deeply to scan for operations", name),
					map[string]interface{}{"maxDepth": maxArgStringDepth, "allowedOperations": c.Operations})
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
				if isSQLVerb(word) {
					// Same detail shape as the engine's handleAllowedOperations for
					// this code, so a SIEM rule keyed on the manifest path's denial
					// also catches a token-scoped caller.
					resp := denyResponseWithDetails(clock, capability.ErrCodeOperationNotPermitted, capability.ConditionTypeAllowedOperations,
						fmt.Sprintf("%q: operation %q is not in the permitted set %v", name, word, c.Operations),
						map[string]interface{}{"operation": word, "allowedOperations": c.Operations})
					return &resp
				}
			}
			if matchedOp == "" {
				// No "argument" key, unlike the engine's MISSING_CONTEXT for this
				// condition: the claim grammar can't name one, which is why every
				// argument is scanned — naming a phantom field would mislead.
				resp := denyResponseWithDetails(clock, capability.ErrCodeMissingContext, capability.ConditionTypeAllowedOperations,
					fmt.Sprintf("%q: no matching operation found in arguments", name),
					map[string]interface{}{"allowedOperations": c.Operations})
				return &resp
			}
		case capability.AllowedValuesCondition:
			// Calls the engine's own predicate rather than a copy: a prior
			// hand-written copy drifted twice (missing the empty-argument guard,
			// and denying every call under a "${task.*}" grant before
			// MatchAllowedValue absorbed task-variable resolution).
			//
			// Commits nothing — it runs BEFORE the inner PDP's own decision, so an
			// evaluator that consumed a quota or wrote a flow label would
			// double-count against the manifest path that follows.
			//
			// Reached through the DECIDING PDP, not called directly, so an embedder's
			// WithConditionHandler override for allowedValues applies here too
			// instead of silently only on the manifest path. The seam refuses
			// (ok=false) a type it cannot evaluate without committing.
			cerr, ok := claimConditionVerdict(eval, ctx, c, req)
			if !ok {
				// ENFORCEMENT_ERROR, not CONDITION_FAILED: the condition guarding this call was
				// never evaluated once — the handler commits state, or is not registered at all —
				// so there is no policy verdict for an observing route to downgrade to a forward.
				// The class is read off the CODE (capability.ClassifyDenialCode), so minting the
				// policy code here made --audit forward a call whose claim condition nothing
				// checked, and report it as "would be allowed" when enforce mode denies it.
				resp := denyResponseWithDetails(clock, capability.ErrCodeEnforcementError, c.ConditionType(),
					fmt.Sprintf("%q: the deciding policy's %s handler cannot be evaluated ahead of its own decision (it commits state, or is not registered); deny (fail closed)", name, c.ConditionType()),
					map[string]interface{}{"conditionType": c.ConditionType()})
				return &resp
			}
			if cerr != nil {
				resp := denyFromCondition(clock, name, cerr)
				return &resp
			}
		default:
			// Fail closed on any condition type without an evaluator. buildV2Constraint
			// emits only AllowedOperations/AllowedValues today, so this is unreachable —
			// but a new type added there without a case here must deny, not be skipped.
			//
			// ENFORCEMENT_ERROR for the same reason as the arm above, and matching the engine's
			// own unmodelled-condition-type refusal: an unevaluated restriction is a fault, and a
			// fault is the one class an observing route may not downgrade to a forward.
			resp := denyResponseWithDetails(clock, capability.ErrCodeEnforcementError, cond.ConditionType(),
				fmt.Sprintf("%q: JWT condition type %q has no evaluator; deny (fail closed)", name, cond.ConditionType()),
				map[string]interface{}{"conditionType": cond.ConditionType()})
			return &resp
		}
	}
	return nil
}
