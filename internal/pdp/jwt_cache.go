// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"time"

	"github.com/eunolabs/eunox/pkg/capability"
)

// Verified-token cache bounds. TTL matches the Redis kill-switch propagation window
// (30s), so a revoked token isn't trusted from cache materially longer than a kill takes
// to propagate.
//
// FIXED, not operator-configurable like the JWKS cache's CacheTTL — this window only
// extends trust in an already-verified token, and the kill switch/audience/policy are
// still re-checked on every call regardless of a cache hit. See the CacheTTL doc in jwt.go.
const (
	jwtTokenCacheTTL     = 30 * time.Second
	jwtTokenCacheMaxSize = 4096
)

// Refusal-cache bounds. Its own TTL rather than an alias of the verified-token cache's: that
// one is pinned to the kill-switch propagation window because it extends TRUST, and tightening
// it for revocation reasons must not silently shorten (or, below a second, silently disable)
// a window that governs something else entirely.
//
// What this one bounds is the KEY SET. Replaying the verdict is correct for any elapsed time —
// memoizableRefusal admits nothing else — and an entry that carries the token's own exp is
// already capped at it, so expiry is not the window either. But a key withdrawn from the JWKS
// makes bytes that verified stop verifying, and a refusal memoized before that keeps naming
// the payload fault where a fresh validation would now say invalid_signature. The verdict is a
// deny throughout; what lags is the category a SIEM keys detection on, so the bound is set
// where an operator responding to a key compromise would want it rather than at whatever the
// memoization would save.
//
// The SIZE matches the verified-token cache deliberately. What stops a stream of distinct
// refusals evicting every legitimate positive entry is that this is a separate INSTANCE, not
// that it is smaller — and the scenario the memoization exists for (an IdP claim template
// mis-spelling one member, so every token it mints is refused) has exactly the token
// cardinality the positive cache is already sized for. A quarter of that size moved the
// eviction cliff to a quarter of the fleet, and past it the cache is worse than none: every
// request misses AND pays PayloadCache.Put's at-capacity sweep. The cliff is inherent to a
// fixed bound; what matters is that both halves fall off it at the same population.
const (
	jwtRefusalCacheTTL     = 30 * time.Second
	jwtRefusalCacheMaxSize = jwtTokenCacheMaxSize
)

// memoizableJWTRefusals declares, for EVERY ValidateToken failure category, whether a refusal
// carrying it may be replayed from the refusal cache. A category with no row is not
// memoizable (fail closed), and TestJWTRefusalMemoization_EveryCategoryDeclaresOne derives the
// set from the package's own constants — every non-test file, since the constants and this
// table already live in different ones — so a category added without a row fails the build
// rather than inheriting that default silently.
//
// True means the verdict is a pure function of the token bytes and this validator's
// construction-time configuration, so nothing that can change within the TTL can invert it.
// False marks the three kinds of state a refusal can otherwise depend on:
//
//   - the CLOCK (expired, not_yet_valid, issued_in_future): an nbf token becomes valid later,
//     and while expiry is monotone the clock is injectable, so replaying it is not an argument
//     this table can make.
//   - the KEY SET (invalid_signature, jwks_unavailable): a rotation makes previously
//     unverifiable bytes verify, and a fetch failure is transient by definition.
//   - nothing at all (invalid): an unclassified failure carries no argument to replay.
//
// invalid_audience and invalid_issuer are memoizable only because ValidateToken is the SHARED
// validator's entry point — it checks the union of every route's audience, and the per-route
// narrowing happens later in Decide — so a negative entry can never answer a route-scoped
// question. That is structural rather than remembered: NewJWTPDPWithCache leaves both caches
// nil, so a route wrapper has nothing to read.
//
// malformed_authorization_header is refused before the cache is consulted (there is no token
// to key on); it is listed so the table stays exhaustive.
var memoizableJWTRefusals = map[string]bool{
	jwtErrMalformedToken:       true,
	jwtErrAmbiguousClaims:      true,
	jwtErrNonCanonicalClaim:    true,
	jwtErrMissingClaims:        true,
	jwtErrUnsupportedVersion:   true,
	jwtErrCapabilitiesDisabled: true,
	jwtErrInvalidCapabilities:  true,
	jwtErrSenderConstrained:    true,
	jwtErrInvalidAudience:      true,
	jwtErrInvalidIssuer:        true,

	jwtErrMalformedHeader: false,
	jwtErrSignature:       false,
	jwtErrExpired:         false,
	jwtErrNotYetValid:     false,
	jwtErrIssuedInFuture:  false,
	jwtErrJWKSUnavailable: false,
	jwtErrUnknown:         false,
}

// memoizableRefusal reports whether a ValidateToken failure may be served from the refusal
// cache on a later request carrying the same bytes.
//
// signatureVerified — the token verified against a JWKS key before this refusal was reached —
// is a gate on top of the category, not a restatement of it: malformed_token is reached both
// before verification (ParseSigned, the kid scan) and after it (the payload decodes), and only
// the second may be cached. What the gate buys is that the refusal cache can only be populated
// by bytes carrying a valid IdP signature, so an unauthenticated peer cannot spray entries
// into it at all — the cheap pre-verification refusals it excludes re-run a parse, not a
// verify.
func memoizableRefusal(err error, signatureVerified bool) bool {
	if !signatureVerified {
		return false
	}
	return memoizableJWTRefusals[ClassifyJWTError(err)]
}

// newJWTPayloadCache builds one of the validator's two token-hash-keyed caches.
//
// The clone is the IDENTITY function for both: each payload is immutable once ValidateToken
// has produced it, so entries are shared by pointer — a consumer that mutated one would race
// the other sessions presenting the same token within the TTL. A ZERO payload (a nil
// *JWTClaims, a nil error) reports the copy as failed, so it is neither stored nor served:
// a hit that answered nothing would hand a caller a nil error beside an unpopulated context.
func newJWTPayloadCache[T comparable](now func() time.Time, ttl time.Duration, maxSize int) *capability.PayloadCache[T] {
	return capability.NewPayloadCache(capability.PayloadCacheConfig[T]{
		MaxEntryTTL: ttl,
		MaxSize:     maxSize,
		Now:         now,
		Clone:       func(v T) (T, bool) { var zero T; return v, v != zero },
	})
}

// newJWTTokenCache builds the verified-token cache for a JWTPDP validator, memoizing
// verified claims by token hash so a repeat bearer token skips signature re-verification
// and the two claim decodes ValidateToken performs on every request.
func newJWTTokenCache(now func() time.Time) *capability.PayloadCache[*JWTClaims] {
	return newJWTPayloadCache[*JWTClaims](now, jwtTokenCacheTTL, jwtTokenCacheMaxSize)
}

// newJWTRefusalCache builds the negative half of that memoization: the refusals ValidateToken
// may replay verbatim (memoizableRefusal), keyed by the same token hash but held in a SEPARATE
// instance so neither half can evict the other.
func newJWTRefusalCache(now func() time.Time) *capability.PayloadCache[error] {
	return newJWTPayloadCache[error](now, jwtRefusalCacheTTL, jwtRefusalCacheMaxSize)
}
