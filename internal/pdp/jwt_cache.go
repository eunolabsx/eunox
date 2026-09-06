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

// Refusal-cache bounds. The TTL is the verified-token cache's, since both extend a verdict
// past the moment it was reached and an operator reasoning about either wants ONE number —
// but it is not what makes replaying a refusal correct: memoizableRefusal already admits only
// verdicts no elapsed time can invert. What it bounds is how long the recorded CATEGORY may
// lag a token that has meanwhile expired.
//
// A SEPARATE, smaller instance rather than a share of the verified-token cache: entries here
// are minted by whatever the IdP happens to be emitting, so sharing would let a stream of
// distinct refusals evict every legitimate positive entry and turn the memoization into an
// eviction lever against the path it exists to speed up.
const (
	jwtRefusalCacheTTL     = jwtTokenCacheTTL
	jwtRefusalCacheMaxSize = 1024
)

// memoizableJWTRefusals declares, for EVERY ValidateToken failure category, whether a refusal
// carrying it may be replayed from the refusal cache. A category with no row is not
// memoizable (fail closed), and TestJWTRefusalMemoization_EveryCategoryDeclaresOne derives the
// set from jwt.go's own constants so a category added without a row fails the build rather
// than inheriting that default silently.
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

// newJWTTokenCache builds the verified-token cache for a JWTPDP validator, memoizing
// verified claims by token hash so a repeat bearer token skips signature re-verification
// and the two claim decodes ValidateToken performs on every request.
//
// The clone is the IDENTITY function: JWTClaims is immutable and read-only by contract,
// so entries are shared by pointer — a consumer that mutates returned claims would race
// other sessions holding the same pointer within the TTL.
func newJWTTokenCache(now func() time.Time) *capability.PayloadCache[*JWTClaims] {
	return capability.NewPayloadCache(capability.PayloadCacheConfig[*JWTClaims]{
		MaxEntryTTL: jwtTokenCacheTTL,
		MaxSize:     jwtTokenCacheMaxSize,
		Now:         now,
		Clone:       func(c *JWTClaims) (*JWTClaims, bool) { return c, c != nil },
	})
}

// newJWTRefusalCache builds the negative half of the validator's memoization: the refusals
// ValidateToken may replay verbatim (memoizableRefusal), keyed by the same token hash as the
// verified-token cache but held in a SEPARATE instance so neither half can evict the other.
//
// The clone is the IDENTITY function for the verified-token cache's reason: the stored value
// is the error ValidateToken already returned, immutable and shared by pointer across the
// sessions that present the same token. A nil error reports the copy as failed, so a caller
// that ever stored one re-validates rather than returning a nil error beside a nil context.
func newJWTRefusalCache(now func() time.Time) *capability.PayloadCache[error] {
	return capability.NewPayloadCache(capability.PayloadCacheConfig[error]{
		MaxEntryTTL: jwtRefusalCacheTTL,
		MaxSize:     jwtRefusalCacheMaxSize,
		Now:         now,
		Clone:       func(e error) (error, bool) { return e, e != nil },
	})
}
