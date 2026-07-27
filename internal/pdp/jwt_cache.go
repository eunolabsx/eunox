// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"time"

	"github.com/eunolabs/eunox/pkg/capability"
)

// Verified-token cache bounds. The TTL bounds how long a token's already-verified
// claims are reused before full re-verification; 30s matches the Redis kill-switch
// propagation window, so a revoked token is not trusted from cache materially longer
// than a kill takes to propagate. The max size bounds memory under a churn of distinct
// tokens.
//
// These are FIXED, not defaults: no JWTPDPOptions field overrides them, unlike the
// JWKS cache's operator-settable CacheTTL. The asymmetry is deliberate — this window
// is what extends trust in an already-verified token, and it is already bounded from
// both ends (capped by the token's own exp, and the kill switch, per-route audience,
// and manifest policy are re-checked on every call regardless of a cache hit). See the
// CacheTTL doc in jwt.go, which points here so the distinction is visible from the
// option an operator actually sets.
const (
	jwtTokenCacheTTL     = 30 * time.Second
	jwtTokenCacheMaxSize = 4096
)

// newJWTTokenCache builds the verified-token cache for a JWTPDP validator: the shared
// capability.PayloadCache engine specialized to *JWTClaims. It memoizes verified
// claims by token hash so a repeat bearer token skips signature re-verification and
// the two claim decodes ValidateToken performs on every request.
//
// JWTClaims is immutable after validation and read-only by contract, so the clone is
// the IDENTITY function — entries are shared by pointer, no deep copy (a JSON
// round-trip clone would drop JWTClaims' unexported cached fields
// parsedCaps/flatClaims). Lazy pruning on Get/Put keeps the cache bounded without a
// background goroutine.
//
// Because Get hands the SAME *JWTClaims pointer to every caller holding the token
// within the TTL, the read-only contract on JWTClaims (and its flatClaims map handed
// to third-party PolicyEvaluators) is load-bearing for thread-safety, not just
// correctness — a consumer that mutates the returned claims would race other sessions.
//
// Security scope: the kill switch, per-route audience, and manifest policy are still
// checked per call in Decide, so caching only skips the signature/exp/iss/aud
// re-check; exp is honored because the entry TTL is capped at the token's remaining
// lifetime.
func newJWTTokenCache(now func() time.Time) *capability.PayloadCache[*JWTClaims] {
	return capability.NewPayloadCache(capability.PayloadCacheConfig[*JWTClaims]{
		MaxEntryTTL: jwtTokenCacheTTL,
		MaxSize:     jwtTokenCacheMaxSize,
		Now:         now,
		Clone:       func(c *JWTClaims) (*JWTClaims, bool) { return c, c != nil },
	})
}
