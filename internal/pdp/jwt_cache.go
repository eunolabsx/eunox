// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"time"

	"github.com/eunolabs/eunox/pkg/capability"
)

// Verified-token cache defaults. The TTL bounds how long a token's already-verified
// claims are reused before full re-verification; the 30s default matches the
// Redis kill-switch propagation window, so a revoked token is not trusted from
// cache materially longer than a kill takes to propagate. The max size bounds
// memory under a churn of distinct tokens.
const (
	defaultJWTCacheTTL     = 30 * time.Second
	defaultJWTCacheMaxSize = 4096
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
		MaxEntryTTL: defaultJWTCacheTTL,
		MaxSize:     defaultJWTCacheMaxSize,
		Now:         now,
		Clone:       func(c *JWTClaims) (*JWTClaims, bool) { return c, c != nil },
	})
}
