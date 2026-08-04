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
