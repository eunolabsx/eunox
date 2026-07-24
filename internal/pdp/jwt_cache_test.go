// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"testing"
	"time"

	"github.com/eunolabs/eunox/pkg/capability"
)

// The generic cache engine (TTL, eviction, LRU-like ordering, concurrency) is tested in
// pkg/capability (payload_cache_internal_test.go); it is lazy-pruned with no background
// goroutine, so there is no Start/Stop. These tests cover only the JWT-specific wiring in
// newJWTTokenCache.

// TestJWTTokenCache_SharesPointer pins the identity-clone contract: Get returns the
// SAME *JWTClaims pointer that was Put, so the immutable claims (and their cached
// flatClaims map) are shared, not deep-copied, on the hot path — safe only because
// JWTClaims is read-only by contract after validation (see newJWTTokenCache's doc).
func TestJWTTokenCache_SharesPointer(t *testing.T) {
	t.Parallel()
	base := time.Unix(1_000_000, 0)
	now := base
	c := newJWTTokenCache(func() time.Time { return now })

	claims := &JWTClaims{Subject: "sub-1"}
	key := capability.HashTokenKey("tok")
	c.Put(key, claims, base.Add(time.Hour).Unix())

	got, ok := c.Get(key)
	if !ok || got != claims {
		t.Fatalf("expected the same pointer back (identity clone): ok=%v got=%p want=%p", ok, got, claims)
	}
	if _, ok := c.Get(capability.HashTokenKey("other")); ok {
		t.Fatal("an unknown token must miss")
	}
}

// TestJWTTokenCache_ExpiresOnDefaultTTL confirms the 30s default TTL is applied via
// the injected clock.
func TestJWTTokenCache_ExpiresOnDefaultTTL(t *testing.T) {
	t.Parallel()
	base := time.Unix(2_000_000, 0)
	now := base
	c := newJWTTokenCache(func() time.Time { return now })

	key := capability.HashTokenKey("tok")
	c.Put(key, &JWTClaims{Subject: "s"}, base.Add(time.Hour).Unix())
	now = base.Add(defaultJWTCacheTTL + time.Second)
	if _, ok := c.Get(key); ok {
		t.Fatal("entry must expire once the default TTL elapses on the injected clock")
	}
}

// TestJWTTokenCache_TTLCappedByExp confirms the entry never outlives the token's own
// exp even when the configured TTL is longer.
func TestJWTTokenCache_TTLCappedByExp(t *testing.T) {
	t.Parallel()
	base := time.Unix(3_000_000, 0)
	now := base
	c := newJWTTokenCache(func() time.Time { return now })

	// Token expires in 5s, shorter than the 30s default TTL.
	key := capability.HashTokenKey("tok")
	c.Put(key, &JWTClaims{Subject: "s"}, base.Add(5*time.Second).Unix())
	now = base.Add(6 * time.Second)
	if _, ok := c.Get(key); ok {
		t.Fatal("entry must not be served past the token's own exp")
	}
}

// TestJWTTokenCache_NoCacheWithoutPositiveExpiry pins the fail-closed rule: a token
// with no positive remaining lifetime (or absent exp) is never cached.
func TestJWTTokenCache_NoCacheWithoutPositiveExpiry(t *testing.T) {
	t.Parallel()
	base := time.Unix(4_000_000, 0)
	now := base
	c := newJWTTokenCache(func() time.Time { return now })

	c.Put(capability.HashTokenKey("no-exp"), &JWTClaims{Subject: "s"}, 0)
	if _, ok := c.Get(capability.HashTokenKey("no-exp")); ok {
		t.Fatal("a token with no positive exp must not be cached")
	}
	c.Put(capability.HashTokenKey("expired"), &JWTClaims{Subject: "s"}, base.Add(-time.Second).Unix())
	if _, ok := c.Get(capability.HashTokenKey("expired")); ok {
		t.Fatal("an already-expired token must not be cached")
	}
}

// TestJWTTokenCache_NilReceiver pins the nil-safe contract a JWTPDP built as a bare
// literal (in tests) relies on: Get misses and Put no-ops without panicking.
func TestJWTTokenCache_NilReceiver(t *testing.T) {
	t.Parallel()
	var c *capability.PayloadCache[*JWTClaims]
	if _, ok := c.Get("k"); ok {
		t.Fatal("nil cache must miss")
	}
	c.Put("k", &JWTClaims{Subject: "s"}, time.Now().Add(time.Hour).Unix()) // must not panic
}
