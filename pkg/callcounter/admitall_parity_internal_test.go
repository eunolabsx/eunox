// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package callcounter

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

// TestAdmitAll_CountedBucketOnWeightedKeyIgnoresTheWeightedCeiling pins both backends to
// the same semantics for the shape #219/#220 flagged as diverging: a counted bucket
// landing on a (Key, WindowSec) key a PRIOR weighted bucket already filled to the
// weighted-entry ceiling (reachable across calls, e.g. a manifest edit that changes a
// key's accounting). The counted bucket's own `maxCalls` limit already bounds how many
// entries it can hold, so the weighted ceiling must not additionally refuse it — that
// would deny an admission at a bound no operator wrote, and it is exactly the property
// TestAdmitAll_WeightedCeilingDoesNotBindACountedBucket / the Redis
// "COUNTED bucket on its own key" case already pin for a FRESH key. The Lua script has
// always skipped counted buckets categorically (`counted ~= 1`); InMemory is aligned to
// match here.
func TestAdmitAll_CountedBucketOnWeightedKeyIgnoresTheWeightedCeiling(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	const key = "sess|tool:shared"
	const windowSec = 60

	weighted := capability.QuotaBucket{Key: key, WindowSec: windowSec, Weight: 1e-9, Limit: 1000}
	counted := capability.QuotaBucket{Key: key, WindowSec: windowSec, Counted: true, Limit: 5}

	t.Run("memory", func(t *testing.T) {
		m := NewInMemory(WithTimeFunc(func() time.Time { return now }), withMaxWeightedEntries(2))
		for i := 1; i <= 2; i++ {
			admitted, _, _, _, err := m.AdmitAll(ctx, []capability.QuotaBucket{weighted})
			require.NoError(t, err)
			require.True(t, admitted, "weighted call %d must fill the key to the ceiling", i)
		}
		// A further weighted call is refused: the key is genuinely at the ceiling.
		_, _, _, _, err := m.AdmitAll(ctx, []capability.QuotaBucket{weighted})
		require.Error(t, err, "a weighted call past the ceiling must still refuse")

		// The counted bucket on the SAME key must be admitted: its own limit governs it.
		admitted, _, _, _, err := m.AdmitAll(ctx, []capability.QuotaBucket{counted})
		require.NoError(t, err, "a counted bucket must not be bound by the weighted ceiling")
		require.True(t, admitted)
	})

	t.Run("redis", func(t *testing.T) {
		mr := miniredis.RunT(t)
		client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		t.Cleanup(func() { _ = client.Close() })

		r := NewRedis(client, withTimeFunc(func() time.Time { return now }), withRedisMaxWeightedEntries(2))
		for i := 1; i <= 2; i++ {
			admitted, _, _, _, err := r.AdmitAll(ctx, []capability.QuotaBucket{weighted})
			require.NoError(t, err)
			require.True(t, admitted, "weighted call %d must fill the key to the ceiling", i)
		}
		_, _, _, _, err := r.AdmitAll(ctx, []capability.QuotaBucket{weighted})
		require.Error(t, err, "a weighted call past the ceiling must still refuse")

		admitted, _, _, _, err := r.AdmitAll(ctx, []capability.QuotaBucket{counted})
		require.NoError(t, err, "a counted bucket must not be bound by the weighted ceiling")
		require.True(t, admitted)
	})
}
