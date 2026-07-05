// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package callcounter

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

// TestIncrIfBelowScript_DenyPathRefreshesTTLWhenKeyExists is a regression test.
// The Go-layer checkLimit guard rejects limit<1 before the script runs, so this
// fail-open path is unreachable in production; the test invokes the Lua script
// DIRECTLY (as an integration test or operator script could) to assert the
// script's own invariant: the deny branch must refresh the key TTL whenever the
// key exists, not only when count>0. Otherwise a (limit<1 AND count==0) deny on
// an already-present key skips the refresh, the key expires, and the sliding
// window silently resets — a fail-open quota.
func TestIncrIfBelowScript_DenyPathRefreshesTTLWhenKeyExists(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()

	now := time.Unix(1_700_000_000, 0)
	const windowSec = 60
	const ttlSec = windowSec * cleanupMarginFactor
	windowMicros := int64(windowSec) * 1_000_000
	key := "callcounter:itest:60"

	run := func(limit int64, member string) {
		cutoff := now.Add(-time.Duration(windowSec) * time.Second).UnixMicro()
		_, err := incrIfBelowScript.Run(ctx, client, []string{key},
			cutoff, now.UnixMicro(), member, limit, ttlSec, windowMicros).Result()
		require.NoError(t, err)
	}

	// Admit one call under a normal limit so the key exists with a TTL and one
	// in-window entry that does NOT age out (the window clock is held fixed).
	run(5, "m-0000000001")
	require.InDelta(t, (time.Duration(ttlSec) * time.Second).Seconds(), mr.TTL(key).Seconds(), 2,
		"admitted call should set the key TTL")

	// Burn most of the Redis TTL clock WITHOUT advancing the window clock, so the
	// admitted entry stays in-window while the key's TTL counts down toward expiry.
	mr.FastForward(time.Duration(ttlSec-10) * time.Second)
	require.True(t, mr.Exists(key), "precondition: key must still exist before the deny call")
	require.InDelta(t, float64(10), mr.TTL(key).Seconds(), 3,
		"precondition: TTL should have counted down to ~10s")

	// A deny driven by limit<1 (a misconfigured/relaxed limit invoking the script
	// directly, bypassing the Go checkLimit guard) reaches the deny branch. It must
	// refresh the TTL because the key EXISTS. Before the fix the branch
	// refreshed only when count>0; the EXISTS gate makes the refresh robust for any
	// reachable deny on a live key, so the key cannot silently expire and reset the
	// quota window.
	run(0, "m-0000000002")

	require.True(t, mr.Exists(key), "key must still exist after the deny call")
	require.InDelta(t, (time.Duration(ttlSec) * time.Second).Seconds(), mr.TTL(key).Seconds(), 2,
		"deny path with limit<1 must refresh the key TTL when the key exists")

	// The entry is still in-window: this exercised the deny branch with the key
	// present, which is what the EXISTS-gated refresh protects.
	card, err := client.ZCard(ctx, key).Result()
	require.NoError(t, err)
	require.Equal(t, int64(1), card, "the in-window entry must remain (deny adds none)")
}
