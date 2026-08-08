// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package callcounter

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

// TestAdmitAllScript_DenyPathRefreshesTTLWhenKeyExists is a regression test.
// The Go-layer bucket validation rejects a non-positive limit before the script runs, so
// this fail-open path is unreachable in production; the test invokes the Lua script
// DIRECTLY (as an integration test or operator script could) to assert the script's own
// invariant: the deny branch must refresh the key TTL whenever the key exists, not only
// when the bucket holds entries. Otherwise a deny on an already-present key skips the
// refresh, the key expires, and the sliding window silently resets — a fail-open quota.
func TestAdmitAllScript_DenyPathRefreshesTTLWhenKeyExists(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()

	now := time.Unix(1_700_000_000, 0)
	const windowSec = 60
	const ttlSec = windowSec * cleanupMarginFactor
	windowMicros := int64(windowSec) * 1_000_000
	key := "callcounter:itest:60"

	// One counted bucket, the shape a lone maxCalls commits: per-bucket ARGV is
	// cutoff, member, limit, ttlSec, windowMicros, counted, weight — then the
	// batch-wide weighted-entry ceiling as the trailing ARGV.
	run := func(limit int64, member string) {
		cutoff := now.Add(-time.Duration(windowSec) * time.Second).UnixMicro()
		_, err := admitAllScript.Run(ctx, client, []string{key},
			now.UnixMicro(), cutoff, member, limit, ttlSec, windowMicros, 1, 0,
			MaxWeightedEntriesPerKey).Result()
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
	// directly, bypassing the Go bucket validation) reaches the deny branch. It must
	// refresh the TTL because the key EXISTS. Before the fix the branch refreshed only
	// when the bucket held entries; the EXISTS gate makes the refresh robust for any
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

// TestRedisAdmitAll_WeightedEntryCeilingRefusesRatherThanGrowing is the Redis half of
// MaxWeightedEntriesPerKey. It matters more here than in-memory: the per-admission re-sum
// is a ZRANGE 0 -1 walk INSIDE the blocking Lua script, so an unbounded weighted key
// slows every replica pointed at that Redis, not just this process. The refusal must be
// an error reply (which the engine denies on) and must write nothing.
func TestRedisAdmitAll_WeightedEntryCeilingRefusesRatherThanGrowing(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()

	now := time.Unix(1_700_000_000, 0)
	r := NewRedisForTest(t, client, withTimeFunc(func() time.Time { return now }), withRedisMaxWeightedEntries(3))
	b := capability.QuotaBucket{Key: "sess|tool:charge", WindowSec: 60, Weight: 1e-9, Limit: 1000}
	redisKey := redisWindowKey(b.Key, b.WindowSec)

	for i := 1; i <= 3; i++ {
		admitted, _, _, _, err := r.AdmitAll(ctx, []capability.QuotaBucket{b})
		require.NoError(t, err, "call %d under the ceiling", i)
		require.True(t, admitted, "call %d under the ceiling", i)
	}

	admitted, _, _, _, err := r.AdmitAll(ctx, []capability.QuotaBucket{b})
	require.Error(t, err, "the call past the ceiling must fail closed")
	require.Contains(t, err.Error(), "weighted entry limit")
	require.False(t, admitted)

	card, cardErr := client.ZCard(ctx, redisKey).Result()
	require.NoError(t, cardErr)
	require.Equal(t, int64(3), card, "the refused commit must write nothing")
	// The refusal still refreshes the TTL, so a key held at the ceiling cannot expire
	// mid-window and silently reset the budget it is holding.
	require.InDelta(t, float64(b.WindowSec*cleanupMarginFactor), mr.TTL(redisKey).Seconds(), 2)

	// A COUNTED bucket on its own key is unaffected: its limit is its retention.
	counted := capability.QuotaBucket{Key: "sess|tool:read", WindowSec: 60, Counted: true, Limit: 5}
	for i := 1; i <= 5; i++ {
		admitted, _, _, _, err := r.AdmitAll(ctx, []capability.QuotaBucket{counted})
		require.NoError(t, err, "counted call %d", i)
		require.True(t, admitted, "counted call %d", i)
	}
}

// TestRedisAdmitAll_WeightedCeilingIsAllOrNothingAcrossTheBatch pins that one bucket at
// the ceiling refuses the WHOLE batch before anything is written. A partial commit would
// let the sibling bucket's budget be spent by a call the batch did not admit — the same
// atomicity AdmitAll gives every other refusal on this path.
func TestRedisAdmitAll_WeightedCeilingIsAllOrNothingAcrossTheBatch(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()

	now := time.Unix(1_700_000_000, 0)
	r := NewRedisForTest(t, client, withTimeFunc(func() time.Time { return now }), withRedisMaxWeightedEntries(2))
	full := capability.QuotaBucket{Key: "sess|tool:charge", WindowSec: 60, Weight: 1e-9, Limit: 1000}
	sibling := capability.QuotaBucket{Key: "sess|tool:charge", WindowSec: 3600, Counted: true, Limit: 100}

	for i := 1; i <= 2; i++ {
		_, _, _, _, err := r.AdmitAll(ctx, []capability.QuotaBucket{full})
		require.NoError(t, err)
	}

	// The sibling is FIRST in the batch, so a ceiling checked inline in the commit loop
	// would already have written it by the time the second bucket refused.
	_, _, _, _, err := r.AdmitAll(ctx, []capability.QuotaBucket{sibling, full})
	require.Error(t, err, "a batch containing a bucket at the ceiling must fail closed")

	card, err := client.ZCard(ctx, redisWindowKey(sibling.Key, sibling.WindowSec)).Result()
	require.NoError(t, err)
	require.Equal(t, int64(0), card, "the sibling bucket must not have been charged")
}

// serverReply is a Redis error REPLY, the shape go-redis' exported Error interface names.
// Hand-rolled because the concrete type go-redis decodes replies into lives in an internal
// package: what matters to isCrossSlot is that the value answers errors.As for that interface,
// which is exactly what the RedisError marker declares.
type serverReply string

func (e serverReply) Error() string { return string(e) }
func (serverReply) RedisError()     {}

// TestIsCrossSlot pins the request-time topology detection against the shapes a real
// deployment produces, and against the two ways a text match got it wrong: a reply the server
// (or a compatible backend) prefixes, and an unrelated error whose message merely mentions the
// word. The sentinel row is the one go-redis raises itself; the prefixed row is the "ERR "
// spelling go-redis' own HasErrorPrefix documents.
func TestIsCrossSlot(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"go-redis sentinel", redis.ErrCrossSlot, true},
		{"server reply", serverReply("CROSSSLOT Keys in request don't hash to the same slot"), true},
		{"prefixed server reply", serverReply("ERR CROSSSLOT Keys in request don't hash to the same slot"), true},
		{"wrapped sentinel", fmt.Errorf("redis eval: %w", redis.ErrCrossSlot), true},
		{"unrelated redis error", serverReply("NOSCRIPT No matching script. Please use EVAL."), false},
		// A plain Go error is not a Redis reply, whatever its text says: mislabelling one as a
		// topology refusal buries the real fault behind an unrelated remediation.
		{"non-redis error naming the word", errors.New("dial tcp: CROSSSLOT appears in this log line"), false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isCrossSlot(tc.err); got != tc.want {
				t.Errorf("isCrossSlot(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
