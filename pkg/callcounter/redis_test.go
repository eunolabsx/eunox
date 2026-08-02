// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package callcounter_test

import (
	"context"
	"math"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
)

func TestRedis_IncrementAndGet_Basic(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	counter := callcounter.NewRedis(client)
	ctx := context.Background()

	count, err := counter.IncrementAndGet(ctx, "key1", 60, noTrimCap)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	count, err = counter.IncrementAndGet(ctx, "key1", 60, noTrimCap)
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)
}

// TestRedis_IncrementAndGet_CapsToMaxEntries is a Redis-backed regression test:
// the sorted set is trimmed to its most-recent maxEntries members on every call
// (ZREMRANGEBYRANK), so a high-rate key over a long window stays bounded instead
// of holding one member per call. Both the returned count and an independent Peek
// stay at the cap.
func TestRedis_IncrementAndGet_CapsToMaxEntries(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	counter := callcounter.NewRedis(client)
	ctx := context.Background()

	const (
		windowSec  = 86400 // 24h
		maxEntries = 1
		key        = "seq:s:tool"
		calls      = 500
	)
	for i := 0; i < calls; i++ {
		count, err := counter.IncrementAndGet(ctx, key, windowSec, maxEntries)
		require.NoError(t, err)
		require.Equal(t, int64(maxEntries), count, "call %d: count must be capped at maxEntries", i)
	}

	// An independent read path confirms the set itself is bounded, not just the
	// returned count: without trimming, Peek (ZCOUNT) would see all `calls` members.
	got, err := counter.Peek(ctx, key, windowSec)
	require.NoError(t, err)
	assert.Equal(t, int64(maxEntries), got, "the sorted set must be trimmed to maxEntries members")
}

// TestRedis_IncrementAndGet_CapKeepsNewest is the Redis counterpart of the
// InMemory keep-newest test: the cap must retain the highest-scored (newest)
// member so a sliding-window presence check stays correct until the last call
// ages out. Trimming the newest instead would fail sequenceBlock open.
func TestRedis_IncrementAndGet_CapKeepsNewest(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	base := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
	now := base
	counter := callcounter.NewRedis(client, callcounter.WithRedisTimeFunc(func() time.Time { return now }))
	ctx := context.Background()

	const (
		windowSec  = 60
		maxEntries = 1
		key        = "seq:s:tool"
	)

	_, err := counter.IncrementAndGet(ctx, key, windowSec, maxEntries)
	require.NoError(t, err)
	now = base.Add(40 * time.Second)
	_, err = counter.IncrementAndGet(ctx, key, windowSec, maxEntries)
	require.NoError(t, err)

	// t=70s: the t=0 member has aged out of the 60s window, the t=40s member has
	// not. The cap kept the newest, so presence still reads 1.
	now = base.Add(70 * time.Second)
	got, err := counter.Peek(ctx, key, windowSec)
	require.NoError(t, err)
	assert.Equal(t, int64(1), got, "the newest member (t=40s) must be the one retained")

	// t=101s: even the t=40s member has aged out.
	now = base.Add(101 * time.Second)
	got, err = counter.Peek(ctx, key, windowSec)
	require.NoError(t, err)
	assert.Equal(t, int64(0), got, "every member should have aged out")
}

// TestRedis_IncrementAndGet_RejectsNonPositiveMaxEntries verifies the cap is
// mandatory on the Redis backend too: a non-positive maxEntries fails closed
// rather than being treated as unbounded.
func TestRedis_IncrementAndGet_RejectsNonPositiveMaxEntries(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	counter := callcounter.NewRedis(client)
	ctx := context.Background()
	for _, mx := range []int{0, -1} {
		_, err := counter.IncrementAndGet(ctx, "k", 60, mx)
		require.Error(t, err, "maxEntries %d must fail closed", mx)
	}
}

// TestRedis_IncrementAndGet_RejectsOversizedMaxEntries is a regression test:
// checkMaxEntries must reject a maxEntries above MaxEntries. Without the upper
// bound, math.MaxInt would be accepted and the ZRemRangeByRank trim computed
// -(maxEntries+1) in int, wrapping through math.MinInt and turning the trim into
// a no-op — leaving the sorted set to grow unbounded. Fail closed instead,
// matching the windowSec upper-bound guard.
func TestRedis_IncrementAndGet_RejectsOversizedMaxEntries(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	counter := callcounter.NewRedis(client)
	ctx := context.Background()
	// Only representable oversized values: on a 32-bit platform MaxEntries equals
	// math.MaxInt, so no int can exceed it and there is nothing to reject above the
	// boundary. Guarding on this keeps the test correct on both int widths.
	for _, mx := range oversizedMaxEntries() {
		_, err := counter.IncrementAndGet(ctx, "k", 60, mx)
		require.Error(t, err, "maxEntries %d must fail closed", mx)
	}

	// The boundary value is accepted.
	_, err := counter.IncrementAndGet(ctx, "k", 60, callcounter.MaxEntries)
	require.NoError(t, err, "maxEntries == MaxEntries must be accepted")
}

// TestRedis_RejectsOutOfRangeWindow is a regression test: a windowSec past
// callcounter.MaxWindowSeconds overflows the 2x TTL margin
// (time.Duration(windowSec)*2*time.Second), wrapping the key TTL to a
// non-positive value so the key expires immediately and the counter resets to 1
// on every call. Reject it (fail closed) instead, on both IncrementAndGet and
// the read-only Peek; a non-positive window is rejected for the same reason.
func TestRedis_RejectsOutOfRangeWindow(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	counter := callcounter.NewRedis(client)
	ctx := context.Background()

	huge := int(callcounter.MaxWindowSeconds) + 1
	_, err := counter.IncrementAndGet(ctx, "huge-ttl", huge, noTrimCap)
	require.Error(t, err, "overflowing windowSec must fail closed")
	_, err = counter.Peek(ctx, "huge-ttl", huge)
	require.Error(t, err, "overflowing windowSec must fail closed on Peek too")

	_, err = counter.IncrementAndGet(ctx, "zero", 0, noTrimCap)
	require.Error(t, err)

	// The largest in-range window is accepted and counts normally — the most
	// valuable assertion for catching an off-by-one in the bound, mirroring the
	// in-memory test so both backends pin the boundary, not just the reject side.
	n, err := counter.IncrementAndGet(ctx, "ok", int(callcounter.MaxWindowSeconds), noTrimCap)
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)
}

func TestRedis_Peek_DoesNotMutate(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	counter := callcounter.NewRedis(client)
	ctx := context.Background()

	// Unknown key reads as zero.
	n, err := counter.Peek(ctx, "key1", 60)
	require.NoError(t, err)
	assert.Equal(t, int64(0), n)

	_, err = counter.IncrementAndGet(ctx, "key1", 60, noTrimCap)
	require.NoError(t, err)
	_, err = counter.IncrementAndGet(ctx, "key1", 60, noTrimCap)
	require.NoError(t, err)

	// Repeated Peek always reports 2 and never records a call. The window must
	// match the one used to record (60) so the same bucket is consulted.
	for i := 0; i < 3; i++ {
		n, err = counter.Peek(ctx, "key1", 60)
		require.NoError(t, err)
		assert.Equal(t, int64(2), n)
	}

	// The next real increment sees 3, proving Peek added nothing.
	n, err = counter.IncrementAndGet(ctx, "key1", 60, noTrimCap)
	require.NoError(t, err)
	assert.Equal(t, int64(3), n)
}

// TestRedis_Peek_ExcludesExactCutoff is a regression test for the boundary bug
// where Redis.Peek counted a sorted-set entry whose score is exactly the window
// cutoff, while the mutating path (IncrementAndGet, via ZRemRangeByScore) and the
// in-memory backend (Peek, via ts.After) both treat that entry as expired. The
// fix makes ZCOUNT use an exclusive lower bound so all three agree at the edge.
func TestRedis_Peek_ExcludesExactCutoff(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	now := time.Unix(1_700_000_000, 0)
	counter := callcounter.NewRedis(client, callcounter.WithRedisTimeFunc(func() time.Time { return now }))
	ctx := context.Background()

	// Record one call, then advance exactly one window so the recorded entry sits
	// precisely on the cutoff timestamp.
	_, err := counter.IncrementAndGet(ctx, "boundary", 60, noTrimCap)
	require.NoError(t, err)

	now = now.Add(60 * time.Second)

	// The entry is at the exact boundary: it must read as expired (0) to match
	// IncrementAndGet and InMemory.Peek, not as still-present (1).
	got, err := counter.Peek(ctx, "boundary", 60)
	require.NoError(t, err)
	assert.Equal(t, int64(0), got, "exact-cutoff entry must be treated as expired")

	// And the mutating path must agree: the boundary entry is dropped, so the new
	// call is the only one in the window.
	count, err := counter.IncrementAndGet(ctx, "boundary", 60, noTrimCap)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count, "IncrementAndGet must also drop the exact-cutoff entry")
}

// TestRedis_Peek_IncludesJustInsideWindow guards the other side of the boundary:
// an entry one microsecond newer than the cutoff is still within the window and
// must be counted.
func TestRedis_Peek_IncludesJustInsideWindow(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	now := time.Unix(1_700_000_000, 0)
	counter := callcounter.NewRedis(client, callcounter.WithRedisTimeFunc(func() time.Time { return now }))
	ctx := context.Background()

	_, err := counter.IncrementAndGet(ctx, "boundary", 60, noTrimCap)
	require.NoError(t, err)

	// Advance one microsecond short of a full window so the entry is strictly
	// newer than the cutoff and therefore still live.
	now = now.Add(60*time.Second - time.Microsecond)

	got, err := counter.Peek(ctx, "boundary", 60)
	require.NoError(t, err)
	assert.Equal(t, int64(1), got, "entry just inside the window must still be counted")
}

// TestRedis_IncrementAndGet_SlidingWindowExpiry verifies that after the key TTL
// elapses, the sorted-set key is evicted by Redis and the counter resets to 1.
//
// Note: miniredis.FastForward only advances Redis's internal TTL clock; it does
// not advance Go's time.Now().  The test therefore relies on key expiry (TTL)
// rather than ZREMRANGEBYSCORE to produce count==1.  The key TTL is
// 2×windowSec (4 s for window=2), so the fast-forward must exceed 4 s.
func TestRedis_IncrementAndGet_SlidingWindowExpiry(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	counter := callcounter.NewRedis(client)
	ctx := context.Background()

	// Make 3 calls with a 2-second window (key TTL = 2×2 = 4 s).
	for i := 0; i < 3; i++ {
		_, err := counter.IncrementAndGet(ctx, "key1", 2, noTrimCap)
		require.NoError(t, err)
	}

	// Advance past the 4-second TTL so that miniredis evicts the key.
	mr.FastForward(5 * time.Second)

	// After TTL expiry the sorted-set key is gone; the next call creates a new
	// one with exactly 1 entry.
	count, err := counter.IncrementAndGet(ctx, "key1", 2, noTrimCap)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count, "key must be evicted after TTL expires")
}

func TestRedis_IncrementAndGet_ConcurrentCallsNoDuplicate(t *testing.T) {
	// Before the fix, two calls at the same UnixNano produced the same ZADD
	// member.  ZADD with an existing member updates its score rather than
	// inserting a new entry, so the counter undercounted.  The monotonic
	// sequence suffix added by the fix ensures each call gets a unique member.
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	counter := callcounter.NewRedis(client)
	ctx := context.Background()

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_, err := counter.IncrementAndGet(ctx, "concurrent-key", 60, noTrimCap)
			require.NoError(t, err)
		}()
	}
	wg.Wait()

	// One final call to read the total.  Expect exactly n+1 distinct entries.
	count, err := counter.IncrementAndGet(ctx, "concurrent-key", 60, noTrimCap)
	require.NoError(t, err)
	assert.Equal(t, int64(n+1), count,
		"all concurrent calls must be counted as distinct entries (no nanosecond collision)")
}

func TestRedis_IncrementIfBelow_AdmitsUpToLimit(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	counter := callcounter.NewRedis(client)
	ctx := context.Background()

	for i := 1; i <= 3; i++ {
		count, admitted, retry, err := counter.IncrementIfBelow(ctx, "k", 60, 3)
		require.NoError(t, err)
		assert.True(t, admitted, "call %d within the limit must be admitted", i)
		assert.Equal(t, int64(i), count)
		assert.Equal(t, time.Duration(0), retry)
	}

	count, admitted, retry, err := counter.IncrementIfBelow(ctx, "k", 60, 3)
	require.NoError(t, err)
	assert.False(t, admitted)
	assert.Equal(t, int64(3), count, "a denied call must not add a member")
	assert.Greater(t, retry, time.Duration(0), "a denied call should report a retryAfter hint")
}

// TestRedis_IncrementIfBelow_AtomicUnderConcurrency pins the single-bucket maxCalls
// admission bound on the Redis backend, mirroring the in-memory sibling: N racing
// callers against a limit of L admit exactly L, never more. This is the PRIMARY maxCalls
// path, and Redis is the backend where over-admission is most plausible — the
// check-and-increment spans a network round trip, so it is atomic only because it runs
// as one server-side script. A regression that split the check from the increment would
// admit more than L here while every sequential test still passed.
func TestRedis_IncrementIfBelow_AtomicUnderConcurrency(t *testing.T) {
	cases := []struct {
		name  string
		limit int64
	}{
		{"limit-1", 1},
		{"limit-5", 5},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			mr := miniredis.RunT(t)
			client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
			t.Cleanup(func() { _ = client.Close() })

			counter := callcounter.NewRedis(client)
			ctx := context.Background()

			const goroutines = 64
			var (
				mu          sync.Mutex
				admittedCnt int
				start       = make(chan struct{})
				wg          sync.WaitGroup
			)
			wg.Add(goroutines)
			for i := 0; i < goroutines; i++ {
				go func() {
					defer wg.Done()
					<-start
					_, admitted, _, err := counter.IncrementIfBelow(ctx, "k", 60, tc.limit)
					if err == nil && admitted {
						mu.Lock()
						admittedCnt++
						mu.Unlock()
					}
				}()
			}
			close(start)
			wg.Wait()

			assert.Equal(t, int(tc.limit), admittedCnt,
				"exactly the limit may be admitted concurrently, never more (a higher count is a maxCalls bypass)")
		})
	}
}

func TestRedis_IncrementIfBelow_RejectsOutOfRangeWindow(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	counter := callcounter.NewRedis(client)
	ctx := context.Background()

	_, _, _, err := counter.IncrementIfBelow(ctx, "k", 0, 1)
	require.Error(t, err, "non-positive window must fail closed")

	_, _, _, err = counter.IncrementIfBelow(ctx, "k", int(callcounter.MaxWindowSeconds)+1, 1)
	require.Error(t, err, "overflowing window must fail closed")
}

// TestRedis_IncrementIfBelow_RejectsNonPositiveLimit is a Redis-backed regression
// test: a limit<1 fails closed with an explicit error before the Lua script runs,
// rather than letting the script's `if limit < 1` branch return a denial with a
// nil error. It also writes no member, matching the window guard.
func TestRedis_IncrementIfBelow_RejectsNonPositiveLimit(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	counter := callcounter.NewRedis(client)
	ctx := context.Background()

	for _, limit := range []int64{0, -1} {
		_, admitted, _, err := counter.IncrementIfBelow(ctx, "k", 60, limit)
		require.Errorf(t, err, "limit=%d must fail closed with an error", limit)
		require.Falsef(t, admitted, "limit=%d must not admit", limit)
	}

	// The rejected calls wrote no state: a subsequent valid call is the first in
	// its window.
	count, admitted, _, err := counter.IncrementIfBelow(ctx, "k", 60, 5)
	require.NoError(t, err)
	require.True(t, admitted, "a valid call after rejected limit<1 calls must be admitted")
	require.Equal(t, int64(1), count, "rejected limit<1 calls must not have written a member")
}

// TestRedis_IncrementIfBelow_DeniedCallsDoNotExtendLockout is a Redis-backed
// regression test: denied retries add no member to the sorted set, so the set
// does not grow under a retry flood and the window clears on time once the
// original calls age out (controlled here via the injected clock).
func TestRedis_IncrementIfBelow_DeniedCallsDoNotExtendLockout(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	now := time.Unix(1_700_000_000, 0)
	counter := callcounter.NewRedis(client, callcounter.WithRedisTimeFunc(func() time.Time { return now }))
	ctx := context.Background()

	// Fill the window: 2 calls at T=0 with a limit of 2.
	for i := 0; i < 2; i++ {
		_, admitted, _, err := counter.IncrementIfBelow(ctx, "k", 60, 2)
		require.NoError(t, err)
		require.True(t, admitted)
	}

	// Retry once per second through the window: every call is denied and adds no
	// member, so the in-window count holds at the limit and the sorted set does
	// not grow with the denied retries.
	for sec := 1; sec <= 59; sec++ {
		now = now.Add(time.Second)
		count, admitted, retry, err := counter.IncrementIfBelow(ctx, "k", 60, 2)
		require.NoError(t, err)
		assert.False(t, admitted, "second %d: over-limit call must be denied", sec)
		assert.Equal(t, int64(2), count, "second %d: denied retries must not grow the sorted set", sec)
		assert.Equal(t, time.Duration(60-sec)*time.Second, retry, "second %d: retryAfter should track the oldest call's expiry", sec)
	}

	// One tick past the original window: the two T=0 calls fall outside the
	// score window and are pruned, so a retry is admitted.
	now = now.Add(2 * time.Second) // T=61
	count, admitted, _, err := counter.IncrementIfBelow(ctx, "k", 60, 2)
	require.NoError(t, err)
	assert.True(t, admitted, "after the original window clears, a retry must be admitted")
	assert.Equal(t, int64(1), count)
}

// TestRedis_IncrementIfBelow_DeniedCallRefreshesTTL is a regression test: the
// Lua script must refresh the key TTL on the denied path too, not only on
// admission. Otherwise a key that is continuously at or above limit (never
// admitted) lets its TTL count down from the last admitted call and can expire
// mid-window, after which ZCARD returns 0 and the quota window silently resets.
// We advance Redis's internal TTL clock (FastForward) without advancing the
// counter's sliding-window clock, so the admitted entry is still logically in the
// window when the denied call arrives; the denied call must restore the full TTL.
func TestRedis_IncrementIfBelow_DeniedCallRefreshesTTL(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	now := time.Unix(1_700_000_000, 0)
	counter := callcounter.NewRedis(client, callcounter.WithRedisTimeFunc(func() time.Time { return now }))
	ctx := context.Background()

	const windowSec = 60 // TTL = windowSec * 2 = 120s
	key := "callcounter:k:60"

	// Admit the single allowed call; this sets the key TTL to 120s.
	_, admitted, _, err := counter.IncrementIfBelow(ctx, "k", windowSec, 1)
	require.NoError(t, err)
	require.True(t, admitted)
	require.InDelta(t, (120 * time.Second).Seconds(), mr.TTL(key).Seconds(), 2,
		"admitted call should set TTL to windowSec*2")

	// Burn most of the TTL on Redis's clock without advancing the window clock,
	// so the admitted entry is still in the sliding window.
	mr.FastForward(100 * time.Second)
	require.InDelta(t, (20 * time.Second).Seconds(), mr.TTL(key).Seconds(), 2,
		"precondition: TTL should have counted down to ~20s")

	// A denied call (still at limit, entry still in window) must refresh the TTL
	// back to the full window so the key does not expire and reset the quota.
	_, admitted, _, err = counter.IncrementIfBelow(ctx, "k", windowSec, 1)
	require.NoError(t, err)
	require.False(t, admitted, "call at limit must be denied")
	require.InDelta(t, (120 * time.Second).Seconds(), mr.TTL(key).Seconds(), 2,
		"denied call must refresh the key TTL to windowSec*2")
}

// TestRedis_IncrementIfBelow_RetryAfterWhenCountExceedsLimit is a regression
// test: when the in-window count exceeds the limit (the situation a manifest
// reload that lowers maxCalls.count creates while earlier, more permissive calls
// are still in the window), the retryAfter hint must point at the entry whose
// expiry first drops the count below the new limit — the one at rank count-limit
// — not the very oldest entry at rank 0. Rank 0 expires sooner, so the old
// script underestimated the wait and a well-behaved client would retry early only
// to be denied again.
func TestRedis_IncrementIfBelow_RetryAfterWhenCountExceedsLimit(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	base := time.Unix(1_700_000_000, 0)
	now := base
	counter := callcounter.NewRedis(client, callcounter.WithRedisTimeFunc(func() time.Time { return now }))
	ctx := context.Background()

	const (
		key       = "maxcalls:s:tool"
		windowSec = 60
		highLimit = 10 // the original, permissive limit
	)

	// Admit six calls spaced 10s apart under the permissive limit. The sorted set
	// then holds entries at T=0,10,20,30,40,50 — all inside the 60s window.
	for i := 0; i < 6; i++ {
		now = base.Add(time.Duration(i*10) * time.Second)
		_, admitted, _, err := counter.IncrementIfBelow(ctx, key, windowSec, highLimit)
		require.NoError(t, err)
		require.True(t, admitted, "call %d under the permissive limit must be admitted", i)
	}

	// A reload lowers the limit to 3 while all six earlier calls are still in the
	// window: count (6) now exceeds limit (3), so the call is denied and adds no
	// member. The retryAfter must track the entry at rank count-limit = 6-3 = 3
	// (the T=30 entry), whose expiry one window later (T=90) first brings the count
	// below 3 — 35s from the T=55 evaluation. The rank-0 bug would have reported
	// the T=0 entry's expiry at T=60, i.e. only 5s: far too soon.
	now = base.Add(55 * time.Second)
	count, admitted, retry, err := counter.IncrementIfBelow(ctx, key, windowSec, 3)
	require.NoError(t, err)
	assert.False(t, admitted, "count 6 over limit 3 must be denied")
	assert.Equal(t, int64(6), count, "a denied call must not add a member")
	assert.Equal(t, 35*time.Second, retry,
		"retryAfter must track the rank count-limit entry (T=30), not the oldest (T=0)")
}

// TestRedis_ScoreEncoding_ConsistentAcrossMethods pins the score-encoding
// invariant: IncrementAndGet, IncrementIfBelow, and Peek all encode sorted-set
// scores as integer microseconds, so entries written via one method are seen by
// the others on the same key and window. Composing IncrementAndGet (which once
// used float-formatted scores) with IncrementIfBelow (integer scores) on one key
// must count both entries, and a read-only Peek must agree with both. This guards
// against a future precision divergence reintroducing the asymmetry.
func TestRedis_ScoreEncoding_ConsistentAcrossMethods(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	now := time.Unix(1_700_000_000, 0)
	counter := callcounter.NewRedis(client, callcounter.WithRedisTimeFunc(func() time.Time { return now }))
	ctx := context.Background()

	const (
		key       = "shared"
		windowSec = 60
	)

	n, err := counter.IncrementAndGet(ctx, key, windowSec, noTrimCap)
	require.NoError(t, err)
	require.Equal(t, int64(1), n)

	count, admitted, _, err := counter.IncrementIfBelow(ctx, key, windowSec, 5)
	require.NoError(t, err)
	require.True(t, admitted)
	assert.Equal(t, int64(2), count,
		"IncrementIfBelow must see the IncrementAndGet entry under a uniform score encoding")

	got, err := counter.Peek(ctx, key, windowSec)
	require.NoError(t, err)
	assert.Equal(t, int64(2), got, "Peek must agree with both writers on the same key")
}

// TestRedis_IncrementAndGet_ConnectionLoss_ReturnsError verifies that when the
// Redis backend becomes unreachable, IncrementAndGet surfaces the error rather
// than silently reporting a zero/low count. The enforcement engine relies on
// this: the maxCalls handler treats a counter error as a CONDITION_FAILED denial
// (fail-closed), so a swallowed error here would silently disable rate limits.
func TestRedis_IncrementAndGet_ConnectionLoss_ReturnsError(t *testing.T) {
	mr := miniredis.NewMiniRedis()
	require.NoError(t, mr.Start())
	client := redis.NewClient(&redis.Options{
		Addr:        mr.Addr(),
		PoolSize:    1,
		DialTimeout: 100 * time.Millisecond,
	})
	t.Cleanup(func() { _ = client.Close() })

	counter := callcounter.NewRedis(client)

	// Simulate Redis becoming unreachable mid-operation.
	mr.Close()

	_, err := counter.IncrementAndGet(context.Background(), "key1", 60, noTrimCap)
	require.Error(t, err, "IncrementAndGet must surface a Redis connection error so the engine can fail closed")
}

// TestRedis_IncrementAndGet_WrongType_ReturnsError guards the fail-closed
// behaviour when a per-command error fires inside the MULTI/EXEC block — here
// WRONGTYPE, because a non-sorted-set value collides with windowKey. The ZCard
// command's Val() is then 0, and returning (0, nil) would silently report zero
// in-window calls and fail open. IncrementAndGet must instead return an error so
// the enforcement count fails closed. (go-redis surfaces this via both the
// top-level Exec error and countCmd.Err(); the explicit per-command check in
// IncrementAndGet is defence in depth so the guarantee does not rely on Exec
// scanning every queued command.)
func TestRedis_IncrementAndGet_WrongType_ReturnsError(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	// Plant a string at the exact key IncrementAndGet computes
	// ("callcounter:<key>:<windowSec>"), so the ZCard inside EXEC hits WRONGTYPE.
	require.NoError(t, mr.Set("callcounter:key1:60", "not-a-sorted-set"))

	counter := callcounter.NewRedis(client)
	_, err := counter.IncrementAndGet(context.Background(), "key1", 60, noTrimCap)
	require.Error(t, err, "IncrementAndGet must surface a per-command (WRONGTYPE) error so the engine fails closed instead of reading a zero count")
}

// TestRedis_Peek_ConnectionLoss_ReturnsError verifies Peek (used by the
// sequenceBlock condition) also fails loudly when Redis is down. A swallowed
// error would make sequenceBlock under-report prior calls and fail open.
func TestRedis_Peek_ConnectionLoss_ReturnsError(t *testing.T) {
	mr := miniredis.NewMiniRedis()
	require.NoError(t, mr.Start())
	client := redis.NewClient(&redis.Options{
		Addr:        mr.Addr(),
		PoolSize:    1,
		DialTimeout: 100 * time.Millisecond,
	})
	t.Cleanup(func() { _ = client.Close() })

	counter := callcounter.NewRedis(client)
	mr.Close()

	_, err := counter.Peek(context.Background(), "key1", 60)
	require.Error(t, err, "Peek must surface a Redis connection error so callers can fail closed")
}

// TestRedis_MultiInstance_SharedCount verifies the documented multi-instance
// guarantee: two eunox processes (modeled here as two independent clients
// and counter instances) pointed at the same Redis see a single shared count.
// This is the property that makes a maxCalls quota enforceable across a
// horizontally-scaled deployment rather than per-process.
func TestRedis_MultiInstance_SharedCount(t *testing.T) {
	mr := miniredis.RunT(t)

	clientA := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	clientB := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() {
		_ = clientA.Close()
		_ = clientB.Close()
	})

	instanceA := callcounter.NewRedis(clientA)
	instanceB := callcounter.NewRedis(clientB)
	ctx := context.Background()

	n, err := instanceA.IncrementAndGet(ctx, "shared", 60, noTrimCap)
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)

	// The second instance must observe the first instance's increment.
	n, err = instanceB.IncrementAndGet(ctx, "shared", 60, noTrimCap)
	require.NoError(t, err)
	assert.Equal(t, int64(2), n, "a second instance must see the first instance's increment (shared backend)")

	// A read-only Peek from either instance reports the combined total.
	n, err = instanceA.Peek(ctx, "shared", 60)
	require.NoError(t, err)
	assert.Equal(t, int64(2), n, "Peek from instance A must see instance B's increment")
}

// TestRedis_MultiInstance_SameTick_NoCollision regression-tests the cross-replica
// member-collision bug: two Redis counter instances pointed at the same backend,
// each with its own per-process seq counter starting at zero, used to emit
// identical ZADD members ("<UnixNano>-<seq>") when their nanosecond clock and
// seq both lined up — and ZADD updates the score instead of inserting on a
// duplicate member, so ZCARD stalled and the maxCalls quota leaked.
//
// We pin both instances to the same constant clock so every member shares the
// same UnixNano segment, then concurrently issue 2N increments from both plus a
// final authoritative read, which must return 2N+1: every call distinct. Before
// the fix it came up short by exactly the number of seq-collision pairs.
func TestRedis_MultiInstance_SameTick_NoCollision(t *testing.T) {
	mr := miniredis.RunT(t)
	clientA := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	clientB := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() {
		_ = clientA.Close()
		_ = clientB.Close()
	})

	pinned := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return pinned }

	instanceA := callcounter.NewRedis(clientA, callcounter.WithRedisTimeFunc(clock))
	instanceB := callcounter.NewRedis(clientB, callcounter.WithRedisTimeFunc(clock))
	ctx := context.Background()

	const n = 50
	var wg sync.WaitGroup
	wg.Add(2 * n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_, err := instanceA.IncrementAndGet(ctx, "shared", 60, noTrimCap)
			assert.NoError(t, err)
		}()
		go func() {
			defer wg.Done()
			_, err := instanceB.IncrementAndGet(ctx, "shared", 60, noTrimCap)
			assert.NoError(t, err)
		}()
	}
	wg.Wait()

	// One more call from either instance returns the authoritative total.
	count, err := instanceA.IncrementAndGet(ctx, "shared", 60, noTrimCap)
	require.NoError(t, err)
	assert.Equal(t, int64(2*n+1), count,
		"every increment across instances must be counted; cross-replica members must be unique even at the same UnixNano tick")
}

// TestParseIncrIfBelowReply is a regression test: the IncrementIfBelow reply
// decoder must fail closed with a structured error on any element whose type is
// not the int64 the Lua script promises, rather than silently defaulting to the
// zero value. A zero retryMicros would otherwise be masked by the maxCalls handler's
// full-window fallback, leaving the type mismatch undetected.
func TestParseIncrIfBelowReply(t *testing.T) {
	tests := []struct {
		name         string
		res          interface{}
		wantErr      bool
		wantCount    int64
		wantAdmitted bool
		wantRetry    time.Duration
	}{
		{
			name:         "admitted",
			res:          []interface{}{int64(1), int64(5), int64(0)},
			wantCount:    5,
			wantAdmitted: true,
			wantRetry:    0,
		},
		{
			name:         "denied with retry",
			res:          []interface{}{int64(0), int64(10), int64(2_000_000)},
			wantCount:    10,
			wantAdmitted: false,
			wantRetry:    2 * time.Second,
		},
		{
			name:    "not an array",
			res:     int64(1),
			wantErr: true,
		},
		{
			name:    "wrong length",
			res:     []interface{}{int64(1), int64(5)},
			wantErr: true,
		},
		{
			name:    "admitted wrong type",
			res:     []interface{}{"1", int64(5), int64(0)},
			wantErr: true,
		},
		{
			name:    "count wrong type",
			res:     []interface{}{int64(1), "5", int64(0)},
			wantErr: true,
		},
		{
			name:    "retryMicros wrong type (bulk string)",
			res:     []interface{}{int64(0), int64(10), "2000000"},
			wantErr: true,
		},
		{
			name:    "retryMicros wrong type (float)",
			res:     []interface{}{int64(0), int64(10), float64(2_000_000)},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			count, admitted, retry, err := callcounter.ParseIncrIfBelowReply(tc.res)
			if tc.wantErr {
				require.Error(t, err)
				// Fail closed: a decode error must not report an admission.
				assert.False(t, admitted, "a decode error must never read as admitted")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantCount, count)
			assert.Equal(t, tc.wantAdmitted, admitted)
			assert.Equal(t, tc.wantRetry, retry)
		})
	}
}

// TestBackendParity_SubMicrosecondWindowBoundary is a regression test: a call
// recorded 500ns inside the window sits exactly on the microsecond boundary at
// peek time. InMemory previously counted it in-window at nanosecond precision
// while Redis (UnixMicro scores) treated it as expired, so the two backends
// disagreed. After flooring InMemory timestamps to microseconds they agree.
func TestBackendParity_SubMicrosecondWindowBoundary(t *testing.T) {
	const windowSec = 60
	base := time.Unix(1_000_000, 0).UTC() // microsecond-aligned instant
	recordAt := base.Add(-time.Duration(windowSec)*time.Second + 500*time.Nanosecond)

	var cur time.Time
	clock := func() time.Time { return cur }

	inmem := callcounter.NewInMemory(callcounter.WithTimeFunc(clock))

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	rds := callcounter.NewRedis(client, callcounter.WithRedisTimeFunc(clock))

	ctx := context.Background()

	// Record the boundary-straddling call on both backends.
	cur = recordAt
	_, err := inmem.IncrementAndGet(ctx, "k", windowSec, 10)
	require.NoError(t, err)
	_, err = rds.IncrementAndGet(ctx, "k", windowSec, 10)
	require.NoError(t, err)

	// Observe at the exact boundary instant.
	cur = base
	memCount, err := inmem.Peek(ctx, "k", windowSec)
	require.NoError(t, err)
	redCount, err := rds.Peek(ctx, "k", windowSec)
	require.NoError(t, err)

	assert.Equal(t, redCount, memCount,
		"InMemory and Redis must agree at the sub-microsecond window boundary")
	assert.Equal(t, int64(0), memCount,
		"a boundary call floored to microseconds is treated as expired by both backends")
}

// TestRedis_IncrementAndGet_CapKeepsNewestAcrossDigitBoundary is a regression
// test: when same-nanosecond entries share a sorted-set score, the rank-trim
// keeps the lexicographically-largest member, so the seq suffix must be
// zero-padded or a digit-boundary tie (seq 9 vs 10) ranks the newer member lower
// and discards it. All calls below share a fixed clock (one score bucket); with
// maxEntries=1 the cap must retain the highest seq (10, the newest), not seq 9.
func TestRedis_IncrementAndGet_CapKeepsNewestAcrossDigitBoundary(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	fixed := time.Date(2026, 6, 15, 7, 10, 0, 123456789, time.UTC)
	counter := callcounter.NewRedis(client, callcounter.WithRedisTimeFunc(func() time.Time { return fixed }))
	ctx := context.Background()

	const (
		windowSec  = 86400
		maxEntries = 1
		key        = "seq:s:tool"
	)

	// 10 calls at the same nanosecond → seq runs 1..10 within one score bucket.
	for i := 0; i < 10; i++ {
		_, err := counter.IncrementAndGet(ctx, key, windowSec, maxEntries)
		require.NoError(t, err)
	}

	windowKey := "callcounter:" + key + ":" + strconv.Itoa(windowSec)
	members, err := client.ZRange(ctx, windowKey, 0, -1).Result()
	require.NoError(t, err)
	require.Len(t, members, maxEntries, "set must be trimmed to maxEntries")

	// The member format is "<instanceID>-<paddedNano>-<paddedSeq>". The retained
	// member must carry the newest seq (10), proving the cap did not discard the
	// just-added entry at the 9->10 digit boundary.
	parts := strings.Split(members[0], "-")
	require.Len(t, parts, 3, "member must be instanceID-nano-seq")
	seq, err := strconv.Atoi(parts[2])
	require.NoError(t, err)
	assert.Equal(t, 10, seq, "the newest member (seq 10) must be retained, not seq 9")
}

// TestRedis_AdmitAll_AllOrNothing is the Redis half of the atomic
// multi-bucket admission check: every bucket records only when all have headroom,
// and a full bucket blocks the batch and records nothing (the script runs the
// check and the all-or-nothing commit in one atomic EVAL).
func TestRedis_AdmitAll_AllOrNothing(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer func() { _ = client.Close() }()
	counter := callcounter.NewRedis(client)
	ctx := context.Background()

	buckets := []capability.QuotaBucket{
		countedBucket("ka", 3600, 10),
		countedBucket("kb", 86400, 1),
	}

	admitted, _, _, _, err := counter.AdmitAll(ctx, buckets)
	require.NoError(t, err)
	require.True(t, admitted, "first call has headroom in every bucket")

	admitted, deniedIndex, total, retry, err := counter.AdmitAll(ctx, buckets)
	require.NoError(t, err)
	assert.False(t, admitted, "a full bucket must block the whole batch")
	assert.Equal(t, 1, deniedIndex, "the daily bucket (index 1) is the blocker")
	assert.Equal(t, float64(1), total)
	assert.Greater(t, retry, time.Duration(0))

	// The sibling (hourly) bucket must not have been charged for the denied batch.
	probe, ok, _, err := counter.IncrementIfBelow(ctx, "ka", 3600, 100)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, int64(2), probe, "the denied batch must not have charged the sibling bucket")
}

// TestRedis_AdmitAll_MixedAccounting is the Redis half of the mixed-accounting batch:
// one EVAL must apply entry-counting to the counted buckets and weight-summing to the
// weighted ones, commit both or neither, and report the blocking bucket's own total in
// its own accounting. This is the shape a capability carrying maxCalls AND a cumulative
// blastRadius produces, so the two backends have to agree on it exactly.
func TestRedis_AdmitAll_MixedAccounting(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer func() { _ = client.Close() }()
	counter := callcounter.NewRedis(client)
	ctx := context.Background()

	mixed := func(weight float64) []capability.QuotaBucket {
		return []capability.QuotaBucket{
			countedBucket("calls", 3600, 5),
			weightedBucket("spend", 3600, weight, 100),
		}
	}

	for i := 0; i < 2; i++ {
		admitted, _, _, _, err := counter.AdmitAll(ctx, mixed(40))
		require.NoError(t, err)
		require.True(t, admitted, "call %d is inside both bounds", i)
	}

	admitted, deniedIndex, total, _, err := counter.AdmitAll(ctx, mixed(40))
	require.NoError(t, err)
	assert.False(t, admitted, "the weighted bound must block while the counted one still has headroom")
	assert.Equal(t, 1, deniedIndex, "the weighted bucket (index 1) is the blocker")
	assert.Equal(t, float64(80), total, "the reported total is the weighted bucket's in-window sum")

	probe, ok, _, err := counter.IncrementIfBelow(ctx, "calls", 3600, 100)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, int64(3), probe, "a weighted denial must not charge the counted sibling")

	// And the mirror: when the counted bound is the blocker, the weighted sibling is
	// left alone. "calls" now holds 3 of a fresh limit of 3.
	admitted, deniedIndex, total, _, err = counter.AdmitAll(ctx, []capability.QuotaBucket{
		countedBucket("calls", 3600, 3),
		weightedBucket("spend", 3600, 1, 1000),
	})
	require.NoError(t, err)
	assert.False(t, admitted, "the spent call budget blocks the batch")
	assert.Equal(t, 0, deniedIndex, "the counted bucket (index 0) is the blocker")
	assert.Equal(t, float64(3), total, "the reported total is the counted bucket's entry count")

	_, _, spend, _, err := counter.AdmitAll(ctx, []capability.QuotaBucket{weightedBucket("spend", 3600, 1, 1000)})
	require.NoError(t, err)
	assert.Equal(t, float64(81), spend, "a counted denial must not charge the weighted sibling")
}

// TestAdmitAll_DuplicateBucketsFailClosed_BothBackends is the cross-backend
// regression for the duplicate-(key, windowSec) fail-open: a batch with two buckets
// resolving to one storage key must return a structured error and record NOTHING on
// BOTH backends, so InMemory cannot silently under-count where Redis would
// double-count. The engine never produces such a batch; this guards a direct consumer
// against the unsupported input and keeps the two backends equivalent.
func TestAdmitAll_DuplicateBucketsFailClosed_BothBackends(t *testing.T) {
	ctx := context.Background()
	// A counted and a weighted bucket on ONE storage key is the dangerous shape: the two
	// accountings disagree about what the key holds, so it must be refused rather than
	// resolved to whichever the backend happens to apply.
	dup := []capability.QuotaBucket{
		countedBucket("k", 60, 5),
		weightedBucket("k", 60, 1, 5),
	}

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer func() { _ = client.Close() }()

	for _, tc := range []struct {
		name    string
		counter capability.CallCounter
	}{
		{"memory", callcounter.NewInMemory()},
		{"redis", callcounter.NewRedis(client)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			admitted, _, _, _, err := tc.counter.AdmitAll(ctx, dup)
			require.Error(t, err, "duplicate (key, windowSec) buckets must fail closed")
			assert.False(t, admitted, "nothing is admitted on the error path")
			assert.Contains(t, err.Error(), "duplicate")
			// Nothing was recorded: a fresh single-bucket probe of the same key sees count 1.
			count, ok, _, perr := tc.counter.IncrementIfBelow(ctx, "k", 60, 100)
			require.NoError(t, perr)
			require.True(t, ok)
			assert.Equal(t, int64(1), count, "the rejected batch must not have recorded any call")
		})
	}
}

// TestRedis_AdmitAll_AdmittedReturnsTotal pins the capability.CallCounter
// contract that the admitted path reports the post-admission in-window total (the
// maximum across buckets), not a hardcoded 0.
func TestRedis_AdmitAll_AdmittedReturnsTotal(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer func() { _ = client.Close() }()
	counter := callcounter.NewRedis(client)
	ctx := context.Background()

	buckets := []capability.QuotaBucket{
		countedBucket("ka", 3600, 10),
		countedBucket("kb", 86400, 10),
	}

	admitted, _, total, _, err := counter.AdmitAll(ctx, buckets)
	require.NoError(t, err)
	require.True(t, admitted)
	assert.Equal(t, float64(1), total, "first admit: every bucket holds exactly one call")

	admitted, _, total, _, err = counter.AdmitAll(ctx, buckets)
	require.NoError(t, err)
	require.True(t, admitted)
	assert.Equal(t, float64(2), total, "second admit: post-admission total is 2, not 0")
}

// TestRedis_AdmitAll_ValidatesInputs pins the fail-closed argument
// checks before the Redis call.
func TestRedis_AdmitAll_ValidatesInputs(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer func() { _ = client.Close() }()
	counter := callcounter.NewRedis(client)
	ctx := context.Background()

	_, _, _, _, err := counter.AdmitAll(ctx, nil)
	assert.Error(t, err, "an empty batch must error")
	_, _, _, _, err = counter.AdmitAll(ctx, []capability.QuotaBucket{countedBucket("a", 0, 1)})
	assert.Error(t, err, "an out-of-range window must error")
	_, _, _, _, err = counter.AdmitAll(ctx, []capability.QuotaBucket{countedBucket("a", 60, 0)})
	assert.Error(t, err, "a non-positive limit must error")
	_, _, _, _, err = counter.AdmitAll(ctx, []capability.QuotaBucket{weightedBucket("a", 60, math.Inf(1), 10)})
	assert.Error(t, err, "a non-finite weight must error")
}
