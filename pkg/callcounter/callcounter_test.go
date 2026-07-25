// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package callcounter_test

import (
	"context"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Both built-in backends must satisfy the single mandatory call-counter contract,
// capability.CallCounter (IncrementAndGet/Peek/IncrementIfBelow/IncrementIfAllBelow):
// Peek backs sequenceBlock and IncrementIfBelow/IncrementIfAllBelow back maxCalls.
// Pinning it proves in a single assertion that each backend carries every method
// any built-in condition can require — a built-in backend that dropped one becomes
// a build failure here instead of an opaque runtime deny, and each line documents
// the one-assertion pattern a third-party backend uses to guard itself.
var (
	_ capability.CallCounter = (*callcounter.InMemory)(nil)
	_ capability.CallCounter = (*callcounter.Redis)(nil)
)

// noTrimCap is an IncrementAndGet retention cap set well above any call count
// these tests reach, so the most-recent-N trimming never engages and assertions
// about the raw sliding-window count hold unchanged. The cap itself is exercised
// by the TestInMemory_IncrementAndGet_CapsTo* / Redis equivalents.
const noTrimCap = 1 << 20

func TestInMemory_Peek_DoesNotMutate(t *testing.T) {
	counter := callcounter.NewInMemory()
	ctx := context.Background()

	// Unknown key reads as zero without creating an entry.
	n, err := counter.Peek(ctx, "missing", 60)
	require.NoError(t, err)
	assert.Equal(t, int64(0), n)

	// Record two calls.
	_, err = counter.IncrementAndGet(ctx, "k", 60, noTrimCap)
	require.NoError(t, err)
	_, err = counter.IncrementAndGet(ctx, "k", 60, noTrimCap)
	require.NoError(t, err)

	// Peeking repeatedly must always report 2 — it never counts as a call.
	for i := 0; i < 3; i++ {
		n, err = counter.Peek(ctx, "k", 60)
		require.NoError(t, err)
		assert.Equal(t, int64(2), n, "Peek must not increment the counter")
	}

	// A subsequent IncrementAndGet still sees exactly the two prior calls plus
	// its own, confirming Peek added nothing.
	n, err = counter.IncrementAndGet(ctx, "k", 60, noTrimCap)
	require.NoError(t, err)
	assert.Equal(t, int64(3), n)
}

// TestInMemory_Peek_RespectsWindow verifies Peek counts only timestamps inside
// its window, and that — like the Redis backend — it consults the entry
// namespaced by the window it is given. A call is read back by a Peek using the
// same window it was recorded under (the contract the engine always honours:
// sequenceHistoryWindowSec for both record and read); a Peek using a *different*
// window addresses a different bucket and reads zero, matching Redis's per-window
// "callcounter:<key>:<windowSec>" sorted sets.
func TestInMemory_Peek_RespectsWindow(t *testing.T) {
	clk := &fakeNow{t: time.Unix(1_000_000, 0)}
	counter := callcounter.NewInMemory(callcounter.WithTimeFunc(clk.now))
	ctx := context.Background()

	// Record under the 60s window — the same window the in-window Peeks below use.
	_, err := counter.IncrementAndGet(ctx, "k", 60, noTrimCap)
	require.NoError(t, err)

	// Within the window, peeked at the recording window: visible.
	n, err := counter.Peek(ctx, "k", 60)
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)

	// A Peek at a different window consults a different bucket (matching Redis),
	// so it does not observe the 60s-window call. The engine never mixes windows
	// on one key, so this divergence cannot arise in production.
	n, err = counter.Peek(ctx, "k", 3600)
	require.NoError(t, err)
	assert.Equal(t, int64(0), n, "a Peek at a different window addresses a different bucket")

	// Advance past the 60s window: the marker falls outside and Peek reports zero,
	// without disturbing the stored timestamp.
	clk.t = clk.t.Add(120 * time.Second)
	n, err = counter.Peek(ctx, "k", 60)
	require.NoError(t, err)
	assert.Equal(t, int64(0), n)
}

type fakeNow struct{ t time.Time }

func (f *fakeNow) now() time.Time { return f.t }

// TestInMemory_Peek_ConcurrentReadersAndWriter exercises the RLock path: many
// goroutines call Peek on a single key in parallel while a writer concurrently
// mutates the same counter. Under `go test -race` this is what actually observes
// the read-lock/write-lock interaction — the other Peek tests are
// single-goroutine and sequential, so the detector never sees two goroutines
// touch the same counter and cannot exercise the RLock path.
//
// The fake clock must be goroutine-safe: concurrent Peek calls now invoke
// m.now() in parallel, so an unsynchronized clock (like the bare fakeNow above)
// would itself trip -race. This mirrors the mutex-protected timeFunc in
// TestInMemory_StartCleanup_RemovesStaleEntries.
func TestInMemory_Peek_ConcurrentReadersAndWriter(t *testing.T) {
	t.Parallel()

	var clkMu sync.Mutex
	current := time.Unix(1_000_000, 0)
	timeFunc := func() time.Time {
		clkMu.Lock()
		defer clkMu.Unlock()
		return current
	}

	counter := callcounter.NewInMemory(callcounter.WithTimeFunc(timeFunc))
	ctx := context.Background()

	// Seed the key so every Peek reads a non-empty timestamp slice. The clock
	// never advances and the window is wide, so nothing ever expires: the
	// in-window count only grows, so it never drops below the seeded 1.
	_, err := counter.IncrementAndGet(ctx, "k", 3600, noTrimCap)
	require.NoError(t, err)

	const readers = 64
	const iterations = 500
	var wg sync.WaitGroup

	// Writer: keep mutating the same counter under the exclusive Lock so the
	// RLock readers genuinely overlap a writer. assert (not require) is used in
	// the goroutines because require's FailNow must run on the test goroutine.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_, werr := counter.IncrementAndGet(ctx, "k", 3600, noTrimCap)
			assert.NoError(t, werr)
		}
	}()

	// Readers: fan out parallel Peeks on the same key. The exact count races with
	// the writer, so we assert only the interleaving-invariant lower bound.
	for r := 0; r < readers; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				n, perr := counter.Peek(ctx, "k", 3600)
				assert.NoError(t, perr)
				assert.GreaterOrEqual(t, n, int64(1), "seeded key never drops below one in-window call")
			}
		}()
	}

	wg.Wait()
}

// BenchmarkInMemory_Peek measures the parallel Peek path targeted by the RLock
// change. b.RunParallel fans Peek across GOMAXPROCS goroutines on a shared
// counter, so the read-lock win — concurrent readers proceeding without
// serializing — shows up here, and the benchmark guards against a future
// regression back to the exclusive Lock. The key is seeded so the critical
// section does real work (iterating the slice) rather than a bare map miss.
func BenchmarkInMemory_Peek(b *testing.B) {
	counter := callcounter.NewInMemory()
	ctx := context.Background()

	for i := 0; i < 8; i++ {
		if _, err := counter.IncrementAndGet(ctx, "k", 3600, noTrimCap); err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := counter.Peek(ctx, "k", 3600); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func TestInMemory_IncrementAndGet(t *testing.T) {
	counter := callcounter.NewInMemory()
	ctx := context.Background()

	count, err := counter.IncrementAndGet(ctx, "key1", 60, noTrimCap)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	count, err = counter.IncrementAndGet(ctx, "key1", 60, noTrimCap)
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)

	count, err = counter.IncrementAndGet(ctx, "key1", 60, noTrimCap)
	require.NoError(t, err)
	assert.Equal(t, int64(3), count)
}

// TestInMemory_RejectsOutOfRangeWindow is a regression test: a windowSec large
// enough to overflow time.Duration(windowSec)*…*time.Second must be rejected
// (fail closed) rather than wrapping the cutoff and silently resetting the
// counter to 1 on every call — a fail-open quota bypass. A non-positive window
// is rejected for the same reason, and the maximum in-range window is still
// accepted.
func TestInMemory_RejectsOutOfRangeWindow(t *testing.T) {
	counter := callcounter.NewInMemory()
	ctx := context.Background()

	huge := int(callcounter.MaxWindowSeconds) + 1

	// Before the fix this returned (1, nil) twice in a row; now both the
	// increment and the read-only Peek fail closed.
	_, err := counter.IncrementAndGet(ctx, "huge", huge, noTrimCap)
	require.Error(t, err, "overflowing windowSec must fail closed")
	_, err = counter.Peek(ctx, "huge", huge)
	require.Error(t, err, "overflowing windowSec must fail closed on Peek too")

	// A non-positive window is also rejected.
	_, err = counter.IncrementAndGet(ctx, "zero", 0, noTrimCap)
	require.Error(t, err)

	// The largest in-range window is accepted and counts normally.
	n, err := counter.IncrementAndGet(ctx, "ok", int(callcounter.MaxWindowSeconds), noTrimCap)
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)
}

// TestInMemory_IncrementAndGet_RejectsNonPositiveMaxEntries verifies the
// retention cap is mandatory: a non-positive maxEntries fails closed rather than
// being treated as "unbounded", which would re-open the heap-growth sink.
func TestInMemory_IncrementAndGet_RejectsNonPositiveMaxEntries(t *testing.T) {
	counter := callcounter.NewInMemory()
	ctx := context.Background()

	for _, mx := range []int{0, -1} {
		_, err := counter.IncrementAndGet(ctx, "k", 60, mx)
		require.Error(t, err, "maxEntries %d must fail closed", mx)
	}
}

// TestInMemory_IncrementAndGet_RejectsOversizedMaxEntries verifies that
// checkMaxEntries (shared by both backends) must reject a maxEntries above
// MaxEntries so the Redis trim arithmetic can never overflow. The boundary value
// is accepted.
func TestInMemory_IncrementAndGet_RejectsOversizedMaxEntries(t *testing.T) {
	counter := callcounter.NewInMemory()
	ctx := context.Background()

	for _, mx := range oversizedMaxEntries() {
		_, err := counter.IncrementAndGet(ctx, "k", 60, mx)
		require.Error(t, err, "maxEntries %d must fail closed", mx)
	}

	_, err := counter.IncrementAndGet(ctx, "k", 60, callcounter.MaxEntries)
	require.NoError(t, err, "maxEntries == MaxEntries must be accepted")
}

// oversizedMaxEntries returns the maxEntries values that exceed callcounter.MaxEntries
// and are representable as int on the current platform. On 64-bit, both
// MaxEntries+1 and math.MaxInt qualify. On 32-bit, MaxEntries == math.MaxInt, so no
// int can exceed it and the slice is empty — there is nothing above the boundary to
// reject, and MaxEntries+1 would overflow to a negative. Callers should always also
// assert that the boundary value (MaxEntries) itself is accepted.
func oversizedMaxEntries() []int {
	if math.MaxInt <= callcounter.MaxEntries {
		return nil
	}
	return []int{callcounter.MaxEntries + 1, math.MaxInt}
}

func TestInMemory_SeparateKeys(t *testing.T) {
	counter := callcounter.NewInMemory()
	ctx := context.Background()

	count, err := counter.IncrementAndGet(ctx, "key1", 60, noTrimCap)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	count, err = counter.IncrementAndGet(ctx, "key2", 60, noTrimCap)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)
}

func TestInMemory_SlidingWindow(t *testing.T) {
	now := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	counter := callcounter.NewInMemory(callcounter.WithTimeFunc(func() time.Time { return now }))
	ctx := context.Background()

	// Make 3 calls at t=0
	for i := 0; i < 3; i++ {
		_, err := counter.IncrementAndGet(ctx, "key1", 60, noTrimCap)
		require.NoError(t, err)
	}

	// Advance time past the window using the same counter
	now = now.Add(61 * time.Second)

	count, err := counter.IncrementAndGet(ctx, "key1", 60, noTrimCap)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count) // Old entries expired
}

func TestInMemory_WindowExpiry(t *testing.T) {
	current := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	timeFunc := func() time.Time { return current }
	counter := callcounter.NewInMemory(callcounter.WithTimeFunc(timeFunc))
	ctx := context.Background()

	// Make some calls
	_, err := counter.IncrementAndGet(ctx, "key1", 10, noTrimCap)
	require.NoError(t, err)
	_, err = counter.IncrementAndGet(ctx, "key1", 10, noTrimCap)
	require.NoError(t, err)

	// Advance time past the window
	current = current.Add(11 * time.Second)

	// New call should only count itself (old ones expired)
	count, err := counter.IncrementAndGet(ctx, "key1", 10, noTrimCap)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)
}

func TestInMemory_Cleanup(t *testing.T) {
	counter := callcounter.NewInMemory()
	ctx := context.Background()

	_, err := counter.IncrementAndGet(ctx, "key1", 60, noTrimCap)
	require.NoError(t, err)

	// Cleanup shouldn't panic
	counter.Cleanup()
}

func TestInMemory_Cleanup_DeletesStaleEntry(t *testing.T) {
	current := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	counter := callcounter.NewInMemory(callcounter.WithTimeFunc(func() time.Time { return current }))
	ctx := context.Background()

	// Record a call at t=0.
	count, err := counter.IncrementAndGet(ctx, "stale-key", 60, noTrimCap)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	// Advance time by 25 hours so the entry is stale (>24h old).
	current = current.Add(25 * time.Hour)

	// Cleanup should delete the stale entry.
	counter.Cleanup()

	// Now IncrementAndGet must return 1 (fresh entry), not 2.
	count, err = counter.IncrementAndGet(ctx, "stale-key", 60, noTrimCap)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count, "stale entry must have been deleted by Cleanup")
}

// TestInMemory_StartCleanup_RemovesStaleEntries verifies that the background
// goroutine launched by StartCleanup calls Cleanup periodically and removes
// stale entries.  This is a regression test for the case where Cleanup was
// defined but never called in production, allowing unbounded heap growth.
func TestInMemory_StartCleanup_RemovesStaleEntries(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	current := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	timeFunc := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return current
	}
	advanceClock := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		current = current.Add(d)
	}

	counter := callcounter.NewInMemory(callcounter.WithTimeFunc(timeFunc))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start cleanup with a very short interval for the test.
	counter.StartCleanup(ctx, 10*time.Millisecond)

	// Record a call.
	count, err := counter.IncrementAndGet(context.Background(), "k", 60, noTrimCap)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	// Advance the fake clock past the 24-hour eviction threshold.
	advanceClock(25 * time.Hour)

	// Wait long enough for at least one cleanup tick to fire.
	time.Sleep(100 * time.Millisecond)

	// A new call must return 1 (old entry cleaned up).
	count, err = counter.IncrementAndGet(context.Background(), "k", 60, noTrimCap)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count, "regression: StartCleanup must evict stale entries")
}

// TestInMemory_StartCleanup_StopsOnContextCancel verifies that the cleanup
// goroutine exits when its context is canceled (no goroutine leak).
func TestInMemory_StartCleanup_StopsOnContextCancel(t *testing.T) {
	t.Parallel()
	counter := callcounter.NewInMemory()
	ctx, cancel := context.WithCancel(context.Background())

	// Canceling immediately; the goroutine must exit without blocking.
	counter.StartCleanup(ctx, 10*time.Millisecond)
	cancel()

	// Give the goroutine a moment to observe the cancellation.
	time.Sleep(50 * time.Millisecond)
	// No assertion needed — if the goroutine leaked it would show up in
	// go test -race / goroutine dump; the test passes cleanly otherwise.
}

// TestInMemory_StartCleanup_Idempotent verifies that StartCleanup launches at
// most one cleanup goroutine no matter how many times it is called: the first
// call reports true (it started the goroutine) and every later call reports
// false (a no-op). Previously each call unconditionally started another goroutine
// — doubling the per-tick cleanup cost and leaking a goroutine that no caller
// could stop independently. Because the goroutine is launched only inside the
// guarded sync.Once block, a false return proves no second goroutine was started.
func TestInMemory_StartCleanup_Idempotent(t *testing.T) {
	t.Parallel()
	counter := callcounter.NewInMemory()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	assert.True(t, counter.StartCleanup(ctx, 10*time.Millisecond),
		"the first StartCleanup must report that it started the cleanup goroutine")
	for i := 0; i < 5; i++ {
		assert.False(t, counter.StartCleanup(ctx, 10*time.Millisecond),
			"a repeat StartCleanup must be a no-op and report false (call %d)", i+2)
	}
}

// (The "first interval wins" contract is verified in cleanup_internal_test.go,
// which can assert on the internal entries map. It cannot be tested from this
// external package: IncrementAndGet self-prunes a key's own expired timestamps,
// so a post-prune count reads 1 whether or not Cleanup evicted the entry — only
// the entry's presence in the map distinguishes the fast from the slow interval.)

func TestInMemory_IncrementIfBelow_AdmitsUpToLimit(t *testing.T) {
	counter := callcounter.NewInMemory()
	ctx := context.Background()

	for i := 1; i <= 3; i++ {
		count, admitted, retry, err := counter.IncrementIfBelow(ctx, "k", 60, 3)
		require.NoError(t, err)
		assert.True(t, admitted, "call %d within the limit must be admitted", i)
		assert.Equal(t, int64(i), count)
		assert.Equal(t, time.Duration(0), retry, "admitted call has no retryAfter")
	}

	// The 4th call is over the limit: denied, the count stays at the limit (no
	// growth from the denied call), and a positive retryAfter is reported.
	count, admitted, retry, err := counter.IncrementIfBelow(ctx, "k", 60, 3)
	require.NoError(t, err)
	assert.False(t, admitted)
	assert.Equal(t, int64(3), count, "a denied call must not increment the counter")
	assert.Greater(t, retry, time.Duration(0), "a denied call should report a retryAfter hint")
}

func TestInMemory_IncrementIfBelow_RejectsOutOfRangeWindow(t *testing.T) {
	counter := callcounter.NewInMemory()
	ctx := context.Background()

	_, _, _, err := counter.IncrementIfBelow(ctx, "k", 0, 1)
	require.Error(t, err, "non-positive window must fail closed")

	_, _, _, err = counter.IncrementIfBelow(ctx, "k", int(callcounter.MaxWindowSeconds)+1, 1)
	require.Error(t, err, "overflowing window must fail closed")
}

// TestInMemory_IncrementIfBelow_RejectsNonPositiveLimit verifies that a limit<1
// is an unambiguously invalid argument (the "fewer than limit calls" contract is
// undefined for it), so it must fail closed with an explicit error instead of a
// silent admitted=false, err=nil denial that reads as an exhausted quota.
func TestInMemory_IncrementIfBelow_RejectsNonPositiveLimit(t *testing.T) {
	counter := callcounter.NewInMemory()
	ctx := context.Background()

	for _, limit := range []int64{0, -1} {
		_, admitted, _, err := counter.IncrementIfBelow(ctx, "k", 60, limit)
		require.Errorf(t, err, "limit=%d must fail closed with an error", limit)
		require.Falsef(t, admitted, "limit=%d must not admit", limit)
	}
}

// TestInMemory_IncrementIfBelow_DeniedCallsDoNotExtendLockout is a regression
// test: a client that keeps retrying after being rate-limited must not push its
// own recovery further out. Because denied calls add no timestamp, once the
// original in-window calls age out the limit clears even though the client never
// stopped retrying. With the pre-fix increment-on-deny, the denied retries would
// refill the window and the lockout would never lift.
func TestInMemory_IncrementIfBelow_DeniedCallsDoNotExtendLockout(t *testing.T) {
	clk := &fakeNow{t: time.Unix(1_000_000, 0)}
	counter := callcounter.NewInMemory(callcounter.WithTimeFunc(clk.now))
	ctx := context.Background()

	// Fill the window: 2 calls at T=0 with a limit of 2.
	for i := 0; i < 2; i++ {
		_, admitted, _, err := counter.IncrementIfBelow(ctx, "k", 60, 2)
		require.NoError(t, err)
		require.True(t, admitted)
	}

	// Hammer one request per second for the rest of the window. Every call is
	// over the limit, so it is denied and records nothing; the count holds at the
	// limit and the retryAfter hint counts down toward the original calls' expiry.
	for sec := 1; sec <= 59; sec++ {
		clk.t = clk.t.Add(time.Second)
		count, admitted, retry, err := counter.IncrementIfBelow(ctx, "k", 60, 2)
		require.NoError(t, err)
		assert.False(t, admitted, "second %d: over-limit call must be denied", sec)
		assert.Equal(t, int64(2), count, "second %d: denied retries must not grow the counter", sec)
		assert.Equal(t, time.Duration(60-sec)*time.Second, retry, "second %d: retryAfter should track the oldest call's expiry", sec)
	}

	// One tick past the original window: the two T=0 calls have aged out, so a
	// retry is admitted even though the client never paused.
	clk.t = clk.t.Add(2 * time.Second) // now T=61
	count, admitted, _, err := counter.IncrementIfBelow(ctx, "k", 60, 2)
	require.NoError(t, err)
	assert.True(t, admitted, "after the original window clears, a retry must be admitted")
	assert.Equal(t, int64(1), count)
}

// TestInMemory_IncrementIfBelow_RetryAfterWhenCountExceedsLimit is the InMemory
// half of the cross-backend agreement check: when the in-window count exceeds
// the limit (as it does after a manifest reload lowers maxCalls.count while
// earlier, more permissive calls are still in the window), the retryAfter hint
// must track the entry at rank count-limit, not the oldest. InMemory already
// does this (valid[cur-limit]); the Redis script is fixed to match. Both
// backends, given the identical scenario, must report the same 35s.
func TestInMemory_IncrementIfBelow_RetryAfterWhenCountExceedsLimit(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	clk := &fakeNow{t: base}
	counter := callcounter.NewInMemory(callcounter.WithTimeFunc(clk.now))
	ctx := context.Background()

	const (
		key       = "maxcalls:s:tool"
		windowSec = 60
	)

	// Admit six calls spaced 10s apart under a permissive limit of 10. The slice
	// then holds timestamps at T=0,10,20,30,40,50, all inside the 60s window.
	for i := 0; i < 6; i++ {
		clk.t = base.Add(time.Duration(i*10) * time.Second)
		_, admitted, _, err := counter.IncrementIfBelow(ctx, key, windowSec, 10)
		require.NoError(t, err)
		require.True(t, admitted, "call %d under the permissive limit must be admitted", i)
	}

	// Lower the limit to 3 mid-window: count (6) exceeds limit (3), so the call is
	// denied and records nothing. retryAfter must track valid[cur-limit] =
	// valid[3] (the T=30 entry), which frees a slot one window later at T=90 —
	// 35s from the T=55 evaluation — not the oldest T=0 entry (which would give 5s).
	clk.t = base.Add(55 * time.Second)
	count, admitted, retry, err := counter.IncrementIfBelow(ctx, key, windowSec, 3)
	require.NoError(t, err)
	assert.False(t, admitted, "count 6 over limit 3 must be denied")
	assert.Equal(t, int64(6), count, "a denied call must not grow the counter")
	assert.Equal(t, 35*time.Second, retry,
		"retryAfter must track the rank count-limit entry (T=30), not the oldest (T=0)")
}

// TestInMemory_IncrementIfBelow_CrossWindowPruneIsolated is a regression test:
// two maxCalls windows that share one logical key must not share one timestamp
// slice. The shorter window's prune (which fires the moment its window elapses)
// previously destroyed timestamps the longer window still counted, undercounting
// the longer window so its sustained-rate quota silently failed open. With each
// window namespaced into its own entry, the long window keeps its full history
// and the quota is enforced.
//
// Mirrors the scenario: a 5/min burst limit and a 10/hour sustained limit on the
// same key.
func TestInMemory_IncrementIfBelow_CrossWindowPruneIsolated(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)
	now := base
	counter := callcounter.NewInMemory(callcounter.WithTimeFunc(func() time.Time { return now }))
	ctx := context.Background()

	const (
		key      = "maxcalls:session-A:dangerous_export"
		shortWin = 60 // burst: 5 per minute
		shortLim = 5
		longWin  = 3600 // sustained: 10 per hour
		longLim  = 10
	)

	// Minute 1 (T=0): five calls, each checked against BOTH windows — as two
	// maxCalls conditions on one capability would be. All are admitted.
	for i := 0; i < 5; i++ {
		_, admitted, _, err := counter.IncrementIfBelow(ctx, key, shortWin, shortLim)
		require.NoError(t, err)
		require.True(t, admitted, "minute 1 call %d: short window must admit (under 5)", i)

		_, admitted, _, err = counter.IncrementIfBelow(ctx, key, longWin, longLim)
		require.NoError(t, err)
		require.True(t, admitted, "minute 1 call %d: long window must admit (under 10)", i)
	}

	// Minute 2 (T=61): the 60s window has fully aged out, so its prune runs; the
	// 3600s window has not. A 6th call is admitted by the short window (its slots
	// freed), but the long window must still see all five prior calls plus this
	// one — count 6, NOT the 1 the shared-slice bug reported after the short
	// window's prune wiped the history.
	now = base.Add(61 * time.Second)
	_, admitted, _, err := counter.IncrementIfBelow(ctx, key, shortWin, shortLim)
	require.NoError(t, err)
	require.True(t, admitted, "minute 2: short window must re-admit after its window cleared")

	count, admitted, _, err := counter.IncrementIfBelow(ctx, key, longWin, longLim)
	require.NoError(t, err)
	require.True(t, admitted, "minute 2: 6th call is still under the hourly limit of 10")
	assert.Equal(t, int64(6), count,
		"the short window's prune must not drop long-window history: want the long window to count all 6 calls")

	// Drive the hourly window to its limit to confirm the quota is enforced and
	// was not silently reset: calls 7..10 admit, the 11th is denied.
	for want := int64(7); want <= 10; want++ {
		count, admitted, _, err := counter.IncrementIfBelow(ctx, key, longWin, longLim)
		require.NoError(t, err)
		require.True(t, admitted, "hourly call to %d must admit", want)
		assert.Equal(t, want, count, "hourly count must climb monotonically")
	}
	_, admitted, _, err = counter.IncrementIfBelow(ctx, key, longWin, longLim)
	require.NoError(t, err)
	assert.False(t, admitted, "the 11th hourly call must be denied: the 10/hour quota must hold, not reset")
}

// TestStartCleanup_CanceledContextDoesNotBlockLaterStart is a regression test: a
// StartCleanup called with an already-canceled context must not start (or wedge) the
// cleanup lifecycle. Otherwise a goroutine would exit on its first select while the
// guard stayed claimed, permanently disabling cleanup, and StartCleanup would still
// return a misleading true.
func TestStartCleanup_CanceledContextDoesNotBlockLaterStart(t *testing.T) {
	t.Parallel()
	counter := callcounter.NewInMemory()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // context is already done

	// A dead context must not start cleanup, and must not claim the lifecycle: the
	// call truthfully reports "not started".
	require.False(t, counter.StartCleanup(ctx, time.Minute),
		"StartCleanup with a canceled context must return false")

	// The lifecycle is free, so a subsequent call with a live context can actually
	// start cleanup.
	require.True(t, counter.StartCleanup(context.Background(), time.Minute),
		"StartCleanup with a live context must start cleanup after a canceled attempt")

	// And it is genuinely idempotent thereafter.
	require.False(t, counter.StartCleanup(context.Background(), time.Minute),
		"a second live StartCleanup is the idempotent no-op")
}

// TestStartCleanup_RecoversAfterContextCancel verifies that once a winning cleanup
// goroutine's context is canceled, a later call with a live context restarts cleanup
// rather than leaving it permanently disabled. The lifecycle is mutex-guarded (no CAS
// re-check window): the restart waits out the canceled goroutine before re-arming, so
// the documented restart-after-cancel guarantee holds deterministically.
func TestStartCleanup_RecoversAfterContextCancel(t *testing.T) {
	t.Parallel()
	counter := callcounter.NewInMemory()

	ctx1, cancel1 := context.WithCancel(context.Background())
	require.True(t, counter.StartCleanup(ctx1, time.Minute),
		"first StartCleanup must start cleanup")
	cancel1()

	// A live call after the cancel must recover and restart cleanup, not report the
	// "already running" no-op that would leave the map growing unbounded forever.
	require.True(t, counter.StartCleanup(context.Background(), time.Minute),
		"a live call must restart cleanup after the prior context was canceled")

	// And it is genuinely idempotent thereafter.
	require.False(t, counter.StartCleanup(context.Background(), time.Minute),
		"a second live StartCleanup is the idempotent no-op")
}

// TestInMemory_IncrementIfAllBelow_AllOrNothing pins the atomic multi-bucket
// admission: when every bucket has headroom all are recorded, and when any bucket
// is full nothing is recorded and the blocking bucket is reported.
func TestInMemory_IncrementIfAllBelow_AllOrNothing(t *testing.T) {
	counter := callcounter.NewInMemory()
	ctx := context.Background()
	keys := []string{"ka", "kb"}
	windows := []int{3600, 86400}
	limits := []int64{10, 1} // hourly 10, daily 1; the daily bucket binds first.

	// First call: both buckets below limit → admitted, one slot recorded in each.
	admitted, _, _, _, err := counter.IncrementIfAllBelow(ctx, keys, windows, limits)
	require.NoError(t, err)
	require.True(t, admitted, "first call has headroom in every bucket")

	// Second call: the daily bucket (index 1) is now full → deny, record nothing.
	admitted, deniedIndex, count, retry, err := counter.IncrementIfAllBelow(ctx, keys, windows, limits)
	require.NoError(t, err)
	assert.False(t, admitted, "a full bucket must block the whole batch")
	assert.Equal(t, 1, deniedIndex, "the daily bucket (index 1) is the blocker")
	assert.Equal(t, int64(1), count, "reported count is the blocking bucket's in-window total")
	assert.Greater(t, retry, time.Duration(0), "a blocked batch reports a retry-after hint")

	// The hourly bucket (index 0) must NOT have been charged for the denied batch:
	// a probe that records one call must see count 2 (the one admitted call + this
	// probe), proving the denied batch left it at 1.
	probe, ok, _, err := counter.IncrementIfBelow(ctx, "ka", 3600, 100)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, int64(2), probe, "the denied batch must not have charged the sibling (hourly) bucket")
}

// TestInMemory_IncrementIfAllBelow_AdmittedReturnsCount pins the capability.CallCounter
// contract that the admitted path reports the post-admission in-window total (the
// maximum across buckets), not a hardcoded 0.
func TestInMemory_IncrementIfAllBelow_AdmittedReturnsCount(t *testing.T) {
	counter := callcounter.NewInMemory()
	ctx := context.Background()
	keys := []string{"ka", "kb"}
	windows := []int{3600, 86400}
	limits := []int64{10, 10}

	admitted, _, count, _, err := counter.IncrementIfAllBelow(ctx, keys, windows, limits)
	require.NoError(t, err)
	require.True(t, admitted)
	assert.Equal(t, int64(1), count, "first admit: every bucket holds exactly one call")

	admitted, _, count, _, err = counter.IncrementIfAllBelow(ctx, keys, windows, limits)
	require.NoError(t, err)
	require.True(t, admitted)
	assert.Equal(t, int64(2), count, "second admit: post-admission total is 2, not 0")
}

// TestInMemory_IncrementIfAllBelow_ValidatesInputs pins the fail-closed argument
// checks: mismatched slice lengths, an empty batch, and an out-of-range window or
// non-positive limit all error and record nothing.
func TestInMemory_IncrementIfAllBelow_ValidatesInputs(t *testing.T) {
	counter := callcounter.NewInMemory()
	ctx := context.Background()

	_, _, _, _, err := counter.IncrementIfAllBelow(ctx, []string{"a", "b"}, []int{60}, []int64{1, 1})
	assert.Error(t, err, "mismatched slice lengths must error")

	_, _, _, _, err = counter.IncrementIfAllBelow(ctx, nil, nil, nil)
	assert.Error(t, err, "an empty batch must error")

	_, _, _, _, err = counter.IncrementIfAllBelow(ctx, []string{"a"}, []int{0}, []int64{1})
	assert.Error(t, err, "an out-of-range window must error")

	_, _, _, _, err = counter.IncrementIfAllBelow(ctx, []string{"a"}, []int{60}, []int64{0})
	assert.Error(t, err, "a non-positive limit must error")

	// None of the rejected calls created a bucket: a fresh admit must report count 1.
	count, ok, _, err := counter.IncrementIfBelow(ctx, "a", 60, 5)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, int64(1), count, "a rejected validation must not create a phantom entry")
}

// TestInMemory_IncrementIfAllBelow_AtomicUnderConcurrency proves the multi-bucket
// admission is atomic: with two buckets of limit 1, exactly one of many concurrent
// callers is admitted — the over-admission the per-bucket check->commit path
// allowed cannot happen. Run with -race.
func TestInMemory_IncrementIfAllBelow_AtomicUnderConcurrency(t *testing.T) {
	counter := callcounter.NewInMemory()
	ctx := context.Background()
	keys := []string{"ka", "kb"}
	windows := []int{60, 3600}
	limits := []int64{1, 1}

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
			admitted, _, _, _, err := counter.IncrementIfAllBelow(ctx, keys, windows, limits)
			if err == nil && admitted {
				mu.Lock()
				admittedCnt++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()

	assert.Equal(t, 1, admittedCnt, "exactly one concurrent caller may be admitted against a limit of 1")
}

// TestInMemory_IncrementIfBelow_AtomicUnderConcurrency pins the single-bucket maxCalls
// admission bound under concurrency: N racing callers against a limit of L admit exactly
// L, never more — over-admission would be a maxCalls bypass. The sibling above covers the
// multi-bucket IncrementIfAllBelow; this covers the primary single-key maxCalls path. Run
// under -race to catch a torn read/write of the bucket counter.
func TestInMemory_IncrementIfBelow_AtomicUnderConcurrency(t *testing.T) {
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
			counter := callcounter.NewInMemory()
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
