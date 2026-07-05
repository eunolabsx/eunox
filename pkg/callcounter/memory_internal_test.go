// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package callcounter

import (
	"context"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestMaxWindowSeconds_BoundaryDoesNotOverflow pins the security bound to the
// cleanup/TTL margin it guards. MaxWindowSeconds is derived by dividing by
// cleanupMarginFactor, and both InMemory.Cleanup and the Redis Expire multiply a
// window by that same factor. This test fails if those ever drift — e.g. if the
// margin is widened without re-deriving the bound — which would silently re-open
// the overflow MaxWindowSeconds exists to close. The values are read into int64
// vars so the products evaluate at runtime (int64 wraparound) rather than as
// constant expressions, which would be a compile error on overflow.
func TestMaxWindowSeconds_BoundaryDoesNotOverflow(t *testing.T) {
	t.Parallel()

	// MaxWindowSeconds must be exactly representable as the int that windowSec is
	// passed as — the property the math.MaxInt cap guarantees on every platform.
	// Without the cap this round-trip would lose bits on a 32-bit build, making
	// the documented [1, MaxWindowSeconds] range unreachable and the out-of-range
	// tests below (which compute int(MaxWindowSeconds)+1) exercise the wrong path.
	if int64(int(MaxWindowSeconds)) != MaxWindowSeconds {
		t.Fatalf("MaxWindowSeconds %d is not representable as int on this platform", MaxWindowSeconds)
	}

	// At the boundary the doubled-margin product must stay positive (no wrap).
	maxWin := MaxWindowSeconds
	if got := time.Duration(maxWin) * cleanupMarginFactor * time.Second; got <= 0 {
		t.Fatalf("MaxWindowSeconds * %d * time.Second overflowed: got %d, want > 0", cleanupMarginFactor, got)
	}

	// The bound must be tight against whichever limit binds. The overflow bound is
	// the time.Duration margin; the int cap is the alternative. When the overflow
	// bound binds — its value fits in int, i.e. the 64-bit case — one second past
	// it must wrap the margin non-positive, proving the bound is the true maximum
	// and not a loose under-approximation. When the int cap binds instead (a
	// 32-bit platform, where math.MaxInt < the overflow bound), MaxWindowSeconds
	// is math.MaxInt and "+1" is not even representable; the representability
	// check above is the binding assertion there.
	overflowBound := int64(math.MaxInt64) / (cleanupMarginFactor * int64(time.Second))
	if MaxWindowSeconds == overflowBound {
		overWin := MaxWindowSeconds + 1
		if got := time.Duration(overWin) * cleanupMarginFactor * time.Second; got > 0 {
			t.Fatalf("MaxWindowSeconds is not tight: (max+1) * %d * time.Second = %d did not overflow", cleanupMarginFactor, got)
		}
	} else if MaxWindowSeconds != int64(math.MaxInt) {
		t.Fatalf("MaxWindowSeconds %d is below the overflow bound %d but is not the int cap math.MaxInt %d",
			MaxWindowSeconds, overflowBound, int64(math.MaxInt))
	}
}

// TestInMemory_Cleanup_EmptyTimestamps exercises the defensive branch in Cleanup
// that removes entries whose timestamp slice is empty.  This state cannot be
// produced via the public IncrementAndGet API (which always appends the current
// time), so we inject it directly through the internal entries map.
func TestInMemory_Cleanup_EmptyTimestamps(t *testing.T) {
	t.Parallel()
	m := NewInMemory()

	// Directly inject an entry with zero timestamps into the internal map.
	// This simulates a corrupt or zeroed-out entry that Cleanup must remove.
	m.mu.Lock()
	m.entries["ghost-key"] = &entry{timestamps: nil}
	m.mu.Unlock()

	// Cleanup must delete the entry without panicking.
	m.Cleanup()

	m.mu.Lock()
	_, stillPresent := m.entries["ghost-key"]
	m.mu.Unlock()

	if stillPresent {
		t.Error("Cleanup must remove entries with zero timestamps")
	}
}

// TestInMemory_Cleanup_StaleEntry verifies that Cleanup removes entries whose
// most-recent timestamp is more than 24 hours old.
func TestInMemory_Cleanup_StaleEntry(t *testing.T) {
	t.Parallel()
	now := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	m := NewInMemory(WithTimeFunc(func() time.Time { return now }))

	// Record a call at t=0.
	m.mu.Lock()
	m.entries["stale-key"] = &entry{
		timestamps: []time.Time{now.Add(-25 * time.Hour)},
	}
	m.mu.Unlock()

	// Advance the clock by 26 hours so the entry is > 24 h old.
	now = now.Add(26 * time.Hour)
	m.Cleanup()

	m.mu.Lock()
	_, stillPresent := m.entries["stale-key"]
	m.mu.Unlock()

	if stillPresent {
		t.Error("Cleanup must remove entries whose most-recent timestamp is > 24 h old")
	}
}

// TestInMemory_Cleanup_PreservesLongWindowQuota is a regression test for the
// fail-open rate-limit bypass: Cleanup's old fixed 24h staleness threshold
// dropped still-live counters for maxCalls windows longer than 24h, silently
// resetting the quota mid-window. After an idle gap that exceeds 24h but stays
// within the entry's own window, Cleanup must NOT drop the counter, so the
// sliding-window count keeps climbing instead of resetting to 1.
func TestInMemory_Cleanup_PreservesLongWindowQuota(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	now := base
	m := NewInMemory(WithTimeFunc(func() time.Time { return now }))

	ctx := context.Background()
	const windowSec = 2 * 24 * 60 * 60 // 48h window, e.g. "10 calls per 2 days"
	const key = "maxcalls:session-A:dangerous_tool"

	// Exhaust a quota of 10 at t=0.
	var count int64
	for i := 0; i < 10; i++ {
		count, _ = m.IncrementAndGet(ctx, key, windowSec, noTrimCap)
	}
	if count != 10 {
		t.Fatalf("after 10 calls, count = %d, want 10", count)
	}

	// Idle 25h: past the old 24h cleanup threshold but well inside the 48h window.
	now = base.Add(25 * time.Hour)
	m.Cleanup()

	// The 11th call within the window must still see the 10 prior calls, so the
	// quota of 10 is correctly exceeded (11 > 10) rather than reset to 1.
	count, _ = m.IncrementAndGet(ctx, key, windowSec, noTrimCap)
	if count != 11 {
		t.Fatalf("after Cleanup mid-window, count = %d, want 11 (quota must not reset)", count)
	}
}

// TestShouldDeleteEntry pins the staleness rule Cleanup keys off, independent of
// the two-phase locking that drives it. An entry is reclaimable when it holds no
// timestamps or its newest timestamp has aged past cleanupMarginFactor times its
// own window; entries with no recorded window fall back to a 24h floor.
func TestShouldDeleteEntry(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)

	const (
		shortWin = 3600          // 1h window  -> 2h margin
		longWin  = 2 * 24 * 3600 // 48h window -> 96h margin
	)

	tests := []struct {
		name string
		e    *entry
		want bool
	}{
		{"empty timestamps reclaimed", &entry{timestamps: nil}, true},
		{"recent within short window kept", &entry{timestamps: []time.Time{now.Add(-time.Minute)}, windowSec: shortWin}, false},
		{"short window within margin kept", &entry{timestamps: []time.Time{now.Add(-90 * time.Minute)}, windowSec: shortWin}, false},
		{"short window past margin reclaimed", &entry{timestamps: []time.Time{now.Add(-3 * time.Hour)}, windowSec: shortWin}, true},
		// Boundary: a newest timestamp exactly staleAfter (2*window) old is
		// reclaimed, matching Redis's at-or-after TTL eviction. One
		// nanosecond inside the boundary is still kept.
		{"short window exactly at margin reclaimed", &entry{timestamps: []time.Time{now.Add(-2 * time.Hour)}, windowSec: shortWin}, true},
		{"short window one ns inside margin kept", &entry{timestamps: []time.Time{now.Add(-2*time.Hour + time.Nanosecond)}, windowSec: shortWin}, false},
		{"long window idle past 24h but within margin kept", &entry{timestamps: []time.Time{now.Add(-25 * time.Hour)}, windowSec: longWin}, false},
		{"long window past margin reclaimed", &entry{timestamps: []time.Time{now.Add(-100 * time.Hour)}, windowSec: longWin}, true},
		{"no window recent kept (24h floor)", &entry{timestamps: []time.Time{now.Add(-23 * time.Hour)}}, false},
		{"no window stale reclaimed (24h floor)", &entry{timestamps: []time.Time{now.Add(-25 * time.Hour)}}, true},
		{"staleness keys off the most-recent timestamp", &entry{timestamps: []time.Time{now.Add(-100 * time.Hour), now.Add(-time.Minute)}, windowSec: shortWin}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := shouldDeleteEntry(tc.e, now); got != tc.want {
				t.Errorf("shouldDeleteEntry = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestInMemory_Cleanup_ConcurrentIncrementNotDropped is a race regression test:
// Cleanup's two-phase delete must never drop a counter that a concurrent
// IncrementAndGet has made live between the collect and delete phases. Each key
// is seeded stale so phase one collects it, then hammered with concurrent
// increments that race the deletes; the staleness re-check in phase two must
// spare every refreshed entry. Run under -race, this also asserts the two-phase
// locking introduces no data race.
func TestInMemory_Cleanup_ConcurrentIncrementNotDropped(t *testing.T) {
	// No t.Parallel(): this stress test wants the scheduler's full attention to
	// interleave Cleanup against the concurrent increments.
	now := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
	m := NewInMemory(WithTimeFunc(func() time.Time { return now }))
	ctx := context.Background()

	const (
		windowSec = 3600 // 1h window; staleAfter = 2h
		numKeys   = 200
		incPerKey = 50
	)

	keys := make([]string, numKeys)
	m.mu.Lock()
	for i := range keys {
		keys[i] = fmt.Sprintf("session-%d:tool", i)
		// Seed each key with a single timestamp 3h old — past the 2h margin — so
		// Cleanup's first phase collects every key as deletable. The concurrent
		// increments below then race to refresh each one before phase two deletes
		// it: exactly the window the staleness re-check exists to cover. The seed
		// goes under storageKey so it lands in the same window-namespaced entry the
		// IncrementAndGet/Peek calls below address.
		m.entries[storageKey(keys[i], windowSec)] = &entry{
			timestamps: []time.Time{now.Add(-3 * time.Hour)},
			windowSec:  windowSec,
		}
	}
	m.mu.Unlock()

	stop := make(chan struct{})
	var cleanupDone sync.WaitGroup
	cleanupDone.Add(1)
	go func() {
		defer cleanupDone.Done()
		for {
			m.Cleanup()
			select {
			case <-stop:
				return
			default:
			}
		}
	}()

	var incs sync.WaitGroup
	for _, k := range keys {
		incs.Add(1)
		go func(key string) {
			defer incs.Done()
			for i := 0; i < incPerKey; i++ {
				if _, err := m.IncrementAndGet(ctx, key, windowSec, noTrimCap); err != nil {
					t.Errorf("IncrementAndGet(%q): %v", key, err)
					return
				}
			}
		}(k)
	}
	incs.Wait()
	close(stop)
	cleanupDone.Wait()

	// Every key was incrementally refreshed to a fresh (in-window) timestamp, so
	// none is stale; a final pass must leave all of them intact.
	m.Cleanup()

	// With the frozen clock, all incPerKey timestamps land inside the window and
	// none is pruned, so the in-window count must equal the number of increments.
	// A short count means a live counter was wrongly deleted mid-flight — the
	// fail-open reset the re-check prevents.
	for _, k := range keys {
		got, err := m.Peek(ctx, k, windowSec)
		if err != nil {
			t.Fatalf("Peek(%q): %v", k, err)
		}
		if got != incPerKey {
			t.Errorf("key %q: in-window count = %d, want %d (a live counter was dropped by concurrent Cleanup)", k, got, incPerKey)
		}
	}
}

// TestInMemory_Cleanup_ConcurrentPeekRaceFree is a regression test:
// Cleanup's phase one now takes a read lock (it only scans the map), so it must
// be safe to run concurrently with Peek (which also takes a read lock) without a
// data race and without corrupting either result. Run under -race, this asserts
// the RLock scan shares correctly with concurrent readers; functionally it
// confirms Peek still sees the live entries throughout a cleanup pass.
func TestInMemory_Cleanup_ConcurrentPeekRaceFree(t *testing.T) {
	now := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
	m := NewInMemory(WithTimeFunc(func() time.Time { return now }))
	ctx := context.Background()

	const (
		windowSec = 3600
		numKeys   = 200
		reads     = 100
	)

	keys := make([]string, numKeys)
	for i := range keys {
		keys[i] = fmt.Sprintf("session-%d:tool", i)
		// Seed each key with a fresh (in-window) timestamp so it is never deletable:
		// Cleanup's read-locked phase one scans every entry while Peek reads them
		// concurrently, the exact RLock/RLock overlap the change enables.
		if _, err := m.IncrementAndGet(ctx, keys[i], windowSec, noTrimCap); err != nil {
			t.Fatalf("seed IncrementAndGet(%q): %v", keys[i], err)
		}
	}

	stop := make(chan struct{})
	var cleanupDone sync.WaitGroup
	cleanupDone.Add(1)
	go func() {
		defer cleanupDone.Done()
		for {
			m.Cleanup()
			select {
			case <-stop:
				return
			default:
			}
		}
	}()

	var readers sync.WaitGroup
	for _, k := range keys {
		readers.Add(1)
		go func(key string) {
			defer readers.Done()
			for i := 0; i < reads; i++ {
				got, err := m.Peek(ctx, key, windowSec)
				if err != nil {
					t.Errorf("Peek(%q): %v", key, err)
					return
				}
				// The entry is live and never deleted, so a concurrent cleanup pass
				// must never make Peek read it as absent.
				if got != 1 {
					t.Errorf("Peek(%q) = %d during concurrent Cleanup, want 1", key, got)
					return
				}
			}
		}(k)
	}
	readers.Wait()
	close(stop)
	cleanupDone.Wait()
}

// TestInMemory_Cleanup_NonMonotonicClock_KeepsLiveEntry is a regression test:
// Cleanup decided staleness from timestamps[last], assuming the
// last-appended timestamp is the most recent. That holds under a monotonic
// clock but not under a WithTimeFunc clock that jumps backward — IncrementAndGet
// then appends a timestamp that is OLDER than an earlier element, and a
// last-element check sees a stale tail and wrongly drops a still-live entry.
//
// Sequence (1h window ⇒ 2h cleanup margin):
//   - First call at t+3h          → timestamps = [t+3h]
//   - Clock resets, call at t      → timestamps = [t+3h, t]   (last is oldest)
//   - Cleanup evaluated at t+4h
//
// At cleanup the newest call (t+3h) is only 1h old — well inside the 2h margin —
// so the entry must survive. A last-element check would instead read
// timestamps[last] = t (4h old), judge it stale, and delete a live counter.
// Scanning for the true maximum is what keeps the entry.
func TestInMemory_Cleanup_NonMonotonicClock_KeepsLiveEntry(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	now := base
	m := NewInMemory(WithTimeFunc(func() time.Time { return now }))

	ctx := context.Background()
	const windowSec = 3600 // 1h window; cleanup margin is 2h
	const key = "maxcalls:session-C:tool"

	// First call lands 3h in the future.
	now = base.Add(3 * time.Hour)
	if _, err := m.IncrementAndGet(ctx, key, windowSec, noTrimCap); err != nil {
		t.Fatalf("IncrementAndGet (future): %v", err)
	}

	// Clock jumps back to the base; the second call appends t (older than the
	// first), so timestamps[last] is no longer the newest element.
	now = base
	if _, err := m.IncrementAndGet(ctx, key, windowSec, noTrimCap); err != nil {
		t.Fatalf("IncrementAndGet (reset): %v", err)
	}

	// Evaluate Cleanup at t+4h. The true newest call (t+3h) is 1h old, inside
	// the 2h margin, so the entry must NOT be dropped. A last-element check would
	// see timestamps[last] = t (4h old), judge it stale, and delete a live
	// counter — the bug this guards against.
	now = base.Add(4 * time.Hour)
	m.Cleanup()

	m.mu.Lock()
	_, present := m.entries[storageKey(key, windowSec)]
	m.mu.Unlock()
	if !present {
		t.Error("Cleanup must keep an entry whose newest timestamp is live, even when it is not the last-appended one")
	}
}

// TestInMemory_StartCleanup_FirstIntervalWins verifies the documented "first
// call wins" contract of the idempotent StartCleanup: once cleanup
// is running, a later StartCleanup with a different interval must neither restart
// nor reconfigure the goroutine the first call established.
//
// It lives in the internal test package and asserts on the entries map directly
// because that is the only place the two intervals are distinguishable.
// IncrementAndGet prunes a key's own expired timestamps before counting, so a
// post-prune count reads 1 whether or not Cleanup evicted the entry; only the
// entry's presence in m.entries reveals whether a cleanup tick actually fired.
func TestInMemory_StartCleanup_FirstIntervalWins(t *testing.T) {
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

	m := NewInMemory(WithTimeFunc(timeFunc))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// First call wins with a fast 10ms interval; the later hour-long call is a
	// no-op that must not take effect.
	if !m.StartCleanup(ctx, 10*time.Millisecond) {
		t.Fatal("first StartCleanup must report it started the cleanup goroutine")
	}
	if m.StartCleanup(ctx, time.Hour) {
		t.Fatal("second StartCleanup must be a no-op and report false")
	}

	if _, err := m.IncrementAndGet(context.Background(), "k", 60, noTrimCap); err != nil {
		t.Fatalf("IncrementAndGet: %v", err)
	}

	// Age the entry past 2x its 60s window so Cleanup is eligible to evict it,
	// then let the fast interval fire. If the hour-long interval had won, no tick
	// would run in this span and the entry would survive in the map.
	advanceClock(25 * time.Hour)
	time.Sleep(100 * time.Millisecond)

	m.mu.Lock()
	n := len(m.entries)
	m.mu.Unlock()
	if n != 0 {
		t.Errorf("entries = %d, want 0: the first call's fast interval must govern cleanup", n)
	}
}

// TestInMemory_StartCleanup_RestartsAfterContextCancel verifies that once the
// winning cleanup goroutine's context is canceled and the goroutine exits, the
// start guard is released so a later call with a fresh live context can restart
// cleanup. A stranded guard would leave the map growing unbounded forever.
func TestInMemory_StartCleanup_RestartsAfterContextCancel(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	current := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
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

	m := NewInMemory(WithTimeFunc(timeFunc))

	// First start, then cancel its context.
	ctx1, cancel1 := context.WithCancel(context.Background())
	if !m.StartCleanup(ctx1, 10*time.Millisecond) {
		t.Fatal("first StartCleanup must report it started cleanup")
	}
	cancel1()

	// A later call with a fresh live context must restart cleanup. StartCleanup
	// itself waits for the prior (canceled) goroutine to exit before re-arming, so
	// this is deterministic without an external poll on internal state.
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	if !m.StartCleanup(ctx2, 10*time.Millisecond) {
		t.Fatal("StartCleanup after cancel must restart cleanup and report true")
	}

	if _, err := m.IncrementAndGet(context.Background(), "k", 60, noTrimCap); err != nil {
		t.Fatalf("IncrementAndGet: %v", err)
	}
	advanceClock(25 * time.Hour)
	time.Sleep(100 * time.Millisecond)

	m.mu.Lock()
	n := len(m.entries)
	m.mu.Unlock()
	if n != 0 {
		t.Errorf("entries = %d, want 0: restarted cleanup goroutine must evict stale entries", n)
	}
}

// TestInMemory_StartCleanup_RestartRacingTeardown reproduces the restart-during-
// teardown race: a StartCleanup arriving right after the prior context is canceled
// (while that goroutine may still be tearing down) must never be lost — it must
// restart cleanup, not return false leaving no goroutine running. Under the old
// released-on-exit atomic flag the restart could lose its CAS against the still-set
// flag and then the exiting goroutine cleared it, leaving cleanup permanently off.
func TestInMemory_StartCleanup_RestartRacingTeardown(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	current := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
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

	m := NewInMemory(WithTimeFunc(timeFunc))

	// Many tight cancel-then-restart cycles, each restart racing the prior
	// goroutine's teardown. Every restart must report true (the goroutine was not
	// lost); the -race detector also exercises the lifecycle handoff here.
	for i := 0; i < 100; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		if !m.StartCleanup(ctx, time.Hour) {
			t.Fatalf("cycle %d: restart must report true, not lose the cleanup goroutine", i)
		}
		cancel()
	}

	// After the raced cycles, a final live restart must run real cleanup — proving a
	// goroutine is genuinely running, not merely that the flag toggled.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if !m.StartCleanup(ctx, 10*time.Millisecond) {
		t.Fatal("final live StartCleanup must restart cleanup")
	}
	if _, err := m.IncrementAndGet(context.Background(), "k", 60, noTrimCap); err != nil {
		t.Fatalf("IncrementAndGet: %v", err)
	}
	advanceClock(25 * time.Hour)
	time.Sleep(100 * time.Millisecond)
	m.mu.Lock()
	n := len(m.entries)
	m.mu.Unlock()
	if n != 0 {
		t.Errorf("entries = %d, want 0: the restarted cleanup goroutine must evict stale entries", n)
	}
}

// TestInMemory_Cleanup_DropsEntryPastDoubleWindow verifies the fix still
// reclaims memory: once an entry's most-recent timestamp is older than twice
// its window, Cleanup drops it, matching the Redis backend's windowSec*2 TTL.
func TestInMemory_Cleanup_DropsEntryPastDoubleWindow(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	now := base
	m := NewInMemory(WithTimeFunc(func() time.Time { return now }))

	ctx := context.Background()
	const windowSec = 3600 // 1h window
	const key = "maxcalls:session-B:tool"

	if _, err := m.IncrementAndGet(ctx, key, windowSec, noTrimCap); err != nil {
		t.Fatalf("IncrementAndGet: %v", err)
	}

	// Advance past 2x the window (2h); the entry's only timestamp is now well
	// outside the window and unrecoverable, so it should be reclaimed.
	now = base.Add(2*time.Hour + time.Minute)
	m.Cleanup()

	m.mu.Lock()
	_, present := m.entries[storageKey(key, windowSec)]
	m.mu.Unlock()
	if present {
		t.Error("Cleanup must drop entries older than 2x their window to reclaim memory")
	}
}

// noTrimCap is an IncrementAndGet retention cap set well above any call count the
// in-package tests reach, so the most-recent-N trimming never engages and these
// tests exercise the pre-existing prune/compact/cleanup behaviour unchanged.
const noTrimCap = 1 << 20

// TestCompactTimestamps exercises the backing-array reclamation helper directly.
// cap is not observable from the external test package, so this lives in-package.
func TestCompactTimestamps(t *testing.T) {
	t.Parallel()

	// makeSlice builds a slice with an explicit capacity and `length` live
	// elements, mirroring how IncrementAndGet leaves a slice after pruning a
	// burst: a long backing array with only a few live timestamps at the front.
	makeSlice := func(length, capacity int) []time.Time {
		s := make([]time.Time, length, capacity)
		for i := range s {
			s[i] = time.Unix(int64(i), 0)
		}
		return s
	}

	tests := []struct {
		name       string
		length     int
		capacity   int
		wantShrunk bool // true => result re-sized to exact length; false => untouched
	}{
		{name: "small cap is left alone", length: 1, capacity: 16, wantShrunk: false},
		{name: "at threshold cap is left alone", length: 1, capacity: compactMinCap, wantShrunk: false},
		{name: "just above threshold and empty is reclaimed", length: 1, capacity: compactMinCap + 1, wantShrunk: true},
		{name: "large and mostly empty is reclaimed", length: 1, capacity: 1024, wantShrunk: true},
		{name: "large but near capacity is left alone", length: 900, capacity: 1024, wantShrunk: false},
		{name: "large at exactly 25% util is left alone", length: 256, capacity: 1024, wantShrunk: false},
		{name: "large just under 25% util is reclaimed", length: 255, capacity: 1024, wantShrunk: true},
		{name: "empty large slice is reclaimed", length: 0, capacity: 1024, wantShrunk: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			in := makeSlice(tc.length, tc.capacity)
			got := compactTimestamps(in)

			// Live contents must always survive unchanged.
			if len(got) != tc.length {
				t.Fatalf("len(got) = %d, want %d", len(got), tc.length)
			}
			for i := range got {
				if !got[i].Equal(in[i]) {
					t.Fatalf("element %d = %v, want %v", i, got[i], in[i])
				}
			}

			if tc.wantShrunk {
				if cap(got) != tc.length {
					t.Errorf("expected reclaim to exact length: cap(got) = %d, want %d", cap(got), tc.length)
				}
			} else {
				if cap(got) != tc.capacity {
					t.Errorf("expected slice left untouched: cap(got) = %d, want %d", cap(got), tc.capacity)
				}
			}
		})
	}
}

// TestInMemory_IncrementAndGet_ReleasesBurstCapacity is a regression test:
// after a burst of calls within one window expires, the next call must
// reclaim the oversized backing array rather than pinning it at the burst peak.
func TestInMemory_IncrementAndGet_ReleasesBurstCapacity(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
	now := base
	m := NewInMemory(WithTimeFunc(func() time.Time { return now }))

	ctx := context.Background()
	const (
		windowSec = 60
		burst     = 1000 // safely above compactMinCap
		key       = "maxcalls:session:tool"
	)

	// Drive a burst within a single window. With a frozen clock every call lands
	// inside the window, so the backing array grows to the burst size.
	var count int64
	var err error
	for i := 0; i < burst; i++ {
		count, err = m.IncrementAndGet(ctx, key, windowSec, noTrimCap)
		if err != nil {
			t.Fatalf("IncrementAndGet: %v", err)
		}
	}
	if count != burst {
		t.Fatalf("after burst, count = %d, want %d", count, burst)
	}

	m.mu.Lock()
	peakCap := cap(m.entries[storageKey(key, windowSec)].timestamps)
	m.mu.Unlock()
	if peakCap < burst {
		t.Fatalf("backing array did not reach burst size: cap = %d, want >= %d", peakCap, burst)
	}

	// Advance past the window so every burst timestamp expires, then make one
	// steady-state call. It prunes all `burst` stale entries, appends one, and
	// must release the now-oversized array.
	now = base.Add(time.Duration(windowSec+1) * time.Second)
	count, err = m.IncrementAndGet(ctx, key, windowSec, noTrimCap)
	if err != nil {
		t.Fatalf("IncrementAndGet after expiry: %v", err)
	}
	if count != 1 {
		t.Fatalf("after window expiry, count = %d, want 1", count)
	}

	m.mu.Lock()
	gotCap := cap(m.entries[storageKey(key, windowSec)].timestamps)
	m.mu.Unlock()
	if gotCap >= peakCap {
		t.Errorf("backing array not reclaimed after burst drained: cap = %d, peak was %d", gotCap, peakCap)
	}
	if gotCap > compactMinCap {
		t.Errorf("reclaimed capacity still oversized: cap = %d, want <= %d", gotCap, compactMinCap)
	}
}

// TestInMemory_IncrementAndGet_SteadyStateKeepsCapacity guards the hot path: a
// counter receiving steady in-window traffic must keep reusing its backing array
// (amortised O(1) appends), not reallocate on every call. cap is observed before
// and after a non-expiring call; it must not drop.
func TestInMemory_IncrementAndGet_SteadyStateKeepsCapacity(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
	m := NewInMemory(WithTimeFunc(func() time.Time { return now }))
	ctx := context.Background()
	const key = "steady"

	// Warm up so the backing array has grown past compactMinCap with all entries
	// still live in the window.
	for i := 0; i < 200; i++ {
		if _, err := m.IncrementAndGet(ctx, key, 3600, noTrimCap); err != nil {
			t.Fatalf("IncrementAndGet: %v", err)
		}
	}

	m.mu.Lock()
	before := cap(m.entries[storageKey(key, 3600)].timestamps)
	m.mu.Unlock()

	if _, err := m.IncrementAndGet(ctx, key, 3600, noTrimCap); err != nil {
		t.Fatalf("IncrementAndGet: %v", err)
	}

	m.mu.Lock()
	after := cap(m.entries[storageKey(key, 3600)].timestamps)
	m.mu.Unlock()

	if after < before {
		t.Errorf("steady-state call must not shrink a near-full backing array: cap %d -> %d", before, after)
	}
}

// TestInMemory_IncrementAndGet_CapsToMaxEntries is a regression test:
// a key under sustained in-window traffic must not accumulate one timestamp
// per call. With maxEntries set, IncrementAndGet retains only the most-recent
// maxEntries timestamps, so both the returned count and the stored slice (and its
// backing array) stay bounded no matter how many calls land in the window — the
// exact case that previously grew a 24h history key without bound.
func TestInMemory_IncrementAndGet_CapsToMaxEntries(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
	m := NewInMemory(WithTimeFunc(func() time.Time { return now }))
	ctx := context.Background()

	const (
		windowSec  = 86400 // 24h, the sequenceBlock history window
		maxEntries = 1
		key        = "seq:session-A:dangerous_tool"
		calls      = 10000
	)

	// Every call lands inside the frozen window. Without the cap this would store
	// `calls` timestamps; with maxEntries=1 the count never climbs past 1.
	for i := 0; i < calls; i++ {
		count, err := m.IncrementAndGet(ctx, key, windowSec, maxEntries)
		if err != nil {
			t.Fatalf("call %d: IncrementAndGet: %v", i, err)
		}
		if count != int64(maxEntries) {
			t.Fatalf("call %d: count = %d, want %d (cap must hold the count down)", i, count, maxEntries)
		}
	}

	m.mu.Lock()
	gotLen := len(m.entries[storageKey(key, windowSec)].timestamps)
	gotCap := cap(m.entries[storageKey(key, windowSec)].timestamps)
	m.mu.Unlock()

	if gotLen != maxEntries {
		t.Fatalf("stored timestamps = %d after %d calls, want %d", gotLen, calls, maxEntries)
	}
	// The backing array peaks at one prune-then-append before the trim, so it must
	// stay tiny — never anywhere near `calls`.
	if gotCap > 2*maxEntries {
		t.Errorf("backing array cap = %d; the cap must keep it bounded near maxEntries, not grow with traffic", gotCap)
	}
}

// TestInMemory_IncrementAndGet_CapKeepsNewest verifies the cap keeps the most
// recent timestamp, not the oldest: with maxEntries=1 a later call's marker must
// survive an earlier one, so a sliding-window presence check (Peek > 0) stays
// correct for as long as ANY call is in the window. Keeping the oldest instead
// would report absence prematurely and fail sequenceBlock open.
func TestInMemory_IncrementAndGet_CapKeepsNewest(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
	now := base
	m := NewInMemory(WithTimeFunc(func() time.Time { return now }))
	ctx := context.Background()

	const (
		windowSec  = 60
		maxEntries = 1
		key        = "seq:s:tool"
	)

	// Record at t=0, then again at t=40s. maxEntries=1 keeps only the t=40s marker.
	if _, err := m.IncrementAndGet(ctx, key, windowSec, maxEntries); err != nil {
		t.Fatal(err)
	}
	now = base.Add(40 * time.Second)
	if _, err := m.IncrementAndGet(ctx, key, windowSec, maxEntries); err != nil {
		t.Fatal(err)
	}

	// At t=70s the t=0 call has aged out of the 60s window but the t=40s call has
	// not (it ages out at t=100s). Presence must still read true.
	now = base.Add(70 * time.Second)
	got, err := m.Peek(ctx, key, windowSec)
	if err != nil {
		t.Fatal(err)
	}
	if got != 1 {
		t.Fatalf("Peek = %d at t=70s, want 1: the newest marker (t=40s) must be the one retained", got)
	}

	// Past t=100s even the t=40s call has aged out: presence reads false.
	now = base.Add(101 * time.Second)
	got, err = m.Peek(ctx, key, windowSec)
	if err != nil {
		t.Fatal(err)
	}
	if got != 0 {
		t.Fatalf("Peek = %d at t=101s, want 0: every marker should have aged out", got)
	}
}

// numEntries reads the live key count under the lock. cap/len of the internal
// map is not observable from the external test package, so these tests live
// in-package.
func numEntries(m *InMemory) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}

// TestInMemory_WithMaxKeys_IncrementAndGet verifies the key bound on the
// sequenceBlock recording path (IncrementAndGet): once the map is full, a call
// under a new key is refused without growing the map, while a key already
// present keeps counting.
func TestInMemory_WithMaxKeys_IncrementAndGet(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	const window = 60
	m := NewInMemory(WithMaxKeys(2))

	// Fill to capacity with two distinct keys.
	for _, key := range []string{"seq:a:tool", "seq:b:tool"} {
		if _, err := m.IncrementAndGet(ctx, key, window, noTrimCap); err != nil {
			t.Fatalf("IncrementAndGet(%q) under capacity: unexpected error %v", key, err)
		}
	}
	if got := numEntries(m); got != 2 {
		t.Fatalf("after filling to capacity, entries = %d, want 2", got)
	}

	// A previously-unseen key past the bound is refused, and the map does not grow.
	count, err := m.IncrementAndGet(ctx, "seq:c:tool", window, noTrimCap)
	if err == nil {
		t.Fatal("IncrementAndGet on a new key past maxKeys: want error, got nil")
	}
	if count != 0 {
		t.Errorf("refused call: count = %d, want 0", count)
	}
	if want := "key limit reached (2)"; !strings.Contains(err.Error(), want) {
		t.Errorf("error = %q, want it to contain %q", err.Error(), want)
	}
	if got := numEntries(m); got != 2 {
		t.Errorf("after a refused new key, entries = %d, want 2 (map must not grow)", got)
	}

	// An existing key still counts — the bound only gates *new* keys.
	count, err = m.IncrementAndGet(ctx, "seq:a:tool", window, noTrimCap)
	if err != nil {
		t.Fatalf("IncrementAndGet on an existing key at capacity: unexpected error %v", err)
	}
	if count != 2 {
		t.Errorf("existing key recount: count = %d, want 2", count)
	}
	if got := numEntries(m); got != 2 {
		t.Errorf("after recounting an existing key, entries = %d, want 2", got)
	}
}

// TestInMemory_WithMaxKeys_IncrementIfBelow verifies the key bound on the
// maxCalls rate-limit path (IncrementIfBelow): a new key past the bound fails
// closed (error, not admitted) so the maxCalls handler denies the call.
func TestInMemory_WithMaxKeys_IncrementIfBelow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	const (
		window = 60
		limit  = 5
	)
	m := NewInMemory(WithMaxKeys(1))

	if _, admitted, _, err := m.IncrementIfBelow(ctx, "maxcalls:a:tool", window, limit); err != nil || !admitted {
		t.Fatalf("first key: admitted=%v err=%v, want admitted=true err=nil", admitted, err)
	}

	count, admitted, retryAfter, err := m.IncrementIfBelow(ctx, "maxcalls:b:tool", window, limit)
	if err == nil {
		t.Fatal("IncrementIfBelow on a new key past maxKeys: want error, got nil")
	}
	if admitted {
		t.Error("refused call: admitted = true, want false (must fail closed)")
	}
	if count != 0 || retryAfter != 0 {
		t.Errorf("refused call: count=%d retryAfter=%v, want 0/0", count, retryAfter)
	}
	if got := numEntries(m); got != 1 {
		t.Errorf("after a refused new key, entries = %d, want 1 (map must not grow)", got)
	}

	// The already-admitted key keeps counting up to its own limit.
	if _, admitted, _, err := m.IncrementIfBelow(ctx, "maxcalls:a:tool", window, limit); err != nil || !admitted {
		t.Fatalf("existing key recount: admitted=%v err=%v, want admitted=true err=nil", admitted, err)
	}
}

// TestInMemory_IncrementIfBelow_LimitBelowOneWritesNoState is a regression test:
// a limit<1 call can never admit, so it must not insert a phantom entry.
// Previously the entry was created (and counted against maxKeys) before the
// limit<1 check, so a limit<1 call on a new key burned the sole slot and then
// permanently denied a legitimate new key until Cleanup ran.
//
// A limit<1 is now reported as a structured error (not a silent nil denial) so
// a misconfigured limit is distinguishable from an exhausted quota; the
// no-phantom-entry guarantee is unchanged and still asserted here.
func TestInMemory_IncrementIfBelow_LimitBelowOneWritesNoState(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	const window = 60
	m := NewInMemory(WithMaxKeys(1))

	// A limit<1 call on a new key fails closed with an error and writes no state.
	count, admitted, retryAfter, err := m.IncrementIfBelow(ctx, "key-A", window, 0)
	if err == nil {
		t.Fatal("limit<1 on a new key: want error, got nil")
	}
	if want := "limit must be >= 1"; !strings.Contains(err.Error(), want) {
		t.Errorf("error = %q, want it to contain %q", err.Error(), want)
	}
	if admitted {
		t.Error("limit<1: admitted = true, want false")
	}
	if count != 0 || retryAfter != 0 {
		t.Errorf("limit<1: count=%d retryAfter=%v, want 0/0", count, retryAfter)
	}
	if got := numEntries(m); got != 0 {
		t.Fatalf("limit<1 must not create an entry: entries = %d, want 0", got)
	}

	// The sole maxKeys slot is still free: a legitimate new key is admitted.
	if _, admitted, _, err := m.IncrementIfBelow(ctx, "key-B", window, 5); err != nil || !admitted {
		t.Fatalf("legitimate new key after a limit<1 denial: admitted=%v err=%v, want admitted=true err=nil", admitted, err)
	}
}

// TestInMemory_IncrementIfBelow_LimitAboveMaxFailsClosed is a regression test:
// a limit above MaxLimit (2^53) would be silently rounded to a different
// threshold in the Redis Lua float64 arithmetic, so checkLimit rejects it up
// front with a structured error and writes no state, exactly like limit<1.
// The boundary value MaxLimit itself is still accepted.
func TestInMemory_IncrementIfBelow_LimitAboveMaxFailsClosed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	const window = 60
	m := NewInMemory(WithMaxKeys(1))

	count, admitted, retryAfter, err := m.IncrementIfBelow(ctx, "key-A", window, MaxLimit+1)
	if err == nil {
		t.Fatal("limit>MaxLimit on a new key: want error, got nil")
	}
	if want := "limit must be <="; !strings.Contains(err.Error(), want) {
		t.Errorf("error = %q, want it to contain %q", err.Error(), want)
	}
	if admitted {
		t.Error("limit>MaxLimit: admitted = true, want false")
	}
	if count != 0 || retryAfter != 0 {
		t.Errorf("limit>MaxLimit: count=%d retryAfter=%v, want 0/0", count, retryAfter)
	}
	if got := numEntries(m); got != 0 {
		t.Fatalf("limit>MaxLimit must not create an entry: entries = %d, want 0", got)
	}

	// The boundary value MaxLimit is in range and admits.
	if _, admitted, _, err := m.IncrementIfBelow(ctx, "key-B", window, MaxLimit); err != nil || !admitted {
		t.Fatalf("limit==MaxLimit: admitted=%v err=%v, want admitted=true err=nil", admitted, err)
	}
}

// TestInMemory_MaxKeys_UnlimitedByDefault confirms the default (no WithMaxKeys,
// equivalently WithMaxKeys(0)) leaves the key count unbounded, preserving the
// historical behavior for library callers and tests.
func TestInMemory_MaxKeys_UnlimitedByDefault(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	const window = 60

	for _, m := range []*InMemory{NewInMemory(), NewInMemory(WithMaxKeys(0)), NewInMemory(WithMaxKeys(-1))} {
		for i := 0; i < 1000; i++ {
			key := "seq:" + string(rune('a'+i%26)) + ":" + time.Duration(i).String()
			if _, err := m.IncrementAndGet(ctx, key, window, noTrimCap); err != nil {
				t.Fatalf("unbounded counter returned error at key %d: %v", i, err)
			}
		}
	}
}

// TestInMemory_WithMaxKeys_CleanupReclaimsSlot verifies that a slot freed by
// Cleanup is reusable: once a stale entry is reclaimed, a new key is admitted
// again. This is the recovery path that keeps the bound from being a permanent
// lockout under normal session churn.
func TestInMemory_WithMaxKeys_CleanupReclaimsSlot(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	base := time.Date(2026, 6, 13, 0, 0, 0, 0, time.UTC)
	now := base
	m := NewInMemory(WithMaxKeys(1), WithTimeFunc(func() time.Time { return now }))

	const window = 60
	if _, err := m.IncrementAndGet(ctx, "seq:a:tool", window, noTrimCap); err != nil {
		t.Fatalf("first key: unexpected error %v", err)
	}
	// At capacity: a new key is refused.
	if _, err := m.IncrementAndGet(ctx, "seq:b:tool", window, noTrimCap); err == nil {
		t.Fatal("new key at capacity: want error, got nil")
	}

	// Advance past the staleness threshold (cleanupMarginFactor * window) and run
	// Cleanup; the lone entry is reclaimed.
	now = base.Add(time.Duration(window)*cleanupMarginFactor*time.Second + time.Second)
	m.Cleanup()
	if got := numEntries(m); got != 0 {
		t.Fatalf("after Cleanup of a stale entry, entries = %d, want 0", got)
	}

	// The freed slot is reusable.
	if _, err := m.IncrementAndGet(ctx, "seq:b:tool", window, noTrimCap); err != nil {
		t.Fatalf("new key after Cleanup freed a slot: unexpected error %v", err)
	}
}

// TestInMemory_WithMaxKeys_PeekNotGated confirms Peek is a pure read: it neither
// creates an entry nor errors when the map is at capacity, so a sequenceBlock
// lookup at the key ceiling still answers "has A run?" instead of failing.
func TestInMemory_WithMaxKeys_PeekNotGated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	const window = 60
	m := NewInMemory(WithMaxKeys(1))

	if _, err := m.IncrementAndGet(ctx, "seq:a:tool", window, noTrimCap); err != nil {
		t.Fatalf("seeding key: unexpected error %v", err)
	}

	count, err := m.Peek(ctx, "seq:never-seen:tool", window)
	if err != nil {
		t.Errorf("Peek at capacity on an absent key: unexpected error %v", err)
	}
	if count != 0 {
		t.Errorf("Peek on an absent key: count = %d, want 0", count)
	}
	if got := numEntries(m); got != 1 {
		t.Errorf("Peek must not create an entry: entries = %d, want 1", got)
	}
}

// TestStorageKey_NamespacesByWindow pins the storageKey derivation that isolates
// windows in the InMemory map: one logical key counted under two
// different windows must occupy two independent entries, mirroring the Redis
// backend's per-window "callcounter:<key>:<windowSec>" sorted sets. This is the
// structural guarantee the cross-window-prune regression below rests on — without
// it the two windows would share one timestamp slice and the shorter window's
// prune would corrupt the longer window's count.
func TestStorageKey_NamespacesByWindow(t *testing.T) {
	t.Parallel()

	const key = "maxcalls:s:tool"
	if got := storageKey(key, 60); got == storageKey(key, 3600) {
		t.Fatalf("storageKey must differ per window: storageKey(%q, 60) == storageKey(%q, 3600) == %q", key, key, got)
	}

	now := time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)
	m := NewInMemory(WithTimeFunc(func() time.Time { return now }))
	ctx := context.Background()

	// One logical key, two windows: each call must create its own entry.
	if _, _, _, err := m.IncrementIfBelow(ctx, key, 60, 5); err != nil {
		t.Fatalf("IncrementIfBelow(60): %v", err)
	}
	if _, _, _, err := m.IncrementIfBelow(ctx, key, 3600, 10); err != nil {
		t.Fatalf("IncrementIfBelow(3600): %v", err)
	}

	m.mu.Lock()
	n := len(m.entries)
	_, short := m.entries[storageKey(key, 60)]
	_, long := m.entries[storageKey(key, 3600)]
	m.mu.Unlock()

	if n != 2 {
		t.Fatalf("entries = %d, want 2: one logical key under two windows must occupy two independent buckets", n)
	}
	if !short || !long {
		t.Fatalf("missing a window-namespaced entry: short=%v long=%v", short, long)
	}
}

// TestInMemoryPeekFloorMatchesIncrement guards the precision fix: Peek floors its
// window cutoff to microsecond precision exactly like IncrementAndGet (and the
// Redis backend, which stores UnixMicro scores), so the two never disagree on
// whether a recorded call is in-window. The clock here carries sub-microsecond
// nanoseconds so a non-floored cutoff would diverge from the floored, recorded
// timestamp.
func TestInMemoryPeekFloorMatchesIncrement(t *testing.T) {
	base := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	now := base.Add(700 * time.Nanosecond) // floors to base

	m := NewInMemory(WithTimeFunc(func() time.Time { return now }))
	ctx := context.Background()

	const windowSec = 1
	inc, err := m.IncrementAndGet(ctx, "session:a", windowSec, 10)
	if err != nil {
		t.Fatalf("IncrementAndGet: %v", err)
	}

	// Peek a little later but well within the window; with a sub-microsecond clock
	// the floored cutoff must keep the just-recorded call visible, matching the
	// count IncrementAndGet returned.
	now = base.Add(500*time.Millisecond + 300*time.Nanosecond)
	peek, err := m.Peek(ctx, "session:a", windowSec)
	if err != nil {
		t.Fatalf("Peek: %v", err)
	}
	if peek != inc {
		t.Fatalf("Peek = %d, IncrementAndGet = %d; the two backends/paths must agree on in-window count", peek, inc)
	}
	if peek != 1 {
		t.Fatalf("Peek = %d, want 1", peek)
	}
}
