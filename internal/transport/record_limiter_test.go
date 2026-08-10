// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// withFakeClock pins a gate's bucket to a caller-driven clock and returns the setter, so a
// test drives refill deterministically instead of sleeping. It also forces the lazy bucket
// into existence before any concurrent use.
//
// The clock itself is guarded by its own mutex (independent of the gate's), rather than a
// bare captured variable: bucket.now is invoked from inside admit() while the gate's lock is
// held, but a later setNow call runs from the test goroutine with no lock of its own, so an
// unsynchronized read/write pair here would itself be the kind of TOCTOU this file's
// production fix (see saturationGate.admit) exists to close one layer down.
func withFakeClock(g *saturationGate, base time.Time) func(time.Time) {
	var mu sync.Mutex
	now := base
	bucket := g.bucket()
	bucket.now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	return func(t time.Time) {
		mu.Lock()
		defer mu.Unlock()
		now = t
	}
}

// TestSaturationGate_CollapsesEpisodeToOneRecord pins the primary rule: a pool that stays
// saturated writes ONE record, not one per refused request. Before the gate, an
// established session that saturated a pool could enqueue an audit record per refusal —
// with no upstream round trip and no response body to await, the cheapest write primitive
// the proxy offers — and the sink's drop counter is monotonic, so enough of them latch
// AuditDegraded() and make --require-audit=strict deny every enforced call on every route.
func TestSaturationGate_CollapsesEpisodeToOneRecord(t *testing.T) {
	t.Parallel()
	var g saturationGate

	admitted := 0
	const refusals = 10_000
	for i := 0; i < refusals; i++ {
		if ok, _ := g.admit(); ok {
			admitted++
		}
	}
	if admitted != 1 {
		t.Fatalf("a single saturation episode must produce exactly 1 record; got %d", admitted)
	}

	// The elided refusals are not lost: the next admitted record carries the count, so an
	// operator sees the magnitude of the episode as well as the fact of it.
	g.clear()
	ok, suppressed := g.admit()
	if !ok {
		t.Fatal("a freed slot ends the episode, so the next refusal must be a new one")
	}
	if want := uint64(refusals - 1); suppressed != want {
		t.Fatalf("suppressed = %d, want %d — every elided refusal must be folded into the next record", suppressed, want)
	}

	// And the count resets, so the following episode does not double-report.
	g.clear()
	if ok, s := g.admit(); !ok || s != 0 {
		t.Fatalf("after reporting, the suppressed counter must reset; ok=%v suppressed=%d", ok, s)
	}
}

// TestSaturationGate_ClearReArmsOnlyAfterAFreeSlot pins that the episode ends on a
// successful acquire and nothing else. Without clear() the gate would record a pool's
// FIRST saturation and then stay silent for the process lifetime, which is worse than no
// gate: a later, unrelated saturation incident would leave no trace at all.
func TestSaturationGate_ClearReArmsOnlyAfterAFreeSlot(t *testing.T) {
	t.Parallel()
	var g saturationGate

	if ok, _ := g.admit(); !ok {
		t.Fatal("the first refusal of an episode must be recorded")
	}
	if ok, _ := g.admit(); ok {
		t.Fatal("a second refusal inside the same episode must not record")
	}
	g.clear()
	if ok, _ := g.admit(); !ok {
		t.Fatal("after a slot frees, the next refusal opens a new episode and must record")
	}
	// clear() on an already-armed gate is a no-op, not a credit: it must not let the next
	// two refusals both record.
	g.clear()
	g.clear()
	if ok, _ := g.admit(); !ok {
		t.Fatal("the new episode's first refusal must record")
	}
	if ok, _ := g.admit(); ok {
		t.Fatal("repeated clear() must not bank episodes")
	}
}

// TestSaturationGate_RateBackstopBoundsFlipFlop pins the second layer. Episode collapsing
// alone is not a rate bound: a caller holding a pool exactly at capacity can cycle
// saturate/drain/re-saturate as fast as the pool drains, opening a fresh episode each time
// and reinstating the unbounded write rate the gate exists to remove. The bucket underneath
// makes the sustained record rate independent of how fast an attacker can cycle it.
func TestSaturationGate_RateBackstopBoundsFlipFlop(t *testing.T) {
	t.Parallel()
	var g saturationGate
	base := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	setNow := withFakeClock(&g, base)

	admitted := 0
	const cycles = 5000
	for i := 0; i < cycles; i++ {
		if ok, _ := g.admit(); ok {
			admitted++
		}
		g.clear() // the drain half of the flip-flop
	}
	if admitted != saturationRecordBurst {
		t.Fatalf("with no clock movement a flip-flop must admit exactly the burst; admitted %d, want %d", admitted, saturationRecordBurst)
	}

	// Sustained pressure is served at the configured rate, not the caller's rate, and the
	// cycles suppressed by the BUCKET (not just by episode collapsing) are still counted.
	setNow(base.Add(time.Second))
	ok, suppressed := g.admit()
	if !ok {
		t.Fatal("a refill second must admit again")
	}
	if want := uint64(cycles - saturationRecordBurst); suppressed != want {
		t.Fatalf("suppressed = %d, want %d — a bucket-suppressed refusal must be counted too", suppressed, want)
	}
}

// TestSaturationGate_ZeroValueIsUsableAndConcurrencySafe pins that a gate embedded in a
// struct literal (as tests build sessions and the stdio proxy) is a real gate, not an
// inert one, and that the lazy bucket cannot be raced into existence twice. Both pools it
// guards are reached from concurrent HTTP handler goroutines.
func TestSaturationGate_ZeroValueIsUsableAndConcurrencySafe(t *testing.T) {
	t.Parallel()
	var g saturationGate

	const goroutines = 64
	var wg sync.WaitGroup
	var mu sync.Mutex
	admitted := 0
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			if ok, _ := g.admit(); ok {
				mu.Lock()
				admitted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if admitted != 1 {
		t.Fatalf("concurrent refusals in one episode must admit exactly one record; got %d", admitted)
	}
	if g.limiter == nil {
		t.Fatal("the zero-value gate must have lazily built its bucket; an inert gate is an unbounded gate")
	}
}

// TestSaturationGate_DeclinedLeadingEdgeRetriesRatherThanBlackout is the regression test for
// a bug a code review found in the prior implementation: admit() latched an episode's leading
// edge as "recorded" via a CompareAndSwap BEFORE knowing whether the token bucket would admit
// it. If the bucket then declined (drained by an earlier flip-flop burst), the episode was
// marked spoken-for anyway — and since clear() is the only other path back to "not
// recorded", and it fires solely on a successful pool acquire, a CONTINUOUS saturation
// (which by definition never acquires) would produce ZERO records for its entire remaining
// duration. That is worse than the per-refusal flood the gate exists to bound: a real,
// sustained incident could leave no trace on the tape at all.
//
// The fix (see saturationGate.admit) latches recorded only AFTER a successful bucket.admit(),
// so a decline leaves the gate open to retry on the next refusal once the bucket refills.
func TestSaturationGate_DeclinedLeadingEdgeRetriesRatherThanBlackout(t *testing.T) {
	t.Parallel()
	var g saturationGate
	base := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	setNow := withFakeClock(&g, base)

	// Drain the bucket via the flip-flop pattern — admit immediately followed by clear,
	// mirroring an attacker cycling the pool before settling into a continuous saturation —
	// with no clock movement, so nothing refills.
	for i := 0; i < saturationRecordBurst; i++ {
		if ok, _ := g.admit(); !ok {
			t.Fatalf("iteration %d: the burst should not be exhausted yet", i)
		}
		g.clear()
	}

	// Now simulate the continuous saturation itself: repeated refusals with NO clear() in
	// between (the pool never hands out a slot again). The leading edge of this episode
	// finds the bucket empty and must decline WITHOUT latching recorded — a buggy latch-on
	// CAS would make every one of these silently vanish for as long as the saturation lasts.
	for i := 0; i < 100; i++ {
		if ok, _ := g.admit(); ok {
			t.Fatalf("iteration %d: the bucket is drained and the clock has not moved; nothing should admit yet", i)
		}
	}

	// The bucket refills over time even though the pool is STILL saturated (no clear() has
	// run since the drain). A correct gate retries the leading edge on every refusal while
	// recorded stays false, so once the bucket has a token, the very next refusal in this
	// still-ongoing, still-unacknowledged saturation must get a record — proving the
	// incident is not permanently silenced.
	setNow(base.Add(time.Second))
	ok, suppressed := g.admit()
	if !ok {
		t.Fatal("a sustained saturation must eventually produce a record once the bucket refills — a declined leading edge must never permanently silence the episode")
	}
	if suppressed == 0 {
		t.Error("the 100 refusals declined while the bucket was drained must be folded into this record's suppressed_count, not dropped")
	}
}

// TestSaturationGate_ConcurrentAdmitClearNoDataRace stresses admit()/clear() from many
// goroutines simultaneously — the shape a session's pool sees under real contention (the
// acquire path calling clear() on every success, the refusal path calling admit() on every
// saturation). It is regression coverage for a second bug the same code review found: the
// prior lock-free implementation's clear() (an unsynchronized Load-then-Store) could race a
// DIFFERENT goroutine's admit() that had just opened a new episode via CompareAndSwap,
// closing that fresh episode before any later refusal folded into it and splitting one
// continuous saturation into spurious extra records — a logical TOCTOU invisible to the race
// detector, since every individual operation was itself a genuine atomic op.
//
// The fix makes admit() and clear() fully mutually exclusive under one mutex (see
// saturationGate.admit), which does not just narrow that window but removes it — there is no
// point during either call where the other can observe a partially-applied state. Run under
// `go test -race`, this also guards against a future refactor reintroducing unsynchronized
// access to recorded.
func TestSaturationGate_ConcurrentAdmitClearNoDataRace(t *testing.T) {
	t.Parallel()
	var g saturationGate

	const goroutines = 32
	const iterations = 2000
	var wg sync.WaitGroup
	var admitted atomic.Int64
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				if ok, _ := g.admit(); ok {
					admitted.Add(1)
				}
				// Every iteration clears — the shape of a pool that is saturated on
				// essentially every refusal but hands out a slot again immediately after,
				// which is the pattern most likely to expose a torn check-then-act.
				g.clear()
			}
		}()
	}
	wg.Wait()

	// Every clear() in this test runs immediately after its own goroutine's admit(), so
	// each goroutine can open at most one episode per iteration and the gate never sees a
	// TRUE continuous saturation — under correct mutual exclusion this keeps the admitted
	// count small and roughly bucket-refill-bound, not anywhere near the goroutines*iterations
	// refusal volume. A torn check-then-act would let far more concurrent leading edges slip
	// past the episode check, so a count near the total iteration volume signals exactly the
	// class of bug this test guards against, without asserting an exact number true
	// concurrency cannot make deterministic.
	const implausibleThreshold = goroutines * iterations / 10
	if got := admitted.Load(); got == 0 || got > implausibleThreshold {
		t.Fatalf("admitted = %d, want in (0, %d] — an implausible count suggests recorded was latched without genuine mutual exclusion", got, implausibleThreshold)
	}
}

// TestSaturationGates_AreIndependentPerPool pins the scope decision. A session's request
// and notification pools saturate independently, so they hold separate gates: a
// notification flood must not elide the request pool's saturation record, which is the
// cross-talk that makes a shared proxy-wide bucket the wrong home for these.
func TestSaturationGates_AreIndependentPerPool(t *testing.T) {
	t.Parallel()
	var sess httpSession

	if ok, _ := sess.notifySaturation.admit(); !ok {
		t.Fatal("the notification pool's first refusal must record")
	}
	if ok, _ := sess.notifySaturation.admit(); ok {
		t.Fatal("the notification pool must collapse its own episode")
	}
	if ok, _ := sess.reqSaturation.admit(); !ok {
		t.Fatal("the request pool's record must survive a concurrent notification episode")
	}
	// Draining one pool must not re-arm the other.
	sess.notifySaturation.clear()
	if ok, _ := sess.reqSaturation.admit(); ok {
		t.Fatal("clearing the notification gate must not re-arm the request gate")
	}
}

// TestPreSessionLimiterAndSaturationGate_DoNotShareABucket pins that the two admission
// controls are separate instances. A shared bucket would let one session's notification
// flood elide the AUTH_FAILED / ORIGIN_REJECTED records an incident responder reads first,
// and would make suppressed_count on any one record a tally of refusals it has nothing to
// do with.
func TestPreSessionLimiterAndSaturationGate_DoNotShareABucket(t *testing.T) {
	t.Parallel()
	preSession := newRefusalRecordLimiter()
	var g saturationGate

	// Drain the saturation gate's bucket via the flip-flop pattern.
	for i := 0; i < saturationRecordBurst+10; i++ {
		_, _ = g.admit()
		g.clear()
	}
	if ok, _ := g.admit(); ok {
		t.Fatal("the saturation bucket must be drained for this test to mean anything")
	}
	// The pre-session bucket is untouched by that.
	if ok, _, _ := preSession.admit(catAuth); !ok {
		t.Fatal("a saturation flood must not spend the pre-session refusal budget")
	}
}

// TestPerCategoryShare_DividesTheAggregateEvenly keeps each category's bucket at the share the
// design intends. The aggregate is derived from len(refusalCategories) now rather than mirrored in
// a hand-typed count, so the failure this guards is no longer a stale constant but an uneven
// division: the floor would silently round a category's share down.
func TestPerCategoryShare_DividesTheAggregateEvenly(t *testing.T) {
	t.Parallel()
	if int(perCategoryDenyRate) != perCategoryDenyRatePerSec || int(perCategoryDenyBurst) != perCategoryDenyBurstSize {
		t.Errorf("per-category share = %v/%v, want %d/%d", perCategoryDenyRate, perCategoryDenyBurst, perCategoryDenyRatePerSec, perCategoryDenyBurstSize)
	}
}
