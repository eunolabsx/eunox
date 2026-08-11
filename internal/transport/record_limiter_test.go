// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/pkg/capability"
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
	if !preSession.admitRefusal(catAuth).ok {
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

// TestUpstreamRefusalFloor_SiblingKeepsItsFirstRecord is the gap the per-session TABLE alone left,
// one axis over from the notice half's.
//
// The child and the parent are the same rate, so a session flooding one category is paced by its
// own bucket to exactly the rate the parent refills at, and a sibling's FIRST record arrives to find
// the parent empty. What is elided there is evidence — the record saying a live in-flight request
// was evicted — not stderr legibility, which is why the floor is worth its cost here even though a
// floored record is an audit WRITE.
//
// The refusal this floor answers is the PARENT's, which is the opposite of the notice half's, and
// for a reason rather than by symmetry: a record holder owns its whole table, so its own bucket
// refusing means it outran its own budget, and its peers contend one tier up.
func TestUpstreamRefusalFloor_SiblingKeepsItsFirstRecord(t *testing.T) {
	t.Parallel()
	at := time.Now()
	aggregate := newRefusalRecordLimiter()
	aggregate.setNow(func() time.Time { return at })

	drain := func(lim *categoryRecordLimiter, n int) int {
		lim.setNow(func() time.Time { return at })
		admitted := 0
		for range n {
			if admitRefusalRecord(&fwdRecorder{}, lim, catDisplaced) != nil {
				admitted++
			}
		}
		return admitted
	}

	a := newUpstreamRefusalLimiter(aggregate, upstreamRefusalCategories)
	require.Positive(t, drain(a, 200), "A's leading edge reaches the tape")
	require.Zero(t, aggregate.bucket(catDisplaced).tokens > 1,
		"A's flood must have drained the shared parent; otherwise this test proves nothing")

	b := newUpstreamRefusalLimiter(aggregate, upstreamRefusalCategories)
	assert.Equal(t, 1, drain(b, 5),
		"a sibling session's first record must survive a flood that has emptied the parent; a table alone paces A to exactly the parent's refill rate")
	assert.Zero(t, drain(b, 5),
		"and it is one record per category per interval, not a second budget")
}

// TestUpstreamRefusalFloor_IsPerCategory keeps the record floor from being spent on the wrong
// evidence: a session whose upstream floods one category must not thereby lose the floor for the
// category that says a LIVE in-flight request was evicted.
func TestUpstreamRefusalFloor_IsPerCategory(t *testing.T) {
	t.Parallel()
	at := time.Now()
	aggregate := newRefusalRecordLimiter()
	aggregate.setNow(func() time.Time { return at })
	flooder := newUpstreamRefusalLimiter(aggregate, upstreamRefusalCategories)
	flooder.setNow(func() time.Time { return at })
	for range 200 {
		_ = admitRefusalRecord(&fwdRecorder{}, flooder, catServerRequestFailed)
	}

	sibling := newUpstreamRefusalLimiter(aggregate, upstreamRefusalCategories)
	sibling.setNow(func() time.Time { return at })
	assert.NotNil(t, admitRefusalRecord(&fwdRecorder{}, sibling, catServerRequestFailed),
		"the flooded category's own floor still delivers this session's first record")
	assert.NotNil(t, admitRefusalRecord(&fwdRecorder{}, sibling, catDisplaced),
		"and a category this session has not written keeps its own floor; categories do not share one")
}

// TestUpstreamRefusalFloor_AggregateStillHoldsTheTotal is the bound that makes a floored AUDIT
// write affordable at all. The parent exists because per-session buckets multiply the sustained
// write rate into one 4096-deep queue by the session count under a --require-audit that defaults to
// strict, so the floor must not reopen that: a floored record DEBITS the tier that refused it, so
// it displaces the flooder's next record rather than adding to the total.
func TestUpstreamRefusalFloor_AggregateStillHoldsTheTotal(t *testing.T) {
	t.Parallel()
	at := time.Now()
	aggregate := newRefusalRecordLimiter()
	aggregate.setNow(func() time.Time { return at })

	const sessions = 50
	admitted := 0
	for range sessions {
		lim := newUpstreamRefusalLimiter(aggregate, upstreamRefusalCategories)
		lim.setNow(func() time.Time { return at })
		for range 20 {
			if admitRefusalRecord(&fwdRecorder{}, lim, catDisplaced) != nil {
				admitted++
			}
		}
	}
	assert.LessOrEqual(t, admitted, int(perCategoryDenyBurst)+sessions,
		"N sessions must not multiply the sustained audit-write rate by N: the parent bounds the total and the floor adds at most one record per session per interval")
	assert.GreaterOrEqual(t, admitted, sessions,
		"every session's first record is the whole point; a bound that elides it is the gap this closes")
	assert.GreaterOrEqual(t, aggregate.bucket(catDisplaced).tokens, -perCategoryDenyBurst,
		"the debt the floors ran up is clamped at one burst, so the aggregate recovers rather than staying shut")
}

// TestRecordFloor_NotClaimedWhenTheHoldersOwnBucketRefused pins the direction the record half's
// floorTier declares, which is the notice half's inverted. A session that outran its OWN table is
// not owed an arrival: nobody else caused that refusal, and flooring it would hand every flooding
// session a bonus record per interval on top of its share.
func TestRecordFloor_NotClaimedWhenTheHoldersOwnBucketRefused(t *testing.T) {
	t.Parallel()
	at := time.Now()
	// No aggregate: every refusal below is this session's own bucket refusing.
	lim := newUpstreamRefusalLimiter(nil, upstreamRefusalCategories)
	lim.setNow(func() time.Time { return at })

	admitted := 0
	for range 200 {
		if admitRefusalRecord(&fwdRecorder{}, lim, catDisplaced) != nil {
			admitted++
		}
	}
	assert.LessOrEqual(t, admitted, int(perCategoryDenyBurst),
		"a holder's own budget is the whole answer to its own flood; a floor on top is a second budget")
}

// TestFloorTier_ZeroValueFloorsNothing pins the enum's fail-safe default. floorNowhere is what a
// table that never declared where its holder's peers contend resolves to, and the safe answer for
// "nobody decided" is the one that hands out no writes outside a bucket.
func TestFloorTier_ZeroValueFloorsNothing(t *testing.T) {
	t.Parallel()
	at := time.Now()
	table := newTieredBuckets(1, 1, recordReserveInterval, []refusalCategory{catDisplaced}, nil, "test", floorNowhere)
	table.setNow(func() time.Time { return at })
	reserve := newKeyReserve([]refusalCategory{catDisplaced})

	admitted := 0
	for range 20 {
		if table.admitWithFloor(catDisplaced, reserve.forKey(catDisplaced)).ok {
			admitted++
		}
	}
	assert.Equal(t, 1, admitted, "an undeclared floor tier must consult no floor at all")
}

// TestReserveSlot_ReArmIsMonotonicAndHasNoEpochSentinel pins the two ways a naive encoding of "when
// was this last claimed" goes wrong, both of which the floor's whole purpose is sensitive to.
func TestReserveSlot_ReArmIsMonotonicAndHasNoEpochSentinel(t *testing.T) {
	t.Parallel()

	t.Run("a backwards wall-clock step does not lock the reserve", func(t *testing.T) {
		// time.Now() carries a monotonic reading; a wall-clock step moves only the wall part, which
		// is what an NTP correction or a VM resume does. An interval measured on the wall clock
		// would refuse every floored write for the length of the step, while every bucket in the
		// same table kept refilling — the exact elision the floor exists to close.
		var slot reserveSlot
		now := time.Now()
		require.True(t, slot.claim(now, recordReserveInterval))
		stepped := now.Add(-10 * time.Minute)
		assert.False(t, slot.claim(stepped, recordReserveInterval),
			"a step alone must not re-arm the reserve either")
		assert.True(t, slot.claim(now.Add(recordReserveInterval), recordReserveInterval),
			"the monotonic reading is what decides; a wall-clock comparison would still be counting down from the step")
	})

	t.Run("the Unix epoch is not a never-claimed sentinel", func(t *testing.T) {
		// An int64 nanosecond encoding has no value outside the clock's range to mean "unclaimed",
		// so a clock reading exactly the epoch stored 0 and read back as never claimed — an
		// unbounded bypass of both tiers, driven by a fake clock this package already uses
		// elsewhere (time.Unix(0, ns)).
		var slot reserveSlot
		epoch := time.Unix(0, 0)
		require.True(t, slot.claim(epoch, recordReserveInterval))
		assert.False(t, slot.claim(epoch, recordReserveInterval), "the reserve is one write per interval, whatever the clock reads")
	})
}

// TestReserveSlot_OneReadingPerAdmission pins claim's contract against the two-tier case, which is
// the one where "which clock" is answerable more than one way.
//
// The instant comes from the bucket the caller ADMITTED THROUGH, not from each tier's own clock:
// re-sampling per tier would let a floor's interval be measured against a different instant than
// the refill that refused it, and setNow deliberately does not descend, so a floor slaved to the
// parent's clock would be uncontrollable from the tier a test drives.
func TestReserveSlot_OneReadingPerAdmission(t *testing.T) {
	t.Parallel()
	at := time.Now()
	aggregate := newRefusalRecordLimiter()
	// The parent is left on the REAL clock on purpose: freezing the tier admitted through must be
	// enough to control the floor's re-arm.
	sess := newUpstreamRefusalLimiter(aggregate, upstreamRefusalCategories)
	sess.setNow(func() time.Time { return at })
	for range 200 {
		_ = admitRefusalRecord(&fwdRecorder{}, newUpstreamRefusalLimiter(aggregate, upstreamRefusalCategories), catDisplaced)
	}

	require.NotNil(t, admitRefusalRecord(&fwdRecorder{}, sess, catDisplaced), "the floor delivers the first one")
	assert.Nil(t, admitRefusalRecord(&fwdRecorder{}, sess, catDisplaced),
		"a frozen entry tier must hold the reserve spent however long the wall clock runs")
	at = at.Add(2 * recordReserveInterval)
	sess.setNow(func() time.Time { return at })
	assert.NotNil(t, admitRefusalRecord(&fwdRecorder{}, sess, catDisplaced),
		"and advancing that same tier is what re-arms it")
}

// TestBorrow_DebtNeverExceedsOneBurst pins the clamp against a FRACTIONAL balance, which is the
// only shape that catches a clamp tested before the decrement rather than after it — and the shape
// every real clock produces, since a partial refill is the normal state of a flooded bucket.
func TestBorrow_DebtNeverExceedsOneBurst(t *testing.T) {
	t.Parallel()
	at := time.Now()
	b := newRecordRateLimiter(2, 5)
	b.now = func() time.Time { return at }
	for range 10 {
		_, _, _ = b.admit()
	}
	// A partial refill, so the balance is not a whole number of tokens.
	at = at.Add(150 * time.Millisecond)
	for range 50 {
		b.borrow()
	}
	assert.GreaterOrEqual(t, b.tokens, -5.0,
		"the debt is clamped at one burst; testing the pre-decrement balance overshoots by a token and adds (1/rate) seconds to the tier's recovery")
}

// TestUpstreamRefusalFloor_DelegatedCategoryStillFloors is the gap a reserve keyed on the table's
// OWN categories left. A narrowed session table (a remote upstream reaches at most one of the four)
// delegates the rest wholly to the aggregate, and a floor built from the same narrowed set gives
// those exactly no reserve — the elision this floor exists to close, surviving for one session kind
// while the aggregate's own floorTier claimed to serve it.
func TestUpstreamRefusalFloor_DelegatedCategoryStillFloors(t *testing.T) {
	t.Parallel()
	at := time.Now()
	aggregate := newRefusalRecordLimiter()
	aggregate.setNow(func() time.Time { return at })

	flooder := newUpstreamRefusalLimiter(aggregate, upstreamRefusalCategories)
	flooder.setNow(func() time.Time { return at })
	for range 200 {
		_ = admitRefusalRecord(&fwdRecorder{}, flooder, catDisplaced)
	}

	narrowed := newUpstreamRefusalLimiter(aggregate, remoteUpstreamRefusalCategories)
	narrowed.setNow(func() time.Time { return at })
	require.Nil(t, narrowed.buckets[catDisplaced], "this test is about a category the narrowed table has no bucket for")
	assert.NotNil(t, admitRefusalRecord(&fwdRecorder{}, narrowed, catDisplaced),
		"a delegated category contends with its peers at the tier it delegates TO, so its floor must be claimable there")
}

// TestUpstreamRefusalFloor_RecordSaysItWasFloored keeps the evidence legible. A record that exists
// only because the reserve delivered it is otherwise byte-identical to one the tier had room for,
// so an auditor reading the tape during a saturation sees clean records and no sign that sibling
// holders' records are being dropped wholesale.
func TestUpstreamRefusalFloor_RecordSaysItWasFloored(t *testing.T) {
	t.Parallel()
	at := time.Now()
	aggregate := newRefusalRecordLimiter()
	aggregate.setNow(func() time.Time { return at })
	flooder := newUpstreamRefusalLimiter(aggregate, upstreamRefusalCategories)
	flooder.setNow(func() time.Time { return at })
	for range 200 {
		_ = admitRefusalRecord(&fwdRecorder{}, flooder, catDisplaced)
	}

	rec := &fwdRecorder{}
	sibling := newUpstreamRefusalLimiter(aggregate, upstreamRefusalCategories)
	sibling.setNow(func() time.Time { return at })
	floored := admitRefusalRecord(rec, sibling, catDisplaced)
	require.NotNil(t, floored, "the sibling's first record is delivered on its reserve")
	floored.RecordDeny(context.Background(), "s", "", "roots/list", capability.ErrCodeEnforcementError, "", nil, false)

	require.Len(t, rec.records, 1)
	assert.Equal(t, true, rec.records[0].details[detailRefusalFloored],
		"a floored record must say so: its arrival is the one that does not mean the tier had room")

	// An ordinary admitted record must NOT carry it, or the marker says nothing.
	plain := &fwdRecorder{}
	quiet := newUpstreamRefusalLimiter(nil, upstreamRefusalCategories)
	quiet.setNow(func() time.Time { return at })
	admitRefusalRecord(plain, quiet, catDisplaced).RecordDeny(context.Background(), "s", "", "roots/list", capability.ErrCodeEnforcementError, "", nil, false)
	require.Len(t, plain.records, 1)
	assert.NotContains(t, plain.records[0].details, detailRefusalFloored)
}
