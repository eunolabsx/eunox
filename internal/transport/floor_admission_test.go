// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The three properties the floor's wiring rests on and none of which the mechanism can state for
// itself: that a floored write debits the tier that actually REFUSED (however deep the chain is),
// that every refusal record reaches the buckets through the one admission that resolves the floor,
// and that the interval a floor re-arms on belongs to the table rather than to the package.

package transport

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// threeTierChain builds child -> middle -> grandparent over one key, every bucket on the same
// frozen clock, sized so only the grandparent can be the tier that refuses.
//
// Three tiers do not exist in production and are not planned. They are built here because the
// structure is recursive and both halves of a floored delivery — which bucket goes into debt for
// it, and which tallies stop counting it as elided — were written for a chain that happened to be
// two deep. What this asserts is that the invariant the whole floor design rests on — a floored
// arrival displaces the FLOODER's next write rather than adding to the tier's total, and no tier
// reports it as a write the reader did not see — is a property of the code rather than of the
// depth.
func threeTierChain(at time.Time) (child, middle, grand *tieredBuckets[refusalCategory]) {
	g := newTieredBuckets(1, 1, recordReserveInterval, []refusalCategory{catDisplaced}, nil, "grand", floorOwnBucket)
	m := newTieredBuckets(50, 50, recordReserveInterval, []refusalCategory{catDisplaced}, g, "middle", floorParentBucket)
	c := newTieredBuckets(50, 50, recordReserveInterval, []refusalCategory{catDisplaced}, m, "child", floorParentBucket)
	// setNow deliberately does not descend, so each tier is frozen explicitly.
	for _, t := range []*tieredBuckets[refusalCategory]{c, m, g} {
		t.setNow(func() time.Time { return at })
	}
	return c, m, g
}

// TestFlooredWrite_DebitsTheTierThatRefused pins the debit to the REFUSING tier rather than to the
// one directly above the floor's holder.
//
// admitWithFloor reports !ok for a refusal anywhere in the chain above, so reaching through exactly
// one level to debit was correct only while the chain was two deep. With a third tier it charged a
// middle tier that had ADMITTED — spending a token and pushing its tally back — and left the tier
// that refused untouched, which is precisely the tier sized to hold the aggregate. Nothing detected
// it: bucket() recurses past a refusing tier without noticing.
func TestFlooredWrite_DebitsTheTierThatRefused(t *testing.T) {
	t.Parallel()
	at := time.Now()
	child, middle, grand := threeTierChain(at)

	// Drain the grandparent (burst 1) so it is the one tier with nothing left.
	require.True(t, grand.admitWithFloor(catDisplaced, nil).ok)
	require.Zero(t, grand.buckets[catDisplaced].tokens)

	// Every refusal names its refuser, at every depth: the floor's debit dereferences it, so a
	// refusal path that returned none would be a nil panic on the arrival guarantee.
	refused := child.admitWithFloor(catDisplaced, nil)
	require.False(t, refused.ok)
	assert.Same(t, grand.buckets[catDisplaced], refused.refusedBy,
		"a refusal reported up through two tiers must still name the bucket that produced it")
	middleBefore := middle.buckets[catDisplaced].tokens

	floor := newKeyReserve([]refusalCategory{catDisplaced})
	verdict := child.admitWithFloor(catDisplaced, floor.forKey(catDisplaced))
	require.True(t, verdict.ok, "the holder's floor must still deliver the write")
	assert.True(t, verdict.reserved, "and say it arrived on the floor rather than on a token")

	assert.Equal(t, float64(-1), grand.buckets[catDisplaced].tokens,
		"the tier that REFUSED is the one that goes into debt for the floored write; anything else stops the floor displacing the flooder's next write at the tier sized to hold the aggregate")
	assert.Equal(t, middleBefore-1, middle.buckets[catDisplaced].tokens,
		"the middle tier pays only for its own admission — it already spent a token on this write, and debiting it again would charge one write twice")
}

// TestFlooredWrite_UnsuppressionLandsOnEveryTierThatCountedIt is the same defect one field over:
// borrow also decrements a suppression tally, and a floored delivery has to be taken off EVERY tier
// that counted it as elided — the one that refused, and each one between that refusal and the floor
// that pushed its own tally back on the way up believing the write would not happen.
//
// The refusing tier's half was structural already (bucketVerdict.refusedBy). The intermediate half
// was not: an admitting tier's push-back is taken before any descendant's floor has decided, so a
// chain three or more deep counted a DELIVERED write as suppressed and over-stated the flood by one
// on the next record reporting it.
func TestFlooredWrite_UnsuppressionLandsOnEveryTierThatCountedIt(t *testing.T) {
	t.Parallel()
	// Differential rather than absolute: every pass through a drained tier adds a suppression of
	// its own, so what has to be isolated is the effect of the FLOORED delivery alone. The same
	// sequence is run twice — once with a live floor, once without — and the difference between
	// them is exactly what the delivery did.
	run := func(withFloor bool) (grandTally, middleTally uint64) {
		at := time.Now()
		child, middle, grand := threeTierChain(at)
		require.True(t, grand.admitWithFloor(catDisplaced, nil).ok) // drain the grandparent
		require.False(t, child.admitWithFloor(catDisplaced, nil).ok)
		var floor *reserveSlot
		if withFloor {
			floor = newKeyReserve([]refusalCategory{catDisplaced}).forKey(catDisplaced)
		}
		assert.Equal(t, withFloor, child.admitWithFloor(catDisplaced, floor).ok)
		return grand.buckets[catDisplaced].suppressed, middle.buckets[catDisplaced].suppressed
	}
	flooredGrand, flooredMiddle := run(true)
	refusedGrand, refusedMiddle := run(false)

	assert.Equal(t, refusedGrand-1, flooredGrand,
		"the write happened, so it comes off the tally of the tier that ELIDED it — the rollup states what the reader did not see")
	assert.Equal(t, refusedMiddle-1, flooredMiddle,
		"and off the tier between them too: it pushed its token's worth of tally back on the way up for a write that then happened, and a tally holding a delivered write over-states the flood on the next record reporting it")

	// The debit is deliberately NOT taken here: an intermediate tier spent a token on this write
	// when it admitted it, and charging a second would count one write twice at the tier sized to
	// hold the aggregate. TestFlooredWrite_DebitsTheTierThatRefused pins that half.
}

// TestFlooredWrite_ADelegatingTierIsLeftAlone is the other shape a chain can have: a middle tier
// holding no bucket for the key forwards the admission wholly upward, so it counted nothing and
// there is nothing to take back from it.
//
// The distinction matters because the correction walks the parent chain rather than a list carried
// on the verdict: a walk that decremented every tier it passed would invent a suppression on a tier
// that never admitted, never refused and never pushed a tally back — under-stating the next flood
// it does report.
func TestFlooredWrite_ADelegatingTierIsLeftAlone(t *testing.T) {
	t.Parallel()
	at := time.Now()
	grand := newTieredBuckets(1, 1, recordReserveInterval, []refusalCategory{catDisplaced}, nil, "grand", floorOwnBucket)
	// No bucket for catDisplaced: this tier delegates the key wholly to its parent.
	middle := newTieredBuckets(50, 50, recordReserveInterval, []refusalCategory{catKill}, grand, "middle", floorParentBucket)
	child := newTieredBuckets(50, 50, recordReserveInterval, []refusalCategory{catDisplaced}, middle, "child", floorParentBucket)
	for _, tier := range []*tieredBuckets[refusalCategory]{child, middle, grand} {
		tier.setNow(func() time.Time { return at })
	}

	require.True(t, grand.admitWithFloor(catDisplaced, nil).ok) // drain the grandparent
	require.False(t, child.admitWithFloor(catDisplaced, nil).ok)
	killBefore := middle.buckets[catKill].suppressed
	grandBefore := grand.buckets[catDisplaced].suppressed

	floor := newKeyReserve([]refusalCategory{catDisplaced}).forKey(catDisplaced)
	verdict := child.admitWithFloor(catDisplaced, floor)
	require.True(t, verdict.ok)
	assert.True(t, verdict.reserved)
	assert.Equal(t, float64(-1), grand.buckets[catDisplaced].tokens,
		"the debit still reaches the tier that refused, through a tier that only forwarded the answer")

	// The assertion with teeth, on the key actually under test: the refusing tier is corrected
	// EXACTLY once, by borrow. A walk that corrected every tier it passed rather than stopping at
	// the refuser takes a second write off it and under-states the next flood grand reports —
	// verified by mutation, which is what distinguishes this from a check that holds under any
	// implementation. (Resolving each tier through bucket() instead of its own map is NOT caught
	// here: that recursion lands on the refuser, which the stop then answers.)
	assert.Equal(t, grandBefore, grand.buckets[catDisplaced].suppressed,
		"the refuser's tally moves by its own refusal and borrow's correction only; a delegating tier must not deliver a second decrement of the bucket it forwards to")
	assert.Equal(t, killBefore, middle.buckets[catKill].suppressed,
		"and a delegating tier's OTHER buckets are untouched: the correction is per key, and this tier carried nothing under the key being delivered")
}

// TestExemptCategory_IsUnboundedOnBothSpellings pins the declaration against the admission, on the
// axis where the two spellings of a refusal write disagreed.
//
// An exempt category is deliberately absent from refusalCategories, so it holds no bucket — and an
// unregistered key on a parentless table falls to the floor-rate `unknown` fallback (1/s, burst 1).
// forCategory read the exemption and short-circuited; recordRefusal's admission did not, so the
// pre-session spelling throttled a DECLARED-EXEMPT refusal five times harder than a metered one.
// The exemption rests on "a policy verdict may never be metered", which makes eliding 19 in 20 the
// exact failure it was written to prevent.
func TestExemptCategory_IsUnboundedOnBothSpellings(t *testing.T) {
	t.Parallel()
	at := time.Now()
	limiter := newRefusalRecordLimiter()
	limiter.setNow(func() time.Time { return at })
	require.Equal(t, meteringExempt, refusalDeclarations[catUnroutable].metering,
		"this test is about a category the table declares exempt")
	require.NotContains(t, limiter.buckets, catUnroutable, "which is therefore absent from the bucket table")

	admitted := 0
	for range 20 {
		if limiter.admitRefusal(catUnroutable).ok {
			admitted++
		}
	}
	assert.Equal(t, 20, admitted,
		"an exempt category charges no bucket on the admission both spellings share; falling to the unknown fallback made it the most throttled refusal in the tree")

	// The control, on the same drained table: a METERED category is still bounded, so what the
	// exemption buys is not a hole in the admission.
	metered := 0
	for range 20 {
		if limiter.admitRefusal(catOrigin).ok {
			metered++
		}
	}
	assert.Positive(t, metered)
	assert.Less(t, metered, 20, "a metered category is still bounded by its own bucket")

	// And the recorder-resolving spelling agrees, which is the property that was only true because
	// it read the declaration a second time.
	assert.NotNil(t, refusalRecorders{rec: &fwdRecorder{}, limits: refusalLimits{records: limiter}}.forCategory(catUnroutable),
		"the exemption resolves the same on either spelling, from one reader")
}

// TestFlooredWrite_WindowIsSizedByTheRefusingTiersBudget pins which table's interval a floored
// write's window comes from.
//
// The delegation branch states the rule: the window a floored write buys is a property of the
// BUDGET it is charged against. On the floorParentBucket arm that budget is the parent's — its
// bucket refused and its bucket is debited — while the interval was read from the child, so a
// per-holder table tuned with a shorter interval than the aggregate it charges would bypass the
// aggregate's drained bucket at the HOLDER's rate. Inert today (both record tables pass
// recordReserveInterval), which is exactly why the assertion has to exist: reserveEvery is a
// per-table constructor parameter whose own doc says the two budgets are not interchangeable.
func TestFlooredWrite_WindowIsSizedByTheRefusingTiersBudget(t *testing.T) {
	t.Parallel()
	at := time.Now()
	// The aggregate re-arms a floor once an hour; the holder's table, once a millisecond. The
	// holder floors against the AGGREGATE's refusal, so the hour is the window that applies.
	aggregate := newTieredBuckets(1, 1, time.Hour, []refusalCategory{catDisplaced}, nil, "aggregate", floorOwnBucket)
	session := newTieredBuckets(50, 50, time.Millisecond, []refusalCategory{catDisplaced}, aggregate, "session", floorParentBucket)
	for _, tier := range []*tieredBuckets[refusalCategory]{session, aggregate} {
		tier.setNow(func() time.Time { return at })
	}
	require.True(t, aggregate.admitWithFloor(catDisplaced, nil).ok) // drain the aggregate

	floor := newKeyReserve([]refusalCategory{catDisplaced}).forKey(catDisplaced)
	require.True(t, session.admitWithFloor(catDisplaced, floor).ok, "the holder's floor delivers the first one")

	// Past the holder's own interval by three orders of magnitude, and nowhere near the
	// aggregate's: the floor must still be spent.
	at = at.Add(time.Second)
	session.setNow(func() time.Time { return at })
	assert.False(t, session.admitWithFloor(catDisplaced, floor).ok,
		"a floored write past the AGGREGATE's drained bucket buys the aggregate's window; reading the holder's would let a per-holder knob loosen a bound sized for the whole process")

	at = at.Add(time.Hour)
	session.setNow(func() time.Time { return at })
	assert.True(t, session.admitWithFloor(catDisplaced, floor).ok,
		"and it re-arms on that same window, not on the one the flooring tier happens to carry")
}

// TestFlooredWrite_ZeroIntervalIsRefusedRatherThanUnbounded pins the direction a missing sizing
// answer fails in.
//
// The interval is a positional time.Duration in a seven-parameter constructor, so a table can be
// built with none. A zero makes `elapsed < every` false for every reading, which turns the floor
// from one arrival per window into an unconditional bypass of the bucket — on the record half, an
// unbounded audit-write rate past a drained tier under a strict-by-default --require-audit.
func TestFlooredWrite_ZeroIntervalIsRefusedRatherThanUnbounded(t *testing.T) {
	t.Parallel()
	at := time.Now()
	slot := &reserveSlot{}
	assert.False(t, slot.claim(at, 0), "an unsized floor delivers nothing rather than everything")
	assert.False(t, slot.claim(at, -time.Second))
	require.True(t, slot.claim(at, time.Minute), "and a sized one still answers")
}

// TestFlooredWrite_TwoTierChainIsUnchanged is the control: the fix is structural, so the shape that
// actually ships must behave exactly as before.
func TestFlooredWrite_TwoTierChainIsUnchanged(t *testing.T) {
	t.Parallel()
	at := time.Now()
	aggregate := newRefusalRecordLimiter()
	aggregate.setNow(func() time.Time { return at })
	session := newUpstreamRefusalLimiter(aggregate, upstreamRefusalCategories)
	session.setNow(func() time.Time { return at })

	// Drain the proxy-wide bucket through a sibling session, so this one's own tier still has
	// tokens and the parent is the tier that refuses.
	sibling := newUpstreamRefusalLimiter(aggregate, upstreamRefusalCategories)
	sibling.setNow(func() time.Time { return at })
	for range perCategoryDenyBurstSize + 1 {
		sibling.admitRefusal(catDisplaced)
	}
	require.Less(t, aggregate.bucket(catDisplaced).tokens, float64(1))

	verdict := session.admitRefusal(catDisplaced)
	require.True(t, verdict.ok, "a sibling's flood must not elide this session's first record")
	assert.True(t, verdict.reserved)
	assert.Equal(t, suppressedScopeSessionCategory, verdict.scope,
		"the count reported is this session's own")
	assert.Negative(t, aggregate.bucket(catDisplaced).tokens,
		"and the aggregate — the tier that refused — carries the debt")
}

// TestRefusalRecord_EveryWriteTakesTheAdmissionThatResolvesTheFloor pins the pre-session path to the
// same admission the four upstream-driven categories take.
//
// recordRefusal writes its record inline (it folds the rollup into details it is already building),
// which is why it took its verdict from the buckets directly. That agreed with the other spelling
// only because p.preSessionDenies happens to hold no floor: the day it gains one — a per-tenant or
// per-source-IP holder is exactly what would want it — all ten categories an unauthenticated caller
// can drive would have skipped it in silence.
func TestRefusalRecord_EveryWriteTakesTheAdmissionThatResolvesTheFloor(t *testing.T) {
	t.Parallel()
	at := time.Now()
	sink, logPath := newTempAuditSink(t)
	limiter := newRefusalRecordLimiter()
	limiter.setNow(func() time.Time { return at })
	// The floor a holder-bearing pre-session table would carry. Assigned here rather than shipped,
	// since what is under test is that the path READS whatever the table holds.
	limiter.floor = newKeyReserve(refusalCategories)

	p := &HTTPProxy{sink: sink, preSessionDenies: limiter}
	req := httptest.NewRequest("POST", "/mcp", strings.NewReader("{}"))

	admitted := 0
	for range perCategoryDenyBurstSize + 1 {
		if p.recordRefusal(context.Background(), req, nil, codeAuthFailed, catAuth, nil) {
			admitted++
		}
	}
	assert.Equal(t, perCategoryDenyBurstSize+1, admitted,
		"the write past the drained bucket is the holder's guaranteed arrival; reaching the buckets directly skipped the floor the table holds")

	// The floor is one write per interval, not a second budget.
	assert.False(t, p.recordRefusal(context.Background(), req, nil, codeAuthFailed, catAuth, nil),
		"and the floor stays spent for the interval, so honouring it is not a way around the bound")

	require.NoError(t, sink.Close())
	records := readAuditRecords(t, logPath)
	require.NotEmpty(t, records)
	last := records[len(records)-1]
	details, _ := last["details"].(map[string]interface{})
	require.NotNil(t, details)
	assert.Equal(t, true, details[detailRefusalFloored],
		"a floored record says so on the tape: its arrival does not mean the tier had room for it")
}

// TestReserveInterval_IsPerTableNotPerPackage pins the third sizing knob to the table beside the
// rate and the burst.
//
// One package constant governed two budgets whose floored writes fail differently — an audit record
// into a queue whose overflow denies the data plane under strict audit, against a stderr line an
// operator is watching — so neither could be sized without moving the other.
func TestReserveInterval_IsPerTableNotPerPackage(t *testing.T) {
	t.Parallel()
	assert.Equal(t, recordReserveInterval, newRefusalRecordLimiter().reserveEvery)
	assert.Equal(t, recordReserveInterval, newUpstreamRefusalLimiter(nil, upstreamRefusalCategories).reserveEvery)
	assert.Equal(t, noticeReserveInterval, newNoticeLimiter(1).reserveEvery)
	assert.Equal(t, noticeReserveInterval, newRouteNoticeLimiter(nil).reserveEvery)

	// The four above catch a dropped or zeroed parameter but cannot catch a TRANSPOSED one, since
	// the two constants are equal today. What distinguishes them is the behaviour: a slot measures
	// against the interval the admission hands it, not one of its own.
	at := time.Now()
	slot := &reserveSlot{}
	require.True(t, slot.claim(at, time.Minute))
	assert.False(t, slot.claim(at.Add(2*time.Second), time.Minute))
	assert.True(t, slot.claim(at.Add(2*time.Second), time.Second),
		"a table that declares a shorter interval re-arms its holders' floors sooner, which is the whole point of the knob being per table")

	// A key DELEGATED wholly upward is answered by the tier it reaches, interval included: the
	// write is charged against the parent's budget, so it re-arms on the parent's argument. Pinned
	// because both constants are a minute today, so the rule is otherwise invisible until the first
	// time somebody moves one.
	aggregate := newRefusalRecordLimiterFor(catDisplaced)
	aggregate.reserveEvery = time.Hour
	session := newUpstreamRefusalLimiter(aggregate, []refusalCategory{catServerRequestFailed})
	require.NotContains(t, session.buckets, catDisplaced, "the category under test must be a delegated one")

	now := at
	aggregate.setNow(func() time.Time { return now })
	session.setNow(func() time.Time { return now })
	for range perCategoryDenyBurstSize {
		require.True(t, session.admitRefusal(catDisplaced).ok)
	}
	require.True(t, session.admitRefusal(catDisplaced).reserved, "the drained aggregate is floored through")

	// Two minutes on, the parent's bucket has refilled, so drain it again to put the floor back in
	// play: what is under test is whether the SLOT re-armed, not whether a token is available.
	now = at.Add(2 * time.Minute)
	for range perCategoryDenyBurstSize {
		require.True(t, session.admitRefusal(catDisplaced).ok)
	}
	assert.False(t, session.admitRefusal(catDisplaced).ok,
		"the floor re-arms on the interval of the table that ANSWERED — the parent's hour, not the child's minute, since the write is charged against the parent's budget")
}

// TestReserveCeiling_IsDerivedFromTheLiveSets computes the floored-write ceiling the two interval
// constants document, from the sets it is actually made of.
//
// The figure is `holders x keys` over three sets living in two other files, and it has already
// drifted once in prose (it counted three notice keys where a session holds four). Deriving it here
// is what keeps the arithmetic in those doc blocks from being a claim nobody re-checks.
func TestReserveCeiling_IsDerivedFromTheLiveSets(t *testing.T) {
	t.Parallel()
	// The two inputs this package cannot see: cmd/eunox's defaultMaxSessions (that package depends
	// on this one, not the reverse) and internal/audit's auditChannelSize (unexported). Copied here
	// rather than derived, so each is held to its own source by a tripwire beside that source —
	// TestDefaultMaxSessions_IsTheHolderCountTheReserveCeilingAssumes and
	// TestAuditChannelSize_IsTheQueueDepthTheReserveCeilingAssumes — which name this test when they
	// fail. Without them the arithmetic below re-checks nothing about the two numbers a future
	// change is most likely to move.
	const documentedHolders = 512
	const documentedAuditQueueDepth = 4096

	recordKeys := len(upstreamRefusalCategories)
	noticeKeys := len(noticeClasses) + len(floorProtectedSites)
	require.Equal(t, 4, recordKeys, "recordReserveInterval's doc states 512x4; a session reserves one slot per upstream-driven category")
	require.Equal(t, 4, noticeKeys, "noticeReserveInterval's doc states 512x4; a session reserves one slot per notice class plus one per protected site")

	assert.Equal(t, 2048, documentedHolders*recordKeys, "the record half's documented leading-edge burst")
	assert.Equal(t, 2048, documentedHolders*noticeKeys, "the notice half's documented leading-edge burst")
	assert.Equal(t, 34, int(float64(documentedHolders*recordKeys)/recordReserveInterval.Seconds()),
		"and the sustained rate after that burst, ~34/s")
	assert.Equal(t, 34, int(float64(documentedHolders*noticeKeys)/noticeReserveInterval.Seconds()))

	// The property the record-side figure exists to establish, rather than the figure itself: the
	// leading edge of a fleet-wide incident must not by itself overflow the audit queue, since an
	// overflow latches AuditDegraded and --require-audit defaults to strict.
	assert.Less(t, documentedHolders*recordKeys, documentedAuditQueueDepth,
		"a floored-write burst that fills the audit queue would turn the arrival guarantee into a data-plane outage")
}
