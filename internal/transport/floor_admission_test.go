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
// structure is recursive and the debit used to be positional: what this asserts is that the
// invariant the whole floor design rests on — a floored arrival displaces the FLOODER's next write
// rather than adding to the tier's total — is a property of the code rather than of there happening
// to be exactly two tiers.
func threeTierChain(at time.Time) (child, middle, grand *tieredBuckets[refusalCategory]) {
	g := newTieredBuckets(1, 1, recordReserveInterval, []refusalCategory{catDisplaced}, nil, "grand", floorOwnBucket)
	m := newTieredBuckets(50, 50, recordReserveInterval, []refusalCategory{catDisplaced}, &g, "middle", floorParentBucket)
	c := newTieredBuckets(50, 50, recordReserveInterval, []refusalCategory{catDisplaced}, &m, "child", floorParentBucket)
	// setNow deliberately does not descend, so each tier is frozen explicitly.
	for _, t := range []*tieredBuckets[refusalCategory]{&c, &m, &g} {
		t.setNow(func() time.Time { return at })
	}
	return &c, &m, &g
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

// TestFlooredWrite_UnsuppressionLandsOnTheRefusingTier is the same defect one field over: borrow
// also decrements a suppression tally, and taking it from a tier that had just PUSHED one back
// under-states a flood on the next line that reports it.
func TestFlooredWrite_UnsuppressionLandsOnTheRefusingTier(t *testing.T) {
	t.Parallel()
	// Differential rather than absolute: every pass through a drained tier adds a suppression of
	// its own, so what has to be isolated is the effect of the FLOORED delivery alone. The same
	// sequence is run twice — once with a live floor, once without — and the difference between
	// them is exactly what borrow did.
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
	assert.Equal(t, refusedMiddle, flooredMiddle,
		"and never off a tier that admitted it: that tally is writes this tier really did elide, and taking one under-states the flood on the next line reporting it")
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
	for range int(perCategoryDenyBurst) + 1 {
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
	for range int(perCategoryDenyBurst) + 1 {
		if p.recordRefusal(context.Background(), req, nil, codeAuthFailed, catAuth, nil) {
			admitted++
		}
	}
	assert.Equal(t, int(perCategoryDenyBurst)+1, admitted,
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
	for range int(perCategoryDenyBurst) {
		require.True(t, session.admitRefusal(catDisplaced).ok)
	}
	require.True(t, session.admitRefusal(catDisplaced).reserved, "the drained aggregate is floored through")

	// Two minutes on, the parent's bucket has refilled, so drain it again to put the floor back in
	// play: what is under test is whether the SLOT re-armed, not whether a token is available.
	now = at.Add(2 * time.Minute)
	for range int(perCategoryDenyBurst) {
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
