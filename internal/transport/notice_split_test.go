// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The two axes the single shared notice bucket collapsed, and the mechanism that picks a bucket.
//
// Every test here drives the admission directly rather than through a transport leg: what is under
// test is which bucket a line charges and what a flood of one can take from another, and a leg would
// only add the question of whether that leg is wired.

package transport

import (
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/internal/audit"
)

// frozen points every bucket in l at a fixed clock, so a burst is measured against the burst size
// rather than against how long the test took to run.
func frozen(l *noticeLimiter, at time.Time) {
	l.setNow(func() time.Time { return at })
}

// drive writes n lines for site through a channel with no session floor, and reports how many
// reached w.
func drive(w *strings.Builder, l *noticeLimiter, site noticeSite, n int) int {
	return driveSession(w, l, nil, site, n)
}

// driveSession is drive for a leg that has a SESSION behind it: the same table, plus that session's
// own reserved floor under it. It builds the channel itself rather than taking one, so the writer
// it counts newlines in cannot be a different writer from the one the lines went to.
func driveSession(w *strings.Builder, l *noticeLimiter, reserve *noticeReserve, site noticeSite, n int) int {
	before := w.Len()
	channel := noticeWriter{out: w, limits: l, reserve: reserve}
	for range n {
		if line, ok := channel.admitNotice(site); ok {
			line.writef("line\n")
		}
	}
	return strings.Count(w.String()[before:], "\n")
}

// claimAt spends the reserve a line from site (of class) would fall back on, as of at. The
// assertion shape the floor's own tests want: "was it still armed" is only answerable by taking it.
func claimAt(r *noticeReserve, site noticeSite, class noticeClass, at time.Time) bool {
	return r.forSite(site, class).claim(func() time.Time { return at })
}

// TestNoticeSplit_RefusalFloodCannotStarveAnUpstreamFailure pins the class split.
//
// refuseUnroutable's line is drivable at a peer's full send rate on the cheapest message it can
// send — no id, no handler slot, no upstream round trip. Sharing one bucket with `upstream error`
// meant a peer looping unmapped methods could hold it empty while a route's upstream started
// failing, and the operator saw no upstream line at all: only a suppression tail folded onto an
// unrelated refusal. The tape was never affected, so what this protects is stderr legibility during
// an incident.
func TestNoticeSplit_RefusalFloodCannotStarveAnUpstreamFailure(t *testing.T) {
	t.Parallel()
	limiter := newNoticeLimiter(1)
	frozen(limiter, time.Now())

	var out strings.Builder
	flood := drive(&out, limiter, siteUnmappedMethod, 500)
	assert.LessOrEqual(t, flood, perClassNoticeBurst, "the cheapest peer-driven line must still be bounded")

	failures := drive(&out, limiter, siteUpstreamError, 3)
	assert.Equal(t, 3, failures,
		"an upstream failure is a different class and must survive a refusal flood; sharing one bucket is what left an operator with no upstream-error line during an incident")
}

// TestNoticeSplit_FailureClassIsBoundedToo pins the other half: classing a line apart is not
// exempting it. A dead upstream drives its own line per frame just as a peer drives a refusal.
func TestNoticeSplit_FailureClassIsBoundedToo(t *testing.T) {
	t.Parallel()
	limiter := newNoticeLimiter(1)
	frozen(limiter, time.Now())

	var out strings.Builder
	written := drive(&out, limiter, siteUpstreamError, 500)
	assert.LessOrEqual(t, written, perClassNoticeBurst)
	assert.Positive(t, written, "a bucket that never admits is not bounding the line, it is silencing it")
}

// TestNoticeSplit_RollupNamesTheClassItSpans covers what an operator reads after a flood. One
// bucket serves several sites, so a bare count would be unattributable — and after the split it
// spans one CLASS, which the reader cannot infer from whichever line the count happens to ride on.
func TestNoticeSplit_RollupNamesTheClassItSpans(t *testing.T) {
	t.Parallel()
	now := time.Now()
	limiter := newNoticeLimiter(1)
	limiter.setNow(func() time.Time { return now })

	var out strings.Builder
	drive(&out, limiter, siteUnmappedMethod, 200)
	now = now.Add(time.Second)
	out.Reset()
	drive(&out, limiter, siteUnmappedMethod, 1)

	assert.Contains(t, out.String(), "further traffic diagnostics suppressed, proxy-wide",
		"the tail names the class AND the tier: after the route split the same sentence would otherwise mean one tenant on a gateway and the whole process here")
	assert.NotContains(t, out.String(), "failure",
		"the count spans the class it charged; naming another would tell an operator a flood happened where none did")
}

// TestNoticeSplit_OneRouteCannotSilenceASibling pins the route split.
//
// A peer looping `{"jsonrpc":"2.0","method":"x/bogus"}` at /mcp/routeA drained the single
// proxy-wide bucket and suppressed routeB's routing-refusal lines for as long as it kept sending.
// refuseUnroutable logs the method name so an operator can detect protocol drift, and a suppressed
// line keeps only a count — so what one tenant could take from another was the other's drift signal.
func TestNoticeSplit_OneRouteCannotSilenceASibling(t *testing.T) {
	t.Parallel()
	at := time.Now()
	aggregate := newNoticeLimiter(2)
	routeA, routeB := newRouteNoticeLimiter(aggregate), newRouteNoticeLimiter(aggregate)
	for _, l := range []*noticeLimiter{aggregate, routeA, routeB} {
		frozen(l, at)
	}

	var outA, outB strings.Builder
	drive(&outA, routeA, siteUnmappedMethod, 500)
	assert.Positive(t, drive(&outB, routeB, siteUnmappedMethod, 5),
		"one tenant's flood must not silence another's; an aggregate sized for every tenant is what makes the split mean something a shared bucket does not")
}

// TestNoticeSplit_AggregateCoversEveryTenantsShare is the sizing decision the route split rests on:
// the aggregate is derived from the tenant count so every route's own budget fits under it.
//
// The rejected alternative was dividing a FIXED aggregate. This is the test that would fail under
// it: at four routes integer division floors each share to a burst of 2, so a route with no flood
// anywhere gets two lines where the unsplit bucket gave ten — worse than not splitting, for exactly
// the incident the class split exists to keep legible.
func TestNoticeSplit_AggregateCoversEveryTenantsShare(t *testing.T) {
	t.Parallel()
	at := time.Now()
	const routes = 4
	aggregate := newNoticeLimiter(routes)
	frozen(aggregate, at)

	var out strings.Builder
	for range routes {
		route := newRouteNoticeLimiter(aggregate)
		frozen(route, at)
		assert.Equal(t, perClassNoticeBurst, drive(&out, route, siteUnmappedMethod, 100),
			"every tenant gets its whole share however many tenants there are; a share of a fixed aggregate floors to nothing past two")
	}
}

// TestNoticeSplit_AggregateStillBoundsTheTotal is the other side: a route's own table is not the only
// gate. Both tiers must admit, so a route cannot exceed what the aggregate was sized to give it —
// which is what keeps the parent meaningful rather than decorative.
func TestNoticeSplit_AggregateStillBoundsTheTotal(t *testing.T) {
	t.Parallel()
	at := time.Now()
	aggregate := newNoticeLimiter(1)
	frozen(aggregate, at)

	var out strings.Builder
	total := 0
	for range 3 {
		route := newRouteNoticeLimiter(aggregate)
		frozen(route, at)
		total += drive(&out, route, siteUnmappedMethod, 100)
	}
	assert.Equal(t, perClassNoticeBurst, total,
		"three routes under an aggregate sized for one share that one budget; dropping the parent link would let each spend its own")
}

// TestNoticeSplit_SingleRouteKeepsThePreSplitBudget guards the common deployment: one route (and
// stdio, which has no route tier at all) must not pay for a split it cannot benefit from.
func TestNoticeSplit_SingleRouteKeepsThePreSplitBudget(t *testing.T) {
	t.Parallel()
	at := time.Now()
	aggregate := newNoticeLimiter(1)
	route := newRouteNoticeLimiter(aggregate)
	frozen(aggregate, at)
	frozen(route, at)

	var out strings.Builder
	assert.Equal(t, perClassNoticeBurst, drive(&out, route, siteUnmappedMethod, 100))
}

// TestNoticeMechanism_ClassComesFromTheDeclaration pins the mechanism: the bucket a line charges is
// READ from its site's declaration at write time, the analogue of forCategory on the record half —
// not chosen by the call site, which is what let "declared metered" and "charges a bucket" disagree.
func TestNoticeMechanism_ClassComesFromTheDeclaration(t *testing.T) {
	t.Parallel()
	for site, class := range meteredNotices {
		// A FRESH table per site: one shared across the loop drains as sites accumulate, so the
		// "admitted nothing on a full bucket" arm would eventually fail naming an arbitrary site
		// (map order is randomized) for the crime of being visited last.
		limiter := newNoticeLimiter(1)
		frozen(limiter, time.Now())
		before := limiter.bucket(class).tokens
		var out strings.Builder
		if line, ok := (noticeWriter{out: &out, limits: limiter}).admitNotice(site); ok {
			line.writef("line\n")
		}
		require.NotEmpty(t, out.String(), "site %q admitted nothing on a full bucket", site)
		assert.Less(t, limiter.bucket(class).tokens, before,
			"site %q must charge the class its declaration names; a site that charges another bucket is the disagreement the runtime lookup exists to remove", site)
	}
}

// TestNoticeMechanism_UndeclaredSiteIsBoundedNotFree pins the fail-closed direction. The zero
// noticeDeclaration means nobody has answered the question for this site, and the safe answer to
// that is the bounded one — an undeclared site charging nothing would be a new unbounded per-frame
// syscall that only the AST walk could catch, which is exactly the weakness the mechanism replaces.
func TestNoticeMechanism_UndeclaredSiteIsBoundedNotFree(t *testing.T) {
	t.Parallel()
	limiter := newNoticeLimiter(1)
	frozen(limiter, time.Now())
	require.NotContains(t, meteredNotices, noticeSite("undeclared-probe"))

	var out strings.Builder
	written := drive(&out, limiter, "undeclared-probe", 100)
	assert.Positive(t, written)
	assert.LessOrEqual(t, written, perBucketFloor,
		"an undeclared site falls to the floor-rate fallback, not to a real class's share and not to writing free")
	// And it spent nothing of a declared class on the way: a full traffic burst must still be
	// available. Asserted by DRIVING one, since a zero-length drive reports zero whatever happened.
	assert.Equal(t, perClassNoticeBurst, drive(&out, limiter, siteUnmappedMethod, perClassNoticeBurst),
		"an undeclared site must not charge a real class's bucket")
}

// TestNoticeMechanism_ZeroChannelWritesEveryLine pins the unbounded disposition: a bare-struct-literal
// proxy in a test writes every line, as every leg did before the bucket existed. A zero value that
// silently suppressed instead would hide a refusal from an operator running a test proxy.
func TestNoticeMechanism_ZeroChannelWritesEveryLine(t *testing.T) {
	t.Parallel()
	var out strings.Builder
	assert.Equal(t, 20, drive(&out, nil, siteUnmappedMethod, 20))
}

// TestNoticeSplit_UpstreamErrorFloodCannotStarveAnObligationFailure pins the THIRD class.
//
// The two-class split rests on "who can drive a line and at what cost", and both halves of the old
// failure class are upstream-driven — but not at the same cost. A flapping upstream produces
// `upstream error` per call as its ordinary behaviour, while a redactFields obligation that cannot
// be applied is a thing a conforming deployment never produces. Sharing one bucket let an
// adversarial upstream elide its own `SECURITY: redaction failed` lines by erroring generically on
// every OTHER call — which forward.go's own note about that upstream already contemplates.
func TestNoticeSplit_UpstreamErrorFloodCannotStarveAnObligationFailure(t *testing.T) {
	t.Parallel()
	limiter := newNoticeLimiter(1)
	frozen(limiter, time.Now())

	var out strings.Builder
	flood := drive(&out, limiter, siteUpstreamError, 500)
	assert.LessOrEqual(t, flood, perClassNoticeBurst, "a dead upstream's own line must still be bounded")

	for _, site := range []noticeSite{siteRedactionFault, siteDeclassifyCommit, siteReceiptInconsistent} {
		assert.Equal(t, 2, drive(&out, limiter, site, 2),
			"%q reports a security obligation that did not hold; an upstream must not be able to elide it by flooding the errors it can produce at will", site)
	}
}

// TestNoticeReserve_SiblingSessionKeepsItsFirstFailureLine is the gap the per-session floor closes.
//
// One route, two sessions. A's subprocess dies and drives the failure class per frame, which is
// exactly what the route's bucket is there to bound — and before the floor existed it also meant
// B's `upstream error` line never reached the operator at all, for as long as A kept failing. The
// record half answers this with a per-session TABLE; the notice half answers it with one guaranteed
// arrival, because what an operator needs from B is that its upstream is down too, not a rate.
func TestNoticeReserve_SiblingSessionKeepsItsFirstFailureLine(t *testing.T) {
	t.Parallel()
	at := time.Now()
	aggregate := newNoticeLimiter(1)
	route := newRouteNoticeLimiter(aggregate)
	frozen(aggregate, at)
	frozen(route, at)

	sessionA, sessionB := newSessionNoticeReserve(), newSessionNoticeReserve()
	var outA, outB strings.Builder
	driveSession(&outA, route, sessionA, siteUpstreamError, 500)

	assert.Equal(t, 1, driveSession(&outB, route, sessionB, siteUpstreamError, 5),
		"a sibling session's first failure line must survive a flood that has emptied the route's bucket")
	assert.Contains(t, outB.String(), "reserved",
		"a line that got out on the floor says so: one line from a session is not evidence that only one thing happened to it")
}

// TestNoticeReserve_IsOnePerClassPerSession pins the floor's bound in both directions. One line per
// class is what makes it affordable at maxSessions (a session already costs an upstream spawn — see
// exemptCostsASession); one line per CLASS is what keeps a session's traffic flood from spending
// the floor its own failure line will need.
func TestNoticeReserve_IsOnePerClassPerSession(t *testing.T) {
	t.Parallel()
	at := time.Now()
	route := newRouteNoticeLimiter(newNoticeLimiter(1))
	frozen(route, at)

	session := newSessionNoticeReserve()
	var out strings.Builder
	// Drain two classes THROUGH this session, spending its floor for each on the way, and the third
	// through a sibling so this session's floor for it is still unspent.
	driveSession(&out, route, session, siteUnmappedMethod, 500)
	driveSession(&out, route, session, siteUpstreamError, 500)
	drive(&out, route, siteDeclassifyCommit, 500)
	out.Reset()

	assert.Zero(t, driveSession(&out, route, session, siteUnmappedMethod, 5),
		"the floor is one line per class per interval, not a second budget")
	assert.Zero(t, driveSession(&out, route, session, siteUpstreamError, 5),
		"the failure floor is spent once too")
	assert.Equal(t, 1, driveSession(&out, route, session, siteDeclassifyCommit, 5),
		"a class this session has not written yet still has its own floor; classes do not share one")
}

// TestNoticeReserve_UnspentWhileTheRouteBucketAdmits is why the floor is a fallback rather than a
// first-line rule: a session whose lines all fit under the route's budget must still have its floor
// when the incident that needs it arrives, possibly hours later.
func TestNoticeReserve_UnspentWhileTheRouteBucketAdmits(t *testing.T) {
	t.Parallel()
	at := time.Now()
	route := newRouteNoticeLimiter(newNoticeLimiter(1))
	frozen(route, at)

	quiet, noisy := newSessionNoticeReserve(), newSessionNoticeReserve()
	var out strings.Builder
	require.Positive(t, driveSession(&out, route, quiet, siteUpstreamError, 1), "the first line fits under a full bucket")
	driveSession(&out, route, noisy, siteUpstreamError, 500)
	out.Reset()

	assert.Equal(t, 1, driveSession(&out, route, quiet, siteUpstreamError, 3),
		"a line admitted by the bucket must not spend the floor; the quiet session's reserve is for the flood it has not met yet")
}

// TestNoticeReserve_FlooredLineCarriesTheCount covers the accounting, in the place the accounting
// is actually read.
//
// The bucket counts a refused line the instant it refuses it, so the floor must hand that one back
// — the rollup states what the reader did NOT see. And it must take the REST with it: under a
// sustained flood the floored line is the next line the reader sees, so a count left for "the next
// admitted line" is a count they get after the incident or never.
func TestNoticeReserve_FlooredLineCarriesTheCount(t *testing.T) {
	t.Parallel()
	at := time.Now()
	route := newRouteNoticeLimiter(newNoticeLimiter(1))
	frozen(route, at)

	session := newSessionNoticeReserve()
	var out strings.Builder
	drive(&out, route, siteUpstreamError, perClassNoticeBurst) // empty the bucket with no floor
	const refused = 10
	drive(&out, route, siteUpstreamError, refused-1) // ...and accumulate a tally with no floor
	out.Reset()

	require.Equal(t, 1, driveSession(&out, route, session, siteUpstreamError, 1),
		"the floor delivers this session's first refused line")
	assert.Contains(t, out.String(), "9 further failure diagnostics suppressed",
		"the floored line reports the lines nobody saw — the 9 refused before it, not the 10th which is the line itself")
	assert.Zero(t, route.bucket(classFailure).suppressed,
		"and takes the tally with it; leaving it behind defers the count to a line that may never come")
}

// TestNoticeReserve_AbsentWithoutASession pins the nil case. A refusal taken before a session exists
// is attributable to no session, so there is no floor to fall back on and the route's bucket is the
// whole answer — which is also what every stdio leg gets.
func TestNoticeReserve_AbsentWithoutASession(t *testing.T) {
	t.Parallel()
	at := time.Now()
	route := newRouteNoticeLimiter(newNoticeLimiter(1))
	frozen(route, at)

	var out strings.Builder
	drive(&out, route, siteUpstreamError, 500)
	out.Reset()
	assert.Zero(t, drive(&out, route, siteUpstreamError, 5),
		"a channel with no session behind it has no floor; a nil reserve must not read as an unspent one")
}

// TestNoticeReserve_SessionChannelCarriesItsOwnFloor is the wiring half: the floor is only worth
// anything if the leg that writes a session's lines actually resolves the session's channel, and
// two sessions on one route must not share one reserve.
func TestNoticeReserve_SessionChannelCarriesItsOwnFloor(t *testing.T) {
	t.Parallel()
	proxy := newTestHTTPProxy()
	route := &UpstreamRoute{name: "up1", notices: newRouteNoticeLimiter(proxy.notices)}
	a := &httpSession{id: "a", proxy: proxy, route: route, noticeFloor: newSessionNoticeReserve()}
	b := &httpSession{id: "b", proxy: proxy, route: route, noticeFloor: newSessionNoticeReserve()}

	require.NotNil(t, a.noticeWriter().reserve, "an established session's channel carries its floor")
	assert.Same(t, route.notices, a.noticeWriter().limits, "and still charges its route's table")
	assert.NotSame(t, a.noticeWriter().reserve, b.noticeWriter().reserve,
		"two sessions sharing one reserve would let the first to fail spend the second's line")
	assert.Nil(t, proxy.routeNoticeWriter(route).reserve,
		"a pre-session leg on the same route has none")

	// The legs the failure lines actually run on. `upstream error`, the upstreamless forward and
	// the redaction fault are written through the enforced path's limits, and the notification
	// gate's through its recorders — either resolving its channel from the ROUTE would lose the
	// floor with every other guard still green, which is the wiring fault this pins.
	assert.Same(t, a.noticeWriter().reserve, proxy.dispatchParams(a, "").limits.notices.reserve,
		"the enforced path's channel must carry the session's floor")
	assert.Same(t, a.noticeWriter().reserve, proxy.routeRefusalRecorders(a, route).notices().reserve,
		"the established-session notification gate's must too")
}

// TestNoticeReserve_NotClaimedWhenTheAggregateRefused pins which refusal the floor answers.
//
// tieredBuckets.admit says false two structurally different ways, and the floor may only answer one
// of them: the route's OWN bucket had nothing left. When the route had a token and the aggregate
// above refused, the write is already paid for at this tier, both tiers have counted it, and the
// pressure comes from other tenants this session cannot influence — claiming the floor there burned
// a session's one-per-class reserve on a sibling ROUTE's flood, which is the cross-tenant elision
// the tiers exist to stop, one level up.
func TestNoticeReserve_NotClaimedWhenTheAggregateRefused(t *testing.T) {
	t.Parallel()
	at := time.Now()
	// An aggregate sized for one tenant with two routes under it: routeA drains the shared parent
	// while routeB's own bucket stays full.
	aggregate := newNoticeLimiter(1)
	routeA, routeB := newRouteNoticeLimiter(aggregate), newRouteNoticeLimiter(aggregate)
	for _, l := range []*noticeLimiter{aggregate, routeA, routeB} {
		frozen(l, at)
	}

	var out strings.Builder
	drive(&out, routeA, siteUpstreamError, 500)
	out.Reset()

	session := newSessionNoticeReserve()
	require.Positive(t, routeB.bucket(classFailure).tokens, "routeB's own bucket is untouched; the aggregate is what refuses")
	assert.Zero(t, driveSession(&out, routeB, session, siteUpstreamError, 3),
		"a refusal from the aggregate is not this session's tier to floor")
	assert.True(t, claimAt(session, siteUpstreamError, classFailure, at),
		"and the reserve must still be unspent: burning it on another tenant's flood leaves nothing for this session's own upstream dying")
}

// TestNoticeReserve_NamesTheTierThatRefused pins the floored line's text against the tier the
// verdict actually came from, rather than a hardcoded "route".
//
// A session whose channel resolves to the proxy-wide aggregate (no route table) is floored by that
// aggregate, and telling an operator their ROUTE is saturated sends them to investigate one tenant
// for a bucket spanning every one — verbatim the misreading the rollup names its scope to prevent.
func TestNoticeReserve_NamesTheTierThatRefused(t *testing.T) {
	t.Parallel()
	at := time.Now()
	aggregate := newNoticeLimiter(1)
	frozen(aggregate, at)

	session := newSessionNoticeReserve()
	var out strings.Builder
	drive(&out, aggregate, siteUpstreamError, 500)
	out.Reset()
	require.Equal(t, 1, driveSession(&out, aggregate, session, siteUpstreamError, 3))
	assert.Contains(t, out.String(), "this proxy's failure budget is spent")
	assert.NotContains(t, out.String(), "route", "the tier comes from the verdict, not from where the floor happens to be held")
}

// TestNoticeReserve_UnclassifiedAndUndeclaredKeysGetNoFloor pins the fail-closed direction on the
// reserve's own key space.
//
// classUnclassified is what an UNDECLARED site resolves to, and the whole answer for a site nobody
// has classified is the floor-rate fallback bucket — a reserve on top would hand exactly that site
// a per-session line outside every bucket. The reserve holds slots for the DECLARED keys alone, so
// that is structural rather than a range check kept in agreement with the enum by hand.
func TestNoticeReserve_UnclassifiedAndUndeclaredKeysGetNoFloor(t *testing.T) {
	t.Parallel()
	at := time.Now()
	session := newSessionNoticeReserve()
	assert.Nil(t, session.forSite("undeclared-probe", classUnclassified),
		"an undeclared site's class must not carry a floor")
	assert.Nil(t, session.forSite("undeclared-probe", noticeClass(99)),
		"nor may a class outside the declared set")
	assert.True(t, claimAt(session, siteUpstreamError, classFailure, at), "and a real class is unaffected")

	limiter := newNoticeLimiter(1)
	frozen(limiter, at)
	var out strings.Builder
	written := driveSession(&out, limiter, newSessionNoticeReserve(), "undeclared-probe", 100)
	assert.LessOrEqual(t, written, perBucketFloor,
		"an undeclared site stays on the floor-rate fallback with a session in scope, exactly as without one")
}

// TestNoticeReserve_ReArmsPerIntervalRatherThanPerSession is the residual the lifetime bit left, and
// the reason it is now an interval.
//
// A bit per class for the session's whole life is claimed by whichever refused line of that class
// comes FIRST. A long-lived session that hits one transient failure during an unrelated flood had
// spent the arrival it needs hours later when its own upstream dies — the exact elision the floor
// exists to close, deferred rather than removed.
func TestNoticeReserve_ReArmsPerIntervalRatherThanPerSession(t *testing.T) {
	t.Parallel()
	at := time.Now()
	// No aggregate above: this is a one-tier assertion, and a parent left on the real clock
	// would decide the refusals rather than the tier under test.
	route := newRouteNoticeLimiter(nil)
	frozen(route, at)

	session := newSessionNoticeReserve()
	var out strings.Builder
	drive(&out, route, siteUpstreamError, 500) // a sibling empties the route's failure bucket
	require.Equal(t, 1, driveSession(&out, route, session, siteUpstreamError, 3),
		"the transient failure claims this session's floor")
	out.Reset()

	// Still inside the interval, and the bucket still empty: no second arrival.
	at = at.Add(reserveInterval / 2)
	frozen(route, at)
	drive(&out, route, siteUpstreamError, 500)
	out.Reset()
	assert.Zero(t, driveSession(&out, route, session, siteUpstreamError, 3),
		"the floor is one line per interval; re-arming faster would double a flooding session's own rate")

	// The incident an operator is actually watching, one interval on.
	at = at.Add(reserveInterval)
	frozen(route, at)
	drive(&out, route, siteUpstreamError, 500)
	out.Reset()
	assert.Equal(t, 1, driveSession(&out, route, session, siteUpstreamError, 3),
		"this session's own upstream dying later must still reach the operator; a lifetime bit spent hours earlier gave it nothing")
}

// TestNoticeReserve_FlooredLineIsBorrowedFromTheTierThatRefused pins the other residual: a floored
// line used to be written outside every bucket, so the process-wide ceiling was not a ceiling.
//
// It is a bypass of the GATE, not of the ACCOUNTING. The bucket that refused is debited, so over
// the long run the tier's rate is exactly what the operator configured and a floored arrival
// DISPLACES the flooder's next line rather than adding to the total.
func TestNoticeReserve_FlooredLineIsBorrowedFromTheTierThatRefused(t *testing.T) {
	t.Parallel()
	at := time.Now()
	// No aggregate above: this is a one-tier assertion, and a parent left on the real clock
	// would decide the refusals rather than the tier under test.
	route := newRouteNoticeLimiter(nil)
	frozen(route, at)

	var out strings.Builder
	drive(&out, route, siteUpstreamError, 500)
	before := route.bucket(classFailure).tokens
	require.Equal(t, 1, driveSession(&out, route, newSessionNoticeReserve(), siteUpstreamError, 1))
	assert.InDelta(t, before-1, route.bucket(classFailure).tokens, 0.001,
		"a floored line costs the refusing tier a token; free, it would put the process-wide rate above what the operator set")

	// And the debit is what the next refill pays back: one second of refill (2 tokens) minus the
	// borrowed one leaves room for exactly one ordinary line.
	at = at.Add(time.Second)
	frozen(route, at)
	out.Reset()
	assert.Equal(t, 1, drive(&out, route, siteUpstreamError, 5),
		"the tier's long-run rate is unchanged: the floored arrival came out of the flooder's next line, not out of thin air")
}

// TestNoticeReserve_DebtIsClampedAtOneBurst is why the debit is not unbounded. Enough holders
// flooring one tier at once would otherwise drive its bucket arbitrarily negative and stop its
// ordinary writes for good — worse than the excess the debit prevents.
func TestNoticeReserve_DebtIsClampedAtOneBurst(t *testing.T) {
	t.Parallel()
	at := time.Now()
	// No aggregate above: this is a one-tier assertion, and a parent left on the real clock
	// would decide the refusals rather than the tier under test.
	route := newRouteNoticeLimiter(nil)
	frozen(route, at)

	var out strings.Builder
	drive(&out, route, siteUpstreamError, 500)
	for range 200 {
		driveSession(&out, route, newSessionNoticeReserve(), siteUpstreamError, 1)
	}
	assert.GreaterOrEqual(t, route.bucket(classFailure).tokens, float64(-perClassNoticeBurst),
		"the debt is clamped at one burst, so the tier recovers within burst/rate seconds of the floors stopping")
}

// TestNoticeReserve_ObligationFloodCannotElideTheRedactionLine is the site axis (issue: a broken
// deployment drives classObligation at the request rate).
//
// A flow store that is down fails every approved declassification's commit, and a stale effect.ref
// pin makes every receipt inconsistent — both at the request rate, both from a CONFORMING peer. So
// the class bucket can be held empty with no adversary at all, and what it reduced to a count on
// somebody else's line was `SECURITY: redaction failed`, the line the class was split out for.
func TestNoticeReserve_ObligationFloodCannotElideTheRedactionLine(t *testing.T) {
	t.Parallel()
	at := time.Now()
	route := newRouteNoticeLimiter(newNoticeLimiter(1))
	frozen(route, at)

	session := newSessionNoticeReserve()
	var out strings.Builder
	// One session, one class: the deployment's own broken commit path floods it, spending both the
	// route's obligation bucket AND this session's class floor.
	driveSession(&out, route, session, siteDeclassifyCommit, 500)
	out.Reset()
	require.Zero(t, driveSession(&out, route, session, siteReceiptInconsistent, 3),
		"a class-mate with no floor of its own is elided, which is the residual the class alone leaves")

	assert.Equal(t, 1, driveSession(&out, route, session, siteRedactionFault, 3),
		"the redaction line holds a floor of its OWN inside the class, so a class-mate's flood cannot elide it")
	assert.Contains(t, out.String(), "reserved",
		"and it says it got out on a reserve rather than on a tier with room")
}

// TestNoticeReserve_SiteFloorIsNotASecondBudget bounds the site axis the same way the class axis is
// bounded: one line per interval, and the flood itself cannot claim it.
func TestNoticeReserve_SiteFloorIsNotASecondBudget(t *testing.T) {
	t.Parallel()
	at := time.Now()
	route := newRouteNoticeLimiter(newNoticeLimiter(1))
	frozen(route, at)

	session := newSessionNoticeReserve()
	var out strings.Builder
	drive(&out, route, siteDeclassifyCommit, 500)
	require.Equal(t, 1, driveSession(&out, route, session, siteRedactionFault, 200),
		"the protected site gets ONE arrival, not a budget")
	out.Reset()
	assert.Zero(t, driveSession(&out, route, session, siteRedactionFault, 5))
	assert.True(t, claimAt(session, siteDeclassifyCommit, classObligation, at),
		"and spending the site floor must leave the class floor its class-mates share untouched: the two answer different starvations")
}

// TestNoticeReserve_ProtectedSiteFallsBackToNoClassFloor pins the resolution order. A site with its
// own slot must NOT also fall back to its holder's class floor once that slot is spent: two arrivals
// per interval for one site and none for the others is not the property being bought.
func TestNoticeReserve_ProtectedSiteFallsBackToNoClassFloor(t *testing.T) {
	t.Parallel()
	session := newSessionNoticeReserve()
	require.NotEmpty(t, floorProtectedSites)
	for _, site := range floorProtectedSites {
		class, metered := meteredNotices[site]
		require.True(t, metered, "a protected site must be metered; an unmetered one charges no bucket to be floored under")
		assert.NotSame(t, session.forSite(site, class), session.byClass.forKey(class),
			"site %q must resolve to its own slot rather than the class slot it is protected from", site)
	}
}

// TestNoticeReserve_SiteAxisIsPresentWithoutAHolder pins the split between the two axes. A whole
// stdio proxy is one holder with no sibling to be starved by, so it reserves nothing per class —
// but the line a class-mate's flood must not elide is written on that transport too.
func TestNoticeReserve_SiteAxisIsPresentWithoutAHolder(t *testing.T) {
	t.Parallel()
	at := time.Now()
	reserve := newSiteNoticeReserve()
	assert.Nil(t, reserve.forSite(siteUpstreamError, classFailure),
		"a proxy is not a holder among peers, so it gets no class floor")
	assert.True(t, claimAt(reserve, siteRedactionFault, classObligation, at),
		"the site axis is not about holders at all")

	limiter := newNoticeLimiter(1)
	frozen(limiter, at)
	var out strings.Builder
	drive(&out, limiter, siteDeclassifyCommit, 500)
	out.Reset()
	assert.Equal(t, 1, driveSession(&out, limiter, newSiteNoticeReserve(), siteRedactionFault, 3),
		"stdio's redaction line survives a broken deployment's commit flood exactly as an HTTP session's does")
}

// TestNoticeAdmission_PreGateSpendsExactlyOneToken pins the admission's accounting: the site
// decides before building its arguments and writes through the line it gets back, taking ONE
// token. A second admission on the write would drain the bucket at twice the rate for the same
// number of lines.
func TestNoticeAdmission_PreGateSpendsExactlyOneToken(t *testing.T) {
	t.Parallel()
	at := time.Now()
	gated, plain := newNoticeLimiter(1), newNoticeLimiter(1)
	frozen(gated, at)
	frozen(plain, at)

	var out strings.Builder
	written := 0
	for range 500 {
		if line, ok := (noticeWriter{out: &out, limits: gated}).admitNotice(siteUnmappedMethod); ok {
			line.writef("line\n")
			written++
		}
	}
	assert.Equal(t, drive(&out, plain, siteUnmappedMethod, 500), written,
		"pre-gating must not change how many lines get out, only what a suppressed one costs to decide")
	assert.InDelta(t, plain.bucket(classTraffic).tokens, gated.bucket(classTraffic).tokens, 0.001,
		"the pre-gated site charges exactly one token per line")
}

// TestNoticeAdmission_SuppressedPreGateStillCountsIntoTheRollup is why the escape hatch returns a
// LINE rather than the bool it was first proposed as.
//
// A bool would be a peek the caller acts on and the mechanism never hears about again: the site
// skips, nothing counts the line, and the next admitted one under-states the flood by however many
// frames the expensive sites elided. Here the admission happens exactly once whichever way the
// caller spells it, so the count is the same either way.
func TestNoticeAdmission_SuppressedPreGateStillCountsIntoTheRollup(t *testing.T) {
	t.Parallel()
	now := time.Now()
	limiter := newNoticeLimiter(1)
	limiter.setNow(func() time.Time { return now })

	var out strings.Builder
	channel := noticeWriter{out: &out, limits: limiter}
	for range 200 {
		if line, ok := channel.admitNotice(siteUnmappedMethod); ok {
			line.writef("line\n")
		}
	}
	now = now.Add(time.Second)
	out.Reset()
	if line, ok := channel.admitNotice(siteUnmappedMethod); ok {
		line.writef("line\n")
	}
	assert.Contains(t, out.String(), "further traffic diagnostics suppressed",
		"a site that never built its arguments still elided lines, and the count is what says so")
}

// BenchmarkNotice_SuppressedPath measures the path the bucket exists for: a peer or a dead upstream
// driving a line per frame, every one of them elided. `arguments` is what a site pays to build a
// line the admission then throws away — the shape every site had before deciding first became the
// one spelling — and `preGated` is what ships. The gap is why the ordering is uniform rather than
// judged per site; the `admission` arm is the floor under both, of which the declaration lookup is
// a small part.
func BenchmarkNotice_SuppressedPath(b *testing.B) {
	limiter := newNoticeLimiter(1)
	// With a session floor, since that is the shipped HTTP-session channel: a reserve-less channel
	// measures a shape only stdio and the pre-session legs have, and skips take() entirely. The
	// floor is spent by the first drained line, so every measured iteration is the steady state.
	channel := noticeWriter{out: io.Discard, limits: limiter, reserve: newSessionNoticeReserve()}
	drain := func() {
		for range perClassNoticeBurst + 1 {
			if line, ok := channel.admitNotice(siteNotifyPoolSaturated); ok {
				line.writef("drain\n")
			}
		}
	}
	const method = "notifications/progress"
	sessionID := "01J8ZK2S0000000000000000"

	b.Run("arguments", func(b *testing.B) {
		drain()
		b.ReportAllocs()
		for b.Loop() {
			eagerNoticef(channel, siteNotifyPoolSaturated, "[eunox] HTTP session %s: notification %q dropped\n",
				sessionID, audit.BoundEnvelopeField(method))
		}
	})
	b.Run("preGated", func(b *testing.B) {
		drain()
		b.ReportAllocs()
		for b.Loop() {
			if line, ok := channel.admitNotice(siteNotifyPoolSaturated); ok {
				line.writef("[eunox] HTTP session %s: notification %q dropped\n",
					sessionID, audit.BoundEnvelopeField(method))
			}
		}
	})
	b.Run("admission", func(b *testing.B) {
		drain()
		b.ReportAllocs()
		for b.Loop() {
			_, _ = channel.admitNotice(siteNotifyPoolSaturated)
		}
	})
	// The declaration lookup's own share of that admission — the number the "leave it a map probe"
	// decision rests on, rather than one to re-derive when the next reader wonders whether an
	// integer site indexing an array would be worth the constants' readable values.
	b.Run("lookup", func(b *testing.B) {
		b.ReportAllocs()
		class := classUnclassified
		for b.Loop() {
			class = meteredNotices[siteNotifyPoolSaturated]
		}
		require.NotEqual(b, classUnclassified, class)
	})
}

// eagerNoticef is the shape the mechanism deliberately no longer ships: a convenience wrapper that
// takes the format and arguments eagerly and discards them when the admission says no. Kept in the
// benchmark alone, as the thing the shipped ordering is measured AGAINST.
func eagerNoticef(n noticeWriter, site noticeSite, format string, args ...interface{}) {
	if line, ok := n.admitNotice(site); ok {
		line.writef(format, args...)
	}
}

// BenchmarkNoticeReserve_Claim is the number behind claim()'s Load-before-CAS: after a holder's
// first refused line of a key the slot is spent for the interval, so the already-spent answer is the
// one the flood path asks for, over a cache line the request goroutine and the upstream reader
// share.
func BenchmarkNoticeReserve_Claim(b *testing.B) {
	now := func() time.Time { return time.Unix(1_760_000_000, 0) }
	spent := newSessionNoticeReserve()
	slot := spent.forSite(siteUpstreamError, classFailure)
	require.True(b, slot.claim(now))
	b.Run("spent", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_ = slot.claim(now)
		}
	})
	b.Run("spentParallel", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_ = slot.claim(now)
			}
		})
	})
	// The resolution beside it: two map probes on the flood path, which is what picking a floor by
	// site rather than by class alone costs.
	b.Run("resolve", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_ = spent.forSite(siteRedactionFault, classObligation)
		}
	})
}
