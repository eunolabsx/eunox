// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The two axes the single shared notice bucket collapsed, and the mechanism that picks a bucket.
//
// Every test here drives noticef directly rather than through a transport leg: what is under test
// is which bucket a line charges and what a flood of one can take from another, and a leg would
// only add the question of whether that leg is wired.

package transport

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// frozen points every bucket in l at a fixed clock, so a burst is measured against the burst size
// rather than against how long the test took to run.
func frozen(l *noticeLimiter, at time.Time) {
	l.setNow(func() time.Time { return at })
}

// drive writes n lines for site and reports how many reached w.
func drive(w *strings.Builder, l *noticeLimiter, site noticeSite, n int) int {
	before := w.Len()
	for range n {
		noticef(noticeWriter{out: w, limits: l}, site, "line\n")
	}
	return strings.Count(w.String()[before:], "\n")
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
	for site, decl := range noticeDeclarations {
		if decl.bound != noticeMetered {
			continue
		}
		// A FRESH table per site: one shared across the loop drains as sites accumulate, so the
		// "admitted nothing on a full bucket" arm would eventually fail naming an arbitrary site
		// (map order is randomized) for the crime of being visited last.
		limiter := newNoticeLimiter(1)
		frozen(limiter, time.Now())
		before := limiter.bucket(decl.class).tokens
		var out strings.Builder
		noticef(noticeWriter{out: &out, limits: limiter}, site, "line\n")
		require.NotEmpty(t, out.String(), "site %q admitted nothing on a full bucket", site)
		assert.Less(t, limiter.bucket(decl.class).tokens, before,
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
	require.NotContains(t, noticeDeclarations, noticeSite("undeclared-probe"))

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
