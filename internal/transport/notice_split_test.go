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

// TestNoticeSplit_RefusalFloodCannotStarveAnUpstreamFailure is #337's property.
//
// refuseUnroutable's line is drivable at a peer's full send rate on the cheapest message it can
// send — no id, no handler slot, no upstream round trip. Sharing one bucket with `upstream error`
// meant a peer looping unmapped methods could hold it empty while a route's upstream started
// failing, and the operator saw no upstream line at all: only a suppression tail folded onto an
// unrelated refusal. The tape was never affected, so what this protects is stderr legibility during
// an incident.
func TestNoticeSplit_RefusalFloodCannotStarveAnUpstreamFailure(t *testing.T) {
	t.Parallel()
	limiter := newNoticeLimiter()
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
	limiter := newNoticeLimiter()
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
	limiter := newNoticeLimiter()
	limiter.setNow(func() time.Time { return now })

	var out strings.Builder
	drive(&out, limiter, siteUnmappedMethod, 200)
	now = now.Add(time.Second)
	out.Reset()
	drive(&out, limiter, siteUnmappedMethod, 1)

	assert.Contains(t, out.String(), "further traffic diagnostics suppressed")
	assert.NotContains(t, out.String(), "failure",
		"the count spans the class it charged; naming another would tell an operator a flood happened where none did")
}

// TestNoticeSplit_OneRouteCannotSilenceASibling is #330's property.
//
// A peer looping `{"jsonrpc":"2.0","method":"x/bogus"}` at /mcp/routeA drained the single
// proxy-wide bucket and suppressed routeB's routing-refusal lines for as long as it kept sending.
// refuseUnroutable logs the method name so an operator can detect protocol drift, and a suppressed
// line keeps only a count — so what one tenant could take from another was the other's drift signal.
func TestNoticeSplit_OneRouteCannotSilenceASibling(t *testing.T) {
	t.Parallel()
	at := time.Now()
	aggregate := newNoticeLimiter()
	routeA, routeB := newRouteNoticeLimiter(aggregate, 2), newRouteNoticeLimiter(aggregate, 2)
	for _, l := range []*noticeLimiter{aggregate, routeA, routeB} {
		frozen(l, at)
	}

	var outA, outB strings.Builder
	drive(&outA, routeA, siteUnmappedMethod, 500)
	assert.Positive(t, drive(&outB, routeB, siteUnmappedMethod, 5),
		"one tenant's flood must not silence another's; a share of the aggregate is what makes the split mean something a bare parent does not")
}

// TestNoticeSplit_RouteSharesDoNotMultiplyTheAggregate is the other side of that split: the reachable
// syscall rate must not grow with the route count. The parent is what holds it, and both tiers must
// admit — a per-route table that only bounded its own share would hand a gateway operator N times the
// diagnostic rate for adding routes.
func TestNoticeSplit_RouteSharesDoNotMultiplyTheAggregate(t *testing.T) {
	t.Parallel()
	at := time.Now()
	const routes = 4
	aggregate := newNoticeLimiter()
	frozen(aggregate, at)

	var out strings.Builder
	total := 0
	for range routes {
		route := newRouteNoticeLimiter(aggregate, routes)
		frozen(route, at)
		total += drive(&out, route, siteUnmappedMethod, 100)
	}
	assert.LessOrEqual(t, total, perClassNoticeBurst,
		"every route charges the aggregate too, so N routes flooding together stay at the pre-split ceiling")
}

// TestNoticeSplit_SingleRouteKeepsThePreSplitBudget guards the common deployment: one route (and
// stdio, which has no route tier at all) must not pay for a split it cannot benefit from.
func TestNoticeSplit_SingleRouteKeepsThePreSplitBudget(t *testing.T) {
	t.Parallel()
	at := time.Now()
	aggregate := newNoticeLimiter()
	route := newRouteNoticeLimiter(aggregate, 1)
	frozen(aggregate, at)
	frozen(route, at)

	var out strings.Builder
	assert.Equal(t, perClassNoticeBurst, drive(&out, route, siteUnmappedMethod, 100))
}

// TestNoticeMechanism_ClassComesFromTheDeclaration is #339's property: the bucket a line charges is
// READ from its site's declaration at write time, the analogue of forCategory on the record half —
// not chosen by the call site, which is what let "declared metered" and "charges a bucket" disagree.
func TestNoticeMechanism_ClassComesFromTheDeclaration(t *testing.T) {
	t.Parallel()
	limiter := newNoticeLimiter()
	frozen(limiter, time.Now())

	for site, decl := range noticeDeclarations {
		if decl.bound != noticeMetered {
			continue
		}
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
	limiter := newNoticeLimiter()
	frozen(limiter, time.Now())
	require.NotContains(t, noticeDeclarations, noticeSite("undeclared-probe"))

	var out strings.Builder
	written := drive(&out, limiter, "undeclared-probe", 100)
	assert.Positive(t, written)
	assert.LessOrEqual(t, written, perBucketFloor,
		"an undeclared site falls to the floor-rate fallback, not to a real class's share and not to writing free")
	assert.Zero(t, drive(&out, limiter, siteUnmappedMethod, 0),
		"and it must not have spent a declared class's tokens on the way")
}

// TestNoticeMechanism_ZeroChannelWritesEveryLine pins the unbounded disposition: a bare-struct-literal
// proxy in a test writes every line, as every leg did before the bucket existed. A zero value that
// silently suppressed instead would hide a refusal from an operator running a test proxy.
func TestNoticeMechanism_ZeroChannelWritesEveryLine(t *testing.T) {
	t.Parallel()
	var out strings.Builder
	assert.Equal(t, 20, drive(&out, nil, siteUnmappedMethod, 20))
}
