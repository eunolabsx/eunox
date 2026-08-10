// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Collapsing a repeating obligation fault at its SOURCE, which is the half of the problem the site
// floor works around rather than removes.
//
// Two of classObligation's sites are drivable at the request rate by a CONFORMING peer against a
// merely broken deployment — a downed flow store fails every approved declassification's commit, a
// stale effect.ref pin makes every receipt inconsistent — so the class bucket could be held empty
// with no adversary involved. The floor under `SECURITY: redaction failed` answers the symptom (an
// arrival past a drained bucket); these tests pin the source: the flood stops existing, so the
// bucket is not drained in the first place.

package transport

import (
	"go/ast"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEpisodeDeclarations_EveryCollapsedSiteIsReopened is the guard the mechanism cannot give
// itself: a site declared collapsed whose episode nothing ever ends is not a quieter channel, it is
// a PERMANENT MUTE — the leading edge is written once and every later occurrence of that fault, for
// the rest of the process's life, folds into a count.
//
// The reopen is necessarily at a call site far from the declaration (it is the fault's own
// operation succeeding), so only a source walk can see that one exists.
func TestEpisodeDeclarations_EveryCollapsedSiteIsReopened(t *testing.T) {
	t.Parallel()
	for site, decl := range episodeCollapsedSites {
		assert.Contains(t, meteredNotices, site,
			"site %q collapses per episode but charges no bucket; there is no flood to collapse and no tally to fold into", site)
		assert.NotEmpty(t, decl.endedBy,
			"site %q must name what ends its episode: it is the reopen CONDITION, the one thing a gate cannot infer, and it is also the text the boundary line reports", site)
	}

	consts := noticeSiteConstants(t)
	reopened := map[noticeSite]bool{}
	for _, src := range packageSources(t) {
		ast.Inspect(src.file, func(n ast.Node) bool {
			call, isCall := n.(*ast.CallExpr)
			if !isCall || callName(call) != "endEpisode" || len(call.Args) != 1 {
				return true
			}
			ident, isIdent := call.Args[0].(*ast.Ident)
			require.True(t, isIdent, "%s:%d: endEpisode must name its site with one of notice.go's constants",
				src.name, src.fset.Position(call.Pos()).Line)
			site, isSite := consts[ident.Name]
			require.True(t, isSite, "%s:%d: %q is not a declared noticeSite", src.name, src.fset.Position(call.Pos()).Line, ident.Name)
			assert.Contains(t, episodeCollapsedSites, site,
				"%s:%d: site %q is reopened but never collapsed, so the call ends an episode nothing opens",
				src.name, src.fset.Position(call.Pos()).Line, site)
			reopened[site] = true
			return true
		})
	}
	for site := range episodeCollapsedSites {
		assert.True(t, reopened[site],
			"site %q collapses per episode with nothing to end one; its first line would be its last for the process's life", site)
	}
}

// driveGated writes n lines for site through a channel that holds episode gates, and reports how
// many reached w. The counterpart of drive/driveSession, which build a channel with none.
func driveGated(w *strings.Builder, ch noticeWriter, site noticeSite, n int) int {
	before := w.Len()
	for range n {
		if line, ok := ch.admitNotice(site); ok {
			line.writef("fault\n")
		}
	}
	return strings.Count(w.String()[before:], "\n")
}

// gatedChannel is one source's diagnostic channel: a parentless route table on a frozen clock, its
// own episode gates, and no floor — so what a test measures is the collapsing rather than a
// reserve delivering lines past a drained bucket.
func gatedChannel(w *strings.Builder, at time.Time) (noticeWriter, *noticeLimiter) {
	route := newRouteNoticeLimiter(nil)
	frozen(route, at)
	return noticeWriter{out: w, limits: route, episodes: newEpisodeGates()}, route
}

// TestEpisodeCollapse_PersistentFaultCostsOneLineAndLeavesTheBudget is the whole point: a fault
// that persists is reported once, and the class budget it used to empty is still there for the line
// the class was split out to keep legible.
func TestEpisodeCollapse_PersistentFaultCostsOneLineAndLeavesTheBudget(t *testing.T) {
	t.Parallel()
	var out strings.Builder
	ch, route := gatedChannel(&out, time.Now())

	assert.Equal(t, 1, driveGated(&out, ch, siteDeclassifyCommit, 500),
		"a downed flow store is one finding, not 500; an operator needs to know the backend is broken once")
	assert.Equal(t, float64(perClassNoticeBurst-1), route.bucket(classObligation).tokens,
		"and the other 499 spend no token at all — collapsing at the source FREES the class bucket, where the floor only works around one the flood has already emptied")

	// The line the class exists to keep legible now arrives on an ordinary token, with no reserve
	// involved: the flood the floor was the backstop for is not happening.
	out.Reset()
	require.Equal(t, 1, driveGated(&out, ch, siteRedactionFault, 1))
	assert.NotContains(t, out.String(), "reserved:",
		"the redaction line must not need its floor to get out when the class-mate flood has been collapsed away")

	// The count is not lost: it rides the tail every admitted line of the class already carries,
	// rather than a second counter beside it.
	assert.Contains(t, out.String(), "499 further obligation diagnostics suppressed",
		"a folded line is still a line the reader did not see, and the rollup is where that is reported")
}

// TestEpisodeCollapse_RecoveryIsTheEpisodeBoundary pins what collapsing buys beyond a quieter
// bucket: the boundary says WHEN the backend recovered, which a suppression count cannot.
func TestEpisodeCollapse_RecoveryIsTheEpisodeBoundary(t *testing.T) {
	t.Parallel()
	var out strings.Builder
	ch, _ := gatedChannel(&out, time.Now())

	require.Equal(t, 1, driveGated(&out, ch, siteReceiptInconsistent, 20))
	out.Reset()

	ch.endEpisode(siteReceiptInconsistent)
	assert.Contains(t, out.String(), "the reported fault has cleared",
		"the episode's end is the fact an operator most needs after its start")
	assert.Contains(t, out.String(), episodeCollapsedSites[siteReceiptInconsistent].endedBy,
		"and it names what cleared it, from the declaration the gate's reopen condition is written in")

	// A second recovery reports nothing: the boundary is per episode, not per success.
	out.Reset()
	ch.endEpisode(siteReceiptInconsistent)
	assert.Empty(t, out.String(), "a line per successful call would be the flood one level over")

	// And the next fault opens a new episode rather than being folded into the closed one.
	assert.Equal(t, 1, driveGated(&out, ch, siteReceiptInconsistent, 20),
		"a fault that returns after a recovery is a new finding")
}

// TestEpisodeCollapse_DeclinedLeadingEdgeDoesNotOpenAnEpisode is saturationGate's documented
// point (1), one axis over: latching before the line is known to have been WRITTEN strands the
// whole fault at zero reports, since only a recovery can reopen an episode.
func TestEpisodeCollapse_DeclinedLeadingEdgeDoesNotOpenAnEpisode(t *testing.T) {
	t.Parallel()
	at := time.Now()
	var out strings.Builder
	ch, route := gatedChannel(&out, at)

	// Empty the class bucket through a site that is NOT collapsed, so the collapsed one's leading
	// edge meets a drained tier.
	drive(&out, route, siteRedactionFault, int(perClassNoticeBurst)+5)
	out.Reset()
	require.Zero(t, driveGated(&out, ch, siteDeclassifyCommit, 3), "the bucket has nothing left")

	// One refill later the fault must still be reportable.
	frozen(route, at.Add(time.Minute))
	assert.Equal(t, 1, driveGated(&out, ch, siteDeclassifyCommit, 3),
		"an episode opened on a line the bucket declined would hold no written line, and every further failure would fold into it until the fault cleared — the fault reported zero times")
}

// TestEpisodeCollapse_GatesAreHeldPerSource pins the scope: the faults are an UPSTREAM's, so one
// tenant's broken backend must not suppress another's report of its own.
func TestEpisodeCollapse_GatesAreHeldPerSource(t *testing.T) {
	t.Parallel()
	at := time.Now()
	var a, b strings.Builder
	routeA, _ := gatedChannel(&a, at)
	routeB, _ := gatedChannel(&b, at)

	require.Equal(t, 1, driveGated(&a, routeA, siteReceiptInconsistent, 50))
	assert.Equal(t, 1, driveGated(&b, routeB, siteReceiptInconsistent, 50),
		"a stale pin on one route says nothing about another's, and a process-wide gate would report only the first")
}

// TestEpisodeCollapse_OnlyTheDeclaredSitesCollapse is the control on both sides of the declaration:
// a site outside episodeCollapsedSites writes every line, and a channel with no gates at all (a leg
// with no source, e.g. a pre-session HTTP arm) collapses nothing.
func TestEpisodeCollapse_OnlyTheDeclaredSitesCollapse(t *testing.T) {
	t.Parallel()
	at := time.Now()
	var out strings.Builder
	ch, _ := gatedChannel(&out, at)

	// The double-commit line reports a fault in THIS proxy's wiring rather than in the flow store,
	// which is why it holds a site of its own: folded into a store-fault episode it would be
	// reported nowhere for as long as the store stayed down.
	require.Equal(t, 1, driveGated(&out, ch, siteDeclassifyCommit, 5))
	out.Reset()
	assert.Positive(t, driveGated(&out, ch, siteDeclassifyDoubleCommit, 5),
		"an open store-fault episode must not swallow a wiring fault beside it")

	var ungated strings.Builder
	route := newRouteNoticeLimiter(nil)
	frozen(route, at)
	bare := noticeWriter{out: &ungated, limits: route}
	assert.Equal(t, int(perClassNoticeBurst), driveGated(&ungated, bare, siteDeclassifyCommit, 50),
		"a leg with no source to attribute an episode to writes what its bucket allows, exactly as before")
}
