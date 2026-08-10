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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// collapsingChannel is one source's diagnostic channel: a parentless route table on a frozen clock,
// that source's collapse windows, and no floor — so what a test measures is the collapsing rather
// than a reserve delivering lines past a drained bucket.
//
// It returns the channel and the table; a driver counts on the channel's OWN writer, so a test
// cannot count newlines in a builder the lines never went to.
func collapsingChannel(w *strings.Builder, at time.Time) (noticeWriter, *noticeLimiter) {
	route := newRouteNoticeLimiter(nil)
	frozen(route, at)
	return noticeWriter{out: w, limits: route, collapse: newNoticeCollapse()}, route
}

// driveChannel writes n lines for site through ch and reports how many reached ch's own writer.
// Counting on the channel's writer rather than one passed beside it is what driveSession's doc
// says its own shape is for: the two cannot be different writers.
func driveChannel(ch noticeWriter, site noticeSite, n int) int {
	out, isBuilder := ch.out.(*strings.Builder)
	if !isBuilder {
		panic("driveChannel needs a channel writing to a *strings.Builder")
	}
	before := out.Len()
	for range n {
		if line, ok := ch.admitNotice(site); ok {
			line.writef("fault\n")
		}
	}
	return strings.Count(out.String()[before:], "\n")
}

// TestNoticeCollapse_PersistentFaultCostsOneLineAndLeavesTheBudget is the whole point: a fault that
// repeats is reported once per window, and the class budget it used to empty is still there for the
// line the class was split out to keep legible.
func TestNoticeCollapse_PersistentFaultCostsOneLineAndLeavesTheBudget(t *testing.T) {
	t.Parallel()
	var out strings.Builder
	ch, route := collapsingChannel(&out, time.Now())

	assert.Equal(t, 1, driveChannel(ch, siteDeclassifyCommit, 500),
		"a downed flow store is one finding, not 500; an operator acts on it once")
	assert.Equal(t, float64(perClassNoticeBurst-1), route.bucket(classObligation).tokens,
		"and the other 499 spend no token at all — collapsing at the source FREES the class bucket, where the floor only works around one the flood has already emptied")

	// The line the class exists to keep legible now arrives on an ordinary token, with no reserve
	// involved: the flood the floor was the backstop for is not happening.
	out.Reset()
	require.Equal(t, 1, driveChannel(ch, siteRedactionFault, 1))
	assert.NotContains(t, out.String(), "reserved:",
		"the redaction line must not need its floor to get out when the class-mate flood has been collapsed away")

	// The count is not lost: it rides the tail every admitted line of the class already carries,
	// rather than a second counter beside it.
	assert.Contains(t, out.String(), "499 further obligation diagnostics suppressed",
		"a folded line is still a line the reader did not see, and the rollup is where that is reported")
}

// TestNoticeCollapse_ReArmsOnTimeRatherThanOnASuccess is the property an episode gate could not
// have, and the reason this is a window rather than one.
//
// A success-reopened episode put the reopen under the control of the party being reported on: an
// upstream that emitted one inconsistent receipt and then never a verifiable one held the site muted
// for the process's life, across every tool and session on the route. A window answers to the clock,
// so the fault reports again whatever the backend does — or declines to do.
func TestNoticeCollapse_ReArmsOnTimeRatherThanOnASuccess(t *testing.T) {
	t.Parallel()
	at := time.Now()
	var out strings.Builder
	ch, route := collapsingChannel(&out, at)

	require.Equal(t, 1, driveChannel(ch, siteReceiptInconsistent, 20))
	assert.Zero(t, driveChannel(ch, siteReceiptInconsistent, 20),
		"inside the window the fault is folded — that is the collapse")

	frozen(route, at.Add(noticeCollapseInterval))
	assert.Equal(t, 1, driveChannel(ch, siteReceiptInconsistent, 20),
		"and it reports again when the window re-arms, with no success required from the upstream whose fault it is")
}

// TestNoticeCollapse_MixedSubjectsDoNotFlapTheWindow pins the failure the success-reopened design
// actually had, in the shape that made it worse than no collapsing at all.
//
// The state can only be keyed per SOURCE (a route has one receipt verifier), while the faults are
// per CALL: one tool's stale effect.ref pin beside a sibling tool that verifies fine. Under a
// success-driven reopen that alternation emitted a fault line AND a "recovered" line per pair —
// twice the output of no collapsing, with the second announcing a recovery on evidence from a
// different tool. A window is indifferent to the interleaving.
func TestNoticeCollapse_MixedSubjectsDoNotFlapTheWindow(t *testing.T) {
	t.Parallel()
	var out strings.Builder
	ch, _ := collapsingChannel(&out, time.Now())

	// The workload: a broken subject interleaved with a healthy one. Only the broken one reaches a
	// diagnostic at all, so the healthy calls are simply the absence of a line.
	lines := 0
	for range 5 {
		lines += driveChannel(ch, siteReceiptInconsistent, 1)
		// a verified receipt on the same route: no line, and nothing to reopen
	}
	assert.Equal(t, 1, lines,
		"one line per window whatever else the route is doing; a success-reopened episode produced one per pair here, plus a false recovery claim beside it")
	assert.NotContains(t, out.String(), "cleared",
		"and nothing announces a recovery the source-scoped state has no standing to assert")
}

// TestNoticeCollapse_IsPerSource pins the scope: the faults are an UPSTREAM's, so one tenant's
// broken backend must not suppress another's report of its own.
func TestNoticeCollapse_IsPerSource(t *testing.T) {
	t.Parallel()
	at := time.Now()
	var a, b strings.Builder
	routeA, _ := collapsingChannel(&a, at)
	routeB, _ := collapsingChannel(&b, at)

	require.Equal(t, 1, driveChannel(routeA, siteReceiptInconsistent, 50))
	assert.Equal(t, 1, driveChannel(routeB, siteReceiptInconsistent, 50),
		"a stale pin on one route says nothing about another's, and a process-wide window would report only the first")
}

// TestNoticeCollapse_OnlyDeclaredSitesCollapse is the control on both sides of the declaration: a
// site outside collapsedNotices writes every line its bucket allows, and a channel with no windows
// at all (a leg with no source, e.g. a pre-session HTTP arm) collapses nothing.
func TestNoticeCollapse_OnlyDeclaredSitesCollapse(t *testing.T) {
	t.Parallel()
	at := time.Now()
	var out strings.Builder
	ch, _ := collapsingChannel(&out, at)

	// The double-commit line reports a fault in THIS proxy's wiring rather than in the flow store,
	// which is why it holds a site of its own: sharing the store fault's window would report it
	// nowhere for as long as the store stayed down.
	require.Equal(t, 1, driveChannel(ch, siteDeclassifyCommit, 5))
	assert.Positive(t, driveChannel(ch, siteDeclassifyDoubleCommit, 5),
		"an open store-fault window must not swallow a wiring fault beside it")

	var ungated strings.Builder
	route := newRouteNoticeLimiter(nil)
	frozen(route, at)
	bare := noticeWriter{out: &ungated, limits: route}
	assert.Equal(t, int(perClassNoticeBurst), driveChannel(bare, siteDeclassifyCommit, 50),
		"a leg with no source to attribute a window to writes what its bucket allows, exactly as before")
}

// TestNoticeCollapse_DeclarationsAreWellFormed is the table guard: a collapsed site must charge a
// bucket (there is otherwise no flood to collapse and no tally to fold into) and must say why one
// line per window is the whole of what an operator needs from it — which is the judgment the
// collapse rests on, and the one thing that cannot be inferred from the code.
func TestNoticeCollapse_DeclarationsAreWellFormed(t *testing.T) {
	t.Parallel()
	for site, decl := range collapsedNotices {
		assert.Contains(t, meteredNotices, site,
			"site %q collapses but charges no bucket", site)
		assert.NotEmpty(t, decl.why,
			"site %q must state why one line per window is enough; what a reader loses is every occurrence after the first, so an undeclared collapse is an unexamined one", site)
	}
	assert.Len(t, collapsedNoticeSites, len(collapsedNotices),
		"the derived slice and the declarations must describe the same set")
}

// TestNoticeCollapse_WindowIsClaimedOnceUnderConcurrency pins the one-atomic-operation shape.
//
// The alternative — peek the window, take the bucket, then mark it — is two steps that race, which
// is the composition saturationGate needed a mutex to make safe. Claiming first is a single CAS, so
// concurrent occurrences of one fault yield exactly one line.
func TestNoticeCollapse_WindowIsClaimedOnceUnderConcurrency(t *testing.T) {
	t.Parallel()
	at := time.Now()
	slot := newNoticeCollapse().forKey(siteReceiptInconsistent)
	require.NotNil(t, slot)

	claims := make(chan bool, 32)
	for range cap(claims) {
		go func() { claims <- slot.claim(at, noticeCollapseInterval) }()
	}
	won := 0
	for range cap(claims) {
		if <-claims {
			won++
		}
	}
	assert.Equal(t, 1, won, "exactly one concurrent occurrence may open a window")
}
