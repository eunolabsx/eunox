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
// site declared collapsePerOccurrence writes every line its bucket allows, and a channel with no
// windows at all (a leg with no source, e.g. a pre-session HTTP arm) collapses nothing.
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

	// The failure class is the recorded decision, not an omission: a dead upstream drives these at
	// the request rate — the windowed sites' own criterion — and they are still reported per
	// occurrence, because each names the call that failed and the error behind it. Pinned here so
	// the trade is visible if someone later folds them in.
	require.Equal(t, collapsePerOccurrence, meteredNotices[siteUpstreamError].collapse)
	assert.Equal(t, perClassNoticeBurst, driveChannel(ch, siteUpstreamError, 50),
		"a failure line writes what its bucket allows; collapsing it would leave 'an upstream is failing' and remove which calls failed")

	var ungated strings.Builder
	route := newRouteNoticeLimiter(nil)
	frozen(route, at)
	bare := noticeWriter{out: &ungated, limits: route}
	assert.Equal(t, int(perClassNoticeBurst), driveChannel(bare, siteDeclassifyCommit, 50),
		"a leg with no source to attribute a window to writes what its bucket allows, exactly as before")
}

// TestNoticeCollapse_EverySiteAnswersTheQuestion is the completeness gate, and it is the whole
// reason the disposition moved into the site's own declaration.
//
// The collapse shipped as an opt-in list, which asked nothing of the sites outside it: a site was
// collapsed by being written down and uncollapsed by being forgotten, and those two are
// indistinguishable to a reader. Every classFailure site meets the collapsed sites' OWN stated
// criterion — a fault a merely broken deployment drives at the request rate from a conforming peer
// — and all six sat outside the list with no judgment recorded either way. The site floor beside it
// had the same treatment applied for the same reason (see floorDisposition): every metered site says
// which side it is on and why, so the next one added answers the question instead of inheriting an
// answer.
// sharedCollapseReasons maps each reason written for a whole CLASS to the class it argues from.
// A per-site reason is absent here and answers only to the non-emptiness check: it is the sites
// that share an argument that can silently inherit the wrong one.
var sharedCollapseReasons = map[string]noticeClass{
	uncollapsedRateIsTheSignal:     classTraffic,
	uncollapsedNamesTheFailingCall: classFailure,
}

func TestNoticeCollapse_EverySiteAnswersTheQuestion(t *testing.T) {
	t.Parallel()
	windowed := 0
	for site, decl := range meteredNotices {
		assert.NotEqual(t, collapseUndeclared, decl.collapse,
			"site %q declares no collapse disposition; collapsing loses every occurrence after the first in the window and not collapsing leaves a per-frame fault charging its class bucket, so neither may be inherited", site)
		// Required on BOTH sides, unlike an exemption reason: each answer costs something the code
		// cannot state for itself, and the flood the collapse was built for still exists on the
		// class whose sites answered "no" by omission.
		assert.NotEmpty(t, decl.collapseWhy,
			"site %q states no reason for its collapse disposition; what a reader loses either way is not inferable from the call site, which is what makes this a declaration rather than a switch", site)
		// Non-emptiness alone cannot catch the mistake the field exists for: eleven of the fifteen
		// rows carry one of two SHARED reasons, so a site pasted with its neighbour's — a failure
		// line claiming to be "an account of one message the peer sent" — is a declaration
		// contradicting its own class, with every assertion still green. A shared reason is
		// therefore bound to the class whose argument it makes, the way the floor reason beside it
		// is bound to its own disposition.
		if class, shared := sharedCollapseReasons[decl.collapseWhy]; shared {
			assert.Equal(t, class, decl.class,
				"site %q carries the reason written for class %q while declaring class %q; the two shared reasons argue from what a line of their own class CARRIES, so neither is true of the other", site, class.label(), decl.class.label())
		}
		if decl.collapse == collapseWindowed {
			windowed++
		}
	}
	assert.Len(t, collapsedNoticeSites, windowed,
		"the derived slice and the declarations must describe the same set; a site declared collapsed with no slot silently reports every occurrence")
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
