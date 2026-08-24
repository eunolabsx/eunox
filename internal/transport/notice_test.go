// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The diagnostic budget's own guards: the class split it exists for, the derivation the bucket
// table is keyed by, and the rollup an operator reads what they missed from.

package transport

import (
	"bytes"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNoticeClasses_AreDerivedFromTheDeclarations is what makes adding a class safe: the bucket
// table is keyed by this list, so a class some site declares but the list omits routes every one of
// that class's sites to the floor-rate fallback — 1/s, shared with every unclassified site — with
// nothing failing. The refusal half derives its own set the same way.
func TestNoticeClasses_AreDerivedFromTheDeclarations(t *testing.T) {
	t.Parallel()
	require.NotEmpty(t, noticeSiteClass, "no sites declared; every guard here would pass vacuously")

	for site, class := range noticeSiteClass {
		assert.NotEqual(t, classUnclassified, class,
			"site %q declares no class, so it charges the floor-rate fallback rather than a share of its own", site)
		assert.Contains(t, noticeClasses, class,
			"site %q charges class %d, which the bucket table is not keyed by", site, class)
	}
	assert.True(t, slices.IsSorted(noticeClasses),
		"the derived list must be sorted: it is built by ranging a map, and an unsorted one makes the table's identity vary per process")
	assert.Equal(t, len(slices.Compact(slices.Clone(noticeClasses))), len(noticeClasses),
		"a duplicate class builds duplicate bucket keys and multiplies the sizing")

	// Every class must have a real bucket, and an unclassified site must NOT.
	lim := newNoticeLimiter(1)
	for _, class := range noticeClasses {
		assert.NotSame(t, lim.fallback, lim.bucket(class), "class %d has no bucket of its own", class)
		assert.NotEmpty(t, class.label(), "a class with no label makes its rollup unreadable")
		assert.NotEqual(t, "unclassified", class.label(),
			"class %d renders as unclassified, so its rollup cannot be told from an undeclared site's", class)
	}
	assert.Same(t, lim.fallback, lim.bucket(classUnclassified),
		"an undeclared site must charge the bounded fallback rather than a real class's share")
}

// TestNotice_AFloodOfOneClassCannotSilenceAnother is the property the whole class axis exists for,
// and the one the budget's collapse to a single bucket per class had to keep.
//
// A peer looping the cheapest per-frame line it can drive (an unmapped method, classTraffic) must
// not be able to hold the only bucket empty while a route's upstream starts failing — the operator
// then sees no `upstream error` line at all, which is the channel they are actually watching during
// an incident.
func TestNotice_AFloodOfOneClassCannotSilenceAnother(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	w := noticeWriter{out: &out, limits: newNoticeLimiter(1)}

	// Drain the traffic class well past its burst.
	flooded := 0
	for range perClassNoticeBurst + 100 {
		if line, ok := w.admitNotice(siteUnmappedMethod); ok {
			line.writef("unmapped\n")
			flooded++
		}
	}
	require.Positive(t, flooded, "the leading edge of a flood must still be written")
	assert.LessOrEqual(t, flooded, perClassNoticeBurst+1, "the flooding class is bounded by its own bucket")

	// The failure and obligation classes are untouched by it.
	failure, ok := w.admitNotice(siteUpstreamError)
	assert.True(t, ok, "a traffic flood must not elide the line saying an upstream is failing")
	failure.writef("upstream error\n")

	obligation, ok := w.admitNotice(siteRedactionFault)
	assert.True(t, ok, "a traffic flood must not elide the line saying a redaction obligation failed")
	obligation.writef("SECURITY: redaction failed\n")

	assert.Contains(t, out.String(), "upstream error")
	assert.Contains(t, out.String(), "SECURITY: redaction failed")
}

// TestNotice_UpstreamErrorsCannotSilenceAnObligationFailure is the second split, one level in.
//
// A generic transit error is free to an upstream — it can return one for any call, on a route with
// no policy obligation in play — while an obligation failure takes a call that CARRIES one. Sharing
// a bucket therefore let an adversarial upstream elide its own `SECURITY: redaction failed` lines by
// erroring generically on every OTHER call, which is the argument classObligation rests on.
func TestNotice_UpstreamErrorsCannotSilenceAnObligationFailure(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	w := noticeWriter{out: &out, limits: newNoticeLimiter(1)}

	for range perClassNoticeBurst + 100 {
		if line, ok := w.admitNotice(siteUpstreamError); ok {
			line.writef("upstream error\n")
		}
	}
	line, ok := w.admitNotice(siteReceiptInconsistent)
	require.True(t, ok, "a failure-class flood must not elide the line saying a signed receipt contradicts its contract")
	line.writef("receipt inconsistent\n")
	assert.Contains(t, out.String(), "receipt inconsistent")
}

// TestNotice_SuppressedLinesAreCountedIntoTheNextAdmittedOne pins the rollup: what a suppressed
// line costs is legibility, not the knowledge that it happened. A bounded channel that reported
// nothing would leave an operator reading a quiet terminal during a flood.
func TestNotice_SuppressedLinesAreCountedIntoTheNextAdmittedOne(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	lim := newNoticeLimiter(1)
	at := time.Now()
	lim.setNow(func() time.Time { return at })
	w := noticeWriter{out: &out, limits: lim}

	const attempts = perClassNoticeBurst + 40
	for range attempts {
		if line, ok := w.admitNotice(siteUnmappedMethod); ok {
			line.writef("unmapped\n")
		}
	}
	out.Reset()

	// A refill second, then the next admitted line carries the tally.
	at = at.Add(time.Second)
	line, ok := w.admitNotice(siteUnmappedMethod)
	require.True(t, ok, "a refill must admit again")
	line.writef("unmapped\n")

	got := out.String()
	assert.Contains(t, got, "diagnostics suppressed", "the count of what the reader did not see must ride the next admitted line")
	assert.Contains(t, got, classTraffic.label(), "a count that does not name its class gets misread")
	assert.Contains(t, got, noticeScopeProxy+"-wide", "a count that does not name its scope gets misread")
	assert.Equal(t, 1, strings.Count(got, "\n"), "a diagnostic must reach the pipe as one line, tail included")

	// And the tally resets, so the following line does not double-report.
	out.Reset()
	at = at.Add(time.Second)
	line, ok = w.admitNotice(siteUnmappedMethod)
	require.True(t, ok)
	line.writef("unmapped\n")
	assert.NotContains(t, out.String(), "suppressed", "after reporting, the tally must reset")
}

// TestNoticeWriter_ZeroValueIsUnboundedRatherThanSilent pins the nil-limits arm. A leg assembled by
// a bare struct literal (as tests build) has no budget; writing nothing would make a diagnostic
// disappear on exactly the legs a reader is most likely to be debugging.
func TestNoticeWriter_ZeroValueIsUnboundedRatherThanSilent(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	w := noticeWriter{out: &out}
	for range 100 {
		line, ok := w.admitNotice(siteUnmappedMethod)
		require.True(t, ok, "an unbounded channel admits every line")
		line.writef("x\n")
	}
	assert.Equal(t, 100, strings.Count(out.String(), "x"))
}

// TestNoticeLatch_FiresOnceAndRefusesWhenAbsent covers the one-shot used for a line whose first
// occurrence is the whole finding. The nil arm is the one that matters: a leg holding no latch must
// refuse rather than panic, which a pointer receiver makes reachable.
func TestNoticeLatch_FiresOnceAndRefusesWhenAbsent(t *testing.T) {
	t.Parallel()
	var latch noticeLatch
	assert.True(t, latch.admitOnce(), "the first occurrence is the finding")
	for range 10 {
		assert.False(t, latch.admitOnce(), "every later occurrence is refused")
	}
	var absent *noticeLatch
	assert.False(t, absent.admitOnce(), "a nil latch refuses rather than panicking")
}
