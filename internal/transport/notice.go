// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The stderr half of a refusal: a bounded diagnostic channel.
//
// Every metered diagnostic goes through noticeWriter.admitNotice, which charges a token bucket
// held per notice CLASS and hands back the line to write. A suppressed line is not lost — it is
// counted into the tally the next admitted line of that class carries, so an operator reading a
// terminal during an incident always learns what they did not see.
//
// The CLASS axis is the one split this budget keeps: a peer looping a cheap unmapped method must
// not be able to hold the only bucket empty while a route's upstream starts failing. Three classes
// separate "what a peer sent" from "what broke in transit" from "a security obligation that did not
// hold", so a flood of the cheapest line cannot silence the most valuable one.
//
// Everything is proxy-wide. A gateway tenant CAN therefore spend a class budget its siblings share,
// and a session's dead upstream can elide a sibling session's first `upstream error` line until the
// bucket refills. That is an accepted trade: the per-route and per-holder tiers, floors and
// source-collapse windows that closed it cost several times this file in machinery for a
// reallocation of stderr legibility that the suppression count already reports.

package transport

import (
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// noticeSite identifies one diagnostic call site. It is passed at the call and looked up in
// noticeSiteClass at write time; the value is descriptive rather than the function's name, since
// several functions hold more than one site and two hold the same name.
type noticeSite string

// The metered diagnostic sites.
const (
	siteUnmappedMethod           noticeSite = "unmapped-method"
	siteObserveDowngrade         noticeSite = "observe-downgrade"
	siteSamplingDowngrade        noticeSite = "sampling-observe-downgrade"
	siteNotifyPoolSaturated      noticeSite = "notification-pool-saturated"
	siteHostInitialized          noticeSite = "host-initialized"
	siteUpstreamlessForward      noticeSite = "upstreamless-forward"
	siteUpstreamlessNotification noticeSite = "upstreamless-notification"
	siteUpstreamError            noticeSite = "upstream-error"
	siteInitiatorUnanswerable    noticeSite = "initiator-unanswerable"
	siteUpstreamNotifyFailed     noticeSite = "upstream-notification-failed"
	siteNotifyUntranslatable     noticeSite = "notification-untranslatable"
	siteUpstreamPostFailed       noticeSite = "upstream-post-failed"
	siteRedactionFault           noticeSite = "redaction-fault"
	siteReceiptInconsistent      noticeSite = "effect-receipt-inconsistent"
)

// noticeClass is what a diagnostic line is WORTH to an operator, and therefore which bucket it
// charges. The zero value is "unclassified", so a site added with no entry in noticeSiteClass
// charges the floor-rate fallback rather than inheriting a real class's share.
type noticeClass int

const (
	classUnclassified noticeClass = iota
	// classTraffic: an account of what a peer or an upstream SENT — a refusal, an observe-mode
	// downgrade, a session's handshake echo. Reachable at the sender's full rate on its cheapest
	// message, and every one of these has a record beside it on the tape, so an elided line costs
	// legibility rather than evidence.
	classTraffic
	// classFailure: an account of something that BROKE in transit — an upstream connection down, a
	// notification POST that failed, a forward with no upstream to forward through. Well-formed
	// traffic does not produce these, so a flood of them is itself the signal, and they must not be
	// starved by one that is.
	classFailure
	// classObligation: a security obligation policy attached to a call did not hold — a redactFields
	// directive that could not be applied, or a signed effect receipt contradicting the contract
	// policy was written against. Apart from
	// classFailure because reaching one takes a call CARRYING an obligation, which a generic transit
	// error does not.
	classObligation
)

// noticeClasses is the set the bucket table is keyed by, DERIVED from the site declarations rather
// than typed out beside them. A hand-written list is two lists that must agree: one naming a class
// no site charges builds a bucket nothing spends, and one MISSING a class some site declares routes
// every one of that class's sites to the floor-rate fallback — silently, at 1/s shared with every
// other unclassified site, which is the class separation this budget exists for quietly undone.
//
// It PROJECTS the map's values where a key-collecting derivation would not, so the dedup is
// load-bearing: without it this is one entry per SITE where one per class is meant, which builds
// duplicate bucket keys and multiplies the sizing.
var noticeClasses = declaredNoticeClasses()

func declaredNoticeClasses() []noticeClass {
	out := make([]noticeClass, 0, len(noticeSiteClass))
	for _, class := range noticeSiteClass {
		// classUnclassified is filtered rather than registered: registering it would hand a site
		// that forgot its class a full class bucket, and move every genuinely undeclared site off
		// the floor-rate fallback onto it, since they all resolve to the same key.
		if class == classUnclassified {
			continue
		}
		out = append(out, class)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// label names a class in the suppression rollup. A count that spans one class must say which,
// since the reader cannot infer it from the line the count rides on.
func (c noticeClass) label() string {
	switch c {
	case classTraffic:
		return "traffic"
	case classFailure:
		return "failure"
	case classObligation:
		return "obligation"
	default:
		return "unclassified"
	}
}

// noticeSiteClass declares which class each metered site charges. A site missing here resolves to
// classUnclassified and charges the floor-rate fallback: the zero value means nobody has answered
// the question, and the safe answer to that is the bounded one.
var noticeSiteClass = map[noticeSite]noticeClass{
	// TRAFFIC: reachable at a peer's or an upstream's send rate, one line per frame, each with a
	// record beside it on the tape.
	siteUnmappedMethod:      classTraffic,
	siteObserveDowngrade:    classTraffic,
	siteSamplingDowngrade:   classTraffic,
	siteNotifyPoolSaturated: classTraffic,
	siteHostInitialized:     classTraffic,

	// FAILURE: an operator-facing account of something broken in transit. Each occurrence names a
	// different failing call and the error behind it, which is what an operator reads it for.
	siteUpstreamlessForward:      classFailure,
	siteUpstreamlessNotification: classFailure,
	siteUpstreamError:            classFailure,
	siteInitiatorUnanswerable:    classFailure,
	siteUpstreamNotifyFailed:     classFailure,
	siteNotifyUntranslatable:     classFailure,
	siteUpstreamPostFailed:       classFailure,

	// OBLIGATION: a security obligation that did not hold. A merely broken deployment can drive
	// these at the request rate from a conforming peer, so within the class one obligation's
	// failure can still elide another's.
	siteRedactionFault:      classObligation,
	siteReceiptInconsistent: classObligation,
}

const (
	perClassNoticeRatePerSec = 2
	perClassNoticeBurst      = 10
)

// noticeScopeProxy qualifies the suppression rollup: the count spans this class across the whole
// process. Named rather than inferred, since a reader cannot tell the span from the line it rides on.
const noticeScopeProxy = "proxy"

// noticeLimiter is the proxy's stderr-diagnostic admission control: one token bucket per notice
// class, plus a floor-rate fallback for any site with no declared class. One table per proxy —
// there is no tier below it, so a route or a session selects nothing.
type noticeLimiter struct {
	buckets  map[noticeClass]*recordRateLimiter
	fallback *recordRateLimiter
}

// newNoticeLimiter builds the proxy's notice table, sized for the given number of tenants (routes
// on a gateway; 1 for stdio). Each tenant is given room for its own per-class share rather than a
// division of a fixed budget, so adding a route does not shrink an existing route's burst to
// nothing — the budget is not split per route, so this is the whole of what tenancy costs.
func newNoticeLimiter(tenants int) *noticeLimiter {
	tenants = max(tenants, 1)
	rate, burst := float64(perClassNoticeRatePerSec*tenants), float64(perClassNoticeBurst*tenants)
	buckets := make(map[noticeClass]*recordRateLimiter, len(noticeClasses))
	for _, class := range noticeClasses {
		buckets[class] = newRecordRateLimiter(rate, burst)
	}
	return &noticeLimiter{buckets: buckets, fallback: newRecordRateLimiter(perBucketFloor, perBucketFloor)}
}

// bucket resolves a class's bucket, falling back to the floor-rate one for an unclassified site.
func (l *noticeLimiter) bucket(class noticeClass) *recordRateLimiter {
	// An unclassified site charges the fallback explicitly rather than by falling out of the map,
	// so the zero value's disposition is stated where it is decided.
	if class == classUnclassified {
		return l.fallback
	}
	if b, ok := l.buckets[class]; ok {
		return b
	}
	return l.fallback
}

// setNow overrides the clock on every bucket, for tests that drive the refill deterministically.
func (l *noticeLimiter) setNow(now func() time.Time) {
	for _, b := range l.buckets {
		b.setNow(now)
	}
	l.fallback.setNow(now)
}

// noticeLatch is a one-shot gate: the first caller wins and every later one is refused, for a line
// where only the first occurrence tells an operator anything. Zero value usable.
type noticeLatch struct{ fired atomic.Bool }

// admitOnce reports whether this is the first call — true exactly once per holder.
//
// A nil latch refuses rather than panicking: a leg assembled without one (a bare struct literal in
// a test) has no holder to be the one-shot of, and the bounded answer for "no latch" is to write
// nothing.
func (l *noticeLatch) admitOnce() bool {
	if l == nil {
		return false
	}
	return l.fired.CompareAndSwap(false, true)
}

// noticeWriter is one leg's diagnostic CHANNEL: where a line goes and what bounds it. One value
// rather than a writer field beside a bucket field, so a leg cannot be wired with half of it.
type noticeWriter struct {
	out    io.Writer
	limits *noticeLimiter
}

// errOut resolves this channel's destination, os.Stderr when unset. The one place a leg's
// diagnostic lines — bounded or not — resolve where they go.
func (n noticeWriter) errOut() io.Writer { return resolvedErrOut(n.out) }

// noticeLine is an ADMITTED diagnostic: the bucket has already been charged and the rollup already
// resolved, so the only thing left is the text. The zero value writes nothing, which is what a
// caller ignoring admitNotice's verdict gets.
type noticeLine struct {
	out io.Writer
	// tail is what the admission has to say beyond the caller's own text — see noticeTail.
	tail string
}

// writef renders this line, folding in whatever tail the admission resolved.
//
// A line with a tail is rendered whole and written ONCE rather than appending the tail to the
// caller's format: appending it puts the tail through Fprintf's own scan, where a `%` in a class
// label would be read as a verb against an already-exhausted argument list. Two writes were not an
// option — a diagnostic must reach the pipe as one syscall or two goroutines interleave halves of a
// line.
//
// It also keeps this a printf wrapper vet can INFER, since neither branch assigns to format or args.
func (l noticeLine) writef(format string, args ...interface{}) {
	if l.out == nil {
		return
	}
	if l.tail == "" {
		_, _ = fmt.Fprintf(l.out, format, args...)
		return
	}
	_, _ = io.WriteString(l.out, strings.TrimSuffix(fmt.Sprintf(format, args...), "\n")+l.tail)
}

// noticeTail is what an admitted line says beyond its own text: that lines of its class were elided
// since the last one.
//
// It names the CLASS and the SCOPE, for the reason the record half stamps suppressed_refusal_scope:
// one bucket serves several sites, so a bare count is a count that gets misread.
//
// Built rather than Sprintf'd because this is also the ADMITTED path's only extra work, and a
// second format-string parse to render one integer is the kind of cost that is invisible until it
// is the thing being measured.
func noticeTail(suppressed uint64, class noticeClass) string {
	if suppressed == 0 {
		return ""
	}
	var b strings.Builder
	var digits [20]byte
	b.WriteString(" (")
	b.Write(strconv.AppendUint(digits[:0], suppressed, 10))
	b.WriteString(" further ")
	b.WriteString(class.label())
	b.WriteString(" diagnostics suppressed, ")
	b.WriteString(noticeScopeProxy)
	b.WriteString("-wide)\n")
	return b.String()
}

// admitNotice charges site's bucket and returns the line to write, or false when this one is
// elided. It is the ONE entry point every metered diagnostic goes through, and the admission is
// taken BEFORE the caller builds its arguments.
//
// That ordering is the whole shape. On the flood path the bucket exists for, every argument the
// caller built is thrown away — a UTF-8 walk, a join, or simply the variadic boxing every one of
// them pays — and the boxing is most of it, which is why this is a CALL-SITE ordering that no
// lazier signature here could remove.
//
// It returns a LINE rather than a bool. A bool is a peek the mechanism never hears about again, so
// a site pre-gating on one would either write its line through a second admission (spending two
// tokens for one line) or skip without counting (under-stating the very flood the count exists to
// report). Because this hands out the bucket's accumulated tally, a caller that takes a line and
// does not write it destroys that count.
//
// The nil-limits guard is here rather than on a second method, because nil is the state a zero
// noticeWriter carries and this is the one place that can produce one.
func (n noticeWriter) admitNotice(site noticeSite) (noticeLine, bool) {
	if n.limits == nil {
		return noticeLine{out: n.errOut()}, true
	}
	class := noticeSiteClass[site]
	ok, suppressed := n.limits.bucket(class).admit()
	if !ok {
		return noticeLine{}, false
	}
	return noticeLine{out: n.errOut(), tail: noticeTail(suppressed, class)}, true
}
