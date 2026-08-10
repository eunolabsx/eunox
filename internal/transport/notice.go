// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The stderr half of a refusal, as a MECHANISM rather than a lint.
//
// The RECORD half is enforced by the thing that writes it: refusalRecorders.forCategory READS
// refusalDeclarations at the moment a record is resolved, so "declared exempt" and "charges no
// bucket" are one fact. The notice half was the same shape one layer weaker — a table keyed by bare
// function name, living in a test, enforced only by an AST walk, beside a vocabulary that shipped
// with no runtime reader at all. What bounded a line was which function a site called, and the
// declaration only checked afterwards that the two agreed.
//
// Now noticef takes the SITE and resolves the bucket from that site's own declaration, which is the
// direct analogue of forCategory: a site cannot be declared metered and charge nothing, and a site
// with no declaration at all charges the floor-rate bucket rather than writing free. The walk in
// notice_bounding_test.go stays, for the two questions a runtime reader cannot answer — a line
// written through a shape it does not model, and a declaration nothing reaches.
//
// The bucket is no longer singular. It is split on the two axes the shared one collapsed:
//
//   - by CLASS, so a flood of the cheapest peer-driven line cannot take the last token from the
//     line that says an upstream is down (see noticeClass);
//   - by ROUTE, so one gateway tenant cannot silence another's (see newRouteNoticeLimiter),
//     with the proxy-wide table as the aggregate parent holding the total where it was.
//
// Both splits are the treatment the refusal RECORDS already had, on the same tieredBuckets: shares
// of one budget rather than a full budget each, so the reachable syscall rate does not multiply by
// the class or route count.

package transport

import (
	"fmt"
	"io"
	"strings"
)

// noticeSite names ONE diagnostic line (or one group of lines answering to the same
// disposition) so its declaration can be looked up where the line is written.
//
// A typed string rather than the enclosing function's name, which is what the old test-only table
// keyed on: one function legitimately holds lines of different WORTH — enforcedForwardCore writes
// an observe-mode downgrade beside a redaction failure — and a key that cannot tell them apart
// forces both into one answer.
type noticeSite string

// The metered diagnostic sites. Each is passed at its own call and looked up in
// noticeDeclarations at write time; the value is descriptive rather than the function's name,
// since several functions hold more than one site and two hold the same name.
const (
	// Class-traffic sites: an account of what a peer (or an upstream) SENT.
	siteUnmappedMethod      noticeSite = "unmapped-method"
	siteObserveDowngrade    noticeSite = "observe-downgrade"
	siteSamplingDowngrade   noticeSite = "sampling-observe-downgrade"
	siteNotifyPoolSaturated noticeSite = "notification-pool-saturated"
	siteHostInitialized     noticeSite = "host-initialized"

	// Class-failure sites: an account of something that BROKE.
	siteUpstreamlessForward      noticeSite = "upstreamless-forward"
	siteUpstreamlessNotification noticeSite = "upstreamless-notification"
	siteRedactionFault           noticeSite = "redaction-fault"
	siteDeclassifyCommit         noticeSite = "declassify-commit"
	siteUpstreamError            noticeSite = "upstream-error"
	siteInitiatorUnanswerable    noticeSite = "initiator-unanswerable"
	siteReceiptInconsistent      noticeSite = "effect-receipt-inconsistent"
	siteUpstreamNotifyFailed     noticeSite = "upstream-notification-failed"
	siteUpstreamPostFailed       noticeSite = "upstream-post-failed"
)

// noticeClass is what a diagnostic line is WORTH to an operator, and therefore which bucket it
// charges. The zero value is "unclassified", so a metered site added with no class charges the
// floor-rate fallback rather than inheriting a real class's share.
//
// The axis exists because the single shared bucket made the cheapest line and the most valuable
// one interchangeable: a peer looping `{"jsonrpc":"2.0","method":"x/bogus"}` — no id, no handler
// slot, no upstream round trip — could hold the bucket empty while a route's upstream started
// failing, and the operator saw no `upstream error` line at all, only a suppression tail folded
// onto an unrelated refusal. The tape was never affected (UPSTREAM_ERROR denies are policy-path
// records and unmetered), so what was lost is stderr legibility during an incident — which is the
// channel an operator actually watches while it is happening.
type noticeClass int

const (
	classUnclassified noticeClass = iota
	// classTraffic: an account of what a peer or an upstream SENT — a refusal, an observe-mode
	// downgrade, a session's handshake echo. Reachable at the sender's full rate on its cheapest
	// message, and every one of these has a record beside it on the tape, so an elided line costs
	// legibility rather than evidence.
	classTraffic
	// classFailure: an account of something that BROKE inside eunox, its flow store, or an
	// upstream — a connection down, a redaction that failed, a clear that did not commit, a
	// signed receipt that contradicts its contract. Well-formed traffic does not produce these,
	// so a flood of them is itself the signal, and they must not be starved by one that is.
	classFailure
)

// noticeClasses is the metered set, in bucket-table order. The divisor for each class's share of
// the aggregate, so adding a class costs one class's worth of aggregate rather than silently
// halving every existing class's share — the derivation refusalCategories uses.
var noticeClasses = []noticeClass{classTraffic, classFailure}

// label names a class in the suppression rollup. A count that spans one class must say which,
// since the reader cannot infer it from the line the count rides on.
func (c noticeClass) label() string {
	switch c {
	case classTraffic:
		return "traffic"
	case classFailure:
		return "failure"
	default:
		return "unclassified"
	}
}

// noticeBound is how ONE diagnostic site is bounded. The zero value is "undeclared", so a site
// added with no entry fails the call-site walk rather than inheriting an answer — the same shape
// refusalDeclarations uses for the RECORD half of a refusal.
//
// Four mechanisms bound a line in this package and only the first was ever written down. The
// declaration exists because the survey behind "how many syscalls can a peer drive" was re-derived
// by hand each time, which is how the routing refusal's line came to be unbounded while its
// record's exemption was being argued in prose.
type noticeBound int

const (
	noticeUndeclared noticeBound = iota
	// noticeMetered: the line goes through noticef, charging its class's bucket. What a
	// peer-drivable per-frame diagnostic must be.
	noticeMetered
	// noticeRecordGated: the line is written only when the refusal's own RECORD was admitted, so
	// it is bounded at that category's rate (recordRefusal returns its verdict for exactly this).
	// A second mechanism rather than a redundancy: these sites describe the record they ride on.
	noticeRecordGated
	// noticeOnce: a latch — at most one line per process or per session — so a peer's rate cannot
	// drive it however cheap the message is.
	noticeOnce
	// noticeExempt: not drivable at a per-frame rate, for the reason declared. Startup, teardown,
	// configuration, and session-lifecycle lines.
	noticeExempt
)

// noticeDeclaration is what every diagnostic site declares. class is required for a metered site
// and must be unset otherwise; why is required for an exemption and must be empty otherwise,
// mirroring refusalDeclaration: the reason IS the exemption.
type noticeDeclaration struct {
	bound noticeBound
	// class picks the bucket a metered line charges. Read at WRITE time (see noticef), which is
	// what makes "declared metered" and "charges that class's bucket" one fact rather than two
	// that a call site could put out of agreement.
	class noticeClass
	why   string
}

// The reasons an exemption can rest on, stated once each because they are shared arguments rather
// than per-site prose.
const (
	// exemptNotPeerDriven covers startup, shutdown, configuration and operator-command lines: the
	// number written over a process's life is fixed by how the operator ran it, not by traffic.
	exemptNotPeerDriven = "written from startup, teardown or operator-command paths, so a peer's send rate cannot drive it"
	// exemptCostsASession covers the per-session lifecycle lines. A peer CAN drive them, but only
	// by opening and closing sessions — each of which spawns or contacts an upstream, so the line
	// is many orders of magnitude cheaper than what it reports and bounding it would hide churn
	// that is itself the signal.
	exemptCostsASession = "one line per session lifecycle event, and a session costs an upstream spawn or handshake — the line is not the expensive part"
	// exemptOncePerConnection covers a line written at most once per host connection or upstream,
	// on a path that then ends it.
	exemptOncePerConnection = "written at most once per connection, on a path that ends it"
	// exemptNotADiagnostic covers a site that writes a RESPONSE BODY with the same fmt call the
	// walk looks for. Bounding it would corrupt what it serves.
	exemptNotADiagnostic = "not a diagnostic: it writes a response body, which bounding would truncate"
)

// noticeDeclarations answers, for every diagnostic line in this package, how it is bounded — and
// for a METERED one, which class's bucket it charges.
//
// It ships here rather than in the test that walks it because noticef READS it: the metered
// entries are consulted at write time, exactly as forCategory consults refusalDeclarations. The
// non-metered entries are the walk's half of the same table and are keyed by the writing
// function's qualified name, which is what an AST walk can see; a metered entry is keyed by the
// site constant its call passes, since one function can hold lines of two different classes.
var noticeDeclarations = map[noticeSite]noticeDeclaration{
	// (1) Metered, class TRAFFIC: reachable at a peer's or an upstream's send rate, one line per
	// frame, each with a record beside it on the tape.
	siteUnmappedMethod:      {bound: noticeMetered, class: classTraffic},
	siteObserveDowngrade:    {bound: noticeMetered, class: classTraffic},
	siteSamplingDowngrade:   {bound: noticeMetered, class: classTraffic},
	siteNotifyPoolSaturated: {bound: noticeMetered, class: classTraffic},
	// The host-initialized line is per `initialize` REQUEST: re-initialize is answered LOCALLY, so
	// it creates no session and contacts no upstream — the exemption it used to carry was reasoned
	// from a session's cost and did not apply.
	siteHostInitialized: {bound: noticeMetered, class: classTraffic},

	// (2) Metered, class FAILURE: an operator-facing account of something broken. Metered because
	// a peer or a dead upstream can still drive them per frame, classed apart so that flood cannot
	// take the last token from a class it does not belong to.
	siteUpstreamlessForward:      {bound: noticeMetered, class: classFailure},
	siteUpstreamlessNotification: {bound: noticeMetered, class: classFailure},
	siteRedactionFault:           {bound: noticeMetered, class: classFailure},
	siteDeclassifyCommit:         {bound: noticeMetered, class: classFailure},
	siteUpstreamError:            {bound: noticeMetered, class: classFailure},
	siteInitiatorUnanswerable:    {bound: noticeMetered, class: classFailure},
	siteReceiptInconsistent:      {bound: noticeMetered, class: classFailure},
	siteUpstreamNotifyFailed:     {bound: noticeMetered, class: classFailure},
	siteUpstreamPostFailed:       {bound: noticeMetered, class: classFailure},

	// (3) Gated on the RECORD's admission verdict, which spends that category's own bucket.
	// These and everything below are keyed by the writing function's QUALIFIED name (receiver
	// included), which is what an AST walk can see for a line that never reaches noticef. Qualified
	// rather than bare because this package has same-named twins that write on both — readUpstream
	// on each transport — and a bare key would let the second silently inherit the first's answer.
	"*HTTPProxy.checkOrigin":            {bound: noticeRecordGated},
	"*HTTPProxy.requireJSONContentType": {bound: noticeRecordGated},

	// (4) One-shot latches: at most one line however hard the source is driven.
	"warnStrictAuditOnce":           {bound: noticeOnce},
	"warnIfStrictAuditJustDegraded": {bound: noticeOnce},
	"*serverReqTracker.track":       {bound: noticeOnce},
	"*httpSession.broadcast":        {bound: noticeOnce},

	// (5) Deliberately unbounded, each carrying the reason it cannot be driven per frame.
	"*HTTPProxy.handleMetrics":           {bound: noticeExempt, why: exemptNotADiagnostic},
	"tightenTokenDir":                    {bound: noticeExempt, why: exemptNotPeerDriven},
	"WriteControlTokenFile":              {bound: noticeExempt, why: exemptNotPeerDriven},
	"*HTTPProxy.warnForwardedForPosture": {bound: noticeExempt, why: exemptNotPeerDriven},
	"*HTTPProxy.Serve":                   {bound: noticeExempt, why: exemptNotPeerDriven},
	"NewHTTPProxyGateway":                {bound: noticeExempt, why: exemptNotPeerDriven},
	"BuildRoutes":                        {bound: noticeExempt, why: exemptNotPeerDriven},
	"DeleteMCPHTTPSession":               {bound: noticeExempt, why: exemptNotPeerDriven},
	"*HTTPProxy.handleKill":              {bound: noticeExempt, why: exemptNotPeerDriven},
	"printRemoteUpstreamNotice":          {bound: noticeExempt, why: exemptNotPeerDriven},
	"PrintRoutePolicyNotices":            {bound: noticeExempt, why: exemptNotPeerDriven},
	"*StdioProxy.signalUpstream":         {bound: noticeExempt, why: exemptNotPeerDriven},
	"*StdioProxy.awaitUpstreamDrain":     {bound: noticeExempt, why: exemptNotPeerDriven},
	"*StdioProxy.initUpstream":           {bound: noticeExempt, why: exemptNotPeerDriven},
	"waitBounded":                        {bound: noticeExempt, why: exemptNotPeerDriven},
	"*StdioProxy.Start":                  {bound: noticeExempt, why: exemptNotPeerDriven},
	"*HTTPProxy.writeSessionCreateError": {bound: noticeExempt, why: exemptCostsASession},
	"*HTTPProxy.newSession":              {bound: noticeExempt, why: exemptCostsASession},
	"*HTTPProxy.newRemoteSession":        {bound: noticeExempt, why: exemptCostsASession},
	"*HTTPProxy.reapOnce":                {bound: noticeExempt, why: exemptCostsASession},
	"*HTTPProxy.reclaimKilledSession":    {bound: noticeExempt, why: exemptCostsASession},
	"*StdioProxy.readUpstream":           {bound: noticeExempt, why: exemptOncePerConnection},
	"*httpSession.readUpstream":          {bound: noticeExempt, why: exemptOncePerConnection},
	"*StdioProxy.serveHost":              {bound: noticeExempt, why: exemptOncePerConnection},
}

// The stderr NOTICE budget, on its own rather than a share of the record aggregate: a notice is not
// a record, so it neither spends that budget nor may it divide it. Sized for an operator watching a
// terminal — a couple of lines a second per class names the drift or the flood, and every line
// elided is counted into the next one of its class rather than lost, so the notice never
// under-states what is happening.
//
// Stated PER CLASS and multiplied up, so adding a class costs one class's worth of aggregate rather
// than halving every existing class's share (20/10 = 2/s, 20/11 = 1/s is what plain division does
// at the integer boundary). The aggregate is still what bounds the reachable syscall rate; it just
// grows with the set it divides.
const (
	perClassNoticeRatePerSec = 2
	perClassNoticeBurst      = 10
)

var (
	noticeRatePerSec = perClassNoticeRatePerSec * len(noticeClasses)
	noticeBurst      = perClassNoticeBurst * len(noticeClasses)

	perClassNoticeRate      = perBucketShare(noticeRatePerSec, len(noticeClasses))
	perClassNoticeBurstSize = perBucketShare(noticeBurst, len(noticeClasses))
)

// noticeLimiter is one leg's stderr-diagnostic admission control: a bucket per notice CLASS, and
// optionally an aggregate parent it also charges. The same two-tier table the refusal RECORDS use,
// one axis over — see tieredBuckets.
type noticeLimiter struct {
	tieredBuckets[noticeClass]
}

// newNoticeLimiter builds a proxy's AGGREGATE notice table: one bucket per class, no parent.
// Every route's table charges this one, so it is what holds the whole process's diagnostic syscall
// rate where it was before the split.
func newNoticeLimiter() *noticeLimiter {
	return &noticeLimiter{tieredBuckets: newTieredBuckets(perClassNoticeRate, perClassNoticeBurstSize, noticeClasses)}
}

// newRouteNoticeLimiter builds ONE of routes gateway routes' notice tables, charging aggregate as
// its parent.
//
// Per route for the reason saturationGate states for its own records and newUpstreamRefusalLimiter
// for a session's: one tenant's flood must not elide another's. A peer looping an unmapped method
// against /mcp/routeA held the single proxy-wide bucket empty and suppressed routeB's routing-refusal
// lines for as long as it kept sending — and refuseUnroutable's whole reason for naming the method is
// that an operator can see protocol drift, which a suppressed line reduces to a count.
//
// Per route rather than per SESSION because a route is an operator-configured tenant boundary with a
// small, known count, while sessions are unbounded by anything but maxSessions — a per-session split
// would put thousands of buckets under one aggregate for a channel whose whole budget is a few lines
// a second.
//
// Each route gets a SHARE of the aggregate rather than a full budget, which is what makes the split
// mean anything: a parent alone bounds the total but is drained first-come, so a child holding the
// parent's whole rate can still empty it and starve its siblings — the bug this exists to fix,
// reintroduced one tier down. A single-route gateway (and stdio, which has no route tier at all)
// therefore sees exactly the pre-split numbers. The floor keeps a many-route gateway's per-route
// bucket alive at the cost of the shares summing past the aggregate, which the parent then throttles
// first-come — the residual, and the same one perBucketFloor carries on the record side.
//
// aggregate may be nil (a bare-struct-literal proxy in a test), which bounds the route alone.
func newRouteNoticeLimiter(aggregate *noticeLimiter, routes int) *noticeLimiter {
	if routes < 1 {
		routes = 1
	}
	l := &noticeLimiter{tieredBuckets: newTieredBuckets(
		perBucketShare(perClassNoticeRatePerSec, routes),
		perBucketShare(perClassNoticeBurst, routes),
		noticeClasses)}
	if aggregate != nil {
		l.parent = &aggregate.tieredBuckets
	}
	return l
}

// noticeWriter is a leg's diagnostic CHANNEL: where a line goes AND what bounds it, as one value.
//
// One value rather than two fields, because holding them apart is a wiring fault nothing catches —
// a leg that sets the writer and not the bucket writes unbounded with every guard still green.
// serverRequestParams was the live shape: its writer was its own errOut field while its bucket came
// from the unblocker it carries, two independently zeroable fields feeding one line.
//
// The zero value writes every line to os.Stderr, which is what a bare-struct-literal proxy in a
// test gets and the behaviour every leg had before the bucket existed.
type noticeWriter struct {
	out    io.Writer
	limits *noticeLimiter
}

// errOut resolves this channel's destination, os.Stderr when unset. The one place a leg's
// diagnostic lines — bounded or not — resolve where they go.
func (n noticeWriter) errOut() io.Writer { return resolvedErrOut(n.out) }

// noticesTo builds an UNBOUNDED channel on w.
//
// Test-only, and held to that by the call-site walk rather than by this comment: a production leg
// reaching for it would be declared metered and charge nothing, which is the exact disagreement
// this file's mechanism exists to make impossible.
func noticesTo(w io.Writer) noticeWriter { return noticeWriter{out: w} }

// noticef writes one bounded diagnostic line for site, folding whatever site's CLASS elided since
// its last admitted line into this one's own text.
//
// The bucket is resolved from site's declaration rather than handed in, which is what makes
// "declared metered" and "charges that class's bucket" one fact — the rule forCategory applies to
// the record half. A site with no declaration charges the floor-rate fallback: the zero
// noticeDeclaration means nobody has answered the question, and the safe answer to that is the
// bounded one.
//
// The rollup is applied HERE rather than returned for a caller to append, for the reason
// admitRefusalRecord hides its own: a site that spends a token and forgets the count silently
// under-states a flood, and nothing fails. Its text names the CLASS the count spans, since one
// bucket now serves several sites and the reader cannot infer the scope from the line it rides on.
func noticef(n noticeWriter, site noticeSite, format string, args ...interface{}) {
	class := noticeDeclarations[site].class
	admitted, suppressed := n.limits.admitNotice(class)
	if !admitted {
		return
	}
	if suppressed > 0 {
		format = strings.TrimSuffix(format, "\n") + " (%d further " + class.label() + " diagnostics suppressed)\n"
		args = append(args, suppressed)
	}
	_, _ = fmt.Fprintf(n.errOut(), format, args...)
}

// admitNotice reports whether a diagnostic of this class may be written now, and how many of that
// class were elided since the last admitted one. A nil limiter admits everything — the unbounded
// disposition a zero noticeWriter carries.
func (l *noticeLimiter) admitNotice(class noticeClass) (ok bool, suppressed uint64) {
	if l == nil {
		return true, 0
	}
	return l.admit(class)
}
