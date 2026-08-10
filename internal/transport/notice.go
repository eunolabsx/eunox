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
// Now admitNotice takes the SITE and resolves the bucket from that site's own declaration, which is
// the direct analogue of forCategory: a site cannot be declared metered and charge nothing, and a
// site with no declaration at all charges the floor-rate bucket rather than writing free. The walk
// in notice_bounding_test.go stays, for the two questions a runtime reader cannot answer — a line
// written through a shape it does not model, and a declaration nothing reaches.
//
// The declaration is TWO tables rather than one with two key spaces. A metered site is keyed by the
// site constant its own call passes (meteredNotices, which admitNotice reads); every other line is
// keyed by the writing function's qualified name (unmeteredNotices, which only the walk can read,
// since the line never reaches this file). One map held both, so a key meant "site constant" or "Go
// function name" depending on the value beside it, and nothing stopped a metered entry being keyed
// by a function name — where admitNotice could never find it and it would silently charge the floor
// bucket. Splitting by key kind is not the "two lists that must agree" the single table replaced:
// the halves answer different questions about disjoint sets of lines and there is nothing to
// reconcile between them. Metered-ness is now membership in the first map rather than a field, so
// noticeBound has no metered value to write in the second.
//
// The bucket is no longer singular. It is split on the axes the shared one collapsed:
//
//   - by CLASS, so a flood of the cheapest peer-driven line cannot take the last token from the
//     line that says an upstream is down, nor a flapping upstream's own errors from the line that
//     says a security obligation did not hold (see noticeClass);
//   - by ROUTE, so one gateway tenant cannot silence another's (see newRouteNoticeLimiter),
//     with the proxy-wide table as the aggregate parent holding the total where it was;
//   - and, below the route, by a per-SESSION reserved floor rather than a third table — one
//     guaranteed line per class per session, spent only where the route's bucket refuses (see
//     noticeReserve).
//
// The first two splits are the treatment the refusal RECORDS already had, on the same tieredBuckets:
// shares of one budget rather than a full budget each, so the reachable syscall rate does not
// multiply by the class or route count.

package transport

import (
	"fmt"
	"io"
	"slices"
	"strings"
	"sync/atomic"
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
// meteredNotices at write time; the value is descriptive rather than the function's name,
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
	siteUpstreamError            noticeSite = "upstream-error"
	siteInitiatorUnanswerable    noticeSite = "initiator-unanswerable"
	siteUpstreamNotifyFailed     noticeSite = "upstream-notification-failed"
	siteUpstreamPostFailed       noticeSite = "upstream-post-failed"

	// Class-obligation sites: a security obligation policy attached to a call did not hold.
	siteRedactionFault      noticeSite = "redaction-fault"
	siteDeclassifyCommit    noticeSite = "declassify-commit"
	siteReceiptInconsistent noticeSite = "effect-receipt-inconsistent"
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
//
// The class is about WHO can drive a line and at what cost, which is why the failure half is two
// classes rather than one: a flapping upstream drives `upstream error` per call as its ordinary
// behaviour, while an obligation failure is a thing a conforming deployment never produces. Sharing
// one bucket let an adversarial upstream elide its own `SECURITY: redaction failed` lines by
// erroring generically on every OTHER call — verbatim the argument the split rests on, one level in.
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
	// starved by one that is. Routine under a flapping upstream, which is what keeps them apart
	// from the class below.
	classFailure
	// classObligation: a security obligation policy attached to a call did not hold — a redactFields
	// directive that could not be applied, an approved declassification whose clear did not commit,
	// a signed effect receipt contradicting the contract policy was written against. An upstream
	// cannot drive one without failing an obligation, so unlike classFailure there is no rate at
	// which a merely broken deployment produces them, and the line is the only place some of them
	// are stated in real time.
	classObligation
	// noticeClassCount bounds the reserve bitmap below. Not a class: nothing declares it, and
	// label() answers for it as it does for any unknown value.
	noticeClassCount
)

// The reserve is one bit per class in a uint32 (see noticeReserve). A class past bit 31 would shift
// to zero there and hand out an unlimited reserve rather than a single line, so the width is a
// compile-time assertion instead of an invariant to remember.
const _ = uint(32 - noticeClassCount)

// noticeClasses is the set the bucket tables are keyed by, DERIVED from the declarations rather
// than typed out beside them — the shape refusalCategories uses. A hand-typed list is two lists that
// must agree: one naming a class no declaration reaches builds a bucket nothing spends, and one
// missing a class a declaration names leaves that class delegated or floored.
var noticeClasses = meteredNoticeClasses()

func meteredNoticeClasses() []noticeClass {
	seen := map[noticeClass]bool{}
	out := make([]noticeClass, 0, noticeClassCount)
	for _, class := range meteredNotices {
		if seen[class] {
			continue
		}
		seen[class] = true
		out = append(out, class)
	}
	slices.Sort(out)
	return out
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

// meteredNotices is the class each metered diagnostic site charges, read at WRITE time by
// admitNotice — which is what makes "declared metered" and "charges that class's bucket" one fact
// rather than two that a call site could put out of agreement.
//
// Membership IS the metering declaration: there is no bound field to set here and no metered value
// to set in unmeteredNotices, so the one disagreement a single table permitted — a metered entry
// keyed by a Go function name, unreachable from this lookup and silently charging the floor bucket
// — cannot be written.
var meteredNotices = map[noticeSite]noticeClass{
	// (1) TRAFFIC: reachable at a peer's or an upstream's send rate, one line per frame, each with
	// a record beside it on the tape.
	siteUnmappedMethod:      classTraffic,
	siteObserveDowngrade:    classTraffic,
	siteSamplingDowngrade:   classTraffic,
	siteNotifyPoolSaturated: classTraffic,
	// The host-initialized line is per `initialize` REQUEST: re-initialize is answered LOCALLY, so
	// it creates no session and contacts no upstream — the exemption it used to carry was reasoned
	// from a session's cost and did not apply.
	siteHostInitialized: classTraffic,

	// (2) FAILURE: an operator-facing account of something broken in transit. Metered because a
	// peer or a dead upstream can drive them per frame, classed apart from traffic so that flood
	// cannot take the last token from a class it does not belong to.
	siteUpstreamlessForward:      classFailure,
	siteUpstreamlessNotification: classFailure,
	siteUpstreamError:            classFailure,
	siteInitiatorUnanswerable:    classFailure,
	siteUpstreamNotifyFailed:     classFailure,
	siteUpstreamPostFailed:       classFailure,

	// (3) OBLIGATION: a security obligation that did not hold. Still metered — an upstream returning
	// a redaction-failing response per call drives one per frame — but never from the same bucket as
	// the generic errors that same upstream can flood beside them.
	siteRedactionFault:      classObligation,
	siteDeclassifyCommit:    classObligation,
	siteReceiptInconsistent: classObligation,
}

// noticeFunc is the key a line that never reaches admitNotice is declared by: the writing
// function's QUALIFIED name (receiver included), which is what an AST walk can see.
//
// Qualified rather than bare because this package has same-named twins that write on both
// transports — readUpstream — and a bare key would let the second silently inherit the first's
// answer. A distinct type from noticeSite because the two name different things and only one of
// them is resolvable at runtime.
type noticeFunc string

// noticeBound is how ONE unmetered diagnostic site is bounded. The zero value is "undeclared", so a
// site added with no entry fails the call-site walk rather than inheriting an answer — the same
// shape refusalDeclarations uses for the RECORD half of a refusal.
//
// Four mechanisms bound a line in this package and only the first was ever written down; the fourth
// is metering, which is membership in meteredNotices rather than a value here. The declaration
// exists because the survey behind "how many syscalls can a peer drive" was re-derived by hand each
// time, which is how the routing refusal's line came to be unbounded while its record's exemption
// was being argued in prose.
type noticeBound int

const (
	noticeUndeclared noticeBound = iota
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

// noticeDeclaration is what every UNMETERED diagnostic site declares. why is required for an
// exemption and must be empty otherwise, mirroring refusalDeclaration: the reason IS the exemption.
// It carries no class, since a line that charges no bucket names none.
type noticeDeclaration struct {
	bound noticeBound
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
	// exemptOncePerDegradation covers a line written on a health TRANSITION: the audit trail
	// degrades once and stays degraded, so a peer's send rate cannot drive it however hard it
	// tries. Not a latch — requests in flight at the transition instant may each observe it, so
	// the count is bounded by concurrency rather than by one — which is why it cannot be declared
	// one-shot and have that declaration be true.
	exemptOncePerDegradation = "written on the audit trail's healthy-to-degraded transition, which happens once, so a peer's send rate cannot drive it"
)

// unmeteredNotices answers, for every diagnostic line in this package that does NOT go through
// admitNotice, how it is bounded instead.
//
// It ships beside the metered half rather than in the test that walks it for the reason that half
// ships here: these are statements about production lines, the same kind of statement
// refusalDeclarations makes about a refusal it exempts, and a reason that lives in a test is a
// reason the next reader of the code does not find. Only its READER is a test, because a line that
// never reaches this file cannot be checked by anything that runs here.
var unmeteredNotices = map[noticeFunc]noticeDeclaration{
	// (1) Gated on the RECORD's admission verdict, which spends that category's own bucket.
	"*HTTPProxy.checkOrigin":            {bound: noticeRecordGated},
	"*HTTPProxy.requireJSONContentType": {bound: noticeRecordGated},

	// (2) One-shot latches: at most one line however hard the source is driven.
	"warnStrictAuditOnce":     {bound: noticeOnce},
	"*serverReqTracker.track": {bound: noticeOnce},
	"*httpSession.broadcast":  {bound: noticeOnce},

	// Bounded by a state TRANSITION rather than a latch, which is why it is not one-shot: it
	// compares the trail's health across one record and writes only when that record degraded it.
	"warnIfStrictAuditJustDegraded": {bound: noticeExempt, why: exemptOncePerDegradation},

	// (3) Deliberately unbounded, each carrying the reason it cannot be driven per frame.
	// The scrape RESPONSE BODY, written through the one emitter every series goes through —
	// declared where the bytes are produced, since the scan keys on the writing function.
	"metricWriter.emit":                  {bound: noticeExempt, why: exemptNotADiagnostic},
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
	"reportUpstreamOpenNotice":           {bound: noticeExempt, why: exemptCostsASession},
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
// terminal — a couple of lines a second per class per tenant names the drift or the flood, and every
// line elided is counted into the next one of its class rather than lost, so the notice never
// under-states what is happening.
//
// Stated PER CLASS PER TENANT, with the aggregate DERIVED by multiplying up, which is the treatment
// the refusal categories already had: adding a key costs one key's worth of aggregate rather than
// eroding every existing key's share (20/10 = 2/s, 20/11 = 1/s is what plain division does at the
// integer boundary).
//
// Dividing a FIXED aggregate by the route count was the other candidate and is rejected on measured
// grounds: integer division floors a route's share to 1/s and its burst to 1 from three routes up,
// so on a ten-route gateway a lone failing upstream — no flood anywhere — yields one line and then
// 1/s where the unsplit bucket delivered ten immediately. That is worse than not splitting at all
// for exactly the incident this budget's class split exists to keep legible, and past two routes the
// shares sum beyond the aggregate anyway, which restores the first-come starvation the split was for.
//
// What multiplying up costs is that the process-wide diagnostic syscall rate grows with the route
// count. That is a bound an OPERATOR sets in configuration, not one a peer can drive: a peer on one
// route still drives at most this per-class rate, and "one tenant must not silence another"
// necessarily means the tenants' budgets add. Ten routes is 60 stderr lines a second at worst.
const (
	perClassNoticeRatePerSec = 2
	perClassNoticeBurst      = 10
)

// The rollup scopes: what a suppression count on a given tier SPANS. Named for the reason the
// record half names its own — a count whose scope a reader has to infer from the line it rides on
// is a count that gets misread, and after the route split the same sentence would otherwise mean
// one tenant on a gateway and the whole process on stdio.
const (
	noticeScopeRoute = "route"
	noticeScopeProxy = "proxy"
)

// noticeLimiter is one leg's stderr-diagnostic admission control: a bucket per notice CLASS, and
// optionally an aggregate parent it also charges. The same two-tier table the refusal RECORDS use,
// one axis over — see tieredBuckets.
type noticeLimiter struct {
	tieredBuckets[noticeClass]
}

// newNoticeLimiter builds a proxy's AGGREGATE notice table: one bucket per class, no parent, sized
// for tenants tenants (routes on a gateway; 1 for stdio, which has no route tier at all).
//
// This is what holds the whole process's diagnostic syscall rate, and it is what every route table
// below it charges — so it must have room for each tenant's own share, or the parent becomes the
// binding constraint and the split under it stops meaning anything.
func newNoticeLimiter(tenants int) *noticeLimiter {
	tenants = max(tenants, 1)
	return &noticeLimiter{tieredBuckets: newTieredBuckets(
		float64(perClassNoticeRatePerSec*tenants), float64(perClassNoticeBurst*tenants),
		noticeClasses, nil, noticeScopeProxy)}
}

// newRouteNoticeLimiter builds ONE gateway route's notice table, charging aggregate as its parent.
//
// Per route for the reason saturationGate states for its own records and newUpstreamRefusalLimiter
// for a session's: one tenant's flood must not elide another's. A peer looping an unmapped method
// against /mcp/routeA held the single proxy-wide bucket empty and suppressed routeB's routing-refusal
// lines for as long as it kept sending — and refuseUnroutable's whole reason for naming the method is
// that an operator can see protocol drift, which a suppressed line reduces to a count.
//
// A route takes the FULL per-class budget and the aggregate is sized to cover every route's, rather
// than each route taking a share of a fixed one — see the sizing constants for why the division was
// measured and rejected. aggregate may be nil (a route built by BuildRoutes for a proxy that never
// stood), which bounds the route alone at the same rate.
//
// The route is the LAST tier with a table. Below it a session gets a reserved floor rather than
// buckets of its own (see noticeReserve), which is a decision rather than where the split stopped:
// a third tier is what the RECORD half does one axis over, and here it would buy almost nothing.
// Sized as the record half sizes it — a child bucket at the parent's own rate — a flooding session
// is paced to exactly the rate the route bucket refills at, so a sibling's line still arrives to
// find it empty; sized as a share instead, the per-session rate floors to 1/s and 1 burst at any
// realistic maxSessions, which is worse for the single-session case than not splitting at all. What
// a sibling actually needs is that its FIRST line of a class gets out, and that is a floor, not a
// rate. The residual the floor leaves is stated where it is spent: after that line, a session with a
// dead upstream and a quiet sibling still share the route's tokens first-come.
func newRouteNoticeLimiter(aggregate *noticeLimiter) *noticeLimiter {
	var parent *tieredBuckets[noticeClass]
	if aggregate != nil {
		parent = &aggregate.tieredBuckets
	}
	return &noticeLimiter{tieredBuckets: newTieredBuckets(
		perClassNoticeRatePerSec, perClassNoticeBurst, noticeClasses, parent, noticeScopeRoute)}
}

// noticeReserve is one SESSION's floor inside its route's class buckets: the first line of each
// class this session cannot get through the route table is written anyway, spending no token.
//
// A floor rather than a fourth table, because what a session needs from the tier below the route is
// not a rate but an arrival — an operator learning that THIS session's upstream is also down needs
// the first line and not the hundredth. It is claimed only where the route bucket refuses, so a
// session whose lines all fit under the route's budget keeps its reserve for the incident that
// eventually needs it, and a flooding session spends its own on its first refused line.
//
// The bound is one line per class per session, which is the exemption exemptCostsASession already
// makes for the session-lifecycle lines: driving a reserve costs opening a session, and a session
// costs an upstream spawn or handshake — orders of magnitude more than the line it buys. maxSessions
// caps how many can be held at once.
//
// The zero value is an unspent reserve, and a nil *noticeReserve is none at all — what a leg with no
// session in hand gets, since a refusal taken before a session exists is attributable to no session.
type noticeReserve struct {
	// taken is one bit per noticeClass. A bitmap rather than a map so a session that never writes
	// a diagnostic allocates nothing, and atomic because sessions write from the request goroutine
	// and their own upstream reader concurrently.
	taken atomic.Uint32
}

// take claims this session's reserved line for class, reporting whether it was still unspent.
// Nil-safe: a channel with no session behind it has no floor to fall back on.
func (r *noticeReserve) take(class noticeClass) bool {
	if r == nil {
		return false
	}
	bit := uint32(1) << uint(class)
	return r.taken.Or(bit)&bit == 0
}

// noticeWriter is a leg's diagnostic CHANNEL: where a line goes, what bounds it, and what floor it
// may fall back on, as one value.
//
// One value rather than fields held apart, because holding them apart is a wiring fault nothing
// catches — a leg that sets the writer and not the bucket writes unbounded with every guard still
// green. serverRequestParams was the live shape: its writer was its own errOut field while its
// bucket came from the unblocker it carries, two independently zeroable fields feeding one line.
//
// The zero value writes every line to os.Stderr, which is what a bare-struct-literal proxy in a
// test gets and the behaviour every leg had before the bucket existed.
type noticeWriter struct {
	out    io.Writer
	limits *noticeLimiter
	// reserve is the per-SESSION floor under limits, nil on a leg with no session (see
	// noticeReserve). Nil is the common case: only an established HTTP session has one.
	reserve *noticeReserve
}

// errOut resolves this channel's destination, os.Stderr when unset. The one place a leg's
// diagnostic lines — bounded or not — resolve where they go.
func (n noticeWriter) errOut() io.Writer { return resolvedErrOut(n.out) }

// noticeLine is an ADMITTED diagnostic: the bucket has already been charged and the rollup already
// resolved, so the only thing left is the text. The zero value writes nothing, which is what a
// caller ignoring admitNotice's verdict gets.
type noticeLine struct {
	out io.Writer
	// tail is appended to the format when non-empty. Rendered BEFORE it gets there (see
	// rollupTail), so it carries no verb of its own and appending it cannot consume an argument
	// the caller meant for its own format.
	tail string
}

// writef renders this line, folding in whatever tail the admission resolved.
func (l noticeLine) writef(format string, args ...interface{}) {
	if l.out == nil {
		return
	}
	if l.tail != "" {
		format = strings.TrimSuffix(format, "\n") + l.tail
	}
	_, _ = fmt.Fprintf(l.out, format, args...)
}

// rollupTail states what site's CLASS elided since its last admitted line, and what that count
// spans. The text names BOTH, for the reason the record half stamps suppressed_refusal_scope: one
// bucket serves several sites, and after the route split the same sentence would otherwise mean one
// tenant on a gateway and the whole process on stdio.
func rollupTail(suppressed uint64, class noticeClass, scope string) string {
	return fmt.Sprintf(" (%d further %s diagnostics suppressed, %s-wide)\n", suppressed, class.label(), scope)
}

// reservedTail marks a line that got out on its session's floor rather than through the route's
// bucket. Worth saying: it tells an operator that this session's channel is otherwise saturated, so
// one line from a session is not evidence that only one thing happened to it.
func reservedTail(class noticeClass) string {
	return " (session-reserved: this route's " + class.label() + " diagnostics are saturated)\n"
}

// admitNotice charges site's bucket and returns the line to write, or false when this one is
// elided. It is the ONE entry point that resolves a site's declaration — noticef is a call to it,
// and so is a site that wants to decide BEFORE building its arguments.
//
// That escape hatch is the whole reason this is separate from noticef rather than folded into it:
// on the flood path the bucket exists for, every argument the caller built is thrown away. Three
// sites build strings that escape to the heap per frame (a bounded method name, a sanitized target,
// a joined reason list); they call this first and build nothing when it says no. Measured on the
// suppressed path (BenchmarkNotice_SuppressedPath): the admission is ~85ns and allocation-free,
// while building one of those lines' arguments for a line then discarded costs ~90ns more and two
// heap allocations. The declaration lookup is ~10ns of the admission, which is why it stays a map
// probe rather than an integer site indexing a dense array — it is not the part that dominates, and
// the constants' readable values are what the call-site walk resolves and what its failures name.
//
// It returns a LINE rather than a bool. A bool is a peek the mechanism never hears about again, so
// a site pre-gating on one would either write its line through a second admission (spending two
// tokens for one line) or skip without counting (under-stating the very flood the count exists to
// report). Here the admission happens exactly once whichever way the caller spells it.
//
// The nil-limits guard is here rather than on a second method, because nil is the state a zero
// noticeWriter carries and this is the one place that can produce one: an admit-with-a-guard beside
// the table's own promoted admit is two entry points with opposite nil semantics, and the promoted
// one is the spelling a later site reaches for.
func (n noticeWriter) admitNotice(site noticeSite) (noticeLine, bool) {
	if n.limits == nil {
		return noticeLine{out: n.errOut()}, true
	}
	// A site with no declaration resolves to classUnclassified and charges the floor-rate fallback:
	// the zero value means nobody has answered the question, and the safe answer to that is the
	// bounded one.
	class := meteredNotices[site]
	admitted, suppressed, scope := n.limits.admit(class)
	switch {
	case admitted && suppressed == 0:
		return noticeLine{out: n.errOut()}, true
	case admitted:
		return noticeLine{out: n.errOut(), tail: rollupTail(suppressed, class, scope)}, true
	case n.reserve.take(class):
		// The bucket counted this line as elided a moment ago and the floor is about to write it,
		// so hand the tally back: the rollup states what an operator did NOT see, and one that
		// counts a line they did see over-states the flood on the next admitted line. bucket()
		// resolves the same tier admit charged, including a class delegated wholly to the parent.
		n.limits.bucket(class).unsuppress()
		return noticeLine{out: n.errOut(), tail: reservedTail(class)}, true
	default:
		return noticeLine{}, false
	}
}

// noticef writes one bounded diagnostic line for site, for the sites whose arguments are cheap
// enough not to bother gating. The rollup is applied by the admission rather than returned for a
// caller to append, for the reason admitRefusalRecord hides its own: a site that spends a token and
// forgets the count silently under-states a flood, and nothing fails.
func noticef(n noticeWriter, site noticeSite, format string, args ...interface{}) {
	if line, ok := n.admitNotice(site); ok {
		line.writef(format, args...)
	}
}
