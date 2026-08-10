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
//   - and, below the route, by reserved FLOORS rather than a third tier of buckets — one guaranteed
//     line per key per interval, on the holder axis (a session, so a sibling's flood cannot elide
//     its first line) and on the site axis (so a class-mate's flood cannot elide the one line in a
//     class that most needs to arrive). See noticeReserve.
//
// Every key on the first two axes holds a FULL per-key budget and the aggregate is derived by
// multiplying up, which is the treatment the refusal RECORDS' categories already had — see the
// sizing constants for why dividing a fixed aggregate was measured and rejected. What that costs is
// stated where it is spent: the rate a PEER can drive is one key's budget however many keys there
// are, while the process-wide total grows with the class and route counts, deliberately, because
// "one tenant must not silence another" is exactly the statement that their budgets add.

package transport

import (
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
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

// The metered diagnostic sites. Each is passed at its own call and looked up in meteredNotices at
// write time; the value is descriptive rather than the function's name, since several functions hold
// more than one site and two hold the same name.
//
// Deliberately NOT grouped by class here: meteredNotices is where a site's class is declared, and a
// grouping comment beside the constant is a second statement of the same fact that a table edit can
// silently contradict.
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
	siteUpstreamPostFailed       noticeSite = "upstream-post-failed"
	siteRedactionFault           noticeSite = "redaction-fault"
	siteDeclassifyCommit         noticeSite = "declassify-commit"
	siteReceiptInconsistent      noticeSite = "effect-receipt-inconsistent"
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
// classes rather than one. A generic transit error is free to an upstream — it can return one for
// any call, on a route with no policy obligation in play at all — while an obligation failure takes
// a call that CARRIES one. Sharing a bucket therefore let an adversarial upstream elide its own
// `SECURITY: redaction failed` lines by erroring generically on every OTHER call, which is the
// argument the split rests on, one level in.
//
// What the class does NOT buy on its own: an obligation failure is not undrivable by a merely
// broken deployment. A flow store that is down fails every approved declassification's commit, and a
// stale effect.ref pin makes every receipt inconsistent — both at the request rate, both from a
// conforming peer. So a flood of this class is a finding about the DEPLOYMENT rather than proof of
// an attack, and it is why the line the class exists to keep legible holds a floor of its OWN
// inside it (floorProtectedSites) rather than a fourth bucket, which would only move the same
// argument one level finer.
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
	// a signed effect receipt contradicting the contract policy was written against. Apart from
	// classFailure because reaching one takes a call CARRYING an obligation, which a generic transit
	// error does not — see the type's doc for what that does and does not bound.
	classObligation
)

// noticeClasses is the set the bucket tables are keyed by, DERIVED from the declarations rather
// than typed out beside them — the shape refusalCategories uses. A hand-typed list is two lists that
// must agree: one naming a class no declaration reaches builds a bucket nothing spends, and one
// missing a class a declaration names leaves that class delegated or floored.
var noticeClasses = meteredNoticeClasses()

func meteredNoticeClasses() []noticeClass {
	return slices.Compact(slices.Sorted(maps.Values(meteredNotices)))
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
		noticeClasses, nil, noticeScopeProxy, floorOwnBucket)}
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
// The route is the LAST tier with buckets. Below it a holder gets a reserved floor instead, which
// is a decision rather than where the split stopped — see noticeReserve for the measurement it
// rests on and the residuals it leaves.
func newRouteNoticeLimiter(aggregate *noticeLimiter) *noticeLimiter {
	var parent *tieredBuckets[noticeClass]
	if aggregate != nil {
		parent = &aggregate.tieredBuckets
	}
	return &noticeLimiter{tieredBuckets: newTieredBuckets(
		perClassNoticeRatePerSec, perClassNoticeBurst, noticeClasses, parent, noticeScopeRoute,
		floorOwnBucket)}
}

// floorProtectedSites are the sites that hold a floor of their OWN, consulted ahead of the class
// floor a holder gets — the answer to a class-mate eliding the one line in that class an operator
// cannot do without.
//
// One site today, and the argument is classObligation's own residual. Two of that class's three
// sites are drivable at the request rate by a CONFORMING peer against a merely broken deployment:
// a flow store that is down fails every approved declassification's commit, and a stale effect.ref
// pin makes every receipt inconsistent. Either drains the class bucket with no adversary involved,
// and what it reduces to a count on somebody else's line is `SECURITY: redaction failed` — the line
// the class was split out to keep legible.
//
// A FOURTH class was the alternative and is rejected because it recurses: it is the same argument
// one level finer, and the next reader asks what elides the declassify-commit line. A floor answers
// the question actually being asked, which is arrival rather than rate, and without another budget:
// the flooding sites keep sharing their holder's class reserve, so the flood spends that one and
// leaves this site's untouched.
var floorProtectedSites = []noticeSite{siteRedactionFault}

// noticeReserve is a leg's diagnostic floors: one guaranteed line per key per reserveInterval,
// delivered when the tier that would have carried it has nothing left.
//
// TWO key spaces, and they answer different questions — the shape meteredNotices/unmeteredNotices
// already uses for the same reason, rather than one map whose key means whichever the value beside
// it implies:
//
//   - byClass is the HOLDER axis. A session shares its route's class buckets with every other
//     session on that route, so one session's dead upstream held the failure bucket empty and elided
//     a sibling's first `upstream error` line — the elision the route split closed one tier up. Only
//     a holder among peers reserves here: a whole stdio proxy is one holder with no sibling to be
//     starved by, and a pre-session HTTP leg is attributable to no holder at all (it carries no
//     reserve whatsoever, on either axis).
//   - bySite is the SITE axis (see floorProtectedSites). Not about holders at all — it is about
//     which line a CLASS-MATE's flood must not elide — so it applies wherever such a line is
//     written, on either transport.
//
// A third tier of BUCKETS was the alternative on the holder axis and is rejected on measured
// grounds: sized like the record half's per-session tables (a child bucket at its parent's own
// rate) a flooding session is paced to exactly the rate the route bucket refills at, so a sibling's
// line still arrives to find it empty; sized as a share instead, the per-session rate floors to 1/s
// and a burst of 1 at any realistic maxSessions, worse for the single-session case than not
// splitting at all. What a sibling needs from this tier is an ARRIVAL — an operator learning that
// THIS session's upstream is also down needs the first line, not the hundredth.
//
// What the floor costs is bounded twice over: it re-arms per reserveInterval rather than
// per lifetime (see that constant for the arithmetic), and a floored line DEBITS the bucket that
// refused it, so it displaces the flooder's next line rather than adding to the process-wide total
// (see tieredBuckets.admitWithFloor and recordRateLimiter.borrow). The residual is stated there:
// past a burst of debt the debit stops, so a flood driven by enough holders at once exceeds the
// tier's configured rate by holders x keys per interval.
//
// A nil *noticeReserve is no floors at all, which is what a leg with neither a session nor a
// site-protected line to write gets.
type noticeReserve struct {
	byClass *keyReserve[noticeClass]
	bySite  *keyReserve[noticeSite]
}

// newSessionNoticeReserve builds the floors of a leg that IS a holder among peers: both axes.
func newSessionNoticeReserve() *noticeReserve {
	return &noticeReserve{byClass: newKeyReserve(noticeClasses), bySite: newKeyReserve(floorProtectedSites)}
}

// newSiteNoticeReserve builds the floors of a leg that is not a holder among peers — a whole
// stdio proxy, which has no sibling to be starved by — so it reserves on the site axis alone.
func newSiteNoticeReserve() *noticeReserve {
	return &noticeReserve{bySite: newKeyReserve(floorProtectedSites)}
}

// forSite is the floor a line from site (of class) may fall back on: its own where it has one,
// this holder's class floor otherwise, and nil for neither.
//
// The site slot WINS rather than composing with the class slot. Falling back to the class floor
// after a site floor is spent would hand the protected site two arrivals per interval and the
// others none, which is not the property being bought: the site floor exists so a class-mate's
// flood cannot elide this line, and the class floor because a peer holder's flood cannot.
func (r *noticeReserve) forSite(site noticeSite, class noticeClass) *reserveSlot {
	if r == nil {
		return nil
	}
	if slot := r.bySite.forKey(site); slot != nil {
		return slot
	}
	// classUnclassified is deliberately unreserved: an undeclared site charges the floor-rate
	// fallback bucket and nothing else, and a reserve for it would hand exactly that site a line
	// outside every bucket. newKeyReserve builds slots for the declared classes alone, so this
	// resolves to nil for it structurally rather than by a range check that must be kept in
	// agreement with the enum.
	return r.byClass.forKey(class)
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
	// reserve is this leg's floors under limits — its holder's per class, and the protected
	// sites' own (see noticeReserve). Nil on a leg that is neither.
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
	// tail is what the admission has to say beyond the caller's own text — see noticeTail.
	tail string
}

// writef renders this line, folding in whatever tail the admission resolved.
//
// A line with a tail is rendered whole and written ONCE rather than appending the tail to the
// caller's format: appending it puts the tail through Fprintf's own scan, where a `%` in a scope or
// a class label would be read as a verb against an already-exhausted argument list. Every component
// of a tail is a constant today; the point is that it does not have to stay one for this to be
// safe. Two writes were not an option — a diagnostic must reach the pipe as one syscall or two
// goroutines interleave halves of a line.
//
// It also keeps this a printf wrapper vet can INFER, since neither branch assigns to format or args
// — the shape that appended to the format did not, which is how a wrapper loses its checking with
// nothing failing. It is declared in .golangci.yml regardless; both are cheap and only one of them
// survives an edit here.
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
// since the last one, that this line got out on its session's floor, or both.
//
// It names the CLASS and the TIER, for the reason the record half stamps suppressed_refusal_scope:
// one bucket serves several sites, and after the route split the same sentence would otherwise mean
// one tenant on a gateway and the whole process on stdio. The scope comes from the VERDICT rather
// than from the table the caller holds, since those disagree for a class delegated wholly to the
// parent.
//
// A floored line carries the count too. It is the line an operator actually sees during the flood
// the floor exists for, so a count deferred to "the next admitted line" is a count deferred to after
// the incident.
//
// Built rather than Sprintf'd because this is also the ADMITTED path's only extra work, and a
// second format-string parse to render one integer is the kind of cost that is invisible until it
// is the thing being measured.
func noticeTail(v bucketVerdict, class noticeClass) string {
	if v.suppressed == 0 && !v.reserved {
		return ""
	}
	var b strings.Builder
	b.WriteString(" (")
	if v.reserved {
		b.WriteString("reserved: this ")
		b.WriteString(v.scope)
		b.WriteString("'s ")
		b.WriteString(class.label())
		b.WriteString(" budget is spent")
		if v.suppressed > 0 {
			b.WriteString("; ")
		}
	}
	if v.suppressed > 0 {
		var digits [20]byte
		b.Write(strconv.AppendUint(digits[:0], v.suppressed, 10))
		b.WriteString(" further ")
		b.WriteString(class.label())
		b.WriteString(" diagnostics suppressed, ")
		b.WriteString(v.scope)
		b.WriteString("-wide")
	}
	b.WriteString(")\n")
	return b.String()
}

// admitNotice charges site's bucket and returns the line to write, or false when this one is
// elided. It is the ONE entry point every metered diagnostic goes through, and the admission is
// taken BEFORE the caller builds its arguments.
//
// That ordering is the whole shape, and it is now uniform rather than applied per site by judgment.
// On the flood path the bucket exists for, every argument the caller built is thrown away — a UTF-8
// walk, a join, or simply the variadic boxing every one of them pays. Measured on the suppressed
// path of a SESSION channel, floor included, which is the shape that ships
// (BenchmarkNotice_SuppressedPath): the admission is ~110ns and allocation-free, while building and
// boxing the arguments for a line then discarded costs ~120ns more and two heap allocations. The
// boxing is most of it, which is why this is a CALL-SITE ordering and no lazier signature here would
// remove it — and why the alternative, a convenience wrapper taking the format eagerly, is gone
// rather than kept for the sites whose arguments happen to be cheap: judged per site it left eight
// of fourteen paying for lines they discard, several of them per-frame drivable, and every one of
// them a fresh judgment for the next reader to re-derive. The declaration lookup is ~13ns of the
// admission, which is why it stays a map probe rather than an integer site indexing a dense array:
// it is not the part that dominates, and the constants' readable values are what the call-site walk
// resolves and what its failures name.
//
// It returns a LINE rather than a bool. A bool is a peek the mechanism never hears about again, so
// a site pre-gating on one would either write its line through a second admission (spending two
// tokens for one line) or skip without counting (under-stating the very flood the count exists to
// report). Here the admission happens exactly once whichever way the caller spells it — and because
// this hands out the bucket's accumulated tally, a caller that takes a line and does not write it
// destroys that count, which is why the call-site walk requires the one shape that always writes.
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
	// bounded one. noticeReserve reserves no floor for that class for the same reason.
	class := meteredNotices[site]
	verdict := n.limits.admitWithFloor(class, n.reserve.forSite(site, class))
	if !verdict.ok {
		return noticeLine{}, false
	}
	return noticeLine{out: n.errOut(), tail: noticeTail(verdict, class)}, true
}
