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
// Two tables, not four: everything a metered site declares — the class it charges, whether its
// occurrences COLLAPSE at their source, and whether it holds a floor of its own inside its class —
// is one value under one key. Both of the folded halves started as a second map keyed by the same
// site, each costing admitNotice a probe on EVERY line for an answer a minority of sites hold (a
// window for two of fifteen, a site floor for one), and each an opt-in list where a site was
// collapsed or protected by being written down and neither by being forgotten. Folding removes
// both: the probe already being taken carries the answers, and a site with no disposition fails the
// table test the way an unclassified one does.
//
// The floor half is a fold rather than a merge, because its reason field has the OPPOSITE
// required-ness from the collapse's: a collapse disposition costs something either way and must
// argue both answers, while a floor's reason IS the elision and a protected site states none. So it
// is a second, distinctly named field with its own rule (see floorDisposition), not one `why`
// serving two questions.
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
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
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
	siteNotifyUntranslatable     noticeSite = "notification-untranslatable"
	siteUpstreamPostFailed       noticeSite = "upstream-post-failed"
	siteRedactionFault           noticeSite = "redaction-fault"
	siteDeclassifyCommit         noticeSite = "declassify-commit"
	siteDeclassifyDoubleCommit   noticeSite = "declassify-double-commit"
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

// meteredNoticeClasses is written out rather than taken from sortedKeysWhere like its three
// neighbours, and the difference is not stylistic: this one PROJECTS the declarations' values where
// they collect their keys. Map keys are unique and class values are not, so the Compact below is
// load-bearing — without it noticeClasses is fifteen entries where three are meant, which builds
// twelve duplicate bucket keys and multiplies the derived aggregate by five.
func meteredNoticeClasses() []noticeClass {
	out := make([]noticeClass, 0, len(meteredNotices))
	for _, decl := range meteredNotices {
		// classUnclassified is filtered rather than registered, which is what makes the
		// undeclared answer STRUCTURAL rather than a property of the table test: registering it
		// would hand an entry that forgot its class a full class bucket and a reserve slot — and
		// move every genuinely undeclared site off the floor-rate fallback onto it, since they
		// all resolve to the same key. Easy to write now that the value is a struct literal with
		// an omissible field, where the bare noticeClass it replaced had to be stated.
		if decl.class == classUnclassified {
			continue
		}
		out = append(out, decl.class)
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

// collapseDisposition is whether a site's occurrences are folded to one line per
// noticeCollapseInterval per SOURCE, or reported one per occurrence.
//
// The zero value is "undeclared", so a metered site added with no answer fails the table test
// rather than inheriting the per-occurrence one — the shape floorDisposition and refusalDeclarations use,
// and the one thing the collapse's first form (an opt-in list) could not have: an absent site was
// indistinguishable from an unexamined one, and five failure-class sites meeting the collapsed
// sites' own stated criterion sat outside it with no recorded judgment either way.
type collapseDisposition int

const (
	collapseUndeclared collapseDisposition = iota
	// collapseWindowed: at most one line per window per source, the rest folded into the class
	// bucket's tally. For a fault whose SUBJECT does not vary, where the occurrences after the
	// first tell an operator nothing the first did not.
	collapseWindowed
	// collapsePerOccurrence: every occurrence its bucket admits is written. The ordinary answer,
	// and the one a line whose occurrences carry different subjects must give.
	collapsePerOccurrence
)

// floorDisposition is where ONE metered site stands with respect to the SITE floor — the reserved
// line a CLASS-MATE's flood must not elide (see noticeReserve's bySite axis).
//
// FOUR values rather than a bool, because "this class has no protected member" and "this site is
// the one that may be elided" are different answers and only one of them carries a cost a reader
// has to be told about. As a bool it was neither: it was an opt-in list that asked nothing of the
// classes with no protected member, so ten of the fifteen sites recorded no judgment at all and a
// site added to such a class inherited one.
//
// floorClassUnprotected is not a way of saying "not applicable and never mind". It is CHECKED
// against the table's own content — a site claiming it in a class that does hold a protected member
// fails the table test, as does floorElidable in a class that does not — so protecting a first site
// in some class fails the build for every one of its class-mates rather than silently moving them
// onto the flooding side. That is the whole reason it is a value here and not the absence of one.
type floorDisposition int

const (
	floorUndeclared floorDisposition = iota
	// floorSiteProtected: this site reserves a slot of its own, so a class-mate's flood cannot
	// elide it (floorProtectedSites is derived from exactly this).
	floorSiteProtected
	// floorElidable: a class-mate holds a floor and this site is the one that may be elided to
	// leave it room, for the reason in floorWhy.
	floorElidable
	// floorClassUnprotected: no site of this class holds a floor of its own, so its sites contend
	// only with each other for the holder's one class reserve — the ordinary arrangement.
	floorClassUnprotected
)

// noticeSiteDeclaration is what ONE metered diagnostic site declares. All three answers are
// required and none may be inherited: an unclassified site charges the floor-rate fallback rather
// than a real class's share, an undeclared collapse is an unexamined one, and an undeclared floor
// is a site that has not said whether it is the line a class-mate's flood removes.
//
// collapseWhy carries the judgment behind the collapse disposition, on BOTH sides of it — unlike
// refusalDeclaration's, where only the exemption has a reason to state. Here each answer costs
// something a reader cannot infer from the code: collapsing loses every occurrence after the first
// in the window, and not collapsing leaves a fault a broken deployment can drive at the request
// rate charging its class's bucket per occurrence. A site that states neither has not decided.
//
// floorWhy is the opposite rule and that is why it is a SECOND field rather than the same one: the
// reason IS the elision, so it is required exactly for floorElidable and must be empty otherwise.
// A protected site's reason is its class's own doc, and a class with no protected member has no
// elision to justify.
type noticeSiteDeclaration struct {
	class       noticeClass
	collapse    collapseDisposition
	collapseWhy string
	floor       floorDisposition
	floorWhy    string
}

// The reasons a collapse disposition rests on, stated once each where they are one argument shared
// by several sites rather than per-site prose — the shape unmeteredNotices' exemption reasons use.
const (
	// collapsedOccurrencesAreOneFinding is what the two windowed sites have in common, kept here
	// because the criterion is what a NEW site is judged against: a fault a merely broken
	// deployment drives at the request rate, whose subject is the deployment rather than the call.
	collapsedOccurrencesAreOneFinding = "a merely broken deployment drives it at the request rate and every occurrence reports the same fault, so an operator acts on it once"
	// uncollapsedRateIsTheSignal covers the traffic lines. Each is an account of one MESSAGE a peer
	// or an upstream sent, so what a window would remove is the RATE — which is the whole of what a
	// reader watching per-frame traffic is reading them for, and which the class bucket's rollup
	// reports as a count only after the fact.
	uncollapsedRateIsTheSignal = "an account of one message the peer sent: the occurrences and their rate are the finding, so a window would report the first and reduce the incident to a count"
	// uncollapsedNamesTheFailingCall covers the failure lines, and it is a TRADE rather than an
	// obvious answer. They meet the windowed sites' criterion exactly — a dead upstream drives one
	// per frame from a conforming peer, and classFailure's own doc calls that routine — so the
	// flood is real and is deliberately not removed at the source. What differs is what an
	// occurrence CARRIES: the failing call, its method, the error the upstream returned, where a
	// windowed site reports a fault whose subject does not vary. Folding them would leave "an
	// upstream is failing" and remove WHICH calls failed, which is what an operator reads during
	// the incident. Its flood is answered by the bounds instead — the class bucket, the route split
	// above it, and the holder's floor below — none of which lose a subject.
	uncollapsedNamesTheFailingCall = "each occurrence names a different failing call and the error behind it, which is what an operator reads it for; the flood is bounded by the class bucket rather than removed at the source"
)

// meteredNotices is everything a metered diagnostic site DECLARES: the class whose bucket it
// charges, whether its occurrences collapse at their source, and the judgment behind that. It is
// read at WRITE time by admitNotice — which is what makes "declared metered" and "charges that
// class's bucket" one fact rather than two that a call site could put out of agreement.
//
// Membership IS the metering declaration: there is no bound field to set here and no metered value
// to set in unmeteredNotices, so the one disagreement a single table permitted — a metered entry
// keyed by a Go function name, unreachable from this lookup and silently charging the floor bucket
// — cannot be written.
//
// The collapse disposition lives HERE rather than in a table of its own for two reasons that point
// the same way: admitNotice reads both in one probe (a second string-keyed lookup on every line,
// for a window two of the fifteen sites hold — see admitNotice for what that measured), and a table
// of its own could only ever be an opt-in list, where the thirteen sites outside it answer nothing
// and "not collapsed" is a judgment with a cost like any other.
var meteredNotices = map[noticeSite]noticeSiteDeclaration{
	// (1) TRAFFIC: reachable at a peer's or an upstream's send rate, one line per frame, each with
	// a record beside it on the tape. No member of this class holds a site floor, so its sites
	// contend only with each other for the holder's one class reserve.
	siteUnmappedMethod:      {class: classTraffic, collapse: collapsePerOccurrence, collapseWhy: uncollapsedRateIsTheSignal, floor: floorClassUnprotected},
	siteObserveDowngrade:    {class: classTraffic, collapse: collapsePerOccurrence, collapseWhy: uncollapsedRateIsTheSignal, floor: floorClassUnprotected},
	siteSamplingDowngrade:   {class: classTraffic, collapse: collapsePerOccurrence, collapseWhy: uncollapsedRateIsTheSignal, floor: floorClassUnprotected},
	siteNotifyPoolSaturated: {class: classTraffic, collapse: collapsePerOccurrence, collapseWhy: uncollapsedRateIsTheSignal, floor: floorClassUnprotected},
	// The host-initialized line is per `initialize` REQUEST: re-initialize is answered LOCALLY, so
	// it creates no session and contacts no upstream — the exemption it used to carry was reasoned
	// from a session's cost and did not apply.
	siteHostInitialized: {class: classTraffic, collapse: collapsePerOccurrence, collapseWhy: uncollapsedRateIsTheSignal, floor: floorClassUnprotected},

	// (2) FAILURE: an operator-facing account of something broken in transit. Metered because a
	// peer or a dead upstream can drive them per frame, classed apart from traffic so that flood
	// cannot take the last token from a class it does not belong to. All SEVEN meet the windowed
	// sites' criterion — a dead upstream drives every one of them per frame, the unanswerable
	// initiator included — and all seven are deliberately reported per occurrence anyway; see
	// uncollapsedNamesTheFailingCall, which is the whole of that judgment. None holds a site floor:
	// what a sibling needs here is its HOLDER's arrival, which is the class reserve one axis over.
	siteUpstreamlessForward:      {class: classFailure, collapse: collapsePerOccurrence, collapseWhy: uncollapsedNamesTheFailingCall, floor: floorClassUnprotected},
	siteUpstreamlessNotification: {class: classFailure, collapse: collapsePerOccurrence, collapseWhy: uncollapsedNamesTheFailingCall, floor: floorClassUnprotected},
	siteUpstreamError:            {class: classFailure, collapse: collapsePerOccurrence, collapseWhy: uncollapsedNamesTheFailingCall, floor: floorClassUnprotected},
	siteInitiatorUnanswerable:    {class: classFailure, collapse: collapsePerOccurrence, collapseWhy: uncollapsedNamesTheFailingCall, floor: floorClassUnprotected},
	siteUpstreamNotifyFailed:     {class: classFailure, collapse: collapsePerOccurrence, collapseWhy: uncollapsedNamesTheFailingCall, floor: floorClassUnprotected},
	siteNotifyUntranslatable:     {class: classFailure, collapse: collapsePerOccurrence, collapseWhy: uncollapsedNamesTheFailingCall, floor: floorClassUnprotected},
	siteUpstreamPostFailed:       {class: classFailure, collapse: collapsePerOccurrence, collapseWhy: uncollapsedNamesTheFailingCall, floor: floorClassUnprotected},

	// (3) OBLIGATION: a security obligation that did not hold. Still metered — an upstream returning
	// a redaction-failing response per call drives one per frame — but never from the same bucket as
	// the generic errors that same upstream can flood beside them. The two INFRASTRUCTURE-driven
	// ones are additionally COLLAPSED at their source, so the bucket they charge is not the bucket a
	// persistent backend fault empties. It is the one class holding a protected member today, which
	// is why its sites are the only ones declaring which side of that protection they are on.
	siteRedactionFault: {class: classObligation, collapse: collapsePerOccurrence,
		collapseWhy: "the line the class split and the site floor both exist to keep legible; each occurrence names the call whose redaction failed, so a window would hide every call after the first — the loss both of those mechanisms are built to prevent",
		floor:       floorSiteProtected},
	siteDeclassifyCommit: {class: classObligation, collapse: collapseWindowed,
		collapseWhy: collapsedOccurrencesAreOneFinding + ": a downed flow store fails every approved declassification's commit, so the finding is 'the flow store is down' rather than one line per clear",
		floor:       floorElidable,
		// Still declared elidable now that it is also collapsed at its source, because collapsing is
		// not a bound: the window is per source, so a gateway's routes each hold one, and this is
		// what answers for their sum.
		floorWhy: "a downed flow store drives it per frame, so it is the flood the protection is against rather than its victim; the first of them still arrives on the holder's class reserve"},
	siteDeclassifyDoubleCommit: {class: classObligation, collapse: collapsePerOccurrence,
		collapseWhy: "a proxy wiring fault nothing in the call graph reaches and no peer can drive, so there is no flood to collapse — and folding it into the store fault's window beside it would report it nowhere for as long as that store stayed down",
		floor:       floorElidable,
		floorWhy:    "a proxy wiring fault, not a backend one: nothing in the call graph reaches it and no peer can drive it, so a class-mate's flood eliding it defers a defect report rather than hiding a live incident"},
	siteReceiptInconsistent: {class: classObligation, collapse: collapseWindowed,
		collapseWhy: collapsedOccurrencesAreOneFinding + ": a stale effect.ref pin makes every receipt on the route inconsistent, so the finding is the pin; the per-call evidence stays on the tape, which is where a per-receipt reader should be looking",
		floor:       floorElidable,
		floorWhy:    "a stale effect.ref pin drives it per frame, same as the commit line beside it, and a flood of either is a finding about the deployment"},
}

// collapsedNoticeSites is the windowed subset as a stable slice, DERIVED from the declarations so a
// site cannot be declared collapsed and hold no slot. Sorted for a deterministic build.
var collapsedNoticeSites = sortedKeysWhere(meteredNotices,
	func(d noticeSiteDeclaration) bool { return d.collapse == collapseWindowed })

// noticeCollapseInterval is how often a windowed site reports again: one line per site per
// interval per SOURCE, with every occurrence in between folded into the class bucket's tally.
//
// A RE-ARMING interval, not an episode a success reopens. An episode was the first design and its
// reopen condition is the part that does not survive contact with the scope available: the state
// can only be keyed per SOURCE (a route has one receipt verifier and one policy engine), while the
// faults are per CALL — one tool's stale effect.ref pin against a sibling tool that verifies fine,
// one anchor's failing commit against another that succeeds. A success-reopened episode therefore
// (1) alternated open/closed on ordinary mixed traffic, emitting MORE lines than no collapsing at
// all, (2) announced a recovery on evidence from a different subject, which is a claim the gate has
// no standing to make, and (3) could be held open indefinitely by an upstream that simply declined
// to produce the success — an adversary-controlled mute on a security-relevant line, which is the
// opposite of what the class split exists for. An interval answers none of those questions and
// needs none of them: the fault reports again when the window re-arms, whatever the backend does.
//
// What it costs is stated plainly: within one window, occurrences after the first are folded into
// the class bucket's tally and their SUBJECTS (the tool, the target) are not recorded anywhere on
// stderr. The tape is unaffected — every one of these lines has a record beside it — so this is a
// legibility trade, taken because the alternative is a bucket a broken deployment keeps empty.
//
// The interval itself is a minute. A minute for the reason
// noticeReserveInterval is one: long enough that a persistent backend fault is a trickle rather than
// a flood, short enough that a fault which returns after being fixed is not silent for an hour.
//
// It is deliberately the same MECHANISM as the diagnostic floor one tier down (a re-arming
// reserveSlot), used in the opposite direction: the floor guarantees a line ARRIVES when the bucket
// has nothing left, and this one guarantees a repeating line does NOT arrive more often than an
// operator can act on it. One primitive, so the re-arm semantics — monotonic clock, no value meaning
// "never claimed", exactly one winner under concurrency — are not implemented twice.
const noticeCollapseInterval = time.Minute

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
	// drive it however cheap the message is. Taken through noticeLatch, which is what makes this
	// declaration a MECHANISM rather than a claim about code elsewhere: the three sites holding it
	// each implemented their own latch (an atomic.Bool, and twice a counter compared against 1),
	// which is where the metered half's collapse started before it became a disposition admitNotice
	// reads.
	noticeOnce
	// noticeExempt: not drivable at a per-frame rate, for the reason declared. Startup, teardown,
	// configuration, and session-lifecycle lines.
	noticeExempt
)

// noticeDeclaration is what every UNMETERED diagnostic site declares. why is required for an
// exemption and must be empty otherwise, mirroring refusalDeclaration: the reason IS the exemption.
// It carries no class, since a line that charges no bucket names none.
//
// It carries no COLLAPSE either, and that is a decision rather than an omission — but a ROUTED one
// now, which is the part that changed. A collapse disposition is applied by admitNotice, which an
// unmetered site never reaches, so a field here with no entry using it would be a declaration whose
// only reader is a test: precisely what noticeOnce was before noticeLatch, and what it would
// compile to is the reserveSlot field it was meant to replace.
//
// So the answer for a site that wants "one line per interval, and no class bucket" is to come HERE
// and give this declaration a collapse disposition with its interval, lifting the window above
// admitNotice's metering branch so one vocabulary serves both halves — NOT to hold a reserveSlot of
// its own beside its Fprintf. That shape is unavailable rather than merely discouraged: the
// primitive's claimants are a closed set (see reserveSlot.claim), so a hand-rolled window fails the
// source guard, and the failure names this field. Which is the whole reason the field can be
// deferred honestly — the first site that wants it arrives here rather than becoming a fourth
// implementation of one idea, which is the state noticeLatch removed one axis over.
//
// Metering is NOT the answer for such a site either — a class bucket is a peer-driven budget, and
// charging one for a line no peer drives takes tokens from the lines the class split exists to keep
// legible.
type noticeDeclaration struct {
	bound noticeBound
	why   string
}

// noticeLatch is the noticeOnce bound as a MECHANISM: at most one line, ever, from the holder that
// owns it. The zero value is unclaimed and usable, so a latch is declared as a field rather than
// constructed.
//
// Built on reserveSlot — the same primitive the collapse window and the diagnostic floor are — with
// an interval that never elapses. One mechanism rather than three, and the re-arm semantics it
// carries are the part worth not reimplementing per site: exactly one winner under concurrency
// (a CAS loop, which the atomic.Bool spelling had and the two counter-compared-against-1 spellings
// only approximated by holding a mutex for other reasons).
//
// It reads no clock, which is what makes a latch cheaper than a window rather than a special case
// of one: the claim is taken against the ZERO instant, so the second and every later occurrence
// measures an elapsed 0 against latchNeverRearms and is refused on one atomic load. A nil latch is
// permanently spent, which is the answer a leg with no latch wired already had.
type noticeLatch struct{ slot reserveSlot }

// latchNeverRearms is the window a LATCH is: one that does not re-arm within any process's life.
// Expressed as an interval so a one-shot and a window are one primitive; the value is only ever
// compared against the zero elapsed time noticeLatch measures, so its magnitude is a statement of
// intent rather than a bound anything waits out.
const latchNeverRearms = time.Duration(math.MaxInt64)

// admitOnce reports whether this latch's one line may be written now — true exactly once per
// holder. The name is distinctive on purpose: notice_bounding_test.go requires every site declared
// noticeOnce to reach it and every site reaching it to be declared noticeOnce, which is the
// two-way gate that keeps the declaration and the mechanism from drifting apart.
func (l *noticeLatch) admitOnce() bool {
	if l == nil {
		return false
	}
	return l.slot.claim(time.Time{}, latchNeverRearms)
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
	"*HTTPProxy.killWriteLanded":         {bound: noticeExempt, why: exemptNotPeerDriven},
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

// noticeReserveInterval is how long a spent diagnostic floor stays spent — the third sizing knob of
// this budget, stated here beside the rate and the burst rather than shared with the record half.
//
// What a floored write is HERE is a write(2) to stderr: an operator watching a terminal during an
// incident gets one guaranteed line per key per interval, and the cost of getting it wrong is
// legibility rather than availability. That is a different argument from the record half's
// (recordReserveInterval, where the same mechanism admits an audit record into a queue whose
// overflow denies the data plane under strict audit), and the two are not interchangeable in either
// direction — an operator who wants more arrivals from a channel that costs a syscall must not be
// loosening the audit queue's bound to get them.
//
// The two values coincide at a minute today. That is a judgment reached twice, not a fact shared
// once: a minute is long enough that `holders x keys` per interval stays a bounded trickle, short
// enough that a second incident on the same key is not silent for an hour.
//
// The ceiling it implies is the same arithmetic recordReserveInterval states, over this budget's
// keys: a holder reserves one slot per notice CLASS plus one per protected SITE, so at the CLI's
// default maxSessions of 512 a fleet-wide upstream failure delivers 512x4 = 2048 stderr lines in a
// burst and ~34/s after. Derived from the live sets by TestReserveCeiling_IsDerivedFromTheLiveSets
// rather than trusted here — the figure is written in terms of two sets in this file and one in
// another, and it has already drifted once.
const noticeReserveInterval = time.Minute

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
// one axis over — see tieredBuckets, embedded by POINTER for the reason stated there.
type noticeLimiter struct {
	*tieredBuckets[noticeClass]
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
		noticeReserveInterval, noticeClasses, nil, noticeScopeProxy, floorOwnBucket)}
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
		parent = aggregate.tieredBuckets
	}
	return &noticeLimiter{tieredBuckets: newTieredBuckets(
		perClassNoticeRatePerSec, perClassNoticeBurst, noticeReserveInterval, noticeClasses, parent,
		noticeScopeRoute, floorOwnBucket)}
}

// The SITE floor's argument, stated once here rather than per declaration, since the whole class
// shares it: classObligation is the only class holding a protected member today, and the reason is
// its own stated residual. Two of its sites are drivable at the request rate by a CONFORMING peer
// against a merely broken deployment — a flow store that is down fails every approved
// declassification's commit, and a stale effect.ref pin makes every receipt inconsistent — so the
// class bucket can be held empty with no adversary involved, and what that reduces to a count on
// somebody else's line is `SECURITY: redaction failed`, the line the class was split out to keep
// legible.
//
// A FOURTH class was the alternative and is rejected because it recurses: it is the same argument
// one level finer, and the next reader asks what elides the declassify-commit line. A floor answers
// the question actually being asked, which is arrival rather than rate, and without another budget:
// the flooding sites keep sharing their holder's class reserve, so the flood spends that one and
// leaves the protected site's untouched.

// newNoticeCollapse builds one SOURCE's collapse slots — an upstream's, which is a route on the
// gateway and the proxy itself on stdio, since that is what the collapsed faults are per (one route
// has one receipt verifier and one policy engine behind it).
//
// keyReserve, the same primitive the diagnostic floor is built on, rather than a keyed table of its
// own: this package has twice decided that two hand-mirrored keyed maps drift, and the re-arm
// semantics being shared is the point rather than a coincidence.
//
// A flow store shared by several routes collapses per route rather than once overall — the stated
// residual, bounded by the route count an operator configured. A process-wide source would let one
// tenant's broken backend silence another tenant's report of its own, which is the elision the route
// split one tier down exists to prevent.
func newNoticeCollapse() *keyReserve[noticeSite] { return newKeyReserve(collapsedNoticeSites) }

// floorProtectedSites is the protected subset, DERIVED from the declarations rather than listed
// beside them, so a site cannot be declared protected and reserve nothing. Sorted for a
// deterministic reserve.
var floorProtectedSites = sortedKeysWhere(meteredNotices,
	func(d noticeSiteDeclaration) bool { return d.floor == floorSiteProtected })

// noticeReserve is a leg's diagnostic floors: one guaranteed line per key per noticeReserveInterval,
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
// What the floor costs is bounded twice over: it re-arms per noticeReserveInterval rather than
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

// newNoticeReserve builds a leg's floors. classes is what the leg reserves on the HOLDER axis —
// noticeClasses for a session, nil for a leg that is not a holder among peers (a whole stdio proxy
// has no sibling to be starved by) — while the site axis is unconditional, being about which line a
// class-mate's flood must not elide rather than about holders.
//
// One constructor taking the axis that varies, rather than a named pair differing by one field: the
// pair made a reader open both to learn which, and a third leg kind needed a third name.
func newNoticeReserve(classes []noticeClass) *noticeReserve {
	r := &noticeReserve{bySite: newKeyReserve(floorProtectedSites)}
	if len(classes) > 0 {
		r.byClass = newKeyReserve(classes)
	}
	return r
}

// forSite is the floor a line from site may fall back on: its own where its declaration says it
// holds one, this holder's class floor otherwise, and nil for neither.
//
// It takes the DECLARATION rather than probing a table of its own, which is what removes a
// string-keyed map lookup from every admitted line for an answer one site of fifteen gives. The
// bySite probe that remains is reached only by a site declaring floorSiteProtected — and still
// answers nil on a leg that reserved nothing (a pre-session HTTP arm), which is what keeps the
// disposition a property of the SITE and the slot a property of the LEG.
//
// The site slot WINS rather than composing with the class slot. Falling back to the class floor
// after a site floor is spent would hand the protected site two arrivals per interval and the
// others none, which is not the property being bought: the site floor exists so a class-mate's
// flood cannot elide this line, and the class floor because a peer holder's flood cannot.
func (r *noticeReserve) forSite(site noticeSite, decl noticeSiteDeclaration) *reserveSlot {
	if r == nil {
		return nil
	}
	if decl.floor == floorSiteProtected {
		if slot := r.bySite.forKey(site); slot != nil {
			return slot
		}
	}
	// classUnclassified is deliberately unreserved: an undeclared site charges the floor-rate
	// fallback bucket and nothing else, and a reserve for it would hand exactly that site a line
	// outside every bucket. newKeyReserve builds slots for the declared classes alone, so this
	// resolves to nil for it structurally rather than by a range check that must be kept in
	// agreement with the enum.
	return r.byClass.forKey(decl.class)
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
	// collapse is the SOURCE's per-site windows for the faults collapsed at their source (see
	// collapseWindowed in meteredNotices), consulted ABOVE the buckets rather than under them: an occurrence this
	// folds spends no token at all. Nil on a leg with no source to attribute one to.
	collapse *keyReserve[noticeSite]
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
// boxing the arguments for a line then discarded costs ~110ns more and two heap allocations. The
// boxing is most of it, which is why this is a CALL-SITE ordering and no lazier signature here would
// remove it — and why the alternative, a convenience wrapper taking the format eagerly, is gone
// rather than kept for the sites whose arguments happen to be cheap: judged per site it left eight
// of fourteen paying for lines they discard, several of them per-frame drivable, and every one of
// them a fresh judgment for the next reader to re-derive.
//
// Where that ~110ns goes, since two of the three parts are decisions rather than givens: the
// declaration lookup is ~11ns, the floor resolution a map probe, and an already-spent slot's claim
// ~13ns (BenchmarkNoticeReserve_Claim). Neither the collapse nor the site floor costs more than a
// comparison on a value already loaded: both dispositions ride the declaration, so the window probe
// is reached only by a site that DECLARES a window and the per-site floor probe only by one that
// declares a floor — one site of fifteen, which is why that probe was worth removing from the other
// fourteen. As tables of their own each was a second string-keyed probe on EVERY line, the collapse
// measured at ~7% of this admission (BenchmarkNotice_SuppressedPath/admission), against the ~2ns the
// wider declaration value adds to the one probe that remains. The lookup stays a map probe rather than an
// integer site indexing a dense array because it is not the part that dominates, and the constants'
// readable values are what the call-site walk resolves and what its failures name. None of the
// three reads a clock: the admission's own sample is handed to the floor, which is what keeps a
// refused frame — the path this whole budget exists for — off a vDSO call it would otherwise pay
// per frame per session.
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
	// bounded one. noticeReserve reserves no floor for that class for the same reason. It also
	// resolves to collapseUndeclared, which collapses nothing — the bounded direction on that axis
	// too, since a window an undeclared site fell into would mute a line nobody has classified.
	decl := meteredNotices[site]
	// The collapse window sits ABOVE the bucket, which is the whole point of collapsing at the
	// source: a folded occurrence spends no token, so a persistent backend fault stops emptying the
	// class bucket instead of sharing one it has already emptied. It is checked FIRST for the same
	// reason the admission precedes the caller's arguments — the cheapest answer on the flood path
	// the mechanism exists for.
	//
	// The disposition comes off the declaration just read rather than from a second string-keyed
	// probe: the windows are keyed by site, so asking the map was asking every line to pay for a
	// window two of fifteen sites hold. The slot lookup that remains is reached only by a site
	// declaring one, and still returns nil on a leg with no SOURCE to attribute a window to (a
	// pre-session HTTP arm), which is what keeps the disposition a property of the site and the
	// window a property of the leg.
	//
	// The fold goes onto that bucket's own tally rather than a counter of its own, so the count
	// reaches a reader through the tail every admitted line of the class already carries: one
	// answer to "what did I not see", not two.
	//
	// The window is CLAIMED here, before the bucket is consulted, which is one atomic operation and
	// not a peek. A peek-then-mark composition — check the window, take the bucket, then mark —
	// reads better and is the shape saturationGate needed a mutex to make safe: two of its steps
	// race, and the lost update leaves a site marked with nothing written or unmarked after a write.
	// The residual of claiming first is stated rather than designed around: an occurrence whose
	// class bucket is empty spends the window anyway, so that site's next report is delayed by at
	// most one interval. Bounded, self-healing, and a line the bucket declined would not have been
	// written under either shape.
	if decl.collapse == collapseWindowed {
		if slot := n.collapse.forKey(site); slot != nil && !slot.claim(n.limits.clock(), noticeCollapseInterval) {
			n.limits.bucket(decl.class).suppress()
			return noticeLine{}, false
		}
	}
	verdict := n.limits.admitWithFloor(decl.class, n.reserve.forSite(site, decl))
	if !verdict.ok {
		return noticeLine{}, false
	}
	return noticeLine{out: n.errOut(), tail: noticeTail(verdict, decl.class)}, true
}
