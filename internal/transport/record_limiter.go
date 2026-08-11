// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Admission control over the writes a refusal makes at a rate a caller (not the policy) sets:
// the RECORDS of transport refusals taken before or beside a policy decision (recordRateLimiter)
// and of pool-saturation refusals (saturationGate), and the stderr NOTICE a refusal writes beside
// its record. No policy ALLOW/DENY record is ever admission-controlled.
//
// Which refusals are metered and which are deliberately not is a DECLARATION, not prose: every
// category carries one in refusalDeclarations, an exempt one carries its reason, and a table test
// walks the recorder call sites so a refusal cannot ship without an answer. It was prose, and the
// survey behind it was incomplete — the routing refusal's exemption was argued in a comment while
// the smuggling refusal beside it, equally unmetered and equally cheap, had no recorded judgment
// either way.
//
// The two halves of one refusal are bounded SEPARATELY and for different reasons: a record may be
// exempt because it is a verdict, and a stderr line is never a verdict (see
// exemptBecausePolicyDenyCostsTheSame and notice.go). They were reasoned about with one standard
// applied to both, which left the cheapest refusal in the tree writing an unbuffered syscall per
// frame while its record was argued exempt.
//
// The NOTICE half lives in notice.go and now carries the same treatment one step further: its
// per-site declaration is READ at write time to pick a bucket, where this file's is read to resolve
// a recorder. What is shared between them is the table below it — tieredBuckets, the two-tier keyed
// admission both are built on.

package transport

import (
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// Token bucket bounding refusal records an unauthenticated caller can trigger for free:
// unbounded, a dropped audit write can latch AUDIT_UNAVAILABLE and deny every call under
// --require-audit=strict, so an attacker could take the data plane down by spraying bad
// bearer tokens. Suppressed refusals fold into the next admitted record's
// suppressed_refusal_count rather than vanishing; buckets are per-CATEGORY (see below) so
// one cheap flood cannot silence another category's records, and per-category shares
// divide (not replicate) the aggregate so the reachable rate an attacker can drive stays
// bounded regardless of category count.
// Sized as a per-category share times the category count, so ADDING a category costs one
// category's worth of aggregate rather than silently halving every existing category's share
// — which is what plain division does at the integer boundary (20/10 = 2/s, 20/11 = 1/s).
// The aggregate is still what bounds the reachable rate; it just grows with the set it
// divides rather than being a fixed number the set erodes.
const (
	perCategoryDenyRatePerSec = 2
	perCategoryDenyBurstSize  = 5
)

// The aggregate budget, DERIVED from the metered set rather than a hand-typed count of it. A count
// written out separately had to be reconciled by a test with a map literal sixty lines away, and
// it moved for two different reasons — adding a category, and flipping an existing one's one-word
// metering — only one of which the test's message named.
var (
	preSessionDenyRatePerSec = perCategoryDenyRatePerSec * len(refusalCategories)
	preSessionDenyBurst      = perCategoryDenyBurstSize * len(refusalCategories)
)

// refusalCategory is a distinct type (not a bare string) because a METERED category's value
// doubles as both the rate-limit bucket key and the audit record's structured condition_type
// field.
//
// A category declared EXEMPT is neither of those: it names a refusal so the declaration has
// something to attach to and the call-site walk has something to find. That asymmetry is the
// price of making an exemption a decision on the record rather than the absence of a call.
type refusalCategory string

// The refusal categories. Every recordPreSessionDeny / recordSessionCapDeny call site
// passes one of these.
const (
	catOrigin      refusalCategory = "origin"
	catJWT         refusalCategory = "jwt"
	catAuth        refusalCategory = "auth"
	catControl     refusalCategory = "control"
	catLoopback    refusalCategory = "loopback"
	catBody        refusalCategory = "body"
	catContentType refusalCategory = "content_type"
	catSaturation  refusalCategory = "saturation"
	// catKill bounds only the PRE-SESSION kill-switch records (session-creating
	// initialize under an active kill, sessionless initialize, unknown/killed-session
	// POSTs). A kill record for a session this proxy already established is written
	// unlimited — it's the record an operator most needs during an emergency stop.
	catKill refusalCategory = "kill"
	// catAudience bounds the PRE-SESSION per-route audience-pin refusal (the
	// session-creating initialize's initAudienceDenial). A caller holding one valid
	// token for any SIBLING route's audience (accepted by the gateway's shared union
	// JWT validator) reaches this on every route whose audience it fails, with no
	// session or upstream ever spawned — the same cheap-flood shape catKill exists to
	// bound, one credential away rather than zero.
	catAudience refusalCategory = "audience"
	// catRevision bounds the protocol-revision refusal (-32022). It is the cheapest
	// refusal the proxy can be made to write: a small body carrying a bogus `_meta`
	// protocol version, refused before the kill check, holding no slot and contacting no
	// upstream. Ungated, that is enough records to latch AuditDegraded(), which under
	// --require-audit=strict denies every route — the same shape catKill and catAudience
	// exist to bound, minus even the need for a credential.
	//
	// The one category BOTH transports meter. Its threat model is the HTTP proxy's
	// unauthenticated peer, which stdio does not have — but the refusal is the same refusal
	// for the same bytes, and on stdio it is written inline on the serve loop, the goroutine
	// that also routes host replies back to a blocked upstream. Metering it there costs the
	// tape nothing (a suppressed record folds into the next admitted one's
	// suppressed_refusal_count) and keeps identical bytes treated identically on the two
	// transports, which is the property that stops the pair drifting.
	catRevision refusalCategory = "revision"
	// catUnroutable and catSmuggled are the two DECLARED-EXEMPT categories: they name a
	// refusal so its non-metering is an answer on the record rather than an absent call. See
	// refusalDeclarations for the reason, which is the same for both.
	catUnroutable refusalCategory = "unroutable"
	catSmuggled   refusalCategory = "smuggled_notification"
	// catServerRequestFailed bounds the two records for a server-initiated request this proxy had
	// already TRACKED and then failed: a delivery that never reached the host, and a host reply
	// destroyed because there was no upstream sink to relay it through. Driven by the upstream like
	// catDisplaced, and metered for the same reason — nothing caps how many such requests an
	// upstream issues over a session's life.
	catServerRequestFailed refusalCategory = "failed_server_request"
	// catUnroutableID bounds the record for a server-initiated request eunox refuses because its
	// own JSON-RPC id is larger than the in-flight tracker retains. Its own bucket, not
	// catDisplaced's: the two refusals are answered identically but are not equally cheap to
	// reach — a displacement needs the bounded set full or an id collision, an over-cap id needs
	// neither — so sharing one bucket would let the cheaper flood suppress the record that says a
	// LIVE in-flight request was evicted.
	catUnroutableID refusalCategory = "unroutable_server_request_id"
	// catDisplaced bounds the record for a server-initiated request the in-flight tracker
	// displaced. Driven by the UPSTREAM rather than by a host peer (see upstreamRefusalCategories
	// for that whole set) because once the bounded set is full every further request displaces
	// one, so an upstream issuing them faster than the host answers turns an unbounded audit-write
	// rate loose for as long as it likes.
	catDisplaced refusalCategory = "displaced_server_request"
	// catRefusalUndeliverable bounds the record for a REFUSED server-initiated request whose answer
	// never reached its initiator (see serverRequestUnblocker.answer). Its own bucket for the reason catUnroutableID
	// has one: this needs neither tracking nor a host — an upstream with a broken stdin drives one
	// per request — so a shared bucket would let it suppress the record that a LIVE request was lost.
	catRefusalUndeliverable refusalCategory = "undeliverable_server_refusal"
)

// refusalMetering is a refusal category's DECLARED disposition. The zero value is "undeclared",
// so a category added with no entry fails the table test rather than silently inheriting either
// answer — the shape pkg/capability's prototype registry uses for Since/State/Uses.
type refusalMetering int

const (
	meteringUndeclared refusalMetering = iota
	// meteringMetered: the category charges its own per-category bucket, and a suppressed
	// record folds into the next admitted one's suppressed_refusal_count.
	meteringMetered
	// meteringExempt: deliberately unbounded, for the reason the declaration states.
	meteringExempt
)

// refusalDeclaration is what every refusal category declares. why is required for an exemption
// and must be empty for a metered category: the reason is the whole content of an exemption, and
// a metered one needs none.
type refusalDeclaration struct {
	metering refusalMetering
	why      string
}

// exemptBecausePolicyDenyCostsTheSame is the reason BOTH exempt categories carry, stated once
// because it is one argument rather than two that happen to agree.
//
// Reaching either refusal takes a peer whose ordinary traffic writes policy DENY records at the
// same one-record-per-message cost — and a policy verdict may NEVER be admission-controlled, since
// a verdict elided is a verdict an incident responder does not have. Metering these would lower no
// ceiling; it would only make the cheapest way to fill the queue the one that leaves the better
// tape.
//
// SCOPE, because the argument was read wider than it holds: it covers the RECORD. The second clause
// is what carries it, and a stderr line is not a verdict — nor does a policy DENY write one, so the
// first clause does not carry it either. The routing refusal's own diagnostic is therefore bounded
// on its own class bucket (see notice.go) rather than inheriting this, which is how it came to be
// the one place in the tree where an unauthenticated peer drives an unbuffered write syscall per
// frame.
const exemptBecausePolicyDenyCostsTheSame = "reaching it needs a peer whose ordinary traffic writes policy DENY records at the same one-per-message cost, and a policy verdict may never be metered"

// refusalDeclarations is authoritative for BOTH questions: which categories exist, and what each
// one's metering disposition is. refusalCategories (the bucket table, and the divisor for every
// category's share of the aggregate budget) is derived from it, so declaring a category exempt
// does not silently shrink the metered ones' shares.
var refusalDeclarations = map[refusalCategory]refusalDeclaration{
	catOrigin:               {metering: meteringMetered},
	catJWT:                  {metering: meteringMetered},
	catAuth:                 {metering: meteringMetered},
	catControl:              {metering: meteringMetered},
	catLoopback:             {metering: meteringMetered},
	catBody:                 {metering: meteringMetered},
	catContentType:          {metering: meteringMetered},
	catSaturation:           {metering: meteringMetered},
	catKill:                 {metering: meteringMetered},
	catAudience:             {metering: meteringMetered},
	catRevision:             {metering: meteringMetered},
	catDisplaced:            {metering: meteringMetered},
	catUnroutableID:         {metering: meteringMetered},
	catServerRequestFailed:  {metering: meteringMetered},
	catRefusalUndeliverable: {metering: meteringMetered},
	// The fail-closed ROUTING refusal, on either transport and in either framing.
	catUnroutable: {metering: meteringExempt, why: exemptBecausePolicyDenyCostsTheSame},
	// The enforced-method-as-notification reject. It writes a record as cheap as the routing
	// refusal's on the same goroutine — `{"jsonrpc":"2.0","method":"tools/call"}` costs no id, no
	// host-handler slot and no upstream round trip — and it is exempt for the same reason: an
	// established peer sending the REQUEST framing of the same method drives a policy DENY per
	// message anyway. Recorded here as a judgment rather than left as the absence of a call,
	// which is how it went unsurveyed while its neighbour's exemption was argued in prose.
	catSmuggled: {metering: meteringExempt, why: exemptBecausePolicyDenyCostsTheSame},
}

// refusalCategories is the METERED subset, sorted so the derived bucket table and every test
// reading it are deterministic. A category declared exempt is deliberately absent: it charges no
// bucket, and counting it would divide the aggregate budget by a share nothing spends.
var refusalCategories = meteredRefusalCategories()

func meteredRefusalCategories() []refusalCategory {
	out := make([]refusalCategory, 0, len(refusalDeclarations))
	for cat, decl := range refusalDeclarations {
		if decl.metering == meteringMetered {
			out = append(out, cat)
		}
	}
	slices.Sort(out)
	return out
}

// perBucketFloor keeps every bucket in a divided table alive even where plain division would
// floor its share to 0 (possible past ~20 categories at today's rate) — a 0-rate bucket
// never refills and would permanently suppress that key's writes.
const perBucketFloor = 1

// perBucketShare divides total evenly across keys, floored at perBucketFloor.
// Integer division (not float) keeps each share a whole token count and lands the sum at
// or slightly UNDER the aggregate when it doesn't divide evenly — the safe direction.
//
// One consumer today, the refusal categories: the notice classes were the second and now multiply a
// per-key budget UP instead, on measured grounds stated at their sizing constants. Kept as a
// function rather than inlined because the floor is the part worth not re-deriving — a share that
// divides to zero never refills and silently stops a key's writes for good.
func perBucketShare(total, keys int) float64 {
	share := total / keys
	if share < perBucketFloor {
		share = perBucketFloor
	}
	return float64(share)
}

// perCategoryDenyRate and perCategoryDenyBurst are each registered category's even share
// of the aggregate budget. The unreachable-in-production "unknown" fallback bucket is
// deliberately NOT sized from these — it gets perBucketFloor instead, so it doesn't
// dilute every real category's share for a bucket no call site actually uses.
var (
	perCategoryDenyRate  = perBucketShare(preSessionDenyRatePerSec, len(refusalCategories))
	perCategoryDenyBurst = perBucketShare(preSessionDenyBurst, len(refusalCategories))
)

// newRefusalRecordLimiter builds a bucket for every METERED category, each holding an equal
// share of the aggregate rate/burst (see perCategoryDenyRate/perCategoryDenyBurst). The HTTP
// proxy's, since that transport charges nearly all of them.
func newRefusalRecordLimiter() *categoryRecordLimiter {
	return newRefusalRecordLimiterFor(refusalCategories...)
}

// newRefusalRecordLimiterFor builds buckets for the categories ONE transport actually charges.
//
// stdio charges exactly one (catRevision), so the full table left it holding ten buckets it can
// never spend — on a proxy that may have no audit sink at all. The per-bucket SHARE is still
// computed from the whole declared set, never from len(cats): a transport's budget is its share of
// the aggregate, not the aggregate.
//
// A category outside cats falls to the shared `unknown` bucket, which is bounded rather than
// unbounded — the safe direction — and each transport's charged set is held to what it declares,
// so the fallback stays unreachable.
func newRefusalRecordLimiterFor(cats ...refusalCategory) *categoryRecordLimiter {
	// floorOwnBucket, even though this table has no holder of its own: a per-session table
	// DELEGATES a category it holds no bucket for wholly upward, floor included, and for such a
	// category this tier is where that session contends with its peers.
	return &categoryRecordLimiter{tieredBuckets: newTieredBuckets(
		perCategoryDenyRate, perCategoryDenyBurst, recordReserveInterval, cats, nil,
		suppressedScopeProxyCategory, floorOwnBucket)}
}

// stdioRefusalCategories is the set the stdio transport charges. Declared rather than left implicit
// in its call sites, so the limiter it builds and the categories it spends are one statement — and
// so a metered refusal added to that transport is a deliberate edit here.
var stdioRefusalCategories = []refusalCategory{
	catRevision, catDisplaced, catUnroutableID, catServerRequestFailed, catRefusalUndeliverable,
}

// upstreamRefusalCategories is the set driven by an UPSTREAM rather than by a host peer, and the
// set whose buckets are held PER SESSION on the HTTP transport (see newUpstreamRefusalLimiter).
// Declared here beside the transports' own sets so "which refusals does a session's own upstream
// drive" is one statement rather than a property re-derived from four category docs.
var upstreamRefusalCategories = []refusalCategory{
	catDisplaced, catUnroutableID, catServerRequestFailed, catRefusalUndeliverable,
}

// remoteUpstreamRefusalCategories is the subset a REMOTE-upstream session holds buckets for.
//
// Three of the four are driven by a server-initiated request the proxy TRACKED, and this mode
// tracks none: there is no upstream reader to receive one, so nothing ever enters the in-flight
// tracker and no displacement, over-cap id, or undeliverable refusal can arise. Their buckets
// would bound nothing.
//
// catServerRequestFailed is kept as the one whose writers are gated on a tracker entry this mode
// merely cannot produce TODAY, rather than on machinery it does not have: a remote leg that ever
// gains an inbound channel reaches it first. Keeping one bucket that a live mode may need beats
// re-deriving this list from a comment when it does — and the cost of being wrong in this
// direction is one idle rate limiter, against a category delegated to the shared aggregate in the
// other.
//
// Narrowing is safe rather than merely cheap because a category this table has no bucket for is
// delegated WHOLLY to the aggregate parent (see tieredBuckets.admitWithFloor) — the proxy-wide bound those
// records had before the per-session split existed, and now labelled with the aggregate's own
// scope rather than this table's.
var remoteUpstreamRefusalCategories = []refusalCategory{catServerRequestFailed}

// newUpstreamRefusalLimiter builds ONE HTTP session's buckets for the upstream-driven categories.
//
// Per session, not proxy-wide, for the reason saturationGate states for its own records: one
// session's flood must not elide another's. These four are driven by a session's OWN upstream, so a
// dead subprocess on session A used to drain the shared bucket at its ~2/s share and suppress
// session B's record that a LIVE in-flight request was lost — folded instead into a
// suppressed_refusal_count on a record stamped with A's route. Each category's own bucket exists to
// stop exactly that between categories; the session is the same argument one dimension out.
//
// The split alone would trade the elision bug for an availability one: at the default
// maxSessions (512) four categories at a per-session share is 4096 records/s sustained and 10240
// burst, against an audit queue of 4096 — and --require-audit defaults to STRICT, so overflowing
// it latches AuditDegraded and denies every route. So the per-session table charges the proxy's
// own table as its AGGREGATE parent: this session's buckets decide fairness, the parent keeps the
// total at the pre-split ceiling. aggregate may be nil (a bare-struct-literal proxy in a test),
// which bounds the session alone. See docs/threat-model-mcp.md §3.7.
//
// cats is the session's own reachable set rather than a constant, since a remote-upstream session
// reaches at most one of the four — see remoteUpstreamRefusalCategories. A SLICE rather than a
// variadic tail: the variadic form let `newUpstreamRefusalLimiter(aggregate)` compile into a table
// with no buckets at all, which delegates every upstream-driven category to the parent and silently
// undoes the per-session split this constructor exists for.
func newUpstreamRefusalLimiter(aggregate *categoryRecordLimiter, cats []refusalCategory) *categoryRecordLimiter {
	var parent *tieredBuckets[refusalCategory]
	if aggregate != nil {
		parent = &aggregate.tieredBuckets
	}
	return &categoryRecordLimiter{
		tieredBuckets: newTieredBuckets(
			perCategoryDenyRate, perCategoryDenyBurst, recordReserveInterval, cats, parent,
			suppressedScopeSessionCategory, floorParentBucket),
		// Over the whole upstream-driven set rather than over cats, which is what makes the
		// aggregate's own floorOwnBucket reachable: a category this table holds no bucket for is
		// DELEGATED wholly upward, and for such a category the session contends with its peers at
		// that tier — so it needs a slot there or the delegation carries no floor at all, which is
		// the elision this constructor exists to close, surviving for exactly the narrowed table.
		floor: newKeyReserve(upstreamRefusalCategories),
	}
}

// refusalLimits is a transport leg's admission control over the writes a REFUSAL makes: the
// per-category buckets bounding its audit records, and the bucket bounding its stderr notice.
//
// Held APART from the audit sink, which every params struct on the refusal path already carries for
// its policy records: a second copy of that sink beside the limits is a wiring fault nothing would
// catch, since the two would be silently free to name different tapes. recorders() is where the two
// are put back together, at the one site that resolves a refusal's recorder.
//
// A zero value meters nothing and bounds no notice — what a bare-struct-literal proxy in a test
// gets, and the behaviour every leg had before either bucket existed.
type refusalLimits struct {
	// records bounds the refusal RECORDS this leg's categories declare metered. nil on a leg that
	// meters none of them: stdio's notification gate, and the established-session HTTP arm, whose
	// kill records describe an already-admitted caller and are deliberately unbounded.
	records *categoryRecordLimiter
	// notices is this leg's diagnostic CHANNEL — where a line goes and what bounds it, as one
	// value. Separate from records because the two answer to different arguments and a leg can
	// legitimately want one without the other: the established-session arm above meters no record
	// it writes and still owes a bound on a per-frame syscall. See noticeWriter.
	notices noticeWriter
}

// recorders pairs these limits with the leg's audit sink; rec may be nil (the leg has no tape).
func (l refusalLimits) recorders(rec auditRecorder) refusalRecorders {
	return refusalRecorders{rec: rec, limits: l}
}

// refusalRecorders is a transport leg's wiring for the recorder a refusal writes its record
// through, resolved per CATEGORY rather than once per leg, plus the admission control over the
// stderr notice it writes beside that record.
//
// Per category because one leg's arms disagree: the HTTP pre-session arm bounds its kill record
// (catKill — an unauthenticated caller drives it) while the smuggling and routing refusals beside
// it are DECLARED exempt, and a single per-leg recorder handed all three the metered one — so an
// exemption on the record spent a catKill token anyway, draining the bucket that bounds the records
// an incident responder reads first during an emergency stop.
//
// Plain values, not thunks: resolving the sink costs a nil-compare and an interface conversion,
// while the TOKEN is spent inside forCategory and only for a record actually being written — so
// laziness is preserved where it mattered, without a closure per message on the leg an
// unauthenticated peer drives at its send rate.
type refusalRecorders struct {
	// rec is the leg's audit sink, or nil when it has none.
	rec auditRecorder
	// limits is a NAMED field rather than an embedded one. Embedding promoted recorders() onto
	// this type, so `recs.recorders(otherSink)` compiled on an already-resolved wiring and minted
	// one keeping this leg's buckets while pointing at a DIFFERENT tape — verbatim the hazard
	// refusalLimits' own doc says holding the sink apart was meant to prevent, and one the
	// surrounding code invites by writing `.recorders()` idiomatically at four sites. forCategory
	// being the one resolver governs which bucket a record charges, never which tape it lands on.
	limits refusalLimits
}

// forCategory applies the disposition the CATEGORY declares rather than the leg's own default,
// which is what makes "declared exempt" and "charges no bucket" one fact. It is the ONE resolver:
// every refusal record's recorder comes from here, so no producer has an entry point the
// declaration does not govern.
//
// An UNDECLARED category is metered, not exempt: the zero refusalDeclaration means nobody has
// answered the question, and the safe answer to that is the bounded one.
//
// The map probe is per refusal record and deliberately kept: the disposition is read from the
// declaration at resolution time rather than pre-resolved into a per-leg table, because a second
// table is a second copy of the answer, and this runs only where a refusal is already writing to
// the tape. Tens of nanoseconds against a record's serialize-sign-write — ~29ns for an exempt
// category (the probe alone) and ~58ns for an admitted metered one (BenchmarkRefusalRecorders_ForCategory).
func (r refusalRecorders) forCategory(category refusalCategory) auditRecorder {
	if r.rec == nil || r.limits.records == nil || refusalDeclarations[category].metering == meteringExempt {
		return r.rec
	}
	return admitRefusalRecord(r.rec, r.limits.records, category)
}

// notices is this wiring's diagnostic channel, reached through the named limits field so a
// caller needs no second vocabulary for the half of a refusal that is not a record.
func (r refusalRecorders) notices() noticeWriter { return r.limits.notices }

// tieredBuckets is the two-tier keyed token-bucket table BOTH admission controls in this package
// are built on: refusal records keyed by category (categoryRecordLimiter) and stderr diagnostics
// keyed by class (noticeLimiter). One implementation rather than two, because the subtle part is
// the same subtle part on either axis — an outer tier that refuses must not lose the inner tier's
// tally — and a second copy of it is a second thing to keep in agreement.
//
// The table is built ONCE at construction rather than lazily, so admit takes no lock but
// its own bucket's — not a second proxy-global lock on the path this file exists to keep
// cheap under attack.
type tieredBuckets[K comparable] struct {
	buckets map[K]*recordRateLimiter
	// unknown serves an unregistered key, and exists ONLY on a table with no parent: a table that
	// has one delegates such a key wholly upward, so a fallback bucket beside it would be an
	// allocation admit can never reach — and worse, one bucket() would hand out for a key admit
	// charges elsewhere.
	unknown *recordRateLimiter
	// parent is the proxy-wide AGGREGATE this table's writes also charge, or nil when this
	// table IS that aggregate. A per-session (or per-route) table has one: its own buckets stop
	// one tenant's flood eliding another's, and the parent stops N tenants multiplying the
	// sustained rate by N. Without it a split trades the elision bug for an availability one —
	// see newUpstreamRefusalLimiter.
	parent *tieredBuckets[K]
	// scope names what a rollup from THIS tier spans. Held here rather than on the embedder
	// because admit is what decides which tier answered, and a scope resolved by the caller from
	// the table it happens to hold is wrong for exactly the delegated key: the count comes from
	// the parent and the label from the child, which stamps a proxy-wide tally as session-scoped.
	scope string
	// floorAt is which refusal this table's holder may deliver a floored write through. See
	// floorTier: it is a property of who SHARES these buckets, which only the constructor knows.
	floorAt floorTier
	// reserveEvery is how long a floor spent against THIS table stays spent, beside the rate and
	// burst it is the third sizing knob of. Per table rather than one package constant, because
	// the two tables' floored writes fail differently and are not interchangeable in either
	// direction: an audit record floored into a 4096-deep queue that latches AuditDegraded() is
	// an availability question for the whole data plane, while a floored stderr line is terminal
	// legibility during an incident — so an operator loosening the second must not be loosening
	// the first. See recordReserveInterval and noticeReserveInterval for each one's argument.
	reserveEvery time.Duration
	// now is this table's clock, beside the per-bucket ones setNow already points at a test's.
	// Held here for the one caller that samples an instant WITHOUT admitting through a bucket —
	// the per-site collapse, which decides before any token is spent — so it cannot measure its
	// interval on a different clock from the tier it sits above.
	now func() time.Time
}

// clock is this table's instant. A table built by a bare struct literal in a test has none and
// falls back to the wall clock, the behaviour every caller had before the field existed.
func (t *tieredBuckets[K]) clock() time.Time {
	if t == nil || t.now == nil {
		return time.Now()
	}
	return t.now()
}

// floorTier declares where a holder's floor answers, which is the tier at which that holder
// contends with its PEERS — the only refusal a guaranteed arrival is the right answer to.
//
// It differs between this package's two tables because their holders sit differently. A notice
// holder (a session) SHARES its route's class buckets with its peers, so its peers' flood shows up
// as this table's own bucket refusing. A refusal from the tier ABOVE is a different fact:
// the route had a token, both tiers have already counted the write, and the pressure comes from
// tenants this session cannot influence — flooring it there burns a holder's reserve on a sibling
// ROUTE's flood. A record holder (a session) instead owns its whole table, so its own bucket
// refusing means it outran its OWN budget — no floor is owed — and its peers contend one tier up,
// at the proxy-wide aggregate, which is exactly where its records were being elided.
//
// The zero value floors nothing, which is what an aggregate reached with no holder in hand wants.
type floorTier int

const (
	floorNowhere floorTier = iota
	// floorOwnBucket: this table's buckets are shared by the holders, so its own refusal is the
	// one attributable to contention among them.
	floorOwnBucket
	// floorParentBucket: this table belongs to one holder alone; its peers contend at the parent.
	floorParentBucket
)

// newTieredBuckets builds one bucket per key at the given rate/burst, under parent (nil for an
// aggregate), labelling its own rollups with scope and re-arming its holders' floors every
// reserveEvery.
//
// parent is a constructor parameter rather than a field a caller sets afterwards, because whether
// this table needs the floor-rate fallback is decided by it: a parented table delegates an
// unregistered key upward and can never reach one.
func newTieredBuckets[K comparable](ratePerSec, burst float64, reserveEvery time.Duration, keys []K, parent *tieredBuckets[K], scope string, floorAt floorTier) tieredBuckets[K] {
	t := tieredBuckets[K]{
		buckets:      make(map[K]*recordRateLimiter, len(keys)),
		parent:       parent,
		scope:        scope,
		floorAt:      floorAt,
		reserveEvery: reserveEvery,
		now:          time.Now,
	}
	if parent == nil {
		t.unknown = newRecordRateLimiter(perBucketFloor, perBucketFloor)
	}
	for _, k := range keys {
		t.buckets[k] = newRecordRateLimiter(ratePerSec, burst)
	}
	return t
}

// bucketVerdict is one tiered admission's outcome: whether the write may happen, how many writes
// UNDER THAT KEY were elided since the last admitted one, which tier's scope that count spans, and
// whether it was the caller's own FLOOR rather than a token that let it through.
//
// A struct rather than a tail of unnamed returns because the fourth answer only exists for a caller
// that supplies a floor, and a bool bolted onto three positional values is the shape a caller
// silently gets the wrong way round.
type bucketVerdict struct {
	ok         bool
	suppressed uint64
	scope      string
	// reserved reports that this table's own bucket had nothing left and the caller's floor
	// delivered the write anyway. The distinction is for the caller's TEXT: a reserved write says
	// so, since it is the one write whose arrival does not mean the tier had room for it.
	reserved bool
	// refusedBy is the bucket that actually said no, at whatever tier that was — nil on an
	// admitted write. It travels back up the chain so a floor DEBITS the tier that refused rather
	// than the one it happens to sit directly under.
	//
	// Positional was the alternative and is wrong for the structure: admitWithFloor reports !ok
	// for a refusal ANYWHERE above, so reaching through exactly one level by hand
	// (t.parent.bucket(key)) holds only while the chain is two deep. With a third tier a middle
	// tier that ADMITTED — spending a token and pushing its tally back — would be debited for a
	// grandparent's refusal, and the tier that refused would keep its token: the floor would stop
	// displacing the flooder's next write, which is the property that made a floored AUDIT write
	// affordable. Nothing detects that positionally, since bucket() recurses happily past the
	// refusing tier and hands back a bucket.
	refusedBy *recordRateLimiter
}

// recordReserveInterval is how long a spent floor stays spent on the refusal-RECORD table.
//
// Sized for what a floored write here IS: an audit record admitted past a drained bucket into a
// 4096-deep queue whose overflow latches AuditDegraded(), which under a --require-audit defaulting
// to strict denies every route. That is the whole data plane, so the interval is the long end of
// what still delivers an arrival during an incident.
//
// A lifetime bit was the first shape and is wrong in the direction that matters. It is claimed by
// whichever refused write of that key comes FIRST, so a long-lived session that hits one transient
// failure during an unrelated flood has spent the arrival it needs hours later when its own
// upstream dies — the exact elision the floor exists to close, deferred rather than removed. Any
// finite interval fixes that, and a longer one is strictly better for the bound, because the
// interval does not delay an arrival: it only stops ONE holder claiming repeatedly.
//
// What it costs, stated as the mechanism actually behaves rather than as a rate. Nothing staggers
// the holders — every slot starts armed — so the leading edge of an incident that trips all of them
// at once delivers `holders x keys` writes in ONE burst, and the steady state after that is
// `holders x keys` per interval for as long as the incident lasts. Here the keys are the
// upstream-driven categories a session holds a slot for, so at the CLI's default maxSessions of
// 512 that is 512x4 = 2048 refusal records in a burst against a queue 4096 deep, then ~34/s
// sustained — what a fleet-wide upstream failure looks like, which is the incident the arrival
// exists for. The arithmetic is DERIVED from the live sets by a test rather than trusted here (see
// TestReserveCeiling_IsDerivedFromTheLiveSets), because it is written in terms of three sets that
// live in two other files and it has already drifted once.
//
// It is NOT bounded by "a session costs an upstream spawn", the bound the lifetime bit had: a
// session created once keeps claiming, so the ceiling is the number of LIVE holders, and
// `maxSessions: 0` (a supported unlimited setting) removes it entirely.
const recordReserveInterval = time.Minute

// reserveSlot is ONE holder's floor for ONE key: the instant it was last spent, or nil when it
// never has been. A nil SLOT is no reserve at all — what a leg with no holder gets, and what a key
// nobody reserved for resolves to.
//
// Bound to its key by whoever hands it out (see keyReserve), rather than being an interface the
// table asks about its own key: the two key spaces are not always the same one. The notice half
// reserves per CLASS for a session and per SITE for the one line a class-mate flood must not
// elide, while the table underneath both is keyed by class.
type reserveSlot struct {
	// last is when this slot was last claimed. A time.Time behind a pointer rather than a
	// unix-nano int64 for two reasons that both bite: UnixNano STRIPS the monotonic reading, so an
	// NTP step or a VM resume would move this interval while every bucket in the same table kept
	// refilling on the monotonic clock (a backwards step would refuse every floored write for the
	// length of the step — the exact elision the floor exists to close); and an int64 has no value
	// outside the clock's range to mean "never claimed", so the epoch read as unclaimed forever.
	// Atomic because a session writes from its request goroutine and its own upstream reader
	// concurrently.
	last atomic.Pointer[time.Time]
}

// claim takes this reserve if it has re-armed as of at — one guaranteed write per holder, per key,
// per every — reporting whether the write may happen. A nil slot answers for itself, which is what
// makes "this leg has no floor" need no branch at the call site.
//
// every is the TABLE's, handed down by the admission rather than read from a package constant here:
// this one slot type serves both budgets, and the two are sized for unrelated failures (see
// tieredBuckets.reserveEvery). A slot that read one constant would let an operator loosening the
// stderr floor loosen the audit queue's with it.
//
// at is the instant the ADMISSION was decided — sampled once, by the bucket the caller admitted
// through (recordRateLimiter.admit hands it back), and used for every tier that admission touches.
// One reading rather than one clock: a floor that re-sampled would measure its interval against a
// different instant than the refill that refused it, and threading each tier's own clock would make
// the answer depend on which tier a two-tier admission happened to be entered at. The consequence
// for a test is worth stating: freeze the tier you admit THROUGH and the floor is frozen with it,
// whatever the tiers above it are running on.
//
// A CAS loop rather than a plain store, so two goroutines racing the same re-armed slot yield
// exactly one write: the loser reloads the instant the winner just stored and finds it unelapsed.
// The stamp is allocated only past the early return, so a spent slot — the flood path's answer —
// costs one atomic load and a comparison.
func (s *reserveSlot) claim(at time.Time, every time.Duration) bool {
	if s == nil {
		return false
	}
	// A non-positive interval makes `elapsed < every` false for every clock reading, so the floor
	// would deliver EVERY refused write rather than one per window — an unconditional bypass of the
	// bucket, which on the record half means an unbounded audit-write rate past a drained tier under
	// a --require-audit defaulting to strict. Refusing here rather than trusting the constructors
	// because the interval is now a positional time.Duration in a seven-parameter signature, and the
	// safe answer to "nobody sized this" is the bound, not the bypass.
	if every <= 0 {
		return false
	}
	for {
		prev := s.last.Load()
		// Sub over two time.Time values, so the monotonic readings decide when both carry one.
		if prev != nil && at.Sub(*prev) < every {
			return false
		}
		stamp := at
		if s.last.CompareAndSwap(prev, &stamp) {
			return true
		}
	}
}

// keyReserve is one HOLDER's floors over a set of keys, built once and never resized, so a lookup
// takes no lock and a key nobody reserved for resolves to no floor rather than to a shared one.
//
// A nil *keyReserve is a holder with no floors — what a leg with no session in hand gets, since a
// refusal taken before a session exists is attributable to no session.
type keyReserve[K comparable] struct {
	slots map[K]*reserveSlot
}

// newKeyReserve builds a holder's floors for keys. Slots are allocated up front: the alternative
// is a lock or a sync.Map on a path whose whole point is being cheap under a flood.
//
// One backing array rather than a slot per key, because this runs per SESSION: at the default
// maxSessions that is one allocation per reserve instead of one per key, held live for the
// session's whole life.
func newKeyReserve[K comparable](keys []K) *keyReserve[K] {
	r := &keyReserve[K]{slots: make(map[K]*reserveSlot, len(keys))}
	backing := make([]reserveSlot, len(keys))
	for i, k := range keys {
		r.slots[k] = &backing[i]
	}
	return r
}

// forKey is this holder's floor for key, or nil where it reserved none.
func (r *keyReserve[K]) forKey(key K) *reserveSlot {
	if r == nil {
		return nil
	}
	return r.slots[key]
}

// admitWithFloor reports whether a write under key may happen now, how many writes UNDER THAT KEY
// were suppressed since the last admitted one, which tier's scope that count spans, and which
// bucket refused when one did.
//
// A table with a PARENT charges both tiers, own bucket first: this table bounds one tenant's
// share, the parent bounds the aggregate. A write the parent refuses is pushed BACK onto this
// table's own count rather than lost, so the rollup stays complete whichever tier elided it.
//
// A key this table holds no bucket for is delegated WHOLLY to the parent — it is simply not
// scoped to this tier, so it charges the aggregate as it did before the split, AND is labelled
// with the aggregate's scope. That is what keeps a subset table from silently routing an
// unlisted key to a floor-rate fallback, which no test could have caught (the metering walk
// cannot answer "which categories does this leg charge" from source).
//
// The floor is a PARAMETER of the one admission rather than a second floorless entry point beside
// it. An `admit(key)` spelling that passed nil existed and was correct only by coincidence of
// wiring: its one production caller happened to serve a table with no floor, so the moment that
// table gained one — which is exactly what a per-tenant or per-source-IP holder wants — every write
// through that spelling would have skipped it silently while the writes beside it did not. There is
// now nothing to forget: a holder resolves its floor at the one place that holds it (see
// categoryRecordLimiter.admitRefusal), and a caller with no holder passes nil explicitly.
//
// The floor is consulted at exactly one point: the refusal this table's floorTier declares its
// holder's peers responsible for. Every other refusal is either the holder's own doing or a ceiling
// an operator configured, and a guaranteed arrival is the wrong answer to both.
//
// A floored write is a bypass of the GATE, not of the ACCOUNTING. The bucket that REFUSED is
// debited for it (borrow), so that tier's long-run rate is unchanged: a floored arrival displaces
// the flooder's next write rather than adding to the tier's total. Only that tier, deliberately —
// on the floorOwnBucket arm the parent is neither consulted nor debited, because this tier's own
// budget is what bounds every write that leaves it and the aggregate's ceiling therefore holds
// transitively; charging both would make the aggregate under-serve by counting one write twice.
// The debit is clamped at one burst of debt, past which floors are free — the residual, bounded by
// holders x keys per this table's reserveEvery — because an unbounded debt would let enough holders starve a
// tier's ordinary writes permanently, which is worse than the excess it prevents.
//
// A floored write also takes the accumulated tally WITH it (deliveredAnyway) rather than leaving it
// for the next admitted write: under a sustained flood the floored line is the next line the reader
// actually sees, so a count left behind is a count reported after the incident or not at all.
func (t *tieredBuckets[K]) admitWithFloor(key K, floor *reserveSlot) bucketVerdict {
	own, registered := t.buckets[key]
	if t.parent != nil && !registered {
		// A delegated key is answered wholly by the tier it reaches, floor included: the parent's
		// floorAt decides whether the floor is consulted at all, and the parent's reserveEvery is
		// what re-arms it. That is the rule rather than an accident of recursion — the window a
		// floored write buys is a property of the BUDGET it is charged against, and this write is
		// charged against the parent's, so re-arming it on this tier's interval would size one
		// table's bypass by another table's argument.
		return t.parent.admitWithFloor(key, floor)
	}
	if !registered {
		own = t.unknown
	}
	ok, suppressed, at := own.admit()
	if !ok {
		if t.floorAt != floorOwnBucket || !floor.claim(at, t.reserveEvery) {
			return bucketVerdict{scope: t.scope, refusedBy: own}
		}
		return bucketVerdict{ok: true, suppressed: own.deliveredAnyway(), scope: t.scope, reserved: true}
	}
	if t.parent == nil {
		return bucketVerdict{ok: true, suppressed: suppressed, scope: t.scope}
	}
	if parent := t.parent.admitWithFloor(key, nil); !parent.ok {
		if t.floorAt == floorParentBucket && floor.claim(at, t.reserveEvery) {
			// This table's own token was already spent on a write that now happens, so its tally
			// is reported rather than pushed back; the tier that REFUSED is the one the debit and
			// the un-suppression land on, and it names itself in the verdict rather than being
			// assumed to be t.parent — a refusal can come from anywhere above. The scope stays this
			// table's: the count being reported is this holder's own, and an ancestor's is
			// deliberately never read here (the same writes are counted at every child).
			parent.refusedBy.borrow()
			return bucketVerdict{ok: true, suppressed: suppressed, scope: t.scope, reserved: true}
		}
		// The aggregate refused, so this write does not happen; give this table back the token's
		// worth of tally (this one plus everything it had accumulated) so the next admitted
		// one still states the true count. The parent's own tally is deliberately discarded: the
		// same writes are already counted here, and counting them twice would over-state a flood.
		// The refusing bucket is carried on unchanged, so a child of THIS table floors against the
		// tier that actually refused rather than against this one, which just pushed a tally back.
		own.suppressN(suppressed + 1)
		return bucketVerdict{scope: t.scope, refusedBy: parent.refusedBy}
	}
	return bucketVerdict{ok: true, suppressed: suppressed, scope: t.scope}
}

// bucket returns the token bucket key actually charges — this table's own, or the parent's for a
// key delegated wholly upward. No lock: the table is immutable after construction.
//
// It answers WHICH BUCKET A KEY CHARGES, never which bucket refused a given write: it recurses past
// a refusing tier without noticing, which is why an admission reports its refuser on the verdict
// (see bucketVerdict.refusedBy) instead of being reconstructed from here.
func (t *tieredBuckets[K]) bucket(key K) *recordRateLimiter {
	if b, exists := t.buckets[key]; exists {
		return b
	}
	if t.parent != nil {
		return t.parent.bucket(key)
	}
	return t.unknown
}

// setNow points every bucket at an injectable clock (test-only). A method rather than a
// field because an assignment to a parent field would miss the per-bucket clocks. It does NOT
// descend to the parent: a test freezing both tiers says so explicitly, which is what keeps a
// two-tier assertion from passing on one tier's clock.
func (t *tieredBuckets[K]) setNow(now func() time.Time) {
	t.now = now
	for _, b := range t.buckets {
		b.now = now
	}
	if t.unknown != nil {
		t.unknown.now = now
	}
}

// categoryRecordLimiter holds one recordRateLimiter per refusal category, so a flood of
// cheap refusals in one category cannot suppress another's records.
type categoryRecordLimiter struct {
	tieredBuckets[refusalCategory]
	// floor is this table's holder's reserve, nil on the proxy-wide aggregate (no holder). It
	// lives HERE rather than being threaded from the call site because this table is already
	// per-holder — the notice half cannot do the same, since its table is per ROUTE while its
	// holder is a session, which is the asymmetry that keeps the two wirings apart.
	floor *keyReserve[refusalCategory]
}

// admitRefusal is the ONE admission a refusal RECORD is written under, on either spelling of the
// write: it charges this table's tiers for category and resolves the holder's floor from the table
// that HOLDS it, so no caller can reach the buckets while leaving the floor beside them unread.
//
// There were two spellings and they agreed only by coincidence of wiring. The pre-session path
// (recordRefusal, which writes its record inline and folds the rollup into its own details) reached
// the buckets directly, and that was correct exactly while p.preSessionDenies carried no floor —
// so the moment it gained one, every refusal an unauthenticated caller can drive would have skipped
// it while the four upstream-driven ones did not, with nothing to detect the difference (the
// metering walk checks a category's DECLARATION, not which entry point a site reached).
func (l *categoryRecordLimiter) admitRefusal(category refusalCategory) bucketVerdict {
	return l.admitWithFloor(category, l.floor.forKey(category))
}

// admitRefusalRecord applies limiter's verdict for category to rec: nil when this record is
// suppressed (the refusal itself still stands — only the tape write is bounded), rec when nothing
// was elided since the last admitted one, and a rollup-stamping wrapper when something was.
//
// The tail every site that RESOLVES a limited recorder shares, so a new one cannot forget the
// rollup and silently under-count a flood. (recordRefusal takes the same admission and writes its
// record directly, since it folds the rollup into details it is already building.)
// A nil limiter panics here exactly as it did at each of those sites: a live
// sink with no bucket beside it is a construction bug, and a "defensive" fallback would write the
// unbounded records the bucket exists to prevent. A caller that legitimately has none (a proxy
// assembled by a bare struct literal in a test) tests for it and does not call.
func admitRefusalRecord(rec auditRecorder, limiter *categoryRecordLimiter, category refusalCategory) auditRecorder {
	if rec == nil {
		// Nothing to write, so nothing to bound: leave the bucket's tokens for a site that has a
		// tape. Also the only guard against wrapping a nil recorder in rolledUpRecorder, which is a
		// NON-nil interface — every `rec != nil` test downstream would pass and the rollup's
		// delegation would nil-deref on a goroutine nothing recovers.
		return nil
	}
	verdict := limiter.admitRefusal(category)
	switch {
	case !verdict.ok:
		return nil
	case verdict.suppressed == 0 && !verdict.reserved:
		return rec
	default:
		// scope comes from the verdict rather than from limiter, because the two disagree for
		// exactly the delegated category: the count is the PARENT's and a table's own label would
		// stamp a proxy-wide tally as spanning one session.
		return rolledUpRecorder{auditRecorder: rec, floored: verdict.reserved, suppressed: verdict.suppressed, scope: verdict.scope}
	}
}

// Rollup keys carried by a refusal record, and the scope values that qualify the count.
//
// The scope is self-describing because the record it rides on isn't: most pre-session
// refusals are written unstamped through the proxy-wide sink, but a session-cap refusal is
// route-stamped, so a proxy-wide tally folded into a route-stamped record would otherwise
// read as thousands of that route's own saturation refusals.
//
// The key is `suppressed_refusal_count` rather than the `suppressed_count` a `*/list`
// ALLOW record already uses for an unrelated statistic (policy-filtered catalog entries) —
// naming it distinctly keeps a query on the bare key from conflating routine filtering
// with an unauthenticated refusal flood.
const (
	detailSuppressedRefusalCount = "suppressed_refusal_count"
	detailSuppressedRefusalScope = "suppressed_refusal_scope"
	// suppressedScopeProxyCategory qualifies the pre-session rollup: it spans every ROUTE
	// but only this record's own refusal category. Changed from the earlier "proxy" when
	// the bucket split by category — the old value would now under-state its precision.
	suppressedScopeProxyCategory = "proxy_category"
	// suppressedScopeSessionCategory qualifies a rollup from a table held PER SESSION (the
	// upstream-driven categories): this session, this category. A per-session tally stamped
	// with the proxy-wide value would tell a reader that a count of 5000 spans every route
	// when it describes one session's upstream — the same misreading the route stamp caused
	// before the scope was recorded at all, one dimension out.
	suppressedScopeSessionCategory = "session_category"
	// detailRefusalFloored marks a record that exists only because its holder's reserve delivered
	// it. Distinct from the count beside it: the count says how many writes the reader did not
	// see under this key, while this says the tier had room for none of them and this one is the
	// holder's guaranteed arrival.
	detailRefusalFloored = "refusal_record_floored"
)

// recordRateLimiter is a token bucket over one CLASS of caller-driven audit refusal
// record, rolling a suppressed write into the next admitted record instead of losing it.
// Zero value unusable; construct with newRecordRateLimiter.
//
// Each class holds its own instance: a shared bucket would let a flood of one refusal
// silence another (e.g. eliding the AUTH_FAILED/ORIGIN_REJECTED records an incident
// responder reads first), and would make suppressed_refusal_count an unrelated tally.
type recordRateLimiter struct {
	mu         sync.Mutex
	tokens     float64
	last       time.Time
	suppressed uint64
	ratePerSec float64
	burst      float64
	now        func() time.Time // injectable for tests
}

func newRecordRateLimiter(ratePerSec, burst float64) *recordRateLimiter {
	return &recordRateLimiter{tokens: burst, ratePerSec: ratePerSec, burst: burst, now: time.Now}
}

// admit reports whether a refusal record may be written now, how many records were suppressed
// since the last admitted one (0 when none were), and the instant it sampled.
//
// The instant is returned rather than re-read by a caller that needs one: a holder's floor is
// consulted on exactly the refusals this decides (see reserveSlot.claim), and re-sampling would
// both add a clock read per refused frame on the flood path this bucket exists for and let the
// floor's interval be measured against a different instant than the refill that refused it.
func (l *recordRateLimiter) admit() (ok bool, suppressed uint64, at time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if l.last.IsZero() {
		l.last = now
	}
	// Refill, clamped to burst. A backwards clock step yields non-positive elapsed and
	// adds nothing, which is the safe direction.
	if elapsed := now.Sub(l.last).Seconds(); elapsed > 0 {
		l.last = now
		l.tokens += elapsed * l.ratePerSec
		if l.tokens > l.burst {
			l.tokens = l.burst
		}
	}
	if l.tokens < 1 {
		l.suppressed++
		return false, 0, now
	}
	l.tokens--
	suppressed, l.suppressed = l.suppressed, 0
	return true, suppressed, now
}

// suppress counts a refusal elided by an OUTER gate that never reached admit (spends no
// token), keeping the rollup complete regardless of which layer did the eliding.
func (l *recordRateLimiter) suppress() { l.suppressN(1) }

// suppressN returns n refusals to this bucket's tally, for a record this bucket ADMITTED that an
// outer tier then refused. The token it spent is deliberately not returned: the outer tier's
// refusal is what bounds the rate, and refunding here would let a saturated aggregate hand this
// bucket unlimited retries.
func (l *recordRateLimiter) suppressN(n uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.suppressed += n
}

// borrow charges this bucket for a write it REFUSED that a holder's floor delivered anyway (see
// admitWithFloor). The write happened, so it comes off the suppression tally — the rollup states
// what the reader did not see — and the bucket goes one token into DEBT for it.
//
// The debt is what keeps a floor from being free. Repaid by the next refill, it leaves the tier's
// long-run rate exactly where the operator set it: a floored arrival displaces the flooder's next
// line instead of adding to the total, which is the reallocation the floor is for. Clamped at one
// burst, because enough holders flooring against one bucket would otherwise drive the debt
// arbitrarily negative and stop the tier's ordinary writes for good.
//
// Best-effort in exactly one direction, and only under concurrency: if another goroutine's admit
// harvested the tally between this bucket's refusal and this call, the decrement finds nothing to
// take and that line stands counted as unseen on the other goroutine's rollup. The counter is
// unsigned, so the alternative to the guard is a wrap — over-stating by one beats under-stating by
// 2^64.
func (l *recordRateLimiter) borrow() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.borrowLocked()
}

func (l *recordRateLimiter) borrowLocked() {
	// The POST-decrement balance is what the clamp is about: testing the pre-decrement one admits a
	// bucket sitting just above the floor and lands it a whole token below, so the tier needs
	// (burst+1)/rate rather than burst/rate seconds to resume ordinary writes.
	if l.tokens-1 >= -l.burst {
		l.tokens--
	}
	if l.suppressed > 0 {
		l.suppressed--
	}
}

// deliveredAnyway is borrow plus the harvest: what remains of the tally is handed to the caller to
// report on the line it is writing. One critical section, because a decrement and a harvest as two
// calls can interleave with a concurrent admit and either lose the remainder or double-count it.
func (l *recordRateLimiter) deliveredAnyway() (remaining uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.borrowLocked()
	remaining, l.suppressed = l.suppressed, 0
	return remaining
}

// A saturation refusal needs a far smaller sustained rate than a pre-session one: it's
// written once per EPISODE (see saturationGate), so steady state is zero and even a real
// incident produces a handful of records. 5/s bounds a flip-flop (saturate/drain/re-
// saturate) pattern that would otherwise open unbounded episodes per second.
const (
	saturationRecordRatePerSec = 5
	saturationRecordBurst      = 20
)

// saturationGate is the admission control over ONE concurrency pool's RESOURCE_EXHAUSTED
// records: the stdio host-handler pool, or an HTTP session's request or notification pool.
// Zero value usable and is how every pool holds one, lazily initialized like the
// semaphores it guards.
//
// Two layers: episode collapsing (primary) records the first refusal after the pool last
// had a free slot; every further refusal in that episode folds into
// suppressed_refusal_count until a successful acquire (clear) reopens it — an operator
// wants to know the pool saturated, not to count every refused frame. A token bucket
// underneath (backstop) bounds the sustained rate even against a caller cycling
// saturate/drain/re-saturate as fast as the pool drains.
//
// Scope is per pool, per SESSION — not proxy-wide — so one session's flood cannot elide
// another's genuine saturation record. Unlike a pre-session refusal (free to an
// unauthenticated caller), saturating a pool costs an established session at full
// per-pool capacity, so N sessions writing at the per-pool rate is the right shape.
type saturationGate struct {
	// mu makes the check-bucket-then-latch sequence in admit() one critical section with
	// clear()'s reset — a lock-free atomic.Bool cannot provide that (see admit's doc).
	mu       sync.Mutex
	recorded bool

	once    sync.Once
	limiter *recordRateLimiter
}

// bucket returns the gate's token bucket, creating it on first use so a zero-value gate is
// still rate-bounded.
func (g *saturationGate) bucket() *recordRateLimiter {
	g.once.Do(func() { g.limiter = newRecordRateLimiter(saturationRecordRatePerSec, saturationRecordBurst) })
	return g.limiter
}

// admit reports whether this refusal may be written as a record, and if so how many
// refusals were elided since the last admitted one.
//
// The episode-open check, the bucket call, and the latch are one critical section under
// g.mu rather than three independently-atomic steps, closing two bugs a prior lock-free
// (bare CompareAndSwap on atomic.Bool) version had: (1) latching before knowing the bucket
// admits would strand a continuous saturation at ZERO records if the leading edge got
// bucket-declined, since only clear() (fired by a successful acquire) can reopen it —
// latching only AFTER a successful bucket.admit() lets the next refusal retry instead of
// being silently swallowed. (2) an unsynchronized clear() (Load-then-Store) can race a
// DIFFERENT goroutine's admit() that just opened a new episode, splitting one continuous
// saturation into two-plus records.
func (g *saturationGate) admit() (ok bool, suppressed uint64) {
	bucket := g.bucket()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.recorded {
		bucket.suppress()
		return false, 0
	}
	// Leading edge of a (possibly new) episode: latch only once the bucket actually
	// admits a record for it (see point 1 above).
	ok, suppressed, _ = bucket.admit()
	if ok {
		g.recorded = true
	}
	return ok, suppressed
}

// clear ends the current saturation episode: the pool just handed out a slot, so the next
// refusal is a new episode and is recorded again. Called from every successful acquire;
// locked for the same mutual-exclusion reason as admit.
func (g *saturationGate) clear() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.recorded = false
}

// nilInterface reports whether v holds no value at all — the interface itself nil, or a typed nil
// inside a non-nil interface. The ONE answer in this package to a question three call sites now ask
// (a diagnostic seam's subsystem, a server-initiated leg's sink), because `x == nil` compares the
// INTERFACE and passes for an interface holding a nil pointer, whose method then dereferences a nil
// receiver.
//
// Reflection rather than a type switch, for redisutil.IsNilClient's reason one layer down: a list of
// concrete types is a second thing to keep in agreement, and nilness is one question for every type
// including one nobody has written yet. IsNil PANICS on any other kind, so the kinds are named
// rather than tried — a guard must not become the crash it prevents. Interface is in the list for
// completeness even though reflect.ValueOf unwraps to the dynamic type and never yields it.
//
// It answers for a value that IS nil, never for a wrapper AROUND one: reflecting into an embedded
// field would refuse decorators that legitimately forward elsewhere.
func nilInterface(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.UnsafePointer:
		return rv.IsNil()
	default:
		return false
	}
}
