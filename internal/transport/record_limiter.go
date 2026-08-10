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
	"slices"
	"sync"
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
// Shared by both divided tables in this package (refusal categories, notice classes): the
// derivation is the same one, and a second copy is a second place for the floor to be forgotten.
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
	return &categoryRecordLimiter{tieredBuckets: newTieredBuckets(
		perCategoryDenyRate, perCategoryDenyBurst, cats, nil, suppressedScopeProxyCategory)}
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
// delegated WHOLLY to the aggregate parent (see tieredBuckets.admit) — the proxy-wide bound those
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
	return &categoryRecordLimiter{tieredBuckets: newTieredBuckets(
		perCategoryDenyRate, perCategoryDenyBurst, cats, parent, suppressedScopeSessionCategory)}
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
}

// newTieredBuckets builds one bucket per key at the given rate/burst, under parent (nil for an
// aggregate), labelling its own rollups with scope.
//
// parent is a constructor parameter rather than a field a caller sets afterwards, because whether
// this table needs the floor-rate fallback is decided by it: a parented table delegates an
// unregistered key upward and can never reach one.
func newTieredBuckets[K comparable](ratePerSec, burst float64, keys []K, parent *tieredBuckets[K], scope string) tieredBuckets[K] {
	t := tieredBuckets[K]{
		buckets: make(map[K]*recordRateLimiter, len(keys)),
		parent:  parent,
		scope:   scope,
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
}

// keyFloor is a per-holder reserve consulted when a tiered table's own bucket has nothing left for
// key — one guaranteed write, held by something SMALLER than the table's own tenant (see
// noticeReserve). An interface rather than a func so passing one costs no closure on the flood path
// the bucket exists for, and so a nil holder answers for itself.
type keyFloor[K comparable] interface {
	take(K) bool
}

// admit reports whether a write under key may happen now, how many writes UNDER THAT KEY were
// suppressed since the last admitted one, and which tier's scope that count spans.
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
func (t *tieredBuckets[K]) admit(key K) bucketVerdict {
	return t.admitWithFloor(key, nil)
}

// admitWithFloor is admit with an optional per-holder FLOOR, consulted at exactly one point: this
// table's OWN bucket had nothing left, which is the only refusal attributable to contention among
// the holders that share this tier.
//
// A refusal from a tier ABOVE is deliberately not floored. It means the aggregate is at the ceiling
// an operator configured, where an extra write is least appropriate — and the floor could not be
// claimed honestly there anyway: the own bucket has already spent a token, both tiers have counted
// the write, and this table's scope is not the one that refused. Claiming it there burned a holder's
// one-per-key reserve for pressure it cannot influence, which is the cross-tenant elision the tiers
// exist to stop, one level up.
//
// A floored write takes the accumulated tally WITH it (deliveredAnyway) rather than leaving it for
// the next admitted write: under a sustained flood the floored line is the next line the reader
// actually sees, so a count left behind is a count reported after the incident or not at all.
func (t *tieredBuckets[K]) admitWithFloor(key K, floor keyFloor[K]) bucketVerdict {
	own, registered := t.buckets[key]
	if t.parent != nil && !registered {
		return t.parent.admitWithFloor(key, floor)
	}
	if !registered {
		own = t.unknown
	}
	ok, suppressed := own.admit()
	if !ok {
		if floor == nil || !floor.take(key) {
			return bucketVerdict{scope: t.scope}
		}
		return bucketVerdict{ok: true, suppressed: own.deliveredAnyway(), scope: t.scope, reserved: true}
	}
	if t.parent == nil {
		return bucketVerdict{ok: true, suppressed: suppressed, scope: t.scope}
	}
	if parent := t.parent.admitWithFloor(key, nil); !parent.ok {
		// The aggregate refused, so this write does not happen; give this table back the token's
		// worth of tally (this one plus everything it had accumulated) so the next admitted
		// one still states the true count. The parent's own tally is deliberately discarded: the
		// same writes are already counted here, and counting them twice would over-state a flood.
		own.suppressN(suppressed + 1)
		return bucketVerdict{scope: t.scope}
	}
	return bucketVerdict{ok: true, suppressed: suppressed, scope: t.scope}
}

// bucket returns the token bucket key actually charges — this table's own, or the parent's for a
// key delegated wholly upward. No lock: the table is immutable after construction.
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
}

// admitRefusalRecord applies limiter's verdict for category to rec: nil when this record is
// suppressed (the refusal itself still stands — only the tape write is bounded), rec when nothing
// was elided since the last admitted one, and a rollup-stamping wrapper when something was.
//
// The tail every site that RESOLVES a limited recorder shares, so a new one cannot forget the
// rollup and silently under-count a flood. (recordRefusal writes its record directly and folds
// the rollup into its own details, so it charges the bucket itself rather than through this.)
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
	verdict := limiter.admit(category)
	switch {
	case !verdict.ok:
		return nil
	case verdict.suppressed == 0:
		return rec
	default:
		// scope comes from the verdict rather than from limiter, because the two disagree for
		// exactly the delegated category: the count is the PARENT's and a table's own label would
		// stamp a proxy-wide tally as spanning one session.
		return rolledUpRecorder{auditRecorder: rec, suppressed: verdict.suppressed, scope: verdict.scope}
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

// admit reports whether a refusal record may be written now, and if so how many records
// were suppressed since the last admitted one (0 when none were).
func (l *recordRateLimiter) admit() (ok bool, suppressed uint64) {
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
		return false, 0
	}
	l.tokens--
	suppressed, l.suppressed = l.suppressed, 0
	return true, suppressed
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

// deliveredAnyway resolves the tally for a write this bucket just REFUSED that a floor above it is
// about to deliver (see admitWithFloor): the refused write comes back off the count, since the
// rollup states what the reader did not see, and what remains is handed to the caller to report on
// the line it is writing. One critical section, because a decrement and a harvest as two calls can
// interleave with a concurrent admit and either lose the remainder or double-count it.
//
// Best-effort in exactly one direction, and only under concurrency: if another goroutine's admit
// harvested the tally between this bucket's refusal and this call, the decrement finds nothing to
// take and that line stands counted as unseen on the other goroutine's rollup. The counter is
// unsigned, so the alternative to the guard is a wrap — over-stating by one beats under-stating by
// 2^64, and no token is spent either way: the floor is a bypass of this bucket, not a draw on it.
func (l *recordRateLimiter) deliveredAnyway() (remaining uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.suppressed > 0 {
		l.suppressed--
	}
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
	ok, suppressed = bucket.admit()
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
