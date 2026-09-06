// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Admission control over the audit records a REFUSAL writes.
//
// A refusal an unauthenticated peer can drive at its send rate is an unbounded audit-write rate: on
// a strict-audit deployment that is enough to latch AuditDegraded() and deny every route, so the
// records the cheapest refusals produce are metered. Each category holds its own token bucket — a
// shared one would let a flood of one refusal silence another, eliding the AUTH_FAILED and
// ORIGIN_REJECTED records an incident responder reads first — and a suppressed write folds into the
// next admitted record of that category as suppressed_refusal_count rather than being lost.
//
// Two categories are declared EXEMPT and write unmetered: a policy verdict may never be
// admission-controlled, and both are reachable only by a peer whose ordinary traffic already writes
// policy DENY records at the same one-per-message cost.
//
// The buckets are proxy-wide. One session's dead upstream can therefore spend a category's budget
// its siblings share; that is an accepted trade against the per-session tier, aggregate parent,
// tally push-back and holder floors that closed it, which cost several times this file in machinery
// to reallocate writes the suppression count already accounts for.

package transport

import (
	"slices"
	"sync"
	"time"
)

const (
	perCategoryDenyRatePerSec = 2
	perCategoryDenyBurstSize  = 5
)

// refusalCategory is a distinct type (not a bare string) because a category's value is the
// rate-limit bucket key, and on the PRE-SESSION leg it doubles as the audit record's structured
// condition_type field (recordRefusal writes it there). The server-request categories below do
// not: their records go through recordServerRequestDropped, which leaves condition_type empty and
// names the site in details.transport instead — so a value's spelling is load-bearing on the tape
// for some of this set and only for the bucket for the rest.
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
	// catAudience bounds the PRE-SESSION per-route audience-pin refusal. A caller holding one
	// valid token for any SIBLING route's audience reaches this on every route whose audience it
	// fails, with no session or upstream ever spawned — the same cheap-flood shape catKill exists
	// to bound, one credential away rather than zero.
	catAudience refusalCategory = "audience"
	// catRevision bounds the protocol-revision refusal (-32022). It is the cheapest refusal the
	// proxy can be made to write: a small body carrying a bogus `_meta` protocol version, refused
	// before the kill check, holding no slot and contacting no upstream.
	//
	// The one category BOTH transports meter. Its threat model is the HTTP proxy's unauthenticated
	// peer, which stdio does not have — but the refusal is the same refusal for the same bytes, and
	// on stdio it is written inline on the serve loop, the goroutine that also routes host replies
	// back to a blocked upstream. Metering it there costs the tape nothing and keeps identical
	// bytes treated identically on the two transports.
	catRevision refusalCategory = "revision"
	// catHeaderMismatch bounds the 2026-07-28 routing-header refusal (-32020). Metered for
	// catRevision's reason and at the same cheapness: a POST with a disagreeing `Mcp-Method` is
	// refused at the envelope, before the kill check, holding no session slot.
	catHeaderMismatch refusalCategory = "header_mismatch"
	// catUnservable bounds the refusal for a peer whose revision this build SPEAKS but cannot serve
	// on this transport — a 2026-07-28 host's sessionless POST, which negotiates fine and then finds
	// no session and no way to create one.
	catUnservable refusalCategory = "unservable_revision"
	// catSessionGate bounds the per-session gate refusals — the audience pin and the owner binding —
	// on an already-resolved session. Metered because session creation on the first enforced request
	// makes a declaring peer's worker id DERIVABLE from its own claims, so any caller who can name a
	// victim's issuer, subject and agent id can address that worker and drive one audit record per
	// attempt with no session of its own.
	catSessionGate refusalCategory = "session_gate"
	// catUnroutable and catSmuggled are the two DECLARED-EXEMPT categories: they name a
	// refusal so its non-metering is an answer on the record rather than an absent call. See
	// exemptRefusals for the reason, which is the same for both.
	catUnroutable refusalCategory = "unroutable"
	catSmuggled   refusalCategory = "smuggled_notification"
	// catServerRequestFailed bounds the records for a server-initiated request this proxy had
	// already TRACKED and then delivered, and then failed: the correction appended when a buffered
	// request never reached the host, and a host reply destroyed because there was no upstream sink
	// to relay it through. Driven by the upstream — nothing caps how many such requests an upstream
	// issues over a session's life.
	catServerRequestFailed refusalCategory = "failed_server_request"
	// catUndeliveredForward bounds the deny for a server-initiated request no client accepted at
	// all. Its own bucket, not catServerRequestFailed's: this needs no host at any point and an
	// upstream drives one per request, while catServerRequestFailed's writers each need a request
	// that was TRACKED and taken — so sharing let the cheaper flood suppress the correction that
	// repairs a standing ALLOW.
	catUndeliveredForward refusalCategory = "undelivered_server_request"
	// catUnroutableID bounds the record for a server-initiated request eunox refuses because its
	// own JSON-RPC id is larger than the in-flight tracker retains. Its own bucket, not
	// catDisplaced's: a displacement needs the bounded set full or an id collision, an over-cap id
	// needs neither.
	catUnroutableID refusalCategory = "unroutable_server_request_id"
	// catDisplaced bounds the record for a server-initiated request the in-flight tracker
	// displaced. Driven by the UPSTREAM: once the bounded set is full every further request
	// displaces one.
	catDisplaced refusalCategory = "displaced_server_request"
	// catRefusalUndeliverable bounds the record for a REFUSED server-initiated request whose answer
	// never reached its initiator. Its own bucket for catUnroutableID's reason: an upstream with a
	// broken stdin drives one per request.
	catRefusalUndeliverable refusalCategory = "undeliverable_server_refusal"
	// catUntranslatableServerRequest bounds the record for a server-initiated request refused at the
	// translation boundary — an upstream aimed one at a host whose revision removed the mechanism.
	// Driven by the UPSTREAM alone: once such a session is up, EVERY server-initiated request it
	// issues takes that arm, at its own send rate, with no host cooperation and no tracking, which is
	// the axis catUndeliveredForward and catServerRequestFailed's writers are metered on.
	//
	// Its own bucket rather than the catRevision the host-side spelling of this same code charges:
	// that one bounds a HOST peer's revision refusal — the record saying someone is probing the
	// negotiated surface — and sharing would let an upstream flood elide it, which is the reason
	// catUndeliveredForward does not share catServerRequestFailed's.
	catUntranslatableServerRequest refusalCategory = "untranslatable_server_request"
)

// exemptBecausePolicyDenyCostsTheSame is the one reason both exemptions rest on.
const exemptBecausePolicyDenyCostsTheSame = "reaching it needs a peer whose ordinary traffic writes policy DENY records at the same one-per-message cost, and a policy verdict may never be metered"

// exemptRefusals names the categories that write unmetered, with the reason. Membership IS the
// declaration: a category absent here is metered, which is the bounded direction for one added
// without an answer.
var exemptRefusals = map[refusalCategory]string{
	catUnroutable: exemptBecausePolicyDenyCostsTheSame,
	catSmuggled:   exemptBecausePolicyDenyCostsTheSame,
}

// allRefusalCategories is every category this package can charge, exempt ones included. One list,
// from which the metered set is derived — so a category cannot be added to a vocabulary and missed
// by the table sized from it.
var allRefusalCategories = []refusalCategory{
	catOrigin, catJWT, catAuth, catControl, catLoopback, catBody, catContentType,
	catSaturation, catKill, catAudience, catRevision, catHeaderMismatch, catUnservable,
	catSessionGate, catUnroutable, catSmuggled, catServerRequestFailed,
	catUndeliveredForward, catUnroutableID, catDisplaced, catRefusalUndeliverable,
	catUntranslatableServerRequest,
}

// refusalCategories is the metered set the proxy-wide bucket table is keyed by.
var refusalCategories = meteredRefusalCategories()

func meteredRefusalCategories() []refusalCategory {
	out := make([]refusalCategory, 0, len(allRefusalCategories))
	for _, cat := range allRefusalCategories {
		if _, exempt := exemptRefusals[cat]; !exempt {
			out = append(out, cat)
		}
	}
	slices.Sort(out)
	return out
}

// perBucketFloor is the rate and burst of the fallback bucket an unregistered key falls to: one
// record per second. A key nothing declared is a key nobody has reasoned about, so it gets the
// bounded answer rather than a real category's share.
const perBucketFloor = 1

// stdioRefusalCategories is the set the stdio transport can charge, declared here rather than
// re-derived from its call sites so the limiter it builds and the categories it spends are one
// statement — and so a metered refusal added to that transport is a deliberate edit here.
//
// catDisplaced and its three neighbours reach stdio through trackServerRequest, a shared helper
// both transports hand their own limiter to, so they live in neither transport's file.
// catUntranslatableServerRequest reaches it the same way, through forwardServerRequest: a stdio
// host pins 2026-07-28 like any other, and its subprocess upstream then has every server-initiated
// request it issues refused at the boundary. catUndeliveredForward arrives through that same core,
// for a request the host writer failed the frame of — a whole-frame stdout failure poisons nothing
// and so tears nothing down, which is what makes it repeatable at the upstream's own rate.
var stdioRefusalCategories = []refusalCategory{
	catRevision, catDisplaced, catUnroutableID, catServerRequestFailed, catRefusalUndeliverable,
	catUntranslatableServerRequest, catUndeliveredForward,
}

// newRefusalRecordLimiter builds the proxy-wide table: a bucket for every metered category.
func newRefusalRecordLimiter() *categoryRecordLimiter {
	return newRefusalRecordLimiterFor(refusalCategories)
}

// newRefusalRecordLimiterFor builds a table holding buckets for cats alone. A category outside cats
// falls to the floor-rate fallback, which is the bounded direction.
func newRefusalRecordLimiterFor(cats []refusalCategory) *categoryRecordLimiter {
	buckets := make(map[refusalCategory]*recordRateLimiter, len(cats))
	for _, cat := range cats {
		buckets[cat] = newRecordRateLimiter(perCategoryDenyRatePerSec, perCategoryDenyBurstSize)
	}
	return &categoryRecordLimiter{buckets: buckets, fallback: newRecordRateLimiter(perBucketFloor, perBucketFloor)}
}

// categoryRecordLimiter is one token bucket per refusal category, plus a floor-rate fallback for a
// category with no bucket of its own.
type categoryRecordLimiter struct {
	buckets  map[refusalCategory]*recordRateLimiter
	fallback *recordRateLimiter
}

// bucket resolves a category's bucket, falling back to the floor-rate one.
func (l *categoryRecordLimiter) bucket(category refusalCategory) *recordRateLimiter {
	if b, ok := l.buckets[category]; ok {
		return b
	}
	return l.fallback
}

// setNow overrides the clock on every bucket, for tests that drive the refill deterministically.
func (l *categoryRecordLimiter) setNow(now func() time.Time) {
	for _, b := range l.buckets {
		b.setNow(now)
	}
	l.fallback.setNow(now)
}

// admitRefusal is the ONE admission a refusal RECORD is written under, on either spelling of the
// write. It applies the category's DECLARATION here rather than at each entry point: an exempt
// category holds no bucket, so reading the exemption only where a recorder is resolved left the
// other spelling falling to the floor-rate fallback and throttling an exempt refusal HARDER than a
// metered one — the exact inversion of what the declaration says, under the very flood the
// exemption exists for.
func (l *categoryRecordLimiter) admitRefusal(category refusalCategory) (ok bool, suppressed uint64) {
	if _, exempt := exemptRefusals[category]; exempt {
		return true, 0
	}
	return l.bucket(category).admit()
}

// refusalLimits is a transport leg's admission control over the two halves of a refusal.
type refusalLimits struct {
	// records bounds the refusal RECORDS this leg's categories declare metered. nil on a leg that
	// meters none of them: stdio's notification gate, and the established-session HTTP arm, whose
	// kill records describe an already-admitted caller and are deliberately unbounded.
	records *categoryRecordLimiter
	// notices is this leg's diagnostic CHANNEL — where a line goes and what bounds it, as one
	// value. Separate from records because the two answer to different arguments and a leg can
	// legitimately want one without the other: the established-session arm above meters no record
	// it writes and still owes a bound on a per-frame syscall.
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
// exemption on the record spent a catKill token anyway.
type refusalRecorders struct {
	// rec is the leg's audit sink, or nil when it has none.
	rec auditRecorder
	// limits is a NAMED field rather than an embedded one. Embedding promoted recorders() onto
	// this type, so `recs.recorders(otherSink)` compiled on an already-resolved wiring and minted
	// one keeping this leg's buckets while pointing at a DIFFERENT tape. forCategory being the one
	// resolver governs which bucket a record charges, never which tape it lands on.
	limits refusalLimits
}

// forCategory is the ONE resolver: every refusal record's recorder comes from here, so no producer
// has an entry point the declaration does not govern.
func (r refusalRecorders) forCategory(category refusalCategory) auditRecorder {
	if r.rec == nil || r.limits.records == nil {
		return r.rec
	}
	return admitRefusalRecord(r.rec, r.limits.records, category)
}

// notices is this wiring's diagnostic channel, reached through the named limits field so a
// caller needs no second vocabulary for the half of a refusal that is not a record.
func (r refusalRecorders) notices() noticeWriter { return r.limits.notices }

// admitRefusalRecord applies limiter's verdict for category to rec: nil when this record is
// suppressed (the refusal itself still stands — only the tape write is bounded), rec when nothing
// was elided since the last admitted one, and a rollup-stamping wrapper when something was.
//
// A nil limiter is NOT guarded here, and deliberately not claimed to be: forCategory returns the
// plain sink before reaching this call, so the panic an earlier doc promised was never reachable
// (see preSessionRefusalRecorders, which states the same). What keeps a live sink from writing
// unbounded kill records is that every production constructor builds the table.
func admitRefusalRecord(rec auditRecorder, limiter *categoryRecordLimiter, category refusalCategory) auditRecorder {
	if rec == nil {
		// Nothing to write, so nothing to bound: leave the bucket's tokens for a site that has a
		// tape. Also the only guard against wrapping a nil recorder in rolledUpRecorder, which is a
		// NON-nil interface — every `rec != nil` test downstream would pass and the rollup's
		// delegation would nil-deref on a goroutine nothing recovers.
		return nil
	}
	ok, suppressed := limiter.admitRefusal(category)
	switch {
	case !ok:
		return nil
	case suppressed == 0:
		return rec
	default:
		return rolledUpRecorder{auditRecorder: rec, suppressed: suppressed}
	}
}

// Rollup keys carried by a refusal record, and the scope value that qualifies the count.
//
// The key is `suppressed_refusal_count` rather than the `suppressed_count` a `*/list`
// ALLOW record already uses for an unrelated statistic (policy-filtered catalog entries) —
// naming it distinctly keeps a query on the bare key from conflating routine filtering
// with an unauthenticated refusal flood.
const (
	detailSuppressedRefusalCount = "suppressed_refusal_count"
	detailSuppressedRefusalScope = "suppressed_refusal_scope"
	// suppressedScopeProxyCategory qualifies the rollup: it spans every ROUTE but only this
	// record's own refusal category.
	suppressedScopeProxyCategory = "proxy_category"
)

// recordRateLimiter is a token bucket over one CLASS of caller-driven audit refusal
// record, rolling a suppressed write into the next admitted record instead of losing it.
// Zero value unusable; construct with newRecordRateLimiter.
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

// setNow overrides this bucket's clock. Tests only.
func (l *recordRateLimiter) setNow(now func() time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.now = now
}

// admit reports whether a refusal record may be written now, and how many records were suppressed
// since the last admitted one (0 when none were).
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
func (l *recordRateLimiter) suppress() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.suppressed++
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
// records: the stdio host-handler pool, an HTTP session's request or notification pool, or a
// server-initiated request pool (proxy-wide on stdio, per session on HTTP).
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
