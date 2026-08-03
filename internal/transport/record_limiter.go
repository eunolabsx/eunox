// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Admission control over the audit records whose write rate a caller — rather than the
// policy — sets: the transport-level refusals an unauthenticated caller triggers
// (recordRateLimiter, instantiated as the pre-session bucket) and the concurrency-pool
// saturation refusals an established session triggers (saturationGate). No POLICY
// decision record is ever admission-controlled; only refusals, whose rate is the
// caller's to choose.

package transport

import (
	"sync"
	"time"
)

// Pre-session denial records are the audit writes an UNAUTHENTICATED caller can trigger,
// so they are the ones whose rate an attacker sets at zero cost. They are bounded by a
// token bucket rather than written one-per-refusal. Two kinds reach that description: the
// transport-level refusals (rejected Origin/JWT/bearer/control token, a bad body or
// content type, a full session table) and the kill-switch records the pre-session legs
// write while a kill is active (catKill). Both are charged here; nothing else is.
//
// Without a bound the refusal record is a lever on the proxy's own availability: the audit
// queue is finite and its drop counter is monotonic, so one drop latches AuditDegraded()
// for the process lifetime, and under the default --require-audit=strict every enforced
// call on every route is then denied AUDIT_UNAVAILABLE. A remote attacker with no
// credential could take the data plane down by spraying wrong bearer tokens. The flood also
// buries genuine policy denials: at the default rotate size a few thousand records/second
// cycles the retention window in minutes.
//
// The bucket keeps the evidence the record exists for — the first refusals in a burst are
// written in full, and the next admitted record carries suppressed_refusal_count, so an
// operator sees both that an attack happened and its scale — while capping the sustained
// write rate at something the drainer absorbs. The counters are global rather than
// per-source on purpose: per-source state is itself attacker-sized memory, and the
// suppressed count already tells the operator how much was elided.
//
// The pre-session bucket is one bucket per refusal CATEGORY, proxy-wide within each.
//
// Not one per route: that would multiply the rate an attacker can drive by the size of the
// route table, re-opening the flood from the direction the per-source-memory argument above
// closes. But not one for everything either, which is what it used to be. Categories differ
// enormously in what it costs an attacker to trigger them and in what their records are
// worth to an incident responder: an unauthenticated Origin probe is one cheap request, and
// under a single bucket a spray of them absorbed the entire budget — so a concurrent
// control-token brute force, the record an incident responder reads first, was suppressed
// into a number on somebody else's record. That is precisely the failure recordRateLimiter's
// own doc names ("a single shared bucket would let a flood of one refusal silence another")
// and holds for every OTHER class by giving each its own instance; the pre-session classes
// were the one place it did not hold internally.
//
// Per-category state is a fixed handful of counters — the categories are an ENUMERATED
// set of typed constants (refusalCategory), not free strings — so unlike per-source
// state it is not attacker-sized, and it cannot grow by accident. The same string is
// also the record's structured condition_type field, which the threat model and
// conformance doc describe as a closed enumeration; an untyped parameter let one typo
// at a new refusal site both mint a private full-budget bucket and write a bogus value
// into that field, with no compile error and nothing to catch it.
//
// The categories DIVIDE one aggregate budget rather than each replicating the
// pre-split proxy-wide one: preSessionDenyRatePerSec/preSessionDenyBurst are the
// TOTAL sustained rate and burst across every category combined (see
// perCategoryDenyRate/perCategoryDenyBurst), not each category's own. An earlier
// version gave every category the full pre-split rate, which raised the sustained
// ceiling an unauthenticated caller could drive from 20/s to ~160/s (8 categories x
// 20/s) with no measurement behind the new number — the same aggregate the bound
// was introduced to hold, moved without re-checking it. Dividing keeps the reachable
// aggregate AT OR UNDER that ceiling (integer division floors each share, so the sum
// across categories can land under the total when it does not divide evenly — the
// safe direction, never over) while KEEPING the property the split exists for: no
// category can silence another, because each still gets its own bucket and its own
// token supply, just a fair share of one budget instead of a full budget each.
//
// The tally still spans routes within a category, and a record reporting it may be
// route-stamped (recordSessionCapDeny writes RESOURCE_EXHAUSTED through the route's sink) —
// detailSuppressedRefusalScope states that outright rather than leaving it to inference.
// saturationGate below is scoped per pool per session, for the same
// one-flood-must-not-elide-another reason, and its own scope value says as much.
const (
	preSessionDenyRatePerSec = 20
	preSessionDenyBurst      = 50
)

// refusalCategory names one pre-session refusal class. It is a distinct type, and the
// constants below are its only values, because this string is used for two things at
// once: it keys the rate-limit bucket AND it is written to the audit record's structured
// condition_type field. The sibling `code` argument at every call site was already a
// named constant; this is the other half of that pair.
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
	// catKill bounds the kill-switch records the PRE-SESSION legs write — the
	// session-creating initialize under an active global kill, the sessionless
	// initialize notification, and any POST naming an unknown or killed session. Those
	// three fire for raw, unauthenticated requests, so on an open-posture deployment
	// (no authToken, no JWT) a caller spraying initialize POSTs while a kill is active
	// drove one signed record per request: the same audit-queue flood this file bounds
	// everywhere else, and the one the invariant above claimed was already covered.
	//
	// It bounds ONLY those legs. A kill record for a session this proxy established is
	// written unlimited — that caller held a session, the record is bounded by traffic
	// the proxy already admitted, and it is the record an operator most needs during an
	// emergency stop.
	catKill refusalCategory = "kill"
)

// refusalCategories is the authoritative list the bucket table is built from. A constant
// added above but omitted here would fall to the shared unknown bucket rather than
// getting its own; TestRefusalCategories_AllHaveTheirOwnBucket pins that they match.
var refusalCategories = []refusalCategory{
	catOrigin, catJWT, catAuth, catControl, catLoopback, catBody, catContentType, catSaturation, catKill,
}

// perCategoryFloor is the minimum share perCategoryShare ever returns. Plain integer
// division floors a share to 0 once the category count exceeds the total (e.g. past
// 20 categories at today's preSessionDenyRatePerSec=20) — and a rate of 0 never
// refills while a burst of 0 admits nothing, so every category's bucket would
// silently and permanently suppress every refusal record for the rest of the
// process's life the moment its initial (zero-sized) burst is "drained". The floor
// keeps every category a genuine, if small, token bucket instead of a dead one; it
// costs at most a few tokens of aggregate overshoot, never a total denial.
const perCategoryFloor = 1

// perCategoryShare divides total evenly across categories (see the const block
// above for why dividing, not replicating, is the fix), flooring at
// perCategoryFloor. Integer division, not float: it keeps each category's share a
// WHOLE token count (simpler to reason about and to test than a fractional bucket),
// at the cost of the sum landing at or slightly UNDER the aggregate rather than
// exactly on it when the category count does not divide evenly — the safe
// direction for an availability bound, and 20/50 over 8 categories (the count
// today) divides with a remainder either way.
func perCategoryShare(total, categories int) float64 {
	share := total / categories
	if share < perCategoryFloor {
		share = perCategoryFloor
	}
	return float64(share)
}

// perCategoryDenyRate and perCategoryDenyBurst are each REGISTERED category's share
// of the aggregate pre-session budget (preSessionDenyRatePerSec/preSessionDenyBurst;
// see perCategoryShare). The unknown fallback bucket (newPreSessionDenyLimiter) is
// deliberately NOT sized from these: it is unreachable in production (every call
// site passes a registered constant, pinned by
// TestRefusalCategories_AllHaveTheirOwnBucket), so treating it as a further category
// sharing the same budget would both overstate what an attacker can actually drive
// and understate each real category's share for no reason — it gets perCategoryFloor
// instead, enough to keep it a usable bucket if it is ever reached without
// participating in the division.
var (
	perCategoryDenyRate  = perCategoryShare(preSessionDenyRatePerSec, len(refusalCategories))
	perCategoryDenyBurst = perCategoryShare(preSessionDenyBurst, len(refusalCategories))
)

// newPreSessionDenyLimiter builds the per-category buckets over pre-session refusal
// records, each holding an equal share of the aggregate rate/burst (see
// perCategoryDenyRate/perCategoryDenyBurst) so the categories divide one budget
// rather than each replicating it.
func newPreSessionDenyLimiter() *categoryRecordLimiter {
	c := &categoryRecordLimiter{
		buckets: make(map[refusalCategory]*recordRateLimiter, len(refusalCategories)),
		unknown: newRecordRateLimiter(perCategoryFloor, perCategoryFloor),
	}
	for _, cat := range refusalCategories {
		c.buckets[cat] = newRecordRateLimiter(perCategoryDenyRate, perCategoryDenyBurst)
	}
	return c
}

// categoryRecordLimiter holds one recordRateLimiter per refusal category, so a flood of
// cheap refusals in one category cannot suppress the records of another.
//
// The table is built ONCE, at construction, from the enumerated category list — not
// lazily on first use. That is what lets admit run without a lock of its own: the map is
// read-only for the process lifetime, so a refusal takes exactly one mutex (its bucket's),
// as it did before the split, rather than serializing every refusing goroutine on a second
// proxy-global lock on the one path this file exists to keep cheap under attack. It also
// removes the lazy path's ordering trap, where a bucket created before a test set the
// clock silently kept the wall clock.
type categoryRecordLimiter struct {
	buckets map[refusalCategory]*recordRateLimiter
	// unknown serves a category not in the table. Unreachable from the call sites (all
	// pass constants) and bounded either way; it exists so an unregistered constant
	// degrades to a shared bucket rather than to no bound at all.
	unknown *recordRateLimiter
}

// admit reports whether a refusal record in category may be written now, and how many
// records IN THAT CATEGORY were suppressed since the last admitted one.
func (c *categoryRecordLimiter) admit(category refusalCategory) (ok bool, suppressed uint64) {
	return c.bucket(category).admit()
}

// bucket returns category's token bucket. No lock: the table is immutable after
// construction.
func (c *categoryRecordLimiter) bucket(category refusalCategory) *recordRateLimiter {
	if b, exists := c.buckets[category]; exists {
		return b
	}
	return c.unknown
}

// setNow points every bucket at an injectable clock. Test-facing, and a method rather
// than a settable field precisely because the buckets are separate token buckets: an
// assignment to a parent field could only ever reach some of them.
func (c *categoryRecordLimiter) setNow(now func() time.Time) {
	for _, b := range c.buckets {
		b.now = now
	}
	c.unknown.now = now
}

// The details keys a rolled-up refusal record carries, and the scope values that qualify the
// count.
//
// The count is deliberately SELF-DESCRIBING about its scope, because the record it rides on
// is not. Most pre-session refusals fire before route resolution and are written unstamped
// through the proxy-wide sink, but the session cap knows its route by the time it fires and is
// written through the route's sink — so a single admitted record can carry an `upstream` /
// `policy_version` / `policy_sha256` stamp while the proxy-wide tally folded into it counts
// refusals from every route and every category. A flood of bad bearer tokens against route A,
// whose next admitted record happens to be a session-cap refusal on route B, would otherwise
// read as thousands of saturation refusals against route B's policy digest — a SIEM rule or an
// operator keyed on route + code draws a conclusion the record's own stamp contradicts. Naming
// the scope removes the inference.
//
// The key is `suppressed_refusal_count` rather than a bare `suppressed_count` because that
// name is already taken, in the same `details` object, by an unrelated statistic: a `*/list`
// ALLOW record reports `suppressed_count` as the entries the manifest hid from the catalog.
// The two are disjoint by decision and method, but a query written against the bare key
// matches both — routine policy filtering and an unauthenticated refusal flood — which are
// opposite signals. Each now says what it counted.
const (
	detailSuppressedRefusalCount = "suppressed_refusal_count"
	detailSuppressedRefusalScope = "suppressed_refusal_scope"
	// suppressedScopeProxyCategory qualifies the pre-session buckets' rollup: the tally
	// spans every ROUTE but covers only this record's own refusal category, which is what
	// the per-category buckets made true. It is written directly at the one call site that
	// needs it (recordRefusal) rather than read off a field on the limiter — a per-scope
	// field would be generality with a single caller. saturationGate below is a
	// narrower-reach limiter, but a distinct type with its own scope constant, not a second
	// caller of this one.
	//
	// The value changed from the earlier "proxy" when the bucket was split by category:
	// under one shared bucket the count really did span categories, and a reader keyed on
	// the old value would now under-read the number's precision rather than over-read it.
	suppressedScopeProxyCategory = "proxy_category"
)

// recordRateLimiter is a token bucket over one CLASS of caller-driven audit refusal
// records, with a rollup counter so a suppressed write is folded into the next admitted
// record instead of vanishing. The zero value is not usable; construct with
// newRecordRateLimiter.
//
// Each class holds its own instance on purpose. A single shared bucket would let a flood
// of one refusal silence another — a notification-pool flood on one session eliding the
// AUTH_FAILED and ORIGIN_REJECTED records an incident responder reads first — and would
// make the suppressed_refusal_count stamped on any one record a tally of refusals it has
// nothing to do with, which is not a number an auditor can act on.
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
// were suppressed since the last admitted one (0 when none were). A suppressed refusal
// still increments the counter, so nothing is lost silently — it is folded into the next
// record that gets through.
func (l *recordRateLimiter) admit() (ok bool, suppressed uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if l.last.IsZero() {
		l.last = now
	}
	// Refill, clamped to the burst ceiling. A backwards clock step yields a non-positive
	// elapsed and simply adds nothing, which is the safe direction.
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

// suppress counts a refusal elided by an OUTER gate — one that never reached admit, so it
// spends no token — keeping the rollup complete whichever layer did the eliding. Without
// it, saturationGate's episode collapsing would drop its elided refusals off the tape
// entirely, which is the accounting hole the suppressed_refusal_count rollup exists to
// prevent.
func (l *recordRateLimiter) suppress() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.suppressed++
}

// A saturation refusal (RESOURCE_EXHAUSTED) needs a far smaller sustained rate than a
// pre-session refusal. It is written once per saturation EPISODE rather than once per
// refused request (see saturationGate), so on a healthy proxy the steady-state rate is
// zero and even a genuine incident produces a handful of records — a burst of 20 captures
// the leading edge of a real one, and 5/s bounds a flip-flop pattern (saturate, drain,
// re-saturate) that would otherwise open an unbounded number of episodes per second.
const (
	saturationRecordRatePerSec = 5
	saturationRecordBurst      = 20
)

// saturationGate is the admission control over ONE concurrency pool's RESOURCE_EXHAUSTED
// records: the stdio host-handler pool, or an HTTP session's request or notification pool.
// The zero value is usable and is how every pool holds one (lazily initialized, mirroring
// the semaphores it guards, so a directly constructed session/proxy still gets a real
// gate).
//
// Two layers, because the record's problem is not only its rate:
//
//   - Episode collapsing (the primary rule). An operator wants to know that a pool
//     saturated, not to count every frame refused while it stayed that way. The first
//     refusal after the pool last had a free slot is recorded; every further refusal in
//     that same episode is folded into suppressed_refusal_count, and a successful acquire
//     (clear) ends the episode so the next saturation records again. One record per episode
//     is the signal; the count is its magnitude.
//
//   - A token bucket underneath (the backstop). Collapsing alone is not a rate bound: a
//     caller that holds a pool exactly at capacity can cycle saturate/drain/re-saturate as
//     fast as the pool drains, opening a fresh episode each time. The bucket makes the
//     sustained record rate independent of how fast an attacker can cycle it.
//
// Scope is per pool, per session — NOT proxy-wide. A proxy-wide bucket would let one
// session's notification flood elide another session's genuine saturation record, the same
// cross-talk that makes a shared bucket the wrong home for these. The residual is that N
// sessions can each write at the per-pool rate, and that is the right shape here: unlike a
// pre-session refusal, which costs an unauthenticated caller one request, saturating a
// pool costs an ESTABLISHED session per-pool-capacity concurrent in-flight forwards, and
// each additional session costs a full authenticated handshake plus its own upstream —
// bounded independently by the session cap. The attacker's cost scales with the record
// rate, which is exactly the property the pre-session case lacks.
//
// Its rollup carries detailSuppressedRefusalScope too, but never suppressedScopeProxyCategory: a
// saturation record's count is exactly as narrow as the session_id beside it, the opposite
// of the pre-session bucket's proxy-wide tally, and the constant it writes (see
// recordResourceExhausted) says so.
type saturationGate struct {
	// mu guards recorded and makes the check-bucket-then-latch sequence in admit() one
	// critical section with clear()'s reset — see admit's doc for why a lock-free
	// atomic.Bool cannot provide that even via CompareAndSwap. The gate sits on the
	// refusal path (admit) and the successful-acquire path (clear), neither the
	// happy-path request handling itself, so a mutex here is not a hot-path cost.
	mu       sync.Mutex
	recorded bool

	once    sync.Once
	limiter *recordRateLimiter
}

// bucket returns the gate's token bucket, creating it on first use so a zero-value gate
// (a session or proxy built by a struct literal, as tests do) is still rate-bounded.
func (g *saturationGate) bucket() *recordRateLimiter {
	g.once.Do(func() { g.limiter = newRecordRateLimiter(saturationRecordRatePerSec, saturationRecordBurst) })
	return g.limiter
}

// admit reports whether this refusal may be written as a record, and if so how many
// refusals were elided since the last admitted one. A refusal inside an episode already
// spoken for, or one the bucket declines, is counted rather than written.
//
// The episode-open check, the bucket call, and the latch are one critical section under
// g.mu — not three independently-atomic steps — because splitting them reintroduces two
// distinct bugs a prior lock-free version (a bare CompareAndSwap on an atomic.Bool) had:
//
//  1. Latching the episode as recorded on the CAS alone, before knowing whether the
//     bucket admits it, is wrong: if the bucket then DECLINES the leading edge (drained by
//     an earlier flip-flop burst), the episode is marked spoken-for anyway, and only
//     clear() — fired solely by a successful pool acquire — can reopen it. A continuous
//     saturation never acquires, so the entire rest of that incident would produce ZERO
//     records: worse than the per-refusal flood this gate exists to bound. Latching only
//     AFTER a successful bucket.admit() means a decline leaves recorded false, so the next
//     refusal retries the bucket rather than being silently swallowed by an episode that
//     never actually got a record out.
//  2. An unsynchronized clear() (Load-then-Store) can race a DIFFERENT goroutine's
//     admit() that just opened a new episode: clear() observes the stale "true" from the
//     episode that just ended, then stores false over the new episode's still-fresh latch,
//     before any later refusal has a chance to fold into it — splitting one continuous
//     saturation into two-plus records. Serializing admit() and clear() on one lock removes
//     the window entirely.
func (g *saturationGate) admit() (ok bool, suppressed uint64) {
	bucket := g.bucket()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.recorded {
		bucket.suppress()
		return false, 0
	}
	// Leading edge of a (possibly new) episode: latch it as recorded ONLY once the bucket
	// actually admits a record for it (see point 1 above).
	ok, suppressed = bucket.admit()
	if ok {
		g.recorded = true
	}
	return ok, suppressed
}

// clear ends the current saturation episode: the pool just handed out a slot, so the next
// refusal is a new episode and is recorded again. Called from every successful acquire.
// Locked — see admit's doc for why clear() and admit() must be mutually exclusive rather
// than each independently atomic.
func (g *saturationGate) clear() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.recorded = false
}
