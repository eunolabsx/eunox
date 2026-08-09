// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Admission control over refusal records whose write rate a caller (not the policy) sets:
// transport refusals taken before or beside a policy decision (recordRateLimiter) and
// pool-saturation refusals (saturationGate). No policy ALLOW/DENY record is ever
// admission-controlled.
//
// What is NOT metered, deliberately: the fail-closed ROUTING refusal (dispatchUnmapped and the
// notification gate's unmapped arm), on either transport. Reaching it means a peer whose other
// traffic writes policy DENY records at the same one-record-per-message cost — and those may
// never be admission-controlled, since a policy verdict elided is a policy verdict an incident
// responder does not have. Metering the routing refusal alone would lower no ceiling; it would
// only make the cheapest way to fill the queue the one that leaves the better tape.

package transport

import (
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

	preSessionDenyRatePerSec = perCategoryDenyRatePerSec * numRefusalCategories
	preSessionDenyBurst      = perCategoryDenyBurstSize * numRefusalCategories
)

// refusalCategory is a distinct type (not a bare string) because its values double as both
// the rate-limit bucket key and the audit record's structured condition_type field.
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
)

// refusalCategories is authoritative: a category added above but omitted here falls to the
// shared unknown bucket instead of getting its own (see
// TestRefusalCategories_AllHaveTheirOwnBucket).
var refusalCategories = []refusalCategory{
	catOrigin, catJWT, catAuth, catControl, catLoopback, catBody, catContentType, catSaturation, catKill, catAudience, catRevision,
}

// numRefusalCategories sizes the aggregate budget above. It is a const because the budget
// constants are, and TestRefusalCategories_AllHaveTheirOwnBucket holds it to len().
const numRefusalCategories = 11

// perCategoryFloor keeps every category's bucket alive even where plain division would
// floor its share to 0 (possible past ~20 categories at today's rate) — a 0-rate bucket
// never refills and would permanently suppress that category's records.
const perCategoryFloor = 1

// perCategoryShare divides total evenly across categories, floored at perCategoryFloor.
// Integer division (not float) keeps each share a whole token count and lands the sum at
// or slightly UNDER the aggregate when it doesn't divide evenly — the safe direction.
func perCategoryShare(total, categories int) float64 {
	share := total / categories
	if share < perCategoryFloor {
		share = perCategoryFloor
	}
	return float64(share)
}

// perCategoryDenyRate and perCategoryDenyBurst are each registered category's even share
// of the aggregate budget. The unreachable-in-production "unknown" fallback bucket is
// deliberately NOT sized from these — it gets perCategoryFloor instead, so it doesn't
// dilute every real category's share for a bucket no call site actually uses.
var (
	perCategoryDenyRate  = perCategoryShare(preSessionDenyRatePerSec, len(refusalCategories))
	perCategoryDenyBurst = perCategoryShare(preSessionDenyBurst, len(refusalCategories))
)

// newRefusalRecordLimiter builds the per-category buckets, each holding an equal share of
// the aggregate rate/burst (see perCategoryDenyRate/perCategoryDenyBurst). Held per PROXY —
// the HTTP proxy for its pre-session refusals, the stdio proxy for catRevision.
func newRefusalRecordLimiter() *categoryRecordLimiter {
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
// cheap refusals in one category cannot suppress another's records.
//
// The table is built ONCE at construction rather than lazily, so admit takes no lock but
// its own bucket's — not a second proxy-global lock on the path this file exists to keep
// cheap under attack.
type categoryRecordLimiter struct {
	buckets map[refusalCategory]*recordRateLimiter
	// unknown serves an unregistered category. Unreachable from call sites (all pass
	// constants), but keeps a future typo bounded rather than unbounded.
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

// setNow points every bucket at an injectable clock (test-only). A method rather than a
// field because an assignment to a parent field would miss the per-bucket clocks.
func (c *categoryRecordLimiter) setNow(now func() time.Time) {
	for _, b := range c.buckets {
		b.now = now
	}
	c.unknown.now = now
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
	admitted, suppressed := limiter.admit(category)
	switch {
	case !admitted:
		return nil
	case suppressed == 0:
		return rec
	default:
		return rolledUpRecorder{auditRecorder: rec, suppressed: suppressed}
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
