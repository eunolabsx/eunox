// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package callcounter

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/eunolabs/eunox/pkg/capability"

	"github.com/redis/go-redis/v9"
)

// Redis is a Redis-backed call counter. Unconditional increments (IncrementAndGet)
// run as an atomic MULTI/EXEC transaction; the check-and-record limiter paths
// (IncrementIfBelow, IncrementIfAllBelow) run as atomic Lua scripts so the count and
// conditional add cannot race. Every path stamps a per-key TTL (windowSec *
// cleanupMarginFactor) so idle counters are reclaimed without a separate sweep.
type Redis struct {
	client redis.Cmdable
	now    func() time.Time
	// instanceID is a one-time random suffix folded into every ZADD member so two
	// replicas pointed at the same Redis can never emit the same member. Without it,
	// two processes whose seq atomics line up at the same UnixNano tick would produce
	// identical members; ZADD would then update the score instead of inserting, so
	// ZCARD does not advance and the counter under-counts across replicas — a
	// fail-open in the multi-instance deployment this backend exists to support.
	instanceID string
	// seq is an atomic counter appended to each member so two calls in the same
	// nanosecond within one process produce distinct members. Cross-process
	// uniqueness comes from instanceID.
	seq atomic.Int64
}

// redisOption configures the Redis counter. It is unexported because the only
// option (a custom clock) exists solely for deterministic tests; the external
// test package reaches it through WithRedisTimeFunc in export_test.go.
type redisOption func(*Redis)

// withTimeFunc sets a custom time function so the same-tick collision regression
// can be tested deterministically.
func withTimeFunc(fn func() time.Time) redisOption {
	return func(r *Redis) {
		r.now = fn
	}
}

// redisWindowKey is the Redis key for one (key, windowSec) counter's sorted set.
// Keying by window means the same key under two windows addresses two independent
// counters. Single source for the "callcounter:<key>:<windowSec>" format so the
// increment, admit, and peek paths cannot drift.
//
// Built on storageKey — the in-memory backend's identical (key, windowSec) composition
// — rather than a second fmt.Sprintf of the same scheme. The two backends must agree on
// how a (key, windowSec) pair collapses into one string (that is what makes their window
// isolation structurally equivalent), and this path runs per enforced call, so the shared
// spelling is both cheaper and the reason a change to one composition cannot silently
// miss the other.
func redisWindowKey(key string, windowSec int) string {
	return "callcounter:" + storageKey(key, windowSec)
}

// newMember builds a unique sorted-set member for one inserted call: the instance
// id, the call's nanosecond timestamp, and the next sequence number. Timestamp and
// seq are zero-padded to fixed width so lexicographic member order matches insertion
// order for same-score (same-microsecond) entries; otherwise a tie breaks at a digit
// boundary ("...-10" before "...-9") and rank-trimming could discard the newest
// member. The seq.Add advance makes two buckets or two same-tick calls never
// collide. 20 digits cover the full uint64 range. The encoding is kept byte-identical
// across all three increment paths, so this is their single source.
func (r *Redis) newMember(now time.Time) string {
	return fmt.Sprintf("%s-%020d-%020d", r.instanceID, now.UnixNano(), r.seq.Add(1))
}

// NewRedis creates a Redis-backed call counter.
//
// Panics if crypto/rand cannot supply the per-instance entropy used to make ZADD
// members unique across replicas — effectively impossible on a healthy host, and a
// silent fallback would risk reintroducing the cross-replica collision the entropy
// prevents.
func NewRedis(client redis.Cmdable, opts ...redisOption) *Redis {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Errorf("callcounter: crypto/rand unavailable: %w", err))
	}
	r := &Redis{
		client:     client,
		now:        time.Now,
		instanceID: hex.EncodeToString(b[:]),
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// IncrementAndGet atomically records a call for key and window via a MULTI/EXEC
// transaction, returning the in-window count capped at maxEntries. A sorted set
// scored by timestamp gives accurate sliding-window counting; trimming to the
// newest maxEntries members keeps it bounded, mirroring InMemory.
func (r *Redis) IncrementAndGet(ctx context.Context, key string, windowSec, maxEntries int) (int64, error) {
	// Reject an out-of-range window before computing the TTL: an overflowing
	// windowSec wraps the Expire to a non-positive TTL, so the key expires
	// immediately and the counter resets every call (a fail-open bypass). A
	// non-positive maxEntries is rejected (see checkMaxEntries).
	if err := checkWindowSec(windowSec); err != nil {
		return 0, err
	}
	if err := checkMaxEntries(maxEntries); err != nil {
		return 0, err
	}

	now := r.now()
	windowKey := redisWindowKey(key, windowSec)
	// Integer microseconds for both score and cutoff so all three methods encode
	// scores identically. Present-day micros (~1.7e15) are within float64's exact
	// range (2^53), so the redis.Z payload round-trips losslessly.
	nowUnixMicro := now.UnixMicro()
	cutoff := now.Add(-time.Duration(windowSec) * time.Second).UnixMicro()
	member := r.newMember(now)

	// Use a transactional pipeline (MULTI/EXEC) for atomicity
	pipe := r.client.TxPipeline()

	// Remove expired entries
	pipe.ZRemRangeByScore(ctx, windowKey, "-inf", strconv.FormatInt(cutoff, 10))

	// Add current timestamp
	pipe.ZAdd(ctx, windowKey, redis.Z{Score: float64(nowUnixMicro), Member: member})

	// Cap to the newest maxEntries: drop all but the highest-scored maxEntries
	// members (negative stop -(maxEntries+1) leaves the top untouched; a no-op below
	// the cap). Keeping the newest keeps presence/count correct as entries age out,
	// matching InMemory. The stop is computed in int64 so maxEntries+1 cannot wrap to
	// a no-op trim (checkMaxEntries already caps at math.MaxInt32).
	pipe.ZRemRangeByRank(ctx, windowKey, 0, -(int64(maxEntries) + 1))

	// Count entries in window (post-trim)
	countCmd := pipe.ZCard(ctx, windowKey)

	// Set TTL for cleanup, with a cleanupMarginFactor margin (not +1s) so entries at
	// the window start are not evicted before the ZREMRANGEBYSCORE cleanup fires
	// under high app/Redis clock skew. Cleanup-only; the margin's storage cost is
	// negligible.
	pipe.Expire(ctx, windowKey, time.Duration(windowSec)*cleanupMarginFactor*time.Second)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("redis pipeline: %w", err)
	}
	// Defence in depth on the value used for enforcement. A command error inside EXEC
	// (e.g. WRONGTYPE) leaves countCmd.Val() at zero, and returning 0 would report no
	// in-window calls and fail open. Exec's aggregated error normally surfaces this,
	// but re-checking countCmd.Err() keeps the fail-closed guarantee local to the
	// command whose Val() we return.
	if err := countCmd.Err(); err != nil {
		return 0, fmt.Errorf("redis pipeline ZCard: %w", err)
	}

	return countCmd.Val(), nil
}

// incrIfBelowScript atomically records a call only when the in-window count is
// below limit. Running prune, count, conditional add, and TTL as one Lua script
// makes check-and-record atomic across replicas, so a denied call adds no member
// and the set never grows from retries (a separate ZCOUNT-then-ZADD would leave a
// TOCTOU gap).
//
//	KEYS[1] sorted-set key
//	ARGV[1] cutoff (microseconds; members with score <= cutoff are expired)
//	ARGV[2] now (microseconds; score for the new member)
//	ARGV[3] member
//	ARGV[4] limit
//	ARGV[5] TTL (seconds)
//	ARGV[6] window (microseconds; for the retryAfter estimate)
//
// Reply: {admitted (1|0), count, retryAfterMicros}.
//
// The retryAfter estimate uses the entry at rank (count - limit), not rank 0: a
// slot frees only once enough of the oldest entries expire to drop below limit, and
// the last of those is the (count-limit)-th oldest. Rank 0 is correct only when
// count == limit; when a manifest reload lowered the limit, count > limit and rank 0
// underestimates. Matches InMemory's valid[cur-limit].
//
// Timestamps MUST be MICROSECONDS, never nanoseconds: Lua numbers are float64, exact
// only to 2^53. UnixMicro (~1.75e15) and the retry-math sum stay inside that range; a
// UnixNano value (~1.75e18) would lose precision and yield a wrong retryAfter.
var incrIfBelowScript = redis.NewScript(`
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[1])
local count = redis.call('ZCARD', KEYS[1])
local limit = tonumber(ARGV[4])
if limit < 1 or count >= limit then
  -- Refresh the TTL on the denied path too: a key constantly at/above limit is
  -- never admitted, so its TTL would count down from the last admit and the key
  -- could expire mid-window, silently resetting the quota. Gate on EXISTS (not
  -- count>0) so the invariant is "refresh whenever present, never re-create an
  -- absent key", correct for the limit<1 branch without relying on zset auto-delete.
  if redis.call('EXISTS', KEYS[1]) == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[5])
  end
  local retry = 0
  if limit >= 1 then
    local idx = count - limit
    local pivot = redis.call('ZRANGE', KEYS[1], idx, idx, 'WITHSCORES')
    if pivot[2] then
      retry = (tonumber(pivot[2]) + tonumber(ARGV[6])) - tonumber(ARGV[2])
      if retry < 0 then retry = 0 end
    end
  end
  return {0, count, retry}
end
redis.call('ZADD', KEYS[1], ARGV[2], ARGV[3])
redis.call('EXPIRE', KEYS[1], ARGV[5])
return {1, count + 1, 0}
`)

// IncrementIfBelow records a call for key only when the in-window count is
// strictly below limit, evaluating check and record in one atomic Lua script (see
// incrIfBelowScript). It is the rate-limiting counterpart of IncrementAndGet that
// maxCalls uses; an over-limit call adds no member.
//
// It returns the resulting in-window count (post-record when admitted, current
// otherwise), whether admitted, and — when rejected — how long until a slot frees
// (the entry at rank count-limit, see incrIfBelowScript).
func (r *Redis) IncrementIfBelow(ctx context.Context, key string, windowSec int, limit int64) (count int64, admitted bool, retryAfter time.Duration, err error) {
	// Reject an out-of-range window before computing the TTL: an overflowing window
	// wraps the TTL non-positive, expiring the key immediately and resetting the
	// quota (as in IncrementAndGet).
	if err := checkWindowSec(windowSec); err != nil {
		return 0, false, 0, err
	}
	// Reject a non-positive limit: the script's `if limit < 1` branch would deny with
	// a nil error, making a misconfigured limit indistinguishable from an exhausted
	// quota.
	if err := checkLimit(limit); err != nil {
		return 0, false, 0, err
	}

	now := r.now()
	windowKey := redisWindowKey(key, windowSec)
	// Integer microseconds for score and cutoff, matching IncrementAndGet and Peek so
	// the encoding is uniform across all three methods (exact within float64's 2^53
	// range).
	nowMicros := now.UnixMicro()
	cutoff := now.Add(-time.Duration(windowSec) * time.Second).UnixMicro()
	windowMicros := int64(windowSec) * 1_000_000
	ttlSec := int64(windowSec) * cleanupMarginFactor
	member := r.newMember(now)

	res, runErr := incrIfBelowScript.Run(ctx, r.client, []string{windowKey},
		cutoff, nowMicros, member, limit, ttlSec, windowMicros).Result()
	if runErr != nil {
		return 0, false, 0, fmt.Errorf("redis eval: %w", runErr)
	}

	return parseIncrIfBelowReply(res)
}

// parseIncrIfBelowReply decodes the {admitted, count, retryAfterMicros} array the
// incrIfBelowScript returns (three Redis integers → int64). Each element is checked
// so a changed encoding (go-redis upgrade, a Valkey/KeyDB proxy, a test mock
// returning a string/float) fails closed with a structured error rather than
// defaulting to the int64 zero value, which would silently report no in-window
// calls and a bogus retryAfter the full-window fallback masks.
func parseIncrIfBelowReply(res interface{}) (count int64, admitted bool, retryAfter time.Duration, err error) {
	arr, ok := res.([]interface{})
	if !ok || len(arr) != 3 {
		return 0, false, 0, fmt.Errorf("redis eval: unexpected reply %T", res)
	}
	admittedRaw, ok := arr[0].(int64)
	if !ok {
		return 0, false, 0, fmt.Errorf("redis eval: unexpected admitted type %T (value %v)", arr[0], arr[0])
	}
	cnt, ok := arr[1].(int64)
	if !ok {
		return 0, false, 0, fmt.Errorf("redis eval: unexpected count type %T (value %v)", arr[1], arr[1])
	}
	retryMicros, ok := arr[2].(int64)
	if !ok {
		return 0, false, 0, fmt.Errorf("redis eval: unexpected retryMicros type %T (value %v)", arr[2], arr[2])
	}

	return cnt, admittedRaw == 1, time.Duration(retryMicros) * time.Microsecond, nil
}

// admitAllScript is the multi-bucket admission: it prunes and totals every bucket under
// that bucket's OWN accounting, and ZADDs a member into all of them only if EVERY bucket
// has headroom — otherwise records nothing and reports the first blocking bucket.
// Evaluating check and all-or-nothing commit in one script makes a multi-condition
// admission atomic.
//
// A counted bucket totals with ZCARD (O(1)); a weighted one sums the per-member weights.
// Mixing the two in one script is what lets "no more than 20 refunds an hour AND no more
// than $2,000 an hour" be one atomic decision instead of two that can disagree.
//
//	KEYS[i]               sorted-set key for bucket i (1..#KEYS)
//	ARGV[1]               now (microseconds; score for new members)
//	ARGV[2+(i-1)*7 .. +7] per-bucket: cutoff, member, limit, ttlSec, windowMicros, counted, weight
//
// Reply: {admitted (1|0), deniedIndex (1-based; 0 when admitted), total (string), retryAfterMicros}.
//
// The total is a STRING for the same reason AddIfTotalBelow's is: it is a magnitude,
// routinely fractional, and %.17g round-trips a float64 exactly where Redis integer replies
// and Lua's own tostring would not. Timestamps are MICROSECONDS throughout: Lua numbers are
// float64, exact only to 2^53.
var admitAllScript = redis.NewScript(`
local now = tonumber(ARGV[1])
local n = #KEYS
local totals = {}
local denied = 0

local function entry_weight(m)
  local sep = string.find(m, '|', 1, true)
  if sep then return tonumber(string.sub(m, sep + 1)) or 1 end
  return 1
end

for i = 1, n do
  local base = 1 + (i-1)*7
  redis.call('ZREMRANGEBYSCORE', KEYS[i], '-inf', ARGV[base+1])
  local counted = tonumber(ARGV[base+6])
  local total = 0
  if counted == 1 then
    total = redis.call('ZCARD', KEYS[i])
  else
    local entries = redis.call('ZRANGE', KEYS[i], 0, -1)
    for j = 1, #entries do
      total = total + entry_weight(entries[j])
    end
  end
  totals[i] = total
  local weight = tonumber(ARGV[base+7])
  if counted == 1 then weight = 1 end
  if denied == 0 and (total + weight) > tonumber(ARGV[base+3]) then
    denied = i
  end
end

if denied > 0 then
  -- Refresh the TTL on the denied path too: a bucket held at its bound is never admitted,
  -- so its TTL would count down from the last admit and could expire mid-window, silently
  -- resetting the quota. Gate on EXISTS so the invariant is "refresh whenever present,
  -- never re-create an absent key".
  for i = 1, n do
    local base = 1 + (i-1)*7
    if redis.call('EXISTS', KEYS[i]) == 1 then
      redis.call('EXPIRE', KEYS[i], ARGV[base+4])
    end
  end
  local base = 1 + (denied-1)*7
  local counted = tonumber(ARGV[base+6])
  local limit = tonumber(ARGV[base+3])
  local weight = tonumber(ARGV[base+7])
  if counted == 1 then weight = 1 end
  local total = totals[denied]
  local retry = 0
  if counted == 1 then
    -- The last entry that must age out is the (total-limit)-th oldest; read it directly
    -- rather than walking, so a large quota does not pay a linear scan on the deny path.
    local idx = total - limit
    local pivot = redis.call('ZRANGE', KEYS[denied], idx, idx, 'WITHSCORES')
    if pivot[2] then
      retry = (tonumber(pivot[2]) + tonumber(ARGV[base+5])) - now
    end
  else
    local needed = (total + weight) - limit
    local freed = 0
    local entries = redis.call('ZRANGE', KEYS[denied], 0, -1, 'WITHSCORES')
    for j = 1, #entries, 2 do
      freed = freed + entry_weight(entries[j])
      if freed >= needed then
        retry = (tonumber(entries[j+1]) + tonumber(ARGV[base+5])) - now
        break
      end
    end
  end
  if retry < 0 then retry = 0 end
  return {0, denied, string.format('%.17g', total), retry}
end

local maxTotal = 0
for i = 1, n do
  local base = 1 + (i-1)*7
  local counted = tonumber(ARGV[base+6])
  local weight = tonumber(ARGV[base+7])
  if counted == 1 then weight = 1 end
  local post = totals[i] + weight
  -- A weight that cannot move the total is admitted WITHOUT being recorded: it can never
  -- affect a future decision, and recording it is the one case that would grow a key
  -- without bound.
  if post ~= totals[i] then
    redis.call('ZADD', KEYS[i], now, ARGV[base+2])
  end
  redis.call('EXPIRE', KEYS[i], ARGV[base+4])
  if post > maxTotal then maxTotal = post end
end
-- Report the maximum post-admission total across buckets per the capability.CallCounter
-- contract, mirroring the in-memory backend (no single binding bucket on admit).
return {1, 0, string.format('%.17g', maxTotal), 0}
`)

// AdmitAll admits a call against several quota buckets atomically, mixing counted and
// weighted accountings in one script (see admitAllScript and the capability.CallCounter
// contract).
//
// This is a multi-key EVAL: the buckets carry distinct windowSec suffixes, so on a Redis
// Cluster they hash to different slots and the script returns CROSSSLOT. The binary wires a
// single-node client, where slots do not apply; if a cluster client is ever wired, that
// error surfaces here and the engine maps it to a deny, so the constraint fails CLOSED
// rather than silently over-admitting.
func (r *Redis) AdmitAll(ctx context.Context, buckets []capability.QuotaBucket) (admitted bool, deniedIndex int, total float64, retryAfter time.Duration, err error) {
	// Validate the batch before the Redis call, failing closed as the single-bucket paths
	// do: two buckets sharing a Redis window key would ZADD two members into one sorted set
	// (double-count), diverging from the fail-closed InMemory backend. checkBuckets is
	// shared with InMemory so both reject the same inputs identically.
	if e := checkBuckets(buckets); e != nil {
		return false, 0, 0, 0, e
	}

	now := r.now()
	redisKeys := make([]string, len(buckets))
	argv := make([]interface{}, 0, 1+7*len(buckets))
	argv = append(argv, now.UnixMicro())
	for i := range buckets {
		b := &buckets[i]
		redisKeys[i] = redisWindowKey(b.Key, b.WindowSec)
		cutoff := now.Add(-time.Duration(b.WindowSec) * time.Second).UnixMicro()
		windowMicros := int64(b.WindowSec) * 1_000_000
		ttlSec := int64(b.WindowSec) * cleanupMarginFactor
		counted := 0
		// A counted bucket's member carries NO weight suffix, so a later weighted read of
		// the same key reads it as 1 — the sense in which maxCalls is this with weight 1.
		member := r.newMember(now)
		if b.Counted {
			counted = 1
		} else {
			member = r.newWeightedMember(now, b.Weight)
		}
		argv = append(argv, cutoff, member, b.Limit, ttlSec, windowMicros, counted, b.Weight)
	}

	res, runErr := admitAllScript.Run(ctx, r.client, redisKeys, argv...).Result()
	if runErr != nil {
		return false, 0, 0, 0, fmt.Errorf("redis eval: %w", runErr)
	}
	return parseAdmitAllReply(res)
}

// parseAdmitAllReply decodes the {admitted, deniedIndex, total, retryAfterMicros} array
// admitAllScript returns, converting the script's 1-based deniedIndex to a 0-based slice
// index. Each element is type-checked so a changed encoding fails closed with a structured
// error rather than defaulting to a zero value (mirroring parseIncrIfBelowReply).
func parseAdmitAllReply(res interface{}) (admitted bool, deniedIndex int, total float64, retryAfter time.Duration, err error) {
	arr, ok := res.([]interface{})
	if !ok || len(arr) != 4 {
		return false, 0, 0, 0, fmt.Errorf("redis eval: unexpected reply %T", res)
	}
	admittedRaw, ok := arr[0].(int64)
	if !ok {
		return false, 0, 0, 0, fmt.Errorf("redis eval: unexpected admitted type %T (value %v)", arr[0], arr[0])
	}
	deniedRaw, ok := arr[1].(int64)
	if !ok {
		return false, 0, 0, 0, fmt.Errorf("redis eval: unexpected deniedIndex type %T (value %v)", arr[1], arr[1])
	}
	totalRaw, ok := arr[2].(string)
	if !ok {
		return false, 0, 0, 0, fmt.Errorf("redis eval: unexpected total type %T (value %v)", arr[2], arr[2])
	}
	total, parseErr := strconv.ParseFloat(totalRaw, 64)
	if parseErr != nil {
		return false, 0, 0, 0, fmt.Errorf("redis eval: unparseable total %q: %w", totalRaw, parseErr)
	}
	retryMicros, ok := arr[3].(int64)
	if !ok {
		return false, 0, 0, 0, fmt.Errorf("redis eval: unexpected retryMicros type %T (value %v)", arr[3], arr[3])
	}
	if admittedRaw == 1 {
		return true, 0, total, 0, nil
	}
	return false, int(deniedRaw) - 1, total, time.Duration(retryMicros) * time.Microsecond, nil
}

// weightMemberSep separates a sorted-set member's uniqueness prefix from the WEIGHT it
// carries. One key holds both the timestamp (the score) and the magnitude (the member
// suffix), so a weighted counter needs no second key to stay consistent with its own
// expiry — the weight ages out with the entry that carried it, atomically, because they
// are the same element.
//
// The separator is a byte the uniqueness prefix cannot contain: newMember emits only hex,
// digits, and '-'. A member WITHOUT it is a plain counted call and reads as weight 1,
// which is what lets a key written by IncrementIfBelow be summed by AddIfTotalBelow
// without a migration — the sense in which the weighted total generalizes the count.
const weightMemberSep = "|"

// newWeightedMember builds a sorted-set member carrying both the per-instance uniqueness
// of newMember and this call's weight. 'g' with -1 precision emits the shortest form that
// round-trips through Lua's tonumber (itself a float64 parse), so the weight summed by the
// script is bit-identical to the one this process admitted.
func (r *Redis) newWeightedMember(now time.Time, weight float64) string {
	return r.newMember(now) + weightMemberSep + strconv.FormatFloat(weight, 'g', -1, 64)
}

// addIfTotalBelowScript atomically adds weight to a key's in-window WEIGHTED TOTAL only
// when the resulting total would not exceed the limit. Running prune, sum, compare,
// conditional add, and TTL as one script makes check-and-record atomic across replicas, so
// a denied call adds no member and a burst of refusals cannot extend its own lockout.
//
//	KEYS[1] sorted-set key
//	ARGV[1] cutoff (microseconds; members with score <= cutoff are expired)
//	ARGV[2] now (microseconds; score for the new member)
//	ARGV[3] member (uniqueness prefix, separator, weight)
//	ARGV[4] weight
//	ARGV[5] limit
//	ARGV[6] TTL (seconds)
//	ARGV[7] window (microseconds; for the retryAfter estimate)
//
// Reply: {admitted (1|0), total (string), retryAfterMicros}.
//
// The total is returned as a STRING, not a Redis integer: it is a magnitude, routinely
// fractional (a currency amount), and Redis integer replies truncate. It is formatted with
// %.17g rather than Lua's tostring, which uses %.14g and would silently round a total in
// the upper range of what MaxWeightedTotal admits — turning an exact budget into an
// approximate one at exactly the magnitudes where the bound matters most. The Go side
// parses it back with the same float64 parse the script used, so the value the caller
// compares is the value the script compared.
//
// The retryAfter estimate walks oldest-first accumulating the weight each expiry frees,
// and reports when the entry that crosses the shortfall leaves the window — the weighted
// analogue of incrIfBelowScript's rank-(count-limit) pivot. Timestamps are MICROSECONDS
// for the same reason as there: Lua numbers are float64, exact only to 2^53.
var addIfTotalBelowScript = redis.NewScript(`
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[1])
local entries = redis.call('ZRANGE', KEYS[1], 0, -1, 'WITHSCORES')
local weight = tonumber(ARGV[4])
local limit = tonumber(ARGV[5])
local total = 0
for i = 1, #entries, 2 do
  local m = entries[i]
  local sep = string.find(m, '|', 1, true)
  local ew = 1
  if sep then
    ew = tonumber(string.sub(m, sep + 1)) or 1
  end
  total = total + ew
end
if total + weight == total then
  -- A weight that cannot move the total is admitted but NOT recorded, matching the
  -- in-memory backend: zero (and any weight too small to register in double precision) is
  -- otherwise admitted forever and grows the sorted set without bound, making every later
  -- call re-scan it. It can never affect a future total, so there is nothing to record.
  if redis.call('EXISTS', KEYS[1]) == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[6])
  end
  return {1, string.format('%.17g', total), 0}
end
if total + weight > limit then
  -- Refresh the TTL on the denied path too: a key held at its bound is never admitted, so
  -- its TTL would count down from the last admit and the key could expire mid-window,
  -- silently resetting the budget. Gate on EXISTS so the invariant is "refresh whenever
  -- present, never re-create an absent key".
  if redis.call('EXISTS', KEYS[1]) == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[6])
  end
  -- The retry estimate re-walks the entries array (already in memory, member and score
  -- interleaved) rather than the script building two parallel tables of size n on EVERY
  -- call to serve a branch only the deny path reaches. On the admit path — the common one
  -- — that was 2n wasted table stores per call inside Redis's single-threaded execution,
  -- growing with the window.
  local needed = (total + weight) - limit
  local retry = 0
  local freed = 0
  for i = 1, #entries, 2 do
    local m = entries[i]
    local sep = string.find(m, '|', 1, true)
    local ew = 1
    if sep then
      ew = tonumber(string.sub(m, sep + 1)) or 1
    end
    freed = freed + ew
    if freed >= needed then
      retry = (tonumber(entries[i + 1]) + tonumber(ARGV[7])) - tonumber(ARGV[2])
      if retry < 0 then retry = 0 end
      break
    end
  end
  return {0, string.format('%.17g', total), retry}
end
redis.call('ZADD', KEYS[1], ARGV[2], ARGV[3])
redis.call('EXPIRE', KEYS[1], ARGV[6])
return {1, string.format('%.17g', total + weight), 0}
`)

// AddIfTotalBelow adds weight to the key's in-window weighted total only when the
// resulting total would not exceed limit, evaluating check and record in one atomic Lua
// script (see addIfTotalBelowScript). It is the weighted counterpart of IncrementIfBelow
// that the cumulative blastRadius bound uses; an over-limit call adds no member.
//
// Cost note: unlike the counting paths, which answer with an O(1) ZCARD, this sums the
// per-member weights and is therefore O(n) in the window's entry count. That asymmetry is
// why maxCalls keeps its own primitive rather than riding this one.
func (r *Redis) AddIfTotalBelow(ctx context.Context, key string, windowSec int, weight, limit float64) (total float64, admitted bool, retryAfter time.Duration, err error) {
	if err := checkWindowSec(windowSec); err != nil {
		return 0, false, 0, err
	}
	// Reject a malformed weight or bound before the round trip: the script's
	// `total + weight > limit` branch would otherwise deny with a nil error, making a
	// misconfiguration indistinguishable from an exhausted budget (and a NaN weight would
	// make that comparison false forever — the fail-OPEN direction).
	if err := checkWeight(weight); err != nil {
		return 0, false, 0, err
	}
	if err := checkTotalLimit(limit); err != nil {
		return 0, false, 0, err
	}

	now := r.now()
	windowKey := redisWindowKey(key, windowSec)
	nowMicros := now.UnixMicro()
	cutoff := now.Add(-time.Duration(windowSec) * time.Second).UnixMicro()
	windowMicros := int64(windowSec) * 1_000_000
	ttlSec := int64(windowSec) * cleanupMarginFactor
	member := r.newWeightedMember(now, weight)

	res, runErr := addIfTotalBelowScript.Run(ctx, r.client, []string{windowKey},
		cutoff, nowMicros, member, weight, limit, ttlSec, windowMicros).Result()
	if runErr != nil {
		return 0, false, 0, fmt.Errorf("redis eval: %w", runErr)
	}
	return parseAddIfTotalBelowReply(res)
}

// parseAddIfTotalBelowReply decodes the {admitted, total, retryAfterMicros} array
// addIfTotalBelowScript returns. Each element is type-checked so a changed encoding (a
// go-redis upgrade, a Valkey/KeyDB proxy, a test mock) fails closed with a structured
// error rather than defaulting to a zero value, which would report an empty budget and
// admit — mirroring parseIncrIfBelowReply.
func parseAddIfTotalBelowReply(res interface{}) (total float64, admitted bool, retryAfter time.Duration, err error) {
	arr, ok := res.([]interface{})
	if !ok || len(arr) != 3 {
		return 0, false, 0, fmt.Errorf("redis eval: unexpected reply %T", res)
	}
	admittedRaw, ok := arr[0].(int64)
	if !ok {
		return 0, false, 0, fmt.Errorf("redis eval: unexpected admitted type %T (value %v)", arr[0], arr[0])
	}
	totalRaw, ok := arr[1].(string)
	if !ok {
		return 0, false, 0, fmt.Errorf("redis eval: unexpected total type %T (value %v)", arr[1], arr[1])
	}
	total, parseErr := strconv.ParseFloat(totalRaw, 64)
	if parseErr != nil {
		return 0, false, 0, fmt.Errorf("redis eval: unparseable total %q: %w", totalRaw, parseErr)
	}
	retryMicros, ok := arr[2].(int64)
	if !ok {
		return 0, false, 0, fmt.Errorf("redis eval: unexpected retryMicros type %T (value %v)", arr[2], arr[2])
	}
	return total, admittedRaw == 1, time.Duration(retryMicros) * time.Microsecond, nil
}

// Peek returns the number of entries recorded for key within the window WITHOUT
// adding one. It is the read-only counterpart of IncrementAndGet used by
// sequenceBlock to test whether a tool has already run. windowSec must match the
// recording value so the same sorted-set bucket is consulted; the engine uses
// sequenceHistoryWindowSec for both, so they agree.
func (r *Redis) Peek(ctx context.Context, key string, windowSec int) (int64, error) {
	if err := checkWindowSec(windowSec); err != nil {
		return 0, err
	}

	now := r.now()
	windowKey := redisWindowKey(key, windowSec)
	// Integer-microsecond cutoff, matching the mutating paths.
	cutoff := now.Add(-time.Duration(windowSec) * time.Second).UnixMicro()

	// Count entries strictly newer than the cutoff. The "(" prefix makes the lower
	// bound exclusive so this shares the mutating path's expiry predicate (which
	// drops scores <= cutoff). Without it, ZCOUNT's inclusive lower bound would count
	// an entry exactly at the cutoff and keep stale history alive at the window edge.
	count, err := r.client.ZCount(ctx, windowKey, "("+strconv.FormatInt(cutoff, 10), "+inf").Result()
	if err != nil {
		return 0, fmt.Errorf("redis zcount: %w", err)
	}
	return count, nil
}
