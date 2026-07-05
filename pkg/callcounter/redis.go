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
func redisWindowKey(key string, windowSec int) string {
	return fmt.Sprintf("callcounter:%s:%d", key, windowSec)
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

// incrIfAllBelowScript is the multi-bucket analogue of incrIfBelowScript: it prunes
// and counts every bucket, and ZADDs a member into all of them only if EVERY bucket
// is strictly below its limit — otherwise records nothing and reports the first
// blocking bucket. Evaluating check and all-or-nothing commit in one script makes a
// multi-maxCalls admission atomic.
//
//	KEYS[i]               sorted-set key for bucket i (1..#KEYS)
//	ARGV[1]               now (microseconds; score for new members)
//	ARGV[2+(i-1)*5 .. +5] per-bucket: cutoff, member, limit, ttlSec, windowMicros
//
// Reply: {admitted (1|0), deniedIndex (1-based; 0 when admitted), count, retryAfterMicros}.
//
// Retry-after, TTL refresh, and the microsecond requirement are as in
// incrIfBelowScript. The bucket keys must share a Redis slot for a multi-key EVAL;
// the binary wires a single-node client, where slots do not apply.
var incrIfAllBelowScript = redis.NewScript(`
local now = tonumber(ARGV[1])
local n = #KEYS
local counts = {}
local denied = 0
for i = 1, n do
  local base = 1 + (i-1)*5
  redis.call('ZREMRANGEBYSCORE', KEYS[i], '-inf', ARGV[base+1])
  local count = redis.call('ZCARD', KEYS[i])
  counts[i] = count
  local limit = tonumber(ARGV[base+3])
  if denied == 0 and (limit < 1 or count >= limit) then
    denied = i
  end
end
if denied > 0 then
  for i = 1, n do
    local base = 1 + (i-1)*5
    if redis.call('EXISTS', KEYS[i]) == 1 then
      redis.call('EXPIRE', KEYS[i], ARGV[base+4])
    end
  end
  local base = 1 + (denied-1)*5
  local limit = tonumber(ARGV[base+3])
  local count = counts[denied]
  local retry = 0
  if limit >= 1 then
    local idx = count - limit
    local pivot = redis.call('ZRANGE', KEYS[denied], idx, idx, 'WITHSCORES')
    if pivot[2] then
      retry = (tonumber(pivot[2]) + tonumber(ARGV[base+5])) - now
      if retry < 0 then retry = 0 end
    end
  end
  return {0, denied, count, retry}
end
local maxCount = 0
for i = 1, n do
  local base = 1 + (i-1)*5
  redis.call('ZADD', KEYS[i], now, ARGV[base+2])
  redis.call('EXPIRE', KEYS[i], ARGV[base+4])
  -- Post-admission total: pruned pre-count plus the member just added. counts[i]+1
  -- is exact because the script runs atomically (no concurrent ZADD between the ZCARD
  -- and this ZADD) and the unique member always inserts (never a no-op overwrite).
  local c = counts[i] + 1
  if c > maxCount then maxCount = c end
end
-- Report the maximum post-admission total across buckets per the capability.CallCounter
-- contract, mirroring the in-memory backend (no single binding bucket on admit).
return {1, 0, maxCount, 0}
`)

// IncrementIfAllBelow admits a call against several maxCalls buckets atomically
// (see the capability.CallCounter contract and incrIfAllBelowScript). The keys,
// windowSecs, and limits slices are parallel and must share one non-zero length.
//
// This is a multi-key EVAL: the buckets carry distinct windowSec suffixes, so on a
// Redis Cluster they hash to different slots and the script returns CROSSSLOT. The
// binary wires a single-node client, where slots do not apply; if a cluster client
// is ever wired, that error surfaces here and the engine maps it to a deny, so the
// constraint fails CLOSED rather than silently over-admitting.
func (r *Redis) IncrementIfAllBelow(ctx context.Context, keys []string, windowSecs []int, limits []int64) (admitted bool, deniedIndex int, count int64, retryAfter time.Duration, err error) {
	// Validate the batch (slice lengths, non-empty, per-bucket window/limit, distinct
	// (key, windowSec) buckets) before the Redis call, failing closed as
	// IncrementIfBelow does: two buckets sharing a Redis window key would ZADD two
	// members into one sorted set (double-count), diverging from the fail-closed
	// InMemory backend. checkBatch is shared with InMemory so both reject the same
	// inputs identically.
	if e := checkBatch(keys, windowSecs, limits); e != nil {
		return false, 0, 0, 0, e
	}

	now := r.now()
	redisKeys := make([]string, len(keys))
	argv := make([]interface{}, 0, 1+5*len(keys))
	argv = append(argv, now.UnixMicro())
	for i := range keys {
		redisKeys[i] = redisWindowKey(keys[i], windowSecs[i])
		cutoff := now.Add(-time.Duration(windowSecs[i]) * time.Second).UnixMicro()
		windowMicros := int64(windowSecs[i]) * 1_000_000
		ttlSec := int64(windowSecs[i]) * cleanupMarginFactor
		member := r.newMember(now)
		argv = append(argv, cutoff, member, limits[i], ttlSec, windowMicros)
	}

	res, runErr := incrIfAllBelowScript.Run(ctx, r.client, redisKeys, argv...).Result()
	if runErr != nil {
		return false, 0, 0, 0, fmt.Errorf("redis eval: %w", runErr)
	}
	return parseIncrIfAllBelowReply(res)
}

// parseIncrIfAllBelowReply decodes the {admitted, deniedIndex, count,
// retryAfterMicros} array incrIfAllBelowScript returns, converting the script's
// 1-based deniedIndex to a 0-based slice index. Each element is checked so a
// changed encoding fails closed with a structured error rather than defaulting to
// a zero value (mirroring parseIncrIfBelowReply).
func parseIncrIfAllBelowReply(res interface{}) (admitted bool, deniedIndex int, count int64, retryAfter time.Duration, err error) {
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
	cnt, ok := arr[2].(int64)
	if !ok {
		return false, 0, 0, 0, fmt.Errorf("redis eval: unexpected count type %T (value %v)", arr[2], arr[2])
	}
	retryMicros, ok := arr[3].(int64)
	if !ok {
		return false, 0, 0, 0, fmt.Errorf("redis eval: unexpected retryMicros type %T (value %v)", arr[3], arr[3])
	}
	if admittedRaw == 1 {
		// Propagate the script's post-admission count; deniedIndex/retryAfter are
		// meaningless on the admit path.
		return true, 0, cnt, 0, nil
	}
	return false, int(deniedRaw) - 1, cnt, time.Duration(retryMicros) * time.Microsecond, nil
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
