// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package callcounter

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/eunolabs/eunox/pkg/capability"

	"github.com/redis/go-redis/v9"
)

// Redis is a Redis-backed call counter. IncrementAndGet runs as an atomic MULTI/EXEC
// transaction; AdmitAll runs as an atomic Lua script so totals and conditional adds cannot
// race across a batch. Every path stamps a per-key TTL (windowSec*cleanupMarginFactor) so
// idle counters are reclaimed without a separate sweep.
type Redis struct {
	client redis.Cmdable
	now    func() time.Time
	// instanceID is a one-time random suffix folded into every ZADD member so two
	// replicas can never emit the same member — without it, two processes whose seq
	// atomics line up at the same tick would collide and under-count (fail-open).
	instanceID string
	// seq is an atomic counter appended to each member so two calls in the same
	// nanosecond within one process produce distinct members.
	seq atomic.Int64
	// maxWeightedEntries bounds live entries one weighted (key, window) may hold,
	// mirroring InMemory. Defaults to MaxWeightedEntriesPerKey; lowered only by tests.
	maxWeightedEntries int
}

// redisOption configures the Redis counter. Unexported: its only use (a custom clock) is
// for deterministic tests, reached externally via WithRedisTimeFunc in export_test.go.
type redisOption func(*Redis)

// withTimeFunc sets a custom time function so the same-tick collision regression
// can be tested deterministically.
func withTimeFunc(fn func() time.Time) redisOption {
	return func(r *Redis) {
		r.now = fn
	}
}

// withRedisMaxWeightedEntries lowers the per-key weighted retention ceiling, so a test
// can reach it without writing MaxWeightedEntriesPerKey entries.
func withRedisMaxWeightedEntries(n int) redisOption {
	return func(r *Redis) {
		r.maxWeightedEntries = n
	}
}

// redisWindowKey is the Redis key for one (key, windowSec) counter's sorted set. Built on
// storageKey — the in-memory backend's identical composition — rather than a second
// fmt.Sprintf, so the two backends cannot silently diverge on how a pair collapses to a string.
func redisWindowKey(key string, windowSec int) string {
	return "callcounter:" + storageKey(key, windowSec)
}

// newMember builds a unique sorted-set member: instance id, nanosecond timestamp, and
// sequence number, zero-padded so lexicographic order matches insertion order for
// same-score entries (an unpadded tie could let rank-trimming discard the newest member).
func (r *Redis) newMember(now time.Time) string {
	return fmt.Sprintf("%s-%020d-%020d", r.instanceID, now.UnixNano(), r.seq.Add(1))
}

// ErrClusterUnsupported is returned by NewRedis for a client that spreads ONE keyspace across
// several servers: a Redis Cluster, or a client-side Ring.
//
// AdmitAll is a single multi-key EVAL, and a batch's keys carry distinct window suffixes, so
// they can hash to different slots and the script is refused with CROSSSLOT. That fails
// closed — the engine maps the error to a deny, never an over-admission — which is precisely
// why it must be refused at the seam: nothing is unsafe, so the wiring error stays invisible
// until the first policy carrying two quota buckets denies in production. Worse, unrelated
// suffixes may collide into one slot by chance, so a deployment can look healthy across
// several policies and then deny on the next one.
//
// Making it WORK instead would mean co-locating one anchor's buckets in a slot, which is a
// physical key-layout change (a migration resetting live counters) on a key that is opaque by
// construction: CompositeKey is injective but not parseable, so a hash tag cannot be recovered
// from the logical key a bucket arrives with. Until that is worth doing, this is the posture.
var ErrClusterUnsupported = errors.New("callcounter: Redis Cluster and Ring clients are not supported: a multi-bucket admission is one multi-key EVAL whose keys can hash to different slots (CROSSSLOT); wire a single-node or Sentinel-backed *redis.Client")

// ShardFanOut visits every server a sharding client spreads its keyspace over, running fn
// against each. It is what a KEYLESS command (SCAN) needs there: routed to one server it
// enumerates one shard of several and reports success.
type ShardFanOut func(ctx context.Context, fn func(ctx context.Context, node *redis.Client) error) error

// ShardIterator returns the per-server iterator for a client that spreads one keyspace across
// several servers, and nil for one that keeps it on a single server. Matched on the CONCRETE
// type — a decorator (a hooked client, a custom Cmdable) can still wrap one — so it catches
// the ordinary wiring mistake rather than proving the topology.
//
// Exported because the topology is not only this package's question: pkg/killswitch fans a
// keyless SCAN out per server for the same reason. It returns the ITERATOR rather than a
// yes/no, and is the ONLY entry point to either answer, because two — a predicate beside an
// iterator — is how they drifted before (one list named Ring, the other did not, so a Ring fell
// through to a single-node SCAN that loaded whichever shard go-redis picked). "Does it shard"
// is `ShardIterator(c) != nil`, which cannot disagree with what the caller then iterates.
func ShardIterator(client redis.Cmdable) ShardFanOut {
	switch c := client.(type) {
	case *redis.ClusterClient:
		// Masters only: a replica holds the same keys, so scanning them would double the work
		// and, mid-failover, disagree with its master about what is there.
		return c.ForEachMaster
	case *redis.Ring:
		return c.ForEachShard
	}
	return nil
}

// ServerInfoReader is the one command CheckServerNotClustered issues. A narrow parameter type
// so a caller can drive the check with a canned reply, since standing up a cluster in a test
// is not a thing that can be done from Go.
type ServerInfoReader interface {
	Info(ctx context.Context, section ...string) *redis.StringCmd
}

// CheckServerNotClustered refuses a single-node client aimed at a node of a Redis Cluster.
// It is the SERVER-side half of the refusal ShardIterator makes client-side: an ordinary
// *redis.Client passes every type check and still cannot run AdmitAll's multi-key EVAL.
//
// It reads `INFO cluster` — not `CLUSTER INFO`, whose reply carries no cluster_enabled field
// at all (that lives only in INFO's Cluster section), and which a standalone server refuses
// outright, so a check written against it could never fire in either direction.
//
// A server that cannot answer INFO (an emulator, a proxy, an ACL that denies it) is treated as
// unclustered, since the alternative is refusing to start against every Redis-protocol server
// that answers the commands eunox actually issues. That branch is inconclusive rather than
// safe, which is why AdmitAll also maps a CROSSSLOT back to this error at request time.
func CheckServerNotClustered(ctx context.Context, client ServerInfoReader) error {
	info, err := client.Info(ctx, "cluster").Result()
	if err != nil || !strings.Contains(info, "cluster_enabled:1") {
		return nil
	}
	return fmt.Errorf("%w (the server at the configured address reports cluster_enabled:1)", ErrClusterUnsupported)
}

// NewRedis creates a Redis-backed call counter. It fails rather than returning a counter that
// cannot admit: on a keyspace-sharding client (ErrClusterUnsupported), or when crypto/rand
// cannot supply the per-instance entropy for ZADD member uniqueness — a silent fallback there
// would risk reintroducing the cross-replica collision the entropy prevents.
func NewRedis(client redis.Cmdable, opts ...redisOption) (*Redis, error) {
	// "Spreads the keyspace" IS "there is a per-server iterator for it": one list, so this
	// refusal and pkg/killswitch's fan-out cannot disagree about a client shape.
	if ShardIterator(client) != nil {
		return nil, fmt.Errorf("%w (got %T)", ErrClusterUnsupported, client)
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, fmt.Errorf("callcounter: crypto/rand unavailable: %w", err)
	}
	r := &Redis{
		client:             client,
		now:                time.Now,
		instanceID:         hex.EncodeToString(b[:]),
		maxWeightedEntries: MaxWeightedEntriesPerKey,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r, nil
}

// IncrementAndGet atomically records a call via a MULTI/EXEC transaction, returning the
// in-window count capped at maxEntries by trimming to the newest members, mirroring InMemory.
func (r *Redis) IncrementAndGet(ctx context.Context, key string, windowSec, maxEntries int) (int64, error) {
	// An overflowing windowSec wraps the Expire to a non-positive TTL, expiring the key
	// immediately and resetting the counter every call (fail-open); see checkMaxEntries.
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

	pipe := r.client.TxPipeline()
	pipe.ZRemRangeByScore(ctx, windowKey, "-inf", strconv.FormatInt(cutoff, 10))
	pipe.ZAdd(ctx, windowKey, redis.Z{Score: float64(nowUnixMicro), Member: member})
	// Drop all but the highest-scored maxEntries members (negative stop leaves the top
	// untouched below the cap), keeping the newest as InMemory does. int64 so
	// maxEntries+1 cannot wrap to a no-op trim (checkMaxEntries caps at math.MaxInt32).
	pipe.ZRemRangeByRank(ctx, windowKey, 0, -(int64(maxEntries) + 1))
	countCmd := pipe.ZCard(ctx, windowKey)
	// cleanupMarginFactor margin (not +1s) so window-start entries are not evicted before
	// the ZREMRANGEBYSCORE cleanup fires under high app/Redis clock skew.
	pipe.Expire(ctx, windowKey, time.Duration(windowSec)*cleanupMarginFactor*time.Second)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("redis pipeline: %w", err)
	}
	// Defence in depth: a command error inside EXEC (e.g. WRONGTYPE) leaves countCmd.Val()
	// at zero, which would fail open by reporting no in-window calls if not re-checked.
	if err := countCmd.Err(); err != nil {
		return 0, fmt.Errorf("redis pipeline ZCard: %w", err)
	}

	return countCmd.Val(), nil
}

// admitAllScript is the multi-bucket admission: prunes and totals every bucket under its
// own accounting, and ZADDs into all of them only if EVERY bucket has headroom — otherwise
// records nothing and reports the first blocker. Check-and-commit in one script makes a
// multi-condition admission atomic, so mixing counted (ZCARD) and weighted (summed) buckets
// lets e.g. "20 refunds/hour AND $2,000/hour" be one atomic decision instead of two.
//
//	KEYS[i]               sorted-set key for bucket i (1..#KEYS)
//	ARGV[1]               now (microseconds; score for new members)
//	ARGV[2+(i-1)*7 .. +7] per-bucket: cutoff, member, limit, ttlSec, windowMicros, counted, weight
//	ARGV[#ARGV]           maxWeightedEntries (per-key weighted retention ceiling; 0 = unbounded)
//
// Reply: {admitted (1|0), deniedIndex (1-based; 0 when admitted), total (string), retryAfterMicros},
// or an ERROR reply when a weighted bucket is at its retention ceiling (the engine denies on it).
//
// total is a STRING, not a Redis integer: it is routinely fractional, and %.17g round-trips
// a float64 exactly where Lua's own tostring (%.14g) would silently round it in the upper
// range MaxWeightedTotal admits. Timestamps are MICROSECONDS throughout (Lua numbers are
// float64, exact only to 2^53).
var admitAllScript = redis.NewScript(`
local now = tonumber(ARGV[1])
local n = #KEYS
local totals = {}
local counts = {}
-- Positional, not ARGV[#ARGV]: omitting the trailing argument would make #ARGV land on the
-- last bucket's WEIGHT instead. Indexing past the block yields nil, so a direct caller
-- missing it fails closed and diagnosably.
local maxWeightedEntries = tonumber(ARGV[2 + n*7])
if maxWeightedEntries == nil then
  return redis.error_reply('callcounter: admitAll requires the trailing weighted-entry ceiling argument')
end
local denied = 0

local function entry_weight(m)
  local sep = string.find(m, '|', 1, true)
  if sep then return tonumber(string.sub(m, sep + 1)) or 1 end
  return 1
end

local function refresh_ttls()
  -- Refresh TTL on every non-admitting path too, or a bucket that's never admitted could
  -- expire mid-window and silently reset. EXISTS-gated: refresh, never re-create.
  for i = 1, n do
    local base = 1 + (i-1)*7
    if redis.call('EXISTS', KEYS[i]) == 1 then
      redis.call('EXPIRE', KEYS[i], ARGV[base+4])
    end
  end
end

for i = 1, n do
  local base = 1 + (i-1)*7
  redis.call('ZREMRANGEBYSCORE', KEYS[i], '-inf', ARGV[base+1])
  local counted = tonumber(ARGV[base+6])
  local total = 0
  if counted == 1 then
    total = redis.call('ZCARD', KEYS[i])
    counts[i] = total
  else
    local entries = redis.call('ZRANGE', KEYS[i], 0, -1)
    counts[i] = #entries
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
  refresh_ttls()
  local base = 1 + (denied-1)*7
  local counted = tonumber(ARGV[base+6])
  local limit = tonumber(ARGV[base+3])
  local weight = tonumber(ARGV[base+7])
  if counted == 1 then weight = 1 end
  local total = totals[denied]
  local retry = 0
  if counted == 1 then
    -- The last entry to age out is the (total-limit)-th oldest; read it directly rather
    -- than walking, so a large quota does not pay a linear scan on the deny path.
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

-- Every bucket has headroom. Before writing ANY of them, check the weighted retention
-- ceiling across the whole batch, so the commit stays all-or-nothing against it too --
-- a weighted bucket's entry count is not bounded by its own limit. Nothing has been
-- written yet, so an error reply here has no partial commit to undo.
if maxWeightedEntries > 0 then
  for i = 1, n do
    local base = 1 + (i-1)*7
    local counted = tonumber(ARGV[base+6])
    local weight = tonumber(ARGV[base+7])
    if counted ~= 1 and (totals[i] + weight) ~= totals[i] and (counts[i] + 1) > maxWeightedEntries then
      refresh_ttls()
      return redis.error_reply('callcounter: weighted entry limit reached (' .. maxWeightedEntries .. ' entries in one window)')
    end
  end
end

local maxTotal = 0
for i = 1, n do
  local base = 1 + (i-1)*7
  local counted = tonumber(ARGV[base+6])
  local weight = tonumber(ARGV[base+7])
  if counted == 1 then weight = 1 end
  local post = totals[i] + weight
  -- A weight that cannot move the total is admitted WITHOUT being recorded -- it could
  -- never affect a future decision, and recording it would grow a key without bound.
  if post ~= totals[i] then
    redis.call('ZADD', KEYS[i], now, ARGV[base+2])
  end
  redis.call('EXPIRE', KEYS[i], ARGV[base+4])
  if post > maxTotal then maxTotal = post end
end
-- Report the maximum post-admission total across buckets, mirroring InMemory (no single
-- binding bucket on admit).
return {1, 0, string.format('%.17g', maxTotal), 0}
`)

// AdmitAll admits against several quota buckets atomically, mixing counted and weighted
// accountings in one script (see admitAllScript). This is the multi-key EVAL that makes a
// sharded keyspace unusable: NewRedis refuses a sharding CLIENT and CheckServerNotClustered
// refuses a single-node client aimed at a cluster NODE, but the second is a probe that can be
// inconclusive, so a CROSSSLOT surfacing here is mapped back to ErrClusterUnsupported rather
// than reported as an opaque backend fault at the first two-bucket policy.
func (r *Redis) AdmitAll(ctx context.Context, buckets []capability.QuotaBucket) (admitted bool, deniedIndex int, total float64, retryAfter time.Duration, err error) {
	// checkBuckets is shared with InMemory: without it, two buckets sharing a window key
	// would ZADD two members into one set (double-count), diverging from InMemory.
	if e := checkBuckets(buckets); e != nil {
		return false, 0, 0, 0, e
	}

	now := r.now()
	redisKeys := make([]string, len(buckets))
	argv := make([]interface{}, 0, 2+7*len(buckets))
	argv = append(argv, now.UnixMicro())
	for i := range buckets {
		b := &buckets[i]
		redisKeys[i] = redisWindowKey(b.Key, b.WindowSec)
		cutoff := now.Add(-time.Duration(b.WindowSec) * time.Second).UnixMicro()
		windowMicros := int64(b.WindowSec) * 1_000_000
		ttlSec := int64(b.WindowSec) * cleanupMarginFactor
		counted := 0
		// A counted bucket's member carries NO weight suffix, so a later weighted read of
		// the same key reads it as 1.
		member := r.newMember(now)
		if b.Counted {
			counted = 1
		} else {
			member = r.newWeightedMember(now, b.Weight)
		}
		argv = append(argv, cutoff, member, b.Limit, ttlSec, windowMicros, counted, b.Weight)
	}
	// Trailing, batch-wide (not an eighth per-bucket field): the ceiling is one package
	// invariant, not a per-bucket property.
	argv = append(argv, r.maxWeightedEntries)

	res, runErr := admitAllScript.Run(ctx, r.client, redisKeys, argv...).Result()
	if runErr != nil {
		if isCrossSlot(runErr) {
			// Self-diagnosing: the startup probe swallows an unanswerable INFO, so this is the
			// only place a keyspace that shards can still announce itself. Still a deny.
			return false, 0, 0, 0, fmt.Errorf("%w: %v", ErrClusterUnsupported, runErr)
		}
		return false, 0, 0, 0, fmt.Errorf("redis eval: %w", runErr)
	}
	return parseAdmitAllReply(res)
}

// isCrossSlot reports whether err is Redis refusing a multi-key command across hash slots.
//
// Two spellings because two producers: errors.Is catches the sentinel go-redis raises itself,
// HasErrorPrefix the server's own reply. Both are type-checked rather than text-matched — a
// strings.Contains is a contract with formatting, which reads an unrelated error mentioning the
// word as a topology refusal and stops recognizing a prefixed one.
func isCrossSlot(err error) bool {
	return errors.Is(err, redis.ErrCrossSlot) || redis.HasErrorPrefix(err, "CROSSSLOT")
}

// parseAdmitAllReply decodes admitAllScript's reply, converting the 1-based deniedIndex to
// 0-based. Each element is type-checked so a changed encoding fails closed with a
// structured error rather than defaulting to a zero value that would read as unspent budget.
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

// weightMemberSep separates a member's uniqueness prefix from its WEIGHT. One key holds
// both the timestamp (score) and magnitude (suffix), so the weight ages out atomically with
// its entry. The separator is a byte newMember's hex/digit/'-' prefix cannot contain; a
// member WITHOUT it is a plain counted call and reads as weight 1.
const weightMemberSep = "|"

// newWeightedMember builds a member carrying newMember's uniqueness plus this call's
// weight. 'g' with -1 precision emits the shortest form round-tripping through Lua's
// tonumber, so the script sums a bit-identical weight.
func (r *Redis) newWeightedMember(now time.Time, weight float64) string {
	return r.newMember(now) + weightMemberSep + strconv.FormatFloat(weight, 'g', -1, 64)
}

// Peek returns the entry count for key within the window WITHOUT adding one. windowSec
// must match the recording value so the same sorted-set bucket is consulted; the engine
// uses sequenceHistoryWindowSec for both, so they agree.
func (r *Redis) Peek(ctx context.Context, key string, windowSec int) (int64, error) {
	if err := checkWindowSec(windowSec); err != nil {
		return 0, err
	}

	now := r.now()
	windowKey := redisWindowKey(key, windowSec)
	// Integer-microsecond cutoff, matching the mutating paths.
	cutoff := now.Add(-time.Duration(windowSec) * time.Second).UnixMicro()

	// The "(" prefix makes the lower bound exclusive, matching the mutating path's
	// drops-scores-<=-cutoff predicate; ZCOUNT's default inclusive bound would keep stale
	// history alive at the window edge.
	count, err := r.client.ZCount(ctx, windowKey, "("+strconv.FormatInt(cutoff, 10), "+inf").Result()
	if err != nil {
		return 0, fmt.Errorf("redis zcount: %w", err)
	}
	return count, nil
}
