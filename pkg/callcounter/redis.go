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

	"github.com/eunolabs/eunox/internal/redisutil"
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
	// declared is the consumer's own answer to the topology question, for a client whose concrete
	// type cannot answer it; TopologyUnknown (the zero value) means nobody answered, which is why
	// no option ever sets it. Weighed against the classification in resolveTopology, never applied
	// over it — so it is construction-time INPUT and never the resolved answer. The resolution is
	// deliberately not retained: nothing below the constructor needs a topology, a counter having
	// no keyless command to route, and a stored copy nothing reads is a second answer to drift.
	declared redisutil.Topology
}

// RedisOption configures the Redis counter.
type RedisOption func(*Redis)

// WithSingleNodeKeyspace declares that a client this package cannot classify keeps its WHOLE
// keyspace on one server, so AdmitAll's multi-key EVAL reaches every key it names.
//
// The escape hatch for a legitimate forwarding wrapper: a consumer's own Cmdable over a plain
// *redis.Client is invisible to a concrete-type match, and without this NewRedis refuses it with
// ErrUnknownTopology. It FILLS an unknown topology and cannot override a known one — declared
// beside a client whose own type shards, it is refused (ErrTopologyContradicted) rather than
// honored, because honoring it would restore exactly the split accounting the refusal prevents.
//
// TWO residuals, stated rather than papered over, both because nothing here verifies the claim:
//
//   - Declared over a wrapper that actually fronts a Ring, it reproduces the split accounting in
//     full — silently, with no CROSSSLOT and nothing on the audit tape. Declare it only for a
//     wrapper you know fronts one server, and run CheckKeyspaceCoLocated at startup to CHECK that
//     rather than assert it: this constructor performs no I/O, so it cannot. There is no way to
//     say "sharded" here, because a multi-key EVAL cannot run over shards at all (unlike the kill
//     switch's keyless SCAN, whose WithShardFanOut has somewhere to go).
//   - Declared over a wrapper holding a NIL client, it constructs: IsNilClient answers for a
//     client that IS nil, not for a wrapper around one, and this is the only remaining way past
//     that guard. The first admission then panics inside go-redis rather than failing closed.
//
// Named as pkg/killswitch's identically-named option is, so a consumer wiring both backends on one
// wrapped client spells the answer the same way twice. Spelling only: the two declarations are
// unrelated types on unrelated structs and nothing cross-checks them, so a wrapper declared
// single-node here and sharded there is accepted by both.
func WithSingleNodeKeyspace() RedisOption {
	return func(r *Redis) {
		r.declared = redisutil.TopologySingleNode
	}
}

// withTimeFunc sets a custom time function so the same-tick collision regression
// can be tested deterministically.
func withTimeFunc(fn func() time.Time) RedisOption {
	return func(r *Redis) {
		r.now = fn
	}
}

// withRedisMaxWeightedEntries lowers the per-key weighted retention ceiling, so a test
// can reach it without writing MaxWeightedEntriesPerKey entries.
func withRedisMaxWeightedEntries(n int) RedisOption {
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
// AdmitAll is a single multi-key EVAL, and a batch's keys carry distinct window suffixes, so a
// SERVER-side cluster hashes them to different slots and refuses the script with CROSSSLOT. That
// fails closed — the engine maps the error to a deny, never an over-admission — which is precisely
// why it must still be refused at the seam: nothing is unsafe, so the wiring error stays invisible
// until the first policy carrying two quota buckets denies in production. Worse, unrelated
// suffixes may collide into one slot by chance, so a deployment can look healthy across
// several policies and then deny on the next one.
//
// CLIENT-side sharding is the worse half and has no such backstop. A *redis.Ring spreads one
// keyspace over STANDALONE servers, none of which knows about hash slots: go-redis routes an EVAL
// by its FIRST key, so the whole multi-key script runs on that one shard, successfully. A bucket
// appearing in two batches under different first keys then accrues on two servers, each seeing
// part of the spend, and its maxCalls or cumulative blastRadius bound is enforced at up to N times
// its declared value — silently, on the decision path. Nothing at request time can announce that,
// which is why an UNRECOGNIZED client is refused too (see ErrUnknownTopology) rather than admitted
// on the strength of the CROSSSLOT above.
//
// Making it WORK instead would mean co-locating one anchor's buckets in a slot, which IS available
// and is not being done for one honest reason: it resets every live counter. Nothing needs to
// recover a hash tag from the opaque key a bucket arrives with — pkg/enforcement's anchoredKey
// splices the anchor in where the key is BUILT, so a `{...}` tag is emittable one layer up, and
// go-redis applies hashtag.Key on a client-side Ring as well as a Cluster, so one tag would fix
// both sharding shapes and retire this refusal outright. What it costs is a physical key-layout
// change across two packages plus a migration that drops every in-flight window on the floor.
// Until that is worth doing, this is the posture.
var ErrClusterUnsupported = errors.New("callcounter: Redis Cluster and Ring clients are not supported: a multi-bucket admission is one multi-key EVAL whose keys can hash to different slots (CROSSSLOT); wire a single-node or Sentinel-backed *redis.Client")

// ErrUnknownTopology is returned by NewRedis for a client whose KEYSPACE TOPOLOGY cannot be
// established: a concrete type redisutil does not recognize, which is a consumer's own Cmdable or
// a hand-rolled wrapper forwarding to one. NOT go-redis' own instrumentation — redisotel and the
// Prometheus hooks go through (*Client).AddHook, which leaves the concrete type alone, so an
// instrumented *redis.Client still classifies single-node and is unaffected by this refusal.
//
// Refused rather than assumed single-node, because assuming is fail-OPEN and silent: a wrapper
// around a Ring is indistinguishable here from one around a single-node client, and the Ring case
// splits a quota bucket's accounting across servers with no request-time signal at all — see
// ErrClusterUnsupported for the routing that does it, and for why the CROSSSLOT backstop covers
// only the server-side half.
//
// A consumer whose wrapper fronts ONE server says so with WithSingleNodeKeyspace(), which is the
// escape hatch this refusal is only tolerable with: it refuses a wrapper around a perfectly
// ordinary single-node client until its consumer says so, in exchange for never over-admitting a
// quota silently. NewRedis performs no I/O, so that declaration is BELIEVED rather than checked —
// CheckKeyspaceCoLocated is the startup probe that checks it, and a consumer reaching for the
// escape hatch should run it.
var ErrUnknownTopology = errors.New("callcounter: the Redis client's keyspace topology cannot be determined (a custom Cmdable, or a wrapper forwarding to one); refusing, since a client-side-sharding wrapper splits one quota bucket's accounting across servers and enforces its limit at a multiple of the declared value. Pass the client itself; or, ONLY if the wrapper fronts a single server, declare that with callcounter.WithSingleNodeKeyspace() and verify it at startup with callcounter.CheckKeyspaceCoLocated. A wrapper fronting a Cluster or a Ring has no supported declaration here and must not be declared single-node — this counter cannot admit against a sharded keyspace at all")

// ErrTopologyContradicted is returned for a topology DECLARATION that disagrees with what the
// client's own concrete type establishes — WithSingleNodeKeyspace() beside a *redis.Ring, say.
//
// Refused rather than obeyed, because obeying is the fail-open: a declaration exists to FILL what
// a concrete-type match cannot answer, and letting one override an answer it CAN give would
// re-admit the split accounting ErrUnknownTopology was added to stop, reached through the very
// option that makes that refusal tolerable. Construction is refused either way here, a sharding
// client being unusable regardless — but the DIAGNOSIS is not the same: a consumer who declared
// single-node needs to be told their declaration disagrees with their client, not to be told to
// wire the single-node client they believe they already wired.
var ErrTopologyContradicted = errors.New("callcounter: the declared keyspace topology contradicts the Redis client's own type (drop the declaration, or pass the client the declaration describes)")

// ServerInfoReader is the one command CheckServerNotClustered issues. A narrow parameter type
// so a caller can drive the check with a canned reply, since standing up a cluster in a test
// is not a thing that can be done from Go.
type ServerInfoReader interface {
	Info(ctx context.Context, section ...string) *redis.StringCmd
}

// CheckServerNotClustered refuses a single-node client aimed at a node of a Redis Cluster.
// It is the SERVER-side half of the refusal redisutil.ClassifyTopology makes client-side: an
// ordinary *redis.Client is classified single-node and still cannot run AdmitAll's multi-key
// EVAL when the server behind it is a cluster node.
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

// KeyspaceProbeClient is the command set CheckKeyspaceCoLocated issues. A narrow parameter type,
// as ServerInfoReader is: a consumer's own wrapper satisfies it by forwarding, which is the point —
// the probe asks the CLIENT what it does, where the construction refusal can only read its type.
type KeyspaceProbeClient interface {
	redis.Scripter
	Exists(ctx context.Context, keys ...string) *redis.IntCmd
	Del(ctx context.Context, keys ...string) *redis.IntCmd
}

// keyspaceProbeKeys is how many keys one probe writes in a single EVAL. A client-side-sharding
// client is caught unless every probe key hashes to one shard, which for k shards is k^(1-n) — at
// 16 keys and two shards, ~3e-5, and lower for a wider ring. Not free (one EVAL plus n EXISTS and
// n DEL), but this is a startup check a consumer runs once.
const keyspaceProbeKeys = 16

// probeScript writes every key it is handed, so a client that routes the whole script by its first
// key writes them all to one server. Values are irrelevant; only WHERE they land is.
var probeScript = redis.NewScript(`
for i = 1, #KEYS do
  redis.call('SET', KEYS[i], '1', 'EX', tonumber(ARGV[1]))
end
return 1
`)

// CheckKeyspaceCoLocated verifies that a multi-key script actually reaches every key it names —
// the property AdmitAll depends on and WithSingleNodeKeyspace only ASSERTS.
//
// A declaration is believed, not checked, so a consumer who declares single-node over a wrapper
// that in fact fronts a Ring gets exactly the split accounting the refusal exists to prevent, with
// no CROSSSLOT and nothing on the tape. This is how they check it. Run it once at startup against
// the same client passed to NewRedis, as CheckServerNotClustered is run.
//
// It writes keyspaceProbeKeys short-lived keys in ONE script and then reads each back
// INDIVIDUALLY, so each read routes on its own key. On one keyspace every key is found. On a
// client that shards — client-side, where no CROSSSLOT is ever raised, or through a proxy fronting
// a sharded backend, which INFO reports as a plain server — the script ran wholly on the first
// key's shard and the keys that hash elsewhere are missing.
//
// INCONCLUSIVE IS SAFE, as it is for CheckServerNotClustered: a client that cannot run the script
// or answer EXISTS (an emulator, an ACL, a proxy that refuses EVAL) reports nothing rather than
// refusing to start against every Redis-protocol server. What it reports positively is a MISS, and
// a miss is re-probed once with fresh keys before it is believed — a shard placement repeats for
// new keys where an eviction under memory pressure does not, which is the one way a single
// keyspace can lose a key between the write and the read.
//
// Cleanup is per-key DEL (always slot-safe) and best-effort; every key carries a TTL regardless.
func CheckKeyspaceCoLocated(ctx context.Context, client KeyspaceProbeClient) error {
	missing, err := probeKeyspace(ctx, client)
	if err != nil || missing == 0 {
		// A probe that could not run says nothing: see INCONCLUSIVE IS SAFE above.
		return nil //nolint:nilerr // an unrunnable probe is inconclusive, not a refusal
	}
	// Fresh keys: a sharded keyspace misses again, an evicted key does not.
	if missing, err = probeKeyspace(ctx, client); err != nil || missing == 0 {
		return nil //nolint:nilerr // same
	}
	return fmt.Errorf("%w (a script writing %d keys at once left %d of them unreachable to a per-key read, so this client does not keep one keyspace on one server)",
		ErrClusterUnsupported, keyspaceProbeKeys, missing)
}

// probeKeyspace runs one round of the probe, returning how many of its keys a per-key read could
// not find. An error means the round could not be run at all, which its caller reads as
// inconclusive rather than as a verdict.
func probeKeyspace(ctx context.Context, client KeyspaceProbeClient) (int, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("callcounter: crypto/rand unavailable: %w", err)
	}
	// Random per round so two instances probing at once cannot read each other's keys, and so the
	// second round genuinely re-hashes rather than repeating the first round's placement.
	prefix := "callcounter:keyspace-probe:" + hex.EncodeToString(b[:]) + ":"
	keys := make([]string, keyspaceProbeKeys)
	for i := range keys {
		keys[i] = prefix + strconv.Itoa(i)
	}
	// Cleanup is per-key: a multi-key DEL is refused CROSSSLOT on a cluster, which would turn
	// tidying up into an error on the one topology the probe most needs to survive.
	defer func() {
		for _, k := range keys {
			_ = client.Del(ctx, k).Err()
		}
	}()

	if err := probeScript.Run(ctx, client, keys, keyspaceProbeTTLSec).Err(); err != nil {
		// A CROSSSLOT here is a SERVER-side cluster answering the question directly, which is a
		// verdict rather than an inconclusive round.
		if isCrossSlot(err) {
			return len(keys), nil
		}
		return 0, fmt.Errorf("callcounter: keyspace probe could not run: %w", err)
	}
	missing := 0
	for _, k := range keys {
		found, err := client.Exists(ctx, k).Result()
		if err != nil {
			return 0, fmt.Errorf("callcounter: keyspace probe could not read back: %w", err)
		}
		if found == 0 {
			missing++
		}
	}
	return missing, nil
}

// keyspaceProbeTTLSec bounds how long a probe key outlives its round, so an interrupted probe
// leaves nothing behind. Generous relative to the read-back that follows immediately.
const keyspaceProbeTTLSec = 60

// NewRedis creates a Redis-backed call counter. It fails rather than returning a counter that
// cannot admit, or one that admits WRONGLY: on a nil client (checked FIRST, so a typed-nil
// sharding handle reports the nil rather than the topology), on a keyspace-sharding client
// (ErrClusterUnsupported), on one whose topology cannot be settled at all (ErrUnknownTopology,
// ErrTopologyContradicted), or when crypto/rand cannot supply the per-instance entropy for ZADD
// member uniqueness — a silent fallback there would risk reintroducing the cross-replica
// collision the entropy prevents.
func NewRedis(client redis.Cmdable, opts ...RedisOption) (*Redis, error) {
	// A nil client — including a typed nil inside a non-nil interface — is refused at the seam
	// rather than at the first command: go-redis dereferences the receiver before it can build a
	// reply, so every command panics instead of returning the error a counter's callers fail
	// closed on. A DECORATOR wrapping a nil client is not caught here; see IsNilClient's scope
	// for why probing for it would refuse working wrappers.
	if redisutil.IsNilClient(client) {
		return nil, fmt.Errorf("callcounter: nil Redis client (got %T)", client)
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, fmt.Errorf("callcounter: crypto/rand unavailable: %w", err)
	}
	// instanceID is set HERE rather than after the options, even though the topology cannot be
	// settled until they have run: RedisOption is exported, so an option receives this *Redis, and
	// newMember interpolates instanceID into every ZADD member — a counter reachable without it
	// emits the collidable member the entropy exists to prevent.
	r := &Redis{
		client:             client,
		now:                time.Now,
		instanceID:         hex.EncodeToString(b[:]),
		maxWeightedEntries: MaxWeightedEntriesPerKey,
	}
	for _, opt := range opts {
		// A nil option is refused rather than called: the type is exported, so a caller assembling
		// a slice conditionally can hold one, and a nil func call is a panic inside the fail-closed
		// seam every other bad input to this constructor is refused at.
		if opt == nil {
			return nil, errors.New("callcounter: nil RedisOption")
		}
		opt(r)
	}
	// Settled AFTER the options, a declaration being one of the two inputs resolveTopology weighs
	// rather than an override applied to a decided answer.
	if err := r.resolveTopology(); err != nil {
		return nil, err
	}
	return r, nil
}

// resolveTopology settles how the client spreads its keyspace, from what its concrete type
// establishes and what the consumer declared, refusing when the two cannot be settled into one
// answer this counter can admit against. See ErrUnknownTopology and ErrTopologyContradicted for
// what each refusal is for.
//
// The fills-never-overrides rule itself is redisutil.Reconcile's, shared with pkg/killswitch so
// the two backends cannot drift on it; what stays here is the part that is this counter's alone —
// nilness first, and a settled SHARDED keyspace refused rather than used.
func (r *Redis) resolveTopology() error {
	// Nilness first, and asked here rather than left to NewRedis's own guard: a nil client
	// classifies UNKNOWN, which is exactly the value a declaration fills, so without this arm a
	// declared nil handle settles as single-node and every command on it panics inside go-redis.
	// A resolver that is only correct when its caller checked first is one a second construction
	// path gets wrong.
	if redisutil.IsNilClient(r.client) {
		return fmt.Errorf("callcounter: nil Redis client (got %T)", r.client)
	}
	classified, _ := redisutil.ClassifyTopology(r.client)
	// No fan-out on either side: this counter runs no keyless command, so a sharded keyspace is
	// refused rather than iterated and an iterator would be a field nothing could use.
	resolved, outcome := redisutil.Reconcile(
		redisutil.Resolution{Topology: classified},
		redisutil.Resolution{Topology: r.declared},
	)
	switch outcome {
	case redisutil.ReconcileUndetermined:
		return fmt.Errorf("%w (got %T)", ErrUnknownTopology, r.client)
	case redisutil.ReconcileContradicted:
		// The concrete type, as its siblings carry it: the remedy is "pass the client the
		// declaration describes", and a Ring and a ClusterClient need different ones.
		return fmt.Errorf("%w: declared %s, but the client's own type is %s (got %T)", ErrTopologyContradicted, r.declared, classified, r.client)
	case redisutil.ReconcileSettled:
	}
	if resolved.Topology == redisutil.TopologySharded {
		return fmt.Errorf("%w (got %T)", ErrClusterUnsupported, r.client)
	}
	return nil
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
// sharded keyspace unusable: NewRedis refuses a sharding CLIENT and one it cannot place at all,
// and CheckServerNotClustered refuses a single-node client aimed at a cluster NODE, but the last
// is a probe that can be inconclusive, so a CROSSSLOT surfacing here is mapped back to
// ErrClusterUnsupported rather than reported as an opaque backend fault at the first two-bucket
// policy.
//
// One escape has NO signal here and cannot get one: a wrapper that fronts a Ring and was declared
// single-node (WithSingleNodeKeyspace). Its shards are standalone servers, so the script runs
// whole on the first key's shard and succeeds — the buckets simply accrue in the wrong places.
// That is why the construction refusal, not this backstop, is the load-bearing half.
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
			// Self-diagnosing: the startup probe swallows an unanswerable INFO, so this is the last
			// place a SERVER-side cluster can still announce itself. Client-side sharding announces
			// itself nowhere (see this method's doc), which is what the construction refusals are
			// for. Still a deny.
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
