// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Package redisutil answers the one go-redis question more than one eunox backend has to ask:
// which client types spread a single keyspace over several servers, and how each one is
// enumerated per server.
//
// It lives here, below both consumers, rather than in either of them. pkg/callcounter refuses a
// sharding client because AdmitAll is a multi-key EVAL; pkg/killswitch fans a keyless SCAN out
// per server. Neither reason belongs to the other package, and hosting the pair in one of them
// made the other link that package's EVAL scripts and instance-id machinery for a type switch —
// and put the next topology question (a Sentinel failover client, a UniversalClient wrapper)
// in a package with no reason to know a keyless SCAN exists.
//
// What it answers is what a CONCRETE TYPE proves, which is why an unrecognized one is a value of
// its own rather than a default. Both consumers refuse it, for the same reason in two shapes: a
// keyless SCAN routed to one server of several loads a PARTIAL kill set and serves it as complete,
// and a multi-key EVAL routed to one server of several splits a quota bucket's accounting and
// enforces its limit at a multiple of the declared value. Neither announces itself — client-side
// sharding raises no CROSSSLOT, the shards being standalone servers — so both are fail-open and
// silent, and each package offers a declaring option for the consumer who knows what their
// decorator wraps.
package redisutil

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync/atomic"

	"github.com/redis/go-redis/v9"
)

// ShardFanOut visits every server a sharding client spreads its keyspace over, running fn
// against each. It is what a KEYLESS command (SCAN) needs there: routed to one server it
// enumerates one shard of several and reports success.
//
// EVERY server, not merely every reachable one: an iterator that quietly covers less than the
// whole keyspace hands its caller a partial result indistinguishable from a complete one, which
// for the kill switch is a partial kill set served as complete. An iterator that cannot cover
// them all returns ErrIncompleteFanOut rather than nil.
type ShardFanOut func(ctx context.Context, fn func(ctx context.Context, node *redis.Client) error) error

// ErrIncompleteFanOut reports an enumeration that covered FEWER servers than the client spreads
// its keyspace over, so its result is a partial view rather than the whole one.
//
// It exists because go-redis' Ring iterator does not say so itself: (*redis.Ring).ForEachShard
// skips a shard its heartbeat has voted down and returns nil, where (*ClusterClient).ForEachMaster
// propagates both the state reload and the per-node error. A caller reading a keyless SCAN through
// the silent version loads the surviving shards' keys, commits them as authoritative, and reports
// healthy — the same fail-open TopologyUnknown exists to refuse, one layer down and reached after
// the topology was correctly established.
var ErrIncompleteFanOut = errors.New("redisutil: shard enumeration covered fewer servers than the client is configured with, so its result is a PARTIAL view of the keyspace")

// Topology is what this package could establish about how a client spreads its keyspace.
//
// THREE values, not a bool, because the concrete-type match has three outcomes and collapsing
// them loses the one that matters. "Recognized, single server" and "not recognized" both used to
// answer "no iterator", so a decorator wrapping a cluster client enumerated one shard of several
// and reported success — for the kill switch, a partial kill set served as complete, silently, in
// the fail-OPEN direction the Manager contract says a backend must never take.
type Topology int

const (
	// TopologyUnknown is what an unrecognized concrete type establishes — a decorator, or a
	// consumer's own Cmdable. NOTHING follows about the keyspace: it may live on one server or be
	// spread over many, and the two are indistinguishable without proving it over the network.
	// A consumer whose correctness depends on WHICH servers a command reaches — every one of them
	// for a keyless SCAN, all of one command's keys at once for a multi-key EVAL — must refuse
	// this or be told the answer (see the topology-declaring options on pkg/killswitch's and
	// pkg/callcounter's Redis).
	TopologyUnknown Topology = iota
	// TopologySingleNode means the whole keyspace lives on one server, so a keyless command
	// reaches all of it.
	TopologySingleNode
	// TopologySharded means the keyspace is spread across several servers, so a keyless command
	// must be run against each — ClassifyTopology returns the iterator that does so.
	TopologySharded
)

// String renders a topology for an error or a log line.
func (t Topology) String() string {
	switch t {
	case TopologySingleNode:
		return "single-node"
	case TopologySharded:
		return "sharded"
	default:
		return "unknown"
	}
}

// ClassifyTopology reports how client spreads its keyspace and, for a sharding one, the
// per-server iterator a KEYLESS command (SCAN) needs there. Matched on the CONCRETE type: this
// proves nothing about a client it does not recognize, which is exactly what TopologyUnknown
// says and why it is a value rather than an omission.
//
// It is the ONLY entry point to either answer, because two — a predicate beside an iterator — is
// how they drifted before (one list named Ring, the other did not, so a Ring fell through to a
// single-node SCAN that loaded whichever shard go-redis picked). Returning both together makes
// "does it shard" and "what the caller then iterates" one answer.
//
// A TYPED NIL is classified TopologyUnknown with no iterator. A nil *redis.ClusterClient matches
// its arm but its ForEachMaster is a non-nil func value bound to a nil receiver, so without the
// guard the definition hands a caller an iterator that panics inside go-redis the moment it is
// called. The check is ONE precondition rather than a copy per arm, so the next client type added
// to the switch inherits it. It makes a returned iterator callable whenever it is non-nil; it
// does not make the client usable — see IsNilClient for the half that does, which every consumer
// asks first because nilness is the more actionable cause.
func ClassifyTopology(client redis.Cmdable) (Topology, ShardFanOut) {
	if IsNilClient(client) {
		return TopologyUnknown, nil
	}
	switch c := client.(type) {
	case *redis.Client, *redis.Conn:
		// *redis.Client covers the Sentinel-backed failover client too, which NewFailoverClient
		// returns as this type: one master holds the whole keyspace.
		return TopologySingleNode, nil
	case *redis.ClusterClient:
		// Masters only: a replica holds the same keys, so scanning them would double the work
		// and, mid-failover, disagree with its master about what is there.
		//
		// Handed over unwrapped because it already reports an incomplete pass: it fails on the
		// state reload and propagates the first per-node error, so a master it could not visit is
		// an error rather than a shorter loop.
		return TopologySharded, c.ForEachMaster
	case *redis.Ring:
		return TopologySharded, WholeRingFanOut(c)
	}
	return TopologyUnknown, nil
}

// WholeRingFanOut is (*redis.Ring).ForEachShard with the completeness ShardFanOut promises and
// go-redis does not: the library's iterator `continue`s past a shard its heartbeat has voted down
// and returns nil, so a keyless SCAN through the bare version enumerates the survivors and reports
// success. Every consumer of a fan-out is running a command it needs the WHOLE keyspace for, so a
// short pass is an error here rather than a caveat each of them re-derives.
//
// Exported because ClassifyTopology is not the only way a ring reaches a backend: a consumer whose
// ring sits behind a decorator can only DECLARE an iterator, and the one they have to hand is the
// unchecked ForEachShard — so without this the escape hatch reintroduces exactly the fail-open the
// check exists to close. See pkg/killswitch's RingFanOut.
//
// How many servers a pass SHOULD have covered is deliberately not Ring.Len() ALONE, which counts
// the LIVE shards — the same set ForEachShard visits, so comparing a pass against it would be a
// tautology that agrees with itself while a shard is down. It is the ring's CONFIGURED count,
// widened by the widest the ring has ever been observed to be, because (*Ring).SetAddrs reshapes a
// ring WITHOUT writing back to the options: on a ring GROWN at runtime the configured count
// under-counts, and under-counting is the fail-OPEN direction. The high-water mark makes the bound
// monotone — once the ring has been seen at a size, a later pass covering less is short whatever
// the options say.
//
// Two residuals, both stated rather than papered over:
//
//   - A deliberate SHRINK reads as short and is refused. That is the fail-closed direction and it
//     is loud; a consumer who shrinks a ring at runtime is the one who can say what its shards are.
//   - A ring GROWN while a shard is already down is not caught. go-redis rebalances a voted-down
//     shard out of both Len() and the iterator and keeps no memory that it existed, and the
//     configured count is stale by then — so no exported signal distinguishes "grown to 4 with one
//     dead" from "grown to 3". What IS caught is the failure this exists for: a shard that goes
//     down while the ring is in service, at any size the wrapper has already seen.
func WholeRingFanOut(ring *redis.Ring) ShardFanOut {
	// highWater is the widest this ring has been observed. Atomic because nothing serializes two
	// passes: the kill switch's reconcile holds its own mutex, but a Reset enumerating for
	// deletion does not take it.
	var highWater atomic.Int64
	return func(ctx context.Context, fn func(ctx context.Context, node *redis.Client) error) error {
		// Sampled BEFORE the pass as well as after: a shard voted down between this read and the
		// enumeration is exactly a short pass, and reading the live count only afterwards would
		// take the narrowed ring's word for how wide it was supposed to be.
		raiseHighWater(&highWater, int64(ring.Len()))
		// Atomic because ForEachShard runs fn on one goroutine PER SHARD.
		var visited atomic.Int64
		err := ring.ForEachShard(ctx, func(ctx context.Context, node *redis.Client) error {
			visited.Add(1)
			return fn(ctx, node)
		})
		if err != nil {
			return err
		}
		got := int(visited.Load())
		want := max(len(ring.Options().Addrs), int(highWater.Load()))
		switch {
		case got == 0:
			// A pass over NO servers is the degenerate total case of a partial view, and `got <
			// want` accepts it whenever want is 0 too — a ring configured with no addresses
			// classifies as sharded and would enumerate nothing, forever, reporting success.
			return fmt.Errorf("%w: the ring enumerated no servers at all (it has no shards configured, or every shard is down)", ErrIncompleteFanOut)
		case got < want:
			return fmt.Errorf("%w: visited %d of the ring's %d shards (go-redis skips a shard it has voted down and reports no error)", ErrIncompleteFanOut, got, want)
		}
		raiseHighWater(&highWater, int64(got))
		return nil
	}
}

// raiseHighWater raises mark to n if n is larger, leaving it alone otherwise. A CAS loop rather
// than a Store: two concurrent passes must not let the narrower one lower the bound.
func raiseHighWater(mark *atomic.Int64, n int64) {
	for {
		cur := mark.Load()
		if n <= cur || mark.CompareAndSwap(cur, n) {
			return
		}
	}
}

// IsNilClient reports whether client IS nil — the interface itself, or a typed nil value inside
// a non-nil interface.
//
// A backend that must fail closed has to ask, because go-redis answers a nil receiver with a
// PANIC rather than an error: every command method dereferences the receiver before it can
// build a reply, so `(*redis.Client)(nil).Scan(...)` is a nil-pointer dereference, not a
// *ScanCmd carrying an error. On a background goroutine — the kill switch's reconcile loop —
// that is process death, which is neither the fail-closed refusal a broken backend should
// produce nor an outcome an operator can act on.
//
// Reflection rather than a type switch on purpose: a second list of client types is exactly
// what ClassifyTopology exists to prevent, and nilness is one question for every client,
// including one go-redis has not added yet.
//
// It answers for a client that is itself nil, NOT for a decorator WRAPPING one — `hooked{nil}`
// is a non-nil struct under every kind. Reflecting into the embedded field would refuse the
// wrappers that legitimately forward elsewhere, and probing with a command puts a network round
// trip in a constructor that performs none; a false refusal at construction is the worse of the
// two failures, so the gap is accepted.
func IsNilClient(client redis.Cmdable) bool {
	return client == nil || isNilValue(client)
}

// isNilValue reports whether v's DYNAMIC value is a nil of a kind that can be one.
//
// Split out from IsNilClient because it is the half with no go-redis in it: every client type
// eunox meets is pointer-shaped, so the other kinds are unconstructible as a redis.Cmdable and
// only reachable — and therefore only testable — through this signature.
func isNilValue(v any) bool {
	switch rv := reflect.ValueOf(v); rv.Kind() {
	// The kinds reflect's own IsNil is defined on, minus Interface (ValueOf unwraps the
	// interface, so a dynamic value never has that kind). IsNil PANICS on any other kind, which
	// is why they are named rather than tried: the guard must not become the crash it prevents.
	case reflect.Pointer, reflect.Map, reflect.Func, reflect.Slice, reflect.Chan, reflect.UnsafePointer:
		return rv.IsNil()
	default:
		return false
	}
}
