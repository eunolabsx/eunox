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
package redisutil

import (
	"context"
	"reflect"

	"github.com/redis/go-redis/v9"
)

// ShardFanOut visits every server a sharding client spreads its keyspace over, running fn
// against each. It is what a KEYLESS command (SCAN) needs there: routed to one server it
// enumerates one shard of several and reports success.
type ShardFanOut func(ctx context.Context, fn func(ctx context.Context, node *redis.Client) error) error

// ShardIterator returns the per-server iterator for a client that spreads one keyspace across
// several servers, and nil for one that keeps it on a single server. Matched on the CONCRETE
// type — a decorator (a hooked client, a custom Cmdable) can still wrap one — so it catches
// the ordinary wiring mistake rather than proving the topology.
//
// It returns the ITERATOR rather than a yes/no, and is the ONLY entry point to either answer,
// because two — a predicate beside an iterator — is how they drifted before (one list named
// Ring, the other did not, so a Ring fell through to a single-node SCAN that loaded whichever
// shard go-redis picked). "Does it shard" is `ShardIterator(c) != nil`, which cannot disagree
// with what the caller then iterates.
//
// A TYPED NIL reports "not sharding". A nil *redis.ClusterClient matches its arm but its
// ForEachMaster is a non-nil func value bound to a nil receiver, so without the guard the
// definition hands a caller an iterator that panics inside go-redis the moment it is called.
// The check is ONE precondition rather than a copy per arm, so the next client type added to
// the switch inherits it instead of needing its author to remember. It makes the returned
// iterator callable whenever it is non-nil; it does not make the client usable — see
// IsNilClient for the half that does.
//
// A DECORATOR is matched on its own concrete type, so one wrapping a sharding client reports
// "not sharding" and its caller enumerates a single server. For the kill switch that is a
// PARTIAL kill set served as complete, not a loud failure — the cost of matching concrete types
// rather than proving topology, and the reason a consumer wrapping a cluster client must pass
// the client itself.
func ShardIterator(client redis.Cmdable) ShardFanOut {
	if IsNilClient(client) {
		return nil
	}
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
// what ShardIterator exists to prevent, and nilness is one question for every client, including
// one go-redis has not added yet.
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
