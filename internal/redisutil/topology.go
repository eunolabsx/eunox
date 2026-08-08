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
// A TYPED NIL reports "not sharding". A nil *redis.ClusterClient matches the arm but its
// ForEachMaster is a non-nil func value bound to a nil receiver, so without the guards below
// the definition hands a caller an iterator that panics inside go-redis the moment it is
// called. Reporting "not sharding" is what makes the returned iterator callable whenever it is
// non-nil; it does not make the client usable — see IsNilClient for the half that does.
func ShardIterator(client redis.Cmdable) ShardFanOut {
	switch c := client.(type) {
	case *redis.ClusterClient:
		if c == nil {
			return nil
		}
		// Masters only: a replica holds the same keys, so scanning them would double the work
		// and, mid-failover, disagree with its master about what is there.
		return c.ForEachMaster
	case *redis.Ring:
		if c == nil {
			return nil
		}
		return c.ForEachShard
	}
	return nil
}

// IsNilClient reports whether client is nil — as an interface, or as a typed nil pointer inside
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
// what ShardIterator exists to prevent, and this question is answered identically for every
// pointer-shaped client, including one go-redis has not added yet.
func IsNilClient(client redis.Cmdable) bool {
	if client == nil {
		return true
	}
	v := reflect.ValueOf(client)
	return v.Kind() == reflect.Pointer && v.IsNil()
}
