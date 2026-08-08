// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package redisutil

import (
	"context"
	"fmt"
	"testing"
	"unsafe"

	"github.com/redis/go-redis/v9"
)

// TestShardIterator_IsOneList pins the definition both backends read: the iterator and the
// "does this client shard" predicate are the same answer, so a client one package calls
// sharding and the other has no iterator for is not a state that can be constructed. The shape
// this replaced — a hand-written type list per package, agreeing by review — had already
// drifted once, and a *redis.Ring fell through to a single-node SCAN that loaded whichever
// shard go-redis picked.
func TestShardIterator_IsOneList(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		client  redis.Cmdable
		wantFan bool
	}{
		{"cluster", redis.NewClusterClient(&redis.ClusterOptions{Addrs: []string{"127.0.0.1:7000"}}), true},
		{"ring", redis.NewRing(&redis.RingOptions{Addrs: map[string]string{"a": "127.0.0.1:7000"}}), true},
		{"single node", redis.NewClient(&redis.Options{Addr: "127.0.0.1:7000"}), false},
		{"universal single node", redis.NewUniversalClient(&redis.UniversalOptions{Addrs: []string{"127.0.0.1:7000"}}), false},
		// A typed nil matches the sharding arm, and its per-server iterator is a NON-nil func
		// value bound to a nil receiver: answering "sharding" hands the caller something that
		// panics inside go-redis the moment it is called, violating the one thing a non-nil
		// answer here is supposed to mean.
		{"typed-nil cluster", (*redis.ClusterClient)(nil), false},
		{"typed-nil ring", (*redis.Ring)(nil), false},
		{"typed-nil single node", (*redis.Client)(nil), false},
		{"untyped nil", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			iterator := ShardIterator(tc.client)
			if (iterator != nil) != tc.wantFan {
				t.Fatalf("ShardIterator(%T) != nil = %v, want %v — this one call decides BOTH questions a consumer asks: does it shard, and how is it enumerated",
					tc.client, iterator != nil, tc.wantFan)
			}
		})
	}
}

// TestIsNilClient_CoversTheTypedNil pins the half ShardIterator's guard does NOT deliver on its
// own. Routing a typed nil to the single-node path makes the returned iterator honest; it does
// not make the client usable, because go-redis dereferences the receiver before it can build a
// reply — every command panics rather than returning an error. A backend that must fail closed
// therefore has to ask this question rather than let the first command answer it.
func TestIsNilClient_CoversTheTypedNil(t *testing.T) {
	t.Parallel()
	live := redis.NewClient(&redis.Options{Addr: "127.0.0.1:7000"})
	t.Cleanup(func() { _ = live.Close() })
	cases := []struct {
		name   string
		client redis.Cmdable
		want   bool
	}{
		{"untyped nil", nil, true},
		{"typed-nil single node", (*redis.Client)(nil), true},
		{"typed-nil cluster", (*redis.ClusterClient)(nil), true},
		{"typed-nil ring", (*redis.Ring)(nil), true},
		{"live client", live, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := IsNilClient(tc.client); got != tc.want {
				t.Fatalf("IsNilClient(%T) = %v, want %v", tc.client, got, tc.want)
			}
		})
	}
}

// hookedClient is the decorator shape ShardIterator's own doc advertises — "a hooked client, a
// custom Cmdable" — with nothing overridden, so every command is the embedded value's.
type hookedClient struct{ redis.Cmdable }

// TestIsNilClient_DoesNotSeeThroughADecorator pins the SCOPE the guard claims, in both
// directions, so the limitation is a decision on the record rather than a gap someone closes by
// reflecting into the embedded field.
//
// A wrapper around a nil client is admitted and will panic on its first promoted command. The
// reason that is not fixed is the second case: a wrapper around a LIVE client is the same shape
// to any reflect-into-the-field probe that would catch the first, and refusing it would take a
// working deployment down at construction — the strictly worse failure of the two.
func TestIsNilClient_DoesNotSeeThroughADecorator(t *testing.T) {
	t.Parallel()
	live := redis.NewClient(&redis.Options{Addr: "127.0.0.1:7000"})
	t.Cleanup(func() { _ = live.Close() })

	if IsNilClient(hookedClient{}) {
		t.Error("IsNilClient reports a decorator wrapping a nil client as nil; that is beyond what it claims, and closing it means probing the embedded field — see the second case for what that costs")
	}
	if IsNilClient(hookedClient{Cmdable: live}) {
		t.Error("IsNilClient must admit a decorator wrapping a live client: refusing a working wrapper at construction is a hard outage, where missing the nil one is a panic on a mis-wiring")
	}
	// And the same shape at the topology seam: a wrapper is matched on its CONCRETE type, so it
	// reports "not sharding" whatever it wraps.
	if ShardIterator(hookedClient{Cmdable: redis.NewClusterClient(&redis.ClusterOptions{Addrs: []string{"127.0.0.1:7000"}})}) != nil {
		t.Error("ShardIterator claims to match the concrete type; a decorator wrapping a cluster client must not report a fan-out it cannot perform")
	}
}

// TestIsNilValue_CoversEveryNilableKind pins the widening the exported guard cannot be handed:
// a redis.Cmdable is pointer-shaped in practice (the interface is too wide to implement without
// embedding, which needs a struct), so the map/func/slice/chan kinds are only reachable here.
//
// The `Kind() == Pointer &&` form this replaced answered "not nil" for every one of them, and —
// the half that matters more — reflect.Value.IsNil PANICS on a kind that cannot be nil, so a
// guard written as a bare IsNil call would have become the crash it exists to prevent.
func TestIsNilValue_CoversEveryNilableKind(t *testing.T) {
	t.Parallel()
	// Declared rather than converted inline: `(chan int)(nil)` is a parenthesized type gocritic
	// asks to simplify, and the simplified spelling reads worse than a typed zero value.
	var nilChan chan int
	cases := []struct {
		name string
		v    any
		want bool
	}{
		{"nil pointer", (*redis.Client)(nil), true},
		{"nil map", map[string]string(nil), true},
		{"nil func", (func())(nil), true},
		{"nil slice", []string(nil), true},
		{"nil chan", nilChan, true},
		{"nil unsafe pointer", unsafe.Pointer(nil), true},
		{"live pointer", redis.NewClient(&redis.Options{Addr: "127.0.0.1:7000"}), false},
		{"non-empty map", map[string]string{"a": "b"}, false},
		// The kinds IsNil panics on: a struct (the decorator shape), and a plain scalar.
		{"struct", hookedClient{}, false},
		{"int", 0, false},
		{"string", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isNilValue(tc.v); got != tc.want {
				t.Fatalf("isNilValue(%T) = %v, want %v", tc.v, got, tc.want)
			}
		})
	}
}

// TestIsNilClient_MatchesWhatGoRedisActuallyDoes is the premise the guard rests on, asserted
// rather than assumed: a nil receiver PANICS on an ordinary command. If a go-redis release ever
// makes these return an error instead, the nil-client refusals above become redundant rather
// than load-bearing, and this is what says so.
func TestIsNilClient_MatchesWhatGoRedisActuallyDoes(t *testing.T) {
	t.Parallel()
	for _, client := range []redis.Cmdable{(*redis.Client)(nil), (*redis.ClusterClient)(nil), (*redis.Ring)(nil)} {
		t.Run(fmt.Sprintf("%T", client), func(t *testing.T) {
			t.Parallel()
			panicked := func() (panicked bool) {
				defer func() { panicked = recover() != nil }()
				_, _, _ = client.Scan(context.Background(), 0, "probe*", 1).Result()
				return false
			}()
			if !panicked {
				t.Errorf("%T no longer panics on a nil receiver; IsNilClient's callers can rely on the command's own error instead", client)
			}
		})
	}
}
