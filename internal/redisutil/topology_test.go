// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package redisutil

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestClassifyTopology_IsOneList pins the definition both backends read: the iterator and the
// "does this client shard" answer are one call, so a client one package calls sharding and the
// other has no iterator for is not a state that can be constructed. The shape this replaced — a
// hand-written type list per package, agreeing by review — had already drifted once, and a
// *redis.Ring fell through to a single-node SCAN that loaded whichever shard go-redis picked.
//
// The THREE-valued answer is the second property. "Recognized single node" and "not recognized"
// both used to answer "no iterator", which is what let a decorator wrapping a cluster client
// enumerate one shard of several and report success.
func TestClassifyTopology_IsOneList(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		client   redis.Cmdable
		want     Topology
		wantIter bool
	}{
		{"cluster", redis.NewClusterClient(&redis.ClusterOptions{Addrs: []string{"127.0.0.1:7000"}}), TopologySharded, true},
		{"ring", redis.NewRing(&redis.RingOptions{Addrs: map[string]string{"a": "127.0.0.1:7000"}}), TopologySharded, true},
		{"single node", redis.NewClient(&redis.Options{Addr: "127.0.0.1:7000"}), TopologySingleNode, false},
		{"universal single node", redis.NewUniversalClient(&redis.UniversalOptions{Addrs: []string{"127.0.0.1:7000"}}), TopologySingleNode, false},
		// A sentinel-backed failover client is a *redis.Client, so it is recognized as the single
		// keyspace it is rather than refused for being unfamiliar.
		{"failover", redis.NewFailoverClient(&redis.FailoverOptions{MasterName: "mymaster", SentinelAddrs: []string{"127.0.0.1:26379"}}), TopologySingleNode, false},
		// A decorator proves nothing about what it wraps, so it is neither — which is the answer
		// a consumer whose correctness depends on visiting every server has to be able to refuse.
		{"decorator over a cluster client", hookedClient{Cmdable: redis.NewClusterClient(&redis.ClusterOptions{Addrs: []string{"127.0.0.1:7000"}})}, TopologyUnknown, false},
		{"decorator over a single-node client", hookedClient{Cmdable: redis.NewClient(&redis.Options{Addr: "127.0.0.1:7000"})}, TopologyUnknown, false},
		// A typed nil matches the sharding arm, and its per-server iterator is a NON-nil func
		// value bound to a nil receiver: handing that back is something that panics inside
		// go-redis the moment it is called, violating the one thing a non-nil iterator means.
		{"typed-nil cluster", (*redis.ClusterClient)(nil), TopologyUnknown, false},
		{"typed-nil ring", (*redis.Ring)(nil), TopologyUnknown, false},
		{"typed-nil single node", (*redis.Client)(nil), TopologyUnknown, false},
		{"untyped nil", nil, TopologyUnknown, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			topology, iterator := ClassifyTopology(tc.client)
			if topology != tc.want {
				t.Errorf("ClassifyTopology(%T) = %s, want %s", tc.client, topology, tc.want)
			}
			if (iterator != nil) != tc.wantIter {
				t.Fatalf("ClassifyTopology(%T) iterator != nil = %v, want %v — one call decides BOTH questions a consumer asks: what the topology is, and how it is enumerated",
					tc.client, iterator != nil, tc.wantIter)
			}
			if (topology == TopologySharded) != (iterator != nil) {
				t.Errorf("ClassifyTopology(%T) = %s with iterator != nil = %v; a sharded client without an iterator (or the reverse) is the disagreement this one call exists to make unrepresentable",
					tc.client, topology, iterator != nil)
			}
		})
	}
}

// TestTopology_String covers the rendering an error or a log line reads, including the zero
// value: an unrecognized client is the case an operator will actually be shown, so it must not
// render as a bare integer.
func TestTopology_String(t *testing.T) {
	t.Parallel()
	for topology, want := range map[Topology]string{
		TopologyUnknown:    "unknown",
		TopologySingleNode: "single-node",
		TopologySharded:    "sharded",
		Topology(99):       "unknown",
	} {
		if got := topology.String(); got != want {
			t.Errorf("Topology(%d).String() = %q, want %q", int(topology), got, want)
		}
	}
}

// TestIsNilClient_CoversTheTypedNil pins the half ClassifyTopology's guard does NOT deliver on
// its own. Withholding an iterator from a typed nil makes the answer honest; it does
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

// TestRingFanOut_RefusesAPassThatSkippedAShard is the regression for a partial enumeration
// reported as a complete one — the same fail-open TopologyUnknown refuses, reached one layer down
// and AFTER the topology was established correctly.
//
// go-redis' own iterator `continue`s past a shard its heartbeat has voted down and returns nil, so
// a keyless SCAN through the bare version loads the surviving shards' keys and its caller cannot
// tell that from the whole keyspace. For the kill switch that is a partial kill set committed as
// authoritative, with HealthStatus reporting ready.
//
// The heartbeat is injected rather than driven by closing a server: the shard's down-vote
// threshold and the dial timeouts would otherwise make the test both slow and timing-dependent,
// and what is under test is the disposition of a skipped shard, not go-redis' liveness detection.
func TestRingFanOut_RefusesAPassThatSkippedAShard(t *testing.T) {
	t.Parallel()
	const downAddr = "127.0.0.1:7001"
	ring := redis.NewRing(&redis.RingOptions{
		Addrs:              map[string]string{"a": "127.0.0.1:7000", "b": downAddr},
		HeartbeatFrequency: time.Millisecond,
		HeartbeatFn:        func(_ context.Context, client *redis.Client) bool { return client.Options().Addr != downAddr },
	})
	t.Cleanup(func() { _ = ring.Close() })

	// Wait for go-redis to vote the shard down (three consecutive votes) and rebalance, which is
	// the state in which ForEachShard silently visits one server of two.
	require.Eventually(t, func() bool { return ring.Len() == 1 }, 2*time.Second, time.Millisecond,
		"go-redis never voted the unreachable shard down, so the skip this test is about never happens")

	topology, fanOut := ClassifyTopology(ring)
	require.Equal(t, TopologySharded, topology)
	require.NotNil(t, fanOut)

	// Atomic because ForEachShard runs fn on one goroutine per shard.
	var visited atomic.Int64
	err := fanOut(context.Background(), func(context.Context, *redis.Client) error {
		visited.Add(1)
		return nil
	})
	assert.Equal(t, int64(1), visited.Load(), "the premise: go-redis skips the shard it voted down")
	assert.ErrorIs(t, err, ErrIncompleteFanOut,
		"a pass that covered one of two shards must report itself incomplete; returning nil is what lets a caller commit a partial view as the whole keyspace")
}

// TestRingFanOut_PassesWhenTheRingIsWhole is the other half: the refusal above must not fire on
// an ordinary healthy ring, or the completeness check would trade a silent fail-open for a
// permanent fail-closed.
//
// It also pins that fn's own error still propagates unchanged — the check is layered over
// go-redis' error path, not in place of it.
func TestRingFanOut_PassesWhenTheRingIsWhole(t *testing.T) {
	t.Parallel()
	ring := redis.NewRing(&redis.RingOptions{
		Addrs:       map[string]string{"a": "127.0.0.1:7000", "b": "127.0.0.1:7001"},
		HeartbeatFn: func(context.Context, *redis.Client) bool { return true },
	})
	t.Cleanup(func() { _ = ring.Close() })
	_, fanOut := ClassifyTopology(ring)
	require.NotNil(t, fanOut)

	var visited atomic.Int64
	require.NoError(t, fanOut(context.Background(), func(context.Context, *redis.Client) error {
		visited.Add(1)
		return nil
	}))
	assert.Equal(t, int64(2), visited.Load())

	sentinel := errors.New("scan failed")
	assert.ErrorIs(t, fanOut(context.Background(), func(context.Context, *redis.Client) error { return sentinel }), sentinel,
		"the completeness check wraps go-redis' error path rather than replacing it")
}

// TestRingFanOut_RefusesAPassOverNoServers closes the degenerate total case of a partial view.
// `got < want` accepts it whenever want is 0 too, so a ring configured with no addresses
// classified as sharded and enumerated nothing, forever, reporting success — for the kill switch,
// an EMPTY kill set committed as authoritative with HealthStatus reporting ready.
func TestRingFanOut_RefusesAPassOverNoServers(t *testing.T) {
	t.Parallel()
	ring := redis.NewRing(&redis.RingOptions{Addrs: map[string]string{}})
	t.Cleanup(func() { _ = ring.Close() })
	topology, fanOut := ClassifyTopology(ring)
	require.Equal(t, TopologySharded, topology)
	require.NotNil(t, fanOut)

	err := fanOut(context.Background(), func(context.Context, *redis.Client) error { return nil })
	assert.ErrorIs(t, err, ErrIncompleteFanOut,
		"a pass that visited no servers at all must not report a complete enumeration of the keyspace")
}

// TestRingFanOut_RefusesAShortPassOnAGrownRing is the direction the first version of this check
// did not consider, and it is the fail-OPEN one.
//
// (*Ring).SetAddrs reshapes a ring without writing back to the options the configured count is
// read from, so after a GROW that count under-counts: a pass covering fewer servers than the ring
// actually has still clears it. The high-water mark closes that — once the ring has been seen at a
// size, a later pass covering less is short whatever the options say.
func TestRingFanOut_RefusesAShortPassOnAGrownRing(t *testing.T) {
	t.Parallel()
	var down atomic.Value
	down.Store("")
	ring := redis.NewRing(&redis.RingOptions{
		Addrs:              map[string]string{"a": "127.0.0.1:7001", "b": "127.0.0.1:7002"},
		HeartbeatFrequency: time.Millisecond,
		HeartbeatFn:        func(_ context.Context, c *redis.Client) bool { return c.Options().Addr != down.Load().(string) },
	})
	t.Cleanup(func() { _ = ring.Close() })
	_, fanOut := ClassifyTopology(ring)
	require.NotNil(t, fanOut)

	// Grow the ring to four shards, all healthy, and take a complete pass — which is what
	// establishes the high-water mark the stale configured count of 2 cannot supply.
	const downAddr = "127.0.0.1:7004"
	ring.SetAddrs(map[string]string{"a": "127.0.0.1:7001", "b": "127.0.0.1:7002", "c": "127.0.0.1:7003", "d": downAddr})
	require.Eventually(t, func() bool { return ring.Len() == 4 }, 2*time.Second, time.Millisecond)
	require.NoError(t, fanOut(context.Background(), func(context.Context, *redis.Client) error { return nil }),
		"a complete pass over the grown ring must be accepted")
	require.Equal(t, 2, len(ring.Options().Addrs), "the premise: go-redis leaves the configured count stale after SetAddrs")

	// Now one of the new shards goes down. The configured count still says 2, so the count alone
	// would accept a 3-shard pass as complete.
	down.Store(downAddr)
	require.Eventually(t, func() bool { return ring.Len() == 3 }, 2*time.Second, time.Millisecond)
	assert.ErrorIs(t, fanOut(context.Background(), func(context.Context, *redis.Client) error { return nil }), ErrIncompleteFanOut,
		"3 of 4 shards is a partial view; accepting it because the ring was CONFIGURED with 2 is the fail-open this check exists to close")
}

// TestRingForEachShard_MatchesWhatGoRedisActuallyDoes is the premise wholeRingFanOut rests on,
// asserted rather than assumed: the library iterator reports NO error for a pass that skipped a
// shard. If a go-redis release ever propagates one, the wrapper becomes redundant rather than
// load-bearing, and this is what says so.
func TestRingForEachShard_MatchesWhatGoRedisActuallyDoes(t *testing.T) {
	t.Parallel()
	const downAddr = "127.0.0.1:7001"
	ring := redis.NewRing(&redis.RingOptions{
		Addrs:              map[string]string{"a": "127.0.0.1:7000", "b": downAddr},
		HeartbeatFrequency: time.Millisecond,
		HeartbeatFn:        func(_ context.Context, client *redis.Client) bool { return client.Options().Addr != downAddr },
	})
	t.Cleanup(func() { _ = ring.Close() })
	require.Eventually(t, func() bool { return ring.Len() == 1 }, 2*time.Second, time.Millisecond)

	assert.NoError(t, ring.ForEachShard(context.Background(), func(context.Context, *redis.Client) error { return nil }),
		"go-redis now reports a skipped shard; wholeRingFanOut's completeness check is no longer the only thing standing between a down shard and a silent partial enumeration")
}

// hookedClient is the decorator shape this package's docs name — "a decorator, or a consumer's
// own Cmdable" — with nothing overridden, so every command is the embedded value's.
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
	// The same shape at the topology seam has a DIFFERENT resolution, and this is where the two
	// part company. Nilness answers "not nil" for a wrapper and accepts the residual, because the
	// failure it misses is a loud panic on a mis-wiring nobody shipped. Topology cannot: an
	// unrecognized client that silently takes the single-node path serves a partial kill set as
	// complete. So it reports UNKNOWN rather than a reassuring "not sharding", and the consumer
	// that cannot live with that refuses it.
	topology, iterator := ClassifyTopology(hookedClient{Cmdable: redis.NewClusterClient(&redis.ClusterOptions{Addrs: []string{"127.0.0.1:7000"}})})
	if topology != TopologyUnknown || iterator != nil {
		t.Errorf("ClassifyTopology(decorator) = %s (iterator != nil = %v), want unknown with no iterator: a concrete-type match proves nothing about what a wrapper wraps, and saying otherwise is how a cluster-backed kill switch enumerates one shard and reports healthy",
			topology, iterator != nil)
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
