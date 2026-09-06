// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package callcounter_test

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/alicebob/miniredis/v2/server"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/pkg/callcounter"
)

// TestCheckKeyspaceCoLocated_CatchesAWrappedRing is what the probe exists for: the one wiring the
// construction refusal cannot see through, because a declaration is believed rather than checked.
//
// Asserted through the DECLARED counter's own client, which is the client a consumer would probe.
func TestCheckKeyspaceCoLocated_CatchesAWrappedRing(t *testing.T) {
	shardA, shardB := miniredis.RunT(t), miniredis.RunT(t)
	ring := redis.NewRing(&redis.RingOptions{
		Addrs:       map[string]string{"a": shardA.Addr(), "b": shardB.Addr()},
		DialTimeout: 200 * time.Millisecond,
		HeartbeatFn: func(context.Context, *redis.Client) bool { return true },
	})
	t.Cleanup(func() { _ = ring.Close() })

	err := callcounter.CheckKeyspaceCoLocated(context.Background(), decoratedClient{Cmdable: ring})
	require.ErrorIs(t, err, callcounter.ErrClusterUnsupported,
		"a wrapper fronting a ring is exactly the declaration NewRedis cannot verify; the probe is the only thing that can")
	assert.Contains(t, err.Error(), "unreachable to a per-key read")
}

// TestCheckKeyspaceCoLocated_PassesOnOneKeyspace is the positive control, and the half that decides
// whether this probe is safe to run at startup: a false refusal here would break a working
// deployment, which is worse than the hole it closes.
func TestCheckKeyspaceCoLocated_PassesOnOneKeyspace(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	for _, tc := range []struct {
		name   string
		client callcounter.KeyspaceProbeClient
	}{
		{"the client itself", client},
		{"behind a wrapper", decoratedClient{Cmdable: client}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, callcounter.CheckKeyspaceCoLocated(context.Background(), tc.client))
		})
	}
}

// TestCheckKeyspaceCoLocated_LeavesNoKeysBehind pins the cleanup: this runs against an operator's
// live Redis, so a probe that accumulated keys per restart would be a slow leak in someone else's
// keyspace. The TTL is the backstop; the DELs are what makes it immediate.
func TestCheckKeyspaceCoLocated_LeavesNoKeysBehind(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	require.NoError(t, callcounter.CheckKeyspaceCoLocated(context.Background(), client))
	assert.Empty(t, mr.Keys(), "the probe must clean up after itself")
}

// TestCheckKeyspaceCoLocated_IsInconclusiveRatherThanRefusing pins the disposition that makes this
// safe to wire into a startup path: a client that cannot run the probe reports NOTHING, as
// CheckServerNotClustered does for a server that cannot answer INFO. Refusing to start against
// every Redis-protocol server that will not run EVAL is worse than the gap.
func TestCheckKeyspaceCoLocated_IsInconclusiveRatherThanRefusing(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	// A canceled context stands in for every way the probe can fail to run — an ACL denying EVAL,
	// an emulator without scripting, an unreachable server. All of them reach the same arm.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assert.NoError(t, callcounter.CheckKeyspaceCoLocated(ctx, client),
		"an unrunnable probe is inconclusive; reporting it as a topology verdict would refuse working deployments")
}

// TestCheckKeyspaceCoLocated_ReprobesBeforeBelievingAMiss pins the one way a SINGLE keyspace can
// lose a probe key between the write and the read: eviction under memory pressure. A shard
// placement repeats for fresh keys where an eviction does not, so a miss is only believed when the
// second round misses too.
func TestCheckKeyspaceCoLocated_ReprobesBeforeBelievingAMiss(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	// Drop every key once, immediately after the first round writes them: the one-shot stands in
	// for an eviction, which does not recur for the second round's fresh keys.
	var dropped bool
	mr.Server().SetPreHook(func(_ *server.Peer, cmd string, _ ...string) bool {
		if cmd == "EXISTS" && !dropped {
			dropped = true
			mr.FlushAll()
		}
		return false
	})

	assert.NoError(t, callcounter.CheckKeyspaceCoLocated(context.Background(), client),
		"a one-off loss on a single keyspace must not be reported as sharding; only a repeat is believed")
}
