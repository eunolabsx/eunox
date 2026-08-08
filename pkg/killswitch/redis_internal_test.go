// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The Redis backend's own behavior suite, authoritative for what it DOES — including the
// exact error sentinels and the cache-before-publish visibility a cross-backend table cannot
// state. conformance_test.go holds only the rules every backend must satisfy.
//
// Error-path tests for the Redis kill-switch that closing a miniredis server
// cannot reach: those require Get to succeed while a later SCAN fails, or one
// prefix's scan to succeed while the next fails. A selective fake redis.Cmdable
// (embedding the interface, overriding only the four methods the kill switch
// calls) lets each sequential error branch be isolated.

package killswitch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedis_HandlePubSubMessage_GlobalActivate(t *testing.T) {
	t.Parallel()
	r := &Redis{
		killedAgents:   make(map[string]bool),
		killedSessions: make(map[string]bool),
	}

	r.handlePubSubMessage("global:activate")
	assert.True(t, r.globalActive)
}

func TestRedis_HandlePubSubMessage_GlobalDeactivate(t *testing.T) {
	t.Parallel()
	r := &Redis{
		globalActive:   true,
		killedAgents:   make(map[string]bool),
		killedSessions: make(map[string]bool),
	}

	r.handlePubSubMessage("global:deactivate")
	assert.False(t, r.globalActive)
}

func TestRedis_HandlePubSubMessage_AgentKill(t *testing.T) {
	t.Parallel()
	r := &Redis{
		killedAgents:   make(map[string]bool),
		killedSessions: make(map[string]bool),
	}

	r.handlePubSubMessage("agent:kill:agent-123")
	assert.True(t, r.killedAgents["agent-123"])
}

func TestRedis_HandlePubSubMessage_AgentRevive(t *testing.T) {
	t.Parallel()
	r := &Redis{
		killedAgents:   map[string]bool{"agent-123": true},
		killedSessions: make(map[string]bool),
	}

	r.handlePubSubMessage("agent:revive:agent-123")
	assert.False(t, r.killedAgents["agent-123"])
}

func TestRedis_HandlePubSubMessage_SessionKill(t *testing.T) {
	t.Parallel()
	r := &Redis{
		killedAgents:   make(map[string]bool),
		killedSessions: make(map[string]bool),
	}

	r.handlePubSubMessage("session:kill:sess-456")
	assert.True(t, r.killedSessions["sess-456"])
}

func TestRedis_HandlePubSubMessage_SessionRevive(t *testing.T) {
	t.Parallel()
	r := &Redis{
		killedAgents:   make(map[string]bool),
		killedSessions: map[string]bool{"sess-456": true},
	}

	r.handlePubSubMessage("session:revive:sess-456")
	assert.False(t, r.killedSessions["sess-456"])
}

func TestRedis_HandlePubSubMessage_Reset(t *testing.T) {
	t.Parallel()
	r := &Redis{
		globalActive:   true,
		killedAgents:   map[string]bool{"agent-1": true, "agent-2": true},
		killedSessions: map[string]bool{"sess-1": true},
	}

	r.handlePubSubMessage("reset")
	assert.False(t, r.globalActive)
	assert.Empty(t, r.killedAgents)
	assert.Empty(t, r.killedSessions)
}

func TestRedis_HandlePubSubMessage_MultipleEvents(t *testing.T) {
	t.Parallel()
	r := &Redis{
		killedAgents:   make(map[string]bool),
		killedSessions: make(map[string]bool),
	}

	// Simulate a sequence of events that would arrive via pub/sub.
	r.handlePubSubMessage("agent:kill:agent-A")
	r.handlePubSubMessage("agent:kill:agent-B")
	r.handlePubSubMessage("session:kill:sess-X")
	r.handlePubSubMessage("global:activate")

	assert.True(t, r.globalActive)
	assert.True(t, r.killedAgents["agent-A"])
	assert.True(t, r.killedAgents["agent-B"])
	assert.True(t, r.killedSessions["sess-X"])

	// Revive one agent and deactivate global.
	r.handlePubSubMessage("agent:revive:agent-A")
	r.handlePubSubMessage("global:deactivate")

	assert.False(t, r.globalActive)
	assert.False(t, r.killedAgents["agent-A"])
	assert.True(t, r.killedAgents["agent-B"])
}

func TestRedis_HandlePubSubMessage_EmptyPayload(t *testing.T) {
	t.Parallel()
	r := &Redis{
		killedAgents:   make(map[string]bool),
		killedSessions: make(map[string]bool),
	}

	// Empty payload or unknown message should not panic.
	r.handlePubSubMessage("")
	r.handlePubSubMessage("unknown:event")
	assert.False(t, r.globalActive)
}

func TestRedis_HandlePubSubMessage_AgentKillEmptyID(t *testing.T) {
	t.Parallel()
	r := &Redis{
		killedAgents:   make(map[string]bool),
		killedSessions: make(map[string]bool),
	}

	// "agent:kill:" with no ID after prefix falls through to default (no-op).
	r.handlePubSubMessage("agent:kill:")
	assert.Empty(t, r.killedAgents)
}

func TestRedis_WithLogger(t *testing.T) {
	t.Parallel()
	// No option: no logger, and the degraded-mode breadcrumbs stay silent.
	assert.Nil(t, NewRedis(nil).logger)

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	assert.Equal(t, logger, NewRedis(nil, WithLogger(logger)).logger)
}

func TestRedis_Reset_DelError(t *testing.T) {
	t.Parallel()

	// Start a real miniredis server so we have a valid address to connect to.
	mr := miniredis.NewMiniRedis()
	if err := mr.Start(); err != nil {
		t.Fatalf("miniredis start: %v", err)
	}
	addr := mr.Addr()

	client := redis.NewClient(&redis.Options{
		Addr:        addr,
		PoolSize:    1,
		DialTimeout: 100 * time.Millisecond,
	})
	t.Cleanup(func() { _ = client.Close() })

	r := NewRedis(client)

	// Close the server so that the DEL command will fail with a connection error.
	mr.Close()

	err := r.Reset(t.Context())
	require.Error(t, err, "Reset must return an error when Redis DEL fails")
	assert.Contains(t, err.Error(), "kill switch reset")
}

func TestRedis_Reset_StatePreservedOnError(t *testing.T) {
	t.Parallel()

	// Start miniredis, grab the address, then close it so all Redis commands fail.
	mr := miniredis.NewMiniRedis()
	require.NoError(t, mr.Start())
	addr := mr.Addr()
	mr.Close()

	client := redis.NewClient(&redis.Options{
		Addr:        addr,
		PoolSize:    1,
		DialTimeout: 100 * time.Millisecond,
	})
	t.Cleanup(func() { _ = client.Close() })

	r := NewRedis(client)

	// Seed in-memory state to represent pre-existing kills.
	r.mu.Lock()
	r.killedAgents["agent-1"] = true
	r.killedSessions["sess-1"] = true
	r.globalActive = true
	r.mu.Unlock()

	err := r.Reset(t.Context())
	require.Error(t, err, "Reset must return an error when Redis is unavailable")

	// In-memory state must NOT be cleared because the Redis deletion failed.
	r.mu.RLock()
	agentStillKilled := r.killedAgents["agent-1"]
	sessStillKilled := r.killedSessions["sess-1"]
	globalStillActive := r.globalActive
	r.mu.RUnlock()

	assert.True(t, agentStillKilled, "agent kill state must be preserved when Reset fails")
	assert.True(t, sessStillKilled, "session kill state must be preserved when Reset fails")
	assert.True(t, globalStillActive, "global state must be preserved when Reset fails")
}

func TestRedis_DeactivateGlobal(t *testing.T) {
	t.Parallel()
	// write-op cache semantics on a started switch
	r, _ := newStartedTestRedis(t)
	ctx := context.Background()

	// Activate then deactivate — ShouldBlock must go false.
	require.NoError(t, r.ActivateGlobal(ctx))
	r.mu.RLock()
	assert.True(t, r.globalActive)
	r.mu.RUnlock()

	require.NoError(t, r.DeactivateGlobal(ctx))
	r.mu.RLock()
	assert.False(t, r.globalActive)
	r.mu.RUnlock()

	blocked, err := r.ShouldBlock(ctx, "", "")
	require.NoError(t, err)
	assert.False(t, blocked)
}

func TestRedis_ReviveSession(t *testing.T) {
	t.Parallel()
	// write-op cache semantics on a started switch
	r, _ := newStartedTestRedis(t)
	ctx := context.Background()

	require.NoError(t, r.KillSession(ctx, "sess-abc"))
	r.mu.RLock()
	assert.True(t, r.killedSessions["sess-abc"])
	r.mu.RUnlock()

	require.NoError(t, r.ReviveSession(ctx, "sess-abc"))
	r.mu.RLock()
	assert.False(t, r.killedSessions["sess-abc"])
	r.mu.RUnlock()

	blocked, err := r.ShouldBlock(ctx, "", "sess-abc")
	require.NoError(t, err)
	assert.False(t, blocked)
}

// TestRedis_KillUpdatesLocalCacheBeforePublish verifies that every write op must
// update the issuing instance's local cache BEFORE publishing, so a ShouldBlock
// that arrives the instant the call returns already observes the kill (no
// fail-open window on the issuing instance). publishCapturingClient records the
// cache state observed at publish time; the kill MUST already be present then,
// and ShouldBlock must block immediately after each call returns.
func TestRedis_KillUpdatesLocalCacheBeforePublish(t *testing.T) {
	t.Parallel()
	// write-op cache semantics on a started switch
	r, _ := newStartedTestRedis(t)
	ctx := context.Background()

	// KillAgent: cache must reflect the kill the moment the call returns.
	require.NoError(t, r.KillAgent(ctx, "agent-x"))
	blocked, err := r.ShouldBlock(ctx, "agent-x", "")
	require.NoError(t, err)
	assert.True(t, blocked, "KillAgent must update the local cache before returning")

	// KillSession.
	require.NoError(t, r.KillSession(ctx, "sess-x"))
	blocked, err = r.ShouldBlock(ctx, "", "sess-x")
	require.NoError(t, err)
	assert.True(t, blocked, "KillSession must update the local cache before returning")

	// ActivateGlobal.
	require.NoError(t, r.ActivateGlobal(ctx))
	blocked, err = r.ShouldBlock(ctx, "other", "")
	require.NoError(t, err)
	assert.True(t, blocked, "ActivateGlobal must update the local cache before returning")

	// DeactivateGlobal: the global flag must be cleared before returning.
	require.NoError(t, r.DeactivateGlobal(ctx))
	r.mu.RLock()
	globalActive := r.globalActive
	r.mu.RUnlock()
	assert.False(t, globalActive, "DeactivateGlobal must update the local cache before returning")

	// ReviveAgent.
	require.NoError(t, r.ReviveAgent(ctx, "agent-x"))
	blocked, err = r.ShouldBlock(ctx, "agent-x", "")
	require.NoError(t, err)
	assert.False(t, blocked, "ReviveAgent must update the local cache before returning")

	// ReviveSession.
	require.NoError(t, r.ReviveSession(ctx, "sess-x"))
	blocked, err = r.ShouldBlock(ctx, "", "sess-x")
	require.NoError(t, err)
	assert.False(t, blocked, "ReviveSession must update the local cache before returning")
}

func TestRedis_Status(t *testing.T) {
	t.Parallel()
	r := &Redis{
		globalActive:   true,
		killedAgents:   map[string]bool{"agent-1": true, "agent-2": true},
		killedSessions: map[string]bool{"sess-1": true},
	}
	markStarted(t, r)

	status, err := r.Status(context.Background())
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.True(t, status.GlobalActive)
	assert.ElementsMatch(t, []string{"agent-1", "agent-2"}, status.KilledAgents)
	assert.Equal(t, []string{"sess-1"}, status.KilledSessions)
}

// TestRedis_Status_MirrorsShouldBlocksGateChain: a snapshot asserts "this is the whole kill
// set", the same claim ShouldBlock makes on a non-match, so it must refuse on the same
// causes. Guarding only the unstarted case left the two states an operator actually reaches
// — a boot into a Redis partition, and a stopped switch — reporting a confident all-clear
// with a nil error while ShouldBlock denied every request on the same instance.
func TestRedis_Status_MirrorsShouldBlocksGateChain(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("unstarted", func(t *testing.T) {
		t.Parallel()
		r, _ := newTestRedis(t)
		status, err := r.Status(ctx)
		require.ErrorIs(t, err, ErrNotStarted)
		require.Nil(t, status, "a refused Status must yield no snapshot to misread as an all-clear")
	})

	// Started, but the initial refresh failed: started is set once the load has been
	// ATTEMPTED, so the flag alone cannot tell this from a seeded cache.
	t.Run("started into an unreachable backend", func(t *testing.T) {
		t.Parallel()
		r, mr := newTestRedis(t)
		mr.Close()
		r.Start(ctx)
		defer r.Stop()

		status, err := r.Status(ctx)
		require.ErrorIs(t, err, ErrBackendUnreachable)
		require.Nil(t, status)
		_, blockErr := r.ShouldBlock(ctx, "agent-x", "sess-x")
		require.ErrorIs(t, blockErr, ErrBackendUnreachable, "report and data plane must agree")
	})

	// Fail-open opts into serving the last-known cache; a report is served on exactly the
	// same terms, so the flag does not mean one thing to ShouldBlock and another here.
	t.Run("degraded under fail-open", func(t *testing.T) {
		t.Parallel()
		r, mr := newTestRedis(t, WithFailOpen(true))
		mr.Close()
		r.Start(ctx)
		defer r.Stop()

		status, err := r.Status(ctx)
		require.NoError(t, err)
		require.NotNil(t, status)
	})

	t.Run("stopped", func(t *testing.T) {
		t.Parallel()
		r, _ := newTestRedis(t)
		r.Start(ctx)
		r.Stop()

		status, err := r.Status(ctx)
		require.ErrorIs(t, err, ErrStopped, "a frozen switch can never converge; it is not a transient outage")
		require.Nil(t, status)
	})
}

func TestRedis_WithLogger_LogsRefreshFailure(t *testing.T) {
	t.Parallel()

	// Start a real miniredis server, then close it before Start() so the
	// initial refreshState call returns a real connection error.
	mr := miniredis.NewMiniRedis()
	if err := mr.Start(); err != nil {
		t.Fatalf("miniredis start: %v", err)
	}
	addr := mr.Addr()
	mr.Close() // kill it immediately so the first refresh fails

	client := redis.NewClient(&redis.Options{
		Addr:        addr,
		PoolSize:    1,
		DialTimeout: 100 * time.Millisecond,
	})
	t.Cleanup(func() { _ = client.Close() })

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	r := NewRedis(client, WithLogger(logger))

	r.Start(t.Context())
	defer r.Stop()

	assert.Contains(t, buf.String(), "initial state refresh failed")
}

// TestRedis_ReconcileRefresh_LogsAndThrottles covers the background-refresh path
// (reconcile tick / pub/sub resync). It must log a single warning when Redis is
// unreachable and throttle repeats so a sustained outage does not flood the log
// on every tick, then log exactly one recovery notice once the refresh succeeds
// again.
func TestRedis_ReconcileRefresh_LogsAndThrottles(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	r := NewRedis(deadClient(t), WithLogger(logger))
	ctx := context.Background()

	// Two failing refreshes must log the warning only once (edge-triggered).
	r.reconcileRefresh(ctx)
	r.reconcileRefresh(ctx)
	if got := strings.Count(buf.String(), "background state refresh from Redis failed"); got != 1 {
		t.Fatalf("expected exactly one throttled failure warning, got %d:\n%s", got, buf.String())
	}

	// Bring Redis back (no goroutines run in this test, so reassigning the client
	// is race-free): the next refresh succeeds and logs exactly one recovery
	// notice, without repeating the failure warning.
	mr := miniredis.NewMiniRedis()
	require.NoError(t, mr.Start())
	t.Cleanup(mr.Close)
	live := redis.NewClient(&redis.Options{Addr: mr.Addr(), DialTimeout: 200 * time.Millisecond})
	t.Cleanup(func() { _ = live.Close() })
	r.client = live

	r.reconcileRefresh(ctx)
	if got := strings.Count(buf.String(), "recovered"); got != 1 {
		t.Fatalf("expected one recovery notice after Redis came back, got %d:\n%s", got, buf.String())
	}
	if got := strings.Count(buf.String(), "background state refresh from Redis failed"); got != 1 {
		t.Fatalf("failure warning must not repeat after recovery; got %d:\n%s", got, buf.String())
	}
}

func TestRedis_HandlePubSubMessage_UnknownPayload_WithClient(t *testing.T) {
	t.Parallel()

	// Create a live miniredis so refreshState succeeds.
	mr := miniredis.NewMiniRedis()
	require.NoError(t, mr.Start())
	t.Cleanup(mr.Close)

	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), DialTimeout: 200 * time.Millisecond})
	t.Cleanup(func() { _ = client.Close() })

	r := NewRedis(client)
	r.Start(t.Context())
	defer r.Stop()

	// Unknown payload triggers shouldRefresh = true and calls refreshState with
	// the live client — must complete without panic.
	r.handlePubSubMessage("unknown-xyz")

	// After refresh from empty Redis, globalActive must still be false.
	r.mu.RLock()
	globalActive := r.globalActive
	r.mu.RUnlock()
	assert.False(t, globalActive)
}

// newTestRedis spins up a miniredis-backed Redis kill switch for a test. Options are
// forwarded to NewRedis, since configuration is construction-time only.
func newTestRedis(t *testing.T, opts ...RedisOption) (*Redis, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.NewMiniRedis()
	require.NoError(t, mr.Start())
	t.Cleanup(mr.Close)

	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), DialTimeout: 200 * time.Millisecond})
	t.Cleanup(func() { _ = client.Close() })

	return NewRedis(client, opts...), mr
}

// markStarted is the ONE test-side definition of "started": seed through it rather than
// touching r.started, which fabricates a state Start never produces (started, runCtx nil) that
// livenessLocked then reads. It stands in for Start's initial load without the listener and
// reconcile goroutines, and leaves startedOnce clear so a test that does want them can still
// call Start.
func markStarted(t *testing.T, r *Redis) {
	t.Helper()
	runCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	// lifeMu as well as mu: Stop reads r.cancel under lifeMu ALONE, so seeding it under mu
	// only would leave the write unpaired with the read that consumes it.
	r.lifeMu.Lock()
	defer r.lifeMu.Unlock()
	r.mu.Lock()
	r.cancel = cancel
	r.runCtx = runCtx
	r.refreshTrigger = make(chan struct{}, 1)
	// Start sets the flag only AFTER refreshState has run, so a started switch always carries
	// the outcome of at least one refresh. Seeding neither stamp leaves the cache
	// never-confirmed, which staleLocked reads as fresh only because of a special case for the
	// zero value — tighten that and every test seeded here would flip to a denial against a
	// healthy backend. A test wanting the failed outcome overwrites lastRefreshErr.
	if r.lastRefreshOK.IsZero() {
		r.lastRefreshOK = r.clock()
	}
	r.mu.Unlock()
	r.started.Store(true)
}

// newStartedTestRedis is newTestRedis followed by markStarted, for the common case: a
// miniredis-backed switch driven directly, without Start's background loops.
func newStartedTestRedis(t *testing.T, opts ...RedisOption) (*Redis, *miniredis.Miniredis) {
	t.Helper()
	r, mr := newTestRedis(t, opts...)
	markStarted(t, r)
	return r, mr
}

// TestScanPrefix_VisitsEveryShard is the keyless-SCAN fan-out asserted on behavior rather than
// on which type switch answered. A *redis.Ring once took the single-node path, so a refresh
// loaded whichever shard go-redis happened to pick and reported healthy — and a partial kill
// set is a fail-open on the emergency stop.
//
// Both keys are written straight to their server, so the assertion does not depend on where the
// Ring's hashing would place one: what is under test is that BOTH servers are enumerated.
func TestScanPrefix_VisitsEveryShard(t *testing.T) {
	t.Parallel()
	shardA, shardB := miniredis.RunT(t), miniredis.RunT(t)
	require.NoError(t, shardA.Set(redisSessionPfx+"sess-a", "1"))
	require.NoError(t, shardB.Set(redisSessionPfx+"sess-b", "1"))

	ring := redis.NewRing(&redis.RingOptions{
		Addrs:       map[string]string{"a": shardA.Addr(), "b": shardB.Addr()},
		DialTimeout: 200 * time.Millisecond,
	})
	t.Cleanup(func() { _ = ring.Close() })

	found := map[string]bool{}
	require.NoError(t, (&Redis{client: ring}).scanPrefix(context.Background(), redisSessionPfx, found))
	assert.True(t, found["sess-a"] && found["sess-b"],
		"a keyless SCAN reached %v, not both shards; the kill set loaded from one server of several would report healthy while missing every kill on the others", found)
}

// TestNilClient_EveryEntryPointFailsClosedRatherThanPanicking drives the REAL lifecycle, which
// is the whole point: go-redis dereferences the receiver before it can build a reply, so every
// command on a nil client panics rather than erroring — and the first two to run are Start's
// Subscribe (a typed nil satisfies the pubSubClient assertion, since that tests the dynamic
// type) and the reconcile goroutine's Get inside refreshState. A guard placed further down the
// call graph is unreachable: nothing gets that far.
//
// So the refusal is latched at construction and every entry point reports it. An unrecovered
// panic on the reconcile goroutine is process death on the emergency-stop path; ErrNilClient is
// a kill switch that denies everything, which is the fail-closed outcome.
//
// Reachable by a library consumer wiring this backend with a nil-valued handle (a config path
// that leaves the client unset, an ignored constructor error). The shipped binary is single-node.
func TestNilClient_EveryEntryPointFailsClosedRatherThanPanicking(t *testing.T) {
	t.Parallel()
	for _, client := range []redis.Cmdable{nil, (*redis.Client)(nil), (*redis.ClusterClient)(nil), (*redis.Ring)(nil)} {
		t.Run(fmt.Sprintf("%T", client), func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			// Every one of these panicked before: Start on Subscribe, the readers on the
			// reconcile goroutine's Get, the writers on Set/Del, Reset on Del.
			r := NewRedis(client, WithFailOpen(true))
			r.Start(ctx)
			defer r.Stop()

			blocked, err := r.ShouldBlock(ctx, "agent", "sess")
			assert.False(t, blocked)
			assert.ErrorIs(t, err, ErrNilClient,
				"fail-OPEN must not turn a permanent wiring fault into a silent all-clear; it trades revocation for availability during a TRANSIENT outage, and this one never heals")
			assert.ErrorIs(t, r.HealthStatus(), ErrNilClient)
			assert.ErrorIs(t, r.ActivateGlobal(ctx), ErrNilClient)
			assert.ErrorIs(t, r.KillSession(ctx, "sess"), ErrNilClient)
			assert.ErrorIs(t, r.KillAgent(ctx, "agent"), ErrNilClient)
			assert.ErrorIs(t, r.Reset(ctx), ErrNilClient)
			_, _, ttlErr := r.PublishSessionKillTTL(ctx)
			assert.ErrorIs(t, ttlErr, ErrNilClient)
			_, statusErr := r.Status(ctx)
			assert.ErrorIs(t, statusErr, ErrNilClient)
		})
	}
}

func TestRedis_KillAndReviveAgent(t *testing.T) {
	t.Parallel()
	r, _ := newTestRedis(t)
	ctx := context.Background()
	r.Start(ctx) // ShouldBlock fails closed until the switch is started
	defer r.Stop()

	// The issuing instance applies a kill/revive to its own cache synchronously, but it
	// ALSO consumes its own pub/sub echoes on the subscriber goroutine. A kill echo still
	// in flight when a later ReviveAgent runs can be applied AFTER the synchronous revive
	// delete and transiently re-add the agent — fail-closed and self-correcting in
	// production, but a test race (the CI flake this guards). Drain the kill echo before
	// reviving so the revive's synchronous delete is final: cacheGen bumps once for the
	// synchronous kill (setBlock) and once more when the echo is applied
	// (handlePubSubMessage), and nothing else mutates it here (refreshState does not bump
	// it), so genBeforeKill+2 means the echo has been consumed. The revive echo only
	// deletes, so it needs no such drain.
	r.mu.RLock()
	genBeforeKill := r.cacheGen
	r.mu.RUnlock()

	require.NoError(t, r.KillAgent(ctx, "agent-xyz"))
	r.mu.RLock()
	assert.True(t, r.killedAgents["agent-xyz"])
	r.mu.RUnlock()

	blocked, err := r.ShouldBlock(ctx, "agent-xyz", "")
	require.NoError(t, err)
	assert.True(t, blocked)

	// A kill blocks the id it NAMES and no other. Asserted here rather than left to the
	// cross-backend table, which cannot state it more precisely than this: without it, a
	// membership test degraded to "is anything killed?" blocks the whole fleet on one
	// `eunox kill --agent`, and every other Redis case still passes (each either starts from an
	// empty kill set or queries the agent it just killed).
	blocked, err = r.ShouldBlock(ctx, "agent-other", "")
	require.NoError(t, err)
	assert.False(t, blocked, "killing one agent must not block an unrelated one")

	require.Eventually(t, func() bool {
		r.mu.RLock()
		defer r.mu.RUnlock()
		return r.cacheGen >= genBeforeKill+2
	}, 2*time.Second, 5*time.Millisecond, "the issuer's own kill pub/sub echo must be consumed before revive")

	require.NoError(t, r.ReviveAgent(ctx, "agent-xyz"))
	r.mu.RLock()
	assert.False(t, r.killedAgents["agent-xyz"])
	r.mu.RUnlock()

	blocked, err = r.ShouldBlock(ctx, "agent-xyz", "")
	require.NoError(t, err)
	assert.False(t, blocked)
}

// TestRedis_KillAgent_EmptyIDRejected pins the contract that an empty agent ID
// must be rejected rather than silently writing the bare "killswitch:agent:" key.
func TestRedis_KillAgent_EmptyIDRejected(t *testing.T) {
	t.Parallel()
	r, mr := newTestRedis(t)
	ctx := context.Background()

	require.Error(t, r.KillAgent(ctx, ""))
	require.Error(t, r.KillSession(ctx, ""))

	// No phantom keys were written to Redis.
	assert.False(t, mr.Exists(redisAgentPrefix), "bare agent prefix key must not exist")
	assert.False(t, mr.Exists(redisSessionPfx), "bare session prefix key must not exist")

	// No phantom "" entry in local state.
	r.mu.RLock()
	_, agentPhantom := r.killedAgents[""]
	_, sessPhantom := r.killedSessions[""]
	r.mu.RUnlock()
	assert.False(t, agentPhantom)
	assert.False(t, sessPhantom)
}

// TestRedis_Revive_EmptyIDRejected pins the contract that an empty ID passed to
// ReviveAgent/ReviveSession must be rejected rather than DELeting the bare prefix
// key and publishing an empty-suffix event that forces a full refresh on every
// subscribed replica.
func TestRedis_Revive_EmptyIDRejected(t *testing.T) {
	t.Parallel()
	r, _ := newTestRedis(t)
	ctx := context.Background()

	require.Error(t, r.ReviveAgent(ctx, ""))
	require.Error(t, r.ReviveSession(ctx, ""))
}

// TestRedis_StartStop_NoRace pins the contract that Stop must read r.cancel under
// r.mu, consistent with how Start writes it, so concurrent Start/Stop is
// race-free. Run with -race to detect a regression.
func TestRedis_StartStop_NoRace(t *testing.T) {
	t.Parallel()
	r, _ := newTestRedis(t)
	ctx := context.Background()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); r.Start(ctx) }()
	go func() { defer wg.Done(); r.Stop() }()
	wg.Wait()
	r.Stop()
}

// TestRedis_StartReset_NoRace exercises the contract that Reset's trailing
// reseed must read r.runCtx under r.mu, consistent with how Start writes it
// (and how ShouldBlock reads it) — a plain, unlocked field read would race a
// concurrent Start. Best-effort under -race, not a guarantee: Reset already
// takes r.mu.Lock() for an unrelated purpose (clearing the in-memory kill
// state) shortly before the runCtx read, and Start's runCtx write is a
// near-instant in-memory operation that typically completes well before
// Reset's own several Redis round-trips let it reach either of those
// touches — so that incidental Lock/Unlock pair often supplies an accidental
// happens-before edge that can mask a reintroduced unlocked read even under
// -race. Looping many fresh instances raises (without guaranteeing) the odds
// of an unlucky interleaving that trips the detector; the fix's correctness
// itself rests on matching ShouldBlock's established locked-read pattern, not
// on this test's detection power.
func TestRedis_StartReset_NoRace(t *testing.T) {
	t.Parallel()
	mr := miniredis.NewMiniRedis()
	require.NoError(t, mr.Start())
	t.Cleanup(mr.Close)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), DialTimeout: 200 * time.Millisecond})
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()

	const trials = 30
	for i := 0; i < trials; i++ {
		r := NewRedis(client)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); r.Start(ctx) }()
		go func() { defer wg.Done(); _ = r.Reset(ctx) }()
		wg.Wait()
		r.Stop()
	}
}

// TestRedis_Stop_WaitsForGoroutines verifies that Stop must block until the
// pub/sub listener and the reconcile loop have exited, so a caller can free
// shared state (the logger, the Redis client) immediately afterward without
// racing an in-flight refresh. The reconcile interval is set tiny so the loop is
// actively touching r.logger/r.reconcileErrLogged; without the WaitGroup the
// unsynchronized writes below race the still-live goroutine under -race.
func TestRedis_Stop_WaitsForGoroutines(t *testing.T) {
	mr := miniredis.NewMiniRedis()
	require.NoError(t, mr.Start())
	t.Cleanup(mr.Close)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), DialTimeout: 200 * time.Millisecond})
	t.Cleanup(func() { _ = client.Close() })

	r := NewRedis(client,
		WithReconcileInterval(time.Millisecond),
		WithLogger(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))))
	r.Start(context.Background())
	time.Sleep(10 * time.Millisecond) // let the reconcile loop tick several times

	r.Stop() // must block until both goroutines have returned

	// No goroutine is running now, so these unsynchronized writes to fields the
	// reconcile loop reads/writes are safe. With a lingering goroutine (no
	// WaitGroup) the race detector flags them.
	r.logger = nil
	r.reconcileErrLogged = false
}

func TestRedis_KillSession_ShouldBlock(t *testing.T) {
	t.Parallel()
	r, _ := newTestRedis(t)
	ctx := context.Background()
	r.Start(ctx) // ShouldBlock fails closed until the switch is started
	defer r.Stop()

	require.NoError(t, r.KillSession(ctx, "sess-block"))
	blocked, err := r.ShouldBlock(ctx, "", "sess-block")
	require.NoError(t, err)
	assert.True(t, blocked)
}

func TestRedis_ActivateGlobal_ShouldBlock(t *testing.T) {
	t.Parallel()
	r, _ := newTestRedis(t)
	ctx := context.Background()
	r.Start(ctx) // ShouldBlock fails closed until the switch is started
	defer r.Stop()

	require.NoError(t, r.ActivateGlobal(ctx))
	blocked, err := r.ShouldBlock(ctx, "any-agent", "any-sess")
	require.NoError(t, err)
	assert.True(t, blocked)
}

// TestRedis_ShouldBlock_BeforeStartFailsClosed pins the fail-closed wiring guard:
// a NewRedis that was never Start()ed must NOT report an all-clear. Its local cache
// has never been seeded, so ShouldBlock returns ErrNotStarted (the caller treats a
// non-nil error as a denial) instead of (false, nil), which would make a kill switch
// wired into the enforcement path but missing Start() a silent no-op.
func TestRedis_ShouldBlock_BeforeStartFailsClosed(t *testing.T) {
	t.Parallel()
	r, _ := newTestRedis(t)
	ctx := context.Background()

	// A live kill in Redis must not be admitted just because Start() was skipped:
	// the durable key exists but the cache was never seeded, so fail closed.
	require.NoError(t, r.ActivateGlobal(ctx))

	blocked, err := r.ShouldBlock(ctx, "agent-x", "sess-x")
	require.ErrorIs(t, err, ErrNotStarted, "an unstarted switch must fail closed, not report an all-clear")
	assert.False(t, blocked, "ShouldBlock returns (false, err); the caller denies on the error, not the bool")

	// After Start the switch seeds its cache and behaves normally again.
	r.Start(ctx)
	defer r.Stop()
	blocked, err = r.ShouldBlock(ctx, "agent-x", "sess-x")
	require.NoError(t, err)
	assert.True(t, blocked, "after Start the previously-set global kill is enforced")
}

func TestRedis_HealthStatus(t *testing.T) {
	t.Parallel()
	r, _ := newTestRedis(t)
	ctx := context.Background()

	// A constructed-but-unstarted switch is NOT healthy: ShouldBlock fails closed with
	// ErrNotStarted, so reporting nil here would publish "ok" through a total
	// data-plane outage. HealthStatus must mirror ShouldBlock's gate order.
	assert.ErrorIs(t, r.HealthStatus(), ErrNotStarted)
	blocked, err := r.ShouldBlock(ctx, "agent-x", "sess-x")
	assert.False(t, blocked)
	assert.ErrorIs(t, err, ErrNotStarted, "health probe and data plane must agree")

	// Started and seeded: healthy.
	r.Start(ctx)
	assert.NoError(t, r.HealthStatus())

	// A successful refresh keeps it healthy.
	require.NoError(t, r.refreshState(ctx))
	assert.NoError(t, r.HealthStatus())

	// Stopped: the liveness cause, not the stale refresh error, and still not nil.
	r.Stop()
	assert.ErrorIs(t, r.HealthStatus(), ErrStopped)
}

func TestRedis_HealthStatus_AfterFailedRefresh(t *testing.T) {
	t.Parallel()

	mr := miniredis.NewMiniRedis()
	require.NoError(t, mr.Start())
	addr := mr.Addr()
	mr.Close() // kill server so refresh fails

	client := redis.NewClient(&redis.Options{
		Addr:        addr,
		PoolSize:    1,
		DialTimeout: 100 * time.Millisecond,
	})
	t.Cleanup(func() { _ = client.Close() })

	r := NewRedis(client)
	// Start (against the dead server) so the not-started gate is satisfied and this
	// asserts what it means to: that a STARTED switch surfaces its refresh error
	// rather than a liveness cause.
	r.Start(context.Background())
	defer r.Stop()
	err := r.refreshState(context.Background())
	require.Error(t, err)
	status := r.HealthStatus()
	assert.Error(t, status, "HealthStatus must surface the last refresh error")
	assert.NotErrorIs(t, status, ErrNotStarted, "the switch is started; the error must be the refresh failure")
	assert.NotErrorIs(t, status, ErrStopped, "the switch is running; the error must be the refresh failure")
}

func TestRedis_Reset_ClearsAllState(t *testing.T) {
	t.Parallel()
	r, _ := newTestRedis(t)
	ctx := context.Background()

	// Seed global, agents, and sessions through the public API so the keys
	// actually exist in Redis (exercises deleteByPrefix scanning real keys).
	require.NoError(t, r.ActivateGlobal(ctx))
	require.NoError(t, r.KillAgent(ctx, "agent-1"))
	require.NoError(t, r.KillAgent(ctx, "agent-2"))
	require.NoError(t, r.KillSession(ctx, "sess-1"))

	require.NoError(t, r.Reset(ctx))

	r.mu.RLock()
	assert.False(t, r.globalActive)
	assert.Empty(t, r.killedAgents)
	assert.Empty(t, r.killedSessions)
	r.mu.RUnlock()

	// A fresh refresh from Redis must agree that everything was deleted.
	require.NoError(t, r.refreshState(ctx))
	markStarted(t, r)
	status, err := r.Status(ctx)
	require.NoError(t, err)
	assert.False(t, status.GlobalActive)
	assert.Empty(t, status.KilledAgents)
	assert.Empty(t, status.KilledSessions)
}

func TestRedis_RefreshState_LoadsExistingKeys(t *testing.T) {
	t.Parallel()
	r, mr := newTestRedis(t)
	ctx := context.Background()

	// Write keys directly into Redis, bypassing the in-memory cache, then
	// refresh to confirm scanPrefix and the global-key read pick them up.
	require.NoError(t, mr.Set(redisGlobalKey, "1"))
	require.NoError(t, mr.Set(redisAgentPrefix+"a1", "1"))
	require.NoError(t, mr.Set(redisSessionPfx+"s1", "1"))

	require.NoError(t, r.refreshState(ctx))

	r.mu.RLock()
	defer r.mu.RUnlock()
	assert.True(t, r.globalActive)
	assert.True(t, r.killedAgents["a1"])
	assert.True(t, r.killedSessions["s1"])
}

func TestRedis_StartLoadsStateAndListens(t *testing.T) {
	t.Parallel()
	r, mr := newTestRedis(t)

	// Pre-seed state so Start's initial refreshState picks it up.
	require.NoError(t, mr.Set(redisGlobalKey, "1"))

	r.Start(t.Context())
	defer r.Stop()

	r.mu.RLock()
	globalActive := r.globalActive
	r.mu.RUnlock()
	assert.True(t, globalActive, "Start must load initial state via refreshState")
}

func TestRedis_PubSubPropagation(t *testing.T) {
	t.Parallel()
	r, _ := newTestRedis(t)

	r.Start(t.Context())
	defer r.Stop()

	ctx := context.Background()
	require.NoError(t, r.KillAgent(ctx, "propagated-agent"))

	// The publish from KillAgent should round-trip through pub/sub and be
	// observed by listenPubSub -> handlePubSubMessage. Poll briefly since the
	// delivery is asynchronous.
	require.Eventually(t, func() bool {
		blocked, _ := r.ShouldBlock(ctx, "propagated-agent", "")
		return blocked
	}, 2*time.Second, 10*time.Millisecond)
}

// deadClient returns a Redis client pointed at an address whose server has
// been shut down, so every command fails with a connection error.
func deadClient(t *testing.T) *redis.Client {
	t.Helper()
	mr := miniredis.NewMiniRedis()
	require.NoError(t, mr.Start())
	addr := mr.Addr()
	mr.Close()

	client := redis.NewClient(&redis.Options{
		Addr:        addr,
		PoolSize:    1,
		DialTimeout: 100 * time.Millisecond,
	})
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestRedis_ScanPrefix_Error(t *testing.T) {
	t.Parallel()
	r := NewRedis(deadClient(t))
	err := r.scanPrefix(context.Background(), redisAgentPrefix, map[string]bool{})
	assert.Error(t, err, "scanPrefix must propagate the SCAN failure")
}

func TestRedis_DeleteByPrefix_Error(t *testing.T) {
	t.Parallel()
	r := NewRedis(deadClient(t))
	err := r.deleteByPrefix(context.Background(), redisAgentPrefix)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SCAN")
}

func TestRedis_RefreshState_ScanError(t *testing.T) {
	t.Parallel()
	r := NewRedis(deadClient(t))
	err := r.refreshState(context.Background())
	require.Error(t, err, "refreshState must fail when Redis is unreachable")
	assert.Error(t, r.HealthStatus())
}

func TestRedis_ListenPubSub_StopsOnCancel(t *testing.T) {
	t.Parallel()
	r, _ := newTestRedis(t)

	ctx, cancel := context.WithCancel(context.Background())
	r.Start(ctx)

	// Give the listener goroutine time to enter its select loop, then cancel
	// the lifecycle context so it returns via the <-ctx.Done() branch.
	time.Sleep(50 * time.Millisecond)
	cancel()
	r.Stop()
	time.Sleep(50 * time.Millisecond)

	// A second Stop must be safe (cancel already fired).
	r.Stop()
}

func TestRedis_ActivateGlobal_Error(t *testing.T) {
	t.Parallel()

	mr := miniredis.NewMiniRedis()
	require.NoError(t, mr.Start())
	addr := mr.Addr()
	mr.Close()

	client := redis.NewClient(&redis.Options{
		Addr:        addr,
		PoolSize:    1,
		DialTimeout: 100 * time.Millisecond,
	})
	t.Cleanup(func() { _ = client.Close() })

	r := NewRedis(client)
	ctx := context.Background()

	assert.Error(t, r.ActivateGlobal(ctx))
	assert.Error(t, r.DeactivateGlobal(ctx))
	assert.Error(t, r.KillAgent(ctx, "a"))
	assert.Error(t, r.ReviveAgent(ctx, "a"))
	assert.Error(t, r.KillSession(ctx, "s"))
	assert.Error(t, r.ReviveSession(ctx, "s"))
}

// TestRedis_RefreshState_DoesNotBlockShouldBlock verifies that refreshState
// no longer holds r.mu across Redis I/O, so concurrent ShouldBlock calls are
// never stalled by an in-progress refresh.  The test runs refreshState and
// ShouldBlock concurrently under the race detector; a deadlock would timeout.
func TestRedis_RefreshState_DoesNotBlockShouldBlock(t *testing.T) {
	t.Parallel()
	r, mr := newTestRedis(t)
	ctx := context.Background()

	// Pre-populate: global active so ShouldBlock returns true after refresh.
	require.NoError(t, mr.Set(redisGlobalKey, "1"))

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Trigger a full state refresh.
		_ = r.refreshState(ctx)
	}()

	// ShouldBlock must not block waiting for the refresh goroutine.
	const workers = 20
	results := make(chan bool, workers)
	for i := 0; i < workers; i++ {
		go func() {
			blocked, err := r.ShouldBlock(ctx, "", "")
			if err == nil {
				results <- blocked
			} else {
				results <- false
			}
		}()
	}

	// Collect all results within a generous timeout to catch potential deadlocks.
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for i := 0; i < workers; i++ {
		select {
		case <-results:
		case <-deadline.C:
			t.Fatal("regression: ShouldBlock timed out — refreshState may be holding the lock")
		}
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("regression: refreshState did not complete in time")
	}
}

// TestRedis_HandlePubSubMessage_UnknownPayload_NilCtx exercises the default
// branch in handlePubSubMessage (shouldRefresh=true) with a nil lifecycleCtx
// so the fallback context.Background() path is taken.
func TestRedis_HandlePubSubMessage_UnknownPayload_NilCtx(t *testing.T) {
	t.Parallel()
	r, _ := newTestRedis(t)
	// Do NOT call Start so lifecycleCtx stays nil.
	// An unknown payload triggers shouldRefresh=true → nil ctx → fallback to context.Background()
	r.handlePubSubMessage("unknown:event:xyz")
	// Verify no panic and the internal state is unmodified (global not active).
	r.mu.RLock()
	assert.False(t, r.globalActive)
	r.mu.RUnlock()
}

// TestRedis_ListenPubSub_ChannelClosed covers the !ok branch in listenPubSub
// which fires when the pub/sub channel is closed (e.g. connection drop).
func TestRedis_ListenPubSub_ChannelClosed(t *testing.T) {
	t.Parallel()
	r, _ := newTestRedis(t)

	if sub, ok := r.client.(interface {
		Subscribe(ctx context.Context, channels ...string) *redis.PubSub
	}); ok {
		ctx := context.Background()
		pubsub := sub.Subscribe(ctx, redisPubSubChan)
		// Close the subscription; its channel will be drained and closed.
		require.NoError(t, pubsub.Close())

		done := make(chan struct{})
		go func() {
			defer close(done)
			r.listenPubSub(ctx, pubsub)
		}()

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("listenPubSub did not exit after channel was closed")
		}
	}
}

// TestRedis_ListenPubSub_HandleMessage verifies that listenPubSub calls
// handlePubSubMessage when a pub/sub message arrives on the channel.
func TestRedis_ListenPubSub_HandleMessage(t *testing.T) {
	t.Parallel()
	r, _ := newTestRedis(t)

	sub, ok := r.client.(interface {
		Subscribe(ctx context.Context, channels ...string) *redis.PubSub
	})
	// The test Redis client always supports Subscribe; assert it rather than
	// t.Skip so a future client stub that drops Subscribe fails loudly here
	// instead of silently dropping the pub/sub coverage this test provides.
	require.True(t, ok, "test Redis client must support Subscribe")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pubsub := sub.Subscribe(ctx, redisPubSubChan)
	// Allow the subscription to establish before publishing.
	time.Sleep(20 * time.Millisecond)

	go r.listenPubSub(ctx, pubsub)
	// Allow the goroutine to enter its select loop.
	time.Sleep(20 * time.Millisecond)

	// Publish a message that will trigger handlePubSubMessage inside the goroutine.
	r.publish(ctx, "global:activate")

	// Wait until handlePubSubMessage has processed the message (in-memory state updated).
	require.Eventually(t, func() bool {
		r.mu.RLock()
		defer r.mu.RUnlock()
		return r.globalActive
	}, 2*time.Second, 5*time.Millisecond, "handlePubSubMessage must update globalActive via pub/sub")
}

// TestRedis_Reset_GlobalDelError verifies that Reset propagates a Del error on
// the global key before attempting to delete agent/session keys.
func TestRedis_Reset_GlobalDelError(t *testing.T) {
	t.Parallel()
	r := NewRedis(deadClient(t))
	ctx := context.Background()

	err := r.Reset(ctx)
	require.Error(t, err, "Reset must fail when Redis is unreachable for global key Del")
}

// TestRedis_HandlePubSubMessage_AllKnownPayloads exercises every explicit
// switch case in handlePubSubMessage with a running Redis instance.
func TestRedis_HandlePubSubMessage_AllKnownPayloads(t *testing.T) {
	t.Parallel()
	r, _ := newTestRedis(t)

	cases := []string{
		"global:activate",
		"global:deactivate",
		"reset",
		"agent:kill:a1",
		"agent:revive:a1",
		"session:kill:s1",
		"session:revive:s1",
	}
	for _, payload := range cases {
		r.handlePubSubMessage(payload)
	}
	// Just verify no panic; state transitions already tested elsewhere.
}

var errBoom = errors.New("boom")

// fakeCmdable implements just enough of redis.Cmdable for refreshState, Reset,
// and deleteByPrefix. The embedded nil interface satisfies the rest of the
// (large) Cmdable surface; any unexpected call would panic, which keeps the
// fake honest about which methods the code under test actually exercises.
type fakeCmdable struct {
	redis.Cmdable
	getVal     string
	getErr     error
	scanKeys   []string
	scanErrFor string // SCAN errors when match begins with this prefix ("" = never)
	delErr     error
}

func (f *fakeCmdable) Get(_ context.Context, _ string) *redis.StringCmd {
	return redis.NewStringResult(f.getVal, f.getErr)
}

func (f *fakeCmdable) Scan(_ context.Context, _ uint64, match string, _ int64) *redis.ScanCmd {
	if f.scanErrFor != "" && strings.HasPrefix(match, f.scanErrFor) {
		return redis.NewScanCmdResult(nil, 0, errBoom)
	}
	return redis.NewScanCmdResult(f.scanKeys, 0, nil)
}

func (f *fakeCmdable) Del(_ context.Context, keys ...string) *redis.IntCmd {
	// Model real deletion: on success, remove the deleted keys from the scannable
	// set so a later SCAN (e.g. Reset's trailing refreshState) does not re-read
	// keys that were just deleted. A failed Del removes nothing.
	if f.delErr == nil {
		for _, k := range keys {
			for i, sk := range f.scanKeys {
				if sk == k {
					f.scanKeys = append(f.scanKeys[:i], f.scanKeys[i+1:]...)
					break
				}
			}
		}
	}
	return redis.NewIntResult(int64(len(keys)), f.delErr)
}

func (f *fakeCmdable) Publish(_ context.Context, _ string, _ interface{}) *redis.IntCmd {
	return redis.NewIntResult(0, nil)
}

// publishFailFake has a succeeding Set/Del and a failing Publish, so a mutation's
// durable write lands but pub/sub propagation fails.
type publishFailFake struct {
	redis.Cmdable
	pubErr error
}

func (f *publishFailFake) Set(_ context.Context, _ string, _ interface{}, _ time.Duration) *redis.StatusCmd {
	return redis.NewStatusResult("OK", nil)
}

func (f *publishFailFake) Del(_ context.Context, keys ...string) *redis.IntCmd {
	return redis.NewIntResult(int64(len(keys)), nil)
}

func (f *publishFailFake) Publish(_ context.Context, _ string, _ interface{}) *redis.IntCmd {
	return redis.NewIntResult(0, f.pubErr)
}

// TestRedis_KillSession_PublishErrorPropagates verifies that when the durable
// Redis SET succeeds but PUBLISH fails, KillSession surfaces the propagation
// error so the caller can report partial propagation and retry, while the local
// cache still reflects the kill (fail-closed on the issuing instance).
func TestRedis_KillSession_PublishErrorPropagates(t *testing.T) {
	t.Parallel()
	r := NewRedis(&publishFailFake{pubErr: errBoom})

	err := r.KillSession(context.Background(), "sess-1")
	if !errors.Is(err, errBoom) {
		t.Errorf("KillSession should surface the publish error, got %v", err)
	}
	// The durable write + local cache update happened despite the publish failure.
	r.mu.RLock()
	killed := r.killedSessions["sess-1"]
	r.mu.RUnlock()
	if !killed {
		t.Error("local cache must still record the kill even when propagation fails")
	}
}

// TestRedis_ActivateGlobal_PublishErrorPropagates mirrors
// TestRedis_KillSession_PublishErrorPropagates for ActivateGlobal: the durable SET
// lands, but the caller still sees the publish error since ActivateGlobal returns
// whatever publish returns.
func TestRedis_ActivateGlobal_PublishErrorPropagates(t *testing.T) {
	t.Parallel()
	r := NewRedis(&publishFailFake{pubErr: errBoom})

	err := r.ActivateGlobal(context.Background())
	if !errors.Is(err, errBoom) {
		t.Errorf("ActivateGlobal should surface the publish error, got %v", err)
	}
	r.mu.RLock()
	active := r.globalActive
	r.mu.RUnlock()
	if !active {
		t.Error("local cache must still record the activation even when propagation fails")
	}
}

// TestRedis_DeactivateGlobal_PublishErrorPropagates mirrors
// TestRedis_KillSession_PublishErrorPropagates for DeactivateGlobal — the DEL leg of
// the same write-then-publish pattern.
func TestRedis_DeactivateGlobal_PublishErrorPropagates(t *testing.T) {
	t.Parallel()
	r := NewRedis(&publishFailFake{pubErr: errBoom})
	r.mu.Lock()
	r.globalActive = true
	r.mu.Unlock()

	err := r.DeactivateGlobal(context.Background())
	if !errors.Is(err, errBoom) {
		t.Errorf("DeactivateGlobal should surface the publish error, got %v", err)
	}
	r.mu.RLock()
	active := r.globalActive
	r.mu.RUnlock()
	if active {
		t.Error("local cache must still record the deactivation even when propagation fails")
	}
}

// TestRedis_ReviveSession_PublishErrorPropagates covers the DEL leg of setBlock
// (kill=false), which cmd/eunox's --revive flag newly routes through — the write half
// of that same write-succeeds/publish-fails split KillSession already pins, but
// unexercised for revive until now.
func TestRedis_ReviveSession_PublishErrorPropagates(t *testing.T) {
	t.Parallel()
	r := NewRedis(&publishFailFake{pubErr: errBoom})
	r.mu.Lock()
	r.killedSessions["sess-1"] = true
	r.mu.Unlock()

	err := r.ReviveSession(context.Background(), "sess-1")
	if !errors.Is(err, errBoom) {
		t.Errorf("ReviveSession should surface the publish error, got %v", err)
	}
	r.mu.RLock()
	_, stillKilled := r.killedSessions["sess-1"]
	r.mu.RUnlock()
	if stillKilled {
		t.Error("local cache must still record the revive even when propagation fails")
	}
}

func TestRedis_RefreshState_GetError(t *testing.T) {
	t.Parallel()
	r := NewRedis(&fakeCmdable{getErr: errBoom})
	if err := r.refreshState(context.Background()); !errors.Is(err, errBoom) {
		t.Errorf("expected Get error to propagate, got %v", err)
	}
	if r.HealthStatus() == nil {
		t.Error("expected lastRefreshErr to be recorded after a Get failure")
	}
}

func TestRedis_RefreshState_AgentScanError(t *testing.T) {
	t.Parallel()
	// Get succeeds (global active); the agent-prefix SCAN fails.
	r := NewRedis(&fakeCmdable{getVal: "1", scanErrFor: redisAgentPrefix})
	if err := r.refreshState(context.Background()); !errors.Is(err, errBoom) {
		t.Errorf("expected agent SCAN error to propagate, got %v", err)
	}
}

func TestRedis_RefreshState_SessionScanError(t *testing.T) {
	t.Parallel()
	// Get + agent SCAN succeed; the session-prefix SCAN fails.
	r := NewRedis(&fakeCmdable{getVal: "1", scanErrFor: redisSessionPfx})
	if err := r.refreshState(context.Background()); !errors.Is(err, errBoom) {
		t.Errorf("expected session SCAN error to propagate, got %v", err)
	}
}

func TestRedis_RefreshState_Success(t *testing.T) {
	t.Parallel()
	r := NewRedis(&fakeCmdable{
		getVal:   "1",
		scanKeys: []string{redisAgentPrefix + "a1"},
	})
	if err := r.refreshState(context.Background()); err != nil {
		t.Fatalf("expected clean refresh, got %v", err)
	}
	markStarted(t, r)
	st, err := r.Status(context.Background())
	if err != nil {
		t.Fatalf("expected a snapshot from a seeded cache, got %v", err)
	}
	if !st.GlobalActive {
		t.Error("expected global kill switch to be active after refresh")
	}
}

func TestRedis_Reset_AgentDeleteScanError(t *testing.T) {
	t.Parallel()
	// Global DEL succeeds; the agent-prefix SCAN inside deleteByPrefix fails.
	r := NewRedis(&fakeCmdable{scanErrFor: redisAgentPrefix})
	if err := r.Reset(context.Background()); !errors.Is(err, errBoom) {
		t.Errorf("expected agent deleteByPrefix error, got %v", err)
	}
}

func TestRedis_Reset_SessionDeleteScanError(t *testing.T) {
	t.Parallel()
	// Global DEL + agent deleteByPrefix succeed; session-prefix SCAN fails.
	r := NewRedis(&fakeCmdable{scanErrFor: redisSessionPfx})
	if err := r.Reset(context.Background()); !errors.Is(err, errBoom) {
		t.Errorf("expected session deleteByPrefix error, got %v", err)
	}
}

func TestRedis_DeleteByPrefix_DelError(t *testing.T) {
	t.Parallel()
	// SCAN returns a key so DEL is attempted; DEL fails.
	r := NewRedis(&fakeCmdable{
		scanKeys: []string{redisAgentPrefix + "a1"},
		delErr:   errBoom,
	})
	if err := r.deleteByPrefix(context.Background(), redisAgentPrefix); !errors.Is(err, errBoom) {
		t.Errorf("expected DEL error from deleteByPrefix, got %v", err)
	}
}

func TestRedis_Reset_Success(t *testing.T) {
	t.Parallel()
	// Everything succeeds: DEL global, both prefix scans return a key + DEL ok.
	r := NewRedis(&fakeCmdable{scanKeys: []string{redisAgentPrefix + "a1"}})
	// Seed some in-memory state so we can confirm Reset clears it.
	r.mu.Lock()
	r.globalActive = true
	r.killedAgents["a1"] = true
	r.killedSessions["s1"] = true
	r.mu.Unlock()

	if err := r.Reset(context.Background()); err != nil {
		t.Fatalf("expected clean reset, got %v", err)
	}
	markStarted(t, r)
	st, err := r.Status(context.Background())
	if err != nil {
		t.Fatalf("expected a snapshot from a seeded cache, got %v", err)
	}
	if st.GlobalActive || len(st.KilledAgents) != 0 || len(st.KilledSessions) != 0 {
		t.Errorf("Reset must clear in-memory state, got %+v", st)
	}
}

// TestRedis_MultiInstance_KillPropagatesAcrossInstances verifies the
// multi-instance guarantee: a kill issued on one eunox instance is observed
// by a second, independent instance sharing the same Redis, propagated over the
// pub/sub channel. This is what lets `eunox kill --all` on one node take
// effect fleet-wide.
func TestRedis_MultiInstance_KillPropagatesAcrossInstances(t *testing.T) {
	mr := miniredis.NewMiniRedis()
	require.NoError(t, mr.Start())
	t.Cleanup(mr.Close)

	clientA := redis.NewClient(&redis.Options{Addr: mr.Addr(), DialTimeout: 200 * time.Millisecond})
	clientB := redis.NewClient(&redis.Options{Addr: mr.Addr(), DialTimeout: 200 * time.Millisecond})
	t.Cleanup(func() {
		_ = clientA.Close()
		_ = clientB.Close()
	})

	instanceA := NewRedis(clientA)
	instanceB := NewRedis(clientB)

	// Only instance B subscribes; instance A issues the kill.
	instanceB.Start(t.Context())
	defer instanceB.Stop()

	ctx := context.Background()
	require.NoError(t, instanceA.KillAgent(ctx, "agent-x"))

	// Instance B must observe the kill issued by A, propagated over Redis pub/sub.
	require.Eventually(t, func() bool {
		blocked, _ := instanceB.ShouldBlock(ctx, "agent-x", "")
		return blocked
	}, 2*time.Second, 10*time.Millisecond,
		"a kill on instance A must propagate to instance B via pub/sub")

	// A revive on A must likewise clear the block on B.
	require.NoError(t, instanceA.ReviveAgent(ctx, "agent-x"))
	require.Eventually(t, func() bool {
		blocked, _ := instanceB.ShouldBlock(ctx, "agent-x", "")
		return !blocked
	}, 2*time.Second, 10*time.Millisecond,
		"a revive on instance A must propagate to instance B via pub/sub")
}

// TestRedis_ShouldBlock_ServesCachedStateWhenRedisDown pins that a kill cached
// before a Redis outage stays enforced *during* the outage: ShouldBlock reads
// the local cache and returns it. Here no failed refresh has been observed yet
// (lastRefreshErr is still nil — Start/reconcile are not running), so the default
// fail-closed degraded path does not trigger and ShouldBlock does not error. Once
// a refresh actually fails (lastRefreshErr set), the default mode denies
// unconfirmed requests; that path is covered by the redis_failclosed tests. See
// ADR-0003.
func TestRedis_ShouldBlock_ServesCachedStateWhenRedisDown(t *testing.T) {
	mr := miniredis.NewMiniRedis()
	require.NoError(t, mr.Start())
	client := redis.NewClient(&redis.Options{
		Addr:        mr.Addr(),
		PoolSize:    1,
		DialTimeout: 100 * time.Millisecond,
	})
	t.Cleanup(func() { _ = client.Close() })

	r := NewRedis(client)
	markStarted(t, r) // a started switch that subsequently loses its backend
	ctx := context.Background()

	// Kill an agent while Redis is healthy: populates both Redis and local cache.
	require.NoError(t, r.KillAgent(ctx, "agent-cached"))
	blocked, err := r.ShouldBlock(ctx, "agent-cached", "")
	require.NoError(t, err)
	require.True(t, blocked)

	// Redis becomes unreachable.
	mr.Close()

	// ShouldBlock serves the local cache: the cached kill is still enforced and
	// no error is returned despite Redis being down.
	blocked, err = r.ShouldBlock(ctx, "agent-cached", "")
	require.NoError(t, err, "ShouldBlock must not error when Redis is down — it reads local cache")
	assert.True(t, blocked, "a kill cached before the outage must remain enforced during the outage")
}

// TestRedis_Reconcile_RecoversLostPubSubEvent verifies that periodic
// reconciliation observes a kill whose pub/sub event was never delivered. Redis
// pub/sub is at-most-once, so a kill issued while a replica is briefly
// disconnected would otherwise never be seen. We simulate the lost event by
// writing the kill key straight to Redis without publishing, then assert the
// reconcile loop picks it up.
func TestRedis_Reconcile_RecoversLostPubSubEvent(t *testing.T) {
	mr := miniredis.NewMiniRedis()
	require.NoError(t, mr.Start())
	t.Cleanup(mr.Close)

	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), DialTimeout: 200 * time.Millisecond})
	t.Cleanup(func() { _ = client.Close() })

	r := NewRedis(client, WithReconcileInterval(50*time.Millisecond))
	r.Start(t.Context())
	defer r.Stop()

	ctx := context.Background()

	// A kill whose pub/sub event was lost: write the key directly, no publish.
	require.NoError(t, client.Set(ctx, redisSessionPfx+"sess-lost", "1", 0).Err())

	require.Eventually(t, func() bool {
		blocked, _ := r.ShouldBlock(ctx, "", "sess-lost")
		return blocked
	}, 2*time.Second, 10*time.Millisecond,
		"a kill whose pub/sub event was lost must be recovered by periodic reconciliation")
}

// resetRaceFake models a kill that lands in Redis AFTER Reset's delete sweep: the
// agent key is invisible to the delete-time SCANs but present by the time Reset's
// trailing refreshState reads Redis. (The first Del — of the global key — flips
// `deleted`, after which agent SCANs surface the raced key.)
type resetRaceFake struct {
	redis.Cmdable
	mu      sync.Mutex
	deleted bool
	agentID string // the bare agent id whose kill races in
}

func (f *resetRaceFake) Get(_ context.Context, _ string) *redis.StringCmd {
	return redis.NewStringResult("", redis.Nil) // no global kill
}

func (f *resetRaceFake) Scan(_ context.Context, _ uint64, match string, _ int64) *redis.ScanCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deleted && strings.HasPrefix(match, redisAgentPrefix) {
		return redis.NewScanCmdResult([]string{redisAgentPrefix + f.agentID}, 0, nil)
	}
	return redis.NewScanCmdResult(nil, 0, nil)
}

func (f *resetRaceFake) Del(_ context.Context, _ ...string) *redis.IntCmd {
	f.mu.Lock()
	f.deleted = true // the raced kill "survives" this delete (no-op removal)
	f.mu.Unlock()
	return redis.NewIntResult(0, nil)
}

func (f *resetRaceFake) Publish(_ context.Context, _ string, _ interface{}) *redis.IntCmd {
	return redis.NewIntResult(0, nil)
}

// TestRedis_Reset_ReseedsRacedKill verifies that a kill that lands in Redis after
// Reset's delete sweep must be reflected in the local cache when Reset returns,
// not left invisible to ShouldBlock until the next reconcile tick. Reset's
// trailing refreshState re-reads Redis and re-seeds it.
func TestRedis_Reset_ReseedsRacedKill(t *testing.T) {
	t.Parallel()
	r := NewRedis(&resetRaceFake{agentID: "victim"})
	markStarted(t, r) // Reset is an admin op on an already-started switch

	if err := r.Reset(context.Background()); err != nil {
		t.Fatalf("Reset returned error: %v", err)
	}

	blocked, err := r.ShouldBlock(context.Background(), "victim", "")
	if err != nil {
		t.Fatalf("ShouldBlock error: %v", err)
	}
	if !blocked {
		t.Error("a kill that raced into Redis during Reset must be re-seeded by Reset's trailing refreshState and block ShouldBlock")
	}
}

// cancelDuringResetFake cancels the Reset caller's context (via cancelFn) from
// inside Publish — the last of Reset's durable writes, so it fires after the
// Del/Publish work Reset must not lose and before the trailing best-effort
// refreshState reseed — reproducing a caller who tears its request-scoped
// context down as soon as Reset's synchronous Redis writes return. Get/Scan
// report the passed-in context's cancellation as their own error, so this fake
// surfaces (rather than silently tolerates) a reseed that is ever wired back to
// the caller's ctx instead of the switch's long-lived runCtx.
type cancelDuringResetFake struct {
	redis.Cmdable
	cancelFn context.CancelFunc
}

func (f *cancelDuringResetFake) Get(ctx context.Context, _ string) *redis.StringCmd {
	if err := ctx.Err(); err != nil {
		return redis.NewStringResult("", err)
	}
	return redis.NewStringResult("", redis.Nil)
}

func (f *cancelDuringResetFake) Scan(ctx context.Context, _ uint64, _ string, _ int64) *redis.ScanCmd {
	if err := ctx.Err(); err != nil {
		return redis.NewScanCmdResult(nil, 0, err)
	}
	return redis.NewScanCmdResult(nil, 0, nil)
}

func (f *cancelDuringResetFake) Del(_ context.Context, _ ...string) *redis.IntCmd {
	return redis.NewIntResult(0, nil)
}

func (f *cancelDuringResetFake) Publish(_ context.Context, _ string, _ interface{}) *redis.IntCmd {
	f.cancelFn()
	return redis.NewIntResult(0, nil)
}

// TestRedis_Reset_TrailingReseedIgnoresCanceledCallerContext is the regression for
// Reset's trailing best-effort reseed being tied to the caller's ctx: a
// request-scoped ctx canceled the instant Reset's durable writes (Del/Publish)
// return would otherwise make refreshState's Get/Scan fail with
// context.Canceled, recorded via recordRefreshErr as a genuine backend-health
// failure — tripping ShouldBlock's fail-closed non-match path (denying every
// request) for up to a reconcile tick against an otherwise-healthy Redis. The
// reseed must run on the switch's long-lived runCtx instead, independent of the
// caller's ctx lifetime.
func TestRedis_Reset_TrailingReseedIgnoresCanceledCallerContext(t *testing.T) {
	t.Parallel()
	callCtx, callCancel := context.WithCancel(context.Background())
	defer callCancel()

	r := NewRedis(&cancelDuringResetFake{cancelFn: callCancel})
	r.Start(context.Background()) // seeds runCtx, independent of callCtx
	defer r.Stop()

	if err := r.Reset(callCtx); err != nil {
		t.Fatalf("Reset returned error: %v", err)
	}

	r.mu.RLock()
	refreshErr := r.lastRefreshErr
	r.mu.RUnlock()
	if refreshErr != nil {
		t.Errorf("Reset's trailing reseed must not record the caller's canceled context as a refresh failure, got: %v", refreshErr)
	}

	// A healthy, non-killed subject must not be denied by a spurious fail-closed
	// window opened by the misattributed cancellation.
	blocked, err := r.ShouldBlock(context.Background(), "some-agent", "")
	if err != nil {
		t.Errorf("ShouldBlock must not fail closed after a clean Reset, got: %v", err)
	}
	if blocked {
		t.Error("a non-killed agent must not be blocked after a clean Reset")
	}
}

// pubsubResetFake serves a kill that is durably present in Redis while a "reset"
// pub/sub event arrives. A replica that merely cleared its local cache (without
// re-reading Redis) would miss it; Scan always surfaces the agent key.
type pubsubResetFake struct {
	redis.Cmdable
	agentID string
}

func (f *pubsubResetFake) Get(_ context.Context, _ string) *redis.StringCmd {
	return redis.NewStringResult("", redis.Nil) // no global kill
}

func (f *pubsubResetFake) Scan(_ context.Context, _ uint64, match string, _ int64) *redis.ScanCmd {
	if strings.HasPrefix(match, redisAgentPrefix) {
		return redis.NewScanCmdResult([]string{redisAgentPrefix + f.agentID}, 0, nil)
	}
	return redis.NewScanCmdResult(nil, 0, nil)
}

// TestRedis_HandlePubSubMessage_Reset_RefreshesFromRedis verifies that a "reset"
// pub/sub event must clear stale local state AND re-read Redis, so a kill that
// raced the publisher's delete sweep (durable in Redis, never deleted) is
// re-seeded on the receiving replica instead of remaining invisible to ShouldBlock
// until the next reconcile tick.
func TestRedis_HandlePubSubMessage_Reset_RefreshesFromRedis(t *testing.T) {
	t.Parallel()
	r := NewRedis(&pubsubResetFake{agentID: "victim"})
	// Start launches the drainRefreshTrigger goroutine that now runs the
	// reset-triggered SCAN asynchronously. Stop tears it down.
	r.Start(context.Background())
	t.Cleanup(r.Stop)

	// Stale local kill that the reset must clear.
	r.mu.Lock()
	r.killedAgents["stale"] = true
	r.mu.Unlock()

	r.handlePubSubMessage("reset")

	// The cache clear is synchronous (under the lock), so the stale kill is gone
	// immediately.
	if blocked, _ := r.ShouldBlock(context.Background(), "stale", ""); blocked {
		t.Error("reset event must clear stale local kill state")
	}
	// The trailing refresh is now asynchronous: the drainRefreshTrigger goroutine
	// re-reads Redis and re-seeds the durable "victim" kill. Poll until it converges.
	require.Eventually(t, func() bool {
		blocked, _ := r.ShouldBlock(context.Background(), "victim", "")
		return blocked
	}, 2*time.Second, 5*time.Millisecond,
		"a kill durably present in Redis must survive a reset event via the async trailing refresh")
}

// newDegradedRedis returns a *Redis whose lastRefreshErr is set, simulating a
// backend whose most recent refresh failed, without standing up a server.
func newDegradedRedis(t *testing.T, failOpen bool) *Redis {
	t.Helper()
	r := &Redis{
		killedAgents:   map[string]bool{},
		killedSessions: map[string]bool{},
		lastRefreshErr: errors.New("dial tcp 10.0.0.5:6379: connect: connection refused"),
		failOpen:       failOpen,
	}
	// Started, so ShouldBlock exercises the degraded-mode decision logic rather than the
	// pre-Start fail-closed guard: these tests simulate a switch that HAS been started and
	// then degraded, not one that was never started.
	markStarted(t, r)
	return r
}

func TestRedis_ShouldBlock_FailClosedByDefault_WhenDegraded(t *testing.T) {
	t.Parallel()
	r := newDegradedRedis(t, false)

	blocked, err := r.ShouldBlock(context.Background(), "agent-1", "sess-1")
	require.Error(t, err, "default fail-closed: a degraded backend must surface an error so the caller denies")
	require.ErrorIs(t, err, ErrBackendUnreachable)
	assert.False(t, blocked)
}

func TestRedis_ShouldBlock_FailClosed_DoesNotLeakBackendError(t *testing.T) {
	t.Parallel()
	r := newDegradedRedis(t, false)

	_, err := r.ShouldBlock(context.Background(), "", "sess-1")
	require.Error(t, err)
	// The underlying redis dial error (host:port, etc.) must NOT be wrapped into
	// the client-facing error -- only the static sentinel -- so backend connection
	// details cannot leak into a denial message returned to the MCP host.
	assert.NotContains(t, err.Error(), "connection refused")
	assert.NotContains(t, err.Error(), "10.0.0.5")
}

func TestRedis_ShouldBlock_FailOpen_OptIn_WhenDegraded(t *testing.T) {
	t.Parallel()
	r := newDegradedRedis(t, true)

	blocked, err := r.ShouldBlock(context.Background(), "agent-1", "sess-1")
	require.NoError(t, err, "fail-open opt-in must not error on a degraded backend")
	assert.False(t, blocked, "no kill in local cache -> not blocked under fail-open")
}

func TestRedis_ShouldBlock_FailOpen_StillHonoursCachedKill_WhenDegraded(t *testing.T) {
	t.Parallel()
	r := newDegradedRedis(t, true)
	r.killedSessions["sess-1"] = true

	blocked, err := r.ShouldBlock(context.Background(), "", "sess-1")
	require.NoError(t, err)
	assert.True(t, blocked, "a kill already in the local cache still blocks under fail-open")
}

func TestRedis_ShouldBlock_FailClosed_CachedKillIsKnownState_NoError(t *testing.T) {
	t.Parallel()
	// Even degraded and fail-closed, a kill already present in the local cache is
	// known state: it blocks as an ordinary kill (no error), so the audit record
	// carries KILL_SWITCH rather than KILL_SWITCH_ERROR.
	r := newDegradedRedis(t, false)
	r.globalActive = true

	blocked, err := r.ShouldBlock(context.Background(), "", "")
	require.NoError(t, err, "a cached global kill is confirmed state, not an unconfirmed request")
	assert.True(t, blocked)
}

func TestRedis_ShouldBlock_Healthy_Unaffected(t *testing.T) {
	t.Parallel()
	// lastRefreshErr nil (healthy): the default fail-closed mode behaves exactly
	// as before -- allow what is not killed, block what is.
	r := &Redis{
		killedAgents:   map[string]bool{},
		killedSessions: map[string]bool{"sess-1": true},
	}
	markStarted(t, r) // a started, healthy switch
	blocked, err := r.ShouldBlock(context.Background(), "", "sess-1")
	require.NoError(t, err)
	assert.True(t, blocked)

	blocked, err = r.ShouldBlock(context.Background(), "", "sess-2")
	require.NoError(t, err)
	assert.False(t, blocked)
}

func TestRedis_WithFailOpen_DefaultsClosed(t *testing.T) {
	t.Parallel()
	assert.False(t, NewRedis(nil).failOpen, "NewRedis must default to fail-closed")
	assert.True(t, NewRedis(nil, WithFailOpen(true)).failOpen)
	assert.False(t, NewRedis(nil, WithFailOpen(false)).failOpen)
}

// TestRedis_ShouldBlock_FailClosed_AfterRealRefreshFailure drives the behaviour
// end-to-end: a closed miniredis makes refreshState fail and populate
// lastRefreshErr, after which ShouldBlock denies in the default mode.
func TestRedis_ShouldBlock_FailClosed_AfterRealRefreshFailure(t *testing.T) {
	t.Parallel()
	mr := miniredis.NewMiniRedis()
	require.NoError(t, mr.Start())
	addr := mr.Addr()
	mr.Close() // backend down: all commands now fail

	client := redis.NewClient(&redis.Options{Addr: addr, PoolSize: 1, DialTimeout: 100 * time.Millisecond})
	t.Cleanup(func() { _ = client.Close() })

	r := NewRedis(client)
	markStarted(t, r) // a started switch whose refresh then fails
	require.Error(t, r.refreshState(context.Background()), "refresh against a closed backend must fail")

	_, err := r.ShouldBlock(context.Background(), "", "sess-1")
	require.ErrorIs(t, err, ErrBackendUnreachable, "default fail-closed: degraded backend must block")
}

// genRaceClient wraps a real Redis client and fires a one-shot hook the first
// time the session-prefix SCAN runs, letting a test deterministically inject a
// cache mutation into the window between refreshState's lock-free scan and its
// guarded swap.
type genRaceClient struct {
	redis.Cmdable
	mu   sync.Mutex
	hook func()
}

func (c *genRaceClient) Scan(ctx context.Context, cursor uint64, match string, count int64) *redis.ScanCmd {
	c.mu.Lock()
	h := c.hook
	if h != nil && strings.HasPrefix(match, redisSessionPfx) {
		c.hook = nil
	} else {
		h = nil
	}
	c.mu.Unlock()
	if h != nil {
		h()
	}
	return c.Cmdable.Scan(ctx, cursor, match, count)
}

// TestRedis_RefreshState_DoesNotEraseConcurrentKill verifies that a kill that
// lands in the local cache after refreshState's agent SCAN snapshot was captured
// but before the swap must not be erased by that stale snapshot. The
// session-prefix SCAN triggers a hook that applies an agent kill through the
// pub/sub path (bumping cacheGen) and writes the durable Redis key — exactly the
// race window. With the generation guard, refreshState detects the concurrent
// mutation, re-reads Redis, and the kill survives; without it the empty agent
// snapshot would overwrite the cache and ShouldBlock would fail open.
func TestRedis_RefreshState_DoesNotEraseConcurrentKill(t *testing.T) {
	mr := miniredis.NewMiniRedis()
	require.NoError(t, mr.Start())
	t.Cleanup(mr.Close)

	base := redis.NewClient(&redis.Options{Addr: mr.Addr(), DialTimeout: 200 * time.Millisecond})
	t.Cleanup(func() { _ = base.Close() })

	hc := &genRaceClient{Cmdable: base}
	r := NewRedis(hc)
	markStarted(t, r) // refreshState's gen-race logic on a started switch

	hc.hook = func() {
		require.NoError(t, base.Set(context.Background(), redisAgentPrefix+"victim", "1", 0).Err())
		r.handlePubSubMessage("agent:kill:victim")
	}

	require.NoError(t, r.refreshState(context.Background()))
	require.True(t, hc.hook == nil, "scan hook must have fired during the refresh")

	blocked, err := r.ShouldBlock(context.Background(), "victim", "")
	require.NoError(t, err)
	assert.True(t, blocked, "kill applied during the refresh scan window must not be erased")
}

// serialScanClient records the maximum number of Scan calls in flight at once, so
// a test can assert refreshState never scans concurrently with itself.
type serialScanClient struct {
	redis.Cmdable
	mu  sync.Mutex
	cur int
	max int
}

func (c *serialScanClient) Scan(ctx context.Context, cursor uint64, match string, count int64) *redis.ScanCmd {
	c.mu.Lock()
	c.cur++
	if c.cur > c.max {
		c.max = c.cur
	}
	c.mu.Unlock()
	time.Sleep(2 * time.Millisecond) // widen the overlap window a missing lock would expose
	c.mu.Lock()
	c.cur--
	c.mu.Unlock()
	return c.Cmdable.Scan(ctx, cursor, match, count)
}

func (c *serialScanClient) maxConcurrent() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.max
}

// TestRedis_RefreshState_Serialized is the regression for the refresh-vs-refresh
// reorder: two concurrent refreshes capture the same cacheGen and neither commit
// bumps it, so without serialization an OLDER scan could commit after a NEWER one
// and erase a kill until the next reconcile tick. refreshMu must serialize the
// whole scan+commit, so at most one refresh scans Redis at a time.
func TestRedis_RefreshState_Serialized(t *testing.T) {
	mr := miniredis.NewMiniRedis()
	require.NoError(t, mr.Start())
	t.Cleanup(mr.Close)

	base := redis.NewClient(&redis.Options{Addr: mr.Addr(), DialTimeout: 200 * time.Millisecond})
	t.Cleanup(func() { _ = base.Close() })

	sc := &serialScanClient{Cmdable: base}
	r := NewRedis(sc)
	markStarted(t, r)

	const n = 6
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = r.refreshState(context.Background())
		}()
	}
	wg.Wait()

	if got := sc.maxConcurrent(); got != 1 {
		t.Fatalf("refreshState scans overlapped (max concurrency %d, want 1); refreshMu must serialize refreshes so an older scan cannot commit after a newer one", got)
	}
}

// blockingGetClient wraps a real Redis client and blocks the FIRST Get call until
// release is closed, signalling on entered once it is inside that Get. It lets a
// test pin Start inside its synchronous initial refreshState while a concurrent
// Stop is issued.
type blockingGetClient struct {
	redis.Cmdable
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *blockingGetClient) Get(ctx context.Context, key string) *redis.StringCmd {
	c.once.Do(func() {
		close(c.entered)
		<-c.release
	})
	return c.Cmdable.Get(ctx, key)
}

// TestRedis_Stop_WaitsForConcurrentStart verifies that a Stop that races an
// in-flight Start must NOT return while Start is still inside its synchronous
// initial refresh using the Redis client. Previously Stop read cancel and called
// wg.Wait() before Start had reached its wg.Add calls, so wg.Wait returned on a
// zero counter and Stop returned while Start was still using the client. lifeMu
// now serializes Stop against the whole Start body, so Stop blocks until Start
// has published cancel, finished the refresh, and registered both goroutines.
func TestRedis_Stop_WaitsForConcurrentStart(t *testing.T) {
	mr := miniredis.NewMiniRedis()
	require.NoError(t, mr.Start())
	t.Cleanup(mr.Close)

	base := redis.NewClient(&redis.Options{Addr: mr.Addr(), DialTimeout: 200 * time.Millisecond})
	t.Cleanup(func() { _ = base.Close() })

	bc := &blockingGetClient{
		Cmdable: base,
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	r := NewRedis(bc)

	go r.Start(context.Background())

	// Wait until Start is inside the initial refresh's blocking Get.
	select {
	case <-bc.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("Start never entered the initial refresh")
	}

	stopDone := make(chan struct{})
	go func() { r.Stop(); close(stopDone) }()

	// Stop must block on lifeMu while Start holds it mid-refresh; it must not return
	// while Start is still using the Redis client.
	select {
	case <-stopDone:
		t.Fatal("Stop returned while a concurrent Start was still using the Redis client")
	case <-time.After(150 * time.Millisecond):
		// Expected: Stop is correctly blocked.
	}

	// Release the in-flight refresh; Start completes and Stop can now finish.
	close(bc.release)
	select {
	case <-stopDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return after Start completed")
	}
}

// TestRedis_StopBeforeStartIsNoOp verifies that a Stop that wins the race against
// Start (or precedes it) marks the switch stopped so a later Start launches no
// goroutines and does not touch the Redis client.
func TestRedis_StopBeforeStartIsNoOp(t *testing.T) {
	mr := miniredis.NewMiniRedis()
	require.NoError(t, mr.Start())
	t.Cleanup(mr.Close)

	base := redis.NewClient(&redis.Options{Addr: mr.Addr(), DialTimeout: 200 * time.Millisecond})
	t.Cleanup(func() { _ = base.Close() })

	r := NewRedis(base)
	r.Stop() // before Start

	r.Start(context.Background())

	// Start must have been a no-op: no goroutines registered, so a second Stop
	// returns immediately without hanging.
	done := make(chan struct{})
	go func() { r.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop hung after a Stop-before-Start sequence")
	}
}

// windowClient embeds a real *redis.Client (so Subscribe and the rest of
// redis.Cmdable are promoted) but overrides Scan to fire a one-shot side effect
// immediately AFTER the session-prefix scan returns. That reproduces the
// startup race: a kill written and published in the window between the snapshot's
// final SCAN and an active subscription.
type windowClient struct {
	*redis.Client
	once sync.Once
	fn   func()
}

func (w *windowClient) Scan(ctx context.Context, cursor uint64, match string, count int64) *redis.ScanCmd {
	cmd := w.Client.Scan(ctx, cursor, match, count)
	if strings.Contains(match, "session:") {
		// The session scan is the snapshot's last read; inject the racing kill now,
		// after it has returned, so the snapshot cannot include it.
		w.once.Do(w.fn)
	}
	return cmd
}

// A kill written and published while Start is taking its initial snapshot must
// not be lost. With the subscription established and confirmed before the
// snapshot, the published event reaches the listener (which bumps cacheGen and
// forces the in-flight refresh to re-read), so the killed agent is blocked even
// though the periodic reconcile is far in the future.
func TestRedis_Start_KillDuringSnapshotWindowIsObserved(t *testing.T) {
	mr := miniredis.NewMiniRedis()
	if err := mr.Start(); err != nil {
		t.Fatalf("miniredis start: %v", err)
	}
	defer mr.Close()

	pub := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer func() { _ = pub.Close() }()

	inject := func() {
		// SET the durable kill and PUBLISH its event from a separate client, exactly
		// as a concurrent KillAgent on another instance would.
		if err := pub.Set(context.Background(), redisAgentPrefix+"alice", "1", 0).Err(); err != nil {
			t.Errorf("inject SET: %v", err)
		}
		if err := pub.Publish(context.Background(), redisPubSubChan, "agent:kill:alice").Err(); err != nil {
			t.Errorf("inject PUBLISH: %v", err)
		}
	}

	wc := &windowClient{Client: redis.NewClient(&redis.Options{Addr: mr.Addr()}), fn: inject}
	defer func() { _ = wc.Close() }()

	// A long reconcile interval ensures the kill can only be observed via the
	// pub/sub path established before the snapshot, not by a periodic re-read.
	ks := NewRedis(wc, WithReconcileInterval(time.Hour))
	ks.Start(context.Background())
	defer ks.Stop()

	deadline := time.Now().Add(3 * time.Second)
	for {
		blocked, _ := ks.ShouldBlock(context.Background(), "alice", "")
		if blocked {
			return // observed the kill from the snapshot window
		}
		if time.Now().After(deadline) {
			t.Fatal("kill published during the startup snapshot window was never observed (subscription must be established before the snapshot)")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestRedis_RefreshState_ClearsErrorWhenNoFresherFailure pins recovery: a successful
// refresh clears a pre-existing lastRefreshErr so the switch stops failing closed.
// refreshMu serializes refreshes (recordRefreshErr is only ever called from within a
// refreshState that holds it), so a successful scan's commit can unconditionally
// clear the health stamp — there is no concurrent refresh that could have recorded a
// fresher error mid-scan.
func TestRedis_RefreshState_ClearsErrorWhenNoFresherFailure(t *testing.T) {
	t.Parallel()
	r, _ := newStartedTestRedis(t)

	// Seed a stale error as if a prior refresh had failed.
	r.recordRefreshErr(errors.New("previous outage"))

	// A clean successful refresh with no concurrent failure must clear it.
	require.NoError(t, r.refreshState(context.Background()))

	require.NoError(t, r.HealthStatus(),
		"a successful refresh with no fresher failure must clear the health stamp")

	blocked, err := r.ShouldBlock(context.Background(), "uncached-agent", "")
	assert.False(t, blocked)
	require.NoError(t, err, "recovered switch must stop failing closed")
}

// TestRedis_ShouldBlock_FailsClosedAfterContextCanceled is the regression for the
// liveness fail-open: once the Start context is canceled, the reconcile/pub-sub loops
// exit and the cache can no longer observe new kills. A ShouldBlock caller that
// outlives that context must then fail closed on a non-match (ErrStopped) rather than
// serve the frozen "nothing is killed" cache forever. This holds even under
// WithFailOpen — a stopped switch is a liveness failure, not a transient outage.
func TestRedis_ShouldBlock_FailsClosedAfterContextCanceled(t *testing.T) {
	t.Parallel()
	// even fail-open must not serve a frozen switch as all-clear
	r, _ := newTestRedis(t, WithFailOpen(true))

	ctx, cancel := context.WithCancel(context.Background())
	r.Start(ctx)
	t.Cleanup(r.Stop)

	// While the context is live, a non-match is a normal all-clear under fail-open.
	blocked, err := r.ShouldBlock(context.Background(), "uncached-agent", "")
	require.NoError(t, err)
	assert.False(t, blocked)

	// Cancel the Start context: the loops exit and the switch freezes.
	cancel()
	require.Eventually(t, func() bool {
		_, err := r.ShouldBlock(context.Background(), "uncached-agent", "")
		return errors.Is(err, ErrStopped)
	}, 2*time.Second, 5*time.Millisecond,
		"after its Start context is canceled, ShouldBlock must fail closed with ErrStopped on a non-match")
}

// TestRedis_WithSessionKillTTL covers the three-way branch its own doc calls a
// fail-open when set wrong: a negative value means "never expire", zero selects the
// default, and a positive value is taken verbatim. An expiring tombstone lifts the
// kill on a session that may still be connected, so an inverted branch here would
// silently un-kill live sessions — and every sibling option is asserted, so this one
// should be too.
func TestRedis_WithSessionKillTTL(t *testing.T) {
	t.Parallel()
	assert.Equal(t, defaultSessionKillTTL, NewRedis(nil).sessionKillTTL,
		"no option must keep the default")
	assert.Equal(t, defaultSessionKillTTL, NewRedis(nil, WithSessionKillTTL(0)).sessionKillTTL,
		"zero selects the default")
	assert.Equal(t, 90*time.Minute, NewRedis(nil, WithSessionKillTTL(90*time.Minute)).sessionKillTTL,
		"a positive value is taken verbatim")
	assert.Equal(t, time.Duration(0), NewRedis(nil, WithSessionKillTTL(-1)).sessionKillTTL,
		"a negative value opts out of expiry entirely (0 = no TTL stamped)")
}
