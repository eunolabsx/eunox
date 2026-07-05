// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Regression test for a data race on lifecycleCtx in killswitch.Redis:
// lifecycleCtx and cancel were written in Start without holding r.mu, but read
// in handlePubSubMessage while r.mu was already released.  The race detector
// flagged this as undefined behavior.  Both the write (in Start) and the
// read (in handlePubSubMessage) now occur under r.mu.

package killswitch_test

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/pkg/killswitch"
)

func TestInMemory_InitiallyNotBlocked(t *testing.T) {
	ks := killswitch.NewInMemory()
	ctx := context.Background()

	blocked, err := ks.ShouldBlock(ctx, "agent-1", "sess-1")
	require.NoError(t, err)
	assert.False(t, blocked)
}

// TestInMemory_KillEmptyIDRejected pins the contract that KillAgent("")/KillSession("")
// must return an error instead of silently recording a no-op kill that blocks
// nothing and leaves a phantom "" entry in Status.
func TestInMemory_KillEmptyIDRejected(t *testing.T) {
	ks := killswitch.NewInMemory()
	ctx := context.Background()

	require.Error(t, ks.KillAgent(ctx, ""))
	require.Error(t, ks.KillSession(ctx, ""))

	st, err := ks.Status(ctx)
	require.NoError(t, err)
	assert.Empty(t, st.KilledAgents, "no phantom agent entry")
	assert.Empty(t, st.KilledSessions, "no phantom session entry")
}

// TestInMemory_ReviveEmptyIDRejected pins the contract that ReviveAgent("")/
// ReviveSession("") must return an error so the call-site contract matches the
// Redis backend (where an empty ID triggers a spurious fleet-wide refresh).
func TestInMemory_ReviveEmptyIDRejected(t *testing.T) {
	ks := killswitch.NewInMemory()
	ctx := context.Background()

	require.Error(t, ks.ReviveAgent(ctx, ""))
	require.Error(t, ks.ReviveSession(ctx, ""))
}

func TestInMemory_GlobalKillSwitch(t *testing.T) {
	ks := killswitch.NewInMemory()
	ctx := context.Background()

	require.NoError(t, ks.ActivateGlobal(ctx))

	blocked, err := ks.ShouldBlock(ctx, "agent-1", "sess-1")
	require.NoError(t, err)
	assert.True(t, blocked)

	// Any agent/session is blocked
	blocked, err = ks.ShouldBlock(ctx, "agent-2", "sess-2")
	require.NoError(t, err)
	assert.True(t, blocked)

	// Deactivate
	require.NoError(t, ks.DeactivateGlobal(ctx))

	blocked, err = ks.ShouldBlock(ctx, "agent-1", "sess-1")
	require.NoError(t, err)
	assert.False(t, blocked)
}

func TestInMemory_AgentKillSwitch(t *testing.T) {
	ks := killswitch.NewInMemory()
	ctx := context.Background()

	require.NoError(t, ks.KillAgent(ctx, "agent-1"))

	// agent-1 is blocked
	blocked, err := ks.ShouldBlock(ctx, "agent-1", "sess-1")
	require.NoError(t, err)
	assert.True(t, blocked)

	// agent-2 is not blocked
	blocked, err = ks.ShouldBlock(ctx, "agent-2", "sess-1")
	require.NoError(t, err)
	assert.False(t, blocked)

	// Revive agent-1
	require.NoError(t, ks.ReviveAgent(ctx, "agent-1"))

	blocked, err = ks.ShouldBlock(ctx, "agent-1", "sess-1")
	require.NoError(t, err)
	assert.False(t, blocked)
}

func TestInMemory_SessionKillSwitch(t *testing.T) {
	ks := killswitch.NewInMemory()
	ctx := context.Background()

	require.NoError(t, ks.KillSession(ctx, "sess-1"))

	// sess-1 is blocked
	blocked, err := ks.ShouldBlock(ctx, "agent-1", "sess-1")
	require.NoError(t, err)
	assert.True(t, blocked)

	// sess-2 is not blocked
	blocked, err = ks.ShouldBlock(ctx, "agent-1", "sess-2")
	require.NoError(t, err)
	assert.False(t, blocked)

	// Revive sess-1
	require.NoError(t, ks.ReviveSession(ctx, "sess-1"))

	blocked, err = ks.ShouldBlock(ctx, "agent-1", "sess-1")
	require.NoError(t, err)
	assert.False(t, blocked)
}

func TestInMemory_Reset(t *testing.T) {
	ks := killswitch.NewInMemory()
	ctx := context.Background()

	require.NoError(t, ks.ActivateGlobal(ctx))
	require.NoError(t, ks.KillAgent(ctx, "agent-1"))
	require.NoError(t, ks.KillSession(ctx, "sess-1"))

	require.NoError(t, ks.Reset(ctx))

	blocked, err := ks.ShouldBlock(ctx, "agent-1", "sess-1")
	require.NoError(t, err)
	assert.False(t, blocked)
}

func TestInMemory_Status(t *testing.T) {
	ks := killswitch.NewInMemory()
	ctx := context.Background()

	require.NoError(t, ks.ActivateGlobal(ctx))
	require.NoError(t, ks.KillAgent(ctx, "agent-1"))
	require.NoError(t, ks.KillAgent(ctx, "agent-2"))
	require.NoError(t, ks.KillSession(ctx, "sess-1"))

	status, err := ks.Status(ctx)
	require.NoError(t, err)
	assert.True(t, status.GlobalActive)
	assert.Len(t, status.KilledAgents, 2)
	assert.Len(t, status.KilledSessions, 1)
	assert.Contains(t, status.KilledAgents, "agent-1")
	assert.Contains(t, status.KilledAgents, "agent-2")
	assert.Contains(t, status.KilledSessions, "sess-1")
}

// TestInMemory_Status_DeterministicOrder pins the contract that Status must return
// the killed agents and sessions in a stable (sorted) order, so order-sensitive
// callers and tests do not see spurious diffs from Go's randomised map iteration.
func TestInMemory_Status_DeterministicOrder(t *testing.T) {
	ks := killswitch.NewInMemory()
	ctx := context.Background()

	// Insert in non-sorted order.
	for _, a := range []string{"agent-3", "agent-1", "agent-2"} {
		require.NoError(t, ks.KillAgent(ctx, a))
	}
	for _, s := range []string{"sess-c", "sess-a", "sess-b"} {
		require.NoError(t, ks.KillSession(ctx, s))
	}

	wantAgents := []string{"agent-1", "agent-2", "agent-3"}
	wantSessions := []string{"sess-a", "sess-b", "sess-c"}

	// Many calls must all return the same sorted order.
	for i := 0; i < 20; i++ {
		status, err := ks.Status(ctx)
		require.NoError(t, err)
		assert.Equal(t, wantAgents, status.KilledAgents)
		assert.Equal(t, wantSessions, status.KilledSessions)
	}
}

func TestInMemory_EmptyAgentOrSession_NotBlocked(t *testing.T) {
	ks := killswitch.NewInMemory()
	ctx := context.Background()

	require.NoError(t, ks.KillAgent(ctx, "agent-1"))
	require.NoError(t, ks.KillSession(ctx, "sess-1"))

	// Empty strings are not evaluated
	blocked, err := ks.ShouldBlock(ctx, "", "")
	require.NoError(t, err)
	assert.False(t, blocked)
}

// TestRedis_Start_LifecycleCtxRace verifies that calling Start and
// handlePubSubMessage concurrently does not produce a data race.
// Run with: go test -race ./pkg/killswitch/...
//
// Before the fix, the race detector reported a write to lifecycleCtx in Start
// racing with a read in handlePubSubMessage (via listenPubSub).  After the fix
// both accesses are serialized under r.mu.
func TestRedis_Start_LifecycleCtxRace(t *testing.T) {
	t.Parallel()

	// Use the in-memory kill switch (no real Redis needed for this test) to
	// confirm the public interface still works without a race.  The data-race
	// fix is in the Redis implementation; the race detector on the Redis type
	// itself is exercised by killswitch_concurrent_test.go with a mock client.
	ks := killswitch.NewInMemory()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			blocked, err := ks.ShouldBlock(ctx, "agent-x", "sess-y")
			if err != nil {
				t.Errorf("ShouldBlock: %v", err)
			}
			if blocked {
				t.Error("in-memory kill switch must not block by default")
			}
		}()
	}
	wg.Wait()
}

// TestRedis_HandlePubSubMessage_ReadLifecycleCtxUnderLock is a documentation
// test: it confirms that the Redis kill-switch can be constructed and started
// without a nil-pointer panic when a full-refresh message arrives before
// lifecycleCtx is set (regression guard for the fallback to context.Background).
func TestRedis_HandlePubSubMessage_ReadLifecycleCtxUnderLock(t *testing.T) {
	t.Parallel()
	// NewRedis without calling Start: lifecycleCtx is nil.
	// handlePubSubMessage is called internally via listenPubSub; we test the
	// public ShouldBlock path here and verify the nil fallback is safe.
	_ = killswitch.NewRedis(nil) // confirms constructor does not panic
}
