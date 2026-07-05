// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package killswitch

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- TEST-4: Concurrent Access Tests for Kill Switch ---

func TestInMemory_ConcurrentShouldBlock(t *testing.T) {
	t.Parallel()

	m := NewInMemory()
	require.NoError(t, m.ActivateGlobal(context.Background()))

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			blocked, err := m.ShouldBlock(context.Background(), "agent-1", "session-1")
			assert.NoError(t, err)
			assert.True(t, blocked, "goroutine %d: should be blocked", idx)
		}(i)
	}
	wg.Wait()
}

func TestInMemory_ConcurrentKillAndRevive(t *testing.T) {
	t.Parallel()

	m := NewInMemory()
	ctx := context.Background()

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	// Half the goroutines kill agents.
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			agentID := "agent-" + itoa(idx%10)
			_ = m.KillAgent(ctx, agentID)
		}(i)
	}

	// Half the goroutines revive agents.
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			agentID := "agent-" + itoa(idx%10)
			_ = m.ReviveAgent(ctx, agentID)
		}(i)
	}
	wg.Wait()

	// No panics or races — final state may vary (kill/revive run concurrently).
	// Just verify no error.
	_, err := m.Status(ctx)
	assert.NoError(t, err)
}

func TestInMemory_ConcurrentGlobalToggle(t *testing.T) {
	t.Parallel()

	m := NewInMemory()
	ctx := context.Background()

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			if idx%2 == 0 {
				_ = m.ActivateGlobal(ctx)
			} else {
				_ = m.DeactivateGlobal(ctx)
			}
		}(i)
	}
	wg.Wait()

	// Final state is either activated or deactivated — no panic.
	_, err := m.ShouldBlock(ctx, "agent-1", "session-1")
	assert.NoError(t, err)
}

func TestInMemory_ConcurrentSessionOperations(t *testing.T) {
	t.Parallel()

	m := NewInMemory()
	ctx := context.Background()

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines * 3)

	// Kill sessions.
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			_ = m.KillSession(ctx, "sess-"+itoa(idx%20))
		}(i)
	}

	// Revive sessions.
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			_ = m.ReviveSession(ctx, "sess-"+itoa(idx%20))
		}(i)
	}

	// Query concurrently.
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			_, _ = m.ShouldBlock(ctx, "agent-1", "sess-"+itoa(idx%20))
		}(i)
	}
	wg.Wait()
}

func TestInMemory_ConcurrentReset(t *testing.T) {
	t.Parallel()

	m := NewInMemory()
	ctx := context.Background()

	// Setup some state.
	_ = m.ActivateGlobal(ctx)
	_ = m.KillAgent(ctx, "agent-1")
	_ = m.KillSession(ctx, "session-1")

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	// Reset from multiple goroutines.
	for range goroutines {
		go func() {
			defer wg.Done()
			_ = m.Reset(ctx)
		}()
	}

	// Concurrent queries.
	for range goroutines {
		go func() {
			defer wg.Done()
			_, _ = m.ShouldBlock(ctx, "agent-1", "session-1")
		}()
	}
	wg.Wait()

	// After all resets, nothing should be blocked.
	blocked, err := m.ShouldBlock(ctx, "agent-1", "session-1")
	assert.NoError(t, err)
	assert.False(t, blocked)
}

func TestInMemory_ConcurrentStatus(t *testing.T) {
	t.Parallel()

	m := NewInMemory()
	ctx := context.Background()

	// Set up state.
	_ = m.ActivateGlobal(ctx)
	_ = m.KillAgent(ctx, "agent-a")
	_ = m.KillSession(ctx, "session-b")

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()
			status, err := m.Status(ctx)
			assert.NoError(t, err)
			assert.NotNil(t, status)
		}()
	}
	wg.Wait()
}

func itoa(i int) string {
	const digits = "0123456789"
	if i < 0 {
		return "-" + itoa(-i)
	}
	if i < 10 {
		return string(digits[i])
	}
	return itoa(i/10) + string(digits[i%10])
}
