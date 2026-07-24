// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package flowlabelstore

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// numSessions reads the live session count under the lock. len of the internal map
// is not observable from the external test package, so the maxKeys invariants that
// assert "the map must not grow" / "a slot was reclaimed" live in-package.
func numSessions(m *InMemory) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sets)
}

// TestInMemory_WithMaxKeys_FailsClosedAtCapacity verifies the key bound: once the map
// is full, an Add creating a NEW session is refused without growing the map, while an
// existing session keeps accumulating; a slot freed by Clear is then reusable.
func TestInMemory_WithMaxKeys_FailsClosedAtCapacity(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	m := NewInMemory(WithMaxKeys(2))

	require.NoError(t, m.Add(ctx, "s1", "pii"))
	require.NoError(t, m.Add(ctx, "s2", "secret"))
	require.Equal(t, 2, numSessions(m))

	// A previously-unseen session past the bound is refused, fails closed, and the
	// map does not grow.
	err := m.Add(ctx, "s3", "phi")
	require.Error(t, err, "a new session at capacity must fail closed")
	assert.Contains(t, err.Error(), "session limit reached (2)")
	assert.Equal(t, 2, numSessions(m), "a refused Add must not grow the map")

	// An existing session still accumulates — the bound gates only NEW sessions.
	require.NoError(t, m.Add(ctx, "s1", "public"))
	got, err := m.Get(ctx, "s1")
	require.NoError(t, err)
	assert.Equal(t, []string{"pii", "public"}, got)
	assert.Equal(t, 2, numSessions(m))

	// Clear frees a slot; the new session is then admitted.
	require.NoError(t, m.Clear(ctx, "s2"))
	assert.Equal(t, 1, numSessions(m))
	require.NoError(t, m.Add(ctx, "s3", "phi"), "a slot freed by Clear must be reusable")
	assert.Equal(t, 2, numSessions(m))
}

// TestInMemory_Add_EmptyLabelsCreatesNoKey verifies that an empty-labels Add is a true
// no-op: it must not materialize a session entry (which would consume a maxKeys slot)
// nor make Get report a present session.
func TestInMemory_Add_EmptyLabelsCreatesNoKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	m := NewInMemory(WithMaxKeys(1))

	require.NoError(t, m.Add(ctx, "empty"))
	assert.Equal(t, 0, numSessions(m), "Add with no labels must not create a key")
	got, err := m.Get(ctx, "empty")
	require.NoError(t, err)
	assert.Empty(t, got)

	// The sole slot is still free, so a real session is admitted.
	require.NoError(t, m.Add(ctx, "real", "pii"))
	assert.Equal(t, 1, numSessions(m))
}

// TestInMemory_Remove_ReclaimsSlotWhenEmptied verifies that removing a session's last
// label drops the map entry, freeing its maxKeys slot for a new session.
func TestInMemory_Remove_ReclaimsSlotWhenEmptied(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	m := NewInMemory(WithMaxKeys(1))

	require.NoError(t, m.Add(ctx, "s1", "pii"))
	require.Error(t, m.Add(ctx, "s2", "secret"), "at capacity, a new session is refused")

	// Removing s1's last label empties its set, reclaiming the map slot (an empty set
	// is indistinguishable from an absent session), so s2 is then admitted.
	require.NoError(t, m.Remove(ctx, "s1", "pii"))
	assert.Equal(t, 0, numSessions(m), "removing the last label must reclaim the slot")
	require.NoError(t, m.Add(ctx, "s2", "secret"))
	assert.Equal(t, 1, numSessions(m))
}

// TestInMemory_MaxKeys_UnlimitedByDefault confirms the default (no WithMaxKeys,
// equivalently WithMaxKeys(0) or a negative) leaves the session count unbounded.
func TestInMemory_MaxKeys_UnlimitedByDefault(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	for _, m := range []*InMemory{NewInMemory(), NewInMemory(WithMaxKeys(0)), NewInMemory(WithMaxKeys(-1))} {
		for i := 0; i < 1000; i++ {
			sk := "session-" + string(rune('a'+i%26)) + "-" + string(rune('0'+i%10))
			if err := m.Add(ctx, sk, "pii"); err != nil {
				t.Fatalf("unbounded store returned error at add %d: %v", i, err)
			}
		}
	}
}
