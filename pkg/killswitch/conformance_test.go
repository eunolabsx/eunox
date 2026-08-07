// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package killswitch

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// managerBackend is one implementation under the cross-backend conformance table.
//
// contracts.go proves at COMPILE time that both backends carry every method; nothing proved
// they answer the same. A backend can satisfy Manager in full and still return the silent
// (false, nil) all-clear in the state the confirmability rule exists for — the one failure the
// kill switch is there to prevent — so the rule is checked here rather than asserted in prose.
type managerBackend struct {
	name string
	// ready builds a backend whose kill set is confirmable, the state every consumer runs it in.
	ready func(t *testing.T) Manager
	// unconfirmed builds one that CANNOT confirm its kill set, or is nil for a backend with no
	// such state: InMemory holds the set in-process, so there is nothing it could fail to
	// confirm. Distinguishing the two is the point of the field — "has no unconfirmed state" is
	// a property of the backend, not a row to skip silently.
	unconfirmed func(t *testing.T) Manager
}

func managerBackends() []managerBackend {
	return []managerBackend{
		{
			name:  "InMemory",
			ready: func(*testing.T) Manager { return NewInMemory() },
		},
		{
			// The ZERO value: nothing in-tree builds one, but a library consumer can write
			// &killswitch.InMemory{}, and it must answer the same contract rather than panicking
			// on assignment to a nil map the first time an operator kills something.
			name:  "InMemoryZeroValue",
			ready: func(*testing.T) Manager { return &InMemory{} },
		},
		{
			name: "Redis",
			ready: func(t *testing.T) Manager {
				t.Helper()
				r, _ := newTestRedis(t)
				r.Start(context.Background())
				t.Cleanup(r.Stop)
				return r
			},
			unconfirmed: func(t *testing.T) Manager {
				t.Helper()
				// Never started: the cache was never loaded, so an empty kill set is a state this
				// backend cannot vouch for.
				r, _ := newTestRedis(t)
				return r
			},
		},
	}
}

// awaitBlock polls ShouldBlock until it reports want, so one table serves both a synchronous
// backend and one that also consumes its own pub/sub echo (an in-flight kill echo applied
// after a revive transiently re-adds the id — fail-closed and self-correcting, but not
// instantaneous). An error is never the answer here: these cases run on a confirmable backend.
func awaitBlock(t *testing.T, m Manager, agentID, sessionID string, want bool, msg string) {
	t.Helper()
	var lastErr error
	require.Eventuallyf(t, func() bool {
		blocked, err := m.ShouldBlock(context.Background(), agentID, sessionID)
		lastErr = err
		return err == nil && blocked == want
	}, 2*time.Second, 5*time.Millisecond, "%s (last error: %v)", msg, lastErr)
}

// TestManagerConformance_ReadyBackendsAnswerAlike runs the whole Manager contract against
// every backend in its ready state, so "the backends behave alike" is checked rather than
// assumed by a consumer holding the interface.
func TestManagerConformance_ReadyBackendsAnswerAlike(t *testing.T) {
	t.Parallel()
	for _, b := range managerBackends() {
		t.Run(b.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			m := b.ready(t)

			require.NoError(t, m.HealthStatus(), "a ready backend must report no cause: its kill set is confirmable")

			// An empty id is rejected rather than recorded: ShouldBlock skips empty ids, so a
			// stored "" would be a kill that blocks nothing while showing up in Status.
			require.Error(t, m.KillAgent(ctx, ""), "KillAgent(\"\") must be refused, not recorded as a no-op kill")
			require.Error(t, m.KillSession(ctx, ""), "KillSession(\"\") must be refused, not recorded as a no-op kill")
			require.Error(t, m.ReviveAgent(ctx, ""), "ReviveAgent(\"\") must be refused for the same reason")
			require.Error(t, m.ReviveSession(ctx, ""), "ReviveSession(\"\") must be refused for the same reason")

			awaitBlock(t, m, "agent-1", "sess-1", false, "a fresh backend must block nothing")

			require.NoError(t, m.KillAgent(ctx, "agent-1"))
			awaitBlock(t, m, "agent-1", "", true, "a killed agent must block")
			awaitBlock(t, m, "agent-2", "", false, "an unrelated agent must not block")

			require.NoError(t, m.KillSession(ctx, "sess-1"))
			awaitBlock(t, m, "", "sess-1", true, "a killed session must block")

			status, err := m.Status(ctx)
			require.NoError(t, err, "a ready backend's snapshot is confirmable")
			require.Equal(t, []string{"agent-1"}, status.KilledAgents)
			require.Equal(t, []string{"sess-1"}, status.KilledSessions)
			require.False(t, status.GlobalActive)

			require.NoError(t, m.ReviveAgent(ctx, "agent-1"))
			awaitBlock(t, m, "agent-1", "", false, "a revived agent must stop blocking")
			require.NoError(t, m.ReviveSession(ctx, "sess-1"))
			awaitBlock(t, m, "", "sess-1", false, "a revived session must stop blocking")

			require.NoError(t, m.ActivateGlobal(ctx))
			awaitBlock(t, m, "", "", true, "the emergency stop must block traffic naming no agent or session")
			require.NoError(t, m.DeactivateGlobal(ctx))
			awaitBlock(t, m, "", "", false, "a deactivated emergency stop must stop blocking")

			require.NoError(t, m.KillAgent(ctx, "agent-3"))
			require.NoError(t, m.Reset(ctx))
			awaitBlock(t, m, "agent-3", "", false, "Reset must clear the kill set")
			status, err = m.Status(ctx)
			require.NoError(t, err)
			require.Empty(t, status.KilledAgents)
			require.Empty(t, status.KilledSessions)
		})
	}
}

// TestManagerConformance_RevocationsAreObservable pins the half of a kill that is not a read:
// a consumer reclaiming what a revoked session holds has no request to hang the work off, so
// every backend must deliver the trigger from its own write path, not only from a remote one.
func TestManagerConformance_RevocationsAreObservable(t *testing.T) {
	t.Parallel()
	for _, b := range managerBackends() {
		t.Run(b.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			m := b.ready(t)

			seen := make(chan Revocation, 8)
			unregister := m.ObserveRevocations(func(ev Revocation) { seen <- ev })

			require.NoError(t, m.KillSession(ctx, "sess-9"))
			select {
			case ev := <-seen:
				require.Equal(t, Revocation{SessionID: "sess-9"}, ev)
			case <-time.After(2 * time.Second):
				t.Fatal("a kill issued through this backend must reach its own observers")
			}

			// Idempotent, and it actually stops delivery: a consumer with a shorter lifetime than
			// the backend relies on both.
			unregister()
			unregister()
			require.NoError(t, m.KillAgent(ctx, "agent-9"))
			select {
			case ev := <-seen:
				t.Fatalf("observer was called after unregister: %+v", ev)
			case <-time.After(100 * time.Millisecond):
			}
		})
	}
}

// TestManagerConformance_UnconfirmedBackendNeverAllClears is the rule itself: in the state
// where a backend cannot confirm its kill set, every reader must report the cause. A backend
// answering (false, nil) here is indistinguishable from one confirming an empty kill set, so
// the consumer that would deny cannot tell it must.
func TestManagerConformance_UnconfirmedBackendNeverAllClears(t *testing.T) {
	t.Parallel()
	for _, b := range managerBackends() {
		if b.unconfirmed == nil {
			continue
		}
		t.Run(b.name, func(t *testing.T) {
			t.Parallel()
			m := b.unconfirmed(t)

			require.Error(t, m.HealthStatus(), "an unconfirmable backend must report the cause to a probe")

			blocked, err := m.ShouldBlock(context.Background(), "agent-1", "sess-1")
			require.Error(t, err, "a non-match must carry the cause rather than read as a confirmed all-clear")
			require.False(t, blocked, "the refusal is the error; a synthetic match would deny for the wrong stated reason")

			_, err = m.Status(context.Background())
			require.Error(t, err, "an unconfirmable snapshot must not be handed out as the whole kill set")
		})
	}
}

// TestInMemory_ZeroValueRecordsKillsRatherThanPanicking pins the specific misuse the table's
// zero-value row covers, at the two methods that write: they assigned into nil maps, so a
// consumer that wrote &InMemory{} lost the goroutine handling the kill instead of recording it.
func TestInMemory_ZeroValueRecordsKillsRatherThanPanicking(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	m := &InMemory{}

	require.NotPanics(t, func() {
		require.NoError(t, m.KillAgent(ctx, "agent-1"))
		require.NoError(t, m.KillSession(ctx, "sess-1"))
	})

	blocked, err := m.ShouldBlock(ctx, "agent-1", "")
	require.NoError(t, err)
	require.True(t, blocked)
	blocked, err = m.ShouldBlock(ctx, "", "sess-1")
	require.NoError(t, err)
	require.True(t, blocked)
}
