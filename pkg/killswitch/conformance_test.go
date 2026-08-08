// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The cross-backend RULES of the Manager contract, and only those: what a consumer holding
// the interface may rely on without knowing which backend it holds. Each backend's own
// BEHAVIOR — what a kill blocks, what Status reports, Reset, the emergency stop, the observer
// registry's dedup and unregister semantics — is pinned per backend in killswitch_test.go,
// redis_internal_test.go and observers_test.go, which assert it more precisely than a table
// polling through the interface can (exact error sentinels, cache-before-publish visibility).
// Add a behavior case THERE; add a case here only for a property that must hold of every
// backend and that no single backend's suite can state.
//
// Re-running behavior here was strictly weaker than those suites — the copy could not fail
// without the original failing first — so it read as a second, authoritative home while
// pinning less.

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
	// unconfirmed builds EVERY state in which this backend cannot confirm its kill set, or is
	// empty for a backend with no such state: InMemory holds the set in-process, so there is
	// nothing it could fail to confirm. Distinguishing the two is the point of the field —
	// "has no unconfirmed state" is a property of the backend, not a row to skip silently.
	//
	// A list rather than one builder because Redis has several and they are gated differently:
	// the not-started guard sits AHEAD of the fail-open check, so a table sampling only that
	// state would exercise the one arm no configuration can weaken.
	unconfirmed []unconfirmedState
}

// unconfirmedState is one named way a backend loses confidence in its kill set.
type unconfirmedState struct {
	name  string
	build func(t *testing.T) Manager
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
			unconfirmed: []unconfirmedState{
				{
					// The cache was never loaded, so an empty kill set is a state this backend
					// cannot vouch for.
					name: "never started",
					build: func(t *testing.T) Manager {
						t.Helper()
						r, _ := newTestRedis(t)
						return r
					},
				},
				{
					// A refresh ran and failed. This is the state an operator actually hits — a
					// partition — and the one --killswitch-fail-open deliberately weakens, so the
					// default (fail-closed) posture is what the rule binds here.
					name:  "refresh failed",
					build: func(t *testing.T) Manager { return newDegradedRedis(t, false) },
				},
				{
					// Started, then stopped: the convergence loops have exited, so the cache can
					// never be confirmed again — a permanent cause, not a transient one.
					name: "convergence stopped",
					build: func(t *testing.T) Manager {
						t.Helper()
						r, _ := newTestRedis(t)
						r.Start(context.Background())
						r.Stop()
						return r
					},
				},
			},
		},
	}
}

// awaitBlock polls ShouldBlock until it reports want, so one table serves both a synchronous
// backend and one that also consumes its own pub/sub echo (an in-flight kill echo applied
// after a revive transiently re-adds the id — fail-closed and self-correcting, but not
// instantaneous). An error is never the answer here: these cases run on a confirmable backend.
//
// It polls by hand rather than through require.Eventuallyf because the diagnostic is the whole
// point: passing lastErr as a format ARG evaluates it at the call, before the first poll, so
// the message would report the zero error forever and send a reader after a wrong boolean when
// the backend was erroring.
func awaitBlock(t *testing.T, m Manager, agentID, sessionID string, want bool, msg string) {
	t.Helper()
	var lastErr error
	deadline := time.Now().Add(2 * time.Second)
	for {
		blocked, err := m.ShouldBlock(context.Background(), agentID, sessionID)
		lastErr = err
		if err == nil && blocked == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: ShouldBlock(%q, %q) = (%v, %v), want (%v, nil)", msg, agentID, sessionID, blocked, lastErr, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestManagerConformance_ReadyBackendsAgreeOnRefusalsAndRevive pins the two places a backend
// could satisfy Manager in full and still answer DIFFERENTLY from its sibling, in a direction
// a consumer holding the interface cannot detect:
//
//   - an empty id is REFUSED rather than recorded. ShouldBlock skips empty ids, so a backend
//     storing "" has a kill that blocks nothing while showing up in Status — an operator who
//     issued it reads the snapshot as proof it took.
//   - a revive is the exact inverse of the kill it undoes. A backend that records the revive
//     but keeps blocking (or blocks again on its own echo) strands the id for good, and the
//     only signal is traffic that never resumes.
//
// What a kill BLOCKS, what Status reports, Reset and the emergency stop are each backend's
// own suite (see this file's header): they are pinned there against the concrete backend
// rather than through a polling loop that must tolerate every backend's slowest path.
func TestManagerConformance_ReadyBackendsAgreeOnRefusalsAndRevive(t *testing.T) {
	t.Parallel()
	for _, b := range managerBackends() {
		t.Run(b.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			m := b.ready(t)

			require.NoError(t, m.HealthStatus(), "a ready backend must report no cause: its kill set is confirmable")

			require.Error(t, m.KillAgent(ctx, ""), "KillAgent(\"\") must be refused, not recorded as a no-op kill")
			require.Error(t, m.KillSession(ctx, ""), "KillSession(\"\") must be refused, not recorded as a no-op kill")
			require.Error(t, m.ReviveAgent(ctx, ""), "ReviveAgent(\"\") must be refused for the same reason")
			require.Error(t, m.ReviveSession(ctx, ""), "ReviveSession(\"\") must be refused for the same reason")

			require.NoError(t, m.KillAgent(ctx, "agent-1"))
			awaitBlock(t, m, "agent-1", "", true, "a killed agent must block")
			require.NoError(t, m.ReviveAgent(ctx, "agent-1"))
			awaitBlock(t, m, "agent-1", "", false, "a revived agent must stop blocking")

			require.NoError(t, m.KillSession(ctx, "sess-1"))
			awaitBlock(t, m, "", "sess-1", true, "a killed session must block")
			require.NoError(t, m.ReviveSession(ctx, "sess-1"))
			awaitBlock(t, m, "", "sess-1", false, "a revived session must stop blocking")
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
		t.Run(b.name, func(t *testing.T) {
			t.Parallel()
			if len(b.unconfirmed) == 0 {
				// Recorded as an exemption rather than dropped from the loop: a row that
				// vanishes reads the same as a row nobody wired, and the next backend whose
				// state stops being in-process would inherit that silence.
				t.Skip("in-process kill set: there is no state this backend could fail to confirm")
			}
			for _, state := range b.unconfirmed {
				t.Run(state.name, func(t *testing.T) {
					t.Parallel()
					m := state.build(t)

					require.Error(t, m.HealthStatus(), "an unconfirmable backend must report the cause to a probe")

					blocked, err := m.ShouldBlock(context.Background(), "agent-1", "sess-1")
					require.Error(t, err, "a non-match must carry the cause rather than read as a confirmed all-clear")
					require.False(t, blocked, "the refusal is the error; a synthetic match would deny for the wrong stated reason")

					_, err = m.Status(context.Background())
					require.Error(t, err, "an unconfirmable snapshot must not be handed out as the whole kill set")
				})
			}
		})
	}
}

// TestManagerConformance_FailOpenIsTheStatedException pins the one carve-out in the
// confirmability rule, so "every reader reports the cause" cannot quietly become false for the
// configuration an operator actually runs during a partition. Under --killswitch-fail-open the
// operator has chosen availability: ShouldBlock serves the cache and Status hands out a
// snapshot, and HealthStatus is the only reader that still reports the cause — which is why it
// is the signal the README tells them to alert on.
func TestManagerConformance_FailOpenIsTheStatedException(t *testing.T) {
	t.Parallel()
	var m Manager = newDegradedRedis(t, true)

	blocked, err := m.ShouldBlock(context.Background(), "agent-1", "sess-1")
	require.NoError(t, err, "fail-open serves the last-known cache rather than denying")
	require.False(t, blocked)

	_, err = m.Status(context.Background())
	require.NoError(t, err, "fail-open hands out the cached snapshot for the same reason")

	require.Error(t, m.HealthStatus(), "the reader an operator alerts on must still report the cause")
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
