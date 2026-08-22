// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package killswitch

import (
	"context"
	"fmt"
	"sync"
)

// InMemory is an in-memory implementation of Manager for single-replica or dev use.
type InMemory struct {
	mu sync.RWMutex
	// globalActive, killedAgents and killedSessions are nil-safe to READ (the zero value is a
	// usable manager), but any method that ASSIGNS into either map must call ensureSetsLocked
	// first — assignment to a nil map panics, which is what it did before that helper existed.
	globalActive   bool
	killedAgents   map[string]bool
	killedSessions map[string]bool
	revokedJTIs    map[string]bool

	// observers receive a Revocation the moment this backend gains one — a consumer
	// calling Kill* directly on the Manager needs it too, not just one reclaiming at its
	// own /control/kill handler. Implemented on both backends so a consumer needs no
	// "which backend is this" test.
	observers revocationObservers
}

// NewInMemory creates an in-memory kill-switch manager. The zero value &InMemory{} is
// equally usable — the kill sets are created on the first write — so this is the
// intent-declaring spelling rather than a required initialization step, and the two cannot
// diverge into a usable shape and a trap.
func NewInMemory() *InMemory {
	return &InMemory{}
}

// ensureSetsLocked creates the kill sets if this InMemory was written as a zero value rather
// than built by NewInMemory. Caller must hold m.mu for writing.
//
// Reads already tolerate nil maps, so only the revoking assignments were affected — and they
// PANICKED, taking down an admin handler mid-request instead of recording the kill. A
// library-facing zero value must fail no worse than an unusable one.
func (m *InMemory) ensureSetsLocked() {
	if m.killedAgents == nil {
		m.killedAgents = make(map[string]bool)
	}
	if m.killedSessions == nil {
		m.killedSessions = make(map[string]bool)
	}
	if m.revokedJTIs == nil {
		m.revokedJTIs = make(map[string]bool)
	}
}

// HealthStatus implements [Manager]: an in-process kill set is always confirmable, so there
// is never a cause to report. Present so a Manager-typed consumer can ask the readiness
// question without a type switch on which backend it holds.
func (m *InMemory) HealthStatus() error { return nil }

// ShouldBlock checks whether any dimension of subj is killed.
//
// Order is broadest-first and is not load-bearing for the ANSWER — a match on any dimension
// blocks — but it keeps the cheapest check first and mirrors the Redis backend's gate chain, so
// the two cannot disagree about which revocation a given request is attributed to.
func (m *InMemory) ShouldBlock(_ context.Context, subj Subject) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.globalActive {
		return true, nil
	}
	if subj.AgentID != "" && m.killedAgents[subj.AgentID] {
		return true, nil
	}
	if subj.SessionID != "" && m.killedSessions[subj.SessionID] {
		return true, nil
	}
	if subj.JTI != "" && m.revokedJTIs[subj.JTI] {
		return true, nil
	}
	return false, nil
}

// ActivateGlobal activates the global kill switch.
func (m *InMemory) ActivateGlobal(_ context.Context) error {
	m.mu.Lock()
	gained := !m.globalActive
	m.globalActive = true
	m.mu.Unlock()
	// Notified outside the lock, and only on a state CHANGE: re-activating an already-active
	// stop reclaims nothing new, and an observer may re-enter this backend.
	if gained {
		m.observers.notify(Revocation{Global: true})
	}
	return nil
}

// DeactivateGlobal deactivates the global kill switch.
func (m *InMemory) DeactivateGlobal(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.globalActive = false
	return nil
}

// KillAgent blocks the specified agent.
func (m *InMemory) KillAgent(_ context.Context, agentID string) error {
	// Reject an empty ID: ShouldBlock skips empty IDs, so recording one would be a
	// silent no-op leaving a phantom "" entry in Status.
	if agentID == "" {
		return fmt.Errorf("killswitch: KillAgent: agentID must not be empty")
	}
	m.mu.Lock()
	m.ensureSetsLocked()
	gained := !m.killedAgents[agentID]
	m.killedAgents[agentID] = true
	m.mu.Unlock()
	if gained {
		m.observers.notify(Revocation{AgentID: agentID})
	}
	return nil
}

// ReviveAgent removes the kill on the specified agent.
func (m *InMemory) ReviveAgent(_ context.Context, agentID string) error {
	// Reject an empty ID to keep the call-site contract uniform with the Redis
	// backend, which must reject it to avoid a spurious fleet-wide refresh.
	if agentID == "" {
		return fmt.Errorf("killswitch: ReviveAgent: agentID must not be empty")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.killedAgents, agentID)
	return nil
}

// KillSession blocks the specified session.
func (m *InMemory) KillSession(_ context.Context, sessionID string) error {
	// Reject an empty ID for the same reason as KillAgent.
	if sessionID == "" {
		return fmt.Errorf("killswitch: KillSession: sessionID must not be empty")
	}
	m.mu.Lock()
	m.ensureSetsLocked()
	gained := !m.killedSessions[sessionID]
	m.killedSessions[sessionID] = true
	m.mu.Unlock()
	if gained {
		m.observers.notify(Revocation{SessionID: sessionID})
	}
	return nil
}

// ReviveSession removes the kill on the specified session.
func (m *InMemory) ReviveSession(_ context.Context, sessionID string) error {
	// Reject an empty ID to keep the call-site contract uniform with the Redis
	// backend.
	if sessionID == "" {
		return fmt.Errorf("killswitch: ReviveSession: sessionID must not be empty")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.killedSessions, sessionID)
	return nil
}

// RevokeJTI blocks every request presenting the bearer token with this id.
func (m *InMemory) RevokeJTI(_ context.Context, jti string) error {
	// Reject an empty id: ShouldBlock skips an empty dimension, so recording one would be a
	// silent no-op leaving a phantom "" entry in Status.
	if jti == "" {
		return fmt.Errorf("killswitch: RevokeJTI: jti must not be empty")
	}
	m.mu.Lock()
	m.ensureSetsLocked()
	gained := !m.revokedJTIs[jti]
	m.revokedJTIs[jti] = true
	m.mu.Unlock()
	// Notified outside the lock, and only on a state CHANGE, as the other revocations are:
	// re-revoking reclaims nothing new, and an observer may re-enter this backend.
	if gained {
		m.observers.notify(Revocation{JTI: jti})
	}
	return nil
}

// ReviveJTI removes the revocation on the specified token id.
func (m *InMemory) ReviveJTI(_ context.Context, jti string) error {
	// Reject an empty id to keep the call-site contract uniform with the Redis backend.
	if jti == "" {
		return fmt.Errorf("killswitch: ReviveJTI: jti must not be empty")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.revokedJTIs, jti)
	return nil
}

// Reset clears all kill-switch state.
func (m *InMemory) Reset(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.globalActive = false
	m.killedAgents = make(map[string]bool)
	m.killedSessions = make(map[string]bool)
	m.revokedJTIs = make(map[string]bool)
	return nil
}

// Status returns the current kill-switch state.
func (m *InMemory) Status(_ context.Context) (*Status, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return buildStatus(m.globalActive, m.killedAgents, m.killedSessions, m.revokedJTIs), nil
}

// ObserveRevocations implements [Manager]. Every revocation is issued in-process, so an
// observer is called synchronously on the calling goroutine, after state is committed and
// outside the lock, so it may re-ask ShouldBlock and see the kill it was told about.
func (m *InMemory) ObserveRevocations(fn func(Revocation)) func() { return m.observers.observe(fn) }
