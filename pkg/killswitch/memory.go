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
	mu             sync.RWMutex
	globalActive   bool
	killedAgents   map[string]bool
	killedSessions map[string]bool
}

// NewInMemory creates an in-memory kill-switch manager.
func NewInMemory() *InMemory {
	return &InMemory{
		killedAgents:   make(map[string]bool),
		killedSessions: make(map[string]bool),
	}
}

// ShouldBlock checks if the global, agent, or session kill switch is active.
func (m *InMemory) ShouldBlock(_ context.Context, agentID, sessionID string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.globalActive {
		return true, nil
	}
	if agentID != "" && m.killedAgents[agentID] {
		return true, nil
	}
	if sessionID != "" && m.killedSessions[sessionID] {
		return true, nil
	}
	return false, nil
}

// ActivateGlobal activates the global kill switch.
func (m *InMemory) ActivateGlobal(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.globalActive = true
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
	// silent no-op that blocks nothing and leaves a phantom "" entry in Status.
	if agentID == "" {
		return fmt.Errorf("killswitch: KillAgent: agentID must not be empty")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.killedAgents[agentID] = true
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
	defer m.mu.Unlock()
	m.killedSessions[sessionID] = true
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

// Reset clears all kill-switch state.
func (m *InMemory) Reset(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.globalActive = false
	m.killedAgents = make(map[string]bool)
	m.killedSessions = make(map[string]bool)
	return nil
}

// Status returns the current kill-switch state.
func (m *InMemory) Status(_ context.Context) (*Status, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return buildStatus(m.globalActive, m.killedAgents, m.killedSessions), nil
}
