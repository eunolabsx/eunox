// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Package killswitch provides kill-switch management for blocking agents, sessions, or all traffic.
package killswitch

import (
	"context"
	"sort"
)

// Checker is the minimal read-only interface for components that only query
// whether a request should be blocked. The hot enforcement path accepts this
// rather than the full Manager, which it never needs.
type Checker interface {
	// ShouldBlock returns true if the given agent/session combination is killed.
	// An empty agentID or sessionID means the field is not evaluated for that dimension.
	ShouldBlock(ctx context.Context, agentID, sessionID string) (bool, error)
}

// Manager is the full kill-switch interface that embeds Checker and adds the
// admin and control-plane operations. Wire the full Manager where both read
// and write access is needed (e.g., the admin API handler); pass only Checker
// to read-only consumers.
type Manager interface {
	Checker

	// ActivateGlobal activates the global kill switch (blocks all requests).
	ActivateGlobal(ctx context.Context) error

	// DeactivateGlobal deactivates the global kill switch.
	DeactivateGlobal(ctx context.Context) error

	// KillAgent blocks all requests from the specified agent.
	// An empty agentID is an error: ShouldBlock skips empty IDs, so a
	// KillAgent("") would be a silent no-op that blocks nothing.
	KillAgent(ctx context.Context, agentID string) error

	// ReviveAgent removes the kill on the specified agent.
	ReviveAgent(ctx context.Context, agentID string) error

	// KillSession blocks all requests for the specified session.
	// An empty sessionID is an error for the same reason as KillAgent.
	KillSession(ctx context.Context, sessionID string) error

	// ReviveSession removes the kill on the specified session.
	ReviveSession(ctx context.Context, sessionID string) error

	// Reset clears all kill-switch state.
	Reset(ctx context.Context) error

	// Status returns the current kill-switch state.
	Status(ctx context.Context) (*Status, error)
}

// Status represents the current state of the kill switch.
type Status struct {
	GlobalActive   bool     `json:"globalActive"`
	KilledAgents   []string `json:"killedAgents"`
	KilledSessions []string `json:"killedSessions"`
}

// buildStatus assembles a *Status from the raw cache maps, sorting both id slices so
// the output is deterministic across calls (Go randomises map iteration order). Both
// the InMemory and Redis backends build their Status through this one helper so the
// two cannot drift. Call under the backend's read lock; the maps are only read.
func buildStatus(globalActive bool, killedAgents, killedSessions map[string]bool) *Status {
	return &Status{
		GlobalActive:   globalActive,
		KilledAgents:   sortedKeys(killedAgents),
		KilledSessions: sortedKeys(killedSessions),
	}
}

// sortedKeys returns m's keys in sorted order (empty, non-nil slice when m is empty)
// so a marshaled Status is stable regardless of Go's randomised map iteration.
func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for id := range m {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	return keys
}
