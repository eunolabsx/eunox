// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Package killswitch provides kill-switch management for blocking agents, sessions, or all traffic.
package killswitch

import (
	"context"
	"slices"
	"sort"
	"sync"
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

	// Status returns the current kill-switch state. A backend that loads its state
	// asynchronously reports an error rather than a snapshot until it has one (the Redis
	// backend's ErrNotStarted), since an empty snapshot cannot be told from an all-clear.
	Status(ctx context.Context) (*Status, error)

	// ObserveRevocations registers fn to be called whenever this backend's LOCAL view
	// gains a revocation, including one delivered from elsewhere (a sibling instance's
	// /control/kill, or `eunox kill --redis-addr`) — the only way a consumer can observe
	// that except by polling.
	//
	// It exists because a kill has two effects and only one is a read: denying revoked
	// traffic follows from ShouldBlock, but RECLAIMING what a revoked session holds (a
	// subprocess, a slot, an open stream) has no request to hang off. The eunox HTTP
	// transport's idle reaper swept for this, but does not run under sessionIdleTimeoutMs: 0.
	//
	// fn is invoked from the backend's own delivery goroutines and MUST NOT block, and is
	// called OUTSIDE the backend's lock so it may call back in. Revocation is a TRIGGER,
	// not a work list — the consumer's correct response is to re-ask ShouldBlock, not
	// reimplement the (agent, session, global) matching.
	//
	// Delivery is BEST-EFFORT, not a substitute for a periodic sweep: a dropped pub/sub
	// message or a late registration leaves state to be found by the next reconcile.
	//
	// The returned unregister is idempotent. A kill switch commonly OUTLIVES its consumer,
	// so a registration with no way out keeps a dead closure reachable forever; a consumer
	// with a shorter lifetime than the backend's must call it.
	ObserveRevocations(fn func(Revocation)) (unregister func())
}

// Revocation reports one kill a backend's local view just gained. Exactly one dimension is
// set: Global for the emergency stop, otherwise the agent or session id. It carries no
// "revive" counterpart on purpose — a revive restores traffic, which the next ShouldBlock
// already reflects, and there is nothing for a consumer to reclaim or undo.
type Revocation struct {
	// Global is set for the emergency stop, which blocks every agent and session.
	Global bool
	// AgentID names a killed agent.
	AgentID string
	// SessionID names a killed session.
	SessionID string
}

// revocationObservers is the shared observer registry both backends embed, so registration,
// locking, and the call-outside-the-lock rule have one implementation rather than two.
type revocationObservers struct {
	mu   sync.RWMutex
	fns  []registeredObserver
	next uint64
}

// registeredObserver is one registration: the callback plus the id its unregister closes over.
type registeredObserver struct {
	id uint64
	fn func(Revocation)
}

// observe registers fn and returns an idempotent unregister, safe to call concurrently
// with a notify. Keyed by a monotonic id, not slice index, so unregistering one cannot
// shift another's identity once two consumers share a backend.
func (o *revocationObservers) observe(fn func(Revocation)) func() {
	if fn == nil {
		return func() {}
	}
	o.mu.Lock()
	o.next++
	id := o.next
	o.fns = append(o.fns, registeredObserver{id: id, fn: fn})
	o.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			o.mu.Lock()
			// Clone before DeleteFunc: notify copies only the slice HEADER under RLock and
			// iterates after releasing the lock, so an in-place DeleteFunc (which shifts
			// surviving elements down and zeroes the tail of the backing array) would race
			// a concurrent notify's iteration over that same array. Cloning first makes
			// unregister copy-on-write, so any header a notify captured stays immutable.
			o.fns = slices.DeleteFunc(slices.Clone(o.fns), func(r registeredObserver) bool { return r.id == id })
			o.mu.Unlock()
		})
	}
}

// notify calls every registered observer with ev. The caller must NOT hold the backend's own
// state lock, since an observer's documented response is to re-ask ShouldBlock. The slice
// header is copied under the read lock and iterated outside it, so a self-unregistering
// observer cannot deadlock (it may still be called once more for this event).
func (o *revocationObservers) notify(ev Revocation) {
	o.mu.RLock()
	fns := o.fns
	o.mu.RUnlock()
	for _, r := range fns {
		r.fn(ev)
	}
}

// Status represents the current state of the kill switch.
type Status struct {
	GlobalActive   bool     `json:"globalActive"`
	KilledAgents   []string `json:"killedAgents"`
	KilledSessions []string `json:"killedSessions"`
}

// buildStatus assembles a *Status from the raw cache maps, sorting both id slices for
// deterministic output. Shared by both backends so the two cannot drift.
func buildStatus(globalActive bool, killedAgents, killedSessions map[string]bool) *Status {
	return &Status{
		GlobalActive:   globalActive,
		KilledAgents:   sortedKeys(killedAgents),
		KilledSessions: sortedKeys(killedSessions),
	}
}

// sortedKeys returns m's keys sorted, so a marshaled Status is stable regardless of Go's
// randomised map iteration.
func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for id := range m {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	return keys
}
