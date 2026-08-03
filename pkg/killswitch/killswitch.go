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

	// Status returns the current kill-switch state.
	Status(ctx context.Context) (*Status, error)

	// ObserveRevocations registers fn to be called whenever this backend's LOCAL view
	// gains a revocation — including one delivered from elsewhere (a sibling instance's
	// /control/kill, or `eunox kill --redis-addr`), which is the case a consumer cannot
	// observe any other way except by polling.
	//
	// It exists because a kill has two effects and only one of them is a read. Denying the
	// revoked traffic follows from ShouldBlock on the next request; RECLAIMING what the
	// revoked session holds — an upstream subprocess, a session slot, an open stream — has
	// no request to hang off, so a consumer that learns of a kill only through ShouldBlock
	// can reclaim nothing until something else happens to sweep. The eunox HTTP transport
	// swept on its IDLE reaper, which does not run at all under sessionIdleTimeoutMs: 0.
	//
	// Registering is additive; every registered fn is called. fn is invoked from the
	// backend's own delivery goroutines (for Redis, its pub/sub listener and its reconcile
	// loop), so it MUST NOT block — fan out and return. It is called OUTSIDE the backend's
	// lock, so fn may call back into the backend.
	//
	// The Revocation is a TRIGGER, not a work list: it names what this backend just learned,
	// while a consumer's correct response is to re-ask ShouldBlock for the things it holds.
	// Treating it as a work list means reimplementing the (agent, session, global) matching
	// the backend already does, in a second place, against ids the consumer may not have.
	//
	// Delivery is BEST-EFFORT and the observer is not a substitute for a periodic sweep: a
	// dropped pub/sub message, a backend with no real-time channel, or a consumer whose
	// registration happened after a kill all leave the state to be found by the next
	// reconcile. Every implementation also fires from its reconcile path for that reason,
	// but a consumer that must not miss one keeps its sweep as the backstop.
	//
	// It returns an idempotent unregister. A kill switch commonly OUTLIVES its consumer — it
	// is built once and handed to a proxy that may be reconstructed (a retry after a listener
	// error, a config reload) — and a registration with no way out keeps the dead consumer's
	// closure, and everything it captured, reachable forever while still being called on
	// every kill. A consumer with a lifetime shorter than the backend's must call it.
	ObserveRevocations(fn func(Revocation)) (unregister func())
}

// Revocation reports one kill a backend's local view just gained. Exactly one dimension is
// set: Global for the emergency stop, otherwise the agent or session id.
//
// It carries no "revive" counterpart on purpose. A revive RESTORES traffic, which the next
// ShouldBlock already reflects; there is nothing for a consumer to reclaim, and nothing it
// could undo (a torn-down upstream does not come back).
type Revocation struct {
	// Global is set for the emergency stop, which blocks every agent and session.
	Global bool
	// AgentID names a killed agent. A consumer holding no agent→session mapping does not
	// need one: re-asking ShouldBlock with each held session's own claims answers the same
	// question, through the same matching the backend already implements.
	AgentID string
	// SessionID names a killed session.
	SessionID string
}

// revocationObservers is the shared observer registry both backends embed, so registration,
// locking, and the call-outside-the-lock rule have one implementation rather than two that
// must agree about which goroutine holds what while a consumer's callback runs.
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

// observe registers fn and returns an idempotent unregister. Additive; safe to call
// concurrently with a notify.
//
// Registrations are keyed by a monotonic id rather than by slice index, so unregistering one
// cannot shift another's identity — an index-keyed removal silently unregisters the wrong
// observer as soon as two consumers share a backend, which is exactly the deployment that
// needs this.
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
			o.fns = slices.DeleteFunc(o.fns, func(r registeredObserver) bool { return r.id == id })
			o.mu.Unlock()
		})
	}
}

// notify calls every registered observer with ev. The caller must NOT hold the backend's own
// state lock: an observer's documented response is to re-ask ShouldBlock, which takes it.
//
// The slice header is copied under the read lock and iterated outside it, so an observer that
// unregisters itself (or another) from inside its own callback cannot deadlock; it may still be
// called for THIS event, which is the same at-most-one-more-call race any callback deregistration
// has.
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
