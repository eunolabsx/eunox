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

// Subject is the identity a kill check is asked about: every dimension a revocation can name,
// in one value.
//
// A STRUCT rather than a parameter list, and the reason is the axis that was just added. Each
// dimension used to be a positional string, so adding one meant editing every implementation,
// every caller and every test in lockstep — and the failure mode of getting that wrong is
// silent, since the arguments are all strings and a transposed pair still compiles. Adding JTI
// here changed no signature at all.
//
// Passed and stored BY VALUE. It is three strings on the hot path — the kill check runs first
// in decision order, ahead of every policy evaluation — so a pointer would put it on the heap
// for nothing. The killswitch benchmarks assert ShouldBlock stays allocation-free.
//
// An empty field means that dimension is NOT evaluated, which is what lets a leg that knows
// only some of the identity ask anyway: a stdio proxy has no bearer token and leaves JTI empty,
// and a pre-authentication refusal has only the session. It is never a wildcard — an empty
// field matches nothing rather than everything, so a revocation cannot be dodged by omitting
// the dimension it names.
type Subject struct {
	// AgentID is the acting agent, from the token's `mcp.agent_id` or the transport's own
	// per-connection identity.
	AgentID string
	// SessionID is the proxy's internal session, which is a CONNECTION on stdio and an
	// `Mcp-Session-Id` worker on HTTP.
	SessionID string
	// JTI is the bearer token's RFC 7519 `jti`, the FINEST revocation unit: it names one
	// issued credential rather than everything an agent or a session holds. Revoking it stops
	// exactly the token that leaked, leaving the same agent's other tokens serving.
	//
	// It is a revocation key only, never a scope key — a manifest's `principal:` scoping reads
	// `sub`, and keying policy state on a per-token value would split an agent's accumulated
	// budgets across every token it was ever issued. See ADR-0004.
	JTI string
}

// Checker is the minimal read-only interface for components that only query
// whether a request should be blocked. The hot enforcement path accepts this
// rather than the full Manager, which it never needs.
type Checker interface {
	// ShouldBlock returns true if any dimension of subj is killed.
	// An empty field means that dimension is not evaluated — see [Subject].
	//
	// A non-nil error means the backend could not CONFIRM its kill set, not that the answer
	// is "no": (false, err) must be treated as a denial, since an unconfirmable non-match is
	// indistinguishable from a confirmed all-clear. See the rule on [Manager], which binds
	// this method too — a backend reaches the hot path through this interface, so a consumer
	// that only ever sees a Checker still has to fail closed on the error.
	ShouldBlock(ctx context.Context, subj Subject) (bool, error)
}

// Manager is the full kill-switch interface that embeds Checker and adds the
// admin and control-plane operations. Wire the full Manager where both read
// and write access is needed (e.g., the admin API handler); pass only Checker
// to read-only consumers.
//
// CONFIRMABILITY is the contract every method shares, stated here rather than on whichever
// one was last touched. A backend answers from a local view of the kill set, and "nothing
// matches" is byte-identical to "the whole kill set is empty" — so a backend that cannot
// currently confirm its view (never loaded, no longer converging, backend unreachable, or wired
// in a way that cannot enumerate the whole kill set) must report that cause from EVERY reader:
// HealthStatus, ShouldBlock on a non-match, and Status.
// Returning (false, nil) or an empty snapshot in that state is a silent all-clear, which is
// exactly the failure the kill switch exists to prevent. A present kill still blocks
// unconditionally — confidence only decides what a NON-match means.
//
// A backend whose state lives in-process is always confirmable and simply never reports a
// cause; the rule binds the ones that mirror remote state.
//
// PARTIAL PROPAGATION is the writers' shared rule, for the same reason. A backend that mirrors
// its state to other instances does two things per write — a durable one and a notification —
// and only the first decides whether the revocation landed. An error from ActivateGlobal /
// KillAgent / KillSession (or their undo) therefore does NOT by itself mean the write failed:
// one wrapping ErrPublishFailed says the state IS durable and only real-time propagation was
// lost, with convergence bounded by the backend's reconcile cadence. A caller whose question is
// "did the revocation land" must check for it before reporting failure — reporting a landed
// emergency stop as failed invites a re-run, or worse, a conclusion that the system is unstopped.
//
// The ONE exception is an explicit operator choice to prefer availability: the Redis backend's
// WithFailOpen (--killswitch-fail-open, ADR-0003) serves the last-known cache from ShouldBlock
// and Status during an outage rather than denying, and HealthStatus alone reports the cause.
// That is a configured trade, not a backend answering as it likes — a consumer that must not
// be surprised by it either declines to wire fail-open, or polls HealthStatus, which reports
// the cause under both postures.
type Manager interface {
	Checker

	// HealthStatus reports whether this backend can confirm its kill set right now: nil when
	// it can, otherwise the reason it cannot. It is the readiness question asked WITHOUT a
	// request in hand — a health probe, a startup gate, an operator's /healthz — which
	// ShouldBlock cannot answer, since a caller cannot tell "not ready yet" from "backend
	// down" from an error it must fail closed on either way.
	//
	// It reports the CURRENT cause, not a latched one: a backend that recovers reports nil
	// again. Implementations answer through the same gate chain their readers use — and it is
	// the one reader that reports a cause even under fail-open, where the others deliberately
	// serve the cache, so it is what an operator alerts on.
	HealthStatus() error

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

	// RevokeJTI blocks every request presenting the bearer token with this `jti`.
	// An empty jti is an error for KillAgent's reason.
	//
	// The FINEST revocation unit, and the one an operator reaches for when a credential
	// leaks: killing the agent stops everything it holds, killing the session stops one
	// connection, and revoking the jti stops exactly the token that got out. A token is
	// presented on every request, so the revocation takes effect on the next one rather than
	// waiting for the credential to expire.
	RevokeJTI(ctx context.Context, jti string) error

	// ReviveJTI removes the revocation on the specified token id.
	ReviveJTI(ctx context.Context, jti string) error

	// Reset clears all kill-switch state.
	Reset(ctx context.Context) error

	// Status returns the current kill-switch state. A snapshot asserts "this is the whole
	// kill set", so an unconfirmable one reports the cause instead (the Redis backend's
	// ErrNotStarted / ErrStopped / ErrBackendUnreachable) — see the confirmability rule on
	// this interface.
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
	// JTI names a revoked bearer token id.
	JTI string
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
	// RevokedJTIs lists the revoked bearer token ids. A token id is a credential
	// identifier, not a secret — it is carried in the clear in every token that presents
	// it — so a snapshot naming one leaks nothing the holder did not already send.
	RevokedJTIs []string `json:"revokedJtis"`
}

// buildStatus assembles a *Status from the raw cache maps, sorting both id slices for
// deterministic output. Shared by both backends so the two cannot drift.
func buildStatus(globalActive bool, killedAgents, killedSessions, revokedJTIs map[string]bool) *Status {
	return &Status{
		GlobalActive:   globalActive,
		KilledAgents:   sortedKeys(killedAgents),
		KilledSessions: sortedKeys(killedSessions),
		RevokedJTIs:    sortedKeys(revokedJTIs),
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
