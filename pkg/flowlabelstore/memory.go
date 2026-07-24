// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package flowlabelstore

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// InMemory is a session-scoped flow-label store backed by in-process memory: each
// session key maps to a set of its accumulated labels. Suitable for single-replica
// deployments or testing. Safe for concurrent use.
type InMemory struct {
	mu sync.RWMutex
	// sets maps an (opaque, caller-namespaced) session key to the set of flow labels
	// accumulated for it. A session with no labels holds no entry at all — Add of an
	// empty list creates nothing and Remove of the last label deletes the entry — so
	// an empty set is never distinguishable from an absent session.
	sets map[string]map[string]struct{}
	// maxKeys bounds how many distinct session keys the map may hold at once; 0 (the
	// default) leaves it unbounded. See WithMaxKeys and admitNewKey.
	maxKeys int
}

// InMemoryOption configures the InMemory store.
type InMemoryOption func(*InMemory)

// WithMaxKeys bounds the number of distinct session keys the store holds at once,
// capping the heap the map can consume when sessions arrive (and are abandoned
// without a Clear) faster than teardown reclaims them — the fresh-session-per-request
// case; see NewInMemory. Once the map holds n sessions, an Add that would create a
// *new* session is refused with an error; the flow engine treats that fail-closed (an
// unwritable provenance state denies the source read rather than silently forwarding
// with an untracked taint). The cost at the ceiling is availability — a new-session
// Add is denied while the map is full — not a bypass: existing sessions keep
// accumulating labels, and a slot freed by Clear (or by Remove dropping a session's
// last label) is reusable. A value <= 0 (the default) is unbounded.
func WithMaxKeys(n int) InMemoryOption {
	return func(m *InMemory) {
		m.maxKeys = n
	}
}

// NewInMemory creates an in-memory session-scoped flow-label store.
//
// Unlike the callcounter InMemory, a session's set has no time window and no
// background cleanup goroutine: provenance is monotonic for the session's lifetime,
// so an entry lives until Clear (session teardown) or until Remove drops its last
// label. There is therefore nothing to age out and no StartCleanup to run — WithMaxKeys
// is the only backstop against unbounded growth from sessions abandoned without a
// Clear (e.g. a fresh-session-per-request host that never tears down). For such
// deployments prefer the Redis backend (per-session idle TTL, off-heap) or pass
// WithMaxKeys to bound the count.
func NewInMemory(opts ...InMemoryOption) *InMemory {
	m := &InMemory{
		sets: make(map[string]map[string]struct{}),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// admitNewKey returns an error when inserting a previously-unseen session would push
// the live key count past maxKeys; nil when unbounded (maxKeys <= 0) or there is room.
// Call under m.mu and only on the new-key path (adding to an existing session grows
// the map by nothing). This is the fail-closed backstop described on WithMaxKeys.
func (m *InMemory) admitNewKey() error {
	if m.maxKeys > 0 && len(m.sets) >= m.maxKeys {
		return fmt.Errorf("flowlabelstore: session limit reached (%d)", m.maxKeys)
	}
	return nil
}

// Add unions labels into the session's accumulated set (idempotent). An empty labels
// list is a no-op that materializes no entry: Get on an untouched session must stay
// absent, and a phantom key would consume a maxKeys slot for a session carrying no
// taint. A new session at the maxKeys ceiling fails closed.
func (m *InMemory) Add(_ context.Context, sessionKey string, labels ...string) error {
	if len(labels) == 0 {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	set, ok := m.sets[sessionKey]
	if !ok {
		// A previously-unseen session: gate it against maxKeys before allocating.
		if err := m.admitNewKey(); err != nil {
			return err
		}
		set = make(map[string]struct{}, len(labels))
		m.sets[sessionKey] = set
	}
	for _, label := range labels {
		set[label] = struct{}{}
	}
	return nil
}

// Get returns a NEW, sorted copy of the session's accumulated set, or nil for an
// absent session. It never errors — an absent session is clean, not a fault, so the
// engine reads an empty carried set. The result is sorted for a deterministic return
// (map iteration is randomized); the engine reorders into the canonical vocabulary
// regardless, but a stable order keeps tests and any digest of the set reproducible.
// The copy means a caller can never mutate the store's internal set.
func (m *InMemory) Get(_ context.Context, sessionKey string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	set, ok := m.sets[sessionKey]
	if !ok {
		return nil, nil
	}
	out := make([]string, 0, len(set))
	for label := range set {
		out = append(out, label)
	}
	sort.Strings(out)
	return out, nil
}

// Remove deletes the named labels from the session's set (idempotent — removing an
// absent label, or from an absent session, is a no-op). When the removal empties the
// set, the map key is dropped so the slot is reclaimed (an empty set is
// indistinguishable from an absent session) and the fail-closed rollback path does
// not pin memory for a session that ended up clean. An empty labels list is a no-op.
func (m *InMemory) Remove(_ context.Context, sessionKey string, labels ...string) error {
	if len(labels) == 0 {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	set, ok := m.sets[sessionKey]
	if !ok {
		return nil
	}
	for _, label := range labels {
		delete(set, label)
	}
	if len(set) == 0 {
		delete(m.sets, sessionKey)
	}
	return nil
}

// Clear releases the session's entire set, called from session teardown so an ended
// session retains no state and a reused session id starts clean. delete is a no-op on
// an absent key, so clearing an absent session is a no-op; either way the slot is freed.
func (m *InMemory) Clear(_ context.Context, sessionKey string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sets, sessionKey)
	return nil
}
