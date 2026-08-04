// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package flowlabelstore

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultCleanupInterval is the period at which StartCleanup sweeps idle sets. It is
// well below DefaultIdleTTL, so a reclaimable set is reclaimed promptly after it goes
// idle rather than at the next time something happens to touch it.
const DefaultCleanupInterval = 5 * time.Minute

// pressureWarnFraction is the share of maxKeys at which the store warns that it is
// approaching its admission ceiling. The ceiling is fail-closed — at it, a new anchor's
// first Add is REFUSED and the engine denies the source call — so the one thing an
// operator must not get is a cliff with no warning before it.
const pressureWarnFraction = 0.9

// labelSet is one anchor's accumulated labels plus when it was last touched.
//
// touched scopes reclamation to ABANDONED anchors: refreshed by Add and Get, so an anchor
// still emitting or being read never ages out (mirroring Redis's refreshed EXPIRE).
//
// It is an atomic, not a plain time.Time, so the refresh can happen under the store's READ
// lock — Get is on the path of every flow-relevant decision, and taking the write lock just
// to stamp a timestamp would serialize every session behind one store-wide lock.
type labelSet struct {
	labels map[string]struct{}
	// touched is Unix nanoseconds; the zero value is never stored (Add stamps it before
	// the entry is published).
	touched atomic.Int64
}

// idleFor reports how long this set has gone untouched as of now.
func (l *labelSet) idleFor(now time.Time) time.Duration {
	return now.Sub(time.Unix(0, l.touched.Load()))
}

// InMemory is an anchor-scoped flow-label store backed by in-process memory: each
// anchor key maps to a set of its accumulated labels. Suitable for single-replica
// deployments or testing. Safe for concurrent use.
type InMemory struct {
	mu sync.RWMutex
	// sets maps an anchor key to its accumulated labels. An anchor with no labels holds
	// no entry at all, so an empty set is never distinguishable from an absent anchor.
	sets map[string]*labelSet
	// maxKeys bounds distinct anchor keys held at once; 0 (default) is unbounded. See
	// WithMaxKeys and admitNewKey.
	maxKeys int
	// ttl is the idle TTL from WithMemoryIdleTTL. Zero (default) DISABLES idle
	// reclamation entirely; see WithMemoryIdleTTL for why.
	ttl time.Duration
	// lastReclaim is when the inline at-ceiling sweep last ran, so a store sitting AT its
	// bound does one full scan per cleanup interval rather than one per refused call.
	lastReclaim time.Time
	now         func() time.Time
	// logger receives the approach-of-ceiling and at-ceiling warnings; nil silences them.
	logger *slog.Logger
	// pressureWarned latches the approach-of-ceiling warning to once per crossing,
	// re-armed when the live count falls back under the threshold.
	pressureWarned bool
	// refusalWarned latches the at-ceiling warning the same way: one line per episode.
	refusalWarned bool

	// cleanupMu guards the cleanup-goroutine lifecycle, mirroring callcounter's InMemory:
	// a plain atomic flag released on exit can't distinguish "running" from "tearing down".
	cleanupMu   sync.Mutex
	cleanupCtx  context.Context
	cleanupDone chan struct{}
}

// InMemoryOption configures the InMemory store.
type InMemoryOption func(*InMemory)

// WithMaxKeys bounds distinct anchor keys held at once; a *new* anchor past it is refused
// (fail-closed: the engine denies the source read rather than forward untracked). It is an
// admission ceiling, not a reaper — pair it with WithLogger so the approach is visible,
// and with WithMemoryIdleTTL for actual reclamation.
func WithMaxKeys(n int) InMemoryOption {
	return func(m *InMemory) {
		m.maxKeys = n
	}
}

// WithMemoryIdleTTL enables idle reclamation: how long an anchor's set is retained with
// nothing touching it, refreshed on every Add/Get so a live anchor never loses provenance.
//
// Unset (default) means NO idle reclamation: a session-anchored key has a real
// reclamation path (transport teardown), and expiring it early would fail-open a
// live-but-quiet session. Enable it only for anchors with no teardown owner (task-anchored
// keys). A value in (0, 1s) is raised to one second.
func WithMemoryIdleTTL(d time.Duration) InMemoryOption {
	return func(m *InMemory) {
		m.ttl = d
	}
}

// WithTimeFunc sets a custom time function (for testing).
func WithTimeFunc(fn func() time.Time) InMemoryOption {
	return func(m *InMemory) {
		m.now = fn
	}
}

// WithLogger wires the logger the store warns through: once approaching pressureWarnFraction
// of maxKeys, and once per refusal episode at the ceiling. Unset (a library default) is silent.
func WithLogger(l *slog.Logger) InMemoryOption {
	return func(m *InMemory) {
		m.logger = l
	}
}

// NewInMemory creates an in-memory anchor-scoped flow-label store.
//
// A set is reclaimed by Clear (teardown), Remove dropping its last label, or — only where
// WithMemoryIdleTTL enables it — an idle bound. That third path is what covers a
// TASK-anchored key, which deliberately outlives its creating session (clearing it on
// disconnect would let an agent launder a task's taint by reconnecting); without it,
// WithMaxKeys alone is an availability cliff with no reaper behind it. It is OFF by
// default since refresh-on-access measures INACTIVITY, not abandonment, and a
// session-anchored key already has a real reclamation path in transport teardown.
func NewInMemory(opts ...InMemoryOption) *InMemory {
	m := &InMemory{
		sets: make(map[string]*labelSet),
		now:  time.Now,
	}
	for _, opt := range opts {
		opt(m)
	}
	if m.now == nil {
		m.now = time.Now
	}
	return m
}

// effectiveTTL is the bound in force, or 0 when idle reclamation is disabled. A positive
// value below one second is raised to one second (sub-second would reclaim a live anchor
// on its next touch); a negative value reads as "off", same as the zero default.
func (m *InMemory) effectiveTTL() time.Duration {
	switch {
	case m.ttl <= 0:
		return 0
	case m.ttl < time.Second:
		return time.Second
	default:
		return m.ttl
	}
}

// idleReclamation reports whether this store expires anchors at all.
func (m *InMemory) idleReclamation() bool { return m.effectiveTTL() > 0 }

// live returns the anchor's set when it exists and has not idled out, nil otherwise.
// An expired set is reported absent rather than deleted here, so this stays usable from
// the read path; Cleanup and the write paths do the actual reclaiming.
func (m *InMemory) live(anchorKey string, now time.Time) *labelSet {
	set, ok := m.sets[anchorKey]
	if !ok {
		return nil
	}
	if ttl := m.effectiveTTL(); ttl > 0 && set.idleFor(now) >= ttl {
		return nil
	}
	return set
}

// admitNewKey refuses a new anchor once maxKeys is reached; nil when unbounded or there is
// room. At the bound it may sweep idled-out anchors first, so the ceiling bounds LIVE
// anchors rather than every anchor ever seen. That sweep is RATE-LIMITED to once per
// cleanup interval — otherwise a store sitting at its bound would pay a full O(n) scan
// under the exclusive lock on EVERY refused call, turning the ceiling into an amplifier.
func (m *InMemory) admitNewKey(now time.Time) error {
	if m.maxKeys <= 0 || len(m.sets) < m.maxKeys {
		m.refusalWarned = false
		return nil
	}
	if m.reclaimIdle(now) && len(m.sets) < m.maxKeys {
		m.refusalWarned = false
		return nil
	}
	m.warnAtCeiling()
	return fmt.Errorf("flowlabelstore: session limit reached (%d)", m.maxKeys)
}

// reclaimIdle drops every anchor past its idle TTL, at most once per cleanup interval, and
// reports whether it ran — the same rule Cleanup applies, run inline when the answer
// changes an outcome, and skipped entirely when this store does not expire anchors.
func (m *InMemory) reclaimIdle(now time.Time) bool {
	ttl := m.effectiveTTL()
	if ttl <= 0 || now.Sub(m.lastReclaim) < DefaultCleanupInterval {
		return false
	}
	m.lastReclaim = now
	for key, set := range m.sets {
		if set.idleFor(now) >= ttl {
			delete(m.sets, key)
		}
	}
	return true
}

// warnAtCeiling reports the cliff itself, once per refusal episode: the resulting deny
// alone reads as a backend fault, but the operator action here is different (raise the
// ceiling, shorten the TTL, or move to Redis), so the store says so in its own terms.
func (m *InMemory) warnAtCeiling() {
	if m.logger == nil || m.refusalWarned {
		return
	}
	m.refusalWarned = true
	m.logger.Error("flow-label store is at its key ceiling; every new anchor's first labelled call now fails closed until a slot frees",
		"live_keys", len(m.sets), "max_keys", m.maxKeys, "idle_ttl", m.effectiveTTL())
}

// warnApproachingCeiling reports the approach, once per crossing, re-armed when the live
// count falls back below threshold. It exists because the ceiling otherwise gives no
// signal until the first denied call — exactly the shape a task-anchored key walks into.
func (m *InMemory) warnApproachingCeiling() {
	if m.logger == nil || m.maxKeys <= 0 {
		return
	}
	threshold := int(float64(m.maxKeys) * pressureWarnFraction)
	if len(m.sets) < threshold {
		m.pressureWarned = false
		return
	}
	if m.pressureWarned {
		return
	}
	m.pressureWarned = true
	m.logger.Warn("flow-label store is approaching its key ceiling; at the ceiling a new anchor's first labelled call fails closed",
		"live_keys", len(m.sets), "max_keys", m.maxKeys, "idle_ttl", m.effectiveTTL())
}

// Add unions labels into the anchor's set (idempotent) and refreshes its idle TTL. An
// empty labels list is a no-op that materializes no entry — a phantom key would otherwise
// consume a maxKeys slot for an anchor carrying no taint. A new anchor at the maxKeys
// ceiling fails closed.
func (m *InMemory) Add(_ context.Context, anchorKey string, labels ...string) error {
	if len(labels) == 0 {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now()
	set := m.live(anchorKey, now)
	if set == nil {
		// Previously-unseen or idled-out: both are new keys as far as the ceiling goes, so
		// drop the stale entry first — else this anchor's own abandoned taint would refuse
		// its return.
		delete(m.sets, anchorKey)
		if err := m.admitNewKey(now); err != nil {
			return err
		}
		set = &labelSet{labels: make(map[string]struct{}, len(labels))}
		set.touched.Store(now.UnixNano())
		m.sets[anchorKey] = set
		m.warnApproachingCeiling()
	}
	set.touched.Store(now.UnixNano())
	for _, label := range labels {
		set.labels[label] = struct{}{}
	}
	return nil
}

// Get returns a NEW, sorted copy of the anchor's set, or nil for absent/idled-out, and
// refreshes the idle TTL on read so a still-being-read anchor never loses its provenance.
// It never errors: an absent anchor is clean, not a fault. It keeps the READ lock (the
// refresh is an atomic store, not a map mutation) — load-bearing since Get is on the path
// of every flow-relevant decision and this mutex is store-WIDE.
func (m *InMemory) Get(_ context.Context, anchorKey string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	now := m.now()
	set := m.live(anchorKey, now)
	if set == nil {
		return nil, nil
	}
	set.touched.Store(now.UnixNano())
	out := make([]string, 0, len(set.labels))
	for label := range set.labels {
		out = append(out, label)
	}
	sort.Strings(out)
	return out, nil
}

// Remove deletes the named labels from the anchor's set (idempotent). When the removal
// empties the set, the map key is dropped so the slot is reclaimed. There is deliberately
// NO TTL refresh, matching Redis: a removal is a rollback, not activity, and must not
// extend the idle bound.
func (m *InMemory) Remove(_ context.Context, anchorKey string, labels ...string) error {
	if len(labels) == 0 {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	set := m.live(anchorKey, m.now())
	if set == nil {
		// Absent or idled out: drop it here so an idled-out slot is not held until the
		// next sweep.
		delete(m.sets, anchorKey)
		return nil
	}
	for _, label := range labels {
		delete(set.labels, label)
	}
	if len(set.labels) == 0 {
		delete(m.sets, anchorKey)
	}
	return nil
}

// Clear releases the anchor's entire set at teardown, so a reused session id starts
// clean. A no-op on an absent key.
func (m *InMemory) Clear(_ context.Context, anchorKey string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sets, anchorKey)
	return nil
}

// Len reports how many anchor keys the store holds, INCLUDING idled-out ones not yet
// swept. For tests and diagnostics only; never an enforcement input.
func (m *InMemory) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sets)
}

// cleanupDeleteBatch bounds idle-key deletes per lock acquisition, so a sweep never
// stalls concurrent Add/Get callers longer than O(batch); mirrors callcounter's sweep.
const cleanupDeleteBatch = 1024

// Cleanup reclaims every anchor idle past the effective TTL — the only path that reclaims
// a set nothing will ever touch again, since the lazy expiry on access paths needs an access.
func (m *InMemory) Cleanup() {
	ttl := m.effectiveTTL()
	if ttl <= 0 {
		// No idle reclamation configured: there is nothing this sweep could collect, and
		// scanning the map to discover that would be pure work on every tick.
		return
	}
	now := m.now()

	m.mu.RLock()
	// Grown on demand, NOT pre-sized to the map: at the million-key ceiling a
	// len(m.sets) pre-size would allocate tens of megabytes every tick even when
	// nothing is stale. Mirrors callcounter's own delete-list sizing.
	var stale []string
	for key, set := range m.sets {
		if set.idleFor(now) >= ttl {
			stale = append(stale, key)
		}
	}
	m.mu.RUnlock()

	for start := 0; start < len(stale); start += cleanupDeleteBatch {
		end := min(start+cleanupDeleteBatch, len(stale))
		m.mu.Lock()
		for _, key := range stale[start:end] {
			// Re-check under the write lock: a concurrent Add/Get may have touched the
			// anchor since the scan, and reclaiming a live taint is the fail-open to avoid.
			if set, ok := m.sets[key]; ok && set.idleFor(m.now()) >= ttl {
				delete(m.sets, key)
			}
		}
		m.mu.Unlock()
	}
}

// StartCleanup launches a background goroutine calling Cleanup on every interval tick
// until ctx is canceled; idempotent for the same reason callcounter's is (cleanupMu-guarded
// so a restart racing a teardown is never lost).
func (m *InMemory) StartCleanup(ctx context.Context, interval time.Duration) bool {
	if ctx.Err() != nil {
		return false
	}
	if !m.idleReclamation() {
		// Nothing expires, so there is nothing to sweep — don't start a goroutine that
		// wakes forever to do nothing.
		return false
	}
	if interval <= 0 {
		interval = DefaultCleanupInterval
	}

	m.cleanupMu.Lock()
	defer m.cleanupMu.Unlock()

	if m.cleanupDone != nil {
		if m.cleanupCtx != nil && m.cleanupCtx.Err() == nil {
			return false
		}
		<-m.cleanupDone // bounded: a canceled context makes the goroutine return promptly
		m.cleanupCtx = nil
		m.cleanupDone = nil
	}

	done := make(chan struct{})
	m.cleanupCtx = ctx
	m.cleanupDone = done
	go func() {
		t := time.NewTicker(interval)
		defer func() {
			t.Stop()
			close(done)
		}()
		for {
			select {
			case <-t.C:
				m.Cleanup()
			case <-ctx.Done():
				return
			}
		}
	}()
	return true
}
