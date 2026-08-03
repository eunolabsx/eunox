// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package flowlabelstore

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"
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
// touched is what scopes reclamation to ABANDONED anchors rather than merely old ones:
// it is refreshed by Add and by Get, so an anchor that is still emitting labels — or
// still having its taint READ by a sink check — never ages out. Only an anchor nothing
// has asked about for a whole idle TTL is reclaimed, which is the same rule the Redis
// backend's refreshed EXPIRE applies.
type labelSet struct {
	labels  map[string]struct{}
	touched time.Time
}

// InMemory is an anchor-scoped flow-label store backed by in-process memory: each
// anchor key maps to a set of its accumulated labels. Suitable for single-replica
// deployments or testing. Safe for concurrent use.
type InMemory struct {
	mu sync.RWMutex
	// sets maps an (opaque, caller-namespaced) anchor key to the set of flow labels
	// accumulated for it. An anchor with no labels holds no entry at all — Add of an
	// empty list creates nothing and Remove of the last label deletes the entry — so
	// an empty set is never distinguishable from an absent anchor.
	sets map[string]*labelSet
	// maxKeys bounds how many distinct anchor keys the map may hold at once; 0 (the
	// default) leaves it unbounded. See WithMaxKeys and admitNewKey.
	maxKeys int
	// ttl is the configured idle TTL as passed to WithMemoryIdleTTL (DefaultIdleTTL when
	// unset). Stored verbatim; effectiveTTL applies the floor at the point of use, so
	// the two backends guard a misconfigured value identically.
	ttl time.Duration
	now func() time.Time
	// logger receives the approach-of-ceiling and at-ceiling warnings. nil (the default)
	// silences them; the binary wires one.
	logger *slog.Logger
	// pressureWarned latches the approach-of-ceiling warning so a store sitting near its
	// bound logs once per crossing rather than once per admitted anchor. It is re-armed
	// when the live count falls back under the threshold.
	pressureWarned bool
	// refusalWarned latches the at-ceiling warning the same way, so a sustained refusal
	// episode is one line rather than one per denied source call.
	refusalWarned bool

	// cleanupMu guards the cleanup-goroutine lifecycle below, mirroring the callcounter's
	// InMemory: a plain atomic flag released on exit cannot distinguish "running" from
	// "tearing down", under which a StartCleanup racing the prior goroutine's exit loses
	// the restart and leaves reclamation permanently off.
	cleanupMu   sync.Mutex
	cleanupCtx  context.Context
	cleanupDone chan struct{}
}

// InMemoryOption configures the InMemory store.
type InMemoryOption func(*InMemory)

// WithMaxKeys bounds the number of distinct anchor keys the store holds at once,
// capping the heap the map can consume when anchors arrive (and are abandoned
// without a Clear) faster than teardown and idle reclamation free them. Once the map
// holds n anchors, an Add that would create a *new* one is refused with an error; the
// flow engine treats that fail-closed (an unwritable provenance state denies the source
// read rather than silently forwarding with an untracked taint). The cost at the ceiling
// is availability — a new-anchor Add is denied while the map is full — not a bypass:
// existing anchors keep accumulating labels, and a slot freed by Clear, by Remove
// dropping an anchor's last label, or by the idle TTL is reusable. A value <= 0 (the
// default) is unbounded.
//
// It is an admission ceiling, not a reaper, and it never was: the reclamation is the idle
// TTL beside it. Pair it with WithLogger so the approach to the ceiling is visible before
// the cliff.
func WithMaxKeys(n int) InMemoryOption {
	return func(m *InMemory) {
		m.maxKeys = n
	}
}

// WithMemoryIdleTTL overrides how long an anchor's label set is retained with nothing touching
// it. It is the in-memory twin of the Redis backend's refreshed EXPIRE and carries the
// identical contract: a safety-reclamation bound for an ABANDONED anchor, NOT a
// security-relevant taint lifetime, because it is refreshed on every Add and Get — so a
// live anchor never loses its provenance. Size it to the deployment's session (or task)
// idle timeout. A value below one second falls back to DefaultIdleTTL (see effectiveTTL),
// since a zero or negative bound would drop a live anchor's taint immediately.
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

// WithLogger wires the logger the store warns through: once when the live anchor count
// crosses pressureWarnFraction of maxKeys, and once per refusal episode at the ceiling
// itself. Both are gated on a non-nil logger, so leaving it unset is silent — which is
// the right default for a library and the wrong one for a long-running proxy, so the
// binary wires one.
func WithLogger(l *slog.Logger) InMemoryOption {
	return func(m *InMemory) {
		m.logger = l
	}
}

// NewInMemory creates an in-memory anchor-scoped flow-label store.
//
// A set is reclaimed by exactly three things: Clear (session teardown), Remove dropping
// its last label, and the idle TTL. The third is what covers an anchor no teardown will
// ever reach — a task-anchored key, which deliberately OUTLIVES the session that created
// it (clearing it on disconnect would restore the per-PEP boundary the anchor exists to
// cross, and would let an agent launder a task's taint by reconnecting), and any anchor
// belonging to a host that abandons sessions without a DELETE. Without it, WithMaxKeys
// was the only backstop, and a ceiling with no reaper behind it is an availability cliff:
// at the bound every flow-relevant source call fails closed for the rest of the process's
// life.
//
// The TTL is scoped to ABANDONED anchors, which is the whole difficulty: this package's
// contract is that provenance is monotonic and must not age out mid-session (a windowed
// marker is a fail-open the "for all flows" claim cannot tolerate). Refresh-on-access is
// the scoping — Add and Get both stamp the anchor live — so the bound measures INACTIVITY
// of the anchor rather than the age of its taint. That is the same rule the Redis backend
// has always applied, so the two backends now behave the same way in the one mode where
// the difference mattered.
func NewInMemory(opts ...InMemoryOption) *InMemory {
	m := &InMemory{
		sets: make(map[string]*labelSet),
		ttl:  DefaultIdleTTL,
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

// effectiveTTL guards a configured value below one second, subsuming zero and negative:
// either would reclaim a live anchor's taint on its next touch, capping provenance far
// below any real session — a fail-open. Falling back to DefaultIdleTTL keeps a
// misconfigured TTL fail-SAFE. It mirrors the Redis backend's guard exactly, including the
// one-second floor, so a config value means the same thing under both backends.
func (m *InMemory) effectiveTTL() time.Duration {
	if m.ttl < time.Second {
		return DefaultIdleTTL
	}
	return m.ttl
}

// live returns the anchor's set when it exists and has not idled out, nil otherwise.
// Call under m.mu (either mode). An expired set is reported absent rather than deleted
// here, so this stays usable from the read path; Cleanup and the write paths reclaim it.
func (m *InMemory) live(anchorKey string, now time.Time) *labelSet {
	set, ok := m.sets[anchorKey]
	if !ok || now.Sub(set.touched) >= m.effectiveTTL() {
		return nil
	}
	return set
}

// admitNewKey returns an error when inserting a previously-unseen anchor would push
// the live key count past maxKeys; nil when unbounded (maxKeys <= 0) or there is room.
// Call under m.mu and only on the new-key path (adding to an existing anchor grows
// the map by nothing). This is the fail-closed backstop described on WithMaxKeys.
//
// At the bound it sweeps idled-out anchors before refusing, so the ceiling bounds LIVE
// anchors rather than every anchor the process has seen since the last background pass.
// Without that, a store full of abandoned keys would refuse a genuinely new one for up to
// a whole cleanup interval — turning the reclamation the TTL provides into something that
// only helps if the reaper happens to have run.
func (m *InMemory) admitNewKey(now time.Time) error {
	if m.maxKeys <= 0 || len(m.sets) < m.maxKeys {
		m.refusalWarned = false
		return nil
	}
	m.reclaimIdle(now)
	if len(m.sets) < m.maxKeys {
		m.refusalWarned = false
		return nil
	}
	m.warnAtCeiling()
	return fmt.Errorf("flowlabelstore: session limit reached (%d)", m.maxKeys)
}

// reclaimIdle drops every anchor past its idle TTL. Call under m.mu (write mode).
// It is the same rule Cleanup applies from the background sweep, run inline at the moment
// the answer actually changes an outcome.
func (m *InMemory) reclaimIdle(now time.Time) {
	ttl := m.effectiveTTL()
	for key, set := range m.sets {
		if now.Sub(set.touched) >= ttl {
			delete(m.sets, key)
		}
	}
}

// warnAtCeiling reports the cliff itself, once per refusal episode. Call under m.mu.
//
// The refusal is already surfaced as a deny, but a deny says "flow state is unwritable",
// which reads as a backend fault. The operator action is different — raise the ceiling,
// shorten the idle TTL, or move to Redis — so the store says so in its own terms.
func (m *InMemory) warnAtCeiling() {
	if m.logger == nil || m.refusalWarned {
		return
	}
	m.refusalWarned = true
	m.logger.Error("flow-label store is at its key ceiling; every new anchor's first labelled call now fails closed until a slot frees",
		"live_keys", len(m.sets), "max_keys", m.maxKeys, "idle_ttl", m.effectiveTTL())
}

// warnApproachingCeiling reports the approach, once per crossing, and re-arms when the
// live count falls back below the threshold. Call under m.mu, after an insert.
//
// It exists because the ceiling's failure mode gives no other signal: the store admits
// every anchor right up to the bound and then fails closed on the next one, with the
// first indication being a denied call. An anchor that no teardown reclaims — a
// task-anchored key — is exactly the shape that walks a long-lived proxy into it.
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

// Add unions labels into the anchor's accumulated set (idempotent) and refreshes its idle
// TTL, so an anchor that keeps emitting labels never ages out. An empty labels list is a
// no-op that materializes no entry: Get on an untouched anchor must stay absent, and a
// phantom key would consume a maxKeys slot for an anchor carrying no taint. A new anchor
// at the maxKeys ceiling fails closed.
func (m *InMemory) Add(_ context.Context, anchorKey string, labels ...string) error {
	if len(labels) == 0 {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now()
	set := m.live(anchorKey, now)
	if set == nil {
		// A previously-unseen anchor, or one whose own set has idled out. Both are new
		// keys as far as the ceiling is concerned, so drop the stale entry first — leaving
		// it would make this anchor's own abandoned taint the thing that refuses its
		// return.
		delete(m.sets, anchorKey)
		if err := m.admitNewKey(now); err != nil {
			return err
		}
		set = &labelSet{labels: make(map[string]struct{}, len(labels))}
		m.sets[anchorKey] = set
		m.warnApproachingCeiling()
	}
	set.touched = now
	for _, label := range labels {
		set.labels[label] = struct{}{}
	}
	return nil
}

// Get returns a NEW, sorted copy of the anchor's accumulated set, or nil for an absent
// (or idled-out) anchor, and refreshes the idle TTL on the read: an anchor that is only
// being READ — sink after sink, emitting no new labels — must not have its provenance
// reclaimed out from under it. It never errors — an absent anchor is clean, not a fault,
// so the engine reads an empty carried set. The result is sorted for a deterministic
// return (map iteration is randomized); the engine reorders into the canonical vocabulary
// regardless, but a stable order keeps tests and any digest of the set reproducible.
// The copy means a caller can never mutate the store's internal set.
//
// It takes the WRITE lock, unlike the read-only Get this replaced, because the refresh is
// what scopes reclamation to abandoned anchors and a read that did not refresh would age
// out a session doing nothing but sink checks. The Redis backend pays the same cost (its
// Get is a transaction carrying an EXPIRE), and a flow-relevant decision is already
// serialized per anchor by the transport's decision turn.
func (m *InMemory) Get(_ context.Context, anchorKey string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now()
	set := m.live(anchorKey, now)
	if set == nil {
		return nil, nil
	}
	set.touched = now
	out := make([]string, 0, len(set.labels))
	for label := range set.labels {
		out = append(out, label)
	}
	sort.Strings(out)
	return out, nil
}

// Remove deletes the named labels from the anchor's set (idempotent — removing an
// absent label, or from an absent anchor, is a no-op). When the removal empties the
// set, the map key is dropped so the slot is reclaimed (an empty set is
// indistinguishable from an absent anchor) and the fail-closed rollback path does
// not pin memory for an anchor that ended up clean. An empty labels list is a no-op.
//
// There is deliberately NO TTL refresh, matching Redis: a removal is a rollback or a
// teardown shrinking the taint, not activity keeping the anchor alive, so it must not
// extend the idle bound.
func (m *InMemory) Remove(_ context.Context, anchorKey string, labels ...string) error {
	if len(labels) == 0 {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	set := m.live(anchorKey, m.now())
	if set == nil {
		// Absent, or idled out — either way there is nothing to remove. An idled-out
		// entry is dropped here so its slot is not held until the next sweep.
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

// Clear releases the anchor's entire set, called from session teardown so an ended
// session retains no state and a reused session id starts clean. delete is a no-op on
// an absent key, so clearing an absent anchor is a no-op; either way the slot is freed.
func (m *InMemory) Clear(_ context.Context, anchorKey string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sets, anchorKey)
	return nil
}

// Len reports how many anchor keys the store currently holds, INCLUDING any that have
// idled out but not yet been swept. Exposed for tests and for an operator-facing
// diagnostic; it is never an enforcement input.
func (m *InMemory) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sets)
}

// cleanupDeleteBatch bounds how many idle keys Cleanup deletes per lock acquisition, so
// a single pass never stalls concurrent Add/Get callers for longer than O(batch) even
// when a large number of anchors idle out together. It mirrors the callcounter's own
// batched sweep.
const cleanupDeleteBatch = 1024

// Cleanup reclaims every anchor whose set has been idle for longer than the effective
// TTL. It is what makes the ceiling a bound on LIVE anchors rather than on every anchor
// the process has ever seen — a set nothing will ever touch again is not reclaimed by
// the lazy expiry on the access paths, because nothing accesses it.
//
// Safe to call at any time; StartCleanup runs it periodically.
func (m *InMemory) Cleanup() {
	now := m.now()
	ttl := m.effectiveTTL()

	m.mu.RLock()
	stale := make([]string, 0, len(m.sets))
	for key, set := range m.sets {
		if now.Sub(set.touched) >= ttl {
			stale = append(stale, key)
		}
	}
	m.mu.RUnlock()

	for start := 0; start < len(stale); start += cleanupDeleteBatch {
		end := min(start+cleanupDeleteBatch, len(stale))
		m.mu.Lock()
		for _, key := range stale[start:end] {
			// Re-check under the write lock: a concurrent Add or Get may have touched the
			// anchor since the scan, and reclaiming a live anchor's taint is the one
			// fail-open this whole mechanism has to avoid.
			if set, ok := m.sets[key]; ok && m.now().Sub(set.touched) >= ttl {
				delete(m.sets, key)
			}
		}
		m.mu.Unlock()
	}
}

// StartCleanup launches a single background goroutine that calls Cleanup on every
// interval tick until ctx is canceled, returning whether this call started it.
// Call once after constructing a process-lifetime store. A non-positive interval
// defaults to DefaultCleanupInterval.
//
// It is idempotent, and its lifecycle is guarded by cleanupMu rather than by a flag
// released on exit, for the same reason the callcounter's is: the first call wins and
// governs the goroutine, a later call while it is still live is a no-op, and a call
// arriving after the prior context was canceled waits for that goroutine to exit and
// starts fresh — so a restart racing a teardown is never lost.
func (m *InMemory) StartCleanup(ctx context.Context, interval time.Duration) bool {
	if ctx.Err() != nil {
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
