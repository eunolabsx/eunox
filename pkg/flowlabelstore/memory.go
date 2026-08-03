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
// touched is what scopes reclamation to ABANDONED anchors rather than merely old ones:
// it is refreshed by Add and by Get, so an anchor that is still emitting labels — or
// still having its taint READ by a sink check — never ages out. Only an anchor nothing
// has asked about for a whole idle TTL is reclaimed, which is the same rule the Redis
// backend's refreshed EXPIRE applies.
//
// It is an atomic rather than a plain time.Time so the REFRESH can happen under the
// store's READ lock. Get is on the path of every flow-relevant decision in the proxy
// (peekSessionLabels calls it before each one), and the decision turn that serializes
// those is keyed per ANCHOR while this mutex is store-WIDE — so making the read path take
// the write lock in order to stamp a timestamp would serialize every session in the
// process behind one lock for a field nothing reads transactionally.
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
	// sets maps an (opaque, caller-namespaced) anchor key to the set of flow labels
	// accumulated for it. An anchor with no labels holds no entry at all — Add of an
	// empty list creates nothing and Remove of the last label deletes the entry — so
	// an empty set is never distinguishable from an absent anchor.
	sets map[string]*labelSet
	// maxKeys bounds how many distinct anchor keys the map may hold at once; 0 (the
	// default) leaves it unbounded. See WithMaxKeys and admitNewKey.
	maxKeys int
	// ttl is the configured idle TTL as passed to WithMemoryIdleTTL. Zero — the default —
	// DISABLES idle reclamation entirely, which is this store's historical behavior and
	// stays the default for the reason WithMemoryIdleTTL gives.
	ttl time.Duration
	// lastReclaim is when the inline at-ceiling sweep last ran, so a store sitting AT its
	// bound does one full scan per cleanup interval rather than one per refused call. See
	// admitNewKey.
	lastReclaim time.Time
	now         func() time.Time
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

// WithMemoryIdleTTL enables idle reclamation and sets its bound: how long an anchor's
// label set is retained with nothing touching it. It is the in-memory twin of the Redis
// backend's refreshed EXPIRE and carries the identical contract — a safety-reclamation
// bound for an ABANDONED anchor, NOT a taint lifetime, because it is refreshed on every
// Add and Get, so a live anchor never loses its provenance. Size it to the deployment's
// session (or task) idle timeout.
//
// Unset (the default) means NO idle reclamation, which is this store's historical
// behavior and is deliberately kept as the default. Refresh-on-access scopes the bound to
// an anchor's INACTIVITY rather than its taint's age, but "inactive" and "abandoned" are
// not the same thing: a session-anchored key belongs to a live session that may simply be
// quiet, and its real reclamation is the transport's teardown (ReleaseSession -> Clear).
// Expiring it would age a taint out from under a session that is still going to make
// another call — the fail-open this package exists to avoid. Enable this where the anchor
// has NO teardown owner, which is precisely the task-anchored case: a task key outlives
// its session by design, so an idle bound is the only reclamation it can safely have.
// A value in (0, 1s) is raised to one second rather than honored, since a sub-second bound
// would reclaim a live anchor on its next touch.
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
// A set is reclaimed by Clear (session teardown), by Remove dropping its last label, and —
// only where WithMemoryIdleTTL enables it — by an idle bound. That third path is what
// covers an anchor no teardown will ever reach: a TASK-anchored key deliberately OUTLIVES
// the session that created it (clearing it on disconnect would restore the per-PEP
// boundary the anchor exists to cross, and would let an agent launder a task's taint by
// reconnecting), so nothing else can release it. Without it, WithMaxKeys was the only
// backstop there — and a ceiling with no reaper behind it is an availability cliff: at the
// bound every flow-relevant source call fails closed for the rest of the process's life.
//
// It is OFF by default, and that is the careful part. The bound has to be scoped to
// ABANDONED anchors, because this package's contract is that provenance is monotonic and
// must not age out mid-session (a windowed marker is a fail-open the "for all flows" claim
// cannot tolerate). Refresh-on-access gets most of the way — Add and Get both stamp the
// anchor live, so the bound measures INACTIVITY rather than the age of a taint — but
// inactive is not the same as abandoned: a session-anchored key belongs to a live session
// that may simply be quiet, and it already HAS a reclamation path in the transport's
// teardown. Turning the bound on there would trade a real fail-open for a bound that
// buys nothing. So the caller enables it exactly where the anchor has no owner; see
// WithMemoryIdleTTL.
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

// effectiveTTL is the bound in force, or 0 when idle reclamation is disabled (the default).
// A positive value below one second is raised to one second: a sub-second bound would
// reclaim a live anchor's taint on its next touch, capping provenance far below any real
// session — a fail-open. A negative value reads as "off", matching the zero default rather
// than silently becoming a bound the caller did not ask for.
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
// Call under m.mu (either mode). An expired set is reported absent rather than deleted
// here, so this stays usable from the read path; Cleanup and the write paths reclaim it.
// With idle reclamation off (the default) an existing set is always live.
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

// admitNewKey returns an error when inserting a previously-unseen anchor would push
// the live key count past maxKeys; nil when unbounded (maxKeys <= 0) or there is room.
// Call under m.mu and only on the new-key path (adding to an existing anchor grows
// the map by nothing). This is the fail-closed backstop described on WithMaxKeys.
//
// At the bound it may sweep idled-out anchors before refusing, so the ceiling bounds LIVE
// anchors rather than every anchor the process has seen since the last background pass:
// without that, a store full of abandoned keys refuses a genuinely new one for up to a
// whole cleanup interval, and the TTL only helps when the reaper happens to have run.
//
// That sweep is RATE-LIMITED to once per cleanup interval, which matters more than it
// looks. A store sitting at its bound with nothing reclaimable would otherwise pay a full
// O(n) map scan under the exclusive lock on EVERY refused call — so the ceiling, whose job
// is to make a flood cheap to refuse, would instead amplify it into a store-wide stall
// proportional to the flood's own rate. One scan per interval bounds that to the same work
// the background sweep already does.
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
// reports whether it actually ran. Call under m.mu (write mode). It is the same rule
// Cleanup applies from the background sweep, run inline at the moment the answer changes
// an outcome — and skipped entirely when this store does not expire anchors at all.
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

// Get returns a NEW, sorted copy of the anchor's accumulated set, or nil for an absent
// (or idled-out) anchor, and refreshes the idle TTL on the read: an anchor that is only
// being READ — sink after sink, emitting no new labels — must not have its provenance
// reclaimed out from under it. It never errors — an absent anchor is clean, not a fault,
// so the engine reads an empty carried set. The result is sorted for a deterministic
// return (map iteration is randomized); the engine reorders into the canonical vocabulary
// regardless, but a stable order keeps tests and any digest of the set reproducible.
// The copy means a caller can never mutate the store's internal set.
//
// It keeps the READ lock, so concurrent decisions on distinct anchors still proceed in
// parallel: the refresh is an atomic store on the entry, not a map mutation. That is
// load-bearing rather than a micro-optimization — Get is on the path of every
// flow-relevant decision in the proxy, and this mutex is store-WIDE while the transport's
// decision turn is per-ANCHOR, so taking the write lock here would serialize every session
// in the process behind one lock in order to stamp a timestamp.
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
	ttl := m.effectiveTTL()
	if ttl <= 0 {
		// No idle reclamation configured: there is nothing this sweep could collect, and
		// scanning the map to discover that would be pure work on every tick.
		return
	}
	now := m.now()

	m.mu.RLock()
	// A nil slice grown on demand, NOT one pre-sized to the map: at the documented
	// million-key ceiling a len(m.sets) pre-size would allocate tens of megabytes every
	// tick even when nothing is stale — churning the heap the ceiling exists to bound.
	// The callcounter's sweep sizes its own delete list the same way.
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
			// Re-check under the write lock: a concurrent Add or Get may have touched the
			// anchor since the scan, and reclaiming a live anchor's taint is the one
			// fail-open this whole mechanism has to avoid.
			if set, ok := m.sets[key]; ok && set.idleFor(m.now()) >= ttl {
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
	if !m.idleReclamation() {
		// Nothing expires, so there is nothing to sweep. Reporting false rather than
		// starting a goroutine that wakes forever to do nothing.
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
