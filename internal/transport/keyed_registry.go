// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The keyed-registry-with-refcount lifetime the two decision-turn primitives share: HTTP's
// mutual-exclusion gate (anchor_gate.go) and stdio's FIFO ticket queue (serialize.go), both
// keyed on the state anchor. One generic here replaces two hand-mirrored maps/refcounts/reclaim
// blocks that could (and did) silently drift apart. The reclaim TRIGGER differs per embedder —
// a mutex is idle at zero refs, a FIFO must also outlive tickets it handed out — so it stays a
// supplied `idle` predicate rather than a fork. Turn semantics themselves are the embedder's;
// this owns only the map, the key, the refcount, and the reclaim.

package transport

import "sync"

// keyedEntry is the per-key bookkeeping every registry value carries — its filed key and its
// live reference count — guarded by the owning registry's mutex. The registry sets key itself
// at insert, so a value cannot end up carrying a key it isn't filed under.
type keyedEntry struct {
	key  string
	refs int
}

// keyedRegistryValue is the contract a registry's value type satisfies: comparable (so the
// registry can re-check map identity before deleting, and a stale handle can't evict a fresh
// entry filed under the same key) and exposing its embedded bookkeeping. Instantiated with a
// POINTER type (*anchorGate, *ticketQueue) so a held value doesn't copy the refcount.
type keyedRegistryValue interface {
	comparable
	entry() *keyedEntry
}

// keyedRegistry hands out one refcounted value per key. Its zero value is not usable — call
// init once, before any concurrent use.
type keyedRegistry[T keyedRegistryValue] struct {
	// mu guards entries and every value's keyedEntry. An embedder whose value state must stay
	// consistent with the registry's own (stdio's ticket queue) reuses this SAME mutex via
	// locker/lock rather than adding a second one, so there's no cross-lock ordering to get wrong.
	mu      sync.Mutex
	entries map[string]T
	// build makes a fresh value; it takes no key because the registry stamps the keyedEntry
	// itself at insert. Runs under mu.
	build func() T
	// idle reports whether an unreferenced value may be dropped; nil means "always" (the
	// mutex-gate case). stdio's FIFO supplies one since a queue can have handed-out tickets
	// with no live reference. Runs under mu.
	idle func(T) bool
}

// init prepares the registry. build makes a fresh value; idle (optional) is the extra
// condition beyond "no references" for dropping one.
func (r *keyedRegistry[T]) init(build func() T, idle func(T) bool) {
	r.entries = map[string]T{}
	r.build = build
	r.idle = idle
}

// locker returns the mutex guarding the registry and every value's own bookkeeping, so an
// embedder can build a sync.Cond over it and mutate value state under that same lock.
func (r *keyedRegistry[T]) locker() sync.Locker { return &r.mu }

// lock and unlock take the registry mutex directly, for an embedder that manipulates value
// state (a ticket counter, a turn) in the same critical section as a lookup.
func (r *keyedRegistry[T]) lock()   { r.mu.Lock() }
func (r *keyedRegistry[T]) unlock() { r.mu.Unlock() }

// entryLocked returns key's value, creating and filing it if absent. Caller holds mu. It
// takes NO reference, for a caller that only needs the value within one locked critical
// section (e.g. stdio reserving a ticket) and shouldn't have to pair a hold with a drop.
func (r *keyedRegistry[T]) entryLocked(key string) T {
	v, ok := r.entries[key]
	if !ok {
		v = r.build()
		v.entry().key = key
		r.entries[key] = v
	}
	return v
}

// hold returns key's value with a reference taken, plus the idempotent func that drops it.
// The value stays in the registry until every holder has dropped and the idle predicate
// agrees, so a caller may keep one across many turns rather than re-resolving (and paying a
// registry-wide mutex + map insert/delete) on every enforced call.
func (r *keyedRegistry[T]) hold(key string) (value T, drop func()) {
	r.mu.Lock()
	v := r.entryLocked(key)
	v.entry().refs++
	r.mu.Unlock()
	return v, sync.OnceFunc(func() {
		r.mu.Lock()
		v.entry().refs--
		r.reapLocked(v)
		r.mu.Unlock()
	})
}

// reapLocked drops v from the registry if nothing references it and the embedder's idle
// predicate agrees. Caller holds mu. Exposed separately from drop() because a value can become
// reclaimable without a reference changing (stdio's queue idles when its last ticket is served,
// a counter move). The map-identity re-check makes a double call harmless: an already-evicted
// value's successor under the same key is never evicted by mistake.
func (r *keyedRegistry[T]) reapLocked(v T) {
	e := v.entry()
	if e.refs > 0 {
		return
	}
	if r.idle != nil && !r.idle(v) {
		return
	}
	if cur, ok := r.entries[e.key]; ok && cur == v {
		delete(r.entries, e.key)
	}
}
