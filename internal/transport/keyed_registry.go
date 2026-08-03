// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The keyed-registry-with-refcount lifetime the two decision-turn primitives share.
//
// Both turns are keyed on the state ANCHOR (anchor_gate.go for HTTP's mutual-exclusion gate,
// serialize.go for stdio's FIFO ticket queue), and both therefore need the same thing under
// the turn itself: one entry per LIVE anchor, created on first use, dropped once nothing needs
// it. A registry that only ever grew would be a slow leak keyed by session id on a gateway
// that serves an unbounded number of sessions over its lifetime.
//
// That lifetime lived twice — two maps, two create-or-get helpers, two refcounts, two
// delete-at-zero blocks whose comments were paraphrases of each other. Neither copy was wrong,
// which is the point: two independent invariants for one unbounded-growth bug means a leak
// fix, a lock-ordering change, or a reclaim-condition correction proven on one is silently not
// applied to the other. The release that a prior session-hold path forgot on a teardown branch
// was catchable precisely because it had ONE home.
//
// What genuinely differs between them is the reclaim TRIGGER, and it stays a parameter rather
// than a fork: a mutual-exclusion gate is done when its last holder drops, while a FIFO also
// has to outlive the tickets it has handed out. That is the `idle` predicate below — one
// function, supplied by the embedder, instead of two hand-maintained lifetimes a reader has to
// diff to discover. The turn semantics themselves (a one-slot channel vs a cond-var FIFO) are
// entirely the embedder's and are NOT modelled here; this owns the map, the key, the refcount
// and the reclaim, and nothing else.

package transport

import "sync"

// keyedEntry is the per-key bookkeeping every registry value carries: the key it is filed
// under and the number of live references keeping it in the map. Embed it in the value type
// and expose it through entry().
//
// The registry sets key itself at insert, so a value cannot end up carrying a key it is not
// filed under — the one way a hand-written copy of this could delete the wrong map slot.
// Both fields are guarded by the owning registry's mutex; a value's own state (a turn, a
// ticket counter) is the embedder's business and may be guarded by that same mutex (see
// keyedRegistry.locker) or by nothing at all.
type keyedEntry struct {
	key  string
	refs int
}

// keyedRegistryValue is the contract a registry's value type satisfies: it must be comparable
// (the registry re-checks map identity before deleting, so a stale handle cannot evict a
// FRESH entry filed under the same key) and it must expose its embedded bookkeeping.
//
// It is instantiated with a POINTER type (*anchorGate, *ticketQueue): callers hold the value
// across a turn, so copying one would copy the refcount the registry is reasoning about.
type keyedRegistryValue interface {
	comparable
	entry() *keyedEntry
}

// keyedRegistry hands out one refcounted value per key. Its zero value is not usable — call
// init once, before any concurrent use.
type keyedRegistry[T keyedRegistryValue] struct {
	// mu guards entries and every value's keyedEntry. Embedders whose value state must be
	// consistent with the registry's own (stdio's ticket queue, whose reclaim predicate reads
	// counters the turn advances) take this SAME mutex through locker/lock rather than adding
	// a second one — one lock means there is no ordering between them to get wrong, and the
	// cond var a FIFO waits on can be built over it directly.
	mu      sync.Mutex
	entries map[string]T
	// build makes a fresh value. It takes no key: the registry files the value and stamps its
	// keyedEntry itself, so "which key is this under" has one answer rather than two that can
	// disagree. Runs under mu.
	build func() T
	// idle reports whether an UNREFERENCED value may be dropped. nil means "always" — the
	// mutual-exclusion gate's answer, where the last holder dropping is the whole condition.
	// stdio's FIFO supplies one, because a queue with no pin can still have handed out tickets
	// whose waiters are parked on it. Runs under mu.
	idle func(T) bool
}

// init prepares the registry. build makes a fresh value; idle (optional) is the extra
// condition beyond "no references" for dropping one.
func (r *keyedRegistry[T]) init(build func() T, idle func(T) bool) {
	r.entries = map[string]T{}
	r.build = build
	r.idle = idle
}

// locker returns the mutex guarding the registry AND every value's own bookkeeping, so an
// embedder can build a sync.Cond over it and mutate value state under the same lock the
// reclaim predicate is evaluated under. See the mu field.
func (r *keyedRegistry[T]) locker() sync.Locker { return &r.mu }

// lock and unlock take the registry mutex directly, for an embedder that manipulates value
// state (a ticket counter, a turn) in the same critical section as a lookup.
func (r *keyedRegistry[T]) lock()   { r.mu.Lock() }
func (r *keyedRegistry[T]) unlock() { r.mu.Unlock() }

// entryLocked returns key's value, creating and filing it if absent. Caller holds mu.
//
// It takes NO reference. A caller that only needs the value for the length of one locked
// critical section (stdio reserving a ticket, which the queue's own counters then account
// for) must not have to pair a hold with a drop it would then have to get right.
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
// The value stays in the registry until every holder has dropped (and the idle predicate
// agrees), so a caller may keep one across many turns.
//
// It is the seam that keeps the registry off the per-request path for a caller whose anchor
// cannot vary. A session-anchored HTTP session and a stdio host each resolve ONE anchor for
// their whole life, so re-resolving per request meant a registry mutex, a map lookup, an
// insert and a delete on every enforced call — the refcount falls to zero the instant a
// non-overlapping request finishes, so the steady state for ordinary sequential traffic was
// create-insert-lookup-delete per call on the microsecond decision path. Worse, that mutex is
// registry-wide, so its contention scaled with the whole route's request rate rather than with
// contending anchors. A holder that keeps its value pays all of that once.
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
// predicate agrees. Caller holds mu.
//
// Exported to the embedder (rather than folded into the drop func alone) because a value can
// become reclaimable WITHOUT a reference changing: stdio's queue becomes idle when its last
// ticket is served, which is a counter move, not a drop. Deleted only under the registry lock,
// so a waiter that already took a reference keeps the value it is queued on, and a later hold
// under the same key builds a fresh one — correct precisely because nobody holds the old.
//
// The map identity re-check is what makes a double call harmless: a value already evicted and
// replaced under the same key must not evict its successor, which may have references of its
// own.
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

// size reports how many values are live. Test-only: the refcounting is what keeps a
// long-lived proxy from accumulating one entry per anchor it has ever served, and that is
// invisible from the outside otherwise.
func (r *keyedRegistry[T]) size() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}
