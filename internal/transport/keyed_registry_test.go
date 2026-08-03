// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// registryProbe is a registry value for exercising the generic on its own. busy stands in for
// whatever the embedder's extra reclaim condition is (stdio's outstanding tickets).
type registryProbe struct {
	keyedEntry
	busy bool
}

func (p *registryProbe) entry() *keyedEntry { return &p.keyedEntry }

// newProbeRegistry builds a registry of probes. idle=nil gives the plain "last holder drops"
// trigger the HTTP gate uses; the busy variant gives the FIFO's.
func newProbeRegistry(honourBusy bool) *keyedRegistry[*registryProbe] {
	r := &keyedRegistry[*registryProbe]{}
	var idle func(*registryProbe) bool
	if honourBusy {
		idle = func(p *registryProbe) bool { return !p.busy }
	}
	r.init(func() *registryProbe { return &registryProbe{} }, idle)
	return r
}

// TestKeyedRegistry_RefcountedLifetime is the invariant both turn primitives now inherit
// instead of each maintaining: an entry is created on first hold, SHARED by every holder of
// that key, and dropped exactly when the last one lets go.
//
// It is the unbounded-growth bug in one place. A gateway route serves an unbounded number of
// sessions over its lifetime, so a registry that only ever grew would be a slow leak keyed by
// session id — and before this generic there were two independent implementations of that
// invariant to keep right.
func TestKeyedRegistry_RefcountedLifetime(t *testing.T) {
	t.Parallel()
	r := newProbeRegistry(false)
	assert.Zero(t, r.size())

	first, dropFirst := r.hold("a")
	second, dropSecond := r.hold("a")
	assert.Same(t, first, second, "one key, one entry: holders of the same key must share it")
	assert.Equal(t, 1, r.size())

	other, dropOther := r.hold("b")
	assert.NotSame(t, first, other, "different keys are different entries")
	assert.Equal(t, 2, r.size())

	dropFirst()
	assert.Equal(t, 2, r.size(), "an entry with a holder left must stay")
	dropSecond()
	assert.Equal(t, 1, r.size(), "and go the moment the last holder drops")
	dropOther()
	assert.Zero(t, r.size())

	// A later hold under a reclaimed key builds a FRESH entry, which is correct precisely
	// because nobody holds the old one.
	again, dropAgain := r.hold("a")
	assert.NotSame(t, first, again)
	dropAgain()
	assert.Zero(t, r.size())
}

// TestKeyedRegistry_DropIsIdempotent pins the property the callers lean on: both transports
// release a turn early AND defer the same release as a backstop, so a drop func is routinely
// called twice. A second call must not underflow the refcount into evicting an entry other
// holders are using.
func TestKeyedRegistry_DropIsIdempotent(t *testing.T) {
	t.Parallel()
	r := newProbeRegistry(false)
	_, dropA := r.hold("k")
	_, dropB := r.hold("k")

	dropA()
	dropA()
	dropA()
	assert.Equal(t, 1, r.size(), "repeated drops of ONE reference must not release another holder's")

	dropB()
	assert.Zero(t, r.size())
}

// TestKeyedRegistry_IdlePredicateHoldsTheEntry covers the difference between the two
// embedders, which is the whole reason this is a parameter rather than a fork: a
// mutual-exclusion gate is finished when its last holder drops, while a FIFO must also outlive
// the tickets it handed out. Same lifetime, one supplied predicate.
func TestKeyedRegistry_IdlePredicateHoldsTheEntry(t *testing.T) {
	t.Parallel()
	r := newProbeRegistry(true)
	v, drop := r.hold("k")
	v.busy = true

	drop()
	assert.Equal(t, 1, r.size(), "no holder left, but the entry is still busy: it must stay")

	// Becoming idle is not a reference change, which is why the embedder can ask for the
	// re-check directly.
	r.lock()
	v.busy = false
	r.reapLocked(v)
	r.unlock()
	assert.Zero(t, r.size(), "and go once the extra condition clears")
}

// TestKeyedRegistry_StaleHandleCannotEvictItsSuccessor is the guard on the delete itself. A
// value that was already reclaimed and replaced under the same key must not evict the
// replacement, which may have holders of its own — the failure mode is silent, and it hands
// two callers independent turns on a key that is supposed to have one.
func TestKeyedRegistry_StaleHandleCannotEvictItsSuccessor(t *testing.T) {
	t.Parallel()
	r := newProbeRegistry(true)
	stale, dropStale := r.hold("k")
	dropStale()
	require.Zero(t, r.size(), "the first entry is gone")

	live, dropLive := r.hold("k")
	require.NotSame(t, stale, live)

	// The stale handle is re-reaped, as a mis-sequenced release would do.
	r.lock()
	r.reapLocked(stale)
	r.unlock()
	assert.Equal(t, 1, r.size(), "a stale handle must not evict the live entry filed under its key")

	current, dropCurrent := r.hold("k")
	assert.Same(t, live, current, "and the live entry must still be the one a new holder gets")
	dropCurrent()
	dropLive()
	assert.Zero(t, r.size())
}

// TestKeyedRegistry_ConcurrentHoldersConvergeOnOneEntry is the race-detector half: the
// registry is entered from every request goroutine on a route, so create-or-get, the refcount
// and the reclaim all have to be one critical section.
func TestKeyedRegistry_ConcurrentHoldersConvergeOnOneEntry(t *testing.T) {
	t.Parallel()
	r := newProbeRegistry(false)

	const holders = 64
	var wg, registered sync.WaitGroup
	seen := make([]*registryProbe, holders)
	release := make(chan struct{})
	for i := range holders {
		wg.Add(1)
		registered.Add(1)
		go func() {
			defer wg.Done()
			v, drop := r.hold("shared")
			seen[i] = v
			registered.Done()
			// Every holder is registered before any drops, so the entry cannot be reclaimed
			// and rebuilt mid-run — which would make the identity assertion below pass or
			// fail on scheduling rather than on the registry.
			<-release
			drop()
		}()
	}
	registered.Wait()
	assert.Equal(t, 1, r.size(), "64 concurrent holders of one key must have produced one entry")
	close(release)
	wg.Wait()

	assert.Zero(t, r.size(), "every reference released means the entry is gone")
	for i, v := range seen {
		require.NotNil(t, v, "holder %d got no entry", i)
		assert.Same(t, seen[0], v, "concurrent holders of one key must converge on one entry")
	}
}

// TestKeyedRegistry_BacksBothTurnPrimitives is the connecting assertion: the two registries
// that used to maintain this lifetime separately now exhibit it through the same code, with
// only their reclaim trigger differing. A future third turn primitive should land here too
// rather than growing a third map.
func TestKeyedRegistry_BacksBothTurnPrimitives(t *testing.T) {
	t.Parallel()
	gates := newAnchorGates()
	gate, dropGate := gates.hold("anchor")
	require.NotNil(t, gate)
	assert.Equal(t, 1, gates.size())
	dropGate()
	assert.Zero(t, gates.size(), "a mutual-exclusion gate is finished when its last holder drops")

	ser := newDecisionSerializer()
	queue, unpin := ser.hold("anchor")
	require.NotNil(t, queue)
	ticket := ser.takeOn(queue)
	unpin()
	assert.Equal(t, 1, ser.size(), "a FIFO with an outstanding ticket must outlive its last pin")
	ser.begin(ticket)()
	assert.Zero(t, ser.size(), "and go once that ticket has been served")
}
