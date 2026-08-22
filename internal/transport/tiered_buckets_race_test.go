// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Concurrency coverage for the primitive both admission controls ship on.
//
// saturationGate and reserveSlot each have a dedicated concurrency test; the tiered chain
// underneath them had none, while carrying explicit "best-effort only under concurrency" claims
// about its accounting. Those claims license an UNDER-count (a tally a racing admit folds into
// the wrong record); nothing licenses an OVER-count, which is what the tally exists to prevent
// being wrong about — a suppression line claiming more elided writes than there were writes
// tells an operator an incident was bigger than it was.
//
// So this hammers the chain from many goroutines and asserts the one aggregate that must hold
// regardless of interleaving. Run under -race (CI's default), where it is also the detector's
// only exercise of the two-tier borrow / push-back / un-push paths.

package transport

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTieredBuckets_ConcurrentAdmissionNeverOverStatesTheFlood(t *testing.T) {
	t.Parallel()

	keys := []refusalCategory{catDisplaced, catUnroutableID, catServerRequestFailed}
	// A deliberately tight parent so most writes are refused above the child: the refusal path
	// is where borrow, the push-back and unpushIntermediateTallies all run.
	parent := newTieredBuckets(1, 2, recordReserveInterval, keys, nil, suppressedScopeProxyCategory, floorOwnBucket)

	const (
		holders          = 8
		goroutinesPerKey = 16
	)
	type holder struct {
		table *tieredBuckets[refusalCategory]
		floor *keyReserve[refusalCategory]
	}
	holdersList := make([]holder, holders)
	for i := range holdersList {
		holdersList[i] = holder{
			// Every holder registers the same keys, which is production's shape and the one the
			// delegation precondition requires (see refusal_delegation_precondition_test.go).
			table: newTieredBuckets(2, 4, recordReserveInterval, keys, parent, suppressedScopeSessionCategory, floorParentBucket),
			floor: newKeyReserve(keys),
		}
	}

	var (
		mu             sync.Mutex
		delivered      int
		reportedElided uint64
		wg             sync.WaitGroup
	)
	attempts := holders * len(keys) * goroutinesPerKey

	for h := range holdersList {
		for _, key := range keys {
			for g := 0; g < goroutinesPerKey; g++ {
				wg.Add(1)
				go func(hh holder, k refusalCategory) {
					defer wg.Done()
					v := hh.table.admitWithFloor(k, hh.floor.forKey(k))
					if !v.ok {
						return
					}
					mu.Lock()
					delivered++
					reportedElided += v.suppressed
					mu.Unlock()
				}(holdersList[h], key)
			}
		}
	}
	wg.Wait()

	require.Positive(t, delivered, "every write refused with none delivered means no record and no count reached the tape at all")
	require.LessOrEqual(t, delivered, attempts)
	// The invariant: what the reader SAW plus what it was TOLD it did not see cannot exceed what
	// was attempted. Under-counting is the documented best-effort residual and is not asserted.
	require.LessOrEqualf(t, uint64(delivered)+reportedElided, uint64(attempts),
		"accounting over-states the flood: %d delivered + %d reported elided > %d attempted", delivered, reportedElided, attempts)
}

// TestTieredBuckets_ConcurrentFlooredDeliveryKeepsTheParentBounded drives the FLOOR path
// concurrently — a drained parent with every holder claiming its one reserved write — which is
// where borrow's debt clamp and the intermediate-tally un-push interleave.
//
// The floor deliberately bypasses the gate, so this asserts what the floor's own contract
// bounds: at most one floored delivery per holder per key per reserveEvery, with the window
// never advancing here (the reserve is claimed against the admission's own instant, and no
// clock moves during the test).
func TestTieredBuckets_ConcurrentFlooredDeliveryKeepsTheParentBounded(t *testing.T) {
	t.Parallel()

	keys := []refusalCategory{catDisplaced}
	// Rate and burst at the floor of what the constructor accepts, so the parent refuses
	// essentially everything and the floor is the only way through.
	parent := newTieredBuckets(0.0001, 1, recordReserveInterval, keys, nil, suppressedScopeProxyCategory, floorOwnBucket)

	const holders = 16
	const perHolder = 32
	type holder struct {
		table *tieredBuckets[refusalCategory]
		floor *keyReserve[refusalCategory]
	}
	hs := make([]holder, holders)
	for i := range hs {
		hs[i] = holder{
			table: newTieredBuckets(1000, 1000, recordReserveInterval, keys, parent, suppressedScopeSessionCategory, floorParentBucket),
			floor: newKeyReserve(keys),
		}
	}

	var mu sync.Mutex
	floored := 0
	var wg sync.WaitGroup
	for i := range hs {
		for g := 0; g < perHolder; g++ {
			wg.Add(1)
			go func(hh holder) {
				defer wg.Done()
				if v := hh.table.admitWithFloor(catDisplaced, hh.floor.forKey(catDisplaced)); v.ok && v.reserved {
					mu.Lock()
					floored++
					mu.Unlock()
				}
			}(hs[i])
		}
	}
	wg.Wait()

	// One reserved delivery per holder per window, never per attempt — the whole point of the
	// slot being a claim rather than a flag each refusal reads.
	require.LessOrEqualf(t, floored, holders,
		"%d floored deliveries from %d holders: a holder claimed its reserve more than once inside one window", floored, holders)
	require.Positive(t, floored, "a drained parent with every holder holding an unclaimed reserve must let at least one line through")
}
