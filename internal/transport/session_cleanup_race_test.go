// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"sync"
	"testing"

	"github.com/eunolabs/eunox/internal/pdp"
)

// TestSessionCleanup_PendingCleanupSparesReRegisteredSameIDWorker pins unregisterSession's
// compare-and-delete and its ownership answer. Scenario per the helper's doc: ids are derived
// from caller identity, so during the window a cleanup goroutine spends parked in Wait after an
// explicit teardown removed its entry, the same identity re-registers a successor under the
// same key — deleting by id alone then orphans the successor's live upstream.
func TestSessionCleanup_PendingCleanupSparesReRegisteredSameIDWorker(t *testing.T) {
	t.Parallel()

	p := &HTTPProxy{sessions: map[string]*httpSession{}}
	const workerID = "worker-derived-from-identity"

	w1 := &httpSession{id: workerID}
	if err := p.registerSession(w1, p.currentReapGen()); err != nil {
		t.Fatalf("registerSession(W1): %v", err)
	}

	// Explicit teardown removes W1's entry (teardownSessionByID's delete) while W1's cleanup
	// goroutine is still parked waiting for the subprocess.
	p.mu.Lock()
	delete(p.sessions, workerID)
	p.mu.Unlock()

	// The same identity re-registers: same derived key, new worker.
	w2 := &httpSession{id: workerID}
	if err := p.registerSession(w2, p.currentReapGen()); err != nil {
		t.Fatalf("registerSession(W2): %v", err)
	}

	// W1's cleanup goroutine finally unparks and runs its delete. It must not touch W2, and it
	// must learn it is not the id's owner — the successor's id-keyed PDP state is not its to
	// release.
	if p.unregisterSession(w1) {
		t.Fatal("unregisterSession(W1) claimed ownership of an id a successor holds")
	}
	if got := p.getSession(workerID); got != w2 {
		t.Fatalf("W1's pending cleanup removed the re-registered worker W2 (got %v): its live upstream is now orphaned", got)
	}

	// The comparison must still delete the entry — and report ownership — when it IS the
	// session being cleaned up, and an id already absent with no successor is the caller's to
	// release too (the explicit-teardown path relies on the cleanup goroutine for the release).
	if !p.unregisterSession(w2) {
		t.Fatal("unregisterSession(W2) denied ownership of the session's own entry")
	}
	if got := p.getSession(workerID); got != nil {
		t.Fatalf("unregisterSession left the session's own entry registered: %v", got)
	}
	if !p.unregisterSession(w2) {
		t.Fatal("unregisterSession denied ownership of an absent id with no successor")
	}
}

// releaseRecordingPDP records ReleaseSession calls; everything else is DenyAllPDP.
type releaseRecordingPDP struct {
	pdp.DenyAllPDP
	mu       sync.Mutex
	released []string
}

func (r *releaseRecordingPDP) ReleaseSession(_ context.Context, sessionID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.released = append(r.released, sessionID)
}

func (r *releaseRecordingPDP) releases() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.released...)
}

// TestSessionCleanup_PendingCleanupSparesSuccessorsIDKeyedState is the state half of the same
// race: the registry entry is only one of the two things keyed by the derived id. The PDP's
// per-id state (Tier-2 surface baseline, flow-label taint) belongs to whichever worker holds
// the id NOW, so a predecessor's late cleanup must not release it — that would silently lift a
// successor's surface quarantine and empty its taint set while it serves requests.
func TestSessionCleanup_PendingCleanupSparesSuccessorsIDKeyedState(t *testing.T) {
	t.Parallel()

	rec := &releaseRecordingPDP{}
	rt := &UpstreamRoute{pdp: rec}
	p := &HTTPProxy{sessions: map[string]*httpSession{}}
	const workerID = "worker-derived-from-identity"

	w1 := newTestSession(&httpSession{id: workerID, route: rt})
	if err := p.registerSession(w1, p.currentReapGen()); err != nil {
		t.Fatalf("registerSession(W1): %v", err)
	}
	p.mu.Lock()
	delete(p.sessions, workerID) // explicit teardown, cleanup still parked
	p.mu.Unlock()
	w2 := newTestSession(&httpSession{id: workerID, route: rt})
	if err := p.registerSession(w2, p.currentReapGen()); err != nil {
		t.Fatalf("registerSession(W2): %v", err)
	}

	// W1's cleanup tail runs late: no id-keyed release may happen while W2 owns the id.
	p.finishSessionCleanup(w1)
	if got := rec.releases(); len(got) != 0 {
		t.Fatalf("predecessor's cleanup released the successor's id-keyed state: %v", got)
	}
	if p.getSession(workerID) != w2 {
		t.Fatal("predecessor's cleanup removed the successor's registry entry")
	}

	// W2's own cleanup is the id's last owner and releases exactly once.
	p.finishSessionCleanup(w2)
	if got := rec.releases(); len(got) != 1 || got[0] != workerID {
		t.Fatalf("owner's cleanup released %v, want exactly [%q]", got, workerID)
	}
	if p.getSession(workerID) != nil {
		t.Fatal("owner's cleanup left the entry registered")
	}
}
