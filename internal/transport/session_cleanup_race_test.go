// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"testing"
)

// TestSessionCleanup_PendingCleanupSparesReRegisteredSameIDWorker pins the compare-and-delete
// in the cleanup goroutines (unregisterSession).
//
// Session ids used to be minted UUIDs, so an unconditional delete-by-id was safe. The
// first-request path now DERIVES ids from caller identity (workerKey), so the same identity
// re-registers under the same key — and a cleanup goroutine can park in <-sess.done/cmd.Wait
// for up to 2x shutdownMs after an explicit teardown (DELETE, kill, drain, drift refusal)
// already removed its entry. If it then deletes by id alone, it deletes the SUCCESSOR: that
// worker's upstream subprocess leaks until process exit (invisible to the idle reaper, the
// kill sweep, and closeAllSessions), its releaseSessionState never runs, and maxSessions
// under-counts. The trigger is the kill/DELETE + re-create cycle — the emergency-stop path.
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

	// W1's cleanup goroutine finally unparks and runs its delete. It must not touch W2.
	p.unregisterSession(w1)
	if got := p.getSession(workerID); got != w2 {
		t.Fatalf("W1's pending cleanup removed the re-registered worker W2 (got %v): its live upstream is now orphaned", got)
	}

	// The comparison must still delete the entry when it IS the session being cleaned up.
	p.unregisterSession(w2)
	if got := p.getSession(workerID); got != nil {
		t.Fatalf("unregisterSession left the session's own entry registered: %v", got)
	}
	// And a second (idempotent) run over an already-gone entry is a no-op.
	p.unregisterSession(w1)
	if n := p.sessionCount(); n != 0 {
		t.Fatalf("sessionCount = %d after cleanup, want 0", n)
	}
}
