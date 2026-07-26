// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"sync"
	"testing"
)

// TestSessionCap_ReservationBoundsConcurrentEstablishment pins that --max-sessions
// bounds concurrent session ESTABLISHMENT, not just registration.
//
// The cap used to be a registry-only pre-check followed by an authoritative check inside
// registerSession. Establishment (upstream spawn + initialize handshake + drift probe)
// runs for up to sessionStartTimeout between the two, so N concurrent initializes against
// an empty registry all passed the pre-check, all spawned an upstream, and only
// maxSessions registered — PID/FD/memory exhaustion despite the cap, repeatable every
// window, contradicting --max-sessions' documented "refused rather than spawning".
//
// Reserving the slot before the spawn is what closes it, so this asserts on the
// reservation primitive rather than on real subprocesses: the number of callers admitted
// concurrently, with nothing yet registered, must never exceed the cap.
func TestSessionCap_ReservationBoundsConcurrentEstablishment(t *testing.T) {
	t.Parallel()

	const limit = 3
	const racers = 32
	p := &HTTPProxy{maxSessions: limit, sessions: map[string]*httpSession{}}

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		admitted int
	)
	for range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if p.tryReserveSessionSlot() {
				mu.Lock()
				admitted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if admitted != limit {
		t.Fatalf("admitted %d concurrent establishments, want exactly %d (the cap): each admission spawns an upstream", admitted, limit)
	}
	// Every admission is still in flight, so the proxy must refuse further ones even
	// though the registry is empty — the property a registry-only check lacked.
	if p.tryReserveSessionSlot() {
		t.Error("reserved a slot while the cap was fully consumed by establishing sessions")
	}
}

// TestSessionCap_ReservationLifecycle pins that a reservation is released on failure and
// converted (not double-counted) on success, so neither a failing upstream permanently
// consumes the cap nor a registered session frees a slot it still holds.
func TestSessionCap_ReservationLifecycle(t *testing.T) {
	t.Parallel()

	p := &HTTPProxy{maxSessions: 2, sessions: map[string]*httpSession{}}

	// Failure path: reserve, then release. The slot comes back.
	if !p.tryReserveSessionSlot() {
		t.Fatal("first reservation refused on an empty proxy")
	}
	p.releaseSessionSlot()
	if p.establishing != 0 {
		t.Fatalf("establishing = %d after release, want 0", p.establishing)
	}

	// A double release must not drive the counter negative — that would silently
	// inflate the effective cap for the rest of the process.
	p.releaseSessionSlot()
	if p.establishing != 0 {
		t.Fatalf("establishing = %d after a double release, want 0 (never negative)", p.establishing)
	}

	// Success path: registerSession must NOT touch the reservation. The caller still
	// holds it and still releases it, so the session is briefly counted twice
	// (registered AND establishing) — the conservative direction.
	if !p.tryReserveSessionSlot() {
		t.Fatal("reservation refused after the released slot returned")
	}
	sess := &httpSession{id: "s1"}
	if err := p.registerSession(sess, p.currentReapGen()); err != nil {
		t.Fatalf("registerSession: %v", err)
	}
	if p.establishing != 1 {
		t.Fatalf("establishing = %d after registration, want 1 (the caller still owns the reservation)", p.establishing)
	}
	if len(p.sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(p.sessions))
	}
	// The handler's unconditional release then ends establishment.
	p.releaseSessionSlot()
	if p.establishing != 0 {
		t.Fatalf("establishing = %d after the caller released, want 0", p.establishing)
	}

	// One slot left: take it, then confirm the cap is reached across both kinds.
	if !p.tryReserveSessionSlot() {
		t.Fatal("second slot refused with one registered and one free")
	}
	if p.tryReserveSessionSlot() {
		t.Error("reserved a third slot with cap=2 (one registered + one establishing)")
	}

	// A failed registration must not touch the reservation either — the caller's
	// unconditional release is the only thing that ever drops it.
	p.shuttingDown = true
	if err := p.registerSession(&httpSession{id: "s2"}, p.currentReapGen()); err == nil {
		t.Fatal("registerSession succeeded during shutdown; want errShuttingDown")
	}
	if p.establishing != 1 {
		t.Errorf("establishing = %d after a failed registration, want 1 (still held for the caller to release)", p.establishing)
	}
}

// TestSessionCap_FailureAfterRegistrationReleasesExactlyOnce pins the regression that
// made the cap defeatable: establishment can fail AFTER registerSession succeeds (the
// startup drift refusal is such a path — it registers, probes, then tears down). When
// registerSession also "converted" the reservation, the caller's release then decremented
// a second time, silently consuming a CONCURRENTLY establishing session's reservation and
// admitting more upstream spawns than the cap allows — the exact over-admission the
// counter exists to prevent. A drift-refusing upstream makes that repeat on every attempt.
func TestSessionCap_FailureAfterRegistrationReleasesExactlyOnce(t *testing.T) {
	t.Parallel()

	p := &HTTPProxy{maxSessions: 2, sessions: map[string]*httpSession{}}

	// Session A and session B both begin establishing. Reserved in separate statements:
	// `!try() || !try()` short-circuits, so the second reservation would be skipped
	// exactly when the first failed — the assertion would pass while the state it
	// describes was never set up.
	if !p.tryReserveSessionSlot() {
		t.Fatal("session A's reservation was refused on an empty proxy")
	}
	if !p.tryReserveSessionSlot() {
		t.Fatal("session B's reservation was refused with one slot free under cap=2")
	}
	// A registers, then fails its post-registration drift check: the session is torn out
	// of the registry and the handler returns, releasing A's reservation exactly once.
	if err := p.registerSession(&httpSession{id: "A"}, p.currentReapGen()); err != nil {
		t.Fatalf("registerSession: %v", err)
	}
	delete(p.sessions, "A") // runDriftCheckOrTeardown's synchronous delete
	p.releaseSessionSlot()  // the handler's deferred release

	// B is still establishing and still holds its slot.
	if p.establishing != 1 {
		t.Fatalf("establishing = %d after A failed post-registration, want 1: B's reservation must survive", p.establishing)
	}
	// Only ONE further establishment may be admitted (cap 2, B holds one).
	if !p.tryReserveSessionSlot() {
		t.Fatal("the free slot was not admitted")
	}
	if p.tryReserveSessionSlot() {
		t.Error("cap defeated: a third concurrent establishment was admitted under maxSessions=2")
	}
}

// TestSessionCap_UnlimitedReservesNothing pins that maxSessions <= 0 (unlimited) keeps
// the reservation path a no-op in both directions, so the counter cannot drift.
func TestSessionCap_UnlimitedReservesNothing(t *testing.T) {
	t.Parallel()

	p := &HTTPProxy{maxSessions: 0, sessions: map[string]*httpSession{}}
	for range 5 {
		if !p.tryReserveSessionSlot() {
			t.Fatal("unlimited cap refused a reservation")
		}
	}
	if p.establishing != 0 {
		t.Errorf("establishing = %d under an unlimited cap, want 0", p.establishing)
	}
	p.releaseSessionSlot()
	if p.establishing != 0 {
		t.Errorf("establishing = %d after release under an unlimited cap, want 0", p.establishing)
	}
}
