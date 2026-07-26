// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package circuitbreaker

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestStats_JSON_OmitsZeroTimes is a regression test: encoding/json ignores
// omitempty on time.Time, so a fresh (or just-Reset) breaker's zero
// lastFailureTime/lastTransitionAt would serialize as "0001-01-01T00:00:00Z" and
// trip "failure in year 1" alerts. Stats.MarshalJSON must omit those fields when
// zero and include them (with real values) once set.
func TestStats_JSON_OmitsZeroTimes(t *testing.T) {
	b := New(DefaultConfig())

	data, err := json.Marshal(b.Stats())
	if err != nil {
		t.Fatalf("marshal fresh Stats: %v", err)
	}
	s := string(data)
	if strings.Contains(s, "0001-01-01") {
		t.Errorf("zero time serialized as year-1 timestamp: %s", s)
	}
	if strings.Contains(s, "lastFailureTime") {
		t.Errorf("lastFailureTime should be omitted when zero: %s", s)
	}
	if strings.Contains(s, "lastTransitionAt") {
		t.Errorf("lastTransitionAt should be omitted when zero: %s", s)
	}

	// After a failure the breaker records a transition; the field must now appear
	// with a real (non year-1) value.
	for range DefaultConfig().FailureThreshold {
		b.markFailure()
	}
	data, err = json.Marshal(b.Stats())
	if err != nil {
		t.Fatalf("marshal tripped Stats: %v", err)
	}
	s = string(data)
	if !strings.Contains(s, "lastFailureTime") || !strings.Contains(s, "lastTransitionAt") {
		t.Errorf("expected both time fields present after a trip: %s", s)
	}
	if strings.Contains(s, "0001-01-01") {
		t.Errorf("tripped Stats still contains a year-1 timestamp: %s", s)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.FailureThreshold != 5 {
		t.Errorf("expected FailureThreshold=5, got %d", cfg.FailureThreshold)
	}
	if cfg.CooldownDuration != 30*time.Second {
		t.Errorf("expected CooldownDuration=30s, got %v", cfg.CooldownDuration)
	}
	if cfg.HalfOpenMaxProbes != 1 {
		t.Errorf("expected HalfOpenMaxProbes=1, got %d", cfg.HalfOpenMaxProbes)
	}
}

func TestBreaker_StartsInClosedState(t *testing.T) {
	b := New(DefaultConfig())
	if s := b.State(); s != StateClosed {
		t.Errorf("expected StateClosed, got %q", s)
	}
}

func TestBreaker_AllowsInClosedState(t *testing.T) {
	b := New(DefaultConfig())
	for i := 0; i < 100; i++ {
		if !b.allowReq() {
			t.Fatalf("expected Allow() = true in closed state, iteration %d", i)
		}
	}
}

func TestBreaker_OpensAfterThreshold(t *testing.T) {
	cfg := Config{
		FailureThreshold:  3,
		CooldownDuration:  10 * time.Second,
		HalfOpenMaxProbes: 1,
	}
	b := New(cfg)

	// 2 failures should not open.
	b.markFailure()
	b.markFailure()
	if !b.allowReq() {
		t.Fatal("breaker should still be closed after 2 failures")
	}

	// 3rd failure opens.
	b.markFailure()
	if b.allowReq() {
		t.Fatal("breaker should be open after 3 failures")
	}
	if s := b.State(); s != StateOpen {
		t.Errorf("expected StateOpen, got %q", s)
	}
}

func TestBreaker_SuccessResetsCounter(t *testing.T) {
	cfg := Config{
		FailureThreshold:  3,
		CooldownDuration:  10 * time.Second,
		HalfOpenMaxProbes: 1,
	}
	b := New(cfg)

	b.markFailure()
	b.markFailure()
	b.markSuccess() // Resets consecutive failures.
	b.markFailure()
	b.markFailure()
	// Only 2 consecutive failures at this point, should still allow.
	if !b.allowReq() {
		t.Fatal("expected breaker to remain closed after success reset")
	}
}

func TestBreaker_TransitionsToHalfOpenAfterCooldown(t *testing.T) {
	var mu sync.Mutex
	current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return current
	}
	advanceClock := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		current = current.Add(d)
	}

	cfg := Config{
		FailureThreshold:  2,
		CooldownDuration:  5 * time.Second,
		HalfOpenMaxProbes: 2,
	}
	b := New(cfg, WithClock(clock))
	b.markFailure()
	b.markFailure()
	if b.allowReq() {
		t.Fatal("expected denial while open")
	}

	advanceClock(6 * time.Second)

	// Should transition to half-open and allow a probe.
	if !b.allowReq() {
		t.Fatal("expected Allow() after cooldown (half-open)")
	}
	if s := b.State(); s != StateHalfOpen {
		t.Errorf("expected StateHalfOpen, got %q", s)
	}

	// Second probe should also be allowed (HalfOpenMaxProbes=2).
	if !b.allowReq() {
		t.Fatal("expected second probe allowed")
	}

	// Third should be denied.
	if b.allowReq() {
		t.Fatal("expected denial after max probes exhausted")
	}
}

func TestBreaker_HalfOpenSuccessCloses(t *testing.T) {
	var mu sync.Mutex
	current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return current
	}
	advanceClock := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		current = current.Add(d)
	}

	cfg := Config{
		FailureThreshold:  2,
		CooldownDuration:  5 * time.Second,
		HalfOpenMaxProbes: 1,
	}
	b := New(cfg, WithClock(clock))

	b.markFailure()
	b.markFailure()
	advanceClock(6 * time.Second)
	b.allowReq() // Transitions to half-open.
	b.markSuccess()

	if s := b.State(); s != StateClosed {
		t.Errorf("expected StateClosed after half-open success, got %q", s)
	}
	// Should allow freely again.
	if !b.allowReq() {
		t.Fatal("expected Allow() after close")
	}
}

func TestBreaker_HalfOpenFailureReopens(t *testing.T) {
	var mu sync.Mutex
	current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return current
	}
	advanceClock := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		current = current.Add(d)
	}

	cfg := Config{
		FailureThreshold:  2,
		CooldownDuration:  5 * time.Second,
		HalfOpenMaxProbes: 1,
	}
	b := New(cfg, WithClock(clock))

	b.markFailure()
	b.markFailure()
	advanceClock(6 * time.Second)
	b.allowReq() // Transitions to half-open.
	b.markFailure()

	if s := b.State(); s != StateOpen {
		t.Errorf("expected StateOpen after half-open failure, got %q", s)
	}
	if b.allowReq() {
		t.Fatal("expected denial after re-open")
	}
}

// TestBreaker_HalfOpenProbeFailureAfterSuccessReopens guards the contract that a
// failed half-open probe re-opens the breaker even when an earlier probe in the
// same window already succeeded. With HalfOpenMaxProbes > 1 the first success
// must not prematurely close the breaker.
func TestBreaker_HalfOpenProbeFailureAfterSuccessReopens(t *testing.T) {
	var mu sync.Mutex
	current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return current
	}
	advanceClock := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		current = current.Add(d)
	}

	cfg := Config{
		FailureThreshold:  3,
		CooldownDuration:  5 * time.Second,
		HalfOpenMaxProbes: 2,
	}
	b := New(cfg, WithClock(clock))

	for i := 0; i < cfg.FailureThreshold; i++ {
		b.markFailure()
	}
	advanceClock(6 * time.Second)

	if !b.allowReq() {
		t.Fatal("expected first half-open probe to be admitted")
	}
	if !b.allowReq() {
		t.Fatal("expected second half-open probe to be admitted")
	}

	b.markSuccess() // first probe succeeds; must NOT close yet
	if s := b.State(); s != StateHalfOpen {
		t.Fatalf("expected StateHalfOpen after one of two probes succeeded, got %q", s)
	}

	b.markFailure() // second probe fails; must re-open
	if s := b.State(); s != StateOpen {
		t.Fatalf("expected a failed half-open probe to re-open the breaker, got %q", s)
	}
	if b.allowReq() {
		t.Fatal("expected denial after re-open")
	}
}

// TestBreaker_StaleProbeDoesNotCloseAcrossWindows is a regression test: a probe
// admitted in one half-open window that reports its outcome only AFTER the breaker
// has reopened and entered a NEW half-open window must not be counted toward
// closing the new window. Reported through the generation-aware Probe from
// AllowProbe, the stale success is dropped, so the breaker stays open instead of
// closing prematurely on one stale + one fresh success.
func TestBreaker_StaleProbeDoesNotCloseAcrossWindows(t *testing.T) {
	var mu sync.Mutex
	current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return current
	}
	advanceClock := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		current = current.Add(d)
	}

	cfg := Config{
		FailureThreshold:  1,
		CooldownDuration:  5 * time.Second,
		HalfOpenMaxProbes: 2, // closing requires 2 successes
	}
	b := New(cfg, WithClock(clock))

	b.markFailure() // trips open (threshold 1)

	// Window 1: admit probes A and B.
	advanceClock(6 * time.Second)
	okA, probeA := b.allowProbe()
	okB, probeB := b.allowProbe()
	if !okA || !okB {
		t.Fatalf("expected both window-1 probes admitted, got A=%v B=%v", okA, okB)
	}

	// A fails, re-opening the breaker. B is still "in flight".
	probeA.failure()
	if s := b.State(); s != StateOpen {
		t.Fatalf("expected re-open after probe A failed, got %q", s)
	}

	// Window 2: cooldown elapses, admit a fresh probe C.
	advanceClock(6 * time.Second)
	okC, probeC := b.allowProbe()
	if !okC {
		t.Fatal("expected window-2 probe C to be admitted")
	}

	// The stale success from B (window 1) must be dropped, not counted toward
	// window 2. C's fresh success is only 1 of the 2 required, so the breaker
	// must remain half-open, not close.
	probeB.success() // stale -> dropped
	probeC.success() // fresh -> 1 of 2
	if s := b.State(); s != StateHalfOpen {
		t.Fatalf("stale probe must not close the breaker; expected StateHalfOpen, got %q", s)
	}
}

// TestBreaker_StaleProbeAfterCloseDoesNotReopen is a regression test: a probe
// admitted in a half-open window that reports a Failure only AFTER that window
// has already closed must be recognized as stale (its generation no longer
// matches the current one) and dropped, rather than re-opening a now-healthy
// closed breaker. Before the fix, recordSuccess closed the breaker without
// bumping halfOpenGen — unlike AllowProbe and Reset — so the in-flight probe
// still carried the matching generation; recordFailure runs in StateClosed
// (where the open-state guard does not apply), counted the stale failure, and
// with FailureThreshold=1 tripped the breaker straight back open.
func TestBreaker_StaleProbeAfterCloseDoesNotReopen(t *testing.T) {
	var mu sync.Mutex
	current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return current
	}
	advanceClock := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		current = current.Add(d)
	}

	cfg := Config{
		FailureThreshold:  1, // a single counted failure trips the closed breaker
		CooldownDuration:  5 * time.Second,
		HalfOpenMaxProbes: 2, // closing requires 2 successes
	}
	b := New(cfg, WithClock(clock))

	b.markFailure() // trip open
	advanceClock(6 * time.Second)

	// Admit two probes in the same half-open window (generation g). B is the slow
	// one whose outcome arrives only after the window has closed.
	okA, _ := b.allowProbe()
	okB, probeB := b.allowProbe()
	if !okA || !okB {
		t.Fatalf("expected both probes admitted, got A=%v B=%v", okA, okB)
	}

	// Close the window with the required two successes while probe B is still in
	// flight. Closing must advance the generation past g.
	b.markSuccess()
	b.markSuccess()
	if s := b.State(); s != StateClosed {
		t.Fatalf("expected breaker closed after required successes, got %q", s)
	}

	// B finally fails. It belongs to the window that just closed (generation g),
	// so it must be dropped as stale and leave the closed breaker untouched.
	probeB.failure()
	if s := b.State(); s != StateClosed {
		t.Fatalf("stale probe failure must not reopen a closed breaker; got %q", s)
	}
}

// TestBreaker_Stats_LastTransitionAtProjectedInLogicalHalfOpen pins this invariant:
// during the logical half-open window (cooldown elapsed but allow() not yet
// called, so b.state is still physically Open), Stats() must project
// LastTransitionAt to the instant the cooldown elapsed (lastFailureTime +
// CooldownDuration), not leave it at the Open time. Otherwise the snapshot pairs
// State=HalfOpen with the Open transition time — internally contradictory, and a
// "half-open since" dashboard would wrongly include the whole cooldown.
func TestBreaker_Stats_LastTransitionAtProjectedInLogicalHalfOpen(t *testing.T) {
	var mu sync.Mutex
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	current := start
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return current
	}
	advance := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		current = current.Add(d)
	}

	cfg := Config{
		FailureThreshold:  1,
		CooldownDuration:  100 * time.Millisecond,
		HalfOpenMaxProbes: 1,
	}
	b := New(cfg, WithClock(clock))

	b.markFailure() // trips open at `start`; physical lastTransitionAt = start
	advance(150 * time.Millisecond)

	// Read Stats WITHOUT calling Allow() — the breaker is still physically Open.
	s := b.Stats()
	if s.State != StateHalfOpen {
		t.Fatalf("expected logical HalfOpen after cooldown, got %q", s.State)
	}
	want := start.Add(cfg.CooldownDuration)
	if !s.LastTransitionAt.Equal(want) {
		t.Fatalf("LastTransitionAt = %v, want %v (cooldown-elapsed instant)", s.LastTransitionAt, want)
	}
	if s.LastTransitionAt.Equal(start) {
		t.Fatal("LastTransitionAt is still the Open time; the cooldown projection was not applied")
	}
}

// TestBreaker_HalfOpenClosesOnlyAfterAllProbesSucceed verifies the breaker closes
// once HalfOpenMaxProbes probes have all succeeded, and not before.
func TestBreaker_HalfOpenClosesOnlyAfterAllProbesSucceed(t *testing.T) {
	var mu sync.Mutex
	current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return current
	}
	advanceClock := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		current = current.Add(d)
	}

	cfg := Config{
		FailureThreshold:  2,
		CooldownDuration:  5 * time.Second,
		HalfOpenMaxProbes: 2,
	}
	b := New(cfg, WithClock(clock))

	b.markFailure()
	b.markFailure()
	advanceClock(6 * time.Second)

	if !b.allowReq() {
		t.Fatal("expected first half-open probe to be admitted")
	}
	if !b.allowReq() {
		t.Fatal("expected second half-open probe to be admitted")
	}

	b.markSuccess()
	if s := b.State(); s != StateHalfOpen {
		t.Fatalf("expected StateHalfOpen after first of two probe successes, got %q", s)
	}

	b.markSuccess()
	if s := b.State(); s != StateClosed {
		t.Fatalf("expected StateClosed after all probes succeeded, got %q", s)
	}
	if !b.allowReq() {
		t.Fatal("expected Allow() once the breaker has closed")
	}
}

// TestBreaker_HalfOpenConcurrentProbes_FailureWins exercises the concurrency the
// fix is motivated by: two probes admitted in the same half-open window report
// their outcomes from separate goroutines. Whatever the interleaving, a failure
// from an admitted probe must leave the breaker open. Run under -race, it also
// guards the mutex interaction directly.
func TestBreaker_HalfOpenConcurrentProbes_FailureWins(t *testing.T) {
	var mu sync.Mutex
	current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return current
	}
	advanceClock := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		current = current.Add(d)
	}

	cfg := Config{
		FailureThreshold:  2,
		CooldownDuration:  5 * time.Second,
		HalfOpenMaxProbes: 2,
	}
	b := New(cfg, WithClock(clock))

	b.markFailure()
	b.markFailure()
	advanceClock(6 * time.Second)

	if !b.allowReq() {
		t.Fatal("expected first half-open probe to be admitted")
	}
	if !b.allowReq() {
		t.Fatal("expected second half-open probe to be admitted")
	}

	// One probe succeeds and one fails, concurrently. Either ordering must end
	// open: success-then-failure re-opens directly; failure-then-success re-opens
	// on the failure and the late success cannot reach the half-open close path.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		b.markSuccess()
	}()
	go func() {
		defer wg.Done()
		b.markFailure()
	}()
	wg.Wait()

	if s := b.State(); s != StateOpen {
		t.Fatalf("a failed half-open probe must leave the breaker open regardless of ordering, got %q", s)
	}
}

func TestBreaker_Reset(t *testing.T) {
	cfg := Config{
		FailureThreshold:  2,
		CooldownDuration:  5 * time.Second,
		HalfOpenMaxProbes: 1,
	}
	b := New(cfg)
	b.markFailure()
	b.markFailure()
	// Open.
	beforeReset := b.Stats()
	if beforeReset.LastFailureTime.IsZero() {
		t.Fatal("expected non-zero LastFailureTime before reset")
	}
	b.reset()
	if s := b.State(); s != StateClosed {
		t.Errorf("expected StateClosed after reset, got %q", s)
	}
	if !b.allowReq() {
		t.Fatal("expected Allow() after reset")
	}
	afterReset := b.Stats()
	if !afterReset.LastFailureTime.IsZero() {
		t.Fatal("expected LastFailureTime to be cleared on reset")
	}
}

func TestBreaker_Stats(t *testing.T) {
	cfg := Config{
		FailureThreshold:  3,
		CooldownDuration:  5 * time.Second,
		HalfOpenMaxProbes: 1,
	}
	b := New(cfg)

	b.markSuccess()
	b.markFailure()
	b.markSuccess()
	b.markFailure()
	b.markFailure()

	Stats := b.Stats()
	if Stats.TotalSuccesses != 2 {
		t.Errorf("expected 2 successes, got %d", Stats.TotalSuccesses)
	}
	if Stats.TotalFailures != 3 {
		t.Errorf("expected 3 failures, got %d", Stats.TotalFailures)
	}
	if Stats.ConsecutiveFails != 2 {
		t.Errorf("expected 2 consecutive fails, got %d", Stats.ConsecutiveFails)
	}
}

// TestBreaker_StatsReportsLogicalStateAfterCooldown verifies that Stats().State
// agrees with State() in the window between cooldown expiry and the first
// Allow() call: both must report half-open. Previously Stats() returned the raw
// b.state field (still open), contradicting State().
func TestBreaker_StatsReportsLogicalStateAfterCooldown(t *testing.T) {
	var mu sync.Mutex
	current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return current
	}
	advanceClock := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		current = current.Add(d)
	}

	cfg := Config{
		FailureThreshold:  2,
		CooldownDuration:  5 * time.Second,
		HalfOpenMaxProbes: 1,
	}
	b := New(cfg, WithClock(clock))
	b.markFailure()
	b.markFailure()

	// Before cooldown both report open.
	if s := b.State(); s != StateOpen {
		t.Fatalf("expected State()=open before cooldown, got %q", s)
	}
	if s := b.Stats().State; s != StateOpen {
		t.Fatalf("expected Stats().State=open before cooldown, got %q", s)
	}

	advanceClock(6 * time.Second)

	// After cooldown, before any Allow(), both must report half-open.
	if s := b.State(); s != StateHalfOpen {
		t.Fatalf("expected State()=half-open after cooldown, got %q", s)
	}
	if s := b.Stats().State; s != StateHalfOpen {
		t.Errorf("expected Stats().State=half-open after cooldown, got %q", s)
	}
}

// TestNewSanitizesDegenerateConfig verifies that New replaces non-positive
// fields with DefaultConfig values instead of producing a breaker that trips on
// the first failure with no cooldown.
func TestNewSanitizesDegenerateConfig(t *testing.T) {
	var mu sync.Mutex
	current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return current
	}

	// Zero-value config: must behave like DefaultConfig (threshold 5), not trip
	// on the first failure.
	b := New(Config{}, WithClock(clock))
	for i := 0; i < 4; i++ {
		b.markFailure()
	}
	if s := b.State(); s != StateClosed {
		t.Fatalf("expected breaker still closed after 4 failures (default threshold 5), got %q", s)
	}
	b.markFailure() // 5th failure opens.
	if s := b.State(); s != StateOpen {
		t.Fatalf("expected breaker open after 5 failures, got %q", s)
	}
	// CooldownDuration was sanitized to 30s (>0), so no immediate half-open.
	if b.allowReq() {
		t.Error("expected denial immediately after opening (cooldown should be positive)")
	}
}

// TestBreaker_RecordFailureWhileOpenDoesNotResetCooldown verifies that a failure
// reported while the breaker is already open (a violation of the admit-before-record
// contract — Allow transitions Open->HalfOpen before returning a probe slot, so a
// genuine probe failure is recorded against half-open, not open) does not restart
// the cooldown clock. Previously RecordFailure unconditionally stamped
// lastFailureTime, so a steady trickle of out-of-band failures kept resetting the
// cooldown and trapped the breaker open until an explicit Reset.
func TestBreaker_RecordFailureWhileOpenDoesNotResetCooldown(t *testing.T) {
	var mu sync.Mutex
	current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return current
	}
	advanceClock := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		current = current.Add(d)
	}

	cfg := Config{
		FailureThreshold:  2,
		CooldownDuration:  10 * time.Second,
		HalfOpenMaxProbes: 1,
	}
	b := New(cfg, WithClock(clock))

	b.markFailure()
	b.markFailure() // opens the breaker
	if s := b.State(); s != StateOpen {
		t.Fatalf("expected StateOpen after threshold failures, got %q", s)
	}

	// A stray failure reported while the breaker is open but before the cooldown
	// elapses (9s < 10s) is counted in TotalFailures yet ignored for
	// consecutiveFails: it did not come from an admitted probe. Observed here while
	// still genuinely open, where the consecutive-failure counter is visible — once
	// the breaker goes half-open it is cleared (asserted below).
	advanceClock(9 * time.Second)
	b.markFailure()
	if s := b.State(); s != StateOpen {
		t.Fatalf("9s < cooldown: breaker should still be open, got %q", s)
	}
	if mid := b.Stats(); mid.ConsecutiveFails != 2 {
		t.Errorf("stray open-state failure must not pollute consecutiveFails; want 2, got %d", mid.ConsecutiveFails)
	}

	// Four more stray failures while open, each less than a full cooldown apart.
	// With the cooldown-reset bug each would reset lastFailureTime so the 10s
	// cooldown never elapses; correct behavior leaves it at the trip instant.
	for i := 0; i < 4; i++ {
		advanceClock(9 * time.Second)
		b.markFailure()
	}

	// 45s have elapsed since the breaker opened, far past the 10s cooldown, so the
	// breaker must report (virtual) half-open and admit a recovery probe.
	if s := b.State(); s != StateHalfOpen {
		t.Fatalf("stray failures while open must not reset the cooldown; expected half-open, got %q", s)
	}
	if !b.allowReq() {
		t.Fatal("expected a recovery probe to be admitted once the cooldown elapsed")
	}

	// All seven reported failures are counted for observability.
	Stats := b.Stats()
	if Stats.TotalFailures != 7 {
		t.Errorf("expected TotalFailures=7 (all reported failures counted), got %d", Stats.TotalFailures)
	}
	// Once the probe is admitted the breaker is half-open, so the consecutive-
	// failure counter is cleared: the snapshot must not be the contradictory
	// "half-open with ConsecutiveFails==FailureThreshold".
	if Stats.ConsecutiveFails != 0 {
		t.Errorf("expected ConsecutiveFails=0 once half-open, got %d", Stats.ConsecutiveFails)
	}
}

// TestBreaker_HalfOpenProbeFailureDoesNotInflateConsecutiveFails is a regression
// test: a failed half-open probe re-opens the breaker, and the
// consecutive-failure counter must be reset on that transition (mirroring
// RecordSuccess on close) rather than continuing to climb past FailureThreshold
// with every failed probe — which made Stats().ConsecutiveFails report a
// meaningless inflated value.
func TestBreaker_HalfOpenProbeFailureDoesNotInflateConsecutiveFails(t *testing.T) {
	var mu sync.Mutex
	current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return current
	}
	advanceClock := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		current = current.Add(d)
	}

	cfg := Config{
		FailureThreshold:  3,
		CooldownDuration:  5 * time.Second,
		HalfOpenMaxProbes: 1,
	}
	b := New(cfg, WithClock(clock))

	for i := 0; i < cfg.FailureThreshold; i++ {
		b.markFailure()
	}
	if s := b.State(); s != StateOpen {
		t.Fatalf("expected StateOpen after %d failures, got %q", cfg.FailureThreshold, s)
	}

	// Repeatedly let the cooldown elapse, admit a recovery probe, and fail it.
	// Each failed probe re-opens the breaker; ConsecutiveFails must never exceed
	// FailureThreshold (with the bug it climbed to threshold+1, +2, +3, ...).
	for cycle := 1; cycle <= 3; cycle++ {
		advanceClock(6 * time.Second)
		if !b.allowReq() {
			t.Fatalf("cycle %d: expected a recovery probe to be admitted after cooldown", cycle)
		}
		b.markFailure() // half-open probe fails -> re-open

		if got := b.Stats().ConsecutiveFails; got > cfg.FailureThreshold {
			t.Fatalf("cycle %d: ConsecutiveFails inflated by a half-open probe failure: got %d, want <= %d",
				cycle, got, cfg.FailureThreshold)
		}
	}
}

// TestBreaker_StatsConsecutiveFailsAfterProbeReopen is a regression test. After
// a failed half-open probe re-opens the breaker (Path B), recordFailure zeroes the
// physical counter, which would otherwise make Stats() report "Open with
// ConsecutiveFails==0" — contradictory, since a breaker cannot be open because of
// zero failures. Stats() must project the count that justifies the Open state (the
// configured FailureThreshold), matching the value the normal Closed->Open trip
// (Path A) reports, so observability code cannot tell the two Open paths apart by a
// nonsensical zero.
func TestBreaker_StatsConsecutiveFailsAfterProbeReopen(t *testing.T) {
	var mu sync.Mutex
	current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return current
	}
	advanceClock := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		current = current.Add(d)
	}

	cfg := Config{
		FailureThreshold:  3,
		CooldownDuration:  100 * time.Millisecond,
		HalfOpenMaxProbes: 1,
	}
	b := New(cfg, WithClock(clock))

	// Path A: Closed -> Open via the normal failure threshold.
	for i := 0; i < cfg.FailureThreshold; i++ {
		b.markFailure()
	}
	if got := b.Stats(); got.State != StateOpen || got.ConsecutiveFails != cfg.FailureThreshold {
		t.Fatalf("Path A: want {Open, %d}, got {%v, %d}", cfg.FailureThreshold, got.State, got.ConsecutiveFails)
	}

	// Path B: let the cooldown elapse, admit a recovery probe, and fail it so the
	// breaker re-opens from HalfOpen.
	advanceClock(150 * time.Millisecond)
	admitted, probe := b.allowProbe()
	if !admitted {
		t.Fatalf("Path B: expected a recovery probe to be admitted after cooldown")
	}
	probe.failure()

	s := b.Stats()
	if s.State != StateOpen {
		t.Fatalf("Path B: expected StateOpen after a failed probe, got %q", s.State)
	}
	// The pre-fix behavior reported 0 here.
	if s.ConsecutiveFails != cfg.FailureThreshold {
		t.Errorf("Path B: expected ConsecutiveFails=%d (projected, not the physical 0), got %d",
			cfg.FailureThreshold, s.ConsecutiveFails)
	}
}

// TestBreaker_RecordSuccessWhileOpenDoesNotResetConsecutiveFails is a regression
// test: an out-of-contract RecordSuccess() reported while the breaker is
// open must not zero consecutiveFails (which would make Stats report that the
// breaker opened with no preceding failures) nor close the breaker. It mirrors
// RecordFailure's open-state guard. TotalSuccesses still counts the call.
func TestBreaker_RecordSuccessWhileOpenDoesNotResetConsecutiveFails(t *testing.T) {
	cfg := Config{
		FailureThreshold:  3,
		CooldownDuration:  30 * time.Second,
		HalfOpenMaxProbes: 1,
	}
	b := New(cfg)

	for i := 0; i < cfg.FailureThreshold; i++ {
		b.markFailure()
	}
	if s := b.State(); s != StateOpen {
		t.Fatalf("expected StateOpen after %d failures, got %q", cfg.FailureThreshold, s)
	}
	if got := b.Stats().ConsecutiveFails; got != cfg.FailureThreshold {
		t.Fatalf("precondition: expected ConsecutiveFails=%d, got %d", cfg.FailureThreshold, got)
	}

	// Out-of-contract success while open.
	b.markSuccess()

	if s := b.State(); s != StateOpen {
		t.Fatalf("a stray success must not close an open breaker; got %q", s)
	}
	if got := b.Stats().ConsecutiveFails; got != cfg.FailureThreshold {
		t.Errorf("stray open-state success zeroed ConsecutiveFails: got %d, want %d", got, cfg.FailureThreshold)
	}
	if got := b.Stats().TotalSuccesses; got != 1 {
		t.Errorf("TotalSuccesses must still count the reported success: got %d, want 1", got)
	}
}

func TestBreaker_ConcurrentAccess(t *testing.T) {
	cfg := Config{
		FailureThreshold:  100,
		CooldownDuration:  time.Second,
		HalfOpenMaxProbes: 10,
	}
	b := New(cfg)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b.allowReq()
			b.markFailure()
			b.allowReq()
			b.markSuccess()
			_ = b.State()
			_ = b.Stats()
		}()
	}
	wg.Wait()
	// No race condition = test passes.
}

// Do tests

func TestDo_SuccessfulCall(t *testing.T) {
	b := New(DefaultConfig())
	ctx := context.Background()

	result, err := Do(ctx, b, func(_ context.Context) (string, error) {
		return "hello", nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "hello" {
		t.Errorf("expected 'hello', got %q", result)
	}
}

func TestDo_FailureRecorded(t *testing.T) {
	cfg := Config{
		FailureThreshold:  2,
		CooldownDuration:  time.Minute,
		HalfOpenMaxProbes: 1,
	}
	b := New(cfg)
	ctx := context.Background()
	testErr := errors.New("remote failure")

	for i := 0; i < 2; i++ {
		_, err := Do(ctx, b, func(_ context.Context) (int, error) {
			return 0, testErr
		})
		if !errors.Is(err, testErr) {
			t.Fatalf("expected testErr, got %v", err)
		}
	}

	// Breaker should now be open.
	_, err := Do(ctx, b, func(_ context.Context) (int, error) {
		t.Fatal("should not be called when breaker is open")
		return 0, nil
	})
	if !errors.Is(err, ErrOpen) {
		t.Fatalf("expected ErrOpen, got %v", err)
	}
}

func TestDo_CanceledContext(t *testing.T) {
	b := New(DefaultConfig())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := Do(ctx, b, func(_ context.Context) (int, error) {
		t.Fatal("fn should not be called with canceled context")
		return 0, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestDo_NilBreakerPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for nil breaker")
		}
	}()
	_, _ = Do(context.Background(), nil, func(_ context.Context) (int, error) {
		return 0, nil
	})
}

// TestDo_PanicRecordsFailureBeforePropagating verifies that a panic inside fn
// still records exactly one failure on the breaker (so an admitted probe always
// reports an outcome) and that the panic is not swallowed.
func TestDo_PanicRecordsFailureBeforePropagating(t *testing.T) {
	b := New(DefaultConfig())

	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("expected the panic from fn to propagate to the caller")
			}
		}()
		_, _ = Do(context.Background(), b, func(_ context.Context) (int, error) {
			panic("boom")
		})
	}()

	if got := b.Stats().TotalFailures; got != 1 {
		t.Fatalf("a panicking probe must record exactly one failure, got %d", got)
	}
}

// TestDo_PanicReopensHalfOpenBreaker pins the liveness fix: with
// HalfOpenMaxProbes > 1, a probe that panics must re-open the breaker rather
// than wedging it half-open with a spent-but-unreported probe slot.
func TestDo_PanicReopensHalfOpenBreaker(t *testing.T) {
	var mu sync.Mutex
	current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return current
	}

	cfg := Config{
		FailureThreshold:  2,
		CooldownDuration:  5 * time.Second,
		HalfOpenMaxProbes: 2,
	}
	b := New(cfg, WithClock(clock))

	b.markFailure()
	b.markFailure()
	mu.Lock()
	current = current.Add(6 * time.Second)
	mu.Unlock()

	// The first admitted half-open probe panics.
	func() {
		defer func() { _ = recover() }()
		_, _ = Do(context.Background(), b, func(_ context.Context) (int, error) {
			panic("boom")
		})
	}()

	if s := b.State(); s != StateOpen {
		t.Fatalf("a panicking half-open probe must re-open the breaker, got %q", s)
	}
}

func TestBreaker_State_HalfOpen(t *testing.T) {
	var mu sync.Mutex
	current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return current
	}

	cfg := Config{
		FailureThreshold:  2,
		CooldownDuration:  5 * time.Second,
		HalfOpenMaxProbes: 1,
	}
	b := New(cfg, WithClock(clock))
	b.markFailure()
	b.markFailure()

	if b.State() != StateOpen {
		t.Fatalf("expected StateOpen after failures")
	}

	// Advance past cooldown.
	mu.Lock()
	current = current.Add(6 * time.Second)
	mu.Unlock()

	if s := b.State(); s != StateHalfOpen {
		t.Errorf("expected StateHalfOpen after cooldown, got %q", s)
	}
}

// TestBreaker_StaleGenerationOutcomeStillCountedInTotals pins this design decision:
// TotalSuccesses/TotalFailures are throughput counters that count EVERY reported
// outcome, including one a probe reports against a superseded generation (which the
// state machine drops). The increment is before the generation guard on purpose, so
// the totals are not a measure of state-affecting outcomes (use consecutiveFails for
// that). A probe admitted in a half-open window that has since closed reports a
// stale-generation success; it must still be counted.
func TestBreaker_StaleGenerationOutcomeStillCountedInTotals(t *testing.T) {
	var mu sync.Mutex
	current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return current
	}
	advance := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		current = current.Add(d)
	}

	cfg := Config{
		FailureThreshold:  1,
		CooldownDuration:  100 * time.Millisecond,
		HalfOpenMaxProbes: 1,
	}
	b := New(cfg, WithClock(clock))

	b.markFailure() // trip -> Open (TotalFailures=1)
	advance(150 * time.Millisecond)

	admitted, probe := b.allowProbe() // Open->HalfOpen, bumps the generation
	if !admitted {
		t.Fatalf("expected a recovery probe to be admitted after cooldown")
	}
	// A bare success closes the window and bumps the generation again, so the
	// in-flight probe above now carries a superseded generation.
	b.markSuccess()

	// The probe reports its success against the stale generation: dropped by the
	// state machine, but still counted in the throughput total.
	probe.success()

	s := b.Stats()
	if s.TotalSuccesses != 2 {
		t.Errorf("TotalSuccesses = %d, want 2 (bare close + stale-generation probe; every reported outcome is counted)", s.TotalSuccesses)
	}
	if s.TotalFailures != 1 {
		t.Errorf("TotalFailures = %d, want 1", s.TotalFailures)
	}
}

// TestBreaker_LastTransitionAtStableAcrossFirstProbe is a regression test: the
// LastTransitionAt that Stats() projects while the breaker is physically Open but
// past cooldown must equal the value allow() writes when it performs the real
// Open->HalfOpen transition on the first probe, so a "time in half-open" dashboard
// never sees the timestamp jump forward when the probe arrives.
func TestBreaker_LastTransitionAtStableAcrossFirstProbe(t *testing.T) {
	var mu sync.Mutex
	current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return current
	}
	advance := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		current = current.Add(d)
	}

	cfg := Config{FailureThreshold: 1, CooldownDuration: time.Minute, HalfOpenMaxProbes: 1}
	b := New(cfg, WithClock(clock))

	b.markFailure()           // Closed -> Open
	advance(90 * time.Second) // well past cooldown, but no probe yet

	// Projected (physically still Open, logically HalfOpen).
	before := b.Stats()
	if before.State != StateHalfOpen {
		t.Fatalf("want logical HalfOpen after cooldown, got %v", before.State)
	}

	// First probe performs the real transition.
	if admitted, _ := b.allowProbe(); !admitted {
		t.Fatal("expected the first probe to be admitted after cooldown")
	}

	after := b.Stats()
	if after.State != StateHalfOpen {
		t.Fatalf("want HalfOpen after the probe, got %v", after.State)
	}
	if !after.LastTransitionAt.Equal(before.LastTransitionAt) {
		t.Errorf("LastTransitionAt jumped on the first probe: before=%v after=%v",
			before.LastTransitionAt, after.LastTransitionAt)
	}
}

// TestAllowProbe_DropsStaleClosedProbeAcrossReopen is a safe-path regression
// test: a probe admitted in the CLOSED state whose Success is reported only
// after the breaker has tripped Open and reopened into a NEW half-open window
// must be DROPPED by the generation guard, not credited to the new window. The
// bare Allow + RecordSuccess pattern (no generation) would instead close the new
// window prematurely on this stale outcome; AllowProbe is immune by construction.
func TestAllowProbe_DropsStaleClosedProbeAcrossReopen(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	b := New(Config{
		FailureThreshold:  1,
		CooldownDuration:  10 * time.Millisecond,
		HalfOpenMaxProbes: 1,
	}, WithClock(func() time.Time { return now }))

	// 1. Closed-state admission: capture a probe but do NOT report it yet.
	okStale, stale := b.allowProbe()
	if !okStale {
		t.Fatal("closed-state admission must succeed")
	}

	// 2. Trip the breaker Open via a separate closed-state probe failure.
	okTrip, trip := b.allowProbe()
	if !okTrip {
		t.Fatal("closed-state admission must succeed")
	}
	trip.failure()
	if s := b.State(); s != StateOpen {
		t.Fatalf("breaker should be OPEN, got %q", s)
	}

	// 3. Elapse cooldown and admit a fresh half-open probe (new generation).
	now = now.Add(20 * time.Millisecond)
	okFresh, fresh := b.allowProbe()
	if !okFresh {
		t.Fatal("a half-open probe must be admitted after cooldown")
	}

	// 4. The stale closed-state success arrives now. It must be dropped, not close
	//    the new half-open window.
	stale.success()
	if s := b.State(); s != StateHalfOpen {
		t.Fatalf("stale closed-probe success must NOT close the new window; state=%q", s)
	}

	// 5. The fresh probe's own success is what legitimately closes the breaker.
	fresh.success()
	if s := b.State(); s != StateClosed {
		t.Fatalf("fresh probe success should close the breaker, got %q", s)
	}
}

// TestRecordFailureTripTimestampsAgree verifies the fix: a single trip is
// one logical event, so lastFailureTime (the cooldown anchor) and
// lastTransitionAt (the reported transition time) must be identical. A
// step-advancing clock would expose two separate b.now() calls as divergent
// timestamps.
func TestRecordFailureTripTimestampsAgree(t *testing.T) {
	base := time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)
	var calls int
	// Each clock read advances by 1ms, so any two reads within one trip differ.
	clock := func() time.Time {
		calls++
		return base.Add(time.Duration(calls) * time.Millisecond)
	}

	b := New(Config{FailureThreshold: 3, CooldownDuration: time.Minute}, WithClock(clock))

	// Closed -> Open trip.
	for range 3 {
		b.markFailure()
	}
	st := b.Stats()
	if st.State != StateOpen {
		t.Fatalf("breaker not open after threshold failures: %v", st.State)
	}
	if !st.LastFailureTime.Equal(st.LastTransitionAt) {
		t.Fatalf("closed->open trip: lastFailureTime %v != lastTransitionAt %v", st.LastFailureTime, st.LastTransitionAt)
	}
}

// TestAllowOpenToHalfOpenTransitionTimestamp verifies the fix: the
// Open->HalfOpen transition in Allow is a single logical event, so the instant
// that decides the cooldown has elapsed and the reported transition time
// (lastTransitionAt) must be identical. The buggy code read the clock twice (one
// read to check the cooldown, a second, later read stored as lastTransitionAt),
// which a step-advancing clock exposes as divergent timestamps and an extra
// clock read.
func TestAllowOpenToHalfOpenTransitionTimestamp(t *testing.T) {
	base := time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)
	cur := base
	const step = time.Microsecond
	var reads []time.Time
	// Each clock read advances by one step, so any two reads within one
	// transition differ — and the count of reads is observable.
	clock := func() time.Time {
		cur = cur.Add(step)
		reads = append(reads, cur)
		return cur
	}

	b := New(Config{FailureThreshold: 1, CooldownDuration: time.Minute}, WithClock(clock))

	// Closed -> Open.
	b.markFailure()
	if st := b.Stats(); st.State != StateOpen {
		t.Fatalf("breaker not open after threshold failure: %v", st.State)
	}

	// Advance well past the cooldown so the next Allow transitions to half-open.
	cur = cur.Add(2 * time.Minute)

	tripInstant := reads[0] // the single clock read inside RecordFailure (Closed->Open)
	readsBefore := len(reads)
	if !b.allowReq() {
		t.Fatal("Allow should admit a probe after cooldown elapsed")
	}
	// The fix reads the clock exactly once on the Open->HalfOpen path; the bug
	// read it twice.
	if got := len(reads) - readsBefore; got != 1 {
		t.Fatalf("Allow Open->HalfOpen read the clock %d times, want exactly 1", got)
	}
	// LastTransitionAt is the LOGICAL transition instant — when the cooldown elapsed
	// (trip time + CooldownDuration) — not the later first-probe time, so it agrees
	// with the value Stats() projects before any probe and never jumps forward when
	// the first probe arrives.
	wantTransition := tripInstant.Add(time.Minute)
	st := b.Stats()
	if st.State != StateHalfOpen {
		t.Fatalf("breaker not half-open after Allow: %v", st.State)
	}
	if !st.LastTransitionAt.Equal(wantTransition) {
		t.Fatalf("open->half-open transition: lastTransitionAt %v != logical (cooldown-elapsed) instant %v", st.LastTransitionAt, wantTransition)
	}
}

// TestStateAndStatsShareProjection verifies the fix: State() and Stats()
// derive the logical (cooldown-projected) state from a single shared helper, so
// for any given clock instant they never disagree about whether an open breaker
// has crossed into the projected half-open window.
func TestStateAndStatsShareProjection(t *testing.T) {
	var now time.Time
	clock := func() time.Time { return now }

	b := New(Config{FailureThreshold: 1, CooldownDuration: time.Second, HalfOpenMaxProbes: 1}, WithClock(clock))

	now = time.Unix(1000, 0)
	b.markFailure() // closed -> open

	// Just before the cooldown boundary: both report Open.
	now = time.Unix(1000, 0).Add(time.Second - time.Nanosecond)
	if got := b.State(); got != StateOpen {
		t.Fatalf("pre-boundary State() = %v, want open", got)
	}
	if b.State() != b.Stats().State {
		t.Fatalf("pre-boundary State()=%v disagrees with Stats().State=%v", b.State(), b.Stats().State)
	}

	// At and past the boundary: both project HalfOpen, and the projected
	// ConsecutiveFails/LastTransitionAt are self-consistent in the Stats snapshot.
	now = time.Unix(1001, 0)
	if got := b.State(); got != StateHalfOpen {
		t.Fatalf("boundary State() = %v, want half-open", got)
	}
	st := b.Stats()
	if st.State != b.State() {
		t.Fatalf("boundary State()=%v disagrees with Stats().State=%v", b.State(), st.State)
	}
	if st.ConsecutiveFails != 0 {
		t.Fatalf("projected HalfOpen ConsecutiveFails = %d, want 0", st.ConsecutiveFails)
	}
	want := time.Unix(1000, 0).Add(time.Second)
	if !st.LastTransitionAt.Equal(want) {
		t.Fatalf("projected LastTransitionAt = %v, want %v", st.LastTransitionAt, want)
	}
}
