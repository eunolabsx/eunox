// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Package circuitbreaker provides a generic, thread-safe circuit breaker
// implementation for protecting calls to external dependencies.
//
// The breaker transitions through three states:
//   - Closed: requests flow normally; consecutive failures are counted.
//   - Open: requests are rejected immediately until a cooldown elapses, then
//     half-open.
//   - HalfOpen: up to HalfOpenMaxProbes probes are allowed. The breaker closes
//     once every admitted probe has succeeded; any probe failure re-opens it.
package circuitbreaker

import (
	"encoding/json"
	"errors"
	"sync"
	"time"
)

// State is a circuit breaker's state. The state machine is driven internally —
// callers cannot set it; they drive the breaker through [Do] and observe the
// current state read-only through [Breaker.State] and [Breaker.Stats].
type State string

const (
	// StateClosed means the circuit is operating normally.
	StateClosed State = "closed"
	// StateOpen means the circuit has tripped due to failures.
	StateOpen State = "open"
	// StateHalfOpen means the circuit is testing with limited probes.
	StateHalfOpen State = "half-open"
)

// ErrOpen is returned when a request is rejected because the circuit is open.
var ErrOpen = errors.New("circuit breaker is open")

// Config configures a circuit breaker.
type Config struct {
	// FailureThreshold is the number of consecutive failures before opening.
	FailureThreshold int
	// CooldownDuration is how long to remain open before transitioning to half-open.
	CooldownDuration time.Duration
	// HalfOpenMaxProbes is the number of probes admitted per half-open window, and
	// also the number that must succeed to close the breaker. Any single probe
	// failure re-opens it.
	HalfOpenMaxProbes int
}

// DefaultConfig returns a reasonable default configuration.
func DefaultConfig() Config {
	return Config{
		FailureThreshold:  5,
		CooldownDuration:  30 * time.Second,
		HalfOpenMaxProbes: 1,
	}
}

// Breaker implements the circuit breaker pattern. Construct it with [New] and
// drive it through the package-level [Do]; [Breaker.State] and [Breaker.Stats]
// expose its state read-only. Every state-machine method below is internal.
//
// Contract: each admitted probe (an allowProbe call returning true) must be followed
// by exactly one outcome on the returned probe (success, failure, or drop). When
// HalfOpenMaxProbes > 1, a probe that never reports can wedge the breaker in
// half-open indefinitely. [Do] honors this even when the guarded call panics.
//
// Concurrency: the probe returned by allowProbe is generation-aware, so a late
// outcome from a reopened half-open window is dropped rather than misapplied (which
// could otherwise close the breaker on a stale success). [Do] is the only production
// caller and reports outcomes exclusively through that probe.
type Breaker struct {
	config Config

	mu               sync.RWMutex
	state            State
	consecutiveFails int
	lastFailureTime  time.Time
	halfOpenProbes   int
	halfOpenSuccess  int
	// halfOpenGen identifies the current half-open window, so a late outcome from a
	// window that has already ended is dropped rather than counted toward the new
	// state. It is incremented at two sites: Open->HalfOpen (opening a new window) and
	// HalfOpen->Closed (closing the breaker after enough successes). The third window-
	// ending transition, the HalfOpen->Open re-trip in recordFailure, deliberately does
	// not bump it — recordFailure and recordSuccess both return early while the state
	// is Open, which already discards every stale outcome, and the next Open->HalfOpen
	// bump supersedes the generation before probes are admitted again.
	halfOpenGen      uint64
	lastTransitionAt time.Time
	totalFailures    int64
	totalSuccesses   int64

	now func() time.Time
}

// probe is the outcome handle for one admitted request, returned by allowProbe.
// Exactly one of success or failure must be called. It records the half-open
// generation it was admitted under so a late outcome from a reopened window is
// dropped rather than counted toward the new one. The zero probe (returned when
// admission is refused) is inert.
type probe struct {
	b   *Breaker
	gen uint64
}

// success reports that the probed request succeeded.
func (p probe) success() {
	if p.b != nil {
		p.b.recordSuccess(p.gen)
	}
}

// failure reports that the probed request failed.
func (p probe) failure() {
	if p.b != nil {
		p.b.recordFailure(p.gen)
	}
}

// drop releases the probe's reserved half-open slot without counting it as success
// or failure, for an outcome that says nothing about upstream health (e.g. a
// client-initiated cancellation). A closed-state probe reserved no slot and a
// superseded-generation drop has nothing to release, so both are no-ops.
func (p probe) drop() {
	if p.b != nil {
		p.b.recordDrop(p.gen)
	}
}

// Option configures a Breaker.
type Option func(*Breaker)

// WithClock overrides the time source (useful for testing).
func WithClock(fn func() time.Time) Option {
	return func(b *Breaker) { b.now = fn }
}

// New creates a new circuit breaker with the given configuration. Sanitizing is the
// package's single config-handling philosophy: any non-positive field is replaced by
// its DefaultConfig value to keep the breaker fail-safe (a non-positive value would
// otherwise be degenerate — tripping on the first failure, no back-pressure, or no
// probes), so New never fails and cfg is immutable afterward. A caller that wants to
// reject a degenerate config rather than have it silently corrected should compare
// against DefaultConfig before calling.
func New(cfg Config, opts ...Option) *Breaker {
	def := DefaultConfig()
	if cfg.FailureThreshold <= 0 {
		cfg.FailureThreshold = def.FailureThreshold
	}
	if cfg.CooldownDuration <= 0 {
		cfg.CooldownDuration = def.CooldownDuration
	}
	if cfg.HalfOpenMaxProbes <= 0 {
		cfg.HalfOpenMaxProbes = def.HalfOpenMaxProbes
	}
	b := &Breaker{
		config: cfg,
		state:  StateClosed,
		now:    time.Now,
	}
	for _, opt := range opts {
		opt(b)
	}
	return b
}

// allowProbe returns whether the breaker permits a request — always in closed state,
// in open state only once cooldown has elapsed (transitioning to half-open), and in
// half-open up to HalfOpenMaxProbes — together with a probe bound to the current
// half-open generation, so a late outcome from a prior window cannot be misapplied.
// On refused admission it returns (false, zero probe). This is the path [Do] uses.
func (b *Breaker) allowProbe() (bool, probe) {
	admitted, gen := b.allow()
	if !admitted {
		return false, probe{}
	}
	return true, probe{b: b, gen: gen}
}

// allow is the shared admission core. It returns whether the request is admitted
// and the half-open generation in effect (the generation a probe admitted now
// belongs to).
func (b *Breaker) allow() (admitted bool, gen uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	switch b.state {
	case StateClosed:
		// A closed-state admission stamps the current generation but reserves NO
		// half-open slot. If the breaker concurrently trips and advances to a new
		// window before this probe reports, the stale-generation outcome is dropped by
		// the guard — harmless: the probe held no slot in the new window, and the
		// totals still count (they increment before the guard). Crediting it would be
		// wrong (a stale failure re-opens, a stale success could close prematurely).
		return true, b.halfOpenGen
	case StateOpen:
		now := b.now()
		if now.Sub(b.lastFailureTime) >= b.config.CooldownDuration {
			b.state = StateHalfOpen
			// New half-open window: bump the generation so in-flight probes from a
			// prior window are recognized as stale.
			b.halfOpenGen++
			b.halfOpenProbes = 1
			b.halfOpenSuccess = 0
			// Clear the trip-time failure count so the snapshot reads HalfOpen with
			// ConsecutiveFails=0, not alongside a stale FailureThreshold.
			b.consecutiveFails = 0
			// Record the LOGICAL transition instant (when cooldown elapsed), not the
			// later first-probe `now`, so lastTransitionAt does not jump forward when
			// the first probe arrives and a "time in half-open" dashboard sees no
			// spurious second transition. State()/Stats() project this same value.
			b.lastTransitionAt = b.lastFailureTime.Add(b.config.CooldownDuration)
			return true, b.halfOpenGen
		}
		return false, b.halfOpenGen
	case StateHalfOpen:
		if b.halfOpenProbes < b.config.HalfOpenMaxProbes {
			b.halfOpenProbes++
			return true, b.halfOpenGen
		}
		return false, b.halfOpenGen
	default:
		return false, b.halfOpenGen
	}
}

// recordSuccess records a successful request reported by a probe admitted under
// generation gen. In half-open state the breaker closes only once every admitted
// probe has succeeded (HalfOpenMaxProbes successes); until then it stays half-open so
// a later failure can still re-open it. A success whose gen no longer matches the
// current half-open window is a stale outcome and is dropped (after being counted in
// the throughput total).
func (b *Breaker) recordSuccess(gen uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// totalSuccesses is observability-only: a throughput counter of every reported
	// success, including ones the state machine drops below. Do not derive net state
	// from it. Incremented before the guards so the count is independent of the drop
	// path. Mirrors totalFailures.
	b.totalSuccesses++

	// A success reported while Open did not come from an admitted probe (allow leaves
	// Open before returning true). Ignore it, symmetric to recordFailure, so it
	// cannot zero consecutiveFails and make a snapshot report an opened breaker with
	// no preceding failures.
	if b.state == StateOpen {
		return
	}

	// Drop an outcome from an earlier half-open window: counting a stale success
	// could push halfOpenSuccess to the close threshold while the upstream still fails.
	if gen != b.halfOpenGen {
		return
	}

	b.consecutiveFails = 0

	if b.state == StateHalfOpen {
		b.halfOpenSuccess++
		// New clamps HalfOpenMaxProbes to >= 1 (and config is never reassigned), so it
		// is the required number of successes to close from half-open directly.
		if b.halfOpenSuccess >= b.config.HalfOpenMaxProbes {
			b.state = StateClosed
			b.halfOpenProbes = 0
			b.halfOpenSuccess = 0
			// Bump the generation to close the window. Without it, a slower sibling
			// probe from this window (HalfOpenMaxProbes > 1) failing after the close
			// would pass recordFailure's guard (now Closed, gen still matching) and
			// spuriously re-open a healthy breaker; the bump makes it a mismatch.
			b.halfOpenGen++
			b.lastTransitionAt = b.now()
		}
	}
}

// recordDrop releases a half-open probe slot without counting the outcome as
// success or failure, leaving consecutiveFails, the success tally, and the cooldown
// clock untouched. This is the neutral outcome for a client-initiated cancellation.
// Only a live half-open probe holds a slot; outside HalfOpen or for a superseded
// generation there is nothing to release, so those are no-ops.
func (b *Breaker) recordDrop(gen uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state != StateHalfOpen || gen != b.halfOpenGen {
		return
	}
	if b.halfOpenProbes > 0 {
		b.halfOpenProbes--
	}
}

// recordFailure records a failed request reported by a probe admitted under
// generation gen. In closed state it opens the circuit once consecutive failures
// reach the threshold; in half-open state any failure re-opens it. A failure reported
// while already open is counted in the throughput total but otherwise ignored — it
// did not come from an admitted probe, so advancing the cooldown clock could keep the
// breaker open indefinitely under a trickle of out-of-band failures. A failure whose
// gen no longer matches the current half-open window is a stale outcome and is dropped
// (after being counted in the throughput total).
func (b *Breaker) recordFailure(gen uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// totalFailures is observability-only: a throughput counter of every reported
	// failure, including ones the state machine drops below. Do not derive net state
	// from it. Incremented before the guards so the count is independent of the drop
	// path. Mirrors totalSuccesses.
	b.totalFailures++

	// A failure reported while already open did not come from an admitted probe
	// (allow leaves Open before returning true), so it violates the admit-before-record
	// contract. It must not touch the cooldown clock or consecutiveFails: restarting
	// the cooldown on every stray failure would trap the breaker open under a trickle
	// of out-of-band failures.
	if b.state == StateOpen {
		return
	}

	// Drop a stale failure from an earlier half-open window: it must neither re-open
	// the current window nor reset its counters.
	if gen != b.halfOpenGen {
		return
	}

	b.consecutiveFails++
	// Capture the instant once so the cooldown anchor (lastFailureTime) and the
	// reported transition time (lastTransitionAt) are identical for this single trip;
	// two b.now() calls would diverge under a step-advancing test clock.
	now := b.now()
	b.lastFailureTime = now

	switch b.state {
	case StateClosed:
		if b.consecutiveFails >= b.config.FailureThreshold {
			b.state = StateOpen
			b.lastTransitionAt = now
		}
	case StateHalfOpen:
		// Any failure from an admitted half-open probe re-opens the breaker,
		// even if an earlier probe in this window already succeeded.
		b.state = StateOpen
		b.halfOpenSuccess = 0
		// Pin consecutiveFails to FailureThreshold on the re-trip. The ++ above ran in
		// half-open and would otherwise leave it growing as FailureThreshold+k.
		// FailureThreshold satisfies "State==Open implies consecutiveFails>=
		// FailureThreshold", never grows, and needs no read-side Stats() projection.
		b.consecutiveFails = b.config.FailureThreshold
		b.lastTransitionAt = now
	}
}

// projectedState reports the logical state, consecutive-failure count, and last
// transition time, sampling the clock EXACTLY ONCE. While the breaker is physically
// Open but past cooldown it projects HalfOpen with the reset counters, mirroring the
// real transition allow() performs; otherwise it returns the physical fields.
//
// State() and Stats() both route through this so that WITHIN A SINGLE call the
// snapshot is internally consistent (one now() sample backs every field). It does
// NOT extend across calls: a State() then Stats() can straddle the cooldown boundary
// and disagree, so a caller needing both fields to agree should call Stats() once and
// read Stats.State. Must be called under b.mu.RLock (or b.mu.Lock).
func (b *Breaker) projectedState() (state State, consecutiveFails int, lastTransitionAt time.Time) {
	if b.state == StateOpen && b.now().Sub(b.lastFailureTime) >= b.config.CooldownDuration {
		// The projection can run in the gap between cooldown elapsing and the first
		// admitted probe, while b.state is still Open. Report ConsecutiveFails=0 (so
		// the snapshot is never "HalfOpen with FailureThreshold", reading as both
		// recovering and failing) and LastTransitionAt=cooldown-elapsed instant (so a
		// "half-open since" dashboard does not include the whole cooldown).
		return StateHalfOpen, 0, b.lastFailureTime.Add(b.config.CooldownDuration)
	}
	// The HalfOpen->Open re-trip needs no projection: recordFailure already sets
	// consecutiveFails to FailureThreshold, so the invariant holds in the field.
	return b.state, b.consecutiveFails, b.lastTransitionAt
}

// State returns the current circuit breaker state. If the breaker is open
// and the cooldown has elapsed it reports HalfOpen (but does not mutate).
func (b *Breaker) State() State {
	b.mu.RLock()
	defer b.mu.RUnlock()

	state, _, _ := b.projectedState()
	return state
}

// Stats returns circuit breaker statistics. Like State, it reports the
// logical state: when the breaker is open and the cooldown has elapsed it reports
// HalfOpen (without mutating), so Stats().State never contradicts State().
// Both route through projectedState so a single now() sample backs the whole
// snapshot.
func (b *Breaker) Stats() Stats {
	b.mu.RLock()
	defer b.mu.RUnlock()

	state, consecutiveFails, lastTransitionAt := b.projectedState()
	return Stats{
		State:            state,
		ConsecutiveFails: consecutiveFails,
		TotalFailures:    b.totalFailures,
		TotalSuccesses:   b.totalSuccesses,
		LastFailureTime:  b.lastFailureTime,
		LastTransitionAt: lastTransitionAt,
	}
}

// Stats holds circuit breaker statistics.
type Stats struct {
	State            State     `json:"state"`
	ConsecutiveFails int       `json:"consecutiveFails"`
	TotalFailures    int64     `json:"totalFailures"`
	TotalSuccesses   int64     `json:"totalSuccesses"`
	LastFailureTime  time.Time `json:"lastFailureTime,omitempty"`
	LastTransitionAt time.Time `json:"lastTransitionAt,omitempty"`
}

// MarshalJSON omits the two time.Time fields when zero. encoding/json never treats
// a struct (including time.Time) as "empty", so the `omitempty` tags are ignored and
// a zero time would serialize as "0001-01-01T00:00:00Z", misleading dashboards into
// reading a fresh breaker as having last failed in year 1. This marshaler emits each
// time field only when non-zero.
func (s Stats) MarshalJSON() ([]byte, error) { //nolint:gocritic // hugeParam: a value receiver is required so a Stats value (returned by Breaker.Stats) satisfies json.Marshaler; a pointer receiver would not be in a value's method set when passed to json.Marshal
	// alias shares Stats' layout but not its MarshalJSON, breaking the recursion. Its
	// same-named time fields are shadowed by the outer pointer fields below, so the
	// zero times never serialize.
	type alias Stats
	out := struct {
		alias
		LastFailureTime  *time.Time `json:"lastFailureTime,omitempty"`
		LastTransitionAt *time.Time `json:"lastTransitionAt,omitempty"`
	}{alias: alias(s)}
	if !s.LastFailureTime.IsZero() {
		out.LastFailureTime = &s.LastFailureTime
	}
	if !s.LastTransitionAt.IsZero() {
		out.LastTransitionAt = &s.LastTransitionAt
	}
	return json.Marshal(out)
}
