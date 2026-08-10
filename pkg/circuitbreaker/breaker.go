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

// Impeded reports whether a breaker in this state is refusing calls, or has tripped and not
// yet proved recovery. Anything but [StateClosed] counts, including a state this build does
// not recognize.
//
// Half-open is NOT a recovering state: it is entered only from open and closes only once a
// probe SUCCEEDS, so it means "tripped, retry outstanding" — and at the common
// HalfOpenMaxProbes of 1 a probe in flight refuses every other call exactly as open does,
// while a cooldown that merely lapsed with no traffic projects half-open indefinitely.
// Reading only [StateOpen] therefore goes quiet for most of a sustained outage.
//
// It lives beside the state machine rather than in each consumer's health endpoint because
// what the states MEAN is this package's to define: a consumer encoding the predicate itself
// got exactly the half-open case wrong, and could only fix and test it by standing up its own
// server.
func (s State) Impeded() bool { return s != StateClosed }

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
// Contract: each admitted probe must be followed by exactly one outcome (success, failure,
// or drop), even at the default HalfOpenMaxProbes of 1 — a probe that never reports wedges
// the breaker in half-open indefinitely. [Do] honors this even when the guarded call panics.
//
// Concurrency: the probe returned by allowProbe is generation-aware, so a late outcome from
// a reopened half-open window is dropped rather than misapplied (closing on a stale success).
type Breaker struct {
	config Config

	mu               sync.RWMutex
	state            State
	consecutiveFails int
	lastFailureTime  time.Time
	halfOpenProbes   int
	halfOpenSuccess  int
	// halfOpenGen identifies the current half-open window, so a late outcome from an
	// ended window is dropped rather than counted toward the new state. Bumped at
	// Open->HalfOpen and HalfOpen->Closed; the HalfOpen->Open re-trip does NOT bump it,
	// since recordFailure/recordSuccess already discard stale outcomes while Open.
	halfOpenGen      uint64
	lastTransitionAt time.Time
	totalFailures    int64
	totalSuccesses   int64

	now func() time.Time
}

// probe is the outcome handle for one admitted request, returned by allowProbe. It records
// the half-open generation it was admitted under so a late outcome from a reopened window
// is dropped. The zero probe (admission refused) is inert.
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

// drop releases the probe's reserved half-open slot without counting success or failure,
// for an outcome that says nothing about upstream health (e.g. client cancellation).
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

// New creates a new circuit breaker. A non-positive field is replaced by its DefaultConfig
// value to stay fail-safe (a degenerate config would otherwise trip on the first failure,
// give no back-pressure, or admit no probes), so New never fails.
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

// allowProbe returns whether the breaker permits a request — always closed, only past
// cooldown when open, up to HalfOpenMaxProbes when half-open — with a probe bound to the
// current generation. Refused admission returns (false, zero probe). This is the path [Do] uses.
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
		// Stamps the current generation but reserves NO half-open slot. If the breaker
		// concurrently trips before this probe reports, the stale-generation guard drops
		// it harmlessly (the totals still count, incremented before the guard).
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
			// Record the LOGICAL transition instant (when cooldown elapsed), not the later
			// first-probe `now`, so a "time in half-open" dashboard sees no spurious jump.
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
// generation gen. In half-open state the breaker closes only once HalfOpenMaxProbes have
// succeeded; a gen mismatch marks a stale outcome from an ended window and is dropped.
func (b *Breaker) recordSuccess(gen uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// totalSuccesses is observability-only, counting every reported success including
	// ones dropped below; do not derive net state from it. Mirrors totalFailures.
	b.totalSuccesses++

	// A success reported while Open did not come from an admitted probe. Ignore it,
	// symmetric to recordFailure, so it cannot zero consecutiveFails spuriously.
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
			// Bump the generation: without it, a slower sibling probe from this window
			// failing after the close would pass recordFailure's guard and re-open spuriously.
			b.halfOpenGen++
			b.lastTransitionAt = b.now()
		}
	}
}

// recordDrop releases a half-open probe slot without counting success or failure, leaving
// consecutiveFails, the success tally, and the cooldown clock untouched. Only a live
// half-open probe holds a slot; outside HalfOpen or a superseded generation it's a no-op.
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

// recordFailure records a failed request reported by a probe admitted under generation
// gen. In closed state it opens the circuit at the failure threshold; in half-open, any
// failure re-opens it. A failure while already open, or from a stale generation, is
// counted in the throughput total but otherwise dropped.
func (b *Breaker) recordFailure(gen uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// totalFailures is observability-only, counting every reported failure including
	// ones dropped below; do not derive net state from it. Mirrors totalSuccesses.
	b.totalFailures++

	// A failure reported while already open did not come from an admitted probe, and
	// must not touch the cooldown clock: restarting it on every stray failure could trap
	// the breaker open under a trickle of out-of-band failures.
	if b.state == StateOpen {
		return
	}

	// Drop a stale failure from an earlier half-open window: it must neither re-open
	// the current window nor reset its counters.
	if gen != b.halfOpenGen {
		return
	}

	b.consecutiveFails++
	// Capture the instant once so lastFailureTime and lastTransitionAt agree for this
	// trip; two b.now() calls would diverge under a step-advancing test clock.
	now := b.now()
	b.lastFailureTime = now

	switch b.state {
	case StateClosed:
		if b.consecutiveFails >= b.config.FailureThreshold {
			b.state = StateOpen
			b.lastTransitionAt = now
		}
	case StateHalfOpen:
		// Any failure from an admitted half-open probe re-opens the breaker, even if an
		// earlier probe in this window already succeeded.
		b.state = StateOpen
		b.halfOpenSuccess = 0
		// Pin to FailureThreshold on the re-trip (the ++ above would otherwise leave it
		// growing as FailureThreshold+k), satisfying "Open implies >= FailureThreshold".
		b.consecutiveFails = b.config.FailureThreshold
		b.lastTransitionAt = now
	}
}

// projectedState reports the logical state, consecutive-failure count, and last
// transition time, sampling the clock EXACTLY ONCE. While physically Open but past
// cooldown it projects HalfOpen with reset counters, mirroring allow()'s real transition.
//
// State() and Stats() both route through this so a single call's snapshot is internally
// consistent; it does NOT extend across calls — a caller needing both fields to agree
// should call Stats() once. Must be called under at least b.mu.RLock.
func (b *Breaker) projectedState() (state State, consecutiveFails int, lastTransitionAt time.Time) {
	if b.state == StateOpen && b.now().Sub(b.lastFailureTime) >= b.config.CooldownDuration {
		// The gap between cooldown elapsing and the first admitted probe: report
		// ConsecutiveFails=0 (not "HalfOpen with FailureThreshold") and the
		// cooldown-elapsed instant (so a "half-open since" dashboard excludes the cooldown).
		return StateHalfOpen, 0, b.lastFailureTime.Add(b.config.CooldownDuration)
	}
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

// MarshalJSON omits the two time.Time fields when zero: encoding/json never treats a
// struct as "empty", so `omitempty` is ignored and a zero time would serialize as
// "0001-01-01T00:00:00Z", misleading a dashboard into reading a fresh breaker as failed in year 1.
func (s Stats) MarshalJSON() ([]byte, error) { //nolint:gocritic // hugeParam: a value receiver is required so a Stats value (returned by Breaker.Stats) satisfies json.Marshaler; a pointer receiver would not be in a value's method set when passed to json.Marshal
	// alias shares Stats' layout but not its MarshalJSON, breaking the recursion.
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
