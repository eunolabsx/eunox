// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package killswitch

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	redisGlobalKey   = "killswitch:global"
	redisAgentPrefix = "killswitch:agent:"
	redisSessionPfx  = "killswitch:session:"
	redisPubSubChan  = "killswitch:events"

	// defaultReconcileInterval is how often the local cache is fully refreshed from
	// Redis, independent of pub/sub. Pub/sub is at-most-once, so a kill event lost
	// during a brief disconnect would never be observed without this; it also
	// re-converges a replica that started degraded (Redis unreachable at boot) and
	// bounds how long degraded mode persists after recovery.
	defaultReconcileInterval = 30 * time.Second

	// defaultSessionKillTTL bounds how long a SESSION kill tombstone lives in Redis.
	//
	// Session ids are ephemeral -- one MCP connection, bounded by the idle reaper and the
	// proxy's own lifetime -- but their tombstones were written with no expiry, so a
	// long-running deployment accumulated one dead key per killed session forever, with
	// nothing to ever collect them. That is unbounded Redis memory growth, and every
	// reconcile SCAN pays for it.
	//
	// This is a garbage-collection bound, NOT a policy expiry, and the default is chosen
	// to make that distinction safe: 30 days is orders of magnitude longer than any
	// session can live, so a tombstone can only expire long after the session it names is
	// gone. Note the direction of the risk if it were set too low -- an expiring tombstone
	// LIFTS the kill -- so a value shorter than the longest session a deployment can hold
	// open would be a fail-open. AGENT kills are deliberately NOT expired: an agent
	// identity is long-lived and its revocation is meant to be durable.
	defaultSessionKillTTL = 30 * 24 * time.Hour
)

// DefaultSessionKillTTL is the exported form of the default session-tombstone lifetime,
// so the binary's startup banner can state the effective value rather than restating the
// number and drifting from it.
const DefaultSessionKillTTL = defaultSessionKillTTL

// subscribeConfirmTimeout bounds the initial pub/sub subscription-confirmation read in
// Start. pubsub.Receive issues a deadline-less socket read (go-redis passes timeout=0),
// so a blackholed or half-open connection -- the TCP dial and SUBSCRIBE write are
// accepted but the confirmation never arrives -- would block Start forever. Start holds
// lifeMu across that call and Stop must take lifeMu to reach r.cancel, so an unbounded
// block deadlocks a concurrent Stop (the cancel that could unblock the read is itself
// unreachable). Bounding the confirmation read funnels a hung subscribe into the same
// retried, reconcile-only degraded mode as an outright subscribe error. A var, not a
// const, only so the deadlock regression test can shrink it; production never mutates it.
var subscribeConfirmTimeout = 5 * time.Second

// subscribeRetryInitialDelay and subscribeRetryMaxDelay bound the background
// resubscribe backoff. Because subscribeConfirmTimeout is a hard cutoff, a
// slow-but-healthy Redis -- a failover, a load spike, a saturated link -- can miss the
// confirmation deadline without being down. Without a retry that instance would run
// reconcile-only for its entire lifetime, stretching kill propagation from
// milliseconds to a full reconcile interval until someone restarted the process. The
// backoff keeps a genuinely unreachable backend from being hammered. Vars, not consts,
// only so tests can shrink them; production never mutates them.
var (
	subscribeRetryInitialDelay = 1 * time.Second
	subscribeRetryMaxDelay     = 30 * time.Second
)

// pubSubClient is the optional Subscribe facet of the Redis client. redis.Cmdable
// does not include Subscribe (a limited Cmdable or a test fake may omit it), so the
// capability is detected by assertion and the subscription path is skipped when it is
// absent.
type pubSubClient interface {
	Subscribe(ctx context.Context, channels ...string) *redis.PubSub
}

// ErrBackendUnreachable is returned by ShouldBlock in the default fail-closed
// degraded mode when the most recent Redis refresh failed, so the cache may be
// stale; the caller treats it as a denial. The underlying Redis error is NOT
// wrapped so backend connection details do not leak into a client-facing message;
// operators read the real error from HealthStatus().
var ErrBackendUnreachable = errors.New("killswitch: redis backend unreachable; failing closed (kill-switch state cannot be confirmed)")

// ErrNotStarted is returned by ShouldBlock before Start has loaded the initial
// kill-switch state. The local cache has never been seeded from Redis, so the
// switch cannot tell "nothing is killed" from "state never loaded": it fails closed
// (the caller treats it as a denial) rather than admit every request as a silent
// no-op. Unlike ErrBackendUnreachable this is a WIRING error, not a transient
// outage, so it fails closed regardless of WithFailOpen — an unstarted kill switch
// is never an all-clear.
var ErrNotStarted = errors.New("killswitch: redis kill switch queried before Start(); failing closed (state never loaded)")

// ErrStopped is returned by ShouldBlock on a non-match after the Start context has
// been canceled and the reconcile/pub-sub loops have exited. The cache can no longer
// converge, so a non-match is unconfirmed. Like ErrNotStarted this is a liveness
// (not transient-outage) condition, so it fails closed regardless of WithFailOpen —
// a frozen kill switch must never be a silent all-clear.
var ErrStopped = errors.New("killswitch: redis kill switch convergence stopped (Start context canceled); failing closed (state can no longer be confirmed)")

// Redis is a Redis-backed kill-switch manager with pub/sub propagation and local cache.
type Redis struct {
	client redis.Cmdable
	logger *slog.Logger

	// refreshMu serializes refreshState so two refreshes cannot overlap. Their
	// snapshots are built lock-free (outside mu, so ShouldBlock is never stalled on
	// Redis I/O), and the commit is guarded only by cacheGen against a racing cache
	// MUTATION -- but two concurrent refreshes capture the same cacheGen and neither
	// commit bumps it, so an OLDER scan could commit after (and overwrite) a NEWER
	// one, erasing a kill until the next reconcile tick. Serializing here makes
	// commits land in scan order. Distinct from mu on purpose: the scan must stay
	// off the hot-path lock.
	refreshMu sync.Mutex

	// Local cache for fast reads (refreshed via pub/sub and the reconcile loop).
	mu             sync.RWMutex
	globalActive   bool
	killedAgents   map[string]bool
	killedSessions map[string]bool
	lastRefreshErr error // last refresh error; nil means healthy
	// lastRefreshOK is when a refresh last CONFIRMED state against Redis. It exists
	// because lastRefreshErr is edge-triggered: it is only set once a refresh has run
	// AND failed. If Redis partitions immediately after a successful refresh, no refresh
	// has failed yet, so lastRefreshErr stays nil and — in fail-CLOSED mode, whose whole
	// promise is that an unconfirmable request is denied — every non-match was served
	// `false, nil` from a cache that could no longer see a new kill. Pub/sub is down
	// during the same partition, so a kill issued via a reachable replica was invisible
	// for the entire window; a wedged reconcile loop made it indefinite. Gating on
	// staleness makes the fail-closed guarantee time-bounded rather than
	// failure-detection-bounded. Zero means no refresh has ever succeeded.
	lastRefreshOK time.Time
	// cacheGen is bumped under mu on every local-cache mutation. refreshState
	// captures it before its lock-free Redis scan and only commits the snapshot if it
	// is unchanged; otherwise a kill applied during the scan would be erased by the
	// stale snapshot, failing open until the next reconcile.
	cacheGen uint64
	// reconcileErrLogged is true once a background-refresh failure has been logged,
	// so a sustained outage does not warn on every tick. Reset on recovery. Distinct
	// from lastRefreshErr (the authoritative health signal); this only throttles the
	// operator log breadcrumb.
	reconcileErrLogged bool

	reconcileInterval time.Duration

	// sessionKillTTL is how long a session-kill tombstone lives; see
	// defaultSessionKillTTL. Zero means no expiry.
	sessionKillTTL time.Duration

	// now is the clock used for the staleness gate, injectable for deterministic tests.
	// nil means time.Now.
	now func() time.Time

	// failOpen selects the degraded-mode behaviour when Redis is unreachable. The
	// zero value (default) is fail-CLOSED: ShouldBlock denies because a kill issued
	// during the outage cannot be confirmed. WithFailOpen(true) instead serves the
	// last-known cache for availability. See ADR-0003.
	failOpen bool

	cancel context.CancelFunc

	// refreshTrigger decouples the pub/sub listener from the full Redis SCAN a reset
	// or unknown event requires: handlePubSubMessage does a non-blocking send instead
	// of running the scan inline, and drainRefreshTrigger consumes it. The 1-element
	// buffer coalesces a burst of events into at most one pending scan, so the single
	// listener never blocks on N sequential SCANs. Created in Start, torn down via
	// subCtx.
	refreshTrigger chan struct{}

	// lifeMu serializes the whole Start body against Stop. It is SEPARATE from mu (the
	// hot-path cache lock) because Start holds it across the initial refreshState
	// network round-trip, during which mu must stay free. Holding it across Start
	// orders every wg.Add before a concurrent Stop's wg.Wait, so Wait cannot return on
	// a still-zero counter mid-refresh. stopped (under lifeMu) makes a Start that
	// loses the race to Stop a no-op.
	lifeMu  sync.Mutex
	stopped bool

	// startedOnce guards Start (under lifeMu, alongside stopped) so the listener and
	// reconcile loop launch at most once; a second Start would otherwise overwrite
	// r.cancel, orphan the first goroutines beyond Stop's reach, and run duplicate
	// loops. A bool under the lock lifeMu already holds across the whole Start body,
	// rather than a separate sync.Once, keeps the lifecycle guarded by one mechanism.
	startedOnce bool

	// runCtx is the Start-derived context that governs the reconcile/pub-sub loops
	// (subCtx). It is set once under mu in Start and read by ShouldBlock: once it is
	// canceled (via Stop or the caller's own context) the loops exit and the cache can
	// no longer track new kills, so ShouldBlock must fail closed on a non-match rather
	// than serve the stale all-clear — otherwise a Start context that outlives neither
	// the instance nor its ShouldBlock callers (an ordinary run-/request-scoped context)
	// would silently turn the switch into a permanent no-op. Reading runCtx.Err()
	// derives liveness straight from the context that already encodes it, so cancellation
	// is observed synchronously with no window (unlike a separate flag latched by a
	// context.AfterFunc goroutine, which trails cancellation). nil before Start, at which
	// point the started guard already fails closed.
	runCtx context.Context
	// started is set true once Start has run its initial state load. Until then the
	// local cache has never been seeded from Redis, so ShouldBlock cannot distinguish
	// "nothing is killed" from "state never loaded": it fails closed (ErrNotStarted)
	// rather than admit every request as a silent no-op. A wiring guard, not a
	// runtime-outage signal (that is lastRefreshErr/failOpen), so it fails closed even
	// in fail-open mode — an unstarted kill switch must never be a no-op.
	started atomic.Bool

	// wg tracks the background goroutines so Stop can block until they exit; without
	// it Stop's cancel() returns while a goroutine is still touching shared state,
	// racing a caller that frees the client or logger.
	wg sync.WaitGroup
}

// RedisOption configures the Redis kill-switch manager at construction.
//
// Configuration is applied here rather than through chained setters on a live
// instance because every field below is read by ShouldBlock and the background
// loops WITHOUT synchronization. As post-construction setters their "must be called
// before Start" contract was enforceable only by doc comment, so a caller who
// reordered a chain past Start raced the loops with nothing to catch it. Threading
// them through NewRedis makes the contract structural: the options run before the
// constructor returns, so there is no instance to misconfigure later. Mirrors the
// option shape pkg/callcounter, pkg/flowlabelstore, and pkg/circuitbreaker use.
type RedisOption func(*Redis)

// WithSessionKillTTL overrides how long a session-kill tombstone lives in Redis. A
// negative value disables expiry (tombstones live forever, the pre-existing behavior);
// zero selects the default.
//
// Raise it only if sessions in your deployment can outlive the default; LOWERING it below
// the longest session you can hold open is a fail-open, because an expiring tombstone
// lifts the kill on a session that may still be connected. Agent kills are never expired.
func WithSessionKillTTL(d time.Duration) RedisOption {
	return func(r *Redis) {
		switch {
		case d < 0:
			r.sessionKillTTL = 0 // explicit opt-out: never expire
		case d == 0:
			r.sessionKillTTL = defaultSessionKillTTL
		default:
			r.sessionKillTTL = d
		}
	}
}

// WithReconcileInterval overrides how often the local cache is fully refreshed from
// Redis independent of pub/sub. A non-positive value restores the default. It bounds
// both the kill-propagation window and, in fail-closed mode, the denial window that
// persists after a transient outage recovers. Lower values increase Redis load.
func WithReconcileInterval(d time.Duration) RedisOption {
	return func(r *Redis) {
		if d <= 0 {
			d = defaultReconcileInterval
		}
		r.reconcileInterval = d
	}
}

// WithLogger sets a structured logger on the kill-switch for operational visibility.
// If set, initial state-refresh failures are logged as warnings rather than silently dropped.
func WithLogger(logger *slog.Logger) RedisOption {
	return func(r *Redis) {
		r.logger = logger
	}
}

// WithFailOpen selects the degraded-mode behaviour when Redis is unreachable.
//
// The default (false) is fail-CLOSED: while the most recent refresh has failed,
// ShouldBlock denies every request, honouring the emergency stop even when its
// backend is partitioned, at the cost of blocking the data plane until Redis health
// is reconfirmed (at the latest on the next reconcile tick).
//
// WithFailOpen(true) is availability-first: ShouldBlock serves the last-known cache
// during an outage. Choose it only where availability outweighs a bounded window in
// which a revocation may be delayed, and Redis HA is in place. See ADR-0003.
func WithFailOpen(failOpen bool) RedisOption {
	return func(r *Redis) {
		r.failOpen = failOpen
	}
}

// NewRedis creates a Redis-backed kill-switch manager.
// It subscribes to a pub/sub channel for real-time state propagation.
//
// Every setting is supplied here (see RedisOption); the instance is fully configured
// by the time it is returned, so no caller can mutate state the background loops
// read once Start is running.
func NewRedis(client redis.Cmdable, opts ...RedisOption) *Redis {
	r := &Redis{
		client:            client,
		killedAgents:      make(map[string]bool),
		killedSessions:    make(map[string]bool),
		reconcileInterval: defaultReconcileInterval,
		sessionKillTTL:    defaultSessionKillTTL,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Start begins the pub/sub subscription for state synchronization. Call once at
// startup. It is idempotent: repeated calls launch the listener and reconcile loop
// only once (a second call would otherwise overwrite r.cancel, leak the first
// goroutines, and run duplicate loops).
func (r *Redis) Start(ctx context.Context) {
	// Hold lifeMu across the whole Start body so a concurrent Stop blocks until cancel
	// is published, the initial refresh completes, and both goroutines are registered.
	// This orders every wg.Add before a concurrent Stop's wg.Wait.
	r.lifeMu.Lock()
	defer r.lifeMu.Unlock()
	// Start at most once. If Stop already ran, do not start either: launching
	// goroutines now would orphan them beyond Stop's reach and use the client after
	// Stop promised teardown was safe.
	if r.startedOnce || r.stopped {
		return
	}
	r.startedOnce = true

	subCtx, cancel := context.WithCancel(ctx)
	// Write cancel/runCtx/refreshTrigger under r.mu so handlePubSubMessage and
	// ShouldBlock, which read them under the same lock, have a consistent view. The
	// channel is always non-nil by the time a send is attempted.
	r.mu.Lock()
	r.cancel = cancel
	r.runCtx = subCtx
	r.refreshTrigger = make(chan struct{}, 1)
	r.mu.Unlock()

	// Subscribe BEFORE the initial snapshot, and confirm the subscription is
	// active first. If the snapshot ran first, a kill published in the window
	// between its final read and an active subscription would reach neither the
	// committed cache nor any subscriber, leaving the subject permitted until the
	// next reconcile. Subscribing first means any handoff-window event is either
	// delivered (bumping cacheGen, forcing the in-flight refreshState to re-read)
	// or captured by the snapshot.
	if sub, ok := r.client.(pubSubClient); ok {
		pubsub, err := r.subscribeConfirmed(subCtx, sub)
		if err != nil {
			if r.logger != nil {
				// Degraded, but NOT for the process's lifetime: resubscribeLoop keeps
				// retrying in the background, so say what converges state meanwhile and
				// that the real-time path can come back on its own.
				r.logger.Warn("kill switch: pub/sub subscription could not be confirmed; converging state on the periodic reconcile only while the subscription is retried in the background",
					slog.String("error", err.Error()))
			}
			// Retry off the Start goroutine: Start holds lifeMu, so blocking here to
			// retry would extend the window in which a concurrent Stop cannot reach
			// r.cancel -- the very deadlock subscribeConfirmTimeout exists to bound.
			// Registering the goroutine under lifeMu keeps this wg.Add ordered before a
			// concurrent Stop's wg.Wait, as for the loops below.
			r.wg.Add(1)
			go func() {
				defer r.wg.Done()
				r.resubscribeLoop(subCtx, sub)
			}()
		} else {
			r.wg.Add(1)
			go func() {
				defer r.wg.Done()
				r.supervisePubSub(subCtx, sub, pubsub)
			}()
		}
	} else if r.logger != nil {
		// The client does not implement Subscribe (e.g. a minimal fake or a limited
		// Cmdable), so real-time pub/sub propagation is unavailable and kill events will
		// only converge on the periodic reconcile tick. Surface it so a degraded
		// propagation path is not silent, mirroring the pub/sub-failure warning above.
		r.logger.Warn("kill switch: redis client does not support pub/sub; kill events will propagate on the periodic reconcile only",
			slog.String("clientType", fmt.Sprintf("%T", r.client)),
			slog.Duration("reconcileInterval", r.reconcileInterval))
	}

	// Load initial state. On failure (logged as a warning) the switch starts
	// degraded — BLOCKING in fail-closed mode, allowing the empty cache in
	// fail-open — and self-corrects on the next event or reconcile tick.
	if err := r.refreshState(subCtx); err != nil {
		if r.logger != nil {
			mode := "blocking all traffic until Redis is reachable (fail-closed)"
			if r.failOpen {
				mode = "allowing traffic from the last-known cache (fail-open)"
			}
			r.logger.Warn("kill switch: initial state refresh failed; starting degraded: "+mode,
				slog.String("error", err.Error()))
		}
	}

	// Mark started now that the initial state load has been ATTEMPTED. From here
	// ShouldBlock trusts the cache; a refresh failure is governed by
	// lastRefreshErr/failOpen, not the unstarted guard. Set AFTER refreshState so no
	// request is ever admitted against an unseeded cache during the initial load.
	r.started.Store(true)
	// The loops below keep the cache converging while subCtx is live; once it is
	// canceled (Stop, or the caller's context) ShouldBlock reads runCtx.Err() and fails
	// closed on a non-match instead of serving a cache that can no longer track new kills.

	// Periodic reconciliation: re-reads authoritative Redis state on a fixed
	// interval so a kill missed by at-most-once pub/sub (or a fail-open cold start)
	// self-heals within one interval.
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.reconcileLoop(subCtx)
	}()

	// Drain the refresh trigger: runs the SCAN for reset/unknown events off the
	// listener goroutine so it never blocks on Redis I/O.
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.drainRefreshTrigger(subCtx)
	}()
}

// reconcileLoop periodically refreshes the local cache from Redis so that kill
// events lost by pub/sub, and fail-open state from a cold start during a Redis
// outage, converge to the authoritative Redis state within one interval.
func (r *Redis) reconcileLoop(ctx context.Context) {
	interval := r.reconcileInterval
	if interval <= 0 {
		interval = defaultReconcileInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.reconcileRefresh(ctx)
		}
	}
}

// drainRefreshTrigger consumes the coalescing refreshTrigger channel and runs a
// full reconcileRefresh per signal. Moving the SCAN off the listener goroutine keeps
// real-time kill events flowing during a reset/unknown-triggered scan; the 1-element
// buffer coalesces a burst into one scan. It exits when ctx is cancelled (Stop).
func (r *Redis) drainRefreshTrigger(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.refreshTrigger:
			// r.client is always set by NewRedis, so no nil guard is needed.
			r.reconcileRefresh(ctx)
		}
	}
}

// reconcileRefresh runs a background state refresh (a reconcile tick or pub/sub
// resync) and logs edge-triggered: one warning on healthy->failing and a notice on
// recovery, so a sustained outage does not log every tick. HealthStatus() remains
// the authoritative health signal; this is the operator breadcrumb. A refresh error
// is otherwise non-fatal (fail-closed denies, fail-open serves the cache; ADR-0003).
func (r *Redis) reconcileRefresh(ctx context.Context) {
	_ = r.refreshState(ctx)
	if r.logger == nil {
		return
	}
	// Decide the log edge from the committed lastRefreshErr (under the lock guarding
	// reconcileErrLogged), not this call's local result: the ticker and a pub/sub
	// resync can call this concurrently, and reading committed state keeps the
	// breadcrumb consistent when their refreshes interleave.
	r.mu.Lock()
	lastErr := r.lastRefreshErr
	wasLogged := r.reconcileErrLogged
	r.reconcileErrLogged = lastErr != nil
	r.mu.Unlock()
	switch {
	case lastErr != nil && !wasLogged:
		degraded := "denying all requests until Redis recovers (fail-closed)"
		if r.failOpen {
			degraded = "serving last-known local cache until Redis recovers (fail-open)"
		}
		r.logger.Warn("kill switch: background state refresh from Redis failed; "+degraded,
			slog.String("error", lastErr.Error()))
	case lastErr == nil && wasLogged:
		r.logger.Info("kill switch: background state refresh from Redis recovered; local cache reconciled")
	}
}

// Stop cancels the pub/sub subscription and blocks until all background goroutines
// have exited, so a caller may free the Redis client or logger once Stop returns
// without racing an in-flight refresh. Stop before, concurrently with, or after
// Start, from any goroutine, is safe: lifeMu serializes it against the whole Start
// body, so a racing Stop either blocks until Start has registered both goroutines or
// wins the race and marks the switch stopped (making the Start body a no-op).
func (r *Redis) Stop() {
	// Take lifeMu to order against the whole Start body: setting stopped makes a
	// not-yet-started Start a no-op, and because Start holds lifeMu across its wg.Add
	// calls, those Adds happen-before the wg.Wait below (closing the zero-counter
	// race).
	r.lifeMu.Lock()
	r.stopped = true
	cancel := r.cancel
	r.lifeMu.Unlock()
	if cancel != nil {
		cancel()
	}
	// Wait after cancelling so both goroutines return before the caller tears down
	// shared state.
	r.wg.Wait()
}

// HealthStatus returns the error from the most recent state refresh, or nil if it
// succeeded. It is the public health-probe API; embedders poll it to tell healthy
// from degraded without an extra refreshState round-trip.
//
// By default the kill switch fails CLOSED on an outage (ShouldBlock denies anything
// not known killed, since a kill issued during the partition cannot be confirmed);
// WithFailOpen instead serves the last-known cache. Either way a kill issued during
// the outage is observed once Redis recovers, at the latest on the next reconcile tick.
func (r *Redis) HealthStatus() error {
	// Mirror ShouldBlock's gate ORDER exactly (not-started, then stopped, then the
	// refresh error) so a health probe and the data plane never disagree about
	// whether the switch is serving. Checked before r.mu so an unstarted switch --
	// whose runCtx/lastRefreshErr are still zero -- reports the wiring cause instead
	// of a nil "healthy". A switch that is constructed but never Started denies 100%
	// of enforced traffic (ShouldBlock returns ErrNotStarted); reporting nil here
	// would publish status "ok" through a total data-plane outage.
	if !r.started.Load() {
		return ErrNotStarted
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	switch r.livenessLocked() {
	case killStopped:
		// A stopped switch can no longer converge, so report the liveness cause rather
		// than the stale refresh error the final in-flight refresh latched as Stop
		// canceled it (context.Canceled) — a permanently frozen switch, not a transient
		// backend outage.
		return ErrStopped
	case killRefreshFailed:
		// The RAW error, unlike ShouldBlock's sanitized sentinel: this is the operator's
		// channel, and connection detail is what makes it actionable.
		return r.lastRefreshErr
	case killStale:
		// No refresh has failed, but none has succeeded recently either — the reconcile
		// loop is not converging. In fail-closed mode the data plane is already denying
		// on this, so a probe reporting "ok" here would publish healthy through an
		// outage.
		return fmt.Errorf("killswitch: no successful redis refresh in over %s; the reconcile loop is not converging and cached kill state cannot be confirmed", r.staleness())
	case killLive:
	}
	return nil
}

// ShouldBlock checks if any kill switch is active, using the local cache first.
//
// A kill present in the cache blocks unconditionally, even while Redis is degraded.
// Only when nothing matches does degraded mode matter: fail-closed denies
// (ErrBackendUnreachable) rather than admit an unconfirmed request; fail-open serves
// the cache. See ADR-0003.
func (r *Redis) ShouldBlock(_ context.Context, agentID, sessionID string) (bool, error) {
	// Fail closed until Start has seeded the cache. An unstarted switch has an empty
	// cache and a nil lastRefreshErr — indistinguishable from an all-clear — so
	// without this guard a NewRedis wired into the enforcement path but never Started
	// would be a silent no-op, ignoring every KillAgent/KillSession/ActivateGlobal in
	// Redis. A wiring error, not a runtime outage, so it fails closed even under
	// WithFailOpen.
	if !r.started.Load() {
		return false, ErrNotStarted
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.globalActive {
		return true, nil
	}
	if agentID != "" && r.killedAgents[agentID] {
		return true, nil
	}
	if sessionID != "" && r.killedSessions[sessionID] {
		return true, nil
	}
	// Nothing matches, so the cache's confidence decides. livenessLocked defines that
	// chain once (shared with HealthStatus); this maps it to the client-facing sentinels.
	switch r.livenessLocked() {
	case killStopped:
		// Fail closed regardless of failOpen — a stopped switch is a liveness failure,
		// not a transient outage that will self-heal.
		return false, ErrStopped
	case killRefreshFailed, killStale:
		// killRefreshFailed: the last refresh ran and failed, so the cache may be stale.
		// killStale: no refresh has FAILED, but detection is edge-triggered — a partition
		// beginning right after a successful refresh leaves lastRefreshErr nil until a
		// reconcile tick actually runs and errors, and pub/sub is down for the same
		// partition, so a kill issued through a reachable replica would be invisible for
		// that whole window while fail-closed mode promises the opposite.
		//
		// Fail-open deliberately serves the cache in both cases: trading guaranteed
		// revocation for availability is exactly what it opts into.
		if !r.failOpen {
			return false, ErrBackendUnreachable
		}
	case killLive:
	}
	return false, nil
}

// killLiveness classifies why a NON-MATCH cannot be served as a confident all-clear.
// It is the single definition of that gate chain, shared by the data plane
// (ShouldBlock) and the health probe (HealthStatus) so the two cannot disagree about
// whether the switch is serving.
//
// The two callers deliberately differ in the ERROR VALUE they map each state to — the
// data plane returns sanitized sentinels so backend connection details never reach a
// client, the health probe returns the raw refresh error for the operator — but the
// ORDER and the set of states are defined once, here. Hand-mirroring them is how a
// fourth state (staleness) ended up gating the data plane while a probe still reported
// "ok" through it.
type killLiveness int

const (
	killLive          killLiveness = iota // cache is confirmed and converging
	killStopped                           // Start context canceled; can never converge again
	killRefreshFailed                     // last refresh ran and failed
	killStale                             // no refresh has failed, but none has succeeded recently either
)

// livenessLocked classifies the cache's confidence. Caller must hold at least mu.RLock.
// The not-started case is deliberately NOT here: r.started is atomic and both callers
// check it before taking mu, so an unstarted switch reports its wiring cause without
// touching zero-valued fields.
func (r *Redis) livenessLocked() killLiveness {
	// Liveness before transient health: once the Start context is canceled the
	// convergence loops have exited and a non-match is PERMANENTLY unconfirmed, which is
	// a different (and more actionable) cause than a transient outage. Stop cancels
	// runCtx and an in-flight refresh then latches context.Canceled as lastRefreshErr, so
	// a stopped switch is frequently ALSO "degraded"; this ordering reports the real one.
	if r.runCtx != nil && r.runCtx.Err() != nil {
		return killStopped
	}
	if r.lastRefreshErr != nil {
		return killRefreshFailed
	}
	if r.staleLocked() {
		return killStale
	}
	return killLive
}

// clock returns the injected clock or time.Now.
func (r *Redis) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// maxRefreshCycleBudget is how long one healthy refresh cycle may plausibly take
// end-to-end: a GET plus two SCAN loops, each a series of round trips bounded only by the
// caller-supplied client's own timeouts, and the whole thing retried up to
// maxRefreshAttempts times when a concurrent kill keeps racing the scan. None of that is
// a fault, and none of it is proportional to the reconcile interval.
//
// It exists because the staleness budget gates a TOTAL, non-downgradable denial (in the
// default fail-closed mode a stale cache denies every request, even under --audit). A bare
// multiple of the reconcile interval makes that denial MORE likely the lower the interval
// goes — and lowering it is exactly what the flag's own help text recommends for faster
// kill propagation, so tuning for responsiveness could take the data plane down against a
// perfectly healthy Redis.
const maxRefreshCycleBudget = 30 * time.Second

// staleness returns how old a confirmed refresh may be before the cache is treated as
// unconfirmed. Two reconcile intervals: one missed tick is ordinary jitter, two means the
// convergence loop is not running or Redis is not answering.
//
// Floored at one interval plus a realistic refresh-cycle budget, because the stamp is set
// when a refresh COMPLETES: the next tick fires an interval later and then takes up to a
// cycle to finish, so the age at the moment of the next successful stamp is legitimately
// interval + cycle even when nothing is wrong. At the default 30s interval the floor and
// the multiple coincide exactly (60s), so only a lowered interval sees any change.
//
// The floor is a TRADE, and it runs against revocation latency in the one case the
// staleness gate is the sole detector: a refresh that HANGS rather than errors (a
// blackholed or half-open connection). An outright failure latches lastRefreshErr and
// livenessLocked reports killRefreshFailed before ever consulting staleness, so only the
// hang reaches here. For that case an operator who set --killswitch-reconcile-interval to
// 1s now serves the last-known cache for ~31s instead of ~2s before failing closed, so a
// kill issued elsewhere during the hang goes unenforced for that much longer.
//
// It is still the right default: without the floor, the same operator's HEALTHY Redis was
// judged stale whenever one ordinary refresh cycle outran two intervals, and fail-closed
// mode then denied ALL traffic — a certain, self-inflicted outage traded against a longer
// window on a rare failure mode. Tuning the interval down for faster kill PROPAGATION
// (the pub/sub-miss reconvergence the flag's help describes) still works exactly as
// documented; it is only this hang-detection window that no longer shrinks with it.
func (r *Redis) staleness() time.Duration {
	iv := r.reconcileInterval
	if iv <= 0 {
		iv = defaultReconcileInterval
	}
	budget := max(2*iv, iv+maxRefreshCycleBudget)
	if budget <= 0 {
		// Both terms overflowed int64 (an absurd interval near the duration ceiling). A
		// negative budget makes staleLocked true forever, which in fail-closed mode denies
		// every request against a perfectly healthy backend — fail back to the floor
		// rather than to a total outage.
		return maxRefreshCycleBudget
	}
	return budget
}

// staleLocked reports whether the cache has gone too long without a confirmed refresh.
// Caller must hold at least a read lock on mu.
//
// A zero lastRefreshOK means no refresh has ever succeeded. That is NOT reported as stale
// here: Start seeds the cache before started is set, so reaching this point with a zero
// stamp means the seed itself came from a path that did not stamp — and the started/stopped
// guards above already cover the genuinely-unseeded cases. Reporting stale on zero would
// turn a healthy freshly-started switch into a denial.
func (r *Redis) staleLocked() bool {
	if r.lastRefreshOK.IsZero() {
		return false
	}
	return r.clock().Sub(r.lastRefreshOK) > r.staleness()
}

// ActivateGlobal activates the global kill switch.
func (r *Redis) ActivateGlobal(ctx context.Context) error {
	if err := r.client.Set(ctx, redisGlobalKey, "1", 0).Err(); err != nil {
		return err
	}
	// Update the local cache BEFORE publishing so the issuing instance is never in a
	// fail-open window: a ShouldBlock between the Redis write and the publish must
	// already observe the kill. Remote replicas converge on the event (or the next
	// reconcile if it is lost).
	r.mu.Lock()
	r.globalActive = true
	r.cacheGen++
	r.mu.Unlock()
	return r.publish(ctx, "global:activate")
}

// DeactivateGlobal deactivates the global kill switch.
func (r *Redis) DeactivateGlobal(ctx context.Context) error {
	if err := r.client.Del(ctx, redisGlobalKey).Err(); err != nil {
		return err
	}
	// Update the local cache before publishing; see ActivateGlobal.
	r.mu.Lock()
	r.globalActive = false
	r.cacheGen++
	r.mu.Unlock()
	return r.publish(ctx, "global:deactivate")
}

// setBlock is the shared body of KillAgent/ReviveAgent/KillSession/ReviveSession.
// The two booleans are the only real axes: kill (Set+add vs Del+remove) and session
// (which entity dimension). Everything else — the key prefix, the publish verb, the
// cache map, and the error-message names — is DERIVED from those two here, so a caller
// cannot mismatch (e.g. write the agent key while publishing on the session channel).
// kill=true SETs the durable Redis key and adds the id to the cache; kill=false DELs
// it and removes the id; the cache map is selected and mutated under r.mu, so a
// concurrent Reset that swaps the maps cannot route the write to a stale one. An empty
// id is rejected because it would write the bare prefix key and publish a verb with an
// empty suffix, polluting the key space and triggering a spurious full refresh on every
// replica. The broadcast happens after the cache update (see ActivateGlobal).
func (r *Redis) setBlock(ctx context.Context, kill, session bool, id string) error {
	verb := "Kill"
	if !kill {
		verb = "Revive"
	}
	entity, idField, keyPrefix := "Agent", "agentID", redisAgentPrefix
	if session {
		entity, idField, keyPrefix = "Session", "sessionID", redisSessionPfx
	}
	if id == "" {
		return fmt.Errorf("killswitch: %s%s: %s must not be empty", verb, entity, idField)
	}
	key := keyPrefix + id
	var err error
	if kill {
		// Only SESSION tombstones expire; an agent kill is durable revocation of a
		// long-lived identity. See defaultSessionKillTTL for why the expiry is a
		// garbage-collection bound rather than a policy one.
		ttl := time.Duration(0)
		if session {
			ttl = r.sessionKillTTL
		}
		err = r.client.Set(ctx, key, "1", ttl).Err()
	} else {
		err = r.client.Del(ctx, key).Err()
	}
	if err != nil {
		return err
	}
	// Update the local cache before publishing; see ActivateGlobal. The map field is
	// selected under the lock so a concurrent Reset swap is not raced.
	r.mu.Lock()
	cache := r.killedAgents
	if session {
		cache = r.killedSessions
	}
	if kill {
		cache[id] = true
	} else {
		delete(cache, id)
	}
	r.cacheGen++
	r.mu.Unlock()
	// The published channel name mirrors the durable-key dimension:
	// "<entity>:<action>:<id>", e.g. "agent:kill:abc123".
	action := "kill"
	if !kill {
		action = "revive"
	}
	return r.publish(ctx, strings.ToLower(entity)+":"+action+":"+id)
}

// KillAgent blocks the specified agent.
func (r *Redis) KillAgent(ctx context.Context, agentID string) error {
	return r.setBlock(ctx, true, false, agentID)
}

// ReviveAgent removes the kill on the specified agent.
func (r *Redis) ReviveAgent(ctx context.Context, agentID string) error {
	return r.setBlock(ctx, false, false, agentID)
}

// KillSession blocks the specified session.
func (r *Redis) KillSession(ctx context.Context, sessionID string) error {
	return r.setBlock(ctx, true, true, sessionID)
}

// ReviveSession removes the kill on the specified session.
func (r *Redis) ReviveSession(ctx context.Context, sessionID string) error {
	return r.setBlock(ctx, false, true, sessionID)
}

// Reset clears all kill-switch state.
func (r *Redis) Reset(ctx context.Context) error {
	// Delete the global key; propagate the error so a silent failure does not leave
	// the global switch active while the caller believes it cleared.
	if err := r.client.Del(ctx, redisGlobalKey).Err(); err != nil {
		return fmt.Errorf("kill switch reset: delete global key: %w", err)
	}

	// Delete agent/session keys, propagating errors. In-memory state is cleared only
	// after all Redis deletions succeed, keeping it consistent with Redis.
	if err := r.deleteByPrefix(ctx, redisAgentPrefix); err != nil {
		return err
	}
	if err := r.deleteByPrefix(ctx, redisSessionPfx); err != nil {
		return err
	}

	// Capture the publish error but finish the local clear + reseed first: the durable
	// deletions already succeeded, so a publish failure must not abort the reset (it
	// only means replicas converge on the next reconcile).
	pubErr := r.publish(ctx, "reset")

	r.mu.Lock()
	r.globalActive = false
	r.killedAgents = make(map[string]bool)
	r.killedSessions = make(map[string]bool)
	r.cacheGen++
	r.mu.Unlock()

	// Re-read Redis after the clear to re-seed any kill that landed between the delete
	// sweep and now: a concurrent KillAgent can SET its key after deleteByPrefix, then
	// have its cache write wiped by the clear above, leaving the kill durable but
	// invisible to ShouldBlock until the next reconcile. refreshState shrinks that
	// fail-open window to the sub-millisecond read-to-swap gap. Best-effort: a
	// transient refresh error must not fail an otherwise-complete Reset.
	//
	// Use runCtx, not the caller's ctx: Reset's durable work (the deletes and publish
	// above) is already done by this point, so a caller ctx that gets canceled right
	// after calling Reset (a request-scoped ctx returning to its handler) must not
	// turn this best-effort reseed into a recorded refresh failure — refreshState
	// cannot tell a caller-cancel from genuine Redis unreachability, and
	// recordRefreshErr's context.Canceled would then trip ShouldBlock's fail-closed
	// non-match path (denying every request) for up to a reconcile tick on an
	// otherwise-healthy backend. runCtx is the same background-lifetime context every
	// other best-effort refresh (reconcileRefresh, the ticker/pub-sub loops) already
	// uses, and is nil only before Start — fall back to the caller's ctx then, since
	// there is no longer-lived context to prefer.
	reseedCtx := ctx //nolint:contextcheck // reseedCtx is deliberately reassigned to r.runCtx below when set: the switch's own background-lifetime context (Start), not derived from this function's ctx parameter, so a caller ctx canceled right after Reset returns cannot be misattributed as a refresh failure (see the comment above).
	// runCtx is written under r.mu in Start, so read it under r.mu too. This
	// goroutine holds no lock here (Reset's durable work is done and its critical
	// sections have all been released), so taking RLock is safe -- a caller that
	// already holds r.mu must read the field directly instead, since re-acquiring an
	// RWMutex for reading from a goroutine that already holds it risks blocking
	// behind a writer that arrived in between (Go's sync.RWMutex favors writers).
	r.mu.RLock()
	runCtx := r.runCtx
	r.mu.RUnlock()
	if runCtx != nil {
		reseedCtx = runCtx
	}
	_ = r.refreshState(reseedCtx)
	return pubErr
}

// Status returns the current kill-switch state from the LOCAL cache.
//
// Unlike ShouldBlock, Status does not fail closed: it returns a nil error even before
// Start has seeded the cache and while a Redis outage has left the cache stale, so a
// pre-Start or degraded Status reports an empty/stale snapshot rather than an error.
// It is an operator-visibility view of the local cache, not an authoritative
// enumeration of Redis; HealthStatus is the authoritative freshness signal, and a
// kill issued during an outage becomes visible here once Redis recovers (at the latest
// on the next reconcile tick).
func (r *Redis) Status(_ context.Context) (*Status, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return buildStatus(r.globalActive, r.killedAgents, r.killedSessions), nil
}

// publish broadcasts msg on the kill-switch channel and returns any publish error.
// The durable write and cache update already happened, so a publish failure does NOT
// undo the kill on the issuing instance — it only delays remote convergence to the
// next reconcile; returning the error lets the caller report partial propagation.
//
// Called directly on r.client: Publish is part of redis.Cmdable, so every client this
// type can hold has it. (Subscribe, which the pub/sub receive path guards for, is NOT on
// Cmdable — that assertion is live, this one never was.)
func (r *Redis) publish(ctx context.Context, msg string) error {
	return r.client.Publish(ctx, redisPubSubChan, msg).Err()
}

// recordRefreshErr stores err as the last refresh error under the lock and returns
// it, so refreshState's three Redis-read failure paths share one stamp-and-return.
// It is only ever called from within refreshState, which holds refreshMu for its
// whole scan+commit body, so lastRefreshErr has a single serialized writer: no
// concurrent refresh can clear an error this one recorded, or vice versa.
func (r *Redis) recordRefreshErr(err error) error {
	r.mu.Lock()
	r.lastRefreshErr = err
	r.mu.Unlock()
	return err
}

func (r *Redis) refreshState(ctx context.Context) error {
	// Serialize refreshes so two scans cannot interleave and commit out of order: a
	// cacheGen match only guards against a racing cache MUTATION, not against a
	// second refresh that captured the same generation, so without this an older
	// scan could overwrite a newer one and erase a kill. refreshMu is held for the
	// whole scan+commit; it is separate from r.mu, which the lock-free scan below
	// deliberately avoids so ShouldBlock is never stalled on Redis I/O.
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()

	// Build the snapshot outside r.mu so ShouldBlock is not stalled during Redis I/O;
	// only the final map-swap takes the write lock.
	//
	// The swap is guarded by cacheGen: a kill applied to the cache after a SCAN
	// returned but before the swap would otherwise be erased by the stale snapshot,
	// failing open until the next reconcile. Capture the generation before scanning
	// and commit only if unchanged; a concurrent mutation forces a retry.
	const maxRefreshAttempts = 4
	for attempt := 0; ; attempt++ {
		r.mu.RLock()
		startGen := r.cacheGen
		r.mu.RUnlock()

		val, err := r.client.Get(ctx, redisGlobalKey).Result()
		if err != nil && !errors.Is(err, redis.Nil) {
			return r.recordRefreshErr(err)
		}
		newGlobal := err == nil && val == "1"

		newAgents := make(map[string]bool)
		if err := r.scanPrefix(ctx, redisAgentPrefix, newAgents); err != nil {
			return r.recordRefreshErr(err)
		}

		newSessions := make(map[string]bool)
		if err := r.scanPrefix(ctx, redisSessionPfx, newSessions); err != nil {
			return r.recordRefreshErr(err)
		}

		r.mu.Lock()
		if r.cacheGen == startGen {
			// No cache mutation raced the scan: the snapshot is consistent.
			r.commitRefreshLocked(newGlobal, newAgents, newSessions)
			r.mu.Unlock()
			return nil
		}
		if attempt+1 < maxRefreshAttempts {
			// A kill/revive/global toggle landed during the scan; the snapshot may
			// be stale. Drop it and re-read Redis from scratch.
			r.mu.Unlock()
			continue
		}
		// Sustained mutation across every attempt (pathological): commit the scan but
		// UNION in the kills the cache gained concurrently so none is erased. This
		// biases fail-closed (a revoked entry is retained, not dropped); the next
		// reconcile reconciles any raced deletion.
		for a := range r.killedAgents {
			newAgents[a] = true
		}
		for s := range r.killedSessions {
			newSessions[s] = true
		}
		r.commitRefreshLocked(newGlobal || r.globalActive, newAgents, newSessions)
		r.mu.Unlock()
		return nil
	}
}

// commitRefreshLocked installs a completed scan's snapshot and stamps the refresh as
// healthy. Caller must hold r.mu for writing.
//
// The two commit sites -- the clean one and the sustained-mutation fallback, twenty lines
// apart -- ran the identical five statements. Sharing them is not cosmetic: the health
// stamp is the pair (lastRefreshErr cleared, lastRefreshOK set), and the staleness gate
// denies ALL traffic in fail-closed mode when it is not maintained. A future field added
// to that stamp on one commit path and not the other would leave the fallback path
// committing a snapshot that reads as unconfirmed.
//
// Clearing lastRefreshErr is correct on both: the Redis read succeeded, and refreshMu
// serializes refreshes, so no concurrent refresh can have recorded a fresher error
// between this scan's start and this commit.
func (r *Redis) commitRefreshLocked(global bool, agents, sessions map[string]bool) {
	r.globalActive = global
	r.killedAgents = agents
	r.killedSessions = sessions
	r.lastRefreshErr = nil
	r.lastRefreshOK = r.clock()
}

// scanner is the subset of a Redis node needed to enumerate keys by prefix. It is a
// PARAMETER type for the per-node helpers, which are called both with r.client and with
// an individual master from ForEachMaster; it is not a capability test, since redis.Cmdable
// (the only type r.client can hold) statically carries Scan.
type scanner interface {
	Scan(ctx context.Context, cursor uint64, match string, count int64) *redis.ScanCmd
}

func (r *Redis) scanPrefix(ctx context.Context, prefix string, target map[string]bool) error {
	// A keyless SCAN on a *redis.ClusterClient hits one random master, so a
	// cluster-wide enumeration must visit every master and merge the scans; otherwise
	// refreshState loads a partial snapshot, treats it as healthy, and drops kills on
	// the other masters. ForEachMaster runs concurrently, so target needs a mutex.
	//
	// Reachable only by a LIBRARY consumer: the shipped binary always builds a
	// single-node client. It is kept because deleting it would not remove the cluster
	// case, only the handling of it -- a ClusterClient would then load a partial kill set
	// and report healthy, which is a fail-open on the emergency stop.
	//
	// Note the asymmetry it exposes, since nothing else in the tree states it: pkg/
	// callcounter has NO cluster handling, so a consumer who supplies a ClusterClient gets
	// correct kill-switch enumeration alongside per-master maxCalls counting that silently
	// under-counts. Redis Cluster is not a supported eunox deployment; use a single-node
	// or replicated (non-sharded) endpoint.
	if cc, ok := r.client.(*redis.ClusterClient); ok {
		var mu sync.Mutex
		return cc.ForEachMaster(ctx, func(ctx context.Context, node *redis.Client) error {
			return scanNode(ctx, node, prefix, target, &mu)
		})
	}
	// r.client satisfies scanner by construction: Scan is part of redis.Cmdable.
	return scanNode(ctx, r.client, prefix, target, nil)
}

// scanNode SCANs a single node for keys matching prefix and records the stripped
// IDs in target. mu, when non-nil, guards target for concurrent callers (cluster
// fan-out via ForEachMaster); pass nil for a single-node scan.
func scanNode(ctx context.Context, sc scanner, prefix string, target map[string]bool, mu *sync.Mutex) error {
	var cursor uint64
	for {
		keys, next, err := sc.Scan(ctx, cursor, prefix+"*", 100).Result()
		if err != nil {
			return err
		}
		if mu != nil {
			mu.Lock()
		}
		for _, key := range keys {
			target[key[len(prefix):]] = true
		}
		if mu != nil {
			mu.Unlock()
		}
		cursor = next
		if cursor == 0 {
			return nil
		}
	}
}

// scanDeleter is the subset of a Redis node needed to enumerate and delete keys
// by prefix. Both *redis.Client and *redis.ClusterClient satisfy it.
type scanDeleter interface {
	scanner
	Del(ctx context.Context, keys ...string) *redis.IntCmd
}

func (r *Redis) deleteByPrefix(ctx context.Context, prefix string) error {
	// As with scanPrefix, a cluster client SCANs only one master, so a reset must
	// visit every master; otherwise Reset() reports success while leaving kills on
	// the others.
	if cc, ok := r.client.(*redis.ClusterClient); ok {
		return cc.ForEachMaster(ctx, func(ctx context.Context, node *redis.Client) error {
			return deleteNodeKeys(ctx, node, prefix)
		})
	}
	// r.client satisfies scanDeleter by construction: Scan and Del are both part of
	// redis.Cmdable.
	return deleteNodeKeys(ctx, r.client, prefix)
}

// deleteNodeKeys SCANs a single node for keys matching prefix and deletes them one
// at a time: in a cluster, keys from one node's SCAN can map to different hash slots
// and a multi-key DEL spanning slots fails with CROSSSLOT, whereas per-key DEL is
// slot-safe on both standalone and cluster nodes.
func deleteNodeKeys(ctx context.Context, sd scanDeleter, prefix string) error {
	var cursor uint64
	for {
		keys, next, err := sd.Scan(ctx, cursor, prefix+"*", 100).Result()
		if err != nil {
			return fmt.Errorf("kill switch reset: SCAN %s*: %w", prefix, err)
		}
		for _, key := range keys {
			if err := sd.Del(ctx, key).Err(); err != nil {
				return fmt.Errorf("kill switch reset: DEL %s: %w", key, err)
			}
		}
		cursor = next
		if cursor == 0 {
			return nil
		}
	}
}

// subscribeConfirmed subscribes to the kill-event channel and blocks until the server
// confirms the subscription, so a caller may order a state snapshot strictly after the
// subscription is live. The confirmation read is bounded by subscribeConfirmTimeout:
// pubsub.Receive issues a deadline-less socket read (go-redis passes timeout=0), so a
// blackholed or half-open connection would otherwise block forever -- and in Start that
// block holds lifeMu, deadlocking a concurrent Stop. A WithTimeout ctx carries a
// deadline, so the read returns i/o timeout instead of hanging. On any failure the
// pubsub is closed so its connection is not leaked across a retry.
func (r *Redis) subscribeConfirmed(ctx context.Context, sub pubSubClient) (*redis.PubSub, error) {
	pubsub := sub.Subscribe(ctx, redisPubSubChan)
	recvCtx, recvCancel := context.WithTimeout(ctx, subscribeConfirmTimeout)
	defer recvCancel()
	if _, err := pubsub.Receive(recvCtx); err != nil {
		_ = pubsub.Close()
		return nil, err
	}
	return pubsub, nil
}

// supervisePubSub consumes a confirmed subscription and, if it is lost while ctx is
// still live, hands off to resubscribeLoop. It exists so the real-time path has one
// owner goroutine for the whole run: listenPubSub returning early (an unexpected
// channel close) is a recoverable loss of propagation, not a reason to spend the rest
// of the process reconcile-only.
func (r *Redis) supervisePubSub(ctx context.Context, sub pubSubClient, pubsub *redis.PubSub) {
	r.listenPubSub(ctx, pubsub)
	if ctx.Err() != nil {
		return
	}
	r.resubscribeLoop(ctx, sub)
}

// resubscribeLoop re-establishes the pub/sub subscription in the background with
// capped exponential backoff, then consumes it, repeating for as long as ctx is live.
// It runs off the Start goroutine so retrying never extends the lifeMu hold that
// subscribeConfirmTimeout exists to bound.
//
// Retry failures are not logged per attempt: the caller already logged one warning on
// entering degraded mode, and a sustained outage would otherwise log on every attempt.
// Only the recovery edge is logged, matching reconcileRefresh's edge-triggered
// breadcrumbs. HealthStatus() remains the authoritative health signal.
func (r *Redis) resubscribeLoop(ctx context.Context, sub pubSubClient) {
	delay := subscribeRetryInitialDelay
	timer := time.NewTimer(delay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		pubsub, err := r.subscribeConfirmed(ctx, sub)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if delay *= 2; delay > subscribeRetryMaxDelay {
				delay = subscribeRetryMaxDelay
			}
			timer.Reset(delay)
			continue
		}
		if r.logger != nil {
			r.logger.Info("kill switch: pub/sub subscription re-established; real-time kill propagation restored")
		}
		// Pub/sub is at-most-once, so every event published while the subscription was
		// down was missed. Reconcile immediately rather than leave those kills
		// unobserved until the next reconcile tick. Ordered AFTER the confirmed
		// subscribe (as Start orders its initial snapshot) so an event racing this
		// refresh is delivered on the now-live subscription instead of falling into the
		// handoff window.
		r.reconcileRefresh(ctx)
		r.listenPubSub(ctx, pubsub)
		if ctx.Err() != nil {
			return
		}
		// The subscription was lost again while running; restart the backoff from the
		// bottom, since this is a fresh outage rather than a continuation of the last.
		delay = subscribeRetryInitialDelay
		timer.Reset(delay)
	}
}

func (r *Redis) listenPubSub(ctx context.Context, pubsub *redis.PubSub) {
	defer func() { _ = pubsub.Close() }()
	ch := pubsub.Channel()
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-ch:
			if !ok {
				// go-redis closes this channel only on an explicit pubsub.Close()
				// (transient network drops auto-reconnect and resubscribe WITHOUT
				// closing it). The sole Close() on this pubsub is this function's own
				// deferred one, which runs after we return, and on teardown the
				// ctx.Done() case above wins first — so reaching here means the channel
				// closed while ctx is still live: an unexpected loss of the real-time
				// path, not the normal shutdown. State still converges on the reconcile
				// loop (fail-closed preserved) and supervisePubSub resubscribes, but
				// surface it so the degraded propagation is not silent.
				if r.logger != nil && ctx.Err() == nil {
					r.logger.Warn("kill switch: pub/sub channel closed unexpectedly while running; converging state on the periodic reconcile only while the subscription is retried in the background")
				}
				return
			}
			r.handlePubSubMessage(msg.Payload)
		}
	}
}

// handlePubSubMessage processes a kill-switch event and updates local cache immediately.
// Message format: "global:activate", "global:deactivate", "agent:kill:<id>",
// "agent:revive:<id>", "session:kill:<id>", "session:revive:<id>", "reset".
func (r *Redis) handlePubSubMessage(payload string) {
	r.mu.Lock()
	shouldRefresh := false

	switch payload {
	case "global:activate":
		r.globalActive = true
	case "global:deactivate":
		r.globalActive = false
	case "reset":
		r.globalActive = false
		r.killedAgents = make(map[string]bool)
		r.killedSessions = make(map[string]bool)
		// Re-read Redis after the clear (as Reset() does): a kill that raced the
		// publisher's delete sweep can land in Redis after the delete but before this
		// event, and clearing local state alone would hide it until the next reconcile,
		// failing open on a non-initiating replica.
		shouldRefresh = true
	default:
		// Prefixed events carry a non-empty id; cutKillID returns "" for a non-match
		// or a bare prefix, so an unrecognized message falls through to a full refresh.
		if id := cutKillID(payload, "agent:kill:"); id != "" {
			r.killedAgents[id] = true
		} else if id := cutKillID(payload, "agent:revive:"); id != "" {
			delete(r.killedAgents, id)
		} else if id := cutKillID(payload, "session:kill:"); id != "" {
			r.killedSessions[id] = true
		} else if id := cutKillID(payload, "session:revive:"); id != "" {
			delete(r.killedSessions, id)
		} else {
			// Unknown message — trigger a full refresh from Redis.
			shouldRefresh = true
		}
	}
	// Bump the cache generation for every event so a concurrent in-flight
	// refreshState discards its now-stale snapshot rather than overwrite this update.
	r.cacheGen++
	// Snapshot refreshTrigger under r.mu to avoid a race with Start, which creates it
	// under the same lock.
	var trigger chan struct{}
	if shouldRefresh {
		trigger = r.refreshTrigger
	}
	r.mu.Unlock()

	// Signal the drainRefreshTrigger goroutine rather than run the SCAN inline, so a
	// reset/unknown event cannot block the single real-time kill-event consumer on
	// Redis I/O. The send is non-blocking and the channel 1-element buffered, so
	// concurrent triggers coalesce.
	if shouldRefresh && trigger != nil {
		select {
		case trigger <- struct{}{}:
		default:
		}
	}
}

// cutKillID returns the id carried by a prefixed kill-switch pub/sub event (e.g.
// "agent:kill:foo" with prefix "agent:kill:" yields "foo"), or "" when payload lacks
// the prefix or carries it with an empty id. Treating an empty id as no match makes a
// bare "agent:kill:" fall through to a full refresh.
func cutKillID(payload, prefix string) string {
	if id, ok := strings.CutPrefix(payload, prefix); ok {
		return id
	}
	return ""
}
