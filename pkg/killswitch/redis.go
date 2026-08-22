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

	"github.com/eunolabs/eunox/internal/redisutil"
	"github.com/eunolabs/eunox/pkg/durationsentinel"
)

const (
	redisGlobalKey   = "killswitch:global"
	redisAgentPrefix = "killswitch:agent:"
	redisSessionPfx  = "killswitch:session:"
	redisJTIPrefix   = "killswitch:jti:"
	redisPubSubChan  = "killswitch:events"

	// defaultReconcileInterval is how often the local cache is fully refreshed from Redis,
	// independent of pub/sub, so an at-most-once kill event lost during a brief
	// disconnect is still observed, and a degraded-boot replica re-converges.
	defaultReconcileInterval = 30 * time.Second

	// defaultSessionKillTTL bounds how long a SESSION kill tombstone lives in Redis: a
	// garbage-collection bound (unbounded tombstones from ephemeral session ids would
	// otherwise accumulate forever), NOT a policy expiry. 30 days is far longer than any
	// session can live, so a value shorter than that would be a fail-open (expiry LIFTS
	// the kill). AGENT kills are never expired: that identity is long-lived.
	defaultSessionKillTTL = 30 * 24 * time.Hour
)

// DefaultSessionKillTTL is the exported form of the default session-tombstone lifetime, so
// the CLI's --killswitch-session-ttl help states it without restating (and risking drifting
// from) it. The startup banner is NOT a consumer: it reports the EFFECTIVE lifetime, which
// NormalizeSessionKillTTL resolves from the operator's flag and which equals this only when
// the flag is unset.
const DefaultSessionKillTTL = defaultSessionKillTTL

// DefaultReconcileInterval is the exported form of the default reconcile cadence, for the
// same reason as DefaultSessionKillTTL: --killswitch-reconcile-interval's help has to name
// the default an unset flag selects, and the prose spelling of it had already drifted out
// of reach of the constant.
const DefaultReconcileInterval = defaultReconcileInterval

// subscribeConfirmTimeout bounds the initial pub/sub subscription-confirmation read in
// Start: pubsub.Receive's deadline-less socket read would otherwise block a blackholed
// connection forever, and Start holds lifeMu across it, deadlocking a concurrent Stop. A
// var, not a const, only so the deadlock regression test can shrink it.
var subscribeConfirmTimeout = 5 * time.Second

// subscribeRetryInitialDelay and subscribeRetryMaxDelay bound the background resubscribe
// backoff: since subscribeConfirmTimeout is a hard cutoff, a merely slow (not down) Redis
// can miss it and would otherwise run reconcile-only for the rest of its lifetime. Vars,
// not consts, only so tests can shrink them.
var (
	subscribeRetryInitialDelay = 1 * time.Second
	subscribeRetryMaxDelay     = 30 * time.Second
)

// pubSubClient is the optional Subscribe facet of the Redis client. redis.Cmdable does
// not include Subscribe, so the capability is detected by assertion and skipped when absent.
type pubSubClient interface {
	Subscribe(ctx context.Context, channels ...string) *redis.PubSub
}

// ErrBackendUnreachable is returned by ShouldBlock in the default fail-closed degraded
// mode when the most recent Redis refresh failed, so the cache may be stale. The
// underlying error is NOT wrapped so connection details don't leak; see HealthStatus().
var ErrBackendUnreachable = errors.New("killswitch: redis backend unreachable; failing closed (kill-switch state cannot be confirmed)")

// ErrNotStarted is returned by every reader of the cache before Start has loaded initial
// state: the cache cannot tell "nothing is killed" from "never loaded", so it fails closed
// regardless of WithFailOpen — a WIRING error, not a transient outage.
var ErrNotStarted = errors.New("killswitch: redis kill switch queried before Start(); failing closed (state never loaded)")

// ErrStopped is returned by ShouldBlock on a non-match once the Start context is
// canceled and the convergence loops have exited: like ErrNotStarted, a liveness
// condition that fails closed regardless of WithFailOpen.
var ErrStopped = errors.New("killswitch: redis kill switch convergence stopped (Start context canceled); failing closed (state can no longer be confirmed)")

// ErrNilClient refuses a backend wired with no Redis client at all. A WIRING error like
// ErrNotStarted, and it fails closed regardless of WithFailOpen for the same reason: fail-open
// trades revocation for availability during a TRANSIENT outage that a later reconcile heals,
// and this one never can.
//
// Detected at construction rather than left to the first command, because go-redis dereferences
// the receiver before it can build a reply — every command on a nil client PANICS instead of
// erroring, and the first ones to run are Start's Subscribe and the reconcile goroutine's Get.
var ErrNilClient = errors.New("killswitch: redis kill switch wired with a nil client; failing closed (kill-switch state cannot be loaded)")

// ErrUnknownTopology refuses a backend whose client's KEYSPACE TOPOLOGY cannot be established:
// a concrete type redisutil does not recognize, which is a decorator (a metrics or tracing
// wrapper) or a consumer's own Cmdable.
//
// Refused rather than assumed single-node, because assuming is fail-OPEN and silent. This
// backend's full enumeration is a keyless SCAN; routed to one server of several it loads a
// PARTIAL kill set, ShouldBlock then answers "not killed" for every session whose key hashed
// elsewhere, and HealthStatus reports ready. An operator issues a kill, gets `{"ok":true}`, and
// the instance behind the wrapper never learns of it. The Manager contract says the opposite: a
// backend that cannot confirm its kill set reports the cause from every reader.
//
// Latched like ErrNilClient, and fails closed regardless of WithFailOpen for the same reason —
// fail-open trades revocation for availability during a TRANSIENT outage, and a wiring fault
// never heals. A consumer that knows what its wrapper wraps says so with WithSingleNodeKeyspace
// or WithShardFanOut, which is the escape hatch this refusal is only tolerable with.
var ErrUnknownTopology = errors.New("killswitch: redis kill switch wired with a client whose keyspace topology cannot be determined (a decorator or a custom Cmdable); failing closed, since a keyless SCAN over a sharded keyspace loads a PARTIAL kill set and reports it as complete. Pass the client itself, or declare the topology with killswitch.WithSingleNodeKeyspace()/WithShardFanOut()")

// ErrIncompleteEnumeration is what a full-keyspace SCAN reports when it covered fewer servers
// than the client spreads its keyspace over — today, a *redis.Ring shard go-redis has voted down,
// which its own iterator skips with no error at all.
//
// It is the same fail-open ErrUnknownTopology refuses, reached one layer down: the topology was
// established correctly and the ENUMERATION still came back short, so without this the surviving
// shards' keys commit as the authoritative kill set, lastRefreshErr stays nil, HealthStatus
// reports ready, and ShouldBlock answers "not killed" for every session whose key lived on the
// missing shard.
//
// Unlike its latched siblings this is a REFRESH error, not a wiring fault: a shard that is down
// comes back, and the next reconcile clears it. So it honours WithFailOpen like any other outage
// rather than overriding it — the posture an operator chose for "Redis is unreachable" is the
// posture for "part of Redis is unreachable" too.
//
// Exported as this package's own name for an error defined below it, so a consumer outside this
// module can errors.Is against the refusal it will actually be handed.
var ErrIncompleteEnumeration = redisutil.ErrIncompleteFanOut

// ErrTopologyContradicted refuses a topology DECLARATION that disagrees with what the client's
// own concrete type establishes — WithSingleNodeKeyspace() beside a *redis.ClusterClient, say.
//
// Refused rather than obeyed, because obeying is the fail-open. The declaring options exist to
// fill what a concrete-type match cannot answer; letting one override an answer it CAN give
// would discard a working per-shard iterator and put the backend back to loading one shard's
// kill set and serving it as complete — with nothing latched and HealthStatus reporting ready,
// which is precisely what ErrUnknownTopology was added to stop. Latched and fail-closed like its
// siblings: a declaration that contradicts the client is a wiring bug, and it never heals.
var ErrTopologyContradicted = errors.New("killswitch: the declared keyspace topology contradicts the Redis client's own type; failing closed (drop the declaration, or pass the client the declaration describes)")

// ErrPublishFailed marks a failure that happened AFTER the durable write already landed: the
// revocation (or its undo) is in Redis and every replica converges on its next reconcile tick,
// but the real-time pub/sub notification did not go out.
//
// Distinguishable rather than returned bare, because a caller whose whole question is "did the
// revocation land" — `eunox kill`'s exit contract, /control/kill's status — cannot tell a lost
// notification from a lost kill through an undifferentiated error, and answering "it failed"
// for a kill that is durably written is the wrong direction on the emergency-stop path. On a
// minimally-privileged Redis ACL granting SET/DEL/SCAN but not PUBLISH, every kill reports
// failure forever while in fact landing.
//
// Wrapped around the cause, so a caller that wants the underlying Redis error still reaches it
// with errors.Is/As.
var ErrPublishFailed = errors.New("killswitch: kill-switch state was written durably, but the pub/sub notification failed")

// Redis is a Redis-backed kill-switch manager with pub/sub propagation and local cache.
type Redis struct {
	client redis.Cmdable
	// wiringErr latches a construction-time fault that makes the client unusable for the
	// instance's whole life. Immutable after NewRedis, so it is read without the lock; every
	// entry point that would touch the client checks it FIRST, which is what makes the refusal
	// cover the write and pub/sub paths rather than only the node enumeration.
	wiringErr error
	// topology is how this client spreads its keyspace, and shardFanOut is the iterator that
	// visits every server it spreads over (nil when the whole keyspace lives on one). Resolved
	// ONCE at construction, from the client's type or from the consumer's declaration, so no
	// enumeration re-asks a question whose answer cannot change and the two keyless-command
	// sites cannot be handed different topologies.
	//
	// The topology is kept as redisutil's own three-valued answer rather than collapsed to a
	// "known" bool: the bool made "known single-node, with a live cluster fan-out discarded"
	// representable, which is exactly the state a declaration overriding a classification would
	// leave behind. resolveTopology holds the pair in agreement.
	topology    redisutil.Topology
	shardFanOut redisutil.ShardFanOut
	// declared/declaredFanOut hold a consumer's topology DECLARATION, kept apart from the
	// classification until resolveTopology settles the two: a declaration fills what the client's
	// type could not establish and never overrides what it did. TopologyUnknown means "nothing
	// declared", which is why the options never set it.
	declared       redisutil.Topology
	declaredFanOut redisutil.ShardFanOut
	logger         *slog.Logger

	// observers receive a Revocation the moment this instance's local view gains one,
	// including a kill issued ELSEWHERE that this instance learns of via pub/sub or the
	// reconcile scan and has no request to hang a teardown off. Fired from BOTH paths, so
	// a dropped publish still reclaims on the next reconcile. See Manager.ObserveRevocations.
	observers revocationObservers

	// refreshMu serializes refreshState so two scans cannot commit out of order: cacheGen
	// alone only guards against a racing cache MUTATION, not a second concurrent refresh
	// capturing the same generation, which could let an older scan overwrite a newer one.
	// Distinct from mu since the scan must stay off the hot-path lock.
	refreshMu sync.Mutex

	// Local cache for fast reads (refreshed via pub/sub and the reconcile loop).
	mu             sync.RWMutex
	globalActive   bool
	killedAgents   map[string]bool
	killedSessions map[string]bool
	revokedJTIs    map[string]bool
	lastRefreshErr error // last refresh error; nil means healthy
	// lastRefreshOK is when a refresh last CONFIRMED state against Redis. lastRefreshErr
	// is edge-triggered (set only once a refresh has run AND failed), so a partition
	// beginning right after a success would otherwise leave fail-closed mode serving a
	// stale all-clear indefinitely; staleness makes that guarantee time-bounded instead
	// of failure-detection-bounded. Zero means no refresh has ever succeeded.
	lastRefreshOK time.Time
	// cacheGen is bumped under mu on every local-cache mutation. refreshState captures it
	// before its lock-free scan and only commits if unchanged, or a kill applied during
	// the scan would be erased by the stale snapshot until the next reconcile.
	cacheGen uint64
	// reconcileErrLogged edge-triggers the background-refresh-failure warning so a
	// sustained outage does not log every tick. Distinct from lastRefreshErr (the
	// authoritative health signal); this only throttles the breadcrumb.
	reconcileErrLogged bool

	// sessionTTLWarnedPrior dedupes the session-kill-TTL disagreement warning on the
	// PRIOR VALUE, not a bare flag, so a persistent disagreement warns once while a
	// changed one warns again. See refreshPublishedSessionKillTTL.
	sessionTTLWarnedPrior string
	// sessionTTLPublishErrLogged edge-triggers the re-publish failure warning, mirroring
	// reconcileErrLogged on the same loop.
	sessionTTLPublishErrLogged bool

	// sessionTTLPublished latches when PublishSessionKillTTL is CALLED (not succeeded),
	// arming the reconcile loop's republish; until then its tick publishes nothing. Start
	// runs before the transport serves, so an unconditional republish would let any
	// startup that survived one reconcile tick before failing clobber a running proxy's
	// published TTL. Latching on success instead would leave a proxy that booted during a
	// brief outage with the republish permanently dead. atomic since it's read on the
	// reconcile goroutine and written on whichever goroutine publishes.
	sessionTTLPublished atomic.Bool

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

	// refreshTrigger decouples the pub/sub listener from the full Redis SCAN a reset or
	// unknown event requires: handlePubSubMessage sends non-blocking and
	// drainRefreshTrigger consumes it. The 1-element buffer coalesces a burst into at
	// most one pending scan, so the listener never blocks on N sequential SCANs.
	refreshTrigger chan struct{}

	// lifeMu serializes the whole Start body against Stop, SEPARATE from mu since Start
	// holds it across the initial refreshState round-trip, during which mu must stay
	// free. Holding it across Start orders every wg.Add before a concurrent Stop's
	// wg.Wait. stopped (under lifeMu) makes a Start that loses the race a no-op.
	lifeMu  sync.Mutex
	stopped bool

	// startedOnce guards Start (under lifeMu) so the listener and reconcile loop launch
	// at most once; a second Start would overwrite r.cancel and orphan the first
	// goroutines beyond Stop's reach.
	startedOnce bool

	// runCtx is the Start-derived context governing the reconcile/pub-sub loops, set once
	// under mu and read by ShouldBlock: once canceled the loops exit and the cache can no
	// longer track new kills, so ShouldBlock must fail closed on a non-match rather than
	// serve a stale all-clear. Reading runCtx.Err() observes cancellation synchronously,
	// unlike a flag latched by a context.AfterFunc goroutine. nil before Start.
	runCtx context.Context
	// started is set true once Start has run its initial state load. Until then the
	// cache cannot distinguish "nothing is killed" from "state never loaded", so it
	// fails closed (ErrNotStarted) even under WithFailOpen — a wiring guard, not a
	// runtime-outage signal.
	started atomic.Bool

	// wg tracks the background goroutines so Stop can block until they exit; without it
	// Stop's cancel() returns while a goroutine still touches shared state, racing a
	// caller that frees the client or logger.
	wg sync.WaitGroup
}

// RedisOption configures the Redis kill-switch manager at construction, rather than
// through chained setters on a live instance, because every field is read by ShouldBlock
// and the background loops WITHOUT synchronization — threading options through NewRedis
// makes "must be called before Start" structural rather than an unenforced doc comment.
type RedisOption func(*Redis)

// WithSessionKillTTL overrides how long a session-kill tombstone lives in Redis. Negative
// disables expiry; zero selects the default. This is the OPERATOR-FACING spelling
// (--killswitch-session-ttl); NormalizeSessionKillTTL resolves its two sentinels.
//
// LOWERING it below the longest session you can hold open is a fail-open, since an
// expiring tombstone lifts the kill on a session that may still be connected. Agent kills
// are never expired.
func WithSessionKillTTL(d time.Duration) RedisOption {
	return WithSessionKillTTLEffective(NormalizeSessionKillTTL(d))
}

// WithSessionKillTTLEffective sets the tombstone lifetime from an ALREADY-RESOLVED
// effective value (the form ReadPublishedSessionKillTTL and SessionKillTTL return): zero
// means never expires, any positive value is verbatim. Exists so a caller adopting a
// lifetime resolved elsewhere skips WithSessionKillTTL's sentinels, where zero instead
// means "use the default" — passing a permanent lifetime there would quietly convert it
// into an expiring one.
func WithSessionKillTTLEffective(d time.Duration) RedisOption {
	return func(r *Redis) {
		// durationsentinel.Resolve's zero-case happens to coincide with this option's
		// already-resolved zero (both mean "never expires" here), even though this
		// option's zero does not mean "use a default" the way NormalizeSessionKillTTL's does.
		r.sessionKillTTL = durationsentinel.Resolve(d, 0)
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

// ShardFanOut visits every server a sharding client spreads its keyspace over, running fn
// against each — what a KEYLESS command (SCAN) needs there, since routed to one server it
// enumerates one shard of several and reports success.
//
// Declared here rather than reused from the internal package that classifies client types, so a
// consumer outside this module can name the parameter WithShardFanOut takes.
type ShardFanOut func(ctx context.Context, fn func(ctx context.Context, node *redis.Client) error) error

// WithSingleNodeKeyspace declares that a client this package cannot classify keeps its WHOLE
// keyspace on one server, so a keyless SCAN against it enumerates all of it.
//
// The escape hatch for the ordinary decorator: a metrics or tracing wrapper around a plain
// *redis.Client is invisible to a concrete-type match, and without this it latches
// ErrUnknownTopology. It FILLS an unknown topology and cannot override a known one — declared
// beside a client whose own type says "sharded", it is refused (ErrTopologyContradicted) rather
// than honored, because honoring it would discard a working fan-out and serve one shard's kill
// set as the whole thing, which is the failure ErrUnknownTopology exists to prevent.
func WithSingleNodeKeyspace() RedisOption {
	return func(r *Redis) {
		r.declared, r.declaredFanOut = redisutil.TopologySingleNode, nil
	}
}

// RingFanOut returns the per-server iterator for a *redis.Ring WITH the completeness check
// go-redis' own ForEachShard lacks — it skips a shard its heartbeat has voted down and returns
// nil, which is a partial keyspace reported as the whole one.
//
// This is what a consumer passes to WithShardFanOut when their ring sits behind a decorator, which
// is the case that option exists for. Without it the only iterator they have to hand is the
// unchecked one, so the escape hatch that makes ErrUnknownTopology tolerable would reintroduce the
// fail-open ErrIncompleteEnumeration exists to close.
//
// Passing the ring itself to NewRedis needs none of this: it is classified, and wrapped, there.
func RingFanOut(ring *redis.Ring) ShardFanOut {
	return ShardFanOut(redisutil.WholeRingFanOut(ring))
}

// WithShardFanOut declares that a client this package cannot classify SPREADS its keyspace over
// several servers, and supplies the per-server iterator every full enumeration must use. Like
// its sibling it fills an unknown topology and cannot override a known one.
//
// A nil iterator is not a way to say "single node" — that is WithSingleNodeKeyspace, whose name
// says so — so it leaves the topology undeclared and the backend refuses as before rather than
// silently adopting the single-node path.
//
// The iterator must visit EVERY server, reporting an error when it cannot, rather than covering
// the reachable ones and returning nil: this backend commits what a pass returns as the whole kill
// set, so a short pass that reports success is the fail-open ErrIncompleteEnumeration exists to
// stop. Declaring (*redis.Ring).ForEachShard here is precisely that — wrap it in RingFanOut, which
// is the same iterator carrying the completeness check the library's own lacks.
func WithShardFanOut(fanOut ShardFanOut) RedisOption {
	return func(r *Redis) {
		if fanOut == nil {
			return
		}
		r.declared, r.declaredFanOut = redisutil.TopologySharded, redisutil.ShardFanOut(fanOut)
	}
}

// WithLogger sets a structured logger on the kill-switch for operational visibility.
// If set, initial state-refresh failures are logged as warnings rather than silently dropped.
func WithLogger(logger *slog.Logger) RedisOption {
	return func(r *Redis) {
		r.logger = logger
	}
}

// WithFailOpen selects the degraded-mode behaviour when Redis is unreachable. Default
// (false) is fail-CLOSED: ShouldBlock denies every request while the last refresh failed,
// honouring the emergency stop at the cost of blocking the data plane. WithFailOpen(true)
// is availability-first, serving the last-known cache instead. See ADR-0003.
func WithFailOpen(failOpen bool) RedisOption {
	return func(r *Redis) {
		r.failOpen = failOpen
	}
}

// NewRedis creates a Redis-backed kill-switch manager. Every setting is supplied here
// (see RedisOption), so the instance is fully configured before Start's background
// loops begin reading it.
//
// A nil client (including a typed nil in a non-nil interface) does not fail here, because this
// signature returns no error and a caller that ignored one would keep the panic either way.
// It latches ErrNilClient instead, which every reader and writer reports and which fails closed
// — the strongest posture available without the caller's cooperation. A DECORATOR wrapping a nil
// client is not caught; see redisutil.IsNilClient's scope for why it is not probed for.
//
// The client's keyspace TOPOLOGY is resolved here too, and a client whose type does not establish
// it latches ErrUnknownTopology unless an option declares it. That refusal is the one this
// constructor makes on its own initiative, and it is a trade: it refuses a decorator wrapping a
// perfectly ordinary single-node client until its consumer says so, in exchange for never serving
// a partial kill set as complete. See ErrUnknownTopology.
func NewRedis(client redis.Cmdable, opts ...RedisOption) *Redis {
	r := &Redis{
		client:            client,
		killedAgents:      make(map[string]bool),
		killedSessions:    make(map[string]bool),
		revokedJTIs:       make(map[string]bool),
		reconcileInterval: defaultReconcileInterval,
		sessionKillTTL:    defaultSessionKillTTL,
	}
	r.topology, r.shardFanOut = redisutil.ClassifyTopology(client)
	// Options run before the topology is settled: a declaration is one of the two inputs
	// resolveTopology weighs, not an override applied after the fact.
	for _, opt := range opts {
		opt(r)
	}
	r.wiringErr = r.resolveTopology(redisutil.IsNilClient(client))
	return r
}

// resolveTopology settles the client's keyspace topology from what its concrete type established
// and what the consumer declared, returning the wiring fault to latch when the two cannot be
// settled into one answer.
//
// A declaration FILLS an unknown topology and never OVERRIDES an established one. That asymmetry
// is the whole point: applied unconditionally, WithSingleNodeKeyspace() beside a real cluster
// client would throw away a working fan-out, leave nothing latched, and put the backend back to
// scanning one shard and reporting the result as the whole kill set — reachable through the very
// option added to prevent it. A contradiction is therefore a wiring error rather than a winner.
//
// nilClient is passed rather than re-derived: ClassifyTopology already asked, and a nil client is
// reported ahead of any topology because it has none and the derived cause would send an operator
// looking for a wrapper that is not there.
func (r *Redis) resolveTopology(nilClient bool) error {
	switch {
	case nilClient:
		return ErrNilClient
	case r.declared == redisutil.TopologyUnknown:
		if r.topology == redisutil.TopologyUnknown {
			return ErrUnknownTopology
		}
	case r.topology == redisutil.TopologyUnknown:
		// The case the options exist for: the type established nothing, the consumer knows.
		r.topology, r.shardFanOut = r.declared, r.declaredFanOut
	case r.declared != r.topology:
		return fmt.Errorf("%w: declared %s, but the client's own type is %s", ErrTopologyContradicted, r.declared, r.topology)
	}
	return nil
}

// Start begins the pub/sub subscription for state synchronization. Call once at startup.
// It is idempotent: repeated calls launch the listener and reconcile loop only once (a
// second call would otherwise overwrite r.cancel and run duplicate loops).
func (r *Redis) Start(ctx context.Context) {
	gained := r.startUnderLifeMu(ctx)
	// The initial snapshot's revocations are delivered with lifeMu RELEASED, for the reason
	// refreshState releases refreshMu first: a callback may call back into the Manager, and
	// Stop takes lifeMu — an observer reacting to a startup-time kill by stopping the switch
	// would otherwise deadlock against the Start that is notifying it. Delivering after the
	// whole body also means such a callback sees a started switch rather than the
	// fail-closed unstarted answer.
	r.notifyRevocations(gained)
}

// startUnderLifeMu is Start's body, run under lifeMu, returning the initial snapshot's
// revocations for Start to deliver once the lock is released.
//
// lifeMu is held across the WHOLE body so a concurrent Stop blocks until cancel is
// published and both goroutines are registered, ordering every wg.Add before Stop's
// wg.Wait.
func (r *Redis) startUnderLifeMu(ctx context.Context) []Revocation {
	r.lifeMu.Lock()
	defer r.lifeMu.Unlock()
	// Start at most once. If Stop already ran, do not start either: launching
	// goroutines now would orphan them beyond Stop's reach.
	if r.startedOnce || r.stopped {
		return nil
	}
	// A latched wiring fault means this backend can never confirm its kill set — the client
	// would panic on every command, or the servers holding the keyspace cannot be enumerated —
	// so nothing is subscribed and no goroutine is launched. started stays false and every
	// reader reports the cause (fail closed) instead of a cache nobody can refresh. The message
	// names no specific cause: there is more than one, and the one that applies rides the error
	// attribute rather than being restated (wrongly) in prose.
	if r.wiringErr != nil {
		if r.logger != nil {
			r.logger.Error("kill switch: wiring fault; the switch is permanently degraded and every check fails closed",
				slog.String("error", r.wiringErr.Error()))
		}
		return nil
	}
	r.startedOnce = true

	subCtx, cancel := context.WithCancel(ctx)
	// Write under r.mu so handlePubSubMessage and ShouldBlock, which read them under the
	// same lock, have a consistent view.
	r.mu.Lock()
	r.cancel = cancel
	r.runCtx = subCtx
	r.refreshTrigger = make(chan struct{}, 1)
	r.mu.Unlock()

	// Subscribe BEFORE the initial snapshot and confirm it is active first: otherwise a
	// kill published in the handoff window would reach neither the committed cache nor
	// any subscriber. Subscribing first means it is either delivered (bumping cacheGen,
	// forcing the in-flight refreshState to re-read) or captured by the snapshot.
	if sub, ok := r.client.(pubSubClient); ok {
		pubsub, err := r.subscribeConfirmed(subCtx, sub)
		if err != nil {
			if r.logger != nil {
				// Degraded, but NOT for the process's lifetime: resubscribeLoop keeps
				// retrying in the background.
				r.logger.Warn("kill switch: pub/sub subscription could not be confirmed; converging state on the periodic reconcile only while the subscription is retried in the background",
					slog.String("error", err.Error()))
			}
			// Retry off the Start goroutine: blocking here would extend the window in
			// which a concurrent Stop cannot reach r.cancel, the deadlock
			// subscribeConfirmTimeout exists to bound.
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
		// The client does not implement Subscribe, so kill events will only converge on
		// the periodic reconcile tick; surface it so the degraded path is not silent.
		r.logger.Warn("kill switch: redis client does not support pub/sub; kill events will propagate on the periodic reconcile only",
			slog.String("clientType", fmt.Sprintf("%T", r.client)),
			slog.Duration("reconcileInterval", r.reconcileInterval))
	}

	// Load initial state. On failure the switch starts degraded (blocking in
	// fail-closed, allowing the empty cache in fail-open) and self-corrects later.
	// serializedRefresh, not refreshState: the revocations it finds are returned to Start
	// and delivered outside lifeMu (see there).
	gained, err := r.serializedRefresh(subCtx)
	if err != nil {
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

	return gained
}

// reconcileLoop periodically refreshes the local cache from Redis so kill events lost by
// pub/sub, and fail-open state from a cold start, converge within one interval.
//
// It also re-publishes the session-kill TTL, riding this tick rather than owning a timer
// (adds a command, not new background activity), deliberately NOT folded into
// reconcileRefresh — a pub/sub resync also calls that, and a kill event should converge
// the cache, not trigger a config write.
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
			// Skip the advisory re-publish when the refresh just failed: two more round
			// trips are guaranteed to fail too, burning the timeout the goroutine needs to
			// converge kill state the moment Redis returns. The key's expiry tolerates
			// missed ticks.
			if !r.lastRefreshFailed() {
				r.refreshPublishedSessionKillTTL(ctx)
			}
		}
	}
}

// drainRefreshTrigger consumes the coalescing refreshTrigger channel and runs a full
// reconcileRefresh per signal, moving the SCAN off the listener goroutine so real-time
// kill events keep flowing during a reset/unknown-triggered scan.
func (r *Redis) drainRefreshTrigger(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.refreshTrigger:
			// A nil client never reaches here: Start refuses to launch this loop for one.
			r.reconcileRefresh(ctx)
		}
	}
}

// reconcileRefresh runs a background state refresh (reconcile tick or pub/sub resync) and
// logs edge-triggered: one warning on healthy->failing, one notice on recovery, so a
// sustained outage does not log every tick. HealthStatus() is the authoritative signal.
func (r *Redis) reconcileRefresh(ctx context.Context) {
	_ = r.refreshState(ctx)
	if r.logger == nil {
		return
	}
	// Decide the log edge from the committed lastRefreshErr, not this call's local
	// result: the ticker and a pub/sub resync can call this concurrently, and reading
	// committed state keeps the breadcrumb consistent when their refreshes interleave.
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

// lastRefreshFailed reports whether the most recent background refresh could not confirm
// state against Redis. Read under the same lock that commits it, so the reconcile loop
// sees the outcome of the refresh it just ran rather than a torn value.
func (r *Redis) lastRefreshFailed() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.lastRefreshErr != nil
}

// Stop cancels the pub/sub subscription and blocks until all background goroutines have
// exited, so a caller may free the client or logger once Stop returns. Safe before,
// concurrently with, or after Start, from any goroutine: lifeMu serializes it against the
// whole Start body.
func (r *Redis) Stop() {
	// Take lifeMu to order against the whole Start body: setting stopped makes a
	// not-yet-started Start a no-op, and Start's wg.Add calls happen-before the
	// wg.Wait below.
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
// succeeded — the public health-probe API, letting embedders poll healthy vs degraded
// without an extra refreshState round-trip. See ADR-0003 for the fail-open/closed choice.
func (r *Redis) HealthStatus() error {
	// Mirror ShouldBlock's gate ORDER exactly so a health probe and the data plane never
	// disagree. Checked before r.mu so a never-Started switch (which denies 100% of
	// traffic) reports the wiring cause instead of a misleading nil "healthy".
	if r.wiringErr != nil {
		return r.wiringErr
	}
	if !r.started.Load() {
		return ErrNotStarted
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	switch r.livenessLocked() {
	case killStopped:
		// Report the liveness cause, not the stale refresh error Stop's cancellation
		// latched — a permanently frozen switch, not a transient outage.
		return ErrStopped
	case killRefreshFailed:
		// The RAW error, unlike ShouldBlock's sanitized sentinel: this is the operator's
		// channel, where connection detail is what makes it actionable.
		return r.lastRefreshErr
	case killStale:
		// No refresh has failed, but none has succeeded recently either — the reconcile
		// loop is not converging, and a probe reporting "ok" here would publish healthy
		// through an outage the data plane is already denying on.
		return fmt.Errorf("killswitch: no successful redis refresh in over %s; the reconcile loop is not converging and cached kill state cannot be confirmed", r.staleness())
	case killLive:
	}
	return nil
}

// ShouldBlock checks if any kill switch is active, using the local cache first. A kill
// present blocks unconditionally even while Redis is degraded; only when nothing matches
// does degraded mode matter (fail-closed denies, fail-open serves the cache). See ADR-0003.
func (r *Redis) ShouldBlock(_ context.Context, subj Subject) (bool, error) {
	// Fail closed until Start has seeded the cache: an unstarted switch has an empty
	// cache and nil lastRefreshErr, indistinguishable from an all-clear, so a NewRedis
	// wired in but never Started would otherwise ignore every kill in Redis silently.
	// Ahead of the started gate: a nil client is a permanent wiring fault, and reporting it
	// as "never started" would send an operator looking for a missing Start call.
	if r.wiringErr != nil {
		return false, r.wiringErr
	}
	if !r.started.Load() {
		return false, ErrNotStarted
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.globalActive {
		return true, nil
	}
	// Walked in declaration order, which is the same order InMemory walks, so the two
	// backends attribute a request that matches several dimensions to the same one.
	for i := range killDimensions {
		dim := &killDimensions[i]
		if id := dim.subject(subj); id != "" && dim.cache(r)[id] {
			return true, nil
		}
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

// killLiveness classifies why a NON-MATCH cannot be served as a confident all-clear — the
// single definition of that gate chain, shared by ShouldBlock and HealthStatus (which map
// each state to a different ERROR VALUE, sanitized vs raw) so the two cannot disagree.
type killLiveness int

const (
	killLive          killLiveness = iota // cache is confirmed and converging
	killStopped                           // Start context canceled; can never converge again
	killRefreshFailed                     // last refresh ran and failed
	killStale                             // no refresh has failed, but none has succeeded recently either
)

// livenessLocked classifies the cache's confidence. Caller must hold at least mu.RLock.
// The not-started case is deliberately NOT here: r.started is atomic and both callers
// check it before taking mu.
func (r *Redis) livenessLocked() killLiveness {
	// Liveness before transient health: once the Start context is canceled the
	// convergence loops have exited (a PERMANENT, more actionable cause than a transient
	// outage). Stop's cancellation also latches context.Canceled as lastRefreshErr, so a
	// stopped switch is frequently ALSO "degraded"; this ordering reports the real one.
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
// end-to-end (a GET plus two retried SCAN loops, none of it proportional to the
// reconcile interval), so the staleness budget's TOTAL denial doesn't get more likely
// the more an operator lowers the interval for faster kill propagation.
const maxRefreshCycleBudget = 30 * time.Second

// staleness returns how old a confirmed refresh may be before the cache is treated as
// unconfirmed: two reconcile intervals (one missed tick is jitter, two means the loop
// isn't converging), floored at one interval plus a refresh-cycle budget since the stamp
// is set on COMPLETION, so interval + cycle is legitimate even when healthy.
//
// The floor trades against revocation latency in the one case staleness is the sole
// detector — a HUNG (not erroring) refresh — but is still the right default: without it,
// a healthy Redis whose ordinary cycle outran two short intervals would be judged stale
// and fail-closed mode would deny ALL traffic, a certain outage traded against a rare one.
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
// Caller must hold at least a read lock on mu. A zero lastRefreshOK is NOT reported as
// stale: the started/stopped guards already cover the genuinely-unseeded case, and
// reporting stale on zero would turn a healthy freshly-started switch into a denial.
func (r *Redis) staleLocked() bool {
	if r.lastRefreshOK.IsZero() {
		return false
	}
	return r.clock().Sub(r.lastRefreshOK) > r.staleness()
}

// ActivateGlobal activates the global kill switch.
func (r *Redis) ActivateGlobal(ctx context.Context) error {
	if r.wiringErr != nil {
		return r.wiringErr
	}
	if err := r.client.Set(ctx, redisGlobalKey, "1", 0).Err(); err != nil {
		return err
	}
	// Update the local cache BEFORE publishing so the issuing instance is never in a
	// fail-open window: a ShouldBlock between the write and the publish must already
	// observe the kill.
	r.mu.Lock()
	gained := !r.globalActive
	r.globalActive = true
	r.cacheGen++
	r.mu.Unlock()
	// Notify outside the lock, mirroring InMemory, and only on a state CHANGE: this
	// instance's own pub/sub echo dedups identically against the now-updated cache, so
	// this is the only delivery a kill issued through THIS Manager ever gets.
	if gained {
		r.observers.notify(Revocation{Global: true})
	}
	return r.publish(ctx, "global:activate")
}

// DeactivateGlobal deactivates the global kill switch.
func (r *Redis) DeactivateGlobal(ctx context.Context) error {
	if r.wiringErr != nil {
		return r.wiringErr
	}
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

// setBlock is the shared body of every per-id kill and revive. The two axes are the VERB
// (kill or revive) and the DIMENSION; the key prefix, publish channel, cache map, TTL policy,
// observer event and error-message names are all read off the dimension's declaration, so a
// caller cannot mismatch them — write the agent key while publishing on the session channel,
// or add a dimension whose revocation nothing ever notifies. An empty id is rejected rather
// than writing the bare prefix key and triggering a spurious full refresh on every replica.
func (r *Redis) setBlock(ctx context.Context, kill bool, dim *killDimension, id string) error {
	if r.wiringErr != nil {
		return r.wiringErr
	}
	verb := "Kill"
	if !kill {
		verb = "Revive"
	}
	if id == "" {
		return fmt.Errorf("killswitch: %s%s: %s must not be empty", verb, dim.entity, dim.idField)
	}
	key := dim.keyPrefix + id
	var err error
	if kill {
		err = r.client.Set(ctx, key, "1", dim.ttl(r.sessionKillTTL)).Err()
	} else {
		err = r.client.Del(ctx, key).Err()
	}
	if err != nil {
		return err
	}
	// The map is selected under the lock so a concurrent Reset swap is not raced.
	r.mu.Lock()
	cache := dim.cache(r)
	gained := kill && !cache[id]
	if kill {
		cache[id] = true
	} else {
		delete(cache, id)
	}
	r.cacheGen++
	r.mu.Unlock()
	// Notify outside the lock, mirroring InMemory, and only on a kill that actually
	// changed local state: this instance's own pub/sub echo dedups identically against
	// the now-updated cache, so this is the only delivery a local kill ever gets.
	if gained {
		r.observers.notify(dim.event(id))
	}
	// Channel name mirrors the durable-key dimension: "<dimension>:<action>:<id>".
	action := "kill"
	if !kill {
		action = "revive"
	}
	return r.publish(ctx, dim.name+":"+action+":"+id)
}

// mustDimension returns the declared dimension by name for this package's own call sites,
// which pass a literal that killDimensions is required to contain.
//
// A panic rather than an error return: a missing entry is a build-time authoring mistake in
// this file, not a runtime condition a caller could handle, and the table test asserts every
// name these methods pass is declared — so this is unreachable in a build that tests.
func mustDimension(name string) *killDimension {
	dim, ok := dimensionByName(name)
	if !ok {
		panic("killswitch: undeclared kill dimension " + name)
	}
	return dim
}

// KillAgent blocks the specified agent.
func (r *Redis) KillAgent(ctx context.Context, agentID string) error {
	return r.setBlock(ctx, true, mustDimension("agent"), agentID)
}

// ReviveAgent removes the kill on the specified agent.
func (r *Redis) ReviveAgent(ctx context.Context, agentID string) error {
	return r.setBlock(ctx, false, mustDimension("agent"), agentID)
}

// KillSession blocks the specified session.
func (r *Redis) KillSession(ctx context.Context, sessionID string) error {
	return r.setBlock(ctx, true, mustDimension("session"), sessionID)
}

// ReviveSession removes the kill on the specified session.
func (r *Redis) ReviveSession(ctx context.Context, sessionID string) error {
	return r.setBlock(ctx, false, mustDimension("session"), sessionID)
}

// RevokeJTI blocks every request presenting the bearer token with this id.
func (r *Redis) RevokeJTI(ctx context.Context, jti string) error {
	return r.setBlock(ctx, true, mustDimension("jti"), jti)
}

// ReviveJTI removes the revocation on the specified token id.
func (r *Redis) ReviveJTI(ctx context.Context, jti string) error {
	return r.setBlock(ctx, false, mustDimension("jti"), jti)
}

// Reset clears all kill-switch state.
func (r *Redis) Reset(ctx context.Context) error {
	if r.wiringErr != nil {
		return r.wiringErr
	}
	// Delete the global key; propagate the error so a silent failure does not leave
	// the global switch active while the caller believes it cleared.
	if err := r.client.Del(ctx, redisGlobalKey).Err(); err != nil {
		return fmt.Errorf("kill switch reset: delete global key: %w", err)
	}

	// Delete every dimension's keys, propagating errors. In-memory state is cleared only
	// after all Redis deletions succeed, keeping it consistent with Redis. Over the
	// declaration, so a dimension added later is swept rather than left behind in Redis to
	// be re-loaded by the next reconcile — a Reset that does not reset.
	for i := range killDimensions {
		if err := r.deleteByPrefix(ctx, killDimensions[i].keyPrefix); err != nil {
			return err
		}
	}

	// Capture the publish error but finish the local clear + reseed first: the durable
	// deletions already succeeded, so a publish failure must not abort the reset (it
	// only means replicas converge on the next reconcile).
	pubErr := r.publish(ctx, "reset")

	r.mu.Lock()
	r.globalActive = false
	for _, dim := range killDimensions {
		dim.replace(r, make(map[string]bool))
	}
	r.cacheGen++
	r.mu.Unlock()

	// Re-read Redis after the clear to re-seed any kill that landed between the delete
	// sweep and now (a concurrent KillAgent's SET could otherwise be wiped by the clear
	// above and stay invisible until the next reconcile). Best-effort: a transient
	// refresh error must not fail an otherwise-complete Reset.
	//
	// Use runCtx, not the caller's ctx: Reset's durable work is already done, so a caller
	// ctx canceled right after Reset returns must not be misattributed by refreshState as
	// a genuine Redis failure, tripping ShouldBlock's fail-closed path on a healthy
	// backend. runCtx is nil only before Start, when there's no longer-lived context to prefer.
	reseedCtx := ctx //nolint:contextcheck // reseedCtx is deliberately reassigned to r.runCtx below when set: the switch's own background-lifetime context (Start), not derived from this function's ctx parameter, so a caller ctx canceled right after Reset returns cannot be misattributed as a refresh failure (see the comment above).
	// runCtx is written under r.mu in Start, so read it under r.mu too (RLock is safe
	// here since this goroutine holds no lock; a caller already holding r.mu must read
	// the field directly instead).
	r.mu.RLock()
	runCtx := r.runCtx
	r.mu.RUnlock()
	if runCtx != nil {
		reseedCtx = runCtx
	}
	_ = r.refreshState(reseedCtx)
	return pubErr
}

// Status returns the current kill-switch state from the LOCAL cache. It answers the same
// question ShouldBlock's NON-MATCH arm does — "this is the whole kill set" — so it refuses
// on the same causes, in the same order, with the same sentinels, and honors failOpen
// identically: a snapshot from a cache that cannot be confirmed is byte-identical to a
// confirmed all-clear, which is the one answer an unconfirmable cache must not give.
// Reading the gate chain through livenessLocked rather than restating it is what keeps the
// three readers from disagreeing about the same instance.
func (r *Redis) Status(_ context.Context) (*Status, error) {
	// Before mu, as the siblings do: a never-Started switch has no cache to lock over.
	if r.wiringErr != nil {
		return nil, r.wiringErr
	}
	if !r.started.Load() {
		return nil, ErrNotStarted
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	switch r.livenessLocked() {
	case killStopped:
		return nil, ErrStopped
	case killRefreshFailed, killStale:
		// The sanitized sentinel, not HealthStatus's raw error: a snapshot may be rendered
		// to a caller that is not the operator, so connection detail stays in HealthStatus.
		if !r.failOpen {
			return nil, ErrBackendUnreachable
		}
	case killLive:
	}
	return buildStatusOf(r.globalActive, func(d *killDimension) map[string]bool { return d.cache(r) }), nil
}

// publish broadcasts msg on the kill-switch channel. The durable write and cache update
// already happened, so a publish failure does NOT undo the kill — it only delays remote
// convergence to the next reconcile. Publish is part of redis.Cmdable, so no assertion needed.
//
// No wiringErr check of its own: every caller returns on it before reaching a durable write,
// so one here could only ever be dead code that reads as a live guard.
//
// That same "the durable write already happened" precondition is what makes this the one place
// ErrPublishFailed is stamped: wrapping at each caller would be four copies of a judgment this
// function's own contract already states, and the next writer added would inherit the bare error.
func (r *Redis) publish(ctx context.Context, msg string) error {
	if err := r.client.Publish(ctx, redisPubSubChan, msg).Err(); err != nil {
		return fmt.Errorf("%w: %w", ErrPublishFailed, err)
	}
	return nil
}

// recordRefreshErr stores err as the last refresh error and returns it, so the refresh's
// failure paths share one stamp-and-return. Every scan-time caller is inside
// serializedRefresh, which holds refreshMu for its whole body, so lastRefreshErr has a
// single serialized writer.
func (r *Redis) recordRefreshErr(err error) error {
	r.mu.Lock()
	r.lastRefreshErr = err
	r.mu.Unlock()
	return err
}

func (r *Redis) refreshState(ctx context.Context) error {
	if r.wiringErr != nil {
		return r.recordRefreshErr(r.wiringErr)
	}
	gained, err := r.serializedRefresh(ctx)
	// Observers run with refreshMu RELEASED, matching the pub/sub delivery path: the
	// contract says a callback may call back in, and refreshMu is neither reentrant nor
	// ctx-aware, so a callback reaching any refresh-taking method (Reset re-seeds through
	// refreshState) would self-deadlock — wedging the reconcile goroutine for the
	// process's life, on the emergency-stop path, and hanging a later Stop on wg.Wait.
	r.notifyRevocations(gained)
	return err
}

// serializedRefresh is refreshState's scan-and-commit half, run under refreshMu. It
// RETURNS the revocations its commit added rather than delivering them, so the lock is
// released before any observer runs.
func (r *Redis) serializedRefresh(ctx context.Context) ([]Revocation, error) {
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
			return nil, r.recordRefreshErr(err)
		}
		newGlobal := err == nil && val == "1"

		scanned := make(map[string]map[string]bool, len(killDimensions))
		for i := range killDimensions {
			dim := &killDimensions[i]
			found := make(map[string]bool)
			if err := r.scanPrefix(ctx, dim.keyPrefix, found); err != nil {
				return nil, r.recordRefreshErr(err)
			}
			scanned[dim.name] = found
		}

		r.mu.Lock()
		if r.cacheGen == startGen {
			// No cache mutation raced the scan: the snapshot is consistent.
			gained := r.commitRefreshLocked(newGlobal, scanned)
			r.mu.Unlock()
			return gained, nil
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
		for i := range killDimensions {
			dim := &killDimensions[i]
			for id := range dim.cache(r) {
				scanned[dim.name][id] = true
			}
		}
		gained := r.commitRefreshLocked(newGlobal || r.globalActive, scanned)
		r.mu.Unlock()
		return gained, nil
	}
}

// notifyRevocations calls the observers for every revocation a refresh added. Always
// OUTSIDE both r.mu and refreshMu, since an observer's documented response is to call back
// into the Manager.
func (r *Redis) notifyRevocations(gained []Revocation) {
	for _, ev := range gained {
		r.observers.notify(ev)
	}
}

// commitRefreshLocked installs a completed scan's snapshot and stamps the refresh as
// healthy. Caller must hold r.mu for writing. Shared by both commit sites so the health
// stamp (lastRefreshErr cleared, lastRefreshOK set) cannot drift between them — the
// staleness gate denies ALL traffic in fail-closed mode when it is not maintained.
//
// It returns the revocations the snapshot ADDS, for the caller to notify after releasing
// r.mu AND refreshMu. The reconcile loop fires observers too, not just pub/sub, because a
// publish that never arrives would otherwise leave a consumer with nothing to reclaim on
// (and the sessionIdleTimeoutMs: 0 case has no sweep at all).
func (r *Redis) commitRefreshLocked(global bool, scanned map[string]map[string]bool) []Revocation {
	var gained []Revocation
	if global && !r.globalActive {
		gained = append(gained, Revocation{Global: true})
	}
	for i := range killDimensions {
		dim := &killDimensions[i]
		held := dim.cache(r)
		for id := range scanned[dim.name] {
			if !held[id] {
				gained = append(gained, dim.event(id))
			}
		}
	}

	r.globalActive = global
	for i := range killDimensions {
		dim := &killDimensions[i]
		// A dimension the scan did not populate keeps its existing cache rather than being
		// replaced with a nil map. Both callers fill every key today, so this cannot fire —
		// but the two failure modes if one ever stops are a PANIC on the next kill (writing
		// to a nil map, inside the emergency stop) and a silently emptied kill set. Keeping
		// what is held is fail-closed and costs one lookup per reconcile.
		found, ok := scanned[dim.name]
		if !ok {
			continue
		}
		dim.replace(r, found)
	}
	r.lastRefreshErr = nil
	r.lastRefreshOK = r.clock()
	return gained
}

// scanner is the subset of a Redis node needed to enumerate keys by prefix. A PARAMETER
// type for the per-node helpers (called with both r.client and an individual
// ForEachMaster master), not a capability test.
type scanner interface {
	Scan(ctx context.Context, cursor uint64, match string, count int64) *redis.ScanCmd
}

func (r *Redis) scanPrefix(ctx context.Context, prefix string, target map[string]bool) error {
	// A keyless SCAN on a client that shards the keyspace reaches ONE server of several, so a
	// full enumeration must visit each and merge the scans — otherwise refreshState loads a
	// partial kill set and reports healthy, a fail-open on the emergency stop.
	//
	// The mutex is taken unconditionally: on the single-node path it is uncontended, and the
	// fan-out below is the only thing that can call fn concurrently, so gating it on the stored
	// topology would buy one atomic on a background loop for a second read of that field.
	var mu sync.Mutex
	return r.forEachNode(ctx, func(ctx context.Context, node redis.Cmdable) error {
		return scanNode(ctx, node, prefix, target, &mu)
	})
}

// forEachNode runs fn against every server holding part of this keyspace: each shard of a
// sharding client, or the one node otherwise. The ONE place that decision is applied, so the two
// keyless-command sites cannot drift — the shape they were in before, when one of them fell
// through to a single-node SCAN for a *redis.Ring and loaded whichever shard go-redis picked.
//
// The topology was RESOLVED at construction (from the client's type, or from the consumer's own
// declaration) and a client whose topology could not be established never reaches here: it
// latches ErrUnknownTopology, which every entry point above refuses on. So a nil iterator here
// means "the whole keyspace is on one server", established, rather than "nothing is known".
//
// That is a fact about the CLIENT, and it says nothing about any one pass over it. Whether the
// enumeration actually reached every server is the iterator's own answer, per call — the
// distinction a *redis.Ring lives in, whose library iterator skips a shard it has voted down and
// returns nil. See ErrIncompleteEnumeration for the error that closes it and where it surfaces.
//
// Reachable only by a LIBRARY consumer wiring this backend on its own: the shipped binary is
// single-node, and callcounter.NewRedis refuses a sharding client outright.
func (r *Redis) forEachNode(ctx context.Context, fn func(context.Context, redis.Cmdable) error) error {
	// Backstop only: NewRedis latches ErrNilClient and every entry point above refuses before
	// reaching here, so this catches a *Redis assembled by some other means (the package's own
	// tests) rather than anything a consumer can reach.
	if redisutil.IsNilClient(r.client) {
		return ErrNilClient
	}
	if r.shardFanOut != nil {
		return r.shardFanOut(ctx, func(ctx context.Context, node *redis.Client) error { return fn(ctx, node) })
	}
	return fn(ctx, r.client)
}

// scanNode SCANs a single node for keys matching prefix and records the stripped IDs in
// target. mu, when non-nil, guards target for concurrent callers (ForEachMaster fan-out).
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
	// Through the same resolver as scanPrefix: a sharding client SCANs only one server, so a
	// reset must visit each or Reset() reports success while leaving kills on the others.
	return r.forEachNode(ctx, func(ctx context.Context, node redis.Cmdable) error {
		return deleteNodeKeys(ctx, node, prefix)
	})
}

// deleteNodeKeys SCANs a single node and deletes keys one at a time: a multi-key DEL can
// span cluster hash slots and fail CROSSSLOT, whereas per-key DEL is always slot-safe.
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

// subscribeConfirmed subscribes and blocks until the server confirms it, so a caller may
// order a state snapshot strictly after. Bounded by subscribeConfirmTimeout: pubsub.Receive's
// deadline-less read would otherwise block forever on a blackholed connection, deadlocking
// Start's concurrent Stop. On failure the pubsub is closed to avoid leaking it across a retry.
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

// supervisePubSub consumes a confirmed subscription and, if lost while ctx is still live,
// hands off to resubscribeLoop — an unexpected channel close is recoverable, not a reason
// to spend the rest of the process reconcile-only.
func (r *Redis) supervisePubSub(ctx context.Context, sub pubSubClient, pubsub *redis.PubSub) {
	r.listenPubSub(ctx, pubsub)
	if ctx.Err() != nil {
		return
	}
	r.resubscribeLoop(ctx, sub)
}

// resubscribeLoop re-establishes the subscription in the background with capped
// exponential backoff, repeating for as long as ctx is live. Runs off the Start goroutine
// so retrying never extends the lifeMu hold subscribeConfirmTimeout bounds. Only the
// recovery edge is logged, not each retry, matching reconcileRefresh's breadcrumbs.
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
		// Pub/sub is at-most-once, so events published while down were missed; reconcile
		// immediately rather than wait for the next tick. Ordered AFTER the confirmed
		// subscribe so a racing event lands on the live subscription, not the handoff window.
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
				// go-redis closes this channel only via an explicit pubsub.Close() (transient
				// drops auto-reconnect without closing it); reaching here with ctx still live
				// means an unexpected loss of the real-time path. State still converges on
				// the reconcile loop and supervisePubSub resubscribes, but surface it.
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
// Message format: "global:activate", "global:deactivate", "reset", and
// "<dimension>:kill:<id>" / "<dimension>:revive:<id>" for every entry in killDimensions —
// the same names setBlock publishes under, read off the same declaration.
func (r *Redis) handlePubSubMessage(payload string) {
	r.mu.Lock()
	shouldRefresh := false
	// gained collects the revocations this event ADDS, notified after the lock is
	// released. Only real additions: re-announcing a kill this instance already holds
	// reclaims nothing.
	var gained []Revocation

	switch payload {
	case "global:activate":
		if !r.globalActive {
			gained = append(gained, Revocation{Global: true})
		}
		r.globalActive = true
	case "global:deactivate":
		r.globalActive = false
	case "reset":
		r.globalActive = false
		for i := range killDimensions {
			killDimensions[i].replace(r, make(map[string]bool))
		}
		// Re-read Redis after the clear (as Reset() does): a kill that raced the
		// publisher's delete sweep could otherwise stay hidden on this replica.
		shouldRefresh = true
	default:
		// Prefixed events carry a non-empty id; cutKillID returns "" for a non-match
		// or a bare prefix, so an unrecognized message falls through to a full refresh.
		//
		// Walked over the declaration rather than spelled out per dimension. A dimension
		// missing from a hand-written chain does not fail loudly — it falls to the refresh
		// arm below, so the revocation still converges on the next reconcile tick while
		// real-time propagation is silently lost for that axis alone. That is the shape of
		// bug nobody finds until an operator revokes a credential mid-incident.
		handled := false
		for i := range killDimensions {
			dim := &killDimensions[i]
			if id := cutKillID(payload, dim.name+":kill:"); id != "" {
				cache := dim.cache(r)
				if !cache[id] {
					gained = append(gained, dim.event(id))
				}
				cache[id] = true
				handled = true
				break
			}
			if id := cutKillID(payload, dim.name+":revive:"); id != "" {
				delete(dim.cache(r), id)
				handled = true
				break
			}
		}
		if !handled {
			// Unknown message — trigger a full refresh from Redis.
			shouldRefresh = true
		}
	}
	// Bump the cache generation for every event so a concurrent in-flight refreshState
	// discards its now-stale snapshot rather than overwrite this update.
	r.cacheGen++
	// Snapshot under r.mu to avoid a race with Start, which creates it under the same lock.
	var trigger chan struct{}
	if shouldRefresh {
		trigger = r.refreshTrigger
	}
	r.mu.Unlock()

	// Signal drainRefreshTrigger rather than run the SCAN inline, so a reset/unknown
	// event cannot block the single real-time consumer on Redis I/O.
	if shouldRefresh && trigger != nil {
		select {
		case trigger <- struct{}{}:
		default:
		}
	}
	// Runs on the SINGLE real-time consumer goroutine, why an observer must not block.
	// Not fanned out to a goroutine per event: that would reorder revocations against
	// the cache updates that justify them.
	for _, ev := range gained {
		r.observers.notify(ev)
	}
}

// ObserveRevocations implements [Manager]. Observers are called from the pub/sub listener
// and the reconcile loop's commit, so a kill reaches one whether or not its publish was
// delivered — both callers are single goroutines the must-not-block rule protects.
func (r *Redis) ObserveRevocations(fn func(Revocation)) func() { return r.observers.observe(fn) }

// cutKillID returns the id carried by a prefixed event (e.g. "agent:kill:foo" with prefix
// "agent:kill:" yields "foo"), or "" for a non-match OR an empty id, so a bare
// "agent:kill:" falls through to a full refresh rather than matching.
func cutKillID(payload, prefix string) string {
	if id, ok := strings.CutPrefix(payload, prefix); ok {
		return id
	}
	return ""
}
