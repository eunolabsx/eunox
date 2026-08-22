// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Lifecycle-hardening regressions for the Redis kill switch: the Start/Stop
// deadlock on a blackholed pub/sub subscription, and the stopped-vs-degraded
// diagnostic ordering in ShouldBlock / HealthStatus.

package killswitch

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

// TestRedis_Start_BlackholedSubscribe_DoesNotWedgeStop is the regression for the
// Start/Stop deadlock. pubsub.Receive issues a deadline-less socket read, so a
// connection that accepts the dial and the SUBSCRIBE write but never sends the
// confirmation would block Start forever while it holds lifeMu — and a concurrent Stop,
// which must take lifeMu to reach r.cancel, would then deadlock. Bounding the
// confirmation read (subscribeConfirmTimeout) funnels the hang into reconcile-only
// degraded mode instead, so Start returns and Stop can proceed.
func TestRedis_Start_BlackholedSubscribe_DoesNotWedgeStop(t *testing.T) {
	// A raw TCP server that accepts connections, drains bytes, and never replies:
	// go-redis dials and writes SUBSCRIBE successfully, then blocks awaiting the
	// confirmation that never arrives.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 512)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	// Shrink the confirmation timeout so the test is fast; restore after.
	origTimeout := subscribeConfirmTimeout
	subscribeConfirmTimeout = 200 * time.Millisecond
	defer func() { subscribeConfirmTimeout = origTimeout }()

	client := redis.NewClient(&redis.Options{
		Addr:        ln.Addr().String(),
		DialTimeout: 500 * time.Millisecond,
		ReadTimeout: 200 * time.Millisecond, // bounds the initial refreshState Get against the blackhole
		PoolSize:    1,
	})
	defer func() { _ = client.Close() }()

	r := NewRedis(client)

	// Start must return despite the blackholed subscription: the bounded confirmation
	// read and the read-timeout-bounded initial refresh both give up. Without the bound,
	// Start hangs here forever (and would deadlock the Stop below).
	startDone := make(chan struct{})
	go func() { r.Start(context.Background()); close(startDone) }()
	select {
	case <-startDone:
	case <-time.After(10 * time.Second):
		t.Fatal("Start hung on a blackholed pub/sub subscription (deadline-less Receive held lifeMu)")
	}

	// The real payoff: Stop takes lifeMu and must not deadlock behind a wedged Start.
	stopDone := make(chan struct{})
	go func() { r.Stop(); close(stopDone) }()
	select {
	case <-stopDone:
	case <-time.After(10 * time.Second):
		t.Fatal("Stop deadlocked on lifeMu held across a wedged Start")
	}
}

// TestRedis_ShouldBlock_StoppedReportsErrStopped_NotUnreachable is the regression for
// the stopped-vs-degraded misreport. A dead backend makes the initial refresh fail
// (lastRefreshErr set → "degraded"); after Stop cancels runCtx the switch is
// permanently frozen. ShouldBlock and HealthStatus must both report the liveness cause
// (ErrStopped) rather than the transient-outage-shaped ErrBackendUnreachable — both fail
// closed, so this is diagnostic accuracy, not a security change.
func TestRedis_ShouldBlock_StoppedReportsErrStopped_NotUnreachable(t *testing.T) {
	r := NewRedis(deadClient(t)) // default fail-CLOSED; initial refresh fails
	r.Start(context.Background())
	require.Error(t, r.HealthStatus(),
		"initial refresh against a dead backend must record a health error (degraded)")

	r.Stop() // cancels runCtx → the switch is now frozen, not merely partitioned

	_, err := r.ShouldBlock(context.Background(), Subject{AgentID: "some-agent", SessionID: "some-session"})
	require.ErrorIs(t, err, ErrStopped,
		"a stopped+degraded switch must report ErrStopped (frozen), not ErrBackendUnreachable (transient)")
	require.NotErrorIs(t, err, ErrBackendUnreachable)

	require.ErrorIs(t, r.HealthStatus(), ErrStopped,
		"HealthStatus must agree with ShouldBlock: a stopped switch is frozen, not merely unreachable")
}

// TestRedis_HealthStatus_UnstartedAgreesWithShouldBlock is the regression for the
// health-probe/data-plane split on an unstarted switch. ShouldBlock fails closed with
// ErrNotStarted (a wiring error: the cache was never seeded), so a constructed-but-never-
// Started switch denies every enforced request. HealthStatus must report that too —
// returning nil would let a health endpoint publish "ok" through a total data-plane
// outage, which is the one state where a green probe is most misleading.
func TestRedis_HealthStatus_UnstartedAgreesWithShouldBlock(t *testing.T) {
	t.Parallel()
	r, _ := newTestRedis(t) // reachable backend: only the missing Start is at fault

	_, blockErr := r.ShouldBlock(context.Background(), Subject{AgentID: "some-agent", SessionID: "some-session"})
	require.ErrorIs(t, blockErr, ErrNotStarted,
		"precondition: an unstarted switch denies with ErrNotStarted")
	require.ErrorIs(t, r.HealthStatus(), ErrNotStarted,
		"HealthStatus must agree with ShouldBlock: an unstarted switch is denying everything, not healthy")
}

// TestRedis_Start_FailedSubscribe_RecoversInBackground is the regression for the
// no-retry gap. subscribeConfirmTimeout is a hard cutoff, so a slow-but-healthy Redis
// (failover, load spike) can miss it without being down. Before the background retry,
// that instance ran reconcile-only for its entire lifetime — kill propagation stretched
// from milliseconds to a full reconcile interval until someone restarted the process.
//
// The proxy blackholes the first connections (subscribe confirmation never arrives),
// then starts forwarding to a real miniredis. The assertion is that real-time pub/sub
// delivery resumes with NO restart. It is specifically pub/sub and not the reconcile
// tick that is proven: the reconcile interval is set far beyond the test's lifetime,
// and the event is PUBLISHED without writing the backing key, so a reconcile would
// read "not active" — only the pub/sub handler can set globalActive here.
func TestRedis_Start_FailedSubscribe_RecoversInBackground(t *testing.T) {
	mr := miniredis.NewMiniRedis()
	require.NoError(t, mr.Start())
	defer mr.Close()

	proxy := newTogglingProxy(t, mr.Addr())
	defer proxy.Close()

	// Shrink the confirmation timeout and the retry backoff so the test is fast.
	origTimeout, origDelay := subscribeConfirmTimeout, subscribeRetryInitialDelay
	subscribeConfirmTimeout = 200 * time.Millisecond
	subscribeRetryInitialDelay = 50 * time.Millisecond
	defer func() {
		subscribeConfirmTimeout, subscribeRetryInitialDelay = origTimeout, origDelay
	}()

	client := redis.NewClient(&redis.Options{
		Addr:        proxy.Addr(),
		DialTimeout: 500 * time.Millisecond,
		ReadTimeout: 300 * time.Millisecond, // bounds the initial refreshState against the blackhole
	})
	defer func() { _ = client.Close() }()

	// A reconcile interval far longer than the test: if globalActive ever becomes true
	// below, pub/sub delivered it, not the reconcile loop.
	r := NewRedis(client, WithReconcileInterval(time.Hour))
	r.Start(context.Background())
	defer r.Stop()

	// Precondition: the subscription was NOT confirmed, so published events reach
	// nothing — the reconcile-only degraded state the retry has to dig it out of.
	require.Never(t, func() bool {
		mr.Publish(redisPubSubChan, "global:activate")
		r.mu.RLock()
		defer r.mu.RUnlock()
		return r.globalActive
	}, 500*time.Millisecond, 50*time.Millisecond,
		"precondition: the blackholed subscribe must leave the real-time path down")

	proxy.SetBlackhole(false) // Redis is now reachable; the background retry should win

	// Publish (without setting the key) until the cache observes it. Republishing is
	// what makes this deterministic: pub/sub is at-most-once, so an event sent before
	// the resubscribe lands is simply dropped rather than queued.
	require.Eventually(t, func() bool {
		mr.Publish(redisPubSubChan, "global:activate")
		r.mu.RLock()
		defer r.mu.RUnlock()
		return r.globalActive
	}, 15*time.Second, 100*time.Millisecond,
		"pub/sub never recovered: the failed initial subscribe left the instance reconcile-only for its lifetime")
}

// togglingProxy is a TCP proxy that blackholes connections (accept, drain, never
// reply) until SetBlackhole(false), then forwards to upstream. Flipping the flag also
// closes the connections opened while blackholed, so the client redials rather than
// reusing a pooled connection that still points at the drain loop.
type togglingProxy struct {
	ln        net.Listener
	upstream  string
	mu        sync.Mutex
	blackhole bool
	held      []net.Conn
}

func newTogglingProxy(t *testing.T, upstream string) *togglingProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	p := &togglingProxy{ln: ln, upstream: upstream, blackhole: true}
	go p.serve()
	return p
}

func (p *togglingProxy) Addr() string { return p.ln.Addr().String() }

func (p *togglingProxy) Close() { _ = p.ln.Close() }

func (p *togglingProxy) SetBlackhole(on bool) {
	p.mu.Lock()
	p.blackhole = on
	held := p.held
	p.held = nil
	p.mu.Unlock()
	if !on {
		for _, c := range held {
			_ = c.Close()
		}
	}
}

func (p *togglingProxy) serve() {
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.mu.Lock()
		blackhole := p.blackhole
		if blackhole {
			p.held = append(p.held, conn)
		}
		p.mu.Unlock()
		if blackhole {
			go func(c net.Conn) {
				buf := make([]byte, 512)
				for {
					if _, err := c.Read(buf); err != nil {
						_ = c.Close()
						return
					}
				}
			}(conn)
			continue
		}
		go p.forward(conn)
	}
}

func (p *togglingProxy) forward(client net.Conn) {
	up, err := net.Dial("tcp", p.upstream)
	if err != nil {
		_ = client.Close()
		return
	}
	go func() {
		_, _ = io.Copy(up, client)
		_ = up.Close()
	}()
	_, _ = io.Copy(client, up)
	_ = client.Close()
}
