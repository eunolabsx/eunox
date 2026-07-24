// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Lifecycle-hardening regressions for the Redis kill switch: the Start/Stop
// deadlock on a blackholed pub/sub subscription, and the stopped-vs-degraded
// diagnostic ordering in ShouldBlock / HealthStatus.

package killswitch

import (
	"context"
	"net"
	"testing"
	"time"

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

	_, err := r.ShouldBlock(context.Background(), "some-agent", "some-session")
	require.ErrorIs(t, err, ErrStopped,
		"a stopped+degraded switch must report ErrStopped (frozen), not ErrBackendUnreachable (transient)")
	require.NotErrorIs(t, err, ErrBackendUnreachable)

	require.ErrorIs(t, r.HealthStatus(), ErrStopped,
		"HealthStatus must agree with ShouldBlock: a stopped switch is frozen, not merely unreachable")
}
