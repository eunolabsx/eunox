// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// -------------------------------------------------------------------------
// buildRedisClient
// -------------------------------------------------------------------------

func TestBuildRedisClient_EmptyAddr(t *testing.T) {
	_, err := buildRedisClient("", "", false)
	if err == nil {
		t.Fatal("expected error for empty addr, got nil")
	}
}

func TestBuildRedisClient_Success(t *testing.T) {
	mr := miniredis.RunT(t)

	client, err := buildRedisClient(mr.Addr(), "", false)
	if err != nil {
		t.Fatalf("buildRedisClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatalf("ping miniredis: %v", err)
	}
}

func TestBuildRedisClient_TLS(t *testing.T) {
	// Just verify TLS config is set — we do not need a real TLS server.
	client, err := buildRedisClient("localhost:6379", "", true)
	if err != nil {
		t.Fatalf("buildRedisClient with TLS: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	opts := client.Options()
	if opts.TLSConfig == nil {
		t.Fatal("expected TLSConfig to be set when useTLS=true")
	}
}

func TestBuildRedisClient_PasswordSet(t *testing.T) {
	client, err := buildRedisClient("localhost:6379", "secret", false)
	if err != nil {
		t.Fatalf("buildRedisClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	if client.Options().Password != "secret" {
		t.Errorf("expected password %q, got %q", "secret", client.Options().Password)
	}
}

// -------------------------------------------------------------------------
// pingRedis
// -------------------------------------------------------------------------

func TestPingRedis_Success(t *testing.T) {
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	ctx := context.Background()
	if err := pingRedis(ctx, client); err != nil {
		t.Fatalf("pingRedis: %v", err)
	}
}

func TestPingRedis_Failure(t *testing.T) {
	// Point at a port where nothing is listening.
	client := goredis.NewClient(&goredis.Options{
		Addr:        "127.0.0.1:19732",
		DialTimeout: 200 * time.Millisecond,
	})
	t.Cleanup(func() { _ = client.Close() })

	ctx := context.Background()
	if err := pingRedis(ctx, client); err == nil {
		t.Fatal("expected error for unreachable server, got nil")
	}
}

// fakeClusterInfo answers CLUSTER INFO with a canned reply, so the clustered branch is
// reachable without a cluster.
type fakeClusterInfo struct {
	reply string
	err   error
}

func (f fakeClusterInfo) ClusterInfo(context.Context) *goredis.StringCmd {
	return goredis.NewStringResult(f.reply, f.err)
}

// TestCheckRedisNotClustered pins the startup topology check. The binary builds a single-node
// client, so its spelling of the unsupported wiring is an ordinary client aimed at a clustered
// server: every command eunox issues works there until a policy carries two quota bounds, and
// the multi-key admission is then refused with CROSSSLOT in production.
func TestCheckRedisNotClustered(t *testing.T) {
	cases := []struct {
		name       string
		lookup     clusterInfoLookup
		wantRefuse bool
	}{
		{"clustered", fakeClusterInfo{reply: "cluster_enabled:1\r\ncluster_state:ok\r\n"}, true},
		{"standalone", fakeClusterInfo{reply: "cluster_enabled:0\r\n"}, false},
		// A server without CLUSTER INFO (or one refusing it) is treated as unclustered: only a
		// definitive cluster_enabled:1 is grounds to refuse, or startup would fail against
		// every Redis-protocol server that answers the commands eunox actually issues.
		{"command unsupported", fakeClusterInfo{err: errors.New("ERR unknown command 'cluster'")}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkRedisNotClustered(context.Background(), tc.lookup)
			if tc.wantRefuse {
				if !errors.Is(err, callcounter.ErrClusterUnsupported) {
					t.Fatalf("err = %v, want %v", err, callcounter.ErrClusterUnsupported)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v, want nil (startup must not fail against a non-cluster server)", err)
			}
		})
	}
}

// -------------------------------------------------------------------------
// callcounter.Redis integration
// -------------------------------------------------------------------------

func TestRedisCallCounter_Integration(t *testing.T) {
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	counter, err := callcounter.NewRedis(client)
	if err != nil {
		t.Fatalf("NewRedis: %v", err)
	}
	ctx := context.Background()

	// histCap is a retention cap above this test's counts, so IncrementAndGet's
	// most-recent-N trimming does not interfere with the assertions.
	const histCap = 1 << 20

	n, err := counter.IncrementAndGet(ctx, "tool:read_file", 60, histCap)
	if err != nil {
		t.Fatalf("IncrementAndGet: %v", err)
	}
	if n != 1 {
		t.Errorf("got %d, want 1", n)
	}

	n, err = counter.IncrementAndGet(ctx, "tool:read_file", 60, histCap)
	if err != nil {
		t.Fatalf("IncrementAndGet: %v", err)
	}
	if n != 2 {
		t.Errorf("got %d, want 2", n)
	}

	// Different key is independent.
	n2, err := counter.IncrementAndGet(ctx, "tool:write_file", 60, histCap)
	if err != nil {
		t.Fatalf("IncrementAndGet write_file: %v", err)
	}
	if n2 != 1 {
		t.Errorf("write_file count got %d, want 1", n2)
	}
}

// -------------------------------------------------------------------------
// killswitch.Redis integration
// -------------------------------------------------------------------------

func TestRedisKillSwitch_Integration(t *testing.T) {
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	ks := killswitch.NewRedis(client)
	ctx, cancel := context.WithCancel(context.Background())
	ks.Start(ctx)
	t.Cleanup(func() {
		cancel()
		ks.Stop()
	})

	// Initially: not blocked.
	blocked, err := ks.ShouldBlock(ctx, "agent-1", "session-abc")
	if err != nil {
		t.Fatalf("ShouldBlock: %v", err)
	}
	if blocked {
		t.Fatal("expected not blocked initially")
	}

	// Kill the session.
	if err := ks.KillSession(ctx, "session-abc"); err != nil {
		t.Fatalf("KillSession: %v", err)
	}

	// Wait for the kill to propagate (pub/sub, or the reconcile fallback) instead
	// of racing a fixed sleep, which can flake on a loaded runner.
	require.Eventually(t, func() bool {
		b, e := ks.ShouldBlock(ctx, "agent-1", "session-abc")
		return e == nil && b
	}, 2*time.Second, 10*time.Millisecond, "session must be blocked after KillSession")

	// A different session is unaffected.
	blocked, err = ks.ShouldBlock(ctx, "agent-1", "session-xyz")
	if err != nil {
		t.Fatalf("ShouldBlock other session: %v", err)
	}
	if blocked {
		t.Fatal("expected unrelated session to not be blocked")
	}
}

func TestRedisKillSwitch_GlobalActivate(t *testing.T) {
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	ks := killswitch.NewRedis(client)
	ctx, cancel := context.WithCancel(context.Background())
	ks.Start(ctx)
	t.Cleanup(func() {
		cancel()
		ks.Stop()
	})

	if err := ks.ActivateGlobal(ctx); err != nil {
		t.Fatalf("ActivateGlobal: %v", err)
	}

	require.Eventually(t, func() bool {
		blocked, err := ks.ShouldBlock(ctx, "any-agent", "any-session")
		return err == nil && blocked
	}, 2*time.Second, 10*time.Millisecond, "all sessions must be blocked under the global kill switch")
}

// TestSessionKillTTLNotice_ResolvesTheSameSentinelsAsTheOption pins the startup banner
// against the option it describes: 0 means the 30-day default and a negative means "never
// expire", so the line must resolve both rather than print the raw flag value. A banner
// claiming one lifetime while Redis enforces another is worse than no banner — the whole
// point is that this expiry LIFTS a revocation.
func TestSessionKillTTLNotice_ResolvesTheSameSentinelsAsTheOption(t *testing.T) {
	t.Parallel()

	def := sessionKillTTLNotice(0)
	require.Contains(t, def, killswitch.DefaultSessionKillTTL.String(),
		"the default notice must state the effective lifetime, not the literal 0")
	require.Contains(t, def, "re-admitted")

	never := sessionKillTTLNotice(-1)
	require.Contains(t, never, "never expire")
	require.NotContains(t, never, "re-admitted",
		"with expiry disabled there is no re-admission to warn about")

	explicit := sessionKillTTLNotice(90 * time.Minute)
	require.Contains(t, explicit, "1h30m0s")
	require.NotContains(t, explicit, "default")
}

// TestKillswitchSessionTTLFlag_IsRedisGated: the flag only takes effect inside the
// --redis-addr branch, so it must be listed with the other Redis-gated flags or an
// operator who sets it without Redis gets no diagnostic.
func TestKillswitchSessionTTLFlag_IsRedisGated(t *testing.T) {
	t.Parallel()
	require.Contains(t, redisGatedFlags, "killswitch-session-ttl")
}

// TestRunRedisKill_HonorsSessionKillTTL: the TTL is applied by whichever process WRITES
// the tombstone, and `eunox kill --redis-addr` is the only out-of-band revocation channel
// a stdio proxy has — the deployment the flag exists for. Building the manager without
// the option here stamped the 30-day default on a kill the operator had configured to
// never expire, so the revoked session came back. No proxy has published a TTL to this
// Redis, so the flag is what resolves.
func TestRunRedisKill_HonorsSessionKillTTL(t *testing.T) {
	mr := miniredis.RunT(t)

	// Negative: expiry disabled, so the tombstone must carry no TTL.
	if err := runRedisKill(redisKillRequest{addr: mr.Addr(), target: killTarget{kind: killTargetSession, id: "sess-permanent"}, sessionKillTTL: -1, ttlFlagSet: true}); err != nil {
		t.Fatalf("runRedisKill: %v", err)
	}
	if ttl := mr.TTL("killswitch:session:sess-permanent"); ttl != 0 {
		t.Errorf("TTL = %v, want 0 (no expiry) for a negative --killswitch-session-ttl", ttl)
	}

	// An explicit positive value is applied verbatim, not replaced by the default.
	if err := runRedisKill(redisKillRequest{addr: mr.Addr(), target: killTarget{kind: killTargetSession, id: "sess-short"}, sessionKillTTL: 90 * time.Minute, ttlFlagSet: true}); err != nil {
		t.Fatalf("runRedisKill: %v", err)
	}
	if ttl := mr.TTL("killswitch:session:sess-short"); ttl != 90*time.Minute {
		t.Errorf("TTL = %v, want 90m", ttl)
	}

	// 0 selects the documented default.
	if err := runRedisKill(redisKillRequest{addr: mr.Addr(), target: killTarget{kind: killTargetSession, id: "sess-default"}}); err != nil {
		t.Fatalf("runRedisKill: %v", err)
	}
	if ttl := mr.TTL("killswitch:session:sess-default"); ttl != killswitch.DefaultSessionKillTTL {
		t.Errorf("TTL = %v, want the %v default", ttl, killswitch.DefaultSessionKillTTL)
	}
}
