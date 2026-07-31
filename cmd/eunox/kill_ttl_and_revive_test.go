// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Tests for the two halves of the out-of-band revocation channel:
//   - `eunox kill --redis-addr` adopts the session-kill TTL the proxy published, so the
//     lifetime cannot be set differently in two places with no diagnostic.
//   - `eunox kill --revive` lifts a revocation, so a permanent tombstone is not a
//     redis-cli-only remediation.

package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/pkg/killswitch"
)

// publishedTTLKey is the shared config key the proxy writes at startup, spelled out
// here (it is unexported in pkg/killswitch) so a rename that breaks the coordination
// between the proxy and this CLI fails a test rather than silently splitting the two
// processes back into independent defaults.
const publishedTTLKey = "killswitch:config:session-kill-ttl"

// TestProxyPublishesSessionKillTTL_ForTheKillCLI: the proxy's startup wiring must
// advertise its effective lifetime, since `eunox kill --redis-addr` writes tombstones
// itself and would otherwise stamp its own default on them.
func TestProxyPublishesSessionKillTTL_ForTheKillCLI(t *testing.T) {
	mr := miniredis.RunT(t)

	_ = captureStderr(t, func() {
		_, _, _, ksRedis, err := buildCallCounterAndKillSwitch(mr.Addr(), "", false, false, 0, 90*time.Minute, 0)
		require.NoError(t, err)
		require.NotNil(t, ksRedis)
	})

	got, err := mr.Get(publishedTTLKey)
	require.NoError(t, err)
	require.Equal(t, "1h30m0s", got)

	// A never-expiring proxy publishes the word, not a bare 0 — the CLI reads it back as
	// a permanent tombstone rather than as "unset, use the default".
	_ = captureStderr(t, func() {
		_, _, _, _, err := buildCallCounterAndKillSwitch(mr.Addr(), "", false, false, 0, -1, 0)
		require.NoError(t, err)
	})
	got, err = mr.Get(publishedTTLKey)
	require.NoError(t, err)
	require.Equal(t, "never", got)
}

// TestProxyPublishSessionKillTTL_WarnsOnADifferingPriorValue: the key is
// last-writer-wins, so two proxies configured differently on one Redis leave `eunox
// kill` adopting whichever started last. That ambiguity has to be visible.
func TestProxyPublishSessionKillTTL_WarnsOnADifferingPriorValue(t *testing.T) {
	mr := miniredis.RunT(t)
	require.NoError(t, mr.Set(publishedTTLKey, "24h0m0s"))

	stderr := captureStderr(t, func() {
		_, _, _, _, err := buildCallCounterAndKillSwitch(mr.Addr(), "", false, false, 0, 90*time.Minute, 0)
		require.NoError(t, err)
	})
	require.Contains(t, stderr, "24h0m0s", "the warning must name the value being replaced")
	require.Contains(t, stderr, "1h30m0s", "and the value replacing it")

	// Republishing the same value is agreement, not a conflict.
	stderr = captureStderr(t, func() {
		_, _, _, _, err := buildCallCounterAndKillSwitch(mr.Addr(), "", false, false, 0, 90*time.Minute, 0)
		require.NoError(t, err)
	})
	require.NotContains(t, stderr, "already advertised")
}

// TestCmdKill_AdoptsPublishedSessionKillTTL is the fix for the two-flag split: with a
// TTL published by the proxy and no --killswitch-session-ttl here, the tombstone this
// command writes carries the PROXY's lifetime. Before, it carried this command's own
// 30-day default, so a kill an operator had configured to last longer (or forever)
// expired early and silently re-admitted the session.
func TestCmdKill_AdoptsPublishedSessionKillTTL(t *testing.T) {
	mr := miniredis.RunT(t)
	require.NoError(t, mr.Set(publishedTTLKey, "1h30m0s"))

	var code int
	stderr := captureStderr(t, func() {
		code = cmdKill([]string{"--redis-addr", mr.Addr(), "sess-adopted"})
	})
	require.Zero(t, code)
	require.Equal(t, 90*time.Minute, mr.TTL("killswitch:session:sess-adopted"))
	require.Contains(t, stderr, "published by the proxy", "the resolved lifetime must never be silent")

	// A published "never" survives the round trip as no expiry at all — the case where
	// reading it as a duration-shaped zero would have re-admitted the session in 30 days.
	require.NoError(t, mr.Set(publishedTTLKey, "never"))
	stderr = captureStderr(t, func() {
		code = cmdKill([]string{"--redis-addr", mr.Addr(), "sess-permanent"})
	})
	require.Zero(t, code)
	require.Zero(t, mr.TTL("killswitch:session:sess-permanent"), "a published 'never' must write a tombstone with no expiry")
	require.Contains(t, stderr, "never expires")
}

// TestCmdKill_TTLMismatchUsesTheLongerTombstone: where an explicit flag still disagrees
// with the published value, the longer-lived of the two wins. Erroring out would refuse
// a revocation over a lifetime disagreement — failing in the one direction that matters
// — while an over-long tombstone only over-blocks a session id that is already gone.
func TestCmdKill_TTLMismatchUsesTheLongerTombstone(t *testing.T) {
	cases := []struct {
		name      string
		published string
		flag      string
		wantTTL   time.Duration
	}{
		{"flag is longer", "1h", "24h", 24 * time.Hour},
		{"published is longer", "24h", "1h", 24 * time.Hour},
		{"published never beats any finite flag", "never", "24h", 0},
		{"flag never beats any finite published value", "24h", "-1s", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mr := miniredis.RunT(t)
			require.NoError(t, mr.Set(publishedTTLKey, tc.published))

			var code int
			stderr := captureStderr(t, func() {
				code = cmdKill([]string{"--redis-addr", mr.Addr(), "--killswitch-session-ttl", tc.flag, "sess-x"})
			})
			require.Zero(t, code, "a lifetime disagreement must not block the revocation")
			require.Equal(t, tc.wantTTL, mr.TTL("killswitch:session:sess-x"))
			require.Contains(t, stderr, "mismatch", "the disagreement must be reported")
		})
	}

	// Agreement is not a diagnostic.
	mr := miniredis.RunT(t)
	require.NoError(t, mr.Set(publishedTTLKey, "1h0m0s"))
	stderr := captureStderr(t, func() {
		require.Zero(t, cmdKill([]string{"--redis-addr", mr.Addr(), "--killswitch-session-ttl", "1h", "sess-agreed"}))
	})
	require.NotContains(t, stderr, "mismatch")
	require.Equal(t, time.Hour, mr.TTL("killswitch:session:sess-agreed"))
}

// TestCmdKill_UnreadablePublishedTTL_StillKills: a malformed key (something other than a
// proxy wrote it) must degrade to the local value with a warning. The kill is the
// emergency stop; it lands either way.
func TestCmdKill_UnreadablePublishedTTL_StillKills(t *testing.T) {
	mr := miniredis.RunT(t)
	require.NoError(t, mr.Set(publishedTTLKey, "whenever"))

	var code int
	stderr := captureStderr(t, func() {
		code = cmdKill([]string{"--redis-addr", mr.Addr(), "sess-fallback"})
	})
	require.Zero(t, code)
	require.Equal(t, "1", mustGet(t, mr, "killswitch:session:sess-fallback"))
	require.Equal(t, killswitch.DefaultSessionKillTTL, mr.TTL("killswitch:session:sess-fallback"))
	require.Contains(t, stderr, "could not read")
}

// TestCmdKill_NoPublishedTTL_SaysSo: nothing has published a lifetime (no proxy has
// started against this Redis since the key existed), so the operator has to be told the
// two values are unverified — this is the exact state the published key exists to end.
func TestCmdKill_NoPublishedTTL_SaysSo(t *testing.T) {
	mr := miniredis.RunT(t)

	stderr := captureStderr(t, func() {
		require.Zero(t, cmdKill([]string{"--redis-addr", mr.Addr(), "sess-unverified"}))
	})
	require.Contains(t, stderr, "no proxy on this Redis has published")
	require.Equal(t, killswitch.DefaultSessionKillTTL, mr.TTL("killswitch:session:sess-unverified"))

	stderr = captureStderr(t, func() {
		require.Zero(t, cmdKill([]string{"--redis-addr", mr.Addr(), "--killswitch-session-ttl", "2h", "sess-flagged"}))
	})
	require.Contains(t, stderr, "must match the proxy's")
	require.Equal(t, 2*time.Hour, mr.TTL("killswitch:session:sess-flagged"))
}

// TestCmdKill_GlobalAndReviveSkipTTLResolution: only a session tombstone carries a
// lifetime. A global kill has no expiry and a revive deletes, so neither should consult
// the published value — and neither should emit a TTL diagnostic about a lifetime it
// never applies.
func TestCmdKill_GlobalAndReviveSkipTTLResolution(t *testing.T) {
	mr := miniredis.RunT(t)

	stderr := captureStderr(t, func() {
		require.Zero(t, cmdKill([]string{"--redis-addr", mr.Addr(), "all"}))
		require.Zero(t, cmdKill([]string{"--redis-addr", mr.Addr(), "--revive", "sess-none"}))
	})
	require.NotContains(t, stderr, "session-kill TTL")
	require.Zero(t, mr.TTL("killswitch:global"), "the global kill never expires")
}

// ── --revive ──────────────────────────────────────────────────────────────

// TestCmdKill_ReviveSession removes the tombstone so the id may connect again. Without
// it a permanent tombstone (a negative --killswitch-session-ttl) could only be cleared
// by deleting keys in redis-cli — the library had ReviveSession, but nothing in the CLI
// reached it.
func TestCmdKill_ReviveSession(t *testing.T) {
	mr := miniredis.RunT(t)

	stdout := captureStdout(t, func() {
		_ = captureStderr(t, func() {
			require.Zero(t, cmdKill([]string{"--redis-addr", mr.Addr(), "sess-1"}))
		})
	})
	require.Contains(t, stdout, `"killed":"sess-1"`)
	require.Equal(t, "1", mustGet(t, mr, "killswitch:session:sess-1"))

	stdout = captureStdout(t, func() {
		require.Zero(t, cmdKill([]string{"--redis-addr", mr.Addr(), "--revive", "sess-1"}))
	})
	require.Contains(t, stdout, `"revived":"sess-1"`)
	require.False(t, mr.Exists("killswitch:session:sess-1"), "the tombstone must be gone")

	// Idempotent: reviving an id that was never killed is not an error, so the command
	// is safe to re-run and reports the state the operator asked for either way.
	require.Zero(t, captureStdoutCode(t, []string{"--redis-addr", mr.Addr(), "--revive", "sess-never-killed"}))
}

// TestCmdKill_ReviveAll deactivates the global switch — the exact inverse of `kill all`
// — and deliberately leaves per-session tombstones in place: clearing sessions an
// operator revoked individually while they only meant to lift the deployment-wide stop
// would be a fail-open.
func TestCmdKill_ReviveAll(t *testing.T) {
	mr := miniredis.RunT(t)

	_ = captureStdout(t, func() {
		_ = captureStderr(t, func() {
			require.Zero(t, cmdKill([]string{"--redis-addr", mr.Addr(), "all"}))
			require.Zero(t, cmdKill([]string{"--redis-addr", mr.Addr(), "sess-keep"}))
		})
	})
	require.Equal(t, "1", mustGet(t, mr, "killswitch:global"))

	stdout := captureStdout(t, func() {
		require.Zero(t, cmdKill([]string{"--redis-addr", mr.Addr(), "--revive", "all"}))
	})
	require.Contains(t, stdout, `"revived":"all"`)
	require.False(t, mr.Exists("killswitch:global"), "the global switch must be off")
	require.Equal(t, "1", mustGet(t, mr, "killswitch:session:sess-keep"),
		"lifting the global stop must not clear individually revoked sessions")
}

// TestCmdKill_ReviveConvergesOnARunningProxy closes the loop the CLI exists to serve: a
// proxy already watching this Redis must stop blocking the session once the revive lands
// — via the pub/sub event, or the reconcile tick if the at-most-once message is lost.
// Writing the key back out is only half the job if the running instance never notices.
func TestCmdKill_ReviveConvergesOnARunningProxy(t *testing.T) {
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	// Stand in for the running proxy: a manager with its listener and reconcile loop up.
	proxyKS := killswitch.NewRedis(client, killswitch.WithReconcileInterval(50*time.Millisecond))
	ctx, cancel := context.WithCancel(context.Background())
	proxyKS.Start(ctx)
	t.Cleanup(func() {
		cancel()
		proxyKS.Stop()
	})

	_ = captureStdout(t, func() {
		_ = captureStderr(t, func() {
			require.Zero(t, cmdKill([]string{"--redis-addr", mr.Addr(), "sess-live"}))
		})
	})
	require.Eventually(t, func() bool {
		blocked, err := proxyKS.ShouldBlock(ctx, "", "sess-live")
		return err == nil && blocked
	}, 2*time.Second, 10*time.Millisecond, "the proxy must observe the kill")

	_ = captureStdout(t, func() {
		require.Zero(t, cmdKill([]string{"--redis-addr", mr.Addr(), "--revive", "sess-live"}))
	})
	require.Eventually(t, func() bool {
		blocked, err := proxyKS.ShouldBlock(ctx, "", "sess-live")
		return err == nil && !blocked
	}, 2*time.Second, 10*time.Millisecond, "the proxy must observe the revive")
}

// TestCmdKill_ReviveRequiresRedisAddr: the HTTP control endpoint is a one-way emergency
// stop, so --revive without --redis-addr must be rejected rather than fall through to a
// KILL — a flag that inverts the verb must never be silently dropped on this path.
func TestCmdKill_ReviveRequiresRedisAddr(t *testing.T) {
	var code int
	stderr := captureStderr(t, func() {
		code = cmdKill([]string{"--revive", "--port", "3000", "sess-1"})
	})
	require.Equal(t, 1, code)
	require.Contains(t, stderr, "--revive requires --redis-addr")
}

// TestCmdKill_ReviveRejectsSessionTTLFlag: a tombstone lifetime is meaningless when the
// tombstone is being deleted, and accepting it silently would suggest --revive writes
// something with an expiry.
func TestCmdKill_ReviveRejectsSessionTTLFlag(t *testing.T) {
	mr := miniredis.RunT(t)
	var code int
	stderr := captureStderr(t, func() {
		code = cmdKill([]string{"--redis-addr", mr.Addr(), "--revive", "--killswitch-session-ttl", "1h", "sess-1"})
	})
	require.Equal(t, 1, code)
	require.Contains(t, stderr, "--killswitch-session-ttl has no effect with --revive")
}

// TestPublishSessionKillTTL_WarnsButDoesNotAbortStartup: the published key is a
// coordination hint, not enforcement — this proxy applies its own configured lifetime
// either way, and the CLI falls back to its flag exactly as it did before the key
// existed. A failure has to be visible, though, or an operator would believe the two
// processes were coordinated when they are not.
func TestPublishSessionKillTTL_WarnsButDoesNotAbortStartup(t *testing.T) {
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	ksRedis := killswitch.NewRedis(client, killswitch.WithSessionKillTTL(0))
	mr.Close()

	stderr := captureStderr(t, func() { publishSessionKillTTL(ksRedis) })
	require.Contains(t, stderr, "WARNING")
	require.Contains(t, stderr, "--killswitch-session-ttl", "the warning must say what the CLI falls back to")
}

// TestReviveViaRedis_BackendErrorsAreReported: a revive that did not land must not print
// the success line — an operator who believes a session was restored would otherwise be
// debugging a proxy that is still denying it.
func TestReviveViaRedis_BackendErrorsAreReported(t *testing.T) {
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	ks := killswitch.NewRedis(client)
	mr.Close()

	err := reviveViaRedis(context.Background(), ks, "sess-1")
	require.Error(t, err)
	require.Contains(t, err.Error(), "revive session")

	err = reviveViaRedis(context.Background(), ks, "all")
	require.Error(t, err)
	require.Contains(t, err.Error(), "deactivate global kill switch")
}

// mustGet reads a key that the test requires to exist.
func mustGet(t *testing.T, mr *miniredis.Miniredis, key string) string {
	t.Helper()
	v, err := mr.Get(key)
	require.NoError(t, err, "key %q should exist", key)
	return v
}

// captureStdoutCode runs cmdKill with both streams captured, returning only the exit
// code — for the assertions that care about the outcome rather than the output.
func captureStdoutCode(t *testing.T, args []string) int {
	t.Helper()
	var code int
	_ = captureStdout(t, func() {
		_ = captureStderr(t, func() { code = cmdKill(args) })
	})
	return code
}

// TestKillUsage_DocumentsRevive keeps the flag discoverable: the startup banner points a
// permanent-tombstone deployment at this command, so `eunox kill -h` has to list it.
func TestKillUsage_DocumentsRevive(t *testing.T) {
	out := captureStderr(t, func() { require.Zero(t, cmdKill([]string{"-h"})) })
	require.Contains(t, out, "-revive")
	require.Contains(t, out, "--revive")
}

// TestSessionKillTTLNotice_PointsAtARealCommand: with expiry disabled the banner used to
// name `eunox kill --revive`, which did not exist, and was corrected to describe manual
// key deletion. Now that the command exists the banner should name it — and the name it
// prints must stay a real invocation.
func TestSessionKillTTLNotice_PointsAtARealCommand(t *testing.T) {
	notice := sessionKillTTLNotice(-1)
	require.Contains(t, notice, "--revive")
	require.Contains(t, notice, "--redis-addr", "revive is Redis-only; the banner must not imply otherwise")
	require.Contains(t, strings.ToLower(notice), "never expire")
}
