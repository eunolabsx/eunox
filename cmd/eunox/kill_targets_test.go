// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Tests for the kill command's three targeting dimensions: the session positional,
// --session (which also addresses a session literally named "all"), and --agent, whose
// kill and revive halves ship together because an agent kill never expires.

package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/require"
)

// agentKey / sessionKey are the durable kill-switch keys, spelled out here so a rename
// that split the CLI from the store fails a test rather than silently writing to a key
// nothing reads.
func agentKey(id string) string   { return "killswitch:agent:" + id }
func sessionKey(id string) string { return "killswitch:session:" + id }

// TestResolveKillTarget covers the exactly-one rule and which dimension each spelling
// selects. The overloaded positional is the reason the flags exist: "all" as a positional
// is the deployment-wide switch, while --session all is a session whose id is that word.
func TestResolveKillTarget(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		pos         []string
		session     string
		sessionSet  bool
		agent       string
		agentSet    bool
		want        killTarget
		wantErrPart string
	}{
		{name: "positional session", pos: []string{"sess-1"}, want: killTarget{kind: killTargetSession, id: "sess-1"}},
		{name: "positional all is the global switch", pos: []string{"all"}, want: killTarget{kind: killTargetGlobal}},
		{name: "session flag", session: "sess-2", sessionSet: true, want: killTarget{kind: killTargetSession, id: "sess-2"}},
		{
			name:       "session flag addresses a session named all",
			session:    "all",
			sessionSet: true,
			want:       killTarget{kind: killTargetSession, id: "all"},
		},
		{name: "agent flag", agent: "agent-7", agentSet: true, want: killTarget{kind: killTargetAgent, id: "agent-7"}},
		{name: "no target", wantErrPart: "no target given"},
		{name: "positional and session", pos: []string{"sess-1"}, session: "sess-2", sessionSet: true, wantErrPart: "more than one target"},
		{name: "positional and agent", pos: []string{"sess-1"}, agent: "agent-7", agentSet: true, wantErrPart: "more than one target"},
		{name: "session and agent", session: "sess-2", sessionSet: true, agent: "agent-7", agentSet: true, wantErrPart: "more than one target"},
		{name: "all three", pos: []string{"x"}, session: "y", sessionSet: true, agent: "z", agentSet: true, wantErrPart: "more than one target"},
		{name: "two positionals", pos: []string{"a", "b"}, wantErrPart: "exactly one argument"},
		// An explicitly-passed but empty flag is a SUPPLIED target, not an absent one:
		// counting it as absent would silently drop a target the operator typed.
		{
			name:       "explicitly empty session flag still counts as a target",
			session:    "",
			sessionSet: true,
			want:       killTarget{kind: killTargetSession},
		},
		{
			name:        "explicitly empty session flag conflicts with a positional",
			pos:         []string{"sess-1"},
			session:     "",
			sessionSet:  true,
			wantErrPart: "more than one target",
		},
		{
			name:        "explicitly empty agent flag conflicts with a positional",
			pos:         []string{"sess-1"},
			agent:       "",
			agentSet:    true,
			wantErrPart: "more than one target",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := resolveKillTarget(tc.pos, tc.session, tc.sessionSet, tc.agent, tc.agentSet)
			if tc.wantErrPart != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.wantErrPart)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestCmdKill_AgentRoundTrip is the property that made shipping both halves together
// non-negotiable: an agent kill never expires, so a kill with no CLI undo would be a
// permanent revocation remediable only by a library call or a hand-written redis-cli DEL.
func TestCmdKill_AgentRoundTrip(t *testing.T) {
	mr := miniredis.RunT(t)

	out := captureStdout(t, func() {
		_ = captureStderr(t, func() {
			require.Zero(t, cmdKill([]string{"--redis-addr", mr.Addr(), "--agent", "agent-7"}))
		})
	})
	require.Equal(t, "1", mustGet(t, mr, agentKey("agent-7")))
	require.Zero(t, mr.TTL(agentKey("agent-7")), "agent kills must never carry an expiry")

	// The dimension is machine-readable: with two id dimensions, the id alone no longer
	// says which store moved.
	var result map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(out)), &result))
	require.Equal(t, true, result["ok"])
	require.Equal(t, "agent-7", result["killed"])
	require.Equal(t, "agent", result["dimension"])

	// And the undo.
	out = captureStdout(t, func() {
		_ = captureStderr(t, func() {
			require.Zero(t, cmdKill([]string{"--redis-addr", mr.Addr(), "--revive", "--agent", "agent-7"}))
		})
	})
	require.False(t, mr.Exists(agentKey("agent-7")), "--revive --agent must remove the kill")
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(out)), &result))
	require.Equal(t, "agent-7", result["revived"])
	require.Equal(t, "agent", result["dimension"])

	// Idempotent: reviving an agent that was never killed still succeeds, so the command
	// is safe to re-run.
	require.Zero(t, captureStdoutCode(t, []string{"--redis-addr", mr.Addr(), "--revive", "--agent", "never-killed"}))
}

// TestCmdKill_AgentAndSessionAreSeparateDimensions: killing an agent must not touch a
// session that happens to share the id, and vice versa. They are distinct stores, and a
// CLI that conflated them would revoke more (or less) than the operator named.
func TestCmdKill_AgentAndSessionAreSeparateDimensions(t *testing.T) {
	mr := miniredis.RunT(t)
	const id = "shared-id"

	require.Zero(t, captureStdoutCode(t, []string{"--redis-addr", mr.Addr(), "--agent", id}))
	require.True(t, mr.Exists(agentKey(id)))
	require.False(t, mr.Exists(sessionKey(id)), "an agent kill must not write a session tombstone")

	require.Zero(t, captureStdoutCode(t, []string{"--redis-addr", mr.Addr(), "--session", id}))
	require.True(t, mr.Exists(sessionKey(id)))

	// Reviving one leaves the other in place.
	require.Zero(t, captureStdoutCode(t, []string{"--redis-addr", mr.Addr(), "--revive", "--agent", id}))
	require.False(t, mr.Exists(agentKey(id)))
	require.True(t, mr.Exists(sessionKey(id)), "reviving an agent must not clear a session tombstone")
}

// TestCmdKill_SessionFlagAddressesTheLiteralAllID closes the gap the positional cannot
// express. A session id is operator-settable on a stdio proxy, so one can be named "all";
// before --session existed, such a session could never be individually killed or revived.
func TestCmdKill_SessionFlagAddressesTheLiteralAllID(t *testing.T) {
	mr := miniredis.RunT(t)

	require.Zero(t, captureStdoutCode(t, []string{"--redis-addr", mr.Addr(), "--session", "all"}))
	require.Equal(t, "1", mustGet(t, mr, sessionKey("all")), "--session all must write a session tombstone for the literal id")
	require.False(t, mr.Exists("killswitch:global"), "--session all must NOT activate the global switch")

	// The positional keeps its documented meaning, unchanged.
	require.Zero(t, captureStdoutCode(t, []string{"--redis-addr", mr.Addr(), "all"}))
	require.True(t, mr.Exists("killswitch:global"), "the positional 'all' must still mean the deployment-wide switch")

	// And the escape hatch works in the revive direction too.
	require.Zero(t, captureStdoutCode(t, []string{"--redis-addr", mr.Addr(), "--revive", "--session", "all"}))
	require.False(t, mr.Exists(sessionKey("all")))
	require.True(t, mr.Exists("killswitch:global"), "reviving the session named 'all' must not deactivate the global switch")
}

// TestCmdKill_TargetFlagRejections: every new way to name a target has to fail loudly
// rather than silently pick one. On the emergency-stop path an ignored flag is the
// difference between a revocation an operator believes landed and one that did not.
func TestCmdKill_TargetFlagRejections(t *testing.T) {
	mr := miniredis.RunT(t)
	cases := []struct {
		name    string
		args    []string
		wantMsg string
	}{
		{
			name:    "agent requires redis",
			args:    []string{"--agent", "agent-7"},
			wantMsg: "--agent requires --redis-addr",
		},
		{
			name:    "agent conflicts with the positional",
			args:    []string{"--redis-addr", mr.Addr(), "--agent", "agent-7", "sess-1"},
			wantMsg: "more than one target",
		},
		{
			name:    "agent conflicts with session",
			args:    []string{"--redis-addr", mr.Addr(), "--agent", "agent-7", "--session", "sess-1"},
			wantMsg: "more than one target",
		},
		{
			name:    "session conflicts with the positional",
			args:    []string{"--redis-addr", mr.Addr(), "--session", "sess-1", "sess-2"},
			wantMsg: "more than one target",
		},
		{
			name:    "no target at all",
			args:    []string{"--redis-addr", mr.Addr()},
			wantMsg: "no target given",
		},
		{
			name:    "ttl flag has no meaning for an agent kill",
			args:    []string{"--redis-addr", mr.Addr(), "--agent", "agent-7", "--killswitch-session-ttl", "2h"},
			wantMsg: "agent kills never expire",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var code int
			stderr := captureStderr(t, func() { code = cmdKill(tc.args) })
			require.Equal(t, 1, code, "the invocation must be rejected, not silently reinterpreted")
			require.Contains(t, stderr, tc.wantMsg)
		})
	}
}

// TestCmdKill_AgentRejectedBeforeTheHTTPTransport pins that --agent without --redis-addr
// is refused rather than falling through to the loopback control endpoint. There is no
// agent dimension there, and adding one would widen what a same-host caller holding the
// control token can reach — the same reasoning that keeps --revive off that transport.
func TestCmdKill_AgentRejectedBeforeTheHTTPTransport(t *testing.T) {
	var code int
	stderr := captureStderr(t, func() {
		// Port 1 is not listening: if the rejection did not happen first, this would fail
		// with a connection error instead of the flag diagnostic.
		code = cmdKill([]string{"--port", "1", "--agent", "agent-7"})
	})
	require.Equal(t, 1, code)
	require.Contains(t, stderr, "--agent requires --redis-addr")
	require.NotContains(t, stderr, "request failed", "the rejection must happen before any HTTP request is attempted")
}

// TestKillUsage_DocumentsTargetingFlags keeps the new dimensions discoverable: the usage
// block is the primary documentation for this command.
func TestKillUsage_DocumentsTargetingFlags(t *testing.T) {
	out := captureStdout(t, func() { require.Zero(t, cmdKill([]string{"-h"})) })
	require.Contains(t, out, "-agent")
	require.Contains(t, out, "-session")
	require.Contains(t, out, "Agent kills never expire")
}

// TestKillTargetZeroValueIsUnset pins that the most destructive dimension is not what a
// caller gets by writing nothing. resolveKillTarget returns a zero killTarget alongside
// every error, and a redisKillRequest literal can omit the field, so a zero value meaning
// "halt the entire deployment" would turn any dropped error or missed field into a
// deployment-wide stop.
func TestKillTargetZeroValueIsUnset(t *testing.T) {
	t.Parallel()
	var zero killTarget
	if zero.kind != killTargetUnset {
		t.Fatalf("the zero killTarget must be killTargetUnset, got kind %d (%s)", zero.kind, zero.dimension())
	}
	if zero.kind == killTargetGlobal {
		t.Error("the zero value must never be the deployment-wide switch")
	}
	// Every error path hands back the zero value; none of them may be actionable.
	if got, err := resolveKillTarget(nil, "", false, "", false); err == nil || got.kind != killTargetUnset {
		t.Errorf("no-target error must return an unset target, got kind %d err %v", got.kind, err)
	}
}

// TestRunRedisKill_UnhandledKindFailsClosed pins the fail-closed default: a kind no arm
// handles must be refused, not quietly routed to the session store while the result line
// reports some other dimension.
func TestRunRedisKill_UnhandledKindFailsClosed(t *testing.T) {
	mr := miniredis.RunT(t)
	err := runRedisKill(redisKillRequest{addr: mr.Addr(), target: killTarget{kind: killTargetUnset, id: "x"}})
	if err == nil {
		t.Fatal("an unhandled kill target kind must be refused")
	}
	if !strings.Contains(err.Error(), "unhandled kill target kind") {
		t.Errorf("error should name the unhandled kind, got %v", err)
	}
	if mr.Exists(sessionKey("x")) {
		t.Error("an unhandled kind must not fall through to a session write")
	}
	if mr.Exists("killswitch:global") {
		t.Error("an unhandled kind must not fall through to a global activation")
	}
}

// TestCmdKill_AgentWarnsItIsInertWithoutJWT: the agent kill lands in Redis whatever the
// proxy is running, but it is only CONSULTED where the proxy has a JWT identity to match
// it against — and a stdio proxy cannot take --jwks-uri at all. Reporting a clean success
// while the revocation is inert is the failure this warning exists to prevent, since this
// command cannot see how the proxy was started.
func TestCmdKill_AgentWarnsItIsInertWithoutJWT(t *testing.T) {
	mr := miniredis.RunT(t)

	var out string
	stderr := captureStderr(t, func() {
		out = captureStdout(t, func() {
			require.Zero(t, cmdKill([]string{"--redis-addr", mr.Addr(), "--agent", "agent-7"}))
		})
	})
	require.Contains(t, stderr, "--jwks-uri", "the warning must name what makes an agent kill effective")
	require.Contains(t, stderr, "stdio")
	// The machine-readable success line stays on stdout, unpolluted: a script parsing it
	// must not have to strip an advisory.
	require.Contains(t, out, `"killed":"agent-7"`)
	require.NotContains(t, out, "jwks")

	// A session kill carries no such caveat — it is enforced on every transport.
	stderr = captureStderr(t, func() {
		_ = captureStdout(t, func() {
			require.Zero(t, cmdKill([]string{"--redis-addr", mr.Addr(), "--session", "sess-1"}))
		})
	})
	require.NotContains(t, stderr, "--jwks-uri", "a session kill needs no JWT caveat")
}
