// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Regression tests for the kill-switch / shutdown lifecycle CLI wiring:
//   - Redis-gated flags must be rejected without --redis-addr (not silently dropped).
//   - Negative numeric limit flags must be rejected (not silently coerced).
//   - `eunox kill` must accept flags on either side of the positional.

package main

import (
	"flag"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
)

// TestValidateRedisFlagsRequireRedisAddr pins that every Redis-gated proxy flag is
// rejected when --redis-addr is absent (without the backend it would be silently
// dropped), and accepted when --redis-addr is set. The error names the flag but must
// never echo a secret value (e.g. the --redis-password argument).
func TestValidateRedisFlagsRequireRedisAddr(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		wantErr  bool
		wantFlag string
	}{
		{"nothing set", nil, false, ""},
		{"failopen without addr", []string{"--killswitch-fail-open"}, true, "--killswitch-fail-open"},
		{"reconcile without addr", []string{"--killswitch-reconcile-interval", "10s"}, true, "--killswitch-reconcile-interval"},
		{"redis-password without addr", []string{"--redis-password", "sup3r-secret"}, true, "--redis-password"},
		{"redis-tls without addr", []string{"--redis-tls"}, true, "--redis-tls"},
		{"failopen WITH addr", []string{"--redis-addr", "localhost:6379", "--killswitch-fail-open"}, false, ""},
		{"addr alone", []string{"--redis-addr", "localhost:6379"}, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
			f := registerProxyFlags(fs)
			if err := fs.Parse(tc.args); err != nil {
				t.Fatalf("parse %v: %v", tc.args, err)
			}
			err := validateRedisFlagsRequireRedisAddr(fs, *f.redisAddr)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("args %v: want error, got nil", tc.args)
				}
				if tc.wantFlag != "" && !strings.Contains(err.Error(), tc.wantFlag) {
					t.Errorf("error %q does not name %q", err, tc.wantFlag)
				}
				if !strings.Contains(err.Error(), "--redis-addr") {
					t.Errorf("error %q should point the operator at --redis-addr", err)
				}
				if strings.Contains(err.Error(), "sup3r-secret") {
					t.Errorf("error leaked the --redis-password value: %q", err)
				}
			} else if err != nil {
				t.Fatalf("args %v: want nil, got %v", tc.args, err)
			}
		})
	}
}

// TestValidateProxyNumericFlags pins that negative numeric limit flags are rejected
// (0 stays a valid "unlimited/disabled/default" spelling) — including --shutdown-timeout,
// which the transports would otherwise silently clamp to the 5000ms default.
func TestValidateProxyNumericFlags(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		wantErr  bool
		wantFlag string
	}{
		{"all defaults", nil, false, ""},
		{"zero shutdown-timeout ok", []string{"--shutdown-timeout", "0"}, false, ""},
		{"zero max-sessions ok", []string{"--max-sessions", "0"}, false, ""},
		{"negative shutdown-timeout", []string{"--shutdown-timeout", "-1"}, true, "--shutdown-timeout"},
		{"negative max-sessions", []string{"--max-sessions", "-1"}, true, "--max-sessions"},
		{"negative session-idle-timeout", []string{"--session-idle-timeout", "-5"}, true, "--session-idle-timeout"},
		{"negative max-call-counter-keys", []string{"--max-call-counter-keys", "-1"}, true, "--max-call-counter-keys"},
		// --upstream-timeout owns a legitimate negative sentinel (-1, "defer to the
		// config"), so -1 and 0 stay valid while anything below the sentinel is a typo
		// that would silently defer instead of setting the bound the operator meant.
		{"sentinel upstream-timeout ok", []string{"--upstream-timeout", "-1"}, false, ""},
		{"zero upstream-timeout ok", []string{"--upstream-timeout", "0"}, false, ""},
		{"sub-sentinel upstream-timeout", []string{"--upstream-timeout", "-5000"}, true, "--upstream-timeout"},
		// A duration flag, and one whose clamp is silent: a negative value became the
		// 30s default, i.e. the opposite of an operator shortening the revocation window.
		{"zero killswitch-reconcile-interval ok", []string{"--killswitch-reconcile-interval", "0"}, false, ""},
		{"negative killswitch-reconcile-interval", []string{"--killswitch-reconcile-interval", "-5s"}, true, "--killswitch-reconcile-interval"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
			f := registerProxyFlags(fs)
			if err := fs.Parse(tc.args); err != nil {
				t.Fatalf("parse %v: %v", tc.args, err)
			}
			err := validateProxyNumericFlags(f)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("args %v: want error, got nil", tc.args)
				}
				if !strings.Contains(err.Error(), tc.wantFlag) {
					t.Errorf("error %q does not name %q", err, tc.wantFlag)
				}
			} else if err != nil {
				t.Fatalf("args %v: want nil, got %v", tc.args, err)
			}
		})
	}
}

// TestCmdKill_FlagsAfterPositional_RedisPath is the regression for `eunox kill`
// rejecting flags after the positional. A single fs.Parse stops at the first non-flag
// token, so "kill all --redis-addr <addr>" (target first) would fail the exact-one-arg
// check; parseFlagsAndPositionals accepts either order, so the kill reaches Redis and
// activates the global switch. Uses miniredis so no real backend is needed.
func TestCmdKill_FlagsAfterPositional_RedisPath(t *testing.T) {
	mr := miniredis.RunT(t)

	var code int
	// Positional FIRST, then the flag — the ordering a single fs.Parse rejects.
	code = cmdKill([]string{"all", "--redis-addr", mr.Addr()})
	if code != 0 {
		t.Fatalf("kill all --redis-addr <addr> (positional first): exit %d, want 0 (flags after the positional must parse)", code)
	}
	// The global kill must actually have landed in Redis (killswitch:global == "1").
	if v, err := mr.Get("killswitch:global"); err != nil || v != "1" {
		t.Fatalf("global kill not written to Redis: value=%q err=%v", v, err)
	}

	// The conventional flag-first order must still work (no regression).
	mr.FlushAll()
	code = cmdKill([]string{"--redis-addr", mr.Addr(), "all"})
	if code != 0 {
		t.Fatalf("kill --redis-addr <addr> all (flag first): exit %d, want 0", code)
	}
	if v, err := mr.Get("killswitch:global"); err != nil || v != "1" {
		t.Fatalf("global kill not written to Redis (flag-first): value=%q err=%v", v, err)
	}
}
