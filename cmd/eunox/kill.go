// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// kill: the emergency-stop client. POSTs to a running proxy's loopback
// /control/kill endpoint to revoke one session or every session at once.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/eunolabs/eunox/internal/transport"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// killControlURL builds the http://host:port/control/kill URL. net.JoinHostPort
// brackets an IPv6 literal (--host ::1 → http://[::1]:3000/...); "%s:%d" would
// emit the unparseable ::1:3000, leaving the endpoint unreachable over IPv6.
func killControlURL(host string, port int) string {
	return fmt.Sprintf("http://%s/control/kill", net.JoinHostPort(host, strconv.Itoa(port)))
}

// cmdKill runs the `kill` subcommand and returns the process exit code (rather
// than calling os.Exit itself), so tests can drive every branch. args carries
// the subcommand's own arguments (os.Args[2:] in a real invocation), threaded
// from run.
func cmdKill(args []string) int {
	fs := flag.NewFlagSet("kill", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: eunox kill [flags] <session-id|all>

Revoke one or all active sessions on a running eunox deployment.

There are two transports, matching how the proxy shares kill-switch state:

  HTTP control endpoint (default)
      POSTs to /control/kill on an HTTP proxy (loopback only). Use this for a
      'transport: http' proxy or gateway.

  Redis (--redis-addr)
      Writes the kill straight to the shared Redis kill-switch state. Use this
      for a stdio proxy started with --redis-addr — a stdio proxy has no HTTP
      control endpoint — or to revoke across every proxy instance sharing one
      Redis at once.

A plain stdio proxy using the default in-memory kill switch has no out-of-band
revocation channel: it is a single process, so stop that process to halt it.

Flags:
`)
		fs.PrintDefaults()
	}
	port := fs.Int("port", 3000, "Port the HTTP proxy is listening on (HTTP transport).")
	host := fs.String("host", "127.0.0.1", "Host the HTTP proxy is bound to (HTTP transport).")
	redisAddr := fs.String("redis-addr", "", "Redis address (host:port). When set, the kill is written to the shared\nRedis kill-switch state instead of an HTTP endpoint — the only way to\nrevoke a stdio proxy started with --redis-addr.")
	redisPassword := fs.String("redis-password", "", "Password for the Redis server (used with --redis-addr). Prefer the\nEUNOX_REDIS_PASSWORD env var; a non-empty flag value takes precedence over\nit, but leaving the flag empty does NOT override a set env var.")
	redisTLS := fs.Bool("redis-tls", false, "Use TLS for the Redis connection (used with --redis-addr).")
	sessionKillTTL := fs.Duration("killswitch-session-ttl", 0, "How long this SESSION kill survives in Redis before it is garbage collected\n(default 720h / 30 days). MUST match the value the proxy runs with: the TTL is\napplied by whichever process writes the tombstone, so a proxy started with a\nlonger (or negative, never-expiring) value does not extend a kill issued here.\nWhen the tombstone expires the kill is LIFTED. Negative disables expiry.\nIgnored for the 'all' target and without --redis-addr.")
	controlToken := fs.String("control-token", "", "Control token for the HTTP /control/kill endpoint. If empty, read from\nEUNOX_CONTROL_TOKEN or --control-token-path (default ~/.eunox/control.token),\nwhere the running proxy wrote it.")
	controlTokenPath := fs.String("control-token-path", "", "Path to the control-token file the proxy wrote (default ~/.eunox/control.token).\nUsed when --control-token and EUNOX_CONTROL_TOKEN are unset.")

	// Permit flags on either side of the positional: Go's flag package stops at the
	// first non-flag token, so a plain fs.Parse would reject "eunox kill all --port 3001"
	// (target first) while accepting "--port 3001 all" — a foot-gun on the emergency-stop
	// path. parseFlagsAndPositionals (used by `validate` for the same reason) peels the
	// positional and re-parses the rest, so order does not matter.
	pos, err := parseFlagsAndPositionals(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}
	if len(pos) != 1 {
		fmt.Fprintf(os.Stderr, "eunox kill: expected exactly one argument: <session-id|all>\n")
		return 1
	}
	target := pos[0]

	// Redis transport: write the kill directly to the shared kill-switch state —
	// the only revocation path for a stdio proxy launched with --redis-addr, which
	// has no HTTP /control/kill endpoint. Reject a mix of Redis and HTTP-transport
	// flags rather than silently picking one transport and ignoring flags meant
	// for the other, matching the package's fail-loud posture on conflicting flags
	// elsewhere (e.g. cmdProxy's --audit/--config check).
	if *redisAddr != "" {
		for _, name := range []string{"port", "host", "control-token", "control-token-path"} {
			// flagWasSet reports only flags the operator actually passed (unlike comparing
			// against defaults, which cannot distinguish an explicit --port=3000 from the
			// unset default), so it detects a flag mix that would otherwise be silently
			// dropped.
			if flagWasSet(fs, name) {
				fmt.Fprintf(os.Stderr, "eunox kill: --%s is an HTTP-transport flag and has no effect with --redis-addr set; remove --%s or drop --redis-addr\n", name, name)
				return 1
			}
		}
		if err := killViaRedis(*redisAddr, resolveRedisPassword(*redisPassword), *redisTLS, *sessionKillTTL, target); err != nil {
			fmt.Fprintf(os.Stderr, "eunox kill: %v\n", err)
			return 1
		}
		return 0
	}
	for _, name := range []string{"redis-password", "redis-tls"} {
		if flagWasSet(fs, name) {
			fmt.Fprintf(os.Stderr, "eunox kill: --%s requires --redis-addr; without it the kill silently uses the HTTP control endpoint instead of Redis\n", name)
			return 1
		}
	}

	var body map[string]interface{}
	if target == "all" {
		body = map[string]interface{}{"all": true}
	} else {
		body = map[string]interface{}{"sessionId": target}
	}

	// Resolve the control token the proxy requires on /control/kill.
	tok, err := transport.ResolveControlToken(*controlToken, *controlTokenPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "eunox kill: %v\n", err)
		return 1
	}

	data, _ := json.Marshal(body)
	killURL := killControlURL(*host, *port)
	// Bound the request: kill is the emergency-stop path, often invoked exactly
	// when the proxy is wedged (accept loop alive, handlers stuck) or the port is
	// blackholed. http.DefaultClient has no timeout, so an unbounded Do would hang
	// with no output and leave the operator unsure whether revocation landed. The
	// sibling Redis path is already bounded at 10s; match it here.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, killURL, bytes.NewReader(data)) //nolint:gosec // G107: URL constructed from user-specified --host/--port flags; one-shot CLI request
	if err != nil {
		fmt.Fprintf(os.Stderr, "eunox kill: %v\n", err)
		return 1
	}
	req.Header.Set("Content-Type", transport.CTJSON)
	req.Header.Set(transport.ControlTokenHeader, tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "eunox kill: request failed: %v\n", err)
		return 1
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, transport.MaxUpstreamErrBodyBytes))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "eunox kill: proxy returned %d: %s\n", resp.StatusCode, strings.TrimSpace(string(respBody)))
		return 1
	}
	fmt.Println(string(respBody))
	return 0
}

// killViaRedis writes a kill directly to the shared Redis kill-switch state,
// matching the HTTP /control/kill semantics: "all" activates the global switch;
// any other value kills that session. The Set is durable; live subscribers are
// notified via pub/sub, and any instance that missed the at-most-once message
// converges on its next reconcile tick. The only out-of-band revocation channel
// for a stdio proxy.
func killViaRedis(addr, password string, useTLS bool, sessionKillTTL time.Duration, target string) error {
	rdb, err := buildRedisClient(addr, password, useTLS)
	if err != nil {
		return fmt.Errorf("redis client: %w", err)
	}
	defer func() { _ = rdb.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := pingRedis(ctx, rdb); err != nil {
		return err
	}

	// The tombstone's TTL is set by whichever process WRITES the key, and this command is
	// the only out-of-band revocation channel a stdio proxy has — the very deployment
	// --killswitch-session-ttl exists for. Building the manager without the option here
	// would silently stamp the 30-day default on a kill an operator running the proxy with
	// a longer or never-expiring TTL believes is permanent, and the session would be
	// re-admitted the day it expired.
	ks := killswitch.NewRedis(rdb, killswitch.WithSessionKillTTL(sessionKillTTL))
	if target == "all" {
		if err := ks.ActivateGlobal(ctx); err != nil {
			return fmt.Errorf("activate global kill switch: %w", err)
		}
		fmt.Println(`{"ok":true,"killed":"all","via":"redis"}`)
		return nil
	}
	if err := ks.KillSession(ctx, target); err != nil {
		return fmt.Errorf("kill session %q: %w", target, err)
	}
	b, _ := json.Marshal(map[string]interface{}{"ok": true, "killed": target, "via": "redis"})
	fmt.Println(string(b))
	return nil
}
