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

	goredis "github.com/redis/go-redis/v9"

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

Revoke one or all active sessions on a running eunox deployment, or with
--revive lift a revocation that was issued earlier.

There are two transports, matching how the proxy shares kill-switch state:

  HTTP control endpoint (default)
      POSTs to /control/kill on an HTTP proxy (loopback only). Use this for a
      'transport: http' proxy or gateway.

  Redis (--redis-addr)
      Writes the kill straight to the shared Redis kill-switch state. Use this
      for a stdio proxy started with --redis-addr — a stdio proxy has no HTTP
      control endpoint — or to revoke across every proxy instance sharing one
      Redis at once. This is also the only transport that can --revive.

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
	sessionKillTTL := fs.Duration("killswitch-session-ttl", 0, "How long this SESSION kill survives in Redis before it is garbage collected.\nRarely needed: the proxy publishes its own value to Redis at startup and this\ncommand adopts it, so the two cannot silently disagree. Pass this only to\noverride that, or when no proxy has published one yet (default 720h / 30 days).\nWhen the tombstone expires the kill is LIFTED. Negative disables expiry. If it\ndisagrees with the published value, the longer-lived of the two is used and the\nmismatch is reported. Rejected together with the 'all' target, --revive, or\nwithout --redis-addr: none of the three writes a session tombstone, so the\nflag would have no effect.")
	revive := fs.Bool("revive", false, "Lift a revocation instead of issuing one: <session-id> removes that session's\nkill tombstone, so a new connection reusing that id is no longer blocked. The\nprimary case is a stdio proxy pinning one long-lived --session-id; for an HTTP\nproxy/gateway, a session killed via the loopback endpoint was already torn\ndown locally, and reviving its tombstone here does not restore that\nconnection. 'all' deactivates the global kill switch (per-session tombstones\nare left in place — revive those by id). Requires --redis-addr: the HTTP\ncontrol endpoint is an emergency stop with no undo, and an in-memory kill\nswitch is cleared by restarting the proxy.")
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
		// A tombstone lifetime is meaningless where no tombstone is written: --revive
		// deletes one instead of creating it, and "all" activates the global switch,
		// which carries no per-session expiry at all (setBlock only reads sessionKillTTL
		// on its kill&&session path — see pkg/killswitch/redis.go). Accepting the flag
		// silently in either case would suggest it did something it didn't.
		if flagWasSet(fs, "killswitch-session-ttl") {
			switch {
			case *revive:
				fmt.Fprintf(os.Stderr, "eunox kill: --killswitch-session-ttl has no effect with --revive, which removes a tombstone rather than writing one; drop one of the two\n")
				return 1
			case target == killTargetAll:
				fmt.Fprintf(os.Stderr, "eunox kill: --killswitch-session-ttl has no effect on the 'all' target, which activates the global kill switch with no per-session expiry; drop one of the two\n")
				return 1
			}
		}
		if err := runRedisKill(redisKillRequest{
			addr:           *redisAddr,
			password:       resolveRedisPassword(*redisPassword),
			useTLS:         *redisTLS,
			target:         target,
			revive:         *revive,
			sessionKillTTL: *sessionKillTTL,
			ttlFlagSet:     flagWasSet(fs, "killswitch-session-ttl"),
		}); err != nil {
			fmt.Fprintf(os.Stderr, "eunox kill: %v\n", err)
			return 1
		}
		return 0
	}
	for _, name := range []string{"redis-password", "redis-tls", "killswitch-session-ttl"} {
		if flagWasSet(fs, name) {
			fmt.Fprintf(os.Stderr, "eunox kill: --%s requires --redis-addr; without it the kill silently uses the HTTP control endpoint instead of Redis\n", name)
			return 1
		}
	}
	// Revocation is undone where the kill-switch state actually lives. The HTTP
	// /control/kill endpoint is deliberately a one-way emergency stop -- a same-host
	// process that reaches it holding the control token can already halt the proxy, and
	// giving that same reach an undo would let it lift the very revocation issued
	// against it. Without --redis-addr the state is also in-memory and process-local, so
	// restarting the proxy clears it. Reject rather than fall through to a kill: a flag
	// that inverts the verb must never be silently dropped on the emergency-stop path.
	if *revive {
		fmt.Fprintf(os.Stderr, "eunox kill: --revive requires --redis-addr; the HTTP control endpoint has no revive, and an in-memory kill switch is cleared by restarting the proxy\n")
		return 1
	}
	return killViaControlEndpoint(*host, *port, *controlToken, *controlTokenPath, target)
}

// killViaControlEndpoint POSTs the kill to a running HTTP proxy's loopback
// /control/kill endpoint and returns the process exit code. Kill-only: the endpoint is
// a one-way emergency stop (see the --revive rejection in cmdKill).
func killViaControlEndpoint(host string, port int, controlToken, controlTokenPath, target string) int {
	var body map[string]interface{}
	if target == killTargetAll {
		body = map[string]interface{}{"all": true}
	} else {
		body = map[string]interface{}{"sessionId": target}
	}

	// Resolve the control token the proxy requires on /control/kill.
	tok, err := transport.ResolveControlToken(controlToken, controlTokenPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "eunox kill: %v\n", err)
		return 1
	}

	data, _ := json.Marshal(body)
	killURL := killControlURL(host, port)
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

// killTargetAll is the positional that addresses the whole deployment rather than one
// session: it activates the global kill switch, and with --revive deactivates it.
const killTargetAll = "all"

// redisKillRequest is one resolved `eunox kill --redis-addr` invocation. The fields are
// named rather than positional because several are same-typed knobs whose transposition
// would be silent — swapping the two booleans would invert the verb, and the TTL pair
// only means anything read together.
type redisKillRequest struct {
	addr     string
	password string
	useTLS   bool
	// target is a session id, or killTargetAll for the whole deployment.
	target string
	// revive inverts the operation: lift the revocation instead of issuing it.
	revive bool
	// sessionKillTTL is the --killswitch-session-ttl flag in its operator-facing form
	// (0 = default, negative = never expire), and ttlFlagSet records whether the
	// operator actually passed it — the two are only meaningful together, since 0 is
	// both the unset default and a legitimate explicit value.
	sessionKillTTL time.Duration
	ttlFlagSet     bool
}

// runRedisKill writes a kill (or, with revive, its undo) directly to the shared Redis
// kill-switch state, matching the HTTP /control/kill semantics: "all" activates the
// global switch; any other value kills that session. The Set is durable; live
// subscribers are notified via pub/sub, and any instance that missed the at-most-once
// message converges on its next reconcile tick. The only out-of-band revocation channel
// for a stdio proxy — and, with revive, the only way to lift a revocation without
// hand-deleting keys in redis-cli.
func runRedisKill(req redisKillRequest) error {
	rdb, err := buildRedisClient(req.addr, req.password, req.useTLS)
	if err != nil {
		return fmt.Errorf("redis client: %w", err)
	}
	defer func() { _ = rdb.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := pingRedis(ctx, rdb); err != nil {
		return err
	}

	// The tombstone's TTL is stamped by whichever process WRITES the key, so it is
	// resolved only on the path that writes one: a global kill carries no expiry, and a
	// revive deletes rather than writes.
	var opts []killswitch.RedisOption
	if !req.revive && req.target != killTargetAll {
		// The published-TTL lookup gets its own, shorter budget carved out of the outer
		// 10s: it is a coordination nicety, not the kill itself, and if it shared the
		// full context a slow-but-not-down Redis could let the lookup consume most of
		// the budget before the actual write below ever runs — turning a kill that
		// would have succeeded pre-lookup into a timeout. On expiry
		// ReadPublishedSessionKillTTL returns a context error, which resolveSessionKillTTL
		// already treats like any other read failure: fall back to the local value and
		// warn, never block the write.
		ttlCtx, ttlCancel := context.WithTimeout(ctx, sessionKillTTLLookupTimeout)
		effective := resolveSessionKillTTL(ttlCtx, rdb, req.sessionKillTTL, req.ttlFlagSet)
		ttlCancel()
		opts = append(opts, killswitch.WithSessionKillTTLEffective(effective))
	}
	ks := killswitch.NewRedis(rdb, opts...)

	if req.revive {
		return reviveViaRedis(ctx, ks, req.target)
	}
	if req.target == killTargetAll {
		if err := ks.ActivateGlobal(ctx); err != nil {
			return fmt.Errorf("activate global kill switch: %w", err)
		}
		printRedisResult("killed", killTargetAll)
		return nil
	}
	if err := ks.KillSession(ctx, req.target); err != nil {
		return fmt.Errorf("kill session %q: %w", req.target, err)
	}
	printRedisResult("killed", req.target)
	return nil
}

// sessionKillTTLLookupTimeout bounds the published-TTL GET inside runRedisKill's shared
// 10s budget; see the call site for why it must be shorter than the outer context.
const sessionKillTTLLookupTimeout = 3 * time.Second

// reviveViaRedis lifts a revocation: for killTargetAll it deactivates the global switch
// (the exact inverse of `kill all`), and otherwise removes one session's tombstone.
//
// Deactivating the global switch deliberately leaves per-session tombstones in place —
// the two are separate kill dimensions, and clearing sessions an operator revoked
// individually while they only meant to lift the deployment-wide stop would be a
// fail-open. Those are revived one id at a time.
//
// Takes the concrete *killswitch.Redis rather than the killswitch.Manager interface on
// purpose: the "revive is reachable only via the Redis transport" invariant this PR's
// other checks enforce at the CLI-flag layer (cmdKill's --redis-addr gate above) should
// also hold structurally, so a future refactor cannot reuse this helper against an
// in-memory or HTTP-proxy-held Manager and silently reintroduce an undo on the loopback
// /control/kill path — which must never exist (see the --revive rejection in cmdKill).
func reviveViaRedis(ctx context.Context, ks *killswitch.Redis, target string) error {
	if target == killTargetAll {
		if err := ks.DeactivateGlobal(ctx); err != nil {
			return fmt.Errorf("deactivate global kill switch: %w", err)
		}
		fmt.Println(`{"ok":true,"revived":"all","via":"redis","note":"per-session kills are unaffected; revive those by id"}`)
		return nil
	}
	// ReviveSession is idempotent: an id that was never killed (or whose tombstone
	// already expired) deletes nothing and still succeeds, so the command is safe to
	// re-run and reports the state the operator asked for either way.
	if err := ks.ReviveSession(ctx, target); err != nil {
		return fmt.Errorf("revive session %q: %w", target, err)
	}
	printRedisResult("revived", target)
	return nil
}

// printRedisResult writes the {"ok":true,"<verb>":<target>,"via":"redis"} line the
// Redis transport reports on success, marshaled rather than formatted so a session id
// carrying a quote or backslash cannot break the JSON a caller parses.
func printRedisResult(verb, target string) {
	b, _ := json.Marshal(map[string]interface{}{"ok": true, verb: target, "via": "redis"})
	fmt.Println(string(b))
}

// resolveSessionKillTTL decides the lifetime this session tombstone is written with,
// preferring the value the proxy published to Redis at startup over this command's own
// flag. Takes only the two fields of redisKillRequest it actually reads (rather than the
// whole struct) so a reader of the signature does not have to check the body to learn
// this is independent of target/revive/addr/password/useTLS.
//
// The TTL is applied by whichever process writes the tombstone, and this command is one
// of the two writers — the only out-of-band revocation channel a stdio proxy has. As two
// independent flags they could disagree with no diagnostic, and the failure runs one
// way: an expiring tombstone LIFTS the kill, re-admitting a session an operator revoked.
// Adopting the published value removes the disagreement entirely for the common case
// (no flag passed here at all). Where the two still disagree, the conflict itself is
// resolved by killswitch.ResolveSessionKillTTLConflict — the exported decision policy, so
// a future non-CLI writer of tombstones can reuse it rather than re-derive the direction.
// Every fallback is announced on stderr so the resolved lifetime is never silent, and
// stdout stays the machine-readable result line.
func resolveSessionKillTTL(ctx context.Context, rdb goredis.Cmdable, sessionKillTTL time.Duration, ttlFlagSet bool) time.Duration {
	local := killswitch.NormalizeSessionKillTTL(sessionKillTTL)
	published, ok, err := killswitch.ReadPublishedSessionKillTTL(ctx, rdb)
	switch {
	case err != nil:
		fmt.Fprintf(os.Stderr, "eunox kill: could not read the session-kill TTL published by the proxy (%v); writing this tombstone with %s. If the proxy runs a different --killswitch-session-ttl, this kill expires on its own schedule.\n", err, killswitch.DescribeSessionKillTTL(local))
		return local
	case !ok:
		if ttlFlagSet {
			fmt.Fprintf(os.Stderr, "eunox kill: no proxy on this Redis has published a session-kill TTL; using --killswitch-session-ttl (%s), which must match the proxy's.\n", killswitch.DescribeSessionKillTTL(local))
		} else {
			fmt.Fprintf(os.Stderr, "eunox kill: no proxy on this Redis has published a session-kill TTL; writing this tombstone with the default (%s). Restart the proxy to publish its value, or pass --killswitch-session-ttl to match it.\n", killswitch.DescribeSessionKillTTL(local))
		}
		return local
	case !ttlFlagSet:
		fmt.Fprintf(os.Stderr, "eunox kill: session-kill TTL %s (published by the proxy on this Redis).\n", killswitch.DescribeSessionKillTTL(published))
		return published
	default:
		effective, mismatch := killswitch.ResolveSessionKillTTLConflict(local, published)
		if mismatch {
			fmt.Fprintf(os.Stderr, "eunox kill: session-kill TTL mismatch — the proxy published %s, --killswitch-session-ttl says %s; writing this tombstone with %s, the longer-lived of the two, so it cannot expire before the proxy's own kills. Align the two values.\n",
				killswitch.DescribeSessionKillTTL(published), killswitch.DescribeSessionKillTTL(local), killswitch.DescribeSessionKillTTL(effective))
		}
		return effective
	}
}
