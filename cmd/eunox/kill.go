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
       eunox kill [flags] --session <session-id>
       eunox kill [flags] --agent <agent-id>

Revoke one or all active sessions on a running eunox deployment, or with
--revive lift a revocation that was issued earlier.

There are three kill dimensions, and exactly one target must be given:

  <session-id>       Revoke that session. --session <id> is the same thing,
                     and is the only way to address a session whose id is
                     literally "all" (the positional "all" means the whole
                     deployment).
  all                Activate the deployment-wide kill switch. With --revive,
                     deactivate it; per-session and per-agent kills are left
                     in place -- revive those by id.
  --agent <agent-id> Revoke a JWT agent identity across every session it holds.
                     Agent kills never expire, so --revive --agent is how one
                     is lifted. Requires --redis-addr.

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
	sessionKillTTL := fs.Duration("killswitch-session-ttl", 0, "How long this SESSION kill survives in Redis before it is garbage collected.\nRarely needed: the proxy publishes its own value to Redis at startup and this\ncommand adopts it, so the two cannot silently disagree. Pass this only to\noverride that, or when no proxy has published one yet (default 720h / 30 days).\nWhen the tombstone expires the kill is LIFTED. Negative disables expiry. If it\ndisagrees with the published value, the longer-lived of the two is used and the\nmismatch is reported. Rejected together with the 'all' target, --agent,\n--revive, or without --redis-addr: none of those writes a session tombstone\n(an agent kill never expires at all), so the flag would have no effect.")
	revive := fs.Bool("revive", false, "Lift a revocation instead of issuing one: <session-id> removes that session's\nkill tombstone, so a new connection reusing that id is no longer blocked. The\nprimary case is a stdio proxy pinning one long-lived --session-id; for an HTTP\nproxy/gateway, a session killed via the loopback endpoint was already torn\ndown locally, and reviving its tombstone here does not restore that\nconnection. With --agent it removes an agent kill, which is the only way to\nlift one since agent kills never expire. 'all' deactivates the global kill\nswitch (per-session and per-agent kills are left in place — revive those by\nid). Requires --redis-addr: the HTTP control endpoint is an emergency stop\nwith no undo, and an in-memory kill switch is cleared by restarting the proxy.")
	sessionTarget := fs.String("session", "", "Target this SESSION id, instead of passing it as the positional argument.\nEquivalent in every way except one: the positional 'all' means the whole\ndeployment, so --session all is the only way to address a session whose id is\nliterally \"all\" (possible, since --session-id is operator-settable on a stdio\nproxy). Cannot be combined with the positional or --agent.")
	agentTarget := fs.String("agent", "", "Target this AGENT id (the JWT agent_id) instead of a session: revokes every\nsession that identity holds, and with --revive lifts that revocation. Agent\nkills never expire, so --revive is the only way to lift one. Requires\n--redis-addr — there is no agent dimension on the HTTP control endpoint, and\nadding one would widen what a same-host caller holding the control token can\nreach. Cannot be combined with the positional or --session.")
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
	target, err := resolveKillTarget(pos, *sessionTarget, flagWasSet(fs, "session"), *agentTarget, flagWasSet(fs, "agent"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "eunox kill: %v\n", err)
		return 1
	}
	// The agent dimension is Redis-only. /control/kill has no agent concept, and giving
	// it one would widen what a same-host process holding the control token can reach —
	// the same reasoning that keeps --revive off that transport. Checked here, before the
	// transport split below, so the rejection does not depend on which branch runs.
	if target.kind == killTargetAgent && *redisAddr == "" {
		fmt.Fprintf(os.Stderr, "eunox kill: --agent requires --redis-addr; the HTTP control endpoint has no agent dimension, and an in-memory kill switch is cleared by restarting the proxy\n")
		return 1
	}

	// Redis transport: write the kill directly to the shared kill-switch state —
	// the only revocation path for a stdio proxy launched with --redis-addr, which
	// has no HTTP /control/kill endpoint. Reject a mix of Redis and HTTP-transport
	// flags rather than silently picking one transport and ignoring flags meant
	// for the other, matching the package's fail-loud posture on conflicting flags
	// elsewhere (e.g. cmdProxy's --audit/--config check).
	if *redisAddr != "" {
		return runRedisKillTransport(fs, redisKillRequest{
			addr:           *redisAddr,
			password:       resolveRedisPassword(*redisPassword),
			useTLS:         *redisTLS,
			target:         target,
			revive:         *revive,
			sessionKillTTL: *sessionKillTTL,
			ttlFlagSet:     flagWasSet(fs, "killswitch-session-ttl"),
		})
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

// runRedisKillTransport handles the --redis-addr branch of `eunox kill`: it rejects the
// flag combinations that would be silently dropped on this transport, then performs the
// write. Split out of cmdKill so the subcommand's body stays the flag surface plus a
// two-way transport choice; the rejection rules are the part that grows with every new
// dimension, and they are easier to review as one block than interleaved with parsing.
func runRedisKillTransport(fs *flag.FlagSet, req redisKillRequest) int {
	// Reject a mix of Redis and HTTP-transport flags rather than silently picking one
	// transport and ignoring flags meant for the other, matching the package's fail-loud
	// posture on conflicting flags elsewhere (e.g. cmdProxy's --audit/--config check).
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
	// A tombstone lifetime is meaningless where no tombstone is written: --revive deletes
	// one instead of creating it, "all" activates the global switch, which carries no
	// per-session expiry at all (setBlock only reads sessionKillTTL on its kill&&session
	// path -- see pkg/killswitch/redis.go), and an agent kill is permanent by design.
	// Accepting the flag silently in any of the three would suggest it did something it
	// didn't.
	if req.ttlFlagSet {
		switch {
		case req.revive:
			fmt.Fprintf(os.Stderr, "eunox kill: --killswitch-session-ttl has no effect with --revive, which removes a tombstone rather than writing one; drop one of the two\n")
			return 1
		case req.target.kind == killTargetGlobal:
			fmt.Fprintf(os.Stderr, "eunox kill: --killswitch-session-ttl has no effect on the 'all' target, which activates the global kill switch with no per-session expiry; drop one of the two\n")
			return 1
		case req.target.kind == killTargetAgent:
			fmt.Fprintf(os.Stderr, "eunox kill: --killswitch-session-ttl has no effect with --agent; agent kills never expire, so there is no lifetime to set; drop one of the two\n")
			return 1
		}
	}
	if err := runRedisKill(req); err != nil {
		fmt.Fprintf(os.Stderr, "eunox kill: %v\n", err)
		return 1
	}
	return 0
}

// killViaControlEndpoint POSTs the kill to a running HTTP proxy's loopback
// /control/kill endpoint and returns the process exit code. Kill-only: the endpoint is
// a one-way emergency stop (see the --revive rejection in cmdKill), and session-or-global
// only — the agent dimension is rejected before this is reached.
func killViaControlEndpoint(host string, port int, controlToken, controlTokenPath string, target killTarget) int {
	var body map[string]interface{}
	if target.kind == killTargetGlobal {
		body = map[string]interface{}{"all": true}
	} else {
		// A session id, including the literal "all" reached via --session all: the
		// endpoint distinguishes the two dimensions by KEY, not by the id's spelling, so
		// {"sessionId":"all"} is unambiguous where the positional alone is not.
		body = map[string]interface{}{"sessionId": target.id}
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
//
// This overloading of the id space is why --session exists. A session id is
// operator-settable on a stdio proxy, so one can literally be "all", and a positional
// cannot express the difference — `--session all` is the escape hatch.
const killTargetAll = "all"

// killTargetKind names which of the three kill dimensions an invocation addresses. They
// are genuinely separate stores, not spellings of one: a global stop is a single flag, a
// session kill is a tombstone with a lifetime, and an agent kill is permanent. Making the
// dimension an explicit field rather than inferring it from the id's spelling is what
// lets "all" mean a session id when the operator says so.
type killTargetKind int

const (
	// killTargetUnset is the ZERO value, and is never a valid target. It is first on
	// purpose: with the global switch in this slot, a killTarget nobody filled in — the
	// value returned alongside every resolveKillTarget error, or a redisKillRequest
	// literal that omits the field — would mean "halt the entire deployment". The most
	// destructive dimension must not be what you get by writing nothing, least of all on
	// the emergency-stop path. Every consumer rejects this kind explicitly rather than
	// letting it fall through a default arm.
	killTargetUnset killTargetKind = iota
	// killTargetGlobal is the deployment-wide switch. It carries no id.
	killTargetGlobal
	killTargetSession
	killTargetAgent
)

// killTarget is one resolved target: which dimension, and (except for global) which id.
type killTarget struct {
	kind killTargetKind
	// id is the session or agent id; empty for killTargetGlobal, which addresses no
	// individual entity.
	id string
}

// dimension renders the target's kind for the machine-readable result line. Once two id
// dimensions exist, {"ok":true,"killed":"x"} alone is ambiguous — an operator (or a
// script) cannot tell which store moved.
// Every arm is explicit and the default fails loudly rather than inventing a plausible
// value: an unmapped kind that rendered as "global" while the switches below performed a
// session write would put a wrong dimension on the one line an operator reads to confirm
// what an emergency stop actually did.
func (t killTarget) dimension() string {
	switch t.kind {
	case killTargetAgent:
		return "agent"
	case killTargetSession:
		return "session"
	case killTargetGlobal:
		return "global"
	case killTargetUnset:
		return "unset"
	default:
		return "unknown"
	}
}

// resolveKillTarget turns the positional argument and the two targeting flags into
// exactly one target, or an error naming what to drop.
//
// Exactly one of the three must be supplied. Accepting more than one and picking a
// precedence would mean an operator on the emergency-stop path can type two targets and
// have one silently ignored — the same fail-loud posture the transport-flag checks in
// cmdKill already take.
// sessionSet/agentSet report whether the operator actually PASSED each flag, rather than
// whether its value is non-empty. `--session "$SID"` with SID unset is a supplied target
// whose id happens to be empty, not an absent one: counting it as absent would silently
// drop a target the operator typed (and, with a positional also present, resolve to the
// other one) — the very outcome the exactly-one rule exists to prevent. An explicitly
// empty id instead reaches the store's own empty-id guard and fails with a precise error.
func resolveKillTarget(pos []string, sessionFlag string, sessionSet bool, agentFlag string, agentSet bool) (killTarget, error) {
	if len(pos) > 1 {
		return killTarget{}, fmt.Errorf("expected exactly one argument: <session-id|all>")
	}
	// Build the candidate list once, so the count and the selection cannot disagree: a
	// fourth dimension added later is one append plus one arm, not a counter that can
	// drift from the arms it guards.
	var found []killTarget
	if len(pos) == 1 {
		if pos[0] == killTargetAll {
			found = append(found, killTarget{kind: killTargetGlobal})
		} else {
			found = append(found, killTarget{kind: killTargetSession, id: pos[0]})
		}
	}
	if sessionSet {
		// No killTargetAll special case on purpose: --session addresses a session id
		// verbatim, which is what makes it the escape hatch for one named "all".
		found = append(found, killTarget{kind: killTargetSession, id: sessionFlag})
	}
	if agentSet {
		found = append(found, killTarget{kind: killTargetAgent, id: agentFlag})
	}
	switch len(found) {
	case 0:
		return killTarget{}, fmt.Errorf("no target given: pass <session-id|all>, --session <session-id>, or --agent <agent-id>")
	case 1:
		return found[0], nil
	default:
		return killTarget{}, fmt.Errorf("more than one target given: pass exactly one of <session-id|all>, --session, or --agent, and drop the others")
	}
}

// redisKillRequest is one resolved `eunox kill --redis-addr` invocation. The fields are
// named rather than positional because several are same-typed knobs whose transposition
// would be silent — swapping the two booleans would invert the verb, and the TTL pair
// only means anything read together. The target carries its own dimension as a typed
// field for the same reason: with three dimensions in play, a bare id string is a value
// whose meaning depends on a convention the struct does not state.
type redisKillRequest struct {
	addr     string
	password string
	useTLS   bool
	// target is which kill dimension to write, and which id within it.
	target killTarget
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
	// resolved only on the path that writes one: a global kill carries no expiry, an
	// agent kill never expires, and a revive deletes rather than writes.
	var opts []killswitch.RedisOption
	if !req.revive && req.target.kind == killTargetSession {
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
	switch req.target.kind {
	case killTargetGlobal:
		if err := ks.ActivateGlobal(ctx); err != nil {
			return fmt.Errorf("activate global kill switch: %w", err)
		}
		printRedisResult("killed", req.target)
	case killTargetSession:
		if err := ks.KillSession(ctx, req.target.id); err != nil {
			return fmt.Errorf("kill session %q: %w", req.target.id, err)
		}
		printRedisResult("killed", req.target)
	case killTargetAgent:
		// Agent kills never expire. That is deliberate — an identity revoked for cause
		// should not be re-admitted by a clock — and it is why --revive --agent ships in
		// the same change: a permanent revocation primitive with no undo is the asymmetry
		// this dimension exists to avoid repeating.
		if err := ks.KillAgent(ctx, req.target.id); err != nil {
			return fmt.Errorf("kill agent %q: %w", req.target.id, err)
		}
		printRedisResult("killed", req.target)
		// An agent kill lands in Redis whatever the proxy is running, but it is only
		// CONSULTED where the proxy has a JWT identity to match it against: a stdio proxy
		// has no HTTP listener and so cannot take --jwks-uri at all, and an HTTP proxy
		// without it never populates an agent id either. Reporting a clean success while
		// the revocation is inert is the failure this warning exists to prevent -- the
		// operator has to know to check, since this command cannot see how the proxy was
		// started.
		fmt.Fprintf(os.Stderr, "eunox kill: the agent kill is written, but a proxy only consults agent identity when it validates JWTs (--jwks-uri, HTTP transport). A stdio proxy, or an HTTP proxy without --jwks-uri, will not match it -- kill the session ids instead there.\n")
	default:
		// Fail closed on a kind no arm handles rather than defaulting to a session write:
		// a dimension added to the enum without updating this switch would otherwise
		// revoke the wrong store while reporting success.
		return fmt.Errorf("internal: unhandled kill target kind %d (%s); refusing to guess which kill dimension was meant", req.target.kind, req.target.dimension())
	}
	return nil
}

// sessionKillTTLLookupTimeout bounds the published-TTL GET inside runRedisKill's shared
// 10s budget; see the call site for why it must be shorter than the outer context.
const sessionKillTTLLookupTimeout = 3 * time.Second

// reviveViaRedis lifts a revocation: for the global target it deactivates the switch (the
// exact inverse of `kill all`), and otherwise removes one session's tombstone or one
// agent's kill.
//
// Deactivating the global switch deliberately leaves per-session and per-agent kills in
// place — the three are separate kill dimensions, and clearing entities an operator
// revoked individually while they only meant to lift the deployment-wide stop would be a
// fail-open. Those are revived one id at a time.
//
// That same reasoning is why there is no `--reset`. The kill switch's Reset clears the
// global flag, every agent kill, and every session tombstone in one call, which is this
// same fail-open with a wider radius; a confirmation prompt in front of it is not a
// design. If clearing many stale session tombstones ever becomes a real operational pain,
// the shape to build is a session-SCOPED sweep backed by a SCAN over the session-kill
// prefix — never Reset, whose blast radius crosses dimensions the operator did not name.
//
// Takes the concrete *killswitch.Redis rather than the killswitch.Manager interface on
// purpose: the "revive is reachable only via the Redis transport" invariant this PR's
// other checks enforce at the CLI-flag layer (cmdKill's --redis-addr gate above) should
// also hold structurally, so a future refactor cannot reuse this helper against an
// in-memory or HTTP-proxy-held Manager and silently reintroduce an undo on the loopback
// /control/kill path — which must never exist (see the --revive rejection in cmdKill).
func reviveViaRedis(ctx context.Context, ks *killswitch.Redis, target killTarget) error {
	switch target.kind {
	case killTargetGlobal:
		if err := ks.DeactivateGlobal(ctx); err != nil {
			return fmt.Errorf("deactivate global kill switch: %w", err)
		}
		printRedisResultWithNote("revived", target,
			"per-session and per-agent kills are unaffected; revive those by id")
	case killTargetAgent:
		// The undo for a kill that never expires. Without it an agent revocation would be
		// remediable only by a library call or a hand-written redis-cli DEL.
		if err := ks.ReviveAgent(ctx, target.id); err != nil {
			return fmt.Errorf("revive agent %q: %w", target.id, err)
		}
		printRedisResult("revived", target)
	case killTargetSession:
		// ReviveSession is idempotent: an id that was never killed (or whose tombstone
		// already expired) deletes nothing and still succeeds, so the command is safe to
		// re-run and reports the state the operator asked for either way. ReviveAgent
		// above behaves the same way.
		if err := ks.ReviveSession(ctx, target.id); err != nil {
			return fmt.Errorf("revive session %q: %w", target.id, err)
		}
		printRedisResult("revived", target)
	default:
		// Fail closed on an unmapped kind, same as the kill switch above.
		return fmt.Errorf("internal: unhandled kill target kind %d (%s); refusing to guess which kill dimension was meant", target.kind, target.dimension())
	}
	return nil
}

// printRedisResult writes the {"ok":true,"<verb>":<id>,"dimension":...,"via":"redis"}
// line the Redis transport reports on success, marshaled rather than formatted so an id
// carrying a quote or backslash cannot break the JSON a caller parses.
//
// The dimension is carried explicitly because the id alone no longer identifies what
// moved: the same string can name a session or an agent, and a script reacting to the
// output needs to know which store it just changed.
func printRedisResult(verb string, target killTarget) {
	printRedisResultWithNote(verb, target, "")
}

// printRedisResultWithNote is printRedisResult plus an operator-facing note, used where
// the result needs a caveat about what it deliberately did NOT do.
func printRedisResultWithNote(verb string, target killTarget, note string) {
	// The global switch addresses no individual entity, so killTarget carries no id for
	// it (see the field's doc). Deriving the reported "all" here rather than having each
	// global call site hand-build a killTarget that violates that invariant keeps one
	// spelling of the global target in the program.
	id := target.id
	if target.kind == killTargetGlobal {
		id = killTargetAll
	}
	out := map[string]interface{}{"ok": true, verb: id, "dimension": target.dimension(), "via": "redis"}
	if note != "" {
		out["note"] = note
	}
	b, _ := json.Marshal(out)
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
		// Deliberately adopts the published value OUTRIGHT, without the longerTombstone
		// safe-direction policy the flag-set branch below applies. The asymmetry reads
		// like an oversight and is not: flooring this branch at the local default would
		// make the publish inert for a proxy configured deliberately SHORTER than the
		// default, and would print a mismatch line on every kill against one when nothing
		// is misconfigured. The published value is only trusted here because a stale one
		// cannot survive — the key carries an expiry the running proxy refreshes, so a
		// value that is readable at all belongs to a proxy that is running now.
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
