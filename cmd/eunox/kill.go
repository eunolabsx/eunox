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
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/eunolabs/eunox/internal/transport"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// killControlURL builds the http://host:port/control/kill URL. net.JoinHostPort brackets
// an IPv6 literal; "%s:%d" would emit the unparseable ::1:3000.
func killControlURL(host string, port int) string {
	return fmt.Sprintf("http://%s/control/kill", net.JoinHostPort(host, strconv.Itoa(port)))
}

// printKillUsage writes the kill subcommand's help. Split out of cmdKill because it is a screen
// of prose in the middle of a control flow that reads as a sequence — parse, resolve a target,
// pick a transport, execute — and the four kill dimensions made it long enough to bury that.
func printKillUsage(fs *flag.FlagSet, args []string) {
	w := usageWriter(args)
	_, _ = fmt.Fprint(w, `Usage: eunox kill [flags] <session-id|all>
       eunox kill [flags] --session <session-id>
       eunox kill [flags] --agent <agent-id>
       eunox kill [flags] --jti <token-id>

Revoke one or all active sessions on a running eunox deployment, or with
--revive lift a revocation that was issued earlier.

There are four kill dimensions, and exactly one target must be given:

  <session-id>       Revoke that session. --session <id> is the same thing,
                     and is the only way to address a session whose id is
                     literally "all" (the positional "all" means the whole
                     deployment).
  all                Activate the deployment-wide kill switch. With --revive,
                     deactivate it; per-session, per-agent and per-token kills
                     are left in place -- revive those by id.
  --agent <agent-id> Revoke a JWT agent identity across every session it holds.
                     Agent kills never expire, so --revive --agent is how one
                     is lifted. Requires --redis-addr.
  --jti <token-id>   Revoke one issued bearer token by its JWT jti, leaving the
                     same agent's other tokens serving. The dimension for a
                     LEAKED credential. Never expires, so --revive --jti is how
                     one is lifted (--revive itself requires --redis-addr).
                     Works over either transport.

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

Exit codes:
  0  The revocation (or --revive) was accepted by the proxy or written to Redis.
     This includes the case where the write landed but the real-time
     notification to other instances did not: the state is durable and every
     running proxy converges on its next reconcile tick, so the kill takes
     effect and the degradation is reported on stderr rather than as a failure.
  1  Anything else. Unlike the binary's other subcommands, kill does NOT split
     usage errors out as 2: the only question its caller has under pressure is
     whether the kill landed, and a second failure code would invite a script
     that treats one of them as success.

Flags:
`)
	fs.SetOutput(w)
	fs.PrintDefaults()
}

// cmdKill runs the `kill` subcommand, returning the exit code (rather than calling
// os.Exit) so tests can drive every branch.
func cmdKill(args []string) int {
	fs := flag.NewFlagSet("kill", flag.ContinueOnError)
	fs.Usage = func() { printKillUsage(fs, args) }
	port := fs.Int("port", 3000, "Port the HTTP proxy is listening on (HTTP transport).")
	host := fs.String("host", "127.0.0.1", "Host the HTTP proxy is bound to (HTTP transport).")
	redisAddr := fs.String("redis-addr", "", "Redis address (host:port). When set, the kill is written to the shared\nRedis kill-switch state instead of an HTTP endpoint — the only way to\nrevoke a stdio proxy started with --redis-addr.")
	redisPassword := fs.String("redis-password", "", "Password for the Redis server (used with --redis-addr). Prefer the\nEUNOX_REDIS_PASSWORD env var; a non-empty flag value takes precedence over\nit, but leaving the flag empty does NOT override a set env var.")
	redisTLS := fs.Bool("redis-tls", false, "Use TLS for the Redis connection (used with --redis-addr).")
	sessionKillTTL := fs.Duration("killswitch-session-ttl", 0, fmt.Sprintf("How long this SESSION kill survives in Redis before it is garbage collected.\nRarely needed: the proxy publishes its own value to Redis at startup and this\ncommand adopts it, so the two cannot silently disagree. Pass this only to\noverride that, or when no proxy has published one yet (default %s).\nWhen the tombstone expires the kill is LIFTED. Negative disables expiry. If it\ndisagrees with the published value, the longer-lived of the two is used and the\nmismatch is reported. Rejected together with the 'all' target, --agent, --jti,\n--revive, or without --redis-addr: none of those writes a session tombstone\n(agent kills and token revocations never expire at all), so the flag would\nhave no effect.", describeDefaultSessionKillTTL()))
	revive := fs.Bool("revive", false, "Lift a revocation instead of issuing one: <session-id> removes that session's\nkill tombstone, so a new connection reusing that id is no longer blocked. The\nprimary case is a stdio proxy pinning one long-lived --session-id; for an HTTP\nproxy/gateway, a session killed via the loopback endpoint was already torn\ndown locally, and reviving its tombstone here does not restore that\nconnection. With --agent it removes an agent kill, which is the only way to\nlift one since agent kills never expire. 'all' deactivates the global kill\nswitch (per-session and per-agent kills are left in place — revive those by\nid). Requires --redis-addr: the HTTP control endpoint is an emergency stop\nwith no undo, and an in-memory kill switch is cleared by restarting the proxy.")
	sessionTarget := fs.String("session", "", "Target this SESSION id, instead of passing it as the positional argument.\nEquivalent in every way except one: the positional 'all' means the whole\ndeployment, so --session all is the only way to address a session whose id is\nliterally \"all\" (possible, since --session-id is operator-settable on a stdio\nproxy). Cannot be combined with the positional or --agent.")
	jtiTarget := fs.String("jti", "", "Target this TOKEN id (the JWT `jti`) instead of a session or an agent: revokes\nexactly the one issued credential, leaving the same agent's other tokens\nserving. This is the dimension to reach for when a token LEAKS — killing the\nagent stops everything that identity holds, and killing a session stops one\nconnection, but neither is the credential that got out. Token revocations never\nexpire, so --revive is the only way to lift one (and --revive requires\n--redis-addr). Unlike --agent this works over either transport. A proxy only\nconsults it when it validates JWTs (--jwks-uri): a token id comes from the\nverified token and nowhere else. Cannot be combined with the positional,\n--session or --agent.")
	agentTarget := fs.String("agent", "", "Target this AGENT id (the JWT agent_id) instead of a session: revokes every\nsession that identity holds, and with --revive lifts that revocation. Agent\nkills never expire, so --revive is the only way to lift one. Requires\n--redis-addr — there is no agent dimension on the HTTP control endpoint, and\nadding one would widen what a same-host caller holding the control token can\nreach. Cannot be combined with the positional or --session.")
	controlToken := fs.String("control-token", "", "Control token for the HTTP /control/kill endpoint. If empty, read from\nEUNOX_CONTROL_TOKEN or --control-token-path (default ~/.eunox/control.token),\nwhere the running proxy wrote it.")
	controlTokenPath := fs.String("control-token-path", "", "Path to the control-token file the proxy wrote (default ~/.eunox/control.token).\nUsed when --control-token and EUNOX_CONTROL_TOKEN are unset.")

	// Go's flag package stops at the first non-flag token, so a plain fs.Parse would reject
	// "eunox kill all --port 3001" while accepting "--port 3001 all" — a foot-gun on the
	// emergency-stop path. parseFlagsAndPositionals makes order not matter.
	pos, err := parseFlagsAndPositionals(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		// 1, not the 2 its sibling commands use for a usage error: kill answers one
		// question — did the revocation land — and every failure is the same answer. See
		// the Exit codes block above.
		return 1
	}
	target, err := resolveKillTarget(pos,
		killFlagTarget{kind: killTargetSession, value: *sessionTarget, set: flagWasSet(fs, "session")},
		killFlagTarget{kind: killTargetAgent, value: *agentTarget, set: flagWasSet(fs, "agent")},
		killFlagTarget{kind: killTargetJTI, value: *jtiTarget, set: flagWasSet(fs, "jti")})
	if err != nil {
		fmt.Fprintf(os.Stderr, "eunox kill: %v\n", err)
		return 1
	}
	// The agent dimension is Redis-only: giving /control/kill an agent concept would widen
	// what a same-host process holding the control token can reach.
	if target.kind == killTargetAgent && *redisAddr == "" {
		fmt.Fprintf(os.Stderr, "eunox kill: --agent requires --redis-addr; the HTTP control endpoint has no agent dimension, and an in-memory kill switch is cleared by restarting the proxy\n")
		return 1
	}

	// Redis transport: the only revocation path for a stdio proxy, which has no HTTP
	// /control/kill endpoint. Reject a mix of Redis and HTTP-transport flags rather than
	// silently picking one and ignoring flags meant for the other.
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
	// The HTTP /control/kill endpoint is deliberately a one-way emergency stop: a same-host
	// process holding the control token could otherwise lift the very revocation it issued.
	// Reject rather than silently drop the flag on the emergency-stop path.
	if *revive {
		fmt.Fprintf(os.Stderr, "eunox kill: --revive requires --redis-addr; the HTTP control endpoint has no revive, and an in-memory kill switch is cleared by restarting the proxy\n")
		return 1
	}
	return killViaControlEndpoint(*host, *port, *controlToken, *controlTokenPath, target)
}

// runRedisKillTransport handles the --redis-addr branch of `eunox kill`: rejects flag
// combinations that would be silently dropped on this transport, then performs the write.
// Split out of cmdKill so the growing rejection rules are one block to review.
func runRedisKillTransport(fs *flag.FlagSet, req redisKillRequest) int {
	for _, name := range []string{"port", "host", "control-token", "control-token-path"} {
		// flagWasSet reports only flags actually passed, distinguishing an explicit
		// --port=3000 from the unset default.
		if flagWasSet(fs, name) {
			fmt.Fprintf(os.Stderr, "eunox kill: --%s is an HTTP-transport flag and has no effect with --redis-addr set; remove --%s or drop --redis-addr\n", name, name)
			return 1
		}
	}
	// A tombstone lifetime is meaningless where no tombstone is written: --revive deletes
	// rather than creates one, "all" carries no per-session expiry, and an agent kill is
	// permanent. Accepting the flag silently in any case would suggest it did something.
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
		case req.target.kind == killTargetJTI:
			fmt.Fprintf(os.Stderr, "eunox kill: --killswitch-session-ttl has no effect with --jti; token revocations never expire, so there is no lifetime to set; drop one of the two\n")
			return 1
		}
	}
	if err := runRedisKill(req); err != nil {
		fmt.Fprintf(os.Stderr, "eunox kill: %v\n", err)
		return 1
	}
	return 0
}

// killViaControlEndpoint POSTs the kill to a running HTTP proxy's loopback /control/kill
// endpoint. Kill-only — --revive and the agent dimension are rejected before this is reached.
func killViaControlEndpoint(host string, port int, controlToken, controlTokenPath string, target killTarget) int {
	// The endpoint distinguishes the dimensions by KEY, not by the id's spelling, so
	// {"sessionId":"all"} (via --session all) is unambiguous. Built from the target's own kind
	// rather than an if/else pair, so a dimension the endpoint accepts cannot be one the CLI
	// silently posts under another key.
	var body map[string]interface{}
	switch target.kind {
	case killTargetGlobal:
		body = map[string]interface{}{"all": true}
	case killTargetSession:
		body = map[string]interface{}{"sessionId": target.id}
	case killTargetJTI:
		body = map[string]interface{}{"jti": target.id}
	default:
		// Fail closed rather than posting a body for a dimension this transport does not
		// carry: the endpoint would reject it, but the useful error names the flag.
		fmt.Fprintf(os.Stderr, "eunox kill: the HTTP control endpoint has no %s dimension; use --redis-addr\n", target.dimension())
		return 1
	}

	tok, err := transport.ResolveControlToken(controlToken, controlTokenPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "eunox kill: %v\n", err)
		return 1
	}

	data, _ := json.Marshal(body)
	killURL := killControlURL(host, port)
	// Bound the request: kill is often invoked exactly when the proxy is wedged, and
	// http.DefaultClient has no timeout of its own. Matches the Redis path's 10s.
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
	// Both prints are bounded and stripped: --host/--port address whatever is listening
	// there, so these bytes are not necessarily the operator's own proxy — a typo'd host, a
	// local process that grabbed the port first, or a proxy the upstream it fronts has
	// compromised. 64 KiB through %s drives the terminal and forges log lines, and this
	// command is run under pressure with the operator reading the output. A no-op on what
	// the endpoint actually answers with: JSON escapes control runes, and the response names
	// one session id, itself bounded well under the truncation point.
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "eunox kill: proxy returned %d: %s\n", resp.StatusCode, transport.BoundConsoleDetail(string(respBody)))
		return 1
	}
	fmt.Println(transport.BoundConsoleDetail(string(respBody)))
	return 0
}

// killTargetAll is the positional that activates the global kill switch rather than one
// session. This overloads the id space, which is why --session exists: a session id is
// operator-settable and can literally be "all", so `--session all` is the escape hatch.
const killTargetAll = "all"

// killTargetKind names which of the three kill dimensions an invocation addresses — genuinely
// separate stores (a global flag, a session tombstone, a permanent agent kill), not spellings
// of one, so a dimension is never inferred from the id's spelling.
type killTargetKind int

const (
	// killTargetUnset is the zero value and never valid. It's first on purpose: if it sat
	// in the global slot, a killTarget nobody filled in would mean "halt the deployment" —
	// the most destructive dimension must not be what you get by writing nothing.
	killTargetUnset killTargetKind = iota
	// killTargetGlobal is the deployment-wide switch. It carries no id.
	killTargetGlobal
	killTargetSession
	killTargetAgent
	// killTargetJTI is the finest dimension: one issued bearer token, not everything the
	// agent holds or one connection.
	killTargetJTI
)

// killTarget is one resolved target: which dimension, and (except for global) which id.
type killTarget struct {
	kind killTargetKind
	// id is the session, agent or token id; empty for killTargetGlobal, which addresses
	// no individual entity.
	id string
}

// dimension renders the target's kind for the machine-readable result line — with two id
// dimensions in play, {"ok":true,"killed":"x"} alone can't tell a script which store moved.
// Every arm is explicit and the default fails loudly rather than inventing a plausible value.
func (t killTarget) dimension() string {
	switch t.kind {
	case killTargetAgent:
		return "agent"
	case killTargetSession:
		return "session"
	case killTargetJTI:
		return "jti"
	case killTargetGlobal:
		return "global"
	case killTargetUnset:
		return "unset"
	default:
		return "unknown"
	}
}

// killFlagTarget is one --flag dimension as the command line presented it: which kind it
// addresses, the id it carried, and whether `set` reports the flag was actually PASSED — not
// whether its value is non-empty. `--session "$SID"` with SID unset is a supplied target with
// an empty id, not an absent one, and must not silently fall through to the positional or a
// default.
type killFlagTarget struct {
	kind  killTargetKind
	value string
	set   bool
}

// resolveKillTarget picks the single target an invocation names, or reports why it cannot —
// accepting more than one and picking a precedence would let an operator type two targets and
// have one silently ignored.
//
// The flag dimensions arrive as a SLICE rather than a positional pair per dimension. With two
// they were four parameters whose transposition — a value with the wrong `set` bool — compiled
// silently and produced a kill on the wrong dimension. Adding the token id would have made it
// six. Now a dimension is one argument at the call site and the arity cannot drift from the
// meaning.
func resolveKillTarget(pos []string, flags ...killFlagTarget) (killTarget, error) {
	if len(pos) > 1 {
		return killTarget{}, fmt.Errorf("expected exactly one argument: <session-id|all>")
	}
	// Build the candidate list once, so the count and the selection cannot disagree.
	var found []killTarget
	if len(pos) == 1 {
		if pos[0] == killTargetAll {
			found = append(found, killTarget{kind: killTargetGlobal})
		} else {
			found = append(found, killTarget{kind: killTargetSession, id: pos[0]})
		}
	}
	for _, f := range flags {
		if !f.set {
			continue
		}
		// No killTargetAll special case on purpose: a --flag addresses an id verbatim —
		// the escape hatch for a session literally named "all".
		found = append(found, killTarget{kind: f.kind, id: f.value})
	}
	switch len(found) {
	case 0:
		return killTarget{}, fmt.Errorf("no target given: pass <session-id|all>, --session <session-id>, --agent <agent-id>, or --jti <token-id>")
	case 1:
		return found[0], nil
	default:
		return killTarget{}, fmt.Errorf("more than one target given: pass exactly one of <session-id|all>, --session, --agent, or --jti, and drop the others")
	}
}

// redisKillRequest is one resolved `eunox kill --redis-addr` invocation. Fields are named
// rather than positional since several are same-typed knobs whose transposition would be
// silent (swapping the two booleans inverts the verb).
type redisKillRequest struct {
	addr     string
	password string
	useTLS   bool
	// target is which kill dimension to write, and which id within it.
	target killTarget
	// revive inverts the operation: lift the revocation instead of issuing it.
	revive bool
	// sessionKillTTL is --killswitch-session-ttl (0=default, negative=never expire);
	// ttlFlagSet records whether it was actually passed, since 0 is also the unset default.
	sessionKillTTL time.Duration
	ttlFlagSet     bool
}

// runRedisKill writes a kill (or, with revive, its undo) directly to the shared Redis
// kill-switch state, matching /control/kill semantics. The Set is durable; live subscribers
// are notified via pub/sub, and any instance that misses the message converges on its next
// reconcile tick.
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

	// The TTL is resolved only on the path that actually writes a tombstone: a global kill
	// carries no expiry, an agent kill never expires, and a revive deletes rather than writes.
	var opts []killswitch.RedisOption
	if !req.revive && req.target.kind == killTargetSession {
		// A shorter budget carved out of the outer 10s: a slow-but-not-down Redis could
		// otherwise let this coordination lookup consume the budget the actual write needs.
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
		if err := killWriteOutcome("activate global kill switch", ks.ActivateGlobal(ctx)); err != nil {
			return err
		}
		printRedisResult("killed", req.target)
	case killTargetSession:
		if err := killWriteOutcome(fmt.Sprintf("kill session %q", req.target.id), ks.KillSession(ctx, req.target.id)); err != nil {
			return err
		}
		printRedisResult("killed", req.target)
	case killTargetAgent:
		// Agent kills never expire — an identity revoked for cause should not be
		// re-admitted by a clock.
		if err := killWriteOutcome(fmt.Sprintf("kill agent %q", req.target.id), ks.KillAgent(ctx, req.target.id)); err != nil {
			return err
		}
		printRedisResult("killed", req.target)
		// The kill is only CONSULTED where the proxy validates JWTs (--jwks-uri, HTTP);
		// a stdio proxy or one without it will not match it, so warn since this command
		// can't see how the proxy was started.
		fmt.Fprintf(os.Stderr, "eunox kill: the agent kill is written, but a proxy only consults agent identity when it validates JWTs (--jwks-uri, HTTP transport). A stdio proxy, or an HTTP proxy without --jwks-uri, will not match it -- kill the session ids instead there.\n")
	case killTargetJTI:
		// Token revocations never expire, for the agent kill's reason: a credential revoked
		// for cause should not be re-admitted by a clock. It stops being consulted when the
		// token's own exp passes, which is the holder's clock and not the operator's.
		if err := killWriteOutcome(fmt.Sprintf("revoke token %q", req.target.id), ks.RevokeJTI(ctx, req.target.id)); err != nil {
			return err
		}
		printRedisResult("killed", req.target)
		// Same caveat as the agent dimension, and narrower: a token id exists only where the
		// proxy validates JWTs, so a deployment that does not will never match it.
		fmt.Fprintf(os.Stderr, "eunox kill: the token revocation is written, but a proxy only knows a token id when it validates JWTs (--jwks-uri, HTTP transport). A stdio proxy, or an HTTP proxy without --jwks-uri, will not match it -- kill the session ids instead there.\n")
	default:
		// Fail closed on a kind no arm handles rather than defaulting to a session write.
		return fmt.Errorf("internal: unhandled kill target kind %d (%s); refusing to guess which kill dimension was meant", req.target.kind, req.target.dimension())
	}
	return nil
}

// sessionKillTTLLookupTimeout bounds the published-TTL GET inside runRedisKill's shared
// 10s budget; see the call site for why it must be shorter than the outer context.
const sessionKillTTLLookupTimeout = 3 * time.Second

// reviveViaRedis lifts a revocation: deactivates the global switch, or removes one session's
// tombstone or one agent's kill. Deactivating the global switch deliberately leaves
// per-session/per-agent kills in place — clearing entities an operator revoked individually
// while only meaning to lift the deployment-wide stop would be a fail-open (same reason
// there is no `--reset`). Takes the concrete *killswitch.Redis, not the Manager interface, so
// "revive is Redis-only" holds structurally and can't be reused against an in-memory or
// HTTP-proxy-held Manager to reintroduce an undo on the loopback /control/kill path.
func reviveViaRedis(ctx context.Context, ks *killswitch.Redis, target killTarget) error {
	switch target.kind {
	case killTargetGlobal:
		if err := killWriteOutcome("deactivate global kill switch", ks.DeactivateGlobal(ctx)); err != nil {
			return err
		}
		printRedisResultWithNote("revived", target,
			"per-session, per-agent and per-token kills are unaffected; revive those by id")
	case killTargetAgent:
		// The undo for a kill that never expires otherwise.
		if err := killWriteOutcome(fmt.Sprintf("revive agent %q", target.id), ks.ReviveAgent(ctx, target.id)); err != nil {
			return err
		}
		printRedisResult("revived", target)
	case killTargetSession:
		// Idempotent: an id never killed (or already expired) deletes nothing and still
		// succeeds, so the command is safe to re-run.
		if err := killWriteOutcome(fmt.Sprintf("revive session %q", target.id), ks.ReviveSession(ctx, target.id)); err != nil {
			return err
		}
		printRedisResult("revived", target)
	case killTargetJTI:
		// The undo for a revocation that never expires otherwise, as for an agent.
		if err := killWriteOutcome(fmt.Sprintf("revive token %q", target.id), ks.ReviveJTI(ctx, target.id)); err != nil {
			return err
		}
		printRedisResult("revived", target)
	default:
		// Fail closed on an unmapped kind, same as the kill switch above.
		return fmt.Errorf("internal: unhandled kill target kind %d (%s); refusing to guess which kill dimension was meant", target.kind, target.dimension())
	}
	return nil
}

// killWriteOutcome folds one kill/revive write into the only question this command's exit
// contract answers: did the revocation land in the shared state. what names the operation for
// the failure message ("kill session \"x\"").
//
// killswitch.ErrPublishFailed means it DID land — the durable write succeeded and only the
// real-time pub/sub notification was lost, so every live proxy picks the kill up on its next
// reconcile tick. Returning that as a failure contradicted the documented exit contract ("0 =
// the revocation was written to Redis") and, on a Redis ACL granting SET/DEL/SCAN but not
// PUBLISH, made every kill report failure forever while in fact taking effect — the worst
// direction to be wrong in on an emergency stop, since the operator's next move is to assume
// nothing was revoked.
//
// The degradation is announced on stderr; stdout keeps the machine-readable result line, the
// same split resolveSessionKillTTL's fallbacks use.
func killWriteOutcome(what string, err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, killswitch.ErrPublishFailed):
		// The tick is named by its FLAG rather than by a duration. Convergence happens on each
		// running PROXY's own --killswitch-reconcile-interval, and this command has no proxy's
		// configuration in hand — printing its own default would state a number that is wrong
		// for exactly the deployment that tuned it, in the message an operator acts on.
		fmt.Fprintf(os.Stderr, "eunox kill: %s: the revocation IS written to the shared Redis state, but the real-time notification to running proxies failed (%v). Each running proxy converges on its next reconcile tick (--killswitch-reconcile-interval), so the kill still takes effect and this does not need re-running.\n",
			what, err)
		return nil
	default:
		return fmt.Errorf("%s: %w", what, err)
	}
}

// printRedisResult writes the {"ok":true,"<verb>":<id>,"dimension":...,"via":"redis"} line,
// marshaled rather than formatted so an id carrying a quote can't break the JSON.
func printRedisResult(verb string, target killTarget) {
	printRedisResultWithNote(verb, target, "")
}

// printRedisResultWithNote is printRedisResult plus an operator-facing note, used where
// the result needs a caveat about what it deliberately did NOT do.
func printRedisResultWithNote(verb string, target killTarget, note string) {
	// killTarget carries no id for the global switch; derive "all" here rather than have
	// each call site hand-build a killTarget that violates that invariant.
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
// preferring the proxy's published Redis value over the local flag — an expiring tombstone
// LIFTS the kill, so a silent disagreement re-admits a session an operator revoked. Every
// fallback is announced on stderr; stdout stays the machine-readable result line.
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
		// Adopts the published value OUTRIGHT (no longer-wins comparison): flooring at the
		// local default would make the publish inert for a proxy configured deliberately
		// shorter. Trusted because a stale value can't survive — the key's own expiry is
		// refreshed by the running proxy.
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
