// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// eunox is a policy-enforcement proxy for MCP (Model Context Protocol)
// servers.  It sits between an MCP host (e.g. Claude Desktop) and an upstream
// MCP server subprocess, evaluating every tools/call request against a local
// capability manifest before forwarding it.
//
// Subcommands:
//
//	proxy          Start the proxy (stdio or HTTP transport).
//	validate       Validate manifest file(s); with --live, diff against a running upstream.
//	init           Generate a deny-all starter manifest from a live upstream's tool list.
//	suggest        Generate a draft manifest from the audit log (observed usage).
//	kill           Revoke a session via a proxy's HTTP control endpoint, or
//	               directly via shared Redis state (--redis-addr) for stdio proxies.
//	audit-verify   Verify HMAC signatures in the audit log.
//	stats          Print a denial histogram from the audit log.
//	doctor         Print a user-initiated support bundle for bug reports.
//	version        Print the binary version and exit.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/internal/config"
	"github.com/eunolabs/eunox/internal/drift"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/internal/transport"
	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/flowlabelstore"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// version is set at build time via -ldflags "-X main.version=<tag>";
// "dev" is the fallback for untagged local/CI builds.
var version = "dev"

func init() {
	// Keep the version reported in MCP initialize responses in sync with the build.
	transport.SetProxyVersion(version)
}

func main() {
	os.Exit(run(os.Args))
}

// run dispatches the subcommand in args (program name at args[0], like os.Args)
// and returns the exit code. Kept separate from main so tests can assert the
// code without terminating the test binary; main holds the only os.Exit in the
// binary — every subcommand returns its code rather than exiting.
//
// Every subcommand takes its own arguments (args[2:]) as a parameter rather than
// re-reading the global os.Args: the dispatch and the flag parsing then read the
// same argument vector, so a caller that is not main cannot pick a subcommand
// while its flags come from the real process arguments.
func run(args []string) int {
	if len(args) < 2 {
		// A bare invocation prints usage and exits 0 (not a usage error): package
		// validators like winget launch the installed binary with no args and flag
		// any non-zero exit. Printing help is also conventional CLI behavior.
		printUsage(os.Stdout)
		return 0
	}
	subArgs := args[2:]
	switch args[1] {
	case "proxy":
		return cmdProxy(subArgs)
	case "validate":
		return cmdValidate(subArgs)
	case "init":
		return cmdInit(subArgs)
	case "suggest":
		return cmdSuggest(subArgs)
	case "kill":
		return cmdKill(subArgs)
	case "audit-verify":
		return cmdAuditVerify(subArgs)
	case "stats":
		return cmdStats(subArgs)
	case "doctor":
		return cmdDoctor(subArgs)
	case "version", "--version", "-version":
		cmdVersion()
	case "--help", "-help", "-h", "help":
		// An explicit help request is a successful query: usage to stdout, exit 0.
		printUsage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "eunox: unknown subcommand %q\n\nRun 'eunox --help' for usage.\n", args[1])
		return 1
	}
	return 0
}

// cmdVersion prints the build version and exits.
func cmdVersion() {
	fmt.Printf("eunox version %s\n", version)
}

// printUsage writes the top-level usage text to w. Help and bare invocations
// pass os.Stdout (a successful query, exit 0); callers that print usage as part
// of an error pass os.Stderr.
func printUsage(w io.Writer) {
	_, _ = fmt.Fprintf(w, `eunox — MCP policy-enforcement proxy (%s)

Usage:
  eunox proxy        --config <eunox.yaml>
  eunox validate     <manifest.yaml> [...]
  eunox validate     <manifest.yaml> --live --upstream-url <url>
  eunox validate     --config <eunox.yaml> [--live]
  eunox init         --upstream-url <url> [--output manifest.yaml] [--config-output eunox.yaml]
  eunox suggest      [--audit-log <path>] [--output manifest.yaml]
  eunox kill         [--port N | --redis-addr H:P] <session-id|all>
  eunox audit-verify [flags]
  eunox stats        [flags]
  eunox doctor       [flags]
  eunox version

Subcommands:
  proxy           Start the policy-enforcement proxy. --config declares the host
                  transport (stdio or http), the upstream(s), and per-route policy.
  validate        Validate manifest file(s) and exit 0 on success.
                  With --live: connect to a running upstream and report contract drift.
  init            Generate a deny-all starter manifest (and, with --config-output, a runnable config) from a live upstream's tool list.
  suggest         Generate a draft manifest from the audit log — grounds entries (and allowedValues
                  conditions) in what the agent actually did. Run a wiretap (proxy --audit) first.
  kill            Revoke one or all sessions on a running proxy — via the HTTP
                  control endpoint, or with --redis-addr via the shared Redis
                  kill switch (the only channel for a stdio proxy).
  audit-verify    Verify HMAC signatures in the local audit log.
  stats           Print a denial count histogram from the audit log.
  doctor          Print a user-initiated support bundle (redacted) for bug reports.
                  Nothing is uploaded — paste the output into your report manually.
  version         Print the binary version and exit.

Run 'eunox <subcommand> --help' for per-command flags.
`, version)
}

// -----------------------------------------------------------------
// proxy subcommand
// -----------------------------------------------------------------

// defaultMaxCallCounterKeys bounds the in-memory call counter's key set. Each
// (session, tool) pair is one map entry, reclaimed only on the periodic Cleanup,
// so a deployment minting a fresh session per request could otherwise grow the
// map without bound and OOM. A backstop far above any realistic live-session
// count, not a policy; --max-call-counter-keys tunes it (0 disables). A call
// under a new key past the ceiling is refused — fail-closed for maxCalls,
// fail-open for sequenceBlock (skipped antecedent leaves a later check unable to
// block); see the threat model's "In-memory store footprint" note.
const defaultMaxCallCounterKeys = 1_000_000

// defaultMaxSessions caps concurrent client sessions for the HTTP transport.
// Each session owns one upstream subprocess or remote connection, so an uncapped
// listener lets an unauthenticated client (off-loopback bind) spawn upstreams
// without bound — a fork-bomb DoS. A backstop far above realistic use, not a
// policy; tune via listen.maxSessions / --max-sessions, or 0 for uncapped.
const defaultMaxSessions = 512

// proxyCLIFlags holds the parsed `proxy` subcommand flags. registerProxyFlags
// binds them to a FlagSet; cmdProxy reads them after fs.Parse.
type proxyCLIFlags struct {
	configPath           *string
	audit                *bool
	wiretapURL           *string
	wiretapAuthHeader    *string
	wiretapTLSSkipVerify *bool
	unsafeBindAll        *bool
	trustFwdFor          *bool
	auditLog             *string
	auditKeyPath         *string
	controlTokenPath     *string
	auditRotateSize      *int64
	auditRetainRotated   *int
	sessionID            *string
	shutdownTimeout      *int
	upstreamTimeout      *int
	maxSessions          *int
	sessionIdleTimeout   *int
	jwksURI              *string
	jwtIssuer            *string
	jwtAudience          *string
	jwtAllowAnyAudience  *bool
	jwtAllowAnyIssuer    *bool
	jwtLeeway            *time.Duration
	jwksAllowInsecure    *bool
	jwtExperimentalCaps  *bool
	oauthResource        *string
	oauthAuthzServer     *string
	redisAddr            *string
	redisPassword        *string
	redisTLS             *bool
	killswitchFailOpen   *bool
	killswitchReconcile  *time.Duration
	killswitchSessionTTL *time.Duration
	maxCallCounterKeys   *int
	requireAudit         *auditRequirement
	strictDrift          *bool
}

// auditRequirement is the --require-audit value — a three-state knob over how
// missing audit coverage is handled:
//
//	strict (default)  sink-open failure fatal at startup, plus a runtime
//	                  fail-closed gate: once the audit trail degrades (record
//	                  dropped under back-pressure, or a log write fails), every
//	                  enforced call and */list enumeration is denied
//	                  (AUDIT_UNAVAILABLE) rather than forwarded unrecorded.
//	on                sink-open failure fatal at startup, but the runtime gate is
//	                  off: a later dropped record is counted and warned, not denied.
//	off               sink-open failure warns; the proxy continues unaudited.
//
// It implements flag.Value with IsBoolFlag so a bare/truthy --require-audit
// selects "strict", the omitted default — the proxy fails closed on audit loss
// out of the box.
type auditRequirement int

const (
	auditRequireOff auditRequirement = iota
	auditRequireOn
	auditRequireStrict
)

// String renders the flag's value (and its default in -help).
func (a *auditRequirement) String() string {
	switch *a {
	case auditRequireOn:
		return "on"
	case auditRequireStrict:
		return "strict"
	default:
		return "off"
	}
}

// Set parses a --require-audit value: bare/truthy spellings → "strict", "on" and
// "off" as named. Anything else is a hard error so a typo fails closed at parse
// time rather than silently disabling the requirement.
func (a *auditRequirement) Set(s string) error {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "true", "strict", "1", "yes":
		*a = auditRequireStrict
	case "on":
		*a = auditRequireOn
	case "false", "off", "0", "no":
		*a = auditRequireOff
	default:
		return fmt.Errorf("invalid --require-audit value %q (want off, on, or strict)", s)
	}
	return nil
}

// IsBoolFlag lets bare `--require-audit` parse as "strict". Like every Go bool
// flag, an explicit value needs '=' (--require-audit=on); a space-separated
// --require-audit on would read "on" as a positional.
func (a *auditRequirement) IsBoolFlag() bool { return true }

// required reports whether a sink-open failure should be fatal at startup
// (on or strict).
func (a auditRequirement) required() bool { return a != auditRequireOff }

// strict reports whether the runtime fail-closed audit gate is enabled.
func (a auditRequirement) strict() bool { return a == auditRequireStrict }

// registerProxyFlags declares every `proxy` flag on fs and returns the bound
// pointers, keeping the ~30 declarations out of cmdProxy's body.
func registerProxyFlags(fs *flag.FlagSet) *proxyCLIFlags {
	// --require-audit is a three-state flag.Var, bound outside the struct literal
	// below. Defaults to strict; relax with =on / =off.
	requireAudit := new(auditRequirement)
	*requireAudit = auditRequireStrict
	fs.Var(requireAudit, "require-audit", "Audit-coverage requirement: strict (default), on, or off.\n"+
		"strict (the default, also a bare --require-audit) a sink-open failure is fatal at\n"+
		"       startup, plus a runtime fail-closed gate: once the audit trail degrades\n"+
		"       (a record dropped under back-pressure, or a log write fails), every\n"+
		"       enforced call and …/list enumeration is denied (AUDIT_UNAVAILABLE)\n"+
		"       rather than forwarded with no durable record.\n"+
		"on     a sink-open failure is fatal at startup, but the runtime gate is off.\n"+
		"off    a sink-open failure warns and the proxy continues with no audit trail.\n"+
		"Set with '=': --require-audit=off (a bare --require-audit means 'strict').")
	f := &proxyCLIFlags{
		configPath:           fs.String("config", "", "Path to the eunox config file (YAML). Declares the host transport,\nupstream(s), per-route policy, listen settings, and audit tape.\nSee schemas/eunox-gateway-config.schema.json."),
		audit:                fs.Bool("audit", false, "Zero-config wiretap mode: bridge stdin/stdout to the upstream named after `--`\n(or to --upstream-url). Enforced-method calls (tools/call, resources/read, resources/subscribe,\nprompts/get, sampling/createMessage) are forwarded and recorded without applying policy.\n…/list calls forward the full upstream catalog unfiltered (no policy is applied) and\nare recorded as enumeration events; only the kill switch still hard-blocks.\nRecorded tool-call arguments may contain secrets; treat the audit log as sensitive.\nMutually exclusive with --config."),
		wiretapURL:           fs.String("upstream-url", "", "HTTP upstream URL for --audit mode (alternative to a `--` subprocess)."),
		wiretapAuthHeader:    fs.String("upstream-auth-header", "", `HTTP upstream auth header for --audit mode, "Name: Value".`),
		wiretapTLSSkipVerify: fs.Bool("upstream-tls-skip-verify", false, "Skip TLS verification for --audit --upstream-url (development only)."),

		// Operational flags layered over the config.
		unsafeBindAll:      fs.Bool("unsafe-bind-all", false, "Allow binding to all interfaces (transport: http only)."),
		trustFwdFor:        fs.Bool("trust-forwarded-for", false, "Trust X-Forwarded-For header for source IP. Only use when a trusted reverse proxy always sets this header; direct clients can spoof it."),
		auditLog:           fs.String("audit-log", "", "Path to the OCSF audit JSONL file (default: ~/.eunox/audit.jsonl). Overridden by the config's audit.log."),
		auditKeyPath:       fs.String("audit-key-path", "", "Path to the HMAC signing key for the audit log (default: ~/.eunox/audit.key).\nOverrides EUNOX_AUDIT_KEY_PATH. Overridden by the config's audit.keyPath."),
		controlTokenPath:   fs.String("control-token-path", "", "Path to write the auto-generated loopback control token for POST /control/kill\n(default: ~/.eunox/control.token, mode 0600). The token authenticates the\nemergency-stop endpoint independently of listen.authToken / JWT mode; the\n'eunox kill' HTTP path reads it from here. HTTP transport only."),
		auditRotateSize:    fs.Int64("audit-rotate-size", 0, "Rotate the audit log when it reaches this size in bytes (default: 100 MiB). Overridden by the config's audit.rotateSizeBytes."),
		auditRetainRotated: fs.Int("audit-retain", 0, "Keep at most this many rotated audit files (audit.jsonl.<timestamp>); the oldest\nbeyond this count are deleted after each rotation so the log directory cannot grow\nwithout bound. 0 = keep all. Overridden by the config's audit.retainRotated."),
		sessionID:          fs.String("session-id", "", "Session ID to use (default: random UUID). (transport: stdio only — a gateway\nmints its own Mcp-Session-Id per client session.)"),
		shutdownTimeout:    fs.Int("shutdown-timeout", 5000, "Milliseconds to wait for graceful upstream shutdown before SIGKILL."),
		upstreamTimeout:    fs.Int("upstream-timeout", transport.UpstreamTimeoutUnset, "Milliseconds to wait for the upstream to respond. An explicit value takes\nprecedence over the config's defaults.upstreamTimeoutMs: 0 disables the timeout,\na positive value sets it. -1 (the default) defers to the config, or to the\nbuilt-in default (30000) when the config does not set one either; any other\nnegative value is rejected rather than silently deferring. For a remote\nHTTP upstream (gateway upstreamUrl), a forwarded host notification (e.g.\nnotifications/cancelled) is independently capped at 30s regardless of this flag,\nso a stalling upstream cannot pin the notification's in-flight slot indefinitely;\nfor a subprocess (command) upstream, notification writes share this flag's bound\nlike any other write to that upstream, so 0 leaves them unbounded too."),
		maxSessions:        fs.Int("max-sessions", defaultMaxSessions, "Cap on concurrent client sessions (transport: http). A new session beyond the cap\nis refused with 503 rather than spawning an unbounded number of upstreams.\nDefaults to a safe backstop (512); pass 0 to disable the cap (unlimited).\nAny listen.maxSessions in the config overrides this flag, including 0, which\ndisables the backstop: a present config value always wins."),
		sessionIdleTimeout: fs.Int("session-idle-timeout", 0, "Close a session whose host has sent no request for this many milliseconds\n(transport: http), so idle sessions cannot pin upstream processes.\n0 = no idle reaping. Overridden by the config's listen.sessionIdleTimeoutMs."),

		// JWT PDP flags (transport: http only).
		jwksURI:             fs.String("jwks-uri", "", "JWKS endpoint URI for IdP-issued capability JWTs (e.g. https://idp.example.com/.well-known/jwks.json).\nWhen set, every request must carry a valid Bearer JWT with eunox capability claims.\nRequires transport: http."),
		jwtIssuer:           fs.String("jwt-issuer", "", "Expected issuer (iss) claim in incoming JWTs. Required with --jwks-uri\nunless --jwt-allow-any-issuer is set, so a token from another issuer that shares\nthe JWKS endpoint cannot be replayed against eunox."),
		jwtAudience:         fs.String("jwt-audience", "", "Expected audience (aud) claim in incoming JWTs. Required with --jwks-uri\nunless --jwt-allow-any-audience is set, so a token minted for another service\ncannot be replayed against eunox."),
		jwtAllowAnyAudience: fs.Bool("jwt-allow-any-audience", false, "Accept IdP JWTs regardless of their aud claim (disables audience pinning).\nNot recommended: a token minted for another relying party of the same IdP can\nthen be replayed against eunox."),
		jwtAllowAnyIssuer:   fs.Bool("jwt-allow-any-issuer", false, "Accept IdP JWTs regardless of their iss claim (disables issuer pinning).\nNot recommended: any issuer whose signing key is served by the same JWKS\nendpoint can then mint tokens accepted by eunox."),
		jwtLeeway:           fs.Duration("jwt-leeway", pdp.DefaultJWTLeeway, "Clock-skew grace applied to JWT exp/nbf/iat validation (e.g. 10s, 30s).\nA token whose exp is up to this far in the past is still accepted, tolerating\nmodest clock skew between the IdP and eunox. 0 disables the grace entirely\n(exp must be strictly in the future). Smaller is safer; the default is conservative."),
		jwksAllowInsecure:   fs.Bool("jwks-allow-insecure-http", false, "Permit a plaintext http:// --jwks-uri to a non-loopback host (development only).\nThe JWKS is the root of trust for every token; over http an on-path attacker\ncan substitute keys and forge capability claims. http:// to a loopback host is\nalways allowed; this flag is only needed for a remote http endpoint."),
		jwtExperimentalCaps: fs.Bool("jwt-experimental-capabilities", false, "Enable enforcement of the EXPERIMENTAL mcp.capabilities claim schema (JWT v0.2).\nOff by default: when unset, a token carrying mcp.capabilities is rejected (HTTP 401)\nrather than having its capability restriction silently dropped. JWT signature, expiry,\nissuer/audience validation, and the identity claims (sub, mcp.task_id, mcp.agent_id)\nare always active regardless of this flag. The claim format may change before 1.0.\nRequires --jwks-uri."),

		// OAuth protected-resource metadata flags (transport: http only; RFC 9728).
		oauthResource:    fs.String("oauth-resource", "", "URI identifying this resource server (RFC 9728 'resource' field).\nWhen set, published in the protected-resource metadata document at\n/.well-known/oauth-protected-resource and in WWW-Authenticate challenges.\nNever derived from the request Host header. Requires transport: http."),
		oauthAuthzServer: fs.String("oauth-authorization-server", "", "Authorization server URI published in the RFC 9728 metadata document.\nDefaults to --jwt-issuer when not set. Requires transport: http."),

		// Redis flags (optional — in-memory is used when absent).
		redisAddr:            fs.String("redis-addr", "", "Redis address (host:port) for persistent call-counter and kill-switch state.\nWhen set, state survives proxy restarts and is shared across instances.\nExample: --redis-addr localhost:6379"),
		redisPassword:        fs.String("redis-password", "", "Redis password (AUTH). Leave empty for unauthenticated connections. Prefer\nthe EUNOX_REDIS_PASSWORD env var: a password on the command line is visible\nin /proc/<pid>/cmdline. A non-empty flag value takes precedence over the env\nvar; leaving the flag empty does NOT override a set EUNOX_REDIS_PASSWORD."),
		redisTLS:             fs.Bool("redis-tls", false, "Enable TLS for the Redis connection."),
		killswitchFailOpen:   fs.Bool("killswitch-fail-open", false, "Redis kill-switch behaviour during a Redis outage. By default the kill switch\nfails CLOSED: while Redis is unreachable the proxy denies every request\n(KILL_SWITCH_ERROR) because a kill issued during the outage cannot be confirmed.\nSet this flag to fail OPEN instead -- serve the last-known kill state and allow\ntraffic not already known to be killed -- trading guaranteed revocation for\ndata-plane availability. Only affects --redis-addr deployments. See ADR-0003."),
		killswitchReconcile:  fs.Duration("killswitch-reconcile-interval", 0, "How often the Redis kill switch reconciles its local cache against Redis\n(default 30s). Lower values shorten the kill-propagation window and, in the\ndefault fail-closed mode, the data-plane denial window that persists after a\ntransient Redis blip recovers -- recovery is bounded by this interval, not Redis.\nVery low values increase Redis load. 0 uses the default. Only affects --redis-addr."),
		killswitchSessionTTL: fs.Duration("killswitch-session-ttl", 0, "How long a SESSION kill tombstone lives in Redis before it is garbage\ncollected (default 720h / 30 days). This is a memory bound, not a policy\nexpiry: when the tombstone expires the kill is LIFTED, so a value shorter\nthan the longest session your deployment holds open re-admits a revoked\nsession. Relevant when a stdio agent pins and reuses one --session-id for\nmonths. Negative disables expiry entirely; 0 uses the default. Agent kills\nare never expired. Only affects --redis-addr."),
		maxCallCounterKeys:   fs.Int("max-call-counter-keys", defaultMaxCallCounterKeys, "Maximum distinct keys the in-memory maxCalls/sequenceBlock counter holds at once.\nEach live (session, tool) pair is one key, reclaimed only on the periodic cleanup;\nthis ceiling bounds the heap a flood of unique session IDs can pin between cleanups\n(a call under a new key past the limit fails closed). The same bound also caps the\nin-memory flow-label store's distinct SESSIONS (one key per session, so its ceiling\nis looser and never trips first). 0 disables the bound. Ignored when --redis-addr is\nset (Redis keeps this state off the Go heap, with TTLs)."),

		// Compliance flags.
		strictDrift: fs.Bool("strict-drift", false, "Promote startup drift warnings to fatal errors that abort session startup: a new\nupstream tool matched by a manifest glob, a manifest entry that matches no live\ntool, or an upstream version that does not satisfy the manifest's serverVersion\npin. (A condition argument absent from the live schema and the uncovered-tool\nINFO stay advisory, never fatal.) A launch-time global override: applies to every\npoliced route, regardless of a per-route 'strictDrift' in the config. Routes with\nno policy are unaffected; the proxy warns if the flag matched no policed route\n(e.g. with --audit)."),
	}
	f.requireAudit = requireAudit
	return f
}

// printProxyUsage writes the `proxy` subcommand help text.
func printProxyUsage(fs *flag.FlagSet) {
	fmt.Fprint(os.Stderr, `Usage:
  eunox proxy --config <eunox.yaml>
  eunox proxy --audit -- <command> [args...]
  eunox proxy --audit --upstream-url <url> [--upstream-auth-header "Name: Value"]

Start the MCP policy-enforcement proxy.

With --config, the file declares the host-facing transport, the upstream(s),
and their per-route policy:

  transport: http  (default) — listen on a socket and front N upstreams, each on
                   its own /mcp/<name> route (the gateway shape).
  transport: stdio — speak MCP over stdin/stdout to exactly one upstream.

With --audit, no config file is needed: eunox runs as a stdio host fronting
the upstream you point it at, in audit (observe) mode — every request is
forwarded, the verdict is recorded, nothing is blocked. Point your MCP host
(Claude Desktop, Cursor, …) at this command and inspect the audit tape with
'eunox stats' to see what an enforcement allowlist would need.

Run 'eunox init --upstream-url <url>' to scaffold a starter config + manifest.

Flags:
`)
	fs.PrintDefaults()
}

// cmdProxy runs the `proxy` subcommand and returns the process exit code (rather than
// calling os.Exit itself), matching every other subcommand so tests can drive its
// branches — including the fail-closed startup rejections — without terminating the
// test binary. args carries the subcommand's own arguments (os.Args[2:] in a real
// invocation), threaded from run.
//
// The return value is NAMED so the deferred audit-sink Close can fail the command: it
// is the last thing to run, and a Close error means buffered records may not have
// reached disk, which for an audit tool is the failure the product exists to prevent.
// Returning normally (rather than calling os.Exit anywhere in here) is what guarantees
// that flush happens at all — an os.Exit skips defers, which is why this function
// previously needed a deferred-exit trick to get the flush and a non-zero status at
// once.
func cmdProxy(args []string) (exitCode int) {
	// ContinueOnError, like every sibling subcommand: an ExitOnError flag set would
	// terminate the process inside Parse, reintroducing exactly the untestable exit
	// this function no longer has.
	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	fs.Usage = func() { printProxyUsage(fs) }

	f := registerProxyFlags(fs)

	// Parse the args run() threaded down, NOT the os.Args global. Under ExitOnError a
	// caller that forgot to set os.Args killed the process loudly; under
	// ContinueOnError the same mistake would quietly parse the surrounding binary's
	// own flags (a test harness's -test.timeout, say) and return a usage error for a
	// branch that was never reached. Taking the slice makes the dispatch contract
	// run() documents actually hold for this subcommand.
	if err := fs.Parse(args); err != nil {
		// Parse has already written the error and the usage text to stderr.
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		// 2 for a usage error, matching what the flag package's ExitOnError mode exited
		// with before and `validate`'s documented convention: it keeps a misspelled flag
		// distinguishable from a startup rejection (1).
		return 2
	}

	if *f.configPath != "" && *f.audit {
		fmt.Fprintf(os.Stderr, "eunox proxy: --audit and --config are mutually exclusive (--audit is for the zero-config wiretap path; --config carries its own enforcement posture).\n")
		return 1
	}

	// Reject negative numeric limit flags at the flag leg, matching the config validator
	// (gateway_config.go). Extracted into a pure helper so each guard is independently
	// unit-testable.
	if err := validateProxyNumericFlags(f); err != nil {
		fmt.Fprintf(os.Stderr, "eunox proxy: %v\n", err)
		return 1
	}
	// The audit knobs mirror the config's fail-closed rejection (Validate rejects a
	// negative audit.rotateSizeBytes / audit.retainRotated). Guard the FLAG leg too so the
	// two surfaces agree: without this a negative flag value silently coerces in audit.Open
	// (rotate-size < 0 → the 100 MiB default, retain < 0 → keep-all), hiding the operator's
	// misconfiguration instead of rejecting it.
	if *f.auditRotateSize < 0 {
		fmt.Fprintf(os.Stderr, "eunox proxy: --audit-rotate-size must be >= 0 (0 = use the default size)\n")
		return 1
	}
	if *f.auditRetainRotated < 0 {
		fmt.Fprintf(os.Stderr, "eunox proxy: --audit-retain must be >= 0 (0 = keep all rotated files)\n")
		return 1
	}

	var (
		cfg *config.GatewayConfig
		err error
	)
	switch {
	case *f.audit:
		cfg, err = buildAuditWiretapConfig(fs.Args(), *f.wiretapURL, *f.wiretapAuthHeader, *f.wiretapTLSSkipVerify)
		if err != nil {
			fmt.Fprintf(os.Stderr, "eunox proxy: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "[eunox] WIRETAP MODE: audit-only, no policy — enforced-method calls are forwarded and recorded (…/list calls forwarded unfiltered and recorded as enumeration events). Use 'eunox stats' to inspect the tape.\n")
	case *f.configPath != "":
		// The upstream command comes from the config in this mode; a trailing
		// "-- <command>" would be silently dropped, so reject stray positionals rather
		// than let the operator believe they took effect.
		if fs.NArg() > 0 {
			fmt.Fprintf(os.Stderr, "eunox proxy: unexpected argument %q (--config takes the upstream from the config file; positional commands are only for --audit mode)\n", fs.Arg(0))
			return 1
		}
		// The wiretap-only upstream flags describe the --audit upstream; under --config the
		// upstream (and its auth/TLS posture) comes from the file, so these would be
		// silently dropped. Reject them for the same reason as a stray positional.
		if *f.wiretapURL != "" || *f.wiretapAuthHeader != "" || *f.wiretapTLSSkipVerify {
			fmt.Fprintf(os.Stderr, "eunox proxy: --upstream-url/--upstream-auth-header/--upstream-tls-skip-verify apply only to --audit wiretap mode; under --config the upstream and its auth/TLS posture come from the config file\n")
			return 1
		}
		cfg, err = config.LoadGatewayConfig(*f.configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "eunox proxy: %v\n", err)
			return 1
		}
	default:
		fmt.Fprintf(os.Stderr, "eunox proxy: one of --config <file> or --audit is required.\n\n  --config <eunox.yaml>           policy enforcement (or audit posture) declared in a file\n  --audit -- <command> [args...]  zero-config wiretap: forward everything, log everything\n\nRun 'eunox init --upstream-url <url>' to scaffold a starter config + manifest.\n")
		return 1
	}

	sid := *f.sessionID
	if sid == "" {
		sid = uuid.New().String()
	}

	// Detect every jwks-gated flag the operator activated, generically over the single
	// jwksGatedFlags list (value detection for zero-default flags, explicit-set for the
	// non-zero-default ones like --jwt-leeway), so the fail-closed guard below reads one
	// precomputed list rather than re-enumerating each flag.
	gatedJWTFlagsSet := gatedFlagsSetWithoutJWKS(fs)

	pf := proxyFlags{
		jwksURI:              *f.jwksURI,
		jwtIssuer:            *f.jwtIssuer,
		jwtAudience:          *f.jwtAudience,
		jwtAllowAnyAudience:  *f.jwtAllowAnyAudience,
		jwtAllowAnyIssuer:    *f.jwtAllowAnyIssuer,
		jwtLeeway:            *f.jwtLeeway,
		gatedJWTFlagsSet:     gatedJWTFlagsSet,
		jwksAllowInsecure:    *f.jwksAllowInsecure,
		jwtExperimentalCaps:  *f.jwtExperimentalCaps,
		oauthResource:        *f.oauthResource,
		oauthAuthzServer:     *f.oauthAuthzServer,
		unsafeBindAll:        *f.unsafeBindAll,
		trustFwdFor:          *f.trustFwdFor,
		shutdownMs:           *f.shutdownTimeout,
		upstreamTimeoutMs:    *f.upstreamTimeout,
		sessionID:            sid,
		sessionIDSet:         *f.sessionID != "",
		configPath:           *f.configPath,
		strictDrift:          *f.strictDrift,
		requireAuditStrict:   f.requireAudit.strict(),
		maxSessions:          *f.maxSessions,
		sessionIdleTimeoutMs: *f.sessionIdleTimeout,
		redisConfigured:      *f.redisAddr != "",
		controlTokenPath:     *f.controlTokenPath,
		httpOnlyFlagsSet:     httpOnlyFlagsSetOnStdio(fs),
	}

	// Fail closed if any JWT flag (including --jwt-experimental-capabilities) was supplied
	// without --jwks-uri, so a forgotten --jwks-uri cannot leave the gateway serving
	// unauthenticated while the operator believes JWT auth is on. One guard covers every
	// jwks-gated flag so the set cannot drift. Transport-agnostic (also catches the stdio
	// case, where --jwks-uri is itself rejected).
	//
	// Deliberately checked here, before buildCallCounterAndKillSwitch/
	// openConfiguredAuditSink below: those have real side effects (a Redis
	// connection attempt, minting a fresh audit key/log file on disk), so a flag
	// error the operator can trivially fix should be reported before anything is
	// touched, not after.
	if err := validateJWTFlagsRequireJWKS(pf); err != nil {
		fmt.Fprintf(os.Stderr, "[eunox] Fatal: %v\n", err)
		return 1
	}

	// Fail closed if a Redis-only flag (--killswitch-fail-open, --redis-password, …) was
	// set without --redis-addr: those configure the Redis-backed counter/kill switch that
	// is never built without the backend, so the operator's intent would silently
	// evaporate. Checked here, before buildCallCounterAndKillSwitch, for the same reason
	// as the JWT guard above — report a trivially-fixable flag error before anything with
	// side effects (a Redis dial, minting an audit key) runs.
	if err := validateRedisFlagsRequireRedisAddr(fs, *f.redisAddr); err != nil {
		fmt.Fprintf(os.Stderr, "[eunox] Fatal: %v\n", err)
		return 1
	}

	// Build call counter and kill-switch manager, shared across routes and the
	// kill-switch endpoint. Backed by Redis when --redis-addr is set.
	counter, flowStore, ks, ksRedis, err := buildCallCounterAndKillSwitch(*f.redisAddr, resolveRedisPassword(*f.redisPassword), *f.redisTLS, *f.killswitchFailOpen, *f.killswitchReconcile, *f.killswitchSessionTTL, *f.maxCallCounterKeys)
	if err != nil {
		fmt.Fprintf(os.Stderr, "eunox proxy: %v\n", err)
		return 1
	}

	// Open the shared audit sink. The config's audit block takes precedence over
	// the CLI flags so every route shares one tape.
	sink, err := openConfiguredAuditSink(*f.auditLog, *f.auditKeyPath, *f.auditRotateSize, *f.auditRetainRotated, flagWasSet(fs, "audit-retain"), cfg, f.requireAudit.required())
	if err != nil {
		fmt.Fprintf(os.Stderr, "[eunox] Fatal: %v\n", err)
		return 1
	}
	if sink != nil {
		defer func() {
			// A Close failure means buffered records may not have reached disk. For
			// an audit tool that silent loss is the failure mode the product exists
			// to prevent, so surface it as a non-zero exit. This runs on every return
			// path below (that is why the return is named), and last among the defers
			// registered here, so it flushes after the kill switch has stopped.
			if err := sink.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "[eunox] Fatal: audit sink close failed; the audit trail may be incomplete: %v\n", err)
				// Only ever UPGRADE from success. A flush failure must not overwrite a
				// more specific non-zero code the function already chose (this file
				// already uses 2 for a usage error), which an unconditional assignment
				// would silently rewrite to 1.
				if exitCode == 0 {
					exitCode = 1
				}
			}
		}()
	}

	ctx, cancel := context.WithCancel(context.Background())
	// Both teardowns are deferred, not left to the signal goroutine below: that
	// goroutine only runs when a signal actually arrives, so on every ordinary return
	// (a serve error, or a clean shutdown) the context would otherwise stay live and
	// the SIGINT/SIGTERM relay stay registered. In the binary that is invisible because
	// the process exits — but cmdProxy now RETURNS rather than calling os.Exit, so an
	// in-process caller would leak the ctx-bound cleanup goroutine (StartCleanup below)
	// and, worse, keep the OS default signal disposition disabled for the whole process
	// once Notify has diverted it. signal.Stop is idempotent, so the goroutine's own
	// call remains correct.
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		<-sigCh
		cancel()
		// Stop relaying SIGINT/SIGTERM into sigCh once the first one has triggered
		// graceful shutdown: this goroutine only ever reads once, so without this a
		// second signal (an operator's repeated Ctrl+C when a graceful shutdown
		// hangs) is captured into the channel's one buffer slot and then silently
		// swallowed forever — nothing reads it, and the OS's default terminate-on-
		// signal behavior never gets a chance to run either, since Notify diverted
		// it. Stop un-registers the relay, so a second signal reverts to the
		// default behavior (immediate termination) — the operator's forced-kill
		// escape hatch when graceful shutdown wedges.
		signal.Stop(sigCh)
	}()

	if ksRedis != nil {
		// Publish the effective session-kill TTL here, not from
		// buildCallCounterAndKillSwitch: everything that can still fail this process's
		// startup and exit it (JWT/Redis flag validation, the Redis ping, opening the
		// audit sink) has already run and succeeded by this point. Publishing any
		// earlier risks the same bug already fixed once for the control-token file — a
		// second, differently-configured instance overwrites a running proxy's
		// published value and then dies before serving a single request, leaving
		// `eunox kill` and this proxy's own diagnostics trusting a lifetime nothing is
		// actually enforcing.
		publishSessionKillTTL(ksRedis)
		ksRedis.Start(ctx)
		// Join the Redis kill-switch's pub/sub listener and reconcile loop on
		// shutdown; otherwise they outlive cmdProxy and may touch the shared Redis
		// client after teardown. Stop() blocks on wg.Wait. Registered after Start
		// so (LIFO) it runs before earlier defers, while sink.Close stays last.
		defer ksRedis.Stop()
	}
	if mem, ok := counter.(*callcounter.InMemory); ok {
		mem.StartCleanup(ctx, callcounter.DefaultCleanupInterval)
	}

	var serveErr error
	switch cfg.HostTransport() {
	case config.HostTransportStdio:
		serveErr = serveStdioHost(ctx, cfg, sink, counter, flowStore, ks, pf)
	default: // config.HostTransportHTTP
		serveErr = serveHTTPGateway(ctx, cfg, sink, counter, flowStore, ks, pf)
	}
	if serveErr != nil {
		fmt.Fprintf(os.Stderr, "[eunox] Fatal: %v\n", serveErr)
		return 1
	}
	return 0
}

// resolveRedisPassword returns the Redis AUTH password with flag > env precedence:
// the explicit --redis-password flag if set, otherwise EUNOX_REDIS_PASSWORD. A
// password passed via argv is world-readable in /proc/<pid>/cmdline for the
// process's lifetime, so the env fallback (mirroring EUNOX_CONTROL_TOKEN and the
// config ${VAR} expansion) lets an operator keep it off the command line. The flag
// wins so an explicit value is never silently overridden by a stray env var.
func resolveRedisPassword(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	return os.Getenv("EUNOX_REDIS_PASSWORD")
}

// buildCallCounterAndKillSwitch builds the shared call counter, flow-label store, and
// kill-switch manager, Redis-backed when redisAddr is set (state survives restarts,
// shared across instances) and in-memory otherwise. The flow-label store is a seam
// distinct from the counter (session-lifetime provenance, not a sliding window) but is
// wired from the same backend so a flow policy gets multi-instance parity exactly as
// maxCalls/sequenceBlock do. ksRedis is non-nil only in
// the Redis case, so cmdProxy can start its reconcile loop.
//
// A Redis config or connectivity error is returned rather than exited on, so the
// caller owns the exit code and the failure path is drivable from a test.
func buildCallCounterAndKillSwitch(redisAddr, redisPassword string, redisTLS, killswitchFailOpen bool, killswitchReconcile, killswitchSessionTTL time.Duration, maxCallCounterKeys int) (capability.CallCounter, capability.FlowLabelStore, killswitch.Manager, *killswitch.Redis, error) {
	var (
		counter capability.CallCounter = callcounter.NewInMemory(callcounter.WithMaxKeys(maxCallCounterKeys))
		// The in-memory flow store has no time window (a taint lives until the session's
		// Clear on teardown), so it needs no cleanup goroutine; WithMaxKeys is its
		// fail-closed growth backstop for a session whose Clear never arrives, sized to
		// the same bound as the counter.
		flowStore capability.FlowLabelStore = flowlabelstore.NewInMemory(flowlabelstore.WithMaxKeys(maxCallCounterKeys))
		ks        killswitch.Manager        = killswitch.NewInMemory()
		ksRedis   *killswitch.Redis         // non-nil when --redis-addr is set
	)
	if redisAddr != "" {
		rdb, err := buildRedisClient(redisAddr, redisPassword, redisTLS)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("Redis configuration error: %w", err) //nolint:staticcheck // ST1005: "Redis" is a proper noun, not a capitalized sentence
		}
		if err := pingRedis(context.Background(), rdb); err != nil {
			// Close the client before abandoning it: buildRedisClient hands back a live
			// connection pool with its own goroutines. This branch used to call os.Exit,
			// which made the leak unobservable; now that it returns, an in-process caller
			// (the tests this function was made returnable for) would accumulate one pool
			// and its dialer per failed attempt. Mirrors the kill subcommand's client.
			_ = rdb.Close()
			return nil, nil, nil, nil, err
		}
		fmt.Fprintf(os.Stderr, "[eunox] Redis backend enabled (%s). State persists across restarts.\n", redisAddr)
		counter = callcounter.NewRedis(rdb)
		// Share the same client: a Redis flow store gives a flow policy the same
		// multi-instance parity as the counter (a source on one instance, a sink on
		// another), and reclaims an orphaned session's set by idle TTL if Clear never lands.
		flowStore = flowlabelstore.NewRedis(rdb)
		// WithReconcileInterval(0) keeps the default; a positive value tunes kill
		// propagation and (fail-closed) the post-recovery denial window.
		//
		// WithLogger wires a real logger so the kill switch's degraded-mode breadcrumbs
		// (initial-refresh-failed, pub/sub-subscription-unconfirmed, background-refresh
		// failed/recovered) actually emit: every one is gated on a non-nil logger, so
		// without this an operator watching for a Redis partition sees nothing in the log
		// (HealthStatus on /healthz still reflects the state). Structured stderr matches
		// where the other [eunox] startup lines already go.
		ksRedis = killswitch.NewRedis(rdb,
			killswitch.WithFailOpen(killswitchFailOpen),
			killswitch.WithReconcileInterval(killswitchReconcile),
			// WithSessionKillTTL(0) keeps the 30-day default. It is wired to a flag rather
			// than left hardwired because the expiry LIFTS the kill: a deployment that pins
			// and reuses one --session-id (the normal way to run a long-lived stdio agent)
			// can outlive the default, and the revoked session is then re-admitted with no
			// operator action. Both directions need to be reachable -- raise it past the
			// longest session, or make it permanent -- so it cannot be a constant.
			killswitch.WithSessionKillTTL(killswitchSessionTTL),
			killswitch.WithLogger(slog.New(slog.NewTextHandler(os.Stderr, nil))))
		ks = ksRedis
		if killswitchFailOpen {
			fmt.Fprintf(os.Stderr, "[eunox] Kill switch: fail-OPEN during a Redis outage (--killswitch-fail-open). Kills issued while Redis is unreachable may be delayed until it recovers; the data plane stays available.\n")
		} else {
			fmt.Fprintf(os.Stderr, "[eunox] Kill switch: fail-CLOSED during a Redis outage (default). While Redis is unreachable every request is denied (KILL_SWITCH_ERROR) until health is reconfirmed; pass --killswitch-fail-open to prioritise availability. Watch HealthStatus on /healthz and /metrics.\n")
		}
		if killswitchReconcile > 0 {
			fmt.Fprintf(os.Stderr, "[eunox] Kill switch: reconcile interval %s (--killswitch-reconcile-interval); bounds kill-propagation and fail-closed post-recovery denial windows.\n", killswitchReconcile)
		}
		// State the session-tombstone lifetime unconditionally, including the default. It
		// is the one kill-switch setting whose expiry LIFTS a revocation, so an operator
		// running a pinned, reused --session-id needs to see the number without having to
		// know the flag exists to ask for it.
		fmt.Fprintf(os.Stderr, "[eunox] Kill switch: %s (--killswitch-session-ttl). Agent kills never expire.\n", sessionKillTTLNotice(killswitchSessionTTL))
		// The TTL is published later, from cmdProxy, once startup is past every step
		// that can still fail and exit the process — see that call site.
	}
	return counter, flowStore, ks, ksRedis, nil
}

// publishSessionKillTTL advertises the effective session-tombstone lifetime on the
// shared Redis so `eunox kill --redis-addr` writes tombstones with the SAME lifetime.
// That command is the only out-of-band revocation channel a stdio proxy has, so it
// writes tombstones itself; as two independent flags the pair could disagree with no
// diagnostic, and the disagreement fails one way — the CLI's shorter default expires a
// kill the operator configured to outlast it, silently re-admitting the session.
//
// Advisory, so a failure warns rather than aborts startup: this proxy enforces its own
// configured value regardless, and the CLI falls back to its flag exactly as it did
// before the key existed. A prior value that differs is reported too — the key is
// last-writer-wins, so two differently configured proxies on one Redis leave `eunox
// kill` adopting whichever started last.
func publishSessionKillTTL(ksRedis *killswitch.Redis) {
	// Bounded and detached: this runs during startup wiring, before the proxy's own
	// run context exists, and must not hang the boot on a Redis that answered PING and
	// then stalled.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	prior, differs, err := ksRedis.PublishSessionKillTTL(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[eunox] WARNING: could not publish the session-kill TTL to Redis (%v); `eunox kill --redis-addr` will fall back to its own --killswitch-session-ttl, which must then match this proxy's.\n", err)
		return
	}
	if differs {
		fmt.Fprintf(os.Stderr, "[eunox] WARNING: this Redis already advertised a session-kill TTL of %s, now replaced by %s. If another proxy instance is running with the old value, the two disagree and `eunox kill` applies whichever was published last; align --killswitch-session-ttl across instances.\n",
			killswitch.DescribeSessionKillTTL(prior), killswitch.DescribeSessionKillTTL(ksRedis.SessionKillTTL()))
	}
}

// sessionKillTTLNotice renders the startup line describing how long a session-kill
// tombstone survives, resolving the flag's two sentinel values through the same
// killswitch.NormalizeSessionKillTTL the option applies (0 = the 30-day default,
// negative = never expire) so the banner cannot claim one lifetime while Redis
// enforces another.
func sessionKillTTLNotice(ttl time.Duration) string {
	effective := killswitch.NormalizeSessionKillTTL(ttl)
	if effective == 0 {
		return "session kills never expire; tombstones accumulate in Redis until `eunox kill --revive <session-id> --redis-addr <addr>` removes them"
	}
	// Only an unset flag is "(default)": an explicit value that happens to equal the
	// default was still chosen by the operator.
	suffix := ""
	if ttl == 0 {
		suffix = " (default)"
	}
	return fmt.Sprintf("session kills expire after %s%s; a session held open longer than that is re-admitted", effective, suffix)
}

// warnAuditFlagOverridden prints the shared "config wins over an explicit --audit-* flag"
// warning for `proxy`, where the audit block always takes precedence so every route
// shares one tape. flagRepr/cfgRepr are the already-formatted (%q for strings, %d for
// ints) values, since the four callers' fields differ in type.
func warnAuditFlagOverridden(flagName, flagRepr, cfgField, cfgRepr string) {
	fmt.Fprintf(os.Stderr, "[eunox] WARNING: %s %s is overridden by the config's %s %s; the config's audit block always takes precedence for `proxy` so every route shares one tape.\n", flagName, flagRepr, cfgField, cfgRepr)
}

// openConfiguredAuditSink resolves the audit-sink settings (config's audit block
// takes precedence over the CLI flags so every route shares one tape) and opens
// the sink. Under --require-audit an open failure is returned as an error for the
// caller to exit on (fail closed); otherwise it warns and returns a nil sink with a
// nil error, so the proxy continues unaudited.
func openConfiguredAuditSink(auditLog, auditKeyPath string, auditRotateSize int64, auditRetainRotated int, auditRetainSet bool, cfg *config.GatewayConfig, requireAudit bool) (*audit.Sink, error) {
	auditLogPath, auditKey, auditRotate := auditLog, auditKeyPath, auditRotateSize
	auditRetain := auditRetainRotated
	// The config's audit block takes precedence over an explicit --audit-log/
	// --audit-key-path flag here (unlike the reader subcommands — suggest, stats,
	// audit-verify — where applyConfigAuditDefaults leaves an explicitly-set flag
	// untouched and the config only fills an EMPTY one). That inversion is
	// intentional for `proxy` (every route must share one tape, so the config is
	// authoritative), but a silently-overridden explicit flag is easy to miss —
	// warn so an operator who passed --audit-log expecting it to be honored sees
	// why it wasn't.
	if cfg.Audit.Log != "" {
		if auditLog != "" && auditLog != cfg.Audit.Log {
			warnAuditFlagOverridden("--audit-log", fmt.Sprintf("%q", auditLog), "audit.log", fmt.Sprintf("%q", cfg.Audit.Log))
		}
		auditLogPath = cfg.Audit.Log
	}
	if cfg.Audit.KeyPath != "" {
		if auditKeyPath != "" && auditKeyPath != cfg.Audit.KeyPath {
			warnAuditFlagOverridden("--audit-key-path", fmt.Sprintf("%q", auditKeyPath), "audit.keyPath", fmt.Sprintf("%q", cfg.Audit.KeyPath))
		}
		auditKey = cfg.Audit.KeyPath
	}
	// Warn on a silently-overridden explicit flag here too. These two are overridden by
	// the same config-wins rule as --audit-log/--audit-key-path above, and an operator who
	// passed a rotation size or retention count and got the config's instead has exactly
	// the same "why wasn't my flag honored" question — it was only the two string flags
	// that said so.
	if cfg.Audit.RotateSizeBytes > 0 {
		// 0 is this flag's "use the built-in default" spelling, so a non-zero value is an
		// explicit one (same test the string flags use against "").
		if auditRotateSize > 0 && auditRotateSize != cfg.Audit.RotateSizeBytes {
			warnAuditFlagOverridden("--audit-rotate-size", fmt.Sprintf("%d", auditRotateSize), "audit.rotateSizeBytes", fmt.Sprintf("%d", cfg.Audit.RotateSizeBytes))
		}
		auditRotate = cfg.Audit.RotateSizeBytes
	}
	// A present config value wins, including an explicit 0 ("keep all rotated files"),
	// so config can disable a non-zero --audit-retain flag; an absent key (nil) leaves
	// the flag's value in force. config.ResolveInt holds exactly this precedence rule
	// (shared with maxSessions/sessionIdleTimeout), so the audit-retention path cannot
	// drift from the other resolved options.
	//
	// Explicitness comes from auditRetainSet (flagWasSet), not from a non-zero value: 0 is
	// a MEANINGFUL setting here ("keep all"), so an operator can be overridden while
	// passing the flag's zero value.
	if cfg.Audit.RetainRotated != nil && auditRetainSet && *cfg.Audit.RetainRotated != auditRetain {
		warnAuditFlagOverridden("--audit-retain", fmt.Sprintf("%d", auditRetain), "audit.retainRotated", fmt.Sprintf("%d", *cfg.Audit.RetainRotated))
	}
	auditRetain = config.ResolveInt(cfg.Audit.RetainRotated, auditRetain)
	sink, err := audit.Open(auditLogPath, auditKey, auditRotate, auditRetain, audit.WithIdentity(pdp.AuditIdentityFromContext))
	if err != nil {
		if requireAudit {
			return nil, fmt.Errorf("audit sink could not be opened and --require-audit is not 'off' (it defaults to 'strict'); set a writable audit path or pass --require-audit=off to run unaudited: %w", err)
		}
		fmt.Fprintf(os.Stderr, "[eunox] Warning: could not open audit log: %v\n", err)
		return nil, nil
	}
	return sink, nil
}

// buildAuditWiretapConfig synthesizes a zero-config `transport: stdio` gateway
// in audit (observe) mode from the operator's --audit arguments. Exactly one
// upstream is configured: a subprocess (positional args after `--`) or a remote
// HTTP server (--upstream-url). No manifest is referenced — every call is
// forwarded and logged, nothing is blocked. Used by `proxy --audit`.
func buildAuditWiretapConfig(positional []string, upstreamURL, authHeader string, tlsSkipVerify bool) (*config.GatewayConfig, error) {
	if len(positional) > 0 && upstreamURL != "" {
		return nil, fmt.Errorf("--audit: pick exactly one upstream — positional `-- <command>` OR --upstream-url, not both")
	}
	// Reject a whitespace-only credential HERE, as an operator flag error. The value is
	// copied verbatim into the synthesized config below, where Validate's own
	// whitespace-only guard would also reject it — but that failure is reported as
	// "internal: synthesized wiretap config rejected", the marker reserved for "the
	// binary built something invalid, file a bug". A shell-quoting slip in
	// --upstream-auth-header is the operator's to fix, not a eunox defect, so it must
	// not be dressed up as one.
	if authHeader != "" && strings.TrimSpace(authHeader) == "" {
		return nil, fmt.Errorf("--upstream-auth-header is whitespace-only, which is not a usable credential — pass a real header value, or omit the flag to forward no auth header")
	}
	cfg := &config.GatewayConfig{
		SchemaVersion: "0.1",
		Transport:     config.HostTransportStdio,
	}
	cfg.Defaults.Enforcement = capability.EnforcementAudit
	u := config.UpstreamConfig{Name: "wiretap"}
	switch {
	case len(positional) > 0:
		// --upstream-auth-header/--upstream-tls-skip-verify configure a REMOTE HTTP
		// upstream; a positional subprocess upstream has neither, so they would be
		// silently dropped. Reject rather than let the operator believe an auth header or
		// a TLS posture took effect (matches buildInitUpstreamSpec's stdio rejection).
		if authHeader != "" || tlsSkipVerify {
			return nil, fmt.Errorf("--audit: --upstream-auth-header/--upstream-tls-skip-verify apply only to a remote --upstream-url upstream, not a positional `-- <command>` subprocess")
		}
		u.Transport = config.HostTransportStdio
		u.Command = positional[0]
		u.Args = positional[1:]
	case upstreamURL != "":
		u.Transport = config.HostTransportHTTP
		u.UpstreamURL = upstreamURL
		u.UpstreamAuthHeader = authHeader
		u.UpstreamTLSSkipVerify = tlsSkipVerify
	default:
		return nil, fmt.Errorf("--audit requires an upstream: pass `-- <command> [args...]` to wrap a subprocess, or --upstream-url <url> to wrap a remote MCP HTTP server")
	}
	cfg.Upstreams = []config.UpstreamConfig{u}
	// nil presentKeys: built field-by-field above, so Validate's non-zero-value
	// fallback suffices.
	if err := cfg.Validate(nil); err != nil {
		return nil, fmt.Errorf("internal: synthesized wiretap config rejected: %w", err)
	}
	return cfg, nil
}

// flagWasSet reports whether the named flag was passed explicitly on the command line
// (flag.Visit visits only the flags that were set), for flags whose default value cannot
// distinguish "explicitly set to the default" from "unset" — e.g. --jwt-leeway (non-zero
// default) and --transport.
func flagWasSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

// jwksGatedFlags is the single authoritative list of flag names that require --jwks-uri:
// each configures bearer-token validation (or the experimental capability intersection),
// which runs ONLY when --jwks-uri stands up the JWT authenticator. validateJWTFlagsRequireJWKS
// is the one guard that reads it; keeping the names here (and every jwks-gated flag listed)
// stops a second, parallel guard from drifting out of sync.
var jwksGatedFlags = []string{
	"jwt-issuer",
	"jwt-audience",
	"jwt-allow-any-audience",
	"jwt-allow-any-issuer",
	"jwks-allow-insecure-http",
	"jwt-experimental-capabilities",
	"jwt-leeway",
}

// flagDefaultIsZero reports whether a flag's default is its type's zero value, by
// comparing DefValue to the stdlib zero renderings for the flag types every gated flag
// uses: string (""), int ("0"), bool ("false"), and time.Duration ("0s"). Every flag in
// jwksGatedFlags is one of these, so the set is exhaustive for the project's flags and
// trivially reviewable; a future gated flag whose type renders its zero differently (an
// enum "none", a slice "[]", …) must add that rendering here.
//
// A zero-default flag can be detected by VALUE (a non-zero value can only come from
// the operator, and an explicit --flag=<zero> carries no JWT intent so it is spared);
// a non-zero-default flag cannot, so it must be detected by explicit-set.
func flagDefaultIsZero(f *flag.Flag) bool {
	switch f.DefValue {
	case "", "0", "false", "0s":
		return true
	default:
		return false
	}
}

// gatedFlagsSetWithoutJWKS returns the "--"-prefixed names of every jwks-gated flag
// that the operator activated, driving BOTH detection halves off the single
// jwksGatedFlags list so the two inventories cannot drift: a new gated flag added to
// jwksGatedFlags is guarded automatically, with no second per-flag block to forget.
// Detection is chosen per flag by how the operator's intent is observable:
//
//   - zero-default flag (string/bool/…): active when its current value differs from its
//     zero default (value detection). This spares an explicit --flag=false/"" that
//     carries no JWT intent, unlike a pure explicit-set model.
//   - non-zero-default flag (e.g. --jwt-leeway): value detection is blind (its default
//     already differs from zero, so --flag=<default> looks like unset), so it is active
//     when passed explicitly — including --flag=<default> — the fail-safe direction.
//
// A pure function of the parsed FlagSet for testability.
func gatedFlagsSetWithoutJWKS(fs *flag.FlagSet) []string {
	return explicitlyActiveFlags(fs, jwksGatedFlags)
}

// explicitlyActiveFlags returns the "--"-prefixed names of every flag in names
// that the operator activated: a zero-default flag (see flagDefaultIsZero) is
// detected by VALUE (a non-zero value can only come from the operator), while a
// non-zero-default flag (e.g. --max-sessions, whose default is
// defaultMaxSessions, not 0) is detected by explicit-set (fs.Visit), since value
// alone cannot distinguish an operator-chosen default from an unset flag. Shared
// by gatedFlagsSetWithoutJWKS (jwksGatedFlags) and httpOnlyFlagsSetOnStdio
// (httpOnlyProxyFlags) so the two detection halves cannot drift apart.
func explicitlyActiveFlags(fs *flag.FlagSet, names []string) []string {
	var out []string
	for _, name := range names {
		f := fs.Lookup(name)
		if f == nil {
			continue
		}
		active := false
		if flagDefaultIsZero(f) {
			active = f.Value.String() != f.DefValue // value detection: non-zero value
		} else {
			active = flagWasSet(fs, name) // explicit-set detection
		}
		if active {
			out = append(out, "--"+name)
		}
	}
	return out
}

// httpOnlyProxyFlags is the single authoritative list of flag names that apply
// only to transport: http (the gateway shape): each configures HTTP-listener
// behavior a stdio host has no socket to apply. serveStdioHost's rejection guard
// reads this list (alongside the --jwks-uri/--oauth-* flags it already rejects
// directly, which stand up JWT/OAuth-metadata serving rather than merely
// configuring an already-standing listener), so a future HTTP-only flag added
// here is covered automatically instead of silently no-oping on a stdio host —
// the fate these five (control-token-path, session-idle-timeout, max-sessions,
// unsafe-bind-all, trust-forwarded-for) suffered before this list existed.
var httpOnlyProxyFlags = []string{
	"control-token-path",
	"session-idle-timeout",
	"max-sessions",
	"unsafe-bind-all",
	"trust-forwarded-for",
}

// httpOnlyFlagsSetOnStdio returns the "--"-prefixed names of every
// httpOnlyProxyFlags flag the operator activated, for serveStdioHost's rejection
// guard.
func httpOnlyFlagsSetOnStdio(fs *flag.FlagSet) []string {
	return explicitlyActiveFlags(fs, httpOnlyProxyFlags)
}

// redisGatedFlags is the single authoritative list of proxy flags that take effect
// ONLY when --redis-addr configures a Redis backend: each is read inside the
// `redisAddr != ""` branch of buildCallCounterAndKillSwitch, so without --redis-addr
// the proxy runs on the in-memory call counter / kill switch and every one is silently
// dropped. An operator who sets --killswitch-fail-open expecting a fail-open outage
// posture, or --redis-password expecting an authenticated connection, gets neither and
// no diagnostic. (--max-call-counter-keys is deliberately NOT here: it is the inverse —
// active in-memory and ignored WHEN --redis-addr is set — so it is meaningful without
// Redis.) cmdKill already rejects the redis-password/redis-tls mix without --redis-addr;
// this is the proxy-path equivalent.
var redisGatedFlags = []string{
	"redis-password",
	"redis-tls",
	"killswitch-fail-open",
	"killswitch-reconcile-interval",
	"killswitch-session-ttl",
}

// validateProxyNumericFlags rejects negative values for the proxy's numeric limit flags,
// matching the config validator (gateway_config.go): each of these treats <= 0 as
// "unlimited / disabled / use-the-default", so a NEGATIVE value silently does the
// opposite of the operator's intent —
//
//   - --max-sessions / --session-idle-timeout / --max-call-counter-keys: a negative
//     silently disables the documented cap (a fail-open the config leg refuses).
//   - --shutdown-timeout: the transports clamp a non-positive value to the 5000ms
//     default, so a negative silently becomes the opposite of a "shorter grace" intent.
//   - --upstream-timeout: this one has a legitimate NEGATIVE sentinel
//     (transport.UpstreamTimeoutUnset, -1) meaning "defer to the config", so only values
//     BELOW it are rejected. ResolveUpstreamTimeout defers on any negative, so a sign typo
//     for a 5s bound (--upstream-timeout -5000) silently became the 30s default — the
//     same silent-opposite-of-intent the other three guards exist to catch.
//
// Returns the first offending flag's error (without the "eunox proxy: " prefix the caller
// adds), or nil. A pure function so every guard is unit-testable independently of
// cmdProxy, which reports it and returns exit code 1. 0 stays a valid
// "unlimited / disabled / default" spelling for every flag.
func validateProxyNumericFlags(f *proxyCLIFlags) error {
	switch {
	case *f.maxSessions < 0:
		return errors.New("--max-sessions must be >= 0 (0 = unlimited)")
	case *f.sessionIdleTimeout < 0:
		return errors.New("--session-idle-timeout must be >= 0 (0 = no idle reaping)")
	case *f.maxCallCounterKeys < 0:
		return errors.New("--max-call-counter-keys must be >= 0 (0 = unbounded)")
	case *f.shutdownTimeout < 0:
		return errors.New("--shutdown-timeout must be >= 0 (0 = use the default)")
	case *f.upstreamTimeout < transport.UpstreamTimeoutUnset:
		return fmt.Errorf("--upstream-timeout must be >= %d (0 disables the timeout, %d defers to the config); a value below that is not a sentinel and would silently defer instead of setting the bound you meant", transport.UpstreamTimeoutUnset, transport.UpstreamTimeoutUnset)
	}
	return nil
}

// validateRedisFlagsRequireRedisAddr fails closed when any Redis-gated proxy flag is set
// without --redis-addr. Without the backend those flags are silently ignored (the proxy
// falls back to in-memory state), so an operator's fail-open/auth/TLS/reconcile intent
// evaporates unobserved — the exact silent-drop the fail-loud posture elsewhere (the
// --audit/--config and JWT-without-JWKS guards) refuses. Reject the mismatch at startup.
// A no-op when --redis-addr is set or no such flag was given. Detection is driven off the
// single redisGatedFlags list via explicitlyActiveFlags (value detection for these
// zero-default flags), so a new Redis-only flag added to the list is guarded automatically.
func validateRedisFlagsRequireRedisAddr(fs *flag.FlagSet, redisAddr string) error {
	if redisAddr != "" {
		return nil
	}
	if active := explicitlyActiveFlags(fs, redisGatedFlags); len(active) > 0 {
		return fmt.Errorf("flag(s) %s require --redis-addr: they configure the Redis-backed call counter / kill switch, which is only built when --redis-addr is set — without it the proxy uses in-memory state and these are silently ignored. Set --redis-addr to enable the Redis backend, or remove these flags", strings.Join(active, ", "))
	}
	return nil
}

// jwtLeewayOption bridges the --jwt-leeway flag to pdp.JWTPDPOptions.Leeway. The
// flag's 0 means "disable the grace"; pdp.JWTPDPOptions reads 0 as "use the
// default" and a negative as disabled. Map flag 0-or-below to a negative so the
// operator's disable intent survives; pass any positive duration through.
func jwtLeewayOption(d time.Duration) time.Duration {
	if d <= 0 {
		return -1
	}
	return d
}

// proxyFlags bundles the operational CLI flags shared by both host transports.
type proxyFlags struct {
	jwksURI, jwtIssuer, jwtAudience string
	jwtAllowAnyAudience             bool
	jwtAllowAnyIssuer               bool
	jwtLeeway                       time.Duration
	// gatedJWTFlagsSet holds the "--"-prefixed names of every jwks-gated flag the operator
	// activated, precomputed generically from the FlagSet by gatedFlagsSetWithoutJWKS
	// (both value- and explicit-set detection). The require-jwks guard reads this list
	// directly rather than re-enumerating each flag, so both halves of the guard are
	// driven off the single jwksGatedFlags inventory and cannot drift.
	gatedJWTFlagsSet                []string
	jwksAllowInsecure               bool
	jwtExperimentalCaps             bool // --jwt-experimental-capabilities: enable the EXPERIMENTAL mcp.capabilities (JWT v0.2) intersection
	oauthResource, oauthAuthzServer string
	unsafeBindAll, trustFwdFor      bool
	shutdownMs, upstreamTimeoutMs   int
	sessionID, configPath           string
	// sessionIDSet is whether --session-id was explicitly passed (unlike
	// sessionID, which is never empty: cmdProxy substitutes a fresh UUID when the
	// flag is unset). serveHTTPGateway's rejection guard reads this, since
	// --session-id is stdio-only.
	sessionIDSet       bool
	strictDrift        bool // global --strict-drift override (promotes drift to fatal on policed routes)
	requireAuditStrict bool // --require-audit=strict: runtime fail-closed gate when the audit trail degrades

	maxSessions          int    // global --max-sessions override (0 = unlimited); HTTP only
	sessionIdleTimeoutMs int    // global --session-idle-timeout override (0 = no reaping); HTTP only
	redisConfigured      bool   // --redis-addr was set; drives the multi-instance state advisory
	controlTokenPath     string // --control-token-path: where to write the /control/kill control token; HTTP only

	// httpOnlyFlagsSet holds the "--"-prefixed names of every HTTP-only flag
	// (httpOnlyProxyFlags) the operator activated, precomputed generically from
	// the FlagSet by httpOnlyFlagsSetOnStdio. serveStdioHost's rejection guard
	// reads this list directly rather than re-enumerating each flag.
	httpOnlyFlagsSet []string
}

// validateJWTAudienceConfig enforces fail-closed audience pinning for --jwks-uri
// mode: --jwt-audience must be set so a token minted for another relying party
// of the same IdP cannot be replayed against eunox. Bypassed only with explicit
// --jwt-allow-any-audience; a no-op when jwksURI is empty (JWT mode off). A
// whitespace-only value counts as unset: the validator collapses it to no pin
// (sanitizeAudiences/normalizeAudience), so accepting it here would silently reject
// every token instead of surfacing the misconfiguration.
func validateJWTAudienceConfig(jwksURI, jwtAudience string, allowAnyAudience bool) error {
	if jwksURI == "" {
		return nil
	}
	if strings.TrimSpace(jwtAudience) == "" && !allowAnyAudience {
		return fmt.Errorf(`--jwks-uri requires --jwt-audience (the expected "aud" claim) so a token minted for another service cannot be replayed against eunox; pass --jwt-allow-any-audience to accept any audience (not recommended)`)
	}
	// A PADDED audience is as broken as an empty one, and worse to diagnose: it survives
	// the trim check above and is then stored and compared VERBATIM against a token's
	// "aud", so it matches nothing and every call on every route is denied with an opaque
	// AUTHORIZATION_FAILED. A trailing space is easy to acquire from a shell heredoc or a
	// YAML block scalar. The manifest loader already refuses the same shape on its own
	// 'audience' field; the flag must not be the looser leg.
	if jwtAudience != strings.TrimSpace(jwtAudience) {
		return fmt.Errorf("--jwt-audience %q has leading or trailing whitespace; the audience is matched verbatim against a token's \"aud\" claim, so this value would never match and would silently deny every call", jwtAudience)
	}
	return nil
}

// jwtAudienceBypassWarning returns the warning to emit when audience pinning is
// disabled, or "" when pinning is active. Keyed on --jwt-allow-any-audience, not
// on whether --jwt-audience is empty: pdp.JWTPDP skips the audience check entirely
// when AllowAnyAudience is set, so a configured --jwt-audience is silently ignored
// when both flags are passed — exactly the dangerous case that must still warn.
func jwtAudienceBypassWarning(allowAnyAudience bool, jwtAudience string) string {
	if !allowAnyAudience {
		return ""
	}
	msg := "--jwt-allow-any-audience is set; tokens minted for other audiences are accepted, disabling cross-service replay protection."
	if jwtAudience != "" {
		msg += fmt.Sprintf(" The configured --jwt-audience %q is ignored.", jwtAudience)
	}
	return msg
}

// validateJWTIssuerConfig enforces fail-closed issuer pinning for --jwks-uri mode:
// --jwt-issuer must be set so a token from another issuer whose signing key is
// served by the same JWKS endpoint cannot be replayed against eunox. Bypassed only
// with explicit --jwt-allow-any-issuer; a no-op when jwksURI is empty (JWT mode off).
func validateJWTIssuerConfig(jwksURI, jwtIssuer string, allowAnyIssuer bool) error {
	if jwksURI == "" {
		return nil
	}
	if jwtIssuer == "" && !allowAnyIssuer {
		return fmt.Errorf(`--jwks-uri requires --jwt-issuer (the expected "iss" claim) so a token from another issuer sharing the JWKS endpoint cannot be replayed against eunox; pass --jwt-allow-any-issuer to accept any issuer (not recommended)`)
	}
	return nil
}

// jwtIssuerBypassWarning returns the warning to emit when issuer pinning is
// disabled, or "" when pinning is active. Keyed on --jwt-allow-any-issuer, not on
// whether --jwt-issuer is empty: pdp.JWTPDP skips the issuer check entirely when
// AllowAnyIssuer is set, so a configured --jwt-issuer is silently ignored when both
// flags are passed — exactly the dangerous case that must still warn.
func jwtIssuerBypassWarning(allowAnyIssuer bool, jwtIssuer string) string {
	if !allowAnyIssuer {
		return ""
	}
	msg := "--jwt-allow-any-issuer is set; tokens from any issuer sharing the JWKS endpoint are accepted, disabling issuer pinning."
	if jwtIssuer != "" {
		msg += fmt.Sprintf(" The configured --jwt-issuer %q is ignored.", jwtIssuer)
	}
	return msg
}

// validateJWTFlagsRequireJWKS fails closed when any JWT flag is set without --jwks-uri. Every
// --jwt-*/--jwks-allow-insecure-http flag configures bearer-token validation (or the
// experimental capability intersection), which runs ONLY when --jwks-uri stands up the JWT
// authenticator; the whole wiring block is gated on `jwksURI != ""`, so without it these flags
// are silently ignored and the gateway serves every request UNAUTHENTICATED while the operator
// believes JWT auth is enforced. Reject that mismatch at startup rather than no-op it.
//
// This is the SINGLE guard for the "these flags require --jwks-uri" contract. The set of
// activated jwks-gated flags is precomputed once by gatedFlagsSetWithoutJWKS over the single
// jwksGatedFlags inventory (both value- and explicit-set detection), so both halves of the
// guard are driven off ONE list: a new --jwt-* flag added to jwksGatedFlags is covered
// automatically, with no second per-flag block that could be forgotten. A no-op when --jwks-uri
// is set (JWT mode on) or no such flag was given.
func validateJWTFlagsRequireJWKS(pf proxyFlags) error { //nolint:gocritic // hugeParam: pf is a small flag bundle
	if pf.jwksURI != "" || len(pf.gatedJWTFlagsSet) == 0 {
		return nil
	}
	return fmt.Errorf("JWT flag(s) %s set without --jwks-uri: they configure bearer-token validation (or the experimental capability intersection), which runs only when --jwks-uri stands up the JWT authenticator — without it the gateway serves every request UNAUTHENTICATED. Set --jwks-uri to enable JWT authentication, or remove these flags", strings.Join(pf.gatedJWTFlagsSet, ", "))
}

// jwtExperimentalCapsWarning returns the startup warning to emit when the experimental
// mcp.capabilities claim schema (JWT v0.2) is enabled, or "" when it is off. Mirrors
// jwtAudienceBypassWarning/jwtIssuerBypassWarning so every JWT-mode advisory is a
// named, testable helper rather than an inline Fprintf.
func jwtExperimentalCapsWarning(experimentalCaps bool) string {
	if !experimentalCaps {
		return ""
	}
	return "--jwt-experimental-capabilities is set; enforcement of the mcp.capabilities claim schema (JWT v0.2) is EXPERIMENTAL and the claim format may change before 1.0."
}

// validateJWKSURIScheme enforces a tamper-resistant channel for the JWKS endpoint,
// the root of trust for every token. https is always accepted; http only to a
// loopback host, unless --jwks-allow-insecure-http is set. A plaintext fetch to a
// remote host would let an attacker substitute the key set and forge capability
// claims, so it fails closed by default.
func validateJWKSURIScheme(jwksURI string, allowInsecure bool) error {
	if jwksURI == "" {
		return nil
	}
	u, err := url.Parse(jwksURI)
	if err != nil {
		// url.Parse returns a *url.Error whose Error() embeds the raw input, so wrapping it
		// with %w would print a credentialed JWKS URI in full at startup. Report the
		// redacted URL and the parse reason separately.
		var uerr *url.Error
		if errors.As(err, &uerr) {
			return fmt.Errorf("--jwks-uri %s is not a valid URL: %v", capability.RedactURLForLog(jwksURI), uerr.Err)
		}
		return fmt.Errorf("--jwks-uri %s is not a valid URL: %v", capability.RedactURLForLog(jwksURI), err)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if capability.IsLoopbackHost(u.Hostname()) || allowInsecure {
			return nil
		}
		return fmt.Errorf("--jwks-uri uses plaintext http:// to a non-loopback host (%q); the JWKS is the root of trust for every token and an on-path attacker could substitute keys to forge capability claims. Use https://, or pass --jwks-allow-insecure-http for development only", u.Host)
	default:
		return fmt.Errorf("--jwks-uri must be an http or https URL, got scheme %q", u.Scheme)
	}
}

// validateOAuthURI rejects an OAuth metadata URI (the --oauth-resource identifier or
// an authorization-server URI) that is unsafe to publish in an RFC 9728
// protected-resource metadata document / WWW-Authenticate challenge: it must be an
// absolute https URI with a host, no fragment, and no character illegal in an HTTP
// quoted-string, and must carry no residual ${VAR}/$VAR reference left by an unset
// environment variable (which would publish the literal text — the same fail-closed
// posture the listen.authToken / upstreamAuthHeader credential guards take). label names
// the source for the operator (e.g. "--oauth-resource"). Single-sourced so a hardening
// fix to one metadata URI cannot miss the other.
//
// allowEmpty governs the empty-string policy, which differs by source: the resource URI
// may be empty (the metadata endpoint is then simply not published), but an
// authorization-server URI may not — an empty entry would be published as "" in the RFC
// 9728 authorization_servers array, so it fails closed.
func validateOAuthURI(label, uri string, allowEmpty bool) error {
	if uri == "" {
		if allowEmpty {
			return nil
		}
		return fmt.Errorf("%s must not be empty", label)
	}
	// url.Parse accepts "${VAR}" in a path or query position, so without this the
	// literal text would be published verbatim in the metadata document.
	if config.ContainsEnvRef(uri) {
		return fmt.Errorf("%s %q contains an unexpanded ${VAR}/$VAR reference (the environment variable is unset, so the literal text would be published in the OAuth metadata document); set the variable, or remove the reference", label, uri)
	}
	u, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("%s is not a valid URI: %w", label, err)
	}
	if !u.IsAbs() || u.Host == "" {
		return fmt.Errorf("%s must be an absolute URI with a scheme and host (e.g. https://example.com), got %q", label, uri)
	}
	// RFC 9728 URIs are always https; a client validating the metadata field against
	// the https URL it was challenged at would reject a plaintext one.
	if !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("%s must use the https scheme (RFC 9728 URIs are always https), got %q", label, uri)
	}
	// RFC 9728 URIs are fragment-free, and a fragment would not survive metadata-URL
	// construction — reject rather than silently drop it.
	if u.Fragment != "" || strings.Contains(uri, "#") {
		return fmt.Errorf("%s must not contain a URI fragment (RFC 9728 URIs are fragment-free), got %q", label, uri)
	}
	for _, r := range uri {
		if r == '"' || r == '\\' || r < 0x20 || r == 0x7f {
			return fmt.Errorf("%s %q contains a character (%q) that is illegal in an HTTP quoted-string and would corrupt the OAuth metadata document / WWW-Authenticate challenge; a valid URI never contains it", label, uri, r)
		}
	}
	return nil
}

// newJWKSHTTPClient returns the HTTP client used to fetch the JWKS. Its redirect
// policy re-applies validateJWKSURIScheme to every redirect target: checking the
// configured URI alone is not enough, since a valid https endpoint could 302 the
// key fetch onto plaintext remote http, reopening the key-substitution path. A
// redirect to a disallowed scheme aborts the fetch.
func newJWKSHTTPClient(allowInsecure bool) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			if err := validateJWKSURIScheme(req.URL.String(), allowInsecure); err != nil {
				return fmt.Errorf("JWKS redirect blocked: %w", err)
			}
			// The JWKS is the root of trust for every token, so a redirect must not leave
			// the configured HOST: the scheme check above still passes an https->https hop,
			// so without this an IdP open-redirect (or a compromised redirector) could point
			// the key fetch at an attacker host and substitute the key set, forging
			// capability claims. via[0] is the original request (the configured --jwks-uri);
			// require every redirect target to share its hostname. Port and path may change
			// (an IdP may relocate the key set within its own host), but the host may not —
			// with one exception: a hop between two loopback spellings (localhost <->
			// 127.0.0.1) never leaves the machine, so it has no on-path attacker surface (and
			// the scheme check above already confined any plaintext http hop to loopback).
			// Allowing it keeps the loopback dev flow working even though the hostname string
			// differs; every other cross-host hop is still refused.
			if len(via) > 0 {
				origHost := via[0].URL.Hostname()
				targetHost := req.URL.Hostname()
				bothLoopback := capability.IsLoopbackHost(targetHost) && capability.IsLoopbackHost(origHost)
				if !strings.EqualFold(targetHost, origHost) && !bothLoopback {
					return fmt.Errorf("JWKS redirect blocked: target host %q differs from the configured JWKS host %q; the key fetch must stay on the configured host", targetHost, origHost)
				}
			}
			return nil
		},
	}
}

// warnNoRedisSharedState prints the multi-instance advisory when a policy depends on
// shared counter/kill-switch state (maxCalls quotas OR sequenceBlock call-ordering
// history) but no Redis backend is configured: the in-memory backend is per-process,
// so running more than one instance silently multiplies quotas, de-syncs kills, and
// lets a sequenceBlock gate fail open when a session's antecedent and blocked calls
// land on different instances. Shared by the stdio and gateway serve paths so the
// wording and trigger cannot drift.
func warnNoRedisSharedState(redisConfigured, policyUsesSharedState bool) {
	if redisConfigured || !policyUsesSharedState {
		return
	}
	fmt.Fprintf(os.Stderr, "[eunox] NOTICE: a policy uses maxCalls or sequenceBlock but no --redis-addr is set — call-counter, call-ordering history, and kill-switch state are per-process. Running multiple instances will not share quotas, sequence history, or revocations; configure --redis-addr for multi-instance deployments.\n")
}

// resolveOAuthMetadata builds the RFC 9728 protected-resource metadata document
// (and its URL) for the gateway, or returns (nil, "", nil) when no resource URI is
// configured — in which case the metadata endpoint is simply not published. It fails
// closed on an invalid resource / authorization-server URI, and on an authorization
// server configured without a resource to publish it in. Config takes precedence over
// the flags.
func resolveOAuthMetadata(cfg *config.GatewayConfig, pf proxyFlags) (*transport.OAuthResourceMetadata, string, error) { //nolint:gocritic // hugeParam: pf is a small flag bundle
	// Resolve the RFC 9728 protected-resource URI (config takes precedence over the
	// flag). The metadata document is published only when this is set: --jwks-uri
	// without --oauth-resource is valid and simply does not expose the metadata
	// endpoint — but it must never serve a document missing the REQUIRED `resource`
	// field.
	oauthResource := cfg.Listen.OAuthResource
	oauthResourceLabel := "listen.oauthResource"
	if oauthResource == "" {
		oauthResource = pf.oauthResource
		oauthResourceLabel = "--oauth-resource"
	} else if pf.oauthResource != "" && pf.oauthResource != cfg.Listen.OAuthResource {
		// Config wins, matching the audit-path precedence above — but say so. The
		// resource URI is what a client's token audience is checked against, so an
		// operator who passed --oauth-resource and got a metadata document naming a
		// different resource would otherwise debug a token-audience mismatch with no
		// hint that their flag was dropped.
		fmt.Fprintf(os.Stderr, "[eunox] WARNING: --oauth-resource %q is overridden by the config's listen.oauthResource %q; the config takes precedence.\n", pf.oauthResource, cfg.Listen.OAuthResource)
	}
	if err := validateOAuthURI(oauthResourceLabel, oauthResource, true); err != nil {
		return nil, "", err
	}

	var oauthAuthzServers []string
	// validateAuthz is set for the two operator-supplied sources
	// (listen.oauthAuthorizationServers and --oauth-authorization-server). The --jwt-issuer
	// fallback is exempt: it is the issuer already wired into JWT validation and may be
	// a loopback http URL in dev (under --jwks-allow-insecure-http), so forcing https on
	// it here would be a regression.
	var validateAuthz bool
	switch {
	case len(cfg.Listen.OAuthAuthorizationServers) > 0:
		oauthAuthzServers = cfg.Listen.OAuthAuthorizationServers
		validateAuthz = true
		if pf.oauthAuthzServer != "" && (len(oauthAuthzServers) != 1 || oauthAuthzServers[0] != pf.oauthAuthzServer) {
			// Same rule as the resource URI above: config wins, but an explicitly-passed
			// flag is never discarded in silence. Name the flag as REGISTERED
			// (--oauth-authorization-server); an operator who greps --help for the name in
			// this message must find it, and --oauth-authz-server does not exist.
			fmt.Fprintf(os.Stderr, "[eunox] WARNING: --oauth-authorization-server=%q is overridden by listen.oauthAuthorizationServers=%v from the config file; the config value is published.\n", pf.oauthAuthzServer, oauthAuthzServers)
		}
	case pf.oauthAuthzServer != "":
		oauthAuthzServers = []string{pf.oauthAuthzServer}
		validateAuthz = true
	case pf.jwtIssuer != "":
		oauthAuthzServers = []string{pf.jwtIssuer}
	}
	// Validate every explicitly-configured authorization-server URI before it enters
	// the RFC 9728 metadata document, mirroring the validateOAuthResourceURI guard on
	// the resource field: reject a residual ${VAR}/$VAR literal (unset env ref) and any
	// non-https / malformed URI. Fail closed before any metadata is built.
	if validateAuthz {
		for _, server := range oauthAuthzServers {
			if err := validateOAuthURI("oauth authorization server", server, false); err != nil {
				return nil, "", err
			}
		}
		// The authorization server is only ever published inside the RFC 9728 metadata
		// document, which is served only when a resource URI is set. An explicit
		// authorization server with no --oauth-resource is therefore a silent no-op;
		// fail closed rather than drop it.
		if oauthResource == "" {
			return nil, "", fmt.Errorf("an OAuth authorization server is configured but --oauth-resource / listen.oauthResource is not set; the authorization server is only published in the RFC 9728 metadata document, which requires a resource URI")
		}
	}

	// Publish the metadata document only when a resource URI is configured (it is
	// non-conforming without the required `resource` field).
	if oauthResource == "" {
		return nil, "", nil
	}
	return &transport.OAuthResourceMetadata{
		Resource:             oauthResource,
		AuthorizationServers: oauthAuthzServers,
	}, transport.BuildOAuthMetadataURL(oauthResource), nil
}

// serveHTTPGateway serves cfg's upstreams over an HTTP listener, one /mcp/<name>
// route each (the gateway shape).
func serveHTTPGateway(ctx context.Context, cfg *config.GatewayConfig, sink *audit.Sink, counter capability.CallCounter, flowStore capability.FlowLabelStore, ks killswitch.Manager, pf proxyFlags) error { //nolint:gocritic // hugeParam: pf is a small flag bundle
	// --session-id is a stdio-only concept (a gateway mints its own Mcp-Session-Id
	// per client session, per-route); silently ignoring it here would let an
	// operator believe a fixed session ID took effect. Fail closed rather than
	// no-op, mirroring serveStdioHost's HTTP-only-flag rejections. pf.sessionIDSet
	// (not pf.sessionID, which is never empty — cmdProxy falls back to a fresh
	// UUID when the flag is unset) tracks whether the operator actually passed it.
	if pf.sessionIDSet {
		return fmt.Errorf("--session-id requires transport: stdio (a gateway mints its own Mcp-Session-Id per client session)")
	}
	// drift.MakeDriftCheck is passed as the per-route hook factory; BuildRoutes
	// wires it inside, so this layer never reaches into route internals.
	routes, err := transport.BuildRoutes(cfg, sink, counter, flowStore, ks, pf.strictDrift, drift.MakeDriftCheck)
	if err != nil {
		return err
	}

	warnNoRedisSharedState(pf.redisConfigured, transport.AnyRouteHasMaxCalls(routes) || transport.AnyRouteHasSequenceBlock(routes) || transport.AnyRouteHasFlowLabel(routes))

	bind := cfg.Listen.Bind
	if bind == "" {
		bind = "127.0.0.1"
	}
	// bindExposesAllInterfaces catches every spelling net.Listen resolves to the
	// unspecified address, including the ones net.ParseIP alone does not.
	bindHost := strings.TrimSuffix(strings.TrimPrefix(bind, "["), "]")
	if bindExposesAllInterfaces(bindHost) {
		if !pf.unsafeBindAll {
			return fmt.Errorf("gateway bind %q exposes the proxy to all network interfaces; pass --unsafe-bind-all to proceed", bind)
		}
		fmt.Fprintf(os.Stderr, "[eunox] WARNING: proxy is bound to all interfaces (%s). Ensure appropriate network controls are in place.\n", bind)
	}
	// The --trust-forwarded-for warning is emitted by HTTPProxy.Serve, which knows
	// the resolved bind and warns only on a non-loopback bind.

	upstreamTimeMs := transport.ResolveUpstreamTimeout(pf.upstreamTimeoutMs, cfg.Defaults.UpstreamTimeoutMs)

	// Concurrency controls (config takes precedence over the flag). 0 ⟹ unlimited
	// sessions / no idle reaping. An explicit listen.maxSessions overrides the flag
	// even at 0, so config can still express "unlimited" despite the flag's non-zero
	// default backstop.
	maxSessions := transport.ResolveMaxSessions(pf.maxSessions, cfg.Listen.MaxSessions)
	// A present config value wins, including an explicit 0 ("no idle reaping"), so config
	// can disable a non-zero --session-idle-timeout flag; an absent key (nil) leaves the
	// flag's value in force. Mirrors ResolveMaxSessions.
	sessionIdleMs := transport.ResolveSessionIdleTimeout(pf.sessionIdleTimeoutMs, cfg.Listen.SessionIdleTimeoutMs)
	// listen.trustedProxyHops is config-only (no flag): the chain depth is a property of
	// the deployment's topology, not something to toggle per invocation. Leaving it 0 when
	// the key is absent lets the constructor apply the single-proxy default.
	var trustedProxyHops int
	if h := cfg.Listen.TrustedProxyHops; h != nil {
		trustedProxyHops = *h
	}

	// Fail closed when a route manifest declares an `audience` pin but no --jwks-uri was
	// set: the pin is a JWT concept consulted only when the JWT PDP is stood up (below),
	// so without --jwks-uri it is silently dead config and the route serves every request
	// unauthenticated — the config-file form of the silently-ignored-JWT-auth footgun the
	// --jwt-* flag guard (validateJWTFlagsRequireJWKS) closes for the CLI form.
	if pf.jwksURI == "" {
		if name, pinned := transport.FirstRouteAudiencePin(routes); pinned {
			return fmt.Errorf("route %q declares an audience pin in its policy manifest but --jwks-uri is not set: the audience pin is a JWT concept that is only enforced in JWT mode, so without --jwks-uri it is silently ignored and the route serves every request unauthenticated. Set --jwks-uri to enable JWT authentication, or remove the manifest 'audience' field", name)
		}
	}

	// Per-route JWT∩manifest intersection: wrap each route's PDP in a pdp.JWTPDP
	// whose Inner is that route's manifest PDP, sharing one JWKS validator.
	var gwJWTPDP *pdp.JWTPDP
	if pf.jwksURI != "" {
		// Fail closed on audience pinning and on a plaintext JWKS endpoint before
		// standing up the JWT PDP.
		if err := validateJWTAudienceConfig(pf.jwksURI, pf.jwtAudience, pf.jwtAllowAnyAudience); err != nil {
			return err
		}
		if err := validateJWTIssuerConfig(pf.jwksURI, pf.jwtIssuer, pf.jwtAllowAnyIssuer); err != nil {
			return err
		}
		if err := validateJWKSURIScheme(pf.jwksURI, pf.jwksAllowInsecure); err != nil {
			return err
		}
		if w := jwtAudienceBypassWarning(pf.jwtAllowAnyAudience, pf.jwtAudience); w != "" {
			fmt.Fprintf(os.Stderr, "[eunox] WARNING: %s\n", w)
		}
		// --jwt-allow-any-audience also voids per-route manifest 'audience' pins (the
		// wrapper skips per-route narrowing when AllowAnyAudience is set). The generic
		// bypass warning above names only the --jwt-audience flag, so call out the dead
		// manifest pin explicitly — otherwise an operator who pinned a route's audience
		// in its policy manifest has no signal that the pin no longer enforces.
		if pf.jwtAllowAnyAudience {
			if name, pinned := transport.FirstRouteAudiencePin(routes); pinned {
				fmt.Fprintf(os.Stderr, "[eunox] WARNING: --jwt-allow-any-audience voids the manifest 'audience' pin on route %q; that route now accepts tokens for any audience. Remove --jwt-allow-any-audience to enforce the pin.\n", name)
			}
		}
		if w := jwtIssuerBypassWarning(pf.jwtAllowAnyIssuer, pf.jwtIssuer); w != "" {
			fmt.Fprintf(os.Stderr, "[eunox] WARNING: %s\n", w)
		}
		if w := jwtExperimentalCapsWarning(pf.jwtExperimentalCaps); w != "" {
			fmt.Fprintf(os.Stderr, "[eunox] WARNING: %s\n", w)
		}
		// Describe what is actually enforced: the manifest intersection with
		// mcp.capabilities runs only when the experimental flag is on. With it off,
		// identity-only tokens are validated and a token carrying mcp.capabilities is
		// rejected, so claiming "intersecting" unconditionally would mislead operators.
		// Redact before printing: some IdPs gate the JWKS endpoint behind a query key or
		// basic-auth userinfo, and this banner goes to the same stderr the systemd journal,
		// container logs, and the doctor bundle collect. That is a log surface, so it takes
		// the strict log-facing redactor (scheme://host only) the other banner and
		// validation-error sites use; the JWKS URI — the root of trust for token
		// verification — must not be the exception.
		safeJWKS := capability.RedactURLForLog(pf.jwksURI)
		if pf.jwtExperimentalCaps {
			fmt.Fprintf(os.Stderr, "[eunox] JWT PDP enabled (JWKS URI: %s); intersecting per-route manifests with experimental mcp.capabilities claims\n", safeJWKS)
		} else {
			fmt.Fprintf(os.Stderr, "[eunox] JWT PDP enabled (JWKS URI: %s); enforcing per-route manifests (experimental mcp.capabilities intersection disabled; pass --jwt-experimental-capabilities to enable)\n", safeJWKS)
		}
		gwJWTPDP, err = transport.WrapRoutesWithJWT(routes, pdp.JWTPDPOptions{
			JWKSURI:                  pf.jwksURI,
			Issuer:                   pf.jwtIssuer,
			Audience:                 pf.jwtAudience,
			AllowAnyAudience:         pf.jwtAllowAnyAudience,
			AllowAnyIssuer:           pf.jwtAllowAnyIssuer,
			Leeway:                   jwtLeewayOption(pf.jwtLeeway),
			KillSwitch:               ks,
			ExperimentalCapabilities: pf.jwtExperimentalCaps,
			// Client enforces the scheme policy on redirects too, so an https
			// JWKS endpoint cannot 302 the key fetch onto plaintext remote http.
			Client: newJWKSHTTPClient(pf.jwksAllowInsecure),
		})
		if err != nil {
			return err
		}
	}

	// listen.authToken and --jwks-uri are mutually exclusive: the static token
	// check runs first and 401s every IdP JWT before the JWT PDP runs, silently
	// disabling JWT auth. Fail closed with a clear error.
	if cfg.Listen.AuthToken != "" && gwJWTPDP != nil {
		return fmt.Errorf("listen.authToken and --jwks-uri are mutually exclusive: JWT mode handles all authentication, but the static token check runs first and rejects every IdP JWT. Remove listen.authToken when --jwks-uri is set")
	}

	// Resolve and validate the RFC 9728 protected-resource metadata (nil when no
	// resource URI is configured — the endpoint is then simply not published).
	oauthMeta, oauthMetaURL, err := resolveOAuthMetadata(cfg, pf)
	if err != nil {
		return err
	}
	// Publishing the metadata document announces "this resource is protected; present a
	// bearer token" — to any unauthenticated client, since the endpoint is
	// unauthenticated by design. With NEITHER --jwks-uri nor listen.authToken the
	// gateway validates no bearer token at all, so it would advertise a protection it
	// does not enforce and a client would present a credential that is never checked.
	// Fail closed, the same way validateJWTFlagsRequireJWKS rejects every other
	// JWT-adjacent flag set without a JWKS endpoint; these two --oauth-* flags were its
	// only gap.
	//
	// listen.authToken counts as validation even though it is a static shared secret
	// rather than OAuth: checkAuth rejects every unauthenticated request and already
	// serves the metadata URL as the resource_metadata hint on its 401 challenge, so
	// that pairing is a supported deployment, not the unenforced-advertisement hole.
	if oauthMeta != nil && gwJWTPDP == nil && cfg.Listen.AuthToken == "" {
		return fmt.Errorf("--oauth-resource / listen.oauthResource publishes RFC 9728 protected-resource metadata, but no bearer-token validation is configured: set --jwks-uri (or listen.authToken) so presented tokens are actually verified, or remove the --oauth-* settings so the gateway does not advertise a protection it cannot enforce")
	}

	// Generate a fresh loopback control token for POST /control/kill, written to a
	// 0600 file the operator (and `eunox kill`) can read. It authenticates the
	// emergency-stop endpoint independently of listen.authToken / JWT mode, so a
	// same-host process cannot trigger it merely by reaching loopback. Fail closed
	// if it cannot be minted or persisted: the endpoint must not come up unauthed.
	controlToken, err := transport.GenerateControlToken()
	if err != nil {
		return fmt.Errorf("kill control endpoint: %w", err)
	}
	// Persist it only AFTER the listener binds (AfterListen). The write deliberately
	// overwrites whatever token sits at the shared default path, so doing it here —
	// before the bind — meant an operator who accidentally started a second proxy got a
	// clean "address already in use" failure from the doomed process that had already
	// replaced the RUNNING proxy's token on disk: `eunox kill` then presents a token the
	// live proxy rejects, and the loopback emergency stop stays broken until restart, in
	// exactly the confused-deployment situation where it matters most.
	writeControlToken := func() error {
		controlTokenFile, werr := transport.WriteControlTokenFile(pf.controlTokenPath, controlToken)
		if werr != nil {
			return fmt.Errorf("kill control endpoint: %w", werr)
		}
		fmt.Fprintf(os.Stderr, "[eunox] Control token for POST /control/kill written to %s (0600). 'eunox kill' reads it from there; override with --control-token-path / --control-token / EUNOX_CONTROL_TOKEN.\n", controlTokenFile)
		return nil
	}

	proxy := transport.NewHTTPProxyGateway(transport.HTTPGatewayOptions{
		Routes:             routes,
		Sink:               sink,
		KS:                 ks,
		JWTPDP:             gwJWTPDP,
		OAuthMeta:          oauthMeta,
		OAuthMetaURL:       oauthMetaURL,
		ShutdownMs:         pf.shutdownMs,
		UpstreamTimeMs:     upstreamTimeMs,
		RequireAuditStrict: pf.requireAuditStrict,
		AuthToken:          cfg.Listen.AuthToken,
		ControlToken:       controlToken,
		AfterListen:        writeControlToken,
		TrustFwdFor:        pf.trustFwdFor,
		TrustedProxyCIDRs:  cfg.Listen.TrustedProxyCIDRs,
		TrustedProxyHops:   trustedProxyHops,
		Bind:               bind,
		Port:               cfg.Listen.Port,
		AllowedOrigins:     cfg.Listen.AllowedOrigins,
		MaxSessions:        maxSessions,
		SessionIdleMs:      sessionIdleMs,
	})
	fmt.Fprintf(os.Stderr, "[eunox] GATEWAY MODE: %d upstream route(s) from %s\n", len(routes), pf.configPath)
	return proxy.Serve(ctx)
}

// serveStdioHost serves cfg's single upstream over stdin/stdout (the stdio host
// shape). The upstream is a subprocess (transport: stdio) or a remote HTTP server
// (transport: http).
func serveStdioHost(ctx context.Context, cfg *config.GatewayConfig, sink *audit.Sink, counter capability.CallCounter, flowStore capability.FlowLabelStore, ks killswitch.Manager, pf proxyFlags) error { //nolint:gocritic // hugeParam: pf is a small flag bundle
	// JWT validation and OAuth metadata are HTTP-listener concerns; a stdio host
	// has no socket on which to serve them.
	if pf.jwksURI != "" {
		return fmt.Errorf("--jwks-uri requires transport: http (a stdio host has no HTTP listener)")
	}
	if pf.oauthResource != "" {
		return fmt.Errorf("--oauth-resource requires transport: http (a stdio host has no HTTP listener)")
	}
	// --oauth-authorization-server only feeds the RFC 9728 metadata document, which is
	// served on the HTTP listener; on stdio it would be a silent no-op, so fail closed
	// like its siblings above rather than ignore it.
	if pf.oauthAuthzServer != "" {
		return fmt.Errorf("--oauth-authorization-server requires transport: http (a stdio host has no HTTP listener)")
	}
	// Every other HTTP-only flag (--control-token-path, --session-idle-timeout,
	// --max-sessions, --unsafe-bind-all, --trust-forwarded-for): all configure the
	// HTTP listener this stdio host does not stand up, so — like --jwks-uri and
	// the --oauth-* flags above — silently accepting them would let an operator
	// believe they took effect. httpOnlyFlagsSetOnStdio (precomputed into
	// pf.httpOnlyFlagsSet) is the single source of truth for this list, so a
	// future HTTP-only flag added there is covered automatically.
	if len(pf.httpOnlyFlagsSet) > 0 {
		return fmt.Errorf("%s requires transport: http (a stdio host has no HTTP listener)", strings.Join(pf.httpOnlyFlagsSet, ", "))
	}

	u := &cfg.Upstreams[0] // validate() guarantees exactly one upstream for transport: stdio
	auditMode := cfg.AuditModeFor(u)

	// Fail-closed per-upstream startup guards (config-declared strictDrift requires a
	// policy; a policyless upstream must be in audit mode). Single-sourced in config so
	// this stdio host and transport.BuildRoutes cannot drift on what they refuse.
	if err := cfg.StartupPolicyError(u); err != nil {
		return err
	}
	configStrict := cfg.ResolvedStrictDrift(u)

	dp, manifest, policyVersion, policySHA256, err := transport.LoadUpstreamPDP(u, cfg.HostTransport(), cfg.BaseDir, counter, flowStore, ks)
	if err != nil {
		return err
	}
	// Resolved once the manifest is known, through the same resolver the gateway
	// uses, so the two transports cannot diverge.
	strictDrift := transport.ResolveStrictDrift(configStrict, pf.strictDrift, manifest != nil)
	if pf.strictDrift && manifest == nil {
		fmt.Fprintf(os.Stderr, "[eunox] WARNING: --strict-drift had no effect: upstream %q has no policy to check drift against.\n", u.Name)
	}

	// The three open-posture notices (per-entry AUDIT NOTICE, whole-route AUDIT MODE
	// banner, TLS-skip WARNING) go through the shared transport helper so the stdio host
	// and the gateway routes cannot drift on wording. routePath is "" — a stdio host runs
	// a single upstream on stdin/stdout with no /mcp mount.
	auditOnlyCount := 0
	if manifest != nil {
		auditOnlyCount = manifest.AuditOnlyCount()
	}
	transport.PrintRoutePolicyNotices(os.Stderr, u.Name, "", auditOnlyCount, auditMode, u.UpstreamTLSSkipVerify)
	// The remote-HTTP-upstream "server-initiated requests are not serviced" NOTICE is
	// emitted once, in the transport layer (StdioProxy.connectUpstream via
	// printRemoteUpstreamNotice), so it is not duplicated here.

	upstreamTimeMs := transport.ResolveUpstreamTimeout(pf.upstreamTimeoutMs, cfg.Defaults.UpstreamTimeoutMs)

	warnNoRedisSharedState(pf.redisConfigured, manifest.HasMaxCalls() || manifest.HasSequenceBlock() || manifest.HasFlowLabel())

	proxy := transport.NewStdioProxy(transport.StdioProxyOptions{
		Command:               u.Command,
		Args:                  u.Args,
		UpstreamURL:           u.UpstreamURL,
		UpstreamAuthHeader:    u.UpstreamAuthHeader,
		UpstreamTLSSkipVerify: u.UpstreamTLSSkipVerify,
		PDP:                   dp,
		Sink:                  sink,
		PolicyVersion:         policyVersion,
		PolicySHA256:          policySHA256,
		SessionID:             pf.sessionID,
		ShutdownMs:            pf.shutdownMs,
		UpstreamTimeMs:        upstreamTimeMs,
		Audit:                 auditMode,
		RequireAuditStrict:    pf.requireAuditStrict,
		// Serialize the decision phase when the policy reads/writes per-session state a
		// source commits and a later call reads (flow labels or sequenceBlock), so a
		// pipelining host cannot race a sink ahead of its source. A non-flow/non-sequence
		// policy keeps full parallelism.
		SerializeDecisions: manifest != nil && (manifest.HasFlowLabel() || manifest.HasSequenceBlock()),
		DriftCheck:         drift.MakeDriftCheck(manifest, strictDrift),
	})
	return proxy.Start(ctx)
}

// -----------------------------------------------------------------
// validate subcommand
// -----------------------------------------------------------------

// parseFlagsAndPositionals parses fs allowing flags and positionals in any order.
// Go's flag package stops at the first non-flag token; this loop peels off one
// positional at a time and re-parses the rest, so "<file> --flag" works as well
// as "--flag <file>". Returns the positionals in order.
func parseFlagsAndPositionals(fs *flag.FlagSet, args []string) ([]string, error) {
	var positionals []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positionals, nil
		}
		positionals = append(positionals, rest[0])
		args = rest[1:]
	}
}

// cmdValidate runs the `validate` subcommand and returns the process exit code
// (rather than calling os.Exit itself), so tests can drive every branch —
// including the fail-closed error paths — without terminating the test binary.
// args carries the subcommand's own arguments (os.Args[2:] in a real
// invocation), threaded from run.
func cmdValidate(args []string) int {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage:
  eunox validate <manifest.yaml> [...] --live --upstream-url <url>
  eunox validate <manifest.yaml> [...] --live --transport stdio -- <cmd> [args...]
  eunox validate --config <eunox.yaml> [--live]

Validate manifest file(s). Without --live, checks file syntax and exits.
With --live, also connects to a running upstream MCP server and reports
contract drift between the manifest and the live tool set. The upstream is
reached over HTTP (--transport http --upstream-url, the default) or as a
subprocess (--transport stdio -- <command>).

With --config, every route in the config is walked: each route's manifest(s)
are merged and validated, and with --live each route's declared upstream
(http or stdio subprocess) is introspected — no need to re-specify the
upstream wiring. The config is the source of truth.

Exit codes:
  0  Manifests valid; with --live, all entries match live tools and no
     glob-matched tools were detected.
  1  Drift warnings or stale entries present (operator review required).
     Reserved for findings, so CI can gate on it; never used for usage errors.
  2  Usage error, or a manifest/config parse or upstream-connection failure.

With --config the exit code is the maximum across all routes.

Flags:
`)
		fs.PrintDefaults()
	}

	live := fs.Bool("live", false, "Connect to a running upstream and report drift against the live tool set.")
	configPath := fs.String("config", "", "Path to an eunox config (YAML). Walks every route, validating each route's\nmanifest(s); with --live, each route's declared upstream is introspected.\nMutually exclusive with positional manifest files and --upstream-url.")
	transportFlag := fs.String("transport", config.HostTransportHTTP, "Upstream transport for --live: \"http\" (default, with --upstream-url) or \"stdio\"\n(subprocess command after \"--\").")
	upstreamURL := fs.String("upstream-url", "", "Base URL of the MCP HTTP server (required with --live --transport http, unless --config is set).")
	authHeader := fs.String("upstream-auth-header", "", `Header forwarded to the upstream in "Name: Value" format.`)
	tlsSkipVerify := fs.Bool("upstream-tls-skip-verify", false, "Skip TLS certificate verification for the upstream (development only).")

	// Split off a stdio subprocess command after the first standalone "--".
	// Manifest files are positional too, so "--" is the only unambiguous boundary;
	// Go's flag package consumes "--", so we split before parsing.
	rawArgs := args
	var stdioCmd []string
	for i, a := range rawArgs {
		if a == "--" {
			stdioCmd = rawArgs[i+1:]
			rawArgs = rawArgs[:i]
			break
		}
	}

	// Allow flags and positional manifest files to be interspersed (see
	// parseFlagsAndPositionals); a single fs.Parse would treat --live in
	// "validate manifest.yaml --live" as a filename.
	files, err := parseFlagsAndPositionals(fs, rawArgs)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		// 2, not 1: exit 1 is reserved for "drift warnings present, operator review
		// required", which a CI pipeline is expected to gate on. A usage error
		// exiting 1 is indistinguishable from a clean run that found drift, so a
		// misspelled flag reads as a policy finding. Every usage rejection below
		// exits 2 for the same reason.
		return 2
	}

	// Track whether --transport was set explicitly so we can reject it in modes
	// where it has no effect rather than ignoring it.
	transportSet := flagWasSet(fs, "transport")
	// Whether any live-upstream flag was supplied at all — computed once and
	// referenced at both guard sites below (the --config mutual-exclusion check and
	// the non---live rejection) so the two hand-maintained copies of this 5-term
	// predicate cannot drift out of lockstep with each other.
	upstreamFlagsGiven := *upstreamURL != "" || *authHeader != "" || *tlsSkipVerify || transportSet || len(stdioCmd) > 0

	// Mode selection: --config is mutually exclusive with positional manifests
	// and per-upstream flags — the config carries that wiring.
	if *configPath != "" {
		if len(files) > 0 {
			fmt.Fprintf(os.Stderr, "eunox validate: --config cannot be combined with positional manifest files (got %d); manifests are declared per-route in the config\n", len(files))
			return 2
		}
		if upstreamFlagsGiven {
			fmt.Fprintf(os.Stderr, "eunox validate: --config cannot be combined with --transport / --upstream-url / --upstream-auth-header / --upstream-tls-skip-verify / a stdio command; each route's transport and upstream wiring is declared in the config\n")
			return 2
		}
		cfg, err := config.LoadGatewayConfig(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "eunox validate: %v\n", err)
			return 2
		}
		// Base context; fetchRouteLive applies its own per-route timeout, so a slow
		// early route cannot exhaust a shared budget and fail the rest.
		return validateConfigRoutes(context.Background(), cfg, *live, os.Stdout)
	}

	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "eunox validate: at least one manifest file is required (or use --config <eunox.yaml>)\n")
		return 2
	}

	// --transport, the upstream-* flags, and a stdio command only select how to
	// reach a live upstream, so they are meaningless without --live. Reject up
	// front rather than silently dropping them in a syntax-only check.
	if !*live && upstreamFlagsGiven {
		fmt.Fprintf(os.Stderr, "eunox validate: --transport / --upstream-url / --upstream-auth-header / --upstream-tls-skip-verify and a stdio command ('-- <cmd>') only apply with --live; add --live to drift-check against the upstream\n")
		return 2
	}

	// Syntax check (always runs).
	ok := true
	var manifests []*config.LocalManifest
	for _, f := range files {
		m, err := config.LoadManifest(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL  %s: %v\n", f, err)
			ok = false
		} else {
			fmt.Printf("OK    %s  (name=%q version=%q capabilities=%d)\n", f, m.Name, m.Version, len(m.Capabilities))
			manifests = append(manifests, m)
		}
	}
	if !ok {
		// A parse/validate failure is exit code 2 ("connection or parse error"), not 1
		// ("drift warnings present"), matching the documented codes and the --config
		// path (LoadGatewayConfig returns 2) so a CI script keyed on the codes does not
		// mislabel a corrupt manifest as drift.
		return 2
	}

	// Cross-file merge-conflict detection (config.MergeManifests) must run even in
	// the syntax-only (non-live) path: `validate a.yaml b.yaml` (no --config, no
	// --live) previously returned 0 right after the per-file syntax check above,
	// so two positional manifests with a genuine merge conflict passed while the
	// equivalent --config route (validateConfigRoutes, which always merges) would
	// have failed, and `proxy` itself refuses to boot on the same conflict.
	merged, err := config.MergeManifests(manifests)
	if err != nil {
		// A merge conflict is a parse-class error (exit 2), not drift.
		fmt.Fprintf(os.Stderr, "eunox validate: %v\n", err)
		return 2
	}

	if !*live {
		return 0
	}

	// Live drift check. buildInitUpstreamSpec (shared with `init`) validates the
	// http/stdio flag combination, then we introspect the upstream as `init` does.
	spec, err := buildInitUpstreamSpec(*transportFlag, *upstreamURL, *authHeader, *tlsSkipVerify, stdioCmd)
	if err != nil {
		// A missing/incoherent upstream wiring is a connection error (exit 2), not drift.
		fmt.Fprintf(os.Stderr, "eunox validate: %v (or use --config <eunox.yaml>)\n", err)
		return 2
	}

	fmt.Printf("\nConnecting to upstream...")
	ctx, cancel := context.WithTimeout(context.Background(), liveUpstreamTimeout)
	defer cancel()
	info, err := fetchSpecLive(ctx, spec)
	if err != nil {
		fmt.Printf("  FAILED\n")
		fmt.Fprintf(os.Stderr, "eunox validate: %v\n", err)
		return 2
	}
	versionLabel := info.ServerVersion
	if versionLabel == "" {
		versionLabel = "unknown"
	}
	fmt.Printf("  ok (%d tool(s), server version: %s)\n\n", len(info.Tools), versionLabel)

	return runValidateLive(merged, info.Tools, info.ServerVersion, os.Stdout)
}

// writePolicyLoadResults prints one FAIL/OK line per outcome.LoadResults entry via
// wf, each indented by prefix, so validate and doctor cannot diverge on how a
// route's per-file manifest load result is reported — both format the exact same
// transport.PolicyLoadResult slice through this one function instead of
// hand-mirroring the loop.
func writePolicyLoadResults(wf func(format string, args ...interface{}), prefix string, results []transport.PolicyLoadResult) {
	for _, lr := range results {
		if lr.Err != nil {
			wf("%sFAIL  %s: %v\n", prefix, lr.Path, lr.Err)
			continue
		}
		wf("%sOK    %s  (name=%q version=%q capabilities=%d)\n", prefix, lr.Path, lr.Manifest.Name, lr.Manifest.Version, len(lr.Manifest.Capabilities))
	}
}

// reportRouteOutcome prints outcome's FAIL/OK/policy-config report for one route
// and reports whether its startup-fatal checks were satisfied. skip is true when
// the route's live-drift introspection (or, without --live, the route entirely)
// must not proceed: a no-policy route that fails closed at startup, a non-live
// no-policy route, or any policy'd-route load/merge/startup-check failure. code is
// the route's exit-code contribution (0 clean, 2 a startup-fatal failure) —
// factored out of validateConfigRoutes's loop body to keep its nesting flat.
func reportRouteOutcome(wf func(string, ...interface{}), wln func(...interface{}), outcome transport.RouteManifestOutcome, live bool) (code int, skip bool) {
	if outcome.NoPolicy {
		// A policyless route is only legal when it will actually boot. Flag a
		// config the proxy would refuse to start as FAIL rather than green-lighting
		// it or (under --live) connecting to an upstream that would never serve
		// traffic.
		if outcome.NoPolicyReason != "" {
			wf("  FAIL  this route fails closed at startup: %s.\n", outcome.NoPolicyReason)
			return 2, true
		}
		if outcome.AuditMode {
			wln("  (no policy configured — observe-only/wiretap route)")
		} else {
			wln("  (no policy configured — route is allow-all)")
		}
		// Without --live there is nothing further to report; with --live, the
		// caller falls through to introspection for visibility (no manifest to
		// drift-check, but the upstream connection is still worth showing).
		return 0, !live
	}

	writePolicyLoadResults(wf, "  ", outcome.LoadResults)
	if outcome.LoadFailed {
		return 2, true
	}
	if outcome.MergeErr != nil {
		wf("  FAIL  %v\n", outcome.MergeErr)
		return 2, true
	}
	if outcome.StartupErr != nil {
		wf("  FAIL  %v\n", outcome.StartupErr)
		return 2, true
	}
	return 0, false
}

// validateConfigRoutes walks every upstream in cfg, validating each route's
// manifest(s) and — when live is set — introspecting the declared upstream and
// reporting drift. A no-policy route the proxy would refuse to start is reported
// FAIL and skipped (never introspected, since the upstream would never serve); a
// valid no-policy route -- which on a gateway means audit/wiretap mode ONLY, since a
// policyless enforce route is refused at startup -- is introspected under --live for
// visibility but contributes no drift findings.
//
// Exit code is the maximum across routes: 0 clean, 1 drift, 2 parse/connection
// failure.
func validateConfigRoutes(ctx context.Context, cfg *config.GatewayConfig, live bool, out io.Writer) int {
	wf, wln := writers(out)

	worst := 0
	for i := range cfg.Upstreams {
		u := &cfg.Upstreams[i]
		if i > 0 {
			wln()
		}
		wf("── route %q (transport: %s) ──\n", u.Name, u.Transport)

		// Reproduce the proxy's actual startup policy-load decision so validate cannot
		// green-light a config `proxy` would refuse to boot: load and merge this
		// route's manifests (the cross-file merge-conflict detection lives in
		// MergeManifests itself), then run the same startup-fatal check LoadUpstreamPDP
		// folds in — the expectVersion pin, the sampling/createMessage-on-http guard,
		// and the stdio-host audience-pin guard — directly against the merged result,
		// via the shared walk both validate and doctor use.
		outcome := transport.WalkRouteManifests(cfg, u)

		exitCode, skip := reportRouteOutcome(wf, wln, outcome, live)
		if exitCode > worst {
			worst = exitCode
		}
		if skip {
			continue
		}

		if !live {
			continue
		}

		// Live drift check for this route.
		info, err := fetchRouteLive(ctx, u)
		if err != nil {
			wf("  Connecting to upstream...  FAILED\n  %v\n", err)
			if worst < 2 {
				worst = 2
			}
			continue
		}
		versionLabel := info.ServerVersion
		if versionLabel == "" {
			versionLabel = "unknown"
		}
		wf("  Connecting to upstream...  ok (%d tool(s), server version: %s)\n\n", len(info.Tools), versionLabel)

		// outcome.NoPolicy is the allow-all/no-policy route: every policy file loaded
		// cleanly to reach here (outcome.LoadFailed would have continued above), so
		// outcome.Merged covers a policy'd route and there is nothing to drift-check
		// for a policyless one.
		if outcome.NoPolicy {
			// Allow-all route with --live: nothing to drift-check against.
			wln("  (no manifest to compare against)")
			continue
		}
		// outcome.Merged was produced by WalkRouteManifests above (a merge failure
		// already FAILed the route), so the live drift check reuses it rather than
		// re-merging.
		code := runValidateLive(outcome.Merged, info.Tools, info.ServerVersion, out)
		if code > worst {
			worst = code
		}
	}
	return worst
}

// fetchSpecLive introspects the upstream an initUpstreamSpec points at, dispatching
// on its transport. Shared by `validate --live` and `init`, which both build a spec
// from the same CLI flags (via buildInitUpstreamSpec) and then probe it identically;
// fetchRouteLive is the gateway-config sibling for a *config.UpstreamConfig.
func fetchSpecLive(ctx context.Context, spec initUpstreamSpec) (LiveUpstreamInfo, error) {
	switch spec.Transport {
	case config.HostTransportStdio:
		return fetchLiveToolsStdio(ctx, spec.Command, spec.Args)
	case config.HostTransportHTTP:
		return fetchLiveTools(ctx, spec.URL, spec.AuthHeader, spec.TLSSkipVerify)
	default:
		// Fail closed on an unrecognized transport rather than probing it as HTTP,
		// matching fetchRouteLive and this package's every-switch-names-its-cases
		// convention. buildInitUpstreamSpec already rejects anything else, so this
		// is the structural guard that keeps a future third transport from silently
		// inheriting the HTTP probe.
		return LiveUpstreamInfo{}, fmt.Errorf("unknown upstream transport %q", spec.Transport)
	}
}

// fetchRouteLive introspects one route's declared upstream, dispatching on its
// transport. A fresh liveUpstreamTimeout is applied PER route so a slow early
// route cannot exhaust a shared budget and fail every later route.
func fetchRouteLive(ctx context.Context, u *config.UpstreamConfig) (LiveUpstreamInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, liveUpstreamTimeout)
	defer cancel()
	switch u.Transport {
	case config.HostTransportStdio:
		return fetchLiveToolsStdio(ctx, u.Command, u.Args)
	case config.HostTransportHTTP:
		return fetchLiveTools(ctx, u.UpstreamURL, u.UpstreamAuthHeader, u.UpstreamTLSSkipVerify)
	default:
		return LiveUpstreamInfo{}, fmt.Errorf("upstream %q: unknown transport %q", u.Name, u.Transport)
	}
}

// -----------------------------------------------------------------
// init subcommand
// -----------------------------------------------------------------

// bindExposesAllInterfaces reports whether bindHost (already stripped of any surrounding
// IPv6 brackets) will make the listener accept connections on every interface.
//
// Comparing the PARSED address rather than the string catches every IP-literal spelling of
// the unspecified address uniformly — "0.0.0.0", "::", "::0", "0:0:0:0:0:0:0:0" — which a
// literal "0.0.0.0"/"::" string match does not.
//
// But net.ParseIP is not the whole grammar the RESOLVER accepts. "0" and hex/octal
// shorthands like "0x0" or "00" are not Go IP literals, so ParseIP returns nil and the
// guard was skipped entirely — yet on a cgo-resolver build getaddrinfo("0") resolves to
// 0.0.0.0 and the listener binds every interface with no --unsafe-bind-all and no warning.
// A host that is entirely numeric (optionally 0x/0-prefixed) is an inet_aton-style integer
// address, not a DNS name, so it is decoded here rather than trusted to ParseIP. A value
// of zero is the unspecified address.
//
// Deliberately no DNS lookup: resolving an operator-supplied name at startup would be
// background network activity for a check that must work offline, and a NAME that resolves
// to 0.0.0.0 is not a shape any real deployment uses.
func bindExposesAllInterfaces(bindHost string) bool {
	if ip := net.ParseIP(bindHost); ip != nil {
		return ip.IsUnspecified()
	}
	if bindHost == "" {
		// An empty host in "host:port" means all interfaces to net.Listen.
		return true
	}
	// inet_aton-style integer form: strconv handles the 0x / 0o / leading-0 octal bases
	// the resolver accepts. Any parse failure means this is a name, not an integer.
	if n, err := strconv.ParseUint(bindHost, 0, 64); err == nil {
		return n == 0
	}
	return false
}

// refuseNonRegularOutput fails closed unless path is a regular file or genuinely absent.
// It is the binding of the shared guard in internal/config for the writers that truncate
// an operator-supplied destination (--output, the doctor bundle); see
// config.RefuseNonRegularPath for what the guard covers.
func refuseNonRegularOutput(path string) error {
	return config.RefuseNonRegularPath(path, "output file")
}

// writeGeneratedFile writes content to path at mode 0600, refusing to clobber a
// pre-existing file unless force is set. It closes two gaps in a plain
// os.WriteFile(path, …, 0o600): (1) O_CREATE applies the mode only on CREATION, so a
// pre-existing looser-mode file (e.g. 0644 from a prior run or a restore) would keep
// that mode and leave a generated config's cleartext upstream credential group/world-
// readable — force overwrites re-tighten the mode to 0600; (2) O_TRUNC silently
// clobbers, so without force an existing file is refused (O_EXCL) rather than
// destroying an operator's hand-edited manifest. Mirrors how the audit key/log paths
// are hardened (internal/audit tightenKeyFileMode + never-overwrite).
func writeGeneratedFile(path, content string, force bool) (err error) {
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if force {
		if err := refuseNonRegularOutput(path); err != nil {
			return err
		}
		// config.OpenNoFollow (O_NOFOLLOW on unix, 0 elsewhere) closes the Lstat->open
		// race the guard above cannot: the guard inspects the path, then OpenFile resolves
		// it again, and a link planted in that window would be followed — truncating the
		// TARGET, which the Chmod below would then re-mode to 0600 as well. O_EXCL already
		// refuses a symlink for free, which is why only the force path needs the flag.
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC | config.OpenNoFollow
	}
	f, err := os.OpenFile(path, flags, 0o600) //nolint:gosec // G304: path is an operator-provided --output/--config-output location, and 0600 is the intended restrictive mode
	if err != nil {
		if !force && errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%q already exists; refusing to overwrite it — pass --force to overwrite, or choose a different path", path)
		}
		return err
	}
	// Surface the close (which flushes): an error-swallowing deferred Close would let a
	// delayed write error (e.g. on NFS) be announced as a complete write. Keep the first
	// error if the body already set one.
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("closing %q: %w", path, cerr)
		}
	}()
	if force {
		// O_TRUNC kept a pre-existing file's (possibly looser) mode; re-tighten it BEFORE
		// writing so a regenerated credential-bearing config never lands at a group/world-
		// readable mode, and tighten on the open fd rather than os.Chmod(path), which would
		// re-resolve the path (following a symlink). On failure the (already-truncated) file
		// is left empty and the error returned — fail closed rather than write the
		// credential at a loose mode.
		if cerr := f.Chmod(0o600); cerr != nil {
			return fmt.Errorf("tightening mode of %q to 0600: %w", path, cerr)
		}
	}
	if _, werr := f.WriteString(content); werr != nil {
		return fmt.Errorf("writing %q: %w", path, werr)
	}
	return nil
}

// cmdInit runs the `init` subcommand and returns the process exit code (rather
// than calling os.Exit itself), so tests can drive every branch — including the
// fail-closed error paths — without terminating the test binary. args carries
// the subcommand's own arguments (os.Args[2:] in a real invocation), threaded
// from run.
func cmdInit(args []string) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage:
  eunox init [--transport http] --upstream-url <url> [flags]
  eunox init   --transport stdio [flags] -- <command> [args...]

Connect to a live MCP server (HTTP or stdio subprocess) and generate a deny-all
starter manifest. Every tool is commented out — uncomment and add conditions
only for tools the agent genuinely needs. Re-running init after a server update
and diffing against the current manifest surfaces additions and removals.

With --config-output, also scaffold a runnable eunox config matching the
introspected transport, so the quickstart is two commands:
  eunox init  --upstream-url <url> --output manifest.yaml --config-output eunox.yaml
  eunox proxy --config eunox.yaml

Flags:
`)
		fs.PrintDefaults()
	}

	transportFlag := fs.String("transport", config.HostTransportHTTP, `Upstream transport to introspect: "http" or "stdio".`)
	upstreamURL := fs.String("upstream-url", "", "Base URL of the MCP HTTP server (required with --transport http).")
	output := fs.String("output", "", "Path to write the generated manifest YAML (default: stdout).")
	configOutput := fs.String("config-output", "", "Also write a runnable eunox config to this path that fronts the introspected\nupstream and enforces the generated manifest. Requires --output (the config references it).")
	force := fs.Bool("force", false, "Overwrite --output / --config-output if they already exist (default: refuse to\nclobber). An overwrite also re-tightens the file mode to 0600.")
	name := fs.String("name", "generated-manifest", "Value for the manifest name field.")
	authHeader := fs.String("upstream-auth-header", "", `Header forwarded to the HTTP upstream in "Name: Value" format.`)
	tlsSkipVerify := fs.Bool("upstream-tls-skip-verify", false, "Skip TLS certificate verification for the HTTP upstream (development only).")
	pinDescriptions := fs.Bool("pin-descriptions", false, "Include a descriptionHash field for each tool, computed from its current live\ndescription. When set in the manifest, the proxy verifies the hash at startup\nand aborts if the description has changed — detecting upstream tool poisoning.")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}

	// Reject the incoherent --config-output-without--output combination up front, before
	// the live upstream fetch — otherwise the operator waits out the whole introspection
	// (up to liveUpstreamTimeout) only to be told their flags were incoherent (matches
	// buildInitUpstreamSpec's reject-flag-mixes-before-the-first-network-call posture).
	if *configOutput != "" && *output == "" {
		fmt.Fprintf(os.Stderr, "eunox init: --config-output requires --output (the config references the manifest file)\n")
		return 1
	}

	positional := fs.Args()
	spec, err := buildInitUpstreamSpec(*transportFlag, *upstreamURL, *authHeader, *tlsSkipVerify, positional)
	if err != nil {
		fmt.Fprintf(os.Stderr, "eunox init: %v\n", err)
		return 1
	}

	fmt.Fprintf(os.Stderr, "Fetching tool list from upstream...")
	ctx, cancel := context.WithTimeout(context.Background(), liveUpstreamTimeout)
	defer cancel()
	info, err := fetchSpecLive(ctx, spec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  FAILED\n")
		fmt.Fprintf(os.Stderr, "eunox init: %v\n", err)
		return 2
	}
	fmt.Fprintf(os.Stderr, "  %d tool(s)\n\n", len(info.Tools))

	manifest := generateInitManifestYAML(info.Tools, *name, info.ServerVersion, *pinDescriptions)

	if *output == "" {
		// --config-output-without--output was already rejected up front.
		fmt.Print(manifest)
		return 0
	}

	if err := writeGeneratedFile(*output, manifest, *force); err != nil {
		fmt.Fprintf(os.Stderr, "eunox init: %v\n", err)
		return 2
	}
	fmt.Fprintf(os.Stderr, "Generated manifest %s — review and uncomment the capabilities you want to permit.\n", *output)

	if *configOutput != "" {
		// Resolve the manifest path to absolute so the config works regardless of
		// the CWD when `proxy --config` is invoked.
		absManifest, err := filepath.Abs(*output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "eunox init: resolving manifest path: %v\n", err)
			return 2
		}
		cfg := generateInitConfigYAML(spec, absManifest)
		if err := writeGeneratedFile(*configOutput, cfg, *force); err != nil {
			fmt.Fprintf(os.Stderr, "eunox init: %v\n", err)
			return 2
		}
		fmt.Fprintf(os.Stderr, "Generated config %s — run: eunox proxy --config %s\n", *configOutput, *configOutput)
		if spec.AuthHeader != "" {
			fmt.Fprintf(os.Stderr, "[eunox] SECURITY: %s embeds the --upstream-auth-header value as a cleartext credential; keep it out of version control, or replace it with an env-ref (e.g. \"Authorization: Bearer ${UPSTREAM_TOKEN}\").\n", *configOutput)
		}
	}
	return 0
}

// buildInitUpstreamSpec validates and returns the live-introspection target,
// rejecting cross-axis flag mixes (http vs stdio) up front rather than at the
// first network call. Shared by `init` and `validate --live`; error messages are
// subcommand-agnostic.
func buildInitUpstreamSpec(transportMode, upstreamURL, authHeader string, tlsSkipVerify bool, positional []string) (initUpstreamSpec, error) {
	switch transportMode {
	case config.HostTransportHTTP:
		if upstreamURL == "" {
			return initUpstreamSpec{}, fmt.Errorf("--upstream-url is required with --transport http")
		}
		if len(positional) > 0 {
			return initUpstreamSpec{}, fmt.Errorf("positional args are not allowed with --transport http (got %q); they are the stdio subprocess command", positional)
		}
		return initUpstreamSpec{
			Transport:     config.HostTransportHTTP,
			URL:           upstreamURL,
			AuthHeader:    authHeader,
			TLSSkipVerify: tlsSkipVerify,
		}, nil
	case config.HostTransportStdio:
		if upstreamURL != "" {
			return initUpstreamSpec{}, fmt.Errorf("--upstream-url is not allowed with --transport stdio")
		}
		if authHeader != "" {
			return initUpstreamSpec{}, fmt.Errorf("--upstream-auth-header is not allowed with --transport stdio")
		}
		if tlsSkipVerify {
			return initUpstreamSpec{}, fmt.Errorf("--upstream-tls-skip-verify is not allowed with --transport stdio")
		}
		if len(positional) == 0 {
			return initUpstreamSpec{}, fmt.Errorf(`--transport stdio requires a subprocess command after "--", e.g.: --transport stdio -- npx -y @modelcontextprotocol/server-filesystem /data`)
		}
		return initUpstreamSpec{
			Transport: config.HostTransportStdio,
			Command:   positional[0],
			Args:      positional[1:],
		}, nil
	default:
		return initUpstreamSpec{}, fmt.Errorf("--transport must be %q or %q (got %q)", config.HostTransportHTTP, config.HostTransportStdio, transportMode)
	}
}

// -----------------------------------------------------------------
// audit-log readers (suggest / stats / audit-verify)
// -----------------------------------------------------------------

// auditLogMissingHint returns a first-run-friendly message for when the audit log
// does not exist yet — what the log is and how to produce one, instead of a raw
// OS error. cmdName is the subcommand, used in the message and re-run command.
func auditLogMissingHint(cmdName, logPath string) string {
	return fmt.Sprintf(
		"eunox %s: no audit log yet at %s.\n\n"+
			"The audit log is written while the proxy runs. Capture one by putting\n"+
			"eunox in front of your MCP server in audit mode:\n\n"+
			"  eunox proxy --audit -- <command that launches your MCP server>\n\n"+
			"Use the agent so it makes some calls, then re-run: eunox %s\n",
		cmdName, logPath, cmdName)
}

// openAuditChain opens the FULL audit chain — every rotated sibling plus the
// active base, discovered via audit.LogChainFiles — for a read-only reporting
// command, returning one concatenated reader (oldest record first) and a closer.
// Reading only the active base segment (the previous behavior) silently dropped
// every rotated file, so stats showed a partial histogram and suggest mined an
// incomplete usage set. audit.OpenLogChain opens one file at a time, so the fd
// count stays bounded even under the unbounded keep-all retention default. On
// error the returned message is the full text to print to stderr verbatim
// (either the first-run hint from auditLogMissingHint or a discovery-error
// line); the caller prints it and exits 1.
func openAuditChain(cmdName, logPath string) (reader io.Reader, closeAll func(), err error) {
	files, ferr := audit.LogChainFiles(logPath)
	if ferr != nil {
		// Pre-formatted via Sprintf (not a literal Errorf format string) so the
		// trailing newline — by design, this message is printed verbatim to
		// stderr like auditLogMissingHint below — doesn't trip the "error
		// strings must not end in punctuation/newline" checks.
		msg := fmt.Sprintf("eunox %s: discovering rotated audit logs: %v\n", cmdName, ferr)
		return nil, nil, fmt.Errorf("%s", msg)
	}
	if len(files) == 0 {
		return nil, nil, fmt.Errorf("%s", auditLogMissingHint(cmdName, logPath))
	}
	rc := audit.OpenLogChain(files)
	return rc, func() { _ = rc.Close() }, nil
}

// -----------------------------------------------------------------
// suggest subcommand
// -----------------------------------------------------------------

// cmdSuggest runs the `suggest` subcommand and returns the process exit code
// (rather than calling os.Exit itself), so tests can drive every branch. args
// carries the subcommand's own arguments (os.Args[2:] in a real invocation),
// threaded from run.
func cmdSuggest(args []string) int {
	fs := flag.NewFlagSet("suggest", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: eunox suggest [flags]

Generate a draft capability manifest from the local audit log. Unlike 'init'
(which scaffolds a deny-all from a live tool list), 'suggest' reads what the
agent actually did: it emits one entry per observed target and, for tool
arguments seen with a bounded set of string values, an allowedValues condition
grounded in those values.

Capture a tape first with a wiretap, then suggest:
  eunox proxy --audit -- <the command that launches your MCP server>
  # …use the agent for real work, then:
  eunox suggest --output manifest.yaml

The output is a DRAFT describing observed usage, not vetted policy. Review and
tighten every entry, then 'eunox validate' it before enforcing.

Exit codes:
  0  Draft manifest generated (to stdout or --output).
  1  Usage, config, or audit-log-read error.
  2  --output was set but writing the file failed.

Flags:
`)
		fs.PrintDefaults()
	}
	auditLogPath := fs.String("audit-log", "", "Path to the audit JSONL log (default: ~/.eunox/audit.jsonl).")
	configPath := fs.String("config", "", "Path to the eunox config (YAML). When set, the configured audit.log is\nused as the default for --audit-log.")
	name := fs.String("name", "suggested-manifest", "Value for the manifest name field.")
	output := fs.String("output", "", "Path to write the draft manifest (default: stdout).")
	force := fs.Bool("force", false, "Overwrite --output if it already exists (default: refuse to clobber). An\noverwrite also re-tightens the file mode to 0600.")
	maxValues := fs.Int("max-values", suggestMaxValuesDefault, "Max distinct values an argument may have before allowedValues is downgraded to a review comment.\n0 or negative falls back to the default (20).")

	if code, done := parseAuditReaderFlags("suggest", fs, args, configPath, auditLogPath, nil); done {
		return code
	}
	logPath, ok := resolveAuditReaderLogPath("suggest", *auditLogPath)
	if !ok {
		return 1
	}

	r, closeChain, err := openAuditChain("suggest", logPath)
	if err != nil {
		fmt.Fprint(os.Stderr, err.Error())
		return 1
	}
	defer closeChain()

	resolvedMaxValues := resolveMaxValues(*maxValues)
	suggestions, err := computeSuggestions(r, resolvedMaxValues)
	if err != nil {
		fmt.Fprintf(os.Stderr, "eunox suggest: reading log: %v\n", err)
		return 1
	}
	manifest := renderSuggestedManifest(suggestions, *name, resolvedMaxValues)

	if *output == "" {
		fmt.Print(manifest)
		return 0
	}
	if err := writeGeneratedFile(*output, manifest, *force); err != nil {
		fmt.Fprintf(os.Stderr, "eunox suggest: %v\n", err)
		return 2
	}
	fmt.Fprintf(os.Stderr, "Generated draft manifest %s from %d audit record(s) — review and tighten each entry, then run: eunox validate %s\n",
		*output, suggestions.records, *output)
	return 0
}
