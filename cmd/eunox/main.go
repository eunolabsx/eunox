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
//	contracts      Verify a local effect-contract corpus and print an entry's effect.ref pin.
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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	goredis "github.com/redis/go-redis/v9"

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

// run dispatches the subcommand in args and returns the exit code. Kept separate from
// main (the only os.Exit in the binary) so tests can assert the code without terminating.
// Every subcommand takes its own arguments (args[2:]) as a parameter rather than
// re-reading the global os.Args, so dispatch and flag parsing read the same vector.
func run(args []string) int {
	if len(args) < 2 {
		// Exit 0, not a usage error: package validators like winget launch the installed
		// binary with no args and flag any non-zero exit.
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
	case "contracts":
		return cmdContracts(subArgs)
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

// usageWriter returns os.Stdout when args explicitly requests help (--help, -help, or -h —
// the same tokens the flag package itself special-cases into ErrHelp), os.Stderr otherwise,
// so every subcommand's fs.Usage follows printUsage's own stated convention: help and bare
// invocations are a successful query (stdout, exit 0), a parse error prints usage to stderr
// alongside the failure. A "--" terminator ends the scan, matching parseFlagsAndPositionals'
// own handling — nothing after it is a flag. This is a heuristic, not a full re-parse: a
// flag value that happens to be the literal string "-h" (e.g. --audit-log -h) would be
// misread as a help request, but none of this binary's flags take a value where that is a
// plausible mistake to make.
func usageWriter(args []string) io.Writer {
	for _, a := range args {
		if a == "--" {
			return os.Stderr
		}
		if a == "--help" || a == "-help" || a == "-h" {
			return os.Stdout
		}
	}
	return os.Stderr
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
  eunox contracts    [--dir <corpus-dir>] [--ref <contract-id>]
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
  contracts       Verify a local effect-contract corpus (every declared digest recomputed
                  from its content) and print the effect.ref pin an author copies into a
                  manifest. Local only — the registry is never fetched.
  doctor          Print a user-initiated support bundle (redacted) for bug reports.
                  Nothing is uploaded — paste the output into your report manually.
  version         Print the binary version and exit.

Run 'eunox <subcommand> --help' for per-command flags.
`, version)
}

// -----------------------------------------------------------------
// proxy subcommand
// -----------------------------------------------------------------

// defaultMaxCallCounterKeys bounds the in-memory call counter's key set: each (session,
// tool) pair is one map entry reclaimed only on periodic Cleanup, so an uncapped map could
// OOM. A call under a new key past the ceiling fails closed for maxCalls, fail-open for
// sequenceBlock; see the threat model's "In-memory store footprint" note.
const defaultMaxCallCounterKeys = 1_000_000

// defaultMaxSessions caps concurrent client sessions for the HTTP transport: each session
// owns one upstream, so an uncapped listener lets an unauthenticated client fork-bomb the
// proxy. Tune via listen.maxSessions / --max-sessions, or 0 for uncapped.
const defaultMaxSessions = 512

// proxyCLIFlags holds the parsed `proxy` subcommand flags. registerProxyFlags
// binds them to a FlagSet; cmdProxy reads them after fs.Parse.
type proxyCLIFlags struct {
	configPath           *string
	audit                *bool
	wiretapURL           *string
	wiretapAuthHeader    *string
	wiretapTLSSkipVerify *bool
	wiretapProtocolVer   *string
	unsafeBindAll        *bool
	trustFwdFor          *bool
	auditLog             *string
	auditKeyPath         *string
	auditPEP             *string
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

// auditRequirement is the --require-audit value — a three-state knob over how missing
// audit coverage is handled: strict (default: sink-open failure fatal, plus a runtime
// fail-closed gate once the audit trail degrades), on (fatal at startup only), or off
// (warns and continues unaudited). Implements flag.Value with IsBoolFlag so a bare
// --require-audit selects "strict".
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
		audit:                fs.Bool("audit", false, "Zero-config wiretap mode: bridge stdin/stdout to the upstream named after `--`\n(or to --upstream-url). Enforced-method calls (tools/call, resources/read,\nresources/subscribe, resources/unsubscribe, prompts/get, sampling/createMessage) are forwarded and recorded without applying policy.\n…/list calls forward the full upstream catalog unfiltered (no policy is applied) and\nare recorded as enumeration events. POLICY blocks nothing; three things still refuse:\nthe kill switch, a method eunox cannot dispatch under the revision the host\nnegotiated (UNROUTABLE_METHOD, marked details."+audit.UnroutableKey+"), and a\nmessage whose revision cannot be established (UNSUPPORTED_PROTOCOL_VERSION).\nRecorded tool-call arguments may contain secrets; treat the audit log as sensitive.\nMutually exclusive with --config."),
		wiretapURL:           fs.String("upstream-url", "", "HTTP upstream URL for --audit mode (alternative to a `--` subprocess)."),
		wiretapAuthHeader:    fs.String("upstream-auth-header", "", `HTTP upstream auth header for --audit mode, "Name: Value".`),
		wiretapTLSSkipVerify: fs.Bool("upstream-tls-skip-verify", false, "Skip TLS verification for --audit --upstream-url (development only)."),
		wiretapProtocolVer:   fs.String("upstream-protocol-version", "", "Pin the MCP protocol revision eunox speaks to the --audit upstream, which selects\nhow the leg is opened: \"auto\" (the default) opens with the `initialize` handshake,\nor name a revision. The config-file equivalent is an upstream's `protocolVersion`\nkey; under --config the pin comes from there, so this flag applies only to --audit\nwiretap mode."),

		// Operational flags layered over the config.
		unsafeBindAll:      fs.Bool("unsafe-bind-all", false, "Allow binding to all interfaces (transport: http only)."),
		trustFwdFor:        fs.Bool("trust-forwarded-for", false, "Trust X-Forwarded-For header for source IP. Only use when a trusted reverse proxy always sets this header; direct clients can spoof it."),
		auditLog:           fs.String("audit-log", "", "Path to the OCSF audit JSONL file (default: ~/.eunox/audit.jsonl). Overridden by the config's audit.log."),
		auditKeyPath:       fs.String("audit-key-path", "", "Path to the HMAC signing key for the audit log (default: ~/.eunox/audit.key).\nOverrides EUNOX_AUDIT_KEY_PATH. Overridden by the config's audit.keyPath."),
		auditPEP:           fs.String("audit-pep", "", "Name this enforcement point on every audit record ('pep', stamped as\n\"mcp:<name>\"), so a sequence that crosses more than one eunox instance can be\nattributed once their tapes are read together. Names may use letters, digits,\n'.', '_' and '-'. Unset stamps nothing, which is what a single-enforcement-point\ndeployment wants. Overridden by the config's audit.pep."),
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
		killswitchReconcile:  fs.Duration("killswitch-reconcile-interval", 0, fmt.Sprintf("How often the Redis kill switch reconciles its local cache against Redis\n(default %s). Lower values shorten the kill-propagation window and, in the\ndefault fail-closed mode, the data-plane denial window that persists after a\ntransient Redis blip recovers -- recovery is bounded by this interval, not Redis.\nVery low values increase Redis load. 0 uses the default. Only affects --redis-addr.", killswitch.DefaultReconcileInterval)),
		killswitchSessionTTL: fs.Duration("killswitch-session-ttl", 0, fmt.Sprintf("How long a SESSION kill tombstone lives in Redis before it is garbage\ncollected (default %s). This is a memory bound, not a policy\nexpiry: when the tombstone expires the kill is LIFTED, so a value shorter\nthan the longest session your deployment holds open re-admits a revoked\nsession. Relevant when a stdio agent pins and reuses one --session-id for\nmonths. Negative disables expiry entirely; 0 uses the default. Agent kills\nare never expired. Only affects --redis-addr.", describeDefaultSessionKillTTL())),
		maxCallCounterKeys:   fs.Int("max-call-counter-keys", defaultMaxCallCounterKeys, "Maximum distinct keys the in-memory maxCalls/sequenceBlock counter holds at once.\nEach live (session, tool) pair is one key, reclaimed only on the periodic cleanup;\nthis ceiling bounds the heap a flood of unique session IDs can pin between cleanups\n(a call under a new key past the limit fails closed). The same bound also caps the\nin-memory flow-label store's distinct ANCHORS — one key per session, or under\ntaskAnchoredState one per TASK, which OUTLIVES the session that created it. Both\nstores reclaim an idle anchor on a periodic sweep, so the ceiling bounds LIVE\nanchors; a warning is logged as it is approached. 0 disables the bound. Ignored when --redis-addr is\nset (Redis keeps this state off the Go heap, with TTLs)."),

		// Compliance flags.
		strictDrift: fs.Bool("strict-drift", false, "Promote startup drift warnings to fatal errors that abort session startup: a new\nupstream tool matched by a manifest glob, a manifest entry that matches no live\ntool, or an upstream version that does not satisfy the manifest's serverVersion\npin. (A condition argument absent from the live schema and the uncovered-tool\nINFO stay advisory, never fatal.) A launch-time global override: applies to every\npoliced route, regardless of a per-route 'strictDrift' in the config. Routes with\nno policy are unaffected; the proxy warns if the flag matched no policed route\n(e.g. with --audit)."),
	}
	f.requireAudit = requireAudit
	return f
}

// printProxyUsage writes the `proxy` subcommand help text.
func printProxyUsage(fs *flag.FlagSet, w io.Writer) {
	_, _ = fmt.Fprint(w, `Usage:
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
the upstream you point it at, in audit (observe) mode — every request eunox can
route is forwarded and its verdict recorded, and policy blocks nothing. Observe
mode downgrades a policy VERDICT, so three refusals stand, none of which has one:
the kill switch; a method eunox cannot dispatch under the MCP revision your host
negotiated (UNROUTABLE_METHOD, whose record carries details.`+audit.UnroutableKey+` naming
which of the three ways it was unroutable); and a message whose revision cannot be established
(UNSUPPORTED_PROTOCOL_VERSION). Point your MCP host (Claude Desktop, Cursor, …)
at this command and inspect the audit tape with 'eunox stats' to see what an
enforcement allowlist would need.

Run 'eunox init --upstream-url <url>' to scaffold a starter config + manifest.

Exit codes:
  0  The proxy served and shut down cleanly (SIGINT/SIGTERM, or the host closed
     the stdio session). -h also exits 0.
  1  The proxy did not serve: an incoherent flag combination, an out-of-range
     flag value, a config or manifest that would not load, a subsystem that
     would not come up, or a fatal error while serving.
  2  The command line did not PARSE — an unknown flag, or a value the flag
     package itself rejects. Narrower than the sibling subcommands' 2: the
     flag-combination and flag-value errors they classify as usage errors are
     reported here as 1, so on this command 2 means "the command line did not
     parse" and 1 means "it parsed, and the proxy refused to start".

Flags:
`)
	fs.SetOutput(w)
	fs.PrintDefaults()
}

// resolveProxyConfig determines cmdProxy's GatewayConfig from the audit/config mode switch:
// --audit builds a zero-config wiretap upstream, --config loads the gateway config, and
// neither is a usage error. Extracted from cmdProxy to keep the latter's own branch count
// under the complexity threshold; every returned error is plain (no "eunox proxy: " prefix
// or trailing newline) so the one call site can wrap it identically regardless of which
// branch produced it.
func resolveProxyConfig(fs *flag.FlagSet, f *proxyCLIFlags) (*config.GatewayConfig, error) {
	switch {
	case *f.audit:
		cfg, err := buildAuditWiretapConfig(fs.Args(), *f.wiretapURL, *f.wiretapAuthHeader, *f.wiretapTLSSkipVerify, *f.wiretapProtocolVer)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(os.Stderr, "[eunox] WIRETAP MODE: audit-only, no policy — enforced-method calls are forwarded and recorded (…/list calls forwarded unfiltered and recorded as enumeration events). Use 'eunox stats' to inspect the tape.\n")
		// Named rather than left to be discovered on the tape: observe mode downgrades POLICY
		// verdicts, and a message eunox cannot route has no verdict to downgrade.
		fmt.Fprintf(os.Stderr, "[eunox] WIRETAP MODE: policy blocks nothing, but three refusals stand — the kill switch, a method absent from the revision your host negotiated (UNROUTABLE_METHOD, marked details.%s), and a revision that cannot be established (UNSUPPORTED_PROTOCOL_VERSION).\n", audit.UnroutableKey)
		return cfg, nil
	case *f.configPath != "":
		// The upstream command comes from the config in this mode; a trailing
		// "-- <command>" would be silently dropped, so reject stray positionals rather
		// than let the operator believe they took effect.
		if fs.NArg() > 0 {
			return nil, fmt.Errorf("unexpected argument %q (--config takes the upstream from the config file; positional commands are only for --audit mode)", fs.Arg(0))
		}
		// The wiretap-only upstream flags describe the --audit upstream; under --config the
		// upstream (and its auth/TLS posture) comes from the file, so these would be
		// silently dropped. Reject them for the same reason as a stray positional.
		if *f.wiretapURL != "" || *f.wiretapAuthHeader != "" || *f.wiretapTLSSkipVerify || *f.wiretapProtocolVer != "" {
			return nil, errors.New("--upstream-url/--upstream-auth-header/--upstream-tls-skip-verify/--upstream-protocol-version apply only to --audit wiretap mode; under --config the upstream, its auth/TLS posture, and its protocolVersion pin come from the config file")
		}
		return config.LoadGatewayConfig(*f.configPath)
	default:
		//nolint:staticcheck // ST1005: this is printed as a multi-line usage block, not a short sentence-case error
		return nil, errors.New("one of --config <file> or --audit is required.\n\n  --config <eunox.yaml>           policy enforcement (or audit posture) declared in a file\n  --audit -- <command> [args...]  zero-config wiretap: forward what it can route, log everything\n\nRun 'eunox init --upstream-url <url>' to scaffold a starter config + manifest.")
	}
}

// cmdProxy runs the `proxy` subcommand, returning the exit code (rather than calling
// os.Exit) so tests can drive every branch including the fail-closed startup rejections.
// The return value is NAMED so the deferred audit-sink Close can fail the command: a Close
// error means buffered records may not have reached disk, the failure an audit tool exists
// to prevent.
func cmdProxy(args []string) (exitCode int) {
	// ContinueOnError, like every sibling subcommand: ExitOnError would terminate the
	// process inside Parse, reintroducing the untestable exit this function avoids.
	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	fs.Usage = func() { printProxyUsage(fs, usageWriter(args)) }

	f := registerProxyFlags(fs)

	// Parse the args run() threaded down, NOT the os.Args global — under ContinueOnError a
	// forgotten slice would quietly parse the surrounding binary's own flags instead.
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		// 2 for a usage error, matching validate's convention: distinguishable from a
		// startup rejection (1).
		return 2
	}

	if *f.configPath != "" && *f.audit {
		fmt.Fprintf(os.Stderr, "eunox proxy: --audit and --config are mutually exclusive (--audit is for the zero-config wiretap path; --config carries its own enforcement posture).\n")
		return 1
	}

	// Matching the config validator (gateway_config.go); extracted so each guard is
	// independently unit-testable.
	if err := validateProxyNumericFlags(f); err != nil {
		fmt.Fprintf(os.Stderr, "eunox proxy: %v\n", err)
		return 1
	}
	// Here rather than at the sink, where the name is CONSTRUCTED: every check between the
	// parse and the first side effect exists so a trivially-fixable flag typo cannot cost a
	// Redis dial or mint an audit key and log on its way to dying. The config's own audit.pep
	// is validated at load, so this covers the flag.
	if err := validateProxyAuditPEPFlag(f); err != nil {
		fmt.Fprintf(os.Stderr, "eunox proxy: %v\n", err)
		return 1
	}
	cfg, err := resolveProxyConfig(fs, f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "eunox proxy: %v\n", err)
		return 1
	}

	sessionIDSet := flagWasSet(fs, "session-id")
	if sessionIDSet && *f.sessionID == "" {
		// An explicitly-empty value (e.g. a unit file pinning --session-id "$SID" for a
		// later `eunox kill "$SID"` where $SID turned out unset) must not silently fall
		// through to a random UUID: resolveKillTarget refuses the identical mistake on the
		// kill side, and both killswitch backends reject empty ids outright. Minting a
		// fresh id here instead would make the pinned emergency kill match nothing.
		fmt.Fprintf(os.Stderr, "eunox proxy: --session-id was passed but empty; unset the flag entirely for a random UUID, or pass a non-empty id\n")
		return 1
	}
	sid := *f.sessionID
	if sid == "" {
		sid = uuid.New().String()
	}

	// Precomputed generically over jwksGatedFlags so the fail-closed guard below reads one
	// list rather than re-enumerating each flag.
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
		sessionIDSet:         sessionIDSet,
		configPath:           *f.configPath,
		strictDrift:          *f.strictDrift,
		requireAuditStrict:   f.requireAudit.strict(),
		maxSessions:          *f.maxSessions,
		sessionIdleTimeoutMs: *f.sessionIdleTimeout,
		redisConfigured:      *f.redisAddr != "",
		auditPEP:             *f.auditPEP,
		controlTokenPath:     *f.controlTokenPath,
		httpOnlyFlagsSet:     httpOnlyFlagsSetOnStdio(fs),
	}

	// Fail closed if any JWT flag was supplied without --jwks-uri, so a forgotten flag
	// cannot leave the gateway serving unauthenticated. Checked before
	// buildCallCounterAndKillSwitch/openConfiguredAuditSink, which have real side effects
	// (a Redis dial, minting an audit key/log), so a trivially-fixable flag error is
	// reported before anything is touched.
	if err := validateJWTFlagsRequireJWKS(pf); err != nil {
		fmt.Fprintf(os.Stderr, "[eunox] Fatal: %v\n", err)
		return 1
	}

	// Reject a flag that cannot take effect under the configured host transport, before
	// the first side effect — these checks used to sit inside the serve functions, firing
	// only after the Redis dial and audit key/log creation had already happened.
	if err := validateTransportConditionalFlags(cfg.HostTransport(), pf); err != nil {
		fmt.Fprintf(os.Stderr, "[eunox] Fatal: %v\n", err)
		return 1
	}

	// The rest of the PURE JWT checks, for the same reason: they used to run inside
	// gatewayJWTLayer, which is reached only after the Redis dial and the audit key/log
	// have been minted. Below the transport gate deliberately — a flag that cannot take
	// effect on this transport at all should be reported as that, not critiqued for its
	// combination with flags that equally cannot take effect.
	if err := validateJWTFlagCombinations(pf); err != nil {
		fmt.Fprintf(os.Stderr, "[eunox] Fatal: %v\n", err)
		return 1
	}

	// Fail closed if a Redis-only flag was set without --redis-addr, before any side effect
	// runs — same reasoning as the JWT guard above.
	if err := validateRedisFlagsRequireRedisAddr(fs, *f.redisAddr); err != nil {
		fmt.Fprintf(os.Stderr, "[eunox] Fatal: %v\n", err)
		return 1
	}

	// Build call counter and kill-switch manager, shared across routes and the
	// kill-switch endpoint. Backed by Redis when --redis-addr is set.
	backends, err := buildCallCounterAndKillSwitch(*f.redisAddr, resolveRedisPassword(*f.redisPassword), *f.redisTLS, *f.killswitchFailOpen, *f.killswitchReconcile, *f.killswitchSessionTTL, *f.maxCallCounterKeys, anyRouteTaskAnchored(cfg))
	if err != nil {
		fmt.Fprintf(os.Stderr, "eunox proxy: %v\n", err)
		return 1
	}
	counter, flowStore, ks, ksRedis := backends.counter, backends.flowStore, backends.killSwitch, backends.ksRedis
	if rdb := backends.redis; rdb != nil {
		// Registered before the audit sink's defer so it runs AFTER that flush: the sink's
		// close must not race a pool teardown the kill switch could still be reading through.
		defer func() { _ = rdb.Close() }()
	}

	// Open the shared audit sink. The config's audit block takes precedence over
	// the CLI flags so every route shares one tape.
	sink, err := openConfiguredAuditSink(*f.auditLog, *f.auditKeyPath, *f.auditPEP, *f.auditRotateSize, *f.auditRetainRotated, flagWasSet(fs, "audit-retain"), cfg, f.requireAudit.required())
	if err != nil {
		fmt.Fprintf(os.Stderr, "[eunox] Fatal: %v\n", err)
		return 1
	}
	if sink != nil {
		defer func() {
			// Registered last among the defers here, so it flushes after the kill switch
			// has stopped.
			if err := sink.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "[eunox] Fatal: audit sink close failed; the audit trail may be incomplete: %v\n", err)
				// Only ever UPGRADE from success; must not overwrite a more specific
				// non-zero code (e.g. 2 for a usage error) the function already chose.
				if exitCode == 0 {
					exitCode = 1
				}
			}
		}()
	}

	ctx, cancel := context.WithCancel(context.Background())
	// Both teardowns are deferred rather than left to the signal goroutine below, which
	// only runs on an actual signal: cmdProxy RETURNS rather than calling os.Exit, so an
	// in-process caller would otherwise leak the ctx-bound cleanup goroutine and keep the
	// OS default signal disposition disabled once Notify has diverted it.
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	// Releases the relay goroutine on a signal-LESS return; without it every in-process
	// cmdProxy call leaks one goroutine for the process's life.
	stopSigWatch := make(chan struct{})
	defer close(stopSigWatch)
	go func() {
		select {
		case <-sigCh:
		case <-stopSigWatch:
			return
		}
		cancel()
		// Stop relaying after the first signal triggers shutdown: this goroutine only
		// ever reads once, so a second signal would otherwise be silently swallowed in
		// the channel's one buffer slot. Un-registering reverts to the OS default
		// (immediate termination) — the operator's forced-kill escape hatch.
		signal.Stop(sigCh)
	}()

	// Published by the ready hook once the transport is actually standing (after the bind
	// for the gateway, after the drift check for stdio) — NOT here — so a process that dies
	// on the way up cannot overwrite a running proxy's advertised lifetime with one nothing
	// enforces (the same clobber-then-die bug already fixed once for the control-token file).
	onServeReady := func(context.Context) {}
	if ksRedis != nil {
		onServeReady = func(ctx context.Context) { publishSessionKillTTL(ctx, ksRedis) }
		ksRedis.Start(ctx)
		// Join the pub/sub listener and reconcile loop on shutdown, or they outlive
		// cmdProxy. Registered after Start so (LIFO) it runs before earlier defers.
		defer ksRedis.Stop()
	}
	startInMemorySweeps(ctx, counter, flowStore)

	var serveErr error
	switch cfg.HostTransport() {
	case config.HostTransportStdio:
		serveErr = serveStdioHost(ctx, cfg, sink, counter, flowStore, ks, pf, onServeReady)
	default: // config.HostTransportHTTP
		serveErr = serveHTTPGateway(ctx, cfg, sink, counter, flowStore, ks, pf, onServeReady)
	}
	if serveErr != nil {
		fmt.Fprintf(os.Stderr, "[eunox] Fatal: %v\n", serveErr)
		return 1
	}
	return 0
}

// resolveRedisPassword returns the Redis AUTH password with flag > env precedence. A
// password passed via argv is world-readable in /proc/<pid>/cmdline, so the
// EUNOX_REDIS_PASSWORD fallback lets an operator keep it off the command line.
func resolveRedisPassword(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	return os.Getenv("EUNOX_REDIS_PASSWORD")
}

// buildCallCounterAndKillSwitch builds the shared call counter, flow-label store, and
// kill-switch manager, Redis-backed when redisAddr is set and in-memory otherwise. ksRedis
// is non-nil only in the Redis case, so cmdProxy can start its reconcile loop. The
// *goredis.Client is returned too (nil without --redis-addr) so the caller can release the
// connection pool on EVERY exit path, not only the ping-failure branch. A Redis config or
// connectivity error is returned rather than exited on, so the failure path is testable.
// upstreamBackends bundles the shared decision state. A struct rather than a six-value
// return list: two of those values encoded the same bit (ksRedis/redis both non-nil
// exactly when --redis-addr is set), so a reader could not tell which was authoritative.
type upstreamBackends struct {
	counter    capability.CallCounter
	flowStore  capability.FlowLabelStore
	killSwitch killswitch.Manager
	// ksRedis is the Redis kill switch, non-nil only with --redis-addr.
	ksRedis *killswitch.Redis
	// redis is the shared connection pool behind counter/flowStore/ksRedis, non-nil only
	// with --redis-addr. The CALLER owns closing it on every return path.
	redis *goredis.Client
}

func buildCallCounterAndKillSwitch(redisAddr, redisPassword string, redisTLS, killswitchFailOpen bool, killswitchReconcile, killswitchSessionTTL time.Duration, maxCallCounterKeys int, taskAnchored bool) (upstreamBackends, error) {
	// One stderr logger for every backend that takes one, rather than the same expression
	// written out per call site: where these lines go (level, format, destination) is one
	// operator-facing decision.
	stderrLog := slog.New(slog.NewTextHandler(os.Stderr, nil))
	var (
		counter   capability.CallCounter
		flowStore capability.FlowLabelStore
		ks        killswitch.Manager
		ksRedis   *killswitch.Redis // non-nil when --redis-addr is set
		rdb       *goredis.Client
	)
	if redisAddr == "" {
		counter = callcounter.NewInMemory(callcounter.WithMaxKeys(maxCallCounterKeys))
		// WithMaxKeys is the flow store's fail-closed admission ceiling. The idle bound is
		// enabled ONLY under task anchoring: a session-anchored key already reclaims via
		// teardown, but a task-anchored key has no teardown owner (reclaiming on disconnect
		// would let an agent launder a task's taint by reconnecting), so idle expiry is the
		// only safe reclamation it can have.
		flowStore = flowlabelstore.NewInMemory(
			append(flowStoreOptions(taskAnchored),
				flowlabelstore.WithMaxKeys(maxCallCounterKeys),
				flowlabelstore.WithLogger(stderrLog))...)
		ks = killswitch.NewInMemory()
	} else {
		var err error
		rdb, err = buildRedisClient(redisAddr, redisPassword, redisTLS)
		if err != nil {
			return upstreamBackends{}, fmt.Errorf("Redis configuration error: %w", err) //nolint:staticcheck // ST1005: "Redis" is a proper noun, not a capitalized sentence
		}
		if err := pingRedis(context.Background(), rdb); err != nil {
			// Close before abandoning: buildRedisClient hands back a live connection pool
			// with its own goroutines, which an in-process caller would otherwise accumulate.
			_ = rdb.Close()
			return upstreamBackends{}, err
		}
		fmt.Fprintf(os.Stderr, "[eunox] Redis backend enabled (%s). State persists across restarts.\n", redisAddr)
		// Refuses a keyspace-sharding client (see callcounter.ErrClusterUnsupported). Close
		// the pool first, as the ping failure above does: this returns before anything else
		// takes ownership of it.
		counter, err = callcounter.NewRedis(rdb)
		if err != nil {
			_ = rdb.Close()
			return upstreamBackends{}, err
		}
		// Share the same client so a flow policy gets the same multi-instance parity as
		// the counter, and reclaims an orphaned session's set by idle TTL if Clear never lands.
		flowStore = flowlabelstore.NewRedis(rdb)
		// WithLogger: the kill switch's degraded-mode breadcrumbs are gated on a non-nil
		// logger, so without this an operator watching for a Redis partition sees nothing.
		ksRedis = killswitch.NewRedis(rdb,
			killswitch.WithFailOpen(killswitchFailOpen),
			killswitch.WithReconcileInterval(killswitchReconcile),
			// Wired to a flag rather than hardwired: expiry LIFTS the kill, and a deployment
			// pinning one --session-id can outlive the default, re-admitting a revoked session.
			killswitch.WithSessionKillTTL(killswitchSessionTTL),
			killswitch.WithLogger(stderrLog))
		ks = ksRedis
		if killswitchFailOpen {
			fmt.Fprintf(os.Stderr, "[eunox] Kill switch: fail-OPEN during a Redis outage (--killswitch-fail-open). Kills issued while Redis is unreachable may be delayed until it recovers; the data plane stays available.\n")
		} else {
			fmt.Fprintf(os.Stderr, "[eunox] Kill switch: fail-CLOSED during a Redis outage (default). While Redis is unreachable every request is denied (KILL_SWITCH_ERROR) until health is reconfirmed; pass --killswitch-fail-open to prioritise availability. Watch HealthStatus on /healthz and /metrics.\n")
		}
		if killswitchReconcile > 0 {
			fmt.Fprintf(os.Stderr, "[eunox] Kill switch: reconcile interval %s (--killswitch-reconcile-interval); bounds kill-propagation and fail-closed post-recovery denial windows.\n", killswitchReconcile)
		}
		// Stated unconditionally, including the default: the one kill-switch setting whose
		// expiry LIFTS a revocation, so an operator needs to see the number unprompted.
		fmt.Fprintf(os.Stderr, "[eunox] Kill switch: %s (--killswitch-session-ttl). Agent kills never expire.\n", sessionKillTTLNotice(killswitchSessionTTL))
		// Published later, from cmdProxy, once startup is past every step that can fail.
	}
	return upstreamBackends{counter: counter, flowStore: flowStore, killSwitch: ks, ksRedis: ksRedis, redis: rdb}, nil
}

// flowStoreOptions returns the anchor-lifetime options for the in-memory flow store: an
// idle bound under task anchoring, none otherwise. See the call site for why.
func flowStoreOptions(taskAnchored bool) []flowlabelstore.InMemoryOption {
	if !taskAnchored {
		return nil
	}
	return []flowlabelstore.InMemoryOption{flowlabelstore.WithMemoryIdleTTL(flowlabelstore.DefaultIdleTTL)}
}

// startInMemorySweeps arms the background reclamation for whichever in-process backends are
// in use; a no-op for the Redis ones (TTL server-side). The flow store's sweep matters most:
// lazy expiry never runs for an abandoned task nothing accesses again, so without the sweep
// the map holds every such task until it hits the admission ceiling and every flow-relevant
// call fails closed.
func startInMemorySweeps(ctx context.Context, counter capability.CallCounter, flowStore capability.FlowLabelStore) {
	if mem, ok := counter.(*callcounter.InMemory); ok {
		mem.StartCleanup(ctx, callcounter.DefaultCleanupInterval)
	}
	if mem, ok := flowStore.(*flowlabelstore.InMemory); ok {
		mem.StartCleanup(ctx, flowlabelstore.DefaultCleanupInterval)
	}
}

// publishSessionKillTTL advertises the effective session-tombstone lifetime on shared Redis
// so `eunox kill --redis-addr` writes tombstones with the SAME lifetime; as two independent
// flags they could otherwise disagree, silently re-admitting a revoked session. Advisory —
// a failure warns rather than aborts startup. Bounded by parent (the ready hook's context,
// not a detached one) so an abandoned hook's write cannot land after the proxy has died.
func publishSessionKillTTL(parent context.Context, ksRedis *killswitch.Redis) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
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

// describeDefaultSessionKillTTL renders the DEFAULT session-kill tombstone lifetime for the
// two --killswitch-session-ttl help strings, through the same renderer every other TTL
// message in this binary uses, so the prose they replace cannot come back as a second
// spelling to keep in step by hand. The "/ N days" gloss is added only when the default IS
// a whole number of days: a truncating count would render 36h as "1 days" and 12h as
// "0 days", relocating the drift rather than removing it.
func describeDefaultSessionKillTTL() string {
	d := killswitch.DefaultSessionKillTTL
	rendered := killswitch.DescribeSessionKillTTL(d)
	if d > 0 && d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%s / %d days", rendered, d/(24*time.Hour))
	}
	return rendered
}

// sessionKillTTLNotice renders the startup line describing how long a session-kill
// tombstone survives, resolved through the same normalizer the option applies so the
// banner cannot claim one lifetime while Redis enforces another.
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
	return fmt.Sprintf("session kills expire after %s%s; a session held open longer than that is re-admitted",
		killswitch.DescribeSessionKillTTL(effective), suffix)
}

// warnAuditFlagOverridden prints the shared "config wins over an explicit --audit-* flag"
// warning for `proxy`, where the audit block always takes precedence so every route
// shares one tape. flagRepr/cfgRepr are the already-formatted (%q for strings, %d for
// ints) values, since the four callers' fields differ in type.
func warnAuditFlagOverridden(flagName, flagRepr, cfgField, cfgRepr string) {
	fmt.Fprintf(os.Stderr, "[eunox] WARNING: %s %s is overridden by the config's %s %s; the config's audit block always takes precedence for `proxy` so every route shares one tape.\n", flagName, flagRepr, cfgField, cfgRepr)
}

// resolveAuditPEP applies the audit block's precedence to the enforcement-point name alone,
// without opening anything.
//
// Split out of openConfiguredAuditSink because two other callers need the resolved value and
// neither may open a sink to get it: the task-anchoring advisory, which fires per serve
// path, and its stdio twin. Pure selection, so calling it three times costs nothing and the
// three cannot disagree about which name this instance runs under.
func resolveAuditPEP(auditPEP string, cfg *config.GatewayConfig) string {
	if cfg.Audit.PEP != "" {
		return cfg.Audit.PEP
	}
	return auditPEP
}

// openConfiguredAuditSink resolves the audit-sink settings (config's audit block takes
// precedence over the CLI flags so every route shares one tape) and opens the sink. Under
// --require-audit an open failure is returned as an error to exit on (fail closed);
// otherwise it warns and returns a nil sink with a nil error.
func openConfiguredAuditSink(auditLog, auditKeyPath, auditPEP string, auditRotateSize int64, auditRetainRotated int, auditRetainSet bool, cfg *config.GatewayConfig, requireAudit bool) (*audit.Sink, error) {
	auditLogPath, auditKey, auditRotate := auditLog, auditKeyPath, auditRotateSize
	auditRetain := auditRetainRotated
	// The config's audit block takes precedence over an explicit flag here (unlike the
	// reader subcommands, which leave an explicit flag untouched) since every route must
	// share one tape — but warn, since a silently-overridden flag is easy to miss.
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
	// Warn on a silently-overridden explicit flag here too, same rule as above.
	if cfg.Audit.RotateSizeBytes > 0 {
		// 0 is this flag's "use the built-in default" spelling, so a non-zero value is an
		// explicit one (same test the string flags use against "").
		if auditRotateSize > 0 && auditRotateSize != cfg.Audit.RotateSizeBytes {
			warnAuditFlagOverridden("--audit-rotate-size", fmt.Sprintf("%d", auditRotateSize), "audit.rotateSizeBytes", fmt.Sprintf("%d", cfg.Audit.RotateSizeBytes))
		}
		auditRotate = cfg.Audit.RotateSizeBytes
	}
	// A present config value wins, including an explicit 0 ("keep all"), via
	// config.ResolveInt (shared with maxSessions/sessionIdleTimeout). Explicitness comes
	// from auditRetainSet, not a non-zero value, since 0 is meaningful here too.
	if cfg.Audit.RetainRotated != nil && auditRetainSet && *cfg.Audit.RetainRotated != auditRetain {
		warnAuditFlagOverridden("--audit-retain", fmt.Sprintf("%d", auditRetain), "audit.retainRotated", fmt.Sprintf("%d", *cfg.Audit.RetainRotated))
	}
	auditRetain = config.ResolveInt(cfg.Audit.RetainRotated, auditRetain)
	// Same precedence, same warning as the four above.
	if cfg.Audit.PEP != "" && auditPEP != "" && auditPEP != cfg.Audit.PEP {
		warnAuditFlagOverridden("--audit-pep", fmt.Sprintf("%q", auditPEP), "audit.pep", fmt.Sprintf("%q", cfg.Audit.PEP))
	}
	opts := []audit.Option{audit.WithIdentity(auditIdentity)}
	if resolved := resolveAuditPEP(auditPEP, cfg); resolved != "" {
		// The construction site's own guard, and the reason a stamp is only ever minted by
		// the validating constructor. Both inputs are already checked before any side effect
		// runs — the config's at load, the flag's by validateProxyAuditPEPFlag — so this is
		// unreachable in production rather than the operator's diagnostic. It is refused
		// unconditionally, not folded into the --require-audit stance below, because that
		// stance decides what to do about a tape that cannot be OPENED.
		ep, err := capability.NewEnforcementPoint(resolved)
		if err != nil {
			return nil, fmt.Errorf("audit enforcement-point name: %w", err)
		}
		opts = append(opts, audit.WithEnforcementPoint(ep))
	}
	sink, err := audit.Open(auditLogPath, auditKey, auditRotate, auditRetain, opts...)
	if err != nil {
		if requireAudit {
			return nil, fmt.Errorf("audit sink could not be opened and --require-audit is not 'off' (it defaults to 'strict'); set a writable audit path or pass --require-audit=off to run unaudited: %w", err)
		}
		fmt.Fprintf(os.Stderr, "[eunox] Warning: could not open audit log: %v\n", err)
		return nil, nil
	}
	return sink, nil
}

// buildAuditWiretapConfig synthesizes a zero-config `transport: stdio` gateway in audit
// (observe) mode from the operator's --audit arguments. Exactly one upstream is configured
// (subprocess or --upstream-url); no manifest is referenced. Used by `proxy --audit`.
func buildAuditWiretapConfig(positional []string, upstreamURL, authHeader string, tlsSkipVerify bool, protocolVersion string) (*config.GatewayConfig, error) {
	if len(positional) > 0 && upstreamURL != "" {
		return nil, fmt.Errorf("--audit: pick exactly one upstream — positional `-- <command>` OR --upstream-url, not both")
	}
	// Reject a whitespace-only credential HERE, as an operator flag error, rather than let
	// Validate's own guard report it as "internal: synthesized wiretap config rejected" —
	// the marker reserved for "the binary built something invalid".
	if authHeader != "" && strings.TrimSpace(authHeader) == "" {
		return nil, fmt.Errorf("--upstream-auth-header is whitespace-only, which is not a usable credential — pass a real header value, or omit the flag to forward no auth header")
	}
	cfg := &config.GatewayConfig{
		SchemaVersion: "0.1",
		Transport:     config.HostTransportStdio,
	}
	cfg.Defaults.Enforcement = capability.EnforcementAudit
	// Validate rejects a revision this build cannot speak, so an unusable pin fails here as
	// an operator flag error rather than being reported as "the binary built something invalid".
	if err := config.ValidateProtocolVersionFlag(protocolVersion); err != nil {
		return nil, err
	}
	u := config.UpstreamConfig{Name: "wiretap", ProtocolVersion: protocolVersion}
	switch {
	case len(positional) > 0:
		// A positional subprocess upstream has neither auth header nor TLS posture, so
		// reject rather than let the operator believe either took effect.
		if authHeader != "" || tlsSkipVerify {
			return nil, fmt.Errorf("--audit: --upstream-auth-header/--upstream-tls-skip-verify apply only to a remote --upstream-url upstream, not a positional `-- <command>` subprocess")
		}
		// The pin used to be refused here, because it reached no wire behavior on a
		// subprocess: every leg was opened with `initialize` whatever it said, and its only
		// effect was the version header a subprocess never sees. It now selects the OPENER,
		// which a subprocess upstream reads exactly as a remote one does — so the flag does
		// something on this transport and refusing it would deny the operator the control.
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

// flagWasSet reports whether the named flag was passed explicitly (flag.Visit visits only
// flags that were set), for flags whose default cannot distinguish "explicitly set to the
// default" from "unset" (e.g. --jwt-leeway).
func flagWasSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

// jwksGatedFlags is the single authoritative list of flag names that require --jwks-uri.
// validateJWTFlagsRequireJWKS is the one guard that reads it, so a second parallel guard
// cannot drift out of sync.
var jwksGatedFlags = []string{
	"jwt-issuer",
	"jwt-audience",
	"jwt-allow-any-audience",
	"jwt-allow-any-issuer",
	"jwks-allow-insecure-http",
	"jwt-experimental-capabilities",
	"jwt-leeway",
}

// flagDefaultIsZero reports whether a flag's default is its type's zero value, comparing
// DefValue against the stdlib zero renderings (string/int/bool/duration). A zero-default
// flag can be detected by VALUE; a non-zero-default flag needs explicit-set detection
// instead, since value alone can't distinguish a chosen default from unset.
func flagDefaultIsZero(f *flag.Flag) bool {
	switch f.DefValue {
	case "", "0", "false", "0s":
		return true
	default:
		return false
	}
}

// gatedFlagsSetWithoutJWKS returns the "--"-prefixed names of every jwks-gated flag the
// operator activated, driving both detection halves off jwksGatedFlags so a newly gated
// flag is covered automatically. A pure function of the parsed FlagSet for testability.
func gatedFlagsSetWithoutJWKS(fs *flag.FlagSet) []string {
	return explicitlyActiveFlags(fs, jwksGatedFlags)
}

// explicitlyActiveFlags returns the "--"-prefixed names of every flag in names that the
// operator activated: value detection for a zero-default flag, explicit-set for a
// non-zero-default one (see flagDefaultIsZero). Shared by gatedFlagsSetWithoutJWKS and
// httpOnlyFlagsSetOnStdio so the two detection halves cannot drift apart.
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

// httpOnlyProxyFlags is the single authoritative list of flag names that apply only to
// transport: http; serveStdioHost's rejection guard reads it so a future HTTP-only flag is
// covered automatically instead of silently no-oping on a stdio host.
var httpOnlyProxyFlags = []string{
	"control-token-path",
	"session-idle-timeout",
	"max-sessions",
	"unsafe-bind-all",
	"trust-forwarded-for",
}

// httpOnlyFlagsSetOnStdio returns the "--"-prefixed names of every
// httpOnlyProxyFlags flag the operator activated, for the transport-conditional
// rejection guard.
func httpOnlyFlagsSetOnStdio(fs *flag.FlagSet) []string {
	return explicitlyActiveFlags(fs, httpOnlyProxyFlags)
}

// validateTransportConditionalFlags rejects flags that cannot take effect under the
// configured host transport — each would otherwise silently no-op, letting an operator
// believe a security-relevant setting took effect. Runs from cmdProxy the moment the
// transport is known, before the Redis dial and audit key/log creation.
func validateTransportConditionalFlags(hostTransport string, pf proxyFlags) error { //nolint:gocritic // hugeParam: pf is a small flag bundle
	if hostTransport == config.HostTransportHTTP {
		// pf.sessionIDSet (not pf.sessionID, which is never empty — cmdProxy falls back to
		// a fresh UUID) tracks whether the operator actually passed it.
		if pf.sessionIDSet {
			return fmt.Errorf("--session-id requires transport: stdio (a gateway mints its own Mcp-Session-Id per client session)")
		}
		return nil
	}
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
	// Every other HTTP-only flag: httpOnlyFlagsSetOnStdio (precomputed into
	// pf.httpOnlyFlagsSet) is the single source of truth, so a future HTTP-only flag is
	// covered automatically.
	if len(pf.httpOnlyFlagsSet) > 0 {
		return fmt.Errorf("%s requires transport: http (a stdio host has no HTTP listener)", strings.Join(pf.httpOnlyFlagsSet, ", "))
	}
	return nil
}

// validateProxyAuditPEPFlag rejects an unusable --audit-pep with the rest of the flag checks,
// before the Redis dial and the audit key/log creation. A pure function so the guard is
// unit-testable, matching validateProxyNumericFlags beside it.
func validateProxyAuditPEPFlag(f *proxyCLIFlags) error {
	if *f.auditPEP == "" {
		return nil
	}
	if _, err := capability.NewEnforcementPoint(*f.auditPEP); err != nil {
		return fmt.Errorf("--audit-pep: %w", err)
	}
	return nil
}

// redisGatedFlags is the single authoritative list of proxy flags that take effect ONLY
// when --redis-addr configures a Redis backend; without it each is silently dropped.
// --max-call-counter-keys is deliberately NOT here — it's the inverse, meaningful without
// Redis.
var redisGatedFlags = []string{
	"redis-password",
	"redis-tls",
	"killswitch-fail-open",
	"killswitch-reconcile-interval",
	"killswitch-session-ttl",
}

// validateProxyNumericFlags rejects negative values for the proxy's numeric limit flags,
// matching the config validator: each treats <= 0 as "unlimited/disabled/default", so a
// negative value would silently do the opposite of the operator's intent. --upstream-timeout
// is the exception with a legitimate negative sentinel (transport.UpstreamTimeoutUnset), so
// only values below it are rejected. A pure function so every guard is unit-testable.
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
	// Mirrors the config's fail-closed rejection: audit.Open silently coerces a negative
	// value (rotate-size -> 100 MiB default, retain -> keep-all), hiding a misconfiguration.
	case *f.auditRotateSize < 0:
		return errors.New("--audit-rotate-size must be >= 0 (0 = use the default size)")
	case *f.auditRetainRotated < 0:
		return errors.New("--audit-retain must be >= 0 (0 = keep all rotated files)")
	// The Redis kill switch clamps a non-positive reconcile interval to the 30s default, so
	// a sign typo meant to shorten it silently produces the default with no diagnostic.
	case *f.killswitchReconcile < 0:
		return errors.New("--killswitch-reconcile-interval must be >= 0 (0 = use the 30s default)")
	}
	return nil
}

// validateRedisFlagsRequireRedisAddr fails closed when any Redis-gated proxy flag is set
// without --redis-addr — without the backend those flags are silently ignored, so an
// operator's fail-open/auth/TLS/reconcile intent evaporates unobserved. A no-op when
// --redis-addr is set or no such flag was given.
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
	// activated, precomputed by gatedFlagsSetWithoutJWKS so the require-jwks guard can't
	// drift from the jwksGatedFlags inventory.
	gatedJWTFlagsSet                []string
	jwksAllowInsecure               bool
	jwtExperimentalCaps             bool // --jwt-experimental-capabilities: enable the EXPERIMENTAL mcp.capabilities (JWT v0.2) intersection
	oauthResource, oauthAuthzServer string
	unsafeBindAll, trustFwdFor      bool
	shutdownMs, upstreamTimeoutMs   int
	sessionID, configPath           string
	// sessionIDSet is whether --session-id was explicitly passed (unlike sessionID, which
	// is never empty: cmdProxy substitutes a fresh UUID when unset).
	sessionIDSet       bool
	strictDrift        bool // global --strict-drift override (promotes drift to fatal on policed routes)
	requireAuditStrict bool // --require-audit=strict: runtime fail-closed gate when the audit trail degrades

	maxSessions          int    // global --max-sessions override (0 = unlimited); HTTP only
	sessionIdleTimeoutMs int    // global --session-idle-timeout override (0 = no reaping); HTTP only
	redisConfigured      bool   // --redis-addr was set; drives the multi-instance state advisory
	auditPEP             string // --audit-pep: this enforcement point's name, before the config's audit.pep takes precedence
	controlTokenPath     string // --control-token-path: where to write the /control/kill control token; HTTP only

	// httpOnlyFlagsSet holds the "--"-prefixed names of every HTTP-only flag the operator
	// activated, precomputed by httpOnlyFlagsSetOnStdio.
	httpOnlyFlagsSet []string
}

// validateJWTAudienceConfig enforces fail-closed audience pinning for --jwks-uri mode:
// --jwt-audience must be set so a token minted for another relying party cannot be replayed
// against eunox, bypassable only with --jwt-allow-any-audience. A no-op when jwksURI is
// empty.
func validateJWTAudienceConfig(jwksURI, jwtAudience string, allowAnyAudience bool) error {
	if jwksURI == "" {
		return nil
	}
	if strings.TrimSpace(jwtAudience) == "" && !allowAnyAudience {
		return fmt.Errorf(`--jwks-uri requires --jwt-audience (the expected "aud" claim) so a token minted for another service cannot be replayed against eunox; pass --jwt-allow-any-audience to accept any audience (not recommended)`)
	}
	// A padded audience is worse to diagnose than an empty one: it's stored and compared
	// verbatim, so it matches nothing and denies every call with an opaque error.
	if jwtAudience != strings.TrimSpace(jwtAudience) {
		return fmt.Errorf("--jwt-audience %q has leading or trailing whitespace; the audience is matched verbatim against a token's \"aud\" claim, so this value would never match and would silently deny every call", jwtAudience)
	}
	return nil
}

// jwtAudienceBypassWarning returns the warning to emit when audience pinning is disabled,
// or "" when active. Keyed on --jwt-allow-any-audience, not on whether --jwt-audience is
// empty: both flags together silently ignore a configured audience, the case that must warn.
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
// --jwt-issuer must be set so a token from another issuer sharing the JWKS endpoint
// cannot be replayed against eunox. Bypassed only with --jwt-allow-any-issuer.
func validateJWTIssuerConfig(jwksURI, jwtIssuer string, allowAnyIssuer bool) error {
	if jwksURI == "" {
		return nil
	}
	if jwtIssuer == "" && !allowAnyIssuer {
		return fmt.Errorf(`--jwks-uri requires --jwt-issuer (the expected "iss" claim) so a token from another issuer sharing the JWKS endpoint cannot be replayed against eunox; pass --jwt-allow-any-issuer to accept any issuer (not recommended)`)
	}
	return nil
}

// jwtIssuerBypassWarning returns the warning to emit when issuer pinning is disabled, or
// "" when active. Keyed on --jwt-allow-any-issuer, mirroring jwtAudienceBypassWarning.
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

// validateJWTFlagsRequireJWKS fails closed when any JWT flag is set without --jwks-uri:
// without it these flags are silently ignored and the gateway serves every request
// UNAUTHENTICATED while the operator believes JWT auth is enforced. The single guard for
// this contract, driven off the precomputed pf.gatedJWTFlagsSet.
func validateJWTFlagsRequireJWKS(pf proxyFlags) error { //nolint:gocritic // hugeParam: pf is a small flag bundle
	if pf.jwksURI != "" || len(pf.gatedJWTFlagsSet) == 0 {
		return nil
	}
	return fmt.Errorf("JWT flag(s) %s set without --jwks-uri: they configure bearer-token validation (or the experimental capability intersection), which runs only when --jwks-uri stands up the JWT authenticator — without it the gateway serves every request UNAUTHENTICATED. Set --jwks-uri to enable JWT authentication, or remove these flags", strings.Join(pf.gatedJWTFlagsSet, ", "))
}

// jwtExperimentalCapsWarning returns the startup warning for the experimental
// mcp.capabilities claim schema (JWT v0.2), or "" when off.
func jwtExperimentalCapsWarning(experimentalCaps bool) string {
	if !experimentalCaps {
		return ""
	}
	return "--jwt-experimental-capabilities is set; enforcement of the mcp.capabilities claim schema (JWT v0.2) is EXPERIMENTAL and the claim format may change before 1.0."
}

// validateJWKSURIScheme enforces a tamper-resistant channel for the JWKS endpoint, the
// root of trust for every token: https always accepted, http only to loopback unless
// --jwks-allow-insecure-http is set, since a remote plaintext fetch would let an attacker
// substitute the key set.
func validateJWKSURIScheme(jwksURI string, allowInsecure bool) error {
	if jwksURI == "" {
		return nil
	}
	u, err := url.Parse(jwksURI)
	if err != nil {
		// %w would print a credentialed JWKS URI in full (*url.Error embeds the raw input).
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

// validateOAuthURI rejects an OAuth metadata URI unsafe to publish in an RFC 9728
// protected-resource document: must be an absolute https URI with a host, no fragment, no
// HTTP-quoted-string-illegal character, and no residual ${VAR} reference. label names the
// source for the operator. allowEmpty differs by source: the resource URI may be empty
// (endpoint not published), an authorization-server URI may not.
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

// newJWKSHTTPClient returns the HTTP client used to fetch the JWKS. Its redirect policy
// re-applies validateJWKSURIScheme to every redirect target, since a valid https endpoint
// could 302 the key fetch onto plaintext remote http, reopening the key-substitution path.
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
			// A redirect must not leave the configured HOST — the scheme check above still
			// passes an https->https hop, so without this an IdP open-redirect could point
			// the key fetch at an attacker host. One exception: a hop between loopback
			// spellings (localhost <-> 127.0.0.1) never leaves the machine.
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

// warnNoRedisSharedState prints the multi-instance advisory when a policy depends on state
// that outlives a single call but no Redis backend is configured: the in-memory backends
// are per-process, so running more than one instance silently multiplies quotas and lets a
// sequenceBlock/flowLabel gate fail open across instances.
func warnNoRedisSharedState(redisConfigured, policyUsesSharedState bool) {
	if redisConfigured || !policyUsesSharedState {
		return
	}
	fmt.Fprintf(os.Stderr, "[eunox] NOTICE: a policy accumulates cross-call state (a maxCalls or blastRadius budget, sequenceBlock history, or flow labels) but no --redis-addr is set — call-counter, call-ordering history, flow-label, and kill-switch state are per-process. Running multiple instances will not share quotas, sequence history, taint, or revocations; configure --redis-addr for multi-instance deployments.\n")
}

// anyRouteTaskAnchored reports whether any upstream resolves to task-anchored state, so the
// advisory fires once per process rather than once per route.
func anyRouteTaskAnchored(cfg *config.GatewayConfig) bool {
	for i := range cfg.Upstreams {
		if cfg.ResolvedTaskAnchoredState(&cfg.Upstreams[i]) {
			return true
		}
	}
	return false
}

// warnTaskAnchoringWithoutJWT prints the advisory for a route that opts into task-anchored
// state on a proxy that never validates a token: with no JWT integration every request
// takes the token-less session fallback and the option does nothing. A notice rather than a
// refusal, since the combination is legitimate mid-rollout (config enabled before the IdP
// starts minting the claim).
func warnTaskAnchoringWithoutJWT(jwtConfigured, taskAnchored bool) {
	if jwtConfigured || !taskAnchored {
		return
	}
	fmt.Fprintf(os.Stderr, "[eunox] NOTICE: taskAnchoredState is enabled but no JWT validation is configured (--jwks-uri) — the anchor comes from the VALIDATED mcp.task_id claim, so every request falls back to session keying and the option has no effect.\n")
}

// warnTaskAnchoringWithoutRedis prints the advisory for task-anchored state on the
// in-memory backends. A task-anchored key deliberately OUTLIVES its session, so a single
// instance stays bounded via idle TTL — but more than one instance means two PEPs each
// hold half the task's state, silently defeating the cross-PEP property the option exists
// to provide.
func warnTaskAnchoringWithoutRedis(redisConfigured, taskAnchored bool) {
	if redisConfigured || !taskAnchored {
		return
	}
	fmt.Fprintf(os.Stderr, "[eunox] NOTICE: taskAnchoredState is enabled but no --redis-addr is set — task-anchored flow labels, budgets and antecedents live in this process only, and a task key outlives the session that created it (nothing tears it down; in this mode the in-memory stores reclaim one idle for %s). A single instance is bounded; more than one will not share a task's state. Configure --redis-addr for multi-instance deployments.\n", flowlabelstore.DefaultIdleTTL)
}

// warnTaskAnchoringWithoutPEP prints the advisory for task-anchored state on an instance
// that stamps no enforcement-point name. Task anchoring is the one configurable statement
// that an operator INTENDS a task to cross enforcement points; with no name on the records,
// the tapes of the instances it crosses are attributable only by which file they came out
// of, which does not survive being merged into a SIEM.
//
// A notice rather than a refusal, for the reason the redis one is: the combination is
// legitimate (the second enforcement point may not be standing yet), and an unnamed tape
// loses attribution rather than enforcement.
func warnTaskAnchoringWithoutPEP(pepConfigured, taskAnchored bool) {
	if pepConfigured || !taskAnchored {
		return
	}
	fmt.Fprintf(os.Stderr, "[eunox] NOTICE: taskAnchoredState is enabled but no enforcement-point name is set — records carry no 'pep' field, so a task's calls handled by two instances cannot be told apart once their tapes are read together. Set --audit-pep / audit.pep to a distinct name per instance.\n")
}

// resolveOAuthMetadata builds the RFC 9728 protected-resource metadata document (and its
// URL), or returns (nil, "", nil) when no resource URI is configured. Fails closed on an
// invalid URI or an authorization server configured with no resource. Config takes
// precedence over the flags.
func resolveOAuthMetadata(cfg *config.GatewayConfig, pf proxyFlags) (*transport.OAuthResourceMetadata, string, error) { //nolint:gocritic // hugeParam: pf is a small flag bundle
	// The metadata document is published only when this is set — --jwks-uri without
	// --oauth-resource is valid and simply doesn't expose the endpoint.
	oauthResource := cfg.Listen.OAuthResource
	oauthResourceLabel := "listen.oauthResource"
	if oauthResource == "" {
		oauthResource = pf.oauthResource
		oauthResourceLabel = "--oauth-resource"
	} else if pf.oauthResource != "" && pf.oauthResource != cfg.Listen.OAuthResource {
		// Config wins, matching the audit-path precedence above — but say so, or an
		// operator debugs a token-audience mismatch with no hint their flag was dropped.
		fmt.Fprintf(os.Stderr, "[eunox] WARNING: --oauth-resource %q is overridden by the config's listen.oauthResource %q; the config takes precedence.\n", pf.oauthResource, cfg.Listen.OAuthResource)
	}
	if err := validateOAuthURI(oauthResourceLabel, oauthResource, true); err != nil {
		return nil, "", err
	}

	var oauthAuthzServers []string
	// validateAuthz covers the two operator-supplied sources. The --jwt-issuer fallback is
	// exempt: it may be a loopback http URL in dev, so forcing https on it would regress.
	var validateAuthz bool
	switch {
	case len(cfg.Listen.OAuthAuthorizationServers) > 0:
		oauthAuthzServers = cfg.Listen.OAuthAuthorizationServers
		validateAuthz = true
		if pf.oauthAuthzServer != "" && (len(oauthAuthzServers) != 1 || oauthAuthzServers[0] != pf.oauthAuthzServer) {
			// Config wins, but an explicitly-passed flag is never discarded in silence.
			fmt.Fprintf(os.Stderr, "[eunox] WARNING: --oauth-authorization-server=%q is overridden by listen.oauthAuthorizationServers=%v from the config file; the config value is published.\n", pf.oauthAuthzServer, oauthAuthzServers)
		}
	case pf.oauthAuthzServer != "":
		oauthAuthzServers = []string{pf.oauthAuthzServer}
		validateAuthz = true
	case pf.jwtIssuer != "":
		oauthAuthzServers = []string{pf.jwtIssuer}
	}
	// Validate every explicitly-configured authorization-server URI before it enters the
	// metadata document. Fail closed before any metadata is built.
	if validateAuthz {
		for _, server := range oauthAuthzServers {
			if err := validateOAuthURI("oauth authorization server", server, false); err != nil {
				return nil, "", err
			}
		}
		// Published only inside the metadata document, which requires a resource URI —
		// an explicit authorization server with no resource is a silent no-op otherwise.
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

// validateJWTFlagCombinations runs the PURE JWT flag checks — the audience and issuer
// combinations and the JWKS URI scheme. A no-op without --jwks-uri, where the JWT layer does
// not stand up at all.
//
// Hoisted out of gatewayJWTLayer, which is reached only after the Redis dial and the audit
// key and log have been minted: a typo'd --jwt-issuer is exactly the trivially-fixable flag
// error cmdProxy's own guards run before any side effect for.
func validateJWTFlagCombinations(pf proxyFlags) error { //nolint:gocritic // hugeParam: pf is a small flag bundle
	if pf.jwksURI == "" {
		return nil
	}
	if err := validateJWTAudienceConfig(pf.jwksURI, pf.jwtAudience, pf.jwtAllowAnyAudience); err != nil {
		return err
	}
	if err := validateJWTIssuerConfig(pf.jwksURI, pf.jwtIssuer, pf.jwtAllowAnyIssuer); err != nil {
		return err
	}
	return validateJWKSURIScheme(pf.jwksURI, pf.jwksAllowInsecure)
}

// gatewayJWTLayer stands up the gateway's JWT layer from the flags: validates JWT-adjacent
// flag combinations, emits bypass warnings, and wraps every route's manifest PDP in a
// pdp.JWTPDP sharing one JWKS validator. Returns a nil PDP when --jwks-uri is unset. routes
// is mutated in place by WrapRoutesWithJWT.
func gatewayJWTLayer(routes map[string]*transport.UpstreamRoute, ks killswitch.Manager, pf proxyFlags) (*pdp.JWTPDP, error) { //nolint:gocritic // hugeParam: pf is a small flag bundle
	if pf.jwksURI == "" {
		return nil, nil
	}
	// Already run before the first side effect (see cmdProxy); repeated here so this
	// function stays self-contained for a caller that reaches it directly. One helper, so
	// the two sites cannot disagree about what a valid JWT flag combination is.
	if err := validateJWTFlagCombinations(pf); err != nil {
		return nil, err
	}
	if w := jwtAudienceBypassWarning(pf.jwtAllowAnyAudience, pf.jwtAudience); w != "" {
		fmt.Fprintf(os.Stderr, "[eunox] WARNING: %s\n", w)
	}
	// --jwt-allow-any-audience also voids per-route manifest 'audience' pins; the generic
	// bypass warning above names only the flag, so call out the dead manifest pin too.
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
	// Redact before printing: some IdPs gate the JWKS endpoint behind a query key or
	// basic-auth userinfo, and this banner goes to the same stderr logs/bundles collect.
	safeJWKS := capability.RedactURLForLog(pf.jwksURI)
	if pf.jwtExperimentalCaps {
		fmt.Fprintf(os.Stderr, "[eunox] JWT PDP enabled (JWKS URI: %s); intersecting per-route manifests with experimental mcp.capabilities claims\n", safeJWKS)
	} else {
		fmt.Fprintf(os.Stderr, "[eunox] JWT PDP enabled (JWKS URI: %s); enforcing per-route manifests (experimental mcp.capabilities intersection disabled; pass --jwt-experimental-capabilities to enable)\n", safeJWKS)
	}
	gwJWTPDP, err := transport.WrapRoutesWithJWT(routes, pdp.JWTPDPOptions{
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
		return nil, err
	}
	return gwJWTPDP, nil
}

// serveHTTPGateway serves cfg's upstreams over an HTTP listener, one /mcp/<name>
// route each (the gateway shape).
func serveHTTPGateway(ctx context.Context, cfg *config.GatewayConfig, sink *audit.Sink, counter capability.CallCounter, flowStore capability.FlowLabelStore, ks killswitch.Manager, pf proxyFlags, onServeReady func(context.Context)) error { //nolint:gocritic // hugeParam: pf is a small flag bundle
	// drift.MakeDriftCheck is the per-route hook factory; BuildRoutes wires it inside, so
	// this layer never reaches into route internals.
	routes, err := transport.BuildRoutes(cfg, sink, counter, flowStore, ks, pf.strictDrift, drift.MakeDriftCheck, os.Stderr)
	if err != nil {
		return err
	}

	warnNoRedisSharedState(pf.redisConfigured, transport.AnyRouteAccumulatesSharedState(routes))
	warnTaskAnchoringWithoutJWT(pf.jwksURI != "", anyRouteTaskAnchored(cfg))
	warnTaskAnchoringWithoutRedis(pf.redisConfigured, anyRouteTaskAnchored(cfg))
	warnTaskAnchoringWithoutPEP(resolveAuditPEP(pf.auditPEP, cfg) != "", anyRouteTaskAnchored(cfg))

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

	// Config takes precedence over the flag; an explicit listen.maxSessions overrides even
	// at 0, so config can still express "unlimited" despite the flag's non-zero default.
	maxSessions := transport.ResolveMaxSessions(pf.maxSessions, cfg.Listen.MaxSessions)
	// Mirrors ResolveMaxSessions: a present config value wins, including an explicit 0.
	sessionIdleMs := transport.ResolveSessionIdleTimeout(pf.sessionIdleTimeoutMs, cfg.Listen.SessionIdleTimeoutMs)
	// listen.trustedProxyHops is config-only (no flag): a property of deployment topology.
	var trustedProxyHops int
	if h := cfg.Listen.TrustedProxyHops; h != nil {
		trustedProxyHops = *h
	}

	// Fail closed when a route manifest declares an `audience` pin but no --jwks-uri was
	// set: the config-file form of the footgun validateJWTFlagsRequireJWKS closes for the CLI.
	if pf.jwksURI == "" {
		if name, pinned := transport.FirstRouteAudiencePin(routes); pinned {
			return fmt.Errorf("route %q declares an audience pin in its policy manifest but --jwks-uri is not set: the audience pin is a JWT concept that is only enforced in JWT mode, so without --jwks-uri it is silently ignored and the route serves every request unauthenticated. Set --jwks-uri to enable JWT authentication, or remove the manifest 'audience' field", name)
		}
	}

	gwJWTPDP, err := gatewayJWTLayer(routes, ks, pf)
	if err != nil {
		return err
	}

	// Mutually exclusive: the static token check runs first and 401s every IdP JWT
	// before the JWT PDP runs, silently disabling JWT auth.
	if cfg.Listen.AuthToken != "" && gwJWTPDP != nil {
		return fmt.Errorf("listen.authToken and --jwks-uri are mutually exclusive: JWT mode handles all authentication, but the static token check runs first and rejects every IdP JWT. Remove listen.authToken when --jwks-uri is set")
	}

	oauthMeta, oauthMetaURL, err := resolveOAuthMetadata(cfg, pf)
	if err != nil {
		return err
	}
	// Publishing the metadata document announces "this resource is protected" to any
	// unauthenticated client. With NEITHER --jwks-uri nor listen.authToken the gateway
	// validates no bearer token at all, so fail closed rather than advertise a protection
	// it cannot enforce. listen.authToken counts as validation even though it's a static
	// secret: checkAuth already serves the metadata URL as its 401 hint.
	if oauthMeta != nil && gwJWTPDP == nil && cfg.Listen.AuthToken == "" {
		return fmt.Errorf("--oauth-resource / listen.oauthResource publishes RFC 9728 protected-resource metadata, but no bearer-token validation is configured: set --jwks-uri (or listen.authToken) so presented tokens are actually verified, or remove the --oauth-* settings so the gateway does not advertise a protection it cannot enforce")
	}

	// Fail closed if the control token cannot be minted or persisted: the endpoint must
	// not come up unauthed.
	controlToken, err := transport.GenerateControlToken()
	if err != nil {
		return fmt.Errorf("kill control endpoint: %w", err)
	}
	// Persist it only AFTER the listener binds: writing before the bind meant a second,
	// doomed proxy could clobber a running proxy's token on disk before hitting its own
	// "address already in use" failure, breaking `eunox kill` until restart.
	//
	// Close over the one field this needs, not pf itself, which would heap-promote the
	// whole flag bundle for the proxy's lifetime.
	controlTokenPath := pf.controlTokenPath
	writeControlToken := func(ctx context.Context) error {
		controlTokenFile, werr := transport.WriteControlTokenFile(ctx, controlTokenPath, controlToken, os.Stderr)
		if werr != nil {
			return fmt.Errorf("kill control endpoint: %w", werr)
		}
		fmt.Fprintf(os.Stderr, "[eunox] Control token for POST /control/kill written to %s (0600). 'eunox kill' reads it from there; override with --control-token-path / --control-token / EUNOX_CONTROL_TOKEN.\n", controlTokenFile)
		// The session-kill TTL publish shares this hook and is ordered LAST, after the
		// token write succeeds, so a startup failure surviving the bind can't clobber a
		// running proxy's TTL. ctx is passed through so an abandoned hook (shutdown landing
		// in this window) cannot land a write; the early return is a fast path, not an error.
		if ctx.Err() != nil {
			return nil
		}
		onServeReady(ctx)
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
func serveStdioHost(ctx context.Context, cfg *config.GatewayConfig, sink *audit.Sink, counter capability.CallCounter, flowStore capability.FlowLabelStore, ks killswitch.Manager, pf proxyFlags, onServeReady func(context.Context)) error { //nolint:gocritic // hugeParam: pf is a small flag bundle
	u := &cfg.Upstreams[0] // validate() guarantees exactly one upstream for transport: stdio
	auditMode := cfg.AuditModeFor(u)

	// Single-sourced in config so this stdio host and transport.BuildRoutes cannot drift.
	if err := cfg.StartupPolicyError(u); err != nil {
		return err
	}
	configStrict := cfg.ResolvedStrictDrift(u)

	dp, manifest, policyVersion, policySHA256, err := transport.LoadUpstreamPDP(u, cfg.HostTransport(), cfg.BaseDir, counter, flowStore, ks, cfg.ResolvedTaskAnchoredState(u))
	if err != nil {
		return err
	}
	// Same resolver the gateway uses, so the two transports cannot diverge.
	strictDrift := transport.ResolveStrictDrift(configStrict, pf.strictDrift, manifest != nil)
	if pf.strictDrift && manifest == nil {
		fmt.Fprintf(os.Stderr, "[eunox] WARNING: --strict-drift had no effect: upstream %q has no policy to check drift against.\n", u.Name)
	}

	// Through the shared transport helper so the stdio host and gateway routes cannot
	// drift on wording. routePath is "" — a stdio host has no /mcp mount.
	transport.PrintRoutePolicyNotices(os.Stderr, u.Name, "", manifest.AuditOnlyCount(), auditMode, u.UpstreamTLSSkipVerify)

	upstreamTimeMs := transport.ResolveUpstreamTimeout(pf.upstreamTimeoutMs, cfg.Defaults.UpstreamTimeoutMs)

	warnNoRedisSharedState(pf.redisConfigured, manifest.AccumulatesSharedState())
	// THIS upstream's resolved posture, not the config's: a stdio host runs exactly one
	// upstream, so scanning the whole file would advise about a route not being served here.
	warnTaskAnchoringWithoutJWT(pf.jwksURI != "", cfg.ResolvedTaskAnchoredState(u))
	warnTaskAnchoringWithoutRedis(pf.redisConfigured, cfg.ResolvedTaskAnchoredState(u))
	warnTaskAnchoringWithoutPEP(resolveAuditPEP(pf.auditPEP, cfg) != "", cfg.ResolvedTaskAnchoredState(u))

	// Absent (the default) leaves the verifier nil; a configured-but-unreadable key set is
	// fatal, since a path typo degrading to "no receipt ever verifies" is indistinguishable
	// from a server that stopped signing.
	receipts, err := transport.LoadEffectReceiptVerifier(cfg.BaseDir, u.EffectReceiptKeys)
	if err != nil {
		return fmt.Errorf("upstream %q: %w", u.Name, err)
	}

	proxy := transport.NewStdioProxy(transport.StdioProxyOptions{
		Command:               u.Command,
		Args:                  u.Args,
		UpstreamURL:           u.UpstreamURL,
		UpstreamAuthHeader:    u.UpstreamAuthHeader,
		UpstreamTLSSkipVerify: u.UpstreamTLSSkipVerify,
		// Empty when the operator wrote `auto` or omitted the key, which opens the leg with
		// the handshake. LoadGatewayConfig has already refused anything else.
		UpstreamProtocolVersion: u.ResolvedProtocolVersion(),
		PDP:                     dp,
		Sink:                    sink,
		PolicyVersion:           policyVersion,
		PolicySHA256:            policySHA256,
		SessionID:               pf.sessionID,
		ShutdownMs:              pf.shutdownMs,
		UpstreamTimeMs:          upstreamTimeMs,
		Audit:                   auditMode,
		RequireAuditStrict:      pf.requireAuditStrict,
		// Serialize the decision phase only when the policy accumulates state a source
		// commits and a later call reads, so a pipelining host cannot race a sink ahead of
		// its source; a policy that accumulates nothing keeps full parallelism.
		SerializeDecisions: manifest.NeedsDecisionTurn(),
		// Same value handed to LoadUpstreamPDP above, so the engine's state key and the
		// decision turn are built from one bit rather than two.
		TaskAnchoredState: cfg.ResolvedTaskAnchoredState(u),
		// Admit the client-supplied attribution interface only under the draft
		// schemaVersion that contains it.
		HonorAttribution: manifest.HonorsAttributionInterface(),
		// Verified against this upstream's own key domain — never the caller IdP's.
		EffectReceipts: receipts,
		DriftCheck:     drift.MakeDriftCheck(manifest, strictDrift),
		// The stdio host has no bind step, so the transport fires this itself from inside
		// Start once the session is live — calling it here would run ahead of Start's own
		// fallible steps, letting a proxy that never came up clobber a running proxy's TTL.
		OnReady: onServeReady,
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
		// A literal "--" terminator makes EVERY remaining token positional, dash-prefixed
		// or not: flag.Parse consumes the "--" itself (it never appears in Args()) and
		// stops all further flag interpretation for the rest of that call. Re-parsing the
		// tail on the next loop iteration would silently re-enable flag parsing for
		// anything after the first token, so `eunox kill -- -weird-session-id` protected
		// only the token right after the terminator and failed on any further dash-prefixed
		// positional with "flag provided but not defined", contradicting the flag package's
		// own convention. `kill` is the reachable case: validate peels its own "--"
		// remainder off as a stdio command BEFORE calling here (see cmdValidate), so a
		// terminator never survives to this loop there.
		if consumed := len(args) - len(rest); terminatorFired(fs, args, consumed) {
			return append(positionals, rest...), nil
		}
		positionals = append(positionals, rest[0])
		args = rest[1:]
	}
}

// terminatorFired reports whether the token immediately before where rest begins in THIS
// call's args was a GENUINE "--" terminator, as opposed to a literal "--" swallowed as the
// VALUE of an immediately preceding flag given in separate "--flag value" form. flag.Parse
// special-cases a bare "--" only when scanning for the START of a new flag; mid-flag, once a
// value-needing flag's name has been consumed, it takes the very next token as that flag's
// value unconditionally, with no check that the token happens to spell "--". So
// `--session -- foo -b` reads session="--" and stops at "foo" (not flag-shaped) — a plain
// `args[consumed-1] == "--"` check then wrongly concludes a terminator fired and swallows
// ["foo", "-b"] as positionals in one shot, instead of re-parsing "-b" as a possible flag on
// the next loop iteration.
func terminatorFired(fs *flag.FlagSet, args []string, consumed int) bool {
	if consumed == 0 || args[consumed-1] != "--" {
		return false
	}
	if consumed < 2 {
		// Nothing preceded it in this call that could have consumed it as a value.
		return true
	}
	prev := args[consumed-2]
	if !strings.HasPrefix(prev, "-") || strings.Contains(prev, "=") {
		// prev isn't a bare flag name in separate-value form (a positional, or a
		// "--flag=value" that already carries its own value), so it cannot have eaten the
		// "--" that follows it.
		return true
	}
	fl := fs.Lookup(strings.TrimLeft(prev, "-"))
	if fl == nil {
		return true // not a flag this set defines; can't have consumed a value
	}
	if bf, ok := fl.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
		return true // a boolean flag never consumes the next token as its value
	}
	// prev is a recognized, value-needing flag in separate-value form: it ate the "--" that
	// follows it as its own value, so no terminator actually fired here.
	return false
}

// bindExposesAllInterfaces reports whether bindHost (already stripped of any surrounding
// IPv6 brackets) will make the listener accept connections on every interface. Comparing
// the PARSED address catches every unspecified-address spelling ("0.0.0.0", "::", "::0",
// …) uniformly. net.ParseIP alone misses inet_aton-style integer hosts ("0", "0x0") that a
// cgo resolver's getaddrinfo still resolves to 0.0.0.0, so those are decoded separately.
// Deliberately no DNS lookup: resolving an operator-supplied name would be background
// network activity for a check that must work offline.
func bindExposesAllInterfaces(bindHost string) bool {
	if ip := net.ParseIP(bindHost); ip != nil {
		return ip.IsUnspecified()
	}
	if bindHost == "" {
		// An empty host in "host:port" means all interfaces to net.Listen.
		return true
	}
	// strconv handles the 0x / 0o / leading-0 bases the resolver accepts; a parse failure
	// means this is a name, not an integer.
	if n, err := strconv.ParseUint(bindHost, 0, 64); err == nil {
		return n == 0
	}
	return false
}

// refuseNonRegularOutput fails closed unless path is a regular file or genuinely absent;
// see config.RefuseNonRegularPath for what the guard covers.
func refuseNonRegularOutput(path string) error {
	return config.RefuseNonRegularPath(path, "output file")
}

// writeGeneratedFile writes content to path at mode 0600, refusing to clobber a
// pre-existing file unless force is set. Closes two gaps in a plain os.WriteFile:
// O_CREATE applies the mode only on creation (force re-tightens to 0600), and O_TRUNC
// silently clobbers (without force, O_EXCL refuses instead).
func writeGeneratedFile(path, content string, force bool) (err error) {
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if force {
		if err := refuseNonRegularOutput(path); err != nil {
			return err
		}
		// config.OpenNoFollow closes the Lstat->open race the guard above cannot; O_EXCL
		// already refuses a symlink for free, which is why only the force path needs it.
		// OpenNonBlock is the FIFO half of that race: a symlink is refused by O_NOFOLLOW,
		// but a FIFO swapped in after the Lstat is opened directly and a write-only open of
		// a reader-less FIFO blocks inside open(2) forever, so no post-open check would run.
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC | config.OpenNoFollow | config.OpenNonBlock
	}
	f, err := os.OpenFile(path, flags, 0o600) //nolint:gosec // G304: path is an operator-provided --output/--config-output location, and 0600 is the intended restrictive mode
	if err != nil {
		if !force && errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%q already exists; refusing to overwrite it — pass --force to overwrite, or choose a different path", path)
		}
		return err
	}
	// Surface the close (which flushes), or a delayed write error (e.g. NFS) would be
	// announced as a complete write.
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("closing %q: %w", path, cerr)
		}
	}()
	if force {
		// Asked through the HANDLE, so it describes what is about to be written rather than
		// what the name resolved to before the open — the one question with no window after
		// it. Ahead of the re-tighten, which would otherwise re-mode a substituted object.
		if rerr := config.RefuseNonRegularHandle(f, "output file", path); rerr != nil {
			return rerr
		}
		// Re-tighten BEFORE writing so a regenerated credential-bearing config never lands
		// at a loose mode; on the open fd rather than os.Chmod(path), which would re-resolve
		// and could follow a symlink.
		if cerr := f.Chmod(0o600); cerr != nil {
			return fmt.Errorf("tightening mode of %q to 0600: %w", path, cerr)
		}
	}
	if _, werr := f.WriteString(content); werr != nil {
		return fmt.Errorf("writing %q: %w", path, werr)
	}
	return nil
}

// -----------------------------------------------------------------
// audit-log readers (suggest / stats / audit-verify)
// -----------------------------------------------------------------

// auditLogMissingHint returns a first-run-friendly message for a missing audit log — what
// it is and how to produce one, instead of a raw OS error.
func auditLogMissingHint(cmdName, logPath string) string {
	return fmt.Sprintf(
		"eunox %s: no audit log yet at %s.\n\n"+
			"The audit log is written while the proxy runs. Capture one by putting\n"+
			"eunox in front of your MCP server in audit mode:\n\n"+
			"  eunox proxy --audit -- <command that launches your MCP server>\n\n"+
			"Use the agent so it makes some calls, then re-run: eunox %s\n",
		cmdName, logPath, cmdName)
}

// openAuditChain opens the FULL audit chain — every rotated sibling plus the active base —
// for a read-only reporting command, returning one concatenated reader (oldest record
// first) and a closer. audit.OpenLogChain opens one file at a time, so the fd count stays
// bounded even under keep-all retention. On error the returned message is the full text to
// print to stderr verbatim; the caller prints it and exits with its own usage code (2 for
// both callers, via openAuditChainOrExit) — a log this command cannot read is a
// configuration failure, not a finding, so it must not collide with a findings code.
func openAuditChain(cmdName, logPath string) (reader io.Reader, closeAll func(), err error) {
	files, ferr := audit.LogChainFiles(logPath)
	if ferr != nil {
		// Pre-formatted via Sprintf, not Errorf, so the deliberate trailing newline
		// doesn't trip the "error strings must not end in punctuation" checks.
		msg := fmt.Sprintf("eunox %s: discovering rotated audit logs: %v\n", cmdName, ferr)
		return nil, nil, fmt.Errorf("%s", msg)
	}
	if len(files) == 0 {
		return nil, nil, fmt.Errorf("%s", auditLogMissingHint(cmdName, logPath))
	}
	rc := audit.OpenLogChain(files)
	return rc, func() { _ = rc.Close() }, nil
}
