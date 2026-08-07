// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// eunox config: declare how eunox fronts one or more MCP upstreams.
//
// The top-level `transport` selects the host-facing transport. With `transport: http`
// (default, "gateway" shape) one process fronts N MCP servers, each on its own route
// (POST /mcp/<name>) with its own manifest, writing to one shared signed audit tape. With
// `transport: stdio` eunox speaks MCP over stdin/stdout to exactly one upstream. Connection
// wiring lives here; policy stays in the per-route manifest files referenced by `policy:`.
//
// A JSON Schema lives at schemas/eunox-gateway-config.schema.json; unknown keys are rejected
// at load, mirroring its "additionalProperties": false.
//
// Example:
//
//	listen:
//	  bind: 127.0.0.1
//	  port: 3000
//	  authToken: ${EUNOX_GATEWAY_TOKEN}
//	audit:
//	  log: ~/.eunox/audit.jsonl
//	defaults:
//	  enforcement: audit          # observe: evaluate and log, but forward not block
//	upstreams:
//	  - name: filesystem            # → POST /mcp/filesystem
//	    transport: stdio
//	    command: npx
//	    args: ["-y", "@modelcontextprotocol/server-filesystem", "/data"]
//	    policy: ["./policies/filesystem.yaml"]
//	    expectVersion: "0.1.0"
//	  - name: stripe                # → POST /mcp/stripe
//	    transport: http
//	    upstreamUrl: https://mcp.stripe.com
//	    upstreamAuthHeader: "Authorization: Bearer ${STRIPE_KEY}"
//	    policy: ["./policies/stripe.yaml"]

package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/eunolabs/eunox/pkg/capability"
)

// routeNameRe constrains upstream names to a safe URL path segment: the name is
// used verbatim in the /mcp/<name> route.
var routeNameRe = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// envRefRe matches an escape or a reference: "$$" (a literal '$'), "${NAME}", or "$NAME". The
// "$$" alternative is FIRST so it wins the leftmost-longest match — without it a literal '$'
// was inexpressible, and a value like "pa$$word" had its "$word" silently expanded the moment
// an unrelated env var named "word" happened to be set, substituting an attacker-influencable
// value into a credential.
var envRefRe = regexp.MustCompile(`\$\$|\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*`)

// envRefEscape is the escape sequence for a literal '$'.
const envRefEscape = "$$"

// isEnvRefEscape reports whether an envRefRe match is the "$$" escape rather than a variable
// reference. Every consumer routes through this one predicate so they agree on what counts as one.
func isEnvRefEscape(match string) bool { return match == envRefEscape }

// envRefName extracts the variable name from a single envRefRe match ("$VAR" or "${VAR}").
// Shared by expandEnvRefs and validateCredentialEnvRefs so the two decode a reference
// identically instead of drifting.
func envRefName(match string) string {
	name := match[1:]
	if name[0] == '{' {
		name = name[1 : len(name)-1]
	}
	return name
}

// envGrammar is which spellings count as an environment reference in ONE config field's text.
// The answer is not the same for every field — a bare "$word" is ordinary content in a stdio
// upstream's argv or a URL's query (e.g. `?$filter=...`) — so a field declares its grammar once
// (the `env` struct tag) and both the expansion pass and the unset-reference guard read that
// same declaration, rather than risk disagreeing about what "$" means in a given field.
type envGrammar int

const (
	// envGrammarFull recognizes "$VAR" and "${VAR}". The default, for fields (path, URL
	// authority, Origin, credential) with no legitimate bare "$".
	envGrammarFull envGrammar = iota
	// envGrammarBraced recognizes only "${VAR}", for text passed verbatim to another program
	// (a stdio upstream's command/args) where a bare "$word" is ordinary literal content.
	envGrammarBraced
	// envGrammarURL is full in the authority and path, braced-only from the first "?" or "#"
	// onward, since a URL's authority has no legitimate bare "$" but its query does.
	envGrammarURL
)

// envTagGrammars maps the `env` struct-tag value to its grammar. A field with no tag takes
// the default (full).
var envTagGrammars = map[string]envGrammar{
	"braced": envGrammarBraced,
	"url":    envGrammarURL,
}

// splitURLEnvScope splits raw at the first "?" or "#" into the full-grammar part and the
// braced-only part. Shared by the expansion and the guard so the two split a URL identically.
func splitURLEnvScope(raw string) (head, tail string) {
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		return raw[:i], raw[i:]
	}
	return raw, ""
}

// expandEnvRefs replaces ${VAR} / $VAR with the environment value when VAR is
// set, leaving the reference text intact when unset (unlike os.ExpandEnv, which
// blanks it). See envRefRe for the matching rules.
func expandEnvRefs(s string) string { return expandEnvRefsUnder(s, envGrammarFull) }

// expandEnvRefsUnder is expandEnvRefs under a field's declared grammar: a spelling the grammar
// does not recognize is left exactly as written rather than substituted. The "$$" escape
// collapses to a literal "$" under EVERY grammar deliberately — it is how a literal "${" is
// written at all, not part of what the grammar narrows.
func expandEnvRefsUnder(s string, g envGrammar) string {
	if g == envGrammarURL {
		head, tail := splitURLEnvScope(s)
		return expandRecognizedRefs(head, envGrammarFull) + expandRecognizedRefs(tail, envGrammarBraced)
	}
	return expandRecognizedRefs(s, g)
}

// expandRecognizedRefs is expandEnvRefsUnder for a grammar with no positional split.
func expandRecognizedRefs(s string, g envGrammar) string {
	return envRefRe.ReplaceAllStringFunc(s, func(match string) string {
		if isEnvRefEscape(match) {
			return "$" // "$$" collapses to a literal '$'
		}
		if !recognizedRef(match, g) {
			return match // not a reference in this field: ordinary literal text
		}
		if val, ok := os.LookupEnv(envRefName(match)); ok {
			return val
		}
		return match // unset → leave the reference text intact
	})
}

// recognizedRef reports whether an envRefRe match (already known not to be an escape) counts
// as a reference under g. The one predicate both passes apply, so "which spellings count" is
// answered identically by the expansion and the guard.
func recognizedRef(match string, g envGrammar) bool {
	return g != envGrammarBraced || strings.HasPrefix(match, "${")
}

// expandEnvInStrings walks v (which must be addressable) and rewrites every string it reaches
// through expandEnvRefsUnder, under the grammar its FIELD declares (the `env` struct tag).
// Running on the DECODED config rather than raw file text is what makes expansion safe: an env
// value is substituted as opaque data and never re-parsed as YAML. The grammar is inherited by
// everything below the field that declared it. Only struct/slice/string/pointer kinds are
// handled; TestExpandEnvInStrings_ConfigTreeHasNoUnhandledKinds fails the build if a map or
// interface field is added, since either would be silently skipped (an un-expanded secret).
func expandEnvInStrings(v reflect.Value, g envGrammar) {
	switch v.Kind() {
	case reflect.String:
		if v.CanSet() {
			v.SetString(expandEnvRefsUnder(v.String(), g))
		}
	case reflect.Pointer:
		if !v.IsNil() {
			expandEnvInStrings(v.Elem(), g)
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if f := v.Field(i); f.CanSet() { // CanSet skips unexported fields
				expandEnvInStrings(f, fieldEnvGrammar(v.Type().Field(i).Tag, g))
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			expandEnvInStrings(v.Index(i), g)
		}
	}
}

// fieldEnvGrammar returns the grammar declared on a struct field by its `env` tag, or inherited
// when it declares none. An unrecognized tag value is caught by declaredEnvGrammarAt at init.
func fieldEnvGrammar(tag reflect.StructTag, inherited envGrammar) envGrammar {
	if g, ok := envTagGrammars[tag.Get("env")]; ok {
		return g
	}
	return inherited
}

// declaredEnvGrammarAt reads the `env` grammar declared on the GatewayConfig field at a dotted
// yaml path ("listen.allowedOrigins", "upstreams.upstreamUrl"), keeping the hand-maintained
// per-field guards and the tag-driven expansion walk reading one declaration instead of
// silently restating the rule twice. It panics on an unresolvable path or tag value — a
// programming error caught by package init on any test run — rather than falling back to full
// and silently reintroducing the guard/expansion divergence this exists to prevent.
func declaredEnvGrammarAt(path string) envGrammar {
	t := reflect.TypeOf(GatewayConfig{})
	g := envGrammarFull
	for _, seg := range strings.Split(path, ".") {
		for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
			t = t.Elem()
		}
		if t.Kind() != reflect.Struct {
			panic(fmt.Sprintf("config: env grammar path %q descends into non-struct %s", path, t.Kind()))
		}
		f, ok := fieldByYAMLName(t, seg)
		if !ok {
			panic(fmt.Sprintf("config: env grammar path %q has no field %q", path, seg))
		}
		if tag := f.Tag.Get("env"); tag != "" {
			declared, known := envTagGrammars[tag]
			if !known {
				panic(fmt.Sprintf("config: field %q declares unknown env grammar %q", path, tag))
			}
			g = declared
		}
		t = f.Type
	}
	return g
}

// fieldByYAMLName finds t's field with the given yaml name.
func fieldByYAMLName(t reflect.Type, yamlName string) (reflect.StructField, bool) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if strings.Split(f.Tag.Get("yaml"), ",")[0] == yamlName {
			return f, true
		}
	}
	return reflect.StructField{}, false
}

// The grammars the unset-reference guards apply. Package-level so a path or tag that stops
// resolving fails at init rather than at the one startup that happens to reach the guard.
var (
	upstreamURLEnvGrammar        = declaredEnvGrammarAt("upstreams.upstreamUrl")
	upstreamCommandEnvGrammar    = declaredEnvGrammarAt("upstreams.command")
	upstreamArgsEnvGrammar       = declaredEnvGrammarAt("upstreams.args")
	upstreamAuthHeaderEnvGrammar = declaredEnvGrammarAt("upstreams.upstreamAuthHeader")
	allowedOriginsEnvGrammar     = declaredEnvGrammarAt("listen.allowedOrigins")
	listenAuthTokenEnvGrammar    = declaredEnvGrammarAt("listen.authToken")
	auditLogEnvGrammar           = declaredEnvGrammarAt("audit.log")
	auditKeyPathEnvGrammar       = declaredEnvGrammarAt("audit.keyPath")
)

// gatewayNumericKeys are the gateway-config scalar fields holding a bare number that yaml.v3
// can auto-type away from the operator's written text — most dangerously a leading-zero value
// read as OCTAL. The gateway-config counterpart to the manifest loader's numericPolicyScalarKeys.
var gatewayNumericKeys = map[string]bool{
	"port":                 true, // listen.port
	"maxSessions":          true, // listen.maxSessions
	"sessionIdleTimeoutMs": true, // listen.sessionIdleTimeoutMs
	"trustedProxyHops":     true, // listen.trustedProxyHops
	"rotateSizeBytes":      true, // audit.rotateSizeBytes
	"retainRotated":        true, // audit.retainRotated
	"upstreamTimeoutMs":    true, // defaults.upstreamTimeoutMs
}

// rejectCoercedGatewayNumerics walks a raw gateway-config YAML node and fails closed on any
// gatewayNumericKeys field whose unquoted value YAML silently coerced (leading-zero octal, float
// normalization, …) — the same class checkNumericFieldNotCoerced rejects in the manifest loader.
func rejectCoercedGatewayNumerics(n *yaml.Node, path string) error {
	if n == nil {
		return nil
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			key := resolveYAMLAlias(n.Content[i])
			if key.Kind == yaml.ScalarNode && gatewayNumericKeys[key.Value] {
				if err := checkNumericFieldNotCoerced(n.Content[i+1], key.Value, false); err != nil {
					return fmt.Errorf("invalid gateway config %q: %w", path, err)
				}
			}
		}
	}
	for _, child := range n.Content {
		if err := rejectCoercedGatewayNumerics(child, path); err != nil {
			return err
		}
	}
	return nil
}

// maxGatewayConfigFileBytes bounds a gateway config file read against a misdirected path
// (a fat-fingered --config pointed at a data file or disk image) that would otherwise be
// buffered whole before the strict decode could reject it — an OOM where an error
// belongs. Generous relative to a real config (a route list, even a large one, is well
// under a megabyte).
const maxGatewayConfigFileBytes = 32 << 20

// GatewayConfig is the top-level eunox config file.
type GatewayConfig struct {
	// SchemaVersion is the config grammar version (e.g. "0.1"). Required; an absent or
	// unsupported version is refused at load. See schema_version.go.
	SchemaVersion string `yaml:"schemaVersion"`

	// Transport selects the host-facing transport:
	//   "http"  (default): listen on a socket and front N upstreams, each on its
	//           own /mcp/<name> route (the gateway shape).
	//   "stdio": speak MCP over stdin/stdout to exactly one upstream; no socket.
	// Independent of each upstream's own `transport` (subprocess vs remote HTTP).
	Transport string `yaml:"transport"`

	Listen struct {
		Bind      string `yaml:"bind"`
		Port      int    `yaml:"port"`
		AuthToken string `yaml:"authToken"`
		// OAuthResource is this resource server's URI (RFC 9728), published in the
		// protected-resource metadata and WWW-Authenticate challenges. Never derived from
		// the request Host header.
		OAuthResource string `yaml:"oauthResource"`
		// OAuthAuthorizationServers lists the authorization server URIs published in the
		// protected-resource metadata document. Defaults to --jwt-issuer when unset.
		OAuthAuthorizationServers []string `yaml:"oauthAuthorizationServers"`
		// AllowedOrigins extends the built-in Origin allowlist used by the DNS-rebinding
		// guard. List full origins, e.g. "https://app.example.com". HTTP transport only.
		AllowedOrigins []string `yaml:"allowedOrigins"`
		// TrustedProxyCIDRs lists the CIDR ranges a reverse proxy may connect from for its
		// X-Forwarded-For header to be trusted under --trust-forwarded-for — otherwise any
		// client reaching the listener directly could forge the header to spoof an ipRange
		// source IP. HTTP transport only.
		TrustedProxyCIDRs []string `yaml:"trustedProxyCIDRs"`
		// TrustedProxyHops is how many trusted reverse proxies sit in front of eunox: the
		// right-most N X-Forwarded-For entries are proxy-written, the client's real address
		// is the N-th from the right, and everything further left is client-supplied and
		// ignored. Unset ⟹ 1. Must be declared rather than inferred from trustedProxyCIDRs,
		// since an entry inside that range is indistinguishable from a client whose own
		// address falls in it. Pointer so 0 is rejected rather than read as "default".
		TrustedProxyHops *int `yaml:"trustedProxyHops"`
		// MaxSessions caps concurrent client sessions. 0 ⟹ unlimited; an initialize beyond
		// the cap is refused with 503. HTTP transport only. Pointer so an explicit 0 is
		// distinguishable from "unset" (where the --max-sessions backstop applies).
		MaxSessions *int `yaml:"maxSessions"`
		// SessionIdleTimeoutMs reaps a session whose host has sent no request for this many
		// milliseconds, closing its upstream. 0 ⟹ no idle reaping. HTTP transport only.
		//
		// The same sweep also reclaims KILLED sessions: a kill this instance did not serve
		// locally reaches it only through the kill store, so a deployment taking kills
		// through Redis needs a non-zero value or a killed session's slot stays pinned
		// until the process exits (traffic is denied throughout regardless — this is
		// resource reclaim, not enforcement). Pointer so an explicit 0 is distinguishable
		// from "unset" (where the --session-idle-timeout flag applies).
		SessionIdleTimeoutMs *int `yaml:"sessionIdleTimeoutMs"`
	} `yaml:"listen"`

	Audit struct {
		Log             string `yaml:"log"`
		KeyPath         string `yaml:"keyPath"`
		RotateSizeBytes int64  `yaml:"rotateSizeBytes"`
		// RetainRotated bounds how many rotated audit files are kept; the oldest beyond
		// this count are deleted. 0 ⟹ keep every rotated file. The active log is never
		// counted or deleted. Pointer so an explicit 0 overrides the --audit-retain flag.
		RetainRotated *int `yaml:"retainRotated"`
	} `yaml:"audit"`

	Defaults  RouteDefaults    `yaml:"defaults"`
	Upstreams []UpstreamConfig `yaml:"upstreams"`

	// BaseDir is the directory of the config file this was loaded from, stamped by
	// LoadGatewayConfig. Relative `policy:` paths resolve against it, not the process cwd.
	BaseDir string `yaml:"-"`
}

// RouteDefaults are applied to every upstream unless overridden per-route.
type RouteDefaults struct {
	// Enforcement is the posture applied to every route: "enforce" (default) or
	// "audit" (observe — evaluate and log, but forward instead of block).
	Enforcement string `yaml:"enforcement"`

	StrictDrift       bool `yaml:"strictDrift"`
	UpstreamTimeoutMs int  `yaml:"upstreamTimeoutMs"`

	// TaskAnchoredState keys every route's accumulated enforcement state (flow-label taint,
	// sequenceBlock antecedents, quota budgets, spent declassify grants) on the caller's
	// VALIDATED mcp.task_id claim rather than its session, so state survives a hop between
	// enforcement points. Off by default since it changes what every budget MEANS (a maxCalls
	// of 20 becomes 20 per task, not per connection); a token with no task_id is DENIED
	// rather than split across both buckets. See enforcement.WithTaskAnchoredState.
	TaskAnchoredState bool `yaml:"taskAnchoredState"`
}

// UpstreamConfig declares one upstream route.
type UpstreamConfig struct {
	Name string `yaml:"name"`

	Transport string `yaml:"transport"` // "stdio" | "http"

	// stdio transport. Both are passed verbatim to another program, so a bare "$word" is
	// ordinary literal content there and only "${VAR}" is a reference — see envGrammar.
	Command string   `yaml:"command" env:"braced"`
	Args    []string `yaml:"args" env:"braced"`

	// http transport. URL grammar: full in the authority and path, braced-only from the
	// first "?" or "#", so `?$filter=` is neither refused nor silently rewritten.
	UpstreamURL           string `yaml:"upstreamUrl" env:"url"`
	UpstreamAuthHeader    string `yaml:"upstreamAuthHeader"`
	UpstreamTLSSkipVerify bool   `yaml:"upstreamTlsSkipVerify"`

	// policy: one or more capability manifest files, merged in order. Omitting it is only
	// valid when the effective enforcement is "audit": a policyless route with no audit
	// posture fails closed at startup (SEC-05) rather than allowing every call unenforced.
	Policy []string `yaml:"policy"`

	// expectVersion pins the manifest's `version`; a mismatch fails startup. Only supported
	// with a single policy file, where the pin is unambiguous. Empty ⟹ no pin.
	ExpectVersion string `yaml:"expectVersion"`

	// Enforcement is the per-route posture: "enforce" or "audit". Empty ⟹ inherit from
	// defaults. "audit" is also the only posture under which a route may omit `policy:`.
	Enforcement string `yaml:"enforcement"`

	// EffectReceiptKeys is a path to a JWKS document holding THIS upstream's
	// receipt-signing public keys (`io.eunolabs.effect-receipt` in a tool result's `_meta`),
	// verified for signature and consistency with the contract the decision used.
	// Deliberately per-upstream and NOT the caller-authenticating JWKS — a receipt is a
	// statement by the server about its own behavior, closer to package signing than to an
	// access token — and a local FILE, never a URL, since fetching it would add a network
	// dependency behind a check whose value is that it is local. Empty disables receipt
	// handling entirely for the route.
	EffectReceiptKeys string `yaml:"effectReceiptKeys"`

	// ProtocolVersion pins the MCP protocol revision eunox speaks to THIS upstream:
	// "auto" (the default, and what an omitted key means) probes it from the upstream's own
	// handshake, or name a revision to override the probe. Per upstream, not per gateway,
	// because a gateway's upstreams migrate on independent schedules — serving a pair that
	// disagrees is the deployment a proxy exists for.
	ProtocolVersion string `yaml:"protocolVersion"`

	// Per-route overrides. Pointer ⟹ "unset, inherit from defaults".
	StrictDrift *bool `yaml:"strictDrift"`
	// TaskAnchoredState overrides RouteDefaults.TaskAnchoredState for this route: the anchor
	// is a property of a route's own topology (delegated sub-agents sharing a task vs. a
	// single host session), so forcing one anchor on both would strand or pool state wrongly.
	TaskAnchoredState *bool `yaml:"taskAnchoredState"`
}

// mcpbBundleMagic is the local-file-header signature that begins every ZIP archive. Claude
// Desktop's Desktop Extension bundles (.mcpb/.dxt) are ZIP archives, and a common install-time
// mistake is pointing --config at the bundle instead of an eunox.yaml; detecting it lets the
// loader fail with guidance rather than yaml.v3's opaque "control characters are not allowed".
var mcpbBundleMagic = []byte{'P', 'K', 0x03, 0x04}

// errIfBinaryConfig returns an actionable error when data is plainly not a text config — a
// ZIP/.mcpb bundle or other binary file. kind labels the file in the error message. Returns
// nil for anything that could plausibly be text, leaving real parse errors to the parser.
func errIfBinaryConfig(kind, path string, data []byte) error {
	if bytes.HasPrefix(data, mcpbBundleMagic) {
		return fmt.Errorf("%s %q looks like a ZIP archive (a Claude Desktop .mcpb/.dxt extension bundle), not a text config — point eunox at your eunox.yaml, not the downloaded .mcpb bundle. Scaffold one with: eunox init --upstream-url <url> --output manifest.yaml --config-output eunox.yaml", kind, path)
	}
	// A NUL byte never appears in valid YAML/JSON text, so its presence means binary content.
	if bytes.IndexByte(data, 0x00) >= 0 {
		return fmt.Errorf("%s %q is not a text config file (it contains NUL bytes) — point eunox at your eunox.yaml", kind, path)
	}
	return nil
}

// gatewaySchemaVersionFromNode reads the top-level schemaVersion scalar's VERBATIM text off
// the already-parsed document, plus whether it was written as a bare number (YAML auto-types
// an unquoted 0.1 as !!float). Verbatim matters: "0.10" must not renormalize to "0.1".
func gatewaySchemaVersionFromNode(root *yaml.Node) (version string, numeric bool) {
	val := topLevelValueNode(root, "schemaVersion")
	if val == nil || val.Kind != yaml.ScalarNode {
		return "", false
	}
	return val.Value, val.Tag == "!!int" || val.Tag == "!!float"
}

// gatewayConfigRawFields holds every env-ref-bearing field's PRE-expansion text, captured
// before expandEnvInStrings overwrites cfg's string fields in place. LoadGatewayConfig's
// unset-reference guards need the raw text (not the expanded value) to tell an operator-set
// variable whose value happens to be empty from a reference that was never set at all.
type gatewayConfigRawFields struct {
	authToken      string
	auditLog       string
	auditKeyPath   string
	allowedOrigins []string
	// upstreamAuth/upstreamURL/command/args are per-upstream, indexed like cfg.Upstreams.
	upstreamAuth []string
	upstreamURL  []string
	command      []string
	args         [][]string
}

// captureGatewayConfigRawFields snapshots cfg's env-ref-bearing fields before expansion. See
// gatewayConfigRawFields.
func captureGatewayConfigRawFields(cfg *GatewayConfig) gatewayConfigRawFields {
	f := gatewayConfigRawFields{
		authToken:      cfg.Listen.AuthToken,
		auditLog:       cfg.Audit.Log,
		auditKeyPath:   cfg.Audit.KeyPath,
		allowedOrigins: slices.Clone(cfg.Listen.AllowedOrigins),
		upstreamAuth:   make([]string, len(cfg.Upstreams)),
		upstreamURL:    make([]string, len(cfg.Upstreams)),
		command:        make([]string, len(cfg.Upstreams)),
		args:           make([][]string, len(cfg.Upstreams)),
	}
	for i := range cfg.Upstreams {
		f.upstreamAuth[i] = cfg.Upstreams[i].UpstreamAuthHeader
		f.upstreamURL[i] = cfg.Upstreams[i].UpstreamURL
		f.command[i] = cfg.Upstreams[i].Command
		f.args[i] = slices.Clone(cfg.Upstreams[i].Args)
	}
	return f
}

// LoadGatewayConfig reads, parses, env-expands, and validates a gateway config.
// ${VAR}/$VAR references are expanded from the environment AFTER parsing — on the decoded
// string values, not the raw text — so an env value can never be re-interpreted as YAML syntax.
// An unset reference is left untouched rather than blanked. See expandEnvRefs/envRefRe.
func LoadGatewayConfig(path string) (*GatewayConfig, error) {
	raw, err := ReadBoundedFile(BoundedRead{
		Path:      path,
		What:      "gateway config",
		Max:       maxGatewayConfigFileBytes,
		OverLimit: "refusing to buffer it rather than parsing a gateway config that cannot be one",
	})
	if err != nil {
		return nil, err
	}
	if err := errIfBinaryConfig("gateway config", path, raw); err != nil {
		return nil, err
	}

	// Gate on the declared grammar version BEFORE the strict decode (mirroring the manifest
	// loader's ordering): without this, a config written for a FUTURE grammar is reported as
	// a typo ("field xyz not found") rather than an unsupported dialect. Read from the NODE,
	// not a `string`-typed probe struct: an unquoted `schemaVersion: 0.1` auto-types !!float,
	// which a string-typed decode would fail to swallow silently, skipping the gate.
	//
	// ONE parse into a node, shared by every check that must see the document as WRITTEN
	// rather than decoded (this pre-read, the numeric-coercion guard, the key-presence map
	// below); each used to re-parse the same bytes. A document that fails to parse falls
	// through with parsed=false to the strict decode, which reports its own syntax error.
	var root yaml.Node
	parsed := yaml.Unmarshal(raw, &root) == nil
	var version string
	var numericVersion bool
	if parsed {
		version, numericVersion = gatewaySchemaVersionFromNode(&root)
		if err := validateGatewaySchemaVersion(version); err != nil {
			return nil, fmt.Errorf("invalid gateway config %q: %w", path, err)
		}
	}
	if numericVersion {
		// The version is one this binary speaks, but spelled as a bare number, which the
		// strict decode below cannot put in a string field. (The manifest loader instead
		// retags the scalar in place; this loader needs the Decoder's KnownFields strictness
		// and so must decode from the raw bytes.)
		return nil, fmt.Errorf("invalid gateway config %q: schemaVersion %s must be quoted (schemaVersion: %q) — YAML reads a bare %s as a number, which is not a version string", path, version, version, version)
	}

	// Decode strictly: unknown keys are an error, mirroring the schema's
	// "additionalProperties": false.
	var cfg GatewayConfig
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		// io.EOF ⟹ empty document; fall through to validate(), which reports the
		// missing `upstreams` with a clearer message than a bare EOF.
		return nil, fmt.Errorf("parsing gateway config %q: %w", path, err)
	}

	// Reject a multi-document stream: a real second document would be silently ignored,
	// so an appended restrictive config would boot while enforcing none of it. A trailing
	// empty document (a bare "---") carries nothing enforceable and is tolerated.
	if err := rejectExtraYAMLDocuments(dec, path, "gateway config"); err != nil {
		return nil, err
	}

	// Reject an unquoted numeric field YAML silently auto-typed away from its written text —
	// most dangerously a leading-zero value read as OCTAL (port: 0755 binds 493, not 755).
	// The strict struct decode above accepts the coerced integer with no signal.
	if parsed {
		if err := rejectCoercedGatewayNumerics(&root, path); err != nil {
			return nil, err
		}
	}

	// Capture every env-ref-bearing field's pre-expansion text, so the unset-reference guards
	// below can tell an empty/unset variable from one legitimately omitted — expandEnvInStrings
	// overwrites cfg's string fields in place next.
	rawFields := captureGatewayConfigRawFields(&cfg)

	// Expand on the PARSED string values, never the raw text: substituting into the text
	// before parsing let a YAML metacharacter in a secret alter the parse (e.g. "#secret"
	// read as a comment, silently blanking listen.authToken).
	expandEnvInStrings(reflect.ValueOf(&cfg).Elem(), envGrammarFull)

	// Fail closed if listen.authToken references a variable that leaves the credential
	// blank (unset, expanded to "", or every reference set but blank): a blank result would
	// otherwise silently start the listener with no bearer-token auth. Scoped to HTTP since
	// only it has a listener. See validateCredentialEnvRefs.
	if cfg.HostTransport() == HostTransportHTTP {
		if err := validateCredentialEnvRefs(path, "listen.authToken", rawFields.authToken, listenAuthTokenEnvGrammar); err != nil {
			return nil, err
		}
	}

	// Apply the same unset/empty-expansion detection to each http upstream's
	// upstreamAuthHeader that listen.authToken gets above: an unset/blank ref yields an
	// auth header the upstream rejects on every call. Fail closed.
	for i := range cfg.Upstreams {
		raw := rawFields.upstreamAuth[i]
		if raw == "" || cfg.Upstreams[i].Transport != "http" {
			continue
		}
		label := fmt.Sprintf("upstream %q upstreamAuthHeader", cfg.Upstreams[i].Name)
		if err := validateCredentialEnvRefs(path, label, raw, upstreamAuthHeaderEnvGrammar); err != nil {
			return nil, err
		}
	}

	// Fail closed on an unresolved env reference left in an upstreamUrl. An unset $VAR/${VAR}
	// survives expansion as literal text that can still satisfy url.Parse (a valid-looking
	// scheme+host), so the gateway would otherwise boot a route pointed at literal "${VAR}"
	// text. Detect on the RAW pre-expansion text, not the expanded value, so a set variable
	// whose value itself contains "$" is not misdiagnosed as unset. The QUERY and FRAGMENT
	// take the braced-only rule, since "?$filter=" is a perfectly good OData URL.
	for i := range cfg.Upstreams {
		if err := failOnUnsetEnvRefUnder(path, fmt.Sprintf("upstream %q upstreamUrl", cfg.Upstreams[i].Name), rawFields.upstreamURL[i], upstreamURLEnvGrammar); err != nil {
			return nil, err
		}
	}

	// The argv and Origin legs of the same rule, kept together in one helper.
	if err := failOnUnsetArgvAndOriginEnvRefs(path, &cfg, rawFields.command, rawFields.args, rawFields.allowedOrigins); err != nil {
		return nil, err
	}

	// Fail closed on an unset env reference in the audit log or key path: an unset
	// ${VAR}/$VAR survives as literal text, silently misdirecting the tamper-evident tape or
	// its HMAC key. Mirrors the upstreamUrl leg, detecting on the RAW text.
	for _, f := range []struct {
		label, raw string
		grammar    envGrammar
	}{
		{"audit.log", rawFields.auditLog, auditLogEnvGrammar},
		{"audit.keyPath", rawFields.auditKeyPath, auditKeyPathEnvGrammar},
	} {
		if err := failOnUnsetEnvRefUnder(path, f.label, f.raw, f.grammar); err != nil {
			return nil, err
		}
	}

	// The strict decode can't tell an explicit zero (command: "", args: []) from an absent
	// key. Re-read which keys each upstream actually wrote so validate() can reject
	// forbidden transport fields on key *presence*, as the JSON Schema does.
	present, err := upstreamKeyPresence(&root)
	if err != nil {
		return nil, fmt.Errorf("parsing gateway config %q: %w", path, err)
	}
	// present is derived from the NODE while cfg.Upstreams comes from the strict Decoder, so
	// the two readings could disagree on a future YAML feature; assert lengths match rather
	// than assume it, so a mismatch cannot silently check one upstream against another's keys.
	if len(present) != len(cfg.Upstreams) {
		return nil, fmt.Errorf("parsing gateway config %q: internal upstream-count mismatch (%d typed vs %d presence entries)", path, len(cfg.Upstreams), len(present))
	}
	if err := cfg.Validate(present); err != nil {
		return nil, fmt.Errorf("invalid gateway config %q: %w", path, err)
	}
	// Record the config file's directory so relative `policy:` paths resolve against
	// it rather than the process cwd (see GatewayConfig.BaseDir). Set after Validate so
	// a malformed config still errors out first.
	cfg.BaseDir = filepath.Dir(path)
	return &cfg, nil
}

// ContainsEnvRef reports whether s still contains an unexpanded ${VAR}/$VAR reference. After
// LoadGatewayConfig's expansion pass, a residual reference means the variable was unset;
// callers that publish the value (e.g. OAuth authorization-server URIs) use this to fail closed.
func ContainsEnvRef(s string) bool {
	return len(realEnvRefs(s)) > 0
}

// realEnvRefs returns every envRefRe match in s that is an actual variable reference,
// dropping the "$$" escapes, so an escape can never be mistaken for a reference named "$".
// recognizedEnvRefs is realEnvRefs restricted to the spellings g recognizes — the same
// predicate the expansion applies, so a field's guard and its expansion agree on what is a
// reference. The URL grammar's positional split is applied here too, via splitURLEnvScope.
func recognizedEnvRefs(s string, g envGrammar) []string {
	if g == envGrammarURL {
		head, tail := splitURLEnvScope(s)
		return append(recognizedEnvRefs(head, envGrammarFull), recognizedEnvRefs(tail, envGrammarBraced)...)
	}
	refs := realEnvRefs(s)
	out := refs[:0]
	for _, ref := range refs {
		if recognizedRef(ref, g) {
			out = append(out, ref)
		}
	}
	return out
}

func realEnvRefs(s string) []string {
	matches := envRefRe.FindAllString(s, -1)
	refs := matches[:0]
	for _, m := range matches {
		if !isEnvRefEscape(m) {
			refs = append(refs, m)
		}
	}
	return refs
}

// firstUnsetEnvRefUnder scans rawValue's raw (pre-expansion) text for the references a field's
// declared grammar RECOGNIZES and returns the name of the first one whose variable is unset. ok
// is false when every recognized reference resolved to a set variable. The single
// walk-and-check-unset core shared by validateCredentialEnvRefs and every path-family guard, so
// "what counts as unset" cannot drift between them.
func firstUnsetEnvRefUnder(rawValue string, g envGrammar) (name string, ok bool) {
	if g == envGrammarURL {
		head, tail := splitURLEnvScope(rawValue)
		if n, found := firstUnsetEnvRefUnder(head, envGrammarFull); found {
			return n, true
		}
		return firstUnsetEnvRefUnder(tail, envGrammarBraced)
	}
	for _, ref := range recognizedEnvRefs(rawValue, g) {
		// envRefRe guarantees at least one identifier character, so envRefName cannot return
		// "" — a "defensive" skip here would be the fail-OPEN direction this guard refuses.
		n := envRefName(ref)
		if _, set := os.LookupEnv(n); !set {
			return n, true
		}
	}
	return "", false
}

// failOnUnsetEnvRefUnder fails closed when raw carries, under the field's declared grammar, a
// reference whose variable is unset — so a path or URL never silently resolves to one literally
// named "${VAR}". Single source of the operator-facing message for the path-family fields;
// the credential fields use validateCredentialEnvRefs instead, whose message differs. path
// names the config file; label names the field.
func failOnUnsetEnvRefUnder(path, label, raw string, g envGrammar) error {
	if name, ok := firstUnsetEnvRefUnder(raw, g); ok {
		return unsetEnvRefError(path, label, name)
	}
	return nil
}

// failOnUnsetArgvAndOriginEnvRefs fails closed on an unset environment reference in a stdio
// upstream's command/args or in listen.allowedOrigins — the expanded fields with no other
// guard, each of which otherwise boots cleanly and fails later far from the config: command/args
// fails at exec time on the first session, and an unset allowedOrigins entry matches no real
// Origin header, giving a browser client a bare 403 with nothing connecting it to the typo.
//
// command/args DECLARE the braced-only grammar (see envGrammar), since they are arbitrary
// subprocess argv where a bare "$word" is ordinary literal content; allowedOrigins keeps the
// full grammar, since an Origin (RFC 6454) carries no legitimate bare "$" to protect.
//
// This family is hand-maintained while expandEnvInStrings rewrites every string in the tree,
// so a field is covered only once added — most others fail at startup for their own reasons
// (routeNameRe, net.Listen, LoadManifest, ParseCIDR), which is why the remaining gaps are quiet.
func failOnUnsetArgvAndOriginEnvRefs(path string, cfg *GatewayConfig, rawCommand []string, rawArgs [][]string, rawAllowedOrigins []string) error {
	for i := range cfg.Upstreams {
		name := cfg.Upstreams[i].Name
		if err := failOnUnsetEnvRefUnder(path, fmt.Sprintf("upstream %q command", name), rawCommand[i], upstreamCommandEnvGrammar); err != nil {
			return err
		}
		for j, rawArg := range rawArgs[i] {
			if err := failOnUnsetEnvRefUnder(path, fmt.Sprintf("upstream %q args[%d]", name, j), rawArg, upstreamArgsEnvGrammar); err != nil {
				return err
			}
		}
	}
	for i, rawOrigin := range rawAllowedOrigins {
		if err := failOnUnsetEnvRefUnder(path, fmt.Sprintf("listen.allowedOrigins[%d]", i), rawOrigin, allowedOriginsEnvGrammar); err != nil {
			return err
		}
	}
	return nil
}

// unsetEnvRefError is the single operator-facing message for an unset reference, shared
// by the full and braced-only guards so the two cannot drift on wording.
func unsetEnvRefError(path, label, name string) error {
	return fmt.Errorf("invalid gateway config %q: %s references environment variable %q, which is unset, so it is left as literal text — set the variable, remove the reference, or write \"$$\" for a literal dollar sign", path, label, name)
}

// validateCredentialEnvRefs fails closed when a credential field built from $VAR/${VAR}
// references would start the gateway with no real secret. Single source of truth for the
// listen.authToken and upstreamAuthHeader legs, which enforce the identical rule and differ
// only in label. rawValue is the pre-expansion text (detected raw so an expanded
// "$identifier" substring in a real secret cannot false-positive). The two fail-closed cases:
// a referenced variable is UNSET (the "${VAR}" literal survives), or EVERY referenced
// variable is set but blank — so "Bearer ${T}" expands non-empty yet carries no secret.
func validateCredentialEnvRefs(path, label, rawValue string, g envGrammar) error {
	if name, ok := firstUnsetEnvRefUnder(rawValue, g); ok {
		return fmt.Errorf("invalid gateway config %q: %s references environment variable %q, which is unset, so it is left as literal text — the field would require a literal token no client/upstream sends; set the variable, or remove the reference", path, label, name)
	}
	// Every reference is confirmed set by firstUnsetEnvRefUnder above, so os.LookupEnv
	// below always succeeds; this pass only tracks blankness.
	refs := recognizedEnvRefs(rawValue, g)
	sawNonEmptyRef := false
	for _, ref := range refs {
		val, _ := os.LookupEnv(envRefName(ref))
		// A whitespace-only value is blank: a credential of only spaces/tabs is no secret.
		if strings.TrimSpace(val) != "" {
			sawNonEmptyRef = true
		}
	}
	// A reference set to "" or whitespace with surrounding literal text (e.g. "Bearer ${T}")
	// expands non-empty, so reject only when EVERY referenced variable is blank.
	if len(refs) > 0 && !sawNonEmptyRef {
		return fmt.Errorf("invalid gateway config %q: every environment variable referenced by %s is set to the empty string or only whitespace, so the credential expanded to literal text with no secret value — refusing to start with a blank credential; set a referenced variable to a non-empty value, or remove %s", path, label, label)
	}
	return nil
}

// rejectExtraYAMLDocuments drains dec after the first document and rejects any further
// document carrying real content, so an appended second config/manifest is never silently
// ignored. A trailing empty/null document decodes to a nil value and is tolerated; the loop
// drains every separator so a real document behind any number of empties is still caught.
// what names the artifact for the error message (e.g. "gateway config").
func rejectExtraYAMLDocuments(dec *yaml.Decoder, path, what string) error {
	for {
		var doc interface{}
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("parsing %s %q: %w", what, path, err)
		}
		if doc != nil {
			return fmt.Errorf("parsing %s %q: multiple YAML documents are not supported", what, path)
		}
	}
}

// upstreamKeyPresence re-parses raw to record, per upstream, exactly which YAML keys were
// written — including keys whose value decodes to a zero, which the strict typed decode
// cannot distinguish from an absent key. Lets validate() reject what the JSON Schema's
// "<field>": false does.
func upstreamKeyPresence(root *yaml.Node) ([]map[string]bool, error) {
	var doc struct {
		Upstreams []map[string]any `yaml:"upstreams"`
	}
	if err := root.Decode(&doc); err != nil {
		return nil, err
	}
	present := make([]map[string]bool, 0, len(doc.Upstreams))
	for i, entry := range doc.Upstreams {
		// A null/empty list element (`- null`, a bare dangling `-`) is silently dropped by
		// the strict typed decoder but kept here as a nil map, desyncing the two slices and
		// tripping the count-mismatch guard with a confusing message. Reject it explicitly.
		if entry == nil {
			return nil, fmt.Errorf("upstream[%d]: entry is empty (a null or bare '-' list item); give it a name/transport/upstreamUrl, or remove it", i)
		}
		keys := make(map[string]bool, len(entry))
		for k := range entry {
			keys[k] = true
		}
		present = append(present, keys)
	}
	return present, nil
}

// Validate checks structural and cross-field invariants. presentKeys, when non-nil, lists the
// YAML keys actually written per upstream so the cross-transport checks can reject a forbidden
// field on *presence*, matching the JSON Schema. A nil presentKeys (a programmatically-built
// config) falls back to rejecting only a non-zero decoded value.
func (cfg *GatewayConfig) Validate(presentKeys []map[string]bool) error {
	// Gate on the declared grammar version first: an unrecognized dialect is
	// refused before any structural interpretation.
	if err := validateGatewaySchemaVersion(cfg.SchemaVersion); err != nil {
		return err
	}
	// Canonicalize to the trimmed form validation accepted, so a padded quoted
	// scalar (e.g. " 0.1") does not survive into downstream exact-string compares.
	cfg.SchemaVersion = strings.TrimSpace(cfg.SchemaVersion)
	if len(cfg.Upstreams) == 0 {
		return fmt.Errorf("at least one upstream is required")
	}
	// Host-facing transport. Default http; stdio has no network listener and
	// fronts exactly one upstream.
	switch cfg.Transport {
	case "", HostTransportHTTP, HostTransportStdio:
	default:
		return fmt.Errorf("transport must be %q or %q, got %q", HostTransportStdio, HostTransportHTTP, cfg.Transport)
	}
	if cfg.HostTransport() == HostTransportStdio {
		if cfg.Listen.Bind != "" || cfg.Listen.Port != 0 || cfg.Listen.AuthToken != "" ||
			cfg.Listen.OAuthResource != "" || len(cfg.Listen.OAuthAuthorizationServers) > 0 ||
			len(cfg.Listen.AllowedOrigins) > 0 || cfg.Listen.MaxSessions != nil ||
			cfg.Listen.SessionIdleTimeoutMs != nil || len(cfg.Listen.TrustedProxyCIDRs) > 0 ||
			cfg.Listen.TrustedProxyHops != nil {
			return fmt.Errorf("transport: stdio has no network listener — remove the 'listen' block " +
				"(bind/port/authToken/oauthResource/oauthAuthorizationServers/allowedOrigins/maxSessions/sessionIdleTimeoutMs/trustedProxyCIDRs/trustedProxyHops)")
		}
		if len(cfg.Upstreams) != 1 {
			return fmt.Errorf("transport: stdio fronts exactly one upstream, got %d", len(cfg.Upstreams))
		}
	}
	for _, cidr := range cfg.Listen.TrustedProxyCIDRs {
		ip, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("listen.trustedProxyCIDRs: invalid CIDR %q: %w", cidr, err)
		}
		// net.ParseCIDR silently masks host bits, so "10.0.0.5/8" behaves as "10.0.0.0/8" —
		// usually a /32-vs-network mistake that would widen this trust boundary silently.
		if !ip.Equal(network.IP) {
			return fmt.Errorf("listen.trustedProxyCIDRs: CIDR %q has host bits set; use the network address %q, or /32 to trust just that host", cidr, network.String())
		}
	}
	// A hop count below 1 leaves no proxy-written entry to read, so it is meaningless rather
	// than a usable "off" switch (that's --trust-forwarded-for, or an empty trustedProxyCIDRs).
	if h := cfg.Listen.TrustedProxyHops; h != nil && *h < 1 {
		return fmt.Errorf("listen.trustedProxyHops must be at least 1, got %d; omit the key for a single proxy, "+
			"or drop --trust-forwarded-for to stop trusting the header entirely", *h)
	}
	if cfg.HostTransport() == HostTransportHTTP && cfg.Listen.Port != 0 {
		if cfg.Listen.Port < 1 || cfg.Listen.Port > 65535 {
			return fmt.Errorf("listen.port %d is out of range [1, 65535]", cfg.Listen.Port)
		}
	}
	// A non-empty but whitespace-only authToken is a degenerate secret: not "", so it is
	// enforced as the required bearer, yet trivially guessable. Mirrors the env-ref leg's
	// blank-credential rejection for a LITERAL whitespace token.
	if cfg.HostTransport() == HostTransportHTTP && cfg.Listen.AuthToken != "" && strings.TrimSpace(cfg.Listen.AuthToken) == "" {
		return fmt.Errorf("listen.authToken is whitespace-only, which is not a usable bearer secret — set a real token, or omit authToken to run without token auth")
	}
	if cfg.Listen.MaxSessions != nil && *cfg.Listen.MaxSessions < 0 {
		return fmt.Errorf("listen.maxSessions %d must not be negative (0 = unlimited)", *cfg.Listen.MaxSessions)
	}
	if cfg.Listen.SessionIdleTimeoutMs != nil {
		if *cfg.Listen.SessionIdleTimeoutMs < 0 {
			return fmt.Errorf("listen.sessionIdleTimeoutMs %d must not be negative (0 = no idle reaping)", *cfg.Listen.SessionIdleTimeoutMs)
		}
		// A value that overflows time.Duration when scaled by time.Millisecond wraps
		// negative, making the reaper close every session on sight.
		if int64(*cfg.Listen.SessionIdleTimeoutMs) > MaxDurationMs {
			return fmt.Errorf("listen.sessionIdleTimeoutMs %d exceeds the maximum %d ms (it would overflow the idle timer)", *cfg.Listen.SessionIdleTimeoutMs, MaxDurationMs)
		}
	}
	// A negative maxBytes makes the audit sink's size check true for every record, rotating
	// the log on every line written and flooding the log directory; 0 stays valid (default).
	if cfg.Audit.RotateSizeBytes < 0 {
		return fmt.Errorf("audit.rotateSizeBytes %d must not be negative (0 = use the default size; positive values set the rotation threshold in bytes)", cfg.Audit.RotateSizeBytes)
	}
	if cfg.Audit.RetainRotated != nil && *cfg.Audit.RetainRotated < 0 {
		return fmt.Errorf("audit.retainRotated %d must not be negative (0 = keep all rotated files)", *cfg.Audit.RetainRotated)
	}
	// Defaults posture: validate the enforcement value.
	if !validEnforcementValue(cfg.Defaults.Enforcement) {
		return fmt.Errorf("defaults: invalid enforcement %q — valid values are %q or %q", cfg.Defaults.Enforcement, capability.EnforcementEnforce, capability.EnforcementAudit)
	}
	// resolveUpstreamTimeout treats <= 0 as "unset" and would silently coerce a negative
	// value to the built-in default with no diagnostic; reject it up front instead.
	if cfg.Defaults.UpstreamTimeoutMs < 0 {
		return fmt.Errorf("defaults.upstreamTimeoutMs %d must not be negative (0 = use the built-in default)", cfg.Defaults.UpstreamTimeoutMs)
	}
	if int64(cfg.Defaults.UpstreamTimeoutMs) > MaxDurationMs {
		return fmt.Errorf("defaults.upstreamTimeoutMs %d exceeds the maximum %d ms (it would overflow the upstream-call timeout)", cfg.Defaults.UpstreamTimeoutMs, MaxDurationMs)
	}
	// presentKey reports whether upstream i wrote key in the source document; nil presentKeys
	// (a synthesized config) ⟹ false, covered by the value fallbacks.
	presentKey := func(i int, key string) bool {
		return i < len(presentKeys) && presentKeys[i][key]
	}
	seen := make(map[string]bool, len(cfg.Upstreams))
	for i := range cfg.Upstreams {
		if err := cfg.validateUpstreamEntry(i, &cfg.Upstreams[i], seen, presentKey); err != nil {
			return err
		}
	}
	return nil
}

func (cfg *GatewayConfig) validateUpstreamEntry(i int, u *UpstreamConfig, seen map[string]bool, presentKey func(int, string) bool) error {
	switch {
	case u.Name == "":
		return fmt.Errorf("upstream[%d]: 'name' is required", i)
	case !routeNameRe.MatchString(u.Name):
		return fmt.Errorf("upstream %q: name must match %s (it is used as the /mcp/<name> URL path)", u.Name, routeNameRe.String())
	case seen[u.Name]:
		return fmt.Errorf("duplicate upstream name %q", u.Name)
	}
	seen[u.Name] = true

	// Per-route posture: same rule as defaults.
	if !validEnforcementValue(u.Enforcement) {
		return fmt.Errorf("upstream %q: invalid enforcement %q — valid values are %q or %q", u.Name, u.Enforcement, capability.EnforcementEnforce, capability.EnforcementAudit)
	}

	// The protocol pin is refused at LOAD, not at the first request: a revision this build
	// cannot speak would otherwise fall back to the probe and silently serve the upstream
	// under a revision the operator did not name.
	if err := validateProtocolVersion(u.Name, u.ProtocolVersion); err != nil {
		return err
	}

	switch u.Transport {
	case "stdio":
		if u.Command == "" {
			return fmt.Errorf("upstream %q: stdio transport requires 'command'", u.Name)
		}
		// HTTP-only fields are rejected on key presence (not just a non-zero value) so the
		// loader refuses exactly what the schema's "<field>": false refuses.
		if presentKey(i, "upstreamUrl") || u.UpstreamURL != "" {
			return fmt.Errorf("upstream %q: 'upstreamUrl' is not allowed with stdio transport (HTTP-only)", u.Name)
		}
		if presentKey(i, "upstreamAuthHeader") || u.UpstreamAuthHeader != "" {
			return fmt.Errorf("upstream %q: 'upstreamAuthHeader' is not allowed with stdio transport (HTTP-only)", u.Name)
		}
		if presentKey(i, "upstreamTlsSkipVerify") || u.UpstreamTLSSkipVerify {
			return fmt.Errorf("upstream %q: 'upstreamTlsSkipVerify' is not allowed with stdio transport (HTTP-only)", u.Name)
		}
	case "http":
		if err := validateHTTPUpstreamURL(u.Name, u.UpstreamURL); err != nil {
			return err
		}
		// A non-empty but whitespace-only upstreamAuthHeader is the upstream leg of the
		// degenerate-credential case listen.authToken rejects above: not "", so it forwards
		// as a real header, yet "Authorization:   " carries no secret.
		if u.UpstreamAuthHeader != "" && strings.TrimSpace(u.UpstreamAuthHeader) == "" {
			return fmt.Errorf("upstream %q: 'upstreamAuthHeader' is whitespace-only, which is not a usable credential — set a real header value, or omit the field to forward no auth header", u.Name)
		}
		// stdio-only fields are rejected on key presence so an explicit zero is refused too.
		if presentKey(i, "command") || u.Command != "" {
			return fmt.Errorf("upstream %q: 'command' is not allowed with http transport (stdio-only)", u.Name)
		}
		if presentKey(i, "args") || u.Args != nil {
			return fmt.Errorf("upstream %q: 'args' is not allowed with http transport (stdio-only)", u.Name)
		}
	case "":
		return fmt.Errorf("upstream %q: 'transport' is required (\"stdio\" or \"http\")", u.Name)
	default:
		return fmt.Errorf("upstream %q: transport must be \"stdio\" or \"http\", got %q", u.Name, u.Transport)
	}

	// Reject an empty or whitespace-only policy entry at load: it has len==1, so it slips
	// past the no-policy classification (NoPolicyStartupRejection, keyed on len==0) and
	// later dies with a misleading "is a directory" error from ResolvePolicyPath instead.
	for _, p := range u.Policy {
		if strings.TrimSpace(p) == "" {
			return fmt.Errorf("upstream %q: 'policy' contains an empty entry; each policy entry must be a manifest file path (an empty entry is often a ${VAR} that expanded to empty, or a stray \"\")", u.Name)
		}
	}

	// expectVersion pins a single manifest's `version`; with multiple files MergeManifests
	// takes only the first file's version, so reject the ambiguous multi-file case.
	if u.ExpectVersion != "" && len(u.Policy) > 1 {
		return fmt.Errorf("upstream %q: 'expectVersion' is only supported with a single policy file; "+
			"with %d files the pin is ambiguous (only the first file's version is compared) — "+
			"use a single merged policy file, or remove 'expectVersion'", u.Name, len(u.Policy))
	}
	return nil
}

// ProtocolVersionAuto is the upstream `protocolVersion` value — and the meaning of an
// omitted key — that probes the revision from the upstream's own handshake instead of
// pinning one. Spelled out rather than left as "" so an operator can write the default
// explicitly and a reader can tell "probe" from "not yet configured".
const ProtocolVersionAuto = "auto"

// validateProtocolVersion refuses an upstream `protocolVersion` that is neither the auto
// sentinel nor a revision this build speaks. The error names the accepted set, since the
// value is a date this build either knows or does not and guessing is unhelpful.
func validateProtocolVersion(name, value string) error {
	if value == "" || value == ProtocolVersionAuto {
		return nil
	}
	if _, ok := capability.ParseRevision(value); ok {
		return nil
	}
	supported := capability.PublishedRevisions()
	names := make([]string, 0, len(supported)+1)
	names = append(names, ProtocolVersionAuto)
	for _, rev := range supported {
		names = append(names, rev.String())
	}
	return fmt.Errorf("upstream %q: invalid protocolVersion %q — valid values are %s", name, value, strings.Join(names, ", "))
}

// ValidateProtocolVersionFlag applies the same rule to the CLI's --upstream-protocol-version
// as Validate applies to an upstream's protocolVersion key, so the flag and the config key
// accept exactly the same set. The error names the flag rather than an upstream.
func ValidateProtocolVersionFlag(value string) error {
	if err := validateProtocolVersion("", value); err != nil {
		supported := capability.PublishedRevisions()
		names := make([]string, 0, len(supported)+1)
		names = append(names, ProtocolVersionAuto)
		for _, rev := range supported {
			names = append(names, rev.String())
		}
		return fmt.Errorf("--upstream-protocol-version %q is not a revision this build speaks — valid values are %s", value, strings.Join(names, ", "))
	}
	return nil
}

// ResolvedProtocolVersion returns the operator's explicit protocol-revision pin for this
// upstream, or "" when the revision is to be probed from the handshake. Validate has already
// refused anything else, so the returned string is either empty or a revision this build
// speaks.
func (u *UpstreamConfig) ResolvedProtocolVersion() string {
	if u.ProtocolVersion == ProtocolVersionAuto {
		return ""
	}
	return u.ProtocolVersion
}

// Host-facing transport values for GatewayConfig.Transport.
const (
	HostTransportHTTP  = "http"
	HostTransportStdio = "stdio"
)

// HostTransport returns the resolved host-facing transport, defaulting to http.
func (cfg *GatewayConfig) HostTransport() string {
	if cfg.Transport == "" {
		return HostTransportHTTP
	}
	return cfg.Transport
}

// validateHTTPUpstreamURL returns an error if rawURL is empty, not parseable, does not use an
// http or https scheme, or has no host. The host check rejects "http://" at load rather than
// deferring the no-host failure to the first upstream request.
func validateHTTPUpstreamURL(name, rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("upstream %q: http transport requires 'upstreamUrl'", name)
	}
	parsed, err := url.Parse(rawURL)
	// capability.RedactURLForLog, not the bundle-facing RedactURL: this error goes to a log
	// (stderr), and for a Slack/Telegram webhook the PATH is the credential.
	if err != nil || !strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https") {
		return fmt.Errorf("upstream %q: upstreamUrl must be an http or https URL, got %q", name, capability.RedactURLForLog(rawURL))
	}
	if parsed.Host == "" {
		return fmt.Errorf("upstream %q: upstreamUrl %q has no host", name, capability.RedactURLForLog(rawURL))
	}
	return nil
}

// validEnforcementValue reports whether s is an accepted enforcement posture:
// "" (inherit/default), "enforce", or "audit".
func validEnforcementValue(s string) bool {
	return s == "" || s == capability.EnforcementEnforce || s == capability.EnforcementAudit
}

// AuditModeFor resolves whether one upstream runs in audit (observe) mode from
// the `enforcement` field, with a per-route value overriding defaults.
func (cfg *GatewayConfig) AuditModeFor(u *UpstreamConfig) bool {
	enforcement := u.Enforcement
	if enforcement == "" {
		enforcement = cfg.Defaults.Enforcement
	}
	return enforcement == capability.EnforcementAudit
}

// ResolvedStrictDrift resolves the effective config-declared strictDrift for u (the per-route
// value overriding the default). This is the CONFIG value only; the global --strict-drift
// flag is folded in later (transport.ResolveStrictDrift) and never promotes a policyless route.
func (cfg *GatewayConfig) ResolvedStrictDrift(u *UpstreamConfig) bool {
	return ResolveBool(u.StrictDrift, cfg.Defaults.StrictDrift)
}

// ResolvedTaskAnchoredState resolves the effective task-anchoring posture for u (the per-route
// value overriding the default). See RouteDefaults.TaskAnchoredState for what it changes.
func (cfg *GatewayConfig) ResolvedTaskAnchoredState(u *UpstreamConfig) bool {
	return ResolveBool(u.TaskAnchoredState, cfg.Defaults.TaskAnchoredState)
}

// startupRefusal classifies whether a policyless upstream is refused at startup and by which
// fail-closed guard. SINGLE source of the two guard conditions, so StartupPolicyError (the
// serve paths' hard error) and NoPolicyStartupRejection (validate/doctor's reason string)
// cannot diverge on WHEN a route is refused.
type startupRefusal int

const (
	startupRefusalNone     startupRefusal = iota // may boot
	startupRefusalStrict                         // config-declared strictDrift on a policyless upstream
	startupRefusalNoPolicy                       // policyless upstream not in audit mode
)

// classifyStartupRefusal applies the two fail-closed guard conditions in proxy order
// (strictDrift first, then audit-mode), returning which guard — if any — refuses u. The
// expectVersion-requires-policy guard is excluded; it lives in LoadUpstreamPDP instead.
func (cfg *GatewayConfig) classifyStartupRefusal(u *UpstreamConfig) startupRefusal {
	if len(u.Policy) != 0 {
		return startupRefusalNone
	}
	if cfg.ResolvedStrictDrift(u) {
		return startupRefusalStrict
	}
	if !cfg.AuditModeFor(u) {
		return startupRefusalNoPolicy
	}
	return startupRefusalNone
}

// StartupPolicyError returns the error a host transport must fail startup with for upstream u,
// or nil when u may boot. Both BuildRoutes and serveStdioHost call this so a guard can never
// be added to one serve path but not the other. The verdict comes from classifyStartupRefusal,
// which NoPolicyStartupRejection also consumes, so runtime and validate/doctor cannot diverge.
func (cfg *GatewayConfig) StartupPolicyError(u *UpstreamConfig) error {
	switch cfg.classifyStartupRefusal(u) {
	case startupRefusalStrict:
		return fmt.Errorf("upstream %q: strictDrift requires a policy", u.Name)
	case startupRefusalNoPolicy:
		return fmt.Errorf("upstream %q: no policy configured and enforcement is not %q — "+
			"every call would be allowed unenforced. Add 'policy:' to enforce, "+
			"or set 'enforcement: audit' to run in observe-only (wiretap) mode",
			u.Name, capability.EnforcementAudit)
	}
	return nil
}

// NoPolicyStartupRejection reports why a route with no `policy:` would be refused at startup,
// or "" when it boots cleanly. Consumes the same classifyStartupRefusal verdict as
// StartupPolicyError so validate/doctor classify a config exactly as the proxy would.
//
// Callers must only pass routes with len(u.Policy) == 0.
func (cfg *GatewayConfig) NoPolicyStartupRejection(u *UpstreamConfig) string {
	switch cfg.classifyStartupRefusal(u) {
	case startupRefusalStrict:
		// Only suggest removing strictDrift when audit mode would then let the route
		// boot; otherwise the audit-mode guard still fires, so name both barriers.
		if cfg.AuditModeFor(u) {
			return `strictDrift requires a policy — add 'policy:' or remove 'strictDrift'`
		}
		return `strictDrift requires a policy, and enforcement is not "audit" — add 'policy:' ` +
			`(or both remove 'strictDrift' AND set 'enforcement: audit')`
	case startupRefusalNoPolicy:
		return `no policy and enforcement is not "audit" — add 'policy:' or set 'enforcement: audit'`
	}
	// Not refused by the shared guards; the remaining policyless refusal is the
	// expectVersion pin.
	if u.ExpectVersion != "" {
		return `expectVersion requires a policy — add 'policy:' or remove 'expectVersion'`
	}
	return ""
}
