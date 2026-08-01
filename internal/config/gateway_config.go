// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// eunox config: declare how eunox fronts one or more MCP upstreams.
//
// The top-level `transport` selects the host-facing transport. With
// `transport: http` (default, "gateway" shape) one process fronts N MCP servers,
// each on its own route (POST /mcp/<name>) with its own manifest, writing to one
// shared signed audit tape. With `transport: stdio` eunox speaks MCP over
// stdin/stdout to exactly one upstream. Connection wiring lives here; policy stays
// in the per-route manifest files referenced by `policy:`.
//
// A JSON Schema lives at schemas/eunox-gateway-config.schema.json. Unknown keys
// are rejected at load, mirroring the schema's "additionalProperties": false.
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

// envRefRe matches an escape or a reference: "$$" (a literal '$'), "${NAME}", or
// "$NAME", where NAME is a POSIX-style identifier. A '$' followed by a non-identifier
// char (e.g. "$-", "$!", trailing '$') is left intact.
//
// The "$$" alternative is FIRST so it wins the leftmost-longest match: without it a
// literal '$' was inexpressible, and a config value that legitimately contains one --
// a generated password like "pa$$word" -- had its second "$word" silently expanded
// the moment an unrelated environment variable named "word" happened to be set,
// substituting an attacker-influencable value into a credential. Escaping is the only
// way to make "this is a literal dollar sign" and "this is a reference" distinguishable
// at all; callers write "$$" for a literal '$'.
var envRefRe = regexp.MustCompile(`\$\$|\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*`)

// envRefEscape is the escape sequence for a literal '$'.
const envRefEscape = "$$"

// isEnvRefEscape reports whether an envRefRe match is the "$$" escape rather than a
// variable reference. Every consumer of envRefRe must skip escapes before treating a
// match as a reference name -- expansion, the unset-reference guard, and the blank-
// credential guard all route through this one predicate so they cannot disagree about
// what counts as a reference.
func isEnvRefEscape(match string) bool { return match == envRefEscape }

// envRefName extracts the variable name from a single envRefRe match ("$VAR" or
// "${VAR}"). Shared by expandEnvRefs and validateCredentialEnvRefs so the expansion
// pass and the fail-closed credential guard decode a reference identically — if the
// reference grammar ever changes, both follow the one helper instead of drifting.
func envRefName(match string) string {
	name := match[1:] // strip leading '$'
	if name[0] == '{' {
		name = name[1 : len(name)-1] // strip the surrounding braces
	}
	return name
}

// expandEnvRefs replaces ${VAR} / $VAR with the environment value when VAR is
// set, leaving the reference text intact when unset (unlike os.ExpandEnv, which
// blanks it). See envRefRe for the matching rules.
func expandEnvRefs(s string) string {
	return envRefRe.ReplaceAllStringFunc(s, func(match string) string {
		if isEnvRefEscape(match) {
			return "$" // "$$" collapses to a literal '$'
		}
		if val, ok := os.LookupEnv(envRefName(match)); ok {
			return val
		}
		return match // unset → leave the reference text intact
	})
}

// expandEnvInStrings walks v (which must be addressable) and rewrites every
// string it reaches through expandEnvRefs. Running on the DECODED config rather
// than the raw file text is what makes expansion safe: an env value is
// substituted as opaque data and never re-parsed as YAML (see LoadGatewayConfig).
//
// Only struct/slice/string/pointer kinds are handled, which is all the
// GatewayConfig tree contains. A map or interface field would be silently skipped
// (leaving a secret reference un-expanded);
// TestExpandEnvInStrings_ConfigTreeHasNoUnhandledKinds fails the moment one is
// added, forcing this walk to be extended first. That guard lives in THIS package
// so `go test ./internal/config/` alone catches it — this package is designed to
// build and test standalone, and a guard sitting in another package's tests would
// pass a green run over exactly the field it is meant to catch.
func expandEnvInStrings(v reflect.Value) {
	switch v.Kind() {
	case reflect.String:
		if v.CanSet() {
			v.SetString(expandEnvRefs(v.String()))
		}
	case reflect.Pointer:
		if !v.IsNil() {
			expandEnvInStrings(v.Elem())
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if f := v.Field(i); f.CanSet() { // CanSet skips unexported fields
				expandEnvInStrings(f)
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			expandEnvInStrings(v.Index(i))
		}
	}
}

// gatewayNumericKeys are the gateway-config scalar fields holding a bare number that
// yaml.v3 can auto-type away from the operator's written text — most dangerously a
// leading-zero value read as OCTAL. The gateway-config counterpart to the manifest
// loader's numericPolicyScalarKeys.
var gatewayNumericKeys = map[string]bool{
	"port":                 true, // listen.port
	"maxSessions":          true, // listen.maxSessions
	"sessionIdleTimeoutMs": true, // listen.sessionIdleTimeoutMs
	"trustedProxyHops":     true, // listen.trustedProxyHops
	"rotateSizeBytes":      true, // audit.rotateSizeBytes
	"retainRotated":        true, // audit.retainRotated
	"upstreamTimeoutMs":    true, // defaults.upstreamTimeoutMs
}

// rejectCoercedGatewayNumerics walks a raw gateway-config YAML node and fails closed on
// any gatewayNumericKeys field whose unquoted value YAML silently coerced (a leading-zero
// octal read, a float normalization, …) — the same class the manifest loader rejects via
// checkNumericFieldNotCoerced. A quoted value (the operator disambiguated it to a string)
// is left alone; only an unquoted number that differs textually from its canonical form
// is rejected.
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

// GatewayConfig is the top-level eunox config file.
type GatewayConfig struct {
	// SchemaVersion is the config grammar version (e.g. "0.1"). Required: a config
	// declaring an absent or unsupported schemaVersion is refused at load
	// (fail-closed). See schema_version.go.
	SchemaVersion string `yaml:"schemaVersion"`

	// Transport selects the host-facing transport — how eunox speaks to its MCP
	// host:
	//   "http"  (default): listen on a socket and front N upstreams, each on its
	//           own /mcp/<name> route (the gateway shape).
	//   "stdio": speak MCP over stdin/stdout to exactly one upstream; no socket,
	//           so the `listen` block is rejected.
	// Independent of each upstream's own `transport` (subprocess vs remote HTTP).
	Transport string `yaml:"transport"`

	Listen struct {
		Bind      string `yaml:"bind"`
		Port      int    `yaml:"port"`
		AuthToken string `yaml:"authToken"`
		// OAuthResource is the URI identifying this resource server (RFC 9728).
		// When set, it is included in the protected-resource metadata document
		// served at /.well-known/oauth-protected-resource and anchors the
		// resource_metadata URL in WWW-Authenticate challenges. Never derived
		// from the request Host header.
		OAuthResource string `yaml:"oauthResource"`
		// OAuthAuthorizationServers lists the authorization server URIs published
		// in the protected-resource metadata document. Defaults to --jwt-issuer
		// when not set.
		OAuthAuthorizationServers []string `yaml:"oauthAuthorizationServers"`
		// AllowedOrigins extends the built-in Origin allowlist (loopback names and
		// the bind host) used by the DNS-rebinding guard. List full origins, e.g.
		// "https://app.example.com". Only valid for transport: http.
		AllowedOrigins []string `yaml:"allowedOrigins"`
		// TrustedProxyCIDRs lists the CIDR ranges a reverse proxy may connect from for
		// its X-Forwarded-For header to be trusted under --trust-forwarded-for. The
		// immediate TCP peer (RemoteAddr) must match one of these ranges, or the header
		// is ignored and the connection's own RemoteAddr is used instead — otherwise any
		// client that reaches the listener directly could forge X-Forwarded-For to spoof
		// an ipRange condition's source IP. Only valid for transport: http.
		TrustedProxyCIDRs []string `yaml:"trustedProxyCIDRs"`
		// TrustedProxyHops is how many trusted reverse proxies sit in front of eunox.
		// Each hop appends the address it saw to X-Forwarded-For, so the right-most N
		// entries are the ones trusted proxies wrote and the client's real address is
		// the N-th from the right; everything further left is client-supplied and
		// ignored. Unset ⟹ 1 (a single proxy, i.e. the right-most entry).
		//
		// The count must be declared rather than inferred by testing entries against
		// trustedProxyCIDRs: an entry inside that range is indistinguishable from a
		// client whose own address happens to fall in it, so inferring would let such
		// a client spoof an ipRange source with a forged left-hand entry. Only valid
		// for transport: http. Pointer so an explicit value is distinguishable from
		// unset, and so an out-of-range 0 is rejected rather than read as "default".
		TrustedProxyHops *int `yaml:"trustedProxyHops"`
		// MaxSessions caps concurrent client sessions (each owns one upstream
		// subprocess or remote connection). 0 ⟹ unlimited; an initialize beyond the
		// cap is refused with 503. Only valid for transport: http. Pointer so an
		// explicit value (including 0) is distinguishable from "unset" (where the
		// --max-sessions backstop applies); a bare int would conflate an omitted key
		// with a deliberate 0.
		MaxSessions *int `yaml:"maxSessions"`
		// SessionIdleTimeoutMs reaps a session whose host has sent no request for
		// this many milliseconds, closing its upstream so idle sessions cannot pin
		// resources indefinitely. 0 ⟹ no idle reaping. Only valid for transport: http.
		// Pointer so an explicit value (including 0) is distinguishable from "unset"
		// (where the --session-idle-timeout flag applies); a bare int would conflate an
		// omitted key with a deliberate 0, making "0 = no idle reaping" inexpressible
		// from config when the flag is non-zero.
		SessionIdleTimeoutMs *int `yaml:"sessionIdleTimeoutMs"`
	} `yaml:"listen"`

	Audit struct {
		Log             string `yaml:"log"`
		KeyPath         string `yaml:"keyPath"`
		RotateSizeBytes int64  `yaml:"rotateSizeBytes"`
		// RetainRotated bounds how many rotated audit files (audit.jsonl.<ts>) are
		// kept after a rotation; the oldest beyond this count are deleted so the log
		// directory cannot grow without bound. 0 ⟹ keep every rotated file (the
		// pre-existing behaviour). The active log is never counted or deleted. Pointer
		// so an explicit value (including 0) overrides the --audit-retain flag while an
		// omitted key leaves the flag in force; a bare int could not express "0 = keep
		// all" from config when the flag is non-zero.
		RetainRotated *int `yaml:"retainRotated"`
	} `yaml:"audit"`

	Defaults  RouteDefaults    `yaml:"defaults"`
	Upstreams []UpstreamConfig `yaml:"upstreams"`

	// BaseDir is the directory of the config file this was loaded from, stamped by
	// LoadGatewayConfig. Relative `policy:` paths resolve against it (not the process
	// working directory), so a config launched from any cwd finds its manifests. The
	// `yaml:"-"` tag keeps the strict decoder (KnownFields(true)) from treating it as
	// an unknown key; it is never read from the file.
	BaseDir string `yaml:"-"`
}

// RouteDefaults are applied to every upstream unless overridden per-route.
type RouteDefaults struct {
	// Enforcement is the posture applied to every route: "enforce" (default) or
	// "audit" (observe — evaluate and log, but forward instead of block).
	Enforcement string `yaml:"enforcement"`

	StrictDrift       bool `yaml:"strictDrift"`
	UpstreamTimeoutMs int  `yaml:"upstreamTimeoutMs"`
}

// UpstreamConfig declares one upstream route.
type UpstreamConfig struct {
	Name string `yaml:"name"`

	Transport string `yaml:"transport"` // "stdio" | "http"

	// stdio transport
	Command string   `yaml:"command"`
	Args    []string `yaml:"args"`

	// http transport
	UpstreamURL           string `yaml:"upstreamUrl"`
	UpstreamAuthHeader    string `yaml:"upstreamAuthHeader"`
	UpstreamTLSSkipVerify bool   `yaml:"upstreamTlsSkipVerify"`

	// policy: one or more capability manifest files, merged in order. Omitting
	// it is only valid when the effective enforcement is "audit" (observe): a
	// policyless route with no audit posture is a misconfiguration and
	// BuildRoutes fails closed at startup (SEC-05) rather than allowing every
	// call unenforced.
	Policy []string `yaml:"policy"`

	// expectVersion pins the manifest's `version`. When set and the manifest
	// version differs, BuildRoutes fails fast (the gateway refuses to start).
	// Only supported with a single policy file — the pin is unambiguous only
	// then. Empty ⟹ no pin.
	ExpectVersion string `yaml:"expectVersion"`

	// Enforcement is the per-route posture: "enforce" or "audit". Empty ⟹ inherit
	// from defaults. "audit" is also the only posture under which a route may omit
	// `policy:` (it acknowledges the observe-only, allow-and-log stance).
	Enforcement string `yaml:"enforcement"`

	// Per-route override. Pointer ⟹ "unset, inherit from defaults".
	StrictDrift *bool `yaml:"strictDrift"`
}

// mcpbBundleMagic is the local-file-header signature that begins every ZIP
// archive. Claude Desktop's Desktop Extension bundles (.mcpb, and the older
// .dxt) are ZIP archives, and a common install-time mistake is to point
// --config at the downloaded bundle instead of an eunox.yaml. Detecting it lets
// the loader fail with guidance rather than yaml.v3's opaque "control
// characters are not allowed" (the 0x03/0x04 bytes in the signature are
// themselves control characters).
var mcpbBundleMagic = []byte{'P', 'K', 0x03, 0x04}

// errIfBinaryConfig returns an actionable error when data is plainly not a text
// config — a ZIP/.mcpb bundle or other binary file — instead of letting the
// YAML/JSON parser fail with an opaque message. kind labels the file in the
// error ("gateway config" or "manifest"). It returns nil for anything that
// could plausibly be text, leaving real parse errors to the parser.
func errIfBinaryConfig(kind, path string, data []byte) error {
	if bytes.HasPrefix(data, mcpbBundleMagic) {
		return fmt.Errorf("%s %q looks like a ZIP archive (a Claude Desktop .mcpb/.dxt extension bundle), not a text config — point eunox at your eunox.yaml, not the downloaded .mcpb bundle. Scaffold one with: eunox init --upstream-url <url> --output manifest.yaml --config-output eunox.yaml", kind, path)
	}
	// A NUL byte never appears in valid YAML/JSON text, so its presence means the
	// file is binary (an executable, image, archive, …) and not a config at all.
	if bytes.IndexByte(data, 0x00) >= 0 {
		return fmt.Errorf("%s %q is not a text config file (it contains NUL bytes) — point eunox at your eunox.yaml", kind, path)
	}
	return nil
}

// gatewaySchemaVersionFromRaw reads the top-level schemaVersion scalar's VERBATIM text
// from raw, plus whether it was written as a bare number (an unquoted 0.1, which YAML
// auto-types !!float). Verbatim matters: "0.10" must stay "0.10" and not renormalize to
// "0.1", which is a different grammar version. Returns "" when the document does not parse
// as YAML at all or carries no schemaVersion — the caller's strict decode then reports the
// syntax error with its own path-qualified message, and an absent version is handled by
// the version validator.
func gatewaySchemaVersionFromRaw(raw []byte) (version string, numeric, parsed bool) {
	var node yaml.Node
	if err := yaml.Unmarshal(raw, &node); err != nil {
		return "", false, false
	}
	val := topLevelValueNode(&node, "schemaVersion")
	if val == nil || val.Kind != yaml.ScalarNode {
		return "", false, true
	}
	return val.Value, val.Tag == "!!int" || val.Tag == "!!float", true
}

// LoadGatewayConfig reads, parses, env-expands, and validates a gateway config.
// ${VAR}/$VAR references are expanded from the environment AFTER parsing — on the
// decoded string values, not the raw text — so secrets need not be committed yet
// an env value can never be re-interpreted as YAML syntax. An unset reference is
// left untouched rather than blanked. See expandEnvRefs/envRefRe.
func LoadGatewayConfig(path string) (*GatewayConfig, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: operator-supplied config path (CLI argument)
	if err != nil {
		return nil, fmt.Errorf("reading gateway config %q: %w", path, err)
	}
	if err := errIfBinaryConfig("gateway config", path, raw); err != nil {
		return nil, err
	}

	// Gate on the declared grammar version BEFORE the strict decode, mirroring the
	// manifest loader's deliberate ordering (validateManifestSchemaVersion runs ahead of
	// checkManifestKeys). The strict decode below rejects any key this binary's structs
	// do not model, so without this pre-read a config written for a FUTURE grammar is
	// reported as a typo ("field xyz not found") when the real problem is that the whole
	// document is a dialect this binary does not speak. That misdirection sends an
	// operator hunting a spelling mistake in a correctly-spelled file. The pre-read is
	// deliberately tolerant — no KnownFields, every other field ignored — so it can reach
	// schemaVersion in a document the strict decode would reject outright. A document
	// that will not parse as YAML at all falls through to the strict decode, which
	// reports the syntax error with its own path-qualified message.
	// Read the value from the NODE, not through a `string`-typed probe struct. An
	// unquoted `schemaVersion: 0.1` is auto-typed !!float by YAML, so a string-typed
	// decode of it fails — and the tolerant probe then swallowed that error, skipping the
	// version gate entirely and leaving the strict decode below to report the whole
	// document with an opaque "cannot unmarshal !!float into string". The node carries the
	// scalar's verbatim text regardless of tag, so the gate runs either way.
	version, numericVersion, parsed := gatewaySchemaVersionFromRaw(raw)
	if parsed {
		if err := validateGatewaySchemaVersion(version); err != nil {
			return nil, fmt.Errorf("invalid gateway config %q: %w", path, err)
		}
	}
	// A document that does not parse as YAML at all falls through to the strict decode,
	// which reports the syntax error with its own path-qualified message.
	if numericVersion {
		// The version is one this binary speaks, but it is spelled as a bare number, which
		// the strict decode below cannot put in a string field. Say so here rather than
		// letting that decode report a type error about a line the operator wrote in the
		// most natural way. (The manifest loader instead retags the scalar in place; it
		// decodes through a yaml.Node, where this loader needs the Decoder's KnownFields
		// strictness and so must decode from the raw bytes.)
		return nil, fmt.Errorf("invalid gateway config %q: schemaVersion %s must be quoted (schemaVersion: %q) — YAML reads a bare %s as a number, which is not a version string", path, version, version, version)
	}

	// Decode strictly: unknown keys are an error, so a typo'd field (e.g.
	// `comand:`) fails loudly instead of being silently ignored. This mirrors
	// the "additionalProperties": false in schemas/eunox-gateway-config.schema.json.
	var cfg GatewayConfig
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		// io.EOF ⟹ empty document; fall through to validate(), which reports the
		// missing `upstreams` with a clearer message than a bare EOF.
		return nil, fmt.Errorf("parsing gateway config %q: %w", path, err)
	}

	// Reject a multi-document stream: a real second document would be silently
	// ignored, so an operator who appends a more restrictive config would get a
	// passing startup that enforces none of it. A trailing empty document (a bare
	// "---" some editors or CI templating append) carries nothing enforceable and is
	// tolerated.
	if err := rejectExtraYAMLDocuments(dec, path, "gateway config"); err != nil {
		return nil, err
	}

	// Reject an unquoted numeric field YAML silently auto-typed away from its written
	// text — most dangerously a leading-zero value read as OCTAL (port: 0755 binds 493,
	// not 755; upstreamTimeoutMs: 010 → an 8 ms timeout; rotateSizeBytes: 0100 → rotate
	// every 64 bytes). The strict struct decode above accepts the coerced integer with no
	// signal, so re-walk the raw node and fail closed, reusing the manifest loader's
	// coercion machinery so the two operator-authored config surfaces agree on this.
	var rawNode yaml.Node
	if err := yaml.Unmarshal(raw, &rawNode); err == nil {
		if err := rejectCoercedGatewayNumerics(&rawNode, path); err != nil {
			return nil, err
		}
	}

	// Capture the raw (pre-expansion) auth token so the post-expansion guard below
	// can tell an empty token the operator INTENDED to be a secret (it carried a
	// ${VAR}/$VAR reference) from one that was legitimately omitted.
	rawAuthToken := cfg.Listen.AuthToken

	// Same for the audit log and key paths: an env ref left unset survives expansion as
	// literal "${VAR}" text, which would silently misdirect the tamper-evident tape (and
	// its signing key) to a directory literally named "${VAR}" — a fail-OPEN on the core
	// integrity artifact, while the sibling credential/URL fields on this same expansion
	// pass fail closed. Capture the raw values for the parallel guard after expansion.
	rawAuditLog := cfg.Audit.Log
	rawAuditKeyPath := cfg.Audit.KeyPath
	rawAllowedOrigins := slices.Clone(cfg.Listen.AllowedOrigins)

	// Same for each upstream's auth header: an env ref in upstreamAuthHeader carries
	// the same unset/empty footgun, so capture the raw values for the parallel guard
	// after expansion.
	rawUpstreamAuth := make([]string, len(cfg.Upstreams))
	rawUpstreamURL := make([]string, len(cfg.Upstreams))
	// And the same for a stdio upstream's command and args, the last expanded fields
	// with no unset-reference guard: `command: ${SERVER_BIN}` with the variable unset
	// boots cleanly and fails per SESSION at exec time, turning a config error into a
	// runtime one that surfaces once a client connects rather than at startup.
	rawCommand := make([]string, len(cfg.Upstreams))
	rawArgs := make([][]string, len(cfg.Upstreams))
	for i := range cfg.Upstreams {
		rawUpstreamAuth[i] = cfg.Upstreams[i].UpstreamAuthHeader
		rawUpstreamURL[i] = cfg.Upstreams[i].UpstreamURL
		rawCommand[i] = cfg.Upstreams[i].Command
		rawArgs[i] = slices.Clone(cfg.Upstreams[i].Args)
	}

	// Expand on the PARSED string values, never the raw text: substituting into
	// the text before parsing let a YAML metacharacter in a secret alter the parse
	// (e.g. "#secret" read as a comment, silently blanking listen.authToken).
	// References resolve only in string-typed fields.
	expandEnvInStrings(reflect.ValueOf(&cfg).Elem())

	// Fail closed if listen.authToken references a variable that leaves the credential
	// blank — unset (left as literal "${VAR}" text), expanded to "", or every reference
	// set but blank. Supplying a ${VAR}/$VAR signals intent to require a shared secret;
	// a blank result would otherwise start the listener with no bearer-token auth, a
	// silent fail-open. An operator who wants no auth omits authToken entirely. Scoped
	// to HTTP since only it has a listener. See validateCredentialEnvRefs (shared with
	// the upstreamAuthHeader leg) for the exact rule and the "$identifier"-substring
	// false-positive it avoids by detecting references on the RAW text.
	if cfg.HostTransport() == HostTransportHTTP {
		if err := validateCredentialEnvRefs(path, "listen.authToken", rawAuthToken); err != nil {
			return nil, err
		}
	}

	// Apply the same unset/empty-expansion detection to each http upstream's
	// upstreamAuthHeader that listen.authToken gets above. expandEnvInStrings walks
	// the whole config and expands this field identically, but nothing checked the
	// result: an env ref that expands to empty (variable unset/blank) or is left as
	// literal "${VAR}" text (variable unset) yields an auth header the upstream
	// rejects on every call — the same silent-misconfiguration footgun, on the
	// upstream leg. Scoped to http upstreams, the only ones the header is valid on (a
	// stdio upstream's forbidden-field check in Validate owns that case). Fail closed.
	for i := range cfg.Upstreams {
		raw := rawUpstreamAuth[i]
		if raw == "" || cfg.Upstreams[i].Transport != "http" {
			continue
		}
		label := fmt.Sprintf("upstream %q upstreamAuthHeader", cfg.Upstreams[i].Name)
		if err := validateCredentialEnvRefs(path, label, raw); err != nil {
			return nil, err
		}
	}

	// Fail closed on an unresolved env reference left in an upstreamUrl. An unset
	// $VAR/${VAR} survives expansion as literal text; for the no-brace, path, or
	// query forms it can still satisfy url.Parse (a valid-looking scheme+host), so
	// validateHTTPUpstreamURL would pass and the gateway would boot a route pointed
	// at a literal "${VAR}" — every request failing. This mirrors the credential
	// guard above: an env ref signals intent to resolve a value, so a residual
	// reference is a misconfiguration.
	//
	// Detect on the RAW pre-expansion text, not the expanded value: a set variable
	// whose VALUE itself contains "${...}"/"$..." text (e.g. an OData query string
	// forwarded through an env var) would make the expanded URL still match
	// ContainsEnvRef even though the reference resolved correctly, misdiagnosing a
	// healthy config as unset. Walking the raw text's references and checking each
	// named variable's presence (matching validateCredentialEnvRefs's rule) avoids
	// that false positive and also lets a literal "$" with no matching env var name
	// (e.g. "?$filter=") pass through untouched.
	for i := range cfg.Upstreams {
		if err := failOnUnsetEnvRef(path, fmt.Sprintf("upstream %q upstreamUrl", cfg.Upstreams[i].Name), rawUpstreamURL[i]); err != nil {
			return nil, err
		}
	}

	// The argv and Origin legs of the same rule, kept together in one helper.
	if err := failOnUnsetArgvAndOriginEnvRefs(path, &cfg, rawCommand, rawArgs, rawAllowedOrigins); err != nil {
		return nil, err
	}

	// Fail closed on an unset env reference in the audit log or key path (see the
	// rawAuditLog/rawAuditKeyPath capture above): an unset ${VAR}/$VAR survives as literal
	// text, so the tamper-evident tape — or its HMAC signing key — would be written to a
	// path literally named "${VAR}", silently misdirecting the integrity artifact. Mirror
	// the upstreamUrl leg, detecting on the RAW text so a set variable whose value itself
	// contains "$" is not misdiagnosed as unset.
	for _, f := range []struct{ label, raw string }{
		{"audit.log", rawAuditLog},
		{"audit.keyPath", rawAuditKeyPath},
	} {
		if err := failOnUnsetEnvRef(path, f.label, f.raw); err != nil {
			return nil, err
		}
	}

	// The strict decode can't tell an explicit zero (command: "", args: []) from an
	// absent key. Re-read which keys each upstream actually wrote so validate() can
	// reject forbidden transport fields on key *presence*, as the JSON Schema does.
	// Read from the unexpanded raw: expansion changes values, never keys.
	present, err := upstreamKeyPresence(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing gateway config %q: %w", path, err)
	}
	// present is indexed parallel to cfg.Upstreams. Assert the lengths match rather
	// than assume it: a future YAML feature the two decoders treat differently
	// could desync them, silently checking one upstream's forbidden fields against
	// another's key set. Fail closed.
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

// ContainsEnvRef reports whether s still contains an unexpanded ${VAR}/$VAR
// reference (per envRefRe). After LoadGatewayConfig's expansion pass, a residual
// reference means the variable was unset and the literal text survived; callers that
// publish the value (e.g. the OAuth authorization-server URIs) use this to fail
// closed rather than advertise literal "${VAR}" text.
func ContainsEnvRef(s string) bool {
	return len(realEnvRefs(s)) > 0
}

// realEnvRefs returns every envRefRe match in s that is an actual variable reference,
// dropping the "$$" escapes. Every consumer that asks "which variables does this value
// reference" goes through here so an escape can never be mistaken for a reference named
// "$" -- which would make ContainsEnvRef report a residual reference for a value that
// correctly expanded to a literal dollar sign, and make the unset-reference guard reject
// a perfectly valid credential.
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

// firstUnsetEnvRef scans rawValue's raw (pre-expansion) text for $VAR/${VAR}
// references and returns the name of the first one whose variable is unset — the
// one expandEnvRefs would leave as literal "${VAR}" text in the expanded value.
// ok is false when every reference (if any) resolved to a set variable. The
// single walk-and-check-unset core shared by validateCredentialEnvRefs (the
// listen.authToken / upstreamAuthHeader legs) and LoadGatewayConfig's upstreamUrl
// residual-reference check, so the "what counts as unset" rule cannot drift
// between them.
func firstUnsetEnvRef(rawValue string) (name string, ok bool) {
	for _, ref := range realEnvRefs(rawValue) {
		n := envRefName(ref)
		if _, set := os.LookupEnv(n); !set {
			return n, true
		}
	}
	return "", false
}

// failOnUnsetEnvRef fails closed when raw carries a $VAR/${VAR} reference whose variable
// is unset: expandEnvRefs leaves the literal "${VAR}" text in place, so the field would
// resolve to a path/URL literally named "${VAR}". Single source of the operator-facing
// message for the "path-family" fields (upstreamUrl, audit.log, audit.keyPath) so they
// cannot drift; the credential fields use validateCredentialEnvRefs, whose message differs
// (a literal token no client/upstream sends). Detection is on the RAW pre-expansion text
// so a set variable whose value itself contains "$" is not misdiagnosed as unset. path
// names the config file; label names the field.
func failOnUnsetEnvRef(path, label, raw string) error {
	if name, ok := firstUnsetEnvRef(raw); ok {
		return unsetEnvRefError(path, label, name)
	}
	return nil
}

// failOnUnsetArgvAndOriginEnvRefs fails closed on an unset environment reference in a
// stdio upstream's command/args or in listen.allowedOrigins — the expanded fields that
// had no such guard, each of which otherwise boots cleanly and fails later somewhere far
// from the config.
//
// command/args: an unset ${SERVER_BIN} survives as literal text and the route boots; the
// failure lands at exec time on the FIRST SESSION instead of at startup, so the operator
// learns of a plain config typo from a client's failed handshake. Restricted to the
// BRACED form, because these two fields are arbitrary subprocess argv rather than a URL:
// a bare "$word" is ordinary literal text there (an OData "?$filter=", a regex "$anchor",
// a jq/JSONPath expression, or anything the child interpolates itself), so treating it as
// a reference would refuse to START a config that works today, blaming a variable the
// operator never wrote. "${VAR}" carries unambiguous intent to substitute. The
// upstreamUrl guard keeps its broader bare-$ rule: it predates this, and a URL is a far
// narrower surface than argv.
//
// listen.allowedOrigins: an unset ${DASHBOARD_ORIGIN} survives, the proxy boots, and the
// entry then matches no real Origin header — so a browser client gets a bare 403 with
// nothing on stderr connecting it to the typo. Nothing else catches this one, which is
// why it is guarded here; it takes the full bare-$ rule, matching the other URL-shaped
// fields.
//
// Note the whole family is a hand-maintained per-field list while expandEnvInStrings
// rewrites EVERY string in the tree, so "covered" is not the default — a field is covered
// only once it is added. Most of the rest fail at startup for their own reasons (a ${VAR}
// in `name` fails routeNameRe, in `bind` fails net.Listen, in `policy` fails LoadManifest,
// in trustedProxyCIDRs fails ParseCIDR), which is why the remaining gaps are quiet rather
// than loud. Detection is on the RAW pre-expansion text throughout, so a set variable
// whose value itself contains "$" is not misdiagnosed as unset.
func failOnUnsetArgvAndOriginEnvRefs(path string, cfg *GatewayConfig, rawCommand []string, rawArgs [][]string, rawAllowedOrigins []string) error {
	for i := range cfg.Upstreams {
		name := cfg.Upstreams[i].Name
		if err := failOnUnsetBracedEnvRef(path, fmt.Sprintf("upstream %q command", name), rawCommand[i]); err != nil {
			return err
		}
		for j, rawArg := range rawArgs[i] {
			if err := failOnUnsetBracedEnvRef(path, fmt.Sprintf("upstream %q args[%d]", name, j), rawArg); err != nil {
				return err
			}
		}
	}
	for i, rawOrigin := range rawAllowedOrigins {
		if err := failOnUnsetEnvRef(path, fmt.Sprintf("listen.allowedOrigins[%d]", i), rawOrigin); err != nil {
			return err
		}
	}
	return nil
}

// failOnUnsetBracedEnvRef is failOnUnsetEnvRef restricted to the unambiguous "${VAR}"
// spelling, for fields whose text is passed verbatim to another program (a stdio
// upstream's command and args). A bare "$word" is ordinary literal content there, so
// treating it as a reference would refuse to start an otherwise-working config; "${VAR}"
// is unambiguous intent to substitute. Escapes ("$$") are skipped exactly as elsewhere,
// and detection is on the RAW pre-expansion text for the same reason.
func failOnUnsetBracedEnvRef(path, label, raw string) error {
	for _, ref := range realEnvRefs(raw) {
		if !strings.HasPrefix(ref, "${") {
			continue
		}
		// envRefRe guarantees at least one identifier character, so envRefName cannot
		// return "" — and if it ever could, skipping would be the fail-OPEN direction
		// (an unset reference left as literal text is exactly what this guard exists to
		// refuse), so a "defensive" continue defended the wrong way.
		name := envRefName(ref)
		if _, set := os.LookupEnv(name); !set {
			return unsetEnvRefError(path, label, name)
		}
	}
	return nil
}

// unsetEnvRefError is the single operator-facing message for an unset reference, shared
// by the full and braced-only guards so the two cannot drift on wording.
func unsetEnvRefError(path, label, name string) error {
	return fmt.Errorf("invalid gateway config %q: %s references environment variable %q, which is unset, so it is left as literal text — set the variable or remove the reference", path, label, name)
}

// validateCredentialEnvRefs fails closed when a credential field whose value is built
// from $VAR / ${VAR} references would start the gateway with no real secret. It is the
// single source of truth for the listen.authToken and upstreamAuthHeader legs, which
// enforce the identical rule and differ only in the field they name (label) — keeping
// the logic in one place so the two cannot drift. rawValue is the pre-expansion text
// (references are detected on the raw text so an expanded "$identifier" substring in a
// real secret cannot false-positive), label names the field for the operator (e.g.
// `listen.authToken`). Returns nil when the field carries a real credential, omits
// references entirely, or is empty without any reference (an operator opting out). The
// two fail-closed cases, in order:
//
//   - a referenced variable is UNSET, so expandEnvRefs left the "${VAR}" literal in
//     place — the field would require a literal token no client/upstream sends;
//   - EVERY referenced variable is set but blank (empty or whitespace-only), so a
//     field like "Bearer ${T}" expands non-empty yet carries no secret. A single
//     non-blank reference (e.g. "${A}${B}" with A blank but B set) is a real credential.
//
// There is deliberately no separate "the whole expanded field is empty" guard: a bare
// "${VAR}" whose only referenced variable is unset or blank is already caught by one of
// the two cases above (unset ⇒ firstUnsetEnvRef; set-but-blank ⇒ the all-blank-refs
// case), since expandEnvRefs only ever replaces ref text with the referenced variable's
// value and leaves every other character untouched — an expanded-field check can never
// catch a case these two miss.
func validateCredentialEnvRefs(path, label, rawValue string) error {
	if name, ok := firstUnsetEnvRef(rawValue); ok {
		return fmt.Errorf("invalid gateway config %q: %s references environment variable %q, which is unset, so it is left as literal text — the field would require a literal token no client/upstream sends; set the variable, or remove the reference", path, label, name)
	}
	// Every reference (if any) is confirmed set by firstUnsetEnvRef above, so
	// os.LookupEnv below always succeeds; this pass only tracks blankness.
	refs := realEnvRefs(rawValue)
	sawNonEmptyRef := false
	for _, ref := range refs {
		val, _ := os.LookupEnv(envRefName(ref))
		// Treat a whitespace-only value as blank: a credential that is only spaces/tabs
		// is no secret (a client would have to send "Bearer  "), the same blank-slot
		// footgun as "", just one TrimSpace away. Counting it as a real value would let
		// "${A}" with A=" " slip past the all-blank guard below.
		if strings.TrimSpace(val) != "" {
			sawNonEmptyRef = true
		}
	}
	// A reference set to "" (or only whitespace) with surrounding literal text (e.g.
	// "Bearer ${T}") expands non-empty, so the field == "" guard above misses it, yet the
	// credential slot is blank. Reject only when EVERY referenced variable is blank — then
	// the field is pure literal scaffolding with no secret. Fail closed.
	if len(refs) > 0 && !sawNonEmptyRef {
		return fmt.Errorf("invalid gateway config %q: every environment variable referenced by %s is set to the empty string or only whitespace, so the credential expanded to literal text with no secret value — refusing to start with a blank credential; set a referenced variable to a non-empty value, or remove %s", path, label, label)
	}
	return nil
}

// rejectExtraYAMLDocuments drains dec after the first document and rejects any
// further document that carries real content, so an appended second config/manifest
// is never silently ignored (it would otherwise load yet enforce none of it). A
// trailing empty/null document — a bare "---" some editors or CI templating append,
// an all-comment document, or an explicit "null" — decodes to a nil value and
// carries nothing enforceable, so it is tolerated; the loop drains every separator
// so a real document behind any number of empties is still caught. Decoding into
// interface{} and testing for nil checks the property we care about (no enforceable
// content) without depending on go-yaml node-tag internals. what names the artifact
// for the error message (e.g. "gateway config", "YAML manifest").
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

// upstreamKeyPresence re-parses raw to record, per upstream (indexed parallel to
// the typed Upstreams slice), exactly which YAML keys were written — including
// keys whose value decodes to a zero. The strict typed decode cannot distinguish
// an explicit zero from an absent key; recording presence lets validate() reject
// the same set the JSON Schema's "<field>": false does, keeping the two in
// lockstep.
func upstreamKeyPresence(raw []byte) ([]map[string]bool, error) {
	var doc struct {
		Upstreams []map[string]any `yaml:"upstreams"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	present := make([]map[string]bool, 0, len(doc.Upstreams))
	for i, entry := range doc.Upstreams {
		// A null/empty list element — `- null`, or a bare dangling `-` with no value
		// — is silently dropped by the strict typed decoder but kept here as a nil
		// map, desyncing the two slices and tripping the count-mismatch guard, which
		// presents a plain operator typo as an internal bug. Reject it explicitly with
		// an index-named, user-facing message instead.
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

// Validate checks structural and cross-field invariants. presentKeys, when
// non-nil, lists the YAML keys actually written for each upstream (indexed
// parallel to cfg.Upstreams) so the cross-transport checks can reject a forbidden
// field on *presence* — even an explicit zero — matching the JSON Schema. A nil
// presentKeys (a programmatically-built config, e.g. the --audit wiretap) falls
// back to rejecting only a non-zero decoded value.
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
		// net.ParseCIDR silently masks host bits, so "10.0.0.5/8" behaves as
		// "10.0.0.0/8" — usually a /32-vs-network mistake that would silently widen
		// this trust boundary far beyond the single host the operator intended.
		// Mirrors validateIPRange's identical guard for manifest ipRange conditions.
		if !ip.Equal(network.IP) {
			return fmt.Errorf("listen.trustedProxyCIDRs: CIDR %q has host bits set; use the network address %q, or /32 to trust just that host", cidr, network.String())
		}
	}
	// A hop count below 1 would leave no proxy-written entry to read, so the value is
	// meaningless rather than a usable "off" switch (X-Forwarded-For is disabled by
	// omitting --trust-forwarded-for, or by leaving trustedProxyCIDRs empty).
	if h := cfg.Listen.TrustedProxyHops; h != nil && *h < 1 {
		return fmt.Errorf("listen.trustedProxyHops must be at least 1, got %d; omit the key for a single proxy, "+
			"or drop --trust-forwarded-for to stop trusting the header entirely", *h)
	}
	if cfg.HostTransport() == HostTransportHTTP && cfg.Listen.Port != 0 {
		if cfg.Listen.Port < 1 || cfg.Listen.Port > 65535 {
			return fmt.Errorf("listen.port %d is out of range [1, 65535]", cfg.Listen.Port)
		}
	}
	// A non-empty but whitespace-only authToken is a degenerate secret: it is not "" so
	// checkAuth enforces it as the required bearer AND openNonLoopbackBind counts auth as
	// "configured" (satisfying the non-loopback-bind safety gate), yet "Bearer   " is
	// trivially guessable. The env-ref leg already rejects a reference that expands to
	// whitespace (validateCredentialEnvRefs); mirror that for a LITERAL whitespace token so
	// the two legs agree. An operator who wants no auth omits authToken entirely.
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
		// Reject a millisecond value that would overflow time.Duration when scaled by
		// time.Millisecond: a wrapped-negative idle window makes the reaper close every
		// session on sight. MaxDurationMs (~292 years) is already effectively unlimited.
		if int64(*cfg.Listen.SessionIdleTimeoutMs) > MaxDurationMs {
			return fmt.Errorf("listen.sessionIdleTimeoutMs %d exceeds the maximum %d ms (it would overflow the idle timer)", *cfg.Listen.SessionIdleTimeoutMs, MaxDurationMs)
		}
	}
	// Reject a negative rotation threshold up front, matching the other bounded
	// numeric fields. A negative maxBytes makes the audit sink's size check
	// (written+n >= maxBytes) true for every record, rotating the log on every line
	// written and flooding the log directory; 0 stays valid ("use the default size").
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
	// Reject a negative value up front, matching listen.maxSessions /
	// listen.sessionIdleTimeoutMs: ResolveUpstreamTimeout would silently coerce a
	// negative cfg value to the built-in default (it treats <= 0 as "unset"), so an
	// operator who writes -1 (or hits it via a templating accident) would get the
	// default with no diagnostic — an inconsistency with the "reject invalid config
	// up front" posture the rest of this file follows. 0 stays valid ("use default").
	if cfg.Defaults.UpstreamTimeoutMs < 0 {
		return fmt.Errorf("defaults.upstreamTimeoutMs %d must not be negative (0 = use the built-in default)", cfg.Defaults.UpstreamTimeoutMs)
	}
	// Same overflow guard for the upstream-call timeout. resolveUpstreamTimeout
	// treats <= 0 as "unset", so only the upper bound is checked here.
	if int64(cfg.Defaults.UpstreamTimeoutMs) > MaxDurationMs {
		return fmt.Errorf("defaults.upstreamTimeoutMs %d exceeds the maximum %d ms (it would overflow the upstream-call timeout)", cfg.Defaults.UpstreamTimeoutMs, MaxDurationMs)
	}
	// presentKey reports whether upstream i wrote key in the source document; nil
	// presentKeys (a synthesized config) ⟹ false, covered by the value fallbacks.
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

	switch u.Transport {
	case "stdio":
		if u.Command == "" {
			return fmt.Errorf("upstream %q: stdio transport requires 'command'", u.Name)
		}
		// HTTP-only fields are rejected on key presence (not just a non-zero
		// value) so the loader refuses exactly what the schema's
		// "<field>": false refuses — e.g. an explicit upstreamTlsSkipVerify: false.
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
		// degenerate-credential case listen.authToken rejects above: it is not "", so the
		// route forwards it as a real header, yet "Authorization:   " carries no secret and
		// every upstream call fails auth in a way that looks like an upstream fault rather
		// than a config error. The env-ref leg already rejects a reference that expands to
		// whitespace (validateCredentialEnvRefs); a LITERAL whitespace value reached neither
		// guard, since that one only runs for values that contain a reference. An operator
		// who wants no upstream auth omits the field entirely.
		if u.UpstreamAuthHeader != "" && strings.TrimSpace(u.UpstreamAuthHeader) == "" {
			return fmt.Errorf("upstream %q: 'upstreamAuthHeader' is whitespace-only, which is not a usable credential — set a real header value, or omit the field to forward no auth header", u.Name)
		}
		// stdio-only fields are rejected on key presence so an explicit zero
		// (command: "" or args: []) is refused too, matching the schema.
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

	// Reject an empty or whitespace-only policy entry at load rather than deferring
	// the failure to route start. A "" entry — a literal policy: [""], or a
	// policy: ["${VAR}"] where VAR is SET but empty/whitespace (expandEnvRefs leaves an
	// UNSET ${VAR} intact as its literal text, so an unset ref is a non-empty entry that
	// fails later at route start, not here) — has len==1, so it slips past the no-policy
	// classification (NoPolicyStartupRejection, which keys on len==0) and masks the "this
	// route has no policy" condition; then ResolvePolicyPath joins "" onto the config dir
	// and the loader dies at startup with a misleading "is a directory" error. Fail closed
	// here with a clear config diagnostic instead.
	for _, p := range u.Policy {
		if strings.TrimSpace(p) == "" {
			return fmt.Errorf("upstream %q: 'policy' contains an empty entry; each policy entry must be a manifest file path (an empty entry is often a ${VAR} that expanded to empty, or a stray \"\")", u.Name)
		}
	}

	// expectVersion pins a single manifest's `version`. With multiple policy
	// files MergeManifests takes the version from the FIRST file only, so the pin
	// silently ignores the others; reject the ambiguous multi-file case rather
	// than enforce a weaker guarantee than the config implies. The no-policy case
	// (len == 0) is handled by NoPolicyStartupRejection.
	if u.ExpectVersion != "" && len(u.Policy) > 1 {
		return fmt.Errorf("upstream %q: 'expectVersion' is only supported with a single policy file; "+
			"with %d files the pin is ambiguous (only the first file's version is compared) — "+
			"use a single merged policy file, or remove 'expectVersion'", u.Name, len(u.Policy))
	}
	return nil
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

// validateHTTPUpstreamURL returns an error if rawURL is empty, not parseable, does
// not use an http or https scheme, or has no host. The host check rejects a
// scheme-only value like "http://" at config load rather than deferring the
// no-host failure to the first upstream request.
func validateHTTPUpstreamURL(name, rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("upstream %q: http transport requires 'upstreamUrl'", name)
	}
	parsed, err := url.Parse(rawURL)
	// capability.RedactURLForLog, not the bundle-facing RedactURL: a validation error
	// goes to stderr (systemd journal, container logs, CI output), and for a Slack
	// webhook or a Telegram bot URL the PATH is the credential. A scheme typo on such a
	// URL parses fine and lands here, so keeping the path would print the whole secret.
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

// ResolvedStrictDrift resolves the effective config-declared strictDrift for u (the
// per-route value overriding the default). Single-sourced so the startup guards, the
// classifier, and both serve paths' drift-hook wiring resolve it identically. Note
// this is the CONFIG value only; the global --strict-drift flag is folded in later
// (transport.ResolveStrictDrift) and never promotes a policyless route.
func (cfg *GatewayConfig) ResolvedStrictDrift(u *UpstreamConfig) bool {
	return ResolveBool(u.StrictDrift, cfg.Defaults.StrictDrift)
}

// startupRefusal classifies whether a policyless upstream is refused at startup and
// by which fail-closed guard. It is the SINGLE source of the two guard CONDITIONS —
// config-declared strictDrift on a policyless upstream, and a policyless upstream not
// in audit mode — so StartupPolicyError (the serve paths' hard error) and
// NoPolicyStartupRejection (validate/doctor's reason string) cannot diverge on WHEN a
// route is refused; each only maps the shared verdict to its own message.
type startupRefusal int

const (
	startupRefusalNone     startupRefusal = iota // may boot
	startupRefusalStrict                         // config-declared strictDrift on a policyless upstream
	startupRefusalNoPolicy                       // policyless upstream not in audit mode
)

// classifyStartupRefusal applies the two fail-closed guard conditions in proxy order
// (strictDrift first, then the audit-mode requirement), returning which guard — if
// any — refuses u. The expectVersion-requires-policy guard is intentionally excluded:
// it lives in LoadUpstreamPDP, which both transports already share.
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

// StartupPolicyError returns the error a host transport must fail startup with for
// upstream u, or nil when u may boot. The two fail-closed per-upstream guards are:
//
//   - a config-declared strictDrift on a policyless upstream is a hard error (the
//     global --strict-drift flag is exempt — it no-ops on a policyless route);
//   - a policyless upstream in enforce (non-audit) mode is refused, since it would
//     forward every call unenforced (fail-closed).
//
// BuildRoutes (gateway) and serveStdioHost (stdio) both call this so a guard can
// never be added to one serve path but not the other, letting one host boot a config
// the other refuses. The verdict comes from classifyStartupRefusal, which
// NoPolicyStartupRejection also consumes, so the runtime and validate/doctor cannot
// diverge on the conditions.
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

// NoPolicyStartupRejection reports why a route with no `policy:` would be refused at
// startup, or "" when it boots cleanly. It consumes the same classifyStartupRefusal
// verdict as StartupPolicyError so validate and doctor classify a config exactly as
// the proxy would, then adds the expectVersion pin (guarded at runtime in
// LoadUpstreamPDP, which both transports share).
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
