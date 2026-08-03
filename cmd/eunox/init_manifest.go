// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The `init` subcommand (cmdInit and its upstream-spec parsing) and the starter manifest
// generator behind it.
//
// generateInitManifestYAML produces a YAML manifest with every tool commented
// out; operators uncomment and add conditions only for tools the agent needs.
// Re-running init after a server update and diffing surfaces additions/removals.

package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/eunolabs/eunox/internal/config"
	"github.com/eunolabs/eunox/internal/drift"
	"github.com/eunolabs/eunox/pkg/capability"
)

// yamlScalar renders s as a single-line YAML scalar safe in BOTH block and flow
// contexts. Upstream-controlled tool/property/type names are interpolated into the
// scaffold; without proper quoting a name like "read: report # prod" produces
// invalid YAML (or silently retargets the entry) once uncommented. For a value the
// YAML encoder would render across lines it falls back to a Go-quoted form, or to a
// single-line !!binary scalar when (and only when) the quoted form would not
// round-trip (a name carrying invalid UTF-8 bytes).
func yamlScalar(s string) string {
	// Prefer yaml.v3's own rendering, but only when it stays on one physical line and
	// round-trips back to exactly s in ALL THREE shapes the value is interpolated into:
	// a bare scalar VALUE (the `- target: X` value and the `X:` body), a flow-sequence
	// element (the `required: [X]` flow call site), and a block-mapping KEY (the
	// property key `X: { ... }`). Verifying the round-trip in the exact shapes — rather
	// than enumerating yaml's significant characters — is self-validating: the bare
	// check rejects a block-scalar header whose body TrimRight stripped (e.g. "\n"
	// renders as "|4+", which decodes to ""); the flow check rejects any plain rendering
	// yaml.Marshal leaves unquoted that is structural in flow context (`,` `[` `]` `{`
	// `}` `:` `?`, so "a,b" splits a list and "?x" injects a mapping key); and the
	// block-key check rejects the merge key "<<", which is structural ONLY in key
	// position (it round-trips fine as a value and a flow element, so the first two
	// checks miss it). All three push the value to the always-safe quoted fallback below
	// with no per-character list to keep current.
	if b, err := yaml.Marshal(s); err == nil {
		out := strings.TrimRight(string(b), "\n")
		if strings.IndexFunc(out, isYAMLLineBreak) == -1 &&
			yamlDecodesTo(out, s) && yamlFlowSeqDecodesTo(out, s) && yamlBlockKeyDecodesTo(out, s) {
			return out
		}
	}
	// Fallback for a value yaml renders across lines, or a plain scalar carrying a
	// flow delimiter. strconv.Quote is a YAML-correct single-line scalar for valid
	// UTF-8, but NOT for invalid UTF-8: Go's \xNN escape means a raw byte while YAML's
	// \xNN means code point U+00NN, so a name carrying raw bytes 0x80-0xFF would decode
	// to a different string. Use the quoted form only when it round-trips; otherwise
	// emit a single-line !!binary scalar, which round-trips any byte sequence.
	if q := strconv.Quote(s); yamlDecodesTo(q, s) {
		return q
	}
	return "!!binary " + base64.StdEncoding.EncodeToString([]byte(s))
}

// yamlDecodesTo reports whether the YAML scalar text decodes back to exactly want,
// so yamlScalar accepts a rendering only when it is loss-free.
func yamlDecodesTo(text, want string) bool {
	var got string
	return yaml.Unmarshal([]byte(text), &got) == nil && got == want
}

// yamlFlowSeqDecodesTo reports whether out, placed as a single flow-sequence element
// ("[" + out + "]"), decodes back to exactly want. yamlScalar interpolates its result
// into the `required: [..]` flow call site, where `,` `[` `]` `{` `}` `:` `?` are
// structural; verifying the value in that exact flow shape rejects any plain
// rendering that would split the list or be reinterpreted as a mapping key, with no
// per-character enumeration to keep in sync with yaml's grammar.
func yamlFlowSeqDecodesTo(out, want string) bool {
	var got []string
	if err := yaml.Unmarshal([]byte("["+out+"]"), &got); err != nil {
		return false
	}
	return len(got) == 1 && got[0] == want
}

// yamlBlockKeyDecodesTo reports whether out, placed as a block-mapping KEY (out +
// ": v"), decodes to a single mapping whose only key is exactly want. yamlScalar
// interpolates its result into the property-key call site (`X: { ... }`), where the
// YAML merge key "<<" is structural ONLY in key position: "<<" round-trips cleanly as
// a scalar value and as a flow element (so the other two checks pass), but as a key it
// merges the value map into the parent and silently drops the "<<" property. Verifying
// the value in this exact key shape rejects that case (and any other key-position
// surprise) so it falls through to the always-safe quoted fallback.
func yamlBlockKeyDecodesTo(out, want string) bool {
	var m map[string]string
	if err := yaml.Unmarshal([]byte(out+": v\n"), &m); err != nil {
		return false
	}
	_, ok := m[want]
	return len(m) == 1 && ok
}

// generateInitManifestYAML returns a deny-all starter YAML manifest: every tool
// entry is commented out, so the capabilities section is valid but empty until
// the operator uncomments entries. A non-empty serverVersion is added as a
// commented-out field for optional version pinning. With pinDescriptions, each
// entry gets a descriptionHash for startup detection of description changes.
func generateInitManifestYAML(tools []drift.UpstreamTool, manifestName, serverVersion string, pinDescriptions bool) string {
	var sb strings.Builder
	sb.WriteString("schemaVersion: \"0.1\"\n")
	fmt.Fprintf(&sb, "name: %s\n", yamlScalar(manifestName))
	sb.WriteString("version: \"0.1.0\"\n")
	if serverVersion != "" {
		// Show an exact pin, plus a wildcard suggestion when one exists that is both
		// looser than the exact version and still matches it (a bare major like "2"
		// has no looser form the drift matcher accepts, so suggesting one would only
		// mislead). serverVersionWildcard guarantees the round trip.
		wildcard := serverVersionWildcard(serverVersion)
		if wildcard != serverVersion {
			fmt.Fprintf(&sb, "# serverVersion: %s  # uncomment to pin; use %s to allow updates\n",
				yamlScalar(serverVersion), yamlScalar(wildcard))
		} else {
			fmt.Fprintf(&sb, "# serverVersion: %s  # uncomment to pin\n", yamlScalar(serverVersion))
		}
	}
	sb.WriteString("\n")

	if len(tools) == 0 {
		sb.WriteString("capabilities: [] # no tools found on upstream\n")
		return sb.String()
	}

	sb.WriteString("capabilities:\n")
	sb.WriteString("  # REVIEW: uncomment and add conditions before enabling each tool.\n")

	for i, tool := range tools {
		if i > 0 {
			// Blank comment line separates entries for readability.
			sb.WriteString("  #\n")
		}
		for _, line := range toolEntryYAMLLines(tool, pinDescriptions) {
			// Re-prefix every physical line: an untrusted upstream name may carry an
			// embedded line break, which would otherwise break out of the comment and
			// plant an ACTIVE capability into the deny-all starter. yaml.v3 treats CR,
			// NEL, LS, and PS as line breaks too, so split on all of them (isYAMLLineBreak).
			for _, phys := range strings.FieldsFunc(line, isYAMLLineBreak) {
				sb.WriteString("  # ")
				sb.WriteString(phys)
				sb.WriteString("\n")
			}
		}
	}

	return sb.String()
}

// isYAMLLineBreak reports whether r is a character yaml.v3 treats as a line
// break: LF, CR, NEL (U+0085), LS (U+2028), or PS (U+2029).
func isYAMLLineBreak(r rune) bool {
	switch r {
	case '\n', '\r', '\u0085', '\u2028', '\u2029':
		return true
	default:
		return false
	}
}

// initUpstreamSpec describes the upstream `init` was pointed at, used to scaffold
// a matching runnable config. Exactly one of {URL, Command} is set, selected by
// Transport.
type initUpstreamSpec struct {
	Transport     string   // "http" or "stdio"
	URL           string   // http: upstream base URL
	AuthHeader    string   // http: optional "Name: Value" auth header
	TLSSkipVerify bool     // http: introspected with --upstream-tls-skip-verify
	Command       string   // stdio: subprocess command
	Args          []string // stdio: subprocess args
}

// initRouteName is the default name of the single upstream scaffolded by
// `eunox init`. It's a placeholder — the operator renames it (it becomes
// the /mcp/<name> route segment in http mode) before flipping to production.
const initRouteName = "upstream"

// generateInitConfigYAML returns a runnable eunox config that fronts the
// introspected upstream and enforces the generated manifest. The host transport
// mirrors the upstream transport (http→gateway with a listen block; stdio→stdio
// host) so `eunox proxy --config` works out of the box.
func generateInitConfigYAML(u initUpstreamSpec, manifestPath string) string {
	var sb strings.Builder
	sb.WriteString("# eunox config generated by `eunox init`. Run:\n")
	sb.WriteString("#   eunox proxy --config <this file>\n")
	sb.WriteString("# yaml-language-server: $schema=https://raw.githubusercontent.com/eunolabs/eunox/main/schemas/eunox-gateway-config.schema.json\n")
	sb.WriteString("schemaVersion: \"0.1\"\n")

	switch u.Transport {
	case config.HostTransportStdio:
		sb.WriteString("transport: stdio           # stdio host: bridges this one upstream over stdin/stdout (Claude Desktop / Cursor / Windsurf)\n")
	default:
		sb.WriteString("transport: http            # http gateway (default); set \"stdio\" to bridge this one upstream over stdin/stdout\n")
		sb.WriteString("listen:\n")
		sb.WriteString("  bind: 127.0.0.1\n")
		sb.WriteString("  port: 3000\n")
	}

	sb.WriteString("audit:\n")
	sb.WriteString("  log: ~/.eunox/audit.jsonl\n")
	sb.WriteString("upstreams:\n")
	fmt.Fprintf(&sb, "  - name: %s\n", initRouteName)

	switch u.Transport {
	case config.HostTransportStdio:
		sb.WriteString("    transport: stdio\n")
		fmt.Fprintf(&sb, "    command: %s\n", yamlScalar(u.Command))
		if len(u.Args) > 0 {
			fmt.Fprintf(&sb, "    args: %s\n", yamlStringList(u.Args))
		}
	default:
		sb.WriteString("    transport: http\n")
		fmt.Fprintf(&sb, "    upstreamUrl: %s\n", yamlScalar(u.URL))
		if u.AuthHeader != "" {
			// The literal --upstream-auth-header value is persisted here verbatim (not an
			// env-ref like ${UPSTREAM_TOKEN}) so the generated config is runnable
			// out of the box, matching every other init-scaffolded field. That means
			// this file now holds a cleartext credential — flag it in-line (and see the
			// matching stderr warning in cmdInit) so an operator does not commit it or
			// paste it into a bug report without noticing.
			sb.WriteString("    # SECURITY: the line below is a cleartext credential (from --upstream-auth-header).\n")
			sb.WriteString("    # Consider replacing it with an env-ref, e.g. \"Authorization: Bearer ${UPSTREAM_TOKEN}\",\n")
			sb.WriteString("    # and keep this file out of version control either way.\n")
			fmt.Fprintf(&sb, "    upstreamAuthHeader: %s\n", yamlScalar(u.AuthHeader))
		} else {
			sb.WriteString("    # upstreamAuthHeader: \"Authorization: Bearer ${UPSTREAM_TOKEN}\"\n")
		}
		// Preserve --upstream-tls-skip-verify so the config can reconnect to the
		// same self-signed upstream `init` introspected.
		if u.TLSSkipVerify {
			sb.WriteString("    upstreamTlsSkipVerify: true   # init introspected with --upstream-tls-skip-verify (development only)\n")
		}
	}

	fmt.Fprintf(&sb, "    policy: [%s]\n", yamlScalar(manifestPath))
	sb.WriteString("    # expectVersion: \"0.1.0\"   # pin the manifest version; fail closed on mismatch\n")
	return sb.String()
}

// yamlStringList renders a string slice as a YAML flow-style sequence with each
// element rendered through yamlScalar so an operator-supplied arg carrying a flow
// delimiter, line break, or invalid UTF-8 still round-trips through the YAML loader,
// e.g. ["-y", "@modelcontextprotocol/server-filesystem"].
func yamlStringList(items []string) string {
	parts := make([]string, len(items))
	for i, s := range items {
		parts[i] = yamlScalar(s)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// toolEntryYAMLLines returns the unindented YAML content lines for one tool entry
// (the caller prefixes each with "  # "). With pinDescriptions, a descriptionHash
// is emitted for every tool including one with an empty description — the hash of
// "" is a verifiable pin, and skipping it would leave a tool-poisoning gap (an
// empty description silently changing into a prompt-injecting one).
func toolEntryYAMLLines(tool drift.UpstreamTool, pinDescriptions bool) []string {
	lines := []string{
		fmt.Sprintf("- target: %s", yamlScalar("tool:"+tool.Name)),
		"  actions: [call]",
	}
	if pinDescriptions {
		lines = append(lines, fmt.Sprintf("  descriptionHash: %q", capability.ComputeToolHash(tool.Description, capability.ToolHashParams(tool.Title, tool.Annotations, tool.InputSchema, tool.OutputSchema))))
	}
	if schemaLines := argumentSchemaYAML(tool.InputSchema); len(schemaLines) > 0 {
		lines = append(lines, "  argumentSchema:")
		lines = append(lines, schemaLines...)
	}
	return lines
}

// argumentSchemaYAML returns indented YAML lines for the argumentSchema block,
// or nil when the schema has no properties to emit.
func argumentSchemaYAML(schema map[string]interface{}) []string {
	props, ok := drift.SchemaProperties(schema)
	if !ok || len(props) == 0 {
		// Nothing to scaffold when the live schema declares no parameters.
		return nil
	}

	// additionalProperties: false makes the scaffolded schema a CLOSED enumeration
	// of the tool's current parameters. It fails a call carrying an undeclared
	// argument closed at request time, and it arms the FM-6 startup drift check:
	// without it, FM-6's "a new, unreviewed parameter appeared" detection cannot
	// fire (an open schema permits any added parameter by definition). The operator
	// reviews and relaxes it if a tool legitimately takes open-ended arguments.
	lines := []string{
		"    type: object",
		"    additionalProperties: false",
		"    properties:",
	}

	for _, name := range sortedKeys(props) {
		lines = append(lines, fmt.Sprintf("      %s: { type: %s }", yamlScalar(name), propertyTypeYAML(props[name])))
	}

	if reqRaw, ok := schema["required"].([]interface{}); ok && len(reqRaw) > 0 {
		required := make([]string, 0, len(reqRaw))
		for _, r := range reqRaw {
			if s, ok := r.(string); ok {
				// Only keep a required name that has a matching property schema. The
				// scaffold always emits additionalProperties:false, so a required field
				// absent from properties would make the (uncommented) schema unsatisfiable
				// — config.LoadManifest rejects exactly that shape, failing the whole
				// manifest. Filtering keeps the deny-all scaffold loadable as documented.
				if _, inProps := props[s]; inProps {
					required = append(required, yamlScalar(s))
				}
			}
		}
		if len(required) > 0 {
			lines = append(lines, fmt.Sprintf("    required: [%s]", strings.Join(required, ", ")))
		}
	}

	return lines
}

// propertyTypeYAML renders the `type:` value for one inputSchema property as a
// YAML scalar or flow sequence. JSON Schema permits `type` to be an array (a
// union), and nullable parameters are routinely declared as ["string","null"]
// (or ["integer","null"], etc.). The manifest grammar's multi-type SchemaType
// accepts a flow sequence, and the enforcement engine checks declared types
// strictly — so a union type collapsed to a wrong scalar (e.g. an
// ["integer","null"] argument emitted as `string`) would make the proxy deny
// legitimate calls once the operator uncomments the entry. Emit the array form
// for a union and fall back to `string` only when no usable type is present.
func propertyTypeYAML(prop interface{}) string {
	propMap, ok := prop.(map[string]interface{})
	if !ok {
		return "string"
	}
	switch t := propMap["type"].(type) {
	case string:
		if t != "" {
			return yamlScalar(t)
		}
	case []interface{}:
		members := make([]string, 0, len(t))
		for _, m := range t {
			if s, ok := m.(string); ok && s != "" {
				members = append(members, yamlScalar(s))
			}
		}
		if len(members) > 0 {
			return "[" + strings.Join(members, ", ") + "]"
		}
	}
	return "string"
}

// serverVersionWildcard returns a wildcarded pin suggestion derived from v, loose
// enough to allow updates while still matching v itself under the drift matcher
// (internal/drift.matchServerVersion). That round-trip is the load-bearing
// property: the matcher treats a trailing "*" as "any value AT this position and
// beyond" and still requires the actual version to HAVE a component there, so a
// wildcard appended past v's last component would not match v — and an operator
// following the inline advice would pin a constraint that fails FM-4 drift against
// the very unchanged server it came from (a self-inflicted strict-drift abort).
// Hence the suggestion only ever wildcards a component v already has:
//
//	"1.2.3" -> "1.2.*"  (any patch of 1.2)
//	"1.2"   -> "1.*"    (any minor of 1; "1.2.*" would need a 3rd component)
//	"2"     -> "2"      (no minor/patch to wildcard; exact pin is the only match)
//
// The sole caller (cmdInit) guards on serverVersion != "", so v is never empty here;
// no empty-string special case is needed (and a bare "*" would contradict the
// "only wildcard a component v has" invariant above).
func serverVersionWildcard(v string) string {
	parts := strings.Split(v, ".")
	switch len(parts) {
	case 1:
		return parts[0]
	case 2:
		return parts[0] + ".*"
	default:
		return parts[0] + "." + parts[1] + ".*"
	}
}

// sortedKeys returns the keys of any string-keyed map in sorted order. The value
// type is a parameter so one helper serves every caller.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// initUsageExit is init's exit code for a usage error. It is 2, matching validate — the
// sibling it shares live-introspection flags with — and contracts, rather than the 1 it
// used: init reports no findings, so it has nothing 1 could mean, and an operator (or a
// scaffolding script) reading a 1 from one command and a 2 from the other for the same
// class of mistake has to learn each command's private convention.
const initUsageExit = 2

// cmdInit runs the `init` subcommand and returns the process exit code (rather
// than calling os.Exit itself), so tests can drive every branch — including the
// fail-closed error paths — without terminating the test binary. args carries
// the subcommand's own arguments (os.Args[2:] in a real invocation), threaded
// from run.

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

Exit codes:
  0  Manifest generated (to stdout, or to --output).
  2  Usage error, or a failure reaching the upstream or writing a file.

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
		return initUsageExit
	}

	// Reject the incoherent --config-output-without--output combination up front, before
	// the live upstream fetch — otherwise the operator waits out the whole introspection
	// (up to liveUpstreamTimeout) only to be told their flags were incoherent (matches
	// buildInitUpstreamSpec's reject-flag-mixes-before-the-first-network-call posture).
	if *configOutput != "" && *output == "" {
		fmt.Fprintf(os.Stderr, "eunox init: --config-output requires --output (the config references the manifest file)\n")
		return initUsageExit
	}

	positional := fs.Args()
	spec, err := buildInitUpstreamSpec(*transportFlag, *upstreamURL, *authHeader, *tlsSkipVerify, positional)
	if err != nil {
		fmt.Fprintf(os.Stderr, "eunox init: %v\n", err)
		return initUsageExit
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
