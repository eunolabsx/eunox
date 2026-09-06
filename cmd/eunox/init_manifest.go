// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The `init` subcommand and the starter manifest generator behind it: produces a YAML
// manifest with every tool commented out, so operators uncomment and add conditions only
// for tools the agent needs.

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

// yamlScalar renders s as a single-line YAML scalar safe in both block and flow contexts.
// Upstream-controlled names are interpolated into the scaffold, so an unquoted name like
// "read: report # prod" would produce invalid YAML (or silently retarget the entry) once
// uncommented.
func yamlScalar(s string) string {
	// Accept yaml.v3's own rendering only when it round-trips in ALL THREE shapes the value
	// is interpolated into (bare value, flow-sequence element, block-mapping key) — each
	// shape catches a distinct failure a per-character check would miss (e.g. "<<" is only
	// structural as a key). Anything that fails falls to the quoted fallback below.
	if b, err := yaml.Marshal(s); err == nil {
		out := strings.TrimRight(string(b), "\n")
		if strings.IndexFunc(out, isYAMLLineBreak) == -1 &&
			yamlDecodesTo(out, s) && yamlFlowSeqDecodesTo(out, s) && yamlBlockKeyDecodesTo(out, s) {
			return out
		}
	}
	// strconv.Quote is YAML-correct for valid UTF-8, but not for raw bytes 0x80-0xFF
	// (Go's \xNN means a raw byte, YAML's means U+00NN) — fall back to !!binary for those.
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

// yamlFlowSeqDecodesTo reports whether out, placed as a single flow-sequence element,
// decodes back to exactly want — catching a plain rendering that would split the
// `required: [..]` list or be reinterpreted as a mapping key.
func yamlFlowSeqDecodesTo(out, want string) bool {
	var got []string
	if err := yaml.Unmarshal([]byte("["+out+"]"), &got); err != nil {
		return false
	}
	return len(got) == 1 && got[0] == want
}

// yamlBlockKeyDecodesTo reports whether out, placed as a block-mapping key, decodes to a
// single mapping whose only key is exactly want — catches the YAML merge key "<<", which
// round-trips fine as a value/flow element but silently merges when used as a key.
func yamlBlockKeyDecodesTo(out, want string) bool {
	var m map[string]string
	if err := yaml.Unmarshal([]byte(out+": v\n"), &m); err != nil {
		return false
	}
	_, ok := m[want]
	return len(m) == 1 && ok
}

// generateInitManifestYAML returns a deny-all starter YAML manifest: every tool entry is
// commented out. With pinDescriptions, each entry gets a descriptionHash for startup
// detection of description changes.
func generateInitManifestYAML(tools []drift.UpstreamTool, manifestName, serverVersion string, pinDescriptions bool) string {
	var sb strings.Builder
	sb.WriteString("schemaVersion: \"0.1\"\n")
	fmt.Fprintf(&sb, "name: %s\n", yamlScalar(manifestName))
	sb.WriteString("version: \"0.1.0\"\n")
	if serverVersion != "" {
		// Suggest a wildcard only when it's both looser than the exact version and still
		// matches it — a bare major like "2" has no such form, so skip the suggestion.
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
			// embedded line break, which would otherwise break out of the comment and plant
			// an ACTIVE capability into the deny-all starter.
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

// initUpstreamSpec describes the upstream `init` was pointed at. Exactly one of
// {URL, Command} is set, selected by Transport.
type initUpstreamSpec struct {
	Transport     string   // "http" or "stdio"
	URL           string   // http: upstream base URL
	AuthHeader    string   // http: optional "Name: Value" auth header
	TLSSkipVerify bool     // http: introspected with --upstream-tls-skip-verify
	Command       string   // stdio: subprocess command
	Args          []string // stdio: subprocess args
	// ProtocolVersion is the operator's per-upstream revision pin, which selects the opener
	// the probe uses — empty (the default) opens with the handshake, as `init` always does:
	// it is pointed at an upstream no config has yet described.
	ProtocolVersion capability.Revision
}

// initRouteName is the placeholder route name `eunox init` scaffolds; it becomes the
// /mcp/<name> segment in http mode and is renamed by the operator before production.
const initRouteName = "upstream"

// generateInitConfigYAML returns a runnable eunox config fronting the introspected
// upstream. The host transport mirrors the upstream transport so `eunox proxy --config`
// works out of the box.
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
			// Persisted verbatim (not as an env-ref) so the config is runnable out of the
			// box — that means this file now holds a cleartext credential, so flag it
			// in-line (and see the matching stderr warning in cmdInit).
			sb.WriteString("    # SECURITY: the line below is a cleartext credential (from --upstream-auth-header).\n")
			sb.WriteString("    # Consider replacing it with an env-ref, e.g. \"Authorization: Bearer ${UPSTREAM_TOKEN}\",\n")
			sb.WriteString("    # and keep this file out of version control either way.\n")
			fmt.Fprintf(&sb, "    upstreamAuthHeader: %s\n", yamlScalar(u.AuthHeader))
		} else {
			sb.WriteString("    # upstreamAuthHeader: \"Authorization: Bearer ${UPSTREAM_TOKEN}\"\n")
		}
		// Preserve so the config can reconnect to the same self-signed upstream `init` used.
		if u.TLSSkipVerify {
			sb.WriteString("    upstreamTlsSkipVerify: true   # init introspected with --upstream-tls-skip-verify (development only)\n")
		}
	}

	fmt.Fprintf(&sb, "    policy: [%s]\n", yamlScalar(manifestPath))
	sb.WriteString("    # expectVersion: \"0.1.0\"   # pin the manifest version; fail closed on mismatch\n")
	return sb.String()
}

// yamlStringList renders a string slice as a YAML flow-style sequence, each element via
// yamlScalar so an arg carrying a flow delimiter or invalid UTF-8 still round-trips.
func yamlStringList(items []string) string {
	parts := make([]string, len(items))
	for i, s := range items {
		parts[i] = yamlScalar(s)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// toolEntryYAMLLines returns the unindented YAML content lines for one tool entry (the
// caller prefixes each with "  # "). With pinDescriptions, a hash is emitted even for an
// empty description — skipping it would leave a tool-poisoning gap.
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
		return nil
	}

	// additionalProperties: false closes the schema, both denying an undeclared argument
	// at request time and arming the FM-6 startup drift check (an open schema can't detect
	// a new, unreviewed parameter). The operator relaxes it if the tool needs open args.
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
				// Only keep a required name with a matching property: since the scaffold
				// emits additionalProperties:false, a required field absent from properties
				// would make the schema unsatisfiable and fail the whole manifest.
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

// propertyTypeYAML renders the `type:` value for one inputSchema property as a YAML scalar
// or flow sequence. JSON Schema permits `type` to be a union array (e.g. nullable params as
// ["string","null"]); collapsing that to a wrong scalar would make the proxy deny legitimate
// calls once the entry is uncommented, since the engine checks declared types strictly.
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

// serverVersionWildcard returns a wildcard pin suggestion loose enough to allow updates
// while still matching v under the drift matcher — it only ever wildcards a component v
// already has ("1.2.3"->"1.2.*", "2"->"2"), since a wildcard past v's last component would
// not match v and would self-inflict an FM-4 drift abort.
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

// sortedKeys returns the keys of any string-keyed map in sorted order.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// initUsageExit is init's exit code for a usage error: 2, matching validate/contracts
// rather than 1, since init reports no findings and 1 would mean nothing here.
const initUsageExit = 2

// initUsage is the `init` subcommand's help text, a constant so the command body does not
// carry a screen of prose inline.
const initUsage = `Usage:
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
`

// cmdInit runs the `init` subcommand, returning the exit code (rather than calling
// os.Exit) so tests can drive every branch including the fail-closed error paths.
func cmdInit(args []string) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	setUsage(fs, args, initUsage)

	transportFlag := fs.String("transport", config.HostTransportHTTP, `Upstream transport to introspect: "http" or "stdio".`)
	upstreamURL := fs.String("upstream-url", "", "Base URL of the MCP HTTP server (required with --transport http).")
	output := fs.String("output", "", "Path to write the generated manifest YAML (default: stdout).")
	configOutput := fs.String("config-output", "", "Also write a runnable eunox config to this path that fronts the introspected\nupstream and enforces the generated manifest. Requires --output (the config references it).")
	force := fs.Bool("force", false, "Overwrite --output / --config-output if they already exist (default: refuse to\nclobber). An overwrite also re-tightens the file mode to 0600. Requires --output\n(there is no file to overwrite when the manifest goes to stdout).")
	name := fs.String("name", "generated-manifest", "Value for the manifest name field.")
	authHeader := fs.String("upstream-auth-header", "", `Header forwarded to the HTTP upstream in "Name: Value" format.`)
	protocolVersion := fs.String("upstream-protocol-version", "", "MCP protocol revision to open the upstream leg at, which selects the opener:\n\"auto\" (the default) opens with the `initialize` handshake, or name a revision.\nThe same key an eunox config sets per upstream — pass it so `init` introspects\nthe upstream the way `eunox proxy` would open it.")
	tlsSkipVerify := fs.Bool("upstream-tls-skip-verify", false, "Skip TLS certificate verification for the HTTP upstream (development only).")
	pinDescriptions := fs.Bool("pin-descriptions", false, "Include a descriptionHash field for each tool, computed from its current live\ndescription. When set in the manifest, the proxy verifies the hash at startup\nand aborts if the description has changed — detecting upstream tool poisoning.")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return initUsageExit
	}

	// Reject before the live upstream fetch — otherwise the operator waits out the whole
	// introspection only to be told their flags were incoherent.
	if *configOutput != "" && *output == "" {
		fmt.Fprintf(os.Stderr, "eunox init: --config-output requires --output (the config references the manifest file)\n")
		return initUsageExit
	}
	// --force names files to overwrite, and with the manifest going to stdout there are none.
	// Rejected rather than left inert, per the binary-wide rule stated at cmdContracts' own
	// unpaired-flag guard: an operator who believed they had named an --output otherwise gets
	// the manifest on stdout with nothing saying the invocation was incoherent.
	if *force && *output == "" {
		fmt.Fprintf(os.Stderr, "eunox init: --force requires --output (there is no file to overwrite when the manifest goes to stdout)\n")
		return initUsageExit
	}

	positional := fs.Args()
	spec, err := buildInitUpstreamSpec(*transportFlag, *upstreamURL, *authHeader, *tlsSkipVerify, positional, *protocolVersion)
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
		// Both flags that only mean something with a file to write — --config-output and
		// --force — were already rejected up front, so this branch owes them nothing.
		fmt.Print(manifest)
		return 0
	}

	if err := writeGeneratedFile(*output, manifest, *force); err != nil {
		fmt.Fprintf(os.Stderr, "eunox init: %v\n", err)
		return 2
	}
	fmt.Fprintf(os.Stderr, "Generated manifest %s — review and uncomment the capabilities you want to permit.\n", *output)

	if *configOutput != "" {
		// Absolute so the config works regardless of CWD when `proxy --config` is invoked.
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

// buildInitUpstreamSpec validates and returns the live-introspection target, rejecting
// cross-axis flag mixes up front rather than at the first network call. Shared by `init`
// and `validate --live`.
func buildInitUpstreamSpec(transportMode, upstreamURL, authHeader string, tlsSkipVerify bool, positional []string, protocolVersion string) (initUpstreamSpec, error) {
	// The same rule the config key and the proxy flag take, so a probe cannot be pointed at a
	// revision the proxy would refuse to open.
	if err := config.ValidateProtocolVersionFlag(protocolVersion); err != nil {
		return initUpstreamSpec{}, err
	}
	pin := (&config.UpstreamConfig{ProtocolVersion: protocolVersion}).ResolvedProtocolVersion()
	switch transportMode {
	case config.HostTransportHTTP:
		if upstreamURL == "" {
			return initUpstreamSpec{}, fmt.Errorf("--upstream-url is required with --transport http")
		}
		if len(positional) > 0 {
			return initUpstreamSpec{}, fmt.Errorf("positional args are not allowed with --transport http (got %q); they are the stdio subprocess command", positional)
		}
		return initUpstreamSpec{
			Transport:       config.HostTransportHTTP,
			URL:             upstreamURL,
			AuthHeader:      authHeader,
			TLSSkipVerify:   tlsSkipVerify,
			ProtocolVersion: pin,
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
			Transport:       config.HostTransportStdio,
			Command:         positional[0],
			Args:            positional[1:],
			ProtocolVersion: pin,
		}, nil
	default:
		return initUpstreamSpec{}, fmt.Errorf("--transport must be %q or %q (got %q)", config.HostTransportHTTP, config.HostTransportStdio, transportMode)
	}
}
