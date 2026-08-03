// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// An unset BRACED reference in a stdio upstream's command must fail the load. Without
// this the reference survives expansion as literal "${VAR}" text, the gateway boots, and
// the failure lands at exec time on the first session — so the operator learns of a plain
// config typo from a client's failed handshake instead of at startup.
func TestLoadGatewayConfig_RejectsUnsetBracedEnvRefInCommand(t *testing.T) {
	_, err := LoadGatewayConfig(writeConfig(t, `
schemaVersion: "0.1"
transport: stdio
upstreams:
  - name: fs
    transport: stdio
    command: ${EUNOX_TEST_NO_SUCH_BIN}
    policy: ["fs.yaml"]
`))
	if err == nil {
		t.Fatal("expected a load error for an unset ${VAR} in command")
	}
	for _, want := range []string{`upstream "fs" command`, "EUNOX_TEST_NO_SUCH_BIN", "unset"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to mention %q", err, want)
		}
	}
}

// The same guard covers args, naming the offending index so the operator does not have
// to bisect a long argv by hand.
func TestLoadGatewayConfig_RejectsUnsetBracedEnvRefInArgs(t *testing.T) {
	_, err := LoadGatewayConfig(writeConfig(t, `
schemaVersion: "0.1"
transport: stdio
upstreams:
  - name: fs
    transport: stdio
    command: /usr/bin/server
    args: ["--root", "${EUNOX_TEST_NO_SUCH_ROOT}"]
    policy: ["fs.yaml"]
`))
	if err == nil {
		t.Fatal("expected a load error for an unset ${VAR} in args")
	}
	for _, want := range []string{`upstream "fs" args[1]`, "EUNOX_TEST_NO_SUCH_ROOT"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to mention %q", err, want)
		}
	}
}

// A SET braced reference must load and expand normally — the guard keys on the variable
// being unset, not on the syntax being present.
func TestLoadGatewayConfig_AcceptsSetBracedEnvRefInCommandAndArgs(t *testing.T) {
	t.Setenv("EUNOX_TEST_SERVER_BIN", "/opt/bin/server")
	t.Setenv("EUNOX_TEST_SERVER_ROOT", "/srv/data")

	cfg, err := LoadGatewayConfig(writeConfig(t, `
schemaVersion: "0.1"
transport: stdio
upstreams:
  - name: fs
    transport: stdio
    command: ${EUNOX_TEST_SERVER_BIN}
    args: ["--root", "${EUNOX_TEST_SERVER_ROOT}"]
    policy: ["fs.yaml"]
`))
	if err != nil {
		t.Fatalf("LoadGatewayConfig rejected a config whose references all resolve: %v", err)
	}
	if got := cfg.Upstreams[0].Command; got != "/opt/bin/server" {
		t.Errorf("command = %q, want the reference expanded", got)
	}
	if got := cfg.Upstreams[0].Args[1]; got != "/srv/data" {
		t.Errorf("args[1] = %q, want the reference expanded", got)
	}
}

// command/args are arbitrary subprocess argv, where a bare "$word" is ordinary literal
// text — an OData "?$filter=", a regex "$anchor", a jq expression. Treating it as a
// reference would refuse to START a config that works today, blaming a variable the
// operator never wrote, so the guard is braced-only for these two fields.
func TestLoadGatewayConfig_BareDollarInCommandArgsIsLiteral(t *testing.T) {
	cfg, err := LoadGatewayConfig(writeConfig(t, `
schemaVersion: "0.1"
transport: stdio
upstreams:
  - name: fs
    transport: stdio
    command: /usr/bin/jq
    args: ["$.items[0].name", "--arg", "$NOT_A_VAR"]
    policy: ["fs.yaml"]
`))
	if err != nil {
		t.Fatalf("bare-$ argv rejected; the guard must be braced-only for command/args: %v", err)
	}
	if got := cfg.Upstreams[0].Args[0]; got != "$.items[0].name" {
		t.Errorf("args[0] = %q, want the jq path preserved verbatim", got)
	}
	if got := cfg.Upstreams[0].Args[2]; got != "$NOT_A_VAR" {
		t.Errorf("args[2] = %q, want the bare reference left as literal text", got)
	}
}

// listen.allowedOrigins has no other startup check: an unset ${DASHBOARD_ORIGIN} boots,
// then matches no real Origin header, so a browser client gets a bare 403 with nothing
// on stderr connecting it to the typo. This one keeps the broader bare-$ rule, matching
// the other URL-shaped fields.
func TestLoadGatewayConfig_RejectsUnsetEnvRefInAllowedOrigins(t *testing.T) {
	_, err := LoadGatewayConfig(writeConfig(t, `
schemaVersion: "0.1"
transport: http
listen:
  bind: 127.0.0.1
  port: 3000
  authToken: static-token
  allowedOrigins: ["https://ok.example", "${EUNOX_TEST_NO_SUCH_ORIGIN}"]
upstreams:
  - name: fs
    transport: stdio
    command: /usr/bin/server
    policy: ["fs.yaml"]
`))
	if err == nil {
		t.Fatal("expected a load error for an unset ${VAR} in listen.allowedOrigins")
	}
	for _, want := range []string{"listen.allowedOrigins[1]", "EUNOX_TEST_NO_SUCH_ORIGIN"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to mention %q", err, want)
		}
	}
}

// The braced-only guard ignores the "$$" escape exactly as the full one does, so an operator
// escaping a literal dollar is not told a variable is unset. The escape is deliberately NOT
// part of what a grammar narrows: it is how a literal "${" is written at all, which a
// braced-only field needs as much as a full one.
func TestFailOnUnsetBracedEnvRef_SkipsEscapes(t *testing.T) {
	for _, g := range []envGrammar{envGrammarFull, envGrammarBraced, envGrammarURL} {
		if err := failOnUnsetEnvRefUnder("cfg.yaml", "upstream \"x\" command", "$${NOT_A_REF}", g); err != nil {
			t.Errorf("escaped $$ treated as a reference under grammar %d: %v", g, err)
		}
	}
}

// TestLoadGatewayConfig_BareDollarInUpstreamURLQueryIsLiteral pins the split in the
// upstreamUrl rule. A URL's query legitimately carries a bare "$" — OData's "?$filter=",
// "?$select=", a JSONPath expression — and the broad bare-$ rule refused to start such a
// config, naming an environment variable ("filter") the operator never wrote. The braced
// form still carries unambiguous intent to substitute, so it is still guarded there.
func TestLoadGatewayConfig_BareDollarInUpstreamURLQueryIsLiteral(t *testing.T) {
	cfg, err := LoadGatewayConfig(writeConfig(t, `
schemaVersion: "0.1"
transport: http
listen:
  bind: "127.0.0.1:9000"
upstreams:
  - name: odata
    transport: http
    upstreamUrl: "https://api.example.com/odata?$filter=name eq 'x'&$select=id"
    policy: ["odata.yaml"]
`))
	if err != nil {
		t.Fatalf("a bare $ in an upstreamUrl query was rejected: %v", err)
	}
	if got := cfg.Upstreams[0].UpstreamURL; got != "https://api.example.com/odata?$filter=name eq 'x'&$select=id" {
		t.Errorf("upstreamUrl = %q, want the OData query preserved verbatim", got)
	}
}

// The authority half keeps the broad rule: a bare "$HOST" there is a reference by any
// reading, and letting it boot points the route at a literal "$HOST".
func TestLoadGatewayConfig_RejectsUnsetBareEnvRefInUpstreamURLHost(t *testing.T) {
	_, err := LoadGatewayConfig(writeConfig(t, `
schemaVersion: "0.1"
transport: http
listen:
  bind: "127.0.0.1:9000"
upstreams:
  - name: api
    transport: http
    upstreamUrl: "https://$EUNOX_TEST_NO_SUCH_HOST/mcp"
    policy: ["api.yaml"]
`))
	if err == nil {
		t.Fatal("expected a load error for an unset bare $VAR in an upstreamUrl host")
	}
	for _, want := range []string{`upstream "api" upstreamUrl`, "EUNOX_TEST_NO_SUCH_HOST", "unset"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to mention %q", err, want)
		}
	}
}

// And the braced form is still guarded inside the query, where intent is unambiguous.
func TestLoadGatewayConfig_RejectsUnsetBracedEnvRefInUpstreamURLQuery(t *testing.T) {
	_, err := LoadGatewayConfig(writeConfig(t, `
schemaVersion: "0.1"
transport: http
listen:
  bind: "127.0.0.1:9000"
upstreams:
  - name: api
    transport: http
    upstreamUrl: "https://api.example.com/mcp?tenant=${EUNOX_TEST_NO_SUCH_TENANT}"
    policy: ["api.yaml"]
`))
	if err == nil {
		t.Fatal("expected a load error for an unset ${VAR} in an upstreamUrl query")
	}
	if !strings.Contains(err.Error(), "EUNOX_TEST_NO_SUCH_TENANT") {
		t.Errorf("error = %q, want it to name the unset variable", err)
	}
}

// TestLoadGatewayConfig_BareDollarInURLQueryIsNotSubstituted is the other half of the split,
// and the one the guard fix left open. The guard governs REFUSAL; expansion governs REWRITING.
// A bare "$filter" in a query no longer fails startup, but the tree-wide expansion still
// substituted it whenever a variable of that name happened to be set — a valid OData URL
// rewritten into something else, silently, on the field that decides which upstream the proxy
// talks to. "$$" escaped it, which is an escape an operator only learns about after the URL
// breaks.
func TestLoadGatewayConfig_BareDollarInURLQueryIsNotSubstituted(t *testing.T) {
	t.Setenv("filter", "PWNED")
	t.Setenv("select", "PWNED")
	t.Setenv("frag", "PWNED")
	const raw = "https://api.example.com/odata?$filter=name eq 'x'&$select=id#$frag"
	cfg, err := LoadGatewayConfig(writeConfig(t, `
schemaVersion: "0.1"
transport: http
listen:
  bind: "127.0.0.1:9000"
upstreams:
  - name: odata
    transport: http
    upstreamUrl: "`+raw+`"
    policy: ["odata.yaml"]
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := cfg.Upstreams[0].UpstreamURL; got != raw {
		t.Errorf("upstreamUrl = %q, want the query and fragment preserved verbatim (%q)", got, raw)
	}
}

// The authority half still expands the bare form: that is where a "$HOST" is a reference by
// any reading, and narrowing it would be a silent loss of a working spelling.
func TestLoadGatewayConfig_BareDollarInURLAuthorityStillExpands(t *testing.T) {
	t.Setenv("EUNOX_TEST_HOST", "api.internal")
	cfg, err := LoadGatewayConfig(writeConfig(t, `
schemaVersion: "0.1"
transport: http
listen:
  bind: "127.0.0.1:9000"
upstreams:
  - name: api
    transport: http
    upstreamUrl: "https://$EUNOX_TEST_HOST/mcp?$filter=x"
    policy: ["api.yaml"]
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got, want := cfg.Upstreams[0].UpstreamURL, "https://api.internal/mcp?$filter=x"; got != want {
		t.Errorf("upstreamUrl = %q, want %q — full grammar in the authority, braced-only in the query", got, want)
	}
}

// The braced form is substituted everywhere in the URL, query included: it is unambiguous
// intent, which is exactly why the guard still refuses it there when unset.
func TestLoadGatewayConfig_BracedRefInURLQueryStillExpands(t *testing.T) {
	t.Setenv("EUNOX_TEST_TENANT", "acme")
	cfg, err := LoadGatewayConfig(writeConfig(t, `
schemaVersion: "0.1"
transport: http
listen:
  bind: "127.0.0.1:9000"
upstreams:
  - name: api
    transport: http
    upstreamUrl: "https://api.example.com/mcp?tenant=${EUNOX_TEST_TENANT}&$filter=x"
    policy: ["api.yaml"]
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got, want := cfg.Upstreams[0].UpstreamURL, "https://api.example.com/mcp?tenant=acme&$filter=x"; got != want {
		t.Errorf("upstreamUrl = %q, want %q", got, want)
	}
}

// TestLoadGatewayConfig_BareDollarInArgvIsNotSubstituted is the same fix on the other
// braced-only field family. argv is passed verbatim to another program, which is why its GUARD
// was already braced-only — and why substituting a bare "$anchor" there was the same silent
// rewrite: a regex, a jq expression, or anything the child interpolates itself.
func TestLoadGatewayConfig_BareDollarInArgvIsNotSubstituted(t *testing.T) {
	t.Setenv("anchor", "PWNED")
	t.Setenv("HOME2", "PWNED")
	cfg, err := LoadGatewayConfig(writeConfig(t, `
schemaVersion: "0.1"
transport: stdio
upstreams:
  - name: fs
    transport: stdio
    command: "/usr/bin/tool$anchor"
    args: ["--match=^x$anchor", "--home=$HOME2"]
    policy: ["fs.yaml"]
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got, want := cfg.Upstreams[0].Command, "/usr/bin/tool$anchor"; got != want {
		t.Errorf("command = %q, want %q verbatim", got, want)
	}
	if got, want := cfg.Upstreams[0].Args, []string{"--match=^x$anchor", "--home=$HOME2"}; len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("args = %q, want %q verbatim — the grammar declared on the slice applies to each element", got, want)
	}
}

// And the braced form still expands in argv, so an operator's ${SERVER_BIN} keeps working.
func TestLoadGatewayConfig_BracedRefInArgvStillExpands(t *testing.T) {
	t.Setenv("EUNOX_TEST_BIN", "/opt/mcp/server")
	t.Setenv("EUNOX_TEST_ROOT", "/srv")
	cfg, err := LoadGatewayConfig(writeConfig(t, `
schemaVersion: "0.1"
transport: stdio
upstreams:
  - name: fs
    transport: stdio
    command: "${EUNOX_TEST_BIN}"
    args: ["--root=${EUNOX_TEST_ROOT}"]
    policy: ["fs.yaml"]
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := cfg.Upstreams[0].Command; got != "/opt/mcp/server" {
		t.Errorf("command = %q, want the braced reference expanded", got)
	}
	if got := cfg.Upstreams[0].Args; len(got) != 1 || got[0] != "--root=/srv" {
		t.Errorf("args = %q, want the braced reference expanded", got)
	}
}

// TestEnvGrammar_GuardAndExpansionReadOneDeclaration pins the property the whole type exists
// for: for any given field, the spellings the guard treats as references are exactly the ones
// the expansion substitutes. They were two independent rules, and the gap between them is what
// let a URL query be refused by one and rewritten by the other.
func TestEnvGrammar_GuardAndExpansionReadOneDeclaration(t *testing.T) {
	t.Setenv("EUNOX_TEST_SET", "value")
	for name, tc := range map[string]struct {
		grammar    envGrammar
		raw        string
		recognized bool // does this field's grammar treat the reference as one?
	}{
		"bare in a full field":            {envGrammarFull, "$EUNOX_TEST_SET", true},
		"braced in a full field":          {envGrammarFull, "${EUNOX_TEST_SET}", true},
		"bare in a braced-only field":     {envGrammarBraced, "$EUNOX_TEST_SET", false},
		"braced in a braced-only field":   {envGrammarBraced, "${EUNOX_TEST_SET}", true},
		"bare in a URL authority":         {envGrammarURL, "https://$EUNOX_TEST_SET/x", true},
		"bare in a URL query":             {envGrammarURL, "https://h/x?$EUNOX_TEST_SET=1", false},
		"braced in a URL query":           {envGrammarURL, "https://h/x?${EUNOX_TEST_SET}=1", true},
		"bare in a URL fragment":          {envGrammarURL, "https://h/x#$EUNOX_TEST_SET", false},
		"bare in a URL path before query": {envGrammarURL, "https://h/$EUNOX_TEST_SET?a=1", true},
	} {
		t.Run(name, func(t *testing.T) {
			// The expansion half: a recognized reference is substituted, an unrecognized
			// one is left exactly as written.
			expanded := expandEnvRefsUnder(tc.raw, tc.grammar)
			if got := expanded != tc.raw; got != tc.recognized {
				t.Errorf("expansion rewrote %q to %q; recognized = %v, want %v", tc.raw, expanded, got, tc.recognized)
			}
			// The guard half, asked about the same spelling with the variable UNSET: a
			// recognized reference is refused, an unrecognized one is literal text.
			unset := strings.ReplaceAll(tc.raw, "EUNOX_TEST_SET", "EUNOX_TEST_UNSET_XYZ")
			err := failOnUnsetEnvRefUnder("cfg.yaml", "field", unset, tc.grammar)
			if got := err != nil; got != tc.recognized {
				t.Errorf("guard on %q returned %v; recognized = %v, want %v", unset, err, got, tc.recognized)
			}
		})
	}
}

// TestDeclaredEnvGrammar_ReadsTheFieldsOwnTag is the other half of "one declaration": the
// guards' grammars come from the same struct tags the expansion walk reads, so a field whose
// declaration changes cannot leave the guard on the old rule.
func TestDeclaredEnvGrammar_ReadsTheFieldsOwnTag(t *testing.T) {
	if upstreamURLEnvGrammar != envGrammarURL {
		t.Errorf("upstreamUrl guard grammar = %d, want the URL grammar its field declares", upstreamURLEnvGrammar)
	}
	if upstreamCommandEnvGrammar != envGrammarBraced || upstreamArgsEnvGrammar != envGrammarBraced {
		t.Errorf("command/args guard grammars = %d/%d, want braced-only", upstreamCommandEnvGrammar, upstreamArgsEnvGrammar)
	}
	if got := declaredEnvGrammar[UpstreamConfig]("upstreamAuthHeader"); got != envGrammarFull {
		t.Errorf("an undeclared field = %d, want the full default", got)
	}
	// A field name that stops resolving must be loud, not silently full: falling back would
	// restore exactly the guard/expansion mismatch this lookup removes.
	func() {
		defer func() {
			if recover() == nil {
				t.Error("declaredEnvGrammar must panic on a field name it cannot resolve")
			}
		}()
		_ = declaredEnvGrammar[UpstreamConfig]("noSuchField")
	}()
}
