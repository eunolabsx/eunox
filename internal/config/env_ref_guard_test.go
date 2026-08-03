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

// failOnUnsetBracedEnvRef ignores the "$$" escape exactly as the other guards do, so an
// operator escaping a literal dollar is not told a variable is unset.
func TestFailOnUnsetBracedEnvRef_SkipsEscapes(t *testing.T) {
	if err := failOnUnsetBracedEnvRef("cfg.yaml", "upstream \"x\" command", "$${NOT_A_REF}"); err != nil {
		t.Errorf("escaped $$ treated as a reference: %v", err)
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
