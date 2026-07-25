// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeConfig writes cfg to a temp file and returns its path.
func writeConfig(t *testing.T, cfg string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "gateway.yaml")
	if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return p
}

// LoadGatewayConfig parses, strictly decodes, env-expands, and validates a
// well-formed stdio gateway config. This exercises the loader in its own package
// rather than only through the cmd/ binary.
func TestLoadGatewayConfig_ParsesValidStdio(t *testing.T) {
	cfg, err := LoadGatewayConfig(writeConfig(t, `
schemaVersion: "0.1"
transport: stdio
upstreams:
  - name: mock
    transport: stdio
    command: echo
    args: ["hi"]
    policy: ["manifest.yaml"]
`))
	if err != nil {
		t.Fatalf("LoadGatewayConfig: %v", err)
	}
	if cfg.Transport != "stdio" {
		t.Errorf("transport = %q, want stdio", cfg.Transport)
	}
	if len(cfg.Upstreams) != 1 || cfg.Upstreams[0].Name != "mock" {
		t.Fatalf("upstreams = %+v, want one named mock", cfg.Upstreams)
	}
}

// listen.trustedProxyHops must survive the strict decode as a real key (not be rejected
// as unknown) and reach the config as a distinguishable pointer, since the transport
// treats an absent key as the single-proxy default rather than as 0.
func TestLoadGatewayConfig_ParsesTrustedProxyHops(t *testing.T) {
	cfg, err := LoadGatewayConfig(writeConfig(t, `
schemaVersion: "0.1"
transport: http
listen:
  bind: 127.0.0.1
  port: 3000
  trustedProxyCIDRs: ["10.0.0.0/8"]
  trustedProxyHops: 3
upstreams:
  - name: mock
    transport: stdio
    command: echo
`))
	if err != nil {
		t.Fatalf("LoadGatewayConfig: %v", err)
	}
	if cfg.Listen.TrustedProxyHops == nil {
		t.Fatal("listen.trustedProxyHops did not parse (nil); an absent pointer is read as the default")
	}
	if got := *cfg.Listen.TrustedProxyHops; got != 3 {
		t.Errorf("listen.trustedProxyHops = %d, want 3", got)
	}
}

// Omitting listen.trustedProxyHops must leave it nil so the transport applies the
// single-proxy default, rather than yielding an explicit 0 (which validation rejects).
func TestLoadGatewayConfig_TrustedProxyHopsAbsentIsNil(t *testing.T) {
	cfg, err := LoadGatewayConfig(writeConfig(t, `
schemaVersion: "0.1"
transport: http
listen:
  bind: 127.0.0.1
  port: 3000
upstreams:
  - name: mock
    transport: stdio
    command: echo
`))
	if err != nil {
		t.Fatalf("LoadGatewayConfig: %v", err)
	}
	if cfg.Listen.TrustedProxyHops != nil {
		t.Errorf("listen.trustedProxyHops = %d, want nil when the key is absent", *cfg.Listen.TrustedProxyHops)
	}
}

// A typo'd / unknown key must be rejected (KnownFields strict decode), so a
// misspelled security-relevant field cannot be silently ignored.
func TestLoadGatewayConfig_RejectsUnknownKey(t *testing.T) {
	_, err := LoadGatewayConfig(writeConfig(t, `
schemaVersion: "0.1"
transport: stdio
upstreammms:           # typo
  - name: mock
    transport: stdio
    command: echo
`))
	if err == nil {
		t.Fatal("expected an error for an unknown top-level key, got nil")
	}
	if !strings.Contains(err.Error(), "upstreammms") {
		t.Errorf("error should name the unknown key, got: %v", err)
	}
}

// A multi-document stream is rejected so an appended (more restrictive) document
// cannot be silently dropped.
func TestLoadGatewayConfig_RejectsMultiDoc(t *testing.T) {
	_, err := LoadGatewayConfig(writeConfig(t, `
schemaVersion: "0.1"
transport: stdio
upstreams:
  - name: mock
    transport: stdio
    command: echo
---
schemaVersion: "0.1"
transport: stdio
upstreams: []
`))
	if err == nil || !strings.Contains(err.Error(), "multiple YAML documents") {
		t.Fatalf("expected a multi-document rejection, got: %v", err)
	}
}

// TestLoadGatewayConfig_ToleratesTrailingEmptyDoc covers a single valid config
// followed by a bare "---" separator (a harmless trailing empty document that
// some editors or CI templating append). go-yaml decodes that trailing document
// as a zero-value node with a nil error; the loader must tolerate it rather than
// wrongly reject the config as multi-document and refuse to start.
func TestLoadGatewayConfig_ToleratesTrailingEmptyDoc(t *testing.T) {
	cfg, err := LoadGatewayConfig(writeConfig(t, `
schemaVersion: "0.1"
transport: stdio
upstreams:
  - name: mock
    transport: stdio
    command: echo
---
`))
	if err != nil {
		t.Fatalf("trailing empty document should load successfully, got: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected a non-nil config")
	}
}

// TestLoadGatewayConfig_RejectsEmptyExpandedAuthToken covers the silent
// auth-disable: an authToken that references an env var set to the empty string
// expands to "" and would otherwise start the HTTP listener with NO
// authentication. The loader must fail closed instead. A var set to a real value
// loads cleanly, and a config that omits authToken entirely (no reference) is
// unaffected.
func TestLoadGatewayConfig_RejectsEmptyExpandedAuthToken(t *testing.T) {
	const cfg = `
schemaVersion: "0.1"
transport: http
listen:
  bind: 127.0.0.1
  port: 3000
  authToken: ${EUNOX_TEST_GATEWAY_TOKEN}
upstreams:
  - name: mock
    transport: stdio
    command: echo
    policy: ["manifest.yaml"]
`
	// Variable set to the empty string: reference expands to "" — must be rejected.
	t.Setenv("EUNOX_TEST_GATEWAY_TOKEN", "")
	if _, err := LoadGatewayConfig(writeConfig(t, cfg)); err == nil {
		t.Fatal("expected LoadGatewayConfig to reject an authToken that expanded to empty, got nil")
	} else if !strings.Contains(err.Error(), "authToken") {
		t.Errorf("error should name authToken, got: %v", err)
	}

	// Variable set to a real value: loads cleanly with the secret as the token.
	t.Setenv("EUNOX_TEST_GATEWAY_TOKEN", "s3cret")
	loaded, err := LoadGatewayConfig(writeConfig(t, cfg))
	if err != nil {
		t.Fatalf("LoadGatewayConfig with a set token: %v", err)
	}
	if loaded.Listen.AuthToken != "s3cret" {
		t.Errorf("authToken = %q, want %q", loaded.Listen.AuthToken, "s3cret")
	}

	// A config that omits authToken entirely (no env reference) is unaffected.
	const noAuth = `
schemaVersion: "0.1"
transport: http
listen:
  bind: 127.0.0.1
  port: 3000
upstreams:
  - name: mock
    transport: stdio
    command: echo
    policy: ["manifest.yaml"]
`
	if _, err := LoadGatewayConfig(writeConfig(t, noAuth)); err != nil {
		t.Fatalf("LoadGatewayConfig without authToken should load cleanly, got: %v", err)
	}
}

// TestLoadGatewayConfig_RejectsUnresolvedAuthTokenReference covers the partial /
// whole-unset case: an UNSET env reference is left intact as literal text, so a
// composite token ("prefix-${SECRET}") or a bare unset "${VAR}" survives non-empty
// and would lock the listener to a literal token no client sends. The loader must
// fail closed pointing at the un-injected secret, not start with a dead token.
func TestLoadGatewayConfig_RejectsUnresolvedAuthTokenReference(t *testing.T) {
	for _, tok := range []string{"prefix-${EUNOX_TEST_UNSET_SECRET}", "${EUNOX_TEST_UNSET_SECRET}", "$EUNOX_TEST_UNSET_SECRET"} {
		cfg := `
schemaVersion: "0.1"
transport: http
listen:
  bind: 127.0.0.1
  port: 3000
  authToken: "` + tok + `"
upstreams:
  - name: mock
    transport: stdio
    command: echo
    policy: ["manifest.yaml"]
`
		// Ensure the variable is unset so the reference is left intact by expansion.
		os.Unsetenv("EUNOX_TEST_UNSET_SECRET")
		_, err := LoadGatewayConfig(writeConfig(t, cfg))
		if err == nil {
			t.Fatalf("authToken %q: expected rejection of an unresolved env reference, got nil", tok)
		}
		if !strings.Contains(err.Error(), "is unset") {
			t.Errorf("authToken %q: error should name the unset reference, got: %v", tok, err)
		}
	}
}

// TestLoadGatewayConfig_RejectsUnresolvedUpstreamAuthHeader covers the upstream
// leg of the env-ref footgun: an upstreamAuthHeader whose env ref is unset (left as
// literal text) or expands to empty must fail closed, mirroring listen.authToken,
// rather than starting and forwarding a dead/literal credential the upstream
// rejects on every call.
func TestLoadGatewayConfig_RejectsUnresolvedUpstreamAuthHeader(t *testing.T) {
	base := func(hdr string) string {
		return `
schemaVersion: "0.1"
transport: http
listen:
  bind: 127.0.0.1
  port: 3000
upstreams:
  - name: stripe
    transport: http
    upstreamUrl: https://mcp.example.com
    upstreamAuthHeader: "` + hdr + `"
    policy: ["manifest.yaml"]
`
	}

	// Unset variable: ref is left as literal text — reject naming the variable.
	os.Unsetenv("EUNOX_TEST_UPSTREAM_KEY")
	if _, err := LoadGatewayConfig(writeConfig(t, base("Authorization: Bearer ${EUNOX_TEST_UPSTREAM_KEY}"))); err == nil {
		t.Fatal("expected rejection of an unset upstreamAuthHeader env reference, got nil")
	} else if !strings.Contains(err.Error(), "is unset") || !strings.Contains(err.Error(), "upstreamAuthHeader") {
		t.Errorf("error should name the unset upstreamAuthHeader reference, got: %v", err)
	}

	// Variable set to the empty string: ref expands to "" — reject.
	t.Setenv("EUNOX_TEST_UPSTREAM_KEY", "")
	if _, err := LoadGatewayConfig(writeConfig(t, base("${EUNOX_TEST_UPSTREAM_KEY}"))); err == nil {
		t.Fatal("expected rejection of an empty-expanded upstreamAuthHeader, got nil")
	} else if !strings.Contains(err.Error(), "upstreamAuthHeader") {
		t.Errorf("error should name upstreamAuthHeader, got: %v", err)
	}

	// Variable set to a real value: loads cleanly with the expanded header.
	t.Setenv("EUNOX_TEST_UPSTREAM_KEY", "sk_live_xyz")
	loaded, err := LoadGatewayConfig(writeConfig(t, base("Authorization: Bearer ${EUNOX_TEST_UPSTREAM_KEY}")))
	if err != nil {
		t.Fatalf("LoadGatewayConfig with a set upstream key: %v", err)
	}
	if got := loaded.Upstreams[0].UpstreamAuthHeader; got != "Authorization: Bearer sk_live_xyz" {
		t.Errorf("upstreamAuthHeader = %q, want the expanded value", got)
	}
}

// An unset $VAR/${VAR} in upstreamUrl survives expansion as literal text; for the
// no-brace, path, and query forms it can still satisfy url.Parse, so without an
// explicit residual-reference guard the gateway would boot a route pointed at a
// literal "${VAR}". LoadGatewayConfig must reject it, naming the upstream.
func TestLoadGatewayConfig_RejectsUnresolvedUpstreamURL(t *testing.T) {
	base := func(u string) string {
		return `
schemaVersion: "0.1"
transport: http
listen:
  bind: 127.0.0.1
  port: 3000
upstreams:
  - name: stripe
    transport: http
    upstreamUrl: "` + u + `"
    policy: ["manifest.yaml"]
`
	}
	os.Unsetenv("EUNOX_TEST_UPSTREAM_HOST")
	// Both the no-brace and the braced form leave a residual reference when unset.
	for _, u := range []string{"https://$EUNOX_TEST_UPSTREAM_HOST/mcp", "https://${EUNOX_TEST_UPSTREAM_HOST}/mcp"} {
		if _, err := LoadGatewayConfig(writeConfig(t, base(u))); err == nil {
			t.Errorf("upstreamUrl %q: expected rejection of the unresolved reference, got nil", u)
		} else if !strings.Contains(err.Error(), "unset") || !strings.Contains(err.Error(), "upstreamUrl") {
			t.Errorf("upstreamUrl %q: error should name the unset upstreamUrl reference, got: %v", u, err)
		}
	}
	// A resolved reference loads cleanly.
	t.Setenv("EUNOX_TEST_UPSTREAM_HOST", "mcp.example.com")
	if _, err := LoadGatewayConfig(writeConfig(t, base("https://$EUNOX_TEST_UPSTREAM_HOST/mcp"))); err != nil {
		t.Fatalf("resolved upstreamUrl reference should load, got: %v", err)
	}
}

// TestLoadGatewayConfig_UpstreamURLEnvRefCheckUsesRawText pins that the residual-
// reference guard is evaluated against the RAW pre-expansion upstreamUrl text, not
// the expanded value. A SET env var whose own value happens to contain "${...}"
// text (e.g. a value that legitimately embeds another placeholder-shaped
// substring) must not make the expanded URL misdiagnosed as an unresolved
// reference — the reference it actually contained (EUNOX_TEST_OUTER) did resolve.
func TestLoadGatewayConfig_UpstreamURLEnvRefCheckUsesRawText(t *testing.T) {
	base := func(u string) string {
		return `
schemaVersion: "0.1"
transport: http
listen:
  bind: 127.0.0.1
  port: 3000
upstreams:
  - name: stripe
    transport: http
    upstreamUrl: "` + u + `"
    policy: ["manifest.yaml"]
`
	}
	// EUNOX_TEST_OUTER is SET, but its value itself contains "${INNER}" literal
	// text — the expanded upstreamUrl still contains that substring, which the old
	// expanded-value check misread as an unresolved reference.
	t.Setenv("EUNOX_TEST_OUTER", "mcp.example.com/${INNER}")
	if _, err := LoadGatewayConfig(writeConfig(t, base("https://$EUNOX_TEST_OUTER/mcp"))); err != nil {
		t.Fatalf("a resolved reference whose value contains placeholder-shaped text must load, got: %v", err)
	}
}

// A token-bearing upstreamUrl that fails validation (e.g. a wrong scheme) must not
// echo the secret userinfo/query verbatim into the error/log. The value is often
// assembled from an expanded env ref, so the leak would land in operator logs.
func TestLoadGatewayConfig_UpstreamURLErrorRedactsSecret(t *testing.T) {
	cfg := `
schemaVersion: "0.1"
transport: http
listen:
  bind: 127.0.0.1
  port: 3000
upstreams:
  - name: stripe
    transport: http
    upstreamUrl: "ftp://alice:hunter2@example.com/mcp?apikey=SEKRET"
    policy: ["manifest.yaml"]
`
	_, err := LoadGatewayConfig(writeConfig(t, cfg))
	if err == nil {
		t.Fatal("expected rejection of a non-http upstreamUrl, got nil")
	}
	if strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "SEKRET") {
		t.Errorf("error must not leak userinfo/query secrets, got: %v", err)
	}
	if !strings.Contains(err.Error(), "example.com") {
		t.Errorf("error should still identify the host for the operator, got: %v", err)
	}
}

// TestLoadGatewayConfig_RejectsEmptyVarWithLiteralText covers the gap where a
// referenced variable is SET to the empty string inside a field that ALSO carries
// literal text (the natural "Bearer ${VAR}" / "Authorization: Bearer ${VAR}" form).
// The field then expands non-empty, so the field == "" guard misses it, and the
// variable is set, so the unset-loop misses it too — yet the credential is blank.
// Both legs must fail closed on the empty value regardless of surrounding literal text.
func TestLoadGatewayConfig_RejectsEmptyVarWithLiteralText(t *testing.T) {
	// listen.authToken leg: "Bearer ${T}" with T="".
	listenCfg := `
schemaVersion: "0.1"
transport: http
listen:
  bind: 127.0.0.1
  port: 3000
  authToken: "Bearer ${EUNOX_TEST_EMPTY_TOKEN}"
upstreams:
  - name: mock
    transport: stdio
    command: echo
    policy: ["manifest.yaml"]
`
	t.Setenv("EUNOX_TEST_EMPTY_TOKEN", "")
	if _, err := LoadGatewayConfig(writeConfig(t, listenCfg)); err == nil {
		t.Fatal("expected rejection of a set-but-empty authToken var with literal text, got nil")
	} else if !strings.Contains(err.Error(), "empty string") || !strings.Contains(err.Error(), "authToken") {
		t.Errorf("error should name authToken and the empty string, got: %v", err)
	}

	// upstreamAuthHeader leg: "Authorization: Bearer ${KEY}" with KEY="".
	upCfg := `
schemaVersion: "0.1"
transport: http
listen:
  bind: 127.0.0.1
  port: 3000
upstreams:
  - name: stripe
    transport: http
    upstreamUrl: https://mcp.example.com
    upstreamAuthHeader: "Authorization: Bearer ${EUNOX_TEST_EMPTY_KEY}"
    policy: ["manifest.yaml"]
`
	t.Setenv("EUNOX_TEST_EMPTY_KEY", "")
	if _, err := LoadGatewayConfig(writeConfig(t, upCfg)); err == nil {
		t.Fatal("expected rejection of a set-but-empty upstreamAuthHeader var with literal text, got nil")
	} else if !strings.Contains(err.Error(), "empty string") || !strings.Contains(err.Error(), "upstreamAuthHeader") {
		t.Errorf("error should name upstreamAuthHeader and the empty string, got: %v", err)
	}
}

// TestLoadGatewayConfig_AcceptsMultiRefWithEmptyAndNonEmptyVar covers the
// composite-token case: a credential field referencing more than one variable where
// one is set to the empty string but another supplies a real secret expands to a
// valid non-empty credential (e.g. "Bearer ${PFX}${TOK}" with PFX="" but TOK set).
// The blank-credential guard must fire only when EVERY referenced variable is empty,
// so this config must load — not be rejected for the empty prefix var alone.
func TestLoadGatewayConfig_AcceptsMultiRefWithEmptyAndNonEmptyVar(t *testing.T) {
	t.Setenv("EUNOX_TEST_MULTIREF_PFX", "")

	// listen.authToken leg: "Bearer ${PFX}${TOK}" with PFX="" and TOK set.
	listenCfg := `
schemaVersion: "0.1"
transport: http
listen:
  bind: 127.0.0.1
  port: 3000
  authToken: "Bearer ${EUNOX_TEST_MULTIREF_PFX}${EUNOX_TEST_MULTIREF_TOK}"
upstreams:
  - name: mock
    transport: stdio
    command: echo
    policy: ["manifest.yaml"]
`
	t.Setenv("EUNOX_TEST_MULTIREF_TOK", "realsecret")
	loaded, err := LoadGatewayConfig(writeConfig(t, listenCfg))
	if err != nil {
		t.Fatalf("multi-ref authToken with an empty prefix var but a set token var must load, got: %v", err)
	}
	if loaded.Listen.AuthToken != "Bearer realsecret" {
		t.Errorf("authToken = %q, want %q", loaded.Listen.AuthToken, "Bearer realsecret")
	}

	// upstreamAuthHeader leg: "Authorization: Bearer ${PFX}${KEY}" with PFX="" and KEY set.
	upCfg := `
schemaVersion: "0.1"
transport: http
listen:
  bind: 127.0.0.1
  port: 3000
upstreams:
  - name: stripe
    transport: http
    upstreamUrl: https://mcp.example.com
    upstreamAuthHeader: "Authorization: Bearer ${EUNOX_TEST_MULTIREF_PFX}${EUNOX_TEST_MULTIREF_KEY}"
    policy: ["manifest.yaml"]
`
	t.Setenv("EUNOX_TEST_MULTIREF_KEY", "sk_live_xyz")
	loaded2, err := LoadGatewayConfig(writeConfig(t, upCfg))
	if err != nil {
		t.Fatalf("multi-ref upstreamAuthHeader with an empty prefix var but a set key var must load, got: %v", err)
	}
	if got := loaded2.Upstreams[0].UpstreamAuthHeader; got != "Authorization: Bearer sk_live_xyz" {
		t.Errorf("upstreamAuthHeader = %q, want %q", got, "Authorization: Bearer sk_live_xyz")
	}
}

// TestLoadGatewayConfig_RejectsWhitespaceOnlyVar covers the gap where every referenced
// variable is set to a value that is non-empty but ONLY whitespace (e.g. a single
// space). The field expands non-empty so the field == "" guard misses it, and the
// variable is set so the unset-loop misses it too — yet "Bearer  " is no credential a
// client would ever send. The blank-credential guard must treat whitespace-only as
// blank and fail closed on both legs.
func TestLoadGatewayConfig_RejectsWhitespaceOnlyVar(t *testing.T) {
	// listen.authToken leg: "Bearer ${T}" with T=" " (a single space).
	listenCfg := `
schemaVersion: "0.1"
transport: http
listen:
  bind: 127.0.0.1
  port: 3000
  authToken: "Bearer ${EUNOX_TEST_WS_TOKEN}"
upstreams:
  - name: mock
    transport: stdio
    command: echo
    policy: ["manifest.yaml"]
`
	t.Setenv("EUNOX_TEST_WS_TOKEN", "   ")
	if _, err := LoadGatewayConfig(writeConfig(t, listenCfg)); err == nil {
		t.Fatal("expected rejection of a whitespace-only authToken var, got nil")
	} else if !strings.Contains(err.Error(), "whitespace") || !strings.Contains(err.Error(), "authToken") {
		t.Errorf("error should name authToken and whitespace, got: %v", err)
	}

	// upstreamAuthHeader leg: "Authorization: Bearer ${KEY}" with KEY="\t".
	upCfg := `
schemaVersion: "0.1"
transport: http
listen:
  bind: 127.0.0.1
  port: 3000
upstreams:
  - name: stripe
    transport: http
    upstreamUrl: https://mcp.example.com
    upstreamAuthHeader: "Authorization: Bearer ${EUNOX_TEST_WS_KEY}"
    policy: ["manifest.yaml"]
`
	t.Setenv("EUNOX_TEST_WS_KEY", "\t")
	if _, err := LoadGatewayConfig(writeConfig(t, upCfg)); err == nil {
		t.Fatal("expected rejection of a whitespace-only upstreamAuthHeader var, got nil")
	} else if !strings.Contains(err.Error(), "whitespace") || !strings.Contains(err.Error(), "upstreamAuthHeader") {
		t.Errorf("error should name upstreamAuthHeader and whitespace, got: %v", err)
	}
}

// TestLoadGatewayConfig_RejectsNullUpstreamEntry covers a null/empty upstreams list
// element (`- null`, or a bare dangling `-`). The typed decoder drops it while the
// presence decoder keeps it, which previously surfaced as a confusing "internal
// upstream-count mismatch". It must now be a clear, index-named user error.
func TestLoadGatewayConfig_RejectsNullUpstreamEntry(t *testing.T) {
	cases := []string{
		`
schemaVersion: "0.1"
transport: stdio
upstreams:
  - null
`,
		`
schemaVersion: "0.1"
transport: http
listen: { bind: 127.0.0.1, port: 3000 }
upstreams:
  - null
  - name: b
    transport: http
    upstreamUrl: http://x
    policy: ["m.yaml"]
`,
	}
	for _, cfg := range cases {
		_, err := LoadGatewayConfig(writeConfig(t, cfg))
		if err == nil {
			t.Fatalf("expected a null upstream entry to be rejected, got nil for:\n%s", cfg)
		}
		if strings.Contains(err.Error(), "internal upstream-count mismatch") {
			t.Errorf("a null upstream entry should not surface as an internal mismatch, got: %v", err)
		}
		if !strings.Contains(err.Error(), "empty") {
			t.Errorf("error should describe the empty upstream entry, got: %v", err)
		}
	}
}

// expandEnvRefs substitutes a set variable and leaves an unset reference intact
// (fail closed: an unset secret reference becomes an unguessable literal, never an
// empty/disabled value). Both $VAR and ${VAR} forms are handled.
func TestExpandEnvRefs(t *testing.T) {
	t.Setenv("EUNOX_TEST_TOKEN", "s3cret")

	cases := map[string]string{
		"plain ${EUNOX_TEST_TOKEN}":   "plain s3cret",
		"plain $EUNOX_TEST_TOKEN":     "plain s3cret",
		"unset ${EUNOX_TEST_UNSET}":   "unset ${EUNOX_TEST_UNSET}",
		"unset $EUNOX_TEST_UNSET end": "unset $EUNOX_TEST_UNSET end",
		"no refs here":                "no refs here",
	}
	for in, want := range cases {
		if got := expandEnvRefs(in); got != want {
			t.Errorf("expandEnvRefs(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestUpstreamKeyPresence_ParallelIndex pins the contract LoadGatewayConfig's
// length assertion depends on: upstreamKeyPresence returns one key set per
// upstream, in the same order as the typed Upstreams slice, recording every
// written key — including those whose value decodes to a zero (args: [],
// upstreamTlsSkipVerify: false). Drift here would let the cross-transport
// forbidden-field check consult the wrong upstream's keys.
func TestUpstreamKeyPresence_ParallelIndex(t *testing.T) {
	raw := []byte(`
schemaVersion: "0.1"
transport: http
upstreams:
  - name: first
    transport: stdio
    command: a
    args: []
  - name: second
    transport: http
    upstreamUrl: https://example.com/mcp
    upstreamTlsSkipVerify: false
`)
	present, err := upstreamKeyPresence(raw)
	if err != nil {
		t.Fatalf("upstreamKeyPresence: %v", err)
	}
	if len(present) != 2 {
		t.Fatalf("len(present) = %d, want 2", len(present))
	}
	for _, key := range []string{"name", "transport", "command", "args"} {
		if !present[0][key] {
			t.Errorf("present[0] missing key %q", key)
		}
	}
	if present[0]["upstreamUrl"] {
		t.Error("present[0] should not carry the second upstream's upstreamUrl key")
	}
	for _, key := range []string{"name", "transport", "upstreamUrl", "upstreamTlsSkipVerify"} {
		if !present[1][key] {
			t.Errorf("present[1] missing key %q", key)
		}
	}
}
