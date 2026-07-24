// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"strings"
	"testing"
)

// TestRedactURL_Cases pins the consolidated redactor's entry point, including the three
// gaps the old config-side redactor (redactURLForError/coarseRedactURL) had and this
// hoisted redactor closes: an OPAQUE credentialed URL, a PATH-embedded secret, and a
// '?'-before-'@' ordering that leaked the credential prefix. Every case asserts the
// property that matters — the secret substring must NOT survive into the output.
func TestRedactURL_Cases(t *testing.T) {
	for _, tc := range []struct {
		name, in, mustNotContain string
	}{
		{"userinfo password", "https://alice:SECRETPW@example.com/p", "SECRETPW"},
		{"query token", "https://api.example.com/data?api_key=SECRETKEY", "SECRETKEY"},
		{"bare query token", "https://api.example.com/data?SECRETJWT", "SECRETJWT"},
		{"fragment token", "https://example.com/#access_token=SECRETFRAG", "SECRETFRAG"},
		// GAP 1 — opaque credentialed URL: userinfo lands in u.Opaque, so the old
		// early-return "nothing to strip" leaked it. Now routed to the fallback.
		{"opaque userinfo", "https:alice:SECRETOPAQUE@host", "SECRETOPAQUE"},
		{"opaque userinfo + query", "https:alice:SECRETOPAQUE2@host?token=xyz", "SECRETOPAQUE2"},
		// GAP 2 — '?'-before-'@' ordering: the old coarse redactor cut at '?' before
		// scanning for '@', leaving the credential prefix visible.
		{"query before at", "https://user:SECRETORDER?x@host/p", "SECRETORDER"},
		// GAP 3 — secret in the query of an otherwise-normal URL is length-redacted.
		{"path-like query secret", "https://host/webhook?tok=SECRETPATH", "SECRETPATH"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := RedactURL(tc.in)
			if strings.Contains(got, tc.mustNotContain) {
				t.Errorf("RedactURL(%q) = %q, still contains the secret %q", tc.in, got, tc.mustNotContain)
			}
		})
	}

	// A credential-free URL is returned unchanged.
	clean := "https://api.example.com/v1/data"
	if got := RedactURL(clean); got != clean {
		t.Errorf("RedactURL(%q) = %q, want it unchanged", clean, got)
	}
	// Empty stays empty.
	if got := RedactURL(""); got != "" {
		t.Errorf("RedactURL(\"\") = %q, want empty", got)
	}
}

// TestRedactURLFallback_Cases pins the parse-failure fallback (moved here with the
// redactor from cmd/eunox/doctor.go during consolidation).
func TestRedactURLFallback_Cases(t *testing.T) {
	cases := map[string]func(string) bool{
		"user:pw@host":  func(s string) bool { return strings.Contains(s, "redacted unparseable URL") },
		"just-a-string": func(s string) bool { return s == "just-a-string" },
		"https://alice:secret@example.com/p": func(s string) bool {
			return strings.Contains(s, "REDACTED@example.com") && !strings.Contains(s, "secret")
		},
		"https://example.com/%?api_key=sk-live": func(s string) bool {
			return strings.Contains(s, "redacted query") && !strings.Contains(s, "sk-live")
		},
		"https://example.com/%#access_token=sk-frag": func(s string) bool {
			return !strings.Contains(s, "sk-frag") && !strings.Contains(s, "#")
		},
	}
	for in, ok := range cases {
		if got := redactURLFallback(in); !ok(got) {
			t.Errorf("redactURLFallback(%q) = %q (unexpected)", in, got)
		}
	}
}

// TestLoadGatewayConfig_UnsetEnvRefInAuditPaths is the finding-C regression: an unset
// ${VAR} in audit.log / audit.keyPath survives expansion as literal text, which would
// silently misdirect the tamper-evident tape (or its signing key) to a path literally
// named "${VAR}". The loader must fail closed, mirroring the upstreamUrl leg.
func TestLoadGatewayConfig_UnsetEnvRefInAuditPaths(t *testing.T) {
	const unset = "EUNOX_TEST_UNSET_AUDIT_XYZ"
	_ = os.Unsetenv(unset)

	base := func(auditBlock string) string {
		return `
schemaVersion: "0.1"
transport: stdio
upstreams:
  - name: mock
    transport: stdio
    command: echo
    args: ["hi"]
    policy: ["manifest.yaml"]
` + auditBlock
	}

	for _, tc := range []struct{ name, block, wantField string }{
		{"audit.log", "audit:\n  log: \"${" + unset + "}/audit.jsonl\"\n", "audit.log"},
		{"audit.keyPath", "audit:\n  keyPath: \"${" + unset + "}/audit.key\"\n", "audit.keyPath"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadGatewayConfig(writeConfig(t, base(tc.block)))
			if err == nil {
				t.Fatalf("expected a fail-closed error for an unset env ref in %s", tc.wantField)
			}
			if !strings.Contains(err.Error(), tc.wantField) || !strings.Contains(err.Error(), unset) {
				t.Errorf("error = %v, want it to name %q and the unset var %q", err, tc.wantField, unset)
			}
		})
	}

	// A set variable resolves and loads cleanly (no false positive).
	t.Setenv(unset, "/var/log/eunox")
	if _, err := LoadGatewayConfig(writeConfig(t, base("audit:\n  log: \"${"+unset+"}/audit.jsonl\"\n"))); err != nil {
		t.Errorf("a SET env ref in audit.log must load cleanly, got %v", err)
	}
}
