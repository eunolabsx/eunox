// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"strings"
	"testing"
)

// TestRedactURL_ExactOutputs pins the consolidated redactor's exact output for every
// credential-carrying shape — asserting not just that the secret is gone but that the
// scheme, host, path, and query parameter NAMES survive (a blunt over-redactor that
// flattened every credentialed input would satisfy a mere secret-absence check but fail
// here). The empty and clean-unchanged cases sit in the same table.
func TestRedactURL_ExactOutputs(t *testing.T) {
	cases := map[string]string{
		"https://mcp.example.com/x": "https://mcp.example.com/x",
		// Userinfo and the query value are both redacted.
		"https://u:p@mcp.example.com/x?y=1": "https://REDACTED:REDACTED@mcp.example.com/x?y=<redacted len=1>",
		"":                                  "",
		"not-a-url-but-still-a-string":      "not-a-url-but-still-a-string",
		"http://onlyuser@host":              "http://REDACTED:REDACTED@host",
		// A credential in the query string must be scrubbed even with no userinfo.
		"https://api.example.com/mcp?api_key=sk-live-9f3c2a": "https://api.example.com/mcp?api_key=<redacted len=14>",
		// Multiple params: every value scrubbed, names and order preserved.
		"https://h/p?token=abc&mode=fast": "https://h/p?token=<redacted len=3>&mode=<redacted len=4>",
		// Percent-encoded value: the reported length is the DECODED byte count (4 bytes
		// for the emoji), matching what redactConfigValue reports for the same secret in
		// plain config, not the 12-byte encoded form.
		"https://h/p?api_key=%F0%9F%90%B9": "https://h/p?api_key=<redacted len=4>",
		// A bare query token with no '=' is a value with no name and could be a
		// credential (e.g. ?sk_live_...), so it is redacted to a length-only
		// placeholder rather than passed through — matching redactRawQuery's behavior
		// on the unparseable path.
		"https://h/p?verbose": "https://h/p?<redacted len=7>",
		// A key= with an empty value carries no secret and is left as-is.
		"https://h/p?flag=": "https://h/p?flag=",
		// url.Parse fails on the trailing invalid percent escape, but the userinfo must
		// still be stripped rather than returned verbatim in a support bundle.
		"https://alice:super-secret@example.com/%": "https://REDACTED@example.com/%",
		// Parse failure with no userinfo: nothing sensitive, returned unchanged.
		"https://example.com/%": "https://example.com/%",
		// A bare '@' in the PATH of a hierarchical URL (no authority credentials, so
		// u.User is nil and u.Opaque is empty) is not a secret: it must be returned
		// unchanged, not over-redacted to a "<redacted unparseable URL>" placeholder.
		"https://example.com/path@here": "https://example.com/path@here",
		"https://host/mcp@v1?x=1":       "https://host/mcp@v1?x=<redacted len=1>",
		// A credential in the FRAGMENT (OAuth 2.0 implicit flow #access_token=...)
		// must be scrubbed, just as the query-string form is.
		"https://mcp.example.com/sse#access_token=SECRETVALUE": "https://mcp.example.com/sse",
		// Fragment alongside a query: both go.
		"https://h/p?x=1#token=abc": "https://h/p?x=<redacted len=1>",
		// A bare '#' carries nothing and is preserved through u.String().
		"https://h/p#": "https://h/p#",
		// Single-slash scheme typo: url.Parse puts the whole credentialed authority in
		// u.Path, which no scrub inspects, so this used to be returned verbatim.
		"https:/alice:SECRET@host/mcp": "<redacted unparseable URL>",
		// Scheme-less "user@host/path": same shape, same fail-safe outcome.
		"alice@host/mcp": "<redacted unparseable URL>",
		// An authority-less hierarchical URL keeps its path: the empty authority is
		// explicit ("//"), so the '@' really is a path character, not a typo'd credential.
		"file:///home/a@b/x": "file:///home/a@b/x",
	}
	for in, want := range cases {
		if got := RedactURL(in); got != want {
			t.Errorf("RedactURL(%q): got %q, want %q", in, got, want)
		}
	}
}

// TestRedactURL_MalformedNeverLeaksPassword covers the shapes where the credential does
// NOT land in u.User — a parse failure, or a parse-success opaque/scheme-less form — so
// the userinfo/query scrubs do not fire and the value must be routed to a fail-safe path
// rather than returned verbatim, regardless of how url.Parse behaves.
func TestRedactURL_MalformedNeverLeaksPassword(t *testing.T) {
	for _, in := range []string{
		"https://alice:super-secret@example.com/%",
		"ftp://user:super-secret@[bad host]/path",
		"super-secret@host\x00",
		// Malformed (trailing invalid percent escape) with an unescaped '/' before the
		// '@', so the authority is cut short of the userinfo boundary and carries no
		// '@' itself; the fallback must still not return the value verbatim and leak
		// the embedded secret.
		"https://alice:super-secret/x@example.com/%",
		// url.Parse SUCCEEDS on these but yields an opaque/scheme-less form where the
		// credential never lands in u.User, so the userinfo/query scrubs do not fire;
		// they must not be returned verbatim.
		"custom:user:super-secret@thing",  // opaque: Scheme="custom", Opaque="user:super-secret@thing"
		"user:super-secret@host.com/path", // scheme-less: Scheme="user", Opaque="super-secret@host.com/path"
		// Opaque body that ALSO contains a later "://": the credential sits BEFORE it, so
		// an authority scan anchored on the first "://" would look past the '@' and return
		// the value verbatim. RedactURL must redact wholesale on the opaque '@'.
		"scheme:user:super-secret@host://path",
		"scheme:user:super-secret@host://path?token=xyz",
		// Opaque userinfo alongside a query.
		"https:alice:super-secret@host?token=xyz",
		// '?'-before-'@' ordering (url.Parse fails on the non-numeric port): the fallback
		// must not leak the credential prefix by cutting at '?' before scanning for '@'.
		"https://user:super-secret?x@host/p",
		// A single-slash scheme typo parses CLEANLY, with the credential landing in
		// u.Path where neither the userinfo, query, fragment, nor opaque scrub reaches
		// it — so `changed` stayed false and the raw value went straight to stderr.
		"https:/alice:super-secret@host/mcp",
		"http:/alice:super-secret@host/mcp?token=xyz",
		// Scheme-less "user@host/path" with no colon: also lands wholly in u.Path.
		"alice-super-secret@host.com/path",
	} {
		if got := RedactURL(in); strings.Contains(got, "super-secret") {
			t.Errorf("RedactURL(%q) leaked the password: %q", in, got)
		}
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

// TestLoadGatewayConfig_UnsetEnvRefInAuditPaths verifies that an unset
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
