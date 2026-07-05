// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Tests for the `doctor` subcommand's support-bundle generator.
//
// The bundle is the OSS-respectful equivalent of telemetry: nothing leaves the
// machine. The thing we cannot afford to get wrong is leaking a secret into
// the bundle, so the tests are organized around that invariant — every fixture
// plants a known sentinel and asserts the bundle does not contain it.

// Tests for the doctor bundle's manifest and live sections. These drive
// writeDoctorManifests (policy load + merge + audit-only count) and
// writeDoctorLive (live drift via the shared validateConfigRoutes path,
// including the indentWriter) against a config whose stdio upstream re-execs
// the test binary as a real MCP server.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/eunolabs/eunox/internal/config"
)

// ─── redactConfigValue ───────────────────────────────────────────────────────
//
// The redactor walks parsed YAML in place. It must scrub every field on the
// allowlist, strip URL userinfo, and leave everything else alone.

func TestRedactConfigValue_ScrubsAllowlistedFields(t *testing.T) {
	root := map[string]interface{}{
		"listen": map[string]interface{}{
			"bind":      "127.0.0.1", // not on the list — must survive
			"authToken": "super-secret-do-not-leak",
		},
		"upstreams": []interface{}{
			map[string]interface{}{
				"name":               "stripe",
				"upstreamUrl":        "https://user:pa$$word@mcp.stripe.com/x",
				"upstreamAuthHeader": "Authorization: Bearer sk_live_VERYSECRET",
				"args":               []interface{}{"--token=NOT-REDACTED-BY-DESIGN"},
			},
		},
	}
	redactConfigValue(root)
	dump := mustJSON(t, root)

	for _, secret := range []string{
		"super-secret-do-not-leak",
		"pa$$word",
		"sk_live_VERYSECRET",
	} {
		if strings.Contains(dump, secret) {
			t.Errorf("redactConfigValue: secret %q present in output:\n%s", secret, dump)
		}
	}
	// Non-sensitive fields must survive — diagnostic value depends on them.
	for _, keep := range []string{
		"127.0.0.1",              // listen.bind
		"mcp.stripe.com",         // upstream host (URL userinfo stripped, host kept)
		"NOT-REDACTED-BY-DESIGN", // args are explicitly NOT on the allowlist
		"REDACTED",               // placeholder userinfo in the URL
	} {
		if !strings.Contains(dump, keep) {
			t.Errorf("redactConfigValue: expected %q to survive redaction; got:\n%s", keep, dump)
		}
	}
}

func TestRedactConfigValue_ScrubsOAuthAndOriginURLFields(t *testing.T) {
	// The scalar oauthResource and the array-valued oauthAuthorizationServers /
	// allowedOrigins are URL/URI fields under listen. A credential embedded in any of
	// them must be scrubbed exactly like the sibling upstreamUrl, not emitted verbatim.
	root := map[string]interface{}{
		"listen": map[string]interface{}{
			"oauthResource": "https://rsuser:rs-secret-pass@rs.example.com/mcp",
			"oauthAuthorizationServers": []interface{}{
				"https://idpuser:idp-secret-pass@idp.example.com/",
				"https://idp.example.com/?client_secret=idp-query-secret",
			},
			"allowedOrigins": []interface{}{
				"https://originuser:origin-secret-pass@origin.example.com",
			},
		},
	}
	redactConfigValue(root)
	dump := mustJSON(t, root)

	for _, secret := range []string{
		"rs-secret-pass",
		"idp-secret-pass",
		"idp-query-secret",
		"origin-secret-pass",
	} {
		if strings.Contains(dump, secret) {
			t.Errorf("redactConfigValue: secret %q leaked from a URL field:\n%s", secret, dump)
		}
	}
	// Hosts (the diagnostic value) must survive; userinfo scrub leaves REDACTED behind.
	for _, keep := range []string{
		"rs.example.com",
		"idp.example.com",
		"origin.example.com",
		"REDACTED",
	} {
		if !strings.Contains(dump, keep) {
			t.Errorf("redactConfigValue: expected %q to survive redaction; got:\n%s", keep, dump)
		}
	}
}

func TestRedactConfigValue_ScrubsURLFieldsUnderNonStringKeyedMap(t *testing.T) {
	// yaml.v3 decodes a mapping carrying any non-string key as
	// map[interface{}]interface{}; the URL/URI fields must be scrubbed in that arm too,
	// so a non-string sibling key cannot smuggle a credentialed URL through verbatim.
	root := map[interface{}]interface{}{
		8080:            "sentinel-int-key", // forces the non-string-keyed-map arm
		"oauthResource": "https://rsuser:rs-secret-pass@rs.example.com/mcp",
		"oauthAuthorizationServers": []interface{}{
			"https://idpuser:idp-secret-pass@idp.example.com/",
		},
		"allowedOrigins": []interface{}{
			"https://originuser:origin-secret-pass@origin.example.com",
		},
	}
	redactConfigValue(root)

	// encoding/json cannot marshal a non-string-keyed map, so re-emit via yaml.v3 (the
	// same path the doctor bundle uses) and assert no credential survives.
	out, err := yaml.Marshal(root)
	if err != nil {
		t.Fatalf("yaml.Marshal: %v", err)
	}
	dump := string(out)
	for _, secret := range []string{"rs-secret-pass", "idp-secret-pass", "origin-secret-pass"} {
		if strings.Contains(dump, secret) {
			t.Errorf("redactConfigValue: secret %q leaked from a non-string-keyed map:\n%s", secret, dump)
		}
	}
}

// TestRedactConfigValue_ScrubsMisconfiguredURLShapes covers a config the typed loader
// would reject but the doctor bundle still raw-parses and prints: a URL/URI field
// written in the WRONG shape. A credential must be scrubbed whether a list-typed field
// (oauthAuthorizationServers/allowedOrigins) is written as a bare scalar, or a
// scalar-typed field (upstreamUrl/oauthResource) is written as a list. Redaction keys
// on the value's shape, not the schema's, so neither mis-shape leaks.
func TestRedactConfigValue_ScrubsMisconfiguredURLShapes(t *testing.T) {
	root := map[string]interface{}{
		"listen": map[string]interface{}{
			// list-typed keys written as bare scalars (the reported leak).
			"oauthAuthorizationServers": "https://idpuser:idp-scalar-secret@idp.example.com/",
			"allowedOrigins":            "https://originuser:origin-scalar-secret@origin.example.com",
			// a scalar-typed key written as a list (the symmetric mis-shape).
			"oauthResource": []interface{}{"https://rsuser:rs-array-secret@rs.example.com/mcp"},
		},
		"upstreams": []interface{}{
			map[string]interface{}{"upstreamUrl": []interface{}{"https://uuser:up-array-secret@up.example.com"}},
		},
	}
	redactConfigValue(root)
	dump := mustJSON(t, root)

	for _, secret := range []string{
		"idp-scalar-secret",
		"origin-scalar-secret",
		"rs-array-secret",
		"up-array-secret",
	} {
		if strings.Contains(dump, secret) {
			t.Errorf("redactConfigValue: secret %q leaked from a mis-shaped URL field:\n%s", secret, dump)
		}
	}
	// The hosts still survive (redaction strips only userinfo/query/fragment).
	for _, keep := range []string{"idp.example.com", "origin.example.com", "rs.example.com", "up.example.com"} {
		if !strings.Contains(dump, keep) {
			t.Errorf("redactConfigValue: expected host %q to survive; got:\n%s", keep, dump)
		}
	}
}

func TestRedactConfigValue_EmptyAndMissingValues(t *testing.T) {
	// An empty authToken (operator omitted it) must read differently from a
	// present-but-redacted one — otherwise a bug report "authToken was set" is
	// indistinguishable from "authToken was empty".
	root := map[string]interface{}{
		"listen": map[string]interface{}{"authToken": ""},
		"upstreams": []interface{}{
			map[string]interface{}{
				"upstreamAuthHeader": "x",
				"upstreamUrl":        "", // empty URL must not crash url.Parse
			},
		},
	}
	redactConfigValue(root)
	dump := mustJSON(t, root)

	if !strings.Contains(dump, `"authToken":""`) {
		t.Errorf("empty authToken should stay empty (distinct from a redacted present value); got:\n%s", dump)
	}
	if !strings.Contains(dump, `"upstreamAuthHeader":"<redacted len=1>"`) {
		t.Errorf("present authHeader should show length; got:\n%s", dump)
	}
	if !strings.Contains(dump, `"upstreamUrl":""`) {
		t.Errorf("empty URL should stay empty; got:\n%s", dump)
	}
}

func TestRedactURL_StripsUserinfoOnly(t *testing.T) {
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
	}
	for in, want := range cases {
		if got := redactURL(in); got != want {
			t.Errorf("redactURL(%q): got %q, want %q", in, got, want)
		}
	}
}

// A malformed URL whose authority carries userinfo must never disclose the
// embedded password, regardless of how url.Parse fails.
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
	} {
		if got := redactURL(in); strings.Contains(got, "super-secret") {
			t.Errorf("redactURL(%q) leaked the password: %q", in, got)
		}
	}
}

// ─── redactAuditLine ─────────────────────────────────────────────────────────
//
// The audit-tape redactor must scrub the `details` map (which carries tool
// arguments — the most likely place for sensitive payloads) while keeping
// every other field that downstream triage needs.

func TestRedactAuditLine_ScrubsDetailsValuesKeepsKeys(t *testing.T) {
	in := `{"decision":"deny","target_type":"tool","target":"write_file","denial_code":"CAP","details":{"path":"/etc/passwd","content":"PRIVATE-KEY-MATERIAL"},"_hmac":"sha256:abc"}`
	out := redactAuditLine(in)

	if strings.Contains(out, "/etc/passwd") || strings.Contains(out, "PRIVATE-KEY-MATERIAL") {
		t.Errorf("details values leaked: %s", out)
	}
	if !strings.Contains(out, `"path":"<redacted>"`) || !strings.Contains(out, `"content":"<redacted>"`) {
		t.Errorf("details keys missing or values not redacted: %s", out)
	}
	if strings.Contains(out, "_hmac") {
		t.Errorf("HMAC field should be stripped: %s", out)
	}
	// Operationally interesting top-level fields must survive — they are how
	// the reviewer reasons about the bug.
	for _, keep := range []string{"deny", "write_file", "CAP"} {
		if !strings.Contains(out, keep) {
			t.Errorf("expected %q to survive in %s", keep, out)
		}
	}
}

func TestRedactAuditLine_ScrubsCredentialedResourceURI(t *testing.T) {
	in := `{"decision":"allow","target_type":"resource","target":"postgres://admin:hunter2@db:5432/prod?api_key=AKIA"}`
	out := redactAuditLine(in)
	if strings.Contains(out, "hunter2") || strings.Contains(out, "AKIA") {
		t.Errorf("credential leaked from resource target: %s", out)
	}
}

func TestRedactAuditLine_PreservesNonResourceTargetWithURLChars(t *testing.T) {
	// A tool name containing URL-significant characters ('?', '@') must NOT be run
	// through redactURL — it is not a URI and carries no credential, and mangling it
	// would distort the bundle relative to the signed audit tape.
	in := `{"decision":"deny","target_type":"tool","target":"search?q@v"}`
	out := redactAuditLine(in)
	if !strings.Contains(out, `"target":"search?q@v"`) {
		t.Errorf("non-resource tool target with URL chars must survive verbatim, got %s", out)
	}
}

func TestRedactAuditLine_UnparseableStaysFlaggedButLossless(t *testing.T) {
	out := redactAuditLine("this is not json")
	if !strings.Contains(out, "unparseable") {
		t.Errorf("expected an unparseable marker, got %s", out)
	}
	if strings.Contains(out, "this is not json") {
		t.Errorf("redactor must not echo back unparseable raw content, got %s", out)
	}
}

// ─── tailAuditLines ──────────────────────────────────────────────────────────

func TestTailAuditLines_ReturnsLastN(t *testing.T) {
	in := "a\nb\nc\nd\ne\n"
	got, err := tailAuditLines(strings.NewReader(in), 3)
	if err != nil {
		t.Fatalf("tailAuditLines: %v", err)
	}
	want := []string{"c", "d", "e"}
	if !equalStringSlice(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestTailAuditLines_SkipsBlankLines(t *testing.T) {
	got, err := tailAuditLines(strings.NewReader("a\n\n\nb\n   \nc\n"), 5)
	if err != nil {
		t.Fatalf("tailAuditLines: %v", err)
	}
	want := []string{"a", "b", "c"}
	if !equalStringSlice(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestTailAuditLines_ZeroReturnsEmpty(t *testing.T) {
	got, err := tailAuditLines(strings.NewReader("a\nb\n"), 0)
	if err != nil {
		t.Fatalf("tailAuditLines: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("n=0 must return no lines, got %v", got)
	}
}

// TestTailAuditLines_HugeNSmallLog is a regression: an enormous --audit-tail must
// not pre-allocate a giant ring against a tiny log. With the pre-alloc capped, a
// huge n against a 2-line log returns just those 2 lines (and does not try to
// reserve n*16 bytes up front).
func TestTailAuditLines_HugeNSmallLog(t *testing.T) {
	got, err := tailAuditLines(strings.NewReader("a\nb\n"), 2_000_000_000)
	if err != nil {
		t.Fatalf("tailAuditLines: %v", err)
	}
	if want := []string{"a", "b"}; len(got) != len(want) || got[0] != "a" || got[1] != "b" {
		t.Errorf("huge n over a 2-line log = %v, want %v", got, want)
	}
}

// ─── writeDoctorBundle (end-to-end) ──────────────────────────────────────────
//
// Pin the contract: regardless of which optional inputs are present, planted
// secrets in the config and the audit log must not appear in the bundle.

// shortWriter fails every write once limit bytes have been written, simulating a
// disk filling (ENOSPC) partway through the bundle.
type shortWriter struct {
	limit   int
	written int
}

func (s *shortWriter) Write(p []byte) (int, error) {
	if s.written >= s.limit {
		return 0, fmt.Errorf("no space left on device")
	}
	s.written += len(p)
	return len(p), nil
}

// TestErrTrackingWriter_CapturesShortWrite is the regression for doctor --output
// reporting success on a truncated bundle: a write error partway through must be
// captured so cmdDoctor can exit non-zero instead of printing "Wrote support
// bundle". The errTrackingWriter must latch the first error and keep returning it.
func TestErrTrackingWriter_CapturesShortWrite(t *testing.T) {
	tw := &errTrackingWriter{w: &shortWriter{limit: 100}}
	writeDoctorBundle(tw, doctorOptions{
		auditLogPath: filepath.Join(t.TempDir(), "does-not-exist.jsonl"),
		auditTail:    0,
	})
	if tw.err == nil {
		t.Fatal("errTrackingWriter must capture the mid-bundle write failure so a truncated --output bundle is not announced as complete")
	}
	// Once latched, subsequent writes keep failing (no partial success reported).
	if n, err := tw.Write([]byte("x")); err == nil || n != 0 {
		t.Fatalf("a latched errTrackingWriter must keep failing, got n=%d err=%v", n, err)
	}
}

func TestWriteDoctorBundle_NoConfigNoLog(t *testing.T) {
	var buf bytes.Buffer
	writeDoctorBundle(&buf, doctorOptions{
		auditLogPath: filepath.Join(t.TempDir(), "does-not-exist.jsonl"),
		auditTail:    0,
	})
	out := buf.String()
	for _, marker := range []string{
		"eunox doctor — support bundle",
		"1. Binary",
		"2. Config (redacted)",
		"(no --config provided)",
		"3. Manifests",
		"4. Audit log",
		"5. Live upstream check",
		"End of bundle",
	} {
		if !strings.Contains(out, marker) {
			t.Errorf("bundle missing section/marker %q\n---\n%s", marker, out)
		}
	}
}

func TestWriteDoctorBundle_ConfigSecretsAreRedacted(t *testing.T) {
	configYAML := `
schemaVersion: "0.1"
listen:
  bind: 127.0.0.1
  port: 3000
  authToken: SENTINEL-LISTEN-AUTH-TOKEN
upstreams:
  - name: stripe
    transport: http
    upstreamUrl: https://uuu:SENTINEL-URL-CRED@mcp.stripe.com
    upstreamAuthHeader: "Authorization: Bearer SENTINEL-UPSTREAM-HEADER"
`
	cfgPath := filepath.Join(t.TempDir(), "eunox.yaml")
	doctorWriteFile(t, cfgPath, configYAML)

	var buf bytes.Buffer
	writeDoctorBundle(&buf, doctorOptions{
		configPath:   cfgPath,
		auditLogPath: filepath.Join(t.TempDir(), "no.jsonl"),
		auditTail:    0,
	})
	out := buf.String()

	for _, secret := range []string{
		"SENTINEL-LISTEN-AUTH-TOKEN",
		"SENTINEL-URL-CRED",
		"SENTINEL-UPSTREAM-HEADER",
	} {
		if strings.Contains(out, secret) {
			t.Errorf("bundle leaked secret %q:\n%s", secret, out)
		}
	}
	// The redacted markers should be present so a reviewer can confirm the
	// field was set on the operator's side.
	if !strings.Contains(out, "<redacted len=") {
		t.Errorf("expected at least one length-tagged redaction marker:\n%s", out)
	}
	if !strings.Contains(out, "REDACTED:REDACTED@mcp.stripe.com") {
		t.Errorf("expected URL userinfo to be replaced with REDACTED placeholder:\n%s", out)
	}
	// Host/transport visibility — the diagnostic value of the bundle depends
	// on these surviving.
	for _, keep := range []string{"mcp.stripe.com", "127.0.0.1", "stripe"} {
		if !strings.Contains(out, keep) {
			t.Errorf("expected non-sensitive field %q to survive:\n%s", keep, out)
		}
	}
}

// TestWriteDoctorBundle_NonStringKeyedMapSecretRedacted is the regression for the
// map[interface{}]interface{} redaction gap: gopkg.in/yaml.v3 decodes a mapping with
// ANY non-string key (here the integer 8080) as map[interface{}]interface{}, which the
// redaction walk previously skipped via its no-op default — emitting a sibling secret
// verbatim. The bundle must redact the secret even when a non-string sibling key forces
// the alternate map type.
func TestWriteDoctorBundle_NonStringKeyedMapSecretRedacted(t *testing.T) {
	configYAML := `
schemaVersion: "0.1"
upstreams:
  - name: a
    transport: stdio
    command: echo
    extraMap:
      8080: x
      authToken: SENTINEL-NONSTRING-MAP-SECRET
`
	cfgPath := filepath.Join(t.TempDir(), "eunox.yaml")
	doctorWriteFile(t, cfgPath, configYAML)

	var buf bytes.Buffer
	writeDoctorBundle(&buf, doctorOptions{
		configPath:   cfgPath,
		auditLogPath: filepath.Join(t.TempDir(), "no.jsonl"),
		auditTail:    0,
	})
	out := buf.String()
	if strings.Contains(out, "SENTINEL-NONSTRING-MAP-SECRET") {
		t.Errorf("bundle leaked a secret sharing a map with a non-string key:\n%s", out)
	}
	if !strings.Contains(out, "<redacted len=") {
		t.Errorf("expected a length-tagged redaction marker for the nested authToken:\n%s", out)
	}
}

// TestWriteDoctorBundle_NoPolicyClassification locks the support bundle's
// per-route classification of policyless routes against the startup guards: a
// plain audit route is a valid wiretap, but an audit route carrying a
// strictDrift or expectVersion pin (which the proxy refuses to start without a
// policy) must be reported as WOULD FAIL CLOSED, not as a healthy wiretap.
func TestWriteDoctorBundle_NoPolicyClassification(t *testing.T) {
	configYAML := `
schemaVersion: "0.1"
transport: http
upstreams:
  - name: wiretap
    transport: stdio
    command: echo
    enforcement: audit
  - name: pinned
    transport: stdio
    command: echo
    enforcement: audit
    expectVersion: "1.0.0"
  - name: open
    transport: stdio
    command: echo
`
	cfgPath := filepath.Join(t.TempDir(), "eunox.yaml")
	doctorWriteFile(t, cfgPath, configYAML)

	var buf bytes.Buffer
	writeDoctorBundle(&buf, doctorOptions{
		configPath:   cfgPath,
		auditLogPath: filepath.Join(t.TempDir(), "no.jsonl"),
		auditTail:    0,
	})
	out := buf.String()

	// The plain audit route is a valid wiretap.
	if !strings.Contains(out, "observe-only/wiretap route") {
		t.Errorf("expected the audit route to be reported as a valid wiretap:\n%s", out)
	}
	// The audit route with an expectVersion pin would not start: it must be
	// flagged, with the reason, rather than reported as a wiretap.
	if !strings.Contains(out, "WOULD FAIL CLOSED at startup") || !strings.Contains(out, "expectVersion") {
		t.Errorf("expected the expectVersion-pinned no-policy route to be flagged WOULD FAIL CLOSED:\n%s", out)
	}
	// The non-audit gateway route fails closed under SEC-05 and must be flagged.
	if !strings.Contains(out, `enforcement is not "audit"`) {
		t.Errorf("expected the non-audit gateway route to be flagged as fail-closed:\n%s", out)
	}
}

func TestWriteDoctorBundle_AuditTailRedactsDetails(t *testing.T) {
	// Plant a sensitive payload inside details — it must not appear verbatim in
	// the bundle, even though the surrounding decision/target does.
	rec := map[string]interface{}{
		"decision":    "deny",
		"target":      "write_file",
		"denial_code": "CAP",
		"details":     map[string]interface{}{"path": "SENTINEL-DETAILS-VALUE"},
		"_hmac":       "sha256:deadbeef",
	}
	b, _ := json.Marshal(rec)
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	doctorWriteFile(t, logPath, string(b)+"\n")

	var buf bytes.Buffer
	writeDoctorBundle(&buf, doctorOptions{
		auditLogPath: logPath,
		auditTail:    10,
	})
	out := buf.String()

	if strings.Contains(out, "SENTINEL-DETAILS-VALUE") {
		t.Errorf("bundle leaked details value:\n%s", out)
	}
	if !strings.Contains(out, `"path":"<redacted>"`) {
		t.Errorf("expected redacted details placeholder:\n%s", out)
	}
	if strings.Contains(out, "deadbeef") {
		t.Errorf("HMAC must be stripped from tailed records:\n%s", out)
	}
	// Aggregate counts and operational fields must still be present.
	for _, keep := range []string{"records=1", "write_file", "CAP"} {
		if !strings.Contains(out, keep) {
			t.Errorf("expected %q to survive in the audit section:\n%s", keep, out)
		}
	}
}

func TestWriteDoctorBundle_LiveSkippedWithoutFlag(t *testing.T) {
	var buf bytes.Buffer
	writeDoctorBundle(&buf, doctorOptions{
		auditTail: 0,
		// live: false
	})
	if !strings.Contains(buf.String(), "pass --live") {
		t.Errorf("expected skipped-live note in bundle:\n%s", buf.String())
	}
}

func TestWriteDoctorBundle_LiveRequiresConfig(t *testing.T) {
	var buf bytes.Buffer
	writeDoctorBundle(&buf, doctorOptions{
		live:      true,
		auditTail: 0,
	})
	if !strings.Contains(buf.String(), "--live requires --config") {
		t.Errorf("expected --live-requires-config note:\n%s", buf.String())
	}
}

// ─── cmdDoctor (CLI surface) ─────────────────────────────────────────────────
//
// Exercises the os.Args wiring + --output path. Not parallel — toggles global
// os.Args.

func TestCmdDoctor_OutputFileGetsWritten(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "doctor.txt")
	withArgs([]string{
		"eunox", "doctor",
		"--output", outPath,
		"--audit-log", filepath.Join(t.TempDir(), "absent.jsonl"),
		"--audit-tail", "0",
	}, func() {
		cmdDoctor()
	})
	// The bundle file should exist and contain the header sentinel.
	got := doctorReadFile(t, outPath)
	if !strings.Contains(got, "eunox doctor — support bundle") {
		t.Errorf("output file missing header:\n%s", got)
	}
}

// TestCmdDoctor_ConfigDefaultsAuditLogPath is a regression: doctor --config
// foo.yaml (no --audit-log) must report against foo.yaml's configured audit.log
// path, matching suggest/stats/audit-verify (which all call
// applyConfigAuditDefaults). Before this, doctor never consulted cfg.Audit.Log,
// so the bundle's audit section silently described the default
// ~/.eunox/audit.jsonl path instead of the deployment's real one.
func TestCmdDoctor_ConfigDefaultsAuditLogPath(t *testing.T) {
	dir := t.TempDir()
	configuredLog := filepath.Join(dir, "configured-audit.jsonl")
	if err := os.WriteFile(configuredLog, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write configured audit log: %v", err)
	}
	cfgPath := filepath.Join(dir, "eunox.yaml")
	if err := os.WriteFile(cfgPath, []byte(`
schemaVersion: "0.1"
transport: stdio
audit:
  log: `+configuredLog+`
upstreams:
  - name: up
    transport: stdio
    command: echo
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	outPath := filepath.Join(dir, "doctor.txt")
	withArgs([]string{
		"eunox", "doctor",
		"--config", cfgPath,
		"--output", outPath,
		"--audit-tail", "0",
	}, func() {
		cmdDoctor()
	})
	got := doctorReadFile(t, outPath)
	// Check the actual "log path:" resolution line specifically, not just any
	// occurrence of configuredLog in the bundle — the bundle separately dumps the
	// raw config file content (including its literal "audit: {log: ...}" line),
	// which would otherwise make this assertion pass even without the fix.
	wantLine := "  log path:  " + configuredLog
	if !strings.Contains(got, wantLine) {
		t.Errorf("bundle's audit section should resolve to the config's audit.log path; want line %q, got:\n%s", wantLine, got)
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// mustJSON marshals v without HTML-escaping `<` `>` `&`, so test assertions
// can use the same literal placeholders ("<redacted>") that the operator sees
// in the bundle — otherwise every assertion would have to spell out `<…`.
func mustJSON(t *testing.T, v interface{}) string {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		t.Fatalf("json.Encode: %v", err)
	}
	return strings.TrimRight(buf.String(), "\n")
}

// doctorWriteFile / doctorReadFile are package-local helpers — the existing
// mustWriteFile in gateway_test.go takes (t, dir, name, content) and returns
// the joined path, which doesn't fit the doctor tests' (t, fullPath, content)
// shape. Renamed to avoid the collision rather than reshape the older signature.
func doctorWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func doctorReadFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // G304: test reads its own tempfile
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func equalStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// helperUpstreamYAMLArgs renders the re-exec args as a YAML inline list so a
// gateway config can spawn TestHelperStdioUpstream as its stdio upstream.
func helperUpstreamYAMLArgs() string {
	return fmt.Sprintf("[%q, %q, %q]", "-test.run=^TestHelperStdioUpstream$", "--", stdioUpstreamSentinel)
}

// cleanManifestYAML is a manifest whose tools exactly match the helper upstream
// (read_file, write_file), with read_file in audit posture so the doctor
// audit-only counter has something to report.
const cleanManifestYAML = `schemaVersion: "0.1"
name: doctor-integ
version: "1.2.3"
serverVersion: "1.0.0"
capabilities:
  - target: "tool:read_file"
    actions: ["call"]
    enforcement: audit
  - target: "tool:write_file"
    actions: ["call"]
`

func TestWriteDoctorManifests_LoadsMergesAndCountsAuditOnly(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "policy.yaml")
	doctorWriteFile(t, manifestPath, cleanManifestYAML)

	cfgPath := filepath.Join(dir, "eunox.yaml")
	cfgYAML := fmt.Sprintf(`schemaVersion: "0.1"
transport: stdio
upstreams:
  - name: integ
    transport: stdio
    command: %q
    args: %s
    policy: [%q]
`, os.Args[0], helperUpstreamYAMLArgs(), manifestPath)
	doctorWriteFile(t, cfgPath, cfgYAML)

	var buf bytes.Buffer
	cfg, cfgErr := config.LoadGatewayConfig(cfgPath)
	writeDoctorManifests(&buf, cfg, cfgErr)
	out := buf.String()

	for _, marker := range []string{
		`route "integ"`,
		"OK    " + manifestPath,
		`name="doctor-integ"`,
		`version="1.2.3"`,
		"merged digest:",
		"pinned serverVersion:    1.0.0",
		"audit-only capabilities: 1",
	} {
		if !strings.Contains(out, marker) {
			t.Errorf("writeDoctorManifests output missing %q\n---\n%s", marker, out)
		}
	}
}

func TestWriteDoctorManifests_ReportsLoadFailure(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "eunox.yaml")
	missing := filepath.Join(dir, "does-not-exist.yaml")
	cfgYAML := fmt.Sprintf(`schemaVersion: "0.1"
transport: stdio
upstreams:
  - name: broken
    transport: stdio
    command: echo
    policy: [%q]
`, missing)
	doctorWriteFile(t, cfgPath, cfgYAML)

	var buf bytes.Buffer
	cfg, cfgErr := config.LoadGatewayConfig(cfgPath)
	writeDoctorManifests(&buf, cfg, cfgErr)
	out := buf.String()
	if !strings.Contains(out, "FAIL  "+missing) {
		t.Errorf("expected a FAIL line for the missing policy file:\n%s", out)
	}
}

// TestWriteDoctorManifests_ReportsWouldFailClosed pins that a policy'd route whose
// manifests merge cleanly but that `proxy` would refuse to boot — here an http
// upstream whose policy opts into system:sampling/createMessage, which is
// unenforceable over the request/response HTTP bridge — is flagged WOULD FAIL
// CLOSED rather than reported OK. The per-file OK line and the merged digest do not
// evaluate that startup-fatal guard; routing through LoadUpstreamPDP (as validate
// does) does.
func TestWriteDoctorManifests_ReportsWouldFailClosed(t *testing.T) {
	dir := t.TempDir()
	samplingPolicy := filepath.Join(dir, "sampling.yaml")
	doctorWriteFile(t, samplingPolicy, `schemaVersion: "0.1"
name: samp
version: "0.1.0"
capabilities:
  - target: "system:sampling/createMessage"
    actions: ["*"]
`)

	cfgPath := filepath.Join(dir, "eunox.yaml")
	cfgYAML := fmt.Sprintf(`schemaVersion: "0.1"
transport: http
upstreams:
  - name: samp
    transport: http
    upstreamUrl: "http://127.0.0.1:9"
    policy: [%q]
`, samplingPolicy)
	doctorWriteFile(t, cfgPath, cfgYAML)

	var buf bytes.Buffer
	cfg, cfgErr := config.LoadGatewayConfig(cfgPath)
	writeDoctorManifests(&buf, cfg, cfgErr)
	out := buf.String()
	// The manifest itself loads and merges fine...
	if !strings.Contains(out, "OK    "+samplingPolicy) || !strings.Contains(out, "merged digest:") {
		t.Errorf("expected the policy to load/merge cleanly:\n%s", out)
	}
	// ...but the route would not boot: doctor must say so, not report a clean OK.
	if !strings.Contains(out, "WOULD FAIL CLOSED at startup") {
		t.Errorf("expected a WOULD FAIL CLOSED line for the sampling-on-http route:\n%s", out)
	}
}

func TestWriteDoctorManifests_BadConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "eunox.yaml")
	doctorWriteFile(t, cfgPath, "this: : not: valid: yaml:\n")

	var buf bytes.Buffer
	cfg, cfgErr := config.LoadGatewayConfig(cfgPath)
	writeDoctorManifests(&buf, cfg, cfgErr)
	if !strings.Contains(buf.String(), "could not load config:") {
		t.Errorf("expected a config-load error line:\n%s", buf.String())
	}
}

func TestWriteDoctorLive_DriftCleanAgainstHelperUpstream(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the test binary as an upstream subprocess; skipped in -short")
	}
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "policy.yaml")
	doctorWriteFile(t, manifestPath, cleanManifestYAML)

	cfgPath := filepath.Join(dir, "eunox.yaml")
	cfgYAML := fmt.Sprintf(`schemaVersion: "0.1"
transport: stdio
upstreams:
  - name: integ
    transport: stdio
    command: %q
    args: %s
    policy: [%q]
`, os.Args[0], helperUpstreamYAMLArgs(), manifestPath)
	doctorWriteFile(t, cfgPath, cfgYAML)

	var buf bytes.Buffer
	cfg, cfgErr := config.LoadGatewayConfig(cfgPath)
	writeDoctorLive(&buf, cfg, cfgErr)
	out := buf.String()

	// indentWriter prefixes every validateConfigRoutes line with two spaces.
	if !strings.Contains(out, "  ── route \"integ\"") {
		t.Errorf("expected indented route header from validateConfigRoutes:\n%s", out)
	}
	if !strings.Contains(out, "Connecting to upstream...  ok") {
		t.Errorf("expected a successful live connection line:\n%s", out)
	}
	if !strings.Contains(out, "validate exit code: 0") {
		t.Errorf("expected a clean (0) validate exit code:\n%s", out)
	}
}

func TestWriteDoctorLive_BadConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "eunox.yaml")
	doctorWriteFile(t, cfgPath, "transport: : nope\n")

	var buf bytes.Buffer
	cfg, cfgErr := config.LoadGatewayConfig(cfgPath)
	writeDoctorLive(&buf, cfg, cfgErr)
	if !strings.Contains(buf.String(), "could not load config:") {
		t.Errorf("expected a config-load error line:\n%s", buf.String())
	}
}

// shortNewlineWriter records all bytes but, for the first write whose slice ends
// in '\n', reports a short count (n = len-1) with a nil error — modeling an
// underlying writer that did not actually flush the trailing newline.
type shortNewlineWriter struct {
	buf     bytes.Buffer
	shorted bool
}

func (s *shortNewlineWriter) Write(p []byte) (int, error) {
	s.buf.Write(p)
	if !s.shorted && len(p) > 0 && p[len(p)-1] == '\n' {
		s.shorted = true
		return len(p) - 1, nil // claim the '\n' was not written
	}
	return len(p), nil
}

// TestIndentWriter_ShortWriteDoesNotMarkLineStart is a regression test: when
// the underlying writer short-writes the chunk ending in '\n' (the newline did
// not reach the stream), indentWriter must NOT set atLineStart, or a subsequent
// Write would prepend an indent prefix mid-line.
func TestIndentWriter_ShortWriteDoesNotMarkLineStart(t *testing.T) {
	sw := &shortNewlineWriter{}
	iw := &indentWriter{w: sw, prefix: []byte("  ")}

	if _, err := iw.Write([]byte("hello\n")); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	if iw.atLineStart {
		t.Error("atLineStart must stay false after a short write that did not flush the newline")
	}
}
