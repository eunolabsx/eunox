// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The forbidden-field checks in Validate reject an HTTP-only key on a stdio
// upstream (and vice versa) by key PRESENCE, not by decoded value, so an explicit
// zero — upstreamTlsSkipVerify: false, command: "" — is refused exactly as the JSON
// Schema refuses it. Presence comes from a second, untyped walk of the same bytes
// (upstreamKeyPresence), which means the two decodes must agree about which keys an
// upstream has.
//
// A YAML merge key (`<<: *anchor`) is where they could disagree: it is the one
// construct that gives a mapping keys its own source text never spells. If the
// untyped walk recorded the literal "<<" instead of the merged-in keys, an operator
// factoring shared settings into an anchor would silently lose the presence half of
// every forbidden-field check on the inheriting upstream.

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeGatewayConfig writes cfg to a temp file and returns its path.
func writeGatewayConfig(t *testing.T, cfg string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "eunox.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

// loadGatewayConfigErr loads cfg from a temp file and returns the load error with
// the (per-test-temp-dir, therefore incomparable) config path elided, so two
// configs' diagnostics can be compared directly.
func loadGatewayConfigErr(t *testing.T, cfg string) string {
	t.Helper()
	path := writeGatewayConfig(t, cfg)
	_, err := LoadGatewayConfig(path)
	if err == nil {
		return ""
	}
	return strings.ReplaceAll(err.Error(), path, "<config>")
}

// TestMergeKey_InheritedForbiddenFieldIsRejectedLikeALiteralOne is the regression:
// a stdio upstream that inherits upstreamTlsSkipVerify through a merge key must be
// refused with the same error as one that writes the key itself. The inherited value
// is false — the zero — so only the presence leg can catch it.
func TestMergeKey_InheritedForbiddenFieldIsRejectedLikeALiteralOne(t *testing.T) {
	t.Parallel()

	inherited := `schemaVersion: "0.1"
transport: http
upstreams:
  - name: remote
    transport: http
    upstreamUrl: http://127.0.0.1:9000
    <<: &shared
      upstreamTlsSkipVerify: false
  - name: local
    transport: stdio
    command: /bin/echo
    <<: *shared
`
	literal := `schemaVersion: "0.1"
transport: http
upstreams:
  - name: remote
    transport: http
    upstreamUrl: http://127.0.0.1:9000
    upstreamTlsSkipVerify: false
  - name: local
    transport: stdio
    command: /bin/echo
    upstreamTlsSkipVerify: false
`

	inheritedErr := loadGatewayConfigErr(t, inherited)
	if inheritedErr == "" {
		t.Fatal("a stdio upstream inheriting 'upstreamTlsSkipVerify' through a merge key loaded successfully; " +
			"the presence check did not see the merged-in key, so an anchor silently defeats it")
	}
	literalErr := loadGatewayConfigErr(t, literal)
	if literalErr == "" {
		t.Fatal("a stdio upstream with a literal 'upstreamTlsSkipVerify: false' loaded successfully")
	}

	const want = `upstream "local": 'upstreamTlsSkipVerify' is not allowed with stdio transport (HTTP-only)`
	if !strings.Contains(inheritedErr, want) {
		t.Errorf("inherited-key error = %s, want it to contain %q", inheritedErr, want)
	}
	if inheritedErr != literalErr {
		t.Errorf("the two configs must be refused identically:\n inherited: %s\n literal:   %s", inheritedErr, literalErr)
	}
}

// TestUpstreamKeyPresence_RecordsMergedKeysNotTheMergeKey pins the mechanism
// underneath: the untyped presence walk resolves `<<` into the keys it merges in,
// rather than recording the literal "<<" (which no forbidden-field check looks for).
func TestUpstreamKeyPresence_RecordsMergedKeysNotTheMergeKey(t *testing.T) {
	t.Parallel()

	raw := []byte(`upstreams:
  - name: remote
    transport: http
    upstreamUrl: http://127.0.0.1:9000
    <<: &shared
      upstreamTlsSkipVerify: false
  - name: local
    transport: stdio
    command: /bin/echo
    <<: *shared
`)
	present, err := upstreamKeyPresence(raw)
	if err != nil {
		t.Fatalf("upstreamKeyPresence: %v", err)
	}
	if len(present) != 2 {
		t.Fatalf("presence entries = %d, want 2", len(present))
	}
	if !present[1]["upstreamTlsSkipVerify"] {
		t.Errorf("upstream[1] presence = %v, want the merged-in 'upstreamTlsSkipVerify' key", present[1])
	}
	if present[1]["<<"] {
		t.Errorf("upstream[1] presence recorded the literal merge key %q; no forbidden-field check looks for it", "<<")
	}
}

// TestMergeKey_BenignInheritanceStillLoads is the control: factoring shared,
// transport-appropriate settings into an anchor is a legitimate thing to do with a
// gateway config and must keep working. The rule is "the inherited key is checked
// like a written one", not "a merge key is refused".
func TestMergeKey_BenignInheritanceStillLoads(t *testing.T) {
	t.Parallel()

	cfg := `schemaVersion: "0.1"
transport: http
upstreams:
  - name: alpha
    transport: http
    upstreamUrl: http://127.0.0.1:9000
    <<: &shared
      enforcement: audit
  - name: beta
    transport: http
    upstreamUrl: http://127.0.0.1:9001
    <<: *shared
`
	loaded, err := LoadGatewayConfig(writeGatewayConfig(t, cfg))
	if err != nil {
		t.Fatalf("LoadGatewayConfig: %v", err)
	}
	if len(loaded.Upstreams) != 2 {
		t.Fatalf("upstreams = %d, want 2", len(loaded.Upstreams))
	}
	for _, u := range loaded.Upstreams {
		if u.Enforcement != "audit" {
			t.Errorf("upstream %q enforcement = %q, want the inherited %q", u.Name, u.Enforcement, "audit")
		}
	}
}
