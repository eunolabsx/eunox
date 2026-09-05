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
	"fmt"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// loadGatewayConfigErr loads cfg from a temp file and returns the load error with
// the (per-test-temp-dir, therefore incomparable) config path elided, so two
// configs' diagnostics can be compared directly.
func loadGatewayConfigErr(t *testing.T, cfg string) string {
	t.Helper()
	path := writeConfig(t, cfg)
	_, err := LoadGatewayConfig(path)
	if err == nil {
		return ""
	}
	return strings.ReplaceAll(err.Error(), path, "<config>")
}

// loadManifestErr is loadGatewayConfigErr's manifest counterpart, eliding the same
// per-test-temp-dir path so two spellings of one document can be compared directly.
func loadManifestErr(t *testing.T, content string) string {
	t.Helper()
	path := writeManifestFile(t, content)
	_, err := LoadManifest(path)
	if err == nil {
		return ""
	}
	return strings.ReplaceAll(err.Error(), path, "<manifest>")
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
	var root yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil {
		t.Fatalf("parse: %v", err)
	}
	present, err := upstreamKeyPresence(&root)
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
	loaded, err := LoadGatewayConfig(writeConfig(t, cfg))
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

// -----------------------------------------------------------------
// resolveMergeKeys: the pre-decode walks see what the decode will
// -----------------------------------------------------------------

// The version gates read the DECODED value and were correct all along — no manifest ever
// reached a grammar it did not declare through a merge. What was wrong is narrower: the walks
// that read the document as WRITTEN scan for a literal key, so a merged declaration was invisible
// to them while the decode saw it. Both symptoms are diagnostics rather than bypasses, and both
// are the merged spelling of a document whose inline spelling is fine.

// The strongest symptom: a legal gateway config that would not start. Asserted as an EQUALITY
// against the inline spelling rather than against a message, so the rule under test is "a merged
// declaration is the declaration", not "this particular error stopped appearing".
func TestMergeKey_GatewaySchemaVersionThroughAMergeIsADeclaration(t *testing.T) {
	t.Parallel()

	const body = `upstreams:
  - name: alpha
    transport: http
    upstreamUrl: http://127.0.0.1:9000
`
	merged := loadGatewayConfigErr(t, "<<: &v\n  schemaVersion: \"0.1\"\n"+body)
	inline := loadGatewayConfigErr(t, "schemaVersion: \"0.1\"\n"+body)

	if merged != inline {
		t.Errorf("a merged schemaVersion must load exactly as the inline spelling does:\nmerged: %s\ninline: %s", merged, inline)
	}
	if strings.Contains(merged, "'schemaVersion' is required") {
		t.Error("the config declares its schemaVersion through a merge; refusing it for not declaring one is the defect")
	}
}

// The manifest half: forceSchemaVersionToString retags an unquoted version so the decode reports
// the friendly unsupported-dialect message rather than an opaque unmarshal error. It retags by
// replacing the key's SLOT — never the shared anchor, for the reason its own doc gives — and a
// merged key had no slot to replace.
func TestMergeKey_ManifestUnquotedSchemaVersionThroughAMergeRetags(t *testing.T) {
	t.Parallel()

	const body = `name: probe
version: "1.0.0"
capabilities:
  - target: "tool:read_file"
    actions: ["call"]
`
	merged := loadManifestErr(t, "<<: &v\n  schemaVersion: 0.1\n"+body)
	inline := loadManifestErr(t, "schemaVersion: 0.1\n"+body)

	if merged != inline {
		t.Errorf("a merged unquoted schemaVersion must be read exactly as the inline spelling is:\nmerged: %s\ninline: %s", merged, inline)
	}
	if strings.Contains(merged, "cannot unmarshal number") {
		t.Error("the opaque unmarshal error is what forceSchemaVersionToString exists to prevent")
	}
}

// The version GATE itself was correct before and stays correct: the pass must not change which
// documents load, only which walks can see their keys.
func TestMergeKey_VersionGatesStillDecideOnTheMergedValue(t *testing.T) {
	t.Parallel()

	unsupported := loadManifestErr(t, `<<: &v
  schemaVersion: "9.9"
name: probe
version: "1.0.0"
capabilities:
  - target: "tool:read_file"
    actions: ["call"]
`)
	if !strings.Contains(unsupported, `unsupported manifest schemaVersion "9.9"`) {
		t.Errorf("a merged future dialect must still be refused as one, got: %s", unsupported)
	}

	// A 0.2-only token under a merged 0.1 declaration is still outside the declared grammar.
	tooNew := loadManifestErr(t, `<<: &v
  schemaVersion: "0.1"
name: probe
version: "1.0.0"
capabilities:
  - target: "tool:refund"
    actions: ["call"]
    conditions:
      - type: blastRadius
        max: 100
`)
	if !strings.Contains(tooNew, "blastRadius") || !strings.Contains(tooNew, `schemaVersion "0.1"`) {
		t.Errorf("a 0.2-only token under a merged 0.1 declaration must still be refused, got: %s", tooNew)
	}
}

// The coercion guard keeps working through a merge — the rev this pass follows made it read
// merged pairs under the merging mapping's own key, and flattening them must not lose that.
func TestMergeKey_CoercedNumberInAMergedConditionIsStillRefused(t *testing.T) {
	t.Parallel()

	got := loadManifestErr(t, `schemaVersion: "0.2"
name: probe
version: "1.0.0"
capabilities:
  - target: "tool:refund"
    actions: ["call"]
    conditions:
      - type: blastRadius
        <<: &s
          max: 010
`)
	if !strings.Contains(got, "max") {
		t.Errorf("a coerced number merged into a condition must still be refused, got: %s", got)
	}
}

// Precedence is the DECODER's, not a copy of its rules: the pre-decode read asks yaml.v3 which
// scalar binds, so own-key-wins, last-`<<`-wins, alias resolution, the self-referential-anchor
// check and the alias-expansion budget are all its. Asserted against the decoder as oracle
// rather than against a hardcoded expectation, which is the only form that can catch a
// divergence.
func TestSchemaVersionRead_MatchesTheDecoder(t *testing.T) {
	t.Parallel()

	docs := []string{
		`schemaVersion: "0.1"`,
		"<<: &v\n  schemaVersion: \"0.1\"",
		"base: &b {schemaVersion: \"0.1\"}\n<<: *b\nschemaVersion: \"0.2\"",
		"one: &x {schemaVersion: \"0.1\"}\ntwo: &y {schemaVersion: \"0.2\"}\n<<: [*x, *y]",
		"root: &r {schemaVersion: \"0.1\"}\nmid: &m\n  <<: *r\n  schemaVersion: \"0.2\"\n<<: *m",
		`other: 1`,
	}
	for _, doc := range docs {
		t.Run(strings.ReplaceAll(doc, "\n", " / "), func(t *testing.T) {
			var node yaml.Node
			if err := yaml.Unmarshal([]byte(doc+"\n"), &node); err != nil {
				t.Fatalf("parse: %v", err)
			}
			// The oracle: what the decode that produces the enforced document binds.
			var want struct {
				SchemaVersion string `yaml:"schemaVersion"`
			}
			if err := node.Decode(&want); err != nil {
				t.Fatalf("oracle decode: %v", err)
			}
			got, _ := schemaVersionFromNode(&node)
			if got != want.SchemaVersion {
				t.Errorf("schemaVersionFromNode = %q, decoder binds %q", got, want.SchemaVersion)
			}
		})
	}
}

// The retag writes a FRESH node and never mutates the one it read, so a scalar reachable from
// somewhere else keeps its own type.
//
// This is the failure forceSchemaVersionToString's doc describes: with `values: [*ver]` beside
// an anchored numeric `schemaVersion`, retagging the anchor decodes that condition's value as a
// Go string rather than a json.Number, and MatchAllowedValue matches a string entry only as a
// glob against a string argument — so the capability silently denies every call it was written
// to allow. It reproduced for the ANCHORED spelling before this change, merge or no merge.
func TestForceSchemaVersion_NeverRetagsASharedScalar(t *testing.T) {
	t.Parallel()

	for _, doc := range []string{
		"schemaVersion: &ver 0.1\nvalues: [*ver]\n",
		"anchor: &ver 0.1\nschemaVersion: *ver\nvalues: [*ver]\n",
		"<<: &d\n  schemaVersion: &ver 0.1\nvalues: [*ver]\n",
	} {
		t.Run(strings.ReplaceAll(doc, "\n", " / "), func(t *testing.T) {
			var node yaml.Node
			if err := yaml.Unmarshal([]byte(doc), &node); err != nil {
				t.Fatalf("parse: %v", err)
			}
			forceSchemaVersionToString(&node)

			var out struct {
				SchemaVersion string        `yaml:"schemaVersion"`
				Values        []interface{} `yaml:"values"`
			}
			if err := node.Decode(&out); err != nil {
				t.Fatalf("decode after retag: %v", err)
			}
			if out.SchemaVersion != "0.1" {
				t.Errorf("schemaVersion = %q, want the verbatim text as a string", out.SchemaVersion)
			}
			if len(out.Values) != 1 {
				t.Fatalf("values = %v", out.Values)
			}
			if _, isString := out.Values[0].(string); isString {
				t.Errorf("values[0] decoded as a Go string; the retag rewrote a scalar it does not own, "+
					"which silently narrows every allowedValues entry aliasing it (got %#v)", out.Values[0])
			}
		})
	}
}

// The pre-decode read must never ACCEPT a document the decode refuses: the gate exists so a
// future dialect is reported as one rather than as a typo, and a gate reading a document the
// enforcement never sees is worse than no gate. Every row here is refused by yaml.v3, so the
// read reports "no version" and the loader falls through to the decode's own diagnosis.
func TestSchemaVersionRead_RefusesNothingTheDecoderRefuses(t *testing.T) {
	t.Parallel()

	for _, doc := range []string{
		"main:\n  <<: &x {schemaVersion: \"0.1\"}\n  <<: &y {schemaVersion: \"0.2\"}\n", // duplicate merge key
		"list: &l\n  - {a: 1}\nt:\n  <<: *l\n",                                          // alias to a sequence
		"a: &A\n  b:\n    <<: *A\n",                                                     // self-referential anchor
	} {
		t.Run(strings.ReplaceAll(doc, "\n", " / "), func(t *testing.T) {
			path := writeManifestFile(t, doc+"name: p\nversion: \"1.0.0\"\ncapabilities: []\n")
			done := make(chan error, 1)
			go func() {
				_, err := LoadManifest(path)
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Error("a document yaml.v3 refuses must not load; the pre-decode read must not resolve it")
				}
			case <-time.After(10 * time.Second):
				t.Fatal("LoadManifest did not terminate")
			}
		})
	}
}

// The alias-expansion budget is yaml.v3's, so a chained-anchor bomb is still refused in
// milliseconds rather than expanded. A pre-decode pass that flattened merges into literal pairs
// defeated it structurally — the decode then counted no aliases at all — and turned a 151 KB
// document into 38 s and 1.5 GB.
func TestSchemaVersionRead_AliasBudgetStillApplies(t *testing.T) {
	t.Parallel()

	doc := "name: p\nversion: \"1.0.0\"\ncapabilities: []\na0: &a0 {k0: 0}\n"
	for i := 1; i <= 2000; i++ {
		doc += fmt.Sprintf("a%d: &a%d {<<: *a%d, k%d: %d}\n", i, i, i-1, i, i)
	}
	path := writeManifestFile(t, doc)

	start := time.Now()
	done := make(chan error, 1)
	go func() {
		_, err := LoadManifest(path)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("an alias bomb must be refused")
		}
		if !strings.Contains(err.Error(), "excessive aliasing") {
			t.Errorf("want yaml.v3's own alias-budget refusal, got: %v", err)
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Errorf("refusal took %v; the budget is not bounding the expansion", elapsed)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("LoadManifest did not terminate on an alias bomb")
	}
}
