// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeEffectManifest writes body to a temp manifest file and loads it.
func writeEffectManifest(t *testing.T, body string) (*LocalManifest, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "manifest.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return LoadManifest(path)
}

// effectManifest wraps capability/ceiling YAML in the draft-version envelope the effect
// tokens are staged behind.
func effectManifest(ceiling, caps string) string {
	return "schemaVersion: \"0.2\"\nname: t\nversion: 1.0.0\n" + ceiling + "capabilities:\n" + caps
}

// TestEffectGrammarAcceptsAWellFormedPolicy is the allow case: the whole effect grammar
// — a ceiling, a contract, an argument-parameterized table, and both conditions — loads.
func TestEffectGrammarAcceptsAWellFormedPolicy(t *testing.T) {
	m, err := writeEffectManifest(t, effectManifest(
		"effectCeiling:\n  maxEffectClass: compensable\n  maxBlastRadius: 1000\n  onExceed: escalate\n",
		`  - target: tool:refund
    actions: [call]
    effect:
      class: compensable
      compensatingAction: tool:reverse_refund
      blastRadius:
        argument: amount
        unit: usd
      ref: eunox/payments.refund@sha256:69c29150ddda6ddcbb538bc20314a55c83445b8e58d6c50fa189342976e65cdb
    conditions:
      - type: effectClass
        allow: [reversible, compensable]
      - type: blastRadius
        max: 500
  - target: tool:db_query
    actions: [call]
    effect:
      class: reversible
      byArgument:
        argument: query
        cases:
          SELECT: {class: reversible}
          DROP: {class: irreversible}
        default: {class: irreversible}
`))
	if err != nil {
		t.Fatalf("a well-formed effect policy must load: %v", err)
	}
	if !m.HasEffectCeiling() {
		t.Fatal("HasEffectCeiling must report the declared ceiling")
	}
	if got := m.EffectAnnotatedCount(); got != 2 {
		t.Fatalf("EffectAnnotatedCount = %d, want 2", got)
	}
}

// TestEffectGrammarRejections is the deny/malformed table: every shape that would leave
// an operator believing a bound is in force when it is not.
func TestEffectGrammarRejections(t *testing.T) {
	cases := []struct {
		name, ceiling, caps, wantErr string
	}{
		{
			name:    "unknown effect class",
			caps:    "  - target: tool:t\n    actions: [call]\n    effect:\n      class: mostly-harmless\n",
			wantErr: "valid effect classes",
		},
		{
			name:    "compensable with nothing to compensate with",
			caps:    "  - target: tool:t\n    actions: [call]\n    effect:\n      class: compensable\n",
			wantErr: "irreversible wearing a softer label",
		},
		{
			name:    "a compensating action on a non-compensable class",
			caps:    "  - target: tool:t\n    actions: [call]\n    effect:\n      class: irreversible\n      compensatingAction: tool:undo\n",
			wantErr: "declare that class or drop the field",
		},
		{
			name:    "a blast radius declaring both a value and an argument",
			caps:    "  - target: tool:t\n    actions: [call]\n    effect:\n      blastRadius:\n        value: 5\n        argument: amount\n",
			wantErr: "not both",
		},
		{
			name:    "a blast radius declaring neither",
			caps:    "  - target: tool:t\n    actions: [call]\n    effect:\n      blastRadius:\n        unit: usd\n",
			wantErr: "quantifies nothing",
		},
		{
			name:    "a negative blast-radius value",
			caps:    "  - target: tool:t\n    actions: [call]\n    effect:\n      blastRadius:\n        value: -1\n",
			wantErr: "must not be negative",
		},
		{
			name:    "a misspelled key inside the effect block",
			caps:    "  - target: tool:t\n    actions: [call]\n    effect:\n      clazz: reversible\n",
			wantErr: "unknown field",
		},
		{
			name:    "a misspelled key inside a blastRadius block",
			caps:    "  - target: tool:t\n    actions: [call]\n    effect:\n      blastRadius:\n        valu: 5\n",
			wantErr: "unknown field",
		},
		{
			name:    "a byArgument table that decides nothing",
			caps:    "  - target: tool:t\n    actions: [call]\n    effect:\n      byArgument:\n        argument: op\n",
			wantErr: "decides nothing",
		},
		{
			// Matching is case-insensitive after trimming, so two keys that fold together
			// would leave which row wins to map iteration order — a nondeterministic
			// effect class, which is disqualifying for a determinism claim.
			name:    "a byArgument table whose cases collide under case folding",
			caps:    "  - target: tool:t\n    actions: [call]\n    effect:\n      byArgument:\n        argument: q\n        cases:\n          DROP: {class: irreversible}\n          drop: {class: reversible}\n",
			wantErr: "match the same argument value",
		},
		{
			name:    "a byArgument table whose cases collide on surrounding whitespace",
			caps:    "  - target: tool:t\n    actions: [call]\n    effect:\n      byArgument:\n        argument: q\n        cases:\n          DROP: {class: irreversible}\n          \"DROP \": {class: reversible}\n",
			wantErr: "match the same argument value",
		},
		{
			name:    "a byArgument table with no argument named",
			caps:    "  - target: tool:t\n    actions: [call]\n    effect:\n      byArgument:\n        cases:\n          x: {class: reversible}\n",
			wantErr: "requires 'argument'",
		},
		{
			name:    "a malformed contract ref",
			caps:    "  - target: tool:t\n    actions: [call]\n    effect:\n      class: reversible\n      ref: not-a-ref\n",
			wantErr: "contract-id",
		},
		{
			// The pin is only worth anything if it matches what is enforced: a manifest
			// carrying a reviewed contract's id alongside a different contract is exactly
			// the substitution a hash-pinned registry exists to prevent, and eunox can
			// catch it locally because the digest is over the contract's own content.
			name:    "a contract edited after it was pinned",
			caps:    "  - target: tool:t\n    actions: [call]\n    effect:\n      class: irreversible\n      ref: eunox/payments.refund@sha256:69c29150ddda6ddcbb538bc20314a55c83445b8e58d6c50fa189342976e65cdb\n",
			wantErr: "was edited after it was pinned",
		},
		{
			name:    "an effectClass condition with an empty allow set",
			caps:    "  - target: tool:t\n    actions: [call]\n    conditions:\n      - type: effectClass\n        allow: []\n",
			wantErr: "admits nothing",
		},
		{
			name:    "an effectClass condition naming an unknown class",
			caps:    "  - target: tool:t\n    actions: [call]\n    conditions:\n      - type: effectClass\n        allow: [catastrophic]\n",
			wantErr: "unknown class",
		},
		{
			name:    "a blastRadius condition with no bound",
			caps:    "  - target: tool:t\n    actions: [call]\n    conditions:\n      - type: blastRadius\n        max: null\n",
			wantErr: "bounds nothing",
		},
		{
			name:    "a misspelled key on a blastRadius condition",
			caps:    "  - target: tool:t\n    actions: [call]\n    conditions:\n      - type: blastRadius\n        maxx: 5\n",
			wantErr: "unknown field",
		},
		{
			name:    "a ceiling that bounds nothing",
			ceiling: "effectCeiling:\n  onExceed: deny\n",
			caps:    "  - target: tool:t\n    actions: [call]\n",
			wantErr: "bounds nothing",
		},
		{
			name:    "a ceiling with an unknown onExceed",
			ceiling: "effectCeiling:\n  maxEffectClass: reversible\n  onExceed: warn\n",
			caps:    "  - target: tool:t\n    actions: [call]\n",
			wantErr: "valid outcomes",
		},
		{
			name:    "requireCompensation without a class bound never fires",
			ceiling: "effectCeiling:\n  requireCompensation: true\n",
			caps:    "  - target: tool:t\n    actions: [call]\n",
			wantErr: "needs 'maxEffectClass'",
		},
		{
			name:    "a misspelled key inside the ceiling",
			ceiling: "effectCeiling:\n  maxEffectClas: reversible\n",
			caps:    "  - target: tool:t\n    actions: [call]\n",
			wantErr: "unknown field",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := writeEffectManifest(t, effectManifest(c.ceiling, c.caps))
			if err == nil {
				t.Fatalf("this policy must be refused at load")
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("error %q must mention %q", err, c.wantErr)
			}
		})
	}
}

// TestEffectTokensRequireTheFlowEffectGrammar pins the closed-grammar invariant across
// revisions: under "0.1" the effect tokens are not part of the language and a manifest
// using one is refused, rather than silently enabling a predicate that revision does not
// define.
func TestEffectTokensRequireTheFlowEffectGrammar(t *testing.T) {
	published := func(ceiling, caps string) string {
		return "schemaVersion: \"0.1\"\nname: t\nversion: 1.0.0\n" + ceiling + "capabilities:\n" + caps
	}
	cases := []struct{ name, body, wantErr string }{
		{
			name:    "effectCeiling",
			body:    published("effectCeiling:\n  maxEffectClass: reversible\n", "  - target: tool:t\n    actions: [call]\n"),
			wantErr: "top-level effectCeiling was introduced in schemaVersion \"0.2\"",
		},
		{
			name:    "effect contract",
			body:    published("", "  - target: tool:t\n    actions: [call]\n    effect:\n      class: reversible\n"),
			wantErr: "effect contract block was introduced in schemaVersion \"0.2\"",
		},
		{
			name:    "effectClass condition",
			body:    published("", "  - target: tool:t\n    actions: [call]\n    conditions:\n      - type: effectClass\n        allow: [reversible]\n"),
			wantErr: "effectClass condition was introduced in schemaVersion \"0.2\"",
		},
		{
			name:    "blastRadius condition",
			body:    published("", "  - target: tool:t\n    actions: [call]\n    conditions:\n      - type: blastRadius\n        max: 5\n"),
			wantErr: "blastRadius condition was introduced in schemaVersion \"0.2\"",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := writeEffectManifest(t, c.body)
			if err == nil {
				t.Fatal("a 0.2 token must be refused under the 0.1 grammar")
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("error %q must mention %q", err, c.wantErr)
			}
		})
	}
}

// TestMergeEffectCeilingConflicts pins that two files cannot silently disagree about the
// consequence bound: dropping one would RAISE the bound for the other file's
// capabilities, which is the fail-open direction.
func TestMergeEffectCeilingConflicts(t *testing.T) {
	load := func(ceiling string) *LocalManifest {
		m, err := writeEffectManifest(t, effectManifest(ceiling, "  - target: tool:t\n    actions: [call]\n"))
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		return m
	}
	a := load("effectCeiling:\n  maxEffectClass: reversible\n")
	b := load("effectCeiling:\n  maxEffectClass: irreversible\n")
	none, err := writeEffectManifest(t, effectManifest("", "  - target: tool:u\n    actions: [call]\n"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if _, err := MergeManifests([]*LocalManifest{a, b}); err == nil {
		t.Fatal("two disagreeing ceilings must be rejected")
	}
	merged, err := MergeManifests([]*LocalManifest{a, none})
	if err != nil {
		t.Fatalf("a file with no ceiling must merge cleanly: %v", err)
	}
	if merged.EffectCeiling == nil || merged.EffectCeiling.MaxEffectClass != "reversible" {
		t.Fatalf("the declared ceiling must survive the merge, got %+v", merged.EffectCeiling)
	}
	// A second file declaring the SAME ceiling merges cleanly — on a disjoint target, so
	// the merge is testing the ceiling fold and not the overlapping-capability check.
	sameCeiling, err := writeEffectManifest(t, effectManifest("effectCeiling:\n  maxEffectClass: reversible\n", "  - target: tool:v\n    actions: [call]\n"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	same, err := MergeManifests([]*LocalManifest{a, sameCeiling})
	if err != nil {
		t.Fatalf("two identical ceilings must merge cleanly: %v", err)
	}
	if same.EffectCeiling.MaxEffectClass != "reversible" {
		t.Fatalf("merged ceiling = %+v", same.EffectCeiling)
	}
}
