// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// -----------------------------------------------------------------
// The effect layer's numeric bounds are subject to the same YAML
// auto-typing coercion as every other enforced number
// -----------------------------------------------------------------

// `max: 0600` is read by YAML as octal 384 — a bound six times the authored one, enforced
// with no load-time signal. The values:/enum: and maxCalls/argumentSchema fields were
// already guarded; the effect layer's three numeric bounds were the gap.
func TestLoadManifest_RejectsCoercedEffectNumerics(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			name: "blastRadius condition max",
			body: effectManifest("", `  - target: tool:refund
    actions: [call]
    conditions:
      - type: blastRadius
        max: 0600
`),
		},
		{
			name: "blastRadius condition maxTotal",
			body: effectManifest("", `  - target: tool:refund
    actions: [call]
    conditions:
      - type: blastRadius
        maxTotal: 0600
        windowSeconds: 3600
`),
		},
		{
			name: "effect contract blastRadius value",
			body: effectManifest("", `  - target: tool:refund
    actions: [call]
    effect:
      class: irreversible
      blastRadius:
        value: 0600
        unit: usd
`),
		},
		{
			name: "byArgument case blastRadius value",
			body: effectManifest("", `  - target: tool:db_query
    actions: [call]
    effect:
      class: irreversible
      byArgument:
        argument: sql
        cases:
          DROP:
            class: irreversible
            blastRadius:
              value: 0600
`),
		},
		{
			name: "effectCeiling maxBlastRadius",
			body: effectManifest("effectCeiling:\n  maxBlastRadius: 0600\n", `  - target: tool:refund
    actions: [call]
`),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := writeEffectManifest(t, tc.body)
			if err == nil {
				t.Fatal("an unquoted leading-zero bound reads as octal and must be rejected, not silently enforced")
			}
			if !strings.Contains(err.Error(), "quote it") {
				t.Errorf("error should guide the author to quote/canonicalize, got: %v", err)
			}
		})
	}
}

// The canonical spellings must still load: the guard rejects text that YAML rewrote, not
// numbers as such.
func TestLoadManifest_AcceptsCanonicalEffectNumerics(t *testing.T) {
	_, err := writeEffectManifest(t, effectManifest("effectCeiling:\n  maxBlastRadius: 1000\n", `  - target: tool:refund
    actions: [call]
    effect:
      class: irreversible
      blastRadius:
        value: 384
        unit: usd
    conditions:
      - type: blastRadius
        max: 500
        maxTotal: 2000
        windowSeconds: 3600
`))
	if err != nil {
		t.Fatalf("canonical numeric bounds must load: %v", err)
	}
}

// -----------------------------------------------------------------
// policy / custom conditions: a blank backend or name is a deny-all
// -----------------------------------------------------------------

// Every other condition whose misconfiguration denies at runtime is rejected at load.
// These two had no validation arm at all, so an empty backend/name loaded clean and then
// denied every matching call at request time with no diagnostic pointing at the manifest.
func TestLoadManifest_RejectsUnnamedPolicyAndCustomConditions(t *testing.T) {
	mkYAML := func(cond string) string {
		return `
name: "t"
version: "1.0.0"
capabilities:
  - target: "tool:transfer"
    actions: [call]
    conditions:
` + cond
	}
	cases := []struct {
		name string
		cond string
		want string
	}{
		{"policy empty backend", "      - type: policy\n        backend: \"\"\n", "backend"},
		{"policy whitespace backend", "      - type: policy\n        backend: \"   \"\n", "backend"},
		{"policy missing backend", "      - type: policy\n", "backend"},
		{"custom empty name", "      - type: custom\n        name: \"\"\n", "name"},
		{"custom whitespace name", "      - type: custom\n        name: \"  \"\n", "name"},
		{"custom missing name", "      - type: custom\n", "name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadManifest(writeManifestFile(t, mkYAML(tc.cond)))
			if err == nil {
				t.Fatal("an unnamed backend/handler denies every matching call at runtime and must be rejected at load")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error should name the missing field %q, got: %v", tc.want, err)
			}
		})
	}
}

// A named backend/handler still loads: the check is for a NAME, not for registration —
// evaluators are registered by the embedding program, possibly after the manifest loads.
func TestLoadManifest_AcceptsNamedPolicyAndCustomConditions(t *testing.T) {
	body := `
name: "t"
version: "1.0.0"
capabilities:
  - target: "tool:transfer"
    actions: [call]
    conditions:
      - type: policy
        backend: opa
      - type: custom
        name: my_handler
        config: {k: v}
`
	if _, err := LoadManifest(writeManifestFile(t, body)); err != nil {
		t.Fatalf("a named policy backend and custom handler must load: %v", err)
	}
}

// -----------------------------------------------------------------
// byArgument case compensation against the INHERITED class
// -----------------------------------------------------------------

// A row that names a compensating action while inheriting a non-compensable base class
// used to load clean and then have the field scrubbed at resolution: the author's declared
// reversal silently did not exist. Validating against the EFFECTIVE (inherited) class
// turns it into the same load-time error every other compensable mismatch gets.
func TestLoadManifest_RejectsCaseCompensationUnderInheritedNonCompensableClass(t *testing.T) {
	_, err := writeEffectManifest(t, effectManifest("", `  - target: tool:db_query
    actions: [call]
    effect:
      class: irreversible
      byArgument:
        argument: sql
        cases:
          DROP:
            compensatingAction: tool:restore_backup
`))
	if err == nil {
		t.Fatal("a case declaring compensatingAction under an inherited irreversible class must be rejected at load")
	}
	if !strings.Contains(err.Error(), "compensatingAction") {
		t.Errorf("error should name the offending field, got: %v", err)
	}
}

// The legitimate spellings still load: a case that raises itself to compensable AND names
// its action, and a case that inherits a compensable base without restating either.
func TestLoadManifest_AcceptsCaseCompensationSpellings(t *testing.T) {
	t.Run("case raises itself to compensable with an action", func(t *testing.T) {
		if _, err := writeEffectManifest(t, effectManifest("", `  - target: tool:db_query
    actions: [call]
    effect:
      class: irreversible
      byArgument:
        argument: sql
        cases:
          DELETE:
            class: compensable
            compensatingAction: tool:restore_backup
`)); err != nil {
			t.Fatalf("a case that declares both class and action must load: %v", err)
		}
	})

	t.Run("case inherits a compensable base", func(t *testing.T) {
		if _, err := writeEffectManifest(t, effectManifest("", `  - target: tool:refund
    actions: [call]
    effect:
      class: compensable
      compensatingAction: tool:reverse_refund
      byArgument:
        argument: mode
        cases:
          partial:
            blastRadius:
              value: 100
`)); err != nil {
			t.Fatalf("a case inheriting a compensable base (which already named its action) must load: %v", err)
		}
	})

	// A row may RESTATE the class it already inherits. It names no action of its own, but
	// ResolveEffect overlays a row's fields only when non-empty, so it inherits the base's
	// and resolves identically to the silent spelling above. Rejecting it for "declaring a
	// class with no compensatingAction" judged the row's own fields instead of the pair
	// that gets enforced, and refused an honest manifest whose only sin was being explicit.
	t.Run("case restates the compensable class it inherits", func(t *testing.T) {
		if _, err := writeEffectManifest(t, effectManifest("", `  - target: tool:refund
    actions: [call]
    effect:
      class: compensable
      compensatingAction: tool:reverse_refund
      byArgument:
        argument: mode
        cases:
          partial:
            class: compensable
            blastRadius:
              value: 100
`)); err != nil {
			t.Fatalf("a case restating its inherited compensable class inherits the base's action too: %v", err)
		}
	})

	// The guard still fires when NOTHING supplies the reversal: the row raises itself to
	// compensable over a base that names no action, so the resolved effect would be a
	// compensable with nothing to compensate it.
	t.Run("case raises itself over a base with no action", func(t *testing.T) {
		_, err := writeEffectManifest(t, effectManifest("", `  - target: tool:db_query
    actions: [call]
    effect:
      class: irreversible
      byArgument:
        argument: sql
        cases:
          DELETE:
            class: compensable
`))
		if err == nil {
			t.Fatal("a case raising itself to compensable with no action to inherit must be rejected at load")
		}
		if !strings.Contains(err.Error(), "compensatingAction") {
			t.Errorf("error should name the missing field, got: %v", err)
		}
	})
}

// The effect layer's numeric bounds have GENERIC spellings (`max`, `value`), and the
// coercion walk visits every mapping in the document. Scoping them to their own blocks is
// what keeps the guard from rejecting an opaque `policy`/`custom` condition payload — both
// are `interface{}`, author-defined input handed verbatim to an external evaluator, where
// eunox enforces nothing and so cannot "silently change the enforced policy".
func TestLoadManifest_NumericGuardIsScopedToTheEffectLayer(t *testing.T) {
	for _, tc := range []struct {
		name string
		cond string
	}{
		{"custom config value", "      - type: custom\n        name: geofence\n        config: {value: 0600}\n"},
		{"custom config max", "      - type: custom\n        name: geofence\n        config: {max: 010}\n"},
		{"policy input value", "      - type: policy\n        backend: opa\n        input: {value: 1.0}\n"},
		{"policy config max", "      - type: policy\n        backend: opa\n        config: {max: 010}\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := "schemaVersion: \"0.1\"\nname: t\nversion: 1.0.0\ncapabilities:\n" +
				"  - target: tool:x\n    actions: [call]\n    conditions:\n" + tc.cond
			if _, err := writeEffectManifest(t, body); err != nil {
				t.Fatalf("an opaque evaluator payload is not an enforced number and must load: %v", err)
			}
		})
	}
}
