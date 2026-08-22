// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
)

// TestSchemaVersionFromNode_ResolvesAnAlias covers the blind spot topLevelValueNode had: an
// `*ref` node carries no Value of its own, so both readers saw an aliased schemaVersion as
// ABSENT.
//
// The two consequences were different and both wrong. The gateway loader refused a document
// that declares its version perfectly well as missing one. The manifest loader skipped its
// PRE-DECODE version gate and fell through to the raw decode — producing exactly the opaque
// "cannot unmarshal number into string" coercion misdiagnosis that gate's ordering exists to
// prevent, for a version this build supports.
//
// The two readers are exercised directly because the mapping that holds the ANCHOR has to live
// somewhere both loaders accept, and their strict unknown-field rejection leaves no neutral
// place to put one in a fixture — see TestLoadManifest_AliasedSchemaVersionLoads for the
// end-to-end half.
func TestSchemaVersionFromNode_ResolvesAnAlias(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		src         string
		want        string
		wantPresent bool
		wantNumeric bool
	}{
		{
			name:        "aliased string",
			src:         "version: &ver \"0.1\"\nschemaVersion: *ver\n",
			want:        "0.1",
			wantPresent: true,
		},
		{
			// Unquoted 0.1 auto-types to !!float. Reaching the reader at all is what lets the
			// friendly gate and the retag run; before the fix this shape was invisible.
			name:        "aliased bare number is seen AND reported numeric",
			src:         "version: &ver 0.1\nschemaVersion: *ver\n",
			want:        "0.1",
			wantPresent: true,
			wantNumeric: true,
		},
		{
			name:        "direct value still reads the same way",
			src:         "schemaVersion: \"0.1\"\n",
			want:        "0.1",
			wantPresent: true,
		},
		{
			name: "genuinely absent stays absent",
			src:  "version: \"0.1.0\"\n",
		},
		{
			// An alias to a MAPPING is not a scalar version; it must read as absent rather
			// than as some rendering of the mapping.
			name: "alias to a non-scalar is not a version",
			src:  "listen: &l\n  port: 3000\nschemaVersion: *l\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var node yaml.Node
			if err := yaml.Unmarshal([]byte(tc.src), &node); err != nil {
				t.Fatalf("parsing fixture: %v", err)
			}
			got, present := schemaVersionFromNode(&node)
			if present != tc.wantPresent || got != tc.want {
				t.Errorf("schemaVersionFromNode = (%q, %v), want (%q, %v)", got, present, tc.want, tc.wantPresent)
			}
			// The gateway reader shares topLevelValueNode, so it must agree on every case —
			// the two disagreeing is what "refused as missing on one loader, mis-decoded on the
			// other" looked like.
			gwGot, numeric := gatewaySchemaVersionFromNode(&node)
			if gwGot != tc.want {
				t.Errorf("gatewaySchemaVersionFromNode = %q, want %q (the two readers must agree)", gwGot, tc.want)
			}
			if numeric != tc.wantNumeric {
				t.Errorf("gatewaySchemaVersionFromNode numeric = %v, want %v", numeric, tc.wantNumeric)
			}
		})
	}
}

// TestLoadManifest_AliasedSchemaVersionLoads is the end-to-end half. The anchor sits on
// serverVersion because both loaders reject unknown fields, so a fixture has no neutral place
// to park one — which is also why the readers above are exercised directly.
func TestLoadManifest_AliasedSchemaVersionLoads(t *testing.T) {
	t.Parallel()

	write := func(t *testing.T, content string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "manifest.yaml")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	t.Run("supported version loads", func(t *testing.T) {
		t.Parallel()
		const src = `name: aliased
version: "0.1.0"
serverVersion: &ver "0.1"
schemaVersion: *ver
capabilities:
  - target: tool:read_file
    actions: [call]
`
		m, err := LoadManifest(write(t, src))
		if err != nil {
			t.Fatalf("an aliased schemaVersion must load: %v", err)
		}
		if m.SchemaVersion != "0.1" {
			t.Errorf("schemaVersion = %q, want %q", m.SchemaVersion, "0.1")
		}
	})

	t.Run("unsupported version is refused BY NAME, not as absent", func(t *testing.T) {
		t.Parallel()
		const src = `name: aliased-bad
version: "0.1.0"
serverVersion: &ver "9.9"
schemaVersion: *ver
capabilities:
  - target: tool:read_file
    actions: [call]
`
		_, err := LoadManifest(write(t, src))
		if err == nil {
			t.Fatal("an unsupported schemaVersion must be refused")
		}
		// The point of resolving the alias: the refusal names what the author wrote instead of
		// reporting the key as missing or dying on an opaque decode error.
		if !strings.Contains(err.Error(), "9.9") {
			t.Errorf("error = %v, want it to name the declared version", err)
		}
	})
}

// TestForceSchemaVersionToString_LeavesASharedAnchorAlone pins the property that makes
// resolving the alias safe: the retag replaces this KEY's slot, never the anchor it points at.
//
// An anchor is shared with every reference to it, so retagging it rewrote fields this function
// has no business touching. See TestLoadManifest_SharedAnchorDoesNotRestrictAPolicy for what
// that cost — the type change here is the mechanism, and a silently non-matching capability is
// the effect.
func TestForceSchemaVersionToString_LeavesASharedAnchorAlone(t *testing.T) {
	t.Parallel()

	const src = `capabilities:
  - values: [&ver 0.2]
schemaVersion: *ver
`
	var node yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(src), &node))

	forceSchemaVersionToString(&node)

	var raw map[string]interface{}
	require.NoError(t, node.Decode(&raw))

	assert.Equal(t, "0.2", raw["schemaVersion"], "the aliased version must decode as a string so the loader's own gate can read it")

	caps, ok := raw["capabilities"].([]interface{})
	require.True(t, ok)
	entry, ok := caps[0].(map[string]interface{})
	require.True(t, ok)
	values, ok := entry["values"].([]interface{})
	require.True(t, ok)
	assert.Equal(t, 0.2, values[0], "a sibling field aliasing the same anchor must keep its own type; retagging the anchor changed it to the string \"0.2\"")
}

// TestForceSchemaVersionToString_RetagsADirectScalarInPlace is the other arm: a value written
// under the key itself is shared with nothing, so it is retagged where it sits.
func TestForceSchemaVersionToString_RetagsADirectScalarInPlace(t *testing.T) {
	t.Parallel()

	var node yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte("schemaVersion: 0.1\n"), &node))
	forceSchemaVersionToString(&node)

	var raw map[string]interface{}
	require.NoError(t, node.Decode(&raw))
	assert.Equal(t, "0.1", raw["schemaVersion"])
}

// TestLoadManifest_SharedAnchorDoesNotRestrictAPolicy is the end-to-end half, and the one that
// says why the node-level property above matters.
//
// Retagging the shared anchor decoded the condition's value as a Go string instead of the
// json.Number every other numeric spelling produces. MatchAllowedValue matches a string entry
// ONLY as a glob, and only against a string argument — so the entry stopped matching the
// numeric argument it was written for, and the capability silently denied every call it was
// meant to allow. Deny-side, and invisible at load time.
//
// Asserted against the PLAIN spelling rather than against a hardcoded type, so the rule under
// test is the one that matters: however the author spells the value, the same argument decides.
func TestLoadManifest_SharedAnchorDoesNotRestrictAPolicy(t *testing.T) {
	t.Parallel()

	write := func(t *testing.T, content string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "manifest.yaml")
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
		return path
	}
	values := func(t *testing.T, path string) []interface{} {
		t.Helper()
		m, err := LoadManifest(path)
		require.NoError(t, err)
		av, ok := m.Capabilities[0].Conditions[0].(*capability.AllowedValuesCondition)
		require.True(t, ok)
		return av.Values
	}

	plain := values(t, write(t, `schemaVersion: "0.1"
name: plain
version: "0.1.0"
capabilities:
  - target: tool:t
    actions: [call]
    conditions:
      - type: allowedValues
        argument: n
        values: [0.2]
`))
	shared := values(t, write(t, `name: shared
version: "0.1.0"
capabilities:
  - target: tool:t
    actions: [call]
    conditions:
      - type: allowedValues
        argument: n
        values: [&ver 0.2]
schemaVersion: *ver
`))

	// A caller's JSON number arrives as a float64.
	const arg = 0.2
	require.True(t, enforcement.MatchAllowedValue(arg, plain, nil),
		"a numeric allowedValues entry must match the numeric argument it names")
	assert.True(t, enforcement.MatchAllowedValue(arg, shared, nil),
		"aliasing the value must not turn the entry into a glob that never matches a numeric argument")
	assert.IsType(t, plain[0], shared[0], "the two spellings must decode to the same type")
}
