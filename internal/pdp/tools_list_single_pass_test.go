// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The arming pass and the list filter used to ask the same two questions of every entry —
// are its bytes ambiguous, and what does it decode to — and answer them separately, on
// every tools/list, with Tier-2 pinning every advertised tool. Arming now hands its
// per-entry verdicts to the filter. These tests pin what must NOT change: which entries
// survive, and that an entry arming did not conclude on is still decided (not defaulted to
// a keep).

func toolsListWith(entries ...string) json.RawMessage {
	return json.RawMessage(`{"tools":[` + strings.Join(entries, ",") + `]}`)
}

func toolEntryJSON(name, description string) string {
	return fmt.Sprintf(`{"name":%q,"description":%q,"inputSchema":{"type":"object","properties":{"path":{"type":"string","description":"a path"}}}}`, name, description)
}

// A clean catalog filters to exactly the manifest-permitted tools, verdict sharing or not.
func TestFilterToolsList_SharedVerdictsKeepTheSameEntries(t *testing.T) {
	t.Parallel()
	mdp := newTestManifestPDP(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
		capability.Constraint{Target: "tool:list_dir", Actions: []string{"call"}},
	)
	result := toolsListWith(
		toolEntryJSON("read_file", "Read a file."),
		toolEntryJSON("write_file", "Write a file."), // not in the manifest
		toolEntryJSON("list_dir", "List a directory."),
	)

	got := mdp.FilterToolsList(WithSessionID(context.Background(), "sess"), result)

	require.Equal(t, 3, got.Upstream, "every upstream entry must be counted")
	var out struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	require.NoError(t, json.Unmarshal(got.Result, &out))
	names := make([]string, 0, len(out.Tools))
	for _, tl := range out.Tools {
		names = append(names, tl.Name)
	}
	assert.Equal(t, []string{"read_file", "list_dir"}, names)
}

// An entry whose bytes are ambiguous is dropped by the shared verdict, exactly as the
// filter's own scan dropped it before — the entry is never advertised, and the entries
// AROUND it keep their positions, which is what an index-aligned verdict list has to get
// right.
func TestFilterToolsList_SharedVerdictsDropAmbiguousEntryWithoutShiftingSiblings(t *testing.T) {
	t.Parallel()
	mdp := newTestManifestPDP(
		capability.Constraint{Target: "tool:*", Actions: []string{"call"}},
	)
	// The middle entry carries a case-variant duplicate of "description": Go binds the
	// last, a case-sensitive host renders the first.
	ambiguous := `{"name":"middle","description":"<INJECT>","Description":"clean","inputSchema":{}}`
	result := toolsListWith(
		toolEntryJSON("first", "First."),
		ambiguous,
		toolEntryJSON("last", "Last."),
	)

	got := mdp.FilterToolsList(WithSessionID(context.Background(), "sess"), result)

	s := string(got.Result)
	assert.NotContains(t, s, "middle", "an entry whose bytes are ambiguous must not be advertised")
	assert.NotContains(t, s, "INJECT")
	assert.Contains(t, s, "first", "an entry before the dropped one must survive")
	assert.Contains(t, s, "last", "an entry after the dropped one must survive: verdicts are index-aligned")
}

// The fallback path: with neither pin active, arming is never called, so the filter has no
// verdicts at all and must still decide every entry itself.
func TestFilterToolsList_NoArmingPassStillDecidesEveryEntry(t *testing.T) {
	t.Parallel()
	mdp := newTestManifestPDP(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
	)
	mdp.surface = nil // no Tier-2 baseline, and the manifest pins no descriptionHash

	result := toolsListWith(
		toolEntryJSON("read_file", "Read a file."),
		`{"name":"read_file","Name":"other","inputSchema":{}}`, // ambiguous
		toolEntryJSON("write_file", "Write a file."),           // not in the manifest
	)

	got := mdp.FilterToolsList(WithSessionID(context.Background(), "sess"), result)

	var out struct {
		Tools []json.RawMessage `json:"tools"`
	}
	require.NoError(t, json.Unmarshal(got.Result, &out))
	assert.Len(t, out.Tools, 1, "only the clean, permitted entry may survive without an arming pass")
	assert.Contains(t, string(out.Tools[0]), "Read a file.")
}

// verdictAt must never turn a missing verdict into a keep: an out-of-range or nil read is
// "unknown", which sends the filter back to its own evaluation.
func TestVerdictAt_MissingVerdictIsUnknownNotAKeep(t *testing.T) {
	t.Parallel()
	for _, v := range []toolEntryVerdict{
		verdictAt(nil, 0),
		verdictAt([]toolEntryVerdict{{known: true, name: "a"}}, 5),
		verdictAt([]toolEntryVerdict{{known: true, name: "a"}}, -1),
	} {
		assert.False(t, v.known, "a missing verdict must be unknown")
		assert.Empty(t, v.name, "a missing verdict must carry no name for the filter to trust")
	}
}

// The fallback evaluation must reach the same conclusions the arming pass does, or a
// verdict would mean something different depending on which pass produced it.
func TestEvaluateToolEntry_MatchesTheArmingPassConclusions(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		raw      string
		wantDrop bool
		wantName string
	}{
		{"clean entry", toolEntryJSON("read_file", "Read."), false, "read_file"},
		{"case-variant key", `{"name":"x","description":"a","Description":"b"}`, true, ""},
		{"duplicate key", `{"name":"x","name":"y"}`, true, ""},
		{"not an object", `"just a string"`, true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := evaluateToolEntry(json.RawMessage(tc.raw))
			assert.True(t, v.known, "the fallback always concludes")
			assert.Equal(t, tc.wantDrop, v.drop)
			assert.Equal(t, tc.wantName, v.name)
		})
	}
}
