// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

// Deterministic list ordering is a spec SHOULD, and a proxy that filters a catalog is exactly
// the component most likely to break it: it decodes an array, drops entries, and re-encodes.
// A host that pages, diffs, or caches by position sees a reordered catalog as a changed one.
//
// Distinct from TestFilteredList_ClampPreservesKeyOrder, which pins the order of the envelope's
// KEYS around the list. This pins the order of the ENTRIES inside it — the two are separate
// properties of the same encoder, and only one of them was covered.
//
// Written against the public filter entry points for the reason the cache-scope table gives:
// what has to hold is the property at the seam a transport calls, and a future filter path that
// re-emitted an envelope some other way would pass a test written one level down.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// orderedCatalog builds a catalog whose permitted entries are INTERLEAVED with entries the PDP
// under test refuses, so a filter that reordered would have to be caught by the relative order
// of what survives rather than by the array merely being short.
//
// nameKey differs per list flavor (tools and prompts key on `name`, resources on `uri`), so the
// permitted entry is supplied by the caller and the filler entries are shaped to match.
func orderedCatalog(field, permitted string, copies int) (body json.RawMessage, wantOrder []string) {
	entries := make([]string, 0, copies*2)
	for i := range copies {
		// A permitted entry, then one nothing permits. Both carry a positional marker so the
		// assertion reads the surviving order rather than merely the surviving set.
		entries = append(entries,
			withMarker(permitted, i),
			fmt.Sprintf(`{"name":"never_permitted_%d","uri":"file:///never/%d","_pos":%d}`, i, i, i))
		wantOrder = append(wantOrder, fmt.Sprintf("%d", i))
	}
	return json.RawMessage(`{"` + field + `":[` + strings.Join(entries, ",") + `]}`), wantOrder
}

// withMarker adds a positional marker to a catalog entry without disturbing the members the
// filter matches on.
func withMarker(entry string, pos int) string {
	return strings.TrimSuffix(entry, "}") + fmt.Sprintf(`,"_pos":%d}`, pos)
}

// survivingOrder reads the `_pos` markers of the entries that survived, in the order they
// appear in the filtered envelope.
func survivingOrder(t *testing.T, field string, out json.RawMessage) []string {
	t.Helper()
	var env map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(out, &env))
	var entries []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(env[field], &entries))
	order := make([]string, 0, len(entries))
	for _, e := range entries {
		order = append(order, string(e["_pos"]))
	}
	return order
}

// TestFilteredList_PreservesUpstreamEntryOrder is W5's ordering criterion: every filter path
// emits the entries it keeps in the order the upstream sent them.
func TestFilteredList_PreservesUpstreamEntryOrder(t *testing.T) {
	t.Parallel()
	for _, tc := range enforcingFilterCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			const copies = 6
			in, wantOrder := orderedCatalog(tc.field, tc.entry, copies)
			out := tc.fn(filterCtx(), in).Result

			got := survivingOrder(t, tc.field, out)
			if len(got) == 0 {
				// The deny-all rows filter to empty, which says nothing about ordering. Their
				// value here is that they must not CRASH or reorder a zero-length array; the
				// ordering property itself is carried by the rows that keep entries.
				assert.Contains(t, tc.name, "denyall",
					"a filter that keeps nothing cannot demonstrate ordering; only the deny-all rows may be empty")
				return
			}
			assert.Equal(t, wantOrder, got,
				"filtering reordered the surviving entries; deterministic ordering is a spec SHOULD a proxy must not break")
		})
	}
}

// The intersection splice is the one filter path that does not go through filterListResult's
// own encode — it writes claim-filtered entries back into the inner PDP's already-ordered
// envelope. It reaches the same encoder, which is why ordering holds there too; asserted
// rather than assumed, since that path is where a second encoder would most plausibly appear.
func TestJWTIntersection_PreservesUpstreamEntryOrder(t *testing.T) {
	t.Parallel()
	inner := newTestManifestPDP(
		capability.Constraint{Target: "tool:tool_0", Actions: []string{"*"}},
		capability.Constraint{Target: "tool:tool_1", Actions: []string{"*"}},
		capability.Constraint{Target: "tool:tool_2", Actions: []string{"*"}},
		capability.Constraint{Target: "tool:tool_3", Actions: []string{"*"}},
	)
	p := NewJWTPDP(JWTPDPOptions{Inner: inner, KillSwitch: killswitch.NewInMemory()})
	ctx := WithJWTClaims(context.Background(), &JWTClaims{
		AgentID:         "agent-1",
		Capabilities:    []string{"tool:tool_0", "tool:tool_2", "tool:tool_3"},
		HasCapabilities: true,
	})

	// Deliberately NOT in claim order: the claim lists 0, 2, 3 while the upstream sends
	// 3, 0, 1, 2. A filter that emitted in claim order rather than upstream order would pass a
	// set-equality assertion and fail this one.
	in := json.RawMessage(`{"tools":[` +
		`{"name":"tool_3","_pos":0},{"name":"tool_0","_pos":1},` +
		`{"name":"tool_1","_pos":2},{"name":"tool_2","_pos":3}]}`)

	got := survivingOrder(t, listKeyTools, p.FilterToolsList(ctx, in).Result)
	assert.Equal(t, []string{"0", "1", "3"}, got,
		"the intersection emitted entries in claim order rather than the upstream's")
}
