// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability_test

import (
	"encoding/json"
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestClaimMembers_RefusesWatchedDuplicates is the ONE-LAYER-OUT counterpart of
// TestClaimDecode_RefusesDuplicateKeys: the ambiguity that matters is not only inside an
// already-selected grant object, but in WHICH claim object gets selected in the first place.
// `{"mcp":{"delegation":[narrow],"Delegation":[wide]}}` never reaches ParseDelegationGrants
// with any sign that two candidates existed — encoding/json's struct decode already picked
// the last one before any grant-level decoder runs.
func TestClaimMembers_RefusesWatchedDuplicates(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		raw   string
		watch []string
	}{
		"top-level act exact duplicate": {
			`{"mcp":{"v":"0.2"},"act":{"sub":"a"},"act":{"sub":"b"}}`,
			[]string{"mcp", "act"},
		},
		"top-level act case variant": {
			`{"mcp":{"v":"0.2"},"act":{"sub":"a"},"Act":{"sub":"b"}}`,
			[]string{"mcp", "act"},
		},
		"mcp-level delegation case variant": {
			`{"v":"0.2","delegation":[{"subject":"a","targets":["tool:read"]}],"Delegation":[{"subject":"a"}]}`,
			[]string{"v", "capabilities", "task_id", "agent_id", "declassify", "delegation"},
		},
		"mcp-level capabilities case variant": {
			`{"v":"0.2","capabilities":["tool:read"],"Capabilities":["tool:read","tool:wipe_db"]}`,
			[]string{"v", "capabilities", "task_id", "agent_id", "declassify", "delegation"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := capability.ClaimMembers(json.RawMessage(tc.raw), "test claim", tc.watch...)
			require.Error(t, err, "an ambiguous watched member must reject the token")
			assert.Contains(t, err.Error(), "same claim")
		})
	}
}

// TestClaimMembers_IgnoresUnwatchedMembers is the property that keeps this usable on a whole
// JWT payload: a token legitimately carries claims for OTHER audiences the proxy never reads
// (email, roles, groups, ...), and an ambiguity among those is not this build's business to
// refuse a token over — unlike decodeClaimObject, which owns its whole object and rejects
// anything it does not recognize.
func TestClaimMembers_IgnoresUnwatchedMembers(t *testing.T) {
	t.Parallel()
	raw := json.RawMessage(`{"sub":"user@example.com","mcp":{"v":"0.2"},"roles":["a"],"Roles":["b"],"email":"user@example.com"}`)
	got, err := capability.ClaimMembers(raw, "test claim", "mcp", "act")
	require.NoError(t, err, "an ambiguity in a claim outside the watch list must not reject the token")
	assert.Equal(t, json.RawMessage(`{"v":"0.2"}`), got[capability.FoldJSONKey("mcp")])
	_, hasAct := got[capability.FoldJSONKey("act")]
	assert.False(t, hasAct, "an absent watched name must not appear in the result")
}
