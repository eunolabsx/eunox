// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestClaimDecode_RefusesNullMembers is the fail-closed property that struct decoding does not
// give you: a JSON null on a claim-borne grant decodes to the field's WIDEST value, silently.
// Every one of these tokens reads as a narrowing and, decoded naively, is not one.
func TestClaimDecode_RefusesNullMembers(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		raw   string
		parse func(json.RawMessage) error
	}{
		// false Once is a STANDING approval, replayable for the token's whole life — exactly
		// the window the flag exists to close.
		"declassify once": {
			`[{"labels":["pii"],"target":"tool:publish","approver":"ops@example.com","once":null}]`,
			func(r json.RawMessage) error { _, err := capability.ParseDeclassifyApprovals(r); return err },
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := tc.parse(json.RawMessage(tc.raw))
			require.Error(t, err, "a null member must reject the token, not decode to the widest value")
			assert.Contains(t, err.Error(), "is null")
		})
	}
}

// TestClaimDecode_RefusesDuplicateKeys covers the ambiguity the struct decoder resolves by
// member ORDER: encoding/json matches field names by folding, so two spellings of one key are
// one field and the LAST wins. Which of the two an author sees depends on nothing visible, so
// the pair is refused rather than silently resolved — the same rule the JSON-RPC envelope and
// tools/list scans apply, through the same FoldJSONKey.
func TestClaimDecode_RefusesDuplicateKeys(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		raw   string
		parse func(json.RawMessage) error
	}{
		// U+017F folds to 's' for encoding/json's matcher but not for strings.ToLower, which is
		// why the scan folds rather than lower-cases.
		"declassify non-ascii fold": {
			"[{\"labels\":[\"pii\"],\"target\":\"tool:publish\",\"approver\":\"ops@example.com\",\"targeT\":\"x\"}]",
			func(r json.RawMessage) error { _, err := capability.ParseDeclassifyApprovals(r); return err },
		},
		"declassify case variant": {
			`[{"labels":["pii"],"target":"tool:publish","approver":"ops@example.com","once":true,"id":"a1","Once":false}]`,
			func(r json.RawMessage) error { _, err := capability.ParseDeclassifyApprovals(r); return err },
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := tc.parse(json.RawMessage(tc.raw))
			require.Error(t, err, "an ambiguous key pair must reject the token")
			assert.Contains(t, err.Error(), "same key")
		})
	}
}

// TestClaimDecode_BoundsListLength pins the cap on a list-valued member: a claim is
// attacker-influenced input the decision path reads, and an unbounded list in it is an
// unbounded allocation per token.
func TestClaimDecode_BoundsListLength(t *testing.T) {
	t.Parallel()
	labels := make([]string, capability.MaxClaimListEntries+1)
	for i := range labels {
		labels[i] = `"pii"`
	}
	raw := fmt.Sprintf(`[{"labels":[%s],"target":"tool:publish","approver":"ops@example.com"}]`, strings.Join(labels, ","))
	_, err := capability.ParseDeclassifyApprovals(json.RawMessage(raw))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "more than the maximum")

	// One under the cap is fine, so the bound is a bound and not an off-by-one refusal.
	raw = fmt.Sprintf(`[{"labels":[%s],"target":"tool:publish","approver":"ops@example.com"}]`, strings.Join(labels[:capability.MaxClaimListEntries], ","))
	_, err = capability.ParseDeclassifyApprovals(json.RawMessage(raw))
	require.NoError(t, err)
}
