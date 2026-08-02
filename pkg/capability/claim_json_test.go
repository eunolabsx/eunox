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
		// nil Targets means "this hop places no target restriction" — the widest value the
		// field has, reached by a member the author explicitly wrote.
		"delegation targets": {
			`[{"subject":"a","targets":null}]`,
			func(r json.RawMessage) error { _, err := capability.ParseDelegationGrants(r); return err },
		},
		// nil AllowLabels means the manifest's own sink allow-set stands unmodified.
		"delegation allowLabels": {
			`[{"subject":"a","allowLabels":null}]`,
			func(r json.RawMessage) error { _, err := capability.ParseDelegationGrants(r); return err },
		},
		// false Once is a STANDING approval, replayable for the token's whole life — exactly
		// the window the flag exists to close.
		"declassify once": {
			`[{"labels":["pii"],"target":"tool:publish","approver":"ops@example.com","once":null}]`,
			func(r json.RawMessage) error { _, err := capability.ParseDeclassifyApprovals(r); return err },
		},
		"actor sub": {
			`{"sub":null}`,
			func(r json.RawMessage) error { _, err := capability.ParseActorChain(r); return err },
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
		"delegation exact duplicate": {
			`[{"subject":"a","targets":["tool:read"],"targets":[]}]`,
			func(r json.RawMessage) error { _, err := capability.ParseDelegationGrants(r); return err },
		},
		"delegation case variant": {
			`[{"subject":"a","targets":["tool:read"],"Targets":["tool:read","tool:wipe_db"]}]`,
			func(r json.RawMessage) error { _, err := capability.ParseDelegationGrants(r); return err },
		},
		// U+017F folds to 's' for encoding/json's matcher but not for strings.ToLower, which is
		// why the scan folds rather than lower-cases.
		"delegation non-ascii fold": {
			"[{\"subject\":\"a\",\"targets\":[\"tool:read\"],\"targetſ\":[\"tool:wipe_db\"]}]",
			func(r json.RawMessage) error { _, err := capability.ParseDelegationGrants(r); return err },
		},
		"declassify case variant": {
			`[{"labels":["pii"],"target":"tool:publish","approver":"ops@example.com","once":true,"id":"a1","Once":false}]`,
			func(r json.RawMessage) error { _, err := capability.ParseDeclassifyApprovals(r); return err },
		},
		"actor case variant": {
			`{"sub":"inner","Sub":"outer"}`,
			func(r json.RawMessage) error { _, err := capability.ParseActorChain(r); return err },
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

// TestParseActorChain_AdmitsIdentityMembers is the outage case: RFC 8693 §4.1 defines an actor
// object as a set of claims identifying the actor, and a token-exchange IdP routinely writes
// the actor's issuer beside its subject. Refusing that denied EVERY request the caller made.
func TestParseActorChain_AdmitsIdentityMembers(t *testing.T) {
	t.Parallel()
	actors, err := capability.ParseActorChain(json.RawMessage(
		`{"sub":"agent-b","iss":"https://idp.example.com","client_id":"cli-1","act":{"sub":"agent-a","iss":"https://idp.example.com"}}`))
	require.NoError(t, err)
	assert.Equal(t, []string{"agent-a", "agent-b"}, actors)

	// A member this build does not recognize stays refused: it may be the one carrying the
	// attenuation, and ignoring it would apply less narrowing than the token declares.
	_, err = capability.ParseActorChain(json.RawMessage(`{"sub":"agent-b","scope":"admin"}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown field")

	// The misspelled-"act" truncation the strict decode exists to catch is still caught.
	_, err = capability.ParseActorChain(json.RawMessage(`{"sub":"agent-b","acts":{"sub":"agent-a"}}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown field")
}

// TestClaimDecode_BoundsListLength pins the cap on a list-valued member. The chain is validated
// once but WALKED on every enforced call, and the target index is a map built per hop.
func TestClaimDecode_BoundsListLength(t *testing.T) {
	t.Parallel()
	targets := make([]string, capability.MaxClaimListEntries+1)
	for i := range targets {
		targets[i] = fmt.Sprintf("%q", fmt.Sprintf("tool:t%d", i))
	}
	raw := fmt.Sprintf(`[{"subject":"a","targets":[%s]}]`, strings.Join(targets, ","))
	_, err := capability.ParseDelegationGrants(json.RawMessage(raw))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "more than the maximum")

	// One under the cap is fine, so the bound is a bound and not an off-by-one refusal.
	raw = fmt.Sprintf(`[{"subject":"a","targets":[%s]}]`, strings.Join(targets[:capability.MaxClaimListEntries], ","))
	_, err = capability.ParseDelegationGrants(json.RawMessage(raw))
	require.NoError(t, err)
}
