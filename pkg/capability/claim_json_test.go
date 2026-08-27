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
			_, err := capability.ClaimMembers(json.RawMessage(tc.raw), "test claim", capability.NewClaimWatch(tc.watch...))
			require.Error(t, err, "an ambiguous watched member must reject the token")
			assert.ErrorIs(t, err, capability.ErrClaimNameCollision)
		})
	}
}

// TestClaimMembers_RefusesLoneNonCanonicalSpelling is the collision gate's mirror image, and
// the shape it admitted by design: one spelling that collides with nothing. Nothing resolves
// it because nothing BINDS it — this scan folds, every consumer of its result matches
// byte-exactly — so the claim reads as absent and the check that reads it is skipped on a
// token that plainly carries it.
func TestClaimMembers_RefusesLoneNonCanonicalSpelling(t *testing.T) {
	t.Parallel()
	for name, raw := range map[string]string{
		"first-rune variant": `{"Capabilities":["tool:read"]}`,
		"all-caps variant":   `{"CAPABILITIES":["tool:read"]}`,
		"interior variant":   `{"capabilitieS":["tool:read"]}`,
		"non-ascii fold":     `{"capabilitieſ":["tool:read"]}`, // U+017F folds to "s"
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := capability.ClaimMembers(json.RawMessage(raw), "test claim", capability.NewClaimWatch("v", "capabilities"))
			require.Error(t, err, "a watched claim spelled a way no decoder binds must reject the token")
			assert.ErrorIs(t, err, capability.ErrClaimNameVariant,
				"the refusal must be distinguishable from the collision refusal: the two are different minting mistakes")
		})
	}
}

// TestClaimMembers_ReportsTheCollisionWhenBothShapesArePresent pins which of the two refusals
// a payload carrying both gets, under EITHER member order. "declare it once" is the actionable
// diagnosis for two candidates, and reporting from the map that records them would name a
// different offender per run.
func TestClaimMembers_ReportsTheCollisionWhenBothShapesArePresent(t *testing.T) {
	t.Parallel()
	for name, raw := range map[string]string{
		"canonical first": `{"capabilities":["tool:read"],"Capabilities":["tool:wipe_db"]}`,
		"variant first":   `{"Capabilities":["tool:wipe_db"],"capabilities":["tool:read"]}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := capability.ClaimMembers(json.RawMessage(raw), "test claim", capability.NewClaimWatch("capabilities"))
			require.Error(t, err)
			assert.ErrorIs(t, err, capability.ErrClaimNameCollision)
			assert.NotErrorIs(t, err, capability.ErrClaimNameVariant)
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
	// `Roles`/`roles` is the collision shape and `Sub` the lone-variant one, both in claims
	// the watch list does not name: neither is this build's business to refuse a token over.
	raw := json.RawMessage(`{"Sub":"user@example.com","mcp":{"v":"0.2"},"roles":["a"],"Roles":["b"],"email":"user@example.com"}`)
	got, err := capability.ClaimMembers(raw, "test claim", capability.NewClaimWatch("mcp", "act"))
	require.NoError(t, err, "an ambiguity in a claim outside the watch list must not reject the token")
	assert.Equal(t, json.RawMessage(`{"v":"0.2"}`), got["mcp"], "the result is keyed by the watched name as watch spells it")
	_, hasAct := got["act"]
	assert.False(t, hasAct, "an absent watched name must not appear in the result")
}

// TestClaimMembers_WatchListReservesItsFoldNamespace is the boundary the two properties above
// meet at, and the one the refusal MOVED: a foreign claim that folds to a watched name is now
// refused even with the canonical spelling absent, where before it was admitted as a lone
// variant colliding with nothing. The scan cannot tell such a member from the watched claim
// mis-minted, and guessing the benign reading is what fails open — so the watch list reserves
// a fold-equivalence namespace, not just a set of literal names. Pinned here because it is the
// one class of token this rule newly refuses.
func TestClaimMembers_WatchListReservesItsFoldNamespace(t *testing.T) {
	t.Parallel()
	_, err := capability.ClaimMembers(json.RawMessage(`{"CNF":"another system's value"}`), "test claim", capability.NewClaimWatch("cnf"))
	require.Error(t, err, "a foreign claim folding onto a watched name is indistinguishable from that claim mis-minted")
	assert.ErrorIs(t, err, capability.ErrClaimNameVariant)

	// One rune outside the namespace, and it is honest data again.
	got, err := capability.ClaimMembers(json.RawMessage(`{"CNFX":"another system's value"}`), "test claim", capability.NewClaimWatch("cnf"))
	require.NoError(t, err, "a name that folds to nothing watched stays none of this build's business")
	assert.Empty(t, got)
}

// TestClaimMembers_NamesEveryVariantInOnePass: the producer the refusal exists for is a
// mapping rule that title-cases claim names, which hits every watched claim at once. Reporting
// only the first would cost the operator one re-mint and redeploy per claim to discover the
// next.
func TestClaimMembers_NamesEveryVariantInOnePass(t *testing.T) {
	t.Parallel()
	raw := json.RawMessage(`{"Sub":"a","Jti":"j","Cnf":{"jkt":"k"},"roles":["x"]}`)
	_, err := capability.ClaimMembers(raw, "jwt payload", capability.NewClaimWatch("sub", "jti", "cnf"))
	require.Error(t, err)
	for _, want := range []string{`"Sub"`, `"Jti"`, `"Cnf"`, `spell it "sub"`, `spell it "jti"`, `spell it "cnf"`} {
		assert.Contains(t, err.Error(), want)
	}
}

// TestClaimMembers_CollisionOfTwoVariantsNamesTheCanonicalSpelling: "declare it once" is the
// whole fix only when one of the two members is canonical. When neither is, dropping one as
// instructed leaves a claim nothing binds and the operator is refused a second time under a
// different code, so every collision names the spelling to declare it under.
func TestClaimMembers_CollisionOfTwoVariantsNamesTheCanonicalSpelling(t *testing.T) {
	t.Parallel()
	_, err := capability.ClaimMembers(json.RawMessage(`{"Cnf":{"jkt":"a"},"CNF":null}`), "jwt payload", capability.NewClaimWatch("cnf"))
	require.Error(t, err)
	assert.ErrorIs(t, err, capability.ErrClaimNameCollision)
	assert.Contains(t, err.Error(), `spell it "cnf"`, "neither member is canonical, so declaring it once is not the whole fix")
}

// TestClaimMembers_RefusesAnIncompleteObject is the fail-closed half of the scan's own input
// handling: json.Decoder.More() reports "is there another member", and a read error is not
// another member, so a truncated object left the loop exactly as a closed one did and the scan
// certified a PARTIAL member list as a whole claim object — everything past the cut unwatched
// by construction, which is the reads-as-absent failure this file exists to refuse.
//
// Not reachable through the JWT path (the payload is decoded whole before the scan sees it),
// which is exactly why it needs a test: nothing in the exported contract obliged a caller to
// pre-validate, so the guarantee held by luck of call order.
func TestClaimMembers_RefusesAnIncompleteObject(t *testing.T) {
	t.Parallel()
	for name, raw := range map[string]string{
		"truncated at a member boundary": `{"mcp":{"v":"0.2"},"sub":"a"`,
		"truncated mid-name":             `{"sub":"a","cn`,
		"second value after the object":  `{"sub":"a"} {"sub":"b"}`,
		"junk after the object":          `{"sub":"a"} X`,
		"trailing brace":                 `{"sub":"a"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := capability.ClaimMembers(json.RawMessage(raw), "test claim", capability.NewClaimWatch("mcp", "sub"))
			require.Error(t, err, "a scan that cannot see the whole object must not report a pass over part of it")
			assert.NotErrorIs(t, err, capability.ErrClaimNameVariant)
			assert.NotErrorIs(t, err, capability.ErrClaimNameCollision)
		})
	}
}

// TestNewClaimWatch_PanicsOnAnAmbiguousList: the watch list is the caller's own constant, so
// two entries that fold together are a programming error no token can reach — and one that
// silently INVERTS the gate, since the surviving entry becomes the spelling every other is
// refused against. It fires at CONSTRUCTION, not per token: on the request path the same
// panic is a dropped connection per request with no status code, which is strictly harder to
// diagnose than the fleet-wide 401 it guards against.
//
// The mis-CASED single entry is the other half of that hazard and cannot be checked here:
// which spelling a foreign decoder binds is not knowable from this package. Its guard is the
// caller's canonical-control test.
func TestNewClaimWatch_PanicsOnAnAmbiguousList(t *testing.T) {
	t.Parallel()
	assert.PanicsWithValue(t,
		`capability.NewClaimWatch: "mcp" and "MCP" are the same claim to a JSON decoder, so which one is canonical depends on their order`,
		func() { capability.NewClaimWatch("mcp", "MCP") })
	// An unbuilt or empty set would scan for nothing and report every claim object clean.
	assert.Panics(t, func() { capability.NewClaimWatch() })
	assert.Panics(t, func() {
		_, _ = capability.ClaimMembers(json.RawMessage(`{}`), "test claim", capability.ClaimWatch{})
	})
}

// TestClaimMembers_NamesEveryProblemInOnePass is the other half of the one-pass rule: a
// collision and a variant in the SAME payload must both be named. The collision arm used to
// return from inside the loop and throw away every variant already found, so an operator with
// both fixed the collision, re-minted, and was refused again for a variant they were never
// told about — the per-claim re-mint the deferred report exists to avoid.
func TestClaimMembers_NamesEveryProblemInOnePass(t *testing.T) {
	t.Parallel()
	raw := json.RawMessage(`{"JTI":"cred","cnf":{"jkt":"a"},"CNF":null,"sub":"s"}`)
	_, err := capability.ClaimMembers(raw, "jwt payload", capability.NewClaimWatch("jti", "cnf", "sub"))
	require.Error(t, err)
	assert.ErrorIs(t, err, capability.ErrClaimNameCollision, "a collision is the more severe ambiguity, so it decides the one verdict")
	for _, want := range []string{`"cnf" and "CNF"`, `"JTI" (spell it "jti")`} {
		assert.Contains(t, err.Error(), want)
	}
}
