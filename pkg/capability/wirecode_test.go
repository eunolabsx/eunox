// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The partition's edges, asserted one integer either side of every boundary.
//
// Boundaries are where an off-by-one lives, and an off-by-one here is not a rounding error: at
// -32020 it is the difference between eunox's own code and one the specification may assign
// tomorrow.
func TestClassifyWireCode_Bands(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		code int
		want WireCodeBand
	}{
		{"just outside the reserved range", -31999, WireCodeBandApplication},
		{"a positive application code", 42, WireCodeBandApplication},
		{"the implementation-defined ceiling", -32000, WireCodeBandImplementationDefined},
		{"inside implementation-defined", -32010, WireCodeBandImplementationDefined},
		{"the implementation-defined floor", -32019, WireCodeBandImplementationDefined},
		{"one past that floor is the spec's", -32020, WireCodeBandSpecReserved},
		{"the spec-assigned revision code", -32022, WireCodeBandSpecReserved},
		{"the spec-reserved floor", -32099, WireCodeBandSpecReserved},
		{"one past the spec's floor is nobody's", -32100, WireCodeBandUnassignedReserved},
		{"the bottom of JSON-RPC's reserved range", -32768, WireCodeBandUnassignedReserved},
		{"below JSON-RPC's reserved range", -32769, WireCodeBandApplication},
		// The pre-defined codes sit inside -32768..-32000 arithmetically, so they are recognized
		// FIRST or they would be read against the partition's bands.
		{"parse error", -32700, WireCodeBandPredefined},
		{"invalid request", -32600, WireCodeBandPredefined},
		{"method not found", -32601, WireCodeBandPredefined},
		{"invalid params", -32602, WireCodeBandPredefined},
		{"internal error", -32603, WireCodeBandPredefined},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, ClassifyWireCode(tc.code), "code %d", tc.code)
		})
	}
}

// Every band names itself: the classification reaches an operator through a test failure, and a
// band rendering as its integer says nothing.
func TestWireCodeBand_EveryBandHasAName(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for band := WireCodeBandApplication; band <= WireCodeBandUnassignedReserved; band++ {
		name := band.String()
		require.NotEqual(t, "unknown", name, "band %d renders as unknown", band)
		require.False(t, seen[name], "two bands render as %q, so a failure cannot say which", name)
		seen[name] = true
	}
	assert.Equal(t, "unknown", WireCodeBand(200).String(), "an unrecognized band must say so rather than borrow a name")
}

func TestMintableWireCode(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		code int
		want bool
	}{
		{"eunox's own denial code", JSONRPCCodeAuthorizationFailed, true},
		{"the implementation-defined floor", -32019, true},
		{"JSON-RPC's internal error", JSONRPCCodeEnforcementError, true},
		{"the spec-assigned revision code", JSONRPCCodeUnsupportedProtocolVersion, true},
		{"an unassigned code in the spec's band", -32021, false},
		{"the spec-reserved floor", -32099, false},
		{"JSON-RPC's unassigned reserved space", -32200, false},
		{"an application code", -1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ok, why := MintableWireCode(tc.code)
			assert.Equal(t, tc.want, ok, "code %d", tc.code)
			if tc.want {
				return
			}
			assert.NotEmpty(t, why, "a refusal must say why; the one reader is a contributor looking at a constant they just wrote")
		})
	}
}

// The spec-assigned exception carries its MEANING, not just membership: the map is eunox
// asserting the specification already defined this integer, and an entry with no meaning is that
// claim made without stating it.
func TestSpecAssignedWireCodes_EveryEntryNamesItsAssignedMeaning(t *testing.T) {
	t.Parallel()
	require.NotEmpty(t, SpecAssignedWireCodes)
	for code, meaning := range SpecAssignedWireCodes {
		assert.NotEmpty(t, meaning, "code %d is exempted from the reserved band without naming what the spec assigned it", code)
		assert.Equal(t, WireCodeBandSpecReserved, ClassifyWireCode(code),
			"code %d needs no exemption; it is not in the reserved band, and listing it here implies a spec assignment that is not what makes it legal", code)
	}
}

// The two revisions disagree about this integer, which is the whole reason a proxy has to ask.
func TestResourceNotFoundWireCode_PerRevision(t *testing.T) {
	t.Parallel()
	assert.Equal(t, JSONRPCCodeResourceNotFound20251125, ResourceNotFoundWireCode(Revision20251125))
	assert.Equal(t, JSONRPCCodeInvalidParams, ResourceNotFoundWireCode(Revision20260728))

	// The unnegotiated carrier resolves to the surface eunox already shipped, matching every
	// other reader of an empty revision. Asserted rather than left implicit: the alternative
	// reading — treating an unknown revision as the newer one — would hand an old host the newer
	// spelling on exactly the path where nothing was established.
	assert.Equal(t, JSONRPCCodeResourceNotFound20251125, ResourceNotFoundWireCode(DefaultRevision),
		"the default revision must spell it the way the revision eunox already shipped does")
	assert.Equal(t, JSONRPCCodeResourceNotFound20251125, ResourceNotFoundWireCode(""),
		"an empty revision must not resolve to the newer spelling")

	// Under 2026-07-28 the meaning shares JSON-RPC's invalid-params integer, which is what makes
	// the boundary's new-to-old direction a narrowing it must not perform. Pinned here so the
	// asymmetry rests on a stated fact rather than on the translation's own comment.
	assert.Equal(t, ResourceNotFoundWireCode(Revision20260728), JSONRPCCodeInvalidParams,
		"the newer spelling collides with invalid-params by design; a test asserting otherwise would license narrowing it")
}

// Both revisions' spellings must themselves be legal to emit — eunox forwards one of them onto
// the wire whenever it translates.
func TestResourceNotFoundWireCode_BothSpellingsAreMintable(t *testing.T) {
	t.Parallel()
	for _, rev := range PublishedRevisions() {
		code := ResourceNotFoundWireCode(rev)
		ok, why := MintableWireCode(code)
		assert.Truef(t, ok, "%s spells resource-not-found %d, which eunox may not emit: %s", rev, code, why)
	}
}
