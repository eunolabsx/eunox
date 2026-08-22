// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"go/ast"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/pkg/capability"
)

// Why IsInfraDenialCode takes no revision, asserted rather than asserted-in-prose.
//
// The execution plan's W9 scope asks for it to be made revision-aware, and the hazard behind that
// ask is real: under 2025-11-25 the INTEGER -32002 means both eunox's CAPABILITY_DENIED and the
// spec's resource-not-found, so anything classifying a denial by its integer has to know which
// revision produced it or it will mine an upstream's missing resource as a policy denial and
// propose a manifest grant for a capability nothing refused.
//
// It does not apply to this function, and the reason is structural rather than lucky: the audit
// tape records the SYMBOLIC code, and IsInfraDenialCode's one production caller (`eunox suggest`)
// reads that field. A symbolic code names one thing under both revisions — the collision exists
// only in the integer, which never reaches the tape or this function.
//
// So the answer here is a parameter NOT added, which is a claim that rots quietly: the day a code
// does become revision-dependent, an unread parameter would have been the place to notice, and
// there is none. These two tests are that place instead. If either fails, the scope item is live
// again and this comment is what says so.

// TestIsInfraDenialCode_TakesNoRevision is the guard that keeps the decision above from rotting.
//
// It reads the SIGNATURE rather than comparing answers across revisions, and that is the only
// honest shape available: the function takes no revision, so there is no second answer to compare
// the first against. A test that looped over PublishedRevisions calling the same one-argument
// function would compare a value to itself and pass forever — which is what this replaced.
//
// What the signature guard actually buys: the day someone makes the classification depend on a
// revision, the natural way to do it is to add the parameter. That fails here, with a message
// naming the decision and the collision behind it, instead of landing silently on a caller
// (`eunox suggest`) that has no revision in hand to pass.
func TestIsInfraDenialCode_TakesNoRevision(t *testing.T) {
	t.Parallel()
	var found *ast.FuncDecl
	var src packageSource
	for _, candidate := range packageSources(t) {
		for _, decl := range candidate.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Name.Name != "IsInfraDenialCode" {
				continue
			}
			found, src = fn, candidate
		}
	}
	require.NotNil(t, found, "IsInfraDenialCode was not found in this package; the guard is asserting nothing")

	params := found.Type.Params.List
	require.Lenf(t, params, 1,
		"%s: IsInfraDenialCode takes %d parameters. If a revision was just added: the revision-dependent collision is in the WIRE INTEGER (-32002 is both CAPABILITY_DENIED and 2025-11-25 resource-not-found), and this function reads the SYMBOLIC code off the audit tape, which names one thing under both revisions. Its one caller, eunox suggest, mines records and holds no revision to pass. Re-read the file comment before threading one through.",
		src.fset.Position(found.Pos()), len(params))
	ident, ok := params[0].Type.(*ast.Ident)
	require.True(t, ok && ident.Name == "string",
		"%s: IsInfraDenialCode's parameter is not the symbolic code; classifying anything else re-opens the integer collision",
		src.fset.Position(found.Pos()))
}

// Every code in the vocabulary gets a definite answer, so `suggest`'s skip decision is total.
//
// Not a revision question, but the one that shares this file's subject: a code the fold has no
// opinion on falls to policy and is MINED, which fabricates a manifest suggestion for a
// capability nothing refused.
func TestIsInfraDenialCode_ClassifiesEveryCodeInTheVocabulary(t *testing.T) {
	t.Parallel()
	require.NotEmpty(t, capability.AllDenialCodes, "the vocabulary is empty; the pin is asserting nothing")
	mined := 0
	for _, code := range capability.AllDenialCodes {
		if !IsInfraDenialCode(code) {
			mined++
			assert.Equalf(t, capability.DenialClassPolicy, capability.ClassifyDenialCode(code),
				"%s is mined by suggest but is not a policy verdict; a non-policy record names no target to suggest a grant for", code)
		}
	}
	assert.NotZero(t, mined, "every code is skipped as infrastructure, so suggest would mine nothing at all")
}

// TestIsInfraDenialCode_NoWireIntegerIsClassifiable is the other half: the collision that DOES
// depend on the revision lives in the integer, and the integer must not be what anything
// classifies.
//
// A caller reaching for the wire code instead — the shape the scope item was written against —
// gets no answer here rather than a wrong one, because an integer rendered as a string matches no
// symbolic code and falls through to policy. That fall-through is the fail-open direction for
// `suggest` (it would mine the record rather than skip it), which is why the safety rests on the
// tape recording symbols and not on this default.
func TestIsInfraDenialCode_NoWireIntegerIsClassifiable(t *testing.T) {
	t.Parallel()
	// The one integer whose meaning genuinely moved between the revisions. Under 2025-11-25 it is
	// both eunox's CAPABILITY_DENIED and the spec's resource-not-found; under 2026-07-28 the
	// second meaning moved to -32602 and left the first alone.
	assert.Equal(t, capability.JSONRPCCodeCapabilityDenied, capability.JSONRPCCodeResourceNotFound20251125,
		"these are the same integer under 2025-11-25; if they diverge, the collision this test is about is gone and so is the reason for it")
	assert.NotEqual(t, capability.ResourceNotFoundWireCode(capability.Revision20251125),
		capability.ResourceNotFoundWireCode(capability.Revision20260728),
		"the two revisions must still disagree; if they agree, nothing here is revision-dependent at all")

	assert.False(t, IsInfraDenialCode("-32002"),
		"an integer is not a symbolic code and must not be classified as one")
}
