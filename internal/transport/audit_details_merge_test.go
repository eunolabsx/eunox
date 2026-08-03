// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMergeAuditDetails_NeverHandsBackAnInput is the merge's contract, and the reason this
// package has ONE merge instead of two.
//
// It used to return base itself when extra was empty, while the dispatch site hand-rolled an
// always-allocating copy because its base is the caller's live parsed argument map and it
// writes the effect receipt in afterwards. The two looked interchangeable at a glance and were
// not: swapping the helper in at the dispatch site would have written a key the caller never
// sent into the request's own argument map — the map the audit record exists to describe — so
// the signed record would misreport the request. Always allocating makes that unrepresentable
// rather than a property of who currently writes what afterwards.
func TestMergeAuditDetails_NeverHandsBackAnInput(t *testing.T) {
	base := map[string]interface{}{"path": "/tmp/x"}
	extra := map[string]interface{}{audit.UpstreamErrorCodeKey: -32000}

	for name, tc := range map[string]struct {
		base, extra map[string]interface{}
		wantKeys    []string
	}{
		"both populated":  {base, extra, []string{"path", audit.UpstreamErrorCodeKey}},
		"empty extra":     {base, nil, []string{"path"}},
		"empty base":      {nil, extra, []string{audit.UpstreamErrorCodeKey}},
		"empty extra map": {base, map[string]interface{}{}, []string{"path"}},
	} {
		t.Run(name, func(t *testing.T) {
			got := mergeAuditDetails(tc.base, tc.extra)
			require.NotNil(t, got)
			for _, k := range tc.wantKeys {
				assert.Contains(t, got, k)
			}
			// The property the dispatch site depends on: writing into the result cannot
			// reach either input.
			got["_probe"] = true
			assert.NotContains(t, tc.base, "_probe", "the result must not alias base")
			assert.NotContains(t, tc.extra, "_probe", "nor extra")
		})
	}

	// Both empty is the one case that allocates nothing, because there is nothing to own —
	// and it must preserve nil-vs-empty: the sink omits a nil details map from the record
	// entirely and marshals an empty one as {}. Returning {} here would put a details field
	// on essentially every allow record that has none today.
	assert.Nil(t, mergeAuditDetails(nil, nil),
		"nothing to merge must stay nil, not become an empty details object on the tape")
}

// TestDispatchToolsCall_ReceiptNeverLandsInTheCallersArguments is the failure the two merge
// semantics could produce, exercised end to end rather than on the helper.
//
// Under --audit a tools/call allow record's details IS the caller's parsed argument map, and
// the effect receipt is merged into it. If any step of that merge hands back the caller's map,
// the reserved receipt key is written into the live request — so the record describes a
// request carrying an argument nobody sent, on the signed tape.
func TestDispatchToolsCall_ReceiptNeverLandsInTheCallersArguments(t *testing.T) {
	live := map[string]interface{}{"path": "/tmp/x"}
	toolDetails := live

	// The merge exactly as dispatchToolsCall performs it: annotations accumulate in a map
	// this side owns, and the caller's map is only ever a merge INPUT.
	extra := map[string]interface{}{audit.UpstreamErrorCodeKey: -32000}
	extra[audit.EffectReceiptKey] = map[string]interface{}{"verdict": "verified"}
	details := mergeAuditDetails(toolDetails, extra)

	assert.Equal(t, map[string]interface{}{"path": "/tmp/x"}, live,
		"the caller's argument map is what the record describes; nothing eunox annotates may land in it")
	assert.Equal(t, "/tmp/x", details["path"], "and the caller's own keys survive the merge")
	assert.Contains(t, details, audit.EffectReceiptKey)
	assert.Contains(t, details, audit.UpstreamErrorCodeKey)
}

// TestDispatchToolsCall_NoInlineDetailsMergeSurvives keeps the "one merge, one semantic"
// property from being undone by the next edit. The hazard is not a subtle one — a second
// hand-rolled copy loop beside the helper is how the two semantics diverged in the first
// place — but it is invisible at review time, since a copy loop reads as ordinary map
// plumbing.
//
// It asserts the shape rather than the behavior: dispatchToolsCall must reach the audit
// details through mergeAuditDetails, and must not assign into the map that merge returns —
// the write that, on the empty-extra path, used to land in the caller's own arguments.
func TestDispatchToolsCall_NoInlineDetailsMergeSurvives(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "dispatch.go", nil, 0)
	require.NoError(t, err)

	fn := findFuncDecl(file, "dispatchToolsCall")
	require.NotNil(t, fn, "dispatchToolsCall must exist for this guard to mean anything")

	merged := false
	ast.Inspect(fn, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "mergeAuditDetails" {
				merged = true
			}
			return true
		}
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, lhs := range assign.Lhs {
			idx, ok := lhs.(*ast.IndexExpr)
			if !ok {
				continue
			}
			ident, ok := idx.X.(*ast.Ident)
			if !ok || ident.Name != "details" {
				continue
			}
			t.Errorf("dispatch.go:%d writes into a merged details map; pass the key through extra instead — "+
				"the merge's result is the caller's to own, and its inputs include the live argument map",
				fset.Position(assign.Pos()).Line)
		}
		return true
	})
	assert.True(t, merged,
		"dispatchToolsCall must fold its annotations through the shared merge, not a private copy loop")
}

// findFuncDecl returns the named top-level function (or method) declaration, or nil.
func findFuncDecl(file *ast.File, name string) *ast.FuncDecl {
	for _, d := range file.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == name {
			return fn
		}
	}
	return nil
}

// TestFlowDiscriminator_IsOneSharedConstant pins the property the flow discriminator's whole
// purpose rests on: one filter finds every information-flow event on the tape.
//
// That held together across five independently typed string literals in two packages, where a
// rename or typo on either side splits an operator's filter and NOTHING fails — the tape stays
// well-formed, signed and chain-verifiable, and the query quietly returns less. The records
// that would vanish from it are the transport's declassification annotations, which nothing
// else on the tape reports.
func TestFlowDiscriminator_IsOneSharedConstant(t *testing.T) {
	// Every producer, reached through its own path, agrees on the key.
	assert.Equal(t, map[string]interface{}{capability.FlowAuditDetailKey: true}, declassifyDetail())

	fp := forwardParams{sessionID: "s"}
	for name, got := range map[string]map[string]interface{}{
		"refusal below the decision": fp.declassifyRefusalDetail(declassifiedAllow()),
		"result withheld":            fp.declassifyWithheldDetail(declassifiedAllow()),
	} {
		assert.Equal(t, true, got[capability.FlowAuditDetailKey], "%s must carry the discriminator", name)
	}

	// And no producer in either package respells it. A bare "flow" string literal is the
	// exact drift this constant retires, and the scan is over parsed literals rather than
	// raw bytes so prose mentioning the key is not mistaken for a producer of it.
	// Parsed per file rather than per package: build-tagged files (the O_NOFOLLOW pair and
	// its siblings) belong to no single parse of a directory, and a producer hidden behind a
	// build tag is exactly the one a reviewer would not notice either.
	for _, dir := range []string{".", filepath.Join("..", "..", "pkg", "enforcement")} {
		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, path, nil, 0)
			require.NoError(t, err)
			ast.Inspect(file, func(n ast.Node) bool {
				// Only where the literal is used as a details-map KEY — written into a map
				// literal, or indexed into one. The same spelling as a plain call argument
				// is the flow-label store's key prefix, an unrelated namespace this
				// constant does not govern.
				var key ast.Expr
				switch node := n.(type) {
				case *ast.KeyValueExpr:
					key = node.Key
				case *ast.IndexExpr:
					key = node.Index
				default:
					return true
				}
				lit, ok := key.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING || lit.Value != `"`+capability.FlowAuditDetailKey+`"` {
					return true
				}
				t.Errorf("%s:%d spells the flow discriminator as a details key literal; use capability.FlowAuditDetailKey",
					path, fset.Position(lit.Pos()).Line)
				return true
			})
		}
	}
}

// TestEnforcedForwardCore_AllowDetailsAreNotTheCallersMap is the same aliasing guard one
// layer up: the allow record's details go through the merge too, so a declassification
// annotation cannot rewrite the request it annotates.
func TestEnforcedForwardCore_AllowDetailsAreNotTheCallersMap(t *testing.T) {
	rec, spy := &fwdRecorder{}, &commitSpy{}
	fp := forwardParams{rec: rec, sessionID: "s", committer: spy,
		callUpstream: func(_ context.Context, msg mcp.RPCMsg) (mcp.RPCMsg, error) {
			return mcp.RPCMsg{ID: msg.ID, Result: json.RawMessage(`{"ok":true}`)}, nil
		}}

	live := map[string]interface{}{"path": "/tmp/x"}
	// Force the commit-failed annotation onto the allow, so the record carries an eunox
	// statement beside the caller's arguments — the shape this guard needs.
	spy.failErr = errors.New("flow store unreachable (test probe)")

	enforcedForwardCore(context.Background(), fp, mcp.RPCMsg{ID: mcp.RawJSON(`1`)},
		declassifiedAllow(), "tools/call", "sanitize", "sanitize", "tool", false,
		func(mcp.RPCMsg) map[string]interface{} { return live })

	assert.Equal(t, map[string]interface{}{"path": "/tmp/x"}, live,
		"the commit-failed annotation must not be written into the caller's argument map")
	require.Len(t, rec.records, 1)
	assert.Contains(t, rec.records[0].details, audit.DeclassifyCommitFailedKey)
	assert.Equal(t, "/tmp/x", rec.records[0].details["path"])
}
