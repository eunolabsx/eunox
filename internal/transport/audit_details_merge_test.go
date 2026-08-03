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
	// Fixtures are built per subtest rather than shared: the assertions below WRITE into the
	// merge result, so a regression that hands an input back would otherwise poison the
	// fixture and fail sibling cases too — in an order Go randomizes, pointing a maintainer
	// at three cases when one is at fault.
	base := func() map[string]interface{} { return map[string]interface{}{"path": "/tmp/x"} }
	extra := func() map[string]interface{} {
		return map[string]interface{}{audit.UpstreamErrorCodeKey: -32000}
	}
	empty := func() map[string]interface{} { return map[string]interface{}{} }

	for name, tc := range map[string]struct {
		base, extra func() map[string]interface{}
		wantKeys    []string
	}{
		"both populated":  {base, extra, []string{"path", audit.UpstreamErrorCodeKey}},
		"empty extra":     {base, nil, []string{"path"}},
		"empty base":      {nil, extra, []string{audit.UpstreamErrorCodeKey}},
		"empty extra map": {base, empty, []string{"path"}},
		// The case that used to slip through: len() is 0 for an empty NON-NIL map too, so
		// the both-empty shortcut handed the caller's own map straight back. "An empty map
		// has nothing to corrupt" is a claim about reads; the write below is what breaks it.
		"empty non-nil base": {empty, nil, nil},
	} {
		t.Run(name, func(t *testing.T) {
			var inBase, inExtra map[string]interface{}
			if tc.base != nil {
				inBase = tc.base()
			}
			if tc.extra != nil {
				inExtra = tc.extra()
			}
			got := mergeAuditDetails(inBase, inExtra)
			require.NotNil(t, got)
			for _, k := range tc.wantKeys {
				assert.Contains(t, got, k)
			}
			// The property the dispatch site depends on: writing into the result cannot
			// reach either input.
			got["_probe"] = true
			assert.NotContains(t, inBase, "_probe", "the result must not alias base")
			assert.NotContains(t, inExtra, "_probe", "nor extra")
		})
	}

	// A nil base with nothing to add is the one case that allocates nothing, because there is
	// nothing to own AND nothing to hand back. It must stay nil: the sink omits a nil details
	// map from the record entirely and marshals an empty one as {}, so returning {} here would
	// put a details field on essentially every allow record that has none today.
	assert.Nil(t, mergeAuditDetails(nil, nil),
		"nothing to merge must stay nil, not become an empty details object on the tape")
}

// TestDispatchToolsCall_AnnotationsNeverLandInTheCallersArguments is the failure the two merge
// semantics could produce, driven through the real dispatcher rather than re-stated on the
// helper — a test that hand-copies the production merge and asserts on its own copy is a
// fourth implementation of the thing this change exists to have one of, and would keep passing
// after any regression in dispatch.go.
//
// Under --audit a tools/call allow record's details IS the caller's parsed argument map, and
// eunox merges its own annotations into it. If any step of that merge hands the caller's map
// back, the annotation is written into the live request — so the signed record describes a
// request carrying something nobody sent.
func TestDispatchToolsCall_AnnotationsNeverLandInTheCallersArguments(t *testing.T) {
	rec := &fwdRecorder{}
	dp := newTestManifestPDP(capability.Constraint{Target: "tool:refund", Actions: []string{"call"}})
	d := dispatchParams{
		forwardParams: forwardParams{
			rec: rec, sessionID: "s",
			// --audit, which is what makes the record's details the caller's own map.
			audit: true,
			callUpstream: func(_ context.Context, msg mcp.RPCMsg) (mcp.RPCMsg, error) {
				// An upstream ERROR, so the closure has an annotation to merge in
				// (audit.UpstreamErrorCodeKey) on a path where extra would otherwise be nil.
				return mcp.RPCMsg{JSONRPC: "2.0", ID: msg.ID,
					Error: &mcp.RPCError{Code: -32000, Message: "upstream said no"}}, nil
			},
		},
		pdp: dp,
	}
	// The exact bytes the host sent, kept so the parsed map can be compared against them.
	const rawArgs = `{"path":"/tmp/x"}`
	msg := mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsCall,
		Params: json.RawMessage(`{"name":"refund","arguments":` + rawArgs + `}`),
	}
	dispatchRequest(context.Background(), d, msg)

	require.Len(t, rec.records, 1)
	got := rec.records[0].details
	assert.Equal(t, "/tmp/x", got["path"], "the caller's own arguments survive the merge")
	assert.Equal(t, -32000, got[audit.UpstreamErrorCodeKey], "and eunox's annotation reaches the record")

	// The point: the request's parsed argument map is still exactly what the host sent. Read
	// back through the same decode the dispatcher used, so this compares the map eunox may
	// have mutated rather than a copy the test made.
	var params struct {
		Arguments map[string]interface{} `json:"arguments"`
	}
	require.NoError(t, json.Unmarshal(msg.Params, &params))
	assert.Equal(t, map[string]interface{}{"path": "/tmp/x"}, params.Arguments,
		"the record's details are the caller's argument map; nothing eunox annotates may land in the request")
	assert.NotContains(t, got, audit.EffectReceiptKey, "no receipts configured here")
}

// successfulReply is the upstream reply shape declassifyCommitted accepts: no error member,
// a result object, no isError flag. The withheld-result fact is gated on it, so a test
// asserting that fact has to present one.
func successfulReply() mcp.RPCMsg {
	return mcp.RPCMsg{ID: mcp.RawJSON(`1`), Result: json.RawMessage(`{"ok":true}`)}
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

	// Names bound to a mergeAuditDetails result. Derived rather than hardcoded: keying the
	// guard on the identifier `details` made it vacuous the moment that local was renamed,
	// and a reintroduced `d := mergeAuditDetails(...); d[k] = v` would have passed it.
	merged := map[string]bool{}
	ast.Inspect(fn, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, rhs := range assign.Rhs {
			call, ok := rhs.(*ast.CallExpr)
			if !ok {
				continue
			}
			if ident, ok := call.Fun.(*ast.Ident); !ok || ident.Name != "mergeAuditDetails" {
				continue
			}
			if i < len(assign.Lhs) {
				if ident, ok := assign.Lhs[i].(*ast.Ident); ok {
					merged[ident.Name] = true
				}
			}
		}
		return true
	})
	ast.Inspect(fn, func(n ast.Node) bool {
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
			if !ok || !merged[ident.Name] {
				continue
			}
			t.Errorf("dispatch.go:%d writes into %q, which holds a mergeAuditDetails result; pass the key "+
				"through extra instead — the merge's result is the caller's to own, and its inputs include "+
				"the live argument map", fset.Position(assign.Pos()).Line, ident.Name)
		}
		return true
	})

	// The merge must actually be reached, or the guard above proves nothing. Asserted on the
	// RETURN so a stray call elsewhere in the function cannot satisfy it.
	returnsMerge := false
	ast.Inspect(fn, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		for _, res := range ret.Results {
			if call, ok := res.(*ast.CallExpr); ok {
				if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "mergeAuditDetails" {
					returnsMerge = true
				}
			}
		}
		return true
	})
	assert.True(t, returnsMerge || len(merged) > 0,
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

	for name, got := range map[string]map[string]interface{}{
		"refusal below the decision": declassifyRefusalDetail(declassifiedAllow()),
		"result withheld":            declassifyRedactionDetail(declassifiedAllow(), successfulReply()),
	} {
		assert.Equal(t, true, got[capability.FlowAuditDetailKey], "%s must carry the discriminator", name)
	}

	// And no producer in either package respells it. A bare "flow" string literal is the
	// exact drift this constant retires, and the scan is over parsed literals rather than
	// raw bytes so prose mentioning the key is not mistaken for a producer of it.
	// Parsed per file rather than per package: build-tagged files (the O_NOFOLLOW pair and
	// its siblings) belong to no single parse of a directory, and a producer hidden behind a
	// build tag is exactly the one a reviewer would not notice either.
	// Every package that builds a denial- or record-details map, not just today's two
	// producers: a respelling added in internal/pdp (which gained a details-carrying deny
	// funnel) or internal/audit would otherwise be invisible to the guard, and the whole
	// point of the constant is that such a divergence fails nothing at runtime.
	scanned := 0
	for _, dir := range []string{
		".",
		filepath.Join("..", "..", "pkg", "enforcement"),
		filepath.Join("..", "pdp"),
		filepath.Join("..", "audit"),
		filepath.Join("..", "..", "cmd", "eunox"),
	} {
		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			require.NoError(t, err)
			scanned++
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
	// Without this the guard degrades silently to covering nothing if a scanned package is
	// renamed or moved — the same class of quiet, nothing-fails failure the constant exists
	// to prevent.
	require.Greater(t, scanned, 40, "the flow-discriminator scan covered too few files to be meaningful")
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
