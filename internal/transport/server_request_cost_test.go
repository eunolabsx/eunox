// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// What one server-initiated request costs to dispatch, held to the decisions recorded on the types
// it flows through rather than to a benchmark nobody reruns.

package transport

import (
	"go/ast"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestServerRequestDispatch_HandlerGoroutineCapturesOnlyItsHandler is the guard for
// serverRequestDispatch's size note.
//
// The struct is past the compiler's 128-byte by-value closure-capture threshold, so a closure that
// names ANY field of it captures the whole thing by reference and heap-moves it at function entry —
// one allocation per server-initiated request, including on the saturation path that spawns no
// goroutine at all. Hoisting the one field the goroutine needs removes it; nothing about the type
// prevents the next edit from putting it back, and `go build -gcflags=-m` is not something a change
// gets checked against.
func TestServerRequestDispatch_HandlerGoroutineCapturesOnlyItsHandler(t *testing.T) {
	t.Parallel()
	fn := findMethod(t, "serverRequestPool", "dispatch")

	param := dispatchParamName(t, fn)
	found := 0
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		goStmt, isGo := n.(*ast.GoStmt)
		if !isGo {
			return true
		}
		found++
		ast.Inspect(goStmt.Call, func(inner ast.Node) bool {
			ident, isIdent := inner.(*ast.Ident)
			if isIdent && ident.Name == param {
				t.Errorf("the handler goroutine names %q, so it captures the whole serverRequestDispatch by reference and heap-moves it on every dispatch; hoist the field it needs into a local first (see serverRequestDispatch's size note)", param)
			}
			return true
		})
		return true
	})
	require.Equal(t, 1, found, "expected exactly one goroutine in dispatch; this guard is written for it")
}

// dispatchParamName is the name of dispatch's serverRequestDispatch parameter, read from the source
// rather than assumed, so renaming it does not turn this guard into a no-op that passes.
func dispatchParamName(t *testing.T, fn *ast.FuncDecl) string {
	t.Helper()
	for _, field := range fn.Type.Params.List {
		ident, isIdent := field.Type.(*ast.Ident)
		if isIdent && ident.Name == "serverRequestDispatch" {
			require.Len(t, field.Names, 1, "the dispatch parameter must be named for this guard to have a subject")
			return field.Names[0].Name
		}
	}
	t.Fatal("dispatch takes no serverRequestDispatch parameter; this guard is walking the wrong function")
	return ""
}

// findMethod returns the named method of the named receiver type from this package's sources.
func findMethod(t *testing.T, recv, name string) *ast.FuncDecl {
	t.Helper()
	for _, src := range packageSources(t) {
		for _, decl := range src.file.Decls {
			fn, isFunc := decl.(*ast.FuncDecl)
			if !isFunc || fn.Name.Name != name || fn.Recv == nil || len(fn.Recv.List) == 0 {
				continue
			}
			if exprString(fn.Recv.List[0].Type) == "*"+recv {
				return fn
			}
		}
	}
	t.Fatalf("no method (*%s).%s in this package", recv, name)
	return nil
}

// TestRemoteSession_RefusalTableHoldsOnlyWhatItCanReach covers the remote-upstream session's own
// bucket table.
//
// A remote upstream issues no server-initiated requests through this proxy — there is no upstream
// reader to receive one and no sink to answer one through — so three of the four upstream-driven
// categories are unreachable there and their buckets were four rate limiters and four map entries
// per session for records nothing can write.
func TestRemoteSession_RefusalTableHoldsOnlyWhatItCanReach(t *testing.T) {
	t.Parallel()
	aggregate := newRefusalRecordLimiter()
	remote := newUpstreamRefusalLimiter(aggregate, remoteUpstreamRefusalCategories)

	assert.Len(t, remote.buckets, 1, "a remote session must not retain buckets for categories its mode cannot reach")
	_, held := remote.buckets[catServerRequestFailed]
	assert.True(t, held, "the host reply this mode cannot relay is the drop it actually produces, so that category stays session-scoped")

	// A category it does NOT hold is delegated WHOLLY to the aggregate, which is the proxy-wide
	// bound those records had before the per-session split existed — never the floor-rate `unknown`
	// bucket, which would silently make an unlisted category the most suppressed one on the proxy.
	for range int(perCategoryDenyBurst) {
		ok := remote.admitWithFloor(catDisplaced, nil).ok
		require.True(t, ok)
	}
	ok := remote.admitWithFloor(catDisplaced, nil).ok
	assert.False(t, ok, "an unlisted category charges the aggregate's bucket for that category, so it is bounded at the pre-split rate")
	assert.Greater(t, aggregate.bucket(catDisplaced).burst, float64(perBucketFloor),
		"and the bucket it charged is the aggregate's real one, not the floor-rate fallback")
}

// TestUpstreamRefusalCategories_LocalSessionKeepsTheWholeSet is the control: narrowing the REMOTE
// set must not narrow the subprocess one, whose upstream genuinely drives all four.
func TestUpstreamRefusalCategories_LocalSessionKeepsTheWholeSet(t *testing.T) {
	t.Parallel()
	local := newUpstreamRefusalLimiter(newRefusalRecordLimiter(), upstreamRefusalCategories)
	assert.Len(t, local.buckets, len(upstreamRefusalCategories))
	for _, cat := range upstreamRefusalCategories {
		_, held := local.buckets[cat]
		assert.True(t, held, "category %q is driven by a subprocess upstream and must stay session-scoped", cat)
	}
}
