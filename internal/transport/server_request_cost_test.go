// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// What one server-initiated request costs to dispatch, held to the decisions recorded on the types
// it flows through rather than to a benchmark nobody reruns.

package transport

import (
	"go/ast"
	"testing"

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
