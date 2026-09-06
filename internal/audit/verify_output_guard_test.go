// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Source guard over verify.go's diagnostic output: every per-record line must pass through
// admitDiagnostic. The declaration table alone cannot give that property — it is opt-in, so
// a diagnostic added without a row prints unbounded and every existing test still passes.
// This walk makes the DEFAULT bounded, which is the direction the transport's notice classes
// and refusal categories take for the same question.

package audit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// unadmittedOutputSites names the functions allowed to write to opts.Out without an
// admission, and why. Nothing else may: a per-record line reaching the output outside an
// admitted block is the unbounded flood the cap exists to prevent.
var unadmittedOutputSites = map[string]string{
	// The closing summary is what ACCOUNTS for elided lines, so metering it against the
	// budget it reports on would suppress the accounting at exactly the volume that needs it.
	// It is bounded structurally instead: at most one line per declared kind, per pass.
	"reportSuppressedDiagnostics": "the per-kind closing summary, bounded at one line per kind",
	// The elision notice, emitted by the admission itself at the moment the cap is passed.
	"admitDiagnostic": "the inline elision notice, emitted once per kind by the admission",
	// A rider on the diagnostic above it, gated on that line's own admission result rather
	// than on a budget of its own (see reportMalformedTime).
	"reportMalformedTime": "a rider gated on its parent line's admission",
}

func TestVerifyDiagnostics_EveryOutputSiteIsAdmitted(t *testing.T) {
	t.Parallel()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "verify.go", nil, 0)
	if err != nil {
		t.Fatalf("parse verify.go: %v", err)
	}

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		if why, exempt := unadmittedOutputSites[fn.Name.Name]; exempt {
			if why == "" {
				t.Errorf("%s: an exemption must state why", fn.Name.Name)
			}
			continue
		}
		walkGuarded(t, fset, fn.Name.Name, fn.Body, false)
	}
}

// walkGuarded reports any write to opts.Out that is not lexically covered by an
// admitDiagnostic call. Lexical rather than data-flow: the admission returns the permission
// to print, so a site that prints outside what it was granted is the bug this guard is for,
// whatever the value was assigned to on the way.
//
// Two spellings count, because both are in use and neither is wrong: `if v.admitDiagnostic(k)
// { print }`, and the early return `if !v.admitDiagnostic(k) { return }`, which guards the
// REST of its block — a function that would otherwise nest past what the linter allows.
func walkGuarded(t *testing.T, fset *token.FileSet, fn string, n ast.Node, guarded bool) {
	t.Helper()
	switch node := n.(type) {
	case nil:
		return
	case *ast.BlockStmt:
		for _, stmt := range node.List {
			walkGuarded(t, fset, fn, stmt, guarded)
			if guardsRestOfBlock(stmt) {
				guarded = true
			}
		}
		return
	case *ast.IfStmt:
		if node.Init != nil {
			walkGuarded(t, fset, fn, node.Init, guarded)
		}
		// A negated admission grants nothing to its own body — that body is the refusal.
		inner := guarded || (condTakesAdmission(node.Cond) && !isNegated(node.Cond))
		walkGuarded(t, fset, fn, node.Body, inner)
		if node.Else != nil {
			// An else branch is the REFUSED side of the admission, so it inherits the
			// enclosing guard rather than the if's.
			walkGuarded(t, fset, fn, node.Else, guarded)
		}
		return
	case *ast.CallExpr:
		if writesToVerifyOut(node) && !guarded {
			t.Errorf("%s:%s: writes to opts.Out without an admission — route it through v.admitDiagnostic(kind), or declare an exemption in unadmittedOutputSites with its reason",
				fn, fset.Position(node.Pos()))
		}
	}
	for _, child := range childNodes(n) {
		walkGuarded(t, fset, fn, child, guarded)
	}
}

// guardsRestOfBlock reports whether stmt is `if !v.admitDiagnostic(k) { return }` — a refused
// admission that leaves the function, so every later statement in the block ran only because
// the admission was granted.
func guardsRestOfBlock(stmt ast.Stmt) bool {
	ifStmt, ok := stmt.(*ast.IfStmt)
	if !ok || ifStmt.Else != nil || !condTakesAdmission(ifStmt.Cond) || !isNegated(ifStmt.Cond) {
		return false
	}
	if len(ifStmt.Body.List) == 0 {
		return false
	}
	_, terminates := ifStmt.Body.List[len(ifStmt.Body.List)-1].(*ast.ReturnStmt)
	return terminates
}

// isNegated reports whether cond is a `!`-prefixed expression.
func isNegated(cond ast.Expr) bool {
	unary, ok := cond.(*ast.UnaryExpr)
	return ok && unary.Op == token.NOT
}

// childNodes returns n's immediate children, via ast.Inspect on a one-level walk.
func childNodes(n ast.Node) []ast.Node {
	var out []ast.Node
	ast.Inspect(n, func(c ast.Node) bool {
		if c == nil || c == n {
			return c == n
		}
		out = append(out, c)
		return false
	})
	return out
}

// condTakesAdmission reports whether cond calls admitDiagnostic anywhere within it, so the
// `printed := v.admitDiagnostic(k); if printed {` spelling counts as guarded too — the
// assignment form exists because two arms hand the result to reportMalformedTime.
func condTakesAdmission(cond ast.Expr) bool {
	found := false
	ast.Inspect(cond, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "admitDiagnostic" {
			found = true
		}
		if id, ok := n.(*ast.Ident); ok && id.Name == "printed" {
			found = true
		}
		return !found
	})
	return found
}

// writesToVerifyOut reports whether call is an fmt print to v.opts.Out.
func writesToVerifyOut(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !strings.HasPrefix(sel.Sel.Name, "Fprint") {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "fmt" || len(call.Args) == 0 {
		return false
	}
	target, ok := call.Args[0].(*ast.SelectorExpr)
	return ok && target.Sel.Name == "Out"
}
