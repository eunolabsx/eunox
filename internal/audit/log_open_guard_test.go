// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"go/types"
	"slices"
	"strings"
	"testing"
)

// guardedAuditOpens names every function in this package that opens a path an attacker who
// can write the audit DIRECTORY chooses the contents of. All five answer to one rule, so
// they are listed rather than filtered: a name here that no longer exists fails the walk
// below, which is the failure mode a filter would hide.
var guardedAuditOpens = []string{
	"openAndPrepareLog",       // the active tape, at startup
	"openGuardedAppend",       // the active tape, at both post-rotation reopens
	"openDiscoveredAuditFile", // any chain file found by a directory scan
	"readAuditKeyFile",        // the HMAC key, whose redirection is unrecoverable
	"openAuditLockFile",       // the sidecar lock, whose payload is its exclusivity
}

// handleGuards are the two spellings of the third guard. Both are the same function —
// refuseNonRegularHandle is the log's subject-binding shim over config.RefuseNonRegularHandle
// — and a site is free to call either, but not to hand-roll a third fstat: that is how the
// package came to answer one question three ways with three different refusal messages.
var handleGuards = []string{"refuseNonRegularHandle", "config.RefuseNonRegularHandle"}

// usesTheHandle names the calls whose safety DEPENDS on the check having already run: the
// fchmod pair (which would re-mode whatever object was substituted) and the whole-file read.
// The guard requires the check to precede them, since a check that runs after the damage is
// a check in name only.
var usesTheHandle = []string{"tightenLogMode", "tightenKeyFileMode", "io.ReadAll"}

// TestGuardedAuditOpens_CarryAllThreeSubstitutionGuards is the deterministic half of the
// FIFO hardening: openDiscoveredAuditFile states the package's rule — OpenNoFollow,
// OpenNonBlock and an fstat through the HANDLE are individually load-bearing and none
// subsumes another — and three of these five sites had only the first. A source guard
// rather than a behavioral test because the behavioral ones have to RACE the Lstat->open
// window to reach the code they cover, so a dropped flag can survive a run that never
// lands in it, and because an open added to any of these functions later inherits the rule
// here rather than the next reviewer's memory.
//
// It is deliberately per-function rather than "no bare os.OpenFile in the package": the
// rule is about paths an attacker influences, and a guard that also refused a legitimate
// unguarded open would be argued with rather than obeyed.
func TestGuardedAuditOpens_CarryAllThreeSubstitutionGuards(t *testing.T) {
	t.Parallel()
	found := map[string]bool{}
	for _, src := range buildableSources(t) {
		for _, decl := range src.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !slices.Contains(guardedAuditOpens, fn.Name.Name) {
				continue
			}
			found[fn.Name.Name] = true
			checkGuardedOpen(t, src.fset, fn)
		}
	}

	// An enumeration that matched nothing would pass vacuously, which is the one way a
	// source guard fails silently: a rename is exactly what leaves it walking nothing.
	for _, name := range guardedAuditOpens {
		if !found[name] {
			t.Fatalf("%s is not among this package's buildable sources; the guard is walking nothing", name)
		}
	}
}

// checkGuardedOpen holds one function to all three guards: both flags on every os.OpenFile
// it performs, and a handle check that is ACTED ON and runs before anything else touches
// the descriptor.
func checkGuardedOpen(t *testing.T, fset *token.FileSet, fn *ast.FuncDecl) {
	t.Helper()
	opens := 0
	checkedAt := token.NoPos
	usedAt := token.NoPos
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := types.ExprString(call.Fun)
		switch {
		case name == "os.OpenFile":
			opens++
			if len(call.Args) < 2 {
				t.Fatalf("%s: os.OpenFile with no flag argument at %s", fn.Name.Name, fset.Position(call.Pos()))
			}
			checkOpenFlags(t, fset, fn, call)
		case slices.Contains(handleGuards, name):
			if !checkedAt.IsValid() {
				checkedAt = call.Pos()
			}
		case slices.Contains(usesTheHandle, name):
			if !usedAt.IsValid() {
				usedAt = call.Pos()
			}
		}
		return true
	})

	if opens == 0 {
		t.Errorf("%s performs no os.OpenFile; the flag guard is vacuous for it", fn.Name.Name)
	}
	if !checkedAt.IsValid() {
		t.Errorf("%s never checks its handle: the two flags make the open safe to ATTEMPT, and only the fstat through the descriptor refuses whatever non-regular object was substituted (a FIFO another process holds open opens fine under both flags)", fn.Name.Name)
		return
	}
	// A check whose error is discarded, or whose failure falls through, is not a check.
	if !guardIsActedOn(fn) {
		t.Errorf("%s calls the handle guard but does not return on its error: the refusal has to stop the function, not be recorded and stepped over", fn.Name.Name)
	}
	if usedAt.IsValid() && usedAt < checkedAt {
		t.Errorf("%s touches the handle at %s before checking it at %s: an fchmod or read that runs first has already acted on whatever object was substituted in the Lstat->open window",
			fn.Name.Name, fset.Position(usedAt), fset.Position(checkedAt))
	}
}

// checkOpenFlags requires both flags on one open. The flag argument is usually a literal
// OR-expression, but the key file BUILDS it in a variable across an opt-out branch, so an
// identifier is resolved by joining every assignment to it in the function — the flag has
// to be applied on some path, which is as much as a syntactic walk can honestly say.
func checkOpenFlags(t *testing.T, fset *token.FileSet, fn *ast.FuncDecl, call *ast.CallExpr) {
	t.Helper()
	flags := types.ExprString(call.Args[1])
	if ident, ok := call.Args[1].(*ast.Ident); ok {
		flags = strings.Join(assignmentsTo(fn, ident.Name), " ")
	}
	for _, guard := range []string{"config.OpenNoFollow", "config.OpenNonBlock"} {
		if !strings.Contains(flags, guard) {
			t.Errorf("%s: the open at %s does not OR in %s (flags: %s) — a path an attacker can plant in the Lstat->open window must not be followed (OpenNoFollow) and must not be able to BLOCK the open (OpenNonBlock), which would wedge the caller where no post-open check can run",
				fn.Name.Name, fset.Position(call.Pos()), guard, flags)
		}
	}
}

// assignmentsTo renders every value assigned to name inside fn, so a flag set built up over
// several statements can be inspected as one string.
func assignmentsTo(fn *ast.FuncDecl, name string) []string {
	var values []string
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, lhs := range assign.Lhs {
			if ident, ok := lhs.(*ast.Ident); ok && ident.Name == name && i < len(assign.Rhs) {
				values = append(values, types.ExprString(assign.Rhs[i]))
			}
		}
		return true
	})
	return values
}

// guardIsActedOn reports whether some handle-guard call appears as the condition (or its
// init) of an if whose body returns — the shape every site uses, and the one that makes the
// refusal binding rather than advisory.
func guardIsActedOn(fn *ast.FuncDecl) bool {
	acted := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		stmt, ok := n.(*ast.IfStmt)
		if !ok || acted {
			return true
		}
		calls := false
		ast.Inspect(stmt, func(inner ast.Node) bool {
			if call, ok := inner.(*ast.CallExpr); ok && slices.Contains(handleGuards, types.ExprString(call.Fun)) {
				calls = true
			}
			return true
		})
		if !calls {
			return true
		}
		ast.Inspect(stmt.Body, func(inner ast.Node) bool {
			if _, ok := inner.(*ast.ReturnStmt); ok {
				acted = true
			}
			return true
		})
		return true
	})
	return acted
}

type packageSource struct {
	fset *token.FileSet
	file *ast.File
}

// buildableSources parses the package's non-test sources that this GOOS/GOARCH actually
// COMPILES. go/parser ignores build constraints, and this package carries six build-tagged
// files: without the filter a per-platform variant of a guarded open would be held to the
// rule on platforms that never build it (a false failure), and — worse — a name found only
// in an excluded file would satisfy the enumeration check while the compiled implementation
// went unread.
func buildableSources(t *testing.T) []packageSource {
	t.Helper()
	ctx := build.Default
	pkg, err := ctx.ImportDir(".", 0)
	if err != nil {
		t.Fatalf("resolving this package's buildable files: %v", err)
	}
	fset := token.NewFileSet()
	var sources []packageSource
	for _, name := range pkg.GoFiles {
		file, perr := parser.ParseFile(fset, name, nil, 0)
		if perr != nil {
			t.Fatalf("parsing %s: %v", name, perr)
		}
		sources = append(sources, packageSource{fset: fset, file: file})
	}
	if len(sources) == 0 {
		t.Fatal("no buildable package sources found; every source guard here would pass vacuously")
	}
	return sources
}
