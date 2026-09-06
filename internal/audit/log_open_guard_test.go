// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// activeLogOpenFuncs names the two functions that produce the ACTIVE tape's write handle.
// Scoped to these two rather than to every open in the package because the rule below is
// about a path an attacker who can write the log DIRECTORY chooses the contents of: the
// whole-file readers already carry all three guards (openDiscoveredAuditFile), while the
// key file and the sidecar lock are their own threat models and their own findings.
var activeLogOpenFuncs = []string{"openAndPrepareLog", "openGuardedAppend"}

// TestActiveLogOpens_CarryAllThreeSubstitutionGuards is the deterministic half of the FIFO
// hardening: openDiscoveredAuditFile states the package's rule — OpenNoFollow, OpenNonBlock
// and an fstat through the HANDLE are individually load-bearing and none subsumes another —
// and these two sites had only the first. A source guard rather than a behavioral test
// because the behavioral one (TestActiveLogOpen_FIFOPlantedInTheCreateWindow) has to RACE
// the Lstat->open window to reach the code it covers, so a dropped flag can survive a run
// that never lands in it, and because an open added to either function later inherits the
// rule here rather than the next reviewer's memory.
func TestActiveLogOpens_CarryAllThreeSubstitutionGuards(t *testing.T) {
	t.Parallel()
	fset := token.NewFileSet()
	found := map[string]bool{}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("listing package sources: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if perr != nil {
			t.Fatalf("parsing %s: %v", name, perr)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !slices.Contains(activeLogOpenFuncs, fn.Name.Name) {
				continue
			}
			found[fn.Name.Name] = true
			checkGuardedOpen(t, fset, fn)
		}
	}

	// An enumeration that matched nothing would pass this guard vacuously, which is the one
	// way a source guard fails silently: a rename is exactly what leaves it walking nothing.
	for _, name := range activeLogOpenFuncs {
		if !found[name] {
			t.Fatalf("%s is not among this package's sources; the guard is walking nothing", name)
		}
	}
}

// checkGuardedOpen holds one function to all three guards: both flags on every os.OpenFile
// it performs, and the handle check somewhere in its body. The handle check is asserted by
// CALL rather than by position because it legitimately sits after a permission-fallback arm
// at one site and immediately after the open at the other.
func checkGuardedOpen(t *testing.T, fset *token.FileSet, fn *ast.FuncDecl) {
	t.Helper()
	opens := 0
	handleChecked := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch callee(call) {
		case "os.OpenFile":
			opens++
			if len(call.Args) < 2 {
				t.Fatalf("%s: os.OpenFile with no flag argument at %s", fn.Name.Name, fset.Position(call.Pos()))
			}
			flags := render(fset, call.Args[1])
			for _, guard := range []string{"config.OpenNoFollow", "config.OpenNonBlock"} {
				if !strings.Contains(flags, guard) {
					t.Errorf("%s: the open at %s does not OR in %s (flags: %s) — a path an attacker can plant in the Lstat->open window must not be followed (OpenNoFollow) and must not be able to BLOCK the open (OpenNonBlock)",
						fn.Name.Name, fset.Position(call.Pos()), guard, flags)
				}
			}
		case "refuseNonRegularHandle":
			handleChecked = true
		}
		return true
	})
	if opens == 0 {
		t.Errorf("%s performs no os.OpenFile; the flag guard above is vacuous for it", fn.Name.Name)
	}
	if !handleChecked {
		t.Errorf("%s never calls refuseNonRegularHandle: the two flags make the open safe to ATTEMPT, and only the fstat through the handle refuses whatever non-regular object was substituted (a FIFO another process holds open for reading opens fine under both flags)", fn.Name.Name)
	}
}

// callee renders a call's function as "pkg.Name" or "Name", the spelling the switch above
// matches on.
func callee(call *ast.CallExpr) string {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name
	case *ast.SelectorExpr:
		if pkg, ok := fun.X.(*ast.Ident); ok {
			return pkg.Name + "." + fun.Sel.Name
		}
		return fun.Sel.Name
	}
	return ""
}

func render(fset *token.FileSet, node ast.Node) string {
	var sb strings.Builder
	if err := printer.Fprint(&sb, fset, node); err != nil {
		return ""
	}
	return sb.String()
}
