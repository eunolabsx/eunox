// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"go/ast"
	"go/types"
	"slices"
	"strings"
	"testing"
)

// TestFileOpens_CarryAllThreeSubstitutionGuards holds every os.OpenFile in this package to the
// rule internal/audit's own source guard enforces over its opens: OpenNoFollow and
// OpenNonBlock on the open, then an fstat through the handle that is acted on before the
// descriptor is read. internal/audit's guard walks that package alone, which is how the
// effect-receipt key set shipped with two of the three — its FIFO half missing, so a FIFO
// swapped in after the Lstat wedged BuildRoutes inside open(2).
//
// Package-wide rather than per-function, unlike the audit guard, because every file this
// package opens is an operator-named credential or trust anchor (the control token, the
// receipt key set); a future open that genuinely needs none of the three is a reason to
// narrow this, argued in review. os.ReadFile is refused outright since it takes no flags and
// yields no handle. The residual is os.Open, left unwalked because the one use here opens a
// DIRECTORY to fsync it and a regular-file check would refuse exactly that.
func TestFileOpens_CarryAllThreeSubstitutionGuards(t *testing.T) {
	t.Parallel()
	opens := 0
	for _, src := range packageSources(t) {
		for _, decl := range src.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			var fnOpens int
			checkedAt, readAt := fn.Body.End(), fn.Body.End()
			acted := false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.IfStmt:
					if callsHandleGuard(n) && bodyReturns(n.Body) {
						acted = true
					}
				case *ast.CallExpr:
					switch name := types.ExprString(n.Fun); name {
					case "os.ReadFile":
						t.Errorf("%s: %s calls os.ReadFile, which cannot take O_NOFOLLOW/O_NONBLOCK and yields no handle to check; open with os.OpenFile under all three guards",
							src.name, fn.Name.Name)
					case "os.OpenFile":
						fnOpens++
						if len(n.Args) < 2 {
							t.Fatalf("%s: os.OpenFile in %s with no flag argument", src.name, fn.Name.Name)
						}
						flags := types.ExprString(n.Args[1])
						for _, guard := range []string{"config.OpenNoFollow", "config.OpenNonBlock"} {
							if !strings.Contains(flags, guard) {
								t.Errorf("%s: the open in %s does not OR in %s (flags: %s)", src.name, fn.Name.Name, guard, flags)
							}
						}
					case "config.RefuseNonRegularHandle":
						if n.Pos() < checkedAt {
							checkedAt = n.Pos()
						}
					case "io.ReadAll":
						if n.Pos() < readAt {
							readAt = n.Pos()
						}
					}
				}
				return true
			})
			if fnOpens == 0 {
				continue
			}
			opens += fnOpens
			switch {
			case checkedAt == fn.Body.End():
				t.Errorf("%s: %s opens a file but never calls config.RefuseNonRegularHandle; only the fstat through the descriptor refuses a non-regular object the two flags let open",
					src.name, fn.Name.Name)
			case !acted:
				t.Errorf("%s: %s calls config.RefuseNonRegularHandle but does not return on its error", src.name, fn.Name.Name)
			case readAt < checkedAt:
				t.Errorf("%s: %s reads the handle before checking it", src.name, fn.Name.Name)
			}
		}
	}
	// A walk that found no open passes vacuously, which is the one way a source guard fails
	// silently.
	if opens == 0 {
		t.Fatal("no os.OpenFile found in this package's sources; the guard is walking nothing")
	}
}

func callsHandleGuard(stmt *ast.IfStmt) bool {
	found := false
	for _, part := range []ast.Node{stmt.Init, stmt.Cond} {
		if part == nil {
			continue
		}
		ast.Inspect(part, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok && types.ExprString(call.Fun) == "config.RefuseNonRegularHandle" {
				found = true
			}
			return true
		})
	}
	return found
}

func bodyReturns(body *ast.BlockStmt) bool {
	return slices.ContainsFunc(body.List, func(s ast.Stmt) bool {
		_, ok := s.(*ast.ReturnStmt)
		return ok
	})
}
