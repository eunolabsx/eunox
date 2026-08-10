// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The residual the notice MECHANISM cannot answer for itself.
//
// noticef now reads a site's declaration at write time (see notice.go), so "declared metered" and
// "charges that class's bucket" are one fact — the analogue of forCategory on the record half. Two
// questions remain outside a runtime reader, and they are what this walk is for:
//
//   - a line written through a shape that never reaches noticef at all (a bare fmt.Fprintf), which
//     the mechanism cannot see because it is never called;
//   - a declaration nothing reaches, which is an answer to a question nobody asks.
//
// Both were the whole guard before the mechanism existed, and the notice budget's "how many
// diagnostic syscalls can a peer drive" claim rests entirely on the first one holding.

package transport

import (
	"go/ast"
	"go/token"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// noticeWriters maps a package qualifier to the calls through it that put a diagnostic line on this
// package's error writer. noticef is deliberately absent: it IS the mechanism, so a call to it is
// the metered site rather than one needing a declaration found for it.
//
// RESIDUAL, stated rather than implied: a line written through a shape not listed here — a raw
// w.Write([]byte(...)), a locally aliased fmt, a helper of one's own — is invisible to this walk,
// because "is this write a diagnostic" is not answerable from the callee alone. What the walk buys
// is that the shapes this package actually uses cannot ship undeclared; it does not make the
// package's diagnostic surface closed.
var noticeWriters = map[string]map[string]bool{
	"fmt": {"Fprintf": true, "Fprintln": true, "Fprint": true},
	"log": {"Printf": true, "Println": true, "Print": true},
	"io":  {"WriteString": true},
}

// TestNoticeBounding_EveryDeclarationIsWellFormed is the build-time half: an entry with no
// disposition, a metered one with no class (or a non-metered one carrying one), or an exemption
// with no reason, fails here rather than shipping as a default.
func TestNoticeBounding_EveryDeclarationIsWellFormed(t *testing.T) {
	t.Parallel()
	for site, decl := range noticeDeclarations {
		switch decl.bound {
		case noticeUndeclared:
			t.Errorf("diagnostic site %q declares no bound; metered, record-gated, one-shot and deliberately-unbounded are all answers, and none may be inherited", site)
		case noticeMetered:
			assert.Contains(t, noticeClasses, decl.class,
				"site %q is metered but names no notice class; the class picks the bucket at write time, and an unclassified one charges the floor-rate fallback rather than its own share", site)
			assert.Empty(t, decl.why, "site %q is bounded but carries an exemption reason, which reads as a disagreement with its own disposition", site)
		case noticeExempt:
			assert.NotEmpty(t, decl.why, "site %q is exempt with no reason; the reason IS the exemption, and one without it is indistinguishable from an oversight", site)
			assert.Equal(t, classUnclassified, decl.class, "site %q is exempt but names a bucket class, which nothing will ever charge", site)
		default:
			assert.Empty(t, decl.why, "site %q is bounded but carries an exemption reason, which reads as a disagreement with its own disposition", site)
			assert.Equal(t, classUnclassified, decl.class, "site %q is not metered but names a bucket class, which nothing will ever charge", site)
		}
	}
}

// TestNoticeBounding_EverySiteIsDeclared walks every diagnostic write in the package's non-test
// sources and requires it to be answered by noticeDeclarations — a metered one through the site
// constant its noticef call passes, any other through its enclosing function's qualified name.
//
// The two keyings are the two things an AST walk can actually see, and they are not
// interchangeable: a site constant is what lets ONE function hold lines of different classes
// (enforcedForwardCore writes an observe downgrade beside a redaction failure), while a bare
// Fprintf has no site to name and only its enclosing function — receiver included, since this
// package has same-named twins that both write — to be attributed to.
func TestNoticeBounding_EverySiteIsDeclared(t *testing.T) {
	t.Parallel()
	sources := packageSources(t)
	consts := noticeSiteConstants(t, sources)
	seen, checked := map[noticeSite]bool{}, 0
	for _, src := range sources {
		for _, decl := range src.file.Decls {
			fnDecl, isFunc := decl.(*ast.FuncDecl)
			if !isFunc || fnDecl.Body == nil {
				continue
			}
			name := fnDecl.Name.Name
			if name == "noticef" {
				// The mechanism's own implementation, not a site that needs a declaration.
				continue
			}
			qualified := qualifiedFuncName(fnDecl)
			ast.Inspect(fnDecl.Body, func(n ast.Node) bool {
				call, isCall := n.(*ast.CallExpr)
				if !isCall {
					return true
				}
				sel, isSel := call.Fun.(*ast.SelectorExpr)
				if !isSel {
					return true
				}
				pkg, isIdent := sel.X.(*ast.Ident)
				if !isIdent || !noticeWriters[pkg.Name][sel.Sel.Name] {
					return true
				}
				checked++
				seen[qualified] = true
				declared, isDeclared := noticeDeclarations[qualified]
				if !isDeclared {
					t.Errorf("%s:%d: %s writes a diagnostic line with no entry in noticeDeclarations; declare how it is bounded (a metered site through noticef, its record's admission verdict, a one-shot latch, or exempt with a reason)",
						src.name, src.fset.Position(call.Pos()).Line, qualified)
					return true
				}
				if declared.bound == noticeMetered {
					t.Errorf("%s:%d: %s is declared metered but writes its line with a bare %s.%s, which charges no bucket; go through noticef",
						src.name, src.fset.Position(call.Pos()).Line, qualified, pkg.Name, sel.Sel.Name)
				}
				return true
			})
			// A metered site is recognized by the site constant its noticef call passes.
			ast.Inspect(fnDecl.Body, func(n ast.Node) bool {
				if !isCallTo(n, "noticef") {
					return true
				}
				checked++
				args := n.(*ast.CallExpr).Args
				require.GreaterOrEqual(t, len(args), 2, "%s:%d: noticef call with no site argument", src.name, src.fset.Position(n.Pos()).Line)
				ident, isIdent := args[1].(*ast.Ident)
				if !isIdent {
					t.Errorf("%s:%d: %s names its noticef site with an expression rather than one of notice.go's site constants; the declaration is looked up by that value at write time, so a computed one cannot be checked against the table",
						src.name, src.fset.Position(n.Pos()).Line, name)
					return true
				}
				site, isSiteConst := consts[ident.Name]
				if !isSiteConst {
					t.Errorf("%s:%d: %s passes %q to noticef, which is not a declared noticeSite constant",
						src.name, src.fset.Position(n.Pos()).Line, name, ident.Name)
					return true
				}
				seen[site] = true
				// A metered site charging nothing is precisely what the runtime lookup exists to
				// prevent, so this can only fail through a table edit that leaves a constant behind.
				assert.Equal(t, noticeMetered, noticeDeclarations[site].bound,
					"%s:%d: %s charges the notice bucket for site %q, which declares %s; a site's declaration and its mechanism are one decision",
					src.name, src.fset.Position(n.Pos()).Line, name, site, noticeBoundName(noticeDeclarations[site].bound))
				return true
			})
		}
	}
	require.Positive(t, checked, "no diagnostic write was found in any non-test file; this guard would pass vacuously")
	for site := range noticeDeclarations {
		assert.True(t, seen[site], "diagnostic site %q is declared but writes no line; a declaration nothing reaches is an answer to a question nobody asks", site)
	}
}

// TestNoticeBounding_UnboundedChannelIsTestOnly holds noticesTo to what its doc claims. A
// production leg reaching for it would be declared metered and charge nothing — the disagreement
// the runtime lookup cannot catch, because the lookup governs which bucket a line charges and this
// hands it no bucket at all.
func TestNoticeBounding_UnboundedChannelIsTestOnly(t *testing.T) {
	t.Parallel()
	found := 0
	for _, src := range packageSources(t) {
		ast.Inspect(src.file, func(n ast.Node) bool {
			if !isCallTo(n, "noticesTo") {
				return true
			}
			found++
			t.Errorf("%s:%d: noticesTo builds an UNBOUNDED diagnostic channel and is test-only; a production leg takes its channel from the proxy (noticeWriter/routeNoticeWriter) so its lines are bounded",
				src.name, src.fset.Position(n.Pos()).Line)
			return true
		})
	}
	assert.Zero(t, found)
}

// noticeSiteConstants collects notice.go's `noticeSite` constants as name -> value, so the walk can
// resolve the identifier a call passes to the key the declaration table is read by. Without it the
// walk sees an identifier and the table sees a string, and nothing checks that they meet.
func noticeSiteConstants(t *testing.T, sources []packageSource) map[string]noticeSite {
	t.Helper()
	out := map[string]noticeSite{}
	for _, src := range sources {
		for _, decl := range src.file.Decls {
			gen, isGen := decl.(*ast.GenDecl)
			if !isGen || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				vs, isValue := spec.(*ast.ValueSpec)
				if !isValue || len(vs.Names) != len(vs.Values) {
					continue
				}
				ident, isIdent := vs.Type.(*ast.Ident)
				if !isIdent || ident.Name != "noticeSite" {
					continue
				}
				for i, nameIdent := range vs.Names {
					lit, isLit := vs.Values[i].(*ast.BasicLit)
					require.True(t, isLit, "noticeSite constant %s is not a string literal", nameIdent.Name)
					value, err := strconv.Unquote(lit.Value)
					require.NoError(t, err)
					out[nameIdent.Name] = noticeSite(value)
				}
			}
		}
	}
	require.NotEmpty(t, out, "no noticeSite constants found; the site half of this guard would pass vacuously")
	return out
}

// qualifiedFuncName is the key a BARE-writer declaration is looked up by: `*T.method` for a method,
// the bare name for a package function.
//
// Qualified rather than bare because this package has same-named twins that both write — readUpstream
// on each transport — and a bare key would silently hand the second the first's answer. The old walk
// could only DETECT that collision and complain; a qualified key makes it unrepresentable, which is
// what lets the two twins carry the same exemption honestly instead of by coincidence.
func qualifiedFuncName(fn *ast.FuncDecl) noticeSite {
	if fn.Recv != nil && len(fn.Recv.List) > 0 {
		return noticeSite(exprString(fn.Recv.List[0].Type) + "." + fn.Name.Name)
	}
	return noticeSite(fn.Name.Name)
}

// exprString renders a receiver type as `*T` or `T`.
func exprString(e ast.Expr) string {
	if star, isStar := e.(*ast.StarExpr); isStar {
		return "*" + exprString(star.X)
	}
	if ident, isIdent := e.(*ast.Ident); isIdent {
		return ident.Name
	}
	return "?"
}

func noticeBoundName(b noticeBound) string {
	switch b {
	case noticeMetered:
		return "metered"
	case noticeRecordGated:
		return "record-gated"
	case noticeOnce:
		return "one-shot"
	case noticeExempt:
		return "exempt"
	default:
		return "undeclared"
	}
}
