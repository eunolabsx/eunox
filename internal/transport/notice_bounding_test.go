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
	"go/types"
	"io"
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

// TestNoticeBounding_EveryDeclarationIsWellFormed is the build-time half, now asking each half of
// the table only what its own key kind can get wrong: a metered site with no class, an unmetered one
// with no disposition, or an exemption with no reason.
//
// The arm that policed the two key spaces against each other is gone with them. A metered entry
// keyed by a Go function name — unreachable from admitNotice, silently charging the floor bucket —
// was the failure the `default:` arm existed to catch, and it is now unwritable: metered-ness is
// membership in meteredNotices, which noticeFunc cannot key.
func TestNoticeBounding_EveryDeclarationIsWellFormed(t *testing.T) {
	t.Parallel()
	for site, class := range meteredNotices {
		assert.Contains(t, noticeClasses, class,
			"site %q is metered but names no notice class; the class picks the bucket at write time, and an unclassified one charges the floor-rate fallback rather than its own share", site)
	}
	for fn, decl := range unmeteredNotices {
		switch decl.bound {
		case noticeUndeclared:
			t.Errorf("diagnostic site %q declares no bound; record-gated, one-shot and deliberately-unbounded are all answers, and none may be inherited (metering is membership in meteredNotices)", fn)
		case noticeExempt:
			assert.NotEmpty(t, decl.why, "site %q is exempt with no reason; the reason IS the exemption, and one without it is indistinguishable from an oversight", fn)
		default:
			assert.Empty(t, decl.why, "site %q is bounded but carries an exemption reason, which reads as a disagreement with its own disposition", fn)
		}
	}
}

// noticeEntryPoints are the mechanism's site-taking calls, mapped to the argument index the site
// travels in. Two, because a site whose arguments are expensive enough to be worth not building
// takes its admission directly and writes through the line it gets back (see admitNotice) — so a
// walk that recognized only noticef would report those sites as declared-but-unreached.
var noticeEntryPoints = map[string]int{
	"noticef":     1,
	"admitNotice": 0,
}

// noticeMechanism is the set of functions that IMPLEMENT the bounded channel rather than write
// through it. Their fmt calls are the mechanism's own and need no declaration of their own.
var noticeMechanism = map[noticeFunc]bool{
	"noticef":           true,
	"noticeLine.writef": true,
}

// TestNoticeBounding_EverySiteIsDeclared walks every diagnostic write in the package's non-test
// sources and requires it to be answered — a metered one through the site constant it passes to a
// notice entry point, any other through its enclosing function's qualified name.
//
// The two keyings are the two things an AST walk can actually see, and they are not
// interchangeable: a site constant is what lets ONE function hold lines of different classes
// (enforcedForwardCore writes an observe downgrade beside a redaction failure), while a bare
// Fprintf has no site to name and only its enclosing function — receiver included, since this
// package has same-named twins that both write — to be attributed to. They are now two TABLES for
// the same reason, which is what removes the check this walk used to need in the other direction:
// a metered entry cannot be keyed by a function name, so a declared-metered site writing through a
// bare Fprintf is not a runtime hazard to detect but a thing that does not typecheck.
func TestNoticeBounding_EverySiteIsDeclared(t *testing.T) {
	t.Parallel()
	sources := packageSources(t)
	consts := noticeSiteConstants(t)
	seenFuncs, seenSites, checked := map[noticeFunc]bool{}, map[noticeSite]bool{}, 0
	for _, src := range sources {
		for _, decl := range src.file.Decls {
			fnDecl, isFunc := decl.(*ast.FuncDecl)
			if !isFunc || fnDecl.Body == nil {
				continue
			}
			name := fnDecl.Name.Name
			qualified := qualifiedFuncName(fnDecl)
			if noticeMechanism[qualified] {
				continue
			}
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
				seenFuncs[qualified] = true
				if _, isDeclared := unmeteredNotices[qualified]; !isDeclared {
					t.Errorf("%s:%d: %s writes a diagnostic line with no entry in unmeteredNotices; declare how it is bounded (its record's admission verdict, a one-shot latch, or exempt with a reason) — or meter it, which means routing it through noticef and declaring its class in meteredNotices",
						src.name, src.fset.Position(call.Pos()).Line, qualified)
				}
				return true
			})
			// A metered site is recognized by the site constant it hands the mechanism.
			ast.Inspect(fnDecl.Body, func(n ast.Node) bool {
				entry, args, isEntry := noticeEntryPointCall(n)
				if !isEntry {
					return true
				}
				checked++
				at := noticeEntryPoints[entry]
				require.Greater(t, len(args), at, "%s:%d: %s call with no site argument", src.name, src.fset.Position(n.Pos()).Line, entry)
				ident, isIdent := args[at].(*ast.Ident)
				if !isIdent {
					t.Errorf("%s:%d: %s names its %s site with an expression rather than one of notice.go's site constants; the declaration is looked up by that value at write time, so a computed one cannot be checked against the table",
						src.name, src.fset.Position(n.Pos()).Line, name, entry)
					return true
				}
				site, isSiteConst := consts[ident.Name]
				if !isSiteConst {
					t.Errorf("%s:%d: %s passes %q to %s, which is not a declared noticeSite constant",
						src.name, src.fset.Position(n.Pos()).Line, name, ident.Name, entry)
					return true
				}
				seenSites[site] = true
				// A site charging the floor-rate fallback instead of a real class's share is what
				// the runtime lookup cannot report for itself, since the fallback is also the
				// correct answer for a site nobody has classified yet.
				assert.Contains(t, meteredNotices, site,
					"%s:%d: %s charges the notice bucket for site %q, which declares no class in meteredNotices; it would fall to the floor-rate fallback rather than its own share",
					src.name, src.fset.Position(n.Pos()).Line, name, site)
				return true
			})
		}
	}
	require.Positive(t, checked, "no diagnostic write was found in any non-test file; this guard would pass vacuously")
	for site := range meteredNotices {
		assert.True(t, seenSites[site], "diagnostic site %q is declared but writes no line; a declaration nothing reaches is an answer to a question nobody asks", site)
	}
	for fn := range unmeteredNotices {
		assert.True(t, seenFuncs[fn], "diagnostic site %q is declared but writes no line; a declaration nothing reaches is an answer to a question nobody asks", fn)
	}
}

// noticeEntryPointCall reports whether n is a call to one of the mechanism's site-taking entry
// points, and its arguments. Both spellings are matched — the package function and the method — so
// adding an entry point is a table edit rather than a second walk.
func noticeEntryPointCall(n ast.Node) (string, []ast.Expr, bool) {
	call, isCall := n.(*ast.CallExpr)
	if !isCall {
		return "", nil, false
	}
	var name string
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		name = fn.Name
	case *ast.SelectorExpr:
		name = fn.Sel.Name
	default:
		return "", nil, false
	}
	if _, isEntry := noticeEntryPoints[name]; !isEntry {
		return "", nil, false
	}
	return name, call.Args, true
}

// noticesTo builds an UNBOUNDED diagnostic channel on w, for a leg a test assembles by hand.
//
// It lives HERE rather than beside noticeWriter, which is what makes it test-only by construction:
// a production leg reaching for it would be declared metered and charge nothing — the one
// disagreement the runtime lookup cannot catch, since the lookup governs which bucket a line
// charges and this hands it no bucket at all. It used to ship in the package under an AST guard
// that said the same thing more weakly; file placement is the compiler saying it.
func noticesTo(w io.Writer) noticeWriter { return noticeWriter{out: w} }

// noticeSiteConstants collects notice.go's `noticeSite` constants as name -> value, so the walk can
// resolve the identifier a call passes to the key the declaration table is read by. Without it the
// walk sees an identifier and the table sees a string, and nothing checks that they meet.
//
// Through the shared const walk rather than a second copy of it: a copy re-derived the "a const
// block declares its type once and later specs inherit it" rule and got it wrong, so a site
// constant continuing an existing block would drop out of this map and the walk would then reject a
// perfectly valid constant as undeclared.
func noticeSiteConstants(t *testing.T) map[string]noticeSite {
	t.Helper()
	out := map[string]noticeSite{}
	for name, value := range declaredStringConstants(t, "noticeSite") {
		out[name] = noticeSite(value)
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
func qualifiedFuncName(fn *ast.FuncDecl) noticeFunc {
	if fn.Recv != nil && len(fn.Recv.List) > 0 {
		return noticeFunc(exprString(fn.Recv.List[0].Type) + "." + fn.Name.Name)
	}
	return noticeFunc(fn.Name.Name)
}

// exprString renders a receiver type as Go source: `*T`, `T`, or `*T[K]` for a generic one.
//
// go/types rather than a hand-rolled switch: the hand-rolled one answered "?" for anything that was
// not an Ident or a StarExpr, so every method on a GENERIC receiver — this package now has
// tieredBuckets[K] — keyed as `*?.name` and collided with every other generic type's same-named
// method. That is the silent inheritance the qualified key exists to make unrepresentable.
func exprString(e ast.Expr) string { return types.ExprString(e) }

func noticeBoundName(b noticeBound) string {
	switch b {
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
