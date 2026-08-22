// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The residual the notice MECHANISM cannot answer for itself.
//
// admitNotice now reads a site's declaration at write time (see notice.go), so "declared metered" and
// "charges that class's bucket" are one fact — the analogue of forCategory on the record half. Two
// questions remain outside a runtime reader, and they are what this walk is for:
//
//   - a line written through a shape that never reaches the mechanism at all (a bare fmt.Fprintf), which
//     the mechanism cannot see because it is never called;
//   - a declaration nothing reaches, which is an answer to a question nobody asks.
//
// Both were the whole guard before the mechanism existed, and the notice budget's "how many
// diagnostic syscalls can a peer drive" claim rests entirely on the first one holding.

package transport

import (
	"go/ast"
	"go/token"
	"go/types"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// noticeWriters maps a package qualifier to the calls through it that put a diagnostic line on this
// package's error writer. noticeLine.writef is deliberately absent: it IS the mechanism, so a call to it is
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
	// NOT `Contains(noticeClasses, class)`: noticeClasses is DERIVED from this map's own values, so
	// that assertion holds for any content whatsoever — including the entry it claims to catch.
	// Naming a real class is the check, and it is what keeps an unclassified value from silently
	// charging the floor-rate fallback.
	for site, decl := range meteredNotices {
		assert.Greater(t, decl.class, classUnclassified,
			"site %q is metered but names no notice class; an unclassified one charges the floor-rate fallback rather than its own share, and registering it as a bucket key would move every genuinely undeclared site off that fallback too", site)
		// Through label()'s own default arm rather than a list of the class names, which would be
		// the second hand-typed list this file's header argues against: every out-of-range value
		// labels itself "unclassified", so one comparison covers both ways a class can be undeclared.
		assert.NotEqual(t, classUnclassified.label(), decl.class.label(),
			"site %q names a class outside the declared set, so its lines would roll up under the label an unclassified line carries", site)
	}
	// EVERY metered site answers the floor question, not only those of a class that already holds a
	// protected member. That conditional gate was the last opt-in list here: a class with no
	// protected member asked nothing of its sites, so ten of the fifteen recorded no judgment and
	// the first protection added to such a class would have moved every class-mate onto the
	// flooding side silently.
	protected, protectedClasses := 0, map[noticeClass]bool{}
	for _, decl := range meteredNotices {
		if decl.floor == floorSiteProtected {
			protected++
			protectedClasses[decl.class] = true
		}
	}
	for site, decl := range meteredNotices {
		assert.NotEqual(t, floorUndeclared, decl.floor,
			"site %q declares no floor disposition; undeclared means it is the one a class-mate's flood elides, which is a decision rather than an oversight", site)
		// The MIRROR of the collapse reason's rule, and the reason the two are separate fields: here
		// the reason IS the elision, so it is required exactly where the site is the one elided.
		assert.Equal(t, decl.floor == floorElidable, decl.floorWhy != "",
			"site %q must either be the one a class-mate's flood may elide and say WHY, or state no floor reason at all", site)
		// Checked against the table's own content, which is what makes floorClassUnprotected a
		// decision rather than a way of declining to answer: protecting a first site in some class
		// fails the build for every one of its class-mates instead of silently demoting them.
		switch decl.floor {
		case floorElidable:
			assert.True(t, protectedClasses[decl.class],
				"site %q declares itself elidable in class %q, which holds no protected member — there is nothing for it to be elided in favour of", site, decl.class.label())
		case floorClassUnprotected:
			assert.False(t, protectedClasses[decl.class],
				"site %q claims class %q holds no protected member, but one of its class-mates reserves a site floor; this site must say which side of that protection it is on", site, decl.class.label())
		}
	}
	assert.Len(t, floorProtectedSites, protected,
		"the derived reserve and the declarations must describe the same set; a site declared protected with no slot falls back to its class floor, which a class-mate's flood is exactly what spends")

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
// travels in. ONE, now that every metered site takes its admission before building its arguments:
// the eager wrapper that took the format string is gone, so there is no second spelling for a new
// site to reach for and no per-site judgment about which to use.
var noticeEntryPoints = map[string]int{
	"admitNotice": 0,
}

// noticeMechanism is the set of functions that IMPLEMENT the bounded channel rather than write
// through it. Their fmt calls are the mechanism's own and need no declaration of their own.
var noticeMechanism = map[noticeFunc]bool{
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
					t.Errorf("%s:%d: %s writes a diagnostic line with no entry in unmeteredNotices; declare how it is bounded (its record's admission verdict, a one-shot latch, or exempt with a reason) — or meter it, which means taking its admission through admitNotice and declaring its class in meteredNotices",
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

// noticeLatchEntryPoint is the one-shot half of the mechanism, named distinctively so this walk can
// see it: noticeLatch.admitOnce, which every noticeOnce site takes its line through.
const noticeLatchEntryPoint = "admitOnce"

// TestNoticeBounding_EveryOneShotSiteUsesTheLatch is what turns noticeOnce from a LINT into a
// mechanism, in both directions.
//
// It shipped as a declaration recording that a site was one-shot while each site implemented that
// itself — an atomic.Bool at one, a counter compared against 1 at the other two — which is exactly
// the shape the metered half's collapse had before it became a disposition admitNotice reads. Three
// implementations of one idea is three places for the re-arm semantics to differ, and a declaration
// nothing enforces is a claim about code somewhere else.
//
// Two-way on purpose. "Declared one-shot but hand-rolls its own latch" is the drift that already
// happened; "latches without declaring it" is the same drift starting again from the other end,
// where the walk's table stops describing the package's diagnostic surface.
func TestNoticeBounding_EveryOneShotSiteUsesTheLatch(t *testing.T) {
	t.Parallel()
	latching := map[noticeFunc]bool{}
	for _, src := range packageSources(t) {
		for _, decl := range src.file.Decls {
			fnDecl, isFunc := decl.(*ast.FuncDecl)
			if !isFunc || fnDecl.Body == nil {
				continue
			}
			qualified := qualifiedFuncName(fnDecl)
			ast.Inspect(fnDecl.Body, func(n ast.Node) bool {
				call, isCall := n.(*ast.CallExpr)
				if isCall && callName(call) == noticeLatchEntryPoint {
					latching[qualified] = true
				}
				return true
			})
		}
	}
	require.NotEmpty(t, latching, "no %s call was found in any non-test file; this guard would pass vacuously", noticeLatchEntryPoint)
	for fn := range latching {
		assert.Equal(t, noticeOnce, unmeteredNotices[fn].bound,
			"%s claims the one-shot latch but is not declared noticeOnce; the declaration is how a reader learns what bounds this line, and the mechanism is how it is actually bounded — neither stands in for the other", fn)
	}
	for fn, decl := range unmeteredNotices {
		if decl.bound != noticeOnce {
			continue
		}
		assert.True(t, latching[fn],
			"%s is declared noticeOnce but reaches no %s; a hand-rolled latch is a fourth implementation of one idea, and the declaration would be describing it rather than enforcing it", fn, noticeLatchEntryPoint)
	}
}

// reserveClaimEntryPoint is the reserve primitive itself: reserveSlot.claim, the one call that
// spends a slot. Matched by name, which is what an AST walk can see without type information — and
// the name is distinctive enough in this package that a collision fails this guard loudly rather
// than passing it silently.
const reserveClaimEntryPoint = "claim"

// reserveClaimants is the CLOSED set of functions that may claim a reserveSlot, each stating the
// direction it uses the primitive in. Three, and they are three different questions asked of one
// re-arming slot: never re-arm at all (a latch), fold every occurrence inside the window (a
// source-side collapse), deliver one line when the tier that would have carried it has nothing left
// (a floor).
//
// It lives here rather than beside the primitive because it is a statement about SOURCE SHAPE —
// which functions IMPLEMENT the mechanism — the same kind of statement noticeMechanism and
// noticeEntryPoints make, and not the kind unmeteredNotices makes about production lines.
//
// Deliberately not narrowed to the diagnostic half, though the drift it is here to catch is a
// diagnostic one: the refusal RECORDS' floor is the same primitive, and a fourth hand-rolled claim
// there is the same three-latches state one axis over. Closing the primitive outright costs nothing
// extra and needs no per-site judgment about whether a given claim is "beside a diagnostic", which
// is a question this walk could not answer from the callee anyway.
var reserveClaimants = map[noticeFunc]string{
	"*noticeLatch.admitOnce":           "the one-shot direction: an interval that never elapses, so every occurrence after the first measures a zero elapsed time and is refused on one atomic load",
	"noticeWriter.admitNotice":         "the collapse window, claimed ABOVE the class bucket so an occurrence it folds spends no token",
	"*tieredBuckets[K].admitWithFloor": "the floor, in the opposite direction from the other two: the guaranteed arrival when the tier that would have carried the write has nothing left",
}

// TestNoticeBounding_EveryReserveClaimIsDeclared closes the reserve primitive to its declared
// claimants, in both directions.
//
// This is the completeness gate the WINDOW half has instead of a vocabulary. A window is
// metered-only: admitNotice reads the collapse disposition and an unmetered site never reaches
// admitNotice, so a site wanting "one line per interval, and no class bucket" has no declaration to
// write — and the shape it reaches for instead is a reserveSlot of its own beside its Fprintf.
// That is exactly the state noticeLatch removed one axis over, where three sites each implemented
// one idea: nothing recorded that the line was windowed, nothing stated the reason on either side,
// and nothing failed when the next site forgot.
//
// Giving noticeDeclaration a collapse field and an interval with zero entries using it was the
// alternative, and it is rejected for the reason a staging grammar string is: a vocabulary whose
// only reader is a test is a mechanism nothing keeps honest, and what it compiles to is the
// reserveSlot field it was meant to replace. So the gate goes on the PRIMITIVE rather than on a
// declaration nobody writes. The first site that wants an unmetered window fails here, and the
// failure names the remedy — extend the declaration, do not claim a fourth slot — which is what
// makes the deferral a routed decision rather than an omission that expires quietly.
//
// Two-way for the reason the latch guard is: "claims without being declared" is the drift starting,
// and "declared but claims nothing" is this table quietly ceasing to describe the mechanism.
func TestNoticeBounding_EveryReserveClaimIsDeclared(t *testing.T) {
	t.Parallel()
	claiming, claims := map[noticeFunc]bool{}, 0
	for _, src := range packageSources(t) {
		for _, decl := range src.file.Decls {
			fnDecl, isFunc := decl.(*ast.FuncDecl)
			if !isFunc || fnDecl.Body == nil {
				continue
			}
			qualified := qualifiedFuncName(fnDecl)
			ast.Inspect(fnDecl.Body, func(n ast.Node) bool {
				call, isCall := n.(*ast.CallExpr)
				if !isCall || callName(call) != reserveClaimEntryPoint {
					return true
				}
				claims++
				claiming[qualified] = true
				if _, isDeclared := reserveClaimants[qualified]; !isDeclared {
					t.Errorf("%s:%d: %s claims a reserve slot but is not one of its declared claimants; a diagnostic that wants a window takes it through its declaration in meteredNotices — extend noticeDeclaration with a collapse disposition and its interval, and lift the window above admitNotice's metering branch, rather than holding a slot of its own where nothing records that the line is windowed, nothing states the reason, and nothing fails when the next site forgets",
						src.name, src.fset.Position(call.Pos()).Line, qualified)
				}
				return true
			})
		}
	}
	require.Positive(t, claims, "no %s call was found in any non-test file; this guard would pass vacuously", reserveClaimEntryPoint)
	for fn, why := range reserveClaimants {
		assert.True(t, claiming[fn],
			"%s is declared a reserve claimant but claims nothing; a declaration nothing reaches stops describing the mechanism it was written about", fn)
		assert.NotEmpty(t, why,
			"%s claims the reserve primitive with no stated direction; the three claimants ask three different questions of one slot, and which one this is cannot be read off the call", fn)
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
	// Through the package's shared callName rather than a third copy of the ident-or-selector
	// switch: it already serves two other walks, and a fix to how a callee is named should reach
	// all of them.
	name := callName(call)
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

// TestNoticeBounding_EveryAdmissionIsWritten is the source guard over admitNotice's return, the
// same shape the tracker's disposal obligation carries.
//
// admitNotice does not peek: it spends the token AND takes the bucket's accumulated suppression
// tally into the line it hands back, so a caller that drops that line destroys a count of what an
// operator did not see, and one that writes it twice buys N write syscalls with one token. Go
// requires neither, and the runtime cannot report either — the line is a value like any other. So
// the shape is required here: the admission is an `if` initializer, its body writes the bound line
// exactly once and unconditionally, and there is no else.
//
// Preparatory statements inside the body are allowed on purpose. Building an expensive argument
// after the admission is the entire point of the escape hatch, and a rule that permitted only the
// bare writef would push those arguments back above the gate.
func TestNoticeBounding_EveryAdmissionIsWritten(t *testing.T) {
	t.Parallel()
	guarded, admissions := map[token.Pos]bool{}, 0
	for _, src := range packageSources(t) {
		ast.Inspect(src.file, func(n ast.Node) bool {
			if _, _, isEntry := noticeEntryPointCall(n); isEntry && callName(n.(*ast.CallExpr)) == "admitNotice" {
				admissions++
			}
			stmt, isIf := n.(*ast.IfStmt)
			if !isIf {
				return true
			}
			line, call, isAdmission := admissionIf(stmt)
			if !isAdmission {
				return true
			}
			guarded[call.Pos()] = true
			at := src.fset.Position(call.Pos())
			assert.Nil(t, stmt.Else,
				"%s:%d: an admitted notice line must be written on the only path out of its gate; an else arm is a path that spent the token and the tally and wrote nothing", src.name, at.Line)
			total, unconditional := writefCalls(stmt.Body, line)
			assert.Equal(t, 1, total,
				"%s:%d: the admitted line must be written exactly once — %d writef calls buy N write syscalls with one token, and 0 destroys the suppression tally admitNotice just harvested", src.name, at.Line, total)
			assert.Equal(t, 1, unconditional,
				"%s:%d: the write must be unconditional inside the gate; a writef under a further branch or a loop is the same lost-or-repeated tally one level in", src.name, at.Line)
			return true
		})
	}
	require.Positive(t, admissions, "no admitNotice call was found; this guard would pass vacuously")
	for _, src := range packageSources(t) {
		ast.Inspect(src.file, func(n ast.Node) bool {
			call, isCall := n.(*ast.CallExpr)
			if !isCall || callName(call) != "admitNotice" || guarded[call.Pos()] {
				return true
			}
			t.Errorf("%s:%d: admitNotice's result must be taken by `if line, ok := ...; ok { line.writef(...) }`; any other shape can spend a token and a suppression tally without writing the line they were spent on",
				src.name, src.fset.Position(call.Pos()).Line)
			return true
		})
	}
}

// admissionIf matches `if <line>, <ok> := <expr>.admitNotice(<site>); <ok> { ... }`, returning the
// identifier the line was bound to and the call itself.
func admissionIf(stmt *ast.IfStmt) (line string, call *ast.CallExpr, ok bool) {
	assign, isAssign := stmt.Init.(*ast.AssignStmt)
	if !isAssign || len(assign.Lhs) != 2 || len(assign.Rhs) != 1 {
		return "", nil, false
	}
	rhs, isCall := assign.Rhs[0].(*ast.CallExpr)
	if !isCall || callName(rhs) != "admitNotice" {
		return "", nil, false
	}
	lineIdent, lineIsIdent := assign.Lhs[0].(*ast.Ident)
	okIdent, okIsIdent := assign.Lhs[1].(*ast.Ident)
	cond, condIsIdent := stmt.Cond.(*ast.Ident)
	if !lineIsIdent || !okIsIdent || !condIsIdent || cond.Name != okIdent.Name {
		return "", nil, false
	}
	return lineIdent.Name, rhs, true
}

// writefCalls counts calls to line.writef anywhere in body, and separately those that are
// statements of body ITSELF — the difference being a write the gate does not guarantee.
func writefCalls(body *ast.BlockStmt, line string) (total, unconditional int) {
	isWrite := func(n ast.Node) bool {
		call, isCall := n.(*ast.CallExpr)
		if !isCall {
			return false
		}
		sel, isSel := call.Fun.(*ast.SelectorExpr)
		if !isSel || sel.Sel.Name != "writef" {
			return false
		}
		recv, isIdent := sel.X.(*ast.Ident)
		return isIdent && recv.Name == line
	}
	ast.Inspect(body, func(n ast.Node) bool {
		if isWrite(n) {
			total++
		}
		return true
	})
	for _, stmt := range body.List {
		if expr, isExpr := stmt.(*ast.ExprStmt); isExpr && isWrite(expr.X) {
			unconditional++
		}
	}
	return total, unconditional
}
