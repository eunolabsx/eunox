// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The metering disposition as a DECLARATION rather than prose: every refusal category answers
// metered-or-exempt-with-a-reason, and the recorder call sites are walked so a refusal cannot ship
// without an answer, or with an answer contradicting the one it declares.
//
// It was prose, and the survey behind it was incomplete — the routing refusal's exemption was
// argued in a package comment while the smuggling refusal beside it, equally cheap and on the same
// goroutine, had no recorded judgment either way.

package transport

import (
	"go/ast"
	"go/token"
	"slices"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// meteringCallSites maps each function that RESOLVES a refusal's recorder to the argument
// position naming the category, and to the metering that function implements. A call whose
// category's declaration disagrees with its function is the contradiction this closes.
var meteringCallSites = map[string]struct {
	categoryArg int
	implements  refusalMetering
	// readsDeclaration marks a resolver that applies whichever disposition the category DECLARES
	// (refusalRecorders.forCategory) rather than a fixed one. Such a site cannot contradict a
	// declaration — that is the whole point of it — so only the naming half is checked and
	// implements is ignored. It is the shape that closed the gap the retired unmeteredRecorder
	// marker structurally could not: a leg that resolved one recorder for every arm handed the
	// metered kill recorder to two arms whose categories declare themselves exempt, and a no-op
	// marker that returns what it is handed has no way to notice — an auditRecorder carries no
	// provenance. With the routing refusal's request framing resolving through forCategory too,
	// nothing is left for the marker to mark.
	readsDeclaration bool
}{
	"admitRefusalRecord":   {categoryArg: 2, implements: meteringMetered},
	"recordRefusal":        {categoryArg: 4, implements: meteringMetered},
	"recordPreSessionDeny": {categoryArg: 2, implements: meteringMetered},
	"forCategory":          {categoryArg: 0, readsDeclaration: true},
}

// TestRefusalMetering_EveryCategoryDeclaresOne is the build-time half: an entry missing its
// disposition, or an exemption with no reason, fails here rather than shipping as a silent
// default. The zero value is deliberately "undeclared" so neither answer can be inherited.
func TestRefusalMetering_EveryCategoryDeclaresOne(t *testing.T) {
	t.Parallel()
	for cat, decl := range refusalDeclarations {
		switch decl.metering {
		case meteringUndeclared:
			t.Errorf("refusal category %q declares no metering disposition; metered and deliberately-exempt are both answers, and no entry may inherit either", cat)
		case meteringExempt:
			assert.NotEmpty(t, decl.why, "category %q is exempt with no reason; the reason IS the exemption, and one without it is indistinguishable from an oversight", cat)
		case meteringMetered:
			assert.Empty(t, decl.why, "category %q is metered but carries an exemption reason; a metered category needs none, and one here reads as a disagreement with its own disposition", cat)
		}
	}
	// Every category CONSTANT must be declared. Read off the source rather than hand-listed here,
	// so a new constant that is never declared is caught by the guard instead of by whoever
	// remembers to extend a second list beside the first.
	for name, cat := range declaredCategoryConstants(t) {
		_, declared := refusalDeclarations[cat]
		assert.True(t, declared, "refusal category constant %s (%q) has no entry in refusalDeclarations", name, cat)
	}
}

// TestRefusalMetering_DerivedListIsTheMeteredSubset pins that the bucket table (and the divisor
// for every category's share of the aggregate budget) follows the declaration, so declaring a
// category EXEMPT cannot silently shrink the metered ones' shares.
func TestRefusalMetering_DerivedListIsTheMeteredSubset(t *testing.T) {
	t.Parallel()
	for _, cat := range refusalCategories {
		assert.Equal(t, meteringMetered, refusalDeclarations[cat].metering,
			"category %q charges a bucket but is not declared metered", cat)
	}
	for cat, decl := range refusalDeclarations {
		if decl.metering == meteringExempt {
			assert.NotContains(t, refusalCategories, cat,
				"category %q is declared exempt yet holds a bucket; it would divide the aggregate budget by a share nothing spends", cat)
		}
	}
	assert.True(t, slices.IsSorted(refusalCategories),
		"the derived list must be sorted: it is built by ranging a map, and an unsorted one makes the bucket table and every test reading it order-dependent")
}

// TestRefusalMetering_CallSitesAgreeWithTheDeclarations walks every site that resolves a refusal's
// recorder: each names its category, and the function it calls must implement the disposition that
// category declares.
//
// It also closes the two ways the old shape passed vacuously — a category declared with no call
// site, and a limiter appearing at a site declared exempt.
func TestRefusalMetering_CallSitesAgreeWithTheDeclarations(t *testing.T) {
	t.Parallel()
	sited := map[refusalCategory]bool{}
	checked := 0
	for _, src := range packageSources(t) {
		name := src.name
		for _, decl := range src.file.Decls {
			fnDecl, isFunc := decl.(*ast.FuncDecl)
			if !isFunc || fnDecl.Body == nil {
				continue
			}
			// A helper that THREADS its own category parameter (recordPreSessionDeny into
			// recordRefusal, and recordRefusal into the limiter) is not a refusal site — its
			// callers are, and they are walked on their own. Skipping by "the argument is this
			// function's parameter" rather than by name keeps an actual computed category, which
			// nothing may pass, an error.
			params := parameterNames(fnDecl)
			ast.Inspect(fnDecl.Body, func(n ast.Node) bool {
				call, isCall := n.(*ast.CallExpr)
				if !isCall {
					return true
				}
				fn, isIdent := call.Fun.(*ast.Ident)
				if !isIdent {
					// A method call (p.recordPreSessionDeny, p.recordRefusal) reaches here as a
					// selector; the site's own function name is the last segment.
					sel, isSel := call.Fun.(*ast.SelectorExpr)
					if !isSel {
						return true
					}
					fn = sel.Sel
				}
				site, tracked := meteringCallSites[fn.Name]
				if !tracked || len(call.Args) <= site.categoryArg {
					return true
				}
				arg := call.Args[site.categoryArg]
				if ident, isIdent := arg.(*ast.Ident); isIdent && params[ident.Name] {
					return true
				}
				cat, ok := categoryConstant(t, arg)
				if !ok {
					t.Errorf("%s: %s is passed a category this walk cannot resolve (%s); pass one of the catXxx constants so its declared disposition can be checked",
						name, fn.Name, exprText(src.fset, arg))
					return true
				}
				checked++
				sited[cat] = true
				declared, isDeclared := refusalDeclarations[cat]
				if !isDeclared {
					t.Errorf("%s: %s names category %q, which declares no metering disposition", name, fn.Name, cat)
					return true
				}
				if site.readsDeclaration {
					// It applies whatever the category declares, so there is no disposition to
					// disagree with — only the naming, checked above.
					return true
				}
				if declared.metering != site.implements {
					t.Errorf("%s: %s implements %s metering but category %q declares the opposite. "+
						"A refusal's disposition is a decision on the record, not a property of which helper a call site reached for.",
						name, fn.Name, meteringName(site.implements), cat)
				}
				return true
			})
		}
	}
	require.Positive(t, checked, "no refusal recorder call found in any non-test file; this guard would pass vacuously")
	for cat, decl := range refusalDeclarations {
		// catSaturation's site is recordSessionCapDeny, which hardcodes the category rather than
		// taking one; recordResourceExhausted charges its pool's own gate instead of a bucket.
		if cat == catSaturation {
			continue
		}
		assert.True(t, sited[cat], "category %q is declared %s but no call site names it; a declaration nothing reaches is an answer to a question nobody asks", cat, meteringName(decl.metering))
	}
}

// TestRefusalMetering_StdioLimiterHasABucketPerDeclaredCategory is what makes building buckets for
// a SUBSET safe: a category a transport charges but does not declare falls to the shared `unknown`
// bucket — bounded, but at the floor rate and shared with every other unregistered category, so
// identical bytes would be metered differently on the two transports.
//
// Asserted on the limiter rather than by scanning stdio.go for call sites, which was the earlier
// shape and had a false premise: "which categories does stdio charge" is not answerable from one
// FILENAME. catDisplaced is charged through trackServerRequest, a shared helper both transports
// hand their own limiter to, and lives in neither transport's file.
func TestRefusalMetering_StdioLimiterHasABucketPerDeclaredCategory(t *testing.T) {
	t.Parallel()
	lim := newRefusalRecordLimiterFor(stdioRefusalCategories...)
	require.NotEmpty(t, stdioRefusalCategories)
	for _, cat := range stdioRefusalCategories {
		assert.Equal(t, meteringMetered, refusalDeclarations[cat].metering,
			"stdio declares it charges %q, which is not a metered category", cat)
		assert.NotEqual(t, lim.unknown, lim.bucket(cat),
			"stdio charges %q but its limiter builds no bucket for it", cat)
	}
	// The one category that reaches stdio through a SHARED helper rather than its own file, which
	// is why the filename-scoped predecessor of this test could not see it.
	assert.Contains(t, stdioRefusalCategories, catDisplaced,
		"trackServerRequest charges catDisplaced with whichever limiter its caller passes, and stdio passes its own")
}

// TestRefusalMetering_SizedLimiterKeepsTheAggregateShare pins that building buckets for a SUBSET
// does not hand that transport the whole budget: a per-category share is a share of the aggregate,
// not of the categories one transport happens to charge.
func TestRefusalMetering_SizedLimiterKeepsTheAggregateShare(t *testing.T) {
	t.Parallel()
	one := newRefusalRecordLimiterFor(catRevision)
	assert.Len(t, one.buckets, 1, "a transport charging one category must not retain buckets it can never spend")
	assert.Equal(t, perCategoryDenyRate, one.bucket(catRevision).ratePerSec,
		"a subset limiter's bucket must hold the same share as the full table's, or a transport charging fewer categories would get a larger budget per category")
	assert.Equal(t, perCategoryDenyBurst, one.bucket(catRevision).burst)
	// An unregistered category is bounded rather than unbounded — the safe direction for the
	// fallback the guards above keep unreachable.
	assert.Equal(t, one.unknown, one.bucket(catAuth))
}

// categoryConstant resolves a catXxx identifier to its value. The name→value table is DERIVED
// from the package's own const declarations rather than hand-listed: a hand-listed one silently
// stops resolving the day a category is added, which turns this guard's "cannot resolve" arm from
// a real complaint into noise about the guard's own staleness.
func categoryConstant(t *testing.T, e ast.Expr) (refusalCategory, bool) {
	ident, ok := e.(*ast.Ident)
	if !ok {
		return "", false
	}
	cat, known := declaredCategoryConstants(t)[ident.Name]
	return cat, known
}

// declaredCategoryConstants reads every `catXxx refusalCategory = "..."` declaration out of the
// package sources.
func declaredCategoryConstants(t *testing.T) map[string]refusalCategory {
	t.Helper()
	out := map[string]refusalCategory{}
	for name, value := range declaredStringConstants(t, "refusalCategory") {
		out[name] = refusalCategory(value)
	}
	require.NotEmpty(t, out, "no refusalCategory constants found; this guard would pass vacuously")
	return out
}

// declaredStringConstants reads every `name typeName = "..."` declaration out of the package's
// non-test sources. ONE scanner for the two guards that each keep a closed vocabulary honest: two
// copies meant a fix to one — handling a multi-name spec, say, which both currently skip — left the
// other blind, and the blind one would be whichever guard nobody was editing.
func declaredStringConstants(t *testing.T, typeName string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, src := range packageSources(t) {
		for _, decl := range src.file.Decls {
			gen, isGen := decl.(*ast.GenDecl)
			if !isGen || gen.Tok != token.CONST {
				continue
			}
			// A const block declares its type once, on the first spec; later specs inherit it.
			declared := ""
			for _, spec := range gen.Specs {
				vs, isValue := spec.(*ast.ValueSpec)
				if !isValue {
					continue
				}
				if id, isIdent := vs.Type.(*ast.Ident); isIdent {
					declared = id.Name
				}
				if declared != typeName || len(vs.Names) != 1 || len(vs.Values) != 1 {
					continue
				}
				lit, isLit := vs.Values[0].(*ast.BasicLit)
				if !isLit || lit.Kind != token.STRING {
					continue
				}
				value, err := strconv.Unquote(lit.Value)
				require.NoError(t, err)
				out[vs.Names[0].Name] = value
			}
		}
	}
	return out
}

// parameterNames returns the names bound by fn's parameter list, so the walk can tell a call that
// THREADS a category through from one that names it.
func parameterNames(fn *ast.FuncDecl) map[string]bool {
	names := map[string]bool{}
	if fn.Type.Params == nil {
		return names
	}
	for _, field := range fn.Type.Params.List {
		for _, ident := range field.Names {
			names[ident.Name] = true
		}
	}
	return names
}

func meteringName(m refusalMetering) string {
	switch m {
	case meteringMetered:
		return "metered"
	case meteringExempt:
		return "exempt"
	default:
		return "undeclared"
	}
}
