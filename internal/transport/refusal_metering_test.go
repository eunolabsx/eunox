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
	"slices"
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
}{
	"admitRefusalRecord":   {categoryArg: 2, implements: meteringMetered},
	"recordRefusal":        {categoryArg: 4, implements: meteringMetered},
	"recordPreSessionDeny": {categoryArg: 2, implements: meteringMetered},
	"unmeteredRecorder":    {categoryArg: 1, implements: meteringExempt},
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
	// Every category CONSTANT must be declared. Checked against the constants themselves, so a
	// new one that is never declared is caught rather than silently inheriting the unknown bucket.
	for _, cat := range []refusalCategory{
		catOrigin, catJWT, catAuth, catControl, catLoopback, catBody, catContentType,
		catSaturation, catKill, catAudience, catRevision, catUnroutable, catSmuggled,
	} {
		_, declared := refusalDeclarations[cat]
		assert.True(t, declared, "refusal category constant %q has no entry in refusalDeclarations", cat)
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

// TestRefusalMetering_CallSitesAgreeWithTheDeclarations is the walk the issue asked for: every
// site that resolves a refusal's recorder names its category, and the function it calls must
// implement the disposition that category declares.
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
				cat, ok := categoryConstant(arg)
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

// TestRefusalMetering_StdioChargesOnlyWhatItDeclares holds the transport's charged set to the one
// it declares, which is what makes building buckets for that set alone safe: a category outside it
// would fall to the shared `unknown` bucket, bounded but not its own.
func TestRefusalMetering_StdioChargesOnlyWhatItDeclares(t *testing.T) {
	t.Parallel()
	charged := map[refusalCategory]bool{}
	for _, src := range packageSources(t) {
		if src.name != "stdio.go" {
			continue
		}
		ast.Inspect(src.file, func(n ast.Node) bool {
			call, isCall := n.(*ast.CallExpr)
			if !isCall {
				return true
			}
			fn, isIdent := call.Fun.(*ast.Ident)
			if !isIdent || fn.Name != "admitRefusalRecord" || len(call.Args) < 3 {
				return true
			}
			if cat, ok := categoryConstant(call.Args[2]); ok {
				charged[cat] = true
			}
			return true
		})
	}
	require.NotEmpty(t, charged, "no metered refusal found in stdio.go; this guard would pass vacuously")
	for cat := range charged {
		assert.Contains(t, stdioRefusalCategories, cat,
			"stdio.go charges category %q, which stdioRefusalCategories does not declare — its limiter builds no bucket for it, so the refusal falls to the shared unknown bucket", cat)
	}
	for _, cat := range stdioRefusalCategories {
		assert.True(t, charged[cat], "stdioRefusalCategories declares %q but stdio.go charges no such refusal; the bucket is retained for nothing", cat)
	}
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

// categoryConstant resolves a catXxx identifier to its value, matching by name against the
// declared constants. Returns false for anything that is not one of them.
func categoryConstant(e ast.Expr) (refusalCategory, bool) {
	ident, ok := e.(*ast.Ident)
	if !ok {
		return "", false
	}
	byName := map[string]refusalCategory{
		"catOrigin": catOrigin, "catJWT": catJWT, "catAuth": catAuth, "catControl": catControl,
		"catLoopback": catLoopback, "catBody": catBody, "catContentType": catContentType,
		"catSaturation": catSaturation, "catKill": catKill, "catAudience": catAudience,
		"catRevision": catRevision, "catUnroutable": catUnroutable, "catSmuggled": catSmuggled,
	}
	cat, known := byName[ident.Name]
	return cat, known
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
