// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The health seam's CROSS-IMPLEMENTATION contract: what must hold of every type that answers
// HealthStatus, whichever package owns it. Each subsystem's own behavior — which breaker states
// are impeded, what a maintenance stall does and does not deny, what a Redis outage latches — is
// pinned in that subsystem's package, which states it more precisely than a table polling through
// the interface can. Add a behavior case there; add one here only for a property that must hold
// of every implementation and that no single package can state.
//
// The property is the seam's fail-safe direction: a reporter that reaches fold before the
// subsystem behind it has anything to report must never say green. That was PROSE on
// healthReporter, and the shipped implementations agreed with it because their authors made them
// agree — nothing checked, and until the rule was written down the two samples failed in OPPOSITE
// directions (capability.KeyFetchHealth{} reported an outage while audit.Health{} was a healthy
// sink with nothing wrong). A new reporter answering nil from its unfilled value compiles, folds,
// and reports a green readiness signal over a subsystem that has never spoken.
//
// The table is two-way against the SOURCES rather than a list to keep in step by hand: a walk over
// every package in this module finds each HealthStatus method and requires a row for it, and each
// row requires a method. That is what makes "every implementation" true of the assertion rather
// than of the intent — a hand-maintained list of three would have passed while the fourth
// implementation went unchecked, which is the same decay the rule already suffered as prose.

package transport

import (
	"go/ast"
	"io/fs"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// seamKind is how a consumer HOLDS a reporter, which is what decides the shape of its unfilled
// value and therefore which mechanism has to catch it.
type seamKind string

const (
	// seamSample: the consumer holds a COPY of a reading. Its unfilled value is the zero struct,
	// which no guard in fold can recognize — a value type is never a typed nil — so the verdict
	// has to be carried by the sample itself.
	seamSample seamKind = "sample"
	// seamLive: the consumer holds the subsystem. Its unfilled value is a nil pointer inside a
	// non-nil interface, which fold answers through capability.IsNilValue WITHOUT calling the
	// method — the only workable answer, since a live reporter dereferences its receiver and a
	// nil one panics on the endpoints an operator reaches for when something is already wrong.
	seamLive seamKind = "live"
)

// healthSeamImpl is one implementation of the seam under the conformance table.
type healthSeamImpl struct {
	// name is "<package>.<Type>", the spelling the source guard below derives from the receiver
	// of the HealthStatus method it finds.
	name string
	kind seamKind
	// unfilled is the value a consumer can hold before the subsystem behind it has anything to
	// report: the zero struct for a sample, the nil pointer for a live subsystem.
	//
	// A live subsystem's own zero value is deliberately NOT this field: &killswitch.InMemory{} is
	// a working in-process kill set with a genuinely healthy verdict, and a table demanding a
	// degradation from it would be asserting the opposite of that backend's documented contract.
	// What has nothing to report is the pointer that holds no backend at all.
	//
	// Typed as the seam so a row also carries the compile-time proof that this implementation
	// reaches fold through ONE interface, rather than through whichever pattern its author read
	// first — the JWT layer answers with a sample and the kill switch answers live, and both had
	// to be reachable from the same call.
	//
	// It is checked against name and kind before it is exercised: a row naming one implementation
	// while holding another's value satisfies both halves of the source guard below — the name is
	// what that guard compares — while the implementation it names is never folded at all, which
	// is the one way the table can be complete and still test nothing.
	unfilled healthReporter
	// unconstructible is the stated reason this package cannot hold that value, for an
	// implementation in a package it may not import: package main, or one importing this
	// transport. The row is still REQUIRED — the guard below is what makes that so — because the
	// alternative reading of an unimportable implementation is a test that fails with nothing its
	// author can do about it, which ends as an exclusion in the walk and takes every future
	// implementation in that package with it. What is given up is the fold assertion for that one
	// row, written down here rather than inferred from a missing value.
	unconstructible string
}

func healthSeamImpls() []healthSeamImpl {
	return []healthSeamImpl{
		{name: "audit.Health", kind: seamSample, unfilled: audit.Health{}},
		{name: "capability.KeyFetchHealth", kind: seamSample, unfilled: capability.KeyFetchHealth{}},
		{name: "killswitch.InMemory", kind: seamLive, unfilled: (*killswitch.InMemory)(nil)},
		{name: "killswitch.Redis", kind: seamLive, unfilled: (*killswitch.Redis)(nil)},
	}
}

// TestHealthSeam_UnfilledReporterNeverReportsGreen is the rule itself, over every implementation:
// what has nothing to report degrades.
//
// Asserted through fold rather than by calling HealthStatus, because fold is the only consumer and
// the two kinds are caught by different halves of it — a sample's own verdict, a live subsystem's
// nil guard. A row asserting only the method would pass for a live reporter that panics.
func TestHealthSeam_UnfilledReporterNeverReportsGreen(t *testing.T) {
	t.Parallel()
	for _, impl := range healthSeamImpls() {
		t.Run(impl.name, func(t *testing.T) {
			t.Parallel()
			// The INTERFACE, compared directly: testify's nil predicates unwrap a typed nil, which
			// is exactly what a live row is required to hold.
			if impl.unconstructible != "" {
				require.True(t, impl.unfilled == nil, "a row that states it cannot be constructed must not also hold a value")
				t.Skipf("not folded here: %s", impl.unconstructible)
			}
			require.False(t, impl.unfilled == nil, "a row must hold the value it is about, or state why it cannot")
			name, isPointer := healthSeamValueName(impl.unfilled)
			require.Equal(t, impl.name, name,
				"the row must hold the implementation it NAMES: the source guard compares names, so a copy-pasted value leaves the named implementation folded by nothing")
			require.Equal(t, impl.kind == seamLive, isPointer,
				"a live row holds the nil POINTER and a sample row the zero struct; the kind decides which half of fold is under test")

			snap := healthSnapshot{Status: statusOK}
			healthy := true
			require.NotPanics(t, func() { snap.fold(impl.unfilled, &healthy) },
				"a reporter with nothing to report must degrade, not take the scrape down with it")
			assert.False(t, healthy, "an unfilled reporter must never report green")
			assert.Equal(t, statusDegraded, snap.Status, "and must flip the summary with its own field")

			if impl.kind == seamSample {
				// The half fold cannot supply: a value type is never a typed nil, so a sample that
				// answers nil here is folded green and nothing downstream can tell.
				assert.Error(t, impl.unfilled.HealthStatus(),
					"a sample carries the fail-safe answer itself; fold has no nil to recognize")
			}
		})
	}
}

// healthSeamGuardedDirs is every package directory in this module — the whole module rather than
// the three packages that answer the seam today, which is the list that would have gone stale
// first.
//
// A package the walk never reaches contributes no implementations, so an UNDECLARED one there goes
// unchecked; that is the guard's one open edge, and it is why the walk is not narrowed. Its own
// gaps are loud rather than open: a parse error is fatal in packageSourcesIn, and a package holding
// a DECLARED implementation that went unparsed fails the table's equality.
func healthSeamGuardedDirs(t *testing.T) []string {
	t.Helper()
	const moduleRoot = "../.."
	seen := map[string]bool{}
	var dirs []string
	err := filepath.WalkDir(moduleRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Hidden trees, vendored code and testdata hold no implementation this seam folds,
			// and testdata in particular holds deliberately malformed sources.
			if name := d.Name(); path != moduleRoot && (strings.HasPrefix(name, ".") || name == "vendor" || name == "testdata") {
				return fs.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		if dir := filepath.Dir(path); !seen[dir] {
			seen[dir], dirs = true, append(dirs, dir)
		}
		return nil
	})
	require.NoError(t, err, "walking the module for health-seam implementations")
	require.NotEmpty(t, dirs, "the walk found no packages at all; the guard is asserting nothing")
	sort.Strings(dirs)
	return dirs
}

// TestHealthSeam_EveryImplementationIsInTheTable is the two-way half: the table names every
// HealthStatus method in the module, and every row names one.
//
// It also cross-checks the KIND against the receiver, which is not bookkeeping: the receiver form
// IS the distinction. A value receiver means the consumer can hold an unfilled copy that fold has
// no way to recognize, so that implementation owes the fail-safe verdict itself; a pointer
// receiver means fold's nil guard is what catches it. A new sample filed under "live" would
// otherwise be exempted from the one assertion it needs, by the row its own author wrote.
func TestHealthSeam_EveryImplementationIsInTheTable(t *testing.T) {
	t.Parallel()
	found := map[string]seamKind{}
	for _, dir := range healthSeamGuardedDirs(t) {
		for _, src := range packageSourcesIn(t, dir) {
			for _, decl := range src.file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				// A receiverless function of the same name and shape satisfies no interface, so it
				// is skipped rather than reported as a receiver this guard cannot name.
				if !ok || fn.Recv == nil || fn.Name.Name != "HealthStatus" || !isHealthVerdictSignature(fn.Type) {
					continue
				}
				name, ptr, ok := healthSeamReceiver(src.file.Name.Name, fn)
				require.Truef(t, ok, "%s: HealthStatus on a receiver this guard cannot name", src.fset.Position(fn.Pos()))
				kind := seamSample
				if ptr {
					kind = seamLive
				}
				found[name] = kind
			}
		}
	}

	declared := map[string]seamKind{}
	for _, impl := range healthSeamImpls() {
		declared[impl.name] = impl.kind
	}
	assert.Equal(t, found, declared,
		"every HealthStatus implementation needs a row (and every row an implementation): a reporter outside the table is one nothing holds to the seam's fail-safe rule")
}

// isHealthVerdictSignature reports whether fn's signature is the seam's: no parameters, one error
// result. A method sharing the name with a different shape does not satisfy healthReporter and is
// not what this guard is about.
func isHealthVerdictSignature(fn *ast.FuncType) bool {
	if fn.Params != nil && len(fn.Params.List) != 0 {
		return false
	}
	if fn.Results == nil || len(fn.Results.List) != 1 {
		return false
	}
	id, ok := fn.Results.List[0].Type.(*ast.Ident)
	return ok && id.Name == "error"
}

// healthSeamValueName names the dynamic type of a row's unfilled value in the guard's own spelling
// ("<package>.<Type>"), and reports whether the row holds a pointer. reflect's own rendering IS
// that spelling — the package's short name, the same one the receiver walk reads off the package
// clause — so the two sides cannot disagree about how a type is written down.
func healthSeamValueName(v healthReporter) (name string, isPointer bool) {
	t := reflect.TypeOf(v)
	if t.Kind() == reflect.Pointer {
		return t.Elem().String(), true
	}
	return t.String(), false
}

// healthSeamReceiver names fn's receiver as "<pkg>.<Type>" and reports whether it is a pointer.
// The generic spellings are unwrapped too, so a future parameterized reporter is named rather
// than skipped — silently skipping is how a walk comes to assert nothing.
func healthSeamReceiver(pkg string, fn *ast.FuncDecl) (name string, isPointer, ok bool) {
	if fn.Recv == nil || len(fn.Recv.List) != 1 {
		return "", false, false
	}
	expr := fn.Recv.List[0].Type
	if star, isStar := expr.(*ast.StarExpr); isStar {
		expr, isPointer = star.X, true
	}
	switch t := expr.(type) {
	case *ast.IndexExpr:
		expr = t.X
	case *ast.IndexListExpr:
		expr = t.X
	}
	id, isIdent := expr.(*ast.Ident)
	if !isIdent {
		return "", isPointer, false
	}
	return pkg + "." + id.Name, isPointer, true
}
