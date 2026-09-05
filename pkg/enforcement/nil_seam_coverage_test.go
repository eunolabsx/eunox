// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The guard behind this package's nil-argument rule: a decision point that PANICS produces no
// decision at all, so a crash is the fail-OPEN reading of "on any ambiguity, deny" — the process
// dies and whatever the operator's supervisor does next decides the traffic.
//
// The rule was enforced seam by seam and by hand, which is how four exported entry points came
// to be left off the list: the input builder handed to a third-party PolicyEvaluator, the
// selection seam an embedder pairs with EvaluateConditions, the obligation collector, and the
// antecedent recorder whose nil return the caller reads as "the marker was written". Two things
// are asserted here rather than one: that every seam ANSWERS (the table below drives each), and
// that the table is COMPLETE (the walk below enumerates the same seams off the sources, so the
// next one added fails the build instead of inheriting a hand-written list).

package enforcement_test

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
)

// nilSeamDisposition is how one seam refuses. The SHAPE legitimately differs — each caller
// consumes a different type, and there is no one value a map, a constraint pointer and an error
// can all be — but the CLASS must not: whatever the shape, no observing route may forward past
// it, which is what "refuses" means here.
type nilSeamDisposition string

const (
	// seamRefusesWithFault answers with a structured refusal carrying ErrCodeEnforcementError,
	// on whichever of its returns the caller already fails closed on.
	seamRefusesWithFault nilSeamDisposition = "fault"
	// seamRefusesWithNoMatch answers "nothing matched", the fail-closed answer this signature
	// already has: FindMatchingCapability's caller denies on a nil constraint.
	seamRefusesWithNoMatch nilSeamDisposition = "no-match"
	// seamDelegates takes no guard of its own because it reaches one before any dereference —
	// a handler entry point routed through the shared registry dispatch, or a wrapper over a
	// guarded seam. The walk still requires it to be DECLARED, so "it is covered elsewhere" is
	// a claim written down rather than one nobody re-checks.
	seamDelegates nilSeamDisposition = "delegates"
	// seamCallerSupplied is an adapter whose body is the caller's own function value. There is
	// nothing here to guard: the func the embedder registered is what runs.
	seamCallerSupplied nilSeamDisposition = "caller-supplied"
)

// nilSeamTable declares every exported func or method in this package taking a
// *capability.EnforceRequest or a *capability.Constraint, keyed "Receiver.Name" (bare name for a
// plain function), with how it answers a nil one. TestNilSeams_TableCoversEveryExportedSeam
// derives the same set from the sources and fails on any difference in either direction.
var nilSeamTable = map[string]nilSeamDisposition{
	"BuildRegoInput":                       seamRefusesWithFault,
	"EvaluateAllowedValues":                seamRefusesWithFault,
	"NonCommittingConditionVerdict":        seamRefusesWithFault,
	"Engine.NonCommittingConditionVerdict": seamRefusesWithFault,
	"Engine.ValidateAction":                seamRefusesWithFault,
	"Engine.EvaluateConditions":            seamRefusesWithFault,
	"Engine.CollectObligations":            seamRefusesWithFault,
	"Engine.RecordSessionCall":             seamRefusesWithFault,
	"Engine.PeekSessionLabels":             seamRefusesWithFault,
	"Engine.RecordSourceCall":              seamRefusesWithFault,
	"Engine.FindMatchingCapability":        seamRefusesWithNoMatch,
	// A nil constraint is "no capability matched", which only a route-level --audit forwards —
	// the posture question, deliberately separate from whether a REFUSAL is downgradable.
	"WillForwardDeny": seamDelegates,
	// Reached only through the registry's committing dispatch, which runs behind the shared
	// counter/anchor guards (counterSubjectGuards refuses a nil request for both).
	"maxCallsHandler.PrepareCommit":    seamDelegates,
	"blastRadiusHandler.PrepareCommit": seamDelegates,
	// Guards the receiver, the request AND the constraint before it reads any of them.
	"Engine.CeilingVerdictFor": seamRefusesWithNoMatch,
	// handlePolicy's only dereference of the request is BuildRegoInput, which refuses.
	"policyConditionHandler.Handle": seamDelegates,
	"ConditionHandlerFunc.Handle":   seamCallerSupplied,
}

// TestNilSeams_EveryDeclaredSeamRefuses drives each seam the table says has its own guard, so
// the declaration is a behavior and not a comment. The delegating and caller-supplied rows are
// covered where their guard actually lives (see the table).
func TestNilSeams_EveryDeclaredSeamRefuses(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	eng := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()))

	t.Run("BuildRegoInput", func(t *testing.T) {
		t.Parallel()
		var input map[string]interface{}
		var err error
		assert.NotPanics(t, func() { input, err = enforcement.BuildRegoInput(ctx, nil) })
		require.Error(t, err, "the doc binds a non-nil error to a deny; that is this seam's refusal")
		assert.Nil(t, input, "a partial input would let a third-party evaluator decide on it")
		assert.Contains(t, err.Error(), "called with a nil request")
	})

	t.Run("Engine.CollectObligations", func(t *testing.T) {
		t.Parallel()
		var obs []capability.Obligation
		var deny *capability.EnforceResponse
		assert.NotPanics(t, func() { obs, deny = eng.CollectObligations(nil, "rid", "now") })
		require.NotNil(t, deny, "the callers treat a non-nil response as a hard block")
		assert.Nil(t, obs)
		assert.Equal(t, capability.ErrCodeEnforcementError, deny.Denial.Code)
		assert.False(t, deny.Denial.Downgradable())
		assert.Contains(t, deny.Denial.Message, "called with a nil constraint")
	})

	t.Run("Engine.RecordSessionCall", func(t *testing.T) {
		t.Parallel()
		// The one seam whose old answer was in the fail-OPEN direction: its own contract makes a
		// nil error mean the marker WAS written, so a composing caller forwarded the call and a
		// later sequenceBlock naming that target Peeked empty history.
		var nilEng *enforcement.Engine
		for _, tc := range []struct {
			name string
			eng  *enforcement.Engine
			req  *capability.EnforceRequest
		}{
			{"nil request", eng, nil},
			{"nil engine", nilEng, &capability.EnforceRequest{SessionID: "s", TargetName: "t"}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				var err error
				assert.NotPanics(t, func() { err = tc.eng.RecordSessionCall(ctx, tc.req) })
				require.Error(t, err, "a nil return here reads as 'the antecedent was recorded'")
				assert.Contains(t, err.Error(), "called with a nil engine or request")
			})
		}
	})

	t.Run("Engine.FindMatchingCapability", func(t *testing.T) {
		t.Parallel()
		caps := []capability.Constraint{{Target: "tool:*", Actions: []string{"call"}}}
		var matched *capability.Constraint
		assert.NotPanics(t, func() { matched = eng.FindMatchingCapability(nil, caps) })
		assert.Nil(t, matched,
			"the seam an embedder pairs with EvaluateConditions must answer, not crash, for the input that one denies")
	})

	t.Run("Engine.CeilingVerdictFor", func(t *testing.T) {
		t.Parallel()
		var resp *capability.EnforceResponse
		assert.NotPanics(t, func() {
			resp = eng.CeilingVerdictFor(ctx, nil, &capability.Constraint{Target: "tool:t"})
		})
		assert.Nil(t, resp)
		assert.NotPanics(t, func() {
			resp = eng.CeilingVerdictFor(ctx, &capability.EnforceRequest{SessionID: "s"}, nil)
		})
		assert.Nil(t, resp, "this composes a HARDER refusal for an already-refused call; nil is 'nothing to add'")
	})
}

// TestNilSeams_TableCoversEveryExportedSeam is the half a per-seam test cannot be: it derives the
// seam set from the package's own sources, so a new exported entry point taking one of these
// pointers fails the build until its disposition is declared — rather than shipping with whatever
// dereference its body happens to reach first.
func TestNilSeams_TableCoversEveryExportedSeam(t *testing.T) {
	t.Parallel()

	found := map[string]bool{}
	for _, file := range parseEnforcementSources(t) {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !fn.Name.IsExported() || !takesEnforcementPointer(fn.Type.Params) {
				continue
			}
			found[seamKey(fn)] = true
		}
	}
	require.NotEmpty(t, found, "the walk found no seams at all; it is asserting nothing")

	for name := range found {
		assert.Contains(t, nilSeamTable, name,
			"%s takes a *capability.EnforceRequest or *capability.Constraint and is not declared in nilSeamTable; "+
				"say how it answers a nil one (and cover it above unless it delegates)", name)
	}
	var stale []string
	for name := range nilSeamTable {
		if !found[name] {
			stale = append(stale, name)
		}
	}
	sort.Strings(stale)
	assert.Empty(t, stale, "nilSeamTable declares seams this package no longer has; a stale row asserts nothing")
}

// seamKey names a declaration the way nilSeamTable is keyed: "Receiver.Name", or the bare name
// for a plain function. The receiver's pointer-ness is dropped — it is not what distinguishes two
// seams, and carrying it would make the table's spelling depend on an unrelated edit.
func seamKey(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	recv := fn.Recv.List[0].Type
	if star, ok := recv.(*ast.StarExpr); ok {
		recv = star.X
	}
	id, ok := recv.(*ast.Ident)
	if !ok {
		return fn.Name.Name
	}
	return id.Name + "." + fn.Name.Name
}

// takesEnforcementPointer reports whether any parameter is a *capability.EnforceRequest or a
// *capability.Constraint — the two types whose nil is a decision this package has to make rather
// than dereference.
func takesEnforcementPointer(params *ast.FieldList) bool {
	if params == nil {
		return false
	}
	for _, field := range params.List {
		star, ok := field.Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		sel, ok := star.X.(*ast.SelectorExpr)
		if !ok {
			continue
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "capability" {
			continue
		}
		if sel.Sel.Name == "EnforceRequest" || sel.Sel.Name == "Constraint" {
			return true
		}
	}
	return false
}

// parseEnforcementSources parses this package's non-test sources. Located via runtime.Caller
// rather than the process cwd, so the guard does not silently walk nothing when the test binary
// is run from elsewhere.
func parseEnforcementSources(t *testing.T) []*ast.File {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok, "runtime.Caller failed; cannot locate the package sources")
	dir := filepath.Dir(thisFile)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		require.NoError(t, perr, fmt.Sprintf("parsing %s", name))
		files = append(files, file)
	}
	return files
}
