// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The guard behind the effect layer's two denial constructors: a refusal the policy REACHED is
// downgradable, one the engine could not reach is not.
//
// One constructor used to hardcode CONDITION_FAILED for every effect refusal, so a `blastRadius`
// bounding nothing, a non-numeric bound, and an unresolved contract were all classified as policy
// verdicts an observing route FORWARDS — with the effect condition never evaluated once. The
// split is held structurally (effectDenial takes the resolved effect, which no unevaluable site
// has) and here in two halves: the source walk below closes the one gap the signature cannot,
// a site hand-rolling the code in a literal, and the table above pins each site's answer.

package enforcement

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
)

// TestEffectRefusals_FaultsAreNotDowngradable drives every effect-condition refusal and asserts
// the class each carries. The unevaluable rows are the defect: each denied CONDITION_FAILED,
// which capability.DenialInfo.Downgradable answers YES for.
func TestEffectRefusals_FaultsAreNotDowngradable(t *testing.T) {
	t.Parallel()

	quantified := &capability.EffectContract{
		Class:              capability.EffectCompensable,
		CompensatingAction: "tool:reverse",
		BlastRadius:        &capability.BlastRadiusSpec{Argument: "amount", Unit: "usd"},
	}
	num := func(s string) *json.Number {
		n := json.Number(s)
		return &n
	}

	cases := []struct {
		name     string
		contract *capability.EffectContract
		cond     capability.Condition
		args     map[string]interface{}
		wantCode string
	}{
		{
			// The contract was resolved and the allow set decided against it: a verdict.
			name:     "effectClass refuses a class outside the allow set",
			contract: quantified,
			cond:     capability.EffectClassCondition{Allow: []string{capability.EffectReversible}},
			wantCode: capability.ErrCodeConditionFailed,
		},
		{
			// Nothing to evaluate against: a fault.
			name:     "effectClass with an empty allow set",
			contract: quantified,
			cond:     capability.EffectClassCondition{},
			wantCode: capability.ErrCodeEnforcementError,
		},
		{
			name:     "effectClass with a class outside the vocabulary",
			contract: quantified,
			cond:     capability.EffectClassCondition{Allow: []string{"mostly-harmless"}},
			wantCode: capability.ErrCodeEnforcementError,
		},
		{
			name:     "blastRadius declaring neither bound",
			contract: quantified,
			cond:     capability.BlastRadiusCondition{},
			wantCode: capability.ErrCodeEnforcementError,
		},
		{
			name:     "blastRadius whose per-call max is not a number",
			contract: quantified,
			cond:     capability.BlastRadiusCondition{Max: num("plenty")},
			args:     map[string]interface{}{"amount": 5},
			wantCode: capability.ErrCodeEnforcementError,
		},
		{
			name:     "blastRadius whose cumulative maxTotal is not a number",
			contract: quantified,
			cond:     capability.BlastRadiusCondition{MaxTotal: num("plenty"), WindowSeconds: 60},
			args:     map[string]interface{}{"amount": 5},
			wantCode: capability.ErrCodeEnforcementError,
		},
		{
			// The bound WAS evaluated against a magnitude the contract could not supply: the
			// unannotated-target flywheel working as intended, so a verdict.
			name:     "blastRadius over an unquantifiable magnitude",
			contract: nil,
			cond:     capability.BlastRadiusCondition{Max: num("10")},
			wantCode: capability.ErrCodeConditionFailed,
		},
		{
			name:     "blastRadius over the per-call maximum",
			contract: quantified,
			cond:     capability.BlastRadiusCondition{Max: num("10")},
			args:     map[string]interface{}{"amount": 5000},
			wantCode: capability.ErrCodeConditionFailed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			eng := New(WithCallCounter(callcounter.NewInMemory()))
			resp := eng.ValidateAction(context.Background(), &capability.EnforceRequest{
				SessionID:  "s",
				TargetName: "act",
				Target:     &capability.EnforceRequestTarget{Type: "tool", Name: "act"},
				Arguments:  tc.args,
			}, []capability.Constraint{{
				Target:     "tool:act",
				Actions:    []string{"call"},
				Effect:     tc.contract,
				Conditions: []capability.Condition{tc.cond},
			}})

			require.Equal(t, capability.DecisionDeny, resp.Decision)
			require.NotNil(t, resp.Denial)
			assert.Equal(t, tc.wantCode, resp.Denial.Code, "message was: %s", resp.Denial.Message)
			assert.Equal(t, tc.wantCode == capability.ErrCodeConditionFailed, resp.Denial.Downgradable(),
				"only a refusal the effect layer actually reached a verdict for may be forwarded by an observing route")
		})
	}
}

// TestEffectFile_BuildsNoConditionErrorOutsideItsTwoConstructors is the half the signatures
// cannot close. effectDenial takes the resolved effect, so a site above the resolution physically
// cannot call it — but nothing stops one writing its own &ConditionError with whichever code it
// picks, which is what every effect refusal did before the split. Requiring the two constructors
// to be the only ones in this file keeps the class a two-way choice at a named constructor.
//
// Scoped to ConditionError, not to the CODES: checkEffectCeiling legitimately names
// ErrCodeConditionFailed in a capability.DenialInfo, a different shape with its own explicit
// BlockOverride, and a rule broad enough to catch that would be one this file has to be exempted
// from rather than held to.
func TestEffectFile_BuildsNoConditionErrorOutsideItsTwoConstructors(t *testing.T) {
	t.Parallel()

	dir, ok := callerDir()
	require.True(t, ok, "runtime.Caller failed; cannot locate effect.go")
	path := filepath.Join(dir, "effect.go")
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	require.NoError(t, err)

	minters := map[string]bool{"effectDenial": true, "effectFault": true}
	found := 0
	for _, decl := range file.Decls {
		fn, isFunc := decl.(*ast.FuncDecl)
		if !isFunc || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			lit, isLit := n.(*ast.CompositeLit)
			if !isLit {
				return true
			}
			name, isIdent := lit.Type.(*ast.Ident)
			if !isIdent || name.Name != "ConditionError" {
				return true
			}
			found++
			assert.True(t, minters[fn.Name.Name],
				"%s: %s builds a ConditionError of its own; route it through effectDenial (a verdict the policy reached) or effectFault (one it could not), so the denial class is not a per-site literal",
				fset.Position(lit.Pos()), fn.Name.Name)
			return true
		})
	}
	assert.Equal(t, len(minters), found,
		"effect.go should build exactly one ConditionError per constructor; found %d, so this walk is asserting something other than what it says", found)
}

// callerDir locates this package's source directory, so the walk does not silently find nothing
// when the test binary runs from another working directory.
func callerDir() (dir string, ok bool) {
	_, thisFile, _, found := runtime.Caller(0)
	if !found {
		return "", false
	}
	return filepath.Dir(thisFile), true
}
