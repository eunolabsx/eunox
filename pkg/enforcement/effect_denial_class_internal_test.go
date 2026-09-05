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
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

// TestConditionFault_IsTheOnlyMinterOfTheFaultCode is the half the signatures cannot close.
//
// effectDenial takes the resolved effect, so a site above the resolution physically cannot call
// it — but nothing stops any handler in the package writing ErrCodeEnforcementError into a
// &ConditionError of its own, which is how blastRadius, timeWindow and ipRange came to call an
// unevaluable condition a policy verdict while their siblings called it a fault. Requiring
// conditionFault to be the single minter puts "which class is this?" at one documented place a
// new handler lands on, package-wide rather than in the one file the split started in.
//
// RESIDUAL, stated rather than implied: this asserts that the fault code has one home, not that
// every unevaluable site reaches it — no walk can tell whether a refusal reached a verdict. What
// it buys is that the rule is discoverable and that a second spelling cannot ship silently.
func TestConditionFault_IsTheOnlyMinterOfTheFaultCode(t *testing.T) {
	t.Parallel()

	dir, ok := callerDir()
	require.True(t, ok, "runtime.Caller failed; cannot locate the package sources")

	// One literal, in the constructor itself.
	exempt := map[string]bool{"conditionFault": true}
	found := 0

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		file, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		require.NoError(t, perr)

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
				typeName, isIdent := lit.Type.(*ast.Ident)
				if !isIdent || typeName.Name != "ConditionError" {
					return true
				}
				if !namesFaultCode(lit) {
					return true
				}
				found++
				assert.True(t, exempt[fn.Name.Name],
					"%s: %s builds a ConditionError carrying ErrCodeEnforcementError of its own; call conditionFault so the fault class has one home",
					fset.Position(lit.Pos()), fn.Name.Name)
				return true
			})
		}
	}
	assert.Equal(t, len(exempt), found,
		"expected exactly one fault-coded ConditionError literal in the package; found %d, so this walk is asserting something other than what it says", found)
}

// namesFaultCode reports whether a composite literal sets Code to ErrCodeEnforcementError.
func namesFaultCode(lit *ast.CompositeLit) bool {
	for _, elt := range lit.Elts {
		kv, isKV := elt.(*ast.KeyValueExpr)
		if !isKV {
			continue
		}
		key, isIdent := kv.Key.(*ast.Ident)
		if !isIdent || key.Name != "Code" {
			continue
		}
		sel, isSel := kv.Value.(*ast.SelectorExpr)
		return isSel && sel.Sel.Name == "ErrCodeEnforcementError"
	}
	return false
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
