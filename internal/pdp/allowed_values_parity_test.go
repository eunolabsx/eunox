// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"context"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAllowedValues_ManifestAndJWTPathsAgree is the drift guard the shared predicate exists
// for. The JWT capability-claim path used to re-implement the engine's handleAllowedValues —
// ResolveArgument, the MISSING_CONTEXT arm, MatchAllowedValue, the VALUE_NOT_PERMITTED arm —
// and the copy had already diverged twice by the time it was retired.
//
// The divergence that cost the most was the details map. One logical refusal reached the
// signed tape with two shapes depending only on whether a token was involved, so a SIEM rule
// written against the manifest path's allowedValues denial found nothing for a token-scoped
// caller — and the transport, which reads details["argument"] to name the offending argument
// in the host-facing error, had nothing to read on that path either.
//
// The other divergence was quieter and the same mechanism: task-variable resolution was added
// on the manifest side as a second call the JWT side never made, so a grant carrying
// "${task.*}" matched nothing and denied every call under it. It failed closed by luck rather
// than design — a coercion that WIDENED would have gone the other way.
//
// So this asserts the two paths agree on the whole refusal shape, not just the code.
func TestAllowedValues_ManifestAndJWTPathsAgree(t *testing.T) {
	for name, tc := range map[string]struct {
		values   []interface{}
		args     map[string]interface{}
		wantCode string
	}{
		"value outside the set": {
			values:   []interface{}{"/tmp/*", "/var/log/*"},
			args:     map[string]interface{}{"path": "/etc/shadow"},
			wantCode: capability.ErrCodeValueNotPermitted,
		},
		"argument absent": {
			values:   []interface{}{"/tmp/*"},
			args:     map[string]interface{}{},
			wantCode: capability.ErrCodeMissingContext,
		},
		"present but wrong type": {
			values:   []interface{}{"/tmp/*"},
			args:     map[string]interface{}{"path": 42},
			wantCode: capability.ErrCodeValueNotPermitted,
		},
		"numeric outside the set": {
			values:   []interface{}{float64(1), float64(2)},
			args:     map[string]interface{}{"path": float64(3)},
			wantCode: capability.ErrCodeValueNotPermitted,
		},
	} {
		t.Run(name, func(t *testing.T) {
			cond := capability.AllowedValuesCondition{Argument: "path", Values: tc.values}

			// The manifest path, through the engine's registered handler.
			engine := enforcement.New()
			manifest := engine.EvaluateConditions(context.Background(),
				&capability.EnforceRequest{
					SessionID:  "s",
					TargetName: "tool:read_file",
					Arguments:  tc.args,
				},
				&capability.Constraint{
					Target:     "tool:read_file",
					Actions:    []string{"invoke"},
					Conditions: []capability.Condition{cond},
				})

			// The JWT capability-claim path.
			jwt := evaluateJWTConditions(nil, []capability.Condition{cond}, "read_file", tc.args, nil)

			require.Equal(t, capability.DecisionDeny, manifest.Decision, "the manifest path must refuse")
			require.NotNil(t, jwt, "the JWT path must refuse the same input")
			require.NotNil(t, manifest.Denial)
			require.NotNil(t, jwt.Denial)

			assert.Equal(t, tc.wantCode, manifest.Denial.Code)
			assert.Equal(t, manifest.Denial.Code, jwt.Denial.Code,
				"one logical refusal must not have two denial codes")
			assert.Equal(t, manifest.Denial.ConditionType, jwt.Denial.ConditionType,
				"nor two condition types")
			assert.Equal(t, manifest.Denial.Details, jwt.Denial.Details,
				"nor two record shapes: a SIEM rule keyed on the manifest path's details must find the token-scoped caller too")
		})
	}
}

// TestAllowedValues_JWTPathHasTheEmptyArgumentGuard is the second surviving divergence. The
// manifest path refuses an allowedValues condition naming no argument (a condition that
// resolves nothing cannot restrict anything); the JWT copy had no such check and went on to
// resolve the empty name. Routing through the shared predicate is what supplies it, so this
// asserts the guard is reachable from THIS path rather than re-asserting the engine's own.
func TestAllowedValues_JWTPathHasTheEmptyArgumentGuard(t *testing.T) {
	cond := capability.AllowedValuesCondition{Argument: "", Values: []interface{}{"*"}}
	resp := evaluateJWTConditions(nil, []capability.Condition{cond}, "read_file",
		map[string]interface{}{"path": "/tmp/x"}, nil)

	require.NotNil(t, resp, "an allowedValues condition that names no argument restricts nothing; fail closed")
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeConditionFailed, resp.Denial.Code)
	assert.Equal(t, capability.ConditionTypeAllowedValues, resp.Denial.ConditionType)
}

// TestAllowedValues_JWTDenialNamesTheGrantAndTheArgument pins the two things the shared
// predicate must NOT flatten away.
//
// The grant name: a capability claim is an OR-list, so "which entry refused" is a diagnostic
// the engine's own message cannot supply and the JWT path's prefix must keep.
//
// The argument: the transport builds its host-facing error from details["argument"], which is
// exactly what this path could not populate before.
func TestAllowedValues_JWTDenialNamesTheGrantAndTheArgument(t *testing.T) {
	cond := capability.AllowedValuesCondition{Argument: "path", Values: []interface{}{"/tmp/*"}}
	resp := evaluateJWTConditions(nil, []capability.Condition{cond}, "read_file",
		map[string]interface{}{"path": "/etc/shadow"}, nil)

	require.NotNil(t, resp)
	require.NotNil(t, resp.Denial)
	assert.Contains(t, resp.Denial.Message, `"read_file"`, "the refusing grant must stay named in the message")
	assert.Equal(t, "path", resp.Denial.Details["argument"])
	assert.Equal(t, "/etc/shadow", resp.Denial.Details["value"])
	assert.Equal(t, []interface{}{"/tmp/*"}, resp.Denial.Details["allowedValues"])
}

// TestAllowedValues_JWTDenialDetailsAreBounded is the cost of carrying details at all. They
// echo the caller's own failed argument, and this path assembles its EnforceResponse itself
// rather than through the engine's denyResponse — which is where every engine-built deny picks
// up that bound. Skipping it would make this the one denial on the signed tape able to carry a
// caller-sized value, turning each denied call into a lever on log growth at whatever rate the
// caller can issue them.
func TestAllowedValues_JWTDenialDetailsAreBounded(t *testing.T) {
	huge := strings.Repeat("A", 64<<10)
	cond := capability.AllowedValuesCondition{Argument: "path", Values: []interface{}{"/tmp/*"}}
	resp := evaluateJWTConditions(nil, []capability.Condition{cond}, "read_file",
		map[string]interface{}{"path": huge}, nil)

	require.NotNil(t, resp)
	require.NotNil(t, resp.Denial)
	got, ok := resp.Denial.Details["value"].(string)
	require.True(t, ok, "the echoed value is still recorded, just bounded")
	assert.Less(t, len(got), len(huge),
		"a caller-supplied argument must not reach the signed tape at its own length")
}

// TestAllowedValues_TaskVariableResolvesOnBothPaths is the divergence that actually shipped:
// a grant whose allowed value referenced the caller's task context matched nothing on the JWT
// path and denied every call under it. Pinned on both paths so the resolution cannot be added
// to one again.
func TestAllowedValues_TaskVariableResolvesOnBothPaths(t *testing.T) {
	claims := map[string]interface{}{"task_id": "t-42"}
	cond := capability.AllowedValuesCondition{Argument: "workspace_id", Values: []interface{}{"${task.id}"}}
	args := map[string]interface{}{"workspace_id": "t-42"}

	assert.Nil(t, evaluateJWTConditions(nil, []capability.Condition{cond}, "fetch_workspace", args, claims),
		"a grant carrying a recognized task reference must match the call it describes")

	manifest := enforcement.New().EvaluateConditions(context.Background(),
		&capability.EnforceRequest{
			SessionID:  "s",
			TargetName: "tool:fetch_workspace",
			Arguments:  args,
			Claims:     claims,
		},
		&capability.Constraint{
			Target:     "tool:fetch_workspace",
			Actions:    []string{"invoke"},
			Conditions: []capability.Condition{cond},
		})
	assert.Equal(t, capability.DecisionAllow, manifest.Decision, "and so must the manifest path")
}

// TestEvaluateAllowedValues_NilRequestDenies covers the exported seam's own fail-closed guard.
// The engine never evaluates a condition without a request, but this is a public function now,
// and a nil request must deny rather than panic the request goroutine (fail-open-via-crash) or
// read as a condition that passed.
func TestEvaluateAllowedValues_NilRequestDenies(t *testing.T) {
	cerr := enforcement.EvaluateAllowedValues(
		capability.AllowedValuesCondition{Argument: "path", Values: []interface{}{"/tmp/*"}}, nil)
	require.NotNil(t, cerr, "no request to check against is ambiguity; deny")
	assert.Equal(t, capability.ErrCodeConditionFailed, cerr.Code)
}

// TestAllowedOperations_JWTDenialsCarryTheEnginesDetails is the other half of the same defect,
// on the other arm of the same function.
//
// The allowedOperations arm cannot share the engine's HANDLER — its scan-all-arguments
// semantics are deliberately different (the claim grammar cannot name the operation argument,
// and the engine hard-denies the empty argument this path always emits) — but "one logical
// refusal, two record shapes depending only on whether a token was involved" applies to it
// exactly as it did to allowedValues. So it shares the record SHAPE: the same detail keys the
// engine records for the same denial code, which is what a SIEM rule and the host-facing error
// are keyed on.
func TestAllowedOperations_JWTDenialsCarryTheEnginesDetails(t *testing.T) {
	cond := capability.AllowedOperationsCondition{Operations: []string{"SELECT"}}

	// The manifest path's shape for the same code, from the engine's own handler.
	manifest := enforcement.New().EvaluateConditions(context.Background(),
		&capability.EnforceRequest{
			SessionID:  "s",
			TargetName: "tool:query_db",
			Arguments:  map[string]interface{}{"sql": "DROP TABLE users"},
		},
		&capability.Constraint{
			Target:     "tool:query_db",
			Actions:    []string{"invoke"},
			Conditions: []capability.Condition{capability.AllowedOperationsCondition{Argument: "sql", Operations: []string{"SELECT"}}},
		})
	require.Equal(t, capability.DecisionDeny, manifest.Decision)
	require.NotNil(t, manifest.Denial)
	require.Equal(t, capability.ErrCodeOperationNotPermitted, manifest.Denial.Code)

	jwt := evaluateJWTConditions(nil, []capability.Condition{cond}, "query_db",
		map[string]interface{}{"sql": "DROP TABLE users"}, nil)
	require.NotNil(t, jwt)
	require.NotNil(t, jwt.Denial)

	assert.Equal(t, manifest.Denial.Code, jwt.Denial.Code)
	assert.Equal(t, manifest.Denial.ConditionType, jwt.Denial.ConditionType)
	assert.Equal(t, manifest.Denial.Details, jwt.Denial.Details,
		"the same denial code must reach the tape with the same details on both paths")
}

// TestAllowedOperations_EveryJWTRefusalCarriesDetails covers the arms with no manifest
// counterpart — the two documented JWT-only fail-closed guards and the depth bound. They keep
// their behavior (the point of those guards is that they refuse), but a refusal with an empty
// details map is one an operator cannot act on and a rule cannot match, which is the whole
// complaint against this function's denials.
func TestAllowedOperations_EveryJWTRefusalCarriesDetails(t *testing.T) {
	for name, tc := range map[string]struct {
		cond     capability.Condition
		args     map[string]interface{}
		wantCode string
		wantKeys []string
	}{
		"named argument is unenforceable from a claim": {
			capability.AllowedOperationsCondition{Argument: "op", Operations: []string{"SELECT"}},
			map[string]interface{}{"op": "SELECT"},
			capability.ErrCodeConditionFailed, []string{"argument", "allowedOperations"},
		},
		"non-SQL op cannot be scanned for": {
			capability.AllowedOperationsCondition{Operations: []string{"publish"}},
			map[string]interface{}{"topic": "x"},
			capability.ErrCodeConditionFailed, []string{"operation", "allowedOperations"},
		},
		"no argument matched any permitted operation": {
			capability.AllowedOperationsCondition{Operations: []string{"SELECT"}},
			map[string]interface{}{"note": "nothing here"},
			capability.ErrCodeMissingContext, []string{"allowedOperations"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			resp := evaluateJWTConditions(nil, []capability.Condition{tc.cond}, "query_db", tc.args, nil)
			require.NotNil(t, resp, "these arms all refuse; that is deliberate and unchanged")
			require.NotNil(t, resp.Denial)
			assert.Equal(t, tc.wantCode, resp.Denial.Code)
			for _, k := range tc.wantKeys {
				assert.Contains(t, resp.Denial.Details, k,
					"a refusal an operator cannot act on is the defect this arm shares with allowedValues")
			}
		})
	}

	// The MISSING_CONTEXT arm deliberately does NOT name an argument, unlike the engine's:
	// the claim grammar cannot express one, so the scan covers every argument, and a phantom
	// name would send an operator looking for a manifest field that does not exist.
	resp := evaluateJWTConditions(nil,
		[]capability.Condition{capability.AllowedOperationsCondition{Operations: []string{"SELECT"}}},
		"query_db", map[string]interface{}{"note": "nothing here"}, nil)
	require.NotNil(t, resp)
	assert.NotContains(t, resp.Denial.Details, "argument")
}

// TestJWTConditionDenials_DetailsAreBounded is the funnel's own guard. Every deny this package
// builds now routes through denyResponse/denyResponseWithDetails, and the bound lives inside
// that funnel rather than at each producer — a rule each site has to remember is one that gets
// forgotten silently, since the resulting deny is still well-formed, signed and
// chain-verifiable, just unbounded.
func TestJWTConditionDenials_DetailsAreBounded(t *testing.T) {
	huge := strings.Repeat("A", 64<<10)
	resp := evaluateJWTConditions(nil,
		[]capability.Condition{capability.AllowedOperationsCondition{Operations: []string{"SELECT"}}},
		"query_db", map[string]interface{}{"sql": "DROP " + huge}, nil)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Denial)
	op, ok := resp.Denial.Details["operation"].(string)
	require.True(t, ok)
	assert.Less(t, len(op), len(huge),
		"a caller-supplied value echoed into a denial must not reach the signed tape at its own length")
}
