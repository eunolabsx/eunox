// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"context"
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
	huge := make([]byte, 64<<10)
	for i := range huge {
		huge[i] = 'A'
	}
	cond := capability.AllowedValuesCondition{Argument: "path", Values: []interface{}{"/tmp/*"}}
	resp := evaluateJWTConditions(nil, []capability.Condition{cond}, "read_file",
		map[string]interface{}{"path": string(huge)}, nil)

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
