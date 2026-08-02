// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement_test

import (
	"context"
	"testing"

	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// taskVarCaps binds a tool argument to the values listed (typically a ${task.*} reference).
func taskVarCaps(argument string, values ...interface{}) []capability.Constraint {
	return []capability.Constraint{{
		Target:  "tool:fetch",
		Actions: []string{"call"},
		Conditions: []capability.Condition{
			capability.AllowedValuesCondition{Argument: argument, Values: values},
		},
	}}
}

func taskVarReq(arg string, claims map[string]interface{}) *capability.EnforceRequest {
	return &capability.EnforceRequest{
		SessionID:  "s",
		TargetName: "fetch",
		Target:     &capability.EnforceRequestTarget{Type: "tool", Name: "fetch"},
		Arguments:  map[string]interface{}{"task": arg},
		Claims:     claims,
	}
}

// TestTaskVar_AllowedValues walks the whole surface: a reference matches the caller's own
// claim, denies for any other value, and denies — never widens — when it cannot resolve.
func TestTaskVar_AllowedValues(t *testing.T) {
	eng := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()))
	ctx := context.Background()
	claims := map[string]interface{}{"task_id": "task-42", "agent_id": "agent-7", "sub": "svc-research"}

	cases := []struct {
		name     string
		variable string
		arg      string
		claims   map[string]interface{}
		allow    bool
	}{
		{"argument equals the token's task id", "${task.id}", "task-42", claims, true},
		{"argument equals the token's agent id", "${task.agent}", "agent-7", claims, true},
		{"argument equals the token's subject", "${task.principal}", "svc-research", claims, true},
		{"a different task is denied", "${task.id}", "task-99", claims, false},
		{"no token denies", "${task.id}", "task-42", nil, false},
		{"absent claim denies", "${task.id}", "task-42", map[string]interface{}{"sub": "x"}, false},
		{"empty claim does not match an empty argument", "${task.id}", "", map[string]interface{}{"task_id": ""}, false},
		{"the literal placeholder never matches", "${task.id}", "${task.id}", claims, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := eng.ValidateAction(ctx, taskVarReq(tc.arg, tc.claims), taskVarCaps("task", tc.variable))
			if tc.allow {
				require.Equal(t, capability.DecisionAllow, resp.Decision)
				return
			}
			require.Equal(t, capability.DecisionDeny, resp.Decision)
		})
	}
}

// TestTaskVar_ResolvedValueIsNotAGlob is the load-bearing security property: a resolved
// claim is compared by EXACT equality. Were it run through the allowedValues glob matcher,
// a token whose task_id is "*" would be an allow-anything wildcard the token holder chose
// for themselves.
func TestTaskVar_ResolvedValueIsNotAGlob(t *testing.T) {
	eng := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()))
	wildcardClaims := map[string]interface{}{"task_id": "*"}

	denied := eng.ValidateAction(context.Background(),
		taskVarReq("anything-at-all", wildcardClaims), taskVarCaps("task", "${task.id}"))
	require.Equal(t, capability.DecisionDeny, denied.Decision,
		"a claim value of * must not become a wildcard")

	// The same claim still matches itself exactly, so the binding is not simply broken.
	allowed := eng.ValidateAction(context.Background(),
		taskVarReq("*", wildcardClaims), taskVarCaps("task", "${task.id}"))
	assert.Equal(t, capability.DecisionAllow, allowed.Decision)
}

// TestTaskVar_ComposesWithLiterals pins that a reference sits alongside ordinary literal
// and glob entries in the same values list without disturbing them.
func TestTaskVar_ComposesWithLiterals(t *testing.T) {
	eng := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()))
	ctx := context.Background()
	claims := map[string]interface{}{"task_id": "task-42"}
	caps := taskVarCaps("task", "shared-*", "${task.id}")

	assert.Equal(t, capability.DecisionAllow,
		eng.ValidateAction(ctx, taskVarReq("shared-inbox", claims), caps).Decision, "the glob still applies")
	assert.Equal(t, capability.DecisionAllow,
		eng.ValidateAction(ctx, taskVarReq("task-42", claims), caps).Decision, "the reference still applies")
	assert.Equal(t, capability.DecisionDeny,
		eng.ValidateAction(ctx, taskVarReq("task-43", claims), caps).Decision)
}
