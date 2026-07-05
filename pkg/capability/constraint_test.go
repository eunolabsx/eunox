// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability_test

import (
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
)

// TestMethodSamplingCreateMessage pins the canonical MCP method string so the
// constant can't silently drift from the wire value every caller (audit, pdp,
// transport) relies on for routing, enforcement, and audit classification.
func TestMethodSamplingCreateMessage(t *testing.T) {
	const want = "sampling/createMessage"
	if capability.MethodSamplingCreateMessage != want {
		t.Errorf("MethodSamplingCreateMessage = %q, want %q", capability.MethodSamplingCreateMessage, want)
	}
}

// TestListMethodConstants pins the */list method names and their result-envelope
// entry keys so the transport dispatch map and the PDP's list accounting, which both
// consume these, cannot silently drift from the wire values or from each other.
func TestListMethodConstants(t *testing.T) {
	cases := []struct {
		method, wantKey string
	}{
		{capability.MethodToolsList, capability.ListKeyTools},
		{capability.MethodResourcesList, capability.ListKeyResources},
		{capability.MethodPromptsList, capability.ListKeyPrompts},
	}
	wantMethods := map[string]string{
		"tools/list":     "tools",
		"resources/list": "resources",
		"prompts/list":   "prompts",
	}
	for _, tc := range cases {
		if capability.ListResultKey(tc.method) != tc.wantKey {
			t.Errorf("ListResultKey(%q) = %q, want %q", tc.method, capability.ListResultKey(tc.method), tc.wantKey)
		}
		if wantMethods[tc.method] != tc.wantKey {
			t.Errorf("method %q maps to key %q, not the expected wire key", tc.method, tc.wantKey)
		}
	}
	if capability.ListResultKey("tools/call") != "" {
		t.Errorf("ListResultKey(non-list) = %q, want \"\"", capability.ListResultKey("tools/call"))
	}
}

func TestConstraintPrincipalMatches(t *testing.T) {
	tests := []struct {
		name      string
		principal map[string][]string
		claims    map[string]interface{}
		want      bool
	}{
		{
			name:      "no principal matches any request",
			principal: nil,
			claims:    nil,
			want:      true,
		},
		{
			name:      "no principal matches even with claims",
			principal: map[string][]string{},
			claims:    map[string]interface{}{"agent_id": "x"},
			want:      true,
		},
		{
			name:      "exact agent_id match",
			principal: map[string][]string{"agent_id": {"agent-admin"}},
			claims:    map[string]interface{}{"agent_id": "agent-admin"},
			want:      true,
		},
		{
			name:      "agent_id mismatch",
			principal: map[string][]string{"agent_id": {"agent-admin"}},
			claims:    map[string]interface{}{"agent_id": "agent-other"},
			want:      false,
		},
		{
			name:      "missing claim fails closed",
			principal: map[string][]string{"agent_id": {"agent-admin"}},
			claims:    map[string]interface{}{"task_id": "t1"},
			want:      false,
		},
		{
			name:      "nil claims never satisfy a principal",
			principal: map[string][]string{"agent_id": {"agent-admin"}},
			claims:    nil,
			want:      false,
		},
		{
			name:      "non-string claim value fails closed",
			principal: map[string][]string{"agent_id": {"42"}},
			claims:    map[string]interface{}{"agent_id": 42},
			want:      false,
		},
		{
			name:      "glob match",
			principal: map[string][]string{"agent_id": {"acme-*"}},
			claims:    map[string]interface{}{"agent_id": "acme-bot-7"},
			want:      true,
		},
		{
			name:      "OR within a claim's value list",
			principal: map[string][]string{"agent_id": {"a", "b", "c"}},
			claims:    map[string]interface{}{"agent_id": "b"},
			want:      true,
		},
		{
			name:      "AND across claims — both satisfied",
			principal: map[string][]string{"agent_id": {"admin"}, "task_id": {"t1"}},
			claims:    map[string]interface{}{"agent_id": "admin", "task_id": "t1"},
			want:      true,
		},
		{
			name:      "AND across claims — one unsatisfied fails",
			principal: map[string][]string{"agent_id": {"admin"}, "task_id": {"t1"}},
			claims:    map[string]interface{}{"agent_id": "admin", "task_id": "t2"},
			want:      false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := capability.Constraint{Principal: tc.principal}
			if got := c.PrincipalMatches(tc.claims); got != tc.want {
				t.Errorf("PrincipalMatches = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestConstraintHasPrincipal(t *testing.T) {
	empty := capability.Constraint{}
	if empty.HasPrincipal() {
		t.Error("empty constraint should not be principal-scoped")
	}
	scoped := capability.Constraint{Principal: map[string][]string{"agent_id": {"x"}}}
	if !scoped.HasPrincipal() {
		t.Error("constraint with a principal should report HasPrincipal")
	}
}
