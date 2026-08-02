// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability_test

import (
	"strings"
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
)

// TestParseVariableRef pins the whole-value rule: a reference is the ENTIRE value or it is
// not a reference. An interpolated one would be glob-matched text built partly from an
// IdP-supplied claim, which is a pattern the manifest author did not write.
func TestParseVariableRef(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in       string
		wantName string
		wantOK   bool
	}{
		{"${task.id}", "task.id", true},
		{"${task.agent}", "task.agent", true},
		{"${task.principal}", "task.principal", true},
		{"${anything}", "anything", true}, // well-formed; ValidateVariableRef judges the NAME
		{"job-${task.id}", "", false},
		{"${task.id}-suffix", "", false},
		{"${task.id", "", false},
		{"$task.id}", "", false},
		{"${}", "", false},
		{"${${task.id}}", "", false},
		{"task.id", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			name, ok := capability.ParseVariableRef(tc.in)
			if ok != tc.wantOK || name != tc.wantName {
				t.Fatalf("ParseVariableRef(%q) = (%q, %v), want (%q, %v)", tc.in, name, ok, tc.wantName, tc.wantOK)
			}
		})
	}
}

// TestValidateVariableRef is the closed-grammar gate: a misspelled variable is a LOAD
// ERROR, not an inert literal that quietly denies every call at runtime.
func TestValidateVariableRef(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, in, wantErr string
	}{
		{"task id", "${task.id}", ""},
		{"task agent", "${task.agent}", ""},
		{"task principal", "${task.principal}", ""},
		{"misspelled", "${task.identifier}", "unknown task-context variable"},
		{"wrong namespace", "${env.HOME}", "unknown task-context variable"},
		{"interpolated", "job-${task.id}", "must be the ENTIRE value"},
		{"unclosed", "${task.id", "must be the ENTIRE value"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := capability.ValidateVariableRef(tc.in)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestResolveTaskVar covers the fail-closed half: every state in which a reference cannot
// resolve reports ok=false, so the caller denies rather than comparing against "".
func TestResolveTaskVar(t *testing.T) {
	t.Parallel()
	claims := map[string]interface{}{
		"task_id":  "task-42",
		"agent_id": "agent-7",
		"sub":      "svc-research",
		"blank":    "   ",
	}
	cases := []struct {
		name, variable string
		claims         map[string]interface{}
		want           string
		ok             bool
	}{
		{"task id", capability.TaskVarID, claims, "task-42", true},
		{"agent", capability.TaskVarAgent, claims, "agent-7", true},
		{"principal", capability.TaskVarPrincipal, claims, "svc-research", true},
		{"unknown variable", "task.nope", claims, "", false},
		{"no claims at all (no token)", capability.TaskVarID, nil, "", false},
		{"claim absent", capability.TaskVarID, map[string]interface{}{"sub": "x"}, "", false},
		{"claim empty", capability.TaskVarID, map[string]interface{}{"task_id": ""}, "", false},
		{"claim blank", capability.TaskVarID, map[string]interface{}{"task_id": "  "}, "", false},
		{"claim not a string", capability.TaskVarID, map[string]interface{}{"task_id": 42}, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := capability.ResolveTaskVar(tc.variable, tc.claims)
			if got != tc.want || ok != tc.ok {
				t.Fatalf("ResolveTaskVar(%q) = (%q, %v), want (%q, %v)", tc.variable, got, ok, tc.want, tc.ok)
			}
		})
	}
}

// TestTaskVarNames pins the closed set. Growing it is a grammar change: the list is what
// the load-time error message enumerates and what the guide documents.
func TestTaskVarNames(t *testing.T) {
	t.Parallel()
	got := capability.TaskVarNames()
	want := []string{"task.agent", "task.id", "task.principal"}
	if len(got) != len(want) {
		t.Fatalf("variable set = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("variable set = %v, want %v", got, want)
		}
	}
}
