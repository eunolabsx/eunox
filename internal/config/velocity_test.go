// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// Load-time validation for the CUMULATIVE blastRadius bound. Every shape here would leave
// an operator believing a limit is in force when it is not, which is exactly why the
// grammar refused to carry the keys at all until they could be enforced.

// TestVelocityGrammarAccepts is the allow case: both bounds together, and each on its own.
func TestVelocityGrammarAccepts(t *testing.T) {
	for _, cond := range []string{
		"        max: 500\n        maxTotal: 2000\n        windowSeconds: 3600\n",
		"        maxTotal: 2000\n        windowSeconds: 3600\n",
		"        max: 500\n",
	} {
		body := effectManifest("", "  - target: tool:refund\n    actions: [call]\n    conditions:\n      - type: blastRadius\n"+cond)
		if _, err := writeEffectManifest(t, body); err != nil {
			t.Fatalf("a well-formed blastRadius condition must load:\n%s\nerror: %v", cond, err)
		}
	}
}

// TestVelocityGrammarRejections is the deny table. The pair rule is the load-bearing one:
// half a cumulative bound silently disables the other half, and an authored bound that
// bounds nothing is worse than its absence.
func TestVelocityGrammarRejections(t *testing.T) {
	cases := []struct {
		name, caps, wantErr string
	}{
		{
			name:    "a total with no window to sum it over",
			caps:    "  - target: tool:t\n    actions: [call]\n    conditions:\n      - type: blastRadius\n        maxTotal: 2000\n",
			wantErr: "requires 'windowSeconds'",
		},
		{
			name:    "a window with no total to bound",
			caps:    "  - target: tool:t\n    actions: [call]\n    conditions:\n      - type: blastRadius\n        windowSeconds: 3600\n",
			wantErr: "requires 'maxTotal'",
		},
		{
			name:    "neither bound",
			caps:    "  - target: tool:t\n    actions: [call]\n    conditions:\n      - type: blastRadius\n        max: null\n",
			wantErr: "bounds nothing",
		},
		{
			name:    "a negative cumulative bound denies every call",
			caps:    "  - target: tool:t\n    actions: [call]\n    conditions:\n      - type: blastRadius\n        maxTotal: -1\n        windowSeconds: 60\n",
			wantErr: "must not be negative",
		},
		{
			name:    "a zero cumulative bound admits no quantified call",
			caps:    "  - target: tool:t\n    actions: [call]\n    conditions:\n      - type: blastRadius\n        maxTotal: 0\n        windowSeconds: 60\n",
			wantErr: "must be > 0",
		},
		{
			name:    "a cumulative bound past what the backends sum exactly",
			caps:    "  - target: tool:t\n    actions: [call]\n    conditions:\n      - type: blastRadius\n        maxTotal: 1e30\n        windowSeconds: 60\n",
			wantErr: "sum exactly",
		},
		{
			name:    "a non-positive window",
			caps:    "  - target: tool:t\n    actions: [call]\n    conditions:\n      - type: blastRadius\n        maxTotal: 100\n        windowSeconds: -5\n",
			wantErr: "must be >= 1",
		},
		{
			name:    "a window past what a duration represents",
			caps:    "  - target: tool:t\n    actions: [call]\n    conditions:\n      - type: blastRadius\n        maxTotal: 100\n        windowSeconds: 9999999999999\n",
			wantErr: "exceeds the maximum",
		},
		{
			name:    "a misspelled cumulative key",
			caps:    "  - target: tool:t\n    actions: [call]\n    conditions:\n      - type: blastRadius\n        maxTotals: 100\n        windowSeconds: 60\n",
			wantErr: "unknown field",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := writeEffectManifest(t, effectManifest("", tc.caps))
			if err == nil {
				t.Fatalf("want a load error naming %q, got none", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error must name %q, got: %v", tc.wantErr, err)
			}
		})
	}
}

// TestVelocityRejectsASecondCommittingCondition pins the one-committing-bound rule. A
// weighted budget and a call count cannot be admitted in one atomic commit, and committing
// them separately would let a call the second denies spend the first's budget — so the
// combination is refused at LOAD rather than enforced with a weaker guarantee than the
// manifest appears to promise.
func TestVelocityRejectsASecondCommittingCondition(t *testing.T) {
	velocity := "      - type: blastRadius\n        maxTotal: 2000\n        windowSeconds: 3600\n"
	maxCalls := "      - type: maxCalls\n        count: 10\n        windowSeconds: 3600\n"
	cases := map[string]string{
		// Order must not decide whether the shape is legal.
		"velocity then maxCalls": velocity + maxCalls,
		"maxCalls then velocity": maxCalls + velocity,
		"two cumulative bounds":  velocity + "      - type: blastRadius\n        maxTotal: 500\n        windowSeconds: 60\n",
	}
	for name, conds := range cases {
		t.Run(name, func(t *testing.T) {
			caps := "  - target: tool:refund\n    actions: [call]\n    conditions:\n" + conds
			_, err := writeEffectManifest(t, effectManifest("", caps))
			if err == nil {
				t.Fatal("want a load error refusing the combination, got none")
			}
			if !strings.Contains(err.Error(), "both consume quota") {
				t.Fatalf("error must explain the conflict, got: %v", err)
			}
		})
	}
}

// TestVelocityAllowsAPerCallBoundBesideMaxCalls is the other half: only the CUMULATIVE
// bound consumes quota, so a per-call blastRadius alongside a maxCalls is a legal and
// common shape that must keep loading.
func TestVelocityAllowsAPerCallBoundBesideMaxCalls(t *testing.T) {
	caps := "  - target: tool:refund\n    actions: [call]\n    conditions:\n" +
		"      - type: blastRadius\n        max: 500\n" +
		"      - type: maxCalls\n        count: 10\n        windowSeconds: 3600\n"
	if _, err := writeEffectManifest(t, effectManifest("", caps)); err != nil {
		t.Fatalf("a per-call bound beside a maxCalls must load: %v", err)
	}
}

// TestVelocityIsStagedBehindTheDraftVersion pins the staging invariant: the cumulative
// keys ride the blastRadius condition, which is already DRAFT-staged, so a published "0.1"
// manifest using them is refused rather than silently enabling an experimental predicate.
// The gate is what keeps a staged token from becoming part of the language by accident.
func TestVelocityIsStagedBehindTheDraftVersion(t *testing.T) {
	body := "schemaVersion: \"0.1\"\nname: t\nversion: 1.0.0\ncapabilities:\n" +
		"  - target: tool:refund\n    actions: [call]\n    conditions:\n" +
		"      - type: blastRadius\n        maxTotal: 2000\n        windowSeconds: 3600\n"
	_, err := writeEffectManifest(t, body)
	if err == nil {
		t.Fatal("a cumulative blastRadius bound must be refused under the published 0.1 grammar")
	}
	if !strings.Contains(err.Error(), "0.2-draft") {
		t.Fatalf("the refusal must name the draft version that admits it, got: %v", err)
	}
}
