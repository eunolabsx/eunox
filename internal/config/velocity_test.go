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

// TestVelocityRejectsTwoBoundsOnOneBucket pins the distinct-bucket rule. Two conditions
// of the SAME kind sharing a windowSeconds address one physical counter bucket, so every
// call is charged to it once per condition and the effective limit is halved — a limit the
// manifest never states. The faithful rewrite is one condition with the lower bound, so the
// shape is refused at LOAD rather than enforced at a bound the author did not author.
func TestVelocityRejectsTwoBoundsOnOneBucket(t *testing.T) {
	cases := map[string]struct{ conds, wantNamespace string }{
		"two cumulative bounds on one window": {
			conds: "      - type: blastRadius\n        maxTotal: 2000\n        windowSeconds: 3600\n" +
				"      - type: blastRadius\n        maxTotal: 500\n        windowSeconds: 3600\n",
			wantNamespace: "blastRadius",
		},
		"two call counts on one window": {
			conds: "      - type: maxCalls\n        count: 10\n        windowSeconds: 3600\n" +
				"      - type: maxCalls\n        count: 3\n        windowSeconds: 3600\n",
			wantNamespace: "maxCalls",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			caps := "  - target: tool:refund\n    actions: [call]\n    conditions:\n" + tc.conds
			_, err := writeEffectManifest(t, effectManifest("", caps))
			if err == nil {
				t.Fatal("want a load error refusing the shared bucket, got none")
			}
			if !strings.Contains(err.Error(), "share one counter bucket") {
				t.Fatalf("error must explain the conflict, got: %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantNamespace) {
				t.Fatalf("error must name the colliding condition kind %q, got: %v", tc.wantNamespace, err)
			}
		})
	}
}

// TestVelocityAcceptsBothBoundsOnOneCapability is the shape the two accountings exist for:
// "no more than 10 refunds an hour AND no more than 2000 units an hour". The two draw on
// separately-namespaced keys and are admitted in one atomic backend call, so the
// combination is ordinary policy and must load — in either authoring order, and with
// distinct windows of the same kind alongside it.
func TestVelocityAcceptsBothBoundsOnOneCapability(t *testing.T) {
	velocity := "      - type: blastRadius\n        maxTotal: 2000\n        windowSeconds: 3600\n"
	maxCalls := "      - type: maxCalls\n        count: 10\n        windowSeconds: 3600\n"
	cases := map[string]string{
		// Order must not decide whether the shape is legal.
		"velocity then maxCalls": velocity + maxCalls,
		"maxCalls then velocity": maxCalls + velocity,
		// Different windows of the same kind are independent limits, not a shared bucket.
		"both kinds across two windows": velocity + maxCalls +
			"      - type: maxCalls\n        count: 100\n        windowSeconds: 86400\n" +
			"      - type: blastRadius\n        maxTotal: 20000\n        windowSeconds: 86400\n",
	}
	for name, conds := range cases {
		t.Run(name, func(t *testing.T) {
			caps := "  - target: tool:refund\n    actions: [call]\n    conditions:\n" + conds
			if _, err := writeEffectManifest(t, effectManifest("", caps)); err != nil {
				t.Fatalf("a counted bound beside a weighted one must load: %v", err)
			}
		})
	}
}

// TestVelocityAllowsAPerCallBoundBesideMaxCalls is the third combination: a per-call
// blastRadius consumes no quota at all, so it addresses no bucket and can sit beside a
// maxCalls on any window.
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
