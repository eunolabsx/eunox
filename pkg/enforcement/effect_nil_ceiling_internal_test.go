// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"strings"
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
)

// pkg/capability makes every accessor on a resolved effect nil-safe on the argument that an
// embedder reaches them with whatever ResolveEffect handed back, and a decision point that
// crashes produces no decision at all. This is the leg that CONSUMES three of them in one
// expression, so guarding two of the three only moved the panic one argument along — the
// outcome AuditDetails' own comment claims to have avoided.
func TestCheckEffectCeiling_NilEffectRefusesRatherThanPanicking(t *testing.T) {
	e := New()
	e.effectCeiling = &capability.EffectCeiling{MaxEffectClass: capability.EffectCompensable}

	resp := e.checkEffectCeiling(evalCtx{}, nil, nil)
	if resp == nil {
		t.Fatal("an effect that cannot be described must not be treated as small or reversible")
	}
	if resp.Decision == capability.DecisionAllow {
		t.Fatalf("decision = %s", resp.Decision)
	}
	if resp.Denial == nil || !strings.Contains(resp.Denial.Message, "unresolved") {
		t.Fatalf("the refusal must name the unresolved effect, got %+v", resp.Denial)
	}
	if resp.Denial.Details["effect_unresolved"] != true {
		t.Fatalf("details = %v", resp.Denial.Details)
	}
}
