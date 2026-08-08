// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"context"
	"testing"
	"time"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
)

// enforcement.WithConditionHandler redefines what a condition TYPE means for an embedder's
// engine. The manifest path dispatches through that registry; the JWT capability-claim path
// dispatches through it for allowedValues and CANNOT for allowedOperations — the `op=`
// shorthand names no operation argument, so its arm scans every argument while the engine's
// handler hard-denies exactly that empty argument. Routing the arm through the override would
// not enforce it, it would deny every `op=` grant in existence.
//
// So the divergence is refused rather than papered over: at startup where the wiring is
// visible (transport.WrapRoutesWithJWT), and here at the request, for a JWTPDP built directly.

// strictOperations is the shape of the override this refusal exists for: an embedder's
// stricter allowedOperations, which the claim arm would otherwise silently not apply.
func strictOperations() enforcement.Option {
	return enforcement.WithConditionHandler(capability.ConditionTypeAllowedOperations,
		enforcement.ConditionHandlerFunc(func(_ context.Context, _ capability.Condition, _ *capability.EnforceRequest) *enforcement.ConditionError {
			return &enforcement.ConditionError{
				Code:          capability.ErrCodeOperationNotPermitted,
				ConditionType: capability.ConditionTypeAllowedOperations,
				Message:       "embedder policy: no operation is permitted from this deployment",
			}
		}))
}

func queryDBPDP(engine *enforcement.Engine) *ManifestPDP {
	return NewManifestPDP([]capability.Constraint{{
		Target:  "tool:query_db",
		Actions: []string{"call"},
	}}, engine, nil)
}

// TestJWTClaimOperations_RefusedWhenTheDecidingEngineOverridesTheHandler is the regression:
// with the override wired, an `op=SELECT` grant must be refused rather than judged by the
// predicate this build ships while the manifest path is judged by the replacement.
func TestJWTClaimOperations_RefusedWhenTheDecidingEngineOverridesTheHandler(t *testing.T) {
	key := newTestKey(t, "k1")
	target := EnforceTarget{Type: capability.TargetTypeTool, Name: "query_db"}
	args := map[string]interface{}{"sql": "SELECT * FROM users"}

	// Control: the SAME call, same claim, against an engine carrying the shipped handler.
	// Without it, "the override case denies" is satisfied by denying every op= grant.
	shipped, cleanup := makeJWTPDPWithInner(t, key, queryDBPDP(enforcement.New()))
	defer cleanup()
	ctrlCtx := makeJWTCtx(t, shipped, makeIDPToken(t, key, []string{"tool:query_db?op=SELECT"}, "", "", "a1", time.Now().Add(time.Hour)))
	if got := shipped.Decide(ctrlCtx, "sess", target, args, "127.0.0.1"); got.Decision != capability.DecisionAllow {
		t.Fatalf("control: an op= grant on an un-overridden engine must still be allowed, got %s (%+v)", got.Decision, got.Denial)
	}

	overridden, cleanup2 := makeJWTPDPWithInner(t, key, queryDBPDP(enforcement.New(strictOperations())))
	defer cleanup2()
	ctx := makeJWTCtx(t, overridden, makeIDPToken(t, key, []string{"tool:query_db?op=SELECT"}, "", "", "a1", time.Now().Add(time.Hour)))
	resp := overridden.Decide(ctx, "sess", target, args, "127.0.0.1")

	if resp.Decision == capability.DecisionAllow {
		t.Fatal("an op= grant was judged by the shipped predicate while the manifest path enforces the embedder's replacement")
	}
	if resp.Denial == nil || resp.Denial.ConditionType != capability.ConditionTypeAllowedOperations {
		t.Fatalf("condition_type = %+v, want allowedOperations", resp.Denial)
	}
	if got := resp.Denial.Details["reason"]; got != "handler_override_unsupported" {
		t.Fatalf("details.reason = %v, want handler_override_unsupported: the record must say the claim path could not honor the override, "+
			"not that the operation was outside the permitted set", got)
	}
}

// The override question must resolve to whatever is actually DECIDING, through any stack of
// wrappers: a JWTPDP answering on its own behalf ("I hold no engine") is the divergence.
func TestConditionHandlerOverridden_ResolvesThroughTheWrapperStack(t *testing.T) {
	key := newTestKey(t, "k1")

	bare, cleanup := makeJWTPDPWithInner(t, key, queryDBPDP(enforcement.New()))
	defer cleanup()
	if bare.ConditionHandlerOverridden(capability.ConditionTypeAllowedOperations) {
		t.Fatal("an engine carrying only built-ins reports no override")
	}

	wrapped, cleanup2 := makeJWTPDPWithInner(t, key, queryDBPDP(enforcement.New(strictOperations())))
	defer cleanup2()
	if !wrapped.ConditionHandlerOverridden(capability.ConditionTypeAllowedOperations) {
		t.Fatal("the wrapper must answer for the PDP it wraps, which is what actually decides")
	}
	// Only the replaced type is affected: an unrelated condition still reports the built-in.
	if wrapped.ConditionHandlerOverridden(capability.ConditionTypeAllowedValues) {
		t.Fatal("an override for one type must not report every other type as overridden")
	}
	// A JWT-only route holds no inner PDP and therefore no engine.
	only, cleanup3 := makeJWTPDPWithInner(t, key, nil)
	defer cleanup3()
	if only.ConditionHandlerOverridden(capability.ConditionTypeAllowedOperations) {
		t.Fatal("a JWT-only route has no engine to have overridden anything")
	}
}

// The claim path's OTHER condition type is unaffected: allowedValues has a shared handler, so
// an override there is enforced through the embedder's handler seam rather than refused.
func TestJWTClaimValues_OverrideIsEnforcedNotRefused(t *testing.T) {
	key := newTestKey(t, "k1")
	permissive := enforcement.WithConditionHandler(capability.ConditionTypeAllowedValues,
		enforcement.ConditionHandlerFunc(func(_ context.Context, _ capability.Condition, _ *capability.EnforceRequest) *enforcement.ConditionError {
			return nil // the embedder's allowedValues admits this call
		}))

	p, cleanup := makeJWTPDPWithInner(t, key, NewManifestPDP([]capability.Constraint{{
		Target:  "tool:read_file",
		Actions: []string{"call"},
	}}, enforcement.New(permissive), nil))
	defer cleanup()

	ctx := makeJWTCtx(t, p, makeIDPToken(t, key, []string{"tool:read_file?path=/reports/*"}, "", "", "a1", time.Now().Add(time.Hour)))
	// A path the SHIPPED predicate would reject: only the embedder's handler admits it.
	resp := p.Decide(ctx, "sess", EnforceTarget{Type: capability.TargetTypeTool, Name: "read_file"},
		map[string]interface{}{"path": "/etc/passwd"}, "127.0.0.1")
	if resp.Decision != capability.DecisionAllow {
		t.Fatalf("decision = %s (%+v), want allow: an allowedValues override reaches the claim path through the deciding PDP",
			resp.Decision, resp.Denial)
	}
}
