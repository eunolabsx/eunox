// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/flowlabelstore"
)

// quarantinedCtx returns a context carrying a validated token whose delegation chain reaches
// exactly the named targets — the shape a control plane mints for a sub-agent.
func quarantinedCtx(targets ...string) context.Context {
	t := append([]string{}, targets...)
	return WithJWTClaims(context.Background(), &JWTClaims{
		Subject: "user@example.com",
		Delegation: &capability.DelegationChain{
			Actors: []string{"worker"},
			Grants: []capability.DelegationGrant{{Subject: "worker", Targets: &t}},
		},
	})
}

func gatedEngine() *enforcement.Engine {
	return enforcement.New(
		enforcement.WithCallCounter(callcounter.NewInMemory()),
		enforcement.WithFlowLabelStore(flowlabelstore.NewInMemory()),
	)
}

// TestDelegationGate_Sampling is the hole a delegated token could otherwise drive straight
// through: sampling/createMessage is the one enforced method that reaches the HOST's model, so
// it is the one a quarantined delegate most wants, and it builds its own enforce request
// rather than going through decideTarget.
func TestDelegationGate_Sampling(t *testing.T) {
	caps := []capability.Constraint{{
		Target:  "system:" + capability.MethodSamplingCreateMessage,
		Actions: []string{"*"},
	}}
	p := NewManifestPDP(caps, gatedEngine(), nil)

	// Undelegated: the manifest opted in, so sampling is allowed.
	if got := p.DecideSampling(context.Background(), "s", "1.2.3.4").Decision; got != capability.DecisionAllow {
		t.Fatalf("undelegated sampling = %v, want allow", got)
	}

	// A delegate granted one read tool must not reach inference.
	resp := p.DecideSampling(quarantinedCtx("tool:search"), "s", "1.2.3.4")
	if resp.Decision == capability.DecisionAllow {
		t.Fatal("a delegate whose chain does not name sampling reached the host's model")
	}
	if resp.Denial == nil || resp.Denial.ConditionType != "delegation" {
		t.Fatalf("want a delegation refusal, got %+v", resp.Denial)
	}

	// A chain that DOES grant it still works — the gate scopes, it does not blanket-deny.
	if got := p.DecideSampling(quarantinedCtx("system:"+capability.MethodSamplingCreateMessage), "s", "1.2.3.4").Decision; got != capability.DecisionAllow {
		t.Fatalf("explicitly delegated sampling = %v, want allow", got)
	}
}

// TestDelegationGate_ResourceCancel covers the method authorized by MATCH ALONE. The gate is
// authority rather than metering, so it belongs on the match side of that line: it commits
// nothing and cannot refuse a cancel by spending a budget.
func TestDelegationGate_ResourceCancel(t *testing.T) {
	caps := []capability.Constraint{{Target: "resource:file:///data.txt", Actions: []string{"read"}}}
	p := NewManifestPDP(caps, gatedEngine(), nil)

	if got := p.DecideResourceCancel(context.Background(), "s", "file:///data.txt", "").Decision; got != capability.DecisionAllow {
		t.Fatalf("undelegated cancel = %v, want allow", got)
	}

	resp := p.DecideResourceCancel(quarantinedCtx("tool:search"), "s", "file:///data.txt", "")
	if resp.Decision == capability.DecisionAllow {
		t.Fatal("a delegate whose chain does not name this resource cancelled a subscription to it")
	}

	// The same delegate that may READ the resource may cancel it, so a legitimate
	// subscribe/unsubscribe pair is never split by this gate.
	if got := p.DecideResourceCancel(quarantinedCtx("resource:file:///data.txt"), "s", "file:///data.txt", "").Decision; got != capability.DecisionAllow {
		t.Fatalf("delegated cancel = %v, want allow", got)
	}
}

// TestDelegationGate_UnresolvableTargetRefuses pins the fail-closed arm: a delegated request
// whose target cannot be resolved cannot be scoped against the chain either, and admitting it
// would make an unresolvable target the way past every hop's grant.
func TestDelegationGate_UnresolvableTargetRefuses(t *testing.T) {
	chain := &capability.DelegationChain{
		Actors: []string{"worker"},
		Grants: []capability.DelegationGrant{{Subject: "worker", Targets: &[]string{"tool:search"}}},
	}
	if got := enforcement.DelegationTargetDenial(chain, "", false, "req-1", "now"); got == nil {
		t.Fatal("an unresolvable target on a delegated request must be refused")
	}
	// No chain: nothing to scope against, so nothing to refuse.
	if got := enforcement.DelegationTargetDenial(nil, "", false, "req-1", "now"); got != nil {
		t.Fatalf("an undelegated request must not be refused, got %+v", got)
	}
}

// TestDelegationGate_JWTListFilter covers the catalog leg on a route where the JWT layer is
// the one doing the filtering — a JWT-only or wiretap route, where the inner filter is a
// passthrough. Without the gate the chain bounded what a delegate could CALL while the listing
// still advertised everything its capability claim named.
func TestDelegationGate_JWTListFilter(t *testing.T) {
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()
	p := makeJWTPDP(t, srv, "", "", nil)

	catalog := json.RawMessage(`{"tools":[{"name":"search"},{"name":"wipe_db"}]}`)
	claims := &JWTClaims{
		Subject:         "user@example.com",
		Capabilities:    []string{"tool:search", "tool:wipe_db"},
		HasCapabilities: true,
		Delegation: &capability.DelegationChain{
			Actors: []string{"worker"},
			Grants: []capability.DelegationGrant{{Subject: "worker", Targets: &[]string{"tool:search"}}},
		},
	}
	out := p.FilterToolsList(WithJWTClaims(context.Background(), claims), catalog).Result
	if strings.Contains(string(out), "wipe_db") {
		t.Errorf("the catalog advertised a tool the delegate's call leg refuses:\n%s", out)
	}
	if !strings.Contains(string(out), "search") {
		t.Errorf("the delegated tool was dropped:\n%s", out)
	}
}

// TestDelegationGate_ComposedVerdictIsNotHardened records a deliberate NON-fix, because it
// looks like a gap and is not one.
//
// A review flagged that hardenOnEffectCeiling's composed verdict does not include the
// delegated maxEffectClass, reasoning that an --audit route would therefore forward a call
// "the same manifest refuses outright without the JWT". It would not: a delegation refusal is
// an authorization verdict and is downgradable BY DESIGN, so the full path forwards it under
// --audit too. There is no inversion to close, only a less specific denial reason — and
// CeilingVerdictFor's contract is that a caller may use it ONLY to harden, never to produce a
// refusal that was already downgradable. Composing a soft verdict through it would have broken
// that contract to fix nothing.
//
// The ceiling is different, and that difference is the whole reason it composes: its own
// refusal is HARD, so a JWT short-circuit really would downgrade something the manifest will
// not.
func TestDelegationGate_ComposedVerdictIsNotHardened(t *testing.T) {
	eng := gatedEngine() // no policy effectCeiling
	caps := []capability.Constraint{{
		Target:  "tool:wipe_db",
		Actions: []string{"call"},
		Effect:  &capability.EffectContract{Class: capability.EffectIrreversible},
	}}
	p := NewManifestPDP(caps, eng, nil)
	chain := &capability.DelegationChain{
		Actors: []string{"worker"},
		Grants: []capability.DelegationGrant{{Subject: "worker", MaxEffectClass: capability.EffectReversible}},
	}
	ctx := WithJWTClaims(context.Background(), &JWTClaims{Subject: "u", Delegation: chain})

	// The FULL path's own delegation refusal is downgradable, which is what makes composing
	// it onto a wrapping layer's refusal unnecessary.
	full := p.Decide(ctx, "s", EnforceTarget{Type: capability.TargetTypeTool, Name: "wipe_db"}, nil, "")
	if full.Decision == capability.DecisionAllow {
		t.Fatal("the delegated class cap must refuse this call on the full path")
	}
	if full.Denial == nil || full.Denial.HardDeny {
		t.Fatalf("a delegation refusal is downgradable by design; got HardDeny=%v", full.Denial)
	}
}
