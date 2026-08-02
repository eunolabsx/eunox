// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"context"
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
