// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// The composed-refusal contract for the effect ceiling, the sibling of the interface-pin
// case in surface_pin_test.go.
//
// JWTPDP.Decide short-circuits above the inner ManifestPDP on two of its OWN denial paths
// — a target absent from mcp.capabilities, and a failing JWT condition. On those paths
// decideInner never runs, so the inner PDP's effect ceiling never evaluated. The call was
// still refused, so this was not a fail-open in the usual sense; what was lost was the KIND
// of refusal. The escalation never happened (so an action that should have entered the
// approval queue silently did not, and escalation counts under-reported), and the refusal
// stayed downgradable — a route running --audit forwards a soft deny, so a JWT-wrapped
// route FORWARDED a call the same manifest without the JWT refuses outright.
//
// The assertions here compare the composed refusal against the BARE ManifestPDP control,
// not only against itself: "the JWT deny is hard" is satisfiable by hardening every JWT
// deny, which would silently turn a wiretap route into a blocking one.

// ceilingPDP builds a ManifestPDP whose engine carries a ceiling admitting nothing above
// reversible, over a single irreversible tool the manifest permits.
func ceilingPDP(t *testing.T, onExceed string) *ManifestPDP {
	t.Helper()
	ceiling := &capability.EffectCeiling{MaxEffectClass: capability.EffectReversible, OnExceed: onExceed}
	return NewManifestPDP(
		[]capability.Constraint{{
			Target:  "tool:wire_transfer",
			Actions: []string{"call"},
			Effect:  &capability.EffectContract{Class: capability.EffectIrreversible},
		}},
		enforcement.New(enforcement.WithEffectCeiling(ceiling)),
		killswitch.NewInMemory(),
	)
}

// TestEffectCeilingSurvivesAJWTShortCircuitDeny is the regression: on both JWT
// short-circuit paths the composed refusal must carry the ceiling's own verdict —
// ESCALATION_REQUIRED, hard, with the consequence inputs — rather than a bare
// AUTHORIZATION_FAILED an --audit route would forward.
func TestEffectCeilingSurvivesAJWTShortCircuitDeny(t *testing.T) {
	const sessionID = "sess-ceiling-jwt"
	key := newTestKey(t, "k1")

	cases := []struct {
		name string
		caps []string
	}{
		// The JWT's capability allowlist does not name the tool at all.
		{"capability claim miss", []string{"tool:other_tool"}},
		// The JWT names the tool but its condition rejects this call's arguments.
		{"jwt condition failure", []string{"tool:wire_transfer?account=/savings/*"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			inner := ceilingPDP(t, capability.OnExceedEscalate)
			args := map[string]interface{}{"account": "/checking/1"}
			target := EnforceTarget{Type: capability.TargetTypeTool, Name: "wire_transfer"}

			// Control: the same call through the bare manifest PDP escalates.
			ctrl := inner.Decide(context.Background(), sessionID, target, args, "")
			if ctrl.Decision != capability.DecisionEscalate {
				t.Fatalf("control: the bare manifest PDP must escalate this call, got %s (%+v)", ctrl.Decision, ctrl.Denial)
			}

			jp, cleanup := makeJWTPDPWithInner(t, key, inner)
			defer cleanup()
			ctx := makeJWTCtx(t, jp, makeJWTToken(t, key, c.caps))
			got := jp.Decide(ctx, sessionID, target, args, "")

			if got.Decision != capability.DecisionEscalate {
				t.Fatalf("decision = %s, want %s: the escalation the manifest would have raised is lost, "+
					"so the action never enters the approval queue and `eunox stats` under-counts escalations",
					got.Decision, capability.DecisionEscalate)
			}
			if got.Denial == nil {
				t.Fatal("a refusal must carry a denial")
			}
			if got.Denial.Code != capability.ErrCodeEscalationRequired {
				t.Errorf("code = %q, want %q", got.Denial.Code, capability.ErrCodeEscalationRequired)
			}
			if !got.Denial.BlockOverride {
				t.Errorf("BlockOverride = false: an --audit route would downgrade this to a forward and perform\n"+
					"the very consequential action the ceiling flagged. denial = %+v", got.Denial)
			}
			if len(got.Obligations) != 0 {
				t.Errorf("an unforwardable refusal has no response to redact, got obligations %v", got.Obligations)
			}
			// The consequence inputs a human in the approval queue acts on.
			if got.Denial.Details["ceiling_exceeded"] == nil {
				t.Errorf("the escalation must carry ceiling_exceeded, got details %v", got.Denial.Details)
			}
			if got.Denial.Details["effect_class"] != capability.EffectIrreversible {
				t.Errorf("effect_class = %v, want %q", got.Denial.Details["effect_class"], capability.EffectIrreversible)
			}
			// The wrapping layer's own reason survives: an operator fixing the token still
			// needs to see the authorization failure.
			if !strings.Contains(got.Denial.Message, "wrapping authorization layer") {
				t.Errorf("message must carry the JWT's own refusal, got %q", got.Denial.Message)
			}
		})
	}
}

// TestEffectCeilingShortCircuitHonorsOnExceedDeny covers the other ceiling outcome: with
// onExceed: deny there is no approval path, so the composed refusal is a plain deny
// attributed to the ceiling rather than an escalation.
func TestEffectCeilingShortCircuitHonorsOnExceedDeny(t *testing.T) {
	key := newTestKey(t, "k1")
	inner := ceilingPDP(t, capability.OnExceedDeny)
	jp, cleanup := makeJWTPDPWithInner(t, key, inner)
	defer cleanup()

	ctx := makeJWTCtx(t, jp, makeJWTToken(t, key, []string{"tool:other_tool"}))
	got := jp.Decide(ctx, "sess-deny", EnforceTarget{Type: capability.TargetTypeTool, Name: "wire_transfer"}, nil, "")

	if got.Decision != capability.DecisionDeny {
		t.Fatalf("decision = %s, want deny", got.Decision)
	}
	if got.Denial == nil || got.Denial.ConditionType != "effectCeiling" {
		t.Fatalf("the refusal must be attributed to the ceiling, got %+v", got.Denial)
	}
}

// TestJWTShortCircuitDenyStaysSoftUnderTheCeiling is the other half: the hardening must
// fire only when the ceiling would ACTUALLY have refused. A JWT deny for a call the
// manifest's ceiling admits is an ordinary policy verdict, and an --audit route is
// documented to forward exactly those.
func TestJWTShortCircuitDenyStaysSoftUnderTheCeiling(t *testing.T) {
	key := newTestKey(t, "k1")
	ceiling := &capability.EffectCeiling{MaxEffectClass: capability.EffectIrreversible}
	inner := NewManifestPDP(
		[]capability.Constraint{{
			Target:  "tool:wire_transfer",
			Actions: []string{"call"},
			Effect:  &capability.EffectContract{Class: capability.EffectReversible},
		}},
		enforcement.New(enforcement.WithEffectCeiling(ceiling)),
		killswitch.NewInMemory(),
	)
	jp, cleanup := makeJWTPDPWithInner(t, key, inner)
	defer cleanup()

	ctx := makeJWTCtx(t, jp, makeJWTToken(t, key, []string{"tool:other_tool"}))
	got := jp.Decide(ctx, "sess-under", EnforceTarget{Type: capability.TargetTypeTool, Name: "wire_transfer"}, nil, "")

	if got.Denial == nil {
		t.Fatal("want a denial")
	}
	if got.Decision != capability.DecisionDeny || got.Denial.BlockOverride {
		t.Errorf("a JWT deny for a call within the ceiling must stay an ordinary downgradable deny, got %s hard=%v",
			got.Decision, got.Denial.BlockOverride)
	}
}

// TestJWTShortCircuitDenyStaysSoftWithNoCeiling pins that a policy declaring no ceiling is
// untouched — the check must cost nothing and change nothing where no bound was authored.
func TestJWTShortCircuitDenyStaysSoftWithNoCeiling(t *testing.T) {
	key := newTestKey(t, "k1")
	inner := newTestManifestPDP(capability.Constraint{
		Target:  "tool:wire_transfer",
		Actions: []string{"call"},
		Effect:  &capability.EffectContract{Class: capability.EffectIrreversible},
	})
	jp, cleanup := makeJWTPDPWithInner(t, key, inner)
	defer cleanup()

	ctx := makeJWTCtx(t, jp, makeJWTToken(t, key, []string{"tool:other_tool"}))
	got := jp.Decide(ctx, "sess-none", EnforceTarget{Type: capability.TargetTypeTool, Name: "wire_transfer"}, nil, "")

	if got.Denial == nil || got.Denial.BlockOverride || got.Decision != capability.DecisionDeny {
		t.Errorf("with no effectCeiling authored, a JWT deny must be unchanged, got %s %+v", got.Decision, got.Denial)
	}
}

// TestCeilingHardeningSkipsATargetTheManifestDoesNotGovern pins the structural gates. A
// target the manifest never names, or names without the required action, is refused by the
// manifest on its own terms and never reaches the ceiling — so the composed refusal must
// not claim a ceiling verdict for it.
func TestCeilingHardeningSkipsATargetTheManifestDoesNotGovern(t *testing.T) {
	key := newTestKey(t, "k1")
	ceiling := &capability.EffectCeiling{MaxEffectClass: capability.EffectReversible}
	inner := NewManifestPDP(
		[]capability.Constraint{{
			// Present in the manifest, but with no "call" action, so the manifest denies
			// with CAPABILITY_DENIED long before the ceiling could run.
			Target:  "tool:wire_transfer",
			Actions: []string{"read"},
			Effect:  &capability.EffectContract{Class: capability.EffectIrreversible},
		}},
		enforcement.New(enforcement.WithEffectCeiling(ceiling)),
		killswitch.NewInMemory(),
	)
	jp, cleanup := makeJWTPDPWithInner(t, key, inner)
	defer cleanup()
	ctx := makeJWTCtx(t, jp, makeJWTToken(t, key, []string{"tool:other_tool"}))

	for _, name := range []string{"wire_transfer", "not_in_the_manifest"} {
		got := jp.Decide(ctx, "sess-ungoverned", EnforceTarget{Type: capability.TargetTypeTool, Name: name}, nil, "")
		if got.Decision != capability.DecisionDeny || (got.Denial != nil && got.Denial.BlockOverride) {
			t.Errorf("%s: a target the manifest refuses before the ceiling must not be re-labelled, got %s %+v",
				name, got.Decision, got.Denial)
		}
	}
}

// TestCeilingHardeningCommitsNoSessionState is the invariant the narrow seam exists to
// preserve: evaluating the ceiling for a call that is already refused must leave neither a
// sequenceBlock antecedent nor a consumed maxCalls slot behind. The constraint below
// carries both a committing condition and an over-ceiling contract; after a JWT
// short-circuit deny, a fresh decision on the bare manifest PDP must still see a pristine
// quota and no antecedent.
func TestCeilingHardeningCommitsNoSessionState(t *testing.T) {
	key := newTestKey(t, "k1")
	counter := newCountingCallCounter()
	ceiling := &capability.EffectCeiling{MaxEffectClass: capability.EffectReversible}
	inner := NewManifestPDP(
		[]capability.Constraint{{
			Target:  "tool:wire_transfer",
			Actions: []string{"call"},
			Effect:  &capability.EffectContract{Class: capability.EffectIrreversible},
			Conditions: []capability.Condition{
				&capability.MaxCallsCondition{Count: 5, WindowSeconds: 60},
			},
		}},
		enforcement.New(enforcement.WithEffectCeiling(ceiling), enforcement.WithCallCounter(counter)),
		killswitch.NewInMemory(),
	)
	jp, cleanup := makeJWTPDPWithInner(t, key, inner)
	defer cleanup()

	ctx := makeJWTCtx(t, jp, makeJWTToken(t, key, []string{"tool:other_tool"}))
	got := jp.Decide(ctx, "sess-nostate", EnforceTarget{Type: capability.TargetTypeTool, Name: "wire_transfer"}, nil, "")
	if got.Decision != capability.DecisionEscalate {
		t.Fatalf("decision = %s, want escalate", got.Decision)
	}
	if n := counter.writes(); n != 0 {
		t.Fatalf("the ceiling seam wrote %d counter entries for a call that is never forwarded; "+
			"a refused call must leave neither a maxCalls slot nor a sequenceBlock antecedent behind", n)
	}
}

// countingCallCounter counts every mutating call-counter operation, so a test can assert
// that a refusal path committed nothing. It EMBEDS the real in-memory backend rather than
// reimplementing the contract, so a method added to capability.CallCounter is inherited
// (and, being uncounted, cannot make this assertion silently weaker by failing to compile
// into it). Reads (Peek) are deliberately not counted: a pure observation commits no
// decision state, which is exactly what makes the ceiling seam safe to run at all.
type countingCallCounter struct {
	*callcounter.InMemory
	n int
}

func newCountingCallCounter() *countingCallCounter {
	return &countingCallCounter{InMemory: callcounter.NewInMemory()}
}

func (c *countingCallCounter) writes() int { return c.n }

func (c *countingCallCounter) IncrementAndGet(ctx context.Context, key string, windowSec, maxEntries int) (int64, error) {
	c.n++
	return c.InMemory.IncrementAndGet(ctx, key, windowSec, maxEntries)
}

func (c *countingCallCounter) AdmitAll(ctx context.Context, buckets []capability.QuotaBucket) (admitted bool, deniedIndex int, total float64, retryAfter time.Duration, err error) {
	c.n += len(buckets)
	return c.InMemory.AdmitAll(ctx, buckets)
}

// TestCeilingHardeningNeverSoftensTheRefusal pins the two ways the composed verdict could
// come back WEAKER than the JWT deny it replaces. The ceiling's onExceed:deny arm is built
// with the matched constraint's own audit posture and carries no obligations, so taking it
// wholesale both downgraded a blocking refusal into a forwarded one and dropped the
// redaction that forward then needed.
func TestCeilingHardeningNeverSoftensTheRefusal(t *testing.T) {
	key := newTestKey(t, "k1")
	ceiling := &capability.EffectCeiling{MaxEffectClass: capability.EffectReversible, OnExceed: capability.OnExceedDeny}
	inner := NewManifestPDP(
		[]capability.Constraint{{
			Target:  "tool:wire_transfer",
			Actions: []string{"call"},
			// Observe mode on the entry itself: this is what the ceiling's deny arm
			// inherits, and what must not survive onto the composed refusal.
			Enforcement: "audit",
			Effect:      &capability.EffectContract{Class: capability.EffectIrreversible},
			Directives:  []capability.Directive{capability.RedactFieldsDirective{Fields: []string{"account"}}},
		}},
		enforcement.New(enforcement.WithEffectCeiling(ceiling)),
		killswitch.NewInMemory(),
	)
	jp, cleanup := makeJWTPDPWithInner(t, key, inner)
	defer cleanup()

	ctx := makeJWTCtx(t, jp, makeJWTToken(t, key, []string{"tool:other_tool"}))
	got := jp.Decide(ctx, "sess-soft", EnforceTarget{Type: capability.TargetTypeTool, Name: "wire_transfer"}, nil, "")

	require.NotNil(t, got.Denial)
	assert.False(t, got.AuditOnly,
		"the JWT's own refusal blocked on this enforce route; the ceiling must not downgrade it to a forward")
	// The refusal is still downgradable by a ROUTE running --audit, and such a forward
	// must carry the manifest's redaction or the response reaches the host unmasked.
	assert.NotEmpty(t, got.Obligations,
		"a forwardable refusal must keep the redactFields obligations the same call gets without a ceiling")
}

// TestHardeningReachesANonManifestInner is the regression for the composition seam itself.
// The wrapper used to reach its inner PDP through a type assertion to the concrete
// *ManifestPDP, so a deployment whose inner was ANY other implementation — an external
// policy engine, a decorator, a test double — composed as though the inner held no pin, no
// ceiling and no obligations. That failure is silent: the refusal still refuses, so nothing
// breaks loudly; it just refuses more WEAKLY than the same policy without the JWT, which is
// the exact inversion of "a token may only ever restrict".
//
// The double here is deliberately not a *ManifestPDP and not a wrapper around one. It
// contributes both halves of what an inner owes a refusal — hardening it against downgrade,
// and attaching the obligations a downgraded forward would need — so the test fails if
// either is dropped in transit, and it records the call identity it was handed so a
// hardening run against the wrong session or a stripped argument map cannot pass either.
func TestHardeningReachesANonManifestInner(t *testing.T) {
	key := newTestKey(t, "k1")
	var (
		calls        int
		gotSessionID string
		gotTarget    string
		gotArgs      map[string]interface{}
	)
	inner := &staticPDP{
		decision: capability.EnforceResponse{Decision: capability.DecisionAllow},
		harden: func(sessionID string, r capability.EnforceResponse, target EnforceTarget, args map[string]interface{}) capability.EnforceResponse {
			calls++
			gotSessionID, gotTarget, gotArgs = sessionID, target.Name, args
			r.Denial.BlockOverride = true
			r.Obligations = []capability.Obligation{{Type: capability.DirectiveTypeRedactFields, Paths: []string{"account"}}}
			return r
		},
	}

	jp, cleanup := makeJWTPDPWithInner(t, key, inner)
	defer cleanup()

	ctx := makeJWTCtx(t, jp, makeJWTToken(t, key, []string{"tool:other_tool"}))
	args := map[string]interface{}{"amount": "5000"}
	got := jp.Decide(ctx, "sess-nonmanifest", EnforceTarget{Type: capability.TargetTypeTool, Name: "wire_transfer"}, args, "")

	require.NotNil(t, got.Denial)
	require.Equal(t, 1, calls, "the wrapper must reach its inner through the contract, whatever the inner's concrete type")
	assert.True(t, got.Denial.BlockOverride,
		"the inner's hardening must survive composition; the type assertion to *ManifestPDP dropped it")
	assert.NotEmpty(t, got.Obligations,
		"the inner's obligations must survive composition, or a downgraded forward reaches the host unmasked")

	assert.Equal(t, "sess-nonmanifest", gotSessionID)
	assert.Equal(t, "wire_transfer", gotTarget)
	assert.Equal(t, args, gotArgs)
}
