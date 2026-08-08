// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"context"
	"fmt"
	"time"

	"github.com/eunolabs/eunox/pkg/capability"
)

// The decision-path half of delegation attenuation. capability/delegation.go owns the grammar
// and the token-boundary narrowing assertion; this applies what the chain says to one call.
//
// Every gate here runs BEFORE any commit, in the same band as the effect ceiling and the
// declassify check, so a refused call leaves no spent quota, no phantom antecedent, no label
// change.
//
// A delegation refusal is a DENY, never an escalation: a delegate reaching past what it was
// handed isn't awaiting anyone's approval — no human at this point can grant authority the
// delegator itself withheld.

// delegationConditionType is the condition_type stamped on a delegation refusal — a taxonomy
// slot, not a claim that a condition ran, like the ceiling's and declassify's own.
const delegationConditionType = "delegation"

// checkDelegationTarget refuses a call whose target no hop of the chain admits. Runs early,
// before the constraint's conditions, since it doesn't depend on them: the manifest may permit
// the target and every condition pass, and the call can still be one this delegate wasn't
// handed.
func (e *Engine) checkDelegationTarget(ec evalCtx) *capability.EnforceResponse {
	if ec.req == nil {
		return nil
	}
	return DelegationTargetDenial(ec.req.Delegation, canonicalApprovalTarget(ec.req), ec.auditOnly(), ec.requestID, ec.now)
}

// DelegationTargetDenial is the ONE construction of the target-axis refusal, exported because
// the gate must run on paths with no manifest engine at all (the PDP's match-only
// resources/unsubscribe, a JWT-only or wiretap route) — three of six enforced methods were
// unbound by the chain before this existed, each having hand-rolled its own deny or forgotten
// to.
//
// An empty target is itself a refusal: an unresolvable target can't be scoped against the
// chain either, and admitting it would make unresolvability the way past every hop's grant.
// Returns nil when there is no chain or the chain admits the target.
func DelegationTargetDenial(chain *capability.DelegationChain, target string, auditOnly bool, requestID, now string) *capability.EnforceResponse {
	if chain.IsEmpty() {
		return nil
	}
	if target == "" {
		return delegationDenial(auditOnly, requestID, now, "unresolvable_target", "",
			"the request carries no resolvable target, so it cannot be scoped against the delegation chain it presents", nil)
	}
	ok, blockedBy := chain.PermitsTarget(target)
	if ok {
		return nil
	}
	return delegationDenial(auditOnly, requestID, now, "target_not_delegated", blockedBy,
		fmt.Sprintf("%s is not among the actions delegated to %q; a delegate cannot reach past the authority its delegator handed it", target, blockedBy),
		map[string]interface{}{"target": target})
}

// checkDelegationEffectClass refuses a call whose resolved effect is more consequential than
// the chain's tightest maxEffectClass. Reads the SAME ResolveEffect the ceiling and the two
// effect conditions read, so the bounds can't disagree about the call's effect. Composes with
// the ceiling rather than replacing it — the more restrictive of the two refuses first.
func (e *Engine) checkDelegationEffectClass(ec evalCtx, eff *capability.ResolvedEffect) *capability.EnforceResponse {
	if ec.req == nil || ec.req.Delegation.IsEmpty() || eff == nil {
		return nil
	}
	cap0, subject, capped := ec.req.Delegation.EffectClassCap()
	if !capped || capability.EffectClassAtMost(eff.Class, cap0) {
		return nil
	}
	return delegationDenial(ec.auditOnly(), ec.requestID, ec.now, "effect_class", subject,
		fmt.Sprintf("this action's effect class %q exceeds the %q cap delegated to %q", eff.Class, cap0, subject),
		map[string]interface{}{"effect_class": eff.Class, "delegated_max_effect_class": cap0})
}

// DelegationEffectClassVerdictFor answers ONE question — "does this action exceed the
// tightest maxEffectClass the chain delegated?" — for an already-selected constraint, without
// evaluating conditions or committing state. Returns the cap's refusal, or nil.
//
// It is the delegation half of the COMPOSED case CeilingVerdictFor exists for: the two halves
// of one hardening path previously disagreed about whether a chain was in scope (redaction
// applied it, the verdict didn't), so a delegated caller capped below the route's ceiling got
// the wrong refusal hardened.
//
// What it composes is an ATTRIBUTION, not extra hardness: a delegation refusal is downgradable
// by design, so this only ever replaces one soft refusal with another that names the axis and
// hop instead of the wrapping layer's generic failure. Use ONLY on an already-refused call,
// and never where a HARDER verdict is available.
func (e *Engine) DelegationEffectClassVerdictFor(_ context.Context, req *capability.EnforceRequest, matched *capability.Constraint) *capability.EnforceResponse {
	if e == nil || req == nil || matched == nil || req.Delegation.IsEmpty() {
		return nil
	}
	effect := capability.ResolveEffect(matched.Effect, req.Arguments)
	ec := evalCtx{req: req, matched: matched, requestID: NewRequestID(), now: e.clock.Now().UTC().Format(time.RFC3339Nano)}
	return e.checkDelegationEffectClass(ec, effect)
}

// IsDelegationRefusal reports whether d is a refusal one of the delegation gates produced.
// Reads the taxonomy slot (not the details discriminator) because it's the one thing nothing
// else can set — an author can't attach delegationConditionType to a target.
//
// Exported for a composing layer deciding whether it has anything to ADD: a verdict on this
// axis composed onto a refusal already on this axis is a REPLACEMENT, not a hardening.
func IsDelegationRefusal(d *capability.DenialInfo) bool {
	return d != nil && d.ConditionType == delegationConditionType
}

// delegationDenial builds the refusal every gate above returns, single-sourcing the code,
// taxonomy slot, and details shape.
//
// Downgradable (HardDeny unset) by design: a delegation bound is an authorization verdict like
// the manifest's own no-match deny, and --audit exists to preview enforcement including a
// delegation chain being rolled out. Only refusals where forwarding would destroy evidence or
// an invariant (declassify, ceiling, a failed state write) must survive --audit; a delegate
// overreaching on an observe route is a prediction being logged.
func delegationDenial(auditOnly bool, requestID, now, reason, hop, message string, extra map[string]interface{}) *capability.EnforceResponse {
	details := map[string]interface{}{
		// The discriminator every refusal on this axis carries, mirroring
		// capability.FlowAuditDetailKey for information-flow events. Kept a literal (one
		// producer) rather than a constant, which FlowAuditDetailKey needs.
		"delegation": true,
		"reason":     reason,
	}
	if hop != "" {
		details["delegate"] = hop
	}
	for k, v := range extra {
		details[k] = v
	}
	resp := denyResponse(requestID, now, auditOnly, nil, capability.DenialInfo{
		Code:          capability.ErrCodeAuthorizationFailed,
		ConditionType: delegationConditionType,
		Message:       message,
		Details:       details,
	})
	return &resp
}

// delegatedRedaction returns the extra redactFields obligation a chain composes onto the
// matched constraint's own, or nil.
//
// A SEPARATE obligation rather than a merge, since the two have different provenance
// (manifest vs. delegators) and the transport unions them anyway — keeping them apart lets the
// audit record show which is which.
func delegatedRedaction(chain *capability.DelegationChain) *capability.Obligation {
	fields := chain.RedactFields()
	if len(fields) == 0 {
		return nil
	}
	return &capability.Obligation{Type: capability.DirectiveTypeRedactFields, Paths: fields}
}

// delegatedAllowLabels intersects a flowLabel condition's Allow set with the cap every hop of
// the chain composed. Intersection is the only safe composition (a hop's cap can only remove
// entries); capped distinguishes "no cap" from "capped to nothing", the strictest a hop can
// say.
func delegatedAllowLabels(allow []string, chain *capability.DelegationChain) []string {
	capped, isCapped := chain.AllowedLabelCap()
	if !isCapped {
		return allow
	}
	permitted := make(map[string]bool, len(capped))
	for _, l := range capped {
		permitted[l] = true
	}
	// Preserves the condition's own ordering: this is reported as allowLabels in a denial's
	// details, and reordering it would make the record harder to match to the manifest.
	out := make([]string, 0, len(allow))
	for _, l := range allow {
		if permitted[l] {
			out = append(out, l)
		}
	}
	return out
}
