// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"context"
	"fmt"
	"time"

	"github.com/eunolabs/eunox/pkg/capability"
)

// The decision-path half of delegation attenuation. capability/delegation.go owns the
// grammar and the token-boundary assertion that every hop narrows its delegator; this
// applies what the chain says to one call.
//
// Every gate here runs BEFORE anything is committed, in the same band as the effect ceiling
// and the declassify approval check, and for the same reason: a call refused for exceeding
// its delegation is never forwarded, so it must leave no spent quota slot, no phantom
// sequenceBlock antecedent, and no change to the anchor's label set.
//
// A delegation refusal is a DENY, never an escalation. The ceiling escalates because a
// consequence the policy permits may still deserve a human; a delegate reaching past what it
// was handed is not awaiting anyone's approval — no human is in a position to grant, at this
// point in the call, authority the delegator itself chose not to pass on.

// delegationConditionType is the condition_type stamped on a delegation refusal. Like the
// ceiling's and the declassify path's, it is a taxonomy slot rather than a claim that a
// condition ran: no condition failed, and labelling it "principal" would send an operator to
// a manifest scoping rule that is not what refused the call.
const delegationConditionType = "delegation"

// checkDelegationTarget refuses a call whose target no hop of the chain admits. It is the
// authority axis, and it runs early — before the constraint's conditions — because it does
// not depend on them: the manifest may permit the target and every condition may pass, and
// the call is still one this delegate was not handed.
//
// The refusal names the hop that blocked it, which is the only detail that makes it
// actionable: with a three-hop chain, "not permitted" says nothing about which delegator's
// grant to widen. The target itself is already on the record.
func (e *Engine) checkDelegationTarget(req *capability.EnforceRequest, auditOnly bool, requestID, now string) *capability.EnforceResponse {
	if req == nil {
		return nil
	}
	return DelegationTargetDenial(req.Delegation, canonicalApprovalTarget(req), auditOnly, requestID, now)
}

// DelegationTargetDenial is the ONE construction of the target-axis refusal, exported
// because the gate has to run on decision paths that never reach the engine: the PDP's
// match-only `resources/unsubscribe`, and a JWT-only or wiretap route where there is no
// manifest engine at all. Those paths built their own denies before this existed, which is
// how three of the six enforced methods ended up unbound by the chain — a refusal every
// caller has to remember to construct is a refusal someone forgets.
//
// target is the request's canonical "<type>:<bare>" spelling. An EMPTY target on a delegated
// request is itself a refusal: a request whose target cannot be resolved cannot be scoped
// against the chain either, and admitting it would make an unresolvable target the way past
// every hop's grant. Returns nil when there is no chain (the overwhelming majority of
// requests) or the chain admits the target.
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
// the chain's tightest maxEffectClass. It runs with the effect ceiling (it reads the SAME
// single ResolveEffect the ceiling and the two effect conditions read, threaded through the
// call, so the delegation bound and the policy bound cannot disagree about what the call's
// effect was), and it composes with the ceiling rather than replacing it: the policy's bound
// and the delegate's bound both apply, and the more restrictive one refuses first.
func (e *Engine) checkDelegationEffectClass(req *capability.EnforceRequest, eff *capability.ResolvedEffect, auditOnly bool, requestID, now string) *capability.EnforceResponse {
	if req == nil || req.Delegation.IsEmpty() || eff == nil {
		return nil
	}
	cap0, subject, capped := req.Delegation.EffectClassCap()
	if !capped || capability.EffectClassAtMost(eff.Class, cap0) {
		return nil
	}
	return delegationDenial(auditOnly, requestID, now, "effect_class", subject,
		fmt.Sprintf("this action's effect class %q exceeds the %q cap delegated to %q", eff.Class, cap0, subject),
		map[string]interface{}{"effect_class": eff.Class, "delegated_max_effect_class": cap0})
}

// DelegationEffectClassVerdictFor answers ONE question — "is this action more consequential
// than the tightest maxEffectClass the request's chain delegated?" — for a constraint that has
// already been selected, WITHOUT evaluating a single condition and WITHOUT committing any
// state. It returns the refusal the cap would produce, or nil when the request carries no
// chain, no hop caps the class, or the action is within the cap.
//
// It is the delegation half of the COMPOSED case CeilingVerdictFor exists for, and it exists
// because the two halves of one harden path disagreed about whether a chain was in scope: the
// obligations fill applied the chain's composed redactFields to the forwarded response while
// the verdict was taken without the chain at all, so a delegated caller whose hop capped its
// effect class below the route's ceiling got a refusal hardened by the ceiling and not by the
// cap. Both choices were individually defensible and neither was stated where they met.
//
// What it composes is an ATTRIBUTION, not extra hardness: a delegation refusal is downgradable
// by design (see delegationDenial), so this can only ever replace one soft refusal with another
// — the caller's composition takes the AND of the two audit postures, and the caller only
// reaches this at all for a refusal that is already soft. What it buys is that the tape names
// the axis and the hop (`delegation: true`, `reason: effect_class`, `delegate`) instead of
// carrying the wrapping layer's generic authorization failure, which is the same reason the
// ceiling's own seam exists. A caller must therefore still use it ONLY on an already-refused
// call, and never where a HARDER verdict is available.
//
// Like the ceiling's, it reads ONE ResolveEffect of the matched constraint's contract, so it
// cannot disagree with the full path about what the call's effect was.
func (e *Engine) DelegationEffectClassVerdictFor(_ context.Context, req *capability.EnforceRequest, matched *capability.Constraint) *capability.EnforceResponse {
	if e == nil || req == nil || matched == nil || req.Delegation.IsEmpty() {
		return nil
	}
	effect := capability.ResolveEffect(matched.Effect, req.Arguments)
	return e.checkDelegationEffectClass(req, effect, matched.IsAuditOnly(), NewRequestID(), e.clock.Now().UTC().Format(time.RFC3339Nano))
}

// IsDelegationRefusal reports whether d is a refusal one of the delegation gates produced.
//
// It reads the taxonomy slot every one of them stamps rather than the details discriminator,
// because the slot is what the audit taxonomy keys on and it cannot be set by anything else:
// delegationConditionType is not a condition an author can attach to a target.
//
// It is exported for a composing layer deciding whether it has anything to ADD. A verdict on
// this axis composed onto a refusal already on this axis is not a hardening but a REPLACEMENT
// — a different reason and a different hop, for a call the enforced path would have refused at
// the earlier gate — so the layer that would compose asks this first.
func IsDelegationRefusal(d *capability.DenialInfo) bool {
	return d != nil && d.ConditionType == delegationConditionType
}

// delegationDenial builds the refusal every gate above returns, so the code, the taxonomy
// slot, and the details shape are single-sourced.
//
// It is downgradable (HardDeny unset), which is deliberate and is the one property here worth
// arguing about. A delegation bound is an AUTHORIZATION verdict, exactly like the manifest's
// own no-match deny, and an --audit route exists to show an operator what enforcement would
// do before it does it — including on the delegation chain they are rolling out. The refusals
// that must survive --audit are the ones where forwarding would perform an action while
// destroying the evidence or the invariant (an unapproved declassification, an over-ceiling
// effect, a failed state write); a delegate reaching past its grant on an observe route is a
// prediction being logged, which is what observe mode is.
func delegationDenial(auditOnly bool, requestID, now, reason, hop, message string, extra map[string]interface{}) *capability.EnforceResponse {
	details := map[string]interface{}{
		// "delegation": true is the discriminator every refusal on this axis carries, so one
		// filter finds every attenuation event on the tape — the same role
		// capability.FlowAuditDetailKey plays for the information-flow events. This one has a
		// single producer, so it stays a literal; that one has five across two packages,
		// which is why it does not.
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
// matched constraint's own, or nil when the chain masks nothing.
//
// It is a SEPARATE obligation rather than a merge into the constraint's own paths, because
// the two have different provenance and the transport applies the union either way: the
// manifest's list is what the operator declared for this target, and the chain's is what the
// delegators declared for this caller. Keeping them apart means an audit record shows which
// is which, and means a constraint carrying no redactFields at all still gets the chain's.
func delegatedRedaction(chain *capability.DelegationChain) *capability.Obligation {
	fields := chain.RedactFields()
	if len(fields) == 0 {
		return nil
	}
	return &capability.Obligation{Type: capability.DirectiveTypeRedactFields, Paths: fields}
}

// delegatedAllowLabels intersects a flowLabel condition's own Allow set with the cap every
// hop of the chain composed, returning the effective allow-set for this call.
//
// Intersection is the only safe composition: the sink rule is "present and not allowed =>
// deny", so a delegate's cap can only ever remove entries. capped reports whether any hop
// declared one — distinct from an empty result, which is the full quarantine (no labeled flow
// reaches any sink) and is the strictest value a hop can express.
func delegatedAllowLabels(allow []string, chain *capability.DelegationChain) []string {
	capped, isCapped := chain.AllowedLabelCap()
	if !isCapped {
		return allow
	}
	permitted := make(map[string]bool, len(capped))
	for _, l := range capped {
		permitted[l] = true
	}
	// Preserves the condition's own ordering rather than imposing one: this value is
	// reported as allowLabels in a denial's details, and reordering what the operator wrote
	// would make the record harder to line up with the manifest it came from.
	out := make([]string, 0, len(allow))
	for _, l := range allow {
		if permitted[l] {
			out = append(out, l)
		}
	}
	return out
}
