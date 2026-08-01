// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"context"
	"fmt"
	"strings"

	"github.com/eunolabs/eunox/pkg/capability"
)

// Effect enforcement — the "what may break" axis, evaluated at the SAME interception
// point as everything else.
//
// Two per-target conditions (effectClass, blastRadius) run through the existing
// ConditionHandler registry like any other predicate. The tool-agnostic effectCeiling is
// different in kind: it is not a condition an author attaches to a target, it is a bound
// EVERY allowed action is additionally checked against, so it runs once on the allow tail
// after the conditions have passed. That placement is the point — a per-target condition
// only guards the targets someone remembered to write one for, while the ceiling catches
// the tool nobody thought about, including the unannotated one.
//
// All three read ONE resolution of the matched constraint's contract against the call's
// arguments, threaded through the context by evaluateMatched. A second resolution would
// be a place for the condition verdict, the ceiling verdict, and the audit record to
// silently disagree about what the call's effect was.

// resolvedEffectKey types the context value carrying the call's resolved effect from
// evaluateMatched into the condition handlers, mirroring withDirectives/withCarriedLabels.
// The ConditionHandler signature is (ctx, condition, request) — it deliberately does not
// see the matched constraint — so the contract, which lives on the constraint, has to
// arrive this way.
type resolvedEffectKey struct{}

// withResolvedEffect returns a child context carrying the call's resolved effect.
//
// By pointer, not by value: one resolution is threaded to three readers (the two
// conditions and the ceiling), and a resolved effect is read-only once produced, so
// copying it per reader buys nothing and costs a multi-word copy on the hot path.
func withResolvedEffect(ctx context.Context, eff *capability.ResolvedEffect) context.Context {
	return context.WithValue(ctx, resolvedEffectKey{}, eff)
}

// resolvedEffectFromContext returns the effect evaluateMatched resolved for this call.
// ok is false for a direct caller of an exported entrypoint that did not thread one; the
// handlers then fail closed rather than guess, because the alternative — resolving an
// UNANNOTATED default here — would silently judge every direct caller's call as
// irreversible without telling them why. A threaded-but-nil pointer reports false for the
// same reason: unevaluable must fail closed, never dereference nil.
func resolvedEffectFromContext(ctx context.Context) (*capability.ResolvedEffect, bool) {
	eff, ok := ctx.Value(resolvedEffectKey{}).(*capability.ResolvedEffect)
	return eff, ok && eff != nil
}

// handleEffectClass denies a call whose resolved effect class is not in the condition's
// Allow set — the per-target consequence gate ("this target may only ever do reversible
// things").
//
// An unannotated constraint resolves to irreversible, so a target with an effectClass
// condition and no contract denies. That is the flywheel working as intended at the
// per-target scale: the author asked for a class gate, so leaving the class undeclared
// cannot pass it.
func (e *Engine) handleEffectClass(ctx context.Context, cond capability.Condition, _ *capability.EnforceRequest) *ConditionError {
	ec, condErr := castCondition[capability.EffectClassCondition](cond)
	if condErr != nil {
		return condErr
	}
	// Defense in depth against a typed-nil *EffectClassCondition: castCondition matches
	// the `*T` case and returns the nil pointer with condErr == nil, so reading ec.Allow
	// below would dereference nil. runConditions rejects a typed-nil condition before
	// dispatch, so this is unreachable in-tree — but an unevaluable condition must fail
	// closed, never panic the enforcement goroutine (mirrors handleFlowLabel).
	if ec == nil {
		return effectDenial(capability.ConditionTypeEffectClass, "effectClass condition is nil and cannot be evaluated", nil)
	}
	// The loader rejects an empty allow set and an unknown class, but a programmatically
	// built condition can carry either. Surface both rather than silently admit: an empty
	// set that fell through as "no restriction" would invert the condition's meaning.
	if len(ec.Allow) == 0 {
		return effectDenial(capability.ConditionTypeEffectClass,
			"effectClass declares an empty 'allow' set, which admits no effect class", nil)
	}
	allow := make(map[string]bool, len(ec.Allow))
	for _, c := range ec.Allow {
		if !capability.IsEffectClass(c) {
			return effectDenial(capability.ConditionTypeEffectClass, fmt.Sprintf(
				"effectClass 'allow' contains unknown class %q; valid effect classes are %s",
				c, strings.Join(capability.EffectClassVocabulary(), ", ")), nil)
		}
		allow[c] = true
	}

	eff, ok := resolvedEffectFromContext(ctx)
	if !ok {
		return effectDenial(capability.ConditionTypeEffectClass,
			"effect contract was not resolved for this call; effect state is unavailable", nil)
	}
	if allow[eff.Class] {
		return nil
	}
	details := eff.AuditDetails()
	details["allow_effect_classes"] = capability.SortedEffectClasses(ec.Allow)
	return effectDenial(capability.ConditionTypeEffectClass, fmt.Sprintf(
		"this call's effect class %q is not permitted at this target (permitted: %s)%s",
		eff.Class, strings.Join(capability.SortedEffectClasses(ec.Allow), ", "), unannotatedHint(eff)), details)
}

// handleBlastRadius denies a call whose magnitude exceeds the condition's per-call bound.
// It is the quantitative gate an argument allowlist cannot express: the argument is legal
// at every value, and only its SIZE is the problem.
//
// An UNQUANTIFIED call — no contract, or a contract naming an argument this call did not
// supply — is denied, not admitted. An action whose size cannot be established must not
// be treated as small; treating unknown as zero is the fail-open this condition exists to
// prevent.
func (e *Engine) handleBlastRadius(ctx context.Context, cond capability.Condition, _ *capability.EnforceRequest) *ConditionError {
	br, condErr := castCondition[capability.BlastRadiusCondition](cond)
	if condErr != nil {
		return condErr
	}
	if br == nil {
		return effectDenial(capability.ConditionTypeBlastRadius, "blastRadius condition is nil and cannot be evaluated", nil)
	}
	if br.Max == nil {
		// The loader requires a bound; a programmatically built condition may omit it. A
		// condition that bounds nothing must not read as "checked and fine".
		return effectDenial(capability.ConditionTypeBlastRadius,
			"blastRadius declares no 'max', so it bounds nothing", nil)
	}
	limit, ok := capability.ParseBlastRadiusNumber(*br.Max)
	if !ok {
		return effectDenial(capability.ConditionTypeBlastRadius, fmt.Sprintf(
			"blastRadius 'max' is not a number (%q)", br.Max.String()), nil)
	}

	eff, resolved := resolvedEffectFromContext(ctx)
	if !resolved {
		return effectDenial(capability.ConditionTypeBlastRadius,
			"effect contract was not resolved for this call; blast radius is unavailable", nil)
	}
	if !eff.Quantified() {
		details := eff.AuditDetails()
		details["blast_radius_max"] = br.Max.String()
		return effectDenial(capability.ConditionTypeBlastRadius, fmt.Sprintf(
			"this call's blast radius could not be quantified, so it cannot be shown to be within the bound of %s%s",
			br.Max.String(), unannotatedHint(eff)), details)
	}
	if eff.BlastRadius.Cmp(limit) <= 0 {
		return nil
	}
	details := eff.AuditDetails()
	details["blast_radius_max"] = br.Max.String()
	return effectDenial(capability.ConditionTypeBlastRadius, fmt.Sprintf(
		"this call's blast radius %s exceeds the permitted maximum %s",
		eff.BlastRadius.Text('f', -1), br.Max.String()), details)
}

// unannotatedHint appends the remediation that differs between "declared, and it does not
// pass" and "never declared, so it defaulted to the most consequential reading". Both
// deny; only the fix differs, and an operator reading a denial needs to know which.
func unannotatedHint(eff *capability.ResolvedEffect) string {
	if eff.Annotated {
		return ""
	}
	return " — this target declares no effect contract, so it resolves to the fail-closed default (irreversible, unquantified); annotate it to buy it out of maximum friction"
}

// effectDenial builds a CONDITION_FAILED for the effect layer. details is stamped onto
// the denial so the tape carries the structured consequence inputs (class, magnitude,
// compensating action) rather than only the prose.
func effectDenial(condType, message string, details map[string]interface{}) *ConditionError {
	return &ConditionError{
		Code:          capability.ErrCodeConditionFailed,
		ConditionType: condType,
		Message:       message,
		Details:       details,
	}
}

// checkEffectCeiling applies the tool-agnostic consequence bound to an action the
// conditions have ALREADY allowed. It returns nil when the call passes, and otherwise the
// response that replaces the allow: an ESCALATION_REQUIRED escalate (the default) or a
// plain deny, per the ceiling's onExceed.
//
// It runs last, on the allow tail, and it can only ever narrow — so it never admits
// anything the allowlist or the conditions denied. Ordering against the state commit is
// load-bearing: an over-ceiling call is NOT forwarded, so it must not leave a
// sequenceBlock antecedent or a flow label behind, exactly as a hard-denied call must
// not (see evaluateMatched).
//
// The escalate outcome is a REFUSAL that says why, not a pending state: with no approval
// integration in the in-path proxy, the fail-closed reading of "escalate" is "not
// forwarded". What it buys over a plain deny is the record — decision=escalate plus the
// consequence inputs — so an auditor or a control plane can tell an action awaiting a
// human from one policy forbids outright.
func (e *Engine) checkEffectCeiling(eff *capability.ResolvedEffect, matched *capability.Constraint, carriedLabels []string, requestID, now string) *capability.EnforceResponse {
	exceeds, reasons := e.effectCeiling.Exceeds(eff)
	if !exceeds {
		return nil
	}
	details := eff.AuditDetails()
	details["ceiling_exceeded"] = reasons
	// Stamp the session's accumulated flow labels INTO the escalation's structured
	// details. The top-level carried_labels field is reserved for allow records (a deny
	// carries none), but an escalation is the one refusal a human is expected to read and
	// act on, and "which provenance produced this" is the first thing they need: it is
	// what ties the who-may-know axis to the what-may-break one on a single record. Empty
	// for a non-flow policy, where the key is simply absent.
	if len(carriedLabels) > 0 {
		details["carried_labels"] = carriedLabels
	}
	if e.effectCeiling.MaxEffectClass != "" {
		details["ceiling_max_effect_class"] = e.effectCeiling.MaxEffectClass
	}
	if e.effectCeiling.MaxBlastRadius != nil {
		details["ceiling_max_blast_radius"] = e.effectCeiling.MaxBlastRadius.String()
	}

	message := fmt.Sprintf("this action exceeds the policy's effect ceiling (%s): %s%s",
		strings.Join(reasons, ", "), eff.String(), unannotatedHint(eff))

	// Both arms go through the shared constructors rather than building an
	// EnforceResponse literal. Those constructors are where boundDenialDetails runs, and
	// details here carries caller-controlled bytes: blast_radius is rendered from a tool
	// ARGUMENT, and compensating_action / effect_contract come from the manifest. A
	// hand-built literal skipped the bound entirely, so the one refusal shape a human is
	// expected to read was also the one that could carry an unbounded value onto the
	// signed tape.
	if e.effectCeiling.Outcome() == capability.OnExceedDeny {
		resp := denyResponse(requestID, now, matched.IsAuditOnly(), nil, capability.DenialInfo{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: ceilingConditionType,
			Message:       message,
			Details:       details,
		})
		return &resp
	}
	resp := escalateResponse(requestID, now, capability.DenialInfo{
		Code:          capability.ErrCodeEscalationRequired,
		ConditionType: ceilingConditionType,
		Message:       message,
		Details:       details,
		// Hard: same reason AuditOnly stays false (see escalateResponse) — a route-wide
		// --audit must not turn "needs human approval" into "performed anyway, logged".
		HardDeny: true,
	})
	return &resp
}

// ceilingConditionType is the conditionType stamped on a ceiling verdict. The ceiling is
// not a condition an author attaches to a target, so it has no condition discriminator of
// its own; naming it explicitly keeps the audit taxonomy honest about which check fired
// rather than borrowing effectClass, which an operator could then not distinguish from a
// per-target class gate.
const ceilingConditionType = "effectCeiling"
