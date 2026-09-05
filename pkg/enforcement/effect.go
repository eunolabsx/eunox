// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"context"
	"fmt"
	"maps"
	"math"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/eunolabs/eunox/pkg/capability"
)

// Effect enforcement — the "what may break" axis, evaluated at the same interception point as
// everything else.
//
// effectClass and blastRadius run as ordinary per-target ConditionHandlers; effectCeiling is
// different in kind — not a condition an author attaches, but a bound EVERY allowed action is
// additionally checked against on the allow tail, catching the target nobody wrote a rule for.
//
// All three read ONE resolution of the matched constraint's contract, threaded through the
// context by evaluateMatched, so the condition verdict, ceiling verdict, and audit record
// can't disagree about what the call's effect was.

// resolvedEffectKey types the context value carrying the call's resolved effect from
// evaluateMatched to the condition handlers, mirroring withDirectives/withCarriedLabels.
type resolvedEffectKey struct{}

// withResolvedEffect returns a child context carrying the call's resolved effect.
//
// By pointer: one resolution is threaded to three readers, and it's read-only once produced,
// so copying per reader buys nothing on the hot path.
func withResolvedEffect(ctx context.Context, eff *capability.ResolvedEffect) context.Context {
	return context.WithValue(ctx, resolvedEffectKey{}, eff)
}

// resolvedEffectFromContext returns the effect evaluateMatched resolved for this call. ok is
// false for a direct caller that threaded none, or a threaded-but-nil pointer — either way the
// handlers fail closed rather than silently resolving an unannotated default here.
func resolvedEffectFromContext(ctx context.Context) (*capability.ResolvedEffect, bool) {
	eff, ok := ctx.Value(resolvedEffectKey{}).(*capability.ResolvedEffect)
	return eff, ok && eff != nil
}

// handleEffectClass denies a call whose resolved effect class is not in the condition's Allow
// set. An unannotated constraint resolves to irreversible, so a target with this condition and
// no contract denies by default — the flywheel working as intended at the per-target scale.
func (e *Engine) handleEffectClass(ctx context.Context, cond capability.Condition, _ *capability.EnforceRequest) *ConditionError {
	ec, condErr := castCondition[capability.EffectClassCondition](cond)
	if condErr != nil {
		return condErr
	}
	// The loader rejects an empty allow set and an unknown class, but a programmatically built
	// condition can carry either — surface both rather than silently admit. Faults, not
	// verdicts: a condition that declares no evaluable set was never evaluated.
	if len(ec.Allow) == 0 {
		return effectFault(capability.ConditionTypeEffectClass,
			"effectClass declares an empty 'allow' set, which admits no effect class")
	}
	allow := make(map[string]bool, len(ec.Allow))
	for _, c := range ec.Allow {
		if !capability.IsEffectClass(c) {
			return effectFault(capability.ConditionTypeEffectClass, fmt.Sprintf(
				"effectClass 'allow' contains unknown class %q; valid effect classes are %s",
				c, strings.Join(capability.EffectClassVocabulary(), ", ")))
		}
		allow[c] = true
	}

	eff, ok := resolvedEffectFromContext(ctx)
	if !ok {
		// Reachable through the exported NonCommittingConditionVerdict seam, whose composing
		// caller never threads a resolved effect: a fault, so the claim leg's refusal is not
		// downgraded to a forward on the strength of a condition nothing evaluated.
		return effectFault(capability.ConditionTypeEffectClass,
			"effect contract was not resolved for this call; effect state is unavailable")
	}
	if allow[eff.Class] {
		return nil
	}
	details := map[string]interface{}{"allow_effect_classes": capability.SortedEffectClasses(ec.Allow)}
	return effectDenial(eff, capability.ConditionTypeEffectClass, fmt.Sprintf(
		"this call's effect class %q is not permitted at this target (permitted: %s)%s",
		eff.Class, strings.Join(capability.SortedEffectClasses(ec.Allow), ", "), unannotatedHint(eff)), details)
}

// blastRadiusBounds is a blastRadius condition's own declaration, parsed. Either field is nil
// when the condition does not declare that bound; at least one is non-nil, since a condition
// declaring neither is refused by parseBlastRadiusBounds.
type blastRadiusBounds struct {
	perCall    *big.Float
	cumulative *big.Float
}

// parseBlastRadiusBounds validates a blastRadius condition's own declaration.
//
// Runs BEFORE the call's effect is resolved, which is what makes its refusals structurally
// unable to take the verdict constructor: everything wrong here is wrong about the CONDITION,
// so there is no resolved effect to hand effectDenial and the compiler says so. The loader
// requires at least one bound and rejects a half-written pair or a non-numeric one; a
// programmatically built condition may carry any of them, and none must read as "checked and
// fine".
func parseBlastRadiusBounds(br *capability.BlastRadiusCondition) (blastRadiusBounds, *ConditionError) {
	var bounds blastRadiusBounds
	if br.Max == nil && !br.HasVelocity() {
		return bounds, effectFault(capability.ConditionTypeBlastRadius,
			"blastRadius declares neither 'max' nor a complete 'maxTotal'/'windowSeconds' pair, so it bounds nothing")
	}
	if br.Max != nil {
		limit, ok := capability.ParseBlastRadiusNumber(*br.Max)
		if !ok {
			return bounds, effectFault(capability.ConditionTypeBlastRadius, fmt.Sprintf(
				"blastRadius 'max' is not a number (%q)", br.Max.String()))
		}
		bounds.perCall = limit
	}
	if br.HasVelocity() {
		limit, ok := capability.ParseBlastRadiusNumber(*br.MaxTotal)
		if !ok {
			return bounds, effectFault(capability.ConditionTypeBlastRadius, fmt.Sprintf(
				"blastRadius 'maxTotal' is not a number (%q)", br.MaxTotal.String()))
		}
		bounds.cumulative = limit
	}
	return bounds, nil
}

// checkPerCallBlastRadius applies the per-call `max` bound against the already-parsed limit.
// It commits nothing.
func checkPerCallBlastRadius(br *capability.BlastRadiusCondition, limit *big.Float, eff *capability.ResolvedEffect) *ConditionError {
	// The details map is built at each refusal rather than up front: the pass below is the hot
	// path, and a map nothing reads is an allocation per allowed call.
	if !eff.Quantified() {
		return effectDenial(eff, capability.ConditionTypeBlastRadius, fmt.Sprintf(
			"this call's blast radius could not be quantified, so it cannot be shown to be within the bound of %s%s",
			br.Max.String(), unannotatedHint(eff)),
			map[string]interface{}{"blast_radius_max": br.Max.String()})
	}
	if eff.BlastRadius.Cmp(limit) <= 0 {
		return nil
	}
	return effectDenial(eff, capability.ConditionTypeBlastRadius, fmt.Sprintf(
		"this call's blast radius %s exceeds the permitted maximum %s",
		eff.BlastRadius.Text('f', -1), br.Max.String()),
		map[string]interface{}{"blast_radius_max": br.Max.String()})
}

// velocityBucket derives the weighted bucket a cumulative bound draws on, after the checks
// that must fail closed first: an unquantified magnitude, one the accumulator can't
// represent, and the structural anchor/target guards. Commits nothing — the engine admits
// the bucket alongside every other quota condition in one atomic call, after the ceiling has
// had its chance to refuse.
func (e *Engine) velocityBucket(ctx context.Context, br *capability.BlastRadiusCondition, limit *big.Float, eff *capability.ResolvedEffect, req *capability.EnforceRequest) (DeferredCommit, bool, *ConditionError) {
	if !eff.Quantified() {
		// Same rule the per-call bound applies: an action whose size can't be established
		// must not contribute 0 to a sum, or the unannotated call becomes the way to spend
		// nothing.
		return DeferredCommit{}, false, effectDenial(eff, capability.ConditionTypeBlastRadius, fmt.Sprintf(
			"this call's blast radius could not be quantified, so it cannot be summed against the cumulative bound of %s per %ds%s",
			br.MaxTotal.String(), br.WindowSeconds, unannotatedHint(eff)), velocityExtras(br))
	}
	// float64 on both sides, matching the counter contract's accumulator.
	weight, _ := eff.BlastRadius.Float64()
	limitF, _ := limit.Float64()
	if !weightSummable(weight) {
		return DeferredCommit{}, false, effectDenial(eff, capability.ConditionTypeBlastRadius, fmt.Sprintf(
			"this call's blast radius %s is outside the range a cumulative bound can sum, so it cannot be shown to be within %s",
			eff.BlastRadius.Text('f', -1), br.MaxTotal.String()), velocityExtras(br))
	}

	key, skip, condErr := e.quotaBucketKey(ctx, req, blastRadiusBucketSpec)
	if condErr != nil {
		return DeferredCommit{}, false, condErr
	}
	if skip {
		// Observe mode: the per-call bound above has already run, which is the half observe
		// mode must still report — leaving it on the commit side let it go unchecked on this
		// run.
		return DeferredCommit{}, true, nil
	}
	return DeferredCommit{
		Bucket: capability.QuotaBucket{
			Key:       key,
			WindowSec: br.WindowSeconds,
			Weight:    weight,
			Limit:     limitF,
		},
		Deny: func(total float64, retryAfter time.Duration) *ConditionError {
			details := velocityExtras(br)
			details["blast_radius_total"] = total
			// Shared helper every quota condition uses: rounds a fractional wait UP
			// (truncating reported a 900ms wait as 0, telling the caller to retry into a
			// guaranteed denial).
			details["retry_after_seconds"] = retryAfterSeconds(retryAfter, br.WindowSeconds)
			return effectDenial(eff, capability.ConditionTypeBlastRadius, fmt.Sprintf(
				"this call's blast radius %s would take this session's cumulative total for the target past the permitted %s per %ds (already %s within the window)",
				eff.BlastRadius.Text('f', -1), br.MaxTotal.String(), br.WindowSeconds, formatTotal(total)), details)
		},
	}, false, nil
}

// weightSummable reports whether a resolved magnitude can join a weighted total at all.
//
// Tests REPRESENTABILITY, not exactness: requiring big.Exact broke the feature's headline
// case, denying a $19.99 refund under a $2,000/hr bound as "too large" because most decimal
// amounts aren't dyadic at float64 precision. A rounded fractional magnitude IS summable —
// both counter backends already accumulate in IEEE-754 double precision. What's genuinely
// unsummable is non-finite, negative, or above the 2^53 bound where Redis's Lua arithmetic
// stops being exact.
func weightSummable(weight float64) bool {
	if math.IsNaN(weight) || math.IsInf(weight, 0) {
		return false
	}
	return weight >= 0 && weight <= capability.MaxWeightedTotal
}

// velocityExtras builds the cumulative-bound fields every velocity refusal carries on top of
// the resolved effect's own (which effectDenial supplies). One builder, because three
// hand-copied sites had let blast_radius_window_seconds drift out of one of them, leaving a
// SIEM rule keyed on it blind to that class of denial.
func velocityExtras(br *capability.BlastRadiusCondition) map[string]interface{} {
	return map[string]interface{}{
		"blast_radius_max_total":      br.MaxTotal.String(),
		"blast_radius_window_seconds": br.WindowSeconds,
	}
}

// formatTotal renders a running weighted total for an operator-facing denial without
// scientific notation, matching how the per-call bound renders a magnitude.
func formatTotal(total float64) string {
	return strconv.FormatFloat(total, 'f', -1, 64)
}

// blastRadiusHandler is the built-in blastRadius condition handler. A condition declaring a
// CUMULATIVE bound commits a weighted slice of a sliding-window budget on admit, so it is a
// CommittingConditionHandler, running after every pure predicate and after the effect ceiling
// so a magnitude is never charged to a call a later check then refuses.
//
// PrepareCommit carries the per-call bound too, so observe mode (which skips the commit)
// still checks it for a constraint carrying both bounds. A configuration with ONLY a per-call
// bound consumes nothing and reports no bucket, which is the shape the skip/commit contract
// admits beside a skip.
type blastRadiusHandler struct{ e *Engine }

// PrepareCommit runs the condition's pure checks (the bounds' well-formedness and the
// per-call `max`) and derives the weighted bucket for a cumulative bound.
func (h blastRadiusHandler) PrepareCommit(ctx context.Context, cond capability.Condition, req *capability.EnforceRequest) (DeferredCommit, bool, *ConditionError) {
	br, condErr := castCondition[capability.BlastRadiusCondition](cond)
	if condErr != nil {
		return DeferredCommit{}, false, condErr
	}
	// The condition's own declaration first, before any effect is resolved: those refusals are
	// faults about the policy text, and running them here is what keeps them off the verdict
	// constructor (see parseBlastRadiusBounds).
	bounds, condErr := parseBlastRadiusBounds(br)
	if condErr != nil {
		return DeferredCommit{}, false, condErr
	}

	eff, resolved := resolvedEffectFromContext(ctx)
	if !resolved {
		return DeferredCommit{}, false, effectFault(capability.ConditionTypeBlastRadius,
			"effect contract was not resolved for this call; blast radius is unavailable")
	}

	// Per-call bound first, cumulative only after: a call over the per-call bound must be
	// refused WITHOUT consuming the cumulative budget, or a burst of oversized attempts
	// exhausts the window.
	if bounds.perCall != nil {
		if condErr := checkPerCallBlastRadius(br, bounds.perCall, eff); condErr != nil {
			return DeferredCommit{}, false, condErr
		}
	}
	if bounds.cumulative == nil {
		// Bound checked, nothing to commit.
		return DeferredCommit{}, false, nil
	}
	return h.e.velocityBucket(ctx, br, bounds.cumulative, eff, req)
}

// unannotatedHint appends the remediation that differs between "declared, and it does not
// pass" and "never declared, so it defaulted to the most consequential reading". Both deny;
// only the fix differs, and an operator reading a denial needs to know which.
func unannotatedHint(eff *capability.ResolvedEffect) string {
	if eff.Annotated {
		return ""
	}
	return " — this target declares no effect contract, so it resolves to the fail-closed default (irreversible, unquantified); annotate it to buy it out of maximum friction"
}

// effectDenial builds the effect layer's policy VERDICT: the contract was resolved, the bound
// was evaluated, and this call does not pass it. CONDITION_FAILED, so an observing route may
// downgrade it to a forward — which is sound precisely because the bound WAS evaluated and
// enforce mode's answer is known. details is stamped onto the denial so the tape carries the
// structured consequence inputs (class, magnitude, compensating action) rather than only the
// prose.
//
// Taking eff is what makes the split structural rather than a per-site choice: the one
// constructor here used to hardcode CONDITION_FAILED for every effect refusal, including the
// three that could reach no verdict at all — an unresolved contract, a condition bounding
// nothing, a non-numeric bound — so an --audit route forwarded a call whose effect condition
// nothing had evaluated. Every unevaluable site sits ABOVE the resolution and has no effect to
// pass, so it cannot reach this constructor at all. eff also supplies the details every verdict
// carries, extra adding only what is specific to the bound that refused.
func effectDenial(eff *capability.ResolvedEffect, condType, message string, extra map[string]interface{}) *ConditionError {
	details := eff.AuditDetails()
	maps.Copy(details, extra)
	return &ConditionError{
		Code:          capability.ErrCodeConditionFailed,
		ConditionType: condType,
		Message:       message,
		Details:       details,
	}
}

// effectFault builds the effect layer's FAULT: a refusal produced because no verdict could be
// reached. ENFORCEMENT_ERROR, whose class no observing route downgrades — there is no verdict
// to stand in for the one that never ran. It carries no details, every site reaching it being
// one with no resolved effect to describe.
func effectFault(condType, message string) *ConditionError {
	return &ConditionError{
		Code:          capability.ErrCodeEnforcementError,
		ConditionType: condType,
		Message:       message,
	}
}

// checkEffectCeiling applies the tool-agnostic consequence bound to an action the conditions
// have ALREADY allowed. Returns nil on pass, or the response that replaces the allow: an
// ESCALATION_REQUIRED (default) or a plain deny, per the ceiling's onExceed.
//
// Runs last, on the allow tail — it can only narrow, never admit what the allowlist denied —
// and ordering against the state commit is load-bearing: an over-ceiling call is not
// forwarded, so it must leave no antecedent or flow label behind, as a hard-denied call must
// not (see evaluateMatched).
//
// Escalate is a REFUSAL, not a pending state: with no approval integration in-path, the
// fail-closed reading of "escalate" is "not forwarded" — what it buys over a plain deny is the
// decision=escalate record for an auditor or control plane.
func (e *Engine) checkEffectCeiling(ec evalCtx, eff *capability.ResolvedEffect, carriedLabels []string) *capability.EnforceResponse {
	exceeds, reasons := e.effectCeiling.Exceeds(eff)
	if !exceeds {
		return nil
	}
	details := eff.AuditDetails()
	details["ceiling_exceeded"] = reasons
	if len(carriedLabels) > 0 {
		// Stamped into the escalation's details (not the allow-only top-level carried_labels
		// field) since an escalation is the one refusal a human is expected to act on.
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

	// Both arms route through the shared constructors rather than a literal, since that's
	// where BoundDenialDetails runs — details here carries a caller-controlled blast_radius
	// argument, and a hand-built literal skipped the bound on the one refusal shape a human is
	// meant to read.
	if e.effectCeiling.Outcome() == capability.OnExceedDeny {
		return ec.denyPtr(nil, capability.DenialInfo{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: ceilingConditionType,
			Message:       message,
			// BlockOverride: the escalate arm's rationale verbatim. CONDITION_FAILED is a
			// policy code, so without the override an observing route (--audit, or an
			// audit-only constraint) forwards the call and PERFORMS the irreversible action
			// the ceiling flagged — the one outcome no posture makes right, and the reason
			// escalateResponse sets the same bit. onExceed picks what an operator gets to
			// READ (a deny record or an approval-queue escalation), not whether the action
			// happens; a soft deny arm would also make CeilingVerdictFor's composition soft
			// for exactly the configuration it exists to harden.
			BlockOverride: true,
			Details:       details,
		})
	}
	resp := ec.escalate(capability.DenialInfo{
		Code:          capability.ErrCodeEscalationRequired,
		ConditionType: ceilingConditionType,
		Message:       message,
		Details:       details,
	})
	return &resp
}

// CeilingVerdictFor answers ONE question — "does this action exceed the policy's effect
// ceiling?" — for an already-selected constraint, WITHOUT evaluating conditions or committing
// state. Returns the refusal the ceiling would produce, or nil.
//
// Exists for the COMPOSED case: a wrapping PDP (the JWT layer) can refuse before
// evaluateMatched ever runs, which both under-counts escalations and produces a soft refusal
// that --audit would downgrade to a forward — inverting the rule that a token may only
// restrict.
//
// Non-committing because some of the matched constraint's conditions COMMIT (maxCalls
// consumes a window, labelOutput writes a label, sequenceBlock writes an antecedent);
// replaying them for a call already refused would leave exactly the phantom state
// evaluateMatched's ordering exists to prevent.
//
// Does NOT reproduce a condition denial that would have fired first — the caller composes a
// harder refusal for a call refused either way, never an allow.
//
// The flow-label peek is a pure Get, taken only for a flow-relevant constraint, and its
// failure is swallowed — this runs on an already-refused call, so a store fault must not
// weaken it.
func (e *Engine) CeilingVerdictFor(ctx context.Context, req *capability.EnforceRequest, matched *capability.Constraint) *capability.EnforceResponse {
	// A nil engine sets no ceiling; this runs on a refusal path, where a panic would replace
	// an answered denial with a dropped connection. A ManifestPDP may legitimately hold none.
	if e == nil || req == nil || matched == nil || !e.effectCeiling.IsSet() {
		return nil
	}
	requestID := NewRequestID()
	now := e.clock.Now().UTC().Format(time.RFC3339Nano)

	// Same single resolution evaluateMatched threads to the two effect conditions and the
	// ceiling, so this can't disagree with a full-path verdict.
	effect := capability.ResolveEffect(matched.Effect, req.Arguments)

	var carriedLabels []string
	// Skip the peek for an unanchorable request, mirroring evaluateMatched's ordering: with
	// no task id the anchor falls back to the SESSION key, and the snapshot would come from
	// the very bucket the full path's refusal exists to reject — wrong-bucket evidence on
	// the hardened record.
	if !e.skipFlow && constraintHasFlow(matched) && !e.anchorUnresolved(req) {
		// A pure read: "which provenance produced this" is one of the consequence inputs the
		// short-circuit was dropping.
		if labels, err := e.peekSessionLabels(ctx, req); err == nil {
			carriedLabels = labels
		}
	}

	resp := e.checkEffectCeiling(evalCtx{req: req, matched: matched, requestID: requestID, now: now}, effect, carriedLabels)
	if resp == nil {
		return nil
	}
	if resp.CarriedLabels == nil {
		// Mirrors evaluateMatched's defer, so a composed escalation carries the same
		// top-level field a full-path one does.
		resp.CarriedLabels = carriedLabels
	}
	return resp
}

// ceilingConditionType is the conditionType stamped on a ceiling verdict — its own taxonomy
// slot rather than borrowing effectClass, which an operator couldn't then distinguish from a
// per-target class gate.
const ceilingConditionType = "effectCeiling"
