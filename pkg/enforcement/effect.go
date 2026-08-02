// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

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

// checkPerCallBlastRadius applies the per-call `max` bound. It commits nothing.
func checkPerCallBlastRadius(br *capability.BlastRadiusCondition, eff *capability.ResolvedEffect) *ConditionError {
	limit, ok := capability.ParseBlastRadiusNumber(*br.Max)
	if !ok {
		return effectDenial(capability.ConditionTypeBlastRadius, fmt.Sprintf(
			"blastRadius 'max' is not a number (%q)", br.Max.String()), nil)
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

// velocityBucket derives the weighted bucket a cumulative bound draws on, after the checks
// that must fail closed before any budget is considered: an unquantified magnitude, one the
// accumulator cannot represent, and the structural session/target guards.
//
// It COMMITS nothing — the engine admits the returned bucket alongside every other
// quota-consuming condition on the constraint, in one atomic call, after the effect ceiling
// has had its chance to refuse.
func (e *Engine) velocityBucket(ctx context.Context, br *capability.BlastRadiusCondition, eff *capability.ResolvedEffect, req *capability.EnforceRequest) (DeferredCommit, bool, *ConditionError) {
	limit, ok := capability.ParseBlastRadiusNumber(*br.MaxTotal)
	if !ok {
		return DeferredCommit{}, false, effectDenial(capability.ConditionTypeBlastRadius, fmt.Sprintf(
			"blastRadius 'maxTotal' is not a number (%q)", br.MaxTotal.String()), nil)
	}
	if !eff.Quantified() {
		// The same rule the per-call bound applies, for the same reason: an action whose
		// size cannot be established must not contribute 0 to a sum. Treating it as
		// weightless would make the unannotated call the one way to spend nothing.
		return DeferredCommit{}, false, effectDenial(capability.ConditionTypeBlastRadius, fmt.Sprintf(
			"this call's blast radius could not be quantified, so it cannot be summed against the cumulative bound of %s per %ds%s",
			br.MaxTotal.String(), br.WindowSeconds, unannotatedHint(eff)), velocityDetails(eff, br))
	}
	// float64 on both sides, matching the counter contract's accumulator.
	weight, _ := eff.BlastRadius.Float64()
	limitF, _ := limit.Float64()
	if !weightSummable(weight) {
		return DeferredCommit{}, false, effectDenial(capability.ConditionTypeBlastRadius, fmt.Sprintf(
			"this call's blast radius %s is outside the range a cumulative bound can sum, so it cannot be shown to be within %s",
			eff.BlastRadius.Text('f', -1), br.MaxTotal.String()), velocityDetails(eff, br))
	}

	key, skip, condErr := e.blastRadiusBucket(ctx, req)
	if condErr != nil {
		return DeferredCommit{}, false, condErr
	}
	if skip {
		// Observe mode (--audit): the budget must not be consumed. The per-call bound has
		// already been evaluated above, which is the half observe mode must still report —
		// leaving it on the commit side is what let it go unchecked on this exact run.
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
			details := velocityDetails(eff, br)
			details["blast_radius_total"] = total
			// The SHARED helper every other quota condition uses: it rounds a fractional
			// estimate UP (a truncating conversion reported a 900ms wait as 0, telling the
			// caller to retry immediately into a guaranteed denial) and falls back to the
			// full window when no estimate could be made.
			details["retry_after_seconds"] = retryAfterSeconds(retryAfter, br.WindowSeconds)
			return effectDenial(capability.ConditionTypeBlastRadius, fmt.Sprintf(
				"this call's blast radius %s would take this session's cumulative total for the target past the permitted %s per %ds (already %s within the window)",
				eff.BlastRadius.Text('f', -1), br.MaxTotal.String(), br.WindowSeconds, formatTotal(total)), details)
		},
	}, false, nil
}

// weightSummable reports whether a resolved magnitude can join a weighted total at all.
//
// It tests REPRESENTABILITY, not exactness. Requiring big.Exact here was wrong and broke
// the feature's own headline case: ParseBlastRadiusNumber builds the magnitude at 64-bit
// precision, so narrowing to a float64's 53-bit mantissa reports Below/Above for any
// decimal that is not dyadic — which is most currency amounts. A $19.99 refund was denied
// under a $2,000-an-hour bound, with a message calling it "too large".
//
// A rounded fractional magnitude IS summable, and the counter contract already says so:
// both backends accumulate in IEEE-754 double precision, and a fractional value can differ
// from an exact decimal sum in the last bits, far below any bound an operator authors. What
// is genuinely unsummable is a value the double cannot hold at all — non-finite, negative,
// or above the 2^53 bound where the Redis backend's Lua arithmetic stops being exact —
// and each of those is refused, matching the counter's own guard.
func weightSummable(weight float64) bool {
	if math.IsNaN(weight) || math.IsInf(weight, 0) {
		return false
	}
	return weight >= 0 && weight <= capability.MaxWeightedTotal
}

// velocityDetails builds the structured denial details every cumulative-bound refusal
// carries: the effect's own fields plus the bound that was not met. One builder, because
// the three refusal sites had hand-copied it and one copy had already dropped
// blast_radius_window_seconds — leaving a SIEM rule keyed on that field silently blind to
// one whole class of velocity denial.
func velocityDetails(eff *capability.ResolvedEffect, br *capability.BlastRadiusCondition) map[string]interface{} {
	details := eff.AuditDetails()
	details["blast_radius_max_total"] = br.MaxTotal.String()
	details["blast_radius_window_seconds"] = br.WindowSeconds
	return details
}

// formatTotal renders a running weighted total for an operator-facing denial without
// scientific notation, matching how the per-call bound renders a magnitude.
func formatTotal(total float64) string {
	return strconv.FormatFloat(total, 'f', -1, 64)
}

// blastRadiusBucket derives the counter bucket a cumulative bound sums into, under the
// same fail-closed guards maxCallsBucket applies and keyed the same way — so a session's
// velocity budget is per (session, target type, target name), never shared across sessions
// or across two targets that happen to share a bare name.
//
// The namespace is its own ("blastradius:"), so a velocity budget and a maxCalls quota on
// the same target never share a bucket: one counts calls and the other sums magnitudes, and
// collapsing them would make each corrupt the other's accounting.
//
// skip is true under observe mode (--audit), derived SOLELY from the request context, as
// the CommittingConditionHandler contract requires.
func (e *Engine) blastRadiusBucket(ctx context.Context, req *capability.EnforceRequest) (key string, skip bool, condErr *ConditionError) {
	if e.counter == nil {
		return "", false, effectDenial(capability.ConditionTypeBlastRadius,
			"call counter not configured, so a cumulative blast-radius bound cannot be enforced", nil)
	}
	if req == nil || req.SessionID == "" {
		// A missing session would merge every anonymous caller's magnitude into one budget
		// — a shared bucket is both a bypass (one caller's spend blocks another) and a DoS.
		return "", false, &ConditionError{
			Code:          capability.ErrCodeMissingContext,
			ConditionType: capability.ConditionTypeBlastRadius,
			Message:       "sessionId is required for a cumulative blastRadius bound",
		}
	}
	targetType, toolName := sessionTargetKey(req)
	if toolName == "" {
		return "", false, &ConditionError{
			Code:          capability.ErrCodeMissingContext,
			ConditionType: capability.ConditionTypeBlastRadius,
			Message:       "tool or resource name is required for a cumulative blastRadius bound",
		}
	}
	// After the structural guards, never before them — the same ordering maxCallsBucket
	// documents. Observe mode exists to predict what enforcement would do, and only the
	// budget WRITE is what it must not perform; a nil counter or an unidentifiable target
	// are misconfigurations that deny in enforce mode whatever the budget holds, and
	// skipping first would hide exactly those from the run made to find them.
	if SkipQuota(ctx) {
		return "", true, nil
	}
	return e.anchoredKey("blastradius", req, targetType, toolName), false, nil
}

// blastRadiusHandler is the built-in blastRadius condition handler. A condition declaring a
// CUMULATIVE bound commits a weighted slice of a sliding-window budget on admit, so beyond
// the plain Handle path it implements CommittingConditionHandler: the engine runs it after
// every pure predicate and after the effect ceiling, so a magnitude is never charged to a
// call a later check then refuses.
//
// PrepareCommit carries the PER-CALL bound as well as the bucket. That is not tidiness: the
// per-call `max` is a pure check, and leaving it in Handle alone meant observe mode — which
// skips the commit — skipped the bound too, so a constraint carrying `max` and `maxTotal`
// together had its per-call bound evaluated or not depending on how many deferred conditions
// happened to sit beside it.
//
// A per-call-only condition commits nothing and reports that by preparing a commit with no
// bucket (DeferredCommit.Commits() == false); its bound has still been checked. Deferral is
// keyed by condition TYPE, so both shapes arrive here and the distinction has to be
// per-condition rather than per-type.
type blastRadiusHandler struct{ e *Engine }

// Handle implements ConditionHandler by routing through PrepareCommit and admitting the
// single bucket, so the condition has ONE implementation of its own semantics.
func (h blastRadiusHandler) Handle(ctx context.Context, cond capability.Condition, req *capability.EnforceRequest) *ConditionError {
	return h.e.prepareAndAdmit(ctx, h, cond, req)
}

// PrepareCommit runs the condition's pure checks (the bounds' well-formedness and the
// per-call `max`) and derives the weighted bucket for a cumulative bound.
func (h blastRadiusHandler) PrepareCommit(ctx context.Context, cond capability.Condition, req *capability.EnforceRequest) (DeferredCommit, bool, *ConditionError) {
	br, condErr := castCondition[capability.BlastRadiusCondition](cond)
	if condErr != nil {
		return DeferredCommit{}, false, condErr
	}
	if br == nil {
		return DeferredCommit{}, false, effectDenial(capability.ConditionTypeBlastRadius,
			"blastRadius condition is nil and cannot be evaluated", nil)
	}
	if br.Max == nil && !br.HasVelocity() {
		// The loader requires at least one bound, and rejects a half-written cumulative
		// pair; a programmatically built condition may carry neither, or half of one. A
		// condition that bounds nothing must not read as "checked and fine".
		return DeferredCommit{}, false, effectDenial(capability.ConditionTypeBlastRadius,
			"blastRadius declares neither 'max' nor a complete 'maxTotal'/'windowSeconds' pair, so it bounds nothing", nil)
	}

	eff, resolved := resolvedEffectFromContext(ctx)
	if !resolved {
		return DeferredCommit{}, false, effectDenial(capability.ConditionTypeBlastRadius,
			"effect contract was not resolved for this call; blast radius is unavailable", nil)
	}

	// The per-call bound first, and only then the cumulative one. A call over the per-call
	// bound must be refused WITHOUT consuming any of the cumulative budget: charging a
	// refused call's magnitude to the window would let a burst of oversized attempts exhaust
	// the budget of the calls that were actually permitted.
	if br.Max != nil {
		if condErr := checkPerCallBlastRadius(br, eff); condErr != nil {
			return DeferredCommit{}, false, condErr
		}
	}
	if !br.HasVelocity() {
		// Bound checked, nothing to commit.
		return DeferredCommit{}, false, nil
	}
	return h.e.velocityBucket(ctx, br, eff, req)
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

// CeilingVerdictFor answers ONE question — "does this action exceed the policy's effect
// ceiling?" — for a constraint that has already been selected, WITHOUT evaluating a single
// condition and WITHOUT committing any state. It returns the refusal the ceiling would
// produce (an ESCALATION_REQUIRED escalate, or a plain deny per onExceed), or nil when the
// policy sets no ceiling, no constraint was selected, or the action is within it.
//
// It exists for the COMPOSED case. A PDP wrapping this engine's PDP — the JWT layer — can
// refuse a call on its own terms and short-circuit above the inner PDP, so evaluateMatched
// never runs and the ceiling never evaluates. The call is still refused, but the KIND of
// refusal is wrong in two ways that matter: the escalation never happens, so an action
// that should have entered the approval queue silently does not and the escalation counts
// under-report; and the composed refusal is a soft deny, which a route running --audit
// downgrades to a FORWARD — so adding a JWT would forward a call the same manifest refuses
// outright, inverting the rule that a token may only ever restrict.
//
// Non-committing is the whole design constraint, and it is why this answers the ceiling
// question ALONE rather than replaying the full decision. Reaching the ceiling the normal
// way means running the matched constraint's conditions, and some of those COMMIT: maxCalls
// consumes a window slot, labelOutput writes a flow label, sequenceBlock writes an
// antecedent. Running them for a call that is already refused and will never be forwarded
// would leave exactly the phantom state evaluateMatched's ordering exists to prevent — the
// reason checkEffectCeiling runs before the state commit in the first place. Trading a
// wrong denial code for corrupted session state is not a fix. The ceiling's inputs are the
// resolved effect of the matched constraint's contract and nothing else, so this cannot
// disagree with the full path about whether the action is over the ceiling.
//
// What it deliberately does NOT reproduce: when a condition would have denied FIRST, the
// full path returns that condition's verdict and never reaches the ceiling, while this
// reports the ceiling. The caller composes a refusal for a call that is being refused
// either way, so the difference is a harder refusal rather than a wrong one — and the
// ceiling statement it carries is true regardless of which check the full path would have
// stopped at. The caller must therefore only ever use this to HARDEN a refusal, never to
// produce an allow, and never on a path that would otherwise forward.
//
// The flow-label peek is the one backend read here, and it is a pure Get, taken only for a
// flow-relevant constraint. Its failure is swallowed rather than converted into a deny:
// this is asked about a call that is ALREADY refused, so a label-store fault must not be
// able to weaken (or replace) the refusal being hardened.
func (e *Engine) CeilingVerdictFor(ctx context.Context, req *capability.EnforceRequest, matched *capability.Constraint) *capability.EnforceResponse {
	if req == nil || matched == nil || !e.effectCeiling.IsSet() {
		return nil
	}
	requestID := NewRequestID()
	now := e.clock.Now().UTC().Format(time.RFC3339Nano)

	// One ResolveEffect of the matched constraint's contract against this call's
	// arguments — the same single resolution evaluateMatched threads to the two effect
	// conditions and the ceiling, so the composed verdict and a full-path verdict cannot
	// disagree about what the call's effect was.
	effect := capability.ResolveEffect(matched.Effect, req.Arguments)

	var carriedLabels []string
	if !e.skipFlow && constraintHasFlow(matched) {
		// A pure read. "Which provenance produced this" is the first thing a human in the
		// approval queue needs, and it is one of the consequence inputs the short-circuit
		// was dropping, so it is worth the round trip on a constraint that has flow at all.
		if labels, err := e.peekSessionLabels(ctx, req); err == nil {
			carriedLabels = labels
		}
	}

	resp := e.checkEffectCeiling(effect, matched, carriedLabels, requestID, now)
	if resp == nil {
		return nil
	}
	// Stamp the snapshot onto the response as evaluateMatched's defer does for every
	// non-allow exit, so a composed escalation carries the same top-level field a
	// full-path one does.
	if resp.CarriedLabels == nil {
		resp.CarriedLabels = carriedLabels
	}
	return resp
}

// ceilingConditionType is the conditionType stamped on a ceiling verdict. The ceiling is
// not a condition an author attaches to a target, so it has no condition discriminator of
// its own; naming it explicitly keeps the audit taxonomy honest about which check fired
// rather than borrowing effectClass, which an operator could then not distinguish from a
// per-target class gate.
const ceilingConditionType = "effectCeiling"
