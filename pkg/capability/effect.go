// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strings"
)

// Effect contracts — the "what may break" axis. Information-flow control answers *who may
// know*; effect contracts answer *what may break*: how consequential an action is,
// independent of who may take it. Same enforcement point, same manifest, two axes.
//
// The vocabulary is a CLOSED, typed set (three effect classes, a numeric blast radius, an
// idempotency flag, a compensating action) because a portable, hash-pinnable registry
// cannot pin a general policy-language blob — "what does this do" would require executing
// it. A partner's complex escalation predicate can still be delegated through the `policy`
// condition instead.
//
// Nothing here infers effect from a payload: a contract is asserted, exactly as a flow
// label is. The argument-parameterized form (ByArgument) is a static decision table
// resolved from the call's own arguments, never a runtime callout.

// Effect class discriminators — the closed reversibility vocabulary, ordered from least
// to most consequential. Flat and totally ordered on purpose: three classes an operator
// can hold in their head, with no lattice until a partner forces a partial order.
const (
	// EffectReversible — the action can be undone by the caller with no external
	// coordination (a read, an idempotent write, a soft-delete with an undo).
	EffectReversible = "reversible"
	// EffectCompensable — the action cannot be undone directly, but a declared
	// compensating action reverses its business effect (a refund reverses a charge).
	// Compensable is NOT the same as safe: the compensation may itself be visible,
	// costly, or delayed, and a compensated action still happened.
	EffectCompensable = "compensable"
	// EffectIrreversible — nothing the caller can do reverses it (an outbound email, a
	// wire transfer, a hard delete). This is also the FAIL-CLOSED default for any action
	// with no contract at all: unannotated means unknown, and unknown must not read as
	// harmless.
	EffectIrreversible = "irreversible"
)

// effectClassOrder ranks the closed vocabulary from least to most consequential. A
// ceiling of "compensable" therefore admits reversible and compensable and stops
// irreversible. Order is fixed so a derived report is deterministic.
var effectClassOrder = []string{EffectReversible, EffectCompensable, EffectIrreversible}

// effectClassRank indexes effectClassOrder for the comparisons.
var effectClassRank = func() map[string]int {
	m := make(map[string]int, len(effectClassOrder))
	for i, c := range effectClassOrder {
		m[c] = i
	}
	return m
}()

// EffectClassVocabulary returns a fresh copy of the ordered effect-class set, so
// validation messages and any derived report enumerate the same closed vocabulary
// without being able to mutate it.
func EffectClassVocabulary() []string {
	return append([]string(nil), effectClassOrder...)
}

// IsEffectClass reports whether s is a recognized effect class. Validation and the
// engine both consult it, so the closed set is enforced identically at load and at
// runtime.
func IsEffectClass(s string) bool {
	_, ok := effectClassRank[s]
	return ok
}

// EffectClassAtMost reports whether class is no more consequential than limit. An
// unrecognized class on either side reports false — fail closed, since an unknown class
// cannot be shown to sit under a bound.
func EffectClassAtMost(class, limit string) bool {
	c, okC := effectClassRank[class]
	l, okL := effectClassRank[limit]
	return okC && okL && c <= l
}

// Condition and directive type discriminators for the effect layer.
const (
	// ConditionTypeEffectClass gates a call on the effect class its contract resolves to.
	ConditionTypeEffectClass = "effectClass"
	// ConditionTypeBlastRadius bounds the quantitative size of one call's effect.
	ConditionTypeBlastRadius = "blastRadius"
)

// EffectContract declares what a call DOES, as PDP-addressable policy input. It replaces
// MCP's self-declared, unauthenticated tool hints: a hint travels with the thing being
// judged, while a contract is asserted by the operator's manifest or pinned from a
// reviewed registry entry.
//
// A constraint with no contract resolves to the fail-closed default (irreversible, blast
// radius unknown), which is the registry flywheel: annotating a tool is what buys it out
// of maximum friction.
type EffectContract struct {
	// Class is the reversibility class (EffectReversible / EffectCompensable /
	// EffectIrreversible). Empty means unannotated and resolves to irreversible.
	Class string `json:"class,omitempty"`
	// Idempotent marks a call that can be safely repeated with no additional effect.
	// It does not by itself make an action reversible — a repeatable outbound email is
	// still irreversible — but it is what lets a retry be treated as one action.
	Idempotent bool `json:"idempotent,omitempty"`
	// CompensatingAction names the target that reverses this one (e.g.
	// "tool:reverse_refund"). Required for a compensable class and rejected on any other
	// — "compensable with nothing to compensate with" is irreversible wearing a softer
	// label, which is exactly the mislabel the consequence gate must not accept.
	CompensatingAction string `json:"compensatingAction,omitempty"`
	// BlastRadius quantifies how much this call affects: a fixed magnitude, or the value
	// of a named argument (rows, spend, recipients). Nil means unquantified, which is
	// treated as exceeding any finite bound.
	BlastRadius *BlastRadiusSpec `json:"blastRadius,omitempty"`
	// ByArgument is the argument-parameterized form: the effect of a call is a function
	// of one of its arguments, expressed as a STATIC decision table (db.query is
	// reversible for SELECT and irreversible for DROP; a transfer's blast radius is its
	// amount). It is resolved from the call's own arguments on the decision path — no
	// callout, no inference — and its matched case overlays the fields above.
	ByArgument *EffectByArgument `json:"byArgument,omitempty"`
	// Ref optionally pins the registry contract this block was authored from, as
	// "<contract-id>@sha256:<hex>", where the digest is EffectContractDigest of this very
	// block. eunox never fetches it — the decision path stays local, so a registry outage
	// cannot change a verdict — but the pin is still verifiable: the loader recomputes the
	// digest of the inline block and refuses a mismatch. That is what makes it an
	// integrity pin rather than a comment. Editing a contract after pinning it therefore
	// fails at load until the author re-pins, which is the review step the registry exists
	// to create.
	Ref string `json:"ref,omitempty"`
}

// BlastRadiusSpec quantifies a call's effect magnitude. Exactly one of Value or Argument
// is set; the loader rejects both and neither.
type BlastRadiusSpec struct {
	// Value is a fixed magnitude for every call to this target.
	Value *json.Number `json:"value,omitempty"`
	// Argument names the call argument carrying the magnitude (an amount, a row count, a
	// recipient list — a list contributes its LENGTH). A missing or unusable argument
	// resolves to unquantified, which exceeds any finite bound: an action whose size
	// cannot be established must not be treated as small.
	Argument string `json:"argument,omitempty"`
	// Unit is a free-form label for reports and audit records ("usd", "rows",
	// "recipients"). It is never compared — eunox does not model unit algebra — so two
	// contracts on the same target must agree on a unit by convention, not by check.
	Unit string `json:"unit,omitempty"`
}

// EffectByArgument is a static decision table keyed on one argument's value: the
// argument-parameterized contract form. Cases are matched against the argument's string
// form, case-insensitively for a string argument, with Default applying when nothing
// matches.
//
// It is deliberately a TABLE and not an expression. A table is reviewable and pinnable —
// the two properties the registry needs — where an expression would have to be executed
// to be understood.
type EffectByArgument struct {
	// Argument names the call argument the table keys on.
	Argument string `json:"argument"`
	// Cases maps an argument value to the contract fields that overlay the base contract
	// when it matches. For an operation-style argument the FIRST whitespace-delimited
	// token is matched too, so a case of "DROP" matches "DROP TABLE users" — the same
	// coarse first-verb rule allowedOperations uses, with the same documented limit that
	// it is not a SQL parser.
	Cases map[string]EffectCase `json:"cases"`
	// Default applies when no case matches. Absent means the fail-closed default
	// (irreversible, unquantified) rather than the base contract: a table that does not
	// cover a value has not said the value is safe.
	Default *EffectCase `json:"default,omitempty"`
}

// EffectCase is one row of an argument-parameterized contract.
type EffectCase struct {
	Class              string           `json:"class,omitempty"`
	Idempotent         *bool            `json:"idempotent,omitempty"`
	CompensatingAction string           `json:"compensatingAction,omitempty"`
	BlastRadius        *BlastRadiusSpec `json:"blastRadius,omitempty"`
}

// ResolvedEffect is a contract reduced against one call's arguments: the values the
// conditions and the ceiling actually compare.
//
// A resolved effect is READ-ONLY once returned. ResolveEffect produces a fresh value per
// call and the engine threads it by pointer through the decision context, so the
// condition handlers, the ceiling, and the audit record all read one snapshot; mutating
// it would change what a later reader in the same decision judges.
type ResolvedEffect struct {
	Class              string
	Idempotent         bool
	CompensatingAction string
	BlastRadius        *big.Float
	Unit               string
	Ref                string
	// Annotated is false when the constraint carried no contract at all, so a caller can
	// distinguish "declared irreversible" from "unannotated, defaulted to irreversible"
	// in an audit record or an operator message. Both deny the same way; only the
	// remediation differs (review the action vs. annotate the tool).
	Annotated bool
}

// Quantified reports whether a blast radius could be established for this call. False —
// no contract, a contract naming an argument the call did not supply, or an argument with
// no magnitude — is treated as EXCEEDING every numeric bound: an action whose size cannot
// be established must not be treated as small.
//
// Derived rather than stored. It was a bool field set alongside BlastRadius, which made
// one fact two sources of truth: a directly-constructed ResolvedEffect could carry
// Quantified: true with a nil BlastRadius, and the very next thing every reader does with
// a quantified effect is dereference that pointer to compare or render it. Deriving it
// makes the pair unable to disagree.
func (e *ResolvedEffect) Quantified() bool { return e != nil && e.BlastRadius != nil }

// UnannotatedEffect is the fail-closed resolution for a target with no contract:
// irreversible, unquantified, nothing to compensate with. It is what makes the registry
// a flywheel rather than a nice-to-have — an unannotated tool exceeds any ceiling and so
// escalates, and the way out is to annotate it.
func UnannotatedEffect() *ResolvedEffect {
	return &ResolvedEffect{Class: EffectIrreversible}
}

// EffectClassCondition denies a call whose resolved effect class is not in Allow. It is
// the per-target gate ("this target may only ever do reversible things"), the coarse
// sibling of the tool-agnostic effectCeiling.
//
// An empty Allow admits nothing — the strictest, fail-closed reading, matching
// flowLabel's empty allow set.
type EffectClassCondition struct {
	Allow []string `json:"allow"`
}

// ConditionType returns the effectClass discriminator.
func (EffectClassCondition) ConditionType() string { return ConditionTypeEffectClass }

// MarshalJSON serializes EffectClassCondition with its discriminator.
func (c EffectClassCondition) MarshalJSON() ([]byte, error) { return marshalCondition(c) }

// BlastRadiusCondition bounds the quantitative size of one call's effect ("no refund over
// $500") — a magnitude an argument-level allowlist cannot express, since the argument is
// legal at every value and only its SIZE is the problem. A call whose size cannot be
// quantified FAILS the condition (an unestablished size must not read as small).
//
// CUMULATIVE velocity (`maxTotal` over `windowSeconds`) is the second half: it bounds the
// SUMMED magnitude of a session's calls to the target, catching four hundred individually-
// permitted $10 refunds where the per-call bound only catches one $5,000 refund — exactly
// the shape a compromised or prompt-injected agent produces. It is backed by a WEIGHTED
// CallCounter.AdmitAll bucket (the same admission maxCalls commits through), and an
// over-limit call writes NOTHING, so a burst of rejections cannot extend its own lockout.
type BlastRadiusCondition struct {
	// Max bounds one call's magnitude. Optional only in the sense that a condition
	// declaring a cumulative bound instead still bounds something; a condition declaring
	// NEITHER is rejected at load, since a bound-free condition bounds nothing.
	Max *json.Number `json:"max,omitempty"`
	// MaxTotal bounds the SUMMED magnitude of this session's calls to this target within
	// WindowSeconds. Set together with WindowSeconds or not at all: half the pair silently
	// disables the other half, which is the failure the loader rejects rather than accepts.
	// An authored bound that bounded nothing would be worse than its absence, because the
	// operator would believe a limit was in force.
	MaxTotal *json.Number `json:"maxTotal,omitempty"`
	// WindowSeconds is the sliding window MaxTotal is summed over. Set together with
	// MaxTotal or not at all.
	WindowSeconds int `json:"windowSeconds,omitempty"`
}

// HasVelocity reports whether this condition declares a cumulative bound — the property
// that makes it commit state, and therefore the property the engine keys deferral and the
// loader keys its one-committing-condition rule on. Both halves are required because
// either alone bounds nothing; the loader rejects that shape, so a manifest-loaded
// condition can never be half-set, but a programmatically built one can.
func (c *BlastRadiusCondition) HasVelocity() bool {
	return c != nil && c.MaxTotal != nil && c.WindowSeconds > 0
}

// RefineStateAccumulation narrows the registry's declared class to what THIS bound actually
// accumulates (see StateRefiner). A cumulative bound consumes a sliding-window budget exactly
// as maxCalls consumes a slot, so it is per-process state under the in-memory counter and the
// multi-instance advisory must fire for it. A per-call `max` compares one call's magnitude
// against a constant and stores nothing, so a policy whose only blastRadius is per-call does
// not depend on shared state and must not be warned about as if it did.
func (c BlastRadiusCondition) RefineStateAccumulation() StateAccumulation {
	if c.HasVelocity() {
		return StateAtomic
	}
	return StateNone
}

// ConditionType returns the blastRadius discriminator.
func (BlastRadiusCondition) ConditionType() string { return ConditionTypeBlastRadius }

// MarshalJSON serializes BlastRadiusCondition with its discriminator.
func (c BlastRadiusCondition) MarshalJSON() ([]byte, error) { return marshalCondition(c) }

// EffectCeiling is the tool-agnostic consequence bound: a top-level policy statement
// that EVERY allowed action is additionally checked against, keyed on the action's effect
// properties rather than on which tool it is.
//
// This is the purest form of consequence-gated escalation. A per-target condition has to
// be written for each target, so the tool nobody thought about is the one with no gate;
// the ceiling inverts that — a new or unannotated tool has no contract, therefore exceeds
// the ceiling, therefore escalates. Approval is triggered by irreversibility plus blast
// radius plus the absence of a compensating action, never by tool identity.
//
// The ceiling can only ever narrow: it is applied after a constraint has already allowed
// the call, so it never admits anything the manifest denied.
type EffectCeiling struct {
	// MaxEffectClass is the most consequential class that passes without escalation.
	// Empty leaves the class dimension unbounded.
	MaxEffectClass string `json:"maxEffectClass,omitempty"`
	// MaxBlastRadius is the largest magnitude that passes. Nil leaves the magnitude
	// dimension unbounded. An unquantified action exceeds any set bound.
	MaxBlastRadius *json.Number `json:"maxBlastRadius,omitempty"`
	// RequireCompensation, when set, additionally demands a compensating action for any
	// action above MaxEffectClass — the third input of the consequence gate. It is what
	// distinguishes "irreversible but undoable in business terms" from "irreversible full
	// stop".
	RequireCompensation bool `json:"requireCompensation,omitempty"`
	// OnExceed selects the outcome for an action over the ceiling: OnExceedEscalate (the
	// default) marks it as needing human approval, OnExceedDeny refuses it outright.
	// Empty means escalate.
	OnExceed string `json:"onExceed,omitempty"`
}

// Ceiling outcomes for EffectCeiling.OnExceed.
const (
	// OnExceedEscalate routes an over-ceiling action to human approval. With no approval
	// integration wired it is a refusal that says WHY — the fail-closed reading of
	// "escalate" is deny, never allow.
	OnExceedEscalate = "escalate"
	// OnExceedDeny refuses an over-ceiling action outright, with no approval path.
	OnExceedDeny = "deny"
)

// Outcome returns the ceiling's effective OnExceed, defaulting to escalate.
func (c *EffectCeiling) Outcome() string {
	if c == nil || c.OnExceed == "" {
		return OnExceedEscalate
	}
	return c.OnExceed
}

// IsSet reports whether the ceiling bounds anything it can actually evaluate. A ceiling
// that bounds nothing is treated as absent rather than as a ceiling every action passes,
// so a half-written block cannot read as "checked and fine".
//
// RequireCompensation deliberately does NOT count on its own: the compensation leg only
// applies to an action ABOVE the class bound, so with no MaxEffectClass it can never fire.
// Counting it would make IsSet — and the HasEffectCeiling wiring gate that reads it —
// report an active ceiling that is structurally incapable of refusing anything, which is
// precisely the state this predicate exists to deny. The manifest loader rejects that
// shape too; this closes the same hole for the exported WithEffectCeiling seam, which
// takes a ceiling directly and never passes through the loader.
func (c *EffectCeiling) IsSet() bool {
	return c != nil && (c.MaxEffectClass != "" || c.MaxBlastRadius != nil)
}

// Exceeds reports whether a resolved effect is over the ceiling, and why. reasons are
// stable, machine-readable tokens for the audit record; the human message is built by the
// caller. A nil or unset ceiling never exceeds.
func (c *EffectCeiling) Exceeds(eff *ResolvedEffect) (exceeds bool, reasons []string) {
	if !c.IsSet() {
		return false, nil
	}
	// requireCompensation with no class bound to hang it on — OR a class bound of
	// "irreversible", the top of the vocabulary, against which overClass below can never
	// be true either. The manifest loader rejects both shapes outright; the exported
	// WithEffectCeiling seam takes a ceiling directly and never passes through it, and
	// there the leg below could never fire — an operator would have authored a
	// compensation requirement that silently bounded nothing. An unevaluable ceiling leg
	// must not read as "checked and fine", so it exceeds, loudly, with a token that names
	// the misconfiguration rather than a consequence.
	if c.RequireCompensation && (c.MaxEffectClass == "" || c.MaxEffectClass == EffectIrreversible) {
		return true, []string{"ceiling_misconfigured"}
	}
	overClass := c.MaxEffectClass != "" && !EffectClassAtMost(eff.Class, c.MaxEffectClass)
	if overClass {
		reasons = append(reasons, "effect_class")
	}
	if c.MaxBlastRadius != nil {
		switch {
		case !eff.Quantified():
			// Unquantified is over ANY finite bound: an action whose size cannot be
			// established must not be treated as small.
			reasons = append(reasons, "blast_radius_unknown")
		case exceedsNumber(eff.BlastRadius, *c.MaxBlastRadius):
			reasons = append(reasons, "blast_radius")
		}
	}
	// The compensation leg is the third input of the consequence gate and applies only to
	// an action already over the class bound: demanding a compensating action for a
	// reversible read would be noise, and the gate is about consequence, not paperwork.
	if c.RequireCompensation && overClass && eff.CompensatingAction == "" {
		reasons = append(reasons, "no_compensating_action")
	}
	return len(reasons) > 0, reasons
}

// exceedsNumber reports whether value is strictly greater than limit. An unparseable
// limit reports true (fail closed: a bound that cannot be read bounds nothing, and
// treating it as satisfied would silently disable the check). A nil value is handled by
// the caller's Quantified test and never reaches here.
func exceedsNumber(value *big.Float, limit json.Number) bool {
	lim, ok := new(big.Float).SetString(limit.String())
	if !ok {
		return true
	}
	return value != nil && value.Cmp(lim) > 0
}

// EffectContractDigest returns the "sha256:<lowercase-hex>" digest of a contract's
// CONTENT — every field except Ref, which cannot be inside its own digest.
//
// It is what makes a registry contract hash-pinnable, and it is why the effect vocabulary
// had to stay a closed typed schema: you can pin a declaration and check it locally, but
// pinning a policy program tells a reviewer nothing without executing it. The encoding is
// encoding/json over the typed struct — field order is the struct's, and map keys (the
// argument-parameterized cases) are sorted by encoding/json — so the same contract always
// produces the same digest regardless of how the source document was written or ordered.
func EffectContractDigest(c *EffectContract) (string, error) {
	if c == nil {
		return "", fmt.Errorf("cannot digest a nil effect contract")
	}
	content := *c
	content.Ref = ""
	b, err := json.Marshal(content)
	if err != nil {
		return "", fmt.Errorf("serializing effect contract for digest: %w", err)
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// SplitEffectRef splits a contract ref into its id and digest halves. ok is false for a
// ref that is not "<contract-id>@sha256:<hex>" shaped.
func SplitEffectRef(ref string) (id, digest string, ok bool) {
	id, digest, ok = strings.Cut(ref, "@")
	if !ok || strings.TrimSpace(id) == "" || digest == "" {
		return "", "", false
	}
	return id, digest, true
}

// Bounds on a decimal literal this package will parse into an arbitrary-precision value.
//
// Length alone does not bound the work: "1e1000000" is nine bytes and expands to a
// ~1 MiB integer, and rendering it back with big.Float.Text('f', -1) costs a full second
// and a megabyte of string. Both bounds are therefore needed, and both are far above any
// literal a real policy or a real tool argument carries — the exact arm exists to compare
// integers around and above 2^63, which needs tens of digits.
//
// Neither bound says anything about a literal outside the decimal grammar: a binary or
// hex-float exponent scales the value by a power of two that no decimal-digit budget
// bounds, so NumericLiteralBounded refuses those forms outright rather than sizing them.
const (
	MaxNumericLiteralLen = 1024
	MaxNumericLiteralExp = 1024
)

// NumericLiteralBounded reports whether s is a DECIMAL numeric literal small enough to
// parse into an arbitrary-precision value without materializing a huge intermediate: the
// grammar
//
//	[+-]? ( digits [ "." [digits] ] | "." digits ) ( [eE] [+-]? digits )?
//
// within MaxNumericLiteralLen bytes and an exponent within MaxNumericLiteralExp.
// big.Float/big.Rat SetString accept more than decimal (binary/hex-float exponents,
// underscore separators, rationals), and a guard that only scanned for 'e'/'E' would miss
// e.g. "1p1000000" — nine bytes whose Text('f', -1) render costs seconds of CPU and
// hundreds of megabytes. Restricting to decimal also keeps the value a caller WRITES the
// same as the value compared (SetString reads "0x1p4" as 16, not as hex-float notation).
//
// Shared by three layers needing the identical bound against the identical input class —
// the JSON-RPC id parse (internal/mcp), allowedValues' exact numeric comparison
// (pkg/enforcement), and the blast-radius parse below — so it lives here rather than as
// three copies that could drift. Anything outside the grammar reports false, so callers
// fall back to their own conservative not-exact path.
func NumericLiteralBounded(s string) bool {
	if s == "" || len(s) > MaxNumericLiteralLen {
		return false
	}
	i := 0
	if s[i] == '+' || s[i] == '-' {
		i++
	}
	mantissa := 0
	for ; i < len(s) && isASCIIDigit(s[i]); i++ {
		mantissa++
	}
	if i < len(s) && s[i] == '.' {
		for i++; i < len(s) && isASCIIDigit(s[i]); i++ {
			mantissa++
		}
	}
	if mantissa == 0 {
		return false // "", "+", ".", "0x1p4", "Inf", "abc" — no decimal mantissa
	}
	if i == len(s) {
		return true // no exponent: only the length cap applies
	}
	if s[i] != 'e' && s[i] != 'E' {
		return false // a trailing 'p', '_', '/', or anything else is not decimal
	}
	i++
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		i++
	}
	exp, digits := 0, 0
	for ; i < len(s) && isASCIIDigit(s[i]); i++ {
		digits++
		if exp <= MaxNumericLiteralExp {
			// Accumulation stops once the bound is passed, so a million-digit
			// exponent cannot overflow the int on its way to being rejected.
			exp = exp*10 + int(s[i]-'0')
		}
	}
	if digits == 0 || i != len(s) {
		return false
	}
	return exp <= MaxNumericLiteralExp
}

func isASCIIDigit(c byte) bool { return c >= '0' && c <= '9' }

// ParseBlastRadiusNumber converts a numeric literal to an exact big.Float, so a bound
// above 2^53 is compared exactly rather than through a lossy float64 widening (the same
// reason condition literals are decoded with UseNumber). ok is false for a literal that
// is not a number, or one outside NumericLiteralBounded.
//
// The bound is load-bearing on BOTH sides. On the manifest side it turns an absurd
// authored bound into a load error. On the REQUEST side it is a DoS guard: the literal is
// a caller-supplied tool argument, and without the bound "1e100000000" — twelve bytes —
// parses cheaply and then costs seconds of CPU and gigabytes of string when the denial
// path renders it with Text('f', -1), synchronously, inside the per-session decision.
// Rejecting it here resolves the call unquantified, which exceeds every bound and so
// fails closed.
func ParseBlastRadiusNumber(n json.Number) (*big.Float, bool) {
	if !NumericLiteralBounded(n.String()) {
		return nil, false
	}
	f, ok := new(big.Float).SetString(n.String())
	return f, ok
}

// ResolveEffect reduces a constraint's contract against one call's arguments. It is the
// single resolution path, so the effectClass condition, the blastRadius condition, the
// ceiling, and the audit record all judge exactly the same values — a second resolver
// would be a place for them to silently disagree.
//
// A nil contract resolves to UnannotatedEffect (irreversible, unquantified): the
// fail-closed default that makes an unannotated tool escalate under any ceiling.
func ResolveEffect(contract *EffectContract, args map[string]interface{}) *ResolvedEffect {
	if contract == nil {
		return UnannotatedEffect()
	}
	eff := &ResolvedEffect{
		Class:              contract.Class,
		Idempotent:         contract.Idempotent,
		CompensatingAction: contract.CompensatingAction,
		Ref:                contract.Ref,
		Annotated:          true,
	}
	spec := contract.BlastRadius

	// The argument-parameterized table overlays the base contract. A table that matches
	// nothing and declares no default resolves to the fail-closed default rather than to
	// the base contract: a table that does not cover a value has not said it is safe.
	if tbl := contract.ByArgument; tbl != nil {
		matched, found := tbl.match(args)
		switch {
		case found:
			if matched.Class != "" {
				eff.Class = matched.Class
			}
			if matched.Idempotent != nil {
				eff.Idempotent = *matched.Idempotent
			}
			if matched.CompensatingAction != "" {
				eff.CompensatingAction = matched.CompensatingAction
			}
			if matched.BlastRadius != nil {
				spec = matched.BlastRadius
			}
		default:
			// No case matched and no default row: the fail-closed reading. Every
			// assertion the base contract made about this call is void, INCLUDING
			// idempotence — a table that does not cover a value has not said the value is
			// safe to repeat any more than it has said it is reversible. Leaving
			// Idempotent set would let a retry-safety claim survive precisely where the
			// contract stopped describing the call.
			eff.Class = EffectIrreversible
			eff.CompensatingAction = ""
			eff.Idempotent = false
			spec = nil
		}
	}

	if eff.Class == "" {
		// Declared a contract but no class: unknown, so irreversible. Annotated stays
		// true — the operator wrote a contract, they just did not say how reversible it
		// is, which is a different remediation from "no contract at all".
		eff.Class = EffectIrreversible
	}
	// Apply the compensable invariant to the RESOLVED effect, not only to the authored
	// one. The loader enforces "a compensating action is what makes an action compensable"
	// per declaration, but an argument-parameterized row that RAISES the class (a
	// compensable base contract whose DROP case is irreversible) inherited the base
	// block's compensatingAction and produced exactly the pairing the loader refuses — an
	// irreversible action carrying something that claims to reverse it. That suppressed
	// the ceiling's no_compensating_action reason and put a false compensating action on
	// the escalation record a human is expected to act on.
	if eff.Class != EffectCompensable {
		eff.CompensatingAction = ""
	}
	if spec != nil {
		eff.Unit = spec.Unit
		if v, ok := spec.resolve(args); ok {
			eff.BlastRadius = v
		}
	}
	return eff
}

// match finds the case for the call's argument value. found is false when the argument is
// absent or unusable and no default is declared.
func (t *EffectByArgument) match(args map[string]interface{}) (EffectCase, bool) {
	// ResolveArgument, not a bare map index: the `argument` reference obeys the same
	// "$." nested-path grammar every argument-matching condition obeys. A bare index
	// made a documented reference like "$.filters.query" resolve to ABSENT, so the
	// table never matched and a permissive default silently applied to the exact call
	// the table was written to catch.
	raw, ok := ResolveArgument(args, t.Argument)
	if !ok {
		if t.Default != nil {
			return *t.Default, true
		}
		return EffectCase{}, false
	}
	key := argumentMatchKey(raw)
	if c, hit := t.lookup(key); hit {
		return c, true
	}
	// Operation-style arguments carry the verb as the first token ("DROP TABLE users").
	// Matching it goes through the SHARED OperationVerb, so it is literally the rule
	// allowedOperations applies rather than a lookalike: splitting on a space alone made
	// a newline- or tab-formatted statement — the norm from a model — miss its case and
	// fall to the default. The documented limit is unchanged: it is not a SQL parser, and
	// a case never matches a verb buried after a leading CTE.
	if verb := OperationVerb(key); verb != "" && verb != key {
		if c, hit := t.lookup(verb); hit {
			return c, true
		}
	}
	if t.Default != nil {
		return *t.Default, true
	}
	return EffectCase{}, false
}

// lookup matches a case key case-insensitively. On a fold collision it resolves to the
// lexicographically SMALLEST matching key rather than Go's randomized map order: the loader
// rejects such collisions in a manifest, but a programmatically built contract can still
// produce one, and a nondeterministic verdict is disqualifying for a layer whose whole claim
// is determinism.
//
// Tracking the smallest match in one pass, rather than materializing and sorting the key
// set, keeps that determinism allocation-free: this runs up to twice per enforced call
// (the raw key, then the first verb) on the decision path, and the sort was O(n log n)
// work plus a fresh slice to answer what is almost always a single-candidate question.
func (t *EffectByArgument) lookup(key string) (EffectCase, bool) {
	var (
		best  string
		found bool
	)
	for k := range t.Cases {
		if !strings.EqualFold(strings.TrimSpace(k), key) {
			continue
		}
		if !found || k < best {
			best, found = k, true
		}
	}
	if !found {
		return EffectCase{}, false
	}
	return t.Cases[best], true
}

// argumentMatchKey renders an argument value as the string the decision table matches on.
// Numbers keep their literal form (json.Number is preserved through decoding), booleans
// render as true/false, and anything else renders through fmt so a table can key on it
// without the resolver having to model every JSON shape.
func argumentMatchKey(raw interface{}) string {
	switch v := raw.(type) {
	case string:
		return strings.TrimSpace(v)
	case json.Number:
		return v.String()
	case bool:
		if v {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%v", raw)
	}
}

// resolve computes the call's blast-radius magnitude. ok is false when it cannot be
// established, which every numeric bound treats as exceeded.
//
// A NEGATIVE result is rejected as unestablished rather than compared. A magnitude is
// non-negative by construction — the loader refuses a negative bound and a negative fixed
// value for exactly that reason — but the argument-supplied value is CALLER-controlled,
// and an unchecked negative passed every bound: `amount: -1000000` compared below any max
// and under any ceiling. Treating it as unquantified applies the same rule to the runtime
// value that the loader applies to the authored one, and lands on the fail-closed side.
func (s *BlastRadiusSpec) resolve(args map[string]interface{}) (*big.Float, bool) {
	v, ok := s.resolveRaw(args)
	if !ok || v == nil || v.Sign() < 0 || v.IsInf() {
		return nil, false
	}
	return v, true
}

// resolveRaw reads the declared magnitude before the non-negativity check.
func (s *BlastRadiusSpec) resolveRaw(args map[string]interface{}) (*big.Float, bool) {
	if s.Value != nil {
		return ParseBlastRadiusNumber(*s.Value)
	}
	if s.Argument == "" {
		return nil, false
	}
	// Same shared resolver the conditions use, so a "$." nested reference addresses the
	// same value here as it does in an allowedValues on the same argument.
	raw, ok := ResolveArgument(args, s.Argument)
	if !ok {
		return nil, false
	}
	switch v := raw.(type) {
	case json.Number:
		return ParseBlastRadiusNumber(v)
	case float64:
		// A caller that decoded arguments without UseNumber. Exactness is already lost
		// upstream; carry the value through rather than reporting it unquantified, which
		// would over-block every such caller. NaN and Inf are screened FIRST:
		// big.Float.SetFloat64 PANICS on NaN, and an unevaluable input must fail closed,
		// never take down the enforcement goroutine.
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return nil, false
		}
		return new(big.Float).SetFloat64(v), true
	case string:
		// A DECIMAL numeric string ("250") is a magnitude; anything else is not. This does
		// NOT fall through to counting characters — a free-form string has no magnitude,
		// and inventing one would be exactly the inference this layer refuses to do.
		//
		// This is the one arm where the literal reaching SetString is BOTH caller-supplied
		// and free of JSON's number grammar: the json.Number arm above cannot spell a
		// binary exponent or a hex float, and this one can. NumericLiteralBounded is
		// therefore load-bearing here in full — length, exponent, AND decimal-only — since
		// "1p100000000" is eleven bytes whose render would cost seconds and hundreds of
		// megabytes on the per-session decision path.
		t := strings.TrimSpace(v)
		if !NumericLiteralBounded(t) {
			return nil, false
		}
		return new(big.Float).SetString(t)
	case []interface{}:
		// A list argument (recipients, row ids) contributes its LENGTH: "how many things
		// does this touch" is the quantity a recipient-count or row-count bound means.
		return new(big.Float).SetInt64(int64(len(v))), true
	default:
		return nil, false
	}
}

// String renders a resolved effect for an operator-facing message.
func (e *ResolvedEffect) String() string {
	parts := []string{"class=" + e.Class}
	if e.Quantified() {
		br := "blastRadius=" + e.BlastRadius.Text('f', -1)
		if e.Unit != "" {
			br += " " + e.Unit
		}
		parts = append(parts, br)
	} else {
		parts = append(parts, "blastRadius=unquantified")
	}
	if e.CompensatingAction != "" {
		parts = append(parts, "compensatingAction="+e.CompensatingAction)
	}
	if !e.Annotated {
		parts = append(parts, "unannotated")
	}
	return strings.Join(parts, " ")
}

// AuditDetails renders a resolved effect as the structured fields an audit record and a
// denial detail carry. Sorted, scalar values only — never free-form prose in a structured
// field.
func (e *ResolvedEffect) AuditDetails() map[string]interface{} {
	d := map[string]interface{}{
		// A stable discriminator saying THIS refusal came from the effect layer, so an
		// operator (or a SIEM rule) can select every effect-layer record on one key
		// instead of enumerating the layer's other details. Set here, once, rather than at
		// each denial site: it was stamped by hand at four of them, which is a marker one
		// new site forgets and a reader then reads as "not an effect refusal".
		"effect":       true,
		"effect_class": e.Class,
		"annotated":    e.Annotated,
	}
	if e.Quantified() {
		d["blast_radius"] = e.BlastRadius.Text('f', -1)
		if e.Unit != "" {
			d["blast_radius_unit"] = e.Unit
		}
	}
	if e.CompensatingAction != "" {
		d["compensating_action"] = e.CompensatingAction
	}
	if e.Ref != "" {
		d["effect_contract"] = e.Ref
	}
	return d
}

// SortedEffectClasses returns classes in vocabulary order, for deterministic messages
// and audit details built from a manifest-authored set.
func SortedEffectClasses(classes []string) []string {
	out := append([]string(nil), classes...)
	sort.SliceStable(out, func(i, j int) bool {
		ri, oki := effectClassRank[out[i]]
		rj, okj := effectClassRank[out[j]]
		if oki && okj {
			return ri < rj
		}
		return out[i] < out[j]
	})
	return out
}
