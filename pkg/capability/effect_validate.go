// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Semantic validation for the effect layer. This package owns the reversibility vocabulary
// and the contract digest, so it owns what makes a contract WELL-FORMED too — these rules
// used to live in internal/config, reachable only from the manifest loader, which let the
// registry corpus validate and digest an entry that was semantically nonsense (wrong class,
// compensable with no compensating action, ...) and fail later at manifest load with a
// confusing error about a block copied verbatim from a corpus that said it was fine.
//
// Errors carry NO positional framing (no capability index, no file name): each caller adds
// its own, so the same rule reads correctly whether it fired on a manifest capability or a
// corpus file.

package capability

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// ValidateEffectContract checks a contract's semantic invariants: a class from the closed
// vocabulary, the compensable/compensatingAction pairing, a blast radius that quantifies
// exactly one way, a well-formed argument-parameterized table, and — when present — a
// registry pin whose digest matches the contract's own content. A nil contract is valid
// (no effect declared).
func ValidateEffectContract(e *EffectContract) error {
	if e == nil {
		return nil
	}
	if e.Class != "" && !IsEffectClass(e.Class) {
		return fmt.Errorf("effect 'class' is %q — valid effect classes are %s", e.Class, strings.Join(EffectClassVocabulary(), ", "))
	}
	if err := validateCompensationPairing("effect", e.Class, e.CompensatingAction); err != nil {
		return err
	}
	if err := validateBlastRadiusSpec("effect.blastRadius", e.BlastRadius); err != nil {
		return err
	}
	if err := validateEffectRefPin(e); err != nil {
		return err
	}
	return validateEffectByArgument(e)
}

// ValidateEffectCeiling checks the top-level consequence bound. A ceiling that bounds
// nothing is rejected rather than treated as satisfied by every action: a half-written
// ceiling that loads cleanly is a policy an operator believes is in force and is not.
func ValidateEffectCeiling(c *EffectCeiling) error {
	if c == nil {
		return nil
	}
	if c.MaxEffectClass != "" && !IsEffectClass(c.MaxEffectClass) {
		return fmt.Errorf("effectCeiling 'maxEffectClass' is %q — valid effect classes are %s", c.MaxEffectClass, strings.Join(EffectClassVocabulary(), ", "))
	}
	if c.MaxBlastRadius != nil {
		v, ok := ParseBlastRadiusNumber(*c.MaxBlastRadius)
		if !ok {
			return fmt.Errorf("effectCeiling 'maxBlastRadius' is not a number (got %q)", c.MaxBlastRadius.String())
		}
		if v.Sign() < 0 {
			return fmt.Errorf("effectCeiling 'maxBlastRadius' must not be negative (got %q)", c.MaxBlastRadius.String())
		}
	}
	switch c.OnExceed {
	case "", OnExceedEscalate, OnExceedDeny:
	default:
		return fmt.Errorf("effectCeiling 'onExceed' is %q — valid outcomes are %s (the default) and %s", c.OnExceed, OnExceedEscalate, OnExceedDeny)
	}
	// RequireCompensation only ever applies to an action already over the class bound
	// (see EffectCeiling.Exceeds), so on its own it is inert — and inert-but-present is
	// exactly the shape that reads as a control when it is not. Checked BEFORE the
	// bounds-nothing test below so the author gets the specific diagnosis ("this key needs
	// that one") rather than the generic one, which would send them to add a key they
	// already wrote.
	//
	// A MaxEffectClass of "irreversible" is the SAME inert shape wearing a valid-looking
	// spelling: irreversible is the top of the vocabulary, so no resolvable class is ever
	// "over" it (Exceeds' overClass can never be true) — the class leg AND the compensation
	// leg both never fire, byte-for-byte the failure mode the empty-MaxEffectClass message
	// above describes, yet this spelling loaded clean and read as an active control.
	if c.RequireCompensation && (c.MaxEffectClass == "" || c.MaxEffectClass == EffectIrreversible) {
		return fmt.Errorf("effectCeiling 'requireCompensation' needs 'maxEffectClass' set to a class below %q: it demands a compensating action only for an action ABOVE the class bound, so with %s it never fires", EffectIrreversible, classOrUnset(c.MaxEffectClass))
	}
	if !c.IsSet() {
		return fmt.Errorf("effectCeiling bounds nothing: set 'maxEffectClass' or 'maxBlastRadius' (a ceiling with only 'onExceed' never fires, which reads as \"checked and fine\")")
	}
	return nil
}

// validateCompensationPairing enforces the one invariant that keeps the compensable class
// meaningful: compensable means "there is a declared action that reverses this", and
// anything else means there is not.
//
// Without it, "compensable" degrades into a softer word for irreversible — an author
// labels a wire transfer compensable, the consequence gate reads a compensating action
// as present, and the exact case the gate exists to escalate passes through it.
func validateCompensationPairing(where, class, compensating string) error {
	switch {
	case class == EffectCompensable && compensating == "":
		return fmt.Errorf("%s declares class %q but no 'compensatingAction'; compensable means a declared action reverses this one, so without it the class is irreversible wearing a softer label", where, EffectCompensable)
	case class != EffectCompensable && compensating != "":
		return fmt.Errorf("%s declares 'compensatingAction' with class %q; a compensating action is what makes an action %q, so declare that class or drop the field", where, classOrUnset(class), EffectCompensable)
	}
	return nil
}

// classOrUnset renders a class for an error message, naming an absent one explicitly
// rather than printing empty quotes.
func classOrUnset(class string) string {
	if class == "" {
		return "(unset, which resolves to irreversible)"
	}
	return class
}

// validateBlastRadiusSpec checks a blast-radius declaration: exactly one of a fixed value
// or an argument reference. Both is ambiguous (which wins?) and neither declares nothing
// while looking like a declaration — the shape most likely to leave an operator believing
// an action is quantified when it is not. where names the block for the error.
func validateBlastRadiusSpec(where string, s *BlastRadiusSpec) error {
	if s == nil {
		return nil
	}
	hasValue, hasArg := s.Value != nil, strings.TrimSpace(s.Argument) != ""
	switch {
	case hasValue && hasArg:
		return fmt.Errorf("%s declares both 'value' and 'argument'; a blast radius is either a fixed magnitude or the value of one argument, not both", where)
	case !hasValue && !hasArg:
		return fmt.Errorf("%s declares neither 'value' nor 'argument', so it quantifies nothing; drop the block (which resolves to unquantified, exceeding any bound) or name one", where)
	}
	if hasValue {
		v, ok := ParseBlastRadiusNumber(*s.Value)
		if !ok {
			return fmt.Errorf("%s 'value' is not a number (got %q)", where, s.Value.String())
		}
		if v.Sign() < 0 {
			return fmt.Errorf("%s 'value' must not be negative (got %q)", where, s.Value.String())
		}
	}
	return nil
}

// validateEffectByArgument checks an argument-parameterized contract: a named argument,
// a non-empty table, and a valid contract in every row. It takes the whole contract
// because a row's rules are evaluated against its EFFECTIVE class — its own when it states
// one, the base contract's when it does not.
func validateEffectByArgument(e *EffectContract) error {
	t := e.ByArgument
	if t == nil {
		return nil
	}
	if strings.TrimSpace(t.Argument) == "" {
		return fmt.Errorf("effect.byArgument requires 'argument' naming the call argument the decision table keys on")
	}
	if len(t.Cases) == 0 && t.Default == nil {
		return fmt.Errorf("effect.byArgument declares neither 'cases' nor 'default', so it decides nothing")
	}
	// Two keys that match the SAME argument value are an ambiguous table. Matching is
	// case-insensitive after trimming (an operator writes "DROP" or "drop"), so
	// {"DROP": irreversible, "drop": reversible} would leave which row wins to lookup's
	// collision tiebreak — the smallest key by byte order, which can be the WEAKER row —
	// rather than to the author. Reject it here, the way every other case-variant
	// ambiguity in this codebase is rejected rather than resolved.
	//
	// The fold has to be the one the MATCHER applies or the certificate this check issues
	// is worthless. lookup matches with strings.EqualFold; strings.ToLower under-folds
	// exactly where EqualFold does not (U+017F LATIN SMALL LETTER LONG S is already lower
	// case, so ToLower leaves "ſelect" distinct from "select" while EqualFold matches both
	// against "SELECT"), so that pair certified clean here and then collided at runtime —
	// exactly the tiebreak a load-time refusal is supposed to make unreachable.
	folded := make(map[string]string, len(t.Cases))
	for value := range t.Cases {
		key := canonicalCaseFold(strings.TrimSpace(value))
		if prev, dup := folded[key]; dup {
			return fmt.Errorf("effect.byArgument declares cases %q and %q, which match the same argument value (matching is case-insensitive after trimming); a single value cannot resolve to two effects, so remove or reconcile one", prev, value)
		}
		folded[key] = value
	}
	for value, c := range t.Cases {
		if err := validateEffectCase(fmt.Sprintf("effect.byArgument.cases[%q]", value), c, e.Class, e.CompensatingAction); err != nil {
			return err
		}
	}
	if t.Default != nil {
		return validateEffectCase("effect.byArgument.default", *t.Default, e.Class, e.CompensatingAction)
	}
	return nil
}

// validateEffectCase checks one row of an argument-parameterized contract, applying the
// same class and compensation rules the base contract obeys — a row is a contract.
//
// baseClass and baseAction are the contract's own class and compensating action, either of
// which a row that states none INHERITS (exactly as ResolveEffect overlays them: a row's
// field wins only when non-empty). Validating the row against the EFFECTIVE pair rather
// than its own declarations alone is what makes the check agree with what gets enforced —
// in both directions. A row declaring `compensatingAction` under an inherited class of,
// say, irreversible used to load clean and then have the field scrubbed at resolution, so
// the author's declared reversal silently did not exist; and a row RESTATING the
// compensable class it already inherits was rejected for naming no action, though it
// inherits the base's and resolves identically to the silent spelling that loads fine.
func validateEffectCase(where string, c EffectCase, baseClass, baseAction string) error {
	if c.Class != "" && !IsEffectClass(c.Class) {
		return fmt.Errorf("%s 'class' is %q — valid effect classes are %s", where, c.Class, strings.Join(EffectClassVocabulary(), ", "))
	}
	effectiveClass := c.Class
	if effectiveClass == "" {
		effectiveClass = baseClass
	}
	effectiveAction := c.CompensatingAction
	if effectiveAction == "" {
		effectiveAction = baseAction
	}
	// A row that states NEITHER a class nor a compensating action overlays nothing on
	// those axes, so there is no pairing to check (and an inherited compensable base
	// already had its own action validated).
	if effectiveClass != "" || c.CompensatingAction != "" {
		if err := validateCaseCompensation(where, c, effectiveClass, effectiveAction); err != nil {
			return err
		}
	}
	return validateBlastRadiusSpec(where+".blastRadius", c.BlastRadius)
}

// validateCaseCompensation applies the compensable pairing to one row, against the
// EFFECTIVE class and action — what ResolveEffect will actually produce for it — rather
// than the row's own fields. That is the one asymmetry a row has against a whole contract:
// a row inherits both halves of the pairing independently, so it can be complete without
// stating either.
func validateCaseCompensation(where string, c EffectCase, effectiveClass, effectiveAction string) error {
	if c.Class == "" && c.CompensatingAction == "" {
		return nil // pure inheritance: the base contract's own validation covers it
	}
	if effectiveClass == EffectCompensable && effectiveAction == "" {
		// Nothing supplies the reversal: the row raised itself to compensable and neither
		// it nor the base names an action. (A row that merely RESTATES a compensable base's
		// class inherits that base's action and is complete, so it does not land here.)
		return fmt.Errorf("%s declares class %q but no 'compensatingAction', and the contract it overlays names none to inherit; compensable means a declared action reverses this one, so without it the class is irreversible wearing a softer label", where, EffectCompensable)
	}
	if effectiveClass != EffectCompensable && c.CompensatingAction != "" {
		return fmt.Errorf("%s declares 'compensatingAction' with class %q; a compensating action is what makes an action %q, so declare that class on the case or drop the field", where, classOrUnset(effectiveClass), EffectCompensable)
	}
	return nil
}

// validateEffectRefPin verifies the registry pin: its shape
// ("<contract-id>@sha256:<64 lowercase hex>") AND that the digest matches the inline
// contract it is attached to.
//
// eunox never fetches the registry — the decision path stays local, so a registry outage
// cannot change a verdict — but the pin is still fully checkable here, because the digest
// is over the contract's own content. Verifying it is what makes `ref` an integrity pin
// rather than a comment: without the check, a manifest could carry the reviewed
// contract's id while enforcing something else entirely, which is the one thing a
// hash-pinned registry exists to prevent. Editing a pinned contract therefore fails at
// load until the author re-pins — the review step, enforced rather than requested.
func validateEffectRefPin(e *EffectContract) error {
	if e.Ref == "" {
		return nil
	}
	_, digest, ok := SplitEffectRef(e.Ref)
	if !ok {
		return fmt.Errorf("effect 'ref' %q must be \"<contract-id>@sha256:<hex>\" — the registry contract this block was authored from", e.Ref)
	}
	if err := ValidateSHA256Pin("digest", digest); err != nil {
		return fmt.Errorf("effect 'ref' %q: %w", e.Ref, err)
	}
	actual, err := EffectContractDigest(e)
	if err != nil {
		return fmt.Errorf("effect 'ref' %q: %w", e.Ref, err)
	}
	if actual != digest {
		return fmt.Errorf("effect 'ref' %q pins digest %s but this contract's content digests to %s — the block was edited after it was pinned; re-review it and update the pin (eunox never fetches the registry, so the pin is only worth anything if it matches what is enforced)", e.Ref, digest, actual)
	}
	return nil
}

// ValidateSHA256Pin checks the "sha256:<64 lowercase hex>" shape shared by the effect
// ref's digest and the manifest's descriptionHash. field names the pin for the error, so
// one rule serves both spellings instead of each layer carrying its own copy of the four
// checks — which is how a tightening (a second algorithm prefix, a relaxed case rule) ends
// up applied to one pin and not the other while both claim to be "the sha256 pin format".
// It lives here because this package owns the digest the pin is over.
func ValidateSHA256Pin(field, s string) error {
	const prefix = "sha256:"
	if !strings.HasPrefix(s, prefix) {
		return fmt.Errorf("%s %q must start with %q", field, s, prefix)
	}
	hexPart := s[len(prefix):]
	if len(hexPart) != 64 {
		return fmt.Errorf("%s %q: hex part must be exactly 64 characters (got %d)", field, s, len(hexPart))
	}
	if _, err := hex.DecodeString(hexPart); err != nil {
		return fmt.Errorf("%s %q: hex part is not valid hex: %w", field, s, err)
	}
	if hexPart != strings.ToLower(hexPart) {
		return fmt.Errorf("%s %q: hex part must be lowercase", field, s)
	}
	return nil
}
