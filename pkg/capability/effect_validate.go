// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Semantic validation for the effect layer. This package owns the reversibility
// vocabulary and the contract digest, so it owns what makes a contract WELL-FORMED too.
//
// The rules lived in internal/config, reachable only from the manifest loader. That left
// the registry corpus — the "reviewable, pinnable" artifact the whole effect layer is
// anchored on — able to validate and digest an entry that is semantically nonsense: a
// class typo ("reversable"), a compensable contract with no compensating action, a blast
// radius declaring both a fixed value and an argument. The entry then passed its own
// checks and failed later, at manifest load, as a confusing error about a block the author
// had copied verbatim from a corpus that told them it was fine.
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
	if err := ValidateBlastRadiusSpec("effect.blastRadius", e.BlastRadius); err != nil {
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
	if c.RequireCompensation && c.MaxEffectClass == "" {
		return fmt.Errorf("effectCeiling 'requireCompensation' needs 'maxEffectClass': it demands a compensating action only for an action ABOVE the class bound, so without one it never fires")
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

// ValidateBlastRadiusSpec checks a blast-radius declaration: exactly one of a fixed value
// or an argument reference. Both is ambiguous (which wins?) and neither declares nothing
// while looking like a declaration — the shape most likely to leave an operator believing
// an action is quantified when it is not. where names the block for the error.
func ValidateBlastRadiusSpec(where string, s *BlastRadiusSpec) error {
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
	// {"DROP": irreversible, "drop": reversible} would leave which row wins to map
	// iteration order — a nondeterministic effect class, which is disqualifying for a
	// layer whose whole claim is determinism. Reject it here, the way every other
	// case-variant ambiguity in this codebase is rejected rather than resolved.
	folded := make(map[string]string, len(t.Cases))
	for value := range t.Cases {
		key := strings.ToLower(strings.TrimSpace(value))
		if prev, dup := folded[key]; dup {
			return fmt.Errorf("effect.byArgument declares cases %q and %q, which match the same argument value (matching is case-insensitive after trimming); a single value cannot resolve to two effects, so remove or reconcile one", prev, value)
		}
		folded[key] = value
	}
	for value, c := range t.Cases {
		if err := validateEffectCase(fmt.Sprintf("effect.byArgument.cases[%q]", value), c, e.Class); err != nil {
			return err
		}
	}
	if t.Default != nil {
		return validateEffectCase("effect.byArgument.default", *t.Default, e.Class)
	}
	return nil
}

// validateEffectCase checks one row of an argument-parameterized contract, applying the
// same class and compensation rules the base contract obeys — a row is a contract.
//
// baseClass is the contract's own class, which a row that states none INHERITS. The
// pairing is checked against that effective class rather than skipped when the row is
// silent: a row declaring `compensatingAction` under an inherited class of, say,
// irreversible used to load clean and then have the field scrubbed at resolution, so the
// author's declared reversal silently did not exist. Validating the effective class turns
// that into the load-time error every other compensable mismatch already gets.
func validateEffectCase(where string, c EffectCase, baseClass string) error {
	if c.Class != "" && !IsEffectClass(c.Class) {
		return fmt.Errorf("%s 'class' is %q — valid effect classes are %s", where, c.Class, strings.Join(EffectClassVocabulary(), ", "))
	}
	effectiveClass := c.Class
	if effectiveClass == "" {
		effectiveClass = baseClass
	}
	// A row that states NEITHER a class nor a compensating action overlays nothing on
	// those axes, so there is no pairing to check (and an inherited compensable base
	// already had its own action validated).
	if effectiveClass != "" || c.CompensatingAction != "" {
		if err := validateCaseCompensation(where, c, effectiveClass); err != nil {
			return err
		}
	}
	return ValidateBlastRadiusSpec(where+".blastRadius", c.BlastRadius)
}

// validateCaseCompensation applies the compensable pairing to one row, with the one
// asymmetry a row has against a whole contract: a row that inherits a compensable class
// and states no action of its own inherits the base contract's action too, so it is NOT
// missing one. Only the row's own declarations can be wrong.
func validateCaseCompensation(where string, c EffectCase, effectiveClass string) error {
	if c.Class == "" && c.CompensatingAction == "" {
		return nil // pure inheritance: the base contract's own validation covers it
	}
	if effectiveClass == EffectCompensable && c.Class != "" && c.CompensatingAction == "" {
		// The row RAISES itself to compensable without naming the action that reverses it.
		return fmt.Errorf("%s declares class %q but no 'compensatingAction'; compensable means a declared action reverses this one, so without it the class is irreversible wearing a softer label", where, EffectCompensable)
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
