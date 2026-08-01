// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/eunolabs/eunox/pkg/capability"
)

// Load-time validation for the effect layer: the effectClass and blastRadius
// conditions, a constraint's effect contract, and the top-level effectCeiling.
//
// Everything here fails at LOAD rather than at request time, on the same principle the
// rest of the grammar follows: a closed typed vocabulary whose misspelled key is a load
// error is falsifiable, where an evaluate-to-know policy is not. An effect contract that
// only reveals its problem on the one call that mattered is exactly the failure the typed
// grammar exists to prevent.

// validateEffectClass checks an effectClass condition's Allow set against the closed
// vocabulary. An EMPTY allow is rejected: unlike flowLabel — where an empty allow set
// means the meaningful "only a clean, unlabeled context reaches this sink" — an empty
// effect-class allow admits nothing at all, which is a dead constraint an author never
// intends (they meant to write a class and left it blank).
func validateEffectClass(i, j int, allow []string) error {
	if len(allow) == 0 {
		return fmt.Errorf("capability at index %d, condition %d: effectClass requires a non-empty 'allow' list naming the effect classes this target may perform (valid classes are %s); an empty list admits nothing", i, j, strings.Join(capability.EffectClassVocabulary(), ", "))
	}
	for _, c := range allow {
		if !capability.IsEffectClass(c) {
			return fmt.Errorf("capability at index %d, condition %d: effectClass 'allow' contains unknown class %q — valid effect classes are %s", i, j, c, strings.Join(capability.EffectClassVocabulary(), ", "))
		}
	}
	return nil
}

// validateBlastRadius checks a blastRadius condition: a present, well-formed,
// non-negative per-call bound.
func validateBlastRadius(i, j int, c *capability.BlastRadiusCondition) error {
	if c.Max == nil {
		return fmt.Errorf("capability at index %d, condition %d: blastRadius requires 'max', the largest magnitude one call may have; a condition with no bound bounds nothing", i, j)
	}
	return validateBlastRadiusNumber(i, j, "max", c.Max)
}

// validateBlastRadiusNumber checks one bound: a parseable, non-negative number. A
// negative bound is rejected because a magnitude is non-negative by construction, so a
// negative bound can never be satisfied — it denies every call, silently, in the shape of
// a limit that looks generous.
func validateBlastRadiusNumber(i, j int, field string, n *json.Number) error {
	if n == nil {
		return nil
	}
	v, ok := capability.ParseBlastRadiusNumber(*n)
	if !ok {
		return fmt.Errorf("capability at index %d, condition %d: blastRadius %q is not a number (got %q)", i, j, field, n.String())
	}
	if v.Sign() < 0 {
		return fmt.Errorf("capability at index %d, condition %d: blastRadius %q must not be negative (got %q); a blast radius is a magnitude, so a negative bound denies every call", i, j, field, n.String())
	}
	return nil
}

// validateEffectContract checks a constraint's effect block. The contract is the input
// every effect check reads, so a malformed one would make all of them wrong at once.
func validateEffectContract(i int, e *capability.EffectContract) error {
	if e == nil {
		return nil
	}
	if e.Class != "" && !capability.IsEffectClass(e.Class) {
		return fmt.Errorf("capability at index %d: effect 'class' is %q — valid effect classes are %s", i, e.Class, strings.Join(capability.EffectClassVocabulary(), ", "))
	}
	if err := validateCompensation(i, "effect", e.Class, e.CompensatingAction); err != nil {
		return err
	}
	if err := validateBlastRadiusSpec(i, "effect.blastRadius", e.BlastRadius); err != nil {
		return err
	}
	if err := validateEffectRef(i, e.Ref); err != nil {
		return err
	}
	return validateEffectByArgument(i, e.ByArgument)
}

// validateCompensation enforces the one invariant that keeps the compensable class
// meaningful: compensable means "there is a declared action that reverses this", and
// anything else means there is not.
//
// Without it, "compensable" degrades into a softer word for irreversible — an author
// labels a wire transfer compensable, the consequence gate reads a compensating action
// as present, and the exact case the gate exists to escalate passes through it.
func validateCompensation(i int, where, class, compensating string) error {
	switch {
	case class == capability.EffectCompensable && compensating == "":
		return fmt.Errorf("capability at index %d: %s declares class %q but no 'compensatingAction'; compensable means a declared action reverses this one, so without it the class is irreversible wearing a softer label", i, where, capability.EffectCompensable)
	case class != capability.EffectCompensable && compensating != "":
		return fmt.Errorf("capability at index %d: %s declares 'compensatingAction' with class %q; a compensating action is what makes an action %q, so declare that class or drop the field", i, where, classOrUnset(class), capability.EffectCompensable)
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

// validateBlastRadiusSpec checks a blast-radius declaration: exactly one of a fixed
// value or an argument reference. Both is ambiguous (which wins?) and neither declares
// nothing while looking like a declaration — the shape most likely to leave an operator
// believing an action is quantified when it is not.
func validateBlastRadiusSpec(i int, where string, s *capability.BlastRadiusSpec) error {
	if s == nil {
		return nil
	}
	hasValue, hasArg := s.Value != nil, strings.TrimSpace(s.Argument) != ""
	switch {
	case hasValue && hasArg:
		return fmt.Errorf("capability at index %d: %s declares both 'value' and 'argument'; a blast radius is either a fixed magnitude or the value of one argument, not both", i, where)
	case !hasValue && !hasArg:
		return fmt.Errorf("capability at index %d: %s declares neither 'value' nor 'argument', so it quantifies nothing; drop the block (which resolves to unquantified, exceeding any bound) or name one", i, where)
	}
	if hasValue {
		v, ok := capability.ParseBlastRadiusNumber(*s.Value)
		if !ok {
			return fmt.Errorf("capability at index %d: %s 'value' is not a number (got %q)", i, where, s.Value.String())
		}
		if v.Sign() < 0 {
			return fmt.Errorf("capability at index %d: %s 'value' must not be negative (got %q)", i, where, s.Value.String())
		}
	}
	return nil
}

// validateEffectByArgument checks an argument-parameterized contract: a named argument,
// a non-empty table, and a valid contract in every row.
func validateEffectByArgument(i int, t *capability.EffectByArgument) error {
	if t == nil {
		return nil
	}
	if strings.TrimSpace(t.Argument) == "" {
		return fmt.Errorf("capability at index %d: effect.byArgument requires 'argument' naming the call argument the decision table keys on", i)
	}
	if len(t.Cases) == 0 && t.Default == nil {
		return fmt.Errorf("capability at index %d: effect.byArgument declares neither 'cases' nor 'default', so it decides nothing", i)
	}
	for value, c := range t.Cases {
		if err := validateEffectCase(i, fmt.Sprintf("effect.byArgument.cases[%q]", value), c); err != nil {
			return err
		}
	}
	if t.Default != nil {
		return validateEffectCase(i, "effect.byArgument.default", *t.Default)
	}
	return nil
}

// validateEffectCase checks one row of an argument-parameterized contract, applying the
// same class and compensation rules the base contract obeys — a row is a contract.
func validateEffectCase(i int, where string, c capability.EffectCase) error {
	if c.Class != "" && !capability.IsEffectClass(c.Class) {
		return fmt.Errorf("capability at index %d: %s 'class' is %q — valid effect classes are %s", i, where, c.Class, strings.Join(capability.EffectClassVocabulary(), ", "))
	}
	// A row that names a compensating action but no class inherits the base contract's
	// class, so the compensable pairing is only checkable when the row states one. A row
	// stating neither is fine (it overlays nothing on those axes).
	if c.Class != "" {
		if err := validateCompensation(i, where, c.Class, c.CompensatingAction); err != nil {
			return err
		}
	}
	return validateBlastRadiusSpec(i, where+".blastRadius", c.BlastRadius)
}

// validateEffectRef checks the registry provenance pin's shape:
// "<contract-id>@sha256:<64 lowercase hex>". eunox never fetches it — the decision path
// stays local — so this is the only check it gets, and a malformed pin must fail at load
// rather than sit in a manifest looking like provenance it is not.
func validateEffectRef(i int, ref string) error {
	if ref == "" {
		return nil
	}
	id, digest, ok := strings.Cut(ref, "@")
	if !ok || strings.TrimSpace(id) == "" {
		return fmt.Errorf("capability at index %d: effect 'ref' %q must be \"<contract-id>@sha256:<hex>\" — the registry contract this block was authored from", i, ref)
	}
	if err := validateDescriptionHashFormat(digest); err != nil {
		return fmt.Errorf("capability at index %d: effect 'ref' %q: %w", i, ref, err)
	}
	return nil
}

// validateEffectCeiling checks the top-level ceiling. A ceiling that bounds nothing is
// rejected rather than treated as satisfied by every action: a half-written ceiling that
// loads cleanly is a policy an operator believes is in force and is not.
func validateEffectCeiling(c *capability.EffectCeiling) error {
	if c == nil {
		return nil
	}
	if c.MaxEffectClass != "" && !capability.IsEffectClass(c.MaxEffectClass) {
		return fmt.Errorf("effectCeiling 'maxEffectClass' is %q — valid effect classes are %s", c.MaxEffectClass, strings.Join(capability.EffectClassVocabulary(), ", "))
	}
	if c.MaxBlastRadius != nil {
		v, ok := capability.ParseBlastRadiusNumber(*c.MaxBlastRadius)
		if !ok {
			return fmt.Errorf("effectCeiling 'maxBlastRadius' is not a number (got %q)", c.MaxBlastRadius.String())
		}
		if v.Sign() < 0 {
			return fmt.Errorf("effectCeiling 'maxBlastRadius' must not be negative (got %q)", c.MaxBlastRadius.String())
		}
	}
	switch c.OnExceed {
	case "", capability.OnExceedEscalate, capability.OnExceedDeny:
	default:
		return fmt.Errorf("effectCeiling 'onExceed' is %q — valid outcomes are %s (the default) and %s", c.OnExceed, capability.OnExceedEscalate, capability.OnExceedDeny)
	}
	if !c.IsSet() {
		return fmt.Errorf("effectCeiling bounds nothing: set 'maxEffectClass', 'maxBlastRadius', or 'requireCompensation' (a ceiling with only 'onExceed' never fires, which reads as \"checked and fine\")")
	}
	// RequireCompensation only ever applies to an action already over the class bound
	// (see EffectCeiling.Exceeds), so on its own it is inert — and inert-but-present is
	// exactly the shape that reads as a control when it is not.
	if c.RequireCompensation && c.MaxEffectClass == "" {
		return fmt.Errorf("effectCeiling 'requireCompensation' needs 'maxEffectClass': it demands a compensating action only for an action ABOVE the class bound, so without one it never fires")
	}
	return nil
}

// mergeEffectCeiling folds a file's ceiling into the merged manifest with a conflict
// check: first non-empty wins, two DIFFERENT ceilings are rejected. Silently dropping one
// would raise the consequence bound for every capability the other file contributed —
// the fail-open direction — so a disagreement is an error, exactly as it is for
// serverVersion and audience.
func mergeEffectCeiling(dst, src *capability.EffectCeiling, srcName string) (*capability.EffectCeiling, error) {
	switch {
	case src == nil:
		return dst, nil
	case dst == nil:
		return src, nil
	case reflect.DeepEqual(dst, src):
		return dst, nil
	default:
		return nil, fmt.Errorf("manifest %q declares an effectCeiling that conflicts with an earlier file's; merged manifests must agree on the consequence bound (dropping one would raise the bound for the other file's capabilities)", srcName)
	}
}

// effectCeilingKeys and effectContractKeys are the permitted key sets for the nested
// effect objects, for the recursive unknown-key walk. The reflective field sets keep them
// in lock-step with the structs: a field added to either type is admitted automatically,
// where a hand-written list would silently reject the new key.
func effectCeilingKeys() map[string]bool {
	return jsonFieldKeys(reflect.TypeOf(capability.EffectCeiling{}))
}

func effectContractKeys() map[string]bool {
	return jsonFieldKeys(reflect.TypeOf(capability.EffectContract{}))
}

// checkEffectKeys walks the nested objects inside a constraint's effect block and the
// top-level effectCeiling, rejecting an unknown key. checkManifestKeys covers the
// TOP-level key of each (both are reflected struct fields), but not their interiors: a
// typo'd "blastRadious" inside an effect block would otherwise decode to nothing and
// leave the action silently unquantified — which reads as "no bound declared" and, under
// a ceiling, as maximum friction, or worse under a bare blastRadius condition as an
// unbounded call.
func checkEffectKeys(root map[string]interface{}) error {
	if ceiling, ok := root["effectCeiling"].(map[string]interface{}); ok {
		if err := checkObjectKeys("effectCeiling", ceiling, effectCeilingKeys()); err != nil {
			return err
		}
	}
	caps, _ := root["capabilities"].([]interface{})
	for i, raw := range caps {
		capObj, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		effect, ok := capObj["effect"].(map[string]interface{})
		if !ok {
			continue
		}
		path := fmt.Sprintf("capabilities[%d].effect", i)
		if err := checkObjectKeys(path, effect, effectContractKeys()); err != nil {
			return err
		}
		if err := checkBlastRadiusKeys(path+".blastRadius", effect["blastRadius"]); err != nil {
			return err
		}
		if err := checkByArgumentKeys(path+".byArgument", effect["byArgument"]); err != nil {
			return err
		}
	}
	return nil
}

// checkBlastRadiusKeys rejects an unknown key inside a blast-radius declaration.
func checkBlastRadiusKeys(path string, raw interface{}) error {
	obj, ok := raw.(map[string]interface{})
	if !ok {
		return nil
	}
	return checkObjectKeys(path, obj, jsonFieldKeys(reflect.TypeOf(capability.BlastRadiusSpec{})))
}

// checkByArgumentKeys rejects an unknown key inside an argument-parameterized contract,
// including every case row (a row is a contract, and a typo in one is as silent as a typo
// in the base block).
func checkByArgumentKeys(path string, raw interface{}) error {
	obj, ok := raw.(map[string]interface{})
	if !ok {
		return nil
	}
	if err := checkObjectKeys(path, obj, jsonFieldKeys(reflect.TypeOf(capability.EffectByArgument{}))); err != nil {
		return err
	}
	caseKeys := jsonFieldKeys(reflect.TypeOf(capability.EffectCase{}))
	if cases, ok := obj["cases"].(map[string]interface{}); ok {
		for value, rawCase := range cases {
			row, ok := rawCase.(map[string]interface{})
			if !ok {
				continue
			}
			rowPath := fmt.Sprintf("%s.cases[%q]", path, value)
			if err := checkObjectKeys(rowPath, row, caseKeys); err != nil {
				return err
			}
			if err := checkBlastRadiusKeys(rowPath+".blastRadius", row["blastRadius"]); err != nil {
				return err
			}
		}
	}
	if def, ok := obj["default"].(map[string]interface{}); ok {
		if err := checkObjectKeys(path+".default", def, caseKeys); err != nil {
			return err
		}
		return checkBlastRadiusKeys(path+".default.blastRadius", def["blastRadius"])
	}
	return nil
}

// HasEffectCeiling reports whether the policy sets a consequence bound, so the wiring
// layer can skip the per-allow ceiling check for a policy that has none. Mirrors
// HasMaxCalls / HasFlowLabel.
func (m *LocalManifest) HasEffectCeiling() bool {
	return m != nil && m.EffectCeiling.IsSet()
}

// EffectAnnotatedCount reports how many capabilities carry an effect contract, for the
// `stats`/`doctor` operator reports: under a ceiling, an unannotated capability is one
// that will escalate, so the ratio is the operator's progress meter on the registry
// flywheel.
func (m *LocalManifest) EffectAnnotatedCount() int {
	if m == nil {
		return 0
	}
	n := 0
	for i := range m.Capabilities {
		if m.Capabilities[i].Effect != nil {
			n++
		}
	}
	return n
}
