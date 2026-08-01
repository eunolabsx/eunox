// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"strings"

	"github.com/eunolabs/eunox/pkg/callcounter"
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

// validateBlastRadius checks a blastRadius condition: well-formed, non-negative bounds,
// at least one of them present, and a cumulative bound whose two halves are both set.
func validateBlastRadius(i, j int, c *capability.BlastRadiusCondition) error {
	// The pair rule, checked FIRST so a half-written velocity bound is reported as the
	// pairing mistake it is rather than as a missing 'max'. Half the pair silently
	// disables the other half — a `maxTotal` with no window has no window to sum over, and
	// a `windowSeconds` with no total bounds nothing — and an authored bound that bounded
	// nothing is worse than its absence, because the operator would believe a limit was in
	// force.
	switch {
	case c.MaxTotal != nil && c.WindowSeconds == 0:
		return fmt.Errorf("capability at index %d, condition %d: blastRadius 'maxTotal' requires 'windowSeconds', the sliding window it is summed over; a total with no window bounds nothing", i, j)
	case c.MaxTotal == nil && c.WindowSeconds != 0:
		return fmt.Errorf("capability at index %d, condition %d: blastRadius 'windowSeconds' requires 'maxTotal', the summed magnitude it bounds; a window with no total bounds nothing", i, j)
	}
	if c.Max == nil && c.MaxTotal == nil {
		return fmt.Errorf("capability at index %d, condition %d: blastRadius requires 'max' (the largest magnitude one call may have) or 'maxTotal' with 'windowSeconds' (the largest summed magnitude within a window), or both; a condition with no bound bounds nothing", i, j)
	}
	if err := validateBlastRadiusNumber(i, j, "max", c.Max); err != nil {
		return err
	}
	if err := validateBlastRadiusNumber(i, j, "maxTotal", c.MaxTotal); err != nil {
		return err
	}
	if c.MaxTotal != nil {
		if err := validateBlastRadiusTotalRange(i, j, c.MaxTotal); err != nil {
			return err
		}
		if c.WindowSeconds < 1 {
			return fmt.Errorf("capability at index %d, condition %d: blastRadius 'windowSeconds' must be >= 1, got %d", i, j, c.WindowSeconds)
		}
		if int64(c.WindowSeconds) > callcounter.MaxWindowSeconds {
			return fmt.Errorf("capability at index %d, condition %d: blastRadius 'windowSeconds' %d exceeds the maximum %d seconds", i, j, c.WindowSeconds, callcounter.MaxWindowSeconds)
		}
	}
	return nil
}

// validateBlastRadiusTotalRange rejects a cumulative bound the counter backends cannot
// represent exactly. Above MaxWeightedTotal the Redis backend's float64 arithmetic would
// silently round the threshold to one the operator never authored — so the bound is
// refused at load rather than enforced approximately at a magnitude where the rounding
// alone could be thousands.
//
// It is separate from validateBlastRadiusNumber because the PER-CALL bound has no such
// limit: it is compared exactly, in arbitrary precision, and never summed.
func validateBlastRadiusTotalRange(i, j int, n *json.Number) error {
	v, ok := capability.ParseBlastRadiusNumber(*n)
	if !ok {
		// Already reported by validateBlastRadiusNumber; nothing to add.
		return nil
	}
	// Compare the arbitrary-precision value, NOT its float64 narrowing. Rounding first let
	// 2^53+1 pass — it narrows to exactly 2^53 — so a bound one unit above the
	// representable maximum loaded clean and was then enforced as a threshold the operator
	// never authored, which is the failure this check exists to prevent.
	if v.Cmp(new(big.Float).SetFloat64(callcounter.MaxWeightedTotal)) > 0 {
		return fmt.Errorf("capability at index %d, condition %d: blastRadius 'maxTotal' must be <= %v (the largest total both counter backends sum exactly), got %q", i, j, callcounter.MaxWeightedTotal, n.String())
	}
	if v.Sign() <= 0 {
		// Zero admits nothing with a positive magnitude and would deny every quantified
		// call in the window — a limit that looks generous and refuses everything, the same
		// trap validateBlastRadiusNumber rejects a negative bound for.
		return fmt.Errorf("capability at index %d, condition %d: blastRadius 'maxTotal' must be > 0, got %q; a zero total admits no quantified call at all", i, j, n.String())
	}
	return nil
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
//
// The rules themselves live in pkg/capability (capability.ValidateEffectContract), which
// owns the reversibility vocabulary and the contract digest. This layer only adds the
// manifest-positional framing, so the registry corpus loader can apply the SAME semantic
// rules to a corpus entry — before, they were unexported here and unreachable from there,
// which let an entry with a class typo or a compensable-with-no-action contract validate
// and digest cleanly, then fail confusingly at manifest load.
func validateEffectContract(i int, e *capability.EffectContract) error {
	if err := capability.ValidateEffectContract(e); err != nil {
		return fmt.Errorf("capability at index %d: %w", i, err)
	}
	return nil
}

// validateEffectCeiling checks the top-level ceiling. Delegates to pkg/capability for the
// same reason validateEffectContract does; the ceiling is manifest-level, so there is no
// capability index to prefix.
func validateEffectCeiling(c *capability.EffectCeiling) error {
	return capability.ValidateEffectCeiling(c)
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
// `validate`/`doctor` operator reports: under a ceiling, an unannotated capability is one
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

// EffectUnannotatedTargets names the capabilities carrying NO effect contract, in
// manifest order, deduplicated.
//
// The count alone is a progress meter; this is the worklist. Under an effectCeiling each
// of these resolves to the fail-closed default (irreversible, unquantified) and therefore
// escalates, so an operator asking "why is everything hitting the approval queue" needs the
// names, not a ratio. Order is the manifest's own so the list reads against the file the
// operator is about to edit; duplicates are dropped because two entries for one target
// (different principals, different conditions) are one annotation job.
func (m *LocalManifest) EffectUnannotatedTargets() []string {
	if m == nil {
		return nil
	}
	var out []string
	seen := make(map[string]struct{}, len(m.Capabilities))
	for i := range m.Capabilities {
		if m.Capabilities[i].Effect != nil {
			continue
		}
		t := m.Capabilities[i].Target
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	return out
}
