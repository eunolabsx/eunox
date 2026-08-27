// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Strict decoders for the effect subtree — the one nested policy object at the exported
// Constraint seam that still decoded leniently, while conditions, directives and
// ArgumentSchema all recursed the same discipline (see rejectUnknownJSONFields).
//
// Both drops a lenient decode allows here WIDEN. "byArguments" for "byArgument" deletes
// the escalation table, so a base class: reversible applies to the very argument values
// the table existed to escalate; a misspelled "ref" skips the effect.ref integrity pin, so
// a block edited after it was pinned loads clean. ValidateEffectContract cannot catch
// either — it reads the decoded struct, not the key that never bound.
//
// The binary's manifest loader runs its own recursive key check over these same structs
// (internal/config's checkEffectKeys, reflected off the same field sets), so this changes
// nothing for a manifest; it closes the exported seam a library consumer decodes through
// without that check.

// decodeStrictEffectObject rejects any key encoding/json would not bind on alias, then
// decodes data into it. alias must be a pointer to a type carrying the target's fields but
// NOT its method set, so the decode does not recurse back into the caller.
//
// UseNumber is re-set here because a custom UnmarshalJSON does not inherit the caller's
// decoder options: both readers of these blocks set it (Constraint.UnmarshalJSON and
// internal/registry's corpus loader) and it stops at this boundary, which would leave the
// subtree decoding numbers under a different rule than the document around it.
func decodeStrictEffectObject(data []byte, alias any, context string) error {
	if err := rejectUnknownJSONFields(data, alias, context); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(alias); err != nil {
		return fmt.Errorf("%s: %w", context, err)
	}
	return nil
}

// UnmarshalJSON deserializes an EffectContract, refusing an unknown key.
func (e *EffectContract) UnmarshalJSON(data []byte) error {
	type alias EffectContract
	return decodeStrictEffectObject(data, (*alias)(e), "effect")
}

// UnmarshalJSON deserializes a BlastRadiusSpec, refusing an unknown key.
func (s *BlastRadiusSpec) UnmarshalJSON(data []byte) error {
	type alias BlastRadiusSpec
	return decodeStrictEffectObject(data, (*alias)(s), "blastRadius")
}

// UnmarshalJSON deserializes an EffectByArgument, refusing an unknown key.
func (t *EffectByArgument) UnmarshalJSON(data []byte) error {
	type alias EffectByArgument
	return decodeStrictEffectObject(data, (*alias)(t), "byArgument")
}

// UnmarshalJSON deserializes an EffectCase, refusing an unknown key.
func (c *EffectCase) UnmarshalJSON(data []byte) error {
	type alias EffectCase
	return decodeStrictEffectObject(data, (*alias)(c), "case")
}

// UnmarshalJSON deserializes an EffectCeiling, refusing an unknown key.
func (c *EffectCeiling) UnmarshalJSON(data []byte) error {
	type alias EffectCeiling
	return decodeStrictEffectObject(data, (*alias)(c), "effectCeiling")
}
