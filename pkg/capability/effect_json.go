// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
)

// Strict decoders for the effect subtree — the one nested policy object at the exported
// Constraint seam that still decoded leniently, while conditions, directives and
// ArgumentSchema all recursed the same discipline.
//
// Both drops a lenient decode allows here WIDEN. "byArguments" for "byArgument" deletes
// the escalation table, so a base class: reversible applies to the very argument values
// the table existed to escalate; a misspelled "ref" skips the effect.ref integrity pin, so
// a block edited after it was pinned loads clean. ValidateEffectContract cannot catch
// either — it reads the decoded struct, not the key that never bound.
//
// Unknown KEYS and AMBIGUOUS ones are two different holes and both are closed here.
// DisallowUnknownFields refuses a key encoding/json would not bind; RefuseAmbiguousJSONKeys
// refuses two spellings that FOLD together, which the unknown-key check passes by
// construction (both fold to a known name) and encoding/json then resolves last-wins. That
// second hole reproduces the same two widenings from a document a reviewer reads as
// correct: a "ByArgument": null sibling deletes the table, a "REF": "" sibling drops the
// pin, and the widened block re-digests to a value that validates against its own pin.
//
// The binary's manifest loader runs its own recursive key check over these same structs
// (internal/config's checkEffectKeys) and refuses an ambiguous key by matching exactly, so
// this changes no manifest verdict; it closes the exported seam a library consumer decodes
// through without either.

// decodeStrictEffectBlock decodes data into fields, refusing an ambiguous member name and
// any key encoding/json would not bind, at every depth.
//
// fields must be a pointer to a type carrying the block's fields but NOT its method set, so
// the decode does not recurse back into the caller; block is the real type it stands in for,
// which is the one encoding/json would have named had there been no stand-in. Only the OUTERMOST type of each block
// needs one: dropping the method set is what lets DisallowUnknownFields — a decoder-level
// flag that stops at any type implementing json.Unmarshaler — recurse through the nested
// types itself. That is why the subtree has two decoders rather than one per struct, and it
// is the whole guarantee: a nested policy object added later is covered with no author
// action, where a per-struct decoder would have shipped it lenient. This is the primitive
// ArgumentSchema.UnmarshalJSON uses for its own recursive subtree, and the reason
// unmarshalCondition rejects it does not apply here — that check must let a polymorphic
// envelope's "type" discriminator survive, and no block in this subtree has one.
//
// UseNumber costs nothing beside the flag and matches every other decoder in the package,
// but nothing in this subtree can observe it today: the only numeric fields are
// *json.Number, which encoding/json fills from the literal either way.
func decodeStrictEffectBlock(data []byte, fields any, block reflect.Type, context string) error {
	if err := RefuseAmbiguousJSONKeys(data); err != nil {
		return fmt.Errorf("%s: %w", context, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	dec.DisallowUnknownFields()
	if err := dec.Decode(fields); err != nil {
		// Reformat encoding/json's own `json: unknown field "x"` into this package's
		// established "<context>: unknown field %q" wording, as ArgumentSchema does.
		if field, ok := strings.CutPrefix(err.Error(), "json: unknown field "); ok {
			return fmt.Errorf("%s: unknown field %s", context, field)
		}
		// Anything else is returned UNWRAPPED so the calling decoder can still prepend its
		// own field path: encoding/json's addErrorContext type-asserts on
		// *json.UnmarshalTypeError, so wrapping one drops the path an operator needs.
		// The stand-in's name is substituted back for the same reason the type is named at
		// all — it is the one part of the message that would otherwise point at an
		// identifier the manifest grammar does not have. Only the outermost value can carry
		// it; a nested type is decoded as itself and already reads correctly.
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &typeErr) && typeErr.Type == reflect.TypeOf(fields).Elem() {
			typeErr.Type = block
		}
		return err
	}
	return nil
}

// effectContractFields and effectCeilingFields carry each block's fields without its method
// set. Named rather than the usual local `alias` because encoding/json prints this type's
// name in a field-type-mismatch error, and "alias" names nothing an operator can look up.
type (
	effectContractFields EffectContract
	effectCeilingFields  EffectCeiling
)

// UnmarshalJSON deserializes an EffectContract and everything under it, refusing an unknown
// or ambiguous key at any depth.
func (e *EffectContract) UnmarshalJSON(data []byte) error {
	// Reset first: encoding/json MERGES into a non-zero destination, so re-decoding a
	// reused value would carry fields the new document does not declare — including a
	// stale ref, an integrity pin over content that is no longer there. Constraint's own
	// decoder states the rule for conditions and directives; a contract needs it more.
	*e = EffectContract{}
	return decodeStrictEffectBlock(data, (*effectContractFields)(e), reflect.TypeOf(EffectContract{}), "effect")
}

// UnmarshalJSON deserializes an EffectCeiling, refusing an unknown or ambiguous key.
func (c *EffectCeiling) UnmarshalJSON(data []byte) error {
	*c = EffectCeiling{}
	return decodeStrictEffectBlock(data, (*effectCeilingFields)(c), reflect.TypeOf(EffectCeiling{}), "effectCeiling")
}
