// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

type directiveEnvelope struct {
	Type string `json:"type"`
}

// DirectiveWrapper wraps a Directive so it can be marshaled and unmarshaled
// polymorphically, parallel to ConditionWrapper for conditions.
type DirectiveWrapper struct {
	Directive
}

// MarshalJSON serializes the wrapped directive.
func (w DirectiveWrapper) MarshalJSON() ([]byte, error) {
	if w.Directive == nil {
		return []byte("null"), nil
	}
	return marshalDirective(w.Directive)
}

// UnmarshalJSON deserializes a wrapped directive from its discriminator.
// Returns an error for any unrecognized directive type (fail-closed).
func (w *DirectiveWrapper) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		w.Directive = nil
		return nil
	}
	directive, err := unmarshalDirective(data)
	if err != nil {
		return err
	}
	w.Directive = directive
	return nil
}

func marshalDirective(directive Directive) ([]byte, error) {
	// A typed-nil pointer slips past DirectiveWrapper.MarshalJSON's nil-interface
	// guard; DirectiveType() has a value receiver and would dereference nil and
	// panic. Guard it once here, mirroring conditions.go's marshalCondition.
	if IsTypedNil(directive) {
		return []byte("null"), nil
	}
	// Normalize a VALUE to its address and re-dispatch, so each directive type's
	// marshaling is written once (in its pointer arm) instead of twice; see
	// marshalCondition for why the pointer arm is the one that needs the `type
	// alias` trick.
	if rv := reflect.ValueOf(directive); rv.Kind() != reflect.Pointer {
		pv := reflect.New(rv.Type())
		pv.Elem().Set(rv)
		ptr, ok := pv.Interface().(Directive)
		if !ok {
			// Unreachable for a value receiver (a *T method set contains T's methods),
			// but fail closed rather than panic on a future receiver change.
			return nil, fmt.Errorf("unsupported directive payload: %T", directive)
		}
		return marshalDirective(ptr)
	}
	switch typed := directive.(type) {
	case *RedactFieldsDirective:
		type alias RedactFieldsDirective
		return json.Marshal(struct {
			directiveEnvelope
			*alias
		}{directiveEnvelope{Type: typed.DirectiveType()}, (*alias)(typed)})
	case *LabelOutputDirective:
		type alias LabelOutputDirective
		return json.Marshal(struct {
			directiveEnvelope
			*alias
		}{directiveEnvelope{Type: typed.DirectiveType()}, (*alias)(typed)})
	case *DeclassifyDirective:
		type alias DeclassifyDirective
		return json.Marshal(struct {
			directiveEnvelope
			*alias
		}{directiveEnvelope{Type: typed.DirectiveType()}, (*alias)(typed)})
	default:
		return nil, fmt.Errorf("unsupported directive payload: %T", directive)
	}
}

func unmarshalDirective(data []byte) (Directive, error) {
	var envelope directiveEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, err
	}
	if envelope.Type == "" {
		return nil, fmt.Errorf("directive is missing required 'type' field")
	}
	target := newDirective(envelope.Type)
	if target == nil {
		// The valid set is enumerated FROM the registry, not spelled out here: a literal
		// list is a third mirror to keep in step, and one whose drift is invisible (an
		// author reading a stale "valid types are" line has no way to tell it is stale).
		return nil, fmt.Errorf("unknown directive type %q — valid types are: %s", envelope.Type, strings.Join(knownDirectiveTypes, ", "))
	}
	// Reject unknown fields, by the same rule and for the same reason as
	// unmarshalCondition (see jsonFieldNames): a lenient decode silently drops a
	// misspelled key. For a directive that is worse than for a condition —
	// {"type":"redactFields","pathss":[...]} decodes to an EMPTY path list, and an empty
	// list means the forward path attaches the redactFields obligation (so the tape
	// records a redaction as applied) while masking nothing. Matching is case-insensitive
	// because that is how encoding/json binds.
	if err := rejectUnknownJSONFields(data, target, fmt.Sprintf("directive %q", envelope.Type), "type"); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, target); err != nil {
		return nil, fmt.Errorf("directive %q: %w", envelope.Type, err)
	}
	return target, nil
}

// directivePrototypes is THE registry of directive discriminators this build models, the
// directive twin of conditionPrototypes: the decoder, the closed vocabulary
// (knownDirectiveTypes), the manifest loader's per-type key sets, and the schemaVersion gate
// all derive from it, so adding a type means adding it HERE rather than in hand-maintained
// tables that drift apart (a prior switch-plus-two-literals split let a fourth directive
// ship with no schema branch).
//
// State and Uses follow the same rules as the condition registry (tokenstate.go,
// subsystem.go): redactFields masks one response and remembers nothing, while labelOutput
// and declassify write/clear the flow-label set — non-atomic read-then-writes that need the
// decision turn and must not have the flow path skipped out from under them.
var directivePrototypes = map[string]tokenSpec[Directive]{
	DirectiveTypeRedactFields: {New: func() Directive { return &RedactFieldsDirective{} }, Since: SchemaVersion01, State: StateNone, Uses: usesNothing},
	DirectiveTypeLabelOutput:  {New: func() Directive { return &LabelOutputDirective{} }, Since: SchemaVersion02, State: StateNonAtomic, Uses: []EngineSubsystem{SubsystemFlowLabels}},
	DirectiveTypeDeclassify:   {New: func() Directive { return &DeclassifyDirective{} }, Since: SchemaVersion02, State: StateNonAtomic, Uses: []EngineSubsystem{SubsystemFlowLabels}},
}

// knownDirectiveTypes is every discriminator in the registry, sorted so the
// unknown-type error enumerates them deterministically (a map's iteration order would
// not).
var knownDirectiveTypes = sortedRegistryKeys(directivePrototypes)

// NewDirectivePrototype returns a fresh zero-valued directive of the given type, or
// (nil, false) for a type this build does not model. It is the directive analogue of
// NewConditionPrototype, exported for the same reason: the manifest loader's
// permitted-key check and the published schema's drift guard must both read the ONE
// registry rather than mirroring it. A hand-written mirror there fails OPEN — an
// unlisted type makes the caller skip the unknown-key check entirely, so a misspelled
// field loads as an empty value instead of erroring.
//
// The prototype is freshly constructed per call, so a caller cannot mutate the
// registry's idea of a type.
func NewDirectivePrototype(directiveType string) (Directive, bool) {
	spec, ok := directivePrototypes[directiveType]
	if !ok {
		return nil, false
	}
	return spec.New(), true
}

// KnownDirectiveTypes returns a fresh copy of the registry's directive discriminators in
// lexical order — the closed directive vocabulary, read from the ONE registry rather
// than a mirrored list. A fresh slice each call, so a caller cannot mutate the package's
// accepted set.
func KnownDirectiveTypes() []string {
	return append([]string(nil), knownDirectiveTypes...)
}

// newDirective returns a zero value of the directive type named by directiveType, or nil
// for a discriminator this build does not model. It is the in-package spelling of
// NewDirectivePrototype — same registry, nil rather than a second (Directive, bool)
// return, because the decoder's next step handles nil anyway.
func newDirective(directiveType string) Directive {
	proto, _ := NewDirectivePrototype(directiveType)
	return proto
}
