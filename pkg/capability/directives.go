// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"encoding/json"
	"fmt"
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
	switch typed := directive.(type) {
	case RedactFieldsDirective:
		type alias RedactFieldsDirective
		return json.Marshal(struct {
			directiveEnvelope
			alias
		}{directiveEnvelope{Type: typed.DirectiveType()}, alias(typed)})
	case *RedactFieldsDirective:
		// A typed-nil pointer slips past MarshalJSON's nil-interface guard;
		// DirectiveType() has a value receiver and would dereference nil and panic.
		if typed == nil {
			return []byte("null"), nil
		}
		type alias RedactFieldsDirective
		return json.Marshal(struct {
			directiveEnvelope
			*alias
		}{directiveEnvelope{Type: typed.DirectiveType()}, (*alias)(typed)})
	case LabelOutputDirective:
		type alias LabelOutputDirective
		return json.Marshal(struct {
			directiveEnvelope
			alias
		}{directiveEnvelope{Type: typed.DirectiveType()}, alias(typed)})
	case *LabelOutputDirective:
		if typed == nil {
			return []byte("null"), nil
		}
		type alias LabelOutputDirective
		return json.Marshal(struct {
			directiveEnvelope
			*alias
		}{directiveEnvelope{Type: typed.DirectiveType()}, (*alias)(typed)})
	case DeclassifyDirective:
		type alias DeclassifyDirective
		return json.Marshal(struct {
			directiveEnvelope
			alias
		}{directiveEnvelope{Type: typed.DirectiveType()}, alias(typed)})
	case *DeclassifyDirective:
		if typed == nil {
			return []byte("null"), nil
		}
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
		return nil, fmt.Errorf("unknown directive type %q — valid types are: redactFields, labelOutput, declassify", envelope.Type)
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

// NewDirectivePrototype returns a fresh zero-valued directive of the given type, or
// (nil, false) for a type this build does not model. It is the directive analogue of
// NewConditionPrototype, exported for the same reason: the manifest loader's
// permitted-key check and the published schema's drift guard must both read the ONE
// registry rather than mirroring it. A hand-written mirror there fails OPEN — an
// unlisted type makes the caller skip the unknown-key check entirely, so a misspelled
// field loads as an empty value instead of erroring.
func NewDirectivePrototype(directiveType string) (Directive, bool) {
	d := newDirective(directiveType)
	return d, d != nil
}

// KnownDirectiveTypes returns the registry's directive discriminators in lexical order —
// the closed directive vocabulary, read from the registry rather than a mirrored list.
// A fresh slice each call.
func KnownDirectiveTypes() []string {
	return []string{DirectiveTypeDeclassify, DirectiveTypeLabelOutput, DirectiveTypeRedactFields}
}

func newDirective(directiveType string) Directive {
	switch directiveType {
	case DirectiveTypeRedactFields:
		return &RedactFieldsDirective{}
	case DirectiveTypeLabelOutput:
		return &LabelOutputDirective{}
	case DirectiveTypeDeclassify:
		return &DeclassifyDirective{}
	default:
		return nil
	}
}
