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
		return nil, fmt.Errorf("unknown directive type %q — valid types are: redactFields, labelOutput", envelope.Type)
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

func newDirective(directiveType string) Directive {
	switch directiveType {
	case DirectiveTypeRedactFields:
		return &RedactFieldsDirective{}
	case DirectiveTypeLabelOutput:
		return &LabelOutputDirective{}
	default:
		return nil
	}
}
