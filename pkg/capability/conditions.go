// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
)

type conditionEnvelope struct {
	Type string `json:"type"`
}

// ConditionWrapper wraps a condition so it can be marshaled and unmarshaled polymorphically.
type ConditionWrapper struct {
	Condition
}

// MarshalJSON serializes the wrapped condition.
func (w ConditionWrapper) MarshalJSON() ([]byte, error) {
	if w.Condition == nil {
		return []byte("null"), nil
	}

	return marshalCondition(w.Condition)
}

// UnmarshalJSON deserializes a wrapped condition from its discriminator.
func (w *ConditionWrapper) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		w.Condition = nil
		return nil
	}

	condition, err := unmarshalCondition(data)
	if err != nil {
		return err
	}

	w.Condition = condition
	return nil
}

// IsTypedNil reports whether v is a non-nil interface wrapping a nil pointer — the
// "typed nil" that slips past a plain v == nil check yet panics on any method call whose
// receiver it dereferences (a value-receiver ConditionType/DirectiveType on a decoded
// condition/directive). It is the single reflect-based typed-nil predicate, so the
// validation and marshaling guards that reject a typed nil before such a call share one
// definition. A plain-nil interface returns false (reflect.ValueOf(nil) has Kind Invalid),
// so callers pair it with an explicit v == nil check where a plain nil is also rejected.
func IsTypedNil(v any) bool {
	rv := reflect.ValueOf(v)
	return rv.Kind() == reflect.Pointer && rv.IsNil()
}

func marshalCondition(condition Condition) ([]byte, error) {
	// A typed-nil pointer slips past ConditionWrapper.MarshalJSON's nil-interface
	// guard; ConditionType() has a value receiver and would dereference nil and
	// panic. Guard it once here, mirroring directives.go's marshalDirective.
	if IsTypedNil(condition) {
		return []byte("null"), nil
	}
	// Normalize a VALUE to its address and re-dispatch, so each condition type's
	// marshaling is written once (in its pointer arm) instead of twice.
	//
	// Every condition's MarshalJSON has a VALUE receiver, so the method is in both T's
	// and *T's method set — which is exactly why the pointer arms need the `type alias`
	// trick: marshaling the concrete type directly would re-enter MarshalJSON and recurse
	// forever. Converting to *alias, a type with no methods, breaks that. Taking the
	// address here changes nothing about that requirement, so the value arms were
	// byte-for-byte copies of the pointer arms and the switch carried 24 cases to express
	// 12 behaviors. Recursion is exactly one level deep: the value below is always a
	// pointer, so it lands in a pointer arm.
	if rv := reflect.ValueOf(condition); rv.Kind() != reflect.Pointer {
		pv := reflect.New(rv.Type())
		pv.Elem().Set(rv)
		ptr, ok := pv.Interface().(Condition)
		if !ok {
			// Unreachable for a value receiver (a *T method set contains T's methods),
			// but fail closed rather than panic on a future receiver change.
			return nil, fmt.Errorf("unsupported condition payload: %T", condition)
		}
		return marshalCondition(ptr)
	}
	// The pointer arms stay an EXPLICIT, exhaustive registry rather than one reflective
	// marshal: it is what guarantees only condition types this build knows can be
	// serialized into a manifest (and therefore into its digest). An unrecognized
	// implementation of the exported Condition interface must fail closed here, not be
	// silently written out.
	switch typed := condition.(type) {
	case *TimeWindowCondition:
		type alias TimeWindowCondition
		return json.Marshal(struct {
			conditionEnvelope
			*alias
		}{conditionEnvelope{Type: typed.ConditionType()}, (*alias)(typed)})
	case *IPRangeCondition:
		type alias IPRangeCondition
		return json.Marshal(struct {
			conditionEnvelope
			*alias
		}{conditionEnvelope{Type: typed.ConditionType()}, (*alias)(typed)})
	case *AllowedOperationsCondition:
		type alias AllowedOperationsCondition
		return json.Marshal(struct {
			conditionEnvelope
			*alias
		}{conditionEnvelope{Type: typed.ConditionType()}, (*alias)(typed)})
	case *AllowedExtensionsCondition:
		type alias AllowedExtensionsCondition
		return json.Marshal(struct {
			conditionEnvelope
			*alias
		}{conditionEnvelope{Type: typed.ConditionType()}, (*alias)(typed)})
	case *AllowedTablesCondition:
		type alias AllowedTablesCondition
		return json.Marshal(struct {
			conditionEnvelope
			*alias
		}{conditionEnvelope{Type: typed.ConditionType()}, (*alias)(typed)})
	case *MaxCallsCondition:
		type alias MaxCallsCondition
		return json.Marshal(struct {
			conditionEnvelope
			*alias
		}{conditionEnvelope{Type: typed.ConditionType()}, (*alias)(typed)})
	case *RecipientDomainCondition:
		type alias RecipientDomainCondition
		return json.Marshal(struct {
			conditionEnvelope
			*alias
		}{conditionEnvelope{Type: typed.ConditionType()}, (*alias)(typed)})
	case *PolicyCondition:
		type alias PolicyCondition
		return json.Marshal(struct {
			conditionEnvelope
			*alias
		}{conditionEnvelope{Type: typed.ConditionType()}, (*alias)(typed)})
	case *CustomCondition:
		type alias CustomCondition
		return json.Marshal(struct {
			conditionEnvelope
			*alias
		}{conditionEnvelope{Type: typed.ConditionType()}, (*alias)(typed)})
	case *AllowedValuesCondition:
		type alias AllowedValuesCondition
		return json.Marshal(struct {
			conditionEnvelope
			*alias
		}{conditionEnvelope{Type: typed.ConditionType()}, (*alias)(typed)})
	case *SequenceBlockCondition:
		type alias SequenceBlockCondition
		return json.Marshal(struct {
			conditionEnvelope
			*alias
		}{conditionEnvelope{Type: typed.ConditionType()}, (*alias)(typed)})
	case *FlowLabelCondition:
		type alias FlowLabelCondition
		return json.Marshal(struct {
			conditionEnvelope
			*alias
		}{conditionEnvelope{Type: typed.ConditionType()}, (*alias)(typed)})
	default:
		return nil, fmt.Errorf("unsupported condition payload: %T", condition)
	}
}

func unmarshalCondition(data []byte) (Condition, error) {
	var envelope conditionEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, err
	}

	// Migration hint: redactFields belongs in directives, not conditions. Compare
	// against the directive discriminator (its sole home) — there is intentionally
	// no condition-type constant for it.
	if envelope.Type == DirectiveTypeRedactFields {
		return nil, fmt.Errorf(`"redactFields" must be placed in "directives", not "conditions" — place it in the constraint's "directives" array (e.g. directives: [{type: redactFields, fields: [...]}])`)
	}

	if envelope.Type == "" {
		return nil, fmt.Errorf("condition is missing required 'type' field")
	}

	target := newCondition(envelope.Type)
	if target == nil {
		if s := suggestConditionType(envelope.Type); s != "" {
			return nil, fmt.Errorf("unknown condition type: %q (did you mean %q?)", envelope.Type, s)
		}
		return nil, fmt.Errorf("unknown condition type: %q", envelope.Type)
	}

	// Decode with UseNumber so numeric policy literals stay json.Number rather than
	// being widened to float64 (which rounds integers above 2^53, e.g. authorizing
	// the neighbour of 9007199254740993). Request arguments are decoded the same
	// way, and numericEqual compares the preserved json.Number values exactly.
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(target); err != nil {
		return nil, err
	}

	return target, nil
}

// knownConditionTypes lists every condition discriminator this build models. It
// drives the "did you mean" hint for an unrecognized type. redactFields is
// deliberately excluded — it has its own migration error pointing at directives.
var knownConditionTypes = []string{
	ConditionTypeTimeWindow,
	ConditionTypeIPRange,
	ConditionTypeAllowedOperations,
	ConditionTypeAllowedExtensions,
	ConditionTypeAllowedTables,
	ConditionTypeMaxCalls,
	ConditionTypeRecipientDomain,
	ConditionTypeAllowedValues,
	ConditionTypeSequenceBlock,
	ConditionTypeFlowLabel,
	ConditionTypePolicy,
	ConditionTypeCustom,
}

// suggestConditionType returns the known condition type nearest to unknown, or
// "" when nothing is close enough. Ties resolve to knownConditionTypes order
// for deterministic messages.
func suggestConditionType(unknown string) string {
	return NearestString(unknown, knownConditionTypes)
}

func newCondition(conditionType string) Condition {
	switch conditionType {
	case ConditionTypeTimeWindow:
		return &TimeWindowCondition{}
	case ConditionTypeIPRange:
		return &IPRangeCondition{}
	case ConditionTypeAllowedOperations:
		return &AllowedOperationsCondition{}
	case ConditionTypeAllowedExtensions:
		return &AllowedExtensionsCondition{}
	case ConditionTypeAllowedTables:
		return &AllowedTablesCondition{}
	case ConditionTypeMaxCalls:
		return &MaxCallsCondition{}
	case ConditionTypeRecipientDomain:
		return &RecipientDomainCondition{}
	case ConditionTypePolicy:
		return &PolicyCondition{}
	case ConditionTypeCustom:
		return &CustomCondition{}
	case ConditionTypeAllowedValues:
		return &AllowedValuesCondition{}
	case ConditionTypeSequenceBlock:
		return &SequenceBlockCondition{}
	case ConditionTypeFlowLabel:
		return &FlowLabelCondition{}
	default:
		return nil
	}
}
