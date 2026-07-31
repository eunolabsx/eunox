// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
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

	// Reject unknown fields BEFORE decoding. A lenient decode silently drops a misspelled
	// field, and for a condition that means a policy quietly wider than written:
	// {"type":"timeWindow","notBefore":...,"notAfterr":...} decodes with NotAfter == ""
	// and enforces only the lower bound. The binary's manifest loader runs its own
	// recursive unknown-key check, but this decoder is also the exported seam
	// (ConditionWrapper) a library consumer decodes through, and a security primitive must
	// not depend on the caller remembering to re-validate.
	//
	// Checked by key MEMBERSHIP against the target's field set rather than by handing a
	// discriminator-stripped copy to DisallowUnknownFields. Stripping means decoding to a
	// map and re-marshaling, and that round-trip is not identity: it sorts keys and
	// collapses duplicates, so which of two case-variant siblings won would change from
	// JSON's last-wins to byte order — a parser differential introduced by the very check
	// meant to tighten things. Matching is case-insensitive because that is how
	// encoding/json binds, so this rejects exactly the keys the decode would have ignored,
	// no more.
	// "type" is the envelope's discriminator, not a field of any condition struct.
	if err := rejectUnknownJSONFields(data, target, fmt.Sprintf("condition %q", envelope.Type), "type"); err != nil {
		return nil, err
	}

	// Decode the ORIGINAL bytes, so duplicate-key and case-variant binding stay exactly
	// what encoding/json does everywhere else. UseNumber keeps numeric policy literals as
	// json.Number rather than widening them to float64 (which rounds integers above 2^53,
	// e.g. authorizing the neighbour of 9007199254740993). Request arguments are decoded
	// the same way, and numericEqual compares the preserved json.Number values exactly.
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(target); err != nil {
		return nil, fmt.Errorf("condition %q: %w", envelope.Type, err)
	}

	return target, nil
}

// jsonFieldNamesCache memoizes jsonFieldNames per concrete type. Conditions and
// directives are decoded on the manifest-load path (every condition of every constraint,
// again on every `validate`/`doctor` run), and the reflect walk is identical for a given
// type.
var jsonFieldNamesCache sync.Map // reflect.Type -> map[string]bool

// rejectUnknownJSONFields fails when data carries a top-level key encoding/json would
// not bind on target, naming the offender. context prefixes the error ("condition
// \"timeWindow\"", "constraint", …); allowExtra names keys that are legitimate on the
// wire but absent from target's field set, such as a polymorphic envelope's "type"
// discriminator.
//
// It is the shared body of every strict decoder in this package, so the rule cannot
// hold in one and lapse in another. See unmarshalCondition for the full rationale; in
// brief, a lenient decode silently drops a MISSPELLED key, and for a policy object that
// means a policy quietly wider than written — a widening the author cannot see, because
// the file they wrote loaded without complaint.
//
// Checked by key MEMBERSHIP rather than by handing a discriminator-stripped copy to
// DisallowUnknownFields: stripping means decoding to a map and re-marshaling, and that
// round-trip is not identity (it sorts keys and collapses duplicates), so which of two
// case-variant siblings won would change from JSON's last-wins to byte order — a parser
// differential introduced by the very check meant to tighten things. Matching is
// case-insensitive because that is how encoding/json binds, so this rejects exactly the
// keys the decode would have ignored, no more.
func rejectUnknownJSONFields(data []byte, target any, context string, allowExtra ...string) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("%s: %w", context, err)
	}
	known := jsonFieldNames(target)
	for k := range fields {
		if known[strings.ToLower(k)] {
			continue
		}
		if slices.ContainsFunc(allowExtra, func(e string) bool { return strings.EqualFold(k, e) }) {
			continue
		}
		return fmt.Errorf("%s: unknown field %q", context, k)
	}
	return nil
}

// jsonFieldNames returns the lowercased JSON field names encoding/json would bind on v,
// for the unknown-field checks in unmarshalCondition and unmarshalDirective. Lowercased
// because encoding/json matches field names case-insensitively; an unexported field
// contributes nothing here, matching what the decoder itself would accept.
func jsonFieldNames(v any) map[string]bool {
	t := reflect.TypeOf(v)
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if cached, ok := jsonFieldNamesCache.Load(t); ok {
		return cached.(map[string]bool)
	}
	names := make(map[string]bool, t.NumField())
	for i := range t.NumField() {
		f := t.Field(i)
		if f.PkgPath != "" { // unexported
			continue
		}
		name := f.Name
		if tag := f.Tag.Get("json"); tag != "" {
			if tag == "-" {
				continue
			}
			if comma := strings.Index(tag, ","); comma >= 0 {
				tag = tag[:comma]
			}
			if tag != "" {
				name = tag
			}
		}
		names[strings.ToLower(name)] = true
	}
	jsonFieldNamesCache.Store(t, names)
	return names
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
