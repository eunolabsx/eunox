// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"sort"
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

// IsTypedNil reports whether v is a non-nil interface wrapping a nil value — the "typed nil"
// that slips past a plain v == nil check yet panics on any method call whose receiver it
// dereferences (a value-receiver ConditionType/DirectiveType on a decoded condition/directive).
// It is the one such predicate for the manifest, engine, config and transport layers, so the
// validation, marshaling and wiring guards that reject a typed nil before such a call share one
// definition. (internal/redisutil answers the same question for a go-redis client separately,
// because it depends on go-redis and the stdlib alone — importing this package for two lines
// would put the whole manifest vocabulary in a kill-switch-only consumer's binary.)
// A plain-nil interface returns false (reflect.ValueOf(nil) has Kind Invalid),
// so callers pair it with an explicit v == nil check — IsNilValue — where a plain nil is also
// rejected.
//
// EVERY nilable kind, not the pointer this package's own callers happen to hand it. The kinds
// are named rather than tried because reflect's IsNil PANICS on any other one, and a guard must
// not become the crash it prevents; the list is IsNil's whole panic set minus Interface, which
// reflect.ValueOf never yields (it unwraps to the dynamic type, and Go does not let that be
// another interface). Narrower was behaviour-preserving for a decoded condition and a silent
// hole for the transport wiring guard that now shares this: the first func- or map-typed
// subsystem handed over as a typed nil would have walked straight through it.
func IsTypedNil(v any) bool {
	switch rv := reflect.ValueOf(v); rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Func, reflect.Slice, reflect.Chan, reflect.UnsafePointer:
		return rv.IsNil()
	default:
		return false
	}
}

// IsNilValue reports whether v holds no value at all: the interface itself nil, or a typed nil
// inside a non-nil interface. It is IsTypedNil paired with the plain-nil test its doc tells
// callers to add, written once because three call sites had written it themselves — a manifest
// token, a proxy's wired subsystem, a diagnostic seam's reporter — and the composition is the
// half a reader gets wrong, not the reflection.
//
// It answers for a value that IS nil, never for a wrapper AROUND one: reflecting into an
// embedded field would refuse decorators that legitimately forward elsewhere.
func IsNilValue(v any) bool { return v == nil || IsTypedNil(v) }

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
	case *EffectClassCondition:
		type alias EffectClassCondition
		return json.Marshal(struct {
			conditionEnvelope
			*alias
		}{conditionEnvelope{Type: typed.ConditionType()}, (*alias)(typed)})
	case *BlastRadiusCondition:
		type alias BlastRadiusCondition
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
// differential introduced by the very check meant to tighten things. Matching folds
// through FoldJSONKey, the same fold encoding/json's own field binder uses (see its doc:
// strings.ToLower/EqualFold under-fold runes like U+017F), so this rejects exactly the
// keys the decode would have ignored, no more.
func rejectUnknownJSONFields(data []byte, target any, context string, allowExtra ...string) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("%s: %w", context, err)
	}
	known := jsonFieldNames(target)
	for k := range fields {
		if known[FoldJSONKey(k)] {
			continue
		}
		if slices.ContainsFunc(allowExtra, func(e string) bool { return FoldJSONKey(k) == FoldJSONKey(e) }) {
			continue
		}
		return fmt.Errorf("%s: unknown field %q", context, k)
	}
	return nil
}

// jsonFieldNames returns the fold-canonicalized JSON field names encoding/json would bind
// on v, for the unknown-field checks in unmarshalCondition and unmarshalDirective. Folded
// through FoldJSONKey because encoding/json matches field names case-insensitively via a
// Unicode simple fold, not plain ASCII lower-casing; an unexported field contributes
// nothing here, matching what the decoder itself would accept.
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
		names[FoldJSONKey(name)] = true
	}
	jsonFieldNamesCache.Store(t, names)
	return names
}

// conditionPrototypes is THE registry of condition discriminators this build models: each
// maps to a constructor, the grammar revision that introduced it (Since), its cross-call
// state class (State; see tokenstate.go), and the engine subsystems it reads (Uses; see
// subsystem.go). Everything that enumerates, instantiates, or classifies condition types
// derives from this one map — newCondition, the "did you mean" hint, the manifest loader's
// per-type key sets, and the schemaVersion gate — so adding a type means adding it HERE, not
// in hand-maintained tables that drift one entry at a time. A classification kept in a
// separate table can silently disagree (e.g. admitting a "0.2" predicate under "0.1"), or
// leave a state-accumulating condition's decisions unserialized, or leave the flow path
// skipped for a policy that reads it. redactFields is deliberately absent — it is a
// directive, with its own migration error pointing there.
var conditionPrototypes = map[string]tokenSpec[Condition]{
	ConditionTypeTimeWindow:        {New: func() Condition { return &TimeWindowCondition{} }, Since: SchemaVersion01, State: StateNone, Uses: usesNothing},
	ConditionTypeIPRange:           {New: func() Condition { return &IPRangeCondition{} }, Since: SchemaVersion01, State: StateNone, Uses: usesNothing},
	ConditionTypeAllowedOperations: {New: func() Condition { return &AllowedOperationsCondition{} }, Since: SchemaVersion01, State: StateNone, Uses: usesNothing},
	ConditionTypeAllowedExtensions: {New: func() Condition { return &AllowedExtensionsCondition{} }, Since: SchemaVersion01, State: StateNone, Uses: usesNothing},
	ConditionTypeAllowedTables:     {New: func() Condition { return &AllowedTablesCondition{} }, Since: SchemaVersion01, State: StateNone, Uses: usesNothing},
	// The quota lives in the call counter, which is wired unconditionally — it is not one of
	// the optional subsystems either gate can skip.
	ConditionTypeMaxCalls:        {New: func() Condition { return &MaxCallsCondition{} }, Since: SchemaVersion01, State: StateAtomic, Uses: usesNothing},
	ConditionTypeRecipientDomain: {New: func() Condition { return &RecipientDomainCondition{} }, Since: SchemaVersion01, State: StateNone, Uses: usesNothing},
	ConditionTypeAllowedValues:   {New: func() Condition { return &AllowedValuesCondition{} }, Since: SchemaVersion01, State: StateNone, Uses: usesNothing},
	// The one reader of the antecedent marker: recording it exists solely so this can ask what
	// preceded the call.
	ConditionTypeSequenceBlock: {New: func() Condition { return &SequenceBlockCondition{} }, Since: SchemaVersion01, State: StateNonAtomic, Uses: []EngineSubsystem{SubsystemAntecedentHistory}},
	// The flow sink: it peeks the label set a labelOutput source writes.
	ConditionTypeFlowLabel:   {New: func() Condition { return &FlowLabelCondition{} }, Since: SchemaVersion02, State: StateNonAtomic, Uses: []EngineSubsystem{SubsystemFlowLabels}},
	ConditionTypeEffectClass: {New: func() Condition { return &EffectClassCondition{} }, Since: SchemaVersion02, State: StateNone, Uses: usesNothing},
	// The strongest class a blastRadius bound can reach; an instance carrying only the
	// per-call `max` narrows itself to StateNone (RefineStateAccumulation). Its cumulative
	// bound is a call-counter budget, not one of the optional subsystems.
	ConditionTypeBlastRadius: {New: func() Condition { return &BlastRadiusCondition{} }, Since: SchemaVersion02, State: StateAtomic, Uses: usesNothing},
	// An external evaluator (OPA, Cedar) may keep state of its own, but none of it is state
	// THIS engine accumulates, orders, or shares between replicas — which is the only thing
	// the two derived predicates can speak for.
	//
	// Uses is the opposite call, and deliberately so: these two are the extension points, so
	// what their enforcement reads is supplied from OUTSIDE this build and cannot be known
	// here. An embedder's handler can close over the very FlowLabelStore the engine was given,
	// and skipping the flow path for a policy whose only token is one of these would leave it
	// reading a set nothing populates. Declaring everything costs a per-call scan; the other
	// direction is the silent one.
	ConditionTypePolicy: {New: func() Condition { return &PolicyCondition{} }, Since: SchemaVersion01, State: StateNone, Uses: engineSubsystems},
	ConditionTypeCustom: {New: func() Condition { return &CustomCondition{} }, Since: SchemaVersion01, State: StateNone, Uses: engineSubsystems},
}

// usesNothing is the shared declaration for a token whose enforcement reads no optional engine
// subsystem. It is a named value rather than a repeated literal so the registry lines stay
// readable, and it is never mutated (TokenEngineSubsystems clones before returning).
var usesNothing = []EngineSubsystem{SubsystemNone}

// knownConditionTypes is every discriminator in the registry, sorted so the "did you mean"
// hint resolves ties deterministically (a map's iteration order would not).
var knownConditionTypes = sortedRegistryKeys(conditionPrototypes)

// sortedRegistryKeys returns a prototype registry's discriminators in lexical order. It is
// generic over the prototype constructor so the condition and directive registries share one
// derivation: two copies of "collect the map keys and sort them" is the same mirrored-table
// shape the registries themselves exist to remove, and a later refinement of how a
// vocabulary is derived (an alias table, a non-lexical tie-break) must not land on one of
// them only.
func sortedRegistryKeys[V any](prototypes map[string]V) []string {
	out := make([]string, 0, len(prototypes))
	for t := range prototypes {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// NewConditionPrototype returns a zero value of the named condition type, and whether this
// build models that discriminator at all.
//
// It exists so a caller outside this package can ask the SAME registry the decoder
// instantiates from what a condition type looks like — concretely, the manifest loader's
// unknown-key check, which derives each type's permitted key set by reflecting over the
// prototype. That check used to carry its own reflect.TypeOf switch over all fourteen
// types: one more table to keep in step, and one that fails SILENTLY when it falls behind
// (a type missing from it is simply not key-checked).
//
// The prototype is freshly constructed per call, so a caller cannot mutate the registry's
// idea of a type.
func NewConditionPrototype(condType string) (Condition, bool) {
	spec, ok := conditionPrototypes[condType]
	if !ok {
		return nil, false
	}
	return spec.New(), true
}

// KnownConditionTypes returns a fresh copy of the registry's discriminators in lexical
// order — the closed condition vocabulary, read from the ONE registry rather than a
// mirrored list. It exists so a consumer that must stay in step with the grammar (the
// published JSON Schema's drift guard) derives its expectation from the registry itself:
// a hand-written mirror is a second table to update per new condition type, and one that
// fails silently — a type missing from it is simply not checked.
//
// A fresh slice each call, so a caller cannot mutate the package's accepted set.
func KnownConditionTypes() []string {
	return append([]string(nil), knownConditionTypes...)
}

// suggestConditionType returns the known condition type nearest to unknown, or
// "" when nothing is close enough. Ties resolve to knownConditionTypes order
// for deterministic messages.
func suggestConditionType(unknown string) string {
	return NearestString(unknown, knownConditionTypes)
}

// newCondition returns a zero value of the condition type named by conditionType, or nil
// for a discriminator this build does not model. It is the in-package spelling of
// NewConditionPrototype — same registry, nil rather than a second (Condition, bool) return,
// because the decoder's next step is a type switch that handles nil anyway.
func newCondition(conditionType string) Condition {
	proto, _ := NewConditionPrototype(conditionType)
	return proto
}
