// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"encoding/json"
	"strings"
	"testing"
)

// Two case-variant spellings of one known field are DISTINCT map keys that both fold to a
// known name, so the membership check passed both and the decode that followed bound them
// last-wins. Through the exported seam a policy then loaded clean and enforced the second
// value while a reviewer read the first — the reviewer-versus-decoder substitution
// RefuseAmbiguousJSONKeys refuses one layer down, on the one surface it does not cover.
//
// Every case here is a spelling the DECODER resolves silently; the refusal is what makes the
// two readings agree.
func TestFoldDuplicateMembersAreRefusedAtTheExportedSeams(t *testing.T) {
	for name, tc := range map[string]struct {
		decode func([]byte) error
		data   string
		want   []string // substrings the refusal must name
	}{
		"condition field": {
			decode: func(b []byte) error { _, err := unmarshalCondition(b); return err },
			data:   `{"type":"recipientDomain","argument":"to","domains":["corp.com"],"Domains":["evil.com"]}`,
			want:   []string{`"domains"`, `"Domains"`},
		},
		// The discriminator itself is swappable, so it is refused too even though it is an
		// allowExtra key rather than a field of any condition struct.
		"condition discriminator": {
			decode: func(b []byte) error { _, err := unmarshalCondition(b); return err },
			data:   `{"type":"timeWindow","Type":"ipRange","notBefore":"09:00","notAfter":"17:00"}`,
			want:   []string{`"type"`, `"Type"`},
		},
		// An EXACT duplicate is the same divergence without the case change: the decoder keeps
		// the last, a reader reads the first.
		"exact duplicate": {
			decode: func(b []byte) error { _, err := unmarshalCondition(b); return err },
			data:   `{"type":"timeWindow","notBefore":"09:00","notBefore":"00:00"}`,
			want:   []string{`"notBefore"`, "declared twice"},
		},
		"directive field": {
			decode: func(b []byte) error { _, err := unmarshalDirective(b); return err },
			data:   `{"type":"redactFields","fields":["users.ssn"],"Fields":["nothing"]}`,
			want:   []string{`"fields"`, `"Fields"`},
		},
		// principals-vs-principal is the field that decides who a constraint governs at all.
		"constraint field": {
			decode: func(b []byte) error { return json.Unmarshal(b, &Constraint{}) },
			data:   `{"target":"tool:send","actions":["call"],"principal":{"sub":["a"]},"Principal":{"sub":["b"]}}`,
			want:   []string{`"principal"`, `"Principal"`},
		},
		"context manifest": {
			decode: func(b []byte) error {
				_, err := ParseContextManifest(map[string]json.RawMessage{MetaKeyContextManifest: b})
				return err
			},
			data: `{"labels":["confidential"],"Labels":["public"]}`,
			want: []string{`"labels"`, `"Labels"`},
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := tc.decode([]byte(tc.data))
			if err == nil {
				t.Fatal("two members that are one field to the decoder must be refused, not resolved")
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("the refusal must name %s, got: %v", want, err)
				}
			}
			if !strings.Contains(err.Error(), "declare it once") {
				t.Fatalf("the refusal must say what the ambiguity IS and how to fix it, got: %v", err)
			}
		})
	}
}

// The ambiguity scan runs before the field set is known — it has to, since the discriminator
// that selects that set is itself one of the members it protects — so an ambiguous name is
// refused as ambiguous whether or not it is one this build binds. A LONE unknown name still
// reports as unknown, which is the message an author with a typo needs.
func TestFoldDuplicateRefusalIsIndependentOfWhetherTheNameIsKnown(t *testing.T) {
	_, err := unmarshalCondition([]byte(`{"type":"timeWindow","notBefore":"09:00","bogus":1,"Bogus":2}`))
	if err == nil || !strings.Contains(err.Error(), "declare it once") {
		t.Fatalf("expected the ambiguity refusal, got: %v", err)
	}
	_, err = unmarshalCondition([]byte(`{"type":"timeWindow","notBefore":"09:00","bogus":1}`))
	if err == nil || !strings.Contains(err.Error(), `unknown field "bogus"`) {
		t.Fatalf("expected the unknown-field refusal, got: %v", err)
	}
}

// A fold-variant discriminator is refused as the ambiguity it is, rather than steering
// newCondition and reporting a condition type the author never wrote.
func TestFoldDuplicateDiscriminatorIsRefusedBeforeItSteers(t *testing.T) {
	for _, data := range []string{
		`{"type":"maxCalls","Type":"bogus","count":5,"windowSeconds":60}`,
		`{"type":"maxCalls","Type":"redactFields","count":5,"windowSeconds":60}`,
	} {
		_, err := unmarshalCondition([]byte(data))
		if err == nil || !strings.Contains(err.Error(), "declare it once") {
			t.Fatalf("expected the ambiguity refusal, got: %v", err)
		}
		if strings.Contains(err.Error(), "unknown condition type") || strings.Contains(err.Error(), "must be placed in") {
			t.Fatalf("the refusal names a type the author never wrote: %v", err)
		}
	}
}

// The rule is TOP LEVEL, which is what keeps it from being the whole-document walk: an
// extension point's Config payload is the embedder's own object, consumed whole here.
func TestFoldDuplicateRuleDoesNotDescendIntoAnExtensionPayload(t *testing.T) {
	cond, err := unmarshalCondition([]byte(`{"type":"policy","backend":"opa","config":{"path":"a","Path":"b"}}`))
	if err != nil {
		t.Fatalf("a nested payload is the embedder's to shape: %v", err)
	}
	if cond.ConditionType() != ConditionTypePolicy {
		t.Fatalf("decoded the wrong condition: %s", cond.ConditionType())
	}
}

// A single canonical spelling still loads, so the refusal costs a conforming author nothing.
func TestSingleSpellingStillDecodes(t *testing.T) {
	cond, err := unmarshalCondition([]byte(`{"type":"recipientDomain","argument":"to","domains":["corp.com"]}`))
	if err != nil {
		t.Fatalf("a well-formed condition must load: %v", err)
	}
	rd, ok := cond.(*RecipientDomainCondition)
	if !ok {
		t.Fatalf("decoded %T", cond)
	}
	if len(rd.Domains) != 1 || rd.Domains[0] != "corp.com" {
		t.Fatalf("domains = %v", rd.Domains)
	}
}

// A malformed document is still the decoder's to report, and reports through this seam's
// context prefix rather than panicking the scan.
func TestFoldDuplicateScanLeavesMalformedInputToTheDecoder(t *testing.T) {
	for _, data := range []string{`[]`, `{"type":"timeWindow"`, `{"type":"timeWindow"} {}`, `7`} {
		if _, err := unmarshalCondition([]byte(data)); err == nil {
			t.Fatalf("%q must not decode as a condition", data)
		}
	}
}

// encoding/json calls an Unmarshaler for a null too, and the convention is that null is a
// no-op. The map decode the member scan replaced gave that for free; without the guard a
// `capabilities: [null]` manifest regressed from the loader's own "'target' must not be
// empty", which names the index, to a shape error naming no position at all.
func TestConstraintNullIsANoOp(t *testing.T) {
	var one Constraint
	if err := json.Unmarshal([]byte("null"), &one); err != nil {
		t.Fatalf("null must be a no-op: %v", err)
	}
	if one.Target != "" {
		t.Fatalf("null must leave the value untouched, got %+v", one)
	}
	var many []Constraint
	if err := json.Unmarshal([]byte("[null]"), &many); err != nil {
		t.Fatalf("a null array element must decode: %v", err)
	}
	if len(many) != 1 || many[0].Target != "" {
		t.Fatalf("decoded %+v", many)
	}
	// It is still the ONLY non-object accepted; the gate stays in force for the rest.
	if err := json.Unmarshal([]byte(`[7]`), &many); err == nil {
		t.Fatal("a non-object constraint must be refused")
	}
}
