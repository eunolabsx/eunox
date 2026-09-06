// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/eunolabs/eunox/pkg/capability"
)

// marshaledLen is the size of the details map as it would land on the signed tape.
func marshaledLen(t *testing.T, m map[string]interface{}) int {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal details: %v", err)
	}
	return len(b)
}

// TestBoundDenialDetails_BoundsEchoedStrings is the base case: a handler echoing the
// argument that failed its check must not put the argument's full length into the
// HMAC-signed tape. Nothing bounds a tool-call argument before the condition check
// runs, so an unbounded echo makes every denied call a kilobyte-per-byte lever on
// signed-log growth.
func TestBoundDenialDetails_BoundsEchoedStrings(t *testing.T) {
	t.Parallel()

	huge := strings.Repeat("A", 1<<20) // 1 MiB, what a single tool argument can carry
	out := BoundDenialDetails(map[string]interface{}{
		"argument": "path",
		"value":    huge,
	})

	got, _ := out["value"].(string)
	if len(got) > maxDenialDetailStringLen {
		t.Errorf("echoed value is %d bytes, want <= %d", len(got), maxDenialDetailStringLen)
	}
	if !strings.Contains(got, "truncated") {
		t.Errorf("value = %q, want a visible truncation marker", got)
	}
	if out["argument"] != "path" {
		t.Errorf("argument = %v, want the short value passed through unchanged", out["argument"])
	}
}

// TestBoundDenialDetails_BoundsTotalNotJustEachString covers what a per-string cap
// alone misses: an argument that decoded to a large container whose every element is
// individually under the string cap. EvaluateAllowedValues echoes the decoded argument
// whatever shape it arrived in.
func TestBoundDenialDetails_BoundsTotalNotJustEachString(t *testing.T) {
	t.Parallel()

	cases := map[string]interface{}{}
	// 50k short strings in an array: every element passes a per-string cap.
	wide := make([]interface{}, 50000)
	for i := range wide {
		wide[i] = "xx"
	}
	cases["wide array"] = wide
	// A large object, every key and value short.
	obj := map[string]interface{}{}
	for i := 0; i < 50000; i++ {
		obj[strings.Repeat("k", 8)+string(rune('a'+i%26))+string(rune('a'+i/26%26))+string(rune('a'+i/676%26))] = "v"
	}
	cases["wide object"] = obj
	// An array of scalars, which carry no string bytes at all.
	bools := make([]interface{}, 200000)
	for i := range bools {
		bools[i] = true
	}
	cases["scalar array"] = bools

	for name, val := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			out := BoundDenialDetails(map[string]interface{}{"value": val})
			// Generous headroom over the budget for markers and JSON punctuation; the
			// point is that the result is KiB, not MiB.
			if n := marshaledLen(t, out); n > 4*maxDenialDetailsBytes {
				t.Errorf("marshaled details = %d bytes, want bounded near the %d-byte budget", n, maxDenialDetailsBytes)
			}
		})
	}
}

// TestBoundDenialDetails_BoundsUnboundedNesting pins the depth cap. The byte budget
// charges for keys and scalars, so a deep chain of POPULATED objects exhausts it — but
// a chain of empty containers costs nothing per level and would otherwise recurse as
// deep as the caller's JSON nested.
func TestBoundDenialDetails_BoundsUnboundedNesting(t *testing.T) {
	t.Parallel()

	var nested interface{} = []interface{}{}
	for i := 0; i < 5000; i++ {
		nested = []interface{}{nested}
	}
	out := BoundDenialDetails(map[string]interface{}{"value": nested})

	// Walk down and confirm the structure terminates at the depth cap.
	depth := 0
	cur := out["value"]
	for {
		arr, ok := cur.([]interface{})
		if !ok || len(arr) == 0 {
			break
		}
		depth++
		cur = arr[0]
		if depth > maxDenialDetailDepth+2 {
			t.Fatalf("nesting was not bounded: still descending past depth %d", depth)
		}
	}
	if s, ok := cur.(string); !ok || s != DenialDetailElided {
		t.Errorf("deepest value = %#v, want the elision marker %q", cur, DenialDetailElided)
	}
}

// TestBoundDenialDetails_DoesNotAliasCallerStructures pins the deep copy. The maps and
// slices handlers put in Details alias live structures — the matched constraint's
// allowedValues slice, the decoded request arguments — read concurrently by other
// in-flight decisions. Bounding in place would mutate the loaded manifest.
func TestBoundDenialDetails_DoesNotAliasCallerStructures(t *testing.T) {
	t.Parallel()

	manifestValues := []string{"alpha", "beta"}
	nestedArg := map[string]interface{}{"inner": "original"}
	in := map[string]interface{}{
		"allowedValues": manifestValues,
		"value":         nestedArg,
	}

	out := BoundDenialDetails(in)

	// Mutating the bounded copy must not reach the caller's structures.
	outVals, _ := out["allowedValues"].([]string)
	if len(outVals) != 2 {
		t.Fatalf("allowedValues = %#v, want both entries preserved", out["allowedValues"])
	}
	outVals[0] = "MUTATED"
	if manifestValues[0] != "alpha" {
		t.Errorf("the manifest's slice was mutated through the bounded copy: %q", manifestValues[0])
	}
	outNested, _ := out["value"].(map[string]interface{})
	outNested["inner"] = "MUTATED"
	if nestedArg["inner"] != "original" {
		t.Errorf("the caller's nested map was mutated through the bounded copy: %v", nestedArg["inner"])
	}
}

// TestBoundDenialDetails_IsDeterministic pins sorted-key iteration. Go randomizes map
// iteration, so under an exhausted budget which entries survived would differ between
// two identical denied calls — reading to an operator, and to a diffing SIEM rule, as
// though the requests differed.
func TestBoundDenialDetails_IsDeterministic(t *testing.T) {
	t.Parallel()

	in := map[string]interface{}{}
	for i := 0; i < 400; i++ {
		in[string(rune('a'+i%26))+string(rune('a'+i/26))] = strings.Repeat("v", 64)
	}

	first, err := json.Marshal(BoundDenialDetails(in))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for i := 0; i < 20; i++ {
		next, err := json.Marshal(BoundDenialDetails(in))
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if !bytes.Equal(next, first) {
			t.Fatal("bounding the same details twice produced different records")
		}
	}
}

// TestBoundDenialDetails_NestedTruncationIsDeterministic pins the same property one level
// down, where it actually broke: BoundDenialDetails collects every top-level key before
// sorting, but boundDetailMap bounds a NESTED object against a per-key share that can admit
// only a subset of its keys, and an early-stopped collection was a random sample of Go's
// map iteration — two identical denied calls wrote different signed records.
func TestBoundDenialDetails_NestedTruncationIsDeterministic(t *testing.T) {
	t.Parallel()

	nested := map[string]interface{}{}
	for i := 0; i < 3000; i++ {
		nested[fmt.Sprintf("k%04d", i)] = i
	}
	// Enough top-level keys to floor the per-key share at minDenialDetailKeyBudget, so the
	// nested object's key count far exceeds what its budget can admit.
	in := map[string]interface{}{"value": nested}
	for i := 0; i < 15; i++ {
		in[fmt.Sprintf("pad%02d", i)] = "x"
	}

	out := BoundDenialDetails(in)
	outNested, _ := out["value"].(map[string]interface{})
	if _, ok := outNested[DenialDetailElidedKey]; !ok {
		t.Fatal("test shape did not force nested truncation; the determinism loop below would pass vacuously")
	}
	// The deterministic rule is smallest-first, so the lexicographic minimum always survives.
	if _, ok := outNested["k0000"]; !ok {
		t.Error("smallest nested key did not survive truncation")
	}

	first, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for i := 0; i < 20; i++ {
		next, err := json.Marshal(BoundDenialDetails(in))
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if !bytes.Equal(next, first) {
			t.Fatal("bounding the same details twice produced different records")
		}
	}
}

// TestBoundDenialDetails_NormalizesInvalidUTF8 pins the UTF-8 treatment. encoding/json
// is not idempotent across a decode-then-re-encode round trip for invalid UTF-8, and
// both the audit chain's HMAC recompute and its canonical-bytes check depend on that
// idempotency: a denial echo carrying a stray invalid byte could otherwise be the
// field that makes a genuine, never-tampered record fail verification.
func TestBoundDenialDetails_NormalizesInvalidUTF8(t *testing.T) {
	t.Parallel()

	out := BoundDenialDetails(map[string]interface{}{"value": "ok\xff\xfebad"})
	got, _ := out["value"].(string)
	if !utf8.ValidString(got) {
		t.Errorf("value = %q, want valid UTF-8", got)
	}
	if strings.ContainsRune(got, 0xff) {
		t.Errorf("value = %q, want the invalid bytes replaced", got)
	}
}

// TestBoundDenialDetails_PreservesNilAndShortValues: the bound must be invisible to
// every real denial. A deny's details are what makes it actionable to the operator
// reading it back, so nothing under the caps may be altered.
func TestBoundDenialDetails_PreservesNilAndShortValues(t *testing.T) {
	t.Parallel()

	if got := BoundDenialDetails(nil); got != nil {
		t.Errorf("nil details = %#v, want nil (an omitted details field, not {})", got)
	}

	in := map[string]interface{}{
		"argument":            "filePath",
		"filePath":            "/srv/data/report.xlsx",
		"extension":           ".xlsx",
		"allowedExtensions":   []string{".csv", ".txt"},
		"limit":               10,
		"current":             11,
		"retry_after_seconds": 30,
		"allowed":             false,
	}
	out := BoundDenialDetails(in)
	if len(out) != len(in) {
		t.Fatalf("got %d entries, want all %d preserved: %#v", len(out), len(in), out)
	}
	for k, want := range in {
		got := out[k]
		if ss, ok := want.([]string); ok {
			gs, ok := got.([]string)
			if !ok || len(gs) != len(ss) {
				t.Errorf("%s = %#v, want %#v", k, got, want)
				continue
			}
			for i := range ss {
				if gs[i] != ss[i] {
					t.Errorf("%s[%d] = %q, want %q", k, i, gs[i], ss[i])
				}
			}
			continue
		}
		if got != want {
			t.Errorf("%s = %#v, want %#v", k, got, want)
		}
	}
}

// TestDenyResponse_BoundsDetails is the wiring assertion: the bound is applied at the
// funnel every deny passes through, not at each handler's Details literal. A handler
// added later must inherit it without touching its own map — the property that keeps
// 20-odd sites from drifting out of sync.
func TestDenyResponse_BoundsDetails(t *testing.T) {
	t.Parallel()

	huge := strings.Repeat("Z", 1<<20)
	resp := denyResponse("req-1", "2026-01-01T00:00:00Z", false, nil, capability.DenialInfo{
		Code:          capability.ErrCodeValueNotPermitted,
		ConditionType: capability.ConditionTypeAllowedValues,
		Message:       "denied",
		Details:       map[string]interface{}{"value": huge},
	})

	if resp.Denial == nil {
		t.Fatal("denyResponse produced no denial")
	}
	got, _ := resp.Denial.Details["value"].(string)
	if len(got) > maxDenialDetailStringLen {
		t.Errorf("denyResponse left a %d-byte value in the details reaching RecordDeny", len(got))
	}
}

// TestBoundDenialDetails_EmptyContainersAreCharged is the regression for the hole that
// made the byte budget bound nothing for a whole class of shapes. The map arm charged
// per KEY and the slice arm per non-empty ELEMENT, so `{}` and `[]` each cost zero —
// and an argument built out of them (3 bytes per element on the wire) carried a
// caller-sized structure into a "bounded" result. Measured before the fix: 600 KB
// against an 8 KiB budget, which then tripped the audit sink's coarse 1 MiB cap and
// replaced the WHOLE details map with a marker, destroying the diagnostic content this
// walk exists to preserve.
// namedDetailString is a named scalar type: it reaches boundDetailValue's default arm
// through reflection rather than the string arm, so it must be charged there too.
type namedDetailString string

func TestBoundDenialDetails_EmptyContainersAreCharged(t *testing.T) {
	t.Parallel()

	for name, elem := range map[string]func() interface{}{
		"empty objects": func() interface{} { return map[string]interface{}{} },
		"empty arrays":  func() interface{} { return []interface{}{} },
		// The same hole one shape further down: a container charges
		// denialDetailContainerCost, but an empty STRING charged len()==0, so an array of
		// them was admitted whole. Both concrete slice arms are covered — []interface{}
		// routes through boundDetailValue and []string through its own bound closure, and
		// the two have drifted apart before.
		"empty strings":       func() interface{} { return "" },
		"empty json.Numbers":  func() interface{} { return json.Number("") },
		"one-byte strings":    func() interface{} { return "x" },
		"empty []byte":        func() interface{} { return []byte{} },
		"empty typed strings": func() interface{} { return namedDetailString("") },
		"empty strings in []string": func() interface{} {
			s := make([]string, 200)
			return s
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			wide := make([]interface{}, 200000)
			for i := range wide {
				wide[i] = elem()
			}
			out := BoundDenialDetails(map[string]interface{}{"value": wide})
			if n := marshaledLen(t, out); n > 4*maxDenialDetailsBytes {
				t.Errorf("marshaled details = %d bytes for %s, want bounded near the %d-byte budget", n, name, maxDenialDetailsBytes)
			}
		})
	}
}

// TestBoundDenialDetails_PolicyListCannotStarveTheEvidence is the regression for the
// budget-allocation bug. Keys were walked in sorted order against ONE shared budget,
// and every handler's policy-list key (allowedValues, allowedExtensions, allowedCIDRs)
// sorts before its evidence keys (argument, value, filePath) — so an ordinary manifest
// with a few hundred allowed values consumed the whole budget and elided the denied
// argument NAME and VALUE, the two fields the bound exists to preserve. The transport
// also reads Details["argument"] to build the host-facing error message, so its loss
// emptied error.data.argument on every deny under such a manifest.
func TestBoundDenialDetails_PolicyListCannotStarveTheEvidence(t *testing.T) {
	t.Parallel()

	allowed := make([]string, 900)
	for i := range allowed {
		allowed[i] = "/srv/data/" + strings.Repeat("x", 32)
	}
	out := BoundDenialDetails(map[string]interface{}{
		"argument":      "path",
		"value":         "/etc/shadow",
		"allowedValues": allowed,
	})

	if got := out["argument"]; got != "path" {
		t.Errorf("argument = %#v, want %q — the denied argument name must survive a large allowlist", got, "path")
	}
	if got := out["value"]; got != "/etc/shadow" {
		t.Errorf("value = %#v, want %q — the offending value must survive a large allowlist", got, "/etc/shadow")
	}
	// The allowlist is still bounded, and still present: a share, not an eviction.
	kept, ok := out["allowedValues"].([]string)
	if !ok || len(kept) == 0 {
		t.Fatalf("allowedValues = %#v, want a bounded but non-empty list", out["allowedValues"])
	}
	if len(kept) >= len(allowed) {
		t.Errorf("allowedValues kept %d of %d entries, want it bounded", len(kept), len(allowed))
	}
}

// TestBoundDenialDetails_BoundsTopLevelKeyCount is the regression for the breadth gap
// the per-key SHARE left open: share floors at minDenialDetailKeyBudget once len(in)
// passes maxDenialDetailsBytes/minDenialDetailKeyBudget keys, so "bounds the WHOLE map"
// held only up to that count — a handler (a custom ConditionHandler or PolicyEvaluator
// echoing attacker-derived arguments) recording thousands of top-level keys grew output
// ~512 bytes per extra key with nothing capping breadth.
func TestBoundDenialDetails_BoundsTopLevelKeyCount(t *testing.T) {
	t.Parallel()

	in := make(map[string]interface{}, 5000)
	for i := 0; i < 5000; i++ {
		in[fmt.Sprintf("key-%05d", i)] = "v"
	}
	out := BoundDenialDetails(in)

	if n := marshaledLen(t, out); n > 2*maxDenialDetailsBytes {
		t.Errorf("marshaled details = %d bytes for %d top-level keys, want bounded near the %d-byte budget", n, len(in), maxDenialDetailsBytes)
	}
	if len(out) > maxDenialDetailTopLevelKeys+1 { // +1 for the elision marker
		t.Errorf("output has %d top-level keys, want at most %d plus the elision marker", len(out), maxDenialDetailTopLevelKeys)
	}
	marker, ok := out[DenialDetailElidedKey].(string)
	if !ok {
		t.Fatalf("out[%q] = %#v, want an elision marker naming the dropped key count", DenialDetailElidedKey, out[DenialDetailElidedKey])
	}
	if !strings.Contains(marker, fmt.Sprintf("of %d entries elided", len(in))) {
		t.Errorf("elision marker = %q, want it to name the total entry count %d", marker, len(in))
	}
	// The surviving keys are the lexicographically FIRST ones, deterministically — not an
	// arbitrary subset Go's randomized map iteration would otherwise pick.
	if _, ok := out["key-00000"]; !ok {
		t.Error("want the lexicographically first key to survive the breadth cap")
	}
	if _, ok := out["key-04999"]; ok {
		t.Error("want the lexicographically last key elided by the breadth cap")
	}
}

// TestBoundDenialDetails_ReservedMarkerIsNotForgeable pins the collision guard. The
// elision marker's purpose is that a SIEM rule can match it to spot a caller probing
// the bound — so a caller able to plant it forges elision provenance on the signed
// tape, making the detector forgeable by the party it exists to detect. Details["value"]
// is the raw decoded argument, so a nested object is all it takes.
func TestBoundDenialDetails_ReservedMarkerIsNotForgeable(t *testing.T) {
	t.Parallel()

	out := BoundDenialDetails(map[string]interface{}{
		"argument": "opts",
		"value":    map[string]interface{}{DenialDetailElidedKey: "473 of 500 entries elided"},
	})
	nested, _ := out["value"].(map[string]interface{})
	if nested == nil {
		t.Fatalf("value = %#v, want the nested object preserved", out["value"])
	}
	if _, forged := nested[DenialDetailElidedKey]; forged {
		t.Errorf("a caller-planted %q survived verbatim: %#v", DenialDetailElidedKey, nested)
	}
	// Re-spelled, not dropped: the caller's data is still visible to a reader.
	if _, kept := nested[denialDetailForgedKeyPrefix+DenialDetailElidedKey]; !kept {
		t.Errorf("the colliding key must be re-spelled, not discarded: %#v", nested)
	}
	// A top-level collision is escaped too.
	top := BoundDenialDetails(map[string]interface{}{DenialDetailElidedKey: "forged"})
	if _, forged := top[DenialDetailElidedKey]; forged {
		t.Errorf("a top-level caller-planted marker survived: %#v", top)
	}
}

// TestCeilingRefusalDetailsAreBounded pins that BOTH effect-ceiling outcomes go through
// the shared response constructors, which is where boundDenialDetails runs.
//
// The details a ceiling stamps carry caller-controlled bytes — blast_radius is rendered
// from a tool ARGUMENT — and the two arms were assembled as EnforceResponse literals, so
// they were the only refusals in the engine exempt from the bound every other deny site
// inherits by construction. An escalation is also the one refusal shape a human is
// expected to read back off the signed tape, which is exactly the record that must not be
// a megabyte of caller-chosen digits.
//
// It lives in the internal test package rather than beside the other ceiling tests so it
// can assert against the real budget constants instead of hardcoded copies of them.
func TestCeilingRefusalDetailsAreBounded(t *testing.T) {
	t.Parallel()

	caps := []capability.Constraint{{
		Target:  "tool:refund",
		Actions: []string{"call"},
		Effect: &capability.EffectContract{
			Class:              capability.EffectCompensable,
			CompensatingAction: "tool:" + strings.Repeat("z", 4096),
			BlastRadius:        &capability.BlastRadiusSpec{Argument: "amount", Unit: strings.Repeat("u", 4096)},
		},
	}}
	req := &capability.EnforceRequest{
		SessionID:  "sess",
		TargetName: "refund",
		Target:     &capability.EnforceRequestTarget{Type: "tool", Name: "refund"},
		// ~1500 digits: over the ceiling, and rendered into the details in full by
		// big.Float.Text('f', -1).
		Arguments: map[string]interface{}{"amount": json.Number(strings.Repeat("9", 1500))},
	}
	bound := json.Number("1000")

	for name, ceiling := range map[string]*capability.EffectCeiling{
		"escalate": {MaxBlastRadius: &bound},
		"deny":     {MaxBlastRadius: &bound, OnExceed: capability.OnExceedDeny},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			eng := New(WithEffectCeiling(ceiling))
			resp := eng.ValidateAction(context.Background(), req, caps)
			if resp.Decision == capability.DecisionAllow || resp.Denial == nil {
				t.Fatalf("decision = %v, want a ceiling refusal", resp.Decision)
			}
			for k, v := range resp.Denial.Details {
				if s, ok := v.(string); ok && len(s) > maxDenialDetailStringLen {
					t.Errorf("details[%q] reached the tape unbounded at %d bytes", k, len(s))
				}
			}
			if n := marshaledLen(t, resp.Denial.Details); n > 4*maxDenialDetailsBytes {
				t.Errorf("marshaled details = %d bytes, want bounded near the %d-byte budget", n, maxDenialDetailsBytes)
			}
		})
	}
}
