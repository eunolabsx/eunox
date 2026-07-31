// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"encoding/json"
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
	out := boundDenialDetails(map[string]interface{}{
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
// individually under the string cap. handleAllowedValues echoes the decoded argument
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
			out := boundDenialDetails(map[string]interface{}{"value": val})
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
	out := boundDenialDetails(map[string]interface{}{"value": nested})

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
	if s, ok := cur.(string); !ok || s != denialDetailElided {
		t.Errorf("deepest value = %#v, want the elision marker %q", cur, denialDetailElided)
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

	out := boundDenialDetails(in)

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

	first, err := json.Marshal(boundDenialDetails(in))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for i := 0; i < 20; i++ {
		next, err := json.Marshal(boundDenialDetails(in))
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if string(next) != string(first) {
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

	out := boundDenialDetails(map[string]interface{}{"value": "ok\xff\xfebad"})
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

	if got := boundDenialDetails(nil); got != nil {
		t.Errorf("nil details = %#v, want nil (an omitted details field, not {})", got)
	}

	in := map[string]interface{}{
		"argument":          "filePath",
		"filePath":          "/srv/data/report.xlsx",
		"extension":         ".xlsx",
		"allowedExtensions": []string{".csv", ".txt"},
		"limit":             10,
		"current":           11,
		"retryAfter":        30,
		"allowed":           false,
	}
	out := boundDenialDetails(in)
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
