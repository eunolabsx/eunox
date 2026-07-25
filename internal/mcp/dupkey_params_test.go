// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"errors"
	"testing"
)

// TestDecodeParams_RejectsDuplicateKeys pins that DecodeParams fails closed on a
// duplicate object key at ANY nesting depth. Go's decoder keeps the last value, but the
// transport forwards the caller's original params bytes verbatim, so a first-key-wins
// upstream would act on a different value than enforcement authorized — argument (and,
// at the params root, tool-name) smuggling. Rejecting the decode is the fail-closed fix.
func TestDecodeParams_RejectsDuplicateKeys(t *testing.T) {
	t.Parallel()
	reject := []struct {
		name string
		raw  string
	}{
		{"top-level tool-name smuggling", `{"name":"safe","name":"dangerous"}`},
		{"nested argument smuggling", `{"name":"read","arguments":{"path":"/safe","path":"/etc/shadow"}}`},
		{"arguments object duplicated", `{"arguments":{"a":1},"arguments":{"b":2}}`},
		{"duplicate inside array element", `{"batch":[{"path":"/a","path":"/b"}]}`},
		{"deeply nested duplicate", `{"a":{"b":{"c":{"k":1,"k":2}}}}`},

		// Case-variant siblings are the same smuggle: encoding/json binds object keys to
		// struct fields by a case-folding match and keeps the LAST, so an exact-only check
		// would let the proxy authorize one value while the forwarded bytes carry another.
		{"tool-name smuggling by case fold", `{"name":"dangerous_tool","Name":"safe_tool"}`},
		{"tool-name smuggling, fold order reversed", `{"Name":"safe_tool","name":"dangerous_tool"}`},
		{"resource URI smuggling by case fold", `{"uri":"file:///etc/shadow","Uri":"file:///safe/ok"}`},
		{"arguments object smuggling by case fold", `{"name":"read","arguments":{"path":"/safe"},"Arguments":{"path":"/etc/shadow"}}`},
		{"nested argument smuggling by case fold", `{"arguments":{"path":"/safe","Path":"/etc/shadow"}}`},
		{"all-caps variant", `{"NAME":"a","name":"b"}`},
		// U+017F (long s) folds onto "s" for the decoder but is untouched by ToLower,
		// so this pins that the fold is a real Unicode simple-fold, not a lower-casing.
		{"unicode long-s fold variant", `{"description":"<INJECT>","deſcription":"<CLEAN>"}`},
	}
	for _, tc := range reject {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var v map[string]interface{}
			err := DecodeParams(json.RawMessage(tc.raw), &v)
			if err == nil {
				t.Fatalf("DecodeParams(%s) = nil error, want a fail-closed rejection", tc.raw)
			}
			if !errors.Is(err, ErrParse) {
				t.Fatalf("DecodeParams(%s) error = %v, want ErrParse-wrapped", tc.raw, err)
			}
		})
	}

	accept := []struct {
		name string
		raw  string
	}{
		{"distinct keys", `{"name":"read","arguments":{"path":"/safe","mode":"r"}}`},
		{"same key in sibling objects is fine", `{"a":{"k":1},"b":{"k":2}}`},
		{"same key across array elements is fine", `{"batch":[{"k":1},{"k":2}]}`},
		{"null params", `null`},
		{"nested arrays and scalars", `{"n":1,"list":[1,2,3],"obj":{"x":true,"y":null}}`},
		// The duplicate-key walk must not narrow what DecodeParams accepts. A number
		// past float64 max is valid JSON with no duplicate key, and is only rejected if
		// the walk's decoder forgets UseNumber and materializes values as float64.
		{"number beyond float64 max", `{"name":"compute","arguments":{"scale":1e309}}`},
		{"large mantissa", `{"arguments":{"n":2.5e308}}`},
		{"integer beyond int64", `{"arguments":{"n":123456789012345678901234567890}}`},
	}
	for _, tc := range accept {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var v interface{}
			if err := DecodeParams(json.RawMessage(tc.raw), &v); err != nil {
				t.Fatalf("DecodeParams(%s) = %v, want nil (no duplicate key)", tc.raw, err)
			}
		})
	}
}

// TestDecodeParams_PreservesNumericPrecision pins the end-to-end guarantee DecodeParams
// documents: a caller-supplied integer that float64 cannot represent (2^53+1 rounds down)
// survives the decode as an exact json.Number. The duplicate-key walk runs first and has
// its own decoder, so this also guards against that walk silently reintroducing float64
// number handling — a numeric constraint must compare the value the caller actually sent,
// because the upstream receives the original bytes verbatim.
func TestDecodeParams_PreservesNumericPrecision(t *testing.T) {
	t.Parallel()
	const exact = "9007199254740993" // 2^53+1: not representable as a float64
	var v struct {
		Arguments struct {
			N json.Number `json:"n"`
		} `json:"arguments"`
	}
	raw := json.RawMessage(`{"arguments":{"n":` + exact + `}}`)
	if err := DecodeParams(raw, &v); err != nil {
		t.Fatalf("DecodeParams(%s) = %v, want nil", raw, err)
	}
	if got := v.Arguments.N.String(); got != exact {
		t.Fatalf("decoded n = %s, want %s (precision lost)", got, exact)
	}
}
