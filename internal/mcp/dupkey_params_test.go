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
