// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"encoding/json"
	"testing"
)

// FuzzParseTarget exercises the target-namespace parser (e.g. "tool:read_file")
// that runs over every manifest capability and over targets derived from request
// arguments. It must never panic on arbitrary input — it returns a typed target
// or an error.
func FuzzParseTarget(f *testing.F) {
	f.Add("tool:read_file")
	f.Add("resource:file:///etc/passwd")
	f.Add("prompt:summarize")
	f.Add("system:sampling")
	f.Add("")
	f.Add(":")
	f.Add("tool:")
	f.Add("unknown:x")

	f.Fuzz(func(t *testing.T, s string) {
		typ, bare, err := ParseTarget(s)
		if err != nil {
			return
		}
		// On success the parser must report a non-empty, recognized target type.
		if typ == "" {
			t.Errorf("ParseTarget(%q) returned no error but an empty target type (bare=%q)", s, bare)
		}
	})
}

// FuzzConstraintUnmarshalJSON exercises the polymorphic Constraint unmarshaller
// (string-discriminated conditions, directives) against arbitrary JSON. It must
// never panic; malformed input yields an error.
func FuzzConstraintUnmarshalJSON(f *testing.F) {
	f.Add([]byte(`{"target":"tool:x","actions":["call"]}`))
	f.Add([]byte(`{"target":"tool:x","conditions":[{"type":"allowedValues","argument":"path","values":["/tmp"]}]}`))
	f.Add([]byte(`{"target":"tool:x","conditions":[{"type":"maxCalls","max":5}]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"conditions":[{"type":"__nope__"}]}`))
	f.Add([]byte(`null`))

	f.Fuzz(func(_ *testing.T, data []byte) {
		var c Constraint
		_ = json.Unmarshal(data, &c)
	})
}
