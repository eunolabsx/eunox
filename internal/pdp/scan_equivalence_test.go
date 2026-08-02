// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// The byte-level duplicate-key walk must agree with the tokenizer-derived oracle
// (scan_oracle_test.go) on EVERY input, not just on the shapes the hand-written matrix
// covers. Two suites do that: a table of the cases a reader would think to write, and a
// fuzz target whose seed corpus runs on every `go test`.
//
// Agreement is checked on all three outputs, because each carries its own consequence:
// untrustworthy is the deny, names bounds which pins an untrustworthy entry could be
// impersonating, and namesComplete decides whether the caller poisons that bounded set or
// every pin on the route.

// scanEquivalenceOpts are the two production fold policies plus the redaction policy with an
// empty scope, which is a distinct code path (non-nil map, nothing in it).
func scanEquivalenceOpts() map[string]jsonKeyScanOpts {
	return map[string]jsonKeyScanOpts{
		"toolsList": {},
		"redaction": {allowArrayRoot: true, foldKeys: redactionFoldKeys([]string{"ssn", "data.ssn", "name"})},
		"emptyFold": {allowArrayRoot: true, foldKeys: map[string]struct{}{}},
	}
}

// assertScanAgrees fails when the production scan and the oracle disagree on any field.
func assertScanAgrees(t *testing.T, raw []byte, optsName string, opts jsonKeyScanOpts) {
	t.Helper()
	got := scanJSONKeys(raw, opts)
	want := scanJSONKeysTokenizer(raw, opts)
	if got.untrustworthy != want.untrustworthy || got.namesComplete != want.namesComplete ||
		!equalStrings(got.names, want.names) {
		t.Errorf("scan disagreement (%s) on %q:\n  byte walk: untrustworthy=%v namesComplete=%v names=%q\n  tokenizer: untrustworthy=%v namesComplete=%v names=%q",
			optsName, truncateForLog(raw),
			got.untrustworthy, got.namesComplete, got.names,
			want.untrustworthy, want.namesComplete, want.names)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func truncateForLog(raw []byte) string {
	const limit = 240
	if len(raw) <= limit {
		return string(raw)
	}
	return string(raw[:limit]) + "...(truncated)"
}

// TestScanJSONKeys_MatchesTokenizerOracle walks the shapes that carry a decision: the
// collisions the gate exists to catch, the honest siblings it must NOT refuse, the
// name-attribution cases, and the malformed bytes whose verdict decides how wide a poison
// gets. Each runs under every fold policy.
func TestScanJSONKeys_MatchesTokenizerOracle(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		raw  string
	}{
		// Ordinary shapes.
		{"empty object", `{}`},
		{"empty array", `[]`},
		{"flat object", `{"a":1,"b":"two","c":true,"d":null}`},
		{"nested", `{"a":{"b":{"c":[1,2,{"d":"e"}]}}}`},
		{"array root of objects", `[{"a":1},{"a":2}]`},
		{"array of arrays", `[[],[[]],[{"k":[]}]]`},
		{"whitespace everywhere", "  {\n\t\"a\" : [ 1 , 2 ] ,\r\n \"b\" : { }  }  "},

		// The collisions.
		{"exact duplicate at root", `{"data":{"ssn":"1"},"data":{}}`},
		{"exact duplicate nested", `{"outer":{"ssn":"1","ssn":"2"}}`},
		{"exact duplicate under array", `[{"ssn":"1","ssn":"2"}]`},
		{"case variant at root", `{"Data":1,"data":2}`},
		{"case variant nested", `{"o":{"SSN":1,"ssn":2}}`},
		{"unicode fold collision", `{"de\u017fcription":"a","description":"b"}`},
		{"escaped duplicate spelling", `{"a\u0062":1,"ab":2}`},
		{"reserved key case variant", `{"content":[],"Content":[{"type":"resource"}]}`},
		{"content item key variant", `{"content":[{"type":"text","text":"a","Text":"b"}]}`},

		// Honest siblings that must not be refused by the wrong rule.
		{"case-distinct unnamed siblings", `{"Report":1,"report":2}`},
		{"case-distinct nested unnamed", `{"o":{"Alpha":1,"alpha":2}}`},

		// Name attribution (tools/list policy reads these).
		{"name value", `{"name":"read_file","description":"d"}`},
		{"name folded spelling", `{"Name":"read_file"}`},
		{"duplicate name values", `{"name":"a","name":"b"}`},
		{"name is not a string", `{"name":{"a":1}}`},
		{"name is empty", `{"name":""}`},
		{"name after deep schema", `{"inputSchema":{"a":{"b":{"c":1}}},"name":"late"}`},
		{"nested name is not the entry name", `{"inputSchema":{"name":"inner"}}`},
		{"escaped name value", `{"name":"re\u0061d"}`},
		{"non-ascii name value", `{"name":"caf\u00e9"}`},

		// Numbers: walked, never converted.
		{"number forms", `{"a":0,"b":-1,"c":1.5,"d":1e10,"e":-2.5E-3,"f":1e999}`},
		{"huge integer", `{"a":123456789012345678901234567890}`},

		// Scalars and non-container roots.
		{"root null", `null`},
		{"root number", `42`},
		{"root string", `"hello"`},
		{"root bool", `false`},
		{"root array", `[1,2,3]`},

		// Malformed: the verdict here decides poison breadth.
		{"unterminated object", `{"a":1`},
		{"unterminated string", `{"a":"x`},
		{"unterminated array", `[1,2`},
		{"trailing comma object", `{"a":1,}`},
		{"trailing comma array", `[1,]`},
		{"missing colon", `{"a" 1}`},
		{"non-string key", `{1:2}`},
		{"bare word", `nul`},
		{"bad literal", `{"a":tru}`},
		{"bad number", `{"a":01}`},
		{"bad number 2", `{"a":1.}`},
		{"bad number 3", `{"a":-}`},
		{"bad escape", `{"a":"\q"}`},
		{"raw control byte in string", "{\"a\":\"x\ny\"}"},
		{"lone closer", `}`},
		{"mismatched closers", `{"a":[1}`},
		{"empty input", ``},
		{"whitespace only", `   `},
		{"leading BOM", "\xef\xbb\xbf{\"a\":1}"},
		{"invalid utf8 key", "{\"a\xffb\":1,\"a\xfec\":2}"},

		// Trailing bytes after a complete root: neither implementation reads past the root.
		{"trailing garbage after object", `{"a":1} trailing`},
		{"two values", `{"a":1}{"b":2}`},
	}

	for optsName, opts := range scanEquivalenceOpts() {
		for _, tc := range cases {
			t.Run(optsName+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				assertScanAgrees(t, []byte(tc.raw), optsName, opts)
			})
		}
	}
}

// TestScanJSONKeys_MatchesOracleOnDepthBoundary pins the one verdict a generated corpus is
// unlikely to reach: nesting at, just under, and just over maxDuplicateKeyScanDepth, where
// the scan must report untrustworthy rather than recurse.
func TestScanJSONKeys_MatchesOracleOnDepthBoundary(t *testing.T) {
	t.Parallel()

	nest := func(depth int, open, close string) []byte {
		return []byte(strings.Repeat(open, depth) + strings.Repeat(close, depth))
	}
	for optsName, opts := range scanEquivalenceOpts() {
		for _, depth := range []int{1, 8, maxDuplicateKeyScanDepth - 1, maxDuplicateKeyScanDepth, maxDuplicateKeyScanDepth + 1, maxDuplicateKeyScanDepth * 2} {
			raw := nest(depth, `{"a":`, `}`)
			t.Run(fmt.Sprintf("%s/objects/%d", optsName, depth), func(t *testing.T) {
				t.Parallel()
				assertScanAgrees(t, raw, optsName, opts)
			})
			arr := nest(depth, `[`, `]`)
			t.Run(fmt.Sprintf("%s/arrays/%d", optsName, depth), func(t *testing.T) {
				t.Parallel()
				assertScanAgrees(t, arr, optsName, opts)
			})
		}
	}
}

// FuzzScanJSONKeys is the general equivalence check: any input at all, under every fold
// policy, must produce the same verdict from both implementations. The seeds run on every
// `go test`; a longer campaign (`go test -run XXX -fuzz FuzzScanJSONKeys ./internal/pdp/`)
// is what to run when either implementation changes.
func FuzzScanJSONKeys(f *testing.F) {
	seeds := []string{
		`{}`, `[]`, `null`, `42`, `"s"`, `true`,
		`{"a":1,"a":2}`, `{"A":1,"a":2}`, `{"name":"x","description":"y"}`,
		`{"content":[{"type":"text","text":"{\"ssn\":1}"}]}`,
		`{"de\u017fcription":"a","description":"b"}`,
		`[{"ssn":1},{"ssn":2,"ssn":3}]`,
		`{"a":{"b":[1,2,{"c":null}]},"d":1e999}`,
		`{"a":1`, `{"a" 1}`, `{1:2}`, `[1,]`, `{"a":"\q"}`, "\xef\xbb\xbf{}",
		"{\"a\xffb\":1}",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	optsByName := scanEquivalenceOpts()
	f.Fuzz(func(t *testing.T, raw []byte) {
		for optsName, opts := range optsByName {
			got := scanJSONKeys(raw, opts)
			want := scanJSONKeysTokenizer(raw, opts)
			if got.untrustworthy != want.untrustworthy || got.namesComplete != want.namesComplete ||
				!equalStrings(got.names, want.names) {
				t.Fatalf("scan disagreement (%s) on %q:\n  byte walk: untrustworthy=%v namesComplete=%v names=%q\n  tokenizer: untrustworthy=%v namesComplete=%v names=%q",
					optsName, truncateForLog(raw),
					got.untrustworthy, got.namesComplete, got.names,
					want.untrustworthy, want.namesComplete, want.names)
			}
		}
	})
}

// FuzzScanJSONKeysWellFormed narrows the fuzzer onto the input class the gate actually sees
// in production: bytes that ALREADY decoded cleanly through encoding/json, since both
// callers decode before they scan. A disagreement here is a live defect rather than an
// unreachable edge case, so it is worth its own target — the general fuzzer above spends
// most of its budget on malformed bytes.
func FuzzScanJSONKeysWellFormed(f *testing.F) {
	for _, s := range []string{
		`{"a":1,"b":[{"c":"d"}]}`,
		`{"name":"tool","inputSchema":{"properties":{"p":{"type":"string"}}}}`,
		`[{"ssn":"1"},{"ssn":"2"}]`,
		`{"caf\u00e9":"\ud83d\ude00"}`,
	} {
		f.Add([]byte(s))
	}
	optsByName := scanEquivalenceOpts()
	f.Fuzz(func(t *testing.T, raw []byte) {
		var v interface{}
		if json.Unmarshal(raw, &v) != nil {
			t.Skip("not a complete JSON value; the general fuzzer covers malformed input")
		}
		for optsName, opts := range optsByName {
			got := scanJSONKeys(raw, opts)
			want := scanJSONKeysTokenizer(raw, opts)
			if got.untrustworthy != want.untrustworthy || got.namesComplete != want.namesComplete ||
				!equalStrings(got.names, want.names) {
				t.Fatalf("scan disagreement on well-formed JSON (%s) %q:\n  byte walk: %+v\n  tokenizer: %+v",
					optsName, truncateForLog(raw), got, want)
			}
		}
	})
}
