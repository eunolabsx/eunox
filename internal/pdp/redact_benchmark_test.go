// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
)

// BenchmarkApplyRedactObligs measures the redaction response path — the work done on every
// allowed tools/call whose constraint carries a redactFields obligation, so it scales with
// response size and leaf count.
//
// The path is two passes over the same bytes by construction: encoding/json has already
// collapsed duplicate keys last-wins by the time a map exists, so the fail-closed
// duplicate-key gate has to read the RAW bytes, once over the envelope and once over every
// JSON leaf the walk unwraps. That is not negotiable (see redactionKeysAmbiguous), which is
// exactly why its cost needs a tracked baseline rather than an estimate.
//
// Four sub-benchmarks, splitting on what changes the shape of the work:
//
//   - NoMatch is the common case: the obligation names a field the response does not
//     carry, so nothing is redacted and the ORIGINAL bytes are returned verbatim. Every
//     leaf is still decoded and scanned, because a field that is not there has to be
//     proven not there.
//   - Match adds the re-marshal of the whole envelope on top of that.
//   - DoublyEncoded is the adversarial shape: each leaf is a JSON string wrapping a JSON
//     string wrapping the object, so every layer costs its own decode + scan.
//   - Prose is the fast-path floor: text leaves that cannot be JSON at all, which the
//     classifier's byte guard rejects without a decoder.
func BenchmarkApplyRedactObligs(b *testing.B) {
	obligs := []capability.Obligation{{Type: capability.DirectiveTypeRedactFields, Paths: []string{"ssn"}}}

	run := func(b *testing.B, payload []byte) {
		b.SetBytes(int64(len(payload)))
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := ApplyRedactObligs(payload, obligs); err != nil {
				b.Fatalf("ApplyRedactObligs: %v", err)
			}
		}
	}

	b.Run("NoMatch", func(b *testing.B) { run(b, benchRedactResult(20, benchLeafJSON, false)) })
	b.Run("Match", func(b *testing.B) { run(b, benchRedactResult(20, benchLeafJSON, true)) })
	b.Run("DoublyEncoded", func(b *testing.B) { run(b, benchRedactResult(20, benchLeafDoublyEncoded, false)) })
	b.Run("Prose", func(b *testing.B) { run(b, benchRedactResult(20, benchLeafProse, false)) })
}

// benchLeafKind selects the body shape of each text content item.
type benchLeafKind int

const (
	// benchLeafJSON is a plain JSON object body — the ordinary structured tool result.
	benchLeafJSON benchLeafKind = iota
	// benchLeafDoublyEncoded wraps that object in two layers of JSON string encoding, the
	// smuggling shape the redactor must unwrap (and scan) at every layer.
	benchLeafDoublyEncoded
	// benchLeafProse is free text: no addressable JSON key, and the classifier's byte
	// guard rejects it without invoking a decoder.
	benchLeafProse
)

// benchRedactResult builds a tools/call result with n text content items of the given shape
// plus a structuredContent object, sized like a real tool response. withMatch decides
// whether the obligation's field ("ssn") is actually present, which is the difference
// between returning the original bytes verbatim and re-marshaling the whole envelope.
func benchRedactResult(n int, kind benchLeafKind, withMatch bool) []byte {
	content := make([]interface{}, 0, n)
	for i := 0; i < n; i++ {
		content = append(content, map[string]interface{}{
			"type": "text",
			"text": benchLeafBody(i, kind, withMatch),
		})
	}
	structured := map[string]interface{}{
		"summary": "quarterly rollup across every region, generated upstream",
		"rows":    benchRows(8, withMatch),
	}
	out, err := json.Marshal(map[string]interface{}{
		"content":           content,
		"structuredContent": structured,
		"isError":           false,
	})
	if err != nil {
		panic(fmt.Sprintf("benchRedactResult: %v", err))
	}
	return out
}

// benchLeafBody renders one content item's text body in the requested shape.
func benchLeafBody(i int, kind benchLeafKind, withMatch bool) string {
	if kind == benchLeafProse {
		return fmt.Sprintf("Record %d: the upstream service completed the request and returned "+
			"a human-readable summary with no structured payload attached.", i)
	}
	body, err := json.Marshal(map[string]interface{}{
		"id":     fmt.Sprintf("rec-%04d", i),
		"region": "us-east-1",
		"detail": strings.Repeat("x", 64),
		"rows":   benchRows(4, withMatch),
	})
	if err != nil {
		panic(fmt.Sprintf("benchLeafBody: %v", err))
	}
	s := string(body)
	if kind == benchLeafDoublyEncoded {
		// Two string-encoding layers: the redactor decodes one to find another string, and
		// only the second unwrap yields a container to scan.
		for layer := 0; layer < 2; layer++ {
			enc, err := json.Marshal(s)
			if err != nil {
				panic(fmt.Sprintf("benchLeafBody encode: %v", err))
			}
			s = string(enc)
		}
	}
	return s
}

// benchRows builds the repeated object rows a tool result carries, optionally including the
// field the benchmark's obligation names.
func benchRows(n int, withMatch bool) []interface{} {
	rows := make([]interface{}, 0, n)
	for i := 0; i < n; i++ {
		row := map[string]interface{}{
			"account": fmt.Sprintf("acct-%06d", i),
			"amount":  1000 + i,
			"status":  "settled",
		}
		if withMatch {
			row["ssn"] = "123-45-6789"
		}
		rows = append(rows, row)
	}
	return rows
}

// BenchmarkScanJSONKeys isolates the duplicate-key scan itself — the pass every redaction
// leaf and every */list entry pays on top of its decode — against a plain decode of the
// same bytes, so a change to the scanner is measured rather than inferred from the
// end-to-end path above.
func BenchmarkScanJSONKeys(b *testing.B) {
	payload := benchRedactResult(20, benchLeafJSON, false)
	fold := redactionFoldKeys([]string{"ssn"})

	b.Run("Scan", func(b *testing.B) {
		b.SetBytes(int64(len(payload)))
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if scanJSONKeys(payload, jsonKeyScanOpts{allowArrayRoot: true, foldKeys: fold}).untrustworthy {
				b.Fatal("benchmark payload must not be ambiguous")
			}
		}
	})

	b.Run("Decode", func(b *testing.B) {
		b.SetBytes(int64(len(payload)))
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var v map[string]interface{}
			if err := json.Unmarshal(payload, &v); err != nil {
				b.Fatalf("unmarshal: %v", err)
			}
		}
	})

	// The tools/list entry gate's rule (root-object fold, exact below), so a change that
	// helps one caller and hurts the other is visible.
	b.Run("ToolEntry", func(b *testing.B) {
		entry := json.RawMessage(benchToolEntryBytes())
		b.SetBytes(int64(len(entry)))
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if scanToolEntry(entry).untrustworthy {
				b.Fatal("benchmark entry must not be ambiguous")
			}
		}
	})
}

// benchToolEntryBytes is one catalog entry shaped like benchToolCatalog's, as raw bytes.
func benchToolEntryBytes() []byte {
	out, err := json.Marshal(benchToolCatalog(1)[0])
	if err != nil {
		panic(fmt.Sprintf("benchToolEntryBytes: %v", err))
	}
	return out
}
