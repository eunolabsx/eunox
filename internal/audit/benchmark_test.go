// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// benchCorpus writes a signed audit log of n records shaped like real traffic (a
// session id, a tool target, and a small details map) and returns its lines plus a
// verifier holding the signing key. It is the fixture for the audit-verify
// benchmarks below: the same bytes an incident responder runs `eunox audit-verify`
// over, rather than a synthetic minimal record whose per-record cost would be
// dominated by the fixed envelope.
func benchCorpus(b *testing.B, n int) ([][]byte, *Sink) {
	b.Helper()
	dir := b.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")
	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		b.Fatalf("Open: %v", err)
	}
	for i := 0; i < n; i++ {
		sink.RecordAllow(context.Background(), "sess-benchmark", "read_file", "tools/call",
			map[string]interface{}{"path": "/srv/data/report.csv", "bytes": 4096}, nil, false, nil, nil)
	}
	if err := sink.Close(); err != nil {
		b.Fatalf("Close: %v", err)
	}
	raw, err := os.ReadFile(logPath) //nolint:gosec // G304: path is a benchmark temp dir
	if err != nil {
		b.Fatalf("read log: %v", err)
	}
	lines := bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n"))
	if len(lines) != n {
		b.Fatalf("corpus has %d lines, want %d", len(lines), n)
	}
	key, err := loadOrCreateAuditKey(keyPath)
	if err != nil {
		b.Fatalf("loadOrCreateAuditKey: %v", err)
	}
	// NewVerifier, not a hand-built Sink: it is what `eunox audit-verify` constructs,
	// and it populates verifyKeys, so keysToTry takes the keyring branch the CLI takes
	// rather than the single-active-key fallback.
	return lines, NewVerifier([][]byte{key})
}

// BenchmarkDecodeAuditRecord measures the per-line decode VerifyLog's chain pass
// performs before verification.
func BenchmarkDecodeAuditRecord(b *testing.B) {
	lines, _ := benchCorpus(b, 64)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, dec := decodeAuditRecord(lines[i%len(lines)]); !dec.wellFormed {
			b.Fatal("corpus record failed to decode")
		}
	}
}

// BenchmarkVerifyRecord measures a single record's signature check: decode,
// re-marshal, canonical-form comparison, and HMAC recomputation.
func BenchmarkVerifyRecord(b *testing.B) {
	lines, verifier := benchCorpus(b, 64)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ok, err := verifier.VerifyRecord(lines[i%len(lines)])
		if err != nil || !ok {
			b.Fatalf("VerifyRecord: ok=%v err=%v", ok, err)
		}
	}
}

// BenchmarkVerifyRecordKeyRing measures the same check against a multi-key
// verification ring on a record naming no key_id — the shape that walks the ring
// instead of selecting one key, so the per-key work in the comparison loop is what
// varies.
//
// It measures the AVERAGE case, not the worst one: keysToTry builds its candidate
// list by ranging a map, and Go randomizes map iteration order, so the matching key
// lands in a uniformly random position and roughly half the ring is hashed per
// record. Read it against BenchmarkVerifyRecord (single key) for the per-key delta
// rather than as a K-key worst case.
func BenchmarkVerifyRecordKeyRing(b *testing.B) {
	lines, verifier := benchCorpus(b, 64)
	key := mustSingleRingKey(b, verifier)
	ring := map[string][]byte{hmacKeyID(key): key}
	for i := 0; i < 3; i++ {
		k := make([]byte, 32)
		for j := range k {
			k[j] = byte(i*32 + j + 1)
		}
		ring[hmacKeyID(k)] = k
	}
	verifier.verifyKeys = ring

	// Strip key_id and re-sign, so the record names no key and the ring is walked.
	unidentified := make([][]byte, 0, len(lines))
	for _, line := range lines {
		rec, dec := decodeAuditRecord(line)
		if !dec.wellFormed {
			b.Fatal("corpus record failed to decode")
		}
		rec.KeyID, rec.HMAC = "", ""
		body, err := json.Marshal(rec)
		if err != nil {
			b.Fatalf("marshal: %v", err)
		}
		signed, err := signedRecordLine(body, recordMAC(key, body))
		if err != nil {
			b.Fatalf("signedRecordLine: %v", err)
		}
		unidentified = append(unidentified, signed)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ok, err := verifier.VerifyRecord(unidentified[i%len(unidentified)])
		if err != nil || !ok {
			b.Fatalf("VerifyRecord: ok=%v err=%v", ok, err)
		}
	}
}

// BenchmarkVerifyLog measures the end-to-end cost of an audit-verify pass: the chain
// walk plus the signature check over every line.
//
// One op is one full pass over the corpus, so ns/op and allocs/op are per PASS; the
// per-record figures — the ones worth quoting — are reported as custom metrics.
// Striding b.N by the record count instead would run a whole pass on the framework's
// b.N=1 calibration and charge it to a single op, leaving every reported number a
// function of how far -benchtime happened to ramp.
func BenchmarkVerifyLog(b *testing.B) {
	const records = 512
	lines, verifier := benchCorpus(b, records)
	joined := bytes.Join(lines, []byte("\n"))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res, err := VerifyLog(bytes.NewReader(joined), verifier, "", time.Time{}, io.Discard)
		if err != nil {
			b.Fatalf("VerifyLog: %v", err)
		}
		if !res.OK() || res.Valid != records {
			b.Fatalf("VerifyLog: %+v", res)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*records), "ns/record")
}

// mustSingleRingKey returns the one key benchCorpus's verifier holds. NewVerifier
// keys its ring by key id, which the caller may not have, so this pulls the value
// back out rather than duplicating that derivation.
func mustSingleRingKey(b *testing.B, verifier *Sink) []byte {
	b.Helper()
	if len(verifier.verifyKeys) != 1 {
		b.Fatalf("verifier holds %d keys, want 1", len(verifier.verifyKeys))
	}
	for _, k := range verifier.verifyKeys {
		return k
	}
	return nil
}
