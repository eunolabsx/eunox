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
	return lines, &Sink{key: key, keyID: hmacKeyID(key)}
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
// verification ring on a record naming no key_id, which is the shape that tries
// every key in turn — the loop whose per-key allocations dominate a rotated log.
func BenchmarkVerifyRecordKeyRing(b *testing.B) {
	lines, verifier := benchCorpus(b, 64)
	ring := map[string][]byte{verifier.keyID: verifier.key}
	for i := 0; i < 3; i++ {
		k := make([]byte, 32)
		for j := range k {
			k[j] = byte(i*32 + j + 1)
		}
		ring[hmacKeyID(k)] = k
	}
	verifier.verifyKeys = ring

	// Strip key_id and re-sign so every ring key is tried before the match.
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
		signed, err := signedRecordLine(body, recordMAC(verifier.key, body))
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

// BenchmarkVerifyLog measures the end-to-end per-record cost of an audit-verify
// pass: the chain walk plus the signature check over every line.
func BenchmarkVerifyLog(b *testing.B) {
	const records = 512
	lines, verifier := benchCorpus(b, records)
	joined := bytes.Join(lines, []byte("\n"))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i += records {
		res, err := VerifyLog(bytes.NewReader(joined), verifier, "", time.Time{}, io.Discard)
		if err != nil {
			b.Fatalf("VerifyLog: %v", err)
		}
		if !res.OK() || res.Valid != records {
			b.Fatalf("VerifyLog: %+v", res)
		}
	}
}
