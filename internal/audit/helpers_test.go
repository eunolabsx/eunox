// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newestRotatedSibling returns the chronologically newest rotated sibling of
// logPath, or "" when there are none — the raw ordering/filtering that
// sortedRotatedSiblings and rotatedOrderLess implement, exercised directly by the
// rotate tests. Production resolves the resume tail through
// newestRotatedSiblingWithTail (content-aware); this test-only wrapper isolates the
// ordering logic from the tail-reading walk.
func newestRotatedSibling(logPath string) string {
	files, err := sortedRotatedSiblings(logPath)
	if err != nil || len(files) == 0 {
		return ""
	}
	return files[len(files)-1]
}

// recordDetails decodes an audit record's marshaled Details (a json.RawMessage,
// produced once by marshalAndBoundDetails so writeRecord embeds it verbatim) into
// a map for test assertions, or nil when the record carries no details. JSON
// numbers decode to float64, matching what the prior map[string]interface{} field
// yielded after a JSONL round-trip.
func recordDetails(tb testing.TB, rec auditRecord) map[string]interface{} {
	tb.Helper()
	if len(rec.Details) == 0 {
		return nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal(rec.Details, &m); err != nil {
		tb.Fatalf("decode audit record details: %v (%s)", err, rec.Details)
	}
	return m
}

// loadOrCreateAuditKey returns the active HMAC signing key, creating a fresh key
// file when none exists. It is the single-key view of LoadOrCreateKeys, used
// only by tests that assert on a single signing key ( finding C-2 moved
// it out of production code, where every call site was a test).
func loadOrCreateAuditKey(keyPath string) ([]byte, error) {
	keys, err := LoadOrCreateKeys(keyPath)
	if err != nil {
		return nil, err
	}
	return keys[0], nil
}

// writeChainLog opens a sink at dir, writes the given tool names as allow
// records, closes it, and returns the log + key paths.
func writeChainLog(t *testing.T, dir string, tools ...string) (logPath, keyPath string) {
	t.Helper()
	logPath = filepath.Join(dir, "audit.jsonl")
	keyPath = filepath.Join(dir, "audit.key")
	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for _, tool := range tools {
		sink.RecordAllow(context.Background(), "sess", tool, "tools/call", nil, nil, false)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return logPath, keyPath
}

func verifierFor(t *testing.T, keyPath string) *Sink {
	t.Helper()
	key, err := loadOrCreateAuditKey(keyPath)
	if err != nil {
		t.Fatalf("loadOrCreateAuditKey: %v", err)
	}
	return &Sink{key: key}
}

func logLines(t *testing.T, logPath string) [][]byte {
	t.Helper()
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	return bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n"))
}

func verifyBytes(t *testing.T, lines [][]byte, verifier *Sink) VerifyResult {
	t.Helper()
	joined := bytes.Join(lines, []byte("\n"))
	res, err := VerifyLog(bytes.NewReader(joined), verifier, "", time.Time{}, &strings.Builder{})
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	return res
}

func hmacHex(key, body []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// writeLegacyTail writes a single pre-chain (HMAC-less) record to logPath, the
// exact shape the pre-signing format wrote: no "_hmac" and no "prev_hmac" field.
// withSeq controls whether a "seq" field is present (a pre-seq legacy tail
// unmarshals to Seq == 0, indistinguishable from a fresh log by seq alone).
func writeLegacyTail(t *testing.T, logPath string, withSeq bool) {
	t.Helper()
	seq := ""
	if withSeq {
		seq = `"seq":41,`
	}
	line := `{"class_uid":6003,"category_uid":6,"activity_id":1,` +
		`"time":"2026-01-01T00:00:00Z",` + seq +
		`"request_id":"req-legacy","session_id":"sess",` +
		`"target_type":"tool","target":"legacy_tool",` +
		`"method":"tools/call","decision":"allow"}` + "\n"
	if err := os.WriteFile(logPath, []byte(line), 0o600); err != nil {
		t.Fatalf("WriteFile legacy tail: %v", err)
	}
}

// readAuditRecords reads all JSONL lines from logPath and returns them parsed.
// This is a package-audit copy of the identically-named cmd/eunox test
// helper, kept so white-box tests here can read records back as plain maps
// without depending on the binary's test package.
func readAuditRecords(t *testing.T, logPath string) []map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(logPath) //nolint:gosec // G304: path is test-controlled temp dir
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}
	var out []map[string]interface{}
	for _, line := range bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var rec map[string]interface{}
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Errorf("unmarshal audit line: %v (line: %s)", err, line)
			continue
		}
		out = append(out, rec)
	}
	return out
}

// mustReadFile reads path, failing the test on error.
func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: test-controlled temp dir
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	return data
}

// mustReadLastAuditLine returns the last audit-log line, failing the test on an
// I/O error.
func mustReadLastAuditLine(t *testing.T, path string) string {
	t.Helper()
	line, err := readLastAuditLine(path)
	if err != nil {
		t.Fatalf("readLastAuditLine(%q): %v", path, err)
	}
	return line
}

// nonZeroTestKey returns a deterministic non-zero 32-byte HMAC key for tests that
// construct a Sink directly. parseAuditKeys rejects an all-zero key, so even
// though direct Sink construction bypasses that check, tests use real (non-zero)
// key material rather than a make([]byte, 32) placeholder so they stay
// representative of a valid installation.
func nonZeroTestKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}
