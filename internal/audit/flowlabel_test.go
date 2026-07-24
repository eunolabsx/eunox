// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
)

// TestRecordAllow_FlowLabelsSignAndVerify is the required sign-and-verify round-trip
// for the two new top-level audit fields (labels_out, carried_labels): a record
// carrying them serializes with both arrays, verifies under the HMAC chain, and — the
// tamper half — fails closed when either array is altered on disk without re-signing.
// A record with no labels omits both fields entirely (omitempty), keeping non-flow
// records lean.
func TestRecordAllow_FlowLabelsSignAndVerify(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// A sink whose output labeled confidential, in a session that had already
	// accumulated internal + confidential.
	sink.RecordAllow(context.Background(), "sess-1", "send_report", "tools/call", nil, nil, false,
		[]string{"confidential"}, []string{"internal", "confidential"})
	// A record with no flow labels must omit both fields.
	sink.RecordAllow(context.Background(), "sess-1", "read_file", "tools/call", nil, nil, false, nil, nil)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := logLines(t, logPath)
	if len(lines) != 2 {
		t.Fatalf("expected 2 records, got %d", len(lines))
	}
	labeled, plain := lines[0], lines[1]

	// The labeled record carries both structured arrays.
	if !bytes.Contains(labeled, []byte(`"labels_out":["confidential"]`)) {
		t.Fatalf("labels_out missing/wrong: %s", labeled)
	}
	if !bytes.Contains(labeled, []byte(`"carried_labels":["internal","confidential"]`)) {
		t.Fatalf("carried_labels missing/wrong: %s", labeled)
	}
	// The no-label record omits both fields (omitempty).
	if bytes.Contains(plain, []byte("labels_out")) || bytes.Contains(plain, []byte("carried_labels")) {
		t.Fatalf("a non-flow record must omit both label fields: %s", plain)
	}

	verifier := verifierFor(t, keyPath)

	// Untampered: both records verify.
	if ok, verr := verifier.VerifyRecord(labeled); !ok || verr != nil {
		t.Fatalf("labeled record must verify: ok=%v err=%v", ok, verr)
	}
	if ok, verr := verifier.VerifyRecord(plain); !ok || verr != nil {
		t.Fatalf("plain record must verify: ok=%v err=%v", ok, verr)
	}

	// Tamper: alter labels_out on disk without re-signing -> must fail closed.
	tampered := bytes.Replace(labeled,
		[]byte(`"labels_out":["confidential"]`),
		[]byte(`"labels_out":["public"]`), 1)
	if bytes.Equal(tampered, labeled) {
		t.Fatal("test setup failed to alter labels_out")
	}
	// A value tamper is a plain HMAC mismatch: ok=false (verr is nil for a mismatch,
	// non-nil only for a structural fault), so the tamper is caught by ok being false.
	if ok, _ := verifier.VerifyRecord(tampered); ok {
		t.Fatal("a tampered labels_out must fail verification")
	}

	// Tamper: alter carried_labels similarly -> must fail closed.
	tampered = bytes.Replace(labeled,
		[]byte(`"carried_labels":["internal","confidential"]`),
		[]byte(`"carried_labels":["internal"]`), 1)
	if bytes.Equal(tampered, labeled) {
		t.Fatal("test setup failed to alter carried_labels")
	}
	if ok, _ := verifier.VerifyRecord(tampered); ok {
		t.Fatal("a tampered carried_labels must fail verification")
	}
}
