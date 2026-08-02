// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
)

// TestRecordDeclassifiedAllow_SignAndVerify is the required sign-and-verify round-trip
// for the three declassification audit fields (labels_cleared, approver, approval_id): a
// record carrying them serializes with all three, verifies under the HMAC chain, and — the
// tamper half — fails closed when any is altered on disk without re-signing.
//
// The tamper half is the point of the test, not a formality. These fields are the evidence
// that a human authorized dropping a flow label; a tape on which the approver could be
// rewritten after the fact would record the declassification without recording who is
// answerable for it. approval_id is signed alongside them rather than riding details for
// the same reason: it is what joins the record back to the approval workflow, and a
// declassification's evidence must be one record shape.
func TestRecordDeclassifiedAllow_SignAndVerify(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	sink.RecordDeclassifiedAllow(context.Background(), "sess-1", "sanitize_report", "tools/call",
		nil, nil, false,
		nil, []string{"internal", "pii"}, []string{"pii"}, "alice@example.com", "apr-9")
	// An ordinary allow must carry neither field.
	sink.RecordAllow(context.Background(), "sess-1", "read_file", "tools/call", nil, nil, false, nil, nil)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := logLines(t, logPath)
	if len(lines) != 2 {
		t.Fatalf("expected 2 records, got %d", len(lines))
	}
	declassified, plain := lines[0], lines[1]

	if !bytes.Contains(declassified, []byte(`"labels_cleared":["pii"]`)) {
		t.Fatalf("labels_cleared missing/wrong: %s", declassified)
	}
	if !bytes.Contains(declassified, []byte(`"approver":"alice@example.com"`)) {
		t.Fatalf("approver missing/wrong: %s", declassified)
	}
	if !bytes.Contains(declassified, []byte(`"approval_id":"apr-9"`)) {
		t.Fatalf("the approval id must be a signed field so a record joins back to the workflow: %s", declassified)
	}
	// The record is still an ALLOW: the call ran. labels_cleared is what distinguishes it.
	if !bytes.Contains(declassified, []byte(`"decision":"allow"`)) {
		t.Fatalf("a declassification is an allow, not a separate decision: %s", declassified)
	}
	if bytes.Contains(plain, []byte("labels_cleared")) || bytes.Contains(plain, []byte("approver")) || bytes.Contains(plain, []byte("approval_id")) {
		t.Fatalf("an ordinary allow must omit both declassification fields: %s", plain)
	}

	verifier := verifierFor(t, keyPath)
	if ok, verr := verifier.VerifyRecord(declassified); !ok || verr != nil {
		t.Fatalf("declassified record must verify: ok=%v err=%v", ok, verr)
	}

	// Tamper: rewrite the approver without re-signing -> must fail closed.
	tampered := bytes.Replace(declassified,
		[]byte(`"approver":"alice@example.com"`),
		[]byte(`"approver":"mallory@example.com"`), 1)
	if bytes.Equal(tampered, declassified) {
		t.Fatal("test setup failed to alter approver")
	}
	if ok, _ := verifier.VerifyRecord(tampered); ok {
		t.Fatal("a tampered approver must fail verification")
	}

	// Tamper: widen the cleared set without re-signing -> must fail closed.
	tampered = bytes.Replace(declassified,
		[]byte(`"labels_cleared":["pii"]`),
		[]byte(`"labels_cleared":["pii","untrusted"]`), 1)
	if bytes.Equal(tampered, declassified) {
		t.Fatal("test setup failed to alter labels_cleared")
	}
	if ok, _ := verifier.VerifyRecord(tampered); ok {
		t.Fatal("a tampered labels_cleared must fail verification")
	}

	// Tamper: repoint the approval id without re-signing -> must fail closed. This arm is
	// the reason the field is top-level and signed rather than a details key: it is what
	// joins the record back to the approval workflow, so a tape on which it could be
	// rewritten would let a declassification be reconciled against someone else's approval.
	tampered = bytes.Replace(declassified,
		[]byte(`"approval_id":"apr-9"`),
		[]byte(`"approval_id":"apr-other"`), 1)
	if bytes.Equal(tampered, declassified) {
		t.Fatal("test setup failed to alter approval_id")
	}
	if ok, _ := verifier.VerifyRecord(tampered); ok {
		t.Fatal("a tampered approval_id must fail verification")
	}
}
