// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// TestRecordAllow_DelegateSignAndVerify is the required sign-and-verify round-trip for the
// two delegation-attribution fields (delegate, delegation_depth).
//
// The shape they close: a delegation REFUSAL already names the hop that blocked it, in the
// denial's details, while an ALLOW carried nothing — so a call made by agent-b, delegated from
// agent-a, acting for a human, produced a record whose only identity was that human's, and was
// indistinguishable from one they made directly. That is backwards for the record an
// investigator most needs ("which sub-agent actually invoked tool:wire_transfer").
func TestRecordAllow_DelegateSignAndVerify(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	// Two calls, one identity extractor: the first is delegated (user -> agent-a -> agent-b),
	// the second is the same human calling directly.
	ids := []Identity{
		{AgentID: "agent-b", UserID: "user@example.com", Delegate: "agent-b", DelegationDepth: 2},
		{AgentID: "agent-b", UserID: "user@example.com"},
	}
	idx := 0
	sink, err := Open(logPath, keyPath, 0, 0, WithIdentity(func(context.Context) Identity {
		id := ids[idx]
		idx++
		return id
	}))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	sink.RecordAllow(context.Background(), "sess-1", "wire_transfer", "tools/call", nil, nil, false, nil, nil)
	sink.RecordAllow(context.Background(), "sess-1", "wire_transfer", "tools/call", nil, nil, false, nil, nil)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := logLines(t, logPath)
	if len(lines) != 2 {
		t.Fatalf("expected 2 records, got %d", len(lines))
	}
	delegated, direct := lines[0], lines[1]

	if !bytes.Contains(delegated, []byte(`"delegate":"agent-b"`)) {
		t.Fatalf("delegate missing/wrong: %s", delegated)
	}
	if !bytes.Contains(delegated, []byte(`"delegation_depth":2`)) {
		t.Fatalf("delegation_depth missing/wrong: %s", delegated)
	}
	// The human is still on the record: the delegate does not replace the identity the token
	// is FOR, it says who used it.
	if !bytes.Contains(delegated, []byte(`"user_id":"user@example.com"`)) {
		t.Fatalf("user_id must still be stamped on a delegated call: %s", delegated)
	}
	// An undelegated record carries neither field (omitempty), so the overwhelming majority
	// of records are unchanged.
	if bytes.Contains(direct, []byte("delegate")) || bytes.Contains(direct, []byte("delegation_depth")) {
		t.Fatalf("an undelegated record must omit both delegation fields: %s", direct)
	}

	verifier := verifierFor(t, keyPath)
	for i, line := range [][]byte{delegated, direct} {
		if ok, verr := verifier.VerifyRecord(line); !ok || verr != nil {
			t.Fatalf("record %d must verify: ok=%v err=%v", i, ok, verr)
		}
	}

	// Tamper: rewrite the acting delegate on disk without re-signing. The whole point of a
	// top-level signed field (rather than a details annotation) is that this fails closed.
	tampered := bytes.Replace(delegated, []byte(`"delegate":"agent-b"`), []byte(`"delegate":"agent-z"`), 1)
	if bytes.Equal(tampered, delegated) {
		t.Fatal("test setup failed to alter delegate")
	}
	if ok, _ := verifier.VerifyRecord(tampered); ok {
		t.Fatal("a tampered delegate must fail verification")
	}

	// Tamper: shorten the chain, hiding an intermediary.
	tampered = bytes.Replace(delegated, []byte(`"delegation_depth":2`), []byte(`"delegation_depth":1`), 1)
	if bytes.Equal(tampered, delegated) {
		t.Fatal("test setup failed to alter delegation_depth")
	}
	if ok, _ := verifier.VerifyRecord(tampered); ok {
		t.Fatal("a tampered delegation_depth must fail verification")
	}
}

// TestRecordBoundsDelegate pins that the acting delegate is bounded like the other
// IdP-supplied identity fields: act.sub is structure-validated at the token boundary but not
// length-bounded at the source, so an unbounded one would push the serialized record past the
// 4 MiB audit-verify scanner buffer and chain-resume tail window.
func TestRecordBoundsDelegate(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	huge := strings.Repeat("D", 5<<20)
	sink, err := Open(logPath, keyPath, 0, 0, WithIdentity(func(context.Context) Identity {
		return Identity{Delegate: huge, DelegationDepth: 3}
	}))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	sink.RecordAllow(context.Background(), "sess", "read_file", "tools/call", nil, nil, false, nil, nil)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	line := logLines(t, logPath)[0]
	if len(line) > auditEnvelopeFieldCap*2 {
		t.Fatalf("an unbounded delegate reached the tape: record is %d bytes", len(line))
	}
	if !bytes.Contains(line, []byte("truncated")) {
		t.Fatalf("the truncation must be visible on the record: %s", line[:min(len(line), 512)])
	}
	if ok, verr := verifierFor(t, keyPath).VerifyRecord(line); !ok || verr != nil {
		t.Fatalf("a bounded record must still verify: ok=%v err=%v", ok, verr)
	}
}
