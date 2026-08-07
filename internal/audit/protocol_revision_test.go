// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
)

// TestRecord_ProtocolRevisionSignAndVerify is the required sign-and-verify round-trip for
// the protocol_revision field.
//
// What it closes: with per-revision method tables, "tools/call denied AUTHORIZATION_FAILED"
// reads identically whether policy refused the call or the method does not exist in the
// revision the peer negotiated. Without the revision on the record an auditor cannot tell
// those apart — and the field has to be in the SIGNED body for the answer to be trustworthy,
// which is what the tamper leg below asserts.
func TestRecord_ProtocolRevisionSignAndVerify(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	old := capability.WithProtocolRevision(context.Background(), capability.Revision20251125)
	current := capability.WithProtocolRevision(context.Background(), capability.Revision20260728)
	sink.RecordAllow(old, "sess-1", "read_file", "tools/call", nil, nil, false, nil, nil)
	sink.RecordDeny(current, "sess-1", "ping", "ping", capability.ErrCodeAuthorizationFailed, "", nil, false)
	// A record written before any revision was negotiated (a pre-session refusal) carries no
	// revision at all, which is honest: none was decided.
	sink.RecordDeny(context.Background(), "sess-1", "tools/call", "tools/call", capability.ErrCodeKillSwitch, "", nil, false)
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := logLines(t, logPath)
	if len(lines) != 3 {
		t.Fatalf("expected 3 records, got %d", len(lines))
	}
	allow, deny, unnegotiated := lines[0], lines[1], lines[2]

	if !bytes.Contains(allow, []byte(`"protocol_revision":"2025-11-25"`)) {
		t.Fatalf("protocol_revision missing/wrong on the allow: %s", allow)
	}
	if !bytes.Contains(deny, []byte(`"protocol_revision":"2026-07-28"`)) {
		t.Fatalf("protocol_revision missing/wrong on the deny: %s", deny)
	}
	if bytes.Contains(unnegotiated, []byte("protocol_revision")) {
		t.Fatalf("a record written before negotiation must omit the field rather than claim a revision: %s", unnegotiated)
	}

	verifier := verifierFor(t, keyPath)
	for i, line := range [][]byte{allow, deny, unnegotiated} {
		if ok, verr := verifier.VerifyRecord(line); !ok || verr != nil {
			t.Fatalf("record %d must verify: ok=%v err=%v", i, ok, verr)
		}
	}

	// Tamper: relabel the denied 2026-07-28 call as an old-revision one, which would recast a
	// removed-method refusal as a policy denial. A top-level signed field makes that fail.
	tampered := bytes.Replace(deny, []byte(`"protocol_revision":"2026-07-28"`), []byte(`"protocol_revision":"2025-11-25"`), 1)
	if ok, _ := verifier.VerifyRecord(tampered); ok {
		t.Fatal("a rewritten protocol_revision must break the record HMAC")
	}
}

// TestRecord_ProtocolRevisionRefusesAnUnspokenRevision: the field is drawn from the closed
// published set, so a context carrying anything else stamps nothing rather than writing an
// unverifiable revision onto the signed tape.
func TestRecord_ProtocolRevisionRefusesAnUnspokenRevision(t *testing.T) {
	t.Parallel()
	ctx := capability.WithProtocolRevision(context.Background(), capability.Revision("1999-01-01"))
	if got := protocolRevision(ctx); got != "" {
		t.Errorf("protocolRevision = %q, want \"\" for a revision this build does not speak", got)
	}
	if got := protocolRevision(context.Background()); got != "" {
		t.Errorf("protocolRevision = %q, want \"\" when nothing was negotiated", got)
	}
	for _, rev := range capability.PublishedRevisions() {
		if got := protocolRevision(capability.WithProtocolRevision(context.Background(), rev)); got != rev.String() {
			t.Errorf("protocolRevision = %q, want %q", got, rev)
		}
	}
}

// TestQueueSize_CountsProtocolRevision keeps the enqueue reservation and the drainer's
// credit balanced: queueSize is charged once at enqueue and credited back verbatim, so a new
// variable-length field it does not count is heap the aggregate budget cannot see.
func TestQueueSize_CountsProtocolRevision(t *testing.T) {
	t.Parallel()
	bare := auditRecord{}
	withRev := auditRecord{ProtocolRevision: capability.Revision20260728.String()}
	if got, want := withRev.queueSize()-bare.queueSize(), int64(len(capability.Revision20260728)); got != want {
		t.Errorf("queueSize delta for protocol_revision = %d, want %d", got, want)
	}
}
