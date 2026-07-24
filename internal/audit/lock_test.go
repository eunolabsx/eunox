// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package audit

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestAuditSink_SecondOpenSamePath_FailsClosed verifies that two Sinks cannot
// write the same audit log path concurrently: the second Open fails while the
// first holds the path lock, so the tamper-evident HMAC chain cannot fork into
// two independently-sequenced writers. After the first closes, a reopen succeeds
// and the resulting single-writer chain verifies.
func TestAuditSink_SecondOpenSamePath_FailsClosed(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")

	s1, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}

	// A second writer against the same path must be refused while s1 holds it.
	if s2, err := Open(logPath, keyPath, 0, 0); err == nil {
		_ = s2.Close()
		t.Fatal("second Open on the same audit path must fail while the first holds the lock")
	}

	// Write through the first sink and close it, releasing the lock.
	s1.RecordAllow(context.Background(), "sess", "tool:read", "tools/call", nil, nil, false, nil, nil)
	if err := s1.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}

	// Reopening after the lock is released must succeed, and the resumed chain
	// must verify (a single writer never forked it).
	s3, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("reopen after Close: %v", err)
	}
	s3.RecordAllow(context.Background(), "sess", "tool:read", "tools/call", nil, nil, false, nil, nil)
	if err := s3.Close(); err != nil {
		t.Fatalf("third Close: %v", err)
	}

	var sb strings.Builder
	res, err := VerifyLog(bytes.NewReader(bytes.Join(logLines(t, logPath), []byte("\n"))),
		verifierFor(t, keyPath), "", time.Time{}, &sb)
	if err != nil {
		t.Fatalf("VerifyLog: %v", err)
	}
	if !res.OK() {
		t.Errorf("single-writer chain must verify after sequential open/close; output:\n%s\nresult: %+v", sb.String(), res)
	}
}
