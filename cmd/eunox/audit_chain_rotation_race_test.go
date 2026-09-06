// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rotateBaseUnder performs what the sink's size-triggered rotation does to the chain, from
// the outside: the base — holding the newest up-to-maxBytes of records — is renamed to a
// sibling, and a fresh, empty base takes its name. Driven from inside the consume callback
// so the rotation lands strictly between the snapshot and the bracket's re-check, which is
// the window a live proxy's rotation lands in and the one a test cannot hit by racing.
func rotateBaseUnder(t *testing.T, logPath string) {
	t.Helper()
	sibling := logPath + ".00000000000000000001.20260101T000000.000000000Z"
	if err := os.Rename(logPath, sibling); err != nil {
		t.Fatalf("rename base to sibling: %v", err)
	}
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatalf("create fresh base: %v", err)
	}
}

// TestReadAuditChainOrExit_RotationMidReadIsNotSilent pins the bracket the reporting
// readers were missing. `stats` and `suggest` open the chain files LAZILY by name, so a
// rotation landing between the listing and the base's open leaves them reading the fresh,
// nearly-empty base while every record it held sits in a sibling the listing never saw.
// The result is not an error but a REPORT — a draft manifest missing the usage the operator
// is about to write policy from, or a denial histogram missing the denials the --audit
// banner sent them to read — and nothing in either output says so.
func TestReadAuditChainOrExit_RotationMidReadIsNotSilent(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(logPath, []byte(auditLine("deny", "tool", "write_file", nil)+"\n"), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}

	var (
		got  int
		code int
		done bool
	)
	stderr := captureStderr(t, func() {
		got, code, done = readAuditChainOrExit("stats", logPath, statsUsageExit, func(r io.Reader) (int, error) {
			n, err := io.Copy(io.Discard, r)
			rotateBaseUnder(t, logPath)
			return int(n), err
		})
	})

	if !done {
		t.Fatalf("a rotation inside the read must stop the caller, got done=false (code %d)", code)
	}
	if code != statsUsageExit {
		t.Errorf("exit code = %d, want %d: an inconclusive read is a read failure, never a findings code", code, statsUsageExit)
	}
	if got != 0 {
		t.Errorf("the consumed value = %d, want the zero value: a report assembled from a chain nobody could read whole must not reach the caller", got)
	}
	if !strings.Contains(stderr, "re-run") {
		t.Errorf("stderr = %q, want it to tell the operator to re-run", stderr)
	}
	if !strings.Contains(stderr, "eunox stats:") {
		t.Errorf("stderr = %q, want the reader's own provenance", stderr)
	}
}

// TestReadAuditChainOrExit_AppendDuringTheReadIsNotARotation is the other half, and the one
// that keeps the bracket usable: a proxy WRITING to the log while stats reads it is the
// normal case, not a race. The read certified a prefix of the chain — all a reader of a
// live log ever can — so appended records must not turn every report against a busy proxy
// into "re-run".
func TestReadAuditChainOrExit_AppendDuringTheReadIsNotARotation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(logPath, []byte(auditLine("allow", "tool", "read_file", nil)+"\n"), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}

	got, code, done := readAuditChainOrExit("stats", logPath, statsUsageExit, func(r io.Reader) (int, error) {
		n, err := io.Copy(io.Discard, r)
		f, oerr := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600)
		if oerr != nil {
			t.Fatalf("reopen log for append: %v", oerr)
		}
		if _, werr := f.WriteString(auditLine("deny", "tool", "write_file", nil) + "\n"); werr != nil {
			t.Fatalf("append record: %v", werr)
		}
		_ = f.Close()
		return int(n), err
	})

	if done {
		t.Fatalf("records appended during the read must not be reported as a rotation (exit %d)", code)
	}
	if got == 0 {
		t.Error("the consumed value must reach the caller on a clean read")
	}
}
