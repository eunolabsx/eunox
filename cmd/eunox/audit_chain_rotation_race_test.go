// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
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

// TestReadAuditChainOrExit_RotationOutranksTheReadError pins the ordering verifyOneTape
// documents and this helper has to share: a rotation PRODUCES read errors. The chain is
// opened lazily by name, so a retention prune unlinks a sibling the reader has not reached
// and a rotation leaves the base absent for the length of its pre-reopen fsync — both
// surface as an open failure inside consume. Reporting that verbatim tells the operator
// their log is missing or misconfigured and sends them to check paths and permissions,
// when the honest answer is that the chain moved and a re-run will succeed.
func TestReadAuditChainOrExit_RotationOutranksTheReadError(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(logPath, []byte(auditLine("deny", "tool", "write_file", nil)+"\n"), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}

	var code int
	stderr := captureStderr(t, func() {
		_, code, _ = readAuditChainOrExit("stats", logPath, statsUsageExit, func(io.Reader) (int, error) {
			rotateBaseUnder(t, logPath)
			return 0, errors.New(`opening audit log "` + logPath + `": no such file or directory`)
		})
	})

	if code != statsUsageExit {
		t.Errorf("exit code = %d, want %d", code, statsUsageExit)
	}
	if !strings.Contains(stderr, "re-run") {
		t.Errorf("stderr = %q, want the rotation reported: a read error a rotation caused must not be reported as a broken log", stderr)
	}
	if strings.Contains(stderr, "reading log:") {
		t.Errorf("stderr = %q, want the bracket's verdict INSTEAD of the raw read error, not as well", stderr)
	}
}

// TestReadAuditChainOrExit_ReadErrorOnAStableChainIsReported is the other side of that
// ordering: a genuine read failure over a chain that never moved must still reach the
// operator as itself, not be recast as a rotation.
func TestReadAuditChainOrExit_ReadErrorOnAStableChainIsReported(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(logPath, []byte(auditLine("allow", "tool", "read_file", nil)+"\n"), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}

	var code int
	stderr := captureStderr(t, func() {
		_, code, _ = readAuditChainOrExit("stats", logPath, statsUsageExit, func(io.Reader) (int, error) {
			return 0, errors.New("record 3 is not valid JSON")
		})
	})

	if code != statsUsageExit {
		t.Errorf("exit code = %d, want %d", code, statsUsageExit)
	}
	if !strings.Contains(stderr, "reading log: record 3 is not valid JSON") {
		t.Errorf("stderr = %q, want the read error reported verbatim", stderr)
	}
}

// rotateOnceAt rotates the chain the first time a line containing trigger is written. The
// writer is doctor's own output parameter, which is what makes the injection deterministic:
// the trigger line is emitted after the snapshot is taken and before the deferred re-check,
// i.e. exactly where a live proxy's rotation would land.
type rotateOnceAt struct {
	t       *testing.T
	out     *strings.Builder
	trigger string
	logPath string
	fired   bool
}

func (w *rotateOnceAt) Write(p []byte) (int, error) {
	n, err := w.out.Write(p)
	if !w.fired && strings.Contains(string(p), w.trigger) {
		w.fired = true
		rotateBaseUnder(w.t, w.logPath)
	}
	return n, err
}

// TestWriteDoctorAudit_CaveatsARacedChain covers the third live-chain reader. doctor lists
// the chain once and opens it lazily TWICE (the totals pass and the record tail), so a
// rotation landing in between reads a fresh, nearly-empty base in place of the sibling
// holding the newest records — and can leave the two passes describing different chains.
// doctor caveats rather than exiting (every other failure in the bundle is a printed line),
// but the count must not be presented as a fact: this is the artifact attached to the ticket
// that says the tape looks empty.
func TestWriteDoctorAudit_CaveatsARacedChain(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(logPath, []byte(auditLine("deny", "tool", "write_file", nil)+"\n"), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}

	var out strings.Builder
	writeDoctorAudit(&rotateOnceAt{t: t, out: &out, trigger: "log size:", logPath: logPath}, logPath, filepath.Join(dir, "audit.key"), 5)

	if !strings.Contains(out.String(), "NOTE:") || !strings.Contains(out.String(), "re-run") {
		t.Errorf("doctor output = %q, want a caveat naming the raced chain — a truncated total presented as a fact is what sends an operator looking for a proxy fault that never happened", out.String())
	}
}
