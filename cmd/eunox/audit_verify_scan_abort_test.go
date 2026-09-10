// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"strings"
	"testing"
)

// overCapLineBytes is a line no audit reader's scanner can hold: internal/audit sizes that
// buffer at 4 MiB (auditScanBufferBytes, unexported from here), and one byte past it aborts
// the scan with bufio.ErrTooLong and NO per-record finding for the line itself. Every test
// below asserts the abort really happened, so a widened window fails them loudly rather than
// letting them pass over a line that now fits.
const overCapLineBytes = (4 << 20) + 1

// appendOverCapLine appends one newline-terminated line the scanner cannot hold. That is the
// whole of the write an attacker needs to stop a verification pass short — no harder than the
// single stripped byte of the torn-tail case, and just as invisible to the rotation bracket
// (an append is not a chain change: see ChainSnapshot.CheckUnchanged).
func appendOverCapLine(t *testing.T, logPath string) {
	t.Helper()
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := f.WriteString(strings.Repeat("x", overCapLineBytes) + "\n"); err != nil {
		_ = f.Close()
		t.Fatalf("append: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestCmdAuditVerify_ScanAbortNeverSuppressesAFinding is the torn-tail regression one branch
// down: a read error that aborts the scan must not discard the findings the pass had already
// PROVEN.
//
// An over-cap line is exactly as appendable as the torn tail's one byte, and it produces no
// finding of its own — the scan just stops. Exiting "inconclusive — re-run" over a tamper
// classified before that stop would move it out of the exit-1 bucket a cron/CI gate watches
// permanently, since re-running a file nobody is truncating answers the same thing forever.
func TestCmdAuditVerify_ScanAbortNeverSuppressesAFinding(t *testing.T) {
	dir := t.TempDir()
	logPath, keyPath := writeTapeFor(t, dir, "tape", "", "task-1", "a", "b", "c", "d")
	deleteInteriorRecord(t, logPath)

	// Control: the tamper alone is reported, exit 1.
	code, stdout, _ := runAuditVerifyCapturing(t, "--audit-log", logPath, "--audit-key-path", keyPath)
	if code != auditVerifyFindingsExit {
		t.Fatalf("a tampered chain must exit %d (findings), got %d\n%s", auditVerifyFindingsExit, code, stdout)
	}
	if !strings.Contains(stdout, "CHAIN BREAK") {
		t.Fatalf("expected the chain-break finding on stdout:\n%s", stdout)
	}

	appendOverCapLine(t, logPath)
	code, stdout, stderr := runAuditVerifyCapturing(t, "--audit-log", logPath, "--audit-key-path", keyPath)
	if code != auditVerifyFindingsExit {
		t.Fatalf("one appended over-cap line must not move a proven tamper out of the exit-%d bucket, got %d\nstdout:\n%s\nstderr:\n%s",
			auditVerifyFindingsExit, code, stdout, stderr)
	}
	if !strings.Contains(stdout, "CHAIN BREAK") {
		t.Fatalf("the finding must still be printed:\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	// Pins that the exit code above came from the SCAN ABORT and not from a fixture whose
	// oversized line merely read as another invalid record.
	if !strings.Contains(stderr, "reading log") {
		t.Fatalf("the read failure must be reported (a line that now fits the scan window would not abort it):\n%s", stderr)
	}
	if !strings.Contains(stderr, "nothing past it was read") {
		t.Fatalf("the operator must be told the pass covered a prefix only:\n%s", stderr)
	}
}

// TestCmdAuditVerify_ScanAbortOnACleanTapeIsInconclusive is the other arm, and the reason the
// fix above is scoped to a proven finding: with nothing classified against the part that WAS
// read, an aborted scan has no verdict to give and must not manufacture one.
func TestCmdAuditVerify_ScanAbortOnACleanTapeIsInconclusive(t *testing.T) {
	dir := t.TempDir()
	logPath, keyPath := writeTapeFor(t, dir, "tape", "", "task-1", "a", "b")

	code, _, _ := runAuditVerifyCapturing(t, "--audit-log", logPath, "--audit-key-path", keyPath)
	if code != 0 {
		t.Fatalf("precondition: the intact tape must verify clean, got %d", code)
	}

	appendOverCapLine(t, logPath)
	code, stdout, stderr := runAuditVerifyCapturing(t, "--audit-log", logPath, "--audit-key-path", keyPath)
	if code != auditVerifyUsageExit {
		t.Fatalf("an aborted scan with no finding is inconclusive (exit %d), got %d\nstdout:\n%s\nstderr:\n%s",
			auditVerifyUsageExit, code, stdout, stderr)
	}
	if !strings.Contains(stderr, "reading log") {
		t.Fatalf("expected the read failure to be reported:\n%s", stderr)
	}
}

// TestCmdAuditVerify_ProvenFindingOutranksALaterTapeWithNoVerdict is the cross-tape half of
// the same inversion: the loop returned the stopping tape's code unconditionally, so a
// verdict an EARLIER tape had already proved was reported as "inconclusive — re-run".
//
// The evasion is the same shape and needs no access to the tape carrying the tamper: strip
// one byte from a sibling nobody has tampered with (or unlink its key, or append an over-cap
// line to it) and the run that found the tamper stops answering 1 forever.
func TestCmdAuditVerify_ProvenFindingOutranksALaterTapeWithNoVerdict(t *testing.T) {
	dir := t.TempDir()
	log1, key1 := writeTapeFor(t, dir, "one", "gateway", "task-1", "a", "b", "c", "d")
	log2, key2 := writeTapeFor(t, dir, "two", "sidecar", "task-1", "d", "e")

	deleteInteriorRecord(t, log1)
	// Tape 2 is otherwise clean: its torn tail is a no-verdict stop, not a finding, so
	// without the ranking rule it is the code the whole run reports.
	stripTrailingNewline(t, log2)

	code, stdout, stderr := runAuditVerifyCapturing(t,
		"--audit-log", log1, "--audit-key-path", key1,
		"--audit-log", log2, "--audit-key-path", key2)

	if code != auditVerifyFindingsExit {
		t.Fatalf("tape 1's proven tamper must outrank tape 2's missing verdict (exit %d), got %d\nstdout:\n%s\nstderr:\n%s",
			auditVerifyFindingsExit, code, stdout, stderr)
	}
	if !strings.Contains(stdout, "CHAIN BREAK") {
		t.Fatalf("tape 1's finding must be printed:\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	// The stop itself is unchanged — the operator is still told tape 2 reached no verdict,
	// which is what tells them the run covered less than they asked for.
	if !strings.Contains(stderr, "no verdict was reached") {
		t.Fatalf("tape 2's missing verdict must still be reported:\n%s", stderr)
	}
}
