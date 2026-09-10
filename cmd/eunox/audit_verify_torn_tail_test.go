// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stripTrailingNewline removes the log's single terminating byte — the whole of the
// "half-written record" an attacker can also simply append.
func stripTrailingNewline(t *testing.T, logPath string) {
	t.Helper()
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if err := os.WriteFile(logPath, raw[:len(raw)-1], 0o600); err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

// deleteInteriorRecord removes the second record, leaving BOTH proofs an interior deletion
// produces — a prev_hmac mismatch and a seq gap — well before the tape's final line, so
// whatever a test then does to that line cannot be what the finding rests on. Shared with
// the scan-abort tests: the two files assert one rule (a finding outranks a missing verdict)
// over the two writes that can withhold a verdict, against the same tampered fixture.
func deleteInteriorRecord(t *testing.T, logPath string) {
	t.Helper()
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) < 3 {
		t.Fatalf("expected at least 3 records to delete an interior one, got %d", len(lines))
	}
	kept := append([]string{lines[0]}, lines[2:]...)
	if err := os.WriteFile(logPath, []byte(strings.Join(kept, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
}

// TestCmdAuditVerify_TornTailNeverSuppressesAFinding is the regression for the way the
// no-verdict exit can be turned into a tamper-suppression primitive.
//
// Exit 1 is reserved for a log that fails verification so a cron/CI job can gate on it. A
// torn final line is ONE byte an attacker with write access can add or remove, and taking
// the inconclusive exit on it would move any finding out of that bucket permanently — the
// suggested re-run answers the same thing forever on a file nobody is appending to. So the
// findings are released and the verdict stands; only what lies past the fragment is unread.
func TestCmdAuditVerify_TornTailNeverSuppressesAFinding(t *testing.T) {
	dir := t.TempDir()
	logPath, keyPath := writeTapeFor(t, dir, "tape", "", "task-1", "a", "b", "c", "d")

	// A prev_hmac mismatch AND a seq gap, both proven well before the final line the strip
	// below turns into a fragment.
	deleteInteriorRecord(t, logPath)

	// Control: the tamper is reported, exit 1.
	code, stdout, _ := runAuditVerifyCapturing(t, "--audit-log", logPath, "--audit-key-path", keyPath)
	if code != auditVerifyFindingsExit {
		t.Fatalf("a tampered chain must exit %d (findings), got %d\n%s", auditVerifyFindingsExit, code, stdout)
	}
	if !strings.Contains(stdout, "CHAIN BREAK") {
		t.Fatalf("expected the chain-break finding on stdout:\n%s", stdout)
	}

	// The same tape with its trailing newline stripped must still report the same finding
	// and the same exit code.
	stripTrailingNewline(t, logPath)
	code, stdout, stderr := runAuditVerifyCapturing(t, "--audit-log", logPath, "--audit-key-path", keyPath)
	if code != 1 {
		t.Fatalf("one stripped newline must not move a proven tamper out of the exit-1 bucket, got %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "CHAIN BREAK") {
		t.Fatalf("the finding must still be printed:\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	if !strings.Contains(stderr, "was not read") {
		t.Fatalf("the operator must be told the pass covered a prefix only:\n%s", stderr)
	}
}

// TestCmdAuditVerify_TornTailOnACleanTapeIsInconclusive is the other arm: with nothing
// proven against the complete prefix, there is no verdict to give — the pass certified a
// prefix and cannot speak for what follows.
func TestCmdAuditVerify_TornTailOnACleanTapeIsInconclusive(t *testing.T) {
	dir := t.TempDir()
	logPath, keyPath := writeTapeFor(t, dir, "tape", "", "task-1", "a", "b")

	code, _, _ := runAuditVerifyCapturing(t, "--audit-log", logPath, "--audit-key-path", keyPath)
	if code != 0 {
		t.Fatalf("precondition: the intact tape must verify clean, got %d", code)
	}

	stripTrailingNewline(t, logPath)
	code, _, stderr := runAuditVerifyCapturing(t, "--audit-log", logPath, "--audit-key-path", keyPath)
	if code != auditVerifyUsageExit {
		t.Fatalf("a torn tail with no finding is inconclusive (exit %d), got %d\n%s", auditVerifyUsageExit, code, stderr)
	}
	if !strings.Contains(stderr, "no verdict was reached") {
		t.Fatalf("expected the no-verdict wording:\n%s", stderr)
	}
}

// TestCmdAuditVerify_TornTailDoesNotAbortSiblingTapes: one tape's torn tail used to return a
// non-zero code from verifyOneTape, which runAuditVerify propagates immediately — so a
// stripped byte on tape 1 left every later enforcement point's tape unverified.
func TestCmdAuditVerify_TornTailDoesNotAbortSiblingTapes(t *testing.T) {
	dir := t.TempDir()
	log1, key1 := writeTapeFor(t, dir, "one", "gateway", "task-1", "a", "b", "c", "d")
	log2, key2 := writeTapeFor(t, dir, "two", "sidecar", "task-1", "d", "e")

	// Tape 1 carries a proven tamper (an interior record deleted) AND a torn tail; tape 2 is
	// clean.
	deleteInteriorRecord(t, log1)
	stripTrailingNewline(t, log1)

	code, stdout, stderr := runAuditVerifyCapturing(t,
		"--audit-log", log1, "--audit-key-path", key1,
		"--audit-log", log2, "--audit-key-path", key2)

	if code != auditVerifyFindingsExit {
		t.Fatalf("a proven tamper on tape 1 must still exit %d, got %d\nstdout:\n%s\nstderr:\n%s",
			auditVerifyFindingsExit, code, stdout, stderr)
	}
	if !strings.Contains(stdout, filepath.Base(log2)) {
		t.Fatalf("tape 2 must still be verified rather than abandoned:\n%s", stdout)
	}
}
