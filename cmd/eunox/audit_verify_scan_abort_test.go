// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/internal/audit"
)

// overCapLineBytes is a line no audit reader's scanner can hold: bufio raises ErrTooLong once
// the buffer reaches its ceiling with no newline in it, so the ceiling itself is already over
// cap and the extra byte is only belt-and-braces. Sourced from the constant rather than a
// second 4 MiB literal, so widening the window moves the fixture with it.
const overCapLineBytes = audit.ScanBufferBytes + 1

// appendOverCapLine appends one newline-terminated line the scanner cannot hold. That is the
// whole of the write an attacker needs to stop a verification pass short — no harder than the
// single stripped byte of the torn-tail case, and just as invisible to the rotation bracket
// (an append is not a chain change: see ChainSnapshot.CheckUnchanged).
//
// The payload and its terminator are written separately: concatenating them would copy the
// whole 4 MiB span a second time for the sake of one byte.
func appendOverCapLine(t *testing.T, logPath string) {
	t.Helper()
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()
	for _, s := range []string{strings.Repeat("x", overCapLineBytes), "\n"} {
		if _, err := f.WriteString(s); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
}

// TestCmdAuditVerify_ScanAbortNeverSuppressesAFinding is the torn-tail regression one branch
// down: a read error that aborts the scan must not discard the findings the pass had already
// PROVED.
//
// An over-cap line is exactly as appendable as the torn tail's one byte, and it produces no
// finding of its own — the scan just stops. Exiting "inconclusive — re-run" over a tamper
// classified before that stop would move it out of the exit-1 bucket a cron/CI gate watches
// permanently, since re-running a file nobody is truncating answers the same thing forever.
func TestCmdAuditVerify_ScanAbortNeverSuppressesAFinding(t *testing.T) {
	dir := t.TempDir()
	logPath, keyPath := writeTapeFor(t, dir, "tape", "", "task-1", "a", "b", "c", "d")
	deleteInteriorRecord(t, logPath)
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
	// The tallies are what a redirected report and a SIEM ingest, so the partial coverage has
	// to be legible there and not only on stderr.
	if !strings.Contains(stdout, "certified a PREFIX") {
		t.Fatalf("stdout must mark the tallies as covering a prefix only:\n%s", stdout)
	}
	if !strings.Contains(stderr, "was not read") {
		t.Fatalf("the operator must be told the pass covered a prefix only:\n%s", stderr)
	}
}

// TestCmdAuditVerify_ScanAbortReportsOnlyThePrefixItRead pins what the tallies mean when the
// abort lands MID-tape rather than after the last record — the shape an attacker uses, since
// it blinds the pass to everything written after the tamper. The counts must describe the
// prefix, and must not be presented as a verdict over the whole tape.
func TestCmdAuditVerify_ScanAbortReportsOnlyThePrefixItRead(t *testing.T) {
	dir := t.TempDir()
	logPath, keyPath := writeTapeFor(t, dir, "tape", "", "task-1", "a", "b", "c", "d", "e", "f")
	deleteInteriorRecord(t, logPath)

	// Rebuild the tape with the over-cap line in the MIDDLE: the tamper is behind it, the
	// remaining records are past it and are never read.
	lines := tapeLines(t, logPath)
	if len(lines) != 5 {
		t.Fatalf("expected 5 records after the deletion, got %d", len(lines))
	}
	head := strings.Join(lines[:3], "\n") + "\n"
	if err := os.WriteFile(logPath, []byte(head), 0o600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	appendOverCapLine(t, logPath)
	tail, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := tail.WriteString(strings.Join(lines[3:], "\n") + "\n"); err != nil {
		t.Fatalf("append tail: %v", err)
	}
	if err := tail.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	code, stdout, stderr := runAuditVerifyCapturing(t, "--audit-log", logPath, "--audit-key-path", keyPath)
	if code != auditVerifyFindingsExit {
		t.Fatalf("a tamper classified before the abort must exit %d, got %d\nstdout:\n%s\nstderr:\n%s",
			auditVerifyFindingsExit, code, stdout, stderr)
	}
	// Three records precede the over-cap line; the two past it are never reached, so a tally
	// of 5 would mean the arm reported over records the scan never read.
	if !strings.Contains(stdout, "Checked 3 record(s)") {
		t.Fatalf("the tallies must cover the prefix the scan read, not the whole tape:\n%s", stdout)
	}
	if !strings.Contains(stdout, "certified a PREFIX") {
		t.Fatalf("the prefix note must sit with the tallies on stdout:\n%s", stdout)
	}
}

// TestCmdAuditVerify_ScanAbortBeforeTheTamperReachesNoVerdict is the RESIDUAL this exit-code
// ranking cannot close, pinned so it is a known limit rather than a surprise: with the
// over-cap line placed BEFORE the tampered record, the scan stops over a clean prefix and the
// tamper is never classified at all. Nothing was proved, so 2 is the only honest answer.
//
// Closing it needs the scan to resynchronize past an over-cap line (which is provably not a
// record this writer emits) and classify it, rather than abort — an internal/audit change
// that would also give stats, suggest and doctor a verdict past one. When that lands, this
// test should assert the findings exit instead.
func TestCmdAuditVerify_ScanAbortBeforeTheTamperReachesNoVerdict(t *testing.T) {
	dir := t.TempDir()
	logPath, keyPath := writeTapeFor(t, dir, "tape", "", "task-1", "a", "b", "c", "d")
	deleteInteriorRecord(t, logPath)

	lines := tapeLines(t, logPath)
	if err := os.WriteFile(logPath, []byte(lines[0]+"\n"), 0o600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	appendOverCapLine(t, logPath)
	tail, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := tail.WriteString(strings.Join(lines[1:], "\n") + "\n"); err != nil {
		t.Fatalf("append tail: %v", err)
	}
	if err := tail.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	code, stdout, stderr := runAuditVerifyCapturing(t, "--audit-log", logPath, "--audit-key-path", keyPath)
	if code != auditVerifyUsageExit {
		t.Fatalf("a scan that stopped over a clean prefix proves nothing and must exit %d, got %d\nstdout:\n%s\nstderr:\n%s",
			auditVerifyUsageExit, code, stdout, stderr)
	}
	if strings.Contains(stdout, "CHAIN BREAK") {
		t.Fatalf("the tamper sits past the abort and cannot have been classified:\n%s", stdout)
	}
}

// TestCmdAuditVerify_ScanAbortOnACleanTapeIsInconclusive is the other arm, and the reason the
// ranking is scoped to a proved finding: with nothing classified against the part that WAS
// read, an aborted scan has no verdict to give and must not manufacture one. Its message is
// the shared no-verdict one, so a runbook greps one phrase for every inconclusive cause.
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
	if !strings.Contains(stderr, "no verdict was reached") {
		t.Fatalf("expected the shared no-verdict wording:\n%s", stderr)
	}
	if strings.Contains(stdout, "certified a PREFIX") {
		t.Fatalf("a pass that proved nothing must not present prefix tallies as findings:\n%s", stdout)
	}
}

// TestCmdAuditVerify_ProvenFindingOutranksAnUnreadableTape_EitherOrder is the cross-tape half
// of the ranking, driven in BOTH orders because ranking on what came first is the bug: the
// loop used to return the first stopping tape's code, so a byte stripped from the tape named
// first suppressed a proved tamper on the tape named second — permanently, and with no access
// to the tampered tape at all.
func TestCmdAuditVerify_ProvenFindingOutranksAnUnreadableTape_EitherOrder(t *testing.T) {
	for _, tc := range []struct {
		name          string
		tamperedFirst bool
	}{
		{"tampered tape named first", true},
		{"tampered tape named second", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tampered, tamperedKey := writeTapeFor(t, dir, "one", "gateway", "task-1", "a", "b", "c", "d")
			clean, cleanKey := writeTapeFor(t, dir, "two", "sidecar", "task-1", "d", "e")

			deleteInteriorRecord(t, tampered)
			// The other tape is otherwise clean: its torn tail is a no-verdict stop, not a
			// finding, so without the ranking rule it is the code the whole run reports.
			stripTrailingNewline(t, clean)

			args := []string{
				"--audit-log", tampered, "--audit-key-path", tamperedKey,
				"--audit-log", clean, "--audit-key-path", cleanKey,
			}
			if !tc.tamperedFirst {
				args = append(append([]string{}, args[4:]...), args[:4]...)
			}
			code, stdout, stderr := runAuditVerifyCapturing(t, args...)

			if code != auditVerifyFindingsExit {
				t.Fatalf("a proved tamper must outrank a sibling's missing verdict in either order (exit %d), got %d\nstdout:\n%s\nstderr:\n%s",
					auditVerifyFindingsExit, code, stdout, stderr)
			}
			if !strings.Contains(stdout, "CHAIN BREAK") {
				t.Fatalf("the tampered tape must be verified whichever position it is named in:\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
			}
			// Every tape is accounted for on stdout: the exit code names neither which tape
			// broke nor which one the run could not speak for.
			if !strings.Contains(stdout, "verdict: FAIL") {
				t.Fatalf("the failing tape needs its own verdict line:\n%s", stdout)
			}
			if !strings.Contains(stdout, "verdict: NO VERDICT") {
				t.Fatalf("the tape the run could not speak for needs one too:\n%s", stdout)
			}
			if !strings.Contains(stderr, "no verdict was reached") {
				t.Fatalf("the missing verdict must still be reported:\n%s", stderr)
			}
		})
	}
}

// TestCmdAuditVerify_SequenceWithheldWhenATapeWasNotFullyRead: the join header tells its
// reader that a record missing from a tape means that enforcement point never handled the
// call. Over a tape read only to a scan abort that is false, and the table cannot carry the
// correction — so the sequence is withheld and the tapes are named.
func TestCmdAuditVerify_SequenceWithheldWhenATapeWasNotFullyRead(t *testing.T) {
	dir := t.TempDir()
	logA, keyA := writeTapeFor(t, dir, "edge", "edge-1", "task-A", "read_file")
	logB, keyB := writeTapeFor(t, dir, "core", "core-1", "task-A", "wire_transfer", "settle", "post", "reconcile")
	deleteInteriorRecord(t, logB)
	appendOverCapLine(t, logB)

	code, stdout, stderr := runAuditVerifyCapturing(t,
		"--audit-log", logA, "--audit-key-path", keyA,
		"--audit-log", logB, "--audit-key-path", keyB,
		"--task-id", "task-A")

	if code != auditVerifyFindingsExit {
		t.Fatalf("tape B's proved tamper must report exit %d, got %d\nstdout:\n%s\nstderr:\n%s",
			auditVerifyFindingsExit, code, stdout, stderr)
	}
	if strings.Contains(stdout, "Sequence for task_id=task-A: 1 record") {
		t.Fatalf("no sequence may be assembled from a partly-read tape:\n%s", stdout)
	}
	if !strings.Contains(stdout, "NOT printed") {
		t.Fatalf("the withheld sequence must say so rather than being silently omitted:\n%s", stdout)
	}
	if !strings.Contains(stdout, logB) {
		t.Fatalf("the withholding note must name the tape responsible:\n%s", stdout)
	}
}
