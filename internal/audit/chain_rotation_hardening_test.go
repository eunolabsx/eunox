// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/internal/config"
)

// TestInterpretAuditTail_WhitespaceOnlyFinalLine is the whitespace-tail unit regression:
// interpretAuditTail must return the last REAL record, not "", when the tail ends in a
// line made only of whitespace. readLastAuditLine reserves ("", nil) for a genuinely
// empty log; returning it for a non-empty log makes Open restart the chain (reissuing
// seqs) or rewind to a sibling.
func TestInterpretAuditTail_WhitespaceOnlyFinalLine(t *testing.T) {
	rec := `{"seq":2,"activity_name":"allow"}`
	prev := `{"seq":1,"activity_name":"allow"}`
	for _, tc := range []struct {
		name, tail, want string
	}{
		{"trailing spaces + newline", prev + "\n" + rec + "\n   \n", rec},
		{"trailing spaces no newline", prev + "\n" + rec + "\n   ", rec},
		{"trailing tab line", prev + "\n" + rec + "\n\t\n", rec},
		{"trailing CRLF blank", prev + "\n" + rec + "\n\r\n", rec},
		{"blank line only (baseline)", prev + "\n" + rec + "\n\n", rec},
		{"clean tail (baseline)", prev + "\n" + rec + "\n", rec},
		{"all whitespace is empty", "   \n\t\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := []byte(tc.tail)
			got, err := interpretAuditTail(buf, len(buf), nil, int64(len(buf)), 0)
			if err != nil {
				t.Fatalf("interpretAuditTail error: %v", err)
			}
			if got != tc.want {
				t.Errorf("interpretAuditTail = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestOpenResumesPastWhitespaceTail is the whitespace-tail end-to-end regression: a whitespace
// line appended to a closed log (an editor save, an `echo " " >>`) must NOT make Open
// restart the chain from genesis. The resumed seq must continue from the last real record.
func TestOpenResumesPastWhitespaceTail(t *testing.T) {
	dir := t.TempDir()
	logPath, keyPath := writeChainLog(t, dir, "a", "b", "c") // seqs 1,2,3
	const wantSeq = 3

	// Append a whitespace-only line, as a non-clean save or a stray echo would.
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open for append: %v", err)
	}
	if _, err := f.WriteString("   \n"); err != nil {
		t.Fatalf("append whitespace: %v", err)
	}
	_ = f.Close()

	sink, err := Open(logPath, keyPath, 0, 0)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = sink.Close() }()
	if sink.seq != wantSeq {
		t.Fatalf("resumed seq = %d, want %d (a whitespace tail must not restart the chain)", sink.seq, wantSeq)
	}
	// No chain_resume_failed / parse-failure marker should have been written: the tail
	// resolved cleanly to record 3.
	for _, line := range logLines(t, logPath) {
		if bytes.Contains(line, []byte("chain_resume_failed")) || bytes.Contains(line, []byte("tail_parse_failure")) {
			t.Fatalf("unexpected integrity marker after a benign whitespace tail: %s", line)
		}
	}
}

// TestHighestSeqAcrossChain is the cross-chain-seed mechanism: the cross-chain seed must fold in
// rotated siblings, not only the base — after a rotation the base holds the highest seqs
// in few bytes while a sibling may carry an even higher one, so scanning the base alone
// under-estimates and reissues seqs.
func TestHighestSeqAcrossChain(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	// Base carries a low seq; a rotated sibling carries a much higher one.
	if err := os.WriteFile(logPath, []byte(`{"seq":5}`+"\n"), 0o600); err != nil {
		t.Fatalf("write base: %v", err)
	}
	sib := logPath + ".00000000000000000001.20260101T000000.000000000Z"
	if err := os.WriteFile(sib, []byte(`{"seq":900}`+"\n"+`{"seq":901}`+"\n"), 0o600); err != nil {
		t.Fatalf("write sibling: %v", err)
	}
	got, ok, complete := highestSeqAcrossChain(logPath)
	if !ok || got != 901 {
		t.Fatalf("highestSeqAcrossChain = (%d,%v), want (901,true) — the sibling's max must win over the base", got, ok)
	}
	if !complete {
		t.Fatal("highestSeqAcrossChain must report complete=true when the log directory listed cleanly")
	}
}

// TestOpenFailsClosedOnOversizedOrphanTail is the oversized-orphan regression: a trailing partial
// write larger than the scan window with no record boundary inside it cannot be safely
// truncated, so Open must fail CLOSED rather than leave it and let the parse-failure
// marker O_APPEND onto (fuse with) the multi-megabyte orphan.
func TestOpenFailsClosedOnOversizedOrphanTail(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, "audit.key")
	// A newline-less blob larger than the scan window: no record boundary is locatable.
	blob := bytes.Repeat([]byte("x"), auditScanBufferBytes+1024)
	if err := os.WriteFile(logPath, blob, 0o600); err != nil {
		t.Fatalf("write oversized orphan: %v", err)
	}
	sink, err := Open(logPath, keyPath, 0, 0)
	if err == nil {
		_ = sink.Close()
		t.Fatal("Open must fail closed on an oversized newline-less orphan tail, got nil error")
	}
	if !strings.Contains(err.Error(), "partial audit tail") {
		t.Errorf("error = %v, want it to name the unrecoverable partial tail", err)
	}
}

// TestRotatedPath_OrdinalUncertainUnreadableDir_Defers is the stale-low-ordinal regression: when
// the rotation-ordinal seed is uncertain AND the sibling directory still cannot be read,
// rotatedPath must return an error (rotate() then backs off) rather than fall through and
// stamp a stale-low ordinal 1 that mis-orders retention and cross-file verification.
func TestRotatedPath_OrdinalUncertainUnreadableDir_Defers(t *testing.T) {
	dir := t.TempDir()
	// Point logPath at a subdirectory that does NOT exist, so maxRotatedOrdinal's
	// os.ReadDir fails deterministically even as root (a missing dir, not a perm bit).
	logPath := filepath.Join(dir, "gone", "audit.jsonl")
	s := &Sink{logPath: logPath, ordinalSeedUncertain: true}
	if _, err := s.rotatedPath(); err == nil {
		t.Fatal("rotatedPath must return an error when the ordinal seed is uncertain and the sibling dir is unreadable")
	}
	// The uncertain flag must remain set so a later rotation retries the seed.
	if !s.ordinalSeedUncertain {
		t.Error("ordinalSeedUncertain must stay set after a deferred rotation")
	}
	// The ordinal must NOT have advanced to a stale-low 1.
	if s.rotateOrdinal != 0 {
		t.Errorf("rotateOrdinal = %d, want 0 (no stale-low stamp on a deferred rotation)", s.rotateOrdinal)
	}
}

// TestOpenGuardedAppend_RefusesSymlink is the reopen symlink-guard regression: the post-rotation
// reopen helper must refuse a symlink at the log path (Lstat-based, so it holds even as
// root) rather than follow it and redirect the tamper-evident tape.
func TestOpenGuardedAppend_RefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("attacker\n"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "audit.jsonl")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	f, err := openGuardedAppend(link)
	if err == nil {
		_ = f.Close()
		t.Fatal("openGuardedAppend must refuse a symlinked log path")
	}
	// The shared guard names the symlink specifically rather than lumping it in with
	// other non-regular files: an operator reading this needs to know a link is present,
	// not just that the path is unusable.
	if !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("error = %v, want it to name the symbolic link", err)
	}
	// A plain regular path still opens.
	plain := filepath.Join(dir, "plain.jsonl")
	g, err := openGuardedAppend(plain)
	if err != nil {
		t.Fatalf("openGuardedAppend must open a regular path: %v", err)
	}
	_ = g.Close()
}

// TestNewestRotatedSiblingWithTail_SkipsEmptyReturnsNewest confirms the unreadable-newer-sibling fix
// preserves the existing empty-sibling skip: an empty newest sibling is skipped (it holds
// no seqs) and the newest NON-empty one is returned, with unreadableNewer=false.
func TestNewestRotatedSiblingWithTail_SkipsEmptyReturnsNewest(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	older := logPath + ".00000000000000000001.20260101T000000.000000000Z"
	newerEmpty := logPath + ".00000000000000000002.20260101T000001.000000000Z"
	if err := os.WriteFile(older, []byte(`{"seq":1}`+"\n"), 0o600); err != nil {
		t.Fatalf("write older: %v", err)
	}
	if err := os.WriteFile(newerEmpty, nil, 0o600); err != nil {
		t.Fatalf("write empty newer: %v", err)
	}
	sib, line, unreadableNewer := newestRotatedSiblingWithTail(logPath)
	if unreadableNewer {
		t.Fatal("an EMPTY newer sibling must be skipped, not treated as unreadable")
	}
	if sib != older || !strings.Contains(line, `"seq":1`) {
		t.Errorf("got sibling=%q line=%q, want the older non-empty sibling", sib, line)
	}
}

// TestHighestSeqAcrossChain_FoldsUnreadableSiblingAdditively pins the fix for the cross-file
// under-seed: a file that cannot be read contributes its BYTE SIZE folded ADDITIVELY onto
// the highest seq read elsewhere, never as a per-file max. Taking a per-file max let one
// rotated sibling's byte count stand in for a global seq, so after enough rotations (when
// the monotonic chain seq exceeds any single file's byte size) the seed fell BELOW the true
// max and reissued seqs — a tamper-shaped duplicate-seq cascade. The unreadable file is
// simulated with an over-cap first line (root-safe, unlike a 0200 permission bit).
func TestHighestSeqAcrossChain_FoldsUnreadableSiblingAdditively(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(logPath, []byte(`{"seq":5}`+"\n"), 0o600); err != nil {
		t.Fatalf("write base: %v", err)
	}
	const bufCap = 4096
	sib := logPath + ".00000000000000000001.20260101T000000.000000000Z"
	// An over-cap first line aborts the scan (bufio.ErrTooLong), so the sibling reports its
	// byte size as an unread over-estimate rather than a parsed seq.
	blob := append(bytes.Repeat([]byte("a"), bufCap+10), '\n')
	if err := os.WriteFile(sib, blob, 0o600); err != nil {
		t.Fatalf("write unreadable sibling: %v", err)
	}
	info, err := os.Stat(sib)
	if err != nil {
		t.Fatalf("stat sibling: %v", err)
	}
	sibSize := uint64(info.Size())

	got, ok, _ := highestSeqAcrossChainCapped(logPath, bufCap)
	if !ok {
		t.Fatal("highestSeqAcrossChainCapped must report ok=true when a seq or unread bytes exist")
	}
	if want := satAddU64(5, sibSize); got != want {
		t.Fatalf("highestSeqAcrossChainCapped = %d, want %d (highest read seq 5 + %d unread sibling bytes, folded additively)", got, want, sibSize)
	}
	// The additive fold must EXCEED the unreadable sibling's own byte size: a per-file max
	// would return just sibSize and, when that file holds the chain's true-max seqs in few
	// bytes, under-seed below them.
	if got <= sibSize {
		t.Fatalf("seed %d must exceed the unread sibling's byte size %d (additive fold, not per-file max)", got, sibSize)
	}
}

// TestNewestRotatedSiblingWithTail_UnlistableDirFailsClosed pins the fix for a silent
// genesis restart: when the log DIRECTORY cannot be listed (distinct from a single sibling
// FILE being unreadable), the resume must fail closed (unreadableNewer=true) so the caller
// seeds past the on-disk max and writes a chain_resume_failed marker, rather than read the
// unlistable directory as "no siblings" and rewind to genesis with no marker. A
// genuinely-absent directory is the fresh-install case and must still pass through.
func TestNewestRotatedSiblingWithTail_UnlistableDirFailsClosed(t *testing.T) {
	dir := t.TempDir()
	// Make the log's PARENT a regular file, so os.ReadDir fails with ENOTDIR — a non-NotExist
	// listing error that reproduces "dir exists but cannot be listed" even as root.
	notDir := filepath.Join(dir, "notadir")
	if err := os.WriteFile(notDir, []byte("x"), 0o600); err != nil {
		t.Fatalf("write not-a-dir: %v", err)
	}
	if _, _, unreadableNewer := newestRotatedSiblingWithTail(filepath.Join(notDir, "audit.jsonl")); !unreadableNewer {
		t.Fatal("an unlistable log directory must fail closed (unreadableNewer=true), not be read as no-siblings")
	}
	// A not-yet-created directory is the fresh-install case: pass through, do not fail closed.
	if _, _, unreadableNewer := newestRotatedSiblingWithTail(filepath.Join(dir, "gone", "audit.jsonl")); unreadableNewer {
		t.Fatal("a not-yet-created log directory must pass through (fresh install), not fail closed")
	}
}

// TestOpenGuardedAppend_RefusesUnstattablePath pins the fail-closed fix for the reopen
// guard: a path that cannot be Lstat'd for a reason OTHER than genuine absence (here
// ENOTDIR, from a parent that is a regular file — reproducible as root) must be refused, not
// fall through to os.OpenFile, which follows a symlink the guard could not classify. Gating
// the refusal on "stat succeeded" would silently skip the check on a stat fault (fail-open).
func TestOpenGuardedAppend_RefusesUnstattablePath(t *testing.T) {
	dir := t.TempDir()
	notDir := filepath.Join(dir, "file")
	if err := os.WriteFile(notDir, []byte("x"), 0o600); err != nil {
		t.Fatalf("write not-a-dir: %v", err)
	}
	if f, err := openGuardedAppend(filepath.Join(notDir, "audit.jsonl")); err == nil {
		_ = f.Close()
		t.Fatal("openGuardedAppend must refuse a path it cannot Lstat (a non-NotExist error), failing closed")
	}
}

// TestOpenNoFollow_RefusesSymlinkWithoutTheLstatGuard pins the defense-in-depth half of
// the symlink refusal: the config.OpenNoFollow flag every audit-log open OR-s in must make the
// KERNEL reject a final-component symlink, independently of refuseNonRegular's Lstat.
// That is what closes the Lstat->OpenFile TOCTOU — a symlink planted between the check
// and the open would otherwise be followed, redirecting the tamper-evident tape and
// dropping the live log out of audit-verify's IsRegular() chain scan.
//
// The Lstat guard is deliberately bypassed here (the raw os.OpenFile is what
// openAndPrepareLog and openGuardedAppend perform after it passes), so this fails if the
// flag is ever dropped from an open even while the guard keeps the higher-level tests
// green. On a platform with no O_NOFOLLOW equivalent config.OpenNoFollow is 0 and the portable
// guard is the only check, so there is nothing to assert.
func TestOpenNoFollow_RefusesSymlinkWithoutTheLstatGuard(t *testing.T) {
	if config.OpenNoFollow == 0 {
		t.Skip("platform has no O_NOFOLLOW equivalent; refuseNonRegular is the only guard there")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("attacker\n"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "audit.jsonl")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	f, err := os.OpenFile(link, os.O_APPEND|os.O_CREATE|os.O_RDWR|config.OpenNoFollow, 0o600) //nolint:gosec // G304: test-controlled path
	if err == nil {
		_ = f.Close()
		t.Fatal("config.OpenNoFollow must make the kernel refuse a symlinked audit-log path")
	}
	data, rerr := os.ReadFile(target) //nolint:gosec // G304: test-controlled path
	if rerr != nil {
		t.Fatalf("read target: %v", rerr)
	}
	if string(data) != "attacker\n" {
		t.Fatalf("symlink target was written through: %q", data)
	}

	// A regular path still opens with the flag set — the flag must not break normal use.
	plain := filepath.Join(dir, "plain.jsonl")
	g, err := os.OpenFile(plain, os.O_APPEND|os.O_CREATE|os.O_RDWR|config.OpenNoFollow, 0o600) //nolint:gosec // G304: test-controlled path
	if err != nil {
		t.Fatalf("config.OpenNoFollow must not block a regular path: %v", err)
	}
	_ = g.Close()
}
