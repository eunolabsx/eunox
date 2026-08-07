// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package audit

import (
	"io"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestOpenDiscoveredAuditFile_RefusesFIFOWithoutBlocking pins the flag the regularity check
// alone cannot stand in for. A read-only open of a FIFO BLOCKS INSIDE open(2) until a writer
// arrives, so without OpenNonBlock a FIFO planted in the readdir->open window wedges the
// reader forever — no error, no timeout, and the post-open fstat never runs. Both callers of
// the shared opener (the resumed-seq scan at startup and the verify chain) would hang.
//
// Timed rather than merely asserting the error: a regression here does not fail, it hangs,
// which without a bound would stall the whole package's test run instead of naming itself.
func TestOpenDiscoveredAuditFile_RefusesFIFOWithoutBlocking(t *testing.T) {
	t.Parallel()
	fifo := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		f, err := openDiscoveredAuditFile(fifo)
		if err == nil {
			_ = f.Close()
		}
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a FIFO substituted for an audit log must be refused, not read as one")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("openDiscoveredAuditFile blocked on a FIFO: the read-only open is waiting for a writer, so the regularity check is unreachable")
	}
}

// TestVerifyLogFiles_RefusesFIFOChainFile is the same hazard at the level an operator meets
// it: `eunox audit-verify` over a chain whose file was swapped for a FIFO must fail closed
// rather than hang, since a wedged forensic tool is indistinguishable from a slow one.
func TestVerifyLogFiles_RefusesFIFOChainFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	fifo := filepath.Join(dir, "audit.jsonl.20260601T000000.000000000Z")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	verifier := verifierFor(t, filepath.Join(dir, "audit.key"))

	done := make(chan error, 1)
	go func() {
		_, err := VerifyLogFiles([]string{fifo}, verifier, "", time.Time{}, io.Discard)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("VerifyLogFiles must fail closed on a non-regular chain file")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("VerifyLogFiles blocked on a FIFO chain file rather than refusing it")
	}
}

// TestScanSeqContribution_RefusesFIFO pins the resume path's half. A non-blocking FIFO open
// SUCCEEDS and then reads clean EOF, so without the regularity check the scan would report
// "opened fine, held no record" and seed the counter at genesis — reissuing every on-disk
// seq, the duplicate-seq cascade scanSeqContribution's own contract calls worse than a gap.
func TestScanSeqContribution_RefusesFIFO(t *testing.T) {
	t.Parallel()
	fifo := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, parsed, _ := scanSeqContribution(fifo, auditScanBufferBytes); parsed {
			t.Error("a FIFO must never be reported as a cleanly-parsed audit log")
		}
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("scanSeqContribution blocked on a FIFO planted at the log path")
	}
}
