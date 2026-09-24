// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package transport

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestLoadEffectReceiptVerifier_RefusesAPlantedFIFO pins that a FIFO at the key-set path
// cannot wedge gateway startup: the loader runs inside BuildRoutes, so a hang here is a proxy
// that never stands and never says why.
func TestLoadEffectReceiptVerifier_RefusesAPlantedFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipt-jwks.json")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := LoadEffectReceiptVerifier("", path)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "non-regular") {
			t.Fatalf("err = %v, want a non-regular-file refusal", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("LoadEffectReceiptVerifier blocked on a reader-less FIFO")
	}
}

// TestReadGuardedEffectReceiptKeys_RefusesAFIFOPastThePathCheck drives the open and handle
// guards on their own: a FIFO swapped in after the Lstat reaches the open directly, so
// O_NONBLOCK must keep it from blocking and the fstat through the handle must refuse it.
func TestReadGuardedEffectReceiptKeys_RefusesAFIFOPastThePathCheck(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipt-jwks.json")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := readGuardedEffectReceiptKeys(path)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "non-regular") {
			t.Fatalf("err = %v, want a non-regular-file refusal through the handle", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the open blocked on a reader-less FIFO; it must take O_NONBLOCK")
	}
}

// TestReadGuardedEffectReceiptKeys_RefusesASymlinkPastThePathCheck is the O_NOFOLLOW half: a
// link swapped in after the Lstat must fail the open rather than adopt the target as the
// receipt trust anchor.
func TestReadGuardedEffectReceiptKeys_RefusesASymlinkPastThePathCheck(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "attacker-jwks.json")
	if err := os.WriteFile(target, []byte(`{"keys":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "receipt-jwks.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if data, err := readGuardedEffectReceiptKeys(link); err == nil {
		t.Fatalf("the open followed a symlink and read %q", data)
	}
}
