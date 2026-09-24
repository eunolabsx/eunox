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

// TestResolveControlToken_RefusesAPlantedFIFO pins that a FIFO at the token path cannot hang
// `eunox kill` inside open(2): the refusal must return, and promptly.
func TestResolveControlToken_RefusesAPlantedFIFO(t *testing.T) {
	t.Setenv("EUNOX_CONTROL_TOKEN", "")
	path := filepath.Join(t.TempDir(), "control.token")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := ResolveControlToken("", path)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "non-regular") {
			t.Fatalf("err = %v, want a non-regular-file refusal", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ResolveControlToken blocked on a reader-less FIFO")
	}
}

// TestReadGuardedControlTokenHandle_RefusesAFIFOPastThePathCheck drives the open and handle
// guards on their own: a FIFO swapped in after the Lstat reaches the open directly, so
// O_NONBLOCK must keep it from blocking and the fstat through the handle must refuse it.
func TestReadGuardedControlTokenHandle_RefusesAFIFOPastThePathCheck(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.token")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := readGuardedControlTokenHandle(path)
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

// TestReadGuardedControlTokenHandle_RefusesASymlinkPastThePathCheck is the O_NOFOLLOW half: a
// link swapped in after the Lstat must fail the open rather than be read through.
func TestReadGuardedControlTokenHandle_RefusesASymlinkPastThePathCheck(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("private\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "control.token")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatal(err)
	}
	if data, err := readGuardedControlTokenHandle(link); err == nil {
		t.Fatalf("the open followed a symlink and read %q", data)
	}
}

// TestResolveControlToken_RefusesASymlink pins that a link planted at the token path is not
// followed: its target's contents would otherwise be sent as X-Eunox-Control-Token.
func TestResolveControlToken_RefusesASymlink(t *testing.T) {
	t.Setenv("EUNOX_CONTROL_TOKEN", "")
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("not-a-token-but-private\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "control.token")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatal(err)
	}
	tok, err := ResolveControlToken("", link)
	if err == nil {
		t.Fatalf("a symlinked token path must be refused, got token %q", tok)
	}
	if !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("err = %v, want the symlink refusal", err)
	}
	if strings.Contains(err.Error(), "not-a-token-but-private") {
		t.Errorf("the refusal leaked the link target's contents: %v", err)
	}
}
