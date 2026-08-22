// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package config

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestReadBoundedFile_RefusesADiscoveredFIFO is the FIFO half of the substitution guard, on
// the paths it is scoped to. A caller's RefuseNonRegularPath runs against the PATH, so a FIFO
// swapped in after that Lstat is opened directly — and a read-only open of a reader-less FIFO
// blocks inside open(2) forever, which no size bound and no O_NOFOLLOW reaches.
func TestReadBoundedFile_RefusesADiscoveredFIFO(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "planted.json")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := ReadBoundedFile(BoundedRead{
			Path: path, What: "contract", Max: 1 << 20, OverLimit: "refusing", Discovered: true,
		})
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a FIFO must be refused, not read")
		}
		if !strings.Contains(err.Error(), "non-regular") {
			t.Errorf("error = %v, want a non-regular-file refusal", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadBoundedFile blocked on a reader-less FIFO; the open must not wait for a writer")
	}
}

// TestReadBoundedFile_OperatorNamedFIFOStillReads is the bound on that guard. A path the
// operator NAMED is theirs to point wherever they like, and pointing it at a FIFO is a
// supported spelling rather than an attack — `--config <(envsubst < t.yaml)` is exactly this
// shape, and `--config /dev/stdin` is a pipe. Applying the guard to every caller refused both
// and bought nothing: an operator who can pass --config can pass anything.
func TestReadBoundedFile_OperatorNamedFIFOStillReads(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "substituted.yaml")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}

	// A writer, as process substitution supplies: the open blocks until one arrives, so this
	// also pins that the operator-named path takes no O_NONBLOCK (which would read EAGAIN
	// before the data lands).
	go func() {
		w, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return
		}
		defer func() { _ = w.Close() }()
		_, _ = w.WriteString("schemaVersion: \"0.1\"\n")
	}()

	done := make(chan struct {
		data []byte
		err  error
	}, 1)
	go func() {
		data, err := ReadBoundedFile(BoundedRead{Path: path, What: "gateway config", Max: 1 << 20, OverLimit: "refusing"})
		done <- struct {
			data []byte
			err  error
		}{data, err}
	}()

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("an operator-named FIFO must still read: %v", got.err)
		}
		if !strings.Contains(string(got.data), "schemaVersion") {
			t.Errorf("read %q, want the substituted content", got.data)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("reading an operator-named FIFO with a live writer must complete")
	}
}

// TestReadBoundedFile_StillReadsARegularFile is the contrast leg: the guard must not cost the
// ordinary read it wraps.
func TestReadBoundedFile_StillReadsARegularFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "ok.json")
	if err := os.WriteFile(path, []byte(`{"a":1}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := ReadBoundedFile(BoundedRead{Path: path, What: "contract", Max: 1 << 20, OverLimit: "refusing"})
	if err != nil {
		t.Fatalf("ReadBoundedFile: %v", err)
	}
	if string(got) != `{"a":1}` {
		t.Errorf("read %q, want the file's content", got)
	}
}

// TestRefuseNonRegularHandle_AnswersThroughTheDescriptor pins the third guard's distinctive
// property: it describes the object the caller holds, so a path replaced after the open
// cannot change its answer.
func TestRefuseNonRegularHandle_AnswersThroughTheDescriptor(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "out")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = f.Close() }()

	if err := RefuseNonRegularHandle(f, "output file", path); err != nil {
		t.Fatalf("a regular file must pass: %v", err)
	}
	// The name now points at a directory; the handle still names the regular file.
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := RefuseNonRegularHandle(f, "output file", path); err != nil {
		t.Errorf("the handle's own identity must decide, not the path's current target: %v", err)
	}

	dirHandle, err := os.Open(path)
	if err != nil {
		t.Fatalf("open dir: %v", err)
	}
	defer func() { _ = dirHandle.Close() }()
	if err := RefuseNonRegularHandle(dirHandle, "output file", path); err == nil {
		t.Error("a directory handle must be refused")
	} else if !strings.Contains(err.Error(), "non-regular") {
		t.Errorf("error = %v, want a non-regular-file refusal", err)
	}
}
