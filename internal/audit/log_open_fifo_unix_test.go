// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package audit

import (
	"github.com/eunolabs/eunox/internal/config"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// openBlockDeadline bounds every open these tests drive. Timed rather than merely asserting
// an error because the regression they cover does not fail, it HANGS — an open of a FIFO
// waits inside open(2) for a peer that never comes — and an unbounded test would stall the
// package's whole run instead of naming itself.
const openBlockDeadline = 10 * time.Second

type openResult struct {
	f   *os.File
	err error
}

// openWithin runs open on its own goroutine and fails the test if it has not returned within
// openBlockDeadline. The goroutine is deliberately NOT joined on the timeout path: it is
// parked inside open(2) and will never return, which is the finding being reported.
func openWithin(t *testing.T, what string, open func() (*os.File, error)) (*os.File, error) {
	t.Helper()
	done := make(chan openResult, 1)
	go func() {
		f, err := open()
		done <- openResult{f, err}
	}()
	select {
	case got := <-done:
		return got.f, got.err
	case <-time.After(openBlockDeadline):
		t.Fatalf("%s blocked rather than refusing: the open is waiting inside open(2), so no post-open check can run", what)
		return nil, nil
	}
}

// logOpenSite is one of the two opens that produce the ACTIVE tape's write handle: the
// startup open and the post-rotation reopen. Both are driven through the same table so a
// guard added to one and not the other fails here rather than in whichever site the next
// test happened to name.
type logOpenSite struct {
	name string
	open func(logPath string) (*os.File, error)
}

func activeLogOpenSites() []logOpenSite {
	return []logOpenSite{
		{name: "openGuardedAppend", open: openGuardedAppend},
		{name: "openAndPrepareLog", open: func(logPath string) (*os.File, error) {
			// A nil lock file is releaseAuditLock's documented no-op, so the open can be
			// driven without standing up the whole sink.
			f, _, _, _, err := openAndPrepareLog(logPath, 0, nil)
			return f, err
		}},
	}
}

func mkfifoOrSkip(t *testing.T, path string) {
	t.Helper()
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
}

// TestActiveLogOpen_RefusesFIFOAtTheLogPath is the operator-facing shape: a FIFO sitting at
// the log path when the open runs is refused, promptly. The pre-open Lstat is what refuses
// it here — the post-open guards are covered below — so what this pins is that the composite
// never hangs, on either site.
func TestActiveLogOpen_RefusesFIFOAtTheLogPath(t *testing.T) {
	t.Parallel()
	for _, site := range activeLogOpenSites() {
		t.Run(site.name, func(t *testing.T) {
			t.Parallel()
			fifo := filepath.Join(t.TempDir(), "audit.jsonl")
			mkfifoOrSkip(t, fifo)

			f, err := openWithin(t, site.name, func() (*os.File, error) { return site.open(fifo) })
			if err == nil {
				_ = f.Close()
				t.Fatal("a FIFO at the audit log path must be refused, not appended to: the signed tape would be written into the pipe while LogChainFiles' IsRegular() scan drops it from verification")
			}
		})
	}
}

// TestOpenGuardedAppend_RefusesFIFOHeldOpenByAReader is the case only the HANDLE check can
// catch, and the one the flags cannot: O_WRONLY|O_NONBLOCK fails ENXIO on a reader-LESS
// FIFO, so with a reader already attached the open succeeds and every guard but the fstat
// waves it through. Without that check the signed tape is appended into the pipe, which
// LogChainFiles' IsRegular() scan then drops from verification entirely.
//
// Driven through the raw open rather than openGuardedAppend, whose pre-open Lstat refuses a
// FIFO already at the path — the reachable shape is one planted in the Lstat->open window,
// which is what this reconstructs.
func TestOpenGuardedAppend_RefusesFIFOHeldOpenByAReader(t *testing.T) {
	t.Parallel()
	fifo := filepath.Join(t.TempDir(), "audit.jsonl")
	mkfifoOrSkip(t, fifo)

	reader, err := os.OpenFile(fifo, os.O_RDONLY|config.OpenNonBlock, 0) //nolint:gosec // G304: test-controlled path
	if err != nil {
		t.Fatalf("attach a reader to the FIFO: %v", err)
	}
	defer func() { _ = reader.Close() }()

	f, err := openWithin(t, "the guarded append open", func() (*os.File, error) {
		w, oerr := os.OpenFile(fifo, os.O_APPEND|os.O_CREATE|os.O_WRONLY|config.OpenNoFollow|config.OpenNonBlock, 0o600) //nolint:gosec // G304: test-controlled path
		if oerr != nil {
			return nil, oerr
		}
		if rerr := refuseNonRegularHandle(w, fifo); rerr != nil {
			_ = w.Close()
			return nil, rerr
		}
		return w, nil
	})
	if err == nil {
		_ = f.Close()
		t.Fatal("a FIFO a reader already holds open is admitted by both flags; only the fstat through the handle refuses it")
	}
}

// TestActiveLogOpen_FIFOPlantedInTheCreateWindow drives the window the Lstat guard cannot
// see. An ABSENT path passes refuseNonRegular by design — it is the ordinary post-rename
// case, and the rename is precisely what leaves the log path absent — so whoever can write
// the log directory plants a FIFO between that check and the O_CREATE open. The two failure
// shapes differ per site and neither is loud: the reopen's O_WRONLY open blocks inside
// open(2) forever, and the startup site's O_RDWR open of a FIFO does not block at all, so
// without the handle check the tape is written into the pipe with writeFailures staying 0
// (--require-audit=strict never trips).
func TestActiveLogOpen_FIFOPlantedInTheCreateWindow(t *testing.T) {
	t.Parallel()
	for _, site := range activeLogOpenSites() {
		t.Run(site.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			logPath := filepath.Join(dir, "audit.jsonl")
			mkfifoOrSkip(t, logPath)
			_ = os.Remove(logPath)

			// The planter cycles the path so the opener's O_CREATE sometimes lands on a
			// FIFO and sometimes creates its own regular file. Stopped and JOINED through
			// Cleanup so every exit — t.Fatal included, which skips the rest of the
			// function — drains it before TempDir's own cleanup: a planter still spinning
			// mkfifo in a directory being removed turns one failure into two, and burns a
			// core through every test that follows.
			var stop atomic.Bool
			planted := make(chan struct{})
			go func() {
				defer close(planted)
				for !stop.Load() {
					_ = os.Remove(logPath)
					_ = syscall.Mkfifo(logPath, 0o600)
				}
			}()
			t.Cleanup(func() {
				stop.Store(true)
				<-planted
			})

			refusals := 0
			for i := 0; i < 400; i++ {
				f, err := openWithin(t, site.name, func() (*os.File, error) { return site.open(logPath) })
				if err != nil {
					refusals++
					continue
				}
				info, serr := f.Stat()
				_ = f.Close()
				if serr != nil {
					t.Fatalf("stat the opened log: %v", serr)
				}
				if !info.Mode().IsRegular() {
					t.Fatalf("%s returned a handle to a non-regular file (mode %v): the signed tape would be written through it", site.name, info.Mode())
				}
			}
			// Without this the test can pass having never landed in the window at all —
			// a filesystem that refused mkfifo, a scheduler that never interleaved — and a
			// vacuous pass is indistinguishable from a real one in CI.
			if refusals == 0 {
				t.Fatal("no open ever landed on a planted FIFO; this run covered nothing")
			}
		})
	}
}
