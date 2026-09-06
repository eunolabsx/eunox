// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package audit

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

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

// TestActiveLogOpen_RefusesFIFOAtTheLogPath is the operator-facing half: a FIFO sitting at
// the log path when the open runs must be refused, and refused PROMPTLY. Timed rather than
// only asserting the error because a regression here does not fail, it hangs — an O_WRONLY
// open of a reader-less FIFO waits inside open(2) for a writer that never comes, which for
// the reopen site means the drainer goroutine wedges for the process's life.
func TestActiveLogOpen_RefusesFIFOAtTheLogPath(t *testing.T) {
	t.Parallel()
	for _, site := range activeLogOpenSites() {
		t.Run(site.name, func(t *testing.T) {
			t.Parallel()
			fifo := filepath.Join(t.TempDir(), "audit.jsonl")
			if err := syscall.Mkfifo(fifo, 0o600); err != nil {
				t.Skipf("mkfifo unavailable: %v", err)
			}

			type result struct {
				f   *os.File
				err error
			}
			done := make(chan result, 1)
			go func() {
				f, err := site.open(fifo)
				done <- result{f, err}
			}()

			select {
			case got := <-done:
				if got.err == nil {
					_ = got.f.Close()
					t.Fatal("a FIFO at the audit log path must be refused, not appended to: the signed tape would be written into the pipe while LogChainFiles' IsRegular() scan drops it from verification")
				}
			case <-time.After(10 * time.Second):
				t.Fatal("the open blocked on a FIFO rather than refusing it")
			}
		})
	}
}

// TestActiveLogOpen_FIFOPlantedInTheCreateWindow drives the window the Lstat guard cannot
// see. An ABSENT path passes refuseNonRegular by design — it is the ordinary post-rename
// case, and the rename is precisely what leaves the log path absent — so whoever can write
// the log directory can plant a FIFO between that check and the O_CREATE open. The two
// failure shapes differ per site and neither is loud: the reopen's O_WRONLY open blocks
// inside open(2) forever, and the startup site's O_RDWR open of a FIFO does not block at
// all, so without the handle check the tape is written into the pipe with writeFailures
// staying 0 (--require-audit=strict never trips).
//
// The window is hit by racing rather than by a seam, so a run that never lands in it still
// passes — the flags and the handle check themselves are pinned deterministically by
// TestActiveLogOpens_CarryAllThreeSubstitutionGuards. What this adds is the behavior: no
// call blocks, and no handle that survives describes anything but a regular file.
func TestActiveLogOpen_FIFOPlantedInTheCreateWindow(t *testing.T) {
	t.Parallel()
	for _, site := range activeLogOpenSites() {
		t.Run(site.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			logPath := filepath.Join(dir, "audit.jsonl")
			if err := syscall.Mkfifo(logPath, 0o600); err != nil {
				t.Skipf("mkfifo unavailable: %v", err)
			}
			_ = os.Remove(logPath)

			// The planter cycles the path so the opener's O_CREATE sometimes lands on a
			// FIFO and sometimes creates its own regular file; stopping it is what lets the
			// opener's last iteration finish.
			var stop atomic.Bool
			planted := make(chan struct{})
			go func() {
				defer close(planted)
				for !stop.Load() {
					_ = os.Remove(logPath)
					_ = syscall.Mkfifo(logPath, 0o600)
				}
			}()

			// Each iteration is watchdogged separately: a blocked open never returns, so an
			// overall deadline on the loop would report "slow" for a permanent wedge.
			deadline := time.Now().Add(2 * time.Second)
			refusals := 0
			for i := 0; i < 4000 && time.Now().Before(deadline); i++ {
				type result struct {
					f   *os.File
					err error
				}
				done := make(chan result, 1)
				go func() {
					f, err := site.open(logPath)
					done <- result{f, err}
				}()
				select {
				case got := <-done:
					if got.err != nil {
						refusals++
						continue
					}
					info, serr := got.f.Stat()
					_ = got.f.Close()
					if serr != nil {
						t.Fatalf("stat the opened log: %v", serr)
					}
					if !info.Mode().IsRegular() {
						stop.Store(true)
						t.Fatalf("%s returned a handle to a non-regular file (mode %v): the signed tape would be written through it", site.name, info.Mode())
					}
				case <-time.After(10 * time.Second):
					stop.Store(true)
					t.Fatalf("%s blocked on a FIFO planted in the Lstat->open window", site.name)
				}
			}
			stop.Store(true)
			<-planted
			t.Logf("%s: %d of the racing opens were refused", site.name, refusals)
		})
	}
}
