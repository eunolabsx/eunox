// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package audit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// acquireAuditLock takes a non-blocking exclusive lock on a sidecar lock file tied
// to the audit log path (the Windows equivalent of the unix flock path), so a second
// writer fails fast instead of resuming from the same chain tail and forking the
// HMAC chain. The lock is on a separate file (not the log handle) so it survives
// rotation without a release window, named ".<base>.lock" so it stays out of the
// rotation glob and retention pruning. golang.org/x/sys is already in the module
// graph, so this adds no new dependency.
func acquireAuditLock(logPath string) (*os.File, error) {
	lockPath := filepath.Join(filepath.Dir(logPath), "."+filepath.Base(logPath)+".lock")
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // G304: derived from the user-configured audit log path
	if err != nil {
		return nil, fmt.Errorf("opening audit lock file %q: %w", lockPath, err)
	}
	// Lock a single byte; the range is arbitrary as long as every writer agrees.
	if err := windows.LockFileEx(
		windows.Handle(lf.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,    // reserved, must be 0
		1, 0, // number of bytes to lock (low, high dwords)
		new(windows.Overlapped),
	); err != nil {
		_ = lf.Close()
		// A non-blocking LockFileEx signals contention as either ERROR_LOCK_VIOLATION or
		// ERROR_IO_PENDING depending on the host/configuration; gofrs/flock maps both to
		// "contended" for this reason. Matching only the former left the operator-facing
		// diagnostic as dead code on hosts that surface ERROR_IO_PENDING.
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_IO_PENDING) {
			return nil, fmt.Errorf("audit log %q is already being written by another eunox instance (lock %q held); refusing to fork the tamper-evident chain", logPath, lockPath)
		}
		return nil, fmt.Errorf("locking audit log %q (lock %q): %w", logPath, lockPath, err)
	}
	return lf, nil
}

// releaseAuditLock unlocks and closes the lock file. Closing releases the lock;
// UnlockFileEx is issued first so the release is explicit.
func releaseAuditLock(lf *os.File) error {
	if lf == nil {
		return nil
	}
	_ = windows.UnlockFileEx(windows.Handle(lf.Fd()), 0, 1, 0, new(windows.Overlapped))
	return lf.Close()
}
