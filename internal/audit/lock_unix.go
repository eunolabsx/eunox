// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// acquireAuditLock takes a non-blocking exclusive flock on a sidecar lock file tied
// to the audit log path, held until releaseAuditLock closes it, so a second writer
// (same process or another instance) fails fast instead of resuming from the same
// chain tail and forking the HMAC chain. The lock is on a separate file (not the log
// fd) so it survives rotation without a release window, named ".<base>.lock" so it
// stays out of the rotation glob and retention pruning.
func acquireAuditLock(logPath string) (*os.File, error) {
	lockPath := filepath.Join(filepath.Dir(logPath), "."+filepath.Base(logPath)+".lock")
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // G304: derived from the user-configured audit log path
	if err != nil {
		return nil, fmt.Errorf("opening audit lock file %q: %w", lockPath, err)
	}
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lf.Close()
		if err == syscall.EWOULDBLOCK {
			return nil, fmt.Errorf("audit log %q is already being written by another eunox instance (lock %q held); refusing to fork the tamper-evident chain", logPath, lockPath)
		}
		return nil, fmt.Errorf("locking audit log %q (lock %q): %w", logPath, lockPath, err)
	}
	return lf, nil
}

// releaseAuditLock unlocks and closes the lock file. Closing releases the flock;
// LOCK_UN is issued first so the release is explicit.
func releaseAuditLock(lf *os.File) error {
	if lf == nil {
		return nil
	}
	_ = syscall.Flock(int(lf.Fd()), syscall.LOCK_UN)
	return lf.Close()
}
