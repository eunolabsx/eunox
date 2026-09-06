// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package audit

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// acquireAuditLock takes a non-blocking exclusive flock on a sidecar lock file tied
// to the audit log path, held until releaseAuditLock closes it, so a second writer
// (same process or another instance) fails fast instead of resuming from the same
// chain tail and forking the HMAC chain. The lock is on a separate file (not the log
// fd) so it survives rotation without a release window, named ".<base>.lock" so it
// stays out of the rotation glob and retention pruning.
//
// The open carries ALL THREE of the package's substitution guards, exactly like every
// other open on an audit-derived path (see refuseNonRegular in rotate.go). It is not
// the lock file's CONTENT that needs protecting — nothing is ever written through this
// handle — it is the lock's EXCLUSIVITY. flock operates on whatever the open resolved
// to, so a link planted at this path ahead of first use sends a second instance's lock
// to a different inode: both instances then believe they hold the audit log and append
// to it, which forks the HMAC chain — the one outcome this file exists to prevent.
// Redirecting the lock to a device or FIFO is the availability version of the same bug.
//
// The directory is not trusted enough to skip this: MkdirAll sets 0700 only on a
// directory it CREATES, so an audit path pointed at a pre-existing group- or
// world-writable location carries no mode guarantee, and that is precisely where a
// symlink planted by another uid is reachable.
//
// Scope, so the claim is not read as wider than it is: this covers the lock PATH's final
// component. It does not make the lock inode-identified -- two spellings of one log (a
// hardlink, or two paths resolving to the same file) still derive two different lock
// paths, and neither excludes the other. That is a pre-existing property of deriving the
// lock name textually from the log path, not something the guard claims to fix.
func acquireAuditLock(logPath string) (*os.File, error) {
	lockPath := auditLockPath(logPath)
	lf, err := openAuditLockFile(lockPath)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lf.Close()
		// errors.Is, not ==: Flock returns a bare syscall.Errno today, but any future
		// wrapping would silently downgrade the "another instance holds the lock"
		// diagnostic to the generic message below. The Windows variant already matches
		// this way. Only EWOULDBLOCK is tested: it and EAGAIN are the same value on every
		// GOOS this file's `unix` build tag selects, so a second clause would be dead code
		// dressed as portability.
		if errors.Is(err, syscall.EWOULDBLOCK) {
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
