// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/eunolabs/eunox/internal/config"
)

// auditLockPath derives the sidecar lock path for a log path. Named ".<base>.lock" so it
// stays out of the rotation glob and retention pruning.
func auditLockPath(logPath string) string {
	return filepath.Join(filepath.Dir(logPath), "."+filepath.Base(logPath)+".lock")
}

// openAuditLockFile opens (creating if absent) the sidecar lock file for logPath, under
// the package's two-halves symlink guard.
//
// It is build-tag-free and shared by both acquireAuditLock variants on purpose. The unix
// and Windows implementations differ only in the LOCKING call; the path derivation, the
// guard and the open were byte-identical in both, which is the shape the package already
// factored out once for the log itself (openGuardedAppend) with the stated reason that "a
// change to the check cannot leave one site weaker than the other". Two build-tagged
// copies are worse than two ordinary ones: a reviewer on Linux never compiles the other.
//
// See the acquireAuditLock doc comments for WHY the lock file needs the guard at all --
// the short version is that the lock's exclusivity, not its (never-written) content, is
// what a redirected open would hand to the wrong object, forking the HMAC chain.
func openAuditLockFile(lockPath string) (*os.File, error) {
	// The shared guard is called directly rather than through refuseNonRegular so the
	// operator-facing error names the LOCK file, not the audit log path; the two are on
	// the same rule and must stay that way.
	if err := config.RefuseNonRegularPath(lockPath, "audit lock file"); err != nil {
		return nil, err
	}
	// config.OpenNoFollow is 0 on platforms with no O_NOFOLLOW equivalent, so this one
	// expression is correct on every GOOS and the portable Lstat above carries the guard
	// alone where the flag does not exist.
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR|config.OpenNoFollow|config.OpenNonBlock, 0o600) //nolint:gosec // G304: derived from the user-configured audit log path
	if err != nil {
		return nil, fmt.Errorf("opening audit lock file %q: %w", lockPath, err)
	}
	// The lock's payload is its EXCLUSIVITY, and flock applies to whatever the open
	// resolved to: a FIFO planted in the Lstat->open window would send a second instance's
	// lock to a different object, leaving both instances appending to the log and forking
	// the HMAC chain. O_RDWR happens not to block on a FIFO on Linux, so the handle check
	// rather than the flag is what refuses it here — which is exactly why the rule is all
	// three guards and not whichever two the platform makes visible.
	if err := config.RefuseNonRegularHandle(lf, "audit lock file", lockPath); err != nil {
		_ = lf.Close()
		return nil, err
	}
	return lf, nil
}
