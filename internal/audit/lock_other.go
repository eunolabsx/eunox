// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

//go:build !unix && !windows

package audit

import (
	"fmt"
	"os"
)

// acquireAuditLock is the fallback for platforms that are neither unix (flock,
// lock_unix.go) nor windows (LockFileEx, lock_windows.go) — e.g. js/wasm, plan9.
// There is no portable advisory file lock there, so fail closed rather than
// silently run without the cross-writer protection the unix and windows builds
// provide.
func acquireAuditLock(logPath string) (*os.File, error) {
	return nil, fmt.Errorf("audit log locking is not supported on this platform; cannot guard %q against concurrent writers", logPath)
}

// releaseAuditLock is the non-unix fallback; acquireAuditLock never returns a
// non-nil file here, so this only handles the nil case.
func releaseAuditLock(lf *os.File) error {
	if lf == nil {
		return nil
	}
	return lf.Close()
}
