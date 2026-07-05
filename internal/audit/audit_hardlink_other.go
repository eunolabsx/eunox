// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

//go:build !unix && !windows

package audit

import (
	"errors"
	"io/fs"
)

// isNoHardlinkErr is the portable fallback for targets that are neither unix nor
// windows (e.g. plan9, js/wasm), where some of the errnos the posix variant
// classifies (syscall.ENOSYS, syscall.EXDEV) are undefined and would break the
// build. It detects only the portably-mappable permission case (fs.ErrPermission,
// which os maps from EPERM/EACCES); a cross-device or not-implemented link error is
// not portably distinguishable here and therefore propagates rather than silently
// falling back. This path is largely moot in practice: acquireAuditLock already
// fails closed on these platforms (lock_other.go), so the audit sink — and thus the
// key-publication link that calls this — never starts there.
func isNoHardlinkErr(err error) bool {
	return errors.Is(err, fs.ErrPermission)
}
