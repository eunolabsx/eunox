// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

//go:build unix || windows

package audit

import (
	"errors"
	"syscall"
)

// isNoHardlinkErr reports whether an os.Link error indicates the filesystem does
// not support hard links (so the right move is to fall back to an atomic rename),
// as opposed to a genuine I/O failure that should propagate. CIFS/Samba, some NFS
// configurations, FAT32/exFAT, and some container bind-mount backends reject
// link(2) with EPERM or ENOSYS; linking across two filesystems returns EXDEV. Some
// network filesystems instead surface the failure as EOPNOTSUPP/ENOTSUP (NFS maps
// NFS3ERR_NOTSUPP to EOPNOTSUPP) — without it here, the proxy fails hard on exactly
// the CIFS/NFS backends this fallback exists for. These errnos are defined on every
// unix target and on windows; the non-unix/non-windows fallback
// (audit_hardlink_other.go) classifies portably because some of them are undefined
// there (e.g. plan9).
func isNoHardlinkErr(err error) bool {
	return errors.Is(err, syscall.EPERM) ||
		errors.Is(err, syscall.ENOSYS) ||
		errors.Is(err, syscall.EXDEV) ||
		errors.Is(err, syscall.EOPNOTSUPP) ||
		errors.Is(err, syscall.ENOTSUP)
}
