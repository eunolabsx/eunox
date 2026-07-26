// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package audit

import "syscall"

// openNoFollow is OR-ed into the audit-log opens that seed or extend the tamper-evident
// tape — the startup append (openAndPrepareLog), the two post-rotation reopens
// (openGuardedAppend), and the chain-resume tail read (readLastAuditLine) — so the kernel
// itself refuses to follow a final-component symlink. That closes the Lstat->OpenFile
// TOCTOU refuseNonRegular cannot: refuseNonRegular inspects the path, then os.OpenFile
// resolves it again, and a symlink planted in that window would be followed — redirecting
// the tape and dropping the live log out of audit-verify's IsRegular() chain scan, so
// verification would PASS without reading a record.
//
// It is NOT applied to the whole-file scans (scanSeqContribution, verification), which
// read rotated siblings too and whose worst case is a mis-seeded ordinal rather than a
// redirected write.
//
// This is defense-in-depth, not the primary control (the log directory is 0700, and
// refuseNonRegular still runs and produces the actionable error naming the path): the
// syscall flag closes the race window, the Lstat closes the portability gap on platforms
// with no such flag and also refuses directories, devices, and FIFOs that O_NOFOLLOW
// would happily open.
const openNoFollow = syscall.O_NOFOLLOW
