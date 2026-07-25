// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package audit

import "syscall"

// openNoFollow is OR-ed into every open of the ACTIVE audit log so the kernel itself
// refuses to follow a final-component symlink, closing the Lstat->OpenFile TOCTOU that
// refuseNonRegular cannot: refuseNonRegular inspects the path, then os.OpenFile resolves
// it again, and a symlink planted in that window would be followed — redirecting the
// tamper-evident tape and dropping the live log out of audit-verify's IsRegular() chain
// scan, so verification would PASS without reading a record.
//
// This is defense-in-depth, not the primary control (the log directory is 0700, and
// refuseNonRegular still runs and produces the actionable error message): the syscall
// flag closes the race window, the Lstat closes the portability gap on platforms with no
// such flag and reports WHY the path was refused.
const openNoFollow = syscall.O_NOFOLLOW
