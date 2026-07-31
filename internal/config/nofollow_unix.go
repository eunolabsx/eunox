// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package config

import "syscall"

// OpenNoFollow is the syscall half of the symlink guard whose portable half is
// RefuseNonRegularPath: OR it into any open that truncates or appends to an
// operator-supplied path, so the kernel itself refuses to follow a final-component
// symlink.
//
// It closes the Lstat->OpenFile TOCTOU the Lstat guard cannot: RefuseNonRegularPath
// inspects the path, then os.OpenFile resolves it AGAIN, and a symlink planted in that
// window is followed — writing through to the link's target, which a subsequent fd Chmod
// then re-modes too. A shared, world-writable output directory is enough to lose that
// race. For the audit log the consequence is sharper: the tape is redirected AND the live
// log drops out of the verifier's IsRegular() chain scan, so verification passes without
// reading a record.
//
// The two halves are complementary, not redundant, which is why callers keep both: the
// flag closes the race window, while the Lstat closes the portability gap on platforms
// with no such flag AND refuses directories, devices, and FIFOs that O_NOFOLLOW would
// happily open. Neither is the primary control — the audit directory is 0700 and the
// Lstat produces the actionable error naming the path.
//
// It lives beside RefuseNonRegularPath for the reason that guard was consolidated here:
// the packages that need it each had their own copy, and a hand-mirrored security check
// drifts. It is deliberately NOT applied to whole-file scans (audit's seq contribution,
// verification), which read rotated siblings too and whose worst case is a mis-seeded
// ordinal rather than a redirected write.
const OpenNoFollow = syscall.O_NOFOLLOW
