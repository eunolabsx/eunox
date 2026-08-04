// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package config

import "syscall"

// OpenNoFollow is the syscall half of the symlink guard whose portable half is
// RefuseNonRegularPath: OR it into any open that truncates or appends to an operator-supplied
// path, closing the Lstat->OpenFile TOCTOU where a symlink planted between the two is followed
// and written through to its target. Not applied to whole-file scans (rotated-sibling reads).
const OpenNoFollow = syscall.O_NOFOLLOW
