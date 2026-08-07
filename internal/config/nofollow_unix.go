// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package config

import "syscall"

// OpenNoFollow is the syscall half of the symlink guard whose portable half is
// RefuseNonRegularPath: OR it into any open that truncates or appends to an operator-supplied
// path, closing the Lstat->OpenFile TOCTOU where a symlink planted between the two is followed
// and written through to its target. Also carried by the whole-file scans (the resumed-seq
// scan and the verify chain's rotated-sibling reads), whose paths are equally attacker-
// choosable and which pair it with OpenNonBlock.
const OpenNoFollow = syscall.O_NOFOLLOW

// OpenNonBlock is the second half of the guard a READ-only open of a discovered path needs.
// O_NOFOLLOW refuses a symlink, but a path replaced by a FIFO in the readdir->open window is
// opened directly, and a read-only open of a FIFO BLOCKS INSIDE open(2) until a writer
// arrives — so a post-open regularity check never runs and the reader hangs forever with no
// error. With this the open returns immediately and the fstat refusal is reachable.
const OpenNonBlock = syscall.O_NONBLOCK
