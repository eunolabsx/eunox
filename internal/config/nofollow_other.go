// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package config

// OpenNoFollow is 0 on platforms with no O_NOFOLLOW equivalent (Windows, js/wasm), where
// RefuseNonRegularPath's portable Lstat guard remains the only symlink check. See nofollow_unix.go.
const OpenNoFollow = 0

// OpenNonBlock is 0 on platforms with no O_NONBLOCK equivalent, where the blocking-FIFO
// open it guards against does not arise the same way. See nofollow_unix.go.
const OpenNonBlock = 0
