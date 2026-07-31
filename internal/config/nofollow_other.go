// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package config

// OpenNoFollow is 0 on platforms with no O_NOFOLLOW equivalent (Windows, js/wasm): the
// portable Lstat guard in RefuseNonRegularPath remains the only symlink check there,
// which is why every caller keeps that guard rather than replacing it with the flag.
// See nofollow_unix.go for the rationale.
const OpenNoFollow = 0
