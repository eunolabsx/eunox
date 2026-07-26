// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package audit

// openNoFollow is 0 on platforms with no O_NOFOLLOW equivalent (Windows, js/wasm):
// the portable Lstat guard in refuseNonRegular remains the only symlink check there,
// which is why that guard stays in place on every platform rather than being replaced
// by the flag. See nofollow_unix.go for the rationale.
const openNoFollow = 0
