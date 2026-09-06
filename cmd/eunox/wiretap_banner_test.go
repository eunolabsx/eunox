// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCmdProxy_WiretapBannerFollowsTheFlagGuards: a proxy that never comes up must not announce
// that it did.
//
// The banners used to print inside resolveProxyConfig, which runs BEFORE the four fail-closed flag
// guards, so `eunox proxy --audit --jwt-issuer x -- cmd` announced WIRETAP MODE twice and then died
// on the JWKS guard. In a supervisor log that reads as a proxy that started, against this file's
// own parse-before-side-effects principle — and it is the operator most likely to be reading, since
// the run they are debugging is the one that failed.
func TestCmdProxy_WiretapBannerFollowsTheFlagGuards(t *testing.T) {
	dir := t.TempDir()
	var code int
	stderr := captureStderr(t, func() {
		code = cmdProxy([]string{
			"--audit-log", filepath.Join(dir, "audit.jsonl"),
			"--audit-key-path", filepath.Join(dir, "audit.key"),
			"--jwt-issuer", "https://idp.example",
			"--audit", "--", "cat",
		})
	})

	require.Equal(t, 1, code, "a JWT flag with no --jwks-uri must fail startup")
	require.Contains(t, stderr, "--jwks-uri", "the run must die on the guard this cell is about")
	require.NotContains(t, stderr, "WIRETAP MODE",
		"a proxy that failed a startup guard announced the mode it never entered")
}

// And the banners themselves still say both halves: what observe mode downgrades, and what it does
// not. The second line is the one an operator reads to learn that a kill, an unroutable method and
// an unestablishable revision still refuse — none of which is a policy verdict to downgrade.
func TestPrintWiretapBanners_NamesWhatStillRefuses(t *testing.T) {
	t.Parallel()
	var out strings.Builder
	printWiretapBanners(&out)
	got := out.String()
	for _, want := range []string{"WIRETAP MODE", "audit-only, no policy", "kill switch", "UNROUTABLE_METHOD", "UNSUPPORTED_PROTOCOL_VERSION"} {
		require.Contains(t, got, want)
	}
}
