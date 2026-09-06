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

// The banners still say both halves: what observe mode downgrades, and that some refusals stand.
//
// Deliberately NOT an assertion that the second line's list is COMPLETE, which it is not: at least
// --require-audit=strict (which defaults to strict and is not exclusive with --audit), the -32020
// routing-header refusal, and the RESOURCE_EXHAUSTED cap refusals also stand in observe mode. That
// is the banner's own copy to correct, not this cell's to pin — but a cell asserting the list as
// closed would make correcting it look like a regression.
func TestPrintWiretapBanners_NamesTheRefusalsItLists(t *testing.T) {
	t.Parallel()
	var out strings.Builder
	printWiretapBanners(&out)
	got := out.String()
	for _, want := range []string{"WIRETAP MODE", "audit-only, no policy", "kill switch", "UNROUTABLE_METHOD", "UNSUPPORTED_PROTOCOL_VERSION"} {
		require.Contains(t, got, want)
	}
}
