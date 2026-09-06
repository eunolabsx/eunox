// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"strings"
	"testing"
)

// TestSetUsage_ProseAndFlagListShareOneStream pins the property the helper exists for: the
// flag list follows the prose to whichever stream usageWriter picked. Each subcommand used to
// hand-roll the four-line ritual, where omitting fs.SetOutput sent the prose to the chosen
// stream and left PrintDefaults writing to the FlagSet's default (stderr) — one screen of help
// split across two file descriptors, on the arm where it is read as a successful query.
//
// Driven through fs.Parse rather than by calling fs.Usage directly, so each row exercises the
// path that actually reaches it: the flag package calls Usage for ErrHelp and, separately,
// after writing its own diagnostic for an undefined flag.
func TestSetUsage_ProseAndFlagListShareOneStream(t *testing.T) {
	cases := []struct {
		name string
		args []string
		// help goes to stdout, a parse error to stderr — usageWriter's convention.
		wantStdout bool
	}{
		{"explicit help", []string{"--help"}, true},
		{"parse error", []string{"--bogus"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("probe", flag.ContinueOnError)
			fs.String("marker-flag", "", "a flag only PrintDefaults can render")
			setUsage(fs, tc.args, "PROSE-MARKER\n\nFlags:\n")

			var stdout string
			stderr := captureStderr(t, func() {
				stdout = captureStdout(t, func() { _ = fs.Parse(tc.args) })
			})

			got, other := stdout, stderr
			if !tc.wantStdout {
				got, other = stderr, stdout
			}
			for _, want := range []string{"PROSE-MARKER", "-marker-flag"} {
				if !strings.Contains(got, want) {
					t.Errorf("help is missing %q on the stream usageWriter picked:\n%s", want, got)
				}
			}
			// The flag package writes its own "not defined" diagnostic before calling Usage, and
			// it goes to the FlagSet's default output — so the help itself is what must not be
			// split, not that the other stream is empty.
			for _, mustNotLeak := range []string{"PROSE-MARKER", "-marker-flag"} {
				if strings.Contains(other, mustNotLeak) {
					t.Errorf("help leaked %q onto the other stream, so one screen is split across two:\n%s", mustNotLeak, other)
				}
			}
		})
	}
}
