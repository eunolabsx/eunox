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
				stdout = captureStdout(t, fs.Usage)
			})

			got, quiet := stdout, stderr
			if !tc.wantStdout {
				got, quiet = stderr, stdout
			}
			for _, want := range []string{"PROSE-MARKER", "-marker-flag"} {
				if !strings.Contains(got, want) {
					t.Errorf("help is missing %q on the stream usageWriter picked:\n%s", want, got)
				}
			}
			if quiet != "" {
				t.Errorf("the other stream must stay silent, got %q", quiet)
			}
		})
	}
}

// TestWriteUsage_HonorsAnExplicitWriter covers the entry point for a caller that has already
// chosen its stream (the tests that render proxyUsage directly), which must not consult the
// args scan setUsage applies.
func TestWriteUsage_HonorsAnExplicitWriter(t *testing.T) {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	fs.String("marker-flag", "", "a flag only PrintDefaults can render")

	var out strings.Builder
	writeUsage(fs, &out, "PROSE-MARKER\n")

	for _, want := range []string{"PROSE-MARKER", "-marker-flag"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("writeUsage dropped %q from the explicit writer:\n%s", want, out.String())
		}
	}
}
