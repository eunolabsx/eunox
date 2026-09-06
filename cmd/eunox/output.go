// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// output.go holds the CLI's shared output plumbing: the stdout-vs-stderr rule every
// subcommand's help follows, the one renderer that applies it, and the write helpers the
// report-printing subcommands share. Neutral ground rather than one subcommand's file, since
// every consumer of these is some OTHER subcommand.

package main

import (
	"flag"
	"fmt"
	"io"
	"os"
)

// usageWriter returns os.Stdout when args explicitly requests help (--help, -help, or -h —
// the same tokens the flag package itself special-cases into ErrHelp), os.Stderr otherwise,
// so every subcommand's fs.Usage follows printUsage's own stated convention: help and bare
// invocations are a successful query (stdout, exit 0), a parse error prints usage to stderr
// alongside the failure. A "--" terminator ends the scan, matching parseFlagsAndPositionals'
// own handling — nothing after it is a flag. This is a heuristic, not a full re-parse: a
// flag value that happens to be the literal string "-h" (e.g. --audit-log -h) would be
// misread as a help request, but none of this binary's flags take a value where that is a
// plausible mistake to make.
func usageWriter(args []string) io.Writer {
	for _, a := range args {
		if a == "--" {
			return os.Stderr
		}
		if a == "--help" || a == "-help" || a == "-h" {
			return os.Stdout
		}
	}
	return os.Stderr
}

// setUsage installs the standard help renderer on fs: the prose, then the flag list, both on
// the stream usageWriter picks for args. The whole point is that SetOutput is not a step a
// site can forget — omitting it sends the prose to the chosen stream and the flag list to
// stderr, splitting one screen of help across two file descriptors.
//
// The writer is resolved INSIDE the closure rather than at install time so it still reflects
// the args scan when Usage fires, matching what the hand-rolled closures did.
func setUsage(fs *flag.FlagSet, args []string, text string) {
	fs.Usage = func() { writeUsage(fs, usageWriter(args), text) }
}

// writeUsage renders one subcommand's help to an explicit writer. setUsage is the entry point
// for a real invocation; this one is for a caller that has already chosen the stream.
func writeUsage(fs *flag.FlagSet, w io.Writer, text string) {
	_, _ = fmt.Fprint(w, text)
	fs.SetOutput(w)
	fs.PrintDefaults()
}

// wf and wln discard per-call write errors (not actionable for stdout); when the bundle goes
// to --output FILE, w is an *errTrackingWriter so a short write is still caught there.
func wf(w io.Writer, format string, args ...interface{}) { _, _ = fmt.Fprintf(w, format, args...) }
func wln(w io.Writer, args ...interface{})               { _, _ = fmt.Fprintln(w, args...) }

// writers binds w into the (wf, wln) pair so a function emitting one stream declares
// `wf, wln := writers(out)` once instead of re-deriving the closures at each site.
func writers(w io.Writer) (writef func(string, ...interface{}), writeln func(...interface{})) {
	return func(format string, args ...interface{}) { wf(w, format, args...) },
		func(args ...interface{}) { wln(w, args...) }
}
