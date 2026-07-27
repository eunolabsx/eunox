// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// ExpandHome is the one "~" expansion in the tree, and every caller feeds its
// result straight to the filesystem — the audit log and its HMAC key, the
// control-token file, each route's policy path. That is why it fails closed
// instead of returning the literal "~" form: audit.Open would otherwise MkdirAll
// a directory named "~" (or "~alice") under the process CWD and write the
// tamper-evident tape somewhere the operator never chose and will not think to
// look. These cases are pinned in the package that owns the implementation, so a
// caller-side copy cannot drift from it.

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestExpandHome covers every branch: a bare "~" resolves to HOME, a "~/sub"
// joins under HOME, absolute and relative non-tilde paths pass through untouched,
// and a "~user/..." form is refused rather than silently treated as relative.
func TestExpandHome(t *testing.T) {
	// Pin HOME rather than reading the ambient value: os.UserHomeDir fails outright
	// where there is no HOME and no /etc/passwd entry (a scratch image, DynamicUser),
	// which would otherwise surface as a bogus ExpandHome failure.
	home := t.TempDir()
	t.Setenv("HOME", home)

	cases := []struct {
		in   string
		want string
	}{
		{"~", home},
		{"~/foo/bar", filepath.Join(home, "foo", "bar")},
		{"~/audit.jsonl", filepath.Join(home, "audit.jsonl")},
		{"~/.eunox/audit.key", filepath.Join(home, ".eunox", "audit.key")},
		{"/etc/eunox/audit.jsonl", "/etc/eunox/audit.jsonl"}, // absolute: passthrough
		{"relative/path", "relative/path"},                   // no leading ~: passthrough
		{"", ""},                                             // empty: passthrough, no home lookup
	}
	for _, c := range cases {
		got, err := ExpandHome(c.in)
		if err != nil {
			t.Fatalf("ExpandHome(%q): unexpected error %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("ExpandHome(%q) = %q, want %q", c.in, got, c.want)
		}
	}

	// A "~user/..." form must be REFUSED, not passed through. Go cannot resolve another
	// user's home portably, so a passthrough would treat "~alice/audit.jsonl" as an
	// ordinary relative path and silently create a directory literally named "~alice"
	// under the process cwd — putting the tamper-evident tape (or its HMAC key) somewhere
	// the operator never chose.
	for _, in := range []string{"~tilde-not-home", "~alice/audit.jsonl", "~root/.eunox/audit.key"} {
		if got, err := ExpandHome(in); err == nil {
			t.Errorf("ExpandHome(%q) = %q with no error; a ~user form must fail closed rather than resolve against the cwd", in, got)
		}
	}
}

// TestExpandHome_HomeUnavailableFailsClosed verifies that when the home directory
// cannot be resolved, ExpandHome returns an error rather than the literal "~"
// form — so audit.Open refuses to start instead of misplacing the log — and that
// it yields no path alongside the error, so a caller cannot use a misresolved one.
func TestExpandHome_HomeUnavailableFailsClosed(t *testing.T) {
	// os.UserHomeDir reads $HOME on unix; clearing it makes resolution fail.
	t.Setenv("HOME", "")
	if _, err := os.UserHomeDir(); err == nil {
		t.Skip("os.UserHomeDir still resolves with HOME unset on this platform; cannot exercise the failure path")
	}

	for _, in := range []string{"~", "~/.eunox/audit.jsonl"} {
		got, err := ExpandHome(in)
		if err == nil {
			t.Fatalf("ExpandHome(%q) returned (%q, nil); want an error when the home dir is unavailable", in, got)
		}
		if got != "" {
			t.Errorf("ExpandHome(%q) returned path %q alongside the error; want empty so a caller cannot use a misresolved path", in, got)
		}
	}

	// A non-tilde path must still resolve with no home, since it never consults
	// UserHomeDir.
	if got, err := ExpandHome("/tmp/x"); err != nil || got != "/tmp/x" {
		t.Fatalf("ExpandHome(absolute) = (%q, %v), want (/tmp/x, nil) with no home", got, err)
	}
}
