// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestResolvePolicyPath_ExpandsTilde pins that a route's policy: entry gets the same
// "~" treatment as the audit-log and control-token paths.
//
// A leading "~/" is not an absolute path, so without expansion the baseDir join
// produced "<config-dir>/~/policies/x.yaml" — a directory the operator never wrote,
// surfacing as a confusing "no such file" naming a path that appears nowhere in their
// config. And "~user/..." (which Go cannot resolve portably) silently became a
// relative "~user" directory under the config dir. Both now resolve or fail closed.
func TestResolvePolicyPath_ExpandsTilde(t *testing.T) {
	t.Parallel()

	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home directory available: %v", err)
	}

	got, err := ResolvePolicyPath("/etc/eunox", "~/policies/x.yaml")
	if err != nil {
		t.Fatalf("ResolvePolicyPath with a ~/ policy path: %v", err)
	}
	want := filepath.Join(home, "policies/x.yaml")
	if got != want {
		t.Errorf("ResolvePolicyPath = %q, want %q (a home-relative path must not be joined under the config dir)", got, want)
	}
	if strings.Contains(got, "~") {
		t.Errorf("ResolvePolicyPath left a literal %q in %q", "~", got)
	}
}

// TestResolvePolicyPath_RejectsUserTilde: the "~user/..." form has no portable
// resolution, so it fails closed with ExpandHome's message rather than resolving to a
// directory literally named "~alice" under the config dir.
func TestResolvePolicyPath_RejectsUserTilde(t *testing.T) {
	t.Parallel()

	if _, err := ResolvePolicyPath("/etc/eunox", "~alice/policies/x.yaml"); err == nil {
		t.Fatal("ResolvePolicyPath accepted a ~user/... policy path; want a fail-closed error")
	}
}

// TestResolvePolicyPath_OrdinaryPathsUnchanged: the "~" handling must not disturb the
// relative-join and absolute-passthrough behavior every existing config relies on.
func TestResolvePolicyPath_OrdinaryPathsUnchanged(t *testing.T) {
	t.Parallel()

	cases := []struct{ name, baseDir, in, want string }{
		{"relative joins baseDir", "/etc/eunox", "policies/x.yaml", "/etc/eunox/policies/x.yaml"},
		{"absolute passes through", "/etc/eunox", "/srv/x.yaml", "/srv/x.yaml"},
		{"empty baseDir passes through", "", "policies/x.yaml", "policies/x.yaml"},
		{"embedded tilde is not a prefix", "/etc/eunox", "poli~cies/x.yaml", "/etc/eunox/poli~cies/x.yaml"},
	}
	for _, c := range cases {
		got, err := ResolvePolicyPath(c.baseDir, c.in)
		if err != nil {
			t.Errorf("%s: unexpected error: %v", c.name, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s: ResolvePolicyPath(%q, %q) = %q, want %q", c.name, c.baseDir, c.in, got, c.want)
		}
	}
}
