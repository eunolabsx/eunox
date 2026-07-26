// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"os"
	"testing"
)

// ExpandHome is the one "~" expansion in the tree — internal/audit resolves the
// audit log and its HMAC key through it, internal/transport the control-token
// file, and the route loader every policy: path — so these cases are pinned here,
// in the package that owns the implementation, rather than at a call site.

func TestExpandHome_WithTilde(t *testing.T) {
	t.Parallel()
	home, _ := os.UserHomeDir()
	result, err := ExpandHome("~/foo/bar")
	if err != nil {
		t.Fatalf("ExpandHome(~/foo/bar) error: %v", err)
	}
	expected := fmt.Sprintf("%s/foo/bar", home)
	if result != expected {
		t.Errorf("ExpandHome(~/foo/bar) = %q, want %q", result, expected)
	}
}

// TestExpandHome_BareTilde regression: a path of exactly "~" (no
// trailing slash) must expand to the home directory, not be returned unchanged —
// otherwise openAuditSink would MkdirAll a directory literally named "~" under the
// CWD and silently misdirect the tamper-evident audit log there.
func TestExpandHome_BareTilde(t *testing.T) {
	t.Parallel()
	home, _ := os.UserHomeDir()
	result, err := ExpandHome("~")
	if err != nil {
		t.Fatalf("ExpandHome(~) error: %v", err)
	}
	if result != home {
		t.Errorf("ExpandHome(~) = %q, want %q", result, home)
	}
}

func TestExpandHome_NoTilde(t *testing.T) {
	t.Parallel()
	result, err := ExpandHome("/absolute/path")
	if err != nil {
		t.Fatalf("ExpandHome(/absolute/path) error: %v", err)
	}
	if result != "/absolute/path" {
		t.Errorf("ExpandHome(/absolute/path) = %q, want /absolute/path", result)
	}
}

func TestExpandHome_EmptyString(t *testing.T) {
	t.Parallel()
	result, err := ExpandHome("")
	if err != nil {
		t.Fatalf("ExpandHome('') error: %v", err)
	}
	if result != "" {
		t.Errorf("ExpandHome('') = %q, want ''", result)
	}
}

// TestExpandHome_HomeUnavailableFailsClosed regression: when the home
// directory cannot be resolved, ExpandHome must return an error (so openAuditSink
// refuses to start) rather than silently returning the literal "~/..." path, which
// would misplace the tamper-evident audit log under a "~" directory in the CWD.
func TestExpandHome_HomeUnavailableFailsClosed(t *testing.T) {
	// os.UserHomeDir reads $HOME on unix; clearing it makes resolution fail.
	t.Setenv("HOME", "")
	if _, err := os.UserHomeDir(); err == nil {
		t.Skip("os.UserHomeDir still resolves with HOME unset on this platform; cannot exercise the failure path")
	}
	got, err := ExpandHome("~/.eunox/audit.jsonl")
	if err == nil {
		t.Fatalf("ExpandHome returned (%q, nil); want an error when the home dir is unavailable", got)
	}
	if got != "" {
		t.Errorf("ExpandHome returned path %q alongside the error; want empty so a caller cannot use a misresolved path", got)
	}
}
