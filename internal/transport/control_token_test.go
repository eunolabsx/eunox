// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestControlToken_GenerateWriteResolve_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.token")

	tok, err := GenerateControlToken()
	if err != nil {
		t.Fatalf("GenerateControlToken: %v", err)
	}
	if len(tok) != 64 { // 32 random bytes, hex-encoded
		t.Fatalf("token length = %d, want 64 hex chars", len(tok))
	}

	written, err := WriteControlTokenFile(path, tok)
	if err != nil {
		t.Fatalf("WriteControlTokenFile: %v", err)
	}
	if written != path {
		t.Errorf("written path = %q, want %q", written, path)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("file mode = %o, want 0600 (control token is a secret)", perm)
	}

	got, err := ResolveControlToken("", path)
	if err != nil {
		t.Fatalf("ResolveControlToken: %v", err)
	}
	if got != tok {
		t.Errorf("resolved token = %q, want %q (round-trip, trailing newline trimmed)", got, tok)
	}
}

func TestWriteControlTokenFile_OverwritesLooseModeWith0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.token")
	// Pre-create the file world-readable (0644) to simulate a stale/loose file;
	// the atomic temp-then-rename write must still land the secret at 0600.
	if err := os.WriteFile(path, []byte("old\n"), 0o644); err != nil { //nolint:gosec // test fixture: deliberately loose mode
		t.Fatal(err)
	}
	if _, err := WriteControlTokenFile(path, "newtoken"); err != nil {
		t.Fatalf("WriteControlTokenFile: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 0600 even when the pre-existing file was 0644", perm)
	}
	got, err := ResolveControlToken("", path)
	if err != nil {
		t.Fatal(err)
	}
	if got != "newtoken" {
		t.Errorf("token = %q, want newtoken", got)
	}
}

func TestResolveControlToken_FlagBeatsEnvAndFile(t *testing.T) {
	t.Setenv("EUNOX_CONTROL_TOKEN", "from-env")
	got, err := ResolveControlToken("from-flag", "/nonexistent/path")
	if err != nil {
		t.Fatalf("ResolveControlToken: %v", err)
	}
	if got != "from-flag" {
		t.Errorf("got %q, want from-flag (explicit flag must win)", got)
	}
}

func TestResolveControlToken_EnvBeatsFile(t *testing.T) {
	t.Setenv("EUNOX_CONTROL_TOKEN", "from-env")
	got, err := ResolveControlToken("", "/nonexistent/path")
	if err != nil {
		t.Fatalf("ResolveControlToken: %v", err)
	}
	if got != "from-env" {
		t.Errorf("got %q, want from-env", got)
	}
}

func TestResolveControlToken_WhitespaceOnlyEnv_FallsThroughToFile(t *testing.T) {
	// A whitespace-only EUNOX_CONTROL_TOKEN (e.g. a lone newline) must not
	// short-circuit with an empty token: it should fall through to the file
	// source, mirroring the flag arm's trim-then-test behavior.
	t.Setenv("EUNOX_CONTROL_TOKEN", "  \n\t ")
	path := filepath.Join(t.TempDir(), "control.token")
	if _, err := WriteControlTokenFile(path, "file-token"); err != nil {
		t.Fatalf("WriteControlTokenFile: %v", err)
	}
	got, err := ResolveControlToken("", path)
	if err != nil {
		t.Fatalf("ResolveControlToken: %v", err)
	}
	if got != "file-token" {
		t.Errorf("got %q, want file-token (whitespace-only env must fall through to file)", got)
	}
}

func TestWriteControlTokenFile_TightensLooseModeDirTo0700(t *testing.T) {
	// Pre-create the control-token directory world-traversable (0755); the write
	// must tighten it to 0700 so the documented directory guarantee holds even
	// for a pre-existing looser-mode directory.
	dir := filepath.Join(t.TempDir(), "eunox")
	if err := os.Mkdir(dir, 0o755); err != nil { //nolint:gosec // test fixture: deliberately loose mode
		t.Fatal(err)
	}
	// Re-Chmod in case umask narrowed the Mkdir mode below 0755.
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // test fixture: deliberately loose mode
		t.Fatal(err)
	}
	path := filepath.Join(dir, "control.token")
	if _, err := WriteControlTokenFile(path, "tok"); err != nil {
		t.Fatalf("WriteControlTokenFile: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("dir mode = %o, want 0700 even when the pre-existing dir was 0755", perm)
	}
}

func TestResolveControlToken_MissingFile_Errors(t *testing.T) {
	t.Setenv("EUNOX_CONTROL_TOKEN", "") // isolate from ambient env
	if got, err := ResolveControlToken("", filepath.Join(t.TempDir(), "absent.token")); err == nil {
		t.Fatalf("expected error for missing token file, got token %q", got)
	}
}

func TestResolveControlToken_EmptyFile_Errors(t *testing.T) {
	t.Setenv("EUNOX_CONTROL_TOKEN", "")
	path := filepath.Join(t.TempDir(), "empty.token")
	if err := os.WriteFile(path, []byte("   \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveControlToken("", path); err == nil {
		t.Fatal("expected error for empty token file")
	}
}

func TestExpandHome_WithTilde(t *testing.T) {
	t.Parallel()
	home, _ := os.UserHomeDir()
	result, err := expandHome("~/foo/bar")
	if err != nil {
		t.Fatalf("expandHome(~/foo/bar) error: %v", err)
	}
	expected := fmt.Sprintf("%s/foo/bar", home)
	if result != expected {
		t.Errorf("expandHome(~/foo/bar) = %q, want %q", result, expected)
	}
}

// TestExpandHome_BareTilde regression: a path of exactly "~" (no
// trailing slash) must expand to the home directory, not be returned unchanged —
// otherwise openAuditSink would MkdirAll a directory literally named "~" under the
// CWD and silently misdirect the tamper-evident audit log there.
func TestExpandHome_BareTilde(t *testing.T) {
	t.Parallel()
	home, _ := os.UserHomeDir()
	result, err := expandHome("~")
	if err != nil {
		t.Fatalf("expandHome(~) error: %v", err)
	}
	if result != home {
		t.Errorf("expandHome(~) = %q, want %q", result, home)
	}
}

func TestExpandHome_NoTilde(t *testing.T) {
	t.Parallel()
	result, err := expandHome("/absolute/path")
	if err != nil {
		t.Fatalf("expandHome(/absolute/path) error: %v", err)
	}
	if result != "/absolute/path" {
		t.Errorf("expandHome(/absolute/path) = %q, want /absolute/path", result)
	}
}

func TestExpandHome_EmptyString(t *testing.T) {
	t.Parallel()
	result, err := expandHome("")
	if err != nil {
		t.Fatalf("expandHome('') error: %v", err)
	}
	if result != "" {
		t.Errorf("expandHome('') = %q, want ''", result)
	}
}

// TestExpandHome_HomeUnavailableFailsClosed regression: when the home
// directory cannot be resolved, expandHome must return an error (so openAuditSink
// refuses to start) rather than silently returning the literal "~/..." path, which
// would misplace the tamper-evident audit log under a "~" directory in the CWD.
func TestExpandHome_HomeUnavailableFailsClosed(t *testing.T) {
	// os.UserHomeDir reads $HOME on unix; clearing it makes resolution fail.
	t.Setenv("HOME", "")
	if _, err := os.UserHomeDir(); err == nil {
		t.Skip("os.UserHomeDir still resolves with HOME unset on this platform; cannot exercise the failure path")
	}
	got, err := expandHome("~/.eunox/audit.jsonl")
	if err == nil {
		t.Fatalf("expandHome returned (%q, nil); want an error when the home dir is unavailable", got)
	}
	if got != "" {
		t.Errorf("expandHome returned path %q alongside the error; want empty so a caller cannot use a misresolved path", got)
	}
}
