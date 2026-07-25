// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"io"
	"os"
	"path/filepath"
	"strings"
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

func TestWriteControlTokenFile_DoesNotMutatePreexistingDirMode(t *testing.T) {
	// A PRE-EXISTING directory eunox did not create must NOT be force-chmod'd: doing so
	// could strip /tmp's sticky bit as root or fail with EPERM on a dir the user doesn't
	// own. The write must succeed and LEAVE the 0755 mode intact (a warning is emitted to
	// stderr, which the operator can act on).
	dir := filepath.Join(t.TempDir(), "eunox")
	if err := os.Mkdir(dir, 0o755); err != nil { //nolint:gosec // test fixture: deliberately loose mode
		t.Fatal(err)
	}
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
	if perm := info.Mode().Perm(); perm != 0o755 {
		t.Errorf("dir mode = %o, want it LEFT at 0755 (eunox must not chmod a pre-existing dir it did not create)", perm)
	}
}

func TestWriteControlTokenFile_TightensDirItCreatesTo0700(t *testing.T) {
	// A directory eunox itself creates (via MkdirAll) IS at 0700 — the guarantee still
	// holds for a path eunox owns.
	base := t.TempDir()
	dir := filepath.Join(base, "created-by-eunox")
	path := filepath.Join(dir, "control.token")
	if _, err := WriteControlTokenFile(path, "tok"); err != nil {
		t.Fatalf("WriteControlTokenFile: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("dir mode = %o, want 0700 for a directory eunox created", perm)
	}
}

func TestWriteControlTokenFile_WarnsOnPreexistingLooseDir(t *testing.T) {
	// The compensating control for NOT chmod'ing a pre-existing dir is a stderr WARNING;
	// assert it actually fires so a future change cannot silently drop or narrow the only
	// signal left to the operator once the 0700 force-chmod was removed. A group-only
	// (0750) fixture pins the GROUP leg of the 0o077 mask specifically: narrowing the check
	// to 0o007 (world-only) would stop warning here and fail this test.
	dir := filepath.Join(t.TempDir(), "eunox")
	if err := os.Mkdir(dir, 0o750); err != nil { //nolint:gosec // test fixture: deliberately loose mode
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o750); err != nil { //nolint:gosec // test fixture: deliberately loose mode
		t.Fatal(err)
	}

	// Capture os.Stderr for the duration of the write.
	origStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	_, writeErr := WriteControlTokenFile(filepath.Join(dir, "control.token"), "tok")
	os.Stderr = origStderr
	_ = w.Close()

	if writeErr != nil {
		t.Fatalf("WriteControlTokenFile: %v", writeErr)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(out); !strings.Contains(got, "WARNING") || !strings.Contains(got, "group/world-accessible") {
		t.Errorf("expected a group/world-accessible WARNING on stderr for a pre-existing 0750 dir, got %q", got)
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
