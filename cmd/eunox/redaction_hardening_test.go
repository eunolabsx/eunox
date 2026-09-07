// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRedactAuditLine_NonObjectDetailsFailsClosed verifies that a record
// whose `details` is a NON-object JSON value (a string/array/number) cannot be scrubbed
// field-by-field, so the map assertion skipped it and the raw value was re-emitted into
// the doctor support bundle. It must now be redacted wholesale (fail closed).
func TestRedactAuditLine_NonObjectDetailsFailsClosed(t *testing.T) {
	for _, tc := range []struct{ name, line, secret string }{
		{"string details", `{"activity_name":"deny","details":"SECRET-STRING"}`, "SECRET-STRING"},
		{"array details", `{"activity_name":"deny","details":["SECRET-ELEM"]}`, "SECRET-ELEM"},
		{"number details", `{"activity_name":"deny","details":8675309}`, "8675309"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := redactAuditLine(tc.line)
			if strings.Contains(got, tc.secret) {
				t.Errorf("non-object details leaked into the bundle: %s", got)
			}
			if !strings.Contains(got, "<redacted>") {
				t.Errorf("expected the non-object details redacted, got: %s", got)
			}
		})
	}

	// An OBJECT details is still scrubbed field-by-field, keeping keys.
	got := redactAuditLine(`{"activity_name":"deny","details":{"password":"hunter2"}}`)
	if strings.Contains(got, "hunter2") {
		t.Errorf("object details value leaked: %s", got)
	}
	if !strings.Contains(got, "password") {
		t.Errorf("object details key should be preserved: %s", got)
	}
}

// TestWriteGeneratedFile_RefusesClobberAndTightens verifies that a plain
// os.WriteFile(…, 0600) neither refuses to clobber a pre-existing file nor re-tightens a
// pre-existing looser mode (O_CREATE applies the mode only on creation). writeGeneratedFile
// must refuse to overwrite without force, and on a forced overwrite must re-tighten to 0600.
func TestWriteGeneratedFile_RefusesClobberAndTightens(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "out.yaml")

	// Fresh write lands at 0600.
	if err := writeGeneratedFile(p, "original", false); err != nil {
		t.Fatalf("fresh write: %v", err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Errorf("fresh mode = %v, want 0600", fi.Mode().Perm())
	}

	// Without force, a second write refuses to clobber and leaves the original intact.
	err := writeGeneratedFile(p, "replacement", false)
	if err == nil {
		t.Fatal("expected refusal to clobber a pre-existing file without force")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error = %v, want it to say the file already exists", err)
	}
	if b, _ := os.ReadFile(p); string(b) != "original" {
		t.Errorf("file was clobbered despite the refusal: %q", b)
	}

	// Loosen the mode (as a prior run / restore might), then force-overwrite: content is
	// replaced AND the mode is re-tightened to 0600.
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if err := writeGeneratedFile(p, "forced", true); err != nil {
		t.Fatalf("force write: %v", err)
	}
	if b, _ := os.ReadFile(p); string(b) != "forced" {
		t.Errorf("force did not overwrite: %q", b)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Errorf("force did not re-tighten mode, got %v", fi.Mode().Perm())
	}
}

// TestCmdDoctor_NeverWritesThroughASymlink pins the SAME guarantee for the other caller of
// openGuardedOutput. The two used to hold hand-mirrored copies of the guard chain, which is
// the class of duplication that drifts silently — each step covers a race the next one
// cannot, so a copy that loses one loses it with no symptom until a link is planted. Driving
// both callers against a planted link is what keeps the extraction honest.
func TestCmdDoctor_NeverWritesThroughASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "victim")
	// 0644, NOT the 0600 the guard re-tightens to: a victim created at the chain's own target
	// mode makes the re-mode assertion below unfalsifiable, which is how its sibling's copy of
	// that assertion came to assert nothing.
	if err := os.WriteFile(target, []byte("victim contents"), 0o644); err != nil { //nolint:gosec // test fixture: deliberately loose, so a re-mode is visible
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "bundle.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}

	// The bundle always truncates — there is no --force gate — so the refusal is unconditional.
	var code int
	errOut := captureStderr(t, func() {
		code = cmdDoctor([]string{"--output", link, "--audit-log", filepath.Join(dir, "absent.jsonl"), "--audit-tail", "0"})
	})
	if code == 0 {
		t.Fatal("writing the bundle to a symlinked destination must be refused")
	}
	// Asserted on the MESSAGE, not the exit code alone: doctor returns the same code from five
	// sites, so a refusal that came from a flag error would pass a code-only check while the
	// guard this test is named for did nothing.
	if !strings.Contains(errOut, "symbolic link") {
		t.Errorf("the refusal must name the symlink guard; got %q", errOut)
	}
	assertSymlinkTargetUntouched(t, target)
}

// assertSymlinkTargetUntouched is the pair of checks every planted-link test makes: the target
// was neither written through nor re-moded by the chain's fd Chmod. One helper because the
// property belongs to openGuardedOutput rather than to either caller, and a copy per caller is
// what the extraction under test exists to stop.
func assertSymlinkTargetUntouched(t *testing.T, target string) {
	t.Helper()
	b, err := os.ReadFile(target)
	if err != nil {
		// Read failure is its own finding, not evidence of a write-through: reporting it as one
		// sends the next reader after the wrong guard.
		t.Fatalf("reading the symlink target: %v", err)
	}
	if string(b) != "victim contents" {
		t.Fatalf("the symlink target was written through: %q", b)
	}
	fi, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat of the symlink target: %v", err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("the symlink target was re-moded to %v", fi.Mode().Perm())
	}
}

// TestWriteGeneratedFile_NeverWritesThroughASymlink pins the guarantee both halves of the
// symlink guard exist for: a link planted at the destination must never have its TARGET
// truncated (and then re-moded 0600 by the fd Chmod). The Lstat refusal names the path,
// and config.OpenNoFollow makes the kernel refuse it too, so the guarantee survives losing
// either one — the open resolves the path a second time, and a link planted in that window
// is what the flag is there to catch.
func TestWriteGeneratedFile_NeverWritesThroughASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "victim")
	if err := os.WriteFile(target, []byte("victim contents"), 0o644); err != nil { //nolint:gosec // test fixture: deliberately loose, so a re-mode is visible
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "out.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}

	// force is the path that drops O_EXCL (which refuses a symlink for free) for O_TRUNC.
	if err := writeGeneratedFile(link, "attacker", true); err == nil {
		t.Fatal("a forced overwrite of a symlinked destination must be refused")
	}
	assertSymlinkTargetUntouched(t, target)
}
