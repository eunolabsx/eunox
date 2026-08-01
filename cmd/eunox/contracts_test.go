// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/internal/config"
	"github.com/eunolabs/eunox/internal/registry"
	"github.com/eunolabs/eunox/pkg/capability"
)

// writeCorpusEntry writes one corpus entry into dir, digesting its contract so the entry
// is self-consistent unless the caller deliberately breaks it.
func writeCorpusEntry(t *testing.T, dir, file string, c registry.Contract) {
	t.Helper()
	if c.Digest == "" && c.Effect != nil {
		d, err := capability.EffectContractDigest(c.Effect)
		if err != nil {
			t.Fatalf("digest: %v", err)
		}
		c.Digest = d
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, file), b, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// validCorpusEntry is a minimal well-formed entry.
func validCorpusEntry(id, tool string) registry.Contract {
	return registry.Contract{
		SchemaVersion: registry.SchemaVersion,
		ID:            id,
		Tool:          tool,
		Server:        registry.ServerRef{Name: "example/server"},
		Attestation: registry.Attestation{
			Author: "tester",
			Source: registry.SourceAuthored,
			Review: registry.ReviewPending,
		},
		Effect: &capability.EffectContract{Class: capability.EffectReversible, Idempotent: true},
	}
}

// TestContractsVerifiesTheShippedCorpus is the whole point of the subcommand: a corpus can
// be checked without writing Go. The repository's own corpus is the one every contributor
// has, so it doubles as the smoke test that the loader and the CLI agree.
func TestContractsVerifiesTheShippedCorpus(t *testing.T) {
	var code int
	out := captureStdout(t, func() { code = cmdContracts([]string{"--dir", "../../registry/contracts"}) })
	if code != 0 {
		t.Fatalf("exit = %d, want 0\n%s", code, out)
	}
	for _, want := range []string{"every declared digest matches its content", "@sha256:", "stripe/mcp.create_refund"} {
		if !strings.Contains(out, want) {
			t.Errorf("output must contain %q, got:\n%s", want, out)
		}
	}
}

// TestContractsRejectsATamperedDigest pins the load-bearing check: a reviewed id carrying a
// rewritten contract is exactly the substitution a hash-pinned registry exists to prevent,
// so it must be an ERROR rather than a listed row.
func TestContractsRejectsATamperedDigest(t *testing.T) {
	dir := t.TempDir()
	e := validCorpusEntry("example/server.read", "read")
	e.Digest = "sha256:" + strings.Repeat("0", 64)
	writeCorpusEntry(t, dir, "read.json", e)

	var code int
	errOut := captureStderr(t, func() { code = cmdContracts([]string{"--dir", dir}) })
	if code != 2 {
		t.Fatalf("exit = %d, want 2 for a tampered entry", code)
	}
	if !strings.Contains(errOut, "does not match its content digest") {
		t.Errorf("the failure must name the digest mismatch, got: %s", errOut)
	}
}

// TestContractsRejectsDuplicateIDs pins the other corpus-level invariant: a ref must
// resolve to exactly one entry.
func TestContractsRejectsDuplicateIDs(t *testing.T) {
	dir := t.TempDir()
	writeCorpusEntry(t, dir, "a.json", validCorpusEntry("example/server.read", "read"))
	writeCorpusEntry(t, dir, "b.json", validCorpusEntry("example/server.read", "read"))

	var code int
	errOut := captureStderr(t, func() { code = cmdContracts([]string{"--dir", dir}) })
	if code != 2 {
		t.Fatalf("exit = %d, want 2 for a duplicate id", code)
	}
	if !strings.Contains(errOut, "duplicate contract id") {
		t.Errorf("the failure must name the duplicate, got: %s", errOut)
	}
}

// TestContractsRefPrintsAPastablePin covers the pin-help path: the printed value must be
// exactly what a manifest's effect.ref takes, and must be the ONLY thing on stdout so it
// can be piped.
func TestContractsRefPrintsAPastablePin(t *testing.T) {
	dir := t.TempDir()
	e := validCorpusEntry("example/server.read", "read")
	writeCorpusEntry(t, dir, "read.json", e)
	want, err := capability.EffectContractDigest(e.Effect)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}

	var code int
	out := captureStdout(t, func() { code = cmdContracts([]string{"--dir", dir, "--ref", "example/server.read"}) })
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if got := strings.TrimSpace(out); got != "example/server.read@"+want {
		t.Fatalf("pin = %q, want %q", got, "example/server.read@"+want)
	}
}

// TestContractsRefUnknownIDFails pins that a pin an author would paste always comes from an
// entry that exists — an unknown id must not print an empty line and exit 0.
func TestContractsRefUnknownIDFails(t *testing.T) {
	dir := t.TempDir()
	writeCorpusEntry(t, dir, "read.json", validCorpusEntry("example/server.read", "read"))

	var code int
	errOut := captureStderr(t, func() { code = cmdContracts([]string{"--dir", dir, "--ref", "example/server.missing"}) })
	if code != 2 {
		t.Fatalf("exit = %d, want 2 for an unknown id", code)
	}
	if !strings.Contains(errOut, "no contract with id") {
		t.Errorf("the failure must name the unknown id, got: %s", errOut)
	}
}

// TestContractsMissingDirIsAnError pins that a path that does not exist is not reported as
// an empty, valid corpus. LoadCorpus globs, so a typo'd --dir would otherwise be a clean
// bill of health for something never read.
func TestContractsMissingDirIsAnError(t *testing.T) {
	var code int
	errOut := captureStderr(t, func() { code = cmdContracts([]string{"--dir", filepath.Join(t.TempDir(), "absent")}) })
	if code != 2 {
		t.Fatalf("exit = %d, want 2 for a missing corpus directory", code)
	}
	if !strings.Contains(errOut, "cannot read corpus directory") {
		t.Errorf("the failure must name the unreadable directory, got: %s", errOut)
	}
}

// TestContractsRejectsAPositionalArgument pins the usage shape: the directory is given with
// --dir, so a positional is a mistake rather than a silently ignored token.
func TestContractsRejectsAPositionalArgument(t *testing.T) {
	var code int
	captureStderr(t, func() { code = cmdContracts([]string{"registry/contracts"}) })
	if code != 2 {
		t.Fatalf("exit = %d, want 2 for an unexpected positional", code)
	}
}

// TestEffectCoverageNamesTheWorklist covers the coverage report: the ratio is the progress
// meter and the names are what an operator acts on. Under a ceiling the line must say the
// unannotated entries ESCALATE — that is the fact "why is everything hitting the approval
// queue" needs answering.
func TestEffectCoverageNamesTheWorklist(t *testing.T) {
	m := &config.LocalManifest{
		Capabilities: []capability.Constraint{
			{Target: "tool:read_file", Effect: &capability.EffectContract{Class: capability.EffectReversible}},
			{Target: "tool:send_email"},
			// A second entry for one target is one annotation job, not two.
			{Target: "tool:send_email"},
		},
	}

	var buf bytes.Buffer
	writeEffectCoverage(&buf, "", m, true)
	got := buf.String()
	if !strings.Contains(got, "effect coverage: 1/3 capabilities annotated") {
		t.Errorf("want the annotated ratio, got:\n%s", got)
	}
	if strings.Count(got, "tool:send_email") != 1 {
		t.Errorf("an unannotated target must be listed once, got:\n%s", got)
	}
	if strings.Contains(got, "tool:read_file") {
		t.Errorf("an annotated target must not be in the worklist, got:\n%s", got)
	}
	if !strings.Contains(got, "would escalate if an effectCeiling were added") {
		t.Errorf("with no ceiling the consequence is conditional, got:\n%s", got)
	}

	m.EffectCeiling = &capability.EffectCeiling{MaxEffectClass: capability.EffectReversible}
	buf.Reset()
	writeEffectCoverage(&buf, "  ", m, true)
	got = buf.String()
	if !strings.Contains(got, "ESCALATE under this policy's effectCeiling") {
		t.Errorf("under a ceiling the consequence is present tense, got:\n%s", got)
	}
	if !strings.Contains(got, "\n      tool:send_email") {
		t.Errorf("the prefix must indent every line, got:\n%s", got)
	}
}

// TestEffectCoverageSilentOnAnEmptyManifest pins that a manifest with no capabilities
// prints nothing: "0/0 annotated" is noise, not a progress meter.
func TestEffectCoverageSilentOnAnEmptyManifest(t *testing.T) {
	var buf bytes.Buffer
	writeEffectCoverage(&buf, "", &config.LocalManifest{}, true)
	if buf.Len() != 0 {
		t.Errorf("want no output for an empty manifest, got %q", buf.String())
	}
}

// TestValidateReportsEffectCoverage pins the wiring: the ratio has to reach the surface an
// operator actually runs, which is the whole point of the accessor having a caller.
func TestValidateReportsEffectCoverage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	manifest := `schemaVersion: "0.2-draft"
name: coverage-policy
version: 0.1.0
capabilities:
  - target: "tool:read_file"
    actions: ["call"]
    effect:
      class: reversible
  - target: "tool:send_email"
    actions: ["call"]
`
	if err := os.WriteFile(path, []byte(manifest), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	var code int
	out := captureStdout(t, func() { code = cmdValidate([]string{path}) })
	if code != 0 {
		t.Fatalf("exit = %d, want 0\n%s", code, out)
	}
	if !strings.Contains(out, "effect coverage: 1/2 capabilities annotated") {
		t.Errorf("validate must report effect coverage, got:\n%s", out)
	}
	if !strings.Contains(out, "tool:send_email") {
		t.Errorf("validate must name the unannotated capability, got:\n%s", out)
	}
}

// TestEffectCoverageWithheldTargetsForTheBundle pins the doctor posture. That bundle is
// written to be pasted into a public bug report, and a capability target is a resource URI
// or a tool name ("resource:postgres://prod-billing/*"); every other manifest line there is
// deliberately a count or a digest, so this must not become the one place it leaks contents.
func TestEffectCoverageWithheldTargetsForTheBundle(t *testing.T) {
	m := &config.LocalManifest{
		Capabilities: []capability.Constraint{
			{Target: "resource:postgres://prod-billing/*"},
			{Target: "tool:transfer_funds_prod"},
		},
	}
	var buf bytes.Buffer
	writeEffectCoverage(&buf, "", m, false)
	got := buf.String()
	if !strings.Contains(got, "effect coverage: 0/2 capabilities annotated") {
		t.Errorf("the ratio must still be reported, got:\n%s", got)
	}
	if !strings.Contains(got, "unannotated: 2") {
		t.Errorf("the count must still be reported, got:\n%s", got)
	}
	for _, secret := range []string{"prod-billing", "transfer_funds_prod"} {
		if strings.Contains(got, secret) {
			t.Errorf("the redacted bundle must not name capability targets; found %q in:\n%s", secret, got)
		}
	}
}
