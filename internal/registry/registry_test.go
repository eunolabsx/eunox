// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
)

// corpusDir is the shipped contract corpus, relative to this package.
const corpusDir = "../../registry/contracts"

// TestShippedCorpusLoadsAndVerifies is the corpus's own gate: every shipped contract
// parses, validates, and — the load-bearing part — digests to exactly what it declares.
// Without this, an entry could carry a reviewed id and a rewritten contract, which is the
// substitution a hash-pinned registry exists to prevent.
func TestShippedCorpusLoadsAndVerifies(t *testing.T) {
	contracts, err := LoadCorpus(corpusDir)
	if err != nil {
		t.Fatalf("the shipped corpus must load and verify: %v", err)
	}
	// The shipped corpus targets ten real public-server contracts; the gate is a floor,
	// not an exact count, so adding one does not fail the build.
	if len(contracts) < 10 {
		t.Fatalf("the corpus must carry at least 10 contracts, got %d", len(contracts))
	}
}

// TestShippedCorpusIsReviewable pins the properties that make an entry worth reviewing
// rather than merely present: it names a real server, says what the tool does, and — where
// the class is not the obvious reading — says why.
func TestShippedCorpusIsReviewable(t *testing.T) {
	contracts, err := LoadCorpus(corpusDir)
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}
	for _, c := range contracts {
		if c.Summary == "" {
			t.Errorf("contract %q has no summary; a reviewer cannot check a claim that was never stated", c.ID)
		}
		if c.Server.Homepage == "" {
			t.Errorf("contract %q names no homepage; a reviewer needs somewhere to check the claim", c.ID)
		}
		// A compensable class is the one most easily mislabeled — "there is an undo" is
		// how an irreversible action gets waved through a consequence gate — so it must
		// carry the reasoning, not just the verdict.
		if c.Effect.Class == capability.EffectCompensable && c.Notes == "" {
			t.Errorf("contract %q declares compensable with no notes; compensable is not safe, and the reasoning is the reviewable part", c.ID)
		}
		if !strings.Contains(c.ID, "."+c.Tool) {
			t.Errorf("contract %q must end in .%s so an id identifies its tool unambiguously", c.ID, c.Tool)
		}
	}
}

// TestCorpusRefsPinIntoAManifest pins the end-to-end property the registry exists for: an
// entry's Ref, copied into a manifest capability alongside the contract, verifies at
// manifest load — and a tampered contract does not.
func TestCorpusRefsPinIntoAManifest(t *testing.T) {
	contracts, err := LoadCorpus(corpusDir)
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}
	c := contracts[0]

	pinned := *c.Effect
	pinned.Ref = c.Ref()
	digest, err := capability.EffectContractDigest(&pinned)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	_, want, ok := capability.SplitEffectRef(c.Ref())
	if !ok {
		t.Fatalf("Ref() must be splittable, got %q", c.Ref())
	}
	if digest != want {
		t.Fatalf("a contract carrying its own ref must still digest to that ref (ref is excluded from the digest): got %s, want %s", digest, want)
	}

	// Tamper with the contract while keeping the pin: the digest must move. Flipping a
	// boolean rather than setting a class guarantees a real change whichever entry sorts
	// first, so the assertion cannot pass by accident on a contract that already had the
	// value being set.
	tampered := pinned
	tampered.Idempotent = !tampered.Idempotent
	after, err := capability.EffectContractDigest(&tampered)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if after == want {
		t.Fatal("editing a pinned contract must change its digest, or the pin secures nothing")
	}
}

// TestValidateRejectsATamperedEntry covers the deny cases of the entry validator, each of
// which is a shape that would leave a corpus consumer trusting something it should not.
func TestValidateRejectsATamperedEntry(t *testing.T) {
	good := func() Contract {
		e := &capability.EffectContract{Class: capability.EffectReversible}
		d, err := capability.EffectContractDigest(e)
		if err != nil {
			t.Fatalf("digest: %v", err)
		}
		return Contract{
			SchemaVersion: SchemaVersion, ID: "acme/server.tool", Tool: "tool",
			Server:      ServerRef{Name: "acme-server"},
			Attestation: Attestation{Author: "acme", Source: SourceAuthored, Review: ReviewPending},
			Digest:      d, Effect: e,
		}
	}
	base := good()
	if err := base.Validate(); err != nil {
		t.Fatalf("the well-formed entry must validate: %v", err)
	}

	cases := []struct {
		name    string
		mutate  func(*Contract)
		wantErr string
	}{
		{"unknown schema version", func(c *Contract) { c.SchemaVersion = "9.9" }, "not one this build models"},
		{"missing id", func(c *Contract) { c.ID = "" }, "missing 'id'"},
		{"missing tool", func(c *Contract) { c.Tool = "" }, "missing 'tool'"},
		{"missing server name", func(c *Contract) { c.Server.Name = "" }, "missing 'server.name'"},
		{"missing author", func(c *Contract) { c.Attestation.Author = "" }, "missing 'attestation.author'"},
		{"unknown source", func(c *Contract) { c.Attestation.Source = "vibes" }, "attestation.source"},
		{"unknown review state", func(c *Contract) { c.Attestation.Review = "trust me" }, "attestation.review"},
		{"missing effect", func(c *Contract) { c.Effect = nil }, "missing 'effect'"},
		{"self-referential ref", func(c *Contract) { c.Effect.Ref = "x@sha256:0" }, "must not carry its own 'ref'"},
		{"digest does not match content", func(c *Contract) { c.Effect.Class = capability.EffectIrreversible }, "does not match its content digest"},
		// The id is the half of Ref() before the "@", and SplitEffectRef cuts at the
		// first one — so an id carrying an "@" digests cleanly here and yields a ref
		// that can never resolve, surfacing much later as a mismatch at manifest load.
		{"id contains @", func(c *Contract) { c.ID = "acme/server@v2.tool" }, "'@'"},
		{"id has leading whitespace", func(c *Contract) { c.ID = " acme/server.tool" }, "whitespace"},
		{"id has trailing whitespace", func(c *Contract) { c.ID = "acme/server.tool " }, "whitespace"},
		{"id has an interior space", func(c *Contract) { c.ID = "acme/my server.tool" }, "whitespace"},
		// Nothing else catches an entry attesting one tool under another's name: every
		// later layer treats the id as the entry's identity.
		{"id does not name its tool", func(c *Contract) { c.Tool = "other_tool" }, `must end in ".other_tool"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := good()
			tc.mutate(&c)
			err := c.Validate()
			if err == nil {
				t.Fatal("this entry must be refused")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q must mention %q", err, tc.wantErr)
			}
		})
	}
}

// TestCorpusRefRoundTripsThroughSplitEffectRef pins Validate's id rules against the
// consumer that makes them matter: every valid entry's Ref() must split back into exactly
// the id and digest it was built from. That is the property an id containing "@" (or
// stray whitespace) silently broke — the entry validated, and only a manifest pinning it
// ever found out.
func TestCorpusRefRoundTripsThroughSplitEffectRef(t *testing.T) {
	corpus, err := LoadCorpus("../../registry/contracts")
	if err != nil {
		t.Fatalf("LoadCorpus: %v", err)
	}
	if len(corpus) == 0 {
		t.Fatal("the shipped corpus must not be empty")
	}
	for _, c := range corpus {
		id, digest, ok := capability.SplitEffectRef(c.Ref())
		if !ok {
			t.Errorf("contract %q: Ref() %q does not split", c.ID, c.Ref())
			continue
		}
		if id != c.ID || digest != c.Digest {
			t.Errorf("contract %q: Ref() split to (%q, %q), want (%q, %q)", c.ID, id, digest, c.ID, c.Digest)
		}
	}
}

// TestLoadCorpusRejectsDuplicateIDs pins that a ref resolves to exactly one entry: two
// files claiming one id would make "which contract was reviewed" unanswerable.
func TestLoadCorpusRejectsDuplicateIDs(t *testing.T) {
	dir := t.TempDir()
	e := &capability.EffectContract{Class: capability.EffectReversible}
	d, err := capability.EffectContractDigest(e)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	entry := Contract{
		SchemaVersion: SchemaVersion, ID: "acme/server.tool", Tool: "tool",
		Server:      ServerRef{Name: "acme-server"},
		Attestation: Attestation{Author: "acme", Source: SourceAuthored, Review: ReviewPending},
		Digest:      d, Effect: e,
	}
	body, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, name := range []string{"a.json", "b.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if _, err := LoadCorpus(dir); err == nil || !strings.Contains(err.Error(), "duplicate contract id") {
		t.Fatalf("two entries with one id must be refused, got %v", err)
	}
}

// TestLoadCorpusBoundsEachEntryRead pins the same rule the trust-store loader states two
// files over: the corpus directory is operator-supplied, so a --dir fat-fingered at a data
// directory holding a multi-gigabyte .json must produce an error, not an OOM. Each entry was
// read with a bare os.ReadFile and buffered whole before the strict decode could reject it. A
// real entry is a few kilobytes.
func TestLoadCorpusBoundsEachEntryRead(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "huge.json"), make([]byte, maxContractFileBytes+1), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := LoadCorpus(dir)
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("an oversized corpus entry must be refused rather than buffered, got %v", err)
	}
	// It ERRORS rather than truncating: a truncated read would fail the decode for a reason
	// that looks like a malformed entry.
	if strings.Contains(err.Error(), "unknown field") || strings.Contains(err.Error(), "unexpected end") {
		t.Fatalf("the bound must be reported as a size refusal, not as a decode failure: %v", err)
	}
}

// TestLoadCorpusRejectsANonRegularEntry: os.ReadDir's
// DirEntry.IsDir() excludes directories but not other special files, so a FIFO named
// "*.json" would reach config.ReadBoundedFile's io.ReadAll(io.LimitReader(...)) and hang
// the CLI forever waiting for a writer that never comes — the trust-store loader already
// guards this (RefuseNonRegularPath), and LoadCorpus needs the same floor. A symlink
// stands in for the special-file case here since it is portable across CI platforms; the
// fix is the same os.Lstat-based check either way, not a FIFO-specific one.
func TestLoadCorpusRejectsANonRegularEntry(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "real.json")
	e := &capability.EffectContract{Class: capability.EffectReversible}
	d, err := capability.EffectContractDigest(e)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	entry := Contract{
		SchemaVersion: SchemaVersion, ID: "acme/server.tool", Tool: "tool",
		Server:      ServerRef{Name: "acme-server"},
		Attestation: Attestation{Author: "acme", Source: SourceAuthored, Review: ReviewPending},
		Digest:      d, Effect: e,
	}
	body, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(target, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	link := filepath.Join(dir, "acme.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := LoadCorpus(dir); err == nil {
		t.Fatal("a non-regular corpus entry must be refused, not opened")
	}
}

// TestLoadCorpusRejectsAnUnknownField pins strict decoding: a misspelled key in a corpus
// entry decodes to nothing, and "nothing" in an effect contract means the fail-closed
// default rather than what the author wrote — a difference the file itself would hide.
func TestLoadCorpusRejectsAnUnknownField(t *testing.T) {
	dir := t.TempDir()
	body := `{"schemaVersion":"0.1","id":"a/b.c","tool":"c","serverr":{"name":"x"},
	          "attestation":{"author":"a","source":"authored","review":"pending"},
	          "digest":"sha256:0","effect":{"class":"reversible"}}`
	if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadCorpus(dir); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("an unknown corpus field must be refused, got %v", err)
	}
}
