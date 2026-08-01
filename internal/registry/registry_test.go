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
	// The Phase-B deliverable is ten real public-server contracts; the gate is a floor,
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
