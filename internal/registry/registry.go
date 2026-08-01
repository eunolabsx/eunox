// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Package registry holds the effect-contract corpus format: the envelope that wraps a
// capability.EffectContract with the identity, provenance, and content digest a shared
// corpus needs, plus the loader that reads and verifies a corpus directory.
//
// The registry is AUTHORING-TIME input, not a runtime dependency. eunox never fetches a
// contract while deciding: a manifest carries the contract inline and optionally pins the
// registry entry it was authored from via `effect.ref`, which the manifest loader verifies
// LOCALLY by recomputing the digest. That keeps the decision path free of network I/O and
// makes a registry outage unable to change a verdict — while still giving the pin real
// integrity, because the digest is over the contract's own content.
//
// Trust model — package signing, NOT behavioral verification. A contract asserts what a
// tool does; nothing here observes whether it is telling the truth. The corpus is
// reviewable (a closed typed schema a human can read), pinnable (a content digest), and
// attributable (an attestation naming who authored and reviewed it). It is not a scanner
// verdict, and a mismatch between a contract and observed behavior is a community-advisory
// signal, never a detection claim.
package registry

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/eunolabs/eunox/pkg/capability"
)

// SchemaVersion is the corpus entry grammar version. It is independent of the manifest
// schemaVersion: a registry entry is a distributed artifact with its own compatibility
// story, and coupling the two would force a corpus republish on every manifest grammar
// bump.
const SchemaVersion = "0.1"

// Contract is one corpus entry: an effect contract plus the identity, provenance, and
// digest that let it be shared, pinned, and reviewed.
type Contract struct {
	// SchemaVersion is the entry grammar version. Required and fail-closed: an entry
	// declaring a version this build does not model is refused rather than parsed under a
	// grammar it may not fully understand.
	SchemaVersion string `json:"schemaVersion"`
	// ID is the corpus-unique contract identifier, "<publisher>/<server>.<tool>". It is
	// the half of a manifest `effect.ref` before the '@'.
	ID string `json:"id"`
	// Tool is the advertised MCP tool name this contract describes.
	Tool string `json:"tool"`
	// Server identifies the MCP server that advertises the tool.
	Server ServerRef `json:"server"`
	// Summary is a one-line description of what the tool does. Prose, for a human
	// reviewer — never parsed, and never an input to any decision.
	Summary string `json:"summary,omitempty"`
	// Notes records the REASONING behind a class, especially where the obvious reading is
	// wrong (why an action that looks undoable is irreversible, why a compensable one is
	// not therefore safe). It is the part of a contract a reviewer actually reviews.
	Notes string `json:"notes,omitempty"`
	// Attestation records who authored the entry and what review it has had. It is the
	// trust surface, and it is deliberately modest: authorship and review state, not a
	// verification claim.
	Attestation Attestation `json:"attestation"`
	// Digest is EffectContractDigest of Effect — the value a manifest pins after the '@'
	// in `effect.ref`. Stored rather than only computed so a corpus consumer can detect a
	// tampered entry without re-deriving the encoding, and so the file is self-describing.
	Digest string `json:"digest"`
	// Effect is the contract itself, in exactly the shape a manifest capability carries.
	// One type, so an author copies the block across with no translation step where the
	// two could drift.
	Effect *capability.EffectContract `json:"effect"`
}

// ServerRef identifies the MCP server a contract's tool belongs to.
type ServerRef struct {
	// Name is the package or service identifier as its publisher spells it.
	Name string `json:"name"`
	// Homepage is where a reviewer goes to check the claim.
	Homepage string `json:"homepage,omitempty"`
	// VersionRange optionally narrows the entry to server versions whose advertised
	// surface matches what was reviewed. Empty means the contract is believed stable
	// across versions — which is a claim, so record it deliberately.
	VersionRange string `json:"versionRange,omitempty"`
}

// Attestation records a contract's provenance and review state.
type Attestation struct {
	// Author is who wrote the entry.
	Author string `json:"author"`
	// Source is how it was produced: "authored" (written by hand from the tool's
	// documented behavior), "vendor" (contributed by the server's publisher), or
	// "imported" (derived from an orchestrator's existing compensation definitions, e.g.
	// a SAGA workflow — has-compensation implies compensable, neither-compensated-nor-
	// idempotent implies irreversible).
	Source string `json:"source"`
	// Review is the review state: "pending", "community", or "vendor". It is not a
	// correctness guarantee — see the package trust-model note.
	Review string `json:"review"`
}

// Corpus source values.
const (
	SourceAuthored = "authored"
	SourceVendor   = "vendor"
	SourceImported = "imported"
)

// Corpus review states.
const (
	ReviewPending   = "pending"
	ReviewCommunity = "community"
	ReviewVendor    = "vendor"
)

var validSources = map[string]bool{SourceAuthored: true, SourceVendor: true, SourceImported: true}
var validReviews = map[string]bool{ReviewPending: true, ReviewCommunity: true, ReviewVendor: true}

// Ref returns the manifest pin for this entry: "<id>@<digest>", the value an author
// copies into a capability's `effect.ref`.
func (c *Contract) Ref() string { return c.ID + "@" + c.Digest }

// Validate checks one entry: a known grammar version, the required identity fields, a
// recognized attestation, and — the load-bearing one — a digest that matches the
// contract's actual content.
//
// The digest check is what makes the corpus worth anything. Without it an entry could
// carry a reviewed id and a rewritten contract, which is precisely the substitution a
// hash-pinned registry exists to prevent; the same check runs again at manifest load
// against the inline copy, so tampering has to survive both.
func (c *Contract) Validate() error {
	if c.SchemaVersion != SchemaVersion {
		return fmt.Errorf("contract %q: schemaVersion %q is not one this build models (want %q)", c.ID, c.SchemaVersion, SchemaVersion)
	}
	if strings.TrimSpace(c.ID) == "" {
		return fmt.Errorf("contract entry is missing 'id'")
	}
	if strings.TrimSpace(c.Tool) == "" {
		return fmt.Errorf("contract %q is missing 'tool'", c.ID)
	}
	if strings.TrimSpace(c.Server.Name) == "" {
		return fmt.Errorf("contract %q is missing 'server.name'", c.ID)
	}
	if strings.TrimSpace(c.Attestation.Author) == "" {
		return fmt.Errorf("contract %q is missing 'attestation.author'", c.ID)
	}
	if !validSources[c.Attestation.Source] {
		return fmt.Errorf("contract %q: attestation.source %q is not one of %s", c.ID, c.Attestation.Source, sortedKeys(validSources))
	}
	if !validReviews[c.Attestation.Review] {
		return fmt.Errorf("contract %q: attestation.review %q is not one of %s", c.ID, c.Attestation.Review, sortedKeys(validReviews))
	}
	if c.Effect == nil {
		return fmt.Errorf("contract %q is missing 'effect'", c.ID)
	}
	if c.Effect.Ref != "" {
		return fmt.Errorf("contract %q: the 'effect' block must not carry its own 'ref' — a corpus entry IS the thing a ref points at, and a self-reference is excluded from the digest", c.ID)
	}
	actual, err := capability.EffectContractDigest(c.Effect)
	if err != nil {
		return fmt.Errorf("contract %q: %w", c.ID, err)
	}
	if actual != c.Digest {
		return fmt.Errorf("contract %q: declared digest %s does not match its content digest %s — the entry was edited without re-digesting", c.ID, c.Digest, actual)
	}
	return nil
}

// LoadCorpus reads every *.json entry in dir, validates each, and returns them sorted by
// id. It fails on the FIRST invalid entry rather than skipping it: a corpus that silently
// drops an unreadable contract would let a tampered file disappear instead of raising an
// alarm.
func LoadCorpus(dir string) ([]Contract, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, fmt.Errorf("scanning contract corpus %q: %w", dir, err)
	}
	sort.Strings(paths)
	out := make([]Contract, 0, len(paths))
	seen := make(map[string]string, len(paths))
	for _, p := range paths {
		data, err := os.ReadFile(p) //nolint:gosec // G304: corpus path derived from the caller-supplied directory
		if err != nil {
			return nil, fmt.Errorf("reading contract %q: %w", p, err)
		}
		var c Contract
		dec := json.NewDecoder(strings.NewReader(string(data)))
		dec.DisallowUnknownFields()
		// UseNumber keeps a blast-radius literal exact: a magnitude above 2^53 widened to
		// float64 would round, and the digest is computed over the decoded value, so the
		// entry would fail its own digest check for a reason that looks like tampering.
		dec.UseNumber()
		if err := dec.Decode(&c); err != nil {
			return nil, fmt.Errorf("parsing contract %q: %w", p, err)
		}
		if err := c.Validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(p), err)
		}
		if prev, dup := seen[c.ID]; dup {
			return nil, fmt.Errorf("duplicate contract id %q in %s and %s — a ref must resolve to exactly one entry", c.ID, prev, filepath.Base(p))
		}
		seen[c.ID] = filepath.Base(p)
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// sortedKeys renders a validation set for a deterministic error message.
func sortedKeys(m map[string]bool) string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return strings.Join(ks, ", ")
}
