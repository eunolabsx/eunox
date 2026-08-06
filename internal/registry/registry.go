// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Package registry holds the effect-contract corpus format: the envelope wrapping a
// capability.EffectContract with identity, provenance, and content digest, plus the
// loader that reads and verifies a corpus directory.
//
// AUTHORING-TIME input, never a runtime dependency: a manifest pins a registry entry via
// `effect.ref`, verified LOCALLY by recomputing the digest, so the decision path stays
// free of network I/O and a registry outage cannot change a verdict.
//
// Trust model is package signing, not behavioral verification — a contract asserts what a
// tool does, and a mismatch with observed behavior is a community-advisory signal, never
// a detection claim.
package registry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/eunolabs/eunox/internal/config"
	"github.com/eunolabs/eunox/pkg/capability"
)

// SchemaVersion is the corpus entry grammar version, independent of the manifest
// schemaVersion — coupling the two would force a corpus republish on every manifest
// grammar bump.
const SchemaVersion = "0.1"

// Contract is one corpus entry: an effect contract plus the identity, provenance, and
// digest that let it be shared, pinned, and reviewed.
type Contract struct {
	// SchemaVersion is the entry grammar version; required and fail-closed against a
	// version this build doesn't model.
	SchemaVersion string `json:"schemaVersion"`
	// ID is the corpus-unique contract identifier, "<publisher>/<server>.<tool>". It is
	// the half of a manifest `effect.ref` before the '@'.
	ID string `json:"id"`
	// Tool is the advertised MCP tool name this contract describes.
	Tool string `json:"tool"`
	// Server identifies the MCP server that advertises the tool.
	Server ServerRef `json:"server"`
	// Summary is a one-line description of what the tool does. Prose, for a human
	// reviewer — never parsed, and never an input to any decision. NOT covered by
	// AttestationPayload (see Signatures below): a signature does not attest to this text.
	Summary string `json:"summary,omitempty"`
	// Notes records the REASONING behind a class, especially where the obvious reading
	// is wrong — the part of a contract a reviewer actually reviews. NOT covered by
	// AttestationPayload: a signature does not attest to this text.
	Notes string `json:"notes,omitempty"`
	// Attestation records who authored the entry and what review it's had —
	// deliberately modest: authorship/review state, not a verification claim. NOT covered
	// by AttestationPayload: the Attestation block itself is provenance ABOUT a signature,
	// not content a signature covers.
	Attestation Attestation `json:"attestation"`
	// Signatures turns the effect content into something a second party asserted with a
	// key; verified LOCALLY, never on the decision path (attest.go). Deliberately OUTSIDE
	// the digest — including them would be circular, since each signature is over that
	// digest.
	//
	// SCOPE: AttestationPayload covers only id, effect content digest, role, and
	// statement — never Summary, Notes, Server, or the Attestation provenance block above.
	// A distributed entry can have its reviewer-facing Notes rewritten or its Server.Name
	// swapped and still pass VerifyAttestations; a signature attests to "this entry's
	// effect content", not to the entry as a whole. Reviewers evaluating a signed entry's
	// prose should treat it as unauthenticated.
	Signatures []Signature `json:"signatures,omitempty"`
	// Digest is EffectContractDigest of Effect — the value a manifest pins after the
	// '@' in `effect.ref`. Stored, not only computed, so the file is self-describing.
	Digest string `json:"digest"`
	// Effect is the contract itself, in the exact shape a manifest capability carries —
	// one type, so copying it across needs no translation step.
	Effect *capability.EffectContract `json:"effect"`
}

// ServerRef identifies the MCP server a contract's tool belongs to.
type ServerRef struct {
	// Name is the package or service identifier as its publisher spells it.
	Name string `json:"name"`
	// Homepage is where a reviewer goes to check the claim.
	Homepage string `json:"homepage,omitempty"`
	// VersionRange optionally narrows to server versions whose surface matches what
	// was reviewed; empty is itself a claim of stability.
	VersionRange string `json:"versionRange,omitempty"`
}

// Attestation records a contract's provenance and review state.
type Attestation struct {
	// Author is who wrote the entry.
	Author string `json:"author"`
	// Source is how it was produced: "authored" (from the tool's documented behavior),
	// "vendor" (from the publisher), or "imported" (derived from an orchestrator's
	// existing compensation definitions, e.g. a SAGA workflow).
	Source string `json:"source"`
	// Review is the review state: "pending", "community", or "vendor" — not a
	// correctness guarantee.
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

// Ref returns the manifest pin for this entry: "<id>@<digest>". Reads the DECLARED
// digest deliberately (unlike contentDigest) — a pin is what the file says it is, and
// Validate has already refused any mismatch.
func (c *Contract) Ref() string { return c.ID + "@" + c.Digest }

// contentDigest is the digest of the entry's own content, recomputed on every call
// rather than cached — Effect is a pointer, so a cache would let an in-process rewrite
// of it pass VerifyAttestations as still verified.
func (c *Contract) contentDigest() (string, error) {
	return capability.EffectContractDigest(c.Effect)
}

// Validate checks one entry: grammar version, identity fields, attestation, and — the
// load-bearing one — that the digest matches the actual content; the same check runs
// again at manifest load, so tampering has to survive both.
func (c *Contract) Validate() error {
	if c.SchemaVersion != SchemaVersion {
		return fmt.Errorf("contract %q: schemaVersion %q is not one this build models (want %q)", c.ID, c.SchemaVersion, SchemaVersion)
	}
	if strings.TrimSpace(c.ID) == "" {
		return fmt.Errorf("contract entry is missing 'id'")
	}
	// The id is the only free-form field in the signed payload; refusing a newline
	// keeps field boundaries a property of the format, not an argument.
	if strings.ContainsAny(c.ID, "\r\n") {
		return fmt.Errorf("contract %q: 'id' contains a line break; an id is a vendor/tool slug and is embedded verbatim in the signed attestation payload", c.ID)
	}
	// The id is also the half of Ref() before "@", and SplitEffectRef cuts at the
	// FIRST "@" — an id containing one would validate here but produce a ref that can
	// never resolve.
	if strings.ContainsRune(c.ID, '@') {
		return fmt.Errorf("contract %q: 'id' contains '@', which separates the id from the digest in the 'effect.ref' pin this entry serves — its ref could never resolve", c.ID)
	}
	if strings.ContainsAny(c.ID, " \t") || c.ID != strings.TrimSpace(c.ID) {
		return fmt.Errorf("contract %q: 'id' contains whitespace; an id is a vendor/tool slug copied verbatim into an 'effect.ref' pin", c.ID)
	}
	if strings.TrimSpace(c.Tool) == "" {
		return fmt.Errorf("contract %q is missing 'tool'", c.ID)
	}
	// The id ends in "." + tool, so an entry cannot attest one tool under another's
	// name — nothing else catches that mislabelling.
	if suffix := "." + c.Tool; !strings.HasSuffix(c.ID, suffix) {
		return fmt.Errorf("contract %q: 'id' must end in %q to match its 'tool' (an id is \"<publisher>/<server>.<tool>\")", c.ID, suffix)
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
	// The contract must be SEMANTICALLY valid, not merely digest-consistent — a digest
	// over nonsense is still stable. Uses the SAME rules the manifest loader applies
	// (pkg/capability), so the two layers cannot disagree about what a valid contract is.
	if err := capability.ValidateEffectContract(c.Effect); err != nil {
		return fmt.Errorf("contract %q: %w", c.ID, err)
	}
	actual, err := capability.EffectContractDigest(c.Effect)
	if err != nil {
		return fmt.Errorf("contract %q: %w", c.ID, err)
	}
	if actual != c.Digest {
		return fmt.Errorf("contract %q: declared digest %s does not match its content digest %s — the entry was edited without re-digesting", c.ID, c.Digest, actual)
	}
	// Structural validation only; signature VERIFICATION needs a trust store and
	// happens in VerifyAttestations. Refused here so a corpus cannot carry a signature
	// that looks like assurance in a listing but turns out to be unevaluable.
	seenSig := make(map[string]bool, len(c.Signatures))
	for i := range c.Signatures {
		if err := c.Signatures[i].Validate(c.ID); err != nil {
			return err
		}
		// One statement per key per entry — two would be either a duplicate or a
		// contradiction a report can't render honestly.
		k := c.Signatures[i].KeyID
		if seenSig[k] {
			return fmt.Errorf("contract %q: key %q signs this entry more than once; one statement per key", c.ID, k)
		}
		seenSig[k] = true
	}
	return nil
}

// strictDecodeJSON is the one JSON reader for a document on disk: unknown fields
// refused, and trailing content after the first value refused (catches two concatenated
// objects, where Decode would otherwise silently read only the first).
//
// useNumber preserves integer literals beyond float64's exact range — matters for a
// contract's blast radius, not for a key file.
func strictDecodeJSON(data []byte, target any, what string, useNumber bool) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if useNumber {
		dec.UseNumber()
	}
	if err := dec.Decode(target); err != nil {
		return fmt.Errorf("parsing %s: %w", what, err)
	}
	if dec.More() {
		return fmt.Errorf("parsing %s: trailing content after the first JSON object", what)
	}
	return nil
}

// LoadCorpus reads every *.json entry in dir, validates each, and returns them sorted by
// id. Fails on the FIRST invalid entry rather than skipping it — silently dropping one
// would let a tampered file disappear instead of raising an alarm.
func LoadCorpus(dir string) ([]Contract, error) {
	// os.ReadDir, not filepath.Glob: Glob re-interprets the directory itself as a
	// pattern, so a name with a metacharacter ("mcp[v2]") silently matched nothing — a
	// clean bill of health for files that were never read.
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("scanning contract corpus %q: %w", dir, err)
	}
	var paths []string
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		paths = append(paths, filepath.Join(dir, e.Name()))
	}
	sort.Strings(paths)
	out := make([]Contract, 0, len(paths))
	seen := make(map[string]string, len(paths))
	for _, p := range paths {
		// The trust-store loader already guards this (attest.go); a corpus entry needs
		// the same floor. os.ReadDir's DirEntry.IsDir() above only excludes directories —
		// a FIFO or other special file named "*.json" would still reach
		// config.ReadBoundedFile below, whose io.ReadAll(io.LimitReader(...)) blocks
		// forever waiting for a writer that will never come, hanging the CLI on a
		// directory an attacker (or a stray mkfifo) can plant into.
		if err := config.RefuseNonRegularPath(p, "contract"); err != nil {
			return nil, err
		}
		data, err := config.ReadBoundedFile(config.BoundedRead{
			Path:      p,
			What:      "contract",
			Max:       maxContractFileBytes,
			OverLimit: "refusing to buffer it rather than decoding a corpus entry that cannot be one",
		})
		if err != nil {
			return nil, err
		}
		var c Contract
		// UseNumber keeps a blast-radius literal exact — a magnitude above 2^53
		// widened to float64 would round and fail its own digest check.
		if err := strictDecodeJSON(data, &c, fmt.Sprintf("contract %q", p), true); err != nil {
			return nil, err
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

// maxContractFileBytes bounds one corpus entry's read against a MISDIRECTED --dir path
// (a multi-gigabyte .json) that would otherwise be buffered whole before
// strictDecodeJSON could reject it — an OOM where an error belongs.
const maxContractFileBytes = 1 << 20

// sortedKeys renders a validation set for a deterministic error message. The collect-and-sort
// is sortedSet's (attest.go); this is that plus the join, so one function orders a set in this
// package rather than two with near-identical bodies.
func sortedKeys(m map[string]bool) string {
	return strings.Join(sortedSet(m), ", ")
}
