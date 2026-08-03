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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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
	// Signatures carries signed statements about this entry — a vendor attesting that the
	// contract describes their tool, a reviewer who read it, or either DISPUTING it. They
	// are what turns the Attestation block above from an unverifiable label into something
	// a second party asserted with a key.
	//
	// They are verified LOCALLY against a trust store the operator points at, at
	// `eunox contracts` time and never on the decision path (see attest.go). They are also
	// deliberately OUTSIDE the digest: the digest is over the effect contract's own content,
	// and each signature is over that digest, so including them would be circular and would
	// mean every new countersignature invalidated every manifest pin to the entry.
	Signatures []Signature `json:"signatures,omitempty"`
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
//
// It reads the DECLARED digest deliberately, unlike contentDigest: a pin is what the file
// says it is, and Validate has already refused any entry where the two differ — so on a
// loaded corpus they are the same string, and on a hand-built Contract this reports what
// the caller declared rather than silently correcting it.
func (c *Contract) Ref() string { return c.ID + "@" + c.Digest }

// contentDigest is the digest of the entry's own CONTENT, recomputed on every call.
//
// Every consumer that binds a signature to an entry must use this rather than c.Digest:
// signing or verifying against a self-declared digest authenticates the declaration
// instead of the content, which is exactly the substitution a content digest exists to
// prevent.
//
// It is deliberately NOT cached at load, and the redundancy with Validate's own
// computation is the price of an unconditional guarantee. A cache would be correct only
// for a Contract nobody has touched since Validate ran — Effect is a pointer, so an
// in-process caller can rewrite the block a signature covers and leave the cached digest
// naming the old content, and VerifyAttestations would then report a tampered entry as
// verified. That is precisely the substitution this whole layer exists to catch, so it
// must not depend on caller discipline. The cost is one SHA-256 over a small JSON block,
// on an authoring-time CLI path that never touches the decision path.
func (c *Contract) contentDigest() (string, error) {
	return capability.EffectContractDigest(c.Effect)
}

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
	// The id is the only free-form field inside the signed attestation payload, whose fields
	// are newline-separated. Refusing a newline keeps that payload's field boundaries a
	// property of the format rather than of an argument about which fields happen to be
	// newline-free — and an id is a "vendor/tool" slug, so nothing legitimate is lost.
	if strings.ContainsAny(c.ID, "\r\n") {
		return fmt.Errorf("contract %q: 'id' contains a line break; an id is a vendor/tool slug and is embedded verbatim in the signed attestation payload", c.ID)
	}
	// The id is also the half of Ref() BEFORE the "@", and SplitEffectRef cuts a ref at
	// its FIRST "@" — so an id containing one validates and digests cleanly here while
	// producing a ref that can never resolve: the id half is truncated and the digest half
	// is whatever followed. The author's mistake then surfaces as a baffling
	// digest-mismatch at manifest load, far from the entry that caused it. Whitespace is
	// refused for the neighbouring reason: a ref is copied into a manifest as one token,
	// and a leading or trailing space is invisible in the place it breaks.
	if strings.ContainsRune(c.ID, '@') {
		return fmt.Errorf("contract %q: 'id' contains '@', which separates the id from the digest in the 'effect.ref' pin this entry serves — its ref could never resolve", c.ID)
	}
	if strings.ContainsAny(c.ID, " \t") || c.ID != strings.TrimSpace(c.ID) {
		return fmt.Errorf("contract %q: 'id' contains whitespace; an id is a vendor/tool slug copied verbatim into an 'effect.ref' pin", c.ID)
	}
	if strings.TrimSpace(c.Tool) == "" {
		return fmt.Errorf("contract %q is missing 'tool'", c.ID)
	}
	// The id ends in "." + the tool it describes ("<publisher>/<server>.<tool>"), so an
	// entry cannot attest one tool under another's name — a mislabelling nothing else
	// catches, since every later layer trusts the id as the entry's identity.
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
	// The contract must be SEMANTICALLY valid, not merely digest-consistent. A digest over
	// nonsense is still a stable digest: an entry with a class outside the closed vocabulary
	// ("safe"), a compensable contract naming no compensating action, or a blast radius
	// declaring both a value and an argument used to validate and digest cleanly here, so the
	// corpus — the
	// artifact whose whole purpose is to be reviewable and pinnable — was not
	// machine-reviewable at all, and the mistake surfaced later as a confusing manifest-load
	// error about a block the author had copied verbatim from it. These are the SAME rules
	// the manifest loader applies (they live in pkg/capability, which owns the vocabulary
	// and the digest), so the two layers cannot disagree about what a valid contract is.
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
	// Structural validation only — everything checkable without a key. Signature
	// VERIFICATION needs the operator's trust store and happens in VerifyAttestations; a
	// malformed signature is refused here rather than there so a corpus cannot carry one
	// that looks like assurance in a listing and turns out to be unevaluable.
	seenSig := make(map[string]bool, len(c.Signatures))
	for i := range c.Signatures {
		if err := c.Signatures[i].Validate(c.ID); err != nil {
			return err
		}
		// One statement per key per entry. Two signatures from one key are either a
		// duplicate or a key that both attests and disputes, and neither is something a
		// report can render honestly.
		k := c.Signatures[i].KeyID
		if seenSig[k] {
			return fmt.Errorf("contract %q: key %q signs this entry more than once; one statement per key", c.ID, k)
		}
		seenSig[k] = true
	}
	return nil
}

// strictDecodeJSON is the one JSON reader this package uses for a document on disk: unknown
// fields refused, and trailing content after the first value refused.
//
// Both halves are load-bearing and both were previously written out twice, once per loader.
// Unknown-field rejection turns a misspelling into an error rather than a silently-absent
// value. The trailing-content check catches a file holding two concatenated objects — a bad
// merge, an append where a rewrite was meant — where Decode would read the first and discard
// the second in silence; a contract or a trusted key that vanishes without an alarm is
// indistinguishable from one that was never there.
//
// useNumber preserves integer literals beyond float64's exact range, which matters for a
// contract's blast radius and not for a key file.
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
// id. It fails on the FIRST invalid entry rather than skipping it: a corpus that silently
// drops an unreadable contract would let a tampered file disappear instead of raising an
// alarm.
func LoadCorpus(dir string) ([]Contract, error) {
	// os.ReadDir, not filepath.Glob: Glob re-interprets the caller's DIRECTORY as a
	// pattern, so a real directory whose name contains a metacharacter
	// ("/opt/corpora/mcp[v2]/contracts") matched nothing and returned an empty corpus with
	// no error — a clean bill of health for files that were never read, which is exactly
	// what this loader's fail-on-first-invalid rule exists to prevent one level down.
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
		data, err := readBoundedFile(boundedRead{
			path:      p,
			what:      "contract",
			max:       maxContractFileBytes,
			overLimit: "refusing to buffer it rather than decoding a corpus entry that cannot be one",
		})
		if err != nil {
			return nil, err
		}
		var c Contract
		// UseNumber keeps a blast-radius literal exact: a magnitude above 2^53 widened to
		// float64 would round, and the digest is computed over the decoded value, so the
		// entry would fail its own digest check for a reason that looks like tampering.
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

// maxContractFileBytes bounds ONE corpus entry's read. Like maxTrustStoreBytes it bounds what
// a MISDIRECTED path can make this loader allocate, not how much an author may write: a real
// entry is a few kilobytes, and a mebibyte is orders of magnitude past the largest plausible
// one. The directory is operator-supplied (`--dir`), so a corpus path fat-fingered at a data
// directory holding a multi-gigabyte .json was buffered whole before strictDecodeJSON could
// reject it — an OOM where an error belongs.
const maxContractFileBytes = 1 << 20

// boundedRead is one bounded whole-file read's parameters. A struct rather than four
// positional arguments because two of them are strings that read identically at a call site
// and swapping them would garble every error message this produces.
type boundedRead struct {
	// path is the file to read; what names its kind for the error messages ("contract").
	path, what string
	// max is the inclusive byte bound: a file exactly this size still loads.
	max int64
	// flags are any extra open flags the caller's own threat model needs, beyond O_RDONLY
	// (the trust store's O_NOFOLLOW). Zero for a caller that needs none.
	flags int
	// overLimit completes the over-size error: "<what> %q is larger than N bytes; <overLimit>".
	// Each caller states what refusing buys IT, since a truncated read means something
	// different for a key set than for a single entry.
	overLimit string
}

// readBoundedFile reads a file whole under a size bound, erroring rather than truncating when
// it is exceeded.
//
// Shared by the two operator-supplied paths this package reads — the attestation trust store
// and each corpus entry — because the rationale is identical and only one of them had it: a
// path fat-fingered at a log, a core dump, or a disk image must produce an error, not an OOM.
func readBoundedFile(rd boundedRead) ([]byte, error) {
	f, err := os.OpenFile(rd.path, os.O_RDONLY|rd.flags, 0) //nolint:gosec // G304: operator-supplied path (trust store, or a corpus entry under the caller's --dir)
	if err != nil {
		return nil, fmt.Errorf("reading %s %q: %w", rd.what, rd.path, err)
	}
	defer func() { _ = f.Close() }()
	// Read one byte past the bound so a file exactly at the limit still loads and anything
	// larger is detectable without reading it all.
	data, err := io.ReadAll(io.LimitReader(f, rd.max+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s %q: %w", rd.what, rd.path, err)
	}
	if int64(len(data)) > rd.max {
		return nil, fmt.Errorf("%s %q is larger than %d bytes; %s", rd.what, rd.path, rd.max, rd.overLimit)
	}
	return data, nil
}

// sortedKeys renders a validation set for a deterministic error message. The collect-and-sort
// is sortedSet's (attest.go); this is that plus the join, so one function orders a set in this
// package rather than two with near-identical bodies.
func sortedKeys(m map[string]bool) string {
	return strings.Join(sortedSet(m), ", ")
}
