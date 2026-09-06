// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/eunolabs/eunox/internal/config"
)

// A content digest proves an entry's EFFECT CONTENT is what it says; a signature adds who
// is saying so and whether anyone looked. Five rules keep that honest: verification is
// LOCAL only (no key fetch, no network — same rule that keeps the registry off the
// decision path); attestations are authoring-time input, never consulted on the decision
// path (a manifest still pins by content digest); a signature claims AUTHORSHIP, not truth
// (a dispute is advisory, like the drift layer's manifest/upstream mismatch signal, never
// a detection result); an untrusted signature is inert, but a signature by a TRUSTED key
// that fails to verify is an error — the entry's EFFECT CONTENT was edited after it was
// signed (see AttestationPayload's SCOPE note: Summary/Notes/Server/Attestation are prose
// and provenance, never covered by the signature, and can be edited on a signed entry
// without invalidating it); and a signature is over CONTENT, never PROSE.
//
// This is deliberately a separate trust-key file from the per-upstream JWKS in
// pkg/capability/receipt.go: one is a detached signature reviewed by a human at authoring
// time, the other a JWS with claims verified on the request path, and each needs its own
// posture (see docs/effect-contracts.md).
const (
	// AttestRoleVendor marks a signature by the tool's own publisher — the strongest
	// claim available, since they'd know and are accountable if it's wrong.
	AttestRoleVendor = "vendor"
	// AttestRoleReviewer marks a signature by a third party who reviewed the entry — a
	// community signal, not a vendor's word.
	AttestRoleReviewer = "reviewer"

	// AttestStatementAttests asserts the contract is a correct description of the tool.
	AttestStatementAttests = "attests"
	// AttestStatementDisputes asserts it is not — the reason this surface is a list of
	// signatures rather than a single one.
	AttestStatementDisputes = "disputes"

	// AttestAlgorithmEd25519 is the only algorithm this build verifies. Fixed rather
	// than negotiated — an algorithm field a verifier honors is one an attacker selects.
	AttestAlgorithmEd25519 = "ed25519"

	// attestPayloadPrefix domain-separates the signed bytes. Without it a signature over
	// a contract could be replayed anywhere else the same key signs a similar-looking string.
	attestPayloadPrefix = "eunox-effect-contract-attestation/v1"
)

var validAttestRoles = map[string]bool{AttestRoleVendor: true, AttestRoleReviewer: true}
var validAttestStatements = map[string]bool{AttestStatementAttests: true, AttestStatementDisputes: true}

// Signature is one party's signed statement about a corpus entry.
//
// Deliberately no timestamp field: an unsigned one invites reading it as though the
// signature covered it, and a signed one would promise a freshness story an offline,
// local-only trust store can't deliver (no revocation, no expiry check).
type Signature struct {
	// KeyID is matched against the operator's trust store; an unmatched key is inert,
	// never an error.
	KeyID string `json:"keyId"`
	// Algorithm must be AttestAlgorithmEd25519.
	Algorithm string `json:"algorithm"`
	// Role is part of the SIGNED payload, so a reviewer's signature cannot be
	// re-presented as a vendor's.
	Role string `json:"role"`
	// Statement is also part of the signed payload — otherwise a dispute could be
	// edited down to look like an endorsement.
	Statement string `json:"statement"`
	// Value is the base64 (standard encoding) Ed25519 signature over AttestationPayload.
	Value string `json:"signature"`
}

// decoded returns the signature bytes, decoded on every call rather than cached — Value
// is a mutable exported field, and a stale cache could pass a signature that no longer
// matches its content.
func (s *Signature) decoded() ([]byte, error) {
	return base64.StdEncoding.DecodeString(s.Value)
}

// AttestationPayload returns the exact bytes a signature covers: domain separator,
// contract id, content digest, role, and statement, newline-separated. Exported so a
// publisher can produce the same bytes to sign (`eunox contracts --attest-payload`
// prints them).
//
// SCOPE: this is EVERYTHING a signature attests to. Summary, Notes, Server (name,
// homepage, versionRange), and the Attestation provenance block are all OUTSIDE this
// payload — a distributed entry can have those fields rewritten and still pass
// VerifyAttestations against an unmodified signature. "Verified" therefore means "this
// entry's effect content is what the signer saw," not "this entry, as a whole, is
// unmodified." A reviewer who needs the prose/provenance itself authenticated must not
// rely on the signature for that.
//
// A newline separator (not a length prefix) is safe here because reading from the END is
// unambiguous — statement/role are closed vocabularies and digest is 64 hex chars, so
// only the id could hide a newline, and Contract.Validate refuses one outright.
func AttestationPayload(id, digest, role, statement string) []byte {
	return []byte(strings.Join([]string{attestPayloadPrefix, id, digest, role, statement}, "\n"))
}

// NewSignaturePayload returns the bytes a signer covers for one corpus entry, validating
// role and statement first. The digest is recomputed from content, never taken from the
// declaration — signing a self-declared digest would authenticate the declaration, not
// the content.
func NewSignaturePayload(c *Contract, role, statement string) ([]byte, error) {
	if !validAttestRoles[role] {
		return nil, fmt.Errorf("attestation role %q is not one of %s", role, sortedKeys(validAttestRoles))
	}
	if !validAttestStatements[statement] {
		return nil, fmt.Errorf("attestation statement %q is not one of %s", statement, sortedKeys(validAttestStatements))
	}
	digest, err := c.contentDigest()
	if err != nil {
		return nil, fmt.Errorf("contract %q: %w", c.ID, err)
	}
	return AttestationPayload(c.ID, digest, role, statement), nil
}

// Validate checks a signature's structure — everything checkable without a key. Runs at
// corpus load so a malformed signature rejects the entry, rather than silently looking
// like assurance later.
func (s *Signature) Validate(contractID string) error {
	if s == nil {
		return fmt.Errorf("contract %q has a null entry in 'signatures'", contractID)
	}
	if strings.TrimSpace(s.KeyID) == "" {
		return fmt.Errorf("contract %q: a signature is missing 'keyId'", contractID)
	}
	if s.KeyID != strings.TrimSpace(s.KeyID) {
		return fmt.Errorf("contract %q: signature keyId %q has leading or trailing whitespace; a keyId is matched verbatim against the trust store, so this one would never match a trusted key and the signature would silently report as unverified — remove the surrounding whitespace", contractID, s.KeyID)
	}
	if s.Algorithm != AttestAlgorithmEd25519 {
		return fmt.Errorf("contract %q: signature %q declares algorithm %q; this build verifies only %q", contractID, s.KeyID, s.Algorithm, AttestAlgorithmEd25519)
	}
	if !validAttestRoles[s.Role] {
		return fmt.Errorf("contract %q: signature %q declares role %q, not one of %s", contractID, s.KeyID, s.Role, sortedKeys(validAttestRoles))
	}
	if !validAttestStatements[s.Statement] {
		return fmt.Errorf("contract %q: signature %q declares statement %q, not one of %s", contractID, s.KeyID, s.Statement, sortedKeys(validAttestStatements))
	}
	raw, err := s.decoded()
	if err != nil {
		return fmt.Errorf("contract %q: signature %q is not valid base64: %w", contractID, s.KeyID, err)
	}
	if len(raw) != ed25519.SignatureSize {
		return fmt.Errorf("contract %q: signature %q is %d bytes, not the %d an Ed25519 signature is", contractID, s.KeyID, len(raw), ed25519.SignatureSize)
	}
	return nil
}

// TrustedKey is one public key an operator has decided to trust, and for what.
type TrustedKey struct {
	// KeyID is matched against a signature's keyId.
	KeyID string `json:"keyId"`
	// Algorithm must be AttestAlgorithmEd25519.
	Algorithm string `json:"algorithm"`
	// PublicKey is the base64 (standard encoding) raw 32-byte Ed25519 public key.
	PublicKey string `json:"publicKey"`
	// Owner is the human-readable party this key belongs to — what an operator reads to
	// judge whether a checkmark means anything to them.
	Owner string `json:"owner"`
	// Roles optionally restricts the roles this key may assert (empty means any) —
	// trusting a key as a reviewer is not the same decision as trusting it as a vendor.
	Roles []string `json:"roles,omitempty"`

	pub ed25519.PublicKey
}

// permits reports whether this key may assert the given role.
func (k *TrustedKey) permits(role string) bool {
	return len(k.Roles) == 0 || slices.Contains(k.Roles, role)
}

// TrustStore is the operator's set of trusted attestation keys, loaded from a local file.
// A nil store trusts nothing, which is the default and makes every signature inert.
type TrustStore struct {
	keys map[string]*TrustedKey
}

// Len reports how many keys the store holds; 0 for a nil store.
func (t *TrustStore) Len() int {
	if t == nil {
		return 0
	}
	return len(t.keys)
}

// maxTrustStoreBytes bounds what a MISDIRECTED path (a fat-fingered --trust-keys pointed
// at a log or disk image) can make this read — an error, not a truncation, since a
// truncated store would silently drop trust in the keys past the cut.
const maxTrustStoreBytes = 4 << 20

// readTrustStoreFile opens with O_NOFOLLOW, closing the Lstat->open TOCTOU window
// RefuseNonRegularPath alone cannot: a symlink swap there would substitute the operator's
// whole trust root.
func readTrustStoreFile(path string) ([]byte, error) {
	return config.ReadBoundedFile(config.BoundedRead{
		Path:      path,
		What:      "attestation trust store",
		Max:       maxTrustStoreBytes,
		Flags:     config.OpenNoFollow,
		OverLimit: "refusing to load it rather than trusting a truncated key set",
	})
}

// LoadTrustStore reads a "keys" array of TrustedKey. Every failure is an error, not a
// skipped key — silently dropping a malformed entry would report it unattested when the
// operator believes they configured its key.
func LoadTrustStore(path string) (*TrustStore, error) {
	resolved, err := config.ExpandHome(path)
	if err != nil {
		return nil, err
	}
	if err := config.RefuseNonRegularPath(resolved, "attestation trust store"); err != nil {
		return nil, err
	}
	data, err := readTrustStoreFile(resolved)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Keys []TrustedKey `json:"keys"`
	}
	if err := strictDecodeJSON(data, &doc, fmt.Sprintf("attestation trust store %q", resolved), false); err != nil {
		return nil, err
	}
	store := &TrustStore{keys: make(map[string]*TrustedKey, len(doc.Keys))}
	for i := range doc.Keys {
		k := doc.Keys[i]
		if strings.TrimSpace(k.KeyID) == "" {
			return nil, fmt.Errorf("attestation trust store %q: key %d is missing 'keyId'", resolved, i)
		}
		// lookup matches a signature's keyId verbatim, so a copy-pasted " acme-vendor"
		// loads as a trusted key that can never be reached: every signature it was added
		// to verify reports unverified(N), which reads as "signed by strangers" rather
		// than as the configuration mistake it is.
		if k.KeyID != strings.TrimSpace(k.KeyID) {
			return nil, fmt.Errorf("attestation trust store %q: key %q has leading or trailing whitespace in 'keyId'; a keyId is matched verbatim against a signature's, so this key would never match one and the signatures it was added to verify would silently report as unverified — remove the surrounding whitespace", resolved, k.KeyID)
		}
		if k.Algorithm != AttestAlgorithmEd25519 {
			return nil, fmt.Errorf("attestation trust store %q: key %q declares algorithm %q; this build verifies only %q", resolved, k.KeyID, k.Algorithm, AttestAlgorithmEd25519)
		}
		raw, decErr := base64.StdEncoding.DecodeString(k.PublicKey)
		if decErr != nil {
			return nil, fmt.Errorf("attestation trust store %q: key %q publicKey is not valid base64: %w", resolved, k.KeyID, decErr)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("attestation trust store %q: key %q publicKey is %d bytes, not the %d an Ed25519 public key is", resolved, k.KeyID, len(raw), ed25519.PublicKeySize)
		}
		for _, r := range k.Roles {
			if !validAttestRoles[r] {
				return nil, fmt.Errorf("attestation trust store %q: key %q restricts role %q, not one of %s", resolved, k.KeyID, r, sortedKeys(validAttestRoles))
			}
		}
		if _, dup := store.keys[k.KeyID]; dup {
			return nil, fmt.Errorf("attestation trust store %q: duplicate keyId %q — a signature must resolve to exactly one key", resolved, k.KeyID)
		}
		k.pub = ed25519.PublicKey(raw)
		store.keys[k.KeyID] = &k
	}
	return store, nil
}

// AttestationStatus is what verification concluded about one entry.
type AttestationStatus struct {
	// Attested and Disputed name the OWNERS (not key ids) of verified signatures,
	// sorted — the question an operator answers is "whose word is this".
	Attested []string
	Disputed []string
	// VendorAttested is true when a verified attests-signature was made in the vendor
	// role — the single bit most consumers want.
	VendorAttested bool
	// Unverified counts signatures whose key isn't trusted (or trusted only in another
	// role) — reported, since "signed by strangers" is a different state from "no signatures".
	Unverified int
}

// Summary renders the status as one short operator-facing token for a report column.
func (s AttestationStatus) Summary() string {
	var head string
	switch {
	case len(s.Disputed) > 0:
		// A dispute always leads, even alongside attestations — a reader must not
		// skim past it.
		head = fmt.Sprintf("DISPUTED(%d)", len(s.Disputed))
	case s.VendorAttested:
		head = "vendor"
	case len(s.Attested) > 0:
		head = fmt.Sprintf("reviewed(%d)", len(s.Attested))
	case s.Unverified > 0:
		return fmt.Sprintf("unverified(%d)", s.Unverified)
	default:
		return "-"
	}
	// The unverified count rides ALONGSIDE the verified head, never replaces it —
	// otherwise an entry with one reviewer and nine stranger signatures rendered as a
	// bare "reviewed(1)".
	if s.Unverified > 0 {
		return fmt.Sprintf("%s +unverified(%d)", head, s.Unverified)
	}
	return head
}

// VerifyAttestations checks every signature on c against the trust store. An untrusted
// (or wrongly-roled) key counts as unverified; a TRUSTED key whose signature fails to
// verify is an error — the only way to get one is editing the entry's EFFECT CONTENT
// after it was signed (see AttestationPayload's SCOPE note: Summary/Notes/Server/
// Attestation are outside the signed payload and can change without tripping this).
func (c *Contract) VerifyAttestations(store *TrustStore) (AttestationStatus, error) {
	var status AttestationStatus
	if len(c.Signatures) == 0 {
		return status, nil
	}
	// Derived from content, never the declared digest — verifying against a
	// self-declared value would authenticate the declaration instead of the content.
	digest, err := c.contentDigest()
	if err != nil {
		return status, fmt.Errorf("contract %q: %w", c.ID, err)
	}
	attested := map[string]bool{}
	disputed := map[string]bool{}
	for i := range c.Signatures {
		sig := &c.Signatures[i]
		key := store.lookup(sig.KeyID)
		if key == nil {
			// A key the operator does not hold. Inert, never an error — see property 4.
			status.Unverified++
			continue
		}
		raw, decErr := sig.decoded()
		if decErr != nil {
			// Structurally checked at load; a caller-built Contract can still bypass
			// that, and an unparseable signature by a TRUSTED key is tampering, not a stranger.
			return AttestationStatus{}, fmt.Errorf("contract %q: signature %q is not valid base64: %w", c.ID, sig.KeyID, decErr)
		}
		// Verify FIRST, then check role: testing the role restriction first would
		// misreport a trusted key's tampered signature as merely "wrong role" instead
		// of the tampering it is.
		if !ed25519.Verify(key.pub, AttestationPayload(c.ID, digest, sig.Role, sig.Statement), raw) {
			return AttestationStatus{}, fmt.Errorf("contract %q: signature by trusted key %q (%s) does not verify against this entry's effect content; the effect content was edited after it was signed, or the signature was copied from another entry (summary/notes/server fields are not covered by this signature and would not trigger this error)", c.ID, sig.KeyID, key.Owner)
		}
		if !key.permits(sig.Role) {
			// A genuine signature, in a role this operator doesn't accept from this
			// key — counts for nothing rather than erroring.
			status.Unverified++
			continue
		}
		owner := key.Owner
		if owner == "" {
			owner = key.KeyID
		}
		// Explicit switch with a fail-closed default: Signature.Validate closes the
		// statement vocabulary only on the LoadCorpus path, so a caller-built Contract
		// can still reach here with an unchecked Statement.
		switch sig.Statement {
		case AttestStatementDisputes:
			disputed[owner] = true
		case AttestStatementAttests:
			attested[owner] = true
			if sig.Role == AttestRoleVendor {
				status.VendorAttested = true
			}
		default:
			status.Unverified++
		}
	}
	status.Attested = sortedSet(attested)
	status.Disputed = sortedSet(disputed)
	return status, nil
}

// lookup returns the trusted key with this id, or nil. Nil-safe: a nil store trusts nothing.
func (t *TrustStore) lookup(keyID string) *TrustedKey {
	if t == nil {
		return nil
	}
	return t.keys[keyID]
}

// sortedSet renders a set as a sorted slice, for deterministic reports. sortedKeys (the
// error-message renderer in registry.go) is this plus a join, so the two share one collect-and-
// sort rather than being near-identical bodies with near-identical names.
func sortedSet(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
