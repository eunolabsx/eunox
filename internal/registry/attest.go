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

// A content digest establishes that an entry is what it says it is. It says nothing about
// WHO is saying it, and nothing about whether anyone else has looked. Those are the two
// things that turn a corpus of files into a corpus with a trust model, and they are what this
// file adds: a signature over an entry's content, made by a named key an operator chose to
// trust, carrying either "I attest to this" or "I dispute this".
//
// Four properties keep it honest, and each is a deliberate limit rather than an omission:
//
//  1. LOCAL, always. Verification takes a trust store the operator points at on disk and
//     nothing else. There is no key discovery, no fetch, no fallback to a well-known URL —
//     the same rule that keeps the registry off the decision path keeps it off the network
//     entirely, so verifying a corpus someone handed you works offline.
//  2. NEVER on the decision path. Attestations are authoring-time input, checked by
//     `eunox contracts` and by whatever CI an operator runs. A manifest still pins an entry
//     by content digest, and that pin is still what the manifest loader verifies. An
//     unattested contract enforces exactly as it did before; attestation changes what a human
//     knows when choosing to pin it, not what the proxy does with it.
//  3. It is a claim of AUTHORSHIP, not of truth. A vendor signature says the vendor asserts
//     this is what their tool does. Nothing here observes the tool. A dispute is likewise a
//     community-advisory signal, not a detection result — the same posture the drift layer
//     takes about a manifest/upstream mismatch.
//  4. An untrusted signature is INERT, but a trusted signature that does not verify is an
//     ERROR. Those are different failures. A corpus may carry signatures from keys an
//     operator has never heard of, and refusing to load it over one would make every entry's
//     usability depend on the operator having collected every publisher's key. But a
//     signature by a key the operator DID configure, which does not verify against the
//     content in front of it, means the entry was edited after it was signed — which is the
//     substitution the whole mechanism exists to catch.
//
// This is the SECOND operator-configured public-key file in the codebase, beside the
// per-upstream JWKS in pkg/capability/receipt.go, and the divergence is deliberate rather
// than an oversight. Property 4 above splits "unknown key" from "trusted key, bad
// signature"; the receipt verifier deliberately COLLAPSES the same two into one
// ReceiptUnverified verdict, because splitting them there would invite a consumer to treat
// some unverified receipts as softer than others when all of them earn nothing. The two
// surfaces are genuinely different objects — a detached signature over content, read by a
// human at authoring time, versus a JWS with claims verified on the request path — so one
// shared format would have to pick a posture that is wrong for one of them. An operator
// reasoning from one file about the other gets it backwards, which is why
// docs/effect-contracts.md states the difference where both are documented.
const (
	// AttestRoleVendor marks a signature by the party that publishes the MCP server the
	// contract describes: the strongest claim available here, because the signer is the one
	// who would know and the one accountable for it being wrong.
	AttestRoleVendor = "vendor"
	// AttestRoleReviewer marks a signature by a third party who read the entry and its
	// notes. It is the community-review signal — several independent reviewers is evidence
	// of a kind, and it is not a vendor's word.
	AttestRoleReviewer = "reviewer"

	// AttestStatementAttests asserts the contract is a correct description of the tool.
	AttestStatementAttests = "attests"
	// AttestStatementDisputes asserts it is not. A dispute is the reason this surface is a
	// list rather than a single signature: the useful signal is often that someone who
	// looked disagreed, and a format with nowhere to record that loses it.
	AttestStatementDisputes = "disputes"

	// AttestAlgorithmEd25519 is the only signature algorithm this build verifies. One
	// algorithm, chosen rather than negotiated: a corpus is a distributed artifact read by
	// many parties, and an algorithm field a verifier honors is an algorithm an attacker
	// selects. Ed25519 needs no parameters, has no curve or hash to get wrong, and is in the
	// standard library, so adding it costs the one-static-binary rule nothing.
	AttestAlgorithmEd25519 = "ed25519"

	// attestPayloadPrefix domain-separates the signed bytes. Without it a signature over a
	// contract could be replayed anywhere else the same key signs a similar-looking string.
	attestPayloadPrefix = "eunox-effect-contract-attestation/v1"
)

var validAttestRoles = map[string]bool{AttestRoleVendor: true, AttestRoleReviewer: true}
var validAttestStatements = map[string]bool{AttestStatementAttests: true, AttestStatementDisputes: true}

// Signature is one party's signed statement about a corpus entry.
//
// There is deliberately no timestamp field. A signature carrying an unsigned timestamp
// invites exactly the mistake the format should not permit — reading a value beside a
// signature as though the signature covered it — and a timestamp INSIDE the payload would
// promise a freshness story an offline, local-only trust store cannot deliver (there is no
// revocation, no expiry check, and nothing to compare a date against). The signed claim is
// the whole claim: this key, in this role, says this about this content.
type Signature struct {
	// KeyID names the key that produced the signature. It is matched against the operator's
	// trust store; a signature whose key is not there is inert, never an error.
	KeyID string `json:"keyId"`
	// Algorithm must be AttestAlgorithmEd25519.
	Algorithm string `json:"algorithm"`
	// Role is the standing the signer claims: AttestRoleVendor or AttestRoleReviewer. It is
	// part of the SIGNED payload, so a reviewer's signature cannot be re-presented as a
	// vendor's, and the trust store may additionally refuse a key the role it is used in.
	Role string `json:"role"`
	// Statement is AttestStatementAttests or AttestStatementDisputes. Also part of the
	// signed payload: without it, a dispute could be stripped down to look like an
	// endorsement by editing one unsigned field.
	Statement string `json:"statement"`
	// Value is the base64 (standard encoding) Ed25519 signature over AttestationPayload.
	Value string `json:"signature"`
}

// decoded returns the signature bytes, decoded on every call.
//
// Validate decodes and length-checks the same string at corpus load, and caching the
// result there would remove that second decode — but it would also make verification
// correct only for a Signature nobody has touched since. Value is a plain field on an
// exported struct: an in-process caller can swap it and leave the cache holding the bytes
// that DID verify, which turns "this signature does not match this content" into a pass on
// the one check that exists to catch exactly that. A base64 decode of 88 characters, on an
// authoring-time CLI path, is not worth making an integrity result conditional on caller
// discipline.
func (s *Signature) decoded() ([]byte, error) {
	return base64.StdEncoding.DecodeString(s.Value)
}

// AttestationPayload returns the exact bytes a signature covers: the domain separator, the
// contract id, its content digest, the signer's role, and the statement, newline-separated.
//
// Every field that gives the signature its meaning is in here, and nothing that does not. The
// digest is what binds it to CONTENT — re-signing is required after any edit to the effect
// block, which is the property that makes a stale signature detectable rather than a rubber
// stamp that survives a rewrite.
//
// Exported because a publisher has to be able to produce these bytes to sign them, and
// deriving them from a prose description of the format is how two implementations end up
// disagreeing about a trailing newline. `eunox contracts --attest-payload` prints exactly
// this.
//
// The separator is a newline rather than the length prefix this codebase uses for counter keys,
// and that is sound HERE for a reason worth stating, since the usual answer is the opposite.
// Field confusion needs two distinct field tuples to render the same bytes. Reading this
// payload from the END is unambiguous: statement and role come from closed vocabularies and
// digest is 64 hex characters, so none of the three can contain a newline and each is
// determined by counting back from the tail. Everything between the fixed prefix and those
// three is the id, whatever it contains. There is no shift to find. The one field that COULD
// carry a newline is the id, and Contract.Validate refuses one outright rather than leaving
// this argument as the only thing standing between a corpus and a re-presented signature.
func AttestationPayload(id, digest, role, statement string) []byte {
	return []byte(strings.Join([]string{attestPayloadPrefix, id, digest, role, statement}, "\n"))
}

// NewSignaturePayload returns the bytes a signer covers for one corpus entry, validating the
// role and statement first so a typo produces an error rather than a payload nobody will ever
// be able to verify against. The digest is recomputed from the entry's own content, never
// taken from its declaration, for the reason VerifyAttestations recomputes it: a signature
// over a self-declared digest authenticates the declaration instead of the content.
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

// Validate checks a signature's structure — everything checkable without a key. It runs at
// corpus load, so a malformed signature is a rejected ENTRY rather than one that silently
// verifies against nothing later: a signature nobody can evaluate is worse than no signature,
// because it looks like assurance in a listing.
func (s *Signature) Validate(contractID string) error {
	if s == nil {
		return fmt.Errorf("contract %q has a null entry in 'signatures'", contractID)
	}
	if strings.TrimSpace(s.KeyID) == "" {
		return fmt.Errorf("contract %q: a signature is missing 'keyId'", contractID)
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
	raw, err := base64.StdEncoding.DecodeString(s.Value)
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
	// Owner is the human-readable party this key belongs to, shown in reports. It is what an
	// operator reads to decide whether a green checkmark means anything to them.
	Owner string `json:"owner"`
	// Roles optionally restricts the roles this key may assert. Empty means any. It exists
	// because trusting a key is not one decision: an operator may well trust a security
	// researcher's key as a REVIEWER while not accepting it as the vendor of anything, and
	// without this the two would be the same grant.
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

// maxTrustStoreBytes bounds a trust-store file. It is a bound on how much a MISDIRECTED path
// can make this read, not on how many keys an operator may configure: RefuseNonRegularPath
// rejects the device and FIFO cases up front, but a plain regular file of the wrong kind
// (a log, a core dump, a pointed-at disk image) is exactly what a fat-fingered --trust-keys
// produces, and reading it whole before discovering it is not JSON is the difference between an
// error message and an OOM. Four mebibytes is roughly ten thousand Ed25519 keys with their
// metadata — far past any real store — and it errors rather than truncating, because a
// truncated store would silently stop trusting the keys past the cut.
const maxTrustStoreBytes = 4 << 20

// readTrustStoreFile opens the store with the same symlink guard the audit key file uses and
// reads it under the size bound. O_NOFOLLOW closes the Lstat->open window RefuseNonRegularPath
// cannot: the trust store names the keys whose attestations are believed, so swapping it for a
// symlink between the check and the read substitutes the operator's whole trust root.
func readTrustStoreFile(path string) ([]byte, error) {
	return readBoundedFile(boundedRead{
		path:      path,
		what:      "attestation trust store",
		max:       maxTrustStoreBytes,
		flags:     config.OpenNoFollow,
		overLimit: "refusing to load it rather than trusting a truncated key set",
	})
}

// LoadTrustStore reads a trusted-key file. The format is a JSON object with a "keys" array of
// TrustedKey. Unknown fields are rejected, and every failure is an error rather than a skipped
// key: a trust store that silently dropped a malformed entry would report an entry as
// unattested when the operator believes they configured its key, which is the wrong direction
// to be wrong in for a file whose whole job is to say what is trusted.
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
	// Attested and Disputed name the OWNERS (not the key ids) of verified signatures, sorted.
	// Owners rather than key ids because the question an operator is answering is "whose word
	// is this", and a key id is an identifier they would have to look up in the same file
	// they already configured.
	Attested []string
	Disputed []string
	// VendorAttested is true when at least one verified attests-signature was made in the
	// vendor role. It is the single bit most consumers want, kept separate from the owner
	// lists so a caller does not re-derive it (and get it wrong for a disputing vendor).
	VendorAttested bool
	// Unverified counts signatures whose key is not in the trust store, or which the store
	// trusts only in another role. Reported rather than hidden: "3 signatures, none I can
	// check" is a materially different state from "no signatures", and collapsing the two
	// would let a corpus look bare when it is merely signed by strangers.
	Unverified int
}

// Summary renders the status as one short operator-facing token for a report column.
func (s AttestationStatus) Summary() string {
	var head string
	switch {
	case len(s.Disputed) > 0:
		// A dispute leads, always, even alongside attestations. The whole reason to record
		// one is that a reader must not skim past it, and a row that led with "vendor" while
		// someone who looked disagreed would bury the signal under the endorsement.
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
	// The unverified count rides ALONGSIDE whatever verified, never gets replaced by it. The
	// Unverified field exists precisely because "signed by strangers" and "not signed" are
	// different states; reporting only the head hid the same distinction one level up, so an
	// entry with one trusted reviewer and nine signatures from unknown keys rendered as a bare
	// "reviewed(1)" and the operator had no indication the nine existed.
	if s.Unverified > 0 {
		return fmt.Sprintf("%s +unverified(%d)", head, s.Unverified)
	}
	return head
}

// VerifyAttestations checks every signature on c against the trust store and reports what
// held. A signature by an untrusted (or wrongly-roled) key is counted as unverified; a
// signature by a TRUSTED key that does not verify is an error, because the only way to get
// one is to edit an entry after it was signed.
func (c *Contract) VerifyAttestations(store *TrustStore) (AttestationStatus, error) {
	var status AttestationStatus
	if len(c.Signatures) == 0 {
		return status, nil
	}
	// The digest derived from the entry's own CONTENT, never the declared one: a signature
	// verified against a self-declared digest would authenticate the declaration instead of
	// the content, which is precisely the substitution the digest exists to prevent.
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
			// Structurally checked at load; a caller-built Contract can still carry one, and
			// an unparseable signature by a TRUSTED key is the tampering case, not the
			// stranger case.
			return AttestationStatus{}, fmt.Errorf("contract %q: signature %q is not valid base64: %w", c.ID, sig.KeyID, decErr)
		}
		// VERIFY FIRST, then decide whether the verified statement counts. Testing the role
		// restriction before the signature collapsed two different failures into one: a key
		// the operator trusts only as a reviewer, whose vendor-role signature no longer
		// matches the content, was reported as a stranger's signature rather than as the
		// tampering it is — and tampering is the substitution this whole mechanism exists to
		// catch, in an entry the operator explicitly configured a key for.
		if !ed25519.Verify(key.pub, AttestationPayload(c.ID, digest, sig.Role, sig.Statement), raw) {
			return AttestationStatus{}, fmt.Errorf("contract %q: signature by trusted key %q (%s) does not verify against this entry's content; the entry was edited after it was signed, or the signature was copied from another entry", c.ID, sig.KeyID, key.Owner)
		}
		if !key.permits(sig.Role) {
			// A genuine signature, in a role this operator does not accept from this key.
			// Trusting a key is not one decision, so this counts for nothing rather than
			// erroring.
			status.Unverified++
			continue
		}
		owner := key.Owner
		if owner == "" {
			owner = key.KeyID
		}
		// An explicit switch with a fail-closed default. Signature.Validate closes the
		// statement vocabulary, but it runs only on the LoadCorpus path, and this method is
		// exported on an exported struct — a caller-built or externally-decoded Contract
		// reaches here with an unchecked Statement. Falling through to "attested" would let a
		// statement this build does not understand ("revoked", or a capitalized "Disputes")
		// earn the strongest badge the report emits.
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
