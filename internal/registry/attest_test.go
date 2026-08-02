// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package registry_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/eunolabs/eunox/internal/registry"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signedEntry builds a valid corpus entry and returns it alongside a keypair, so a test can
// sign it, tamper with it, or hand a mismatched key to the verifier.
func signedEntry(t *testing.T) (registry.Contract, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	eff := &capability.EffectContract{Class: capability.EffectIrreversible}
	digest, err := capability.EffectContractDigest(eff)
	require.NoError(t, err)
	return registry.Contract{
		SchemaVersion: registry.SchemaVersion,
		ID:            "acme/mcp.send_email",
		Tool:          "send_email",
		Server:        registry.ServerRef{Name: "@acme/mcp"},
		Attestation:   registry.Attestation{Author: "acme", Source: registry.SourceVendor, Review: registry.ReviewVendor},
		Digest:        digest,
		Effect:        eff,
	}, pub, priv
}

// sign attaches a signature over the entry's own content for the given role and statement.
func sign(t *testing.T, c *registry.Contract, keyID, role, statement string, priv ed25519.PrivateKey) {
	t.Helper()
	payload, err := registry.NewSignaturePayload(c, role, statement)
	require.NoError(t, err)
	c.Signatures = append(c.Signatures, registry.Signature{
		KeyID:     keyID,
		Algorithm: registry.AttestAlgorithmEd25519,
		Role:      role,
		Statement: statement,
		Value:     base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload)),
	})
}

// writeTrustStore writes a trusted-key file naming the given keys and returns its path.
func writeTrustStore(t *testing.T, keys ...registry.TrustedKey) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "keys.json")
	body, err := json.Marshal(map[string]interface{}{"keys": keys})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, body, 0o600))
	return path
}

func trusted(keyID, owner string, pub ed25519.PublicKey, roles ...string) registry.TrustedKey {
	return registry.TrustedKey{
		KeyID:     keyID,
		Algorithm: registry.AttestAlgorithmEd25519,
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		Owner:     owner,
		Roles:     roles,
	}
}

// TestVerifyAttestations_VendorSignatureVerifies is the happy path: a signature made over the
// entry's own content, by a key the operator trusts, reports the owner and the vendor bit.
func TestVerifyAttestations_VendorSignatureVerifies(t *testing.T) {
	c, pub, priv := signedEntry(t)
	sign(t, &c, "acme-2026", registry.AttestRoleVendor, registry.AttestStatementAttests, priv)
	require.NoError(t, c.Validate())

	store, err := registry.LoadTrustStore(writeTrustStore(t, trusted("acme-2026", "Acme Inc", pub)))
	require.NoError(t, err)

	status, err := c.VerifyAttestations(store)
	require.NoError(t, err)
	assert.True(t, status.VendorAttested)
	assert.Equal(t, []string{"Acme Inc"}, status.Attested)
	assert.Empty(t, status.Disputed)
	assert.Zero(t, status.Unverified)
	assert.Equal(t, "vendor", status.Summary())
}

// TestVerifyAttestations_TamperedEntryIsAnError is the substitution the whole mechanism exists
// to catch: an entry edited after it was signed, by a key the operator DOES trust.
func TestVerifyAttestations_TamperedEntryIsAnError(t *testing.T) {
	c, pub, priv := signedEntry(t)
	sign(t, &c, "acme-2026", registry.AttestRoleVendor, registry.AttestStatementAttests, priv)

	// Rewrite the effect and re-digest, exactly as a tampering publisher would.
	c.Effect = &capability.EffectContract{Class: capability.EffectReversible}
	digest, err := capability.EffectContractDigest(c.Effect)
	require.NoError(t, err)
	c.Digest = digest
	require.NoError(t, c.Validate(), "the entry is internally consistent — only the signature betrays it")

	store, err := registry.LoadTrustStore(writeTrustStore(t, trusted("acme-2026", "Acme Inc", pub)))
	require.NoError(t, err)
	_, err = c.VerifyAttestations(store)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "edited after it was signed")
}

// TestVerifyAttestations_UntrustedKeyIsInertNotAnError draws the line between the two
// failures: a corpus may be signed by parties an operator has not chosen to trust, and
// refusing to load it over one would make every entry's usability depend on collecting every
// publisher's key.
func TestVerifyAttestations_UntrustedKeyIsInertNotAnError(t *testing.T) {
	c, _, priv := signedEntry(t)
	sign(t, &c, "stranger-1", registry.AttestRoleReviewer, registry.AttestStatementAttests, priv)

	otherPub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	store, err := registry.LoadTrustStore(writeTrustStore(t, trusted("someone-else", "Someone Else", otherPub)))
	require.NoError(t, err)

	status, err := c.VerifyAttestations(store)
	require.NoError(t, err)
	assert.Equal(t, 1, status.Unverified)
	assert.Empty(t, status.Attested)
	assert.Empty(t, status.Disputed)
	assert.Equal(t, "unverified(1)", status.Summary(),
		"'signed by strangers' and 'not signed' are different states and must not collapse")
}

// TestVerifyAttestations_RoleRestrictionIsHonored covers the two-decisions property: trusting a
// key as a reviewer is not trusting it as the vendor of anything.
func TestVerifyAttestations_RoleRestrictionIsHonored(t *testing.T) {
	c, pub, priv := signedEntry(t)
	sign(t, &c, "researcher-1", registry.AttestRoleVendor, registry.AttestStatementAttests, priv)

	store, err := registry.LoadTrustStore(writeTrustStore(t, trusted("researcher-1", "A Researcher", pub, registry.AttestRoleReviewer)))
	require.NoError(t, err)
	status, err := c.VerifyAttestations(store)
	require.NoError(t, err)
	assert.Equal(t, 1, status.Unverified)
	assert.False(t, status.VendorAttested)
}

// TestVerifyAttestations_DisputeLeads is the community-advisory half: a dispute from a trusted
// key must not be buried under an endorsement in the summary a reader skims.
func TestVerifyAttestations_DisputeLeads(t *testing.T) {
	c, vendorPub, vendorPriv := signedEntry(t)
	sign(t, &c, "acme-2026", registry.AttestRoleVendor, registry.AttestStatementAttests, vendorPriv)

	reviewerPub, reviewerPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	sign(t, &c, "reviewer-1", registry.AttestRoleReviewer, registry.AttestStatementDisputes, reviewerPriv)
	require.NoError(t, c.Validate())

	store, err := registry.LoadTrustStore(writeTrustStore(t,
		trusted("acme-2026", "Acme Inc", vendorPub),
		trusted("reviewer-1", "A Reviewer", reviewerPub)))
	require.NoError(t, err)

	status, err := c.VerifyAttestations(store)
	require.NoError(t, err)
	assert.Equal(t, []string{"Acme Inc"}, status.Attested)
	assert.Equal(t, []string{"A Reviewer"}, status.Disputed)
	assert.Equal(t, "DISPUTED(1)", status.Summary())
}

// TestSignaturePayload_BindsRoleAndStatement pins that neither field can be edited beside the
// signature: a reviewer's signature must not be re-presentable as a vendor's, and a dispute
// must not be editable into an endorsement.
func TestSignaturePayload_BindsRoleAndStatement(t *testing.T) {
	c, pub, priv := signedEntry(t)
	sign(t, &c, "reviewer-1", registry.AttestRoleReviewer, registry.AttestStatementDisputes, priv)
	store, err := registry.LoadTrustStore(writeTrustStore(t, trusted("reviewer-1", "A Reviewer", pub)))
	require.NoError(t, err)

	for _, edit := range []func(*registry.Signature){
		func(s *registry.Signature) { s.Role = registry.AttestRoleVendor },
		func(s *registry.Signature) { s.Statement = registry.AttestStatementAttests },
	} {
		tampered := c
		tampered.Signatures = []registry.Signature{c.Signatures[0]}
		edit(&tampered.Signatures[0])
		_, verifyErr := tampered.VerifyAttestations(store)
		assert.Error(t, verifyErr, "role and statement are inside the signed payload")
	}
}

// TestContractValidate_RejectsMalformedSignatures keeps an unevaluable signature out of the
// corpus: one that looks like assurance in a listing is worse than none.
func TestContractValidate_RejectsMalformedSignatures(t *testing.T) {
	base, _, priv := signedEntry(t)
	payload, err := registry.NewSignaturePayload(&base, registry.AttestRoleVendor, registry.AttestStatementAttests)
	require.NoError(t, err)
	good := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload))

	for name, sig := range map[string]registry.Signature{
		"no key id":     {Algorithm: registry.AttestAlgorithmEd25519, Role: registry.AttestRoleVendor, Statement: registry.AttestStatementAttests, Value: good},
		"bad algorithm": {KeyID: "k", Algorithm: "rsa", Role: registry.AttestRoleVendor, Statement: registry.AttestStatementAttests, Value: good},
		"bad role":      {KeyID: "k", Algorithm: registry.AttestAlgorithmEd25519, Role: "owner", Statement: registry.AttestStatementAttests, Value: good},
		"bad statement": {KeyID: "k", Algorithm: registry.AttestAlgorithmEd25519, Role: registry.AttestRoleVendor, Statement: "maybe", Value: good},
		"not base64":    {KeyID: "k", Algorithm: registry.AttestAlgorithmEd25519, Role: registry.AttestRoleVendor, Statement: registry.AttestStatementAttests, Value: "!!!"},
		"wrong length":  {KeyID: "k", Algorithm: registry.AttestAlgorithmEd25519, Role: registry.AttestRoleVendor, Statement: registry.AttestStatementAttests, Value: base64.StdEncoding.EncodeToString([]byte("short"))},
	} {
		t.Run(name, func(t *testing.T) {
			c := base
			c.Signatures = []registry.Signature{sig}
			assert.Error(t, c.Validate())
		})
	}

	t.Run("one statement per key", func(t *testing.T) {
		c := base
		sign(t, &c, "k", registry.AttestRoleVendor, registry.AttestStatementAttests, priv)
		sign(t, &c, "k", registry.AttestRoleVendor, registry.AttestStatementDisputes, priv)
		err := c.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "more than once")
	})
}

// TestLoadTrustStore_RejectsMalformed fails on the first bad key rather than skipping it: a
// silently dropped key reports an entry as unattested when the operator believes they
// configured it, which is the wrong direction to be wrong in for this file.
func TestLoadTrustStore_RejectsMalformed(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	valid := trusted("k1", "One", pub)

	for name, keys := range map[string][]registry.TrustedKey{
		"no key id":     {{Algorithm: registry.AttestAlgorithmEd25519, PublicKey: valid.PublicKey}},
		"bad algorithm": {{KeyID: "k", Algorithm: "rsa", PublicKey: valid.PublicKey}},
		"not base64":    {{KeyID: "k", Algorithm: registry.AttestAlgorithmEd25519, PublicKey: "!!!"}},
		"wrong length":  {{KeyID: "k", Algorithm: registry.AttestAlgorithmEd25519, PublicKey: base64.StdEncoding.EncodeToString([]byte("short"))}},
		"bad role":      {{KeyID: "k", Algorithm: registry.AttestAlgorithmEd25519, PublicKey: valid.PublicKey, Roles: []string{"owner"}}},
		"duplicate id":  {valid, valid},
	} {
		t.Run(name, func(t *testing.T) {
			_, loadErr := registry.LoadTrustStore(writeTrustStore(t, keys...))
			assert.Error(t, loadErr)
		})
	}

	t.Run("missing file", func(t *testing.T) {
		_, loadErr := registry.LoadTrustStore(filepath.Join(t.TempDir(), "absent.json"))
		assert.Error(t, loadErr)
	})

	t.Run("unknown field", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "keys.json")
		require.NoError(t, os.WriteFile(path, []byte(`{"keys":[],"trusted":true}`), 0o600))
		_, loadErr := registry.LoadTrustStore(path)
		assert.Error(t, loadErr)
	})
}

// TestVerifyAttestations_NilStoreTrustsNothing is the default posture: without --trust-keys
// every signature is inert, and nothing errors.
func TestVerifyAttestations_NilStoreTrustsNothing(t *testing.T) {
	c, _, priv := signedEntry(t)
	sign(t, &c, "acme-2026", registry.AttestRoleVendor, registry.AttestStatementAttests, priv)
	status, err := c.VerifyAttestations(nil)
	require.NoError(t, err)
	assert.Equal(t, 1, status.Unverified)
	assert.Empty(t, status.Attested)
}

// TestVerifyAttestations_UnsignedEntryIsBlank keeps an unsigned corpus (which is every entry
// shipped today) reporting as unsigned rather than as anything stronger or weaker.
func TestVerifyAttestations_UnsignedEntryIsBlank(t *testing.T) {
	c, pub, _ := signedEntry(t)
	store, err := registry.LoadTrustStore(writeTrustStore(t, trusted("acme-2026", "Acme Inc", pub)))
	require.NoError(t, err)
	status, err := c.VerifyAttestations(store)
	require.NoError(t, err)
	assert.Equal(t, "-", status.Summary())
	assert.Equal(t, 1, store.Len())
}

// TestNewSignaturePayload_ValidatesAndBindsContent pins that the printed payload is bound to
// the entry's recomputed content, not to whatever digest the file declared.
func TestNewSignaturePayload_ValidatesAndBindsContent(t *testing.T) {
	c, _, _ := signedEntry(t)
	c.Digest = "sha256:deadbeef" // a lie the payload must not repeat

	payload, err := registry.NewSignaturePayload(&c, registry.AttestRoleVendor, registry.AttestStatementAttests)
	require.NoError(t, err)
	actual, err := capability.EffectContractDigest(c.Effect)
	require.NoError(t, err)
	assert.Contains(t, string(payload), actual)
	assert.NotContains(t, string(payload), "deadbeef")

	_, err = registry.NewSignaturePayload(&c, "owner", registry.AttestStatementAttests)
	assert.Error(t, err)
	_, err = registry.NewSignaturePayload(&c, registry.AttestRoleVendor, "maybe")
	assert.Error(t, err)
}

// TestVerifyAttestations_RoleRestrictedKeyStillSurfacesTampering is the ordering the file's
// own stated property depends on: verify FIRST, then decide whether the verified statement
// counts. Testing the role restriction first collapsed "a key I do not hold" with "a key I
// hold, but not for this role", so tampering in an entry the operator had explicitly
// configured a key for was reported as a stranger's signature.
func TestVerifyAttestations_RoleRestrictedKeyStillSurfacesTampering(t *testing.T) {
	c, pub, priv := signedEntry(t)
	sign(t, &c, "researcher-1", registry.AttestRoleVendor, registry.AttestStatementAttests, priv)

	// Edit the entry after signing, and re-digest so only the signature betrays it.
	c.Effect = &capability.EffectContract{Class: capability.EffectReversible}
	digest, err := capability.EffectContractDigest(c.Effect)
	require.NoError(t, err)
	c.Digest = digest

	// The operator trusts this key ONLY as a reviewer; the signature claims the vendor role.
	store, err := registry.LoadTrustStore(writeTrustStore(t, trusted("researcher-1", "A Researcher", pub, registry.AttestRoleReviewer)))
	require.NoError(t, err)

	_, err = c.VerifyAttestations(store)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "edited after it was signed")
}

// TestVerifyAttestations_UnknownStatementCountsForNothing is the fail-closed default. Statement
// validation runs only on the LoadCorpus path, and this method is exported on an exported
// struct — so a caller-built Contract reaches it with an unchecked statement, and falling
// through to "attested" would let one this build does not understand earn the strongest badge
// the report emits.
func TestVerifyAttestations_UnknownStatementCountsForNothing(t *testing.T) {
	c, pub, priv := signedEntry(t)
	sign(t, &c, "acme-2026", registry.AttestRoleVendor, registry.AttestStatementAttests, priv)
	// A genuine signature whose statement this build does not model. Signed over the same
	// payload so it verifies; only the vocabulary is unknown.
	c.Signatures[0].Statement = "revoked"
	payload := registry.AttestationPayload(c.ID, c.Digest, registry.AttestRoleVendor, "revoked")
	c.Signatures[0].Value = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload))

	store, err := registry.LoadTrustStore(writeTrustStore(t, trusted("acme-2026", "Acme Inc", pub)))
	require.NoError(t, err)
	status, err := c.VerifyAttestations(store)
	require.NoError(t, err)
	assert.False(t, status.VendorAttested, "a statement this build cannot interpret must not earn the vendor badge")
	assert.Empty(t, status.Attested)
	assert.Equal(t, 1, status.Unverified)
}

// TestAttestationStatus_SummaryKeepsTheUnverifiedCount pins that "signed by strangers" is
// reported alongside whatever verified rather than being replaced by it — the same distinction
// the Unverified field exists to preserve one level down.
func TestAttestationStatus_SummaryKeepsTheUnverifiedCount(t *testing.T) {
	c, pub, priv := signedEntry(t)
	sign(t, &c, "acme-2026", registry.AttestRoleVendor, registry.AttestStatementAttests, priv)

	// Nine more signatures from keys the operator has never seen.
	for i := 0; i < 9; i++ {
		_, strangerPriv, err := ed25519.GenerateKey(nil)
		require.NoError(t, err)
		sign(t, &c, fmt.Sprintf("stranger-%d", i), registry.AttestRoleReviewer, registry.AttestStatementAttests, strangerPriv)
	}

	store, err := registry.LoadTrustStore(writeTrustStore(t, trusted("acme-2026", "Acme Inc", pub)))
	require.NoError(t, err)
	status, err := c.VerifyAttestations(store)
	require.NoError(t, err)
	assert.Equal(t, 9, status.Unverified)
	assert.Equal(t, "vendor +unverified(9)", status.Summary())
}
