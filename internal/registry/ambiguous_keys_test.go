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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/internal/registry"
	"github.com/eunolabs/eunox/pkg/capability"
)

// Both documents this package reads — the attestation trust store and a corpus entry — are
// REVIEWED before they are decoded, and encoding/json binds member names case-insensitively
// and keeps the last duplicate. That is a substitution a reviewer reading the file top-down
// cannot see, on the two surfaces whose whole premise is that somebody read the file: the
// trust ROOT, and the entry a manifest pins by digest. The tests below are written as the
// attack rather than as a parser check, so each one states what the accepted document would
// have bought.

// TestLoadTrustStore_RefusesASubstitutedTrustRoot: a second, case-variant "publicKey" is
// the key the store actually trusts, while the reviewed one sits above it in the file.
func TestLoadTrustStore_RefusesASubstitutedTrustRoot(t *testing.T) {
	reviewed, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	substituted, substitutedPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "keys.json")
	body := fmt.Sprintf(`{"keys":[{"keyId":"acme-2026","algorithm":"ed25519","owner":"Acme","publicKey":%q,"PublicKey":%q}]}`,
		base64.StdEncoding.EncodeToString(reviewed),
		base64.StdEncoding.EncodeToString(substituted))
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	store, loadErr := registry.LoadTrustStore(path)
	require.Error(t, loadErr, "a trust store presenting one key to a reviewer and loading another must be refused")
	assert.Contains(t, loadErr.Error(), "same name to a JSON decoder")
	require.Nil(t, store)

	// What acceptance would have bought: a signature by the SUBSTITUTED key verifying as
	// the reviewed operator-trusted one.
	c, _, _ := signedEntry(t)
	sign(t, &c, "acme-2026", registry.AttestRoleVendor, registry.AttestStatementAttests, substitutedPriv)
	require.NoError(t, c.Validate())
	status, verifyErr := c.VerifyAttestations(nil)
	require.NoError(t, verifyErr)
	assert.False(t, status.VendorAttested, "with no store loaded nothing is trusted, which is the posture the refusal leaves behind")
}

// TestLoadCorpus_RefusesAnEntryThatSelfValidatesAsSomethingElse is the sharpest form: the
// digest is computed over the DECODED block, so a case-variant "Effect" wins the decode AND
// digests consistently — the entry passes its own integrity check while a reviewer reads the
// class above it.
func TestLoadCorpus_RefusesAnEntryThatSelfValidatesAsSomethingElse(t *testing.T) {
	enforced := &capability.EffectContract{Class: capability.EffectReversible}
	digest, err := capability.EffectContractDigest(enforced)
	require.NoError(t, err)

	dir := t.TempDir()
	body := fmt.Sprintf(`{"schemaVersion":%q,"id":"acme/mcp.send_email","tool":"send_email",
	  "server":{"name":"@acme/mcp"},
	  "attestation":{"author":"acme","source":"authored","review":"pending"},
	  "digest":%q,
	  "effect":{"class":"irreversible"},
	  "Effect":{"class":"reversible"}}`, registry.SchemaVersion, digest)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "e.json"), []byte(body), 0o600))

	_, loadErr := registry.LoadCorpus(dir)
	require.Error(t, loadErr, "an entry whose reviewed class is not the class it enforces must be refused")
	assert.Contains(t, loadErr.Error(), "same name to a JSON decoder")
}

// TestLoadCorpus_RefusesAmbiguityInsideTheEffectBlock: the walk is whole-document, so the
// substitution does not become invisible by moving one level down.
func TestLoadCorpus_RefusesAmbiguityInsideTheEffectBlock(t *testing.T) {
	dir := t.TempDir()
	body := fmt.Sprintf(`{"schemaVersion":%q,"id":"acme/mcp.send_email","tool":"send_email",
	  "server":{"name":"@acme/mcp"},
	  "attestation":{"author":"acme","source":"authored","review":"pending"},
	  "digest":"sha256:0",
	  "effect":{"class":"irreversible","CLASS":"reversible"}}`, registry.SchemaVersion)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "e.json"), []byte(body), 0o600))

	_, loadErr := registry.LoadCorpus(dir)
	require.Error(t, loadErr)
	assert.Contains(t, loadErr.Error(), "same name to a JSON decoder")
	assert.Contains(t, loadErr.Error(), `"effect"`, "the refusal must name the block the ambiguity is in")
}

// TestLoadCorpus_AcceptsRepeatedNamesInSiblingBlocks guards the other direction: "class"
// appears once per case row of an argument-parameterized table, which is not a duplicate of
// anything. Over-refusing would reject the corpus's most useful shape.
func TestLoadCorpus_AcceptsRepeatedNamesInSiblingBlocks(t *testing.T) {
	eff := &capability.EffectContract{
		ByArgument: &capability.EffectByArgument{
			Argument: "operation",
			Cases: map[string]capability.EffectCase{
				"select": {Class: capability.EffectReversible},
				"drop":   {Class: capability.EffectIrreversible},
			},
			Default: &capability.EffectCase{Class: capability.EffectIrreversible},
		},
	}
	digest, err := capability.EffectContractDigest(eff)
	require.NoError(t, err)
	entry := registry.Contract{
		SchemaVersion: registry.SchemaVersion, ID: "acme/db.query", Tool: "query",
		Server:      registry.ServerRef{Name: "@acme/db"},
		Attestation: registry.Attestation{Author: "acme", Source: registry.SourceAuthored, Review: registry.ReviewPending},
		Digest:      digest, Effect: eff,
	}
	body, err := json.Marshal(entry)
	require.NoError(t, err)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "e.json"), body, 0o600))

	loaded, loadErr := registry.LoadCorpus(dir)
	require.NoError(t, loadErr)
	require.Len(t, loaded, 1)
}
