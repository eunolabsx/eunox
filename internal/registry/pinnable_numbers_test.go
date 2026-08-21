// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package registry_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/internal/config"
	"github.com/eunolabs/eunox/internal/registry"
	"github.com/eunolabs/eunox/pkg/capability"
)

// A corpus entry exists to be COPIED into a manifest and pinned by digest. The corpus loader
// keeps a number's literal (UseNumber) while the manifest loader renormalizes it through
// YAML -> interface{} -> JSON, so a spelling that does not survive that round trip digests to
// two different values: the entry publishes and self-validates, and the verbatim copy can
// never match its own pin — reported as "the block was edited after it was pinned", blaming
// the author for a block they did not touch. These pin both halves: the unpinnable spelling
// is refused at publish, and a published one still pins end to end.

// shippedCorpusDir is the corpus this repository publishes, relative to this package.
const shippedCorpusDir = "../../registry/contracts"

// numberedContract builds an entry whose blast radius carries the given literal spelling.
func numberedContract(t *testing.T, literal string) registry.Contract {
	t.Helper()
	n := json.Number(literal)
	eff := &capability.EffectContract{
		Class:       capability.EffectReversible,
		BlastRadius: &capability.BlastRadiusSpec{Value: &n, Unit: "rows"},
	}
	digest, err := capability.EffectContractDigest(eff)
	require.NoError(t, err)
	return registry.Contract{
		SchemaVersion: registry.SchemaVersion, ID: "acme/mcp.read_rows", Tool: "read_rows",
		Server:      registry.ServerRef{Name: "@acme/mcp"},
		Attestation: registry.Attestation{Author: "acme", Source: registry.SourceAuthored, Review: registry.ReviewPending},
		Digest:      digest, Effect: eff,
	}
}

// TestValidateRefusesAnUnpinnableNumberLiteral: each of these self-validates (the digest is
// over its own literal) and is nonetheless unusable, so the refusal is at publish time.
func TestValidateRefusesAnUnpinnableNumberLiteral(t *testing.T) {
	for literal, canonical := range map[string]string{
		"1.0":   "1",
		"1e3":   "1000",
		"1.50":  "1.5",
		"100.0": "100",
	} {
		t.Run(literal, func(t *testing.T) {
			c := numberedContract(t, literal)
			err := c.Validate()
			require.Error(t, err, "a literal a manifest renormalizes must not be publishable")
			assert.Contains(t, err.Error(), canonical, "the refusal must name the spelling to write instead")
			assert.NotContains(t, err.Error(), "was edited without re-digesting",
				"the entry IS digest-consistent; reporting it as tampering is the misdiagnosis this check exists to replace")
		})
	}
}

// TestValidateAcceptsPinnableNumberLiterals: the check must not refuse a spelling the
// manifest loader leaves alone, including an integer past float64's exact range (yaml.v3
// resolves it through uint64, which round-trips).
func TestValidateAcceptsPinnableNumberLiterals(t *testing.T) {
	for _, literal := range []string{"1", "0", "1000", "1.5", "12345678901234567890", "1e999"} {
		t.Run(literal, func(t *testing.T) {
			c := numberedContract(t, literal)
			assert.NoError(t, c.Validate())
		})
	}
}

// TestValidateRefusesAnUnrepresentableMagnitudeWithoutRenamingIt: a literal the manifest
// loader ROUNDS (or cannot carry at all) has no faithful spelling, so the refusal must say
// so rather than name its renormalized form — following that advice would declare a
// different magnitude, and a blast radius is the ceiling's and the cumulative bound's own
// input.
func TestValidateRefusesAnUnrepresentableMagnitudeWithoutRenamingIt(t *testing.T) {
	for name, tc := range map[string]struct{ literal, rounded string }{
		// Rounds through float64: 1.2345678901234568e+29, ~1.2e13 away from what was written.
		"past float64's exact range": {"123456789012345678901234567890", "1.2345678901234568e+29"},
		// Underflows to zero, which is a bound that admits no quantified call at all.
		"below float64's smallest": {"1e-999", "0"},
	} {
		t.Run(name, func(t *testing.T) {
			c := numberedContract(t, tc.literal)
			err := c.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.literal, "the refusal must name the literal it is refusing")
			// The rounded form may be REPORTED — it is what would be enforced — but never
			// recommended, which is the form the re-spelling case ("so write 1 here") uses.
			assert.NotContains(t, err.Error(), "write "+tc.rounded+" here",
				"a magnitude the author did not write must not be offered as the correction")
			assert.NotContains(t, err.Error(), "so write",
				"there is no faithful spelling of this literal to recommend")
		})
	}
}

// TestValidateAcceptsALiteralTheLoaderStoresVerbatim guards the over-refusal direction on
// the case that is easiest to get wrong: yaml.v3 declines to resolve an exponent past
// float64's range and leaves the scalar a STRING, which the manifest loader re-marshals
// quoted and encoding/json accepts into the json.Number field verbatim — so the literal
// reaches the policy unchanged and IS pinnable, though a check reading the yaml kind alone
// would call it unusable. Asserted end to end rather than on the helper, since the property
// is about what the loader stores.
func TestValidateAcceptsALiteralTheLoaderStoresVerbatim(t *testing.T) {
	c := numberedContract(t, "1e999")
	require.NoError(t, c.Validate())

	block, err := json.Marshal(map[string]json.RawMessage{
		"class":       json.RawMessage(`"reversible"`),
		"blastRadius": json.RawMessage(`{"value":1e999,"unit":"rows"}`),
		"ref":         json.RawMessage(fmt.Sprintf("%q", c.Ref())),
	})
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "manifest.json")
	body := fmt.Sprintf(`{"schemaVersion":"0.2","name":"m","version":"1.0.0",
	  "capabilities":[{"target":"tool:t","actions":["call"],"effect":%s}]}`, block)
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	_, loadErr := config.LoadManifest(path)
	require.NoError(t, loadErr, "the literal reaches the manifest verbatim, so its pin must verify")
}

// TestValidateChecksEveryMagnitudeInATable: a case row and the default carry the same
// literal and the same consequence, so neither may be published unpinnable either.
func TestValidateChecksEveryMagnitudeInATable(t *testing.T) {
	n := json.Number("1.0")
	for name, table := range map[string]*capability.EffectByArgument{
		"case row": {Argument: "op", Cases: map[string]capability.EffectCase{
			"drop": {Class: capability.EffectIrreversible, BlastRadius: &capability.BlastRadiusSpec{Value: &n, Unit: "rows"}},
		}},
		"default row": {Argument: "op", Default: &capability.EffectCase{
			Class: capability.EffectIrreversible, BlastRadius: &capability.BlastRadiusSpec{Value: &n, Unit: "rows"},
		}},
	} {
		t.Run(name, func(t *testing.T) {
			eff := &capability.EffectContract{ByArgument: table}
			digest, err := capability.EffectContractDigest(eff)
			require.NoError(t, err)
			c := registry.Contract{
				SchemaVersion: registry.SchemaVersion, ID: "acme/db.query", Tool: "query",
				Server:      registry.ServerRef{Name: "@acme/db"},
				Attestation: registry.Attestation{Author: "acme", Source: registry.SourceAuthored, Review: registry.ReviewPending},
				Digest:      digest, Effect: eff,
			}
			require.ErrorContains(t, c.Validate(), "could never match this entry")
		})
	}
}

// TestPublishedCorpusEntriesPinFromTheirOwnBytes is the end-to-end property, run over the
// SHIPPED corpus: each entry's effect block, copied out of the file verbatim and pinned by
// the ref the entry publishes, loads in a manifest. It reads the raw file rather than the
// decoded Contract, because renormalizing the block on the way in is exactly the step that
// would hide the bug.
func TestPublishedCorpusEntriesPinFromTheirOwnBytes(t *testing.T) {
	entries, err := os.ReadDir(shippedCorpusDir)
	require.NoError(t, err)
	loaded, err := registry.LoadCorpus(shippedCorpusDir)
	require.NoError(t, err)
	refs := make(map[string]string, len(loaded))
	for _, c := range loaded {
		refs[c.ID] = c.Ref()
	}

	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		t.Run(e.Name(), func(t *testing.T) {
			raw, readErr := os.ReadFile(filepath.Join(shippedCorpusDir, e.Name()))
			require.NoError(t, readErr)
			// map[string]json.RawMessage, so every value below the top level keeps the
			// bytes the publisher wrote.
			var doc map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(raw, &doc))
			var id string
			require.NoError(t, json.Unmarshal(doc["id"], &id))
			var block map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(doc["effect"], &block))
			ref, err := json.Marshal(refs[id])
			require.NoError(t, err)
			block["ref"] = ref
			pinned, err := json.Marshal(block)
			require.NoError(t, err)

			path := filepath.Join(t.TempDir(), "manifest.json")
			body := fmt.Sprintf(`{"schemaVersion":"0.2","name":"m","version":"1.0.0",
			  "capabilities":[{"target":"tool:t","actions":["call"],"effect":%s}]}`, pinned)
			require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
			_, loadErr := config.LoadManifest(path)
			require.NoError(t, loadErr, "a published entry's own bytes must satisfy the pin it publishes")
		})
	}
}
