// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability_test

import (
	"context"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/pkg/capability"
)

// A kid past the bound is refused before anything hashes it, at BOTH seams that route one into
// the JWKS cache: the token-side extractor and the rotation choreography an out-of-tree caller
// can reach directly. The negative cache digests the kid twice per rejected token on the
// pre-auth path, so what the bound buys is that the cost is constant rather than chosen by
// whoever is sending the tokens.
func TestKIDBound_RefusedAtEverySeamThatReachesTheCache(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("k", capability.MaxKIDBytes+1)

	t.Run("CandidateKIDs", func(t *testing.T) {
		t.Parallel()
		_, err := capability.CandidateKIDs([]jose.Header{{KeyID: long}})
		require.Error(t, err, "an over-long kid must not reach the key set or the negative cache")
		assert.Contains(t, err.Error(), "exceeding the limit")

		// The whole token, not just the offending header: dropping one would silently narrow
		// which signatures a multi-signature JWS was checked against.
		_, err = capability.CandidateKIDs([]jose.Header{{KeyID: "good"}, {KeyID: long}})
		require.Error(t, err)
	})

	t.Run("VerifyWithKeyRotation", func(t *testing.T) {
		t.Parallel()
		// A nil cache proves the refusal precedes every cache interaction: reaching one would
		// panic rather than return this error.
		_, err := capability.VerifyWithKeyRotation(context.Background(), nil, long,
			func(*jose.JSONWebKey, bool) (*struct{}, error) {
				t.Fatal("verify must never run for a kid past the bound")
				return nil, nil
			})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeding the limit")
	})
}

// The bound is generous, not tight: every kid an issuer actually publishes is well inside it,
// and a kid-less token keeps the "" try-every-key sentinel.
func TestKIDBound_AdmitsRealisticIdentifiers(t *testing.T) {
	t.Parallel()
	for _, kid := range []string{
		"",
		"1",
		"a4f9b2c1-7e3d-4a6b-9c0f-2d8e1b5a3c74",
		strings.Repeat("f", 64), // a SHA-256 thumbprint in hex
		strings.Repeat("k", capability.MaxKIDBytes),
	} {
		kids, err := capability.CandidateKIDs([]jose.Header{{KeyID: kid}})
		require.NoError(t, err, "kid of %d bytes must be admitted", len(kid))
		assert.Equal(t, []string{kid}, kids)
	}
}
