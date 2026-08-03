// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The grammar classification is a property of the registry entry, not of a table one package
// over. These pin the two things a consumer of TokenSince depends on: every token this build
// models declares a published revision, and nothing else is classified at all.

func TestTokenSince_EveryRegisteredTokenDeclaresAPublishedRevision(t *testing.T) {
	t.Parallel()
	// The published sequence itself, not a restatement of it: this file declares that
	// sequence to be the one place the revisions are written down, and a literal here would
	// be the second — failing on correct code the first time a token is filed under a newly
	// published revision, with the reflex fix being to edit the copy.
	for _, token := range append(KnownConditionTypes(), KnownDirectiveTypes()...) {
		t.Run(token, func(t *testing.T) {
			since, ok := TokenSince(token)
			require.True(t, ok, "%q declares no Since, so the manifest loader must refuse every manifest carrying it", token)
			assert.True(t, slices.Contains(publishedSchemaVersions, since),
				"%q declares Since %q, which is not a published grammar revision", token, since)
		})
	}
}

// A token with no Since is UNCLASSIFIED, not base grammar. The comma-ok that reported an
// unclassified token as part of "0.1" is the fail-open this whole gate exists to reverse, so
// an entry with an empty Since must read as "cannot classify" even though the token
// instantiates fine.
func TestTokenSince_EmptySinceIsUnclassified(t *testing.T) {
	const token = "unclassifiedForTest"
	conditionPrototypes[token] = tokenSpec[Condition]{New: func() Condition { return &MaxCallsCondition{} }}
	t.Cleanup(func() { delete(conditionPrototypes, token) })

	since, ok := TokenSince(token)
	assert.False(t, ok, "an entry with no Since must not be classified")
	assert.Empty(t, since)
}

func TestTokenSince_UnknownTokenIsUnclassified(t *testing.T) {
	t.Parallel()
	for _, token := range []string{"", "no-such-token", "MAXCALLS", "maxCall"} {
		since, ok := TokenSince(token)
		assert.False(t, ok, "%q is in neither registry", token)
		assert.Empty(t, since)
	}
}

// The two revisions are distinct strings and the flow+effect batch really is filed under the
// later one — the mis-classification that a separate table made possible, now readable off
// the registry.
func TestTokenSince_FlowAndEffectTokensAreTheLaterRevision(t *testing.T) {
	t.Parallel()
	require.NotEqual(t, SchemaVersion01, SchemaVersion02)
	for _, token := range []string{
		ConditionTypeFlowLabel, ConditionTypeEffectClass, ConditionTypeBlastRadius,
		DirectiveTypeLabelOutput, DirectiveTypeDeclassify,
	} {
		since, ok := TokenSince(token)
		require.True(t, ok)
		assert.Equal(t, SchemaVersion02, since, "%q belongs to the flow+effect revision", token)
	}
	for _, token := range []string{ConditionTypeMaxCalls, ConditionTypeTimeWindow, DirectiveTypeRedactFields} {
		since, ok := TokenSince(token)
		require.True(t, ok)
		assert.Equal(t, SchemaVersion01, since, "%q is base grammar", token)
	}
}

// TestTokenRegistries_AreDisjoint keeps the one state the two-table classification could
// represent from surviving the move onto the registries: a discriminator present in BOTH
// vocabularies. TokenSince resolves conditions first, so such a token would silently take the
// condition's revision — a directive spelling of it would then load under whichever revision
// the condition declares. The old completeness test asserted "not in both" over the two
// tables; this asserts it over the two registries, which is where it is now representable.
func TestTokenRegistries_AreDisjoint(t *testing.T) {
	// Not parallel: it reads the registries a sibling test temporarily adds an entry to.
	for _, token := range KnownConditionTypes() {
		_, alsoDirective := directivePrototypes[token]
		assert.False(t, alsoDirective,
			"%q is registered as BOTH a condition and a directive; one discriminator cannot have two classifications", token)
	}
}

// TestTokenRegistries_EveryEntryCanInstantiate is the other half a generic registry value made
// representable: an entry declaring only Since compiles, reads plausibly, and classifies fine —
// and then panics on a nil func call the first time a manifest names it, turning a fail-closed
// load error into a crash on the load path.
func TestTokenRegistries_EveryEntryCanInstantiate(t *testing.T) {
	// Not parallel: same reason as TestTokenRegistries_AreDisjoint above.
	for token, spec := range conditionPrototypes {
		require.NotNil(t, spec.New, "condition %q declares no constructor", token)
		assert.NotNil(t, spec.New(), "condition %q must instantiate", token)
	}
	for token, spec := range directivePrototypes {
		require.NotNil(t, spec.New, "directive %q declares no constructor", token)
		assert.NotNil(t, spec.New(), "directive %q must instantiate", token)
	}
}
