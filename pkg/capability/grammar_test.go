// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The grammar classification is a property of the registry entry, not of a table one package
// over. These pin the two things a consumer of TokenSince depends on: every token this build
// models declares a published revision, and nothing else is classified at all.

func TestTokenSince_EveryRegisteredTokenDeclaresAPublishedRevision(t *testing.T) {
	t.Parallel()
	published := map[string]bool{SchemaVersion01: true, SchemaVersion02: true}
	for _, token := range append(KnownConditionTypes(), KnownDirectiveTypes()...) {
		t.Run(token, func(t *testing.T) {
			since, ok := TokenSince(token)
			require.True(t, ok, "%q declares no Since, so the manifest loader must refuse every manifest carrying it", token)
			assert.True(t, published[since], "%q declares Since %q, which is not a published grammar revision", token, since)
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
