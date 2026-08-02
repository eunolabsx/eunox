// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGrammarTables_CoverTheWholeVocabulary is the gate that keeps this package's two
// hand-maintained grammar tables in step with pkg/capability's prototype registries.
//
// The registries made the vocabulary derivable INSIDE pkg/capability — the decoder, the
// unknown-type message, the permitted-key sets and the published schema's drift guard all
// read them. The classification a manifest load depends on lives one package over, and was
// not derived from anything: tokenGrammarVersions was consulted with a comma-ok, so a token
// absent from it was silently admitted under schemaVersion "0.1". That is the fail-OPEN
// direction on the one guard whose entire job is stopping a later revision's predicate from
// widening an earlier one, and no test in the tree walked the registries against it.
//
// Every discriminator must now be classified into exactly one of the two tables. Being in
// neither is refused at load (checkTokenRevision), so this test is the build-time half of a
// gate that also fails closed at runtime.
func TestGrammarTables_CoverTheWholeVocabulary(t *testing.T) {
	for _, tc := range []struct {
		kind   string
		tokens []string
	}{
		{"condition", capability.KnownConditionTypes()},
		{"directive", capability.KnownDirectiveTypes()},
	} {
		for _, token := range tc.tokens {
			t.Run(tc.kind+"/"+token, func(t *testing.T) {
				_, gated := tokenGrammarVersions[token]
				base := baseGrammarTokens[token]
				assert.False(t, gated && base,
					"%q is in BOTH tables; it cannot be a base-grammar token and one a later revision introduced", token)
				assert.True(t, gated || base,
					"%q is in NEITHER tokenGrammarVersions nor baseGrammarTokens, so no manifest can carry it. "+
						"A token introduced after \"0.1\" belongs in tokenGrammarVersions (with a test asserting it is REFUSED under \"0.1\"); "+
						"one that is part of the base grammar belongs in baseGrammarTokens", token)
			})
		}
	}
}

// TestGrammarTables_NameOnlyRealTokens is the reverse direction. A stale entry — a token
// renamed or removed from the registry, with its classification left behind — is not
// fail-open, but it is a dead line that makes the tables look maintained while the real
// token is unclassified. The forward test above would still catch the real one; this names
// the leftover so the fix is obvious rather than a second puzzle.
func TestGrammarTables_NameOnlyRealTokens(t *testing.T) {
	known := map[string]bool{}
	for _, c := range capability.KnownConditionTypes() {
		known[c] = true
	}
	for _, d := range capability.KnownDirectiveTypes() {
		known[d] = true
	}
	for token := range tokenGrammarVersions {
		assert.True(t, known[token], "tokenGrammarVersions names %q, which is in neither prototype registry", token)
	}
	for token := range baseGrammarTokens {
		assert.True(t, known[token], "baseGrammarTokens names %q, which is in neither prototype registry", token)
	}
}

// TestDirectiveValidators_CoverEveryKnownDirective walks the directive registry against this
// package's per-type validation table. A directive present in the registry and missing here
// loads no manifest at all — the fail-closed default refuses it — so the failure is a
// diagnostic one rather than a hole: before the table existed, the type switch's default arm
// reported "the only supported directives are redactFields, labelOutput and declassify",
// naming three directives that were not the problem and pointing an author away from the
// fault.
func TestDirectiveValidators_CoverEveryKnownDirective(t *testing.T) {
	for _, dirType := range capability.KnownDirectiveTypes() {
		_, ok := directiveValidators[dirType]
		assert.True(t, ok, "directiveValidators has no entry for %q, so every manifest carrying it is refused at load", dirType)
	}
	for dirType := range directiveValidators {
		_, ok := capability.NewDirectivePrototype(dirType)
		assert.True(t, ok, "directiveValidators names %q, which pkg/capability's registry does not model", dirType)
	}
}

// TestUnknownDirectiveMessage_ComesFromTheRegistry pins that the fail-closed default
// ENUMERATES from KnownDirectiveTypes rather than restating a literal list. The old message
// hardcoded the three directives that existed when it was written; a fourth would have made
// it false, and an author reading a stale "the only supported directives are…" line has no
// way to tell that it is stale.
func TestUnknownDirectiveMessage_ComesFromTheRegistry(t *testing.T) {
	m := &LocalManifest{
		SchemaVersion: ManifestSchemaVersion01,
		Name:          "p",
		Version:       "1.0.0",
		Capabilities: []capability.Constraint{{
			Target:     "tool:x",
			Actions:    []string{"call"},
			Directives: []capability.Directive{unknownDirective{}},
		}},
	}
	err := validateLocalManifest(m)
	require.Error(t, err)
	for _, want := range capability.KnownDirectiveTypes() {
		assert.Contains(t, err.Error(), want, "the message must enumerate the real vocabulary")
	}
	assert.Contains(t, err.Error(), "no-such-directive")
}

// TestUnclassifiedTokenIsRefused is the runtime half of the completeness gate: a
// discriminator this build models but has classified into neither table is refused under
// EVERY revision, rather than silently admitted under "0.1".
//
// It is reached with a directive whose type is not in either table — the same shape a
// contributor produces by adding a directive to pkg/capability's registry and forgetting the
// grammar gate, except that here the type is unknown to the registry too, so the validation
// pass has to be bypassed to reach the gate. checkTokenGrammarVersion is therefore called
// directly, which is exactly the function under test.
func TestUnclassifiedTokenIsRefused(t *testing.T) {
	m := &LocalManifest{
		SchemaVersion: ManifestSchemaVersion01,
		Capabilities: []capability.Constraint{{
			Target:     "tool:x",
			Actions:    []string{"call"},
			Directives: []capability.Directive{unknownDirective{}},
		}},
	}
	err := checkTokenGrammarVersion(m)
	require.Error(t, err, "an unclassified token must not be admitted under any revision")
	assert.Contains(t, err.Error(), "not classified into any published schemaVersion")
	assert.Contains(t, err.Error(), "tokenGrammarVersions", "and the message must say how to fix it")

	// The same manifest under the later revision is refused identically: the gate is about
	// classification, not about which revision was declared.
	m.SchemaVersion = ManifestSchemaVersion02
	assert.Error(t, checkTokenGrammarVersion(m))
}

// TestFlowAndEffectTokensAreRefusedUnder01 is the assertion CONTRIBUTING requires for every
// token a revision later than "0.1" introduced, applied to the whole set at once and derived
// from the table rather than listed. Adding an entry to tokenGrammarVersions therefore
// brings its "refused under 0.1" coverage with it.
func TestFlowAndEffectTokensAreRefusedUnder01(t *testing.T) {
	for token, required := range tokenGrammarVersions {
		t.Run(token, func(t *testing.T) {
			require.Equal(t, ManifestSchemaVersion02, required,
				"a third revision needs its own refusal cases here, not just a map entry")
			c := constraintCarrying(t, token)
			m := &LocalManifest{SchemaVersion: ManifestSchemaVersion01, Capabilities: []capability.Constraint{c}}
			err := checkTokenGrammarVersion(m)
			require.Error(t, err, "%q must be refused under schemaVersion %q", token, ManifestSchemaVersion01)
			assert.Contains(t, err.Error(), token)

			m.SchemaVersion = required
			assert.NoError(t, checkTokenGrammarVersion(m), "%q must load under the revision that introduced it", token)
		})
	}
}

// constraintCarrying builds a constraint holding one token of the named type, whichever
// vocabulary it belongs to. It instantiates from pkg/capability's own prototype registries,
// so a token added there needs no case added here.
func constraintCarrying(t *testing.T, token string) capability.Constraint {
	t.Helper()
	c := capability.Constraint{Target: "tool:x", Actions: []string{"call"}}
	if cond, ok := capability.NewConditionPrototype(token); ok {
		c.Conditions = []capability.Condition{cond}
		return c
	}
	dir, ok := capability.NewDirectivePrototype(token)
	require.True(t, ok, "%q is in tokenGrammarVersions but in neither prototype registry", token)
	c.Directives = []capability.Directive{dir}
	return c
}

// unknownDirective is a directive type pkg/capability does not model, for driving the
// fail-closed arms. Its type string deliberately does not resemble a real one.
type unknownDirective struct{}

func (unknownDirective) DirectiveType() string { return "no-such-directive" }

// ToObligation is never reached — every path that would call it refuses the directive
// first — but the interface requires it, which is itself the point: a directive type the
// loader does not recognize is still a well-formed Directive to the compiler.
func (unknownDirective) ToObligation() capability.Obligation {
	return capability.Obligation{Type: "no-such-directive"}
}

// TestBaseGrammarTokensLoadUnderBothRevisions pins the other half of the classification: a
// base-grammar token is admitted under every published revision, so folding the two tables
// into one gate did not narrow "0.1".
func TestBaseGrammarTokensLoadUnderBothRevisions(t *testing.T) {
	for token := range baseGrammarTokens {
		t.Run(token, func(t *testing.T) {
			c := constraintCarrying(t, token)
			for _, v := range []string{ManifestSchemaVersion01, ManifestSchemaVersion02} {
				m := &LocalManifest{SchemaVersion: v, Capabilities: []capability.Constraint{c}}
				assert.NoError(t, checkTokenGrammarVersion(m),
					"%q is a base-grammar token and must load under schemaVersion %q", token, v)
			}
		})
	}
}

// TestGrammarTables_NoStrayPrefixes is a small guard on the message text the two gates
// produce, so a rename that leaves the error naming a token that no longer exists shows up
// here rather than in an operator's terminal.
func TestGrammarTables_NoStrayPrefixes(t *testing.T) {
	err := checkTokenRevision(0, capability.DirectiveTypeDeclassify, "directive", ManifestSchemaVersion01)
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), capability.DirectiveTypeDeclassify),
		"the refusal must name the token it refused")
	assert.NoError(t, checkTokenRevision(0, capability.DirectiveTypeDeclassify, "directive", ManifestSchemaVersion02))
}
