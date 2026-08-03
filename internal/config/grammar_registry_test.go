// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGrammarClassification_CoversTheWholeVocabulary is the gate that keeps the loader's
// schemaVersion check total over pkg/capability's prototype registries.
//
// The classification a manifest load depends on used to live here, as two hand-maintained
// maps: one naming the tokens a later revision introduced, one naming the base grammar. That
// split made a state representable that a test had to exclude rather than the types — a token
// filed in BOTH, or (the one that matters) filed in the WRONG one, which admits a "0.2"
// predicate under a "0.1" manifest. The revision now rides the registry entry that declares
// the token exists, so there is one answer per token by construction and this test asserts
// only that every entry declares one.
//
// A token TokenSince cannot classify is refused at load under every revision
// (checkTokenRevision), so this is the build-time half of a gate that also fails closed at
// runtime.
func TestGrammarClassification_CoversTheWholeVocabulary(t *testing.T) {
	published := map[string]bool{ManifestSchemaVersion01: true, ManifestSchemaVersion02: true}
	for _, tc := range []struct {
		kind   string
		tokens []string
	}{
		{"condition", capability.KnownConditionTypes()},
		{"directive", capability.KnownDirectiveTypes()},
	} {
		for _, token := range tc.tokens {
			t.Run(tc.kind+"/"+token, func(t *testing.T) {
				since, classified := capability.TokenSince(token)
				require.True(t, classified,
					"%q declares no Since on its pkg/capability prototype registry entry, so no manifest can carry it. "+
						"Every entry needs the published schemaVersion that introduced its discriminator", token)
				assert.True(t, published[since],
					"%q declares Since %q, which is not a published grammar revision", token, since)
			})
		}
	}
}

// TestGrammarClassification_RejectsUnknownTokens is the reverse direction: TokenSince must
// not classify something the registries do not model. It is what keeps the loader's gate from
// silently accepting a token this build cannot instantiate.
func TestGrammarClassification_RejectsUnknownTokens(t *testing.T) {
	for _, token := range []string{"", "no-such-token", "maxCall", "FLOWLABEL"} {
		_, classified := capability.TokenSince(token)
		assert.False(t, classified, "%q is in neither prototype registry and must not be classified", token)
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
	assert.Contains(t, err.Error(), "Since", "and the message must say how to fix it")

	// The same manifest under the later revision is refused identically: the gate is about
	// classification, not about which revision was declared.
	m.SchemaVersion = ManifestSchemaVersion02
	assert.Error(t, checkTokenGrammarVersion(m))
}

// TestFlowAndEffectTokensAreRefusedUnder01 is the assertion CONTRIBUTING requires for every
// token a revision later than "0.1" introduced, applied to the whole vocabulary at once and
// derived from the registry rather than listed. Declaring a later Since on a registry entry
// therefore brings its "refused under 0.1" coverage with it.
func TestFlowAndEffectTokensAreRefusedUnder01(t *testing.T) {
	for _, token := range allKnownTokens() {
		required, classified := capability.TokenSince(token)
		if !classified || required == ManifestSchemaVersion01 {
			continue // base grammar; TestBaseGrammarTokensLoadUnderBothRevisions covers those
		}
		t.Run(token, func(t *testing.T) {
			require.Equal(t, ManifestSchemaVersion02, required,
				"a third revision needs its own refusal cases here, not just a registry entry")
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

// allKnownTokens is the whole closed vocabulary — every condition and directive
// discriminator — read from the prototype registries the classification now rides on.
func allKnownTokens() []string {
	return append(capability.KnownConditionTypes(), capability.KnownDirectiveTypes()...)
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
	require.True(t, ok, "%q is classified but in neither prototype registry", token)
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
// base-grammar token is admitted under every published revision, so deriving the gate from
// one registry entry did not narrow "0.1" (the mirror mistake of admitting a "0.2" token
// under it).
func TestBaseGrammarTokensLoadUnderBothRevisions(t *testing.T) {
	for _, token := range allKnownTokens() {
		if since, classified := capability.TokenSince(token); !classified || since != ManifestSchemaVersion01 {
			continue
		}
		t.Run(token, func(t *testing.T) {
			c := constraintCarrying(t, token)
			// The published sequence, not a restated pair: a base-grammar token must load
			// under EVERY published revision, which is what the name says and what a
			// two-element literal stops asserting the moment a third is published.
			for _, v := range supportedManifestSchemaVersions {
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

// TestDirectiveValidator_TypeMismatchIsRefusedNotPanicked covers the failure mode that
// appeared the moment dispatch moved off the concrete Go type. directiveValidators is keyed
// by dir.DirectiveType() — a string the directive REPORTS — so a value whose report
// disagrees with its type selects an entry whose assertion then fails. The type switch this
// replaced could not reach that state; a discarded ok here would dereference nil and panic
// the loader, turning a fail-closed load error into a crash on the path the fail-closed arm
// exists for (a programmatically built manifest, reachable through MergeManifests).
func TestDirectiveValidator_TypeMismatchIsRefusedNotPanicked(t *testing.T) {
	m := &LocalManifest{
		SchemaVersion: ManifestSchemaVersion01,
		Name:          "p",
		Version:       "1.0.0",
		Capabilities: []capability.Constraint{{
			Target:     "tool:x",
			Actions:    []string{"call"},
			Directives: []capability.Directive{impostorDirective{}},
		}},
	}
	require.NotPanics(t, func() {
		err := validateLocalManifest(m)
		require.Error(t, err, "a directive that is not the type it claims must be refused")
		assert.Contains(t, err.Error(), "reports type")
		assert.Contains(t, err.Error(), capability.DirectiveTypeRedactFields)
	})
}

// impostorDirective reports a discriminator the registry models while being an entirely
// different Go type — the shape a keyed dispatch cannot rule out and a type switch could.
type impostorDirective struct{}

func (impostorDirective) DirectiveType() string { return capability.DirectiveTypeRedactFields }
func (impostorDirective) ToObligation() capability.Obligation {
	return capability.Obligation{Type: capability.DirectiveTypeRedactFields}
}

// withPublishedRevision appends a synthetic grammar revision to the published sequence for
// the duration of one test, and returns it.
//
// A third revision cannot otherwise be covered before it exists, and "before it exists" is
// exactly when the forward-compatibility of the gate has to be right: the failure it guards
// against is a semantics-only revision that introduces NO token and, under a rule spelled as
// an equality, refuses every token its predecessor defined — with the operator told their
// flowLabel condition "requires schemaVersion 0.2" on a manifest that declares 0.3.
//
// It mutates a package var, so its tests do not run in parallel.
func withPublishedRevision(t *testing.T) string {
	t.Helper()
	const synthetic = "0.3-synthetic"
	orig := supportedManifestSchemaVersions
	supportedManifestSchemaVersions = append(slices.Clone(orig), synthetic)
	t.Cleanup(func() { supportedManifestSchemaVersions = orig })
	return synthetic
}

// TestThirdRevisionInheritsEveryPublishedToken is the forward-compatibility guard on the
// grammar gate. Every token any published revision introduced must still load under a revision
// published AFTER it — including the whole flow+effect batch, which a rule written for exactly
// two revisions refused the moment a third appeared.
func TestThirdRevisionInheritsEveryPublishedToken(t *testing.T) {
	next := withPublishedRevision(t)
	for _, token := range allKnownTokens() {
		if _, classified := capability.TokenSince(token); !classified {
			continue
		}
		t.Run(token, func(t *testing.T) {
			m := &LocalManifest{
				SchemaVersion: next,
				Capabilities:  []capability.Constraint{constraintCarrying(t, token)},
			}
			assert.NoError(t, checkTokenGrammarVersion(m),
				"%q was published before %q and must still be part of its grammar", token, next)
		})
	}
}

// TestThirdRevisionInheritsTheNonDiscriminatorTokens covers the same rule for the four tokens
// that carry no prototype-registry entry and are therefore gated by hand — the top-level
// effectCeiling, a constraint's effect contract, the ${task.*} variables, and the wire-side
// attribution interface. Each was its own equality against the introducing revision, so each
// would have inverted independently.
func TestThirdRevisionInheritsTheNonDiscriminatorTokens(t *testing.T) {
	next := withPublishedRevision(t)

	ceiling := &LocalManifest{
		SchemaVersion: next,
		EffectCeiling: &capability.EffectCeiling{MaxEffectClass: capability.EffectReversible},
		Capabilities:  []capability.Constraint{{Target: "tool:x", Actions: []string{"call"}}},
	}
	assert.NoError(t, checkTokenGrammarVersion(ceiling), "the top-level effectCeiling must survive a later revision")

	contract := &LocalManifest{
		SchemaVersion: next,
		Capabilities: []capability.Constraint{{
			Target: "tool:x", Actions: []string{"call"},
			Effect: &capability.EffectContract{Class: capability.EffectReversible},
		}},
	}
	assert.NoError(t, checkTokenGrammarVersion(contract), "a capability's effect contract must survive a later revision")

	taskVar := &LocalManifest{
		SchemaVersion: next,
		Capabilities: []capability.Constraint{{
			Target: "tool:x", Actions: []string{"call"},
			Conditions: []capability.Condition{capability.AllowedValuesCondition{
				Argument: "a", Values: []interface{}{"${" + capability.TaskVarID + "}"},
			}},
		}},
	}
	assert.NoError(t, checkTokenGrammarVersion(taskVar), "a ${task.*} reference must survive a later revision")

	assert.True(t, (&LocalManifest{SchemaVersion: next}).HonorsAttributionInterface(),
		"the attribution interface must stay admitted under a revision published after the one that introduced it")
}

// TestEarlierRevisionStaysClosedAgainstALaterToken is the half that must NOT change:
// inheritance runs forward only. A token a later revision introduces is still refused under
// every revision published before it, which is the gate's entire job.
func TestEarlierRevisionStaysClosedAgainstALaterToken(t *testing.T) {
	next := withPublishedRevision(t)
	assert.False(t, revisionAdmits(ManifestSchemaVersion01, next),
		"the base grammar must not admit a token introduced by a later revision")
	assert.False(t, revisionAdmits(ManifestSchemaVersion02, next))
	assert.True(t, revisionAdmits(next, ManifestSchemaVersion01))
	assert.True(t, revisionAdmits(next, ManifestSchemaVersion02))
	assert.True(t, revisionAdmits(next, next))

	// And an unknown revision on either side admits nothing: this build cannot place it in
	// the sequence, so it must refuse rather than guess.
	assert.False(t, revisionAdmits("0.9-unpublished", ManifestSchemaVersion01))
	assert.False(t, revisionAdmits(ManifestSchemaVersion02, "0.9-unpublished"))
}

// TestThirdRevisionLoadsAFlowManifestEndToEnd drives the whole loader rather than the gate
// alone: a manifest file declaring the synthetic revision and carrying a flow+effect token
// must load. The two halves are separate reads of the published sequence — one decides which
// versions parse, the other which tokens each admits — and this is what pins that they agree.
func TestThirdRevisionLoadsAFlowManifestEndToEnd(t *testing.T) {
	next := withPublishedRevision(t)
	path := filepath.Join(t.TempDir(), "m.yaml")
	body := "schemaVersion: \"" + next + "\"\nname: m\nversion: \"1.0.0\"\n" +
		"capabilities:\n  - target: tool:t\n    actions: [call]\n" +
		"    conditions:\n      - type: flowLabel\n        allow: [public]\n" +
		"    directives:\n      - type: labelOutput\n        labels: [pii]\n"
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	m, err := LoadManifest(path)
	require.NoError(t, err, "a revision published after 0.2 still contains 0.2's grammar")
	require.Len(t, m.Capabilities, 1)
	assert.True(t, m.HasFlowLabel())
}
