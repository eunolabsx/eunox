// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"encoding/json"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The directive half of TestConditionRegistry_DrivesEveryDerivedTable. It matters more
// than the condition half did, because the directive vocabulary's only completeness
// guard compares COUNTS: cmd/eunox's schema drift test builds its expectation by walking
// KnownDirectiveTypes and asserts len(branches) == len(want), so a hand-written
// KnownDirectiveTypes that fell behind the decoder kept both sides at the same stale
// number and let a directive ship with no published schema branch.

func TestDirectiveRegistry_DrivesEveryDerivedTable(t *testing.T) {
	t.Parallel()
	require.NotEmpty(t, directivePrototypes)

	for dirType := range directivePrototypes {
		t.Run(dirType, func(t *testing.T) {
			// newDirective instantiates it...
			d := newDirective(dirType)
			require.NotNil(t, d, "every registered type must instantiate")
			assert.Equal(t, dirType, d.DirectiveType(), "the prototype must report the discriminator it is registered under")

			// ...the exported vocabulary lists it (this is the list the schema drift
			// guard derives its expectation from)...
			assert.Contains(t, KnownDirectiveTypes(), dirType)

			// ...the exported prototype accessor returns it, freshly each time...
			proto, ok := NewDirectivePrototype(dirType)
			require.True(t, ok)
			require.NotNil(t, proto)
			other, _ := NewDirectivePrototype(dirType)
			assert.NotSame(t, proto, other, "each call must return a fresh value, so a caller cannot mutate the registry")

			// ...and it round-trips through the polymorphic envelope with its
			// discriminator intact, which is what the manifest digest is taken over.
			b, err := json.Marshal(DirectiveWrapper{Directive: proto})
			require.NoError(t, err, "every registered type must marshal")
			var back DirectiveWrapper
			require.NoError(t, json.Unmarshal(b, &back), "and unmarshal: %s", b)
			require.NotNil(t, back.Directive)
			assert.Equal(t, dirType, back.DirectiveType())
		})
	}
}

// KnownDirectiveTypes must be EXACTLY the decoder's registry, not a superset or a subset
// of it. A superset makes the drift guard demand a schema branch for a token no manifest
// can carry; a subset is the fail-open direction the mirrored list actually shipped.
func TestDirectiveRegistry_KnownTypesMatchTheDecoder(t *testing.T) {
	t.Parallel()
	want := make([]string, 0, len(directivePrototypes))
	for dirType := range directivePrototypes {
		want = append(want, dirType)
	}
	sort.Strings(want)
	assert.Equal(t, want, KnownDirectiveTypes(), "the exported vocabulary must be derived from the registry, never mirrored")

	// A fresh slice per call: a consumer that sorts or truncates its copy must not be
	// able to reshape the package's accepted set.
	first := KnownDirectiveTypes()
	first[0] = "mutated"
	assert.NotEqual(t, "mutated", KnownDirectiveTypes()[0])
}

func TestDirectiveRegistry_RejectsAnUnknownType(t *testing.T) {
	t.Parallel()
	assert.Nil(t, newDirective("no_such_directive"))
	_, ok := NewDirectivePrototype("no_such_directive")
	assert.False(t, ok)
	assert.NotContains(t, KnownDirectiveTypes(), "no_such_directive")

	// The unknown-type error enumerates the registry rather than a literal, so an
	// author reading it cannot be shown a stale vocabulary.
	_, err := unmarshalDirective([]byte(`{"type":"no_such_directive"}`))
	require.Error(t, err)
	for _, dirType := range KnownDirectiveTypes() {
		assert.Contains(t, err.Error(), dirType)
	}
}
