// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Adding a condition type used to mean editing three hand-maintained tables in this
// package plus one in the manifest loader. These pin that the derived tables cannot fall
// behind the one registry they now come from.

func TestConditionRegistry_DrivesEveryDerivedTable(t *testing.T) {
	t.Parallel()
	require.NotEmpty(t, conditionPrototypes)

	for condType := range conditionPrototypes {
		t.Run(condType, func(t *testing.T) {
			// newCondition instantiates it...
			c := newCondition(condType)
			require.NotNil(t, c, "every registered type must instantiate")
			assert.Equal(t, condType, c.ConditionType(), "the prototype must report the discriminator it is registered under")

			// ...the "did you mean" vocabulary lists it...
			assert.Contains(t, knownConditionTypes, condType)

			// ...the exported prototype accessor returns it, freshly each time...
			proto, ok := NewConditionPrototype(condType)
			require.True(t, ok)
			require.NotNil(t, proto)
			other, _ := NewConditionPrototype(condType)
			assert.NotSame(t, proto, other, "each call must return a fresh value, so a caller cannot mutate the registry")

			// ...and it round-trips through the polymorphic envelope with its
			// discriminator intact, which is what the manifest digest is taken over.
			b, err := json.Marshal(ConditionWrapper{Condition: proto})
			require.NoError(t, err, "every registered type must marshal")
			var back ConditionWrapper
			require.NoError(t, json.Unmarshal(b, &back), "and unmarshal: %s", b)
			require.NotNil(t, back.Condition)
			assert.Equal(t, condType, back.Condition.ConditionType())
		})
	}
}

func TestConditionRegistry_RejectsAnUnknownType(t *testing.T) {
	t.Parallel()
	assert.Nil(t, newCondition("no_such_condition"))
	_, ok := NewConditionPrototype("no_such_condition")
	assert.False(t, ok)
	assert.NotContains(t, knownConditionTypes, "no_such_condition")
}

// redactFields is a directive, not a condition: it must stay out of the registry so its
// migration error (pointing at directives) keeps firing instead of a generic unknown-type
// message or, worse, an accidental instantiation.
func TestConditionRegistry_ExcludesRedactFields(t *testing.T) {
	t.Parallel()
	_, ok := conditionPrototypes[DirectiveTypeRedactFields]
	assert.False(t, ok, "redactFields is a directive and must not be a registered condition type")

	_, err := unmarshalCondition([]byte(`{"type":"redactFields","paths":["a"]}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "directives", "the migration hint must survive")
}
