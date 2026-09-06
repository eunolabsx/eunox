// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package redisutil

import (
	"context"
	"testing"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReconcile_EveryCell drives all nine (declared, classified) pairs of the rule both Redis
// backends now share, because it is the rule the two hand-written copies this replaced had already
// diverged on. Each package's DIAGNOSIS stays its own; what must not differ is the outcome.
func TestReconcile_EveryCell(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		classified  Topology
		declared    Topology
		wantOutcome Reconciliation
		wantResolve Topology
		// wantFromDeclaration says which side's iterator the resolution must carry. Only
		// meaningful for a sharded resolution.
		wantFromDeclaration bool
	}{
		{"nothing established, nothing declared", TopologyUnknown, TopologyUnknown, ReconcileUndetermined, TopologyUnknown, false},
		{"single-node established, nothing declared", TopologySingleNode, TopologyUnknown, ReconcileSettled, TopologySingleNode, false},
		{"sharded established, nothing declared", TopologySharded, TopologyUnknown, ReconcileSettled, TopologySharded, false},
		{"nothing established, single-node declared", TopologyUnknown, TopologySingleNode, ReconcileSettled, TopologySingleNode, true},
		{"nothing established, sharded declared", TopologyUnknown, TopologySharded, ReconcileSettled, TopologySharded, true},
		{"single-node established and declared", TopologySingleNode, TopologySingleNode, ReconcileSettled, TopologySingleNode, false},
		{"sharded established and declared", TopologySharded, TopologySharded, ReconcileSettled, TopologySharded, false},
		{"single-node established, sharded declared", TopologySingleNode, TopologySharded, ReconcileContradicted, TopologyUnknown, false},
		{"sharded established, single-node declared", TopologySharded, TopologySingleNode, ReconcileContradicted, TopologyUnknown, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// The two iterators are told apart by what they DO, not by func identity: funcs are
			// incomparable, and comparing code pointers would rest on the compiler not merging two
			// identical bodies. Built per subtest so parallel cells share no marker.
			var ran string
			mark := func(who string) ShardFanOut {
				return func(context.Context, func(context.Context, *redis.Client) error) error {
					ran = who
					return nil
				}
			}
			fanOutOf := map[Topology]ShardFanOut{TopologySharded: mark("classified")}
			declaredFanOutOf := map[Topology]ShardFanOut{TopologySharded: mark("declared")}

			got, outcome := Reconcile(
				Resolution{Topology: tc.classified, FanOut: fanOutOf[tc.classified]},
				Resolution{Topology: tc.declared, FanOut: declaredFanOutOf[tc.declared]},
			)
			require.Equal(t, tc.wantOutcome, outcome, "outcome for (classified %s, declared %s)", tc.classified, tc.declared)
			assert.Equal(t, tc.wantResolve, got.Topology)
			if tc.wantOutcome != ReconcileSettled {
				assert.Nil(t, got.FanOut, "a refusal must resolve to nothing; a caller reading a topology off it would act on a pair that was never settled")
				return
			}
			if tc.wantResolve != TopologySharded {
				return
			}
			// An AGREEING declaration must keep the CLASSIFIED iterator: the declared one carries
			// nothing the type did not already supply, and preferring it is how a working fan-out
			// gets swapped for whatever a consumer happened to hand over.
			want := "classified"
			if tc.wantFromDeclaration {
				want = "declared"
			}
			require.NotNil(t, got.FanOut)
			require.NoError(t, got.FanOut(context.Background(), nil))
			assert.Equal(t, want, ran, "resolution carried the wrong side's iterator")
		})
	}
}

// TestReconcile_DeclarationNeverOverridesAnEstablishedTopology states the asymmetry as a property
// rather than as cells: honoring a declaration over a classification is the fail-open both
// backends' refusals exist to close, reached through the option added to make them tolerable.
func TestReconcile_DeclarationNeverOverridesAnEstablishedTopology(t *testing.T) {
	t.Parallel()
	for _, classified := range []Topology{TopologySingleNode, TopologySharded} {
		for _, declared := range []Topology{TopologySingleNode, TopologySharded} {
			got, outcome := Reconcile(Resolution{Topology: classified}, Resolution{Topology: declared})
			if classified == declared {
				assert.Equal(t, ReconcileSettled, outcome)
				assert.Equal(t, classified, got.Topology)
				continue
			}
			assert.Equal(t, ReconcileContradicted, outcome,
				"declared %s beside a client whose type says %s must be refused, never obeyed", declared, classified)
		}
	}
}

// TestReconciliation_String pins the labels an error or log line renders, including the value no
// constructor produces — a caller switching on an outcome it does not recognize must still be able
// to name it.
func TestReconciliation_String(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "settled", ReconcileSettled.String())
	assert.Equal(t, "undetermined", ReconcileUndetermined.String())
	assert.Equal(t, "contradicted", ReconcileContradicted.String())
	assert.Equal(t, "unknown", Reconciliation(99).String())
}
