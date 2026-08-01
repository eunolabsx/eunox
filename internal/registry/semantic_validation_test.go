// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
)

// TestValidateRejectsASemanticallyInvalidContract is the gap the digest check alone left
// open: a digest over nonsense is still a stable digest. A corpus entry whose contract is
// semantically invalid — a class typo, a compensable contract naming no compensating
// action, a blast radius declaring both a value and an argument — used to validate and
// digest cleanly here, so the artifact whose entire purpose is to be reviewable and
// pinnable was not machine-reviewable, and the mistake surfaced later as a confusing
// manifest-load error about a block the author had copied verbatim from the corpus.
func TestValidateRejectsASemanticallyInvalidContract(t *testing.T) {
	entryFor := func(t *testing.T, e *capability.EffectContract) Contract {
		t.Helper()
		d, err := capability.EffectContractDigest(e)
		if err != nil {
			t.Fatalf("digest: %v", err)
		}
		return Contract{
			SchemaVersion: SchemaVersion, ID: "acme/server.tool", Tool: "tool",
			Server:      ServerRef{Name: "acme-server"},
			Attestation: Attestation{Author: "acme", Source: SourceAuthored, Review: ReviewPending},
			Digest:      d, Effect: e,
		}
	}
	num := func(s string) *json.Number { n := json.Number(s); return &n }

	cases := []struct {
		name    string
		effect  *capability.EffectContract
		wantErr string
	}{
		{
			name:    "class typo",
			effect:  &capability.EffectContract{Class: "reversable"},
			wantErr: "valid effect classes are",
		},
		{
			name:    "compensable with no compensating action",
			effect:  &capability.EffectContract{Class: capability.EffectCompensable},
			wantErr: "compensatingAction",
		},
		{
			name:    "compensating action on a non-compensable class",
			effect:  &capability.EffectContract{Class: capability.EffectIrreversible, CompensatingAction: "tool:undo"},
			wantErr: "compensatingAction",
		},
		{
			name: "blast radius declaring both value and argument",
			effect: &capability.EffectContract{
				Class:       capability.EffectIrreversible,
				BlastRadius: &capability.BlastRadiusSpec{Value: num("100"), Argument: "amount"},
			},
			wantErr: "both 'value' and 'argument'",
		},
		{
			name: "blast radius declaring neither",
			effect: &capability.EffectContract{
				Class:       capability.EffectIrreversible,
				BlastRadius: &capability.BlastRadiusSpec{Unit: "usd"},
			},
			wantErr: "quantifies nothing",
		},
		{
			name: "negative blast radius",
			effect: &capability.EffectContract{
				Class:       capability.EffectIrreversible,
				BlastRadius: &capability.BlastRadiusSpec{Value: num("-1")},
			},
			wantErr: "must not be negative",
		},
		{
			name: "byArgument table that decides nothing",
			effect: &capability.EffectContract{
				Class:      capability.EffectIrreversible,
				ByArgument: &capability.EffectByArgument{Argument: "sql"},
			},
			wantErr: "decides nothing",
		},
		{
			name: "byArgument case-variant keys",
			effect: &capability.EffectContract{
				Class: capability.EffectIrreversible,
				ByArgument: &capability.EffectByArgument{
					Argument: "sql",
					Cases: map[string]capability.EffectCase{
						"DROP": {Class: capability.EffectIrreversible},
						"drop": {Class: capability.EffectReversible},
					},
				},
			},
			wantErr: "match the same argument value",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entry := entryFor(t, tc.effect)
			err := entry.Validate()
			if err == nil {
				t.Fatal("a semantically invalid contract must be rejected by the corpus loader, not merely digested")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want it to mention %q", err, tc.wantErr)
			}
			if !strings.Contains(err.Error(), entry.ID) {
				t.Errorf("error must name the offending contract id, got: %v", err)
			}
		})
	}
}

// The well-formed shapes must still validate, including the ones the new rules touch.
func TestValidateAcceptsWellFormedContracts(t *testing.T) {
	num := func(s string) *json.Number { n := json.Number(s); return &n }
	effects := map[string]*capability.EffectContract{
		"compensable with action": {
			Class:              capability.EffectCompensable,
			CompensatingAction: "tool:reverse_refund",
		},
		"argument-keyed blast radius": {
			Class:       capability.EffectIrreversible,
			BlastRadius: &capability.BlastRadiusSpec{Argument: "amount", Unit: "usd"},
		},
		"fixed blast radius": {
			Class:       capability.EffectIrreversible,
			BlastRadius: &capability.BlastRadiusSpec{Value: num("500"), Unit: "rows"},
		},
		"byArgument table": {
			Class: capability.EffectReversible,
			ByArgument: &capability.EffectByArgument{
				Argument: "sql",
				Cases:    map[string]capability.EffectCase{"DROP": {Class: capability.EffectIrreversible}},
				Default:  &capability.EffectCase{Class: capability.EffectReversible},
			},
		},
	}
	for name, e := range effects {
		t.Run(name, func(t *testing.T) {
			d, err := capability.EffectContractDigest(e)
			if err != nil {
				t.Fatalf("digest: %v", err)
			}
			entry := Contract{
				SchemaVersion: SchemaVersion, ID: "acme/server.tool", Tool: "tool",
				Server:      ServerRef{Name: "acme-server"},
				Attestation: Attestation{Author: "acme", Source: SourceAuthored, Review: ReviewPending},
				Digest:      d, Effect: e,
			}
			if err := entry.Validate(); err != nil {
				t.Errorf("a well-formed contract must validate: %v", err)
			}
		})
	}
}
