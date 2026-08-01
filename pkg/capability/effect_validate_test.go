// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The effect-contract rules live here, in the package that owns the reversibility
// vocabulary and the contract digest, so the manifest loader and the registry corpus
// loader apply exactly the same ones. These are the rules themselves; the two callers'
// tests cover their own framing.
func TestValidateEffectContract(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		effect  *EffectContract
		wantErr string // "" means it must validate
	}{
		{name: "nil contract is valid", effect: nil},
		{name: "class only", effect: &EffectContract{Class: EffectReversible}},
		{name: "unset class", effect: &EffectContract{}},
		{
			name:    "class outside the vocabulary",
			effect:  &EffectContract{Class: "reversable"},
			wantErr: "valid effect classes are",
		},
		{
			name:    "compensable with no action",
			effect:  &EffectContract{Class: EffectCompensable},
			wantErr: "no 'compensatingAction'",
		},
		{
			name:   "compensable with an action",
			effect: &EffectContract{Class: EffectCompensable, CompensatingAction: "tool:reverse"},
		},
		{
			name:    "action on a non-compensable class",
			effect:  &EffectContract{Class: EffectIrreversible, CompensatingAction: "tool:reverse"},
			wantErr: "declares 'compensatingAction'",
		},
		{
			name:    "action with an unset class names the default",
			effect:  &EffectContract{CompensatingAction: "tool:reverse"},
			wantErr: "unset, which resolves to irreversible",
		},
		{
			name:    "blast radius with both value and argument",
			effect:  &EffectContract{BlastRadius: &BlastRadiusSpec{Value: num("1"), Argument: "amount"}},
			wantErr: "both 'value' and 'argument'",
		},
		{
			name:    "blast radius with neither",
			effect:  &EffectContract{BlastRadius: &BlastRadiusSpec{Unit: "usd"}},
			wantErr: "quantifies nothing",
		},
		{
			name:    "blast radius value is not a number",
			effect:  &EffectContract{BlastRadius: &BlastRadiusSpec{Value: num("lots")}},
			wantErr: "is not a number",
		},
		{
			name:    "negative blast radius",
			effect:  &EffectContract{BlastRadius: &BlastRadiusSpec{Value: num("-1")}},
			wantErr: "must not be negative",
		},
		{
			name:   "argument-keyed blast radius",
			effect: &EffectContract{BlastRadius: &BlastRadiusSpec{Argument: "amount", Unit: "usd"}},
		},
		{
			name:    "byArgument with no argument",
			effect:  &EffectContract{ByArgument: &EffectByArgument{Cases: map[string]EffectCase{"DROP": {}}}},
			wantErr: "requires 'argument'",
		},
		{
			name:    "byArgument with neither cases nor default",
			effect:  &EffectContract{ByArgument: &EffectByArgument{Argument: "sql"}},
			wantErr: "decides nothing",
		},
		{
			name: "byArgument case-variant keys",
			effect: &EffectContract{ByArgument: &EffectByArgument{
				Argument: "sql",
				Cases:    map[string]EffectCase{"DROP": {Class: EffectIrreversible}, " drop ": {Class: EffectReversible}},
			}},
			wantErr: "match the same argument value",
		},
		{
			name: "byArgument case with an invalid class",
			effect: &EffectContract{ByArgument: &EffectByArgument{
				Argument: "sql",
				Cases:    map[string]EffectCase{"DROP": {Class: "gone"}},
			}},
			wantErr: "valid effect classes are",
		},
		{
			name: "byArgument case raising itself to compensable with no action",
			effect: &EffectContract{ByArgument: &EffectByArgument{
				Argument: "sql",
				Cases:    map[string]EffectCase{"DELETE": {Class: EffectCompensable}},
			}},
			wantErr: "no 'compensatingAction'",
		},
		{
			// The inherited-class rule: the row states no class, so it inherits
			// irreversible, and its compensating action would be silently scrubbed.
			name: "byArgument case action under an inherited non-compensable class",
			effect: &EffectContract{
				Class: EffectIrreversible,
				ByArgument: &EffectByArgument{
					Argument: "sql",
					Cases:    map[string]EffectCase{"DROP": {CompensatingAction: "tool:restore"}},
				},
			},
			wantErr: "declares 'compensatingAction'",
		},
		{
			// A row inheriting a compensable base inherits its action too, so it is not
			// missing one.
			name: "byArgument case inheriting a compensable base",
			effect: &EffectContract{
				Class:              EffectCompensable,
				CompensatingAction: "tool:reverse",
				ByArgument: &EffectByArgument{
					Argument: "mode",
					Cases:    map[string]EffectCase{"partial": {BlastRadius: &BlastRadiusSpec{Value: num("10")}}},
				},
			},
		},
		{
			name: "byArgument default row is validated too",
			effect: &EffectContract{ByArgument: &EffectByArgument{
				Argument: "sql",
				Default:  &EffectCase{Class: EffectCompensable},
			}},
			wantErr: "no 'compensatingAction'",
		},
		{
			name:    "ref that is not a pin",
			effect:  &EffectContract{Class: EffectReversible, Ref: "just-an-id"},
			wantErr: `must be "<contract-id>@sha256:<hex>"`,
		},
		{
			name:    "ref digest is not sha256-hex",
			effect:  &EffectContract{Class: EffectReversible, Ref: "acme/x.tool@sha256:nothex"},
			wantErr: "hex part must be exactly 64 characters",
		},
		{
			name:    "ref digest does not match the contract",
			effect:  &EffectContract{Class: EffectReversible, Ref: "acme/x.tool@sha256:" + strings.Repeat("ab", 32)},
			wantErr: "the block was edited after it was pinned",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateEffectContract(tc.effect)
			if tc.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// A pin whose digest matches its own contract validates — the property that makes `ref`
// an integrity pin rather than a comment.
func TestValidateEffectContract_MatchingPinValidates(t *testing.T) {
	t.Parallel()
	e := &EffectContract{Class: EffectCompensable, CompensatingAction: "tool:reverse"}
	digest, err := EffectContractDigest(e)
	require.NoError(t, err)
	e.Ref = "acme/payments.refund@" + digest
	assert.NoError(t, ValidateEffectContract(e))
}

func TestValidateEffectCeiling(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		ceiling *EffectCeiling
		wantErr string
	}{
		{name: "nil ceiling is valid", ceiling: nil},
		{name: "class bound", ceiling: &EffectCeiling{MaxEffectClass: EffectCompensable}},
		{name: "magnitude bound", ceiling: &EffectCeiling{MaxBlastRadius: num("1000")}},
		{
			name:    "class outside the vocabulary",
			ceiling: &EffectCeiling{MaxEffectClass: "mostly-fine"},
			wantErr: "valid effect classes are",
		},
		{
			name:    "magnitude is not a number",
			ceiling: &EffectCeiling{MaxBlastRadius: num("big")},
			wantErr: "is not a number",
		},
		{
			name:    "negative magnitude",
			ceiling: &EffectCeiling{MaxBlastRadius: num("-1")},
			wantErr: "must not be negative",
		},
		{
			name:    "unknown onExceed",
			ceiling: &EffectCeiling{MaxEffectClass: EffectReversible, OnExceed: "shrug"},
			wantErr: "valid outcomes are",
		},
		{
			name:    "requireCompensation with no class bound never fires",
			ceiling: &EffectCeiling{MaxBlastRadius: num("10"), RequireCompensation: true},
			wantErr: "needs 'maxEffectClass'",
		},
		{
			name:    "a ceiling that bounds nothing",
			ceiling: &EffectCeiling{OnExceed: OnExceedDeny},
			wantErr: "bounds nothing",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateEffectCeiling(tc.ceiling)
			if tc.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}
