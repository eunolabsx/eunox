// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
)

// validateQuotaBucketsDistinct dispatches on a condition's concrete TYPE, so it dereferences
// what the per-condition loop's nil and typed-nil guards exist to refuse. Running it ABOVE
// them meant a typed-nil condition — a non-nil interface, so it matches the pointer arm —
// panicked the loader where every other malformed condition fails it closed.
//
// Reached through MergeManifests, which re-validates the merged union and whose input is a
// programmatically built []*LocalManifest (manifest_policy.go documents that as a real
// source); the YAML path cannot spell a typed nil at all.
func TestValidateQuotaBuckets_TypedNilConditionFailsClosedRatherThanPanicking(t *testing.T) {
	for name, cond := range map[string]capability.Condition{
		// The arm that panicked: MaxCallsCondition's field read has nothing nil-safe about it.
		"maxCalls": (*capability.MaxCallsCondition)(nil),
		// Survived only because HasVelocity happens to be nil-safe — a property of that one
		// method, not of the ordering, so it is pinned here beside the arm that did not.
		"blastRadius": (*capability.BlastRadiusCondition)(nil),
		// A plain nil never matched a pointer arm; it is here so the loop's own guard stays
		// the thing that reports both shapes.
		"plain nil": nil,
	} {
		t.Run(name, func(t *testing.T) {
			base := &LocalManifest{
				Name:          "a",
				Version:       "1.0.0",
				SchemaVersion: "0.1",
				Capabilities:  []capability.Constraint{{Target: "tool:read", Actions: []string{"call"}}},
			}
			bad := &LocalManifest{
				Name:          "b",
				Version:       "1.0.0",
				SchemaVersion: "0.1",
				Capabilities: []capability.Constraint{{
					Target:     "tool:send",
					Actions:    []string{"call"},
					Conditions: []capability.Condition{cond},
				}},
			}

			_, err := MergeManifests([]*LocalManifest{base, bad})
			if err == nil {
				t.Fatal("expected the merged manifest to be refused")
			}
			if !strings.Contains(err.Error(), "condition 0") {
				t.Fatalf("the refusal must name the offending condition, got: %v", err)
			}
		})
	}
}

// The check itself still fires, so moving it below the guards did not move it out of reach.
func TestValidateQuotaBuckets_StillRejectsTwoBucketsOnOneWindow(t *testing.T) {
	m := &LocalManifest{
		Name:          "a",
		Version:       "1.0.0",
		SchemaVersion: "0.1",
		Capabilities: []capability.Constraint{{
			Target:  "tool:send",
			Actions: []string{"call"},
			Conditions: []capability.Condition{
				capability.MaxCallsCondition{Count: 5, WindowSeconds: 60},
				capability.MaxCallsCondition{Count: 3, WindowSeconds: 60},
			},
		}},
	}
	err := validateLocalManifest(m)
	if err == nil || !strings.Contains(err.Error(), "share one counter bucket") {
		t.Fatalf("expected the shared-bucket refusal, got: %v", err)
	}
}
