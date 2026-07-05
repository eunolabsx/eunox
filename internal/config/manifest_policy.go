// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
)

// anyCondition reports whether any condition on any capability entry satisfies
// pred. Predicates accept both forms a condition can take: the JSON loader builds
// pointer conditions, the JWT path value-typed ones.
func (m *LocalManifest) anyCondition(pred func(capability.Condition) bool) bool {
	if m == nil {
		return false
	}
	for i := range m.Capabilities {
		for _, cond := range m.Capabilities[i].Conditions {
			if pred(cond) {
				return true
			}
		}
	}
	return false
}

// HasMaxCalls reports whether any capability entry carries a maxCalls condition.
// The in-memory call counter is per-process, so the multi-instance state advisory
// uses this to warn only when sharing that state would matter.
func (m *LocalManifest) HasMaxCalls() bool {
	return m.anyCondition(func(cond capability.Condition) bool {
		switch cond.(type) {
		case capability.MaxCallsCondition, *capability.MaxCallsCondition:
			return true
		}
		return false
	})
}

// HasSequenceBlock reports whether any capability entry carries a sequenceBlock
// condition. The engine records a per-call antecedent marker only so a later
// sequenceBlock can read it; when no entry uses sequenceBlock the marker is never
// read, so recording (and its fail-closed deny on a counter-write fault) can be
// skipped entirely.
func (m *LocalManifest) HasSequenceBlock() bool {
	return m.anyCondition(func(cond capability.Condition) bool {
		switch cond.(type) {
		case capability.SequenceBlockCondition, *capability.SequenceBlockCondition:
			return true
		}
		return false
	})
}

// HasSamplingGrant reports whether the manifest grants server-initiated sampling:
// a system: target whose bare name matches sampling/createMessage (by the same
// enforcement.MatchesResource glob the engine uses, so "system:*" and
// "system:sampling/*" count) AND whose actions permit it ("allow" or "*").
//
// This is single-sourced beside the other manifest-policy predicates so the startup
// HTTP-upstream sampling guard and ManifestPDP.DecideSampling cannot drift: it
// applies the SAME grant rule DecideSampling enforces at runtime (a matching system:
// constraint whose actions contain "allow"). It is action-aware — a prior transport-
// layer copy checked only the target's presence and ignored the entry's actions, so a
// future system-namespace action or relaxed validation could have desynchronized the
// startup guard from enforcement. It deliberately ignores principal scoping and
// conditions: it answers "could this manifest grant sampling at all" — the
// conservative (fail-closed for its single consumer) question the startup guard
// needs, not a per-request decision.
func (m *LocalManifest) HasSamplingGrant() bool {
	if m == nil {
		return false
	}
	for i := range m.Capabilities {
		tt, bare, err := capability.ParseTarget(m.Capabilities[i].Target)
		if err != nil || tt != capability.TargetTypeSystem {
			continue
		}
		if !enforcement.MatchesResource(bare, capability.MethodSamplingCreateMessage) {
			continue
		}
		for _, a := range m.Capabilities[i].Actions {
			if a == "allow" || a == "*" {
				return true
			}
		}
	}
	return false
}

// AuditOnlyCount returns how many of the manifest's capability entries are in
// audit (observe) mode.
func (m *LocalManifest) AuditOnlyCount() int {
	if m == nil {
		return 0
	}
	n := 0
	for i := range m.Capabilities {
		if m.Capabilities[i].IsAuditOnly() {
			n++
		}
	}
	return n
}

// Digest returns a hex SHA-256 over the canonical JSON encoding of the manifest.
// json.Marshal is deterministic for these types, so the digest is stable for a
// given effective policy. Computed once at load, off the request hot path.
func (m *LocalManifest) Digest() (string, error) {
	b, err := json.Marshal(m)
	if err != nil {
		// Fail closed rather than stamp an empty policy_sha256 into every audit
		// record. This runs at load before any traffic, so a marshal failure is
		// almost certainly a programming error; abort loudly instead of corrupting
		// the audit trail.
		return "", fmt.Errorf("Digest: marshal failed: %w", err)
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
