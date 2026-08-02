// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

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

// anyDirective is the directive-side mirror of anyCondition: it reports whether any
// directive on any capability entry satisfies pred. Predicates accept both forms a
// directive can take (pointer from the JSON loader, value from a programmatic build).
func (m *LocalManifest) anyDirective(pred func(capability.Directive) bool) bool {
	if m == nil {
		return false
	}
	for i := range m.Capabilities {
		for _, dir := range m.Capabilities[i].Directives {
			if pred(dir) {
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

// HasBlastRadiusVelocity reports whether any capability entry carries a CUMULATIVE
// blastRadius bound. Such a bound consumes a sliding-window budget exactly as maxCalls
// consumes a slot, so it is per-process state under the in-memory counter — and the
// operator advisory about running several replicas without a shared Redis has to know
// about it, or a $2,000-an-hour ceiling is silently enforced as $6,000 across three
// replicas with no notice printed. The per-call `max` bound consumes nothing and does not
// count.
func (m *LocalManifest) HasBlastRadiusVelocity() bool {
	return m.anyCondition(func(cond capability.Condition) bool {
		switch v := cond.(type) {
		case capability.BlastRadiusCondition:
			return v.HasVelocity()
		case *capability.BlastRadiusCondition:
			return v.HasVelocity()
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

// HasFlowLabel reports whether any capability entry uses information-flow control — a
// flowLabel condition (sink; reads per-session label state) or a labelOutput directive
// (source; writes it). Both rely on cross-call CallCounter state exactly like maxCalls
// and sequenceBlock, so the multi-instance shared-state advisory must warn on them too:
// without shared Redis, a source recording a label on one instance and a sink Peeking it
// on another fails open silently.
func (m *LocalManifest) HasFlowLabel() bool {
	// Single-sourced through the capability predicates (value/pointer-safe) so this
	// config-level advisory and the engine's constraintHasFlow gate cannot drift on
	// what counts as flow-relevant when the type set grows.
	return m.anyCondition(capability.IsFlowLabelCondition) ||
		m.anyDirective(capability.IsLabelOutputDirective)
}

// HonorsAttributionInterface reports whether this policy admits the client-supplied
// attribution interface (the `io.eunolabs.context-manifest` block in a request's `_meta`).
//
// It is the staging gate for a wire-side draft token, and it exists for the same reason
// checkExperimentalTokenStaging gates the manifest-side ones: a DRAFT feature must not
// change behavior for an operator running the published grammar. This one cannot ride
// checkExperimentalTokenStaging itself because the token never appears in the manifest —
// it arrives on a REQUEST, so there is nothing to reject at load, and the gate has to be
// a runtime predicate the transport consults.
//
// Under the published grammar the block is IGNORED rather than rejected, which is the
// conservative direction: the interface is union-only (a declaration may only tighten a
// call's labels, never widen them), so ignoring it falls back to the conservative session
// join — the stricter reading. Rejecting instead would make a `0.1` operator's calls start
// failing on a `_meta` key that is not part of their grammar, which is a behavior change
// in the opposite, breaking direction.
//
// A nil manifest (a route with no policy) has no schema version and therefore no draft
// opt-in, so it reports false.
func (m *LocalManifest) HonorsAttributionInterface() bool {
	return m != nil && strings.TrimSpace(m.SchemaVersion) == ManifestSchemaVersionFlowEffectDraft
}

// HasSamplingGrant reports whether the manifest grants server-initiated sampling:
// a system: target whose bare name matches sampling/createMessage (by the same
// enforcement.MatchesResource matcher the engine uses; note that system: targets
// reject glob metacharacters at load, so in practice only the exact
// "system:sampling/createMessage" is loadable — the matcher is used for
// engine-consistency, not to admit "system:*") AND whose actions permit it ("allow" or "*").
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
