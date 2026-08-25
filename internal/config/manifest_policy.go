// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
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

// anyTokenState reports whether any condition or directive on any capability entry has a
// cross-call state class satisfying pred, read from the class each token DECLARES on its
// pkg/capability prototype-registry entry rather than a hand-maintained list here — which
// keeps a newly added accumulating token from silently reporting neither. An UNCLASSIFIED
// token is treated as the strongest class, so it satisfies every predicate until it ships.
func (m *LocalManifest) anyTokenState(pred func(capability.StateAccumulation) bool) bool {
	if m == nil {
		return false
	}
	classify := func(s capability.StateAccumulation, ok bool) capability.StateAccumulation {
		if !ok {
			return capability.StateNonAtomic
		}
		return s
	}
	for i := range m.Capabilities {
		for _, cond := range m.Capabilities[i].Conditions {
			if pred(classify(capability.ConditionStateAccumulation(cond))) {
				return true
			}
		}
		for _, dir := range m.Capabilities[i].Directives {
			if pred(classify(capability.DirectiveStateAccumulation(dir))) {
				return true
			}
		}
	}
	return false
}

// AccumulatesSharedState reports whether this policy depends on state that outlives a single
// call (a maxCalls/blastRadius budget, sequenceBlock history, the flow-label set). All of it
// is PER-PROCESS under the default in-memory backends, so the multi-instance advisory warns on
// it: three replicas without shared Redis enforce a maxCalls of 20 as 60.
func (m *LocalManifest) AccumulatesSharedState() bool {
	return m.anyTokenState(capability.StateAccumulation.AccumulatesSharedState)
}

// PolicyTokens returns the set of condition and directive discriminators this policy carries,
// sorted and deduplicated, fed to enforcement.WithPolicyTokens to decide which optional engine
// subsystems to wire. It reports a FACT rather than a conclusion, so the engine's own handler
// registry — which a caller can replace via enforcement.WithConditionHandler — decides subsystem
// use rather than this layer guessing it from the token's declared default handler.
func (m *LocalManifest) PolicyTokens() []string {
	seen := map[string]struct{}{}
	// The discriminator methods have value receivers, so a typed-nil entry would panic on the
	// call; MergeManifests takes programmatically built constraints, so a manifest is not the
	// only source of these values. Same guard capability's own classification path applies.
	m.anyCondition(func(cond capability.Condition) bool {
		if cond != nil && !capability.IsTypedNil(cond) {
			seen[cond.ConditionType()] = struct{}{}
		}
		return false // collect every entry, never short-circuit
	})
	m.anyDirective(func(dir capability.Directive) bool {
		if dir != nil && !capability.IsTypedNil(dir) {
			seen[dir.DirectiveType()] = struct{}{}
		}
		return false
	})
	tokens := make([]string, 0, len(seen))
	for t := range seen {
		tokens = append(tokens, t)
	}
	slices.Sort(tokens)
	return tokens
}

// NeedsDecisionTurn reports whether this policy's decisions must be SERIALIZED on the state
// anchor: whether any token does a NON-ATOMIC read-then-write against accumulated state (a
// flowLabel sink peeking what a labelOutput source Adds, a sequenceBlock reading an antecedent
// an earlier call recorded) with a window a pipelined host could race through. maxCalls and a
// cumulative blastRadius need no turn — AdmitAll admits a whole batch atomically. The
// classification is DECLARED BY THE TOKEN, not a hand-maintained list, so a new accumulating
// token defaults to needing the turn rather than silently running unserialized.
func (m *LocalManifest) NeedsDecisionTurn() bool {
	return m.anyTokenState(capability.StateAccumulation.NeedsSerializedDecisions)
}

// HonorsAttributionInterface reports whether this policy admits the client-supplied
// attribution interface (the `io.eunolabs.context-manifest` block in a request's `_meta`). It
// is the grammar gate for a wire-side token that never appears in the manifest — it arrives on
// a REQUEST, so there is nothing to reject at load, making this a runtime predicate rather than
// a load-time check like checkTokenGrammarVersion. Under "0.1" the block is IGNORED rather than
// rejected: the interface is union-only, so ignoring it falls back to the stricter conservative
// join instead of breaking a "0.1" operator's calls on a `_meta` key outside their grammar.
// A nil manifest reports false. Uses revisionAdmits, not an equality check against the
// introducing revision, so a later revision still contains the interface.
func (m *LocalManifest) HonorsAttributionInterface() bool {
	return m != nil && revisionAdmits(strings.TrimSpace(m.SchemaVersion), ManifestSchemaVersion02)
}

// HasSamplingGrant reports whether the manifest grants server-initiated sampling: a system:
// target matching sampling/createMessage (via the same enforcement.MatchesResource matcher the
// engine uses, for consistency, though system: targets reject glob metacharacters at load so in
// practice only the exact target is loadable) whose actions permit it ("allow" or "*"). Applies
// the SAME grant rule ManifestPDP.DecideSampling enforces at runtime, so the startup
// HTTP-upstream sampling guard cannot drift from it. Ignores principal scoping and conditions
// deliberately — it answers "could this manifest grant sampling at all", not a per-request one.
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
