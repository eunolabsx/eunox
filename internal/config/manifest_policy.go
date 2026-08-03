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

// anyTokenState reports whether any condition or directive on any capability entry has a
// cross-call state class satisfying pred. It is the one walk both derived policy properties
// (NeedsDecisionTurn, AccumulatesSharedState) read, over the class each token DECLARES on its
// pkg/capability prototype-registry entry rather than over a list of token types spelled out
// here — which is what keeps a newly added accumulating token from silently reporting neither.
//
// An UNCLASSIFIED token (one whose registry entry declares no class, or a discriminator this
// build does not model) is treated as the strongest class, so it satisfies every predicate:
// the build-time completeness test is what stops it from ever shipping, and the runtime answer
// while it exists is "serialize, and warn" rather than "neither".
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
// call — a maxCalls or cumulative blastRadius budget, the sequenceBlock antecedent history, the
// flow-label set. All of it is PER-PROCESS under the default in-memory backends, so the
// multi-instance advisory warns on it: three replicas without a shared Redis enforce a
// maxCalls of 20 as 60, and a source recorded on one instance is invisible to a sink on
// another.
//
// It replaced four hand-written per-token predicates ORed together at each of its two call
// sites (the stdio host's and the gateway's). Those were four places to forget for one
// question, and forgetting was silent in the direction that matters: the operator who most
// needs the advisory is the one running a policy the list has not caught up with.
func (m *LocalManifest) AccumulatesSharedState() bool {
	return m.anyTokenState(capability.StateAccumulation.AccumulatesSharedState)
}

// UsesEngineSubsystem reports whether any of this policy's tokens depends on the named
// OPTIONAL engine subsystem — the antecedent history a sequenceBlock reads, or the flow-label
// set a sink peeks and a source writes. The route builder asks it once per subsystem and skips
// the ones no token needs (WithoutAntecedentRecording, WithoutFlowLabels).
//
// It is a narrower question than "does this policy accumulate state", and deliberately so: a
// sequenceBlock-only policy accumulates plenty and still wants the flow path skipped. The two
// were previously separate hand-written predicates — one naming sequenceBlock, one naming the
// three flow token types — and the flow one failed in the direction that matters. Add a
// condition that READS the flow-label set and a policy carrying only it reports "no flow
// token": the engine is built WithoutFlowLabels and the new handler runs against an engine
// holding no flow state, most plausibly reading an empty set and allowing what the labels
// existed to block. Both gates now derive from the subsystem each token DECLARES on its
// pkg/capability prototype-registry entry, so a token added there is covered by construction.
//
// An UNCLASSIFIED token (one declaring no subsystem, or naming one this build does not model)
// depends on all of them, so it disables both skips. That is the cheap direction — the skips
// are optimizations, and the build-time completeness test is what stops such a token shipping.
//
// A nil manifest (a route with no policy) carries no token and needs no subsystem.
func (m *LocalManifest) UsesEngineSubsystem(s capability.EngineSubsystem) bool {
	return m.anyCondition(func(cond capability.Condition) bool {
		return capability.ConditionUsesEngineSubsystem(cond, s)
	}) || m.anyDirective(func(dir capability.Directive) bool {
		return capability.DirectiveUsesEngineSubsystem(dir, s)
	})
}

// NeedsDecisionTurn reports whether this policy's decisions must be SERIALIZED on the state
// anchor: whether any of its tokens does a NON-ATOMIC read-then-write against accumulated
// state — one call committing what a later one reads back, with a window in between. Both
// transports gate their decision turn on it.
//
// Non-atomic is the whole of the predicate, and stating it loosely is how the wrong tokens get
// counted: maxCalls and a cumulative blastRadius also accumulate state that a later call reads
// back, and deliberately need NO turn, because AdmitAll admits or refuses a whole batch of
// buckets indivisibly. A flowLabel sink peeking a set a labelOutput source Adds to, and a
// sequenceBlock reading an antecedent marker an earlier call recorded, have no such atomicity:
// a host that pipelines the source and the sink lets the sink's read run before the source's
// write commits, which is the fail-open the turn exists to close. Everything else keeps full
// decision parallelism.
//
// The classification is DECLARED BY THE TOKEN — on its pkg/capability prototype-registry entry,
// beside the grammar revision — and this derives from it rather than naming the tokens that
// happen to accumulate today. The predicate was previously spelled out twice (once per
// transport) and then once as a literal disjunction of two per-token predicates; both shapes
// have the same failure, and it is silent: a new accumulating condition simply is not in the
// list, both transports run its decisions unserialized, and every completeness test still
// passes. A token that declares nothing now fails the build instead
// (TestTokenStateAccumulation_EveryRegisteredTokenDeclaresAClass), and is treated as needing
// the turn until it does.
//
// A nil manifest (a route with no policy) accumulates nothing and needs no turn.
func (m *LocalManifest) NeedsDecisionTurn() bool {
	return m.anyTokenState(capability.StateAccumulation.NeedsSerializedDecisions)
}

// HasDeclassify reports whether this policy carries a declassify directive — the one
// token whose satisfaction depends on a channel (a validated JWT) that not every host
// transport has. The startup check consults it to refuse a manifest whose declassification
// could never be approved; it is single-sourced here beside the other policy predicates so
// that check and the engine's own gate cannot drift on what counts as declassifying.
func (m *LocalManifest) HasDeclassify() bool {
	return m != nil && m.anyDirective(capability.IsDeclassifyDirective)
}

// HonorsAttributionInterface reports whether this policy admits the client-supplied
// attribution interface (the `io.eunolabs.context-manifest` block in a request's `_meta`).
//
// It is the grammar gate for a wire-side token, and it exists for the same reason
// checkTokenGrammarVersion gates the manifest-side ones: a token introduced by a later
// grammar revision must not change behavior for an operator running an earlier one. This
// one cannot ride checkTokenGrammarVersion itself because the token never appears in the
// manifest — it arrives on a REQUEST, so there is nothing to reject at load, and the gate
// has to be a runtime predicate the transport consults.
//
// Under "0.1" the block is IGNORED rather than rejected, which is the conservative
// direction: the interface is union-only (a declaration may only tighten a call's labels,
// never widen them), so ignoring it falls back to the conservative session join — the
// stricter reading. Rejecting instead would make a `0.1` operator's calls start failing on
// a `_meta` key that is not part of their grammar, which is a behavior change in the
// opposite, breaking direction.
//
// A nil manifest (a route with no policy) has no schema version and therefore no opt-in,
// so it reports false.
//
// It asks revisionAdmits rather than comparing to the introducing revision, which is the same
// rule the manifest-side gates apply: a revision published after the one that introduced the
// interface still contains it. An equality check would silently turn the interface OFF for a
// policy on a later revision — and "off" here means the client's declaration is ignored, which
// is quiet rather than loud.
func (m *LocalManifest) HonorsAttributionInterface() bool {
	return m != nil && revisionAdmits(strings.TrimSpace(m.SchemaVersion), ManifestSchemaVersion02)
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
