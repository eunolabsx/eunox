// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"encoding/json"
	"fmt"
	"strings"
)

// The attribution interface — the specified escape hatch for the conservative flow join.
//
// eunox cannot see how a host assembles a model's context, so its default propagation is a
// conservative SESSION-level set union: everything that flowed into the session is treated
// as having flowed into every later call. That over-approximates, and for a long-running
// agent it over-blocks. The honest answer is not to guess better — that would be inference
// — but to let a client that DOES know say so, through a specified interface. The weakness
// becomes spec surface rather than a classifier.
//
// The interface is deliberately ONE-DIRECTIONAL: a client may declare labels the proxy did
// not know about, and those are UNIONED into the effective set for that call. It may not
// declare that a call carries FEWER labels than the session join believes.
//
// That asymmetry is not a simplification, it is the security property. The premise of the
// whole flow layer is that the agent may be prompt-injected; an agent that could narrow its
// own taint would defeat information-flow control with a single extra field, and it would
// be the FIRST thing an injection reached for. Union-only means an untrusted client's
// declaration can only produce MORE denials, so honoring it needs no trust decision at all.
//
// The sound narrowing direction exists, but it is a different mechanism: a DELEGATOR
// narrowing a DELEGATE's authority is attenuation, where the party doing the narrowing is
// the one giving something up. That belongs to the delegation surface, not here. A client
// narrowing its own taint is not attenuation; it is self-attestation by the party under
// suspicion.

// MetaKeyContextManifest is the reverse-DNS `_meta` key a cooperating client uses to
// attribute a call's inputs. Namespaced so a non-supporting client, host, or upstream
// simply never sets it and nothing changes — the interface costs nothing to ignore.
const MetaKeyContextManifest = "io.eunolabs.context-manifest"

// ContextManifest is a client's per-call attribution: the native flow labels it asserts
// this call's inputs carry, over and above what the proxy's own session state records.
//
// It is an assertion, exactly as a manifest's labelOutput directive is — never an
// inference from content. The difference is who asserts it and how far it is trusted: a
// labelOutput comes from the operator's policy and is authoritative in both directions,
// while this comes from the client and is honored only where it tightens.
type ContextManifest struct {
	// Labels are native flow labels this call's inputs carry. They are unioned into the
	// session's accumulated set for THIS call's sink check only — they are not written
	// into session state, because per-call attribution is a statement about one call, and
	// persisting it would let a client permanently taint a session it merely passed
	// through.
	Labels []string `json:"labels,omitempty"`
}

// ParseContextManifest extracts the attribution block from a request's `_meta`, or
// (nil, nil) when the client supplied none.
//
// It fails closed on a MALFORMED block rather than ignoring it: a client that tried to
// attribute a call and got the shape wrong must find out, and silently discarding the
// block would leave it believing a tightening was in force when it was not. An unknown
// label is likewise an error, not a dropped entry — the flow vocabulary is closed, and a
// typo'd label that silently vanished would be the same failure in a different costume.
func ParseContextManifest(meta map[string]json.RawMessage) (*ContextManifest, error) {
	raw, ok := meta[MetaKeyContextManifest]
	if !ok || len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var cm ContextManifest
	if err := rejectUnknownJSONFields(raw, &cm, "_meta "+MetaKeyContextManifest); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &cm); err != nil {
		return nil, fmt.Errorf("_meta %s: %w", MetaKeyContextManifest, err)
	}
	for _, l := range cm.Labels {
		if !IsFlowLabel(l) {
			return nil, fmt.Errorf("_meta %s: unknown flow label %q; valid native labels are %s",
				MetaKeyContextManifest, l, strings.Join(FlowLabelVocabulary(), ", "))
		}
	}
	if len(cm.Labels) == 0 {
		// A block that declares nothing tightens nothing. Returning nil rather than an
		// empty manifest keeps "the client attributed this call" a single, unambiguous
		// test downstream.
		return nil, nil
	}
	return &cm, nil
}

// NormalizeDeclaredLabels returns labels in the fixed vocabulary order with duplicates
// collapsed, so the effective set and the audit field are deterministic regardless of how
// the client ordered them. Unknown labels are dropped — ParseContextManifest already
// rejects them at the boundary, so this only guards a programmatic caller, and dropping
// an unknown label is the fail-safe direction here (it cannot manufacture a tightening
// the vocabulary does not model).
func NormalizeDeclaredLabels(labels []string) []string {
	if len(labels) == 0 {
		return nil
	}
	in := make(map[string]bool, len(labels))
	for _, l := range labels {
		in[l] = true
	}
	var out []string
	for _, l := range flowLabelVocabulary {
		if in[l] {
			out = append(out, l)
		}
	}
	return out
}
