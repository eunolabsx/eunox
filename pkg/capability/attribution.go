// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"encoding/json"
	"fmt"
)

// The attribution interface lets a cooperating client narrow eunox's conservative
// session-level flow join by declaring labels it knows a call's inputs carry.
//
// It is deliberately ONE-DIRECTIONAL (union-only): a client may only ADD labels the proxy
// did not know about, never remove ones the session join believes apply. That asymmetry is
// the security property, not a simplification — an agent that could narrow its own taint
// would defeat flow control with one field, the first thing a prompt injection would reach
// for. The sound narrowing direction (a delegator narrowing a delegate) is attenuation, a
// different mechanism that belongs to the delegation surface, not here.

// MetaKeyContextManifest is the reverse-DNS `_meta` key a cooperating client uses to
// attribute a call's inputs. Namespaced so a non-supporting client, host, or upstream
// simply never sets it and nothing changes — the interface costs nothing to ignore.
const MetaKeyContextManifest = "io.eunolabs.context-manifest"

// ContextManifest is a client's per-call attribution: the flow labels, on either axis, it
// asserts this call's inputs carry, over and above what the proxy's own session state
// records.
//
// It is an assertion, exactly as a manifest's labelOutput directive is — never an
// inference from content. The difference is who asserts it and how far it is trusted: a
// labelOutput comes from the operator's policy and is authoritative in both directions,
// while this comes from the client and is honored only where it tightens.
type ContextManifest struct {
	// Labels are flow labels this call's inputs carry. They are unioned into the
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
// block would leave it believing a tightening was in force when it was not. A label
// belonging to neither axis is likewise an error, not a dropped entry: a typo'd label that
// silently vanished would be the same failure in a different costume.
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
	// Both axes: a cooperating client may attribute an imported sensitivity class its own
	// inputs carried. Structural validation only — this boundary holds no manifest, and a
	// declaration union-only ADDS taint, so an undeclared namespace here can produce extra
	// denials and never an allowance. COUNT-bounded because this is the one label list an
	// untrusted peer writes directly, and the decision path sorts and walks it once per
	// enforced call; see MaxExternalFlowLabels for the measured cost of leaving it open.
	if err := checkExternalFlowLabels(cm.Labels, "_meta "+MetaKeyContextManifest); err != nil {
		return nil, err
	}
	if len(cm.Labels) == 0 {
		// A block that declares nothing tightens nothing. Returning nil rather than an
		// empty manifest keeps "the client attributed this call" a single, unambiguous
		// test downstream.
		return nil, nil
	}
	return &cm, nil
}

// NormalizeDeclaredLabels returns a client's declared labels in canonical order with
// duplicates collapsed, so the effective set and the audit field are deterministic
// regardless of how the client ordered them.
//
// A thin alias for NormalizeFlowLabels, kept as a name at the attribution boundary because
// that is where the drop-malformed policy is justified: ParseContextManifest already
// rejects an unknown label, so this only guards a programmatic caller.
func NormalizeDeclaredLabels(labels []string) []string {
	return NormalizeFlowLabels(labels)
}
