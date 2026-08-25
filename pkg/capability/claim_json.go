// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Claim-borne grants are decoded from a token an IdP minted, and every one of them NARROWS
// something — so unlike a manifest,
// where a parse failure is the operator's own error, a grant that parses to something WEAKER
// than it reads is an invisible loss of a control someone believes is in force.
//
// Three JSON shapes produce exactly that and none is caught by a plain struct decode: an
// unknown member (a misspelled "targts" decodes to NO restriction), an explicit null (the
// author wrote the key, so "absent means unrestricted" isn't what they meant), and a duplicate
// key (encoding/json folds case-insensitively and keeps the last, so which member wins depends
// on order, not on anything the author can see — the same ambiguity FoldJSONKey closes for the
// JSON-RPC envelope and tools/list scans). All three REJECT THE TOKEN rather than silently
// evaporating the narrowing.

// MaxClaimListEntries bounds how many entries one grant's list-valued member may carry. A bound
// on attacker-influenced input, not hygiene: a grant is validated once but READ on every
// enforced call. Two hundred fifty-six is far above any real grant and far below anything that
// costs measurable memory.
const MaxClaimListEntries = 256

// claimMember is one key/value pair of a claim object, in source order and WITHOUT the
// duplicate collapsing an unmarshal into a map performs.
type claimMember struct {
	key   string
	value json.RawMessage
}

// claimObjectMembers returns data's top-level members in source order, keeping duplicates.
// Nested values are consumed whole and not descended into: a nested object is its own claim
// object and is scanned at its own depth (the actor chain is the only nesting in this package,
// and ParseActorChain walks it one node at a time).
func claimObjectMembers(data []byte, context string) ([]claimMember, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", context, err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("%s: expected a JSON object", context)
	}
	var out []claimMember
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", context, err)
		}
		key, ok := t.(string)
		if !ok {
			return nil, fmt.Errorf("%s: expected a member name", context)
		}
		// Decoding the value into a RawMessage consumes exactly one value, descending through
		// any nested object or array without interpreting it.
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, fmt.Errorf("%s: member %q: %w", context, key, err)
		}
		out = append(out, claimMember{key: key, value: raw})
	}
	return out, nil
}

// ClaimMembers validates that none of watch is spelled more than one way among data's
// top-level JSON members, and returns each watched name's value keyed by FoldJSONKey(name)
// — a name absent under every spelling is simply missing from the map.
//
// It is decodeClaimObject's duplicate-key check, applied one layer OUT rather than one layer
// IN: decodeClaimObject asks "does this already-selected claim object's OWN fields agree with
// what it says", this asks "is there only one candidate for a claim object at all". A JWT
// payload's `mcp` claim and the `mcp` block's own `capabilities` member are decoded by
// go-jose's/encoding/json's plain struct unmarshal — the
// same case-insensitive-fold-and-keep-the-last-one rule decodeClaimObject exists to refuse —
// but that struct decode happens BEFORE any per-grant decoder ever runs, so a grant's own
// strict decoding cannot see an ambiguity that was already silently resolved one level up:
// `{"mcp":{"capabilities":[narrow],"Capabilities":[wide]}}` hands the decoder only the WIDE
// array, with nothing left to indicate a narrower candidate ever existed. A JWT is
// signed by its issuer, so this is not an externally forgeable ambiguity — but it is the same
// "an IdP template mistake becomes a rejected token, not a silently-resolved one" failure
// decodeClaimObject documents, and a minting pipeline that merges claim sources (or a
// migration that renamed a claim and left both spellings live) can produce it exactly as
// easily one level up as one level in.
//
// Unlike decodeClaimObject this does NOT reject an unrecognized member: data may be a claim
// object other parties legitimately extend — a JWT's whole payload carries claims for
// audiences besides this proxy, and even the proxy-owned `mcp` block is versioned
// (`schemaVersion`-style) and may grow fields a running build predates. Only the small set of
// names in watch is checked; everything else is ignored, ambiguous or not — an ambiguity in a
// claim this build never reads is not this build's business to refuse a token over.
func ClaimMembers(data []byte, context string, watch ...string) (map[string]json.RawMessage, error) {
	members, err := claimObjectMembers(data, context)
	if err != nil {
		return nil, err
	}
	want := make(map[string]bool, len(watch))
	for _, w := range watch {
		want[FoldJSONKey(w)] = true
	}
	out := make(map[string]json.RawMessage, len(want))
	seen := make(map[string]string, len(want))
	for _, m := range members {
		folded := FoldJSONKey(m.key)
		if !want[folded] {
			continue
		}
		if prior, dup := seen[folded]; dup {
			return nil, fmt.Errorf("%s: members %q and %q are the same claim to a JSON decoder, so which one is enforced depends on their order; declare it once", context, prior, m.key)
		}
		seen[folded] = m.key
		out[folded] = m.value
	}
	return out, nil
}
