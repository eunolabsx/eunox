// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// A claim object decoded from a token an IdP minted is ambiguous in a way a plain struct
// unmarshal resolves silently: encoding/json folds member names case-insensitively and keeps
// the last one, so which member takes effect depends on source order rather than on anything
// the author can see — the same ambiguity FoldJSONKey closes for the JSON-RPC envelope and the
// tools/list scans. ClaimMembers REJECTS THE TOKEN for that rather than letting the decode pick.
//
// A JWT is signed by its issuer, so this is the issuer's own minting-pipeline mistake to make
// rather than a third party's forgery — but a claim resolved by member order is one nobody can
// review, which is why it is refused rather than reported.

// claimMember is one key/value pair of a claim object, in source order and WITHOUT the
// duplicate collapsing an unmarshal into a map performs.
type claimMember struct {
	key   string
	value json.RawMessage
}

// claimObjectMembers returns data's top-level members in source order, keeping duplicates.
// Nested values are consumed whole and not descended into: a nested object is its own claim
// object and is scanned at its own depth.
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
// The check asks "is there only one candidate for this claim at all". A JWT payload's `mcp`
// claim and the `mcp` block's own `capabilities` member are decoded by go-jose's/encoding/json's
// plain struct unmarshal — the case-insensitive-fold-and-keep-the-last-one rule — so an
// ambiguity is resolved silently before anything downstream can see it:
// `{"mcp":{"capabilities":[narrow],"Capabilities":[wide]}}` hands the decoder only the WIDE
// array, with nothing left to indicate a narrower candidate ever existed. A JWT is signed by its
// issuer, so this is not an externally forgeable ambiguity — but a minting pipeline that merges
// claim sources (or a migration that renamed a claim and left both spellings live) produces it
// easily, and the result is an authorization nobody can review.
//
// It does NOT reject an unrecognized member: data may be a claim
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
