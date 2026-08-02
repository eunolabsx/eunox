// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// The claim-borne grants in this package (delegation grants, declassify approvals, actor-chain
// nodes) are decoded from a token an IdP minted, and every one of them NARROWS something. That
// makes their decoding asymmetric with the manifest's: a manifest that fails to parse is an
// operator's file and an operator's error, while a grant that parses to something WEAKER than
// it reads is an invisible loss of a control someone believes is in force.
//
// Three JSON shapes produce exactly that, and none of them is caught by decoding into a struct:
//
//   - An unknown member. `{"targts":["tool:read"]}` decodes to a grant with NO target
//     restriction — the widest value the field has.
//   - An explicit null. `{"targets":null}` decodes to a nil pointer, which this package reads as
//     "this hop places no target restriction". `{"once":null}` decodes to false, turning a
//     single-use approval into a standing one. In both cases the author WROTE the key, so
//     "absent means unrestricted" is not the reading they intended.
//   - A duplicate key. `{"targets":["tool:read"],"Targets":[]}` is two members; encoding/json
//     matches field names case-insensitively and keeps the LAST, so which of the two takes
//     effect depends on member order rather than on anything the author can see. That is the
//     same ambiguity the JSON-RPC envelope and tools/list scans already refuse, for the same
//     reason, and FoldJSONKey is shared with them so the three cannot drift on what "the same
//     key" means.
//
// All three are refused, which rejects the TOKEN. That is the loud failure: an IdP template
// mistake becomes a caller who cannot authenticate rather than a caller whose narrowing quietly
// evaporated.

// MaxClaimListEntries bounds how many entries one grant's list-valued member may carry. Like
// MaxDelegationDepth this is a bound on attacker-influenced input, not hygiene: a chain is
// validated once but WALKED on every enforced call, and the target index is a map built per hop
// per token. Two hundred fifty-six is far above any real grant (a delegated sub-agent scoped to
// more tools than a whole manifest declares is not a narrowing) and far below anything that
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

// decodeClaimObject decodes one claim-borne grant object into target, refusing the three shapes
// documented above before the struct decode runs. allowExtra names members that are permitted
// but not decoded — used only for the actor chain's identity-descriptive members.
func decodeClaimObject(data []byte, target any, context string, allowExtra ...string) error {
	members, err := claimObjectMembers(data, context)
	if err != nil {
		return err
	}
	// jsonFieldNames keys on the lower-cased field name. Looking it up with the FOLDED member
	// name agrees with it on every key an author writes (folding an ASCII name lower-cases it)
	// and is strictly closer to the decoder's own matcher on the ones they do not: encoding/json
	// folds rather than lower-cases, so "maxEffectClaſs" binds to MaxEffectClass and is a known
	// member here too, where a lower-cased lookup would have called it unknown.
	known := jsonFieldNames(target)
	extra := make(map[string]bool, len(allowExtra))
	for _, e := range allowExtra {
		extra[FoldJSONKey(e)] = true
	}
	seen := make(map[string]string, len(members))
	for _, m := range members {
		folded := FoldJSONKey(m.key)
		if prior, dup := seen[folded]; dup {
			return fmt.Errorf("%s: members %q and %q are the same key to a JSON decoder, so which one takes effect depends on their order; declare it once", context, prior, m.key)
		}
		seen[folded] = m.key
		if !known[folded] && !extra[folded] {
			return fmt.Errorf("%s: unknown field %q", context, m.key)
		}
		if bytes.Equal(bytes.TrimSpace(m.value), []byte("null")) {
			return fmt.Errorf("%s: member %q is null; a null decodes to this field's WIDEST value, which is the opposite of the narrowing a declared member expresses — omit the member instead", context, m.key)
		}
		if err := checkClaimListLength(m.value, m.key, context); err != nil {
			return err
		}
	}
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("%s: %w", context, err)
	}
	return nil
}

// checkClaimListLength bounds a list-valued member. Non-array members are left alone; the
// element values themselves are the decoder's business.
func checkClaimListLength(value json.RawMessage, key, context string) error {
	trimmed := bytes.TrimSpace(value)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return nil
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(trimmed, &entries); err != nil {
		// Leave the diagnosis to the struct decode below, which names the expected type.
		return nil //nolint:nilerr // the struct decode reports the type error with better context
	}
	if len(entries) > MaxClaimListEntries {
		return fmt.Errorf("%s: member %q carries %d entries, more than the maximum of %d", context, key, len(entries), MaxClaimListEntries)
	}
	return nil
}
