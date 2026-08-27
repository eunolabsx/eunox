// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// A claim object an IdP minted can name one claim in two ways a plain struct unmarshal
// resolves silently, and the two readers of these bytes disagree about which:
//
//   - This scan and encoding/json work in FOLD space (see FoldJSONKey), where a member name
//     is matched case-insensitively.
//   - go-jose's vendored json fork — the decoder that actually reads a JWT payload — matches
//     BYTE-EXACTLY, with no EqualFold fallback anywhere in it.
//
// So a COLLISION (`mcp` beside `MCP`) is resolved by member order for one reader and by
// spelling for the other, and a LONE VARIANT (`MCP` alone) collides with nothing, resolves to
// nothing, and binds to nothing — every check that reads the claim behaves as though the token
// never carried it. ClaimMembers REJECTS THE TOKEN for both rather than letting either decode
// pick, which is what makes the two readers agree about which claims a token carries.
//
// A JWT is signed by its issuer, so neither shape is a third party's forgery — but a claim
// resolved by member order, or by nothing at all, is one nobody can review.

var (
	// ErrClaimNameVariant marks a watched claim spelled a way no decoder on this path binds:
	// a lone case variant, which reads as an ABSENT claim rather than as the value the payload
	// plainly carries.
	ErrClaimNameVariant = errors.New("watched claim is spelled a way no decoder binds")
	// ErrClaimNameCollision marks a watched claim named more than once. Separate from
	// ErrClaimNameVariant because the two are different minting mistakes with different fixes
	// — stop emitting two spellings, versus correct the one — and a caller classifying a
	// refusal for an operator has only the sentinel to tell them apart. A failure carrying
	// NEITHER sentinel is a malformed claim object, which is a third thing again.
	ErrClaimNameCollision = errors.New("watched claim is named more than once")
)

// ClaimWatch is the validated set of canonical claim names ClaimMembers scans for.
type ClaimWatch struct {
	// byFold maps each name's fold to the name as the caller spelled it, which is what every
	// other spelling of that claim is refused against.
	byFold map[string]string
}

// NewClaimWatch validates names and returns the set ClaimMembers scans with. Build it ONCE
// from the caller's own constants: the entries are a compile-time fact, and validating them
// per token would put a caller's programming error on the request path, where a panic is a
// dropped connection per request rather than a failed startup.
//
// Every name must be the CANONICAL spelling — the one the decoders reading those bytes
// downstream bind — since it is what every other spelling is refused against. A single
// mis-cased entry cannot be caught here (which spelling a foreign decoder binds is not
// knowable from this package) and inverts the gate: the spelling every decoder binds is
// refused and the one that binds nothing is admitted. Its guard is the caller's own test that
// a payload spelling every watched name canonically is not refused for its spelling.
//
// Two names that fold together ARE caught, because that is the same ambiguity this package
// refuses in the data, and the survivor would silently become the canonical spelling. It
// panics rather than erroring: a watch list no token can reach should fail where a wiring
// fault fails, at construction.
func NewClaimWatch(names ...string) ClaimWatch {
	if len(names) == 0 {
		panic("capability.NewClaimWatch: no names, so the scan would report a pass over every claim object")
	}
	byFold := make(map[string]string, len(names))
	for _, name := range names {
		folded := FoldJSONKey(name)
		if prior, dup := byFold[folded]; dup {
			panic(fmt.Sprintf("capability.NewClaimWatch: %q and %q are the same claim to a JSON decoder, so which one is canonical depends on their order", prior, name))
		}
		byFold[folded] = name
	}
	return ClaimWatch{byFold: byFold}
}

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
	// More() answers "is there another member", and a read error is not another member, so a
	// truncated object leaves the loop exactly as a closed one does. Neither in-tree caller can
	// reach that today (both hand over bytes a completed decode produced), but nothing in the
	// exported contract obliges them to, and a scan that reports a pass over the part of an
	// object it could read is the reads-as-absent failure this file exists to refuse.
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("%s: %w", context, err)
	}
	// Not dec.More(): it answers false for a trailing `}` or `]` as readily as for end of
	// input, so it cannot tell a whole document from one with a second value after it.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: trailing data after the claim object", context)
	}
	return out, nil
}

// ClaimMembers validates that each name in watch appears among data's top-level JSON members
// at most once and spelled exactly as watch spells it, and returns each watched name's value
// keyed by that name — a name absent under every spelling is simply missing from the map.
//
// Refusing a lone variant rather than honoring it is the rule two sibling guards already
// apply to a protocol-reserved key (the tools/list envelope's list key, and the reserved
// roots of a tool result). It is deliberately NOT the rule RefuseAmbiguousJSONKeys and the
// strict corpus decode apply one layer down: those refuse a collision only, because the
// stdlib decoder under them FOLDS, so a lone variant there binds to the field its author
// meant. Here nothing binds it, which is the whole difference. Refusing costs a conforming
// issuer nothing — RFC 7519 claim names are case-sensitive — and leaves the property
// independent of whether any given decoder folds.
//
// Neither check rejects a member whose name is simply UNRECOGNIZED: data may be a claim
// object other parties legitimately extend — a JWT's whole payload carries claims for
// audiences besides this proxy, and even a proxy-owned block is versioned and may grow fields
// a running build predates. What the watch list DOES reserve is a fold-equivalence NAMESPACE:
// a foreign claim that folds to a watched name is refused even with the canonical spelling
// absent, since this scan cannot tell it from the watched claim mis-minted and guessing the
// benign reading is what fails open. Everything outside that namespace is ignored, ambiguous
// or not.
//
// One pass names every problem it finds. The producer these refusals exist for is a mapping
// rule that title-cases claim names, which hits several at once, so reporting the first would
// cost the operator a credential re-mint per claim to discover the next.
func ClaimMembers(data []byte, context string, watch ClaimWatch) (map[string]json.RawMessage, error) {
	if len(watch.byFold) == 0 {
		panic("capability.ClaimMembers: unbuilt ClaimWatch, so the scan would report a pass over every claim object")
	}
	members, err := claimObjectMembers(data, context)
	if err != nil {
		return nil, err
	}
	kept := make(map[string]claimMember, len(watch.byFold))
	collided := make(map[string]bool, len(watch.byFold))
	var collisions, variants []string
	for _, m := range members {
		canonical, watched := watch.byFold[FoldJSONKey(m.key)]
		if !watched {
			continue
		}
		if prior, dup := kept[canonical]; dup {
			// One report per claim, not per extra member: the finding is that the claim has
			// more than one candidate, and a payload repeating it a thousand times would
			// otherwise build a message a thousand entries long.
			if !collided[canonical] {
				collided[canonical] = true
				collisions = append(collisions, fmt.Sprintf("%q and %q (spell it %q)", prior.key, m.key, canonical))
			}
			continue
		}
		kept[canonical] = m
		if m.key != canonical {
			variants = append(variants, fmt.Sprintf("%q (spell it %q)", m.key, canonical))
		}
	}
	if len(collisions) > 0 || len(variants) > 0 {
		return nil, claimNameError(context, collisions, variants)
	}
	out := make(map[string]json.RawMessage, len(kept))
	for canonical, m := range kept {
		out[canonical] = m.value
	}
	return out, nil
}

// claimNameError reports every mis-named claim in one error, carrying the COLLISION sentinel
// when there is one: two candidates is the more severe ambiguity, and a caller stamping an
// audit category needs one verdict per token however many findings the payload carries.
func claimNameError(context string, collisions, variants []string) error {
	var problems []string
	if len(collisions) > 0 {
		problems = append(problems, "named more than once, so which one is enforced depends on their order: "+strings.Join(collisions, ", "))
	}
	if len(variants) > 0 {
		problems = append(problems, "spelled a way no decoder here binds, so the claim would be read as absent and every check that reads it silently skipped: "+strings.Join(variants, ", "))
	}
	sentinel := ErrClaimNameVariant
	if len(collisions) > 0 {
		sentinel = ErrClaimNameCollision
	}
	return fmt.Errorf("%s: %s: %w", context, strings.Join(problems, "; "), sentinel)
}
