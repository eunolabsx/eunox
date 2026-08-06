// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Bounding for the structured details a deny carries into the signed audit tape.

package enforcement

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"sort"

	"github.com/eunolabs/eunox/pkg/capability"
)

// A condition denial's Details map is the one place caller-controlled bytes cross from a
// rejected request into the HMAC-signed OCSF tape: handlers echo the failing value so a deny
// is actionable, but nothing upstream bounds a tool-call argument, so an unbounded echo made
// every denied call a kilobyte-per-byte lever on signed-log growth — the same amplifier closed
// pre-auth for the Origin header and loopback paths, reachable here post-auth via an argument.
//
// The bound lives at denyResponse, the single funnel every deny passes through, so a handler
// added later inherits it by construction instead of one of 20-odd sites forgetting to call it.
//
// Not a substitute for the audit sink's own caps (auditDetailValueCap/auditDetailsTotalCap),
// which are far looser: those guard any record including a full-argument audit-mode ALLOW,
// while these guard a DENY's diagnostic echo.
const (
	// maxDenialDetailStringLen bounds one string value inside a denial's details. 512 matches
	// the transport's maxRefusalDetailLen — no legitimate echoed value approaches it.
	maxDenialDetailStringLen = 512

	// maxDenialDetailsBytes bounds the WHOLE map. A per-string cap alone doesn't bound a
	// handler echoing a huge array of individually-tiny (or empty) elements — every key,
	// scalar, and container the walk visits is charged (see denialDetailContainerCost), so
	// the total stays a few KiB whatever shape the caller sent.
	maxDenialDetailsBytes = 8 << 10 // 8 KiB

	// maxDenialDetailDepth bounds nesting independently of the byte budget; eight levels is
	// past any real tool argument worth echoing.
	maxDenialDetailDepth = 8

	// minDenialDetailKeyBudget floors the per-key share below, bounding how far the whole map
	// can overshoot maxDenialDetailsBytes when a handler records an unusual number of keys.
	minDenialDetailKeyBudget = 512

	// maxDenialDetailTopLevelKeys bounds how many top-level keys BoundDenialDetails processes.
	// The per-key share floors at minDenialDetailKeyBudget once len(in) passes this count, so
	// "bounds the whole map" held only up to here — past it, output grows ~512 bytes per extra
	// key with nothing capping how many keys there can be. Matches maxDenialDetailsBytes /
	// minDenialDetailKeyBudget: the floor's own breakeven point.
	maxDenialDetailTopLevelKeys = maxDenialDetailsBytes / minDenialDetailKeyBudget
)

// denialDetailContainerCost is what one map or slice charges before its contents. Without it
// an EMPTY container was free — `[{},{},{}…]` carried a full caller-sized structure through a
// "bounded" result, measured at 600 KB against an 8 KiB budget, tripping the audit sink's
// coarse cap and replacing the whole details map with a marker.
const denialDetailContainerCost = 8

// denialDetailScalarCost is what one non-string scalar charges, so an array of a million
// booleans is bounded like a long string rather than passing through free.
const denialDetailScalarCost = 8

// DenialDetailElided replaces a value dropped for exceeding the byte budget or depth — a
// marker rather than an omission, so a reader (or SIEM rule) can tell "recorded nothing" from
// "cut".
const DenialDetailElided = "[eunox: elided]"

// DenialDetailElidedKey names the marker entry boundDetailMap adds when a key's share runs
// out mid-object. The reserved-key convention alone doesn't stop a caller planting this exact
// string to forge elision provenance; escapeReservedDetailKey closes that by re-spelling a
// colliding caller key, mirroring internal/transport/dispatch.go's own collision guard.
const DenialDetailElidedKey = "_eunox_elided"

// denialDetailForgedKeyPrefix re-spells a caller key colliding with the reserved marker so it
// can't be mistaken for one eunox wrote.
const denialDetailForgedKeyPrefix = "_eunox_caller_"

// denialDetailSliceElidedRe matches the two marker spellings boundDetailSlice appends for a
// fully- vs. partially-elided slice, so IsDenialDetailSliceElided recognizes both as one
// family.
var denialDetailSliceElidedRe = regexp.MustCompile(`^\[eunox: \d+( of \d+)? elements elided\]$`)

// IsDenialDetailElided reports whether s is exactly DenialDetailElided.
//
// Exported alongside the marker so a consumer mining a denial's Details for real values
// (cmd/eunox's suggest miner) can recognize this layer's placeholder rather than mining it as
// literal caller data. Mirrors internal/audit.IsOverCapValuePlaceholder for that layer's own
// truncation marker.
func IsDenialDetailElided(s string) bool {
	return s == DenialDetailElided
}

// IsDenialDetailSliceElided reports whether s is one of the markers boundDetailSlice
// substitutes for dropped slice elements. See IsDenialDetailElided.
func IsDenialDetailSliceElided(s string) bool {
	return denialDetailSliceElidedRe.MatchString(s)
}

// BoundDenialDetails returns a bounded deep copy of a denial's details map, or nil.
//
// Deep copy, not in-place: a handler's Details routinely aliases live structures (the matched
// constraint's allowedValues, decoded request arguments) read concurrently by other
// decisions — truncating in place would mutate the loaded manifest.
//
// The budget is a per-key SHARE, not first-come: keys walked in sorted order against one
// shared budget meant a manifest with a few hundred allowedValues consumed the whole budget
// and elided the denied argument's name and value — the two fields the bound exists to
// preserve.
//
// Exported with no unexported twin because EvaluateAllowedValues assembles its own
// EnforceResponse one layer up rather than going through denyResponse, so it needs a reachable
// bound of its own; its one caller routes every deny through a single funnel.
//
// NOT idempotent: boundDetailMap writes DenialDetailElidedKey for an elided entry, and
// applying this twice would re-spell eunox's own marker as caller forgery. Bound once, at the
// funnel.
func BoundDenialDetails(in map[string]interface{}) map[string]interface{} {
	if len(in) == 0 {
		// Preserve nil-vs-empty: a nil map is omitted from the audit record, {} marshals for
		// an empty non-nil one, and handlers rely on the former for denials with no context.
		return in
	}
	share := maxDenialDetailsBytes / len(in)
	if share < minDenialDetailKeyBudget {
		share = minDenialDetailKeyBudget
	}

	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	// Sorted so which keys survive a breadth cap (or an exhausted budget) is deterministic —
	// Go's randomized map iteration would otherwise make two identical denied calls write
	// different records.
	sort.Strings(keys)
	elided := 0
	if len(keys) > maxDenialDetailTopLevelKeys {
		elided = len(keys) - maxDenialDetailTopLevelKeys
		keys = keys[:maxDenialDetailTopLevelKeys]
	}

	out := make(map[string]interface{}, len(keys)+1)
	for _, k := range keys {
		bk := escapeReservedDetailKey(boundDetailString(k))
		budget := share - len(bk)
		out[bk] = boundDetailValue(in[k], &budget, 0)
	}
	if elided > 0 {
		out[DenialDetailElidedKey] = fmt.Sprintf("%d of %d entries elided", elided, len(in))
	}
	return out
}

// escapeReservedDetailKey re-spells a caller key colliding with the reserved elision marker,
// so a marker on a record always means eunox elided something.
func escapeReservedDetailKey(k string) string {
	if k == DenialDetailElidedKey {
		return denialDetailForgedKeyPrefix + k
	}
	return k
}

// boundDetailMap bounds one object level against the caller's remaining budget, charging
// every key and recursing for every value.
func boundDetailMap(in map[string]interface{}, budget *int, depth int) map[string]interface{} {
	*budget -= denialDetailContainerCost
	if *budget < 0 {
		return map[string]interface{}{DenialDetailElidedKey: fmt.Sprintf("%d entries elided", len(in))}
	}
	keys := make([]string, 0, boundedPrealloc(len(in), *budget))
	for k := range in {
		keys = append(keys, k)
		if len(keys) == cap(keys) {
			// Stop once the remaining budget provably can't admit another entry — sizing from
			// len(in) meant a 4 MiB argument allocated tens of MiB to sort a few hundred
			// thousand keys for a few KiB of output, on a path an attacker triggers at will.
			break
		}
	}
	// Sorted so which entries survive an exhausted budget is deterministic — Go's randomized
	// map iteration would otherwise make two identical denied calls write different records.
	sort.Strings(keys)

	out := make(map[string]interface{}, len(keys))
	for i, k := range keys {
		bk := escapeReservedDetailKey(boundDetailString(k))
		*budget -= len(bk)
		if *budget < 0 {
			// ONE marker naming the elision, not one per dropped key — a per-key marker would
			// itself be proportional to the input.
			out[DenialDetailElidedKey] = fmt.Sprintf("%d of %d entries elided", len(in)-i, len(in))
			return out
		}
		out[bk] = boundDetailValue(in[k], budget, depth)
	}
	if len(keys) < len(in) {
		out[DenialDetailElidedKey] = fmt.Sprintf("%d of %d entries elided", len(in)-len(keys), len(in))
	}
	return out
}

// boundedPrealloc caps a make() hint (and the fill loop) from untrusted input at what the
// remaining budget could admit.
func boundedPrealloc(n, budget int) int {
	if budget < 0 {
		budget = 0
	}
	if maxEntries := budget/2 + 1; n > maxEntries {
		return maxEntries
	}
	return n
}

// boundDetailValue bounds one value of any JSON shape, charging budget as it goes.
func boundDetailValue(v interface{}, budget *int, depth int) interface{} {
	if depth >= maxDenialDetailDepth {
		return DenialDetailElided
	}
	switch t := v.(type) {
	case string:
		b, ok := chargeBoundedString(t, budget)
		if !ok {
			return DenialDetailElided
		}
		return b
	case json.Number:
		// A json.Number is a string underneath with no ceiling on digit count, so an
		// arbitrarily long literal reaches here intact; bound it like a string but keep the
		// json.Number type.
		b, ok := chargeBoundedString(string(t), budget)
		if !ok {
			return DenialDetailElided
		}
		return json.Number(b)
	case []byte:
		// Modelled explicitly: a []byte is neither fixed-width nor immutable, so the default
		// arm would exempt it from the budget, deep copy, and UTF-8 normalization. Reachable
		// from a custom ConditionHandler or external PolicyEvaluator.
		b, ok := chargeBoundedString(string(t), budget)
		if !ok {
			return DenialDetailElided
		}
		return []byte(b)
	case map[string]interface{}:
		return boundDetailMap(t, budget, depth+1)
	case []interface{}:
		return boundDetailSlice(in2any(t), budget,
			func(s string) interface{} { return s },
			func(e interface{}) interface{} { return boundDetailValue(e, budget, depth+1) })
	case []string:
		// Bounded like []interface{} even though most entries are operator-supplied lists
		// (allowedExtensions, allowedCIDRs, …) — no provenance exemption a future handler
		// could route an argument through. Type preserved since a Go consumer reasonably
		// type-asserts it.
		return boundDetailSlice(t, budget,
			func(s string) string { return s },
			func(e string) string {
				b, ok := chargeBoundedString(e, budget)
				if !ok {
					return DenialDetailElided
				}
				return b
			})
	default:
		// A named scalar type (`type Path string`) lands here rather than the string arm;
		// recover its underlying string via reflection instead of letting it bypass every
		// bound.
		if rv := reflect.ValueOf(v); rv.IsValid() && rv.Kind() == reflect.String {
			b, ok := chargeBoundedString(rv.String(), budget)
			if !ok {
				return DenialDetailElided
			}
			return b
		}
		// Bools, decoded numbers, nil: fixed-width and immutable, so no copy or bound needed
		// — charged a nominal amount so a large array of them still exhausts the budget.
		*budget -= denialDetailScalarCost
		if *budget < 0 {
			return DenialDetailElided
		}
		return v
	}
}

// in2any is the identity on []interface{}, present only so the []interface{} arm can
// instantiate the same generic helper the []string arm uses.
func in2any(v []interface{}) []interface{} { return v }

// chargeBoundedString bounds s and charges the result against budget, reporting false when
// that exhausts it — the one place subtract-then-check lives, so no caller can charge and
// forget to check (the []string arm previously missed its last element).
//
// The charge floors at denialDetailScalarCost rather than s's own length: charging len()
// alone made the empty string free, so an array of them was admitted in full — half a million
// elements marshaling to ~1.5 MB against an 8 KiB budget, the same unbounded-breadth hole
// denialDetailContainerCost closed for empty containers.
func chargeBoundedString(s string, budget *int) (string, bool) {
	b := boundDetailString(s)
	cost := len(b)
	if cost < denialDetailScalarCost {
		cost = denialDetailScalarCost
	}
	*budget -= cost
	if *budget < 0 {
		return "", false
	}
	return b, true
}

// boundDetailSlice bounds one array level, charging the container then each element. Shared
// by the []interface{} and []string arms, which were near-copies that charged in different
// orders; marker builds the elision entry in the caller's element type so each arm keeps its
// own slice type.
func boundDetailSlice[T any](in []T, budget *int, marker func(string) T, bound func(T) T) []T {
	*budget -= denialDetailContainerCost
	if *budget < 0 {
		return []T{marker(fmt.Sprintf("[eunox: %d elements elided]", len(in)))}
	}
	out := make([]T, 0, boundedPrealloc(len(in), *budget))
	for i, e := range in {
		if *budget < 0 {
			out = append(out, marker(fmt.Sprintf("[eunox: %d of %d elements elided]", len(in)-i, len(in))))
			return out
		}
		out = append(out, bound(e))
	}
	return out
}

// boundDetailString truncates s to maxDenialDetailStringLen with a visible marker recording
// the original length, keeping the marker within the cap.
//
// Delegates to capability.BoundString, which normalizes to valid UTF-8 first: a tool argument
// is wire-decoded, not UTF-8-validated beyond JSON's own rules, and encoding/json isn't
// idempotent across decode-then-re-encode for invalid UTF-8 — the audit chain's HMAC verify
// depends on that idempotency, same as the audit sink's own boundFieldTo.
func boundDetailString(s string) string {
	return capability.BoundString(s, maxDenialDetailStringLen)
}
