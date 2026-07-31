// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Bounding for the structured details a deny carries into the signed audit tape.

package enforcement

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"unicode/utf8"
)

// A condition denial's Details map is the one place caller-controlled bytes cross
// from a rejected request into the HMAC-signed OCSF tape. Handlers echo the value
// that failed the check — the argument that missed the allowlist, the path whose
// extension was refused — because that is what makes a deny actionable to the
// operator reading it back. Nothing upstream bounds a tool-call argument before the
// condition check runs, so verbatim echoes made every denied call a kilobyte-per-byte
// lever on signed-log growth: an agent that can trigger a condition denial with a
// large argument inflates the tape at whatever rate it can issue calls. This is the
// same amplifier the transport layer closed for the rejected Origin header and the
// loopback endpoints' path (boundedRefusalDetail / maxRefusalDetailLen), reachable
// post-auth through an argument instead of pre-auth through a header.
//
// The bound lives at the single funnel every deny passes through (denyResponse)
// rather than at each handler's Details literal, so a handler added later inherits it
// by construction — the property that keeps 20-odd sites from drifting out of sync,
// and the reason the transport side centralized its source_ip stamping instead of
// asking eight call sites to remember.
//
// It is deliberately NOT a substitute for the audit sink's own caps
// (auditDetailValueCap / auditDetailsTotalCap). Those exist to keep any record —
// including an audit-mode ALLOW, which carries full arguments on purpose — under the
// scanner buffer the chain resume depends on. These are far tighter because a DENY's
// details are a diagnostic echo, not the record of what was actually forwarded.
const (
	// maxDenialDetailStringLen bounds one string value inside a denial's details.
	// 512 bytes matches the transport's maxRefusalDetailLen for the same reason: no
	// legitimate echoed value — an argument, a file path, a resource URI, an operation
	// verb — approaches it, while the truncation marker keeps the cut visible to a
	// reader rather than silently presenting a prefix as the whole value.
	maxDenialDetailStringLen = 512

	// maxDenialDetailsBytes bounds the WHOLE map. A per-string cap alone bounds a
	// handler that echoes one argument; it does not bound handleAllowedValues echoing
	// an argument that decoded to a large object or a 100k-element array, where each
	// element is individually tiny — or, worse, an array of EMPTY containers, which
	// carry no strings and no scalars at all. Every key, every scalar AND every
	// container the walk visits is charged (see denialDetailContainerCost), so the
	// marshaled details of a deny cannot exceed a few KiB whatever shape the caller
	// sent.
	maxDenialDetailsBytes = 8 << 10 // 8 KiB

	// maxDenialDetailDepth bounds nesting independently of the byte budget. Eight
	// levels is past any real tool argument worth echoing.
	maxDenialDetailDepth = 8

	// minDenialDetailKeyBudget is the floor on the per-key share below. It bounds how
	// far the whole map can overshoot maxDenialDetailsBytes when a handler records an
	// unusual number of keys (share x keys), and no handler in the tree records more
	// than five.
	minDenialDetailKeyBudget = 512
)

// denialDetailContainerCost is what one map or slice charges against the byte budget,
// counted before its contents. Without it an EMPTY container was free: the map arm
// charges per key and the slice arm per element, so `[{},{},{}…]` and `[[],[],[]…]`
// carried a full copy of a caller-sized structure into a "bounded" result — measured
// at 600 KB against an 8 KiB budget, which then tripped the audit sink's coarse 1 MiB
// cap and replaced the WHOLE details map with a marker, destroying the diagnostic
// content this walk exists to preserve. The value approximates a container's marshaled
// punctuation; what matters is that it is non-zero, so breadth is bounded like depth.
const denialDetailContainerCost = 8

// denialDetailScalarCost is what one non-string scalar charges: roughly its marshaled
// width, so an array of a million booleans is elided on the same budget a long string
// is rather than passing through free.
const denialDetailScalarCost = 8

// denialDetailElided replaces a value dropped for exceeding the byte budget or
// maxDenialDetailDepth. A marker rather than an omitted key: a reader must be able to
// tell "this handler recorded nothing here" from "this was recorded and then cut",
// and a SIEM rule can match the marker to spot a caller probing the bound.
const denialDetailElided = "[eunox: elided]"

// denialDetailElidedKey names the marker entry boundDetailMap adds when a key's share
// ran out partway through an object. The underscore prefix follows the audit package's
// reserved-key convention — but the convention alone is not a guarantee, because a
// caller-supplied argument key is just a string and nothing rejects this spelling. A
// caller planting it would forge elision provenance on the signed tape, making the
// detector forgeable by the party it exists to detect (and, planted on every call,
// noise that buries genuine elisions). escapeReservedDetailKey is what closes that,
// mirroring the collision guard internal/transport/dispatch.go applies to its own
// reserved key.
const denialDetailElidedKey = "_eunox_elided"

// denialDetailForgedKeyPrefix re-spells a caller key that collides with the reserved
// marker. The result is still visible to a reader — nothing is dropped — but it can no
// longer be mistaken for a marker eunox wrote.
const denialDetailForgedKeyPrefix = "_eunox_caller_"

// boundDenialDetails returns a bounded deep copy of a denial's details map, or nil
// when there is nothing to bound.
//
// Deep copy, not in-place: the maps and slices a handler puts in Details routinely
// alias live structures — the matched constraint's allowedValues slice, the decoded
// request arguments — and both are read concurrently by other in-flight decisions.
// Truncating in place would mutate the loaded manifest.
//
// The budget is divided into a per-key SHARE rather than spent first-come. Keys were
// walked in sorted order against one shared budget, and every handler's policy-list
// key (allowedValues, allowedExtensions, allowedCIDRs, …) sorts before its evidence
// keys (argument, value, filePath, …) — so an ordinary manifest with a few hundred
// allowed values consumed the whole budget and elided the denied argument NAME and
// VALUE, the two fields the bound exists to preserve. (The transport also reads
// Details["argument"] to build the host-facing error message.) An equal share per key
// cannot starve one key with another, needs no hand-maintained list of which keys are
// "important", and stays deterministic.
func boundDenialDetails(in map[string]interface{}) map[string]interface{} {
	if len(in) == 0 {
		// Preserve nil-vs-empty: a nil details map is omitted from the audit record
		// entirely, and an empty non-nil one marshals to {}. Handlers rely on the
		// former for denials that carry no structured context.
		return in
	}
	share := maxDenialDetailsBytes / len(in)
	if share < minDenialDetailKeyBudget {
		share = minDenialDetailKeyBudget
	}
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		bk := escapeReservedDetailKey(boundDetailString(k))
		budget := share - len(bk)
		out[bk] = boundDetailValue(v, &budget, 0)
	}
	return out
}

// escapeReservedDetailKey re-spells a caller key that collides with the reserved
// elision marker, so a marker on a record always means eunox elided something.
func escapeReservedDetailKey(k string) string {
	if k == denialDetailElidedKey {
		return denialDetailForgedKeyPrefix + k
	}
	return k
}

// boundDetailMap bounds one object level against the caller's remaining budget,
// charging every key and recursing for every value.
func boundDetailMap(in map[string]interface{}, budget *int, depth int) map[string]interface{} {
	*budget -= denialDetailContainerCost
	if *budget < 0 {
		return map[string]interface{}{denialDetailElidedKey: fmt.Sprintf("%d entries elided", len(in))}
	}
	keys := make([]string, 0, boundedPrealloc(len(in), *budget))
	for k := range in {
		keys = append(keys, k)
		if len(keys) == cap(keys) {
			// Stop collecting once the remaining budget provably cannot admit another
			// entry. Sizing the slice — and the sort below — from len(in) meant a 4 MiB
			// argument allocated tens of MiB and ordered a few hundred thousand keys to
			// produce a few KiB of output, per denied request, on a path an attacker
			// triggers at will.
			break
		}
	}
	// Sorted so that WHICH entries survive an exhausted budget is deterministic: Go's
	// randomized map iteration would otherwise make two identical denied calls write
	// different records, which an operator (and a diffing SIEM rule) reads as a
	// difference in the requests.
	sort.Strings(keys)

	out := make(map[string]interface{}, len(keys))
	for i, k := range keys {
		bk := escapeReservedDetailKey(boundDetailString(k))
		*budget -= len(bk)
		if *budget < 0 {
			// Budget exhausted mid-map. ONE marker naming the elision, not one per
			// dropped key — a per-key marker would itself be proportional to the input.
			out[denialDetailElidedKey] = fmt.Sprintf("%d of %d entries elided", len(in)-i, len(in))
			return out
		}
		out[bk] = boundDetailValue(in[k], budget, depth)
	}
	if len(keys) < len(in) {
		out[denialDetailElidedKey] = fmt.Sprintf("%d of %d entries elided", len(in)-len(keys), len(in))
	}
	return out
}

// boundedPrealloc caps a make() hint (and the iteration that fills it) taken from
// untrusted input at what the remaining budget could possibly admit. Two bytes is below
// the smallest thing that can be charged — a one-character key plus its value — so the
// cap can never be smaller than what actually fits.
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
		return denialDetailElided
	}
	switch t := v.(type) {
	case string:
		b, ok := chargeBoundedString(t, budget)
		if !ok {
			return denialDetailElided
		}
		return b
	case json.Number:
		// A json.Number is a string underneath, and the JSON grammar puts no ceiling on
		// a numeric literal's digit count — the stack preserves them undecoded for exact
		// comparison, so an arbitrarily long one reaches here intact. Bound it like any
		// other string, but keep the json.Number type so a consumer that type-switches on
		// it still sees a number.
		b, ok := chargeBoundedString(string(t), budget)
		if !ok {
			return denialDetailElided
		}
		return json.Number(b)
	case []byte:
		// Modelled explicitly rather than left to the default arm: a []byte is neither
		// fixed-width nor immutable, so passing it through would exempt it from the
		// budget, the deep copy AND the UTF-8 normalization. It is reachable from a
		// custom ConditionHandler or an external PolicyEvaluator — the same surface that
		// motivates bounding the denial taxonomy at the sink.
		b, ok := chargeBoundedString(string(t), budget)
		if !ok {
			return denialDetailElided
		}
		return []byte(b)
	case map[string]interface{}:
		return boundDetailMap(t, budget, depth+1)
	case []interface{}:
		return boundDetailSlice(in2any(t), budget,
			func(s string) interface{} { return s },
			func(e interface{}) interface{} { return boundDetailValue(e, budget, depth+1) })
	case []string:
		// Handlers echo the manifest's own lists (allowedExtensions, allowedCIDRs,
		// allowedOperations) and the flow-label engine echoes its blocked set in this
		// concrete form. Bounded like []interface{} even though most entries are
		// operator-supplied: the rule is "every string in a denial's details is
		// bounded", with no provenance exemption a future handler could accidentally
		// route an argument through. The []string TYPE is preserved rather than
		// normalized away — a Go consumer reading Details reasonably type-asserts it.
		return boundDetailSlice(t, budget,
			func(s string) string { return s },
			func(e string) string {
				b, ok := chargeBoundedString(e, budget)
				if !ok {
					return denialDetailElided
				}
				return b
			})
	default:
		// A named scalar type (`type Path string`) reaches here rather than the string
		// arm, and it is neither fixed-width nor already normalized — so recover its
		// underlying string through reflection instead of letting it bypass every bound.
		if rv := reflect.ValueOf(v); rv.IsValid() && rv.Kind() == reflect.String {
			b, ok := chargeBoundedString(rv.String(), budget)
			if !ok {
				return denialDetailElided
			}
			return b
		}
		// Bools, numbers already decoded to float64/int, and nil: fixed-width and
		// immutable, so they need neither a copy nor a bound. Charged a nominal amount
		// so a large array of them still exhausts the budget.
		*budget -= denialDetailScalarCost
		if *budget < 0 {
			return denialDetailElided
		}
		return v
	}
}

// in2any is the identity on []interface{}, present only so the []interface{} arm can
// instantiate the same generic helper the []string arm uses.
func in2any(v []interface{}) []interface{} { return v }

// chargeBoundedString bounds s and charges the result against budget, reporting false
// when that exhausts it. It is the one place the subtract-then-check order lives, so no
// arm can charge and then forget to check — the []string arm previously checked only at
// the top of its loop, writing the element that crossed the budget in full and never
// checking the last element at all, while the []interface{} arm elided it.
func chargeBoundedString(s string, budget *int) (string, bool) {
	b := boundDetailString(s)
	*budget -= len(b)
	if *budget < 0 {
		return "", false
	}
	return b, true
}

// boundDetailSlice bounds one array level, charging the container and then each element
// through bound. Shared by the []interface{} and []string arms, which were near-copies
// that charged in different orders — two spellings of one elision policy, where the next
// edit to either would have missed the other. marker builds the elision entry in the
// caller's element type, which is what lets each arm keep its own concrete slice type.
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

// boundDetailString truncates one string to maxDenialDetailStringLen with a visible
// marker recording the original length, keeping the marker WITHIN the cap so the
// result never exceeds it.
//
// It first normalizes to valid UTF-8. Every string reaching here can hold raw
// caller-supplied bytes (a tool argument is decoded from the wire, not validated as
// UTF-8 beyond JSON's own rules), and encoding/json is not idempotent across a
// decode-then-re-encode round trip for invalid UTF-8 — the audit chain's HMAC
// recompute and canonical-bytes check both depend on that idempotency, and the sink's
// own boundFieldTo normalizes the envelope for exactly this reason. Details take the
// same treatment so a denial echo cannot be the field that makes a genuine record
// fail verification.
func boundDetailString(s string) string {
	s = strings.ToValidUTF8(s, "�")
	if len(s) <= maxDenialDetailStringLen {
		return s
	}
	marker := fmt.Sprintf("...[eunox: truncated, %d bytes]", len(s))
	keep := maxDenialDetailStringLen - len(marker)
	if keep < 0 {
		return "..."
	}
	// Cut on a rune boundary so the truncated value is still valid UTF-8.
	for keep > 0 && !utf8.RuneStart(s[keep]) {
		keep--
	}
	return s[:keep] + marker
}
