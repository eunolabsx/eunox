// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Bounding for the structured details a deny carries into the signed audit tape.

package enforcement

import (
	"encoding/json"
	"fmt"
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

	// maxDenialDetailsBytes bounds the WHOLE map, counting every key and every scalar
	// the walk visits. A per-string cap alone bounds a handler that echoes one
	// argument; it does not bound handleAllowedValues echoing an argument that decoded
	// to a large object or a 100k-element array, where each element is individually
	// tiny. The budget is charged as the walk descends and values past its exhaustion
	// are elided, so the marshaled details of a deny cannot exceed a few KiB whatever
	// shape the caller sent.
	maxDenialDetailsBytes = 8 << 10 // 8 KiB

	// maxDenialDetailDepth bounds nesting. The byte budget already charges for keys, so
	// a deep chain of *populated* objects exhausts it — but a chain of empty containers
	// ([[[[…]]]]) costs nothing per level and would otherwise recurse as deep as the
	// caller's JSON nested. Eight levels is past any real tool argument worth echoing.
	maxDenialDetailDepth = 8
)

// denialDetailElided replaces a value dropped for exceeding maxDenialDetailsBytes or
// maxDenialDetailDepth. A marker rather than an omitted key: a reader must be able to
// tell "this handler recorded nothing here" from "this was recorded and then cut",
// and a SIEM rule can match the marker to spot a caller probing the bound.
const denialDetailElided = "[eunox: elided]"

// boundDenialDetails returns a bounded deep copy of a denial's details map, or nil
// when there is nothing to bound.
//
// Deep copy, not in-place: the maps and slices a handler puts in Details routinely
// alias live structures — the matched constraint's allowedValues slice, the decoded
// request arguments — and both are read concurrently by other in-flight decisions.
// Truncating in place would mutate the loaded manifest.
//
// Keys are walked in sorted order so that which entries survive an exhausted budget
// is deterministic. Go's randomized map iteration would otherwise make two identical
// denied calls write different details into the tape, which reads to an operator (and
// to a diffing SIEM rule) as though the requests differed.
func boundDenialDetails(in map[string]interface{}) map[string]interface{} {
	if len(in) == 0 {
		// Preserve nil-vs-empty: a nil details map is omitted from the audit record
		// entirely, and an empty non-nil one marshals to {}. Handlers rely on the
		// former for denials that carry no structured context.
		return in
	}
	budget := maxDenialDetailsBytes
	return boundDetailMap(in, &budget, 0)
}

// boundDetailMap bounds one object level. budget is charged (through the pointer) by
// every key and scalar the walk visits, so the total across the whole structure is
// what maxDenialDetailsBytes bounds — not each level independently.
func boundDetailMap(in map[string]interface{}, budget *int, depth int) map[string]interface{} {
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make(map[string]interface{}, len(in))
	for _, k := range keys {
		// The key is charged before its value: an object of many empty-valued keys is
		// as much tape growth as one of few large values.
		bk := boundDetailString(k)
		*budget -= len(bk)
		if *budget < 0 {
			// Budget exhausted mid-map. Record ONE marker naming the elision rather than
			// a marker per dropped key, which would itself be proportional to the input.
			out[denialDetailElidedKey] = fmt.Sprintf("%d of %d entries elided", len(in)-len(out), len(in))
			return out
		}
		out[bk] = boundDetailValue(in[k], budget, depth)
	}
	return out
}

// denialDetailElidedKey names the marker entry boundDetailMap adds when the byte
// budget ran out partway through an object. The underscore prefix keeps it clear of
// real argument names, matching the audit package's own reserved-key convention.
const denialDetailElidedKey = "_eunox_elided"

// boundDetailValue bounds one value of any JSON shape, charging budget as it goes.
func boundDetailValue(v interface{}, budget *int, depth int) interface{} {
	if depth >= maxDenialDetailDepth {
		return denialDetailElided
	}
	switch t := v.(type) {
	case string:
		s := boundDetailString(t)
		*budget -= len(s)
		if *budget < 0 {
			return denialDetailElided
		}
		return s
	case json.Number:
		// A json.Number is a string underneath, and the JSON grammar puts no ceiling on
		// a numeric literal's digit count — the stack preserves them undecoded for exact
		// comparison, so an arbitrarily long one reaches here intact. Bound it like any
		// other string, but keep the json.Number type so a consumer that type-switches on
		// it still sees a number.
		s := boundDetailString(string(t))
		*budget -= len(s)
		if *budget < 0 {
			return denialDetailElided
		}
		return json.Number(s)
	case map[string]interface{}:
		return boundDetailMap(t, budget, depth+1)
	case []interface{}:
		out := make([]interface{}, 0, len(t))
		for i, e := range t {
			if *budget < 0 {
				out = append(out, fmt.Sprintf("[eunox: %d of %d elements elided]", len(t)-i, len(t)))
				return out
			}
			out = append(out, boundDetailValue(e, budget, depth+1))
		}
		return out
	case []string:
		// Handlers echo the manifest's own lists (allowedExtensions, allowedCIDRs,
		// allowedOperations) in this concrete form. Bounded like []interface{} even
		// though the entries are operator-supplied: the rule is "every string in a
		// denial's details is bounded", with no provenance exemption a future handler
		// could accidentally route an argument through.
		out := make([]string, 0, len(t))
		for i, e := range t {
			if *budget < 0 {
				out = append(out, fmt.Sprintf("[eunox: %d of %d elements elided]", len(t)-i, len(t)))
				return out
			}
			s := boundDetailString(e)
			*budget -= len(s)
			out = append(out, s)
		}
		return out
	default:
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

// denialDetailScalarCost is what one non-string scalar charges against the byte
// budget: roughly its marshaled width, so an array of a million booleans is elided on
// the same budget a long string is, rather than passing through free.
const denialDetailScalarCost = 8

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
