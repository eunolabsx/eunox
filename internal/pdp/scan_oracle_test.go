// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"bytes"
	"encoding/json"

	"github.com/eunolabs/eunox/pkg/capability"
)

// scanJSONKeysTokenizer is the duplicate-key scan as it was written against
// encoding/json's tokenizer, kept verbatim as the ORACLE for the byte-level walk that
// replaced it. The replacement is a performance change on a fail-closed security gate, so
// "it still passes the existing matrix" is not the bar: every verdict — untrustworthy, the
// candidate-name set, and whether that set is complete — has to match the implementation
// derived directly from the decoder's own tokens, on generated and fuzzed input alike.
//
// Do not "clean this up". Its value is that it does NOT share code with the scanner it
// checks. If the production scanner's contract changes deliberately, change this one to
// match in the same commit and say why.
func scanJSONKeysTokenizer(raw json.RawMessage, opts jsonKeyScanOpts) toolEntryScan {
	// frame tracks one open composite. seen is allocated lazily: most nested objects in a
	// tool schema are small, and an empty-object-heavy payload should not cost a map
	// header per object.
	type frame struct {
		object    bool
		seen      map[string]struct{}
		expectKey bool
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	// UseNumber so a float64-overflowing literal (1e999) inside a schema yields a
	// json.Number instead of erroring the walk, which would otherwise report a valid
	// entry untrustworthy (and, worse, shield a later duplicate behind that error).
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return toolEntryScan{untrustworthy: true}
	}
	rootDelim, rootIsDelim := tok.(json.Delim)
	rootObject := rootIsDelim && rootDelim == '{'
	rootAdmittedArray := opts.allowArrayRoot && rootIsDelim && rootDelim == '['
	if !rootObject && !rootAdmittedArray {
		// Not a JSON object: null, a number, a string, a bool, or (unless the caller admits
		// one) an array. The entry is
		// still untrustworthy — it cannot decode into the hashed tool surface, so the
		// filter must drop it — but unlike an entry whose bytes ABORTED the scan, its
		// candidate-name set is knowably EMPTY, not unknown: none of these shapes carries
		// a top-level "name", so a host renders no tool name from it and it cannot
		// impersonate any pin. Mark the (empty) name set complete so the caller poisons
		// nothing, rather than escalating a single null entry to a route-wide,
		// sticky-to-process-exit poison of every pinned tool.
		//
		// The entries arrive as json.RawMessage elements of an already-unmarshaled array,
		// so each is exactly one complete, well-formed JSON value: reading its first token
		// is enough to classify it, with no trailing bytes left to hide anything.
		return toolEntryScan{untrustworthy: true, namesComplete: true}
	}
	var out toolEntryScan
	stack := []frame{{object: rootObject, expectKey: rootObject}}
	// pendingName is set when the value about to be read is the ENTRY's top-level name
	// value, so the names it could present to a host can be collected in the same pass.
	// Only the struct-binding caller (opts.foldKeys == nil, i.e. the tools/list entry gate)
	// reads out.names; the redaction gate consults untrustworthy alone, so it never arms
	// this and never pays for the name collection.
	pendingName := false
	markValueDone := func() {
		if n := len(stack); n > 0 && stack[n-1].object {
			stack[n-1].expectKey = true
		}
	}
	// Every abort below returns `out` rather than a fresh zero value, so names already
	// collected survive -- and leaves namesComplete false, so the caller knows the list is
	// truncated and widens the poison accordingly.
	for len(stack) > 0 {
		tok, err := dec.Token()
		if err != nil {
			out.untrustworthy = true
			return out
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				if len(stack) >= maxDuplicateKeyScanDepth {
					out.untrustworthy = true // pathologically deep
					return out
				}
				stack = append(stack, frame{object: d == '{', expectKey: d == '{'})
				pendingName = false
			default: // '}' or ']'
				stack = stack[:len(stack)-1]
				markValueDone()
			}
			continue
		}
		n := len(stack)
		if stack[n-1].object && stack[n-1].expectKey {
			key, ok := tok.(string)
			if !ok {
				out.untrustworthy = true
				return out
			}
			// Canonicalize per the caller's fold policy (see jsonKeyScanOpts). Everything
			// not folded is compared byte-exactly, which is what catches the
			// caller-independent exact duplicate. capability.FoldJSONKey, not
			// strings.ToLower: ToLower leaves an already-lower-case case variant such as
			// U+017F ("deſcription") distinct from "description", so the collision the
			// decoder makes would go unseen and the bytes would clear the scan.
			canon := key
			switch {
			case opts.foldKeys != nil:
				// Scoped fold, at every depth: only a name whose case variant could change
				// what a consumer resolves. Depth-uniform on purpose -- an unscoped rule
				// keyed to depth made the verdict depend on whether the value happened to
				// be wrapped in an array, since the bracket occupies a level of its own.
				//
				// A key already equal to its folded form needs no rewrite (canon is that
				// form), so only the variant spelling is redirected onto it -- which is what
				// makes the two collide in `seen`.
				if folded := capability.FoldJSONKey(key); folded != key {
					if _, scoped := opts.foldKeys[folded]; scoped {
						canon = folded
					}
				}
			case n == 1:
				// Struct-binding fold, root object only. n == 1 IS the root object here:
				// this arm is reached only when opts.foldKeys is nil, and that caller does
				// not admit an array root, so the root frame is always the object.
				canon = capability.FoldJSONKey(key)
			}
			if stack[n-1].seen == nil {
				stack[n-1].seen = make(map[string]struct{})
			}
			if _, dup := stack[n-1].seen[canon]; dup {
				out.untrustworthy = true
			}
			stack[n-1].seen[canon] = struct{}{}
			stack[n-1].expectKey = false
			pendingName = opts.foldKeys == nil && n == 1 && canon == jsonKeyNameFolded
			continue
		}
		if pendingName {
			if s, ok := tok.(string); ok && s != "" {
				out.names = append(out.names, s)
			}
			pendingName = false
		}
		markValueDone()
	}
	// The stack unwound to empty: the whole entry was walked, so names is authoritative.
	out.namesComplete = true
	return out
}
