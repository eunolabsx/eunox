// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// A JSON document on disk is read by a REVIEWER before it is read by a decoder, and
// encoding/json binds member names case-insensitively and keeps the LAST duplicate — so
// `{"publicKey": <the reviewed one>, "PublicKey": <another>}` shows one value to the human
// and hands a different one to the program. On a surface whose whole premise is that
// somebody evaluated the entry (an attestation trust root, a reviewed effect contract, an
// upstream's receipt-signing key set) that divergence is the substitution the review exists
// to catch, arriving in the one form review cannot see.
//
// This is the whole-document form of the check decodeClaimObject applies to one claim
// object: same fold (FoldJSONKey, the decoder's own case-insensitive matcher), same
// answer — refuse the document rather than resolve the ambiguity, because which member
// takes effect depends on their ORDER, which is not something a reader evaluates.

// maxAmbiguousKeyScanDepth bounds the walk's recursion. json.Unmarshal caps nesting at its
// own fixed limit, but a Token()-driven walk has none, so a deeply-nested document would
// recurse until the stack overflows — an uncatchable fatal error on operator-supplied
// input. Far above any document this check reads (a corpus entry's deepest member sits six
// levels down), so exceeding it is itself a refusal rather than a skipped scan: a scan that
// silently stopped would leave the ambiguity below the cut unexamined.
const maxAmbiguousKeyScanDepth = 64

// ambiguityRefusal marks the two verdicts RefuseAmbiguousJSONKeys reports, as opposed to
// the parse failures it leaves to the decoder that follows it.
type ambiguityRefusal struct{ msg string }

func (e *ambiguityRefusal) Error() string { return e.msg }

// RefuseAmbiguousJSONKeys reports an error when data contains an object with two members
// that are the same name to a JSON decoder (FoldJSONKey-equal), at any depth.
//
// It is a PRE-decode guard, so it deliberately says nothing about a malformed document:
// a syntax error, a non-string member name, or a truncated value is left to the strict
// decode that follows, which names the position and the expected type. Only the two
// verdicts this walk alone can reach — an ambiguous member name, and nesting past
// maxAmbiguousKeyScanDepth — come back as errors.
func RefuseAmbiguousJSONKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	// UseNumber so a literal outside float64's range (1e999) is carried as TEXT rather than
	// parsed. Token() otherwise fails on it and the walk stops there, leaving every member
	// after that number unscanned — while the decoders this guard protects read the same
	// bytes without complaint (the corpus loader uses UseNumber itself, and a plain
	// Unmarshal skips an unknown member without range-checking it), so one padding number
	// in front of the substitution bought a silent pass.
	dec.UseNumber()
	err := scanAmbiguousKeys(dec, "", 0)
	if err == nil {
		return nil
	}
	var refusal *ambiguityRefusal
	if errors.As(err, &refusal) {
		return err
	}
	// Any OTHER walk failure on a document that PARSES is this reader disagreeing with the
	// decoder about the same bytes — which is the class of divergence this guard exists to
	// refuse, not one to wave through on the strength of the decode succeeding. Only
	// genuinely malformed input is left to the decode that follows, which reports it with
	// the offset and the expected type.
	if json.Valid(data) {
		return &ambiguityRefusal{msg: fmt.Sprintf("could not be walked for ambiguous member names (%v) although it parses as JSON; refusing rather than decoding the part the walk never read", err)}
	}
	return nil
}

// scanAmbiguousKeys walks one JSON value, recursing through objects and arrays. path names
// where the walk is for the error message; depth bounds the recursion.
func scanAmbiguousKeys(dec *json.Decoder, path string, depth int) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, isDelim := tok.(json.Delim)
	if !isDelim {
		return nil // a scalar; Token consumed it whole
	}
	if depth >= maxAmbiguousKeyScanDepth {
		return &ambiguityRefusal{msg: fmt.Sprintf("%s nests more than %d levels deep, past what this reader will walk to check for ambiguous member names", describeJSONPath(path), maxAmbiguousKeyScanDepth)}
	}
	switch delim {
	case '{':
		if err := scanObjectMembers(dec, path, depth); err != nil {
			return err
		}
	case '[':
		for i := 0; dec.More(); i++ {
			if err := scanAmbiguousKeys(dec, path+"["+strconv.Itoa(i)+"]", depth+1); err != nil {
				return err
			}
		}
	}
	// The closing delimiter, so the caller's dec.More() reads the next sibling.
	_, err = dec.Token()
	return err
}

// scanObjectMembers checks one object's member names against each other and descends into
// each value.
func scanObjectMembers(dec *json.Decoder, path string, depth int) error {
	seen := map[string]string{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := tok.(string)
		if !ok {
			return fmt.Errorf("expected a member name")
		}
		folded := FoldJSONKey(key)
		if prior, dup := seen[folded]; dup {
			return &ambiguityRefusal{msg: fmt.Sprintf("members %q and %q of %s are the same name to a JSON decoder, which keeps the LAST of them — so which value takes effect depends on their order rather than on anything a reviewer reading the file can see; declare it once", prior, key, describeJSONPath(path))}
		}
		seen[folded] = key
		if err := scanAmbiguousKeys(dec, path+"."+key, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// describeJSONPath renders a walk position for an error message, naming the root
// explicitly rather than printing an empty string.
func describeJSONPath(path string) string {
	if path == "" {
		return "the top-level object"
	}
	return strconv.Quote(strings.TrimPrefix(path, "."))
}
