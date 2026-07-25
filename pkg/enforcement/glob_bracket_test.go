// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement_test

import (
	"path"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/pkg/enforcement"
)

// TestValidateValueGlobUnopenedBracketIsLiteral pins that a ']' with no open '[' is
// treated as an ordinary literal, matching path.Match's grammar.
//
// The bug this guards: the literal renderer used to drop every ']' unconditionally, so
// the neighbours on either side spliced together. "a%2]f" rendered as "a%2f" and the
// pattern was rejected at load as carrying an encoded path separator — even though
// path.Match matches it against the literal value "a%2]f" perfectly well. The rejection
// is meant to catch grants that can never match; here it killed one that can.
func TestValidateValueGlobUnopenedBracketIsLiteral(t *testing.T) {
	// Each pattern is a literal that path.Match matches against itself, so none of them
	// is a dead grant and none may be rejected.
	patterns := []string{
		"a%2]f",
		"x%]2f",
		"]",
		"]%2",
		"2f]%",
		"report]x%5",
		"a]b",
	}
	for _, p := range patterns {
		t.Run(p, func(t *testing.T) {
			// Establish the premise: path.Match really does treat this as a live pattern
			// that matches its own literal text. If this ever stops holding, the
			// expectation below needs re-deriving rather than silently flipping.
			ok, err := path.Match(p, p)
			if err != nil {
				t.Fatalf("path.Match(%q, %q) returned %v; pattern is not valid, premise broken", p, p, err)
			}
			if !ok {
				t.Fatalf("path.Match(%q, %q) = false; pattern does not match its own literal text, premise broken", p, p)
			}
			if err := enforcement.ValidateValueGlob(p); err != nil {
				t.Errorf("ValidateValueGlob(%q) = %v, want nil — a matchable pattern was rejected as a dead grant", p, err)
			}
		})
	}
}

// TestValidateValueGlobStillRejectsRealEncodedSeparators guards the other direction: the
// fix must not blunt the check it sits inside. These patterns really do carry an encoded
// separator in their literal text and must still be refused at load.
func TestValidateValueGlobStillRejectsRealEncodedSeparators(t *testing.T) {
	patterns := []string{
		"a%2fb",
		"a%2Fb",
		"reports/%5cetc",
		"%2f",
		"pre]post%2fx", // literal ']' now emitted, and the %2f after it is still caught
	}
	for _, p := range patterns {
		t.Run(p, func(t *testing.T) {
			err := enforcement.ValidateValueGlob(p)
			if err == nil {
				t.Fatalf("ValidateValueGlob(%q) = nil, want an encoded-separator rejection", p)
			}
			if !strings.Contains(err.Error(), "encoded path separator") {
				t.Errorf("ValidateValueGlob(%q) rejected for the wrong reason: %v", p, err)
			}
		})
	}
}

// TestValidateValueGlobBracketClassStillElided pins the behavior the renderer exists for:
// '%', '2' and 'f' written INSIDE a class are class members, so the pattern is a live
// grant and must load. The ']' fix must not disturb this.
func TestValidateValueGlobBracketClassStillElided(t *testing.T) {
	patterns := []string{
		"[a%2f]",
		"report[%2f]x",
		"a[bc]d",
	}
	for _, p := range patterns {
		t.Run(p, func(t *testing.T) {
			if err := enforcement.ValidateValueGlob(p); err != nil {
				t.Errorf("ValidateValueGlob(%q) = %v, want nil — class members must not read as an encoded separator", p, err)
			}
		})
	}
}

// TestValidateValueGlobClassElisionCannotSpliceSeparator is the security-relevant
// direction: eliding a class must not let the bytes on either side of it splice into an
// encoded separator that was never literally present. The placeholder exists for this.
func TestValidateValueGlobClassElisionCannotSpliceSeparator(t *testing.T) {
	// "%[x]2f": eliding "[x]" naively would yield "%2f" and produce a rejection for a
	// token the pattern never spelled literally. The class stands for one value
	// character, so this grant is live and must load.
	const p = "%[x]2f"
	if err := enforcement.ValidateValueGlob(p); err != nil {
		t.Errorf("ValidateValueGlob(%q) = %v, want nil — an elided class must not splice an encoded separator into existence", p, err)
	}
}
