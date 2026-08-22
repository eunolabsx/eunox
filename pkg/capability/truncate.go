// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// TruncateUTF8 normalizes s to valid UTF-8 (replacing any invalid byte sequence with
// U+FFFD) and cuts it to at most limit bytes without splitting a rune. A non-positive limit
// truncates to "". The result carries no visible truncation marker; a caller that needs one
// uses BoundString.
//
// Shared by internal/audit and pkg/enforcement's denial-details bound, both of which make
// caller/attacker-controlled bytes safe for the HMAC-signed audit tape — a divergence
// between two copies of this logic could make a genuine record fail chain verification on
// one side and not the other. pkg/ cannot import internal/, so this is their common home.
func TruncateUTF8(s string, limit int) string {
	s = strings.ToValidUTF8(s, "�")
	if limit <= 0 {
		return ""
	}
	if len(s) <= limit {
		return s
	}
	return s[:runeBoundaryCut(s, limit)]
}

// runeBoundaryCut returns the largest n <= limit such that s[:n] does not split a UTF-8
// rune, so a byte-length truncation never leaves an orphaned continuation byte that
// json.Marshal would silently rewrite to the replacement character. Callers must have
// already normalized s to valid UTF-8 and must pass limit < len(s); it indexes s[limit]
// directly and panics on an out-of-range limit.
func runeBoundaryCut(s string, limit int) int {
	keep := limit
	for keep > 0 && !utf8.RuneStart(s[keep]) {
		keep--
	}
	return keep
}

// BoundString truncates s to at most limit bytes, appending a visible marker recording the
// original length when a cut is needed. The marker is kept WITHIN limit (the kept prefix
// shortens to make room), so the result never exceeds limit. s is first normalized to valid
// UTF-8 exactly as TruncateUTF8 does.
//
// Shared by internal/audit's envelope-field bound and pkg/enforcement's denial-Details
// bound, so a truncated value reads the same way regardless of which layer cut it.
func BoundString(s string, limit int) string {
	s = strings.ToValidUTF8(s, "�")
	if len(s) <= limit {
		return s
	}
	marker := fmt.Sprintf("...[eunox: truncated, %d bytes]", len(s))
	keep := limit - len(marker)
	if keep < 0 {
		// The full marker does not fit. The result must stay non-empty (so it isn't
		// mistaken for a genuinely empty field) but not exceed limit, so emit the
		// shortest recognizable "..." marker instead.
		const shortMarker = "..."
		if limit <= 0 {
			return ""
		}
		if limit < len(shortMarker) {
			return shortMarker[:limit]
		}
		return shortMarker
	}
	return s[:runeBoundaryCut(s, keep)] + marker
}

// SanitizeControlRunes replaces every control and line-terminating rune in s with a space,
// leaving the rest of the text (including non-ASCII) intact. Invalid UTF-8 is normalized to
// U+FFFD first, so the walk sees runes rather than raw bytes.
//
// It exists because a string that reaches a terminal or a line-oriented reader is not made safe
// by being length-bounded alone: an ESC-bearing value drives the operator's console (cursor
// moves, colour, title rewrites, and on some emulators worse), and a value carrying a newline
// injects a whole spurious line into a diagnostic a SIEM parses one line at a time. Both are
// reachable from strings eunox does not author — a remote upstream's error body, a header, a
// tool name.
//
// unicode.IsControl covers only category Cc (the C0 and C1 controls), so it misses U+2028 (LINE
// SEPARATOR) and U+2029 (PARAGRAPH SEPARATOR) — line terminators plenty of parsers, terminals
// and log splitters honour. Those are mapped too, or a raw U+2028 injects the very line this
// exists to prevent.
//
// Mapped to a space rather than dropped: removing the rune silently joins the tokens either
// side of it, which changes what a reader sees the value SAY, where a space preserves the
// break. Bounding is a separate question — compose with TruncateUTF8 or BoundString.
func SanitizeControlRunes(s string) string {
	s = strings.ToValidUTF8(s, "\ufffd")
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return ' '
		}
		return r
	}, s)
}
