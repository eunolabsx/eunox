// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// TruncateUTF8 normalizes s to valid UTF-8 (replacing any invalid byte sequence with
// U+FFFD) and cuts it to at most limit bytes without splitting a rune. A non-positive
// limit truncates to "". The result carries no visible truncation marker; a caller
// that needs one uses BoundString.
//
// Shared home for internal/audit (envelope/session-ID fields, and a caller outside
// that package — internal/transport's sanitizeClaimedID) and pkg/enforcement's
// denial-details bound: all three make caller/attacker-controlled bytes safe for the
// HMAC-signed audit tape and must not re-derive this exact normalize-then-rune-safe-cut
// logic, since a divergence between copies (differing rune-boundary handling, or a
// missed normalize step) is exactly what would make a genuine, never-tampered record
// fail chain verification on one side and not the other. pkg/ cannot import internal/,
// so this is their common home rather than each depending on the other.
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

// runeBoundaryCut returns the largest n <= limit such that s[:n] does not split a
// UTF-8 rune, so a byte-length truncation never leaves an orphaned continuation byte
// that json.Marshal would silently rewrite to the replacement character. Walks back
// from limit to the nearest rune start (drops at most 3 bytes). Callers must have
// already normalized s to valid UTF-8 and must pass limit < len(s); it indexes s[limit]
// directly and panics on an out-of-range limit.
func runeBoundaryCut(s string, limit int) int {
	keep := limit
	for keep > 0 && !utf8.RuneStart(s[keep]) {
		keep--
	}
	return keep
}

// BoundString truncates s to at most limit bytes, appending a visible marker
// recording the original length when a cut is needed. The marker is kept WITHIN
// limit (the kept prefix shortens to make room), so the result never exceeds limit.
// s is first normalized to valid UTF-8 exactly as TruncateUTF8 does, for the same
// round-trip-idempotency reason.
//
// Shared by internal/audit's envelope-field bound (SessionID, Target, Method, the
// gateway route provenance fields) and pkg/enforcement's denial-Details bound: both
// need the identical marker text and rune-safe cut so a truncated value reads the
// same way regardless of which layer cut it.
func BoundString(s string, limit int) string {
	s = strings.ToValidUTF8(s, "�")
	if len(s) <= limit {
		return s
	}
	marker := fmt.Sprintf("...[eunox: truncated, %d bytes]", len(s))
	keep := limit - len(marker)
	if keep < 0 {
		// The full marker does not fit (a limit smaller than the marker). The result
		// must stay non-empty so it is not mistaken for a genuinely empty field, but
		// must not exceed limit, so emit the shortest recognizable "..." marker. Only
		// a non-positive limit yields "", which is a caller bug (every real cap is far
		// larger than this marker).
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
