// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// TestAppendJSONString_MatchesJSONMarshal pins the fast path in appendJSONString to
// the encoder it stands in for. It is what makes the writer's splice and the
// verifier's canonical-form check agree by construction: both spell a MAC through
// this helper, so any string it encodes differently from encoding/json would make
// genuine records fail their own verification.
func TestAppendJSONString_MatchesJSONMarshal(t *testing.T) {
	t.Parallel()
	tests := []string{
		"",
		"sha256:0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0",
		"sha256:genesis",
		`has "quotes"`,
		`has \backslash`,
		"has <angle> brackets",
		"has & ampersand",
		"has\ttab",
		"has\nnewline",
		"has\x00nul",
		"has\x7fdel",
		"has\u2028line separator",
		"has\u2029paragraph separator",
		"hás nön-ASCII",
		"\xff\xfe invalid utf-8",
		"all printable: !#$%'()*+,-./0123456789:;=?@[]^_`{|}~",
	}
	for _, s := range tests {
		t.Run(strings.ToValidUTF8(s, "?"), func(t *testing.T) {
			t.Parallel()
			want, err := json.Marshal(s)
			if err != nil {
				t.Fatalf("json.Marshal(%q): %v", s, err)
			}
			got, err := appendJSONString(nil, s)
			if err != nil {
				t.Fatalf("appendJSONString(%q): %v", s, err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("appendJSONString(%q) = %s, want %s (plain=%v)", s, got, want, isPlainJSONString(s))
			}
		})
	}
}

// TestIsPlainJSONString_NeverOverclaims sweeps every byte value: whenever the
// predicate says a string needs no escaping, encoding/json must in fact encode it as
// its own bytes in quotes. A false positive here would have isCanonicalSignedLine
// compare against a spelling the writer never emits, so the direction that matters
// is checked exhaustively rather than by example.
func TestIsPlainJSONString_NeverOverclaims(t *testing.T) {
	t.Parallel()
	for c := 0; c < 256; c++ {
		s := "sha256:" + string([]byte{byte(c)}) + "ab"
		if !isPlainJSONString(s) {
			continue
		}
		want, err := json.Marshal(s)
		if err != nil {
			t.Fatalf("json.Marshal(byte %d): %v", c, err)
		}
		if string(want) != `"`+s+`"` {
			t.Errorf("isPlainJSONString says byte %d needs no escaping, but json.Marshal produced %s", c, want)
		}
	}
}

// TestAppendRecordMAC_MatchesGoldenDigest pins the MAC's on-disk spelling. It is a
// signed value: a change to the algorithm, prefix, or hex encoding would make every
// record already on disk verify as tampered, so the digest is checked against an
// independently computed one rather than against the helper itself.
func TestAppendRecordMAC_MatchesGoldenDigest(t *testing.T) {
	t.Parallel()
	key := nonZeroTestKey()
	body := []byte(`{"class_uid":6003,"decision":"allow"}`)
	want := "sha256:" + hmacHex(key, body)

	if got := recordMAC(key, body); got != want {
		t.Errorf("recordMAC = %q, want %q", got, want)
	}
	if got := string(appendRecordMAC(nil, key, body)); got != want {
		t.Errorf("appendRecordMAC(nil) = %q, want %q", got, want)
	}
	// Appending onto an existing buffer must leave that buffer's contents alone —
	// the property signedRecordLine's splice depends on.
	if got := string(appendRecordMAC([]byte("prefix:"), key, body)); got != "prefix:"+want {
		t.Errorf("appendRecordMAC(dst) = %q, want %q", got, "prefix:"+want)
	}
	// Refilling one buffer across keys is how the verifier's per-key loop avoids an
	// allocation per key; a stale suffix left behind by a shorter digest would make a
	// later key's comparison read bytes from an earlier one.
	buf := appendRecordMAC(nil, key, body)
	other := append([]byte(nil), key...)
	other[0] ^= 0xff
	buf = appendRecordMAC(buf[:0], other, body)
	if string(buf) == want {
		t.Error("refilled buffer still holds the first key's digest")
	}
	if got := string(appendRecordMAC(buf[:0], key, body)); got != want {
		t.Errorf("refilled buffer = %q, want %q", got, want)
	}
}

// TestIsCanonicalSignedLine_AgreesWithSignedRecordLine pins the two halves of the
// single on-disk-form definition to each other: the verifier must accept exactly the
// bytes the writer emits, for a MAC needing escaping as much as for the "sha256:"
// hex one every genuine record carries. The escaped case is the one the fast path
// declines, so it is what proves the fallback still lines up with the writer.
func TestIsCanonicalSignedLine_AgreesWithSignedRecordLine(t *testing.T) {
	t.Parallel()
	body := []byte(`{"class_uid":6003,"seq":1,"decision":"allow"}`)

	macs := map[string]string{
		"plain hex digest":     "sha256:" + strings.Repeat("ab", 32),
		"genesis sentinel":     auditGenesisPrev,
		"needs escaping":       "sha256:\"quoted\"\\and\ttabbed",
		"html-escaped bytes":   "sha256:<tag>&more",
		"non-ASCII":            "sha256:ünïcödé",
		"line separator U2028": "sha256:\u2028split",
	}
	for name, mac := range macs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			line, err := signedRecordLine(append([]byte(nil), body...), mac)
			if err != nil {
				t.Fatalf("signedRecordLine: %v", err)
			}
			ok, err := isCanonicalSignedLine(line, body, mac)
			if err != nil {
				t.Fatalf("isCanonicalSignedLine: %v", err)
			}
			if !ok {
				t.Fatalf("the writer's own line was rejected as non-canonical: %s", line)
			}
			// A record whose _hmac decodes to the same string but is spelled another
			// way is exactly what the check exists to reject, so the encodings must not
			// be interchangeable.
			if isPlainJSONString(mac) {
				escaped, mErr := json.Marshal(mac)
				if mErr != nil {
					t.Fatalf("json.Marshal: %v", mErr)
				}
				alt := append(append([]byte(nil), line[:len(line)-len(escaped)-1]...),
					append([]byte(`"\u0073`+mac[1:]+`"`), '}')...)
				if ok, _ := isCanonicalSignedLine(alt, body, mac); ok {
					t.Errorf("an alternate escaping of the mac was accepted: %s", alt)
				}
			}
		})
	}
}

// TestIsCanonicalSignedLine_RejectsNearMisses covers the byte-level edges of the
// in-place comparison that replaced materializing the expected line: a truncated
// tail, a missing brace, extra bytes after it, and a body that is not an object.
func TestIsCanonicalSignedLine_RejectsNearMisses(t *testing.T) {
	t.Parallel()
	body := []byte(`{"class_uid":6003,"seq":1,"decision":"allow"}`)
	mac := "sha256:" + strings.Repeat("ab", 32)
	line, err := signedRecordLine(append([]byte(nil), body...), mac)
	if err != nil {
		t.Fatalf("signedRecordLine: %v", err)
	}

	tests := map[string][]byte{
		"truncated before the mac field": line[:len(body)],
		"truncated inside the mac":       line[:len(line)-8],
		"missing closing brace":          line[:len(line)-1],
		"extra trailing byte":            append(append([]byte(nil), line...), 'x'),
		"body prefix altered":            bytes.Replace(line, []byte(`"allow"`), []byte(`"deNy!"`), 1),
		"mac field renamed":              bytes.Replace(line, []byte(`"_hmac"`), []byte(`"_HMAC"`), 1),
		"whitespace before the mac":      bytes.Replace(line, []byte(`,"_hmac"`), []byte(`, "_hmac"`), 1),
		"empty line":                     {},
	}
	for name, tampered := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ok, err := isCanonicalSignedLine(tampered, body, mac)
			if err != nil {
				t.Fatalf("isCanonicalSignedLine: %v", err)
			}
			if ok {
				t.Errorf("accepted a non-canonical line: %s", tampered)
			}
		})
	}

	// A body that is not a JSON object is the writer-side guard's mirror: it is
	// unreachable from a struct marshal, and it must error rather than report a
	// verdict on bytes that cannot be spliced.
	if _, err := isCanonicalSignedLine(line, []byte(`"not an object"`), mac); err == nil {
		t.Error("isCanonicalSignedLine accepted a non-object body")
	}
}
