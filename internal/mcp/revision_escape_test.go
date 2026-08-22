// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
)

// TestDeclaredRevision_EscapedKeyIsStillADeclaration is the regression for the probe that
// compared raw bytes against the unescaped key.
//
// JSON lets a peer escape any character of an object key, so `io.modelcontextprotocol\/…`
// and an escaped `_meta` decode to exactly the keys eunox looks for while missing a
// byte-substring scan. That made a declaration invisible to enforcement but visible to the
// upstream reading the same forwarded bytes — the parser differential the duplicate-key
// rejection exists to close, reintroduced by the fast path sitting in front of it.
func TestDeclaredRevision_EscapedKeyIsStillADeclaration(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		params string
	}{
		{name: "plain", params: `{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}`},
		{name: "escaped solidus in the key", params: `{"name":"x","_meta":{"io.modelcontextprotocol\/protocolVersion":"2026-07-28"}}`},
		{name: "unicode-escaped character in the key", params: `{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}`},
		{name: "unicode-escaped _meta", params: `{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rev, declared, err := DeclaredRevision(json.RawMessage(tc.params))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !declared || rev != capability.Revision20260728 {
				t.Errorf("rev=%q declared=%v; want 2026-07-28, true — an escaped spelling must not hide a declaration", rev, declared)
			}
		})
	}
	// The same holds for a revision that must be REFUSED: an escaped key must not be a way to
	// have an unspeakable declaration read as an absence and fall through to another table.
	_, declared, err := DeclaredRevision(json.RawMessage(`{"_meta":{"io.modelcontextprotocol\/protocolVersion":"1999-01-01"}}`))
	if !declared || !errors.Is(err, ErrUnknownRevision) {
		t.Errorf("declared=%v err=%v; want an ErrUnknownRevision refusal", declared, err)
	}
}

// TestDeclaredRevision_BoundsReflectedText: the rejected version string is arbitrary caller
// text — it reaches the error precisely by FAILING the closed-set match — so the refusal must
// truncate it and strip anything a terminal would interpret, rather than reflecting a frame's
// worth of attacker bytes back.
func TestDeclaredRevision_BoundsReflectedText(t *testing.T) {
	t.Parallel()
	huge := strings.Repeat("A", 4096)
	_, _, err := DeclaredRevision(json.RawMessage(`{"_meta":{"io.modelcontextprotocol/protocolVersion":"` + huge + `"}}`))
	if err == nil {
		t.Fatal("an unspeakable revision must be refused")
	}
	resp := RevisionRefusalResponse(RawJSON(`1`), capability.ErrCodeUnsupportedProtocolVersion, err.Error())
	if len(resp.Error.Message) > 256 {
		t.Errorf("refusal message is %d bytes; the caller's own string must be truncated, not reflected whole", len(resp.Error.Message))
	}

	// A real revision date must survive the bound untouched, so the message stays useful.
	_, _, dateErr := DeclaredRevision(json.RawMessage(`{"_meta":{"io.modelcontextprotocol/protocolVersion":"2099-01-01"}}`))
	if dateErr == nil || !strings.Contains(dateErr.Error(), "2099-01-01") {
		t.Errorf("error = %v, want it to name the rejected revision verbatim", dateErr)
	}

	// The escape is written in its JSON form: a raw control byte inside a string is invalid
	// JSON, so the decoder would reject the body before the value is ever looked at.
	_, _, ctrlErr := DeclaredRevision(json.RawMessage(`{"_meta":{"io.modelcontextprotocol/protocolVersion":"\u001b[31mred"}}`))
	if ctrlErr == nil {
		t.Fatal("an unspeakable revision must be refused")
	}
	if strings.ContainsRune(ctrlErr.Error(), 0x1b) {
		t.Errorf("refusal reflected a control character back to the peer: %q", ctrlErr.Error())
	}
}
