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

func TestDeclaredRevision(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		params       string
		wantRev      capability.Revision
		wantDeclared bool
		wantErr      error
	}{
		{name: "no params"},
		{name: "no _meta", params: `{"name":"read_file"}`},
		{name: "_meta without the version key", params: `{"_meta":{"io.eunolabs.context-manifest":{}}}`},
		{
			name:         "current revision",
			params:       `{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}`,
			wantRev:      capability.Revision20260728,
			wantDeclared: true,
		},
		{
			name:         "older revision",
			params:       `{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-11-25"}}`,
			wantRev:      capability.Revision20251125,
			wantDeclared: true,
		},
		{
			name:         "unknown revision",
			params:       `{"_meta":{"io.modelcontextprotocol/protocolVersion":"2099-01-01"}}`,
			wantDeclared: true,
			wantErr:      ErrUnknownRevision,
		},
		{
			name:         "empty revision",
			params:       `{"_meta":{"io.modelcontextprotocol/protocolVersion":""}}`,
			wantDeclared: true,
			wantErr:      ErrUnknownRevision,
		},
		{
			// A non-string declaration is a refusal rather than "absent": reading it as absent
			// would make a wrong type a way to fall back onto the context's revision while
			// still looking like a declaration to whatever else parses the same bytes.
			name:         "non-string revision",
			params:       `{"_meta":{"io.modelcontextprotocol/protocolVersion":20260728}}`,
			wantDeclared: true,
			wantErr:      ErrUnknownRevision,
		},
		{
			// An explicit null is the JSON spelling of "no value", and a client SDK that always
			// emits the `_meta` slot with an unset optional field sends exactly this. Refusing
			// it would lock out a conforming host over a serialization detail; reading it as
			// absent grants nothing, since an undeclared request inherits its context.
			name:   "null revision reads as absent",
			params: `{"_meta":{"io.modelcontextprotocol/protocolVersion":null}}`,
		},
		{
			// Duplicate keys are rejected by DecodeParams, which leaves this build with no
			// answer at all rather than with "nothing declared" — the two readings a caller
			// must keep apart, since the peer reading the same forwarded bytes has an answer.
			name:    "duplicate version key is undecodable, not absent",
			params:  `{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/protocolVersion":"2025-11-25"}}`,
			wantErr: ErrUndecodableDeclaration,
		},
		{
			// The smuggling shape: the duplicate is a THROWAWAY key that has nothing to do with
			// the version, so nothing about the declaration itself looks malformed — a last-wins
			// upstream reads 2026-07-28 out of bytes this decoder refuses whole.
			name:    "a throwaway duplicate key elsewhere in params is undecodable",
			params:  `{"progressToken":1,"x":1,"x":1,"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}`,
			wantErr: ErrUndecodableDeclaration,
		},
		{
			name:    "params that are not an object are undecodable",
			params:  `[1,2,3]`,
			wantErr: ErrUndecodableDeclaration,
		},
		{
			name:   "the key appearing as a string VALUE is not a declaration",
			params: `{"note":"io.modelcontextprotocol/protocolVersion"}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rev, declared, err := DeclaredRevision(json.RawMessage(tc.params))
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("error = %v, want %v", err, tc.wantErr)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if declared != tc.wantDeclared {
				t.Errorf("declared = %v, want %v", declared, tc.wantDeclared)
			}
			if rev != tc.wantRev {
				t.Errorf("revision = %q, want %q", rev, tc.wantRev)
			}
		})
	}
}

// TestUnsupportedProtocolVersionResponse pins the spec-assigned wire code and the retry
// affordance: a peer refused for its version needs to be told what this build does speak.
func TestUnsupportedProtocolVersionResponse(t *testing.T) {
	t.Parallel()
	resp := UnsupportedProtocolVersionResponse(RawJSON(`7`), "context negotiated 2025-11-25")
	if resp.Error == nil {
		t.Fatal("refusal carries no error object")
	}
	if resp.Error.Code != -32022 {
		t.Errorf("code = %d, want -32022 (the specification's assigned value, not one eunox chose)", resp.Error.Code)
	}
	if !strings.HasPrefix(resp.Error.Message, capability.ErrCodeUnsupportedProtocolVersion) {
		t.Errorf("message = %q, want it to lead with the symbolic code so it is greppable", resp.Error.Message)
	}
	var data struct {
		Code      string   `json:"code"`
		Supported []string `json:"supported"`
	}
	if err := json.Unmarshal(resp.Error.Data, &data); err != nil {
		t.Fatalf("error.data: %v", err)
	}
	want := capability.PublishedRevisions()
	if len(data.Supported) != len(want) {
		t.Fatalf("supported = %v, want every published revision %v", data.Supported, want)
	}
	for i, rev := range want {
		if data.Supported[i] != rev.String() {
			t.Errorf("supported[%d] = %q, want %q", i, data.Supported[i], rev)
		}
	}
}
