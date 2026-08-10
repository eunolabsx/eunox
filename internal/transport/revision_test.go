// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// TestResolveHostRevision covers the whole negotiation rule in one table, including the two
// cases that carry the load: an UNDECLARED revision must inherit the context (and, with no
// context, the older revision), so nothing reaches a different method table by omission; and
// a declaration DISAGREEING with the context is a refusal, not a re-negotiation.
func TestResolveHostRevision(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		method     string // "" = tools/call, whose params reach the upstream
		contextRev capability.Revision
		legRev     capability.Revision // "" = no upstream leg established, so nothing to disagree with
		declared   any                 // nil = no `_meta` block at all
		rawParams  string              // a params body written out verbatim, for shapes `declared` cannot express
		want       capability.Revision
		wantErr    error
	}{
		{name: "undeclared, unnegotiated context falls back to the old revision", want: capability.Revision20251125},
		{name: "undeclared inherits the negotiated context", contextRev: capability.Revision20251125, want: capability.Revision20251125},
		{name: "undeclared inherits a new-revision context", contextRev: capability.Revision20260728, want: capability.Revision20260728},
		{name: "declared, no context", declared: "2026-07-28", want: capability.Revision20260728},
		{name: "declared agreeing with the context", contextRev: capability.Revision20260728, declared: "2026-07-28", want: capability.Revision20260728},
		{name: "declared disagreeing with the context", contextRev: capability.Revision20251125, declared: "2026-07-28", wantErr: errRevisionMismatch},
		{name: "declared disagreeing the other way", contextRev: capability.Revision20260728, declared: "2025-11-25", wantErr: errRevisionMismatch},
		{name: "unknown revision", declared: "1999-01-01", wantErr: mcp.ErrUnknownRevision},
		{name: "unknown revision inside a context", contextRev: capability.Revision20251125, declared: "2030-01-01", wantErr: mcp.ErrUnknownRevision},
		{name: "non-string revision", declared: 20260728, wantErr: mcp.ErrUnknownRevision},
		// declared is `any`, and nil means "no _meta block at all" in this table — an explicit
		// JSON null needs its own case, since it takes a different path through the decoder.
		{name: "explicit null revision inherits the context", rawParams: `{"_meta":{"io.modelcontextprotocol/protocolVersion":null}}`, contextRev: capability.Revision20260728, want: capability.Revision20260728},
		{name: "explicit null revision with no context", rawParams: `{"_meta":{"io.modelcontextprotocol/protocolVersion":null}}`, want: capability.Revision20251125},
		// The upstream leg. What a forwarded request must not contradict is the revision this
		// proxy ADDRESSES its upstream as, which is the revision the leg was OPENED at — the
		// operator's pin, or the handshake revision under `auto`.
		{name: "resolving to the addressed revision", contextRev: capability.Revision20251125, legRev: capability.Revision20251125, declared: "2025-11-25", want: capability.Revision20251125},
		{name: "resolving past the addressed revision", contextRev: capability.Revision20260728, legRev: capability.Revision20251125, declared: "2026-07-28", wantErr: errUnhonorableUpstreamRevision},
		// A MATCHED pair on a pinned leg: the host declares what the leg speaks, so the body
		// and the header eunox stamps name one revision and the request is forwardable. This is
		// what the pin bought — before the opener was revision-selected, every leg was addressed
		// as the handshake revision and this exact pair was refused.
		{name: "matched pair on a pinned leg", contextRev: capability.Revision20260728, legRev: capability.Revision20260728, declared: "2026-07-28", want: capability.Revision20260728},
		// And the mismatched pair in the other direction: an old host in front of a pinned new
		// upstream is refused rather than served into a conversation held at another revision.
		{name: "old host against a pinned new leg", contextRev: capability.Revision20251125, legRev: capability.Revision20260728, declared: "2025-11-25", wantErr: errUnhonorableUpstreamRevision},
		// INHERITED, not declared: a peer pins the newer revision by declaring once on a method
		// that forwards nothing, then omits the declaration forever after. Checking the
		// declaration alone let exactly that request through.
		{name: "inheriting a revision the leg is not addressed as", contextRev: capability.Revision20260728, legRev: capability.Revision20251125, wantErr: errUnhonorableUpstreamRevision},
		// A method answered without contacting the upstream carries its revision nowhere, so
		// the leg has nothing to be contradicted by and the message resolves normally.
		{name: "declared on a locally answered method", method: methodPing, contextRev: capability.Revision20260728, legRev: capability.Revision20251125, declared: "2026-07-28", want: capability.Revision20260728},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			method := tc.method
			if method == "" {
				method = capability.MethodToolsCall
			}
			msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: method}
			switch {
			case tc.rawParams != "":
				msg.Params = json.RawMessage(tc.rawParams)
			case tc.declared != nil:
				msg.Params = metaParams(t, tc.declared, map[string]any{"name": "read_file"})
			}
			got, err := resolveHostRevision(tc.contextRev, tc.legRev, msg)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("error = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("revision = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestResolveHostRevision_MalformedParamsAreNotAVersionFailure: a params body that cannot be
// decoded must NOT be relabeled as a version problem. The method handler decodes the same
// bytes moments later and denies them as INVALID_REQUEST with a target-bearing record; a
// -32022 here would replace that with a misleading refusal for every malformed request.
func TestResolveHostRevision_MalformedParamsAreNotAVersionFailure(t *testing.T) {
	t.Parallel()
	for _, params := range []string{
		`{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"},"_meta":{}}`, // duplicate key
		`{"_meta":"io.modelcontextprotocol/protocolVersion"}`,                           // key name as a value
		`{"_meta":[{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}]}`,          // wrong shape
	} {
		msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsCall, Params: json.RawMessage(params)}
		got, err := resolveHostRevision(capability.Revision20251125, "", msg)
		if err != nil {
			t.Errorf("params %s: got version error %v, want the request to fall through to its handler", params, err)
		}
		if got != capability.Revision20251125 {
			t.Errorf("params %s: revision = %q, want the context's %q", params, got, capability.Revision20251125)
		}
	}
}

// TestRefuseHostRevision_EmitsSpecCodeAndRecords: the refusal is -32022 on the wire and an
// UNSUPPORTED_PROTOCOL_VERSION record on the tape, together. A refusal the tape does not
// carry is exactly the blind spot the notification-framing guards exist to close.
func TestRefuseHostRevision_EmitsSpecCodeAndRecords(t *testing.T) {
	t.Parallel()
	rec := &fwdRecorder{}
	msg := requestWithRevision(t, "abc", capability.MethodToolsCall, "1999-01-01")
	_, err := resolveHostRevision("", "", msg)
	if err == nil {
		t.Fatal("an unknown declared revision must not resolve")
	}
	resp := refuseHostRevision(context.Background(), rec, "sess-1", "", msg, err)
	if resp.Error == nil || resp.Error.Code != capability.JSONRPCCodeUnsupportedProtocolVersion {
		t.Fatalf("response error = %+v, want code %d", resp.Error, capability.JSONRPCCodeUnsupportedProtocolVersion)
	}
	if mcp.MsgKey(resp.ID) != mcp.MsgKey(msg.ID) {
		t.Errorf("refusal id = %v, want it to echo the request's", resp.ID)
	}
	// The peer needs to know what to retry with, so the data payload names the set.
	var data struct {
		Code      string   `json:"code"`
		Supported []string `json:"supported"`
	}
	if err := json.Unmarshal(resp.Error.Data, &data); err != nil {
		t.Fatalf("error.data is not decodable: %v", err)
	}
	if data.Code != capability.ErrCodeUnsupportedProtocolVersion || len(data.Supported) != len(capability.PublishedRevisions()) {
		t.Errorf("error.data = %+v, want the symbolic code and every published revision", data)
	}
	if len(rec.records) != 1 || rec.records[0].decision != "deny" || rec.records[0].code != capability.ErrCodeUnsupportedProtocolVersion {
		t.Fatalf("records = %+v, want one UNSUPPORTED_PROTOCOL_VERSION deny", rec.records)
	}
}

// TestRefuseHostRevision_NotificationGetsNoReply: JSON-RPC forbids replying to a
// notification, so the refusal is recorded and nothing is written back — a response stamped
// with a null id would read as a reply to a different request.
func TestRefuseHostRevision_NotificationGetsNoReply(t *testing.T) {
	t.Parallel()
	rec := &fwdRecorder{}
	notif := mcp.RPCMsg{JSONRPC: "2.0", Method: methodNotificationsProgress, Params: metaParams(t, "1999-01-01", nil)}
	_, err := resolveHostRevision("", "", notif)
	if err == nil {
		t.Fatal("an unknown declared revision must not resolve")
	}
	resp := refuseHostRevision(context.Background(), rec, "sess-1", "", notif, err)
	if resp.Error != nil || resp.ID != nil || resp.JSONRPC != "" {
		t.Errorf("a notification refusal must produce no reply, got %+v", resp)
	}
	if len(rec.records) != 1 {
		t.Fatalf("records = %+v, want the refusal recorded even though nothing is replied", rec.records)
	}
}

// TestUpstreamOpenRevision pins the upstream-side rule the pin became: the operator's pin
// selects the revision the leg is OPENED at, and no pin opens with the handshake — the surface
// every release before the pin existed presented.
func TestUpstreamOpenRevision(t *testing.T) {
	t.Parallel()
	cases := []struct {
		pin  capability.Revision
		want capability.Revision
	}{
		{pin: "", want: handshakeRevision},
		{pin: capability.Revision20251125, want: capability.Revision20251125},
		{pin: capability.Revision20260728, want: capability.Revision20260728},
	}
	for _, tc := range cases {
		if got := UpstreamOpenRevision(tc.pin); got != tc.want {
			t.Errorf("UpstreamOpenRevision(%q) = %q, want %q", tc.pin, got, tc.want)
		}
	}
}

// TestCheckNegotiatedRevision pins the inversion: a handshake's answer is CHECKED against the
// revision the leg was opened at rather than allowed to set it.
//
// The two refusals are the ones the silent downgrade used to hide. A version this build cannot
// speak resolved to the default, so eunox stamped every later request with a header naming a
// negotiation that never happened; a speakable version that is not the one offered produced a
// leg that looked negotiated while eunox spoke a revision over a method that revision removed.
func TestCheckNegotiatedRevision(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		opened   capability.Revision
		reported string
		wantErr  string
	}{
		{name: "agrees", opened: capability.Revision20251125, reported: "2025-11-25"},
		{name: "unspeakable is refused, not downgraded", opened: capability.Revision20251125, reported: "1999-01-01", wantErr: "does not speak"},
		{name: "empty is refused", opened: capability.Revision20251125, reported: "", wantErr: "does not speak"},
		{name: "speakable but not the one offered", opened: capability.Revision20251125, reported: "2026-07-28", wantErr: "opened at"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := checkNegotiatedRevision(tc.opened, tc.reported)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("checkNegotiatedRevision(%q, %q) = %v, want nil", tc.opened, tc.reported, err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("checkNegotiatedRevision(%q, %q) = nil, want an error mentioning %q", tc.opened, tc.reported, tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Errorf("error = %q, want it to mention %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// TestCheckNegotiatedRevision_BoundsTheReflectedVersion: the refusal echoes an
// upstream-controlled string to an operator's console, so it must be bounded and stripped of
// anything a terminal would act on — the same rule the host-side -32022 applies to a peer's.
func TestCheckNegotiatedRevision_BoundsTheReflectedVersion(t *testing.T) {
	t.Parallel()
	hostile := "\x1b]0;pwned\x07" + strings.Repeat("A", 8192)
	err := checkNegotiatedRevision(handshakeRevision, hostile)
	if err == nil {
		t.Fatal("a version this build cannot speak must be refused")
	}
	if strings.ContainsAny(err.Error(), "\x1b\x07") {
		t.Error("the refusal reflected control characters from the upstream's version string")
	}
	if len(err.Error()) > 4096 {
		t.Errorf("refusal is %d bytes; an upstream must not be able to size this diagnostic", len(err.Error()))
	}
}

// TestUpstreamDeclaration_NeverContradictsTheHeaderEunoxStamps is the property the
// upstream-leg check exists for, asserted against the header PRODUCER rather than against a
// second copy of what it emits.
//
// Params are forwarded verbatim, so a host's `_meta` declaration reaches the upstream beside
// eunox's own MCP-Protocol-Version. Every combination of declared revision and leg revision
// this build can produce is driven through the gate, and any pair it ADMITS must be one whose
// body and header name the same revision — otherwise the proxy is manufacturing exactly the
// mismatch its host leg refuses, and a first-wins and a last-wins upstream resolve the same
// request under different method sets.
func TestUpstreamDeclaration_NeverContradictsTheHeaderEunoxStamps(t *testing.T) {
	t.Parallel()
	admitted := 0
	for _, declared := range capability.PublishedRevisions() {
		for _, legRev := range capability.PublishedRevisions() {
			t.Run(fmt.Sprintf("declared=%s/leg=%s", declared, legRev), func(t *testing.T) {
				msg := mcp.RPCMsg{
					JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsCall,
					Params: json.RawMessage(fmt.Sprintf(
						`{"name":"read_file","_meta":{"io.modelcontextprotocol/protocolVersion":%q}}`, declared)),
				}
				if _, err := resolveHostRevision(declared, legRev, msg); err != nil {
					return // refused: nothing is forwarded, so no pair is manufactured
				}
				admitted++
				// Admitted, so these bytes reach the upstream. Read the header off the real
				// producer: a hand-written expectation here would keep passing the day
				// setNegotiatedVersionHeader changes what it stamps.
				req := httptest.NewRequest(http.MethodPost, "http://upstream.invalid/mcp", http.NoBody)
				setNegotiatedVersionHeader(req, legRev)
				if got := req.Header.Get("MCP-Protocol-Version"); got != declared.String() {
					t.Errorf("a forwarded body declaring %s would carry MCP-Protocol-Version: %s — the gate admitted a pair that names two revisions", declared, got)
				}
			})
		}
	}
	// Not vacuous: a gate that refused every declaration would satisfy the loop above while
	// making the whole declaration surface unusable.
	if admitted == 0 {
		t.Error("no declaration was admitted on any leg; the property held only because nothing is ever forwarded")
	}
}
