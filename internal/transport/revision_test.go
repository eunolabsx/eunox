// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
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
		contextRev capability.Revision
		declared   any // nil = no `_meta` block at all
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
		{name: "null revision", declared: nil, want: capability.Revision20251125},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsCall}
			if tc.declared != nil {
				msg.Params = metaParams(t, tc.declared, map[string]any{"name": "read_file"})
			}
			got, err := resolveHostRevision(tc.contextRev, msg)
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
		got, err := resolveHostRevision(capability.Revision20251125, msg)
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
	_, err := resolveHostRevision("", msg)
	if err == nil {
		t.Fatal("an unknown declared revision must not resolve")
	}
	resp := refuseHostRevision(context.Background(), rec, "sess-1", msg, err)
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
	_, err := resolveHostRevision("", notif)
	if err == nil {
		t.Fatal("an unknown declared revision must not resolve")
	}
	resp := refuseHostRevision(context.Background(), rec, "sess-1", notif, err)
	if resp.Error != nil || resp.ID != nil || resp.JSONRPC != "" {
		t.Errorf("a notification refusal must produce no reply, got %+v", resp)
	}
	if len(rec.records) != 1 {
		t.Fatalf("records = %+v, want the refusal recorded even though nothing is replied", rec.records)
	}
}

// TestResolveUpstreamRevision pins the upstream-side rule: an operator pin wins outright,
// otherwise the upstream's own reported version, and a version this build cannot speak falls
// back to the default rather than pinning something nobody named.
func TestResolveUpstreamRevision(t *testing.T) {
	t.Parallel()
	cases := []struct {
		configured capability.Revision
		reported   string
		want       capability.Revision
	}{
		{configured: "", reported: "2025-11-25", want: capability.Revision20251125},
		{configured: "", reported: "2026-07-28", want: capability.Revision20260728},
		{configured: "", reported: "1999-01-01", want: capability.DefaultRevision},
		{configured: "", reported: "", want: capability.DefaultRevision},
		{configured: capability.Revision20260728, reported: "2025-11-25", want: capability.Revision20260728},
		{configured: capability.Revision20251125, reported: "2026-07-28", want: capability.Revision20251125},
	}
	for _, tc := range cases {
		if got := resolveUpstreamRevision(tc.configured, tc.reported); got != tc.want {
			t.Errorf("resolveUpstreamRevision(%q, %q) = %q, want %q", tc.configured, tc.reported, got, tc.want)
		}
	}
}

// TestDispatchRequest_PerRevisionUnmappedDenials is the fail-closed sweep across the seam:
// a method outside the requesting peer's table hits dispatchUnmapped exactly as an unknown
// method does, with the AUTHORIZATION_FAILED record that path already writes. Removal is
// expressed by absence — there is no second mechanism to assert.
func TestDispatchRequest_PerRevisionUnmappedDenials(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		rev      capability.Revision
		method   string
		wantDeny bool
	}{
		{name: "ping is answered for an old-revision peer", rev: capability.Revision20251125, method: methodPing},
		{name: "ping is denied for a new-revision peer", rev: capability.Revision20260728, method: methodPing, wantDeny: true},
		{name: "initialize is answered for an old-revision peer", rev: capability.Revision20251125, method: mcp.MethodInitialize},
		{name: "initialize is denied for a new-revision peer", rev: capability.Revision20260728, method: mcp.MethodInitialize, wantDeny: true},
		{name: "server/discover is denied for an old-revision peer", rev: capability.Revision20251125, method: "server/discover", wantDeny: true},
		{name: "server/discover is denied until its own workstream lands", rev: capability.Revision20260728, method: "server/discover", wantDeny: true},
		{name: "resources/subscribe is denied for a new-revision peer", rev: capability.Revision20260728, method: capability.MethodResourcesSubscribe, wantDeny: true},
		{name: "resources/unsubscribe is denied for a new-revision peer", rev: capability.Revision20260728, method: capability.MethodResourcesUnsubscribe, wantDeny: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := &fwdRecorder{}
			d := dispatchParams{
				forwardParams: forwardParams{rec: rec, errOut: io.Discard},
				pdp:           pdp.AlwaysAllowPDP{},
				revision:      tc.rev,
				buildInit: func(msg mcp.RPCMsg) mcp.RPCMsg {
					return mcp.RPCMsg{JSONRPC: "2.0", ID: msg.ID, Result: json.RawMessage(`{}`)}
				},
			}
			out := dispatchRequest(context.Background(), d, mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: tc.method})
			if !tc.wantDeny {
				if out.Error != nil {
					t.Fatalf("%s under %s must be answered, got error %+v", tc.method, tc.rev, out.Error)
				}
				return
			}
			if out.Error == nil {
				t.Fatalf("%s under %s must be denied, got result %s", tc.method, tc.rev, out.Result)
			}
			if len(rec.records) != 1 || rec.records[0].code != capability.ErrCodeAuthorizationFailed {
				t.Fatalf("records = %+v, want one AUTHORIZATION_FAILED deny", rec.records)
			}
		})
	}
}

// TestNotificationTables_PerRevision: roots/list_changed is forwardable to an old-revision
// upstream and dropped-plus-recorded for a new-revision peer (the capability is deprecated
// there), while notifications/initialized stops being a swallowed construct and becomes an
// ordinary unmapped notification — the revision has no handshake to close.
func TestNotificationTables_PerRevision(t *testing.T) {
	t.Parallel()
	cases := []struct {
		rev        capability.Revision
		method     string
		wantDenied bool
	}{
		{rev: capability.Revision20251125, method: methodNotificationsRootsListChanged, wantDenied: false},
		{rev: capability.Revision20260728, method: methodNotificationsRootsListChanged, wantDenied: true},
		{rev: capability.Revision20251125, method: methodNotificationsCancelled, wantDenied: false},
		{rev: capability.Revision20260728, method: methodNotificationsCancelled, wantDenied: false},
		{rev: capability.Revision20260728, method: mcp.MethodNotificationsInitialized, wantDenied: true},
	}
	for _, tc := range cases {
		rec := &fwdRecorder{}
		msg := mcp.RPCMsg{JSONRPC: "2.0", Method: tc.method}
		denied := denyUnmappedHostNotification(context.Background(), io.Discard, rec, "sess", tc.rev, msg)
		if denied != tc.wantDenied {
			t.Errorf("%s under %s: denied = %v, want %v", tc.method, tc.rev, denied, tc.wantDenied)
		}
		if tc.wantDenied && (len(rec.records) != 1 || rec.records[0].code != capability.ErrCodeAuthorizationFailed) {
			t.Errorf("%s under %s: records = %+v, want the drop recorded", tc.method, tc.rev, rec.records)
		}
	}
	// The swallowed set is the one disposition that writes NO record, so it is asserted
	// separately: silently dropping a method the revision does not have would hide it.
	if !isSwallowedHostNotification(capability.Revision20251125, mcp.MethodNotificationsInitialized) {
		t.Error("notifications/initialized must stay swallowed for an old-revision peer")
	}
	if isSwallowedHostNotification(capability.Revision20260728, mcp.MethodNotificationsInitialized) {
		t.Error("notifications/initialized must not be silently swallowed for a new-revision peer: the revision has no handshake, so it is an unmapped notification and must be recorded")
	}
}
