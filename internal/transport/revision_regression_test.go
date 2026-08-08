// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// TestUnmappedDenial_NamesNoPolicyTargetForARemovedMethod is the regression for the record
// shape revision-scoped removal newly made reachable.
//
// Until routing was revision-scoped, only methods with NO target type could reach the
// fail-closed default, so the record's target stayed empty. resources/subscribe can reach it
// now and DOES resolve a target type — recording the method as the identifier would stamp a
// resource literally named "resources/subscribe" onto the signed tape, and AUTHORIZATION_FAILED
// is a genuine policy code, so `eunox suggest` would mine a capability for it.
func TestUnmappedDenial_NamesNoPolicyTargetForARemovedMethod(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name           string
		method         string
		rev            capability.Revision
		wantIdentifier string
	}{
		{
			name: "a method the revision removed names no target", method: capability.MethodResourcesSubscribe,
			rev: capability.Revision20260728, wantIdentifier: "",
		},
		{
			// A genuinely unknown method resolves no target type either way, so the identifier
			// stays: it is the only place the method name survives for an operator.
			name: "an unknown method keeps naming itself", method: "agents/delegate",
			rev: capability.Revision20260728, wantIdentifier: "agents/delegate",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := &fwdRecorder{}
			d := dispatchParams{
				forwardParams: forwardParams{rec: rec, errOut: io.Discard},
				pdp:           pdp.AlwaysAllowPDP{},
			}
			dispatchUnmapped(revisionContext(tc.rev), d, mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: tc.method})
			if len(rec.records) != 1 {
				t.Fatalf("records = %+v, want exactly one", rec.records)
			}
			if rec.records[0].identifier != tc.wantIdentifier {
				t.Errorf("identifier = %q, want %q", rec.records[0].identifier, tc.wantIdentifier)
			}
		})
	}
}

// TestUnmappedNotificationDenial_NamesNoPolicyTargetForARemovedMethod is the same property on
// the notification-framed path, which has its own recorder call and would otherwise keep
// fabricating the target the request-framed twin no longer does.
func TestUnmappedNotificationDenial_NamesNoPolicyTargetForARemovedMethod(t *testing.T) {
	t.Parallel()
	rec := &fwdRecorder{}
	msg := mcp.RPCMsg{JSONRPC: "2.0", Method: capability.MethodResourcesSubscribe}
	gate := hostNotificationGate{rec: rec, subject: verifiedSession("sess"), established: true, errOut: io.Discard, checkKill: noKill, leg: legStdioNotification}
	if gate.admit(revisionContext(capability.Revision20260728), msg) {
		t.Fatal("a method the revision removed must be denied in notification framing too")
	}
	if len(rec.records) != 1 || rec.records[0].identifier != "" {
		t.Fatalf("records = %+v, want one record naming no policy target", rec.records)
	}
}

// TestRevisionRefusal_IsClassedAsInfrastructure: the refusal names no policy target (nothing
// was ever matched), and a peer can drive it at will, so `eunox suggest` must skip it rather
// than mine a phantom capability out of caller-controlled method text.
func TestRevisionRefusal_IsClassedAsInfrastructure(t *testing.T) {
	t.Parallel()
	if !IsInfraDenialCode(capability.ErrCodeUnsupportedProtocolVersion) {
		t.Error("UNSUPPORTED_PROTOCOL_VERSION must be an infrastructure code; its own godoc says so, and suggest keys off this")
	}
}

// TestSetNegotiatedVersionHeader_AlwaysSignalsAVersion is the regression for suppressing the
// header on a leg pinned to a revision this build has no opener for.
//
// eunox opens every upstream leg with `initialize`, so the handshake revision is what was
// negotiated whatever the pin says. Omitting the header without emitting a replacement leaves
// the request with no version signal at all, which a conformant upstream answers with 400 —
// including the terminating DELETE, whose failure leaks the upstream session.
func TestSetNegotiatedVersionHeader_AlwaysSignalsAVersion(t *testing.T) {
	t.Parallel()
	for _, rev := range []capability.Revision{"", capability.Revision20251125, capability.Revision20260728, "1999-01-01"} {
		req := newTestRequestForHeader(t)
		setNegotiatedVersionHeader(req, rev)
		if got := req.Header.Get("MCP-Protocol-Version"); got != handshakeRevision.String() {
			t.Errorf("rev %q: MCP-Protocol-Version = %q, want %q — a post-handshake request must always carry the version the handshake negotiated", rev, got, handshakeRevision)
		}
	}
}

// newTestRequestForHeader builds a bare request to inspect header stamping on.
func newTestRequestForHeader(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://127.0.0.1/mcp", http.NoBody)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	return req
}
