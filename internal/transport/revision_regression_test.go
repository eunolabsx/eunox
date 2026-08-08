// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"

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
	gate := hostNotificationGate{rec: staticRecorder(rec), subject: verifiedSession("sess"), established: true, errOut: io.Discard, checkKill: noKill, leg: legStdioNotification}
	if gate.admit(revisionContext(capability.Revision20260728), msg) {
		t.Fatal("a method the revision removed must be denied in notification framing too")
	}
	if len(rec.records) != 1 || rec.records[0].identifier != "" {
		t.Fatalf("records = %+v, want one record naming no policy target", rec.records)
	}
}

// TestStdioNegotiation_PinsOnlyFromAMessageTheRevisionDefines is the regression for a
// connection that could be wedged for the process's lifetime by one stray line.
//
// The stdio context pins from its first RESOLVED message, which is what makes the flip refusal
// reachable for a peer that never handshakes. An id-less `initialize` is a notification by
// IsNotification's structural classification and resolves like any other message — so a single
// one declaring the revision that REMOVED `initialize` latched that revision, and the host's
// real handshake was then denied under a table with no `initialize` in it. Re-declaring the
// older revision was refused as a mid-context flip; omitting the declaration inherited the pin.
// There was no way to renegotiate.
//
// The stray notification is still dropped by the fail-closed default, and still recorded — what
// changes is that it no longer speaks for the connection.
func TestStdioNegotiation_PinsOnlyFromAMessageTheRevisionDefines(t *testing.T) {
	t.Parallel()
	hw := &mockHostWriter{}
	pr, pw := io.Pipe()
	p := &StdioProxy{
		pdp:          newTestManifestPDP(capability.Constraint{Target: "tool:*", Actions: []string{"call"}}),
		sessionID:    "sess",
		hostReader:   mcp.NewMsgReader(pr),
		hostWriter:   mcp.NewMsgWriter(&writerAdapter{hw}),
		upWriter:     mcp.NewMsgWriter(io.Discard),
		stderr:       io.Discard,
		upstreamDone: make(chan struct{}),
	}
	done := make(chan struct{})
	go func() { p.serveHost(context.Background()); close(done) }()

	// The stray line, then the host's real handshake declaring nothing at all.
	_, _ = io.WriteString(pw, `{"jsonrpc":"2.0","method":"initialize","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`+"\n")
	_, _ = io.WriteString(pw, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`+"\n")
	_ = pw.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serveHost did not return after the host closed stdin")
	}

	if len(hw.messages) != 1 {
		t.Fatalf("host received %d message(s), want exactly the handshake reply: %+v", len(hw.messages), hw.messages)
	}
	if resp := hw.messages[0]; resp.Error != nil || resp.Result == nil {
		t.Fatalf("the handshake was refused (%+v); one stray notification must not decide which revision this connection speaks", resp.Error)
	}
	if got := p.hostRevision(); got != handshakeRevision {
		t.Errorf("pinned revision = %q, want %q — the pin belongs to the message that actually negotiated", got, handshakeRevision)
	}
}

// TestStdioNegotiation_StillPinsFromADefinedMethod is the other half: the wedge fix must not
// cost the property the pin exists for. A peer that never sends `initialize` still latches its
// revision from its first ordinary message, so a later declaration disagreeing with it is
// refused as the mid-context flip it is.
func TestStdioNegotiation_StillPinsFromADefinedMethod(t *testing.T) {
	t.Parallel()
	hw := &mockHostWriter{}
	pr, pw := io.Pipe()
	p := &StdioProxy{
		// No capabilities: the calls below are denied by policy, so neither reaches an upstream
		// this proxy does not have.
		pdp:          newTestManifestPDP(),
		sessionID:    "sess",
		hostReader:   mcp.NewMsgReader(pr),
		hostWriter:   mcp.NewMsgWriter(&writerAdapter{hw}),
		upWriter:     mcp.NewMsgWriter(io.Discard),
		stderr:       io.Discard,
		upstreamDone: make(chan struct{}),
	}
	done := make(chan struct{})
	go func() { p.serveHost(context.Background()); close(done) }()

	// tools/call exists in BOTH revisions, so declaring the newer one here is evidence about
	// the conversation — unlike the `initialize` above, which the declared revision removed.
	_, _ = io.WriteString(pw, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"probe","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`+"\n")
	_, _ = io.WriteString(pw, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"probe","_meta":{"io.modelcontextprotocol/protocolVersion":"2025-11-25"}}}`+"\n")
	_ = pw.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serveHost did not return after the host closed stdin")
	}

	if got := p.hostRevision(); got != capability.Revision20260728 {
		t.Fatalf("pinned revision = %q, want %q from the first message the revision defines", got, capability.Revision20260728)
	}
	if len(hw.messages) != 2 {
		t.Fatalf("host received %d message(s), want two: %+v", len(hw.messages), hw.messages)
	}
	// Order-independent: the flip is refused inline by the read loop while the first call's
	// policy denial is written by its own handler goroutine, so either may land first.
	flipped := false
	for _, m := range hw.messages {
		if m.Error != nil && m.Error.Code == capability.JSONRPCCodeUnsupportedProtocolVersion {
			flipped = true
		}
	}
	if !flipped {
		t.Errorf("no -32022 among %+v; the second declaration disagrees with the pinned context and must be refused as a mid-context flip", hw.messages)
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
