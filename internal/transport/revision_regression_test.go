// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"encoding/json"
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
	gate := hostNotificationGate{rec: staticRecorder(rec), subject: verifiedSession("sess"), established: true, errOut: io.Discard, checkKill: noKill, leg: legStdioNotification}
	if gate.admit(revisionContext(capability.Revision20260728), msg) == notificationForward {
		t.Fatal("a method the revision removed must be denied in notification framing too")
	}
	if len(rec.records) != 1 || rec.records[0].identifier != "" {
		t.Fatalf("records = %+v, want one record naming no policy target", rec.records)
	}
}

// TestStdioNegotiation_PinsOnlyFromAMessageTheRevisionDispatches is the regression for a
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
func TestStdioNegotiation_PinsOnlyFromAMessageTheRevisionDispatches(t *testing.T) {
	t.Parallel()
	// The stray line, then the host's real handshake declaring nothing at all.
	p, hw := serveHostLines(t, stdioServe{pdp: newTestManifestPDP(capability.Constraint{Target: "tool:*", Actions: []string{"call"}})},
		`{"jsonrpc":"2.0","method":"initialize","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
	)

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

// TestStdioNegotiation_StillPinsFromADispatchedMethod is the other half: the wedge fix must not
// cost the property the pin exists for. A peer that never sends `initialize` still latches its
// revision from its first ordinary message, so a later declaration disagreeing with it is
// refused as the mid-context flip it is.
//
// The peer declares the HANDSHAKE revision, which is the only one a live upstream leg can
// dispatch: eunox addresses every leg it opens as that revision, and every method 2026-07-28
// currently declares forwards its params, so a declaration of the newer one is refused by
// checkUpstreamHonorable one gate before the pin is even consulted (see its doc — that is
// incidental, not something the pin relies on). A fixture that pinned 2026-07-28 would only
// reach the pin by leaving the leg revision unset — a state Start never produces.
func TestStdioNegotiation_StillPinsFromADispatchedMethod(t *testing.T) {
	t.Parallel()
	// ping is answered locally and exists in the declared revision, so it both pins and is
	// dispatched — unlike the `initialize` above, which the revision IT declared had removed.
	p, hw := serveHostLines(t, stdioServe{pdp: newTestManifestPDP()},
		`{"jsonrpc":"2.0","id":1,"method":"ping","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-11-25"}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"ping","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`,
	)

	if got := p.hostRevision(); got != handshakeRevision {
		t.Fatalf("pinned revision = %q, want %q from the first message the revision defines", got, handshakeRevision)
	}
	if len(hw.messages) != 2 {
		t.Fatalf("host received %d message(s), want two: %+v", len(hw.messages), hw.messages)
	}
	// Order-independent: the flip is refused inline by the read loop while the first message's
	// own reply is written by its handler goroutine, so either may land first.
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

// TestStdioNegotiation_DoesNotPinFromAMessageTheFramingDiscards is the wedge CLASS, not the one
// instance of it. Pinning from "the revision has this method" closed the id-less `initialize`
// and left the shape open: revision membership is declared per METHOD, so a REQUEST-framed
// `notifications/progress` names a method both revisions have, satisfies that predicate, pins
// the connection — and is then dropped by dispatchUnmapped, which is a message the fail-closed
// default discards deciding what the peer speaks.
//
// Driven through the real serve loop at the handshake revision, which is the framing/revision
// pair a live upstream leg actually admits. The message is still denied; what must not happen
// is the latch.
func TestStdioNegotiation_DoesNotPinFromAMessageTheFramingDiscards(t *testing.T) {
	t.Parallel()
	p, hw := serveHostLines(t, stdioServe{},
		`{"jsonrpc":"2.0","id":1,"method":"notifications/progress","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-11-25"}}}`,
	)

	if len(hw.messages) != 1 || hw.messages[0].Error == nil {
		t.Fatalf("host received %+v, want the fail-closed refusal: a notification-only method has no request handler in either revision", hw.messages)
	}
	if got := p.hostRevision(); got != "" {
		t.Errorf("pinned revision = %q, want unpinned — the proxy discarded this message, so it is no evidence about which revision the conversation is on", got)
	}
}

// TestDispatchesMessage_AgreesWithTheDispatchTables pins WHICH SOURCE the predicate reads: the
// revision's derived tables, in the message's framing, across every published revision, every
// declared method and both framings.
//
// Deliberately not billed as proving the predicate and the dispatcher agree — its expectation
// is computed from the same tablesFor result the predicate reads, so a rewrite of
// dispatchesMessage is the only thing it can fail. What it does catch is the tempting
// "simplification" to a methodRegistry + spec.In membership test, which reports true for a
// revision this build does not speak while buildRevisionDispatch gives it empty tables — a pin
// onto a revision that dispatches nothing. The behavioral regression for the wedge itself is
// its hardcoded sibling below.
func TestDispatchesMessage_AgreesWithTheDispatchTables(t *testing.T) {
	t.Parallel()
	for _, rev := range capability.PublishedRevisions() {
		tables := tablesFor(rev)
		for method := range methodRegistry {
			_, decided := tables.decide[method]
			_, local := tables.local[method]
			_, notified := tables.notifications[method]

			request := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: method}
			if got := dispatchesMessage(rev, request); got != (decided || local) {
				t.Errorf("%s %s (request framing): dispatchesMessage = %v, tables hold a handler = %v", rev, method, got, decided || local)
			}
			notification := mcp.RPCMsg{JSONRPC: "2.0", Method: method}
			if got := dispatchesMessage(rev, notification); got != notified {
				t.Errorf("%s %s (notification framing): dispatchesMessage = %v, tables hold a disposition = %v", rev, method, got, notified)
			}
		}
		// A response carries no method and is dispatched by neither table, so it can never pin.
		if dispatchesMessage(rev, mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Result: json.RawMessage(`{}`)}) {
			t.Errorf("%s: a response must not pin a context; the proxy routes it to a waiting upstream, it does not dispatch it", rev)
		}
		// And an unknown method, in either framing.
		if dispatchesMessage(rev, mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "agents/delegate"}) ||
			dispatchesMessage(rev, mcp.RPCMsg{JSONRPC: "2.0", Method: "agents/delegate"}) {
			t.Errorf("%s: an unmapped method must not pin a context", rev)
		}
	}
}

// TestDispatchesMessage_RejectsTheRequestFramedNotification names the cell the per-method
// predicate got wrong, in both revisions, so a future predicate that answers per METHOD again
// fails here rather than in a wedged connection.
func TestDispatchesMessage_RejectsTheRequestFramedNotification(t *testing.T) {
	t.Parallel()
	for _, rev := range []capability.Revision{capability.Revision20251125, capability.Revision20260728} {
		request := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: methodNotificationsProgress}
		if dispatchesMessage(rev, request) {
			t.Errorf("%s: a request-framed %s must not pin — %s has no request handler in any revision, so the message is about to be discarded",
				rev, methodNotificationsProgress, methodNotificationsProgress)
		}
		// The same method in its own framing IS acted on, so it does pin: the predicate is about
		// the framing, not about the method being second-class.
		if !dispatchesMessage(rev, mcp.RPCMsg{JSONRPC: "2.0", Method: methodNotificationsProgress}) {
			t.Errorf("%s: %s in notification framing is forwarded, so it is evidence about the conversation's revision", rev, methodNotificationsProgress)
		}
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
