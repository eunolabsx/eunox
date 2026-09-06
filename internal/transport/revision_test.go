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
		// A mismatched pair on a TRANSLATABLE method resolves rather than refusing: the boundary
		// carries tools/call across, rewriting the declaration so the body and the header eunox
		// stamps still name one revision (see translate.go, and the property test below).
		{name: "resolving past the addressed revision", contextRev: capability.Revision20260728, legRev: capability.Revision20251125, declared: "2026-07-28", want: capability.Revision20260728},
		// ROUTING PRECEDES THE PAIR. resources/subscribe is not in 2026-07-28's table at all, so
		// this peer's own revision has already removed it — and the boundary must stay silent so
		// the ordinary unmapped default answers, naming the method rather than telling an
		// operator their two revisions cannot bridge something a matched pair would refuse too.
		// Negotiation runs before routing, so without an explicit check this resolved as a pair
		// problem.
		{name: "a method the peer's own revision removed is left to routing", method: capability.MethodResourcesSubscribe, contextRev: capability.Revision20260728, legRev: capability.Revision20251125, declared: "2026-07-28", want: capability.Revision20260728},
		// A MATCHED pair on a pinned leg: the host declares what the leg speaks, so the body
		// and the header eunox stamps name one revision and the request is forwardable. This is
		// what the pin bought — before the opener was revision-selected, every leg was addressed
		// as the handshake revision and this exact pair was refused.
		{name: "matched pair on a pinned leg", contextRev: capability.Revision20260728, legRev: capability.Revision20260728, declared: "2026-07-28", want: capability.Revision20260728},
		// The same pair with the declaration OMITTED. Host-side, omission inherits the context;
		// upstream-side, eunox declares only on requests it originates. Together they would send
		// a declaring upstream a request missing the member that revision requires, so this is
		// refused HERE rather than one layer away by the upstream.
		{name: "inherited on a declaring leg", contextRev: capability.Revision20260728, legRev: capability.Revision20260728, wantErr: errUndeclaredOnDeclaringLeg},
		// And the mismatched pair in the other direction: an old host in front of a pinned new
		// upstream. This is the primary migration deployment ADR-0006 exists to serve, so the
		// translatable methods cross — translateRequest adds the declaration the newer upstream
		// requires and the older host has no way to send.
		{name: "old host against a pinned new leg", contextRev: capability.Revision20251125, legRev: capability.Revision20260728, declared: "2025-11-25", want: capability.Revision20251125},
		// The direction in which the boundary refusal is actually reachable: subscribe IS in the
		// old host's table, so routing admits it and the PAIR is what cannot carry it — the new
		// upstream replaced the pair with subscriptions/listen. Every method the boundary
		// refuses is one the newer revision removed, so this is the only direction that reaches
		// it; the other is answered by routing, above.
		{name: "old host, refused method, pinned new leg", method: capability.MethodResourcesSubscribe, contextRev: capability.Revision20251125, legRev: capability.Revision20260728, declared: "2025-11-25", wantErr: errUntranslatableAcrossRevisions},
		// INHERITED, not declared: a peer pins the newer revision by declaring once on a method
		// that forwards nothing, then omits the declaration forever after. Checking the
		// declaration alone let exactly that request through.
		{name: "inheriting a revision the leg is not addressed as", contextRev: capability.Revision20260728, legRev: capability.Revision20251125, want: capability.Revision20260728},
		{name: "inheriting one, on a method that peer's revision removed", method: capability.MethodResourcesSubscribe, contextRev: capability.Revision20260728, legRev: capability.Revision20251125, want: capability.Revision20260728},
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
// decoded must NOT be relabeled as a version problem for the one message shape whose bytes are
// re-read before they go anywhere — a request routed to a Decide handler, which decodes the
// same bytes moments later and denies them as INVALID_REQUEST with a target-bearing record. A
// -32022 here would replace that with a misleading refusal for every malformed request.
//
// Asserted on a LIVE leg as well as on none, because that is the whole remaining exception: the
// unreadable body reaches a real upstream here and is still admitted, on the strength of the
// handler that stops it. TestResolveHostRevision_UndecodableParamsReachingTheUpstream covers
// the shapes with no such handler, and
// TestResolveHostRevision_UnreadableIsNotAStatedAbsenceOnADeclaringLeg the leg revision whose
// own per-request rule would otherwise relabel the very refusal this one protects.
func TestResolveHostRevision_MalformedParamsAreNotAVersionFailure(t *testing.T) {
	t.Parallel()
	for _, params := range []string{
		`{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"},"_meta":{}}`, // duplicate key
		`{"_meta":"io.modelcontextprotocol/protocolVersion"}`,                           // key name as a value
		`{"_meta":[{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}]}`,          // wrong shape
	} {
		for _, legRev := range []capability.Revision{"", capability.Revision20251125} {
			msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsCall, Params: json.RawMessage(params)}
			got, err := resolveHostRevision(capability.Revision20251125, legRev, msg)
			if err != nil {
				t.Errorf("params %s (leg %q): got version error %v, want the request to fall through to its handler", params, legRev, err)
			}
			if got != capability.Revision20251125 {
				t.Errorf("params %s (leg %q): revision = %q, want the context's %q", params, legRev, got, capability.Revision20251125)
			}
		}
	}
}

// TestResolveHostRevision_UndecodableParamsReachingTheUpstream is the regression for
// revision-declaration smuggling on the framings eunox forwards verbatim.
//
// mcp.DeclaredRevision cannot decode a body carrying a duplicate key, and reading that as
// "nothing declared" is only safe where something re-decodes the bytes and denies them. For a
// host RESPONSE, a forwarded NOTIFICATION, and a */list REQUEST, nothing does: the bytes travel
// to the upstream untouched. A peer therefore adds any throwaway duplicate key to make this
// decoder bail — eunox inherits the context, errRevisionMismatch and checkUpstreamHonorable
// both pass, and on a remote leg eunox stamps an MCP-Protocol-Version header naming the leg's
// revision — while a clean io.modelcontextprotocol/protocolVersion in `_meta` names another one
// to the upstream's own last-wins parser. Both peers agree the message is well-formed; only
// eunox is looking at a different revision than the one it forwards.
func TestResolveHostRevision_UndecodableParamsReachingTheUpstream(t *testing.T) {
	t.Parallel()
	// The declaration itself is clean and names the revision the leg is NOT addressed as; the
	// duplicate is a throwaway that has nothing to do with it.
	const smuggled = `{"progressToken":1,"x":1,"x":1,"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}`
	cases := []struct {
		name    string
		msg     mcp.RPCMsg
		refused bool
	}{
		{
			name:    "forwarded notification",
			msg:     mcp.RPCMsg{JSONRPC: "2.0", Method: methodNotificationsProgress, Params: json.RawMessage(smuggled)},
			refused: true,
		},
		{
			// A response is the framing with no method at all, relayed straight through by the
			// serve loops, and MCP puts a result's metadata in `result._meta`.
			name:    "host response, declaration in the result",
			msg:     mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Result: json.RawMessage(smuggled)},
			refused: true,
		},
		{
			name:    "host response, declaration in the params",
			msg:     mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Result: json.RawMessage(`{}`), Params: json.RawMessage(smuggled)},
			refused: true,
		},
		{
			// LocalForwards: dispatchList hands msg to the upstream untouched and filters only
			// the reply, so a */list request is as unread as the two framings above.
			name:    "*/list request, whose handler forwards params verbatim",
			msg:     mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsList, Params: json.RawMessage(smuggled)},
			refused: true,
		},
		{
			// The surviving exception: dispatchToolsCall re-decodes and answers a malformedDeny.
			name: "Decide request, re-decoded and denied by its own handler",
			msg:  mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsCall, Params: json.RawMessage(smuggled)},
		},
		{
			// A locally answered method contacts no upstream, so the bytes are read by nobody
			// else and there is no differential to have.
			name: "locally answered method",
			msg:  mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: methodPing, Params: json.RawMessage(smuggled)},
		},
		{
			// The three pairings paramsReachUpstream's per-method OR reports true for and this
			// proxy nonetheless never forwards: an enforced method in notification framing is
			// rejected, and a notification-only method in request framing — plus a */list in
			// notification framing — fall to the fail-closed routing default. Their bytes reach
			// nobody, so refusing them HERE would relabel a refusal they already earn.
			name: "enforced method in notification framing",
			msg:  mcp.RPCMsg{JSONRPC: "2.0", Method: capability.MethodToolsCall, Params: json.RawMessage(smuggled)},
		},
		{
			name: "notification-only method in request framing",
			msg:  mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: methodNotificationsProgress, Params: json.RawMessage(smuggled)},
		},
		{
			name: "*/list in notification framing",
			msg:  mcp.RPCMsg{JSONRPC: "2.0", Method: capability.MethodToolsList, Params: json.RawMessage(smuggled)},
		},
		// The decode failures that are NOT this differential. Each reaches the upstream on a
		// framing nothing re-decodes, and each must still be admitted: none can carry the
		// `_meta` object a last-wins parser would read a declaration out of, so refusing them
		// would deny well-formed JSON-RPC (params are optional and need not be an object) for
		// a smuggle that cannot exist.
		{
			name: "*/list request with array params",
			msg:  mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsList, Params: json.RawMessage(`[]`)},
		},
		{
			name: "forwarded notification with a non-object _meta",
			msg:  mcp.RPCMsg{JSONRPC: "2.0", Method: methodNotificationsProgress, Params: json.RawMessage(`{"progressToken":1,"_meta":5}`)},
		},
		{
			// A scalar result decodes fine as JSON and cannot hold `_meta`. Refusing it also
			// aborted the upstream request it was answering, for nothing.
			name: "host response with a scalar result",
			msg:  mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Result: json.RawMessage(`true`)},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := resolveHostRevision(capability.Revision20251125, capability.Revision20251125, tc.msg)
			if got := errors.Is(err, errUndecodableForwardedParams); got != tc.refused {
				t.Fatalf("refused = %v (err %v), want %v", got, err, tc.refused)
			}
			if tc.refused {
				// The refusal must be echoable: its text is eunox's own and names no caller
				// value, so collapsing it to the fixed fallback would tell a peer nothing.
				if reason := revisionRefusalReason(err); reason != err.Error() {
					t.Errorf("refusal reason = %q, want the sentinel's own text %q", reason, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
	// A leg with no revision has no upstream for the bytes to reach — the sessionless arms —
	// which is the same window checkUpstreamHonorable declines to judge.
	msg := mcp.RPCMsg{JSONRPC: "2.0", Method: methodNotificationsProgress, Params: json.RawMessage(smuggled)}
	if got, err := resolveHostRevision(capability.Revision20251125, "", msg); err != nil {
		t.Errorf("no upstream leg: err = %v, want the message to resolve to %q", err, got)
	}
}

// TestResolveHostRevision_UnreadableIsNotAStatedAbsenceOnADeclaringLeg pins the half of the
// carve-out that only shows on a 2026-07-28 leg.
//
// Reading an unreadable body as "nothing declared" is safe for a request whose handler
// re-decodes and denies it — but that reading is this decoder's, not the peer's, and
// checkDeclarationReachesUpstream refuses a message for carrying NO declaration on a leg whose
// revision requires one every time. Handing it the manufactured absence refused a malformed
// tools/call -32022 as errUndeclaredOnDeclaringLeg, which is the exact relabelling of the
// target-bearing INVALID_REQUEST the carve-out exists to prevent. Nothing is lost by skipping
// it: the handler denies these bytes long before the upstream that wanted the member sees them.
func TestResolveHostRevision_UnreadableIsNotAStatedAbsenceOnADeclaringLeg(t *testing.T) {
	t.Parallel()
	const dupKey = `{"name":"read_file","x":1,"x":1}`
	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsCall, Params: json.RawMessage(dupKey)}
	got, err := resolveHostRevision(capability.Revision20260728, capability.Revision20260728, msg)
	if err != nil {
		t.Fatalf("err = %v, want the request to fall through to the handler that denies it", err)
	}
	if got != capability.Revision20260728 {
		t.Errorf("revision = %q, want the context's %q", got, capability.Revision20260728)
	}
	// The rule itself is untouched: a peer that really states no declaration is still refused
	// on the same leg.
	undeclared := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsCall, Params: json.RawMessage(`{"name":"read_file"}`)}
	if _, err := resolveHostRevision(capability.Revision20260728, capability.Revision20260728, undeclared); !errors.Is(err, errUndeclaredOnDeclaringLeg) {
		t.Errorf("err = %v, want %v for a message that genuinely carries no declaration", err, errUndeclaredOnDeclaringLeg)
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

// TestCheckNegotiatedRevision pins the inversion — a handshake's answer is CHECKED against the
// revision the leg was opened at rather than allowed to set it — and the two answers it gets.
//
// A speakable revision other than the one offered is REFUSED: the leg would look negotiated
// while eunox spoke a revision over a method that revision removed. A version this build does
// not speak is REPORTED and the leg continues, because refusing it would take eunox offline
// against every server on a revision outside the published set; what was wrong before was the
// silence, not the fallback.
func TestCheckNegotiatedRevision(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		opened     capability.Revision
		reported   string
		wantErr    string
		wantNotice string
	}{
		{name: "agrees", opened: capability.Revision20251125, reported: "2025-11-25"},
		{
			name: "an unspeakable version is reported, not refused", opened: capability.Revision20251125,
			reported: "2025-06-18", wantNotice: "does not speak",
		},
		{
			// Only a declaring leg reaches this with an empty string: the handshake opener's
			// own result validation requires the member first. Silence there is conformance,
			// not a disagreement to report.
			name: "nothing stated is nothing to judge", opened: capability.Revision20251125,
			reported: "",
		},
		{
			name: "a speakable version that is not the one offered is refused", opened: capability.Revision20251125,
			reported: "2026-07-28", wantErr: "opened at",
		},
		{
			// The declaring opener negotiates none, so a conforming reply carries none.
			name: "a declaring leg's silent reply is neither", opened: capability.Revision20260728,
			reported: "",
		},
		{
			// But one that VOLUNTEERS a speakable version other than the leg's is stating a
			// disagreement, and is refused on the same terms the handshake opener's is.
			name: "a declaring leg's contradicting reply is refused", opened: capability.Revision20260728,
			reported: "2025-11-25", wantErr: "opened at",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			notice, err := checkNegotiatedRevision(tc.opened, tc.reported)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("checkNegotiatedRevision(%q, %q) = %v, want no error", tc.opened, tc.reported, err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("checkNegotiatedRevision(%q, %q) = nil, want an error mentioning %q", tc.opened, tc.reported, tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Errorf("error = %q, want it to mention %q", err.Error(), tc.wantErr)
			}
			if tc.wantNotice == "" && notice != "" {
				t.Errorf("notice = %q, want none", notice)
			}
			if tc.wantNotice != "" && !strings.Contains(notice, tc.wantNotice) {
				t.Errorf("notice = %q, want it to mention %q", notice, tc.wantNotice)
			}
		})
	}
}

// TestCheckNegotiatedRevision_ResolvesThroughTheOpenersResolver pins WHICH resolver settles an
// unset leg revision here.
//
// upstreamAddressedRevision states the rule and its reason: an unset leg revision resolves through
// UpstreamOpenRevision — the resolver that SELECTED the opener — not through resolveRevision, which
// answers the host side's empty-carrier question and lands on capability.DefaultRevision. The two
// agree only while the default IS the handshake revision, so this cell is written against the
// resolver rather than against today's shared value: the day the default advances, an in-tree
// caller's `ApplyUpstreamOpenerResult("")` would open with the handshake opener while this check
// judged the reply against the new default, refusing a conforming handshake.
func TestCheckNegotiatedRevision_ResolvesThroughTheOpenersResolver(t *testing.T) {
	t.Parallel()
	for _, pin := range []capability.Revision{"", "1999-01-01"} {
		opened := UpstreamOpenRevision(pin)
		if _, err := checkNegotiatedRevision(pin, opened.String()); err != nil {
			t.Errorf("pin %q opened at %s; a reply naming that revision must not be refused: %v", pin, opened, err)
		}
		for _, other := range capability.PublishedRevisions() {
			if other == opened {
				continue
			}
			if _, err := checkNegotiatedRevision(pin, other.String()); err == nil {
				t.Errorf("pin %q opened at %s; a reply naming %s must be refused", pin, opened, other)
			}
		}
	}
}

// TestCheckNegotiatedRevision_BoundsTheReflectedVersion: the notice echoes an
// upstream-controlled string to an operator's console, so it must be bounded and stripped of
// anything a terminal would act on — the same rule the host-side -32022 refusal applies to a
// peer's.
func TestCheckNegotiatedRevision_BoundsTheReflectedVersion(t *testing.T) {
	t.Parallel()
	hostile := "\x1b]0;pwned\x07" + strings.Repeat("A", 8192)
	notice, err := checkNegotiatedRevision(handshakeRevision, hostile)
	if err != nil {
		t.Fatalf("an unspeakable version must be reported, not refused: %v", err)
	}
	if notice == "" {
		t.Fatal("an unspeakable version must produce a notice")
	}
	if strings.ContainsAny(notice, "\x1b\x07") {
		t.Error("the notice reflected control characters from the upstream's version string")
	}
	if len(notice) > 4096 {
		t.Errorf("notice is %d bytes; an upstream must not be able to size this diagnostic", len(notice))
	}
}

// TestUpstreamDeclaration_NeverContradictsTheHeaderEunoxStamps is the property the
// upstream-leg check exists for, asserted against the header PRODUCER rather than against a
// second copy of what it emits.
//
// A host's `_meta` declaration reaches the upstream beside eunox's own MCP-Protocol-Version.
// Every combination of declared revision and leg revision this build can produce is driven
// through the gate, and any pair it ADMITS must be one whose body and header name the same
// revision — otherwise the proxy is manufacturing exactly the mismatch its host leg refuses,
// and a first-wins and a last-wins upstream resolve the same request under different method
// sets.
//
// Read off the message as it ACTUALLY reaches the upstream, which since the translation
// boundary means after translateRequest. A mismatched pair is now admitted rather than refused,
// and translation is what keeps the property true there: toward a declaring leg the declaration
// is rewritten to the leg's own revision, and toward a non-declaring one it is removed, so
// neither can contradict the header. Asserting against the pre-translation bytes would have
// reported those admissions as violations while the wire was correct — and, worse, would keep
// passing if translation later stopped rewriting them.
func TestUpstreamDeclaration_NeverContradictsTheHeaderEunoxStamps(t *testing.T) {
	t.Parallel()
	admitted, translated := 0, 0
	for _, declared := range capability.PublishedRevisions() {
		for _, legRev := range capability.PublishedRevisions() {
			t.Run(fmt.Sprintf("declared=%s/leg=%s", declared, legRev), func(t *testing.T) {
				msg := mcp.RPCMsg{
					JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsCall,
					Params: json.RawMessage(fmt.Sprintf(
						`{"name":"read_file","_meta":{"io.modelcontextprotocol/protocolVersion":%q}}`, declared)),
				}
				resolved, err := resolveHostRevision(declared, legRev, msg)
				if err != nil {
					return // refused: nothing is forwarded, so no pair is manufactured
				}
				admitted++
				forwarded, err := translateRequest(msg, resolved, legRev)
				if err != nil {
					t.Fatalf("the gate admitted a message translation then refused: %v", err)
				}
				if declared != upstreamAddressedRevision(legRev) {
					translated++
				}
				// Read the header off the real producer: a hand-written expectation here would
				// keep passing the day setNegotiatedVersionHeader changes what it stamps.
				req := httptest.NewRequest(http.MethodPost, "http://upstream.invalid/mcp", http.NoBody)
				setNegotiatedVersionHeader(req, legRev)
				header := req.Header.Get("MCP-Protocol-Version")

				body, present, err := mcp.DeclaredRevisionOf(forwarded)
				if err != nil {
					t.Fatalf("the translated body's declaration is unreadable: %v", err)
				}
				// An absent declaration contradicts nothing: the upstream reads its revision off
				// the header alone, which is what a client of its revision would send.
				if present && body.String() != header {
					t.Errorf("a forwarded body declaring %s would carry MCP-Protocol-Version: %s — the pair names two revisions", body, header)
				}
			})
		}
	}
	// The translated admissions are the ones this property newly covers; without them the loop
	// would be asserting only the matched pairs it always did.
	if translated == 0 {
		t.Error("no mismatched pair was admitted; the property held only over matched pairs")
	}
	// Not vacuous: a gate that refused every declaration would satisfy the loop above while
	// making the whole declaration surface unusable.
	if admitted == 0 {
		t.Error("no declaration was admitted on any leg; the property held only because nothing is ever forwarded")
	}
}

// TestCheckDeclarationReachesUpstream covers the seam between two rules that are each correct
// alone: host-side omission INHERITS the context, and upstream-side eunox declares only on the
// requests it originates. Only their combination is a defect, and only on a declaring leg.
func TestCheckDeclarationReachesUpstream(t *testing.T) {
	t.Parallel()
	call := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsCall}
	response := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Result: json.RawMessage(`{}`)}
	cases := []struct {
		name     string
		resolved capability.Revision
		legRev   capability.Revision
		msg      mcp.RPCMsg
		declared bool
		wantErr  bool
	}{
		{name: "inherited on a declaring leg", resolved: capability.Revision20260728, legRev: capability.Revision20260728, msg: call, wantErr: true},
		{name: "declared on a declaring leg", resolved: capability.Revision20260728, legRev: capability.Revision20260728, msg: call, declared: true},
		{name: "inherited on a negotiating leg", resolved: capability.Revision20251125, legRev: capability.Revision20251125, msg: call},
		// A host RESPONSE is the one framing relayed verbatim with no method of its own; it
		// answers something the upstream already declared for, so it owes no declaration.
		{name: "a response owes none", resolved: capability.Revision20260728, legRev: capability.Revision20260728, msg: response},
		// No leg means no upstream to reach, so there is nothing to arrive undeclared at.
		{name: "no upstream leg", resolved: capability.Revision20260728, msg: call},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := checkDeclarationReachesUpstream(tc.resolved, tc.legRev, tc.msg, tc.declared)
			if tc.wantErr && !errors.Is(err, errUndeclaredOnDeclaringLeg) {
				t.Errorf("err = %v, want the undeclared-on-a-declaring-leg refusal", err)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("err = %v, want none", err)
			}
		})
	}
}

// TestRevisionRefusalReason_EveryAllowlistedSentinelReachesThePeer pins the allowlist against
// the one way it silently fails: a refusal whose text was written to name a cause, collapsed to
// the opaque fallback because its sentinel was never added.
//
// That is what happened to errUndeclaredOnDeclaringLeg. Its own doc says "Refusing here names
// the cause", its text satisfies the allowlist's stated criterion (fixed prose plus revision
// names from a closed set), and a host pinned to a declaring revision that omitted the
// per-request declaration nonetheless got "protocol revision could not be established" —
// telling a peer with a mechanically fixable request nothing about what to fix.
//
// Each case is produced by resolveHostRevision rather than constructed here, so an error the
// allowlist matches but the resolver no longer returns fails as a dead entry.
func TestRevisionRefusalReason_EveryAllowlistedSentinelReachesThePeer(t *testing.T) {
	t.Parallel()

	smuggled := `{"name":"read_file","_meta":{"io.modelcontextprotocol/protocolVersion":"2025-11-25","io.modelcontextprotocol/protocolVersion":"2026-07-28"}}`

	cases := []struct {
		name       string
		contextRev capability.Revision
		legRev     capability.Revision
		msg        mcp.RPCMsg
		sentinel   error
		// names is a fragment the echoed reason must carry: the thing a peer needs in order to
		// act on the refusal, which the fallback string cannot carry for any of them.
		names string
	}{
		{
			name:       "declaration disagreeing with the context",
			contextRev: capability.Revision20251125,
			msg:        mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsCall, Params: metaParams(t, "2026-07-28", map[string]any{"name": "read_file"})},
			sentinel:   errRevisionMismatch,
			names:      "2026-07-28",
		},
		{
			name:     "a revision this build does not speak",
			msg:      mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsCall, Params: metaParams(t, "1999-01-01", map[string]any{"name": "read_file"})},
			sentinel: mcp.ErrUnknownRevision,
			names:    "1999-01-01",
		},
		{
			// A method the boundary will not carry. tools/call would be TRANSLATED across this
			// pair, so the case has to name one of the refused methods for the sentinel to be
			// reachable at all — which is itself the shape of the change: what used to refuse
			// every message on a mismatched pair now refuses only the ones that cannot cross.
			name:       "a method the revision pair cannot carry",
			contextRev: capability.Revision20251125,
			legRev:     capability.Revision20260728,
			msg:        mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodResourcesSubscribe, Params: metaParams(t, "2025-11-25", map[string]any{"uri": "file:///x"})},
			sentinel:   errUntranslatableAcrossRevisions,
			names:      capability.MethodResourcesSubscribe,
		},
		{
			name:       "params this build alone refused, reaching the upstream unread",
			contextRev: capability.Revision20251125,
			legRev:     capability.Revision20251125,
			msg:        mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsList, Params: json.RawMessage(smuggled)},
			sentinel:   errUndecodableForwardedParams,
			names:      "could not be decoded",
		},
		{
			// The entry that was missing. What a peer needs is the member's exact spelling, so
			// that is what the reason has to reach it carrying.
			name:       "inherited on a leg whose revision requires a declaration",
			contextRev: capability.Revision20260728,
			legRev:     capability.Revision20260728,
			msg:        mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsCall, Params: metaParams(t, nil, map[string]any{"name": "read_file"})},
			sentinel:   errUndeclaredOnDeclaringLeg,
			names:      capability.MetaKeyProtocolVersion,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := resolveHostRevision(tc.contextRev, tc.legRev, tc.msg)
			if !errors.Is(err, tc.sentinel) {
				t.Fatalf("err = %v, want %v", err, tc.sentinel)
			}
			reason := revisionRefusalReason(err)
			if reason != err.Error() {
				t.Fatalf("reason = %q, want the sentinel's own text %q — an allowlist miss reads exactly like this", reason, err.Error())
			}
			if !strings.Contains(reason, tc.names) {
				t.Errorf("reason = %q, want it to name %q", reason, tc.names)
			}
		})
	}

	// The other half of the allowlist: anything NOT on it collapses, so an error carrying an
	// unreviewed (possibly caller-supplied) string cannot be echoed by being added later.
	if got := revisionRefusalReason(errors.New("some upstream said: " + strings.Repeat("x", 40))); got != "protocol revision could not be established" {
		t.Errorf("unlisted error echoed %q, want the fixed fallback", got)
	}
}
