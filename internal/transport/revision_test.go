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
		// The same pair with the declaration OMITTED. Host-side, omission inherits the context;
		// upstream-side, eunox declares only on requests it originates. Together they would send
		// a declaring upstream a request missing the member that revision requires, so this is
		// refused HERE rather than one layer away by the upstream.
		{name: "inherited on a declaring leg", contextRev: capability.Revision20260728, legRev: capability.Revision20260728, wantErr: errUndeclaredOnDeclaringLeg},
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
// decoded must NOT be relabeled as a version problem for the one message shape whose bytes are
// re-read before they go anywhere — a request routed to a Decide handler, which decodes the
// same bytes moments later and denies them as INVALID_REQUEST with a target-bearing record. A
// -32022 here would replace that with a misleading refusal for every malformed request.
//
// Asserted on a LIVE leg as well as on none, because that is the whole remaining exception: the
// undecodable body reaches a real upstream here and is still admitted, on the strength of the
// handler that stops it. TestResolveHostRevision_UndecodableParamsReachingTheUpstream covers
// the shapes with no such handler.
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
