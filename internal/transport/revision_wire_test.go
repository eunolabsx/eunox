// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Old-revision wire regression: the exact BYTES a 2025-11-25 host sees from the proxy for the
// messages the proxy answers itself. Revision scoping put a table lookup in front of every one
// of them, and the full suite is a weaker net than a byte comparison — it asserts fields, so a
// changed envelope, a dropped member, or a re-ordered struct passes it. The golden lines here
// fail on any of those.
//
// Scope: the responses the PROXY generates. A byte-stable old-host/old-upstream interop cell
// over a live upstream belongs to the e2e matrix, which is separate work; this is the portion
// reachable without it.

package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"testing"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// TestOldRevisionWire_ProxyAnsweredResponsesAreByteStable pins the host-facing bytes for every
// method the old revision answers locally, plus the fail-closed default.
//
// The context carries NO negotiated revision on purpose: that is the old-revision peer's own
// shape (omission resolves to the shipped default), so this doubles as the assertion that a
// host which declares nothing still gets exactly the surface it got before revision scoping.
func TestOldRevisionWire_ProxyAnsweredResponsesAreByteStable(t *testing.T) {
	// Not parallel: pins proxyVersion, which is package-global. Restored after the test.
	prev := proxyVersion
	t.Cleanup(func() { proxyVersion = prev })
	SetProxyVersion("1.2.3")

	upstreamTools := json.RawMessage(`{"tools":[{"name":"read_file","description":"d"}]}`)
	cases := []struct {
		name string
		msg  mcp.RPCMsg
		want string
	}{
		{
			name: "initialize",
			msg:  mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: mcp.MethodInitialize},
			want: `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"eunox-proxy","version":"1.2.3"},"instructions":"upstream instructions"}}`,
		},
		{
			name: "ping",
			msg:  mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`2`), Method: methodPing},
			want: `{"jsonrpc":"2.0","id":2,"result":{}}`,
		},
		{
			name: "tools/list",
			msg:  mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`3`), Method: capability.MethodToolsList},
			want: `{"jsonrpc":"2.0","id":3,"result":{"tools":[{"name":"read_file","description":"d"}]}}`,
		},
		{
			// The one line here that has moved since revision scoping: the routing refusal's
			// symbolic code split off from AUTHORIZATION_FAILED, which it used to borrow, so
			// that its CLASS could say no policy evaluated the message. The JSON-RPC integer a
			// host branches on is deliberately unchanged.
			name: "unmapped method",
			msg:  mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`4`), Method: "agents/delegate"},
			want: `{"jsonrpc":"2.0","id":4,"error":{"code":-32001,"message":"UNROUTABLE_METHOD: target \"agents/delegate\"","data":{"code":"UNROUTABLE_METHOD","target":"agents/delegate"}}}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			d := dispatchParams{
				forwardParams: forwardParams{
					errOut: io.Discard,
					callUpstream: func(_ context.Context, msg mcp.RPCMsg) (mcp.RPCMsg, error) {
						return mcp.RPCMsg{JSONRPC: "2.0", ID: msg.ID, Result: upstreamTools}, nil
					},
				},
				pdp:       pdp.AlwaysAllowPDP{},
				buildInit: func(msg mcp.RPCMsg) mcp.RPCMsg { return buildInitializeResponse(msg.ID, nil, "upstream instructions") },
			}
			if err := mcp.NewMsgWriter(&buf).Write(dispatchRequest(context.Background(), d, tc.msg)); err != nil {
				t.Fatalf("write response: %v", err)
			}
			if got := string(bytes.TrimRight(buf.Bytes(), "\n")); got != tc.want {
				t.Errorf("old-revision wire bytes changed\n got: %s\nwant: %s", got, tc.want)
			}
		})
	}
}

// TestOldRevisionWire_RefusalIsByteStable pins the one response revision negotiation itself
// mints, so the code and shape a peer is refused with cannot drift silently.
func TestOldRevisionWire_RefusalIsByteStable(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	msg := mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`9`), Method: capability.MethodToolsCall,
		Params: json.RawMessage(`{"_meta":{"io.modelcontextprotocol/protocolVersion":"1999-01-01"}}`),
	}
	_, err := resolveHostRevision(capability.Revision20251125, "", msg)
	if err == nil {
		t.Fatal("a revision this build does not speak must not resolve")
	}
	if werr := mcp.NewMsgWriter(&buf).Write(refuseHostRevision(context.Background(), nil, "sess", capability.Revision20251125, msg, err)); werr != nil {
		t.Fatalf("write refusal: %v", werr)
	}
	const want = `{"jsonrpc":"2.0","id":9,"error":{"code":-32022,"message":"UNSUPPORTED_PROTOCOL_VERSION: mcp: unsupported protocol revision: \"1999-01-01\"","data":{"code":"UNSUPPORTED_PROTOCOL_VERSION","supported":["2025-11-25","2026-07-28"]}}}`
	if got := string(bytes.TrimRight(buf.Bytes(), "\n")); got != want {
		t.Errorf("revision refusal bytes changed\n got: %s\nwant: %s", got, want)
	}
}
