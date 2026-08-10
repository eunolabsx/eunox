// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The old x old interop cell: a 2025-11-25 host and a LIVE 2025-11-25 upstream, one on each
// side of a real proxy, with the exact BYTES asserted in both directions.
//
// revision_wire_test.go pins the responses the proxy GENERATES. What it cannot reach is a live
// upstream on the other side: the leg's opener, the header its requests carry, and whether a
// host's own params cross to it untouched were all covered by field-level assertions, which
// pass a changed envelope, a dropped member, or an added `_meta` block.
//
// Both transports, because their upstream legs are different code (the HTTP session's own
// client, and stdio's remote bridge) reaching one shared opener, and a cell on one of them
// would not have caught a change to the other.
//
// The out-of-process interop matrix is separate work; what is here is the same cell in process,
// and it is what makes the upstream half of the old-revision surface byte-stable rather than
// field-stable.

package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// oldRevisionUpstream is a live 2025-11-25 MCP server that records the exact bytes and headers
// of everything the proxy sends it. STRICT on purpose: it answers only what that revision
// defines, so a leg opened with anything else fails the cell rather than being quietly served.
type oldRevisionUpstream struct {
	mu       sync.Mutex
	requests []upstreamRequest
	srv      *httptest.Server
}

// upstreamRequest is one request as the upstream received it: the raw body, so an assertion is
// a byte comparison rather than a re-marshal of a decode, plus the version header beside it.
type upstreamRequest struct {
	body       string
	versionHdr string
	method     string
}

func newOldRevisionUpstream(t *testing.T) *oldRevisionUpstream {
	t.Helper()
	up := &oldRevisionUpstream{}
	up.srv = httptest.NewServer(http.StripPrefix("/mcp", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var msg mcp.RPCMsg
		if err := json.Unmarshal(raw, &msg); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		up.mu.Lock()
		up.requests = append(up.requests, upstreamRequest{
			body: string(bytes.TrimSpace(raw)), versionHdr: r.Header.Get("MCP-Protocol-Version"), method: msg.Method,
		})
		up.mu.Unlock()

		w.Header().Set("Content-Type", CTJSON)
		switch msg.Method {
		case mcp.MethodInitialize:
			w.Header().Set(SessionHeader, "up-sess")
			result, _ := json.Marshal(mcp.InitResult{
				ProtocolVersion: capability.Revision20251125.String(),
				Capabilities:    map[string]interface{}{"tools": map[string]interface{}{}},
				ServerInfo:      map[string]interface{}{"name": "old-upstream", "version": "1.0.0"},
				Instructions:    "old instructions",
			})
			_ = json.NewEncoder(w).Encode(mcp.RPCMsg{JSONRPC: "2.0", ID: msg.ID, Result: result})
		case capability.MethodToolsList:
			_ = json.NewEncoder(w).Encode(mcp.RPCMsg{JSONRPC: "2.0", ID: msg.ID,
				Result: json.RawMessage(`{"tools":[{"name":"read_file","description":"d"},{"name":"delete_all","description":"x"}]}`)})
		case capability.MethodToolsCall:
			_ = json.NewEncoder(w).Encode(mcp.RPCMsg{JSONRPC: "2.0", ID: msg.ID,
				Result: json.RawMessage(`{"content":[{"type":"text","text":"ok"}]}`)})
		default:
			// A notification (no id) is acked bodyless, exactly as the spec says; anything else
			// this revision does not define is an error, so an unexpected opener shows up as a
			// failed leg rather than as a silent success.
			if msg.ID == nil {
				w.WriteHeader(http.StatusAccepted)
				return
			}
			_ = json.NewEncoder(w).Encode(mcp.ErrorResponse(msg.ID, -32601, "method not found: "+msg.Method))
		}
	})))
	t.Cleanup(up.srv.Close)
	return up
}

func (u *oldRevisionUpstream) seen() []upstreamRequest {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]upstreamRequest(nil), u.requests...)
}

// The bytes the proxy sends a 2025-11-25 upstream. Golden strings rather than a rebuild from
// the same builders the proxy uses: a shared builder would make this cell agree with whatever
// the code does today, which is precisely what a regression net must not do.
const (
	oldLegOpenerBody      = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"capabilities":{},"clientInfo":{"name":"eunox-proxy","version":"1.2.3"},"protocolVersion":"2025-11-25"}}`
	oldLegCompletionBody  = `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	oldLegForwardedParams = `{"name":"read_file","arguments":{"path":"/etc/hosts"}}`
)

// assertOldUpstreamLeg checks the upstream half of the cell: how the leg was opened, how it was
// completed, what header every post-handshake request carried, and that the host's own
// tools/call params crossed untouched.
func assertOldUpstreamLeg(t *testing.T, seen []upstreamRequest) {
	t.Helper()
	if len(seen) < 3 {
		t.Fatalf("upstream saw %d request(s), want the opener, its completion, and the forwarded call: %+v", len(seen), seen)
	}
	if seen[0].body != oldLegOpenerBody {
		t.Errorf("the leg was opened with:\n got: %s\nwant: %s", seen[0].body, oldLegOpenerBody)
	}
	if seen[0].versionHdr != "" {
		t.Errorf("the opener carried MCP-Protocol-Version %q; `initialize` IS the negotiation and precedes the header", seen[0].versionHdr)
	}
	if seen[1].body != oldLegCompletionBody {
		t.Errorf("the handshake was completed with:\n got: %s\nwant: %s", seen[1].body, oldLegCompletionBody)
	}
	for _, req := range seen[1:] {
		if req.versionHdr != capability.Revision20251125.String() {
			t.Errorf("%s carried MCP-Protocol-Version %q, want %q", req.method, req.versionHdr, capability.Revision20251125)
		}
	}
	call := findUpstreamRequest(seen, capability.MethodToolsCall)
	if call == nil {
		t.Fatalf("no tools/call reached the upstream: %+v", seen)
	}
	var forwarded mcp.RPCMsg
	if err := json.Unmarshal([]byte(call.body), &forwarded); err != nil {
		t.Fatalf("the forwarded call does not decode: %v", err)
	}
	// VERBATIM is the property: no `_meta` declaration added on an old leg, no rewriting, no
	// re-ordering of the host's own arguments. The id is the proxy's own nonce, which is why
	// this compares params rather than the whole envelope.
	if string(forwarded.Params) != oldLegForwardedParams {
		t.Errorf("the host's params were rewritten on the way upstream:\n got: %s\nwant: %s", forwarded.Params, oldLegForwardedParams)
	}
}

func findUpstreamRequest(seen []upstreamRequest, method string) *upstreamRequest {
	for i := range seen {
		if seen[i].method == method {
			return &seen[i]
		}
	}
	return nil
}

// hostCallLine is the host's tools/call, written as bytes so the params reaching the upstream
// are the host's own and not a re-marshal.
const hostCallLine = `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/hosts"}}}`

// oldRevisionPolicy permits read_file and nothing else, so the cell covers a filtered
// enumeration and an allowed call rather than a wiretap that forwards everything.
func oldRevisionPolicy() *pdp.ManifestPDP {
	return newTestManifestPDP(capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}})
}

// TestOldRevisionInterop_HTTPTransport is the cell over the HTTP host transport, whose upstream
// leg is the session's own HTTP client.
func TestOldRevisionInterop_HTTPTransport(t *testing.T) {
	// Not parallel: pins proxyVersion, which is package-global and appears in the opener bytes.
	prev := proxyVersion
	t.Cleanup(func() { proxyVersion = prev })
	SetProxyVersion("1.2.3")

	up := newOldRevisionUpstream(t)
	_, srv := newTestRemoteProxy(t, up.srv.URL, httpProxyOptions{PDP: oldRevisionPolicy()})

	sid := initSession(t, srv)
	listResp := decodeRPC(t, postMCP(t, srv, mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`3`), Method: capability.MethodToolsList}, sid))
	if got := string(listResp.Result); got != oldFilteredToolsList {
		t.Errorf("filtered tools/list:\n got: %s\nwant: %s", got, oldFilteredToolsList)
	}

	var call mcp.RPCMsg
	if err := json.Unmarshal([]byte(hostCallLine), &call); err != nil {
		t.Fatalf("decoding the host call: %v", err)
	}
	callResp := decodeRPC(t, postMCP(t, srv, call, sid))
	if got := string(callResp.Result); got != oldAllowedCallResult {
		t.Errorf("allowed call result:\n got: %s\nwant: %s", got, oldAllowedCallResult)
	}

	assertOldUpstreamLeg(t, up.seen())
}

// TestOldRevisionInterop_StdioTransport is the same cell over the stdio host transport, whose
// upstream leg is the remote-HTTP bridge — different code reaching the same opener, which is
// why one cell would not have covered both.
func TestOldRevisionInterop_StdioTransport(t *testing.T) {
	prev := proxyVersion
	t.Cleanup(func() { proxyVersion = prev })
	SetProxyVersion("1.2.3")

	up := newOldRevisionUpstream(t)
	p := NewStdioProxy(StdioProxyOptions{
		UpstreamURL: up.srv.URL,
		PDP:         oldRevisionPolicy(),
		SessionID:   "sess",
		Stderr:      io.Discard,
	})

	// Mirror Start's upstream sequence, then serve the host over a pipe: Start's own host side
	// is os.Stdin/os.Stdout, which a test may not take over.
	ctx := context.Background()
	if err := p.connectUpstream(ctx); err != nil {
		t.Fatalf("connectUpstream: %v", err)
	}
	if err := p.initUpstream(ctx); err != nil {
		t.Fatalf("initUpstream: %v", err)
	}
	p.upstreamDone = make(chan struct{})
	go func() {
		defer close(p.upstreamDone)
		p.readUpstream(ctx)
	}()
	t.Cleanup(p.closeUpstreamInput)

	var hostOut syncBuffer
	pr, pw := io.Pipe()
	p.hostReader = mcp.NewMsgReader(pr)
	p.hostWriter = mcp.NewMsgWriter(&hostOut)
	go writeHostLines(pw, []string{
		`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`,
		hostCallLine,
	}, true)
	p.serveHost(ctx)

	replies := decodeHostLines(t, hostOut.String())
	if len(replies) != 2 {
		t.Fatalf("host received %d reply/replies, want the list and the call: %q", len(replies), hostOut.String())
	}
	if got := string(replies["3"].Result); got != oldFilteredToolsList {
		t.Errorf("filtered tools/list:\n got: %s\nwant: %s", got, oldFilteredToolsList)
	}
	if got := string(replies["2"].Result); got != oldAllowedCallResult {
		t.Errorf("allowed call result:\n got: %s\nwant: %s", got, oldAllowedCallResult)
	}

	assertOldUpstreamLeg(t, up.seen())
}

// The host-facing bytes of the two forwarded methods. The list is FILTERED — delete_all is not
// in the policy — so this also pins that filtering leaves the surviving entry's own bytes
// alone.
const (
	oldFilteredToolsList = `{"tools":[{"name":"read_file","description":"d"}]}`
	oldAllowedCallResult = `{"content":[{"type":"text","text":"ok"}]}`
)

// decodeHostLines splits the host stream into messages keyed by their JSON-RPC id. Keyed
// rather than ordered: serveHost dispatches each request on its own goroutine, so the reply
// order is a scheduling artifact and an ordered assertion would be flaky rather than strict.
func decodeHostLines(t *testing.T, stream string) map[string]mcp.RPCMsg {
	t.Helper()
	out := map[string]mcp.RPCMsg{}
	for _, line := range strings.Split(strings.TrimSpace(stream), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var msg mcp.RPCMsg
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			t.Fatalf("host line %q does not decode: %v", line, err)
		}
		if msg.ID == nil {
			t.Fatalf("host line %q carries no id", line)
		}
		out[string(*msg.ID)] = msg
	}
	return out
}
