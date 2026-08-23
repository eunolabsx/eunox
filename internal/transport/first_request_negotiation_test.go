// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// What a pre-session message is held to is a property of the MESSAGE, not of being sessionless.
//
// ADR-0004 §Addendum (2026-08-23). An `initialize` arm asserts the handshake revision, because
// answering `initialize` IS the negotiation — a declaration naming another revision there
// contradicts the very context the message is opening. Every other pre-session message asserts
// nothing, so its declaration ESTABLISHES a context rather than being checked against one.
//
// Asserted on the leg rather than only end to end, because this is the whole decision in one
// value and the arms that consume it are added over time: a new pre-session arm inherits the
// rule instead of choosing one.
func TestFirstRequestNegotiation_TheAssertedContextIsPerMessage(t *testing.T) {
	t.Parallel()
	assert.Equal(t, handshakeRevision, sessionlessLeg(mcp.RPCMsg{Method: mcp.MethodInitialize}).contextRev,
		"answering initialize is the negotiation, so that arm asserts the revision the handshake lives in")
	assert.Empty(t, sessionlessLeg(mcp.RPCMsg{Method: capability.MethodToolsList}).contextRev,
		"a first message opens a context rather than flipping one; asserting a default refuses a declaring peer for contradicting a context it never opened")
	// A response and a malformed frame carry no method and are not initialize either, so they
	// assert nothing too — which is the safe direction: they establish nothing and reach no
	// upstream on this arm.
	assert.Empty(t, sessionlessLeg(mcp.RPCMsg{}).contextRev)
}

// The property that closes the loop: a declaring host's first request is no longer refused at
// negotiation, and so reaches the arm that will one day mint its session.
//
// This is why a 2026-07-28 host was unservable over HTTP at all — the refusal landed ABOVE
// session creation, so nothing could reach the path that would create one. Driven end to end,
// since "resolves" is only interesting if a real POST gets past the real gate.
func TestFirstRequestNegotiation_ADeclaringHostGetsPastNegotiation(t *testing.T) {
	t.Parallel()
	srv, _, _ := forwardingProxy(t, nil)

	resp := declaringHostPOST(t, srv, capability.MethodToolsList)
	t.Cleanup(func() { _ = resp.Body.Close() })
	body := new(bytes.Buffer)
	_, _ = body.ReadFrom(resp.Body)

	assert.NotContains(t, body.String(), capability.ErrCodeUnsupportedProtocolVersion,
		"a first message cannot contradict a context it never opened; refusing it here is what made a declaring host unservable")
	assert.Equal(t, http.StatusNotImplemented, resp.StatusCode,
		"it reaches the arm's own refusal, which is where session creation on first request will land")
}

// Omission still resolves to the surface eunox already shipped. This is the half that must NOT
// change: if silence reached the newer table, leaving a declaration out would become a way to
// pick a method set the peer never negotiated.
func TestFirstRequestNegotiation_OmissionStillLandsOnTheOldRevision(t *testing.T) {
	t.Parallel()
	rev, err := resolveHostRevision("", "", mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsList,
	})
	require.NoError(t, err)
	assert.Equal(t, capability.DefaultRevision, rev,
		"an undeclared first message must not reach a newer method set by saying nothing")

	// End to end: the old-revision refusal, unchanged, is what an undeclared POST still gets.
	srv, _, _ := forwardingProxy(t, nil)
	resp := hostPOST(t, srv, capability.MethodToolsList, nil)
	t.Cleanup(func() { _ = resp.Body.Close() })
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// The `initialize` arms are untouched, in both framings: a declaration naming any other revision
// there still contradicts the context answering `initialize` establishes.
//
// Both framings, because they are separate arms — the session-creating REQUEST and the
// swallowed NOTIFICATION — and the rule they share is the message's, not the arm's.
func TestFirstRequestNegotiation_InitializeArmsStillAssertTheHandshakeRevision(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		id   *json.RawMessage
	}{
		{"request", mcp.RawJSON(`1`)},
		{"notification", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv, _, _ := forwardingProxy(t, nil)
			body, err := json.Marshal(mcp.RPCMsg{
				JSONRPC: "2.0", ID: tc.id, Method: mcp.MethodInitialize,
				Params: json.RawMessage(
					`{"protocolVersion":"2025-11-25","capabilities":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}`),
			})
			require.NoError(t, err)
			req, err := http.NewRequest(http.MethodPost, srv.URL+"/mcp", bytes.NewReader(body))
			require.NoError(t, err)
			req.Header.Set("Content-Type", CTJSON)
			resp, err := srv.Client().Do(req)
			require.NoError(t, err)
			t.Cleanup(func() { _ = resp.Body.Close() })

			got := new(bytes.Buffer)
			_, _ = got.ReadFrom(resp.Body)
			assert.Empty(t, resp.Header.Get(SessionHeader),
				"a refused initialize must not establish a session")
			if tc.id == nil {
				// A notification gets no body, so the refusal shows as the absence of a session
				// and of an ack of readiness; the record is what carries the code.
				assert.NotEqual(t, http.StatusOK, resp.StatusCode)
				return
			}
			assert.Contains(t, got.String(), capability.ErrCodeUnsupportedProtocolVersion,
				"answering initialize IS the negotiation; a declaration naming another revision contradicts it")
		})
	}
}

// The mid-context flip refusal is untouched and governs from the SECOND message on — which is
// where a peer probing for the more permissive table actually lives.
//
// This is the property that makes relaxing the FIRST message safe: establishing is not flipping,
// and only establishing was relaxed.
func TestFirstRequestNegotiation_TheFlipRefusalStillGovernsAfterTheFirstMessage(t *testing.T) {
	t.Parallel()
	srv, proxy, _ := forwardingProxy(t, nil)
	sid := initSession(t, srv)
	require.NotNil(t, proxy.getSession(sid))

	body, err := json.Marshal(mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`2`), Method: capability.MethodToolsCall,
		Params: json.RawMessage(
			`{"name":"read_file","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}`),
	})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/mcp", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", CTJSON)
	req.Header.Set(SessionHeader, sid)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })

	got := new(bytes.Buffer)
	_, _ = got.ReadFrom(resp.Body)
	assert.Contains(t, got.String(), capability.ErrCodeUnsupportedProtocolVersion,
		"a session established at one revision must still refuse a later message declaring another")
}

// W3's routing-header check becomes REACHABLE on this arm, which is the first place it can run
// against a real declaring peer over HTTP.
//
// Worth its own cell because the check is revision-gated: while a declaring host was refused at
// negotiation, nothing on this transport ever reached it, and a check no traffic reaches is a
// check whose first real exercise is in production.
func TestFirstRequestNegotiation_RoutingHeadersAreCheckedOnADeclaringFirstRequest(t *testing.T) {
	t.Parallel()
	srv, _, _ := forwardingProxy(t, nil)

	body, err := json.Marshal(mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsCall,
		Params: json.RawMessage(
			`{"name":"read_file","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}`),
	})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/mcp", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", CTJSON)
	req.Header.Set(RoutingHeaderMethod, capability.MethodToolsCall)
	req.Header.Set(RoutingHeaderName, "some_other_tool") // disagrees with the body
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })

	got := new(bytes.Buffer)
	_, _ = got.ReadFrom(resp.Body)
	assert.Contains(t, got.String(), capability.ErrCodeHeaderMismatch,
		"a declaring peer now gets past negotiation, so its routing headers are held to its body")
}
