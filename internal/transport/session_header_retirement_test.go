// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// 2026-07-28 removed `Mcp-Session-Id`. An upstream on that revision has no session for eunox to
// hold, so an id it sends anyway is not captured — and therefore never stamped back on later
// requests, which would be eunox re-introducing, in its own name, the state the revision sheds.
//
// Driven against a real leg on each revision rather than asserted about the predicate: what
// matters is whether the header goes back out, and only the round trip can show that.
func TestSessionHeaderRetirement_UpstreamIDIsCapturedOnlyOnTheOldRevision(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		rev        capability.Revision
		wantEchoed string
	}{
		{capability.Revision20251125, "upstream-session-1"},
		{capability.Revision20260728, ""},
	} {
		t.Run(tc.rev.String(), func(t *testing.T) {
			t.Parallel()
			var second http.Header
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if calls == 2 {
					second = r.Header.Clone()
				}
				// A lenient upstream that hands one out regardless of revision, which is the
				// case worth covering: a conformant 2026-07-28 upstream sends none anyway, so
				// gating on what the upstream does would prove nothing about eunox.
				w.Header().Set(SessionHeader, "upstream-session-1")
				w.Header().Set("Content-Type", CTJSON)
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
			}))
			t.Cleanup(srv.Close)

			up := newHTTPUpstream(context.Background(), srv.URL, "", false, 0)
			t.Cleanup(up.close)
			up.setRevision(tc.rev)

			// First call establishes (or does not establish) the id; the second is where it
			// would be stamped back.
			opener := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: mcp.MethodInitialize}
			require.NoError(t, up.writeSync(context.Background(), opener))
			_, _, err := up.do(context.Background(), mcp.RPCMsg{
				JSONRPC: "2.0", ID: mcp.RawJSON(`2`), Method: capability.MethodToolsList,
			})
			require.NoError(t, err)
			require.NotNil(t, second, "the second call never reached the upstream")

			assert.Equal(t, tc.wantEchoed, second.Get(SessionHeader),
				"a %s leg must%s stamp the upstream session header", tc.rev, map[bool]string{true: " not", false: ""}[tc.wantEchoed == ""])
		})
	}
}

// UpstreamSessionID is the one place the question is asked, and it answers "" for anything that
// is not an old-revision leg with a header in hand. A nil header is the transport-error case,
// where there is nothing to read.
func TestSessionHeaderRetirement_TheReaderIsTheOnlyGate(t *testing.T) {
	t.Parallel()
	withID := http.Header{SessionHeader: []string{"sid"}}
	assert.Equal(t, "sid", UpstreamSessionID(capability.Revision20251125, withID))
	assert.Empty(t, UpstreamSessionID(capability.Revision20260728, withID),
		"a revision that retired the header must yield no session to hold")
	assert.Empty(t, UpstreamSessionID(capability.Revision20251125, nil))
	assert.Empty(t, UpstreamSessionID(capability.Revision20251125, http.Header{}))
}

// No response to a declaring host carries the retired header.
//
// The `initialize` cell is the one that could: it is the single host-leg path that emits
// `Mcp-Session-Id`, and it is answered OUTSIDE dispatchRequest. What keeps it from emitting for
// a declaring peer is that answering `initialize` IS the negotiation, so a 2026-07-28
// declaration on it is refused — a structural fact worth pinning, since the day session
// creation moves the emission would silently follow it.
func TestSessionHeaderRetirement_NoDeclaringResponseCarriesTheHeader(t *testing.T) {
	t.Parallel()
	srv, _, _ := forwardingProxy(t, nil)

	for _, method := range []string{mcp.MethodInitialize, capability.MethodToolsList, capability.MethodToolsCall} {
		t.Run(method, func(t *testing.T) {
			resp := declaringHostPOST(t, srv, method)
			t.Cleanup(func() { _ = resp.Body.Close() })
			assert.Empty(t, resp.Header.Get(SessionHeader),
				"a response to a %s host carried the header that revision retired", capability.Revision20260728)
		})
	}
}

// And the refusal a declaring host gets does not demand the retired header back.
//
// This cell was written in W3 to change as the D3 work landed, and it has twice: first when a
// declaring peer stopped being turned away above this arm, and again now that the arm CREATES a
// session rather than refusing for want of one. What it pins across both is the invariant that
// outlives them — a 2026-07-28 host is never told to send `Mcp-Session-Id`, a header its revision
// removed and a conformant client cannot produce. This request is refused for presenting no
// identity, which is a fact about the credential and not about a session header.
func TestSessionHeaderRetirement_TheSessionlessRefusalDoesNotDemandARetiredHeader(t *testing.T) {
	t.Parallel()
	srv, _, _ := forwardingProxy(t, nil)

	resp := declaringHostPOST(t, srv, capability.MethodToolsList)
	t.Cleanup(func() { _ = resp.Body.Close() })
	body := new(bytes.Buffer)
	_, _ = body.ReadFrom(resp.Body)

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"a declaring host's request is not malformed; this one presented no identity to key a worker on")
	assert.NotContains(t, body.String(), SessionHeader,
		"the refusal instructs a 2026-07-28 host to send a header its revision removed")
	assert.Contains(t, body.String(), "credential")

	// The old revision is unchanged: it still gets the 400 naming the header it really does
	// need, which is this release's regression invariant.
	old := hostPOST(t, srv, capability.MethodToolsList, nil)
	t.Cleanup(func() { _ = old.Body.Close() })
	oldBody := new(bytes.Buffer)
	_, _ = oldBody.ReadFrom(old.Body)
	assert.Equal(t, http.StatusBadRequest, old.StatusCode)
	assert.Contains(t, oldBody.String(), SessionHeader)
}

// A sessionless POST is negotiated before it is refused, so a declaration this build cannot
// honor is recorded as UNSUPPORTED_PROTOCOL_VERSION here exactly as on every other arm.
//
// This was the one host-leg refusal taken ahead of the revision: identical bytes got a bare 400
// with nothing on the tape, which is the gate order dispatch.go states being violated in the one
// place no test looked.
func TestSessionHeaderRetirement_SessionlessPostNegotiatesFirst(t *testing.T) {
	t.Parallel()
	srv, _, _ := forwardingProxy(t, nil)

	resp := hostPOST(t, srv, capability.MethodToolsList, json.RawMessage(
		`{"_meta":{"io.modelcontextprotocol/protocolVersion":"1999-01-01"}}`))
	t.Cleanup(func() { _ = resp.Body.Close() })
	body := new(bytes.Buffer)
	_, _ = body.ReadFrom(resp.Body)

	assert.Contains(t, body.String(), capability.ErrCodeUnsupportedProtocolVersion,
		"an unhonorable declaration on a sessionless POST was refused before it was negotiated")
}

// declaringHostPOST makes one sessionless POST from a 2026-07-28 host, routing headers included
// so the refusal under test is the session one rather than W3's own header check.
func declaringHostPOST(t *testing.T, srv *httptest.Server, method string) *http.Response {
	t.Helper()
	return hostPOST(t, srv, method, json.RawMessage(
		`{"name":"read_file","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}`))
}

// hostPOST makes one sessionless POST with the given params, carrying the routing headers the
// body implies so a declaring cell is not refused for the wrong reason.
func hostPOST(t *testing.T, srv *httptest.Server, method string, params json.RawMessage) *http.Response {
	t.Helper()
	body, err := json.Marshal(mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: method, Params: params})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/mcp", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", CTJSON)
	req.Header.Set(RoutingHeaderMethod, method)
	if method == capability.MethodToolsCall {
		req.Header.Set(RoutingHeaderName, "read_file")
	}
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	return resp
}
