// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// declaringPOST builds a 2026-07-28 request body: the per-request `_meta` declaration is what
// puts the message on the revision that defines the routing headers, so every cell below is
// exercising the same gate a real declaring peer would.
func declaringPOST(t *testing.T, method string, params map[string]interface{}) mcp.RPCMsg {
	t.Helper()
	if params == nil {
		params = map[string]interface{}{}
	}
	params["_meta"] = map[string]interface{}{
		capability.MetaKeyProtocolVersion: capability.Revision20260728.String(),
	}
	raw, err := json.Marshal(params)
	require.NoError(t, err)
	return mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: method, Params: raw}
}

// headerRequest builds the HTTP request carrying a routing-header pair. An empty value means
// the header is ABSENT, which is a distinct cell from one carrying the wrong value.
func headerRequest(method, name string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{}"))
	if method != "" {
		r.Header.Set(RoutingHeaderMethod, method)
	}
	if name != "" {
		r.Header.Set(RoutingHeaderName, name)
	}
	return r
}

// The mismatch matrix: every way a routing-header pair can fail to describe the body it
// travelled with.
//
// Each row is a request eunox would otherwise FORWARD with its halves disagreeing. eunox's own
// decision is unaffected — it has always decided on the body — so what these cells protect is
// every downstream reader that trusts the cheap half: an upstream routing on the header, a
// sidecar metering on it, a log correlating on it. One of them acting on the header while the
// upstream executes the body is the confusion this refusal exists to catch once.
func TestRoutingHeaders_MismatchMatrix(t *testing.T) {
	t.Parallel()
	call := declaringPOST(t, capability.MethodToolsCall, map[string]interface{}{"name": "read_file"})
	read := declaringPOST(t, capability.MethodResourcesRead, map[string]interface{}{"uri": "file:///a"})
	list := declaringPOST(t, capability.MethodToolsList, nil)

	cases := []struct {
		name       string
		msg        mcp.RPCMsg
		hdrMethod  string
		hdrName    string
		wantHeader string
	}{
		{
			// The sharpest cell: the header names a method a metering sidecar would count,
			// while the body invokes another.
			name: "method header names a different method", msg: call,
			hdrMethod: capability.MethodToolsList, hdrName: "read_file", wantHeader: RoutingHeaderMethod,
		},
		{
			name: "method header absent", msg: call,
			hdrMethod: "", hdrName: "read_file", wantHeader: RoutingHeaderMethod,
		},
		{
			// The name half of the same confusion: the call executes against one tool and is
			// attributed to another.
			name: "name header names a different tool", msg: call,
			hdrMethod: capability.MethodToolsCall, hdrName: "write_file", wantHeader: RoutingHeaderName,
		},
		{
			name: "name header absent for a method that addresses a target", msg: call,
			hdrMethod: capability.MethodToolsCall, hdrName: "", wantHeader: RoutingHeaderName,
		},
		{
			name: "name header names a different resource", msg: read,
			hdrMethod: capability.MethodResourcesRead, hdrName: "file:///b", wantHeader: RoutingHeaderName,
		},
		{
			name: "name header absent for a resource read", msg: read,
			hdrMethod: capability.MethodResourcesRead, hdrName: "", wantHeader: RoutingHeaderName,
		},
		{
			// A value sent for a method that names nothing is still a claim a downstream
			// reader may act on, so it must agree or be refused rather than ignored.
			name: "name header sent for an enumeration that addresses nothing", msg: list,
			hdrMethod: capability.MethodToolsList, hdrName: "read_file", wantHeader: RoutingHeaderName,
		},
		{
			// Malformed in the way that matters: a header whose value is a different method
			// entirely, not merely misspelled. Case is significant in a JSON-RPC method name.
			name: "method header differs only in case", msg: call,
			hdrMethod: strings.ToUpper(capability.MethodToolsCall), hdrName: "read_file", wantHeader: RoutingHeaderMethod,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := checkRoutingHeaders(capability.Revision20260728, headerRequest(tc.hdrMethod, tc.hdrName), tc.msg)
			require.Error(t, err, "a disagreeing pair must be refused, not forwarded")

			var m headerMismatch
			require.True(t, asHeaderMismatch(err, &m), "the refusal must be a typed mismatch so the record and the wire agree")
			assert.Equal(t, tc.wantHeader, m.header, "the refusal must name the header that disagreed")
			assert.Equal(t, map[string]interface{}{detailMismatchedHeader: strings.ToLower(tc.wantHeader)},
				headerMismatchDetail(err), "the audit detail names which header, never the value it carried")
		})
	}
}

// The other half of the matrix: pairs that AGREE must pass, or the check refuses ordinary
// traffic. Without these rows the matrix above is satisfied by a function that refuses
// everything.
func TestRoutingHeaders_AgreeingPairsPass(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		msg       mcp.RPCMsg
		hdrMethod string
		hdrName   string
	}{
		{"a tool call naming its tool", declaringPOST(t, capability.MethodToolsCall,
			map[string]interface{}{"name": "read_file"}), capability.MethodToolsCall, "read_file"},
		{"a resource read naming its uri", declaringPOST(t, capability.MethodResourcesRead,
			map[string]interface{}{"uri": "file:///a"}), capability.MethodResourcesRead, "file:///a"},
		{"a prompt get naming its prompt", declaringPOST(t, capability.MethodPromptsGet,
			map[string]interface{}{"name": "review"}), capability.MethodPromptsGet, "review"},
		{"an enumeration with no name header", declaringPOST(t, capability.MethodToolsList, nil),
			capability.MethodToolsList, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.NoError(t, checkRoutingHeaders(capability.Revision20260728,
				headerRequest(tc.hdrMethod, tc.hdrName), tc.msg))
		})
	}
}

// A 2025-11-25 peer is untouched: that revision defines no routing headers, so requiring or
// reading them would refuse ordinary traffic and break the release's own regression invariant.
//
// Driven with a pair that WOULD be refused on the newer revision, so the row is about the
// revision gate rather than about the pair happening to agree.
func TestRoutingHeaders_OldRevisionIsUnchecked(t *testing.T) {
	t.Parallel()
	msg := mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`1`),
		Method: capability.MethodToolsCall,
		Params: json.RawMessage(`{"name":"read_file"}`),
	}
	r := headerRequest(capability.MethodToolsList, "write_file")

	require.Error(t, checkRoutingHeaders(capability.Revision20260728, r, msg),
		"precondition: this pair is refused on the revision that defines the headers")
	assert.NoError(t, checkRoutingHeaders(capability.Revision20251125, r, msg),
		"a 2025-11-25 peer has no routing headers, so there is nothing to hold it to")
	assert.NoError(t, checkRoutingHeaders(capability.DefaultRevision, r, msg),
		"and neither does an unnegotiated context, which resolves to the surface eunox already shipped")
}

// A host RESPONSE carries no method to route on, so the revision requires no routing headers for
// one. Refusing it would break the server-initiated leg's reply path for every declaring peer.
func TestRoutingHeaders_ResponseCarriesNoRoutingHeaders(t *testing.T) {
	t.Parallel()
	resp := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Result: json.RawMessage(`{}`)}
	assert.NoError(t, checkRoutingHeaders(capability.Revision20260728, headerRequest("", ""), resp))
}

// Unreadable params are the dispatcher's refusal to make, not this check's: it decodes the same
// bytes and denies them with a target-bearing INVALID_REQUEST, which says more than a header
// complaint about a malformed body would.
func TestRoutingHeaders_MalformedParamsAreLeftToTheDispatcher(t *testing.T) {
	t.Parallel()
	msg := mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`1`),
		Method: capability.MethodToolsCall,
		// A duplicate key, which mcp.DecodeParams refuses at every depth.
		Params: json.RawMessage(`{"name":"a","name":"b"}`),
	}
	assert.NoError(t, checkRoutingHeaders(capability.Revision20260728,
		headerRequest(capability.MethodToolsCall, "a"), msg),
		"the header check must not pre-empt the dispatcher's own, richer refusal")
}

// A peer must not be able to size the refusal it provoked. The value is quoted back for
// diagnosis, so it takes the bound and the control-strip every foreign value takes before it
// becomes part of an error string — this is a pre-authentication path an attacker probing the
// boundary controls the rate of.
func TestRoutingHeaders_ReflectedValueIsBoundedAndStripped(t *testing.T) {
	t.Parallel()
	hostile := strings.Repeat("A", 8192) + "\r\n[eunox] SECURITY: forged line"
	msg := declaringPOST(t, capability.MethodToolsCall, map[string]interface{}{"name": "read_file"})

	err := checkRoutingHeaders(capability.Revision20260728,
		headerRequest(capability.MethodToolsCall, hostile), msg)
	require.Error(t, err)

	got := err.Error()
	assert.Less(t, len(got), 1024, "an unbounded header let the peer size the refusal it provoked")
	assert.NotContains(t, got, "\n", "a newline lets an upstream forge a log line")
	assert.NotContains(t, got, "\r")
	assert.NotContains(t, got, " ", "U+2028 is a line terminator to a terminal even though unicode.IsControl says otherwise")

	// The audit detail names the header, never the value: an attacker-chosen string in a signed
	// structured field buys nothing the wire message does not already say.
	detail := headerMismatchDetail(err)
	require.NotNil(t, detail)
	assert.NotContains(t, fmt.Sprint(detail), "AAAA", "the peer's value must not reach the tape")
}

// The refusal's wire code and its symbolic code must agree, and the integer must be the
// specification's -32020 rather than the -32022 its sibling refusal shares.
//
// Asserted against the real classifier rather than a restatement of it: the two refusals are
// built by neighbouring functions, and reusing the revision builder here would have shipped a
// HEADER_MISMATCH on the revision integer.
func TestRoutingHeaders_RefusalCarriesTheSpecCode(t *testing.T) {
	t.Parallel()
	resp := mcp.HeaderMismatchResponse(mcp.RawJSON(`1`), "the Mcp-Method header says something else")
	require.NotNil(t, resp.Error)

	wire, ok := capability.DenialWireCode(capability.ErrCodeHeaderMismatch)
	require.True(t, ok)
	assert.Equal(t, capability.JSONRPCCodeHeaderMismatch, resp.Error.Code)
	assert.Equal(t, wire, resp.Error.Code, "the wire integer must come from the one mapping that owns it")
	assert.NotEqual(t, capability.JSONRPCCodeUnsupportedProtocolVersion, resp.Error.Code,
		"a header mismatch is not a revision problem; sharing that integer would tell a host the wrong thing")
	assert.Contains(t, resp.Error.Message, capability.ErrCodeHeaderMismatch,
		"the greppable prefix and data.code must not disagree")
	assert.Contains(t, string(resp.Error.Data), capability.ErrCodeHeaderMismatch)
	assert.NotContains(t, string(resp.Error.Data), "supported",
		"a header mismatch must not advertise supported revisions; the peer asked no revision question")

	// A notification carries no id, so JSON-RPC forbids a reply and the refusal is acked
	// bodyless rather than written as a frame with no id.
	notif := mcp.RPCMsg{JSONRPC: "2.0", Method: capability.MethodToolsCall}
	assert.True(t, refuseHeaderMismatch(context.Background(), nil, "", notif,
		headerMismatch{header: RoutingHeaderMethod, reason: "was not sent"}).IsZero(),
		"a notification's refusal must be acked bodyless, never written as a JSON-RPC frame")
}

// The check is applied at the one adapter every POST arm calls, so a fourth arm cannot forward
// a disagreeing pair by forgetting to ask.
//
// A source guard because the failure is silent: an arm that skipped it would serve ordinary
// traffic correctly and only differ for the request this refusal exists to catch.
func TestRoutingHeaders_CheckedInsideTheOneNegotiationAdapter(t *testing.T) {
	t.Parallel()
	var found bool
	for _, src := range packageSources(t) {
		ast.Inspect(src.file, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Name.Name != "negotiateHostRevision" || fn.Recv == nil {
				return true
			}
			ast.Inspect(fn, func(inner ast.Node) bool {
				call, ok := inner.(*ast.CallExpr)
				if !ok {
					return true
				}
				if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "checkRoutingHeaders" {
					found = true
				}
				return true
			})
			return false
		})
	}
	assert.True(t, found,
		"negotiateHostRevision no longer checks the routing headers; every POST arm calls it, and no arm checks them itself")
}

// capturingUpstream is an upstream that records the headers of the last POST it received and
// answers a minimal result, so a test can read the pair eunox actually put on the wire rather
// than the pair a helper claims it would.
func capturingUpstream(t *testing.T) (srv *httptest.Server, lastHeaders func() http.Header) {
	t.Helper()
	var mu sync.Mutex
	var last http.Header
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		last = r.Header.Clone()
		mu.Unlock()
		w.Header().Set("Content-Type", CTJSON)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	t.Cleanup(srv.Close)
	return srv, func() http.Header {
		mu.Lock()
		defer mu.Unlock()
		return last
	}
}

// The pair eunox emits upstream is the pair its own inbound check accepts.
//
// This is the property the emission half exists for, and it is DRIVEN rather than asserted
// about: for every message shape a declaring leg forwards, the headers are stamped by the real
// producer and then handed to the real verifier. Two hand-written tables — one of what is
// emitted, one of what is accepted — could agree today and drift the first time either side
// learns a new method; one derivation checked against itself cannot.
func TestRoutingHeaders_EmittedPairSatisfiesTheInboundCheck(t *testing.T) {
	t.Parallel()
	msgs := []mcp.RPCMsg{
		declaringPOST(t, capability.MethodToolsCall, map[string]interface{}{"name": "read_file"}),
		declaringPOST(t, capability.MethodToolsList, nil),
		declaringPOST(t, capability.MethodResourcesRead, map[string]interface{}{"uri": "file:///etc/hosts"}),
		declaringPOST(t, capability.MethodPromptsGet, map[string]interface{}{"name": "summarize"}),
		declaringPOST(t, capability.MethodResourcesList, nil),
		{JSONRPC: "2.0", Method: mcp.MethodNotificationsInitialized},
	}
	named := 0
	for _, msg := range msgs {
		t.Run(msg.Method, func(t *testing.T) {
			out := httptest.NewRequest(http.MethodPost, "http://upstream.invalid/mcp", http.NoBody)
			require.NoError(t, setRoutingHeaders(out, capability.Revision20260728, msg),
				"a message eunox forwards must be expressible in the headers its revision requires")
			require.NotEmpty(t, out.Header.Get(RoutingHeaderMethod),
				"the revision requires Mcp-Method on every POST that names a method")
			if out.Header.Get(RoutingHeaderName) != "" {
				named++
			}
			// The emitted request read back through the verifier, which is what a conformant
			// intermediary between eunox and the upstream would apply.
			assert.NoError(t, checkRoutingHeaders(capability.Revision20260728, out, msg),
				"eunox emitted a pair its own check refuses")
		})
	}
	// Not vacuous: an emitter that never set Mcp-Name would satisfy every cell above, since the
	// check only demands one for a target-addressing method.
	assert.GreaterOrEqual(t, named, 3, "no target-addressing message carried Mcp-Name; the name half was never exercised")
}

// The headers are derived from the body eunox is SENDING, never relayed from the one it
// received. A `*/list` the filter narrowed, a stdio host's message that never had headers, and
// eunox's own opener are all requests whose inbound pair does not describe what goes out.
func TestRoutingHeaders_EmittedFromTheOutboundBodyNotTheInboundHeaders(t *testing.T) {
	t.Parallel()
	srv, lastHeaders := capturingUpstream(t)

	// The body says read_file; a relaying proxy would carry whatever a host claimed.
	msg := declaringPOST(t, capability.MethodToolsCall, map[string]interface{}{"name": "read_file"})
	_, _, err := DoMCPHTTP(context.Background(), srv.Client(), srv.URL, msg, "", "", capability.Revision20260728)
	require.NoError(t, err)

	got := lastHeaders()
	assert.Equal(t, capability.MethodToolsCall, got.Get(RoutingHeaderMethod))
	assert.Equal(t, "read_file", got.Get(RoutingHeaderName))
}

// A leg on the revision that has no such headers must be byte-identical to before: emitting
// them would be eunox inventing a requirement its upstream never agreed to, and this release's
// regression invariant is that 2025-11-25 traffic is unchanged.
func TestRoutingHeaders_OldRevisionUpstreamGetsNeither(t *testing.T) {
	t.Parallel()
	srv, lastHeaders := capturingUpstream(t)

	msg := mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsCall,
		Params: json.RawMessage(`{"name":"read_file"}`),
	}
	_, _, err := DoMCPHTTP(context.Background(), srv.Client(), srv.URL, msg, "", "", capability.Revision20251125)
	require.NoError(t, err)

	got := lastHeaders()
	assert.Empty(t, got.Get(RoutingHeaderMethod))
	assert.Empty(t, got.Get(RoutingHeaderName))
}

// A forwarded host RESPONSE names no method, so there is nothing to route on and neither header
// is claimed. Emission gates on the absence of a method rather than on the response shape: the
// two agree here, and the gate that generalizes is the one that cannot state a route it lacks.
func TestRoutingHeaders_ForwardedResponseClaimsNoRoute(t *testing.T) {
	t.Parallel()
	out := httptest.NewRequest(http.MethodPost, "http://upstream.invalid/mcp", http.NoBody)
	resp := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`7`), Result: json.RawMessage(`{}`)}
	require.NoError(t, setRoutingHeaders(out, capability.Revision20260728, resp))
	assert.Empty(t, out.Header.Get(RoutingHeaderMethod))
	assert.Empty(t, out.Header.Get(RoutingHeaderName))
}

// A target eunox cannot express in a header fails the CALL, and fails it before anything is
// sent.
//
// The alternative is worse than it looks: truncating or escaping the value to fit would
// MANUFACTURE the header/body disagreement this file refuses inbound, with eunox's signature on
// it. Letting net/http reject it later would be fail-closed too, but the upstream would already
// have been contacted on some paths and the operator would get a generic write error naming no
// header.
func TestRoutingHeaders_UnsendableTargetRefusesBeforeContactingTheUpstream(t *testing.T) {
	t.Parallel()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", CTJSON)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	t.Cleanup(srv.Close)

	// A tool name that would forge a second header line if it were ever emitted verbatim.
	msg := declaringPOST(t, capability.MethodToolsCall, map[string]interface{}{
		"name": "read_file\r\nX-Injected: yes",
	})
	_, _, err := DoMCPHTTP(context.Background(), srv.Client(), srv.URL, msg, "", "", capability.Revision20260728)
	require.Error(t, err, "a target that cannot be sent as a header must fail the call, not be altered to fit")
	assert.Contains(t, err.Error(), RoutingHeaderName, "the refusal must name the header that could not be sent")
	assert.NotContains(t, err.Error(), "\r\n", "the rejected value reaches an operator's console; it must not carry the bytes it was rejected for")
	assert.Zero(t, atomic.LoadInt32(&hits), "the upstream was contacted for a request eunox could not describe honestly")
}

// eunox accepts a routing-header value if and only if it survives an HTTP header BYTE-EXACT.
//
// Both directions matter and they fail differently. Accept something the transport will not
// write, and the refusal stops being what catches it: the call fails anyway, but as a generic
// transport error naming no header and after the connection is up. Accept something the
// transport ALTERS, and the header stops describing the body — the disagreement this file exists
// to prevent, manufactured by eunox itself. Refuse something that would have survived, and
// legitimate traffic is rejected.
//
// The altering case is the one a naive probe misses. net/http trims leading and trailing spaces
// and tabs off every value it writes, and reports no error doing it, so `" read_file "` is
// "accepted" by the transport and arrives as `"read_file"`. (Nor does (*http.Request).Write
// validate at all — it runs values through a newline-to-space replacer, so even CRLF comes out
// silently altered and looks fine. Only a real round trip through Transport shows either.)
func TestRoutingHeaders_SendabilityMatchesWhatSurvivesTheWire(t *testing.T) {
	t.Parallel()
	srv, lastHeaders := capturingUpstream(t)

	for _, v := range []string{
		"read_file", "file:///etc/hosts", "tool with spaces", "caf\u00e9-tool", "a\tb",
		"read\r\nX-Injected: 1", "read\nX", "read\rX", "read\x00file", "read\x7ffile", "\x1b[31mred",
		" read_file", "read_file ", " read_file ", "\tread_file", "read_file\t",
	} {
		t.Run(fmt.Sprintf("%q", v), func(t *testing.T) {
			out := httptest.NewRequest(http.MethodPost, srv.URL, http.NoBody)
			ourVerdict := setRoutingHeader(out, RoutingHeaderName, v) == nil

			probe, err := http.NewRequest(http.MethodPost, srv.URL, http.NoBody)
			require.NoError(t, err)
			probe.Header[RoutingHeaderName] = []string{v} // bypass Set: the point is what the WIRE does
			resp, rtErr := srv.Client().Do(probe)
			if resp != nil {
				_ = resp.Body.Close()
			}
			survivesVerbatim := rtErr == nil && lastHeaders().Get(RoutingHeaderName) == v

			assert.Equal(t, survivesVerbatim, ourVerdict,
				"eunox accepts a routing-header value exactly when it survives the wire byte-exact; "+
					"accepted=%v, survives=%v (transport error %v)", ourVerdict, survivesVerbatim, rtErr)
		})
	}
}

// A target the body names but no HTTP header can carry is refused for THAT reason — on both
// legs, and neither by trimming it nor by reporting a mismatch it did not cause.
//
// The inbound half is the subtle one. Go's server trims a header value on the way IN, so a host
// whose target genuinely ends in a space cannot make Mcp-Name equal it: the comparison always
// fails, and reporting "which is not the target this body addresses" blames the host for a
// difference its own HTTP stack created. Refusing as inexpressible is the honest answer — and
// still a refusal, because every downstream reader of that header would be told a different
// target than the body names, and there is no header eunox could send that would not mislead.
func TestRoutingHeaders_ATargetNoHeaderCanCarryIsRefusedAsSuch(t *testing.T) {
	t.Parallel()
	for _, target := range []string{"read_file ", " read_file", "read\tfile\t", "read\nfile"} {
		t.Run(fmt.Sprintf("%q", target), func(t *testing.T) {
			t.Parallel()
			msg := declaringPOST(t, capability.MethodToolsCall, map[string]interface{}{"name": target})

			// Inbound: the header carries what a conformant host's stack would actually send —
			// the trimmed form — so a naive comparison reports a mismatch.
			inbound := headerRequest(capability.MethodToolsCall, strings.TrimSpace(target))
			err := checkRoutingHeaders(capability.Revision20260728, inbound, msg)
			require.Error(t, err, "a target no header can carry must not be forwarded")
			assert.Contains(t, err.Error(), "does not survive an HTTP header field verbatim",
				"the refusal blames the host for a difference its HTTP stack created")

			// Outbound: the call fails before anything is sent, rather than emitting a trimmed
			// header that names something the body does not.
			out := httptest.NewRequest(http.MethodPost, "http://upstream.invalid/mcp", http.NoBody)
			assert.Error(t, setRoutingHeaders(out, capability.Revision20260728, msg))
			assert.Empty(t, out.Header.Get(RoutingHeaderName), "a refused value must not be left on the request")
		})
	}
}

// The record names the target the BODY addressed.
//
// This is the fact both the code comment and the threat model rest on when they justify leaving
// the attacker-chosen header VALUE off the signed record: the operator can still correlate,
// because the real target is there. auditIdentity alone cannot supply it — it holds only the
// method and blanks the identifier for exactly the target-resolving methods an Mcp-Name mismatch
// is reachable on — so without this the record carried neither target and the justification was
// false.
func TestRoutingHeaders_RefusalRecordNamesTheBodysTarget(t *testing.T) {
	t.Parallel()
	msg := declaringPOST(t, capability.MethodToolsCall, map[string]interface{}{"name": "read_file"})
	err := checkRoutingHeaders(capability.Revision20260728,
		headerRequest(capability.MethodToolsCall, "some_other_tool"), msg)
	require.Error(t, err)

	// Asserted on the RECORD the refusal path actually writes, not on the helper: a helper that
	// resolves the target while refuseHeaderMismatch keeps calling auditIdentity leaves the tape
	// exactly as empty as before, with a green test over the part that was never wrong.
	sink, logPath := newTempAuditSink(t)
	refuseHeaderMismatch(context.Background(), asRecorder(sink), "sess-1", msg, err)
	require.NoError(t, sink.Close())

	rec := findAuditRecordByCode(readAuditRecords(t, logPath), capability.ErrCodeHeaderMismatch)
	require.NotNil(t, rec, "the refusal wrote no record")
	assert.Equal(t, "read_file", rec["target"],
		"the record must name the target the body carried, which is what an operator correlates on — "+
			"and is the whole justification for leaving the attacker-chosen header value off it")

	// A method that addresses nothing named acquires no target — auditIdentity's own answer
	// stands. `tools/list` resolves a target TYPE without naming an entry in it, which is the
	// case auditIdentity blanks so a catalog read is never stamped with a tool named after the
	// method it arrived as. The peer's invented header value must not become that target either.
	listMsg := declaringPOST(t, capability.MethodToolsList, nil)
	listErr := checkRoutingHeaders(capability.Revision20260728,
		headerRequest(capability.MethodToolsList, "invented"), listMsg)
	require.Error(t, listErr)
	listSink, listPath := newTempAuditSink(t)
	refuseHeaderMismatch(context.Background(), asRecorder(listSink), "sess-1", listMsg, listErr)
	require.NoError(t, listSink.Close())
	listRec := findAuditRecordByCode(readAuditRecords(t, listPath), capability.ErrCodeHeaderMismatch)
	require.NotNil(t, listRec)
	if target, present := listRec["target"]; present {
		assert.Empty(t, target, "an enumeration names no entry; the record must not invent one")
	}
}

// The stdio host's HTTP bridge is the second upstream leg, and it must emit the same pair.
//
// Asserted by driving it rather than by reading its source: both legs reach one sender today,
// and this is what fails if either ever grows a request build of its own.
func TestRoutingHeaders_StdioBridgeEmitsThemToo(t *testing.T) {
	t.Parallel()
	srv, lastHeaders := capturingUpstream(t)

	up := newHTTPUpstream(context.Background(), srv.URL, "", false, 0)
	t.Cleanup(up.close)
	up.setRevision(capability.Revision20260728)

	msg := declaringPOST(t, capability.MethodResourcesRead, map[string]interface{}{"uri": "file:///etc/hosts"})
	_, _, err := up.do(context.Background(), msg)
	require.NoError(t, err)

	got := lastHeaders()
	assert.Equal(t, capability.MethodResourcesRead, got.Get(RoutingHeaderMethod))
	assert.Equal(t, "file:///etc/hosts", got.Get(RoutingHeaderName),
		"a resource is addressed by uri, not name; the bridge must claim the same target the body does")
}
