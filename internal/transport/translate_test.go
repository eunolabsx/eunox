// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// TestCrossRevisionRegistry_CoversEveryForwardingMethod is the completeness guard the boundary
// rests on: the zero crossRevisionDeclaration REFUSES, so an unlisted method fails closed at
// runtime — but it fails closed by ACCIDENT, with no reason to give an operator and no evidence
// anyone decided. Every method whose params reach an upstream must have answered deliberately.
//
// Derived from methodRegistry through the same predicate the gate uses, so a method added there
// cannot pick up a disposition here by default, and a method whose handler fields change shape
// (gaining LocalForwards, say) is pulled into this set automatically.
func TestCrossRevisionRegistry_CoversEveryForwardingMethod(t *testing.T) {
	t.Parallel()
	for method := range methodRegistry {
		if !forwardsHostParams(method) {
			continue
		}
		decl, ok := crossRevisionRegistry[method]
		if !ok {
			t.Errorf("method %q forwards host params but declares no cross-revision disposition; the zero value would refuse it with no reason to report", method)
			continue
		}
		if decl.why == "" {
			t.Errorf("method %q declares a disposition with no reason; a refusal an operator hits mid-migration has to say what it protects", method)
		}
	}
	// The other direction: an entry for a method that forwards nothing is a rule nothing reads,
	// and reads as coverage this table does not have.
	for method := range crossRevisionRegistry {
		if !forwardsHostParams(method) {
			t.Errorf("crossRevisionRegistry declares %q, whose params never reach an upstream; the boundary is never asked about it", method)
		}
	}
}

// A matched pair must be byte-identical through both translation steps. This is the release's
// own regression invariant, and it is held STRUCTURALLY (each step returns early) rather than by
// this test — which is exactly why the test exists: the early return is one refactor away from
// becoming a rewrite that happens to produce the same bytes today.
func TestTranslate_MatchedPairIsByteIdentical(t *testing.T) {
	t.Parallel()
	for _, rev := range capability.PublishedRevisions() {
		t.Run(rev.String(), func(t *testing.T) {
			t.Parallel()
			params := json.RawMessage(`{"name":"read_file","_meta":{"io.modelcontextprotocol/protocolVersion":"` + rev.String() + `","progressToken":"p"}}`)
			req := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsCall, Params: params}
			got, err := translateRequest(req, rev, rev)
			if err != nil {
				t.Fatalf("translateRequest on a matched pair: %v", err)
			}
			if string(got.Params) != string(params) {
				t.Errorf("params rewritten on a matched pair:\n got %s\nwant %s", got.Params, params)
			}

			result := json.RawMessage(`{"content":[],"cacheScope":"public"}`)
			resp := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Result: result}
			out, err := translateResult(capability.MethodToolsList, resp, rev, rev)
			if err != nil {
				t.Fatalf("translateResult on a matched pair: %v", err)
			}
			if string(out.Result) != string(result) {
				t.Errorf("result rewritten on a matched pair:\n got %s\nwant %s", out.Result, result)
			}
		})
	}
}

func TestTranslateRequest_AddsTheDeclarationTowardADeclaringLeg(t *testing.T) {
	t.Parallel()
	req := mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsCall,
		Params: json.RawMessage(`{"name":"read_file","_meta":{"progressToken":"keep-me"}}`),
	}
	got, err := translateRequest(req, capability.Revision20251125, capability.Revision20260728)
	if err != nil {
		t.Fatalf("translateRequest: %v", err)
	}
	declared, present, err := mcp.DeclaredRevisionOf(got)
	if err != nil {
		t.Fatalf("the translated request's declaration is unreadable: %v", err)
	}
	if !present || declared != capability.Revision20260728 {
		t.Errorf("declaration = %q (present=%v), want the LEG's revision — the upstream requires it and the host had no way to send it", declared, present)
	}
	// Merged, not replaced: whatever else the host put in `_meta` is its own, and dropping it
	// would surface only as the member's absence at the upstream.
	if !strings.Contains(string(got.Params), "keep-me") {
		t.Errorf("params = %s, want the host's own _meta members preserved", got.Params)
	}
	if !strings.Contains(string(got.Params), `"name":"read_file"`) {
		t.Errorf("params = %s, want the host's own params preserved", got.Params)
	}
}

func TestTranslateRequest_StripsTheDeclarationTowardANonDeclaringLeg(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		params     string
		wantAbsent []string
		wantKept   []string
	}{
		{
			name:       "both declaring members removed, siblings kept",
			params:     `{"name":"read_file","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"progressToken":"keep-me"}}`,
			wantAbsent: []string{capability.MetaKeyProtocolVersion, capability.MetaKeyClientCapabilities},
			wantKept:   []string{"keep-me", "read_file", "_meta"},
		},
		{
			// An emptied `_meta` goes with them: the upstream should see the shape a client of
			// its own revision sends, not a vestigial empty object.
			name:       "an emptied _meta is removed too",
			params:     `{"name":"read_file","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}`,
			wantAbsent: []string{capability.MetaKeyProtocolVersion, "_meta"},
			wantKept:   []string{"read_file"},
		},
		{
			name:     "params with no _meta are untouched",
			params:   `{"name":"read_file"}`,
			wantKept: []string{"read_file"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsCall, Params: json.RawMessage(tc.params)}
			got, err := translateRequest(req, capability.Revision20260728, capability.Revision20251125)
			if err != nil {
				t.Fatalf("translateRequest: %v", err)
			}
			for _, absent := range tc.wantAbsent {
				if strings.Contains(string(got.Params), absent) {
					t.Errorf("params = %s, want %q removed", got.Params, absent)
				}
			}
			for _, kept := range tc.wantKept {
				if !strings.Contains(string(got.Params), kept) {
					t.Errorf("params = %s, want %q kept", got.Params, kept)
				}
			}
		})
	}
}

// Both translation directions must fail closed on the shapes that look like successes to a
// plain Unmarshal: a `null` params body (which nils the map with no error) and a duplicate key
// (which resolves last-wins where mcp.DecodeParams refuses). A translated message is one eunox
// wrote to, so a shape it misread is one it would rewrite wrongly.
func TestTranslateRequest_FailsClosedOnMalformedParams(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		params string
	}{
		{"duplicate declaration keys", `{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/protocolVersion":"2025-11-25"}}`},
		{"params that are not an object", `"scalar"`},
		{"_meta that is not an object", `{"_meta":"scalar"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsCall, Params: json.RawMessage(tc.params)}
			if _, err := translateRequest(req, capability.Revision20260728, capability.Revision20251125); err == nil {
				t.Error("stripping accepted a malformed params body")
			}
			if _, err := translateRequest(req, capability.Revision20251125, capability.Revision20260728); err == nil {
				t.Error("declaring accepted a malformed params body")
			}
		})
	}
}

func TestTranslateResult_AddsTheShapeADeclaringHostRequires(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		method     string
		result     string
		wantSubstr []string
		wantAbsent []string
	}{
		{
			name:       "a call result gains resultType and nothing else",
			method:     capability.MethodToolsCall,
			result:     `{"content":[{"type":"text","text":"ok"}]}`,
			wantSubstr: []string{`"resultType":"complete"`, `"content"`},
			// cacheScope belongs to the list-shaped results; a call is not cacheable.
			wantAbsent: []string{"cacheScope", "ttlMs"},
		},
		{
			name:       "a list result gains the private cache scope",
			method:     capability.MethodToolsList,
			result:     `{"tools":[]}`,
			wantSubstr: []string{`"resultType":"complete"`, `"cacheScope":"private"`},
			// ttlMs is a freshness hint the old upstream never offered; inventing a lifetime for
			// someone else's data is the fabrication this boundary exists to avoid.
			wantAbsent: []string{"ttlMs"},
		},
		{
			name:       "an upstream's own members are never overwritten",
			method:     capability.MethodToolsList,
			result:     `{"tools":[],"resultType":"something-else","cacheScope":"public"}`,
			wantSubstr: []string{`"something-else"`, `"public"`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resp := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Result: json.RawMessage(tc.result)}
			got, err := translateResult(tc.method, resp, capability.Revision20260728, capability.Revision20251125)
			if err != nil {
				t.Fatalf("translateResult: %v", err)
			}
			for _, want := range tc.wantSubstr {
				if !strings.Contains(string(got.Result), want) {
					t.Errorf("result = %s, want %s", got.Result, want)
				}
			}
			for _, absent := range tc.wantAbsent {
				if strings.Contains(string(got.Result), absent) {
					t.Errorf("result = %s, want %q absent", got.Result, absent)
				}
			}
		})
	}
}

// The refusal that keeps a mid-exchange result from being read as a finished one. Passing an
// `input_required` result to a host with no `resultType` in its vocabulary is SILENT: it reads
// the call as complete, drops the inputRequests the upstream is waiting on, and both sides
// believe they are done.
func TestTranslateResult_RefusesAVariantTheHostCannotRead(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		result    string
		wantRefus bool
	}{
		{"input_required", `{"resultType":"input_required","inputRequests":[]}`, true},
		{"a variant this build has never heard of", `{"resultType":"some-future-variant"}`, true},
		{"complete crosses", `{"resultType":"complete","content":[]}`, false},
		// The shape every 2025-11-25 upstream produces. Absent means complete by the spec's own
		// rule for earlier-revision servers, so refusing it would refuse every ordinary result.
		{"absent means complete", `{"content":[]}`, false},
		{"an unreadable result is refused, not guessed", `{"resultType":"complete","resultType":"input_required"}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resp := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Result: json.RawMessage(tc.result)}
			got, err := translateResult(capability.MethodToolsCall, resp, capability.Revision20251125, capability.Revision20260728)
			switch {
			case tc.wantRefus && err == nil:
				t.Fatalf("a result a %s host cannot read was forwarded: %s", capability.Revision20251125, got.Result)
			case tc.wantRefus:
				if !errors.Is(err, errUntranslatableAcrossRevisions) {
					t.Errorf("err = %v, want the boundary sentinel so the tape records it as a pair problem", err)
				}
			case err != nil:
				t.Fatalf("a readable result was refused: %v", err)
			default:
				// Nothing is stripped in this direction: the extra members a newer upstream
				// sends are inert for a host that does not read them, and rewriting a payload to
				// remove members nobody looks at puts eunox's hands on bytes for no gain.
				if string(got.Result) != tc.result {
					t.Errorf("result rewritten toward a non-declaring host:\n got %s\nwant %s", got.Result, tc.result)
				}
			}
		})
	}
}

// The wrapper is the seam every enforced forward crosses, so its own contract matters as much
// as the translation it applies.
func TestWithCrossRevisionTranslation(t *testing.T) {
	t.Parallel()

	t.Run("nil inner stays nil", func(t *testing.T) {
		t.Parallel()
		// nil is a MODE both the forward core and dispatchList read (a leg with no upstream);
		// wrapping it into a non-nil func that fails on use would turn a fail-closed refusal
		// naming the wiring fault into an upstream error naming nothing.
		if got := withCrossRevisionTranslation(capability.Revision20251125, nil); got != nil {
			t.Error("a nil upstream call was wrapped; the absent-upstream mode must survive")
		}
	})

	t.Run("a refused method never reaches the upstream", func(t *testing.T) {
		t.Parallel()
		called := false
		call := withCrossRevisionTranslation(capability.Revision20260728, func(context.Context, mcp.RPCMsg) (mcp.RPCMsg, error) {
			called = true
			return mcp.RPCMsg{}, nil
		})
		ctx := capability.WithProtocolRevision(context.Background(), capability.Revision20251125)
		_, err := call(ctx, mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodResourcesSubscribe})
		if !errors.Is(err, errUntranslatableAcrossRevisions) {
			t.Fatalf("err = %v, want the boundary refusal", err)
		}
		if called {
			t.Error("the upstream was contacted for a message the boundary refuses")
		}
	})

	t.Run("a matched pair is passed through untouched", func(t *testing.T) {
		t.Parallel()
		params := json.RawMessage(`{"name":"read_file"}`)
		var seen mcp.RPCMsg
		call := withCrossRevisionTranslation(capability.Revision20251125, func(_ context.Context, m mcp.RPCMsg) (mcp.RPCMsg, error) {
			seen = m
			return mcp.RPCMsg{JSONRPC: "2.0", ID: m.ID, Result: json.RawMessage(`{"content":[]}`)}, nil
		})
		ctx := capability.WithProtocolRevision(context.Background(), capability.Revision20251125)
		got, err := call(ctx, mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsCall, Params: params})
		if err != nil {
			t.Fatalf("call: %v", err)
		}
		if string(seen.Params) != string(params) {
			t.Errorf("upstream saw %s, want the host's own bytes %s", seen.Params, params)
		}
		if string(got.Result) != `{"content":[]}` {
			t.Errorf("host saw %s, want the upstream's own bytes", got.Result)
		}
	})

	t.Run("an unnegotiated context resolves rather than refusing", func(t *testing.T) {
		t.Parallel()
		// The empty carrier resolves to DefaultRevision through the one resolver, the same way
		// every other reader of it does — so a leg addressed at that revision is a MATCHED pair
		// and nothing is translated.
		var seen mcp.RPCMsg
		call := withCrossRevisionTranslation(capability.Revision20251125, func(_ context.Context, m mcp.RPCMsg) (mcp.RPCMsg, error) {
			seen = m
			return mcp.RPCMsg{JSONRPC: "2.0", ID: m.ID, Result: json.RawMessage(`{}`)}, nil
		})
		params := json.RawMessage(`{"name":"read_file"}`)
		if _, err := call(context.Background(), mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsCall, Params: params}); err != nil {
			t.Fatalf("call: %v", err)
		}
		if string(seen.Params) != string(params) {
			t.Errorf("upstream saw %s, want untouched bytes", seen.Params)
		}
	})

	t.Run("the upstream's own error is relayed unchanged", func(t *testing.T) {
		t.Parallel()
		sentinel := errors.New("upstream is down")
		call := withCrossRevisionTranslation(capability.Revision20260728, func(context.Context, mcp.RPCMsg) (mcp.RPCMsg, error) {
			return mcp.RPCMsg{}, sentinel
		})
		ctx := capability.WithProtocolRevision(context.Background(), capability.Revision20251125)
		_, err := call(ctx, mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsCall})
		if !errors.Is(err, sentinel) {
			t.Fatalf("err = %v, want the upstream's own error — a real outage must not be relabelled a pair problem", err)
		}
		if errors.Is(err, errUntranslatableAcrossRevisions) {
			t.Error("an upstream outage was reported as a translation refusal")
		}
	})
}

// A forwarded NOTIFICATION crosses the boundary too, and it is the one class that does not
// reach the upstream through the call seam the wrapper covers: each transport writes it
// straight out. So the wrapper's coverage argument does not extend to it, and this is what
// pins the second seam.
//
// The consequence if it were missed is specific and bad: notifications/cancelled is declared
// translatable precisely so a call that crossed the boundary can still be aborted. An
// untranslated cancel is refused by a declaring upstream for the missing member, and the tool
// call the host meant to abort runs to completion.
func TestTranslateNotificationForLeg(t *testing.T) {
	t.Parallel()

	t.Run("the declaration is added toward a declaring leg", func(t *testing.T) {
		t.Parallel()
		notif := mcp.RPCMsg{JSONRPC: "2.0", Method: methodNotificationsCancelled, Params: json.RawMessage(`{"requestId":"7"}`)}
		got, ok := translateNotificationForLeg(notif, capability.Revision20251125, capability.Revision20260728)
		if !ok {
			t.Fatal("a translatable notification was dropped")
		}
		declared, present, err := mcp.DeclaredRevisionOf(got)
		if err != nil {
			t.Fatalf("the translated notification's declaration is unreadable: %v", err)
		}
		if !present || declared != capability.Revision20260728 {
			t.Errorf("declaration = %q (present=%v), want the leg's revision — a declaring upstream requires it on every message, not only the ones with an id", declared, present)
		}
		if !strings.Contains(string(got.Params), `"requestId":"7"`) {
			t.Errorf("params = %s, want the notification's own members preserved", got.Params)
		}
	})

	t.Run("the declaration is stripped toward a non-declaring leg", func(t *testing.T) {
		t.Parallel()
		notif := mcp.RPCMsg{
			JSONRPC: "2.0", Method: methodNotificationsProgress,
			Params: json.RawMessage(`{"progressToken":"p","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}`),
		}
		got, ok := translateNotificationForLeg(notif, capability.Revision20260728, capability.Revision20251125)
		if !ok {
			t.Fatal("a translatable notification was dropped")
		}
		if strings.Contains(string(got.Params), capability.MetaKeyProtocolVersion) {
			t.Errorf("params = %s, want the declaration removed for a leg that negotiates once", got.Params)
		}
		if !strings.Contains(string(got.Params), `"progressToken":"p"`) {
			t.Errorf("params = %s, want the notification's own members preserved", got.Params)
		}
	})

	t.Run("a matched pair is untouched", func(t *testing.T) {
		t.Parallel()
		params := json.RawMessage(`{"requestId":"7","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}`)
		notif := mcp.RPCMsg{JSONRPC: "2.0", Method: methodNotificationsCancelled, Params: params}
		got, ok := translateNotificationForLeg(notif, capability.Revision20260728, capability.Revision20260728)
		if !ok {
			t.Fatal("a matched-pair notification was dropped")
		}
		if string(got.Params) != string(params) {
			t.Errorf("params rewritten on a matched pair:\n got %s\nwant %s", got.Params, params)
		}
	})

	t.Run("a malformed notification is dropped, not forwarded", func(t *testing.T) {
		t.Parallel()
		// JSON-RPC forbids answering a notification, and the boundary already admitted this one
		// at negotiation — so a translation failure here can only be dropped. What must not
		// happen is forwarding it untranslated.
		notif := mcp.RPCMsg{JSONRPC: "2.0", Method: methodNotificationsCancelled, Params: json.RawMessage(`"scalar"`)}
		if _, ok := translateNotificationForLeg(notif, capability.Revision20251125, capability.Revision20260728); ok {
			t.Error("a notification whose params could not be translated was admitted for forwarding")
		}
	})
}

func TestRefuseServerRequestAcrossRevisions(t *testing.T) {
	t.Parallel()
	// A host whose revision removed server-initiated requests entirely: there is no way to ask
	// it and no honest answer eunox could give on its behalf, so every method on the leg is
	// refused rather than the ones policy would have weighed.
	for _, method := range []string{capability.MethodSamplingCreateMessage, "roots/list", "elicitation/create"} {
		if err := refuseServerRequestAcrossRevisions(method, capability.Revision20260728); !errors.Is(err, errUntranslatableAcrossRevisions) {
			t.Errorf("refuseServerRequestAcrossRevisions(%q, declaring host) = %v, want the boundary refusal", method, err)
		}
	}
	// The matched pair: an old host can be asked, so the leg proceeds to its policy decision.
	if err := refuseServerRequestAcrossRevisions(capability.MethodSamplingCreateMessage, capability.Revision20251125); err != nil {
		t.Errorf("a handshake-revision host was refused its own server-initiated leg: %v", err)
	}
}

func TestNarrowCapabilitiesToTranslatable(t *testing.T) {
	t.Parallel()
	got := narrowCapabilitiesToTranslatable(map[string]interface{}{
		"tools":         map[string]interface{}{"listChanged": true},
		"prompts":       map[string]interface{}{},
		"resources":     map[string]interface{}{"subscribe": true, "listChanged": true},
		"logging":       map[string]interface{}{},
		"subscriptions": map[string]interface{}{},
		"experimental":  map[string]interface{}{"anything": true},
	})
	for _, kept := range []string{"tools", "prompts", "resources"} {
		if _, ok := got[kept]; !ok {
			t.Errorf("%q was dropped; the pair carries every method it implies", kept)
		}
	}
	// A capability this build knows no methods for cannot be reasoned about, so it cannot be
	// known to translate — and advertising an unknown surface is the fail-open direction.
	for _, dropped := range []string{"logging", "subscriptions", "experimental"} {
		if _, ok := got[dropped]; ok {
			t.Errorf("%q survived narrowing; an unrecognized capability must be dropped, not forwarded", dropped)
		}
	}
	resources, ok := got["resources"].(map[string]interface{})
	if !ok {
		t.Fatal("resources is not an object after narrowing")
	}
	if _, ok := resources["subscribe"]; ok {
		t.Error("resources.subscribe survived; it advertises the one pair inside resources the boundary refuses")
	}
	if _, ok := resources["listChanged"]; !ok {
		t.Error("resources.listChanged was dropped; narrowing must remove only what the boundary refuses")
	}
}

// TestCallUpstream_AlwaysWrappedAtItsSeam is the source guard for the wrapper's whole argument.
//
// Translation is applied at CONSTRUCTION so no forward path has to remember it. That only holds
// while every construction site actually wraps: a third one assigning a bare upstream call is a
// message crossing a mismatched pair untranslated, failing at the far peer with an error that
// names eunox's own bug as the upstream's.
//
// Walks the same parsed sources every other guard here does, so a file behind a build tag
// cannot drop out of the enumeration silently.
func TestCallUpstream_AlwaysWrappedAtItsSeam(t *testing.T) {
	t.Parallel()
	const field = "callUpstream"
	found := 0
	for _, src := range packageSources(t) {
		ast.Inspect(src.file, func(n ast.Node) bool {
			kv, ok := n.(*ast.KeyValueExpr)
			if !ok {
				return true
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok || key.Name != field {
				return true
			}
			found++
			call, ok := kv.Value.(*ast.CallExpr)
			if !ok {
				t.Errorf("%s: %s is assigned something other than a call to withCrossRevisionTranslation; a bare upstream call forwards untranslated across a mismatched pair",
					src.name, field)
				return true
			}
			fn, ok := call.Fun.(*ast.Ident)
			if !ok || fn.Name != "withCrossRevisionTranslation" {
				t.Errorf("%s: %s is wrapped by something other than withCrossRevisionTranslation", src.name, field)
			}
			return true
		})
	}
	if found == 0 {
		t.Fatal("no callUpstream assignment was found; the guard passed by walking nothing")
	}
}

// The wire and tape halves of a boundary refusal, asserted against the real classifier rather
// than a restatement of it: the code an operator greps for, and the integer a host branches on.
func TestBoundaryRefusal_ClassifiedAsAPairProblem(t *testing.T) {
	t.Parallel()
	err := fmt.Errorf("%w: test", errUntranslatableAcrossRevisions)
	code, _, rpcCode := upstreamErrInfo(noticeWriter{}, err, 0)
	if code != capability.ErrCodeUntranslatableAcrossRevisions {
		t.Errorf("code = %q, want %q — recording it as an upstream failure reports a healthy server as failing",
			code, capability.ErrCodeUntranslatableAcrossRevisions)
	}
	if rpcCode != capability.JSONRPCCodeUnsupportedProtocolVersion {
		t.Errorf("wire code = %d, want the spec's -32022", rpcCode)
	}
	if got := revisionRefusalCode(err); got != capability.ErrCodeUntranslatableAcrossRevisions {
		t.Errorf("revisionRefusalCode = %q, want the boundary code", got)
	}
	// The sibling refusal keeps its own code: a revision that could not be ESTABLISHED and a
	// pair that cannot bridge are different operator problems sharing one wire integer.
	if got := revisionRefusalCode(errRevisionMismatch); got != capability.ErrCodeUnsupportedProtocolVersion {
		t.Errorf("revisionRefusalCode(mismatch) = %q, want the establish-a-revision code", got)
	}
	// An observing route must not forward what this refuses: there is no policy verdict behind
	// it, and forwarding would hand a peer a result its revision cannot read.
	if capability.ClassifyDenialCode(capability.ErrCodeUntranslatableAcrossRevisions) == capability.DenialClassPolicy {
		t.Error("the boundary refusal classifies as a policy verdict, so an observing route would forward it")
	}
}

// The wire response and the audit record must name the SAME symbolic code.
//
// Two refusals share the -32022 integer, so `data.code` is the only thing that separates them
// for a host or a SIEM rule — and it is the whole argument for the second code existing. A
// cached `data` payload built once for the older code made the wire say
// UNSUPPORTED_PROTOCOL_VERSION while the tape said UNTRANSLATABLE_ACROSS_REVISIONS, which is
// worse than having one code: it tells two readers of the same refusal different things.
func TestRevisionRefusal_WireAndTapeNameTheSameCode(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"the pair cannot carry it", fmt.Errorf("%w: test", errUntranslatableAcrossRevisions), capability.ErrCodeUntranslatableAcrossRevisions},
		{"a revision could not be established", fmt.Errorf("%w: test", errRevisionMismatch), capability.ErrCodeUnsupportedProtocolVersion},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			taped := revisionRefusalCode(tc.err)
			if taped != tc.want {
				t.Fatalf("tape code = %q, want %q", taped, tc.want)
			}
			resp := mcp.RevisionRefusalResponse(mcp.RawJSON(`1`), taped, revisionRefusalReason(tc.err))
			if resp.Error.Code != capability.JSONRPCCodeUnsupportedProtocolVersion {
				t.Errorf("wire integer = %d, want the spec's -32022 for both", resp.Error.Code)
			}
			var data struct {
				Code      string   `json:"code"`
				Supported []string `json:"supported"`
			}
			if err := json.Unmarshal(resp.Error.Data, &data); err != nil {
				t.Fatalf("error.data is unreadable: %v", err)
			}
			if data.Code != tc.want {
				t.Errorf("error.data.code = %q, want %q — the wire and the tape must not describe one refusal differently", data.Code, tc.want)
			}
			if !strings.HasPrefix(resp.Error.Message, tc.want+":") {
				t.Errorf("message = %q, want the greppable prefix %q", resp.Error.Message, tc.want)
			}
			if len(data.Supported) != len(capability.PublishedRevisions()) {
				t.Errorf("supported = %v, want every revision this build speaks so a refused peer can retry", data.Supported)
			}
		})
	}
}
