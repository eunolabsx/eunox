// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"slices"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// resultBearingMethods returns every method a peer on rev can dispatch that comes back carrying
// an upstream RESULT — the set the shape rules are responsible for.
//
// DERIVED from methodRegistry rather than listed, so a method added for a revision is covered
// the day it is added rather than the day someone remembers to extend a literal here. That is
// the whole value of the sweep: the criterion it serves is "no result eunox emits to a
// 2026-07-28 peer lacks resultType", and a hand-written list cannot make that claim about
// methods it does not know exist.
func resultBearingMethods(rev capability.Revision) []string {
	var methods []string
	for method, spec := range methodRegistry {
		if !forwardsHostParams(method) || !slices.Contains(spec.In, rev) {
			continue
		}
		// Notification-only methods produce no result to shape.
		if spec.Decide == nil && !spec.LocalForwards {
			continue
		}
		methods = append(methods, method)
	}
	return methods
}

// TestResultShape_SweepEveryResultBearingMethod is the exit criterion: no result eunox hands a
// 2026-07-28 peer lacks the members that revision requires, and no result it hands a 2025-11-25
// peer gains one.
func TestResultShape_SweepEveryResultBearingMethod(t *testing.T) {
	t.Parallel()
	declaring := resultBearingMethods(capability.Revision20260728)
	if len(declaring) == 0 {
		t.Fatal("no result-bearing methods derived; the sweep would pass by covering nothing")
	}
	for _, method := range declaring {
		t.Run("declaring/"+method, func(t *testing.T) {
			t.Parallel()
			// A bare upstream result: exactly what a server that predates the member sends, and
			// what the supply half exists for.
			resp := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Result: json.RawMessage(`{"content":[]}`)}
			got, err := applyResultShape(capability.Revision20260728, method, resp)
			if err != nil {
				t.Fatalf("applyResultShape: %v", err)
			}
			fields := decodeResultFields(t, got)
			if variant := fields["resultType"]; variant != capability.ResultTypeComplete {
				t.Errorf("%s result carries resultType %q, want %q", method, variant, capability.ResultTypeComplete)
			}
			// Cache directives belong to the list-shaped results alone; a call result is not a
			// cacheable enumeration and stamping one would describe it wrongly.
			scope, hasScope := fields["cacheScope"]
			switch {
			case listShapedResult(method) && scope != capability.CacheScopePrivate:
				t.Errorf("%s is list-shaped but carries cacheScope %q, want %q", method, scope, capability.CacheScopePrivate)
			case !listShapedResult(method) && hasScope:
				t.Errorf("%s is not list-shaped but carries cacheScope %q", method, scope)
			}
			if _, hasTTL := fields["ttlMs"]; hasTTL {
				t.Errorf("%s gained a ttlMs the upstream never offered; a freshness hint may not be invented", method)
			}
		})
	}

	// The other half of the same criterion. An old-revision peer's result must come back with
	// the upstream's own bytes, because these members are ones its revision does not define.
	for _, method := range resultBearingMethods(capability.Revision20251125) {
		t.Run("handshake/"+method, func(t *testing.T) {
			t.Parallel()
			body := json.RawMessage(`{"content":[],"tools":[]}`)
			resp := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Result: body}
			got, err := applyResultShape(capability.Revision20251125, method, resp)
			if err != nil {
				t.Fatalf("applyResultShape: %v", err)
			}
			if string(got.Result) != string(body) {
				t.Errorf("%s result rewritten for a 2025-11-25 peer:\n got %s\nwant %s", method, got.Result, body)
			}
		})
	}
}

// A conforming upstream's result must come back byte-identical. Re-marshalling reorders members
// and re-escapes strings, so a proxy that rewrites a payload it had nothing to add to is one
// whose output a peer cannot diff against its upstream's.
func TestResultShape_ConformingResultIsNotRewritten(t *testing.T) {
	t.Parallel()
	body := json.RawMessage(`{"tools":[],"resultType":"complete","cacheScope":"private","ttlMs":60000,"x":"<&>"}`)
	resp := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Result: body}
	got, err := applyResultShape(capability.Revision20260728, capability.MethodToolsList, resp)
	if err != nil {
		t.Fatalf("applyResultShape: %v", err)
	}
	if string(got.Result) != string(body) {
		t.Errorf("a conforming result was rewritten:\n got %s\nwant %s", got.Result, body)
	}
}

// The open union: absent means complete, `complete` forwards, anything else is refused.
func TestResultShape_ResultTypeOpenUnion(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		result    string
		wantRefus bool
	}{
		// The shape every server predating the member sends. Reading it as anything but
		// complete would refuse ordinary traffic, which is why absence is the permissive case.
		{"absent means complete", `{"content":[]}`, false},
		{"complete forwards", `{"content":[],"resultType":"complete"}`, false},
		// The variant that exists today, and the reason the refusal is not pedantry: it means
		// the upstream is WAITING, and forwarding it says the exchange finished.
		{"input_required is refused", `{"content":[],"resultType":"input_required","inputRequests":[]}`, true},
		{"a variant published after this build is refused", `{"content":[],"resultType":"some-future-variant"}`, true},
		{"a non-string variant is refused", `{"content":[],"resultType":7}`, true},
		{"an explicit null reads as absent", `{"content":[],"resultType":null}`, false},
		// mcp.DecodeParams refuses a duplicate key, where last-wins would let an upstream show
		// eunox one variant and its host another.
		{"duplicate members are refused", `{"resultType":"complete","resultType":"input_required"}`, true},
		{"a non-object result is refused", `"scalar"`, true},
		{"a null result is refused rather than replaced", `null`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resp := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Result: json.RawMessage(tc.result)}
			got, err := applyResultShape(capability.Revision20260728, capability.MethodToolsCall, resp)
			switch {
			case tc.wantRefus && err == nil:
				t.Fatalf("a result this build cannot enforce was forwarded: %s", got.Result)
			case tc.wantRefus:
				if !errors.Is(err, errUnenforceableResultShape) {
					t.Errorf("err = %v, want the shape sentinel so the tape records the right class", err)
				}
			case err != nil:
				t.Fatalf("an enforceable result was refused: %v", err)
			default:
				if decodeResultFields(t, got)["resultType"] != capability.ResultTypeComplete {
					t.Errorf("result = %s, want the terminal variant", got.Result)
				}
			}
		})
	}
}

// An upstream must not be able to size or style the operator's console through a member eunox
// quotes back at it.
func TestResultShape_ReflectedVariantIsBounded(t *testing.T) {
	t.Parallel()
	hostile, err := json.Marshal(strings.Repeat("A", 4096) + "\x1b[31m\r\nFAKE LOG LINE")
	if err != nil {
		t.Fatal(err)
	}
	resp := mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`1`),
		Result: json.RawMessage(`{"resultType":` + string(hostile) + `}`),
	}
	_, shapeErr := applyResultShape(capability.Revision20260728, capability.MethodToolsCall, resp)
	if shapeErr == nil {
		t.Fatal("a hostile variant was forwarded")
	}
	msg := shapeErr.Error()
	if strings.ContainsAny(msg, "\x1b\r\n") {
		t.Error("the refusal reflected control characters from the upstream's variant")
	}
	if len(msg) > 1024 {
		t.Errorf("refusal is %d bytes; an upstream must not be able to size this message", len(msg))
	}
}

// The wire and tape halves of the refusal, read off the real classifier rather than restated.
func TestResultShape_RefusalIsAnEnforcementFault(t *testing.T) {
	t.Parallel()
	code, reason, rpcCode := upstreamErrInfo(noticeWriter{}, errUnenforceableResultShape, 0)
	if code != capability.ErrCodeEnforcementError {
		t.Errorf("code = %q, want %q — the upstream answered, so this is not an outage",
			code, capability.ErrCodeEnforcementError)
	}
	if rpcCode != capability.JSONRPCCodeEnforcementError {
		t.Errorf("wire code = %d, want the internal-error code", rpcCode)
	}
	if reason == "" {
		t.Error("the refusal reaches the host with no reason")
	}
	// Not a policy verdict: nothing was matched, so an observing route has no decision of its
	// own to forward in its place.
	if capability.ClassifyDenialCode(code) == capability.DenialClassPolicy {
		t.Error("the shape refusal classifies as a policy verdict, so an observing route would forward it")
	}
}

func TestWithResultShape(t *testing.T) {
	t.Parallel()

	t.Run("nil inner stays nil", func(t *testing.T) {
		t.Parallel()
		// nil is a MODE both the forward core and dispatchList read; wrapping it into a non-nil
		// func that fails on use turns a fail-closed refusal naming the wiring fault into an
		// upstream error naming nothing.
		if got := withResultShape(nil); got != nil {
			t.Error("a nil upstream call was wrapped; the absent-upstream mode must survive")
		}
	})

	t.Run("the upstream's own error is relayed unchanged", func(t *testing.T) {
		t.Parallel()
		sentinel := errors.New("upstream is down")
		call := withResultShape(func(context.Context, mcp.RPCMsg) (mcp.RPCMsg, error) {
			return mcp.RPCMsg{}, sentinel
		})
		ctx := capability.WithProtocolRevision(context.Background(), capability.Revision20260728)
		_, err := call(ctx, mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsCall})
		if !errors.Is(err, sentinel) {
			t.Fatalf("err = %v, want the upstream's own error — a real outage must not be relabelled a shape fault", err)
		}
		if errors.Is(err, errUnenforceableResultShape) {
			t.Error("an upstream outage was reported as a result-shape refusal")
		}
	})

	t.Run("an unnegotiated context takes the older revision", func(t *testing.T) {
		t.Parallel()
		// requestRevision resolves the empty carrier the one way every other reader does, so a
		// result on a context that negotiated nothing is left alone rather than gaining members
		// for a revision nobody chose.
		body := json.RawMessage(`{"content":[]}`)
		call := withResultShape(func(_ context.Context, m mcp.RPCMsg) (mcp.RPCMsg, error) {
			return mcp.RPCMsg{JSONRPC: "2.0", ID: m.ID, Result: body}, nil
		})
		got, err := call(context.Background(), mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsCall})
		if err != nil {
			t.Fatalf("call: %v", err)
		}
		if string(got.Result) != string(body) {
			t.Errorf("result = %s, want the upstream's own bytes", got.Result)
		}
	})
}

// TestCallUpstream_AlwaysWrappedAtItsSeam is the source guard for the seam's whole argument.
//
// The shape rules are applied at CONSTRUCTION so no forward path has to remember them. That
// holds only while every construction site wraps: a third one assigning a bare upstream call is
// a result reaching a peer without the members its revision requires, failing at that peer with
// an error that names eunox's own omission as the upstream's.
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
				t.Errorf("%s: %s is assigned a bare upstream call; its results reach a peer unshaped", src.name, field)
				return true
			}
			if fn, ok := call.Fun.(*ast.Ident); !ok || fn.Name != "withResultShape" {
				t.Errorf("%s: %s is wrapped by something other than withResultShape", src.name, field)
			}
			return true
		})
	}
	if found == 0 {
		t.Fatal("no callUpstream assignment was found; the guard passed by walking nothing")
	}
}

// decodeResultFields reads a result's top-level string members, for assertions that care about
// values rather than bytes.
func decodeResultFields(t *testing.T, resp mcp.RPCMsg) map[string]string { //nolint:gocritic // hugeParam: rpcMsg by value mirrors the package convention.
	t.Helper()
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(resp.Result, &raw); err != nil {
		t.Fatalf("result is not an object: %v", err)
	}
	out := make(map[string]string, len(raw))
	for key, value := range raw {
		var s string
		if err := json.Unmarshal(value, &s); err == nil {
			out[key] = s
			continue
		}
		out[key] = string(value)
	}
	return out
}
