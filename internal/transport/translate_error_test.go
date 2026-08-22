// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"go/ast"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// crossRevisionErrorReply drives an upstream ERROR through the composed upstream-call seam —
// both wrappers, in the order the source guard pins — and returns what the host would receive.
//
// Driven through the seam rather than through translateErrorCode, for the reason the result-shape
// tests are: the gap this closes was not a wrong answer inside the translation, it was the
// translation never being ASKED about an error at all. A test calling the helper directly would
// have passed against the broken build.
func crossRevisionErrorReply(t *testing.T, method string, hostRev, legRev capability.Revision, code int) mcp.RPCMsg {
	t.Helper()
	upstream := mcp.RPCMsg{
		JSONRPC: "2.0",
		ID:      mcp.RawJSON(`1`),
		Error:   &mcp.RPCError{Code: code, Message: "no such resource"},
	}
	call := withResultShape(false, withCrossRevisionTranslation(legRev,
		func(context.Context, mcp.RPCMsg) (mcp.RPCMsg, error) { return upstream, nil }))
	ctx := capability.WithProtocolRevision(context.Background(), hostRev)
	got, err := call(ctx, mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: method})
	require.NoError(t, err, "an upstream error is a reply, not a transport failure")
	require.NotNil(t, got.Error, "the reply must still be an error response")
	return got
}

// The code whose meaning moved between the revisions, translated in the one direction where the
// integer is unambiguous.
func TestTranslateErrorCode_ResourceNotFoundReachesADeclaringHostInItsOwnSpelling(t *testing.T) {
	t.Parallel()
	got := crossRevisionErrorReply(t, capability.MethodResourcesRead,
		capability.Revision20260728, capability.Revision20251125,
		capability.JSONRPCCodeResourceNotFound20251125)
	assert.Equal(t, capability.JSONRPCCodeInvalidParams, got.Error.Code,
		"a 2026-07-28 host spells resource-not-found -32602; forwarding the old -32002 hands it a code from the other revision's dictionary")
	assert.Equal(t, "no such resource", got.Error.Message,
		"only the integer is translated; the upstream's own message is not eunox's to rewrite")
}

// The asymmetry, which is the part worth a test rather than a comment: the newer revision
// collapsed resource-not-found onto JSON-RPC's invalid-params integer, so the same -32602 carries
// two meanings and narrowing it would assert one of them.
func TestTranslateErrorCode_NewToOldIsNotNarrowed(t *testing.T) {
	t.Parallel()
	got := crossRevisionErrorReply(t, capability.MethodResourcesRead,
		capability.Revision20251125, capability.Revision20260728,
		capability.JSONRPCCodeInvalidParams)
	assert.Equal(t, capability.JSONRPCCodeInvalidParams, got.Error.Code,
		"-32602 means both resource-not-found and invalid-params under 2026-07-28; remapping it to -32002 would assert the first about what may have been the second")
}

// Everything the translation must NOT touch. Each row is a way the rewrite could over-reach, and
// each is a fabricated claim rather than a lost nicety.
func TestTranslateErrorCode_LeavesEverythingElseAlone(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		method  string
		hostRev capability.Revision
		legRev  capability.Revision
		code    int
	}{
		{
			// The integer is the old resource-not-found, but the method addresses a tool: under
			// 2025-11-25 an upstream may use -32002 as its own implementation-defined code on a
			// method that names no resource, and rewriting it would invent a meaning.
			name:    "a method that addresses no resource",
			method:  capability.MethodToolsCall,
			hostRev: capability.Revision20260728,
			legRev:  capability.Revision20251125,
			code:    capability.JSONRPCCodeResourceNotFound20251125,
		},
		{
			name:    "a matched pair is byte-identical",
			method:  capability.MethodResourcesRead,
			hostRev: capability.Revision20251125,
			legRev:  capability.Revision20251125,
			code:    capability.JSONRPCCodeResourceNotFound20251125,
		},
		{
			// Any other code the upstream chose is its own; only the one whose meaning MOVED is
			// eunox's to restate.
			name:    "an unrelated upstream code",
			method:  capability.MethodResourcesRead,
			hostRev: capability.Revision20260728,
			legRev:  capability.Revision20251125,
			code:    -32010,
		},
		{
			name:    "an upstream internal error",
			method:  capability.MethodResourcesRead,
			hostRev: capability.Revision20260728,
			legRev:  capability.Revision20251125,
			code:    capability.JSONRPCCodeEnforcementError,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := crossRevisionErrorReply(t, tc.method, tc.hostRev, tc.legRev, tc.code)
			assert.Equal(t, tc.code, got.Error.Code, "this reply's code is not the boundary's to rewrite")
		})
	}
}

// The rewrite must not reach back into the message the upstream reader still holds. RPCMsg
// carries its error by POINTER, so a rewrite in place would edit the decoded message itself —
// visible to anything holding it, and to a second read of the same reply.
func TestTranslateErrorCode_DoesNotMutateTheUpstreamsOwnMessage(t *testing.T) {
	t.Parallel()
	original := &mcp.RPCError{Code: capability.JSONRPCCodeResourceNotFound20251125, Message: "gone"}
	upstream := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Error: original}

	got := translateErrorCode(context.Background(), capability.MethodResourcesRead, upstream,
		capability.Revision20260728, capability.Revision20251125)

	assert.Equal(t, capability.JSONRPCCodeInvalidParams, got.Error.Code, "the host's copy is translated")
	assert.Equal(t, capability.JSONRPCCodeResourceNotFound20251125, original.Code,
		"the upstream's own decoded error must be untouched; the reader may still hold it")
}

// The audit tape must name what the UPSTREAM sent, not what the host was handed.
//
// The rewrite happens below the record, on the same response object, so the tape recorded the
// translated integer under a field whose name promises the upstream's own — and a translated
// -32602 is indistinguishable from an upstream that genuinely sent -32602, so nothing on the
// record could recover it. This asserts the two halves separately: the host is translated, the
// tape is not.
func TestUpstreamErrorDetail_RecordsWhatTheUpstreamSent(t *testing.T) {
	t.Parallel()
	upstream := mcp.RPCMsg{
		JSONRPC: "2.0",
		ID:      mcp.RawJSON(`1`),
		Error:   &mcp.RPCError{Code: capability.JSONRPCCodeResourceNotFound20251125, Message: "no such resource"},
	}
	call := withResultShape(false, withCrossRevisionTranslation(capability.Revision20251125,
		func(context.Context, mcp.RPCMsg) (mcp.RPCMsg, error) { return upstream, nil }))

	// The slot dispatchRequest installs. Its absence is what the guard below is about.
	ctx := withUpstreamCodeRewrite(capability.WithProtocolRevision(context.Background(), capability.Revision20260728))
	got, err := call(ctx, mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodResourcesRead})
	require.NoError(t, err)

	assert.Equal(t, capability.JSONRPCCodeInvalidParams, got.Error.Code, "the host receives its own revision's spelling")
	assert.Equal(t, map[string]interface{}{
		audit.UpstreamErrorCodeKey: capability.JSONRPCCodeResourceNotFound20251125,
	}, upstreamErrorDetail(ctx, got), "the tape must name the code the upstream actually sent")
}

// An untranslated reply records its own code, so the slot cannot leak a stale value onto a
// record it has nothing to do with.
func TestUpstreamErrorDetail_UntranslatedRepliesAreUnaffected(t *testing.T) {
	t.Parallel()
	ctx := withUpstreamCodeRewrite(context.Background())
	resp := mcp.RPCMsg{Error: &mcp.RPCError{Code: capability.JSONRPCCodeEnforcementError}}
	assert.Equal(t, map[string]interface{}{
		audit.UpstreamErrorCodeKey: capability.JSONRPCCodeEnforcementError,
	}, upstreamErrorDetail(ctx, resp))

	// And with no slot installed at all: today's behavior, not a panic.
	assert.Equal(t, map[string]interface{}{
		audit.UpstreamErrorCodeKey: capability.JSONRPCCodeEnforcementError,
	}, upstreamErrorDetail(context.Background(), resp))
}

// dispatchRequest is where the slot is installed, and the install is what makes the record
// truthful on every audited path. A source guard rather than a behavioral test because the
// failure mode is silent: without it the detail falls back to the forwarded code, which is
// exactly the wrong value and looks like an ordinary record.
func TestDispatchRequest_InstallsTheUpstreamCodeRewriteSlot(t *testing.T) {
	t.Parallel()
	src := dispatchSource(t)
	var found bool
	ast.Inspect(src.file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "dispatchRequest" {
			return true
		}
		ast.Inspect(fn, func(inner ast.Node) bool {
			call, ok := inner.(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "withUpstreamCodeRewrite" {
				found = true
			}
			return true
		})
		return false
	})
	assert.True(t, found,
		"dispatchRequest no longer installs the rewrite slot; every audited path would record the code the HOST was handed under a field naming the upstream")
}
