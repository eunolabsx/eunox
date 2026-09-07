// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"encoding/json"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// TestCallIdentity_PromptsGetKeepsItsFourFieldsApart is the transposition regression for the
// one leg where the four identity fields do NOT collapse onto the same value: prompts/get
// records the "prompts/"-prefixed identifier while the host-facing denial names the bare
// prompt. On every other enforced leg auditID == denialTarget, so a swapped pair compiles and
// passes; here it mis-stamps the signed tape and misnames the target to the caller.
func TestCallIdentity_PromptsGetKeepsItsFourFieldsApart(t *testing.T) {
	t.Parallel()
	id := callIdentity{
		method:       capability.MethodPromptsGet,
		auditID:      "prompts/code_review",
		denialTarget: "code_review",
		kind:         "prompt",
	}

	for _, tc := range []struct {
		name string
		dec  capability.EnforceResponse
		want string
	}{
		{
			name: "hard deny",
			dec: capability.EnforceResponse{
				Decision: capability.DecisionDeny,
				Denial:   &capability.DenialInfo{Code: capability.ErrCodeCapabilityDenied},
			},
			want: "deny",
		},
		{
			name: "allow",
			dec:  capability.EnforceResponse{Decision: capability.DecisionAllow},
			want: "allow",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := &fwdRecorder{}
			fp := forwardParams{
				rec:       rec,
				sessionID: "s",
				limits:    refusalLimits{notices: noticesTo(io.Discard)},
				callUpstream: func(context.Context, mcp.RPCMsg) (mcp.RPCMsg, error) {
					return mcp.RPCMsg{JSONRPC: "2.0", Result: json.RawMessage(`{}`)}, nil
				},
			}
			resp := enforcedForwardCore(context.Background(), fp,
				mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodPromptsGet},
				tc.dec, id, true, upstreamErrorDetail)

			require.Len(t, rec.records, 1)
			assert.Equal(t, tc.want, rec.records[0].decision)
			assert.Equal(t, "prompts/code_review", rec.records[0].identifier,
				"the tape's identifier is auditID, never the method or the denial target")
			assert.Equal(t, capability.MethodPromptsGet, rec.records[0].method,
				"the tape's method is the method, never the identifier")

			if tc.want == "allow" {
				return
			}
			require.NotNil(t, resp.Error)
			var data denialErrorData
			require.NoError(t, json.Unmarshal(resp.Error.Data, &data))
			assert.Equal(t, "code_review", data.Target,
				"the host is told the BARE prompt name, never the tape's prefixed identifier")
		})
	}
}

// TestCallIdentity_MethodIdentityNamesTheMethodEverywhere pins the shape */list and the
// locally-answered methods use: no target below the method, so all three identifier fields
// are the method itself and only kind is left empty.
func TestCallIdentity_MethodIdentityNamesTheMethodEverywhere(t *testing.T) {
	t.Parallel()
	id := methodIdentity(capability.MethodToolsList)
	assert.Equal(t, capability.MethodToolsList, id.method)
	assert.Equal(t, capability.MethodToolsList, id.auditID)
	assert.Equal(t, capability.MethodToolsList, id.denialTarget)
	assert.Empty(t, id.kind, "a leg with no target below its method has no noun to name either")
}
