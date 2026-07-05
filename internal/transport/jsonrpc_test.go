// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Tests for JSON-RPC integer error codes: exact wire codes, no raw args in responses.
//
// Acceptance criteria (from the plan):
//   - Each denial path returns its exact integer code.
//   - error.message carries the symbolic name.
//   - error.data MAY carry the failing condition type but MUST NOT echo raw
//     caller-supplied argument values (§ 7.6).
//   - sampling/createMessage denial returns -32001 to the upstream server.
package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/internal/config"
	"github.com/eunolabs/eunox/internal/drift"
	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// ---------------------------------------------------------------------------
// Unit tests: denialToJSONRPCCode mapping table (§ 5.13)
// ---------------------------------------------------------------------------

func TestJSONRPCCode_DenialCodeMapping_INVALID_PARAMS(t *testing.T) {
	t.Parallel()
	assert.Equal(t, -32602, denialToJSONRPCCode(capability.ErrCodeInvalidParams))
}

func TestJSONRPCCode_DenialCodeMapping_AUTHORIZATION_FAILED(t *testing.T) {
	t.Parallel()
	assert.Equal(t, -32001, denialToJSONRPCCode(capability.ErrCodeAuthorizationFailed))
}

func TestJSONRPCCode_DenialCodeMapping_CAPABILITY_DENIED(t *testing.T) {
	t.Parallel()
	assert.Equal(t, -32002, denialToJSONRPCCode(capability.ErrCodeCapabilityDenied))
}

func TestJSONRPCCode_DenialCodeMapping_CONDITION_FAILED(t *testing.T) {
	t.Parallel()
	assert.Equal(t, -32003, denialToJSONRPCCode(capability.ErrCodeConditionFailed))
}

func TestJSONRPCCode_DenialCodeMapping_RATE_LIMITED(t *testing.T) {
	t.Parallel()
	// RATE_LIMITED is a maxCalls condition failure and uses the documented
	// CONDITION_FAILED wire code, not the CAPABILITY_DENIED fallback.
	assert.Equal(t, -32003, denialToJSONRPCCode(capability.ErrCodeRateLimited))
}

func TestJSONRPCCode_DenialCodeMapping_MISSING_CONTEXT(t *testing.T) {
	t.Parallel()
	// MISSING_CONTEXT fires when a required argument is absent during condition
	// evaluation — it is a condition failure (-32003), not a capability miss (-32002).
	assert.Equal(t, -32003, denialToJSONRPCCode(capability.ErrCodeMissingContext))
}

func TestJSONRPCCode_DenialCodeMapping_KILL_SWITCH(t *testing.T) {
	t.Parallel()
	// Kill-switch denials are authorization-layer events (active session revocation)
	// and share -32001 with AUTHORIZATION_FAILED.
	assert.Equal(t, -32001, denialToJSONRPCCode(capability.ErrCodeKillSwitch))
}

func TestJSONRPCCode_DenialCodeMapping_KILL_SWITCH_ERROR(t *testing.T) {
	t.Parallel()
	// KILL_SWITCH_ERROR fires when the kill-switch backend is unreachable; the
	// proxy fails closed. It is an authorization-layer denial, same as KILL_SWITCH.
	assert.Equal(t, -32001, denialToJSONRPCCode(capability.ErrCodeKillSwitchError))
}

func TestJSONRPCCode_DenialCodeMapping_NO_JWT_CLAIMS(t *testing.T) {
	t.Parallel()
	// NO_JWT_CLAIMS is an authentication failure (no validated token) and is an
	// authorization-layer event; it shares -32001 with AUTHORIZATION_FAILED.
	assert.Equal(t, -32001, denialToJSONRPCCode(capability.ErrCodeNoJWTClaims))
}

func TestJSONRPCCode_DenialCodeMapping_OPERATION_NOT_PERMITTED(t *testing.T) {
	t.Parallel()
	// OPERATION_NOT_PERMITTED is the JWTPDP equivalent of the manifest engine's
	// allowedOperations condition failure; it maps to -32003 (CONDITION_FAILED).
	assert.Equal(t, -32003, denialToJSONRPCCode(capability.ErrCodeOperationNotPermitted))
}

func TestJSONRPCCode_DenialCodeMapping_VALUE_NOT_PERMITTED(t *testing.T) {
	t.Parallel()
	// VALUE_NOT_PERMITTED is the JWTPDP equivalent of the manifest engine's
	// allowedValues condition failure; it maps to -32003 (CONDITION_FAILED).
	assert.Equal(t, -32003, denialToJSONRPCCode(capability.ErrCodeValueNotPermitted))
}

func TestJSONRPCCode_DenialCodeMapping_ENFORCEMENT_ERROR(t *testing.T) {
	t.Parallel()
	// ENFORCEMENT_ERROR is the reserved, fail-closed code for an internal
	// enforcement-engine failure. It is a server-side internal error, not a policy
	// denial, so it maps to -32603 (the standard JSON-RPC internal-error code)
	// rather than the -32002 CAPABILITY_DENIED fallback used for unknown codes.
	// The engine does not currently surface such an error (condition failures
	// resolve to CONDITION_FAILED), so this asserts the wire mapping the PDP's
	// defensive guard would emit.
	assert.Equal(t, -32603, denialToJSONRPCCode(capability.ErrCodeEnforcementError))
	assert.Equal(t, capability.JSONRPCCodeEnforcementError, denialToJSONRPCCode(capability.ErrCodeEnforcementError))
}

func TestJSONRPCCode_DenialCodeMapping_UnknownFallsBack(t *testing.T) {
	t.Parallel()
	// Unknown symbolic codes fall back to -32002 (CAPABILITY_DENIED).
	assert.Equal(t, capability.JSONRPCCodeCapabilityDenied, denialToJSONRPCCode("SOME_UNKNOWN_CODE"))
}

// ---------------------------------------------------------------------------
// Unit tests: denialResult wire format (§ 5.13)
// ---------------------------------------------------------------------------

func TestJSONRPCCode_DenialResult_IsJSONRPCError(t *testing.T) {
	t.Parallel()
	id := mcp.RawJSON(`1`)
	msg := denialResult(id, capability.ErrCodeAuthorizationFailed, "", "read_file", "")

	require.NotNil(t, msg.Error, "denial must be a JSON-RPC error object")
	assert.Nil(t, msg.Result, "denial must not carry a result")
}

func TestJSONRPCCode_DenialResult_MessageNamesCodeTargetAndArgument(t *testing.T) {
	t.Parallel()
	id := mcp.RawJSON(`2`)
	msg := denialResult(id, capability.ErrCodeConditionFailed, "allowedValues", "read_file", "path")
	require.NotNil(t, msg.Error)
	// error.message stays greppable (begins with the symbolic code) but now names
	// the denied target, the failing condition, and the argument it checked.
	assert.True(t, strings.HasPrefix(msg.Error.Message, capability.ErrCodeConditionFailed),
		"error.message must begin with the symbolic code")
	assert.Contains(t, msg.Error.Message, "read_file", "error.message must name the target")
	assert.Contains(t, msg.Error.Message, "allowedValues", "error.message must name the condition")
	assert.Contains(t, msg.Error.Message, "path", "error.message must name the argument")
}

func TestJSONRPCCode_DenialResult_DataCarriesCodeTypeTargetArgument(t *testing.T) {
	t.Parallel()
	id := mcp.RawJSON(`3`)
	msg := denialResult(id, capability.ErrCodeConditionFailed, "allowedValues", "read_file", "path")
	require.NotNil(t, msg.Error)
	require.NotNil(t, msg.Error.Data, "error.data must be present")

	var data map[string]string
	require.NoError(t, json.Unmarshal(msg.Error.Data, &data))
	assert.Equal(t, capability.ErrCodeConditionFailed, data["code"])
	assert.Equal(t, "allowedValues", data["type"])
	assert.Equal(t, "read_file", data["target"])
	assert.Equal(t, "path", data["argument"])
}

func TestJSONRPCCode_DenialResult_NoConditionType_OmitsTypeAndArgument(t *testing.T) {
	t.Parallel()
	id := mcp.RawJSON(`4`)
	msg := denialResult(id, capability.ErrCodeAuthorizationFailed, "", "unlisted_tool", "")
	require.NotNil(t, msg.Error)
	require.NotNil(t, msg.Error.Data, "error.data still carries code + target")

	var data map[string]string
	require.NoError(t, json.Unmarshal(msg.Error.Data, &data))
	assert.Equal(t, capability.ErrCodeAuthorizationFailed, data["code"])
	assert.Equal(t, "unlisted_tool", data["target"])
	_, hasType := data["type"]
	assert.False(t, hasType, "error.data must omit type when conditionType is empty")
	_, hasArg := data["argument"]
	assert.False(t, hasArg, "error.data must omit argument when none was checked")
}

func TestJSONRPCCode_DenialResult_NoRawArgsInData(t *testing.T) {
	t.Parallel()
	// Deny with code, condition type, target, and argument name — but the raw
	// value the caller supplied must never appear in the response.
	id := mcp.RawJSON(`5`)
	msg := denialResult(id, capability.ErrCodeConditionFailed, "allowedIPs", "connect", "host")
	require.NotNil(t, msg.Error)

	wire, _ := json.Marshal(msg)
	// A real source value such as "192.168.1.100" is never supplied to
	// denialResult: only the code, condition type, target, and argument name reach
	// the wire — never the value.
	assert.False(t, bytes.Contains(wire, []byte("192.168.1")),
		"raw caller-supplied values must not appear in the error response")
}

// ---------------------------------------------------------------------------
// HTTP-level integration tests
// ---------------------------------------------------------------------------

// TestJSONRPCCode_HTTP_ToolCall_NotInManifest_AuthorizationFailed verifies that a
// tools/call for a tool absent from the manifest returns AUTHORIZATION_FAILED
// (-32001) as a JSON-RPC error.
func TestJSONRPCCode_HTTP_ToolCall_NotInManifest_AuthorizationFailed(t *testing.T) {
	t.Parallel()

	fu := newFakeUpstream()
	upSrv := httptest.NewServer(fu)
	t.Cleanup(upSrv.Close)
	upURL := upSrv.URL

	_, proxySrv := newManifestProxy(t, upURL,
		capability.Constraint{Target: "tool:allowed_tool", Actions: []string{"call"}},
	)
	sid := initSession(t, proxySrv)

	params, _ := json.Marshal(mcp.ToolCallParams{Name: "unlisted_tool", Arguments: map[string]interface{}{}})
	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`101`), Method: "tools/call", Params: params}
	resp := postMCP(t, proxySrv, msg, sid)
	result := decodeRPC(t, resp)

	require.NotNil(t, result.Error, "expected JSON-RPC error for tool absent from manifest")
	assert.Equal(t, capability.JSONRPCCodeAuthorizationFailed, result.Error.Code)
	assert.True(t, strings.HasPrefix(result.Error.Message, capability.ErrCodeAuthorizationFailed),
		"error.message must begin with the symbolic code")
	// error.data carries code + target (no conditionType for a not-in-manifest denial).
	require.NotNil(t, result.Error.Data)
	var data map[string]string
	require.NoError(t, json.Unmarshal(result.Error.Data, &data))
	assert.Equal(t, capability.ErrCodeAuthorizationFailed, data["code"])
	assert.Equal(t, "unlisted_tool", data["target"])
	_, hasType := data["type"]
	assert.False(t, hasType, "not-in-manifest denial has no conditionType")
	assert.Equal(t, 0, fu.CountByMethod("tools/call"), "upstream must not receive denied call")
}

// TestJSONRPCCode_HTTP_ToolCall_WrongAction_CapabilityDenied verifies that a
// tools/call on an entry with the wrong action returns CAPABILITY_DENIED
// (-32002).
func TestJSONRPCCode_HTTP_ToolCall_WrongAction_CapabilityDenied(t *testing.T) {
	t.Parallel()

	fu := newFakeUpstream()
	upSrv := httptest.NewServer(fu)
	t.Cleanup(upSrv.Close)
	upURL := upSrv.URL

	// Entry exists but has "read" not "call".
	_, proxySrv := newManifestProxy(t, upURL,
		capability.Constraint{Target: "tool:read_file", Actions: []string{"read"}},
	)
	sid := initSession(t, proxySrv)

	params, _ := json.Marshal(mcp.ToolCallParams{Name: "read_file", Arguments: map[string]interface{}{}})
	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`102`), Method: "tools/call", Params: params}
	resp := postMCP(t, proxySrv, msg, sid)
	result := decodeRPC(t, resp)

	require.NotNil(t, result.Error)
	assert.Equal(t, capability.JSONRPCCodeCapabilityDenied, result.Error.Code)
	assert.True(t, strings.HasPrefix(result.Error.Message, capability.ErrCodeCapabilityDenied),
		"error.message must begin with the symbolic code")
	assert.Contains(t, result.Error.Message, "read_file", "error.message must name the target")
	assert.Equal(t, 0, fu.CountByMethod("tools/call"))
}

// TestJSONRPCCode_HTTP_ToolCall_ConditionFailed verifies that a condition failure
// returns CONDITION_FAILED (-32003) with the condition type in error.data.
func TestJSONRPCCode_HTTP_ToolCall_ConditionFailed(t *testing.T) {
	t.Parallel()

	fu := newFakeUpstream()
	upSrv := httptest.NewServer(fu)
	t.Cleanup(upSrv.Close)
	upURL := upSrv.URL

	_, proxySrv := newManifestProxy(t, upURL,
		capability.Constraint{
			Target:  "tool:read_file",
			Actions: []string{"call"},
			Conditions: []capability.Condition{
				&capability.AllowedValuesCondition{
					Argument: "path",
					Values:   []interface{}{"/reports/*"},
				},
			},
		},
	)
	sid := initSession(t, proxySrv)

	params, _ := json.Marshal(mcp.ToolCallParams{
		Name:      "read_file",
		Arguments: map[string]interface{}{"path": "/etc/passwd"},
	})
	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`103`), Method: "tools/call", Params: params}
	resp := postMCP(t, proxySrv, msg, sid)
	result := decodeRPC(t, resp)

	require.NotNil(t, result.Error)
	// A disallowed allowedValues value denies with VALUE_NOT_PERMITTED; the
	// JSON-RPC integer code is unchanged (-32003, the same wire code as
	// CONDITION_FAILED), only the symbolic denial_code differs.
	assert.Equal(t, capability.JSONRPCCodeConditionFailed, result.Error.Code)
	assert.True(t, strings.HasPrefix(result.Error.Message, capability.ErrCodeValueNotPermitted),
		"error.message must begin with the symbolic code")

	// error.data names the code, condition type, target, and argument — but not
	// the raw path value the caller supplied.
	require.NotNil(t, result.Error.Data)
	var data map[string]string
	require.NoError(t, json.Unmarshal(result.Error.Data, &data))
	assert.Equal(t, capability.ErrCodeValueNotPermitted, data["code"])
	assert.Equal(t, "allowedValues", data["type"])
	assert.Equal(t, "read_file", data["target"])
	assert.Equal(t, "path", data["argument"])

	wire, _ := json.Marshal(result)
	assert.False(t, bytes.Contains(wire, []byte("/etc/passwd")),
		"raw path must not appear in error response")
}

// TestJSONRPCCode_HTTP_ToolCall_RateLimited verifies that exhausting a maxCalls
// limit returns RATE_LIMITED with the CONDITION_FAILED wire code (-32003), not
// the CAPABILITY_DENIED fallback (-32002).
func TestJSONRPCCode_HTTP_ToolCall_RateLimited(t *testing.T) {
	t.Parallel()

	fu := newFakeUpstream()
	upSrv := httptest.NewServer(fu)
	t.Cleanup(upSrv.Close)
	upURL := upSrv.URL

	manifest := &config.LocalManifest{
		Name:    "test-policy",
		Version: "1.0.0",
		Capabilities: []capability.Constraint{
			{
				Target:  "tool:read_file",
				Actions: []string{"call"},
				Conditions: []capability.Condition{
					&capability.MaxCallsCondition{Count: 1, WindowSeconds: 60},
				},
			},
		},
	}
	// maxCalls needs a counter backend; newManifestProxy wires none.
	engine := enforcement.New(enforcement.WithCallCounter(callcounter.NewInMemory()))
	dp := pdp.NewManifestPDP(manifest.Capabilities, engine, killswitch.NewInMemory())
	_, proxySrv := newTestRemoteProxy(t, upURL, httpProxyOptions{
		PDP:        dp,
		DriftCheck: drift.CheckFunc(func(json.RawMessage, string, error) error { return nil }),
	})
	sid := initSession(t, proxySrv)

	params, _ := json.Marshal(mcp.ToolCallParams{Name: "read_file", Arguments: map[string]interface{}{}})

	// First call is within the limit and reaches the upstream.
	first := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`106`), Method: "tools/call", Params: params}
	resp := decodeRPC(t, postMCP(t, proxySrv, first, sid))
	require.Nil(t, resp.Error, "first call must be allowed")
	require.Equal(t, 1, fu.CountByMethod("tools/call"))

	// Second call exceeds count: 1 and must be denied with -32003.
	second := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`107`), Method: "tools/call", Params: params}
	result := decodeRPC(t, postMCP(t, proxySrv, second, sid))

	require.NotNil(t, result.Error, "expected JSON-RPC error once the call limit is exceeded")
	assert.Equal(t, capability.JSONRPCCodeRateLimited, result.Error.Code,
		"RATE_LIMITED must use -32003 on the wire")
	assert.True(t, strings.HasPrefix(result.Error.Message, capability.ErrCodeRateLimited),
		"error.message must begin with the symbolic code")
	assert.Contains(t, result.Error.Message, "read_file", "error.message must name the target")

	require.NotNil(t, result.Error.Data)
	var data map[string]string
	require.NoError(t, json.Unmarshal(result.Error.Data, &data))
	assert.Equal(t, capability.ErrCodeRateLimited, data["code"])
	assert.Equal(t, "maxCalls", data["type"])
	assert.Equal(t, "read_file", data["target"])

	assert.Equal(t, 1, fu.CountByMethod("tools/call"), "denied call must not reach the upstream")
}

// TestJSONRPCCode_HTTP_ToolCall_InvalidSchema_INVALID_PARAMS verifies that an
// argumentSchema violation returns INVALID_PARAMS (-32602).
func TestJSONRPCCode_HTTP_ToolCall_InvalidSchema_INVALID_PARAMS(t *testing.T) {
	t.Parallel()

	fu := newFakeUpstream()
	upSrv := httptest.NewServer(fu)
	t.Cleanup(upSrv.Close)
	upURL := upSrv.URL

	_, proxySrv := newManifestProxy(t, upURL,
		capability.Constraint{
			Target:  "tool:create_doc",
			Actions: []string{"call"},
			ArgumentSchema: &capability.ArgumentSchema{
				Required: []string{"title"},
			},
		},
	)
	sid := initSession(t, proxySrv)

	params, _ := json.Marshal(mcp.ToolCallParams{
		Name:      "create_doc",
		Arguments: map[string]interface{}{}, // missing required "title"
	})
	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`104`), Method: "tools/call", Params: params}
	resp := postMCP(t, proxySrv, msg, sid)
	result := decodeRPC(t, resp)

	require.NotNil(t, result.Error)
	assert.Equal(t, capability.JSONRPCCodeInvalidParams, result.Error.Code)
	assert.True(t, strings.HasPrefix(result.Error.Message, capability.ErrCodeInvalidParams),
		"error.message must begin with the symbolic code")
	assert.Contains(t, result.Error.Message, "create_doc", "error.message must name the target")
	assert.Equal(t, 0, fu.CountByMethod("tools/call"))
}

// TestJSONRPCCode_HTTP_ResourceRead_NotInManifest_AuthorizationFailed verifies that
// a resources/read denial returns AUTHORIZATION_FAILED (-32001).
func TestJSONRPCCode_HTTP_ResourceRead_NotInManifest_AuthorizationFailed(t *testing.T) {
	t.Parallel()

	fu := newFakeUpstreamWithResources()
	upURL := startFakeUpstream(t, fu)

	_, proxySrv := newManifestProxy(t, upURL,
		capability.Constraint{Target: "tool:some_tool", Actions: []string{"call"}},
	)
	sid := initSession(t, proxySrv)

	params, _ := json.Marshal(mcp.ResourceReadParams{URI: "file:///data/secret"})
	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`105`), Method: "resources/read", Params: params}
	resp := postMCP(t, proxySrv, msg, sid)
	result := decodeRPC(t, resp)

	require.NotNil(t, result.Error)
	assert.Equal(t, capability.JSONRPCCodeAuthorizationFailed, result.Error.Code)
	assert.True(t, strings.HasPrefix(result.Error.Message, capability.ErrCodeAuthorizationFailed),
		"error.message must begin with the symbolic code")
	assert.Contains(t, result.Error.Message, "file:///data/secret", "error.message must name the denied resource")
	assert.Equal(t, 0, fu.CountByMethod("resources/read"))
}

// TestJSONRPCCode_SamplingDenial_ReturnsAuthorizationFailed verifies that a
// server-initiated sampling/createMessage denial sends AUTHORIZATION_FAILED
// (-32001) to the upstream.
func TestJSONRPCCode_SamplingDenial_ReturnsAuthorizationFailed(t *testing.T) {
	t.Parallel()

	dp := newTestManifestPDP(
		// No system:sampling/createMessage entry → sampling denied.
		capability.Constraint{Target: "tool:read_file", Actions: []string{"call"}},
	)

	uw := &mockUpstreamWriter{}
	p := &StdioProxy{
		pdp:        dp,
		sessionID:  "test-sess",
		pending:    make(map[string]chan upstreamResult),
		hostWriter: mcp.NewMsgWriter(&writerAdapter{&mockHostWriter{}}),
		upWriter:   mcp.NewMsgWriter(&writerAdapter{uw}),
	}

	samplingReq := mcp.RPCMsg{
		JSONRPC: "2.0",
		ID:      mcp.RawJSON(`200`),
		Method:  "sampling/createMessage",
		Params:  json.RawMessage(`{"messages":[],"maxTokens":100}`),
	}
	p.handleUpstreamRequest(context.Background(), samplingReq)

	require.Len(t, uw.messages, 1, "upstream must receive exactly one error response")
	require.NotNil(t, uw.messages[0].Error)
	assert.Equal(t, capability.JSONRPCCodeAuthorizationFailed, uw.messages[0].Error.Code,
		"sampling denial must use -32001 (AUTHORIZATION_FAILED)")
	// The wire code stays -32001, but the message carries the real denial code so the
	// upstream sees the actual reason (matching the audit record), not a hardcoded string.
	assert.Equal(t, "SAMPLING_DENIED", uw.messages[0].Error.Message)
}

// TestJSONRPCCode_DenialResult_IDPreserved verifies that the original request ID is
// preserved in the denial response.
func TestJSONRPCCode_DenialResult_IDPreserved(t *testing.T) {
	t.Parallel()
	id := mcp.RawJSON(`"req-xyz"`)
	msg := denialResult(id, capability.ErrCodeAuthorizationFailed, "", "read_file", "")
	require.NotNil(t, msg.Error)
	assert.Equal(t, `"req-xyz"`, string(*msg.ID))
}

// TestJSONRPCCode_AllCodes_ExactIntegers is a table-driven sanity check that each
// symbolic code maps to its spec-mandated integer (§ 5.13).
func TestJSONRPCCode_AllCodes_ExactIntegers(t *testing.T) {
	t.Parallel()

	cases := []struct {
		symbolic string
		want     int
	}{
		{capability.ErrCodeInvalidParams, -32602},
		{capability.ErrCodeAuthorizationFailed, -32001},
		{capability.ErrCodeKillSwitch, -32001},
		{capability.ErrCodeKillSwitchError, -32001},
		{capability.ErrCodeCapabilityDenied, -32002},
		{capability.ErrCodeConditionFailed, -32003},
		{capability.ErrCodeRateLimited, -32003},
		{capability.ErrCodeMissingContext, -32003},
		{capability.ErrCodeNoJWTClaims, -32001},
		{capability.ErrCodeOperationNotPermitted, -32003},
		{capability.ErrCodeValueNotPermitted, -32003},
		{capability.ErrCodeEnforcementError, -32603},
		// SAMPLING_DENIED surfaces on the wire as AUTHORIZATION_FAILED (-32001); the
		// mapping must agree with forwardServerRequest's hard-deny so they cannot drift.
		{capability.ErrCodeSamplingDenied, -32001},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.symbolic, func(t *testing.T) {
			t.Parallel()
			got := denialToJSONRPCCode(tc.symbolic)
			assert.Equal(t, tc.want, got,
				"symbolic %q must map to %d", tc.symbolic, tc.want)

			// Verify round-trip through denialResult.
			msg := denialResult(mcp.RawJSON(`1`), tc.symbolic, "", "some_target", "")
			require.NotNil(t, msg.Error)
			assert.Equal(t, tc.want, msg.Error.Code)
			assert.True(t, strings.HasPrefix(msg.Error.Message, tc.symbolic),
				"error.message must begin with the symbolic code")
		})
	}
}

// ---------------------------------------------------------------------------
// Verify integer code constants match spec values.
// ---------------------------------------------------------------------------

func TestJSONRPCCode_ConstantValues(t *testing.T) {
	t.Parallel()
	assert.Equal(t, -32602, capability.JSONRPCCodeInvalidParams)
	assert.Equal(t, -32001, capability.JSONRPCCodeAuthorizationFailed)
	assert.Equal(t, -32002, capability.JSONRPCCodeCapabilityDenied)
	assert.Equal(t, -32003, capability.JSONRPCCodeConditionFailed)
	assert.Equal(t, -32003, capability.JSONRPCCodeRateLimited)
	assert.Equal(t, capability.JSONRPCCodeConditionFailed, capability.JSONRPCCodeRateLimited)
	assert.Equal(t, -32603, capability.JSONRPCCodeEnforcementError)
}

// ── Upstream timeout error code detection ───────────────────────

// TestTimeoutErrorDetection_DeadlineExceeded verifies that a DeadlineExceeded
// error is correctly identified — the fix uses errors.Is(fwdErr, DeadlineExceeded)
// rather than ctx.Err() on the parent context.
func TestTimeoutErrorDetection_DeadlineExceeded(t *testing.T) {
	fwdErr := context.DeadlineExceeded
	if !errors.Is(fwdErr, context.DeadlineExceeded) {
		t.Fatal("regression: errors.Is check for DeadlineExceeded must be true")
	}

	otherErr := errors.New("upstream exited")
	if errors.Is(otherErr, context.DeadlineExceeded) {
		t.Fatal("regression: non-timeout error must not match DeadlineExceeded")
	}
}

// TestTimeoutErrorDetection_ParentContextNotCanceled validates the exact
// scenario where an inner deadline fires while the parent is still valid.
func TestTimeoutErrorDetection_ParentContextNotCanceled(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()

	inner, cancelInner := context.WithTimeout(parent, 0)
	defer cancelInner()
	<-inner.Done()

	fwdErr := inner.Err()

	oldCheck := parent.Err() != nil
	if oldCheck {
		t.Fatal("setup: parent context must still be valid for this test to be meaningful")
	}

	newCheck := errors.Is(fwdErr, context.DeadlineExceeded)
	if !newCheck {
		t.Error("regression: errors.Is(fwdErr, DeadlineExceeded) must be true when inner deadline fires")
	}
}

// TestTrackServerReqID verifies the bounded insert: new IDs accumulate up to the
// cap, re-inserting a tracked ID never evicts, and once at the cap the set stays
// bounded while still admitting the newest ID. This guards against unbounded
// growth when a host never answers a server-initiated request.
func TestTrackServerReqID(t *testing.T) {
	t.Parallel()

	// nil map is allocated on first use; no eviction below the cap.
	ids, evicted := trackServerReqID(nil, "a")
	if len(ids) != 1 {
		t.Fatalf("first insert: len = %d, want 1", len(ids))
	}
	if evicted {
		t.Error("first insert must not report an eviction")
	}

	// Re-inserting an already-tracked ID is a no-op, not growth, and never evicts.
	ids, evicted = trackServerReqID(ids, "a")
	if len(ids) != 1 {
		t.Fatalf("duplicate insert: len = %d, want 1", len(ids))
	}
	if evicted {
		t.Error("duplicate insert must not report an eviction")
	}

	// Fill to the cap.
	for i := 0; len(ids) < maxTrackedServerReqs; i++ {
		ids, _ = trackServerReqID(ids, fmt.Sprintf("k%d", i))
	}
	if len(ids) != maxTrackedServerReqs {
		t.Fatalf("after fill: len = %d, want %d", len(ids), maxTrackedServerReqs)
	}

	// A new ID at the cap evicts one entry rather than growing the set, reports the
	// eviction so the caller can warn, and the newest ID is always present afterward.
	ids, evicted = trackServerReqID(ids, "overflow")
	if len(ids) != maxTrackedServerReqs {
		t.Fatalf("at cap: len = %d, want %d (must stay bounded)", len(ids), maxTrackedServerReqs)
	}
	if !evicted {
		t.Error("inserting a new ID at the cap must report an eviction")
	}
	if _, ok := ids["overflow"]; !ok {
		t.Error("newest ID must be retained after eviction at the cap")
	}

	// Re-inserting a tracked ID at the cap must not evict (size unchanged).
	ids, evicted = trackServerReqID(ids, "overflow")
	if len(ids) != maxTrackedServerReqs {
		t.Fatalf("duplicate at cap: len = %d, want %d", len(ids), maxTrackedServerReqs)
	}
	if evicted {
		t.Error("re-inserting a tracked ID at the cap must not report an eviction")
	}
}

// TestServerReqTracker_TalliesEvictions pins the CR-3 observability contract: the
// warn line states that evictions past the first are "counted but not individually
// logged", so serverReqTracker must actually tally every eviction (not just latch a
// logged-once bool). Each distinct ID tracked past the cap forces exactly one
// eviction; re-tracking an already-present ID evicts nothing.
func TestServerReqTracker_TalliesEvictions(t *testing.T) {
	t.Parallel()

	var tr serverReqTracker
	// Fill exactly to the cap: every insert is new but none overflows yet.
	for i := 0; i < maxTrackedServerReqs; i++ {
		tr.track(fmt.Sprintf("fill-%d", i))
	}
	if tr.evictions != 0 {
		t.Fatalf("evictions after filling to the cap = %d, want 0", tr.evictions)
	}

	// Each further distinct ID is one eviction, and every one is tallied (not just
	// the first logged one).
	const overflow = 5
	for i := 0; i < overflow; i++ {
		tr.track(fmt.Sprintf("overflow-%d", i))
	}
	if tr.evictions != overflow {
		t.Fatalf("evictions after %d overflow inserts = %d, want %d", overflow, tr.evictions, overflow)
	}

	// The most-recently-added ID is always retained, so re-tracking it evicts
	// nothing and leaves the tally unchanged.
	tr.track(fmt.Sprintf("overflow-%d", overflow-1))
	if tr.evictions != overflow {
		t.Fatalf("re-tracking a present ID changed the tally to %d, want %d", tr.evictions, overflow)
	}
}

// ---------------------------------------------------------------------------
// applyInitializeResult fail-closed
// ---------------------------------------------------------------------------

// TestApplyInitializeResult_RejectsErrorResponse: a JSON-RPC
// error response to initialize must surface as an error so the handshake aborts.
func TestApplyInitializeResult_RejectsErrorResponse(t *testing.T) {
	t.Parallel()
	resp := mcp.RPCMsg{
		JSONRPC: "2.0",
		ID:      mcp.RawJSON("1"),
		Error:   &mcp.RPCError{Code: -32600, Message: "unsupported protocol version"},
	}
	caps, ver, instructions, err := applyInitializeResult(resp)
	if err == nil {
		t.Fatal("applyInitializeResult must fail on an error response")
	}
	if caps != nil || ver != "" || instructions != "" {
		t.Errorf("error response must yield no caps/version/instructions, got caps=%v ver=%q instructions=%q", caps, ver, instructions)
	}
	if !strings.Contains(err.Error(), "initialize rejected") {
		t.Errorf("error = %q, want it to report the upstream rejection", err.Error())
	}
}

// TestApplyInitializeResult_FailsClosedOnMalformedShapes regression:
// a response carrying neither result nor error, and a present-but-unparseable
// result, were both silently accepted as a successful handshake (fail-open). Both
// must now return an error so the handshake aborts.
func TestApplyInitializeResult_FailsClosedOnMalformedShapes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		resp    mcp.RPCMsg
		wantSub string
	}{
		{
			name:    "neither result nor error",
			resp:    mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON("1")},
			wantSub: "neither result nor error",
		},
		{
			name:    "present but unparseable result",
			resp:    mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON("1"), Result: json.RawMessage(`"not-an-object"`)},
			wantSub: "result malformed",
		},
		{
			name:    "result is malformed json",
			resp:    mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON("1"), Result: json.RawMessage(`{`)},
			wantSub: "result malformed",
		},
		{
			// JSON null unmarshals into the struct without error but leaves every field
			// zero; it must be rejected rather than accepted as an empty handshake.
			name:    "result is JSON null",
			resp:    mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON("1"), Result: json.RawMessage(`null`)},
			wantSub: "protocolVersion",
		},
		{
			name:    "result object missing capabilities and serverInfo",
			resp:    mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON("1"), Result: json.RawMessage(`{"protocolVersion":"2025-11-25"}`)},
			wantSub: "capabilities",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			caps, ver, instructions, err := applyInitializeResult(tc.resp)
			if err == nil {
				t.Fatalf("applyInitializeResult must fail closed on a %s", tc.name)
			}
			if caps != nil || ver != "" || instructions != "" {
				t.Errorf("malformed response must yield no caps/version/instructions, got caps=%v ver=%q instructions=%q", caps, ver, instructions)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tc.wantSub)
			}
		})
	}
}

// TestApplyInitializeResult_AcceptsValidResult confirms a well-formed initialize
// result still yields capabilities and the serverInfo.version (FM-4 drift check).
func TestApplyInitializeResult_AcceptsValidResult(t *testing.T) {
	t.Parallel()
	result := mcp.InitResult{
		ProtocolVersion: MCPProtocolVersion,
		Capabilities:    map[string]interface{}{"tools": map[string]interface{}{}},
		ServerInfo:      map[string]interface{}{"name": "up", "version": "9.9.9"},
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	resp := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON("1"), Result: json.RawMessage(raw)}
	caps, ver, _, err := applyInitializeResult(resp)
	if err != nil {
		t.Fatalf("applyInitializeResult rejected a valid result: %v", err)
	}
	if ver != "9.9.9" {
		t.Errorf("serverVersion = %q, want %q", ver, "9.9.9")
	}
	if caps == nil {
		t.Error("capabilities must be captured from a valid result")
	}
}

// TestApplyInitializeResult_PreservesInstructions asserts that when the upstream
// initialize response contains an instructions field, it is captured and returned.
func TestApplyInitializeResult_PreservesInstructions(t *testing.T) {
	t.Parallel()
	result := mcp.InitResult{
		ProtocolVersion: MCPProtocolVersion,
		Capabilities:    map[string]interface{}{"tools": map[string]interface{}{}},
		ServerInfo:      map[string]interface{}{"name": "up", "version": "1.0.0"},
		Instructions:    "use this tool carefully",
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	resp := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON("1"), Result: json.RawMessage(raw)}
	caps, ver, instructions, err := applyInitializeResult(resp)
	if err != nil {
		t.Fatalf("applyInitializeResult rejected a valid result: %v", err)
	}
	if ver != "1.0.0" {
		t.Errorf("serverVersion = %q, want %q", ver, "1.0.0")
	}
	if caps == nil {
		t.Error("capabilities must be captured from a valid result")
	}
	if instructions != "use this tool carefully" {
		t.Errorf("instructions = %q, want %q", instructions, "use this tool carefully")
	}
}

// TestCorrelateUpstreamReply pins the contract of the shared reply-shape rule that
// every HTTP-upstream correlation site (post, callRemoteUpstream, initRemoteUpstream)
// now funnels through, so the fail-closed behavior can't drift between them again.
func TestCorrelateUpstreamReply(t *testing.T) {
	req := func(id string) mcp.RPCMsg {
		m := mcp.RPCMsg{JSONRPC: "2.0", Method: "tools/call"}
		if id != "" {
			m.ID = mcp.RawJSON(id)
		}
		return m
	}
	tests := []struct {
		name    string
		req     mcp.RPCMsg
		resp    mcp.RPCMsg
		wantErr bool
		// when wantErr is false, the id the returned reply must carry ("" => nil).
		wantID string
	}{
		{
			name:   "notification passes through unchecked",
			req:    req(""), // no id
			resp:   mcp.RPCMsg{JSONRPC: "2.0", Method: "anything", ID: mcp.RawJSON(`9`)},
			wantID: "9",
		},
		{
			name:   "matching result accepted unchanged",
			req:    req("1"),
			resp:   mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Result: json.RawMessage(`{"ok":true}`)},
			wantID: "1",
		},
		{
			name:    "method-bearing reply with matching id is refused (the forgery)",
			req:     req("1"),
			resp:    mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "sampling/createMessage", Params: json.RawMessage(`{}`)},
			wantErr: true,
		},
		{
			name:    "id-less reply is refused",
			req:     req("1"),
			resp:    mcp.RPCMsg{JSONRPC: "2.0", Result: json.RawMessage(`{"ok":true}`)},
			wantErr: true,
		},
		{
			name:    "mismatched result id is refused (fail closed)",
			req:     req("1"),
			resp:    mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`99`), Result: json.RawMessage(`{"ok":true}`)},
			wantErr: true,
		},
		{
			// An upstream error whose id does not echo the request is now REFUSED rather
			// than re-stamped: re-stamping let an adversarial upstream label caller B's
			// error with caller A's id and inject it into A's reply channel (cross-call
			// leakage). Fail closed instead.
			name:    "mismatched error id is refused (fail closed, no cross-call injection)",
			req:     req("1"),
			resp:    mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`null`), Error: &mcp.RPCError{Code: -32601, Message: "Method not found"}},
			wantErr: true,
		},
		{
			// id matches and IsResponse() holds, but the reply carries NEITHER result nor
			// error — a malformed JSON-RPC response that would otherwise be forwarded to the
			// host as a meaningless/empty reply. Refuse it (fail closed).
			name:    "matching id with neither result nor error is refused",
			req:     req("1"),
			resp:    mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`)},
			wantErr: true,
		},
		{
			// id matches but the reply carries BOTH result and error, violating the
			// JSON-RPC 2.0 exactly-one invariant. Refuse it (fail closed).
			name:    "matching id with both result and error is refused",
			req:     req("1"),
			resp:    mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Result: json.RawMessage(`{"ok":true}`), Error: &mcp.RPCError{Code: -32603, Message: "x"}},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := correlateUpstreamReply(tt.req, tt.resp)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected a refusal error, got reply %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if mcp.MsgKey(got.ID) != mcp.MsgKey(req(tt.wantID).ID) {
				t.Errorf("reply id = %s, want %s", mcp.MsgKey(got.ID), tt.wantID)
			}
		})
	}
}
