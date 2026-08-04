// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// maxTrackedServerReqs bounds outstanding server-initiated request IDs so a host that never
// answers can't grow the set unbounded; past the cap an arbitrary tracked ID is evicted
// (its call may re-hang until teardown), which is a safer failure than unbounded growth.
const maxTrackedServerReqs = 1024

// trackServerReqID adds key to ids (allocating on first use), keeping the set bounded, and
// returns the map plus whether a tracked ID had to be evicted. Caller holds the set's mutex.
func trackServerReqID(ids map[string]struct{}, key string) (map[string]struct{}, bool) {
	if ids == nil {
		ids = make(map[string]struct{})
	}
	evicted := false
	if _, exists := ids[key]; !exists && len(ids) >= maxTrackedServerReqs {
		for k := range ids {
			delete(ids, k)
			evicted = true
			break
		}
	}
	ids[key] = struct{}{}
	return ids, evicted
}

// serverReqTracker records the JSON-RPC IDs of in-flight server-initiated
// requests (e.g. sampling/createMessage, roots/list) forwarded to the host, so
// the host's response (same ID) can be routed back to the upstream — and only
// that response; an untracked ID is ignored. Bounded (see trackServerReqID) and
// safe for concurrent use. Both transports hold one.
type serverReqTracker struct {
	mu  sync.Mutex
	ids map[string]struct{}
	// evictions tallies every eviction; only the first is logged, so a sustained flood
	// doesn't spam stderr. Guarded by mu.
	evictions uint64
}

// track records key as an outstanding server-initiated request ID, evicting an arbitrary
// tracked one if the bounded set is full. Only the first eviction is logged.
func (t *serverReqTracker) track(key string) {
	t.mu.Lock()
	var evicted bool
	t.ids, evicted = trackServerReqID(t.ids, key)
	warn := false
	if evicted {
		t.evictions++
		warn = t.evictions == 1
	}
	t.mu.Unlock()
	if warn {
		fmt.Fprintf(os.Stderr,
			"[eunox] WARNING: server-initiated request tracker reached its %d-entry cap; evicting an in-flight request ID to make room (the evicted request may hang until session teardown). Further evictions are counted but not individually logged.\n",
			maxTrackedServerReqs)
	}
}

// take reports whether key was a tracked server-initiated request ID, removing
// it so each forwarded request is matched to exactly one host response.
func (t *serverReqTracker) take(key string) bool {
	t.mu.Lock()
	_, ok := t.ids[key]
	if ok {
		delete(t.ids, key)
	}
	t.mu.Unlock()
	return ok
}

// errUpstreamExited is returned by awaitNonced (see stdio.go) when the upstream
// (its subprocess or session) closes its done channel before the response arrives.
var errUpstreamExited = errors.New("upstream exited")

// errDuplicateID is returned by awaitNonced when the host pipelines a request
// reusing a JSON-RPC id already in flight. It is a HOST protocol fault, not an
// upstream failure (the request never reached the upstream), so upstreamErrInfo
// maps it to an invalid-request (-32600) response with a non-infra audit code
// rather than blaming the upstream with UPSTREAM_ERROR.
var errDuplicateID = errors.New("duplicate JSON-RPC message ID")

// upstreamResult is what awaitNonced's routing channel carries: either a genuine upstream
// response (msg set) or a transport-level failure the bridge couldn't turn into an in-band
// reply (err set). Carrying both on one channel lets a transport failure ride the same
// routing path as a normal response instead of a parallel error map to keep in lockstep.
type upstreamResult struct {
	msg mcp.RPCMsg
	err error
}

// sendUpstreamResult is the shared non-blocking delivery core for deliverUpstreamResponse
// and deliverUpstreamError: looks up key in byID (guarded by mu) and, if a caller is still
// waiting, sends on its buffered(1) channel. The send never blocks, so the delivering
// goroutine never wedges on an untracked/already-served/abandoned key. Returns whether a
// caller was found, for a fallback path (the stdio-to-HTTP bridge's synthesized response).
func sendUpstreamResult(mu *sync.Mutex, byID map[string]chan upstreamResult, key string, result upstreamResult) bool {
	mu.Lock()
	ch, ok := byID[key]
	mu.Unlock()
	if !ok {
		return false
	}
	select {
	case ch <- result:
	default: // ID already served or caller gone; drop the duplicate/late result
	}
	return true
}

// deliverUpstreamResponse routes a genuine upstream response to the caller in
// byUpstreamID awaiting its nonce, if any. Both transports' readUpstream loops deliver
// through here.
func deliverUpstreamResponse(mu *sync.Mutex, byID map[string]chan upstreamResult, msg mcp.RPCMsg) {
	sendUpstreamResult(mu, byID, mcp.MsgKey(msg.ID), upstreamResult{msg: msg})
}

// deliverUpstreamError routes a transport-level failure (connection refused, DNS, non-2xx,
// timeout — anything the bridge couldn't turn into an in-band JSON-RPC reply) to the caller
// registered under upKey, reporting whether one was found. Used by the stdio-to-HTTP
// bridge's fire-and-forget POST failure path; an unregistered caller is a no-op and the
// bridge falls back to its in-band synthesized response.
func deliverUpstreamError(mu *sync.Mutex, byID map[string]chan upstreamResult, upKey string, err error) bool {
	return sendUpstreamResult(mu, byID, upKey, upstreamResult{err: err})
}

// isMalformedResponse reports whether resp violates the JSON-RPC 2.0 invariant
// that a response carries exactly one of result/error — neither (an empty
// {"jsonrpc":"2.0","id":N}) or both. IsResponse() only inspects the id/method
// shape, so this is the single source of truth for the well-formedness check
// itself, shared by correlateUpstreamReply (the HTTP-upstream bridge) and
// awaitNonced (the subprocess-upstream path, see stdio.go), so the rule cannot
// drift between hand-mirrored copies.
func isMalformedResponse(resp mcp.RPCMsg) bool {
	return (resp.Result == nil) == (resp.Error == nil)
}

// correlateUpstreamReply validates that resp is a genuine JSON-RPC response to req and
// returns the reply to deliver, or a fail-closed error if it must be refused. Single source
// of truth shared by every HTTP-upstream site reading a POST's own response, so the rule
// cannot drift between hand-mirrored copies (which is how a method-bearing reply once
// slipped through). For a request it refuses: a non-response reply (would otherwise be
// reclassified as a forged server-initiated request), a reply whose id doesn't echo the
// request (an adversarial upstream could inject one caller's reply into another's — the id
// match alone isn't enough, a result or error may carry content computed for a different
// call), or one violating the exactly-one-of-result/error invariant. A notification passes
// through untouched.
func correlateUpstreamReply(req, resp mcp.RPCMsg) (mcp.RPCMsg, error) {
	if req.ID == nil {
		return resp, nil
	}
	if !resp.IsResponse() {
		return mcp.RPCMsg{}, fmt.Errorf("upstream returned a non-response reply for request %s (expected a JSON-RPC result or error)", req.Method)
	}
	if mcp.MsgKey(resp.ID) != mcp.MsgKey(req.ID) {
		// Refuse rather than re-stamp and mis-bind: a mismatched id's result/error may be
		// content computed for a different call. Previously a mismatched error was
		// re-stamped with the request id, letting an adversarial upstream inject one
		// caller's error into another's reply channel.
		return mcp.RPCMsg{}, fmt.Errorf("upstream response id %s does not match request id %s for %s", mcp.MsgKey(resp.ID), mcp.MsgKey(req.ID), req.Method)
	}
	// IsResponse() only checks id/method shape, so a reply carrying neither or both of
	// result/error would otherwise pass through as malformed/empty.
	if isMalformedResponse(resp) {
		return mcp.RPCMsg{}, fmt.Errorf("upstream response for %s carried neither result nor error (or both)", req.Method)
	}
	return resp, nil
}

// buildInitializeParams marshals the initialize params the proxy sends to every upstream:
// no capabilities of its own, clientInfo stamped with the proxy name/version.
// Package-internal — the CLI probe reaches it via BuildInitializeRequestWithID instead, so
// the handshake stays identical without a second exported spelling.
func buildInitializeParams() json.RawMessage {
	params, _ := json.Marshal(map[string]interface{}{
		"protocolVersion": MCPProtocolVersion,
		"capabilities":    map[string]interface{}{},
		"clientInfo": map[string]interface{}{
			"name":    proxyName,
			"version": proxyVersion,
		},
	})
	return params
}

// BuildInitializeRequestWithID constructs the MCP `initialize` request the proxy sends to
// every upstream, with a caller-supplied id. Exported so the CLI's live-upstream probes
// build the identical envelope the running proxy does, rather than a copy that could drift.
func BuildInitializeRequestWithID(id *json.RawMessage) mcp.RPCMsg {
	return mcp.RPCMsg{JSONRPC: "2.0", ID: id, Method: mcp.MethodInitialize, Params: buildInitializeParams()}
}

// buildInitializeRequest constructs the MCP `initialize` request, with the id derived
// from idCounter so the caller can match the response. Shared by all three upstream
// handshakes (stdio, local-HTTP, remote-HTTP).
func buildInitializeRequest(idCounter int64) (mcp.RPCMsg, *json.RawMessage) {
	initID := mcp.RawJSON(fmt.Sprintf("%d", idCounter))
	return BuildInitializeRequestWithID(initID), initID
}

// buildInitializeResponse constructs the host-facing `initialize` response from the
// upstream capabilities/instructions gathered at session startup. A nil caps map defaults
// to an empty `tools` capability so the host still sees the proxy as MCP-capable. Both
// transports produce the body through this one builder, injected as dispatchParams.buildInit
// so `initialize` flows through the shared dispatcher's kill gate like every other
// locally-answered method — only the response body differs per transport.
func buildInitializeResponse(id *json.RawMessage, caps map[string]interface{}, instructions string) mcp.RPCMsg {
	if caps == nil {
		caps = map[string]interface{}{"tools": map[string]interface{}{}}
	}
	result := mcp.InitResult{
		ProtocolVersion: MCPProtocolVersion,
		Capabilities:    caps,
		ServerInfo: map[string]interface{}{
			"name":    proxyName,
			"version": proxyVersion,
		},
		Instructions: instructions,
	}
	resp, err := mcp.SuccessResponse(id, result)
	if err != nil {
		return mcp.ErrorResponse(id, jsonRPCCodeInternalError, "internal error building initialize response")
	}
	return resp
}

// RejectPreInitServerRequest replies a JSON-RPC error to a server-initiated request
// received during a startup read loop, before the background reader exists to route it —
// silently dropping a request would otherwise wedge the upstream until teardown. A no-op
// for any non-request message.
func RejectPreInitServerRequest(w mcp.MsgSink, msg mcp.RPCMsg) {
	if !msg.IsRequest() {
		return
	}
	_ = w.Write(mcp.ErrorResponse(msg.ID, capability.JSONRPCCodeEnforcementError,
		"server-initiated request received before initialize handshake completed"))
}

// awaitStartupReply reads upstream messages until the response matching wantID arrives.
// Every other message is discarded, with a discarded server-initiated REQUEST answered via
// RejectPreInitServerRequest so the upstream isn't left blocked (these startup paths run
// before the background reader exists). onDiscard, when non-nil, is invoked before each
// rejection (the stdio handshake logs it). Shared by the three startup read loops so a fix
// to the discard path lands once. A read error is returned unwrapped for the caller's own
// context.
func awaitStartupReply(
	read func() (mcp.RPCMsg, error),
	wantID *json.RawMessage,
	w mcp.MsgSink,
	onDiscard func(mcp.RPCMsg),
) (mcp.RPCMsg, error) {
	wantKey := mcp.MsgKey(wantID)
	for {
		msg, err := read()
		if err != nil {
			return mcp.RPCMsg{}, err
		}
		if msg.IsResponse() && mcp.MsgKey(msg.ID) == wantKey {
			return msg, nil
		}
		if onDiscard != nil {
			onDiscard(msg)
		}
		RejectPreInitServerRequest(w, msg)
	}
}

// applyInitializeResult validates an upstream's `initialize` response and extracts the
// server capabilities, version, and instructions. Fails closed on any non-success shape
// rather than handing the client a session backed by an unconfirmed upstream.
// serverInfo.version is captured for the FM-4 drift check.
func applyInitializeResult(resp mcp.RPCMsg) (caps map[string]interface{}, serverVersion, instructions string, err error) {
	if resp.Error != nil {
		return nil, "", "", fmt.Errorf("upstream initialize rejected: %s (code %d)", resp.Error.Message, resp.Error.Code)
	}
	if resp.Result == nil {
		return nil, "", "", fmt.Errorf("upstream initialize response carried neither result nor error")
	}
	var result mcp.InitResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, "", "", fmt.Errorf("upstream initialize result malformed: %w", err)
	}
	// Unmarshalling JSON `null` into a struct succeeds with all fields zero, which
	// would be accepted as a successful handshake with empty capabilities. Require
	// the mandatory MCP fields before accepting the handshake (fail closed).
	if err := validateInitializeResultFields(result); err != nil {
		return nil, "", "", err
	}
	caps = result.Capabilities
	if sv, ok := result.ServerInfo["version"].(string); ok {
		serverVersion = sv
	}
	return caps, serverVersion, result.Instructions, nil
}

// validateInitializeResultFields rejects a structurally invalid MCP InitializeResult —
// most importantly a JSON `null` result, which unmarshals without error but leaves every
// field zero.
func validateInitializeResultFields(result mcp.InitResult) error {
	if result.ProtocolVersion == "" {
		return fmt.Errorf("upstream initialize result missing required 'protocolVersion' (a null or empty result is not a valid MCP handshake)")
	}
	if result.Capabilities == nil {
		return fmt.Errorf("upstream initialize result missing required 'capabilities' object")
	}
	if result.ServerInfo == nil {
		return fmt.Errorf("upstream initialize result missing required 'serverInfo' object")
	}
	return nil
}

// ApplyInitializeResult is the exported form of applyInitializeResult, shared
// with the CLI's live-upstream probe so the proxy and CLI cannot diverge on what
// counts as a valid handshake.
func ApplyInitializeResult(resp mcp.RPCMsg) (caps map[string]interface{}, serverVersion, instructions string, err error) {
	return applyInitializeResult(resp)
}

// denialToJSONRPCCode maps a symbolic denial code to its JSON-RPC integer via
// capability.DenialWireCode, which owns the symbolic→wire pairing beside the codes
// it maps between (so a new ErrCode* without a wire mapping is a test-time miss, not
// a silent -32002). Unknown codes fall back to -32002 (CAPABILITY_DENIED).
func denialToJSONRPCCode(code string) int {
	wire, _ := capability.DenialWireCode(code)
	return wire
}

// denialErrorData is the structured payload carried in a denial's error.data. Every field
// names something the caller already supplied or describes the rejecting policy — never a
// raw caller-supplied argument *value* (§ 7.6).
type denialErrorData struct {
	Code     string `json:"code"`
	Type     string `json:"type,omitempty"`
	Target   string `json:"target,omitempty"`
	Argument string `json:"argument,omitempty"`
}

// denialMessage builds an operator-actionable error.message beginning with the
// symbolic code (greppable), naming the denied target and, when applicable, the
// failing condition and argument. Never includes the argument value.
func denialMessage(code, conditionType, target, argument string) string {
	msg := code
	if target != "" {
		msg += fmt.Sprintf(": target %q", target)
	}
	if conditionType != "" {
		msg += fmt.Sprintf(" failed condition %q", conditionType)
		if argument != "" {
			msg += fmt.Sprintf(" on argument %q", argument)
		}
	}
	return msg
}

// denialResult builds a JSON-RPC 2.0 error response for a policy denial.
// error.message is human-readable; error.data carries the same facts structured
// (denialErrorData). Neither echoes a raw caller-supplied argument value (§ 7.6).
func denialResult(id *json.RawMessage, code, conditionType, target, argument string) mcp.RPCMsg {
	dataJSON, _ := json.Marshal(denialErrorData{
		Code:     code,
		Type:     conditionType,
		Target:   target,
		Argument: argument,
	})
	return mcp.RPCMsg{
		JSONRPC: "2.0",
		ID:      id,
		Error: &mcp.RPCError{
			Code:    denialToJSONRPCCode(code),
			Message: denialMessage(code, conditionType, target, argument),
			Data:    dataJSON,
		},
	}
}

// denialArgument returns the name of the argument a condition checked, if any.
// Only the name — never the caller-supplied value — so it is safe to surface to
// the host (§ 7.6).
func denialArgument(d *capability.DenialInfo) string {
	if d == nil {
		return ""
	}
	if a, ok := d.Details["argument"].(string); ok {
		return a
	}
	return ""
}
