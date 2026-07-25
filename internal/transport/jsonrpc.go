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

// maxTrackedServerReqs bounds the outstanding server-initiated request IDs a
// session tracks. An ID is removed only when the host answers, so a host that
// never responds would grow the set unbounded. At the cap an arbitrary tracked
// ID is evicted to bound memory; that ID belongs to a real in-flight request
// whose upstream is now blocked, so its one call may re-hang until session
// teardown. This only triggers under a pathological flood (1024+ ignored
// requests, where the upstream is already wedged), so bounding memory is the
// safer failure than unbounded growth.
const maxTrackedServerReqs = 1024

// trackServerReqID adds key to ids (allocating on first use), keeping the set
// bounded by maxTrackedServerReqs, and returns the map plus whether a tracked ID
// had to be evicted. Caller must hold the set's mutex. Shared by both transports.
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
	// evictions tallies every eviction made to stay under maxTrackedServerReqs;
	// only the first is logged, so a sustained flood is recorded without spamming
	// stderr. Guarded by mu.
	evictions uint64
}

// track records key as an outstanding server-initiated request ID, evicting an
// arbitrary tracked ID if the bounded set is full (see maxTrackedServerReqs).
// Every eviction is tallied; only the first is logged, surfacing the re-hung
// call without letting a flood spam stderr.
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

// upstreamResult is what awaitNonced's routing channel carries: either a genuine
// upstream response (msg set, err nil) or a transport-level failure the upstream
// bridge could not turn into an in-band reply (err set, msg zero). Widening the
// channel to carry both lets a transport failure ride the SAME routing path as a
// normal response (deliverUpstreamResponse / deliverUpstreamError -> the one
// per-call channel awaitNonced selects on), instead of a parallel nonce-keyed error
// map kept in lockstep with the routing map: the result dies with the channel when
// a caller is abandoned, with nothing further to leak or clean up.
type upstreamResult struct {
	msg mcp.RPCMsg
	err error
}

// sendUpstreamResult is the shared non-blocking delivery core for
// deliverUpstreamResponse and deliverUpstreamError: it looks up key in pending
// (guarded by mu) and, if a caller is still waiting, sends result on its
// buffered(1) channel. The send never blocks, so the reader/bridge goroutine
// delivering it never wedges: an untracked, already-served, or abandoned key is
// simply dropped (there is nothing to deliver to). Returns whether a registered
// caller was found — callers that need a fallback when nobody was waiting (the
// stdio-to-HTTP bridge's in-band synthesized response) key it off this.
func sendUpstreamResult(mu *sync.Mutex, pending map[string]chan upstreamResult, key string, result upstreamResult) bool {
	mu.Lock()
	ch, ok := pending[key]
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
// pending awaiting its ID, if any. Both transports' readUpstream loops deliver
// through here.
func deliverUpstreamResponse(mu *sync.Mutex, pending map[string]chan upstreamResult, msg mcp.RPCMsg) {
	sendUpstreamResult(mu, pending, mcp.MsgKey(msg.ID), upstreamResult{msg: msg})
}

// deliverUpstreamError routes a transport-level failure (connection refused, DNS,
// non-2xx, per-call timeout — anything the upstream bridge could not turn into an
// in-band JSON-RPC reply) to the caller registered under upKey, if any, and reports
// whether one was found. This is the stdio-to-HTTP bridge's fire-and-forget POST
// failure path (see StdioProxy.reportUpstreamErr); a caller no longer registered
// (already timed out or the upstream exited) is a no-op — there is no separate
// error lifecycle to leak — and the bridge falls back to its in-band synthesized
// response instead (the handshake/probe path never registers in byUpstreamID at
// all, since it reads the bridge directly rather than through callUpstream).
func deliverUpstreamError(mu *sync.Mutex, pending map[string]chan upstreamResult, upKey string, err error) bool {
	return sendUpstreamResult(mu, pending, upKey, upstreamResult{err: err})
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

// correlateUpstreamReply validates that resp is a genuine JSON-RPC response to req
// and returns the reply to deliver, or an error if it must be refused (fail closed).
// It is the single source of truth for upstream reply-shape correlation, shared by
// every HTTP-upstream site that reads one POST's own response body (the stdio host's
// bridge post(), the gateway's callRemoteUpstream, and the remote initialize
// handshake) so the fail-closed rule cannot drift between them — a drift between two
// hand-mirrored copies is exactly how a method-bearing reply once slipped through.
//
// For a request (req carries an id):
//   - a non-response reply — id-less or method-bearing, IsResponse()==false — is
//     refused: a method-bearing reply echoing the proxy-known nonce id would otherwise
//     be reclassified as a forged server-initiated request and forwarded to the host;
//   - a reply whose id does not echo the request — whether a result OR an error — is
//     refused (fail closed): it may carry content (a result body, or an error
//     message/data) computed for a DIFFERENT call, so binding it to this caller would
//     let an adversarial upstream with concurrent callers inject one caller's reply
//     into another's reply channel (cross-call leakage). The caller surfaces a generic
//     upstream error for its own request instead of forwarding the mismatched reply.
//   - a reply that violates the JSON-RPC 2.0 invariant of carrying exactly one of
//     result/error — neither (an empty {"jsonrpc":"2.0","id":N}) or both — is refused
//     (fail closed): IsResponse() only inspects the id/method shape, so a malformed or
//     adversarial upstream could otherwise have an empty/contradictory response
//     forwarded to the host instead of a proxy-substituted upstream error.
//
// A notification (req.ID == nil) has no response to correlate and passes through.
func correlateUpstreamReply(req, resp mcp.RPCMsg) (mcp.RPCMsg, error) {
	if req.ID == nil {
		return resp, nil
	}
	if !resp.IsResponse() {
		return mcp.RPCMsg{}, fmt.Errorf("upstream returned a non-response reply for request %s (expected a JSON-RPC result or error)", req.Method)
	}
	if mcp.MsgKey(resp.ID) != mcp.MsgKey(req.ID) {
		// An id that does not echo the request — on a result OR an error — may carry
		// content computed for a DIFFERENT call, so refuse it (fail closed) rather than
		// re-stamp and mis-bind it to this caller. Previously a mismatched error was
		// re-stamped with the request id and delivered; an adversarial upstream with
		// concurrent callers could exploit that to craft an error for caller B, label it
		// with caller A's id, and inject B's error message/data into A's reply channel.
		// Dropping it makes the caller surface a generic upstream error for its own
		// request instead.
		return mcp.RPCMsg{}, fmt.Errorf("upstream response id %s does not match request id %s for %s", mcp.MsgKey(resp.ID), mcp.MsgKey(req.ID), req.Method)
	}
	// A JSON-RPC 2.0 response MUST carry exactly one of result/error. IsResponse()
	// only checks the id/method shape, so a reply such as {"jsonrpc":"2.0","id":N}
	// (neither result nor error) or one carrying BOTH satisfies it and the id match
	// above, then would be forwarded to the host as a malformed/empty response.
	// Assert the invariant here — the one shared correlation site — so the rule
	// cannot drift, and let the caller's wrapping surface a clean -32603 instead.
	if isMalformedResponse(resp) {
		return mcp.RPCMsg{}, fmt.Errorf("upstream response for %s carried neither result nor error (or both)", req.Method)
	}
	return resp, nil
}

// BuildInitializeParams marshals the initialize params the proxy sends to every
// upstream: it advertises no capabilities of its own and stamps clientInfo with the
// proxy name and build version. Exported (like ApplyInitializeResult) so the CLI's
// live-upstream probe sends the identical handshake as the running proxy rather than
// maintaining its own copy that could silently drift from it.
func BuildInitializeParams() json.RawMessage {
	params, _ := json.Marshal(map[string]interface{}{
		"protocolVersion": MCPProtocolVersion,
		"capabilities":    map[string]interface{}{},
		"clientInfo": map[string]interface{}{
			"name":    ProxyName,
			"version": proxyVersion,
		},
	})
	return params
}

// BuildInitializeRequestWithID constructs the MCP `initialize` request the proxy sends
// to every upstream, with a caller-supplied id. Exported so the CLI live-upstream probes
// (which need the string ids "_init"/"1") build the identical envelope the running proxy
// does, rather than hand-assembling their own copy that could drift from it (e.g. a new
// capabilities entry). Both the id-derived proxy handshake below and the CLI probes flow
// through this one builder.
func BuildInitializeRequestWithID(id *json.RawMessage) mcp.RPCMsg {
	return mcp.RPCMsg{JSONRPC: "2.0", ID: id, Method: "initialize", Params: BuildInitializeParams()}
}

// buildInitializeRequest constructs the MCP `initialize` request the proxy sends
// to every upstream. The id derives from idCounter so the caller can match the
// response; the proxy advertises no capabilities of its own. Shared by all three
// upstream handshakes (stdio, local-HTTP, remote-HTTP).
func buildInitializeRequest(idCounter int64) (mcp.RPCMsg, *json.RawMessage) {
	initID := mcp.RawJSON(fmt.Sprintf("%d", idCounter))
	return BuildInitializeRequestWithID(initID), initID
}

// buildInitializeResponse constructs the host-facing `initialize` response from the
// upstream capabilities and instructions gathered at session startup. A nil caps map
// defaults to advertising an empty `tools` capability (so a host still sees the proxy
// as MCP-capable). On the practically-impossible marshal failure it returns a -32603
// error response. Both transports produce the response body through this one builder,
// injected into the shared dispatcher as dispatchParams.buildInit: `initialize` now
// flows THROUGH dispatchRequest (dispatchInitialize) like every other locally-answered
// method, so its cross-cutting kill gate cannot drift — only the response body differs
// per transport, and it lives here. The lone carve-out is the HTTP session-CREATING
// initialize (no session/dispatchParams yet, and it carries the strict-audit gate),
// which the HTTP transport answers before the dispatcher.
func buildInitializeResponse(id *json.RawMessage, caps map[string]interface{}, instructions string) mcp.RPCMsg {
	if caps == nil {
		caps = map[string]interface{}{"tools": map[string]interface{}{}}
	}
	result := mcp.InitResult{
		ProtocolVersion: MCPProtocolVersion,
		Capabilities:    caps,
		ServerInfo: map[string]interface{}{
			"name":    ProxyName,
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
// received during a startup read loop (the initialize handshake or the drift
// tools/list probe), before the background reader is running to route it. A
// JSON-RPC request blocks its initiator until answered, so silently dropping one
// would wedge the upstream until session teardown. A no-op for any non-request
// message. Shared by StdioProxy.initUpstream, httpSession.runInitHandshake, the
// stdio drift probe, and the CLI live-upstream probe so the error code and wording
// stay in one place.
func RejectPreInitServerRequest(w mcp.MsgSink, msg mcp.RPCMsg) {
	if !msg.IsRequest() {
		return
	}
	_ = w.Write(mcp.ErrorResponse(msg.ID, capability.JSONRPCCodeEnforcementError,
		"server-initiated request received before initialize handshake completed"))
}

// awaitStartupReply reads upstream messages until the response matching wantID arrives and
// returns it. Every other message is discarded, and a discarded server-initiated REQUEST is
// answered through RejectPreInitServerRequest so the upstream is not left blocked — these
// startup paths all run before the background reader is up, so nothing else would answer
// it. onDiscard, when non-nil, is invoked with each discarded message before it is
// rejected (the stdio handshake uses it to log, making a chattering upstream observable).
//
// This is the protocol fragment the three startup read loops share —
// StdioProxy.initUpstream, httpSession.runInitHandshake, and the stdio drift probe's
// tools/list fetch. They previously hand-mirrored it, so a fix to the discard path (say,
// bounding how many pre-init messages are absorbed) had to land in three places or silently
// protect only some of them. read and the post-match handling stay with the callers: each
// reads through a different mechanism (context-aware bridge read vs blocking pipe read) and
// does something different with the reply, but the loop itself is now single-sourced.
//
// A read error is returned unwrapped so each caller can attach its own context.
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

// applyInitializeResult validates an upstream's `initialize` response and
// extracts the server capabilities, version, and instructions. Fails closed on
// any non-success shape — a JSON-RPC error (upstream rejected initialize), a
// response with neither result nor error, or an unparseable result — rather than
// handing the client a session backed by an unconfirmed upstream. serverInfo.version
// is captured for the FM-4 drift check. Shared by all three handshakes.
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

// validateInitializeResultFields rejects a structurally invalid MCP
// InitializeResult — most importantly a JSON `null` result, which unmarshals
// without error but leaves every field zero. A valid handshake carries a
// non-empty protocolVersion plus capabilities and serverInfo objects. Shared by
// the proxy handshake and the CLI live-introspection probe.
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

// denialErrorData is the structured payload carried in a denial's error.data.
// Every field names something the caller already supplied (the target it
// addressed, the argument it set) or describes the policy that rejected it —
// never a raw caller-supplied argument *value* (§ 7.6).
type denialErrorData struct {
	Code     string `json:"code"`               // symbolic code, e.g. CONDITION_FAILED
	Type     string `json:"type,omitempty"`     // failing condition type, e.g. allowedValues
	Target   string `json:"target,omitempty"`   // tool/resource/prompt the call addressed
	Argument string `json:"argument,omitempty"` // argument name a condition checked
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
