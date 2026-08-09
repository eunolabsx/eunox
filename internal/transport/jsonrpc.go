// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// maxTrackedServerReqs bounds outstanding server-initiated request IDs so a host that never
// answers can't grow the set unbounded; past the cap an arbitrary tracked request is evicted,
// which is a safer failure than unbounded growth. The evicted initiator is answered by the
// caller rather than abandoned — see trackServerRequest.
const maxTrackedServerReqs = 1024

// trackedServerRequest is what the tracker remembers about one outstanding server-initiated
// request: enough to ANSWER its initiator, not merely to recognize a reply to it.
//
// The id is kept verbatim because an answer must be stamped with the bytes the peer sent (MsgKey
// canonicalizes by value and type, so it is not reversible), and the method because an evicted
// request is reported on the tape, where a record naming none names nothing an operator can
// correlate on.
//
// Both are BOUNDED, because both come off the upstream's mcp.MsgReader at up to 4 MiB per message
// and the set holds maxTrackedServerReqs of them, released only by a host reply or teardown. The
// two are bounded differently because they are load-bearing differently: the method is read by the
// drop record alone, so it is truncated through the same audit.BoundEnvelopeField every other
// envelope field takes; the id is what an answer is stamped with and what the canonical map key is
// derived from, so a truncated one would be useless for both — an over-cap id makes the request
// unroutable instead (see trackableServerRequestID).
type trackedServerRequest struct {
	id     *json.RawMessage
	method string
	// seq orders entries by when they were tracked, so an eviction can take the one that has
	// waited longest rather than whichever the map's randomized range yields first.
	seq uint64
}

// maxTrackedServerReqIDBytes bounds the JSON-RPC id one tracked entry retains, and with it the
// canonical key the map is indexed by — the two together being most of what an entry holds.
//
// 8 KiB is far past any real JSON-RPC id (a number, a uuid) and keeps the whole set's retention in
// the tens of megabytes rather than the gigabytes an upstream issuing 4 MiB ids could pin.
//
// Enforced by REFUSING to track, not by truncating: a truncated id can neither answer the initiator
// it was kept for nor index the reply it was kept to match, and the key would still hold the full
// bytes. Matches the audit envelope cap, since the same value is what the drop record names.
//
// Enforced by the TRACKER, so the bound belongs to the thing retaining the bytes; the REFUSAL stays
// at each transport's entry to this leg (admitServerRequestID), above the decision that would
// otherwise commit a quota slot for a call the host never sees.
const maxTrackedServerReqIDBytes = 8 << 10

// trackableServerRequestID reports whether id is one the tracker will retain. Asked by
// admitServerRequestID before the request is admitted at all, so a request whose reply could never
// be routed is refused to its initiator rather than forwarded to a host whose answer would be
// dropped — and by track itself, which is what makes it the tracker's own bound.
func trackableServerRequestID(id *json.RawMessage) bool {
	return id != nil && len(*id) <= maxTrackedServerReqIDBytes
}

// trackServerReqID adds req to ids (allocating on first use), keeping the set bounded, and returns
// the map plus whatever req DISPLACED — an entry evicted to make room, or one this key overwrote.
// Caller holds the set's mutex.
//
// Both are the same event to the caller: an outstanding request has left the set without a host
// reply, so nothing can ever route one to it and its initiator has to be answered here or never.
// The overwrite is the easier one to miss — mcp.MsgKey canonicalizes by VALUE, so an upstream
// issuing ids `1` and `1.0` collides two distinct wire requests onto one entry — and it was
// invisible while the map's value was a struct{}: there was nothing to lose.
func trackServerReqID(ids map[string]trackedServerRequest, key string, req trackedServerRequest) (map[string]trackedServerRequest, trackedServerRequest, bool) {
	if ids == nil {
		ids = make(map[string]trackedServerRequest)
	}
	if displaced, exists := ids[key]; exists {
		ids[key] = req
		return ids, displaced, true
	}
	var displaced trackedServerRequest
	found := false
	if len(ids) >= maxTrackedServerReqs {
		// The victim is the one that has waited LONGEST. Arbitrary choice was tolerable when an
		// eviction merely left a request to hang; it is not once eviction actively answers the
		// initiator, since a random pick is as likely to abort a request the host is about to
		// answer correctly as one that is genuinely stuck.
		oldestKey, oldest := "", trackedServerRequest{}
		for k, v := range ids {
			if oldestKey == "" || v.seq < oldest.seq {
				oldestKey, oldest = k, v
			}
		}
		delete(ids, oldestKey)
		displaced, found = oldest, true
	}
	ids[key] = req
	return ids, displaced, found
}

// serverReqTracker records the in-flight server-initiated requests (e.g.
// sampling/createMessage, roots/list) forwarded to the host, so the host's response (same ID)
// can be routed back to the upstream — and only that response; an untracked ID is ignored.
// Bounded (see trackServerReqID) and safe for concurrent use. Both transports hold one.
type serverReqTracker struct {
	mu  sync.Mutex
	ids map[string]trackedServerRequest
	// nextSeq stamps each tracked entry's arrival order, for the oldest-first eviction.
	nextSeq uint64
	// evictions tallies every displacement; only the first is logged, so a sustained flood
	// doesn't spam stderr. Guarded by mu.
	evictions uint64
}

// track records msg as an outstanding server-initiated request and RETURNS whatever it displaced —
// the oldest entry if the bounded set was full, or one this id overwrote — so the caller can
// answer that initiator: once the entry is gone even a correct host reply can no longer be routed
// to it, and nothing else could ever answer it. Only the first displacement is logged, to errOut
// (each caller holds its proxy's or session's writer), never to os.Stderr directly.
//
// A message with no id is not tracked at all: its key would be "", which no reply can match and no
// unblock can address, so the entry could only ever leave the set by displacing a real one. An
// over-cap id is refused here too — the exposure is what an entry HOLDS — and its callers must not
// forward what this refuses, which is why both forward paths ask admitServerRequestID first.
//
// Reached ONLY through trackServerRequest, which disposes of what this returns. Go does not require
// a return value to be consumed, so a second caller reaching for the obvious-looking method here
// would silently abandon a displaced initiator — the exact hang the displacement answer exists to
// close, with no compiler error and no test. TestServerReqTracker_TrackIsOnlyReachedThroughTheDisposingWrapper
// is what makes that a build failure instead.
func (t *serverReqTracker) track(msg mcp.RPCMsg, errOut io.Writer) (trackedServerRequest, bool) {
	if !trackableServerRequestID(msg.ID) {
		return trackedServerRequest{}, false
	}
	key := mcp.MsgKey(msg.ID)
	// Bounded on the way IN — what an entry holds for its whole lifetime is the exposure, and the
	// drop record's own bound would arrive far too late — and ABOVE the lock, like the key: this is
	// a full UTF-8 scan of an upstream-controlled string, and t.mu is also taken by the take() that
	// routes every host reply back to a blocked upstream.
	method := audit.BoundEnvelopeField(msg.Method)
	t.mu.Lock()
	var (
		displaced trackedServerRequest
		found     bool
	)
	t.nextSeq++
	entry := trackedServerRequest{id: msg.ID, method: method, seq: t.nextSeq}
	t.ids, displaced, found = trackServerReqID(t.ids, key, entry)
	warn := false
	if found {
		t.evictions++
		warn = t.evictions == 1
	}
	t.mu.Unlock()
	if warn {
		_, _ = fmt.Fprintf(resolvedErrOut(errOut),
			"[eunox] WARNING: server-initiated request tracker reached its %d-entry cap; the longest-waiting in-flight request is displaced to make room (its initiator is answered with an error, since nothing could route a reply to it afterwards). Further displacements are counted but not individually logged.\n",
			maxTrackedServerReqs)
	}
	return displaced, found
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

// tracked reports whether key is an outstanding server-initiated request WITHOUT consuming it.
// The peek exists for the one disposition that must not consume: a site with no upstream writer
// to answer through, which reports the abandoned request rather than dropping it silently but
// must leave the id routable by whatever path still can. See serverRequestUnblocker.unblock.
func (t *serverReqTracker) tracked(key string) bool {
	t.mu.Lock()
	_, ok := t.ids[key]
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
		// The handshake exists only in the older revision, so the version it offers is that
		// revision by construction — a newer-revision upstream is reached through its own
		// opener, not by offering it a version it removed. Read off the registry that
		// declares which revision has `initialize` rather than restated here.
		"protocolVersion": handshakeRevision.String(),
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
		// Answering `initialize` at all means the host opened a handshake-revision context:
		// the method does not exist in the newer revision, so the response cannot name one.
		ProtocolVersion: handshakeRevision.String(),
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

// UpstreamHandshake is what a validated upstream `initialize` response yields.
//
// A struct rather than a positional tuple for the reason audit.RecordParams gives: three of
// its fields are strings, so any two transposed at a call site compiles cleanly and silently
// misconfigures a session — and adding the protocol revision made it three of four.
type UpstreamHandshake struct {
	// Capabilities is the upstream's advertised capability object, echoed to the host.
	Capabilities map[string]interface{}
	// ServerVersion is serverInfo.version, captured for the FM-4 drift check.
	ServerVersion string
	// Instructions is the upstream's optional instructions string.
	Instructions string
	// ProtocolVersion is the revision the upstream reported, VERBATIM rather than parsed: a
	// version this build does not speak is still a fact worth carrying, and
	// resolveUpstreamRevision is the one place that decides what to do with an unknown one.
	ProtocolVersion string
}

// applyInitializeResult validates an upstream's `initialize` response and extracts the
// handshake facts. Fails closed on any non-success shape rather than handing the client a
// session backed by an unconfirmed upstream.
func applyInitializeResult(resp mcp.RPCMsg) (UpstreamHandshake, error) {
	if resp.Error != nil {
		return UpstreamHandshake{}, fmt.Errorf("upstream initialize rejected: %s (code %d)", resp.Error.Message, resp.Error.Code)
	}
	if resp.Result == nil {
		return UpstreamHandshake{}, fmt.Errorf("upstream initialize response carried neither result nor error")
	}
	var result mcp.InitResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return UpstreamHandshake{}, fmt.Errorf("upstream initialize result malformed: %w", err)
	}
	// Unmarshalling JSON `null` into a struct succeeds with all fields zero, which
	// would be accepted as a successful handshake with empty capabilities. Require
	// the mandatory MCP fields before accepting the handshake (fail closed).
	if err := validateInitializeResultFields(result); err != nil {
		return UpstreamHandshake{}, err
	}
	hs := UpstreamHandshake{
		Capabilities:    result.Capabilities,
		Instructions:    result.Instructions,
		ProtocolVersion: result.ProtocolVersion,
	}
	if sv, ok := result.ServerInfo["version"].(string); ok {
		hs.ServerVersion = sv
	}
	return hs, nil
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
func ApplyInitializeResult(resp mcp.RPCMsg) (UpstreamHandshake, error) {
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
