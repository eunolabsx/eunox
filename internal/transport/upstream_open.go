// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Opening an upstream leg, per revision.
//
// The revision a leg is OPENED at is what eunox speaks there, and every downstream fact about
// that leg follows from it: which method opens it, whether it is closed with
// `notifications/initialized`, what the MCP-Protocol-Version header on its later requests
// names, whether eunox's own requests carry the per-request `_meta` declaration, and which
// resolved revision a host message must agree with to be forwardable at all
// (checkUpstreamHonorable). Before this file existed those were four independent expressions
// of one constant, so the operator's `protocolVersion` pin named a revision nothing on the
// wire reflected.
//
// # What selects the opener, and what deliberately does not
//
// The PIN selects it. `auto` — no pin — opens with `initialize`, exactly as every release so
// far has, so an existing deployment's upstream sees byte-identical traffic at session start.
//
// ADR-0006 also describes a PROBE for the `auto` case: open with `server/discover` and fall
// back to `initialize` on method-not-found. That half is deliberately not activated here. It
// changes what every 2025-11-25 upstream sees before eunox knows anything about it, which is
// the one thing this release's regression invariant forbids, and its arbiter is the interop
// matrix that does not exist yet. Selecting the opener from the pin needs neither: an operator
// who writes `protocolVersion: "2026-07-28"` has stated the fact the probe would have gone
// looking for.

package transport

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// UpstreamOpenRevision returns the revision an upstream leg is opened at: the operator's pin
// when set, otherwise the handshake revision.
//
// One expression, read by every leg's construction AND by the CLI's live-upstream probe, so
// "what this leg speaks" is decided once per leg and before the first byte rather than
// re-derived from a handshake result that is no longer in scope — and so a probe and the proxy
// it is validating cannot open the same configured upstream at different revisions. The empty
// pin resolving to the handshake revision is what keeps `auto` byte-identical to the releases
// before the pin existed.
func UpstreamOpenRevision(pin capability.Revision) capability.Revision {
	if pin != "" {
		return pin
	}
	return handshakeRevision
}

// declaresPerRequestRevision reports whether a leg at rev carries its protocol revision in each
// request's `_meta` rather than negotiating it once.
//
// Phrased against the handshake revision rather than listing the revisions that declare, so a
// third published revision inherits the declaring behavior by default: a revision with no
// handshake has nowhere else to state its version, and defaulting the other way would open a
// leg whose every request omits a member that revision requires.
func declaresPerRequestRevision(rev capability.Revision) bool {
	return resolveRevision(rev) != handshakeRevision
}

// revisionDeclaration builds the `_meta` block eunox stamps on the requests it originates on a
// declaring leg: the revision, and the empty client-capabilities object its `initialize` params
// already offer (a proxy advertises no capabilities of its own upstream).
func revisionDeclaration(rev capability.Revision) map[string]interface{} {
	return map[string]interface{}{
		capability.MetaKeyProtocolVersion:    rev.String(),
		capability.MetaKeyClientCapabilities: map[string]interface{}{},
	}
}

// DeclareUpstreamRevision returns msg with the leg's per-request revision declaration merged
// into its params, or msg unchanged on a leg that negotiated once.
//
// Only for requests eunox ORIGINATES — the opener and the session-start drift probe. A host's
// own params are forwarded verbatim, `_meta` included: adding a member to them is translation,
// which the mismatched-pair boundary governs and this build does not do. The consequence is
// stated in docs/conformance.md rather than papered over here: a host message reaching a
// declaring leg must carry its own declaration, which on a matched pair it already does.
//
// Fails closed rather than returning msg unmodified on a marshal error. These params are
// eunox's own, so an error here is a bug rather than a wire input — but a leg that silently
// dropped the declaration would be refused per request by the upstream, one layer away from
// the cause.
func DeclareUpstreamRevision(msg mcp.RPCMsg, rev capability.Revision) (mcp.RPCMsg, error) {
	if !declaresPerRequestRevision(rev) {
		return msg, nil
	}
	fields := map[string]json.RawMessage{}
	if len(msg.Params) > 0 {
		if err := json.Unmarshal(msg.Params, &fields); err != nil {
			return mcp.RPCMsg{}, fmt.Errorf("declaring revision %s on %s: params are not a JSON object: %w", rev, msg.Method, err)
		}
	}
	meta, err := json.Marshal(revisionDeclaration(rev))
	if err != nil {
		return mcp.RPCMsg{}, fmt.Errorf("declaring revision %s on %s: %w", rev, msg.Method, err)
	}
	fields["_meta"] = meta
	raw, err := json.Marshal(fields)
	if err != nil {
		return mcp.RPCMsg{}, fmt.Errorf("declaring revision %s on %s: %w", rev, msg.Method, err)
	}
	msg.Params = raw
	return msg, nil
}

// openerMethod returns the method that opens a leg at rev.
func openerMethod(rev capability.Revision) string {
	if declaresPerRequestRevision(rev) {
		return mcp.MethodServerDiscover
	}
	return mcp.MethodInitialize
}

// buildInitializeParams marshals the initialize params the proxy sends to a handshake-revision
// upstream: no capabilities of its own, clientInfo stamped with the proxy name/version.
func buildInitializeParams() json.RawMessage {
	params, _ := json.Marshal(map[string]interface{}{
		// The handshake exists only in one revision, so the version it offers is that
		// revision by construction — a declaring upstream is reached through its own opener,
		// not by offering it a version it removed. Read off the registry that declares which
		// revision has `initialize` rather than restated here.
		"protocolVersion": handshakeRevision.String(),
		"capabilities":    map[string]interface{}{},
		"clientInfo": map[string]interface{}{
			"name":    proxyName,
			"version": proxyVersion,
		},
	})
	return params
}

// BuildUpstreamOpenerWithID constructs the request that opens an upstream leg at rev, with a
// caller-supplied id. Exported so the CLI's live-upstream probes open the leg the running
// proxy does, rather than a copy that could drift.
//
// The discover opener carries the declaration and nothing else. `initialize` identifies eunox
// in `clientInfo`; the stateless revision has no agreed per-request equivalent, and inventing a
// member for a request whose schema this build cannot check would be exactly the guess the
// fail-closed posture exists to avoid.
func BuildUpstreamOpenerWithID(rev capability.Revision, id *json.RawMessage) (mcp.RPCMsg, error) {
	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: id, Method: openerMethod(rev)}
	if !declaresPerRequestRevision(rev) {
		msg.Params = buildInitializeParams()
		return msg, nil
	}
	return DeclareUpstreamRevision(msg, rev)
}

// buildUpstreamOpener constructs the opener with the id derived from idCounter so the caller
// can match the response. Shared by all three upstream legs (stdio subprocess, local-HTTP,
// remote-HTTP).
func buildUpstreamOpener(rev capability.Revision, idCounter int64) (mcp.RPCMsg, *json.RawMessage, error) {
	openID := mcp.RawJSON(fmt.Sprintf("%d", idCounter))
	msg, err := BuildUpstreamOpenerWithID(rev, openID)
	return msg, openID, err
}

// UpstreamOpenerCompletion returns the notification that completes an opened leg, and whether
// the revision has one at all. Only the handshake revision does: `notifications/initialized`
// closes a handshake, and a revision with no handshake has nothing to close.
//
// Exported for the CLI probe, which opens its own leg and owes the upstream the same
// completion the proxy does.
func UpstreamOpenerCompletion(rev capability.Revision) (mcp.RPCMsg, bool, error) {
	if declaresPerRequestRevision(rev) {
		return mcp.RPCMsg{}, false, nil
	}
	notif, err := mcp.NotificationMsg(mcp.MethodNotificationsInitialized, nil)
	return notif, true, err
}

// UpstreamHandshake is what a validated upstream opener reply yields.
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
	// ProtocolVersion is the revision the upstream NEGOTIATED, verbatim rather than parsed —
	// empty on a declaring leg, which negotiates none (the client states it per request, so
	// there is no field for an upstream to answer with). Carried rather than resolved here so
	// checkNegotiatedRevision is the one place a reported version is judged.
	ProtocolVersion string
}

// openerResult extracts the success result bytes from an opener reply, failing closed on any
// non-success shape rather than handing the caller a session backed by an unconfirmed
// upstream. method names the opener in the error, since the two are told apart by nothing else
// on this path.
func openerResult(method string, resp mcp.RPCMsg) (json.RawMessage, error) {
	if resp.Error != nil {
		return nil, fmt.Errorf("upstream %s rejected: %s (code %d)", method, resp.Error.Message, resp.Error.Code)
	}
	if resp.Result == nil {
		return nil, fmt.Errorf("upstream %s response carried neither result nor error", method)
	}
	return resp.Result, nil
}

// ApplyUpstreamOpenerResult validates the reply to a leg opened at rev and extracts the
// handshake facts. Exported and shared with the CLI's live-upstream probe so the proxy and CLI
// cannot diverge on what counts as a valid open.
func ApplyUpstreamOpenerResult(rev capability.Revision, resp mcp.RPCMsg) (UpstreamHandshake, error) {
	if declaresPerRequestRevision(rev) {
		return applyDiscoverResult(resp)
	}
	hs, err := applyInitializeResult(resp)
	if err != nil {
		return UpstreamHandshake{}, err
	}
	if err := checkNegotiatedRevision(rev, hs.ProtocolVersion); err != nil {
		return UpstreamHandshake{}, err
	}
	return hs, nil
}

// applyInitializeResult validates an upstream's `initialize` response and extracts the
// handshake facts.
func applyInitializeResult(resp mcp.RPCMsg) (UpstreamHandshake, error) {
	raw, err := openerResult(mcp.MethodInitialize, resp)
	if err != nil {
		return UpstreamHandshake{}, err
	}
	var result mcp.InitResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return UpstreamHandshake{}, fmt.Errorf("upstream initialize result malformed: %w", err)
	}
	// Unmarshalling JSON `null` into a struct succeeds with all fields zero, which
	// would be accepted as a successful handshake with empty capabilities. Require
	// the mandatory MCP fields before accepting the handshake (fail closed).
	if err := validateInitializeResultFields(result); err != nil {
		return UpstreamHandshake{}, err
	}
	return UpstreamHandshake{
		Capabilities:    result.Capabilities,
		Instructions:    result.Instructions,
		ProtocolVersion: result.ProtocolVersion,
		ServerVersion:   serverInfoVersion(result.ServerInfo),
	}, nil
}

// applyDiscoverResult validates an upstream's `server/discover` response. Same fail-closed
// shape as the handshake's, minus the version: that revision negotiates none, so requiring a
// field the upstream has no way to answer would refuse every conforming server.
func applyDiscoverResult(resp mcp.RPCMsg) (UpstreamHandshake, error) {
	raw, err := openerResult(mcp.MethodServerDiscover, resp)
	if err != nil {
		return UpstreamHandshake{}, err
	}
	var result mcp.DiscoverResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return UpstreamHandshake{}, fmt.Errorf("upstream server/discover result malformed: %w", err)
	}
	if result.Capabilities == nil {
		return UpstreamHandshake{}, fmt.Errorf("upstream server/discover result missing required 'capabilities' object (a null or empty result is not a valid discovery response)")
	}
	if result.ServerInfo == nil {
		return UpstreamHandshake{}, fmt.Errorf("upstream server/discover result missing required 'serverInfo' object")
	}
	return UpstreamHandshake{
		Capabilities:  result.Capabilities,
		Instructions:  result.Instructions,
		ServerVersion: serverInfoVersion(result.ServerInfo),
	}, nil
}

// serverInfoVersion reads serverInfo.version, the one field the drift check needs off an
// opener reply. A missing or non-string value is absent rather than an error: FM-4 treats an
// unknown server version as nothing to compare, and refusing the whole leg over a field MCP
// does not require would be a stricter rule than the drift check itself applies.
func serverInfoVersion(serverInfo map[string]interface{}) string {
	version, _ := serverInfo["version"].(string)
	return version
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

// checkNegotiatedRevision refuses a handshake whose answer contradicts the revision the leg was
// opened at.
//
// Two failures, one rule — the leg speaks what it was opened at, and eunox does not switch
// revisions on an already-open one:
//
//   - A version this build does not speak used to resolve silently to capability.DefaultRevision,
//     so eunox stamped every later request with a header naming a negotiation that did not
//     happen. Nothing else caught it: the drift check compares serverInfo.version, not this.
//   - A version this build DOES speak but that is not the one offered is the same problem with a
//     worse blast radius, because the resulting leg looks negotiated. Continuing would mean
//     speaking a revision over a leg opened with a method that revision removed.
//
// The refusal reflects the upstream's own string back to the operator, bounded and stripped of
// control characters: it is a startup diagnostic, and an unbounded one would put an upstream in
// control of the console.
func checkNegotiatedRevision(opened capability.Revision, reported string) error {
	// An opener built with no explicit revision opened at the default, the same resolution
	// every other empty carrier takes; refusing here on the strength of an empty string would
	// name a revision no caller chose.
	opened = resolveRevision(opened)
	got, ok := capability.ParseRevision(reported)
	if !ok {
		return fmt.Errorf("upstream initialize answered protocolVersion %q, which this build does not speak (it speaks %s); refusing rather than proceeding as %s, which would stamp every later request with a version nobody negotiated",
			mcp.BoundReflectedRevision(reported), publishedRevisionList(), opened)
	}
	if got != opened {
		return fmt.Errorf("upstream initialize answered protocolVersion %s, but this leg was opened at %s; eunox does not switch revisions on an already-opened leg — pin `protocolVersion: %s` on this upstream to open it at %s instead",
			got, opened, got, got)
	}
	return nil
}

// publishedRevisionList renders the revisions this build speaks for an operator-facing error.
func publishedRevisionList() string {
	revs := capability.PublishedRevisions()
	names := make([]string, 0, len(revs))
	for _, rev := range revs {
		names = append(names, rev.String())
	}
	return strings.Join(names, ", ")
}
