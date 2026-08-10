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
// back to `initialize` on method-not-found. That half is deliberately not activated here,
// because it changes what every 2025-11-25 upstream sees before eunox knows anything about it,
// and the interop matrix that would arbitrate the change does not exist. Selecting the opener
// from the pin needs neither: an operator who writes `protocolVersion: "2026-07-28"` has stated
// the fact the probe would have gone looking for.

package transport

import (
	"encoding/json"
	"fmt"
	"io"
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
//
// A pin this build does not speak resolves to the handshake revision rather than being taken
// verbatim. The config and flag loaders already refuse one, but this is an EXPORTED resolver
// behind an exported option field, and the branch an unrecognized value would otherwise fall
// into is the DECLARING one — the newest wire behavior, reached by a value nobody validated,
// which is the fail-open direction. Resolving it to the surface eunox already shipped is the
// same rule every other unresolvable revision takes.
func UpstreamOpenRevision(pin capability.Revision) capability.Revision {
	if pin.Supported() {
		return pin
	}
	return handshakeRevision
}

// openerSpec is everything a revision decides about how eunox opens an upstream leg at it.
//
// One declaration per revision, in a registry, for the reason methodRegistry is one: these four
// facts were five `if rev != handshakeRevision` branches across three exported functions and
// one HTTP sender, and a third published revision inherited the DECLARING arm of every one of
// them by default. It would have been opened with `server/discover` whether or not it has that
// method, never completed, and stamped with the other revision's `_meta` keys — with nothing
// failing until a live upstream answered -32601 at session start. Absence is a build failure
// now (TestOpenerRegistry_EveryPublishedRevisionDeclaresItsOpener), which is the same trade
// `methodSpec.In` makes for routing.
type openerSpec struct {
	// method opens the leg.
	method string
	// completion closes the open, or "" for a revision with nothing to close.
	completion string
	// declares is true when this revision carries its protocol version in every request's
	// `_meta` rather than negotiating it once.
	declares bool
	// negotiatesVersion is true when the OPENER itself performs the version negotiation, so it
	// precedes the MCP-Protocol-Version header and must not carry one. False for an opener that
	// is an ordinary request of a revision the client has already declared.
	negotiatesVersion bool
}

// openerRegistry declares the opener for every revision this build speaks. A revision missing
// from it has no opener and fails the build rather than inheriting another revision's.
var openerRegistry = map[capability.Revision]openerSpec{
	capability.Revision20251125: {
		method:            mcp.MethodInitialize,
		completion:        mcp.MethodNotificationsInitialized,
		negotiatesVersion: true,
	},
	capability.Revision20260728: {
		method:   mcp.MethodServerDiscover,
		declares: true,
	},
}

// openerFor returns the opener declaration for a leg speaking rev, resolving an unset or
// unspeakable revision through UpstreamOpenRevision — the one resolver that decides what a leg
// with no explicit revision is opened at, so this cannot answer a different question than the
// construction that picked the opener in the first place.
func openerFor(rev capability.Revision) openerSpec {
	return openerRegistry[UpstreamOpenRevision(rev)]
}

// declaresPerRequestRevision reports whether a leg at rev carries its protocol revision in each
// request's `_meta` rather than negotiating it once.
func declaresPerRequestRevision(rev capability.Revision) bool {
	return openerFor(rev).declares
}

// openerNegotiatesVersion reports whether method is the opener of a leg at rev AND that opener
// performs the version negotiation — the one request that must NOT carry the negotiated version
// header, because it is what establishes it.
//
// Keyed on the leg's revision as well as the method, so the rule follows the opener declaration
// rather than a hardcoded method name in the generic HTTP sender. A host-forwarded message that
// merely shares the opener's name on a leg that does not open with it still carries its header.
func openerNegotiatesVersion(rev capability.Revision, method string) bool {
	spec := openerFor(rev)
	return spec.negotiatesVersion && method == spec.method
}

// revisionDeclaration returns the `_meta` members eunox stamps on the requests it originates on
// a declaring leg: the revision, and the empty client-capabilities object its `initialize`
// params already offer (a proxy advertises no capabilities of its own upstream).
//
// Per member rather than as one pre-encoded block, so DeclareUpstreamRevision can merge them
// into whatever `_meta` the request already carries instead of replacing it.
func revisionDeclaration(rev capability.Revision) map[string]json.RawMessage {
	version, _ := json.Marshal(rev.String())
	return map[string]json.RawMessage{
		capability.MetaKeyProtocolVersion:    version,
		capability.MetaKeyClientCapabilities: json.RawMessage(`{}`),
	}
}

// metaMember is the params member every MCP request carries its out-of-band metadata in.
const metaMember = "_meta"

// DeclareUpstreamRevision returns msg with the leg's per-request revision declaration merged
// into its params — and into whatever `_meta` block they already carry — or msg unchanged on a
// leg that negotiated once.
//
// Only for requests eunox ORIGINATES — the opener and the session-start drift probe. A host's
// own params are forwarded verbatim, `_meta` included: adding a member to them is translation,
// which the mismatched-pair boundary governs and this build does not do. The consequence is
// stated in docs/conformance.md rather than papered over here: a host message reaching a
// declaring leg must carry its own declaration, which on a matched pair it already does.
//
// Merged at BOTH levels, not just the params one. Replacing `_meta` wholesale would silently
// drop whatever else the caller put there — a progress token, an attribution block — and the
// only symptom would be the member's absence at the upstream. Nothing eunox originates carries
// one today; that is why the wholesale write survived review, and why the merge is written now
// rather than the first time it matters.
//
// Fails closed on every malformed shape, including the two that look like successes: params
// that decode to JSON `null` (which unmarshals into a map by NILLING it, with no error, so an
// unguarded write panics), and params carrying a duplicate key (mcp.DecodeParams refuses those,
// where a plain Unmarshal would resolve one last-wins and re-emit normalized bytes — the
// enforcement-versus-upstream parser differential mcp.DeclaredRevision refuses for the same
// reason).
func DeclareUpstreamRevision(msg mcp.RPCMsg, rev capability.Revision) (mcp.RPCMsg, error) {
	if !declaresPerRequestRevision(rev) {
		return msg, nil
	}
	fail := func(err error) (mcp.RPCMsg, error) {
		return mcp.RPCMsg{}, fmt.Errorf("declaring revision %s on %s: %w", rev, msg.Method, err)
	}
	fields := map[string]json.RawMessage{}
	if len(msg.Params) > 0 {
		if err := mcp.DecodeParams(msg.Params, &fields); err != nil {
			return fail(fmt.Errorf("params are not a JSON object: %w", err))
		}
	}
	// A `null` params body decodes without error and leaves the map nil, so re-make it rather
	// than writing into nil.
	if fields == nil {
		fields = map[string]json.RawMessage{}
	}
	meta := map[string]json.RawMessage{}
	if existing, ok := fields[metaMember]; ok && len(existing) > 0 {
		if err := mcp.DecodeParams(existing, &meta); err != nil {
			return fail(fmt.Errorf("existing %s is not a JSON object: %w", metaMember, err))
		}
		if meta == nil {
			meta = map[string]json.RawMessage{}
		}
	}
	for key, value := range revisionDeclaration(rev) {
		meta[key] = value
	}
	encoded, err := json.Marshal(meta)
	if err != nil {
		return fail(err)
	}
	fields[metaMember] = encoded
	raw, err := json.Marshal(fields)
	if err != nil {
		return fail(err)
	}
	msg.Params = raw
	return msg, nil
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
	spec := openerFor(rev)
	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: id, Method: spec.method}
	if !spec.declares {
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
//
// No error return: the notification carries no params, and mcp.NotificationMsg marshals
// nothing in that case, so there is nothing here that can fail. An always-nil error forced
// three different idioms across five call sites, one of which (`if err != nil || !wanted {
// return err }`) returns nil to mean "nothing to do" and reads as a bug.
func UpstreamOpenerCompletion(rev capability.Revision) (mcp.RPCMsg, bool) {
	completion := openerFor(rev).completion
	if completion == "" {
		return mcp.RPCMsg{}, false
	}
	notif, _ := mcp.NotificationMsg(completion, nil)
	return notif, true
}

// reportUpstreamOpenNotice writes an opener's non-fatal disagreement to a leg's diagnostic
// stream, or nothing when there is none.
//
// Exempt from the notice budget by the shape every caller shares: it runs once per LEG OPEN,
// which costs an upstream spawn or handshake, so a peer cannot drive it at a per-frame rate.
// One function rather than three inline writes so the three transports cannot disagree about
// whether a disagreement is reported at all — the silence this notice exists to end was
// itself three sites agreeing to say nothing.
func reportUpstreamOpenNotice(errOut io.Writer, hs UpstreamHandshake) {
	if hs.Notice == "" {
		return
	}
	_, _ = fmt.Fprintf(resolvedErrOut(errOut), "[eunox] WARN upstream protocol revision: %s\n", hs.Notice)
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
	// Notice is a non-fatal disagreement the caller must SURFACE rather than swallow: the
	// upstream answered a protocol version this build does not speak, so the leg continues at
	// the revision it was opened at. Empty when there is nothing to report. It is a return
	// value rather than a stderr write here because this function is shared with the CLI probe,
	// which writes to its own stream. See checkNegotiatedRevision for why this is a notice
	// rather than a refusal.
	Notice string
}

// openerResult extracts the success result bytes from an opener reply, failing closed on any
// non-success shape rather than handing the caller a session backed by an unconfirmed
// upstream. method names the opener in the error, since the two are told apart by nothing else
// on this path.
//
// The exactly-one-of-result/error shape is isMalformedResponse's, not a fourth hand-written
// spelling of it: this is the ONLY well-formedness gate the subprocess and local-HTTP openers
// pass (they read through awaitStartupReply, which does not run correlateUpstreamReply), so a
// reply carrying BOTH members must be refused here rather than silently read as a rejection.
func openerResult(method string, resp mcp.RPCMsg) (json.RawMessage, error) {
	if isMalformedResponse(resp) {
		return nil, fmt.Errorf("upstream %s response carried neither result nor error (or both)", method)
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("upstream %s rejected: %s (code %d)", method, resp.Error.Message, resp.Error.Code)
	}
	return resp.Result, nil
}

// ApplyUpstreamOpenerResult validates the reply to a leg opened at rev and extracts the
// handshake facts. Exported and shared with the CLI's live-upstream probe so the proxy and CLI
// cannot diverge on what counts as a valid open.
//
// Both openers reach checkNegotiatedRevision, not just the handshake. A declaring revision
// negotiates no version, so a conforming discover reply carries none and the check passes on
// an empty string — but an upstream that VOLUNTEERS one is stating a disagreement, and letting
// exactly one of the two openers skip the judgement is how "check the answer, never infer from
// it" would have held for half the legs.
func ApplyUpstreamOpenerResult(rev capability.Revision, resp mcp.RPCMsg) (UpstreamHandshake, error) {
	spec := openerFor(rev)
	method := spec.method
	raw, err := openerResult(method, resp)
	if err != nil {
		return UpstreamHandshake{}, err
	}
	var result mcp.InitResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return UpstreamHandshake{}, fmt.Errorf("upstream %s result malformed: %w", method, err)
	}
	// Unmarshalling JSON `null` into a struct succeeds with all fields zero, which would be
	// accepted as a successful open with empty capabilities. Require the mandatory fields
	// before accepting it (fail closed).
	// requireVersion follows the opener's own declaration: only an opener that NEGOTIATES a
	// version can be missing one.
	if err := validateOpenerResultFields(method, result, spec.negotiatesVersion); err != nil {
		return UpstreamHandshake{}, err
	}
	notice, err := checkNegotiatedRevision(rev, result.ProtocolVersion)
	if err != nil {
		return UpstreamHandshake{}, err
	}
	return UpstreamHandshake{
		Capabilities:  result.Capabilities,
		Instructions:  result.Instructions,
		ServerVersion: serverInfoVersion(result.ServerInfo),
		Notice:        notice,
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

// validateOpenerResultFields rejects a structurally invalid opener result — most importantly a
// JSON `null`, which unmarshals without error but leaves every field zero.
//
// requireVersion is the one difference between the two openers: the handshake NEGOTIATES a
// version, so a reply without one negotiated nothing; a declaring revision has no version to
// answer with, and requiring one there would refuse every conforming server.
func validateOpenerResultFields(method string, result mcp.InitResult, requireVersion bool) error {
	if requireVersion && result.ProtocolVersion == "" {
		return fmt.Errorf("upstream %s result missing required 'protocolVersion' (a null or empty result is not a valid MCP handshake)", method)
	}
	if result.Capabilities == nil {
		return fmt.Errorf("upstream %s result missing required 'capabilities' object", method)
	}
	if result.ServerInfo == nil {
		return fmt.Errorf("upstream %s result missing required 'serverInfo' object", method)
	}
	return nil
}

// checkNegotiatedRevision judges the version a handshake answered against the revision the leg
// was OPENED at, and the two failures get different answers because their blast radii differ.
//
//   - A version this build DOES speak but that is not the one offered is REFUSED. The resulting
//     leg would look negotiated while eunox spoke a revision over a leg opened with a method
//     that revision removed — an incoherence with no honest way to continue.
//   - A version this build does NOT speak is reported and the leg continues at the revision it
//     was opened at. That is the surface every release so far presented, and refusing it instead
//     would take eunox offline against every server on a revision outside the published set —
//     which today is most of them, since the handshake rule requires a server that cannot meet
//     the offered version to answer with its own. What was wrong before was not the fallback but
//     the SILENCE: it resolved to the default with nothing on stderr and nothing in the drift
//     check, which compares serverInfo.version and never this. The returned notice is what
//     closes that, so an operator learns the upstream disagreed rather than discovering it from
//     a header naming a negotiation that did not happen.
//
// The notice reflects the upstream's own string back, bounded and stripped of control
// characters through the same rule a peer's takes: it is a startup diagnostic, and an unbounded
// one would put an upstream in control of the console.
func checkNegotiatedRevision(opened capability.Revision, reported string) (notice string, err error) {
	// An opener built with no explicit revision opened at the default, the same resolution
	// every other empty carrier takes; judging on the strength of an empty string would name a
	// revision no caller chose.
	opened = resolveRevision(opened)
	// Nothing stated is nothing to judge. Only a declaring leg reaches this with an empty
	// string — the handshake opener's own result validation requires the member before this
	// runs — and that revision negotiates no version, so silence there is conformance.
	if reported == "" {
		return "", nil
	}
	got, ok := capability.ParseRevision(reported)
	if !ok {
		return fmt.Sprintf("upstream answered protocolVersion %q, which this build does not speak (it speaks %s); this leg continues at %s, which is the version eunox offered — its requests carry that in MCP-Protocol-Version, so an upstream expecting its own will refuse them",
			mcp.BoundReflectedRevision(reported), strings.Join(capability.PublishedRevisionNames(), ", "), opened), nil
	}
	if got != opened {
		return "", fmt.Errorf("upstream answered protocolVersion %s, but this leg was opened at %s; eunox does not switch revisions on an already-opened leg. Open it at %s instead by pinning `protocolVersion: %s` on this upstream — but note that pin also selects the OPENER, so only pin a revision the upstream implements the opener for, and only where the host can declare the same revision (see docs/conformance.md)",
			got, opened, got, got)
	}
	return "", nil
}
