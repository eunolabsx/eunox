// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Protocol-revision negotiation at the message layer: reading the revision a request
// declares in its `_meta`, and the spec's -32022 refusal for one that cannot be
// established. The revision vocabulary itself lives in pkg/capability (reachable from
// internal/config and internal/audit, which may not import this package).

package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/eunolabs/eunox/pkg/capability"
)

// ErrUnknownRevision marks a request that declared a protocol revision this build does not
// speak. Distinct from "declared nothing", which is not an error at this layer: only the
// negotiating caller knows whether an undeclared revision is admissible in the context the
// request arrived in.
var ErrUnknownRevision = errors.New("mcp: unsupported protocol revision")

// ErrConflictingRevision marks a message declaring a revision in more than one member. Two
// declarations are two claims; picking either is a guess, and the peer already has one way to
// state its revision.
var ErrConflictingRevision = errors.New("mcp: protocol revision declared in more than one member")

// ErrUndecodableDeclaration marks a member this build refused whole while a conforming peer
// reads it fine, so whether it declares a revision — and which — is UNKNOWN rather than
// answered.
//
// Scoped to the duplicate-key rejection, which is the whole differential: it is eunox's own
// strictness, so those bytes carry an answer for the peer they are forwarded to and none for
// the proxy forwarding them. The other decode failures are NOT this — invalid JSON is rejected
// by every decoder alike, and a shape mismatch means there was no `_meta` object for anyone to
// read a declaration out of — so they stay the plain "nothing declared" they were.
//
// Reported rather than folded into declared=false because only the caller knows which of the
// two readings its message admits. For one a method handler re-decodes and denies moments
// later, "unknown" is safely read as "nothing declared". For one whose bytes travel to a peer
// unread, it is not.
//
// Deliberately not wrapping the decode error: that error names the caller's own key spellings,
// and this one's text is echoed to the peer it refuses.
var ErrUndecodableDeclaration = errors.New("mcp: protocol revision declaration could not be decoded")

// maxReflectedRevisionLen bounds how much of a rejected version string is echoed back to the
// peer. The value reaches the error precisely BECAUSE it failed the closed-set match, so it
// is arbitrary caller text up to the transport's whole frame — reflecting it unbounded would
// make the refusal an amplifier. Long enough that a real revision date is never truncated.
const maxReflectedRevisionLen = 32

// DeclaredRevision reads the protocol revision a request declares in its `_meta`
// (capability.MetaKeyProtocolVersion), as 2026-07-28 requires on every request.
//
// Four outcomes, and the caller must keep them apart: a revision this build speaks; nothing
// declared (declared=false, err=nil); a declaration this build cannot honor
// (ErrUnknownRevision); or a body this build alone refuses, so there is no answer either way
// (ErrUndecodableDeclaration).
//
// The params are DECODED rather than scanned for the key as raw bytes. A byte-substring probe
// was the obvious fast path and was wrong: JSON permits escaping any character of an object
// key (`io.modelcontextprotocol\/protocolVersion`, `\u005fmeta`), so a peer could spell the
// key in a way the probe missed while every conforming decoder — including the upstream's,
// reading the same bytes eunox forwards verbatim — still saw it. That is the enforcement
// versus upstream parser differential the DecodeParams choice below exists to close, so the
// probe cannot be the thing that reintroduces it. Cost: one JSON walk per host message.
//
// A params body that does not decode reports nothing declared rather than an error, EXCEPT for
// the duplicate-key rejection (ErrUndecodableDeclaration, whose doc has the distinction).
// Reading a malformed body as undeclared is what keeps a version failure from replacing the
// target-bearing INVALID_REQUEST record the enforced-method handlers write, and what makes it
// safe is where a caller-chosen table can come from at all: "nothing declared" resolves the
// context's pinned revision — or, on a context with no pin yet, capability.DefaultRevision.
// Neither is a table the malformed body chose.
func DeclaredRevision(params json.RawMessage) (rev capability.Revision, declared bool, err error) {
	if len(params) == 0 {
		return "", false, nil
	}
	// Only the one key is modelled, so an unrelated `_meta` entry (an attribution block, a
	// progress token) costs no allocation of its own.
	var probe struct {
		Meta struct {
			Version json.RawMessage `json:"io.modelcontextprotocol/protocolVersion"`
		} `json:"_meta"`
	}
	// DecodeParams, not json.Unmarshal: it rejects a duplicate object key at any depth, so a
	// params body carrying the version key twice cannot resolve to one revision here and a
	// different one in whatever the upstream reads from the same forwarded bytes.
	if decErr := DecodeParams(params, &probe); decErr != nil {
		if errors.Is(decErr, errDuplicateObjectKey) {
			return "", false, ErrUndecodableDeclaration
		}
		return "", false, nil
	}
	raw := bytes.TrimSpace(probe.Meta.Version)
	// Absent, or present as an explicit null: both are the JSON spellings of "no value", and
	// a client SDK that always emits the `_meta` slot with an unset optional field sends the
	// second. Refusing it would lock out a conforming host over a serialization detail, and it
	// grants nothing — an undeclared request inherits its context's revision.
	if len(raw) == 0 || string(raw) == "null" {
		return "", false, nil
	}
	var version string
	if unmarshalErr := json.Unmarshal(raw, &version); unmarshalErr != nil {
		// Present but not a string: a declaration was made and cannot be honored. Refusing
		// (rather than reading it as absent) keeps a non-string from being a way to fall
		// back onto the context's revision while still looking like a declaration upstream.
		return "", true, fmt.Errorf("%w: protocol version must be a string", ErrUnknownRevision)
	}
	parsed, ok := capability.ParseRevision(version)
	if !ok {
		return "", true, fmt.Errorf("%w: %q", ErrUnknownRevision, BoundReflectedRevision(version))
	}
	return parsed, true, nil
}

// DeclaredRevisionOf reads msg's declaration from every member whose bytes travel to the peer
// this message is relayed to — which is NOT the same member for every framing.
//
// A request or notification declares in `params`. A RESPONSE has no params at all: MCP puts a
// result's metadata in `result._meta`, and a response is the one framing a proxy relays
// verbatim, so reading only `params` there sees nothing while the declaration reaches the
// upstream unread. That was the whole hole a per-framing honorability gate was supposed to
// close; a gate that is framing-aware over a reader that is not closes nothing.
//
// A response's `params` is checked too, even though no conforming client sends one: an
// RPCMsg re-marshals whatever it decoded, so those bytes travel as well. Declaring in both and
// disagreeing is refused rather than resolved.
func DeclaredRevisionOf(msg RPCMsg) (rev capability.Revision, declared bool, err error) {
	fromParams, inParams, err := DeclaredRevision(msg.Params)
	if err != nil || !msg.IsResponse() {
		return fromParams, inParams, err
	}
	fromResult, inResult, err := DeclaredRevision(msg.Result)
	switch {
	case err != nil:
		return "", inResult, err
	case inParams && inResult && fromParams != fromResult:
		return "", true, fmt.Errorf("%w: params declares %s, result declares %s", ErrConflictingRevision, fromParams, fromResult)
	case inResult:
		return fromResult, true, nil
	default:
		return fromParams, inParams, nil
	}
}

// BoundReflectedRevision truncates a rejected version string to what is safe to echo back to
// the peer that sent it, and strips anything that is not printable ASCII so a terminal reading
// the error cannot be driven by the value. See maxReflectedRevisionLen.
//
// Exported because the UPSTREAM leg reflects one too — a handshake naming a revision this build
// cannot speak is refused, naming what the upstream said, to an operator's console. What is
// safe to echo does not depend on which peer sent it, so it is one rule rather than two.
func BoundReflectedRevision(version string) string {
	if len(version) > maxReflectedRevisionLen {
		version = version[:maxReflectedRevisionLen] + "..."
	}
	out := []rune(version)
	for i, r := range out {
		if r < 0x20 || r > 0x7e {
			out[i] = '?'
		}
	}
	return string(out)
}

// revisionRefusalData caches the `data` payload for each symbolic code that rides the -32022
// wire integer: the code plus every revision this build speaks, so a refused peer can retry
// against one rather than guess.
//
// Built once per code — none of it depends on the request, and the refusal path is reachable
// pre-authentication. Keyed by code rather than a single value because two DIFFERENT refusals
// share the integer: one says a revision could not be established, the other that an
// established PAIR cannot carry the message. `data.code` is the only thing that separates them
// for a host or a SIEM rule, so a single cached payload would have made the distinction the
// audit tape draws invisible on the wire.
var revisionRefusalData = map[string]json.RawMessage{
	capability.ErrCodeUnsupportedProtocolVersion:    buildRevisionRefusalData(capability.ErrCodeUnsupportedProtocolVersion),
	capability.ErrCodeUntranslatableAcrossRevisions: buildRevisionRefusalData(capability.ErrCodeUntranslatableAcrossRevisions),
}

func buildRevisionRefusalData(code string) json.RawMessage {
	versions := capability.PublishedRevisionNames()
	data, _ := json.Marshal(struct {
		Code      string   `json:"code"`
		Supported []string `json:"supported"`
	}{Code: code, Supported: versions})
	return data
}

// RevisionRefusalResponse builds the spec's -32022 refusal under a named symbolic code.
// message names what was wrong; any caller-supplied text it embeds has already been bounded
// and stripped by BoundReflectedRevision.
//
// The integer is the spec's and is SHARED; the CODE is what tells a host which of the two
// revision problems it hit — one peer's revision could not be established, or two established
// revisions cannot carry this message between them. It is stamped into both the message prefix
// and `data.code`, so the greppable text and the structured field cannot disagree.
//
// Every caller names its code rather than one of them being the default behind a shorter
// spelling: the two refusals share a wire integer, which is exactly the situation in which a
// convenience wrapper gets reached for by a site that meant the other one.
//
// An unrecognized code falls back to the establish-a-revision payload rather than emitting a
// `data` block naming a code with no cached payload: this is the pre-authentication refusal
// path, and minting JSON per request there is what the cache exists to avoid.
func RevisionRefusalResponse(id *json.RawMessage, code, message string) RPCMsg {
	data, ok := revisionRefusalData[code]
	if !ok {
		code = capability.ErrCodeUnsupportedProtocolVersion
		data = revisionRefusalData[code]
	}
	return RPCMsg{
		JSONRPC: "2.0",
		ID:      id,
		Error: &RPCError{
			Code:    capability.JSONRPCCodeUnsupportedProtocolVersion,
			Message: code + ": " + message,
			Data:    data,
		},
	}
}

// headerMismatchData is the `data` block a routing-header refusal carries, built once for the
// same reason revisionRefusalData is: this refusal is reachable pre-authentication, so minting
// JSON per request is what the cache exists to avoid.
//
// It names the two HEADERS rather than the published revisions. A header mismatch is not a
// revision problem — telling a host which revisions eunox speaks would answer a question it did
// not ask and did not get wrong.
var headerMismatchData = buildHeaderMismatchData()

func buildHeaderMismatchData() json.RawMessage {
	data, _ := json.Marshal(struct {
		Code     string   `json:"code"`
		Required []string `json:"required"`
	}{Code: capability.ErrCodeHeaderMismatch, Required: []string{"Mcp-Method", "Mcp-Name"}})
	return data
}

// HeaderMismatchResponse builds the spec's -32020 refusal for a Streamable HTTP POST whose
// routing headers disagree with the body they describe.
//
// The integer is DERIVED from capability.DenialWireCode rather than written here, so the
// symbolic code and the integer a host branches on are paired in the one place that owns that
// mapping. Its sibling above hardcodes the integer it shares with a second code; this one has a
// code of its own and no reason to.
//
// message is the mismatch's own text, already bounded and control-stripped where it quotes what
// the peer sent.
func HeaderMismatchResponse(id *json.RawMessage, message string) RPCMsg {
	wire, _ := capability.DenialWireCode(capability.ErrCodeHeaderMismatch)
	return RPCMsg{
		JSONRPC: "2.0",
		ID:      id,
		Error: &RPCError{
			Code:    wire,
			Message: capability.ErrCodeHeaderMismatch + ": " + message,
			Data:    headerMismatchData,
		},
	}
}
