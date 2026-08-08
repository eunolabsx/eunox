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

// maxReflectedRevisionLen bounds how much of a rejected version string is echoed back to the
// peer. The value reaches the error precisely BECAUSE it failed the closed-set match, so it
// is arbitrary caller text up to the transport's whole frame — reflecting it unbounded would
// make the refusal an amplifier. Long enough that a real revision date is never truncated.
const maxReflectedRevisionLen = 32

// DeclaredRevision reads the protocol revision a request declares in its `_meta`
// (capability.MetaKeyProtocolVersion), as 2026-07-28 requires on every request.
//
// Three outcomes, and the caller must keep them apart: a revision this build speaks; nothing
// declared (declared=false, err=nil); or a declaration this build cannot honor
// (ErrUnknownRevision).
//
// The params are DECODED rather than scanned for the key as raw bytes. A byte-substring probe
// was the obvious fast path and was wrong: JSON permits escaping any character of an object
// key (`io.modelcontextprotocol\/protocolVersion`, `\u005fmeta`), so a peer could spell the
// key in a way the probe missed while every conforming decoder — including the upstream's,
// reading the same bytes eunox forwards verbatim — still saw it. That is the enforcement
// versus upstream parser differential the DecodeParams choice below exists to close, so the
// probe cannot be the thing that reintroduces it. Cost: one JSON walk per host message.
//
// A params body that does not decode reports nothing declared rather than an error. It is a
// malformed REQUEST, and relabelling every one of those as a version failure would replace
// the target-bearing INVALID_REQUEST record the enforced-method handlers write. What keeps
// that safe is where a caller-chosen table can come from at all: this reports "nothing
// declared", so the caller resolves the context's pinned revision — or, on a context with no
// pin yet, capability.DefaultRevision. Neither is a table the malformed body chose.
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
		return "", true, fmt.Errorf("%w: %q", ErrUnknownRevision, boundReflected(version))
	}
	return parsed, true, nil
}

// boundReflected truncates a rejected version string to what is safe to echo back to the peer
// that sent it, and strips anything that is not printable ASCII so a terminal reading the
// error cannot be driven by the value. See maxReflectedRevisionLen.
func boundReflected(version string) string {
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

// unsupportedRevisionData is the constant `data` payload every -32022 refusal carries: the
// symbolic code plus every revision this build speaks, so a refused peer can retry against
// one rather than guess. Built once — none of it depends on the request, and the refusal path
// is reachable pre-authentication.
var unsupportedRevisionData = buildUnsupportedRevisionData()

func buildUnsupportedRevisionData() json.RawMessage {
	supported := capability.PublishedRevisions()
	versions := make([]string, 0, len(supported))
	for _, rev := range supported {
		versions = append(versions, rev.String())
	}
	data, _ := json.Marshal(struct {
		Code      string   `json:"code"`
		Supported []string `json:"supported"`
	}{Code: capability.ErrCodeUnsupportedProtocolVersion, Supported: versions})
	return data
}

// UnsupportedProtocolVersionResponse builds the spec's UNSUPPORTED_PROTOCOL_VERSION
// (-32022) refusal. message names what was wrong with the request's own declaration; any
// caller-supplied text it embeds has already been bounded and stripped by boundReflected.
func UnsupportedProtocolVersionResponse(id *json.RawMessage, message string) RPCMsg {
	return RPCMsg{
		JSONRPC: "2.0",
		ID:      id,
		Error: &RPCError{
			Code:    capability.JSONRPCCodeUnsupportedProtocolVersion,
			Message: capability.ErrCodeUnsupportedProtocolVersion + ": " + message,
			Data:    unsupportedRevisionData,
		},
	}
}
