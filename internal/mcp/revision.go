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

// DeclaredRevision reads the protocol revision a request declares in its `_meta`
// (capability.MetaKeyProtocolVersion), as 2026-07-28 requires on every request.
//
// Three outcomes, and the caller must keep them apart: a revision this build speaks;
// nothing declared (declared=false, err=nil); or a declaration this build cannot honor
// (ErrUnknownRevision). Malformed params report nothing declared rather than an error — the
// method handler decodes the same bytes moments later and denies them as INVALID_REQUEST
// with the target-bearing record that path already writes, and reporting a version failure
// here would relabel every malformed request as a version problem.
func DeclaredRevision(params json.RawMessage) (rev capability.Revision, declared bool, err error) {
	// Substring probe before the decode: the key is absent from every 2025-11-25 request,
	// and this runs once per host message on the hot path, so the common case pays one scan
	// instead of a full JSON walk. A false positive costs only the decode below.
	if len(params) == 0 || !bytes.Contains(params, []byte(capability.MetaKeyProtocolVersion)) {
		return "", false, nil
	}
	var probe struct {
		Meta map[string]json.RawMessage `json:"_meta"`
	}
	// DecodeParams, not json.Unmarshal: it rejects a duplicate object key at any depth, so a
	// params body carrying the version key twice cannot resolve to one revision here and a
	// different one in whatever the upstream reads from the same forwarded bytes.
	if decErr := DecodeParams(params, &probe); decErr != nil {
		return "", false, nil
	}
	raw, ok := probe.Meta[capability.MetaKeyProtocolVersion]
	if !ok {
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
		return "", true, fmt.Errorf("%w: %q", ErrUnknownRevision, version)
	}
	return parsed, true, nil
}

// UnsupportedProtocolVersionResponse builds the spec's UNSUPPORTED_PROTOCOL_VERSION
// (-32022) refusal, carrying the revisions this build speaks so a peer can retry against
// one rather than guess. message names what was wrong with the request's own declaration;
// it never echoes a caller-supplied value beyond the version string itself, which the peer
// sent and which is bounded by being compared against a closed set.
func UnsupportedProtocolVersionResponse(id *json.RawMessage, message string) RPCMsg {
	supported := capability.PublishedRevisions()
	versions := make([]string, 0, len(supported))
	for _, rev := range supported {
		versions = append(versions, rev.String())
	}
	data, _ := json.Marshal(struct {
		Code      string   `json:"code"`
		Supported []string `json:"supported"`
	}{Code: capability.ErrCodeUnsupportedProtocolVersion, Supported: versions})
	return RPCMsg{
		JSONRPC: "2.0",
		ID:      id,
		Error: &RPCError{
			Code:    capability.JSONRPCCodeUnsupportedProtocolVersion,
			Message: capability.ErrCodeUnsupportedProtocolVersion + ": " + message,
			Data:    data,
		},
	}
}
