// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Protocol-revision negotiation, host side and upstream side.
//
// The two are tracked independently on purpose: a proxy exists to stand between peers that
// disagree, and the common migration deployment is a current host in front of a lagging
// upstream (or the reverse). The host-side result is established per context and CHECKED per
// request; the upstream-side result is probed once and pinned for the route's life.

package transport

import (
	"context"
	"errors"
	"fmt"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// errRevisionMismatch marks a request declaring a revision other than the one its context
// was opened at. It is a refusal rather than a re-negotiation: each revision has its own
// method table, so a mid-context flip is indistinguishable from a probe for the more
// permissive one — the same family of enforcement confusion as a header disagreeing with the
// body it describes.
var errRevisionMismatch = errors.New("protocol revision disagrees with the context it arrived in")

// resolveHostRevision decides which revision one host message is dispatched under.
//
// contextRev is the revision the peer's context was opened at, or "" for a context that
// never negotiated one. An undeclared revision inherits the context's, and an unnegotiated
// context falls back to capability.DefaultRevision — the surface eunox already shipped, so
// nothing reaches a different method table by omitting a declaration. (Session creation
// without a handshake, where "no context and no declaration" becomes a decision rather than
// a default, is ADR-0004's session-creation half and not this seam's to make.)
func resolveHostRevision(contextRev capability.Revision, msg mcp.RPCMsg) (capability.Revision, error) {
	declared, present, err := mcp.DeclaredRevision(msg.Params)
	if err != nil {
		return "", err
	}
	if !present {
		if contextRev != "" {
			return contextRev, nil
		}
		return capability.DefaultRevision, nil
	}
	if contextRev != "" && declared != contextRev {
		return "", fmt.Errorf("%w: context negotiated %s, request declares %s", errRevisionMismatch, contextRev, declared)
	}
	return declared, nil
}

// revisionRefusalReason turns a resolveHostRevision error into the host-facing message for
// the -32022 refusal. It names the failure class and the revision the peer declared (which
// the peer sent and which is bounded by having been matched against a closed set), never any
// other caller-supplied value.
func revisionRefusalReason(err error) string {
	// One condition, not an arm per sentinel: what this function protects is the ALLOWLIST of
	// errors whose text is safe to echo, and both of these are (each names only the failure
	// class and a version string boundReflected has already truncated and stripped). Anything
	// else collapses to a fixed string rather than leaking an unreviewed message.
	if errors.Is(err, errRevisionMismatch) || errors.Is(err, mcp.ErrUnknownRevision) {
		return err.Error()
	}
	return "protocol revision could not be established"
}

// refuseHostRevision records the refusal and builds the -32022 response for a request whose
// revision cannot be established. Shared by both transports so the record and the wire reply
// are minted together — a refusal the tape does not carry is exactly the blind spot the
// notification-framing guards exist to close.
//
// This refusal precedes the kill check on both transports, because a message whose revision
// is unresolved has no method table to be looked up in. It performs nothing and contacts no
// upstream, so a revoked session gains nothing by taking this path; what it costs is that
// such a probe is recorded under this code rather than KILL_SWITCH.
//
// A NOTIFICATION gets the record and a zero RPCMsg: JSON-RPC forbids replying to one, and
// stamping the response with a null id would read as a reply to a different request.
func refuseHostRevision(ctx context.Context, rec auditRecorder, sessionID string, msg mcp.RPCMsg, err error) mcp.RPCMsg {
	reason := revisionRefusalReason(err)
	if rec != nil {
		rec.RecordDeny(ctx, sessionID, msg.Method, msg.Method, capability.ErrCodeUnsupportedProtocolVersion, "", nil, false)
	}
	if !msg.IsRequest() {
		return mcp.RPCMsg{}
	}
	return mcp.UnsupportedProtocolVersionResponse(msg.ID, reason)
}

// resolveUpstreamRevision pins the revision a route speaks to its upstream: the operator's
// explicit config pin when set, otherwise the revision the upstream itself reported in its
// handshake. A handshake reporting a revision this build does not speak is NOT an error
// here — it falls back to the default so the existing probe's own validation stays the one
// place a bad handshake is rejected — but the pin never claims a revision nobody named.
func resolveUpstreamRevision(configured capability.Revision, handshakeVersion string) capability.Revision {
	if configured != "" {
		return configured
	}
	if rev, ok := capability.ParseRevision(handshakeVersion); ok {
		return rev
	}
	return capability.DefaultRevision
}
