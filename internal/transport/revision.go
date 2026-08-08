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

// errUnhonorableUpstreamDeclaration marks a request whose `_meta` revision declaration the
// upstream leg cannot be given honestly.
//
// Params are forwarded VERBATIM — nothing strips or rewrites `_meta` — and every outbound
// request carries eunox's own MCP-Protocol-Version naming the revision its leg negotiated. So
// forwarding a declaration that names a different revision does not relay a mismatched pair,
// it MANUFACTURES one: the same family of enforcement confusion errRevisionMismatch refuses on
// the host leg, with a first-wins and a last-wins upstream resolving the request under
// different method sets while eunox decided under a third. Rewriting the declaration to match
// is translation, which the mismatched-pair boundary governs and this build does not do — so
// the pair is refused instead, at the same gate and with the same code as its host-side twin.
var errUnhonorableUpstreamDeclaration = errors.New("protocol revision declaration cannot be honored by the upstream leg")

// resolveHostRevision decides which revision one host message is dispatched under.
//
// contextRev is the revision the peer's context was opened at, or "" for a context that
// never negotiated one. An undeclared revision inherits the context's, and an unnegotiated
// context falls back to capability.DefaultRevision — the surface eunox already shipped, so
// nothing reaches a different method table by omitting a declaration. (Session creation
// without a handshake, where "no context and no declaration" becomes a decision rather than
// a default, is ADR-0004's session-creation half and not this seam's to make.)
//
// legRev is the revision this proxy's UPSTREAM leg negotiated, or "" for a caller with no
// upstream leg yet (the sessionless arms, whose messages reach no upstream). It is checked
// only against an EXPLICIT declaration: omitting one leaves the body making no claim at all,
// which is the posture eunox has always shipped and manufactures nothing.
func resolveHostRevision(contextRev, legRev capability.Revision, msg mcp.RPCMsg) (capability.Revision, error) {
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
	// Asked here, on the one decode of `_meta` the whole gate does, and only for a method whose
	// params actually travel: a declaration on a locally-answered method contradicts nothing,
	// so refusing it would deny a message on the strength of a forward that never happens.
	if forwardsHostParams(msg.Method) {
		if err := checkUpstreamHonorable(declared, legRev); err != nil {
			return "", err
		}
	}
	return declared, nil
}

// checkUpstreamHonorable refuses a declaration this proxy cannot forward without contradicting
// itself. Two comparisons, because two things the upstream reads carry a revision:
//
//   - legRev, what the leg's handshake settled on. A declaration naming anything else would be
//     forwarded into a conversation held at another revision.
//   - handshakeRevision, which is what the MCP-Protocol-Version header names on every
//     post-handshake request, unconditionally: eunox opens every upstream leg with
//     `initialize`, a method only the handshake-bearing revision has. An operator's
//     protocolVersion pin does not change that opener, so on a leg pinned newer the two
//     comparisons genuinely differ, and the header is the one the upstream reads beside the
//     body. When an opener for a newer revision exists, the second comparison becomes
//     redundant rather than wrong.
//
// A leg with no revision yet ("") is checked against neither: there is nothing for the
// declaration to disagree with, and refusing would deny a message on the strength of a fact
// nobody has established.
func checkUpstreamHonorable(declared, legRev capability.Revision) error {
	if legRev == "" {
		return nil
	}
	if declared != legRev {
		return fmt.Errorf("%w: the upstream leg speaks %s, request declares %s",
			errUnhonorableUpstreamDeclaration, legRev, declared)
	}
	// Reached only on a leg pinned to something the opener cannot negotiate, which is why the
	// two comparisons are separate arms and say different things.
	if declared != handshakeRevision {
		return fmt.Errorf("%w: the upstream leg is addressed as %s, request declares %s",
			errUnhonorableUpstreamDeclaration, handshakeRevision, declared)
	}
	return nil
}

// revisionRefusalReason turns a resolveHostRevision error into the host-facing message for
// the -32022 refusal. It names the failure class and the revision the peer declared (which
// the peer sent and which is bounded by having been matched against a closed set), never any
// other caller-supplied value.
func revisionRefusalReason(err error) string {
	// One condition, not an arm per sentinel: what this function protects is the ALLOWLIST of
	// errors whose text is safe to echo, and all of these are (each names only the failure
	// class and version strings — the peer's own, already matched against a closed set, and
	// this proxy's own leg revisions). Anything else collapses to a fixed string rather than
	// leaking an unreviewed message.
	if errors.Is(err, errRevisionMismatch) || errors.Is(err, mcp.ErrUnknownRevision) ||
		errors.Is(err, errUnhonorableUpstreamDeclaration) {
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
