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

// errUnhonorableUpstreamRevision marks a message this proxy cannot forward at the revision it
// resolved under.
//
// Params are forwarded VERBATIM into a conversation eunox itself opened with `initialize`, so
// dispatching under one revision and addressing the upstream as another does not relay a
// mismatched pair, it MANUFACTURES one — the same family of enforcement confusion
// errRevisionMismatch refuses on the host leg. The handshake is the carrier both legs have; a
// remote HTTP upstream reads a second one, the MCP-Protocol-Version header, which names the
// same revision. Rewriting the request to match is translation, which the mismatched-pair
// boundary governs and this build does not do.
var errUnhonorableUpstreamRevision = errors.New("request revision cannot be honored by the upstream leg")

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
// upstream leg yet (the sessionless arms, whose messages reach no upstream). See
// checkUpstreamHonorable for what it gates.
func resolveHostRevision(contextRev, legRev capability.Revision, msg mcp.RPCMsg) (capability.Revision, error) {
	declared, present, err := mcp.DeclaredRevision(msg.Params)
	if err != nil {
		return "", err
	}
	resolved := declared
	switch {
	case !present && contextRev != "":
		resolved = contextRev
	case !present:
		resolved = capability.DefaultRevision
	case contextRev != "" && declared != contextRev:
		return "", fmt.Errorf("%w: context negotiated %s, request declares %s", errRevisionMismatch, contextRev, declared)
	}
	// Only for a message whose params actually travel: one answered without contacting the
	// upstream contradicts nothing there, so refusing it would deny a message on the strength of
	// a forward that never happens. Asked per FRAMING — a host RESPONSE has no method to look up
	// and is relayed verbatim, so a method-keyed gate skipped exactly the class whose bytes reach
	// the upstream unconditionally.
	if paramsReachUpstream(msg) {
		if err := checkUpstreamHonorable(resolved, legRev); err != nil {
			return "", err
		}
	}
	return resolved, nil
}

// upstreamAddressedRevision is the revision this proxy PRESENTS to an upstream leg. Every leg
// is opened with `initialize`, a method only the handshake-bearing revision has, so that is
// what eunox negotiated there whatever the leg itself reported or an operator pinned — true of
// a subprocess upstream, which reads bare JSON-RPC and no header at all, as much as of a
// remote HTTP one.
//
// One expression, read by the header stamper and by the check below, so what is sent and what
// is checked cannot drift — including on the day an opener for a newer revision lands.
func upstreamAddressedRevision(_ capability.Revision) capability.Revision { return handshakeRevision }

// checkUpstreamHonorable refuses a message this proxy cannot forward without contradicting
// itself: one whose RESOLVED revision is not the one the upstream leg is addressed as.
//
// Resolved, not declared. A declaration is only half of how a message acquires its revision —
// the other half is inheriting the context, which a peer pins by declaring once on a method
// that forwards nothing. Checking the declaration alone let that peer be dispatched under the
// newer method table and forwarded anyway, on every later request that simply omitted it.
//
// Which messages reach it is paramsReachUpstream's question, not this one's; it deliberately
// covers a framing (the host response) that carries no method and is never dispatched at all,
// because "its bytes reach the upstream" is the whole trigger.
//
// A leg with no revision yet ("") is not checked: there is nothing to contradict, and refusing
// would deny a message on the strength of a fact nobody has established.
//
// Consequence worth stating: today no method the newer revision declares reaches the PIN against
// a live leg, so nothing downstream may assume the pin's value — that is incidental, not a
// property to rely on.
func checkUpstreamHonorable(resolved, legRev capability.Revision) error {
	if legRev == "" {
		return nil
	}
	if addressed := upstreamAddressedRevision(legRev); resolved != addressed {
		return fmt.Errorf("%w: this proxy addresses its upstream leg as %s, request resolves to %s",
			errUnhonorableUpstreamRevision, addressed, resolved)
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
		errors.Is(err, errUnhonorableUpstreamRevision) {
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
// stamping the response with a null id would read as a reply to a different request. A host
// RESPONSE — reachable since the honorability gate became framing-aware — is dropped the same
// way, and recorded under methodLabelServerResponse because it carries no method of its own.
func refuseHostRevision(ctx context.Context, rec auditRecorder, sessionID string, msg mcp.RPCMsg, err error) mcp.RPCMsg {
	reason := revisionRefusalReason(err)
	label := msg.Method
	if msg.IsResponse() {
		label = methodLabelServerResponse
	}
	if rec != nil {
		rec.RecordDeny(ctx, sessionID, label, label, capability.ErrCodeUnsupportedProtocolVersion, "", nil, false)
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
