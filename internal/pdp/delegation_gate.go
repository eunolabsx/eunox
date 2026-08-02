// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"context"
	"strings"
	"time"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
)

// The delegation target gate for decision paths that never reach the enforcement engine.
//
// Most enforced methods run through evaluateMatched, which applies the chain itself. Three do
// not, each for its own good reason, and each was silently unbound by the chain until this
// existed: `resources/unsubscribe` is authorized by MATCH ALONE (no conditions, no engine), a
// JWT-only route has no manifest engine at all, and a policyless route's PDP is the wiretap
// AlwaysAllowPDP. A delegate whose grant reaches nothing was still allowed on all three.
//
// The refusal itself is NOT rebuilt here. enforcement.DelegationTargetDenial is the one
// construction of it, so a call refused on this path carries the same code, condition type,
// and details a call refused inside the engine carries — an operator filtering the tape on
// `delegation: true` sees both, and a future axis added to that refusal reaches both.

// delegationTargetDenial returns the refusal for a target no hop of the request's chain
// admits, or nil when there is no chain (the overwhelming majority of requests) or the chain
// admits it. auditOnly carries the matched constraint's observe posture where the caller has
// one; a caller with no constraint in hand passes false, which leaves the refusal downgradable
// by a route-level --audit exactly as the engine's own is.
func delegationTargetDenial(ctx context.Context, clock enforcement.Clock, target EnforceTarget, auditOnly bool) *capability.EnforceResponse {
	chain := delegationFromContext(ctx)
	if chain.IsEmpty() {
		return nil
	}
	// The canonical "<type>:<bare>" spelling a grant names. It is built from the resolved
	// EnforceTarget rather than from a raw request field, so it matches what the engine's own
	// canonicalApprovalTarget produces for the same call and what the list filters test.
	//
	// An unresolved target is passed through as the EMPTY string rather than as "tool:", so
	// DelegationTargetDenial's unresolvable-target arm is the one that answers it. Concatenating
	// unconditionally made that arm unreachable from here — every canonical form carried at
	// least the type and a colon — and the call was then measured against the chain as if
	// "tool:" were an action, which no grant names, so it refused with the wrong reason.
	//
	// TrimSpace decides ONLY whether the target resolved to anything; the value compared
	// against the chain is the untrimmed one. A grant's entries are trimmed at the token
	// boundary, which tolerates padding in the CLAIM — it does not make " search " and "search"
	// the same action, and trimming the REQUEST here would have let a delegate reach a grant by
	// naming an action the grant does not name. Both arms of that are wrong, and this one is
	// wrong in the fail-open direction.
	canonical := ""
	if strings.TrimSpace(target.Name) != "" {
		canonical = string(target.Type) + ":" + target.Name
	}
	return enforcement.DelegationTargetDenial(chain, canonical, auditOnly,
		enforcement.NewRequestID(), clockNow(clock).UTC().Format(time.RFC3339Nano))
}
