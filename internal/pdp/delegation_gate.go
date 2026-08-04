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

// The delegation target gate for decision paths that skip evaluateMatched and never
// reach the enforcement engine's own chain check: resources/unsubscribe (match-alone), a
// JWT-only route (no manifest engine), and a policyless route (AlwaysAllowPDP) — a
// delegate's grant reached nothing on all three until this existed.
//
// Reuses enforcement.DelegationTargetDenial rather than rebuilding the refusal, so a
// call refused here carries the same code/details a call refused inside the engine does.

// delegationTargetDenial returns the refusal for a target no hop of the request's chain
// admits, or nil when there's no chain or the chain admits it. auditOnly lets the
// refusal downgrade via route-level --audit exactly as the engine's own does.
func delegationTargetDenial(ctx context.Context, clock enforcement.Clock, target EnforceTarget, auditOnly bool) *capability.EnforceResponse {
	chain := delegationFromContext(ctx)
	if chain.IsEmpty() {
		return nil
	}
	// The canonical "<type>:<bare>" spelling, built from the resolved EnforceTarget so
	// it matches what canonicalApprovalTarget produces for the same call. An unresolved
	// target passes through as "" (not "tool:"), so DelegationTargetDenial's
	// unresolvable-target arm — not a wrong-reason refusal against "tool:" — answers it.
	//
	// TrimSpace decides only whether the target resolved to anything; the untrimmed
	// value is what's compared against the chain — trimming it here would let a
	// delegate reach a grant by naming an action the grant doesn't (fail-open).
	canonical := ""
	if strings.TrimSpace(target.Name) != "" {
		canonical = string(target.Type) + ":" + target.Name
	}
	return enforcement.DelegationTargetDenial(chain, canonical, auditOnly,
		enforcement.NewRequestID(), clockNow(clock).UTC().Format(time.RFC3339Nano))
}
