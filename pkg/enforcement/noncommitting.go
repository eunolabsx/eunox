// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"context"
	"sync"

	"github.com/eunolabs/eunox/pkg/capability"
)

// builtinConditionEngine is a registry-only engine (no counter/store/policy) answering
// "what does this build's built-in handler do" for a caller with no *Engine of its own.
// Built lazily so importing this package for anything else costs nothing.
var builtinConditionEngine = sync.OnceValue(func() *Engine { return New() })

// NonCommittingConditionVerdict evaluates cond under this build's built-in semantics, for a
// caller with no *Engine. A caller that HAS an engine must use the method instead: an
// embedder's WithConditionHandler override is invisible to this package-level function.
func NonCommittingConditionVerdict(ctx context.Context, cond capability.Condition, req *capability.EnforceRequest) (*ConditionError, bool) {
	return builtinConditionEngine().NonCommittingConditionVerdict(ctx, cond, req)
}

// NonCommittingConditionVerdict evaluates ONE condition through this engine's own handler
// registry without committing anything, for a composing layer (e.g. the JWT capability-claim
// path) that must decide a condition BEFORE the deciding PDP runs and needs the same
// semantics that PDP will apply, not a hardcoded copy of the built-in.
//
// ok is false, and the caller must fail closed rather than treat it as passed, when: no
// handler is registered for the type; or the handler COMMITS state on admit
// (CommittingConditionHandler) — running it here would consume a slot/write a label for a
// call the deciding PDP hasn't decided yet, then charge it again when it does.
//
// A nil engine answers from the built-ins, so an embedder holding an unwired *Engine (the
// fields are unexported, a legitimate state) gets this build's semantics instead of a panic.
func (e *Engine) NonCommittingConditionVerdict(ctx context.Context, cond capability.Condition, req *capability.EnforceRequest) (*ConditionError, bool) {
	// isTypedNil for the reason the handler half below applies it, one seam over: every
	// ConditionType() has a VALUE receiver, so a nil pointer boxed in the interface survives
	// == nil and panics on the auto-dereference this lookup performs.
	if cond == nil || isTypedNil(cond) {
		return nil, false
	}
	// Most pure handlers dereference req (Context.SourceIP, Arguments, SessionID), so dispatching
	// one would panic where the rest of the package denies — see nilRequestDenial.
	//
	// Reported as a VERDICT (ok=true) carrying the fault code rather than as ok=false: the
	// consumer renders ok=false as "this handler commits state, or is not registered", every
	// clause of which is false for a nil request, and a structured denial must not fabricate a
	// cause. denyFromCondition copies Code verbatim, so the refusal stays a non-downgradable
	// fault and no caller needs a new branch.
	if req == nil {
		return &ConditionError{
			Code:          capability.ErrCodeEnforcementError,
			ConditionType: cond.ConditionType(),
			Message:       nilSeamRefusal("NonCommittingConditionVerdict", "a nil request"),
		}, true
	}
	if e == nil {
		return NonCommittingConditionVerdict(ctx, cond, req)
	}
	handler, exists := e.handlers[cond.ConditionType()]
	if !exists {
		return nil, false
	}
	if handler.pure == nil || isTypedNil(handler.pure) {
		// No entry point that decides without consuming: registered as committing, or an entry
		// whose handler cannot be called at all. isTypedNil for the reason evalCondition applies
		// it — a nil POINTER boxed in the interface survives == nil — and the answer here must
		// match the decision path's, which denies this entry fail-closed. Reporting it as usable
		// would either panic the request goroutine or, for a nil-receiver-safe Handle, report the
		// claim condition as PASSED where the engine hard-denies it: a fail-open on the claim leg.
		return nil, false
	}
	return handler.pure.Handle(ctx, cond, req), true
}
