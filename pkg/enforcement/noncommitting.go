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
	if cond == nil {
		return nil, false
	}
	if e == nil {
		return NonCommittingConditionVerdict(ctx, cond, req)
	}
	handler, exists := e.handlers[cond.ConditionType()]
	if !exists {
		return nil, false
	}
	if handler.pure == nil {
		// Registered as committing: it has no entry point that decides without consuming, so
		// there is nothing to run here.
		return nil, false
	}
	return handler.pure.Handle(ctx, cond, req), true
}
