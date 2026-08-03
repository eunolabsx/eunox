// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"context"
	"sync"

	"github.com/eunolabs/eunox/pkg/capability"
)

// builtinConditionEngine is an engine carrying nothing but the built-in handler registry:
// no counter, no store, no policy. It is what "the semantics this build ships" means for a
// caller that holds no *Engine at all — a JWT-only route, a wiretap route — and it is built
// lazily so importing this package for anything else costs nothing.
var builtinConditionEngine = sync.OnceValue(func() *Engine { return New() })

// NonCommittingConditionVerdict evaluates cond under the BUILT-IN semantics this build
// ships, for a caller that has no *Engine to dispatch through. See the method of the same
// name for what "non-committing" buys and when ok is false.
//
// A caller that DOES have an engine must use the method: the whole point is that an
// embedder's WithConditionHandler override is the deployment's meaning of that condition
// type, and this function cannot know about it.
func NonCommittingConditionVerdict(ctx context.Context, cond capability.Condition, req *capability.EnforceRequest) (*ConditionError, bool) {
	return builtinConditionEngine().NonCommittingConditionVerdict(ctx, cond, req)
}

// NonCommittingConditionVerdict evaluates ONE condition through THIS engine's own handler
// registry, without committing anything, and reports whether the engine could answer.
//
// It exists for the COMPOSED case. A layer above the engine — the JWT capability-claim
// path — derives conditions from a token and evaluates them BEFORE the deciding PDP runs,
// so a token-scoped caller is refused by the token's own grant rather than by the
// manifest. That evaluation must mean what this engine means: WithConditionHandler is the
// documented seam for an embedder to redefine a built-in, and a composing layer that
// called the package-level built-in directly would enforce one semantics on the manifest
// path and another on the JWT path for the same condition type on the same call. Neither
// verdict fails or logs; they are each internally consistent and only wrong together.
//
// ok is false in the two cases the caller must NOT paper over, and it is deliberately not
// an error value — there is exactly one right response to either, which is to fail closed:
//
//   - No handler is registered for the condition type. The engine would deny it as an
//     unknown type on its own path, so a composing layer must not treat it as passed.
//   - The registered handler COMMITS state on admit (it implements
//     CommittingConditionHandler). Running it here would consume a window slot, or write a
//     label, for a call the deciding PDP has not decided yet — and then charge it again
//     when that PDP runs. Non-committing is the property that makes evaluating ahead of
//     the decision safe at all, so an override that gave it up is refused rather than
//     silently double-charged. That is a real narrowing an embedder can hit, and it is
//     visible (the call is refused, with the condition type named) rather than silent.
//
// A nil engine answers from the built-ins, so an embedder holding an unwired *Engine — the
// fields are unexported, so that is a legitimate state — gets this build's semantics rather
// than a panic on a refusal path.
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
	if _, commits := handler.ConditionHandler.(CommittingConditionHandler); commits {
		return nil, false
	}
	return handler.Handle(ctx, cond, req), true
}
