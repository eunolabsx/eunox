// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement

import "github.com/eunolabs/eunox/pkg/capability"

// Every piece of accumulated enforcement state — the flow-label set a labelOutput writes,
// the sequenceBlock antecedent history, the maxCalls and cumulative blastRadius budgets, the
// single-use declassify ledger — is addressed under an ANCHOR: the identity the state
// accrues to. This file owns that choice, in one place, because the whole guarantee of each
// of those features is "the same subject cannot get more than this", and the anchor is what
// "the same subject" means.
//
// The default anchor is the session, which is exactly right for one enforcement point in
// front of one host<->upstream pair. It is also the boundary the state cannot cross: a
// sub-agent delegated to a second PEP, or the same task re-entering through a fresh session,
// starts with a clean set of labels, an empty antecedent history and a full budget — so a
// source read on one hop and the sink that read feeds on the next are, to the proxy, two
// unrelated sessions. Information-flow control's "for all flows" claim spans one PEP under
// session anchoring, and no more.
//
// Task anchoring closes that gap by keying the same state on the validated mcp.task_id claim
// instead. Three properties make it safe to turn on, and each is structural rather than
// conventional:
//
//  1. It is OPT-IN (WithTaskAnchoredState). Task anchoring makes two sessions share state,
//     and sharing state is a semantic change to every budget in the policy — a maxCalls of 20
//     becomes 20 per task rather than 20 per connection. That is the point, and it is not a
//     change to make on an operator's behalf.
//  2. The anchor is a VALIDATED claim, never a caller-supplied field. req.Claims is populated
//     from the verified token, and task_id is one of the reserved keys a custom claim cannot
//     shadow (see the PDP's reservedClaimKeys). An agent therefore cannot pick which task's
//     budget it spends, which is the one way task anchoring could widen anything.
//  3. It FALLS BACK to the session, never to a shared bucket. A request with no token, or a
//     token carrying no task_id, is anchored exactly as it is today. An unauthenticated
//     caller can never join another caller's state — the failure direction is "no sharing",
//     which is the current behavior, rather than "shared with everyone", which would be both
//     a bypass and a denial-of-service.
//
// The key encoding keeps the two anchors disjoint: a task-anchored key carries the kind as
// its own length-prefixed component, so a task named X and a session named X address
// different buckets, and a session-anchored key is byte-for-byte what it was before this
// existed (an operator who does not enable anchoring cannot be affected by it, including
// mid-rollout against a shared Redis backend).
const anchorKindTask = "task"

// stateAnchor returns the key components identifying the subject this request's accumulated
// state accrues to, and the kind for the audit record. The result is a fresh slice the caller
// may append to.
//
// A nil request or an empty session id yields a session anchor of "" — never a shared one.
// Every caller already fails closed on an empty session id before it builds a key (an empty
// anchor would merge anonymous callers into one bucket), so this returns the degenerate value
// rather than second-guessing those guards; it must not silently substitute some other
// identity for a session the caller is about to refuse.
func (e *Engine) stateAnchor(req *capability.EnforceRequest) (parts []string, kind string) {
	if e.taskAnchored && req != nil {
		// ResolveTaskVar is the same resolver a ${task.id} allowedValues entry uses, so the
		// anchor and the manifest's own task binding cannot disagree about what the task id
		// is — or about when there isn't one. It reports absent for a missing claim, a
		// non-string claim, and a whitespace-only claim alike, each of which must fall back
		// rather than anchor on "".
		if id, ok := capability.ResolveTaskVar(capability.TaskVarID, req.Claims); ok {
			return []string{anchorKindTask, id}, anchorKindTask
		}
	}
	if req == nil {
		return []string{""}, anchorKindSession
	}
	return []string{req.SessionID}, anchorKindSession
}

// anchorKindSession names the default anchor in audit details and error messages.
const anchorKindSession = "session"

// anchoredKey builds a counter/store key for this request's anchor: the engine's route
// namespace, then the anchor, then whatever addresses the specific bucket (a target type and
// name, usually). It is the one place the anchor is spliced into a key, so a new piece of
// accumulated state cannot be added under session keying by accident while every existing one
// follows the task.
func (e *Engine) anchoredKey(prefix string, req *capability.EnforceRequest, tail ...string) string {
	anchor, _ := e.stateAnchor(req)
	parts := make([]string, 0, 1+len(anchor)+len(tail))
	parts = append(parts, e.counterKeyNamespace)
	parts = append(parts, anchor...)
	parts = append(parts, tail...)
	return compositeCounterKey(prefix, parts...)
}

// TaskAnchored reports whether this engine keys accumulated state on the validated task id
// when a request carries one. Exported for the transport's session teardown, which must not
// Clear task-anchored state: the whole point of the anchor is that it outlives the session
// that created it, so tearing it down on disconnect would restore exactly the boundary it
// exists to cross.
func (e *Engine) TaskAnchored() bool { return e.taskAnchored }

// sequenceHistoryKey builds the per-anchor, per-target key under which an
// allowed call is recorded for sequenceBlock lookups. namespace (the engine's
// counterKeyNamespace) is the leading component so routes sharing one CallCounter
// address disjoint history. The target type is part of the key because the bare name
// alone is ambiguous — a tool "export" and a prompt "export" would otherwise collide
// on one bucket and cross-trip each other's sequenceBlocks. Recording and Peek must
// pass the same namespace and type (see RecordSessionCall and handleSequenceBlock);
// both build the key through Engine.anchoredKey, so they cannot disagree about the
// anchor either.
func (e *Engine) sequenceHistoryKey(req *capability.EnforceRequest, targetType, target string) string {
	return e.anchoredKey("seq", req, targetType, target)
}
