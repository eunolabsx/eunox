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
//  3. It never falls back to a SHARED bucket, and it falls back to the session only for the
//     one case that is safe: a request with NO TOKEN AT ALL is anchored exactly as it is
//     today, so an unauthenticated caller can never join another caller's state. A request
//     that presented a token carrying no task_id is REFUSED rather than session-keyed — see
//     anchorUnresolved for why the two cases diverge. The failure direction is "no sharing"
//     or "no service", never "shared with everyone".
//
// The key encoding keeps the two anchors disjoint: a task-anchored key carries the kind as
// its own length-prefixed component, so a task named X and a session named X address
// different buckets, and a session-anchored key is byte-for-byte what it was before this
// existed (an operator who does not enable anchoring cannot be affected by it, including
// mid-rollout against a shared Redis backend).
const anchorKindTask = "task"

// appendStateAnchor appends the key components identifying the subject this request's
// accumulated state accrues to. It APPENDS rather than returning a fresh slice so the only two
// callers — the key builder and the task-keyed predicate — can supply the backing array they
// already have, instead of allocating one per key build on the decision path.
//
// A nil request or an empty session id yields a session anchor of "" — never a shared one.
// Every caller already fails closed on an empty session id before it builds a key (an empty
// anchor would merge anonymous callers into one bucket), so this returns the degenerate value
// rather than second-guessing those guards; it must not silently substitute some other
// identity for a session the caller is about to refuse.
func (e *Engine) appendStateAnchor(dst []string, req *capability.EnforceRequest) []string {
	if e.taskAnchored && req != nil {
		// ResolveTaskVar is the same resolver a ${task.id} allowedValues entry uses, so the
		// anchor and the manifest's own task binding cannot disagree about what the task id
		// is — or about when there isn't one. It reports absent for a missing claim, a
		// non-string claim, and a whitespace-only claim alike.
		if id, ok := capability.ResolveTaskVar(capability.TaskVarID, req.Claims); ok {
			return append(dst, anchorKindTask, id)
		}
	}
	if req == nil {
		return append(dst, "")
	}
	return append(dst, req.SessionID)
}

// anchoredOnTask reports whether THIS request's state is keyed on a task rather than on its
// session. It is NOT the same question as e.taskAnchored: a task-anchored engine still falls
// back to session keying for a request that presents no token at all, and a caller that reasons
// about cross-session sharing must ask about the request in hand. Asking the engine's mode
// instead applied a task-shaped restriction to a plainly session-keyed request — see
// rollbackLabels, where it stranded a flow label for every unauthenticated caller on the route.
//
// It resolves through the same appendStateAnchor the key builder uses rather than repeating the
// claim lookup, so it cannot disagree with the key that was actually built. The two-element
// backing array is the widest anchor there is, so the resolve costs no allocation.
func (e *Engine) anchoredOnTask(req *capability.EnforceRequest) bool {
	if !e.taskAnchored {
		return false
	}
	var buf [2]string
	anchor := e.appendStateAnchor(buf[:0], req)
	return len(anchor) > 0 && anchor[0] == anchorKindTask
}

// anchorUnresolved reports a request this engine cannot anchor as the operator configured it:
// task anchoring is on and the caller PRESENTED A TOKEN, but that token carries no usable
// mcp.task_id.
//
// Such a request would fall back to session keying, and the fallback is only safe for the case
// it was written for — a caller with no token at all, which shares state with nobody. An
// AUTHENTICATED caller mixing the two shapes on one session splits its own state across two
// buckets, and the split is a fail-open in every direction that matters: a labelOutput written
// under the task key is invisible to a sink read under the session key, a spent maxCalls
// budget is refilled, and a sequenceBlock antecedent is hidden. On an HTTP host each request
// carries its own Authorization header, so a caller can produce the mix at will.
//
// The caller turns this into a deny. That is deliberately strict — an operator who enables
// task anchoring has an IdP minting the claim, and a token without it on such a route is a
// misconfiguration the proxy cannot account for safely — and it is the fail-closed reading of
// "on any ambiguity, deny".
func (e *Engine) anchorUnresolved(req *capability.EnforceRequest) bool {
	if !e.taskAnchored || req == nil || len(req.Claims) == 0 {
		return false
	}
	_, ok := capability.ResolveTaskVar(capability.TaskVarID, req.Claims)
	return !ok
}

// anchoredKey builds a counter/store key for this request's anchor: the engine's route
// namespace, then the anchor, then whatever addresses the specific bucket (a target type and
// name, usually). It is the one place the anchor is spliced into a key, so a new piece of
// accumulated state cannot be added under session keying by accident while every existing one
// follows the task.
func (e *Engine) anchoredKey(prefix string, req *capability.EnforceRequest, tail ...string) string {
	// 1 namespace + at most 2 anchor components + the tail, sized once so the anchor lands in
	// this slice rather than in one of its own.
	parts := make([]string, 0, 3+len(tail))
	parts = append(parts, e.counterKeyNamespace)
	parts = e.appendStateAnchor(parts, req)
	parts = append(parts, tail...)
	return compositeCounterKey(prefix, parts...)
}

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
