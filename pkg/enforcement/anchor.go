// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement

import "github.com/eunolabs/eunox/pkg/capability"

// Every piece of accumulated enforcement state — the flow-label set a labelOutput writes,
// the sequenceBlock antecedent history, the maxCalls and cumulative blastRadius budgets — is
// addressed under an ANCHOR: the identity the state accrues to.
//
// With ONE deliberate exception, stated here so it is not read as an oversight and "fixed"
// back into the hole it closes: the single-use declassify ledger carries no session and no
// task. Anchoring it made "approve clearing this once" mean once per session (or per task),
// which is a replay of the approval rather than a scope for it. See declassifyLedgerKey. This file owns that choice, in one place, because the whole guarantee of each
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

// AnchorKind names which identity a request's state accrues to. The two constants are the
// closed set: there is no third kind, and no "unanchored".
type AnchorKind string

const (
	// AnchorKindSession keys the state on the host<->upstream connection.
	AnchorKindSession AnchorKind = "session"
	// AnchorKindTask keys it on the validated mcp.task_id claim, which two sessions can share.
	// It is also the component spliced into a task-anchored counter/store key, and the
	// condition type the anchor-unresolved refusal reports.
	AnchorKindTask AnchorKind = "task"
)

// StateAnchor is the resolved identity a request's accumulated state accrues to — the answer
// to "the same subject" for this one request.
//
// It is exported because the engine is not the only thing that has to know: a transport
// serializing the decision phase must take its turn on the key the state actually LIVES on
// (see the decision turn in internal/transport), and a turn keyed on anything else is not
// serialization at all. Two independent readings of "is this request task-anchored, and under
// which id" is exactly where the gate and the key come to disagree — silently, since nothing
// compares them — so both sides resolve through ResolveStateAnchor and neither re-derives the
// fallback.
//
// The ENCODING is deliberately not shared, and that is a property of the two consumers rather
// than an oversight: the engine splices the anchor into a length-prefixed counter/store key
// whose session form must stay byte-for-byte what it was before task anchoring existed (an
// operator who never enabled it must not have their Redis budgets re-keyed by a release),
// while an in-process turn registry needs one opaque, unambiguous map key and has no stored
// history to preserve. Key() below is that second form, and it is the only other encoding in
// the tree.
type StateAnchor struct {
	// Kind is which identity this request resolved to.
	Kind AnchorKind
	// ID is the identity within that kind: the validated task id, or the session id.
	ID string
}

// ResolveStateAnchor picks the anchor for one request. taskAnchored is the operator's
// WithTaskAnchoredState setting for this engine or route; hasTask/taskID are the result of
// resolving the validated mcp.task_id claim (capability.ResolveTaskVar for the engine,
// pdp.TaskAnchor for the transport — the same resolver either way, so "there isn't one"
// means the same thing on both sides).
//
// The session fallback fires when task anchoring is off and when the caller presented no
// usable task claim. It is never a shared bucket: the failure direction is "no sharing", and
// an AUTHENTICATED caller whose token carries no task id is refused outright rather than
// session-keyed (see anchorUnresolved) — a decision that belongs to the engine, not here,
// because this must still report the turn such a request takes while it is being denied.
func ResolveStateAnchor(taskAnchored, hasTask bool, taskID, sessionID string) StateAnchor {
	if taskAnchored && hasTask {
		return StateAnchor{Kind: AnchorKindTask, ID: taskID}
	}
	return StateAnchor{Kind: AnchorKindSession, ID: sessionID}
}

// Key renders the anchor as one opaque string for an in-process registry keyed on it — the
// decision turn's gate map. The separator is a NUL, which neither a session id nor a task
// claim can contain, so a session named X and a task named X never share an entry.
//
// It is NOT the engine's counter/store key and must never be used as one: those are built by
// anchoredKey, which keeps the session form byte-compatible with pre-task-anchoring
// deployments. Two encodings, one resolution — see StateAnchor.
func (a StateAnchor) Key() string { return string(a.Kind) + "\x00" + a.ID }

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
	anchor := e.resolveAnchor(req)
	if anchor.Kind == AnchorKindTask {
		return append(dst, string(anchor.Kind), anchor.ID)
	}
	// The session form carries no kind component, so it is byte-for-byte the key this engine
	// built before task anchoring existed. See the encoding note on StateAnchor.
	return append(dst, anchor.ID)
}

// resolveAnchor answers which subject this request's state accrues to, through the one
// exported resolver a transport also uses (ResolveStateAnchor), so the engine's key and a
// caller's decision turn cannot come to different answers about the same request.
//
// The claim lookup is capability.ResolveTaskVar — the same resolver a ${task.id}
// allowedValues entry uses — so the anchor and the manifest's own task binding cannot
// disagree about what the task id is, or about when there isn't one. It reports absent for a
// missing claim, a non-string claim, and a whitespace-only claim alike.
//
// A nil request yields a session anchor of "" — never a shared one. Every caller already
// fails closed on an empty session id before it builds a key, so this returns the degenerate
// value rather than substituting some other identity for a session the caller is about to
// refuse.
func (e *Engine) resolveAnchor(req *capability.EnforceRequest) StateAnchor {
	if req == nil {
		return ResolveStateAnchor(false, false, "", "")
	}
	id, hasTask := "", false
	if e.taskAnchored {
		id, hasTask = capability.ResolveTaskVar(capability.TaskVarID, req.Claims)
	}
	return ResolveStateAnchor(e.taskAnchored, hasTask, id, req.SessionID)
}

// anchoredOnTask reports whether THIS request's state is keyed on a task rather than on its
// session. It is NOT the same question as e.taskAnchored: a task-anchored engine still falls
// back to session keying for a request that presents no token at all, and a caller that reasons
// about cross-session sharing must ask about the request in hand. Asking the engine's mode
// instead applied a task-shaped restriction to a plainly session-keyed request — see
// rollbackLabels, where it stranded a flow label for every unauthenticated caller on the route.
//
// It resolves through the same resolveAnchor the key builder uses rather than repeating the
// claim lookup, so it cannot disagree with the key that was actually built — and it asks only
// about the resolved KIND. Re-testing e.taskAnchored beside that would be a second guard on a
// condition the resolver has already applied (it cannot return a task anchor with anchoring
// off), which is the shape this file exists to remove rather than add.
func (e *Engine) anchoredOnTask(req *capability.EnforceRequest) bool {
	return e.resolveAnchor(req).Kind == AnchorKindTask
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
