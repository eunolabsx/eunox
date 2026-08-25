// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement

import "github.com/eunolabs/eunox/pkg/capability"

// Every piece of accumulated enforcement state (flow labels, sequenceBlock history, quota
// budgets) is addressed under an ANCHOR: the identity that state accrues to. The default is
// the session; WithTaskAnchoredState keys it on the validated mcp.task_id claim instead, so
// state survives a hop across enforcement points instead of resetting per session.

// AnchorKind names which identity a request's state accrues to. Closed set: session or task,
// never unanchored.
type AnchorKind string

const (
	// AnchorKindSession keys state on the host<->upstream connection.
	AnchorKindSession AnchorKind = "session"
	// AnchorKindTask keys state on the validated mcp.task_id claim, shareable across sessions.
	AnchorKindTask AnchorKind = "task"
)

// StateAnchor is the resolved identity a request's accumulated state accrues to.
//
// Exported because a transport serializing the decision phase must take its turn on the same
// key the state lives on; both sides resolve through ResolveStateAnchor so they cannot
// disagree.
//
// Key() is a separate encoding from the engine's counter/store key: the latter must stay
// byte-compatible with pre-task-anchoring deployments, while the turn registry just needs an
// opaque map key.
type StateAnchor struct {
	// Kind is which identity this request resolved to.
	Kind AnchorKind
	// ID is the identity within that kind: the validated task id, or the session id.
	ID string
}

// ResolveStateAnchor picks the anchor for one request. taskAnchored is the operator's
// WithTaskAnchoredState setting; hasTask/taskID come from resolving the validated mcp.task_id
// claim (the same resolver on both the engine and transport sides).
//
// Falls back to session only when task anchoring is off or the caller presented no task claim
// — never to a shared bucket. An authenticated caller whose token carries no task id is
// refused rather than session-keyed (see anchorUnresolved).
func ResolveStateAnchor(taskAnchored, hasTask bool, taskID, sessionID string) StateAnchor {
	if taskAnchored && hasTask {
		return StateAnchor{Kind: AnchorKindTask, ID: taskID}
	}
	return StateAnchor{Kind: AnchorKindSession, ID: sessionID}
}

// Key renders the anchor as one opaque string for an in-process registry (the decision turn's
// gate map), NUL-separated so a session and task with the same name never collide.
//
// Not the engine's counter/store key — that is anchoredKey, which stays byte-compatible with
// pre-task-anchoring deployments.
func (a StateAnchor) Key() string { return string(a.Kind) + "\x00" + a.ID }

// appendStateAnchor appends the anchor's key components. It appends rather than returning a
// fresh slice so its caller can supply a stack array as the backing store instead of
// allocating one per key build.
func (e *Engine) appendStateAnchor(dst []string, req *capability.EnforceRequest) []string {
	anchor := e.resolveAnchor(req)
	if anchor.Kind == AnchorKindTask {
		return append(dst, string(anchor.Kind), anchor.ID)
	}
	// Session form carries no kind component, so it stays byte-for-byte what this engine built
	// before task anchoring existed.
	return append(dst, anchor.ID)
}

// resolveAnchor answers which subject this request's state accrues to, through the same
// exported resolver a transport uses, so the two cannot disagree about one request.
//
// The claim lookup is capability.ResolveTaskVar, the same resolver a ${task.id} allowedValues
// entry uses, so the anchor and the manifest's own task binding agree on what "no task id"
// means.
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

// anchoredOnTask reports whether THIS request's state is keyed on a task, which is not the
// same question as e.taskAnchored: a task-anchored engine still falls back to session keying
// for a tokenless request. Resolves through resolveAnchor so it cannot disagree with the built
// key.
func (e *Engine) anchoredOnTask(req *capability.EnforceRequest) bool {
	return e.resolveAnchor(req).Kind == AnchorKindTask
}

// anchorUnresolved reports a request this engine cannot anchor as configured: task anchoring
// is on and the caller presented a token, but it carries no usable mcp.task_id.
//
// Falling back to session keying here would split an authenticated caller's state across two
// buckets (a label written under the task key invisible to a sink read under the session key),
// so the caller turns this into a hard deny instead — the fail-closed reading of "on
// ambiguity, deny".
func (e *Engine) anchorUnresolved(req *capability.EnforceRequest) bool {
	if !e.taskAnchored || req == nil || len(req.Claims) == 0 {
		return false
	}
	_, ok := capability.ResolveTaskVar(capability.TaskVarID, req.Claims)
	return !ok
}

// anchoredKey builds a counter/store key for this request's anchor: route namespace, then
// anchor, then the bucket-specific tail. The one place the anchor is spliced in, so a new
// piece of state can't accidentally land on session keying while everything else follows the
// task.
func (e *Engine) anchoredKey(prefix string, req *capability.EnforceRequest, tail ...string) string {
	// Head backed by a STACK array, and joined with the tail rather than flattened onto it:
	// namespace plus the anchor is at most three components, and the joiner only reads them.
	// The `make([]string, 0, 3+len(tail))` this replaced was a heap allocation per key built —
	// half the allocations on a path that runs per quota bucket and per sequenceBlock lookup —
	// for a slice nothing outlives the call to read.
	var backing [3]string
	head := e.appendStateAnchor(append(backing[:0], e.counterKeyNamespace), req)
	// capability.CompositeKeyJoin directly rather than through a counter-side alias: the alias
	// would be a second name for one encoding whose whole point is that there is one.
	return capability.CompositeKeyJoin(prefix, head, tail)
}

// sequenceHistoryKey builds the per-anchor, per-target key an allowed call is recorded under
// for sequenceBlock lookups. The target type is part of the key so a tool "export" and a
// prompt "export" don't collide on one bucket.
func (e *Engine) sequenceHistoryKey(req *capability.EnforceRequest, targetType, target string) string {
	return e.anchoredKey("seq", req, targetType, target)
}
