// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement

import (
	"context"
	"fmt"

	"github.com/eunolabs/eunox/pkg/capability"
)

// Flow labels are per-session provenance state in the FlowLabelStore seam (distinct
// from the CallCounter): a labelOutput directive on an allowed source call Adds its
// labels to the session's accumulated SET, and a flowLabel condition at a sink Gets the
// set and denies when a class outside its Allow is present. Presence is the only bit
// that matters — a SET, not a count — so the store holds one entry per (session,label).
//
// The "flow" key prefix and the engine's counterKeyNamespace (route name) lead the
// store key so routes sharing one backend address disjoint label state, exactly as
// sequenceHistoryKey namespaces its history. Unlike sequenceBlock's 24h sliding window,
// flow state has NO wall-clock expiry: it is a monotonic, session-lifetime fact,
// reclaimed by the transport's Clear on session end (a windowed marker aged a taint out
// mid-session, a fail-open the "for all flows" claim cannot tolerate). See
// pkg/flowlabelstore.
//
// Under WithTaskAnchoredState the same set is keyed on the validated task instead, so taint
// crosses a hop between enforcement points rather than restarting clean on the far side.
// See anchor.go.

// flowLabelVocab is the native flow-label vocabulary, cached once from
// capability.FlowLabelVocabulary so the subset check and the accumulated-set peek do
// not re-allocate it per request. Read-only.
var flowLabelVocab = capability.FlowLabelVocabulary()

// flowKey builds the flow-label store key for a request's anchor — the session, or the
// validated task under WithTaskAnchoredState. namespace (the engine's counterKeyNamespace)
// leads so routes sharing one FlowLabelStore address disjoint label state, mirroring
// sequenceHistoryKey. There is no per-label component: the store holds the whole accumulated
// SET under this one key (Add unions, Get returns the set), where the old windowed counter
// needed one marker key per label.
func (e *Engine) flowKey(req *capability.EnforceRequest) string {
	return e.anchoredKey("flow", req)
}

// flowSessionKey is the SESSION-anchored flow key, for the one caller that has a session id
// and nothing else: the transport's teardown Clear. It equals flowKey for every request
// without task anchoring, and under task anchoring it addresses the key a task-less request
// on that session would have written — which is precisely what teardown should reclaim and
// all it should reclaim.
func (e *Engine) flowSessionKey(sessionID string) string {
	return compositeCounterKey("flow", e.counterKeyNamespace, sessionID)
}

// handleFlowLabel enforces the sink half of information-flow control: it denies when
// the session's accumulated flow labels are not a subset of the condition's Allow set
// — i.e. when a source class that flowed into this session is not permitted here. The
// check reads only eunox's per-session label state (never the payload), so it is
// deterministic with no model in the decision path.
//
// It reports ALL present-and-not-allowed classes (not only the first), so an integrity
// (untrusted) signal is never hidden behind a benign class; the single-value
// blockedLabel is the highest-vocabulary-order class present (untrusted-preferring),
// while blockedLabels carries the full set. Because the check covers the whole closed
// vocabulary, a label the sink does not explicitly permit is denied by construction —
// the allowlist survives a label the author never enumerated (fail closed). An empty
// Allow admits only an unlabeled (clean-context) flow.
//
// To avoid Peeking the vocabulary twice per sink call (once here, once in the engine's
// peekSessionLabels for the audit field) and to keep the audited carried_labels and the
// enforced set a single atomic snapshot, it prefers the accumulated set the engine
// already peeked and threaded via ctx, falling back to its own Peek only for a direct
// caller that did not thread one.
//
// Concurrency: the source's label write (recordLabels' Add) and this sink's read happen
// in two independent requests. The transport serializes the per-session decision phase
// for a flow-relevant session, so a source read
// received before an egress commits its label before the egress's sink read runs —
// deterministically, even under a client that pipelines both without waiting. (On a
// direct engine caller that does not serialize, the ordering is the caller's
// responsibility, as with sequenceBlock.)
func (e *Engine) handleFlowLabel(ctx context.Context, cond capability.Condition, req *capability.EnforceRequest) *ConditionError {
	fl, condErr := castCondition[capability.FlowLabelCondition](cond)
	if condErr != nil {
		return condErr
	}
	// Defense in depth against a typed-nil *FlowLabelCondition: castCondition matches the
	// `*T` case and returns the nil pointer with condErr==nil, so `len(fl.Allow)` below
	// would dereference nil. runConditions already rejects a typed-nil condition before
	// dispatch (its isTypedNil guard), so this is unreachable in-tree — but the source
	// half (recordLabels) guards its own typed-nil labelOutput, so guard the sink too: an
	// unevaluable condition must fail closed, never panic the enforcement goroutine.
	if fl == nil {
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeFlowLabel,
			Message:       "flowLabel condition is nil and cannot be evaluated",
		}
	}

	// Compose the delegation chain's allow-set cap into the condition's own: the effective
	// allow-set is the manifest's Allow INTERSECTED with what every hop kept. Intersection is
	// the only safe composition, because the sink rule is "present and not allowed => deny" —
	// so a hop's cap can only ever remove entries, never add one. A hop with a present-empty
	// allowLabels reduces this to the empty set, which is the full quarantine: a delegate
	// sharing a tainted task then reaches no labeled sink at all, whatever it is injected to
	// call.
	effectiveAllow := delegatedAllowLabels(fl.Allow, req.Delegation)

	// Defense in depth: the loader rejects an unknown label in Allow, but a
	// programmatically built condition can carry one. Surface it rather than silently
	// ignore (matching recordLabels, which also errors on an unknown label). The unknown-label
	// scan runs over the AUTHORED set, not the intersected one, so a typo in the manifest is
	// still reported when a delegation cap happens to have removed the entry.
	for _, l := range fl.Allow {
		if !capability.IsFlowLabel(l) {
			return &ConditionError{
				Code:          capability.ErrCodeConditionFailed,
				ConditionType: capability.ConditionTypeFlowLabel,
				Message:       fmt.Sprintf("flowLabel 'allow' contains unknown label %q; valid native labels are %v", l, flowLabelVocab),
			}
		}
	}
	allow := make(map[string]bool, len(effectiveAllow))
	for _, l := range effectiveAllow {
		allow[l] = true
	}

	// Fail closed when label state cannot be read: no store, or no session (which
	// would merge label state across anonymous callers). These guards run before the
	// threaded set is used, so a nil threaded set (which peekSessionLabels also returns
	// for these cases) can never be mistaken for "clean context".
	if e.flowStore == nil {
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeFlowLabel,
			Message:       "flow-label store not configured; flow-label state is unavailable",
		}
	}
	if req.SessionID == "" {
		return &ConditionError{
			Code:          capability.ErrCodeMissingContext,
			ConditionType: capability.ConditionTypeFlowLabel,
			Message:       "sessionId is required for flowLabel condition",
		}
	}

	// Prefer the engine's already-peeked snapshot (threaded via ctx). A real Peek error
	// makes the engine fail closed before this handler runs, so a threaded set is
	// trustworthy; the fallback reuses peekSessionLabels (the same vocab scan the audit
	// path runs, single-sourced so the two cannot drift) for a direct caller that did not
	// thread one. The flowStore==nil / empty-session guards above already fired (the
	// store is what peekSessionLabels short-circuits on, not the call counter), so its
	// own short-circuit is unreachable here and it runs the full scan.
	present, threaded := carriedLabelsFromContext(ctx)
	if !threaded {
		peeked, err := e.peekSessionLabels(ctx, req)
		if err != nil {
			return &ConditionError{
				Code:          capability.ErrCodeConditionFailed,
				ConditionType: capability.ConditionTypeFlowLabel,
				Message:       fmt.Sprintf("flow-label state lookup failed: %v", err),
			}
		}
		present = peeked
	}

	// Union in a cooperating client's per-call attribution. The interface is one-
	// directional by design: a client may declare labels the session join did not know
	// about, never fewer. Union-only means an untrusted client's declaration can produce
	// only MORE denials, which is what makes honoring it need no trust decision — an agent
	// that could narrow its own taint would defeat information-flow control with one extra
	// field, and it would be the first thing an injection reached for. The declared set is
	// used for THIS check only and is never written into session state.
	declared := capability.NormalizeDeclaredLabels(req.DeclaredLabels)
	present = unionLabels(present, declared)

	// Union in the taint every hop of the delegation chain forces onto this delegate's calls.
	// It is the same one-directional rule the client attribution above follows and safe for
	// the same reason — more taint produces only more denials — but it is not the same input:
	// the client's declaration is a cooperating agent describing its own inputs, while this is
	// what the delegators DECIDED this delegate is, carried on a verified token the delegate
	// cannot edit. A sub-agent reading arbitrary web content is `untrusted` whether or not it
	// cares to say so, which is precisely what makes the quarantine hold against an agent that
	// has been fully injected.
	//
	// Like the declaration, it is used for THIS check only and never written into the anchor's
	// stored set: it is the delegate's own constitution, not something it deposits on the task
	// for every hop that follows.
	forced := req.Delegation.ForcedLabels()
	present = unionLabels(present, forced)

	// blocked = present labels not permitted here. present is vocabulary-ordered (both
	// the threaded snapshot and the fallback append in vocab order), so blocked is too.
	var blocked []string
	for _, label := range present {
		if !allow[label] {
			blocked = append(blocked, label)
		}
	}
	if len(blocked) > 0 {
		return &ConditionError{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeFlowLabel,
			Message:       fmt.Sprintf("flow label(s) %v present in this session but not permitted at this sink", blocked),
			Details: func() map[string]interface{} {
				d := map[string]interface{}{
					// "flow": true distinguishes a source->sink flow denial from a plain
					// capability/argument denial. blockedLabels lists every offending class;
					// blockedLabel is the highest-vocabulary-order one (untrusted-preferring),
					// so a single-value consumer keyed on the integrity signal still sees it.
					"flow":          true,
					"blockedLabel":  blocked[len(blocked)-1],
					"blockedLabels": blocked,
					// The EFFECTIVE allow-set the check ran against, not the authored one:
					// under a delegation cap the two differ, and recording the manifest's
					// list would put a set on the tape that no decision used — sending an
					// operator to widen a sink rule that was never what refused the call.
					"allowLabels": effectiveAllow,
				}
				// Record the client's own attribution separately from the proxy's observed
				// state, so an auditor can tell a denial the proxy derived from one the
				// client asked for. Conflating them into carried_labels would make the
				// tape unable to answer "did we see this, or were we told?".
				if len(declared) > 0 {
					d["declared_labels"] = declared
				}
				// Recorded separately from both of the above for the same reason they are
				// separate from each other: an auditor has to be able to tell a denial the
				// proxy OBSERVED from one the client asked for from one the delegation chain
				// imposed. Conflating them leaves the tape unable to answer "why was this
				// call tainted".
				if len(forced) > 0 {
					d["delegated_labels"] = forced
				}
				return d
			}(),
		}
	}
	return nil
}

// unionLabels merges declared into present, deduplicated and in the fixed vocabulary
// order. Returns present unchanged when there is nothing to add, so the common
// non-cooperating-client path allocates nothing.
//
// The merge itself is capability.NormalizeDeclaredLabels — the same routine that
// normalizes a client's declaration at the wire boundary — rather than a second copy of
// "dedupe, then emit in vocabulary order". Two copies of that would be two places to
// update when the vocabulary grows, and they would disagree silently: the ordering here
// is what both the enforced subset check and the audit record's label fields rely on, so
// a divergence would not show up as an error, only as a differently-ordered label set on
// the tape. Both slices are bounded by the closed vocabulary (at most five entries), so
// the concat is trivially small.
func unionLabels(present, declared []string) []string {
	if len(declared) == 0 {
		return present
	}
	all := make([]string, 0, len(present)+len(declared))
	all = append(all, present...)
	all = append(all, declared...)
	return capability.NormalizeDeclaredLabels(all)
}

// peekSessionLabels reports the session's accumulated flow-label set (vocabulary order)
// for the audit record's carried_labels field and for handleFlowLabel's threaded
// snapshot. It fails closed: a store error is returned rather than silently dropped, so a
// source-only constraint (which runs no flowLabel condition to fail-closed first) cannot
// under-report the accumulated set on the signed tape — the caller denies instead.
// Returns (nil, nil) when there is nothing to read. The store returns the set in
// unspecified order, so this reorders it into the fixed vocabulary order (public..
// untrusted) — the single ordering both the enforced subset check and the audit field
// rely on.
//
// A stored label OUTSIDE the closed vocabulary is an ERROR, not something to reorder past.
// Dropping it was labelled "fail-safe" and is the opposite: the sink rule is "present and
// not in Allow => deny", so removing a present label can only SUPPRESS a denial. A store
// holding a label this build does not know — two proxy versions with different
// vocabularies sharing one Redis flow store, or a store written out-of-band — would then
// have its unknown (and, by construction, un-allowlistable) labels silently forgiven at
// every sink. Every sibling path already fails closed on an unknown label (recordLabels at
// the source, handleFlowLabel at the sink); returning an error here makes the read agree
// with them, and the caller denies. Over-denying during a mixed-version rollout is the
// point: the alternative is enforcing a policy against a label set this build cannot see.
func (e *Engine) peekSessionLabels(ctx context.Context, req *capability.EnforceRequest) ([]string, error) {
	// skipFlow (the whole policy carries no flow token) short-circuits here as well as at
	// the evaluateMatched gate, so the engine stays internally consistent even if a caller
	// passes flowRelevant=true against a skipFlow engine (e.g. the PDP audit path derives
	// flow-relevance from ConstraintHasFlow alone). skipFlow implies no flow constraint,
	// so this cannot suppress a real flow read; it only makes the gate authoritative here.
	if e.skipFlow || e.flowStore == nil || req.SessionID == "" {
		return nil, nil
	}
	present, err := e.flowStore.Get(ctx, e.flowKey(req))
	if err != nil {
		return nil, err
	}
	if len(present) == 0 {
		return nil, nil
	}
	inSet := make(map[string]bool, len(present))
	for _, l := range present {
		if !capability.IsFlowLabel(l) {
			return nil, fmt.Errorf("session flow-label store holds %q, which is not in this build's flow-label vocabulary; refusing to evaluate an information-flow policy against a label set this build cannot interpret", l)
		}
		inSet[l] = true
	}
	var out []string
	for _, label := range flowLabelVocab {
		if inSet[label] {
			out = append(out, label)
		}
	}
	return out, nil
}

// PeekSessionLabels is the exported form of peekSessionLabels, for the audit-mode
// antecedent path to back-fill carried_labels onto a downgraded-and-forwarded deny that
// never went through evaluateMatched's own peek.
func (e *Engine) PeekSessionLabels(ctx context.Context, req *capability.EnforceRequest) ([]string, error) {
	return e.peekSessionLabels(ctx, req)
}

// recordLabels performs the source half of information-flow control: it unions the
// labelOutput labels of an allowed call into the session's accumulated set (one atomic
// store Add), so a later flowLabel sink observes them. It returns the recorded labels
// (canonical vocabulary order) for the audit record's labels_out field.
//
// It runs regardless of audit/observe mode: like sequenceBlock's antecedent recording
// (RecordSessionCall / recordAuditModeAntecedent), flow provenance is history that must
// stay accurate for a later ENFORCED sink, so an observed source still records its
// labels. This differs from maxCalls, which skips its commit under --audit only because
// observing a quota would consume it; recording provenance consumes nothing.
//
// A constraint carrying labelOutput but lacking a session or store cannot persist the
// label, which would let a later sink Get empty and fail OPEN; recordLabels returns an
// error in that case (and on an unknown label, or a backend write fault) and the caller
// denies the source read fail-closed. A constraint with no labelOutput records nothing
// and returns (nil, nil).
//
// The write is a single Add of the whole label set, so — unlike the old per-label
// counter loop — there is no mid-write partial-commit to order defensively; the store
// commits the set atomically. The ordering of this write relative to RecordSessionCall
// (and the atomic-commit rollback across the two namespaces) lives in recordSourceCall.
func (e *Engine) recordLabels(ctx context.Context, req *capability.EnforceRequest, matched *capability.Constraint) ([]string, error) {
	// skipFlow short-circuits recording too, mirroring peekSessionLabels, so a skipFlow
	// engine never writes flow state regardless of the caller's flow-relevance derivation
	// (defense in depth; skipFlow implies the policy has no labelOutput to record anyway).
	if e.skipFlow {
		return nil, nil
	}
	set := map[string]bool{}
	for _, dir := range matched.Directives {
		lo, ok := capability.AsValueOrPointer[capability.LabelOutputDirective](dir)
		if !ok || lo == nil {
			// !ok: not a labelOutput. lo == nil: a typed-nil *LabelOutputDirective, which
			// AsValueOrPointer returns as (nil, true); dereferencing lo.Labels would panic.
			continue
		}
		for _, l := range lo.Labels {
			// Fail closed on an unknown label rather than silently drop it (matching
			// handleFlowLabel's Allow check): a typo'd label on a non-manifest code path
			// must not let a source assert NO taint while declaring one.
			if !capability.IsFlowLabel(l) {
				return nil, fmt.Errorf("labelOutput contains unknown flow label %q; valid native labels are %v", l, flowLabelVocab)
			}
			set[l] = true
		}
	}
	if len(set) == 0 {
		return nil, nil
	}
	if e.flowStore == nil {
		return nil, fmt.Errorf("flow label store not configured; flow labels cannot be recorded")
	}
	if req.SessionID == "" {
		return nil, fmt.Errorf("sessionId is required to record flow labels")
	}
	// out is canonical vocabulary order (public..untrusted) for labels_out. The store
	// commits the whole set in one Add, so order is immaterial to the write; it matters
	// only for the deterministic audit field.
	out := make([]string, 0, len(set))
	for _, label := range flowLabelVocab {
		if set[label] {
			out = append(out, label)
		}
	}
	if err := e.flowStore.Add(ctx, e.flowKey(req), out...); err != nil {
		return nil, err
	}
	return out, nil
}

// RecordLabels is the exported form of recordLabels for the audit-mode antecedent path:
// when an audit-mode source's deny is downgraded and the read forwarded, the labels its
// output carries must still be recorded (or a later ENFORCED sink Gets empty and fails
// open) AND surfaced on the forwarded call's audit record. It returns the recorded
// labels so the caller can stamp labels_out, mirroring the genuine-allow path. Returns
// an error on a record fault, which the caller turns into a hard deny.
func (e *Engine) RecordLabels(ctx context.Context, req *capability.EnforceRequest, matched *capability.Constraint) ([]string, error) {
	return e.recordLabels(ctx, req, matched)
}

// intersectLabels returns the members of want that are present in held, in want's order.
// Both slices are bounded by the closed vocabulary (at most five entries), so a linear scan
// beats a map.
//
// It is what bounds an approved declassification's clear to the taint the decision actually
// OBSERVED. The alternative — intersecting at commit time, against whatever the anchor holds
// a round trip later — silently widens the clear to cover a label a concurrent source added
// in between, which a set store cannot distinguish from the one the approval was granted
// against. See LabelsPendingClear.
func intersectLabels(want, held []string) []string {
	if len(want) == 0 || len(held) == 0 {
		return nil
	}
	var out []string
	for _, w := range want {
		for _, h := range held {
			if w == h {
				out = append(out, w)
				break
			}
		}
	}
	return out
}

// SourceCommitError classifies which leg of the atomic source-call commit
// (recordSourceCall) faulted, so the caller builds the matching fail-closed deny: a
// flow-label write fault (Flow=true) is a HARD deny (labelRecordFailureDenial /
// hardDenyResponse — an unlabeled forward would fail a later sink open), a declassify leg
// fault (Declassify=true) is a HARD deny via declassifyRecordFailureDenial, and a
// sequenceBlock antecedent write fault (both false) denies via recordFailureDenial.
//
// The declassify leg's fault is a BURN fault, not a clear fault: the clear is the caller's
// second phase and does not run inside this commit at all, so what can fail here is the
// ledger admission that spends a single-use grant — a CallCounter write, not a
// FlowLabelStore one. It sets Flow too, so a caller that checks Flow alone (the audit-mode
// antecedent path, which never declassifies) still routes it to a hard deny without knowing
// about the third leg; Declassify is checked first, so the two never disagree about which
// denial to build. An operator reading Flow off this should look at the flow store only when
// Declassify is unset.
type SourceCommitError struct {
	Err        error
	Flow       bool
	Declassify bool
	// SpentApprovalID names a single-use grant this commit BURNED before faulting, empty
	// when nothing was spent. It exists because the burn is the one piece of declassify
	// state the decision writes, and a fault after it produces a refusal that carries no
	// LabelsPendingClear — so without carrying the id here, a grant spent by a call that
	// never ran would reach the tape named by nothing at all, which is the reconciliation
	// gap the whole spent-approval key exists to close. The burn's OWN fault arm leaves it
	// empty: the loser of a concurrent admission records nothing, so there is nothing spent
	// to report.
	SpentApprovalID string
}

// Error implements error.
func (e *SourceCommitError) Error() string { return e.Err.Error() }

// recordSourceCall commits an allowed call's flow labels and its sequenceBlock
// antecedent as a single all-or-nothing unit, closing the cross-namespace half-commit.
// The two live in disjoint backends (the
// FlowLabelStore holds "flow:", the CallCounter holds "seq:"), so a fault between the two
// writes could otherwise strand one: a phantom seq antecedent for a call that hard-denied
// and never ran, or a stranded flow label.
//
// It writes flow FIRST (the FlowLabelStore supports targeted Remove), then the seq
// antecedent; if the seq write faults, it rolls back the flow labels THIS call added
// (out minus the pre-call carried set) so the hard-denied call leaves NEITHER committed.
// This reverses the old seq-first order, which could not clean up a stranded write at
// all. The per-session decision lock serializes this critical section, so the
// rollback removes exactly this call's additions with no concurrent writer to race.
//
// An APPROVED declassification (decl, resolved by checkDeclassify before anything was
// committed) contributes exactly ONE thing here: the BURN of a single-use grant. Its label
// clear does NOT happen here — it is deferred to CommitDeclassification, which the caller
// runs after the call has actually completed. See LabelsPendingClear for why: a clear
// applied at this point is invisible to every concurrent decision for the whole upstream
// round trip, and a sink that the taint existed to stop can be allowed and forwarded while
// the sanitizing call is still in flight. labelOutput's add stays here and is safe there
// for the mirror reason — a call that taints and then fails leaves EXTRA taint, which
// over-blocks.
//
// The burn stays for the reason it exists: it is the atomic test that makes "once" mean
// once under concurrency, so it belongs with the decision that accepted the grant, not with
// a later commit two callers could both reach. A burn that is never followed by a clear
// over-refuses (the operator mints another approval), which is the safe direction —
// burnApproval documents the same trade for the un-burn it deliberately does not offer.
//
// Every write still fails closed on its own fault (returned as a SourceCommitError the
// caller maps to the right deny). recordLabels is skipped when the constraint is not
// flow-relevant; RecordSessionCall self-guards when the policy has no sequenceBlock
// (skipAntecedentRecording) — so a flow-only or seq-only policy does exactly one write
// and needs no rollback. carriedLabels is the pre-call accumulated set (peeked by the
// caller before this commit), used to compute the rollback delta.
func (e *Engine) recordSourceCall(ctx context.Context, req *capability.EnforceRequest, matched *capability.Constraint, flowRelevant bool, carriedLabels []string, decl declassifyOutcome) (labelsOut []string, cerr *SourceCommitError) {
	var added []string
	if flowRelevant {
		var err error
		labelsOut, err = e.recordLabels(ctx, req, matched)
		if err != nil {
			return nil, &SourceCommitError{Err: err, Flow: true}
		}
		added = labelsAdded(labelsOut, carriedLabels)
	}
	if len(decl.Labels) > 0 {
		// A standing grant burns nothing and costs no round-trip; a single-use one is spent
		// here, atomically, and the loser of a concurrent race hard-denies.
		if err := e.burnApproval(ctx, decl.LedgerID); err != nil {
			e.rollbackLabels(ctx, req, added)
			return nil, &SourceCommitError{Err: err, Flow: true, Declassify: true}
		}
	}
	if err := e.RecordSessionCall(ctx, req); err != nil {
		// The seq write faulted after the label add committed: take it back out so the
		// hard-denied call leaves no taint. Best-effort — a rollback fault leaves a stranded
		// label (fail-closed: over-blocks a later sink, never a leak), the narrow accepted
		// residual. It runs before the branch because BOTH arms need it; only the error's
		// shape differs below.
		e.rollbackLabels(ctx, req, added)
		// A call that BURNED a single-use grant takes the declassify arm, so the deny it maps
		// to is the HARD one. The plain antecedent-fault deny is SOFT — downgraded and
		// FORWARDED by an --audit route — and forwarding a call whose one-shot approval was
		// just spent is the worst of both: the action runs, and the operator's single approval
		// is gone with nothing to show for it. Keyed on LedgerID because the burn is the only
		// declassify state this commit writes; the clear has not run and needs no undo. The id
		// travels with the error so the refusal can name the grant it spent.
		if decl.LedgerID != "" {
			return nil, &SourceCommitError{Err: err, Flow: true, Declassify: true, SpentApprovalID: decl.ApprovalID}
		}
		return nil, &SourceCommitError{Err: err, Flow: false}
	}
	return labelsOut, nil
}

// RecordSourceCall is the exported form of recordSourceCall for the audit-mode
// antecedent path (recordAuditModeAntecedent): when an audit-mode source's deny is
// downgraded and the read forwarded, its flow labels and sequenceBlock antecedent must
// still be recorded — atomically, so a fault leaves neither stranded — and the labels
// surfaced on the forwarded call's record. It returns labelsOut for that back-fill and a
// SourceCommitError the caller maps to a hard deny.
//
// It deliberately commits NO declassification. That path forwards a call whose verdict was
// a DENY, and the approval check that authorizes a clear runs only on the allow tail — so
// clearing here would drop a label for a call policy refused, on the strength of an
// approval nothing verified. A downgraded observe deny never untaints a session.
func (e *Engine) RecordSourceCall(ctx context.Context, req *capability.EnforceRequest, matched *capability.Constraint, flowRelevant bool, carriedLabels []string) ([]string, *SourceCommitError) {
	return e.recordSourceCall(ctx, req, matched, flowRelevant, carriedLabels, declassifyOutcome{})
}

// labelsAdded returns the labels in out that were NOT already in the pre-call carried
// set — i.e. the ones this call's Add introduced. Rolling back only these preserves a
// label a prior source in the same session already asserted. Both slices are small
// (bounded by the closed vocabulary), so a linear scan is cheaper than a map.
func labelsAdded(out, carried []string) []string {
	if len(out) == 0 {
		return nil
	}
	var added []string
	for _, l := range out {
		pre := false
		for _, c := range carried {
			if c == l {
				pre = true
				break
			}
		}
		if !pre {
			added = append(added, l)
		}
	}
	return added
}

// rollbackLabels best-effort removes the labels a faulted source call added, so a
// hard-denied call leaves no flow taint (see recordSourceCall). A nil store, empty
// session, or empty set is a no-op; a Remove fault is swallowed (the fail-closed
// residual — a stranded label over-blocks, never leaks).
func (e *Engine) rollbackLabels(ctx context.Context, req *capability.EnforceRequest, added []string) {
	if e.flowStore == nil || req.SessionID == "" || len(added) == 0 {
		return
	}
	// Not when THIS request is task-keyed. The rollback removes exactly the labels this call
	// added, computed from a snapshot peeked under this session's decision lock — and that lock
	// does not span a task key two sessions share. A concurrent session that legitimately added
	// the same label between the snapshot and here would have it deleted, leaving the task
	// UNTAINTED for a source read that really happened: a fail-open on precisely the "for all
	// flows" claim the anchor exists to extend. Declining to roll back strands this call's
	// label instead, which over-blocks a later sink — the direction the whole rollback path
	// already accepts as its residual when a Remove faults.
	//
	// The question is about the REQUEST, not the engine's mode. A task-anchored engine still
	// keys a token-less caller on its session, where the decision lock does span the key and
	// no concurrent writer exists — standing down there strands a label for a hazard that
	// cannot occur, on every unauthenticated caller the route serves.
	if e.anchoredOnTask(req) {
		return
	}
	_ = e.flowStore.Remove(ctx, e.flowKey(req), added...)
}

// CommitDeclassification applies an approved declassification's label clear, for a call
// the decision AUTHORIZED and the caller has now actually performed. It is the second half
// of the two-phase clear: the decision resolves and authorizes (LabelsPendingClear, plus
// the burn of a single-use grant), and this removes the labels once the action it sanitizes
// has run.
//
// The split is what makes the clear safe under concurrency. Applied inside the decision, the
// removal outlived the per-session decision lock the transport releases before the upstream
// forward — so for the whole round trip (bounded only by --upstream-timeout, and by nothing
// at all when it is 0) every concurrent decision on the anchor read an already-clean label
// set, and a sink the taint existed to stop could be allowed and forwarded before the
// sanitizing call had even returned. Under task-anchored state it was wider still: the lock
// is per-session and does not span a task key two sessions share, so the concurrent reader
// need not have been on the same session at all. Deferring the removal to here removes the
// window rather than narrowing it, and does so without depending on any lock: the labels are
// never absent until the call that clears them has completed.
//
// It is also why nothing above the engine needs an UNDO any more. Every refusal below the
// decision — the --require-audit=strict gate, an upstream transport failure, a redaction
// failure — now simply never calls this, so the labels were never gone and there is nothing
// to put back. The compensating restore that used to run there could only narrow the window,
// never close it, and its own failure arm was the residual fail-open an operator was told to
// alert on.
//
// A caller that never commits (a crash, a store fault here, an embedder that forgets)
// leaves the session as tainted as it found it. That over-blocks a later sink, which the
// operator resolves with another approval — the fail-closed direction, and the mirror of
// the burn's own accepted over-refusal.
//
// labels MUST be the decision's LabelsPendingClear and nothing else. That set was already
// intersected against what the anchor was carrying, INSIDE the decision's critical section,
// and this removes exactly it — it does NOT re-read the anchor. Both halves of that matter:
//
//   - Re-reading here would widen the clear to whatever the anchor holds a round trip later,
//     so a source read decided while the sanitizing call was in flight would have its
//     brand-new taint laundered by an approval granted before that read existed. A set store
//     cannot tell one occurrence of a label from another, so nothing downstream could catch
//     it. That is the mirror of the fail-open the deferral closes, and it is why the
//     intersection is a decision-time fact rather than a commit-time one.
//   - Removing exactly the pre-intersected set also makes what the tape reports and what the
//     store did the same thing by construction: labels_cleared can no longer disagree with
//     the carried_labels stamped on the same record, and the commit costs one round trip
//     rather than two on the host's response path.
//
// A caller passing a wider set than the decision authorized would clear more than the
// approval covered; the transport passes dec.LabelsPendingClear verbatim, and the parameter
// exists rather than being re-derived here because only the caller knows the call ran.
//
// Anchoring follows the request (flowKey), so a task-anchored call clears the key its
// decision was accounted against. The caller MUST therefore hand a context that still
// carries the request's validated claims: the anchor resolves from Claims["task_id"], so a
// context detached with context.Background() would clear the SESSION key instead — leaving
// the task tainted, deleting a label the session never asked to drop, and reporting success.
// Detach cancellation only (context.WithoutCancel), never the values.
func (e *Engine) CommitDeclassification(ctx context.Context, req *capability.EnforceRequest, labels []string) (cleared []string, err error) {
	if len(labels) == 0 {
		return nil, nil
	}
	// Exported, so it is reachable on an engine that holds no flow state at all — and on a
	// PDP whose commit chain terminates in a no-op. Each of those means the labels stay
	// exactly where they are, so none of them may report a clear.
	if e == nil || e.skipFlow || e.flowStore == nil || req == nil || req.SessionID == "" {
		return nil, errNoFlowStateToClear
	}
	if err := e.flowStore.Remove(ctx, e.flowKey(req), labels...); err != nil {
		// labels, not nil: the Remove may well have taken effect before the error surfaced,
		// and the caller reports which labels MAY have gone rather than claiming they did.
		return labels, err
	}
	return labels, nil
}

// errNoFlowStateToClear is what an engine holding no flow state returns from a commit it was
// asked to perform. It is an ERROR rather than a silent empty result because the two are not
// the same fact: a no-op clear is decided at decision time (LabelsPendingClear comes back
// empty and the caller never commits at all), so reaching the commit with labels in hand and
// no store is a wiring fault — the policy's sanitizing step will never take effect, and the
// old contract's `restored bool` existed precisely so that could not be mistaken for success.
// The caller records it as a failed commit, which is the loud, fail-closed direction.
var errNoFlowStateToClear = fmt.Errorf("this decision point holds no flow-label state, so an approved declassification cannot be applied (wiring fault, not a store failure)")

// ClearSessionLabels releases a session's accumulated flow-label set, called from the
// transport's session teardown so an ended session retains no state and a reused session
// id starts clean. It is a no-op when no store is
// wired, the policy uses no flow control (skipFlow), or the session id is empty — the
// same guards recordLabels/peekSessionLabels apply, so a non-flow deployment pays
// nothing on teardown.
//
// It clears the SESSION-anchored key only, which is the whole of what a session owns. Under
// WithTaskAnchoredState a request carrying a task id wrote its labels under the TASK's key,
// and that state is meant to outlive this session — clearing it here would restore exactly
// the per-PEP boundary the anchor exists to cross, and would let an agent launder a task's
// taint by disconnecting. Abandoned task state is reclaimed by the store's own idle TTL
// (Redis) or bounded by flowlabelstore.WithMaxKeys (in-memory); see WithTaskAnchoredState.
func (e *Engine) ClearSessionLabels(ctx context.Context, sessionID string) error {
	if e.flowStore == nil || e.skipFlow || sessionID == "" {
		return nil
	}
	return e.flowStore.Clear(ctx, e.flowSessionKey(sessionID))
}

// constraintHasFlow reports whether matched participates in information-flow control
// (carries a flowLabel condition or a labelOutput directive), so the engine peeks and
// records label state only for flow-relevant constraints. Delegates to the single-sourced,
// nil-safe capability.ConstraintHasFlow so the engine's allow-path gate, the PDP's
// audit-mode antecedent gate, and the config-level HasFlowLabel cannot drift on what
// counts as flow.
func constraintHasFlow(matched *capability.Constraint) bool {
	return capability.ConstraintHasFlow(matched)
}

// labelRecordFailureDenial is the fail-closed response when recordLabels cannot persist
// a marker. It is a HARD deny: unlike a plain audit-mode denial, a record fault must NOT
// be downgraded to a forwarded (observe) allow, because forwarding the source read while
// its label failed to persist leaves the read unlabeled and a later sink fails open
// (the exfil this backs). This mirrors recordAuditModeAntecedent's hardDenyResponse for
// the analogous sequenceBlock record-fault case. The "phase":"record" detail
// distinguishes it from an actual flowLabel sink denial (which carries blockedLabel).
func labelRecordFailureDenial(requestID, now string, auditOnly bool, obligations []capability.Obligation) capability.EnforceResponse {
	return denyResponse(requestID, now, auditOnly, obligations, capability.DenialInfo{
		Code:          capability.ErrCodeConditionFailed,
		ConditionType: capability.ConditionTypeFlowLabel,
		Message:       "flow-label recording failed; source->sink flow state is unreliable",
		HardDeny:      true,
		// "flow": true is the discriminator every information-flow event on the tape
		// carries (the flowLabel sink denial, the declassify refusal and its record
		// fault). Without it here, a filter keyed on that field missed the one flow event
		// an operator most needs to see: the hard deny raised when a source's label write
		// faulted.
		Details: map[string]interface{}{"flow": true, "phase": "record"},
	})
}
