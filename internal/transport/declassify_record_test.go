// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/internal/config"
	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/flowlabelstore"
	"github.com/eunolabs/eunox/pkg/killswitch"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// declassifiedAllow is the decision an approved single-use declassification produces: the
// clear is AUTHORIZED (the handle carries it) and the grant is already spent, but no label
// has moved — that happens at the commit, once the call has run.
func declassifiedAllow() capability.EnforceResponse {
	return capability.EnforceResponse{
		Decision:      capability.DecisionAllow,
		CarriedLabels: []string{capability.FlowLabelInternal, capability.FlowLabelPII},
		Declassification: capability.NewDeclassification(
			[]string{capability.FlowLabelPII}, "alice@example.com", "apr-9", true),
	}
}

func cleanUpstream() func(context.Context, mcp.RPCMsg) (mcp.RPCMsg, error) {
	return func(_ context.Context, msg mcp.RPCMsg) (mcp.RPCMsg, error) {
		return mcp.RPCMsg{ID: msg.ID, Result: json.RawMessage(`{"ok":true}`)}, nil
	}
}

// commitSpy is the transport's view of the PDP for the deferred clear: it records what it
// was asked to clear and the context it was handed, and can fault or report a no-op on
// demand so both of those record shapes are reachable.
type commitSpy struct {
	labels  []string
	calls   int
	failErr error
	noop    bool // report an empty cleared set, as a clear on a clean anchor does
	// What the commit context looked like: whether it was already done, whether it stayed
	// bounded, and whether the request's values (which the state anchor resolves from)
	// survived the detach.
	sawErr    error
	sawBound  bool
	sawValue  interface{}
	sawCalled bool
}

// commitCtxProbe keys a value planted on the request context, so a test can assert the
// commit context still carries it — WithoutCancel preserves values, context.Background()
// would not.
type commitCtxProbe struct{}

func (c *commitSpy) CommitDeclassified(ctx context.Context, _ string, decl *capability.Declassification) ([]string, error) {
	c.calls++
	c.sawCalled = true
	labels := decl.Labels()
	c.labels = append([]string(nil), labels...)
	c.sawErr = ctx.Err()
	_, c.sawBound = ctx.Deadline()
	c.sawValue = ctx.Value(commitCtxProbe{})
	if c.failErr != nil {
		// A Remove can delete and then lose its reply, so the set travels with the error.
		return labels, c.failErr
	}
	if c.noop {
		return nil, nil
	}
	return labels, nil
}

// TestEnforcedForwardCore_DeclassifiedAllowRecordsTheApproval covers the transport leg of
// the declassification record — the branch that chooses the approval-carrying recorder,
// and the one that lands the three fields on the tape.
//
// It exists because that leg had NO coverage: the branch and routeSink's recorder were
// both never executed by any test, leaving the field wiring for the rarest records on the
// tape — and the ones an auditor most needs complete — unguarded.
func TestEnforcedForwardCore_DeclassifiedAllowRecordsTheApproval(t *testing.T) {
	rec, spy := &fwdRecorder{}, &commitSpy{}
	fp := forwardParams{rec: rec, sessionID: "s", callUpstream: cleanUpstream()}

	resp := enforcedForwardCore(context.Background(), fp, spy, mcp.RPCMsg{ID: mcp.RawJSON(`1`)},
		declassifiedAllow(), "tools/call", "sanitize", "sanitize", "tool", false, upstreamErrorDetail)

	require.Nil(t, resp.Error)
	require.Equal(t, 1, spy.calls, "the clear is applied once the call has actually run")
	assert.Equal(t, []string{capability.FlowLabelPII}, spy.labels)

	require.Len(t, rec.records, 1)
	got := rec.records[0]
	assert.Equal(t, "allow", got.decision, "a declassification is an allow; labels_cleared is what distinguishes it")
	assert.Equal(t, []string{capability.FlowLabelPII}, got.labelsCleared,
		"what the COMMIT changed, which is what the tape asserts")
	assert.Equal(t, "alice@example.com", got.approver)
	assert.Equal(t, "apr-9", got.approvalID)
	assert.Equal(t, []string{capability.FlowLabelInternal, capability.FlowLabelPII}, got.carriedLabels)
	assert.Equal(t, "apr-9", got.details[audit.DeclassifySpentApprovalKey],
		"the spent single-use grant is named in details, beside the signed triple, not instead of it")
	assert.Nil(t, got.details[audit.DeclassifyCommitFailedKey])
}

// TestEnforcedForwardCore_OrdinaryAllowCarriesNoApproval is the negative half: a call that
// cleared nothing takes the plain recorder and stamps none of the three fields, so no
// ordinary allow can be mistaken for a declassification.
func TestEnforcedForwardCore_OrdinaryAllowCarriesNoApproval(t *testing.T) {
	rec := &fwdRecorder{}
	fp := forwardParams{rec: rec, sessionID: "s", callUpstream: cleanUpstream()}

	enforcedForwardCore(context.Background(), fp, &commitSpy{}, mcp.RPCMsg{ID: mcp.RawJSON(`1`)},
		allowDecision(), "tools/call", "read_file", "read_file", "tool", false, upstreamErrorDetail)

	require.Len(t, rec.records, 1)
	assert.Empty(t, rec.records[0].labelsCleared)
	assert.Empty(t, rec.records[0].approver)
	assert.Empty(t, rec.records[0].approvalID)
}

// TestEnforcedForwardCore_DeclassifyDoesNotMutateCallerDetails is the aliasing guard. On
// the audit-mode tools/call path the details map an allowDetails closure returns IS the
// caller's live parsed argument map, which dispatch.go documents must never be mutated.
// Writing the approval id into it put a key the caller never sent onto the signed tape and
// silently overwrote a real argument of the same name.
func TestEnforcedForwardCore_DeclassifyDoesNotMutateCallerDetails(t *testing.T) {
	rec, spy := &fwdRecorder{}, &commitSpy{}
	fp := forwardParams{rec: rec, sessionID: "s", callUpstream: cleanUpstream()}

	// A closure returning the caller's own map by reference, as the tools/call one does.
	live := map[string]interface{}{"path": "/tmp/x"}
	enforcedForwardCore(context.Background(), fp, spy, mcp.RPCMsg{ID: mcp.RawJSON(`1`)},
		declassifiedAllow(), "tools/call", "sanitize", "sanitize", "tool", false,
		func(mcp.RPCMsg) map[string]interface{} { return live })

	assert.Equal(t, map[string]interface{}{"path": "/tmp/x"}, live,
		"the caller's argument map must be untouched")
	require.Len(t, rec.records, 1)
	assert.Equal(t, "apr-9", rec.records[0].approvalID, "the approval id travels as a field")
	assert.Equal(t, "/tmp/x", rec.records[0].details["path"], "and the caller's own keys survive the merge")
}

// TestRouteSink_DeclassifiedAllowStampsRouteIdentity pins that the gateway wrapper stamps
// the same route provenance on a declassification record that it stamps on every other
// allow. It is a hand-maintained parallel of RecordAllow, so a dropped route field would
// otherwise produce a valid, signed, chain-verified record with a blank upstream — and
// only on the rarest record shape.
func TestRouteSink_DeclassifiedAllowStampsRouteIdentity(t *testing.T) {
	dir := t.TempDir()
	sink, err := audit.Open(dir+"/audit.jsonl", dir+"/audit.key", 0, 0)
	require.NoError(t, err)
	rs := &routeSink{sink: sink, upstream: "crm", policyVersion: "1.2.3", policySHA256: "abc123"}

	rs.RecordDeclassifiedAllow(context.Background(), "s", "sanitize", "tools/call", nil, nil, false,
		nil, []string{capability.FlowLabelPII}, []string{capability.FlowLabelPII}, "alice@example.com", "apr-9")
	require.NoError(t, sink.Close())

	raw, err := os.ReadFile(dir + "/audit.jsonl")
	require.NoError(t, err)
	line := strings.TrimSpace(string(raw))
	for _, want := range []string{
		`"upstream":"crm"`, `"policy_version":"1.2.3"`, `"policy_sha256":"abc123"`,
		`"labels_cleared":["pii"]`, `"approver":"alice@example.com"`, `"approval_id":"apr-9"`,
	} {
		assert.Contains(t, line, want)
	}
}

// TestEnforcedForwardCore_RefusalBelowTheDecisionNeverCommits is the fix for the window the
// old commit ordering opened. Three of this transport's own gates refuse a call AFTER the
// decision and WITHOUT reaching the upstream, so the sanitizing action never runs. The clear
// is simply never committed — the taint stays, no undo is needed, and no window exists in
// which a concurrent decision could have seen the session untainted.
//
// The record still has to carry two facts: that an approved declassification did not take
// effect, and that the single-use grant authorizing it is spent all the same (the burn is
// atomic with the decision and has no un-burn).
//
// wantWithheld is the third fact, and it holds on exactly ONE of the three. The other two
// leave it unknowable whether the upstream ran anything — strict blocks before the forward,
// and a transport failure can follow a side effect that already happened — while the redaction
// exit is reached only after a well-formed, successful reply, so the action demonstrably ran
// and only its result was withheld. An operator reconciling the burned grant needs that
// difference: it separates "retry the work" from "the work is done, only the delivery failed".
func TestEnforcedForwardCore_RefusalBelowTheDecisionNeverCommits(t *testing.T) {
	redactingDecision := func() capability.EnforceResponse {
		dec := declassifiedAllow()
		dec.Obligations = []capability.Obligation{{Type: capability.DirectiveTypeRedactFields, Paths: []string{"$.ssn"}}}
		return dec
	}
	for name, tc := range map[string]struct {
		fp           func(*fwdRecorder, *commitSpy) forwardParams
		dec          func() capability.EnforceResponse
		wantCode     string
		wantWithheld bool
	}{
		// --require-audit=strict with a degraded trail: the upstream is never called.
		"strict-audit gate": {
			fp: func(rec *fwdRecorder, spy *commitSpy) forwardParams {
				rec.degraded, rec.reason = true, "audit trail degraded"
				return forwardParams{
					rec: rec, sessionID: "s", callUpstream: cleanUpstream(),
					strictAuditState: strictAuditState{requireAuditStrict: true},
				}
			},
			dec:      declassifiedAllow,
			wantCode: capability.ErrCodeAuditUnavailable,
		},
		"upstream failure": {
			fp: func(rec *fwdRecorder, spy *commitSpy) forwardParams {
				return forwardParams{
					rec: rec, sessionID: "s",
					callUpstream: func(context.Context, mcp.RPCMsg) (mcp.RPCMsg, error) {
						return mcp.RPCMsg{}, errors.New("upstream gone")
					},
				}
			},
			dec:      declassifiedAllow,
			wantCode: codeUpstreamError,
		},
		// The third exit, and the one that pins the commit's POSITION: the upstream did
		// answer, but the response is withheld, so the clear must not have landed either.
		"redaction failure": {
			fp: func(rec *fwdRecorder, spy *commitSpy) forwardParams {
				return forwardParams{rec: rec, sessionID: "s",
					callUpstream: func(_ context.Context, msg mcp.RPCMsg) (mcp.RPCMsg, error) {
						// A result the redact path cannot walk, so ApplyRedactObligs fails.
						return mcp.RPCMsg{ID: msg.ID, Result: json.RawMessage(`"not-an-object"`)}, nil
					}}
			},
			dec:          redactingDecision,
			wantCode:     capability.ErrCodeEnforcementError,
			wantWithheld: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			rec, spy := &fwdRecorder{}, &commitSpy{}
			resp := enforcedForwardCore(context.Background(), tc.fp(rec, spy), spy, mcp.RPCMsg{ID: mcp.RawJSON(`1`)},
				tc.dec(), "tools/call", "sanitize", "sanitize", "tool", false, upstreamErrorDetail)

			require.NotNil(t, resp.Error, "the call is refused")
			assert.Zero(t, spy.calls,
				"a call that was refused below the decision must never clear a label")

			require.Len(t, rec.records, 1)
			got := rec.records[0]
			assert.Equal(t, "deny", got.decision)
			assert.Equal(t, tc.wantCode, got.code)
			assert.Equal(t, []string{capability.FlowLabelPII}, got.details[audit.DeclassifyNotAppliedKey],
				"the tape must say an approved declassification did not take effect")
			assert.Equal(t, "apr-9", got.details[audit.DeclassifySpentApprovalKey],
				"the grant stays burned, so the record names it for reconciliation")
			assert.Equal(t, true, got.details[capability.FlowAuditDetailKey])
			assert.Empty(t, got.labelsCleared, "nothing was cleared, so nothing is claimed")

			if tc.wantWithheld {
				assert.Equal(t, true, got.details[audit.DeclassifyResultWithheldKey],
					"the upstream ran the action here, so the tape must not read like the two exits where it may not have")
				return
			}
			assert.Nil(t, got.details[audit.DeclassifyResultWithheldKey],
				"whether the action executed is unknown on this exit; claiming it did would be a fact the proxy cannot back")
		})
	}
}

// TestDeclassifyRedactionDetail_ClaimsExecutionOnlyForASuccessfulReply is the guard on the
// one fact this key asserts. Reaching the redaction exit means a reply came back; it does NOT
// mean the sanitizing action succeeded, and the difference is upstream-controlled. A reply
// flagged isError, a reply carrying an error member beside a result, and bytes this build
// cannot interpret can all reach that exit and fail redaction — so an ungated claim would let
// a hostile or merely broken upstream write "the work is done" onto the tamper-evident tape at
// will, and an operator reconciling the burned grant would re-deliver work that never ran.
//
// The gate is declassifyCommitted, the SAME predicate the success path uses, so the two cannot
// disagree about what counts as the action having happened.
func TestDeclassifyRedactionDetail_ClaimsExecutionOnlyForASuccessfulReply(t *testing.T) {
	for name, tc := range map[string]struct {
		upResp      mcp.RPCMsg
		dec         func() capability.EnforceResponse
		wantExecute bool
	}{
		"clean result": {successfulReply(), declassifiedAllow, true},
		"tool-level failure": {
			mcp.RPCMsg{ID: mcp.RawJSON(`1`), Result: json.RawMessage(`{"isError":true}`)},
			declassifiedAllow, false,
		},
		"error beside a result (a hostile upstream may emit both)": {
			mcp.RPCMsg{ID: mcp.RawJSON(`1`), Result: json.RawMessage(`{"ok":true}`),
				Error: &mcp.RPCError{Code: -32000, Message: "no"}},
			declassifiedAllow, false,
		},
		"uninterpretable bytes beside an isError probe": {
			mcp.RPCMsg{ID: mcp.RawJSON(`1`), Result: json.RawMessage(`{"isError":`)},
			declassifiedAllow, false,
		},
		// A downgraded deny is forwarded under --audit and still carries redactFields
		// obligations, so it can reach this exit; it must never be reported as an executed
		// declassification. The same guard the commit arm applies.
		"observe-mode deny": {
			successfulReply(),
			func() capability.EnforceResponse {
				dec := declassifiedAllow()
				dec.Decision = capability.DecisionDeny
				dec.Denial = &capability.DenialInfo{Code: capability.ErrCodeAuthorizationFailed}
				return dec
			}, false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := declassifyRedactionDetail(tc.dec(), tc.upResp)
			require.NotNil(t, got, "an authorized clear that did not take effect is always reported")
			assert.Equal(t, []string{capability.FlowLabelPII}, got[audit.DeclassifyNotAppliedKey])
			assert.Equal(t, true, got[capability.FlowAuditDetailKey])
			if tc.wantExecute {
				assert.Equal(t, true, got[audit.DeclassifyResultWithheldKey],
					"a successful reply is the one case where the proxy can say the action ran")
				return
			}
			assert.Nil(t, got[audit.DeclassifyResultWithheldKey],
				"the reply does not show the action succeeding, so claiming it did is a fact the proxy cannot back")
		})
	}
}

// TestDeclassifyRedactionDetail_SilentOnANonDeclassifyingCall is the negative half of the
// withheld key. A redaction failure is an ordinary enforcement error on the overwhelming
// majority of calls — no declassify directive anywhere in the deployment — and stamping a
// flow annotation on those would put an information-flow event on the tape for a call that
// has nothing to do with one, inflating exactly the filter the discriminator exists to keep
// meaningful.
func TestDeclassifyRedactionDetail_SilentOnANonDeclassifyingCall(t *testing.T) {
	assert.Nil(t, declassifyRedactionDetail(allowDecision(), successfulReply()),
		"a decision that authorized no clear and spent no grant is not a declassification event")

	// A standing grant with no `once` id still authorizes a clear, so the withheld fact is
	// reportable and rides beside the benign not-applied key rather than replacing it.
	dec := declassifiedAllow()
	dec.Declassification = capability.NewDeclassification(
		[]string{capability.FlowLabelPII}, "alice@example.com", "apr-9", false) // standing grant
	got := declassifyRedactionDetail(dec, successfulReply())
	require.NotNil(t, got)
	assert.Equal(t, true, got[audit.DeclassifyResultWithheldKey])
	assert.Equal(t, []string{capability.FlowLabelPII}, got[audit.DeclassifyNotAppliedKey],
		"both facts are true, and a consumer keyed on the benign case must still find this refusal")
	assert.Equal(t, true, got[capability.FlowAuditDetailKey])
}

// TestDeclassifyRedactionDetail_RidesAloneOnANoOpClear pins the one shape where the withheld
// key has no not-applied key beside it, because the docs and `eunox stats` both used to assert
// a containment that does not hold.
//
// A single-use grant is burned by the decision that accepts it even when the clear turns out
// to be a no-op — the anchor was not carrying the approved labels — so the handle authorizes
// no clear while still naming a spent grant. If that call then fails redaction, the withheld fact is
// still worth recording (it is what says the spent grant bought work that actually happened),
// and it is the only declassify key on the record.
func TestDeclassifyRedactionDetail_RidesAloneOnANoOpClear(t *testing.T) {
	dec := declassifiedAllow()
	// The anchor held none of the approved labels, so the handle authorizes no clear while
	// still naming the grant the decision burned.
	dec.Declassification = capability.NewDeclassification(nil, "alice@example.com", "apr-9", true)
	got := declassifyRedactionDetail(dec, successfulReply())

	require.NotNil(t, got, "the spent grant alone is worth a record")
	assert.Equal(t, true, got[audit.DeclassifyResultWithheldKey])
	assert.Equal(t, "apr-9", got[audit.DeclassifySpentApprovalKey])
	assert.NotContains(t, got, audit.DeclassifyNotAppliedKey,
		"there are no pending labels to report, so a consumer must not expect this key beside the withheld one")
}

// TestEnforcedForwardCore_CommitFaultIsRecordedOnTheAllow is the residual, and it now fails
// in the SAFE direction. The call has run and its response is in hand, so a flow-store fault
// at the commit cannot un-run it and must not be turned into a refusal; the label simply
// stays. The session then over-blocks a later sink until the operator retries under a new
// approval, which is the opposite of the old ordering's residual — labels gone for a call
// that never ran.
func TestEnforcedForwardCore_CommitFaultIsRecordedOnTheAllow(t *testing.T) {
	rec := &fwdRecorder{}
	spy := &commitSpy{failErr: errors.New("flow store unreachable")}
	fp := forwardParams{rec: rec, sessionID: "s", callUpstream: cleanUpstream()}

	resp := enforcedForwardCore(context.Background(), fp, spy, mcp.RPCMsg{ID: mcp.RawJSON(`1`)},
		declassifiedAllow(), "tools/call", "sanitize", "sanitize", "tool", false, upstreamErrorDetail)

	require.Nil(t, resp.Error, "the call ran; its response is not withheld because bookkeeping failed")
	require.Len(t, rec.records, 1)
	got := rec.records[0]
	assert.Equal(t, "allow", got.decision)
	assert.Equal(t, []string{capability.FlowLabelPII}, got.details[audit.DeclassifyCommitFailedKey],
		"an authorized clear that could not be applied is the one thing the record must carry")
	assert.Empty(t, got.labelsCleared,
		"labels_cleared is a signed claim that these labels are gone; a set that may not have landed cannot back it")
	assert.Empty(t, got.approver, "and no approver is stamped for a declassification that did not complete")
	assert.Equal(t, "apr-9", got.details[audit.DeclassifySpentApprovalKey])
	assert.Nil(t, got.details[audit.DeclassifyNotAppliedKey],
		"the call was not refused; that is a different key with a different remedy")
}

// TestEnforcedForwardCore_NoOpCommitStillNamesTheSpentGrant is the reconciliation gap a
// single-use grant used to fall into. The grant is burned by the decision that accepted it —
// deliberately, including when the clear turns out to be a no-op, because burning only on a
// clear that moved a label makes the grant replayable by ordering — while
// labels_cleared/approver/approval_id ride only on a clear that CHANGED something. Between
// the two, a real approval was spent with nothing on the signed tape naming it, and an
// operator could not tell which of their outstanding one-shot approvals were still live.
func TestEnforcedForwardCore_NoOpCommitStillNamesTheSpentGrant(t *testing.T) {
	rec, spy := &fwdRecorder{}, &commitSpy{noop: true}
	fp := forwardParams{rec: rec, sessionID: "s", callUpstream: cleanUpstream()}

	enforcedForwardCore(context.Background(), fp, spy, mcp.RPCMsg{ID: mcp.RawJSON(`1`)},
		declassifiedAllow(), "tools/call", "sanitize", "sanitize", "tool", false, upstreamErrorDetail)

	require.Equal(t, 1, spy.calls)
	require.Len(t, rec.records, 1)
	got := rec.records[0]
	assert.Empty(t, got.labelsCleared, "the anchor carried nothing, so nothing changed")
	assert.Empty(t, got.approver, "and the tape must not record a declassification that did not happen")
	assert.Equal(t, "apr-9", got.details[audit.DeclassifySpentApprovalKey],
		"but the grant IS spent, and this is the only record of it")
}

// TestEnforcedForwardCore_StandingGrantStampsNoSpentID is the negative half: a standing
// (non-`once`) grant spends nothing, so there is nothing to reconcile and no key.
func TestEnforcedForwardCore_StandingGrantStampsNoSpentID(t *testing.T) {
	rec, spy := &fwdRecorder{}, &commitSpy{}
	dec := declassifiedAllow()
	// Standing grant: authorized, but nothing burned.
	dec.Declassification = capability.NewDeclassification(
		[]string{capability.FlowLabelPII}, "alice@example.com", "apr-9", false)
	fp := forwardParams{rec: rec, sessionID: "s", callUpstream: cleanUpstream()}

	enforcedForwardCore(context.Background(), fp, spy, mcp.RPCMsg{ID: mcp.RawJSON(`1`)},
		dec, "tools/call", "sanitize", "sanitize", "tool", false, upstreamErrorDetail)

	require.Len(t, rec.records, 1)
	got := rec.records[0]
	assert.Equal(t, []string{capability.FlowLabelPII}, got.labelsCleared)
	assert.Nil(t, got.details[audit.DeclassifySpentApprovalKey], "nothing was spent, so there is nothing to reconcile")
	assert.Equal(t, true, got.details[capability.FlowAuditDetailKey],
		"every declassification event carries the information-flow discriminator, including this one")
}

// TestEnforcedForwardCore_CommitOutlivesTheRequestContext pins the context contract. The
// commit runs after the upstream has answered, and a client that disconnects while its
// response is being assembled cancels the request context — after which a context-honouring
// FlowLabelStore (the Redis backend passes ctx into every pipelined command) would refuse
// the write, losing the clear for a call that DID run. The in-memory store ignores ctx,
// which is why a test that did not assert this would pass either way.
//
// It must be detached from CANCELLATION but not from VALUES: the anchor the labels are
// cleared under resolves from the request's validated claims, so context.Background() would
// clear the session key for a task-anchored call — leaving the task tainted while deleting a
// label the session never asked to drop. WithoutCancel plus a bound is the shape.
func TestEnforcedForwardCore_CommitOutlivesTheRequestContext(t *testing.T) {
	rec, spy := &fwdRecorder{}, &commitSpy{}
	// A value stands in for the validated JWT claims the real request context carries and
	// the state anchor resolves from.
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), commitCtxProbe{}, "claims"))
	defer cancel()
	fp := forwardParams{rec: rec, sessionID: "s",
		callUpstream: func(_ context.Context, msg mcp.RPCMsg) (mcp.RPCMsg, error) {
			// What a client disconnect looks like from here: the upstream answered, and the
			// request context is done by the time the response is assembled.
			cancel()
			return mcp.RPCMsg{ID: msg.ID, Result: json.RawMessage(`{"ok":true}`)}, nil
		}}

	enforcedForwardCore(ctx, fp, spy, mcp.RPCMsg{ID: mcp.RawJSON(`1`)},
		declassifiedAllow(), "tools/call", "sanitize", "sanitize", "tool", false, upstreamErrorDetail)

	require.True(t, spy.sawCalled)
	assert.NoError(t, spy.sawErr,
		"the commit must not run on an already-canceled context — against a ctx-honouring store it would lose the clear for a call that really ran")
	assert.True(t, spy.sawBound, "and it must stay bounded rather than run unbounded after the request")
	assert.Equal(t, "claims", spy.sawValue,
		"cancellation is detached, VALUES are not: the state anchor resolves from the request's claims, so context.Background() would clear the wrong key")
	require.Len(t, rec.records, 1)
	assert.Equal(t, []string{capability.FlowLabelPII}, rec.records[0].labelsCleared)
}

// TestEnforcedForwardCore_BoundsTheSpentApprovalID keeps an IdP-supplied string off the tape
// unbounded. DeclassifyApproval.Validate places no length limit on the id, and a value
// written straight into a transport-built details map reaches the sink under only the 1 MiB
// whole-map cap — where the same value on the allow record is cut at the 8 KiB envelope cap.
func TestEnforcedForwardCore_BoundsTheSpentApprovalID(t *testing.T) {
	rec, spy := &fwdRecorder{}, &commitSpy{}
	dec := declassifiedAllow()
	longID := strings.Repeat("a", 64*1024)
	dec.Declassification = capability.NewDeclassification([]string{capability.FlowLabelPII}, "alice@example.com", longID, true)
	fp := forwardParams{rec: rec, sessionID: "s",
		callUpstream: func(context.Context, mcp.RPCMsg) (mcp.RPCMsg, error) {
			return mcp.RPCMsg{}, errors.New("upstream gone")
		}}

	enforcedForwardCore(context.Background(), fp, spy, mcp.RPCMsg{ID: mcp.RawJSON(`1`)},
		dec, "tools/call", "sanitize", "sanitize", "tool", false, upstreamErrorDetail)

	require.Len(t, rec.records, 1)
	got, ok := rec.records[0].details[audit.DeclassifySpentApprovalKey].(string)
	require.True(t, ok)
	assert.Less(t, len(got), len(longID), "an unbounded IdP string must not reach the tape verbatim")
	assert.Contains(t, got, "eunox: truncated", "and the cut must be visible")
}

// TestEnforcedForwardCore_CommitsWithTheDecidingPDP is what is left to guard once the
// committer stopped being a FIELD. It used to be forwardParams.committer, a second copy of
// the decision point the dispatcher decides with, kept in agreement by a constructor step
// (withPDP), an embedded wrapper that made the field unspellable, and an AST walk over every
// literal and assignment in the package. The core takes it as a parameter now — the shape
// commitDeclassify one layer down always had — so there is no pair to keep in agreement and
// none of that machinery has anything left to protect.
//
// One invariant does survive the deletion: the committer a call site passes must be the PDP
// that MADE the decision it is committing, not merely some decision point in scope. That is a
// property of five call expressions, and this asserts it directly on them: each passes
// X.forwardParams and X.pdp for the same X. A site that decided with d.pdp and committed with
// something else would compile and would silently apply a clear the decision never authorized
// — the same class of failure the old guard existed for, now expressible as one property of
// the call rather than as a rule about who may write a field.
func TestEnforcedForwardCore_CommitsWithTheDecidingPDP(t *testing.T) {
	t.Parallel()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	fset := token.NewFileSet()
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, name, nil, 0)
		require.NoError(t, perr)
		ast.Inspect(file, func(n ast.Node) bool {
			call, isCall := n.(*ast.CallExpr)
			if !isCall {
				return true
			}
			fn, isIdent := call.Fun.(*ast.Ident)
			if !isIdent || fn.Name != "enforcedForwardCore" || len(call.Args) < 3 {
				return true
			}
			checked++
			params, committer := receiverOf(call.Args[1], "forwardParams"), receiverOf(call.Args[2], "pdp")
			if params == "" || committer == "" || params != committer {
				t.Errorf("%s: enforcedForwardCore must be handed the decision point that MADE the decision "+
					"(pass d.forwardParams and d.pdp for the same d); got %s and %s",
					name, exprText(fset, call.Args[1]), exprText(fset, call.Args[2]))
			}
			return true
		})
	}
	require.Positive(t, checked, "no enforcedForwardCore call found in any non-test file; this guard would pass vacuously")
}

// receiverOf returns the receiver identifier of `x.field` when field matches, or "" for any
// other expression shape — which the caller treats as a failure, so an unrecognized spelling
// is reported rather than skipped.
func receiverOf(e ast.Expr, field string) string {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != field {
		return ""
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return ""
	}
	return ident.Name
}

// exprText renders an expression for a failure message, through the fileset it was parsed
// with so positions resolve.
func exprText(fset *token.FileSet, e ast.Expr) string {
	var b strings.Builder
	if err := printer.Fprint(&b, fset, e); err != nil {
		return "<unprintable>"
	}
	return b.String()
}

// TestEnforcedForwardCore_OrdinaryCallTouchesNoCommitter is the negative half: a call that
// authorized no clear must not reach the committer at all, on either the refusal or the
// allow path, and its record must not grow declassify fields. This is every call in a
// deployment with no declassify directive.
func TestEnforcedForwardCore_OrdinaryCallTouchesNoCommitter(t *testing.T) {
	for name, upstream := range map[string]func(context.Context, mcp.RPCMsg) (mcp.RPCMsg, error){
		"refused": func(context.Context, mcp.RPCMsg) (mcp.RPCMsg, error) {
			return mcp.RPCMsg{}, errors.New("upstream gone")
		},
		"forwarded": cleanUpstream(),
	} {
		t.Run(name, func(t *testing.T) {
			rec, spy := &fwdRecorder{}, &commitSpy{}
			fp := forwardParams{rec: rec, sessionID: "s", callUpstream: upstream}

			enforcedForwardCore(context.Background(), fp, spy, mcp.RPCMsg{ID: mcp.RawJSON(`1`)},
				allowDecision(), "tools/call", "read_file", "read_file", "tool", false, upstreamErrorDetail)

			assert.Zero(t, spy.calls, "a decision that authorized no clear has nothing to commit")
			require.Len(t, rec.records, 1)
			assert.Nil(t, rec.records[0].details[audit.DeclassifyNotAppliedKey])
			assert.Nil(t, rec.records[0].details[audit.DeclassifySpentApprovalKey])
		})
	}
}

// TestEnforcedForwardCore_MissingCommitterIsRecordedNotSilent covers the wiring fault the
// dispatchParams constructor makes unreachable. A params built without a committer cannot
// apply the clear, and the failure that matters is the silent one: the policy's sanitizing
// step never takes effect and nothing says so.
func TestEnforcedForwardCore_MissingCommitterIsRecordedNotSilent(t *testing.T) {
	rec := &fwdRecorder{}
	fp := forwardParams{rec: rec, sessionID: "s", callUpstream: cleanUpstream()} // no committer

	enforcedForwardCore(context.Background(), fp, nil, mcp.RPCMsg{ID: mcp.RawJSON(`1`)},
		declassifiedAllow(), "tools/call", "sanitize", "sanitize", "tool", false, upstreamErrorDetail)

	require.Len(t, rec.records, 1)
	assert.Equal(t, []string{capability.FlowLabelPII}, rec.records[0].details[audit.DeclassifyCommitFailedKey],
		"a wiring fault must land on the tape rather than pass as a completed clear")
	assert.Empty(t, rec.records[0].labelsCleared)
}

// TestDeclassifyDetailKeys_SignAndVerifyRoundTrip puts the four declassification detail
// keys through a real sink and the tamper-evident verifier, so they are covered by the record
// HMAC and survive the chain intact.
//
// It matters more for these than for an ordinary detail: two of them are what an operator
// alerts on and reconciles approvals against, and a value that reached the tape outside the
// signature would be an unauthenticated claim about the very state the tape exists to attest.
func TestDeclassifyDetailKeys_SignAndVerifyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	sink, err := audit.Open(dir+"/audit.jsonl", dir+"/audit.key", 0, 0)
	require.NoError(t, err)

	rs := &routeSink{sink: sink, upstream: "crm"}
	rs.RecordAllow(context.Background(), "s", "sanitize", "tools/call", map[string]interface{}{
		audit.DeclassifyCommitFailedKey:  []string{capability.FlowLabelPII},
		audit.DeclassifySpentApprovalKey: "apr-9",
	}, nil, false, nil, []string{capability.FlowLabelPII})
	rs.RecordDeny(context.Background(), "s", "sanitize", "tools/call", codeUpstreamError, "", map[string]interface{}{
		capability.FlowAuditDetailKey:    true,
		audit.DeclassifyNotAppliedKey:    []string{capability.FlowLabelPII},
		audit.DeclassifySpentApprovalKey: "apr-10",
	}, false)
	// The redaction exit's shape, whose withheld-result key is the newest of the four: a
	// boolean rather than a label list, so its JSON form is one the chain has not carried
	// before on this family of keys.
	rs.RecordDeny(context.Background(), "s", "sanitize", "tools/call", capability.ErrCodeEnforcementError, "", map[string]interface{}{
		capability.FlowAuditDetailKey:     true,
		audit.DeclassifyNotAppliedKey:     []string{capability.FlowLabelPII},
		audit.DeclassifyResultWithheldKey: true,
		audit.DeclassifySpentApprovalKey:  "apr-11",
	}, false)
	require.NoError(t, sink.Close())

	data, err := os.ReadFile(dir + "/audit.jsonl")
	require.NoError(t, err)
	for _, want := range []string{
		`"` + audit.DeclassifyCommitFailedKey + `":["pii"]`,
		`"` + audit.DeclassifySpentApprovalKey + `":"apr-9"`,
		`"` + audit.DeclassifyNotAppliedKey + `":["pii"]`,
		`"` + audit.DeclassifySpentApprovalKey + `":"apr-10"`,
		`"` + audit.DeclassifyResultWithheldKey + `":true`,
		`"` + audit.DeclassifySpentApprovalKey + `":"apr-11"`,
	} {
		assert.Contains(t, string(data), want)
	}

	keys, err := audit.LoadOrCreateKeys(dir + "/audit.key")
	require.NoError(t, err)
	var out strings.Builder
	res, err := audit.VerifyLog(bytes.NewReader(data), audit.NewVerifier(keys), "", time.Time{}, &out)
	require.NoError(t, err)
	assert.True(t, res.OK(), "the declassification detail keys must verify under the record HMAC:\n%s", out.String())
	assert.Equal(t, 3, res.Valid)
}

// TestEnforcedForwardCore_ConcurrentSinkStaysBlockedDuringTheForward is the regression test
// for the window the two-phase clear closes, driven through the REAL decision point and flow
// store rather than a spy — the bug was in when the store was written, so a double that only
// records the call could not have caught it.
//
// The scenario is the reported one. A session carries `pii`. A sanitizing call that clears
// `pii` under an approval is decided, and the transport releases the per-session decision lock
// immediately — deliberately, so the upstream forward is not held under it. While that call is
// still in flight (up to the full `--upstream-timeout`, or forever when it is `0`), a
// concurrent egress on the same session is decided.
//
// With the clear committed inside the decision, that egress read a clean label set and was
// ALLOWED and FORWARDED: the exfil the label existed to stop, with a tape that looked clean
// because from the sanitizing call's own perspective it was. The compensating undo could not
// help — it ran after the round trip, i.e. after this window.
func TestEnforcedForwardCore_ConcurrentSinkStaysBlockedDuringTheForward(t *testing.T) {
	ctx := context.Background()
	caps := []capability.Constraint{
		{Target: "tool:read_customer", Actions: []string{"call"},
			Directives: []capability.Directive{capability.LabelOutputDirective{Labels: []string{capability.FlowLabelPII}}}},
		{Target: "tool:publish", Actions: []string{"call"},
			Conditions: []capability.Condition{capability.FlowLabelCondition{Allow: []string{capability.FlowLabelPublic}}}},
	}
	engine := enforcement.New(
		enforcement.WithCallCounter(callcounter.NewInMemory()),
		enforcement.WithFlowLabelStore(flowlabelstore.NewInMemory()),
	)
	dp := pdp.NewManifestPDP(caps, engine, killswitch.NewInMemory())

	// Taint the session through the real source path.
	src := dp.Decide(ctx, "s", pdp.EnforceTarget{Type: capability.TargetTypeTool, Name: "read_customer"}, nil, "")
	require.Equal(t, capability.DecisionAllow, src.Decision)
	require.Equal(t, capability.DecisionDeny,
		dp.Decide(ctx, "s", pdp.EnforceTarget{Type: capability.TargetTypeTool, Name: "publish"}, nil, "").Decision,
		"precondition: the egress is blocked while the session carries pii")

	// The sanitizing call: decided (its clear authorized), then blocked in the upstream.
	inFlight, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	fp := forwardParams{rec: &fwdRecorder{}, sessionID: "s",
		callUpstream: func(_ context.Context, msg mcp.RPCMsg) (mcp.RPCMsg, error) {
			close(inFlight)
			<-release
			return mcp.RPCMsg{ID: msg.ID, Result: json.RawMessage(`{"ok":true}`)}, nil
		}}
	go func() {
		defer close(done)
		enforcedForwardCore(ctx, fp, dp, mcp.RPCMsg{ID: mcp.RawJSON(`1`)},
			declassifiedAllow(), "tools/call", "sanitize", "sanitize", "tool", false, upstreamErrorDetail)
	}()

	<-inFlight
	mid := dp.Decide(ctx, "s", pdp.EnforceTarget{Type: capability.TargetTypeTool, Name: "publish"}, nil, "")
	assert.Equal(t, capability.DecisionDeny, mid.Decision,
		"an egress decided while the sanitizing call is still in flight must NOT see the label cleared")
	if mid.Denial != nil {
		assert.Equal(t, capability.ConditionTypeFlowLabel, mid.Denial.ConditionType)
	}

	close(release)
	<-done

	// And once the sanitizing call has actually completed, the clear is in force.
	assert.Equal(t, capability.DecisionAllow,
		dp.Decide(ctx, "s", pdp.EnforceTarget{Type: capability.TargetTypeTool, Name: "publish"}, nil, "").Decision,
		"the clear takes effect once the call it sanitizes has run")
}

// TestEnforcedForwardCore_ConcurrentSourceKeepsItsTaintAcrossTheCommit is the mirror of the
// test above, and the case a deferred clear gets wrong if it re-reads the anchor at commit
// time. Deferring the removal closes the SINK race; re-deriving what to remove a round trip
// later opens the SOURCE one.
//
// Here the sanitizing call is decided against a clean session — so it has nothing to clear —
// and a real source read taints the session while that call is in flight. If the commit
// intersected against the anchor as it stands when it lands, it would remove the taint that
// read just asserted: data the sanitizing call never saw, laundered by an approval granted
// before the read existed. The egress after must stay blocked.
func TestEnforcedForwardCore_ConcurrentSourceKeepsItsTaintAcrossTheCommit(t *testing.T) {
	ctx := context.Background()
	caps := []capability.Constraint{
		{Target: "tool:read_customer", Actions: []string{"call"},
			Directives: []capability.Directive{capability.LabelOutputDirective{Labels: []string{capability.FlowLabelPII}}}},
		{Target: "tool:publish", Actions: []string{"call"},
			Conditions: []capability.Condition{capability.FlowLabelCondition{Allow: []string{capability.FlowLabelPublic}}}},
	}
	engine := enforcement.New(
		enforcement.WithCallCounter(callcounter.NewInMemory()),
		enforcement.WithFlowLabelStore(flowlabelstore.NewInMemory()),
	)
	// The declassifying constraint is part of the SAME policy, so the decision below is a
	// real one: what it resolves as pending is the engine's own intersection, not a literal
	// this test chose. A hand-built decision would pass here whatever the engine did.
	caps = append(caps, capability.Constraint{
		Target: "tool:sanitize", Actions: []string{"call"},
		Directives: []capability.Directive{capability.DeclassifyDirective{Labels: []string{capability.FlowLabelPII}}},
	})
	dp := pdp.NewManifestPDP(caps, engine, killswitch.NewInMemory())

	// Decided against a CLEAN session, under a covering approval, so the approved clear
	// resolves to nothing.
	approved := pdp.WithJWTClaims(ctx, &pdp.JWTClaims{Declassify: []capability.DeclassifyApproval{{
		Labels: []string{capability.FlowLabelPII}, Target: "tool:sanitize", Approver: "alice@example.com", ID: "apr-9",
	}}})
	decided := dp.Decide(approved, "s", pdp.EnforceTarget{Type: capability.TargetTypeTool, Name: "sanitize"}, nil, "")
	require.Equal(t, capability.DecisionAllow, decided.Decision)
	require.False(t, decided.Declassification.PendingClear(), "the anchor was clean, so the approved clear has nothing pending")

	inFlight, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	fp := forwardParams{rec: &fwdRecorder{}, sessionID: "s",
		callUpstream: func(_ context.Context, msg mcp.RPCMsg) (mcp.RPCMsg, error) {
			close(inFlight)
			<-release
			return mcp.RPCMsg{ID: msg.ID, Result: json.RawMessage(`{"ok":true}`)}, nil
		}}
	go func() {
		defer close(done)
		enforcedForwardCore(ctx, fp, dp, mcp.RPCMsg{ID: mcp.RawJSON(`1`)},
			decided, "tools/call", "sanitize", "sanitize", "tool", false, upstreamErrorDetail)
	}()

	<-inFlight
	// A real tainting read lands while the sanitizing call is still in flight.
	require.Equal(t, capability.DecisionAllow,
		dp.Decide(ctx, "s", pdp.EnforceTarget{Type: capability.TargetTypeTool, Name: "read_customer"}, nil, "").Decision)

	close(release)
	<-done

	assert.Equal(t, capability.DecisionDeny,
		dp.Decide(ctx, "s", pdp.EnforceTarget{Type: capability.TargetTypeTool, Name: "publish"}, nil, "").Decision,
		"the sanitizing call was decided before that read existed and must not have cleared its taint")
}

// TestEnforcedForwardCore_UnsuccessfulCallDoesNotCommit is the success gate. "The call ran"
// is not "the call did what the approval was granted for": a sanitize whose upstream answers
// with a JSON-RPC error, or with a tool result flagged isError, is delivered to the host and
// is NOT a transport failure — so it reaches the commit with the transform never performed.
// Dropping the taint there would forward the next egress on the strength of a step that
// failed, and the audit record would assert a declassification that did not happen.
func TestEnforcedForwardCore_UnsuccessfulCallDoesNotCommit(t *testing.T) {
	for name, reply := range map[string]mcp.RPCMsg{
		// Protocol-level failure: the upstream refused the call outright.
		"json-rpc error": {Error: &mcp.RPCError{Code: -32603, Message: "sanitizer backend unavailable"}},
		// Tool-level failure: MCP conveys this in the RESULT, so the error member is nil and
		// nothing above the commit can see it.
		"tool isError": {Result: json.RawMessage(`{"content":[{"type":"text","text":"scrub failed"}],"isError":true}`)},
		// Ambiguity reads as failure rather than as success.
		"undecodable result": {Result: json.RawMessage(`{"isError":`)},
	} {
		t.Run(name, func(t *testing.T) {
			rec, spy := &fwdRecorder{}, &commitSpy{}
			fp := forwardParams{rec: rec, sessionID: "s",
				callUpstream: func(_ context.Context, msg mcp.RPCMsg) (mcp.RPCMsg, error) {
					out := reply
					out.ID = msg.ID
					return out, nil
				}}

			enforcedForwardCore(context.Background(), fp, spy, mcp.RPCMsg{ID: mcp.RawJSON(`1`)},
				declassifiedAllow(), "tools/call", "sanitize", "sanitize", "tool", false, upstreamErrorDetail)

			assert.Zero(t, spy.calls, "a sanitizing call that FAILED must not drop the taint")
			require.Len(t, rec.records, 1)
			got := rec.records[0]
			assert.Empty(t, got.labelsCleared, "and the tape must not claim a declassification")
			assert.Empty(t, got.approver)
			assert.Equal(t, []string{capability.FlowLabelPII}, got.details[audit.DeclassifyNotAppliedKey],
				"it is recorded exactly as a refused call is: the approved clear did not take effect")
			assert.Equal(t, "apr-9", got.details[audit.DeclassifySpentApprovalKey],
				"and the grant it spent is still named")
		})
	}
}

// TestEnforcedForwardCore_SuccessfulResultCommits is the positive half of the gate: an
// ordinary result, and one that carries isError explicitly false, both commit. Without this
// the gate above could be satisfied by never committing at all.
func TestEnforcedForwardCore_SuccessfulResultCommits(t *testing.T) {
	for name, body := range map[string]string{
		"plain result":   `{"content":[{"type":"text","text":"clean"}]}`,
		"isError false":  `{"content":[],"isError":false}`,
		"isError absent": `{"ok":true}`,
	} {
		t.Run(name, func(t *testing.T) {
			rec, spy := &fwdRecorder{}, &commitSpy{}
			fp := forwardParams{rec: rec, sessionID: "s",
				callUpstream: func(_ context.Context, msg mcp.RPCMsg) (mcp.RPCMsg, error) {
					return mcp.RPCMsg{ID: msg.ID, Result: json.RawMessage(body)}, nil
				}}

			enforcedForwardCore(context.Background(), fp, spy, mcp.RPCMsg{ID: mcp.RawJSON(`1`)},
				declassifiedAllow(), "tools/call", "sanitize", "sanitize", "tool", false, upstreamErrorDetail)

			require.Equal(t, 1, spy.calls)
			require.Len(t, rec.records, 1)
			assert.Equal(t, []string{capability.FlowLabelPII}, rec.records[0].labelsCleared)
		})
	}
}

// TestEnforcedForwardCore_SpentGrantIsNamedWithoutPendingLabels covers the refusal shape the
// engine produces when its own declassify-leg commit faults AFTER burning a single-use grant:
// the clear was never resolved, so the decision's handle authorizes nothing, but the grant
// is spent for good. Keying the refusal detail on the labels alone dropped the id on exactly
// that path — the one record it would ever have appeared on.
func TestEnforcedForwardCore_SpentGrantIsNamedWithoutPendingLabels(t *testing.T) {
	rec, spy := &fwdRecorder{}, &commitSpy{}
	dec := capability.EnforceResponse{
		Decision: capability.DecisionDeny,
		// The engine's own declassify-leg commit fault: no clear was resolved, so the handle
		// carries no labels and exists only to name the grant that was burned.
		Declassification: capability.NewDeclassification(nil, "", "apr-9", true),
		Denial: &capability.DenialInfo{
			Code: capability.ErrCodeConditionFailed, ConditionType: capability.DirectiveTypeDeclassify,
			HardDeny: true, Details: map[string]interface{}{capability.FlowAuditDetailKey: true, "phase": "record"},
		},
	}
	fp := forwardParams{rec: rec, sessionID: "s", callUpstream: cleanUpstream()}

	enforcedForwardCore(context.Background(), fp, spy, mcp.RPCMsg{ID: mcp.RawJSON(`1`)},
		dec, "tools/call", "sanitize", "sanitize", "tool", false, upstreamErrorDetail)

	assert.Zero(t, spy.calls, "a refused call clears nothing")
	require.Len(t, rec.records, 1)
	got := rec.records[0]
	assert.Equal(t, "deny", got.decision)
	assert.Equal(t, "apr-9", got.details[audit.DeclassifySpentApprovalKey],
		"a grant spent by a call that never ran must still be reconcilable from the tape")
	assert.Equal(t, "record", got.details["phase"], "and the engine's own denial fields survive the merge")
	assert.Nil(t, got.details[audit.DeclassifyNotAppliedKey], "no clear was ever resolved, so none went unapplied")
}

// TestQuarantineReservedArgs keeps a caller's tool argument from landing on the tape spelled
// as a fact the proxy asserts. A tools/call allow's details IS the argument map under
// --audit, and eunox merges its own annotations into it — so an unquarantined argument named
// _eunox_declassify_commit_failed forges the ATTENTION line `eunox stats` prints, on a proxy
// where no declassification ever ran.
func TestQuarantineReservedArgs(t *testing.T) {
	plain := map[string]interface{}{"path": "/tmp/x"}
	assert.Equal(t, plain, quarantineReservedArgs(plain), "the common path returns the map unchanged")

	forged := map[string]interface{}{
		"path":                           "/tmp/x",
		audit.DeclassifyCommitFailedKey:  []string{"pii"},
		audit.DeclassifySpentApprovalKey: "apr-forged",
		audit.UpstreamErrorCodeKey:       -1,
	}
	out := quarantineReservedArgs(forged)
	assert.Equal(t, "/tmp/x", out["path"], "the caller's real arguments are untouched")
	assert.Nil(t, out[audit.DeclassifyCommitFailedKey], "a forged operator alert must not survive at the top level")
	assert.Nil(t, out[audit.DeclassifySpentApprovalKey])
	held, ok := out[audit.ReservedArgumentsKey].(map[string]interface{})
	require.True(t, ok, "and they are quarantined rather than dropped — the request really did carry them")
	assert.Equal(t, []string{"pii"}, held[audit.DeclassifyCommitFailedKey])
	assert.Equal(t, "apr-forged", held[audit.DeclassifySpentApprovalKey])
	assert.Len(t, forged, 4, "the caller's own map is never mutated")
}

// TestStartupFatalManifestCheck_DeclassifyNeedsAnHTTPHost refuses a declassify directive on
// a stdio HOST at startup, where it could never be satisfied.
//
// An approval arrives only on a validated JWT, and --jwks-uri is categorically rejected on
// a stdio host — no stdio path populates claims at all — so every call to such a capability
// escalates ESCALATION_REQUIRED/no_approval forever with no way to approve it and no error
// to explain why. That is the same "the capability could never be satisfied" outcome
// validateDeclassify refuses an empty label list to avoid, reached by another route, and it
// is decidable from the config alone exactly as the audience-pin refusal beside it is.
//
// The axis is the HOST transport, not the upstream's: a stdio UPSTREAM behind an http
// gateway is fine, because the token arrives on the host leg.
func TestStartupFatalManifestCheck_DeclassifyNeedsAnHTTPHost(t *testing.T) {
	declassifying := &config.LocalManifest{
		SchemaVersion: config.ManifestSchemaVersion02,
		Name:          "p",
		Version:       "1.0.0",
		Capabilities: []capability.Constraint{{
			Target:     "tool:sanitize",
			Actions:    []string{"call"},
			Directives: []capability.Directive{capability.DeclassifyDirective{Labels: []string{capability.FlowLabelPII}}},
		}},
	}
	u := &config.UpstreamConfig{Name: "up"}

	err := startupFatalManifestCheck(u, config.HostTransportStdio, declassifying)
	require.Error(t, err, "a stdio host cannot present an approval, so the directive must be refused at startup")
	assert.Contains(t, err.Error(), "declassify")

	assert.NoError(t, startupFatalManifestCheck(u, config.HostTransportHTTP, declassifying),
		"an http host can present an approval, so the same manifest boots")

	// A manifest without the directive is unaffected on either host.
	plain := &config.LocalManifest{
		SchemaVersion: config.ManifestSchemaVersion02, Name: "p", Version: "1.0.0",
		Capabilities: []capability.Constraint{{Target: "tool:read", Actions: []string{"call"}}},
	}
	assert.NoError(t, startupFatalManifestCheck(u, config.HostTransportStdio, plain))
}

// TestEnforcedForwardCore_NoOpClearOnASuccessfulCallNamesTheSpentGrant covers the shape the
// commit's early return used to record NOTHING for: a single-use grant burned by a decision
// whose clear resolved to nothing, on a call that then SUCCEEDED.
//
// The burn happens whether or not a label moves (burning only on a clear that moved one would
// make the grant replayable by ordering), and the signed labels_cleared/approver/approval_id
// triple rides only a clear that changed something — so this record is the only one that will
// ever name the grant. Returning a bare nil detail here left it named nowhere on the success
// path while every refusal path named it, which is the reconciliation gap backwards.
func TestEnforcedForwardCore_NoOpClearOnASuccessfulCallNamesTheSpentGrant(t *testing.T) {
	rec, spy := &fwdRecorder{}, &commitSpy{}
	dec := capability.EnforceResponse{
		Decision: capability.DecisionAllow,
		// The anchor was not carrying the approved labels, so the decision authorized no
		// clear — but it burned the grant to get here.
		Declassification: capability.NewDeclassification(nil, "alice@example.com", "apr-9", true),
	}
	fp := forwardParams{rec: rec, sessionID: "s", callUpstream: cleanUpstream()}

	enforcedForwardCore(context.Background(), fp, spy, mcp.RPCMsg{ID: mcp.RawJSON(`1`)},
		dec, "tools/call", "sanitize", "sanitize", "tool", false, upstreamErrorDetail)

	assert.Zero(t, spy.calls, "nothing was pending, so no store round trip")
	require.Len(t, rec.records, 1)
	got := rec.records[0]
	assert.Equal(t, "allow", got.decision)
	assert.Empty(t, got.labelsCleared, "no label moved, so the tape must not claim a declassification")
	assert.Equal(t, "apr-9", got.details[audit.DeclassifySpentApprovalKey],
		"a grant spent on a no-op clear must still be reconcilable from the tape")
	assert.Equal(t, true, got.details[capability.FlowAuditDetailKey])
	assert.Nil(t, got.details[audit.DeclassifyNotAppliedKey], "nothing was pending, so nothing went unapplied")
}

// TestDeclassifyDetail_SilentWhenAnApprovedClearHasNothingToReport is the mirror: an approved
// declassification under a STANDING grant whose labels the anchor was not carrying has neither
// fact to record — no pending clear, no burned grant — so it must annotate nothing at all.
//
// Testing the handle's nil instead of its facts put a bare flow discriminator on the tape for
// such a call, and let the redaction exit stamp _eunox_declassify_result_withheld — an
// executed-and-withheld claim for a declassification that authorized nothing.
func TestDeclassifyDetail_SilentWhenAnApprovedClearHasNothingToReport(t *testing.T) {
	dec := capability.EnforceResponse{
		Decision:         capability.DecisionAllow,
		Declassification: capability.NewDeclassification(nil, "alice@example.com", "apr-9", false),
	}
	assert.Nil(t, declassifyRefusalDetail(dec),
		"no pending clear and no spent grant is not a declassification event")
	assert.Nil(t, declassifyRedactionDetail(dec, successfulReply()),
		"and the withheld-result key must not ride a record with no declassification facts")

	// The same decision under a single-use grant DOES have a fact: the burn.
	spent := dec
	spent.Declassification = capability.NewDeclassification(nil, "alice@example.com", "apr-9", true)
	assert.Equal(t, "apr-9", declassifyRefusalDetail(spent)[audit.DeclassifySpentApprovalKey])
}

// samplingDecision returns a serverRequestParams wired to a PDP that answers DecideSampling
// with dec, plus the recorder and the upstream reply captured.
type samplingPDP struct {
	pdp.PolicyDecisionPoint
	dec capability.EnforceResponse
}

func (s samplingPDP) DecideSampling(context.Context, string, string) capability.EnforceResponse {
	return s.dec
}

// TestForwardServerRequest_RefusesADeclassifyingSamplingDecision pins the fail-closed arm the
// server-initiated leg takes instead of committing.
//
// This leg learns only that the host RECEIVED the request — an SSE buffer accepted it, or it
// was written to stdout — never that the sanitizing action ran, and a server-initiated request
// is answered later out of band. Committing on delivery would drop taint for work that has not
// happened. A load rule keeps the case unreachable today (declassify is refused on a system:
// target); this is what makes relaxing that rule loud rather than silently wrong.
func TestForwardServerRequest_RefusesADeclassifyingSamplingDecision(t *testing.T) {
	rec := &fwdRecorder{}
	var forwarded bool
	var toUpstream []mcp.RPCMsg
	dec := capability.EnforceResponse{
		Decision:         capability.DecisionAllow,
		Declassification: capability.NewDeclassification([]string{capability.FlowLabelPII}, "alice@example.com", "apr-9", true),
	}
	fp := serverRequestParams{
		rec:           rec,
		sessionID:     "s",
		forward:       func(mcp.RPCMsg) bool { forwarded = true; return true },
		writeUpstream: func(m mcp.RPCMsg) { toUpstream = append(toUpstream, m) },
		pdp:           samplingPDP{dec: dec},
	}

	forwardServerRequest(context.Background(), mcp.RPCMsg{ID: mcp.RawJSON(`1`), Method: capability.MethodSamplingCreateMessage}, fp)

	assert.False(t, forwarded, "a declassification this leg cannot commit must not be forwarded")
	require.Len(t, toUpstream, 1, "the upstream initiator is answered")
	require.NotNil(t, toUpstream[0].Error)
	require.Len(t, rec.records, 1)
	assert.Equal(t, "deny", rec.records[0].decision)
	assert.Equal(t, "apr-9", rec.records[0].details[audit.DeclassifySpentApprovalKey],
		"the grant the decision burned still reaches the tape")
	assert.Equal(t, []string{capability.FlowLabelPII}, rec.records[0].details[audit.DeclassifyNotAppliedKey])
}

// TestForwardServerRequest_RefusesWhenTheTurnIsUnavailable is the other fail-closed arm: a
// decision that cannot be serialized against the anchor's host-path decisions is refused
// rather than taken on possibly-mid-write flow state. Waiting instead would wedge the
// session's upstream reader; deciding anyway is the fail-open the turn exists to close.
func TestForwardServerRequest_RefusesWhenTheTurnIsUnavailable(t *testing.T) {
	rec := &fwdRecorder{}
	var forwarded bool
	var toUpstream []mcp.RPCMsg
	fp := serverRequestParams{
		rec:           rec,
		sessionID:     "s",
		forward:       func(mcp.RPCMsg) bool { forwarded = true; return true },
		writeUpstream: func(m mcp.RPCMsg) { toUpstream = append(toUpstream, m) },
		decideLock:    func() (func(), bool) { return nil, false },
		pdp:           samplingPDP{dec: capability.EnforceResponse{Decision: capability.DecisionAllow}},
	}

	forwardServerRequest(context.Background(), mcp.RPCMsg{ID: mcp.RawJSON(`1`), Method: capability.MethodSamplingCreateMessage}, fp)

	assert.False(t, forwarded, "an unserialized flow decision must not be forwarded")
	require.Len(t, toUpstream, 1)
	require.Len(t, rec.records, 1)
	assert.Equal(t, "deny", rec.records[0].decision)
	assert.Equal(t, capability.ErrCodeConditionFailed, rec.records[0].code)
	assert.Equal(t, false, rec.records[0].auditOnly, "the refusal is hard: --audit must not downgrade it")
}

// TestEnforcedForwardCore_DoubleCommitIsNotReportedAsAFailedClear covers the one error the
// commit path must not fold into its store-fault arm. A second commit of one decision returns
// ErrDeclassificationCommitted — the handle authorizes exactly one clear — and the facts are
// the OPPOSITE of a store fault's: the first commit applied the clear, so the labels are gone,
// the session is not over-blocking, and there is nothing to re-approve.
//
// Reported as a commit failure it stamps the key `eunox stats` raises an ATTENTION line on and
// tells an operator to reissue an approval for work that already landed — an alert that is
// wrong in the unsafe direction, on a tamper-evident tape. It is unreachable through this
// transport's call graph today; the branch exists to answer "what if it is called twice", so
// it has to answer correctly rather than plausibly.
func TestEnforcedForwardCore_DoubleCommitIsNotReportedAsAFailedClear(t *testing.T) {
	rec := &fwdRecorder{}
	spy := &commitSpy{failErr: capability.ErrDeclassificationCommitted}
	fp := forwardParams{rec: rec, sessionID: "s", callUpstream: cleanUpstream()}

	resp := enforcedForwardCore(context.Background(), fp, spy, mcp.RPCMsg{ID: mcp.RawJSON(`1`)},
		declassifiedAllow(), "tools/call", "sanitize", "sanitize", "tool", false, upstreamErrorDetail)

	require.Nil(t, resp.Error, "a wiring fault after the call ran does not withhold its response")
	require.Len(t, rec.records, 1)
	got := rec.records[0]
	assert.Equal(t, "allow", got.decision)
	assert.Nil(t, got.details[audit.DeclassifyCommitFailedKey],
		"the clear DID land on the first commit; claiming otherwise pages an operator to re-approve work already done")
	assert.Empty(t, got.labelsCleared,
		"and this call changed nothing, so it must not re-claim the labels the first commit removed")
	assert.Equal(t, "apr-9", got.details[audit.DeclassifySpentApprovalKey],
		"the spent grant is still named, exactly as a no-op clear names it")

	// And under a STANDING grant there is no spent id, so there is no declassification
	// evidence at all — the record must carry nothing rather than a bare flow discriminator,
	// which is what the shared producer guarantees and a hand-built detail map did not.
	standing := declassifiedAllow()
	standing.Declassification = capability.NewDeclassification(
		[]string{capability.FlowLabelPII}, "alice@example.com", "apr-9", false)
	rec2 := &fwdRecorder{}
	enforcedForwardCore(context.Background(),
		forwardParams{rec: rec2, sessionID: "s", callUpstream: cleanUpstream()}, spy,
		mcp.RPCMsg{ID: mcp.RawJSON(`1`)}, standing, "tools/call", "sanitize", "sanitize", "tool", false, upstreamErrorDetail)
	require.Len(t, rec2.records, 1)
	for key, v := range rec2.records[0].details {
		assert.NotEqual(t, capability.FlowAuditDetailKey, key,
			"a call with no declassification evidence must not be marked as an information-flow event (got %v)", v)
	}
}

// TestStrictAuditDenial_BuildsTheDeclassifyDetailOnlyWhenItTrips is the eager-evaluation guard.
// The gate returns before reading the decision whenever the audit trail is healthy — every call
// in every healthy deployment — so building the detail map at the CALL SITE allocated a map plus
// a copy of the handle's label slice and handed both straight to the GC, unused, on every
// declassifying call. The sampling leg was already taking the decision itself; this pins that
// the host leg does too, and that the facts still land when the gate actually trips.
func TestStrictAuditDenial_BuildsTheDeclassifyDetailOnlyWhenItTrips(t *testing.T) {
	dec := declassifiedAllow()
	msg := mcp.RPCMsg{ID: mcp.RawJSON(`1`)}

	// Healthy trail: the gate does not fire, reads nothing off the decision, and allocates
	// nothing for it.
	healthy := forwardParams{rec: &fwdRecorder{}, sessionID: "s",
		strictAuditState: strictAuditState{requireAuditStrict: true}}
	_, blocked := healthy.strictAuditDenial(context.Background(), msg, "sanitize", "tools/call", "sanitize", dec)
	require.False(t, blocked)
	allocs := testing.AllocsPerRun(50, func() {
		healthy.strictAuditDenial(context.Background(), msg, "sanitize", "tools/call", "sanitize", dec)
	})
	assert.Zero(t, allocs, "the common path must not build a details map for a gate that never reads it")

	// Degraded trail: the gate fires and the declassification facts reach the record.
	rec := &fwdRecorder{degraded: true, reason: "audit trail degraded"}
	tripped := forwardParams{rec: rec, sessionID: "s",
		strictAuditState: strictAuditState{requireAuditStrict: true}}
	denied, blocked := tripped.strictAuditDenial(context.Background(), msg, "sanitize", "tools/call", "sanitize", dec)
	require.True(t, blocked)
	require.NotNil(t, denied.Error)
	require.Len(t, rec.records, 1)
	assert.Equal(t, []string{capability.FlowLabelPII}, rec.records[0].details[audit.DeclassifyNotAppliedKey])
	assert.Equal(t, "apr-9", rec.records[0].details[audit.DeclassifySpentApprovalKey])
}
