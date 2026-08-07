// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
)

// auditRecorder is the subset of the audit sink the enforced-forward path needs. Both
// *audit.Sink (stdio) and *routeSink (HTTP/gateway) satisfy it, letting the shared forward
// core record without knowing its transport.
//
// A missing sink must yield a genuine nil INTERFACE, never a non-nil interface wrapping a nil
// pointer — the typed-nil trap that would turn `rec != nil` into a lie. asRecorder and
// StdioProxy.rec both uphold this; never assign a concrete sink pointer directly.
type auditRecorder interface {
	RecordAllow(ctx context.Context, sessionID, identifier, method string, details map[string]interface{}, obligs []string, auditOnly bool, labelsOut, carriedLabels []string)
	// RecordDeclassifiedAllow is the allow recorder for a call that ALSO cleared flow labels
	// under a human approval. Separate from RecordAllow so the cleared labels and the
	// approving human can only ever be stamped together.
	RecordDeclassifiedAllow(ctx context.Context, sessionID, identifier, method string, details map[string]interface{}, obligs []string, auditOnly bool, labelsOut, carriedLabels, labelsCleared []string, approver, approvalID string)
	RecordDeny(ctx context.Context, sessionID, identifier, method, denialCode, condType string, details map[string]interface{}, observe bool)
	// AuditDegraded reports whether the audit trail has lost coverage. reason is prose for the
	// host-facing error/stderr warning; detail is discrete counts for the structured record.
	// Retrospective: the boundary call whose own record is the first lost is still forwarded;
	// the next call is the first denied.
	AuditDegraded() (degraded bool, reason string, detail map[string]interface{})
}

// asRecorder converts a possibly-nil concrete sink pointer into the auditRecorder interface,
// returning a genuine nil interface for a nil pointer rather than one wrapping a nil pointer
// (the typed-nil trap), so `rec != nil` stays a true "no sink configured" test everywhere.
func asRecorder[T interface {
	auditRecorder
	comparable
}](s T) auditRecorder {
	var zero T
	if s == zero {
		return nil
	}
	return s
}

// killSubject names WHOSE session a kill-switch record describes and whether this proxy can
// VOUCH for that name. Only two things can produce one:
//
//   - verifiedSession: an id this proxy actually established. Safe to stamp as fact into the
//     structured, signed session_id field.
//   - claimedSession: the raw, client-supplied Mcp-Session-Id header of an UNRESOLVED
//     session. Not safe — a caller holding any unrelated valid credential could put an
//     arbitrary (including a victim's) id in the header. session_id stays EMPTY; the value
//     survives only as details.claimed_session_id, clearly marked unverified.
//
// A type rather than a `sessionID string` param because picking wrong fails SILENTLY — a
// well-formed signed record asserting a session this proxy never established. The zero value
// is the safe one, so a hand-written composite literal degrades to recording less, never
// forging more. An AST test (guardedStructs) fails the build if a composite literal of this
// type appears outside the file holding its constructors.
//
// Scope: covers the ~10 kill-record call sites only; the general RecordAllow/RecordDeny
// surface keeps plain-string sessionIDs, where "verified" stays a control-flow fact rather
// than a type guarantee — safe because no dispatchParams constructor can even receive a raw
// header.
type killSubject struct {
	// verified is the registry-resolved session id, stamped into session_id. Empty for a
	// claimed subject.
	verified string
	// claimed is the (not yet sanitized) Mcp-Session-Id header value for a claimed
	// subject, read once at construction; empty for a verified subject AND for a claimed
	// one whose header was absent — auditDetails treats both identically (no detail
	// added), so the two cases need no separate tag. Held as the already-extracted string
	// rather than the *http.Request: every claimedSession(r) call site already reads this
	// exact header into its own local sessionID before constructing the subject, so
	// storing the request would only defer a second, redundant read to record time.
	claimed string
}

// verifiedSession names a session THIS proxy established, safe to stamp into the signed
// session_id field. Pass an id from session state, never one read back off the request.
func verifiedSession(id string) killSubject { return killSubject{verified: id} }

// claimedSession names the session id a client claimed in r's Mcp-Session-Id header at a
// call site that has NOT resolved it against the registry. Its id never reaches session_id;
// see killSubject. Takes *http.Request (read immediately, not retained), not a bare string,
// so a call site cannot spell "this header is verified" by handing it something that merely
// looks like a session id.
func claimedSession(r *http.Request) killSubject {
	return killSubject{claimed: r.Header.Get(SessionHeader)}
}

// auditSessionID is the value for the record's structured, signed session_id field: the
// verified id, or empty for a claimed subject.
func (k killSubject) auditSessionID() string { return k.verified }

// auditDetails folds a claimed subject's unverified id into base as details.claimed_session_id
// (bounded and sanitized by addClaimedSessionIDValue); a no-op for a verified subject or an
// empty header, through the same call so no branch is needed to distinguish them.
func (k killSubject) auditDetails(base map[string]interface{}) map[string]interface{} {
	return addClaimedSessionIDValue(base, k.claimed)
}

// recordKillDenial records a kill-switch denial and builds the host-facing denial response.
// Non-enforced paths call CheckKill themselves then funnel the deny here so the record shape
// and response envelope are defined once. rec may be nil (skipped then). A kill addresses no
// sub-target, so one method name serves as identifier/method/target alike. subj decides
// whether the session id is recorded as fact or an unverified claim — see killSubject.
func recordKillDenial(ctx context.Context, rec auditRecorder, deny *capability.EnforceResponse, id *json.RawMessage, subj killSubject, method string) mcp.RPCMsg {
	denial := normalizeDenial(deny.Denial)
	if rec != nil {
		rec.RecordDeny(ctx, subj.auditSessionID(), method, method, denial.Code, denial.ConditionType, subj.auditDetails(nil), false)
	}
	return denialResult(id, denial.Code, denial.ConditionType, method, "")
}

// killDropLeg identifies the transport leg a recordKillDrop call site drops a message on,
// stamped into the audit detail so an operator can distinguish drop sites during an incident.
// A typed enum (not a bare string at each of the 8 call sites) makes a typo'd leg a compile
// error rather than a silently corrupted "transport" detail. Covers the recordKillDrop family
// only; two other producers of the "transport" detail stay bare strings.
type killDropLeg string

const (
	legHTTPNotification          killDropLeg = "http-notification"
	legHTTPServerResponse        killDropLeg = "http-server-response"
	legHTTPUpstreamNotification  killDropLeg = "http-upstream-notification"
	legSSEGet                    killDropLeg = "sse-get"
	legStdioNotification         killDropLeg = "stdio-notification"
	legStdioServerResponse       killDropLeg = "stdio-server-response"
	legStdioUpstreamNotification killDropLeg = "stdio-upstream-notification"
)

// recordKillDrop records a kill-switch denial for a message that is DROPPED rather than
// answered with a host-facing error — a notification or a server-initiated message with no
// response envelope to deny into. Mirrors recordKillDenial's record shape and stamps the
// originating transport leg into the audit detail, but returns nothing to send — the caller
// owns the drop control flow. rec may be nil (skipped). Folds ~8 hand-mirrored sites so the
// record shape can't drift apart.
func recordKillDrop(ctx context.Context, rec auditRecorder, deny *capability.EnforceResponse, subj killSubject, identifier, method string, transportLeg killDropLeg) {
	if rec == nil {
		return
	}
	denial := normalizeDenial(deny.Denial)
	details := subj.auditDetails(map[string]interface{}{"transport": string(transportLeg)})
	rec.RecordDeny(ctx, subj.auditSessionID(), identifier, method, denial.Code, denial.ConditionType, details, false)
}

// recordResourceExhausted records a host request refused because a concurrency pool was
// saturated, so a DoS-probe flood against either transport leaves a trace on the tape rather
// than only a JSON-RPC server-busy reply. Shared by all three saturation sites so they can't
// record divergent shapes. The identifier is left EMPTY (no target parsed yet) so
// deriveTargetFields can't synthesize a phantom target. rec may be nil (skipped).
//
// gate is the saturated pool's own admission control (required), collapsing an episode of
// saturation to one record carrying a suppressed-refusal count — see saturationGate for why a
// per-refusal record is a lever on --require-audit=strict.
func recordResourceExhausted(ctx context.Context, rec auditRecorder, gate *saturationGate, sessionID, method string) {
	if rec == nil {
		return
	}
	ok, suppressed := gate.admit()
	if !ok {
		return
	}
	var details map[string]interface{}
	if suppressed > 0 {
		details = map[string]interface{}{
			detailSuppressedRefusalCount: suppressed,
			detailSuppressedRefusalScope: suppressedScopeSession,
		}
	}
	rec.RecordDeny(ctx, sessionID, "", method, codeResourceExhausted, "", details, false)
}

// suppressedScopeSession qualifies a saturation gate's rollup (see recordResourceExhausted):
// the count spans only the one session (indeed one pool within it) whose refusals fed the
// gate. Written at this call site rather than carried on saturationGate — a per-scope field
// would be generality with a single caller.
const suppressedScopeSession = "session"

// recordDriftRefused writes the startup manifest-drift refusal record. Both transports refuse
// a session on this condition; folding the previously hand-mirrored sites here keeps the
// record shape from drifting apart between transports.
//
// The raw drift reason (naming the drifted tools) deliberately stays on stderr; the tape
// carries only the stable DRIFT_REFUSED category.
func recordDriftRefused(ctx context.Context, rec auditRecorder, sessionID string) {
	if rec == nil {
		return
	}
	rec.RecordDeny(ctx, sessionID, mcp.MethodInitialize, mcp.MethodInitialize, codeDriftRefused, "drift", nil, false)
}

// forwardParams bundles the per-transport bits the shared enforced-forward core
// needs (HTTP fills these from sess.route + the session; stdio from the proxy),
// keeping the policy/audit/forward logic in one place rather than hand-mirrored.
type forwardParams struct {
	rec            auditRecorder
	audit          bool
	sessionID      string
	upstreamTimeMs int
	callUpstream   func(context.Context, mcp.RPCMsg) (mcp.RPCMsg, error)
	// endDecision closes the decision critical section a serialize-relevant transport opened
	// around this enforced request, idempotent. Decide* handlers call it immediately after the
	// PDP decision so the forward runs OUTSIDE the turn; a declassifying call keeps it past the
	// decision, released HERE by the forward core the moment its commit lands.
	//
	// Lives on these params (not beside the dispatcher's pdp) because releasing at handler
	// return would hold the turn across the client-facing response write, which is bounded by
	// a client that may simply stop reading. nil for a non-serialized request. The transports
	// also defer the same release as a backstop for paths that return before deciding.
	endDecision func()
	strictAuditState
	// errOut is where this forward's diagnostic (SECURITY/AUDIT) lines are written. Nil (the
	// default, and what every construction that doesn't set it gets — including every test
	// literal) means os.Stderr, mirroring StdioProxyOptions.Stderr/HTTPGatewayOptions.Stderr:
	// a caller that wants to capture these lines (or avoid racing a concurrently-read
	// os.Stderr) configures the proxy's writer, which flows down to here, instead of
	// reassigning the process-global os.Stderr.
	errOut io.Writer
}

// errOutOrStderr returns fp.errOut when set, else os.Stderr — the one place every
// dispatch/forward diagnostic line resolves its destination, so a proxy's configured Stderr
// writer actually reaches them instead of being bypassed by a direct os.Stderr write.
func (fp forwardParams) errOutOrStderr() io.Writer {
	return resolvedErrOut(fp.errOut)
}

// resolvedErrOut returns w when set, else os.Stderr — the fallback forwardParams.errOutOrStderr
// and serverRequestParams.errOutOrStderr share, since the two params structs don't embed one
// another but must resolve a nil errOut identically.
func resolvedErrOut(w io.Writer) io.Writer {
	if w == nil {
		return os.Stderr
	}
	return w
}

// declassifyCommitter is the one method the forward core needs from the PDP: apply the flow
// label clear an approved declassification authorized, for a call decided here that has now
// actually run. Every PolicyDecisionPoint satisfies it, so the core stays ignorant of which
// one it holds.
//
// A narrow interface (not a pdp.PolicyDecisionPoint field) because that is all this path may
// do — the decision is already made, and nothing below it may re-decide. The decision's own
// handle is the parameter for the same reason: the authorized set is unexported, so this path
// can apply a clear but cannot widen one.
type declassifyCommitter interface {
	CommitDeclassified(ctx context.Context, sessionID string, decl *capability.Declassification) ([]string, error)
}

// declassifyCommitTimeout bounds the single flow-store write commitDeclassify makes after the
// upstream call returns.
//
// It sits on the host's response path AND under the anchor-keyed decision turn a
// declassifying call holds until commit — so an exhausted bound stalls every decision on the
// session for its full length. Shorter than a background-write bound would be: long enough to
// ride out a hiccup, short enough that a wedged flow store degrades latency, not availability.
// Failing it is not a refusal — the label just stays and a later sink over-blocks.
const declassifyCommitTimeout = 2 * time.Second

// strictAuditState is the --require-audit=strict configuration shared by the host-facing
// forward path (forwardParams) and the server-initiated sampling path (serverRequestParams).
// Embedded in both so a future field is declared once instead of mirrored; fields are
// promoted, so call sites still read fp.requireAuditStrict / fp.strictAuditWarned unchanged.
type strictAuditState struct {
	// requireAuditStrict is the --require-audit=strict gate: once a prior record
	// has been lost, an otherwise-authorized forward is denied fail-closed
	// (AUDIT_UNAVAILABLE) so no further privileged call reaches the upstream
	// unaudited. Retrospective (see auditRecorder.AuditDegraded). Off by default.
	requireAuditStrict bool
	// strictAuditWarned makes the strict-gate stderr warning one-shot — the gate is sticky, so
	// it would otherwise log on every forward. nil disables the warning (tests).
	strictAuditWarned *atomic.Bool
}

// auditGateTripped reports whether --require-audit=strict should fail a forward closed.
// reason is prose for the host-facing error/stderr warning; detail is discrete counts for
// the structured deny record. Shared by the forward core, */list dispatch, and sampling.
func auditGateTripped(rec auditRecorder, strict bool) (tripped bool, reason string, detail map[string]interface{}) {
	if !strict || rec == nil {
		return false, "", nil
	}
	return rec.AuditDegraded()
}

// warnStrictAuditOnce emits the "strict mode is now denying forwards" diagnostic line once
// per process, on the first trip; later denials remain visible as AUDIT_UNAVAILABLE records.
func warnStrictAuditOnce(w io.Writer, warned *atomic.Bool, reason string) {
	if warned != nil && warned.CompareAndSwap(false, true) {
		_, _ = fmt.Fprintf(w,
			"[eunox] SECURITY: --require-audit=strict is now denying forwards (AUDIT_UNAVAILABLE) until restart — %s. "+
				"Each denied call is recorded as an AUDIT_UNAVAILABLE audit record.\n",
			reason,
		)
	}
}

// warnIfStrictAuditJustDegraded runs recordFn (a RecordAllow/RecordDeny for a call already
// forwarded) and, under strict mode, emits an immediate SECURITY warning if the trail
// transitioned healthy-to-degraded across that exact call.
//
// Narrows, but doesn't close, the strict gate's retrospective window: the gate check runs
// BEFORE callUpstream using counters that only reflect prior calls, so the boundary call
// whose own record is the first lost is still forwarded. Closing it fully would require a
// synchronous record under strict mode; this stays non-blocking, adding only a diagnostic.
//
// Best-effort, not exact attribution: concurrent in-flight requests at the transition instant
// may each warn, which is acceptable — each is a genuine boundary-call candidate.
func warnIfStrictAuditJustDegraded(w io.Writer, strict bool, rec auditRecorder, kind, target string, recordFn func()) {
	if !strict || rec == nil {
		recordFn()
		return
	}
	preDegraded, _, _ := rec.AuditDegraded()
	recordFn()
	if preDegraded {
		return
	}
	if postDegraded, reason, _ := rec.AuditDegraded(); postDegraded {
		_, _ = fmt.Fprintf(w,
			"[eunox] SECURITY: --require-audit=strict: the audit record for the %s %q request just forwarded to the upstream may itself have been lost (%s) — that call could be unaudited; every subsequent forward is now denied.\n",
			kind, target, reason,
		)
	}
}

// recordUpstreamFailure records the deny for a callUpstream error and returns the host-facing
// JSON-RPC error response. Shared by the forward core and */list dispatch so both produce
// byte-identical records for the same physical outage. dispatchList passes the method as
// both auditID and method (no sub-target); the forward core passes the per-target audit id.
func (fp forwardParams) recordUpstreamFailure(ctx context.Context, msg mcp.RPCMsg, err error, auditID, method string, detail map[string]interface{}) mcp.RPCMsg {
	code, reason, rpcCode := upstreamErrInfo(fp.errOutOrStderr(), err, fp.upstreamTimeMs)
	// This deny records a call already forwarded to (and answered, however badly, by)
	// the upstream — the same boundary-call shape warnIfStrictAuditJustDegraded exists
	// for, so it gets the same immediate diagnostic under strict mode.
	warnIfStrictAuditJustDegraded(fp.errOutOrStderr(), fp.requireAuditStrict, fp.rec, method, auditID, func() {
		if fp.rec != nil {
			fp.rec.RecordDeny(ctx, fp.sessionID, auditID, method, code, "", detail, false)
		}
	})
	return mcp.ErrorResponse(msg.ID, rpcCode, reason)
}

// declassifyRefusalDetail reports, for a call refused BELOW the decision, that an approved
// declassification did not take effect — and names the single-use grant it spent. Returns nil
// for a decision that authorized no clear (every call with no declassify directive).
//
// Nothing to UNDO here, which is the point of the two-phase clear: commitDeclassify applies
// it only on the success path, so at any refusal below the decision the labels were never
// removed. The grant is still BURNED (the atomic "once" test belongs with the decision that
// accepted it) — over-refusal the operator resolves with another approval.
//
// Called from five sites beyond its three obvious refusals: declassifyRedactionDetail falls
// back to this shape, and the success path's else-branch calls it for a delivered reply whose
// action failed (isError/JSON-RPC error) — riding an ALLOW record there, so "not applied"
// never means "rejected". A package function (not a method) since it reads only the decision,
// and the server-initiated leg needs the same annotation via its own params type.
func declassifyRefusalDetail(dec capability.EnforceResponse) map[string]interface{} {
	// Either fact is worth a record on its own, and neither implies the other; both hang off
	// the ONE handle so they can't disagree about which decision they came from. Testing the
	// handle's nil instead (rather than both facts) put a bare flow discriminator on the tape
	// for a call with no declassification evidence at all.
	if !dec.Declassification.PendingClear() {
		return spentGrantDetail(dec)
	}
	detail := declassifyDetail()
	detail[audit.DeclassifyNotAppliedKey] = dec.Declassification.Labels()
	addSpentApproval(detail, dec)
	return detail
}

// spentGrantDetail is the annotation for a call with nothing to clear but a burned single-use
// grant to name, or nil when the decision burned nothing. The whole record a NO-OP clear
// produces — nothing is "not applied", but the grant is spent for good, and this is the only
// record that will ever name it. Reached by both the success and refusal paths.
func spentGrantDetail(dec capability.EnforceResponse) map[string]interface{} {
	if dec.Declassification.SpentApprovalID() == "" {
		return nil
	}
	detail := declassifyDetail()
	addSpentApproval(detail, dec)
	return detail
}

// declassifyRedactionDetail is declassifyRefusalDetail for the redaction-failure exit — the
// one refusal below the decision that the upstream may have ANSWERED before it was taken.
//
// The other two exits share "the approved clear did not take effect" as the whole story
// (blocked before the forward, or unknowable whether a side effect landed). Here a reply came
// back and eunox dropped it rather than forward it unredacted, so it may demonstrably have
// run — worth distinguishing so an operator knows whether reissuing the approval retries the
// work or re-delivers work already done.
//
// "Executed" is decided by the same declassifyCommitted the success path uses, never by mere
// presence of a result body — an isError reply, a hostile result+error envelope, or
// undecodable bytes all mean the transform did not happen and fall back to the plain refusal
// shape; stamping "executed" there would put an unbackable fact on the signed tape.
//
// The clear stays withheld either way: the redacted response never reached the host, so the
// taint still accurately describes what entered the session. See
// audit.DeclassifyResultWithheldKey.
func declassifyRedactionDetail(dec capability.EnforceResponse, upResp mcp.RPCMsg) map[string]interface{} {
	detail := declassifyRefusalDetail(dec)
	if detail == nil {
		return nil
	}
	if dec.Decision != capability.DecisionAllow || !declassifyCommitted(upResp) {
		// The reply did not show the action succeeding, so this exit says only what the
		// other two say: the approved clear did not take effect.
		return detail
	}
	// Beside the not-applied key rather than instead of it: both facts are true, and a
	// consumer keyed on the benign "clear never ran" case must still find this refusal.
	// The one shape where it rides ALONE is a no-op clear under a single-use grant — the
	// decision authorized a clear the anchor was not carrying, so there is no not-applied
	// label set, and the spent grant is what makes the withheld fact worth recording at all.
	detail[audit.DeclassifyResultWithheldKey] = true
	return detail
}

// declassifyDetail starts a declassification detail map with the discriminator every
// information-flow event on the tape carries, so one filter finds these beside sink denials
// and declassify escalations. Shared by refusal and commit paths, which had already diverged
// on it once. The reserved `_eunox_declassify_*` keys, not this, are what a rule should
// MATCH on — this is a filter aid, not evidence.
func declassifyDetail() map[string]interface{} {
	return map[string]interface{}{capability.FlowAuditDetailKey: true}
}

// addSpentApproval stamps the single-use declassify grant this call burned, if it burned one.
// Shared by allow and refusal paths since a `once` approval is spent by the decision that
// accepted it regardless of outcome. See audit.DeclassifySpentApprovalKey.
//
// Bounded through the SAME cap the top-level approval_id gets: the id is an IdP-supplied
// string with no length limit, and a transport-built details map only gets the 1 MiB
// whole-map cap — unbounded, one 500 KB approval id would write 128x the envelope cap per
// declassification into the tape.
func addSpentApproval(detail map[string]interface{}, dec capability.EnforceResponse) {
	spent := dec.Declassification.SpentApprovalID()
	if spent == "" {
		return
	}
	detail[audit.DeclassifySpentApprovalKey] = audit.BoundEnvelopeField(spent)
}

// commitDeclassify applies the label clear an approved declassification authorized, for a call
// that has now RUN and whose response is about to reach the host. Returns what the clear
// changed (for the allow record's labels_cleared/approver/approval_id triple) and the extra
// details.
//
// The second phase of the clear: labels stay visible to every concurrent decision until the
// sanitizing call completes, so a sink cannot be allowed while it's still in flight. Holds
// without leaning on the decision turn (deliberately released before the forward, and
// in-process only).
//
// A commit FAULT is not a refusal — the upstream already executed the action, so the honest
// outcome is to deliver it and record the clear didn't land; the session keeps taint it
// should have dropped, over-blocking until retried under a new approval (fail-closed).
//
// committer and sessionID are passed rather than read off a params struct so the host path
// and the server-initiated one share this body instead of mirroring it.
func commitDeclassify(ctx context.Context, w io.Writer, committer declassifyCommitter, sessionID string, dec capability.EnforceResponse, kind, target string) (cleared []string, detail map[string]interface{}) {
	decl := dec.Declassification
	if !decl.PendingClear() {
		// Either no declassify directive at all, or an approved one whose labels the anchor
		// was not carrying — the decision resolved that intersection, so a no-op clear needs
		// no store round trip and records no declassification.
		//
		// A single-use grant it BURNED still has to reach the tape, and this is the only
		// record that will ever name it: the signed labels_cleared/approver/approval_id triple
		// rides a clear that changed something, and this one changed nothing. Returning a bare
		// nil here left that grant named nowhere on a call that SUCCEEDED, while the refusal
		// paths named it — the reconciliation gap backwards.
		return nil, spentGrantDetail(dec)
	}
	detail = declassifyDetail()
	addSpentApproval(detail, dec)
	cleared, err := commitCleared(ctx, committer, sessionID, decl)
	if errors.Is(err, capability.ErrDeclassificationCommitted) {
		// A SECOND commit of one decision is a wiring fault, not a store fault, and must be
		// reported as one. Unreachable through this transport's call graph, but the handle's
		// single-use claim answers "what if it is called twice", so this must answer
		// correctly rather than plausibly. The first commit already applied the clear, so
		// folding this into the fault arm below would tell an operator to reissue an
		// approval for work that already landed — the unsafe direction for an alert to be
		// wrong in. Nothing is cleared HERE, so the record carries only the spent grant.
		_, _ = fmt.Fprintf(w,
			"[eunox] WARN declassify %s %q: the authorized clear was committed twice; the first commit applied it and this one changed nothing (proxy wiring fault, not a flow-store failure — the session is NOT over-tainted)\n",
			kind, target)
		return nil, spentGrantDetail(dec)
	}
	if err != nil {
		authorized := decl.Labels()
		// The call ran and the clear did not, so the tape says so — a distinct key from the
		// refusal's, since the operator action differs: reissue the approval to reach the
		// state the policy describes.
		detail[audit.DeclassifyCommitFailedKey] = authorized
		_, _ = fmt.Fprintf(w,
			"[eunox] WARN declassify %s %q ran under an approved declassification, but the flow label(s) %v could not be cleared: %v — the session stays tainted, so a later sink will over-block until the action is retried under a new approval\n",
			kind, target, authorized, err)
		// cleared may still be non-empty beside the error (a Remove can delete and lose its
		// reply); DISCARDED here since labels_cleared is a signed claim these labels are
		// gone, which an uncertain set cannot back.
		return nil, detail
	}
	return cleared, detail
}

// declassifyCommitted reports whether the upstream's reply is one an approved declassification
// may be committed against — whether the sanitizing action actually SUCCEEDED, not merely
// whether a message came back. A JSON-RPC error or an `isError` tool result must not drop the
// taint: the transform never ran. Ambiguity (undecodable bytes, non-object result) reads as
// failure — over-blocking, resolved with another approval, rather than clearing on a reply
// this build could not interpret.
func declassifyCommitted(upResp mcp.RPCMsg) bool {
	if upResp.Error != nil {
		return false
	}
	if upResp.Result == nil {
		return false
	}
	// A substring probe before the decode: `isError` is absent from most tool results, and a
	// tool result is the largest body on the wire. A miss safely reads as "no failure flag".
	if !bytes.Contains(upResp.Result, []byte(`"isError"`)) {
		return true
	}
	var res struct {
		IsError *bool `json:"isError"`
	}
	if err := json.Unmarshal(upResp.Result, &res); err != nil {
		return false
	}
	return res.IsError == nil || !*res.IsError
}

// commitCleared runs the clear on a context that outlives the request. The request's own
// context is wrong: a client disconnecting while its response is being assembled cancels it,
// failing the commit exactly when the call it sanitizes DID run.
//
// context.WithoutCancel, NOT context.Background: the anchor resolves from the request's
// validated claims, so a fully detached context would clear the SESSION key for a
// task-anchored call — leaving the task tainted while reporting success.
func commitCleared(ctx context.Context, committer declassifyCommitter, sessionID string, decl *capability.Declassification) ([]string, error) {
	if committer == nil {
		// Unreachable through either params constructor, both of which set this from the same
		// PDP they decide with — but a clear that silently never happens is exactly the
		// failure those constructors exist to prevent, so it reports rather than assumes.
		// Distinguished from a store fault in the message: the remedies are a code fix and a
		// backend fix respectively.
		return nil, fmt.Errorf("no policy decision point is wired into this transport path (wiring fault, not a flow-store failure)")
	}
	commitCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), declassifyCommitTimeout)
	defer cancel()
	return committer.CommitDeclassified(commitCtx, sessionID, decl)
}

// mergeAuditDetails folds extra into base and returns a map the caller OWNS, without mutating
// either input. The package's one "fold extra keys into an audit details map" primitive.
//
// Always allocating is load-bearing: base is routinely a map the record is supposed to
// DESCRIBE rather than one this package owns (the request's own parsed argument map, or the
// engine's denial.Details) — handing one of those back would let a later-written key (an
// effect receipt annotation) silently corrupt the request on the signed tape.
//
// nil base with no extra returns nil (preserving nil-vs-empty for the sink); an EMPTY non-nil
// base does NOT take that shortcut — returning it would hand back an input.
func mergeAuditDetails(base, extra map[string]interface{}) map[string]interface{} {
	if base == nil && len(extra) == 0 {
		return nil
	}
	out := make(map[string]interface{}, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// strictAuditDenial implements the --require-audit=strict gate for the host-facing path: when
// strict mode is active and the trail has degraded, it records a fail-closed AUDIT_UNAVAILABLE
// deny and returns the host-facing denial (ok=true); otherwise ok=false and the caller proceeds.
//
// dec is the decision this gate refuses below, zero for paths that run no decision at all. Its
// declassification facts ride the deny record: blocking here means the sanitizing action never
// runs, so an approved clear's grant is named nowhere else.
//
// dec (not a pre-built details map) is the parameter because the gate returns without reading
// it whenever the trail is healthy — every call in a healthy deployment — so building the map
// at the call site would allocate for a value nothing reads. A value, not a callback: nothing
// below the decision mutates state, unlike the compensating version this replaced.
func (fp forwardParams) strictAuditDenial(ctx context.Context, msg mcp.RPCMsg, auditID, method, denialTarget string, dec capability.EnforceResponse) (mcp.RPCMsg, bool) {
	tripped, reason, detail := auditGateTripped(fp.rec, fp.requireAuditStrict)
	if !tripped {
		return mcp.RPCMsg{}, false
	}
	detail = mergeAuditDetails(detail, declassifyRefusalDetail(dec))
	// detail carries discrete counts (dropped_count/write_failure_count); the prose
	// reason is for the host-facing error and the stderr warning only, never the
	// structured audit field.
	fp.rec.RecordDeny(ctx, fp.sessionID, auditID, method, capability.ErrCodeAuditUnavailable, "", detail, false)
	warnStrictAuditOnce(fp.errOutOrStderr(), fp.strictAuditWarned, reason)
	return denialResult(msg.ID, capability.ErrCodeAuditUnavailable, "", denialTarget, ""), true
}

// normalizeDenial returns a non-nil DenialInfo for a deny decision. A third-party PDP could
// implement PolicyDecisionPoint with a nil Denial; dereferencing it would panic the request
// goroutine (fail-open-via-crash), so substitute a generic AUTHORIZATION_FAILED denial.
func normalizeDenial(d *capability.DenialInfo) *capability.DenialInfo {
	if d == nil {
		return &capability.DenialInfo{Code: capability.ErrCodeAuthorizationFailed}
	}
	return d
}

// isObserveDeny reports whether a deny decision should be downgraded to a logged forward
// (audit/observe mode) instead of hard-blocked. Kill-switch and hard denials are never
// downgraded. Shared by the forward core and the sampling leg so their observe gates agree.
func isObserveDeny(denial *capability.DenialInfo, auditMode, auditOnly bool) bool {
	// denial is always non-nil here (both callers normalize first); intentionally no nil
	// guard, since defaulting nil to observable would be the wrong direction to fail in.
	return !pdp.IsKillSwitchDenial(denial) && !denial.HardDeny && (auditMode || auditOnly)
}

// enforcedForwardCore is the shared deny/observe/forward/record decision both transports apply
// to every enforced method. Returns the JSON-RPC message to deliver to the host — a denial, an
// upstream transport error, or the (possibly redacted) response. Transports differ only in
// delivery.
//
// Sequence: a hard deny records and returns without calling upstream; observe downgrades a
// deny to a logged forward (kill-switch always hard-blocks); a transport failure records the
// upstream error code; success applies redactFields obligations (fail closed) and records an
// allow with obligation tokens and allowDetails.
//
// committer is the decision point that MADE dec, passed rather than a field on fp so "these
// two must be the same PDP" cannot silently drift — every call site is a dispatchParams
// handler already holding it. nil means no decision point is in hand (session-creating
// initialize, a test), so no clear can be committed.
func enforcedForwardCore(ctx context.Context, fp forwardParams, committer declassifyCommitter, msg mcp.RPCMsg, dec capability.EnforceResponse, method, auditID, denialTarget, kind string, recordObligations bool, allowDetails func(mcp.RPCMsg) map[string]interface{}) mcp.RPCMsg {
	observe := false
	var denial *capability.DenialInfo // set on the deny path; reused by the observe branch below
	// Fail closed on anything that is not an explicit allow, not just the literal
	// "deny". A PDP that returns a zero-value EnforceResponse (Decision == "") — a
	// buggy custom PDP, or a future in-tree error path that forgets to set Decision —
	// must be treated as a denial, never silently forwarded to the upstream with an
	// allow record. Gating on `== DecisionDeny` would let a "" decision slip past the
	// deny block as an unaudited fail-open; `!= DecisionAllow` is the fail-closed form.
	if dec.Decision != capability.DecisionAllow {
		denial = normalizeDenial(dec.Denial)
		observe = isObserveDeny(denial, fp.audit, dec.AuditOnly)
		if !observe {
			// A genuine hard deny: record it (upstream never called) and return. The declassify
			// fields ride along through mergeAuditDetails (engine's own map never written
			// into) — in-tree always a no-op, but structural so a spent grant reaching a
			// refusal exit is never silently unreported.
			if fp.rec != nil {
				fp.rec.RecordDeny(ctx, fp.sessionID, auditID, method, denial.Code, denial.ConditionType,
					mergeAuditDetails(denial.Details, declassifyRefusalDetail(dec)), false)
			}
			return denialResult(msg.ID, denial.Code, denial.ConditionType, denialTarget, denialArgument(denial))
		}
		// observe: downgrade to a forwarded call. The audit_only=true record is
		// written below, AFTER the strict-audit gate, so a gate-blocked call never
		// leaves a stale "forwarded" deny record for a call that was hard-blocked.
	}

	// --require-audit=strict: don't forward an authorized call once the trail has degraded.
	// Runs BEFORE the observe deny is recorded so a gate block doesn't leave a stale
	// audit_only=true record contradicting the AUDIT_UNAVAILABLE hard-block.
	//
	// The FIRST of three exits below the decision; blocking here means an approved clear's
	// sanitizing action never runs (see declassifyRefusalDetail).
	if denied, blocked := fp.strictAuditDenial(ctx, msg, auditID, method, denialTarget, dec); blocked {
		return denied
	}

	// Gate passed: record the observed (audit_only=true) deny and log the downgrade.
	// denial was set on the deny path above (observe is only true there), so non-nil.
	if observe {
		// The same declassify merge the hard-deny arm makes: no exit below the decision may
		// silently fail to report a spent grant.
		observeDetail := mergeAuditDetails(denial.Details, declassifyRefusalDetail(dec))
		warnIfStrictAuditJustDegraded(fp.errOutOrStderr(), fp.requireAuditStrict, fp.rec, kind, denialTarget, func() {
			if fp.rec != nil {
				fp.rec.RecordDeny(ctx, fp.sessionID, auditID, method, denial.Code, denial.ConditionType, observeDetail, true)
			}
		})
		_, _ = fmt.Fprintf(fp.errOutOrStderr(),
			"[eunox] AUDIT: %s %q would be denied (%s) — forwarding (audit mode)\n",
			kind, denialTarget, denial.Code,
		)
	}

	upResp, fwdErr := fp.callUpstream(ctx, msg)
	if fwdErr != nil {
		// The maxCalls quota slot this call consumed is INTENTIONALLY NOT refunded here. Decide
		// committed the counter atomically WITH the decision, and the upstream may have
		// executed the call before the failure (a write timeout means the bytes were already
		// sent), so a compensating decrement would hand back quota for calls that did run.
		// Accepted cost: an upstream that stops draining stdin can burn a caller's whole
		// budget on calls that never executed — the fail-closed direction (over-count, never
		// under-count), visible on the tape via this deny's upstream error code.
		//
		// The declassification is likewise NOT committed here: keeping a label for a call
		// that may have run over-blocks (resolved with another approval), while clearing it
		// for a call that did NOT run silently admits the egress the label exists to stop.
		return fp.recordUpstreamFailure(ctx, msg, fwdErr, auditID, method, declassifyRefusalDetail(dec))
	}

	// Apply post-allow obligations (redactFields) before the response reaches the host. Only
	// tools carry directives. Fail closed: a redaction error must never forward unredacted data.
	if len(dec.Obligations) > 0 && upResp.Result != nil {
		redacted, redactErr := pdp.ApplyRedactObligs(upResp.Result, dec.Obligations)
		if redactErr != nil {
			_, _ = fmt.Fprintf(fp.errOutOrStderr(), "[eunox] SECURITY: redaction failed for %s %q: %v\n", kind, denialTarget, redactErr)
			// Record a deny so the call stays visible on the tape — otherwise an adversarial
			// upstream could return a redaction-failing response to make every redactFields-
			// guarded call vanish from the audit trail.
			//
			// The third exit below the decision, and the only one the upstream may have
			// ANSWERED before it was taken. declassifyRedactionDetail decides what the record
			// may CLAIM about that reply (see its doc).
			redactDetail := declassifyRedactionDetail(dec, upResp)
			warnIfStrictAuditJustDegraded(fp.errOutOrStderr(), fp.requireAuditStrict, fp.rec, kind, denialTarget, func() {
				if fp.rec != nil {
					fp.rec.RecordDeny(ctx, fp.sessionID, auditID, method, capability.ErrCodeEnforcementError, "", redactDetail, false)
				}
			})
			return mcp.ErrorResponse(msg.ID, jsonRPCCodeInternalError, "internal error: response redaction failed")
		}
		upResp.Result = redacted
	}
	// Independently of the result branch (separate `if`, not `else if`): a malformed/hostile
	// upstream returning BOTH a result and an error (which JSON-RPC forbids) must not forward
	// a redactable value through error.data, a free-form channel the redact paths can't verify.
	if upResp.Error != nil && upResp.Error.Data != nil && hasRedactFieldsObligation(dec.Obligations) {
		_, _ = fmt.Fprintf(fp.errOutOrStderr(), "[eunox] SECURITY: dropping error.data on %s %q — a redactFields obligation cannot be verified against the free-form JSON-RPC error channel\n", kind, denialTarget)
		upResp.Error.Data = nil
	}

	var oblNames []string
	// Only record obligation tokens when there was a result body to redact — a JSON-RPC error
	// response skips the redaction block above, so listing fields here would overstate what
	// happened.
	if recordObligations && upResp.Result != nil {
		oblNames = auditObligationNames(dec.Obligations)
	}
	// The call has run, SUCCEEDED, and its redacted response is deliverable — the condition an
	// approved clear was waiting on. Commit HERE: after the last exit that could still refuse,
	// before the record that reports it.
	//
	// declassifyCommitted is the SUCCESS half, not redundant with the exits above: a reply
	// flagged isError (or a JSON-RPC error) reaches here with the transform never performed
	// and is treated as a refused call — nothing cleared.
	var labelsCleared []string
	var declDetail map[string]interface{}
	// dec.Decision, not just the pending set: the observe path forwards a call whose verdict
	// was a DENY, and a downgraded deny must never untaint a session (defense in depth against
	// a PDP that stamps a handle on a deny).
	if dec.Decision == capability.DecisionAllow && declassifyCommitted(upResp) {
		labelsCleared, declDetail = commitDeclassify(ctx, fp.errOutOrStderr(), committer, fp.sessionID, dec, kind, denialTarget)
	} else {
		declDetail = declassifyRefusalDetail(dec)
	}
	// The commit was the last thing that had to be inside the decision turn, so release it
	// HERE rather than at handler return — the audit enqueue and response write that follow
	// don't touch the turn's state, and under task anchoring holding it would let one
	// client's backpressure stall another session's decisions. Idempotent; a no-op for a
	// call that already released after its decision or a non-serialized request.
	if fp.endDecision != nil {
		fp.endDecision()
	}

	// Carry dec.AuditOnly so a per-entry audit-mode forward is not logged as a
	// genuine allow. allowDetails supplies the structured details.
	warnIfStrictAuditJustDegraded(fp.errOutOrStderr(), fp.requireAuditStrict, fp.rec, kind, denialTarget, func() {
		if fp.rec == nil {
			return
		}
		// Through mergeAuditDetails, never a write into allowDetails' return: the tools/call
		// closure's base under --audit is the caller's live parsed argument map, so writing
		// into whatever that chain hands back would rewrite the request being described.
		details := mergeAuditDetails(allowDetails(upResp), declDetail)
		// A call that CLEARED flow labels takes the recorder that carries the approval; every
		// other call takes the plain one. The branch is on what the commit actually CHANGED,
		// not on what was authorized — a no-op clear would otherwise record an approver for a
		// declassification that never happened.
		if len(labelsCleared) > 0 {
			// The declassification's three facts are passed as FIELDS — top-level, signed, and
			// appearing together or not at all — never merged into the details map.
			fp.rec.RecordDeclassifiedAllow(ctx, fp.sessionID, auditID, method, details, oblNames, fp.audit || dec.AuditOnly, dec.LabelsOut, dec.CarriedLabels, labelsCleared, dec.Declassification.Approver(), dec.Declassification.ApprovalID())
			return
		}
		fp.rec.RecordAllow(ctx, fp.sessionID, auditID, method, details, oblNames, fp.audit || dec.AuditOnly, dec.LabelsOut, dec.CarriedLabels)
	})
	upResp.ID = msg.ID
	return upResp
}

// hasRedactFieldsObligation reports whether obligs carries a redactFields directive with at
// least one path — gates the fail-closed error.data strip against an upstream error carrying
// free-form data eunox cannot verify.
func hasRedactFieldsObligation(obligs []capability.Obligation) bool {
	for _, ob := range obligs {
		if ob.Type == capability.DirectiveTypeRedactFields && len(ob.Paths) > 0 {
			return true
		}
	}
	return false
}

// auditObligationNames flattens the obligations applied to an allowed response into the
// obligations[] tokens: one "type:path" entry per matched redact path, so the tape captures
// WHICH fields were masked, never the redacted values (docs/threat-model-mcp.md §6.3).
// Consumers split a token on its FIRST ':'. The audit sink bounds the returned slice before
// enqueue (boundAuditObligations).
func auditObligationNames(obligs []capability.Obligation) []string {
	if len(obligs) == 0 {
		return nil
	}
	// Capacity is the total token count — one per path, or one bare-type token for an
	// obligation with no paths — not len(obligs), since one obligation can carry several.
	total := 0
	for _, ob := range obligs {
		if len(ob.Paths) == 0 {
			total++
			continue
		}
		total += len(ob.Paths)
	}
	names := make([]string, 0, total)
	for _, ob := range obligs {
		if len(ob.Paths) == 0 {
			names = append(names, ob.Type)
			continue
		}
		for _, p := range ob.Paths {
			names = append(names, ob.Type+":"+p)
		}
	}
	return names
}

// upstreamErrorDetail returns a structured audit detail noting that the upstream returned a
// JSON-RPC error on an otherwise-allowed call, or nil for a clean success. The numeric code
// is recorded — never the message, which can carry sensitive content.
func upstreamErrorDetail(upResp mcp.RPCMsg) map[string]interface{} {
	if upResp.Error == nil {
		return nil
	}
	return map[string]interface{}{audit.UpstreamErrorCodeKey: upResp.Error.Code}
}

// serverRequestParams bundles the per-transport bits the shared server-initiated request core
// needs. forward delivers msg to the host and reports whether a client received it;
// writeUpstream sends a response back to the upstream initiator; claims carries the session's
// JWT identity (HTTP only). The rest mirror forwardParams.
type serverRequestParams struct {
	rec       auditRecorder
	audit     bool
	sessionID string
	sourceIP  string
	claims    *pdp.JWTClaims
	// pdp is the decision point this leg decides with. Nothing here is DERIVED from it — a
	// declassification is refused here rather than committed — so a plain field is enough.
	pdp pdp.PolicyDecisionPoint
	// revision is the revision this session's HOST context negotiated. This leg has no host
	// request to read one from, so each transport supplies the fact and forwardServerRequest
	// stamps it — a new server-initiated entry point inherits the stamp rather than needing it
	// re-placed, which is how this leg came to record every sampling decision on a negotiated
	// session as though no revision had been resolved. Empty means the host has not negotiated
	// yet, and stays absent on the record: that IS the honest reading.
	revision      capability.Revision
	forward       func(mcp.RPCMsg) bool
	writeUpstream func(mcp.RPCMsg)
	// decideLock serializes the sampling decision against host-path decisions on the same
	// anchor when the policy is flow-relevant, since this path runs on the upstream-reader
	// goroutine outside the host decision turn and could otherwise peek the flow set
	// mid-commit of a host source's write. Wraps ONLY the decision, never the forward. nil
	// disables serialization.
	//
	// ok is false when the turn could not be entered within its bound: this runs on the
	// session's single upstream-reader goroutine, so blocking it for another call's turn
	// stalls every in-flight request on the session. Failing closed costs one deny-by-default
	// request; waiting costs the whole response path.
	decideLock func() (end func(), ok bool)
	// anchorSplit reports whether this session's host leg has resolved MORE THAN ONE state
	// anchor, in which case this leg cannot decide at all — it has no host request in scope,
	// so deciding against the captured claims' anchor would peek one bucket while the host leg
	// taints another. nil where the question cannot arise (stdio, or non-task-anchored routes).
	anchorSplit func() bool
	// strictAuditState (embedded) carries the --require-audit=strict gate, which also
	// covers the enforced sampling/createMessage path below. See forwardParams.
	strictAuditState
	// errOut is this leg's diagnostic writer; see forwardParams.errOut for the fallback rule
	// and rationale (nil means os.Stderr).
	errOut io.Writer
}

// errOutOrStderr returns fp.errOut when set, else os.Stderr. See forwardParams.errOutOrStderr;
// duplicated as a method (not shared via embedding) because serverRequestParams and
// forwardParams are deliberately separate structs — the server-initiated leg carries none of
// forwardParams' host-request-only fields (callUpstream, endDecision, upstreamTimeMs).
func (fp serverRequestParams) errOutOrStderr() io.Writer {
	return resolvedErrOut(fp.errOut)
}

// samplingTurnWait bounds how long the server-initiated leg waits for the decision turn. BOTH
// transports bound it here since the hazard is a property of where this leg runs, not of
// which gate it waits on. Each server-initiated request runs on its own goroutine
// (serverRequestPool), so a handler parked here blocks only itself — the bound below is on an
// unbounded WAIT, not a wedge.
//
//   - perHolder (2s) bounds ONE turn holder, since the turn may be held across a whole upstream
//     round trip by a declassifying call (see finishDecision), including on a different
//     session under task anchoring. Bounding the HOLDER (not the waiter's own arrival) is what
//     keeps a batch of waiters from being refused together for one slow turn.
//   - total (8s) is the absolute ceiling, since "the queue is moving" must not mean "forever" —
//     a parked handler holds a pool slot, so a steady stream of sub-2s holders would otherwise
//     pin slots indefinitely.
//
// The refusal on give-up stays HARD (see samplingTurnDenial), not the pool's retryable -32000:
// forwarding a sampling request whose decision never ran is exactly what serialization exists
// to prevent, so transience buys a retry, not a forward.
var samplingTurnWait = turnWait{perHolder: 2 * time.Second, total: 8 * time.Second}

// decideSampling runs the sampling decision under the decision turn when configured (see
// decideLock), releasing it BEFORE the caller forwards to the host.
//
// A turn this leg cannot enter within samplingTurnWait produces a DENY rather than an
// unserialized decision — the peek would race a host source's label write, the exact fail-open
// serialization exists to close. HARD: an --audit route must not downgrade it into the forward
// it exists to prevent.
func (fp serverRequestParams) decideSampling(ctx context.Context) capability.EnforceResponse {
	// Asked BEFORE the turn, so a decision that cannot be made correctly does not queue for
	// the right to make it.
	if fp.anchorSplit != nil && fp.anchorSplit() {
		return samplingAnchorSplitDenial()
	}
	if fp.decideLock != nil {
		end, ok := fp.decideLock()
		if !ok {
			return samplingTurnDenial()
		}
		defer end()
		// And AGAIN once the turn is held: the two anchors take DIFFERENT gates (why this
		// refusal exists), so without the re-check a taint committed under the other anchor
		// during the wait would be invisible to the peek that follows. A lock-free atomic read.
		if fp.anchorSplit != nil && fp.anchorSplit() {
			return samplingAnchorSplitDenial()
		}
	}
	return fp.pdp.DecideSampling(ctx, fp.sessionID, fp.sourceIP)
}

// samplingTurnDenial is the fail-closed response for a sampling request whose decision could
// not be serialized against the anchor's host-path decisions.
func samplingTurnDenial() capability.EnforceResponse {
	return samplingFlowDenial(
		"the sampling decision could not be serialized against concurrent decisions on this anchor; refusing rather than reading flow state mid-write",
		"turn_unavailable")
}

// samplingAnchorSplitDenial is the fail-closed response for a server-initiated request on a
// session whose host leg has resolved more than one state anchor.
//
// A session on a task-anchored route may span tasks, each decided on its own anchor — correct
// for the host leg, but this leg has no host request in scope, so which task a
// sampling/createMessage belongs to is undetermined. Attributing it to the captured claims'
// anchor would let the sink peek one bucket while a source taints another.
//
// HARD (forwarding would perform an egress whose authorization couldn't be evaluated) and
// STICKY for the session's life (see noteRequestAnchor) — a client needing sampling on a
// task-anchored route keeps one session per task.
func samplingAnchorSplitDenial() capability.EnforceResponse {
	return samplingFlowDenial(
		"this session has issued requests under more than one state anchor, so which task a server-initiated request belongs to is undetermined; refusing rather than reading one task's flow state for another",
		"session_spans_anchors")
}

// samplingDeclassifyDenial is the fail-closed response for a sampling decision that authorized
// a flow-label clear. This leg cannot commit one — see forwardServerRequest for why "the host
// received the request" is not "the sanitizing action ran" — so it refuses.
//
// It CARRIES the refused decision's handle: the decision already burned any single-use grant
// it accepted, and replacing the response wholesale would leave that grant spent with nothing
// on the tape naming it.
func samplingDeclassifyDenial(dec capability.EnforceResponse) capability.EnforceResponse {
	refusal := samplingFlowDenial(
		"a declassification cannot be committed on the server-initiated leg: this path learns only that the host received the request, never that the sanitizing action ran",
		"declassify_unsupported")
	refusal.Declassification = dec.Declassification
	refusal.CarriedLabels = dec.CarriedLabels
	return refusal
}

// samplingFlowDenial builds this leg's flow-layer refusals. Both are HARD: an --audit route
// downgrades a policy verdict being staged, and neither of these is one — forwarding either
// would perform the very thing the refusal exists to prevent.
func samplingFlowDenial(message, reason string) capability.EnforceResponse {
	return capability.EnforceResponse{
		Decision: capability.DecisionDeny,
		Denial: &capability.DenialInfo{
			Code:          capability.ErrCodeConditionFailed,
			ConditionType: capability.ConditionTypeFlowLabel,
			Message:       message,
			HardDeny:      true,
			Details:       map[string]interface{}{capability.FlowAuditDetailKey: true, "reason": reason},
		},
	}
}

// strictServerRequestAuditDenial applies the --require-audit=strict gate to a server-initiated
// (upstream -> host) request, sampling and non-sampling alike: when tripped it records the
// deny, replies AUDIT_UNAVAILABLE to the upstream initiator, warns once, and returns true. The
// server-initiated analogue of strictAuditDenial, failing closed toward the initiator.
//
// dec is the decision this gate refuses below, zero for the non-sampling leg. Its
// declassification facts ride the deny record exactly as on the host path.
func (fp serverRequestParams) strictServerRequestAuditDenial(ctx context.Context, msg mcp.RPCMsg, method string, dec capability.EnforceResponse) bool {
	tripped, reason, detail := auditGateTripped(fp.rec, fp.requireAuditStrict)
	if !tripped {
		return false
	}
	// Record BEFORE replying to the upstream (record-before-act), matching the other legs, so
	// a crash between the two can't leave the upstream answered with no matching record.
	fp.rec.RecordDeny(ctx, fp.sessionID, method, method, capability.ErrCodeAuditUnavailable, "",
		mergeAuditDetails(detail, declassifyRefusalDetail(dec)), false)
	fp.writeUpstream(mcp.ErrorResponse(msg.ID, capability.JSONRPCCodeEnforcementError, capability.ErrCodeAuditUnavailable))
	warnStrictAuditOnce(fp.errOutOrStderr(), fp.strictAuditWarned, reason)
	return true
}

// recordForwardOutcome writes the audit record for a forwarded server-initiated request: an
// allow when a client accepted it, or an ENFORCEMENT_ERROR deny when none could. Shared by all
// three forwardServerRequest legs so the record shape cannot drift between them.
//
// On HTTP, "delivered" means buffered onto an SSE subscriber channel, not that the host's
// socket received it — httpSession.failServerRequestDelivery appends a correction deny if
// async delivery later fails. On stdio, forward always reports delivered.
//
// dec supplies the record's flow fields and, when a clear changed something, the
// declassification's signed triple. The non-sampling leg passes the zero decision (commits no
// clear today). declDetail carries the annotations for a clear that did not land.
func (fp serverRequestParams) recordForwardOutcome(ctx context.Context, method string, delivered, auditOnly bool, dec capability.EnforceResponse, cleared []string, declDetail map[string]interface{}) {
	warnIfStrictAuditJustDegraded(fp.errOutOrStderr(), fp.requireAuditStrict, fp.rec, method, method, func() {
		if fp.rec == nil {
			return
		}
		if !delivered {
			fp.rec.RecordDeny(ctx, fp.sessionID, method, method, capability.ErrCodeEnforcementError, "", declDetail, false)
			return
		}
		if len(cleared) > 0 {
			fp.rec.RecordDeclassifiedAllow(ctx, fp.sessionID, method, method, declDetail, nil, auditOnly, dec.LabelsOut, dec.CarriedLabels,
				cleared, dec.Declassification.Approver(), dec.Declassification.ApprovalID())
			return
		}
		fp.rec.RecordAllow(ctx, fp.sessionID, method, method, declDetail, nil, auditOnly, dec.LabelsOut, dec.CarriedLabels)
	})
}

// forwardServerRequest is the shared handling both transports apply to an upstream-initiated
// (server→client) request. Non-sampling methods (roots/list, elicitation/create, …) are not
// policy-enforced — always forwarded, still audited, and still gated by --require-audit=strict.
// sampling/createMessage is deny-by-default (pdp.DecideSampling checks the kill switch and the
// manifest opt-in); a denial returns the denial code unless route-level audit mode
// observes-and-forwards it (kill-switch always hard-blocks). Transports differ only in
// fp.forward, fp.writeUpstream, and fp.claims.
//
// Caller contract: msg is a REQUEST (mcp.RPCMsg.IsRequest) — every denial below answers the
// initiator unconditionally, with no notification arm to skip.
func forwardServerRequest(ctx context.Context, msg mcp.RPCMsg, fp serverRequestParams) {
	const samplingMethod = capability.MethodSamplingCreateMessage
	// Attach JWT claims BEFORE the method split so both branches' kill checks see the
	// per-agent dimension (ShouldBlock only consults killedAgents when agentID != "").
	// Without this, the non-sampling kill check would silently forward a killed agent's
	// roots/list, elicitation/create, etc. Inert for stdio (claims always nil).
	if fp.claims != nil {
		ctx = pdp.WithJWTClaims(ctx, fp.claims)
	}
	// Stamped here for the same reason the claims are: both branches record, and a stamp
	// placed in one transport's caller is a stamp the other transport (or the next entry
	// point) can be written without.
	if fp.revision != "" {
		ctx = capability.WithProtocolRevision(ctx, fp.revision)
	}
	if msg.Method != samplingMethod {
		if deny := fp.pdp.CheckKill(ctx, fp.sessionID); deny != nil {
			denial := normalizeDenial(deny.Denial)
			if fp.rec != nil {
				fp.rec.RecordDeny(ctx, fp.sessionID, msg.Method, msg.Method, denial.Code, denial.ConditionType, nil, false)
			}
			fp.writeUpstream(mcp.ErrorResponse(msg.ID, denialToJSONRPCCode(denial.Code), denial.Code))
			return
		}
		// --require-audit=strict gates non-sampling server-initiated requests too: a degraded
		// trail must fail closed here too, mirroring the sampling branch's gate below.
		if fp.strictServerRequestAuditDenial(ctx, msg, msg.Method, capability.EnforceResponse{}) {
			return
		}
		delivered := fp.forward(msg)
		// Non-sampling methods are not policy-enforced, so there is no flow decision to record.
		fp.recordForwardOutcome(ctx, msg.Method, delivered, fp.audit, capability.EnforceResponse{}, nil, nil)
		return
	}

	// Claims were attached above the method split; the sampling decision reads them from ctx.
	if fp.audit {
		ctx = enforcement.WithSkipQuota(ctx)
	}
	// Serialized against host-path decisions for a flow-relevant session, so a flowLabel sink
	// cannot read the flow set concurrently with a host source's write. Covers only the
	// decision's flow peek; the forward below runs unlocked.
	dec := fp.decideSampling(ctx)
	// A decision on this leg may not authorize a clear: requireSourceDirectiveTarget refuses a
	// declassify directive at LOAD on a system: target, but relaxing that must not silently
	// produce a wrong clear here — this path has no honest commit point. "Delivered" means
	// buffered onto SSE or written to stdout, not that the host performed anything, so
	// committing on delivery would drop taint for work that may never happen. Refusing is
	// loud: whoever relaxes the load rule sees this, rather than a tape claiming success.
	if dec.Declassification.PendingClear() {
		dec = samplingDeclassifyDenial(dec)
	}
	if dec.Decision == capability.DecisionAllow {
		// --require-audit=strict gates this enforced method too. Scope: sampling needs the
		// system:sampling opt-in, rejected at startup for HTTP upstreams, so this only bites
		// stdio subprocess upstreams.
		if fp.strictServerRequestAuditDenial(ctx, msg, samplingMethod, dec) {
			return
		}
		delivered := fp.forward(msg)
		// Carry the sampling decision's flow labels onto the tape, or the tape and state
		// disagree for the sampling leg. declassifyRefusalDetail names a burned grant if one
		// ever reaches this leg, at no cost otherwise.
		fp.recordForwardOutcome(ctx, samplingMethod, delivered, fp.audit, dec, nil, declassifyRefusalDetail(dec))
		return
	}

	// Same observe gate as enforcedForwardCore, via the shared isObserveDeny — a future
	// audit-only system: entry can't silently lose observe-mode behavior here.
	denial := normalizeDenial(dec.Denial)
	observe := isObserveDeny(denial, fp.audit, dec.AuditOnly)
	if !observe {
		// Hard deny. Record BEFORE replying (record-before-act). Reply with the REAL denial code
		// as both JSON-RPC code and message — derived via denialToJSONRPCCode rather than a
		// literal, and sending denial.Code as the message so an upstream sees the actual
		// reason instead of a hardcoded "AUTHORIZATION_FAILED".
		if fp.rec != nil {
			// Pass denial.Details: a flowLabel deny on system:sampling names the blocked
			// provenance class there, which dropping details would leave absent from the tape.
			fp.rec.RecordDeny(ctx, fp.sessionID, samplingMethod, samplingMethod, denial.Code, denial.ConditionType,
				mergeAuditDetails(denial.Details, declassifyRefusalDetail(dec)), false)
		}
		fp.writeUpstream(mcp.ErrorResponse(msg.ID, denialToJSONRPCCode(denial.Code), denial.Code))
		return
	}
	// Strict mode gates the audit-mode observe forward too — an unrecorded observation has no
	// audit value. Runs after the kill-switch hard-deny above so a kill still surfaces
	// AUTHORIZATION_FAILED.
	if fp.strictServerRequestAuditDenial(ctx, msg, samplingMethod, dec) {
		return
	}
	// Record-before-act: recorded before both the stderr notice and the forward, so a crash
	// between them can't leave a SIEM alert with no corresponding audit record.
	if fp.rec != nil {
		// Carry denial.Details here too: the would-be flowLabel deny's blocked label must
		// reach the tape.
		fp.rec.RecordDeny(ctx, fp.sessionID, samplingMethod, samplingMethod, denial.Code, denial.ConditionType,
			mergeAuditDetails(denial.Details, declassifyRefusalDetail(dec)), true)
	}
	_, _ = fmt.Fprintf(fp.errOutOrStderr(),
		"[eunox] AUDIT: sampling/createMessage would be denied (%s) — forwarding (audit mode)\n",
		denial.Code,
	)
	delivered := fp.forward(msg)
	// audit=true: the observe path. dec (the downgraded deny) still carries carried_labels, so
	// the record shows the flow that was let through.
	//
	// No commit: a downgraded deny is still a deny, and untainting on one would drop a label
	// for a call policy refused (the same rule enforcedForwardCore's DecisionAllow gate states).
	fp.recordForwardOutcome(ctx, samplingMethod, delivered, true, dec, nil, declassifyRefusalDetail(dec))
}
