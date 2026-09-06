// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The wiring around a refusal, asserted rather than assumed: which bucket a refusal charges, which
// vocabulary its `transport` detail is drawn from, whether the leg it runs on can forward or reply
// at all, and that the one method able to strand a server-initiated initiator is reached only
// through the wrapper that disposes of what it returns.
//
// Every property here held once by an accident of control flow — an arm that happened to return
// earlier, a caller that happened to be the only one — which is why each is pinned at the seam
// rather than through the one path that reaches it today.

package transport

import (
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/token"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// preSessionGateFor builds the PRE-SESSION notification gate the way handleMCPPost's id-less
// `initialize` arm does: the leg's own recorder wiring, established=false, no revocation.
func preSessionGateFor(p *HTTPProxy, route *UpstreamRoute) hostNotificationGate {
	return hostNotificationGate{
		recorders: p.preSessionRefusalRecorders(route),
		subject:   verifiedSession(""),
		checkKill: noKill,
		leg:       legHTTPNotification,
	}
}

// TestPreSessionGate_DeclaredExemptRefusalsSpendNoKillToken is the regression for a declaration and
// its wiring disagreeing.
//
// catUnroutable and catSmuggled are declared EXEMPT, and both arms named their category — but the
// recorder they were handed was the LEG's, and the pre-session leg's is drawn from the catKill
// bucket. So an exemption on the record spent a catKill token anyway, and spent the one bucket that
// bounds the pre-session KILL_SWITCH records an incident responder reads first. The marker function
// that used to stand in for the resolver could not see it: it returned what it was handed, and an
// auditRecorder carries no provenance.
//
// It held only because that arm structurally handles `initialize` alone, whose notification
// disposition is swallowed — a coincidence nothing enforced. Driven here through the gate itself,
// with the methods that arm would see the day a second pre-session method exists.
func TestPreSessionGate_DeclaredExemptRefusalsSpendNoKillToken(t *testing.T) {
	t.Parallel()
	sink, _ := newTempAuditSink(t)
	defer func() { _ = sink.Close() }()
	proxy := newTestHTTPProxy()
	route := &UpstreamRoute{name: "up1", sink: &routeSink{sink: sink, upstream: "up1"}}
	gate := preSessionGateFor(proxy, route)
	ctx := revisionContext(handshakeRevision)

	// Both exempt arms, far past what any bucket would admit: the fail-closed routing refusal and
	// the enforced-method-as-notification reject.
	for range 500 {
		require.Equal(t, notificationRefused, gate.admit(ctx, mcp.RPCMsg{JSONRPC: "2.0", Method: "x/bogus"}))
		require.Equal(t, notificationRefused, gate.admit(ctx, mcp.RPCMsg{JSONRPC: "2.0", Method: capability.MethodToolsCall}))
	}

	// The kill bucket must be untouched: its whole burst still admits.
	for i := range perCategoryDenyBurstSize {
		assert.NotNil(t, proxy.preSessionKillRecorder(route),
			"kill record %d was suppressed: a refusal DECLARED exempt drained the bucket bounding the records an emergency stop depends on", i)
	}
}

// TestRefusalRecorders_ApplyTheDeclarationNotTheLegsDefault pins the property that makes the fix
// structural rather than a corrected call site: the resolver READS exemptRefusals, so a
// category added later cannot be metered by a leg that meters, or exempted by one that does not,
// against what it declares.
func TestRefusalRecorders_ApplyTheDeclarationNotTheLegsDefault(t *testing.T) {
	t.Parallel()
	sink, _ := newTempAuditSink(t)
	defer func() { _ = sink.Close() }()
	proxy := newTestHTTPProxy()
	route := &UpstreamRoute{name: "up1", sink: &routeSink{sink: sink, upstream: "up1"}}
	recs := proxy.preSessionRefusalRecorders(route)

	for _, cat := range allRefusalCategories {
		charged := 0
		// A metered category runs out; an exempt one never does.
		for range perCategoryDenyBurstSize + 50 {
			if recs.forCategory(cat) != nil {
				charged++
			}
		}
		if _, exempt := exemptRefusals[cat]; exempt {
			assert.Equal(t, perCategoryDenyBurstSize+50, charged,
				"category %q is declared exempt but its resolved recorder was suppressed; the wiring is metering what the declaration does not", cat)
			continue
		}
		assert.LessOrEqual(t, charged, perCategoryDenyBurstSize+1,
			"category %q is declared metered but its resolved recorder was never suppressed; the wiring is exempting what the declaration meters", cat)
		assert.Positive(t, charged,
			"category %q resolved to nil for EVERY record; a bucket that never admits is not metering, it is silence", cat)
	}
}

// TestRouteRefusalRecorders_EstablishedSessionKillIsUnbounded is the other half of the per-category
// split: a kill record for a session this proxy already established describes an already-admitted
// caller and is deliberately written unlimited (see catKill), so the established leg must not
// inherit the pre-session leg's bucket along with its shape.
func TestRouteRefusalRecorders_EstablishedSessionKillIsUnbounded(t *testing.T) {
	t.Parallel()
	sink, _ := newTempAuditSink(t)
	defer func() { _ = sink.Close() }()
	route := &UpstreamRoute{name: "up1", sink: &routeSink{sink: sink, upstream: "up1"}}
	recs := newTestHTTPProxy().routeRefusalRecorders(route)
	for i := range perCategoryDenyBurstSize + 50 {
		require.NotNil(t, recs.forCategory(catKill),
			"kill record %d was suppressed on an ESTABLISHED session; that record is the one an operator most needs during an emergency stop", i)
	}
}

// TestRoutingRefusal_NotificationFramingBuildsNoResponse pins the framing split. JSON-RPC forbids
// replying to a notification, so the caller discards whatever the core returns — and the core was
// building a complete denial envelope for it anyway (a reflection-based json.Marshal of the denial
// data, a fmt chain, a heap RPCError) on the cheapest message an unauthenticated peer can drive.
//
// The record is what must NOT be skipped, so both halves are asserted together.
func TestRoutingRefusal_NotificationFramingBuildsNoResponse(t *testing.T) {
	t.Parallel()
	ctx := revisionContext(handshakeRevision)
	msg := mcp.RPCMsg{JSONRPC: "2.0", Method: "x/bogus"}

	notifRec := &fwdRecorder{}
	resp := refuseUnroutable(ctx, refusalForwardParams(verifiedSession("s"), false, strictAuditState{}),
		refusalLimits{notices: noticesTo(io.Discard)}.recorders(notifRec), verifiedSession("s"), msg, unroutableFramingNotification)
	assert.Nil(t, resp.Error, "the notification framing has no reply channel, so no denial envelope may be built for it")
	assert.Nil(t, resp.ID)
	require.Len(t, notifRec.records, 1, "skipping the response must not skip the record the refusal legitimately writes")
	assert.Equal(t, capability.ErrCodeUnroutableMethod, notifRec.records[0].code)

	// The request framing is the control: same refusal, same record, and an envelope to send.
	reqRec := &fwdRecorder{}
	reqMsg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "x/bogus"}
	resp = refuseUnroutable(ctx, refusalForwardParams(verifiedSession("s"), false, strictAuditState{}),
		refusalLimits{notices: noticesTo(io.Discard)}.recorders(reqRec), verifiedSession("s"), reqMsg, unroutableFramingRequest)
	require.NotNil(t, resp.Error, "the request framing must still be answered")
	require.Len(t, reqRec.records, 1)
	assert.Equal(t, notifRec.records[0].code, reqRec.records[0].code,
		"the two framings are one refusal for one reason; only the reply channel differs")
}

// TestEnforcedForwardCore_NoIDRefusalsBuildNoEnvelope extends the id-keyed rule above from three of
// the core's six host-facing exits to five.
//
// The upstream-transport failure and the fail-closed redaction failure are refusals too, and both
// built a complete JSON-RPC error for a message JSON-RPC forbids answering. They are unreachable for
// a no-id message today only because the one caller that passes one also removes the upstream — two
// independent facts nothing couples, and the natural next step (folding the smuggled-notification
// reject into this core) arrives with a live upstream and reaches both. The RECORD is what must not
// be skipped, so both halves are asserted together.
func TestEnforcedForwardCore_NoIDRefusalsBuildNoEnvelope(t *testing.T) {
	t.Parallel()
	allow := capability.EnforceResponse{Decision: capability.DecisionAllow}
	notification := mcp.RPCMsg{JSONRPC: "2.0", Method: capability.MethodToolsCall}

	t.Run("upstream failure", func(t *testing.T) {
		t.Parallel()
		rec := &fwdRecorder{}
		fp := forwardParams{rec: rec, sessionID: "s", limits: refusalLimits{notices: noticesTo(io.Discard)},
			callUpstream: func(context.Context, mcp.RPCMsg) (mcp.RPCMsg, error) {
				return mcp.RPCMsg{}, errors.New("upstream exited (test probe)")
			}}
		resp := enforcedForwardCore(revisionContext(handshakeRevision), fp, notification, allow,
			capability.MethodToolsCall, "tool:x", "tool:x", "tool", false, nil)
		assert.Nil(t, resp.Error, "a message with no id has no reply channel, so no error envelope may be built for it")
		assert.Nil(t, resp.ID)
		require.Len(t, rec.records, 1, "skipping the envelope must not skip the record the refusal legitimately writes")
	})

	t.Run("redaction failure", func(t *testing.T) {
		t.Parallel()
		rec := &fwdRecorder{}
		redacting := allow
		redacting.Obligations = []capability.Obligation{{Type: capability.DirectiveTypeRedactFields, Paths: []string{"secret"}}}
		fp := forwardParams{rec: rec, sessionID: "s", limits: refusalLimits{notices: noticesTo(io.Discard)},
			callUpstream: func(_ context.Context, msg mcp.RPCMsg) (mcp.RPCMsg, error) {
				// "content" present but not an array: ApplyRedactObligs fails closed on it.
				return mcp.RPCMsg{ID: msg.ID, Result: json.RawMessage(`{"content":{}}`)}, nil
			}}
		resp := enforcedForwardCore(revisionContext(handshakeRevision), fp, notification, redacting,
			capability.MethodToolsCall, "tool:x", "tool:x", "tool", false, nil)
		assert.Nil(t, resp.Error)
		assert.Nil(t, resp.ID)
		require.Len(t, rec.records, 1)
		assert.Equal(t, capability.ErrCodeEnforcementError, rec.records[0].code,
			"an adversarial upstream must not be able to make a redactFields-guarded call vanish from the tape")
	})
}

// TestRoutingRefusal_NoticeIsBoundedWhileItsRecordIsNot settles the two halves of the cheapest
// refusal in the tree, which were reasoned about with one standard applied to both.
//
// The RECORD is declared exempt because a policy verdict may never be admission-controlled. That
// argument does not reach the stderr NOTICE — no policy DENY writes one, and a diagnostic line is
// not a verdict — so the notice was the one place an unauthenticated peer drove an unbuffered write
// syscall per frame, at its full send rate, on a message with no id, no handler slot and no upstream
// round trip.
func TestRoutingRefusal_NoticeIsBoundedWhileItsRecordIsNot(t *testing.T) {
	t.Parallel()
	ctx := revisionContext(handshakeRevision)
	msg := mcp.RPCMsg{JSONRPC: "2.0", Method: "x/bogus"}
	const frames = 200

	now := time.Now()
	notices := newNoticeLimiter(1)
	notices.setNow(func() time.Time { return now })

	var errOut strings.Builder
	rec := &fwdRecorder{}
	recs := refusalLimits{notices: noticeWriter{out: &errOut, limits: notices}}.recorders(rec)
	refuse := func() {
		refuseUnroutable(ctx, refusalForwardParams(verifiedSession("s"), false, strictAuditState{}),
			recs, verifiedSession("s"), msg, unroutableFramingNotification)
	}
	for range frames {
		refuse()
	}

	assert.Len(t, rec.records, frames,
		"the RECORD is exempt by declaration: a verdict elided is a verdict an incident responder does not have, so every refused frame still reaches the tape")
	lines := strings.Count(errOut.String(), "\n")
	assert.LessOrEqual(t, lines, perClassNoticeBurst,
		"the notice must be bounded: one write syscall per refused frame is what a peer looping an unmapped method drives for free")
	assert.Positive(t, lines, "a bucket that never admits is not bounding the notice, it is silencing it")

	// A refill: the next admitted line must name what it stood in for, so an operator watching
	// stderr sees the RATE rather than a handful of lines and no sign of a flood.
	now = now.Add(time.Second)
	errOut.Reset()
	refuse()
	assert.Contains(t, errOut.String(), "further traffic diagnostics suppressed",
		"an elided notice folds into the next admitted one, naming the CLASS it spans; losing the count would under-state the flood")
	assert.NotContains(t, errOut.String(), "such",
		"one bucket serves every line of a class, so the count may not be claimed as a tally of the message it rides on")
}

// TestRoutingRefusal_NoNoticeBucketWritesEveryLine pins the other side of that bound: nil is the
// UNBOUNDED disposition, which is what a proxy assembled by a bare struct literal gets and what
// every leg had before the bucket existed. A nil that silently suppressed instead would hide the
// refusal from an operator running a test proxy.
func TestRoutingRefusal_NoNoticeBucketWritesEveryLine(t *testing.T) {
	t.Parallel()
	var errOut strings.Builder
	recs := refusalLimits{notices: noticesTo(&errOut)}.recorders(&fwdRecorder{})
	for range 20 {
		refuseUnroutable(revisionContext(handshakeRevision),
			refusalForwardParams(verifiedSession("s"), false, strictAuditState{}),
			recs, verifiedSession("s"), mcp.RPCMsg{JSONRPC: "2.0", Method: "x/bogus"}, unroutableFramingNotification)
	}
	assert.Equal(t, 20, strings.Count(errOut.String(), "\n"))
}

// TestUpstreamlessLeg_ObserveCannotDowngradeIntoAFabricatedOutage is the regression for the
// substituted upstream sink.
//
// "A message no routing table can route is never forwarded" was made structural by replacing the
// caller's sink with a stub that FAILED on use. But the core's only consumer of that stub is the
// observe arm, where a failure is not "nothing happened" — it is recordUpstreamFailure, which
// classifies through upstreamErrInfo's default arm and writes an UPSTREAM_ERROR deny for an
// upstream that was never contacted. On an --audit route that is a fabricated outage on the
// tamper-evident tape, plus a -32603 to the host in place of the routing denial.
//
// Driven with a DOWNGRADABLE denial, which is the world the routing refusal would enter if its code
// were ever reclassified — the scenario the substitution was supposed to survive.
func TestUpstreamlessLeg_ObserveCannotDowngradeIntoAFabricatedOutage(t *testing.T) {
	t.Parallel()
	rec := &fwdRecorder{}
	// audit:true and a downgradable denial: every condition for the observe forward but an upstream.
	fp := forwardParams{rec: rec, audit: true, sessionID: "s", limits: refusalLimits{notices: noticesTo(io.Discard)}}
	dec := capability.EnforceResponse{
		Decision: capability.DecisionDeny,
		Denial:   &capability.DenialInfo{Code: capability.ErrCodeCapabilityDenied},
	}
	require.True(t, dec.Denial.Downgradable(), "the premise: this denial WOULD be downgraded on a leg that could forward")

	resp := enforcedForwardCore(revisionContext(handshakeRevision), fp,
		mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "x/bogus"}, dec, "x/bogus", "x/bogus", "x/bogus", "method", false, nil)

	require.Len(t, rec.records, 1, "one refusal, one record: an upstream that was never contacted may not also produce a transport-failure deny")
	assert.Equal(t, capability.ErrCodeCapabilityDenied, rec.records[0].code,
		"the refusal must keep the code naming the REAL cause, not one blaming an upstream nothing reached")
	assert.False(t, rec.records[0].auditOnly,
		"an observe downgrade IS a forward, so a leg with nothing to forward through must not record one as observed-and-forwarded")
	require.NotNil(t, resp.Error)
	assert.NotEqual(t, jsonRPCCodeInternalError, resp.Error.Code,
		"the host must get the refusal's own denial, not the -32603 an upstream transport failure produces")
}

// TestUpstreamlessLeg_AnAllowRefusesRatherThanNilCalling is the mode's other arm. No in-tree caller
// produces an allow with no upstream — the one upstream-less caller always denies — but a nil call
// here would be a crash where the honest answer is a fail-closed refusal naming the wiring fault.
func TestUpstreamlessLeg_AnAllowRefusesRatherThanNilCalling(t *testing.T) {
	t.Parallel()
	rec := &fwdRecorder{}
	fp := forwardParams{rec: rec, sessionID: "s", limits: refusalLimits{notices: noticesTo(io.Discard)}}
	resp := enforcedForwardCore(revisionContext(handshakeRevision), fp,
		mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsCall},
		capability.EnforceResponse{Decision: capability.DecisionAllow},
		capability.MethodToolsCall, "t", "t", "tool", false, func(context.Context, mcp.RPCMsg) map[string]interface{} { return nil })

	require.Len(t, rec.records, 1)
	assert.Equal(t, "deny", rec.records[0].decision)
	assert.Equal(t, capability.ErrCodeEnforcementError, rec.records[0].code,
		"a wiring fault must be recorded as one, never as a transport failure of an upstream that was never contacted")
	require.NotNil(t, resp.Error)
}

// TestFoldDecisionDetail_HandsOverAMapNoRecorderWillMutate is the precondition for the merge this
// path skips.
//
// mergeAuditDetails always allocates because its result is routinely EXTENDED by its caller; the
// hard-deny arm's is not — it goes straight to a recorder — so folding a nil annotation into the
// engine's one-key denial map to produce an identical one-key map is pure cost on the cheapest
// refusal a peer can drive. Skipping it hands the engine's own map to the recorder chain, which is
// only safe while nothing in that chain writes into what it is given: the sink bounds and
// deep-clones before enqueue, and the rollup wrapper — the one recorder that stamps its own keys —
// must copy first.
func TestFoldDecisionDetail_HandsOverAMapNoRecorderWillMutate(t *testing.T) {
	t.Parallel()
	engineOwned := map[string]interface{}{"argument": "path"}
	rec := &fwdRecorder{}
	fp := forwardParams{rec: rolledUpRecorder{auditRecorder: rec, suppressed: 3}, sessionID: "s", limits: refusalLimits{notices: noticesTo(io.Discard)}}
	dec := capability.EnforceResponse{
		Decision: capability.DecisionDeny,
		Denial:   &capability.DenialInfo{Code: capability.ErrCodeCapabilityDenied, Details: engineOwned},
	}
	enforcedForwardCore(revisionContext(handshakeRevision), fp,
		mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "x/bogus"}, dec, "x/bogus", "x/bogus", "x/bogus", "method", false, nil)

	assert.Equal(t, map[string]interface{}{"argument": "path"}, engineOwned,
		"a recorder wrapper wrote into the engine's own denial map; the tape would then claim the engine reported keys it never set")
	require.Len(t, rec.records, 1)
	assert.Equal(t, uint64(3), rec.records[0].details[detailSuppressedRefusalCount],
		"the rollup must still reach the record it rides on — copying must not mean dropping")
}

// transportLegConstants reads every `xxx transportLeg = "..."` declaration out of the package's
// non-test sources, so the vocabulary guard checks the set the code actually declares.
func transportLegConstants(t *testing.T) map[string]transportLeg {
	t.Helper()
	out := map[string]transportLeg{}
	for name, value := range declaredStringConstants(t, "transportLeg") {
		out[name] = transportLeg(value)
	}
	require.NotEmpty(t, out, "no transportLeg constants found; this guard would pass vacuously")
	return out
}

// TestTransportLeg_IsOneClosedVocabulary settles what the `transport` audit detail is.
//
// It was written from three unrelated sources: a typed enum for the kill drops, a second typed enum
// for the server-request drops, and a bare string parameter for the session gates. Each enum kept
// its OWN spelling honest and none of them kept the FIELD honest — nothing stopped two of them
// minting the same value for different legs, and an operator's SIEM filter had no single set to
// match against. "sse-get" was already spelled twice.
//
// Two halves: the declared values are distinct, and nothing writes the key except through the one
// constant — which is what stops a fourth producer appearing with a vocabulary of its own.
func TestTransportLeg_IsOneClosedVocabulary(t *testing.T) {
	t.Parallel()
	seen := map[transportLeg]string{}
	for name, leg := range transportLegConstants(t) {
		assert.NotEmpty(t, string(leg), "transportLeg constant %s is empty; an empty `transport` detail names no leg", name)
		if prior, dup := seen[leg]; dup {
			t.Errorf("transportLeg constants %s and %s both spell %q; one value must mean one leg, or a filter on `transport` conflates two drop sites", prior, name, leg)
		}
		seen[leg] = name
	}

	// Every package that builds a details map reaching an audit record, not just this one. The
	// engine's denial.Details is stamped onto a record by the transport, so a `transport` key
	// written in pkg/enforcement would land in the same field with a vocabulary of its own and be
	// invisible to a walk scoped here — the reach its sibling guard (the flow discriminator's) has
	// had all along, on the same class of field.
	//
	// Matched only in KEY position, which is what makes the wider walk possible at all: `transport`
	// is an ordinary word in the config layer (the gateway's own `transport: http`), and a
	// bare-literal walk over five packages would report those. A struct tag is a literal in neither
	// position, so it is not a false positive either.
	scanned := 0
	for _, dir := range detailKeyScanDirs {
		for _, src := range packageSourcesIn(t, dir) {
			scanned++
			ast.Inspect(src.file, func(n ast.Node) bool {
				var key ast.Expr
				switch node := n.(type) {
				case *ast.KeyValueExpr:
					key = node.Key
				case *ast.IndexExpr:
					key = node.Index
				default:
					return true
				}
				lit, isLit := key.(*ast.BasicLit)
				if !isLit || lit.Kind != token.STRING {
					return true
				}
				if value, err := strconv.Unquote(lit.Value); err != nil || value != detailTransport {
					return true
				}
				t.Errorf("%s:%d writes the %q details key as a literal; use the transport package's detailTransport constant so the field and its transportLeg vocabulary stay edited together",
					src.path, src.fset.Position(lit.Pos()).Line, detailTransport)
				return true
			})
		}
	}
	// Without this the guard degrades silently to covering nothing if a scanned package moves —
	// the same quiet, nothing-fails failure the closed vocabulary exists to prevent.
	require.Greater(t, scanned, 40, "the transport-vocabulary scan covered too few files to be meaningful")
}

// TestServerReqTracker_TrackIsOnlyReachedThroughTheDisposingWrapper pins an invariant the compiler
// cannot.
//
// An entry leaving the tracker without a host reply must have its initiator answered, or the
// upstream blocks on a request nothing can complete. track DELIVERS on that by RETURNING what it
// displaced and leaving the answering to trackServerRequest — and Go does not require a return
// value to be consumed, so `t.serverReqs.track(msg, errOut)` compiles, drops the displaced entry on
// the floor, and reintroduces the exact hang, with no compiler error, no lint and no test.
//
// Today it holds because trackServerRequest is the only caller. That is a fact about the package as
// it stands, not a rule, until it is asserted here.
func TestServerReqTracker_TrackIsOnlyReachedThroughTheDisposingWrapper(t *testing.T) {
	t.Parallel()
	const disposer = "trackServerRequest"
	found := 0
	for _, src := range packageSources(t) {
		for _, decl := range src.file.Decls {
			fnDecl, isFunc := decl.(*ast.FuncDecl)
			if !isFunc || fnDecl.Body == nil {
				continue
			}
			// Every SELECTOR named track, not only one in call position: `f := reqs.track` followed
			// by `f(msg, errOut)` is an assignment over a selector and a call over an identifier, so
			// a call-shaped guard sees neither half and the displaced entry is dropped on the floor.
			ast.Inspect(fnDecl.Body, func(n ast.Node) bool {
				sel, isSel := n.(*ast.SelectorExpr)
				if !isSel || sel.Sel.Name != "track" {
					return true
				}
				found++
				if fnDecl.Name.Name != disposer {
					t.Errorf("%s:%d: %s reaches %s, but only %s disposes of what it returns — a displaced entry dropped here strands its initiator with the upstream blocked on it forever",
						src.name, src.fset.Position(sel.Pos()).Line, fnDecl.Name.Name, exprText(src.fset, sel), disposer)
				}
				return true
			})
		}
	}
	require.Positive(t, found, "no call to the tracker's track was found in any non-test file; this guard would pass vacuously")
}

// TestServerRequestLegs_AnswerThroughTheNilWriterSeam is the source half of the nil-writer rule.
//
// serverRequestUnblocker exists because a nil CONCRETE writer handed to a shared parameter is a
// non-nil interface that panics on use rather than the "no upstream to answer" case each caller
// tests for — and three sites went on building the unguarded literal anyway, feeding the same sink
// from the other direction. (*mcp.MsgWriter).Write locks its mutex on a nil receiver, and on the
// denial arms that panic lands AFTER the audit record, leaving a tape recording a denial the
// process died delivering.
//
// The guard is now STRUCTURAL rather than a provenance walk: the two params structs hold the
// unblocker itself, so there is no writer field for a bare closure to be assigned to. What this
// checks is that no struct grows one back, plus the half that cannot be made structural — that
// initiatorWriter, which sees through the typed-nil trap, is called from the one method that
// DECIDES the nil answer and from nowhere else.
func TestServerRequestLegs_AnswerThroughTheNilWriterSeam(t *testing.T) {
	t.Parallel()
	const resolver = "writeUpstream"
	resolvers, structs := 0, 0
	for _, src := range packageSources(t) {
		for _, decl := range src.file.Decls {
			if fnDecl, isFunc := decl.(*ast.FuncDecl); isFunc && fnDecl.Body != nil {
				ast.Inspect(fnDecl.Body, func(n ast.Node) bool {
					if !isCallTo(n, "initiatorWriter") {
						return true
					}
					resolvers++
					if fnDecl.Name.Name != resolver {
						t.Errorf("%s:%d: %s resolves the upstream sink itself; the nil answer is decided once, in the unblocker's %s, and every other site takes it from there",
							src.name, src.fset.Position(n.Pos()).Line, fnDecl.Name.Name, resolver)
					}
					return true
				})
			}
			// A struct carrying a raw `func(mcp.RPCMsg) error` is a field a caller can fill with a
			// closure over a concrete writer — the exact shape that panicked past the audit record.
			// Carry the unblocker instead; it answers AND reports.
			ast.Inspect(decl, func(n ast.Node) bool {
				st, isStruct := n.(*ast.StructType)
				if !isStruct || st.Fields == nil {
					return true
				}
				structs++
				for _, field := range st.Fields.List {
					if !isMsgWriterFuncType(field.Type) {
						continue
					}
					t.Errorf("%s:%d: a struct field of type %s lets a leg be wired with a bare closure over a concrete writer; hold a serverRequestUnblocker, which decides the nil answer once and records an answer that did not land",
						src.name, src.fset.Position(field.Pos()).Line, exprText(src.fset, field.Type))
				}
				return true
			})
		}
	}
	require.Positive(t, resolvers, "no initiatorWriter call was found; the single-decider half is matching on a name nothing calls")
	require.Positive(t, structs, "no struct declaration was found in any non-test file; the field guard would pass vacuously")
}

// TestServerRequestLegs_HoldNoSinkBesideTheirUnblocker is the same rule one field over, and the
// structural half of it: a struct carrying a serverRequestUnblocker already holds this leg's TAPE
// (report.recs), so a recorder field beside it is a SECOND, independently-wired copy of one thing.
//
// Nothing was wrong while both production constructors filled the two from the same route — which is
// exactly the shape this package refuses elsewhere: a hand-built params struct that fills one splits
// the leg's records across two tapes, silently, with every other guard still green. One of the two
// copies also reached through s.route without a nil check, where the wiring it duplicated is
// route-nil tolerant.
//
// Structural rather than a provenance walk, for the reason the nil-writer guard above is: there is
// now no field to fill, and this fails the build for a struct that grows one back.
func TestServerRequestLegs_HoldNoSinkBesideTheirUnblocker(t *testing.T) {
	t.Parallel()
	legs := 0
	for _, src := range packageSources(t) {
		for _, decl := range src.file.Decls {
			ast.Inspect(decl, func(n ast.Node) bool {
				st, isStruct := n.(*ast.StructType)
				if !isStruct || st.Fields == nil || !hasFieldOfType(st, "serverRequestUnblocker") {
					return true
				}
				legs++
				for _, field := range st.Fields.List {
					if ident, isIdent := field.Type.(*ast.Ident); !isIdent || ident.Name != "auditRecorder" {
						continue
					}
					t.Errorf("%s:%d: this struct carries an %s beside its serverRequestUnblocker, which already holds the leg's tape; derive it (see serverRequestParams.recorder) rather than wiring a second copy that a hand-built literal can point at a different tape",
						src.name, src.fset.Position(field.Pos()).Line, exprText(src.fset, field.Type))
				}
				return true
			})
		}
	}
	require.Positive(t, legs, "no struct carrying a serverRequestUnblocker was found in any non-test file; this guard would pass vacuously")
}

// hasFieldOfType reports whether st declares a field of the named package-local type.
func hasFieldOfType(st *ast.StructType, name string) bool {
	for _, field := range st.Fields.List {
		if ident, isIdent := field.Type.(*ast.Ident); isIdent && ident.Name == name {
			return true
		}
	}
	return false
}

// isMsgWriterFuncType reports whether e spells `func(mcp.RPCMsg) error`, the writer shape a leg must
// take from an unblocker rather than hold itself.
func isMsgWriterFuncType(e ast.Expr) bool {
	fn, isFunc := e.(*ast.FuncType)
	if !isFunc || fn.Params == nil || fn.Results == nil || len(fn.Params.List) != 1 || len(fn.Results.List) != 1 {
		return false
	}
	param, isSel := fn.Params.List[0].Type.(*ast.SelectorExpr)
	if !isSel || param.Sel.Name != "RPCMsg" {
		return false
	}
	result, isIdent := fn.Results.List[0].Type.(*ast.Ident)
	return isIdent && result.Name == "error"
}

// isCallTo reports whether n is a call of the named package-level function.
func isCallTo(n ast.Node, name string) bool {
	call, isCall := n.(*ast.CallExpr)
	if !isCall {
		return false
	}
	fn, isIdent := call.Fun.(*ast.Ident)
	return isIdent && fn.Name == name
}

// TestServerRequestLegs_NilWriterReportsRatherThanPanics is the behavioral half, on the two shapes
// the source guard covers: a denial that must answer its initiator, and the pool's saturation
// refusal. Both call the sink AFTER their audit record, so a panic here is strictly worse than a
// lost answer.
func TestServerRequestLegs_NilWriterReportsRatherThanPanics(t *testing.T) {
	t.Parallel()
	var errOut strings.Builder
	rec := &fwdRecorder{}
	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "roots/list"}

	// The pool's saturation path: fill every slot, then dispatch one more with no upstream sink.
	pool := &serverRequestPool{}
	block := make(chan struct{})
	defer close(block)
	for range maxConcurrentServerRequests {
		pool.dispatch(context.Background(), msg, serverRequestDispatch{
			handle: func(context.Context, mcp.RPCMsg) { <-block },
		})
	}
	// A nil write func is the leg with NO upstream sink at all — the case the seam reports rather
	// than nil-calls. errOut rides the unblocker, which is what writes the report.
	sinkless := answeringSeam(nil, rec, httpServerRequestLegs, &errOut)
	require.NotPanics(t, func() {
		pool.dispatch(context.Background(), msg, serverRequestDispatch{sessionID: "s", unblocker: sinkless})
	}, "the saturation refusal must report a missing upstream sink, not panic on a nil concrete writer")
	assert.Contains(t, errOut.String(), "no upstream writer to answer it")

	// A policy hard deny on the sampling leg, which answers its initiator unconditionally.
	errOut.Reset()
	require.NotPanics(t, func() {
		forwardServerRequest(revisionContext(handshakeRevision),
			mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`2`), Method: capability.MethodSamplingCreateMessage},
			serverRequestParams{sessionID: "s", pdp: pdp.DenyAllPDP{},
				unblocker: answeringSeam(nil, rec, stdioServerRequestLegs, &errOut)})
	}, "a denial that answers its initiator must report a missing upstream sink, not panic after writing its record")
	assert.Contains(t, errOut.String(), "no upstream writer to answer it")
}

// TestServerRequestRefusal_DestroyedAnswerReachesTheTape is the regression for the four denial arms
// that answered a blocked initiator and threw the delivery report away.
//
// The refusal record each of them writes describes the REFUSAL, not the delivery — so an operator
// reconstructing a wedged upstream could not tell "denied and told so" from "denied and the upstream
// never heard". The reachable failure is not the unreachable absent sink: an upstream subprocess
// that dies mid-denial EPIPEs the write, which poisons no writer and tears nothing down, so there is
// no other trace at all.
//
// Driven with a FAILING writer (not a nil one) for exactly that reason, and asserted on both shapes
// that take such a refusal: the sampling leg's policy deny and the pool's saturation refusal.
func TestServerRequestRefusal_DestroyedAnswerReachesTheTape(t *testing.T) {
	t.Parallel()
	broken := func(mcp.RPCMsg) error { return errors.New("write: broken pipe (test probe)") }
	samplingReq := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`2`), Method: capability.MethodSamplingCreateMessage}

	t.Run("policy deny", func(t *testing.T) {
		t.Parallel()
		rec := &fwdRecorder{}
		forwardServerRequest(revisionContext(handshakeRevision), samplingReq, serverRequestParams{
			sessionID: "s", pdp: pdp.DenyAllPDP{},
			unblocker: answeringSeam(broken, rec, stdioServerRequestLegs, io.Discard),
		})
		require.Len(t, rec.records, 2, "a destroyed answer is a second fact about the request, and the refusal's own record does not carry it")
		assertRefusalDropRecord(t, rec.records[1], dropStdioRefusalUndeliverable)
	})

	t.Run("pool saturation", func(t *testing.T) {
		t.Parallel()
		rec := &fwdRecorder{}
		pool, block := &serverRequestPool{}, make(chan struct{})
		defer close(block)
		for range maxConcurrentServerRequests {
			pool.dispatch(context.Background(), samplingReq, serverRequestDispatch{
				handle: func(context.Context, mcp.RPCMsg) { <-block },
			})
		}
		pool.dispatch(context.Background(), samplingReq, serverRequestDispatch{
			sessionID: "s",
			unblocker: answeringSeam(broken, rec, httpServerRequestLegs, io.Discard),
		})
		require.Len(t, rec.records, 2, "the saturation refusal has the same shape and the same gap")
		assert.Equal(t, codeResourceExhausted, rec.records[0].code)
		assertRefusalDropRecord(t, rec.records[1], dropHTTPRefusalUndeliverable)
	})

	// The control: an answer that LANDS writes one record, so the drop is reported on the outcome
	// of the write rather than on every refusal.
	t.Run("delivered", func(t *testing.T) {
		t.Parallel()
		rec := &fwdRecorder{}
		forwardServerRequest(revisionContext(handshakeRevision), samplingReq, serverRequestParams{
			sessionID: "s", pdp: pdp.DenyAllPDP{},
			unblocker: answeringSeam(func(mcp.RPCMsg) error { return nil }, rec, stdioServerRequestLegs, io.Discard),
		})
		assert.Len(t, rec.records, 1, "a refusal the initiator received is one event, not two")
	})
}

// assertRefusalDropRecord checks the shape of the tape's account of an answer that never landed.
func assertRefusalDropRecord(t *testing.T, got fwdCapturedRecord, leg transportLeg) {
	t.Helper()
	assert.Equal(t, "deny", got.decision)
	assert.Equal(t, capability.ErrCodeEnforcementError, got.code,
		"the record states the proxy failed the request, which is what an append-only tape can say about it")
	assert.Equal(t, string(leg), got.details[detailTransport],
		"the record must name the answering site, so a destroyed refusal is distinguishable from an undelivered forward")
	assert.Empty(t, got.identifier,
		"sampling/createMessage resolves a policy target, so naming it here would stamp one onto a record no PDP produced")
}

// TestServerRequestAnswer_DiagnosticIsBoundedAtTheSeam is the other half of the destroyed answer.
//
// The record got a bucket; the stderr line beside it did not, on the very leg whose flood the bucket
// was added for — an upstream that closes its stdin and keeps emitting requests fails every answer,
// so an unbounded line there is one write syscall per frame at the upstream's rate. It is bounded at
// writeToInitiator rather than at any one caller, because that is the seam all nine answering sites
// funnel through and a bound on one caller is a bound the next site added does not inherit.
func TestServerRequestAnswer_DiagnosticIsBoundedAtTheSeam(t *testing.T) {
	t.Parallel()
	var errOut strings.Builder
	broken := func(mcp.RPCMsg) error { return errors.New("write: broken pipe (test probe)") }
	u := serverRequestUnblocker{
		reqs: &serverReqTracker{}, sink: sinkFunc(broken),
		notices: noticeWriter{out: &errOut, limits: newNoticeLimiter(1)},
		report:  dropReport{recs: refusalLimits{}.recorders(nil)},
	}
	for range 200 {
		u.write(mcp.RPCMsg{}, "test probe")
	}
	lines := strings.Count(errOut.String(), "\n")
	assert.LessOrEqual(t, lines, perClassNoticeBurst,
		"a dead upstream sink fails every answer; unbounded, that is one write syscall per frame at the peer's rate")
	assert.Positive(t, lines, "a bucket that never admits is not bounding the diagnostic, it is silencing it")
}

// TestServerRequestForward_UntrackableIDIsRefusedNotForwarded is the fail-closed half of the
// tracker's own bound.
//
// track refuses an over-cap id, but its refusal shares the `false` that means "displaced nothing",
// so trackServerRequest could not tell them apart and both forward paths delivered to the host
// anyway — the host answers, both routing arms drop that answer as untracked, and the upstream
// blocks with nothing on the tape. Strictly worse than the retention the bound exists to prevent.
func TestServerRequestForward_UntrackableIDIsRefusedNotForwarded(t *testing.T) {
	t.Parallel()
	over := json.RawMessage(`"` + strings.Repeat("x", maxTrackedServerReqIDBytes) + `"`)
	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: &over, Method: "roots/list"}

	var delivered int
	sess := newTestSession(&httpSession{
		id: "s", route: &UpstreamRoute{name: "up1"}, proxy: newTestHTTPProxy(), done: make(chan struct{}),
	})
	sub := make(chan mcp.RPCMsg, 1)
	require.True(t, sess.addSub(sub))
	ok := sess.broadcastServerRequest(context.Background(), msg)
	delivered = len(sub)

	assert.Equal(t, forwardRefused, ok,
		"a request whose reply could never be routed is REFUSED, not merely undelivered: this leg wrote its own record, and reporting it as undelivered files a second one naming a host that was never asked")
	assert.Zero(t, delivered, "and must not reach the host at all: its answer would be dropped as untracked")
	assert.False(t, sess.serverReqs.tracked(mcp.MsgKey(&over)))
}

// TestServerRequestForward_StdioRecordsWhatItActuallyDid is the stdio leg's forward asked about the
// TAPE: what it reports is what recordForwardOutcome writes, so each of its three answers must
// produce exactly the records that answer earns.
//
// stdio used to hand that leg a closure reporting delivered unconditionally, so the refusing branch
// — which forwards nothing and writes its own attributed drop — also filed an ALLOW saying the host
// had the request. Reporting it merely "undelivered" is not the fix either: that files a second,
// site-less deny for one refusal, under a category whose declaration names a host that was never
// asked. Driven through handleUpstreamRequest rather than the method, because the WIRING is the
// subject: a closure answering a constant passes any assertion made on the method alone.
func TestServerRequestForward_StdioRecordsWhatItActuallyDid(t *testing.T) {
	t.Parallel()
	over := json.RawMessage(`"` + strings.Repeat("x", maxTrackedServerReqIDBytes) + `"`)

	t.Run("refused writes one attributed record and no allow", func(t *testing.T) {
		t.Parallel()
		rec := &fwdRecorder{}
		p, host := newStdioProxy(stdioServe{setup: recordingTo(rec)}, strings.NewReader(""))

		p.handleUpstreamRequest(revisionContext(handshakeRevision),
			mcp.RPCMsg{JSONRPC: "2.0", ID: &over, Method: "roots/list"})

		assert.Empty(t, host.messages, "the refusing branch forwards nothing; an answer to it could not be routed back")
		require.Len(t, rec.records, 1,
			"one refusal, one record: the forward already wrote its own, so the leg above must not file a second")
		assert.Equal(t, "deny", rec.records[0].decision,
			"a refusal may not also write an allow claiming the host received the request")
		assert.Equal(t, string(dropStdioUnroutableID), rec.records[0].details[detailTransport],
			"and the one record must be the attributed one — a bare ENFORCEMENT_ERROR names no site to join on")
	})

	// The other two answers, on an id the tracker retains. A failing host writer is the one
	// not-delivered case stdio can actually reach: it is NOT fire-and-forget (Write returns the
	// error) and NOT bounded by the poison teardown, which only a PARTIAL write latches.
	t.Run("a failed host write is undelivered, not allowed", func(t *testing.T) {
		t.Parallel()
		rec := &fwdRecorder{}
		var upstream []mcp.RPCMsg
		p, _ := newStdioProxy(stdioServe{
			upSink: sinkFunc(func(m mcp.RPCMsg) error { upstream = append(upstream, m); return nil }),
			setup:  recordingTo(rec),
		}, strings.NewReader(""))
		p.hostWriter = mcp.NewMsgWriter(&failingWriter{})

		p.handleUpstreamRequest(revisionContext(handshakeRevision),
			mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`4`), Method: "roots/list"})

		require.Len(t, rec.records, 1)
		assert.Equal(t, "deny", rec.records[0].decision,
			"a frame the host writer refused never reached the host; recording an allow for it is the lie this leg exists to prevent")
		assert.Equal(t, capability.ErrCodeEnforcementError, rec.records[0].code)
		require.Len(t, upstream, 1, "and the initiator is answered on the upstream's own sink, which a broken stdout says nothing about")
		assert.NotNil(t, upstream[0].Error)
	})

	t.Run("a written frame is delivered", func(t *testing.T) {
		t.Parallel()
		rec := &fwdRecorder{}
		p, host := newStdioProxy(stdioServe{setup: recordingTo(rec)}, strings.NewReader(""))

		p.handleUpstreamRequest(revisionContext(handshakeRevision),
			mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`5`), Method: "roots/list"})

		require.Len(t, host.messages, 1, "the control: an ordinary forward still reaches the host")
		require.Len(t, rec.records, 1)
		assert.Equal(t, "allow", rec.records[0].decision)
	})
}

// recordingTo injects rec as the proxy's audit recorder, so a test asserting on record SHAPE needs
// no on-disk sink (StdioProxy.rec() returns nil without one, and reading a real tape back costs a
// key-file create plus three fsyncs per case).
func recordingTo(rec auditRecorder) func(*StdioProxy) {
	return func(p *StdioProxy) {
		p.recOnce.Do(func() {})
		p.recCached = rec
	}
}

// TestServerRequestRefusal_DestroyedAnswerRecordIsMetered bounds a record the UPSTREAM drives: an
// upstream that closes its stdin and keeps emitting requests on stdout has every one of them
// refused and every answer destroyed, at its own send rate, with no host and no tracking involved.
func TestServerRequestRefusal_DestroyedAnswerRecordIsMetered(t *testing.T) {
	t.Parallel()
	rec := &fwdRecorder{}
	fp := serverRequestParams{
		sessionID: "s", pdp: pdp.DenyAllPDP{},
		unblocker: answeringSeam(func(mcp.RPCMsg) error { return errors.New("write: broken pipe (test probe)") },
			rec, stdioServerRequestLegs, io.Discard),
	}
	drops := 0
	for range 200 {
		rec.records = nil
		forwardServerRequest(revisionContext(handshakeRevision),
			mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`2`), Method: capability.MethodSamplingCreateMessage}, fp)
		require.NotEmpty(t, rec.records, "the policy DENY is a verdict and is never metered")
		drops += len(rec.records) - 1
	}
	assert.LessOrEqual(t, drops, perCategoryDenyBurstSize+1,
		"a sustained flood of destroyed answers must be bounded by its own bucket")
	assert.Positive(t, drops, "the leading edge of the flood must still reach the tape")
}

// TestHostServerReply_DestroyedWithNoUpstreamWriterReachesTheTape is the regression for the one
// disposition on this leg with no tape entry.
//
// Both transports CONSUME the tracked id before they know whether they can relay, and the take is
// what makes the reply unroutable by any later path — deliberately, since an entry nothing can
// reclaim eventually displaces a live request. With no upstream writer the relay then prints a
// stderr line and returns: the upstream's request is permanently unanswerable AND permanently
// unattributable, and this is the drop that destroys a reply the host actually produced.
//
// Every sibling disposition (undelivered, displaced, the deliberate kill drop) appends a record.
// Asserted on both transports, since "reported rather than dropped" being the rule on one and not
// the other for an identical condition is what the shared seam exists to prevent.
func TestHostServerReply_DestroyedWithNoUpstreamWriterReachesTheTape(t *testing.T) {
	t.Parallel()
	reply := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`7`), Result: json.RawMessage(`{}`)}

	t.Run("http", func(t *testing.T) {
		t.Parallel()
		sink, logPath := newTempAuditSink(t)
		route := &UpstreamRoute{name: "up1", sink: &routeSink{sink: sink, upstream: "up1"}}
		proxy := newTestHTTPProxy()
		proxy.stderr = io.Discard
		sess := newTestSession(&httpSession{id: "s", route: route, proxy: proxy, done: make(chan struct{})})
		// The proxy issued this server-initiated request, so the host's reply IS routable — and
		// remote-upstream mode leaves no sink to route it through.
		_, _ = sess.serverReqs.track(mcp.RPCMsg{ID: mcp.RawJSON(`7`), Method: capability.MethodSamplingCreateMessage}, io.Discard)
		require.Nil(t, sess.upWriter, "the premise: remote-upstream mode has no upstream sink")

		require.True(t, proxy.routeHostServerResponse(revisionContext(handshakeRevision), route, sess, noKill, reply))
		_ = sink.Close()

		rec := findAuditRecordByMethod(readAuditRecords(t, logPath), methodLabelServerResponse, "deny")
		require.NotNil(t, rec, "a host reply the proxy destroyed left nothing on the tape; a stderr line is not something a SIEM sees")
		assertDroppedReplyRecord(t, rec, dropHTTPReplyUndeliverable)
	})

	t.Run("stdio", func(t *testing.T) {
		t.Parallel()
		sink, logPath := newTempAuditSink(t)
		serveHostMessages(t, stdioServe{sink: sink, setup: func(p *StdioProxy) {
			p.upWriter = nil
			_, _ = p.serverReqs.track(mcp.RPCMsg{ID: mcp.RawJSON(`7`), Method: capability.MethodSamplingCreateMessage}, io.Discard)
		}}, reply)
		_ = sink.Close()

		rec := findAuditRecordByMethod(readAuditRecords(t, logPath), methodLabelServerResponse, "deny")
		require.NotNil(t, rec, "the stdio leg must record the same destroyed reply its HTTP twin does")
		assertDroppedReplyRecord(t, rec, dropStdioReplyUndeliverable)
	})
}

// assertDroppedReplyRecord checks the shape shared by both transports' destroyed-reply records.
func assertDroppedReplyRecord(t *testing.T, rec map[string]interface{}, leg transportLeg) {
	t.Helper()
	assert.Equal(t, capability.ErrCodeEnforcementError, rec["denial_code"],
		"the record states the proxy failed the request, which is what an append-only tape can say about it")
	details, _ := rec["details"].(map[string]interface{})
	assert.Equal(t, string(leg), details[detailTransport],
		"the record must name the drop site, so a destroyed reply is distinguishable from an undelivered broadcast")
}

// TestServerRequestAdmission_RefusesAnIDLargerThanTheTrackerRetains bounds what the tracker HOLDS.
//
// Each entry retains the raw id bytes plus the canonical key derived from them, both off the
// upstream's 4 MiB-per-message reader, and the set holds maxTrackedServerReqs of them until a host
// reply or teardown. Truncating the id would leave it unable to answer the initiator it was kept
// for or to index the reply it was kept to match, so an over-cap id makes the request unroutable
// instead — answered and recorded ONCE, at this leg's entry.
//
// At the ENTRY rather than at the tracker, which is what keeps it to one record and one decision:
// refusing further down let the leg below write its own not-delivered deny for the same request
// (unmetered, and naming a cause that never happened), and on the sampling path it burned a
// maxCalls slot on a decision for a call the host never saw.
func TestServerRequestAdmission_RefusesAnIDLargerThanTheTrackerRetains(t *testing.T) {
	t.Parallel()
	var reqs serverReqTracker
	var written []mcp.RPCMsg
	rec := &fwdRecorder{}
	u := serverRequestUnblocker{
		reqs:    &reqs,
		sink:    sinkFunc(func(m mcp.RPCMsg) error { written = append(written, m); return nil }),
		notices: noticesTo(io.Discard),
		report:  displacementReport(rec, verifiedSession("s")),
	}
	huge := json.RawMessage(`"` + strings.Repeat("x", maxTrackedServerReqIDBytes) + `"`)

	admitted := admitServerRequestID(context.Background(), u,
		mcp.RPCMsg{JSONRPC: "2.0", ID: &huge, Method: capability.MethodSamplingCreateMessage})

	assert.False(t, admitted, "a request whose reply could never be routed must not reach the pool, the decision, or the host")
	assert.False(t, reqs.tracked(mcp.MsgKey(&huge)), "the over-cap id must not be retained; retaining it is the whole exposure")
	require.Len(t, written, 1, "the initiator must be answered rather than left blocked on a request eunox will not track")
	require.NotNil(t, written[0].Error)
	assert.Contains(t, written[0].Error.Message, "larger than the proxy's in-flight tracker retains")
	require.Len(t, rec.records, 1, "the refusal is a call the proxy actively failed, so it reaches the tape — exactly once")
	assert.Equal(t, string(dropStdioUnroutableID), rec.records[0].details[detailTransport])
	assert.Empty(t, rec.records[0].identifier,
		"sampling/createMessage resolves a policy target, so naming it here would stamp one onto the signed tape for a request no PDP saw")

	// The control: one byte under the cap is admitted and tracked as before.
	ok := json.RawMessage(`"` + strings.Repeat("x", maxTrackedServerReqIDBytes-3) + `"`)
	okMsg := mcp.RPCMsg{JSONRPC: "2.0", ID: &ok, Method: "roots/list"}
	assert.True(t, admitServerRequestID(context.Background(), u, okMsg))
	trackServerRequest(context.Background(), u, okMsg)
	assert.True(t, reqs.tracked(mcp.MsgKey(&ok)))
}

// TestServerReqTracker_RefusesAnOverCapIDItself is the same bound asked of the thing that holds the
// bytes.
//
// maxTrackedServerReqIDBytes is argued from what an ENTRY retains for its whole lifetime, and was
// enforced one layer up, at each transport's entry gate. That placement is right for the REFUSAL —
// it must precede the pool and the decision — but it left track happy to retain a 4 MiB id, so the
// retention argument in the constant's own doc was not backed by the type it describes. The gate
// keeps its early-refusal role; this is the property behind it.
func TestServerReqTracker_RefusesAnOverCapIDItself(t *testing.T) {
	t.Parallel()
	var reqs serverReqTracker
	over := json.RawMessage(`"` + strings.Repeat("x", maxTrackedServerReqIDBytes) + `"`)

	displaced, ok := reqs.track(mcp.RPCMsg{ID: &over, Method: capability.MethodSamplingCreateMessage}, io.Discard)
	assert.False(t, ok, "an over-cap id displaces nothing: it was never admitted to the set")
	assert.Zero(t, displaced)
	assert.False(t, reqs.tracked(mcp.MsgKey(&over)), "retaining the id is the whole exposure the bound exists to cap")

	// At the cap exactly, which is what keeps the refusal from being an off-by-one on every id.
	atCap := json.RawMessage(`"` + strings.Repeat("x", maxTrackedServerReqIDBytes-2) + `"`)
	_, _ = reqs.track(mcp.RPCMsg{ID: &atCap, Method: "roots/list"}, io.Discard)
	assert.True(t, reqs.tracked(mcp.MsgKey(&atCap)))
}

// TestServerReqTracker_BoundsTheRetainedMethod is the other retained field. The method is read by
// the drop record alone and the sink bounds what it writes, so it is truncated rather than refused —
// what was missing is a bound on what the TRACKER holds for an entry's whole lifetime, through the
// same audit.BoundEnvelopeField every other envelope field takes.
func TestServerReqTracker_BoundsTheRetainedMethod(t *testing.T) {
	t.Parallel()
	var reqs serverReqTracker
	huge := strings.Repeat("m", 1<<20)
	displaced, _ := reqs.track(mcp.RPCMsg{ID: mcp.RawJSON(`1`), Method: huge}, io.Discard)
	assert.Zero(t, displaced.method)

	entry, ok := reqs.ids[mcp.MsgKey(mcp.RawJSON(`1`))]
	require.True(t, ok)
	assert.Less(t, len(entry.method), len(huge),
		"the tracker must bound the method it retains: %d entries times an unbounded 4 MiB field is the exposure", maxTrackedServerReqs)
	assert.Equal(t, audit.BoundEnvelopeField(huge), entry.method,
		"bounded through the audit envelope cap, so the tracker and the record it feeds cannot disagree about the limit")
}

// TestAdmitRefusalRecord_NeverWrapsANilRecorder is the regression for a crash, not a record.
//
// A proxy with no audit sink (--require-audit=off, or an unopenable path — a shape recordRefusal
// itself calls reachable in production) still builds its limiter, so a metered site resolved a nil
// recorder against a live bucket. Past the burst, the next admitted record came back as
// rolledUpRecorder{nil}: a NON-nil interface, so every `rec != nil` guard downstream passed and the
// rollup's delegation nil-dereferenced — on a serverRequestPool goroutine, which nothing recovers,
// so the whole proxy exited.
func TestAdmitRefusalRecord_NeverWrapsANilRecorder(t *testing.T) {
	t.Parallel()
	now := time.Now()
	lim := newRefusalRecordLimiter()
	lim.setNow(func() time.Time { return now })
	for i := range perCategoryDenyBurstSize + 5 {
		require.Nil(t, admitRefusalRecord(nil, lim, catDisplaced),
			"resolution %d wrapped a nil recorder; the wrapper is a non-nil interface, so every nil guard below it passes and the delegation panics", i)
		if i == perCategoryDenyBurstSize {
			now = now.Add(10 * time.Second) // refill, so the next admit carries suppressed > 0
		}
	}
	// The whole point of the guard: a site with no tape must also spend no tokens.
	require.NotNil(t, admitRefusalRecord(&fwdRecorder{}, lim, catDisplaced),
		"a sink-less site drained the bucket it was supposed to leave for a site that has a tape")
}

// TestServerRequestAdmission_RefusalCostsOneRecordAndNoQuota pins WHERE the id refusal runs.
//
// Below the decision it produced two contradictory records — its own metered one naming the real
// cause, and the leg's unmetered not-delivered deny claiming no client accepted a request no client
// was ever offered — and it ran after the sampling decision had already committed a maxCalls slot
// for a call the host never saw, so an upstream could exhaust a session's sampling budget with
// requests it knew would be refused.
func TestServerRequestAdmission_RefusalCostsOneRecordAndNoQuota(t *testing.T) {
	t.Parallel()
	var reqs serverReqTracker
	rec := &fwdRecorder{}
	decided := 0
	u := serverRequestUnblocker{
		reqs: &reqs, sink: sinkFunc(func(mcp.RPCMsg) error { return nil }), notices: noticesTo(io.Discard),
		report: displacementReport(rec, verifiedSession("s")),
	}
	huge := json.RawMessage(`"` + strings.Repeat("x", maxTrackedServerReqIDBytes+1) + `"`)
	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: &huge, Method: capability.MethodSamplingCreateMessage}

	if admitServerRequestID(context.Background(), u, msg) {
		// Only reached if the gate admits; the decision below is what the gate exists to precede.
		decided++
		forwardServerRequest(revisionContext(handshakeRevision), msg, serverRequestParams{
			sessionID: "s", pdp: pdp.AlwaysAllowPDP{},
			forward:   func(context.Context, mcp.RPCMsg) forwardOutcome { return forwardUndelivered },
			unblocker: recordingSeam(func(mcp.RPCMsg) error { return nil }, rec),
		})
	}

	assert.Zero(t, decided, "the refusal must run above the decision: deciding first commits a quota slot for a call the host never sees")
	require.Len(t, rec.records, 1, "one refusal, one record — the leg below must not also file a not-delivered deny naming a cause that never happened")
	assert.Equal(t, string(dropStdioUnroutableID), rec.records[0].details[detailTransport])
}
