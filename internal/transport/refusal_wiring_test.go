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
	"go/ast"
	"go/token"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
		errOut:    io.Discard,
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
// bounds the pre-session KILL_SWITCH records an incident responder reads first. unmeteredRecorder
// could not see it: it returns what it is handed, and an auditRecorder carries no provenance.
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
	for i := range int(perCategoryDenyBurst) {
		assert.NotNil(t, proxy.preSessionKillRecorder(route),
			"kill record %d was suppressed: a refusal DECLARED exempt drained the bucket bounding the records an emergency stop depends on", i)
	}
}

// TestRefusalRecorders_ApplyTheDeclarationNotTheLegsDefault pins the property that makes the fix
// structural rather than a corrected call site: the resolver READS refusalDeclarations, so a
// category added later cannot be metered by a leg that meters, or exempted by one that does not,
// against what it declares.
func TestRefusalRecorders_ApplyTheDeclarationNotTheLegsDefault(t *testing.T) {
	t.Parallel()
	sink, _ := newTempAuditSink(t)
	defer func() { _ = sink.Close() }()
	proxy := newTestHTTPProxy()
	route := &UpstreamRoute{name: "up1", sink: &routeSink{sink: sink, upstream: "up1"}}
	recs := proxy.preSessionRefusalRecorders(route)

	for cat, decl := range refusalDeclarations {
		charged := 0
		// A metered category runs out; an exempt one never does.
		for range int(perCategoryDenyBurst) + 50 {
			if recs.forCategory(cat) != nil {
				charged++
			}
		}
		if decl.metering == meteringExempt {
			assert.Equal(t, int(perCategoryDenyBurst)+50, charged,
				"category %q is declared exempt but its resolved recorder was suppressed; the wiring is metering what the declaration does not", cat)
			continue
		}
		assert.LessOrEqual(t, charged, int(perCategoryDenyBurst)+1,
			"category %q is declared metered but the pre-session leg charged no bucket for it", cat)
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
	recs := routeRefusalRecorders(&UpstreamRoute{name: "up1", sink: &routeSink{sink: sink, upstream: "up1"}})
	for i := range int(perCategoryDenyBurst) + 50 {
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
	resp := refuseUnroutable(ctx, refusalForwardParams(notifRec, verifiedSession("s"), false, strictAuditState{}, io.Discard),
		verifiedSession("s"), msg, unroutableFramingNotification)
	assert.Nil(t, resp.Error, "the notification framing has no reply channel, so no denial envelope may be built for it")
	assert.Nil(t, resp.ID)
	require.Len(t, notifRec.records, 1, "skipping the response must not skip the record the refusal legitimately writes")
	assert.Equal(t, capability.ErrCodeUnroutableMethod, notifRec.records[0].code)

	// The request framing is the control: same refusal, same record, and an envelope to send.
	reqRec := &fwdRecorder{}
	reqMsg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "x/bogus"}
	resp = refuseUnroutable(ctx, refusalForwardParams(reqRec, verifiedSession("s"), false, strictAuditState{}, io.Discard),
		verifiedSession("s"), reqMsg, unroutableFramingRequest)
	require.NotNil(t, resp.Error, "the request framing must still be answered")
	require.Len(t, reqRec.records, 1)
	assert.Equal(t, notifRec.records[0].code, reqRec.records[0].code,
		"the two framings are one refusal for one reason; only the reply channel differs")
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
	fp := forwardParams{rec: rec, audit: true, sessionID: "s", errOut: io.Discard}
	dec := capability.EnforceResponse{
		Decision: capability.DecisionDeny,
		Denial:   &capability.DenialInfo{Code: capability.ErrCodeCapabilityDenied},
	}
	require.True(t, dec.Denial.Downgradable(), "the premise: this denial WOULD be downgraded on a leg that could forward")

	resp := enforcedForwardCore(revisionContext(handshakeRevision), fp, nil,
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
	fp := forwardParams{rec: rec, sessionID: "s", errOut: io.Discard}
	resp := enforcedForwardCore(revisionContext(handshakeRevision), fp, nil,
		mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsCall},
		capability.EnforceResponse{Decision: capability.DecisionAllow},
		capability.MethodToolsCall, "t", "t", "tool", false, func(mcp.RPCMsg) map[string]interface{} { return nil })

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
	fp := forwardParams{rec: rolledUpRecorder{auditRecorder: rec, suppressed: 3}, sessionID: "s", errOut: io.Discard}
	dec := capability.EnforceResponse{
		Decision: capability.DecisionDeny,
		Denial:   &capability.DenialInfo{Code: capability.ErrCodeCapabilityDenied, Details: engineOwned},
	}
	enforcedForwardCore(revisionContext(handshakeRevision), fp, nil,
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
	for _, src := range packageSources(t) {
		for _, decl := range src.file.Decls {
			gen, isGen := decl.(*ast.GenDecl)
			if !isGen || gen.Tok != token.CONST {
				continue
			}
			// A const block declares its type once, on the first spec; later specs inherit it.
			typeName := ""
			for _, spec := range gen.Specs {
				vs, isValue := spec.(*ast.ValueSpec)
				if !isValue {
					continue
				}
				if id, isIdent := vs.Type.(*ast.Ident); isIdent {
					typeName = id.Name
				}
				if typeName != "transportLeg" || len(vs.Names) != 1 || len(vs.Values) != 1 {
					continue
				}
				lit, isLit := vs.Values[0].(*ast.BasicLit)
				if !isLit || lit.Kind != token.STRING {
					continue
				}
				value, err := strconv.Unquote(lit.Value)
				require.NoError(t, err)
				out[vs.Names[0].Name] = transportLeg(value)
			}
		}
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

	for _, src := range packageSources(t) {
		ast.Inspect(src.file, func(n ast.Node) bool {
			lit, isLit := n.(*ast.BasicLit)
			if !isLit || lit.Kind != token.STRING {
				return true
			}
			value, err := strconv.Unquote(lit.Value)
			if err != nil || value != detailTransport {
				return true
			}
			// The one legitimate occurrence is the constant's own declaration.
			if src.name == "forward.go" {
				return true
			}
			t.Errorf("%s:%d writes the %q details key as a literal; use the detailTransport constant so the field and its transportLeg vocabulary stay edited together",
				src.name, src.fset.Position(lit.Pos()).Line, detailTransport)
			return true
		})
	}
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
			ast.Inspect(fnDecl.Body, func(n ast.Node) bool {
				call, isCall := n.(*ast.CallExpr)
				if !isCall {
					return true
				}
				sel, isSel := call.Fun.(*ast.SelectorExpr)
				if !isSel || sel.Sel.Name != "track" {
					return true
				}
				found++
				if fnDecl.Name.Name != disposer {
					t.Errorf("%s:%d: %s calls %s, but only %s disposes of what it returns — a displaced entry dropped here strands its initiator with the upstream blocked on it forever",
						src.name, src.fset.Position(call.Pos()).Line, fnDecl.Name.Name, exprText(src.fset, call.Fun), disposer)
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
// Every writeUpstream must therefore come from an unblocker, which decides the nil answer once.
func TestServerRequestLegs_AnswerThroughTheNilWriterSeam(t *testing.T) {
	t.Parallel()
	// The two unblocker constructors are the exception, and the only one: they are where the nil
	// answer is DECIDED (each tests its own concrete writer before wrapping it), which is exactly
	// the decision every other site must inherit rather than re-make.
	const decider = "unblocker"
	found, exempt := 0, 0
	for _, src := range packageSources(t) {
		for _, decl := range src.file.Decls {
			fnDecl, isFunc := decl.(*ast.FuncDecl)
			if !isFunc || fnDecl.Body == nil {
				continue
			}
			ast.Inspect(fnDecl.Body, func(n ast.Node) bool {
				kv, isKV := n.(*ast.KeyValueExpr)
				if !isKV {
					return true
				}
				key, isIdent := kv.Key.(*ast.Ident)
				if !isIdent || key.Name != "writeUpstream" {
					return true
				}
				if fnDecl.Name.Name == decider {
					exempt++
					return true
				}
				found++
				// The one admissible shape elsewhere: <transport>.unblocker().writeUpstream, which
				// is nil exactly when there is genuinely no upstream sink.
				if text := exprText(src.fset, kv.Value); !strings.HasSuffix(text, "unblocker().writeUpstream") {
					t.Errorf("%s:%d: %s wires writeUpstream as %s; take it from the unblocker so a missing upstream sink is REPORTED once rather than panicking at each site",
						src.name, src.fset.Position(kv.Pos()).Line, fnDecl.Name.Name, text)
				}
				return true
			})
		}
	}
	require.Positive(t, found, "no writeUpstream wiring was found outside the unblocker constructors; this guard would pass vacuously")
	require.Positive(t, exempt, "no unblocker constructor was found; the exemption above is matching on a name nothing declares")
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
	require.NotPanics(t, func() {
		pool.dispatch(context.Background(), msg, serverRequestDispatch{rec: rec, sessionID: "s", errOut: &errOut})
	}, "the saturation refusal must report a missing upstream sink, not panic on a nil concrete writer")
	assert.Contains(t, errOut.String(), "no upstream writer to answer it")

	// A policy hard deny on the sampling leg, which answers its initiator unconditionally.
	errOut.Reset()
	require.NotPanics(t, func() {
		forwardServerRequest(revisionContext(handshakeRevision),
			mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`2`), Method: capability.MethodSamplingCreateMessage},
			serverRequestParams{rec: rec, sessionID: "s", pdp: pdp.DenyAllPDP{}, errOut: &errOut})
	}, "a denial that answers its initiator must report a missing upstream sink, not panic after writing its record")
	assert.Contains(t, errOut.String(), "no upstream writer to answer it")
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

// TestServerRequestTracking_RefusesAnIDLargerThanTheTrackerRetains bounds what the tracker HOLDS.
//
// Each entry retains the raw id bytes plus the canonical key derived from them, both off the
// upstream's 4 MiB-per-message reader, and the set holds maxTrackedServerReqs of them until a host
// reply or teardown. Truncating the id would leave it unable to answer the initiator it was kept
// for, so an over-cap id makes the request unroutable instead — answered, recorded, and not
// forwarded, rather than delivered to a host whose reply this proxy would then drop as untracked.
func TestServerRequestTracking_RefusesAnIDLargerThanTheTrackerRetains(t *testing.T) {
	t.Parallel()
	var reqs serverReqTracker
	var written []mcp.RPCMsg
	u := serverRequestUnblocker{
		reqs:          &reqs,
		writeUpstream: func(m mcp.RPCMsg) { written = append(written, m) },
		errOut:        io.Discard,
	}
	huge := json.RawMessage(`"` + strings.Repeat("x", maxTrackedServerReqIDBytes) + `"`)
	rec := &fwdRecorder{}

	routable := trackServerRequest(context.Background(), u, rec, newRefusalRecordLimiter(), verifiedSession("s"),
		stdioServerRequestDrops, mcp.RPCMsg{JSONRPC: "2.0", ID: &huge, Method: "roots/list"})

	assert.False(t, routable, "a request whose reply could never be routed must not be forwarded to the host")
	assert.False(t, reqs.tracked(mcp.MsgKey(&huge)), "the over-cap id must not be retained; retaining it is the whole exposure")
	require.Len(t, written, 1, "the initiator must be answered rather than left blocked on a request eunox will not track")
	require.NotNil(t, written[0].Error)
	assert.Contains(t, written[0].Error.Message, "larger than the proxy's in-flight tracker retains")
	require.Len(t, rec.records, 1, "the refusal is a call the proxy actively failed, so it reaches the tape")
	assert.Equal(t, string(dropStdioUnroutableID), rec.records[0].details[detailTransport])

	// The control: one byte under the cap is tracked and forwarded as before.
	ok := json.RawMessage(`"` + strings.Repeat("x", maxTrackedServerReqIDBytes-3) + `"`)
	assert.True(t, trackServerRequest(context.Background(), u, rec, newRefusalRecordLimiter(), verifiedSession("s"),
		stdioServerRequestDrops, mcp.RPCMsg{JSONRPC: "2.0", ID: &ok, Method: "roots/list"}))
	assert.True(t, reqs.tracked(mcp.MsgKey(&ok)))
}

// TestServerReqTracker_BoundsTheRetainedMethod is the other retained field. The method is read by
// the drop record alone and the sink bounds what it writes, so it is truncated rather than refused —
// what was missing is a bound on what the TRACKER holds for an entry's whole lifetime.
func TestServerReqTracker_BoundsTheRetainedMethod(t *testing.T) {
	t.Parallel()
	var reqs serverReqTracker
	displaced, _ := reqs.track(mcp.RPCMsg{ID: mcp.RawJSON(`1`), Method: strings.Repeat("m", maxTrackedServerReqMethodBytes*2)}, io.Discard)
	assert.Zero(t, displaced.method)

	entry, ok := reqs.ids[mcp.MsgKey(mcp.RawJSON(`1`))]
	require.True(t, ok)
	assert.LessOrEqual(t, len(entry.method), maxTrackedServerReqMethodBytes,
		"the tracker must bound the method it retains: %d entries times an unbounded 4 MiB field is the exposure", maxTrackedServerReqs)
}
