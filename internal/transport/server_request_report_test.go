// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The other half of the server-initiated leg's rule: an answer that did not LAND is a second fact
// about the request, and the seam that answers is what puts it on the tape.
//
// unblock reports whether the id was HELD, not whether the answer landed, and its three callers
// turned on that bool and threw the delivery report away — so with a dead upstream sink each
// consumed the tracker entry (making the reply unroutable by any later path, deliberately), failed
// the write, and left the upstream blocked with only a stderr line, itself rate-limited.

package transport

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// brokenSink fails every write, which is the REACHABLE shape of this failure: an upstream
// subprocess that dies mid-answer EPIPEs the write. The absent-sink case is unreachable on both
// transports, so a test driven by it would exercise the branch that cannot happen.
func brokenSink() mcp.MsgSink {
	return sinkFunc(func(mcp.RPCMsg) error { return errors.New("write: broken pipe (test probe)") })
}

// TestUnblock_DestroyedAnswerReachesTheTape covers unblock's three callers at the seam they share.
//
// Each of them consumes the tracked id BEFORE it knows whether the answer can be written — which is
// what makes a failed write final, since no later path can route anything to that initiator. The
// refusal each caller already recorded describes the refusal, not the delivery, so without this an
// operator reconstructing a wedged upstream cannot tell "refused and told so" from "refused and the
// upstream never heard".
func TestUnblock_DestroyedAnswerReachesTheTape(t *testing.T) {
	t.Parallel()
	var reqs serverReqTracker
	rec := &fwdRecorder{}
	_, _ = reqs.track(mcp.RPCMsg{ID: mcp.RawJSON(`7`), Method: capability.MethodSamplingCreateMessage}, io.Discard)
	u := serverRequestUnblocker{
		reqs: &reqs, sink: brokenSink(), notices: noticesTo(io.Discard),
		report: dropReport{
			recs: refusalLimits{records: newRefusalRecordLimiter()}.recorders(rec),
			subj: verifiedSession("s"),
			legs: httpServerRequestLegs,
		},
	}

	require.True(t, u.unblock(context.Background(), mcp.RawJSON(`7`), "refused"),
		"the id was held, so the entry is consumed whether or not the answer lands")

	require.Len(t, rec.records, 1, "a destroyed answer leaves the upstream blocked and must reach the tape; a rate-limited stderr line is not something a SIEM sees")
	assert.Equal(t, "deny", rec.records[0].decision)
	assert.Equal(t, capability.ErrCodeEnforcementError, rec.records[0].code)
	assert.Equal(t, string(dropHTTPRefusalUndeliverable), rec.records[0].details[detailTransport])
	assert.Empty(t, rec.records[0].identifier,
		"sampling/createMessage resolves a policy target, so naming it here would stamp one onto a record no PDP produced")
}

// TestUnblock_RecordNamesTheTakenRequest pins where the record's method comes from.
//
// unblock's commonest caller (a revision-refused host reply) holds a RESPONSE, which carries no
// method at all — so the name has to come from the tracker entry the take consumed, or the record
// would name the empty string for the very request it just made unanswerable.
func TestUnblock_RecordNamesTheTakenRequest(t *testing.T) {
	t.Parallel()
	var reqs serverReqTracker
	rec := &fwdRecorder{}
	_, _ = reqs.track(mcp.RPCMsg{ID: mcp.RawJSON(`7`), Method: "roots/list"}, io.Discard)
	u := serverRequestUnblocker{
		reqs: &reqs, sink: brokenSink(), notices: noticesTo(io.Discard),
		report: dropReport{
			recs: refusalLimits{records: newRefusalRecordLimiter()}.recorders(rec),
			subj: verifiedSession("s"),
			legs: stdioServerRequestLegs,
		},
	}

	// A host RESPONSE: no method of its own, which is the whole point.
	u.unblock(context.Background(), mcp.RawJSON(`7`), refusedReplyUpstreamError)

	require.Len(t, rec.records, 1)
	assert.Equal(t, "roots/list", rec.records[0].identifier,
		"the record names the request left blocked, which only the tracker entry knows")
}

// TestUnblock_DeliveredAnswerRecordsNothing is the control: the drop is reported on the WRITE's
// outcome, not on every unblock.
func TestUnblock_DeliveredAnswerRecordsNothing(t *testing.T) {
	t.Parallel()
	var reqs serverReqTracker
	rec := &fwdRecorder{}
	_, _ = reqs.track(mcp.RPCMsg{ID: mcp.RawJSON(`7`), Method: "roots/list"}, io.Discard)
	u := serverRequestUnblocker{
		reqs: &reqs, sink: sinkFunc(func(mcp.RPCMsg) error { return nil }), notices: noticesTo(io.Discard),
		report: dropReport{
			recs: refusalLimits{records: newRefusalRecordLimiter()}.recorders(rec),
			subj: verifiedSession("s"),
			legs: stdioServerRequestLegs,
		},
	}

	require.True(t, u.unblock(context.Background(), mcp.RawJSON(`7`), "refused"))
	assert.Empty(t, rec.records, "an initiator that received its answer is one event, not two")
}

// TestBroadcastServerRequest_NoSubscriberRecordsADestroyedAnswer is the same rule through the
// caller that reaches it with no host at all: nothing accepted the request, eunox answers its
// initiator, and that answer is destroyed.
func TestBroadcastServerRequest_NoSubscriberRecordsADestroyedAnswer(t *testing.T) {
	t.Parallel()
	rec := &fwdRecorder{}
	sess := newTestSession(&httpSession{
		id:             "s",
		route:          &UpstreamRoute{name: "up1", sink: nil},
		proxy:          newTestHTTPProxy(),
		done:           make(chan struct{}),
		upstreamDenies: newUpstreamRefusalLimiter(nil, upstreamRefusalCategories),
	})
	// The route's own sink is what a session's refusal records resolve through; substitute the
	// capture recorder by driving the seam the session builds.
	u := sess.unblocker()
	u.report.recs = refusalLimits{records: sess.upstreamDenies}.recorders(rec)
	u.sink = brokenSink()

	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`5`), Method: capability.MethodSamplingCreateMessage}
	trackServerRequest(context.Background(), u, msg)
	require.False(t, sess.deliverToOne(msg), "the premise: no SSE subscriber can take it")
	u.unblock(context.Background(), msg.ID, "no client stream available to service server-initiated request")

	require.Len(t, rec.records, 1, "the answer to an undeliverable request was itself destroyed, which is what leaves the upstream wedged")
	assert.Equal(t, string(dropHTTPRefusalUndeliverable), rec.records[0].details[detailTransport])
}

// TestUpstreamRefusalBuckets_ArePerSession is the regression for one session's flood eliding
// another's record.
//
// All four upstream-driven categories used to charge one proxy-wide table, so session A's dead
// subprocess drained catRefusalUndeliverable at its ~2/s share and session B's genuinely lost
// in-flight refusal was folded into a suppressed_refusal_count on a record stamped with A's route.
// Each category has its own bucket for exactly that reason between categories; the session is the
// same argument one dimension out, and saturationGate already states it for its own records.
func TestUpstreamRefusalBuckets_ArePerSession(t *testing.T) {
	t.Parallel()
	drain := func(rec *fwdRecorder, lim *categoryRecordLimiter, rounds int) {
		var reqs serverReqTracker
		u := serverRequestUnblocker{
			reqs: &reqs, sink: brokenSink(), notices: noticesTo(io.Discard),
			report: dropReport{
				recs: refusalLimits{records: lim}.recorders(rec),
				subj: verifiedSession("s"),
				legs: httpServerRequestLegs,
			},
		}
		for i := range rounds {
			id := mcp.RawJSON(jsonNumber(i))
			_, _ = reqs.track(mcp.RPCMsg{ID: id, Method: "roots/list"}, io.Discard)
			u.unblock(context.Background(), id, "refused")
		}
	}

	// Session A empties its own bucket many times over.
	a, aLim := &fwdRecorder{}, newUpstreamRefusalLimiter(nil, upstreamRefusalCategories)
	drain(a, aLim, 200)
	require.NotEmpty(t, a.records)
	assert.LessOrEqual(t, len(a.records), perCategoryDenyBurstSize+1, "A's own flood is still bounded by A's bucket")

	// Session B, with one lost in-flight refusal, must still be recorded.
	b, bLim := &fwdRecorder{}, newUpstreamRefusalLimiter(nil, upstreamRefusalCategories)
	drain(b, bLim, 1)
	assert.Len(t, b.records, 1,
		"a sibling session's flood must not elide the record that says THIS session lost a live in-flight request")
}

// TestUpstreamRefusalBuckets_StillChargeTheAggregate is the other half, and the reason the split is
// not simply "a full share each". It isolates the TIER arithmetic: it drives admit directly, so no
// holder floor is in play (see TestUpstreamRefusalFloor_AggregateStillHoldsTheTotal for the same
// property through the production entry point, floor included).
//
// Per-session buckets alone multiply the sustained write rate into the ONE shared audit queue by the
// session count — at the default maxSessions that is 4096/s sustained against a 4096-deep queue,
// and --require-audit defaults to strict, so overflowing it latches AuditDegraded and denies every
// route. The session tier decides fairness; the proxy-wide parent keeps the total bounded.
func TestUpstreamRefusalBuckets_StillChargeTheAggregate(t *testing.T) {
	t.Parallel()
	aggregate := newRefusalRecordLimiter()
	admitted := 0
	// Many sessions, each with its own full-share table, all flooding the same category.
	for range 50 {
		lim := newUpstreamRefusalLimiter(aggregate, upstreamRefusalCategories)
		for range 20 {
			if lim.admitWithFloor(catDisplaced, nil).ok {
				admitted++
			}
		}
	}
	assert.LessOrEqual(t, admitted, perCategoryDenyBurstSize+1,
		"N sessions must not multiply the aggregate audit-write rate by N; the per-session tier bounds fairness, the parent bounds the total")
	assert.Positive(t, admitted, "the leading edge must still reach the tape")
}

// TestUpstreamRefusalBuckets_RollupNamesItsOwnScope is the regression for a per-session tally
// claiming proxy-wide reach on the signed tape.
//
// The scope value is what tells a reader whether a count of 5000 spans every route or one session's
// upstream; a per-session table stamping the proxy-wide value is the same misreading the route stamp
// caused before the scope was recorded at all.
func TestUpstreamRefusalBuckets_RollupNamesItsOwnScope(t *testing.T) {
	t.Parallel()
	rec := &fwdRecorder{}
	lim := newUpstreamRefusalLimiter(nil, upstreamRefusalCategories)
	// Exhaust the burst so the next admitted record carries a rollup.
	for range perCategoryDenyBurstSize + 20 {
		_ = admitRefusalRecord(rec, lim, catDisplaced)
	}
	lim.setNow(func() time.Time { return time.Now().Add(time.Hour) })
	rolled := admitRefusalRecord(rec, lim, catDisplaced)
	require.NotNil(t, rolled)
	rolled.RecordDeny(context.Background(), "s", "", "roots/list", capability.ErrCodeEnforcementError, "", nil, false)

	last := rec.records[len(rec.records)-1]
	assert.Equal(t, suppressedScopeSessionCategory, last.details[detailSuppressedRefusalScope],
		"a per-session tally stamped proxy_category tells a reader it spans every route")
	assert.Positive(t, last.details[detailSuppressedRefusalCount])
}

// TestUpstreamRefusalLimiter_HasABucketPerUpstreamCategory keeps the per-session table honest: a
// category it charges but does not build falls to the shared `unknown` bucket, which is bounded at
// the floor rate and shared with every other unregistered category.
func TestUpstreamRefusalLimiter_HasABucketPerUpstreamCategory(t *testing.T) {
	t.Parallel()
	lim := newUpstreamRefusalLimiter(nil, upstreamRefusalCategories)
	require.NotEmpty(t, upstreamRefusalCategories)
	for _, cat := range upstreamRefusalCategories {
		assert.Equal(t, meteringMetered, refusalDeclarations[cat].metering,
			"the per-session table charges %q, which is not a metered category", cat)
		assert.NotEqual(t, lim.unknown, lim.bucket(cat), "no bucket built for %q", cat)
	}
	// The share is still a share of the AGGREGATE, not of the four this table happens to hold —
	// splitting a bucket per session must not also widen each one.
	assert.Equal(t, float64(perCategoryDenyRatePerSec), lim.bucket(catDisplaced).ratePerSec)
}

// TestInitiatorWriter_AnswersTheConcreteWriterByName pins the half of the nil-writer question that
// is safe to answer statically: the sink both transports hold is resolved by NAME, above the
// reflection, so the relay path — every answered initiator — no longer reaches reflect at all.
func TestInitiatorWriter_AnswersTheConcreteWriterByName(t *testing.T) {
	t.Parallel()
	assert.NotNil(t, initiatorWriter(mcp.NewMsgWriter(io.Discard)))
	assert.Nil(t, initiatorWriter((*mcp.MsgWriter)(nil)),
		"a nil *mcp.MsgWriter locks a mutex on a nil receiver; it is genuinely absent")
	assert.Nil(t, initiatorWriter(nil))
}

// TestInitiatorWriter_RefusesEveryNilAbleSink is the half that must NOT be narrowed.
//
// The tempting reading is that a nil-able VALUE receiver is a false refusal because its Write is
// "callable". It dispatches, but for the ordinary func adapter — this package's own sinkFunc — the
// body then calls a nil func and panics, and a nil chan-backed one blocks forever. Both land AFTER
// the refusal's audit record, which is the tape-records-a-denial-the-process-died-delivering outcome
// the seam exists to replace, so the refusal is worth its residual false positive.
func TestInitiatorWriter_RefusesEveryNilAbleSink(t *testing.T) {
	t.Parallel()
	assert.Nil(t, initiatorWriter(sinkFunc(nil)),
		"a nil func adapter dispatches Write and then panics calling the nil func — worse than a refused answer")
	assert.Nil(t, initiatorWriter(chanSink(nil)),
		"a nil chan adapter blocks forever, wedging the goroutine that was answering")
	assert.Nil(t, initiatorWriter(mapSink(nil)))
	// The control: a non-nil value-receiver adapter is not refused.
	assert.NotNil(t, initiatorWriter(mapSink{}))
}

// mapSink and chanSink are nil-able VALUE receivers, the adapter shapes the narrowing would have
// admitted. chanSink's Write is the one whose nil value hangs rather than panics.
type mapSink map[string]string

func (mapSink) Write(mcp.RPCMsg) error { return nil }

type chanSink chan mcp.RPCMsg

func (c chanSink) Write(m mcp.RPCMsg) error { c <- m; return nil }

// TestServerRequestLegs_EachTableNamesItsOwnTransport closes the one hazard a struct of four
// same-typed fields has: `httpServerRequestLegs{reply: dropHTTPRefusalUndeliverable}` — a
// copy-paste from the field above it — compiles, passes every other test, and labels every
// destroyed HOST REPLY on the tape as a refusal drop. That distinction is the whole reason the
// report is per disposition, and `transport` is the only thing an operator has to tell a wedged
// upstream from a merely refused one.
func TestServerRequestLegs_EachTableNamesItsOwnTransport(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		legs   serverRequestLegs
		prefix string
	}{
		{"http", httpServerRequestLegs, "http-"},
		{"stdio", stdioServerRequestLegs, "stdio-"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			seen := map[transportLeg]bool{}
			for field, leg := range map[string]transportLeg{
				"displaced": tc.legs.displaced, "unroutableID": tc.legs.unroutableID,
				"refusal": tc.legs.refusal, "reply": tc.legs.reply,
			} {
				assert.True(t, strings.HasPrefix(string(leg), tc.prefix),
					"%s.%s is %q, which belongs to the other transport; a SIEM filter on this key would attribute the drop to the wrong leg", tc.name, field, leg)
				assert.False(t, seen[leg], "%s.%s repeats %q; two dispositions sharing one leg value make them indistinguishable on the tape", tc.name, field, leg)
				seen[leg] = true
			}
		})
	}
}

// TestRefusalRecorders_CannotRePointItsOwnTape is the structural half of holding the limits apart
// from the sink.
//
// refusalRecorders used to EMBED refusalLimits, so recorders() was promoted onto it and
// `recs.recorders(otherSink)` compiled on an already-resolved wiring — minting one that keeps this
// leg's buckets while pointing at a different tape, verbatim the hazard refusalLimits' own doc says
// holding the sink apart was meant to prevent. forCategory being the one resolver governs which
// bucket a record charges, never which tape it lands on.
func TestRefusalRecorders_CannotRePointItsOwnTape(t *testing.T) {
	t.Parallel()
	field, found := reflect.TypeOf(refusalRecorders{}).FieldByName("limits")
	require.True(t, found, "refusalRecorders must hold its limits in a named field")
	assert.False(t, field.Anonymous,
		"embedding promotes recorders() onto refusalRecorders, so a producer holding one can mint a wiring with this leg's buckets and a different tape")
}

// TestEnforcedForwardCore_SendsNothingForAMessageWithNoReplyChannel makes the "no reply channel"
// rule structural rather than a property of which helper each exit reached for.
//
// mcp.RPCMsg.JSONRPC has no omitempty, so a zero message marshals to `{"jsonrpc":""}` — a malformed
// frame — rather than to nothing, and both transports write the dispatcher's result. Unreachable
// today only because both gate on IsRequest before dispatching.
func TestEnforcedForwardCore_SendsNothingForAMessageWithNoReplyChannel(t *testing.T) {
	t.Parallel()
	notification := mcp.RPCMsg{JSONRPC: "2.0", Method: "tools/call"}
	allow := capability.EnforceResponse{Decision: capability.DecisionAllow}

	cases := []struct {
		name string
		dec  capability.EnforceResponse
		up   func(context.Context, mcp.RPCMsg) (mcp.RPCMsg, error)
	}{
		{"hard deny", capability.EnforceResponse{Decision: capability.DecisionDeny,
			Denial: &capability.DenialInfo{Code: capability.ErrCodeAuthorizationFailed}}, nil},
		{"upstream failure", allow, func(context.Context, mcp.RPCMsg) (mcp.RPCMsg, error) {
			return mcp.RPCMsg{}, errors.New("upstream down (test probe)")
		}},
		{"allow", allow, func(_ context.Context, m mcp.RPCMsg) (mcp.RPCMsg, error) {
			return mcp.RPCMsg{JSONRPC: "2.0", ID: m.ID, Result: json.RawMessage(`{}`)}, nil
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fp := forwardParams{rec: &fwdRecorder{}, limits: refusalLimits{notices: noticesTo(io.Discard)}, callUpstream: tc.up}
			got := enforcedForwardCore(context.Background(), fp, nil, notification, tc.dec,
				"tools/call", "tool:x", "x", "tool", false, func(mcp.RPCMsg) map[string]interface{} { return nil })
			assert.True(t, got.IsZero(),
				"a message with no id has no reply channel; anything but the zero message reaches the host as `{\"jsonrpc\":\"\"}`")
		})
	}
}

// TestWriteDispatchResult_SkipsTheZeroMessage is the consumer-side half on HTTP: the transport that
// writes the dispatcher's result must be able to tell "nothing to send" from a message.
func TestWriteDispatchResult_SkipsTheZeroMessage(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	writeDispatchResult(rec, mcp.RPCMsg{})
	assert.Equal(t, 202, rec.Code, "a POST with nothing to reply to is acked, not answered with a malformed frame")
	assert.Empty(t, rec.Body.String())

	rec = httptest.NewRecorder()
	writeDispatchResult(rec, mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Result: json.RawMessage(`{}`)})
	assert.Contains(t, rec.Body.String(), `"jsonrpc":"2.0"`)
}
