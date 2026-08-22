// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The not-delivered deny is a REFUSAL record, charges the category it declares, and does not share
// that category with the correction record.
//
// It used to write straight through the leg's sink, reaching neither refusalDeclarations nor the
// call-site walk that keeps every other refusal honest — while an HTTP upstream alone can drive one
// per request (outrun the SSE buffer, or hold no GET stream open), with no host cooperation at all.
// That is the same axis catDisplaced and catServerRequestFailed's writers are metered on.
//
// It is also why this deny holds its OWN bucket: routing it onto catServerRequestFailed bounded it,
// but at the cost of letting that flood spend the tokens for failServerRequestDelivery's correction
// — the record that repairs a standing ALLOW, and the one the tamper-evident tape most needs.

package transport

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
)

// undeliveredLeg builds the server-initiated leg a forward always fails on, wired the way both
// transports' unblocker() constructors wire theirs: one limiter holding buckets for the categories
// under test, and the leg's tape paired with it.
func undeliveredLeg(rec auditRecorder, lim *categoryRecordLimiter) serverRequestParams {
	u := serverRequestUnblocker{
		reqs:    &serverReqTracker{},
		sink:    sinkFunc(func(mcp.RPCMsg) error { return nil }),
		notices: noticesTo(io.Discard),
		report: dropReport{
			recs: refusalLimits{records: lim}.recorders(rec),
			subj: verifiedSession("s"),
			legs: httpServerRequestLegs,
		},
	}
	return serverRequestParams{
		rec:       rec,
		sessionID: "s",
		pdp:       pdp.AlwaysAllowPDP{},
		// The HTTP shape this bounds: broadcastServerRequest reporting that no subscriber took the
		// request.
		forward:   func(context.Context, mcp.RPCMsg) bool { return false },
		unblocker: u,
	}
}

// floodUndelivered runs n non-sampling server-initiated requests through a leg whose forward always
// fails. Non-sampling so no policy decision is involved: what is under test is the record the leg
// writes for a request no client accepted.
func floodUndelivered(fp serverRequestParams, n int) {
	for range n {
		forwardServerRequest(revisionContext(handshakeRevision),
			mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "roots/list"}, fp)
	}
}

// TestUndeliveredServerRequest_RecordChargesItsCategory pins that the flood is bounded at all: an
// upstream driving one undelivered request per frame must not turn an unbounded audit-write rate
// loose on the tape — under --require-audit=strict, enough dropped writes latch AuditDegraded and
// deny every route.
func TestUndeliveredServerRequest_RecordChargesItsCategory(t *testing.T) {
	t.Parallel()
	rec := &fwdRecorder{}
	lim := newRefusalRecordLimiterFor([]refusalCategory{catUndeliveredForward})
	now := time.Now()
	lim.setNow(func() time.Time { return now })

	const frames = perCategoryDenyBurstSize + 20
	floodUndelivered(undeliveredLeg(rec, lim), frames)

	assert.Less(t, len(rec.records), frames,
		"an upstream drives this record with no host cooperation; writing one per frame is the flood the declaration exists to bound")
	// The bucket's own burst plus the one floored write its reserve admits per interval — the
	// budget catUndeliveredForward declares, not the floor-rate `unknown` fallback an
	// unregistered category would land in.
	assert.LessOrEqual(t, len(rec.records), perCategoryDenyBurstSize+1)
	assert.GreaterOrEqual(t, len(rec.records), perCategoryDenyBurstSize,
		"a record resolved against a category the table holds no bucket for falls to the floor-rate fallback, which would admit far fewer")
	require.NotEmpty(t, rec.records)
	for i, r := range rec.records {
		assert.Equal(t, "deny", r.decision, "record %d", i)
	}
}

// TestUndeliveredServerRequest_FloodLeavesTheCorrectionRecordWritable is the reason this deny holds
// its own bucket rather than the one its asynchronous counterpart charges.
//
// failServerRequestDelivery's correction is appended when a request that WAS buffered never reached
// the host; without it the earlier ALLOW stands on the tamper-evident tape claiming a delivery that
// never happened. An upstream needs no host at all to drive the synchronous deny, so sharing one
// category let the cheap flood suppress the record that repairs the standing allow.
func TestUndeliveredServerRequest_FloodLeavesTheCorrectionRecordWritable(t *testing.T) {
	t.Parallel()
	rec := &fwdRecorder{}
	lim := newUpstreamRefusalLimiter(nil, upstreamRefusalCategories)
	now := time.Now()
	lim.setNow(func() time.Time { return now })

	floodUndelivered(undeliveredLeg(rec, lim), perCategoryDenyBurstSize+50)
	recs := refusalLimits{records: lim}.recorders(rec)

	// The finding first, so a regression names the harm rather than the vacuity guard below it.
	assert.NotNil(t, recs.forCategory(catServerRequestFailed),
		"the undelivered flood drained the correction's bucket; the correction is what stops an earlier ALLOW standing on the tape as a delivery that never happened")
	// The other upstream-driven categories are the same argument, already made for each of them.
	assert.NotNil(t, recs.forCategory(catDisplaced))
	assert.NotNil(t, recs.forCategory(catRefusalUndeliverable))
	assert.Nil(t, recs.forCategory(catUndeliveredForward),
		"the flood must have exhausted its OWN bucket, or the assertions above hold for a table nothing spent")
}

// TestUndeliveredServerRequest_SuppressionDoesNotElideAnotherCategory pins the reason each category
// holds its OWN bucket, on the narrowest table that can show it: an upstream flooding undelivered
// requests must not spend the tokens that bound a sibling refusal's records.
func TestUndeliveredServerRequest_SuppressionDoesNotElideAnotherCategory(t *testing.T) {
	t.Parallel()
	rec := &fwdRecorder{}
	lim := newRefusalRecordLimiterFor([]refusalCategory{catUndeliveredForward, catDisplaced})
	now := time.Now()
	lim.setNow(func() time.Time { return now })

	floodUndelivered(undeliveredLeg(rec, lim), perCategoryDenyBurstSize+20)
	drained := len(rec.records)

	assert.NotNil(t, refusalLimits{records: lim}.recorders(rec).forCategory(catDisplaced),
		"the undelivered flood drained a sibling category's bucket; each category holds its own so the cheapest flood cannot elide the record a live request was lost")
	assert.Nil(t, refusalLimits{records: lim}.recorders(rec).forCategory(catUndeliveredForward),
		"its own bucket must be the one that is empty after %d admitted writes", drained)
}
