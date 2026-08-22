// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The not-delivered deny is a REFUSAL record and charges the category it declares.
//
// It used to write straight through the leg's sink, reaching neither refusalDeclarations nor the
// call-site walk that keeps every other refusal honest — while an HTTP upstream alone can drive one
// per request (outrun the SSE buffer, or hold no GET stream open), with no host cooperation at all.
// That is the same axis catDisplaced and catServerRequestFailed's other writers are metered on.

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
	lim := newRefusalRecordLimiterFor([]refusalCategory{catServerRequestFailed})
	now := time.Now()
	lim.setNow(func() time.Time { return now })

	const frames = perCategoryDenyBurstSize + 20
	floodUndelivered(undeliveredLeg(rec, lim), frames)

	assert.Less(t, len(rec.records), frames,
		"an upstream drives this record with no host cooperation; writing one per frame is the flood the declaration exists to bound")
	// The bucket's own burst plus the one floored write its reserve admits per interval — the
	// budget catServerRequestFailed declares, not the floor-rate `unknown` fallback an
	// unregistered category would land in.
	assert.LessOrEqual(t, len(rec.records), perCategoryDenyBurstSize+1)
	assert.GreaterOrEqual(t, len(rec.records), perCategoryDenyBurstSize,
		"a record resolved against a category the table holds no bucket for falls to the floor-rate fallback, which would admit far fewer")
	require.NotEmpty(t, rec.records)
	for i, r := range rec.records {
		assert.Equal(t, "deny", r.decision, "record %d", i)
	}
}

// TestUndeliveredServerRequest_SuppressionDoesNotElideAnotherCategory pins the reason each category
// holds its OWN bucket: an upstream flooding undelivered requests must not spend the tokens that
// bound a sibling refusal's records, which are what an operator reads first.
func TestUndeliveredServerRequest_SuppressionDoesNotElideAnotherCategory(t *testing.T) {
	t.Parallel()
	rec := &fwdRecorder{}
	lim := newRefusalRecordLimiterFor([]refusalCategory{catServerRequestFailed, catDisplaced})
	now := time.Now()
	lim.setNow(func() time.Time { return now })

	floodUndelivered(undeliveredLeg(rec, lim), perCategoryDenyBurstSize+20)
	drained := len(rec.records)

	assert.NotNil(t, refusalLimits{records: lim}.recorders(rec).forCategory(catDisplaced),
		"the undelivered flood drained a sibling category's bucket; each category holds its own so the cheapest flood cannot elide the record a live request was lost")
	assert.Nil(t, refusalLimits{records: lim}.recorders(rec).forCategory(catServerRequestFailed),
		"its own bucket must be the one that is empty after %d admitted writes", drained)
}
