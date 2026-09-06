// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The translation boundary's server-initiated refusal: what it may name on the signed tape, and
// which bucket its record charges.
//
// Nothing was ABOUT the arm before this — the one test that reached it (gate_order_test.go's
// revision stamp) asserted on a different property of the record it happened to produce. It wrote
// straight through the leg's sink with the METHOD as the identifier, which is both halves of what a
// refusal taken with no policy decision behind it owes the tape: sampling/createMessage resolves a
// target type, so the sink stamped a policy target for a request no PDP saw; and the write reached
// neither the metering declaration nor the call-site walk that holds every other transport refusal
// to a declared bucket — while the UPSTREAM alone sets its rate, once its host has declared a
// revision with no server-initiated mechanism.

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
	"github.com/eunolabs/eunox/pkg/capability"
)

// untranslatableSeam is the answering wiring these tests hand the leg: the shared seam builder both
// transports' unblocker() constructors are modelled on, over a bucket table the caller sizes.
func untranslatableSeam(write func(mcp.RPCMsg) error, rec auditRecorder, lim *categoryRecordLimiter) serverRequestUnblocker {
	return answeringSeamWith(write, rec, httpServerRequestLegs, io.Discard, lim)
}

// untranslatableLeg is a server-initiated leg on a session whose HOST pinned 2026-07-28 — the
// mismatched pair the boundary refuses. forward reports true so a leg that reached it at all would
// record an ALLOW, which is the failure this refusal exists to prevent rather than a silent no-op.
func untranslatableLeg(u serverRequestUnblocker) serverRequestParams {
	return serverRequestParams{
		sessionID: "s",
		pdp:       pdp.AlwaysAllowPDP{},
		revision:  capability.Revision20260728,
		forward:   func(context.Context, mcp.RPCMsg) forwardOutcome { return forwardDelivered },
		unblocker: u,
	}
}

// samplingServerRequest is the request an upstream aims at a host that has no way to receive it.
// sampling/createMessage specifically, because it RESOLVES a target type: it is the method whose
// name, recorded as an identifier, becomes a policy target on the signed tape.
func samplingServerRequest() mcp.RPCMsg {
	return mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodSamplingCreateMessage}
}

// floodUntranslatable runs n server-initiated requests into a host whose revision removed the
// mechanism — the rate an upstream drives with no host cooperation, no tracking and no delivery.
func floodUntranslatable(fp serverRequestParams, n int) {
	for range n {
		forwardServerRequest(revisionContext(capability.Revision20260728), samplingServerRequest(), fp)
	}
}

// TestUntranslatableServerRequest_RefusalNamesNoPolicyTargetAndAnswersItsInitiator pins the record
// against the real sink, since what went wrong is what the SINK derives from the identifier it was
// handed: `target_type: system, target: sampling/createMessage` for a request the PDP never
// evaluated. Every sibling refusal on this leg goes through auditIdentity for exactly that reason.
//
// The answer is asserted beside it because the two are one obligation: this leg's rule is that eunox
// answers a blocked initiator wherever it can do so without acting on a second identity's behalf,
// and a refusal of its own says nothing about the host.
func TestUntranslatableServerRequest_RefusalNamesNoPolicyTargetAndAnswersItsInitiator(t *testing.T) {
	t.Parallel()
	sink, logPath := newTempAuditSink(t)
	rec := asRecorder(&routeSink{sink: sink, upstream: "up1"})
	var answered []mcp.RPCMsg

	forwardServerRequest(revisionContext(capability.Revision20260728), samplingServerRequest(),
		untranslatableLeg(untranslatableSeam(func(m mcp.RPCMsg) error {
			answered = append(answered, m)
			return nil
		}, rec, newRefusalRecordLimiter())))
	_ = sink.Close()

	got := findAuditRecordByMethod(readAuditRecords(t, logPath), capability.MethodSamplingCreateMessage, "deny")
	require.NotNil(t, got, "a boundary refusal the tape does not carry is the blind spot every framing guard here exists to close")
	assert.Equal(t, capability.ErrCodeUntranslatableAcrossRevisions, got["denial_code"],
		"both revisions are established; what fails is that the PAIR cannot carry this")
	requireNoPhantomTarget(t, got, capability.ErrCodeUntranslatableAcrossRevisions)

	require.Len(t, answered, 1, "the initiator blocks until something answers it, and eunox can refuse on its own behalf without relaying anything the host said")
	require.NotNil(t, answered[0].Error)
	assert.Equal(t, capability.JSONRPCCodeUnsupportedProtocolVersion, answered[0].Error.Code)
}

// TestUntranslatableServerRequest_RecordChargesItsCategory is the metering half: on a session whose
// host declared 2026-07-28, EVERY server-initiated request the upstream issues takes this arm, at the
// upstream's own send rate. Unbounded that is an unbounded audit-write rate — under
// --require-audit=strict, enough dropped writes latch AuditDegraded and deny every route.
func TestUntranslatableServerRequest_RecordChargesItsCategory(t *testing.T) {
	t.Parallel()
	rec := &fwdRecorder{}
	lim := newRefusalRecordLimiterFor([]refusalCategory{catUntranslatableServerRequest})
	now := time.Now()
	lim.setNow(func() time.Time { return now })

	const frames = perCategoryDenyBurstSize + 20
	floodUntranslatable(untranslatableLeg(untranslatableSeam(func(mcp.RPCMsg) error { return nil }, rec, lim)), frames)

	assert.Less(t, len(rec.records), frames,
		"an upstream drives this record with no host cooperation; writing one per frame is the flood the declaration exists to bound")
	// EXACTLY the burst: the clock is frozen, so no bucket refills, and the budget spent is the one
	// catUntranslatableServerRequest declares rather than the floor-rate fallback an unregistered
	// category lands in. Asserted exactly rather than with slack, since slack here would absorb an
	// off-by-one admitting one more than the burst on the leading frame.
	assert.Len(t, rec.records, perCategoryDenyBurstSize)
	for i, r := range rec.records {
		assert.Equal(t, "deny", r.decision, "record %d", i)
		assert.Empty(t, r.identifier, "record %d names a policy target for a request no PDP evaluated", i)
	}
}

// TestUntranslatableServerRequest_FloodLeavesTheHostRevisionRefusalWritable is why this refusal holds
// its OWN bucket rather than the catRevision its host-side spelling charges.
//
// That one bounds a HOST peer's revision refusal — the record saying someone is probing the
// negotiated surface, which an incident responder reads. An upstream needs no host at all to drive
// this one, so sharing would let the cheaper flood suppress it.
func TestUntranslatableServerRequest_FloodLeavesTheHostRevisionRefusalWritable(t *testing.T) {
	t.Parallel()
	rec := &fwdRecorder{}
	lim := newRefusalRecordLimiter()
	now := time.Now()
	lim.setNow(func() time.Time { return now })

	floodUntranslatable(untranslatableLeg(untranslatableSeam(func(mcp.RPCMsg) error { return nil }, rec, lim)),
		perCategoryDenyBurstSize+50)
	recs := refusalLimits{records: lim}.recorders(rec)

	// The finding first, so a regression names the harm rather than the vacuity guard below it.
	assert.NotNil(t, recs.forCategory(catRevision),
		"the boundary flood drained the host-side revision refusal's bucket; that record is what says a peer is probing the negotiated surface")
	// The other upstream-driven categories are the same argument, already made for each of them.
	assert.NotNil(t, recs.forCategory(catServerRequestFailed))
	assert.NotNil(t, recs.forCategory(catUndeliveredForward))
	assert.Nil(t, recs.forCategory(catUntranslatableServerRequest),
		"the flood must have exhausted its OWN bucket, or the assertions above hold for a table nothing spent")
}

// TestUntranslatableServerRequest_RefusesBeforeTheMethodSplit pins the boundary as a fact about the
// LEG rather than about what was asked for: a non-sampling method is refused on the same terms, and
// neither method reaches the host.
func TestUntranslatableServerRequest_RefusesBeforeTheMethodSplit(t *testing.T) {
	t.Parallel()
	for _, method := range []string{capability.MethodSamplingCreateMessage, "roots/list", "elicitation/create"} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			rec := &fwdRecorder{}
			var forwarded int
			fp := untranslatableLeg(untranslatableSeam(func(mcp.RPCMsg) error { return nil }, rec, newRefusalRecordLimiter()))
			fp.forward = func(context.Context, mcp.RPCMsg) forwardOutcome { forwarded++; return forwardDelivered }

			forwardServerRequest(revisionContext(capability.Revision20260728),
				mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: method}, fp)

			assert.Zero(t, forwarded, "there is no way to ask a host whose revision removed the mechanism, and no honest answer eunox could give on its behalf")
			require.Len(t, rec.records, 1)
			assert.Equal(t, capability.ErrCodeUntranslatableAcrossRevisions, rec.records[0].code)
		})
	}

	// The control: on a matched pair the same request is not a boundary refusal at all.
	t.Run("handshake host forwards", func(t *testing.T) {
		t.Parallel()
		rec := &fwdRecorder{}
		var forwarded int
		fp := untranslatableLeg(untranslatableSeam(func(mcp.RPCMsg) error { return nil }, rec, newRefusalRecordLimiter()))
		fp.revision = handshakeRevision
		fp.forward = func(context.Context, mcp.RPCMsg) forwardOutcome { forwarded++; return forwardDelivered }

		forwardServerRequest(revisionContext(handshakeRevision),
			mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "roots/list"}, fp)

		assert.Equal(t, 1, forwarded)
		require.Len(t, rec.records, 1)
		assert.Equal(t, "allow", rec.records[0].decision)
	})
}
