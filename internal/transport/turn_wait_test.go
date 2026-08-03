// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The server-initiated leg's turn wait bounds ONE HOLDER, not the waiter's own arrival.
//
// It was per-arrival when the leg ran inline on the upstream reader, where each request got a
// fresh window for free — the next was not read off the pipe until the previous finished. Once
// each request ran on its own goroutine, N waiters started one window together on the same gate
// and expired together: one slow holder refused every one of them. These pin the replacement on
// BOTH transports, since the two legs are meant to answer identically.

// A waiter queued behind a MOVING queue is not refused: each handoff opens a fresh window, so
// the total wait exceeds perHolder without anything being stalled.
func TestTurnWait_StdioFreshWindowPerHandoff(t *testing.T) {
	t.Parallel()
	g := newDecisionSerializer()
	anchor := sessionAnchorKey("sess-a")

	const holders = 5
	const hold = 100 * time.Millisecond
	tickets := make([]decisionTicket, holders)
	for i := range tickets {
		tickets[i] = g.take(anchor)
	}
	waiter := g.take(anchor)

	go func() {
		for _, tk := range tickets {
			end := g.begin(tk)
			time.Sleep(hold)
			end()
		}
	}()

	start := time.Now()
	// perHolder is comfortably above any single hold and well below their sum: the old
	// per-arrival rule refused this waiter at 250ms with the queue making steady progress.
	end, ok := g.beginWithin(waiter, turnWait{perHolder: 250 * time.Millisecond, total: 10 * time.Second})
	require.True(t, ok, "a waiter behind a queue that keeps handing off must not be refused: nothing stalled it")
	require.NotNil(t, end)
	assert.GreaterOrEqual(t, time.Since(start), holders*hold/2,
		"the test did not actually exercise a wait longer than one window")
	end()
}

// The condition worth refusing over: ONE holder that never hands off. The waiter gives up at
// roughly its per-holder window, whatever else is happening.
func TestTurnWait_StdioStuckHolderIsRefused(t *testing.T) {
	t.Parallel()
	g := newDecisionSerializer()
	anchor := sessionAnchorKey("sess-a")

	stuck := g.begin(g.take(anchor)) // taken and never released while the waiter waits
	waiter := g.take(anchor)

	start := time.Now()
	end, ok := g.beginWithin(waiter, turnWait{perHolder: 50 * time.Millisecond, total: 10 * time.Second})
	waited := time.Since(start)
	assert.False(t, ok, "a holder that has held the turn for a whole window must not park the waiter indefinitely")
	assert.Nil(t, end, "no turn was taken, so there is nothing to release")
	assert.GreaterOrEqual(t, waited, 25*time.Millisecond, "it must WAIT — an instant refusal fails every request under ordinary contention")
	assert.Less(t, waited, 5*time.Second, "and give up on roughly its own window, not on the total ceiling")

	stuck()
}

// The ceiling: "the queue is moving" must not mean "forever". A waiter holds one of the
// server-request pool's slots, so an anchor with a steady stream of short holders would
// otherwise pin slots indefinitely.
func TestTurnWait_StdioTotalCeilingCapsAMovingQueue(t *testing.T) {
	t.Parallel()
	g := newDecisionSerializer()
	anchor := sessionAnchorKey("sess-a")

	const holders = 40
	tickets := make([]decisionTicket, holders)
	for i := range tickets {
		tickets[i] = g.take(anchor)
	}
	waiter := g.take(anchor)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, tk := range tickets {
			end := g.begin(tk)
			time.Sleep(20 * time.Millisecond)
			end()
		}
	}()

	start := time.Now()
	// The queue hands off every 20ms forever (800ms of work), so per-holder alone would never
	// fire. The ceiling is what ends the wait.
	_, ok := g.beginWithin(waiter, turnWait{perHolder: 200 * time.Millisecond, total: 150 * time.Millisecond})
	waited := time.Since(start)
	assert.False(t, ok, "a moving queue must still be bounded by the total ceiling")
	assert.Less(t, waited, 600*time.Millisecond, "the ceiling must end the wait well before the queue drains")
	<-done
}

// The HTTP gate is a one-slot channel rather than a FIFO, so it counts HANDOFFS to tell "the
// holder is stuck" from "the queue is moving". This drives that counter directly: the turn is
// held throughout, so the waiter never wins it, and the bumps stand in for turns it lost to
// other contenders — the case a one-slot channel cannot stage deterministically any other way.
func TestTurnWait_HTTPGateFreshWindowPerHandoff(t *testing.T) {
	t.Parallel()
	gate := &anchorGate{turn: make(chan struct{}, 1)}
	gate.turn <- struct{}{} // held for the whole test; the waiter can never acquire

	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(30 * time.Millisecond):
				gate.handoffs.Add(1)
			}
		}
	}()
	defer close(stop)

	start := time.Now()
	end, ok := gate.take(turnWait{perHolder: 80 * time.Millisecond, total: 400 * time.Millisecond})
	waited := time.Since(start)
	assert.False(t, ok, "the turn was never free, so the wait must end at the ceiling")
	assert.Nil(t, end)
	assert.GreaterOrEqual(t, waited, 150*time.Millisecond,
		"a waiter observing handoffs must keep taking fresh windows rather than expiring on the first")
	assert.Less(t, waited, 3*time.Second, "and the ceiling must still end it")
}

// The same stuck-holder property on the HTTP gate, with no handoffs at all: one window and out.
func TestTurnWait_HTTPGateStuckHolderIsRefused(t *testing.T) {
	t.Parallel()
	gate := &anchorGate{turn: make(chan struct{}, 1)}
	release, ok := gate.take(turnWait{})
	require.True(t, ok)

	start := time.Now()
	end, ok := gate.take(turnWait{perHolder: 50 * time.Millisecond, total: 10 * time.Second})
	waited := time.Since(start)
	assert.False(t, ok)
	assert.Nil(t, end)
	assert.GreaterOrEqual(t, waited, 25*time.Millisecond)
	assert.Less(t, waited, 5*time.Second, "one stuck holder must not stretch the wait to the ceiling")

	release()
	// And the gate is usable afterwards: a refusal takes no turn and leaves nothing held.
	end, ok = gate.take(turnWait{perHolder: time.Second, total: time.Second})
	require.True(t, ok)
	end()
}
