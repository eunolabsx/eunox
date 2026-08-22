// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// TestStdioForwardHostNotification_KillLandingDuringTheBarrierIsObserved is the regression for
// a one-message hole in the emergency stop.
//
// The gate order lets the NOTIFICATION framing take its revocation check in the shared
// prologue, justified by that framing waiting for nothing. True on the gateway; false on stdio,
// where the wire-ordering barrier parks the notification behind every request the host already
// sent — an UNBOUNDED wait under --upstream-timeout=0. A kill landing inside that window was
// never re-observed, so host-controlled bytes reached a revoked session's upstream with no
// KILL_SWITCH record. This is the same "take it FRESH past the wait" rule the request framing
// has always followed.
func TestStdioForwardHostNotification_KillLandingDuringTheBarrierIsObserved(t *testing.T) {
	ks := killswitch.NewInMemory()
	dp := pdp.NewManifestPDP(
		[]capability.Constraint{{Target: "tool:*", Actions: []string{"call"}}},
		enforcement.New(), ks)

	p, _, uw := newStdioProxyForSamplingTest(t, dp)
	p.sessionID = "barrier-sess"
	sink, logPath := newTempAuditSink(t)
	p.sink = sink

	// Hold the ordering barrier open, exactly as an in-flight host request does, and activate
	// the kill while the notification is parked behind it.
	p.fwdHostWrites.Add(1)
	p.fwdHostInFlight.Add(1)

	// The releasing goroutine makes NO assertions of its own. require's Goexit would skip the
	// Done below, leaving the notification blocked in the barrier forever and turning a clean
	// failure into a package-wide timeout — the one shape a helper goroutine must not have.
	// The error is carried back and checked on the test goroutine instead.
	var (
		wg      sync.WaitGroup
		killErr error
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer p.fwdHostWrites.Done()
		defer p.fwdHostInFlight.Add(-1)
		// The kill lands strictly INSIDE the wait: the notification has already cleared the
		// prologue's check by the time this runs.
		time.Sleep(50 * time.Millisecond)
		killErr = ks.KillSession(context.Background(), "barrier-sess")
	}()

	msg := mcp.RPCMsg{
		JSONRPC: "2.0",
		Method:  methodNotificationsProgress,
		Params:  json.RawMessage(`{"progressToken":1,"progress":1}`),
	}
	require.True(t, msg.IsNotification())

	stop := p.forwardHostNotification(context.Background(), msg)
	wg.Wait()
	require.NoError(t, killErr)

	assert.False(t, stop, "a kill is a refusal, not a shutdown signal")
	assert.Empty(t, uw.messages, "host bytes must not reach a revoked session's upstream")

	_ = sink.Close()
	rec := findAuditRecordByMethod(readAuditRecords(t, logPath), methodNotificationsProgress, "deny")
	require.NotNil(t, rec, "the refusal must land on the tape; a silent drop is the blind spot the gate order exists to close")
	code, _ := rec["denial_code"].(string)
	assert.Equal(t, "KILL_SWITCH", code)
}

// TestStdioForwardHostNotification_NoKillStillForwards is the control: the re-check must not
// turn every notification into a refusal, and the barrier must still release normally.
func TestStdioForwardHostNotification_NoKillStillForwards(t *testing.T) {
	ks := killswitch.NewInMemory()
	dp := pdp.NewManifestPDP(
		[]capability.Constraint{{Target: "tool:*", Actions: []string{"call"}}},
		enforcement.New(), ks)

	p, _, uw := newStdioProxyForSamplingTest(t, dp)
	p.sessionID = "live-sess"

	msg := mcp.RPCMsg{
		JSONRPC: "2.0",
		Method:  methodNotificationsProgress,
		Params:  json.RawMessage(`{"progressToken":1,"progress":1}`),
	}
	require.False(t, p.forwardHostNotification(context.Background(), msg))
	assert.Len(t, uw.messages, 1, "an unrevoked session's notification must still reach the upstream")
}
