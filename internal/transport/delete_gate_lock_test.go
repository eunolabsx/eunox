// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eunolabs/eunox/pkg/capability"

	"github.com/eunolabs/eunox/internal/pdp"
)

// audienceProbePDP allows everything but runs a hook inside CheckAudience, so a test can
// observe what the transport is holding when it calls that gate. Every other method comes
// from the embedded AlwaysAllowPDP.
type audienceProbePDP struct {
	pdp.AlwaysAllowPDP
	onCheck func()
}

func (p audienceProbePDP) CheckAudience(_ context.Context) *capability.EnforceResponse {
	if p.onCheck != nil {
		p.onCheck()
	}
	return nil
}

// TestHandleMCPDelete_AudienceGateNotUnderRegistryLock pins that handleMCPDelete evaluates
// the audience gate WITHOUT holding the session-registry write lock.
//
// PolicyDecisionPoint is an exported seam third parties implement. Every in-tree
// CheckAudience compares claims and returns, but the transport must not depend on that: a
// CheckAudience that blocks — network I/O, a contended lock — while p.mu was held would
// stall every session lookup, registration, and reap in the proxy.
//
// The probe calls proxy.sessionCount(), which takes p.mu.RLock(). p.mu is a
// sync.RWMutex and Go's RWMutex is not reentrant, so taking a read lock while the same
// goroutine holds the write lock blocks forever. If the gate is ever moved back under the
// lock this test stops completing rather than failing on a threshold, which is why the
// deadline below is generous — it is a liveness backstop, not a latency assertion.
func TestHandleMCPDelete_AudienceGateNotUnderRegistryLock(t *testing.T) {
	t.Parallel()

	proxy := &HTTPProxy{
		sessions:   make(map[string]*httpSession),
		shutdownMs: 50,
	}

	probed := make(chan struct{}, 1)
	route := &UpstreamRoute{
		name: "r",
		pdp: audienceProbePDP{onCheck: func() {
			// Deadlocks if the caller holds p.mu for writing.
			_ = proxy.sessionCount()
			select {
			case probed <- struct{}{}:
			default:
			}
		}},
		sink: &routeSink{},
	}

	sess := newTestSession(&httpSession{
		id:           "gate-sess",
		route:        route,
		done:         make(chan struct{}),
		upHTTPClient: &http.Client{},
	})
	proxy.mu.Lock()
	proxy.sessions[sess.id] = sess
	proxy.mu.Unlock()

	req := httptest.NewRequest(http.MethodDelete, "/mcp/r", http.NoBody)
	req.Header.Set(SessionHeader, sess.id)
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		defer close(done)
		proxy.handleMCPDelete(w, req, route)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("handleMCPDelete did not return: the audience gate is being evaluated while the " +
			"session-registry write lock is held, so a PDP that touches the registry (or any " +
			"other blocking implementation) deadlocks the proxy")
	}

	select {
	case <-probed:
	default:
		t.Error("CheckAudience was never called on the DELETE path; the audience gate is not being enforced")
	}
	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNoContent)
	}
	if proxy.sessionCount() != 0 {
		t.Error("session should have been removed after a permitted DELETE")
	}
}

// TestHandleMCPDelete_GateOrderPreserved pins that hoisting the audience half above the
// lock did not change WHEN the gates are applied: a DELETE for a session id that does not
// exist must still fall through to 404 rather than being refused by a gate, so a caller
// holding a wrong-audience token cannot use the response code to probe which session ids
// exist.
func TestHandleMCPDelete_GateOrderPreserved(t *testing.T) {
	t.Parallel()

	proxy := &HTTPProxy{
		sessions:   make(map[string]*httpSession),
		shutdownMs: 50,
	}
	denied := &capability.EnforceResponse{
		Denial: &capability.DenialInfo{Code: capability.ErrCodeAuthorizationFailed},
	}
	route := &UpstreamRoute{
		name: "r",
		pdp:  denyAudiencePDP{deny: denied},
		sink: &routeSink{},
	}

	req := httptest.NewRequest(http.MethodDelete, "/mcp/r", http.NoBody)
	req.Header.Set(SessionHeader, "no-such-session")
	w := httptest.NewRecorder()
	proxy.handleMCPDelete(w, req, route)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d — an unknown session id must 404, not be refused by a "+
			"gate, or the response code reveals which ids exist", w.Code, http.StatusNotFound)
	}
}

// denyAudiencePDP refuses every audience check.
type denyAudiencePDP struct {
	pdp.AlwaysAllowPDP
	deny *capability.EnforceResponse
}

func (p denyAudiencePDP) CheckAudience(_ context.Context) *capability.EnforceResponse {
	return p.deny
}

// TestHandleMCPDelete_AudienceDenialStillRefuses is the companion to the order test: for a
// session that DOES exist, a failed audience gate must still refuse the teardown and leave
// the session in place.
func TestHandleMCPDelete_AudienceDenialStillRefuses(t *testing.T) {
	t.Parallel()

	proxy := &HTTPProxy{
		sessions:   make(map[string]*httpSession),
		shutdownMs: 50,
	}
	route := &UpstreamRoute{
		name: "r",
		pdp: denyAudiencePDP{deny: &capability.EnforceResponse{
			Denial: &capability.DenialInfo{Code: capability.ErrCodeAuthorizationFailed},
		}},
		sink: &routeSink{},
	}
	sess := newTestSession(&httpSession{
		id:           "kept-sess",
		route:        route,
		done:         make(chan struct{}),
		upHTTPClient: &http.Client{},
	})
	proxy.mu.Lock()
	proxy.sessions[sess.id] = sess
	proxy.mu.Unlock()

	req := httptest.NewRequest(http.MethodDelete, "/mcp/r", http.NoBody)
	req.Header.Set(SessionHeader, sess.id)
	w := httptest.NewRecorder()
	proxy.handleMCPDelete(w, req, route)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if proxy.sessionCount() != 1 {
		t.Error("a refused DELETE must not tear the session down")
	}
}
