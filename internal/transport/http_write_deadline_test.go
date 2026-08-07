// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"encoding/json"
	"github.com/eunolabs/eunox/pkg/capability"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
)

// deadlineRecorder is a ResponseWriter that records every write deadline armed on it, in
// order, so a test can assert the window a handler leg gave the client-facing write.
// http.ResponseController finds SetWriteDeadline by interface assertion, so implementing it
// beside an embedded recorder is all that is needed.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	mu        sync.Mutex
	deadlines []time.Time
}

func (d *deadlineRecorder) SetWriteDeadline(t time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.deadlines = append(d.deadlines, t)
	return nil
}

func (d *deadlineRecorder) armed() []time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]time.Time(nil), d.deadlines...)
}

func newDeadlineRecorder() *deadlineRecorder {
	return &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
}

// TestRearmWriteDeadline_WindowFloorsAtHTTPWriteTimeout pins the one rule every
// response-write deadline in this package now shares: the window is the leg's own budget
// plus writeSlack, never shorter than httpWriteTimeout.
//
// The floor is the point. A write deadline bounds how long the CLIENT may take to read a
// response, which has nothing to do with how long the UPSTREAM was given — so a deployment
// running a small --upstream-timeout must not get a proportionally small window for its
// writes. Every leg that hand-computed its own window is now routed through these helpers.
func TestRearmWriteDeadline_WindowFloorsAtHTTPWriteTimeout(t *testing.T) {
	t.Parallel()

	// tolerance covers the time.Now() sample inside the helper versus the one here.
	const tolerance = 2 * time.Second

	cases := []struct {
		name string
		arm  func(w http.ResponseWriter)
		want time.Duration
	}{
		{
			name: "no budget arms the floor",
			arm:  func(w http.ResponseWriter) { rearmWriteDeadline(w, 0) },
			want: httpWriteTimeout,
		},
		{
			name: "budget below the floor still arms the floor",
			arm:  func(w http.ResponseWriter) { rearmWriteDeadline(w, 50) },
			want: httpWriteTimeout,
		},
		{
			name: "budget above the floor arms budget plus slack",
			arm:  func(w http.ResponseWriter) { rearmWriteDeadline(w, 60_000) },
			want: 60*time.Second + writeSlack,
		},
		{
			name: "duration spelling, below the floor",
			arm:  func(w http.ResponseWriter) { rearmWriteDeadlineFor(w, sessionStartTimeout) },
			want: httpWriteTimeout,
		},
		{
			name: "duration spelling, above the floor",
			arm:  func(w http.ResponseWriter) { rearmWriteDeadlineFor(w, 90*time.Second) },
			want: 90*time.Second + writeSlack,
		},
		{
			name: "duration spelling, no budget",
			arm:  func(w http.ResponseWriter) { rearmWriteDeadlineFor(w, 0) },
			want: httpWriteTimeout,
		},
		{
			// Teardown doubles its budget: close waits --shutdown-timeout for the
			// subprocess, then SIGKILLs it and waits the same budget again.
			name: "teardown spelling doubles the budget",
			arm:  func(w http.ResponseWriter) { rearmWriteDeadlineForTeardown(w, 40_000) },
			want: 80*time.Second + writeSlack,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := newDeadlineRecorder()
			start := time.Now()
			tc.arm(w)
			armed := w.armed()
			if len(armed) != 1 {
				t.Fatalf("armed %d deadlines, want exactly 1", len(armed))
			}
			got := armed[0].Sub(start)
			if got < tc.want-tolerance || got > tc.want+tolerance {
				t.Errorf("armed window %v, want %v (+/- %v)", got, tc.want, tolerance)
			}
		})
	}
}

// TestHandleMCPPost_EntryDeadlineFloorsAtHTTPWriteTimeout is the regression for the
// small-budget case at the handler-entry arm.
//
// That site used to compute its own window: --upstream-timeout plus slack when the budget
// was set, the fixed backstop otherwise. With a budget BELOW httpWriteTimeout that armed a
// window shorter than every other leg's — a 50 ms upstream timeout gave the client just over
// five seconds to read any response written before the pre-encode re-arm, including the
// early 4xx/404 legs that return without one. Routed through the shared helper, the floor
// applies here too.
func TestHandleMCPPost_EntryDeadlineFloorsAtHTTPWriteTimeout(t *testing.T) {
	t.Parallel()

	rt := &UpstreamRoute{pdp: pdp.AlwaysAllowPDP{}}
	proxy := &HTTPProxy{sessions: make(map[string]*httpSession), upstreamTimeMs: 50}

	// Any body reaching the entry arm proves the point; an unknown session id returns
	// early (404) so nothing re-arms afterwards and the entry window is the only one.
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", CTJSON)
	req.Header.Set(SessionHeader, "no-such-session")

	w := newDeadlineRecorder()
	start := time.Now()
	proxy.handleMCPPost(w, req, rt)

	armed := w.armed()
	if len(armed) == 0 {
		t.Fatal("handleMCPPost armed no write deadline at entry")
	}
	if got := armed[0].Sub(start); got < httpWriteTimeout {
		t.Errorf("entry write window %v is shorter than httpWriteTimeout (%v): a small --upstream-timeout must not shrink the window a client gets to read its response", got, httpWriteTimeout)
	}
}

// TestHandleMCPPost_SessionStartDeadlineFloorsAtHTTPWriteTimeout is the same regression for
// the session-creating initialize arm, which covers the larger of sessionStartTimeout and
// --upstream-timeout. Its hand-written form lacked the floor as well, so with the default
// 20-second start budget it armed 25 seconds where every other leg gets at least 30.
func TestHandleMCPPost_SessionStartDeadlineFloorsAtHTTPWriteTimeout(t *testing.T) {
	t.Parallel()

	fu := newFullFakeUpstream()
	upURL := startFakeUpstream(t, fu)
	proxy, _ := newTestRemoteProxy(t, upURL, httpProxyOptions{UpstreamTimeMs: 50})

	var route *UpstreamRoute
	for _, r := range proxy.routes {
		route = r
		break
	}
	if route == nil {
		t.Fatal("test proxy has no route")
	}

	msg := mcp.RPCMsg{
		JSONRPC: "2.0",
		ID:      mcp.RawJSON(`1`),
		Method:  mcp.MethodInitialize,
		Params:  json.RawMessage(`{"protocolVersion":"` + capability.Revision20251125.String() + `","capabilities":{},"clientInfo":{"name":"t","version":"0"}}`),
	}
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal initialize: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(string(data)))
	req.Header.Set("Content-Type", CTJSON)

	w := newDeadlineRecorder()
	start := time.Now()
	proxy.handleMCPPost(w, req, route)

	armed := w.armed()
	if len(armed) < 2 {
		t.Fatalf("armed %d write deadlines, want at least the entry arm and the session-start arm", len(armed))
	}
	for i, d := range armed {
		if got := d.Sub(start); got < httpWriteTimeout {
			t.Errorf("write deadline %d armed a %v window, shorter than httpWriteTimeout (%v)", i, got, httpWriteTimeout)
		}
	}
}
