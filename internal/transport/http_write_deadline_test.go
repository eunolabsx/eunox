// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/capability"
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

// TestWriteSessionCreateError_ReArmsForTheTeardownItMayHaveJustPaid is the regression for the
// one teardown-shaped write the teardown re-arm missed.
//
// The session-creating initialize arm arms a window covering ESTABLISHMENT. Its failure paths
// then spend time that window does not budget for: a startup drift refusal runs sess.close
// synchronously, whose worst case is two sequential --shutdown-timeout bounds (SIGTERM, then
// SIGKILL), and the ctx-expiry arm adds another bounded wait after that. Nothing re-armed
// before http.Error, so at a large shutdown budget against a SIGTERM-ignoring subprocess the
// 500 carrying the drift refusal — the FM-5 rug-pull event the check exists to deliver —
// reached the host as a connection error instead. Every arm re-arms now, because which arm was
// taken says nothing about how long the failing establishment ran.
func TestWriteSessionCreateError_ReArmsForTheTeardownItMayHaveJustPaid(t *testing.T) {
	t.Parallel()

	const shutdownMs = 40_000
	// Two sequential shutdown budgets, the same worst case the teardown spelling covers.
	want := 2*msToDuration(shutdownMs) + writeSlack

	cases := []struct {
		name string
		err  error
	}{
		// The drift refusal and any other upstream-start failure land here, and this is the
		// arm that pays a full sess.close before it writes.
		{name: "upstream start failure (the drift refusal's arm)", err: errors.New("drift: upstream tool set changed")},
		{name: "session limit", err: errSessionLimit},
		{name: "raced reap", err: errRacedReap},
		{name: "shutting down", err: errShuttingDown},
		{name: "adoption of the race winner failed", err: errSessionExists},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// No sink and no route: writeSessionCreateError's recording leg tolerates both, and
			// what is under test is the deadline, not the record.
			proxy := &HTTPProxy{sessions: make(map[string]*httpSession), shutdownMs: shutdownMs, stderr: io.Discard}
			req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{}"))
			w := newDeadlineRecorder()
			start := time.Now()
			proxy.writeSessionCreateError(context.Background(), w, req, nil, tc.err)

			armed := w.armed()
			if len(armed) != 1 {
				t.Fatalf("armed %d write deadlines, want exactly the teardown re-arm", len(armed))
			}
			if got := armed[0].Sub(start); got < want-2*time.Second {
				t.Errorf("armed a %v window, want at least %v: a failure path that just paid a full session teardown must not write under the establishment window", got, want)
			}
		})
	}
}

// TestAwaitServableWorker_ReArmsForTheEstablishmentItJustWaitedOut is the joiner-side twin of
// the cell above.
//
// A serving leg that waited for a worker to finish coming up has spent part of the window its
// entry armed — and on the teardown that makes the wait FAIL, the establishment budget plus the
// same two sequential shutdown budgets the creating path re-arms for, since `established` closes
// only when the constructor returns and that is after its close. Both outcomes therefore write
// against a window armed for neither, which is why the re-arm covers both rather than sitting on
// the refusal alone: the success path's own exits (a swallowed notification's 202, a saturation
// refusal, the SSE leg's kill 403) write with no re-arm of their own.
func TestAwaitServableWorker_ReArmsForTheEstablishmentItJustWaitedOut(t *testing.T) {
	t.Parallel()

	const shutdownMs = 40_000
	want := 2*msToDuration(shutdownMs) + writeSlack

	post := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsCall}
	notif := mcp.RPCMsg{JSONRPC: "2.0", Method: mcp.MethodNotificationsInitialized}

	for _, tc := range []struct {
		name     string
		msg      mcp.RPCMsg
		leg      transportLeg
		survived bool
	}{
		{name: "POST request, worker torn down", msg: post, leg: legHTTPPost},
		{name: "POST notification, worker torn down", msg: notif, leg: legHTTPPost},
		{name: "SSE GET, worker torn down", leg: legSSEGet},
		{name: "POST request, worker came up", msg: post, leg: legHTTPPost, survived: true},
		{name: "SSE GET, worker came up", leg: legSSEGet, survived: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			proxy := &HTTPProxy{sessions: make(map[string]*httpSession), shutdownMs: shutdownMs, stderr: io.Discard}
			route := &UpstreamRoute{name: "up1", pdp: pdp.AlwaysAllowPDP{}, sink: &routeSink{}}
			// Establishment has ALREADY ended, so the cell measures the re-arm rather than a
			// wall clock: what makes this leg a waiter is that it found the worker coming up.
			established := make(chan struct{})
			close(established)
			sess := newTestSession(&httpSession{id: "w1", route: route, done: make(chan struct{}), established: established})
			sess.initInProgress.Store(true)
			if tc.survived {
				proxy.mu.Lock()
				proxy.sessions[sess.id] = sess
				proxy.mu.Unlock()
			}

			w := newDeadlineRecorder()
			req := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
			start := time.Now()
			if got := proxy.awaitServableWorker(w, req, route, sess, tc.msg, tc.leg); got != tc.survived {
				t.Fatalf("servable = %v, want %v", got, tc.survived)
			}

			armed := w.armed()
			if len(armed) != 1 {
				t.Fatalf("armed %d write deadlines, want exactly the post-wait re-arm", len(armed))
			}
			if got := armed[0].Sub(start); got < want-2*time.Second {
				t.Errorf("armed a %v window, want at least %v: this leg waited out an establishment that can end in a full session teardown", got, want)
			}
		})
	}
}

// Nothing waited for is nothing to re-arm.
//
// The re-arm is a syscall, and every request on an established worker takes this path — a window
// that has not moved must not be charged for one.
func TestAwaitServableWorker_DoesNotReArmWhenItDidNotWait(t *testing.T) {
	t.Parallel()
	proxy := &HTTPProxy{sessions: make(map[string]*httpSession), shutdownMs: 5000, stderr: io.Discard}
	route := &UpstreamRoute{name: "up1", pdp: pdp.AlwaysAllowPDP{}, sink: &routeSink{}}
	sess := newTestSession(&httpSession{id: "w1", route: route, done: make(chan struct{})})
	proxy.mu.Lock()
	proxy.sessions[sess.id] = sess
	proxy.mu.Unlock()

	w := newDeadlineRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
	if !proxy.awaitServableWorker(w, req, route, sess, mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsCall}, legHTTPPost) {
		t.Fatal("an established worker was refused")
	}
	if armed := w.armed(); len(armed) != 0 {
		t.Errorf("armed %d write deadlines for a leg that never waited", len(armed))
	}
}

// A waiter whose OWN context ended is answered nothing, recorded nothing, and charged nothing.
//
// The wait's false verdict has two causes and only one of them is about the worker: a caller that
// hung up may have been parked on a worker establishing perfectly well. Answering it would spend
// a kill-store round trip and, under an active stop, sign a refusal against a live registration
// on behalf of a client that is already gone.
func TestAwaitServableWorker_SaysNothingToACallerThatIsAlreadyGone(t *testing.T) {
	t.Parallel()
	proxy := &HTTPProxy{sessions: make(map[string]*httpSession), shutdownMs: 5000, stderr: io.Discard}
	route := &UpstreamRoute{name: "up1", pdp: pdp.AlwaysAllowPDP{}, sink: &routeSink{}}
	sess := newTestSession(&httpSession{id: "w1", route: route, done: make(chan struct{}), established: make(chan struct{})})
	sess.initInProgress.Store(true)
	proxy.mu.Lock()
	proxy.sessions[sess.id] = sess
	proxy.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w := newDeadlineRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody).WithContext(ctx)
	if proxy.awaitServableWorker(w, req, route, sess,
		mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsCall}, legHTTPPost) {
		t.Fatal("a departed caller was told its worker is servable")
	}
	if armed := w.armed(); len(armed) != 0 {
		t.Errorf("armed %d write deadlines for a caller that is already gone", len(armed))
	}
	if body := w.Body.String(); body != "" {
		t.Errorf("answered %q to a departed caller, about a worker that may be establishing fine", body)
	}
}
