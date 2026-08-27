// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// What a failed session creation tells the caller: a benign lifecycle race is a 503 the client
// retries, and only a genuine upstream-start failure is the opaque 500.
//
// errSessionExists was in the first family and answered as the second. It is raised when a
// concurrent first request on the same caller identity won the registration race, and reaches
// writeSessionCreateError only when the ADOPTION that normally absorbs it also failed — the winner
// torn down while this request awaited it. That is the same shape as errRacedReap and
// errShuttingDown, and it was answered "failed to start upstream: a worker is already registered
// for this identity" on a status no client retries, about an upstream that started fine.

package transport

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWriteSessionCreateError_MapsTheRetryableRacesToRetry(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantBody   string
		// wantStderr marks the arm that logs: the raw error may carry a command path, IP:port or
		// TLS detail, so it goes to the operator's console and never to the caller.
		wantStderr bool
	}{
		{
			name:       "a concurrent first request won the race and its worker is already gone",
			err:        errSessionExists,
			wantStatus: http.StatusServiceUnavailable,
			wantBody:   "retry",
		},
		{
			name:       "session limit",
			err:        errSessionLimit,
			wantStatus: http.StatusServiceUnavailable,
			wantBody:   "session limit reached",
		},
		{
			name:       "raced reap",
			err:        errRacedReap,
			wantStatus: http.StatusServiceUnavailable,
			wantBody:   "retry",
		},
		{
			name:       "shutting down",
			err:        errShuttingDown,
			wantStatus: http.StatusServiceUnavailable,
			wantBody:   "retry",
		},
		{
			name:       "upstream start failure",
			err:        errors.New("exec: \"/opt/secret/path/mcp-server\": no such file or directory"),
			wantStatus: http.StatusInternalServerError,
			wantBody:   "upstream unavailable",
			wantStderr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var errOut bytes.Buffer
			// No sink and no route: only the errSessionLimit arm records, and what is under test
			// here is the answer, not the record.
			proxy := &HTTPProxy{sessions: make(map[string]*httpSession), stderr: &errOut}
			req := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
			w := httptest.NewRecorder()

			proxy.writeSessionCreateError(context.Background(), w, req, nil, tc.err)

			assert.Equal(t, tc.wantStatus, w.Code)
			assert.Contains(t, w.Body.String(), tc.wantBody)
			if tc.wantStderr {
				assert.Contains(t, errOut.String(), "failed to start upstream")
				return
			}
			assert.Empty(t, errOut.String(),
				"a benign lifecycle race is not an upstream-start failure and must not be reported to the operator as one")
			assert.NotContains(t, strings.ToLower(w.Body.String()), "upstream",
				"the caller is told to retry, not that an upstream that started fine failed to")
		})
	}
}
