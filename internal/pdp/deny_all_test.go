// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/pkg/capability"
)

// DenyAllPDP must deny every enforced method with a structured
// AUTHORIZATION_FAILED response — it is the fail-closed default the transport
// constructors substitute when no PDP is wired.
func TestDenyAllPDP_DeniesEveryMethod(t *testing.T) {
	t.Parallel()
	var p DenyAllPDP
	ctx := context.Background()

	resps := map[string]capability.EnforceResponse{
		"Decide":             p.Decide(ctx, "sid", EnforceTarget{Type: capability.TargetTypeTool, Name: "read_file"}, nil, ""),
		"DecideResourceRead": p.DecideResourceRead(ctx, "sid", "file:///x", ""),
		"DecidePromptGet":    p.DecidePromptGet(ctx, "sid", "summarize", ""),
		"DecideSampling":     p.DecideSampling(ctx, "sid", ""),
	}
	for name, resp := range resps {
		assert.Equalf(t, capability.DecisionDeny, resp.Decision, "%s: must deny", name)
		require.NotNilf(t, resp.Denial, "%s: deny must carry structured denial info", name)
		assert.Equalf(t, capability.ErrCodeAuthorizationFailed, resp.Denial.Code, "%s: denial code", name)
	}
}

// CheckKill fails closed: it gates the non-Decide transport paths (*/list
// forwarding, session-creating initialize, notification relay), so DenyAllPDP — which
// authorizes nothing — must block them too rather than let them proceed. Returning nil
// would leave the one hole in an otherwise total deny.
func TestDenyAllPDP_CheckKillDeniesUnconditionally(t *testing.T) {
	t.Parallel()
	var p DenyAllPDP
	deny := p.CheckKill(context.Background(), "sid")
	require.NotNil(t, deny, "CheckKill must fail closed, not return nil")
	require.NotNil(t, deny.Denial)
	assert.Equal(t, capability.ErrCodeAuthorizationFailed, deny.Denial.Code)
}

// Every */list filter must drop every entry (fail closed), while preserving the
// envelope's sibling fields (e.g. nextCursor).
func TestDenyAllPDP_FilterListsEmptyAll(t *testing.T) {
	t.Parallel()
	var p DenyAllPDP
	ctx := context.Background()

	cases := []struct {
		name  string
		field string
		in    string
		fn    func(context.Context, json.RawMessage) ListFilterResult
	}{
		{"tools", "tools", `{"tools":[{"name":"read_file"},{"name":"exfil"}],"nextCursor":"c1"}`, p.FilterToolsList},
		{"resources", "resources", `{"resources":[{"uri":"file:///a"}],"nextCursor":"c2"}`, p.FilterResourcesList},
		{"prompts", "prompts", `{"prompts":[{"name":"p1"}]}`, p.FilterPromptsList},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := tc.fn(ctx, json.RawMessage(tc.in)).Result
			var env map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(out, &env))

			var entries []json.RawMessage
			require.NoError(t, json.Unmarshal(env[tc.field], &entries))
			assert.Emptyf(t, entries, "%s: every entry must be filtered out", tc.name)

			// An empty input still fails closed to {"field":[]}, never the
			// original (empty) bytes.
			emptyOut := tc.fn(ctx, json.RawMessage(nil)).Result
			require.NoError(t, json.Unmarshal(emptyOut, &env))
			require.Contains(t, env, tc.field)
			require.NoError(t, json.Unmarshal(env[tc.field], &entries))
			assert.Emptyf(t, entries, "%s: empty input must fail closed to an empty list", tc.name)
		})
	}
}
