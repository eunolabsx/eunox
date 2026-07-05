// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// A wiretap PDP wired to the kill switch (NewAlwaysAllowPDP) allows until a kill
// is active, then hard-blocks every enforced method and the */list pre-check —
// so an operator's emergency stop halts even a policyless audit/wiretap route.
func TestAlwaysAllowPDP_KillSwitchHardBlocks(t *testing.T) {
	t.Parallel()
	ks := killswitch.NewInMemory()
	p := NewAlwaysAllowPDP(ks)
	ctx := context.Background()
	const sid = "sess-1"
	tgt := EnforceTarget{Type: capability.TargetTypeTool, Name: "read_file"}

	// Before any kill: wiretap forwards (allow) and the list pre-check passes.
	require.Equal(t, capability.DecisionAllow, p.Decide(ctx, sid, tgt, nil, "").Decision)
	require.Nil(t, p.CheckKill(ctx, sid))

	require.NoError(t, ks.ActivateGlobal(ctx))

	resps := map[string]capability.EnforceResponse{
		"Decide":             p.Decide(ctx, sid, tgt, nil, ""),
		"DecideResourceRead": p.DecideResourceRead(ctx, sid, "file:///x", ""),
		"DecidePromptGet":    p.DecidePromptGet(ctx, sid, "summarize", ""),
		"DecideSampling":     p.DecideSampling(ctx, sid, ""),
	}
	for name, resp := range resps {
		assert.Equalf(t, capability.DecisionDeny, resp.Decision, "%s after kill must deny", name)
		require.NotNilf(t, resp.Denial, "%s: deny must carry denial info", name)
		assert.Equalf(t, capability.ErrCodeKillSwitch, resp.Denial.Code, "%s denial code", name)
	}
	require.NotNil(t, p.CheckKill(ctx, sid), "CheckKill must block */list enumeration after a kill")
}

// A zero-value AlwaysAllowPDP{} (no kill switch wired) keeps pure-passthrough
// behavior: it never blocks, even when a kill switch elsewhere is active.
func TestAlwaysAllowPDP_NoKillSwitch_NeverBlocks(t *testing.T) {
	t.Parallel()
	var bare AlwaysAllowPDP
	ctx := context.Background()
	tgt := EnforceTarget{Type: capability.TargetTypeTool, Name: "read_file"}

	assert.Nil(t, bare.CheckKill(ctx, "sess-1"))
	assert.Equal(t, capability.DecisionAllow, bare.Decide(ctx, "sess-1", tgt, nil, "").Decision)
	assert.Equal(t, capability.DecisionAllow, bare.DecideSampling(ctx, "sess-1", "").Decision)
}
