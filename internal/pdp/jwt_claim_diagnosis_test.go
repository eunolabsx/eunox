// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"context"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A capability claim that NAMES the target but whose condition suffix will not parse
// grants nothing (fail closed) and lands on the same deny as an absent claim. Reporting
// it as "not in the JWT capability claims" sent the operator looking for a claim that is
// right in front of them.
func TestJWTPDP_Decide_MalformedConditionSuffixIsDiagnosedDistinctly(t *testing.T) {
	t.Parallel()
	p := NewJWTPDP(JWTPDPOptions{AllowAnyAudience: true, AllowAnyIssuer: true})
	// "missing-separator" has no '=' , so parseCondSuffix refuses the suffix.
	ctx := WithJWTClaims(context.Background(), &JWTClaims{
		HasCapabilities: true,
		Capabilities:    []string{"tool:read_file?missing-separator"},
	})

	resp := p.Decide(ctx, "sess", EnforceTarget{Type: capability.TargetTypeTool, Name: "read_file"}, nil, "")

	require.Equal(t, capability.DecisionDeny, resp.Decision, "a claim that grants nothing must still deny")
	require.NotNil(t, resp.Denial)
	assert.Contains(t, resp.Denial.Message, "condition suffix could not be parsed",
		"the deny must say the claim exists but is malformed")
	assert.NotContains(t, resp.Denial.Message, "is not in the JWT capability claims",
		"reporting a present-but-malformed claim as absent sends the operator to the wrong fix")
}

// The ordinary case keeps its ordinary message: a target the token simply does not list.
func TestJWTPDP_Decide_AbsentClaimKeepsTheAbsentMessage(t *testing.T) {
	t.Parallel()
	p := NewJWTPDP(JWTPDPOptions{AllowAnyAudience: true, AllowAnyIssuer: true})
	ctx := WithJWTClaims(context.Background(), &JWTClaims{
		HasCapabilities: true,
		Capabilities:    []string{"tool:read_file"},
	})

	resp := p.Decide(ctx, "sess", EnforceTarget{Type: capability.TargetTypeTool, Name: "write_file"}, nil, "")

	require.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.True(t, strings.Contains(resp.Denial.Message, "is not in the JWT capability claims"),
		"an unlisted target must still read as absent, got: %s", resp.Denial.Message)
}
