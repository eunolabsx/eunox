// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The wrapped-nil Inner: a JWTPDPOptions.Inner holding a typed nil is not a policy backstop, and
// the wrapper must deny an identity-only token rather than dereference it.
//
// `case nil` in innerEnforces matches an untyped nil interface alone, so before normalizedInner a
// (*ManifestPDP)(nil) fell to the default arm, was treated as a real backstop, and the first token
// with no mcp.capabilities panicked a request goroutine — on stdio, the process — where this
// package's whole contract is to fail closed.

package pdp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/pkg/capability"
)

// typedNilInners are the wrapped-nil shapes a caller can hand the constructor. Both concrete PDPs,
// since either can be built as a nil pointer by a consumer wiring one conditionally.
func typedNilInners() map[string]PolicyDecisionPoint {
	return map[string]PolicyDecisionPoint{
		"nil *ManifestPDP": (*ManifestPDP)(nil),
		"nil *JWTPDP":      (*JWTPDP)(nil),
	}
}

// toolsListResult is a minimal upstream tools/list body, so the filter leg below has a catalog to
// empty rather than passing through on absent input.
var toolsListResult = []byte(`{"tools":[{"name":"read_file"}]}`)

// TestNewJWTPDP_TypedNilInnerIsNotABackstop pins the normalization at the CONSTRUCTOR, which is
// what makes every `p.inner != nil` guard in this package correct for the wrapped-nil shape rather
// than each of them needing its own reflection.
func TestNewJWTPDP_TypedNilInnerIsNotABackstop(t *testing.T) {
	t.Parallel()
	for name, inner := range typedNilInners() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			key := newTestKey(t, "k1")
			p, cleanup := makeJWTPDPWithInner(t, key, inner)
			defer cleanup()

			assert.Nil(t, p.inner, "a typed-nil Inner must be collapsed to a plain nil at construction; every guard below reads this field with a bare != nil")
			assert.False(t, p.innerEnforces(), "a typed nil is not a policy backstop, and treating it as one is what dereferences it")
		})
	}
}

// TestNewJWTPDPWithCache_TypedNilInnerIsNotABackstop covers the second constructor: a gateway's
// per-route wrappers are built through it, so a route wired with a conditionally-nil inner reaches
// this one rather than NewJWTPDP.
func TestNewJWTPDPWithCache_TypedNilInnerIsNotABackstop(t *testing.T) {
	t.Parallel()
	p := NewJWTPDPWithCache(JWTPDPOptions{Inner: (*ManifestPDP)(nil), AllowAnyIssuer: true, AllowAnyAudience: true},
		capability.NewJWKSCache(capability.JWKSCacheConfig{}))
	assert.Nil(t, p.inner)
	assert.False(t, p.innerEnforces())
}

// TestJWTDecide_TypedNilInner_DeniesIdentityOnlyToken is the failure the normalization exists to
// prevent, on the path that reaches it: an identity-only token (no mcp.capabilities) with a
// wrapped-nil inner used to dispatch Decide on the nil receiver. The wrapper owes a deny.
func TestJWTDecide_TypedNilInner_DeniesIdentityOnlyToken(t *testing.T) {
	t.Parallel()
	key := newTestKey(t, "k1")
	p, cleanup := makeJWTPDPWithInner(t, key, (*ManifestPDP)(nil))
	defer cleanup()

	ctx := makeJWTCtx(t, p, makeJWTToken(t, key, nil))
	resp := p.Decide(ctx, "sess", EnforceTarget{Type: capability.TargetTypeTool, Name: "any_tool"}, nil, "")

	assert.Equal(t, capability.DecisionDeny, resp.Decision, "no capability claim and no real inner policy: JWT mode must fail closed")
	require.NotNil(t, resp.Denial)
	assert.Equal(t, capability.ErrCodeAuthorizationFailed, resp.Denial.Code)
}

// TestJWTLegs_TypedNilInner_DoNotDereference walks the other legs that reach the inner through a
// bare nil check, so the constructor's one normalization is pinned as covering all of them rather
// than only the one that motivated it.
func TestJWTLegs_TypedNilInner_DoNotDereference(t *testing.T) {
	t.Parallel()
	key := newTestKey(t, "k1")
	p, cleanup := makeJWTPDPWithInner(t, key, (*ManifestPDP)(nil))
	defer cleanup()
	ctx := makeJWTCtx(t, p, makeJWTToken(t, key, nil))

	assert.Equal(t, capability.DecisionDeny,
		p.DecideResourceCancel(ctx, "sess", "file:///x", "").Decision,
		"a cancel with no capability claim and no real inner has nothing authorizing it")
	assert.Equal(t, capability.DecisionDeny,
		p.DecideSampling(ctx, "sess", "").Decision,
		"sampling is deny-by-default with no inner manifest opt-in")
	assert.Zero(t, p.FilterToolsList(ctx, toolsListResult).Kept(),
		"an identity-only token with no backstop sees no catalog")
	p.ReleaseSession(ctx, "sess")
	cleared, err := p.CommitDeclassified(ctx, "sess", nil)
	// Nothing to clear, so nothing to fail: what is pinned here is that the commit leg reaches its
	// own no-inner answer instead of dispatching on the wrapped nil.
	assert.NoError(t, err)
	assert.Empty(t, cleared)
}
