// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

// The L-6 invariant: a */list response eunox FILTERED never reaches the host carrying
// `cacheScope: public`. Every list an enforced route emits is authorization-context-
// specific, so a shared cache downstream of the proxy honoring an upstream `public`
// would serve one identity's narrowed view to another.
//
// The clamp lives at one encoder (encodeOrderedObjectWithList), so the table below is
// deliberately written against the PUBLIC filter entry points rather than that function:
// what has to hold is the property at the seam a transport calls, and a future filter
// path that re-emitted an envelope some other way would pass a test written one level
// down.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// listFilterer is the trio of ListFilterer methods, so one table can drive every
// implementation across every list flavor.
type filterCase struct {
	name  string
	field string
	fn    func(context.Context, json.RawMessage) ListFilterResult
	// entry is one catalog entry the PDP under test permits, so the filtered result is
	// non-empty and the clamp is exercised on a response that actually carries entries.
	entry string
}

// cacheScopeOf decodes the envelope's cacheScope member, reporting whether it is present.
func cacheScopeOf(t *testing.T, out json.RawMessage) (string, bool) {
	t.Helper()
	var env map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(out, &env))
	raw, ok := env[capability.ResultKeyCacheScope]
	if !ok {
		return "", false
	}
	var scope string
	if err := json.Unmarshal(raw, &scope); err != nil {
		return string(raw), true // a non-string value, reported verbatim
	}
	return scope, true
}

// enforcingFilterCases builds one case per (PDP, list flavor) pair that FILTERS.
// AlwaysAllowPDP is deliberately absent — it forwards the upstream catalog untouched
// and is covered by its own test below.
func enforcingFilterCases(t *testing.T) []filterCase {
	t.Helper()

	manifest := newTestManifestPDP(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"*"}},
		capability.Constraint{Target: "resource:file:///data/a", Actions: []string{"read"}},
		capability.Constraint{Target: "prompt:code_review", Actions: []string{"*"}},
	)
	jwt := NewJWTPDP(JWTPDPOptions{})
	var denyAll DenyAllPDP

	return []filterCase{
		{"manifest/tools", listKeyTools, manifest.FilterToolsList, `{"name":"read_file"}`},
		{"manifest/resources", listKeyResources, manifest.FilterResourcesList, `{"uri":"file:///data/a"}`},
		{"manifest/prompts", listKeyPrompts, manifest.FilterPromptsList, `{"name":"code_review"}`},
		{"jwt/tools", listKeyTools, jwt.FilterToolsList, `{"name":"read_file"}`},
		{"jwt/resources", listKeyResources, jwt.FilterResourcesList, `{"uri":"file:///data/a"}`},
		{"jwt/prompts", listKeyPrompts, jwt.FilterPromptsList, `{"name":"code_review"}`},
		{"denyall/tools", listKeyTools, denyAll.FilterToolsList, `{"name":"read_file"}`},
		{"denyall/resources", listKeyResources, denyAll.FilterResourcesList, `{"uri":"file:///data/a"}`},
		{"denyall/prompts", listKeyPrompts, denyAll.FilterPromptsList, `{"name":"code_review"}`},
	}
}

// filterCtx carries the JWT claims the JWT PDP needs to filter rather than fail closed;
// the manifest and deny-all PDPs ignore them.
func filterCtx() context.Context {
	return WithJWTClaims(context.Background(), &JWTClaims{
		AgentID:         "agent-1",
		Capabilities:    []string{"tool:read_file", "resource:file:///data/*", "prompt:code_review"},
		HasCapabilities: true,
	})
}

// TestFilteredList_NeverCarriesPublicCacheScope is the property the threat model's L-6
// mitigation rests on, asserted across every filter path and every upstream spelling of
// the member that a host could bind to it.
func TestFilteredList_NeverCarriesPublicCacheScope(t *testing.T) {
	t.Parallel()

	// Each upstream `cacheScope` value a filtered envelope could arrive carrying. The
	// non-`public` ones are here because the clamp is to `private`, not away from
	// `public`: an unrecognized or non-string scope is an ambiguity, and the only
	// reading of an ambiguous cacheability that cannot leak is the narrow one.
	scopes := []struct {
		name string
		raw  string
	}{
		{"public", `"public"`},
		{"unrecognized", `"session"`},
		{"empty string", `""`},
		{"non-string", `42`},
		{"null", `null`},
		{"object", `{"scope":"public"}`},
	}
	// Both spellings a case-insensitive host would bind. decodeOrderedObject refuses an
	// envelope carrying BOTH, so each is tested alone.
	keys := []string{capability.ResultKeyCacheScope, "CacheScope"}

	for _, tc := range enforcingFilterCases(t) {
		for _, sc := range scopes {
			for _, key := range keys {
				t.Run(tc.name+"/"+sc.name+"/"+key, func(t *testing.T) {
					in := json.RawMessage(`{"` + tc.field + `":[` + tc.entry +
						`,{"name":"never_permitted","uri":"file:///never"}],"` +
						key + `":` + sc.raw + `,"ttlMs":60000}`)

					out := tc.fn(filterCtx(), in).Result
					require.NotContains(t, string(out), capability.CacheScopePublic,
						"a filtered response must not carry cacheScope: public anywhere")

					scope, present := cacheScopeOf(t, out)
					if key == capability.ResultKeyCacheScope {
						require.True(t, present, "the member the upstream sent must survive, clamped")
						assert.Equal(t, capability.CacheScopePrivate, scope)
					} else {
						// The case-variant spelling is re-emitted under its own key; the
						// clamp applies in the fold space decodeOrderedObject admitted it in.
						var env map[string]json.RawMessage
						require.NoError(t, json.Unmarshal(out, &env))
						assert.JSONEq(t, `"`+capability.CacheScopePrivate+`"`, string(env[key]))
					}

					// ttlMs is a freshness hint and is preserved verbatim; clamping the
					// scope must not also drop the upstream's TTL.
					assert.Contains(t, string(out), `"ttlMs":60000`)
				})
			}
		}
	}
}

// TestFilteredList_PrivateCacheScopeIsByteStable pins that the clamp rewrites nothing when
// the upstream already said `private`: an upstream that conforms sees its own bytes back.
func TestFilteredList_PrivateCacheScopeIsByteStable(t *testing.T) {
	t.Parallel()
	in := json.RawMessage(`{"tools":[{"name":"read_file"}],"cacheScope":"private","ttlMs":1}`)
	out := filterListResult(in, listKeyTools, func(json.RawMessage) (bool, string) { return true, "" })
	assert.JSONEq(t, string(in), string(out.Result))
	assert.Equal(t, string(in), string(out.Result), "a conforming envelope must round-trip byte for byte")
}

// TestFilteredList_AbsentCacheScopeIsNotAdded is the other half of the clamp's scope. A
// 2025-11-25 list result has no cacheScope at all, and the filter layer has no revision in
// hand, so adding one would put a member that revision does not define on every old-revision
// response. The residual — a declaring upstream that OMITS the member its own revision
// requires — is stated on clampCacheScope rather than papered over by an unconditional add.
func TestFilteredList_AbsentCacheScopeIsNotAdded(t *testing.T) {
	t.Parallel()
	in := json.RawMessage(`{"tools":[{"name":"read_file"},{"name":"drop_me"}],"nextCursor":"c1"}`)
	out := filterListResult(in, listKeyTools, func(raw json.RawMessage) (bool, string) {
		return strings.Contains(string(raw), "read_file"), ""
	})
	_, present := cacheScopeOf(t, out.Result)
	assert.False(t, present, "the clamp must never introduce a member the upstream did not send")
	assert.Contains(t, string(out.Result), `"nextCursor":"c1"`)
}

// TestFilteredList_ClampPreservesKeyOrder pins that the substitution happens in place: the
// clamp writes the new value under the upstream's own key, at its own position, so the
// spec's deterministic-ordering SHOULD is not broken by the mitigation.
func TestFilteredList_ClampPreservesKeyOrder(t *testing.T) {
	t.Parallel()
	in := json.RawMessage(`{"cacheScope":"public","tools":[{"name":"a"}],"ttlMs":5,"nextCursor":"c"}`)
	out := filterListResult(in, listKeyTools, func(json.RawMessage) (bool, string) { return true, "" })
	assert.Equal(t, `{"cacheScope":"private","tools":[{"name":"a"}],"ttlMs":5,"nextCursor":"c"}`, string(out.Result))
}

// TestFilteredList_FailClosedEnvelopeCarriesNoScope pins the parse-failure path: the
// canonical empty listing drops every sibling, so there is no scope to clamp and none is
// invented.
func TestFilteredList_FailClosedEnvelopeCarriesNoScope(t *testing.T) {
	t.Parallel()
	out := filterListResult(json.RawMessage(`not json`), listKeyTools,
		func(json.RawMessage) (bool, string) { return true, "" })
	assert.Equal(t, `{"tools":[]}`, string(out.Result))
}

// TestJWTIntersection_ClampsCacheScope covers the one filter path that does NOT go through
// filterListResult's own encode: the intersection splices its claim-filtered entries back
// into the inner PDP's already-ordered envelope through replaceOrderedListField. It reaches
// the same encoder, which is why the clamp holds there too — asserted rather than assumed,
// since that path is where a second encoder would most plausibly be introduced.
func TestJWTIntersection_ClampsCacheScope(t *testing.T) {
	t.Parallel()
	inner := newTestManifestPDP(
		capability.Constraint{Target: "tool:read_file", Actions: []string{"*"}},
		capability.Constraint{Target: "tool:query_db", Actions: []string{"*"}},
	)
	p := NewJWTPDP(JWTPDPOptions{Inner: inner, KillSwitch: killswitch.NewInMemory()})
	ctx := WithJWTClaims(context.Background(), &JWTClaims{
		AgentID:         "agent-1",
		Capabilities:    []string{"tool:read_file"},
		HasCapabilities: true,
	})

	in := json.RawMessage(`{"tools":[{"name":"read_file"},{"name":"query_db"}],"cacheScope":"public"}`)
	out := p.FilterToolsList(ctx, in).Result

	assert.Equal(t, []string{"read_file"}, entryNames(t, out, "tools", "name"),
		"the intersection must still narrow to the claim")
	scope, present := cacheScopeOf(t, out)
	require.True(t, present)
	assert.Equal(t, capability.CacheScopePrivate, scope)
}

// TestPassThroughList_PreservesUpstreamCacheScope pins the deliberate exemption. The
// wiretap passthrough forwards the upstream's WHOLE catalog, identical for every caller,
// so an upstream `public` is a true statement about that response and clamping it would
// describe an authorization context the response does not have. Asserted so the exemption
// is a decision on the record rather than a path the clamp happens to miss.
func TestPassThroughList_PreservesUpstreamCacheScope(t *testing.T) {
	t.Parallel()
	var p AlwaysAllowPDP
	in := json.RawMessage(`{"tools":[{"name":"read_file"}],"cacheScope":"public"}`)
	out := p.FilterToolsList(context.Background(), in).Result
	scope, present := cacheScopeOf(t, out)
	require.True(t, present)
	assert.Equal(t, capability.CacheScopePublic, scope,
		"an unfiltered catalog keeps the upstream's own scope; see passThroughList")
}
