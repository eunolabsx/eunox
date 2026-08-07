// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// TestMethodRegistry_EveryMethodDeclaresRevisionMembership is the build gate the
// per-revision tables rest on, mirroring the token registry's TestTokenSince_ pattern.
//
// An entry declaring no revision (or one this build does not speak) contributes to no
// table, so the method silently stops being dispatched under EVERY revision — a
// fail-closed outcome, but a silent one. This turns it into a build failure.
func TestMethodRegistry_EveryMethodDeclaresRevisionMembership(t *testing.T) {
	t.Parallel()
	published := capability.PublishedRevisions()
	for method, spec := range methodRegistry {
		if len(spec.In) == 0 {
			t.Errorf("method %q declares no revision membership; every entry must name the revisions it exists in (removal is expressed by absence from In, never by an empty In)", method)
			continue
		}
		for _, rev := range spec.In {
			if !slices.Contains(published, rev) {
				t.Errorf("method %q declares revision %q, which this build does not speak (%v)", method, rev, published)
			}
		}
		if len(slices.Compact(slices.Clone(spec.In))) != len(spec.In) {
			t.Errorf("method %q declares a duplicate revision in %v", method, spec.In)
		}
		if spec.Enforced && spec.Handler == nil {
			t.Errorf("method %q is marked Enforced but declares no handler", method)
		}
		if spec.Handler == nil && spec.Notification == notifyUnmapped {
			t.Errorf("method %q declares neither a handler nor a notification disposition, so it dispatches nowhere — delete the entry rather than leaving a no-op", method)
		}
	}
}

// TestRevisionDispatch_ExactSetPerRevision pins each revision's EXACT four tables, derived
// from the declarations rather than restated by hand at the call sites.
//
// Exact, not "contains": a method silently gaining membership in a revision that removed it
// is the failure this workstream exists to prevent, and only an exact set catches an
// addition. The 2026-07-28 sets are deliberately smaller than the spec's full method list —
// server/discover, subscriptions/listen and tasks/* land with the workstreams that implement
// them, and until then they fall to the fail-closed default like any unknown method.
func TestRevisionDispatch_ExactSetPerRevision(t *testing.T) {
	t.Parallel()
	cases := []struct {
		rev      capability.Revision
		decide   []string
		local    []string
		forward  []string
		swallow  []string
		absentOK []string // methods asserted to be dispatched NOWHERE under this revision
	}{
		{
			rev: capability.Revision20251125,
			decide: []string{
				capability.MethodPromptsGet,
				capability.MethodResourcesRead,
				capability.MethodResourcesSubscribe,
				capability.MethodResourcesUnsubscribe,
				capability.MethodToolsCall,
			},
			local: []string{
				capability.MethodPromptsList,
				capability.MethodResourcesList,
				capability.MethodToolsList,
				mcp.MethodInitialize,
				methodPing,
			},
			forward: []string{
				methodNotificationsCancelled,
				methodNotificationsProgress,
				methodNotificationsRootsListChanged,
			},
			swallow: []string{
				mcp.MethodInitialize,
				mcp.MethodNotificationsInitialized,
			},
			absentOK: []string{"server/discover", "subscriptions/listen", "tasks/get"},
		},
		{
			rev: capability.Revision20260728,
			decide: []string{
				capability.MethodPromptsGet,
				capability.MethodResourcesRead,
				capability.MethodToolsCall,
			},
			local: []string{
				capability.MethodPromptsList,
				capability.MethodResourcesList,
				capability.MethodToolsList,
			},
			forward: []string{
				methodNotificationsCancelled,
				methodNotificationsProgress,
			},
			swallow: nil,
			// The handshake, the liveness probe, the resources/subscribe pair and the roots
			// notification are all constructs this revision removed: each must fall to the
			// fail-closed default, not to another revision's table.
			absentOK: []string{
				mcp.MethodInitialize,
				mcp.MethodNotificationsInitialized,
				methodPing,
				capability.MethodResourcesSubscribe,
				capability.MethodResourcesUnsubscribe,
				methodNotificationsRootsListChanged,
				"server/discover",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.rev.String(), func(t *testing.T) {
			t.Parallel()
			tables := tablesFor(tc.rev)
			assertKeySet(t, "decide", handlerKeys(tables.decide), tc.decide)
			assertKeySet(t, "local", handlerKeys(tables.local), tc.local)
			assertKeySet(t, "forwardNotifications", markerKeys(tables.forwardNotifications), tc.forward)
			assertKeySet(t, "swallowNotifications", markerKeys(tables.swallowNotifications), tc.swallow)
			for _, m := range tc.absentOK {
				if _, ok := tables.decide[m]; ok {
					t.Errorf("%q must not be an enforced method under %s", m, tc.rev)
				}
				if _, ok := tables.local[m]; ok {
					t.Errorf("%q must not be locally answered under %s", m, tc.rev)
				}
				if isForwardableHostNotification(tc.rev, m) {
					t.Errorf("%q must not be a forwardable notification under %s", m, tc.rev)
				}
				if isSwallowedHostNotification(tc.rev, m) {
					t.Errorf("%q must not be a swallowed notification under %s", m, tc.rev)
				}
			}
		})
	}
}

// TestTablesFor_UnknownRevisionDispatchesNothing: an unset revision inherits the old
// revision's tables (the surface eunox already shipped, so a caller that never negotiated
// sees no change), but a revision this build does not speak dispatches NOTHING rather than
// borrowing another revision's set.
func TestTablesFor_UnknownRevisionDispatchesNothing(t *testing.T) {
	t.Parallel()
	unset := tablesFor("")
	if len(unset.decide) != len(tablesFor(capability.DefaultRevision).decide) {
		t.Errorf("an unset revision must resolve to the default revision's tables")
	}
	unknown := tablesFor(capability.Revision("1999-01-01"))
	if len(unknown.decide)+len(unknown.local)+len(unknown.forwardNotifications)+len(unknown.swallowNotifications) != 0 {
		t.Errorf("an unspoken revision must dispatch nothing, got decide=%d local=%d forward=%d swallow=%d",
			len(unknown.decide), len(unknown.local), len(unknown.forwardNotifications), len(unknown.swallowNotifications))
	}
	if isEnforcedMethod(capability.Revision("1999-01-01"), capability.MethodToolsCall) {
		t.Error("tools/call must not be enforced under a revision this build does not speak")
	}
}

// TestBuildRevisionDispatch_SkipsUndeclaredEntries pins the builder's own fail-closed
// behavior directly, since the registry itself can never carry such an entry (the build gate
// above forbids it): a declaration naming no revision, or one this build does not speak,
// contributes to no table at all.
func TestBuildRevisionDispatch_SkipsUndeclaredEntries(t *testing.T) {
	t.Parallel()
	handler := func(_ context.Context, _ dispatchParams, msg mcp.RPCMsg) mcp.RPCMsg { return msg }
	built := buildRevisionDispatch(map[string]methodSpec{
		"no/revisions":      {Handler: handler},
		"unknown/revision":  {In: []capability.Revision{"1999-01-01"}, Handler: handler},
		"declared/properly": {In: []capability.Revision{capability.Revision20260728}, Handler: handler},
	})
	for _, rev := range capability.PublishedRevisions() {
		for _, m := range []string{"no/revisions", "unknown/revision"} {
			if _, ok := built[rev].local[m]; ok {
				t.Errorf("%q was dispatched under %s despite declaring no membership in it", m, rev)
			}
		}
	}
	if _, ok := built[capability.Revision20260728].local["declared/properly"]; !ok {
		t.Error("a properly declared method must reach its revision's table")
	}
	if _, ok := built[capability.Revision20251125].local["declared/properly"]; ok {
		t.Error("a method declared only for the newer revision must be absent from the older one's table")
	}
}

// TestEnforcedMethodSummary_SpansEveryRevision: the audit-mode banner prints at startup,
// before any peer has negotiated, so it must name every method this build may enforce under
// ANY revision — including the ones only the older revision has.
func TestEnforcedMethodSummary_SpansEveryRevision(t *testing.T) {
	t.Parallel()
	for _, rev := range capability.PublishedRevisions() {
		for m := range tablesFor(rev).decide {
			if !strings.Contains(enforcedMethodSummary, m) {
				t.Errorf("method %q is enforced under %s but missing from the banner summary %q", m, rev, enforcedMethodSummary)
			}
		}
	}
}

// handlerKeys and markerKeys read a derived table's method names.
func handlerKeys(m map[string]methodHandler) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func markerKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// assertKeySet compares a derived table's method set against the expected one exactly.
func assertKeySet(t *testing.T, label string, got, want []string) {
	t.Helper()
	sort.Strings(got)
	w := slices.Clone(want)
	sort.Strings(w)
	if strings.Join(got, ",") != strings.Join(w, ",") {
		t.Errorf("%s table = [%s], want [%s]", label, strings.Join(got, ", "), strings.Join(w, ", "))
	}
}

// metaParams builds a request params body declaring a protocol revision in `_meta`, the way
// a 2026-07-28 peer does.
func metaParams(t *testing.T, version any, extra map[string]any) json.RawMessage {
	t.Helper()
	params := map[string]any{}
	for k, v := range extra {
		params[k] = v
	}
	params["_meta"] = map[string]any{capability.MetaKeyProtocolVersion: version}
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	return raw
}

// requestWithRevision builds a request declaring rev in its `_meta`.
func requestWithRevision(t *testing.T, id, method string, rev any) mcp.RPCMsg {
	t.Helper()
	return mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(fmt.Sprintf("%q", id)), Method: method, Params: metaParams(t, rev, nil)}
}
