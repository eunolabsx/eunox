// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
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
		// Sorted before Compact: it collapses only ADJACENT equal elements, so an unsorted
		// check would miss the duplicate shape a copy-paste actually produces (A, B, A).
		sorted := slices.Clone(spec.In)
		slices.Sort(sorted)
		if len(slices.Compact(sorted)) != len(spec.In) {
			t.Errorf("method %q declares a duplicate revision in %v", method, spec.In)
		}
		if spec.Decide != nil && spec.Local != nil {
			t.Errorf("method %q declares both a Decide and a Local handler; the field it sits in IS its classification, so exactly one may be set", method)
		}
		if handler, _ := spec.handler(); handler == nil && spec.Notification == notifyUnmapped {
			t.Errorf("method %q declares neither a handler nor a notification disposition, so it dispatches nowhere — delete the entry rather than leaving a no-op", method)
		}
		// forwardsHostParams derives the two halves the handler fields already answer, so what
		// is left to check is that the remaining declaration is not claimed by a method whose
		// handler cannot forward: LocalForwards on a Decide entry (redundant, and a sign the
		// author thought the flag was load-bearing) or on an entry with no Local handler at
		// all (a declaration about a handler that does not exist).
		if spec.LocalForwards && spec.Local == nil {
			t.Errorf("method %q declares LocalForwards but has no Local handler to forward from", method)
		}
		if spec.LocalForwards && spec.Decide != nil {
			t.Errorf("method %q is PDP-decided, which already forwards; LocalForwards says nothing here", method)
		}
	}
}

// TestHandshakeRevision_DerivedFromTheRegistry pins the derivation behind handshakeRevision:
// every site that opens, answers, or version-stamps a handshake reads it, so a registry
// change that leaves it unresolvable must fail here rather than silently falling back to the
// shipped default at eleven call sites.
func TestHandshakeRevision_DerivedFromTheRegistry(t *testing.T) {
	t.Parallel()
	spec, ok := methodRegistry[mcp.MethodInitialize]
	if !ok {
		t.Fatalf("%q has no registry entry, so the handshake revision cannot be derived", mcp.MethodInitialize)
	}
	if len(spec.In) != 1 {
		t.Fatalf("%q declares %v; the handshake revision is derivable only while exactly one revision has it — give the sites that read handshakeRevision a per-peer answer before widening this", mcp.MethodInitialize, spec.In)
	}
	if handshakeRevision != spec.In[0] {
		t.Errorf("handshakeRevision = %q, want %q from the registry", handshakeRevision, spec.In[0])
	}
	// The same fact lives in pkg/capability for the layers that may not import this package
	// (the config loader refusing a pin the host leg could never match). Two homes, one
	// authority: the registry derives it, and this is what keeps the published constant honest.
	if capability.HandshakeRevision() != handshakeRevision {
		t.Errorf("capability.HandshakeRevision() = %q, but the registry derives %q — the config loader would refuse the wrong pins",
			capability.HandshakeRevision(), handshakeRevision)
	}
}

// TestRevisionDispatch_ExactSetPerRevision pins each revision's EXACT four tables, derived
// from the declarations rather than restated by hand at the call sites.
//
// Exact, not "contains": a method silently gaining membership in a revision that removed it
// is the failure revision-scoped routing exists to prevent, and only an exact set catches an
// addition. The 2026-07-28 sets are deliberately smaller than the spec's full method list —
// server/discover, subscriptions/listen and tasks/* land with their own responders, and until
// then they fall to the fail-closed default like any unknown method.
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
			assertKeySet(t, "forwardNotifications", dispositionKeys(tables, notifyForward), tc.forward)
			assertKeySet(t, "swallowNotifications", dispositionKeys(tables, notifySwallow), tc.swallow)
			for _, m := range tc.absentOK {
				if _, ok := tables.decide[m]; ok {
					t.Errorf("%q must not be an enforced method under %s", m, tc.rev)
				}
				if _, ok := tables.local[m]; ok {
					t.Errorf("%q must not be locally answered under %s", m, tc.rev)
				}
				if got := tables.notifications[m]; got != notifyUnmapped {
					t.Errorf("%q must have no notification disposition under %s, got %v", m, tc.rev, got)
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
	if len(unknown.decide)+len(unknown.local)+len(unknown.notifications) != 0 {
		t.Errorf("an unspoken revision must dispatch nothing, got decide=%d local=%d notifications=%d",
			len(unknown.decide), len(unknown.local), len(unknown.notifications))
	}
	if isEnforcedMethod(revisionContext(capability.Revision("1999-01-01")), capability.MethodToolsCall) {
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
		"no/revisions":      {Local: handler},
		"unknown/revision":  {In: []capability.Revision{"1999-01-01"}, Local: handler},
		"declared/properly": {In: []capability.Revision{capability.Revision20260728}, Local: handler},
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

// dispositionKeys reads the method names a revision's notification table maps to want.
func dispositionKeys(t revisionTables, want notificationDisposition) []string {
	out := make([]string, 0, len(t.notifications))
	for k, d := range t.notifications {
		if d == want {
			out = append(out, k)
		}
	}
	return out
}

// revisionContext returns a context negotiated at rev — the single carrier the dispatcher and
// the audit tape both read, so a test naming a revision names it the way a transport does.
func revisionContext(rev capability.Revision) context.Context {
	return capability.WithProtocolRevision(context.Background(), rev)
}

// noKill is the hostNotificationGate kill thunk for a live (unrevoked) session.
func noKill() *capability.EnforceResponse { return nil }

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

// TestMethodRegistry_EveryUpstreamForwardingLocalHandlerDeclaresIt closes the one direction
// forwardsHostParams cannot derive.
//
// A Decide method forwards by definition and a notifyForward notification says so in its
// disposition, so both halves are read off fields that already exist. A LOCAL handler that
// forwards is invisible to the type system — dispatchList sends the host's request upstream
// and filters the reply, dispatchPing and dispatchInitialize contact nothing — so it is the
// one fact still declared by hand, and a forgotten declaration silently turns the
// upstream-revision gate off for that method while it keeps dispatching.
//
// This walks the registry literal for Local handlers that reach the upstream and requires the
// declaration, so the next */list-shaped method fails the build rather than review.
func TestMethodRegistry_EveryUpstreamForwardingLocalHandlerDeclaresIt(t *testing.T) {
	t.Parallel()
	src := dispatchSource(t)
	// The registry is one composite literal keyed by method; each value is a methodSpec
	// literal whose Local field holds the handler whose body is being inspected.
	checked := 0
	ast.Inspect(src.file, func(n ast.Node) bool {
		spec, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		var local ast.Expr
		declared := false
		for _, elt := range spec.Elts {
			kv, isKV := elt.(*ast.KeyValueExpr)
			if !isKV {
				continue
			}
			key, isIdent := kv.Key.(*ast.Ident)
			if !isIdent {
				continue
			}
			switch key.Name {
			case "Local":
				local = kv.Value
			case "LocalForwards":
				declared = true
			}
		}
		if local == nil {
			return true
		}
		checked++
		forwards := false
		ast.Inspect(local, func(inner ast.Node) bool {
			call, isCall := inner.(*ast.CallExpr)
			if !isCall {
				return true
			}
			// Either spelling of reaching the upstream from a Local handler: the shared
			// list forwarder, or the raw call.
			switch fn := call.Fun.(type) {
			case *ast.Ident:
				forwards = forwards || fn.Name == "dispatchList"
			case *ast.SelectorExpr:
				forwards = forwards || fn.Sel.Name == "callUpstream"
			}
			return true
		})
		if forwards && !declared {
			t.Errorf("a Local handler at %s forwards the host's request upstream but its entry does not declare LocalForwards; the upstream-revision gate is off for that method",
				src.fset.Position(local.Pos()))
		}
		if !forwards && declared {
			t.Errorf("an entry at %s declares LocalForwards but its handler reaches no upstream", src.fset.Position(local.Pos()))
		}
		return true
	})
	if checked == 0 {
		t.Fatal("no Local handlers found in the registry literal; the walk is not seeing what it claims to")
	}
}
