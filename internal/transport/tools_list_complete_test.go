// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// This file covers the transport's half of Tier-2's membership contract: deciding whether
// a host tools/list observation covers the WHOLE advertised surface, and marking it so.
//
// The Tier-2 baseline reports a tool APPEARING or DISAPPEARING only for a complete
// listing that is not the session's first. The session-start drift probe supplies the
// first; nothing supplied a second, so both findings were structurally unreachable — the
// probe is always a session's first observation, and a route with no drift check took no
// complete observation at all. The gate is only as reachable as this decision makes it,
// which is why it is pinned here rather than only at the SurfaceBaseline.

// TestCompleteToolsListing covers the completeness predicate. Only a cursor-less request
// answered by a cursor-less response is the whole surface; every ambiguous input is
// incomplete, which suppresses the advisory membership findings and never a break.
func TestCompleteToolsListing(t *testing.T) {
	for _, tc := range []struct {
		name   string
		params string
		result string
		want   bool
	}{
		{"no params, no next cursor", "", `{"tools":[{"name":"a"}]}`, true},
		{"empty params object", `{}`, `{"tools":[]}`, true},
		{"null cursor asks for the first page", `{"cursor":null}`, `{"tools":[]}`, true},
		{"empty cursor asks for the first page", `{"cursor":""}`, `{"tools":[]}`, true},
		{"null params", `null`, `{"tools":[]}`, true},
		{"a requested page is one page", `{"cursor":"p2"}`, `{"tools":[]}`, false},
		{"more pages follow", "", `{"tools":[],"nextCursor":"p2"}`, false},
		{"both halves paginated", `{"cursor":"p2"}`, `{"tools":[],"nextCursor":"p3"}`, false},
		{"unparseable params fail closed", `[1,2]`, `{"tools":[]}`, false},
		{"unparseable result fails closed", "", `{"tools":`, false},
		{"non-object result fails closed", "", `[]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var params json.RawMessage
			if tc.params != "" {
				params = json.RawMessage(tc.params)
			}
			if got := completeToolsListing(params, json.RawMessage(tc.result)); got != tc.want {
				t.Fatalf("completeToolsListing(%s, %s) = %v, want %v", tc.params, tc.result, got, tc.want)
			}
		})
	}
}

// listingObserver is a PDP that records the completeness marking of every tools/list
// context it is handed, so the transport's decision is observable at the boundary that
// makes it. The Tier-2 findings it gates are advisory (a logged line, no decision), so
// there is nothing else downstream to assert against.
type listingObserver struct {
	pdp.AlwaysAllowPDP
	marks []bool
}

func (o *listingObserver) FilterToolsList(ctx context.Context, result json.RawMessage) pdp.ListFilterResult {
	o.marks = append(o.marks, pdp.CompleteToolListingFromContext(ctx))
	return o.AlwaysAllowPDP.FilterToolsList(ctx, result)
}

func (o *listingObserver) RecordObservedToolHashes(ctx context.Context, result json.RawMessage) int {
	o.marks = append(o.marks, pdp.CompleteToolListingFromContext(ctx))
	return o.AlwaysAllowPDP.RecordObservedToolHashes(ctx, result)
}

// dispatchToolsList drives one tools/list through the shared dispatcher against an
// upstream returning result, and returns whether the observer saw a complete marking.
func dispatchToolsList(t *testing.T, o *listingObserver, audit bool, params, result string) bool {
	t.Helper()
	d := dispatchParams{
		forwardParams: forwardParams{
			sessionID: "s",
			audit:     audit,
			callUpstream: func(_ context.Context, msg mcp.RPCMsg) (mcp.RPCMsg, error) {
				return mcp.RPCMsg{JSONRPC: "2.0", ID: msg.ID, Result: json.RawMessage(result)}, nil
			},
		},
		pdp: o,
	}
	msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsList}
	if params != "" {
		msg.Params = json.RawMessage(params)
	}
	before := len(o.marks)
	if out := dispatchRequest(context.Background(), d, msg); out.Error != nil {
		t.Fatalf("tools/list returned an error: %+v", out.Error)
	}
	if len(o.marks) != before+1 {
		t.Fatalf("the tools/list observation pass did not run (marks %d -> %d)", before, len(o.marks))
	}
	return o.marks[len(o.marks)-1]
}

// TestDispatchList_MarksAnUnpaginatedHostListingComplete is the regression the dead
// membership findings needed: a SECOND complete observation has to be reachable in
// production, not only at the session-start probe. An ordinary unpaginated host
// tools/list is one, on both the enforce (filter) and audit (observe) paths.
func TestDispatchList_MarksAnUnpaginatedHostListingComplete(t *testing.T) {
	for _, auditMode := range []bool{false, true} {
		o := &listingObserver{}
		// Two listings in the same session: the first establishes membership, the second is
		// the one an addition or removal can be reported against. Both must be marked, or
		// the gate reachable at neither.
		for i := 0; i < 2; i++ {
			if !dispatchToolsList(t, o, auditMode, "", `{"tools":[{"name":"read_file"}]}`) {
				t.Fatalf("audit=%v: an unpaginated host tools/list must be marked complete (observation %d)", auditMode, i+1)
			}
		}
	}
}

// TestDispatchList_LeavesAPaginatedListingIncomplete pins the other direction: one page of
// a paginated listing says nothing about which tools exist, so marking it complete would
// report every tool on the other pages as removed on every pagination cycle — the false
// notice the gate exists to prevent.
func TestDispatchList_LeavesAPaginatedListingIncomplete(t *testing.T) {
	o := &listingObserver{}
	if dispatchToolsList(t, o, false, "", `{"tools":[{"name":"read_file"}],"nextCursor":"p2"}`) {
		t.Error("a response carrying nextCursor must not be marked complete")
	}
	if dispatchToolsList(t, o, false, `{"cursor":"p2"}`, `{"tools":[{"name":"write_file"}]}`) {
		t.Error("a request carrying a cursor asked for one page and must not be marked complete")
	}
}

// TestDispatchList_MarksOnlyToolsList pins the marking's scope. resources/list and
// prompts/list carry no Tier-2 surface to baseline, and the flag names a TOOL listing, so
// setting it there would be a claim about a catalog nothing pins.
func TestDispatchList_MarksOnlyToolsList(t *testing.T) {
	var seen bool
	d := dispatchParams{
		forwardParams: forwardParams{
			sessionID: "s",
			callUpstream: func(_ context.Context, msg mcp.RPCMsg) (mcp.RPCMsg, error) {
				return mcp.RPCMsg{JSONRPC: "2.0", ID: msg.ID, Result: json.RawMessage(`{"resources":[]}`)}, nil
			},
		},
		pdp: filterProbePDP{onFilter: func(ctx context.Context) { seen = pdp.CompleteToolListingFromContext(ctx) }},
	}
	out := dispatchRequest(context.Background(), d, mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodResourcesList})
	if out.Error != nil {
		t.Fatalf("resources/list returned an error: %+v", out.Error)
	}
	if seen {
		t.Error("only a tools/list observation may be marked complete")
	}
}

// filterProbePDP reports the context a resources/list filter was handed.
type filterProbePDP struct {
	pdp.AlwaysAllowPDP
	onFilter func(context.Context)
}

func (p filterProbePDP) FilterResourcesList(ctx context.Context, result json.RawMessage) pdp.ListFilterResult {
	p.onFilter(ctx)
	return p.AlwaysAllowPDP.FilterResourcesList(ctx, result)
}
