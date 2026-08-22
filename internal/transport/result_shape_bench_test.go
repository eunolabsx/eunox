// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

// The shape pass runs on every result a host receives, so ADR-0006's "the parse must stay
// allocation-lean" applies to it. These pin the three cases that matter: a peer whose revision
// does not define the members (which must cost nothing at all), a conforming upstream (which
// must not be rewritten), and a large body needing a member supplied (which must not be
// re-marshalled).
//
// Run through scripts/bench.sh like the engine's.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/pkg/capability"
)

func benchResult(payload int) mcp.RPCMsg {
	return mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`1`),
		Result: json.RawMessage(`{"content":[{"type":"text","text":"` + strings.Repeat("x", payload) + `"}]}`),
	}
}

// A 2025-11-25 peer must not pay for a revision it does not speak: the gate returns before
// reading a byte, so this is allocation-free however large the body.
func BenchmarkResultShape_OldRevisionIsFree(b *testing.B) {
	resp := benchResult(64 << 10)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := applyResultShape(capability.Revision20251125, capability.MethodToolsCall, false, resp); err != nil {
			b.Fatal(err)
		}
	}
}

// A conforming upstream costs one shallow pass and NO re-encoding — the reason the scan reads
// the body rather than decoding and re-marshalling it.
func BenchmarkResultShape_ConformingIsNotRewritten(b *testing.B) {
	resp := mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`1`),
		Result: json.RawMessage(`{"resultType":"complete","cacheScope":"private","tools":[]}`),
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := applyResultShape(capability.Revision20260728, capability.MethodToolsList, false, resp); err != nil {
			b.Fatal(err)
		}
	}
}

// Supplying a member costs the scan plus ONE copy of the body — not a decode and re-marshal of
// every value in it.
func BenchmarkResultShape_SupplyLargeBody(b *testing.B) {
	resp := benchResult(64 << 10)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := applyResultShape(capability.Revision20260728, capability.MethodToolsCall, false, resp); err != nil {
			b.Fatal(err)
		}
	}
}
