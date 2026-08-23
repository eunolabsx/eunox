// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// What resolving a routing header's target costs, as a function of the params a peer sends.
//
// Committed because the number is the argument. The routing headers add a params walk on each
// leg that uses them, and the walk is mcp.DecodeParams' — the duplicate-key scan plus the decode,
// both linear in the whole document, over bodies bounded only by maxRequestBodyBytes. It is
// deliberately NOT a cheaper reader: what eunox names in the header must be what the upstream
// reads out of the same bytes, and a second decoder spelling is the differential this whole file
// exists to close.
//
// The reachable multiple today is TWO passes per forwarded target-addressing call on a leg an
// operator pinned to a declaring revision — the dispatcher's, which predates this, plus the
// emission's. The inbound check's third pass is not reachable over HTTP yet: it is gated on the
// HOST's revision, and a declaring host is refused at negotiation until session creation on first
// request lands. Run this before assuming that third pass is free.
func BenchmarkRoutingTargetOf(b *testing.B) {
	for _, argBytes := range []int{64, 4 << 10, 256 << 10} {
		msg := benchToolCall(argBytes)
		b.Run(fmt.Sprintf("params=%dB", len(msg.Params)), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, named, err := routingTargetOf(msg); err != nil || !named {
					b.Fatalf("target unresolved: named=%v err=%v", named, err)
				}
			}
		})
	}
}

// A method that addresses nothing named must cost nothing at all: routingTargetOf returns before
// any decode for an enumeration, which is what keeps the check off the `*/list` path.
func BenchmarkRoutingTargetOf_EnumerationDecodesNothing(b *testing.B) {
	msg := benchToolCall(256 << 10)
	msg.Method = capability.MethodToolsList
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, named, _ := routingTargetOf(msg); named {
			b.Fatal("an enumeration resolved a target")
		}
	}
}

func benchToolCall(argBytes int) mcp.RPCMsg {
	args, _ := json.Marshal(map[string]interface{}{"path": "/data/" + strings.Repeat("x", argBytes)})
	params, _ := json.Marshal(map[string]interface{}{
		"name":      "read_file",
		"arguments": json.RawMessage(args),
		"_meta":     map[string]string{capability.MetaKeyProtocolVersion: capability.Revision20260728.String()},
	})
	return mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: capability.MethodToolsCall, Params: params}
}
