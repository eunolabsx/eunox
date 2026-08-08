// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Benchmarks for the decision path — the code every enforced request runs.
//
// They exist because the properties worth holding here are the ones a refactor loses
// silently: per-condition dispatch cost, that dispatch staying allocation-free, the two-pass
// structure's cost on a constraint carrying several conditions, and the anchored-key builders
// on every quota-carrying call. A measured claim about any of those was, until these, not
// re-measurable by whoever read it next.
//
// Not a CI gate: threshold-checked benchmarks are their own maintenance burden and this repo
// has none. The ask they answer is that the numbers exist and are runnable
// (scripts/bench.sh, which covers pkg/ as well as internal/).
//
// White-box (package enforcement) because two of the three subjects are unexported: the
// anchored-key builders, and the condition-dispatch loop reached with a resolved handler.

package enforcement

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/eunolabs/eunox/pkg/capability"
)

// benchRequest is the shape every benchmark below decides: one tool call carrying the
// arguments the pure conditions read.
func benchRequest(args map[string]interface{}) *capability.EnforceRequest {
	return &capability.EnforceRequest{
		SessionID:  "bench-session",
		TargetName: "read_file",
		Target:     &capability.EnforceRequestTarget{Type: string(capability.TargetTypeTool), Name: "read_file"},
		Arguments:  args,
	}
}

// benchPureConditions builds n allowedValues conditions on distinct arguments, plus the
// argument map that satisfies them. allowedValues is the cheapest pure predicate that still
// reads a request argument, so what the loop measures is dispatch rather than one condition's
// own work.
func benchPureConditions(n int) (conds []capability.Condition, args map[string]interface{}) {
	conds = make([]capability.Condition, 0, n)
	args = make(map[string]interface{}, n)
	for i := range n {
		arg := fmt.Sprintf("arg%d", i)
		conds = append(conds, &capability.AllowedValuesCondition{Argument: arg, Values: []interface{}{"ok"}})
		args[arg] = "ok"
	}
	return conds, args
}

// benchCounter admits everything in constant time, so the cells below measure the ENGINE.
//
// The in-memory counter is not a stand-in for "no backend": it retains one timestamp per
// admitted call and rescans the in-window slice on each admission, so a benchmark whose
// budget never denies is quadratic in b.N — the reported ns/op then tracks -benchtime rather
// than the code, and one cell ran ~14x its requested budget.
type benchCounter struct{}

func (benchCounter) IncrementAndGet(context.Context, string, int, int) (int64, error) { return 1, nil }
func (benchCounter) Peek(context.Context, string, int) (int64, error)                 { return 0, nil }
func (benchCounter) AdmitAll(context.Context, []capability.QuotaBucket) (admitted bool, deniedIndex int, total float64, retryAfter time.Duration, err error) {
	return true, 0, 0, 0, nil
}

// benchEngine wires the constant-time counter every quota-carrying policy needs.
func benchEngine() *Engine {
	return New(WithCallCounter(benchCounter{}))
}

// runValidateAction is the shared loop: an ALLOW every iteration, since a deny short-circuits
// the very dispatch being measured.
func runValidateAction(b *testing.B, e *Engine, req *capability.EnforceRequest, caps []capability.Constraint) {
	b.Helper()
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		resp := e.ValidateAction(ctx, req, caps)
		if resp.Decision != capability.DecisionAllow {
			b.Fatalf("benchmark must measure the allow path; got %q (%+v)", resp.Decision, resp.Denial)
		}
	}
}

// BenchmarkValidateAction_NoConditions is the floor: matching, target resolution, and the
// allow tail with nothing to dispatch. Every other number here is read against it.
func BenchmarkValidateAction_NoConditions(b *testing.B) {
	caps := []capability.Constraint{{Target: "tool:read_file", Actions: []string{"call"}}}
	runValidateAction(b, benchEngine(), benchRequest(nil), caps)
}

// BenchmarkValidateAction_PureConditions is per-condition dispatch cost: subtract the floor
// and divide. Read allocs/op ACROSS the cells, not within one — dispatch is allocation-free
// exactly while that column is constant in n, which is the property a refactor loses without
// changing any test. The 8-condition cell is what a dispatch change is measured against; a
// redundant registry lookup and interface call per condition was ~22% of one such loop.
func BenchmarkValidateAction_PureConditions(b *testing.B) {
	for _, n := range []int{1, 4, 8} {
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			conds, args := benchPureConditions(n)
			caps := []capability.Constraint{{Target: "tool:read_file", Actions: []string{"call"}, Conditions: conds}}
			runValidateAction(b, benchEngine(), benchRequest(args), caps)
		})
	}
}

// BenchmarkValidateAction_PureAndCommitting adds the second pass: the same pure set plus one
// quota-consuming condition, so the difference from the cell above is what deferral and bucket
// derivation cost the engine. The admission itself is constant-time here on purpose — see
// benchCounter; measuring a backend's data structure would make the number a function of how
// long the benchmark ran.
func BenchmarkValidateAction_PureAndCommitting(b *testing.B) {
	conds, args := benchPureConditions(4)
	conds = append(conds, &capability.MaxCallsCondition{Count: 1 << 30, WindowSeconds: 3600})
	caps := []capability.Constraint{{Target: "tool:read_file", Actions: []string{"call"}, Conditions: conds}}
	runValidateAction(b, benchEngine(), benchRequest(args), caps)
}

// BenchmarkAnchoredKey covers the builder every piece of accumulated state routes through, on
// both anchor kinds: it runs per quota bucket and per history lookup, so its cost rides calls
// the two benchmarks above only sample once.
func BenchmarkAnchoredKey(b *testing.B) {
	sessionReq := benchRequest(nil)
	taskReq := benchRequest(nil)
	taskReq.Claims = map[string]interface{}{"task_id": "task-42"}

	for _, tc := range []struct {
		name   string
		engine *Engine
		req    *capability.EnforceRequest
	}{
		{"session anchored", benchEngine(), sessionReq},
		{"task anchored", New(WithCallCounter(benchCounter{}), WithTaskAnchoredState()), taskReq},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if key := tc.engine.sequenceHistoryKey(tc.req, string(capability.TargetTypeTool), "read_file"); key == "" {
					b.Fatal("empty key")
				}
			}
		})
	}
}
