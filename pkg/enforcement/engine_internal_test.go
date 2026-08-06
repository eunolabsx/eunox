// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// White-box (package enforcement) tests for the counter-key construction shared
// by the maxCalls quota bucket and the sequenceBlock session-history marker. Both
// keys are (sessionID, targetType, name) tuples; the encoding must map distinct
// tuples to distinct buckets even when a component contains the ":" separator,
// the collision class reported.

// White-box (package enforcement) regression test: the
// logical maxCalls counter key must NOT fold windowSeconds in. Each backend
// appends the window to the physical key exactly once, so embedding it here too
// made the physical key carry the window twice (callcounter:maxcalls:...:300:300).

// White-box (package enforcement) tests for small unexported helpers whose
// branches are awkward to reach exhaustively through the public Engine API:
// the JSON type discriminator used by schema validation and the
// SequenceBlockCondition type assertion that accepts both value and pointer
// forms.

package enforcement

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
)

// seqKeyForTest builds a sequenceBlock-history key the way the engine does, for the tests
// that assert on the key ENCODING rather than on a decision. The engine method takes the
// request (the anchor is derived from it — see anchor.go), so this adapts the (namespace,
// session, type, target) tuple those tests are written in terms of.
func seqKeyForTest(namespace, sessionID, targetType, target string) string {
	e := &Engine{counterKeyNamespace: namespace}
	return e.sequenceHistoryKey(&capability.EnforceRequest{SessionID: sessionID}, targetType, target)
}

// TestSequenceHistoryKey_ColonCollisionResistant pins the ambiguity from
// the three-component history key: joined with a bare ":" delimiter,
// (session "a:b", type "c", target "d") and (session "a", type "b", target "c:d")
// both render "seq:a:b:c:d" and so address one bucket. The length-prefixed
// encoding must keep them distinct.
func TestSequenceHistoryKey_ColonCollisionResistant(t *testing.T) {
	a := seqKeyForTest("", "a:b", "c", "d")
	b := seqKeyForTest("", "a", "b", "c:d")
	if a == b {
		t.Fatalf("sequenceHistoryKey collides for ('a:b','c','d') and ('a','b','c:d'): both = %q", a)
	}
	// A distinct namespace (gateway route) must also disjoin two otherwise-identical
	// (session, type, target) tuples, so routes sharing one CallCounter cannot collide.
	if seqKeyForTest("routeA", "s", "tool", "x") == seqKeyForTest("routeB", "s", "tool", "x") {
		t.Fatal("sequenceHistoryKey must disjoin distinct namespaces for the same tuple")
	}
}

// TestCounterKeyNamespace_DisjoinsRoutes confirms the route namespace disjoins both
// counter kinds so gateway routes sharing one CallCounter cannot drain or interfere
// with each other's maxCalls/sequenceBlock buckets under a session-id collision.
func TestCounterKeyNamespace_DisjoinsRoutes(t *testing.T) {
	if compositeCounterKey("maxcalls", "routeA", "s", "tool", "x") ==
		compositeCounterKey("maxcalls", "routeB", "s", "tool", "x") {
		t.Fatal("maxCalls key must disjoin distinct route namespaces for the same tuple")
	}
	// An empty namespace (single-upstream) keeps a stable, collision-resistant key.
	if compositeCounterKey("maxcalls", "", "s", "tool", "x") ==
		compositeCounterKey("maxcalls", "", "s", "tool", "y") {
		t.Fatal("distinct tools must not collide under an empty namespace")
	}
}

// TestMaxCallsCounterKey_ColonCollisionResistant covers the same ambiguity for
// the three-component maxCalls key, across each adjacent-component boundary a
// colon could bleed across (session/type and type/tool), plus the empty-type
// case a nil req.Target produces.
func TestMaxCallsCounterKey_ColonCollisionResistant(t *testing.T) {
	cases := []struct {
		name string
		x, y [3]string // sessionID, targetType, toolName
	}{
		{"session-into-type", [3]string{"s:tool", "", "export"}, [3]string{"s", "tool", "export"}},
		{"type-into-tool", [3]string{"s", "tool", "a:b"}, [3]string{"s", "tool:a", "b"}},
		{"session-into-tool-empty-type", [3]string{"a:b", "", "c"}, [3]string{"a", "", "b:c"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kx := compositeCounterKey("maxcalls", tc.x[0], tc.x[1], tc.x[2])
			ky := compositeCounterKey("maxcalls", tc.y[0], tc.y[1], tc.y[2])
			if kx == ky {
				t.Fatalf("maxCalls key collides for %v and %v: both = %q", tc.x, tc.y, kx)
			}
		})
	}
}

// TestCompositeCounterKey_NulSeparatorWouldNotSuffice guards the choice of
// length-prefixing over a single sentinel separator: a NUL byte (the separator
// the issue floated as "the simplest option") can appear in a caller-supplied
// component just as a colon can, so length-prefixing — not any one-byte sentinel
// — is what makes the encoding injective for arbitrary content.
func TestCompositeCounterKey_NulSeparatorWouldNotSuffice(t *testing.T) {
	a := compositeCounterKey("seq", "a\x00b", "c")
	b := compositeCounterKey("seq", "a", "b\x00c")
	if a == b {
		t.Fatalf("compositeCounterKey collides for NUL-bearing components: both = %q", a)
	}
}

// TestCompositeCounterKey_PrefixPreserved confirms the disjoint "seq:" /
// "maxcalls:" namespaces the callcounter backends rely on (redis.go) survive the
// length-prefixed encoding: each key still leads with its verbatim prefix token.
func TestCompositeCounterKey_PrefixPreserved(t *testing.T) {
	if got := seqKeyForTest("", "s", "tool", "t"); !strings.HasPrefix(got, "seq:") {
		t.Errorf("sequenceHistoryKey = %q, want \"seq:\" prefix", got)
	}
	if got := compositeCounterKey("maxcalls", "s", "tool", "t"); !strings.HasPrefix(got, "maxcalls:") {
		t.Errorf("maxCalls key = %q, want \"maxcalls:\" prefix", got)
	}
}

// keyCapturingCounter records the bucket the maxCalls handler hands the rate limiter.
// Peek is a stub: the commit path is AdmitAll, which is what this
// test inspects.
type keyCapturingCounter struct {
	gotKey       string
	gotWindowSec int
}

func (c *keyCapturingCounter) IncrementAndGet(_ context.Context, _ string, _, _ int) (int64, error) {
	return 1, nil
}

func (c *keyCapturingCounter) Peek(_ context.Context, _ string, _ int) (int64, error) {
	return 0, nil
}

func (c *keyCapturingCounter) AdmitAll(_ context.Context, buckets []capability.QuotaBucket) (admitted bool, deniedIndex int, total float64, retryAfter time.Duration, err error) {
	if len(buckets) > 0 {
		c.gotKey = buckets[0].Key
		c.gotWindowSec = buckets[0].WindowSec
	}
	return true, 0, 0, 0, nil
}

// incrKeyCapturingCounter records every key RecordSessionCall passes to
// IncrementAndGet (the sequenceBlock history write path).
type incrKeyCapturingCounter struct {
	keyCapturingCounter
	incrKeys []string
}

func (c *incrKeyCapturingCounter) IncrementAndGet(_ context.Context, key string, _, _ int) (int64, error) {
	c.incrKeys = append(c.incrKeys, key)
	return 1, nil
}

func (c *incrKeyCapturingCounter) hasKey(key string) bool {
	for _, k := range c.incrKeys {
		if k == key {
			return true
		}
	}
	return false
}

// recordingCommittingHandler is a custom CommittingConditionHandler registered under
// the maxCalls type. It records that PrepareCommit was called and otherwise delegates
// to the built-in bucket derivation, so the test can prove the multi-deferred commit
// path dispatches through the registry rather than a hardcoded maxCalls type switch.
// Pointer receiver so the copy held in the registry and the test's reference share
// the same engine pointer and call counter.
type recordingCommittingHandler struct {
	e            *Engine
	prepareCalls int
}

func (h *recordingCommittingHandler) Handle(ctx context.Context, cond capability.Condition, req *capability.EnforceRequest) *ConditionError {
	return h.e.prepareAndAdmit(ctx, h, cond, req)
}

func (h *recordingCommittingHandler) PrepareCommit(ctx context.Context, cond capability.Condition, req *capability.EnforceRequest) (DeferredCommit, bool, *ConditionError) {
	h.prepareCalls++
	mc, key, skip, condErr := h.e.maxCallsBucket(ctx, cond, req)
	if skip {
		return DeferredCommit{}, true, nil
	}
	if condErr != nil {
		return DeferredCommit{}, false, condErr
	}
	return DeferredCommit{
		Bucket: capability.QuotaBucket{
			Key:       key,
			WindowSec: mc.WindowSeconds,
			Counted:   true,
			Limit:     float64(mc.Count),
		},
		Deny: func(total float64, retryAfter time.Duration) *ConditionError {
			return maxCallsRateLimited(mc, int64(total), retryAfterSeconds(retryAfter, mc.WindowSeconds))
		},
	}, false, nil
}

// TestCommitDeferredAtomic_DispatchesThroughRegistry pins the contract that a constraint
// carrying more than one deferred condition commits through the registered
// CommittingConditionHandler, so a custom WithConditionHandler for maxCalls is honored
// on the multi-deferred path exactly as on the single-condition path — not bypassed by
// a hardcoded maxCalls type switch. Before the fix the atomic commit called the
// built-in maxCallsBucket directly and this custom handler's PrepareCommit was never
// invoked.
func TestCommitDeferredAtomic_DispatchesThroughRegistry(t *testing.T) {
	counter := callcounter.NewInMemory()
	handler := &recordingCommittingHandler{}
	// The handler is only invoked during ValidateAction, after e is assigned below, so
	// wiring e post-construction is safe (WithConditionHandler only registers the
	// pointer; the deferred call reads h.e once set).
	e := New(WithCallCounter(counter), WithConditionHandler(capability.ConditionTypeMaxCalls, handler))
	handler.e = e

	req := &capability.EnforceRequest{SessionID: "sess-1", TargetName: "tool"}
	caps := []capability.Constraint{{
		Target:  "tool",
		Actions: []string{"*"},
		// Two maxCalls with DISTINCT windows: forces the multi-deferred atomic-commit path
		// (validateQuotaBucketsDistinct requires the windows differ).
		Conditions: []capability.Condition{
			&capability.MaxCallsCondition{Count: 5, WindowSeconds: 60},
			&capability.MaxCallsCondition{Count: 3, WindowSeconds: 3600},
		},
	}}

	resp := e.ValidateAction(context.Background(), req, caps)
	if resp.Decision != capability.DecisionAllow {
		t.Fatalf("decision = %q, want allow", resp.Decision)
	}
	if handler.prepareCalls != 2 {
		t.Fatalf("custom PrepareCommit called %d times, want 2 (once per deferred condition) — the multi-deferred path must dispatch through the registry", handler.prepareCalls)
	}
}

// nonUniformSkipHandler is a custom CommittingConditionHandler that reports skip=true
// for its OWN reason (never from ctx/SkipQuota), violating the contract that skip must
// be uniform across the constraint. On the multi-deferred path this would fail OPEN —
// one bucket's skip shortcuts the whole set to allow without limit-checking the rest —
// so the atomic commit must instead fail closed.
type nonUniformSkipHandler struct{ e *Engine }

func (h nonUniformSkipHandler) Handle(ctx context.Context, cond capability.Condition, req *capability.EnforceRequest) *ConditionError {
	return h.e.prepareAndAdmit(ctx, h, cond, req)
}

func (h nonUniformSkipHandler) PrepareCommit(_ context.Context, _ capability.Condition, _ *capability.EnforceRequest) (DeferredCommit, bool, *ConditionError) {
	// skip unconditionally, regardless of ctx — the contract violation under test.
	return DeferredCommit{}, true, nil
}

// TestCommitDeferredAtomic_NonUniformSkipFailsClosed pins that a committing handler
// reporting skip for a reason other than the ctx (SkipQuota) is rejected with a deny
// rather than admitting the call. Without the guard, one bucket's non-uniform skip
// would allow the whole deferred set without limit-checking the remaining conditions.
func TestCommitDeferredAtomic_NonUniformSkipFailsClosed(t *testing.T) {
	counter := callcounter.NewInMemory()
	handler := nonUniformSkipHandler{}
	e := New(WithCallCounter(counter), WithConditionHandler(capability.ConditionTypeMaxCalls, handler))
	handler.e = e

	req := &capability.EnforceRequest{SessionID: "sess-1", TargetName: "tool"}
	caps := []capability.Constraint{{
		Target:  "tool",
		Actions: []string{"*"},
		// Two maxCalls with DISTINCT windows: forces the multi-deferred atomic-commit path.
		Conditions: []capability.Condition{
			&capability.MaxCallsCondition{Count: 5, WindowSeconds: 60},
			&capability.MaxCallsCondition{Count: 3, WindowSeconds: 3600},
		},
	}}

	// No WithSkipQuota on the context, so SkipQuota(ctx) is false: the handler's skip is
	// non-uniform and must fail closed.
	resp := e.ValidateAction(context.Background(), req, caps)
	if resp.Decision != capability.DecisionDeny {
		t.Fatalf("decision = %q, want deny (non-uniform skip must fail closed)", resp.Decision)
	}
	if resp.Denial == nil || resp.Denial.Code != capability.ErrCodeConditionFailed {
		t.Fatalf("denial = %+v, want CONDITION_FAILED", resp.Denial)
	}
}

// nilDenyHandler is a custom CommittingConditionHandler whose PrepareCommit
// derives a real bucket (Key/WindowSecs/Limit) via the built-in maxCallsBucket
// but deliberately leaves Deny nil — a handler bug the atomic commit must not
// let panic the enforcement goroutine when that bucket is the one the call
// counter denies. Pointer receiver so the copy held in the registry and the
// test's reference share the same engine pointer (mirrors
// recordingCommittingHandler).
type nilDenyHandler struct{ e *Engine }

func (h *nilDenyHandler) Handle(ctx context.Context, cond capability.Condition, req *capability.EnforceRequest) *ConditionError {
	return h.e.prepareAndAdmit(ctx, h, cond, req)
}

func (h *nilDenyHandler) PrepareCommit(ctx context.Context, cond capability.Condition, req *capability.EnforceRequest) (DeferredCommit, bool, *ConditionError) {
	mc, key, skip, condErr := h.e.maxCallsBucket(ctx, cond, req)
	if skip {
		return DeferredCommit{}, true, nil
	}
	if condErr != nil {
		return DeferredCommit{}, false, condErr
	}
	return DeferredCommit{
		Bucket: capability.QuotaBucket{
			Key:       key,
			WindowSec: mc.WindowSeconds,
			Counted:   true,
			Limit:     float64(mc.Count),
		},
		// Deny deliberately left nil: the handler bug under test.
	}, false, nil
}

// forceDenyAtIndexZeroCounter is a minimal CallCounter fake whose
// AdmitAll always denies bucket 0, deterministically driving
// commitDeferredConditions to invoke denies[0] regardless of the built-in InMemory
// counter's real quota semantics.
type forceDenyAtIndexZeroCounter struct{}

func (forceDenyAtIndexZeroCounter) IncrementAndGet(_ context.Context, _ string, _, _ int) (int64, error) {
	return 1, nil
}
func (forceDenyAtIndexZeroCounter) Peek(_ context.Context, _ string, _ int) (int64, error) {
	return 0, nil
}
func (forceDenyAtIndexZeroCounter) AdmitAll(_ context.Context, _ []capability.QuotaBucket) (admitted bool, deniedIndex int, total float64, retryAfter time.Duration, err error) {
	return false, 0, 5, 0, nil
}

// TestCommitDeferredAtomic_NilDenyCallbackFailsClosed pins that a committing
// handler whose PrepareCommit leaves DeferredCommit.Deny nil is denied with a
// structured CONDITION_FAILED error, not a nil-func-call panic, when the call
// counter denies that handler's bucket on the multi-deferred atomic-commit path.
func TestCommitDeferredAtomic_NilDenyCallbackFailsClosed(t *testing.T) {
	handler := &nilDenyHandler{}
	e := New(WithCallCounter(forceDenyAtIndexZeroCounter{}), WithConditionHandler(capability.ConditionTypeMaxCalls, handler))
	handler.e = e

	req := &capability.EnforceRequest{SessionID: "sess-1", TargetName: "tool"}
	caps := []capability.Constraint{{
		Target:  "tool",
		Actions: []string{"*"},
		// Two maxCalls with DISTINCT windows: forces the multi-deferred atomic-commit path.
		Conditions: []capability.Condition{
			&capability.MaxCallsCondition{Count: 5, WindowSeconds: 60},
			&capability.MaxCallsCondition{Count: 3, WindowSeconds: 3600},
		},
	}}

	resp := e.ValidateAction(context.Background(), req, caps)
	if resp.Decision != capability.DecisionDeny {
		t.Fatalf("decision = %q, want deny (a nil Deny callback must fail closed, not panic)", resp.Decision)
	}
	if resp.Denial == nil || resp.Denial.Code != capability.ErrCodeConditionFailed {
		t.Fatalf("denial = %+v, want CONDITION_FAILED", resp.Denial)
	}
}

// nilDenyResultHandler is a custom CommittingConditionHandler whose PrepareCommit
// supplies a non-nil Deny callback that itself returns nil — the sibling handler bug
// to nilDenyHandler's nil callback: prepareAndAdmit's guard validated that Deny was a
// non-nil function but trusted its RESULT, so a refused admission reported nil (no
// error) and read as satisfied. Pointer receiver so the copy held in the registry and
// the test's reference share the same engine pointer.
type nilDenyResultHandler struct{ e *Engine }

func (h *nilDenyResultHandler) Handle(ctx context.Context, cond capability.Condition, req *capability.EnforceRequest) *ConditionError {
	return h.e.prepareAndAdmit(ctx, h, cond, req)
}

func (h *nilDenyResultHandler) PrepareCommit(ctx context.Context, cond capability.Condition, req *capability.EnforceRequest) (DeferredCommit, bool, *ConditionError) {
	mc, key, skip, condErr := h.e.maxCallsBucket(ctx, cond, req)
	if skip {
		return DeferredCommit{}, true, nil
	}
	if condErr != nil {
		return DeferredCommit{}, false, condErr
	}
	return DeferredCommit{
		Bucket: capability.QuotaBucket{
			Key:       key,
			WindowSec: mc.WindowSeconds,
			Counted:   true,
			Limit:     float64(mc.Count),
		},
		// Deny is a real, non-nil callback that itself returns nil — the bug under test.
		Deny: func(float64, time.Duration) *ConditionError { return nil },
	}, false, nil
}

// alwaysDenyCounter is a minimal CallCounter fake whose AdmitAll always refuses
// admission for a single-bucket batch, driving prepareAndAdmit straight to its
// Deny-result handling without depending on real quota bookkeeping.
type alwaysDenyCounter struct{}

func (alwaysDenyCounter) IncrementAndGet(_ context.Context, _ string, _, _ int) (int64, error) {
	return 1, nil
}
func (alwaysDenyCounter) Peek(_ context.Context, _ string, _ int) (int64, error) {
	return 0, nil
}
func (alwaysDenyCounter) AdmitAll(_ context.Context, _ []capability.QuotaBucket) (admitted bool, deniedIndex int, total float64, retryAfter time.Duration, err error) {
	return false, 0, 5, 0, nil
}

// TestPrepareAndAdmit_NilDenyResultFailsClosed pins that prepareAndAdmit — reached
// through a CommittingConditionHandler's own Handle, the documented WithConditionHandler
// seam — denies with a structured CONDITION_FAILED error, not a silent allow, when a
// refused admission's Deny callback itself returns nil.
func TestPrepareAndAdmit_NilDenyResultFailsClosed(t *testing.T) {
	handler := &nilDenyResultHandler{}
	e := New(WithCallCounter(alwaysDenyCounter{}), WithConditionHandler(capability.ConditionTypeMaxCalls, handler))
	handler.e = e

	req := &capability.EnforceRequest{SessionID: "sess-1", TargetName: "tool"}
	cond := &capability.MaxCallsCondition{Count: 5, WindowSeconds: 60}

	condErr := handler.Handle(context.Background(), cond, req)
	if condErr == nil {
		t.Fatal("Handle returned nil (allow) for a refused admission whose Deny callback returned nil — want a fail-closed CONDITION_FAILED error")
	}
	if condErr.Code != capability.ErrCodeConditionFailed {
		t.Fatalf("condErr = %+v, want code %q", condErr, capability.ErrCodeConditionFailed)
	}
}

// TestCommitDeferredAtomic_NilDenyResultFailsClosed pins the atomic multi-deferred
// commit path's twin of the test above: a committing handler's DeferredCommit.Deny is
// a real, non-nil callback, but the CALL to it returns nil for a refused admission.
// denyFromConditionError dereferences its argument unconditionally, so the untested
// gap here was a nil-pointer panic on the enforcement goroutine, not just a bypass.
func TestCommitDeferredAtomic_NilDenyResultFailsClosed(t *testing.T) {
	handler := &nilDenyResultHandler{}
	e := New(WithCallCounter(forceDenyAtIndexZeroCounter{}), WithConditionHandler(capability.ConditionTypeMaxCalls, handler))
	handler.e = e

	req := &capability.EnforceRequest{SessionID: "sess-1", TargetName: "tool"}
	caps := []capability.Constraint{{
		Target:  "tool",
		Actions: []string{"*"},
		// Two maxCalls with DISTINCT windows: forces the multi-deferred atomic-commit path.
		Conditions: []capability.Condition{
			&capability.MaxCallsCondition{Count: 5, WindowSeconds: 60},
			&capability.MaxCallsCondition{Count: 3, WindowSeconds: 3600},
		},
	}}

	resp := e.ValidateAction(context.Background(), req, caps)
	if resp.Decision != capability.DecisionDeny {
		t.Fatalf("decision = %q, want deny (a Deny callback returning nil must fail closed, not allow or panic)", resp.Decision)
	}
	if resp.Denial == nil || resp.Denial.Code != capability.ErrCodeConditionFailed {
		t.Fatalf("denial = %+v, want CONDITION_FAILED", resp.Denial)
	}
}

// nilCounterCommitHandler is a custom CommittingConditionHandler whose
// PrepareCommit returns a complete DeferredCommit WITHOUT consulting the engine's
// call counter — unlike the built-in maxCallsBucket, which fails closed on a nil
// counter before the atomic commit ever reaches the backend. It models a library
// consumer that registers a committing handler on an engine built without
// WithCallCounter, so the atomic multi-deferred commit path reaches its backend call
// with e.counter still nil.
type nilCounterCommitHandler struct{ e *Engine }

func (h *nilCounterCommitHandler) Handle(ctx context.Context, cond capability.Condition, req *capability.EnforceRequest) *ConditionError {
	return h.e.prepareAndAdmit(ctx, h, cond, req)
}

func (h *nilCounterCommitHandler) PrepareCommit(_ context.Context, cond capability.Condition, _ *capability.EnforceRequest) (DeferredCommit, bool, *ConditionError) {
	mc, condErr := castCondition[capability.MaxCallsCondition](cond)
	if condErr != nil {
		return DeferredCommit{}, false, condErr
	}
	return DeferredCommit{
		Bucket: capability.QuotaBucket{
			Key:       "nil-counter-bucket",
			WindowSec: mc.WindowSeconds,
			Counted:   true,
			Limit:     float64(mc.Count),
		},
		Deny: func(float64, time.Duration) *ConditionError {
			return &ConditionError{Code: capability.ErrCodeConditionFailed, ConditionType: capability.ConditionTypeMaxCalls, Message: "over limit"}
		},
	}, false, nil
}

// TestCommitDeferredAtomic_NilCounterFailsClosed pins that the atomic
// multi-deferred commit path fails closed with a structured CONDITION_FAILED deny —
// not a nil-pointer panic on e.counter.AdmitAll — when a custom
// committing handler is registered on an engine built without WithCallCounter. The
// built-in maxCalls funnels through maxCallsBucket (whose nil guard surfaces earlier
// as a PrepareCommit condErr), so a custom handler that skips that guard is the only
// way this backend call is reached with a nil counter.
func TestCommitDeferredAtomic_NilCounterFailsClosed(t *testing.T) {
	handler := &nilCounterCommitHandler{}
	// NB: no WithCallCounter — e.counter stays nil.
	e := New(WithConditionHandler(capability.ConditionTypeMaxCalls, handler))
	handler.e = e

	req := &capability.EnforceRequest{SessionID: "sess-1", TargetName: "tool"}
	caps := []capability.Constraint{{
		Target:  "tool",
		Actions: []string{"*"},
		// Two committing conditions with DISTINCT windows force the multi-deferred
		// atomic-commit path (commitDeferredConditions) rather than the direct handler leg.
		Conditions: []capability.Condition{
			&capability.MaxCallsCondition{Count: 5, WindowSeconds: 60},
			&capability.MaxCallsCondition{Count: 3, WindowSeconds: 3600},
		},
	}}

	resp := e.ValidateAction(context.Background(), req, caps)
	if resp.Decision != capability.DecisionDeny {
		t.Fatalf("decision = %q, want deny (a nil call counter must fail closed, not panic)", resp.Decision)
	}
	if resp.Denial == nil || resp.Denial.Code != capability.ErrCodeConditionFailed {
		t.Fatalf("denial = %+v, want CONDITION_FAILED", resp.Denial)
	}
}

// sentinelCommitHandler is a custom CommittingConditionHandler used to exercise the
// multi-bucket atomic-commit path's observe-mode (SkipQuota) behavior. It branches on
// MaxCallsCondition.Count so one constraint can mix bucket behaviors the built-in
// maxCalls never mixes (maxCalls always derives skip solely from SkipQuota, so its
// buckets are uniform):
//
//	Count < 0  → always a validation condErr, even under SkipQuota (a committing
//	             condition whose validity is independent of the quota skip)
//	Count == 7 → always commits, IGNORING SkipQuota (violates the ctx-uniform skip
//	             contract, producing a non-uniform skip across buckets)
//	otherwise  → skips under SkipQuota, commits otherwise (the well-behaved case)
type sentinelCommitHandler struct{}

func (sentinelCommitHandler) Handle(context.Context, capability.Condition, *capability.EnforceRequest) *ConditionError {
	return nil
}

func (sentinelCommitHandler) PrepareCommit(ctx context.Context, cond capability.Condition, _ *capability.EnforceRequest) (DeferredCommit, bool, *ConditionError) {
	mc, condErr := castCondition[capability.MaxCallsCondition](cond)
	if condErr != nil {
		return DeferredCommit{}, false, condErr
	}
	commit := DeferredCommit{
		Bucket: capability.QuotaBucket{
			Key:       "sentinel-bucket",
			WindowSec: mc.WindowSeconds,
			Counted:   true,
			Limit:     float64(mc.Count),
		},
		Deny: func(float64, time.Duration) *ConditionError {
			return &ConditionError{Code: capability.ErrCodeConditionFailed, ConditionType: capability.ConditionTypeMaxCalls, Message: "over limit"}
		},
	}
	switch {
	case mc.Count < 0:
		return DeferredCommit{}, false, &ConditionError{Code: capability.ErrCodeConditionFailed, ConditionType: capability.ConditionTypeMaxCalls, Message: "invalid bucket"}
	case mc.Count == 99:
		// Reports skip AND a validation error at once. PrepareCommit's contract puts no
		// exclusion between the two, so a handler may legitimately do this.
		return DeferredCommit{}, true, &ConditionError{Code: capability.ErrCodeConditionFailed, ConditionType: capability.ConditionTypeMaxCalls, Message: "invalid bucket config"}
	case mc.Count == 7:
		return commit, false, nil // commit even under SkipQuota
	case SkipQuota(ctx):
		return DeferredCommit{}, true, nil
	default:
		return commit, false, nil
	}
}

func sentinelEngine() *Engine {
	return New(WithCallCounter(callcounter.NewInMemory()), WithConditionHandler(capability.ConditionTypeMaxCalls, sentinelCommitHandler{}))
}

// TestCommitDeferredAtomic_ObserveSurfacesLaterBucketCondErr pins that under the
// observe (SkipQuota) posture the multi-bucket commit evaluates EVERY bucket, so a later
// bucket's validation error still denies. Returning on the first bucket's skip (the prior
// behavior) masked it as an allow — the observe/enforce divergence this closes.
func TestCommitDeferredAtomic_ObserveSurfacesLaterBucketCondErr(t *testing.T) {
	e := sentinelEngine()
	req := &capability.EnforceRequest{SessionID: "s", TargetName: "tool"}
	caps := []capability.Constraint{{
		Target:  "tool",
		Actions: []string{"*"},
		Conditions: []capability.Condition{
			&capability.MaxCallsCondition{Count: 5, WindowSeconds: 60},    // skips under observe
			&capability.MaxCallsCondition{Count: -1, WindowSeconds: 3600}, // invalid: condErr even under observe
		},
	}}
	resp := e.ValidateAction(WithSkipQuota(context.Background()), req, caps)
	if resp.Decision != capability.DecisionDeny {
		t.Fatalf("decision = %q, want deny (observe must surface a later bucket's validation error, not mask it on the first skip)", resp.Decision)
	}
	if resp.Denial == nil || resp.Denial.Code != capability.ErrCodeConditionFailed {
		t.Fatalf("denial = %+v, want CONDITION_FAILED", resp.Denial)
	}
}

// TestCommitDeferredAtomic_PartialSkipFailsClosed pins that a non-uniform skip — some
// buckets skip under SkipQuota while another commits — fails closed after the loop. The
// per-bucket assertion cannot catch it (each skipping bucket individually satisfies
// SkipQuota); admitting the committing buckets while dropping the skipped ones would be a
// fail-open.
func TestCommitDeferredAtomic_PartialSkipFailsClosed(t *testing.T) {
	e := sentinelEngine()
	req := &capability.EnforceRequest{SessionID: "s", TargetName: "tool"}
	caps := []capability.Constraint{{
		Target:  "tool",
		Actions: []string{"*"},
		Conditions: []capability.Condition{
			&capability.MaxCallsCondition{Count: 5, WindowSeconds: 60},   // skips under observe
			&capability.MaxCallsCondition{Count: 7, WindowSeconds: 3600}, // commits, ignoring SkipQuota
		},
	}}
	resp := e.ValidateAction(WithSkipQuota(context.Background()), req, caps)
	if resp.Decision != capability.DecisionDeny {
		t.Fatalf("decision = %q, want deny (a partial/non-uniform skip across buckets must fail closed)", resp.Decision)
	}
	if resp.Denial == nil || resp.Denial.Code != capability.ErrCodeConditionFailed {
		t.Fatalf("denial = %+v, want CONDITION_FAILED", resp.Denial)
	}
	// HardDeny, or the guard cannot actually block. A partial skip is only reachable when
	// SkipQuota is set, which the binary sets only on a route running --audit — and there
	// the transport downgrades and FORWARDS any non-HardDeny verdict, letting the call
	// proceed with zero quota consumed on any bucket.
	if !resp.Denial.HardDeny {
		t.Error("the partial-skip deny must be HardDeny; a downgradable verdict is forwarded on the only posture that reaches this branch, so the guard would never block")
	}
}

// TestCommitDeferredAtomic_SkipDoesNotSwallowCondErr pins that a bucket reporting skip
// AND a validation error still denies. PrepareCommit's contract puts no exclusion between
// the two, so honoring skip first discarded the error — and when every bucket skipped, the
// call was ALLOWED under observe while enforce denied it: the exact observe/enforce
// divergence this function exists to prevent.
func TestCommitDeferredAtomic_SkipDoesNotSwallowCondErr(t *testing.T) {
	e := sentinelEngine()
	req := &capability.EnforceRequest{SessionID: "s", TargetName: "tool"}
	caps := []capability.Constraint{{
		Target:  "tool",
		Actions: []string{"*"},
		Conditions: []capability.Condition{
			// Both buckets skip under observe; both also report a validation error, so
			// skipped == len(deferred) and the all-skip allow would mask them.
			&capability.MaxCallsCondition{Count: 99, WindowSeconds: 60},
			&capability.MaxCallsCondition{Count: 99, WindowSeconds: 3600},
		},
	}}
	resp := e.ValidateAction(WithSkipQuota(context.Background()), req, caps)
	if resp.Decision != capability.DecisionDeny {
		t.Fatalf("decision = %q, want deny (a skipping bucket's own condErr must not be swallowed)", resp.Decision)
	}
	if resp.Denial == nil || resp.Denial.Code != capability.ErrCodeConditionFailed {
		t.Fatalf("denial = %+v, want CONDITION_FAILED", resp.Denial)
	}
}

// TestCommitDeferredAtomic_AllSkipUnderObserveAllows is the positive control: when EVERY
// bucket skips under SkipQuota (the shipped maxCalls-only observe path), quota is not
// consumed and the call is allowed.
func TestCommitDeferredAtomic_AllSkipUnderObserveAllows(t *testing.T) {
	e := sentinelEngine()
	req := &capability.EnforceRequest{SessionID: "s", TargetName: "tool"}
	caps := []capability.Constraint{{
		Target:  "tool",
		Actions: []string{"*"},
		Conditions: []capability.Condition{
			&capability.MaxCallsCondition{Count: 5, WindowSeconds: 60},
			&capability.MaxCallsCondition{Count: 6, WindowSeconds: 3600},
		},
	}}
	resp := e.ValidateAction(WithSkipQuota(context.Background()), req, caps)
	if resp.Decision != capability.DecisionAllow {
		t.Fatalf("decision = %q, want allow (all buckets skip under observe); denial %+v", resp.Decision, resp.Denial)
	}
}

// typedNilCondition is a Condition implementation used only as a nil pointer, to
// exercise the isTypedNil guard: as an interface value it is non-nil (it
// carries a concrete type), but the pointer it wraps is nil.
type typedNilCondition struct{ capability.MaxCallsCondition }

// TestRunConditions_TypedNilConditionFailsClosed pins that a Condition interface
// value wrapping a nil pointer — which survives a plain `cond == nil` check — is
// rejected with a structured deny instead of panicking in ConditionType(),
// mirroring CollectObligations' identical typed-nil directive guard.
func TestRunConditions_TypedNilConditionFailsClosed(t *testing.T) {
	e := New(WithCallCounter(callcounter.NewInMemory()))
	req := &capability.EnforceRequest{SessionID: "sess-1", TargetName: "tool"}
	var nilCond *typedNilCondition // typed nil: (*typedNilCondition)(nil)
	constraint := &capability.Constraint{
		Target:     "tool",
		Actions:    []string{"*"},
		Conditions: []capability.Condition{nilCond},
	}

	resp := e.EvaluateConditions(context.Background(), req, constraint)
	if resp.Decision != capability.DecisionDeny {
		t.Fatalf("decision = %q, want deny (a typed-nil condition must fail closed, not panic)", resp.Decision)
	}
	if resp.Denial == nil || resp.Denial.Code != capability.ErrCodeConditionFailed {
		t.Fatalf("denial = %+v, want CONDITION_FAILED", resp.Denial)
	}
	// HardDeny, like the two sibling engine-bug denies in runConditions. Without it an
	// audit-only constraint (or a route under --audit) downgrades this verdict and
	// FORWARDS the call — so a restriction the policy declared but the engine could not
	// evaluate even once would let the call through, which is the fail-open the guard
	// exists to prevent.
	if !resp.Denial.HardDeny {
		t.Error("denial.HardDeny = false; an unevaluable condition is a construction fault, not a downgradable policy verdict")
	}
}

// TestRunConditions_NullConditionIsNotDowngradedUnderAuditMode is the reachable half:
// the guard above only actually blocks if the verdict survives audit-mode downgrading,
// and an audit-only constraint is exactly where a null condition would otherwise be
// forwarded with its declared restriction never checked.
func TestRunConditions_NullConditionIsNotDowngradedUnderAuditMode(t *testing.T) {
	e := New(WithCallCounter(callcounter.NewInMemory()))
	req := &capability.EnforceRequest{SessionID: "sess-1", TargetName: "tool"}
	constraint := &capability.Constraint{
		Target:      "tool",
		Actions:     []string{"*"},
		Enforcement: "audit",
		Conditions:  []capability.Condition{nil},
	}

	resp := e.EvaluateConditions(context.Background(), req, constraint)
	if resp.Decision != capability.DecisionDeny {
		t.Fatalf("decision = %q, want deny", resp.Decision)
	}
	if resp.Denial == nil || !resp.Denial.HardDeny {
		t.Fatalf("denial = %+v, want HardDeny so the audit-only constraint cannot downgrade it to a forward", resp.Denial)
	}
}

// RecordSessionCall must key the sequenceBlock history WRITE under req.Target.Name
// VERBATIM (only whitespace-trimmed) so the explicit afterTools spelling
// ("resource:system:foo") matches, AND ALSO write a secondary marker keyed the way
// the lookup parses the bare spelling ("system:foo" -> (system, foo)), so a target
// whose name itself begins with a recognized namespace token trips the gate by
// either spelling. Recording only the prefix-stripped name failed the gate OPEN for
// the explicit spelling; recording only the verbatim name fails it OPEN for the bare
// spelling — both keys must be present.
func TestRecordSessionCall_TargetNameKeyedVerbatim(t *testing.T) {
	counter := &incrKeyCapturingCounter{}
	e := New(WithCallCounter(counter))

	// A resource whose URI begins with a recognized engine token. The afterTools
	// entry naming this antecedent is "resource:system:foo", whose lookup key is
	// (resource, "system:foo") — recording must match it byte-for-byte.
	req := &capability.EnforceRequest{
		SessionID:  "s1",
		TargetName: "system:foo",
		Target:     &capability.EnforceRequestTarget{Type: "resource", Name: "system:foo"},
	}
	if err := e.RecordSessionCall(context.Background(), req); err != nil {
		t.Fatalf("RecordSessionCall: %v", err)
	}

	// Primary: the explicit afterTools entry "resource:system:foo" strips one
	// "resource:" token via splitEnginePrefix, leaving the name "system:foo" verbatim.
	_, priorName := splitEnginePrefix("resource:system:foo")
	primaryKey := seqKeyForTest("", "s1", "resource", priorName)
	if !counter.hasKey(primaryKey) {
		t.Errorf("verbatim primary key %q not recorded; keys=%v", primaryKey, counter.incrKeys)
	}

	// Secondary: the bare afterTools entry "system:foo" splits to (system, foo).
	secType, secName := splitEnginePrefix("system:foo")
	secondaryKey := seqKeyForTest("", "s1", secType, secName)
	if !counter.hasKey(secondaryKey) {
		t.Errorf("bare-spelling secondary key %q not recorded; keys=%v", secondaryKey, counter.incrKeys)
	}
}

// recordFaultCounter admits maxCalls (AdmitAll) but fails the
// sequenceBlock-antecedent write (IncrementAndGet), reproducing the counter-fault
// the RecordSessionCall deny path is reachable through.
type recordFaultCounter struct {
	incrementAndGetCalls int
}

func (c *recordFaultCounter) IncrementAndGet(_ context.Context, _ string, _, _ int) (int64, error) {
	c.incrementAndGetCalls++
	return 0, errors.New("counter backend fault")
}
func (c *recordFaultCounter) Peek(_ context.Context, _ string, _ int) (int64, error) { return 0, nil }
func (c *recordFaultCounter) AdmitAll(_ context.Context, _ []capability.QuotaBucket) (admitted bool, deniedIndex int, total float64, retryAfter time.Duration, err error) {
	return true, 0, 0, 0, nil
}

// TestRecordSessionCall_NoSequenceBlock_NoQuotaBurnOnRecordFault is the regression
// for the maxCalls slot being burned on a RecordSessionCall-fault deny. For a
// maxCalls-only policy (no sequenceBlock), the engine derives that nothing reads the
// antecedent history and skips the write entirely, so a counter fault on that write can no
// longer turn a committed-maxCalls allow into a deny. An engine told nothing about its policy
// still records and so still denies on the fault, demonstrating both the difference and the
// fail-closed default.
func TestRecordSessionCall_NoSequenceBlock_NoQuotaBurnOnRecordFault(t *testing.T) {
	maxCallsOnly := []capability.Constraint{{
		Target:     "tool:t",
		Actions:    []string{"call"},
		Conditions: []capability.Condition{capability.MaxCallsCondition{Count: 5, WindowSeconds: 60}},
	}}
	req := &capability.EnforceRequest{
		SessionID:  "s1",
		TargetName: "t",
		Target:     &capability.EnforceRequestTarget{Type: "tool", Name: "t"},
	}

	// Engine told nothing about its policy: records the antecedent, so the IncrementAndGet
	// fault denies the call (the residual burn the invariant doc now acknowledges).
	cDefault := &recordFaultCounter{}
	respDefault := New(WithCallCounter(cDefault)).ValidateAction(context.Background(), req, maxCallsOnly)
	if respDefault.Decision != capability.DecisionDeny {
		t.Fatalf("default engine: a record fault must deny, got %v", respDefault.Decision)
	}
	if cDefault.incrementAndGetCalls == 0 {
		t.Error("default engine must attempt the antecedent write")
	}

	// Told that the policy carries only maxCalls, the engine skips the antecedent write, so
	// the same fault cannot deny — the call is allowed and IncrementAndGet is never called.
	cSkip := &recordFaultCounter{}
	respSkip := New(WithCallCounter(cSkip), WithPolicyTokens([]string{capability.ConditionTypeMaxCalls})).
		ValidateAction(context.Background(), req, maxCallsOnly)
	if respSkip.Decision != capability.DecisionAllow {
		t.Fatalf("skip-recording engine: a maxCalls-only call must be allowed despite a record-path fault, got %v (denial=%+v)", respSkip.Decision, respSkip.Denial)
	}
	if cSkip.incrementAndGetCalls != 0 {
		t.Errorf("skip-recording engine must not attempt the antecedent write, got %d calls", cSkip.incrementAndGetCalls)
	}
}

func TestMaxCalls_LogicalKeyExcludesWindow(t *testing.T) {
	counter := &keyCapturingCounter{}
	e := New(WithCallCounter(counter))

	req := &capability.EnforceRequest{
		SessionID:  "sess-1",
		TargetName: "export",
		Target:     &capability.EnforceRequestTarget{Type: "tool", Name: "export"},
	}
	constraint := &capability.Constraint{
		Target:  "tool:export",
		Actions: []string{"call"},
		Conditions: []capability.Condition{
			&capability.MaxCallsCondition{Count: 5, WindowSeconds: 300},
		},
	}

	resp := e.EvaluateConditions(context.Background(), req, constraint)
	if resp.Decision != capability.DecisionAllow {
		t.Fatalf("decision = %v, want allow: %+v", resp.Decision, resp.Denial)
	}

	// The window travels as the windowSec argument, never folded into the logical
	// key — so the backend appends it exactly once and the physical key carries it
	// once, not twice.
	wantKey := compositeCounterKey("maxcalls", "", "sess-1", "tool", "export")
	if counter.gotKey != wantKey {
		t.Errorf("maxCalls logical key = %q, want %q (window must not be in the key)", counter.gotKey, wantKey)
	}
	if strings.Contains(counter.gotKey, "300") {
		t.Errorf("maxCalls logical key %q must not embed the window 300", counter.gotKey)
	}
	if counter.gotWindowSec != 300 {
		t.Errorf("windowSec argument = %d, want 300", counter.gotWindowSec)
	}
}

func TestSchemaJSONTypeOf_AllCases(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		val  interface{}
		want string
	}{
		{"string", "hello", "string"},
		{"number", float64(3.14), "number"},
		{"boolean", true, "boolean"},
		{"object", map[string]interface{}{"k": "v"}, "object"},
		{"array", []interface{}{1, 2}, "array"},
		{"null", nil, "null"},
		{"unknown int", 42, "unknown"}, // raw int is not a JSON-decoded type
		{"unknown struct", struct{}{}, "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := schemaJSONTypeOf(tc.val); got != tc.want {
				t.Errorf("schemaJSONTypeOf(%T) = %q, want %q", tc.val, got, tc.want)
			}
		})
	}
}

func TestSchemaTypeCompatible(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		got, schema string
		val         interface{}
		want        bool
	}{
		{"string matches string", "string", "string", "x", true},
		{"number matches number", "number", "number", float64(1.5), true},
		{"whole number matches integer", "number", "integer", float64(42), true},
		{"fractional number rejects integer", "number", "integer", float64(3.14), false},
		{"string rejects integer", "string", "integer", "x", false},
		{"boolean rejects string", "boolean", "string", true, false},
	}
	for _, tc := range cases {
		if got := schemaTypeCompatible(tc.got, tc.schema, tc.val); got != tc.want {
			t.Errorf("%s: schemaTypeCompatible(%q,%q,%v) = %v, want %v", tc.name, tc.got, tc.schema, tc.val, got, tc.want)
		}
	}
}

func TestAsSequenceBlock_PointerValueAndMismatch(t *testing.T) {
	t.Parallel()

	// Pointer form.
	ptr := &capability.SequenceBlockCondition{}
	if got, ok := asCondition[capability.SequenceBlockCondition](ptr); !ok || got != ptr {
		t.Errorf("pointer form: got (%v,%v), want (%v,true)", got, ok, ptr)
	}

	// Value form: must be normalised to a non-nil pointer.
	val := capability.SequenceBlockCondition{}
	if got, ok := asCondition[capability.SequenceBlockCondition](val); !ok || got == nil {
		t.Errorf("value form: got (%v,%v), want (non-nil,true)", got, ok)
	}

	// A different condition type must not match.
	other := &capability.MaxCallsCondition{}
	if got, ok := asCondition[capability.SequenceBlockCondition](other); ok || got != nil {
		t.Errorf("mismatch: got (%v,%v), want (nil,false)", got, ok)
	}
}

// TestFileSuffix locks the presentational suffix used in allowedExtensions
// denial messages, including the compound-extension and dotfile edge cases
// raised in review. The realistic compound case ("archive.tar.gz" and the hidden
// ".archive.tar.gz") yields ".tar.gz"; the dotfile prefix is treated as a base
// name so its own dot is never a suffix boundary. This is presentational only —
// the allow/deny decision is strings.HasSuffix in handleAllowedExtensions.
func TestFileSuffix(t *testing.T) {
	t.Parallel()

	cases := []struct {
		base string
		want string
	}{
		{"backup.zip.gz", ".zip.gz"},   // compound extension, normal base name
		{"archive.tar.gz", ".tar.gz"},  // the realistic .tar.gz case
		{".archive.tar.gz", ".tar.gz"}, // hidden file, compound ext: base "archive"
		{"data.gz", ".gz"},             // single extension
		{".env", ".env"},               // bare dotfile, no internal dot
		{".tar.gz", ".gz"},             // hidden file "tar" with ext ".gz"
		{".gitignore", ".gitignore"},   // bare dotfile
		{"noext", "noext"},             // no dot at all
		{"REPORT.PDF", ".pdf"},         // suffix is lower-cased
		{"a.b.c.d", ".b.c.d"},          // multiple dots: from the first
	}
	for _, tc := range cases {
		if got := fileSuffix(tc.base); got != tc.want {
			t.Errorf("fileSuffix(%q) = %q, want %q", tc.base, got, tc.want)
		}
	}
}

// TestCompilePattern_CachesAndReuses verifies that compilePattern returns the
// identical *regexp.Regexp instance on repeat calls for the same pattern — the
// point of the cache is that the hot enforcement path does not recompile a
// static manifest pattern on every request.
func TestCompilePattern_CachesAndReuses(t *testing.T) {
	// Not parallel: asserts on the shared package-level patternCache.
	const pat = `^cache-probe-[0-9]+$`
	patternCache.Delete(pat)

	first, err := compilePattern(pat)
	if err != nil {
		t.Fatalf("first compile: unexpected error %v", err)
	}
	second, err := compilePattern(pat)
	if err != nil {
		t.Fatalf("second compile: unexpected error %v", err)
	}
	if first != second {
		t.Errorf("compilePattern returned distinct instances %p and %p; the cache should reuse the first", first, second)
	}
	if !first.MatchString("cache-probe-42") {
		t.Errorf("cached regexp does not match a value it should")
	}
}

// TestCompilePattern_BadPatternNotCached verifies that a pattern that fails to
// compile returns an error and is not stored, so a later valid registration of
// the same key would not be shadowed by a cached failure.
func TestCompilePattern_BadPatternNotCached(t *testing.T) {
	const pat = "[unclosed"
	patternCache.Delete(pat)
	if _, err := compilePattern(pat); err == nil {
		t.Fatalf("compilePattern(%q) = nil error, want a compile error", pat)
	}
	if _, ok := patternCache.Load(pat); ok {
		t.Errorf("a non-compiling pattern was cached; only successful compiles should be stored")
	}
}

// TestCompileSchemaPatterns_WalksTreeAndReports verifies that CompileSchemaPatterns
// recurses through properties and items, rejects the first malformed pattern with
// a path-qualified message, and primes the cache for valid patterns.
func TestCompileSchemaPatterns_WalksTreeAndReports(t *testing.T) {
	t.Parallel()

	// nil is a no-op.
	if err := CompileSchemaPatterns("argumentSchema", nil); err != nil {
		t.Errorf("nil schema: unexpected error %v", err)
	}

	// A valid tree compiles cleanly and primes the cache.
	good := &capability.ArgumentSchema{
		Properties: map[string]*capability.ArgumentSchema{
			"name": {Pattern: `^[a-z]+$`},
			"tags": {Items: &capability.ArgumentSchema{Pattern: `^t-[0-9]+$`}},
		},
	}
	if err := CompileSchemaPatterns("argumentSchema", good); err != nil {
		t.Fatalf("valid schema: unexpected error %v", err)
	}
	if _, ok := patternCache.Load(`^t-[0-9]+$`); !ok {
		t.Errorf("nested items pattern was not primed into the cache")
	}

	// A malformed pattern nested under a property is rejected, and the error
	// extends the supplied root with the schema-location path so the operator
	// can locate the offending node.
	bad := &capability.ArgumentSchema{
		Properties: map[string]*capability.ArgumentSchema{
			"q": {Pattern: "[unclosed"},
		},
	}
	err := CompileSchemaPatterns("argumentSchema", bad)
	if err == nil {
		t.Fatalf("malformed pattern: got nil error, want a compile error")
	}
	for _, want := range []string{"argumentSchema.properties.q", "invalid pattern"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err.Error(), want)
		}
	}
}

// ---- merged from allowed_value_precision_test.go ----

// A manifest allowedValues literal above 2^53 must authorize exactly that value
// and not its float64-rounded neighbour. With UseNumber decoding preserving the
// policy literal as json.Number, MatchAllowedValue (via numericEqual/asInt64)
// compares the integers exactly: the authored value matches, the adjacent value
// is denied.
func TestMatchAllowedValue_LargeIntegerExactMatch(t *testing.T) {
	allowed := []interface{}{json.Number("9007199254740993")} // 2^53 + 1, as decoded from the manifest

	authored := json.Number("9007199254740993") // request carrying the authorized value
	adjacent := json.Number("9007199254740992") // the float64-rounded neighbour

	if !MatchAllowedValue(authored, allowed, nil) {
		t.Errorf("the authored value %s must be allowed", authored)
	}
	if MatchAllowedValue(adjacent, allowed, nil) {
		t.Errorf("the adjacent value %s must NOT be allowed (would authorize the wrong value)", adjacent)
	}
}

// numericEqual must not collapse an exact int64 onto a non-int64 operand that
// rounds to the same float64. math.MaxInt64 (an exact int64) and MaxInt64+1=2^63
// (which overflows int64) share a float64; the allowlist authorizing only MaxInt64
// must deny a request carrying MaxInt64+1, and symmetrically.
func TestNumericEqual_MaxInt64BoundaryNotConflated(t *testing.T) {
	maxInt64 := json.Number("9223372036854775807")  // math.MaxInt64
	overInt64 := json.Number("9223372036854775808") // one past MaxInt64 (two to the 63rd power)

	if numericEqual(maxInt64, overInt64) {
		t.Errorf("MaxInt64 and MaxInt64+1 must not compare equal")
	}
	if numericEqual(overInt64, maxInt64) {
		t.Errorf("MaxInt64+1 and MaxInt64 must not compare equal (symmetric)")
	}
	if !numericEqual(maxInt64, json.Number("9223372036854775807")) {
		t.Errorf("MaxInt64 must compare equal to itself")
	}

	allowed := []interface{}{maxInt64}
	if MatchAllowedValue(maxInt64, allowed, nil) != true {
		t.Errorf("the authorized MaxInt64 must be allowed")
	}
	if MatchAllowedValue(overInt64, allowed, nil) {
		t.Errorf("MaxInt64+1 must NOT be allowed by an allowlist of only MaxInt64")
	}
}

// ---- merged from collect_obligations_test.go ----

// TestCollectObligationsValueDirective verifies that a value-typed
// RedactFieldsDirective (as opposed to a pointer) yields the same obligation
// instead of failing closed with ENFORCEMENT_ERROR.
func TestCollectObligationsValueDirective(t *testing.T) {
	e := New()

	cases := map[string]capability.Directive{
		"pointer": &capability.RedactFieldsDirective{Fields: []string{"ssn", "token"}},
		"value":   capability.RedactFieldsDirective{Fields: []string{"ssn", "token"}},
	}

	for name, dir := range cases {
		t.Run(name, func(t *testing.T) {
			c := &capability.Constraint{
				Target:     "tool:read_user",
				Actions:    []string{"call"},
				Directives: []capability.Directive{dir},
			}
			obs, deny := e.CollectObligations(nil, c, "req-1", "2026-06-14T00:00:00Z")
			if deny != nil {
				t.Fatalf("CollectObligations denied a valid redactFields directive: %+v", deny.Denial)
			}
			if len(obs) != 1 || obs[0].Type != capability.DirectiveTypeRedactFields {
				t.Fatalf("unexpected obligations: %+v", obs)
			}
			if len(obs[0].Paths) != 2 || obs[0].Paths[0] != "ssn" || obs[0].Paths[1] != "token" {
				t.Fatalf("unexpected obligation paths: %v", obs[0].Paths)
			}
		})
	}
}

// ---- merged from numeric_equal_test.go ----

func TestNumericEqual(t *testing.T) {
	tests := []struct {
		name string
		a, b any
		want bool
	}{
		// The bridge the function exists for: manifest int vs request float64.
		{"int vs equal float64", 5, float64(5), true},
		{"int vs unequal float64", 5, float64(6), false},
		{"int vs fractional float64", 5, 5.5, false},
		{"negative int vs float64", -3, float64(-3), true},

		// Exact integer comparison above 2^53: these two int64 values share a
		// float64 representation, so the old float-only path matched them. They
		// must now be distinguished.
		{"distinct int64 above 2^53", int64(9007199254740993), int64(9007199254740992), false},
		{"equal int64 above 2^53", int64(9007199254740993), int64(9007199254740993), true},

		// A request float64 that exactly equals a large manifest int still matches;
		// one that differs by one (but rounds to the same float) must not.
		{"int64 vs exact large float64", int64(9007199254740992), float64(9007199254740992), true},
		{"int64 vs near-but-distinct large float64", int64(9007199254740993), float64(9007199254740992), false},

		// Mixed signed/unsigned integer types compare by value.
		{"int vs uint equal", 7, uint(7), true},
		{"int8 vs int64 equal", int8(42), int64(42), true},

		// Non-numeric and bool are not numerically equal.
		{"bool is not numeric", true, 1, false},
		{"string is not numeric", "5", 5, false},
		{"nil is not numeric", nil, 0, false},

		// Float-to-float still works for genuinely fractional values.
		{"equal float64", 1.5, 1.5, true},
		{"unequal float64", 1.5, 2.5, false},

		// json.Number (produced by a json.Decoder in UseNumber mode) must compare
		// by value against both manifest ints and request floats. Without
		// the json.Number arms in asInt64/toFloat64 these all returned false.
		{"json.Number int vs int", json.Number("5"), 5, true},
		{"json.Number int vs unequal int", json.Number("5"), 6, false},
		{"json.Number int vs float64", json.Number("5"), float64(5), true},
		{"json.Number fractional vs float64", json.Number("1.5"), 1.5, true},
		{"json.Number negative vs int", json.Number("-3"), -3, true},
		{"json.Number large int distinct", json.Number("9007199254740993"), int64(9007199254740992), false},
		{"json.Number large int equal", json.Number("9007199254740993"), int64(9007199254740993), true},

		// Above 2^63 NEITHER operand is int64-representable, so the exact int64 arm
		// and the one-side-only guard both fall through and the float64 fallback
		// rounds distinct integers onto a shared value. allowedValues:
		// [9223372036854775808] then admitted the argument 9223372036854775809 — a
		// value outside the declared set, the fail-open direction, on a boundary.
		{"distinct integers above 2^63", json.Number("9223372036854775808"), json.Number("9223372036854775809"), false},
		{"equal integers above 2^63", json.Number("9223372036854775808"), json.Number("9223372036854775808"), true},
		{"distinct integers far above 2^63", json.Number("100000000000000000000000"), json.Number("100000000000000000000001"), false},
		{"exponent form equals its expansion", json.Number("1e30"), json.Number("1000000000000000000000000000000"), true},
		// A float64 operand IS its exact binary value: one that reads as 2^63 is 2^63,
		// and is genuinely distinct from the decimal literal 2^63+1.
		{"float64 2^63 vs the next integer", float64(9223372036854775808), json.Number("9223372036854775809"), false},
		{"float64 2^63 vs its own literal", float64(9223372036854775808), json.Number("9223372036854775808"), true},

		// The exact arm is restricted to INTEGERS on purpose. A fractional decimal
		// literal and its float64 coercion are different rationals (0.1 is not the
		// binary double nearest 0.1), so comparing those exactly would break working
		// policies for no security gain — the approximation is consistent on both sides.
		{"fractional literal vs its float64 coercion", json.Number("0.1"), 0.1, true},
		{"fractional literal vs its own text", json.Number("0.1"), json.Number("0.1"), true},
		{"distinct fractionals stay distinct", json.Number("0.1"), json.Number("0.2"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := numericEqual(tt.a, tt.b); got != tt.want {
				t.Errorf("numericEqual(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
			// Symmetry: the comparison must not depend on argument order.
			if got := numericEqual(tt.b, tt.a); got != tt.want {
				t.Errorf("numericEqual(%v, %v) [swapped] = %v, want %v", tt.b, tt.a, got, tt.want)
			}
		})
	}
}

// ---- merged from retry_after_test.go ----

func TestRetryAfterSeconds(t *testing.T) {
	const windowSec = 60

	cases := []struct {
		name string
		d    time.Duration
		want int64
	}{
		{"zero falls back to window", 0, windowSec},
		{"exactly one second", time.Second, 1},
		{"sub-second rounds up", 500 * time.Millisecond, 1},
		{"ceiling of fractional", 1500 * time.Millisecond, 2},
		{"exact multiple", 3 * time.Second, 3},
		{"negative sub-second falls back to window", -500 * time.Millisecond, windowSec},
		{"negative nanosecond falls back to window", -1 * time.Nanosecond, windowSec},
		{"negative whole second falls back to window", -1 * time.Second, windowSec},
		{"large negative falls back to window", -9 * time.Hour, windowSec},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := retryAfterSeconds(tc.d, windowSec); got != tc.want {
				t.Errorf("retryAfterSeconds(%v, %d) = %d, want %d", tc.d, windowSec, got, tc.want)
			}
		})
	}
}

// TestExactRat_BoundsTheParse is the regression for the DoS the exact-comparison arm
// introduced. big.Rat.SetString's mantissa scan is superlinear and its exponent handling
// materializes 10^N, so handing it an unbounded caller literal turned one tool-call
// argument into seconds of CPU on the pre-forward enforcement path: a 1M-digit
// fractional literal cost ~1.8 s, and the nine-byte "1e1000000" ~25 ms and ~1 MiB, each
// multiplied by the number of allowedValues/enum entries. Arguments decode in UseNumber
// mode, so they arrive here as their verbatim literal text.
func TestExactRat_BoundsTheParse(t *testing.T) {
	for _, tc := range []struct {
		name string
		lit  string
	}{
		{"over-long fractional", "0." + strings.Repeat("7", capability.MaxNumericLiteralLen*4)},
		{"over-long integer", strings.Repeat("9", capability.MaxNumericLiteralLen+1)},
		{"huge positive exponent", "1e1000000"},
		{"huge negative exponent", "1e-1000000"},
		{"unparseable exponent", "1e" + strings.Repeat("9", 40)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := exactRat(json.Number(tc.lit)); ok {
				t.Errorf("exactRat accepted a literal past the parse bounds (%d bytes); it must decline so the caller takes the float64 path", len(tc.lit))
			}
		})
	}

	// Declining must not cost exactness where the arm actually matters: integers around
	// and above 2^63 need tens of digits, far inside the bound.
	for _, tc := range []struct {
		name string
		a, b string
		want bool
	}{
		{"2^63 vs its successor", "9223372036854775808", "9223372036854775809", false},
		{"2^63 vs itself", "9223372036854775808", "9223372036854775808", true},
		{"exponent form vs expansion", "1e30", "1000000000000000000000000000000", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := numericEqual(json.Number(tc.a), json.Number(tc.b)); got != tc.want {
				t.Errorf("numericEqual(%s, %s) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}
