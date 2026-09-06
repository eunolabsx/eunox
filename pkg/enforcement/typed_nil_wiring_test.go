// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package enforcement_test

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/flowlabelstore"
)

// A subsystem handed over as a TYPED nil is a non-nil interface, so it walks straight past the
// `x == nil` reads that route to each subsystem's fail-closed absent case and panics on the
// first method call that dereferences the receiver. The engine is exported with no
// requireUsableOptions wall in front of it (the transport's own guard covers the proxy's
// options struct, not a library caller's), so these are the shapes an embedder reaches
// directly. Every case here asserts the REFUSAL the absent case already promises — never a
// panic, since a decision point that crashes produces no decision at all and the supervisor,
// not the policy, then decides the traffic.

// nilEvaluator's methods dereference the receiver, which is what makes the typed nil fatal
// rather than merely odd — the shape any evaluator holding configuration has. Its sibling
// doubles are the package's existing ones: faultyCounter and newFakeClock dereference too.
type nilEvaluator struct{ backend string }

func (e *nilEvaluator) Evaluate(context.Context, string, interface{}, interface{}, *capability.EnforceRequest) *enforcement.ConditionError {
	_ = e.backend
	return nil
}

// UsesEngineSubsystems makes this the SubsystemDependent shape New itself calls through, so a
// typed nil crashes the constructor and not only the request.
func (e *nilEvaluator) UsesEngineSubsystems() []capability.EngineSubsystem {
	_ = e.backend
	return nil
}

// nilFlowStore is the one double with no counterpart in this package; it forwards to an inner
// store so its field reads are load-bearing rather than blank assignments.
type nilFlowStore struct{ inner capability.FlowLabelStore }

func (s *nilFlowStore) Add(ctx context.Context, key string, labels ...string) error {
	return s.inner.Add(ctx, key, labels...)
}

func (s *nilFlowStore) Get(ctx context.Context, key string) ([]string, error) {
	return s.inner.Get(ctx, key)
}

func (s *nilFlowStore) Remove(ctx context.Context, key string, labels ...string) error {
	return s.inner.Remove(ctx, key, labels...)
}

func (s *nilFlowStore) Clear(ctx context.Context, key string) error {
	return s.inner.Clear(ctx, key)
}

// One body per subsystem, so every one of them is held to the same assertions rather than to
// whichever the copy it was written from happened to carry.
func TestTypedNilSubsystems_DenyRatherThanPanic(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		opt  enforcement.Option
		cond capability.Condition
	}{
		// The evaluator is also read during New (policyConditionHandler asks it which
		// subsystems it reads), so WithPolicyTokens naming "policy" covers the constructor
		// half of the same defect.
		"policy evaluator": {
			opt:  enforcement.WithPolicyEvaluator((*nilEvaluator)(nil)),
			cond: capability.PolicyCondition{Backend: "opa", Config: map[string]interface{}{"path": "x"}},
		},
		"call counter": {
			opt:  enforcement.WithCallCounter((*faultyCounter)(nil)),
			cond: capability.MaxCallsCondition{Count: 1, WindowSeconds: 60},
		},
		"flow-label store": {
			opt:  enforcement.WithFlowLabelStore((*nilFlowStore)(nil)),
			cond: capability.FlowLabelCondition{Allow: []string{capability.FlowLabelPublic}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			caps := []capability.Constraint{{
				Target:     "tool:send_email",
				Actions:    []string{"call"},
				Conditions: []capability.Condition{tc.cond},
			}}
			eng := enforcement.New(tc.opt, enforcement.WithPolicyTokens([]string{tc.cond.ConditionType()}))

			resp := eng.ValidateAction(context.Background(), req("s-1", "send_email"), caps)
			require.Equal(t, capability.DecisionDeny, resp.Decision)
			require.NotNil(t, resp.Denial)
			assert.Equal(t, capability.ErrCodeEnforcementError, resp.Denial.Code,
				"a subsystem that cannot be called reached no verdict")
			assert.False(t, resp.Denial.Downgradable(),
				"an observing route must not forward a call nothing evaluated")
		})
	}
}

// A real subsystem still wins, so the normalization cannot be read as "options are advisory".
func TestWiredSubsystemsStillTakeEffect(t *testing.T) {
	t.Parallel()

	caps := []capability.Constraint{{
		Target:     "tool:send_email",
		Actions:    []string{"call"},
		Conditions: []capability.Condition{capability.FlowLabelCondition{Allow: []string{capability.FlowLabelPublic}}},
	}}
	eng := enforcement.New(enforcement.WithFlowLabelStore(&nilFlowStore{inner: flowlabelstore.NewInMemory()}))
	assert.Equal(t, capability.DecisionAllow,
		eng.ValidateAction(context.Background(), req("s-1", "send_email"), caps).Decision)
}

// The clock has no fail-closed absent case to route to — every read is a bare e.clock.Now() —
// so absent means the DEFAULT here, not nil.
func TestWithClock_ValuelessClockLeavesTheSystemClock(t *testing.T) {
	t.Parallel()

	for name, opt := range map[string]enforcement.Option{
		"plain nil": enforcement.WithClock(nil),
		"typed nil": enforcement.WithClock((*fakeClock)(nil)),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			eng := enforcement.New(opt)
			require.NotNil(t, eng.Clock())
			assert.WithinDuration(t, time.Now(), eng.Clock().Now(), time.Minute)

			// The decision path stamps DecidedAt from that clock; before the fix this panicked
			// on the first timeWindow evaluation.
			caps := []capability.Constraint{{
				Target:     "tool:send_email",
				Actions:    []string{"call"},
				Conditions: []capability.Condition{capability.TimeWindowCondition{NotBefore: "00:00", NotAfter: "23:59"}},
			}}
			assert.NotEmpty(t, eng.ValidateAction(context.Background(), req("s-1", "send_email"), caps).DecidedAt)
		})
	}
}

// A REAL clock still wins, and a nil RECEIVER answers the system clock rather than panicking
// the deny path this accessor exists to serve — the rule its two sibling exported methods
// state on themselves.
func TestClock_RealClockWinsAndNilEngineAnswers(t *testing.T) {
	t.Parallel()

	frozen := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	assert.Equal(t, frozen, enforcement.New(enforcement.WithClock(newFakeClock(frozen))).Clock().Now())

	var unwired *enforcement.Engine
	require.NotNil(t, unwired.Clock())
	assert.WithinDuration(t, time.Now(), unwired.Clock().Now(), time.Minute)
}

// wiredOrAbsent's whole argument is that an option is the only way these fields are ever set,
// and handlers.go SPENDS that claim — policyConditionHandler.UsesEngineSubsystems declines the
// typed-nil guard its immediate sibling carries because the option normalizes. A hand-written
// list of options is what lets the claim lapse silently, so the set is DERIVED from the
// sources, as nil_seam_coverage_test.go derives its seams: an option taking an interface must
// normalize, and a field assigned anywhere but an option fails the build.
func TestEveryInterfaceTypedOptionNormalizesItsArgument(t *testing.T) {
	t.Parallel()

	// The subsystem fields whose reads route a nil to a fail-closed absent case. A field added
	// here without an option to match is the direct-assignment case the walk below catches.
	subsystemFields := map[string]bool{
		"clock": true, "counter": true, "flowStore": true, "policyEvaluator": true,
	}

	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	checkedOptions := 0
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", entry.Name()), nil, 0)
		require.NoError(t, err)

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Body == nil {
				continue
			}
			// An option constructor: returns Option, takes exactly one parameter.
			if !returnsOption(fn) || fn.Type.Params == nil || len(fn.Type.Params.List) != 1 {
				continue
			}
			src := nodeText(t, fset, fn.Body)
			assigned := assignedSubsystemFields(src, subsystemFields)
			if len(assigned) == 0 {
				continue
			}
			checkedOptions++
			assert.Contains(t, src, "wiredOrAbsent",
				"%s assigns %v but does not normalize its argument; a typed nil would survive every `== nil` read that routes to the fail-closed absent case",
				fn.Name.Name, assigned)
		}
	}
	assert.GreaterOrEqual(t, checkedOptions, 4, "the walk found no options; its own selector has drifted")
}

func returnsOption(fn *ast.FuncDecl) bool {
	if fn.Type.Results == nil || len(fn.Type.Results.List) != 1 {
		return false
	}
	ident, ok := fn.Type.Results.List[0].Type.(*ast.Ident)
	return ok && ident.Name == "Option"
}

func assignedSubsystemFields(body string, fields map[string]bool) []string {
	var assigned []string
	for field := range fields {
		if strings.Contains(body, "e."+field+" =") {
			assigned = append(assigned, field)
		}
	}
	return assigned
}

func nodeText(t *testing.T, fset *token.FileSet, node ast.Node) string {
	t.Helper()
	src, err := os.ReadFile(fset.File(node.Pos()).Name())
	require.NoError(t, err)
	start := fset.Position(node.Pos()).Offset
	end := fset.Position(node.End()).Offset
	return string(src[start:end])
}
