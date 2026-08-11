// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// A wiring fault refused where it is made, rather than discovered as a nil dereference somewhere
// downstream — and the two facts the guard must keep apart: a field left nil (absent, the
// constructor's own business) and a field holding a typed nil (wired and unusable).

package transport

import (
	"reflect"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/killswitch"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWiring_TypedNilSubsystemIsRefusedAtConstruction pins the constructor half of the answer.
//
// The health seam already reports a wired-but-nil subsystem as degraded, but that guard is only
// reachable by a proxy that STANDS: `opts.KS == nil` compares the interface, so a typed nil walked
// through the in-memory substitution and panicked inside ObserveRevocations — a nil receiver
// dereference in a dependency's reconcile goroutine, which is not a diagnosis.
func TestWiring_TypedNilSubsystemIsRefusedAtConstruction(t *testing.T) {
	t.Parallel()
	var deadRedis *killswitch.Redis

	assert.PanicsWithValue(t,
		"eunox: HTTPGatewayOptions.KS holds a typed nil (*killswitch.Redis): the field is wired but every call on it dereferences a nil receiver. "+
			"Leave it nil to take this constructor's default, or pass a usable value.",
		func() { NewHTTPProxyGateway(HTTPGatewayOptions{KS: deadRedis}) },
		"the refusal must name the FIELD; that is the whole difference between this and the panic it replaces")

	// The rule is the options struct's, not the kill switch's: every interface a caller can hand
	// over has the same hazard, and the guard reaches them by reflection precisely so a field added
	// later cannot inherit "unchecked".
	var deadWriter *strings.Builder
	assert.Panics(t, func() { NewHTTPProxyGateway(HTTPGatewayOptions{Stderr: deadWriter}) },
		"a typed-nil Stderr writes every diagnostic line through a nil receiver")

	var deadPDP *pdp.JWTPDP
	assert.Panics(t, func() { NewStdioProxy(StdioProxyOptions{PDP: deadPDP}) },
		"and the same rule holds on the other transport, where a typed-nil PDP would decide nothing rather than deny")
}

// TestWiring_AbsentSubsystemIsNotAWiringFault is the other half, and the reason the guard tests the
// interface's CONTENT rather than the field: a nil field is an omission every constructor here
// already answers deliberately (an in-memory kill switch, a deny-all PDP, os.Stderr), and refusing
// it would break every caller that legitimately omits one.
func TestWiring_AbsentSubsystemIsNotAWiringFault(t *testing.T) {
	t.Parallel()
	assert.NotPanics(t, func() { NewHTTPProxyGateway(HTTPGatewayOptions{}) })
	assert.NotPanics(t, func() { NewStdioProxy(StdioProxyOptions{}) })

	// A nil CONCRETE pointer stays absent too. The guard cannot reach one — it looks only at
	// interface-typed fields — which is what makes it safe to apply to the whole struct: an audit
	// sink is legitimately optional (--require-audit=off) and a nil one must construct.
	assert.NotPanics(t, func() { NewHTTPProxyGateway(HTTPGatewayOptions{Sink: nil, JWTPDP: nil}) })
}

// typedNilOptions is one nilable stand-in per interface-typed option field, keyed by field name.
// The guard needs no such list — it reflects over the struct — but a TEST does: nothing can
// synthesize a value implementing an arbitrary interface at runtime, so each field's is named here
// and the completeness check below is what makes the naming mandatory rather than optional.
var typedNilOptions = map[string]any{
	"KS":     (*killswitch.Redis)(nil),
	"PDP":    (*pdp.JWTPDP)(nil),
	"Stderr": (*strings.Builder)(nil),
}

// TestWiring_GuardCoversEveryInterfaceOption is the completeness half: every interface a caller can
// hand either constructor is refused when it holds a typed nil.
//
// The guard reaches them by reflecting over the struct, so a NEW interface-typed option is covered
// with no edit to it — which is the property this asserts. A hand-listed guard would leave a later
// field "unchecked" silently, which is precisely how the kill switch came to be the only subsystem
// this question was ever asked about.
func TestWiring_GuardCoversEveryInterfaceOption(t *testing.T) {
	t.Parallel()
	for _, opts := range []any{HTTPGatewayOptions{}, StdioProxyOptions{}} {
		ty := reflect.TypeOf(opts)
		interfaces := 0
		for i := range ty.NumField() {
			name := ty.Field(i).Name
			if ty.Field(i).Type.Kind() != reflect.Interface {
				continue
			}
			interfaces++
			stand, named := typedNilOptions[name]
			require.True(t, named,
				"%s.%s is an interface a caller can hand a typed nil, and this test has no stand-in for it; name one in typedNilOptions so the guard is actually exercised on it", ty.Name(), name)
			v := reflect.New(ty).Elem()
			v.Field(i).Set(reflect.ValueOf(stand))
			assert.PanicsWithValue(t,
				"eunox: "+ty.Name()+"."+name+" holds a typed nil ("+reflect.TypeOf(stand).String()+"): the field is wired but every call on it dereferences a nil receiver. "+
					"Leave it nil to take this constructor's default, or pass a usable value.",
				func() { requireUsableOptions(v.Interface()) },
				"%s.%s must be refused, naming itself", ty.Name(), name)
		}
		require.Positive(t, interfaces, "%s declares no interface fields, so this guard would pass vacuously", ty.Name())
	}
}
