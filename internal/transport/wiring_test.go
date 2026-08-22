// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// A wiring fault refused where it is made, rather than discovered as a nil dereference somewhere
// downstream — and the two facts the guard must keep apart: a field left nil (absent, the
// constructor's own business) and a field holding a typed nil (wired and unusable).

package transport

import (
	"fmt"
	"io"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/internal/config"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/callcounter"
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

	// Through the one producer rather than a second copy of its text: a message asserted twice is a
	// message that can be improved in one place and fail in the other, which is what this did.
	assert.PanicsWithValue(t,
		wiringFault("HTTPGatewayOptions.KS", reflect.TypeOf(deadRedis)),
		func() { NewHTTPProxyGateway(HTTPGatewayOptions{KS: deadRedis}) },
		"the refusal must name the FIELD; that is the whole difference between this and the panic it replaces")
	assert.Contains(t, wiringFault("X.Y", reflect.TypeOf(deadRedis)), "X.Y holds a typed nil (*killswitch.Redis)",
		"and the text must carry the field and the concrete type, which is what makes it a diagnosis")

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

// typedNilOptions is one nilable stand-in per interface-typed option field, keyed by its dotted
// PATH from the options struct — the same key the guard's own refusal names, so a field that moves
// into a nested block needs a new entry rather than silently matching its old leaf name. The guard
// needs no such list — it reflects over the struct — but a TEST does: nothing can synthesize a
// value implementing an arbitrary interface at runtime, so each field's is named here and the
// completeness check below is what makes the naming mandatory rather than optional.
var typedNilOptions = map[string]any{
	"HTTPGatewayOptions.KS":     (*killswitch.Redis)(nil),
	"HTTPGatewayOptions.Stderr": (*strings.Builder)(nil),
	"StdioProxyOptions.PDP":     (*pdp.JWTPDP)(nil),
	"StdioProxyOptions.Stderr":  (*strings.Builder)(nil),
}

// TestWiring_GuardCoversEveryInterfaceOption is the completeness half: every interface a caller can
// hand either constructor is refused when it holds a typed nil.
//
// The guard reaches them by reflecting over the struct, so a NEW interface-typed option is covered
// with no edit to it — which is the property this asserts. A hand-listed guard would leave a later
// field "unchecked" silently, which is precisely how the kill switch came to be the only subsystem
// this question was ever asked about.
//
// The walk here DESCENDS the same way the guard does. Iterating one level while the guard iterated
// one level was the shared blind spot: a field moved into a nested options block would leave both
// green — the guard by not reaching it, the test by not asking about it — which is a completeness
// claim asserted against its own limitation.
func TestWiring_GuardCoversEveryInterfaceOption(t *testing.T) {
	t.Parallel()
	for _, opts := range []any{HTTPGatewayOptions{}, StdioProxyOptions{}} {
		ty := reflect.TypeOf(opts)
		interfaces := interfaceOptionSetters(ty, ty.Name(), map[reflect.Type]bool{})
		require.NotEmpty(t, interfaces, "%s declares no interface fields, so this guard would pass vacuously", ty.Name())
		for path, fill := range interfaces {
			stand, named := typedNilOptions[path]
			require.True(t, named,
				"%s is an interface a caller can hand a typed nil, and this test has no stand-in for it; name one in typedNilOptions so the guard is actually exercised on it", path)
			v := reflect.New(ty).Elem()
			fill(v, reflect.ValueOf(stand))
			assert.PanicsWithValue(t,
				wiringFault(path, reflect.TypeOf(stand)),
				func() { requireUsableOptions(v.Interface()) },
				"%s must be refused, naming itself", path)
		}
	}
}

// optionSetter fills one interface leaf of an options value, materializing whatever containers
// stand between the root and it. A locator alone would not do: a map's elements are not
// addressable, so reaching one means building the element and putting it back.
type optionSetter func(dst reflect.Value, val reflect.Value)

// interfaceOptionSetters collects every interface reachable from ty the way requireUsableValue
// reaches one — descending struct fields and the elements of a map, slice or array, and stopping at
// a pointer — keyed by the same dotted path the guard's refusal names. It mirrors that traversal on
// purpose, so the test asks about exactly the set the guard covers: a container of interfaces added
// to either options struct shows up here and demands a stand-in, which is the property a paths-only
// walk over FIELDS did not have.
//
// The visited set is scoped to the current recursion, as pointerElementContainerPaths' is, and for
// the reason cyclicOptions pins as legal: this walks the TYPE graph, which a container may close a
// cycle in. The guard's own containerSeen is no help here — it bounds a VALUE walk — so without
// this a self-referential container option would hang the completeness test rather than fail it.
func interfaceOptionSetters(ty reflect.Type, path string, walking map[reflect.Type]bool) map[string]optionSetter {
	out := map[string]optionSetter{}
	if walking[ty] {
		return out
	}
	walking[ty] = true
	defer delete(walking, ty)

	switch ty.Kind() {
	case reflect.Interface:
		out[path] = func(dst, val reflect.Value) { dst.Set(val) }
	case reflect.Struct:
		for i := range ty.NumField() {
			field := ty.Field(i)
			// Unexported stops the walk here for the same reason it stops the guard: reflect will
			// neither read such a field nor let this test SET one, and a field no caller can set is
			// not wiring a caller handed over.
			if !field.IsExported() {
				continue
			}
			for nested, inner := range interfaceOptionSetters(field.Type, path+"."+field.Name, walking) {
				out[nested] = func(dst, val reflect.Value) { inner(dst.Field(i), val) }
			}
		}
	case reflect.Slice:
		for nested, inner := range interfaceOptionSetters(ty.Elem(), path+"[0]", walking) {
			out[nested] = func(dst, val reflect.Value) {
				dst.Set(reflect.MakeSlice(ty, 1, 1))
				inner(dst.Index(0), val)
			}
		}
	case reflect.Array:
		if ty.Len() == 0 {
			break
		}
		for nested, inner := range interfaceOptionSetters(ty.Elem(), path+"[0]", walking) {
			out[nested] = func(dst, val reflect.Value) { inner(dst.Index(0), val) }
		}
	case reflect.Map:
		key := reflect.New(ty.Key()).Elem()
		for nested, inner := range interfaceOptionSetters(ty.Elem(), mapElemPath(path, key), walking) {
			out[nested] = func(dst, val reflect.Value) {
				elem := reflect.New(ty.Elem()).Elem()
				inner(elem, val)
				m := reflect.MakeMap(ty)
				m.SetMapIndex(key, elem)
				dst.Set(m)
			}
		}
	}
	return out
}

// nestedOptions is the refactor the depth-1 walk would have stopped covering: the two options
// structs already share ~8 fields, so folding them into a common block is ordinary. Neither ships
// one today, which is exactly why the descent needs a subject here — otherwise the recursion is
// asserted only by never being taken.
type nestedOptions struct {
	Common struct {
		Deeper struct{ Stderr io.Writer }
	}
}

// TestWiring_GuardDescendsIntoNestedOptions pins the descent itself, at a depth no accidental
// single `continue` covers, and pins the path the refusal names: "which field" is the whole
// difference between this panic and the nil dereference it replaces, and a nested field named by
// its leaf alone is ambiguous the moment two blocks carry a Stderr.
func TestWiring_GuardDescendsIntoNestedOptions(t *testing.T) {
	t.Parallel()
	var deadWriter *strings.Builder
	opts := nestedOptions{}
	opts.Common.Deeper.Stderr = deadWriter

	assert.PanicsWithValue(t,
		wiringFault("nestedOptions.Common.Deeper.Stderr", reflect.TypeOf(deadWriter)),
		func() { requireUsableOptions(opts) },
		"a nested options block must not inherit \"unchecked\" — that is the shape the reflective walk exists to keep covered")
	assert.NotPanics(t, func() { requireUsableOptions(nestedOptions{}) },
		"and an absent nested field is still absent")
}

// unreadableOptions holds the two shapes reflect will not let the walk read: an unexported
// interface field, and an EXPORTED one nested under an unexported block — the read-only flag
// propagates, so both are unreadable and neither is settable by an outside caller.
type unreadableOptions struct {
	hidden io.Writer
	block  struct{ Stderr io.Writer }
}

// TestWiring_UnreadableFieldsAreNotTheGuardsSubject pins the skip and, more importantly, pins that
// it is a skip rather than a refusal.
//
// Refusing was the first shape, on the argument that it kept the completeness claim exact. It does
// not survive the propagation rule: an EXPORTED interface inside an unexported block is unreadable
// too, so the refusal fired on valid wiring while telling its author to export a field that
// already was — and a shared nested options block is the very refactor the descent was added to
// support. The honest line is the one the guard draws everywhere else: what it refuses is wiring a
// CALLER handed over, and a field an outside caller cannot set is not that.
func TestWiring_UnreadableFieldsAreNotTheGuardsSubject(t *testing.T) {
	t.Parallel()
	var deadWriter *strings.Builder

	opts := unreadableOptions{hidden: deadWriter}
	opts.block.Stderr = deadWriter
	require.False(t, reflect.ValueOf(opts).Field(1).Field(0).CanInterface(),
		"the premise: an exported field under an unexported one is read-only too, which is what makes refusing here fire on valid wiring")
	assert.NotPanics(t, func() { requireUsableOptions(opts) },
		"neither unreadable field is caller-supplied wiring, so neither is this guard's subject")

	// And the residual that skip leaves, asserted rather than described: such a field is answered
	// where this package hands it over instead (requireUsable), the way a route's PDP is.
	assert.Panics(t, func() { requireUsable("X.hidden", deadWriter) },
		"the seam that hands an in-package subsystem over is what covers what the walk cannot read")
}

// aliasedContainerOptions is one container reached through two fields, only one of them exported —
// an ordinary shape once a container option exists (an unexported index beside the map a caller
// populates).
type aliasedContainerOptions struct {
	hidden map[string]io.Writer
	Shown  map[string]io.Writer
}

// TestWiring_AnUnreadableAliasDoesNotConsumeItsContainer pins that the skip happens BEFORE the
// container is recorded.
//
// Entering a container records it, and reflect's read-only flag propagates, so walking the
// unreadable alias first consumed the key and turned the exported alias into a repeat visit — every
// element skipped, nothing refused. Whether the caller's own wiring was checked at all then came
// down to field declaration ORDER, which is not a rule anyone could follow.
func TestWiring_AnUnreadableAliasDoesNotConsumeItsContainer(t *testing.T) {
	t.Parallel()
	var deadWriter *strings.Builder

	shared := map[string]io.Writer{"a": deadWriter}
	opts := aliasedContainerOptions{hidden: shared, Shown: shared}
	require.False(t, reflect.ValueOf(opts).Field(0).CanInterface(),
		"the premise: the unexported alias is read-only, and it is declared first")

	assert.PanicsWithValue(t, wiringFault(`aliasedContainerOptions.Shown["a"]`, reflect.TypeOf(deadWriter)),
		func() { requireUsableOptions(opts) },
		"the exported alias is caller-supplied wiring whatever an unexported field beside it aliases")
}

// TestWiring_TheGuardStopsAtAPointer pins the OTHER side of the descent, which is a decision rather
// than a limit: a pointer field is a subsystem the CALLER built, and judging its internals by this
// guard's rule would refuse a construct whose own package deliberately holds a typed nil somewhere.
// What this guard refuses is the caller's wiring.
func TestWiring_TheGuardStopsAtAPointer(t *testing.T) {
	t.Parallel()
	type held struct{ W io.Writer }
	type opts struct{ Sub *held }
	type viaContainer struct {
		Subs  []*held
		ByKey map[string]*held
	}

	var deadWriter *strings.Builder
	assert.NotPanics(t, func() { requireUsableOptions(opts{Sub: &held{W: deadWriter}}) },
		"the walk must not look through a pointer into a subsystem the caller built")

	// The stop is on the POINTER, not on the container holding it: a container's elements are
	// walked, and one that is a pointer is exactly as much a caller-built subsystem as a field is.
	assert.NotPanics(t, func() {
		requireUsableOptions(viaContainer{
			Subs:  []*held{{W: deadWriter}},
			ByKey: map[string]*held{"a": {W: deadWriter}},
		})
	}, "reaching an element does not change whose business a pointer's internals are")

	// The live example of that residual is closed at its own construction site instead.
	assert.PanicsWithValue(t,
		wiringFault(`HTTPGatewayOptions.Routes["a"].pdp`, reflect.TypeOf((*pdp.JWTPDP)(nil))),
		func() {
			NewHTTPProxyGateway(HTTPGatewayOptions{Routes: map[string]*UpstreamRoute{"a": {name: "a", pdp: (*pdp.JWTPDP)(nil)}}})
		},
		"a route's PDP is the one interface held inside a map value, and it must be refused by name rather than left to visibility")
}

// containerOptions is the shape the walk gained, and the one a hand-written seam check does not
// generalize to: interfaces held in a slice, a map, an array and a value struct inside one. Neither
// options struct ships a container of interfaces today, which is exactly why the descent needs a
// subject here — otherwise it is asserted only by never being taken.
type containerOptions struct {
	Writers    []io.Writer
	ByName     map[string]io.Writer
	Fixed      [1]io.Writer
	Nested     []struct{ Stderr io.Writer }
	Deep       map[string][]io.Writer
	Subsystems []*nestedOptions
}

// TestWiring_GuardDescendsIntoContainerElements pins the descent through a container and the path
// each element is named by — `Routes["a"]` being the format the live seam check already produces,
// so a refusal reads the same wherever it came from.
func TestWiring_GuardDescendsIntoContainerElements(t *testing.T) {
	t.Parallel()
	var deadWriter *strings.Builder
	dead := reflect.TypeOf(deadWriter)

	for _, tc := range []struct {
		path string
		opts func() containerOptions
	}{
		{"containerOptions.Writers[0]", func() containerOptions {
			return containerOptions{Writers: []io.Writer{deadWriter}}
		}},
		{`containerOptions.ByName["a"]`, func() containerOptions {
			return containerOptions{ByName: map[string]io.Writer{"a": deadWriter}}
		}},
		{"containerOptions.Fixed[0]", func() containerOptions {
			return containerOptions{Fixed: [1]io.Writer{deadWriter}}
		}},
		{"containerOptions.Nested[0].Stderr", func() containerOptions {
			return containerOptions{Nested: []struct{ Stderr io.Writer }{{Stderr: deadWriter}}}
		}},
		{`containerOptions.Deep["a"][0]`, func() containerOptions {
			return containerOptions{Deep: map[string][]io.Writer{"a": {deadWriter}}}
		}},
	} {
		assert.PanicsWithValue(t, wiringFault(tc.path, dead),
			func() { requireUsableOptions(tc.opts()) },
			"%s must be refused, naming itself — a container of interfaces inherited no check at all", tc.path)
	}

	assert.NotPanics(t, func() { requireUsableOptions(containerOptions{}) },
		"an empty container holds no wiring, so there is nothing to refuse")
	assert.NotPanics(t, func() {
		opts := containerOptions{Subsystems: []*nestedOptions{{}}}
		opts.Subsystems[0].Common.Deeper.Stderr = deadWriter
		requireUsableOptions(opts)
	}, "and the pointer stop still holds one container in")
}

// cyclicOptions is the value cycle a container's type permits and a struct's does not. It is not a
// shape any options struct would take, but the walk's termination must not rest on that: a hung
// constructor is a worse diagnosis than the nil dereference this file exists to replace.
type cyclicOptions struct {
	Stderr io.Writer
	Kids   []cyclicOptions
}

// TestWiring_GuardTerminatesOnACyclicContainer pins that the cycle is bounded AND that bounding it
// does not skip the first visit's real work — a visited set that recorded too eagerly would
// terminate by never looking at anything.
func TestWiring_GuardTerminatesOnACyclicContainer(t *testing.T) {
	t.Parallel()
	var deadWriter *strings.Builder

	kids := make([]cyclicOptions, 1)
	kids[0].Kids = kids
	assert.NotPanics(t, func() { requireUsableOptions(cyclicOptions{Kids: kids}) },
		"a container value that closes a cycle must be walked once, not forever")

	kids[0].Stderr = deadWriter
	assert.PanicsWithValue(t, wiringFault("cyclicOptions.Kids[0].Stderr", reflect.TypeOf(deadWriter)),
		func() { requireUsableOptions(cyclicOptions{Kids: kids}) },
		"and the wiring inside that cycle is still this guard's subject")
}

// TestWiring_TheCoverageMirrorTerminatesOnACyclicType pins the completeness test's own walk against
// the shape cyclicOptions makes legal. It recurses the TYPE graph, which the guard's value-level
// containerSeen does not bound, so a self-referential container option would hang this suite rather
// than fail it — a test that never finishes reports nothing at all.
func TestWiring_TheCoverageMirrorTerminatesOnACyclicType(t *testing.T) {
	t.Parallel()
	ty := reflect.TypeOf(cyclicOptions{})
	setters := interfaceOptionSetters(ty, ty.Name(), map[reflect.Type]bool{})

	assert.Equal(t, []string{"cyclicOptions.Stderr"}, slices.Sorted(maps.Keys(setters)),
		"pruning a non-simple path loses no interface: every one reachable in the type graph is "+
			"reachable without re-entering a cycle, and it is the PATH that carries the stand-in")
}

// containersClosedAtTheirSeam names every option field holding a container the walk deliberately
// stops inside — one whose elements are POINTERS, which is the same subsystem-internals stop it
// applies to a pointer FIELD — together with where that container is closed instead.
//
// This is the residual the descent above does not remove, and the reason it is a declaration rather
// than a paragraph: two hand-written lines at one construction site are exactly the shape a second
// container inherits nothing from, silently. A new entry here is a deliberate act with a stated
// seam; a new pointer-element container without one fails the build.
var containersClosedAtTheirSeam = map[string]string{
	"HTTPGatewayOptions.Routes": "NewHTTPProxyGateway refuses a nil route value and the one interface a route holds (route.pdp)",
}

// TestWiring_PointerElementContainersAreDeclared is what turns that residual from an assertion
// about today's fields into one the next field must answer.
func TestWiring_PointerElementContainersAreDeclared(t *testing.T) {
	t.Parallel()
	found := map[string]bool{}
	for _, opts := range []any{HTTPGatewayOptions{}, StdioProxyOptions{}} {
		ty := reflect.TypeOf(opts)
		for _, path := range pointerElementContainerPaths(ty, ty.Name(), map[reflect.Type]bool{}) {
			found[path] = true
			seam, declared := containersClosedAtTheirSeam[path]
			require.True(t, declared,
				"%s holds pointer elements, which the guard walks up to and stops at; close it at the seam that builds it and name that seam in containersClosedAtTheirSeam", path)
			assert.NotEmpty(t, seam, "%s must say WHERE it is closed, not merely that it is", path)
		}
	}
	for path := range containersClosedAtTheirSeam {
		assert.True(t, found[path],
			"%s is declared as closed at its seam but is no longer a pointer-element container option; drop the entry", path)
	}
}

// pointerElementContainerPaths collects the containers reachable from ty whose ELEMENTS are
// pointers, as the dotted paths the guard would have named them by. It descends the same shapes the
// guard does; the visited set is scoped to the current recursion because a type — unlike a value
// struct — may legally reach itself through a container.
func pointerElementContainerPaths(ty reflect.Type, path string, walking map[reflect.Type]bool) []string {
	if walking[ty] {
		return nil
	}
	walking[ty] = true
	defer delete(walking, ty)

	var out []string
	switch ty.Kind() {
	case reflect.Struct:
		for i := range ty.NumField() {
			if field := ty.Field(i); field.IsExported() {
				out = append(out, pointerElementContainerPaths(field.Type, path+"."+field.Name, walking)...)
			}
		}
	case reflect.Map, reflect.Slice, reflect.Array:
		if ty.Elem().Kind() == reflect.Pointer {
			return []string{path}
		}
		elem := path + "[0]"
		if ty.Kind() == reflect.Map {
			elem = mapElemPath(path, reflect.New(ty.Key()).Elem())
		}
		out = pointerElementContainerPaths(ty.Elem(), elem, walking)
	}
	return out
}

// TestWiring_NonStructArgumentIsRefusedByName pins the guard against becoming the crash it
// replaces. The parameter is `any`, so `requireUsableOptions(&opts)` compiles — and reflect's own
// "NumField of non-struct type" names neither the field nor the fault, which is the diagnosis-free
// panic this whole file exists to remove, one level up.
func TestWiring_NonStructArgumentIsRefusedByName(t *testing.T) {
	t.Parallel()
	for _, bad := range []any{nil, &HTTPGatewayOptions{}, 42, "opts"} {
		assert.PanicsWithValue(t,
			"eunox: requireUsableOptions needs an options struct by value, got "+fmt.Sprintf("%T", bad),
			func() { requireUsableOptions(bad) },
			"%T must be refused by name rather than inside reflect", bad)
	}
}

// TestWiring_PositionalSubsystemsAreRefusedToo pins the seam the options guard cannot reach.
//
// StdioProxyOptions carries no kill switch, counter or flow store — all three reach that transport
// through LoadUpstreamPDP — so the constructor's guard sees a fully-built PDP and can refuse nothing
// behind it. These are also the subsystems the engine guards with `x == nil` so an unwired backend
// DENIES rather than panics, and a typed nil is exactly the value those guards cannot see.
func TestWiring_PositionalSubsystemsAreRefusedToo(t *testing.T) {
	t.Parallel()
	var deadCounter *callcounter.Redis
	var deadKS *killswitch.Redis

	assert.PanicsWithValue(t, wiringFault("LoadUpstreamPDP counter", reflect.TypeOf(deadCounter)), func() {
		_, _, _, _, _ = LoadUpstreamPDP(&config.UpstreamConfig{Name: "u"}, config.HostTransportStdio, "", deadCounter, nil, nil, false)
	})
	assert.PanicsWithValue(t, wiringFault("BuildRoutes ks", reflect.TypeOf(deadKS)), func() {
		_, _ = BuildRoutes(&config.GatewayConfig{}, nil, nil, nil, deadKS, false, nil, io.Discard)
	})

	// And an ABSENT one still passes: a nil counter is what an unwired backend looks like, and the
	// engine denies on it deliberately.
	assert.NotPanics(t, func() {
		_, _, _, _, _ = LoadUpstreamPDP(&config.UpstreamConfig{Name: "u"}, config.HostTransportStdio, "", nil, nil, nil, false)
	})
}

// TestWiring_ARouteBindsToOneProxy pins the refusal that keeps a caller-owned route map from being
// silently taken over.
//
// NewHTTPProxyGateway re-parents each route's notice table and replaces its collapse windows IN
// PLACE, on values the caller still holds. A second proxy over the same map therefore repointed the
// first proxy's per-route buckets at its own aggregate — so a flood on one silenced the other's
// diagnostics — and re-armed windows that were mid-incident, with every guard on both reading green.
func TestWiring_ARouteBindsToOneProxy(t *testing.T) {
	t.Parallel()
	routes := map[string]*UpstreamRoute{"a": {name: "a"}}

	first := NewHTTPProxyGateway(HTTPGatewayOptions{Routes: routes})
	require.NotNil(t, first.routes["a"].notices, "the first proxy claims the route and wires it")

	assert.PanicsWithValue(t,
		"eunox: HTTPGatewayOptions.Routes[\"a\"] is already bound to another HTTPProxy: a route holds "+
			"per-upstream diagnostic state that a second proxy would take over, silencing the first's "+
			"lines and re-arming its collapse windows. Build routes per proxy.",
		func() { NewHTTPProxyGateway(HTTPGatewayOptions{Routes: routes}) },
		"the second construction must be refused rather than quietly repointing the first proxy's tables")

	// And a nil VALUE in the same map is the other way that map reaches the loop unusable.
	assert.Panics(t, func() {
		NewHTTPProxyGateway(HTTPGatewayOptions{Routes: map[string]*UpstreamRoute{"b": nil}})
	}, "a nil route was dereferenced one line under the guard that exists to name a wiring fault")
}
