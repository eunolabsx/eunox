// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// What a WIRED-but-nil value means at this package's seams, and where that question is answered.
//
// `x == nil` compares the INTERFACE, so it passes for an interface holding a nil pointer — and the
// call behind it dereferences a nil receiver. Both of this package's constructors normalize an
// absent subsystem that way (`if opts.KS == nil { opts.KS = killswitch.NewInMemory() }`), so a
// caller wiring `var ks *killswitch.Redis` walked straight through the substitution and panicked
// inside go-redis on the reconcile goroutine.
//
// Two answers, and they are not alternatives — a wiring fault should be refused where it is made,
// and a subsystem that becomes unusable later is still reported by whoever asks:
//
//   - CONSTRUCTION refuses it, naming the field (requireUsableOptions). A proxy built on unusable
//     wiring cannot enforce what its operator configured, and there is no good later moment to
//     discover that.
//   - The diagnostic seam reports it as DEGRADED (healthSnapshot.fold), which stays the backstop it
//     is: it answers for any reporter, including one this package never constructed.
//
// Two entry points, because the seams have two shapes and the completeness argument differs:
// requireUsableOptions reflects over an options STRUCT (so a field added later cannot inherit
// "unchecked"), and requireUsable names one PARAMETER (where the compiler already enforces
// completeness — adding a parameter changes the signature, which a struct field does not).
//
// The residual, stated rather than implied, because the first version of this paragraph claimed a
// coverage that does not exist. requireUsableOptions descends into struct-kind fields (so a nested
// options block cannot inherit "unchecked" — see requireUsableFields for why that terminates), but
// StdioProxyOptions carries no kill switch, counter or flow store at all: they reach that transport
// through LoadUpstreamPDP, which is why that seam and BuildRoutes check their own. What the walk
// still does not look through is a POINTER, MAP or SLICE — deliberately for the first, since a
// pointer field is a subsystem the caller built and its internals are its own package's business.
// HTTPGatewayOptions.Routes is the live map, and it is closed at its own construction site:
// NewHTTPProxyGateway refuses a nil route value AND the one interface a route holds. Nor does the
// walk read a field reachable only through an unexported name, which is a different kind of gap:
// such a field is not caller-supplied wiring at all, so it is skipped rather than refused. That
// leaves no CALLER-SETTABLE interface in either options graph outside a check, and both limits are
// asserted by wiring_test.go rather than resting on this paragraph.

package transport

import (
	"fmt"
	"reflect"

	"github.com/eunolabs/eunox/pkg/capability"
)

// requireUsableOptions refuses an options struct carrying a WIRED-but-nil interface field, naming
// the field it found. It is the rule for both transports' options structs rather than a branch for
// one subsystem: the same hazard sits on every interface a caller can hand over.
//
// The three answers to unusable wiring, since only one of them is honest here. SUBSTITUTING a
// working default — what the absent case already does — is a security downgrade for the kill
// switch in particular: revocation silently stops crossing replicas, which is the one subsystem
// whose whole job is to work when everything else has gone wrong. Returning an ERROR is the honest
// signature for a constructor that can be handed unusable wiring, and is the change to make if
// these ever grow a fallible step; today they have none, and giving both constructors an error
// return for this one case would put an `if err != nil` at every call site for a condition no
// correct caller can produce. So: panic, at the seam, naming the field — a wiring fault reported as
// a wiring fault rather than as a nil dereference in a dependency's goroutine three layers down.
//
// REFLECTIVE over the struct rather than a hand-listed set of fields. A list is the same
// completeness problem the declaration tables in this package exist to remove: a field added later
// inherits "unchecked" silently, which is exactly how the kill switch came to be the only one asked
// about. It also means the check can only ever apply to INTERFACE-typed fields, which is the
// distinction that makes it safe — a nil *audit.Sink or a nil AfterListen hook is a legitimately
// ABSENT value, and only an interface can be non-nil while holding nothing.
//
// It refuses a non-struct argument by name rather than reaching NumField and dying inside reflect:
// the parameter is `any`, so a caller passing &opts compiles, and "reflect: NumField of non-struct
// type *transport.HTTPGatewayOptions" names neither the field nor the fault — which is the crash
// this whole file exists to replace, one level up.
func requireUsableOptions(opts any) {
	v := reflect.ValueOf(opts)
	if v.Kind() != reflect.Struct {
		panic(fmt.Sprintf("eunox: requireUsableOptions needs an options struct by value, got %T", opts))
	}
	requireUsableFields(v.Type().Name(), v)
}

// requireUsableFields is the walk itself, over one struct and every struct NESTED in it by value.
//
// It descends because a depth-1 walk contradicted the completeness claim above in exactly the shape
// the reflection was chosen to prevent: the two options structs already share ~8 fields, so folding
// them into a `Common CommonOptions` block is an ordinary refactor that moves Stderr — and any
// future subsystem — one level down, where a depth-1 walk stops seeing it and the test asserting
// the walk's coverage stops asserting on it. Both would still pass, which is the failure mode a
// hand-listed set has.
//
// Descending needs no visited set and no depth cap, and that is a property of the type system
// rather than of today's structs: Go forbids a struct type from containing itself by value,
// directly or transitively, so the value-struct graph reachable from here is finite and acyclic.
// Only VALUE structs are descended into for that reason — and for a second one that matters more:
// a POINTER field is a subsystem the caller built (an *audit.Sink, an *pdp.JWTPDP), and walking
// into one would judge that subsystem's internal wiring by this guard's rule, refusing a construct
// whose own package deliberately holds a typed nil somewhere. The caller's wiring is what this
// refuses; what a subsystem does inside itself is not this guard's business.
//
// What that leaves is the map/slice/pointer residual, and the fields reflect will not let it READ
// (anything reachable only through an unexported name). Both are ASSERTED by the test rather than
// only described here. HTTPGatewayOptions.Routes is the live map, closed at its own construction
// site (NewHTTPProxyGateway checks each route's value AND its PDP, the one interface held inside
// one), and the unreadable set is by definition not caller-supplied wiring.
func requireUsableFields(path string, v reflect.Value) {
	ty := v.Type()
	for i := range ty.NumField() {
		field, name := v.Field(i), path+"."+ty.Field(i).Name
		switch field.Kind() {
		case reflect.Struct:
			requireUsableFields(name, field)
		case reflect.Interface:
			if field.IsNil() {
				// A nil interface is ABSENT, which is the caller's own business: every constructor
				// here already decides what an omitted subsystem means (a deny-all PDP, an
				// in-memory kill switch, os.Stderr), and those decisions are deliberate.
				continue
			}
			if !field.CanInterface() {
				// Not caller-supplied wiring, which is this guard's whole subject. reflect's
				// read-only flag marks exactly the fields unreachable through exported names, and
				// a field an outside caller cannot even SET is not one they can hand a typed nil
				// to; this package's own wiring is answered where it is made instead, through
				// requireUsable at the seam that hands the value over (a route's PDP is the live
				// example).
				//
				// REFUSING here was the first shape and is wrong in the direction that matters:
				// the read-only flag PROPAGATES, so an EXPORTED interface inside an unexported
				// block is unreadable too — the refusal would fire on valid wiring while naming a
				// field that is already exported, and the nested block is precisely the refactor
				// the descent above exists to support.
				continue
			}
			if !capability.IsTypedNil(field.Interface()) {
				continue
			}
			panic(wiringFault(name, field.Elem().Type()))
		}
	}
}

// requireUsable is the same refusal for a subsystem handed over as a PARAMETER rather than an
// options field — LoadUpstreamPDP's and BuildRoutes' counter, flow store and kill switch, which
// reach the stdio transport without passing through any options struct at all.
//
// Named one by one, which is the hand-listed shape requireUsableOptions avoids — and acceptable
// here for a reason that does not hold for a struct: a parameter list is complete by compilation.
// Adding a parameter changes the signature and every caller with it, so a subsystem cannot be added
// to one of these seams without the author seeing this list; a struct field can.
//
// A nil value is ABSENT and passes: the engine guards these with `if e.counter == nil` precisely so
// an unwired backend denies rather than panics. A TYPED nil defeats that guard — it is the case
// those `== nil` tests cannot see — and reaches AdmitAll on the enforcement goroutine.
func requireUsable(field string, v any) {
	if v == nil || !capability.IsNilValue(v) {
		return
	}
	panic(wiringFault(field, reflect.TypeOf(v)))
}

// wiringFault is what both refusals say. It names the field and the concrete type, and deliberately
// does NOT claim the value would panic on use: (*os.File)(nil) satisfies io.Writer and returns
// ErrInvalid rather than dereferencing anything, and every diagnostic write in this package
// discards its error — so that implementation would have run silently rather than crashed. Refusing
// it is still right (a writer that drops every line is not the writer the caller wired), but the
// reason is that the value is unusable, not that it is guaranteed to fault.
func wiringFault(field string, held reflect.Type) string {
	return fmt.Sprintf(
		"eunox: %s holds a typed nil (%s): the field is wired but holds no usable value — "+
			"a call on it either dereferences a nil receiver or silently does nothing. "+
			"Leave it nil to take the default, or pass a usable value.",
		field, held)
}

// The nilness question this file asks — "the interface itself nil, or a typed nil inside a non-nil
// one" — is capability.IsNilValue's, not a predicate of this package's own. It used to be both: a
// kind switch here and a composition over it, against a shared answer this package already links in
// dozens of files. The dependency-weight argument that licenses internal/redisutil's separate copy
// (go-redis and the stdlib alone) does not apply here, so the copy existed for no stated reason —
// and its kind list had drifted WIDER than the shared one, which is the direction that hides the
// divergence: every current field is pointer-shaped, so the two agreed until the first func- or
// map-typed subsystem. The shared predicate is now the wide one and this file has none.
