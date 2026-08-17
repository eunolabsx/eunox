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
// coverage that does not exist. requireUsableOptions reaches TOP-LEVEL interface fields only, and
// StdioProxyOptions carries no kill switch, counter or flow store at all — they reach that
// transport through LoadUpstreamPDP, which is why that seam and BuildRoutes check their own. A
// field that is a map, slice or struct is not descended into: HTTPGatewayOptions.Routes is the live
// example, so NewHTTPProxyGateway checks its values for nil where it walks them, and what stays
// outside every check is an interface held INSIDE an UpstreamRoute — closed today by visibility
// rather than by rule (those fields are unexported, so only BuildRoutes and WrapRoutesWithJWT can
// populate them). Worth knowing before a nested options struct is added, since that is the shape
// the reflective walk would silently stop covering.

package transport

import (
	"fmt"
	"reflect"
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
// this whole file exists to replace, one level up. Same rule nilValue states for its kind list.
func requireUsableOptions(opts any) {
	v := reflect.ValueOf(opts)
	if v.Kind() != reflect.Struct {
		panic(fmt.Sprintf("eunox: requireUsableOptions needs an options struct by value, got %T", opts))
	}
	ty := v.Type()
	for i := range ty.NumField() {
		field := v.Field(i)
		if field.Kind() != reflect.Interface || field.IsNil() {
			// A nil interface is ABSENT, which is the caller's own business: every constructor here
			// already decides what an omitted subsystem means (a deny-all PDP, an in-memory kill
			// switch, os.Stderr), and those decisions are deliberate.
			continue
		}
		if !nilValue(field.Elem()) {
			continue
		}
		panic(wiringFault(ty.Name()+"."+ty.Field(i).Name, field.Elem().Type()))
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
	if v == nil || !nilInterface(v) {
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

// nilInterface reports whether v holds no value at all — the interface itself nil, or a typed nil
// inside a non-nil interface. The ONE answer in this package to a question several call sites ask
// (a diagnostic seam's subsystem, a server-initiated leg's sink), because `x == nil` compares the
// INTERFACE and passes for an interface holding a nil pointer, whose method then dereferences a nil
// receiver.
//
// It answers for a value that IS nil, never for a wrapper AROUND one: reflecting into an embedded
// field would refuse decorators that legitimately forward elsewhere.
func nilInterface(v any) bool {
	if v == nil {
		return true
	}
	return nilValue(reflect.ValueOf(v))
}

// nilValue reports whether rv is a nil of a kind that HAS a nil. The kinds are named rather than
// tried because IsNil panics on any other one — a guard must not become the crash it prevents — and
// reflection rather than a type switch for redisutil.IsNilClient's reason one layer down: a list of
// concrete types is a second thing to keep in agreement, while nilness is one question for every
// type including one nobody has written yet.
//
// Interface is in the list for completeness and is unreachable from both callers: reflect.ValueOf
// unwraps to the dynamic type, and Value.Elem() on an interface field yields its DYNAMIC value,
// which Go never lets be another interface. It is here so the list enumerates IsNil's whole panic
// set rather than the subset today's callers happen to reach.
func nilValue(rv reflect.Value) bool {
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.UnsafePointer:
		return rv.IsNil()
	default:
		return false
	}
}
