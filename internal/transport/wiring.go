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
// RESIDUAL, stated rather than implied: the constructor half is a rule for the OPTIONS STRUCTS,
// which is what makes it complete without a list. An exported seam taking its subsystems as
// positional parameters (BuildRoutes' counter, flow store and kill switch) is outside it — checking
// those means naming them one by one, which is the hand-listed shape this avoids. The binary hands
// the same values to both, so the constructor still refuses them on the path a proxy is actually
// built through; a library consumer calling BuildRoutes alone is the gap.

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
func requireUsableOptions(opts any) {
	v := reflect.ValueOf(opts)
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
		panic(fmt.Sprintf(
			"eunox: %s.%s holds a typed nil (%s): the field is wired but every call on it dereferences a nil receiver. "+
				"Leave it nil to take this constructor's default, or pass a usable value.",
			ty.Name(), ty.Field(i).Name, field.Elem().Type()))
	}
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
// Interface is in the list for completeness. reflect.ValueOf unwraps to the dynamic type and never
// yields it, but a Value reached through a struct FIELD (requireUsableOptions) can be one.
func nilValue(rv reflect.Value) bool {
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.UnsafePointer:
		return rv.IsNil()
	default:
		return false
	}
}
