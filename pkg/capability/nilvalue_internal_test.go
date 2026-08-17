// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The one nilness predicate three layers share, and the two things it must not get wrong: the
// kinds it answers for, and the ones it must not call reflect.IsNil on.

package capability

import (
	"testing"
	"unsafe"
)

// TestIsTypedNil_AnswersEveryNilableKind pins the width.
//
// It was Pointer-only, which was behaviour-preserving for this package's own callers (a decoded
// condition is always pointer-shaped) and a silent hole for the consumers that now share it: a
// transport wiring guard refusing a typed-nil subsystem sees whatever kind a caller hands over, and
// the first func- or map-typed one would have walked straight through a pointer-only answer. Every
// case below is a NON-nil interface holding a nil value, which is the whole subject.
func TestIsTypedNil_AnswersEveryNilableKind(t *testing.T) {
	t.Parallel()
	var (
		ptr    *int
		m      map[string]int
		fn     func()
		sl     []int
		ch     chan int
		unsafP unsafe.Pointer
	)
	for name, v := range map[string]any{
		"pointer":        ptr,
		"map":            m,
		"func":           fn,
		"slice":          sl,
		"chan":           ch,
		"unsafe.Pointer": unsafP,
	} {
		if v == nil {
			t.Fatalf("%s: the case is only meaningful for a NON-nil interface holding a nil value", name)
		}
		if !IsTypedNil(v) {
			t.Errorf("%s: a wired-but-nil %s must answer true; the caller's next move is a method call that dereferences it", name, name)
		}
	}
}

// TestIsTypedNil_IsFalseForEverythingElse is the half that keeps the guard from becoming the crash
// it prevents: reflect.IsNil PANICS outside the kinds above, which is why they are named rather
// than tried. A plain-nil interface is false by the same rule (Kind Invalid) — see IsNilValue for
// the composition that answers it.
func TestIsTypedNil_IsFalseForEverythingElse(t *testing.T) {
	t.Parallel()
	notNil := 7
	for name, v := range map[string]any{
		"plain nil interface": nil,
		"int":                 0,
		"empty string":        "",
		"zero struct":         struct{ A int }{},
		"zero array":          [2]int{},
		"live pointer":        &notNil,
	} {
		if IsTypedNil(v) {
			t.Errorf("%s: must not be reported as a typed nil", name)
		}
	}
}

// TestIsNilValue_JoinsBothFacts pins the composition, which is the half three call sites had each
// written for themselves: `x == nil` alone misses the typed nil, and IsTypedNil alone misses the
// plain one.
func TestIsNilValue_JoinsBothFacts(t *testing.T) {
	t.Parallel()
	var ptr *int
	notNil := 7
	for name, tc := range map[string]struct {
		v    any
		want bool
	}{
		"plain nil interface": {nil, true},
		"typed nil":           {ptr, true},
		"live value":          {&notNil, false},
		"zero int":            {0, false},
	} {
		if got := IsNilValue(tc.v); got != tc.want {
			t.Errorf("%s: IsNilValue = %v, want %v", name, got, tc.want)
		}
	}
}
