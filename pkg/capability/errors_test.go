// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
)

// TestDenialWireCode_CoversEveryCode fails closed when a symbolic denial code
// (ErrCode*) has no explicit wire mapping in DenialWireCode. Without this, a new
// code would ship on the wire as CAPABILITY_DENIED (-32002) via the fallback while
// its own error.data.code said otherwise — the exact silent divergence the mapping
// was consolidated to prevent. Every code in AllDenialCodes must map with ok=true.
func TestDenialWireCode_CoversEveryCode(t *testing.T) {
	t.Parallel()
	for _, code := range capability.AllDenialCodes {
		wire, ok := capability.DenialWireCode(code)
		if !ok {
			t.Errorf("denial code %q has no explicit wire mapping in DenialWireCode (would silently default to CAPABILITY_DENIED)", code)
		}
		if wire == 0 {
			t.Errorf("denial code %q mapped to wire code 0 (unset)", code)
		}
	}
}

// TestAllDenialCodes_MatchesErrCodeConstants closes the const→list direction that the
// value-level coverage tests cannot: TestDenialWireCode_CoversEveryCode only iterates
// AllDenialCodes, so a new ErrCode* constant omitted from the list would ship on the wire
// as CAPABILITY_DENIED via the DenialWireCode fallback with no test failing. Go cannot
// reflect over untyped-string consts, so this parses errors.go, collects every ErrCode*
// const's value, and asserts the set is exactly AllDenialCodes — a new ErrCode* is then
// forced into both the list (here) and a DenialWireCode case (by the coverage test).
func TestAllDenialCodes_MatchesErrCodeConstants(t *testing.T) {
	t.Parallel()

	// Locate errors.go beside this test file via runtime.Caller rather than assuming the
	// process cwd is the package dir, so the guard does not silently break if the test is
	// ever run from another working directory.
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed; cannot locate errors.go")
	}
	errorsGo := filepath.Join(filepath.Dir(thisFile), "errors.go")

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, errorsGo, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", errorsGo, err)
	}

	srcCodes := map[string]struct{}{}
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if !strings.HasPrefix(name.Name, "ErrCode") || i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				val, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatalf("unquote %s value %q: %v", name.Name, lit.Value, err)
				}
				srcCodes[val] = struct{}{}
			}
		}
	}
	if len(srcCodes) == 0 {
		t.Fatal("no ErrCode* constants found in errors.go; parser or naming changed")
	}

	listCodes := map[string]struct{}{}
	for _, code := range capability.AllDenialCodes {
		listCodes[code] = struct{}{}
	}

	for code := range srcCodes {
		if _, ok := listCodes[code]; !ok {
			t.Errorf("ErrCode constant %q is missing from AllDenialCodes (a denial carrying it would silently ship as CAPABILITY_DENIED)", code)
		}
	}
	for code := range listCodes {
		if _, ok := srcCodes[code]; !ok {
			t.Errorf("AllDenialCodes entry %q has no matching ErrCode* constant in errors.go", code)
		}
	}
}

// TestDenialWireCode_KnownMappings pins the symbolic→wire pairing so a change to a
// wire code is a deliberate, reviewed edit rather than an accident.
func TestDenialWireCode_KnownMappings(t *testing.T) {
	t.Parallel()
	cases := []struct {
		code string
		want int
	}{
		{capability.ErrCodeInvalidParams, capability.JSONRPCCodeInvalidParams},
		{capability.ErrCodeAuthorizationFailed, capability.JSONRPCCodeAuthorizationFailed},
		{capability.ErrCodeKillSwitch, capability.JSONRPCCodeAuthorizationFailed},
		{capability.ErrCodeSamplingDenied, capability.JSONRPCCodeAuthorizationFailed},
		{capability.ErrCodeConditionFailed, capability.JSONRPCCodeConditionFailed},
		{capability.ErrCodeRateLimited, capability.JSONRPCCodeConditionFailed},
		{capability.ErrCodeValueNotPermitted, capability.JSONRPCCodeConditionFailed},
		{capability.ErrCodeEnforcementError, capability.JSONRPCCodeEnforcementError},
		{capability.ErrCodeAuditUnavailable, capability.JSONRPCCodeEnforcementError},
		{capability.ErrCodeCapabilityDenied, capability.JSONRPCCodeCapabilityDenied},
	}
	for _, c := range cases {
		if got, ok := capability.DenialWireCode(c.code); !ok || got != c.want {
			t.Errorf("DenialWireCode(%q) = (%d, %v), want (%d, true)", c.code, got, ok, c.want)
		}
	}
	// An unrecognized code returns the CAPABILITY_DENIED fallback with ok=false.
	if got, ok := capability.DenialWireCode("NOT_A_REAL_CODE"); ok || got != capability.JSONRPCCodeCapabilityDenied {
		t.Errorf("DenialWireCode(unknown) = (%d, %v), want (%d, false)", got, ok, capability.JSONRPCCodeCapabilityDenied)
	}
}
