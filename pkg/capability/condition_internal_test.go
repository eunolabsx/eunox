// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestIPRangeCondition_Compile covers the load-time pre-compilation of ipRange
// CIDRs: a compiled condition exposes ready *net.IPNet values that
// match the same IPs net.ParseCIDR would, an uncompiled one reports no networks
// so the handler falls back to per-request parsing, and a malformed CIDR errors
// without clobbering any previously compiled result.
func TestIPRangeCondition_Compile(t *testing.T) {
	t.Run("valid CIDRs compile and match", func(t *testing.T) {
		c := &IPRangeCondition{CIDRs: []string{"10.0.0.0/8", "192.168.0.0/16"}}
		if err := c.Compile(); err != nil {
			t.Fatalf("Compile: unexpected error: %v", err)
		}
		networks, ok := c.Networks()
		if !ok {
			t.Fatal("Networks: ok = false after Compile, want true")
		}
		if len(networks) != 2 {
			t.Fatalf("Networks: got %d networks, want 2", len(networks))
		}
		// In-range and out-of-range IPs resolve as net.ParseCIDR would.
		cases := []struct {
			ip   string
			want bool
		}{
			{"10.1.2.3", true},
			{"192.168.50.50", true},
			{"172.16.0.1", false},
			{"8.8.8.8", false},
		}
		for _, tc := range cases {
			ip := net.ParseIP(tc.ip)
			var matched bool
			for _, nw := range networks {
				if nw.Contains(ip) {
					matched = true
					break
				}
			}
			if matched != tc.want {
				t.Errorf("IP %s: matched=%v, want %v", tc.ip, matched, tc.want)
			}
		}
	})

	t.Run("uncompiled reports no networks", func(t *testing.T) {
		c := &IPRangeCondition{CIDRs: []string{"10.0.0.0/8"}}
		if networks, ok := c.Networks(); ok || networks != nil {
			t.Errorf("Networks before Compile = (%v, %v), want (nil, false)", networks, ok)
		}
	})

	t.Run("malformed CIDR errors and leaves prior result untouched", func(t *testing.T) {
		c := &IPRangeCondition{CIDRs: []string{"10.0.0.0/8"}}
		if err := c.Compile(); err != nil {
			t.Fatalf("first Compile: unexpected error: %v", err)
		}
		first, _ := c.Networks()

		c.CIDRs = []string{"10.0.0.0/8", "not-a-cidr"}
		err := c.Compile()
		if err == nil {
			t.Fatal("Compile: expected error for malformed CIDR, got nil")
		}
		// The earlier compiled slice is still in place (Compile commits only on
		// full success), so the condition never ends up half-compiled.
		got, ok := c.Networks()
		if !ok {
			t.Fatal("Networks: ok = false after failed recompile, want the prior result")
		}
		if len(got) != len(first) {
			t.Errorf("Networks: got %d networks after failed recompile, want %d (unchanged)", len(got), len(first))
		}
	})

	t.Run("idempotent recompile", func(t *testing.T) {
		c := &IPRangeCondition{CIDRs: []string{"10.0.0.0/8"}}
		if err := c.Compile(); err != nil {
			t.Fatalf("Compile: unexpected error: %v", err)
		}
		if err := c.Compile(); err != nil {
			t.Fatalf("second Compile: unexpected error: %v", err)
		}
		if networks, ok := c.Networks(); !ok || len(networks) != 1 {
			t.Errorf("Networks after recompile = (len %d, %v), want (1, true)", len(networks), ok)
		}
	})

	t.Run("empty CIDRs compile to a non-nil empty set", func(t *testing.T) {
		c := &IPRangeCondition{CIDRs: []string{}}
		if err := c.Compile(); err != nil {
			t.Fatalf("Compile: unexpected error: %v", err)
		}
		networks, ok := c.Networks()
		if !ok {
			t.Error("Networks: ok = false after compiling empty CIDRs, want true (compiled, matches nothing)")
		}
		if len(networks) != 0 {
			t.Errorf("Networks: got %d networks, want 0", len(networks))
		}
	})
}

// TestTimeWindowCondition_Compile covers the load-time pre-parse of notBefore /
// notAfter: a compiled condition reports ready time.Time values (so the hot path
// skips time.Parse), an uncompiled one reports ok=false (the handler parses on
// demand), a blank bound stays the zero Time, and a malformed bound errors without
// clobbering a prior compiled result.
func TestTimeWindowCondition_Compile(t *testing.T) {
	t.Run("both bounds compile and parse as UTC", func(t *testing.T) {
		c := &TimeWindowCondition{NotBefore: "2025-01-01T00:00:00Z", NotAfter: "2025-12-31T23:59:59Z"}
		if err := c.Compile(); err != nil {
			t.Fatalf("Compile: unexpected error: %v", err)
		}
		nb, na, ok := c.Window()
		if !ok {
			t.Fatal("Window: ok = false after Compile, want true")
		}
		wantNB, _ := time.Parse(time.RFC3339Nano, "2025-01-01T00:00:00Z")
		wantNA, _ := time.Parse(time.RFC3339Nano, "2025-12-31T23:59:59Z")
		if !nb.Equal(wantNB) || !na.Equal(wantNA) {
			t.Errorf("Window = (%v, %v), want (%v, %v)", nb, na, wantNB, wantNA)
		}
	})

	t.Run("blank bound stays the zero time", func(t *testing.T) {
		c := &TimeWindowCondition{NotAfter: "2025-12-31T23:59:59Z"}
		if err := c.Compile(); err != nil {
			t.Fatalf("Compile: unexpected error: %v", err)
		}
		nb, _, ok := c.Window()
		if !ok {
			t.Fatal("Window: ok = false after Compile, want true")
		}
		if !nb.IsZero() {
			t.Errorf("Window notBefore = %v, want the zero Time for a blank bound", nb)
		}
	})

	t.Run("uncompiled reports not-ok", func(t *testing.T) {
		c := &TimeWindowCondition{NotBefore: "2025-01-01T00:00:00Z"}
		if _, _, ok := c.Window(); ok {
			t.Error("Window before Compile: ok = true, want false")
		}
	})

	t.Run("malformed bound errors and leaves prior result untouched", func(t *testing.T) {
		c := &TimeWindowCondition{NotBefore: "2025-01-01T00:00:00Z"}
		if err := c.Compile(); err != nil {
			t.Fatalf("first Compile: unexpected error: %v", err)
		}
		first, _, _ := c.Window()

		c.NotAfter = "not-a-time"
		if err := c.Compile(); err == nil {
			t.Fatal("Compile: expected error for malformed notAfter, got nil")
		}
		got, _, ok := c.Window()
		if !ok {
			t.Fatal("Window: ok = false after failed recompile, want the prior result")
		}
		if !got.Equal(first) {
			t.Errorf("Window notBefore = %v after failed recompile, want the prior %v", got, first)
		}
	})
}

// goConditionTypes lists every condition type discriminator registered in Go.
// This must be kept in sync with condition.go.
// NOTE: redactFields is intentionally absent — it is a directive
// (DirectiveTypeRedactFields), never a condition, and has no condition-type
// constant.
var goConditionTypes = []string{
	ConditionTypeTimeWindow,
	ConditionTypeIPRange,
	ConditionTypeAllowedOperations,
	ConditionTypeAllowedExtensions,
	ConditionTypeAllowedTables,
	ConditionTypeMaxCalls,
	ConditionTypeRecipientDomain,
	ConditionTypeAllowedValues,
	ConditionTypeSequenceBlock,
	ConditionTypePolicy,
	ConditionTypeCustom,
}

// goDirectiveTypes is every directive type discriminator registered in Go, read from
// the registry rather than restated. It was a hand-written list, and it rotted exactly
// as such a list does: it still named only redactFields after labelOutput and
// declassify shipped, so the round-trip assertions below covered one third of the
// vocabulary while reading as if they covered all of it.
//
// Through the accessor, not by aliasing knownDirectiveTypes: that variable is read on a
// PRODUCTION path (unmarshalDirective enumerates it in the unknown-type error), so a test
// that sorted or wrote an element of a shared backing array would corrupt the vocabulary
// the decoder reports — and race against the parallel registry tests reading it.
var goDirectiveTypes = KnownDirectiveTypes()

// TestConditionTypeConstantsValid verifies that each Go condition type constant
// is a non-empty camelCase string and matches the JSON round-trip discriminator.
func TestConditionTypeConstantsValid(t *testing.T) {
	camelCase := regexp.MustCompile(`^[a-z][a-zA-Z0-9]+$`)
	for _, ct := range goConditionTypes {
		ct := ct
		t.Run(ct, func(t *testing.T) {
			if ct == "" {
				t.Error("condition type constant is empty")
			}
			if !camelCase.MatchString(ct) {
				t.Errorf("condition type %q is not camelCase", ct)
			}

			// Verify that newCondition can create an instance for this type.
			cond := newCondition(ct)
			if cond == nil {
				t.Errorf("newCondition(%q) returned nil", ct)
				return
			}
			if cond.ConditionType() != ct {
				t.Errorf("ConditionType() = %q, want %q", cond.ConditionType(), ct)
			}

			// Verify that JSON round-trip preserves the discriminator.
			data, err := json.Marshal(cond)
			if err != nil {
				t.Fatalf("json.Marshal: %v", err)
			}
			var envelope struct {
				Type string `json:"type"`
			}
			if err := json.Unmarshal(data, &envelope); err != nil {
				t.Fatalf("json.Unmarshal: %v", err)
			}
			if envelope.Type != ct {
				t.Errorf("JSON type discriminator = %q, want %q", envelope.Type, ct)
			}
		})
	}
}

// TestAllConditionTypesHaveHandlers checks that every condition type constant
// exposed by the capability package can be JSON-marshalled with its discriminator
// and round-tripped through ConditionWrapper unmarshalling without error. It does
// not verify enforcement-engine handler registration; see enforcement_test.go for that.
func TestAllConditionTypesHaveHandlers(t *testing.T) {
	for _, ct := range goConditionTypes {
		ct := ct
		t.Run(ct, func(t *testing.T) {
			cond := newCondition(ct)
			if cond == nil {
				t.Fatalf("newCondition(%q) returned nil", ct)
			}
			// Verifying condition type is registered: just ensure it round-trips.
			data, err := json.Marshal(cond)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var envelope struct {
				Type string `json:"type"`
			}
			if err := json.Unmarshal(data, &envelope); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if envelope.Type != ct {
				t.Errorf("got type %q, want %q", envelope.Type, ct)
			}
			// Marshal via ConditionWrapper to exercise full polymorphic path.
			w := ConditionWrapper{Condition: cond}
			wData, err := json.Marshal(w)
			if err != nil {
				t.Fatalf("marshal wrapper: %v", err)
			}
			var decoded ConditionWrapper
			if err := json.Unmarshal(wData, &decoded); err != nil {
				t.Fatalf("unmarshal wrapper: %v (%s)", err, ct)
			}
			if decoded.ConditionType() != ct {
				t.Errorf("decoded type = %q, want %q", decoded.ConditionType(), ct)
			}
			_ = fmt.Sprintf("ok: %s", ct)
		})
	}
}

// TestDirectiveTypeConstantsValid verifies that each Go directive type constant
// is a non-empty camelCase string and round-trips through DirectiveWrapper
// marshaling/unmarshaling without error.
func TestDirectiveTypeConstantsValid(t *testing.T) {
	camelCase := regexp.MustCompile(`^[a-z][a-zA-Z0-9]+$`)
	for _, dt := range goDirectiveTypes {
		dt := dt
		t.Run(dt, func(t *testing.T) {
			if dt == "" {
				t.Error("directive type constant is empty")
			}
			if !camelCase.MatchString(dt) {
				t.Errorf("directive type %q is not camelCase", dt)
			}
			dir := newDirective(dt)
			if dir == nil {
				t.Fatalf("newDirective(%q) returned nil", dt)
			}
			if dir.DirectiveType() != dt {
				t.Errorf("DirectiveType() = %q, want %q", dir.DirectiveType(), dt)
			}
			// Verify JSON round-trip via DirectiveWrapper.
			w := DirectiveWrapper{Directive: dir}
			data, err := json.Marshal(w)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var decoded DirectiveWrapper
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if decoded.DirectiveType() != dt {
				t.Errorf("decoded type = %q, want %q", decoded.DirectiveType(), dt)
			}
			_ = fmt.Sprintf("ok: %s", dt)
		})
	}
}

// TestRedactFieldsInConditions_IsRejected verifies the migration hint:
// a "redactFields" entry inside "conditions" must fail with a clear error.
func TestRedactFieldsInConditions_IsRejected(t *testing.T) {
	data := []byte(`{"type":"redactFields","fields":["ssn"]}`)
	var w ConditionWrapper
	err := json.Unmarshal(data, &w)
	if err == nil {
		t.Fatal("expected error for redactFields in conditions, got nil")
	}
	if !regexp.MustCompile(`directives`).MatchString(err.Error()) {
		t.Errorf("expected migration hint mentioning 'directives', got: %v", err)
	}
}

// TestAllowlistConditions_CompiledMatchesUncompiled is the load-time-normalization
// contract for the four allowlist conditions whose lookup structures moved from the
// hot path to Compile. Every case asserts the SAME answer from a compiled condition
// and an uncompiled one, because the uncompiled fallback is what a programmatically
// built condition (a test, a library caller, the JWT shorthand PDP) actually runs —
// so a normalization that lived in only one of the two paths would silently enforce a
// different policy depending on how the condition was constructed.
func TestAllowlistConditions_CompiledMatchesUncompiled(t *testing.T) {
	t.Run("allowedExtensions", func(t *testing.T) {
		// Padded, upper-case, dot-less, blank, and duplicate entries all normalize.
		raw := []string{" .PDF ", "txt", "", "  ", ".pdf", ".TAR.GZ"}
		uncompiled := &AllowedExtensionsCondition{Argument: "path", Extensions: raw}
		compiled := &AllowedExtensionsCondition{Argument: "path", Extensions: raw}
		if err := compiled.Compile(); err != nil {
			t.Fatalf("Compile: %v", err)
		}
		want := []string{".pdf", ".txt", ".tar.gz"}
		for _, got := range [][]string{uncompiled.MatchExtensions(), compiled.MatchExtensions()} {
			if len(got) != len(want) {
				t.Fatalf("normalized extensions = %v, want %v", got, want)
			}
			for i := range want {
				if got[i] != want[i] {
					t.Errorf("normalized extensions = %v, want %v", got, want)
					break
				}
			}
		}
	})

	t.Run("allowedTables", func(t *testing.T) {
		raw := []string{" Users ", "orders"}
		cols := map[string][]string{" USERS ": {" ID ", "Email"}}
		uncompiled := &AllowedTablesCondition{Argument: "table", Tables: raw, Columns: cols}
		compiled := &AllowedTablesCondition{Argument: "table", Tables: raw, Columns: cols}
		if err := compiled.Compile(); err != nil {
			t.Fatalf("Compile: %v", err)
		}
		// The accessor REPORTS compiled-ness rather than building on the spot, so its caller can
		// compile a local copy and fail closed on an error this signature cannot carry.
		if _, _, _, ok := uncompiled.TableLookup(); ok {
			t.Error("an uncompiled condition must report itself uncompiled, not silently compile")
		}
		tables, byTable, sets, ok := compiled.TableLookup()
		if !ok {
			t.Fatal("a compiled condition must report itself compiled")
		}
		if !tables["users"] || !tables["orders"] {
			t.Errorf("table set = %v, want the trimmed lowercase names", tables)
		}
		if tables["Users"] {
			t.Error("table set must be keyed on the folded name only")
		}
		// The restriction index is keyed on the folded table name but keeps the
		// column list in original case, so denial details echo the manifest.
		if got := byTable["users"]; len(got) != 2 || got[0] != " ID " {
			t.Errorf("columnsByTable[users] = %v, want the original-case list", got)
		}
		if !sets["users"]["id"] || !sets["users"]["email"] {
			t.Errorf("column set = %v, want the trimmed lowercase names", sets["users"])
		}
	})

	t.Run("allowedTables with no column restrictions", func(t *testing.T) {
		// nil Columns must stay nil through both paths: "no restrictions declared" is a
		// distinct state from "an empty restriction", and only the former skips the ACL.
		compiled := &AllowedTablesCondition{Argument: "table", Tables: []string{"users"}}
		if err := compiled.Compile(); err != nil {
			t.Fatalf("Compile: %v", err)
		}
		if _, byTable, _, _ := compiled.TableLookup(); byTable != nil {
			t.Errorf("columnsByTable = %v, want nil when no restrictions are declared", byTable)
		}
	})

	t.Run("allowedTables refuses a column-key fold collision", func(t *testing.T) {
		// Two keys addressing one table are an ambiguous ACL, refused the way every other
		// case-variant ambiguity here is rather than resolved: picking a side enforces a
		// column allowlist the author never wrote, and the smaller key can be the wider one.
		c := &AllowedTablesCondition{Argument: "table", Tables: []string{"users"}, Columns: map[string][]string{"Users": {"id", "ssn"}, "users": {"id"}}}
		err := c.Compile()
		if err == nil {
			t.Fatal("a columns fold collision must be refused at Compile")
		}
		for _, want := range []string{"Users", "users", "same table"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error should name %q, got: %v", want, err)
			}
		}
		// Stable across runs: the pair is ranged out of a map, so an unsorted message would
		// name the two keys in a different order per process.
		for i := 0; i < 32; i++ {
			again := &AllowedTablesCondition{Argument: "table", Tables: []string{"users"}, Columns: c.Columns}
			if got := again.Compile().Error(); got != err.Error() {
				t.Fatalf("collision message is unstable:\n%s\n%s", err, got)
			}
		}
		// A condition built through the API and never compiled hands its caller no ACL at all,
		// rather than one resolved out of the ambiguity Compile refuses. The handler's own
		// fail-closed exit for that is pinned in pkg/enforcement.
		uncompiled := &AllowedTablesCondition{Argument: "table", Tables: []string{"users"}, Columns: c.Columns}
		if _, byTable, _, ok := uncompiled.TableLookup(); ok || byTable != nil {
			t.Fatalf("an uncompiled condition must report itself uncompiled, got ok=%v byTable=%v", ok, byTable)
		}
	})

	t.Run("recipientDomain", func(t *testing.T) {
		raw := []string{" Example.COM ", "partner.org"}
		uncompiled := &RecipientDomainCondition{Argument: "to", Domains: raw}
		compiled := &RecipientDomainCondition{Argument: "to", Domains: raw}
		if err := compiled.Compile(); err != nil {
			t.Fatalf("Compile: %v", err)
		}
		for _, c := range []*RecipientDomainCondition{uncompiled, compiled} {
			set := c.MatchDomains()
			if !set["example.com"] || !set["partner.org"] {
				t.Errorf("domain set = %v, want the trimmed lowercase domains", set)
			}
			if set["evil.com"] {
				t.Error("domain set must not admit an unlisted domain")
			}
		}
	})

	t.Run("allowedOperations", func(t *testing.T) {
		raw := []string{" SELECT ", "insert"}
		uncompiled := &AllowedOperationsCondition{Argument: "query", Operations: raw}
		compiled := &AllowedOperationsCondition{Argument: "query", Operations: raw}
		if err := compiled.Compile(); err != nil {
			t.Fatalf("Compile: %v", err)
		}
		cases := []struct {
			op   string
			want bool
		}{
			{"SELECT", true},  // padded entry still matches
			{"INSERT", true},  // case-insensitive
			{"DELETE", false}, // unlisted
			{"*", false},      // "*" is not a wildcard
		}
		for _, c := range []*AllowedOperationsCondition{uncompiled, compiled} {
			for _, tc := range cases {
				if got := c.AllowsOperation(tc.op); got != tc.want {
					t.Errorf("AllowsOperation(%q) = %v, want %v", tc.op, got, tc.want)
				}
				// The bare-slice matcher the JWT shorthand PDP uses must agree.
				if got := MatchOperation(c.Operations, tc.op); got != tc.want {
					t.Errorf("MatchOperation(%q) = %v, want %v", tc.op, got, tc.want)
				}
			}
		}
	})
}
