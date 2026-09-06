// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package callcounter_test

import (
	"context"
	"testing"

	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/capability"
)

// A clock option holding no value must leave the default in place: every read here is a bare
// m.now(), so there is no fail-closed absent case to route a nil to and the first admission
// panicked the enforcement goroutine instead of denying — the fail-OPEN reading of a decision
// point. flowlabelstore's identical option has always normalized; these two disagreed.
func TestNewInMemory_ValuelessClockLeavesTheDefault(t *testing.T) {
	m := callcounter.NewInMemory(callcounter.WithTimeFunc(nil))
	ctx := context.Background()

	if _, err := m.IncrementAndGet(ctx, "k", 60, 10); err != nil {
		t.Fatalf("IncrementAndGet: %v", err)
	}
	if _, err := m.Peek(ctx, "k", 60); err != nil {
		t.Fatalf("Peek: %v", err)
	}
	admitted, _, _, _, err := m.AdmitAll(ctx, []capability.QuotaBucket{{
		Key: "k2", WindowSec: 60, Limit: 5, Counted: true,
	}})
	if err != nil || !admitted {
		t.Fatalf("AdmitAll: admitted=%v err=%v", admitted, err)
	}
}
