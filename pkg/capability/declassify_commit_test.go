// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability_test

import (
	"sync"
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The commit handle is the carrier for an obligation that used to be prose on a []string.
// These pin the three properties the second phase of a clear rests on: the authorized set
// cannot be widened, one authorization applies to one clear, and the common nil is safe to
// ask anything of.

func TestDeclassification_LabelsCannotBeWidenedByTheCaller(t *testing.T) {
	t.Parallel()
	authorized := []string{capability.FlowLabelPII}
	d := capability.NewDeclassification(authorized, "ada@example.com", "apr-1", false)

	// Mutating the slice the decision was built from must not reach the handle: the
	// authorization was fixed inside the decision's critical section.
	authorized[0] = capability.FlowLabelConfidential
	assert.Equal(t, []string{capability.FlowLabelPII}, d.Labels())

	// Nor may a caller widen the handle through the set it hands back.
	got := d.Labels()
	got = append(got, capability.FlowLabelConfidential)
	assert.Equal(t, []string{capability.FlowLabelPII}, d.Labels(), "Labels must hand back a copy, not the authorized set itself")
	assert.Len(t, got, 2, "the caller's own copy is theirs to mutate")

	claimed, err := d.Claim()
	require.NoError(t, err)
	claimed = append(claimed, capability.FlowLabelConfidential)
	assert.Equal(t, []string{capability.FlowLabelPII}, d.Labels(), "and so must Claim")
	assert.Len(t, claimed, 2)
}

func TestDeclassification_ClaimIsSingleUse(t *testing.T) {
	t.Parallel()
	d := capability.NewDeclassification([]string{capability.FlowLabelPII}, "ada@example.com", "apr-1", true)
	require.False(t, d.Committed())

	labels, err := d.Claim()
	require.NoError(t, err)
	assert.Equal(t, []string{capability.FlowLabelPII}, labels)
	assert.True(t, d.Committed())

	labels, err = d.Claim()
	require.ErrorIs(t, err, capability.ErrDeclassificationCommitted,
		"one authorization applies to exactly one clear")
	assert.Empty(t, labels, "and a refused claim must hand back nothing to clear")
}

// Exactly one of N racing commits may win. The handle rides a decision the transport can read
// from more than one goroutine, and two winners would be one authorization applied twice.
func TestDeclassification_ConcurrentClaimAdmitsOne(t *testing.T) {
	t.Parallel()
	d := capability.NewDeclassification([]string{capability.FlowLabelPII}, "ada@example.com", "apr-1", true)

	const racers = 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	won := 0
	wg.Add(racers)
	for range racers {
		go func() {
			defer wg.Done()
			if _, err := d.Claim(); err == nil {
				mu.Lock()
				won++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, 1, won, "exactly one commit may apply an authorization")
}

// SpentApprovalID is the approval id plus one bit, not a fourth parallel string two sites had
// to keep in agreement.
func TestDeclassification_SpentApprovalIDFollowsTheSingleUseBit(t *testing.T) {
	t.Parallel()
	once := capability.NewDeclassification([]string{capability.FlowLabelPII}, "ada@example.com", "apr-1", true)
	assert.Equal(t, "apr-1", once.SpentApprovalID())
	assert.Equal(t, "apr-1", once.ApprovalID())

	standing := capability.NewDeclassification([]string{capability.FlowLabelPII}, "ada@example.com", "apr-1", false)
	assert.Empty(t, standing.SpentApprovalID(), "a standing grant spends nothing, so there is nothing to reconcile")
	assert.Equal(t, "apr-1", standing.ApprovalID())

	// A burned grant whose clear resolved to nothing: no pending clear, still a spent id. This
	// is the shape that makes an empty-label handle legitimate rather than a nil.
	noop := capability.NewDeclassification(nil, "ada@example.com", "apr-1", true)
	assert.False(t, noop.PendingClear())
	assert.Equal(t, "apr-1", noop.SpentApprovalID())
}

// The nil handle is the overwhelmingly common case — every call in a deployment with no
// declassify directive — so every accessor has to answer for it without a branch at the call
// site.
func TestDeclassification_NilIsSafeToAsk(t *testing.T) {
	t.Parallel()
	var d *capability.Declassification
	assert.Nil(t, d.Labels())
	assert.False(t, d.PendingClear())
	assert.Empty(t, d.Approver())
	assert.Empty(t, d.ApprovalID())
	assert.Empty(t, d.SpentApprovalID())
	assert.False(t, d.Committed())

	labels, err := d.Claim()
	assert.NoError(t, err, "a nil handle authorizes nothing, which is not a fault")
	assert.Empty(t, labels)
}

// TestNewSpentGrantOnly_NamesTheBurnWithoutClaimingAnAuthorization is the record-shape
// invariant the two accessors carry between them. A decision whose own commit faulted after
// burning a single-use grant authorized NOTHING — the clear was never resolved — and its
// handle exists solely so the spent grant reaches the tape.
//
// ApprovalID feeds the top-level, HMAC-signed approval_id field, which is reserved for a
// declassification that actually TOOK EFFECT; SpentApprovalID feeds a details key with the
// opposite meaning. A handle built as a single-use grant with no labels used to return the
// same string from both, putting one id on the tape through two fields with two documented
// provenances — the collision the separate detail key exists to prevent.
func TestNewSpentGrantOnly_NamesTheBurnWithoutClaimingAnAuthorization(t *testing.T) {
	d := capability.NewSpentGrantOnly("apr-9")
	assert.Equal(t, "apr-9", d.SpentApprovalID(), "the burned grant is the one fact this handle carries")
	assert.Empty(t, d.ApprovalID(),
		"nothing was authorized, so the field reserved for a clear that took effect must stay empty")
	assert.Empty(t, d.Approver())
	assert.Empty(t, d.Labels())
	assert.False(t, d.PendingClear(), "the commit must skip it: this cannot become a clear on a refused call")
}

// TestNewDeclassification_SpentIDTracksTheBurnFlag is the positive half. On a handle that DID
// authorize a clear, the authorizing approval and the burned grant are genuinely the same
// approval, so both accessors name it — and a standing grant burns nothing, so only the
// authorizing one is populated.
func TestNewDeclassification_SpentIDTracksTheBurnFlag(t *testing.T) {
	once := capability.NewDeclassification([]string{capability.FlowLabelPII}, "alice@example.com", "apr-9", true)
	assert.Equal(t, "apr-9", once.ApprovalID())
	assert.Equal(t, "apr-9", once.SpentApprovalID())

	standing := capability.NewDeclassification([]string{capability.FlowLabelPII}, "alice@example.com", "apr-9", false)
	assert.Equal(t, "apr-9", standing.ApprovalID())
	assert.Empty(t, standing.SpentApprovalID(), "a standing grant spends nothing and needs no reconciliation")
}
