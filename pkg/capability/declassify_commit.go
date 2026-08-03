// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The handle that carries an authorized declassification from the decision to the commit.
//
// A declassification is applied in two phases: the decision resolves and AUTHORIZES the clear
// (selecting a covering approval and burning it when it is single-use), and the caller applies
// it once the sanitizing call has actually run. Splitting them is what keeps the labels
// visible to every concurrent decision for the whole upstream round trip — see
// EnforceResponse.Declassification — but it leaves an obligation, and an obligation needs a
// carrier.
//
// The carrier is this type, and it is what the second phase takes INSTEAD of a label slice:
//
//   - The authorized set is unexported and copied out, so the phase that applies the clear
//     cannot widen it. Every gate the declassify surface installs — the approval scope, the
//     escalation, the single-use ledger — sits on the FIRST phase, so a second phase that
//     accepted an arbitrary []string was an unauthorized clear primitive: an embedder holding
//     an engine could remove any label it named, with no approval presented and nothing on the
//     tape to say so.
//   - It is minted only by a decision that authorized a declassification, and is nil on every
//     other call — which is every call in a deployment that does not declassify. The two facts
//     a record may have to carry (what a clear did not remove, and which single-use grant the
//     decision burned) hang off this ONE handle, so they cannot disagree about which decision
//     they came from; as four parallel response fields their populated-together rule was
//     prose, and had already been broken once.
//   - Claim is single-use, so an authorization cannot be replayed into two clears.
//
// SCOPE, honestly: an embedder can still construct one through NewDeclassification, which
// exists because the engine that mints handles lives in another package. This narrows the
// surface from "any label slice reaches the store" to "a caller has to build something that
// says what it is" — the same scope note the transport's killSubject carries. What it does
// close completely is the accidental version: the in-tree paths, and any embedder following
// the response, cannot clear a set the decision did not authorize.

package capability

import (
	"errors"
	"slices"
	"sync/atomic"
)

// ErrDeclassificationCommitted is returned by Claim for a handle whose authorized clear has
// already been applied. A handle authorizes ONE clear: a second commit would be an
// authorization replayed, and for a single-use grant it would be the grant's whole point
// undone (the burn happened once, in the decision that minted this).
var ErrDeclassificationCommitted = errors.New("this declassification has already been committed; an authorization applies to exactly one clear")

// Declassification is the authorized-but-not-yet-applied second phase of a flow-label clear:
// the labels an approved declassify directive may remove, plus the approval that authorized
// them. It is minted by the decision (see EnforceResponse.Declassification) and consumed by
// the commit; a caller that never commits leaves the session exactly as tainted as it found
// it, which over-blocks a later sink rather than leaking.
//
// Values are shared by pointer on purpose: an EnforceResponse is copied freely along the
// forward path, and the single-use claim has to mean once per DECISION, not once per copy.
//
// Every accessor is nil-safe, so a caller holding the common "no declassification here" nil
// needs no branch.
type Declassification struct {
	// labels is the authorized set: what the approval covered, intersected inside the
	// decision's critical section with what the anchor was carrying. Unexported so the
	// commit phase cannot widen it, and copied on the way out so a caller cannot either.
	labels []string
	// approver and approvalID identify the human approval that AUTHORIZED the clear. They
	// reach the audit record's top-level, signed triple beside the labels the commit
	// actually changed, so they are populated only on a handle that authorizes something.
	approver   string
	approvalID string
	// spentApprovalID names an approval the decision BURNED in the ledger, and is empty for
	// a standing grant (which spends nothing).
	//
	// It is a second string rather than a bit over approvalID because the two are not the
	// same fact, and one handle shape proves it: a decision whose own commit faulted after
	// burning a grant authorizes NOTHING and still has a spent id to report (see
	// NewSpentGrantOnly). Derived from approvalID, that handle reported the same string from
	// ApprovalID() — the top-level signed field reserved for a declassification that actually
	// took effect — putting one id on the tape with two provenances, which is exactly what
	// the separate detail key exists to prevent. The two fields are written in ONE place each
	// (the two constructors below), so there is no pair for a caller to keep in agreement.
	spentApprovalID string
	// committed makes the handle single-use. atomic because a decision's response can be
	// read by more than one goroutine on the transport's response path.
	committed atomic.Bool
}

// NewDeclassification mints the handle for an authorized clear. It is exported for the
// enforcement engine, which lives in another package and is the only thing in this repository
// that may mint one — a handle asserts that an approval was resolved, scoped, and (for a
// single-use grant) burned, and none of that is checked here.
//
// labels is copied, so a later mutation of the caller's slice cannot widen an authorization
// that has already been handed out. singleUse reports whether the approval was burned in the
// ledger, which is what SpentApprovalID keys off.
//
// A handle with NO labels is legitimate and is the reason this does not return nil for one: a
// single-use grant is spent by the decision that accepted it even when the intersection turns
// out empty (the anchor was not carrying the approved labels), and the spent grant still has
// to reach the tape. The commit skips a handle with nothing to clear.
func NewDeclassification(labels []string, approver, approvalID string, singleUse bool) *Declassification {
	d := &Declassification{
		labels:     slices.Clone(labels),
		approver:   approver,
		approvalID: approvalID,
	}
	if singleUse {
		// The approval that authorized this clear is also the one that was burned. That
		// coincidence is real HERE — the clear was authorized, so both facts name the same
		// grant — and it is precisely what must NOT be assumed on a handle that authorizes
		// nothing; see NewSpentGrantOnly.
		d.spentApprovalID = approvalID
	}
	return d
}

// NewSpentGrantOnly mints a handle that authorizes NO clear and exists solely to name a
// single-use grant a decision already burned.
//
// It is the shape a fault inside the decision produces: the ledger burn is atomic with the
// decision and has no un-burn, so a commit that faults after burning has spent the operator's
// one-shot approval on a call that is about to be refused. That grant appears on no other
// record, and an operator reconciling outstanding approvals would otherwise believe it live.
//
// The distinction from NewDeclassification(nil, "", id, true) is the whole point of a separate
// constructor: that call produces a handle whose ApprovalID() and SpentApprovalID() are the
// same string, and ApprovalID feeds the top-level, HMAC-signed approval_id field, which is
// reserved for a declassification that actually TOOK EFFECT. One id reaching the tape through
// two fields with two documented meanings is the collision the separate detail key exists to
// avoid; a handle that authorizes nothing must not be able to populate the authorizing field
// at all.
//
// It carries no labels, so PendingClear is false and the commit skips it — this cannot become
// a clear on a refused call.
func NewSpentGrantOnly(spentApprovalID string) *Declassification {
	return &Declassification{spentApprovalID: spentApprovalID}
}

// Labels reports the authorized set — what the approval covered, as resolved at decision
// time. A fresh copy per call: this is the set the commit is bounded by, and a caller that
// could append to the handle's own slice would be widening the authorization it was handed.
//
// It is safe to read after Claim; it reports what was authorized, not what remains.
func (d *Declassification) Labels() []string {
	if d == nil {
		return nil
	}
	// slices.Clone(nil) is nil, which preserves the nil-vs-empty distinction the no-op handle
	// depends on (see NewDeclassification).
	return slices.Clone(d.labels)
}

// PendingClear reports whether this handle authorizes a clear that would actually remove
// something. False for the no-op case a burned single-use grant still produces, where the
// handle exists only so the spent approval reaches the tape.
func (d *Declassification) PendingClear() bool { return d != nil && len(d.labels) > 0 }

// Approver names the human whose approval authorized the clear.
func (d *Declassification) Approver() string {
	if d == nil {
		return ""
	}
	return d.approver
}

// ApprovalID identifies the approval that AUTHORIZED the clear — the control plane's own
// record identifier, stamped on the allow that performed it.
//
// Empty on a handle that authorizes nothing, which is what keeps it from aliasing
// SpentApprovalID: the field it feeds is the top-level signed approval_id, reserved for a
// declassification that took effect, and a burned grant reaching the tape through it would put
// one id in two places with two provenances. See NewSpentGrantOnly.
func (d *Declassification) ApprovalID() string {
	if d == nil {
		return ""
	}
	return d.approvalID
}

// SpentApprovalID names a SINGLE-USE approval this call burned in the ledger, and is empty
// for a standing grant (which spends nothing and needs no reconciliation).
//
// It is populated whether or not the clear it authorized went on to change anything, and
// whether or not the commit ever runs — the burn is what makes "once" mean once, so it happens
// in the decision, and an operator reconciling outstanding one-shot approvals needs this on the
// tape either way. It is therefore also the ONLY fact a handle minted after an in-decision
// fault carries.
func (d *Declassification) SpentApprovalID() string {
	if d == nil {
		return ""
	}
	return d.spentApprovalID
}

// Claim consumes the handle and returns the labels the caller may now clear. The second call
// returns ErrDeclassificationCommitted and no labels: one authorization applies to exactly one
// clear.
//
// The single-use test is the same shape as the ledger's own — an atomic compare-and-swap, so
// two goroutines racing a commit cannot both win. It bounds REPLAY of an authorization, and
// deliberately not much more: the grant itself is made single-use by the ledger burn in the
// decision, because two concurrent decisions get two handles and no per-handle flag could
// span them.
func (d *Declassification) Claim() ([]string, error) {
	if d == nil {
		return nil, nil
	}
	if !d.committed.CompareAndSwap(false, true) {
		return nil, ErrDeclassificationCommitted
	}
	return d.Labels(), nil
}

// Committed reports whether this handle's authorization has been consumed.
//
// It is the NON-DESTRUCTIVE half of the single-use claim, and that is its whole reason for
// existing: the only other way to ask is to call Claim, which answers by consuming. A caller
// deciding whether a commit still has to run — and the tests that pin "a path which cleared
// nothing must leave the authorization spendable" — need to ask without spending.
//
// It is deliberately NOT what the audit record branches on. The tape reports what a commit
// CHANGED (the cleared set), never what was claimed, so a claim whose clear moved no label
// must not read as a declassification.
func (d *Declassification) Committed() bool { return d != nil && d.committed.Load() }
