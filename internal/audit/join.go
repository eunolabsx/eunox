// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Cross-enforcement-point join: the vocabulary for reading SEVERAL tapes together.
//
// Each enforcement point signs its own chain over its own file — two of them cannot
// append to one file, and concatenating their lines does not produce one chain, since
// every seq and prev_hmac is per writer. So a sequence spanning two enforcement points
// is not one verification pass over N files: it is N independent passes, each with its
// own verdict, plus a JOIN over the records they collected (§3.14).
//
// This file holds only the join half — what a joined record carries, and what an
// ordering over records from different writers' clocks may and may not claim. The
// verification half is verify.go's and is unchanged by it: a record reaches a join
// carrying the verdict its own tape's pass gave it, never a second opinion.

package audit

import (
	"sort"
	"time"
)

// RecordStatus is one record's verification outcome as the join reports it. A joined
// sequence carries records that FAILED verification too — dropping them would hide the
// evidence the sequence is read for — so every entry states which of these it is.
type RecordStatus string

const (
	// StatusVerified means the record's HMAC recomputed correctly under a held key.
	// It says nothing about the record's CHAIN links: a break is a property of two
	// adjacent records on one tape, reported by that tape's own verdict.
	StatusVerified RecordStatus = "verified"
	// StatusInvalid means the record could not be certified as written: an HMAC mismatch
	// under a held key, a strict-decode refusal, a non-canonical on-disk form, a line
	// that did not decode at all, a forged seq-0 decoy, or an unparseable signed `time`.
	//
	// It is deliberately NOT a synonym for "tampered", and the causes differ in what was
	// actually established. Only the mismatch ran a key comparison and lost it. The
	// decode and canonical-form refusals reject the line before any comparison, so they
	// cover version skew (a newer writer's field an older verifier refuses) as well as
	// rewriting. The malformed-`time` case is the opposite end: it is reached only after
	// the HMAC VERIFIED, so that record is authentic and fails on the field alone —
	// which is why it is the one cause that leaves the chain anchor trusted.
	StatusInvalid RecordStatus = "invalid"
	// StatusUnknownKey means the record names a key_id absent from the ring — the
	// routine post-rotation state, not tampering, but unverified either way.
	StatusUnknownKey RecordStatus = "unknown-key"
	// StatusUnverifiable means no key was available to check the record at all.
	StatusUnverifiable RecordStatus = "unverifiable"
	// StatusUnsigned means the record carries no _hmac: pre-signing history, or a
	// signature stripped by a write-capable attacker without the key.
	StatusUnsigned RecordStatus = "unsigned"
)

// JoinedRecord is one record as the cross-tape join presents it: the fields that place
// a call in a sequence (who enforced it, when, on what) plus the verdict its own tape's
// pass reached. It is deliberately NOT the whole record — a join is read to reconstruct
// an order of events across writers, and the per-record detail stays on the tapes.
//
// Tape is stamped by the CALLER after collection: the verify pass reads bytes and knows
// nothing about which of the operator's tapes it was handed.
type JoinedRecord struct {
	Tape int // 1-based index of the tape this came from, in the order the operator named them

	// PEP is the enforcement point the WRITER stamped (§6.1). Empty for a tape written
	// by an instance with no configured name — attribution then falls back to the tape
	// the record came out of, which is exactly the fallback this field exists to remove
	// once records are merged, so a join reports such a tape rather than printing a
	// blank.
	PEP string

	Seq  uint64
	Time string    // the record's signed `time`, verbatim
	At   time.Time // Time parsed as RFC3339Nano; meaningful only when TimeOK
	// TimeOK reports whether Time parsed. A record whose time does not parse has NO
	// position in a joined sequence — it is reported separately rather than sorted to
	// an arbitrary place.
	TimeOK bool

	// TaskID is the join key the record matched.
	TaskID     string
	Method     string
	TargetType string
	Target     string
	Decision   string
	DenialCode string

	Status RecordStatus
}

// JoinOrdering is the result of ordering records collected from several tapes, together
// with everything that ordering rests on but cannot itself establish.
//
// The distinction the type exists to keep: Ordered is a PRESENTATION, not a verdict.
// Within one tape, order is proven — seq is inside the signature and its contiguity is
// checked — and the ordering FOLLOWS it. Across tapes nothing is proven: the records
// carry each writer's own clock, and eunox neither requires nor checks clock sync
// between enforcement points. So a consumer must not read Ordered as "this is what
// happened in this order"; it is "this is each tape's proven order, interleaved by what
// each writer said the time was".
type JoinOrdering struct {
	// Ordered holds every record whose time parsed, oldest first by that time — except
	// that a record is never placed before a same-tape record its seq proves came
	// first (see clampedPlacement). Ties break on (tape, seq) so the output is
	// deterministic, never so it is right: two records stamped the same instant by
	// different writers have no established order.
	Ordered []JoinedRecord
	// Unordered holds the records whose signed `time` does not parse, in collection
	// order. They belong to the sequence but have no position in it.
	Unordered []JoinedRecord
	// NonMonotonicTapes names (1-based) the tapes whose recorded `time` does not
	// increase with `seq`, so the sequence had to place at least one of their records
	// later than its own timestamp to keep the order that tape PROVES.
	//
	// It is deliberately not called clock skew, because it does not establish one: the
	// sink stamps `time` on the CALLING goroutine and assigns `seq` in its drainer, so
	// two concurrent recorders on a busy tape are routinely stamped in one order and
	// sequenced in the other, on a tape whose clock never moved. A writer whose clock
	// really did move backwards is indistinguishable from here. What the name does say
	// is the thing a reader needs: for these tapes the TIME column is not the order.
	NonMonotonicTapes []int
	// UnattributedTapes names (1-based) the tapes that contributed records carrying no
	// `pep`. Their records are attributed by file path instead, which does not survive
	// the merge into a SIEM that the field exists for.
	UnattributedTapes []int
}

// OrderJoinedRecords arranges records collected from several tapes into the sequence a
// cross-tape report prints, and reports what that arrangement rests on. It reads only
// the records handed to it: it opens nothing, verifies nothing, and re-decides nothing
// that the per-tape passes already decided.
//
// The input is not mutated; the caller's slice keeps its collection order, which is what
// the per-tape sections print.
func OrderJoinedRecords(recs []JoinedRecord) JoinOrdering {
	var out JoinOrdering
	out.UnattributedTapes = unattributedTapes(recs)

	placed, nonMonotonic := clampedPlacement(recs)
	for i := range recs {
		if !recs[i].TimeOK {
			out.Unordered = append(out.Unordered, recs[i])
		}
	}
	out.NonMonotonicTapes = nonMonotonic
	// Stable, and with an explicit total order on the tie: two writers stamping the same
	// instant is common at low resolution, and a report whose line order changes between
	// two runs over the same bytes is one an auditor cannot diff. Sorted on the CLAMPED
	// instant — which is what makes the tie-break on seq restore a tape's own order
	// rather than merely make an arbitrary one repeatable — so the sort runs over the
	// placements and the records are extracted after, never the other way round: sorting
	// the records while indexing a parallel slice reads a different record's instant the
	// moment the first swap lands.
	sort.SliceStable(placed, func(i, j int) bool {
		a, b := &placed[i], &placed[j]
		if !a.at.Equal(b.at) {
			return a.at.Before(b.at)
		}
		if a.rec.Tape != b.rec.Tape {
			return a.rec.Tape < b.rec.Tape
		}
		return a.rec.Seq < b.rec.Seq
	})
	out.Ordered = make([]JoinedRecord, 0, len(placed))
	for i := range placed {
		out.Ordered = append(out.Ordered, placed[i].rec)
	}
	return out
}

// placement pairs a record with the instant the sequence places it at: its own `time`,
// raised to that of any earlier-seq record on the same tape.
type placement struct {
	rec JoinedRecord
	at  time.Time
}

// clampedPlacement computes each orderable record's placement instant and reports which
// tapes needed raising.
//
// The clamp is what keeps a tape's PROVEN order intact inside a presentation that
// otherwise rests on unproven clocks. Within a tape `seq` is authoritative — it is
// signed and its contiguity is checked — while `time` is not monotonic in it even on a
// healthy tape: the sink stamps `time` on the calling goroutine and assigns `seq` in its
// drainer, so two concurrent recorders are routinely stamped in one order and sequenced
// in the other. Sorting on the raw timestamp would then print a tape's own records out
// of the order that tape proves, which is the one ordering claim this report CAN make.
//
// Raising rather than substituting seq outright, because the instant is still what
// interleaves the tapes; the clamp only forbids a record from being placed before a
// same-tape record that provably preceded it.
//
// It walks COLLECTION order, which is file order within each tape — the order the seq
// contiguity check ran in — and only advances on a record whose seq actually increases.
// A repeated or lower seq within one tape is that tape's own chain finding, already
// reported by its verdict, and letting it move the high-water mark would report one
// fault twice under a second name.
func clampedPlacement(recs []JoinedRecord) (placed []placement, nonMonotonic []int) {
	type mark struct {
		at  time.Time
		seq uint64
	}
	high := map[int]mark{}
	raised := map[int]bool{}
	placed = make([]placement, 0, len(recs))
	for i := range recs {
		r := &recs[i]
		if !r.TimeOK {
			continue
		}
		at := r.At
		prev, ok := high[r.Tape]
		if ok && r.Seq > prev.seq && at.Before(prev.at) {
			at = prev.at
			if !raised[r.Tape] {
				raised[r.Tape] = true
				nonMonotonic = append(nonMonotonic, r.Tape)
			}
		}
		if !ok || r.Seq > prev.seq {
			high[r.Tape] = mark{at: at, seq: r.Seq}
		}
		placed = append(placed, placement{rec: *r, at: at})
	}
	sort.Ints(nonMonotonic)
	return placed, nonMonotonic
}

// unattributedTapes reports which tapes contributed a record carrying no `pep`.
func unattributedTapes(recs []JoinedRecord) []int {
	seen := map[int]bool{}
	var out []int
	for i := range recs {
		if recs[i].PEP != "" || seen[recs[i].Tape] {
			continue
		}
		seen[recs[i].Tape] = true
		out = append(out, recs[i].Tape)
	}
	sort.Ints(out)
	return out
}
