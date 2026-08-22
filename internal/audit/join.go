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
	// StatusInvalid means the record was provably not what its signature covers (an
	// HMAC mismatch under a held key, a forged seq-0 decoy, or an unparseable signed
	// `time`).
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
// checked. Across tapes nothing is proven: the records carry each writer's own clock,
// and eunox neither requires nor checks clock sync between enforcement points. So a
// consumer must not read Ordered as "this is what happened in this order"; it is "this
// is what each writer said the time was". ClockSkewedTapes names the tapes that
// disagree with themselves, which is the one part of that assumption a local reader CAN
// falsify.
type JoinOrdering struct {
	// Ordered holds every record whose time parsed, oldest first by that time. Ties
	// break on (tape, seq) so the output is deterministic — never so it is right: two
	// records stamped the same instant by different writers have no established order.
	Ordered []JoinedRecord
	// Unordered holds the records whose signed `time` does not parse, in collection
	// order. They belong to the sequence but have no position in it.
	Unordered []JoinedRecord
	// ClockSkewedTapes names (1-based) the tapes whose OWN records disagree with
	// themselves: a later seq carrying an earlier time. seq order is signed and
	// contiguity-checked, so within a tape it is authoritative — a disagreement means
	// that writer's clock moved backwards, and the cross-tape ordering, which rests on
	// nothing BUT these clocks, cannot be trusted for those records.
	ClockSkewedTapes []int
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
	// Skew is computed over COLLECTION order, before the sort: that order is file
	// order within each tape, which is the order the seq contiguity check ran in.
	// Sorting first would destroy exactly the sequence being tested.
	out.ClockSkewedTapes = skewedTapes(recs)
	out.UnattributedTapes = unattributedTapes(recs)
	for i := range recs {
		if recs[i].TimeOK {
			out.Ordered = append(out.Ordered, recs[i])
			continue
		}
		out.Unordered = append(out.Unordered, recs[i])
	}
	// Stable, and with an explicit total order on the tie: two writers stamping the same
	// instant is common at low resolution, and a report whose line order changes between
	// two runs over the same bytes is one an auditor cannot diff.
	sort.SliceStable(out.Ordered, func(i, j int) bool {
		a, b := out.Ordered[i], out.Ordered[j]
		if !a.At.Equal(b.At) {
			return a.At.Before(b.At)
		}
		if a.Tape != b.Tape {
			return a.Tape < b.Tape
		}
		return a.Seq < b.Seq
	})
	return out
}

// skewedTapes reports which tapes carry a record whose time precedes that of an earlier
// record on the SAME tape. Only records with a parseable time and an advancing seq are
// compared: a repeated or lower seq within one tape is that tape's own chain finding,
// already reported by its verdict, and reading it as clock skew would report one fault
// twice under the wrong name.
func skewedTapes(recs []JoinedRecord) []int {
	type mark struct {
		at  time.Time
		seq uint64
	}
	last := map[int]mark{}
	seen := map[int]bool{}
	var out []int
	for i := range recs {
		r := &recs[i]
		if !r.TimeOK {
			continue
		}
		prev, ok := last[r.Tape]
		if ok && r.Seq > prev.seq && r.At.Before(prev.at) && !seen[r.Tape] {
			seen[r.Tape] = true
			out = append(out, r.Tape)
		}
		if !ok || r.Seq > prev.seq {
			last[r.Tape] = mark{at: r.At, seq: r.Seq}
		}
	}
	sort.Ints(out)
	return out
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
