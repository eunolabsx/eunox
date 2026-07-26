// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Audit-log verification: per-record HMAC recomputation and tamper-evident chain checks.

package audit

import (
	"bytes"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode"
)

// errKeyIDNotInRing is returned by keysToTry (and propagated by VerifyRecord) when
// a record names a key_id absent from the verification ring — a missing key (the
// expected state after a rotation retired the signing key), NOT an HMAC mismatch.
// Signalling it distinctly lets VerifyLog report UNKNOWN_KEY_ID rather than INVALID.
var errKeyIDNotInRing = errors.New("audit record key_id is not in the verification ring")

// errUnidentifiedNoMatch is returned by VerifyRecord when a record names NO key_id
// (a pre-key_id-era signed record) and no key in the ring matched its HMAC. Unlike
// a named-key-in-ring mismatch (genuine tampering → INVALID), an unidentified
// record offers no way to tell a retired/absent signing key from tampering, so the
// caller reports UNVERIFIABLE rather than asserting tampering — still failing the
// verdict (fail-closed), distinct from both INVALID and UNKNOWN_KEY_ID.
var errUnidentifiedNoMatch = errors.New("audit record names no key_id and no ring key matched its HMAC")

// errNonCanonicalRecord is returned by VerifyRecord's canonical-on-disk-form check;
// see that check's comment in VerifyRecord for what it catches and why.
var errNonCanonicalRecord = errors.New("signed audit record is not in canonical on-disk form: its bytes are not what the writer emits for these fields (a duplicate, re-spelled, or reordered key, an added zero-valued field, an alternate escape, or inserted whitespace) — the HMAC covers the record's fields, not its bytes, so a rewrite that decodes to the same fields is rejected here")

// VerifyRecord re-computes the HMAC of a raw record line and reports whether it
// matches. The record's key_id selects the key, so a log straddling a rotation
// still verifies: a known key_id is checked against that key, and a record with no
// key_id (pre-rotation or single-key) against every key in the ring.
func (s *Sink) VerifyRecord(line []byte) (bool, error) {
	var rec auditRecord
	// Decode strictly (DisallowUnknownFields) in a SINGLE pass: this both populates the
	// record and rejects any unknown top-level field. A signed record must contain no
	// field the auditRecord struct does not model — the HMAC is recomputed below over
	// the re-marshaled struct, and a lenient decode silently DROPS unknown fields, so an
	// injected field (e.g. "operator_override":"approved") would not be covered by the
	// recomputed HMAC yet the modified on-disk line would still verify. The disallowed
	// set is derived from the struct tags automatically, so it cannot drift from
	// auditRecord the way a hand-maintained field list would.
	//
	// UseNumber decodes any JSON number landing on an interface{} as json.Number (exact
	// text) rather than float64, which cannot round-trip integers above 2^53. Details is
	// a json.RawMessage (preserved verbatim, so unaffected) and no other auditRecord
	// field is interface{}-typed, so this is currently a no-op — retained as a guard so a
	// future interface{}/map field cannot silently break the decode→re-marshal round-trip.
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rec); err != nil {
		// The strict decode failed. Re-decode leniently to disambiguate: if the lenient
		// decode ALSO fails, the record is genuinely malformed (fatal for signed and
		// legacy alike, matching the old lenient-first behavior). If it succeeds, the
		// strict failure was purely an unknown field — fatal only for a SIGNED record,
		// since a legacy (unsigned, pre-HMAC) record predates the current struct and may
		// legitimately carry a field it no longer models. Whether the record is signed is
		// only knowable once decoded, so this lenient fallback is what disambiguates —
		// without any string-matching on the json error text.
		lenient := json.NewDecoder(bytes.NewReader(line))
		lenient.UseNumber()
		if lerr := lenient.Decode(&rec); lerr != nil {
			return false, lerr
		}
		if isSignedRecord(rec) {
			return false, fmt.Errorf("signed audit record contains an unknown or malformed field: %w", err)
		}
		// Legacy record: accept the leniently-decoded rec and continue the trailing-data
		// check on the lenient decoder (positioned after the value).
		dec = lenient
	}
	// Reject trailing bytes: Decode stops at the first value and ignores the rest, so
	// a tampered {…record…}GARBAGE line would otherwise verify (the HMAC covers the
	// re-marshaled fields, not the raw line). More() flags any trailing token.
	if dec.More() {
		return false, fmt.Errorf("trailing data after audit record")
	}
	storedHMAC := rec.HMAC
	rec.HMAC = "" // zero before re-signing, matching Record()

	body, err := json.Marshal(rec)
	if err != nil {
		return false, err
	}
	// The HMAC certifies the re-marshaled STRUCT, not the on-disk bytes, so every
	// rewrite that decodes to the same fields survives it. An attacker with file-write
	// access but no signing key can therefore rewrite a signed record's bytes and keep
	// it verifying, while the line a byte-oriented consumer reads (SIEM ingest, jq, a
	// grep of the raw log) says something else:
	//
	//   - a duplicate top-level key — {"decision":"allow",<the signed "deny" record>} —
	//     since decoding is last-wins while many consumers are first-wins;
	//   - a re-spelled key ("Decision", "DECISION"), since encoding/json binds fields
	//     case-insensitively even under DisallowUnknownFields, and re-marshaling
	//     restores the canonical spelling;
	//   - a foreign zero-valued omitempty field ("agent_id":""), which the re-marshal
	//     drops again, so it is invisible to the recomputed HMAC;
	//   - an alternate escape of a value ("deny" spelled "\u0064eny"), or whitespace
	//     inserted inside the object or the details subtree — all of which decode to
	//     the very same value.
	//
	// Rather than enumerate those vectors one at a time, require the line to BE the
	// bytes the writer emits for the fields it decoded to: rebuild the canonical line
	// through the same splice writeRecord uses and compare. Anything the writer would
	// not have produced is rejected, which covers the whole class rather than its
	// currently-known members.
	//
	// This adds no cross-version fragility: the HMAC is already computed over
	// json.Marshal of the struct, so any change to the field set or their order breaks
	// old records' signatures regardless — canonical form and HMAC validity move
	// together. Appending a new omitempty field stays compatible under both.
	//
	// Signed records only: a legacy (pre-HMAC) record predates the current struct and
	// carries no signature to contradict, so it has no canonical form to compare with.
	//
	// Whitespace OUTSIDE the object is trimmed rather than rejected: it cannot add,
	// remove, or re-spell a field, so it changes no consumer's reading of the record,
	// and callers legitimately differ on whether the terminating newline is included.
	if storedHMAC != "" {
		canonical, cerr := isCanonicalSignedLine(bytes.TrimSpace(line), body, storedHMAC)
		if cerr != nil {
			return false, cerr
		}
		if !canonical {
			return false, errNonCanonicalRecord
		}
	}
	keys, kerr := s.keysToTry(rec.KeyID)
	if kerr != nil {
		// errKeyIDNotInRing (retired-key state): propagate so the caller reports
		// UNKNOWN_KEY_ID rather than treating the record as tampered.
		return false, kerr
	}
	// Constant-time comparison to prevent a timing side channel that could
	// let an attacker forge an HMAC byte-by-byte.
	for _, key := range keys {
		want := recordMAC(key, body)
		if hmac.Equal([]byte(storedHMAC), []byte(want)) {
			return true, nil
		}
	}
	// No key matched. Distinguish "could not verify" from "tampered":
	//   - A record naming a key_id present in the ring, or one naming none while the
	//     ring DID hold keys to try, was checked against a real key and failed →
	//     (false, nil) → INVALID. When keys were tried, a mismatch is tampering (or an
	//     indistinguishable retired-key case, which we accept reporting as a defensible
	//     INVALID), and the tamper-detection guarantee depends on it.
	//   - A record that names NO key_id verified against NO keys at all (empty ring /
	//     no configured key) could not be checked: the signing key is unidentifiable
	//     AND absent, so calling it tampering is unjustified. Signal that distinctly
	//     (still fail-closed) so the caller reports UNVERIFIABLE. storedHMAC is
	//     non-empty here (empty-HMAC records are classified before VerifyRecord).
	if rec.KeyID == "" && storedHMAC != "" && len(keys) == 0 {
		return false, errUnidentifiedNoMatch
	}
	return false, nil
}

// hasVerificationKey reports whether this sink holds any key to verify records against
// — a non-empty audit-verify keyring or the single active signing key. When it does,
// signing is expected, so an all-legacy (unsigned) log cannot be certified (see
// VerifyResult.Unanchored). An empty (but non-nil) keyring holds no key, so it is not a
// verification key: without a key there is nothing to verify, and an all-legacy log is
// unverifiable rather than a failed anchor.
func (s *Sink) hasVerificationKey() bool {
	return s != nil && (len(s.verifyKeys) > 0 || s.key != nil)
}

// keysToTry returns the candidate keys for verifying a record carrying keyID. With
// a keyring (audit-verify), a non-empty keyID selects its key and an empty keyID is
// tried against every key; without a keyring the single active key is used. A
// non-empty keyID absent from the ring returns errKeyIDNotInRing (fail-closed: no
// key to try) so the caller reports UNKNOWN_KEY_ID rather than INVALID.
func (s *Sink) keysToTry(keyID string) ([][]byte, error) {
	// A nil receiver holds no keys, matching hasVerificationKey's nil tolerance. Both
	// are reachable from the exported VerifyLog/VerifyLogFiles, whose verifier
	// parameter a caller may legitimately leave nil (verify structure only, no
	// signature check) — so the two must agree rather than one answering "no keys" and
	// the other panicking. Returning no keys routes the record through VerifyRecord's
	// "could not verify" branch, never its "tampered" one.
	if s == nil {
		return nil, nil
	}
	ring := s.verifyKeys
	if ring == nil {
		if s.key == nil {
			return nil, nil
		}
		id := s.keyID
		if id == "" {
			id = hmacKeyID(s.key)
		}
		ring = map[string][]byte{id: s.key}
	}
	if keyID != "" {
		if k, ok := ring[keyID]; ok {
			return [][]byte{k}, nil
		}
		return nil, errKeyIDNotInRing
	}
	out := make([][]byte, 0, len(ring))
	for _, k := range ring {
		out = append(out, k)
	}
	return out, nil
}

// VerifyResult summarizes a single audit-verify pass. Its fields are exported so
// the audit-verify subcommand in cmd/eunox can print the per-pass tallies.
type VerifyResult struct {
	Total        int
	Valid        int
	Invalid      int
	Skipped      int
	Legacy       int    // pre-signing records (no _hmac, no seq); exempt, not invalid
	UnknownKey   int    // records naming a key_id absent from the verification ring (retired-key state; not tampering)
	Unverifiable int    // records naming NO key_id that no ring key matched (signing key unidentifiable; not provably tampering)
	ChainBreaks  int    // prev_hmac mismatches or seq gaps between consecutive records
	FirstSeq     uint64 // seq of the first record (0 when the log is empty)
	// Unanchored is set when the verifier held a signing key but the (non-empty) log
	// carried NO signed record — every line was pre-signing legacy shape (no _hmac,
	// seq 0). Such a log has no cryptographic anchor, so it cannot be certified: it is
	// either genuinely pre-HMAC history the held key can say nothing about, or a
	// wholesale unsigned forgery by a write-capable attacker without the key. A
	// legitimate legacy->signed upgrade always leaves a signed marker (see
	// isLegacyTailResumedMarker), so a keyed verify of an all-legacy log is not a normal
	// state. Fails the verdict (see OK) so audit-verify cannot report PASS over it.
	Unanchored bool
	// LegacyUnanchored is set when a head legacy record (unsigned, seq 0) is followed by
	// a BARE genesis seq-1 signed record rather than the legacy_tail_resumed marker. That
	// shape is the rare marker-write-failed upgrade fallback — but it is also exactly what
	// a write-capable attacker WITHOUT the signing key produces by prepending fabricated
	// unsigned "legacy" records ahead of an ordinary signed log (whose first record is a
	// genesis seq-1). The two are indistinguishable without the key, so the mixed-log case
	// is failed closed for the same reason the all-legacy case (Unanchored) is: a genuine
	// upgrade links its signed marker with an empty prev_hmac and never takes this path, so
	// only the rare fallback is a false positive — the fail-closed direction.
	LegacyUnanchored bool
}

// OK reports whether the log passed: no HMAC failure, no chain break, every record
// checkable against a held key, and (when a key was held) at least one signed record
// anchoring the chain. UnknownKey records are not tampered but are unverified (their
// key is absent), so counting them as a failure keeps the verdict fail-closed (a
// tampered record cannot evade detection by relabelling its key_id) while the dedicated
// count tells the operator the cause is a missing key. Unanchored fails the verdict for
// the same fail-closed reason: an all-legacy log under a held key carries no signature
// to verify, so it cannot be certified (see the field comment).
func (r VerifyResult) OK() bool {
	return r.Invalid == 0 && r.ChainBreaks == 0 && r.UnknownKey == 0 && r.Unverifiable == 0 && !r.Unanchored && !r.LegacyUnanchored
}

// SanitizeAuditField replaces every line-breaking rune with a space before an
// attacker-influenceable field (target from a tool/resource/prompt name, session_id
// from the Mcp-Session-Id header — both length-bounded but not control-char-
// sanitized at storage) is interpolated into a single-line diagnostic. A field with
// a literal newline would otherwise inject a spurious finding line that misleads a
// SIEM parsing the output line by line.
//
// unicode.IsControl covers only category Cc (C0/C1 controls), so it misses U+2028
// (LINE SEPARATOR) and U+2029 (PARAGRAPH SEPARATOR) — line terminators recognized by
// many parsers, terminals, and SIEM line-splitters. Neutralize those too, matching
// isYAMLLineBreak in cmd/eunox/init_manifest.go, which already treats both as
// line breaks; otherwise a raw U+2028/U+2029 in target/session_id/key_id would inject
// the very spurious finding line this guard exists to prevent.
func SanitizeAuditField(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return ' '
		}
		return r
	}, s)
}

// VerifyLog scans r and verifies the audit log. Every record's HMAC is recomputed
// (detecting modification) and the chain across consecutive records — prev_hmac
// linkage and seq contiguity — is always verified (detecting deletion, reordering,
// insertion). Both checks run over every record regardless of the
// --request-id/--since filter; those filters narrow only which records are counted
// "valid" and printed, never whether a record is verified, so an attacker cannot
// hide tampering by making the investigator pass a filter.
//
// Scope: the chain is self-contained, so trailing truncation and (on a rotated log)
// leading removal cannot be proven from the file alone — that needs an external
// high-water mark. Interior deletion, reordering, insertion, and modification ARE
// detected here.
func VerifyLog(r io.Reader, verifier *Sink, requestID string, since time.Time, out io.Writer) (VerifyResult, error) {
	v := &auditChainVerifier{verifier: verifier, requestID: requestID, since: since, out: out}
	scanner := NewLineScanner(r)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		v.processLine(line)
	}
	if err := scanner.Err(); err != nil {
		return v.res, err
	}
	// A log whose EVERY record classified as legacy (pre-signing shape: no _hmac, seq 0),
	// while the verifier holds a key, has no cryptographic anchor — no signature to verify.
	// A legitimate legacy->signed upgrade always leaves a signed record (the
	// legacy_tail_resumed marker or a genesis seq-1 record), so an all-legacy log under a
	// key is not a normal state: it is either genuine pre-HMAC history the held key cannot
	// certify, or a wholesale unsigned forgery by a write-capable attacker without the key
	// (deleting the log and its rotated siblings and rewriting them in legacy shape). Treat
	// it as unverifiable rather than silently PASS. Keyed on Total == Legacy (not signedSeen,
	// which a stream of records the chain walk rejected as decoys leaves false even though
	// none of them was legacy): Total == Legacy holds only when every record landed in the
	// legacy bucket, which is the state this diagnostic describes. Empty logs
	// are exempt (nothing to anchor); leading-truncation-to-empty needs an external
	// high-water mark, as documented above.
	if v.res.Legacy > 0 && v.res.Legacy == v.res.Total && verifier.hasVerificationKey() {
		v.res.Unanchored = true
		_, _ = fmt.Fprintf(out, "UNANCHORED  the log has %d record(s) but none is signed (all pre-HMAC legacy shape) while a verification key is configured; it carries no signature to verify — either genuine pre-signing history the key cannot certify, or a wholesale unsigned forgery\n", v.res.Total)
	}
	return v.res, nil
}

// VerifyLogFiles verifies an ordered set of audit-log files as ONE continuous
// chain. It runs VerifyLog's per-record HMAC and chain checks threaded across file
// boundaries: each file's head record is checked against the previous file's tail,
// so deletion of an entire interior rotated file is caught (a prev_hmac mismatch and
// a seq gap) — something verifying any single file cannot detect. Every guard
// applies to the concatenated stream as to a single file, since cross-file links
// are just ordinary consecutive-record links.
//
// Pass files in chain order, oldest first (LogChainFiles produces exactly that).
// They are joined with a newline so an unterminated final record cannot glue onto
// the next file's head (empty lines are skipped).
//
// Each file is opened lazily and closed when exhausted, so at most one is open at a
// time. This bounds the fd count under the keep-all default (--audit-retain 0),
// where the sibling count is unbounded. An open error is surfaced (as a VerifyLog
// read error), not skipped: an unreadable chain file cannot be certified, so
// audit-verify fails closed.
func VerifyLogFiles(paths []string, verifier *Sink, requestID string, since time.Time, out io.Writer) (VerifyResult, error) {
	r, lazies := buildLazyChain(paths)
	// Backstop: if VerifyLog returns before draining (e.g. a scanner error), close
	// whatever file is still open. A clean pass already closes each at EOF.
	defer func() {
		for _, lr := range lazies {
			lr.close()
		}
	}()
	return VerifyLog(r, verifier, requestID, since, out)
}

// buildLazyChain joins paths (chain order, oldest first) into one io.Reader that
// opens a single file at a time, newline-separating files so an unterminated final
// record cannot glue onto the next file's head (empty lines are skipped by line
// scanners). It returns the lazies so the caller can close any file still open if
// it stops reading before EOF. Shared by VerifyLogFiles and OpenLogChain so the
// one-fd-at-a-time chain construction lives once.
func buildLazyChain(paths []string) (io.Reader, []*lazyFileReader) {
	lazies := make([]*lazyFileReader, 0, len(paths))
	readers := make([]io.Reader, 0, len(paths)*2)
	for i, p := range paths {
		lr := &lazyFileReader{path: p}
		lazies = append(lazies, lr)
		if i > 0 {
			readers = append(readers, strings.NewReader("\n"))
		}
		readers = append(readers, lr)
	}
	return io.MultiReader(readers...), lazies
}

// lazyFileReader opens its path on the first Read and closes it once exhausted (EOF
// or error), so a sequence fed to io.MultiReader keeps at most one file open at a
// time. Single-use: once done it reports EOF (or its sticky open error) and never
// reopens, so MultiReader cannot make it re-read a streamed file.
type lazyFileReader struct {
	path string
	f    *os.File
	done bool  // exhausted/closed: report EOF (or err) and never reopen
	err  error // sticky open error, re-reported if Read is called again
}

func (l *lazyFileReader) Read(p []byte) (int, error) {
	if l.f == nil {
		if l.done {
			if l.err != nil {
				return 0, l.err
			}
			return 0, io.EOF
		}
		f, err := os.Open(l.path) //nolint:gosec // G304: path is a discovered audit-log file
		if err != nil {
			l.done = true
			l.err = fmt.Errorf("opening audit log %q: %w", l.path, err)
			return 0, l.err
		}
		l.f = f
	}
	n, err := l.f.Read(p)
	if err != nil {
		// EOF or error: release the fd before MultiReader advances (the point of
		// opening lazily). The error (io.EOF included) is returned unchanged.
		l.close()
	}
	return n, err
}

// close releases the fd (if any) and marks the reader done. Idempotent, so the
// VerifyLogFiles backstop can call it unconditionally.
func (l *lazyFileReader) close() {
	if l.f != nil {
		_ = l.f.Close()
		l.f = nil
	}
	l.done = true
}

// OpenLogChain returns a reader over the rotated audit chain (pass paths in chain
// order, oldest first — LogChainFiles produces exactly that), opening one file at a
// time so at most one fd is held regardless of how many rotated siblings exist.
// This bounds the fd count for read-only reporting (stats/suggest/doctor) under the
// keep-all retention default (--audit-retain 0), where the sibling count is
// unbounded; eagerly opening every file would risk EMFILE on a long-rotated log.
// Files are newline-joined so an unterminated final record cannot glue onto the
// next file's head (empty lines are skipped by line scanners). Callers MUST Close
// the returned reader to release any file still open. It is the verification-free
// counterpart to VerifyLogFiles, which adds HMAC chain checks on the same stream.
func OpenLogChain(paths []string) io.ReadCloser {
	r, lazies := buildLazyChain(paths)
	return &chainReader{r: r, lazies: lazies}
}

// chainReader adapts the lazy MultiReader from OpenLogChain to io.ReadCloser so
// callers can release a partially-read chain (a scanner error before EOF leaves one
// file open; a clean pass closes each at EOF). Close is idempotent.
type chainReader struct {
	r      io.Reader
	lazies []*lazyFileReader
}

// Read streams the next bytes from the lazy chain (one file open at a time).
func (c *chainReader) Read(p []byte) (int, error) { return c.r.Read(p) }

// Close releases any file still open (idempotent), so a caller that stops reading
// before EOF does not leak the in-progress fd.
func (c *chainReader) Close() error {
	for _, lr := range c.lazies {
		lr.close()
	}
	return nil
}

// auditChainVerifier carries the loop state of one VerifyLog pass: the running
// tallies (res) and the chain anchor (hmac/seq of the last LEGITIMATE record).
// processLine is called for each non-empty line, in order.
type auditChainVerifier struct {
	verifier  *Sink
	requestID string
	since     time.Time
	out       io.Writer

	res      VerifyResult
	havePrev bool
	prevHMAC string
	prevSeq  uint64
	// signedSeen latches true once any signed record (isSignedRecord) is processed.
	// After that a genuine pre-signing legacy record (HMAC=="" && Seq==0) can no
	// longer legitimately appear, so a later one is treated as tampering.
	signedSeen bool
	// prevRecordInvalid is set by classify ONLY when the previous record's HMAC was
	// provably wrong under a held key (the !ok / err cases) — i.e. its content was
	// modified while its stored _hmac was left intact. updateChain stores rec.HMAC
	// before classify runs, so such a tampered record's forged HMAC is written into
	// v.prevHMAC; prevRecordInvalid lets the NEXT record's updateChain call detect
	// that the anchor is untrustworthy and emit a CHAIN BREAK before the usual
	// prev_hmac link check. It is deliberately NOT set for UnknownKey/Unverifiable
	// records, whose _hmac is intact (a retired/absent key, not tampering) and still
	// chains correctly — flagging those would mislabel a routine rotation as tampering.
	prevRecordInvalid bool
	// prevWasLegacyHead is true when the record just folded into the chain state was a
	// head legacy record (unsigned, HMAC=="" && Seq==0, before any signed record). It
	// lets the next record's link check accept the one legitimate legacy->signed
	// transition that carries the genesis sentinel (see updateChain).
	prevWasLegacyHead bool
}

// decodeAuditRecord decodes one line into an auditRecord, reporting whether it was
// well-formed JSON with no trailing data. UseNumber gives parity with VerifyRecord
// (a guard for any future interface{}-typed field; see there), and the !More() guard
// rejects a tampered {…record…}GARBAGE line the !unmarshalOK gate would otherwise
// accept. A malformed line leaves rec at its zero value (HMAC="", Seq=0); the caller
// must keep it out of the chain state so it does not poison prevHMAC/prevSeq and
// fabricate spurious breaks.
func decodeAuditRecord(line []byte) (auditRecord, bool) {
	var rec auditRecord
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	unmarshalOK := dec.Decode(&rec) == nil && !dec.More()
	return rec, unmarshalOK
}

// isSignedRecord reports whether rec belongs to the signed era, i.e. carries a
// non-empty HMAC — writeRecord signs every record it writes unconditionally, so a
// genuinely written record's HMAC presence is exactly what distinguishes it from a
// pre-chain legacy record.
//
// Single source of truth for this discriminator: EVERY signed/legacy split in this
// file routes through it — VerifyRecord's lenient-decode fallback and canonical-form
// check, updateChain's signedSeen latch and prevWasLegacyHead, processLine's
// forgedLegacySplice, and classify's legacy bucket — rather than re-deriving the
// comparison. That is what makes the promise load-bearing: today every spelling is
// behaviorally identical, but a future change to what a signed record looks like
// (an added decoy shape, a different empty sentinel) would otherwise have to find
// and update each open-coded check, and a missed one would silently classify a
// forged record into the legacy bucket that exists to be lenient.
func isSignedRecord(rec auditRecord) bool {
	return rec.HMAC != ""
}

// processLine verifies one log line: it maintains the tamper-evident chain state
// across legitimate records (updateChain), then classifies and reports it.
func (v *auditChainVerifier) processLine(line []byte) {
	v.res.Total++
	rec, unmarshalOK := decodeAuditRecord(line)

	// A Seq==0 record with a non-empty HMAC is structurally impossible (legacy
	// records carry no HMAC; signed records start at seq 1), so it is a forged decoy,
	// rejected below and kept out of the chain state — adopting its seq 0 as prevSeq
	// would suppress the next record's SEQ GAP diagnostic (the `prevSeq > 0` guard).
	//
	// The rejection is unconditional. The only shape that could ever be a LEGITIMATE
	// seq-0 signed record is the uint64 counter wrapping past 2^64 records — which no
	// deployment reaches (~584,000 years at 10^6 records/sec) and which the writer
	// cannot even carry across a restart, since a resume that cannot trust the tail
	// reseeds the counter. Exempting the wrap (and the head record that a
	// wrap-then-rotate would leave with no in-stream predecessor) put two holes in the
	// hottest piece of decoy rejection in exchange for a state that cannot occur: an
	// attacker only had to place their seq-0 decoy at the head of a stream, or after a
	// record claiming seq MaxUint64, to skip this check entirely.
	forgedSeq0 := rec.Seq == 0 && rec.HMAC != ""
	// An HMAC-less record AFTER a signed one is a forged legacy record spliced into
	// the signed chain (a genuine legacy record — pre-signing history the writer
	// resumed onto — only precedes the first signed one). Kept out of the chain
	// state: adopting its "" prev_hmac would let a deletion be hidden (the next
	// record links with prev_hmac="" and the seq-gap check is suppressed).
	//
	// This is NOT restricted to Seq==0: the writer's resume rule in Open
	// (`s.resumedLegacyTail = prev.HMAC == ""`) is deliberately seq-independent, so a
	// pre-chain tail can carry ANY stale seq value inherited from before the chain
	// existed (see TestAuditChain_ResumesFromLegacyTail's "seq-bearing legacy tail"
	// case) — not just the seq-0 shape a fresh, never-yet-chained log also produces.
	// Gating this on Seq==0 would count a seq-bearing legacy tail INVALID (an
	// HMAC-less record with a non-zero Seq matches neither this exemption nor any
	// other), contradicting the writer's own documented, tested resume behavior — the
	// two components would disagree on what the identical on-disk shape means. A
	// genuine head legacy record (signedSeen false) is NOT excluded here, whatever its
	// seq, so the legacy->first-signed transition still verifies.
	forgedLegacySplice := !isSignedRecord(rec) && v.signedSeen

	// Chain verification runs over every decodable record (except the decoys above),
	// independent of the filter; the reporting filter is applied only afterward.
	// prev_hmac linkage and seq contiguity are checked as separate ifs, not switch
	// cases: an interior deletion trips BOTH, and a switch would emit only the first,
	// hiding how many records were removed.
	if unmarshalOK && !forgedSeq0 && !forgedLegacySplice {
		v.updateChain(rec)
	}
	v.classify(line, rec, unmarshalOK, forgedSeq0, forgedLegacySplice)
}

// isLegacyTailResumedMarker reports whether rec is the synthetic legacy_tail_resumed
// integrity marker — the one record that legitimately starts a signed chain with an
// empty prev_hmac (written first after resuming onto a pre-chain unsigned tail). It
// is identified by the integrity-failure denial code AND the details.kind shared with
// the writer (audit.go), so the genesis check can distinguish a real legacy boundary
// from a leading-truncation forgery wearing an empty prev_hmac. The record is signed,
// so without the key neither field can be set on a forged record that also verifies.
func isLegacyTailResumedMarker(rec auditRecord) bool {
	if rec.DenialCode != auditIntegrityFailureCode || len(rec.Details) == 0 {
		return false
	}
	var d struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(rec.Details, &d); err != nil {
		return false
	}
	return d.Kind == auditKindLegacyTailResumed
}

// updateChain checks a legitimate record's prev_hmac linkage and seq contiguity
// against the chain anchor, reporting any break, then advances the anchor.
func (v *auditChainVerifier) updateChain(rec auditRecord) {
	if !v.havePrev {
		v.res.FirstSeq = rec.Seq
		// The first record of a fresh log (seq == 1) must carry the genesis sentinel
		// as prev_hmac (writeRecord stamps it unconditionally). Verifying it closes a
		// leading-truncation gap: excising the true seq-1 record and rewriting the
		// survivor to claim seq 1 would otherwise pass, since the chain check below is
		// skipped for the first record. A rotated log legitimately starts at seq > 1,
		// so this is provable only at seq == 1.
		//
		// An empty prev_hmac at seq 1 is exempt ONLY when this first record is the
		// genuine legacy_tail_resumed integrity marker. writeRecord emits an empty
		// prev_hmac exclusively right after a resume onto a pre-chain (unsigned) tail,
		// and that resume always writes the legacy_tail_resumed marker as its first
		// record — so a legitimate empty-prev_hmac seq-1 record is ALWAYS that marker
		// (recognizable, and signed, so its kind cannot be flipped without the key).
		// The previous blanket `prev_hmac != ""` exemption instead let a key-holder
		// truncate all leading records and forge an ORDINARY seq-1 allow/deny record
		// with prev_hmac="" and a valid HMAC, passing verification with no chain break.
		// Now any non-marker empty-prev_hmac seq-1 record is flagged; a key-holder can
		// still forge the marker itself, but that pushes the forgery into a conspicuous,
		// auditable AUDIT_INTEGRITY_FAILURE record that should appear at most once ever
		// (the pre-chain→chain upgrade), rather than hiding as routine traffic.
		// A genuine legacy_tail_resumed marker is the one record that legitimately
		// starts a signed chain with an empty prev_hmac; everything else at seq 1 must
		// carry the genesis sentinel.
		legitLegacyBoundary := rec.PrevHMAC == "" && isLegacyTailResumedMarker(rec)
		if rec.Seq == 1 && rec.PrevHMAC != auditGenesisPrev && !legitLegacyBoundary {
			v.res.ChainBreaks++
			if rec.PrevHMAC == "" {
				_, _ = fmt.Fprintf(v.out, "CHAIN BREAK at seq 1: prev_hmac is empty but the record is not a legacy_tail_resumed marker — a legitimate legacy-tail resume starts the signed chain with that marker, so a bare empty-prev_hmac seq-1 record indicates leading records were deleted and a replacement was forged\n")
			} else {
				_, _ = fmt.Fprintf(v.out, "CHAIN BREAK at seq 1: prev_hmac is %q, expected genesis sentinel %q (a leading record was deleted or the origin was rewritten)\n", rec.PrevHMAC, auditGenesisPrev)
			}
		}
	} else {
		// If the preceding record failed VerifyRecord (an HMAC mismatch, or — since
		// this branch is reached on any non-nil error — a non-canonical-form
		// rejection) its _hmac value in v.prevHMAC is untrustworthy: an attacker can
		// set an arbitrary forged _hmac on the bad record and then stitch its
		// successor by setting prev_hmac to that same value, making the link check
		// pass for a tampered record. Fire a CHAIN BREAK before the link check to
		// surface the untrustworthy anchor.
		if v.prevRecordInvalid {
			v.res.ChainBreaks++
			_, _ = fmt.Fprintf(v.out, "CHAIN BREAK at seq %d: the preceding record failed verification; its _hmac is untrustworthy and cannot serve as a valid chain anchor\n", rec.Seq)
			v.prevRecordInvalid = false
		}
		// A genesis-sentinel seq-1 record immediately following a head legacy (unsigned)
		// record is the legitimate legacy->signed transition when the legacy_tail_resumed
		// marker write failed: the writer then clears resumedLegacyTail and the first
		// appended record falls through to the genesis branch (see audit.go writeRecord),
		// so it carries the genesis sentinel rather than the empty prev_hmac the marker
		// would. Accept it — a lone genesis seq-1 record is already a valid fresh-chain
		// start, and the preceding record is unsigned (carries no integrity), so this
		// adds no forgery surface a key-holder does not already have (they could forge a
		// lone genesis seq-1 start by truncating everything before it regardless).
		legacyToSignedGenesis := v.prevWasLegacyHead && rec.Seq == 1 && rec.PrevHMAC == auditGenesisPrev
		if legacyToSignedGenesis {
			// The link check accepts this transition (no CHAIN BREAK) — but the same shape is
			// what a write-capable attacker WITHOUT the signing key produces by prepending
			// fabricated unsigned "legacy" records ahead of an ordinary signed log, so the
			// VERDICT is failed closed (LegacyUnanchored). A genuine upgrade links its signed
			// legacy_tail_resumed marker via an empty prev_hmac and never reaches this branch;
			// only the rare marker-write-failed fallback is a false positive.
			v.res.LegacyUnanchored = true
			_, _ = fmt.Fprintf(v.out, "UNANCHORED  at seq 1: a bare genesis seq-1 record follows a head legacy (unsigned) record instead of the legacy_tail_resumed marker; the preceding unsigned record(s) carry no signature and cannot be certified — either a marker-write-failed upgrade or fabricated legacy records prepended by a write-capable attacker without the key\n")
		}
		if !legacyToSignedGenesis && rec.PrevHMAC != v.prevHMAC {
			v.res.ChainBreaks++
			_, _ = fmt.Fprintf(v.out, "CHAIN BREAK at seq %d: prev_hmac does not match the preceding record (a record was deleted, reordered, or inserted)\n", rec.Seq)
		}
		// A seq gap is meaningful only in the signed era: consecutive legacy records
		// both decode to seq 0, so "0 does not follow 0" would fire spuriously, and
		// the legacy->first-signed transition (0 -> 1) is contiguous. Gate on
		// signedSeen, not prevSeq > 0: a legacy tail can carry any stale seq, so
		// prevSeq > 0 would both miss that suppression and, wherever prevSeq is 0,
		// skip the check entirely and give an inserter a blind spot. signedSeen tracks
		// the property actually being gated on — has the signed era begun.
		if rec.Seq != v.prevSeq+1 && rec.Seq > 0 && v.signedSeen {
			v.res.ChainBreaks++
			_, _ = fmt.Fprintf(v.out, "SEQ GAP: record seq %d does not follow %d (a record is missing)\n", rec.Seq, v.prevSeq)
		}
	}
	v.havePrev = true
	v.prevHMAC = rec.HMAC
	v.prevSeq = rec.Seq
	// A head legacy record reaches updateChain only before any signed record (the
	// forgedLegacySplice guard excludes a post-signed unsigned splice), so an
	// HMAC-less seq-0 record here is a genuine legacy head. Record that so the next
	// record's link check can accept the genesis-sentinel legacy->signed transition.
	// Restricted to Seq==0 (unlike forgedLegacySplice/the classify legacy bucket,
	// which accept any seq): the downstream legacyToSignedGenesis check this field
	// feeds is itself gated on the FOLLOWING record's Seq==1, which writeRecord's
	// resume (`rec.Seq = s.seq+1`, seeded from the tail's own seq) only ever produces
	// after a seq-0 tail — a seq-bearing tail's next record starts at tail.Seq+1, so
	// leaving this narrower does not miss that case.
	v.prevWasLegacyHead = !isSignedRecord(rec) && rec.Seq == 0
	// signedSeen means "a genuinely SIGNED record has been seen" (gating both the
	// seq-gap check above and forgedLegacySplice in processLine), which is exactly
	// isSignedRecord: a legacy record can itself carry a non-zero seq (the
	// seq-bearing legacy tail forgedLegacySplice now accepts), so gating on Seq > 0
	// alone would flip signedSeen true on a legacy record and misclassify the NEXT
	// genuine legacy record — still HMAC-less, still preceding any real signed
	// record — as a forged post-signing splice. isSignedRecord's HMAC check is what
	// excludes that shape.
	if isSignedRecord(rec) {
		v.signedSeen = true
	}
}

// classify counts and reports the record's verification outcome: malformed,
// forged decoy, legacy, or HMAC-verified (valid/invalid/skipped per the filter).
func (v *auditChainVerifier) classify(line []byte, rec auditRecord, unmarshalOK, forgedSeq0, forgedLegacySplice bool) {
	// A line that failed to decode cannot be filtered or HMAC-verified, but is
	// unambiguous corruption. Count it invalid before the filter so an active
	// --request-id/--since cannot downgrade it to a silent skip and produce a false
	// PASS over a corrupted log.
	if !unmarshalOK {
		v.res.Invalid++
		_, _ = fmt.Fprintf(v.out, "INVALID  malformed record %d: not valid JSON\n", v.res.Total)
		return
	}

	// A forged seq-0 decoy (Seq==0 + HMAC, anywhere in the stream) is rejected
	// regardless of whether its HMAC verifies, closing the substitution vector even
	// against a signing-key holder.
	if forgedSeq0 {
		v.res.Invalid++
		_, _ = fmt.Fprintf(v.out, "INVALID  record %d: seq 0 with a non-empty HMAC is not a valid record (forged seq-0 decoy)\n", v.res.Total)
		return
	}

	// Pre-signing legacy records carry no _hmac. They may carry ANY seq value — the
	// familiar seq-0 shape (HMAC=="", Seq==0) from a log that never got signed, or a
	// seq-bearing tail inherited from before the chain existed (see
	// forgedLegacySplice's doc comment in processLine): the writer's own resume rule
	// treats both identically, so this check must too, or the two components disagree
	// on what the identical on-disk shape means. Neither shape has an HMAC to verify,
	// so VerifyRecord would count every one INVALID; count them in their own legacy
	// bucket instead (mirroring Open's resume exemption) so audit-verify is safe
	// across the upgrade boundary. The exemption holds only at the head: an
	// HMAC-less record AFTER a signed one is a forged splice that would otherwise
	// launder through the legacy bucket, so classify it invalid.
	if !isSignedRecord(rec) {
		// Use the forgedLegacySplice computed in processLine rather than re-deriving
		// it from v.signedSeen, so classify stays a pure function of its inputs.
		if forgedLegacySplice {
			v.res.Invalid++
			_, _ = fmt.Fprintf(v.out, "INVALID  record %d: unsigned record (seq=%d) follows a signed record (forged legacy record spliced into a signed chain)\n", v.res.Total, rec.Seq)
			return
		}
		v.res.Legacy++
		return
	}

	// Every record's HMAC is recomputed UNCONDITIONALLY, before the filter. Gating
	// VerifyRecord behind --request-id/--since would let an attacker modify any
	// record outside the filter window with its _hmac intact: the chain check above
	// only confirms rec.HMAC appears in the next record's prev_hmac, it does not
	// recompute it from content. The filter controls only what is counted "valid" and
	// printed, never whether a record is verified.
	inReportWindow := v.requestID == "" || rec.RequestID == v.requestID
	// The signed `time` field is validated for EVERY signed record, independent of the
	// --since/--request-id filter: an unparseable time on an HMAC-valid record is format
	// drift or tampering and must fail the verdict identically whether or not a filter is
	// passed (the filter narrows only what is counted "valid"/printed, never whether a
	// record is verified). Gating this behind --since would make the same log PASS bare
	// but FAIL under --since. The parse also feeds the --since lower-bound comparison.
	// malformedTime distinguishes a bad-time record from one that is simply older than
	// --since; both would otherwise fall to Skipped, understating Valid and hiding drift.
	t, timeErr := time.Parse(time.RFC3339Nano, rec.Time)
	malformedTime := timeErr != nil
	switch {
	case malformedTime:
		inReportWindow = false
	case !v.since.IsZero() && t.Before(v.since):
		// --since is an inclusive lower bound: t.Before(since) is the exclusive skip
		// region (t < since), so t == since is kept, matching log-tailing tools.
		inReportWindow = false
	}

	ok, err := v.verifier.VerifyRecord(line)
	switch {
	case errors.Is(err, errKeyIDNotInRing):
		// Key absent from the ring (retired-key state, not tampering). Report and count
		// it distinctly so the INVALID tally stays a true tamper count; the verdict
		// still fails (OK() treats UnknownKey as unverified). key_id is sanitized in
		// case a future writer admits control chars.
		_, _ = fmt.Fprintf(v.out, "UNKNOWN_KEY_ID  seq=%d key_id=%s — signed with a key absent from the verification ring; add that key to verify it (expected after a key rotation that retired the signing key)\n",
			rec.Seq, SanitizeAuditField(rec.KeyID))
		v.res.UnknownKey++
		// Do NOT mark the chain anchor untrustworthy here: a named-but-absent key_id is
		// the routine post-rotation state, and the record's _hmac is intact (it was
		// computed by the legitimate signer with the now-retired key), so its successor's
		// prev_hmac still links correctly. Flagging a chain break would mislabel a benign
		// rotation as tampering. Only a provable HMAC mismatch under a held key (the !ok /
		// err cases below) invalidates the anchor.
	case errors.Is(err, errUnidentifiedNoMatch):
		// The record names no key_id and no ring key matched it: the signing key is
		// unidentifiable, so this cannot be proven to be tampering rather than a
		// retired/absent key (as a named-but-missing key_id can). Report distinctly and
		// count it in its own bucket so the INVALID tally stays a true tamper count; the
		// verdict still fails (OK() treats Unverifiable as unverified).
		_, _ = fmt.Fprintf(v.out, "UNVERIFIABLE  seq=%d — record names no key_id and no key in the verification ring matched it; cannot identify the signing key to verify it (add the original key, or this may be tampering)\n",
			rec.Seq)
		v.res.Unverifiable++
		// Not provably tampering (see the message): this is indistinguishable from a
		// retired/absent key whose _hmac is intact and chains correctly, so do not
		// fabricate a chain break on the successor. OK() already fails the verdict on any
		// Unverifiable record; only a provable HMAC mismatch (the !ok / err cases below)
		// invalidates the anchor.
	case err != nil:
		// A verification error or HMAC mismatch is tampering: count it regardless of
		// the filter.
		_, _ = fmt.Fprintf(v.out, "ERROR  seq %d: %v\n", rec.Seq, err)
		v.res.Invalid++
		v.prevRecordInvalid = true
	case !ok:
		// Sanitize the interpolated fields (target and session_id are
		// attacker-influenceable and not control-char-sanitized at storage, so a
		// literal newline could inject a spurious finding line).
		_, _ = fmt.Fprintf(v.out, "INVALID  seq=%d request_id=%s session_id=%s target=%s\n",
			rec.Seq, SanitizeAuditField(rec.RequestID), SanitizeAuditField(rec.SessionID), SanitizeAuditField(rec.Target))
		v.res.Invalid++
		v.prevRecordInvalid = true
	case malformedTime:
		// HMAC-valid but the required, signed `time` field does not parse as RFC3339
		// Nano: count it Invalid (not Skipped) and surface a diagnostic so format drift
		// or tampering is visible rather than buried in the Skipped tally.
		_, _ = fmt.Fprintf(v.out, "INVALID  seq=%d: unparseable time field %q\n", rec.Seq, SanitizeAuditField(rec.Time))
		v.res.Invalid++
	case inReportWindow:
		v.res.Valid++
	default:
		// Verified OK but outside the report window: counted skipped for display only.
		v.res.Skipped++
	}
}
