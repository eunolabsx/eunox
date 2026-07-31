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

// errKeyIDNotInRing is returned by keysToTry (and propagated by the signature check) when
// a record names a key_id absent from the verification ring — a missing key (the
// expected state after a rotation retired the signing key), NOT an HMAC mismatch.
// Signalling it distinctly lets VerifyLog report UNKNOWN_KEY_ID rather than INVALID.
var errKeyIDNotInRing = errors.New("audit record key_id is not in the verification ring")

// errUnidentifiedNoMatch is returned by the signature check when a record names NO key_id
// (a pre-key_id-era signed record) and no key in the ring matched its HMAC. Unlike
// a named-key-in-ring mismatch (genuine tampering → INVALID), an unidentified
// record offers no way to tell a retired/absent signing key from tampering, so the
// caller reports UNVERIFIABLE rather than asserting tampering — still failing the
// verdict (fail-closed), distinct from both INVALID and UNKNOWN_KEY_ID.
var errUnidentifiedNoMatch = errors.New("audit record names no key_id and no ring key matched its HMAC")

// errNonCanonicalRecord is returned by the canonical-on-disk-form check; see that
// check's comment in verifyDecodedRecord for what it catches and why.
var errNonCanonicalRecord = errors.New("signed audit record is not in canonical on-disk form: its bytes are not what the writer emits for these fields (a duplicate, re-spelled, or reordered key, an added zero-valued field, an alternate escape, or inserted whitespace) — the HMAC covers the record's fields, not its bytes, so a rewrite that decodes to the same fields is rejected here")

// VerifyRecord re-computes the HMAC of a raw record line and reports whether it
// matches. The record's key_id selects the key, so a log straddling a rotation
// still verifies: a known key_id is checked against that key, and a record with no
// key_id (pre-rotation or single-key) against every key in the ring.
//
// It is the entry point for a caller holding only the line. A caller that has
// already strict-decoded it (VerifyLog's chain walk) hands the record straight to
// verifyDecodedRecord instead, so a verify pass decodes each line once.
func (s *Sink) VerifyRecord(line []byte) (bool, error) {
	rec, err := strictDecodeAuditRecord(line)
	if err != nil {
		return false, err
	}
	return s.verifyDecodedRecord(line, rec)
}

// verifyDecodedRecord is VerifyRecord's body over a line the caller has already
// strict-decoded. Splitting it this way is what lets VerifyLog verify without
// decoding a second time.
//
// rec MUST be the product of a SUCCESSFUL strictDecodeAuditRecord, never of a
// lenient decode: the HMAC is recomputed below over the re-marshaled struct, and a
// lenient decode silently DROPS unknown fields, so an injected field (e.g.
// "operator_override":"approved") would not be covered by the recomputed HMAC yet
// the modified on-disk line would still verify. Taking no error parameter is what
// enforces that — a caller holding a lenient record holds it precisely because the
// strict decode FAILED, and it has an error to report instead of a record to pass
// here, so the unsafe pairing cannot be spelled.
//
// A nil receiver is tolerated (see keysToTry): it is the structure-only verify mode.
func (s *Sink) verifyDecodedRecord(line []byte, rec auditRecord) (bool, error) {
	storedHMAC := rec.HMAC
	// Fail closed on an unsigned record rather than proceeding to a comparison against
	// an empty MAC. Callers classify this shape before reaching here (see classify and
	// resumeChainFromTail), so this is the backstop, not the primary path — it exists so
	// a reordering of those pre-filters degrades to a plain refusal instead of a
	// silently-passing verification. It is deliberately NOT a distinct sentinel: no
	// caller branches on the reason, and an error value nothing reads reads as a
	// distinction that is being made somewhere.
	if storedHMAC == "" {
		return false, fmt.Errorf("audit record carries no _hmac, so it cannot be verified")
	}
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
	// bytes the writer emits for the fields it decoded to: compare it against the same
	// splice writeRecord uses (in place, without materializing that line). Anything the
	// writer would not have produced is rejected, which covers the whole class rather
	// than its currently-known members.
	//
	// This adds no cross-version fragility: the HMAC is already computed over
	// json.Marshal of the struct, so any change to the field set or their order breaks
	// old records' signatures regardless — canonical form and HMAC validity move
	// together. Appending a new omitempty field stays compatible under both.
	//
	// Whitespace OUTSIDE the object is trimmed rather than rejected: it cannot add,
	// remove, or re-spell a field, so it changes no consumer's reading of the record,
	// and callers legitimately differ on whether the terminating newline is included.
	canonical, cerr := isCanonicalSignedLine(bytes.TrimSpace(line), body, storedHMAC)
	if cerr != nil {
		return false, cerr
	}
	if !canonical {
		return false, errNonCanonicalRecord
	}
	keys, kerr := s.keysToTry(rec.KeyID)
	if kerr != nil {
		// errKeyIDNotInRing (retired-key state): propagate so the caller reports
		// UNKNOWN_KEY_ID rather than treating the record as tampered.
		return false, kerr
	}
	// Constant-time comparison to prevent a timing side channel that could
	// let an attacker forge an HMAC byte-by-byte.
	//
	// macBuf is refilled in place per key rather than each key allocating its own
	// digest: appendRecordMAC writes into it, where recordMAC would hex-encode into a
	// fresh string and then convert that back to bytes to compare — 3 allocations per
	// key per record, on a path that runs once per record of a multi-GB archive.
	// (The storedHMAC conversion is hoisted for clarity, not for allocation: the
	// compiler already keeps a non-escaping []byte(string) off the heap, measurably so
	// both before and after this hoist.)
	storedMAC := []byte(storedHMAC)
	var macBuf []byte
	for _, key := range keys {
		macBuf = appendRecordMAC(macBuf[:0], key, body)
		if hmac.Equal(storedMAC, macBuf) {
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
	//     (still fail-closed) so the caller reports UNVERIFIABLE. An HMAC-less record
	//     cannot reach here: it is refused above (errUnsignedRecord).
	if rec.KeyID == "" && len(keys) == 0 {
		return false, errUnidentifiedNoMatch
	}
	return false, nil
}

// keysToTry returns the candidate keys for verifying a record carrying keyID. With
// a keyring (audit-verify), a non-empty keyID selects its key and an empty keyID is
// tried against every key; without a keyring the single active key is used. A
// non-empty keyID absent from the ring returns errKeyIDNotInRing (fail-closed: no
// key to try) so the caller reports UNKNOWN_KEY_ID rather than INVALID.
func (s *Sink) keysToTry(keyID string) ([][]byte, error) {
	// A nil receiver holds no keys rather than panicking. That tolerance is
	// load-bearing, not defensive: VerifyLog/VerifyLogFiles document a nil verifier as
	// the structure-only mode (verify shape and chain, no signature check), and classify
	// reaches it through verifyDecodedRecord on every signed record, so deleting this
	// branch turns that pass into a nil dereference. Returning no keys routes the
	// record through the "could not verify" branch, never the "tampered" one.
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
	UnknownKey   int // records naming a key_id absent from the verification ring (retired-key state; not tampering)
	Unverifiable int // records naming NO key_id that no ring key matched (signing key unidentifiable; not provably tampering)
	ChainBreaks  int // prev_hmac mismatches or seq gaps between consecutive records
	// FirstSeq is the seq of the first record that entered the chain — i.e. the first
	// SIGNED one. It is 0 for an empty log AND for a log that carries no signed record
	// at all (every line unsigned: pre-signing history, or a wholesale unsigned
	// forgery), so a consumer must read it together with Total/Invalid rather than
	// treating 0 as "empty".
	FirstSeq uint64
}

// OK reports whether the log passed: no HMAC failure, no chain break, and every record
// checkable against a held key. UnknownKey records are not tampered but are unverified
// (their key is absent), so counting them as a failure keeps the verdict fail-closed (a
// tampered record cannot evade detection by relabelling its key_id) while the dedicated
// count tells the operator the cause is a missing key.
//
// An unsigned record has no separate bucket: it is INVALID like any other record that
// cannot be certified, so a log with no signed records anywhere — pre-signing history,
// or a wholesale unsigned forgery by a write-capable attacker without the key — fails
// on the Invalid count alone.
func (r VerifyResult) OK() bool {
	return r.Invalid == 0 && r.ChainBreaks == 0 && r.UnknownKey == 0 && r.Unverifiable == 0
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
	v.reportSuppressedUnsigned()
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
	// unsignedSeen counts HMAC-less records so their per-record diagnostic can be capped
	// at maxUnsignedDiagnostics; the Invalid tally in res is unaffected and stays exact.
	unsignedSeen int
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
}

// maxUnsignedDiagnostics bounds how many per-record "unsigned record" lines a single
// verify pass prints. A log with a pre-signing prefix produces one per record, and an
// unbounded stream of them buries the CHAIN BREAK / INVALID findings the tool exists to
// surface — the practical result being an operator who suppresses the whole check. Sized
// to show enough to recognize the shape while leaving the output readable; the exact
// count always survives in VerifyResult.Invalid and in the closing summary line.
const maxUnsignedDiagnostics = 10

// recordDecode is what decodeAuditRecord's pass over a line yields for the two
// consumers that read it with different tolerances. Holding both verdicts in one
// value is what lets a verify pass decode each line once rather than twice.
type recordDecode struct {
	// wellFormed is the LENIENT verdict: the line parsed as one complete JSON value
	// with no trailing data. It stays true for a line carrying an unknown top-level
	// field — such a record is still a record for counting and chain-state purposes,
	// even though it can never verify. The chain walk reads this one.
	wellFormed bool
	// verifyErr is the STRICT verdict: non-nil when the line is anything a verifier
	// must refuse — malformed JSON, trailing data, or an unknown top-level field.
	// verifyDecodedRecord reads this one, and reports it verbatim.
	verifyErr error
}

// decodeAuditRecord decodes one line into an auditRecord and reports both verdicts
// a verify pass needs (see recordDecode): the lenient "is this a record at all",
// which drives counting and chain state, and the strict "may this be verified",
// which drives the signature check.
//
// The two are deliberately different — a line with an unknown top-level field is a
// record the chain must account for AND a line no verifier may accept — but no line
// is ever decoded twice. The strict pass runs first and answers both questions on
// its own for every line except one shape: a record with no unknown field decodes
// identically under both tolerances (so the strict result IS the lenient one), and a
// line broken in any way a lenient decode would also reject is simply not a record.
// The unknown-field line is the sole case where the verdicts genuinely differ, and
// it alone pays the second decode — see strictRejectionIsFatal.
//
// wellFormed — NOT the returned record's contents — is what gates the chain. A
// rejected line comes back with the zero record, but the caller must key on the flag
// rather than on rec looking empty, or a shape that decodes partially would poison
// prevHMAC/prevSeq and fabricate spurious breaks.
func decodeAuditRecord(line []byte) (auditRecord, recordDecode) {
	rec, err := strictDecodeAuditRecord(line)
	if err == nil {
		return rec, recordDecode{wellFormed: true}
	}
	if strictRejectionIsFatal(err) {
		// Not a record under any tolerance, so there is nothing the lenient decode
		// could add: it would re-parse the same broken bytes to reach the same
		// verdict. Skipping it matters because a corrupted or attacker-padded archive
		// is precisely the log an incident responder runs this over — the case that
		// must not get slower than a single decode.
		return auditRecord{}, recordDecode{verifyErr: err}
	}
	// The strict pass refused an otherwise well-formed line for carrying an unknown
	// top-level field. That is still a record for counting and chain purposes, and
	// only a lenient decode can produce it — this is the one line shape in the log
	// that is parsed twice.
	lenient, wellFormed := lenientDecodeAuditRecord(line)
	return lenient, recordDecode{wellFormed: wellFormed, verifyErr: err}
}

// strictRejectionIsFatal reports whether a strictDecodeAuditRecord error means the
// line is not a well-formed JSON record at all — in which case a lenient decode is
// guaranteed to reject it too and is not worth running.
//
// The enumerated errors are the ones encoding/json raises for bytes that are not one
// complete JSON value, plus this package's own trailing-data rejection. Everything
// else — today, only the unknown-field rejection, which carries no sentinel of its
// own — falls through to the lenient decode. That default is the safe direction: an
// unrecognized error costs one extra decode of one line, whereas mistaking a
// still-decodable line for a fatal one would silently drop it out of the chain.
func strictRejectionIsFatal(err error) bool {
	var syntaxErr *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	return errors.Is(err, errTrailingRecordData) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, io.EOF) ||
		errors.As(err, &syntaxErr) ||
		errors.As(err, &typeErr)
}

// strictDecodeAuditRecord decodes one line into an auditRecord, refusing everything
// a verifier must refuse. It returns the ZERO record alongside any error, so a
// caller cannot accidentally build on a half-populated struct.
//
// DisallowUnknownFields rejects any top-level field the auditRecord struct does not
// model: the HMAC is recomputed over the re-marshaled struct, so a field the decode
// drops would not be covered by it (see verifyDecodedRecord). The disallowed set is
// derived from the struct tags automatically, so it cannot drift from auditRecord
// the way a hand-maintained field list would.
//
// UseNumber decodes any JSON number landing on an interface{} as json.Number (exact
// text) rather than float64, which cannot round-trip integers above 2^53. Details is
// a json.RawMessage (preserved verbatim, so unaffected) and no other auditRecord
// field is interface{}-typed, so this is currently a no-op — retained as a guard so a
// future interface{}/map field cannot silently break the decode→re-marshal round-trip.
func strictDecodeAuditRecord(line []byte) (auditRecord, error) {
	var rec auditRecord
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rec); err != nil {
		return auditRecord{}, fmt.Errorf("audit record is malformed or contains an unknown field: %w", err)
	}
	// Reject trailing bytes: Decode stops at the first value and ignores the rest, so
	// a tampered {…record…}GARBAGE line would otherwise verify (the HMAC covers the
	// re-marshaled fields, not the raw line). More() flags a trailing token. It is not
	// the only guard against a padded line — a stray closing brace slips past it, and
	// the canonical-form check is what rejects that — so this narrows the shapes that
	// reach verification rather than being the last word on them.
	if dec.More() {
		return auditRecord{}, errTrailingRecordData
	}
	return rec, nil
}

// errTrailingRecordData is strictDecodeAuditRecord's rejection of bytes after the
// record. It is a sentinel so strictRejectionIsFatal can recognize it (a line with
// trailing data is not a record under any tolerance); no caller branches on it
// otherwise, and it is reported like any other decode error.
var errTrailingRecordData = errors.New("trailing data after audit record")

// lenientDecodeAuditRecord decodes one line into an auditRecord, TOLERATING an
// unknown top-level field, and reports whether the line was well-formed JSON with
// no trailing data. It answers "is this a record at all" for counting and chain
// state — questions an unknown field does not change — and is never the decode a
// signature check is built on (see strictDecodeAuditRecord for why).
func lenientDecodeAuditRecord(line []byte) (auditRecord, bool) {
	var rec auditRecord
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	wellFormed := dec.Decode(&rec) == nil && !dec.More()
	return rec, wellFormed
}

// isSignedRecord reports whether rec carries a signature at all. writeRecord signs
// every record it writes unconditionally, so an HMAC-less line is never one this
// writer produced: it is pre-signing history, or a record whose signature was
// stripped by a write-capable attacker without the key. Neither can be certified, so
// callers treat both as INVALID and keep them out of the chain state.
//
// Single source of truth for this discriminator: BOTH shapes processLine derives —
// the unsigned gate and the seq-0 decoy gate — are expressed in terms of this
// function rather than re-deriving `rec.HMAC != ""`, so a future change to what a
// signed record looks like (an added decoy shape, a different empty sentinel) has one
// place to update and the two gates cannot end up disagreeing about the same record.
func isSignedRecord(rec auditRecord) bool {
	return rec.HMAC != ""
}

// processLine verifies one log line: it maintains the tamper-evident chain state
// across legitimate records (updateChain), then classifies and reports it.
func (v *auditChainVerifier) processLine(line []byte) {
	v.res.Total++
	rec, dec := decodeAuditRecord(line)

	// A Seq==0 record with a non-empty HMAC is structurally impossible (a signed chain
	// starts at seq 1), so it is a forged decoy, rejected below and kept out of the
	// chain state — adopting its seq 0 as prevSeq would fabricate a gap against the
	// next record and misreport where the tampering is.
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
	// Derived from `unsigned` below rather than re-testing rec.HMAC, so the two gates
	// share one definition of "signed" (see isSignedRecord).
	unsigned := !isSignedRecord(rec)
	forgedSeq0 := rec.Seq == 0 && !unsigned
	// An HMAC-less record is never one this writer produced (writeRecord signs
	// unconditionally): it is pre-signing history, or a signature a write-capable
	// attacker stripped — the one edit possible without the key. Both are INVALID, and
	// both are kept out of the chain state, because adopting an unsigned record's ""
	// prev_hmac and seq would let a deletion hide behind it (the next record links with
	// prev_hmac="" and the seq-gap check is suppressed). No seq shape is exempt: a
	// pre-signing record can carry any stale seq inherited from before the chain
	// existed, and none of them is certifiable.
	//
	// Chain verification runs over every decodable record (except the decoys above),
	// independent of the filter; the reporting filter is applied only afterward.
	// prev_hmac linkage and seq contiguity are checked as separate ifs, not switch
	// cases: an interior deletion trips BOTH, and a switch would emit only the first,
	// hiding how many records were removed.
	if dec.wellFormed && !forgedSeq0 && !unsigned {
		v.updateChain(rec)
	}
	v.classify(line, rec, dec, forgedSeq0, unsigned)
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
		// There is no exemption for an empty prev_hmac: writeRecord emits either the
		// resumed predecessor's _hmac or the genesis sentinel, never "", so an empty one
		// at seq 1 is always a leading-truncation forgery (delete the leading records,
		// rewrite the survivor to claim seq 1). The pre-signing upgrade path that once
		// produced a legitimately-empty prev_hmac here is gone — an unsigned tail is no
		// longer resumed onto, so a chain restarted after one begins at genesis like any
		// other fresh chain.
		if rec.Seq == 1 && rec.PrevHMAC != auditGenesisPrev {
			v.res.ChainBreaks++
			if rec.PrevHMAC == "" {
				_, _ = fmt.Fprintf(v.out, "CHAIN BREAK at seq 1: prev_hmac is empty, expected genesis sentinel %q — the writer never emits an empty prev_hmac, so leading records were deleted and a replacement was forged\n", auditGenesisPrev)
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
		if rec.PrevHMAC != v.prevHMAC {
			v.res.ChainBreaks++
			_, _ = fmt.Fprintf(v.out, "CHAIN BREAK at seq %d: prev_hmac does not match the preceding record (a record was deleted, reordered, or inserted)\n", rec.Seq)
		}
		// Every record reaching updateChain is signed and carries a seq > 0 (processLine
		// keeps unsigned records and seq-0 decoys out of the chain state), so the gap
		// check needs no era or zero-seq guard: consecutive records must simply be
		// contiguous.
		if rec.Seq != v.prevSeq+1 {
			v.res.ChainBreaks++
			_, _ = fmt.Fprintf(v.out, "SEQ GAP: record seq %d does not follow %d (a record is missing)\n", rec.Seq, v.prevSeq)
		}
	}
	v.havePrev = true
	v.prevHMAC = rec.HMAC
	v.prevSeq = rec.Seq
}

// reportSuppressedUnsigned prints the one-line tail summary for unsigned records whose
// individual diagnostics were capped (see maxUnsignedDiagnostics). It names the total so
// the elided lines are accounted for rather than silently dropped — the same posture the
// pre-session record limiter takes with suppressed_count — and repeats the remedy, since
// a log in this state is one an operator has to act on rather than re-run.
func (v *auditChainVerifier) reportSuppressedUnsigned() {
	if v.unsignedSeen <= maxUnsignedDiagnostics {
		return
	}
	_, _ = fmt.Fprintf(v.out,
		"INVALID  %d unsigned record(s) in total (%d diagnostics elided): none carries an _hmac, so none can be verified. Pre-signing history must be moved aside before upgrading; otherwise reconcile against your external sink.\n",
		v.unsignedSeen, v.unsignedSeen-maxUnsignedDiagnostics)
}

// reportMalformedTime emits the unparseable-`time` diagnostic on the arms that return
// before classify's own malformed-time case can run — UNKNOWN_KEY_ID and UNVERIFIABLE.
// The time field is signed and required, so an unparseable one is format drift or
// tampering on those records exactly as it is on an HMAC-valid one, and losing the signal
// because the record ALSO named a retired key hides two findings behind one.
//
// It deliberately counts nothing: the record is already tallied in its own bucket and the
// verdict already fails (OK() treats both as unverified), so adding to Invalid here would
// double-count one record. Diagnostic completeness only.
func (v *auditChainVerifier) reportMalformedTime(rec auditRecord, malformed bool) {
	if !malformed {
		return
	}
	_, _ = fmt.Fprintf(v.out, "         also: seq=%d has an unparseable time field %q (already counted above)\n",
		rec.Seq, SanitizeAuditField(rec.Time))
}

// classify counts and reports the record's verification outcome: malformed,
// forged decoy, unsigned, or HMAC-verified (valid/invalid/skipped per the filter).
func (v *auditChainVerifier) classify(line []byte, rec auditRecord, dec recordDecode, forgedSeq0, unsigned bool) {
	// A line that failed to decode cannot be filtered or HMAC-verified, but is
	// unambiguous corruption. Count it invalid before the filter so an active
	// --request-id/--since cannot downgrade it to a silent skip and produce a false
	// PASS over a corrupted log.
	if !dec.wellFormed {
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

	// An unsigned record carries nothing to verify. Treating one as merely skipped
	// would hand an attacker a trivial evasion — strip _hmac and the record stops
	// being checked — so it is INVALID, whatever its seq and wherever it sits in the
	// stream. Pre-signing history is the same shape and gets the same verdict: move
	// such a log aside before upgrading rather than expecting it to certify.
	// (unsigned is computed in processLine so classify stays a pure function of its
	// inputs.)
	//
	// The per-record diagnostic is CAPPED. A pre-signing log is precisely the case that
	// produces one of these per line, and an unbounded stream of them — a 1M-record log
	// emits well over a hundred megabytes — buries the genuine CHAIN BREAK or INVALID
	// findings an operator is reading for, which is how a fail-closed check ends up
	// suppressed with `|| true`. The Invalid COUNT stays exact; only the printing is
	// bounded, and the tail is summarized once at the end (see reportSuppressedUnsigned).
	if unsigned {
		v.res.Invalid++
		v.unsignedSeen++
		switch {
		case v.unsignedSeen <= maxUnsignedDiagnostics:
			_, _ = fmt.Fprintf(v.out, "INVALID  record %d: unsigned record (seq=%d) carries no _hmac, so it cannot be verified (pre-signing history, or a stripped signature)\n", v.res.Total, rec.Seq)
		case v.unsignedSeen == maxUnsignedDiagnostics+1:
			_, _ = fmt.Fprintf(v.out, "INVALID  ... further unsigned records reported once at the end rather than one line each\n")
		}
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

	// A line the strict decode refused is reported on that error alone: rec is the
	// LENIENT record in exactly that case (it is what the chain walk needed), and
	// handing it to the signature check would recompute the HMAC over a struct missing
	// the very field that made the line unverifiable. Otherwise rec is the strict
	// decode processLine already performed, reused so this pass decodes each line once.
	ok, err := false, dec.verifyErr
	if err == nil {
		ok, err = v.verifier.verifyDecodedRecord(line, rec)
	}
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
		v.reportMalformedTime(rec, malformedTime)
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
		v.reportMalformedTime(rec, malformedTime)
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
