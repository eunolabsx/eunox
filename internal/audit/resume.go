// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Crash-recovery of the audit log's tail: reading back the last complete record
// after a restart, truncating the partial fragment a non-clean shutdown can leave
// behind, deciding which line the chain resumes from (base tail, rotated sibling, or
// neither), verifying that line before chaining onto it, and — when it cannot be
// trusted — seeding the seq counter past every seq already on disk. Open drives all
// of it before the first append, so the chain either resumes from an intact record or
// fails closed with an in-band marker naming which of those steps failed.

package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"unicode"
)

// interpretAuditTail extracts the last COMPLETE record line from the bytes ReadAt
// produced, distinguishing the file-shrink race from a normal (possibly partial)
// read. Split out from readLastAuditLine so the race logic is unit-testable
// without staging a real TOCTOU on disk. size is the Stat size that sized the
// read; n/readErr are ReadAt's results.
//
// writeRecord terminates every record with a trailing newline, so a complete
// record always ends in '\n'. A non-clean shutdown (kill -9, power loss) can leave
// a partial in-progress write — bytes after the final newline with no terminating
// newline of their own. Returning that fragment as "the last record" would make
// Open fail to parse it and restart the chain from genesis, a spurious break even
// though the prior COMPLETE record is intact. So when the tail does not end in a
// newline, that trailing fragment is an incomplete write: skip it and return the
// last fully-written (newline-terminated) record instead. A genuinely corrupt
// COMPLETE record (newline-terminated but unparseable) is still returned as-is so
// Open's tailParseFailure path fires for it — only the newline-less fragment is
// dropped, preserving fail-closed semantics.
//
// For the ACTIVE log, Open also truncates that trailing fragment from disk (via
// truncatePartialTail) before the first append, so the orphan can never be
// concatenated onto by the next write. This in-memory skip therefore matters for
// read-only callers that never truncate (rotated-sibling resume) and as
// defense-in-depth between the truncation and the tail read.
func interpretAuditTail(buf []byte, n int, readErr error, size, start int64) (string, error) {
	// Stat reported size>0 but ReadAt returned zero bytes: the file was truncated to
	// empty (or shrank below the tail offset) between the two syscalls — a rotation
	// daemon racing a restart, or a stale NFS size cache. Reporting this as ("", nil)
	// would let the caller start a fresh chain and leave an unmarked gap, so return a
	// distinguishable error and let Open write an in-band marker.
	// A short read with io.EOF (n < len(buf), zero included) is a shrink: buf was sized
	// to exactly the bytes Stat reported, so fewer means truncation between Stat and
	// ReadAt. Processing buf[:n] would validate a stale or fragmentary record as the
	// tail and mask the shrink.
	//
	// One branch, not two: an n == 0 arm ahead of this one was a strict subset of it
	// (the caller guarantees len(buf) >= 1, so 0 < len(buf) always holds) differing
	// only in the wording of an error nothing branches on — two exits to keep in step
	// for one condition.
	if n < len(buf) && errors.Is(readErr, io.EOF) {
		return "", fmt.Errorf("audit tail read: file shrank from %d bytes (read %d of %d tail bytes) between stat and read: %w", size, n, len(buf), errAuditFileShrunk)
	}
	line, bounded := lastCompleteLineFromTail(buf[:n])
	if !bounded && line != "" && start != 0 {
		// The line begins at the window's first byte and the window did not begin at file
		// offset 0, so its LEADING boundary is outside the bytes in hand: what came back is
		// a record clipped at the window edge, not a record. This caller has no handle to
		// re-read through (the active-log path does, and re-anchors), so it fails closed
		// exactly as the whitespace case below does. Discarding bounded instead let a
		// rotated sibling's over-window newline-less tail through as a genuine record, which
		// then reads as unparseable and takes the DESTRUCTIVE genesis-restart branch — the
		// same input the active log refuses.
		return "", fmt.Errorf("%w (%d bytes scanned from offset %d, the last record's leading boundary is outside the window)", errAuditTailUnbounded, n, start)
	}
	if line == "" && start != 0 {
		// The entire tail window trimmed away as whitespace (a run of blank lines/spaces
		// filling the whole scan window) and the window did not begin at file offset 0: a
		// real record may sit further back than this window reaches. Reporting ("", nil)
		// here reads as "the file is empty," which for a rotated sibling means the caller
		// (newestRotatedSiblingWithTail) silently skips to an older sibling and the chain
		// resumes short of this file's actual seqs — a tamper-shaped duplicate-seq cascade
		// with no chain_resume_failed marker, the one tail anomaly the package's own
		// invariant says must never be silent. Fail closed exactly as the newline-less
		// overflow case does: the boundary cannot be located within the window.
		return "", fmt.Errorf("%w (%d bytes scanned from offset %d, entire window is whitespace)", errAuditTailUnbounded, n, start)
	}
	return line, nil
}

// lastCompleteLineFromTail extracts the last COMPLETE (newline-terminated) record
// from a tail window — the bytes of some file range [start, EOF). It is the single
// extraction rule shared by readLastAuditLine (which reads its own window) and the
// startup path (which reuses the window truncatePartialTail already read through the
// open append handle), so the two cannot drift on what "the last record" means.
//
// bounded reports whether the returned line's LEADING record boundary was inside the
// window. When false the line begins at the window's first byte, so it is the whole
// record only if the window started at file offset 0; a caller whose window started
// later must re-read anchored further back before trusting it.
func lastCompleteLineFromTail(buf []byte) (line string, bounded bool) {
	// Drop a trailing incomplete (newline-less) fragment before locating the last
	// record: such a fragment is a partial in-progress write left by a non-clean
	// shutdown, never a complete record (writeRecord always appends '\n'). Skipping
	// it here lets the chain resume from the last fully-written record instead of
	// treating the fragment as the tail and restarting from genesis. We only drop
	// the final unterminated run; any newline-terminated record (even a corrupt one)
	// is preserved so Open's parse/HMAC checks still see it.
	if i := bytes.LastIndexByte(buf, '\n'); i >= 0 {
		// buf[i+1:] is the run after the final newline. If it is non-blank, it is an
		// unterminated trailing fragment — discard it by truncating to the final
		// newline (inclusive), leaving only complete records.
		if len(bytes.TrimSpace(buf[i+1:])) > 0 {
			buf = buf[:i+1]
		}
	}
	// Trim ALL trailing whitespace (spaces, tabs, CR, blank lines), not only '\n':
	// a final line made of whitespace (an editor save, an `echo " " >>`, a Windows
	// CRLF artifact) is blank, so the fragment-drop above skips it, but a bytes.TrimRight
	// on "\n" alone would leave it — and the extraction below would then land on the
	// whitespace run and return "". readLastAuditLine's contract reserves ("", nil) for a
	// GENUINELY empty log; returning it for a non-empty log makes Open restart the chain
	// from genesis (reissuing existing seqs) or rewind to an older sibling — a tamper-
	// shaped duplicate-seq cascade, and the one tail anomaly that writes no marker. Trim
	// through the whitespace so the extraction lands on the last real record instead.
	trimmed := bytes.TrimRightFunc(buf, unicode.IsSpace)
	if i := bytes.LastIndexByte(trimmed, '\n'); i >= 0 {
		return string(bytes.TrimSpace(trimmed[i+1:])), true
	}
	return string(bytes.TrimSpace(trimmed)), false
}

// recoverWrittenSize recovers the byte count the rotation threshold resumes from on
// Open: the open handle's Stat size when available, else the pre-open probe size
// (continuing the counter for a large existing log without force-rotating a
// brand-new/empty one), else 0. The name reflects the job — a startup recovery of the
// persisted write counter via stat, not a fresh measurement.
//
// When BOTH stat calls fail (the size is genuinely unknown) the resume point is 0. An
// earlier version seeded the rotation size (== maxBytes) here, which made the very
// first writeRecord exceed the threshold and force an immediate, spurious rotation —
// restarting the HMAC chain and creating an empty rotated sibling — even on a
// brand-new or nearly-empty log, and on every restart under persistent I/O
// degradation. The invariant is that a failure-to-stat must behave no worse than an
// empty file: measuring up from 0 bounds this session's growth to maxBytes, instead
// of letting the size accounting be wrong in the direction that rotates needlessly.
func recoverWrittenSize(f *os.File, logPath string, preSize int64) int64 {
	info, statErr := f.Stat()
	switch {
	case statErr == nil:
		return info.Size()
	case preSize >= 0:
		fmt.Fprintf(os.Stderr, "[eunox] WARNING: could not stat open audit log %q: %v; using pre-open size %d\n", logPath, statErr, preSize)
		return preSize
	default:
		fmt.Fprintf(os.Stderr, "[eunox] WARNING: could not stat audit log %q: %v; resuming size accounting from 0 (no forced rotation)\n", logPath, statErr)
		return 0
	}
}

// recoverPartialTail truncates a trailing partial write via truncatePartialTail,
// logs the outcome, and returns the number of bytes recovered (0 on a clean tail).
// writeRecord ends every record with '\n', so trailing bytes without one were never
// a complete record and this never removes one.
//
// It distinguishes two failure modes by their consequence:
//
//   - A TRUNCATION failure (errAuditTailTruncate: a partial tail was found but ftruncate
//     was rejected — EROFS, quota, a transient kernel error) is FATAL: leaving the orphan
//     would let the first post-restart O_APPEND write concatenate onto it, fusing two
//     records into one line audit-verify reports as corruption. Failing Open is the
//     fail-closed direction — the operator fixes the filesystem rather than corrupting
//     the next record (this function exists precisely to prevent that fusion).
//
//   - A PROBE failure on a NON-EMPTY log (errAuditTailProbe: f.Stat or f.ReadAt failed
//     while the log holds bytes — an EIO blip, an NFS hiccup) is FATAL. "Could not check"
//     cannot rule out an orphan on a non-empty log, so proceeding would risk fusing the
//     first append onto a real partial record exactly as the truncation-failure case
//     would. Failing closed forces the operator to resolve the I/O fault rather than
//     silently corrupting the next record; the truncation path already takes this stance.
//
//   - Any OTHER read failure (the file is genuinely empty or absent, so there is no orphan
//     to fuse onto) does NOT block Open: a local audit-log read problem on an empty log
//     must not stop enforcement (the documented audit-failure tradeoff). truncatePartialTail
//     reports these as the empty/absent (0, nil) case, so they never reach this branch as an
//     error; a bare non-probe error here is treated conservatively as a warn-and-proceed.
func recoverPartialTail(logPath string, f *os.File, readable bool) (int64, tailResume, error) {
	if !readable {
		// The log was opened append-only because O_RDWR was refused (a deliberately
		// write-only 0200 log on a non-root process). Its tail cannot be read, so
		// partial-tail recovery is skipped: a non-clean shutdown on a write-only log falls
		// into the chain-resume-failed path rather than being recovered, and Open still
		// proceeds — the documented audit-failure tradeoff for an operator-chosen
		// unreadable log. A readable log instead probes the tail below and fails closed on
		// a transient read fault (errAuditTailProbe).
		//
		// Skip the warning for a genuinely empty log (e.g. just created by O_CREATE): no
		// orphan can exist there, so the warning would be alarming and always false. f.Stat
		// works on a write-only fd — fstat reads metadata, not the file contents.
		if info, statErr := f.Stat(); statErr == nil && info.Size() == 0 {
			// Nothing on disk to resume from, and nothing lost by not reading it: report a
			// readable (empty) tail so Open takes its ordinary brand-new-log path.
			return 0, tailResume{readable: true}, nil
		}
		fmt.Fprintf(os.Stderr, "[eunox] WARNING: audit log %q is write-only; a partial trailing write from a non-clean shutdown cannot be checked or recovered (its tail is unreadable) — run 'eunox audit-verify' if a crash is suspected\n", logPath)
		return 0, tailResume{readable: false}, nil
	}
	rb, last, err := truncatePartialTail(f)
	switch {
	case errors.Is(err, errAuditTailTruncate):
		return 0, tailResume{}, fmt.Errorf("could not recover a partial audit tail in %q: %w", logPath, err)
	case errors.Is(err, errAuditTailProbe):
		// The tail probe failed on a NON-EMPTY log. We could not establish that no orphan
		// partial record is present, and on a non-empty log we cannot assume there is none
		// — proceeding would let the first O_APPEND write fuse onto a still-present orphan.
		// Fail closed, like the truncation-failure path, rather than corrupt the next record.
		return 0, tailResume{}, fmt.Errorf("could not recover a partial audit tail in %q: %w", logPath, err)
	case errors.Is(err, errAuditTailUnbounded):
		// A trailing orphan larger than the scan window with no record boundary inside it:
		// its boundary cannot be located, so it cannot be safely truncated. Fail closed —
		// proceeding would fuse Open's parse-failure marker onto the multi-MiB orphan.
		return 0, tailResume{}, fmt.Errorf("could not recover a partial audit tail in %q: %w", logPath, err)
	case err != nil:
		// truncatePartialTail's contract returns only the wrapped sentinels handled above
		// or nil, so this is unreachable today. Fail CLOSED anyway (do not warn-and-proceed):
		// if a future change ever returns a bare error here, proceeding would reopen the
		// record-fusion window this function exists to close. An unrecognized error means we
		// could not establish the tail is clean, so refuse to start rather than fail open.
		return 0, tailResume{}, fmt.Errorf("could not check the audit tail of %q for a partial trailing write: %w", logPath, err)
	case rb > 0:
		fmt.Fprintf(os.Stderr, "[eunox] audit log %q: recovered a %d-byte partial trailing write left by a non-clean shutdown; resuming the chain from the last complete record\n", logPath, rb)
	}
	return rb, tailResume{last: last, readable: true}, nil
}

// tailResume is what the startup tail probe established about the existing log, read
// ONCE through the open append handle: the last complete record the chain resumes
// from, and whether the tail could be read at all.
//
// readable is false only for a log opened append-only because O_RDWR was refused (a
// deliberately write-only 0200 log under a non-root process). Its tail cannot be read,
// so the chain cannot be resumed from it and Open must fail that closed — seeding seq
// past the on-disk maximum and marking the break in-band — rather than restarting from
// genesis and reissuing every existing seq.
//
// last is "" when the log is genuinely empty (brand new, just rotated, or truncated
// whole by the partial-tail recovery); Open then falls back to the newest rotated
// sibling's tail. Every way the tail could NOT be established is already a fail-closed
// error from truncatePartialTail (errAuditTailProbe / errAuditTailTruncate /
// errAuditTailUnbounded), so "" here always means empty and never "unknown".
type tailResume struct {
	last     string
	readable bool
}

// errAuditTailTruncate marks a failure to ftruncate a partial tail that WAS found
// (the two f.Truncate calls below). recoverPartialTail fails Open closed on this error —
// a known-but-unremovable orphan would be fused onto by the next append.
var errAuditTailTruncate = errors.New("audit partial-tail truncation failed")

// errAuditTailProbe marks a failure of the tail PROBE (f.Stat or f.ReadAt) on a NON-EMPTY
// log: the file holds bytes but we could not read them to check for a trailing partial
// record. recoverPartialTail fails Open closed on this error — on a non-empty log "could
// not check" cannot rule out an orphan, so proceeding could fuse the next append onto a
// real partial record. The empty/absent log (no orphan possible) is reported as (0, nil),
// never this error, so the documented audit-failure tradeoff still lets enforcement start
// when the log is genuinely empty/unreadable-because-empty.
var errAuditTailProbe = errors.New("audit partial-tail probe failed")

// errAuditTailUnbounded marks a NON-EMPTY tail whose trailing partial write fills the
// entire scan window with no record boundary (newline) inside it: the last complete
// record's boundary cannot be located, so the orphan cannot be safely truncated
// (dropping the window could remove a complete record whose newline sits just before
// it). recoverPartialTail fails Open closed on it — leaving the orphan and proceeding
// would let Open's parse-failure marker O_APPEND directly onto the multi-megabyte
// orphan, fusing them into one physical line that trips bufio.ErrTooLong in audit-verify
// and buries the marker's HMAC.
var errAuditTailUnbounded = errors.New("audit partial-tail exceeds the scan window with no record boundary")

// truncatePartialTail removes a trailing partial record left by a non-clean
// shutdown (kill -9, power loss) so the next O_APPEND write begins at a clean
// record boundary instead of concatenating onto the orphan and producing a line
// that audit-verify cannot parse. writeRecord terminates every record with '\n',
// so trailing bytes without one were never a complete record and are safe to drop;
// a newline-terminated record (even a corrupt one) is left in place for Open's
// parse/HMAC checks. f is the append handle being readied (opened O_RDWR), and the
// tail is probed through this SAME handle (f.Stat/f.ReadAt) rather than a second
// read-only os.Open: a second open can fail transiently while a real orphan exists,
// and proceeding on that "could not check" would let the next append fuse onto the
// orphan. A probe failure on a NON-EMPTY log is therefore returned wrapped in
// errAuditTailProbe so recoverPartialTail fails Open closed rather than proceeding;
// an empty file (no orphan possible) returns (0, "", nil).
//
// It also returns the log's last COMPLETE record line, extracted from the very
// window it already read, so the startup chain-resume needs no second read of the
// same bytes. Reading the tail once through the held handle — rather than probing
// here and then re-opening the path read-only to fetch the resume line — is the
// whole point of taking O_RDWR above: the second open was a fresh syscall triple
// (open+Stat+ReadAt) with its own transient-failure and stat/read-shrink race
// modes, on bytes this function had already read under the exclusive audit lock.
// The line is "" when the log is (or has just become) empty.
//
// Returns the number of bytes truncated (0 when the tail already ends at a record
// boundary). Runs under the exclusive audit lock, before the drainer starts.
func truncatePartialTail(f *os.File) (truncated int64, last string, err error) {
	return truncatePartialTailWindowed(f, auditScanBufferBytes)
}

// truncatePartialTailWindowed is truncatePartialTail with the tail scan window injected,
// so a test can drive the window-boundary paths against a few dozen bytes instead of
// staging a multi-megabyte file. Mirrors highestSeqAcrossChainCapped / scanSeqContribution,
// which take their scan cap the same way and for the same reason. Production always passes
// auditScanBufferBytes.
func truncatePartialTailWindowed(f *os.File, winSize int64) (truncated int64, last string, err error) {
	info, err := f.Stat()
	if err != nil {
		// Stat failed on the open append handle. We cannot tell whether the log is empty
		// (no orphan) or non-empty (a possible orphan), so fail closed: an empty log is the
		// common brand-new case and would normally proceed, but here we cannot establish
		// emptiness, and a stat blip on a non-empty log must not let the next append fuse.
		return 0, "", fmt.Errorf("%w: stat: %v", errAuditTailProbe, err)
	}
	size := info.Size()
	if size == 0 {
		// Genuinely empty (e.g. just created by O_CREATE): no orphan can exist. This is the
		// documented audit-failure tradeoff's safe case — nothing to fuse onto.
		return 0, "", nil
	}
	// A record (plus its boundary newline) always fits in this window — details are
	// capped well below it — so the last newline, the boundary of the last complete
	// record, is always within the window when the file holds any complete record.
	start := tailWindowStart(size, winSize)
	buf := make([]byte, size-start)
	n, err := f.ReadAt(buf, start)
	if err != nil && err != io.EOF {
		// ReadAt failed on a NON-EMPTY log (size > 0 here): an orphan partial record may be
		// present and we could not look. Fail closed rather than proceed and risk a fused
		// next append.
		return 0, "", fmt.Errorf("%w: read: %v", errAuditTailProbe, err)
	}
	buf = buf[:n]
	if len(buf) == 0 || buf[len(buf)-1] == '\n' {
		// The tail ends at a record boundary: nothing to recover. buf is already the
		// window [start, EOF), so the resume line comes straight out of it.
		line, err := tailLineFromWindow(f, buf, start, size, winSize)
		if err != nil {
			return 0, "", err
		}
		return 0, line, nil
	}
	// The tail does not end in '\n': the bytes after the last newline are a partial
	// write. Drop them so the next append starts at a record boundary.
	i := bytes.LastIndexByte(buf, '\n')
	if i < 0 {
		if start > 0 {
			// A full window with no newline means a trailing run longer than the scan
			// window with no record boundary inside it (a single record over the detail
			// cap, or a corrupt/oversized orphan). The last complete record's boundary is
			// outside the window, so we cannot safely truncate — dropping the window could
			// delete a complete record whose newline sits just before it. Fail closed
			// rather than leave it: proceeding would let Open's tail_parse_failure marker
			// O_APPEND directly onto the multi-MiB orphan, fusing one physical line that
			// trips bufio.ErrTooLong in audit-verify and buries the marker's HMAC. The
			// operator must resolve the corrupt tail.
			return 0, "", fmt.Errorf("%w (%d bytes scanned from offset %d)", errAuditTailUnbounded, len(buf), start)
		}
		// The whole file is one newline-less partial record: drop it entirely. The log
		// is now empty, so there is no record to resume from.
		if err := f.Truncate(0); err != nil {
			return 0, "", fmt.Errorf("%w: %v", errAuditTailTruncate, err)
		}
		return size, "", nil
	}
	newSize := start + int64(i) + 1 // keep through the final newline (inclusive)
	if err := f.Truncate(newSize); err != nil {
		return 0, "", fmt.Errorf("%w: %v", errAuditTailTruncate, err)
	}
	// buf[:i+1] is now exactly the window [start, newSize) — the file's tail after the
	// truncation — so the resume line comes from the bytes already in hand.
	line, err := tailLineFromWindow(f, buf[:i+1], start, newSize, winSize)
	if err != nil {
		return 0, "", err
	}
	return size - newSize, line, nil
}

// tailWindowStart returns the offset a size-byte log's trailing win-byte scan window
// begins at: the last win bytes, or the whole file when it is shorter.
//
// One definition, because the three places that compute it must agree on what "the tail
// window" IS — the resume probe, the resume line re-read, and the seq-contribution scan.
// Drift between them would silently change which bytes each considers the tail, and the
// re-read's no-op short-circuit is stated in terms of the probe's answer.
func tailWindowStart(size, win int64) int64 {
	return max(0, size-win)
}

// tailLineFromWindow returns the last complete record of a log whose current size is
// size, given window — the bytes of the range [start, size) already read from f.
//
// It normally answers from window alone. It re-reads only in the one case where the
// window cannot answer: the last record has no leading boundary inside it AND the
// window did not begin at file offset 0, so the record started before the bytes in
// hand and returning it would hand Open a record clipped at the window edge (which
// then reads as an unparseable tail and restarts the chain from genesis). That can
// only happen after a truncation shortened the window, and the re-read is anchored at
// the new EOF through the SAME handle — never a second open. One re-read always
// suffices: the window now ends at a record boundary and a record is capped far below
// auditScanBufferBytes, so the preceding boundary is inside it unless the file holds
// exactly one record, in which case the window starts at 0 and is authoritative.
func tailLineFromWindow(f *os.File, window []byte, start, size, winSize int64) (string, error) {
	line, bounded := lastCompleteLineFromTail(window)
	if line == "" && start != 0 {
		// The whole window trimmed away as whitespace and the window did not begin at
		// file offset 0: re-reading with the same winSize would recompute the identical
		// start (tailWindowStart is a pure function of size and winSize, and size has not
		// shrunk in this call path), so it cannot resolve the ambiguity. A real record may
		// exist before this window; reporting "" would read as an empty log and silently
		// rewind the chain. Fail closed like the newline-less overflow case below.
		return "", fmt.Errorf("%w (%d bytes scanned from offset %d, entire window is whitespace)", errAuditTailUnbounded, len(window), start)
	}
	if bounded || start == 0 {
		return line, nil
	}
	reStart := tailWindowStart(size, winSize)
	// Re-read only when the truncation actually moved the window's start. reStart is
	// derived from the POST-truncation size, so when nothing was dropped it lands on the
	// same offset as start and the read returns the bytes already in hand — the same
	// answer, one syscall later. It can never land LATER than start: the file only shrinks.
	if reStart >= start {
		return line, nil
	}
	buf := make([]byte, size-reStart)
	n, err := f.ReadAt(buf, reStart)
	if err != nil && err != io.EOF {
		// Same stance as the probe failure above: on a non-empty log a read we cannot
		// complete must not be reported as a clean tail.
		return "", fmt.Errorf("%w: read: %v", errAuditTailProbe, err)
	}
	line, _ = lastCompleteLineFromTail(buf[:n])
	return line, nil
}

// errAuditFileShrunk reports that an audit log file was non-empty at Stat but returned
// zero bytes at ReadAt — truncated/rotated out between the two syscalls. Wrapped in
// readLastAuditLine's error so the caller can recognize the race; the sibling scan treats
// it like any other tail-read error.
var errAuditFileShrunk = errors.New("audit log shrank between stat and read")

// rescanBufferBytes is the WIDE per-line buffer scanSeqContribution uses on the
// chain-resume error path so its single pass reads PAST a record larger than the
// ~1 MiB cap, while still bounding memory: a line longer than this is refused rather
// than accumulated unbounded, so a corrupt or tampered log cannot drive the resume
// scan to OOM. Generous relative to the record cap, so any plausibly-large record is
// read, yet a hard ceiling on the one-shot startup allocation.
const rescanBufferBytes = 64 << 20

// tailFailure enumerates the mutually exclusive ways Open's tail-verification
// check (during resume) can fail, so the outcomes share one variable
// instead of independent bools that could (incorrectly) all be set.
type tailFailure int

const (
	tailFailNone tailFailure = iota
	tailFailHMACMismatch
	tailFailKeyUnknown
	// tailFailUnsigned: the tail carries no _hmac at all. Either a pre-HMAC log
	// written before signing existed, or a signed record whose signature was stripped
	// — indistinguishable from the record alone, and the second is the one splice a
	// write-capable attacker can make WITHOUT the key. It is therefore treated exactly
	// like an unparseable tail: the chain is not resumed onto it.
	tailFailUnsigned
	// tailFailUndecodable: the tail was refused by the strict decoder (malformed, an
	// unknown top-level field, or trailing bytes), so no HMAC comparison ever ran. It
	// restarts the chain exactly like a mismatch does; it is a distinct kind purely so
	// the marker on the tape names what actually happened.
	tailFailUndecodable
	// tailFailNonCanonical: the tail decoded to a well-formed record whose BYTES are not
	// what the writer emits for those fields (a duplicate, re-spelled or reordered key,
	// an added zero-valued field, an alternate escape, inserted whitespace). The canonical
	// check runs BEFORE any MAC is computed, so — exactly as for tailFailUndecodable — no
	// comparison ever ran, and it is its own kind so the marker does not assert one did.
	// It is deliberately NOT folded into tailFailUndecodable: that kind says the line
	// could not be READ, while this one says it read fine and was REWRITTEN, which is the
	// rewrite-a-signed-record attack rather than a malformed or forward-versioned line.
	tailFailNonCanonical
)

// highestSeqAcrossChain returns the seq the resumed counter must start past, computed
// across the base log AND every rotated sibling so a startup path that cannot trust the
// tail never reissues an existing seq. See highestSeqAcrossChainCapped for how unreadable
// files are folded in as a safe over-estimate. complete is false when the log directory
// could not be listed, so the rotated siblings' seqs are unknown and the returned value
// bounds only the base log — the caller must treat the seed as unbounded, not as a
// confident maximum.
func highestSeqAcrossChain(logPath string) (highest uint64, ok, complete bool) {
	return highestSeqAcrossChainCapped(logPath, rescanBufferBytes)
}

// highestSeqAcrossChainCapped is highestSeqAcrossChain with the per-line scan cap injected
// for deterministic tests. It over-estimates PAST the true
// on-disk max as: the highest seq actually READ anywhere in the chain (exact) PLUS the
// total BYTES of every file that could not be read. Each unread record occupies >= 1 byte,
// so the unread byte total bounds how many higher seqs an unreadable file can hold beyond
// the readable max; folding those bytes ADDITIVELY — rather than taking the max of per-file
// byte sizes, as scanning each file independently would — is what keeps a single rotated
// sibling's byte count from masquerading as a global seq. seq is monotonic across the WHOLE
// chain while each file's size is bounded by the rotation size, so after enough rotations
// (or with a small configured rotate size) the global seq exceeds any one file's byte size:
// the old per-file max then seeded BELOW the true max and reissued seqs. The additive fold
// seeds past the true max whenever ANY file in the chain is readable (the readable max is
// the anchor the unread bytes extend). The one residual — a chain whose files are ALL
// unreadable AND whose earlier history was pruned — cannot reconstruct the pruned records'
// seq span from the surviving bytes and may restart low, but always under a
// chain_resume_failed marker (the break is never silent). Like scanSeqContribution it never
// verifies HMACs or seeds prev_hmac; it only advances the monotonic counter. ok is false
// only when nothing — no parseable record and no unread bytes — was found anywhere on disk.
// complete is false when the log directory could not be listed at all: the fold then saw
// only the base log, so the result cannot be trusted as a chain-wide maximum.
func highestSeqAcrossChainCapped(logPath string, bufCap int) (highest uint64, ok, complete bool) {
	var maxParsed, unreadBytes uint64
	var parsedAny, sawUnread bool
	fold := func(path string) {
		p, parsed, ub := scanSeqContribution(path, bufCap)
		if parsed {
			parsedAny = true
			if p > maxParsed {
				maxParsed = p
			}
		}
		if ub > 0 {
			sawUnread = true
			unreadBytes = satAddU64(unreadBytes, ub)
		}
	}
	fold(logPath)
	// A directory-listing failure leaves only the base's contribution, which does NOT
	// bound the rotated siblings' seqs — the seed can land below the true on-disk maximum
	// and reissue history. Report it through complete so the caller surfaces the
	// uncertainty in-band instead of presenting a partial fold as a confident maximum.
	// A directory that does not exist yet is the ordinary fresh-install case (no siblings
	// to miss), so it stays complete.
	complete = true
	if sibs, err := sortedRotatedSiblings(logPath); err == nil {
		for _, sib := range sibs {
			fold(sib)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		// errors.Is, not os.IsNotExist: the latter does not unwrap, and this error comes
		// from a helper chain (sortedRotatedSiblings -> scanLogDir) that returns os.ReadDir's
		// raw *fs.PathError only by convention. The moment any layer adds context with %w,
		// a genuinely-absent directory would stop being recognized and every fresh install
		// would stamp seed_unbounded on the tape. rotate.go classifies the same error from
		// the same helper this way.
		complete = false
	}
	return satAddU64(maxParsed, unreadBytes), parsedAny || sawUnread, complete
}

// satAddU64 adds two uint64 values, saturating at the maximum rather than wrapping, so a
// pathologically large unread-byte total can never wrap the seed back down to a small value
// (which would then reissue existing seqs — the very failure the seed exists to prevent).
func satAddU64(a, b uint64) uint64 {
	if a > ^uint64(0)-b {
		return ^uint64(0)
	}
	return a + b
}

// seedSeqPastOnDiskMax advances s.seq past the highest seq already on disk (base +
// rotated siblings) so a chain that could not READ its tail — a write-only base, or a
// newest rotated sibling that could not be opened — restarts with a marker whose seq,
// and every record after it, is past every existing seq rather than restarting at genesis
// and reissuing them (a duplicate-seq cascade audit-verify cannot distinguish from
// tampering; the package's own scanSeqContribution comment calls a duplicate "WORSE than
// a gap"). It deliberately leaves s.prevHMAC at genesis: the break is real and
// audit-verify must see the prev_hmac discontinuity — only the seq counter is advanced,
// monotonic and gap-detectable. A best-effort scan finding nothing leaves s.seq unchanged
// (a genuinely unreadable log, already handled by the read-error seed path).
//
// It is deliberately NOT used by the paths where the tail WAS read but could not be
// trusted — a parse failure, an HMAC mismatch, a retired key, an unsigned tail. Those
// restart at genesis on purpose: the seqs on disk are then attacker-influenced (both the
// tail's own seq and, since highestSeqAcrossChain parses every line without verifying
// any, the maximum this function would find), so seeding from them would let a forged
// record inflate the counter. Trusting no on-disk seq is the fail-closed direction; the
// resulting duplicate seqs against the untrusted prefix are themselves a signal
// audit-verify surfaces. See resumeChainFromTail and the threat model's section 3.4.
//
// On the paths that DO use it, the folded values are still unverified — an unreadable
// tail is exactly the case where nothing can be verified — so what an unverified value
// must never do is inflate the counter to the point where the next `s.seq + 1` wraps back
// to 0 and reissues genesis. The seed is clamped to maxSeedableSeq for that, far above any
// reachable real history and far below the wrap. bounded is false when the fold could not
// see the whole chain, so the caller can mark the uncertainty on the tape rather than
// trusting a partial seed.
func (s *Sink) seedSeqPastOnDiskMax() (bounded bool) {
	highest, ok, complete := highestSeqAcrossChain(s.logPath)
	if ok && highest > maxSeedableSeq {
		// No real deployment reaches maxSeedableSeq records; a value this large is a
		// corrupt or planted seq, and honoring it would push the counter into the wrap
		// zone. Clamp and say so — the clamped seed still lands past every plausible
		// genuine record, so the monotonic guarantee holds for real history.
		fmt.Fprintf(os.Stderr, "[eunox] WARNING: audit log %q holds an implausible sequence number (%d); it is corrupt or planted. Seeding the resumed counter at %d instead — run 'eunox audit-verify' and reconcile against your external sink.\n", s.logPath, highest, maxSeedableSeq)
		highest = maxSeedableSeq
	}
	if ok && highest > s.seq {
		s.seq = highest
	}
	return complete
}

// maxSeedableSeq caps the value seedSeqPastOnDiskMax will adopt from unverified on-disk
// bytes. 2^62 is ~4.6e18 records — unreachable by any real log (millennia at a million
// records per second) — while leaving writeRecord's `s.seq + 1` two orders of magnitude of
// headroom below the uint64 wrap. Without the cap, a single planted
// {"seq":18446744073709551615} line seeds the counter at the maximum and the very next
// write reissues seq 0/1, which audit-verify cannot distinguish from tampering.
const maxSeedableSeq uint64 = 1 << 62

// tailResumeResult is resumeChainFromTail's report of how the existing tail
// record (if any) resolved: which integrity marker Open must write, and the
// seq/hmac a forensic reader needs to locate the record in question.
type tailResumeResult struct {
	tailFailKind     tailFailure
	tailParseFailure bool
	tailParseBytes   int
	tailSeq          uint64
	tailHMAC         string
}

// resumeChainFromTail parses and verifies last — the most recent existing audit
// record, or "" when the log is new/empty — and on success seeds s.seq/
// s.prevHMAC so the chain continues from it. Split out of
// Open to keep both functions under the complexity budget; the fields it
// mutates on s belong to a single-threaded Open (opt application has already
// run, the drainer has not started), so no locking is needed here either.
func (s *Sink) resumeChainFromTail(last string) tailResumeResult {
	if last == "" {
		return tailResumeResult{}
	}
	var prev auditRecord
	if err := json.Unmarshal([]byte(last), &prev); err != nil {
		// The tail did not parse as JSON (a partial write, power loss, or
		// corruption). The chain restarts from genesis (seq 1, sha256:genesis),
		// which audit-verify later reports as a break against the real prior
		// records on disk. Warn and mark it in-band: stderr alone is lost to
		// container log rotation and is not part of the tamper-evident trail, so
		// a deliberate truncation erasing a break would otherwise be silent. The
		// marker is written by the caller, chained from genesis.
		fmt.Fprintf(os.Stderr, "[eunox] WARNING: audit log tail failed to parse (%v); the last record may be truncated or corrupt. Restarting the chain from genesis — run 'eunox audit-verify' and reconcile against your external sink.\n", err)
		// Deliberately restart from genesis (seq 0), NOT past the on-disk max: the tail is
		// untrusted, and an attacker who appended a forged record with a chosen huge seq
		// must not be able to inflate the resumed counter (see the
		// IntegrityFailedTail_DoesNotInheritAttackerSeq guarantee). The resulting
		// duplicate-seq cascade against the real prior records is itself a tamper signal
		// audit-verify surfaces — the fail-closed choice here is to trust NO on-disk seq.
		return tailResumeResult{tailParseFailure: true, tailParseBytes: len(last)}
	}
	// An unsigned tail is never chained onto. Appending an unsigned record is the one
	// splice a write-capable attacker can make WITHOUT the signing key (truncate to a
	// chosen record, append an unsigned record as the new tail), so resuming from it
	// would seed seq/prev_hmac from bytes nothing certifies. A genuinely pre-HMAC log
	// is the same shape and gets the same treatment — restart the chain from genesis
	// and record the boundary in-band — so the migration is: move a pre-HMAC log aside
	// before upgrading, or accept a chain restart and a permanently INVALID prefix
	// (audit-verify counts every HMAC-less record invalid).
	if prev.HMAC == "" {
		fmt.Fprintf(os.Stderr, "[eunox] WARNING: audit log tail carries no _hmac, so it cannot be verified: either a pre-signing log or a record whose signature was stripped. The chain cannot be resumed and restarts from genesis — move a pre-signing log aside before upgrading, and run 'eunox audit-verify' plus a reconcile against your external sink otherwise.\n")
		return tailResumeResult{tailFailKind: tailFailUnsigned, tailSeq: prev.Seq}
	}
	// Verify the tail's HMAC before chaining onto it: otherwise an attacker who
	// truncates to a chosen record, or appends a crafted tail, seeds the resumed
	// seq/prev_hmac from unverified bytes.
	// Warn rather than abort so a corrupted local log does not block enforcement
	// (the documented audit-failure tradeoff).
	if ok, err := s.VerifyRecord([]byte(last)); err != nil || !ok {
		if errors.Is(err, errKeyIDNotInRing) {
			// The tail names a key_id absent from the verification ring — the
			// expected state right after a key rotation retired the signing key,
			// NOT evidence of tampering. Folding this into tail_hmac_mismatch
			// (below) would misdiagnose a routine rotation as a tamper event and
			// point the operator at the wrong remediation. Distinguish it with its
			// own marker and message instead.
			fmt.Fprintf(os.Stderr, "[eunox] WARNING: audit log tail was signed by a retired key no longer in the verification ring; this is expected immediately after a key rotation. The chain cannot be resumed and restarts from genesis — run 'eunox audit-verify' with the retired key still available to confirm the tail is intact.\n")
			return tailResumeResult{tailFailKind: tailFailKeyUnknown, tailSeq: prev.Seq, tailHMAC: prev.HMAC}
		}
		if errors.Is(err, errNonCanonicalRecord) {
			// The canonical-form check runs BEFORE any MAC is computed, so — like the
			// strict-decode refusal below — tail_hmac_mismatch would assert a comparison
			// that never ran, and point the operator at "a known key rejected this" when
			// what happened is that the bytes on disk are not the bytes the writer emits.
			// The chain still restarts from genesis; only the label differs.
			fmt.Fprintf(os.Stderr, "[eunox] WARNING: audit log tail is not in canonical on-disk form (a duplicate, re-spelled or reordered key, an added zero-valued field, an alternate escape, or inserted whitespace), so its signature was never checked: the record's bytes were rewritten after it was signed. The chain cannot be resumed and restarts from genesis — run 'eunox audit-verify' and reconcile against your external sink.\n")
			return tailResumeResult{tailFailKind: tailFailNonCanonical, tailSeq: prev.Seq, tailHMAC: prev.HMAC}
		}
		if errors.Is(err, errStrictDecodeRefused) {
			// The strict decoder refused the line, so VerifyRecord returned BEFORE
			// computing any MAC. Recording this as tail_hmac_mismatch asserted a
			// comparison that never ran and pointed the operator at a tampering
			// remediation for what is usually a malformed or forward-versioned record.
			// The chain still restarts from genesis — only the label differs.
			fmt.Fprintf(os.Stderr, "[eunox] WARNING: audit log tail could not be decoded for verification (malformed, an unknown field, or trailing bytes), so its signature was never checked. The chain cannot be resumed and restarts from genesis — run 'eunox audit-verify' and reconcile against your external sink.\n")
			return tailResumeResult{tailFailKind: tailFailUndecodable, tailSeq: prev.Seq, tailHMAC: prev.HMAC}
		}
		fmt.Fprintf(os.Stderr, "[eunox] WARNING: audit log tail failed HMAC verification; the last record may have been tampered with or truncated. The chain cannot be resumed and restarts from genesis — run 'eunox audit-verify' and reconcile against your external sink.\n")
		// Mark it in-band too (stderr is lost to log rotation and not in the
		// tamper-evident trail); the signed marker is written by the caller.
		return tailResumeResult{tailFailKind: tailFailHMACMismatch, tailSeq: prev.Seq, tailHMAC: prev.HMAC}
	}
	// A tape has exactly one writer at a time (Open holds the lock across the whole
	// process's life), so a VERIFIED tail naming a different enforcement point means this
	// file was written by another one before this process started: an instance renamed, or
	// two enforcement points pointed at one path in turn. Nothing about the chain is wrong
	// — it resumes normally, and because the stamp is per record rather than a file-level
	// header, the boundary stays legible on the tape with no marker to write — but the log
	// as a whole has stopped answering "which enforcement point produced this", and the
	// usual cause is a copied config, which is worth one line at startup. Only a tail that
	// NAMES one is compared: a tape predating the stamp, or written before the operator
	// configured one, is an ordinary first-time configuration, not a change.
	if prev.PEP != "" && prev.PEP != s.pep {
		// Rendered rather than %q'd straight: an unset stamp prints as an empty pair of
		// quotes, which reads as a name that is the empty string rather than as none.
		mine := "no enforcement point at all"
		if s.pep != "" {
			mine = fmt.Sprintf("%q", s.pep)
		}
		fmt.Fprintf(os.Stderr, "[eunox] WARNING: the audit log tail was written by enforcement point %q, but this instance stamps %s; the chain resumes normally and every record still names its own writer, but this log has stopped belonging to a single enforcement point — give each one its own audit.log, or reconcile the names.\n", prev.PEP, mine)
	}
	// Chain onto the tail only when it verified (handled above by returning
	// early on any failure). A failed tail is attacker-controllable (a
	// syntactically valid record with arbitrary seq/_hmac needs no signing key),
	// so seeding s.seq/s.prevHMAC from it would inject a fabricated seq jump and
	// chosen prev_hmac — that path already returned above, leaving seq 0/
	// prevHMAC "" so the chain restarts from genesis while the marker records
	// the event for forensics.
	s.seq = prev.Seq
	s.prevHMAC = prev.HMAC
	// Zero value: the struct's tail fields exist to tell a forensic reader WHICH record
	// a failure marker is about, and a clean resume writes no marker. Populating them
	// here would invite a later success-path diagnostic to read a field that is only
	// meaningful on the failure paths.
	return tailResumeResult{}
}

// startupResume is resolveStartupResume's report: which tail line the chain resumes
// from, and whether that resolution failed closed (so Open writes a chain_resume_failed
// marker) and whether the reseed it performed could see the whole chain.
type startupResume struct {
	last              string
	chainResumeFailed bool
	seedUnbounded     bool
	failReason        string
}

// resolveStartupResume decides which line the chain resumes from, handling the two ways
// that resolution can fail closed: an unreadable base tail, and an empty base whose newest
// rotated sibling is unreadable. Both seed the seq counter past the on-disk maximum rather
// than restarting at genesis, and both report chainResumeFailed so the caller marks the
// break in-band. Split out of Open to keep that function within the cyclomatic-complexity
// budget; it mutates s.seq through seedSeqPastOnDiskMax, which is safe because Open is
// single-threaded here (opt application has run, the drainer has not started).
func (s *Sink) resolveStartupResume(tail tailResume, logPath string) startupResume {
	r := startupResume{last: tail.last}
	switch {
	case !tail.readable:
		// A write-only (0200) log opened append-only: its tail cannot be read, so the
		// chain genuinely cannot be resumed. Restarting from genesis would renumber seq
		// from 1 and reissue every seq already on disk — a tamper-shaped duplicate-seq
		// cascade, worse than a gap — so seed past the highest seq anywhere in the chain
		// and mark the break in-band instead. prev_hmac stays the genesis sentinel: the
		// real tail could not be read, so the cryptographic link honestly cannot continue,
		// and the marker is the single break rather than a per-record one.
		r.seedUnbounded = !s.seedSeqPastOnDiskMax()
		r.chainResumeFailed = true
		r.failReason = auditReasonTailReadFailed
		fmt.Fprintf(os.Stderr, "[eunox] WARNING: could not read audit log tail of %q (the log is write-only, so its tail cannot be probed); the chain cannot be resumed and a chain_resume_failed marker is appended (seq continues past the on-disk maximum) — run 'eunox audit-verify' and reconcile against your external sink.\n", logPath)
	case r.last == "":
		// logPath is empty or absent: a brand-new install, a just-rotated base, or a
		// reopen-fallback that renamed the base away. In the latter two the chain
		// tail lives in the newest rotated sibling. Resuming from the empty base
		// would restart at genesis and silently orphan every prior record with no
		// detectable gap, so fall back to the sibling's tail and warn.
		sib, l, unreadableNewer := newestRotatedSiblingWithTail(logPath)
		switch {
		case sib != "":
			r.last = l
			fmt.Fprintf(os.Stderr, "[eunox] audit chain resumed from rotated file %q because the base log %q was empty on startup\n", sib, logPath)
		case unreadableNewer:
			// The newest rotated sibling exists but could not be read, so resuming from an
			// older one (or genesis) would reissue its seqs. Fail closed exactly as a base
			// read failure does: seed past the on-disk max and record the break in-band.
			r.seedUnbounded = !s.seedSeqPastOnDiskMax()
			r.chainResumeFailed = true
			r.failReason = auditReasonTailReadFailed
			fmt.Fprintf(os.Stderr, "[eunox] WARNING: the newest rotated audit sibling of %q could not be read; the chain cannot be safely resumed and a chain_resume_failed marker is appended (seq continues past the on-disk maximum) — run 'eunox audit-verify' and reconcile against your external sink.\n", logPath)
		}
	}
	return r
}

// readLastAuditLine returns the last non-blank line of an audit log file, reading only
// a bounded tail rather than scanning a large log.
//
// Its one caller is the rotated-sibling scan (newestRotatedSiblingWithTail): the ACTIVE
// log's tail is read through the already-open append handle at startup (see tailResume),
// which is what removed this function's original chain-resume role and the second open
// that came with it. The three-case contract below is still what that caller needs — an
// unreadable sibling must not be mistaken for an empty one — so it is stated, not
// inherited:
//
//   - ("", nil): the file is genuinely empty or absent — the chain resumes from a
//     rotated sibling or the genesis sentinel.
//   - ("", err): an I/O error (Stat/ReadAt failure on a present file, or the file
//     shrank to empty between the two — errAuditFileShrunk). The caller MUST NOT
//     treat this as empty: resuming from genesis on a non-empty log leaves an
//     unmarked chain gap. A MISSING file is reported as ("", nil), since absence
//     is the normal brand-new-install case.
//   - (line, nil): the extracted last record line.
func readLastAuditLine(path string) (string, error) {
	// Guarded like the other whole-file reads, and for a sharper reason than theirs: this
	// is Open's chain-resume path AND its callers walk rotated siblings found by a
	// directory scan, so a substituted path would otherwise seed the resumed chain from
	// attacker-chosen bytes — or, for a planted FIFO, block forever inside open(2).
	f, err := openDiscoveredAuditFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Absent file: the normal brand-new-install / freshly-rotated case, not an
			// I/O error. Report empty so the caller resumes from genesis or a sibling.
			return "", nil
		}
		// Every other refusal (including a non-regular substitution) is an unreadable
		// file, which the callers fail closed on rather than treating as empty.
		return "", err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if info.Size() == 0 {
		return "", nil
	}
	// Details is capped at 1 MiB and the envelope is far smaller, so a record (plus
	// its preceding boundary newline) is always captured within this tail. Sized from
	// auditScanBufferBytes rather than a second 4 MiB literal: the tail window and the
	// line-scan ceiling must agree, or a record one reader accepts is one the other
	// truncates.
	size := info.Size()
	start := tailWindowStart(size, auditScanBufferBytes)
	buf := make([]byte, size-start)
	n, err := f.ReadAt(buf, start)
	if err != nil && err != io.EOF {
		return "", err
	}
	return interpretAuditTail(buf, n, err, size, start)
}

// scanSeqContribution reads path once and separates the two distinct ways a file can inform
// the resumed seq counter, which callers combine differently:
//
//   - parsedMax/parsed: the largest seq actually decoded from a record (exact and
//     authoritative). parsed is false when the file opened and read cleanly but held no
//     parseable record (empty/blank/all-unparseable).
//   - unreadBytes: the file's byte size when it could NOT be fully read — the open was
//     refused (a write-only 0200 log fails EACCES on every restart; a symlinked path fails
//     under config.OpenNoFollow, same as every other audit-file open) or the scan aborted
//     on an over-cap line (bufio.ErrTooLong) or a mid-file read fault — so the true max is
//     unknown and bounded only by the byte count (>= 1 byte per record). Zero when the file
//     read cleanly to EOF.
//
// Returning (0, false) for an unreadable non-empty file would seed the counter at genesis
// (seq 1) and reissue every on-disk seq — a tamper-shaped duplicate-seq cascade, WORSE than
// a gap — so an unopenable file reports its stat(2) size instead (stat needs no read
// permission). It never verifies HMACs and never seeds prev_hmac: it only advances the
// monotonic seq counter, so an unsigned or forged on-disk record can at worst inflate the
// counter (harmless), never inject a trusted chain link.
func scanSeqContribution(path string, bufCap int) (parsedMax uint64, parsed bool, unreadBytes uint64) {
	// Refused for the same reason readLastAuditLine carries O_NOFOLLOW: this scan runs on
	// the resume path, so a substituted path would otherwise feed the counter from an
	// attacker-chosen file. A refusal takes the stat fallback below, which reports a size —
	// inflation only, which the seq fold already tolerates.
	f, err := openDiscoveredAuditFile(path)
	if err != nil {
		if info, statErr := os.Stat(path); statErr == nil {
			if sz := uint64(info.Size()); sz > 0 { //nolint:gosec // G115: file size is non-negative
				return 0, false, sz
			}
		}
		return 0, false, 0
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, min(64<<10, bufCap)), bufCap)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec auditRecord
		if json.Unmarshal(line, &rec) != nil {
			continue
		}
		parsed = true
		if rec.Seq > parsedMax {
			parsedMax = rec.Seq
		}
	}
	if scanner.Err() == nil {
		// Clean EOF: parsedMax is the confident true max; nothing was left unread.
		return parsedMax, parsed, 0
	}
	// The scan aborted — a line over the cap or a mid-file read fault — so parsedMax is only
	// a LOWER bound: a higher-seq record may sit beyond the offending line. Report the file
	// size as the unread over-estimate too, so the caller seeds past the on-disk maximum
	// rather than from an under-count (a duplicate seq reads as tampering; a gap only as
	// loss). This genuinely-undeterminable case is the only one that falls back to size.
	if info, statErr := f.Stat(); statErr == nil {
		if sz := uint64(info.Size()); sz > 0 { //nolint:gosec // G115: file size is non-negative
			return parsedMax, parsed, sz
		}
	}
	return parsedMax, parsed, 0
}
