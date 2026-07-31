// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Crash-recovery of the audit log's tail: reading back the last complete record
// after a restart, and truncating the partial fragment a non-clean shutdown can
// leave behind. Open drives all of it before the first append, so the chain either
// resumes from an intact record or fails closed with an in-band marker.
//
// Split out of audit.go verbatim (writer core), alongside rotate.go (rotation and
// retention) and verify.go (chain verification). No behavior change.

package audit

import (
	"bytes"
	"errors"
	"fmt"
	"io"
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
func interpretAuditTail(buf []byte, n int, readErr error, size int64) (string, error) {
	// Stat reported size>0 but ReadAt returned zero bytes: the file was truncated to
	// empty (or shrank below the tail offset) between the two syscalls — a rotation
	// daemon racing a restart, or a stale NFS size cache. Reporting this as ("", nil)
	// would let the caller start a fresh chain and leave an unmarked gap, so return a
	// distinguishable error and let Open write an in-band marker.
	if n == 0 && errors.Is(readErr, io.EOF) {
		return "", fmt.Errorf("audit tail read: file shrank from %d bytes between stat and read: %w", size, errAuditFileShrunk)
	}
	// A partial read with io.EOF (0 < n < len(buf)) is also a shrink: buf was sized
	// to exactly the bytes Stat reported, so fewer means truncation between Stat and
	// ReadAt. Processing buf[:n] would validate a stale or fragmentary record as the
	// tail and mask the shrink, so treat it like the n==0 case.
	if n < len(buf) && errors.Is(readErr, io.EOF) {
		return "", fmt.Errorf("audit tail read: file shrank from %d bytes (read %d of %d tail bytes) between stat and read: %w", size, n, len(buf), errAuditFileShrunk)
	}
	line, _ := lastCompleteLineFromTail(buf[:n])
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
	if bounded || start == 0 || line == "" {
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
