// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Audit-log rotation: size-triggered rename, retention pruning, and rotated-sibling naming.

package audit

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// rotateBackoffWritten returns the value rotate() backs s.written off to after a
// failed rotation: maxBytes minus ~10% headroom, so the next record does not
// immediately re-trigger rotation (which under a persistent fault would spin a
// per-record rename loop). The 1-byte floor matters because maxBytes/10 == 0 for
// any rotateSizeBytes < 10, which would otherwise leave zero headroom.
func (s *Sink) rotateBackoffWritten() int64 {
	// A zero-or-negative maxBytes carries no meaningful threshold to back off from;
	// returning maxBytes-headroom would underflow to a negative s.written (e.g. -1 for
	// maxBytes==0), which makes the size check (s.written+n > s.maxBytes) true for
	// every subsequent record and spins a per-record rotation loop. Open() floors
	// maxBytes to a positive default so this is unreachable in production, but a
	// directly-constructed Sink can hit it; fail safe to "start fresh" (0) instead.
	if s.maxBytes <= 0 {
		return 0
	}
	headroom := s.maxBytes / 10
	if headroom < 1 {
		headroom = 1
	}
	return s.maxBytes - headroom
}

// rotatedAuditRe matches the suffix rotatedPath() appends: a leading "." then an
// OPTIONAL fixed-width 20-digit rotation ORDINAL — not the chain seq, from which it is
// deliberately decoupled (seq resets to genesis on tail corruption; the ordinal never
// does; see rotatedOrderLess) — the nanosecond UTC layout
// "20060102T150405.000000000Z", and an optional ".N" collision backstop. The
// seq-prefixed form is the current scheme; the seq-less form is a pre-upgrade
// legacy sibling (see rotatedOrderLess). Used to retain only genuine rotated
// siblings. MUST stay in lockstep with rotatedPath's format string, or pruning
// silently matches nothing.
var rotatedAuditRe = regexp.MustCompile(`^\.(\d{20}\.)?\d{8}T\d{6}\.\d{9}Z(\.\d+)?$`)

// rotatedOrderLess orders two rotated siblings (sharing the prefix logPath) in
// write/chain order. The ordering key is the rotation ordinal embedded in the name
// (rotatedPath stamps each rotated file with a dedicated per-rotation counter): the
// ordinal is monotonic and clock-independent — it advances by one per rotation and is
// seeded past the highest existing sibling across restarts — so ordering by it
// follows the true rotation order regardless of any wall-clock step (an NTP
// correction, VM migration, or manual clock set moving time BACKWARD between two
// rotations would otherwise mis-order the wall-clock-timestamped names, so
// retention could delete the newer file and cross-file verification could trip
// a spurious CHAIN BREAK / SEQ GAP). The ordinal is DECOUPLED from the chain seq on
// purpose (seq resets to genesis on tail corruption; the ordinal never does). The
// wall-clock timestamp is retained in the name for operator readability only and serves
// as a tiebreak. A legacy (pre-upgrade, ordinal-less) sibling predates any
// ordinal-stamped one, so it holds older records and orders first; among legacy
// siblings the old timestamp-then-collision order is preserved.
func rotatedOrderLess(a, b, logPath string) bool {
	ordA, hasA, tsA, nA := rotatedStampParts(a, logPath)
	ordB, hasB, tsB, nB := rotatedStampParts(b, logPath)
	// Prefer the monotonic rotation ordinal whenever both names carry it (current scheme).
	if hasA && hasB && ordA != ordB {
		return ordA < ordB
	}
	// Exactly one legacy (ordinal-less) name: it predates the naming upgrade and holds
	// older records, so it orders first.
	if hasA != hasB {
		return hasB
	}
	// Both legacy, or an (unreachable in normal operation) equal ordinal: fall back to
	// the wall-clock timestamp base, then the numeric collision suffix.
	if tsA != tsB {
		return tsA < tsB
	}
	return nA < nB
}

// rotatedStampParts splits a rotated sibling path into its embedded rotation ordinal
// (present only in the current scheme), its Z-stamped timestamp base (through the
// trailing "Z"), and the integer ".N" collision suffix (0 when absent or
// unparseable). hasOrdinal is false for a legacy (pre-upgrade, ordinal-less) name. name
// is expected to begin with logPath; a name without a "Z" (an unrelated sibling)
// returns its whole remaining suffix as the timestamp base with ordinal 0 / N 0,
// keeping it deterministically ordered without affecting the entries callers act on.
func rotatedStampParts(name, logPath string) (ordinal uint64, hasOrdinal bool, tsBase string, n int) {
	suffix := name
	if strings.HasPrefix(name, logPath) {
		suffix = name[len(logPath):]
	}
	rest := suffix
	if rest != "" && rest[0] == '.' {
		rest = rest[1:]
	}
	// Optional leading fixed-width 20-digit ordinal field ("<20 digits>."). The legacy
	// timestamp's first '.' falls at offset 15 ("20060102T150405."), so a legacy name
	// never presents 20 leading digits followed by '.'; ParseUint double-guards it.
	if len(rest) >= 21 && rest[20] == '.' {
		if v, err := strconv.ParseUint(rest[:20], 10, 64); err == nil {
			ordinal = v
			hasOrdinal = true
			rest = rest[21:]
		}
	}
	zi := strings.IndexByte(rest, 'Z')
	if zi < 0 {
		return ordinal, hasOrdinal, rest, 0
	}
	tsBase = rest[:zi+1]
	tail := rest[zi+1:] // "" or ".<N>"
	if len(tail) > 1 && tail[0] == '.' {
		if v, err := strconv.Atoi(tail[1:]); err == nil {
			n = v
		}
	}
	return ordinal, hasOrdinal, tsBase, n
}

// scanLogDir reads logPath's directory ONCE and splits that single snapshot into every
// regular file sharing the "<base>." prefix (returned as full paths) and whether the
// active base itself was present in the SAME read.
//
// The single read is load-bearing for LogChainFiles, not just an optimization. A
// glob-then-stat decomposition (list siblings at T1, stat the base at T2) has a TOCTOU
// gap: a rotate() landing between T1 and T2 renames the base to a new sibling and opens
// a fresh empty base, so the result would carry the empty base but omit the just-rotated
// sibling holding every record up to the rotation boundary — and audit-verify would PASS
// on an incomplete chain. os.ReadDir is a single directory read, atomic against a
// concurrent rotate() w.r.t. the kernel's directory view: a rotation completing before
// the read shows the new rotated name; one completing after still shows the original
// base. Either way no file falls through the gap.
//
// Only regular files participate. A directory or symlink named like a rotated log would
// otherwise reach pruneRotated (os.Remove fails on a non-empty dir, or burns a retention
// slot on an empty one) or newestRotatedSiblingWithTail (os.Open succeeds on a dir but
// Read fails, breaking the chain). The rotatedAuditRe name filter is applied one level
// up, in sortedRotatedSiblingsWithBase, so the siblings returned here are only
// prefix-matched, not yet confirmed to be genuine rotated names.
//
// The scan is a literal os.ReadDir + HasPrefix rather than filepath.Glob: a logPath
// carrying glob metacharacters would make Glob match unrelated files, miss siblings, or
// return ErrBadPattern that callers treat as "no matches". Each sibling is reconstructed
// as logPath + <suffix> so it carries an exact logPath prefix, which rotatedAuditRe and
// rotatedStampParts rely on.
func scanLogDir(logPath string) (siblings []string, hasActive bool, err error) {
	dir := filepath.Dir(logPath)
	base := filepath.Base(logPath)
	prefix := base + "."
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, false, err
	}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		name := e.Name()
		if name == base {
			hasActive = true
			continue
		}
		if strings.HasPrefix(name, prefix) {
			siblings = append(siblings, logPath+name[len(base):])
		}
	}
	return siblings, hasActive, nil
}

// sortedRotatedSiblings returns logPath's genuine rotated siblings
// ("<logPath>.<ordinal>.<timestamp>Z"), filtered and ordered by the monotonic rotation
// ordinal (timestamp base only as a legacy tiebreak), then numeric collision suffix.
// The filter drops unrelated "<base>." names (audit.jsonl.bak, .lock, ...) so they
// can't seed the resumed chain or burn a retention slot.
func sortedRotatedSiblings(logPath string) ([]string, error) {
	files, _, err := sortedRotatedSiblingsWithBase(logPath)
	return files, err
}

// sortedRotatedSiblingsWithBase is sortedRotatedSiblings plus whether the active base
// was present in the same directory read. Only LogChainFiles needs the second value,
// and it needs it from THIS read (see scanLogDir's TOCTOU note).
func sortedRotatedSiblingsWithBase(logPath string) (rotated []string, hasActive bool, err error) {
	all, hasActive, err := scanLogDir(logPath)
	if err != nil {
		return nil, false, err
	}
	// [:0:0] shares none of all's backing array, so the first append allocates fresh.
	files := all[:0:0]
	for _, m := range all {
		if rotatedAuditRe.MatchString(m[len(logPath):]) {
			files = append(files, m)
		}
	}
	// Numeric-aware order so a ".10" suffix sorts after ".2", not before it.
	sort.Slice(files, func(i, j int) bool {
		return rotatedOrderLess(files[i], files[j], logPath)
	})
	return files, hasActive, nil
}

// newestRotatedSiblingWithTail walks logPath's rotated siblings newest-to-oldest and
// returns the first whose last line is readable and non-empty, along with that line.
//
// An EMPTY sibling (readable, no content — the empty rotated file an empty-base rotate()
// guards against, or one left by a race with an in-progress rotation) is skipped: it
// holds no seqs, so resuming from an older non-empty sibling loses nothing.
//
// An UNREADABLE newer sibling (a permission/IO error) is NOT skipped: it may hold higher
// seqs than any older sibling, so silently rewinding to the older one would reissue the
// unreadable file's seqs — a duplicate-seq cascade audit-verify cannot tell from
// tampering. The walk stops and returns unreadableNewer=true so the caller fails closed
// (seed past the on-disk max + write a chain_resume_failed marker) instead of rewinding.
// This is the same fail-closed stance Open takes for an unreadable BASE log.
//
// Returns ("", "", false) when no sibling has a usable tail and none was unreadable and the
// directory listed cleanly. An unreadable sibling FILE, or a log directory that cannot be
// LISTED at all (any error other than a not-yet-created one), returns ("", "", true) so the
// caller fails closed. Used by Open's empty-base chain-resume path.
func newestRotatedSiblingWithTail(logPath string) (path, line string, unreadableNewer bool) {
	files, err := sortedRotatedSiblings(logPath)
	if err != nil {
		// A log directory that does not exist yet is the ordinary fresh-install case (no
		// siblings): pass through. Any OTHER listing error (a permission bit, EIO, NFS
		// ESTALE, or the parent not being a directory) means we cannot rule out a newer
		// sibling holding higher seqs, so fail closed exactly as an unreadable sibling FILE
		// does below — the empty-base caller then seeds past the on-disk max and writes a
		// chain_resume_failed marker instead of silently rewinding to genesis and reissuing
		// seqs with no marker.
		if errors.Is(err, fs.ErrNotExist) {
			return "", "", false
		}
		return "", "", true
	}
	for i := len(files) - 1; i >= 0; i-- {
		l, lerr := readLastAuditLine(files[i])
		if lerr != nil {
			// A newer sibling we cannot read: do not skip to an older one, fail closed.
			return "", "", true
		}
		if l != "" {
			return files[i], l, false
		}
	}
	return "", "", false
}

// LogChainFiles returns the files carrying the tamper-evident chain for logPath, in
// verification order: every genuine rotated sibling oldest-first, then the current
// base log last. The chain is continuous across rotation (rotate() threads seq and
// prev_hmac in memory), but the cross-file link is only checked when the files are
// verified as one stream — verifying the base alone cannot detect deletion of an
// entire interior rotated file. Used by audit-verify (via VerifyLogFiles) to catch
// that gap.
//
// Only existing regular files are returned: a just-rotated base (absent logPath,
// siblings present) still yields the sibling chain; a fresh install yields an empty
// slice. Siblings are filtered with rotatedAuditRe and ordered as elsewhere; the
// base sorts last (rotation renames the active file and opens a fresh base), so the
// order matches the write order across rotations.
func LogChainFiles(logPath string) ([]string, error) {
	// One directory read backs both halves: the ordered rotated siblings AND whether
	// the active base exists. Splitting them into two scans would reopen the TOCTOU gap
	// scanLogDir documents, where a rotation landing between them yields the fresh empty
	// base without the sibling holding every record up to the rotation boundary.
	files, hasActive, err := sortedRotatedSiblingsWithBase(logPath)
	if err != nil {
		return nil, err
	}
	// The base sorts last: rotation renames the active file and opens a fresh one, so
	// appending it matches the write order across rotations. It is omitted when absent —
	// after a reopen-fallback it can be briefly missing (tail in the newest sibling), and
	// a fresh install has none yet.
	if hasActive {
		files = append(files, logPath)
	}
	return files, nil
}

// swapToFreshBase completes a rotation once a fresh base log f has been opened,
// running the tail that rotate() (clean rotation) and retryRotateReopen() (fallback
// recovery) share so it cannot drift between them: it tightens the new file's mode,
// closes the old fd, swaps f in as the active writer, resets the write counter and
// active path to the configured base, and prunes old siblings.
//
// The caller MUST have synced the old fd first — the sync-before-open ordering is
// load-bearing (see rotate()) — and clears any fallback state it owns
// (retryRotateReopen resets s.inFallback before calling in). tightenLogMode drops any
// group/world access defensively, in case something recreated logPath in the
// rename->open window. A Close failure on the old fd is recorded (not discarded):
// rare after a successful Sync, but possible on some filesystems, and tracking it
// keeps AuditDegraded() accurate, matching Close's treatment of the same operation.
// closeErrContext labels that stderr line so each caller keeps its own provenance
// ("rotated fd" vs "fallback fd").
func (s *Sink) swapToFreshBase(f *os.File, closeErrContext string) {
	tightenLogMode(f, s.logPath)
	if cerr := s.f.Close(); cerr != nil {
		s.writeFailures.Add(1)
		fmt.Fprintf(os.Stderr, "[eunox] audit rotate error (close of %s): %v\n", closeErrContext, cerr)
	}
	s.f = f
	s.activePath = s.logPath
	s.written = 0
	s.pruneRotated()
}

// openGuardedAppend opens logPath for append (creating it if absent), refusing a path
// that exists but is NOT a regular file. os.OpenFile follows a symlink and would append
// the tamper-evident tape straight through it; worse, a symlinked active log is silently
// dropped from LogChainFiles' IsRegular() scan, so audit-verify would PASS without
// reading a single live record. This mirrors the startup guard in openAndPrepareLog for
// the two post-rotation reopen sites, where a symlink planted in the rename->reopen
// window would otherwise be followed for the rest of the process. Lstat inspects the
// path itself, not its target; a missing path is the ordinary post-rename case and
// passes through to O_CREATE. On refusal the caller takes its existing reopen-failure
// fallback (keep the renamed fd, retry later), the fail-closed direction.
func openGuardedAppend(logPath string) (*os.File, error) {
	if err := refuseNonRegular(logPath); err != nil {
		return nil, err
	}
	// openNoFollow (O_NOFOLLOW on unix) closes the Lstat->open race the guard above
	// cannot; the rename->reopen window is exactly where a planted symlink would land.
	return os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY|openNoFollow, 0o600) //nolint:gosec // G304: path is user-configured audit log location
}

// refuseNonRegular fails closed unless logPath is a regular file or genuinely absent. It is
// the single implementation of the audit-log symlink/non-regular open guard, shared by the
// startup open (openAndPrepareLog) and the two post-rotation reopen sites (via
// openGuardedAppend) so a change to the check cannot leave one site weaker than the other.
// os.OpenFile FOLLOWS a symlink, so opening the log through one would redirect the
// tamper-evident tape AND drop the live log out of LogChainFiles' IsRegular() scan —
// audit-verify would then PASS without reading a single record. Only a genuinely-absent
// path (fs.ErrNotExist) is let through: the ordinary fresh-install and post-rename case
// O_CREATE then fills. Any OTHER Lstat error (EIO, NFS ESTALE, ELOOP, EACCES on a path
// component) is REFUSED, not assumed benign — gating the refusal on "stat succeeded" would
// let a stat fault skip the check and follow a symlink, the fail-OPEN direction this guard
// exists to prevent. Lstat inspects the path itself, not its target. A Lstat->open TOCTOU
// remains (a symlink planted between this check and the open is still followed); closing it
// fully needs O_NOFOLLOW-level atomicity, not portable here, so this guard closes the
// steady-state and stat-error holes while the caller keeps the rename->reopen window narrow.
func refuseNonRegular(logPath string) error {
	fi, statErr := os.Lstat(logPath)
	if statErr != nil {
		if errors.Is(statErr, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("refusing audit log path %q: cannot stat it (%v); refusing a path that may be a symlink or other non-regular file", logPath, statErr)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("refusing a non-regular log path %q (mode %v): the audit log must be a regular file, not a symlink or other special file", logPath, fi.Mode())
	}
	return nil
}

func (s *Sink) rotate() {
	if s.f == nil {
		return
	}
	// Already in the reopen-fallback state: a prior rotation renamed the log but could
	// not open a fresh base, so the fd is appending to the renamed (already-rotated,
	// over-size) file. Renaming it AGAIN on every size trigger would churn a fresh
	// sibling per ~maxBytes and never reclaim space — the fd keeps the same inode, so
	// the only way out is a successful reopen. Retry just the reopen here, on a bounded
	// cadence, instead of renaming. Checked BEFORE the written==0 guard below: the
	// fallback file is never empty (it already holds everything written before the
	// failed reopen), even though rotateBackoffWritten's in-memory accounting can back
	// off to 0 for a very small maxBytes — that must still retry the reopen, not be
	// mistaken for a fresh empty base.
	if s.inFallback {
		s.retryRotateReopen()
		return
	}
	// A record whose serialized line alone exceeds maxBytes trips the size trigger
	// (s.written+len(line) > s.maxBytes) while s.written is still 0 on a freshly
	// opened base. Renaming an empty file would create a spurious zero-byte rotated
	// sibling that carries the newest timestamp, letting pruneRotated evict a real
	// historical sibling to keep it. Nothing to rotate; leave the empty base in
	// place for the oversized record to land in.
	if s.written == 0 {
		return
	}
	// Rename first (non-destructive), then open the new file. The old fd stays valid
	// after rename (the inode is still open), so we can fall back to it if reopen
	// fails — records are not lost — and only close it once the new one opens.
	// rotatedPath returns a target that does not yet exist (so os.Rename cannot
	// silently clobber a same-second sibling) and bases its suffix on logPath, so
	// rotated files are always "<base>.<ts>" regardless of any earlier fallback.
	rotated, pathErr := s.rotatedPath()
	if pathErr != nil {
		// No collision-free name found. Fail closed like the rename branch: keep the
		// existing fd and back off rather than risk clobbering a sibling.
		fmt.Fprintf(os.Stderr, "[eunox] audit rotate error (target): %v; continuing with existing file\n", pathErr)
		s.written = s.rotateBackoffWritten()
		return
	}
	// Rename activePath (the file the fd actually writes to), which differs from
	// logPath only after a prior fallback; logPath would be "source missing" then.
	if err := os.Rename(s.activePath, rotated); err != nil {
		fmt.Fprintf(os.Stderr, "[eunox] audit rotate error (rename): %v; continuing with existing file\n", err)
		// Back off by ~10% rather than resetting to 0: resetting meant the file had
		// to grow a full maxBytes before retrying, so under a persistent fault the log
		// grew ~maxBytes per failure. This still avoids a tight loop but caps growth
		// to ~10% of maxBytes per failed attempt.
		s.written = s.rotateBackoffWritten()
		return
	}
	// Sync the rotated file BEFORE opening the new one. Close does not fsync on
	// Linux, so a crash could otherwise leave the rotated file missing its tail — an
	// undetectable chain gap, since the HMAC-linked successor lives in the new file.
	// The sync must precede OpenFile: with it after, a crash between creating the
	// empty logPath and the sync leaves an empty logPath while the rotated tail is
	// still in the page cache, so restart falls back to the sibling and trips a
	// tail_hmac_mismatch (permanent loss). Syncing first leaves the rotated file
	// durable and no logPath, so restart resumes cleanly. s.f is not closed until
	// OpenFile succeeds, so it stays valid (now synced) on reopen failure. A sync
	// failure is logged, not fatal.
	if err := s.f.Sync(); err != nil {
		// A failed fsync means the rotated sibling's tail may not be durable on disk. Do
		// NOT proceed to reopen+swap: swapToFreshBase closes this fd for good (Close does
		// not fsync on Linux), so a crash would permanently drop the un-synced tail and
		// leave a tamper-shaped chain gap at the rotation boundary — the HMAC-linked
		// successor lives in the fresh base. Instead enter the reopen-fallback state,
		// keeping this fd as the active path so retryRotateReopen re-Syncs it on the
		// bounded backoff cadence and only completes the swap once the tail is durable.
		// Account for it in writeFailures so the degradation stays visible to operators.
		s.writeFailures.Add(1)
		fmt.Fprintf(os.Stderr, "[eunox] audit rotate error (sync): %v; deferring reopen until the rotated tail is durable\n", err)
		s.activePath = rotated
		s.inFallback = true
		s.written = s.rotateBackoffWritten()
		s.pruneRotated()
		return
	}
	f, err := openGuardedAppend(s.logPath)
	if err != nil {
		// Reopen failed; fall back to the renamed fd (valid and already synced).
		// Point activePath at it so the next rotation renames it, but keep logPath as
		// the configured base so pruneRotated still matches every sibling and a
		// recovered rotation returns to the base path shippers and resume expect.
		fmt.Fprintf(os.Stderr, "[eunox] audit rotate error (reopen): %v; falling back to renamed file %q\n", err, rotated)
		s.activePath = rotated
		s.inFallback = true
		// Back off rather than reset to 0. Resetting under-counted the renamed file
		// (which already holds ~maxBytes) by a full maxBytes, so it was allowed to grow
		// to ~2x maxBytes before the next rotation even checked — a silent size-bound
		// overshoot. rotateBackoffWritten keeps a small headroom (~10% of maxBytes), so
		// the next record re-enters rotate() promptly; the inFallback guard then retries
		// only the reopen (no further rename/churn) until a fresh base can be opened.
		s.written = s.rotateBackoffWritten()
		// Prune on the fallback path too: the rename above produced a new sibling, so
		// skipping retention here would let siblings accumulate unbounded under a
		// persistent reopen fault. Pruning is independent of whether the fresh file
		// opened, so it is safe here.
		s.pruneRotated()
		return
	}
	// A clean rotation always lands on the configured base. Fallback recovery is
	// handled separately by retryRotateReopen, so this path never runs while in
	// fallback (the guard at the top of rotate() routes there first).
	s.swapToFreshBase(f, "rotated fd")
}

// retryRotateReopen runs when rotate() fires while the Sink is in the reopen-fallback
// state: a prior rotation renamed the active log to a timestamped sibling but could
// not open a fresh base, so the fd is still appending to that (already-rotated,
// over-size) file. The fd keeps the same inode, so renaming it again would only churn
// a new sibling per size trigger without reclaiming any space — the sole way to bound
// the file is a successful reopen. So this retries ONLY the reopen, on the bounded
// cadence the size trigger provides (~every 10% of maxBytes via rotateBackoffWritten);
// it never renames. On success it completes the deferred rotation by switching to the
// fresh base, leaving the over-size fallback file as a normal rotated sibling.
func (s *Sink) retryRotateReopen() {
	// Sync the over-size fallback file (already a rotated sibling, so shippers and
	// resume find it) BEFORE creating the fresh base, mirroring rotate()'s
	// sync-before-reopen ordering. Doing it after os.OpenFile would invert the
	// crash-ordering invariant: a power loss / kill -9 between creating the empty
	// base and syncing the fallback would lose the fallback's un-fsynced tail while
	// an empty base already exists on disk, so restart would see the empty base,
	// resume from the sibling, and hit a stale or torn tail (tail_hmac_mismatch) —
	// the permanent-loss window rotate() explicitly reordered to close. Syncing
	// first also bounds the fallback's non-durable tail on every retry, including
	// the attempts where the reopen below still fails.
	if serr := s.f.Sync(); serr != nil {
		// The fallback sidecar's tail is not durable. Do NOT complete the swap on a failed
		// sync: swapToFreshBase closes this fd for good (Close does not fsync on Linux), so a
		// crash would permanently drop the un-synced tail and leave a tamper-shaped chain gap
		// at the rotation boundary — the exact window rotate()'s sync-defer closes, and the
		// "caller MUST have synced the old fd first" precondition swapToFreshBase documents.
		// Stay in fallback (s.inFallback is still set) and retry the sync on the next bounded
		// attempt; only complete the swap once the tail is durable. Re-syncing the SAME fd is
		// a bounded best effort — Linux reports a writeback error to a given fd at most once,
		// so a later nil Sync does not by itself prove the first-failed pages reached disk —
		// but never completing the swap on a failed sync is the load-bearing half: it keeps
		// the fd open and retryable instead of closing over a non-durable tail.
		s.writeFailures.Add(1)
		fmt.Fprintf(os.Stderr, "[eunox] audit rotate error (sync on fallback recovery): %v; deferring the swap until the fallback tail is durable\n", serr)
		s.written = s.rotateBackoffWritten()
		return
	}
	f, err := openGuardedAppend(s.logPath)
	if err != nil {
		// Still cannot open a fresh base. Do NOT rename (the fallback file already
		// carries a rotated-sibling name); just back off so the next reopen attempt is
		// ~10% of maxBytes away rather than one record away. The fallback file keeps
		// growing while the fault persists — unavoidable, since records cannot be
		// dropped and no new file can be created — but at a throttled, retrying cadence
		// instead of the prior ~2x-then-rename behavior.
		fmt.Fprintf(os.Stderr, "[eunox] audit rotate error (reopen retry): %v; still appending to fallback file %q\n", err, s.activePath)
		s.written = s.rotateBackoffWritten()
		return
	}
	// Clear fallback state before the shared tail swaps the fresh base in: the
	// deferred rotation is now completing, leaving the over-size fallback file as a
	// normal rotated sibling.
	s.inFallback = false
	s.swapToFreshBase(f, "fallback fd")
}

// pruneRotated deletes the oldest rotated files so at most s.retain are kept; a
// retain of 0 keeps everything. Best-effort: a failed unlink is logged, not fatal,
// so losing a rotated file never wedges the audit path. Drainer-only (no lock).
func (s *Sink) pruneRotated() {
	if s.retain <= 0 {
		return
	}
	// Genuine rotated siblings only, oldest-first, via the shared helper so pruning
	// stays in lockstep with the chain walk over exactly the same files.
	rotated, err := sortedRotatedSiblings(s.logPath)
	if err != nil {
		// A persistent listing failure would silently stop pruning and let siblings
		// accumulate, so log it like the per-file failures below.
		fmt.Fprintf(os.Stderr, "[eunox] audit retention: could not list rotated siblings of %q: %v\n", s.logPath, err)
		return
	}
	// In fallback mode (a reopen failure left activePath pointing at a rotated-pattern
	// file that is still being written to) that active file matches the rotated
	// sibling pattern. Exclude it so it does not consume a retain slot — retain counts
	// only historical (closed) rotated files, never the live one.
	if s.activePath != s.logPath {
		filtered := rotated[:0]
		for _, p := range rotated {
			if p != s.activePath {
				filtered = append(filtered, p)
			}
		}
		rotated = filtered
	}
	if len(rotated) <= s.retain {
		return
	}
	// Delete oldest-first. On the FIRST real failure, STOP rather than continue:
	// retention is only safe because it removes a contiguous OLDEST prefix, leaving the
	// kept files a contiguous suffix. Continuing past a failed unlink could delete a
	// NEWER sibling while this OLDER one survives — an interior hole that cross-file
	// verify (VerifyLogFiles) reports as a prev_hmac CHAIN BREAK + SEQ GAP at the seam,
	// indistinguishable from an attacker deleting an interior file. A file already gone
	// (a raced prune, or an operator removed it) is not a hole, so keep going past that.
	// The next rotation retries the prune, so a transient fault self-heals.
	for _, old := range rotated[:len(rotated)-s.retain] {
		if err := os.Remove(old); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			fmt.Fprintf(os.Stderr, "[eunox] audit retention: could not delete %q: %v; stopping prune to keep rotated files contiguous (retried on the next rotation)\n", old, err)
			// Stopping is correct — a hole in the retained chain is indistinguishable from
			// an attacker deleting an interior file — but the file that fails is always the
			// OLDEST, hence always the first one tried, so a PERMANENT fault (an immutable
			// attribute, a read-only mount, EPERM under a sticky-bit dir) means the loop
			// breaks at index 0 on every future rotation and retention never runs again.
			// retainRotated is then silently voided and siblings accumulate without bound.
			// Report it rather than let the disk fill behind one stderr line per rotation.
			s.markMaintenanceStalled(fmt.Sprintf("retention stalled: rotated audit file %q cannot be deleted (%v), and pruning stops there to keep the retained chain contiguous; the retention bound is not being enforced until this file is removable", old, err))
			return
		}
	}
	// Every over-retention sibling was removed: retention is healthy again.
	s.clearMaintenanceStalled()
}

// rotatedPath returns the path the active log is renamed to during rotation: a
// fixed-width, zero-padded rotation ordinal followed by a nanosecond UTC timestamp
// suffix on logPath ("<logPath>.<020d ordinal>.<ts>Z"). It advances s.rotateOrdinal
// (so each call yields a fresh, larger ordinal) and is called exactly once per
// rotation, before the rename.
//
// The ordinal is the ordering key rotatedOrderLess sorts on: unlike the wall-clock
// timestamp it is monotonic and clock-independent, so retention and cross-file
// verification stay correct across a backward wall-clock step between two rotations.
// It is a DEDICATED rotation counter, NOT the chain seq: seq resumes from the tail and
// legitimately resets to genesis on a detected tail corruption / HMAC mismatch, which
// would make a fresh post-reset rotation sort BEFORE the older high-seq siblings and
// let retention delete the newer file. rotateOrdinal is seeded at Open from the highest
// existing sibling ordinal, so it stays monotonic across restarts and chain resets. The
// timestamp remains for operator readability. %020d holds any uint64 (max is 20 digits),
// so the field is fixed-width and its lexical order matches its numeric order.
//
// os.Rename maps to rename(2) (and MOVEFILE_REPLACE_EXISTING on Windows), which
// atomically replaces an existing target with no trace, so a coarser suffix would
// lose records when two rotations land in the same second. Nanosecond resolution
// plus uniqueRotatedPath's deterministic backstop guarantees a non-existing target,
// so a prior rotated file is never destroyed. (The ordinal is already unique per
// rotation, making a collision essentially impossible, but the backstop is retained
// as a defensive invariant.)
//
// Uniqueness is time-of-check (Lstat) to time-of-use (the Rename), so it relies on
// no other writer creating that target in between. That holds only because rotate()
// runs solely on the drain() goroutine; a concurrent rotate() would reintroduce the
// overwrite.
func (s *Sink) rotatedPath() (string, error) {
	// If Open could not read the siblings to seed the ordinal, re-derive it now (rotation
	// is rare, so the scan cost is negligible) so this rotation is stamped ABOVE any
	// existing sibling rather than restarting from 1 and mis-ordering retention. Only
	// raise the counter — never lower a value later rotations already advanced.
	if s.ordinalSeedUncertain {
		seed, ok := maxRotatedOrdinal(s.logPath)
		if !ok {
			// Surface the stall. Deferring is correct for chain integrity, but a fault that
			// persists (a 0300 log dir, a chronic EIO/ESTALE) defers EVERY future rotation
			// too, so rotateSizeBytes and retainRotated are silently voided and the active
			// log grows unbounded until the filesystem fills — at which point writes fail
			// and --require-audit=strict denies all traffic. A single stderr line before a
			// self-inflicted outage is not enough signal; MaintenanceStalled puts it on
			// /healthz and in doctor while it is still recoverable.
			s.markMaintenanceStalled(fmt.Sprintf("rotation deferred: the audit log's sibling directory for %q cannot be listed, so a rotation ordinal cannot be seeded; the size bound is not being enforced and the log will grow until this is fixed", s.logPath))
			// The same directory-read fault that set the uncertain flag still persists (e.g.
			// a write+exec-but-not-readable log dir, where ReadDir fails while Rename/Lstat
			// still succeed). Do NOT fall through and stamp ordinal 1: it would sort BEFORE
			// the existing higher-ordinal siblings, so pruneRotated would delete the NEWEST
			// file first and LogChainFiles would feed verify out of order (a spurious CHAIN
			// BREAK / SEQ GAP). Defer this rotation instead — rotate()'s target-error branch
			// backs off and retries — keeping the uncertain flag set for the next attempt.
			return "", fmt.Errorf("cannot seed the rotation ordinal for %q (sibling directory still unreadable); deferring rotation to avoid stamping a stale-low ordinal", s.logPath)
		}
		if seed > s.rotateOrdinal {
			s.rotateOrdinal = seed
		}
		s.ordinalSeedUncertain = false
		// The directory became readable again: the deferral self-healed, so stop reporting.
		s.clearMaintenanceStalled()
	}
	s.rotateOrdinal++
	base := s.logPath + "." + fmt.Sprintf("%020d", s.rotateOrdinal) + "." + s.clock().UTC().Format("20060102T150405.000000000Z")
	return uniqueRotatedPath(base)
}

// maxRotatedOrdinal returns the highest rotation ordinal embedded in logPath's
// existing rotated siblings, or 0 when there are none or all are legacy (ordinal-less)
// names. Open seeds s.rotateOrdinal from it so the counter is monotonic across process
// restarts and chain resets (a genesis restart cannot reissue an ordinal an older
// sibling already carries). It reads only directory entry names — no file contents —
// so a corrupt or unreadable sibling body never affects the seed. ok is false when the
// sibling directory could not be read: the caller must NOT treat the 0 result as an
// authoritative "no siblings", since a 0 seed would let the next rotation stamp ordinal
// 1 ahead of existing higher-ordinal siblings and mis-order retention.
func maxRotatedOrdinal(logPath string) (highest uint64, ok bool) {
	files, err := sortedRotatedSiblings(logPath)
	if err != nil {
		return 0, false
	}
	for _, f := range files {
		if ord, hasOrd, _, _ := rotatedStampParts(f, logPath); hasOrd && ord > highest {
			highest = ord
		}
	}
	return highest, true
}

// maxRotateSuffix bounds the ".N" collision-backstop search. Reaching it requires
// this many siblings sharing one nanosecond base (unreachable in normal operation),
// so the cap exists only to guarantee the loop terminates rather than spinning
// toward an int wraparound producing a negative-suffix filename.
const maxRotateSuffix = 10_000

// uniqueRotatedPath returns base, or the first ".N" suffix (N from 1) that does not
// exist on disk. rotatedPath's collision backstop, split out so the fallback is
// testable without depending on clock granularity. It errors only when no free name
// is found within maxRotateSuffix attempts, so the loop is finite and rotate() can
// fail closed rather than overwrite a sibling.
func uniqueRotatedPath(base string) (string, error) {
	return uniqueRotatedPathBounded(base, maxRotateSuffix)
}

// uniqueRotatedPathBounded is uniqueRotatedPath with an explicit attempt cap, so the
// exhaustion path is testable without seeding maxRotateSuffix files. It probes the
// bare base then base.1 .. base.maxSuffix (maxSuffix+1 candidates), returning the
// first free one.
func uniqueRotatedPathBounded(base string, maxSuffix int) (string, error) {
	for i := 0; i <= maxSuffix; i++ {
		candidate := base
		if i > 0 {
			candidate = fmt.Sprintf("%s.%d", base, i)
		}
		// A candidate is free only when Lstat reports it genuinely absent. Any other
		// error (EACCES, EIO, ESTALE) leaves existence unknown, and treating it as
		// free would let rotate()'s Rename clobber an existing sibling and its chain
		// tail, so skip it; if every candidate is ambiguous the loop exhausts and
		// rotate() keeps its fd. Lstat (not Stat) so a dangling symlink counts as
		// occupied.
		if _, err := os.Lstat(candidate); errors.Is(err, fs.ErrNotExist) {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("uniqueRotatedPath: no free rotated name for %q after %d attempts", base, maxSuffix+1)
}
