// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Package audit implements the tamper-evident, HMAC-signed OCSF JSONL audit log:
// the asynchronous record sink (writer plus bounded background drainer),
// size-triggered rotation with retention pruning, and per-record HMAC plus
// tamper-evident chain verification. It depends only on internal/config (the
// shared ExpandHome helper), pkg/capability, and the standard library, never
// back on the binary.
package audit

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/eunolabs/eunox/internal/config"
	"github.com/eunolabs/eunox/pkg/capability"
)

// auditRecord is an OCSF-inspired audit record written to the local audit log.
type auditRecord struct {
	ClassUID      int             `json:"class_uid"`    // 6003 = API Activity
	CategoryUID   int             `json:"category_uid"` // 6 = Application Activity
	ActivityID    int             `json:"activity_id"`  // 1 = Allow, 2 = Deny
	Time          string          `json:"time"`
	Seq           uint64          `json:"seq"` // monotonic per-log sequence number; links the tamper-evident chain
	RequestID     string          `json:"request_id"`
	SessionID     string          `json:"session_id,omitempty"`     // omitted when empty, matching AgentID/TaskID/UserID: synthetic integrity/drop markers carry no session, so they no longer emit "session_id":""
	AgentID       string          `json:"agent_id,omitempty"`       // JWT mcp.agent_id, stamped when a validated token is present (§ 2.1)
	TaskID        string          `json:"task_id,omitempty"`        // JWT mcp.task_id, stamped when a validated token is present (§ 2.1)
	UserID        string          `json:"user_id,omitempty"`        // JWT subject (sub): the human/principal identity, stamped when a validated token is present (§ 2.1)
	Upstream      string          `json:"upstream,omitempty"`       // gateway route name (empty in single-upstream mode)
	PolicyVersion string          `json:"policy_version,omitempty"` // manifest.Version in force for this decision
	PolicySHA256  string          `json:"policy_sha256,omitempty"`  // digest of the canonical policy document
	TargetType    string          `json:"target_type,omitempty"`    // "tool" | "resource" | "prompt" | "system"; namespace taken from the MCP method, not the raw identifier
	Target        string          `json:"target,omitempty"`         // canonical bare target: tool name, resource URI, prompt name, or "sampling/createMessage"
	Method        string          `json:"method,omitempty"`         // MCP method that produced the decision, e.g. "tools/call"
	Decision      string          `json:"decision"`                 // "allow" | "deny"
	AuditOnly     bool            `json:"audit_only,omitempty"`     // true when the decision was observed, not enforced (audit mode)
	DenialCode    string          `json:"denial_code,omitempty"`
	ConditionType string          `json:"condition_type,omitempty"`
	Details       json.RawMessage `json:"details,omitempty"` // marshaled once at record time (marshalAndBoundDetails); writeRecord embeds it verbatim rather than re-marshaling the map
	Obligations   []string        `json:"obligations,omitempty"`
	// LabelsOut and CarriedLabels are the information-flow-control fields: the native
	// flow labels this call's output asserted into the session (labelsOut, from its
	// labelOutput directives) and the session's accumulated label set observed at
	// decision time (carriedLabels), so a source->sink flow reconstructs from the tape
	// alone. Both are drawn from the closed native vocabulary — never free-form, never
	// IdP- or argument-sourced — so unlike Obligations they need no length bound.
	// Present only on flow-relevant decisions; omitted otherwise.
	LabelsOut     []string `json:"labels_out,omitempty"`
	CarriedLabels []string `json:"carried_labels,omitempty"`
	KeyID         string   `json:"key_id,omitempty"` // id of the HMAC key that signed this record; lets audit-verify select the right key after rotation (§ 3.4)
	PrevHMAC      string   `json:"prev_hmac"`        // _hmac of the preceding record (genesis sentinel for the first); chains records together
	HMAC          string   `json:"_hmac,omitempty"`
}

// auditGenesisPrev is the prev_hmac stamped on the first record of a brand-new
// log. A fixed sentinel (rather than "") keeps the field always present, so a
// stripped prev_hmac on a later record reads as a chain break, not a genesis.
const auditGenesisPrev = "sha256:genesis"

// auditIntegrityFailureCode is the DenialCode on every synthetic integrity marker
// (writeIntegrityMarker).
const auditIntegrityFailureCode = "AUDIT_INTEGRITY_FAILURE"

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
)

// auditChannelSize bounds the queue feeding the background drainer. When full,
// records are dropped (counted by DroppedRecords) and the drainer emits an
// in-chain AUDIT_RECORDS_DROPPED marker (see flushDropMarker) so the loss is
// tamper-evident.
const auditChannelSize = 4096

// reqIDGen generates monotonically increasing request IDs ("req-<nonce>-<counter>")
// from a startup nonce + atomic counter, keeping crypto/rand off the Record hot path.
// The random per-process nonce is mixed into every ID because the bare counter
// restarts at zero each process start: without it a log spanning restarts would share
// request_id "req-1" across unrelated sessions, polluting `audit-verify --request-id`
// and SIEM joins. The crypto/rand call happens once at startup. Shared scheme with the
// enforcement engine's decision IDs via capability.IDGenerator.
var reqIDGen = capability.NewIDGenerator("req", 4)

func nextRequestID() string {
	return reqIDGen.Next()
}

// hmacKeyID returns a stable, non-secret identifier for an HMAC key: the first
// 16 hex chars of SHA-256(key). Stamped on every record so audit-verify can
// select the key that signed it after rotation (§ 3.4). Being a one-way digest,
// it discloses nothing about the key material.
func hmacKeyID(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:8])
}

// Sink writes OCSF audit records to a JSONL file, signing each record with
// HMAC-SHA256 using a per-installation key. Record does only struct
// initialization and a non-blocking channel send; all serialization, signing,
// and disk I/O run in a single background drainer goroutine, keeping the audit
// path off the policy hot path.
type Sink struct {
	// key, keyID, verifyKeys, maxBytes, retain, logPath, now, identity, and
	// lockFile are written once at construction and read-only thereafter, so any
	// goroutine may read them without a lock.
	key   []byte // active HMAC signing key
	keyID string // identifier of the active key, stamped on every record (§ 3.4)
	// verifyKeys is the keyring used by VerifyRecord, mapping key id to key so a
	// record verifies against whichever key signed it (supports rotation). nil on
	// the signing path falls back to the single active key.
	verifyKeys map[string][]byte
	maxBytes   int64
	// retain bounds how many rotated files (logPath.<timestamp>) are kept; 0 = keep
	// all. Read by the drainer only (in rotate).
	retain  int
	logPath string

	// now is the clock for record timestamps and the rotation filename. Defaults
	// to time.Now; injectable so rotation and timestamping are testable with a
	// fake clock.
	now func() time.Time

	// identity, when set, extracts the agent/task/user identity to stamp on each
	// record from the request context. Injected via WithIdentity so the audit
	// subsystem need not depend on the JWT/PDP layer; nil leaves
	// AgentID/TaskID/UserID empty.
	identity func(ctx context.Context) (agentID, taskID, userID string)

	// activePath is the file the current fd (s.f) writes to. It equals logPath
	// normally, but a rotation whose reopen of logPath fails keeps writing to the
	// renamed file and points activePath there — so the next rotation renames the
	// file actually in use, while logPath stays the configured base for
	// rotatedPath, pruneRotated, and restart resume. Owned by the drainer (set in
	// rotate); initialized to logPath.
	activePath string

	// records is the bounded channel of raw records awaiting the drainer.
	records chan auditRecord

	// dropped counts records discarded because records was full (see DroppedRecords).
	dropped atomic.Int64

	// queuedBytes tracks the approximate heap held by records awaiting the drainer.
	// The 4096-slot channel bounds the record COUNT, but each record can carry up to
	// ~1.1 MiB (Details + Obligations), so the count bound alone permits ~4.3 GiB of
	// retained heap when a slow disk meets audit-mode large-argument logging — enough
	// to OOM the proxy, taking down enforcement and the audit trail together. This
	// counter adds an aggregate BYTE bound (auditQueueByteBudget): the enqueue path
	// drops over-budget records like a full queue (the drop marker keeps the loss
	// tamper-evident) and the drainer subtracts each record's size as it is consumed.
	// The check-then-add is not atomic with the send, so the bound is soft (a few
	// concurrent enqueuers may overshoot by a record each) — that is fine; the goal is
	// bounding gigabytes, not exact accounting.
	queuedBytes atomic.Int64

	// lastDroppedMarked is the dropped count already reflected by a written
	// AUDIT_RECORDS_DROPPED marker. Drainer-only.
	lastDroppedMarked int64

	// dropBucketsMu guards dropBuckets, which multiple enqueuing goroutines can
	// update concurrently (unlike lastDroppedMarked, which only the drainer
	// touches). A dedicated mutex rather than s.mu: it protects a different
	// invariant (bucket-count bookkeeping, not the records-channel/closed pair)
	// and is held only across a map read-increment, never across the channel send.
	dropBucketsMu sync.Mutex
	// dropBuckets tallies dropped records by method/target since the last
	// AUDIT_RECORDS_DROPPED marker, so the marker can name what was affected
	// instead of only a bare count. Bounded to auditDropBucketCap distinct entries;
	// beyond that, further distinct buckets fold into dropBucketOverflowKey so a
	// flood across many targets cannot grow this map unboundedly.
	dropBuckets map[string]int64

	// writeErrWarned / syncErrWarned gate the one-shot stderr warnings for the
	// write-error and steady-state-fsync paths respectively. Each has its own flag
	// (not the shared writeFailures counter) so the first live alert on its path
	// fires regardless of unrelated failures. Drainer-only.
	writeErrWarned bool
	syncErrWarned  bool

	// writeFailures counts records that reached the drainer but could not be
	// durably written: a serialization error, a file lost to a failed rotation, a
	// write error (full disk, EIO), or an fsync failure leaving a batch unflushed.
	// Distinct from dropped: dropped is back-pressure on a healthy file (the queue
	// can't keep up), writeFailures means the file itself is unwritable. Unlike a
	// drop, a write failure cannot be recorded in-chain (the target file is the
	// thing failing), so it is surfaced out of band: this counter
	// (eunox_audit_write_failures_total), a one-shot stderr warning, and a non-zero
	// Close/exit. Atomic (read/written from any goroutine); exposed via WriteFailures.
	writeFailures atomic.Int64

	// maintenanceStalled is set when size-triggered rotation or retention pruning has
	// stopped making progress while record writing itself is still healthy: the sibling
	// directory cannot be listed (so an ordinal cannot be seeded and rotation defers), or
	// the oldest rotated file cannot be unlinked (so pruning stops to keep the retained
	// chain contiguous). Both are deliberately non-fatal — deferring is what keeps the
	// chain verifiable — but both silently void the configured disk bound, and the log
	// then grows until the filesystem fills, at which point writes DO fail and
	// --require-audit=strict denies everything. That end state is far worse than the
	// warning, so the stall is surfaced while it is still just a stall.
	//
	// Deliberately NOT folded into AuditDegraded: that gate denies live traffic under
	// --require-audit=strict, and a stalled rotation has lost no records — every decision
	// is still being written and signed. This is a maintenance/readiness signal for
	// /healthz, metrics, and doctor, not an enforcement input. Cleared when the operation
	// next succeeds, so a transient fault self-heals in the reporting too.
	maintenanceStalled atomic.Bool
	// maintenanceStallReason carries the human-readable cause of maintenanceStalled.
	// Guarded by its own mutex rather than an atomic.Value so an empty reason is cheap.
	maintenanceStallMu     sync.Mutex
	maintenanceStallReason string

	// wg tracks the drainer so Close can wait for it to flush.
	wg sync.WaitGroup

	// closeOnce makes Close idempotent.
	closeOnce sync.Once

	// closeErr holds the one-shot close result on the struct (not a Close-local)
	// so every caller, including closeOnce-race losers, observes the real
	// Sync/Close error. sync.Once.Do's happens-before makes the read safe.
	closeErr error

	// mu guards the records-channel send in Record() against Close's channel close.
	// Record() holds it for read across the non-blocking send; Close holds it for
	// write while setting closed and closing the channel. The write lock cannot be
	// acquired until every in-flight read lock releases, so a send can never be
	// mid-flight when close(s.records) runs (which would panic). A read lock lets
	// concurrent producers still enqueue in parallel. closed, once set, turns any
	// later send into a counted drop.
	mu     sync.RWMutex
	closed bool

	// lockFile holds an exclusive advisory lock on a sidecar lock file tied to
	// logPath for the Sink's lifetime, so two writers (same process or another
	// instance) cannot resume from the same chain tail and fork the HMAC chain.
	// Released by Close.
	lockFile *os.File

	// The fields below are accessed only by the drainer goroutine; no mutex.
	f       *os.File
	written int64

	// rotateOrdinal is a monotonic per-log rotation counter stamped into each rotated
	// sibling's name and used as the sibling ordering key (see rotatedPath /
	// rotatedOrderLess). It is DECOUPLED from the chain seq on purpose: seq resumes from
	// the tail and legitimately RESETS to genesis on a detected tail corruption / HMAC
	// mismatch (see Open), so keying sibling order on seq would sort a fresh post-reset
	// rotation BEFORE the older high-seq siblings and let retention delete the newer
	// file. Seeded at Open from the highest ordinal among existing siblings (0 when none
	// or all are legacy/seq-less) so it stays monotonic across restarts and chain resets,
	// then incremented once per rotation. Drainer-only.
	rotateOrdinal uint64

	// ordinalSeedUncertain is set when Open could not read the rotated siblings to seed
	// rotateOrdinal (a transient directory-read error), so the seed fell back to 0. A 0
	// seed makes the next rotation stamp ordinal 1, which rotatedOrderLess would sort
	// BEFORE existing higher-ordinal siblings — so retention would delete the NEWEST file
	// first (the exact loss the ordinal exists to prevent). While this flag is set,
	// rotatedPath re-attempts the sibling scan before stamping, so the first successful
	// rotation recovers the true high-water mark. Drainer-only.
	ordinalSeedUncertain bool

	// inFallback is set when a rotation renamed the active log but could not open a
	// fresh base (e.g. the log directory transiently lost create permission), so the
	// fd is still appending to the renamed, already-rotated file. While set, rotate()
	// does NOT rename again — that would churn a new sibling per size trigger without
	// ever reclaiming space, since the fd keeps the same inode — and instead retries
	// only the reopen on a bounded cadence (retryRotateReopen). Cleared once a reopen
	// recovers. Drainer-only, like the fields above.
	inFallback bool

	// tailOrphanBytes is non-zero when a partial write left an unterminated fragment
	// (that many bytes) at the end of the file that writeRecord's Stat/Truncate
	// repair could not clean up (a degraded filesystem, or a concurrent external
	// truncation) — it doubles as the "a dirty tail is pending" flag (pending ⟺
	// tailOrphanBytes > 0) and as the byte count needed to recompute the truncate
	// target (current file size - tailOrphanBytes) on a later repair retry. While
	// non-zero, writeRecord refuses to append ANY record — appending would fuse a
	// full record onto the orphan, producing one corrupt physical line that fails
	// verification AND desyncs the seq/prev_hmac chain for every following record
	// (an INVALID + CHAIN BREAK + SEQ GAP cascade indistinguishable from tampering)
	// — and instead retries the repair before every write, counting a write failure
	// and skipping the write again if the repair still fails. This replaces the old
	// "force rotation via s.written = s.maxBytes" signal: a forced rotation can
	// itself fail (rename/reopen error, plausible on the same degraded filesystem),
	// which left the same fd — and the same un-terminated orphan — in place for the
	// next write to splice onto.
	tailOrphanBytes int64

	// sinceSync counts records written since the last fsync. The drainer forces a
	// sync once it reaches syncEveryN even if the channel never empties, so a proxy
	// under sustained load still bounds its non-durable tail to syncEveryN records.
	sinceSync int

	// writeLine, when non-nil, replaces the drainer's direct write to f. Test-only
	// seam for a slow/failing writer; nil in production. Set before any record is
	// enqueued, and read only after a channel receive, so no data race.
	writeLine func([]byte) (int, error)

	// seq and prevHMAC are the sequence number and _hmac of the last record
	// written; the next record is stamped seq+1 and carries prevHMAC as prev_hmac.
	// Together they form the tamper-evident chain. Both resume from the log tail at
	// open and carry across rotation in memory, so the chain is continuous.
	seq      uint64
	prevHMAC string
}

const (
	// defaultAuditLog and defaultAuditKeyPath store the UNEXPANDED "~" form. The OS
	// does not resolve "~", so using either path verbatim would create a literal
	// "~" directory in the CWD. Resolve only through ResolveLogPath/ResolveKeyPath,
	// which run config.ExpandHome (fails closed when the home directory is unknown).
	defaultAuditLog        = "~/.eunox/audit.jsonl"
	defaultAuditKeyPath    = "~/.eunox/audit.key"
	defaultRotateSizeBytes = 100 << 20 // 100 MiB
)

// Option customizes a Sink at construction time. Options are applied before the
// drainer starts, so they may set construction-time read-only fields without
// synchronization.
type Option func(*Sink)

// WithIdentity injects the agent/task/user identity extractor read by Record.
// Supplied by the caller so the audit subsystem need not import the JWT/PDP layer.
func WithIdentity(fn func(ctx context.Context) (agentID, taskID, userID string)) Option {
	return func(s *Sink) { s.identity = fn }
}

// auditReasonTailReadFailed is the structured, OS-independent sentinel stored in the
// chain_resume_failed marker's details.reason. The raw OS error (which varies by OS,
// libc, and errno, and can embed the audit-log file path) is written only to the
// stderr warning, never into the signed, append-only tape — keeping details.reason a
// fixed code SIEM rules can match across environments rather than free-form prose.
const auditReasonTailReadFailed = "tail_read_failed"

// openAndPrepareLog opens the audit log for append, tightens its mode, computes the
// byte count the rotation threshold resumes from, and recovers a trailing partial write
// left by a non-clean shutdown. It returns the open handle, the (non-negative) resume
// size, and the number of partial bytes recovered (which Open records in-band as a
// tail_partial_write_recovered marker).
//
// Both failure modes are fatal and fail closed: the log cannot be opened, or a trailing
// orphan cannot be truncated (leaving it would let the next O_APPEND write fuse onto it,
// producing a line audit-verify reports as corruption). On either, it releases the audit
// lock (and closes the handle, when one was opened) so the caller returns directly. Runs
// under the exclusive lock, before the drainer starts. preSize is Open's pre-open probe.
func openAndPrepareLog(logPath string, preSize int64, lockFile *os.File) (f *os.File, written, recoveredPartialBytes int64, tail tailResume, err error) {
	// Prefer O_RDWR (not O_WRONLY) so recoverPartialTail can probe the tail (f.Stat/
	// f.ReadAt) through this same already-open handle rather than a second read-only
	// os.Open. A second open can fail transiently (EIO/NFS blip) while a real orphan
	// partial record is present, and the old code mistook that "could not check" for "no
	// orphan found" and proceeded — letting the first O_APPEND write fuse onto the orphan.
	// One handle removes that read-only-open failure mode. O_APPEND still forces every
	// write to the end regardless of the read offset ReadAt uses, so the probe cannot
	// disturb appends.
	//
	// Fall back to O_WRONLY when O_RDWR is refused: an operator may deliberately run a
	// write-only (0200) audit log, which a non-root process cannot open for reading. That
	// is the documented audit-failure tradeoff — Open must still succeed and append. With
	// only a write handle the tail cannot be read, so recoverPartialTail (readable=false)
	// skips partial-tail recovery and a non-clean shutdown falls into the
	// chain-resume-failed path, same as any genuinely unreadable log. We never widen the
	// mode to gain read access (see tightenLogMode).
	// Refuse a non-regular log path (a symlink, most concretely) — or one that cannot be
	// Lstat'd for any reason other than genuine absence — before opening it: os.OpenFile
	// follows a symlink and a symlinked active log is silently excluded from audit-verify's
	// IsRegular() chain scan. The shared refuseNonRegular guard (see rotate.go) fails closed
	// on a stat fault too, so this startup site and the two post-rotation reopen sites can
	// never diverge on the check. Wrapping keeps the "opening audit log" provenance here.
	if err := refuseNonRegular(logPath); err != nil {
		_ = releaseAuditLock(lockFile)
		return nil, 0, 0, tailResume{}, fmt.Errorf("opening audit log %q: %w", logPath, err)
	}

	readable := true
	// config.OpenNoFollow (O_NOFOLLOW on unix, 0 elsewhere) makes the kernel refuse a
	// final-component symlink atomically, closing the Lstat->OpenFile TOCTOU the
	// refuseNonRegular check above cannot. A symlink surviving to here fails the open
	// with ELOOP, which is neither ErrPermission nor ErrNotExist, so it falls straight
	// into the fail-closed return below rather than the write-only fallback.
	f, err = os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_RDWR|config.OpenNoFollow, 0o600) //nolint:gosec // G304: path is user-configured audit log location
	if errors.Is(err, os.ErrPermission) {
		readable = false
		f, err = os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY|config.OpenNoFollow, 0o600) //nolint:gosec // G304: path is user-configured audit log location
	}
	if err != nil {
		_ = releaseAuditLock(lockFile)
		return nil, 0, 0, tailResume{}, fmt.Errorf("opening audit log %q: %w", logPath, err)
	}
	// O_CREATE applies the restrictive mode only on creation; an existing log keeps its
	// on-disk mode. Drop any group/world access so a log left readable by a looser umask,
	// a restore, or a pre-created path cannot leak the signed tape.
	tightenLogMode(f, logPath)

	// Determine the current size so the rotation threshold continues from the tail.
	written = recoverWrittenSize(f, logPath, preSize)

	// Recover from a non-clean shutdown that left a partial (non-newline-terminated)
	// trailing write: drop it so the next append starts at a clean record boundary
	// instead of concatenating onto the orphan and corrupting that line at verify time.
	recoveredPartialBytes, tail, err = recoverPartialTail(logPath, f, readable)
	if err != nil {
		_ = f.Close()
		_ = releaseAuditLock(lockFile)
		return nil, 0, 0, tailResume{}, fmt.Errorf("opening audit log %q: %w", logPath, err)
	}
	// Never let the size accounting go negative: recoverWrittenSize falls back to 0 (or a
	// possibly-stale pre-open size) when stat fails, so a partial-tail recovery larger
	// than that fallback would otherwise leave written < 0.
	return f, max(0, written-recoveredPartialBytes), recoveredPartialBytes, tail, nil
}

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
		fmt.Fprintf(os.Stderr, "[eunox] WARNING: audit log tail failed HMAC verification; the last record may have been tampered with or truncated. The chain cannot be resumed and restarts from genesis — run 'eunox audit-verify' and reconcile against your external sink.\n")
		// Mark it in-band too (stderr is lost to log rotation and not in the
		// tamper-evident trail); the signed marker is written by the caller.
		return tailResumeResult{tailFailKind: tailFailHMACMismatch, tailSeq: prev.Seq, tailHMAC: prev.HMAC}
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

// Open opens (or creates) the audit log and loads (or generates) the HMAC
// signing key. logPath, keyPath, and rotateSizeBytes may be zero for defaults.
//
// keyPath is configurable so the key can be injected in containerized or
// shared-host deployments. Empty uses the default (~/.eunox/audit.key), itself
// overridable by EUNOX_AUDIT_KEY_PATH.
func Open(logPath, keyPath string, rotateSizeBytes int64, retainRotated int, opts ...Option) (*Sink, error) {
	logPath, err := ResolveLogPath(logPath)
	if err != nil {
		return nil, fmt.Errorf("audit log path: %w", err)
	}

	if rotateSizeBytes <= 0 {
		rotateSizeBytes = defaultRotateSizeBytes
	}
	if retainRotated < 0 {
		retainRotated = 0
	}

	// Resolve the key path through the single source of truth for flag/env/default
	// precedence so the proxy never drifts from the audit-verify/doctor subcommands.
	expandedKeyPath, err := ResolveKeyPath(keyPath)
	if err != nil {
		return nil, fmt.Errorf("audit key path: %w", err)
	}
	keys, err := LoadOrCreateKeys(expandedKeyPath)
	if err != nil {
		return nil, fmt.Errorf("audit key: %w", err)
	}
	// First key is the active signing key; the rest are retired keys kept only so
	// audit-verify can validate records they signed before rotation (§ 3.4).
	key := keys[0]
	// Build the full verification keyring (active + retired) so the startup tail
	// check below can validate a tail signed by a retired key; otherwise keysToTry
	// would fall back to the active key alone and warn spuriously. Signing still
	// uses the active key; verifyKeys is consulted only by VerifyRecord.
	verifyRing := make(map[string][]byte, len(keys))
	for _, k := range keys {
		verifyRing[hmacKeyID(k)] = k
	}

	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		return nil, fmt.Errorf("creating audit log directory: %w", err)
	}

	// Acquire the exclusive lock BEFORE reading the tail or opening for append, so
	// a second writer cannot resume from the same predecessor and fork the chain. A
	// held lock fails startup clearly rather than producing a forked, unverifiable
	// log. Released in Close.
	lockFile, err := acquireAuditLock(logPath)
	if err != nil {
		return nil, err
	}

	// Probe the path BEFORE O_CREATE so the size is known even if the post-open
	// f.Stat() fails. preSize == -1 means genuinely unknown (probe errored with
	// something other than not-exist); not-exist means brand-new and empty.
	var preSize int64 = -1
	if info, statErr := os.Stat(logPath); statErr == nil {
		preSize = info.Size()
	} else if os.IsNotExist(statErr) {
		preSize = 0
	}

	f, written, recoveredPartialBytes, tail, err := openAndPrepareLog(logPath, preSize, lockFile)
	if err != nil {
		return nil, err
	}

	// Seed the rotation ordinal from the existing siblings. A read failure is transient
	// and non-fatal (the log still opens), but it must not silently fall back to 0 and let
	// the next rotation stamp ordinal 1 ahead of higher-ordinal siblings — so warn and
	// remember the uncertainty (rotatedPath re-derives on the next rotation).
	seedOrdinal, seedOK := maxRotatedOrdinal(logPath)
	if !seedOK {
		fmt.Fprintf(os.Stderr, "[eunox] WARNING: could not read rotated audit siblings to seed the rotation ordinal for %q; the next rotation will re-derive it (retention ordering is temporarily uncertain)\n", logPath)
	}

	s := &Sink{
		key:        key,
		keyID:      hmacKeyID(key),
		verifyKeys: verifyRing,
		maxBytes:   rotateSizeBytes,
		retain:     retainRotated,
		logPath:    logPath,
		activePath: logPath,
		now:        time.Now,
		records:    make(chan auditRecord, auditChannelSize),
		f:          f,
		lockFile:   lockFile,
		written:    written,
		// Seed the rotation ordinal past the highest existing sibling so it stays
		// monotonic across restarts and a chain reset — keyed off the sibling NAMES, not
		// the resumed chain seq (which can reset to genesis on tail corruption). This
		// keeps rotated-sibling ordering (retention + verification) robust even when a
		// post-reset rotation writes a lower seq than the pre-reset siblings hold.
		rotateOrdinal: seedOrdinal,
		// A failed seed read is not fatal (the log must still open), but is remembered so
		// the next rotation re-derives the ordinal rather than trusting the 0 fallback.
		ordinalSeedUncertain: !seedOK,
	}
	// Apply options before the drainer starts, while still single-threaded.
	for _, opt := range opts {
		opt(s)
	}
	// Resume the chain from the existing tail so seq stays monotonic and prev_hmac
	// links across restarts. Only a tail that verifies under a held key is resumed
	// onto; anything else (unparseable, HMAC mismatch, retired key, or unsigned)
	// restarts the chain from genesis and leaves a signed marker naming the reason.
	//
	// The tail was read once, through the open append handle, by the partial-tail
	// recovery above (see tailResume): every way it could fail to establish the tail
	// is already a fail-closed Open error, so only two cases remain here.
	resume := s.resolveStartupResume(tail, logPath)
	last := resume.last
	chainResumeFailed, seedUnbounded, resumeFailReason := resume.chainResumeFailed, resume.seedUnbounded, resume.failReason
	tr := s.resumeChainFromTail(last)
	tailFailKind, tailParseFailure, tailParseBytes := tr.tailFailKind, tr.tailParseFailure, tr.tailParseBytes
	tailSeq, tailHMAC := tr.tailSeq, tr.tailHMAC
	// Emit the integrity marker before the drainer starts: Open is single-threaded
	// here, so writeRecord has no contention and the marker becomes the first
	// appended line, chained from the resumed tail like the first real record. The
	// first five cases are mutually exclusive (a read failure leaves last=="" so no
	// parse/HMAC attempt; the parse must succeed before the signature checks; and the
	// unsigned tail, the HMAC mismatch, and the unknown-key tail are distinct outcomes
	// of that same step), so at most one of THEM is written. All of them chain from
	// genesis: none of those tails is resumable, so there is no seq/prev_hmac to
	// continue from. The tail_partial_write_recovered marker is independent of these
	// (it concerns the dropped fragment, not the resumed record) and may fire alongside
	// one of them.
	// wroteMarker says whether any writeIntegrityMarker call below appended a line, so
	// the fsync further down only pays for a startup that put something new on disk — a
	// clean startup (the common case: no tail failure, no partial-write recovery) has
	// nothing to durably flush that Close (or the drain goroutine's own debounced fsync,
	// once real traffic arrives) won't cover anyway.
	//
	// DERIVED from the same conditions the branches below test, rather than assigned once
	// per branch: a hand-maintained flag has to be remembered at every new marker site,
	// and forgetting it silently skips the fsync — so a crash right after Open loses
	// exactly the tamper-evidence marker that fsync exists to make durable, on a path no
	// test exercises.
	wroteMarker := chainResumeFailed || tailParseFailure ||
		tailFailKind != tailFailNone || recoveredPartialBytes > 0
	if chainResumeFailed {
		// seed_unbounded says whether the reseed could see the whole chain. When the log
		// directory cannot be listed, the rotated siblings' seqs are unknown and the
		// reseed bounds only the base log — so the new records may collide with seqs the
		// unlisted siblings already hold. That is a materially different forensic state
		// from a bounded reseed, and stating it on the signed tape is what keeps it from
		// looking (to audit-verify, later) like an unexplained duplicate-seq cascade.
		details := map[string]interface{}{"reason": resumeFailReason}
		if seedUnbounded {
			details["seed_unbounded"] = true
			fmt.Fprintf(os.Stderr, "[eunox] WARNING: the audit log directory of %q could not be listed, so the resumed sequence number could not be bounded against the rotated siblings; new records may reissue seqs those files already hold — run 'eunox audit-verify' and reconcile against your external sink.\n", logPath)
		}
		s.writeIntegrityMarker("chain_resume_failed", details)
	}
	if tailParseFailure {
		// tail_bytes records the length; the bytes are unparseable, so not embedded.
		s.writeIntegrityMarker("tail_parse_failure", map[string]interface{}{"tail_bytes": tailParseBytes})
	}
	switch tailFailKind {
	case tailFailHMACMismatch:
		// Carry the suspect record's seq and hmac so a forensic reader can locate it.
		s.writeIntegrityMarker("tail_hmac_mismatch", map[string]interface{}{"claimed_tail_seq": tailSeq, "claimed_tail_hmac": tailHMAC})
	case tailFailKeyUnknown:
		// Distinct from tail_hmac_mismatch: this tail could not be verified because its
		// signing key was retired, not because the HMAC failed to match a known key.
		s.writeIntegrityMarker("tail_key_unknown", map[string]interface{}{"claimed_tail_seq": tailSeq, "claimed_tail_hmac": tailHMAC})
	case tailFailUnsigned:
		// The tail carries no signature at all — a pre-signing log, or a stripped
		// signature. Carry its seq so a forensic reader can locate the boundary.
		s.writeIntegrityMarker("tail_unsigned", map[string]interface{}{"claimed_tail_seq": tailSeq})
	}
	if recoveredPartialBytes > 0 {
		// A partial trailing write was truncated above. Record the recovery so the
		// event is on the tamper-evident trail and an anomalous rate of partial writes
		// is visible. Unlike the four cases above this is NOT mutually exclusive with
		// them: the recovery concerns the dropped fragment, while those markers concern
		// the COMPLETE record the chain resumes from, so both can legitimately fire. It
		// chains from the resumed tail like any appended record.
		s.writeIntegrityMarker("tail_partial_write_recovered", map[string]interface{}{"recovered_bytes": recoveredPartialBytes})
	}

	// Sync now, before returning, but only when a marker above actually wrote a
	// new line: every writeIntegrityMarker call wrote directly via writeRecord on
	// this (single-threaded) goroutine, bypassing the drain goroutine's debounced/
	// every-syncEveryN fsync entirely (that logic lives in drain's local state,
	// which does not exist until the goroutine below starts). An idle proxy that
	// receives no further traffic would otherwise leave this startup evidence —
	// e.g. a tail_hmac_mismatch or tail_key_unknown marker — sitting unsynced in
	// the OS page cache until Close() runs, so a crash or power loss right after
	// Open returns could lose it. Gating on wroteMarker keeps this a rare-path cost
	// (paid only on an actual tail anomaly/recovery), not a fsync every process
	// start pays against a log with nothing new to flush.
	if wroteMarker && s.f != nil {
		if err := s.f.Sync(); err != nil {
			s.writeFailures.Add(1)
			fmt.Fprintf(os.Stderr, "[eunox] WARNING: audit fsync failed at startup — recently written records may not be durable on disk; check disk health: %v\n", err)
		}
	}

	s.wg.Add(1)
	go s.drain()
	return s, nil
}

// NewVerifier returns a verify-only Sink that signs nothing and opens no log, but
// whose keyring holds every supplied key indexed by key id, so VerifyLog can
// validate records straddling a key rotation: each record is checked against the
// key its key_id names, and a record with no key_id is tried against every key
// (§ 3.4). An empty slice yields a Sink that verifies nothing. audit-verify builds
// its verifier here so the unexported Sink internals stay package-private.
//
// verifyKeys is always non-nil (even for an empty slice), so keysToTry never takes
// its single-key (s.key) fallback for a verifier — the verifier signs nothing and
// so needs no active key.
func NewVerifier(keys [][]byte) *Sink {
	ring := make(map[string][]byte, len(keys))
	for _, k := range keys {
		ring[hmacKeyID(k)] = k
	}
	return &Sink{verifyKeys: ring}
}

// syntheticDenyMarker builds the common envelope shared by every synthetic,
// signed marker the sink writes itself (integrity-failure, tail-parse,
// chain-resume, dropped-records): a deny-class OCSF record with a structured
// DenialCode and bounded Details, stamped with a fresh RequestID and active
// KeyID. Centralizing the shape keeps every marker identical, so a future
// top-level field cannot land on one and be forgotten on the others. Details is
// bounded here so writeRecord's already-bounded invariant holds for every caller.
func (s *Sink) syntheticDenyMarker(code string, details map[string]interface{}) auditRecord {
	return auditRecord{
		ClassUID:    6003,
		CategoryUID: 6,
		ActivityID:  2, // deny-class: a loss of audit integrity/coverage
		Time:        s.clock().UTC().Format(time.RFC3339Nano),
		RequestID:   nextRequestID(),
		Decision:    "deny",
		DenialCode:  code,
		Details:     marshalAndBoundDetails(details),
		KeyID:       s.keyID,
	}
}

// writeIntegrityMarker writes one synthetic, signed record reporting a loss of
// chain integrity detected at startup. kind names the failure and is folded into
// details:
//
//   - tail_hmac_mismatch: the prior tail failed HMAC verification against a known
//     key; details carry claimed_tail_seq and claimed_tail_hmac so a forensic reader
//     can locate the suspect record.
//   - tail_key_unknown: the prior tail names a key_id absent from the verification
//     ring (the expected state right after a key rotation retired the signing
//     key), so it could not be verified either way — distinct from
//     tail_hmac_mismatch, which implies a known key rejected it. Details carry
//     claimed_tail_seq and claimed_tail_hmac.
//   - tail_parse_failure: the prior tail did not parse as JSON; details carry
//     tail_bytes (the bytes are unparseable, so not embedded).
//   - chain_resume_failed: an I/O error prevented reading the prior tail; details
//     carry the reason.
//   - tail_unsigned: the prior tail carried no _hmac (a pre-signing log, or a
//     stripped signature — indistinguishable, so both restart the chain); details
//     carry claimed_tail_seq.
//   - tail_partial_write_recovered: a partial (non-newline-terminated) trailing
//     write was truncated so the next append starts clean; details carry
//     recovered_bytes.
//
// The first five are mutually exclusive (at most one per start); the partial-write
// recovery is independent and may accompany one of them. All reuse the
// AUDIT_INTEGRITY_FAILURE deny shape (no new top-level field) and are chained and
// signed like any record, so audit-verify and any external sink surface them —
// evidence a transient stderr warning would lose to log rotation.
//
// The claimed_ prefix on the tail fields is deliberate and matches the convention the
// transport layer applies to an unverified Mcp-Session-Id: every one of those values is
// read from the record this writer just declared UNCERTIFIABLE, so it is whatever a
// write-capable attacker put there. Signing it under a bare name would let anyone with
// file access have eunox attest an arbitrary seq or hmac as fact — a SIEM rule keyed on
// tail-seq discontinuities being the obvious target. The prefix keeps the forensic hint
// while marking, in the record itself, that nothing vouches for it.
func (s *Sink) writeIntegrityMarker(kind string, details map[string]interface{}) {
	// Build a fresh map rather than mutating the caller's: the marker owns its
	// Details, and a nil details must not panic on the "kind" assignment. "kind" is
	// set last so it wins over any same-named caller key.
	d := make(map[string]interface{}, len(details)+1)
	for k, v := range details {
		d[k] = v
	}
	d["kind"] = kind
	marker := s.syntheticDenyMarker(auditIntegrityFailureCode, d)
	s.writeRecord(&marker)
}

// errAuditFileShrunk reports that the audit log was non-empty at Stat but returned
// zero bytes at ReadAt — truncated/rotated out between the two syscalls. Wrapped in
// readLastAuditLine's error so the caller can recognize the race; the chain-resume
// path treats it like any other tail-read error.
var errAuditFileShrunk = errors.New("audit log shrank between stat and read")

// auditScanBufferBytes is the line-buffer ceiling every audit-JSONL reader uses.
// Details is capped at auditDetailsTotalCap (1 MiB) and the envelope is far
// smaller, so every record stays well under this 4 MiB bound and never trips
// bufio.ErrTooLong. Centralizing ties the buffer to the record caps rather than
// leaving independent literals that could drift past 4 MiB.
const auditScanBufferBytes = 4 << 20

// rescanBufferBytes is the WIDE per-line buffer scanSeqContribution uses on the
// chain-resume error path so its single pass reads PAST a record larger than the
// ~1 MiB cap, while still bounding memory: a line longer than this is refused rather
// than accumulated unbounded, so a corrupt or tampered log cannot drive the resume
// scan to OOM. Generous relative to the record cap, so any plausibly-large record is
// read, yet a hard ceiling on the one-shot startup allocation.
const rescanBufferBytes = 64 << 20

// NewLineScanner returns a bufio.Scanner sized to hold one audit record, for the
// readers that scan a log line by line (audit-verify, stats, suggest), keeping
// their buffer bound identical.
func NewLineScanner(r io.Reader) *bufio.Scanner {
	scanner := bufio.NewScanner(r)
	// Start small and grow on demand up to the cap: an eager auditScanBufferBytes
	// allocation would reserve the full buffer up front for every reader even when
	// records are far smaller.
	scanner.Buffer(make([]byte, 0, 64<<10), auditScanBufferBytes)
	return scanner
}

// readLastAuditLine returns the last non-blank line of the audit log, reading only
// a bounded tail so startup resume does not scan a large log. Its returns let the
// caller distinguish three cases:
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
	// config.OpenNoFollow here too, not just on the append opens: this read is Open's
	// chain-resume path, so a symlink planted at the log path would otherwise seed the
	// resumed chain from an attacker-chosen file.
	f, err := os.OpenFile(path, os.O_RDONLY|config.OpenNoFollow, 0) //nolint:gosec // G304: path is the user-configured audit log
	if err != nil {
		if os.IsNotExist(err) {
			// Absent file: the normal brand-new-install / freshly-rotated case, not an
			// I/O error. Report empty so the caller resumes from genesis or a sibling.
			return "", nil
		}
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
	start := int64(0)
	if size > auditScanBufferBytes {
		start = size - auditScanBufferBytes
	}
	buf := make([]byte, size-start)
	n, err := f.ReadAt(buf, start)
	if err != nil && err != io.EOF {
		return "", err
	}
	return interpretAuditTail(buf, n, err, size)
}

// scanSeqContribution reads path once and separates the two distinct ways a file can inform
// the resumed seq counter, which callers combine differently:
//
//   - parsedMax/parsed: the largest seq actually decoded from a record (exact and
//     authoritative). parsed is false when the file opened and read cleanly but held no
//     parseable record (empty/blank/all-unparseable).
//   - unreadBytes: the file's byte size when it could NOT be fully read — os.Open was
//     refused (a write-only 0200 log fails EACCES on every restart) or the scan aborted on
//     an over-cap line (bufio.ErrTooLong) or a mid-file read fault — so the true max is
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
	f, err := os.Open(path) //nolint:gosec // G304: path is the user-configured audit log
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

// RecordAllow enqueues an allow audit record for asynchronous serialization and
// disk write. The only synchronous work is struct init and a non-blocking channel
// send; marshalling, HMAC signing, and I/O happen in the drainer. A full queue
// drops the record and bumps the dropped counter. Encoding the decision by which
// method is called (not a positional string) means an allow can never carry a
// denial code, nor a deny obligations.
//
// identifier is the raw MCP target (tool name, resource URI, "prompts/<name>", or
// "sampling/createMessage"); target_type/target are derived from it with method.
// method is the MCP method ("tools/call", …); pass "" only for pre-dispatch
// records with no target (e.g. a JWT rejection). ctx carries validated JWT claims,
// whose agent_id/task_id/user_id are stamped (§ 2.1). auditOnly marks an observed-but-not-
// enforced allow (audit mode): the would-be verdict is logged with full arguments
// and the call forwarded.
func (s *Sink) RecordAllow(ctx context.Context, sessionID, identifier, method string, details map[string]interface{}, obligs []string, auditOnly bool, labelsOut, carriedLabels []string) {
	s.Record(ctx, RecordParams{
		SessionID:     sessionID,
		Identifier:    identifier,
		Method:        method,
		Decision:      "allow",
		Details:       details,
		Obligations:   obligs,
		AuditOnly:     auditOnly,
		LabelsOut:     labelsOut,
		CarriedLabels: carriedLabels,
	})
}

// RecordDeny enqueues a deny audit record (see RecordAllow for the shared
// semantics). denialCode and condType carry the structured denial taxonomy;
// observe is the audit-mode flag — an observed deny is logged and forwarded rather
// than enforced. A deny never carries obligations, so none is accepted.
func (s *Sink) RecordDeny(ctx context.Context, sessionID, identifier, method, denialCode, condType string, details map[string]interface{}, observe bool) {
	// A deny carries no labels_out (the call produced no output) and no carried_labels:
	// a flowLabel deny already names the offending label in its structured details, so
	// the deny path leaves both unset. Obligations likewise stay unset — a deny never
	// carries any.
	s.Record(ctx, RecordParams{
		SessionID:     sessionID,
		Identifier:    identifier,
		Method:        method,
		Decision:      "deny",
		DenialCode:    denialCode,
		ConditionType: condType,
		Details:       details,
		AuditOnly:     observe,
	})
}

// clock returns the sink's current time via the injected now func, falling back
// to time.Now when unset (verify-only sinks and tests that wired no clock).
func (s *Sink) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// RecordParams carries one audit record's fields from the call site into Record.
//
// It is a struct rather than a parameter list because the fields it replaced were
// nine consecutive strings (upstream, policy version, policy digest, session,
// identifier, method, decision, denial code, condition type): any two of them
// transposed at a call site compiles cleanly and silently writes the wrong values
// into structured audit fields — a corrupted trail that nothing downstream can
// detect, since each field still holds a well-formed string. Named fields make a
// transposition a compile error or an obvious misspelling at the call site.
//
// Identifier is the raw MCP target (tool name, resource URI, "prompts/<name>", or
// "sampling/createMessage"); target_type/target are derived from it together with
// Method. Upstream, PolicyVersion, and PolicySHA256 are the gateway route name and
// in-force policy provenance, left empty on the single-upstream/stdio path.
type RecordParams struct {
	Upstream      string
	PolicyVersion string
	PolicySHA256  string
	SessionID     string
	Identifier    string
	Method        string
	Decision      string
	DenialCode    string
	ConditionType string
	Details       map[string]interface{}
	Obligations   []string
	AuditOnly     bool
	LabelsOut     []string
	CarriedLabels []string
}

// Record is the gateway-aware variant: p.Upstream, p.PolicyVersion, and
// p.PolicySHA256 stamp the route name and in-force policy provenance.
// RecordAllow/RecordDeny forward here with those left empty for the
// single-upstream/stdio path; gateway routeSinks call it directly.
func (s *Sink) Record(ctx context.Context, p RecordParams) {
	activityID := 1
	if p.Decision == "deny" {
		activityID = 2
	}

	mcpMethod, targetType, target := deriveTargetFields(p.Method, p.Identifier)

	// Stamp the agent/task/user identity from any validated JWT claims. Bound each
	// to auditEnvelopeFieldCap: these IdP-supplied claims are structure-validated but
	// not length-bounded, so a misconfigured or compromised IdP could otherwise push
	// a record past the 4 MiB scanner buffer. Mirrors SessionID/Target/Method.
	var agentID, taskID, userID string
	if s.identity != nil {
		agentID, taskID, userID = s.identity(ctx)
		agentID = boundFieldTo(agentID, auditEnvelopeFieldCap)
		taskID = boundFieldTo(taskID, auditEnvelopeFieldCap)
		userID = boundFieldTo(userID, auditEnvelopeFieldCap)
	}

	rec := auditRecord{
		ClassUID:      6003,
		CategoryUID:   6,
		ActivityID:    activityID,
		Time:          s.clock().UTC().Format(time.RFC3339Nano),
		RequestID:     nextRequestID(),
		SessionID:     boundFieldTo(p.SessionID, auditSessionIDCap),
		AgentID:       agentID,
		TaskID:        taskID,
		UserID:        userID,
		Upstream:      p.Upstream,
		PolicyVersion: p.PolicyVersion,
		PolicySHA256:  p.PolicySHA256,
		TargetType:    targetType,
		Target:        target,
		Method:        mcpMethod,
		Decision:      p.Decision,
		AuditOnly:     p.AuditOnly,
		DenialCode:    p.DenialCode,
		ConditionType: p.ConditionType,
		// Bound (and, in the same pass, deep-clone) details before enqueue, then
		// marshal the bounded copy ONCE — here, on the caller's goroutine. The queued
		// record therefore carries immutable bytes, not the live params.Arguments map
		// (audit-mode allow) or the engine's Details map (denials): a caller mutation
		// after Record returns cannot reach the already-serialized bytes, and the
		// drainer never marshals a caller-shared structure. Bounding here, not in the
		// drainer, also keeps the 4096-slot queue from retaining 4096 un-truncated
		// multi-MiB payloads (~16 GiB of heap); each queued Details is capped at
		// auditDetailsTotalCap.
		Details: marshalAndBoundDetails(p.Details),
		// Bound obligations like Details, before enqueue. redactFields-style directives
		// emit one obligation per match, so a crafted manifest can grow this slice past
		// the 4 MiB scanner buffer and defeat the queue's per-record bound.
		Obligations: boundAuditObligations(slices.Clone(p.Obligations)),
		// Clone the label slices so the queued record owns immutable bytes (a caller
		// mutation after Record returns cannot reach the serialized record), mirroring
		// Obligations. No length bound: labels are drawn from the closed native
		// vocabulary, not caller free-form text. slices.Clone(nil) is nil, so a non-flow
		// decision keeps both fields omitted.
		LabelsOut:     slices.Clone(p.LabelsOut),
		CarriedLabels: slices.Clone(p.CarriedLabels),
		KeyID:         s.keyID,
	}

	// The drop warnings are emitted OUTSIDE the lock. stderr can block indefinitely — a
	// log collector that died with its pipe full is the ordinary case — and these lines
	// fire precisely during a drop storm, which is when Close (which needs the WRITE lock)
	// most needs to make progress. Writing them inside the read-locked span put a blocking
	// syscall in front of it; the rate limit bounds how OFTEN they are written, not how
	// long one write can stall.
	if warn := s.enqueue(rec, mcpMethod, target); warn != "" {
		fmt.Fprint(os.Stderr, warn)
	}
}

// enqueue is the locked half of Record: the shutdown check, the byte-budget check, and the
// non-blocking send. The read lock excludes Close's channel close for the span of the send,
// so the send never races close(s.records); once closed, the send is skipped and the record
// is counted as dropped rather than panicking on a closed channel.
//
// It returns the drop-warning line for the caller to write after releasing the lock (empty
// when there is nothing to warn about); formatting the message is cheap and lock-safe, only
// the write to stderr is not.
func (s *Sink) enqueue(rec auditRecord, mcpMethod, target string) string {
	size := rec.queueSize()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		// Shutting down; the drainer may already be gone. Count the loss (surfaced by
		// Close's warning and DroppedRecords) without the queue-full message, which
		// would misattribute the cause.
		s.dropped.Add(1)
		s.recordDropBucket(mcpMethod, target)
		return ""
	}
	if s.queuedBytes.Load()+size > auditQueueByteBudget {
		// Over the aggregate byte budget even though a slot may still be free: a slow
		// disk plus large-argument records would otherwise retain gigabytes of heap and
		// OOM the proxy. Drop and count like a full queue — the drop marker keeps the
		// loss tamper-evident.
		warn := ""
		if n := s.dropped.Add(1); n == 1 || n%100 == 0 {
			warn = fmt.Sprintf("[eunox] WARNING: audit record dropped (%d total) — write queue over its %d-byte memory budget; check disk I/O\n", n, int64(auditQueueByteBudget))
		}
		s.recordDropBucket(mcpMethod, target)
		return warn
	}
	select {
	case s.records <- rec:
		s.queuedBytes.Add(size)
		return ""
	default:
		warn := ""
		if n := s.dropped.Add(1); n == 1 || n%100 == 0 {
			warn = fmt.Sprintf("[eunox] WARNING: audit record dropped (%d total) — write queue is full; check disk I/O\n", n)
		}
		s.recordDropBucket(mcpMethod, target)
		return warn
	}
}

// cloneAndBound deep-clones a single audit detail value while bounding it in the
// same pass. It recurses through the JSON containers a decoded argument map can
// nest (objects, arrays), allocating fresh storage at every level so the bounded
// copy marshalAndBoundDetails serializes shares no map/slice backing with the
// caller's map — the copy, not the caller's live structures, is what is marshaled.
// Strings over auditDetailValueCap are replaced with a placeholder; scalars are
// returned as-is (immutable). marshalAndBoundDetails is the map-level entry point
// driving this per-value recursion. []string slices are cloned unconditionally so
// the bounded copy never aliases a caller slice.
func cloneAndBound(v interface{}) interface{} {
	switch t := v.(type) {
	case string:
		if len(t) > auditDetailValueCap {
			return overCapPlaceholder(len(t))
		}
		return t
	case json.Number:
		// Tool-call arguments decode with UseNumber, so numeric fields arrive as
		// json.Number (a string alias). Bound it like a string, otherwise an oversized
		// number literal would slip past the per-value cap and trip the coarser
		// whole-map truncation at marshal time, erasing the rest of the record.
		if len(t) > auditDetailValueCap {
			return overCapPlaceholder(len(t))
		}
		return t
	case map[string]interface{}:
		out := make(map[string]interface{}, len(t))
		for k, e := range t {
			out[k] = cloneAndBound(e)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(t))
		for i, e := range t {
			out[i] = cloneAndBound(e)
		}
		return out
	case []string:
		// Clone unconditionally (never share backing) and bound each element like the
		// string case. condition-failure Details (pkg/enforcement/handlers.go) embed a
		// manifest condition's []string field (e.g. ipRange's CIDRs) directly, and that
		// same backing array is read concurrently by every goroutine evaluating that
		// condition for the lifetime of the process — cloning here keeps each queued
		// record's slice independent of that shared, concurrently-read source rather
		// than relying on nothing ever mutating it.
		out := make([]string, len(t))
		for i, s := range t {
			if len(s) > auditDetailValueCap {
				out[i] = overCapPlaceholder(len(s))
			} else {
				out[i] = s
			}
		}
		return out
	case []byte:
		// []byte is a mutable, reference-typed value: returning it as-is would share
		// the backing array with the caller. marshalAndBoundDetails runs synchronously
		// on the caller's own goroutine (before Record() enqueues, not in the drainer),
		// so today nothing races the marshal itself — but a caller that mutates or
		// reuses its buffer immediately after the call returns would otherwise corrupt
		// an already-queued record. Clone unconditionally, mirroring the []string case.
		// Also bound it — but on the BASE64-ENCODED length, the size the
		// record actually pays: json.Marshal base64-encodes a []byte into one string
		// (~4/3 the byte length), so a raw-len() cap would let a value up to ~4/3 the
		// cap (e.g. a 512 KiB blob → ~683 KiB string) slip past and trip only the
		// coarser whole-map truncation. EncodedLen is the exact marshaled size, and the
		// placeholder reports it so the "N-byte value exceeding the M-byte cap" message
		// stays truthful (N is the encoded size that would have appeared, not the raw).
		if encLen := base64.StdEncoding.EncodedLen(len(t)); encLen > auditDetailValueCap {
			return overCapPlaceholder(encLen)
		}
		out := make([]byte, len(t))
		copy(out, t)
		return out
	default:
		return v
	}
}

// overCapPlaceholder is the structured stand-in cloneAndBound substitutes for any
// audit detail value whose length exceeds auditDetailValueCap. Centralised so the
// wording and the two-cap format stay identical across the string/json.Number/
// []string/[]byte arms (a divergence would let one oversized form slip past while
// another is replaced).
func overCapPlaceholder(n int) string {
	return fmt.Sprintf("[eunox: omitted %d-byte value exceeding the %d-byte audit detail cap]", n, auditDetailValueCap)
}

// overCapPlaceholderRe matches exactly the text overCapPlaceholder emits. Anchored
// and structural so a consumer recognizes a placeholder by its FULL shape, not a
// loose prefix: a genuine argument value that merely begins with "[eunox: omitted "
// (but does not reproduce the "<n>-byte value exceeding the <cap>-byte audit detail
// cap]" form) is not a placeholder and must not be mistaken for one. Kept beside
// overCapPlaceholder so the producer and detector cannot drift apart.
var overCapPlaceholderRe = regexp.MustCompile(`^\[eunox: omitted \d+-byte value exceeding the \d+-byte audit detail cap\]$`)

// IsOverCapValuePlaceholder reports whether s is exactly the placeholder the audit
// layer substitutes for a single argument value exceeding the per-value detail cap
// (overCapPlaceholder). It is the audit layer's own detector, exported so consumers
// (e.g. the suggest miner) recognize a redacted-for-size value from the layer that
// produced it instead of hand-copying the placeholder text and drifting from it.
func IsOverCapValuePlaceholder(s string) bool {
	return overCapPlaceholderRe.MatchString(s)
}

// auditDetailValueCap bounds the byte length of any single string in Details. In
// audit-only mode the allow path logs params.Arguments verbatim, so a
// multi-megabyte argument (a write_file body, base64 blob, large corpus) would
// otherwise produce a record larger than the scanner buffer and chain-resume tail
// window. Oversized values become a self-describing placeholder, keeping the record
// bounded and the truncation visible.
const auditDetailValueCap = 512 << 10 // 512 KiB

// auditDetailsTotalCap bounds the marshaled size of Details after per-value
// truncation, catching a map made large by many moderate values. When exceeded the
// whole map is replaced with a single marker.
const auditDetailsTotalCap = 1 << 20 // 1 MiB

// auditQueueByteBudget bounds the aggregate heap held by queued-but-undrained audit
// records (see Sink.queuedBytes). 256 MiB is well above the working set of a healthy
// drainer (which empties the queue continuously) yet far below the ~4.3 GiB the
// 4096-slot count bound alone would permit, so a slow disk under large-argument load
// sheds records (counted, tamper-evident) instead of OOM-ing the process.
const auditQueueByteBudget = 256 << 20 // 256 MiB

// auditRecordEnvelopeEstimate is a flat per-record allowance for the genuinely
// FIXED-width envelope (timestamps, request id, key id, decision/denial codes, the
// two hex HMACs) that queueSize adds on top of the variable-length fields it counts
// individually. It need not be exact — queuedBytes is a soft bound.
const auditRecordEnvelopeEstimate = 512

// queueSize estimates the heap a queued record retains: its already-marshaled Details
// and Obligations bytes, the variable-length envelope strings, and a flat allowance
// for the fixed remainder. The drainer recomputes it from the same immutable fields,
// so the enqueue add and the drain subtract always agree.
//
// The variable strings are counted rather than folded into the flat allowance because
// they are attacker- or IdP-influenced and individually bounded at up to
// auditEnvelopeFieldCap (8 KiB): Target, an unrecognized raw Method, and the three
// JWT identity claims can together retain ~40 KiB that a flat 512 did not see. Under
// a flood of such records the queue would hold ~80x the byte budget it is sized to
// bound — the shed-instead-of-OOM guarantee the budget exists for. Labels are drawn
// from the closed native vocabulary and are counted for completeness, not bounds.
func (rec *auditRecord) queueSize() int64 {
	n := int64(len(rec.Details)) + auditRecordEnvelopeEstimate
	for _, o := range rec.Obligations {
		n += int64(len(o))
	}
	n += int64(len(rec.SessionID) + len(rec.AgentID) + len(rec.TaskID) + len(rec.UserID))
	n += int64(len(rec.Target) + len(rec.Method) + len(rec.TargetType))
	n += int64(len(rec.Upstream) + len(rec.PolicyVersion) + len(rec.PolicySHA256))
	for _, l := range rec.LabelsOut {
		n += int64(len(l))
	}
	for _, l := range rec.CarriedLabels {
		n += int64(len(l))
	}
	return n
}

// TruncatedKey is the marker key set in Details when the map was replaced wholesale
// for exceeding auditDetailsTotalCap. The underscore prefix keeps it clear of real
// tool-argument names.
const TruncatedKey = "_eunox_truncated"

// UpstreamErrorCodeKey is the reserved detail key the transport merges into an
// ALLOW record's Details when the upstream call itself returned a JSON-RPC error
// (the policy allowed the call; the upstream then failed). It is an audit-only
// annotation, never a caller-supplied tool argument. The underscore prefix (mirroring
// TruncatedKey) puts it in the same reserved namespace real tool-argument names are
// not expected to use, so a tools/call whose real argument happens to be named
// "upstream_error_code" (bare, no prefix) no longer collides with the injected code in
// the ordinary case. A tool argument literally matching THIS exact reserved string
// remains possible in principle — nothing outside this codebase's own convention stops
// it — so dispatch.go's flat merge still falls back to its nested-wrapper shape on that
// rare collision, exactly as it did for the old bare name; only the name that can no
// longer be silently shadowed by ordinary usage changed. Consumers mining Details for
// real arguments (the suggest subcommand) must still exclude it. Kept here so the
// producer (internal/transport) and the miner (cmd/eunox/suggest) share one spelling
// and cannot drift.
const UpstreamErrorCodeKey = "_eunox_upstream_error_code"

// Reason codes for the TruncatedKey marker's structured value. The marker carries a
// {"reason": <code>, ...} object rather than a free-form prose sentence, so SIEM
// rules can match details._eunox_truncated.reason across versions instead of parsing
// English text whose wording (and embedded byte counts) could drift.
const (
	// auditTruncReasonOverCap: the marshaled Details map exceeded auditDetailsTotalCap;
	// the marker also carries the numeric "bytes" and "cap" facts.
	auditTruncReasonOverCap = "over_total_cap"
	// auditTruncReasonNotSerializable: a Details value could not be JSON-encoded.
	auditTruncReasonNotSerializable = "not_serializable"
)

// marshalAndBoundDetails marshals m into the bytes the audit record's `details`
// field carries, exactly once. It deep-clones and bounds each value first (via
// cloneAndBound: fresh storage at every level so the queued record shares no
// backing with the caller, over-cap values replaced with a placeholder), then
// marshals the clone. writeRecord embeds the returned json.RawMessage verbatim in
// its single whole-record marshal, so the details map is no longer marshaled twice
// per allow/deny (once here to size-check, once again in the record) — this is the
// one marshal.
//
// Returns nil for a nil or empty map so the omitempty `details` field stays absent
// rather than serializing as `{}`. If the marshaled clone still exceeds
// auditDetailsTotalCap, the whole map is replaced with a single marker (rebuilt
// from a fresh map — truncation is rare, so its extra marshal does not matter).
// Record() and syntheticDenyMarker apply it before enqueue so the queue never
// retains an un-truncated or aliased payload.
func marshalAndBoundDetails(m map[string]interface{}) json.RawMessage {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = cloneAndBound(v)
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		return marshalTruncationMarker(map[string]interface{}{"reason": auditTruncReasonNotSerializable})
	}
	if len(encoded) > auditDetailsTotalCap {
		return marshalTruncationMarker(map[string]interface{}{
			"reason": auditTruncReasonOverCap,
			"bytes":  len(encoded),
			"cap":    auditDetailsTotalCap,
		})
	}
	return encoded
}

// marshalTruncationMarker builds the {_eunox_truncated: {...}} replacement details
// blob for the rare path where the real details cannot be carried (unserializable
// or over the total cap). The value is a STRUCTURED object — a stable "reason" code
// plus any numeric facts — not free-form prose, so consumers key on a code rather
// than parse English. A constant key over a small reason/int map cannot fail to
// marshal; the hardcoded fallback only guarantees the field is never invalid JSON.
func marshalTruncationMarker(info map[string]interface{}) json.RawMessage {
	b, err := json.Marshal(map[string]interface{}{TruncatedKey: info})
	if err != nil {
		return json.RawMessage(`{"` + TruncatedKey + `":{"reason":"` + auditTruncReasonNotSerializable + `"}}`)
	}
	return b
}

// auditObligationsTotalCap bounds the marshaled size of Obligations. Like Details,
// an unbounded list would let a record exceed the 4 MiB scanner buffer. Obligations
// are emitted one per directive match (e.g. a redactFields path), so a crafted
// manifest can drive the slice arbitrarily large. 64 KiB preserves thousands of
// realistic entries while keeping the record far below the window.
const auditObligationsTotalCap = 64 << 10 // 64 KiB

// boundAuditObligations caps the serialized size of an obligations slice. A slice
// within auditObligationsTotalCap is returned unchanged; otherwise the leading
// entries that fit are kept and a single "obligations_truncated:N" sentinel (N =
// omitted count) is appended, keeping the record valid and the truncation visible.
// Record() applies it before enqueue, like marshalAndBoundDetails.
func boundAuditObligations(obligs []string) []string {
	if len(obligs) == 0 {
		return obligs
	}
	const commaOverhead = 1 // one comma per entry (quotes are in the encoded length)
	// Fast path: a cheap worst-case upper bound on the marshaled size — each input byte
	// escapes to at most \u00XX (6 bytes), plus the two surrounding quotes and one comma
	// per entry — computed with NO marshaling. If even that bound fits, the real encoding
	// (always <= the bound) fits, so return as-is. The common case (a few short
	// obligations) thus pays only integer arithmetic, not a json.Marshal per entry — which
	// is what the previous incremental jsonEncodedStringLen accounting did, making the
	// "avoid the throwaway whole-slice marshal" fast path actually allocate MORE on the hot
	// path. Seed with 1, not 2: the comma over-counts the first entry (no preceding comma)
	// by one byte, matching the true `[`+entries+`]` size. Break early so a pathologically
	// large entry cannot overflow the running sum into a false "fits".
	upper := 1
	for _, o := range obligs {
		upper += len(o)*6 + 2 + commaOverhead
		if upper > auditObligationsTotalCap {
			break
		}
	}
	if upper <= auditObligationsTotalCap {
		return obligs
	}
	// The cheap bound was exceeded (a large obligations slice). Only here do we pay the
	// EXACT per-entry accounting (jsonEncodedStringLen marshals each string): if the slice
	// still fits exactly, return it unchanged; otherwise truncate below.
	total := 1
	for _, o := range obligs {
		total += jsonEncodedStringLen(o) + commaOverhead
	}
	if total <= auditObligationsTotalCap {
		return obligs
	}
	// Over budget: keep the prefix that fits, accounting each entry by its EXACT
	// JSON-encoded length (quotes + escaping). A raw len(o) undercounts strings
	// carrying ", \, or control chars, so the kept slice could still serialize over
	// cap. Reserve room for the sentinel up front.
	used := 1
	kept := make([]string, 0, len(obligs))
	for i, o := range obligs {
		omitted := len(obligs) - i
		sentinel := fmt.Sprintf("obligations_truncated:%d", omitted)
		reserve := jsonEncodedStringLen(sentinel) + commaOverhead
		if used+jsonEncodedStringLen(o)+commaOverhead+reserve > auditObligationsTotalCap {
			return truncatedObligations(kept, len(obligs))
		}
		used += jsonEncodedStringLen(o) + commaOverhead
		kept = append(kept, o)
	}
	// Defensive: the total above exceeded the cap, and each per-entry check additionally
	// reserves the sentinel, so the loop truncates before reaching here in practice.
	// Returning kept (== obligs) is the safe fallback if it ever does.
	return kept
}

// jsonEncodedStringLen returns the byte count json.Marshal produces for s (quotes
// plus escaping). boundAuditObligations uses it so accounting matches what lands in
// the record, not the raw UTF-8 length. Marshal of a string does not error; the
// fallback (6 bytes/rune plus two quotes) is a conservative worst case.
func jsonEncodedStringLen(s string) int {
	if b, err := json.Marshal(s); err == nil {
		return len(b)
	}
	return len(s)*6 + 2
}

// truncatedObligations builds the kept prefix plus a single
// "obligations_truncated:N" sentinel (N = total - len(kept)) and GUARANTEES the
// result marshals within auditObligationsTotalCap. boundAuditObligations's
// incremental budget already reserves room for the sentinel, but only by
// arithmetic; this final re-marshal makes the invariant explicit, dropping trailing
// kept entries (folded into N) until the encoding fits. Runs only on the rare
// truncation path.
func truncatedObligations(kept []string, total int) []string {
	for {
		sentinel := fmt.Sprintf("obligations_truncated:%d", total-len(kept))
		result := make([]string, 0, len(kept)+1)
		result = append(result, kept...)
		result = append(result, sentinel)
		if encoded, err := json.Marshal(result); err == nil && len(encoded) <= auditObligationsTotalCap {
			return result
		}
		if len(kept) == 0 {
			// Even the lone sentinel exceeds the cap (a pathologically huge total).
			// Return it anyway — the smallest possible marker — to keep the function
			// total; the arithmetic guarantees this is unreachable for realistic counts.
			return []string{sentinel}
		}
		kept = kept[:len(kept)-1]
	}
}

// deriveTargetFields resolves the structured target identity from the MCP method.
// target_type is taken from the method (authoritative), never inferred from the
// overloaded identifier, so an opaque resource URI or an oddly-named tool is
// recorded under its true namespace. The mapping comes from
// capability.MethodTargetType — the single source of truth shared with
// internal/transport's dispatch map — rather than a second, raw-literal copy here.
// Returns empty strings for records with no MCP method (e.g. a pre-dispatch JWT
// rejection). For a method that exists but is not a recognized request method (e.g.
// "tools/execute"), the raw method is preserved so audit consumers can distinguish
// unmapped-method denials from pre-dispatch ones.
func deriveTargetFields(method, identifier string) (mcpMethod, targetType, target string) {
	if method == "" {
		return "", "", ""
	}
	tt, ok := capability.MethodTargetType(method)
	if !ok {
		// Post-dispatch: an unrecognized method string. Preserve it (bounded, since
		// it is attacker-controlled) so SIEM and suggest can distinguish these from
		// pre-dispatch denials.
		return boundEnvelopeField(method), "", ""
	}
	return method, string(tt), boundEnvelopeField(bareTargetName(tt, identifier))
}

// auditEnvelopeFieldCap bounds attacker-controlled envelope string fields (Target
// from params.Name/URI, an unrecognized raw Method). Unlike Details these are not
// capped by marshalAndBoundDetails yet are written even on the deny path, and an
// incoming request is allowed up to 4 MiB, so an unbounded Target could push the
// line past the 4 MiB scanner buffer and chain-resume window. 8 KiB leaves the
// envelope far below 4 MiB while preserving every realistic value; with the 1 MiB
// Details cap the full record is provably below the window.
const auditEnvelopeFieldCap = 8 << 10 // 8 KiB

// auditSessionIDCap bounds SessionID. In HTTP mode it comes from the
// client-controlled Mcp-Session-Id header, so like Target and Method it is capped.
// Server session IDs are UUIDv4 (36 bytes), so 256 is generous headroom.
const auditSessionIDCap = 256

// boundEnvelopeField truncates an over-cap envelope string with a visible marker.
func boundEnvelopeField(s string) string {
	return boundFieldTo(s, auditEnvelopeFieldCap)
}

// boundFieldTo truncates s to at most limit bytes, appending a visible marker
// recording the original length. The marker is kept WITHIN the limit (the prefix
// shortens to make room), so the result is always <= limit bytes — the invariant
// the 4 MiB scanner buffer relies on.
//
// s is first normalized to valid UTF-8 (strings.ToValidUTF8, replacing any invalid
// byte sequence with U+FFFD). Every caller of this function passes a field that can
// hold raw attacker/IdP-supplied bytes not yet validated as UTF-8 — SessionID from
// the client-controlled Mcp-Session-Id HTTP header, Target/Method from request
// envelope fields, AgentID/TaskID/UserID from JWT claims — and encoding/json's
// Marshal is NOT idempotent across a decode-then-re-encode round trip when a string
// holds invalid UTF-8: it writes a lone invalid byte as the literal 6-byte escape
// text `�`, but decoding that text and re-marshaling the resulting (valid)
// U+FFFD rune instead emits its raw 3-byte UTF-8 encoding. Two different on-disk
// byte sequences for what is nominally "the same" value break the assumption behind
// both the HMAC recompute (decode → clear _hmac → re-marshal → re-sign) and
// VerifyRecord's canonical-bytes check, which is not a hypothetical: a session ID
// containing one stray invalid byte forwarded from an untrusted header round-trips
// to different bytes than it was signed with, so a genuine, never-tampered record
// fails verification and (via resumeChainFromTail, which runs this same check on
// every restart) can make the live proxy restart its own chain from genesis. Normalizing
// here, before the field is ever marshaled the first time, makes the stored value
// already-valid UTF-8 from the start, so every later marshal of it is byte-identical —
// restoring the round-trip idempotency both mechanisms depend on.
func boundFieldTo(s string, limit int) string {
	s = strings.ToValidUTF8(s, "�")
	if len(s) <= limit {
		return s
	}
	marker := fmt.Sprintf("...[eunox: truncated, %d bytes]", len(s))
	keep := limit - len(marker)
	if keep < 0 {
		// The full marker does not fit (a limit smaller than the marker). The result
		// must stay non-empty so it is not mistaken for a genuinely empty field, but
		// must not exceed limit, so emit the shortest recognizable "..." marker. Only
		// a non-positive limit yields "", which is a caller bug (every real cap is far
		// larger than this marker).
		const shortMarker = "..."
		if limit <= 0 {
			return ""
		}
		if limit < len(shortMarker) {
			return shortMarker[:limit]
		}
		return shortMarker
	}
	// Truncate on a UTF-8 rune boundary: a byte-level s[:keep] can split a multi-byte
	// rune, leaving orphaned continuation bytes that json.Marshal rewrites to the
	// replacement character. Walk back to the rune start (drops at most 3 bytes).
	for keep > 0 && !utf8.RuneStart(s[keep]) {
		keep--
	}
	return s[:keep] + marker
}

// bareTargetName returns the canonical bare target value. Every method except
// prompts/get already passes the bare value as the identifier; prompts/get passes a
// "prompts/" display prefix, stripped here so target is the plain prompt name a
// manifest entry uses after the "prompt:" namespace.
func bareTargetName(tt capability.TargetType, identifier string) string {
	if tt == capability.TargetTypePrompt {
		return strings.TrimPrefix(identifier, "prompts/")
	}
	return identifier
}

// DroppedRecords returns the number of records discarded because the write queue
// was full. Expose as a metric to detect sustained disk pressure.
func (s *Sink) DroppedRecords() int64 {
	return s.dropped.Load()
}

// markMaintenanceStalled records that rotation or retention could not make progress.
// Called on every failed attempt; the reason is overwritten so the newest cause wins.
func (s *Sink) markMaintenanceStalled(reason string) {
	if s == nil {
		return
	}
	s.maintenanceStalled.Store(true)
	s.maintenanceStallMu.Lock()
	s.maintenanceStallReason = reason
	s.maintenanceStallMu.Unlock()
}

// clearMaintenanceStalled records that the stalled operation succeeded, so a transient
// fault (a directory temporarily unreadable, a file briefly locked) stops being reported.
func (s *Sink) clearMaintenanceStalled() {
	if s == nil || !s.maintenanceStalled.Load() {
		return
	}
	s.maintenanceStalled.Store(false)
	s.maintenanceStallMu.Lock()
	s.maintenanceStallReason = ""
	s.maintenanceStallMu.Unlock()
}

// MaintenanceStalled reports whether size-triggered rotation or retention pruning has
// stopped making progress, with the reason. Records are still being written and signed —
// this is NOT an audit-integrity loss and deliberately does not feed the
// --require-audit=strict gate (see AuditDegraded). It means the configured
// rotateSizeBytes/retainRotated disk bound is currently not being enforced, so the log
// will grow without limit until the underlying fault is fixed. Surfaced by /healthz,
// /metrics, and doctor so an operator sees it before the filesystem fills.
func (s *Sink) MaintenanceStalled() (stalled bool, reason string) {
	if s == nil || !s.maintenanceStalled.Load() {
		return false, ""
	}
	s.maintenanceStallMu.Lock()
	defer s.maintenanceStallMu.Unlock()
	return true, s.maintenanceStallReason
}

// WriteFailures returns the number of records that reached the drainer but could
// not be durably written (full disk, EIO, a serialization error, or a file lost to
// a failed rotation). Distinct from DroppedRecords: that is a "queue can't keep up"
// signal on a healthy file, this is a "file is broken" signal. Expose as
// eunox_audit_write_failures_total and alert on it.
func (s *Sink) WriteFailures() int64 {
	return s.writeFailures.Load()
}

// AuditDegraded reports whether the audit trail has lost coverage (a back-pressure
// drop or a write failure). It is the runtime signal --require-audit=strict
// consults to fail subsequent calls closed once a loss is observed. The signal is
// retrospective: both counters reflect only completed calls, so it cannot flag the
// boundary call whose own record is the first lost.
//
// It returns three things: degraded, a human-facing reason string (prose, for the
// host-facing error response and the stderr warning — NOT for a structured audit
// field), and detail, the discrete counts to stamp into the structured audit
// record. detail is nil when healthy; when degraded it carries only the counters
// that are non-zero ("dropped_count", "write_failure_count"), never prose, so the
// structured audit field stays free of free-form text. A nil receiver reports
// healthy (a strict proxy whose sink failed to open is refused at startup, so the
// gate never sees one).
func (s *Sink) AuditDegraded() (degraded bool, reason string, detail map[string]interface{}) {
	if s == nil {
		return false, "", nil
	}
	dropped := s.dropped.Load()
	failures := s.writeFailures.Load()
	if dropped == 0 && failures == 0 {
		return false, "", nil
	}
	detail = make(map[string]interface{}, 2)
	if dropped > 0 {
		detail["dropped_count"] = dropped
	}
	if failures > 0 {
		detail["write_failure_count"] = failures
	}
	switch {
	case dropped > 0 && failures > 0:
		reason = fmt.Sprintf("audit trail degraded: %d record(s) dropped under back-pressure and %d write failure(s)", dropped, failures)
	case dropped > 0:
		reason = fmt.Sprintf("audit trail degraded: %d record(s) dropped under back-pressure", dropped)
	default:
		reason = fmt.Sprintf("audit trail degraded: %d audit write failure(s)", failures)
	}
	return true, reason, detail
}

// syncEveryN bounds the non-durable tail in COUNT under sustained load: the drainer
// forces an fsync at least this often even when the channel never drains to empty.
// Chosen so amortized fsync cost stays low on a saturated proxy while a kill -9 /
// power loss loses at most a bounded handful of records.
const syncEveryN = 64

// syncDebounce bounds the non-durable tail in TIME under light-to-moderate load: an
// unsynced record waits at most this long before the drainer forces an fsync. The
// queue draining to empty between records used to trigger an immediate per-record
// fsync — one multi-hundred-µs-to-ms disk barrier per proxied call at low rates; the
// debounce coalesces those into at most one fsync per window while still flushing a
// lull promptly. Bounded-tail durability is preserved (records are non-durable until
// the fsync either way — a documented fail-open), just batched.
const syncDebounce = 50 * time.Millisecond

// drain is the background goroutine that serializes, signs, and writes every
// record. It is the sole writer of s.f and s.written (no mutex needed) and exits
// when the records channel is closed.
func (s *Sink) drain() {
	defer s.wg.Done()

	// syncNow pushes the written-but-unsynced tail to disk. A failed fsync means the
	// batch is not durable even though each Write succeeded and the chain head
	// advanced: count it and warn once. sinceSync resets on any attempt (success or
	// failure) — the tail has been pushed to the kernel either way, and a failure is
	// already counted, so retrying on the next record would just spin. s.f is nil only
	// on the lost-file path writeRecord already counts.
	syncNow := func() {
		if s.sinceSync == 0 || s.f == nil {
			s.sinceSync = 0
			return
		}
		if err := s.f.Sync(); err != nil {
			s.writeFailures.Add(1)
			if !s.syncErrWarned {
				s.syncErrWarned = true
				fmt.Fprintf(os.Stderr, "[eunox] WARNING: audit fsync failed — recently written records may not be durable on disk; check disk health (further fsync errors are suppressed): %v\n", err)
			}
		}
		s.sinceSync = 0
	}

	// The debounce timer fires syncDebounce after the first record of an unsynced
	// batch. It is created stopped; timerArmed tracks whether it is counting so the
	// batch's first record arms it and subsequent records do not re-arm (which would
	// keep pushing the deadline out and let the tail live longer than syncDebounce).
	//
	// The module targets Go >= 1.23 (see go.mod), where Timer.Stop/Reset guarantee no
	// stale value is ever delivered on the channel, so this drainer never uses the
	// pre-1.23 `if !Stop() { <-C }` drain idiom: that idiom would DEADLOCK here because
	// the select below also receives from timer.C, so Stop can observe a fired timer
	// and clear its pending value, leaving the drain's `<-C` blocked forever.
	timer := time.NewTimer(syncDebounce)
	timer.Stop()
	timerArmed := false

	for {
		select {
		case rec, ok := <-s.records:
			if !ok {
				// Channel closed. Final drop-marker accounting so the closing log reflects
				// drops after the last record, then a final fsync of any unsynced tail.
				s.flushDropMarker()
				syncNow()
				if timerArmed {
					timer.Stop()
				}
				return
			}
			// Flush any pending drop marker first so a back-pressure drop is tamper-
			// evident: without it a drop leaves no seq gap and no break (the chain head
			// advances only on a successful write), so audit-verify could not tell a clean
			// log from one with a silently excised window.
			// Count records actually written this iteration, NOT iterations: one iteration
			// can write two records (a drop marker via flushDropMarker, then the real
			// record), so a per-iteration increment let the un-fsync'd tail grow to
			// 2*syncEveryN under sustained back-pressure — twice the documented syncEveryN
			// bound. writeRecord advances s.seq by exactly one per SUCCESSFUL write, so the
			// seq delta is the count of records that actually reached the file (a failed
			// write advances neither seq nor the durability debt). "Successful", not
			// "durable": a completed write leaves the record in the page cache, and it
			// becomes durable only at the next fsync — the syncDebounce timer or the
			// every-syncEveryN counter below, whichever fires first.
			seqBefore := s.seq
			s.flushDropMarker()
			s.writeRecord(&rec)
			// Release this record's reserved bytes now that it has been drained, mirroring
			// the enqueue reservation (recomputed from the same immutable fields).
			s.queuedBytes.Add(-rec.queueSize())
			// The delta is 0-2: writeRecord advances s.seq by at most 1 per call, and an
			// iteration makes at most two calls (drop marker + real record), so the
			// uint64->int conversion can never overflow.
			s.sinceSync += int(s.seq - seqBefore) //nolint:gosec // G115: seq delta is bounded to 0-2 (see above)
			switch {
			case s.sinceSync >= syncEveryN:
				// Count bound hit: fsync immediately and disarm the debounce timer.
				// Bare Stop (no channel drain) is correct and required under Go 1.23+:
				// if the timer already fired, Stop clears its pending value so the
				// select's timer.C case cannot spuriously fire a redundant sync later.
				syncNow()
				if timerArmed {
					timer.Stop()
					timerArmed = false
				}
			case s.sinceSync > 0 && !timerArmed:
				// First record of a new unsynced batch: start the time bound.
				timer.Reset(syncDebounce)
				timerArmed = true
			}
		case <-timer.C:
			// Time bound reached: flush the tail that has been waiting.
			timerArmed = false
			syncNow()
		}
	}
}

// auditDropBucketCap bounds how many distinct method/target buckets the
// drop-context accumulator tracks between markers, so a flood spread across many
// distinct targets cannot grow dropBuckets unboundedly; further distinct buckets
// fold into dropBucketOverflowKey.
const auditDropBucketCap = 32

// dropBucketOverflowKey is the fold-in key once auditDropBucketCap distinct
// method/target pairs have been tallied since the last marker.
const dropBucketOverflowKey = "(other)"

// recordDropBucket tallies one dropped record under its method/target pair. Called
// from the enqueue path in Record on any goroutine, so it must stay cheap; the
// count is best-effort relative to the dropped counter (see flushDropMarker), not
// an exact reconciliation.
//
// This does add one more mutex acquisition to the drop path, alongside the
// already-atomic dropped counter — a deliberate, accepted tradeoff: the critical
// section is a single bounded-map lookup-and-increment (auditDropBucketCap keys, a
// handful of bytes), and it only runs once a drop has already happened (a queue
// already full or over budget, i.e. disk I/O is very likely the actual bottleneck),
// not on the normal per-record enqueue path. Sharding the map to shave this further
// would add real complexity for a cost this small.
func (s *Sink) recordDropBucket(method, target string) {
	key := method
	if target != "" {
		key = method + " " + target
	}
	s.dropBucketsMu.Lock()
	defer s.dropBucketsMu.Unlock()
	if s.dropBuckets == nil {
		s.dropBuckets = make(map[string]int64)
	}
	if _, ok := s.dropBuckets[key]; !ok && len(s.dropBuckets) >= auditDropBucketCap {
		key = dropBucketOverflowKey
	}
	s.dropBuckets[key]++
}

// snapshotDropBuckets returns a copy of the accumulated method/target drop buckets
// without clearing them — mirroring lastDroppedMarked's not-yet-committed
// semantics, the buckets are only cleared (resetDropBuckets) once the marker
// carrying this snapshot is durably written, so a failed write retries with the
// same accumulated buckets rather than losing them.
func (s *Sink) snapshotDropBuckets() map[string]int64 {
	s.dropBucketsMu.Lock()
	defer s.dropBucketsMu.Unlock()
	if len(s.dropBuckets) == 0 {
		return nil
	}
	out := make(map[string]int64, len(s.dropBuckets))
	for k, v := range s.dropBuckets {
		out[k] = v
	}
	return out
}

// resetDropBuckets removes exactly the counts captured in snapshotted from the
// live accumulator, decrementing (and deleting once a key reaches zero) rather
// than wiping the whole map. writeRecord's disk I/O runs between the snapshot and
// this call, so a concurrent recordDropBucket landing in that window — on an
// already-snapshotted key or a brand new one — must survive into the next
// marker instead of being discarded by an unconditional nil-out. Drainer-only.
func (s *Sink) resetDropBuckets(snapshotted map[string]int64) {
	if len(snapshotted) == 0 {
		return
	}
	s.dropBucketsMu.Lock()
	defer s.dropBucketsMu.Unlock()
	for k, v := range snapshotted {
		cur, ok := s.dropBuckets[k]
		if !ok {
			continue
		}
		if cur <= v {
			delete(s.dropBuckets, k)
		} else {
			s.dropBuckets[k] = cur - v
		}
	}
	if len(s.dropBuckets) == 0 {
		s.dropBuckets = nil
	}
}

// flushDropMarker writes a synthetic, signed record reflecting any records dropped
// since the last marker, advancing the marked count only once that record is
// durably written. No-op when nothing new was dropped. Alongside the aggregate
// count, the marker names WHICH method/target pairs were affected (bounded by
// auditDropBucketCap) so a reader can act on the loss without the underlying
// record — e.g. a flood of denied tools/call probes against one tool is visible as
// a single dominant bucket, not just an opaque total.
func (s *Sink) flushDropMarker() {
	cur := s.dropped.Load()
	if cur <= s.lastDroppedMarked {
		return
	}
	newDrops := cur - s.lastDroppedMarked
	details := map[string]interface{}{
		"dropped":       newDrops,
		"dropped_total": cur,
	}
	buckets := s.snapshotDropBuckets()
	if len(buckets) > 0 {
		details["by_method_target"] = buckets
	}
	marker := s.syntheticDenyMarker("AUDIT_RECORDS_DROPPED", details)
	// Advance the marked count only after a successful write (writeRecord advances seq
	// only on success; durability follows at the next syncDebounce/syncEveryN fsync). On a write failure the count is left behind and the next
	// flush retries with the full accumulated count, so the drop evidence is never
	// silently lost from the chain. flushDropMarker runs once per drained record and
	// at Close, so a broken writer cannot spin (and while broken, real records fail
	// too).
	//
	// Best-effort limit: if the writer stays broken through shutdown (no later record
	// drains and the Close flush also fails), no marker lands and the chain shows no
	// gap. That residual loss is surfaced only out-of-band (writeFailures and the
	// Close error), so the in-log-alone guarantee holds for a recovered writer, not
	// one that fails from the drop through exit.
	seqBefore := s.seq
	s.writeRecord(&marker)
	if s.seq != seqBefore {
		s.lastDroppedMarked = cur
		s.resetDropBuckets(buckets)
	}
}

// repairTailOrphan retries truncating a pending unterminated tail fragment
// (tailOrphanBytes long, left by an earlier partial write) back to the last clean
// record boundary, using Stat to recompute the truncate target (current file size
// minus tailOrphanBytes) rather than trusting s.written, which is not a reliable
// proxy for the file size here (a failed rotation backs it off to ~90% of maxBytes
// without touching the file). Truncate is position-independent, so it is safe on
// the O_APPEND fd.
//
// Returns whether the file is now clean: on success it zeroes tailOrphanBytes
// (clearing the pending flag) and rolls s.written back by that count (undoing the
// write's earlier unconditional size-accounting bump), so normal writeRecord
// accounting resumes unmodified afterward. On failure (Stat error, the reported
// size smaller than tailOrphanBytes — e.g. Stat racing a concurrent external
// truncation — or the Truncate call itself failing) it touches nothing on disk or
// in s.written, leaving tailOrphanBytes > 0 (pending) for the next retry. Safe to
// call repeatedly: it is the sole repair path, invoked both on first detection
// (writeRecord's partial-write arm) and on every subsequent writeRecord while
// pending.
//
// This is deliberately NOT truncatePartialTail (the startup helper), despite the
// superficial Stat+Truncate similarity: their contracts differ in exactly the
// double-fault case this guards. truncatePartialTail SCANS the tail for the last
// newline and treats an EMPTY file as "nothing to recover" (returns 0). Here the
// orphan byte count is KNOWN from the failed write, and a reported size SMALLER
// than that count (e.g. the writer claimed n bytes landed but the file is shorter,
// or empty) is a genuine double fault we must fail-closed on (stay pending), NOT
// treat as a clean tail. Merging the two would silently clear the pending flag on
// that double-fault path and reopen the fusion window.
func (s *Sink) repairTailOrphan() bool {
	fi, statErr := s.f.Stat()
	if statErr != nil || fi.Size()-s.tailOrphanBytes < 0 {
		return false
	}
	if err := s.f.Truncate(fi.Size() - s.tailOrphanBytes); err != nil {
		return false
	}
	s.written -= s.tailOrphanBytes
	s.tailOrphanBytes = 0 // clears the pending flag (pending ⟺ tailOrphanBytes > 0)
	return true
}

// recordMAC computes the tamper-evidence digest over an HMAC-stripped marshaled record
// body: HMAC-SHA256 under key, hex-encoded with the "sha256:" algorithm prefix. The
// signer (writeRecord) and the verifier (verify.go) MUST produce byte-identical digest
// strings for the chain to hold, so both call this one helper — a one-sided change to
// the algorithm, prefix, or encoding would otherwise make every existing record verify
// as tampered.
func recordMAC(key, body []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	return "sha256:" + hex.EncodeToString(mac.Sum(nil))
}

// signedRecordLine returns the canonical on-disk bytes of a signed record (no
// trailing newline): the signed body — the record marshaled with an empty _hmac —
// with mac spliced in as the final _hmac field.
//
// Splicing rather than re-marshaling the record with its HMAC set makes the write
// invariant structural: the written bytes ARE the signed bytes plus the one field
// the verifier strips back off, so a second marshal cannot, after a future struct
// change, diverge from the bytes that were signed and make a record fail its own
// verification. body ends in '}' (rec.HMAC is empty when it is marshaled and the
// field is tagged omitempty), so replacing that brace with `,"_hmac":"..."}` yields
// the whole record. The spliced field name must match the struct json tag ("_hmac").
//
// This is the SINGLE definition of a signed record's on-disk form: writeRecord emits
// the line with it, and VerifyRecord rebuilds the expected line with it to reject a
// byte-level rewrite that still decodes to the same fields. One definition is what
// makes that byte comparison safe — two hand-mirrored splices could drift, and the
// verifier would then reject genuine records.
//
// It takes ownership of body (it appends through body's backing array); callers must
// not use body afterwards.
func signedRecordLine(body []byte, mac string) ([]byte, error) {
	if n := len(body); n == 0 || body[n-1] != '}' {
		// Defensive: a struct marshal always ends in '}', so this is unreachable, but
		// splicing into a non-object would corrupt the record.
		return nil, errors.New("signing body is not a JSON object")
	}
	macJSON, err := json.Marshal(mac)
	if err != nil {
		return nil, err
	}
	// No summed-length capacity (which CodeQL flags as a potential allocation
	// overflow); append grows safely.
	line := body[:len(body)-1] // drop the trailing '}'
	line = append(line, `,"_hmac":`...)
	line = append(line, macJSON...)
	return append(line, '}'), nil
}

// isCanonicalSignedLine reports whether line is byte-identical to what
// signedRecordLine(body, mac) would produce, without materializing that line.
//
// VerifyRecord calls this for every signed record in an audit-verify pass, which
// can scan a multi-GB log, so this avoids signedRecordLine's clone-and-append — an
// allocation and copy proportional to the record's size, dominated by Details, up
// to 1 MiB — in favor of a prefix/suffix comparison directly against body's own
// backing array. Only mac (always small: "sha256:" plus a hex digest) is marshaled
// and copied; nothing here scales with record size.
func isCanonicalSignedLine(line, body []byte, mac string) (bool, error) {
	if n := len(body); n == 0 || body[n-1] != '}' {
		// Defensive: a struct marshal always ends in '}', so this is unreachable —
		// mirrors signedRecordLine's identical guard.
		return false, errors.New("signing body is not a JSON object")
	}
	macJSON, err := json.Marshal(mac)
	if err != nil {
		return false, err
	}
	prefix := body[:len(body)-1] // body minus its trailing '}'
	suffix := append(append([]byte(`,"_hmac":`), macJSON...), '}')
	return len(line) == len(prefix)+len(suffix) &&
		bytes.HasPrefix(line, prefix) &&
		bytes.HasSuffix(line, suffix), nil
}

// writeRecord stamps the chain fields, signs, and writes a single record,
// advancing the chain head and seq only after a successful write. A dropped or
// failed record never consumes a seq or leaves a dangling link.
//
// Successful, not durable: a returned write leaves the record in the page cache.
// Durability is the drainer's job — the debounced syncDebounce timer or the
// every-syncEveryN counter — so a crash can lose a written-but-unsynced tail
// without breaking the chain (the seqs are contiguous either way).
func (s *Sink) writeRecord(rec *auditRecord) {
	// Details and envelope are already bounded at Record() time, so the serialized
	// record is provably far below the 4 MiB scanner buffer / chain-resume window.

	// The counter is one short of the uint64 ceiling, so the increment below would wrap
	// to 0 and reissue the genesis seq — a duplicate-seq cascade audit-verify cannot
	// distinguish from tampering. Refuse to write instead: a counted, warned gap is
	// recoverable, a silently renumbered chain is not. seedSeqPastOnDiskMax clamps the
	// untrusted on-disk seed far below this, so reaching it means the counter was driven
	// here some other way; the guard is what makes the wrap structurally impossible.
	if s.seq == ^uint64(0) {
		s.writeFailures.Add(1)
		if !s.writeErrWarned {
			s.writeErrWarned = true
			fmt.Fprintf(os.Stderr, "[eunox] WARNING: audit sequence number is exhausted — refusing to write further records rather than reissuing sequence numbers already on disk (further write errors are suppressed)\n")
		}
		return
	}

	// Stamp the chain fields before signing so the HMAC covers them: the next
	// monotonic seq and the predecessor's _hmac. An attacker deleting or reordering
	// records (without the key) breaks prev_hmac linkage and seq contiguity, both of
	// which audit-verify detects.
	rec.Seq = s.seq + 1
	if s.prevHMAC != "" {
		rec.PrevHMAC = s.prevHMAC
	} else {
		// First record of a fresh log — or of a chain restarted because the tail could
		// not be verified. Either way the sentinel marks this chain's origin; an empty
		// prev_hmac is never emitted, so audit-verify can treat one as a break outright.
		rec.PrevHMAC = auditGenesisPrev
	}

	// Serialize without HMAC, then sign. rec.HMAC is empty here and tagged
	// "_hmac,omitempty", so body omits it and ends in '}'.
	body, err := json.Marshal(rec)
	if err != nil {
		s.writeFailures.Add(1)
		fmt.Fprintf(os.Stderr, "[eunox] audit marshal error: %v\n", err)
		return
	}
	rec.HMAC = recordMAC(s.key, body)

	// Build the on-disk line through the shared splice (body is not reused after
	// this, so handing off its backing array is fine). VerifyRecord rebuilds the same
	// line from the decoded record and requires the on-disk bytes to match it, so
	// this call is the definition both sides follow.
	line, err := signedRecordLine(body, rec.HMAC)
	if err != nil {
		s.writeFailures.Add(1)
		fmt.Fprintf(os.Stderr, "[eunox] audit marshal error: %v\n", err)
		return
	}
	line = append(line, '\n')

	if s.f == nil {
		// File lost during a failed rotation. Defensive: rotate() always retains a
		// valid fd, but count the loss if ever hit.
		s.writeFailures.Add(1)
		return
	}
	if s.tailOrphanBytes > 0 && !s.repairTailOrphan() {
		// A prior partial write's orphan fragment still cannot be cleaned up (Stat or
		// Truncate still failing — the same degraded filesystem, or a persistent
		// external interference). Never append onto a known-dirty tail: doing so would
		// fuse this record onto the un-terminated fragment, producing one corrupt
		// physical line indistinguishable from tampering. Count the loss like any other
		// unwritable-file failure below and retry the repair again on the next record.
		s.writeFailures.Add(1)
		if !s.writeErrWarned {
			s.writeErrWarned = true
			fmt.Fprintf(os.Stderr, "[eunox] WARNING: audit log has an unrepaired partial-write tail — refusing to append further records until it is cleaned up; check disk space and I/O (further write errors are suppressed)\n")
		}
		return
	}
	if s.written+int64(len(line)) > s.maxBytes {
		s.rotate()
	}
	// No post-rotate nil guard: rotate() never assigns nil to s.f (errors keep the
	// original fd; success swaps in a non-nil one). writeLine is the test-only seam;
	// otherwise write straight to the file.
	var n int
	if s.writeLine != nil {
		n, err = s.writeLine(line)
	} else {
		n, err = s.f.Write(line)
	}
	// Count bytes that landed even on a partial write: the io.Writer contract allows
	// (n > 0, err != nil), and Linux write() can return a positive count with ENOSPC.
	// Updating only on success left s.written underestimated, delaying rotation past
	// maxBytes. This is size accounting; the chain head still advances only on full
	// success.
	s.written += int64(n)
	if err != nil {
		// A partial write (n>0) left an unterminated fragment at EOF. The fd is
		// O_APPEND, so the NEXT writeRecord would splice a full {…}\n immediately onto
		// that orphan, producing one corrupt physical line that fails verification AND
		// desyncs the seq/prev_hmac chain for every following record (an INVALID +
		// CHAIN BREAK + SEQ GAP cascade indistinguishable from tampering). Attempt to
		// truncate the orphan back to the last clean record boundary right away via
		// repairTailOrphan so the next append starts at a record boundary, mirroring
		// the startup truncatePartialTail guard. If that immediate attempt fails
		// (Stat/Truncate error, or the reported size is smaller than n — e.g. Stat
		// racing a concurrent external truncation), tailOrphanBytes stays > 0: the
		// guard at the top of this function retries the SAME repair before every
		// subsequent record, and refuses to write while it keeps failing. This is
		// deliberately NOT "force rotation on the next write" (the old behavior): a
		// forced rotation can itself fail (rename/reopen error, plausible on the same
		// degraded filesystem) and would leave this same fd — and the same orphan — in
		// place for the next append to splice onto.
		//
		// Setting tailOrphanBytes = n BEFORE the repair attempt is what latches the
		// pending state on failure: a successful repair zeroes it again, a failed one
		// leaves it > 0 (so the guard above catches it on the next record).
		if n > 0 && s.f != nil {
			s.tailOrphanBytes = int64(n)
			s.repairTailOrphan()
		}
		// The file is unwritable (full disk, EIO). The record is lost and the chain
		// head is not advanced, so the chain stays consistent but the trail is
		// incomplete. Count every loss and warn once (a per-record stderr flood under
		// a sustained outage is not actionable). The loss cannot be self-recorded
		// in-chain (the target file is the thing failing). The dedicated one-shot flag
		// keeps a prior marshal/nil-file increment from suppressing this first alert.
		s.writeFailures.Add(1)
		if !s.writeErrWarned {
			s.writeErrWarned = true
			fmt.Fprintf(os.Stderr, "[eunox] WARNING: audit record write failed — the audit trail is now incomplete; check disk space and I/O (further write errors are suppressed): %v\n", err)
		}
		return
	}
	// Record durably written: advance the chain head and sequence number.
	s.seq = rec.Seq
	s.prevHMAC = rec.HMAC
}

// Close signals the drainer goroutine to stop, waits for it to flush all
// queued records to disk, then syncs and closes the underlying file.
// Close is idempotent: subsequent calls are no-ops.
func (s *Sink) Close() error {
	s.closeOnce.Do(func() {
		// Set closed and close the channel under the write lock so no in-flight
		// Record() send is on the channel-send arm when close() runs (which would
		// panic). The write lock waits for every concurrent send (each read-locked) to
		// finish; later sends see closed and drop. Released before wg.Wait so
		// post-close Record() calls are not blocked behind the final flush.
		//
		// A verify-only Sink (NewVerifier) has no records channel and no drainer, so
		// guard the close: close(nil) panics, and there is nothing to drain or wait on.
		s.mu.Lock()
		s.closed = true
		if s.records != nil {
			close(s.records) // signal the drainer to exit after draining
		}
		s.mu.Unlock()

		s.wg.Wait() // block until the drainer has exited (no-op for a verifier)

		// Sample the drop counter under the write lock so the warning counts every
		// Record() already in its read-locked critical section: a racing producer
		// does dropped.Add(1) under the read lock, and the write lock waits for those
		// to complete, so an unsynchronized Load cannot miss one. Drops arriving after
		// this barrier are post-shutdown and remain visible via DroppedRecords().
		s.mu.Lock()
		droppedAtClose := s.dropped.Load()
		s.mu.Unlock()
		if droppedAtClose > 0 {
			fmt.Fprintf(os.Stderr, "[eunox] WARNING: %d audit record(s) were dropped during this session\n", droppedAtClose)
		}
		if n := s.writeFailures.Load(); n > 0 {
			fmt.Fprintf(os.Stderr, "[eunox] WARNING: %d audit record(s) failed to write to disk during this session; the audit trail is incomplete\n", n)
		}
		if s.f != nil {
			// Close even when Sync fails (closeOnce makes this a one-shot, so an early
			// return would leak the fd). Join both so neither error is lost; Join
			// returns nil when both are, leaving the happy path unchanged.
			syncErr := s.f.Sync()
			closeErr := s.f.Close()
			s.closeErr = errors.Join(syncErr, closeErr)
		}

		// Release the lock last, after the fd is synced and closed, so the chain tail
		// is durable before another writer can acquire the path. Only fold a non-nil
		// release error in so the normal path keeps closeErr's joined structure.
		if s.lockFile != nil {
			if relErr := releaseAuditLock(s.lockFile); relErr != nil {
				s.closeErr = errors.Join(s.closeErr, relErr)
			}
		}

		// Surface mid-operation write failures through the returned error too: a clean
		// final Sync/Close does not mean the trail is complete (records lost during
		// the session never reached disk), so a caller checking only Close's error
		// would otherwise believe the log is whole, breaking the fail-closed contract.
		if n := s.writeFailures.Load(); n > 0 {
			s.closeErr = errors.Join(s.closeErr,
				fmt.Errorf("audit: %d record(s) failed to write during operation; the audit trail is incomplete", n))
		}
	})
	return s.closeErr
}
