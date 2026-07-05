// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"sync/atomic"
	"time"
)

// IDGenerator produces process-unique, opaque, monotonically increasing IDs of the
// form "<prefix>-<nonce>-<counter>" WITHOUT a per-call crypto/rand read: the random
// nonce is drawn once at construction and mixed into every ID, while the hot path is
// a single atomic increment. The bare counter restarts at zero each process start, so
// the nonce is what keeps IDs distinct across restarts (e.g. an audit log spanning
// restarts, or correlation joins). Safe for concurrent use.
//
// It lives in pkg/capability — the lowest layer both the audit sink
// (internal/audit) and the enforcement engine (pkg/enforcement) already import — so
// those two hot-path ID schemes share one implementation instead of each carrying a
// hand-copied nonce+counter.
type IDGenerator struct {
	prefix  string
	nonce   string
	counter atomic.Uint64
}

// NewIDGenerator returns an IDGenerator stamping the given prefix and a fresh random
// nonce of nonceBytes bytes (hex-encoded, so 2*nonceBytes hex chars).
func NewIDGenerator(prefix string, nonceBytes int) *IDGenerator {
	return &IDGenerator{prefix: prefix, nonce: randomNonce(nonceBytes)}
}

// Next returns the next ID: "<prefix>-<nonce>-<counter>", counter in hex.
func (g *IDGenerator) Next() string {
	return g.prefix + "-" + g.nonce + "-" + strconv.FormatUint(g.counter.Add(1), 16)
}

// randomNonce returns n cryptographically random bytes hex-encoded. On the
// unrecoverable crypto/rand failure it falls back to a time-derived value so IDs stay
// distinct rather than collapsing onto an empty nonce.
func randomNonce(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b)
}
