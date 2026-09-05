// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"crypto/sha256"
	"encoding/hex"
)

// HashTokenKey derives a fixed-size cache key from a raw token string (hex-encoded
// SHA-256), so an in-process cache keys an unbounded-length, caller-supplied value by a
// bounded-size digest rather than by the value itself. Exported so every such cache in the
// binary derives its key from one implementation.
func HashTokenKey(tokenStr string) string {
	h := sha256.Sum256([]byte(tokenStr))
	return hex.EncodeToString(h[:])
}
