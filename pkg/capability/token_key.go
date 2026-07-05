// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"crypto/sha256"
	"encoding/hex"
)

// HashTokenKey derives a fixed-size cache key from a raw token string (hex-encoded
// SHA-256), so an in-process verified-token cache keys tokens by a bounded-size
// digest rather than the raw (unbounded-length) token string. Exported so every
// verified-token cache in the binary — currently the JWT cache in internal/pdp —
// keys tokens the same way from one implementation.
func HashTokenKey(tokenStr string) string {
	h := sha256.Sum256([]byte(tokenStr))
	return hex.EncodeToString(h[:])
}
