// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Caller-identity extractor for the audit sink: turns validated JWT claims into the
// audit.Identity fields a signed record carries. Lives in the binary since cmd/eunox is the
// only place that already imports both internal/audit and internal/pdp.

package main

import (
	"context"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/internal/pdp"
)

// auditIdentity returns the caller identity from ctx's validated JWT claims, or the zero
// Identity when there are none.
func auditIdentity(ctx context.Context) audit.Identity {
	c := pdp.JWTClaimsPtr(ctx)
	if c == nil {
		return audit.Identity{}
	}
	return audit.Identity{
		AgentID: c.AgentID,
		TaskID:  c.TaskID,
		UserID:  c.Subject,
		TokenID: c.TokenID,
	}
}
