// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/capability"
)

func TestAuditIdentity_FromClaims(t *testing.T) {
	t.Parallel()
	// With claims: agent/task/user (sub) all flow through.
	ctx := pdp.WithJWTClaims(context.Background(), &pdp.JWTClaims{AgentID: "agent-1", TaskID: "task-9", Subject: "user-7"})
	id := auditIdentity(ctx)
	assert.Equal(t, "agent-1", id.AgentID)
	assert.Equal(t, "task-9", id.TaskID)
	assert.Equal(t, "user-7", id.UserID)
	// An undelegated token carries no acting delegate and no depth, so both stay off the record.
	assert.Empty(t, id.Delegate)
	assert.Zero(t, id.DelegationDepth)

	// Without claims: all empty.
	assert.Equal(t, audit.Identity{}, auditIdentity(context.Background()))

	// A delegated token: the CURRENT holder and the chain depth, alongside the human the
	// token is for. Without these the record is indistinguishable from one the human made
	// directly, which is the shape a delegated allow could not answer.
	delegated := pdp.WithJWTClaims(context.Background(), &pdp.JWTClaims{
		Subject: "user@example.com",
		Delegation: &capability.DelegationChain{
			Actors: []string{"agent-a", "agent-b"},
		},
	})
	id = auditIdentity(delegated)
	assert.Equal(t, "user@example.com", id.UserID)
	assert.Equal(t, "agent-b", id.Delegate, "the outermost act actor is who holds the token now")
	assert.Equal(t, 2, id.DelegationDepth)
}

// The token id answers a DIFFERENT question from the identity fields beside it: which
// credential authorized the call, not which identity it speaks for. An incident needs both —
// after a token is revoked, this is the only field that separates the calls it made from the
// same agent's calls on a token that was never compromised.
func TestAuditIdentity_CarriesTheTokenID(t *testing.T) {
	t.Parallel()
	ctx := pdp.WithJWTClaims(context.Background(), &pdp.JWTClaims{
		AgentID: "agent-1",
		Subject: "user@example.com",
		TokenID: "jti-abc",
	})
	id := auditIdentity(ctx)
	assert.Equal(t, "jti-abc", id.TokenID)
	assert.Equal(t, "agent-1", id.AgentID, "the credential id must not displace the identity fields")
	assert.Equal(t, "user@example.com", id.UserID)

	// A token that carries no jti leaves the field empty rather than borrowing another
	// axis: an existing deployment's records stay byte-identical until its IdP issues one.
	none := auditIdentity(pdp.WithJWTClaims(context.Background(), &pdp.JWTClaims{AgentID: "agent-1"}))
	assert.Empty(t, none.TokenID)
}

// TestAuditIdentity_PopulatesEveryField is the guard that pays for keeping this adapter in the
// binary rather than in the package that owns the claims (see audit_identity.go).
//
// Moving it here means a new axis on audit.Identity is a field someone must remember to fill
// HERE, and a forgotten one is not a build failure — it is a silently empty column on a signed,
// append-only tape, which is the failure mode that is hardest to notice and impossible to
// backfill. So the reminder is mechanical: every field of audit.Identity must be non-zero for
// claims that set every identity axis. A field added to the struct and not mapped here fails
// this test by name.
//
// It reflects over the struct rather than listing the fields, because a hand-written list is
// the same thing being guarded against — one more place to remember.
func TestAuditIdentity_PopulatesEveryField(t *testing.T) {
	t.Parallel()
	// Claims that exercise every identity axis at once.
	ctx := pdp.WithJWTClaims(context.Background(), &pdp.JWTClaims{
		AgentID: "agent-1",
		TaskID:  "task-9",
		Subject: "user-7",
		TokenID: "jti-3",
		Delegation: &capability.DelegationChain{
			Actors: []string{"agent-a", "agent-b"},
		},
	})
	id := auditIdentity(ctx)

	v := reflect.ValueOf(id)
	typ := v.Type()
	require.Positive(t, typ.NumField(), "audit.Identity must have fields")
	for i := range typ.NumField() {
		f := typ.Field(i)
		if !f.IsExported() {
			continue
		}
		assert.Falsef(t, v.Field(i).IsZero(),
			"audit.Identity.%s is not populated by auditIdentity: a new identity field must be "+
				"mapped from the claims here, or it is silently empty on every signed record",
			f.Name)
	}
}
