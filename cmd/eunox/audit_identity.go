// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The audit sink's caller-identity extractor: the one place a validated token's claims become
// the identity fields a signed record carries.
//
// It lives in the BINARY rather than in either package it joins. audit.WithIdentity exists so
// the audit subsystem — file I/O, HMAC signing, rotation, retention — need not import the
// JWT/PDP layer, and having internal/pdp return the writer's own struct satisfied that by
// INVERTING the arrow instead of removing it: every consumer of the PDP layer then linked the
// writer, internal/drift included, which has nothing to do with the tape. cmd/eunox already
// imports both, so the adapter belongs at the join rather than on either side of it, and the
// named fields the seam gained (a fifth positional string is a transposition that silently
// swaps two structured identity fields on a signed tape) are kept either way.
//
// What the move costs is a thing the wiring must be remembered to do: a new axis on
// audit.Identity is a field this function has to fill, and a forgotten one is a silently empty
// column on the tape rather than a build failure — where a mapping living beside the claims
// would at least be edited by whoever added the claim. TestAuditIdentity_PopulatesEveryField
// is what closes that: it reflects over audit.Identity and fails when any field is still zero
// for claims that set every axis, so the reminder is a test rather than a convention.

package main

import (
	"context"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/internal/pdp"
)

// auditIdentity returns the caller identity from any validated JWT claims in ctx — the zero
// Identity when there are none, which leaves every identity field off the record.
//
// The user identity is the token SUBJECT (sub): the human or principal the agent acts for. On
// a delegated call that is still the human, which is precisely why Delegate is its own field.
//
// The delegation half is what makes a DELEGATED allow attributable. A refusal on that axis
// already names the hop that blocked it, in the denial's details; an allow carried nothing at
// all, so a call made by agent-b, delegated from agent-a, acting for a human, produced a record
// whose only identity was that human's — indistinguishable from one they made directly, which
// is backwards for the record an investigator most needs to attribute.
//
// Wired into the sink via audit.WithIdentity (see setupAuditSink). It reads the typed,
// already-validated claims through pdp.JWTClaimsPtr; a caller identity taken from an unverified
// token would be an attacker-chosen value signed onto the tape as fact.
func auditIdentity(ctx context.Context) audit.Identity {
	c := pdp.JWTClaimsPtr(ctx)
	if c == nil {
		return audit.Identity{}
	}
	return audit.Identity{
		AgentID:  c.AgentID,
		TaskID:   c.TaskID,
		UserID:   c.Subject,
		Delegate: c.Delegation.Delegate(),
		// len(Actors), not len(Grants): the actors are the identities the token passed
		// through, which is what a depth means to a reader reconstructing user -> a -> b. A
		// chain may carry per-hop grants without an act claim, and Delegate() is empty there
		// too — the two fields agree about what they describe.
		DelegationDepth: c.Delegation.ActorDepth(),
	}
}
