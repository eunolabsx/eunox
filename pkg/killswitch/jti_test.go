// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package killswitch

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The per-token dimension's own properties, beyond what the cross-backend conformance table
// states. Everything here is about the two ways a revocation reaches a replica that did not
// issue it — the pub/sub event and the reconcile scan — because those are the paths a
// hand-mirrored dimension silently falls out of: a missed event does not fail, it degrades to
// "converges on the next tick", and a missed scan does not fail either, it just never
// converges.

// The pub/sub handler must RECOGNIZE a jti event, not merely survive it.
//
// This is the assertion the end-to-end propagation test below cannot make, and finding that out
// is why it exists: an unrecognized event falls through to the unknown-message arm, which
// triggers a full Redis SCAN. That converges — so the replica does end up blocking and the
// propagation test passes either way — but it turns an O(1) cache update into an O(keys) scan on
// every revocation, at exactly the moment an operator is revoking under pressure. A mutation
// disabling the handler's table walk passed the propagation test and fails this one.
func TestRedis_JTIPubSubEventIsHandledWithoutAFullRefresh(t *testing.T) {
	t.Parallel()
	r, _ := newTestRedis(t)
	markStarted(t, r)

	r.handlePubSubMessage("jti:kill:tok-1")

	r.mu.RLock()
	revoked := r.revokedJTIs["tok-1"]
	r.mu.RUnlock()
	assert.True(t, revoked, "the handler must apply the revocation to the local cache directly")
	assert.Empty(t, r.refreshTrigger, "a RECOGNIZED event must not fall through to the full-SCAN refresh arm")

	r.handlePubSubMessage("jti:revive:tok-1")
	r.mu.RLock()
	revoked = r.revokedJTIs["tok-1"]
	r.mu.RUnlock()
	assert.False(t, revoked, "and the revive must be recognized the same way")
	assert.Empty(t, r.refreshTrigger)

	// The control: an event naming no declared dimension DOES fall through, which is what
	// makes the assertions above about recognition rather than about the channel being unused.
	r.handlePubSubMessage("nonsense:kill:x")
	assert.Len(t, r.refreshTrigger, 1, "an unknown event must still trigger the refresh backstop")
}

// A revocation published by one instance must reach another's cache. End-to-end over a real
// listener, which is what proves the publish, the channel name and the handler agree — the
// test above proves the handler alone.
func TestRedis_JTIRevocationPropagatesOverPubSub(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	issuer, replica, _ := startedPairOn(t)

	require.NoError(t, issuer.RevokeJTI(ctx, "tok-leaked"))

	awaitBlock(t, replica, Subject{JTI: "tok-leaked"}, true,
		"a token revoked on one instance must block on another")
	awaitBlock(t, replica, Subject{JTI: "tok-other"}, false,
		"and must not block a different credential")

	require.NoError(t, issuer.ReviveJTI(ctx, "tok-leaked"))
	awaitBlock(t, replica, Subject{JTI: "tok-leaked"}, false,
		"and the revive must propagate the same way")
}

// The reconcile path is the backstop when a publish is lost, and it has to carry the new
// dimension too — a scan that does not enumerate the jti prefix means a replica that missed the
// event never converges at all, which is strictly worse than the delay the backstop exists for.
//
// The revocation is written straight to Redis, bypassing the publish, so only the scan can find
// it.
func TestRedis_JTIRevocationConvergesThroughReconcile(t *testing.T) {
	t.Parallel()
	replica, srv := startedOn(t)

	require.NoError(t, srv.Set(redisJTIPrefix+"tok-quiet", "1"))

	require.NoError(t, replica.refreshState(context.Background()))
	blocked, err := replica.ShouldBlock(context.Background(), Subject{JTI: "tok-quiet"})
	require.NoError(t, err)
	assert.True(t, blocked, "a revocation only the SCAN can see must still be found; the reconcile is the backstop for a lost publish")
}

// A revocation delivered from elsewhere must reach ObserveRevocations, because denying the
// traffic is only half of what a kill does: the other half is RECLAIMING what the revoked
// credential holds, and that has no request to hang off. A dimension whose event never fires
// leaves an HTTP session serving until its idle ceiling — and with idle reaping off, forever.
func TestRedis_JTIRevocationNotifiesObservers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	issuer, replica, _ := startedPairOn(t)

	seen := make(chan Revocation, 4)
	unregister := replica.ObserveRevocations(func(ev Revocation) { seen <- ev })
	defer unregister()

	require.NoError(t, issuer.RevokeJTI(ctx, "tok-observed"))

	select {
	case ev := <-seen:
		assert.Equal(t, Revocation{JTI: "tok-observed"}, ev,
			"the event must name the DIMENSION as well as the id; a consumer re-asks ShouldBlock, but an operator reads which axis moved")
	case <-time.After(2 * time.Second):
		t.Fatal("a jti revocation delivered over pub/sub did not reach ObserveRevocations; a consumer has nothing to reclaim on")
	}
}

// Reset must sweep the new dimension's durable keys. A Reset that leaves them behind is not a
// reset: the next reconcile scan re-loads every revocation the operator just cleared, and the
// local clear makes it look like it worked until then.
func TestRedis_ResetSweepsRevokedTokens(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r, srv := startedOn(t)

	require.NoError(t, r.RevokeJTI(ctx, "tok-1"))
	awaitBlock(t, r, Subject{JTI: "tok-1"}, true, "precondition: the revocation is live")

	require.NoError(t, r.Reset(ctx))

	assert.False(t, srv.Exists(redisJTIPrefix+"tok-1"),
		"Reset left the durable key in Redis; the next reconcile would re-load the revocation it just cleared")
	blocked, err := r.ShouldBlock(ctx, Subject{JTI: "tok-1"})
	require.NoError(t, err)
	assert.False(t, blocked)
}

// Status names the revoked tokens, so an operator can confirm what is in force. A token id is
// a credential IDENTIFIER carried in the clear in every token that presents it, not a secret,
// so listing it discloses nothing the holder did not already send.
func TestRedis_StatusListsRevokedTokens(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r, _ := startedOn(t)

	require.NoError(t, r.RevokeJTI(ctx, "tok-b"))
	require.NoError(t, r.RevokeJTI(ctx, "tok-a"))

	st, err := r.Status(ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{"tok-a", "tok-b"}, st.RevokedJTIs, "sorted, so a marshaled Status is stable")
	assert.Empty(t, st.KilledSessions, "the dimensions must not bleed into one another")
	assert.Empty(t, st.KilledAgents)
}

// A token revocation must NOT expire. A session tombstone does, deliberately — a session is
// gone anyway once its TTL elapses — but a credential revoked for cause that quietly comes
// back is a revocation the operator never withdrew.
func TestRedis_TokenRevocationDoesNotExpire(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r, srv := startedOn(t)

	require.NoError(t, r.RevokeJTI(ctx, "tok-durable"))
	require.NoError(t, r.KillSession(ctx, "sess-ttl"))

	assert.Zero(t, srv.TTL(redisJTIPrefix+"tok-durable"),
		"a token revocation must carry no TTL; one that expires re-admits a credential revoked for cause")
	assert.NotZero(t, srv.TTL(redisSessionPfx+"sess-ttl"),
		"the session dimension must still expire, or this test proves nothing about the difference")
}

// ShouldBlock is taken ahead of every policy evaluation on every request, so the subject must
// not cost an allocation. This is the budget the struct was chosen to stay inside — a pointer
// subject, or one carrying a slice, would show up here.
func BenchmarkShouldBlock_SubjectIsAllocationFree(b *testing.B) {
	m := NewInMemory()
	ctx := context.Background()
	require.NoError(b, m.KillSession(ctx, "sess-killed"))
	subj := Subject{AgentID: "agent-1", SessionID: "sess-live", JTI: "tok-1"}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if blocked, err := m.ShouldBlock(ctx, subj); blocked || err != nil {
			b.Fatal("benchmark subject must not be blocked")
		}
	}
}

// startedPairOn builds two started backends sharing one miniredis: an issuer and a replica
// that must learn about the issuer's revocations without issuing any itself.
func startedPairOn(t *testing.T) (issuer, replica *Redis, srv *miniredis.Miniredis) {
	t.Helper()
	issuer, srv = newTestRedis(t)
	issuer.Start(context.Background())
	t.Cleanup(issuer.Stop)

	client := redis.NewClient(&redis.Options{Addr: srv.Addr(), DialTimeout: 200 * time.Millisecond})
	t.Cleanup(func() { _ = client.Close() })
	replica = NewRedis(client)
	replica.Start(context.Background())
	t.Cleanup(replica.Stop)
	return issuer, replica, srv
}

// startedOn builds one started backend, for the cases with no second instance in them.
func startedOn(t *testing.T) (*Redis, *miniredis.Miniredis) {
	t.Helper()
	r, srv := newTestRedis(t)
	r.Start(context.Background())
	t.Cleanup(r.Stop)
	return r, srv
}
