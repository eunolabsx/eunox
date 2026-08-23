// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package killswitch

import (
	"context"
	"reflect"
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

// TestKillDimensions_EveryEntryIsComplete is the declaration's own guard.
//
// The table is what makes "declared once" true, and it is only as good as its entries: a
// dimension missing an accessor does not fail loudly, it goes missing from ONE path. A nil
// `slot` drops it from every Status an operator reads to confirm what is in force; a nil
// `memCache` panics the in-memory backend's read; a nil `event` silently reclaims nothing.
//
// Reflective over the struct rather than a checklist, because a hand-written list of required
// fields is the same thing being guarded against — one more place to remember when a field is
// added to killDimension.
func TestKillDimensions_EveryEntryIsComplete(t *testing.T) {
	t.Parallel()
	require.NotEmpty(t, killDimensions)
	names := map[string]bool{}
	for i := range killDimensions {
		dim := &killDimensions[i]
		t.Run(dim.name, func(t *testing.T) {
			v := reflect.ValueOf(*dim)
			typ := v.Type()
			for f := range typ.NumField() {
				field := typ.Field(f)
				// `expires` is the one legitimately-false field: only sessions carry a TTL,
				// so a zero value there is an answer rather than an omission.
				if field.Name == "expires" {
					continue
				}
				assert.Falsef(t, v.Field(f).IsZero(),
					"killDimensions[%q].%s is unset; a dimension missing an accessor goes missing from one path rather than failing",
					dim.name, field.Name)
			}
			assert.Equal(t, dim.keyPrefix, "killswitch:"+dim.name+":",
				"the durable key prefix must be name-derived, or a writer and a scanner can disagree about where this dimension lives")
		})
		require.Falsef(t, names[dim.name], "two dimensions named %q; the pub/sub handler matches on the name", dim.name)
		names[dim.name] = true
	}
}

// TestKillDimensions_MethodNamesExistOnTheInterface pins the operator-facing half of an
// empty-id error against the interface it names. The names used to be COMPOSED as
// verb+entity, which spelled the jti axis's kill method "KillJTI" — a method that does not
// exist (it is RevokeJTI), so the one backend that composed them pointed an operator at
// nothing while the one that spelled them by hand was right. Reflection over Manager is what
// makes a wrong name a failing build rather than a wrong error string.
func TestKillDimensions_MethodNamesExistOnTheInterface(t *testing.T) {
	t.Parallel()
	mgr := reflect.TypeOf((*Manager)(nil)).Elem()
	for i := range killDimensions {
		dim := &killDimensions[i]
		for _, name := range []string{dim.killMethod, dim.reviveMethod} {
			_, ok := mgr.MethodByName(name)
			assert.Truef(t, ok, "killDimensions[%q] names %q, which Manager does not declare", dim.name, name)
		}
	}
}

// TestEmptyID_BothBackendsNameTheSameMethod pins the two backends against each other on one
// misuse: the in-memory backend spells the six method names by hand and the Redis backend
// reads them off the declaration, so a divergence here means one of the two is naming a
// method the operator cannot find.
func TestEmptyID_BothBackendsNameTheSameMethod(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r, _ := startedOn(t)
	m := NewInMemory()
	cases := []struct {
		name  string
		redis func(context.Context, string) error
		mem   func(context.Context, string) error
	}{
		{"KillAgent", r.KillAgent, m.KillAgent},
		{"ReviveAgent", r.ReviveAgent, m.ReviveAgent},
		{"KillSession", r.KillSession, m.KillSession},
		{"ReviveSession", r.ReviveSession, m.ReviveSession},
		{"RevokeJTI", r.RevokeJTI, m.RevokeJTI},
		{"ReviveJTI", r.ReviveJTI, m.ReviveJTI},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rerr := tc.redis(ctx, "")
			merr := tc.mem(ctx, "")
			require.Error(t, rerr)
			require.Error(t, merr)
			assert.Equal(t, merr.Error(), rerr.Error(),
				"the two backends must name the same method for the same misuse")
			assert.Contains(t, rerr.Error(), tc.name,
				"the error must name the method the operator actually called")
		})
	}
}

// Every name this package's own methods pass to mustDimension must be declared, or the panic it
// documents as unreachable becomes reachable.
func TestMustDimension_EveryNamePassedIsDeclared(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"agent", "session", "jti"} {
		require.NotPanics(t, func() { _ = mustDimension(name) }, "mustDimension(%q)", name)
	}
	assert.Panics(t, func() { _ = mustDimension("nope") },
		"an undeclared name must panic rather than returning a zero dimension that writes the bare prefix key")
}

// Every dimension appears in a Status snapshot, driven through the backend rather than through
// buildStatusOf, so a backend whose accessor reaches the wrong set fails here too.
func TestStatus_ReportsEveryDimension(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	m := NewInMemory()
	require.NoError(t, m.KillAgent(ctx, "a-1"))
	require.NoError(t, m.KillSession(ctx, "s-1"))
	require.NoError(t, m.RevokeJTI(ctx, "t-1"))

	st, err := m.Status(ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{"a-1"}, st.KilledAgents)
	assert.Equal(t, []string{"s-1"}, st.KilledSessions)
	assert.Equal(t, []string{"t-1"}, st.RevokedJTIs)

	// Each dimension's slot is DISTINCT: two entries pointing at one field would report the
	// last writer's ids under both names and lose the other's entirely.
	slots := map[*[]string]string{}
	for i := range killDimensions {
		dim := &killDimensions[i]
		slot := dim.slot(st)
		require.Emptyf(t, slots[slot], "dimensions %q and %q report into the same Status field", slots[slot], dim.name)
		slots[slot] = dim.name
	}
}
