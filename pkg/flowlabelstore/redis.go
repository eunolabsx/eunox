// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package flowlabelstore

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/redis/go-redis/v9"
)

// DefaultIdleTTL is the idle TTL stamped on a session's label set when no WithIdleTTL
// override is given (or a non-positive one is). It is a safety-reclamation bound for
// an orphaned session whose Clear never arrives — a crashed or leaked instance — NOT
// a security-relevant taint lifetime: it is refreshed on every Add and Get, so a live
// session never loses its provenance. Sized to a generous session idle timeout.
const DefaultIdleTTL = 24 * time.Hour

// Redis is a Redis-backed session-scoped flow-label store: each session's labels are
// a Redis SET at "flowlabels:<sessionKey>" carrying an idle TTL refreshed on each
// Add/Get. A shared Redis lets a source read on one instance and a sink on another
// see the same taint. Safe for concurrent use.
type Redis struct {
	client redis.Cmdable
	// ttl is the configured idle TTL as passed to WithRedisIdleTTL (DefaultIdleTTL when
	// unset). It is stored verbatim; effectiveTTL applies the non-positive guard at
	// the point of use.
	ttl time.Duration
}

// RedisOption configures the Redis store.
type RedisOption func(*Redis)

// WithRedisIdleTTL overrides the idle TTL stamped (and refreshed) on each anchor's label
// set. The TTL is a safety-reclamation bound for an orphaned anchor whose Clear never
// arrives (e.g. a crashed instance, or a task-anchored key no teardown owns), NOT a
// security-relevant lifetime: it is refreshed on every Add and Get, so a live/active
// anchor never loses its taint. Size it to the deployment's session idle timeout. A
// non-positive d is ignored in favor of DefaultIdleTTL (see effectiveTTL), since a
// zero/negative EXPIRE would drop a live anchor's taint immediately — fail safe, not open.
//
// It is spelled per-backend, beside WithMemoryIdleTTL, because the setting is now common
// to both and the two constructors take different option types: one name would have to be
// the one that silently does not apply to the store you passed it to.
func WithRedisIdleTTL(d time.Duration) RedisOption {
	return func(r *Redis) {
		r.ttl = d
	}
}

// NewRedis creates a Redis-backed session-scoped flow-label store. Labels for a
// session live at "flowlabels:<sessionKey>" under an idle TTL (DefaultIdleTTL,
// override via WithIdleTTL) refreshed on each Add/Get.
func NewRedis(client redis.Cmdable, opts ...RedisOption) *Redis {
	r := &Redis{
		client: client,
		ttl:    DefaultIdleTTL,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// redisKey is the Redis key for one session's flow-label set. Single source of the
// "flowlabels:<sessionKey>" format so Add, Get, Remove, and Clear cannot drift onto
// different keys (mirrors callcounter's redisWindowKey). The sessionKey is already
// namespaced by the caller (route + session id), so distinct sessions and gateway
// routes address disjoint sets even on a shared backend.
func redisKey(sessionKey string) string {
	return "flowlabels:" + sessionKey
}

// effectiveTTL is the idle TTL to stamp on a key, guarding any configured value below one
// second (the floor subsumes non-positive values): a zero/negative ttl would make EXPIRE
// delete the key at once, and a 0 < ttl < 1s value truncates to Redis EXPIRE's one-second
// granularity — either way capping a live session's taint far below any real session, a
// fail-open. Falling back to DefaultIdleTTL keeps a misconfigured TTL fail-safe (taint
// retained for the default bound). Any realistic idle timeout is far above this one-second
// floor, so a legitimate config is never clamped.
func (r *Redis) effectiveTTL() time.Duration {
	if r.ttl < time.Second {
		return DefaultIdleTTL
	}
	return r.ttl
}

// Add unions labels into the session's set and refreshes the idle TTL, so an active
// session that keeps emitting labels never expires. An empty labels list is a
// no-op — SADD requires at least one member, and there is nothing to union, matching
// InMemory materializing no entry.
func (r *Redis) Add(ctx context.Context, sessionKey string, labels ...string) error {
	if len(labels) == 0 {
		return nil
	}

	key := redisKey(sessionKey)
	members := make([]interface{}, len(labels))
	for i, label := range labels {
		members[i] = label
	}

	// One transaction so the union and the TTL refresh commit together: the key can
	// never be observed with labels but no TTL (which would leak forever), nor lose
	// its TTL between the two commands.
	pipe := r.client.TxPipeline()
	addCmd := pipe.SAdd(ctx, key, members...)
	pipe.Expire(ctx, key, r.effectiveTTL())
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("redis pipeline: %w", err)
	}
	// Defense in depth on the write we depend on: a per-command error inside EXEC
	// (e.g. WRONGTYPE from a key collision) can be masked if only the aggregate Exec
	// error is inspected, so re-check SADD's own error and fail closed.
	if err := addCmd.Err(); err != nil {
		return fmt.Errorf("redis pipeline SAdd: %w", err)
	}
	return nil
}

// Get returns a sorted copy of the session's accumulated set, refreshing the idle TTL
// on the read too: a session that is only being READ — sink after sink,
// emitting no new labels — must not have its provenance reclaimed out from under it.
// An absent session returns an empty slice and a nil error, never an error; EXPIRE on
// an absent key is a harmless no-op, so an untainted session is unaffected.
func (r *Redis) Get(ctx context.Context, sessionKey string) ([]string, error) {
	key := redisKey(sessionKey)

	pipe := r.client.TxPipeline()
	membersCmd := pipe.SMembers(ctx, key)
	pipe.Expire(ctx, key, r.effectiveTTL())
	if _, err := pipe.Exec(ctx); err != nil {
		return nil, fmt.Errorf("redis pipeline: %w", err)
	}
	// Check the SMEMBERS command's own error before trusting its value (defense in
	// depth, as in Add). SMEMBERS returns an empty slice for an absent set — exactly
	// the clean empty result the contract wants, never an error.
	if err := membersCmd.Err(); err != nil {
		return nil, fmt.Errorf("redis pipeline SMembers: %w", err)
	}
	labels := membersCmd.Val()
	// Return nil (not a non-nil empty slice) for an absent/empty session, byte-for-byte
	// matching InMemory.Get so the two backends are substitutable — a consumer that
	// JSON-marshals the result, or distinguishes nil from [], sees the same shape either
	// way. The engine treats both as "clean context" regardless.
	if len(labels) == 0 {
		return nil, nil
	}
	// Sort for a deterministic return, matching InMemory; the engine reorders into the
	// canonical vocabulary regardless.
	sort.Strings(labels)
	return labels, nil
}

// Remove deletes the named labels from the session's set (idempotent). A single SREM
// is atomic on its own, so no transaction is needed, and there is deliberately NO TTL
// refresh: a removal is a rollback or teardown shrinking the taint, not activity
// keeping the session alive, so it must not extend the idle bound. Redis auto-deletes
// the set once its last member is removed, mirroring InMemory reclaiming the map key.
// An empty labels list is a no-op.
func (r *Redis) Remove(ctx context.Context, sessionKey string, labels ...string) error {
	if len(labels) == 0 {
		return nil
	}
	members := make([]interface{}, len(labels))
	for i, label := range labels {
		members[i] = label
	}
	if err := r.client.SRem(ctx, redisKey(sessionKey), members...).Err(); err != nil {
		return fmt.Errorf("redis srem: %w", err)
	}
	return nil
}

// Clear releases the session's entire set at teardown. DEL is a no-op on an
// absent key, so clearing an absent session is a no-op.
func (r *Redis) Clear(ctx context.Context, sessionKey string) error {
	if err := r.client.Del(ctx, redisKey(sessionKey)).Err(); err != nil {
		return fmt.Errorf("redis del: %w", err)
	}
	return nil
}
