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

// DefaultIdleTTL is the idle TTL stamped on a session's label set by default: a
// safety-reclamation bound for an orphaned session whose Clear never arrives, NOT a
// taint lifetime (refreshed on every Add/Get, so a live session never loses provenance).
const DefaultIdleTTL = 24 * time.Hour

// Redis is a Redis-backed session-scoped flow-label store: each session's labels are
// a Redis SET at "flowlabels:<sessionKey>" carrying an idle TTL refreshed on each
// Add/Get. A shared Redis lets a source read on one instance and a sink on another
// see the same taint. Safe for concurrent use.
type Redis struct {
	client redis.Cmdable
	// ttl is the configured idle TTL as passed to WithRedisIdleTTL, stored verbatim;
	// effectiveTTL applies the non-positive guard at the point of use.
	ttl time.Duration
}

// RedisOption configures the Redis store.
type RedisOption func(*Redis)

// WithRedisIdleTTL overrides the idle TTL stamped (and refreshed) on each anchor's label
// set — a safety-reclamation bound for an orphaned anchor, NOT a taint lifetime, since a
// live anchor keeps refreshing it. A non-positive d falls back to DefaultIdleTTL rather
// than dropping a live taint immediately (fail safe, not open).
func WithRedisIdleTTL(d time.Duration) RedisOption {
	return func(r *Redis) {
		r.ttl = d
	}
}

// NewRedis creates a Redis-backed session-scoped flow-label store. Labels live at
// "flowlabels:<sessionKey>" under an idle TTL refreshed on each Add/Get.
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
// "flowlabels:<sessionKey>" format so Add/Get/Remove/Clear cannot drift onto different
// keys (mirrors callcounter's redisWindowKey).
func redisKey(sessionKey string) string {
	return "flowlabels:" + sessionKey
}

// effectiveTTL guards any configured value below one second: a zero/negative or
// sub-second ttl would cap a live session's taint far below any real session (fail-open),
// so it falls back to DefaultIdleTTL instead. A legitimate config is never clamped.
func (r *Redis) effectiveTTL() time.Duration {
	if r.ttl < time.Second {
		return DefaultIdleTTL
	}
	return r.ttl
}

// Add unions labels into the session's set and refreshes the idle TTL. An empty labels
// list is a no-op, matching InMemory materializing no entry.
func (r *Redis) Add(ctx context.Context, sessionKey string, labels ...string) error {
	if len(labels) == 0 {
		return nil
	}

	key := redisKey(sessionKey)
	members := make([]interface{}, len(labels))
	for i, label := range labels {
		members[i] = label
	}

	// One transaction so the union and TTL refresh commit together: the key can never
	// be observed with labels but no TTL (leaking forever), nor lose its TTL between them.
	pipe := r.client.TxPipeline()
	addCmd := pipe.SAdd(ctx, key, members...)
	pipe.Expire(ctx, key, r.effectiveTTL())
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("redis pipeline: %w", err)
	}
	// Defense in depth: a per-command error inside EXEC (e.g. WRONGTYPE) can be masked
	// by only checking the aggregate Exec error, so re-check SADD's own and fail closed.
	if err := addCmd.Err(); err != nil {
		return fmt.Errorf("redis pipeline SAdd: %w", err)
	}
	return nil
}

// Get returns a sorted copy of the session's set, refreshing the idle TTL on read too, so
// a session only being READ never has its provenance reclaimed. Never errors on absence;
// EXPIRE on an absent key is a harmless no-op.
func (r *Redis) Get(ctx context.Context, sessionKey string) ([]string, error) {
	key := redisKey(sessionKey)

	pipe := r.client.TxPipeline()
	membersCmd := pipe.SMembers(ctx, key)
	pipe.Expire(ctx, key, r.effectiveTTL())
	if _, err := pipe.Exec(ctx); err != nil {
		return nil, fmt.Errorf("redis pipeline: %w", err)
	}
	// Check SMEMBERS's own error before trusting its value (defense in depth, as in Add).
	if err := membersCmd.Err(); err != nil {
		return nil, fmt.Errorf("redis pipeline SMembers: %w", err)
	}
	labels := membersCmd.Val()
	// Return nil (not a non-nil empty slice) for absent/empty, byte-for-byte matching
	// InMemory.Get so the two backends stay substitutable.
	if len(labels) == 0 {
		return nil, nil
	}
	sort.Strings(labels)
	return labels, nil
}

// Remove deletes the named labels from the session's set (idempotent). No transaction
// needed (SREM is atomic alone) and deliberately NO TTL refresh: a removal is a rollback,
// not activity, and must not extend the idle bound. Redis auto-deletes the set once empty.
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

// Clear releases the session's entire set at teardown. A no-op on an absent key.
func (r *Redis) Clear(ctx context.Context, sessionKey string) error {
	if err := r.client.Del(ctx, redisKey(sessionKey)).Err(); err != nil {
		return fmt.Errorf("redis del: %w", err)
	}
	return nil
}
