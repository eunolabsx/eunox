// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Redis client construction for the eunox proxy: with --redis-addr, the call counter and
// kill-switch manager are Redis-backed, so state persists and is shared between instances.

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/eunolabs/eunox/pkg/callcounter"

	goredis "github.com/redis/go-redis/v9"
)

// buildRedisClient constructs a single-node Redis client. The returned client is not yet
// connected — callers must Ping before use.
func buildRedisClient(addr, password string, useTLS bool) (*goredis.Client, error) {
	if addr == "" {
		return nil, fmt.Errorf("redis address must not be empty")
	}
	opts := &goredis.Options{
		Addr:         addr,
		Password:     password,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	}
	if useTLS {
		opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return goredis.NewClient(opts), nil
}

// pingRedis checks connectivity AND refuses a topology eunox cannot use, returning an error
// safe to print on startup.
//
// The topology check lives here rather than beside one caller because this is the one round
// trip every path that reaches for Redis already makes (`proxy --redis-addr` and `kill
// --redis-addr` today), so a future subcommand inherits the refusal instead of being a new
// place to remember it.
func pingRedis(ctx context.Context, client *goredis.Client) error {
	pingCtx, cancel := context.WithTimeout(ctx, redisStartupTimeout)
	defer cancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		return fmt.Errorf("redis ping failed: %w (check --redis-addr, --redis-password, --redis-tls)", err)
	}
	// Same deadline as the ping, not a second budget of its own: the two are one startup
	// handshake, and a slow server should not be able to double the time before the proxy
	// either serves or says why it will not.
	return callcounter.CheckServerNotClustered(pingCtx, client)
}

// redisStartupTimeout bounds the startup handshake (ping plus topology probe). One budget for
// the pair, so tuning it cannot leave two halves disagreeing.
const redisStartupTimeout = 5 * time.Second
