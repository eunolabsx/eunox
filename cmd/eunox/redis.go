// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Redis client construction for the eunox proxy: with --redis-addr, the call counter and
// kill-switch manager are Redis-backed, so state persists and is shared between instances.

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
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

// pingRedis checks connectivity, returning an error safe to print on startup.
func pingRedis(ctx context.Context, client *goredis.Client) error {
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		return fmt.Errorf("redis ping failed: %w (check --redis-addr, --redis-password, --redis-tls)", err)
	}
	return nil
}

// checkRedisNotClustered refuses a --redis-addr pointed at a node of a Redis Cluster.
//
// callcounter.NewRedis refuses a *redis.ClusterClient, which is the library-facing spelling of
// this mistake; the binary never builds one, so its own spelling is an ordinary single-node
// client aimed at a clustered server — where a multi-bucket admission's multi-key EVAL is
// refused with CROSSSLOT once a policy carries two quota bounds, and not before. One round
// trip at startup turns that into a refusal naming the reason.
//
// A server that does not implement CLUSTER INFO (Valkey-compatible servers, an embedded fake)
// or refuses the command is treated as unclustered: only a definitive cluster_enabled:1 is
// grounds to refuse, since the alternative is failing startup against every Redis-protocol
// server that answers the commands eunox actually issues.
func checkRedisNotClustered(ctx context.Context, client clusterInfoLookup) error {
	infoCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	info, err := client.ClusterInfo(infoCtx).Result()
	if err != nil {
		return nil
	}
	if !strings.Contains(info, "cluster_enabled:1") {
		return nil
	}
	return fmt.Errorf("%w: --redis-addr points at a node of a Redis Cluster", callcounter.ErrClusterUnsupported)
}

// clusterInfoLookup is the single command checkRedisNotClustered issues, as a parameter type
// so the clustered branch is reachable in a test without standing up a cluster.
type clusterInfoLookup interface {
	ClusterInfo(ctx context.Context) *goredis.StringCmd
}
