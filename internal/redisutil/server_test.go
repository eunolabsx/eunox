// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package redisutil

import (
	"context"
	"errors"
	"testing"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
)

// infoStub answers INFO with a canned reply, which is the only way to drive this: a Redis
// Cluster cannot be stood up in-process, and the emulators that can refuse INFO's Cluster
// section outright.
type infoStub struct {
	reply string
	err   error
	// sections records what was asked for. INFO's Cluster section is the ONLY place
	// cluster_enabled appears — CLUSTER INFO does not carry it and a standalone server refuses
	// that command outright — so a probe written against the wrong one is dead in both
	// directions and passes every reply-shape row silently.
	sections *[]string
}

func (s infoStub) Info(_ context.Context, section ...string) *redis.StringCmd {
	if s.sections != nil {
		*s.sections = append(*s.sections, section...)
	}
	return redis.NewStringResult(s.reply, s.err)
}

// TestServerReportsClustered pins the reading BOTH backends share, including the carve-out each
// of them then states its own residual for: an INFO nobody could answer reads as unclustered,
// since refusing it would refuse every emulator, proxy and restrictive ACL that answers the
// commands eunox actually issues.
func TestServerReportsClustered(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		client   infoStub
		want     bool
		answered bool
	}{
		{"a cluster node", infoStub{reply: "# Cluster\r\ncluster_enabled:1\r\n"}, true, true},
		{"a standalone server", infoStub{reply: "# Cluster\r\ncluster_enabled:0\r\n"}, false, true},
		{"an empty reply", infoStub{}, false, true},
		// The section a standalone server refuses, an ACL that denies INFO, a server that is not
		// up yet: an ANSWER was never obtained, which is not the same fact as "not a cluster" and
		// is why the second return value exists.
		{"an INFO nobody could answer", infoStub{err: errors.New("ERR unknown section")}, false, false},
		{"the field on its own line among others", infoStub{reply: "# Server\r\nredis_version:7\r\ncluster_enabled:1\r\n"}, true, true},
		// Line-anchored, so a field merely ENDING in the watched name is not a positive. A caller
		// that latches a permanent refusal on this cannot recover from a false one.
		{"a field whose name ends in the watched one", infoStub{reply: "# Server\r\nproxy_cluster_enabled:1\r\n"}, false, true},
		{"a longer value under the same name", infoStub{reply: "cluster_enabled:10\r\n"}, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			clustered, answered := ServerReportsClustered(context.Background(), tc.client)
			assert.Equal(t, tc.want, clustered)
			assert.Equal(t, tc.answered, answered)
		})
	}
}

// TestServerReportsClustered_ReadsTheClusterSection pins the command, which is the half a
// reply-shape table cannot check: cluster_enabled lives only in INFO's Cluster section, so a
// probe reading CLUSTER INFO would answer "not clustered" for every server on earth.
func TestServerReportsClustered_ReadsTheClusterSection(t *testing.T) {
	t.Parallel()
	var asked []string
	ServerReportsClustered(context.Background(), infoStub{sections: &asked})
	assert.Equal(t, []string{"cluster"}, asked)
}
