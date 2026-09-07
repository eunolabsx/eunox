// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package redisutil

import (
	"context"
	"strings"

	"github.com/redis/go-redis/v9"
)

// ServerInfoReader is the one command ServerReportsClustered issues. A narrow parameter type so
// a caller can drive the probe with a canned reply, since standing a Redis Cluster up from a Go
// test is not a thing that can be done.
type ServerInfoReader interface {
	Info(ctx context.Context, section ...string) *redis.StringCmd
}

// ServerReportsClustered reports whether the server behind client says it is a node of a Redis
// Cluster, and whether it answered at all — the SERVER-side half of the question ClassifyTopology
// answers from the client's concrete type, and the half that type cannot answer: an ordinary
// *redis.Client aimed at one node of a cluster is a single-node client by every property visible
// in-process.
//
// It lives here for Reconcile's reason. BOTH backends have to ask it — the counter because a
// multi-key EVAL against a cluster node is refused CROSSSLOT, the kill switch because a keyless
// SCAN against one enumerates only the slots that node owns — and the two REFUSALS differ while
// the reading does not, which is exactly the split that let one hand-written copy of a topology
// question drift from its sibling before either was shared.
//
// It reads `INFO cluster`, not `CLUSTER INFO`: the latter's reply carries no cluster_enabled
// field at all (that lives only in INFO's Cluster section) and a standalone server refuses it
// outright, so a probe written against it could never fire in either direction.
//
// It answers in TWO parts because "the server says no" and "I could not ask" are different
// facts, and folding them is the shape ClassifyTopology is three-valued to avoid. An INFO nobody
// could answer (an emulator, a proxy, an ACL that denies it, a server that is not up yet) must
// not refuse a start — that would refuse every Redis-protocol server answering the commands
// eunox actually issues — but a caller whose only other check is a keyless SCAN needs to know it
// never got an answer, so it can ask again rather than treat a transient outage as a verdict.
//
// The field is matched on its own LINE rather than anywhere in the reply. INFO sections are
// CRLF-delimited key:value lines, and an unanchored scan takes a proxy echoing a backend's
// section — or any future field whose name merely ends in this one — as a positive, which for a
// caller that latches a permanent refusal is unrecoverable without a code change.
func ServerReportsClustered(ctx context.Context, client ServerInfoReader) (clustered, answered bool) {
	info, err := client.Info(ctx, "cluster").Result()
	if err != nil {
		return false, false
	}
	for _, line := range strings.Split(info, "\n") {
		if strings.TrimRight(line, "\r") == "cluster_enabled:1" {
			return true, true
		}
	}
	return false, true
}
