// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

// Methods on production types that only tests call. They live in a _test.go file so
// "test-only" is structural rather than prose: a production caller fails to compile
// instead of being talked out of it by a doc comment.

// tracked reports whether key is an outstanding server-initiated request WITHOUT consuming it.
//
// The peek-without-consume disposition it was written for is gone: unblock now takes the entry
// unconditionally, because a destroyed answer must be reported from the entry that made it
// unroutable. What remains is the tests' way to assert which ids a refusal left routable, which
// is exactly the property the take-then-report order exists to preserve.
func (t *serverReqTracker) tracked(key string) bool {
	t.mu.Lock()
	_, ok := t.ids[key]
	t.mu.Unlock()
	return ok
}

// size reports how many values are live, making the refcounting that keeps a long-lived proxy
// from accumulating one entry per anchor it has ever served observable.
func (r *keyedRegistry[T]) size() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}

// size reports how many anchor queues are live: the drop-at-zero behavior is what keeps a
// long-lived proxy from accumulating an entry per anchor it has ever served, and that is
// invisible from the outside.
func (g *decisionSerializer) size() int { return g.queues.size() }

// size reports how many gates are live: visibility into the refcounting that keeps a long-lived
// gateway from accumulating one entry per session it has ever served.
func (g *anchorGates) size() int { return g.reg.size() }

// size reports how many anchors this cache holds. The cap and the release-on-teardown are what
// keep a long-lived session from pinning one route gate per task it has ever served, invisible
// from the outside otherwise.
func (c *gateCache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
