// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"sync"
	"testing"
)

// TestRoute_SharedUpstreamTransport_ShutdownRace drives the exact concurrency the
// shutdown path can produce: srv.Shutdown returns on TIMEOUT with a straggler handler
// still inside sharedUpstreamTransport's Once, while the deferred
// closeIdleUpstreamConns reads the field. When upstreamTransport was a plain
// *http.Transport that pair was an unsynchronized write/read — a -race failure and a
// possible nil observation. It is an atomic.Pointer now, so this is race-clean.
//
// Run under -race (the project's default) for the assertion to mean anything.
func TestRoute_SharedUpstreamTransport_ShutdownRace(t *testing.T) {
	t.Parallel()

	const builders = 8
	r := &UpstreamRoute{name: "race"}

	var start sync.WaitGroup
	start.Add(1)
	var done sync.WaitGroup

	// Stragglers still building the shared transport.
	for range builders {
		done.Add(1)
		go func() {
			defer done.Done()
			start.Wait()
			if tr := r.sharedUpstreamTransport(1000); tr == nil {
				t.Error("sharedUpstreamTransport returned nil: a straggler must never be silently demoted to http.DefaultTransport, which would drop this route's TLS settings")
			}
		}()
	}
	// The shutdown defer, racing them.
	done.Add(1)
	go func() {
		defer done.Done()
		start.Wait()
		r.closeIdleUpstreamConns()
	}()

	start.Done()
	done.Wait()

	// Exactly-once construction still holds: every caller sees the same transport.
	first := r.sharedUpstreamTransport(1000)
	if first == nil {
		t.Fatal("sharedUpstreamTransport returned nil after the race")
	}
	if second := r.sharedUpstreamTransport(9999); second != first {
		t.Error("sharedUpstreamTransport rebuilt the transport; the Once must still guarantee exactly one build")
	}
}

// TestRoute_CloseIdleUpstreamConns_NeverBuilds pins that the shutdown path does not
// CONSUME the build Once. Reading through the same Once would also close the race, but
// a shutdown that won the Do would then permanently hand every straggler a nil
// transport — silently demoting them to http.DefaultTransport and dropping this
// route's TLS configuration. A stdio route (which never opens a remote session) must
// likewise still end with no transport built.
func TestRoute_CloseIdleUpstreamConns_NeverBuilds(t *testing.T) {
	t.Parallel()

	r := &UpstreamRoute{name: "stdio-route"}
	r.closeIdleUpstreamConns() // no remote session ever opened: a no-op
	if got := r.upstreamTransport.Load(); got != nil {
		t.Fatal("closeIdleUpstreamConns built a transport; it must only release one that already exists")
	}
	// The Once is still unspent, so a later session gets a real transport.
	if tr := r.sharedUpstreamTransport(1000); tr == nil {
		t.Fatal("sharedUpstreamTransport returned nil after a prior closeIdleUpstreamConns: the shutdown path consumed the build Once")
	}
}
