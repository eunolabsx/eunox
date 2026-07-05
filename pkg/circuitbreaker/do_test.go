// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package circuitbreaker

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

// TestDo_UpstreamHangs_DeadlineRecordedAsFailure models an upstream that hangs:
// fn blocks until the request context's deadline fires and then returns the
// context error (as a well-behaved RPC client would). The breaker must record
// this as a failure so that a persistently hanging upstream eventually trips it.
func TestDo_UpstreamHangs_DeadlineRecordedAsFailure(t *testing.T) {
	cfg := Config{
		FailureThreshold:  2,
		CooldownDuration:  time.Minute,
		HalfOpenMaxProbes: 1,
	}
	b := New(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, err := Do(ctx, b, func(ctx context.Context) (int, error) {
		<-ctx.Done() // hang until the deadline fires
		return 0, ctx.Err()
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded from a hung upstream, got %v", err)
	}
	if got := b.Stats().ConsecutiveFails; got != 1 {
		t.Fatalf("a hung upstream must count as one failure; got %d", got)
	}
}

// TestDo_UpstreamHangs_TripsBreakerAfterThreshold verifies that repeated hangs
// open the breaker, after which fn is no longer invoked (the proxy stops
// forwarding to a dead upstream and returns ErrOpen immediately).
func TestDo_UpstreamHangs_TripsBreakerAfterThreshold(t *testing.T) {
	cfg := Config{
		FailureThreshold:  3,
		CooldownDuration:  time.Minute,
		HalfOpenMaxProbes: 1,
	}
	b := New(cfg)

	hang := func(ctx context.Context) (int, error) {
		<-ctx.Done()
		return 0, ctx.Err()
	}
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		_, _ = Do(ctx, b, hang)
		cancel()
	}
	if s := b.State(); s != StateOpen {
		t.Fatalf("expected breaker OPEN after 3 hangs, got %q", s)
	}

	// Once open, fn must not be invoked.
	_, err := Do(context.Background(), b, func(_ context.Context) (int, error) {
		t.Fatal("fn must not run while the breaker is open")
		return 0, nil
	})
	if !errors.Is(err, ErrOpen) {
		t.Fatalf("expected ErrOpen once the breaker has tripped, got %v", err)
	}
}

// TestDo_UpstreamDiesMidRequest_RecordsFailure models an upstream that dies or
// resets the connection after the request is sent but before a full response is
// read. io.ErrUnexpectedEOF is the canonical such error; it must be recorded as
// a failure and trip the breaker like any other transport error.
func TestDo_UpstreamDiesMidRequest_RecordsFailure(t *testing.T) {
	cfg := Config{
		FailureThreshold:  2,
		CooldownDuration:  time.Minute,
		HalfOpenMaxProbes: 1,
	}
	b := New(cfg)
	ctx := context.Background()

	died := func(_ context.Context) (string, error) {
		return "", io.ErrUnexpectedEOF
	}
	for i := 0; i < 2; i++ {
		_, err := Do(ctx, b, died)
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("expected ErrUnexpectedEOF, got %v", err)
		}
	}
	if s := b.State(); s != StateOpen {
		t.Fatalf("expected breaker OPEN after the upstream died, got %q", s)
	}
}

// TestDo_UpstreamReturnsGarbage_RecordedAsSuccess pins an important boundary:
// the breaker guards transport health, not payload validity. A malformed but
// successfully delivered response (nil error) is a SUCCESS to the breaker —
// validating the payload is the caller's job, and tripping the breaker on
// garbage would let a single malformed response wrongly take an upstream out of
// rotation.
func TestDo_UpstreamReturnsGarbage_RecordedAsSuccess(t *testing.T) {
	cfg := Config{
		FailureThreshold:  2,
		CooldownDuration:  time.Minute,
		HalfOpenMaxProbes: 1,
	}
	b := New(cfg)
	ctx := context.Background()

	garbage := func(_ context.Context) (string, error) {
		return "\x00\xff not-valid-json \x01", nil // delivered, but garbage
	}
	for i := 0; i < 10; i++ {
		if _, err := Do(ctx, b, garbage); err != nil {
			t.Fatalf("a delivered-but-garbage response must not error at the breaker level: %v", err)
		}
	}
	if s := b.State(); s != StateClosed {
		t.Fatalf("breaker must stay CLOSED for delivered-but-garbage responses, got %q", s)
	}
	if f := b.Stats().TotalFailures; f != 0 {
		t.Fatalf("garbage payloads must not count as failures; got %d", f)
	}
}

// TestDo_ClientCanceledContext_DoesNotOpenBreaker is the regression: a
// client-initiated cancellation (context.Canceled) observed by fn AFTER admission
// must not count as an upstream failure. A burst of such cancels on a healthy
// upstream must not trip the breaker. We cancel the context after admission (so
// the pre-admission ctx.Err() guard does not short-circuit) and have fn surface
// context.Canceled, as a well-behaved client would.
func TestDo_ClientCanceledContext_DoesNotOpenBreaker(t *testing.T) {
	cfg := Config{
		FailureThreshold:  3,
		CooldownDuration:  time.Minute,
		HalfOpenMaxProbes: 1,
	}
	b := New(cfg)

	for i := 0; i < 10; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		_, err := Do(ctx, b, func(ctx context.Context) (int, error) {
			cancel()     // client aborts after admission, before/while fn runs
			<-ctx.Done() // observe the cancellation
			return 0, ctx.Err()
		})
		cancel()
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	}

	if s := b.State(); s != StateClosed {
		t.Fatalf("client cancellations must not trip the breaker; state=%q", s)
	}
	if f := b.Stats().ConsecutiveFails; f != 0 {
		t.Fatalf("client cancellations must not increment consecutiveFails; got %d", f)
	}
	if f := b.Stats().TotalFailures; f != 0 {
		t.Fatalf("client cancellations must not be recorded as failures; got %d", f)
	}
}

// TestDo_UpstreamOwnedCancel_TripsBreaker verifies that a context.Canceled error
// originating from the upstream's own internal context, while the caller's ctx is
// still live, is recorded as an upstream failure (not a neutral client abort) and
// trips the breaker.
func TestDo_UpstreamOwnedCancel_TripsBreaker(t *testing.T) {
	cfg := Config{FailureThreshold: 1, CooldownDuration: time.Minute, HalfOpenMaxProbes: 1}
	b := New(cfg)

	// The caller ctx (context.Background) is never canceled, but fn returns
	// context.Canceled from some internal context it owns.
	_, err := Do(context.Background(), b, func(context.Context) (int, error) {
		return 0, context.Canceled
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if s := b.State(); s != StateOpen {
		t.Fatalf("upstream-owned cancellation must trip the breaker; state=%q", s)
	}
	if f := b.Stats().TotalFailures; f != 1 {
		t.Fatalf("upstream-owned cancellation must be recorded as a failure; got %d", f)
	}
}

// TestDo_ClientCancelInHalfOpen_IsNeutral verifies the fix is fully neutral:
// a client cancellation observed while the breaker is HalfOpen neither closes it
// (as a success would) nor re-opens it (as a failure would). It releases the probe
// slot so a subsequent genuine success can still close the breaker.
func TestDo_ClientCancelInHalfOpen_IsNeutral(t *testing.T) {
	now := time.Now()
	cfg := Config{FailureThreshold: 1, CooldownDuration: time.Minute, HalfOpenMaxProbes: 1}
	b := New(cfg, WithClock(func() time.Time { return now }))

	// Trip the breaker: one real failure opens it.
	_, _ = Do(context.Background(), b, func(context.Context) (int, error) {
		return 0, errors.New("boom")
	})
	if s := b.State(); s != StateOpen {
		t.Fatalf("breaker should be Open after a failure, got %q", s)
	}

	// Advance past the cooldown so the next call is admitted as a half-open probe.
	now = now.Add(2 * time.Minute)

	// A client-cancel probe in half-open must be neutral: it must not close the
	// breaker (a success would) and must not re-open it (a failure would).
	ctx, cancel := context.WithCancel(context.Background())
	_, err := Do(ctx, b, func(ctx context.Context) (int, error) {
		cancel()
		<-ctx.Done()
		return 0, ctx.Err()
	})
	cancel()
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if s := b.State(); s != StateHalfOpen {
		t.Fatalf("a client cancel in half-open must leave the breaker HalfOpen (neutral), got %q", s)
	}

	// The slot was released, so a genuine success is admitted and closes the breaker.
	if _, err := Do(context.Background(), b, func(context.Context) (int, error) {
		return 1, nil
	}); err != nil {
		t.Fatalf("post-cancel success call: %v", err)
	}
	if s := b.State(); s != StateClosed {
		t.Fatalf("a success after the neutral drop should close the breaker, got %q", s)
	}
}

// TestDo_PreCancelledContextWithSlowFn_DoesNotOpen mirrors the repro most
// directly: a pre-cancelled context handed to a slow fn. Do's pre-admission guard
// returns context.Canceled before fn runs, so no probe is consumed and the
// breaker stays closed no matter how many times it is called.
func TestDo_PreCancelledContextWithSlowFn_DoesNotOpen(t *testing.T) {
	cfg := Config{
		FailureThreshold:  2,
		CooldownDuration:  time.Minute,
		HalfOpenMaxProbes: 1,
	}
	b := New(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancelled

	for i := 0; i < 5; i++ {
		_, err := Do(ctx, b, func(ctx context.Context) (int, error) {
			time.Sleep(10 * time.Millisecond) // slow fn (never reached: guarded out)
			return 0, ctx.Err()
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	}

	if s := b.State(); s != StateClosed {
		t.Fatalf("a pre-cancelled context must not trip the breaker; state=%q", s)
	}
	if f := b.Stats().TotalFailures; f != 0 {
		t.Fatalf("a pre-cancelled context must record no failures; got %d", f)
	}
}

// TestDo_NilFnPanics covers the constructor-guard invariant for a nil fn,
// mirroring the existing nil-breaker panic test.
func TestDo_NilFnPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for nil fn")
		}
	}()
	b := New(DefaultConfig())
	_, _ = Do[int](context.Background(), b, nil)
}
