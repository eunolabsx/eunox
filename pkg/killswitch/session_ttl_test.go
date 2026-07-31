// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Tests for the shared session-kill TTL: the flag/effective sentinel conversion, and
// the config key the proxy publishes so a process that writes tombstones out-of-band
// (`eunox kill --redis-addr`) applies the same lifetime instead of its own default.

package killswitch

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

// newTTLTestRedis builds a Redis manager against a fresh miniredis, returning both so a
// test can assert on the raw key. Start is deliberately NOT called: publishing and
// reading the config key are one-shot Redis commands with no dependency on the
// reconcile/pub-sub loops, exactly as `eunox kill` uses them.
func newTTLTestRedis(t *testing.T, opts ...RedisOption) (*Redis, *miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return NewRedis(client, opts...), mr, client
}

// TestNormalizeSessionKillTTL pins the flag-to-effective conversion both spellings
// depend on: the operator-facing value uses 0 for "the default" and a negative for
// "never", while the effective value uses 0 for "never". A caller that re-derived this
// could state one lifetime while Redis enforced another.
func TestNormalizeSessionKillTTL(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		flag time.Duration
		want time.Duration
	}{
		{"zero selects the default", 0, defaultSessionKillTTL},
		{"negative means never expire", -1, 0},
		{"large negative means never expire", -720 * time.Hour, 0},
		{"positive is verbatim", 90 * time.Minute, 90 * time.Minute},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, NormalizeSessionKillTTL(tc.flag))
		})
	}
}

// TestWithSessionKillTTLEffective_KeepsNeverExpiring is the regression for the sentinel
// collision between the two options. A permanent lifetime is the zero value in effective
// form, and 0 through WithSessionKillTTL means "use the 30-day default" — so routing a
// resolved value through the wrong option silently converts a permanent tombstone into
// an expiring one, which is the fail-open direction.
func TestWithSessionKillTTLEffective_KeepsNeverExpiring(t *testing.T) {
	t.Parallel()
	r := NewRedis(nil, WithSessionKillTTLEffective(0))
	require.Zero(t, r.SessionKillTTL(), "an effective 0 must stay 'never expires', not become the default")

	r = NewRedis(nil, WithSessionKillTTLEffective(90*time.Minute))
	require.Equal(t, 90*time.Minute, r.SessionKillTTL())

	// A negative has no meaning in effective form; treat it as never rather than as a
	// duration Redis would reject.
	r = NewRedis(nil, WithSessionKillTTLEffective(-time.Hour))
	require.Zero(t, r.SessionKillTTL())

	// The operator-facing option still resolves its own sentinels.
	r = NewRedis(nil, WithSessionKillTTL(0))
	require.Equal(t, defaultSessionKillTTL, r.SessionKillTTL())
	r = NewRedis(nil, WithSessionKillTTL(-1))
	require.Zero(t, r.SessionKillTTL())
}

// TestResolveSessionKillTTLConflict pins the exported conflict-resolution policy: the
// longer-lived of the two effective lifetimes wins (zero, "never expires", beats every
// positive value), and equal values report no mismatch. This is the decision
// cmd/eunox/kill.go's resolveSessionKillTTL used to make inline; it now lives here so a
// future non-CLI writer of session tombstones can reuse the direction instead of
// re-deriving it -- naively preferring its own local value would be the fail-open one.
func TestResolveSessionKillTTLConflict(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name          string
		local         time.Duration
		published     time.Duration
		wantEffective time.Duration
		wantMismatch  bool
	}{
		{"equal values agree", time.Hour, time.Hour, time.Hour, false},
		{"local is longer", 24 * time.Hour, time.Hour, 24 * time.Hour, true},
		{"published is longer", time.Hour, 24 * time.Hour, 24 * time.Hour, true},
		{"local never beats any finite published", 0, 24 * time.Hour, 0, true},
		{"published never beats any finite local", 24 * time.Hour, 0, 0, true},
		{"both never agree", 0, 0, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			effective, mismatch := ResolveSessionKillTTLConflict(tc.local, tc.published)
			require.Equal(t, tc.wantEffective, effective)
			require.Equal(t, tc.wantMismatch, mismatch)
		})
	}
}

// TestPublishAndReadSessionKillTTL_RoundTrip covers the whole point of the key: what the
// proxy publishes is what a second process reads back, for an expiring and a permanent
// lifetime alike.
func TestPublishAndReadSessionKillTTL_RoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		ttl  time.Duration
		raw  string
	}{
		{"expiring", 90 * time.Minute, "1h30m0s"},
		{"never expires", 0, sessionKillTTLNever},
		{"default", defaultSessionKillTTL, defaultSessionKillTTL.String()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, mr, client := newTTLTestRedis(t, WithSessionKillTTLEffective(tc.ttl))
			ctx := context.Background()

			prior, differs, err := r.PublishSessionKillTTL(ctx)
			require.NoError(t, err)
			require.False(t, differs, "nothing was published before, so there is nothing to disagree with")
			require.Zero(t, prior)

			// The stored form is readable in redis-cli: a duration, or the word "never" —
			// never a bare 0, whose numeric form says the opposite of what it means.
			stored, err := mr.Get(redisSessionTTLKey)
			require.NoError(t, err)
			require.Equal(t, tc.raw, stored)

			got, ok, err := ReadPublishedSessionKillTTL(ctx, client)
			require.NoError(t, err)
			require.True(t, ok)
			require.Equal(t, tc.ttl, got)
		})
	}
}

// TestPublishSessionKillTTL_ReportsADifferingPriorValue: the key is last-writer-wins, so
// two proxies configured differently on one Redis leave `eunox kill` adopting whichever
// started last. The publisher reports the disagreement so the operator gets the
// diagnostic the two independent flags never had.
func TestPublishSessionKillTTL_ReportsADifferingPriorValue(t *testing.T) {
	r, _, client := newTTLTestRedis(t, WithSessionKillTTLEffective(2*time.Hour))
	ctx := context.Background()

	_, differs, err := r.PublishSessionKillTTL(ctx)
	require.NoError(t, err)
	require.False(t, differs)

	// Same value again: agreement is not a diagnostic.
	_, differs, err = r.PublishSessionKillTTL(ctx)
	require.NoError(t, err)
	require.False(t, differs, "republishing an identical value must not warn")

	// A second instance with a different lifetime sees the one it replaces.
	other := NewRedis(client, WithSessionKillTTLEffective(0))
	prior, differs, err := other.PublishSessionKillTTL(ctx)
	require.NoError(t, err)
	require.True(t, differs)
	require.Equal(t, 2*time.Hour, prior)

	// And the replacement is what a reader now sees.
	got, ok, err := ReadPublishedSessionKillTTL(ctx, client)
	require.NoError(t, err)
	require.True(t, ok)
	require.Zero(t, got, "the later publisher's permanent lifetime wins")
}

// TestReadPublishedSessionKillTTL_AbsentIsNotAnError: no proxy has started against this
// Redis since the key existed, which is a fall-back-to-local condition rather than a
// failure — the CLI must still be able to write its kill.
func TestReadPublishedSessionKillTTL_AbsentIsNotAnError(t *testing.T) {
	_, _, client := newTTLTestRedis(t)
	ttl, ok, err := ReadPublishedSessionKillTTL(context.Background(), client)
	require.NoError(t, err)
	require.False(t, ok)
	require.Zero(t, ttl)
}

// TestReadPublishedSessionKillTTL_MalformedIsAnError: something other than a proxy wrote
// the key. Reporting it as absent would hide that, and reporting a zero lifetime as a
// value would read as "never expires" — a permanent tombstone nobody configured.
func TestReadPublishedSessionKillTTL_MalformedIsAnError(t *testing.T) {
	cases := []struct{ name, raw string }{
		{"empty", ""},
		{"not a duration", "soon"},
		{"bare zero", "0"},
		{"zero duration", "0s"},
		{"negative duration", "-5m"},
		{"oversized", string(make([]byte, maxSessionTTLValueBytes+1))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, mr, client := newTTLTestRedis(t)
			require.NoError(t, mr.Set(redisSessionTTLKey, tc.raw))

			ttl, ok, err := ReadPublishedSessionKillTTL(context.Background(), client)
			require.Error(t, err, "a malformed published value must not be reported as a lifetime")
			require.False(t, ok)
			require.Zero(t, ttl)
		})
	}
}

// TestParseSessionKillTTL_BoundsRawLengthBeforeTrimming is the regression for checking
// the size guard against the TRIMMED string instead of the raw one: whitespace padding
// around a short, well-formed value would trim down to something under the limit and be
// accepted as a valid duration, even though the raw value is exactly the "garbage or
// hostile" size the bound exists to reject outright -- something other than a proxy
// wrote this key, and TrimSpace should not be able to launder that past the length check.
func TestParseSessionKillTTL_BoundsRawLengthBeforeTrimming(t *testing.T) {
	t.Parallel()
	padded := strings.Repeat(" ", maxSessionTTLValueBytes*4) + "24h" + strings.Repeat(" ", maxSessionTTLValueBytes*4)
	require.Greater(t, len(padded), maxSessionTTLValueBytes, "the raw value must exceed the bound")

	ttl, err := parseSessionKillTTL(padded)
	require.Error(t, err, "oversized padding around a valid duration must still be rejected")
	require.Zero(t, ttl)

	// A value that is short even before trimming is unaffected by the ordering.
	ttl, err = parseSessionKillTTL("  24h  ")
	require.NoError(t, err)
	require.Equal(t, 24*time.Hour, ttl)
}

// TestPublishSessionKillTTL_IgnoresAnUnparseablePriorValue: the read only feeds the
// disagreement diagnostic, so garbage in the key must still be overwritten with a good
// value rather than block the publish.
func TestPublishSessionKillTTL_IgnoresAnUnparseablePriorValue(t *testing.T) {
	r, mr, client := newTTLTestRedis(t, WithSessionKillTTLEffective(time.Hour))
	require.NoError(t, mr.Set(redisSessionTTLKey, "not-a-duration"))

	prior, differs, err := r.PublishSessionKillTTL(context.Background())
	require.NoError(t, err)
	require.False(t, differs, "garbage is not a second live value to reconcile")
	require.Zero(t, prior)

	got, ok, err := ReadPublishedSessionKillTTL(context.Background(), client)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, time.Hour, got)
}

// TestSessionKillTTLKey_SurvivesResetAndIsNotAKill: the config key sits outside the
// agent/session prefixes the reconcile scan and Reset sweep walk. If it were inside
// them, a published TTL would read as a kill on a session named "session-kill-ttl" and a
// Reset would erase the coordination the CLI depends on.
func TestSessionKillTTLKey_SurvivesResetAndIsNotAKill(t *testing.T) {
	r, _, client := newTTLTestRedis(t, WithSessionKillTTLEffective(time.Hour))
	ctx := context.Background()
	_, _, err := r.PublishSessionKillTTL(ctx)
	require.NoError(t, err)

	require.NoError(t, r.KillSession(ctx, "sess-1"))
	require.NoError(t, r.Reset(ctx))

	status, err := r.Status(ctx)
	require.NoError(t, err)
	require.Empty(t, status.KilledSessions, "the config key must never be scanned as a session kill")

	ttl, ok, err := ReadPublishedSessionKillTTL(ctx, client)
	require.NoError(t, err)
	require.True(t, ok, "a kill-state reset must not clear configuration")
	require.Equal(t, time.Hour, ttl)
}

// TestSessionKillTTL_BackendErrorsSurface: publishing is advisory, but a caller can only
// warn about a failure it is told about — a swallowed error would leave the CLI adopting
// its own default while the operator believed the two were coordinated. The same holds
// for the read: an unreachable backend is not "nothing published".
func TestSessionKillTTL_BackendErrorsSurface(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	r := NewRedis(client, WithSessionKillTTLEffective(time.Hour))
	mr.Close() // the backend goes away after the client is built

	_, _, err := r.PublishSessionKillTTL(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "publish session-kill TTL")

	_, ok, err := ReadPublishedSessionKillTTL(context.Background(), client)
	require.Error(t, err)
	require.False(t, ok, "an unreachable backend must not read as 'nothing published'")
}

// TestDescribeSessionKillTTL spells the zero value as words: "0s" says the opposite of
// what it means, and the string lands in operator-facing startup and CLI lines.
func TestDescribeSessionKillTTL(t *testing.T) {
	t.Parallel()
	require.Equal(t, "never expires", DescribeSessionKillTTL(0))
	require.Equal(t, "never expires", DescribeSessionKillTTL(-time.Hour))
	require.Equal(t, "1h30m0s", DescribeSessionKillTTL(90*time.Minute))
}

// ── published-key freshness ────────────────────────────────────────────────

// countingHandler is a slog.Handler that records the messages it is asked to emit, so a
// test can assert not just THAT a diagnostic fired but how many times — which is the
// whole point of deduping a warning that otherwise reprints every reconcile interval.
type countingHandler struct {
	mu   sync.Mutex
	msgs []string
}

func (h *countingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *countingHandler) Handle(_ context.Context, rec slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.msgs = append(h.msgs, rec.Message)
	return nil
}

func (h *countingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *countingHandler) WithGroup(string) slog.Handler      { return h }

// countMatching returns how many recorded messages contain substr.
func (h *countingHandler) countMatching(substr string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, m := range h.msgs {
		if strings.Contains(m, substr) {
			n++
		}
	}
	return n
}

// disagreementMsg is the distinguishing fragment of the periodic mismatch warning.
const disagreementMsg = "advertises a different session-kill TTL"

// TestPublishSessionKillTTL_KeyCarriesExpiry: the published value must not be persistent.
// A key with no expiry is indistinguishable from one a decommissioned instance left
// behind months ago, and `eunox kill` adopts it outright in the common no-flag case —
// silently writing a tombstone that can expire earlier than the running proxy's own.
func TestPublishSessionKillTTL_KeyCarriesExpiry(t *testing.T) {
	t.Parallel()
	r, mr, _ := newTTLTestRedis(t, WithSessionKillTTL(24*time.Hour), WithReconcileInterval(30*time.Second))

	_, _, err := r.PublishSessionKillTTL(context.Background())
	require.NoError(t, err)

	ttl := mr.TTL(redisSessionTTLKey)
	require.NotZero(t, ttl, "the published key must carry a Redis expiry, not be persistent")
	require.Equal(t, r.sessionTTLKeyExpiry(), ttl)
	require.Equal(t, sessionTTLKeyExpiryFactor*30*time.Second, ttl,
		"the expiry must be derived from the reconcile interval, so lengthening one cannot silently invalidate the other")
}

// TestPublishSessionKillTTL_ExpiryFollowsReconcileInterval: an operator who lengthens
// --killswitch-reconcile-interval must not end up with a key that expires between ticks.
func TestPublishSessionKillTTL_ExpiryFollowsReconcileInterval(t *testing.T) {
	t.Parallel()
	for _, interval := range []time.Duration{time.Second, 30 * time.Second, 10 * time.Minute} {
		r, mr, _ := newTTLTestRedis(t, WithSessionKillTTL(time.Hour), WithReconcileInterval(interval))
		_, _, err := r.PublishSessionKillTTL(context.Background())
		require.NoError(t, err)
		got := mr.TTL(redisSessionTTLKey)
		require.Greater(t, got, interval, "expiry %v must outlast at least one reconcile interval %v", got, interval)
		require.Equal(t, sessionTTLKeyExpiryFactor*interval, got)
	}
}

// TestReadPublishedSessionKillTTL_AfterExpiryReportsAbsent is the property the expiry
// buys: a value left behind by a proxy that is no longer running stops being readable, so
// a STALE lifetime becomes an ABSENT one. The reader side already handles absence
// correctly and loudly, so this routes the failure into a path that is already written.
func TestReadPublishedSessionKillTTL_AfterExpiryReportsAbsent(t *testing.T) {
	t.Parallel()
	r, mr, client := newTTLTestRedis(t, WithSessionKillTTL(time.Hour), WithReconcileInterval(30*time.Second))
	ctx := context.Background()

	_, _, err := r.PublishSessionKillTTL(ctx)
	require.NoError(t, err)

	// Still readable while fresh.
	got, ok, err := ReadPublishedSessionKillTTL(ctx, client)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, time.Hour, got)

	// Past the expiry, the decommissioned instance's value is simply gone.
	mr.FastForward(r.sessionTTLKeyExpiry() + time.Second)

	got, ok, err = ReadPublishedSessionKillTTL(ctx, client)
	require.NoError(t, err, "an expired key is a fallback-to-local condition, not an error")
	require.False(t, ok, "an expired value must report absent, not a stale duration")
	require.Zero(t, got)
}

// TestRefreshPublishedSessionKillTTL_ExtendsExpiry: a RUNNING proxy's value must never
// expire under it. The reconcile tick re-publishes, which resets the key's expiry.
func TestRefreshPublishedSessionKillTTL_ExtendsExpiry(t *testing.T) {
	t.Parallel()
	r, mr, client := newTTLTestRedis(t, WithSessionKillTTL(time.Hour), WithReconcileInterval(30*time.Second))
	ctx := context.Background()

	_, _, err := r.PublishSessionKillTTL(ctx)
	require.NoError(t, err)

	// Advance most of the way to expiry, then run the tick's re-publish.
	mr.FastForward(2 * 30 * time.Second)
	require.Less(t, mr.TTL(redisSessionTTLKey), r.sessionTTLKeyExpiry(), "precondition: the key should have aged")

	r.refreshPublishedSessionKillTTL(ctx)
	require.Equal(t, r.sessionTTLKeyExpiry(), mr.TTL(redisSessionTTLKey), "a reconcile tick must reset the expiry")

	// And the value is still readable past the point it would have expired without it.
	mr.FastForward(2 * 30 * time.Second)
	_, ok, err := ReadPublishedSessionKillTTL(ctx, client)
	require.NoError(t, err)
	require.True(t, ok, "a running proxy's value must survive across reconcile ticks")
}

// TestRefreshPublishedSessionKillTTL_WarnsOncePerDistinctPrior covers both halves of the
// dedupe. A persistent disagreement warns ONCE — without that it prints every reconcile
// interval for the life of the process, which trains operators to ignore it — while a
// prior value that CHANGES warns again, because that is new information.
func TestRefreshPublishedSessionKillTTL_WarnsOncePerDistinctPrior(t *testing.T) {
	t.Parallel()
	h := &countingHandler{}
	r, _, client := newTTLTestRedis(t,
		WithSessionKillTTL(24*time.Hour),
		WithReconcileInterval(30*time.Second),
		WithLogger(slog.New(h)))
	ctx := context.Background()

	// Another instance published a different lifetime.
	require.NoError(t, client.Set(ctx, redisSessionTTLKey, "48h0m0s", 0).Err())

	r.refreshPublishedSessionKillTTL(ctx)
	require.Equal(t, 1, h.countMatching(disagreementMsg), "the first disagreement must be reported")

	// The other instance keeps overwriting with the SAME value: still one warning.
	for i := 0; i < 3; i++ {
		require.NoError(t, client.Set(ctx, redisSessionTTLKey, "48h0m0s", 0).Err())
		r.refreshPublishedSessionKillTTL(ctx)
	}
	require.Equal(t, 1, h.countMatching(disagreementMsg), "a persistent disagreement must not reprint every tick")

	// A DIFFERENT prior value is new information and warns again.
	require.NoError(t, client.Set(ctx, redisSessionTTLKey, "12h0m0s", 0).Err())
	r.refreshPublishedSessionKillTTL(ctx)
	require.Equal(t, 2, h.countMatching(disagreementMsg), "a changed prior value must warn again")

	// Once the disagreement resolves (this proxy's own value is what it reads back), the
	// dedupe resets so a recurrence is reported rather than suppressed forever.
	r.refreshPublishedSessionKillTTL(ctx)
	require.Equal(t, 2, h.countMatching(disagreementMsg), "agreement must not warn")
	require.NoError(t, client.Set(ctx, redisSessionTTLKey, "48h0m0s", 0).Err())
	r.refreshPublishedSessionKillTTL(ctx)
	require.Equal(t, 3, h.countMatching(disagreementMsg), "a disagreement that returns must warn again")
}

// TestRefreshPublishedSessionKillTTL_TwoInstancesEachReport: the case a startup-only
// check structurally cannot catch — two proxies whose starts do not overlap. With a
// periodic re-publish they overwrite each other continuously, so each learns of the other
// on its next tick.
func TestRefreshPublishedSessionKillTTL_TwoInstancesEachReport(t *testing.T) {
	t.Parallel()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()

	hA, hB := &countingHandler{}, &countingHandler{}
	a := NewRedis(client, WithSessionKillTTL(24*time.Hour), WithReconcileInterval(30*time.Second), WithLogger(slog.New(hA)))
	b := NewRedis(client, WithSessionKillTTL(48*time.Hour), WithReconcileInterval(30*time.Second), WithLogger(slog.New(hB)))

	// A starts alone: nothing to disagree with.
	_, differs, err := a.PublishSessionKillTTL(ctx)
	require.NoError(t, err)
	require.False(t, differs)

	// B starts an hour later and sees A's value; then A's next tick sees B's.
	_, differs, err = b.PublishSessionKillTTL(ctx)
	require.NoError(t, err)
	require.True(t, differs, "the later-starting instance sees the earlier one at startup")

	a.refreshPublishedSessionKillTTL(ctx)
	require.Equal(t, 1, hA.countMatching(disagreementMsg),
		"the earlier instance must learn of the later one on its next tick, which no startup-only check can do")
}

// TestRefreshPublishedSessionKillTTL_GetFailureStillPublishes matches the startup
// contract: the read only feeds the diagnostic, so a GET failure must not stop the write.
// A WRONGTYPE at the key makes GET fail while SET still succeeds (SET replaces any type).
func TestRefreshPublishedSessionKillTTL_GetFailureStillPublishes(t *testing.T) {
	t.Parallel()
	h := &countingHandler{}
	r, mr, client := newTTLTestRedis(t,
		WithSessionKillTTL(24*time.Hour),
		WithReconcileInterval(30*time.Second),
		WithLogger(slog.New(h)))
	ctx := context.Background()

	require.NoError(t, client.LPush(ctx, redisSessionTTLKey, "not-a-string").Err())
	require.Error(t, client.Get(ctx, redisSessionTTLKey).Err(), "precondition: GET must fail on this key")

	r.refreshPublishedSessionKillTTL(ctx)

	got, ok, err := ReadPublishedSessionKillTTL(ctx, client)
	require.NoError(t, err)
	require.True(t, ok, "a failed GET must not stop the publish")
	require.Equal(t, 24*time.Hour, got)
	require.Equal(t, r.sessionTTLKeyExpiry(), mr.TTL(redisSessionTTLKey), "the re-published key still carries its expiry")
}

// TestRefreshPublishedSessionKillTTL_PublishFailureIsNotFatal: publishing is advisory —
// this proxy applies its own configured lifetime to the tombstones it writes regardless —
// so a failing Redis must be logged and the loop must continue. The failure log is
// edge-triggered for the same reason the disagreement one is.
func TestRefreshPublishedSessionKillTTL_PublishFailureIsNotFatal(t *testing.T) {
	t.Parallel()
	h := &countingHandler{}
	mr := miniredis.RunT(t)
	// Short, non-retrying timeouts: the point of this test is the LOG behaviour on a
	// failing publish, and the client's default retry/backoff would otherwise spend
	// seconds per call proving a server that is already gone is still gone.
	client := redis.NewClient(&redis.Options{
		Addr:         mr.Addr(),
		DialTimeout:  50 * time.Millisecond,
		ReadTimeout:  50 * time.Millisecond,
		WriteTimeout: 50 * time.Millisecond,
		MaxRetries:   -1,
	})
	t.Cleanup(func() { _ = client.Close() })
	r := NewRedis(client, WithSessionKillTTL(time.Hour), WithReconcileInterval(30*time.Second), WithLogger(slog.New(h)))

	mr.Close() // every command now fails

	const failMsg = "could not refresh the session-kill TTL"
	require.NotPanics(t, func() {
		for i := 0; i < 3; i++ {
			r.refreshPublishedSessionKillTTL(context.Background())
		}
	})
	require.Equal(t, 1, h.countMatching(failMsg), "a sustained publish failure must warn once, not every tick")
}
