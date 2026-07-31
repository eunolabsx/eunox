// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Tests for the shared session-kill TTL: the flag/effective sentinel conversion, and
// the config key the proxy publishes so a process that writes tombstones out-of-band
// (`eunox kill --redis-addr`) applies the same lifetime instead of its own default.

package killswitch

import (
	"context"
	"strings"
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
