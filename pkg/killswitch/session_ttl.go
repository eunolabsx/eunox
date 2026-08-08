// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package killswitch

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/eunolabs/eunox/pkg/durationsentinel"
)

const (
	// redisSessionTTLKey holds the session-kill tombstone lifetime the proxy is running
	// with, so every process writing a tombstone applies the same one. `eunox kill
	// --redis-addr` writes tombstones directly too, so a disagreement's failure mode
	// runs one way — the shorter lifetime wins, and an expiring tombstone LIFTS the
	// kill. The proxy publishes here at startup so the CLI can adopt it rather than guess.
	//
	// It sits under its own killswitch:config: prefix, outside the reconcile scan and
	// Reset sweep's prefixes, so it is never mistaken for a kill or cleared by a reset.
	redisSessionTTLKey = "killswitch:config:session-kill-ttl"

	// sessionKillTTLNever is the wire spelling of a tombstone that never expires: the
	// in-process zero duration reads as "unset" to a human running `redis-cli GET`, so
	// the word cannot be misread.
	sessionKillTTLNever = "never"

	// maxSessionTTLValueBytes bounds the published value before parsing: a well-formed
	// value is a couple dozen bytes, so anything larger is garbage or hostile.
	maxSessionTTLValueBytes = 64

	// sessionTTLKeyExpiryFactor sets the key's own Redis expiry as a MULTIPLE of the
	// reconcile interval (not a fixed duration), since the running proxy keeps it alive
	// by re-publishing from that loop; three tolerates a missed tick plus jitter while
	// still making a decommissioned instance's value stop answering quickly.
	sessionTTLKeyExpiryFactor = 3

	// sessionTTLPublishTimeout bounds the reconcile tick's re-publish. A small fraction
	// of the interval, since the publish shares a goroutine with the cache refresh that
	// bounds kill propagation and must not delay it.
	sessionTTLPublishTimeout = 3 * time.Second
)

// sessionTTLKeyExpiry is how long a published value stays readable without being
// refreshed. Bounding freshness turns a STALE value — indistinguishable from a live one,
// since the key carries no timestamp or writer identity — into an ABSENT one, routing it
// into the already-correct "nothing published" fallback path.
func (r *Redis) sessionTTLKeyExpiry() time.Duration {
	iv := r.reconcileInterval
	if iv <= 0 {
		iv = defaultReconcileInterval
	}
	expiry := sessionTTLKeyExpiryFactor * iv
	if expiry <= 0 {
		// Overflowed int64 (an absurd reconcile interval). A negative expiry is worse
		// than useless: go-redis treats it as "no expiration", making the key PERSISTENT
		// — the opposite of this function's guarantee. Fall back to the default bound.
		return sessionTTLKeyExpiryFactor * defaultReconcileInterval
	}
	return expiry
}

// publishedValueExpiry is the expiry to stamp on a published value, NOT always
// sessionTTLKeyExpiry: a permanent lifetime is published with no expiry, since letting a
// "never expires" value lapse would only make `eunox kill` fall back to its own 30-day
// default — the fail-open direction — while a stale permanent value can only OVER-block.
func (r *Redis) publishedValueExpiry(effective time.Duration) time.Duration {
	if effective <= 0 {
		return 0 // never expires, in both the value and the key
	}
	return r.sessionTTLKeyExpiry()
}

// NormalizeSessionKillTTL resolves an OPERATOR-FACING session-kill TTL value (the
// --killswitch-session-ttl flag, or the argument to WithSessionKillTTL) to the
// EFFECTIVE lifetime the Redis SET applies: negative means never expire, zero selects
// the default, and any positive value is used as-is.
//
// The two spellings do not agree on what zero means -- it is "use the default" going in
// and "never expires" coming out -- so the conversion lives here once. A caller that
// re-derived it (a startup banner, a CLI comparing its flag against the published
// value) could state one lifetime while Redis enforced another.
func NormalizeSessionKillTTL(flagValue time.Duration) time.Duration {
	return durationsentinel.Resolve(flagValue, defaultSessionKillTTL)
}

// SessionKillTTL returns the EFFECTIVE session-kill tombstone lifetime this manager
// applies: zero means tombstones never expire. Agent kills are never expired, so this
// governs session kills only.
func (r *Redis) SessionKillTTL() time.Duration {
	// Set at construction and never mutated (see RedisOption), so this needs no lock.
	return r.sessionKillTTL
}

// PublishSessionKillTTL writes this manager's effective session-kill TTL to the shared
// config key, so `eunox kill --redis-addr` (the only out-of-band revocation channel a
// stdio proxy has) applies the proxy's lifetime instead of its own default. Call once at
// startup; Start's reconcile loop then keeps the key alive (see sessionTTLKeyExpiry).
//
// It returns the previously published lifetime and true when one DIFFERS from this
// instance's — a real ambiguity (last-writer-wins) worth surfacing; absent, identical, or
// unparseable reports false. The read is best-effort (a failed GET yields no diagnostic,
// but still publishes); only a failed SET is returned as an error.
func (r *Redis) PublishSessionKillTTL(ctx context.Context) (prior time.Duration, differs bool, err error) {
	if r.wiringErr != nil {
		return 0, false, r.wiringErr
	}
	// Arm the reconcile loop's republish HERE, regardless of how the round trip goes: once
	// the caller's ready hook has run, a FAILED publish is exactly the case the loop should
	// retry. Latching on success alone would silently disable that self-healing. See
	// sessionTTLPublished.
	r.sessionTTLPublished.Store(true)
	mine := r.SessionKillTTL()
	// Read before writing so the caller can report a disagreement. A GET error (or an
	// absent/garbage value) simply yields no diagnostic; it must not stop the publish.
	if raw, gerr := r.client.Get(ctx, redisSessionTTLKey).Result(); gerr == nil {
		if parsed, perr := parseSessionKillTTL(raw); perr == nil && parsed != mine {
			prior, differs = parsed, true
		}
	}
	// setErr, not err: a future edit merging this into a shared error path could
	// otherwise silently return the outer, never-assigned err (nil) instead.
	if setErr := r.client.Set(ctx, redisSessionTTLKey, formatSessionKillTTL(mine), r.publishedValueExpiry(mine)).Err(); setErr != nil {
		return 0, false, fmt.Errorf("killswitch: publish session-kill TTL: %w", setErr)
	}
	return prior, differs, nil
}

// refreshPublishedSessionKillTTL re-publishes the value from the reconcile tick, keeping
// the key alive for as long as this proxy runs. It rides the EXISTING loop deliberately
// (no new goroutine, ticker, or connection) and also fixes the disagreement diagnostic a
// one-shot startup check cannot, since two proxies with different lifetimes overwrite each
// other continuously. Advisory and never fatal: a failure is logged and the loop continues.
func (r *Redis) refreshPublishedSessionKillTTL(ctx context.Context) {
	// REFRESH means refresh: publishes nothing on its own. Start runs before the
	// transport serves, so an unconditional SET here would let any failed startup
	// clobber a running proxy's published lifetime. See sessionTTLPublished.
	if !r.sessionTTLPublished.Load() {
		return
	}
	// Carve a short budget out of the loop's deadline-free context: this runs right
	// after the cache refresh that BOUNDS kill propagation, so a slow Redis must not let
	// this advisory write stretch the reconcile interval and the denial window with it.
	pubCtx, cancel := context.WithTimeout(ctx, sessionTTLPublishTimeout)
	defer cancel()
	prior, differs, err := r.PublishSessionKillTTL(pubCtx)
	if r.logger == nil {
		return
	}
	if err != nil {
		if r.markSessionTTLPublishErr(true) {
			r.logger.Warn("kill switch: could not refresh the session-kill TTL published to Redis; `eunox kill --redis-addr` falls back to its own --killswitch-session-ttl once the published value expires",
				slog.String("error", err.Error()),
				slog.Duration("keyExpiry", r.sessionTTLKeyExpiry()))
		}
		return
	}
	r.markSessionTTLPublishErr(false)
	if !differs {
		// Deliberately does NOT reset the dedupe: two proxies ticking at different rates
		// would otherwise alternate between agreement and disagreement, re-arming the
		// warning every tick and printing it forever.
		return
	}
	if r.markSessionTTLDisagreement(formatSessionKillTTL(prior)) {
		r.logger.Warn("kill switch: another writer on this Redis advertises a different session-kill TTL; the key is last-writer-wins, so `eunox kill` adopts whichever was published most recently. Align --killswitch-session-ttl across instances",
			slog.String("published", DescribeSessionKillTTL(prior)),
			slog.String("mine", DescribeSessionKillTTL(r.SessionKillTTL())))
	}
}

// markSessionTTLDisagreement records the prior value observed and reports whether it is
// NEW, worth another log line. Keyed on the value itself, not a flag, so a value that
// CHANGES warns again; formatSessionKillTTL never returns "", so zero is unambiguous.
func (r *Redis) markSessionTTLDisagreement(prior string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sessionTTLWarnedPrior == prior {
		return false
	}
	r.sessionTTLWarnedPrior = prior
	return true
}

// markSessionTTLPublishErr edge-triggers the re-publish failure log (failing after being
// healthy), mirroring reconcileErrLogged on the same loop.
func (r *Redis) markSessionTTLPublishErr(failing bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	wasLogged := r.sessionTTLPublishErrLogged
	r.sessionTTLPublishErrLogged = failing
	return failing && !wasLogged
}

// ReadPublishedSessionKillTTL returns the EFFECTIVE session-kill tombstone lifetime a
// proxy on this Redis published at startup, and whether one was published at all. A
// missing key reports (0, false, nil), a fallback-to-local condition, not an error; a
// malformed value IS an error, since something other than a proxy wrote the key.
func ReadPublishedSessionKillTTL(ctx context.Context, client redis.Cmdable) (time.Duration, bool, error) {
	raw, err := client.Get(ctx, redisSessionTTLKey).Result()
	if errors.Is(err, redis.Nil) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("killswitch: read published session-kill TTL: %w", err)
	}
	ttl, err := parseSessionKillTTL(raw)
	if err != nil {
		return 0, false, err
	}
	return ttl, true, nil
}

// ResolveSessionKillTTLConflict decides which of two EFFECTIVE session-kill lifetimes a
// tombstone write should use when local (already normalized) disagrees with published
// (from ReadPublishedSessionKillTTL). Returns the LONGER-lived of the two, not the
// published one outright: the tombstone is an emergency-stop write, so refusing it on
// disagreement fails in the one direction that matters, while over-long only over-blocks
// an already-gone session id.
func ResolveSessionKillTTLConflict(local, published time.Duration) (effective time.Duration, mismatch bool) {
	if local == published {
		return local, false
	}
	return longerTombstone(local, published), true
}

// longerTombstone returns whichever effective lifetime keeps a tombstone alive longer,
// where zero means it never expires and therefore outlives every finite value.
func longerTombstone(a, b time.Duration) time.Duration {
	if a <= 0 || b <= 0 {
		return 0
	}
	return max(a, b)
}

// DescribeSessionKillTTL renders an effective lifetime for an operator message, spelling
// zero as "never expires" rather than "0s", the one form that says the opposite of what it means.
func DescribeSessionKillTTL(effective time.Duration) string {
	if effective <= 0 {
		return "never expires"
	}
	return effective.String()
}

// formatSessionKillTTL encodes an effective lifetime for the shared config key.
func formatSessionKillTTL(effective time.Duration) string {
	if effective <= 0 {
		return sessionKillTTLNever
	}
	return effective.String()
}

// parseSessionKillTTL decodes a published value into an effective lifetime (zero means
// never expires). A non-positive duration is rejected rather than mapped onto "never",
// since a "0s" meaning "expire immediately" would otherwise read as a permanent tombstone.
func parseSessionKillTTL(raw string) (time.Duration, error) {
	// Bound the RAW length before TrimSpace: checking the trimmed string would let
	// megabytes of whitespace around a short value sail through under the limit.
	if len(raw) > maxSessionTTLValueBytes {
		return 0, fmt.Errorf("killswitch: published session-kill TTL is %d bytes; expected a duration or %q", len(raw), sessionKillTTLNever)
	}
	s := strings.TrimSpace(raw)
	if strings.EqualFold(s, sessionKillTTLNever) {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("killswitch: published session-kill TTL %q is not a duration or %q", s, sessionKillTTLNever)
	}
	if d <= 0 {
		return 0, fmt.Errorf("killswitch: published session-kill TTL %q must be positive, or %q for a tombstone that never expires", s, sessionKillTTLNever)
	}
	return d, nil
}
