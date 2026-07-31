// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package killswitch

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/eunolabs/eunox/pkg/durationsentinel"
)

const (
	// redisSessionTTLKey holds the session-kill tombstone lifetime the proxy is running
	// with, so every process that writes a tombstone to this Redis applies the same one.
	//
	// The TTL is stamped by whichever process WRITES the key, and the proxy is not the
	// only writer: `eunox kill --redis-addr` writes tombstones directly, because that is
	// the sole out-of-band revocation channel a stdio proxy has. As two independently
	// configured values there was no way to detect a disagreement, and the failure mode
	// runs one way -- the shorter lifetime wins whenever the CLI is the writer, and an
	// expiring tombstone LIFTS the kill, silently re-admitting a revoked session. The
	// proxy publishes its value here at startup so the CLI can adopt it rather than
	// guess.
	//
	// It sits under its own killswitch:config: prefix, outside the killswitch:agent: and
	// killswitch:session: prefixes the reconcile scan and Reset sweep walk, so it is
	// never mistaken for a kill and never cleared by a state reset -- it is
	// configuration, not kill-switch state.
	redisSessionTTLKey = "killswitch:config:session-kill-ttl"

	// sessionKillTTLNever is the wire spelling of a tombstone that never expires. The
	// in-process representation of "never" is a zero duration (Redis SET applies no
	// expiry at 0), which reads as "unset" to a human running `redis-cli GET` on the
	// key; the word cannot be misread.
	sessionKillTTLNever = "never"

	// maxSessionTTLValueBytes bounds the published value before it is parsed. A
	// well-formed value is a couple of dozen bytes ("720h0m0s"), so anything larger is
	// garbage or hostile and is rejected without being handed to time.ParseDuration.
	maxSessionTTLValueBytes = 64
)

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
// config key, so a process that writes tombstones out-of-band -- `eunox kill
// --redis-addr`, the only revocation channel a stdio proxy has -- applies the proxy's
// lifetime instead of its own default. Call it once at startup, after connectivity is
// confirmed.
//
// It returns the previously published lifetime and true when one was present and
// DIFFERS from this instance's: two proxies sharing one Redis with different
// configurations, or a restart that changed the value. That is a real ambiguity (the
// key is last-writer-wins) and the caller should say so; an absent, identical, or
// unparseable prior value reports false, since none of the three leaves an operator
// with two live values to reconcile.
//
// The read is best-effort and only feeds that diagnostic: a failed GET still publishes,
// and only a failed SET is returned as an error. Publishing is advisory -- enforcement
// uses this instance's own configured value either way -- so a caller should warn on an
// error rather than refuse to start.
func (r *Redis) PublishSessionKillTTL(ctx context.Context) (prior time.Duration, differs bool, err error) {
	mine := r.SessionKillTTL()
	// Read before writing so the caller can report a disagreement. A GET error (or an
	// absent/garbage value) simply yields no diagnostic; it must not stop the publish.
	if raw, gerr := r.client.Get(ctx, redisSessionTTLKey).Result(); gerr == nil {
		if parsed, perr := parseSessionKillTTL(raw); perr == nil && parsed != mine {
			prior, differs = parsed, true
		}
	}
	// setErr, not err: the named return err is never otherwise assigned in this
	// function (both paths use an explicit return triple), so shadowing it here would
	// be harmless today but a future edit that merges this branch into a shared error
	// path (e.g. "err = ...; return") could silently start returning the outer,
	// never-assigned err (nil) instead of this one -- the caller would then believe
	// the publish succeeded when the SET actually failed.
	if setErr := r.client.Set(ctx, redisSessionTTLKey, formatSessionKillTTL(mine), 0).Err(); setErr != nil {
		return 0, false, fmt.Errorf("killswitch: publish session-kill TTL: %w", setErr)
	}
	return prior, differs, nil
}

// ReadPublishedSessionKillTTL returns the EFFECTIVE session-kill tombstone lifetime a
// proxy on this Redis published at startup (zero means tombstones never expire) and
// whether one was published at all. A caller that writes tombstones itself should apply
// this value rather than its own default, so a revocation cannot expire earlier than
// the proxy's own kills do.
//
// A missing key reports (0, false, nil) -- no proxy has published one (none has started
// against this Redis since the value existed, or the write failed) -- which is a
// fallback-to-local condition, not an error. A malformed value IS an error: it means
// something other than a proxy wrote the key, and silently treating that as "absent"
// would hide it.
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
// tombstone write should use when a value this writer would use on its own (local,
// already normalized -- e.g. through NormalizeSessionKillTTL) disagrees with a value
// published by a proxy on the same Redis (published, from ReadPublishedSessionKillTTL).
// It returns the longer-lived of the two -- zero (never expires) beats every positive
// value -- and whether the two actually disagreed.
//
// Preferring the LONGER lifetime, not the published one outright, matters because the
// tombstone this decision governs is itself an emergency-stop write: refusing to write
// it because two lifetimes disagree fails in the one direction that matters, while a
// too-long tombstone only ever over-blocks a session id that is already gone. This is
// exported, not folded into the CLI, so a future non-CLI writer of session tombstones
// can reuse the decision rather than re-derive it -- naively preferring its own local
// value over the published one is exactly the fail-open direction this coordination
// exists to close.
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

// DescribeSessionKillTTL renders an effective lifetime for an operator-facing message,
// spelling the zero value as "never expires" rather than "0s" -- the one value whose
// numeric form says the opposite of what it means.
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
// never expires). A non-positive duration is rejected rather than mapped onto "never":
// the two spellings of never would then differ by a sign that no writer intends, and a
// "0s" that actually meant "expire immediately" would be read as a permanent tombstone.
func parseSessionKillTTL(raw string) (time.Duration, error) {
	// Bound the RAW length before any processing, including TrimSpace: checking the
	// trimmed string instead would let arbitrary whitespace padding around a short,
	// well-formed value (e.g. a few hundred KB of spaces around "24h") trim down to
	// something under the limit and sail through as valid -- exactly the "handed to
	// time.ParseDuration" outcome this bound exists to prevent for a value this large.
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
