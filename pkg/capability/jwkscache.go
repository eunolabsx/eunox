// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"context"
	"crypto"
	_ "crypto/sha256" // registers SHA-256 for jose.JSONWebKey.Thumbprint
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/eunolabs/eunox/pkg/circuitbreaker"
	jose "github.com/go-jose/go-jose/v4"
)

// ErrJWKSUnavailable tags every failure to obtain a usable key set from the JWKS endpoint —
// a network error, a non-200, an empty/oversized set, an unparseable body, or an open
// circuit breaker. It marks the failure as a key-infrastructure availability problem, not a
// forged token: the presented token was never even checked against a key, so it must NOT be
// recorded in the audit trail as if it were. The audit layer keys on it via errors.Is to
// classify the record as a JWKS outage (see ClassifyJWTError).
var ErrJWKSUnavailable = errors.New("JWKS unavailable")

// JWKSCache fetches and caches a remote JSON Web Key Set. It is the shared cache consumed by
// the gateway's IdP-JWT validator, which keeps only its own claim-validation logic and
// delegates fetch/cache/singleflight/breaker/TTL behaviour here.
//
// Concurrency: a singleflight group collapses concurrent refreshes into one HTTP round-trip
// whose result waiters share. The fetch is decoupled from any caller's context
// (context.WithoutCancel) so one caller's deadline neither aborts the shared fetch nor
// charges a spurious breaker failure for every waiter.
type JWKSCache struct {
	jwksURI string
	client  *http.Client
	logger  *slog.Logger
	breaker *circuitbreaker.Breaker
	now     func() time.Time

	mu        sync.RWMutex
	jwks      *jose.JSONWebKeySet
	fetchedAt time.Time
	cacheTTL  time.Duration
	// fetchTicket issues a monotonically increasing generation to each fetch when it begins;
	// installedFetchGen records the ticket of the installed set. Forced and non-forced
	// refreshes run concurrently with no completion ordering, so the guard commits an
	// install only when its ticket is newer than the installed one — otherwise an
	// earlier-started, later-finishing fetch could overwrite a newer forced rotation and
	// reintroduce a removed key for the TTL. Both guarded by mu.
	fetchTicket       uint64
	installedFetchGen uint64

	// maxFetch is the ceiling applied to the shared fetch when the HTTP client has no finite
	// timeout of its own (see maxJWKSFetch). Overridable in tests.
	maxFetch time.Duration

	// sfGroup deduplicates concurrent refreshes into one in-flight round-trip; callers block
	// on the group (not c.mu) and share the result.
	sfGroup singleflight.Group

	// negMu guards negKIDs, the negative cache of key IDs a forced refresh failed to resolve
	// (see ForceRefreshForKID), so a flood of distinct unknown-kid tokens cannot amplify into
	// one round-trip each. Separate from mu so a kid-miss lookup never contends with a
	// fetch's write lock; RWMutex so the hot-path read runs concurrently across flood callers.
	// Keyed by negKIDKey, never by the raw kid.
	negMu   sync.RWMutex
	negKIDs map[string]time.Time
}

const (
	// negativeKIDTTL bounds how long a kid a forced refetch failed to resolve is remembered
	// as absent (fails closed without another forced fetch); short so a genuinely
	// rotated-in kid is retried promptly.
	negativeKIDTTL = 30 * time.Second
	// negativeKIDMaxLen caps the negative cache so a flood of distinct unknown kids cannot
	// grow the map without bound. At the cap a new kid falls back to the breaker-bounded
	// forced-refresh path, degrading safely.
	negativeKIDMaxLen = 1024
	// maxJWKSKeys bounds how many keys a JWKS response may carry. A kid-less token trials
	// every key, so an oversized set lets a compromised endpoint force O(keys) asymmetric
	// verifications per such token. Over the cap is rejected wholesale (fail closed); the
	// breaker records it and any cached good set keeps serving.
	maxJWKSKeys = 100
	// maxJWKSFetch is the ceiling on the shared fetch when the HTTP client has no finite
	// timeout of its own (a zero-value client has Timeout == 0); without this a stalled
	// transport would hang every verification joining the singleflight call.
	maxJWKSFetch = 30 * time.Second
)

// JWKSCacheConfig configures a [JWKSCache].
type JWKSCacheConfig struct {
	// JWKSURL is the endpoint serving the issuer's JSON Web Key Set.
	JWKSURL string
	// CacheTTL is how long a fetched JWKS is served from cache. Default: 5 minutes.
	CacheTTL time.Duration
	// Client is the HTTP client used for fetching. Default: 10s timeout with redirects
	// refused outright. Supplying a client replaces that redirect policy with whatever the
	// client carries, so the cache additionally enforces the same-origin floor on the
	// RESPONSE (see refuseCrossOriginResponse) — a supplied client cannot weaken it.
	Client *http.Client
	// Logger for operational messages. Default: slog.Default().
	Logger *slog.Logger
	// Breaker optionally protects refreshes from a flapping upstream. When nil the cache
	// fetches directly; a caller wanting breaker protection on every fetch must supply one.
	Breaker *circuitbreaker.Breaker
	// Now is an optional clock used for the cache-TTL comparison (testing). Default: time.Now.
	Now func() time.Time
}

// NewJWKSCache creates a JWKS cache. Unset config fields take their defaults.
func NewJWKSCache(cfg JWKSCacheConfig) *JWKSCache { //nolint:gocritic // hugeParam: config struct is intentionally passed by value; callers build it inline
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 5 * time.Minute
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{
			Timeout: 10 * time.Second,
			// Refuse to follow redirects: the JWKS endpoint is the root of trust, so a 30x to
			// another host (an SSRF pivot or attacker-chosen key source) must never be followed
			// silently. ErrUseLastResponse surfaces the redirect as a non-200 fetchKeys fails
			// closed on. In-library defense for direct cache callers; the CLI also validates
			// scheme/host up front.
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	// The JWKS endpoint is the root of trust for token verification, so a plaintext http://
	// URL to a non-loopback host is silently MITM-able. The CLI validates the scheme up
	// front, but a direct library consumer gets no such check — warn loudly here (without
	// failing construction, so the CLI's own opt-out isn't double-reported).
	if u, err := url.Parse(cfg.JWKSURL); err == nil && u.Scheme == "http" && !IsLoopbackHost(u.Hostname()) {
		// Redact: some IdPs gate the JWKS endpoint behind a query key or basic-auth
		// userinfo, and this lands in whatever handler the consumer wired — commonly a
		// JSON log shipped to a central store.
		cfg.Logger.Warn("JWKS URL uses plaintext http to a non-loopback host; the key set is the root of trust for token verification and is MITM-able over http — use https", slog.String("url", RedactURLForLog(cfg.JWKSURL)))
	}
	return &JWKSCache{
		jwksURI:  cfg.JWKSURL,
		client:   cfg.Client,
		logger:   cfg.Logger,
		breaker:  cfg.Breaker,
		now:      cfg.Now,
		cacheTTL: cfg.CacheTTL,
		maxFetch: maxJWKSFetch,
		negKIDs:  make(map[string]time.Time),
	}
}

// ErrKeysUnservable is the key-fetch health verdict for the one condition under which this
// layer can no longer validate anything: refreshes refused AND no cached set inside its TTL.
// It wraps [ErrJWKSUnavailable] because that is exactly what a token arriving now would meet.
var ErrKeysUnservable = fmt.Errorf("%w: key refreshes are being refused and no cached key set is within its TTL, so every token fails closed", ErrJWKSUnavailable)

// KeyFetchHealth is a cache's key-fetch readiness: the breaker's own statistics, plus the one
// fact the breaker cannot know — whether the cached key set can still serve.
//
// Both, rather than the breaker's state alone, because trip time and impact time are not the
// same moment: the breaker's cooldown is tens of seconds while CacheTTL defaults to five
// minutes, so an IdP blip trips it while the cached set is seconds old and carries every `kid`
// in live use. A consumer reading only the state reports an outage through a window in which
// 100% of tokens validate — which is the cached-then-fail-closed posture working as intended.
type KeyFetchHealth struct {
	// Breaker is the guard's projected state and counters. Read-only by construction: Stats
	// PROJECTS the post-cooldown half-open state without mutating, so a caller polling this
	// can never consume the half-open probe budget a real verification needs.
	Breaker circuitbreaker.Stats
	// KeysServable reports that a fetched key set is installed and still inside its TTL, so
	// tokens carrying a `kid` it holds keep validating however the breaker reads.
	KeysServable bool
}

// FetchImpeded reports that key REFRESHES are refused: rotation is blocked for the duration,
// and a token carrying a `kid` the cached set does not hold fails closed at once, since
// ForceRefreshForKID is refused too. True well before the layer stops working, which is why it
// is not on its own the readiness verdict — see Status.
func (h KeyFetchHealth) FetchImpeded() bool { //nolint:gocritic // hugeParam: a value receiver keeps these predicates callable directly on the snapshot KeyFetchHealth returns, including a non-addressable one; the type is a read-only sample read once per scrape, and a pointer receiver on it would invite the reader to treat it as live state
	return h.Breaker.State.Impeded()
}

// HealthStatus is the readiness verdict for THIS sample: nil while the layer it describes can
// still validate tokens, and [ErrKeysUnservable] once it cannot.
//
// The verdict is impact rather than impediment. An impeded breaker over a warm cache is
// worth an ALERT (rotation is blocked, an unknown `kid` fails now) and is reported as
// FetchImpeded for exactly that, but it is not a readiness regression: draining a replica on
// it takes the whole fleet out of rotation on a blip the cache absorbs, and every replica
// shares the IdP, so they all trip inside the same window.
//
// On the SAMPLE rather than on the cache, and named to satisfy a consumer's readiness seam, so a
// consumer that also renders this sample's fields folds the verdict OF THE FIELDS IT RENDERED. Re-
// asking the cache takes a second, independent reading: one /healthz body could then report a
// servable key set beside a verdict that says every token fails closed, purely because the TTL
// lapsed between the two reads.
//
// The zero value is not a sample and reports an outage — [KeyFetchHealth]'s zero State is unknown,
// which [circuitbreaker.State.Impeded] answers true for, fail-safe. A caller must honour the ok
// result of [JWKSCache.KeyFetchHealth] rather than verdict on an unpopulated value.
func (h KeyFetchHealth) HealthStatus() error { //nolint:gocritic // hugeParam: see FetchImpeded
	if h.FetchImpeded() && !h.KeysServable {
		return ErrKeysUnservable
	}
	return nil
}

// KeyFetchHealth reports this cache's key-fetch readiness, and whether there is a guard to
// report on at all: Breaker is optional, and a cache without one fetches directly.
//
// It answers the readiness question rather than passing its dependency's state machine
// through, because the staleness half of that answer is this type's own (see freshAt) and a
// consumer joining the two would be re-deriving a predicate it cannot see. The nil-receiver
// arm lets a health endpoint report rather than panic on a consumer-built validator carrying
// no cache.
func (c *JWKSCache) KeyFetchHealth() (KeyFetchHealth, bool) {
	if c == nil || c.breaker == nil {
		return KeyFetchHealth{}, false
	}
	c.mu.RLock()
	servable := c.freshAt(c.now())
	c.mu.RUnlock()
	return KeyFetchHealth{Breaker: c.breaker.Stats(), KeysServable: servable}, true
}

// IsLoopbackHost reports whether host (a URL hostname, no port) is a loopback name or
// address — the one case where a plaintext http JWKS URL carries no MITM exposure. Exported
// as the single source of truth: cmd/eunox's startup --jwks-uri scheme gate consults it too,
// so the two cannot re-diverge the way two independent copies previously did.
func IsLoopbackHost(host string) bool {
	// DNS host names are case-insensitive (RFC 4343) and url.Parse does not normalize case,
	// so "LOCALHOST"/"Localhost" reach here verbatim. Trim a trailing FQDN dot too.
	if strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// freshAt reports whether a key set is installed and still inside its TTL as of now — the
// single staleness predicate for the cache, asked at three different lock depths (GetKeys,
// refresh's pre-singleflight check, refresh's in-closure double-check) so a change to what
// "fresh" means lands in one place.
//
// The clock reading is the CALLER's rather than taken inside: c.now is an injectable func
// field, and an indirect call through it pushes this past the inliner's budget on the
// per-token verification path. Passing the sampled time keeps the predicate inlined.
//
// The caller MUST hold c.mu (read or write): it reads jwks and fetchedAt, both guarded.
func (c *JWKSCache) freshAt(now time.Time) bool {
	return c.jwks != nil && now.Sub(c.fetchedAt) < c.cacheTTL
}

// GetKeys returns the cached JWKS when it is still within the TTL, otherwise it fetches a
// fresh copy.
//
// The returned set's Keys SLICE is independent of the cache's (see copyKeySet), so a caller
// may hold, append to, or reorder it without disturbing concurrent verifications — every
// exported accessor shares this contract, so no caller holds the live instance.
//
// The copy is one level deep: each jose.JSONWebKey still carries a Key interface{} pointing
// at the same underlying public key, so the KEYS THEMSELVES remain read-only; mutating one
// would corrupt the root-of-trust material seen by every concurrent validation.
//
// The production consumer (VerifyWithKeyRotation) uses getKeysLive instead — see its doc.
func (c *JWKSCache) GetKeys(ctx context.Context) (*jose.JSONWebKeySet, error) {
	keys, err := c.getKeysLive(ctx)
	if err != nil {
		return nil, err
	}
	return copyKeySet(keys), nil
}

// getKeysLive is GetKeys' uncopied core: it returns the cache's live *jose.JSONWebKeySet (or
// a fresh one just fetched), never a copy.
//
// Unexported, reached only from VerifyWithKeyRotation, which immediately narrows the result
// through FindKeys — itself always allocating a fresh slice — so copyKeySet's whole-set copy
// on this path is pure transient garbage (measured ~14.4 KB per call at maxJWKSKeys keys,
// paid on every verification including the cache-hit case). GetKeys wraps this with
// copyKeySet for every other caller, whose contract still promises an independent set.
func (c *JWKSCache) getKeysLive(ctx context.Context) (*jose.JSONWebKeySet, error) {
	c.mu.RLock()
	if c.freshAt(c.now()) {
		keys := c.jwks
		c.mu.RUnlock()
		return keys, nil
	}
	c.mu.RUnlock()
	keys, _, err := c.refresh(ctx, false)
	return keys, err
}

// copyKeySet returns a set whose Keys SLICE is independent of the cached one, so a caller
// appending to, reordering, or truncating the result cannot mutate the shared cache other
// verifications are concurrently reading. Handing out the live pointer made that aliasing
// defense bypassable by anyone calling GetKeys/Refresh directly.
//
// The copy is one level deep: mutating a KEY'S INTERNALS still reaches the cache (inherent
// to the type, same bound FindKeys has) — the realistic accident this closes is slice
// mutation.
func copyKeySet(set *jose.JSONWebKeySet) *jose.JSONWebKeySet {
	if set == nil {
		return nil
	}
	return &jose.JSONWebKeySet{Keys: append([]jose.JSONWebKey(nil), set.Keys...)}
}

// Refresh returns a fresh JWKS, respecting the cache TTL: if the cached copy is still
// within TTL it is returned without an HTTP fetch. The returned set's Keys slice is
// independent of the cache's (see copyKeySet); individual jose.JSONWebKey values still
// share their underlying crypto key, so treat the KEYS themselves as read-only.
func (c *JWKSCache) Refresh(ctx context.Context) (*jose.JSONWebKeySet, error) {
	keys, _, err := c.refresh(ctx, false)
	return copyKeySet(keys), err
}

// ForceRefreshForKID performs a rate-limited forced fetch, but suppresses it for a kid
// that cannot be resolved right now, returning the cached set instead — so a stream of
// distinct unknown-kid tokens cannot drive one round-trip per token. The caller still
// fails closed when suppressed (the kid is absent from the returned set).
//
// Two suppression signals gate the fetch, both bounded by negativeKIDTTL:
//   - per-kid: a kid a recent forced refetch failed to resolve is not refetched;
//   - shared budget (sharedRefreshSentinel): once a forced fetch returns an unchanged set
//     it is charged, and while charged DISTINCT unknown kids are suppressed too — the
//     bound the per-kid cache alone can't give, since an unchanged 200 never trips the
//     breaker.
//
// Tradeoff: while the budget is charged, a kid the issuer rotates IN is not observed for up
// to negativeKIDTTL. Bounded and self-healing: when the budget expires the next lookup
// fetches, sees the CHANGED set, resolves the kid, and does not re-charge.
//
// An empty kid is never suppressed, a found kid never charges either signal, and a cold
// cache (no set at all) is never suppressed.
func (c *JWKSCache) ForceRefreshForKID(ctx context.Context, kid string) (*jose.JSONWebKeySet, error) {
	keys, err := c.forceRefreshForKIDLive(ctx, kid)
	if err != nil {
		return nil, err
	}
	return copyKeySet(keys), nil
}

// forceRefreshForKIDLive is ForceRefreshForKID's uncopied core: like getKeysLive, it returns
// the cache's live *jose.JSONWebKeySet on both arms, never a copy. Reached only from
// VerifyWithKeyRotation, which narrows the result through FindKeys — always a fresh,
// independent slice — so ForceRefreshForKID's copy would be pure allocation on a pre-auth
// path a flood of unknown-kid tokens can drive at will.
func (c *JWKSCache) forceRefreshForKIDLive(ctx context.Context, kid string) (*jose.JSONWebKeySet, error) {
	if kid == "" {
		// A kid-less lookup is not an unknown-kid lookup. The suppression block below is
		// gated on kid != "", so routing it here would skip the rate-limit and let a flood
		// of kid-less tokens hammer the endpoint. Delegate to the rate-limited kid-less path.
		return c.forceRefreshForVerifyLive(ctx)
	}
	if c.kidRecentlyAbsent(kid) || c.kidRecentlyAbsent(sharedRefreshSentinel) {
		c.mu.RLock()
		cached := c.jwks
		c.mu.RUnlock()
		if cached != nil {
			return cached, nil
		}
	}
	// changed reports whether THIS fetch altered the key set, computed atomically inside the
	// singleflight closure so the shared-budget decision never races a concurrent rotation.
	keys, changed, err := c.refresh(ctx, true)
	if err != nil {
		return nil, err
	}
	if len(FindKeys(keys, kid)) == 0 {
		// Still absent after a real fetch. Record it per-kid, and — when the set was
		// UNCHANGED — also charge the shared budget so the next distinct unknown kid is
		// suppressed. A CHANGED set leaves the budget open so rotations keep landing.
		c.markKIDAbsent(kid)
		if !changed {
			c.markKIDAbsent(sharedRefreshSentinel)
		}
	}
	return keys, nil
}

// sharedRefreshSentinel is the negKIDs key for a SHARED forced-refresh budget across both
// kid-rotation paths. It is marked whenever a forced fetch returns an unchanged set ("the
// endpoint has exactly our keys, so another fetch cannot resolve any absent kid"), and while
// marked both paths serve the cached set — bounding a flood of DISTINCT unknown kids, which
// the per-kid cache (same-kid only) cannot. A real JWT kid is never empty, so no collision.
const sharedRefreshSentinel = ""

// ForceRefreshForVerify forces a single JWKS refresh for the kid-LESS rotation case: a token
// with no kid matches every cached key, so ForceRefreshForKID never runs for it, and after a
// rotation it would be rejected until the TTL elapsed. This pulls the rotated key in
// immediately, rate-limited to at most one forced fetch per negativeKIDTTL (sharing the
// sharedRefreshSentinel budget with ForceRefreshForKID). The caller fails closed when
// suppressed.
func (c *JWKSCache) ForceRefreshForVerify(ctx context.Context) (*jose.JSONWebKeySet, error) {
	keys, err := c.forceRefreshForVerifyLive(ctx)
	if err != nil {
		return nil, err
	}
	return copyKeySet(keys), nil
}

// forceRefreshForVerifyLive is ForceRefreshForVerify's uncopied core, for the same reason as
// forceRefreshForKIDLive: the caller immediately narrows the result through FindKeys, so
// copying here first is wasted work on a pre-auth path a flood of bad-signature kid-less
// tokens can drive.
func (c *JWKSCache) forceRefreshForVerifyLive(ctx context.Context) (*jose.JSONWebKeySet, error) {
	if c.kidRecentlyAbsent(sharedRefreshSentinel) {
		c.mu.RLock()
		cached := c.jwks
		c.mu.RUnlock()
		if cached != nil {
			return cached, nil
		}
	}
	// refresh reports whether this fetch changed the set atomically inside the singleflight
	// closure, so we do not snapshot the cache here (a pre-fetch snapshot could observe
	// another goroutine's rotation).
	keys, changed, err := c.refresh(ctx, true)
	if err != nil {
		return nil, err
	}
	// Charge the sentinel ONLY when the set was unchanged: an immediate retry would be
	// pointless, and this rate-limits a flood of bad-signature kid-less tokens while leaving
	// the fast path open when the set CHANGED, so a second rotation isn't blocked.
	if !changed {
		c.markKIDAbsent(sharedRefreshSentinel)
	}
	return keys, nil
}

// jwksKeysUnchanged reports whether two key sets hold the same keys by RFC 7638
// thumbprint, independent of order. A nil set differs from any non-nil set (so the first
// fetch into a cold cache counts as a change). On any thumbprint error it returns false
// (treat as changed) — the fail-safe direction: the cost is an extra refresh, never a
// wrongly suppressed one.
func jwksKeysUnchanged(before, after *jose.JSONWebKeySet) bool {
	if before == nil || after == nil {
		return before == nil && after == nil
	}
	return sameKeyMultiset(before.Keys, after.Keys)
}

// sameKeyMultiset reports whether two key slices hold the same keys by RFC 7638
// thumbprint, order-independent. Shared by jwksKeysUnchanged and VerifyWithKeyRotation's
// retry-skip guard so the security-relevant comparison lives once. On any thumbprint error
// it returns false (treat as different) — the fail-safe direction for both callers.
func sameKeyMultiset(before, after []jose.JSONWebKey) bool {
	if len(before) != len(after) {
		return false
	}
	counts := make(map[string]int, len(before))
	for i := range before {
		tp, err := before[i].Thumbprint(crypto.SHA256)
		if err != nil {
			return false
		}
		counts[string(tp)]++
	}
	for i := range after {
		tp, err := after[i].Thumbprint(crypto.SHA256)
		if err != nil {
			return false
		}
		counts[string(tp)]--
		if counts[string(tp)] < 0 {
			return false
		}
	}
	return true
}

// kidRecentlyAbsent reports whether kid was marked absent within negativeKIDTTL, pruning an
// expired entry on read. The hot path (present and unexpired) is a pure read under the read
// lock, so concurrent validations consult the sentinel in parallel rather than serializing —
// serializing would itself be a DoS-amplification vector under the kid-flood the sentinel
// absorbs. The write lock is taken only on the expiry branch, re-checking after acquiring it
// (RWMutex has no atomic upgrade) so a concurrent refresh is not clobbered.
func (c *JWKSCache) kidRecentlyAbsent(kid string) bool {
	k := negKIDKey(kid)
	c.negMu.RLock()
	at, ok := c.negKIDs[k]
	if !ok {
		c.negMu.RUnlock()
		return false
	}
	if c.now().Sub(at) < negativeKIDTTL {
		c.negMu.RUnlock()
		return true
	}
	c.negMu.RUnlock()

	// Expired under the read lock: take the write lock and re-check, since a concurrent
	// markKIDAbsent may have re-inserted the kid with a fresh timestamp between RUnlock
	// and Lock.
	c.negMu.Lock()
	defer c.negMu.Unlock()
	at2, ok2 := c.negKIDs[k]
	if !ok2 {
		return false
	}
	if c.now().Sub(at2) < negativeKIDTTL {
		return true
	}
	delete(c.negKIDs, k)
	return false
}

// markKIDAbsent records that a forced refetch did not resolve kid. It first sweeps expired
// entries so a long-running process does not accumulate kids, and honours negativeKIDMaxLen
// so a flood of distinct kids cannot grow the map without bound. The shared refresh
// sentinel is exempt from the cap (see the cap check below).
func (c *JWKSCache) markKIDAbsent(kid string) {
	// Derive before locking, as kidRecentlyAbsent does: the kid is attacker-sized, and the
	// RWMutex is documented as deliberately not serializing flood callers — a digest over a
	// megabyte of JWS header held under the exclusive lock is that serialization.
	k := negKIDKey(kid)
	c.negMu.Lock()
	defer c.negMu.Unlock()
	now := c.now()
	for k, at := range c.negKIDs {
		if now.Sub(at) >= negativeKIDTTL {
			delete(c.negKIDs, k)
		}
	}
	// Anchor the suppress window to the FIRST absent observation: overwriting on every
	// presentation would slide the window forward indefinitely, letting a client that keeps
	// presenting a stale kid pin it even after a JWKS update adds it back.
	if _, ok := c.negKIDs[k]; ok {
		return
	}
	// The shared sentinel must always be insertable: dropping it because a flood of distinct
	// kids filled the map would disable the forced-refresh rate-limit it provides. Costs at
	// most one extra slot; real kids still honour the cap.
	if kid != sharedRefreshSentinel && len(c.negKIDs) >= negativeKIDMaxLen {
		return
	}
	c.negKIDs[k] = now
}

// negKIDKey derives the negative cache's map key from a kid. A kid is attacker-chosen text
// read out of an UNAUTHENTICATED token's JWS header, so keying by it verbatim let
// negativeKIDMaxLen bound how MANY entries are retained for the TTL while nothing bounded how
// big one is. Hashing keeps every kid cached at a fixed key width, so no length slips back onto
// the forced-refresh path.
//
// What bounds the digest's own COST is MaxKIDBytes, applied before a kid reaches this cache at
// all: the hash is over a value the caller chooses, on the pre-auth path, twice per rejected
// token. Keying short kids verbatim and hashing only long ones is NOT the alternative — a
// 64-char lowercase-hex kid would then collide with a digest and reintroduce an
// attacker-poisonable slot.
//
// The sentinel's key is precomputed: it is consulted once or twice per rejected token on the
// pre-auth path this cache exists to absorb, and it is a digest of a constant.
func negKIDKey(kid string) string {
	if kid == sharedRefreshSentinel {
		return negKIDSentinelKey
	}
	return HashTokenKey(kid)
}

// negKIDSentinelKey is negKIDKey(sharedRefreshSentinel).
var negKIDSentinelKey = HashTokenKey(sharedRefreshSentinel)

// refresh fetches a fresh JWKS and stores it. When force is false it first double-checks the
// TTL under the read lock; when true it always fetches. The store and log line run inside
// the singleflight closure, so they happen once per round-trip even when N callers are
// unblocked together.
func (c *JWKSCache) refresh(ctx context.Context, force bool) (*jose.JSONWebKeySet, bool, error) {
	if !force {
		c.mu.RLock()
		if c.freshAt(c.now()) {
			keys := c.jwks
			c.mu.RUnlock()
			return keys, false, nil
		}
		c.mu.RUnlock()
	}

	// Key the singleflight group by force so a forced caller never coalesces with a
	// non-forced leader and inherits its TTL fast-path — which would hand it stale keys
	// during a rotation. Separate keys give forced callers an always-fetching slot while
	// still collapsing concurrent same-kind refreshes into one round-trip.
	sfKey := "background"
	if force {
		sfKey = "forced"
	}
	v, err, _ := c.sfGroup.Do(sfKey, func() (interface{}, error) {
		// Double-checked staleness: the TTL check above runs OUTSIDE the singleflight, so a
		// non-forced refresh whose cache became fresh while it waited would otherwise issue
		// a redundant fetch. Forced refreshes always fetch.
		if !force {
			c.mu.RLock()
			if c.freshAt(c.now()) {
				keys := c.jwks
				c.mu.RUnlock()
				return refreshResult{keys: keys, changed: false}, nil
			}
			c.mu.RUnlock()
		}
		// Decouple the shared fetch from the first caller's context: every waiter shares
		// this fetch, so binding it to one caller's context would let that caller's
		// deadline fail every waiter and charge a spurious breaker failure. WithoutCancel
		// keeps context values while stripping cancellation/deadline.
		fetchCtx := context.WithoutCancel(ctx)
		// A custom client may have Timeout <= 0, so impose an internal ceiling; otherwise a
		// hung transport would block this call — and every verification joining it — forever.
		if c.client.Timeout <= 0 {
			var cancel context.CancelFunc
			fetchCtx, cancel = context.WithTimeout(fetchCtx, c.maxFetch)
			defer cancel()
		}
		fetch := func(fc context.Context) (*jose.JSONWebKeySet, error) {
			return c.fetchKeys(fc)
		}

		// Take a fetch generation as this fetch begins; the install below commits only if
		// it is still the newest, so a slower earlier-started fetch cannot clobber a
		// newer one's result.
		c.mu.Lock()
		c.fetchTicket++
		myGen := c.fetchTicket
		c.mu.Unlock()

		var (
			jwks *jose.JSONWebKeySet
			ferr error
		)
		if c.breaker != nil {
			jwks, ferr = circuitbreaker.Do(fetchCtx, c.breaker, fetch)
			if ferr != nil {
				if errors.Is(ferr, circuitbreaker.ErrOpen) {
					// Breaker-open is a JWKS-availability failure too (the endpoint is being
					// shielded because recent fetches failed) — tag it like a fetchKeys error
					// so the audit layer classifies it as an outage, not a forged token.
					return nil, fmt.Errorf("%w: JWKS fetch blocked by circuit breaker: %w", ErrJWKSUnavailable, ferr)
				}
				return nil, ferr
			}
		} else {
			jwks, ferr = fetch(fetchCtx)
			if ferr != nil {
				return nil, ferr
			}
		}

		// Snapshot the replaced set and compute "changed" here, under the same lock that
		// installs the new set, so every joiner shares a determination reflecting THIS
		// fetch's old->new transition rather than a caller's stale pre-call snapshot.
		c.mu.Lock()
		before := c.jwks
		installed := false
		// resultKeys is what this closure reports to joiners: normally this fetch's keys,
		// but the installed set when the install is skipped (a newer-generation refresh
		// already committed) — reporting our discarded fetch would hand callers a set
		// GetKeys never serves and let a forced caller re-charge the sentinel against it.
		resultKeys := jwks
		if myGen > c.installedFetchGen {
			// At least as fresh as the installed set: commit it. An older-started fetch with
			// a now-stale generation is dropped so completion order cannot undo start order.
			c.jwks = jwks
			c.fetchedAt = c.now()
			c.installedFetchGen = myGen
			installed = true
		} else if c.jwks != nil {
			resultKeys = c.jwks
		}
		c.mu.Unlock()
		if installed {
			c.logger.Info("refreshed JWKS", slog.Int("keys", len(jwks.Keys)))
		} else {
			c.logger.Info("discarded stale JWKS fetch superseded by a newer refresh", slog.Int("keys", len(jwks.Keys)))
		}
		// On the install path this compares old-vs-new as intended; on the superseded path
		// resultKeys IS `before`, so changed is correctly false (this closure committed
		// nothing).
		return refreshResult{keys: resultKeys, changed: !jwksKeysUnchanged(before, resultKeys)}, nil
	})
	if err != nil {
		return nil, false, err
	}
	res := v.(refreshResult)
	return res.keys, res.changed, nil
}

// refreshResult is the singleflight closure's return value: the fetched key set and whether
// that fetch changed it relative to the set it replaced. Bundling both lets every joiner
// observe the same, atomically-computed change determination.
type refreshResult struct {
	keys    *jose.JSONWebKeySet
	changed bool
}

// refuseCrossOriginResponse fails closed unless resp was served by the host the cache was
// configured to fetch from. net/http sets resp.Request to the LAST request in a redirect
// chain, so this sees the final hop regardless of how many redirects were followed — the
// one same-origin check that does not depend on the caller's CheckRedirect being intact.
//
// Mirrors the CLI's redirect policy: hostname must match, port and path may change (an IdP
// may relocate the key set within its own host), and a hop between loopback spellings
// (localhost <-> 127.0.0.1) is allowed since it never leaves the machine.
func (c *JWKSCache) refuseCrossOriginResponse(resp *http.Response) error {
	if resp.Request == nil || resp.Request.URL == nil {
		// Fail closed rather than exempt: resp.Request is documented as "only populated for
		// Client requests" (net/http), so a caller-supplied *http.Client whose RoundTripper
		// builds its own *http.Response can leave it nil — admitting the response here would
		// make exactly that RoundTripper the one way to bypass this floor.
		return fmt.Errorf("JWKS response carries no final-request URL to verify against the configured JWKS host %q; refusing (the HTTP client's RoundTripper did not populate resp.Request)", c.jwksURI)
	}
	want, err := url.Parse(c.jwksURI)
	if err != nil {
		return fmt.Errorf("JWKS URI is not parseable: %w", err)
	}
	gotHost, wantHost := resp.Request.URL.Hostname(), want.Hostname()
	sameHost := strings.EqualFold(gotHost, wantHost) || (IsLoopbackHost(gotHost) && IsLoopbackHost(wantHost))
	if !sameHost {
		return fmt.Errorf("JWKS response came from host %q, not the configured JWKS host %q; the key set is the root of trust for token verification and a redirect must not move it to another host", gotHost, wantHost)
	}
	// A same-host hop can still downgrade scheme (an https-configured IdP redirecting to
	// http on the same name): the hostname check alone would pass it. The floor is
	// documented as "a supplied client cannot weaken," so a plaintext-http response is
	// refused whenever the configured URL demanded TLS, not just warned about at the
	// configured URL (loopback is exempt: it never leaves the machine either way).
	if want.Scheme == "https" && resp.Request.URL.Scheme != "https" && (!IsLoopbackHost(gotHost) || !IsLoopbackHost(wantHost)) {
		return fmt.Errorf("JWKS response for host %q was served over %q, not https; the configured JWKS URL demands TLS and a redirect must not downgrade it", gotHost, resp.Request.URL.Scheme)
	}
	return nil
}

func (c *JWKSCache) fetchKeys(ctx context.Context) (_ *jose.JSONWebKeySet, err error) {
	// Every non-nil return below is a failure to obtain a usable key set; tag them all with
	// ErrJWKSUnavailable in one place so the audit layer can tell a JWKS-infra outage apart
	// from a forged token. %w keeps errors.Is transparent while leaving the message intact.
	defer func() {
		if err != nil {
			err = fmt.Errorf("%w: %w", ErrJWKSUnavailable, err)
		}
	}()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.jwksURI, http.NoBody)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("JWKS request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Enforce the same-origin floor HERE, on the response, rather than relying on the
	// client's CheckRedirect: the redirect refusal in NewJWKSCache applies only to the
	// DEFAULT client, so a consumer supplying its own gets Go's default redirect-following
	// back, and an IdP open redirect could then substitute the key set and forge every
	// token the proxy accepts.
	if err := c.refuseCrossOriginResponse(resp); err != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		// Drain the body before returning so net/http can reuse the keep-alive connection
		// instead of tearing down the handshake on the next probe. Bound to the same 1 MiB
		// ceiling as the success path so a hostile endpoint cannot stream unbounded bytes.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("JWKS endpoint returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read JWKS body: %w", err)
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("parse JWKS: %w", err)
	}
	// A 200 carrying an empty key set (a rotation window or degraded endpoint) would
	// otherwise cache as success for the full TTL, rejecting every JWT with no breaker
	// signal. Treat it as a fetch failure so the breaker records it and the previously
	// cached set keeps serving.
	if len(jwks.Keys) == 0 {
		return nil, fmt.Errorf("JWKS endpoint returned an empty key set")
	}
	// Bound the key count so a kid-less token cannot be made to trial an unbounded number
	// of keys (see maxJWKSKeys). Fail closed on an oversized set.
	if len(jwks.Keys) > maxJWKSKeys {
		return nil, fmt.Errorf("JWKS endpoint returned %d keys, exceeding the limit of %d", len(jwks.Keys), maxJWKSKeys)
	}
	return &jwks, nil
}

// FindKeys returns the keys matching kid from the JWKS, all keys when kid is empty. A nil
// JWKS yields no keys rather than panicking.
//
// The returned SLICE is always fresh — never an alias into the cached set's backing array —
// so a caller cannot reorder or overwrite entries in the shared root-of-trust set. Its
// elements are SHALLOW copies, so the key material each reaches through its Key field is
// still shared: callers must treat it as read-only, since mutating THROUGH it would corrupt
// the cached set for every other verification.
func FindKeys(jwks *jose.JSONWebKeySet, kid string) []jose.JSONWebKey {
	if jwks == nil {
		return nil
	}
	if kid != "" {
		return jwks.Key(kid)
	}
	return append([]jose.JSONWebKey(nil), jwks.Keys...)
}
