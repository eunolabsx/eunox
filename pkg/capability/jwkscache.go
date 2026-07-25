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

// ErrJWKSUnavailable tags every failure to obtain a usable key set from the JWKS
// endpoint — a network error, a non-200 response, an empty or oversized set, an
// unparseable body, or an open circuit breaker. It marks the failure as an
// availability problem with the key infrastructure rather than a problem with the
// token: when a fetch fails, the presented token was never even checked against a
// key, so it must NOT be recorded in the fail-closed audit trail as if it were
// forged. Callers surface it through the "fetch JWKS"/"refresh JWKS" %w wraps in
// VerifyWithKeyRotation, so errors.Is finds it end-to-end; the audit layer keys on
// it to classify the record as a JWKS outage (see ClassifyJWTError).
var ErrJWKSUnavailable = errors.New("JWKS unavailable")

// JWKSCache fetches and caches a remote JSON Web Key Set. It is the shared cache
// consumed by the gateway's IdP-JWT validator, which keeps only its own
// claim-validation logic and delegates all fetch/cache/singleflight/breaker/TTL
// behaviour here.
//
// Concurrency: a singleflight group collapses concurrent refreshes into one HTTP
// round-trip whose result waiters share. The fetch is decoupled from any caller's
// context (context.WithoutCancel) so one caller's deadline neither aborts the
// shared fetch nor charges a spurious breaker failure for every waiter; the HTTP
// client's own timeout still bounds it.
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
	// fetchTicket issues a monotonically increasing generation to each fetch when
	// it begins; installedFetchGen records the ticket of the installed set. Forced
	// and non-forced refreshes run concurrently with no completion ordering, so the
	// generation guard commits an install only when its ticket is newer than the
	// installed one — otherwise an earlier-started, later-finishing fetch could
	// overwrite a newer forced rotation and reintroduce a removed key for the TTL.
	// Both guarded by mu.
	fetchTicket       uint64
	installedFetchGen uint64

	// maxFetch is the ceiling applied to the shared fetch when the HTTP client has
	// no finite timeout of its own (see maxJWKSFetch). Overridable in tests.
	maxFetch time.Duration

	// sfGroup deduplicates concurrent refreshes into one in-flight round-trip;
	// callers block on the group (not c.mu) and share the result.
	sfGroup singleflight.Group

	// negMu guards negKIDs, the negative cache of key IDs a forced refresh failed to
	// resolve (see ForceRefreshForKID), so a flood of distinct unknown-kid tokens
	// cannot amplify into one round-trip each. Separate from mu so a kid-miss lookup
	// never contends with a fetch's write lock; an RWMutex so the kidRecentlyAbsent
	// hot path (a pure read) runs concurrently across flood callers.
	negMu   sync.RWMutex
	negKIDs map[string]time.Time
}

const (
	// negativeKIDTTL bounds how long a kid a forced refetch failed to resolve is
	// remembered as absent; while remembered, a token carrying it fails closed
	// without another forced fetch. Short so a genuinely rotated-in kid is retried
	// promptly.
	negativeKIDTTL = 30 * time.Second
	// negativeKIDMaxLen caps the negative cache so a flood of distinct unknown kids
	// cannot grow the map without bound. At the cap a new kid is not recorded and
	// falls back to the breaker-bounded forced-refresh path, degrading safely.
	negativeKIDMaxLen = 1024
	// maxJWKSKeys bounds how many keys a JWKS response may carry. A kid-less token
	// trials every key (FindKeys returns the whole set), so an oversized set lets a
	// compromised endpoint force O(keys) asymmetric verifications per such token. A
	// response over the cap is rejected wholesale (fail closed); the breaker records
	// it and any cached good set keeps serving. Far above any legitimate rotation
	// overlap. Mirrors maxResolverKeys on the co-issuer proof path.
	maxJWKSKeys = 100
	// maxJWKSFetch is the ceiling on the shared fetch when the HTTP client has no
	// finite timeout of its own. The fetch is decoupled from the caller's context
	// (context.WithoutCancel) assuming the client's Timeout bounds it, but a custom
	// zero-value client has Timeout == 0; without this ceiling a stalled transport
	// would hang every later verification joining the singleflight call. Generous so
	// a slow-but-live issuer still succeeds.
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
	// Breaker optionally protects refreshes from a flapping upstream. When nil
	// the cache fetches directly; callers that want breaker protection on every
	// fetch (e.g. the shipped proxy) must supply one.
	Breaker *circuitbreaker.Breaker
	// Now is an optional clock used for the cache-TTL comparison (testing).
	// Default: time.Now.
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
			// Refuse to follow redirects: the JWKS endpoint is the root of trust, so
			// a 30x to another host (an SSRF pivot or attacker-chosen key source) must
			// never be followed silently. A legitimate endpoint answers 200 directly;
			// ErrUseLastResponse surfaces the redirect as a non-200 that fetchKeys
			// fails closed on. This is the in-library defense for direct cache callers
			// (the CLI also validates scheme/host up front).
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
	// The JWKS endpoint is the root of trust for token verification, so a plaintext
	// http:// URL to a non-loopback host is silently MITM-able. The CLI validates the
	// scheme up front (with an explicit --jwks-allow-insecure-http opt-out), but a direct
	// library consumer gets no such check — warn loudly here (the in-library floor,
	// mirroring the redirect refusal above), without failing construction so the CLI's
	// explicit opt-out is not double-reported.
	if u, err := url.Parse(cfg.JWKSURL); err == nil && u.Scheme == "http" && !IsLoopbackHost(u.Hostname()) {
		// Redact: some IdPs gate the JWKS endpoint behind a query key or basic-auth
		// userinfo, and this attribute lands in whatever handler the consumer wired —
		// commonly a JSON log shipped to a central store.
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

// IsLoopbackHost reports whether host (a URL hostname, no port) is a loopback
// name or address — the one case where a plaintext http JWKS URL carries no MITM
// exposure (the traffic never leaves the machine). Exported as the single source
// of truth for this check: cmd/eunox's startup --jwks-uri scheme gate consults it
// too, so the CLI's validation and this package's own warning cannot re-diverge
// the way two independent copies previously did.
func IsLoopbackHost(host string) bool {
	// DNS host names are case-insensitive (RFC 4343) and url.Parse does not
	// normalize case, so "LOCALHOST"/"Localhost" reach here verbatim. Trim a
	// trailing FQDN dot too ("localhost.").
	if strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// cachedFresh reports whether a key set is installed and still inside its TTL — the
// single staleness predicate for the cache. GetKeys, refresh's pre-singleflight check,
// and refresh's in-closure double-check all ask exactly this question at different lock
// depths, so a change to what "fresh" means (a jitter, a soft-TTL grace) must land in
// one place rather than three that can silently disagree about when a key set expires.
//
// The caller MUST hold c.mu (read or write): it reads jwks and fetchedAt, both guarded.
func (c *JWKSCache) cachedFresh() bool {
	return c.jwks != nil && c.now().Sub(c.fetchedAt) < c.cacheTTL
}

// GetKeys returns the cached JWKS when it is still within the TTL, otherwise it
// fetches a fresh copy.
//
// The returned *jose.JSONWebKeySet is the cache's own shared instance, handed
// concurrently to every verification in flight — it is READ-ONLY. Never mutate it or
// its Keys slice; to obtain keys you can hold or reorder, copy them through FindKeys
// (which always returns a fresh slice) as the production consumer (VerifyWithKeyRotation)
// does. Mutating the returned set would corrupt the root-of-trust key material seen by
// all concurrent token validations. Refresh and the ForceRefresh* methods carry the
// same contract.
func (c *JWKSCache) GetKeys(ctx context.Context) (*jose.JSONWebKeySet, error) {
	c.mu.RLock()
	if c.cachedFresh() {
		keys := c.jwks
		c.mu.RUnlock()
		return copyKeySet(keys), nil
	}
	c.mu.RUnlock()
	return c.Refresh(ctx)
}

// copyKeySet returns a set whose Keys SLICE is independent of the cached one, so a
// caller appending to, reordering, or truncating the returned set cannot mutate the
// shared cache other verifications are concurrently reading. Handing out the live
// pointer made the cache's aliasing defense -- which FindKeys documents and applies --
// bypassable by anyone who called GetKeys/Refresh directly.
//
// The copy is one level deep. Each jose.JSONWebKey still carries a Key interface{}
// pointing at the same underlying *rsa.PublicKey / *ecdsa.PublicKey, so mutating a KEY'S
// INTERNALS still reaches the cache; that is inherent to the type and is the same bound
// FindKeys has. The realistic accident -- slice mutation -- is what this closes.
func copyKeySet(set *jose.JSONWebKeySet) *jose.JSONWebKeySet {
	if set == nil {
		return nil
	}
	return &jose.JSONWebKeySet{Keys: append([]jose.JSONWebKey(nil), set.Keys...)}
}

// Refresh returns a fresh JWKS, respecting the cache TTL: if the cached copy is
// still within TTL it is returned without an HTTP fetch.
//
// The returned set's Keys slice is independent of the cache's (see copyKeySet), so a
// caller may hold, append to, or reorder it without disturbing concurrent verifications.
// Handing out the live pointer made the aliasing defense FindKeys documents bypassable by
// anyone calling this directly. Individual jose.JSONWebKey values still share their
// underlying crypto key, so treat the KEYS themselves as read-only.
func (c *JWKSCache) Refresh(ctx context.Context) (*jose.JSONWebKeySet, error) {
	keys, _, err := c.refresh(ctx, false)
	return copyKeySet(keys), err
}

// ForceRefreshForKID performs a rate-limited forced fetch (refresh(ctx, true)), but
// suppresses it for a kid that cannot be resolved right now, returning the cached set
// instead, so a stream of distinct unknown-kid tokens cannot drive one round-trip per
// token. The caller still fails closed when suppressed (the kid is absent from the
// returned set).
//
// Two suppression signals gate the fetch, both bounded by negativeKIDTTL:
//   - per-kid: a kid a recent forced refetch failed to resolve is not refetched;
//   - shared budget (sharedRefreshSentinel): once a forced fetch returns an
//     unchanged set it is charged, and while charged DISTINCT unknown kids are
//     suppressed too — the bound the per-kid cache alone cannot give, since an
//     unchanged 200 never trips the breaker.
//
// Tradeoff: while the budget is charged, a kid the issuer rotates IN is not
// observed for up to negativeKIDTTL (attacker-triggerable). It is bounded and
// self-healing and far below CacheTTL: when the budget expires the next lookup
// fetches, sees the CHANGED set, resolves the kid, and does not re-charge, so a run
// of rotations is not blocked.
//
// An empty kid is never suppressed, and a found kid never CHARGES either signal.
// When the cache holds no set at all the fetch is not suppressed, so a cold start
// never denies purely for lack of a cached copy.
//
// The returned set is the cache's shared, READ-ONLY instance (see GetKeys): a
// suppressed call hands back the live cached pointer directly, so copy through
// FindKeys before holding or mutating it.
func (c *JWKSCache) ForceRefreshForKID(ctx context.Context, kid string) (*jose.JSONWebKeySet, error) {
	if kid == "" {
		// A kid-less lookup is not an unknown-kid lookup. The suppression block below
		// is gated on kid != "", so routing it here would skip the rate-limit and let
		// a flood of kid-less tokens hammer the endpoint. Delegate to the rate-limited
		// kid-less path.
		return c.ForceRefreshForVerify(ctx)
	}
	if c.kidRecentlyAbsent(kid) || c.kidRecentlyAbsent(sharedRefreshSentinel) {
		c.mu.RLock()
		cached := c.jwks
		c.mu.RUnlock()
		if cached != nil {
			return cached, nil
		}
	}
	// changed reports whether THIS fetch altered the key set, computed atomically
	// inside the singleflight closure so the shared-budget decision never races a
	// concurrent rotation.
	keys, changed, err := c.refresh(ctx, true)
	if err != nil {
		return nil, err
	}
	if len(FindKeys(keys, kid)) == 0 {
		// Still absent after a real fetch. Record it per-kid, and — when the set was
		// UNCHANGED — also charge the shared budget so the next distinct unknown kid
		// is suppressed. A CHANGED set leaves the budget open so distinct unknown kids
		// keep fetching while rotations are actively landing.
		c.markKIDAbsent(kid)
		if !changed {
			c.markKIDAbsent(sharedRefreshSentinel)
		}
	}
	return keys, nil
}

// sharedRefreshSentinel is the negKIDs key for a SHARED forced-refresh budget
// across both kid-rotation paths (ForceRefreshForVerify and ForceRefreshForKID).
// It is marked whenever a forced fetch returns an unchanged set ("the endpoint has
// exactly our keys, so another fetch cannot resolve any absent kid"), and while
// marked both paths serve the cached set. This is what bounds a flood of DISTINCT
// unknown kids, which the per-kid cache (same-kid only) cannot. A real JWT kid is
// never empty, so this cannot collide with a genuine kid.
const sharedRefreshSentinel = ""

// ForceRefreshForVerify forces a single JWKS refresh for the kid-LESS rotation
// case: a token with no kid matches every cached key, so ForceRefreshForKID never
// runs for it, and after a key rotation it would be rejected until the TTL
// elapsed. This pulls the rotated key in immediately.
//
// Like ForceRefreshForKID it is rate-limited to at most one forced fetch per
// negativeKIDTTL, tracked under sharedRefreshSentinel (which ForceRefreshForKID
// charges too, so the two paths share one budget). The caller fails closed when
// suppressed.
//
// The returned set is the cache's shared, READ-ONLY instance (see GetKeys): a
// suppressed call hands back the live cached pointer directly, so copy through
// FindKeys before holding or mutating it.
func (c *JWKSCache) ForceRefreshForVerify(ctx context.Context) (*jose.JSONWebKeySet, error) {
	if c.kidRecentlyAbsent(sharedRefreshSentinel) {
		c.mu.RLock()
		cached := c.jwks
		c.mu.RUnlock()
		if cached != nil {
			return cached, nil
		}
	}
	// refresh reports whether this fetch changed the set atomically inside the
	// singleflight closure, so we do not snapshot the cache here (a pre-fetch
	// snapshot could observe another goroutine's rotation).
	keys, changed, err := c.refresh(ctx, true)
	if err != nil {
		return nil, err
	}
	// Charge the sentinel ONLY when the set was unchanged: an immediate retry would
	// be pointless and this rate-limits a flood of bad-signature kid-less tokens.
	// When the set CHANGED, leave the fast path open so a second rotation within the
	// window is not blocked. Identity is by RFC 7638 thumbprint (order-independent),
	// so a same-length hard rotation is correctly seen as a change.
	if !changed {
		c.markKIDAbsent(sharedRefreshSentinel)
	}
	return keys, nil
}

// jwksKeysUnchanged reports whether two key sets hold the same keys by RFC 7638
// thumbprint, independent of order. A nil set differs from any non-nil set (so the
// first fetch into a cold cache counts as a change and is not suppressed). On any
// thumbprint error it returns false (treat as changed): the only cost is an extra
// forced refresh, never a wrongly suppressed one — the fail-safe direction for a
// rotation-detection guard.
func jwksKeysUnchanged(before, after *jose.JSONWebKeySet) bool {
	if before == nil || after == nil {
		return before == nil && after == nil
	}
	return sameKeyMultiset(before.Keys, after.Keys)
}

// sameMatchingKeys reports whether two candidate-key slices hold the same keys by
// RFC 7638 thumbprint, independent of order. It backs the post-signature-failure
// retry skip in VerifyWithKeyRotation: when a forced refresh returns the identical
// keys the caller already tried, re-verifying them against the same token can never
// succeed, so the retry (a full per-key signature pass) is pointless CPU. The
// comparison is against the keys the caller ACTUALLY tried rather than a bare "did
// our own fetch change the cache" flag, so a set a concurrent goroutine rotated in
// (different from ours) still differs here and is retried — a real rotation is never
// skipped. On any thumbprint error it returns false (treat as different), so the
// only failure cost is one extra retry, never a wrongly skipped one.
func sameMatchingKeys(before, after []jose.JSONWebKey) bool {
	return sameKeyMultiset(before, after)
}

// sameKeyMultiset reports whether two key slices hold the same keys by RFC 7638
// thumbprint, order-independent (a multiset compare). Shared by jwksKeysUnchanged
// (rotation-detection guard) and sameMatchingKeys (retry-skip guard) so the security-
// relevant thumbprint comparison lives once. On any thumbprint error it returns false
// (treat as different) — the fail-safe direction for both callers: the only cost is an
// extra forced refresh or an extra retry, never a wrongly suppressed one.
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

// kidRecentlyAbsent reports whether kid was marked absent within negativeKIDTTL,
// pruning an expired entry on read. The hot path (present and unexpired) is a pure
// read under the read lock, so concurrent validations consult the sentinel in
// parallel rather than serializing — that serialization was itself a DoS-
// amplification vector under the very kid-flood the sentinel absorbs. The write
// lock is taken only on the expiry branch, re-checking after acquiring it (RWMutex
// has no atomic upgrade) so a concurrent refresh is not clobbered.
func (c *JWKSCache) kidRecentlyAbsent(kid string) bool {
	c.negMu.RLock()
	at, ok := c.negKIDs[kid]
	if !ok {
		c.negMu.RUnlock()
		return false
	}
	if c.now().Sub(at) < negativeKIDTTL {
		c.negMu.RUnlock()
		return true // hot path: pure read under the shared lock
	}
	c.negMu.RUnlock()

	// Expired under the read lock: take the write lock and re-check, since a
	// concurrent markKIDAbsent may have re-inserted the kid with a fresh timestamp
	// between RUnlock and Lock. If so it IS recently absent and we report true;
	// otherwise prune and report not-absent.
	c.negMu.Lock()
	defer c.negMu.Unlock()
	at2, ok2 := c.negKIDs[kid]
	if !ok2 {
		return false
	}
	if c.now().Sub(at2) < negativeKIDTTL {
		// Re-inserted fresh between the unlock and the write lock: still absent.
		return true
	}
	delete(c.negKIDs, kid)
	return false
}

// markKIDAbsent records that a forced refetch did not resolve kid. It first
// sweeps expired entries so a long-running process does not accumulate kids, and
// honours negativeKIDMaxLen so a flood of distinct kids cannot grow the map
// without bound. The shared refresh sentinel is exempt from the cap so it can
// always be recorded (see the cap check below).
func (c *JWKSCache) markKIDAbsent(kid string) {
	c.negMu.Lock()
	defer c.negMu.Unlock()
	now := c.now()
	for k, at := range c.negKIDs {
		if now.Sub(at) >= negativeKIDTTL {
			delete(c.negKIDs, k)
		}
	}
	// Anchor the suppress window to the FIRST absent observation: overwriting on
	// every presentation would slide the window forward indefinitely, letting a
	// client that keeps presenting a stale kid pin it even after a JWKS update adds
	// it back. An already-tracked kid keeps its original timestamp; only a new kid
	// is inserted, and only with room under negativeKIDMaxLen.
	if _, ok := c.negKIDs[kid]; ok {
		return
	}
	// The shared sentinel must always be insertable: dropping it because a flood of
	// distinct kids filled the map would disable the forced-refresh rate-limit it
	// provides, letting an attacker drive unbounded JWKS fetches. It costs at most
	// one extra slot; real kids still honour the cap.
	if kid != sharedRefreshSentinel && len(c.negKIDs) >= negativeKIDMaxLen {
		return
	}
	c.negKIDs[kid] = now
}

// refresh fetches a fresh JWKS and stores it. When force is false it first
// double-checks the TTL under the read lock; when true it always fetches. The
// store and log line run inside the singleflight closure, so they happen once per
// round-trip even when N callers are unblocked together.
func (c *JWKSCache) refresh(ctx context.Context, force bool) (*jose.JSONWebKeySet, bool, error) {
	if !force {
		c.mu.RLock()
		if c.cachedFresh() {
			keys := c.jwks
			c.mu.RUnlock()
			// No fetch happened (still within TTL), so the key set did not change.
			return keys, false, nil
		}
		c.mu.RUnlock()
	}

	// Key the singleflight group by force so a forced caller never coalesces with a
	// non-forced leader and inherits its TTL fast-path — which would hand the forced
	// caller stale keys during a rotation and make ForceRefreshForKID mark the kid
	// absent for the window. Separate keys give forced callers an always-fetching
	// slot while still collapsing concurrent same-kind refreshes into one round-trip.
	sfKey := "background"
	if force {
		sfKey = "forced"
	}
	v, err, _ := c.sfGroup.Do(sfKey, func() (interface{}, error) {
		// Double-checked staleness: the TTL check above runs OUTSIDE the
		// singleflight, so a non-forced refresh whose cache became fresh while it
		// waited would otherwise issue a redundant fetch. Re-check under the lock and
		// return the fresh set with no round-trip. Forced refreshes always fetch.
		if !force {
			c.mu.RLock()
			if c.cachedFresh() {
				keys := c.jwks
				c.mu.RUnlock()
				return refreshResult{keys: keys, changed: false}, nil
			}
			c.mu.RUnlock()
		}
		// Decouple the shared fetch from the first caller's context: every waiter
		// shares this fetch, so binding it to one caller's context would let that
		// caller's deadline fail every waiter and charge a spurious breaker failure.
		// WithoutCancel keeps context values while stripping cancellation/deadline;
		// the HTTP client's timeout still bounds it.
		fetchCtx := context.WithoutCancel(ctx)
		// A custom client may have Timeout <= 0, so impose an internal ceiling in that
		// case; otherwise a hung transport would block this singleflight call — and
		// every verification joining it — forever.
		if c.client.Timeout <= 0 {
			var cancel context.CancelFunc
			fetchCtx, cancel = context.WithTimeout(fetchCtx, c.maxFetch)
			defer cancel()
		}
		fetch := func(fc context.Context) (*jose.JSONWebKeySet, error) {
			return c.fetchKeys(fc)
		}

		// Take a fetch generation as this fetch begins; the install below commits only
		// if it is still the newest, so a slower earlier-started fetch cannot clobber
		// a newer one's result.
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
					// Breaker-open is a JWKS-availability failure by a different mechanism than
					// a fetchKeys error (which the defer already tags): the endpoint is being
					// shielded because recent fetches failed. Tag it too so the audit layer
					// classifies it as an outage, not a forged token.
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

		// Snapshot the replaced set and compute "changed" here, under the same lock
		// that installs the new set and inside the closure owning the shared fetch, so
		// every joiner shares a determination reflecting THIS fetch's old->new
		// transition rather than a caller's stale pre-call snapshot.
		c.mu.Lock()
		before := c.jwks
		installed := false
		// resultKeys is what this closure reports to joiners: normally this fetch's
		// keys, but the installed set when the install is skipped (a newer-generation
		// refresh already committed). Reporting our discarded fetch would hand callers
		// a set GetKeys never serves and let a forced caller re-charge the sentinel
		// against it, cascading redundant fetches.
		resultKeys := jwks
		if myGen > c.installedFetchGen {
			// At least as fresh as the installed set: commit it. An older-started fetch
			// with a now-stale generation is dropped so completion order cannot undo
			// start order.
			c.jwks = jwks
			c.fetchedAt = c.now()
			c.installedFetchGen = myGen
			installed = true
		} else if c.jwks != nil {
			// Install skipped: report the currently-installed set so the keys returned
			// match what GetKeys serves and "changed" is computed against it.
			resultKeys = c.jwks
		}
		c.mu.Unlock()
		if installed {
			c.logger.Info("refreshed JWKS", slog.Int("keys", len(jwks.Keys)))
		} else {
			c.logger.Info("discarded stale JWKS fetch superseded by a newer refresh", slog.Int("keys", len(jwks.Keys)))
		}
		// "changed" compares resultKeys (what this closure reports) against `before`
		// (the set read at the top of this locked section). On the install path this
		// is old-vs-new as intended; on the superseded path resultKeys IS `before`, so
		// changed is false — correct, since this closure committed nothing.
		return refreshResult{keys: resultKeys, changed: !jwksKeysUnchanged(before, resultKeys)}, nil
	})
	if err != nil {
		return nil, false, err
	}
	res := v.(refreshResult)
	return res.keys, res.changed, nil
}

// refreshResult is the singleflight closure's return value: the fetched key set
// and whether that fetch changed it relative to the set it replaced. Bundling both
// lets every joiner of the shared fetch observe the same, atomically-computed
// change determination.
type refreshResult struct {
	keys    *jose.JSONWebKeySet
	changed bool
}

// refuseCrossOriginResponse fails closed unless resp was served by the host the cache was
// configured to fetch from. net/http sets resp.Request to the LAST request in a redirect
// chain, so this sees the final hop no matter how many redirects were followed or which
// client followed them — which is the point: it is the one same-origin check that does not
// depend on the caller's CheckRedirect being intact.
//
// The rule mirrors the CLI's redirect policy so the two layers cannot disagree: the
// hostname must match, port and path may change (an IdP may relocate the key set within its
// own host), and a hop between two loopback spellings (localhost <-> 127.0.0.1) is allowed
// because it never leaves the machine and so has no on-path attacker surface.
func (c *JWKSCache) refuseCrossOriginResponse(resp *http.Response) error {
	if resp.Request == nil || resp.Request.URL == nil {
		return nil // no final-URL information to compare (a stubbed transport in tests)
	}
	want, err := url.Parse(c.jwksURI)
	if err != nil {
		return fmt.Errorf("JWKS URI is not parseable: %w", err)
	}
	gotHost, wantHost := resp.Request.URL.Hostname(), want.Hostname()
	if strings.EqualFold(gotHost, wantHost) {
		return nil
	}
	if IsLoopbackHost(gotHost) && IsLoopbackHost(wantHost) {
		return nil
	}
	return fmt.Errorf("JWKS response came from host %q, not the configured JWKS host %q; the key set is the root of trust for token verification and a redirect must not move it to another host", gotHost, wantHost)
}

func (c *JWKSCache) fetchKeys(ctx context.Context) (_ *jose.JSONWebKeySet, err error) {
	// Every non-nil return below is a failure to obtain a usable key set; tag them all
	// with ErrJWKSUnavailable in one place so the audit layer can tell a JWKS-infra
	// outage apart from a forged token (the token was never checked against a key). The
	// %w keeps errors.Is transparent to the underlying cause and leaves the descriptive
	// message (checked by existing substring tests) intact.
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
	// client's CheckRedirect. The redirect refusal installed in NewJWKSCache applies only
	// to the DEFAULT client, so any consumer supplying its own *http.Client — a natural
	// thing to do for a proxy, a custom transport, or a different timeout — silently got
	// Go's default redirect-following back, and an IdP open redirect could then substitute
	// the key set and forge every token the proxy accepts. net/http rewrites
	// resp.Request.URL to the FINAL hop, so comparing it to the configured URI catches any
	// number of redirects regardless of which client was used, and needs no cooperation
	// from the caller.
	if err := c.refuseCrossOriginResponse(resp); err != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		// Drain the body before returning so net/http can reuse the keep-alive
		// connection instead of tearing down the TCP+TLS handshake on the next
		// probe. Bound the drain to the same 1 MiB ceiling as the success
		// path so a hostile endpoint cannot stream unbounded bytes here.
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
	// A 200 carrying an empty key set (a rotation window or degraded endpoint)
	// would otherwise cache as success for the full TTL, rejecting every JWT with no
	// breaker signal. Treat it as a fetch failure so the breaker records it and the
	// previously-cached set keeps serving.
	if len(jwks.Keys) == 0 {
		return nil, fmt.Errorf("JWKS endpoint returned an empty key set")
	}
	// Bound the key count so a kid-less token cannot be made to trial an
	// unbounded number of keys (see maxJWKSKeys). Fail closed on an oversized
	// set: the breaker records it and the previously-cached set keeps serving.
	if len(jwks.Keys) > maxJWKSKeys {
		return nil, fmt.Errorf("JWKS endpoint returned %d keys, exceeding the limit of %d", len(jwks.Keys), maxJWKSKeys)
	}
	return &jwks, nil
}

// FindKeys returns the keys matching kid from the JWKS, all keys when kid is empty.
// A nil JWKS yields no keys rather than panicking. The returned slice is always a
// fresh copy, never an alias into the cached set — handing out a live alias would
// let a caller that mutates an entry corrupt the shared root-of-trust set seen by
// every concurrent verification.
func FindKeys(jwks *jose.JSONWebKeySet, kid string) []jose.JSONWebKey {
	if jwks == nil {
		return nil
	}
	if kid != "" {
		return jwks.Key(kid)
	}
	return append([]jose.JSONWebKey(nil), jwks.Keys...)
}
