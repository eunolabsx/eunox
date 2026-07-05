// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// DefaultTokenLeeway is the clock-skew grace applied to standard JWT claim
// validation (exp/nbf/iat) when leeway is left at its zero value. Kept small so a
// stolen short-lived token's reuse window is not materially extended. Consumed by
// the IdP JWT path (JWTPDP, via DefaultJWTLeeway).
const DefaultTokenLeeway = 10 * time.Second

// EffectiveLeeway resolves a configured token-validation leeway: a zero value
// selects the conservative DefaultTokenLeeway, a negative value disables leeway
// (clamped to zero, requiring exp strictly in the future), and a positive value is
// used as-is.
func EffectiveLeeway(configured time.Duration) time.Duration {
	switch {
	case configured == 0:
		return DefaultTokenLeeway
	case configured < 0:
		return 0
	default:
		return configured
	}
}

// jwksAlgorithms is the asymmetric-only allowlist of signature algorithms accepted
// for every JWKS-verified token (currently IdP JWTs, JWTPDP.ValidateToken).
// Symmetric algorithms (HS*) are deliberately excluded so a public verification key
// can never be misused as an HMAC secret (algorithm-confusion). Unexported and only
// ever read through JWKSAlgorithms(), which returns a copy: an exported mutable
// slice let any code in the process
// append(capability.JWKSAlgorithms, jose.HS256) and silently re-enable symmetric
// algorithms for every verifier — the exact algorithm-confusion this allowlist exists
// to prevent.
var jwksAlgorithms = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.EdDSA,
}

// JWKSAlgorithms returns a fresh copy of the asymmetric-only signature-algorithm
// allowlist, so a caller cannot mutate the package's defense in place (see
// jwksAlgorithms). Pass it directly to jwt.ParseSigned at each verification site.
func JWKSAlgorithms() []jose.SignatureAlgorithm {
	return slices.Clone(jwksAlgorithms)
}

// terminalError marks a per-key verification failure as terminal: the signature
// verified but the claims/payload are invalid, so the failure is key-independent
// and MUST be surfaced as-is rather than retried against another key or a
// refreshed set. VerifyWithKeyRotation detects it with errors.As; a plain
// (unwrapped) error is a retryable signature failure. Encoding the distinction in
// the type stops a future verifier from silently swapping the two.
type terminalError struct{ err error }

func (e *terminalError) Error() string { return e.err.Error() }
func (e *terminalError) Unwrap() error { return e.err }

// Terminal marks err as a terminal (non-retryable) per-key verification failure for a
// VerifyWithKeyRotation verifier. See that function's verify contract.
func Terminal(err error) error { return &terminalError{err: err} }

// CandidateKIDs returns the distinct kid values to verify against for a token's
// JWS headers, in first-seen order. jwt.ParseSigned is compact-only, so a token
// carries one header today and this returns a single kid; consulting all headers
// avoids a headers[0] foot-gun should a multi-signature JWS ever reach this path.
//
// With requireKID, the "" (kid-less) entry — which FindKeys expands to "try every
// key" — is dropped and at least one explicit kid must remain. Without requireKID,
// "" is preserved so a kid-less token still falls back to trying all keys. An
// empty header list (or a requireKID token with no kid anywhere) is an error.
func CandidateKIDs(headers []jose.Header, requireKID bool) ([]string, error) {
	seen := make(map[string]bool, len(headers))
	kids := make([]string, 0, len(headers))
	for _, h := range headers {
		if seen[h.KeyID] {
			continue
		}
		seen[h.KeyID] = true
		if requireKID && h.KeyID == "" {
			continue
		}
		kids = append(kids, h.KeyID)
	}
	if len(kids) == 0 {
		if requireKID {
			return nil, fmt.Errorf("JWT missing required kid header")
		}
		return nil, fmt.Errorf("JWT has no headers")
	}
	return kids, nil
}

// VerifyWithKeyRotationMultiKID runs VerifyWithKeyRotation for each candidate kid
// in order, returning the first success, so the capability-token and IdP-JWT paths
// share multi-signature handling. kids must be non-empty (see CandidateKIDs); a ""
// entry means "try every key". The verify closure is shared across kids; its
// freshKeySet argument is true for the first verify call against a key set this call
// just fetched from the JWKS endpoint (a kid-miss refresh or a forced-refresh
// rotation retry), false for a set served from cache. A closure that pins a
// lazily-sampled validation clock therefore samples once on its first call (across
// all cached kids of a multi-signature token, keeping the clock consistent) and
// re-samples only after a forced refresh (closing the stale-clock-across-refresh
// hazard).
//
// A terminal failure (signature verified, claims invalid) is prioritized over a
// later structural failure (key-miss): a multi-signature JWS (the only token with
// more than one kid) has one shared payload, so the claims verdict is identical
// under every kid, and a key-miss on a different kid must not overwrite the real
// reason for rejection. Surfacing a "no matching key" error when the true cause is
// an expired claim would mislead callers into treating a permanent rejection as a
// transient infrastructure failure warranting a retry. The only reachable
// (single-kid) path loops once.
func VerifyWithKeyRotationMultiKID[T any](
	ctx context.Context,
	cache *JWKSCache,
	kids []string,
	verify func(key *jose.JSONWebKey, freshKeySet bool) (result *T, err error),
) (*T, error) {
	if len(kids) == 0 {
		// Caller contract violation; fail closed rather than verify against nothing.
		return nil, fmt.Errorf("no kid candidates to verify against (fail closed)")
	}
	var lastErr error
	for _, kid := range kids {
		result, err := VerifyWithKeyRotation(ctx, cache, kid, verify)
		if result != nil {
			return result, nil
		}
		if err != nil {
			// A terminal (claims) failure is payload-bound: every kid would reach the
			// same verdict, so return it immediately rather than letting a later
			// key-miss replace it.
			var te *terminalError
			if errors.As(err, &te) {
				return nil, err
			}
			lastErr = err
		}
	}
	return nil, lastErr
}

// VerifyWithKeyRotation runs the shared JWKS key-selection and rotation-retry
// choreography around a caller-supplied per-key verifier, so the IdP-JWT and
// capability-token paths cannot drift apart. The caller has already parsed the
// token and extracted kid; this selects the candidate keys, forces a JWKS refresh
// on a kid miss, and — when every candidate fails signature verification — forces
// one rate-limited refresh and retries exactly once.
//
// verify performs the per-key signature + claim validation for ONE candidate key.
// Its freshKeySet argument is true on the FIRST call against a key set this call just
// fetched from the JWKS endpoint (the kid-miss refresh or the forced-refresh retry)
// and false for the remaining keys of that set AND for a set served from cache, so a
// verifier that pins a lazily-sampled validation clock samples it on its own first
// call (after the fetch GetKeys may have done, never before) and re-samples once per
// genuine refresh — never reusing a clock sampled before a slow forced refresh:
//   - return (result, nil)        on full success;
//   - return (nil, Terminal(err)) when the signature verified but the payload/claims
//     are invalid — a key-independent failure surfaced as-is, never retried against
//     other keys or a refreshed set;
//   - return (nil, err)           when the key failed signature verification — try the
//     next candidate, and ultimately one refreshed set.
//
// A (nil, nil) return is a contract violation (a verifier must yield a result or an
// error) and fails closed with an explicit message rather than an empty one.
//
// When every candidate (across at most one forced refresh) fails signature
// verification, the last signature error is wrapped as "verify signature". A
// forced-refresh failure is surfaced as "refresh JWKS ..." rather than the
// cached-key signature error, so a transient JWKS outage during key rotation is
// distinguishable from a forged token.
func VerifyWithKeyRotation[T any](
	ctx context.Context,
	cache *JWKSCache,
	kid string,
	verify func(key *jose.JSONWebKey, freshKeySet bool) (result *T, err error),
) (*T, error) {
	keys, err := cache.GetKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}

	matchingKeys := FindKeys(keys, kid)
	// refreshedForKid records whether the kid-miss path below already forced a JWKS
	// refresh for this kid. It gates the post-signature-failure retry so a token
	// that already refreshed here does not refetch the just-fetched set.
	refreshedForKid := false
	if len(matchingKeys) == 0 {
		// Key not in cache — force a fresh fetch in case the issuer rotated keys (a
		// TTL-respecting refresh would return the stale cached set). ForceRefreshForKID
		// also rate-limits this so a flood of distinct unknown-kid tokens cannot
		// amplify into one upstream fetch each.
		keys, err = cache.ForceRefreshForKID(ctx, kid)
		if err != nil {
			return nil, fmt.Errorf("refresh JWKS: %w", err)
		}
		refreshedForKid = true
		matchingKeys = FindKeys(keys, kid)
		if len(matchingKeys) == 0 {
			return nil, fmt.Errorf("no matching key for kid %q", kid)
		}
	}

	// tryKeys runs verify against each candidate from ONE key set. freshKeySet is the
	// caller's promise that candidateKeys come from a key set just fetched from the
	// JWKS endpoint during THIS call (the kid-miss refresh or the post-signature-
	// failure retry) rather than served from cache; it is forwarded to the FIRST
	// verify call only, so a verifier that pins a lazily-sampled validation clock can
	// re-sample once per fresh fetch (after the fetch, never mid-set) and stay
	// consistent across the keys within the set and across cached sets.
	tryKeys := func(candidateKeys []jose.JSONWebKey, freshKeySet bool) (result *T, terminal, lastSig error) {
		for i := range candidateKeys {
			r, err := verify(&candidateKeys[i], freshKeySet && i == 0)
			if r != nil {
				return r, nil, nil
			}
			var te *terminalError
			switch {
			case errors.As(err, &te):
				// Signature verified but claims/payload invalid: surface keeping the
				// terminalError marker so a higher layer (VerifyWithKeyRotationMultiKID)
				// can distinguish a terminal claim failure from a structural key-miss.
				// The marker delegates Error()/Unwrap() to the inner error, so callers
				// using errors.Is/As against the inner error are unaffected. Never
				// retried against another key.
				return nil, te, nil
			case err != nil:
				lastSig = err
			default:
				// (nil, nil): a verifier must yield a result or an error. Fail closed with
				// an intelligible message rather than letting it fall through to the
				// "verify signature: <nil>" terminus below.
				return nil, fmt.Errorf("per-key verifier returned neither a result nor an error (fail closed)"), nil
			}
		}
		return nil, nil, lastSig
	}

	// freshKeySet is refreshedForKid, not an unconditional true: the initial set is
	// fresh only when the kid-miss path above forced a fetch for it. A set served from
	// cache passes false, and the verifier's own first-call guard samples the clock
	// then (after GetKeys returned, so still post-fetch on a cold cache) — so the
	// clock stays consistent across cached kids in a multi-signature token and is
	// re-sampled only after a genuine refresh.
	result, terminal, lastErr := tryKeys(matchingKeys, refreshedForKid)
	if terminal != nil {
		return nil, terminal
	}
	if result != nil {
		return result, nil
	}

	// Every matching key failed signature verification. The cached keys may be stale
	// from a rotation, so force one (rate-limited) refresh and retry before giving
	// up. Two cases reach here unrefreshed: a kid-LESS token that matched every
	// cached key (the kid-miss branch never ran), and a kid-BEARING token served
	// straight from the cache whose issuer rotated key material while REUSING the
	// same kid. ForceRefreshForVerify is rate-limited so a flood of bad-signature
	// tokens cannot amplify into one fetch each, while a real (CHANGED) rotation is
	// picked up immediately. A kid-bearing token that already refreshed above is NOT
	// retried — the just-fetched set is current, so its failure is terminal.
	if kid == "" || !refreshedForKid {
		refreshed, ferr := cache.ForceRefreshForVerify(ctx)
		if ferr != nil {
			// Surface the refresh error, not the cached-key signature failure, so a
			// transient JWKS outage during rotation is distinguishable from a forged
			// token in the fail-closed audit trail.
			return nil, fmt.Errorf("refresh JWKS after signature failure: %w", ferr)
		}
		// Skip the retry when the refreshed candidate set is IDENTICAL to the one we
		// already tried: re-verifying the same keys against the same token can never
		// succeed, so a flood of forged kid-less tokens would otherwise pay ~2x the
		// per-key signature-verification cost during the rate-limit suppression window
		// (the window the sentinel exists to protect). sameMatchingKeys compares against
		// the keys THIS caller tried, so a set a CONCURRENT goroutine just rotated in
		// (different from ours) is still retried and a real rotation is never missed.
		retryKeys := FindKeys(refreshed, kid)
		if !sameMatchingKeys(matchingKeys, retryKeys) {
			// The forced refresh returned a DIFFERENT (rotated) set, so signal the verifier
			// to re-sample its validation clock: reusing a clock sampled before this
			// (possibly slow) refresh would let a token that expired DURING the refresh pass
			// the exp check against a stale now.
			result, terminal, lastSig := tryKeys(retryKeys, true)
			if terminal != nil {
				return nil, terminal
			}
			if result != nil {
				return result, nil
			}
			if lastSig != nil {
				lastErr = lastSig
			}
		}
	}

	return nil, fmt.Errorf("verify signature: %w", lastErr)
}
