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

	"github.com/eunolabs/eunox/pkg/durationsentinel"
)

// DefaultTokenLeeway is the clock-skew grace applied to standard JWT claim validation
// (exp/nbf/iat) when leeway is left at its zero value. Kept small so a stolen short-lived
// token's reuse window is not materially extended.
const DefaultTokenLeeway = 10 * time.Second

// EffectiveLeeway resolves a configured token-validation leeway: a zero value
// selects the conservative DefaultTokenLeeway, a negative value disables leeway
// (clamped to zero, requiring exp strictly in the future), and a positive value is
// used as-is.
func EffectiveLeeway(configured time.Duration) time.Duration {
	return durationsentinel.Resolve(configured, DefaultTokenLeeway)
}

// jwksAlgorithms is the asymmetric-only allowlist of signature algorithms accepted for every
// JWKS-verified token. Symmetric algorithms (HS*) are deliberately excluded so a public
// verification key can never be misused as an HMAC secret (algorithm-confusion). Unexported
// and read only through JWKSAlgorithms(), which returns a copy — an exported mutable slice
// would let any code append(jose.HS256) and silently re-enable symmetric algorithms.
var jwksAlgorithms = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.EdDSA,
}

// JWKSAlgorithms returns a fresh copy of the asymmetric-only signature-algorithm allowlist,
// so a caller cannot mutate the package's defense in place. Pass it directly to
// jwt.ParseSigned at each verification site.
func JWKSAlgorithms() []jose.SignatureAlgorithm {
	return slices.Clone(jwksAlgorithms)
}

// terminalError marks a per-key verification failure as terminal: the signature verified but
// the claims/payload are invalid, so it is key-independent and MUST be surfaced as-is rather
// than retried against another key or a refreshed set. A plain (unwrapped) error is a
// retryable signature failure; encoding the distinction in the type prevents the two being
// silently swapped.
type terminalError struct{ err error }

func (e *terminalError) Error() string { return e.err.Error() }
func (e *terminalError) Unwrap() error { return e.err }

// Terminal marks err as a terminal (non-retryable) per-key verification failure for a
// VerifyWithKeyRotation verifier. See that function's verify contract.
func Terminal(err error) error { return &terminalError{err: err} }

// CandidateKIDs returns the distinct kid values to verify against for a token's JWS headers,
// in first-seen order. jwt.ParseSigned is compact-only, so a token carries one header today;
// consulting all headers avoids a headers[0] foot-gun should a multi-signature JWS ever
// reach this path. The "" (kid-less) entry is preserved (FindKeys expands it to "try every
// key"), since the IdP-JWT caller enforces no kid-required policy. An empty header list is
// an error.
func CandidateKIDs(headers []jose.Header) ([]string, error) {
	seen := make(map[string]bool, len(headers))
	kids := make([]string, 0, len(headers))
	for _, h := range headers {
		if seen[h.KeyID] {
			continue
		}
		seen[h.KeyID] = true
		kids = append(kids, h.KeyID)
	}
	if len(kids) == 0 {
		return nil, fmt.Errorf("JWT has no headers")
	}
	return kids, nil
}

// VerifyWithKeyRotationMultiKID runs VerifyWithKeyRotation for each candidate kid in order,
// returning the first success, so the IdP-JWT path handles a multi-signature JWS without
// open-coding the loop. kids must be non-empty (see CandidateKIDs); a "" entry means "try
// every key". freshKeySet is true only for the first verify call against a key set just
// fetched this call, so a closure pinning a lazily-sampled validation clock samples once and
// re-samples only after a forced refresh (closing the stale-clock-across-refresh hazard).
//
// A terminal failure (signature verified, claims invalid) is prioritized over a later
// key-miss: a multi-signature JWS has one shared payload, so the claims verdict is identical
// under every kid, and surfacing "no matching key" when the true cause is an expired claim
// would mislead callers into retrying a permanent rejection.
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
			// A terminal (claims) failure is payload-bound: every kid reaches the same
			// verdict, so return it immediately rather than letting a key-miss replace it.
			var te *terminalError
			if errors.As(err, &te) {
				return nil, err
			}
			lastErr = err
		}
	}
	return nil, lastErr
}

// VerifyWithKeyRotation runs the JWKS key-selection and rotation-retry choreography around a
// caller-supplied per-key verifier, keeping it in one place rather than in the IdP-JWT
// verifier. The caller has already parsed the token and extracted kid; this selects the
// candidate keys, forces a JWKS refresh on a kid miss, and — when every candidate fails
// signature verification — forces one rate-limited refresh and retries exactly once.
//
// verify performs the per-key signature + claim validation for ONE candidate key.
// freshKeySet is true only on the FIRST call against a key set just fetched this call, so a
// verifier pinning a lazily-sampled validation clock samples once per genuine refresh —
// never reusing a clock sampled before a slow forced refresh:
//   - return (result, nil)        on full success;
//   - return (nil, Terminal(err)) when the signature verified but the payload/claims are
//     invalid — a key-independent failure surfaced as-is, never retried;
//   - return (nil, err)           when the key failed signature verification — try the next
//     candidate, and ultimately one refreshed set.
//
// A (nil, nil) return is a contract violation and fails closed with an explicit message.
//
// When every candidate fails signature verification, the last signature error is wrapped as
// "verify signature". A forced-refresh failure is surfaced as "refresh JWKS ..." instead, so
// a transient JWKS outage during key rotation is distinguishable from a forged token.
func VerifyWithKeyRotation[T any](
	ctx context.Context,
	cache *JWKSCache,
	kid string,
	verify func(key *jose.JSONWebKey, freshKeySet bool) (result *T, err error),
) (*T, error) {
	// getKeysLive, not GetKeys: the result is immediately narrowed through FindKeys below,
	// which always allocates its own fresh slice — GetKeys' copyKeySet copy would be
	// transient garbage paid on every verification. See getKeysLive's doc.
	keys, err := cache.getKeysLive(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}

	matchingKeys := FindKeys(keys, kid)
	// refreshedForKid records whether the kid-miss path below already forced a refresh for
	// this kid, gating the post-signature-failure retry so it doesn't refetch the same set.
	refreshedForKid := false
	if len(matchingKeys) == 0 {
		// Key not in cache — force a fresh fetch in case the issuer rotated keys (a
		// TTL-respecting refresh would return the stale cached set). Rate-limited so a flood
		// of distinct unknown-kid tokens cannot amplify into one upstream fetch each.
		keys, err = cache.forceRefreshForKIDLive(ctx, kid)
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
	// caller's promise that candidateKeys were just fetched this call rather than served
	// from cache; forwarded to the FIRST verify call only, so a verifier pinning a
	// lazily-sampled clock re-samples once per fresh fetch, never mid-set.
	tryKeys := func(candidateKeys []jose.JSONWebKey, freshKeySet bool) (result *T, terminal, lastSig error) {
		for i := range candidateKeys {
			r, err := verify(&candidateKeys[i], freshKeySet && i == 0)
			if r != nil {
				return r, nil, nil
			}
			var te *terminalError
			switch {
			case errors.As(err, &te):
				// Signature verified but claims/payload invalid: surface with the marker so
				// VerifyWithKeyRotationMultiKID can distinguish this from a key-miss. Never
				// retried against another key.
				return nil, te, nil
			case err != nil:
				lastSig = err
			default:
				// (nil, nil): a verifier must yield a result or an error. Fail closed with an
				// intelligible message rather than the "verify signature: <nil>" terminus below.
				return nil, fmt.Errorf("per-key verifier returned neither a result nor an error (fail closed)"), nil
			}
		}
		return nil, nil, lastSig
	}

	// freshKeySet is refreshedForKid, not an unconditional true: the initial set is fresh
	// only when the kid-miss path above forced a fetch for it.
	result, terminal, lastErr := tryKeys(matchingKeys, refreshedForKid)
	if terminal != nil {
		return nil, terminal
	}
	if result != nil {
		return result, nil
	}

	// Every matching key failed signature verification. The cached keys may be stale from a
	// rotation, so force one (rate-limited) refresh and retry. Two cases reach here
	// unrefreshed: a kid-LESS token (the kid-miss branch never ran), and a kid-BEARING token
	// served from cache whose issuer rotated key material while REUSING the same kid. A
	// kid-bearing token that already refreshed above is NOT retried — its failure is terminal.
	if kid == "" || !refreshedForKid {
		refreshed, ferr := cache.forceRefreshForVerifyLive(ctx)
		if ferr != nil {
			// The token was already checked against a key we DID hold and failed that check,
			// so this is a signature failure, not a "never checked" outage. Surface lastErr
			// (%w) so the audit layer classifies it invalid_signature, carrying the refresh
			// failure only as non-wrapping (%v) context — otherwise a forged token presented
			// during a JWKS blip would record as an infra outage, masking forgery from a SIEM
			// keyed on invalid_signature.
			return nil, fmt.Errorf("verify signature (JWKS refresh after signature failure also failed: %v): %w", ferr, lastErr)
		}
		// Skip the retry when the refreshed set is IDENTICAL to the one already tried:
		// re-verifying can never succeed, and this bounds the cost of a flood of forged
		// kid-less tokens during the rate-limit suppression window. Compared against the keys
		// THIS caller tried (not a bare cache-changed flag) so a set a CONCURRENT goroutine
		// just rotated in still differs here and is retried.
		retryKeys := FindKeys(refreshed, kid)
		if !sameKeyMultiset(matchingKeys, retryKeys) {
			// The forced refresh returned a DIFFERENT (rotated) set: signal the verifier to
			// re-sample its clock, since reusing one sampled before this refresh would let a
			// token that expired DURING it pass the exp check against a stale now.
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
