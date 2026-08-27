// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/eunolabs/eunox/pkg/capability"
)

// signClaimsMapToken signs EXACTLY the members of raw, with no jwt.Claims merged in.
//
// signRawClaimsToken contributes `sub`, `iat` and `exp` of its own, which is the right
// default for a COLLISION test — the canonical spelling is already in the payload for a
// second one to collide with — and the wrong one here: a LONE variant is the shape under
// test, so the canonical member must be absent from the payload rather than supplied by the
// builder. A map passed straight to Claims is merged key-for-key with no struct round trip,
// so the payload bytes carry the spellings this file writes, verbatim.
func signClaimsMapToken(t *testing.T, key testKey, raw map[string]interface{}) string {
	t.Helper()
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key.priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", key.kid),
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	signed, err := jwt.Signed(sig).Claims(raw).Serialize()
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

// variantSpelling returns name with its first CASE-VARIABLE rune upper-cased — a spelling
// that folds to name (so the scan sees the same claim) but is not byte-equal to it (so no
// decoder on this path binds it). The shape a claims-merging bug or a half-finished claim
// rename actually produces. ok is false for a name with no such rune (`_meta`, a digit-led
// claim), which has no variant spelling at all and so cannot carry the differential.
//
// Rune-wise rather than name[:1]: byte-slicing a multi-byte first rune yields U+FFFD, and an
// underscore upper-cases to itself, so the byte form turned a legitimate watched name into a
// hard test failure blaming the watch list for the helper's limitation.
func variantSpelling(name string) (string, bool) {
	for i, r := range name {
		if u := unicode.ToUpper(r); u != r {
			return name[:i] + string(u) + name[i+len(string(r)):], true
		}
	}
	return name, false
}

// liveTokenClaims is an otherwise-valid payload for the PDP the tests below build: signed,
// unexpired, and identity-only, with no watched claim beyond the ones each case adds.
func liveTokenClaims() map[string]interface{} {
	now := time.Now()
	return map[string]interface{}{
		"mcp": map[string]interface{}{"v": mcpClaimVersion},
		"sub": "agent-1",
		"iat": now.Add(-time.Minute).Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}
}

// TestJWT_LoneClaimVariantRefused is the regression for the decoder differential between the
// claim scan and every reader of its result: the scan works in FOLD space and refused a
// COLLISION only, while go-jose's vendored decoder matches a member name byte-exactly (no
// EqualFold fallback) and an exact-key lookup in the decoded map has no fold either. A LONE
// variant collides with nothing, so it passed the scan and then bound to NOTHING — every
// check that reads the claim behaved as though the token never carried it.
//
// Each row pairs the canonical spelling with the lone variant of the same claim and the same
// value, so what the drop cost is visible in the diff between the two verdicts rather than
// asserted in prose. Not third-party forgeable — the signature covers the payload — so the
// precondition is the issuer's own minting pipeline, which is exactly what the scan exists to
// surface fail-closed.
func TestJWT_LoneClaimVariantRefused(t *testing.T) {
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()

	// The experimental capability-claim gate is ON here (makeJWTPDP's default); the row that
	// tests the DEFAULT posture builds its own validator below.
	p := makeJWTPDP(t, srv, "", "", nil)

	rows := []struct {
		name      string
		canonical string
		// build writes the claim under the given spelling into a fresh live payload, so the
		// canonical and variant tokens differ in nothing but the member name.
		build func(spelling string) map[string]interface{}
		// wantCanonical is the category the CANONICAL spelling is refused with; "" means it
		// must validate, and verify then asserts what the claim bought.
		wantCanonical string
		verify        func(t *testing.T, claims *JWTClaims)
		// dropped names what admitting the variant cost, for the failure message.
		dropped string
	}{
		{
			name:      "cnf downgrades proof-of-possession to a bearer token",
			canonical: "cnf",
			build: func(spelling string) map[string]interface{} {
				c := liveTokenClaims()
				c[spelling] = map[string]interface{}{"jkt": "abc"}
				return c
			},
			wantCanonical: jwtErrSenderConstrained,
			dropped:       "a DPoP/mTLS-bound token is honored as a plain bearer token that anyone who captured it can replay",
		},
		{
			name:      "nbf leaves no lower validity bound",
			canonical: "nbf",
			build: func(spelling string) map[string]interface{} {
				c := liveTokenClaims()
				c[spelling] = time.Now().Add(2 * time.Hour).Unix()
				return c
			},
			// validateStandardClaims requires iat and exp because an absent one imposes no
			// bound; nbf carries no such requirement, so go-jose gates its not-yet-valid
			// branch on the claim being decoded at all and a post-dated token is usable now.
			wantCanonical: jwtErrNotYetValid,
			dropped:       "a post-dated token is usable for the whole window its issuer meant to exclude",
		},
		{
			name:      "jti empties the kill switch's finest revocation dimension",
			canonical: "jti",
			build: func(spelling string) map[string]interface{} {
				c := liveTokenClaims()
				c[spelling] = "cred-42"
				return c
			},
			verify: func(t *testing.T, claims *JWTClaims) {
				if claims.TokenID != "cred-42" {
					t.Fatalf("TokenID = %q, want cred-42", claims.TokenID)
				}
			},
			dropped: "`eunox kill --jti` matches nothing for the rest of the token's exp window and the tape's token_id is blank",
		},
		{
			name:      "mcp.task_id drops attribution from the signed record",
			canonical: "task_id",
			build: func(spelling string) map[string]interface{} {
				c := liveTokenClaims()
				c["mcp"].(map[string]interface{})[spelling] = "t-1"
				return c
			},
			verify: func(t *testing.T, claims *JWTClaims) {
				if claims.TaskID != "t-1" {
					t.Fatalf("TaskID = %q, want t-1", claims.TaskID)
				}
			},
			dropped: "the tape asserts the call had no task when the token named one",
		},
		{
			name:      "mcp.agent_id drops attribution from the signed record",
			canonical: "agent_id",
			build: func(spelling string) map[string]interface{} {
				c := liveTokenClaims()
				c["mcp"].(map[string]interface{})[spelling] = "a-1"
				return c
			},
			verify: func(t *testing.T, claims *JWTClaims) {
				if claims.AgentID != "a-1" {
					t.Fatalf("AgentID = %q, want a-1", claims.AgentID)
				}
			},
			dropped: "`eunox kill --agent` cannot match, and the tape asserts the call had no agent",
		},
		{
			name:      "mcp.capabilities drops the allowlist its issuer wrote",
			canonical: mcpMemberCapabilities,
			build: func(spelling string) map[string]interface{} {
				c := liveTokenClaims()
				c["mcp"].(map[string]interface{})[spelling] = []interface{}{"tool:read_file"}
				return c
			},
			verify: func(t *testing.T, claims *JWTClaims) {
				if !claims.HasCapabilities {
					t.Fatal("HasCapabilities = false; the canonical spelling must carry the exhaustive allowlist")
				}
			},
			dropped: "the token validates identity-only and the route's manifest governs alone",
		},
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			ctx, err := p.ValidateToken(context.Background(), "Bearer "+signClaimsMapToken(t, key, row.build(row.canonical)))
			if row.wantCanonical == "" {
				if err != nil {
					t.Fatalf("the canonical spelling %q must validate: %v", row.canonical, err)
				}
				row.verify(t, JWTClaimsPtr(ctx))
			} else if got := ClassifyJWTError(err); got != row.wantCanonical {
				t.Fatalf("canonical %q: error category = %q, want %q", row.canonical, got, row.wantCanonical)
			}

			variant, ok := variantSpelling(row.canonical)
			if !ok {
				t.Fatalf("%q has no case-variable rune, so this row cannot express the differential", row.canonical)
			}
			_, err = p.ValidateToken(context.Background(), "Bearer "+signClaimsMapToken(t, key, row.build(variant)))
			if err == nil {
				t.Fatalf("ValidateToken accepted a token spelling %q as %q; %s", row.canonical, variant, row.dropped)
			}
			if got := ClassifyJWTError(err); got != jwtErrNonCanonicalClaim {
				t.Fatalf("variant %q: error category = %q, want %q", variant, got, jwtErrNonCanonicalClaim)
			}
		})
	}
}

// TestJWT_CapabilitiesVariantUnderDefaultPosture is the sharpest row of the family, and the
// one that is not merely a lost restriction: with the experimental gate OFF (the default) the
// canonical spelling is REFUSED, so before the scan watched spellings the variant was
// strictly MORE permissive than the claim it is a misspelling of — the unstable schema relied
// on silently in the one configuration written to make that impossible.
func TestJWT_CapabilitiesVariantUnderDefaultPosture(t *testing.T) {
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()

	p := NewJWTPDP(JWTPDPOptions{
		JWKSURI:          srv.URL + "/",
		AllowAnyIssuer:   true,
		AllowAnyAudience: true,
		CacheTTL:         5 * time.Second,
		// ExperimentalCapabilities deliberately left off: this IS the default posture.
	})

	build := func(spelling string) string {
		c := liveTokenClaims()
		c["mcp"].(map[string]interface{})[spelling] = []interface{}{"tool:read_file"}
		return signClaimsMapToken(t, key, c)
	}

	_, err := p.ValidateToken(context.Background(), "Bearer "+build(mcpMemberCapabilities))
	if got := ClassifyJWTError(err); got != jwtErrCapabilitiesDisabled {
		t.Fatalf("canonical spelling: error category = %q, want %q", got, jwtErrCapabilitiesDisabled)
	}

	variant, _ := variantSpelling(mcpMemberCapabilities)
	_, err = p.ValidateToken(context.Background(), "Bearer "+build(variant))
	if err == nil {
		t.Fatalf("ValidateToken admitted %q identity-only where the canonical spelling is refused %s", variant, jwtErrCapabilitiesDisabled)
	}
	if got := ClassifyJWTError(err); got != jwtErrNonCanonicalClaim {
		t.Fatalf("variant spelling: error category = %q, want %q", got, jwtErrNonCanonicalClaim)
	}
}

// fullyPopulatedClaims names every watched claim once, under its canonical spelling. The
// structural test below moves one member at a time to a variant spelling, so this fixture is
// what makes each row non-vacuous — a watched name missing from it would produce a payload
// with no variant in it at all.
func fullyPopulatedClaims() map[string]interface{} {
	now := time.Now()
	return map[string]interface{}{
		"mcp": map[string]interface{}{
			"v":                   mcpClaimVersion,
			mcpMemberCapabilities: []interface{}{"tool:read_file"},
			"task_id":             "t-1",
			"agent_id":            "a-1",
		},
		"sub": "agent-1",
		"iss": "https://idp.example.com",
		"aud": "eunox",
		"jti": "cred-42",
		"exp": now.Add(time.Hour).Unix(),
		"nbf": now.Add(-time.Minute).Unix(),
		"iat": now.Add(-time.Minute).Unix(),
		"cnf": map[string]interface{}{"jkt": "abc"},
	}
}

// TestJWT_EveryWatchedClaimNameVariantRefused drives the refusal off the watch lists
// themselves, so a claim added to watchedTopLevelClaims or watchedMCPMembers cannot inherit
// the decoder differential silently: the moment a name is watched, this test demands that a
// lone variant of it be refused.
//
// It doubles as the guard on the lists' own spelling. Each entry is what every OTHER spelling
// is refused against, so an entry written with the wrong case would invert the gate — the
// canonical-control half fails loudly rather than leaving the claim quietly unenforceable.
func TestJWT_EveryWatchedClaimNameVariantRefused(t *testing.T) {
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()
	p := makeJWTPDP(t, srv, "", "", nil)

	// The control carries every watched claim canonically. It is refused (its `cnf` is
	// sender-constraining) — the assertion is only that it is not refused for a SPELLING.
	_, err := p.ValidateToken(context.Background(), "Bearer "+signClaimsMapToken(t, key, fullyPopulatedClaims()))
	if got := ClassifyJWTError(err); got == jwtErrNonCanonicalClaim {
		t.Fatalf("a payload spelling every watched claim canonically was refused %q, so a watch list entry is not the spelling this build reads: %v", got, err)
	}

	// nested picks the object a watched name lives in: the mcp block's members are scanned
	// at their own depth, one claim object in.
	for _, tc := range []struct {
		watched []string
		nested  bool
	}{
		{watchedTopLevelClaims, false},
		{watchedMCPMembers, true},
	} {
		for _, name := range tc.watched {
			t.Run(name, func(t *testing.T) {
				variant, ok := variantSpelling(name)
				if !ok {
					// Not a failure: a name with no case-variable rune cannot be mis-cased, so
					// there is no differential for the scan to close.
					t.Skipf("%q has no case variant, so no spelling of it can read as absent", name)
				}
				if capability.FoldJSONKey(variant) != capability.FoldJSONKey(name) {
					t.Fatalf("%q does not fold to %q, so the payload below carries an unrelated claim", variant, name)
				}

				claims := fullyPopulatedClaims()
				obj := claims
				if tc.nested {
					obj = claims["mcp"].(map[string]interface{})
				}
				value, ok := obj[name]
				if !ok {
					t.Fatalf("fullyPopulatedClaims does not name %q, so no variant of it reaches the scan; add it there", name)
				}
				delete(obj, name)
				obj[variant] = value

				_, err := p.ValidateToken(context.Background(), "Bearer "+signClaimsMapToken(t, key, claims))
				if err == nil {
					t.Fatalf("ValidateToken accepted a token spelling the watched claim %q as %q, which no decoder here binds", name, variant)
				}
				if got := ClassifyJWTError(err); got != jwtErrNonCanonicalClaim {
					t.Fatalf("error category = %q, want %q", got, jwtErrNonCanonicalClaim)
				}
			})
		}
	}
}

// decodedMemberNames returns the json member names encoding/json — and go-jose's fork, which
// builds its field table the same way — would bind on ty. That is the question a watch list
// has to answer: what does this build DECODE.
//
// A field with no json NAME (no tag at all, or an options-only `json:",omitempty"`) binds
// under its Go field name, not nothing. Reading the tag alone made the drift guard blind to
// exactly the careless addition it exists to catch: the member would be decoded, unwatched,
// and a variant spelling of it would read as absent with the guard still green.
func decodedMemberNames(t *testing.T, ty reflect.Type) []string {
	t.Helper()
	var out []string
	for i := 0; i < ty.NumField(); i++ {
		f := ty.Field(i)
		if f.Anonymous {
			// encoding/json flattens an embedded struct's fields into the parent object, so a
			// watch list derived without walking it would be short. Refused rather than walked
			// because no such field exists here and a half-right walk is worse than none.
			t.Fatalf("%s embeds %s; decodedMemberNames does not flatten embedded fields", ty, f.Type)
		}
		if f.PkgPath != "" {
			continue // unexported: encoding/json binds nothing to it
		}
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if name == "" {
			name = f.Name
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// TestWatchedMCPMembers_MatchesTheDecodedStruct is what makes watchedMCPMembers' rationale
// true rather than aspirational. Making it a var lets a test enumerate what IS listed; the
// hazard is the member that is NOT — a field added to mcpClaimSet and left off the list is
// read by this build and unwatched by the scan, which is the decoder differential reopened
// with every existing test green (they all iterate FROM the list).
//
// Derived here rather than at run time, and unlike watchedTopLevelClaims' deliberate refusal
// to reflect off jwt.Claims: that argument is about a THIRD-PARTY struct moving under this
// build between releases. mcpClaimSet is declared in this package, so the drift a derivation
// would hide cannot happen, while the drift a hand-written list hides is the live one.
func TestWatchedMCPMembers_MatchesTheDecodedStruct(t *testing.T) {
	t.Parallel()
	want := decodedMemberNames(t, reflect.TypeOf(mcpClaimSet{}))
	got := append([]string(nil), watchedMCPMembers...)
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("watchedMCPMembers = %v, mcpClaimSet decodes %v; every member this build decodes must be watched, or a variant spelling of it reads as absent", got, want)
	}
}

// TestWatchedTopLevelClaims_CoverEveryRegisteredClaimGoJoseBinds keeps the hand-written list
// honest without deriving it: watchedTopLevelClaims is listed explicitly so a go-jose release
// cannot silently widen or narrow the set, and this is the other half of that argument — the
// release that ADDS a registered-claim field would otherwise reopen the differential for it,
// with the same silence. Superset rather than equality: `mcp` and `cnf` are watched and are
// not jwt.Claims fields at all.
func TestWatchedTopLevelClaims_CoverEveryRegisteredClaimGoJoseBinds(t *testing.T) {
	t.Parallel()
	watched := make(map[string]bool, len(watchedTopLevelClaims))
	for _, name := range watchedTopLevelClaims {
		watched[name] = true
	}
	for _, tag := range decodedMemberNames(t, reflect.TypeOf(jwt.Claims{})) {
		if !watched[tag] {
			t.Errorf("jwt.Claims binds %q and watchedTopLevelClaims does not name it, so a variant spelling of it reads as absent", tag)
		}
	}
}

// TestJWT_EveryWatchedClaimNameCollisionRefused is the collision half of the same derivation.
// Without it the two halves of one gate drift apart in coverage: a claim added to either watch
// list picks up a lone-variant row automatically (from the test above) and no collision row,
// and the derived test passing is what makes the addition look fully covered.
//
// The exact-duplicate shape is deliberately not exercised through ValidateToken: go-jose's
// fork refuses a duplicate KEY outright, above this scan, so no JWT reaches the collision arm
// that way. Two spellings is the shape that does.
func TestJWT_EveryWatchedClaimNameCollisionRefused(t *testing.T) {
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()
	p := makeJWTPDP(t, srv, "", "", nil)

	for _, tc := range []struct {
		watched []string
		nested  bool
	}{
		{watchedTopLevelClaims, false},
		{watchedMCPMembers, true},
	} {
		for _, name := range tc.watched {
			t.Run(name, func(t *testing.T) {
				variant, ok := variantSpelling(name)
				if !ok {
					t.Skipf("%q has no case variant, so it cannot be named twice by spelling", name)
				}
				claims := fullyPopulatedClaims()
				obj := claims
				if tc.nested {
					obj = claims["mcp"].(map[string]interface{})
				}
				value, present := obj[name]
				if !present {
					t.Fatalf("fullyPopulatedClaims does not name %q; add it there", name)
				}
				obj[variant] = value

				_, err := p.ValidateToken(context.Background(), "Bearer "+signClaimsMapToken(t, key, claims))
				if err == nil {
					t.Fatalf("ValidateToken accepted a token naming the watched claim %q as both %q and %q", name, name, variant)
				}
				if got := ClassifyJWTError(err); got != jwtErrAmbiguousClaims {
					t.Fatalf("error category = %q, want %q", got, jwtErrAmbiguousClaims)
				}
			})
		}
	}
}

// TestJWT_MalformedMcpBlockIsNotReportedAsAmbiguous: the scan has THREE outcomes and the audit
// category had two. `{"mcp":null}` decodes into mcpClaimSet as a no-op, so it passes the
// struct unmarshal and fails in the scan on the block's SHAPE — which, defaulted to
// `ambiguous_claims`, told an operator to stop emitting two spellings of a claim their token
// spells exactly once. error_type is a closed set matched in a SIEM and the message never
// reaches the record, so the category is the whole diagnosis.
func TestJWT_MalformedMcpBlockIsNotReportedAsAmbiguous(t *testing.T) {
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()
	p := makeJWTPDP(t, srv, "", "", nil)

	claims := liveTokenClaims()
	claims["mcp"] = nil
	_, err := p.ValidateToken(context.Background(), "Bearer "+signClaimsMapToken(t, key, claims))
	if err == nil {
		t.Fatal("a non-object mcp claim must be refused")
	}
	if got := ClassifyJWTError(err); got != jwtErrMalformedToken {
		t.Fatalf("error category = %q, want %q", got, jwtErrMalformedToken)
	}
}

// TestGoJoseBindsMemberNamesByteExactly pins the premise the whole canonical-spelling design
// rests on, and the one no token can exercise any more: the scan refuses a variant above
// anything go-jose binds, so the refusal is now identical whether or not that decoder folds.
// That independence is a virtue, but it also means nothing else in the suite would notice a
// release that started folding — and three comment blocks (this package's claim scan, the
// watch lists, and pkg/capability/claim_json.go's file header) reason from byte-exactness
// about which spelling wins a collision. Asserted directly against the decoder instead.
func TestGoJoseBindsMemberNamesByteExactly(t *testing.T) {
	t.Parallel()
	// Through go-jose's own decode of a real token, not encoding/json: the stdlib DOES fold,
	// and asserting against it would pin the opposite of the premise under test.
	key := newTestKey(t, "k1")
	tokenStr := signClaimsMapToken(t, key, map[string]interface{}{
		"Sub": "admin", "Jti": "cred",
		"MCP": map[string]interface{}{"V": mcpClaimVersion, "Task_Id": "t-1"},
	})
	parsed, err := jwt.ParseSigned(tokenStr, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("parsing a variant-spelled token: %v", err)
	}
	var std jwt.Claims
	if err := parsed.UnsafeClaimsWithoutVerification(&std); err != nil {
		t.Fatalf("a variant-spelled payload must still decode: %v", err)
	}
	if std.Subject != "" || std.ID != "" {
		t.Fatalf("go-jose bound a case variant (sub=%q jti=%q); it folds now, so the collision reasoning in the claim-scan comments no longer holds", std.Subject, std.ID)
	}
	var payload idpJWTPayload
	if err := parsed.UnsafeClaimsWithoutVerification(&payload); err != nil {
		t.Fatalf("a variant-spelled payload must still decode: %v", err)
	}
	if payload.MCP.Version != "" || payload.MCP.TaskID != "" {
		t.Fatalf("go-jose bound a case-variant mcp block (v=%q task_id=%q); see above", payload.MCP.Version, payload.MCP.TaskID)
	}
}

// TestClaimScanSentinelsEachGetTheirOwnCategory keeps claimScanErrCode exhaustive by
// construction. Its default arm is a NEGATION over sentinels another package owns, so a new
// refusal shape added to capability.ClaimMembers would silently record `malformed_token` —
// telling an operator their claim object is not an object when it is, which is the inherited
// misdiagnosis this commit fixed one layer down. The source guard is what makes the
// exhaustiveness executable rather than prose.
func TestClaimScanSentinelsEachGetTheirOwnCategory(t *testing.T) {
	t.Parallel()
	categories := map[string]string{
		"ErrClaimNameVariant":   jwtErrNonCanonicalClaim,
		"ErrClaimNameCollision": jwtErrAmbiguousClaims,
	}
	for sentinel, want := range map[error]string{
		capability.ErrClaimNameVariant:   jwtErrNonCanonicalClaim,
		capability.ErrClaimNameCollision: jwtErrAmbiguousClaims,
	} {
		if got := claimScanErrCode(fmt.Errorf("scan: %w", sentinel)); got != want {
			t.Errorf("claimScanErrCode(%v) = %q, want %q", sentinel, got, want)
		}
	}
	// An unsentinelled failure is the claim object's SHAPE, which is neither minting mistake.
	if got := claimScanErrCode(errors.New("jwt mcp claim: expected a JSON object")); got != jwtErrMalformedToken {
		t.Errorf("an unsentinelled scan failure = %q, want %q", got, jwtErrMalformedToken)
	}

	src, err := os.ReadFile(filepath.Join("..", "..", "pkg", "capability", "claim_json.go"))
	if err != nil {
		t.Fatalf("reading the scan's source: %v", err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), "claim_json.go", src, 0)
	if err != nil {
		t.Fatalf("parsing the scan's source: %v", err)
	}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			for _, name := range spec.(*ast.ValueSpec).Names {
				if !strings.HasPrefix(name.Name, "ErrClaim") {
					continue
				}
				if _, covered := categories[name.Name]; !covered {
					t.Errorf("capability.%s has no audit category: claimScanErrCode would fold it into %q, which describes a different fault", name.Name, jwtErrMalformedToken)
				}
			}
		}
	}
}

// TestDecodeJWTClaimsPreservingNumbers_RefusesNonObjectAndTrailers is the direct proof of two
// guards nothing else can reach: go-jose refuses the same bytes first, so reverting either
// would leave the whole suite green while restoring a fail-open. A trailing `}` or `]` passed
// the old dec.More() check, and a payload of the literal `null` decoded to a NIL claim map
// whose every exact-key read — the `cnf` proof-of-possession check included — answers absent.
func TestDecodeJWTClaimsPreservingNumbers_RefusesNonObjectAndTrailers(t *testing.T) {
	t.Parallel()
	for name, payload := range map[string]string{
		"trailing brace":   `{"sub":"a"}}`,
		"trailing bracket": `{"sub":"a"}]`,
		"second value":     `{"sub":"a"} {"sub":"b"}`,
		"json null":        `null`,
		"json array":       `[1,2]`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			claims, err := decodeJWTClaimsPreservingNumbers([]byte(payload))
			if err == nil {
				t.Fatalf("decoded %s as a claim map (%v); a payload is one JSON object", payload, claims)
			}
		})
	}
}
