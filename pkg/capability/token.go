// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"encoding/json"
)

// Confirmation carries the RFC 7800 `cnf` claim. The three RFC 7800 proof-of-possession
// methods — JKT (§3.1 thumbprint), JWK (§3.2 embedded key), KID (§3.3 reference) — are
// exposed as typed convenience fields, but the authoritative representation is `members`:
// the FULL cnf object verbatim (every member, modeled and unmodeled). MarshalJSON re-emits
// members and IsSenderConstrained counts them, so a decode-then-re-encode round-trip
// preserves EXACTLY what was decoded — a bare {"jkt":""}, a null-valued member, or an
// unmodeled RFC 8705 "x5t#S256" mTLS binding all survive with IsSenderConstrained
// unchanged: any member at all makes the token sender-constrained. The proxy has no PoP
// verification path, so [CnfIsSenderConstrained] and its callers FAIL CLOSED on any
// non-empty cnf rather than downgrade it to a bearer token (which would let a captured
// token be replayed).
type Confirmation struct {
	// Typed convenience views of the modeled methods, populated on decode for callers that
	// read them. NOT authoritative for serialization or IsSenderConstrained — `members` is.
	JKT string           // RFC 7800 §3.1 JWK SHA-256 thumbprint
	JWK *json.RawMessage // RFC 7800 §3.2 embedded public key
	KID string           // RFC 7800 §3.3 key reference

	// members holds the full cnf object keyed by member name. It is reconstructed by
	// UnmarshalJSON from the serialized cnf object (so it need not itself be a serialized
	// field), and is nil only for a struct-literal-built Confirmation (in tests), where
	// MarshalJSON and IsSenderConstrained fall back to the typed fields above.
	members map[string]json.RawMessage
}

// UnmarshalJSON decodes the cnf claim into `members` verbatim and populates the typed
// convenience fields. cnf is a JSON object (RFC 7800 §3.1), so a non-object value errors
// here and the caller fails closed — with ONE deliberate exception: JSON `null` decodes
// successfully to a nil map, leaving a not-sender-constrained Confirmation. That matches
// CnfIsSenderConstrained, which treats an explicit-null cnf the same as an absent one.
func (c *Confirmation) UnmarshalJSON(data []byte) error {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil {
		return err
	}
	*c = Confirmation{members: members}
	if v, ok := members["jkt"]; ok {
		if err := json.Unmarshal(v, &c.JKT); err != nil {
			return err
		}
	}
	if v, ok := members["jwk"]; ok {
		raw := append(json.RawMessage(nil), v...)
		c.JWK = &raw
	}
	if v, ok := members["kid"]; ok {
		if err := json.Unmarshal(v, &c.KID); err != nil {
			return err
		}
	}
	return nil
}

// MarshalJSON re-emits the exact decoded cnf object, so a round-trip is faithful for every
// member (modeled, unmodeled, or empty-valued). Map marshaling sorts keys → deterministic
// output. MUST NOT be removed: `members` is unexported and untagged, so default struct
// marshaling would drop the whole cnf object and downgrade a sender-constrained token — the
// TestConfirmation_RoundTripPreservesSenderConstrained test guards against this.
func (c Confirmation) MarshalJSON() ([]byte, error) {
	if c.members != nil {
		return json.Marshal(c.members)
	}
	// Struct-literal fallback (constructed in Go, never decoded): synthesize the object
	// from the typed fields.
	out := make(map[string]json.RawMessage, 3)
	if c.JKT != "" {
		b, err := json.Marshal(c.JKT)
		if err != nil {
			return nil, err
		}
		out["jkt"] = b
	}
	if c.JWK != nil {
		out["jwk"] = *c.JWK
	}
	if c.KID != "" {
		b, err := json.Marshal(c.KID)
		if err != nil {
			return nil, err
		}
		out["kid"] = b
	}
	return json.Marshal(out)
}

// IsSenderConstrained reports whether the cnf claim declares any proof-of-possession
// binding: ANY member of the cnf object (authoritative on a decoded Confirmation), or a set
// typed field (the fallback for a struct-literal-built one where members is nil). Any member
// — including an empty-valued or null modeled one, or an unmodeled RFC 8705 x5t#S256 binding
// — fails closed. A nil Confirmation is not sender-constrained.
func (c *Confirmation) IsSenderConstrained() bool {
	if c == nil {
		return false
	}
	return len(c.members) > 0 || c.JKT != "" || c.JWK != nil || c.KID != ""
}

// CnfIsSenderConstrained reports whether an already-decoded RFC 7800 `cnf` claim value
// (as produced by a generic json.Unmarshal into interface{}, e.g. an IdP JWT's raw claim
// map) declares a proof-of-possession binding. It decodes the value through Confirmation,
// so every JWT-verification path in this binary shares ONE canonical sender-constrained
// rule and cannot drift. A nil value (absent or explicit-null cnf) is not constraining. A
// present non-object cnf is malformed; malformed is reported so the caller can fail closed
// with an accurate reason rather than mislabeling it.
func CnfIsSenderConstrained(v interface{}) (constrained, malformed bool) {
	if v == nil {
		return false, false
	}
	b, err := json.Marshal(v)
	if err != nil {
		return false, true
	}
	var conf Confirmation
	if err := json.Unmarshal(b, &conf); err != nil {
		return false, true
	}
	return conf.IsSenderConstrained(), false
}
