// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"encoding/json"
	"fmt"
)

// Obligation represents a post-decision action to apply. Only the redactFields
// obligation exists today.
type Obligation struct {
	Type string
	// Paths is the redactFields target list (dot-path strings).
	Paths []string
}

// MarshalJSON serializes Obligation based on its type-specific payload.
func (o Obligation) MarshalJSON() ([]byte, error) {
	switch o.Type {
	case DirectiveTypeRedactFields:
		// Normalize a nil Paths to an empty slice so the marshaled shape is always
		// "paths":[], never "paths":null.
		paths := o.Paths
		if paths == nil {
			paths = []string{}
		}
		return json.Marshal(struct {
			Type  string   `json:"type"`
			Paths []string `json:"paths"`
		}{
			Type:  o.Type,
			Paths: paths,
		})
	default:
		return nil, fmt.Errorf("unknown obligation type: %q", o.Type)
	}
}

// UnmarshalJSON deserializes Obligation based on its discriminator. No production path
// decodes an Obligation today; this exists for symmetry with MarshalJSON — reflection-based
// default unmarshal would silently accept an unknown Type instead of failing closed.
func (o *Obligation) UnmarshalJSON(data []byte) error {
	var envelope struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return err
	}

	switch envelope.Type {
	case DirectiveTypeRedactFields:
		var payload struct {
			Type  string   `json:"type"`
			Paths []string `json:"paths"`
		}
		if err := json.Unmarshal(data, &payload); err != nil {
			return err
		}
		o.Type = payload.Type
		o.Paths = payload.Paths
		return nil
	default:
		return fmt.Errorf("unknown obligation type: %q", envelope.Type)
	}
}
