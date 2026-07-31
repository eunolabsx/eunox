// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package durationsentinel

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestResolve(t *testing.T) {
	t.Parallel()
	const defaultVal = 10 * time.Second
	cases := []struct {
		name       string
		configured time.Duration
		want       time.Duration
	}{
		{"zero selects the default", 0, defaultVal},
		{"negative is disabled", -1, 0},
		{"large negative is disabled", -30 * 24 * time.Hour, 0},
		{"positive is verbatim", 90 * time.Minute, 90 * time.Minute},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, Resolve(tc.configured, defaultVal))
		})
	}
}
