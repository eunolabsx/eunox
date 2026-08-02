// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package callcounter_test

import "github.com/eunolabs/eunox/pkg/callcounter"

// The external test package's spelling of the shared single-bucket admission helpers; the
// definitions and the rationale live in export_test.go, beside the other in-package test
// seams, so both test packages exercise one helper rather than two that can drift.
var (
	admitCounted  = callcounter.AdmitCounted
	admitWeighted = callcounter.AdmitWeighted
)
