// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

// Shared white-box test helpers for the package-pdp tests. These mirror the
// helpers of the same name in cmd/eunox (package main): the main-package
// copies build a *ManifestPDP through the LocalManifest config wrapper, while
// here — where ManifestPDP and its construction live — the wrapper is
// unnecessary, so these build it directly from the capability constraints.
// Keeping a copy in each package is the documented cost of the PDP package
// split (the main copies stay because many package-main transport/audit tests
// depend on them).

import (
	"context"
	"encoding/json"
	"time"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// newTestManifestPDP builds a ManifestPDP over caps with an in-memory kill switch.
func newTestManifestPDP(caps ...capability.Constraint) *ManifestPDP {
	return newTestManifestPDPWithKS(killswitch.NewInMemory(), caps...)
}

// newTestManifestPDPWithKS builds a ManifestPDP over caps with the given kill switch.
func newTestManifestPDPWithKS(ks killswitch.Checker, caps ...capability.Constraint) *ManifestPDP {
	return NewManifestPDP(caps, enforcement.New(), ks)
}

// fixedClock is an enforcement.Clock that always reports t.
type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

// ctxWithAgent returns a context carrying JWT claims for agentID.
func ctxWithAgent(agentID string) context.Context {
	return WithJWTClaims(context.Background(), &JWTClaims{AgentID: agentID})
}

// callTool runs a tools/call decision through the ManifestPDP.
func callTool(p *ManifestPDP, ctx context.Context, name string, args map[string]interface{}) capability.EnforceResponse {
	return p.Decide(ctx, "sess-1", EnforceTarget{Type: capability.TargetTypeTool, Name: name}, args, "")
}

// PolicyDecisionPoint test doubles for the package-pdp white-box tests. These
// are copies of the doubles of the same name in cmd/eunox (package main),
// where they back the transport tests; the pdp white-box tests that wrap an
// inner PDP (JWTPDP intersection, list-filter passthrough) need their own copy
// because the originals live in package main.

// denyAllPDP denies every enforced method and passes list results through.
type denyAllPDP struct{}

func (denyAllPDP) Decide(_ context.Context, _ string, target EnforceTarget, _ map[string]interface{}, _ string) capability.EnforceResponse {
	return capability.EnforceResponse{
		Decision: capability.DecisionDeny,
		Denial: &capability.DenialInfo{
			Code:    "CAPABILITY_DENIED",
			Message: "denied by test policy: " + target.Name,
		},
	}
}

func (denyAllPDP) DecideResourceRead(_ context.Context, _, uri, _ string) capability.EnforceResponse {
	return capability.EnforceResponse{
		Decision: capability.DecisionDeny,
		Denial:   &capability.DenialInfo{Code: "CAPABILITY_DENIED", Message: "denied by test policy: " + uri},
	}
}

func (denyAllPDP) DecidePromptGet(_ context.Context, _, promptName, _ string) capability.EnforceResponse {
	return capability.EnforceResponse{
		Decision: capability.DecisionDeny,
		Denial:   &capability.DenialInfo{Code: "CAPABILITY_DENIED", Message: "denied by test policy: " + promptName},
	}
}

func (denyAllPDP) DecideSampling(_ context.Context, _, _ string) capability.EnforceResponse {
	return capability.EnforceResponse{
		Decision: capability.DecisionDeny,
		Denial: &capability.DenialInfo{
			Code:    capability.ErrCodeSamplingDenied,
			Message: "denied by test policy: sampling",
		},
	}
}
func (denyAllPDP) CheckKill(_ context.Context, _ string) *capability.EnforceResponse {
	return nil
}
func (denyAllPDP) CheckAudience(_ context.Context) *capability.EnforceResponse {
	return nil
}
func (denyAllPDP) RecordObservedToolHashes(_ context.Context, _ json.RawMessage) int { return 0 }
func (denyAllPDP) ReleaseSession(_ context.Context, _ string)                        {}
func (denyAllPDP) FilterToolsList(_ context.Context, result json.RawMessage) ListFilterResult {
	return ListFilterResult{Result: result}
}
func (denyAllPDP) FilterResourcesList(_ context.Context, result json.RawMessage) ListFilterResult {
	return ListFilterResult{Result: result}
}
func (denyAllPDP) FilterPromptsList(_ context.Context, result json.RawMessage) ListFilterResult {
	return ListFilterResult{Result: result}
}

// staticPDP returns a fixed decision for every enforced method and passes list
// results through.
type staticPDP struct {
	decision capability.EnforceResponse
}

func (s *staticPDP) Decide(_ context.Context, _ string, _ EnforceTarget, _ map[string]interface{}, _ string) capability.EnforceResponse {
	return s.decision
}

func (s *staticPDP) DecideResourceRead(_ context.Context, _, _, _ string) capability.EnforceResponse {
	return s.decision
}

func (s *staticPDP) DecidePromptGet(_ context.Context, _, _, _ string) capability.EnforceResponse {
	return s.decision
}

func (*staticPDP) DecideSampling(_ context.Context, _, _ string) capability.EnforceResponse {
	return capability.EnforceResponse{
		Decision: capability.DecisionDeny,
		Denial: &capability.DenialInfo{
			Code:    capability.ErrCodeSamplingDenied,
			Message: "staticPDP: sampling deny-by-default",
		},
	}
}
func (*staticPDP) CheckKill(_ context.Context, _ string) *capability.EnforceResponse {
	return nil
}
func (*staticPDP) CheckAudience(_ context.Context) *capability.EnforceResponse {
	return nil
}
func (*staticPDP) RecordObservedToolHashes(_ context.Context, _ json.RawMessage) int { return 0 }
func (*staticPDP) ReleaseSession(_ context.Context, _ string)                        {}
func (*staticPDP) FilterToolsList(_ context.Context, result json.RawMessage) ListFilterResult {
	return ListFilterResult{Result: result}
}
func (*staticPDP) FilterResourcesList(_ context.Context, result json.RawMessage) ListFilterResult {
	return ListFilterResult{Result: result}
}
func (*staticPDP) FilterPromptsList(_ context.Context, result json.RawMessage) ListFilterResult {
	return ListFilterResult{Result: result}
}

// recordObservedToolHash records a tool's observed surface from its FIELDS rather than a
// precomputed hash. Production computes the hash once per tools/list entry and shares it
// between the FM-5 and Tier-2 pins (see recordObservedHash), so this spelling exists only
// for tests, which are clearer stating the description they mean to pin than the digest of
// it.
func (p *ManifestPDP) recordObservedToolHash(name, description, title string, annotations, inputSchema, outputSchema map[string]interface{}, pin string) {
	p.recordObservedHash(name, SurfaceHash(description, title, annotations, inputSchema, outputSchema), pin)
}
