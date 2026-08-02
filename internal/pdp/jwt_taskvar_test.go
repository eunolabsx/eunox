// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package pdp

import (
	"context"
	"testing"
	"time"

	"github.com/eunolabs/eunox/pkg/capability"
)

// taskVarCapPDP builds a JWT PDP and a token whose mcp.capabilities shorthand binds an
// argument to the token's own task id — the shape an issuer writes to say "this agent may
// fetch only ITS workspace", once, instead of minting a per-task claim.
func taskVarCapToken(t *testing.T, key testKey, taskID string, caps ...string) string {
	t.Helper()
	return signRawClaimsToken(t, key, "svc-research", time.Now().Add(time.Hour), map[string]interface{}{
		"mcp": map[string]interface{}{
			"v":            mcpClaimVersion,
			"task_id":      taskID,
			"capabilities": caps,
		},
	})
}

// TestJWTShorthand_ResolvesTaskVariable is the regression for a grant that silently
// covered nothing. The shared allowedValues matcher SKIPS a recognized "${task.*}" entry
// — it must, or an argument whose value is the placeholder TEXT would satisfy an identity
// binding by spelling it out — so resolution is the only thing that can ever match one.
// Resolution used to live outside the matcher, in a second call the manifest path made and
// the JWT shorthand path did not, so a token carrying
//
//	"capabilities": ["tool:fetch_workspace?workspace_id=${task.id}"]
//
// skipped its only allowed-value entry, matched nothing, and denied every call under the
// grant with VALUE_NOT_PERMITTED — fail-closed, and with no diagnostic naming the cause.
func TestJWTShorthand_ResolvesTaskVariable(t *testing.T) {
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()
	pdp := makeJWTPDP(t, srv, "", "", nil)

	token := taskVarCapToken(t, key, "task-42", "tool:fetch_workspace?workspace_id=${task.id}")
	ctx, err := pdp.ValidateToken(context.Background(), "Bearer "+token)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	target := EnforceTarget{Type: capability.TargetTypeTool, Name: "fetch_workspace"}

	// The caller's own task: the grant covers it.
	resp := pdp.Decide(ctx, "sess-1", target, map[string]interface{}{"workspace_id": "task-42"}, "127.0.0.1")
	if resp.Decision != capability.DecisionAllow {
		t.Fatalf("a grant bound to ${task.id} must admit the caller's own task id; got %s (%+v)", resp.Decision, resp.Denial)
	}

	// Another task: still denied. Resolving the reference must not turn the binding into
	// a wildcard — that is the whole point of the condition.
	resp = pdp.Decide(ctx, "sess-1", target, map[string]interface{}{"workspace_id": "task-99"}, "127.0.0.1")
	if resp.Decision != capability.DecisionDeny {
		t.Fatalf("a grant bound to ${task.id} must deny another task's id; got %s", resp.Decision)
	}

	// The literal placeholder never matches: an argument that spells the reference out
	// must not satisfy the identity binding.
	resp = pdp.Decide(ctx, "sess-1", target, map[string]interface{}{"workspace_id": "${task.id}"}, "127.0.0.1")
	if resp.Decision != capability.DecisionDeny {
		t.Fatalf("the placeholder text must never match itself; got %s", resp.Decision)
	}
}

// TestJWTShorthand_ResolvedTaskVariableIsNotAGlob pins the property that makes resolution
// safe on this path specifically: the resolved value is IdP-supplied text, compared by
// EXACT equality. Run through the allowedValues glob instead, a token whose task_id is "*"
// would be an allow-anything wildcard its own holder chose.
func TestJWTShorthand_ResolvedTaskVariableIsNotAGlob(t *testing.T) {
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()
	pdp := makeJWTPDP(t, srv, "", "", nil)

	token := taskVarCapToken(t, key, "*", "tool:fetch_workspace?workspace_id=${task.id}")
	ctx, err := pdp.ValidateToken(context.Background(), "Bearer "+token)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	resp := pdp.Decide(ctx, "sess-1",
		EnforceTarget{Type: capability.TargetTypeTool, Name: "fetch_workspace"},
		map[string]interface{}{"workspace_id": "someone-elses-workspace"}, "127.0.0.1")
	if resp.Decision != capability.DecisionDeny {
		t.Fatalf("a task_id of %q must not become a wildcard; got %s", "*", resp.Decision)
	}
}

// TestJWTShorthand_UnrecognizedReferenceStaysLiteral is the case the skip's narrowing to
// IsTaskVarRef was chosen for, and it must survive resolution moving into the matcher. A
// token's capability values never pass through the manifest loader, so "${STAGE}" there
// has no chance to be reported as a bad reference — it stays an ordinary literal and keeps
// matching itself, rather than voiding the grant with nothing to grep for.
func TestJWTShorthand_UnrecognizedReferenceStaysLiteral(t *testing.T) {
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()
	pdp := makeJWTPDP(t, srv, "", "", nil)

	token := taskVarCapToken(t, key, "task-42", "tool:deploy?stage=${STAGE}")
	ctx, err := pdp.ValidateToken(context.Background(), "Bearer "+token)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	target := EnforceTarget{Type: capability.TargetTypeTool, Name: "deploy"}

	resp := pdp.Decide(ctx, "sess-1", target, map[string]interface{}{"stage": "${STAGE}"}, "127.0.0.1")
	if resp.Decision != capability.DecisionAllow {
		t.Fatalf("an unrecognized reference must stay a literal and match itself; got %s (%+v)", resp.Decision, resp.Denial)
	}
	resp = pdp.Decide(ctx, "sess-1", target, map[string]interface{}{"stage": "prod"}, "127.0.0.1")
	if resp.Decision != capability.DecisionDeny {
		t.Fatalf("a literal must not match some other value; got %s", resp.Decision)
	}
}
