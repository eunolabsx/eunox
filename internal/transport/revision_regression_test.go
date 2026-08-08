// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/eunolabs/eunox/internal/audit"
	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// TestUnmappedDenial_NamesNoPolicyTargetWhenTheMethodResolvesOne is the regression for the
// record shape revision-scoped removal newly made reachable.
//
// Until routing was revision-scoped, only methods with NO target type could reach the
// fail-closed default, so the record's target stayed empty. resources/subscribe can reach it
// now and DOES resolve a target type — recording the method as the identifier would stamp a
// resource literally named "resources/subscribe" onto the signed tape, and AUTHORIZATION_FAILED
// is a genuine policy code, so `eunox suggest` would mine a capability for it.
//
// The rule is keyed on RESOLVING A TARGET TYPE, not on removal: removal is how the first case
// became reachable, not what makes the identifier a fabrication. See the notification-framed
// sibling for the same fabrication reached with no removal in sight.
func TestUnmappedDenial_NamesNoPolicyTargetWhenTheMethodResolvesOne(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name           string
		method         string
		rev            capability.Revision
		wantIdentifier string
	}{
		{
			name: "a method the revision removed names no target", method: capability.MethodResourcesSubscribe,
			rev: capability.Revision20260728, wantIdentifier: "",
		},
		{
			// A genuinely unknown method resolves no target type either way, so the identifier
			// stays: it is the only place the method name survives for an operator.
			name: "an unknown method keeps naming itself", method: "agents/delegate",
			rev: capability.Revision20260728, wantIdentifier: "agents/delegate",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := &fwdRecorder{}
			d := dispatchParams{
				forwardParams: forwardParams{rec: rec, errOut: io.Discard},
				pdp:           pdp.AlwaysAllowPDP{},
			}
			dispatchUnmapped(revisionContext(tc.rev), d, mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: tc.method})
			if len(rec.records) != 1 {
				t.Fatalf("records = %+v, want exactly one", rec.records)
			}
			if rec.records[0].identifier != tc.wantIdentifier {
				t.Errorf("identifier = %q, want %q", rec.records[0].identifier, tc.wantIdentifier)
			}
		})
	}
}

// TestUnmappedNotificationDenial_NamesNoPolicyTargetWhenTheMethodResolvesOne is the same
// property on the notification-framed path, which has its own recorder call and would otherwise
// keep fabricating the target the request-framed twin no longer does.
//
// The second case is why the rule is not keyed on removal: tools/list is present in BOTH
// revisions and answered locally, so nothing about it was ever removed — its notification
// framing simply has no disposition and falls to the same fail-closed default, while the method
// still resolves a target type. Keyed on removal, that identifier survived and stamped a tool
// literally named "tools/list" onto the signed tape.
func TestUnmappedNotificationDenial_NamesNoPolicyTargetWhenTheMethodResolvesOne(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		method string
		rev    capability.Revision
	}{
		{"a method the revision removed", capability.MethodResourcesSubscribe, capability.Revision20260728},
		{"a method present in the revision but not in this framing", capability.MethodToolsList, capability.Revision20251125},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := &fwdRecorder{}
			gate := hostNotificationGate{rec: staticRecorder(rec), subject: verifiedSession("sess"), established: true, errOut: io.Discard, checkKill: noKill, leg: legStdioNotification}
			if gate.admit(revisionContext(tc.rev), mcp.RPCMsg{JSONRPC: "2.0", Method: tc.method}) == notificationForward {
				t.Fatalf("%s must be denied in notification framing", tc.method)
			}
			if len(rec.records) != 1 || rec.records[0].identifier != "" {
				t.Fatalf("records = %+v, want one record naming no policy target", rec.records)
			}
		})
	}
}

// TestStdioNegotiation_PinsOnlyFromAMessageTheRevisionDispatches is the regression for a
// connection that could be wedged for the process's lifetime by one stray line.
//
// The stdio context pins from its first RESOLVED message, which is what makes the flip refusal
// reachable for a peer that never handshakes. An id-less `initialize` is a notification by
// IsNotification's structural classification and resolves like any other message — so a single
// one declaring the revision that REMOVED `initialize` latched that revision, and the host's
// real handshake was then denied under a table with no `initialize` in it. Re-declaring the
// older revision was refused as a mid-context flip; omitting the declaration inherited the pin.
// There was no way to renegotiate.
//
// The stray notification is still dropped by the fail-closed default, and still recorded — what
// changes is that it no longer speaks for the connection.
func TestStdioNegotiation_PinsOnlyFromAMessageTheRevisionDispatches(t *testing.T) {
	t.Parallel()
	// The stray line, then the host's real handshake declaring nothing at all.
	p, hw := serveHostLines(t, stdioServe{pdp: newTestManifestPDP(capability.Constraint{Target: "tool:*", Actions: []string{"call"}})},
		`{"jsonrpc":"2.0","method":"initialize","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
	)

	if len(hw.messages) != 1 {
		t.Fatalf("host received %d message(s), want exactly the handshake reply: %+v", len(hw.messages), hw.messages)
	}
	if resp := hw.messages[0]; resp.Error != nil || resp.Result == nil {
		t.Fatalf("the handshake was refused (%+v); one stray notification must not decide which revision this connection speaks", resp.Error)
	}
	if got := p.hostRevision(); got != handshakeRevision {
		t.Errorf("pinned revision = %q, want %q — the pin belongs to the message that actually negotiated", got, handshakeRevision)
	}
}

// TestStdioNegotiation_StillPinsFromADispatchedMethod is the other half: the wedge fix must not
// cost the property the pin exists for. A peer that never sends `initialize` still latches its
// revision from its first ordinary message, so a later declaration disagreeing with it is
// refused as the mid-context flip it is.
//
// The peer declares the HANDSHAKE revision, which is the only one a live upstream leg can
// dispatch: eunox addresses every leg it opens as that revision, and every method 2026-07-28
// currently declares forwards its params, so a declaration of the newer one is refused by
// checkUpstreamHonorable one gate before the pin is even consulted (see its doc — that is
// incidental, not something the pin relies on). A fixture that pinned 2026-07-28 would only
// reach the pin by leaving the leg revision unset — a state Start never produces.
func TestStdioNegotiation_StillPinsFromADispatchedMethod(t *testing.T) {
	t.Parallel()
	// ping is answered locally and exists in the declared revision, so it both pins and is
	// dispatched — unlike the `initialize` above, which the revision IT declared had removed.
	p, hw := serveHostLines(t, stdioServe{pdp: newTestManifestPDP()},
		`{"jsonrpc":"2.0","id":1,"method":"ping","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-11-25"}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"ping","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`,
	)

	if got := p.hostRevision(); got != handshakeRevision {
		t.Fatalf("pinned revision = %q, want %q from the first message the revision defines", got, handshakeRevision)
	}
	if len(hw.messages) != 2 {
		t.Fatalf("host received %d message(s), want two: %+v", len(hw.messages), hw.messages)
	}
	// Order-independent: the flip is refused inline by the read loop while the first message's
	// own reply is written by its handler goroutine, so either may land first.
	flipped := false
	for _, m := range hw.messages {
		if m.Error != nil && m.Error.Code == capability.JSONRPCCodeUnsupportedProtocolVersion {
			flipped = true
		}
	}
	if !flipped {
		t.Errorf("no -32022 among %+v; the second declaration disagrees with the pinned context and must be refused as a mid-context flip", hw.messages)
	}
}

// TestStdioNegotiation_DoesNotPinFromAMessageTheFramingDiscards is the wedge CLASS, not the one
// instance of it. Pinning from "the revision has this method" closed the id-less `initialize`
// and left the shape open: revision membership is declared per METHOD, so a REQUEST-framed
// `notifications/progress` names a method both revisions have, satisfies that predicate, pins
// the connection — and is then dropped by dispatchUnmapped, which is a message the fail-closed
// default discards deciding what the peer speaks.
//
// Driven through the real serve loop at the handshake revision, which is the framing/revision
// pair a live upstream leg actually admits. The message is still denied; what must not happen
// is the latch.
func TestStdioNegotiation_DoesNotPinFromAMessageTheFramingDiscards(t *testing.T) {
	t.Parallel()
	p, hw := serveHostLines(t, stdioServe{},
		`{"jsonrpc":"2.0","id":1,"method":"notifications/progress","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-11-25"}}}`,
	)

	if len(hw.messages) != 1 || hw.messages[0].Error == nil {
		t.Fatalf("host received %+v, want the fail-closed refusal: a notification-only method has no request handler in either revision", hw.messages)
	}
	if got := p.hostRevision(); got != "" {
		t.Errorf("pinned revision = %q, want unpinned — the proxy discarded this message, so it is no evidence about which revision the conversation is on", got)
	}
}

// TestDispatchesMessage_AgreesWithTheDispatchTables pins WHICH SOURCE the predicate reads: the
// revision's derived tables, in the message's framing, across every published revision, every
// declared method and both framings.
//
// Deliberately not billed as proving the predicate and the dispatcher agree — its expectation
// is computed from the same tablesFor result the predicate reads, so a rewrite of
// dispatchesMessage is the only thing it can fail. What it does catch is the tempting
// "simplification" to a methodRegistry + spec.In membership test, which reports true for a
// revision this build does not speak while buildRevisionDispatch gives it empty tables — a pin
// onto a revision that dispatches nothing. The behavioral regression for the wedge itself is
// its hardcoded sibling below, and the guard that actually compares the predicate against the
// dispatcher's OBSERVED behavior is TestDispatchesMessage_MatchesWhatTheDispatcherActuallyDoes.
func TestDispatchesMessage_AgreesWithTheDispatchTables(t *testing.T) {
	t.Parallel()
	for _, rev := range capability.PublishedRevisions() {
		tables := tablesFor(rev)
		for method := range methodRegistry {
			_, decided := tables.decide[method]
			_, local := tables.local[method]
			_, notified := tables.notifications[method]

			request := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: method}
			if got := dispatchesMessage(rev, request); got != (decided || local) {
				t.Errorf("%s %s (request framing): dispatchesMessage = %v, tables hold a handler = %v", rev, method, got, decided || local)
			}
			notification := mcp.RPCMsg{JSONRPC: "2.0", Method: method}
			if got := dispatchesMessage(rev, notification); got != notified {
				t.Errorf("%s %s (notification framing): dispatchesMessage = %v, tables hold a disposition = %v", rev, method, got, notified)
			}
		}
		// A response carries no method and is dispatched by neither table, so it can never pin.
		if dispatchesMessage(rev, mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Result: json.RawMessage(`{}`)}) {
			t.Errorf("%s: a response must not pin a context; the proxy routes it to a waiting upstream, it does not dispatch it", rev)
		}
		// And an unknown method, in either framing.
		if dispatchesMessage(rev, mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "agents/delegate"}) ||
			dispatchesMessage(rev, mcp.RPCMsg{JSONRPC: "2.0", Method: "agents/delegate"}) {
			t.Errorf("%s: an unmapped method must not pin a context", rev)
		}
	}
}

// TestDispatchesMessage_MatchesWhatTheDispatcherActuallyDoes is the STRUCTURAL half its
// derived sibling above cannot be: it never consults the tables. Each message is driven through
// the real dispatcher (dispatchRequest) or the real notification gate (hostNotificationGate.admit),
// and the predicate is compared against what those two OBSERVABLY did with it.
//
// That is the property the pin depends on and the one nothing enforced: the sibling computes its
// expectation from the same tablesFor result the predicate reads, so only a rewrite of
// dispatchesMessage can fail it. A third dispatch table, a new fallback in dispatchRequest, or a
// disposition the gate starts acting on would reopen the wedge class with that test still green —
// a message the proxy acts on but does not pin, or the reverse, which is a connection latched onto
// a revision decided by a message the fail-closed default threw away.
//
// "The proxy acted on it" is read from each path's own fail-closed exit: dispatchUnmapped's
// SECURITY line for the request framing (its AUTHORIZATION_FAILED reply is indistinguishable from
// a policy deny, the line is not), and the gate's own three-valued outcome for the notification
// framing, where anything but a refusal means it was disposed of by a table entry.
func TestDispatchesMessage_MatchesWhatTheDispatcherActuallyDoes(t *testing.T) {
	t.Parallel()
	// Every declared method plus a method no revision has, in both framings.
	methods := append(slices.Sorted(maps.Keys(methodRegistry)), "agents/delegate")
	for _, rev := range capability.PublishedRevisions() {
		for _, method := range methods {
			t.Run(string(rev)+"/"+method, func(t *testing.T) {
				t.Parallel()
				ctx := revisionContext(rev)

				request := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: method}
				var errOut bytes.Buffer
				dispatchRequest(ctx, dispatcherProbeParams(&errOut), request)
				dispatched := !strings.Contains(errOut.String(), "unmapped MCP method")
				if got := dispatchesMessage(rev, request); got != dispatched {
					t.Errorf("request framing: dispatchesMessage = %v, but the dispatcher %s",
						got, actedOrDropped(dispatched))
				}

				notification := mcp.RPCMsg{JSONRPC: "2.0", Method: method}
				gate := hostNotificationGate{
					rec: staticRecorder(&fwdRecorder{}), subject: verifiedSession("sess"),
					established: true, errOut: io.Discard, checkKill: noKill, leg: legStdioNotification,
				}
				admitted := gate.admit(ctx, notification) != notificationRefused
				if got := dispatchesMessage(rev, notification); got != admitted {
					t.Errorf("notification framing: dispatchesMessage = %v, but the gate %s",
						got, actedOrDropped(admitted))
				}
			})
		}
	}
}

// actedOrDropped renders the dispatcher's observed disposition for the mismatch messages above.
func actedOrDropped(acted bool) string {
	if acted {
		return "acted on it (so a pin from it is evidence about the conversation's revision)"
	}
	return "dropped it through the fail-closed default (so pinning from it would latch on a discarded message)"
}

// dispatcherProbeParams builds the minimum wiring every dispatched handler needs, so the probe
// above reaches each one rather than nil-panicking short of the comparison it exists to make.
// AlwaysAllowPDP and a canned upstream keep policy and the network out of the answer: what is
// being observed is which ROUTE the message took, not what any handler decided.
func dispatcherProbeParams(errOut io.Writer) dispatchParams {
	return dispatchParams{
		forwardParams: forwardParams{
			errOut: errOut,
			callUpstream: func(_ context.Context, msg mcp.RPCMsg) (mcp.RPCMsg, error) {
				return mcp.RPCMsg{JSONRPC: "2.0", ID: msg.ID, Result: json.RawMessage(`{}`)}, nil
			},
		},
		pdp: pdp.AlwaysAllowPDP{},
		buildInit: func(msg mcp.RPCMsg) mcp.RPCMsg {
			return mcp.RPCMsg{JSONRPC: "2.0", ID: msg.ID, Result: json.RawMessage(`{}`)}
		},
	}
}

// TestDispatchesMessage_RejectsTheRequestFramedNotification names the cell the per-method
// predicate got wrong, in both revisions, so a future predicate that answers per METHOD again
// fails here rather than in a wedged connection.
func TestDispatchesMessage_RejectsTheRequestFramedNotification(t *testing.T) {
	t.Parallel()
	for _, rev := range []capability.Revision{capability.Revision20251125, capability.Revision20260728} {
		request := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: methodNotificationsProgress}
		if dispatchesMessage(rev, request) {
			t.Errorf("%s: a request-framed %s must not pin — %s has no request handler in any revision, so the message is about to be discarded",
				rev, methodNotificationsProgress, methodNotificationsProgress)
		}
		// The same method in its own framing IS acted on, so it does pin: the predicate is about
		// the framing, not about the method being second-class.
		if !dispatchesMessage(rev, mcp.RPCMsg{JSONRPC: "2.0", Method: methodNotificationsProgress}) {
			t.Errorf("%s: %s in notification framing is forwarded, so it is evidence about the conversation's revision", rev, methodNotificationsProgress)
		}
	}
}

// TestHonorabilityGate_CoversTheHostResponseFraming is the regression for the one framing a
// method-keyed gate structurally could not see.
//
// A host RESPONSE carries no method, so the methodRegistry lookup missed and
// checkUpstreamHonorable was skipped — yet the serve loop writes that response to the upstream
// VERBATIM, `_meta` declaration included. So a peer answering an upstream-initiated
// sampling/createMessage before the context had pinned could declare the newer revision, have it
// resolved and honored, pin nothing (a response is dispatched by neither table), and have the
// declaration relayed into a leg eunox opened and addresses as the handshake revision — the
// manufactured mismatched pair errUnhonorableUpstreamRevision exists to refuse, reached through
// the framing whose bytes travel with no dispatch decision at all.
//
// The FIRST case is the one that matters and the one a framing-aware gate over a request-shaped
// READER still missed: a conforming response has no `params` at all — MCP puts a result's
// metadata in `result._meta` — so reading the declaration from params saw nothing while the
// bytes carrying it went upstream unread. The second is the non-conforming hybrid, whose params
// travel too because an RPCMsg re-marshals whatever it decoded.
func TestHonorabilityGate_CoversTheHostResponseFraming(t *testing.T) {
	t.Parallel()
	const declaration = `{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}`
	cases := []struct {
		name string
		line string
	}{
		{"declared where a conforming response carries _meta", `{"jsonrpc":"2.0","id":5,"result":{"_meta":` + declaration + `}}`},
		{"declared in a params member no conforming response has", `{"jsonrpc":"2.0","id":5,"params":{"_meta":` + declaration + `},"result":{}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			up := &blockingUpWriter{gate: make(chan struct{})}
			close(up.gate) // do not hold writes; the test asserts none happen
			sink, logPath := newTempAuditSink(t)

			// A reply to a server-initiated request the proxy had forwarded, declaring the
			// revision the upstream leg is NOT addressed as.
			p, _ := serveHostLines(t, stdioServe{
				sink:   sink,
				upSink: up,
				setup:  func(p *StdioProxy) { p.serverReqs.track(mcp.MsgKey(mcp.RawJSON(`5`)), io.Discard) },
			}, tc.line)
			_ = sink.Close()

			if got := up.messages(); len(got) != 0 {
				t.Errorf("the response reached the upstream carrying a revision declaration the leg is not addressed as; got %+v", got)
			}
			if got := p.hostRevision(); got != "" {
				t.Errorf("pinned revision = %q, want unpinned — a response is dispatched by neither table", got)
			}
			rec := findAuditRecordByMethod(readAuditRecords(t, logPath), methodLabelServerResponse, "deny")
			if rec == nil {
				t.Fatal("the refused response left no record; a refusal the tape does not carry is the blind spot the framing guards exist to close")
			}
			if code, _ := rec["denial_code"].(string); code != capability.ErrCodeUnsupportedProtocolVersion {
				t.Errorf("denial_code = %q, want %q", code, capability.ErrCodeUnsupportedProtocolVersion)
			}
		})
	}
}

// TestHonorabilityGate_RefusesAResponseDeclaringTwoRevisions pins the one shape reading two
// members introduces: a message declaring in both. Resolving either is a guess, and a peer that
// wants to state its revision has one place to do it.
func TestHonorabilityGate_RefusesAResponseDeclaringTwoRevisions(t *testing.T) {
	t.Parallel()
	msg := mcp.RPCMsg{
		JSONRPC: "2.0", ID: mcp.RawJSON(`5`),
		Params: json.RawMessage(`{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-11-25"}}`),
		Result: json.RawMessage(`{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}`),
	}
	_, err := resolveHostRevision("", handshakeRevision, msg)
	if !errors.Is(err, mcp.ErrConflictingRevision) {
		t.Errorf("err = %v, want a conflicting-declaration refusal", err)
	}
	// The refusal text is echoed to the peer, so it must stay on the allowlist rather than
	// collapsing to the opaque fallback.
	if reason := revisionRefusalReason(err); !strings.Contains(reason, "2026-07-28") {
		t.Errorf("refusal reason = %q, want the class and the declared revisions", reason)
	}
}

// TestServerInitiatedLeg_NamesTheRevisionAnUnpinnedContextIsRoutedBy is the regression for the
// second meaning an absent protocol_revision quietly acquired.
//
// Narrowing the pin to "the revision DISPATCHES this message" widened the set of connections
// where hostRevision() is empty: a message can RESOLVE a revision, be recorded under it, and
// still not pin, because the proxy discarded it. This leg read that emptiness as "nothing was
// ever negotiated" and wrote a record asserting so — on a session whose host-leg records already
// name a revision, which an operator correlating the two reads as different negotiation states.
//
// The leg now resolves the empty carrier exactly as requestRevision does, so both legs of one
// session name the surface it is actually routed by.
func TestServerInitiatedLeg_NamesTheRevisionAnUnpinnedContextIsRoutedBy(t *testing.T) {
	t.Parallel()
	sink, logPath := newTempAuditSink(t)
	// A request-framed notifications/progress: it RESOLVES the default revision and is recorded
	// under it, but no revision's tables hold a request handler for it, so it pins nothing.
	p, _ := serveHostLines(t, stdioServe{sink: sink},
		`{"jsonrpc":"2.0","id":1,"method":"notifications/progress","params":{}}`,
	)
	if got := p.hostRevision(); got != "" {
		t.Fatalf("pinned revision = %q, want unpinned — this test needs the connection the widened set created", got)
	}
	p.handleUpstreamRequest(context.Background(), mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`9`), Method: "roots/list"})
	_ = sink.Close()

	records := readAuditRecords(t, logPath)
	rec := findAuditRecordByMethod(records, "roots/list", "")
	if rec == nil {
		t.Fatalf("the server-initiated forward left no record; got %+v", records)
	}
	if got, _ := rec["protocol_revision"].(string); got != capability.DefaultRevision.String() {
		t.Errorf("protocol_revision = %q, want %q — an absent field claims nothing was ever negotiated, and this session's host-leg records name a revision",
			got, capability.DefaultRevision)
	}
}

// TestStdioNegotiation_PinIsWrittenOnce pins the guard in front of the pin as a measurement
// rather than as a comment. The pin cannot change once set — resolveHostRevision refuses a
// disagreeing declaration one gate earlier and returns before this — so both the predicate and
// the Store re-answer a settled question on every host message, and the Store boxes a
// string-kind value through runtime.convTstring each time.
//
// RELATIVE, not an absolute allocation count: the two messages below take the same path through
// negotiation (neither method forwards its params, so both skip checkUpstreamHonorable, and both
// carry the same params to decode) and differ only in whether the pin would be re-written. So
// the assertion survives an unrelated allocation appearing on the shared path, and still fails
// the moment the redundant Store comes back.
//
// Not parallel: AllocsPerRun panics inside one, and measures process-wide mallocs, so it must
// not run beside another test's goroutines.
func TestStdioNegotiation_PinIsWrittenOnce(t *testing.T) {
	p, _ := newStdioProxy(stdioServe{pdp: newTestManifestPDP()}, strings.NewReader(""))
	ctx := context.Background()
	// Both dispatch under the pinned revision's tables; only ping is a message the pin would be
	// taken from, so only it can re-Store.
	pins := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: methodPing}
	neverPins := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: "agents/delegate"}
	if _, ok := p.negotiateHostRevision(ctx, pins); !ok {
		t.Fatal("the pinning message was refused")
	}
	if got := p.hostRevision(); got != handshakeRevision {
		t.Fatalf("pinned revision = %q, want %q", got, handshakeRevision)
	}

	// Single-goroutine by contract (negotiateHostRevision runs on the reader), so repeating a
	// message here is exactly what the serve loop does with every later one.
	repin := testing.AllocsPerRun(200, func() { p.negotiateHostRevision(ctx, pins) })
	baseline := testing.AllocsPerRun(200, func() { p.negotiateHostRevision(ctx, neverPins) })
	if repin > baseline {
		t.Errorf("negotiating a pin-eligible message on an ALREADY pinned connection allocates %v against a baseline of %v; the pin is being re-Stored after the message that established it",
			repin, baseline)
	}
	if got := p.hostRevision(); got != handshakeRevision {
		t.Errorf("pinned revision = %q after further messages, want %q", got, handshakeRevision)
	}
}

// TestObserveMode_DoesNotDowngradeARoutingRefusal states the rule as behavior: observe mode
// downgrades a POLICY verdict, and a message no revision's tables can route has no verdict to
// downgrade.
//
// The three alternatives were weighed. Forwarding verbatim makes observe mode invent a route it
// has no entry for — the one thing a wiretap must not do, and the reason the fail-closed default
// exists. Recording and dropping is today's behavior under a different label. Downgrading only
// the -32022 refusal reads as the narrowest option and is the least defensible of the three,
// once its causes are taken one at a time: an unknown revision leaves nothing to route by, a
// declaration disagreeing with its context leaves two candidates and no basis to pick, and a
// resolution the upstream leg cannot honor is the one case where the revision IS known — and
// forwarding it is precisely the manufactured mismatched pair the refusal exists to prevent.
//
// What changes instead is that the refusal is LEGIBLE. Its code is AUTHORIZATION_FAILED, a
// genuine policy code, on a route where policy denied nothing — so a discovery run's tape read
// as the upstream's behavior. The marker says whose refusal it is, and which of the two ways it
// was unroutable.
func TestObserveMode_DoesNotDowngradeARoutingRefusal(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		method     string
		rev        capability.Revision
		wantReason string
	}{
		{
			// The wiretap-against-a-newer-host case: 2026-07-28 removed resources/subscribe.
			name: "a method the peer's revision removed", method: capability.MethodResourcesSubscribe,
			rev: capability.Revision20260728, wantReason: audit.UnroutableRemovedInRevision,
		},
		{
			name: "a method no revision declares", method: "agents/delegate",
			rev: capability.Revision20251125, wantReason: audit.UnroutableUnknownMethod,
		},
		{
			// In the peer's revision, but with no handler for the framing it arrived in.
			name: "a notification-only method sent as a request", method: methodNotificationsProgress,
			rev: capability.Revision20251125, wantReason: audit.UnroutableFramingUnmapped,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := &fwdRecorder{}
			// The wiretap posture exactly: no policy (AlwaysAllowPDP) and audit=true, so
			// nothing below could produce a policy denial to observe.
			d := dispatchParams{
				forwardParams: forwardParams{rec: rec, errOut: io.Discard, audit: true},
				pdp:           pdp.AlwaysAllowPDP{},
			}
			msg := mcp.RPCMsg{JSONRPC: "2.0", ID: mcp.RawJSON(`1`), Method: tc.method}
			resp := dispatchRequest(revisionContext(tc.rev), d, msg)

			if resp.Error == nil {
				t.Fatalf("audit mode forwarded a message it has no route for; response %+v", resp)
			}
			if len(rec.records) != 1 {
				t.Fatalf("records = %+v, want exactly one", rec.records)
			}
			got := rec.records[0]
			if got.auditOnly {
				t.Error("the refusal was recorded as an OBSERVED denial; there was no policy verdict to observe")
			}
			assertUnroutableDetail(t, got.details, tc.rev, tc.wantReason)
		})
	}
}

// TestObserveMode_MarksTheNotificationFramedRefusalToo is the same property on the arm with its
// own recorder call, which is where the identifier rule had to be hand-mirrored once already.
func TestObserveMode_MarksTheNotificationFramedRefusalToo(t *testing.T) {
	t.Parallel()
	rec := &fwdRecorder{}
	gate := hostNotificationGate{
		rec: staticRecorder(rec), subject: verifiedSession("sess"), established: true,
		errOut: io.Discard, checkKill: noKill, leg: legStdioNotification,
	}
	// ping exists in this revision and is answered locally; it has no notification disposition
	// at all, so its notification framing falls to the same fail-closed default.
	if out := gate.admit(revisionContext(capability.Revision20251125), mcp.RPCMsg{JSONRPC: "2.0", Method: methodPing}); out != notificationRefused {
		t.Fatalf("gate outcome = %v, want a refusal", out)
	}
	if len(rec.records) != 1 {
		t.Fatalf("records = %+v, want exactly one", rec.records)
	}
	assertUnroutableDetail(t, rec.records[0].details, capability.Revision20251125, audit.UnroutableFramingUnmapped)
}

// assertUnroutableDetail checks the routing-refusal marker's shape, since a SIEM rule matches
// its reason code rather than parsing prose.
func assertUnroutableDetail(t *testing.T, details map[string]interface{}, rev capability.Revision, wantReason string) {
	t.Helper()
	if !audit.IsReservedDetailKey(audit.UnroutableKey) {
		t.Errorf("key %q is not reserved, so `eunox suggest` would mine it as a tool argument", audit.UnroutableKey)
	}
	marker, ok := details[audit.UnroutableKey].(map[string]interface{})
	if !ok {
		t.Fatalf("details = %+v, want a %s marker naming this as eunox's own routing refusal rather than a policy verdict", details, audit.UnroutableKey)
	}
	if got, _ := marker["reason"].(string); got != wantReason {
		t.Errorf("reason = %q, want %q", got, wantReason)
	}
	if got, _ := marker["revision"].(string); got != rev.String() {
		t.Errorf("revision = %q, want %q — the marker must name the tables that were consulted", got, rev)
	}
}

// TestRevisionRefusal_NamesTheContextItWasRefusedOn pins the two halves of what a -32022 record
// may claim, both of which the fail-closed routing sibling already got right.
//
// The MESSAGE resolved no revision — that is why it is refused — but its CONTEXT may have one,
// and an absent protocol_revision is reserved for a record written before anything could be
// resolved. And the identifier follows the same no-policy-decision rule as every other refusal:
// tools/call resolves a target type, so naming it would stamp a tool that no policy matched.
func TestRevisionRefusal_NamesTheContextItWasRefusedOn(t *testing.T) {
	t.Parallel()
	sink, logPath := newTempAuditSink(t)
	// ping pins the context; the tools/call then declares a revision that disagrees with it.
	serveHostLines(t, stdioServe{pdp: newTestManifestPDP(), sink: sink},
		`{"jsonrpc":"2.0","id":1,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"x","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`,
	)
	_ = sink.Close()

	rec := findAuditRecordByMethod(readAuditRecords(t, logPath), capability.MethodToolsCall, "deny")
	if rec == nil {
		t.Fatal("the mid-context flip left no record")
	}
	if code, _ := rec["denial_code"].(string); code != capability.ErrCodeUnsupportedProtocolVersion {
		t.Fatalf("denial_code = %q, want %q", code, capability.ErrCodeUnsupportedProtocolVersion)
	}
	if got, _ := rec["protocol_revision"].(string); got != handshakeRevision.String() {
		t.Errorf("protocol_revision = %q, want %q — this session HAS a negotiated surface, and absence claims none was ever resolved", got, handshakeRevision)
	}
	if target, ok := rec["target"]; ok && target != "" {
		t.Errorf("target = %q, want none — no policy evaluated this message, so naming one fabricates it", target)
	}
}

// TestRevisionRefusal_IsClassedAsInfrastructure: the refusal names no policy target (nothing
// was ever matched), and a peer can drive it at will, so `eunox suggest` must skip it rather
// than mine a phantom capability out of caller-controlled method text.
func TestRevisionRefusal_IsClassedAsInfrastructure(t *testing.T) {
	t.Parallel()
	if !IsInfraDenialCode(capability.ErrCodeUnsupportedProtocolVersion) {
		t.Error("UNSUPPORTED_PROTOCOL_VERSION must be an infrastructure code; its own godoc says so, and suggest keys off this")
	}
}

// TestSetNegotiatedVersionHeader_AlwaysSignalsAVersion is the regression for suppressing the
// header on a leg pinned to a revision this build has no opener for.
//
// eunox opens every upstream leg with `initialize`, so the handshake revision is what was
// negotiated whatever the pin says. Omitting the header without emitting a replacement leaves
// the request with no version signal at all, which a conformant upstream answers with 400 —
// including the terminating DELETE, whose failure leaks the upstream session.
func TestSetNegotiatedVersionHeader_AlwaysSignalsAVersion(t *testing.T) {
	t.Parallel()
	for _, rev := range []capability.Revision{"", capability.Revision20251125, capability.Revision20260728, "1999-01-01"} {
		req := newTestRequestForHeader(t)
		setNegotiatedVersionHeader(req, rev)
		if got := req.Header.Get("MCP-Protocol-Version"); got != handshakeRevision.String() {
			t.Errorf("rev %q: MCP-Protocol-Version = %q, want %q — a post-handshake request must always carry the version the handshake negotiated", rev, got, handshakeRevision)
		}
	}
}

// newTestRequestForHeader builds a bare request to inspect header stamping on.
func newTestRequestForHeader(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://127.0.0.1/mcp", http.NoBody)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	return req
}
