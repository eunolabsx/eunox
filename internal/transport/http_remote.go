// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Remote HTTP upstream support for the MCP proxy (--upstream-url): each client session
// forwards to a remote MCP HTTP server instead of a local subprocess, still through the
// full PDP enforcement stack.
//
// Limitations: SSE notifications pushed by the remote server are not forwarded to the
// client (the GET /mcp stream only emits proxy-originated events like kill-switch).
// Server-initiated requests (sampling/createMessage, roots/list, elicitation/create) are
// not serviced — this path is strict request/response with no inbound channel to deliver
// one, so that opt-in is rejected at startup for an HTTP upstream (route.go). Use stdio if
// server-initiated requests must be enforced.

package transport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/eunolabs/eunox/internal/mcp"
	"github.com/eunolabs/eunox/internal/pdp"
	"github.com/eunolabs/eunox/pkg/capability"
)

// scrubURLError redacts the credentialed URL carried by a *url.Error before it is surfaced.
// The stdlib's own formatting strips only the userinfo PASSWORD, leaving the username and
// query string (a ?api_key=/?token= credential) in the message — which reaches the
// live-probe's stderr and the doctor support bundle. Preserves the wrapped cause so
// errors.Is/As still match. A non-URL error is returned unchanged.
func scrubURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return &url.Error{Op: ue.Op, URL: capability.RedactURLForLog(ue.URL), Err: ue.Err}
	}
	return err
}

// upstreamSessionDeleteTimeout bounds the best-effort session-termination DELETE
// sent to a remote upstream on close. It runs during teardown, so it must be short
// enough not to stall a graceful stop on an unresponsive upstream.
const upstreamSessionDeleteTimeout = 5 * time.Second

// DeleteMCPHTTPSession sends a best-effort, bounded MCP session-termination DELETE so the
// remote frees the session's server-side state instead of leaking it. A blank sessID is a
// no-op. Uses a fresh background context since it runs from teardown paths whose own
// context is typically being canceled; failures are logged, not returned, so teardown never
// blocks.
func DeleteMCPHTTPSession(client *http.Client, endpoint, sessID, authHeaderLine string) {
	if sessID == "" || client == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), upstreamSessionDeleteTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, http.NoBody) //nolint:gosec // G107: endpoint is operator-configured (user-supplied URL or config file)
	if err != nil {
		return
	}
	req.Header.Set(SessionHeader, sessID)
	// A post-handshake request must carry the negotiated protocol version; without it a
	// spec-conformant upstream rejects the DELETE with 400 and leaks the session.
	req.Header.Set("MCP-Protocol-Version", MCPProtocolVersion)
	if name, value, ok := splitHeaderLine(authHeaderLine); ok {
		req.Header.Set(name, value)
	}
	resp, err := client.Do(req)
	if err != nil {
		// Scrub before logging: net/http's *url.Error strips only the password, not the
		// username/query-string credential (same leak class as scrubURLError elsewhere).
		fmt.Fprintf(os.Stderr, "[eunox] upstream session DELETE failed: %v\n", scrubURLError(err))
		return
	}
	_ = resp.Body.Close()
}

const (
	// maxUpstreamRespBytes bounds a remote upstream's JSON-RPC response body before
	// decoding so a hostile upstream cannot drive unbounded allocation. Matches the
	// 4 MiB per-message cap the subprocess transport enforces (jsonrpc.go).
	maxUpstreamRespBytes = 4 << 20
	// MaxUpstreamErrBodyBytes bounds how much of a non-2xx upstream body is read for
	// the operator-facing error/log. A diagnostic snippet, not the payload, so small.
	MaxUpstreamErrBodyBytes = 64 << 10
)

// buildUpstreamTransport builds the *http.Transport for a remote upstream. When
// tlsSkipVerify is true it accepts any TLS certificate (development only; callers warn).
// upstreamTimeoutMs is the resolved per-call timeout; pass <= 0 when disabled.
//
// Idle connections are bounded by IdleConnTimeout and MaxIdleConnsPerHost, so a single
// transport can be SHARED across a route's sessions (UpstreamRoute.sharedUpstreamTransport)
// without idle-conn accumulation under session churn, while still reusing warm connections.
func buildUpstreamTransport(tlsSkipVerify bool, upstreamTimeoutMs int) *http.Transport {
	// Clone the default transport only when it's still the stdlib *http.Transport; a bare
	// type assertion on a replaced (tracing wrapper, test spy) DefaultTransport would panic.
	var transport *http.Transport
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		transport = t.Clone()
	} else {
		transport = &http.Transport{
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			IdleConnTimeout:       90 * time.Second,
		}
	}
	// All of a route's sessions target the same host, so raise the per-host idle-conn cap
	// above the stdlib default of 2 for more reuse under concurrency (still bounded and
	// reaped by IdleConnTimeout).
	transport.MaxIdleConnsPerHost = 32
	// ResponseHeaderTimeout is a transport property, so it applies to every request
	// (foreground calls AND the session-start drift probe) on top of any per-call context
	// deadline. Floor it at sessionStartTimeout: a hardcoded value would undercut a larger
	// --upstream-timeout, while the floor keeps a tight per-call timeout from shortening the
	// drift probe's header wait. Foreground calls stay bounded by their own deadline, so
	// this is only a backstop; <= 0 leaves it unset.
	if upstreamTimeoutMs > 0 {
		rht := msToDuration(upstreamTimeoutMs)
		if rht < sessionStartTimeout {
			rht = sessionStartTimeout
		}
		transport.ResponseHeaderTimeout = rht
	}
	if tlsSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // G402: explicit dev flag; warning logged at startup
	}
	return transport
}

// newUpstreamClient wraps a (possibly shared) transport in an *http.Client with the
// redirect guard every remote-upstream call needs. The *http.Client is cheap and
// per-session; the *http.Transport (and its connection pool) is the part worth sharing.
func newUpstreamClient(transport *http.Transport) *http.Client {
	return &http.Client{
		Transport: transport,
		// Refuse redirects: an MCP JSON-RPC POST has none legitimately, and Go's client
		// only strips Authorization/Cookie cross-host — a custom upstreamAuthHeader would
		// otherwise be replayed to whatever host a compromised upstream names in a 30x.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// BuildUpstreamClient returns an HTTP client for the remote upstream with its own fresh
// transport. Used by the CLI live-upstream probe (a one-shot, so pooling across sessions
// does not apply); pass upstreamTimeoutMs <= 0 there since the probe is bounded by its
// own context. The proxy's per-session path shares a transport instead (newRemoteSession
// via UpstreamRoute.sharedUpstreamTransport).
func BuildUpstreamClient(tlsSkipVerify bool, upstreamTimeoutMs int) *http.Client {
	return newUpstreamClient(buildUpstreamTransport(tlsSkipVerify, upstreamTimeoutMs))
}

// UpstreamMCPEndpoint returns the full MCP endpoint URL for a remote upstream base URL:
// the base with any trailing slash trimmed plus the "/mcp" path the proxy forwards to.
// Single-sourced (and exported for the CLI live-upstream probe) so the runtime forward
// target, the stdio remote bridge, and the probe cannot drift on the /mcp convention.
func UpstreamMCPEndpoint(baseURL string) string {
	return strings.TrimRight(baseURL, "/") + "/mcp"
}

// mcpEndpointURL returns the full URL of the remote MCP endpoint for this
// session's route. The proxy appends /mcp to the configured base URL.
func (s *httpSession) mcpEndpointURL() string {
	return UpstreamMCPEndpoint(s.route.upstreamURL)
}

// newRemoteSession creates a client session backed by the configured remote HTTP upstream:
// performs the initialize handshake, stores the upstream session ID, registers in p.sessions.
// startGen is the reap generation the CALLER observed before its pre-spawn kill gate (see
// handleMCPPost and newSession).
func (p *HTTPProxy) newRemoteSession(ctx context.Context, route *UpstreamRoute, clientIP string, startGen uint64) (*httpSession, error) {
	// Share the route's *http.Transport (connection pool) across sessions so a
	// session-creating initialize reuses a warm connection; the *http.Client is per-session.
	client := newUpstreamClient(route.sharedUpstreamTransport(p.upstreamTimeMs))

	// Descends from Background, NOT the request ctx that created the session: that ctx ends
	// when initialize returns, which must not cancel later per-call teardown.
	sessCtx, sessCancel := context.WithCancel(context.Background())
	sess := &httpSession{
		id:    uuid.New().String(),
		proxy: p,
		route: route,
		// byUpstreamID and hostToUp are left nil: they never apply on the remote-HTTP
		// path, which is plain request/response through doRemoteHTTP.
		done:         make(chan struct{}),
		evicted:      make(chan struct{}),
		sessCtx:      sessCtx,
		sessCancel:   sessCancel,
		upHTTPClient: client,
		claims:       pdp.JWTClaimsPtr(ctx),
		clientIP:     clientIP,
	}
	// Marks initializing until this returns (after the drift check) so the idle reaper
	// doesn't tear it down mid-establishment — same guard as local-subprocess newSession.
	sess.initInProgress.Store(true)
	defer p.finishEstablishing(sess) //nolint:contextcheck // the establishment edge's kill check and any teardown it triggers are deliberately detached: this defer runs as the request context is finishing, and binding the reclaim to it would cancel the teardown the moment the handler returns — the same rationale as the other reap sites.

	if err := sess.initRemoteUpstream(ctx); err != nil {
		// A partial initialize may already have captured the upstream session ID, so
		// close so the bounded DELETE terminates it instead of leaking it.
		sess.close(p.shutdownMs) //nolint:contextcheck // teardown path: the upstream session-termination DELETE intentionally uses a detached, bounded background context — close/reaper/signal/shutdown carry no request context.
		return nil, fmt.Errorf("upstream initialize: %w", err)
	}

	// Register before starting any goroutine that might close the session: a fast close
	// otherwise fires the cleanup goroutine before the entry exists, leaking the dead
	// session into the map (same ordering invariant as newSession).
	if err := p.registerSession(sess, startGen); err != nil {
		sess.close(p.shutdownMs) //nolint:contextcheck // teardown path: the upstream session-termination DELETE intentionally uses a detached, bounded background context — close/reaper/signal/shutdown carry no request context.
		return nil, err
	}

	// Cleanup goroutine: remove the session once done is closed.
	go func() { //nolint:contextcheck // teardown path: releaseSessionState uses a detached, bounded context by design (the session is gone; no request context).
		<-sess.done
		p.mu.Lock()
		delete(p.sessions, sess.id)
		p.mu.Unlock()
		releaseSessionState(sess)
		fmt.Fprintf(p.errOut(), "[eunox] HTTP session %s ended.\n", sess.id)
	}()

	// Always synchronous so FM-5 aborts before the session is returned; --strict-drift
	// additionally gates FM-1/2/4. On failure delete synchronously so the failed session
	// stops counting against maxSessions immediately; the goroutine's later delete is a no-op.
	if err := p.runDriftCheckOrTeardown(ctx, sess, route); err != nil {
		return nil, err
	}

	// Re-stamp the activity clocks now that establishment is complete, so idle is measured
	// from readiness, not from registration (which ran before the handshake/drift probe).
	sess.touchRequest()

	fmt.Fprintf(p.errOut(), "[eunox] HTTP session %s started (remote: %s).\n", sess.id, capability.RedactURLForLog(route.upstreamURL))
	return sess, nil
}

// initRemoteUpstream performs the MCP initialize handshake with the remote upstream:
// sends initialize, captures the upstream Mcp-Session-Id, stores the server capabilities,
// then sends notifications/initialized.
func (s *httpSession) initRemoteUpstream(ctx context.Context) error {
	s.idCounter++
	initReq, _ := buildInitializeRequest(s.idCounter)

	respMsg, respHdr, err := s.doRemoteHTTP(ctx, initReq, "")
	// Capture the session ID the instant headers arrive, BEFORE any gate: a non-2xx, a
	// 202 to a request, an empty 200 body, or an SSE stream with no matching event all
	// return headers alongside an error, and the upstream may already have ALLOCATED a
	// session on such a response — close() must be able to DELETE it on every failure
	// path below. A true transport error returns a nil header, so the guard skips it.
	if respHdr != nil {
		s.upstreamSessID = respHdr.Get(SessionHeader)
	}
	if err != nil {
		return fmt.Errorf("sending initialize: %w", err)
	}
	// Correlate by shape via the shared rule (same as callRemoteUpstream and the stdio
	// bridge): a wrong-id reply is refused even as an error, since re-stamping it would let
	// an adversarial upstream inject one caller's error into this handshake.
	respMsg, err = correlateUpstreamReply(initReq, respMsg)
	if err != nil {
		return fmt.Errorf("upstream initialize: %w", err)
	}

	caps, sv, instructions, err := applyInitializeResult(respMsg)
	if err != nil {
		return err
	}
	s.upstreamCaps, s.upstreamServerVersion, s.upstreamInstructions = caps, sv, instructions

	notif, _ := mcp.NotificationMsg(mcp.MethodNotificationsInitialized, nil)
	_, _, err = s.doRemoteHTTP(ctx, notif, s.upstreamSessID)
	return err
}

// callRemoteUpstream forwards msg to the remote upstream and returns the response, bounded
// by --upstream-timeout and by the session's teardown. Notifications (no ID) return an
// empty rpcMsg on success. The initialize handshake uses doRemoteHTTP directly (bounded by
// the session-start deadline), so it is not double-bounded here.
func (s *httpSession) callRemoteUpstream(ctx context.Context, msg mcp.RPCMsg) (mcp.RPCMsg, error) {
	ctx, cancel := s.withUpstreamTimeout(ctx)
	defer cancel()
	// Cancel this call if the session ends, so a stuck round-trip cannot outlive it —
	// essential under --upstream-timeout=0, where withUpstreamTimeout's cancel is a no-op
	// and close() only drops idle connections. context.AfterFunc on the session context
	// spawns no goroutine on the completed-call path (the deferred stop deregisters it).
	var teardownCancel context.CancelFunc
	ctx, teardownCancel = context.WithCancel(ctx)
	defer teardownCancel()
	//nolint:contextcheck // s.sessCtx is the deliberate SESSION-teardown dimension (canceled in close()), not the per-call request context — registering the AfterFunc on it is the whole point: cancel this call when the session ends, independent of the request context.
	stop := context.AfterFunc(s.sessCtx, teardownCancel)
	defer stop()
	resp, _, err := s.doRemoteHTTP(ctx, msg, s.upstreamSessID)
	if err != nil {
		return resp, err
	}
	// enforcedForwardCore later overwrites the id with the host's, masking a mismatch, so
	// a non-response or wrong-id reply must fail closed here rather than be forwarded.
	return correlateUpstreamReply(msg, resp)
}

// DoMCPHTTP marshals msg and POSTs it to endpoint, setting the session-id header when
// sessID is non-empty and parsing authHeaderLine as "Name: Value" for the auth header. A
// 202 Accepted is a valid no-body ack only for a notification; for a request it is a
// spec-violating empty answer and returns an error (fail closed). The single HTTP-upstream
// implementation, shared by the gateway's per-session path, the validation live-check, and
// the stdio host's HTTP bridge.
func DoMCPHTTP(ctx context.Context, client *http.Client, endpoint string, msg mcp.RPCMsg, sessID, authHeaderLine string) (mcp.RPCMsg, http.Header, error) {
	data, err := json.Marshal(msg)
	if err != nil {
		return mcp.RPCMsg{}, nil, fmt.Errorf("marshalling request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data)) //nolint:gosec // G107: endpoint is operator-configured (user-supplied URL or config file)
	if err != nil {
		// Scrub before surfacing: a url.Parse-fatal endpoint makes NewRequestWithContext
		// return a *url.Error whose URL is the raw, UNstripped input — password included,
		// unlike the client.Do path below — which would otherwise leak to stderr/the doctor bundle.
		return mcp.RPCMsg{}, nil, fmt.Errorf("building request: %w", scrubURLError(err))
	}
	req.Header.Set("Content-Type", CTJSON)
	// The spec requires the client to advertise both JSON and SSE content types so the
	// server may answer either way.
	req.Header.Set("Accept", CTJSON+", "+ctSSE)
	// Every post-handshake request must carry the negotiated protocol version; the
	// initialize request precedes negotiation and must not.
	if msg.Method != mcp.MethodInitialize {
		req.Header.Set("MCP-Protocol-Version", MCPProtocolVersion)
	}
	if sessID != "" {
		req.Header.Set(SessionHeader, sessID)
	}
	if name, value, ok := splitHeaderLine(authHeaderLine); ok {
		req.Header.Set(name, value)
	}
	resp, err := client.Do(req) //nolint:gosec // G704: endpoint is the operator-configured upstream MCP URL (gateway config / CLI flag), not attacker-controlled input — reaching it is the proxy's purpose, not an SSRF (same rationale as the G107 suppression on the request build above)
	if err != nil {
		// net/http's *url.Error strips only the password, not username/query; scrub before surfacing.
		return mcp.RPCMsg{}, nil, fmt.Errorf("upstream HTTP: %w", scrubURLError(err))
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusAccepted {
		// A 202 with no body is a valid ack only for input expecting no response. For an
		// enforced REQUEST it would otherwise be returned as an empty RPCMsg with nil error
		// and recorded as an allow, so fail closed. Gating on IsRequest (not id != nil) keeps
		// a 202-ack to a forwarded response (id, no method) valid.
		if msg.IsRequest() {
			return mcp.RPCMsg{}, resp.Header, fmt.Errorf("upstream returned 202 Accepted with no body to a request expecting a response; the MCP Streamable HTTP spec requires a 200 with a JSON-RPC result or error")
		}
		return mcp.RPCMsg{}, resp.Header, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, MaxUpstreamErrBodyBytes))
		return mcp.RPCMsg{}, resp.Header, fmt.Errorf("upstream returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	// A 200 OK may carry a JSON or SSE body; for SSE, extract the matching JSON-RPC payload.
	// A lenient upstream may answer a notification with an empty body/no matching event
	// instead of the spec's 202 — treat that as a valid ack too, symmetric to the 202
	// handling above. A genuine REQUEST still fails closed: it needs a result/error.
	body := io.LimitReader(resp.Body, maxUpstreamRespBytes)
	if isSSEContentType(resp.Header.Get("Content-Type")) {
		out, err := sseResponseForID(body, msg.ID)
		if err != nil {
			if !msg.IsRequest() {
				return mcp.RPCMsg{}, resp.Header, nil
			}
			return mcp.RPCMsg{}, resp.Header, fmt.Errorf("decoding upstream SSE response: %w", err)
		}
		return out, resp.Header, nil
	}
	raw, err := io.ReadAll(body)
	if err != nil {
		return mcp.RPCMsg{}, resp.Header, fmt.Errorf("reading upstream response: %w", err)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		if !msg.IsRequest() {
			return mcp.RPCMsg{}, resp.Header, nil
		}
		return mcp.RPCMsg{}, resp.Header, fmt.Errorf("upstream returned 200 OK with an empty body to a request expecting a response")
	}
	var out mcp.RPCMsg
	if err := json.Unmarshal(raw, &out); err != nil {
		return mcp.RPCMsg{}, resp.Header, fmt.Errorf("decoding upstream response: %w", err)
	}
	return out, resp.Header, nil
}

// isSSEContentType reports whether a Content-Type header value denotes an SSE
// event stream (ignoring any "; charset=..." parameters and surrounding space).
func isSSEContentType(contentType string) bool {
	mediaType := contentType
	if i := strings.IndexByte(mediaType, ';'); i >= 0 {
		mediaType = mediaType[:i]
	}
	return strings.EqualFold(strings.TrimSpace(mediaType), ctSSE)
}

// sseResponseForID reads an SSE event stream from r and returns the first event whose
// decoded JSON-RPC id matches wantID (a server may interleave unrelated messages ahead of
// the response). Each event's payload is the concatenation of its consecutive "data:"
// lines. Bounded by the maxUpstreamRespBytes LimitReader the caller wraps r in.
func sseResponseForID(r io.Reader, wantID *json.RawMessage) (mcp.RPCMsg, error) {
	// Strip a leading UTF-8 BOM: it would otherwise turn the first field into a "data:"
	// that strings.CutPrefix misses, losing a response in the first event.
	br := bufio.NewReaderSize(r, 64<<10)
	if bom, _ := br.Peek(3); len(bom) == 3 && bom[0] == 0xEF && bom[1] == 0xBB && bom[2] == 0xBF {
		_, _ = br.Discard(3)
	}
	scanner := bufio.NewScanner(br)
	// Allow a single SSE data line up to the upstream cap; bufio's default 64 KiB token
	// limit would reject a large-but-legitimate JSON-RPC payload.
	scanner.Buffer(make([]byte, 0, 64<<10), maxUpstreamRespBytes)
	// bufio.ScanLines doesn't treat a bare CR as a terminator, so a bare-CR upstream (WHATWG/
	// EventSource allows CR/LF/CRLF) would frame no events; use a splitter that honors all three.
	scanner.Split(scanSSELines)
	want := mcp.MsgKey(wantID)
	var data []byte
	sawData := false

	// decodeEvent parses the accumulated payload and reports whether it is the
	// response for wantID. Undecodable or non-matching events are skipped.
	decodeEvent := func() (mcp.RPCMsg, bool) {
		if !sawData {
			return mcp.RPCMsg{}, false
		}
		var out mcp.RPCMsg
		if err := json.Unmarshal(data, &out); err != nil {
			return mcp.RPCMsg{}, false
		}
		// An id-less event keys to "" — the same key a nil wantID produces — so without
		// this explicit guard a forwarded notification would match the first interleaved one.
		if out.ID == nil || mcp.MsgKey(out.ID) != want {
			return mcp.RPCMsg{}, false
		}
		return out, true
	}

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			// Blank line terminates the event.
			if out, matched := decodeEvent(); matched {
				return out, nil
			}
			data = data[:0]
			sawData = false
			continue
		}
		value, ok := strings.CutPrefix(line, "data:")
		if !ok {
			// Comment lines (":..."), "event:", "id:", etc. are not payload.
			continue
		}
		// A single leading space after the colon is part of the framing, not data.
		value = strings.TrimPrefix(value, " ")
		if sawData {
			data = append(data, '\n')
		}
		data = append(data, value...)
		sawData = true
	}
	if err := scanner.Err(); err != nil {
		return mcp.RPCMsg{}, err
	}
	// Stream ended without a trailing blank line; try the final accumulated event.
	if out, matched := decodeEvent(); matched {
		return out, nil
	}
	return mcp.RPCMsg{}, fmt.Errorf("no SSE event matched request id %s", want)
}

// scanSSELines is a bufio.SplitFunc that splits an SSE byte stream on CR, LF, or
// CRLF (WHATWG/EventSource), returning each line without its terminator. Unlike
// bufio.ScanLines it treats a bare CR as a terminator.
func scanSSELines(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	for i := 0; i < len(data); i++ {
		switch data[i] {
		case '\n':
			return i + 1, data[:i], nil
		case '\r':
			if i+1 < len(data) {
				if data[i+1] == '\n' {
					return i + 2, data[:i], nil // CRLF
				}
				return i + 1, data[:i], nil // bare CR
			}
			// CR at buffer end: ask for more so a CRLF pair isn't split across reads
			// (which would emit a spurious empty line). At EOF the CR is the terminator.
			if atEOF {
				return i + 1, data[:i], nil
			}
			return 0, nil, nil // request more data
		}
	}
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil // request more data
}

// doRemoteHTTP marshals msg and POSTs it to the upstream MCP endpoint,
// setting the given session ID header (empty string omits the header).
// It returns the decoded JSON-RPC response and the response headers.
func (s *httpSession) doRemoteHTTP(ctx context.Context, msg mcp.RPCMsg, sessID string) (mcp.RPCMsg, http.Header, error) {
	return DoMCPHTTP(ctx, s.upHTTPClient, s.mcpEndpointURL(), msg, sessID, s.route.upstreamAuthHeader)
}
