// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/eunolabs/eunox/pkg/capability"
)

// ErrParse marks a message that framed correctly but failed JSON parsing — recoverable,
// unlike io.EOF or scanner errors, which lose framing and are terminal.
var ErrParse = errors.New("mcp: malformed JSON-RPC message")

// RPCMsg is a JSON-RPC 2.0 message — a request, response, or notification depending on
// which fields are populated.
//
// ID is nil only for an absent "id" (a notification); an explicit `"id": null` is a
// non-nil RawMessage holding the literal `null`. See [RPCMsg.UnmarshalJSON].
type RPCMsg struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id,omitempty"` // nil only for notifications
	Method  string           `json:"method,omitempty"`
	Params  json.RawMessage  `json:"params,omitempty"`
	Result  json.RawMessage  `json:"result,omitempty"`
	Error   *RPCError        `json:"error,omitempty"`
}

// IsZero reports whether m is the zero message — the value a proxy layer hands back to mean "there
// is nothing to send at all", as distinct from a message it built badly.
//
// Every field is tested rather than JSONRPC alone: that field has no `omitempty`, so a zero message
// marshals to the malformed frame `{"jsonrpc":""}` and a writer must be able to tell it from a
// message a peer sent without a version. A caller that writes without asking puts that frame on the
// wire where nothing should have been sent.
func (m RPCMsg) IsZero() bool {
	return m.JSONRPC == "" && m.ID == nil && m.Method == "" &&
		m.Params == nil && m.Result == nil && m.Error == nil
}

// UnmarshalJSON decodes a JSON-RPC message while distinguishing an absent id (a
// notification) from an explicit `"id": null` (a valid identifier), which plain struct
// decoding would collapse to nil.
func (m *RPCMsg) UnmarshalJSON(b []byte) error {
	// alias drops UnmarshalJSON so this delegates to default struct decoding without
	// recursing, decoding id as a value json.RawMessage (zero-length ⟹ absent).
	type alias struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method,omitempty"`
		Params  json.RawMessage `json:"params,omitempty"`
		Result  json.RawMessage `json:"result,omitempty"`
		Error   *RPCError       `json:"error,omitempty"`
	}
	var a alias
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	*m = RPCMsg{
		JSONRPC: a.JSONRPC,
		Method:  a.Method,
		Params:  a.Params,
		Result:  a.Result,
		Error:   a.Error,
	}
	// Zero-length raw means "id" absent (notification); any present id, including
	// literal `null`, is kept non-nil.
	if len(a.ID) > 0 {
		id := a.ID
		m.ID = &id
	}
	return nil
}

// RPCError is the error object of a JSON-RPC 2.0 response.
type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// IsRequest reports whether msg is a JSON-RPC request (has id + method); a present-null
// id counts, since UnmarshalJSON keeps it non-nil.
func (m *RPCMsg) IsRequest() bool {
	return m.ID != nil && m.Method != ""
}

// IsNotification reports whether msg is a notification (id absent, has method); a
// present-null id is a request, not this.
func (m *RPCMsg) IsNotification() bool {
	return m.ID == nil && m.Method != ""
}

// IsResponse reports whether msg is a response (has id, no method); a present-null id
// counts here too.
func (m *RPCMsg) IsResponse() bool {
	return m.ID != nil && m.Method == ""
}

// MsgKey returns a stable string key for a message ID, canonicalized by JSON value and
// type (not raw bytes) so 5/5.0/5e0 share a key and a re-serialized id is not orphaned.
// A type prefix keeps a string id from colliding with a numeric or null one; absent
// keys to "".
func MsgKey(id *json.RawMessage) string {
	// maxNumericIDLen bounds big.Rat cost against a short exponent literal like
	// "1e1000000" (~1MB of math), while staying generous enough that legitimate
	// large ids still canonicalize. See numericIDExponentBounded.
	const maxNumericIDLen = 1024
	if id == nil {
		return ""
	}
	raw := bytes.TrimSpace(*id)
	if len(raw) == 0 {
		return ""
	}
	switch raw[0] {
	case '"':
		// String ID: json.Unmarshal silently collapses invalid UTF-8 and unpaired
		// surrogate escapes to U+FFFD, which could cross-correlate two distinct
		// malformed ids; stringIDIsWellFormed catches that before it's lost.
		var s string
		if err := json.Unmarshal(raw, &s); err == nil && stringIDIsWellFormed(raw) {
			return "s:" + s
		}
	case 'n':
		// null is a valid JSON-RPC ID; key it under its own type prefix.
		if string(raw) == "null" {
			return "z:null"
		}
	default:
		// Numeric ID: canonicalize (int64 or normalized big.Rat) so equal spellings
		// share a key. Fast path avoids allocation for the common plain-integer
		// case, since MsgKey runs 3-5x per proxied request.
		if i, ok := parseCanonicalJSONInt(raw); ok {
			return "n:" + strconv.FormatInt(i, 10)
		}
		// Slow path for floats/exponents/large integers. Bound the input before
		// big.Rat.SetString, which eagerly materializes 10^N for "1eN" — an
		// unbounded input is a DoS on the hot path.
		if len(raw) <= maxNumericIDLen && numericIDExponentBounded(raw) {
			var n json.Number
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.UseNumber()
			if err := dec.Decode(&n); err == nil && dec.Decode(new(json.RawMessage)) == io.EOF {
				if i, err := strconv.ParseInt(string(n), 10, 64); err == nil {
					return "n:" + strconv.FormatInt(i, 10)
				}
				if r, ok := new(big.Rat).SetString(string(n)); ok {
					return "n:" + r.RatString()
				}
			}
		}
	}
	// Unparseable or unexpected shape: fall back to the raw bytes under a
	// distinct prefix so a malformed ID cannot collide with a well-formed key.
	return "r:" + string(raw)
}

// stringIDIsWellFormed reports whether raw — a JSON string id's quoted text — decodes
// losslessly (valid UTF-8, properly paired surrogates), catching what json.Unmarshal
// silently maps to U+FFFD.
func stringIDIsWellFormed(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	for i := 0; i < len(raw); {
		if raw[i] == '\\' {
			// Only \uXXXX warrants a further look: it's the one escape that can
			// encode a surrogate half.
			if i+1 < len(raw) && raw[i+1] == 'u' {
				hi, _ := strconv.ParseUint(string(raw[i+2:i+6]), 16, 32)
				switch {
				case hi >= 0xD800 && hi <= 0xDBFF:
					// High surrogate: valid only when immediately followed by a \u low
					// surrogate, forming one code point together.
					if i+12 <= len(raw) && raw[i+6] == '\\' && raw[i+7] == 'u' {
						if lo, err := strconv.ParseUint(string(raw[i+8:i+12]), 16, 32); err == nil && lo >= 0xDC00 && lo <= 0xDFFF {
							i += 12
							continue
						}
					}
					return false // lone high surrogate
				case hi >= 0xDC00 && hi <= 0xDFFF:
					return false // lone low surrogate (a valid pair is consumed above)
				}
				i += 6
				continue
			}
			i += 2 // an ordinary one-char escape (\", \\, \/, \b, \f, \n, \r, \t)
			continue
		}
		_, size := utf8.DecodeRune(raw[i:])
		i += size
	}
	return true
}

// numericIDExponentBounded bounds the exponent so big.Rat.SetString won't materialize a
// huge 10^N value; delegates to pkg/capability's shared bound so this and
// pkg/enforcement's comparisons cannot drift.
func numericIDExponentBounded(raw []byte) bool {
	return capability.NumericLiteralBounded(string(raw))
}

// parseCanonicalJSONInt parses a canonical JSON integer (no leading zero, no
// "+5"/"05"/"-0"), returning false for anything else so the caller falls back to the
// slow path — never a second, divergent canonicalizer. The 18-digit cap keeps v*10 from
// overflowing int64.
func parseCanonicalJSONInt(raw []byte) (int64, bool) {
	d := raw
	neg := false
	if len(d) > 0 && d[0] == '-' {
		neg = true
		d = d[1:]
	}
	if len(d) == 0 || len(d) > 18 {
		return 0, false
	}
	if d[0] == '0' {
		// Only "0" is canonical; "-0" is valid JSON but declines here to let the
		// slow path fold it onto the same "n:0" key.
		if len(d) > 1 || neg {
			return 0, false
		}
		return 0, true
	}
	var v int64
	for _, c := range d {
		if c < '0' || c > '9' {
			return 0, false
		}
		v = v*10 + int64(c-'0')
	}
	if neg {
		v = -v
	}
	return v, true
}

// RawJSON returns a *json.RawMessage addressing a copy of s. s must already be valid
// JSON; nothing here validates or escapes it.
func RawJSON(s string) *json.RawMessage {
	r := json.RawMessage(s)
	return &r
}

// SuccessResponse builds a JSON-RPC 2.0 success response.
func SuccessResponse(id *json.RawMessage, result interface{}) (RPCMsg, error) {
	res, err := json.Marshal(result)
	if err != nil {
		return RPCMsg{}, err
	}
	return RPCMsg{
		JSONRPC: "2.0",
		ID:      id,
		Result:  res,
	}, nil
}

// ErrorResponse builds a JSON-RPC 2.0 error response.
func ErrorResponse(id *json.RawMessage, code int, message string) RPCMsg {
	return RPCMsg{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &RPCError{Code: code, Message: message},
	}
}

// MethodInitialize is the MCP handshake request that opens a session — transport-level,
// not an enforced method, but a single source of truth so a typo can't silently misroute
// it at any of the several sites that consult it.
const MethodInitialize = "initialize"

// MethodNotificationsInitialized is the notification a client sends after a successful
// initialize handshake — single source of truth for the spelling so a typo can't
// silently drop it and leave a strict upstream refusing subsequent requests.
const MethodNotificationsInitialized = "notifications/initialized"

// MethodServerDiscover is the 2026-07-28 discovery request, which replaces the handshake as
// the way a leg on that revision is opened: it carries no session and negotiates no version
// (the client declares one per request), so what it yields is the same server facts
// `initialize` returns rather than a negotiation.
//
// Beside MethodInitialize for the same reason: eunox opens legs with one or the other, and a
// typo in either would silently misroute an opener at the several sites that build one.
const MethodServerDiscover = "server/discover"

// NotificationMsg builds a JSON-RPC 2.0 notification (no id).
func NotificationMsg(method string, params interface{}) (RPCMsg, error) { //nolint:unparam // method is always MethodNotificationsInitialized today; kept generic for future use
	var p json.RawMessage
	if params != nil {
		var err error
		p, err = json.Marshal(params)
		if err != nil {
			return RPCMsg{}, err
		}
	}
	return RPCMsg{JSONRPC: "2.0", Method: method, Params: p}, nil
}

// DecodeParams unmarshals a request's params into v, preserving JSON numbers as
// json.Number rather than float64 — a float64 can't represent every int64, so a
// numeric constraint could otherwise match a different integer than the caller sent.
func DecodeParams(raw json.RawMessage, v interface{}) error {
	// Reject a duplicate object key at ANY nesting depth before decoding: the transport
	// forwards the caller's original params bytes verbatim, so a first-key-wins upstream
	// would act on a different value than the one enforcement authorized (argument or
	// tool-name smuggling). Every caller treats a DecodeParams error as a fail-closed,
	// audited INVALID_REQUEST deny.
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	return dec.Decode(v)
}

// rejectDuplicateJSONKeys returns an ErrParse-wrapped error when any JSON object in raw
// carries the same key more than once, at any nesting depth — a top-level-only check
// would still leave nested-field smuggling live. Empty/whitespace input is not an error.
//
// Keys collide under Unicode simple-fold, not byte equality, because encoding/json binds
// object keys to struct fields by a case-folding match and keeps the last one: folding
// only at the struct-bound root would miss the identical smuggle one level down, in
// forwarded bytes decoded by an upstream whose binding shape this proxy does not
// control.
func rejectDuplicateJSONKeys(raw json.RawMessage) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	type frame struct {
		object bool
		// seen maps a fold-canonical key to the raw key first seen under it, so a
		// collision can name both spellings in the error.
		seen      map[string]string
		expectKey bool
	}
	var stack []frame
	// markValueDone signals the enclosing object (if any) now expects a key next.
	markValueDone := func() {
		if n := len(stack); n > 0 && stack[n-1].object {
			stack[n-1].expectKey = true
		}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	// Mirror DecodeParams' UseNumber: without it, Token() errors on a magnitude past
	// float64 max, wrongly rejecting a valid large-number body this walk only needs to
	// skip over (it inspects keys only).
	dec.UseNumber()
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: %v", ErrParse, err)
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				// seen allocates lazily on the first key (nil map reads fine), so a
				// payload of many empty objects — up to ~1.3M in a 4 MiB body —
				// doesn't allocate a map header per object.
				stack = append(stack, frame{object: true, expectKey: true})
			case '[':
				stack = append(stack, frame{object: false})
			case '}', ']':
				stack = stack[:len(stack)-1]
				markValueDone() // the composite just closed is a value in its parent
			}
		case string:
			if n := len(stack); n > 0 && stack[n-1].object && stack[n-1].expectKey {
				key := foldJSONKey(t)
				if prior, dup := stack[n-1].seen[key]; dup {
					if prior == t {
						return fmt.Errorf("%w: duplicate object key %q", ErrParse, t)
					}
					// Not byte-identical, but encoding/json would fold both onto one
					// struct field and keep the last — the smuggling shape.
					return fmt.Errorf("%w: object keys %q and %q differ only by case fold", ErrParse, prior, t)
				}
				if stack[n-1].seen == nil {
					stack[n-1].seen = make(map[string]string, 1)
				}
				stack[n-1].seen[key] = t
				stack[n-1].expectKey = false
			} else {
				markValueDone() // a string value
			}
		default:
			markValueDone() // number, bool, or null value
		}
	}
}

// foldJSONKey canonicalizes a JSON object key so two spellings encoding/json would bind
// to the same struct field fold together; delegates to capability.FoldJSONKey so this
// and the tools/list entry scan in the PDP share one rule.
func foldJSONKey(key string) string {
	return capability.FoldJSONKey(key)
}

// -----------------------------------------------------------------
// Framed I/O: newline-delimited JSON
// -----------------------------------------------------------------

// ErrUpstreamWriteTimeout marks a write that exceeded its deadline and poisons the
// writer: a partial frame would desync the stream, so every later Write fails fast and
// onPoison (see NewMsgWriterWithTimeout) tears the session down.
var ErrUpstreamWriteTimeout = errors.New("mcp: upstream write deadline exceeded; stream framing desynced")

// ErrFrameDesync marks a partial write NOT caused by a deadline (EPIPE, ENOSPC, a
// signal) — the same poison as a timeout, but a distinct sentinel so the audit tape
// doesn't misreport a crashed upstream as UPSTREAM_TIMEOUT.
var ErrFrameDesync = errors.New("mcp: partial frame written; stream framing desynced")

// writeDeadliner is the subset of *os.File a subprocess stdin pipe satisfies, letting a
// write be bounded against an upstream that stopped draining stdin; a platform without
// pipe deadlines degrades to unbounded writes.
type writeDeadliner interface {
	SetWriteDeadline(time.Time) error
}

// writeDeadlineUnsupportedWarned makes the "platform does not support pipe write
// deadlines" warning fire at most once per process, not once per session/writer.
var writeDeadlineUnsupportedWarned sync.Once

// MsgWriter writes newline-delimited JSON-RPC messages to an io.Writer.
// Concurrent-safe.
type MsgWriter struct {
	mu sync.Mutex
	w  io.Writer
	// deadliner and timeout bound each write when both are set; deadliner is non-nil
	// only after NewMsgWriterWithTimeout confirmed the pipe accepts a deadline, so its
	// presence is a true "the write is bounded" invariant. See ErrUpstreamWriteTimeout.
	deadliner writeDeadliner
	timeout   time.Duration
	// onPoison, if set, fires exactly once (off-lock) on the poison transition so the
	// owner can tear the session down; a writer with no hook fails silently at call
	// sites that discard the error.
	onPoison func()
	// poisonErr latches the reason the writer was poisoned (nil = healthy) so a later
	// write reports the actual cause (deadline vs partial frame) rather than collapsing
	// both onto one sentinel.
	poisonErr error
}

// NewMsgWriter returns a MsgWriter with no per-write deadline and no poison hook. Use it
// only where the caller inspects the returned error; add SetPoisonHook or use
// NewMsgWriterWithTimeout otherwise.
func NewMsgWriter(w io.Writer) *MsgWriter { return &MsgWriter{w: w} }

// SetPoisonHook installs (or replaces) the teardown hook on an already-built writer, for
// a stream (e.g. stdio's fire-and-forget stdout) that would otherwise silently drop
// every response after one partial write.
//
// Separate from construction because the teardown owner is not always available at
// build time; installing on an already-poisoned writer does not retroactively fire it.
func (mw *MsgWriter) SetPoisonHook(onPoison func()) {
	mw.mu.Lock()
	defer mw.mu.Unlock()
	mw.onPoison = onPoison
}

// NewMsgWriterWithTimeout bounds each write by timeout when the writer supports a
// deadline, so a subprocess upstream that stops draining stdin can't wedge the caller
// indefinitely; support is probed once here, not per write. timeout<=0 or a writer
// without a write deadline disables the bound, identical to NewMsgWriter.
func NewMsgWriterWithTimeout(w io.Writer, timeout time.Duration, onPoison func()) *MsgWriter {
	mw := &MsgWriter{w: w, timeout: timeout, onPoison: onPoison}
	if timeout <= 0 {
		return mw
	}
	d, ok := w.(writeDeadliner)
	if !ok {
		return mw
	}
	// Probe with a zero time (clears any deadline): nil means the pipe is pollable and
	// deadlines will work; an error means the platform doesn't support them, so leave
	// deadliner nil and warn rather than arm a deadline that never fires.
	if err := d.SetWriteDeadline(time.Time{}); err != nil {
		writeDeadlineUnsupportedWarned.Do(func() {
			fmt.Fprintf(os.Stderr, "[eunox] WARNING: this platform does not support pipe write deadlines (%v); --upstream-timeout will NOT bound upstream stdin writes, so a subprocess upstream that stops draining its stdin can wedge a call until shutdown.\n", err)
		})
		return mw
	}
	mw.deadliner = d
	return mw
}

// Write encodes msg and writes it as a single line to the underlying writer.
func (mw *MsgWriter) Write(msg RPCMsg) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshalling message: %w", err)
	}
	// Append in place: data was just allocated by json.Marshal and is owned solely by
	// this call, avoiding fmt.Fprintf's extra allocation on this hot path.
	data = append(data, '\n')
	mw.mu.Lock()
	// A prior write left the stream desynced: refuse rather than append after it.
	// Failing fast (no deadline wait) lets a second in-flight writer return instead of
	// blocking behind a wedged one.
	if mw.poisonErr != nil {
		err := mw.poisonErr
		mw.mu.Unlock()
		return err
	}
	if mw.deadliner != nil {
		// Absolute deadline, reset per write.
		_ = mw.deadliner.SetWriteDeadline(time.Now().Add(mw.timeout))
	}
	n, err := mw.w.Write(data)
	justPoisoned := false
	// Poison on ANY partial frame, not only a deadline timeout — keyed on byte count
	// rather than err, since a short write desyncs the framing regardless of whether
	// io.Writer reported one.
	switch {
	case n < len(data) && mw.deadliner != nil && errors.Is(err, os.ErrDeadlineExceeded):
		// n < len(data) subsumes n == 0 (every frame ends in '\n'), so no third
		// byte-count case is needed. %w preserves os.ErrDeadlineExceeded in the chain
		// — %v would break errors.Is/As on the latched poisonErr.
		err = fmt.Errorf("%w: %d of %d bytes: %w", ErrUpstreamWriteTimeout, n, len(data), err)
		mw.poisonErr = err
		justPoisoned = true
	case n > 0 && n < len(data):
		// A distinct sentinel from the deadline case: same desync, but the cause
		// isn't a timeout, and the audit tape must not record a crashed upstream as
		// one.
		if err == nil {
			err = io.ErrShortWrite
		}
		err = fmt.Errorf("%w: %d of %d bytes: %w", ErrFrameDesync, n, len(data), err)
		mw.poisonErr = err
		justPoisoned = true
	}
	mw.mu.Unlock()
	// Fire the hook off-lock so it can never re-enter Write (which would self-deadlock
	// on mw.mu), regardless of which write path first wedged.
	if justPoisoned && mw.onPoison != nil {
		mw.onPoison()
	}
	return err
}

// MsgSink writes a single JSON-RPC message to an upstream. *MsgWriter (a
// subprocess pipe) and *httpUpstream (a remote HTTP server) both satisfy it, so
// the StdioProxy is upstream-transport-agnostic.
type MsgSink interface {
	Write(RPCMsg) error
}

// MsgSource reads the next JSON-RPC message from an upstream. *MsgReader (a
// subprocess pipe) and *httpUpstream (a remote HTTP server) both satisfy it.
type MsgSource interface {
	Read() (RPCMsg, error)
}

// MsgReader reads newline-delimited JSON-RPC messages from a *bufio.Scanner.
// NOT concurrent-safe: only one goroutine should call Scan at a time.
type MsgReader struct {
	s *bufio.Scanner
}

// NewMsgReader returns a MsgReader that parses newline-delimited messages from r.
func NewMsgReader(r io.Reader) *MsgReader {
	s := bufio.NewScanner(r)
	// Start small and grow on demand — a 4 MiB eager allocation per session would
	// waste heap on sessions carrying only sub-KiB traffic. Past the cap,
	// bufio.ErrTooLong loses framing, so the caller must tear the whole session down;
	// 4 MiB comfortably covers normal JSON-RPC traffic.
	s.Buffer(make([]byte, 0, 64<<10), 4<<20)
	return &MsgReader{s: s}
}

// Read returns the next message. Returns io.EOF when the stream ends.
func (mr *MsgReader) Read() (RPCMsg, error) {
	if !mr.s.Scan() {
		if err := mr.s.Err(); err != nil {
			return RPCMsg{}, err
		}
		return RPCMsg{}, io.EOF
	}
	var msg RPCMsg
	if err := json.Unmarshal(mr.s.Bytes(), &msg); err != nil {
		// Wrap ErrParse (recoverable): framing is intact, so the caller may skip this
		// line and continue.
		return RPCMsg{}, fmt.Errorf("%w: %v", ErrParse, err)
	}
	return msg, nil
}
