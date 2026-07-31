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

// ErrParse marks a message that framed correctly — a full newline-delimited line
// was read — but failed JSON parsing. It is recoverable: the caller may answer
// JSON-RPC -32700 and keep reading, because the scanner's newline framing is intact.
// Distinct from io.EOF and from scanner errors (bufio.ErrTooLong, underlying I/O),
// which lose framing and are terminal.
var ErrParse = errors.New("mcp: malformed JSON-RPC message")

// RPCMsg is a JSON-RPC 2.0 message — a request, response, or notification
// depending on which fields are populated.
//
// ID is nil ONLY for a notification (the "id" key absent from the wire). An
// explicit `"id": null` — a valid identifier — is a non-nil RawMessage holding the
// literal `null`. See [RPCMsg.UnmarshalJSON].
type RPCMsg struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id,omitempty"` // nil only for notifications
	Method  string           `json:"method,omitempty"`
	Params  json.RawMessage  `json:"params,omitempty"`
	Result  json.RawMessage  `json:"result,omitempty"`
	Error   *RPCError        `json:"error,omitempty"`
}

// UnmarshalJSON decodes a JSON-RPC message while distinguishing an ABSENT id (a
// notification) from an explicitly PRESENT `"id": null` (a valid identifier).
// Plain struct decoding collapses both to a nil pointer, misclassifying a
// null-id request as a notification. A present-null id is preserved as a non-nil
// RawMessage holding `null` so the classification helpers treat it as a
// request/response.
//
// Decoding the id as a value json.RawMessage (zero-length ⟹ absent) captures the
// distinction in one struct decode, with no probe map or second unmarshal on the
// hot path.
func (m *RPCMsg) UnmarshalJSON(b []byte) error {
	// alias holds the id as a value json.RawMessage (absent ⟹ zero-length, present
	// `null` ⟹ 4-byte literal) and drops UnmarshalJSON so this delegates to default
	// struct decoding without recursing.
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
	// Zero-length raw ⟹ "id" absent ⟹ notification (leave m.ID nil); any present id
	// (including the literal `null`) is kept non-nil.
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

// IsRequest reports whether msg is a JSON-RPC request (has id + method). A
// present-null id counts as a request: UnmarshalJSON keeps it as a non-nil
// RawMessage so it is not misread as a notification.
func (m *RPCMsg) IsRequest() bool {
	return m.ID != nil && m.Method != ""
}

// IsNotification reports whether msg is a notification (id ABSENT, has method).
// Only a truly absent id makes a notification; a present-null id is a request.
func (m *RPCMsg) IsNotification() bool {
	return m.ID == nil && m.Method != ""
}

// IsResponse reports whether msg is a response (has id, no method). A present-null
// id counts here too.
func (m *RPCMsg) IsResponse() bool {
	return m.ID != nil && m.Method == ""
}

// MsgKey returns a stable string key for a message ID, for use as a map key and
// response correlation. The key canonicalizes by the ID's JSON *value* and type,
// not raw bytes, so different spellings of one value (the numbers 5, 5.0, 5e0)
// share a key — otherwise a server-initiated request tracked under one spelling
// would be dropped when a host re-serializes it differently. A type prefix keeps a
// string ID from colliding with a numeric or null one. An absent ID keys to "".
func MsgKey(id *json.RawMessage) string {
	// maxNumericIDLen caps the numeric-id text length before big.Rat
	// canonicalization. 1024 chars is far past any id a conforming peer emits while
	// still bounding cost: a 1024-digit integer (or a 10^1024 exponent expansion) is
	// only ~425 bytes of big.Int math, whereas a short "1e1000000" would force ~1 MB.
	// The bound is generous ON PURPOSE — two byte-spellings of the same out-of-bounds
	// value (1e70 vs 1.0e+70) would key differently under the raw-bytes fallback, so an
	// upstream that re-serializes a large-but-legitimate numeric id in a different
	// spelling would orphan its own reply on the correlation path. See
	// numericIDExponentBounded.
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
		// String ID: decode so escape sequences canonicalize to their value. But
		// json.Unmarshal SILENTLY collapses both invalid UTF-8 bytes and lone
		// (unpaired) UTF-16 surrogate \u escapes to U+FFFD, so two distinct
		// nonconforming ids (say, a raw invalid byte and a lone surrogate escape)
		// can decode to the identical string and collide under this "s:" prefix —
		// a nonconforming peer could get one request's reply cross-correlated to a
		// different one. stringIDIsWellFormed re-checks the raw bytes independently
		// of json.Unmarshal, before that distinguishing information is lost, so a
		// malformed id falls through to the raw-bytes fallback below instead.
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
		// Numeric ID: key by a canonicalized form so equal spellings share a key.
		// Integral values key by int64 decimal (the common case); other values key
		// by a normalized big.Rat (collapsing 5.0/5e0 to "5").
		//
		// Fast path: a plain JSON integer (optional '-', then digits) is by far the most
		// common id and is keyed with zero allocation, byte-identical to the decoder path
		// below. MsgKey runs 3-5x per proxied request, so skipping the json.Decoder +
		// bytes.Reader + json.Number allocation here removes avoidable per-request garbage
		// on the hottest correlation path. parseCanonicalJSONInt rejects non-canonical
		// spellings ("+5", "05", "-0") that strconv would otherwise accept, so the fast
		// and slow paths never disagree.
		if i, ok := parseCanonicalJSONInt(raw); ok {
			return "n:" + strconv.FormatInt(i, 10)
		}
		// Slow path for floats/exponents/large integers. Bound the candidate BEFORE
		// big.Rat: SetString eagerly materializes the rational — for "1eN" it computes
		// 10^N — so a short id like "1e1000000" would force ~1 MB of big.Int math, a
		// triggerable DoS on the hot path. A length cap and an exponent-magnitude cap
		// together bound the cost; anything outside falls through to the raw-bytes
		// fallback (canonicalizing only matters for ids a conforming peer actually uses).
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

// stringIDIsWellFormed reports whether raw — the quoted JSON text of a string
// id, escapes and all — decodes losslessly: every literal byte is valid UTF-8
// and every \uXXXX escape is either an ordinary code point or one half of a
// correctly paired UTF-16 surrogate pair. Called only after json.Unmarshal has
// already accepted raw as syntactically valid JSON, so a false return here
// means the *content*, not the syntax, is nonconforming (a lone/unpaired
// surrogate escape) — a case json.Unmarshal silently maps to U+FFFD instead of
// rejecting. MsgKey uses this to route such an id to the raw-bytes fallback
// instead of the decoded-string key, so two distinct nonconforming ids can
// never collide on the U+FFFD they'd otherwise share.
//
// The leading utf8.Valid check covers every literal byte at once, and a
// syntactically valid \uXXXX escape (guaranteed once json.Unmarshal has
// accepted raw) always has exactly 4 hex digits — so the only content
// question left for the loop is surrogate pairing.
func stringIDIsWellFormed(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	for i := 0; i < len(raw); {
		if raw[i] == '\\' {
			// The escape syntax itself is already valid (json.Unmarshal succeeded), so
			// only \uXXXX warrants a further look: it is the one escape that can encode
			// a surrogate half, which is only meaningful — and only unambiguous — when
			// paired.
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

// numericIDExponentBounded reports whether a numeric id's exponent (if any) is
// small enough that big.Rat.SetString will not materialize a huge 10^N value (a
// short literal like "1e1000000" would otherwise expand to a ~1 MB integer). An
// unparseable or over-bound exponent reports false so the caller uses the
// raw-bytes fallback.
func numericIDExponentBounded(raw []byte) bool {
	const maxNumericIDExp = 1024
	i := bytes.IndexAny(raw, "eE")
	if i < 0 {
		return true // no exponent: only the length cap applies
	}
	exp := bytes.TrimPrefix(raw[i+1:], []byte("+"))
	v, err := strconv.Atoi(string(exp))
	if err != nil {
		return false
	}
	if v < 0 {
		v = -v
	}
	return v <= maxNumericIDExp
}

// parseCanonicalJSONInt parses raw as a CANONICAL JSON integer — an optional leading
// '-' followed by digits with no leading zero (except "0" itself), and no "-0" — and
// returns its int64 value. It reports false for any other shape (a leading '+', a
// leading zero, a float/exponent, an empty/sign-only string, or more than 18 digits)
// so the caller falls back to the allocating decoder/big.Rat path, which keys the same
// input identically. strconv.ParseInt alone accepts "+5"/"05"/"-0", none of which this
// fast path may claim: "+5" and "05" are invalid JSON and must reach the raw-bytes
// fallback ("r:"), while "-0" is valid JSON but a non-canonical spelling of zero that
// the slow path already folds onto the same "n:0" key as "0" (so a peer echoing "-0"
// still correlates). Declining all three here keeps the fast path's answers a subset of
// the slow path's rather than a second, divergent canonicalizer, and avoids any
// allocation. The 18-digit cap keeps v*10 from overflowing
// int64 (10^18 < math.MaxInt64); the rare longer or MinInt64-magnitude id falls through
// to the slow path rather than complicating the overflow guard here.
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
		// Only "0" is the canonical spelling of zero. "-0" is valid JSON but non-canonical,
		// so decline it here and let the slow path fold it onto the same "n:0" key.
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

// RawJSON returns a *json.RawMessage addressing a copy of s. s is NOT required to be
// a compile-time literal — callers pass runtime-built ids (a counter formatted with
// fmt.Sprintf, an id read off the wire) — so s must already be valid JSON; nothing
// here validates or escapes it.
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

// MethodInitialize is the MCP handshake request that opens a session. It is
// transport-level, not an enforced method (those live in pkg/capability), but it is
// consulted at more sites than any of them — the session-creating POST, the
// notification-shaped swallow, the re-initialize echo, the drift-refusal record, the
// upstream handshake builder, and the protocol-version header gate — and a typo in any
// one would silently misroute the handshake rather than fail. It sits beside
// MethodNotificationsInitialized, the other half of the same handshake, for the same
// single-source-of-truth reason.
const MethodInitialize = "initialize"

// MethodNotificationsInitialized is the MCP notification a client sends after a
// successful initialize handshake. It is the single source of truth for the spelling
// across the transports' upstream handshakes, the CLI live-upstream probes, and the
// dispatch swallow-list, so a typo in any one copy (which would silently drop the
// notification and leave a strict upstream refusing subsequent requests) cannot happen.
const MethodNotificationsInitialized = "notifications/initialized"

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
// json.Number rather than float64. The decode path for caller-supplied arguments
// (tools/call, prompts/get).
//
// A float64 cannot represent every int64 (2^53+1 rounds down), so the default path
// would let a numeric allowedValues / schema-enum constraint match a *different*
// large integer than the caller sent, while the upstream receives the original
// bytes verbatim. The enforcement engine compares json.Number at full int64
// precision, so UseNumber here closes the gap end-to-end.
func DecodeParams(raw json.RawMessage, v interface{}) error {
	// Reject a duplicate object key at ANY nesting depth before decoding. Go's decoder
	// keeps the LAST value on a duplicate, but the transport forwards the caller's
	// ORIGINAL params bytes to the upstream verbatim (msg.Params is a json.RawMessage),
	// so a first-key-wins upstream — common outside Go — would act on a DIFFERENT value
	// than the one enforcement authorized. That parser differential is argument
	// smuggling ({"path":"/safe","path":"/etc/shadow"}) and, at the params root,
	// tool-name smuggling ({"name":"safe","name":"dangerous"}). Failing closed here
	// makes the enforced view and the forwarded bytes agree; every caller treats a
	// DecodeParams error as a fail-closed, audited INVALID_REQUEST deny.
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	return dec.Decode(v)
}

// rejectDuplicateJSONKeys returns an ErrParse-wrapped error when any JSON object in raw
// carries the same key more than once, at any nesting depth. It walks the token stream
// with a stack of per-object frames: each object frame tracks the keys seen so far and
// whether the next string token is a key (keys and values alternate within an object).
// A nested object or array is a value in its parent, so on its close the parent returns
// to expecting a key. A top-level-only check would still leave nested-field smuggling
// live, so the walk is fully recursive. Empty/whitespace input is not an error (absent
// params is valid); a malformed token stream returns its decode error (also fail-closed).
//
// Keys collide under Unicode simple-fold, not byte equality, because a byte-exact check
// does not close the smuggle. encoding/json binds object keys to STRUCT FIELDS by a
// case-folding match and keeps the LAST one, so {"name":"dangerous","Name":"safe"} is two
// distinct keys to an exact check but resolves to Name="safe" here — the proxy authorizes
// "safe", forwards the original bytes verbatim, and a case-sensitive upstream (the
// TypeScript/Python SDKs, any plain JSON.parse) acts on "dangerous". Folding at every
// depth rather than only at the struct-bound root is deliberate: the forwarded bytes are
// decoded by an upstream whose binding shape this proxy does not control, so any pair of
// keys a reasonable parser could conflate is rejected. The cost is refusing an object that
// deliberately carries case-distinct siblings ({"a":1,"A":2}) — a denial, not a bypass,
// which is the direction this proxy fails.
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
	// markValueDone records that a scalar or closed composite just finished, so the
	// enclosing object (if any) expects a key next.
	markValueDone := func() {
		if n := len(stack); n > 0 && stack[n-1].object {
			stack[n-1].expectKey = true
		}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	// Mirror the real decode's UseNumber. Without it Token() materializes every numeric
	// value as a float64 and returns an error for any magnitude past float64 max, so a
	// valid, duplicate-free params body carrying a large number (1e309, a 310-digit
	// integer) would be rejected here as malformed — defeating the full-precision
	// guarantee DecodeParams documents above. This walk only inspects object KEYS; the
	// numeric form it yields is irrelevant beyond not erroring.
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
				// seen is allocated lazily on the first key (a nil map reads fine), so a
				// payload of many empty objects — [{},{},{}, ...], which a 4 MiB body can
				// hold ~1.3M of — does not allocate a map header per object.
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

// foldJSONKey canonicalizes a JSON object key so that any two keys encoding/json could
// bind to the same struct field map to the same value. It delegates to
// capability.FoldJSONKey so this scan and the tools/list entry scan in the PDP fold by
// one shared rule — see that function for why strings.ToLower is not sufficient.
func foldJSONKey(key string) string {
	return capability.FoldJSONKey(key)
}

// -----------------------------------------------------------------
// Framed I/O: newline-delimited JSON
// -----------------------------------------------------------------

// ErrUpstreamWriteTimeout marks a framed write that exceeded its per-write deadline (see
// NewMsgWriterWithTimeout), and every write after one. The writer is POISONED on it: a
// timed-out write can flush a partial frame larger than the pipe's atomic-write size, so
// every later Write fails fast rather than interleaving bytes into a corrupt stream. On
// the poison transition the writer's onPoison hook fires (the transports wire it to tear
// the upstream session down), so the desynced stream is reaped rather than reused — the
// recovery the deadline exists to enable.
var ErrUpstreamWriteTimeout = errors.New("mcp: upstream write deadline exceeded; stream framing desynced")

// ErrFrameDesync marks a write that flushed only PART of its frame for a reason other
// than a deadline — EPIPE, ENOSPC, or a signal interrupting a write larger than the
// pipe's atomic-write size. The framing consequence is identical to a timeout (the next
// frame would be appended onto half of the previous one), so it poisons the writer the
// same way, but the CAUSE is not a timeout and must not be reported as one: classifying
// an upstream that died mid-write as UPSTREAM_TIMEOUT puts a fabricated duration on the
// audit tape and tells the operator to raise --upstream-timeout. A distinct sentinel lets
// the classification layer tell them apart; the underlying error is wrapped alongside it.
var ErrFrameDesync = errors.New("mcp: partial frame written; stream framing desynced")

// writeDeadliner is the subset of *os.File a subprocess stdin pipe satisfies. On
// Linux/macOS the parent write end from cmd.StdinPipe() is a pollable *os.File, so
// SetWriteDeadline bounds a write against an upstream that has stopped draining its
// stdin. Where the platform does not support pipe deadlines SetWriteDeadline returns an
// error and the writer degrades to the unbounded behavior.
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
	// deadliner and timeout bound each write when both are set (subprocess pipe with
	// --upstream-timeout set); nil deadliner means writes block as before. deadliner is
	// non-nil ONLY after NewMsgWriterWithTimeout confirmed the pipe accepts a deadline, so
	// "deadliner != nil" is a true "the write is bounded" invariant. See ErrUpstreamWriteTimeout.
	deadliner writeDeadliner
	timeout   time.Duration
	// onPoison, if set, is invoked exactly once (off-lock) when a write first leaves the
	// stream desynced and poisons the writer, so the owner can tear the session down
	// regardless of which write path (request, notification, server-reply) hit it. A
	// writer with no hook has no owner to react, so every later write fails silently at
	// call sites that discard the error — set one on any writer whose stream matters.
	onPoison func()
	// poisonErr latches the reason the writer was poisoned (nil = healthy): the stream
	// framing is desynced, so all subsequent writes fail fast with this same error.
	// Storing the reason rather than a bool keeps a later write reporting the CAUSE that
	// broke the stream (deadline vs partial frame) instead of collapsing both onto one
	// sentinel.
	poisonErr error
}

// NewMsgWriter returns a MsgWriter that frames messages onto w, with no per-write
// deadline (writes block until the underlying writer accepts them) and no poison hook.
// Use it as-is only where the caller INSPECTS the returned error — a writer with no hook
// has nothing to tear the stream down, so a poisoned one fails every later write silently
// at any call site that discards the error. Where the stream's owner needs to react, add
// one with SetPoisonHook, or use NewMsgWriterWithTimeout for bounded writes.
func NewMsgWriter(w io.Writer) *MsgWriter { return &MsgWriter{w: w} }

// SetPoisonHook installs (or replaces) the teardown hook on an already-constructed
// writer, for a stream that cannot be bounded by a deadline yet still must not be left
// silently dead once its framing desyncs — the stdio host's stdout, whose writes are
// fire-and-forget at every call site. Without a hook a single partial write there latches
// the writer and the proxy goes on enforcing policy and forwarding calls upstream while
// every response is dropped: real side effects, no replies, no diagnostic.
//
// Separate from construction because the owner that performs the teardown is not always
// available when the writer is built: the stdio host writer's hook kills the upstream, so
// it is wired from Start (a context-carrying path) rather than the proxy constructor.
//
// Installing a hook on an ALREADY-poisoned writer does not retroactively fire it. The
// hook reacts to the transition, and a caller arriving after it has, by definition, not
// been watching; every later Write still fails fast with the latched cause.
func (mw *MsgWriter) SetPoisonHook(onPoison func()) {
	mw.mu.Lock()
	defer mw.mu.Unlock()
	mw.onPoison = onPoison
}

// NewMsgWriterWithTimeout returns a MsgWriter that bounds each write by timeout when the
// underlying writer supports a write deadline (a subprocess stdin *os.File pipe). A write
// that exceeds the deadline returns ErrUpstreamWriteTimeout, poisons the writer, and invokes
// onPoison (if non-nil) so the owner tears the upstream session down — so a subprocess
// upstream that stops draining its stdin cannot wedge the caller, or (for the stdio serve
// loop) the whole session, indefinitely.
//
// Support is probed ONCE here rather than per write: if SetWriteDeadline fails on this pipe
// the deadline is left unarmed and a one-time warning is logged, so an operator who set
// --upstream-timeout learns the bound is inert on this platform instead of silently getting
// the unbounded, deadlock-prone behavior. timeout<=0 (e.g. --upstream-timeout=0) or a writer
// without a write deadline disables the bound, identical to NewMsgWriter — the documented opt-out.
func NewMsgWriterWithTimeout(w io.Writer, timeout time.Duration, onPoison func()) *MsgWriter {
	mw := &MsgWriter{w: w, timeout: timeout, onPoison: onPoison}
	if timeout <= 0 {
		return mw
	}
	d, ok := w.(writeDeadliner)
	if !ok {
		return mw
	}
	// Probe with a zero time (clears any deadline): a nil return means the pipe is pollable
	// and per-write deadlines will work; an error means the platform/fd does not support
	// them, so leave deadliner nil and warn rather than arm a deadline that never fires.
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
	// Append the framing newline in place: data was just allocated by json.Marshal
	// and is owned solely by this call, so this is safe and avoids the format-machinery
	// allocation of fmt.Fprintf on this hot path.
	data = append(data, '\n')
	mw.mu.Lock()
	// A prior write left a partial frame on the wire: the stream is desynced, so refuse
	// rather than append this frame after it. Fails fast (no deadline wait), which is what
	// lets a second in-flight writer — e.g. a sampling reply queued behind a wedged
	// request write — return instead of blocking on this mutex until the wedge clears.
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
	// Poison on ANY partial frame, not only a deadline timeout. A deadline expiry is the
	// common way to flush half a frame, but it is not the only one: a >PIPE_BUF write
	// interrupted by EPIPE, ENOSPC, or a signal leaves n < len(data) just the same, and
	// the framing is equally desynced. Keyed on the byte count rather than on err, because
	// a short write is a desync whether or not the writer honored io.Writer's contract of
	// reporting one. n == len(data) with a non-nil error (which io.Writer permits) is NOT
	// poison: the whole frame landed.
	switch {
	case n > 0 && n < len(data):
		// A distinct sentinel from the deadline case: the framing outcome is the same, the
		// cause is not, and the audit tape must not record a crashed upstream as a timeout.
		//
		// Except when the cause IS the deadline. On a pollable pipe, a frame larger than
		// the free buffer against an upstream that stopped draining stdin returns
		// (n > 0, os.ErrDeadlineExceeded): the same physical failure as the n == 0 arm
		// below, differing only in whether the frame happened to fit. Keying the sentinel
		// purely on byte count recorded that one failure as UPSTREAM_TIMEOUT for a small
		// frame and UPSTREAM_ERROR for a large one — precisely the split classification
		// these two sentinels exist to prevent. The framing is desynced either way (the
		// poison below is unconditional); only the recorded CAUSE differs, and the cause
		// here is the deadline.
		if err == nil {
			err = io.ErrShortWrite
		}
		if mw.deadliner != nil && errors.Is(err, os.ErrDeadlineExceeded) {
			// %w on the cause too, matching the desync arm below: %v would drop
			// os.ErrDeadlineExceeded (and the net.Error the poller returns) out of the
			// chain, so errors.Is/As for a deadline would go false on this value — and it
			// is latched as poisonErr and returned verbatim from every later Write.
			// upstreamErrInfo matches the sentinel first today, but its default arm has a
			// net.Error timeout fallback this error must stay able to satisfy.
			err = fmt.Errorf("%w: %d of %d bytes: %w", ErrUpstreamWriteTimeout, n, len(data), err)
		} else {
			err = fmt.Errorf("%w: %d of %d bytes: %w", ErrFrameDesync, n, len(data), err)
		}
		mw.poisonErr = err
		justPoisoned = true
	case n == 0 && mw.deadliner != nil && errors.Is(err, os.ErrDeadlineExceeded):
		// A deadline expiry that wrote nothing left the framing intact, but the pipe is
		// wedged and the session is torn down either way; keep the established behavior.
		//
		// Gated on n == 0 for the same reason the partial-write arm is keyed on the byte
		// count: a deadline error accompanying a COMPLETE write (n == len(data), which
		// io.Writer permits) means the frame landed, so poisoning the writer would tear
		// down a healthy stream and put a fabricated UPSTREAM_TIMEOUT on the tape for a
		// call that was delivered — the misclassification the ErrFrameDesync /
		// ErrUpstreamWriteTimeout split exists to prevent, in the other direction.
		err = fmt.Errorf("%w: %v", ErrUpstreamWriteTimeout, err)
		mw.poisonErr = err
		justPoisoned = true
	}
	mw.mu.Unlock()
	// Fire the teardown hook once, OFF the lock, on the poison transition. Off-lock so the
	// hook can never re-enter Write (which would self-deadlock on mw.mu), and so the hook
	// runs regardless of which write path first wedged.
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
	// Start small and let bufio.Scanner grow on demand up to the 4 MiB cap, rather
	// than pinning 4 MiB per reader up front: one MsgReader lives per session, so an
	// eager allocation would reserve ~4 MiB of mostly-empty heap for every session
	// even when all traffic is sub-KiB JSON-RPC frames.
	// The 4 MiB cap is a fixed, non-configurable per-message limit. A single frame
	// larger than this surfaces bufio.ErrTooLong from Read; because bufio.Scanner
	// loses newline framing once it trips, the caller cannot skip just that frame and
	// must tear the stream (and, for the transports, the whole session) down. A
	// legitimate oversized upstream response therefore fails every in-flight call on
	// that session — an accepted limit, since 4 MiB comfortably covers normal JSON-RPC
	// traffic and raising it would only move the boundary.
	s.Buffer(make([]byte, 0, 64<<10), 4<<20) // grows to a 4 MiB per-message limit
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
		// Wrap ErrParse (recoverable) while preserving the underlying json error in the
		// message; the framing is intact so the caller may skip this line and continue.
		return RPCMsg{}, fmt.Errorf("%w: %v", ErrParse, err)
	}
	return msg, nil
}
