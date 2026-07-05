// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

// failingWriter is an io.Writer that always fails, used to exercise the
// write-error path of MsgWriter.Write without touching the network or disk.
type failingWriter struct{}

func (failingWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("boom: write failed")
}

// failingReader is an io.Reader that always returns a non-EOF error, used to
// exercise the scanner-error (not io.EOF) branch of MsgReader.Read.
type failingReader struct{}

func (failingReader) Read(_ []byte) (int, error) {
	return 0, errors.New("boom: read failed")
}

// unmarshalable is a type json.Marshal cannot encode (channels are unsupported),
// used to drive the marshal-error branches of SuccessResponse and NotificationMsg.
type unmarshalable struct {
	Ch chan int
}

func newUnmarshalable() unmarshalable { return unmarshalable{Ch: make(chan int)} }

// TestErrorResponse verifies ErrorResponse builds a well-formed JSON-RPC 2.0
// error response, echoing the id and carrying the code/message, for both a
// concrete id and a nil (notification-shaped) id.
func TestErrorResponse(t *testing.T) {
	cases := []struct {
		name    string
		id      *json.RawMessage
		code    int
		message string
		wantID  string // expected raw id bytes if id non-nil
	}{
		{
			name:    "integer id",
			id:      RawJSON(`7`),
			code:    -32601,
			message: "method not found",
			wantID:  "7",
		},
		{
			name:    "string id",
			id:      RawJSON(`"abc"`),
			code:    -32000,
			message: "authorization failed",
			wantID:  `"abc"`,
		},
		{
			name:    "null id",
			id:      RawJSON(`null`),
			code:    -32600,
			message: "invalid request",
			wantID:  "null",
		},
		{
			name:    "nil id",
			id:      nil,
			code:    -32603,
			message: "internal error",
			wantID:  "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := ErrorResponse(tc.id, tc.code, tc.message)
			if resp.JSONRPC != "2.0" {
				t.Errorf("JSONRPC = %q, want 2.0", resp.JSONRPC)
			}
			if resp.Error == nil {
				t.Fatalf("Error is nil, want populated RPCError")
			}
			if resp.Error.Code != tc.code {
				t.Errorf("Error.Code = %d, want %d", resp.Error.Code, tc.code)
			}
			if resp.Error.Message != tc.message {
				t.Errorf("Error.Message = %q, want %q", resp.Error.Message, tc.message)
			}
			if resp.Result != nil {
				t.Errorf("Result = %s, want nil for an error response", resp.Result)
			}
			if tc.wantID == "" {
				if resp.ID != nil {
					t.Errorf("ID = %s, want nil", *resp.ID)
				}
			} else {
				if resp.ID == nil {
					t.Fatalf("ID = nil, want %q", tc.wantID)
				}
				if string(*resp.ID) != tc.wantID {
					t.Errorf("ID = %q, want %q", string(*resp.ID), tc.wantID)
				}
			}

			// The response must marshal as the wrapper JSON-RPC error shape and must
			// not contain a result field.
			out, err := json.Marshal(resp)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if !strings.Contains(string(out), `"error"`) {
				t.Errorf("marshaled response %s missing error object", out)
			}
			if strings.Contains(string(out), `"result"`) {
				t.Errorf("marshaled error response %s must not carry result", out)
			}
		})
	}
}

// TestDecodeParams covers DecodeParams: a successful decode that preserves large
// integers as json.Number (the float64-precision-loss guard), a decode into a
// typed struct, and a malformed-JSON error.
func TestDecodeParams(t *testing.T) {
	t.Run("preserves large integer as json.Number", func(t *testing.T) {
		// 2^53+1 cannot be represented exactly by float64; UseNumber must keep it.
		const big = "9007199254740993"
		raw := json.RawMessage(`{"value":` + big + `}`)
		var got map[string]any
		if err := DecodeParams(raw, &got); err != nil {
			t.Fatalf("DecodeParams: %v", err)
		}
		num, ok := got["value"].(json.Number)
		if !ok {
			t.Fatalf("value type = %T, want json.Number", got["value"])
		}
		if num.String() != big {
			t.Errorf("value = %s, want %s (no float64 rounding)", num.String(), big)
		}
	})

	t.Run("decodes into typed struct", func(t *testing.T) {
		raw := json.RawMessage(`{"name":"do_thing","arguments":{"count":5}}`)
		var p ToolCallParams
		if err := DecodeParams(raw, &p); err != nil {
			t.Fatalf("DecodeParams: %v", err)
		}
		if p.Name != "do_thing" {
			t.Errorf("Name = %q, want do_thing", p.Name)
		}
		if got, ok := p.Arguments["count"].(json.Number); !ok || got.String() != "5" {
			t.Errorf("arguments[count] = %v (%T), want json.Number 5", p.Arguments["count"], p.Arguments["count"])
		}
	})

	t.Run("malformed JSON returns error", func(t *testing.T) {
		raw := json.RawMessage(`{"name":`) // truncated
		var p ToolCallParams
		if err := DecodeParams(raw, &p); err == nil {
			t.Fatalf("DecodeParams on malformed input = nil error, want decode error")
		}
	})

	t.Run("type mismatch returns error", func(t *testing.T) {
		raw := json.RawMessage(`{"name":123}`) // name should be string
		var p ToolCallParams
		if err := DecodeParams(raw, &p); err == nil {
			t.Fatalf("DecodeParams on type mismatch = nil error, want decode error")
		}
	})
}

// TestMsgWriter_WriteSuccess verifies NewMsgWriter + Write frame a message as a
// single newline-terminated JSON line on the underlying writer.
func TestMsgWriter_WriteSuccess(t *testing.T) {
	var buf bytes.Buffer
	mw := NewMsgWriter(&buf)
	if mw == nil {
		t.Fatalf("NewMsgWriter returned nil")
	}

	msg := ErrorResponse(RawJSON(`1`), -32000, "denied")
	if err := mw.Write(msg); err != nil {
		t.Fatalf("Write: %v", err)
	}

	out := buf.String()
	if !strings.HasSuffix(out, "\n") {
		t.Errorf("framed output %q must end with newline", out)
	}
	if strings.Count(out, "\n") != 1 {
		t.Errorf("framed output %q must contain exactly one newline", out)
	}

	// The line (sans trailing newline) must round-trip back to an equivalent message.
	var got RPCMsg
	if err := json.Unmarshal([]byte(strings.TrimRight(out, "\n")), &got); err != nil {
		t.Fatalf("round-trip unmarshal: %v", err)
	}
	if got.Error == nil || got.Error.Code != -32000 || got.Error.Message != "denied" {
		t.Errorf("round-tripped message = %+v, want error code -32000 denied", got)
	}

	// A second write must append a second framed line (writer is reusable).
	if err := mw.Write(NotificationMsgMust(t, "notifications/initialized", nil)); err != nil {
		t.Fatalf("second Write: %v", err)
	}
	if strings.Count(buf.String(), "\n") != 2 {
		t.Errorf("after two writes want 2 newlines, got buffer %q", buf.String())
	}
}

// TestMsgWriter_WriteError verifies Write surfaces the underlying writer's error.
func TestMsgWriter_WriteError(t *testing.T) {
	mw := NewMsgWriter(failingWriter{})
	err := mw.Write(ErrorResponse(RawJSON(`1`), -32000, "denied"))
	if err == nil {
		t.Fatalf("Write to a failing writer = nil error, want propagated write error")
	}
	if !strings.Contains(err.Error(), "boom: write failed") {
		t.Errorf("error %q must surface the underlying writer failure", err)
	}
}

// NotificationMsgMust is a test helper that builds a notification and fails the
// test on error, keeping the call sites above terse.
func NotificationMsgMust(t *testing.T, method string, params interface{}) RPCMsg {
	t.Helper()
	m, err := NotificationMsg(method, params)
	if err != nil {
		t.Fatalf("NotificationMsg(%q): %v", method, err)
	}
	return m
}

// TestNotificationMsg covers the nil-params path, the non-nil-params marshal
// path, and the marshal-error path of NotificationMsg.
func TestNotificationMsg(t *testing.T) {
	t.Run("nil params leaves Params unset", func(t *testing.T) {
		m, err := NotificationMsg("notifications/initialized", nil)
		if err != nil {
			t.Fatalf("NotificationMsg: %v", err)
		}
		if m.JSONRPC != "2.0" {
			t.Errorf("JSONRPC = %q, want 2.0", m.JSONRPC)
		}
		if m.Method != "notifications/initialized" {
			t.Errorf("Method = %q, want notifications/initialized", m.Method)
		}
		if m.Params != nil {
			t.Errorf("Params = %s, want nil for nil input", m.Params)
		}
		if m.ID != nil {
			t.Errorf("ID = %s, want nil for a notification", *m.ID)
		}
		if !m.IsNotification() {
			t.Errorf("built message must classify as a notification")
		}
	})

	t.Run("non-nil params are marshaled", func(t *testing.T) {
		m, err := NotificationMsg("notifications/progress", map[string]any{"pct": 50})
		if err != nil {
			t.Fatalf("NotificationMsg: %v", err)
		}
		if m.Params == nil {
			t.Fatalf("Params = nil, want marshaled object")
		}
		var decoded map[string]any
		if err := json.Unmarshal(m.Params, &decoded); err != nil {
			t.Fatalf("unmarshal params: %v", err)
		}
		if _, ok := decoded["pct"]; !ok {
			t.Errorf("params %s missing pct key", m.Params)
		}
		if !m.IsNotification() {
			t.Errorf("notification with params must still classify as a notification")
		}
	})

	t.Run("unmarshalable params return error", func(t *testing.T) {
		_, err := NotificationMsg("notifications/progress", newUnmarshalable())
		if err == nil {
			t.Fatalf("NotificationMsg with unmarshalable params = nil error, want marshal error")
		}
	})
}

// TestSuccessResponse covers the happy path and the marshal-error branch of
// SuccessResponse.
func TestSuccessResponse(t *testing.T) {
	t.Run("marshals result and echoes id", func(t *testing.T) {
		m, err := SuccessResponse(RawJSON(`"req-1"`), map[string]any{"ok": true})
		if err != nil {
			t.Fatalf("SuccessResponse: %v", err)
		}
		if m.JSONRPC != "2.0" {
			t.Errorf("JSONRPC = %q, want 2.0", m.JSONRPC)
		}
		if m.ID == nil || string(*m.ID) != `"req-1"` {
			t.Fatalf("ID = %v, want \"req-1\"", m.ID)
		}
		if m.Error != nil {
			t.Errorf("Error = %+v, want nil for a success response", m.Error)
		}
		var decoded map[string]any
		if err := json.Unmarshal(m.Result, &decoded); err != nil {
			t.Fatalf("unmarshal result: %v", err)
		}
		if decoded["ok"] != true {
			t.Errorf("result %s missing ok:true", m.Result)
		}
		if !m.IsResponse() {
			t.Errorf("built message must classify as a response")
		}
	})

	t.Run("nil result marshals to JSON null", func(t *testing.T) {
		m, err := SuccessResponse(RawJSON(`1`), nil)
		if err != nil {
			t.Fatalf("SuccessResponse: %v", err)
		}
		if string(m.Result) != "null" {
			t.Errorf("Result = %s, want null", m.Result)
		}
	})

	t.Run("unmarshalable result returns error", func(t *testing.T) {
		_, err := SuccessResponse(RawJSON(`1`), newUnmarshalable())
		if err == nil {
			t.Fatalf("SuccessResponse with unmarshalable result = nil error, want marshal error")
		}
		// A zero RPCMsg must come back on error.
		zero, err := SuccessResponse(RawJSON(`1`), make(chan int))
		if err == nil {
			t.Fatalf("SuccessResponse with channel result = nil error, want marshal error")
		}
		if zero.JSONRPC != "" || zero.ID != nil || zero.Result != nil {
			t.Errorf("on marshal error want zero RPCMsg, got %+v", zero)
		}
	})
}

// TestMsgKey_FallbackAndEdges covers the branches of MsgKey not already hit by
// the existing canonicalization test: the nil and empty/whitespace-only inputs,
// the malformed-string fallback, the numeric-with-trailing-garbage fallback, and
// a bare non-"null" token starting with 'n'.
func TestMsgKey_FallbackAndEdges(t *testing.T) {
	cases := []struct {
		name string
		id   *json.RawMessage
		want string
	}{
		{name: "nil id keys to empty", id: nil, want: ""},
		{name: "empty raw keys to empty", id: RawJSON(``), want: ""},
		{name: "whitespace-only raw keys to empty", id: RawJSON("   "), want: ""},
		{name: "plain integer", id: RawJSON(`42`), want: "n:42"},
		{name: "plain string", id: RawJSON(`"hi"`), want: "s:hi"},
		{name: "literal null", id: RawJSON(`null`), want: "z:null"},
		// Starts with 'n' but is not the literal null: must fall through to raw.
		{name: "n-prefixed non-null token", id: RawJSON(`nope`), want: "r:nope"},
		// Numeric prefix but trailing garbage: the second Decode != io.EOF, so the
		// canonical-number branch is rejected and we fall back to raw bytes.
		{name: "numeric with trailing garbage", id: RawJSON(`7x`), want: "r:7x"},
		{name: "two numbers (trailing token)", id: RawJSON(`7 8`), want: "r:7 8"},
		// Malformed string (unterminated): json.Unmarshal fails, fall back to raw.
		{name: "unterminated string", id: RawJSON(`"oops`), want: `r:"oops`},
		// Object/array shaped id: default branch, not a valid number, raw fallback.
		{name: "object-shaped id", id: RawJSON(`{}`), want: "r:{}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := MsgKey(tc.id); got != tc.want {
				t.Errorf("MsgKey = %q, want %q", got, tc.want)
			}
		})
	}

	// Equal numeric values with different spellings share the canonical key.
	if MsgKey(RawJSON(`100`)) != MsgKey(RawJSON(` 100 `)) {
		t.Errorf("numeric spellings of 100 must share a key")
	}
	// A raw-fallback malformed id must not collide with a well-formed numeric key.
	if MsgKey(RawJSON(`7x`)) == MsgKey(RawJSON(`7`)) {
		t.Errorf("malformed numeric id must not collide with a valid numeric key")
	}
}

// TestMsgKey_NonconformingStringIDsDoNotCollide pins the fix for a correlation
// hazard: json.Unmarshal silently maps BOTH a raw invalid UTF-8 byte and a lone
// (unpaired) UTF-16 surrogate \u escape to the same U+FFFD replacement
// character. Keying a string id by its decoded value alone would therefore give
// two distinct, nonconforming raw ids the identical "s:�" key — on this
// proxy, sitting between an MCP host and an upstream and correlating their
// JSON-RPC messages by this key, that would let a nonconforming peer cause two
// different in-flight requests/responses to be cross-correlated. Both must
// instead route through the "r:" raw-bytes fallback, which is keyed by the
// (distinct) raw bytes, so they no longer collide.
func TestMsgKey_NonconformingStringIDsDoNotCollide(t *testing.T) {
	// A raw invalid UTF-8 byte embedded directly in the JSON string text.
	invalidByte := RawJSON("\"\xff\"")
	// A lone (unpaired) high surrogate \u escape — syntactically valid JSON, but
	// not a valid Unicode scalar value on its own.
	loneSurrogate := RawJSON(`"\ud800"`)

	keyInvalidByte := MsgKey(invalidByte)
	keyLoneSurrogate := MsgKey(loneSurrogate)

	if keyInvalidByte == keyLoneSurrogate {
		t.Errorf("two distinct nonconforming string ids must not collide: MsgKey(%q) = MsgKey(%q) = %q",
			*invalidByte, *loneSurrogate, keyInvalidByte)
	}
	// Both are nonconforming content behind syntactically-valid JSON, so both must
	// take the raw-bytes fallback rather than the "s:" decoded-string path.
	if !strings.HasPrefix(keyInvalidByte, "r:") {
		t.Errorf("raw-invalid-UTF-8 string id must use the raw fallback, got %q", keyInvalidByte)
	}
	if !strings.HasPrefix(keyLoneSurrogate, "r:") {
		t.Errorf("lone-surrogate string id must use the raw fallback, got %q", keyLoneSurrogate)
	}

	// Regression check: two IDENTICAL, well-formed string ids must still share a key.
	keyHelloA := MsgKey(RawJSON(`"hello"`))
	keyHelloB := MsgKey(RawJSON(`"hello"`))
	if keyHelloA != keyHelloB {
		t.Errorf("identical well-formed string ids must share a key")
	}

	// The pre-existing "r:" raw-fallback behavior for an unrelated malformed shape
	// (an unterminated string, where json.Unmarshal itself fails) must be untouched.
	if got := MsgKey(RawJSON(`"oops`)); got != `r:"oops` {
		t.Errorf(`unterminated string id must still key as the raw fallback, got %q`, got)
	}
}

// TestRPCMsg_UnmarshalJSON_Error verifies UnmarshalJSON surfaces the underlying
// json error on malformed input rather than silently succeeding.
func TestRPCMsg_UnmarshalJSON_Error(t *testing.T) {
	cases := []struct {
		name string
		wire string
	}{
		{name: "truncated object", wire: `{"jsonrpc":"2.0"`},
		{name: "not an object", wire: `not json`},
		{name: "id is wrong type for inner alias", wire: `{"jsonrpc":"2.0","error":"should-be-object"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var m RPCMsg
			if err := json.Unmarshal([]byte(tc.wire), &m); err == nil {
				t.Fatalf("UnmarshalJSON(%q) = nil error, want decode error", tc.wire)
			}
		})
	}
}

// TestRPCMsg_UnmarshalJSON_EmptyIDObject verifies that an id present but holding
// an empty raw (only achievable via the absent key) keeps ID nil, while a present
// scalar id is preserved. This pins the len(a.ID) > 0 branch boundary.
func TestRPCMsg_UnmarshalJSON_AbsentVsPresent(t *testing.T) {
	var notif RPCMsg
	if err := json.Unmarshal([]byte(`{"jsonrpc":"2.0","method":"x"}`), &notif); err != nil {
		t.Fatalf("unmarshal notif: %v", err)
	}
	if notif.ID != nil {
		t.Errorf("absent id must leave ID nil, got %s", *notif.ID)
	}

	var req RPCMsg
	if err := json.Unmarshal([]byte(`{"jsonrpc":"2.0","id":3,"method":"x","params":{"a":1}}`), &req); err != nil {
		t.Fatalf("unmarshal req: %v", err)
	}
	if req.ID == nil || string(*req.ID) != "3" {
		t.Fatalf("present id must be preserved, got %v", req.ID)
	}
	if string(req.Params) != `{"a":1}` {
		t.Errorf("Params = %s, want {\"a\":1}", req.Params)
	}
}

// TestMsgReader_Read covers the Read paths: a successful parse, a clean io.EOF on
// stream end, a parse error on malformed JSON, and a non-EOF scanner error
// surfaced from a failing reader.
func TestMsgReader_Read(t *testing.T) {
	t.Run("reads framed messages then EOF", func(t *testing.T) {
		input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}` + "\n" +
			`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n"
		mr := NewMsgReader(strings.NewReader(input))

		first, err := mr.Read()
		if err != nil {
			t.Fatalf("first Read: %v", err)
		}
		if !first.IsRequest() || first.Method != "tools/call" {
			t.Errorf("first message = %+v, want tools/call request", first)
		}

		second, err := mr.Read()
		if err != nil {
			t.Fatalf("second Read: %v", err)
		}
		if !second.IsNotification() {
			t.Errorf("second message = %+v, want notification", second)
		}

		if _, err := mr.Read(); !errors.Is(err, io.EOF) {
			t.Fatalf("Read past end = %v, want io.EOF", err)
		}
	})

	t.Run("empty stream is immediate EOF", func(t *testing.T) {
		mr := NewMsgReader(strings.NewReader(""))
		if _, err := mr.Read(); !errors.Is(err, io.EOF) {
			t.Fatalf("Read on empty = %v, want io.EOF", err)
		}
	})

	t.Run("malformed JSON line returns parse error (not EOF)", func(t *testing.T) {
		mr := NewMsgReader(strings.NewReader("this is not json\n"))
		_, err := mr.Read()
		if err == nil {
			t.Fatalf("Read on malformed line = nil error, want parse error")
		}
		if errors.Is(err, io.EOF) {
			t.Fatalf("malformed line must not be reported as io.EOF")
		}
		if !errors.Is(err, ErrParse) {
			t.Errorf("error %q must wrap ErrParse so the caller can recover and continue", err)
		}
	})

	t.Run("non-EOF scanner error is surfaced", func(t *testing.T) {
		mr := NewMsgReader(failingReader{})
		_, err := mr.Read()
		if err == nil {
			t.Fatalf("Read from a failing reader = nil error, want scanner error")
		}
		if errors.Is(err, io.EOF) {
			t.Fatalf("a real read failure must not be masked as io.EOF")
		}
		if !strings.Contains(err.Error(), "boom: read failed") {
			t.Errorf("error %q must surface the underlying reader failure", err)
		}
	})
}
