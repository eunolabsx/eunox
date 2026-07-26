// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"errors"
	"testing"
)

// FuzzMsgReader exercises the JSON-RPC framing/parse path that consumes the most
// untrusted input in the proxy: bytes the MCP host writes on stdin. The reader
// must never panic on arbitrary input — it returns a parse error or io.EOF — so
// a malformed or hostile host cannot crash the proxy through the message reader.
//
// The loop skips ErrParse and keeps reading rather than stopping at the first
// error, mirroring what every production reader does (the stdio serve loop answers
// -32700 and continues; the upstream reader and the CLI live probe skip the line).
// That is the point: returning on the first error left the documented
// recover-and-keep-reading contract covered only by hand-written unit tests, so the
// fuzzer never explored what the reader does with bytes FOLLOWING a malformed line —
// exactly where a framing desynchronization would show up.
func FuzzMsgReader(f *testing.F) {
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}` + "\n"))
	f.Add([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	f.Add([]byte("not json\n{}\n"))
	f.Add([]byte(`{"id":` + "\x00" + `}`))
	f.Add([]byte(""))
	f.Add([]byte("\n\n\n"))
	// Garbage BEFORE and BETWEEN valid messages: the banner-then-protocol shape a
	// real stdio server produces, and the one the skip path has to survive.
	f.Add([]byte("server v1.2.3 starting\n" +
		`{"jsonrpc":"2.0","id":1,"result":{}}` + "\n" +
		"[debug] handled\n" +
		`{"jsonrpc":"2.0","id":2,"result":{}}` + "\n"))

	f.Fuzz(func(_ *testing.T, data []byte) {
		mr := NewMsgReader(bytes.NewReader(data))
		// Drain the stream. A malformed line is recoverable — the newline framing is
		// intact — so skip it and keep reading; any other error (io.EOF, a scanner
		// error) is terminal. The bound is belt-and-suspenders against a future change
		// that could return (zero, nil) indefinitely.
		for i := 0; i < 1<<16; i++ {
			_, err := mr.Read()
			if errors.Is(err, ErrParse) {
				continue
			}
			if err != nil {
				return
			}
		}
	})
}
