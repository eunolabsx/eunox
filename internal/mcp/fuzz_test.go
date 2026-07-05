// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"testing"
)

// FuzzMsgReader exercises the JSON-RPC framing/parse path that consumes the most
// untrusted input in the proxy: bytes the MCP host writes on stdin. The reader
// must never panic on arbitrary input — it returns a parse error or io.EOF — so
// a malformed or hostile host cannot crash the proxy through the message reader.
func FuzzMsgReader(f *testing.F) {
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}` + "\n"))
	f.Add([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	f.Add([]byte("not json\n{}\n"))
	f.Add([]byte(`{"id":` + "\x00" + `}`))
	f.Add([]byte(""))
	f.Add([]byte("\n\n\n"))

	f.Fuzz(func(_ *testing.T, data []byte) {
		mr := NewMsgReader(bytes.NewReader(data))
		// Drain the stream. Read returns a non-nil error (parse failure or io.EOF)
		// to terminate; the bound is belt-and-suspenders against a future change
		// that could return (zero, nil) indefinitely.
		for i := 0; i < 1<<16; i++ {
			if _, err := mr.Read(); err != nil {
				return
			}
		}
	})
}
