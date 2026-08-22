// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// The host-header passthrough: nothing crosses unless an operator named it for that upstream.
//
// The posture and the vocabulary of names that can never be granted live in internal/config
// (forward_headers.go), where an operator's configuration is refused. What lives HERE is the
// carrying: which of a host request's headers were granted, how they reach the one sender that
// builds an upstream POST, and the backstop that re-asks the reserved question at request time.
//
// # Why the context carries them
//
// The alternative is a parameter on DoMCPHTTP, which is the single sender shared by the
// gateway's per-session path, the stdio host's HTTP bridge, and the CLI's live probe. Two of
// those three have no host request at all — a stdio host sends no HTTP headers, and the probe
// is eunox talking for itself — so a parameter would be a value they exist to pass empty, on an
// exported signature, forever. The context already carries the other per-request facts the
// sender's callers thread through it (the resolved revision, the caller's claims), and it
// carries this one exactly as far: from the host leg that was granted the headers to the
// forward made on its behalf, and no further.
//
// That "no further" is the scope, deliberately: eunox's OWN upstream requests — the opener, the
// session-start drift probe, the terminating DELETE — are not made on behalf of a host request
// and carry no host header. A granted passthrough is a channel between a host and an upstream,
// not a property of the leg.

package transport

import (
	"context"
	"fmt"
	"net/http"

	"github.com/eunolabs/eunox/internal/config"
)

// forwardedHeadersKey is the context key under which a host leg carries the headers its route's
// allowlist granted.
type forwardedHeadersKeyType struct{}

var forwardedHeadersKey forwardedHeadersKeyType

// withForwardedHeaders returns ctx carrying the host headers this route grants to its upstream.
// An empty selection returns ctx unchanged, so the default posture allocates nothing.
func withForwardedHeaders(ctx context.Context, h http.Header) context.Context {
	if len(h) == 0 {
		return ctx
	}
	return context.WithValue(ctx, forwardedHeadersKey, h)
}

// forwardedHeaders returns the granted host headers carried on ctx, or nil.
func forwardedHeaders(ctx context.Context) http.Header {
	h, _ := ctx.Value(forwardedHeadersKey).(http.Header)
	return h
}

// selectForwardableHeaders copies the values of allow's names out of src.
//
// It reads only the names an operator granted rather than walking src and testing each: a host
// controls how many headers it sends, and the allowlist is a short operator-fixed list, so the
// cost of the selection is the operator's to set and not the caller's to drive. allow is already
// canonical (config.CanonicalForwardClientHeaders), which is the form net/http keys on.
//
// Values are copied, not aliased: the returned header outlives the handler's request on the
// forwarding path, and net/http reuses the request's own header storage.
func selectForwardableHeaders(allow []string, src http.Header) http.Header {
	if len(allow) == 0 || len(src) == 0 {
		return nil
	}
	var out http.Header
	for _, name := range allow {
		values, present := src[name]
		if !present || len(values) == 0 {
			continue
		}
		if out == nil {
			out = make(http.Header, len(allow))
		}
		out[name] = append([]string(nil), values...)
	}
	return out
}

// applyForwardedHeaders writes ctx's granted host headers onto an outbound upstream request,
// reporting a value that cannot be sent.
//
// Called BEFORE eunox sets its own, so every header eunox is accountable for overwrites a
// forwarded one structurally rather than because the configuration was checked. The reserved
// check is asked again here as the backstop for that ordering — a hop-by-hop header eunox does
// NOT set would otherwise survive it — which is the same startup-refusal-plus-request-backstop
// shape the condition-handler override gate uses, and for the same reason: the startup answer
// is the operator's, and this one is the code's.
func applyForwardedHeaders(ctx context.Context, req *http.Request) error {
	for name, values := range forwardedHeaders(ctx) {
		if _, reserved := config.ReservedUpstreamHeaders[name]; reserved {
			continue
		}
		for _, v := range values {
			if !sendableHeaderValue(v) {
				// Consistent with the routing headers: a header eunox cannot send verbatim
				// fails the call rather than being altered or dropped. Dropping would run the
				// upstream without a header the operator granted, which is a silent change to
				// what the upstream was asked to do. Unreachable through net/http's own server,
				// which rejects such a value on the inbound parse.
				return fmt.Errorf("cannot forward: the granted host header %s carries a value that is not a valid HTTP header field value", name)
			}
		}
		req.Header[name] = append([]string(nil), values...)
	}
	return nil
}
