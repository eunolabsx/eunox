#!/usr/bin/env python3
# Copyright 2026 Eunolabs, LLC
# SPDX-License-Identifier: Apache-2.0
"""Reference client stub for the eunox attribution interface.

A cooperating MCP client attributes a call's inputs by adding one namespaced key to the
request's `_meta`. eunox unions the declared labels into the session's accumulated flow
labels for THAT call's sink check.

The interface is ONE-DIRECTIONAL: a client may add labels, never remove them. That is the
security property, not a simplification — an agent that could narrow its own taint would
defeat information-flow control with one extra field, and it would be the first thing a
prompt injection reached for. Union-only means a declaration can only produce more denials,
so honoring it needs no trust decision. See docs/attribution-interface.md.

This is illustrative, not a supported SDK: it shows the wire shape an SDK hook would wrap.
Dependency-free, and it makes no network calls — run it to print the request it would send.
"""

import json
import sys

# The reverse-DNS `_meta` key. Namespaced so a non-supporting client, host, or upstream
# never sets it and nothing changes.
CONTEXT_MANIFEST_KEY = "io.eunolabs.context-manifest"

# The closed native flow vocabulary. eunox rejects an unknown label rather than dropping it:
# a typo'd label that silently vanished would leave the client believing a tightening was in
# force when it was not.
FLOW_LABELS = ("public", "internal", "confidential", "pii", "untrusted")


def attribute(request: dict, labels) -> dict:
    """Return `request` with the caller's flow attribution attached to params._meta.

    Existing `_meta` keys are preserved — other vendors' keys are none of our business, and
    eunox forwards params upstream verbatim, so a key meant for the upstream still reaches
    it untouched.
    """
    labels = list(labels)
    unknown = [label for label in labels if label not in FLOW_LABELS]
    if unknown:
        # Fail here rather than let the proxy reject the request: the client knows its own
        # vocabulary, and a local error names the mistake at the line that made it.
        raise ValueError(
            f"unknown flow label(s) {unknown}; valid labels are {', '.join(FLOW_LABELS)}"
        )
    if not labels:
        # Attributing nothing is not an error, it is just a no-op. Sending an empty block
        # would be indistinguishable to eunox, which treats it as no attribution.
        return request

    params = request.setdefault("params", {})
    meta = params.setdefault("_meta", {})
    meta[CONTEXT_MANIFEST_KEY] = {"labels": labels}
    return request


def tool_call(request_id: int, name: str, arguments: dict) -> dict:
    """Build a plain MCP tools/call request."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }


def main() -> int:
    # The case the interface exists for: this client fetched a customer-submitted ticket
    # OUTSIDE eunox's view (a direct HTTP call, a file the harness read, a message from
    # another agent), so the proxy's own session state has no way to know the context is
    # untrusted. Declaring it makes the proxy stricter on this call than it would otherwise
    # have been.
    request = attribute(
        tool_call(7, "send_email", {"to": "ops@example.com", "body": "summary of ticket 4471"}),
        ["untrusted"],
    )
    json.dump(request, sys.stdout, indent=2)
    sys.stdout.write("\n")

    # The declaration a compromised agent would want to make, and the reason it buys nothing:
    # eunox UNIONS the declared set with what it already observed, so declaring a benign
    # label cannot subtract the label the proxy recorded for itself.
    sys.stderr.write(
        "\nNote: declaring ['public'] here would NOT clear a `confidential` label eunox\n"
        "recorded from a labelOutput source. The interface only ever adds.\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
