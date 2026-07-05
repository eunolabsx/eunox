---
name: Bug report
about: Report unexpected behavior in eunox
title: "[Bug] "
labels: bug
assignees: ""
---

<!-- If this is a security vulnerability (policy bypass, audit-tape forgery,
     fail-closed regression, JWT-claim widening, etc.), STOP and report it
     privately via the channels in SECURITY.md:
     https://github.com/eunolabs/eunox/security/advisories/new
     Do not file it as a public issue. -->

## What happened

<!-- One or two sentences. What did you observe? -->

## What you expected

<!-- What should have happened instead? -->

## How to reproduce

<!-- Minimum viable reproduction. Reviewers cannot help with vague reports —
     the more concrete this section is, the faster the fix.

     For policy / enforcement issues, paste:
       1. The capability manifest fragment (or a minimized version of it).
       2. The exact JSON-RPC request that triggered the bug.
       3. The response or audit record you observed.
       4. The response or audit record you expected. -->

```yaml
# manifest fragment
```

```json
// JSON-RPC request
```

```json
// observed response / audit record (redact the _hmac field if you prefer)
```

## Severity (your assessment)

<!-- Pick one. We may reclassify during triage. -->

- [ ] Crash / data loss / fail-open (highest)
- [ ] Wrong allow or wrong deny (the manifest said one thing and the proxy did the other)
- [ ] List-filtering leak (tools/list, resources/list, or prompts/list exposes blocked entries)
- [ ] Audit-tape oddity (missing field, bad signature, rotation issue, …)
- [ ] CLI / config / docs / build / demo
- [ ] Other

## Environment

- `eunox --version` (or commit SHA / Docker tag):
- Install method: brew · winget · docker · .deb · .rpm · `go install` · built from source
- Transport: stdio / HTTP
- JWT mode in use: yes / no
- Gateway mode in use: yes / no
- Upstream MCP server (name + version, if known):
- MCP host (Claude Desktop, Cursor, VS Code, Cline, LangChain, …) and its version:
- OS + arch:
- Anything unusual about the environment (corporate proxy, custom JWKS, air-gapped, ARM CI runner, etc.):

## Doctor bundle (strongly recommended)

<!-- `eunox doctor` collects everything the Environment + Logs sections ask
     for in one shot — binary identity, redacted config, manifest digests,
     audit log tail with values scrubbed, and (with --live) drift against the
     upstream. Nothing is uploaded; the output prints to your terminal.

     Field-level redaction: `authToken` and `upstreamAuthHeader` are replaced
     with length-only markers, URL credentials are stripped, and `details`
     values inside audit records are blanked. Skim the output for any
     remaining sensitive values before pasting (command-line args, paths,
     etc. are shown verbatim — they are usually load-bearing for diagnosis).

     With a config: eunox doctor --config eunox.yaml --live
     Without:       eunox doctor
     To a file:     eunox doctor --output auto   (writes eunox-doctor-<ts>.txt) -->

<details>
<summary>doctor bundle</summary>

```
```

</details>

## Logs (optional, but very helpful)

<!-- Anything `doctor` did not cover — extra stderr lines, screenshots, etc.
     Redact secrets and the audit `_hmac` field if you don't want to share them. -->

```
```
