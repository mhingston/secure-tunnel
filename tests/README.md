# Test fixtures

## Local transport contracts

`integration/security_integration.rs` is the transport security-contract suite.
It starts the released tunnel binaries against loopback-only fixture services;
it does not need the pre-existing Codex compatibility service or ChatGPT
credentials. Run it with:

```sh
cargo build -p codex-tunnel-client -p codex-tunnel-server
cargo test -p codex-tunnel-integration
```

`compatibility/` is a separate local byte-transparency contract. Its fixture
destination performs only exact reads and writes. It does **not** parse,
normalise, or reconstruct HTTP, Responses, SSE, tool/reasoning, or WebSocket
data, and neither do the tunnel binaries. Every fixture conversation runs twice:

```text
direct local TCP fixture destination
tunnel client → tunnel ingress → same local TCP fixture destination
```

The harness asserts exact fixture bytes for both paths and exact equality
between them. It covers:

* models-like HTTP;
* normal SSE;
* a deliberately split, long SSE response (the first fragment must arrive
  before the fixture makes its remaining bytes available);
* native tool-call and reasoning-shaped payload bytes;
* canned cancellation (`499`), upstream-error (`502`), and rate-limit (`429`)
  responses; and
* a real client-disconnect contract: after an opaque cancellation request, the
  client closes before a deliberately delayed destination response.  The
  destination must observe EOF/connection close before that response deadline
  both directly and through the tunnel, so the response is suppressed rather
  than continuing through a stale tunnel session;
* WebSocket-like upgrade and message bytes; and
* two opaque exchanges on a single reused TCP connection.

Run it with:

```sh
cargo build -p codex-tunnel-client -p codex-tunnel-server
cargo test -p codex-tunnel-compatibility --test compatibility
```

These are local deterministic transport tests, not evidence that a stock Codex
CLI works against ChatGPT. They deliberately contain no credentials, live
OAuth, or real compatibility-service behaviour. Production acceptance still
requires the already-authorised compatibility-service E2E scenarios to run
against the actual deployment directly and then through the tunnel, comparing
the captured raw bytes for the same cases. That live validation is externally
provisioned and must not be replaced by these canned fixtures.

## TLS-MITM contract

The security suite also includes the TLS-MITM contract. It uses a test CA
appended to (not substituted for) client system roots, terminates TLS 1.3 on
both relay legs, records decrypted TLS application data, and proves unique
request and response markers remain absent. Production configuration has no
certificate-verification bypass.
