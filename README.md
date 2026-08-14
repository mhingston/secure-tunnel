# Codex Secure Tunnel

Codex Secure Tunnel is a native Rust transport layer for an existing Codex
compatibility service. It encrypts an opaque TCP stream with mutually
authenticated Noise IK, so application content remains confidential and
tamper-evident even when outer TLS is intercepted.

It deliberately does not parse HTTP, Responses, SSE, WebSockets, OAuth,
prompts, or model output. The compatibility service remains independently
usable and is the only component that understands those protocols.

## What is deployed

```text
Codex -> 127.0.0.1:18787 -> Noise tunnel -> remote ingress:8443
                                              -> 127.0.0.1:8787 compatibility service
```

The client listener is loopback-only. The ingress accepts only provisioned
client identities and has one fixed loopback destination; it cannot be used as
an arbitrary TCP proxy.

On the current LAN deployment, the remote ingress is `192.168.6.213:8443` and
the firewall permits only the restricted Mac. Codex is configured to use
`http://127.0.0.1:18787/v1`.

## Behaviour away from the LAN

The Mac client is a LaunchAgent that keeps only its loopback listener open. It
does not maintain a background tunnel, poll the remote host, or retry while
idle. If Codex is used away from the LAN, that request attempts the configured
remote address and fails after the configured connection timeout; the agent
continues running and works again when the Mac returns to the LAN.

## Operator quick start

1. Create distinct server and client Noise identities with each binary's
   `keygen` command. Keep private keys and configuration files mode `0600`.
2. Fill in [examples/server.toml](examples/server.toml) and
   [examples/client.toml](examples/client.toml), then validate them with
   `deploy/validate-install.sh`.
3. Run the server on the compatibility-service host and the client as a
   per-user LaunchAgent on the Mac. Use `doctor --config …` on the client to
   verify the real pinned Noise peer before redirecting Codex.
4. Point the Codex provider to the local client listener, never directly to
   the remote compatibility-service port.

The full operational procedures are in [docs/operations.md](docs/operations.md),
[docs/key-management.md](docs/key-management.md), and
[docs/release.md](docs/release.md).

## Security and release notes

- Noise IK with pinned server keys and an ingress client allow-list is the
  security boundary; outer TLS is optional defence in depth.
- The system intentionally does not conceal metadata such as timing, packet
  sizes, destination IP, or the existence of traffic.
- macOS release tooling creates universal, signed artifacts. A Development
  identity is appropriate for controlled local use; distribution requires the
  operator's Developer ID and any applicable notarization process.
- The external acceptance ledger is fail-closed. Local tests and a successful
  restricted-network smoke test do not replace the live corpus and production
  benchmark evidence described in [acceptance/README.md](acceptance/README.md).

## Development

```sh
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
release/tests/release-scripts-test.sh
acceptance/tests/live-acceptance-test.sh
```

See [docs/protocol.md](docs/protocol.md) for framing and compatibility rules,
[docs/threat-model.md](docs/threat-model.md) for the trust boundary, and
[tests/README.md](tests/README.md) for the contract suite.
