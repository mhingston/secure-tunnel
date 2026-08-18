# Codex Secure Tunnel

Codex Secure Tunnel is a native Rust application-layer transport that carries an
opaque TCP stream over a mutually authenticated Noise IK channel. It was built
for a Codex compatibility-service deployment, but the tunnel itself is not
Codex-specific: it does not parse HTTP, Responses, SSE, WebSockets, OAuth,
prompts, model output, or proxy protocols.

Its security boundary is intentionally narrow:

- the client exposes a loopback-only TCP listener;
- the client authenticates one pinned tunnel server identity;
- the server authenticates provisioned client identities; and
- after decryption, the server connects only to one operator-configured
  **loopback destination**.

The server never accepts a destination selected by the tunnel client. It is not
a SOCKS server, HTTP forward proxy, or arbitrary TCP port forwarder.

## Core architecture

```text
application -> 127.0.0.1:18787 -> Noise tunnel -> remote ingress:8443
                                                   -> fixed loopback service
```

The fixed loopback service is deliberately outside the tunnel's concerns. It
may be the original Codex compatibility service, a forward proxy, or another
operator-controlled TCP service.

The current Codex deployment is therefore one composition of the generic
transport:

```text
Codex -> 127.0.0.1:18787 -> Noise tunnel -> remote ingress:8443
                                              -> 127.0.0.1:8787 compatibility service
```

## Composing with a forward proxy

A generic forward-proxy deployment does **not** require proxy functionality in
the tunnel server. Run a normal proxy on the remote host's loopback interface
and configure the tunnel server's fixed destination to point at it:

```text
HTTP/SOCKS-capable application
          |
          v
  127.0.0.1:18787
          |
          | opaque Noise-protected TCP
          v
   remote tunnel ingress
          |
          v
   127.0.0.1:3128
          |
          v
   forward proxy
          |
          v
       Internet
```

For example, when the downstream service is an HTTP forward proxy, an
application can use `http://127.0.0.1:18787` as its proxy endpoint. HTTP proxy
requests, including `CONNECT`, pass through the tunnel as opaque bytes and are
interpreted only by the downstream proxy.

This separation keeps destination selection, DNS behaviour, ACLs,
authentication, logging policy, and Internet egress in the forward proxy where
they belong. The tunnel remains responsible only for authenticated encrypted
transport to one fixed local service.

See [docs/composition.md](docs/composition.md) for deployment patterns and the
trust-boundary implications.

## What is deployed today

On the current LAN deployment, the remote ingress is `192.168.6.213:8443`, the
fixed destination is the Codex compatibility service on `127.0.0.1:8787`, and
the firewall permits only the restricted Mac. Codex is configured to use
`http://127.0.0.1:18787/v1`.

The client listener is loopback-only. The server destination is also constrained
to loopback by configuration validation, so changing the downstream service
does not turn the tunnel itself into an arbitrary network proxy.

## Behaviour away from the LAN

The Mac client is a LaunchAgent that keeps only its loopback listener open. It
does not maintain a background tunnel, poll the remote host, or retry while
idle. If an application uses the local listener away from the LAN, that request
attempts the configured remote address and fails after the configured
connection timeout; the agent continues running and works again when the Mac
returns to the LAN.

## Operator quick start

1. Create distinct server and client Noise identities with each binary's
   `keygen` command. Keep private keys and configuration files mode `0600`.
2. Fill in [examples/server.toml](examples/server.toml) and
   [examples/client.toml](examples/client.toml), then validate them with
   `deploy/validate-install.sh`.
3. Run the server on the ingress host and the client as a per-user LaunchAgent
   on the Mac. Use `doctor --config ...` on the client to verify the real pinned
   Noise peer before redirecting an application to the local listener.
4. Configure the server destination as one trusted loopback TCP service. If
   broader egress is required, make that service a separately managed forward
   proxy rather than adding destination routing to the tunnel protocol.

The full operational procedures are in [docs/operations.md](docs/operations.md),
[docs/key-management.md](docs/key-management.md), and
[docs/release.md](docs/release.md).

## Security and release notes

- Noise IK with pinned server keys and an ingress client allow-list is the
  security boundary; outer TLS is optional defence in depth.
- The server's fixed loopback destination is a deliberate confinement boundary.
  Do not add a client-supplied host/port field to the tunnel protocol to support
  forward-proxy use cases.
- A downstream forward proxy is a separate trust and policy boundary. Its ACLs,
  authentication, destination restrictions, DNS behaviour, and logging are not
  enforced by the tunnel.
- The system intentionally does not conceal metadata such as timing, packet
  sizes, destination ingress IP, or the existence of traffic.
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
