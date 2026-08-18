# Threat model

## Security claim

Application traffic is protected by an application-layer Noise IK channel
before it leaves the local tunnel client. The channel uses X25519,
ChaCha20-Poly1305, and SHA-256 (`Noise_IK_25519_ChaChaPoly_SHA256`). It provides
confidentiality, integrity, server authentication by a pinned public key, and
client authentication by the server allow-list.

The tunnel protects an opaque TCP byte stream and is not coupled to Codex,
HTTP, SOCKS, or any other application protocol. The current Codex deployment is
one use of this transport rather than part of its security protocol.

Outer TCP/TLS is transport only. TLS 1.3 is implemented as defence in depth but
is not an application identity or confidentiality root. A contract test gives
the client a trusted interception CA, successfully terminates outer TLS, and
shows the interceptor cannot recover request or response markers protected by
Noise.

## Trusted

- The client host, its local tunnel process, and the client static private key.
- The ingress host, its tunnel process, its static private key, and its fixed
  loopback destination.
- The operator-selected loopback service after ingress has authenticated a
  client. In the original deployment this is the Codex compatibility service;
  in another composition it may be a dedicated forward proxy.
- An out-of-band process that verifies and provisions public-key fingerprints.
- The Noise implementation and the host OS protections for private-key files.

## Untrusted

- The network, DNS, routing, and all outer TCP/TLS intermediaries.
- Any TLS certificate chain, including enterprise interception certificates.
- The downstream-service-facing path before Noise authentication completes.
- Ciphertext framing received from the network, including lengths, ordering,
  duplication, truncation, and timing.
- Any Internet destination reached by a downstream forward proxy unless that
  destination is independently trusted by the application.

## Protected

- Application payloads carried in the opaque TCP stream. In the Codex
  deployment this includes prompts, source code, model output, tool
  inputs/outputs, and HTTP/SSE/WebSocket bytes. In a proxy composition this
  includes the proxy protocol stream between the local application and the
  ingress host.
- Tunnel endpoint identity: a client accepts only its configured server static
  public key; ingress accepts only configured client static public keys.
- Payload integrity: an invalid handshake, record, tag, version, or length
  fails closed before plaintext reaches the configured loopback service.

## Not protected

- Connection existence, endpoint IP address, timing, duration, or approximate
  byte counts.
- A compromised client or ingress host, including theft of its current private
  key.
- A compromised or misconfigured downstream loopback service.
- Destination selection, DNS policy, ACLs, or Internet egress performed by a
  downstream forward proxy; those are the proxy's security responsibilities.
- Denial of service, packet dropping, connection resets, or resource exhaustion
  outside configured limits.
- Plaintext held by the application or downstream loopback service after
  decryption.

## Operational boundaries

The client listener is loopback-only, normally `127.0.0.1:18787`. The server
has one statically configured loopback destination, normally
`127.0.0.1:8787` in the Codex deployment. It is not a SOCKS proxy, HTTP forward
proxy, or arbitrary port forwarder. The tunnel never parses, rewrites, or logs
application payloads.

Generic egress is composed by placing a separately managed forward proxy at the
fixed loopback destination. That proxy, not the tunnel server, interprets
client-supplied destination information and applies egress policy. The tunnel
protocol must not acquire a client-supplied host/port field merely to support
this composition.

Private keys are separate per peer. There is no shared traffic-encryption key,
password-derived key, or TOFU bootstrap. Compromise response is documented in
[key-management.md](key-management.md).
