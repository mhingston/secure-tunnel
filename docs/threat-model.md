# Threat model

## Security claim

Codex traffic is protected by an application-layer Noise IK channel before it
leaves the local tunnel client. The channel uses X25519, ChaCha20-Poly1305, and
SHA-256 (`Noise_IK_25519_ChaChaPoly_SHA256`). It provides confidentiality,
integrity, server authentication by a pinned public key, and client
authentication by the server allow-list.

Outer TCP/TLS is transport only. TLS 1.3 is implemented as defence in depth but
is not an application identity or confidentiality root. A contract test gives
the client a trusted interception CA, successfully terminates outer TLS, and
shows the interceptor cannot recover request or response markers protected by
Noise.

## Trusted

- The client host, its local tunnel process, and the client static private key.
- The ingress host, its tunnel process, its static private key, and its fixed
  loopback destination.
- An out-of-band process that verifies and provisions public-key fingerprints.
- The existing compatibility service after ingress has authenticated a client.
- The Noise implementation and the host OS protections for private-key files.

## Untrusted

- The network, DNS, routing, and all outer TCP/TLS intermediaries.
- Any TLS certificate chain, including enterprise interception certificates.
- The compatibility-service-facing network before Noise authentication
  completes.
- Ciphertext framing received from the network, including lengths, ordering,
  duplication, truncation, and timing.

## Protected

- Codex prompts, source code, model output, tool inputs/outputs, and the opaque
  HTTP/SSE/WebSocket byte stream.
- Tunnel endpoint identity: a client accepts only its configured server static
  public key; ingress accepts only configured client static public keys.
- Payload integrity: an invalid handshake, record, tag, version, or length
  fails closed before plaintext reaches the compatibility service.

## Not protected

- Connection existence, endpoint IP address, timing, duration, or approximate
  byte counts.
- A compromised client or ingress host, including theft of its current private
  key.
- Denial of service, packet dropping, connection resets, or resource exhaustion
  outside configured limits.
- Plaintext held by Codex or the compatibility service after decryption.

## Operational boundaries

The client listener is loopback-only, normally `127.0.0.1:18787`. The server
has one statically configured destination, normally `127.0.0.1:8787`; it is not
a SOCKS proxy or arbitrary port forwarder. The tunnel never parses, rewrites,
or logs application payloads.

Private keys are separate per peer. There is no shared traffic-encryption key,
password-derived key, or TOFU bootstrap. Compromise response is documented in
[key-management.md](key-management.md).
