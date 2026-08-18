# Encrypted transport protocol

## Scope

Version 1 carries one opaque, bidirectional TCP byte stream. It does not know
about HTTP, SSE, WebSockets, OAuth, SOCKS, forward-proxy semantics, or
destinations selected by a client.

Application protocols are deliberately outside the encrypted transport. The
server terminates the Noise channel and connects the recovered byte stream to
one operator-configured loopback TCP service.

## Handshake

The client initiates an outer TCP connection. The deployment may use TCP only
or TLS 1.3 over that TCP connection. After the optional TLS handshake it writes:

```text
"CDXT" | major:u8 | minor:u8
```

This clear preface is the Noise prologue. The peers then exchange Noise IK
handshake messages, each preceded by an unsigned 16-bit big-endian length.
Handshake messages over 4 KiB, malformed prefaces, and unsupported major
versions terminate the connection before the ingress opens its destination.

When enabled, Rustls is restricted to TLS 1.3. The client validates a configured
DNS server name against its system roots; a test-only additional CA file may be
appended for the interception fixture. There is no insecure-verification mode.
TLS never determines application peer identity: Noise IK remains mandatory
inside either outer mode. The interception contract test proves a trusted test
CA can terminate outer TLS while it cannot recover the Noise-protected payload.

The client has its own static private key and pins one active server public
key. The server has its own static private key (or a bounded overlapping set
during server-key rotation) and authorises the client's static public key from
its allow-list. TLS names and certificate authorities never decide Noise peer
trust.

On success, the Noise cipher states supply independent directional AEAD keys
and monotonically advancing nonces. Failed authentication is terminal; there
is no downgrade, retry with another server key, or unauthenticated plaintext.

## Destination model

The encrypted protocol contains no destination-routing message. The client
cannot request a hostname, IP address, or port. After a successful Noise
handshake, ingress connects solely to the one loopback `destination.address`
provided by server configuration.

This is a protocol invariant, not merely a deployment convention. Generic
forward-proxy use cases are composed by making that fixed loopback service a
separately managed HTTP or SOCKS proxy. Any `CONNECT`, SOCKS address, DNS name,
or other routing information remains part of the opaque application byte
stream and is interpreted only by the downstream proxy.

Adding a client-supplied destination to the tunnel protocol would change the
security boundary and requires a new protocol design and threat model; it must
not be introduced as a convenience change for proxy composition.

## Transport records

After the handshake, each direction is a sequence of:

```text
ciphertext_length:u32be | ciphertext
```

`ciphertext_length` includes the 16-byte ChaCha20-Poly1305 tag. A record may
contain at most 16,384 plaintext bytes and 16,400 ciphertext bytes. Validate
the advertised length before allocation. TCP writes may be split or coalesced;
record boundaries are not socket-write boundaries.

The only Version 1 record type is payload. Send partial records promptly so a
flushed streaming response is not held until a 16 KiB buffer fills. Backpressure
must be bounded and propagate through the stream rather than buffering an
entire response.

All local, outer, and destination TCP sockets enable ordinary OS TCP keepalive.
This is connection liveness support, not an encrypted application keepalive or
traffic-shaping mechanism.

## Failure and closure

Unexpected EOF, invalid lengths, version mismatch, unknown client identity,
wrong pinned server identity, nonce exhaustion, and AEAD failure close the
session. Corrupted data is discarded and no further record is attempted with
that cipher state. Version 1 performs a full bidirectional close when either
side reaches EOF; it does not forward half-closes.

Noise's per-session cipher state rejects replayed or altered records within a
session and records from another session. Version 1 intentionally has no rekey
or maximum session duration; a future rekey design requires a new protocol
version, not an implicit compatibility change.

## Compatibility and versioning

The protocol version describes this encrypted transport only, not any
application release or downstream service. Unknown major versions fail with a
diagnostic. Minor versions may add only explicitly negotiated compatible
behavior. Transport configuration has no host/port requested by the client:
ingress connects solely to its configured loopback service.

The `CDXT` preface is retained as the Version 1 wire magic for compatibility
with existing tunnel peers. It does not define or constrain payload semantics.
Changing the preface would be a protocol compatibility change and therefore
requires an explicit new protocol version rather than a project-naming change.

## Key rotation rule

During a server-key overlap, ingress tries its bounded configured static-key
set (at most eight private identities) for the single initial IK frame, but
every client uses exactly its configured active server key. A client must never
fall back from a newly configured key to the old key after a failure, because
that enables downgrade attacks. See
[key-management.md](key-management.md).
