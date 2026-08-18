# Composing the tunnel with downstream services

## Principle

The tunnel transports one opaque TCP stream between a loopback-only client
listener and one fixed loopback service on the ingress host. It intentionally
does not interpret the application protocol or accept a destination requested
by the client.

Keep those responsibilities separate:

```text
application protocol        secure transport             downstream policy
        |                         |                              |
        v                         v                              v
 local application -> tunnel client -> tunnel server -> fixed loopback service
```

The downstream service owns whatever application semantics are required after
the authenticated encrypted channel terminates.

## Codex compatibility-service composition

The original deployment terminates the tunnel at the compatibility service:

```text
Codex -> localhost tunnel client -> Noise -> tunnel ingress
                                              |
                                              v
                                   127.0.0.1:8787
                                              |
                                              v
                                  compatibility service
```

The tunnel does not know that the byte stream contains Codex HTTP, Responses,
SSE, WebSocket, or OAuth traffic.

## Forward-proxy composition

To provide generic forward-proxy egress, run a dedicated forward proxy on the
ingress host and configure that proxy's loopback listener as the tunnel's fixed
destination:

```text
application
    |
    | HTTP proxy or SOCKS protocol
    v
127.0.0.1:18787
    |
    | Noise-protected opaque TCP
    v
remote tunnel ingress
    |
    | fixed loopback connection
    v
127.0.0.1:3128
    |
    v
forward proxy
    |
    +----> permitted destination A
    +----> permitted destination B
    `----> denied destination C
```

For an HTTP forward proxy, configure the application to use the local tunnel
listener as its HTTP/HTTPS proxy endpoint. The application generates ordinary
proxy requests such as `CONNECT example.com:443`; the tunnel carries those
bytes without parsing them; the downstream proxy interprets the request and
applies its policy.

A SOCKS deployment follows the same composition provided the application
speaks SOCKS to the local tunnel listener and the downstream service is a SOCKS
proxy. The tunnel itself remains unaware of SOCKS addressing.

## Why the tunnel server must not become the proxy

Do not extend the encrypted transport protocol with a client-supplied hostname,
IP address, or port merely to support generic egress. That would move
client-directed routing into the tunnel server and weaken the existing
confinement boundary.

Keeping the destination static provides useful properties:

- compromise or misuse of an authorised tunnel client cannot make the ingress
  connect directly to arbitrary network destinations;
- the tunnel's protocol and security review remain independent of HTTP, SOCKS,
  DNS, and proxy-routing semantics;
- egress ACLs, authentication, destination restrictions, DNS policy, and logs
  can be implemented by a mature proxy without duplicating that functionality;
- the downstream service can be replaced without changing the encrypted
  transport protocol.

The server configuration must therefore continue to reject non-loopback
`destination.address` values.

## Trust boundaries

The Noise channel protects application bytes only between the tunnel client and
tunnel server. Once decrypted, bytes are delivered to the configured loopback
service in plaintext TCP on the ingress host.

When that service is a forward proxy:

- the proxy becomes trusted with the decrypted proxy protocol stream;
- destination selection and Internet egress are the proxy's responsibility;
- proxy authentication and ACLs are defence in depth even though the tunnel
  already authenticates clients;
- payload logging should remain disabled unless there is an explicit reason to
  accept that confidentiality trade-off;
- the tunnel does not hide connection timing, approximate traffic volume, or
  the ingress endpoint from the outer network.

The ingress firewall remains an independent control and should restrict access
to the tunnel listener to the intended client population where practical.

## Configuration example

For the original compatibility service:

```toml
[destination]
address = "127.0.0.1:8787"
```

For a separately managed forward proxy listening on loopback:

```toml
[destination]
address = "127.0.0.1:3128"
```

No tunnel protocol or routing change is required between these compositions.
