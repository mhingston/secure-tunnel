# Operations

## Deployment layout

The client and remote ingress are native Rust binaries. The restricted Mac runs
the client as a per-user LaunchAgent and exposes only `127.0.0.1:18787`. The
remote Mac runs ingress as a LaunchDaemon and forwards only to one configured
loopback TCP service.

The downstream service is not part of the tunnel protocol. A deployment may
point the fixed destination at an application service or at another trusted
loopback service such as a separately managed HTTP or SOCKS forward proxy. See
[composition.md](composition.md).

Use [client.toml](../examples/client.toml) and
[server.toml](../examples/server.toml) as templates. They intentionally contain
placeholders and must fail validation until completed.

Both roles default to at most 32 active sessions and reject a configured limit
above 1,024. This is a per-process resource bound, not an authentication or
network firewall control.

## Choosing the downstream service

The ingress `destination.address` must remain a single loopback address. The
server does not accept a host or port selected by the client and must not be
extended into a general-purpose forward proxy.

For a fixed application service:

```toml
[destination]
address = "127.0.0.1:9000"
```

For a dedicated forward proxy listening locally on the ingress host:

```toml
[destination]
address = "127.0.0.1:3128"
```

In the latter composition, the proxy owns destination routing, DNS behaviour,
authentication, ACLs, egress restrictions, and proxy logging. The tunnel only
authenticates the tunnel peers and transports the opaque TCP stream to that
fixed local service.

Before changing the destination, verify that the intended loopback service is
bound only as broadly as required and that its own access policy is appropriate
for authenticated tunnel clients. The ingress `doctor` command must be able to
connect to the configured destination.

## Binary-only macOS installation

Build and test releases on a separate Mac with Xcode Command Line Tools and
rustup. Build `aarch64-apple-darwin` and `x86_64-apple-darwin` separately and
combine with `lipo` into a signed universal Mach-O. Publish a SHA-256 digest.
The deployed Macs require no source tree, package manager, compiler, or Rust
runtime.

Before replacing an executable, verify its signature and published digest:

```sh
codesign --verify --deep --strict --verbose=2 /path/to/binary
shasum -a 256 /path/to/binary
```

On the client, install the signed binary as the generic
`/usr/local/libexec/network-sync-agent`; this local naming is only operational
hygiene and does not hide network traffic. Store config/key material in
`~/Library/Application Support/NetworkSync/` and logs in
`~/Library/Logs/NetworkSync/`. On ingress, use
`/Library/PrivilegedHelperTools/secure-tunnel-server` and
`/Library/Application Support/SecureTunnel/`.

Create private directories and files before loading services:

```sh
install -d -m 700 "$HOME/Library/Application Support/NetworkSync"
install -d -m 700 "$HOME/Library/Logs/NetworkSync"
chmod 600 "$HOME/Library/Application Support/NetworkSync/client.toml" \
  "$HOME/Library/Application Support/NetworkSync/client.key"
sudo install -d -o root -g wheel -m 700 "/Library/Application Support/SecureTunnel"
sudo chmod 600 "/Library/Application Support/SecureTunnel/server.toml" \
  "/Library/Application Support/SecureTunnel/server.key"
```

Outer TLS is optional defence in depth. When enabled, both tunnel binaries use
TLS 1.3 and the client validates the configured DNS server name with its normal
system trust roots. There is no certificate-verification bypass. The client may
append `outer_tls.additional_ca_file` only for the TLS-interception test
harness; it does not replace or disable system roots. The server's TLS private
key is mode `0600`; its certificate may be world-readable. Noise remains
mandatory inside TLS and is the application identity and confidentiality
boundary whether outer TLS is enabled or disabled.

## Validate and load launchd

Copy the supplied plists from `deploy/`, replace their username placeholders,
and validate their syntax with `plutil -lint`. Validate completed configs before
loading:

```sh
deploy/validate-install.sh --client "$HOME/Library/Application Support/NetworkSync/client.toml"
sudo deploy/validate-install.sh --server "/Library/Application Support/SecureTunnel/server.toml"
plutil -lint deploy/com.example.network-sync-agent.plist
plutil -lint deploy/com.example.secure-tunnel-server.plist
```

Install the client plist at `~/Library/LaunchAgents/` and load it into the GUI
domain. Install the server plist at `/Library/LaunchDaemons/` (root:wheel,
mode `0644`) and load it into the system domain:

```sh
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.example.network-sync-agent.plist"
sudo launchctl bootstrap system /Library/LaunchDaemons/com.example.secure-tunnel-server.plist
```

For changes, use `launchctl bootout` for the corresponding domain before
`bootstrap` again. Both plists set `RunAtLoad` and `KeepAlive`; the binaries
must validate key/config permissions at startup and terminate cleanly on
SIGTERM.

## Update and rollback

Keep the previous signed binary beside the active binary, for example
`network-sync-agent.previous` and `secure-tunnel-server.previous`. Verify the
new universal binary before installation, stop the service, then use `mv` on
the same volume for an atomic replacement. Retain the previous config/key pair
only when it remains valid for the current rotation overlap.

If the update fails, boot out the job, atomically restore the previous signed
binary, revalidate its digest/signature and configuration, then bootstrap it.
Do not roll back a server binary/configuration in a way that re-authorises a
revoked client key or reintroduces a retired compromised server identity.

## Routine checks and incident response

Run the binary's `doctor` command after deployment. The client doctor binds its
configured loopback address temporarily and performs a real outer-transport
and pinned Noise handshake to the configured ingress; it sends no application
payload. The ingress doctor checks its own listener and fixed destination
directly. Review only structured, non-sensitive JSON logs/metrics: active
connections, handshake result, decrypt failures, destination-connect failures,
bytes, and close reason. Never enable payload logging for debugging. Both
`serve` and `doctor` reject a configuration file with group or world access;
install configuration and private-key files as mode `0600`.

For an unknown-client, wrong-server-key, malformed-frame, or AEAD error, expect
a closed connection and no plaintext forwarding. Investigate the peer identity
and network path; do not enable a fallback or TOFU mode. Follow the explicit
rotation/revocation runbooks in [key-management.md](key-management.md) for key
incidents.
