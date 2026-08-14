# Key management

## Identity material

Each peer owns a distinct long-term X25519 private key. The client config holds
its `private_key_file` and one active pinned `server_public_key`. The server
holds its `private_key_file` and an explicit `authorized_clients` public-key
allow-list. Provision public keys and independently verified SHA-256
fingerprints out of band; do not learn them from the first tunnel connection.

Generate keys through the binaries rather than low-level crypto tooling:

```sh
codex-tunnel keygen --private-key-file ~/.config/codex-tunnel/client.key
codex-tunnel-server keygen --private-key-file /var/lib/codex-tunnel/server.key
```

Use a dedicated mode-`0700` parent directory. Key generation creates one
missing final parent directory with that mode, but deliberately refuses to
chmod an existing shared or broad directory such as `/tmp`.

Record the public key, fingerprint, owner, creation date, and intended role in
an operator-controlled inventory. Do not record the private material there.
Never put a private key in source control, a command argument, log, crash
report, or binary.

## Storage and permission checks

Private key files and configuration files containing their paths are mode
`0600`; their parent directories are `0700` where practical. The deployment
validator rejects a configured private key unless it is an existing regular file
with mode exactly `0600`:

```sh
deploy/validate-install.sh --client /path/to/client.toml
deploy/validate-install.sh --server /path/to/server.toml
```

Run the validator after each key, config, or release change and before loading
launchd. It deliberately rejects template placeholders.

## Server-key rotation

1. Generate server identity **B** and record its fingerprint out of band.
2. Deploy ingress with the new private key in
   `identity.additional_private_key_files`, retaining **A** as
   `identity.private_key_file`. Ingress supports at most eight total server
   identities. Leave all clients pinning **A** initially.
3. Deploy each client configuration with **B** as its only active pinned server
   key; restart and verify a successful handshake from each managed client.
4. Remove **A** from the ingress accepted identities, restart ingress, and
   verify **B** clients still connect.
5. Remove **A** from all retained configuration, key storage, and inventory
   access records according to the organisation's secure-retention policy.

A client never retries **A** after being configured for **B**. A connection
failure is an error to investigate, not authority to downgrade.

## Client-key rotation

1. Generate client identity **B** on the client host; transfer only B's public
   key/fingerprint to the ingress operator out of band.
2. Add B to `[[authorized_clients]]` while retaining client key **A**.
3. Deploy the client configuration referencing B's private-key file, restart
   the client service, and verify its identity in non-sensitive ingress logs.
4. Remove A from the server allow-list and reload/restart ingress.
5. Confirm A can no longer establish a new session and securely retire A's
   private key after rollback is no longer needed.

## Revocation and compromise

Removing a client public key from the server allow-list prevents future
sessions. Version 1 permits sessions already authenticated with that key to
continue until disconnect; restart ingress to terminate them immediately when
incident response requires it.

For a suspected client-key compromise, remove the key, restart ingress, issue
a replacement, and audit only non-sensitive handshake metadata. For a suspected
server-key compromise, treat every client pin as potentially exposed: create a
new server key, distribute its verified public key out of band, rotate clients,
then retire the compromised identity. Do not attempt an in-band key update.
