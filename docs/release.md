# macOS release and atomic installation

These scripts package the tunnel for the binary-only macOS deployment described in the handoff. They run only on macOS and deliberately fail on another OS. The release host needs Xcode Command Line Tools and rustup with both macOS Rust targets; deployed hosts need neither Rust nor the source tree.

## Build a signed universal release

On the controlled release Mac, install the two targets once:

```sh
rustup target add aarch64-apple-darwin x86_64-apple-darwin
```

Choose the signing identity explicitly. The build script will not inspect the keychain to choose one, will not fall back to ad-hoc signing, and rejects `-`.

```sh
release/build-macos-universal.sh \
  --output-dir /private/tmp/codex-tunnel-1.0.0-macos \
  --sign-identity 'Developer ID Application: Example Operator (TEAMID)'
```

The output directory must not already exist. The command builds both `aarch64-apple-darwin` and `x86_64-apple-darwin` variants, combines each with `lipo`, verifies both slices, signs each result, then publishes the complete directory with one rename. It contains:

```text
network-sync-agent       signed universal client artifact
codex-tunnel-server      signed universal server artifact
SHA256SUMS               published SHA-256 digest manifest
```

`network-sync-agent` is intentionally the client release name. It is the generic client installation name required on the restricted Mac; it does not change the wire protocol or conceal network metadata.

Run an independent verification after transferring the release directory:

```sh
release/verify-artifact.sh \
  --artifact-dir /path/to/codex-tunnel-1.0.0-macos \
  --require-identity 'Developer ID Application: Example Operator (TEAMID)'
```

This checks the manifest has exactly the two expected names, validates both SHA-256 values, validates `arm64` and `x86_64` with `lipo`, and performs strict `codesign` verification. Passing `--require-identity` prevents accepting an artifact signed by a different otherwise-valid developer identity. Use it for deployment; omitting it is reserved for an initial diagnostic of an artifact whose expected authority is not yet known.

For Gatekeeper-governed distribution, submit/notarize the final signed release through the operator's normal Apple notarization process before transfer. The scripts do not submit, staple, or otherwise make network-visible signing decisions.

## Install without losing the prior executable

Copy the full release directory, including `SHA256SUMS`, to the target Mac. Create its config/key files and validate them before changing the executable as documented in [operations.md](operations.md). The installer makes no launchd decision: boot out the relevant job first if the operator requires a quiescent upgrade, then bootstrap it again after a successful install.

Client example:

```sh
release/install-atomic.sh \
  --artifact-dir /path/to/codex-tunnel-1.0.0-macos \
  --binary network-sync-agent \
  --destination /usr/local/libexec/network-sync-agent \
  --require-identity 'Developer ID Application: Example Operator (TEAMID)'
```

Server example:

```sh
sudo release/install-atomic.sh \
  --artifact-dir /path/to/codex-tunnel-1.0.0-macos \
  --binary codex-tunnel-server \
  --destination /Library/PrivilegedHelperTools/codex-tunnel-server \
  --require-identity 'Developer ID Application: Example Operator (TEAMID)'
```

The destination directory must already exist and the destination basename must match the selected artifact. Before it writes, the installer runs the full release verification. It copies the new executable into the destination directory, validates its digest, universal slices, and signature again, then renames it over the active path atomically. If an active binary exists, it is first signature/slice checked and retained as `PATH.previous` via a hard link; the active pathname therefore never has a gap during replacement. The retained predecessor is the immediate prior version and may be used for a deliberate, separately verified rollback.

Inspect an upgrade without writing any files:

```sh
release/install-atomic.sh \
  --artifact-dir /path/to/codex-tunnel-1.0.0-macos \
  --binary network-sync-agent \
  --destination /usr/local/libexec/network-sync-agent \
  --require-identity 'Developer ID Application: Example Operator (TEAMID)' \
  --dry-run
```

Never replace a binary after a failed digest, slice, or signature check. Do not use `PATH.previous` to bypass normal config/key validation or key-revocation controls.

## Script verification

The scripts have a portable shell contract test that stubs macOS build and signing commands. It first asserts the real scripts reject non-macOS hosts, then exercises successful universal build/manifest/signature verification, tampered-manifest rejection, dry run, and retained-predecessor installation:

```sh
release/tests/release-scripts-test.sh
```

On a release Mac, additionally run the real build and `verify-artifact.sh` commands above. The shell test is not a substitute for a signed release produced with the operator's actual Apple identity.
