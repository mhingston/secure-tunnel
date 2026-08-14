# External acceptance ledger and evidence runbook

This directory intentionally contains no release evidence. It specifies the
remaining external gates from `additional-layer.md` §§38, 39, 45, 50, and 53.
Store a real bundle in controlled release storage, not in Git, then validate
it with:

```sh
scripts/live-acceptance.sh --evidence-dir /secure/release-evidence/RELEASE_ID
```

The command validates evidence; it does not independently reproduce it. A
passing result means the supplied bundle has the required fields, hashes, and
cross-file consistency. The release owner remains responsible for ensuring
captures came from the stated systems and were access-controlled after capture.

## Ledger

| ID | Requirement | Evidence | State in this repository |
| --- | --- | --- | --- |
| LIVE-1 | Existing compatibility service works directly and through the tunnel without semantic changes | `live-codex.json` and hashed captures | Unmet: needs live subscription/deployment. |
| PERF-1 | Same-hardware/route benchmark meets §39 latency, throughput, and memory gates | Harness `benchmark.json` plus RSS/CPU attestation | Unmet: needs production hardware and live route. |
| MAC-1 | Both deployable components are signed universal macOS binaries that run without source/compiler/runtime | `artifacts.json`, artifacts, command captures | Unmet: needs a macOS signing/release host. |

## Bundle layout

```text
RELEASE_ID/
  live-codex.json
  benchmark.json
  benchmark-attestation.json
  artifacts.json
  captures/…
  artifacts/codex-tunnel-server
  artifacts/network-sync-agent
```

All `path` fields below are relative to this directory, name a regular file,
and are paired with a lower-case 64-hex `sha256`. Hash each capture after it is
complete with `shasum -a 256 FILE` (macOS) or `sha256sum FILE` (Linux).

## LIVE-1: direct-versus-tunnel Codex capture

On the restricted Mac, use the same Codex release, account/workspace,
compatibility-service deployment, request corpus, and client settings twice:

1. Directly against the compatibility service.
2. Through the tunnel client at `127.0.0.1:18787`.

For every passed path, save a redacted capture that records command/version,
endpoint mode, request identifier, start/end time, and assertions. Never save
authorization headers, OAuth state, prompts, source code, or model output.

`live-codex.json` is version 1 and contains:

```json
{
  "schema_version": 1,
  "captured_at_utc": "RFC3339 timestamp",
  "release_id": "immutable release identifier",
  "operator": "responsible operator",
  "websocket_required": false,
  "environment": {
    "client_host": "hardware and OS identifier",
    "remote_host": "hardware and OS identifier",
    "route": "private-lan or documented route"
  },
  "cases": [
    {
      "id": "models",
      "direct": {"status": "passed", "capture": {"path": "captures/models-direct.txt", "sha256": "…"}},
      "tunnel": {"status": "passed", "capture": {"path": "captures/models-tunnel.txt", "sha256": "…"}}
    }
  ]
}
```

Required `id` values are `models`, `responses_sse`, `long_sse`,
`tool_round_trip`, `reasoning`, `model_switching`, `client_cancellation`,
`upstream_error`, `rate_limit`, and `http_connection_reuse`. Each must occur
once and have `passed` direct and tunnel results. If WebSockets are enabled in
the compatibility service, set `websocket_required` to `true` and provide the
same two passed captures for `websocket`. If they are disabled, set it to
`false` and add exactly one `websocket` case with
`{"status":"not_applicable","reason":"…"}`.

## PERF-1: real route, hardware, RSS, and CPU evidence

First produce `benchmark.json` with the release candidate harness, exactly as
described in [`docs/benchmarking.md`](../docs/benchmarking.md). It must be the
fresh output of `codex-tunnel-bench run`, not handwritten JSON. The validator
requires its schema version 1, 20 or more samples per path, a 67,108,864-byte
stream in both directions, a 9-byte promptly-flushed write, all three true
gates, measured RSS, and arithmetic matching the reported values.

At the same time collect the documented five median inputs and CPU output.
Create `benchmark-attestation.json`:

```json
{
  "schema_version": 1,
  "release_id": "same release_id as live-codex.json",
  "benchmark_sha256": "SHA-256 of benchmark.json",
  "route": "private-lan",
  "hardware": {
    "client": "model, CPU architecture, RAM, OS version",
    "remote": "model, CPU architecture, RAM, OS version"
  },
  "rss": {
    "baseline_samples_kib": [100, 100, 100, 100, 100],
    "active_samples_kib": [200, 200, 200, 200, 200]
  },
  "cpu_capture": {"path": "captures/cpu.txt", "sha256": "…"}
}
```

The median (third sorted item) of each five-value list must equal the baseline
and active RSS in `benchmark.json`. The CPU capture must show five process
samples for tunnel client and ingress during the same active-connection window;
it has no numeric threshold, but it is mandatory release evidence. Preserve
the actual endpoints, active connection count, process IDs, methodology, and
any route deviation in the capture/release record.

## MAC-1: signed universal binaries

On the macOS release host, build both architectures, combine with `lipo`, sign
the final universal files, and copy the final binaries—not intermediate slices—
into `artifacts/`. Capture and hash output of these commands for both roles:

```sh
lipo -archs artifacts/codex-tunnel-server
codesign --verify --strict --verbose=4 artifacts/codex-tunnel-server
./artifacts/codex-tunnel-server --help
```

Repeat for the client artifact (named `network-sync-agent` on the restricted
Mac). The runtime capture must be taken on the clean binary-only target and
record that it launched without source code, a compiler, or a language runtime.
Notarization is additionally required where Gatekeeper policy applies; retain
that output with the release notes.

`artifacts.json` is version 1:

```json
{
  "schema_version": 1,
  "release_id": "same release_id as live-codex.json",
  "build_host": "macOS version and Xcode CLT version",
  "artifacts": [
    {
      "role": "server",
      "path": "artifacts/codex-tunnel-server",
      "sha256": "published SHA-256 of final binary",
      "architectures": ["arm64", "x86_64"],
      "codesign_capture": {"path": "captures/server-codesign.txt", "sha256": "…"},
      "lipo_capture": {"path": "captures/server-lipo.txt", "sha256": "…"},
      "runtime_smoke_capture": {"path": "captures/server-runtime.txt", "sha256": "…"}
    }
  ]
}
```

Include exactly one `server` and one `client` record. The validator ensures the
published binary digest matches the stored binary and all supporting captures
are present and hashed. Inspect the captured macOS command output as part of
the release review; a manifest cannot cryptographically replace `codesign`.

