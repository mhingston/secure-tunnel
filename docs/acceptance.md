# External release acceptance

The repository tests prove the transport implementation. They cannot prove a
specific restricted Mac, compatibility-service deployment, production route,
or macOS release artifact. Those remaining criteria are fail-closed: no
evidence bundle is checked in, and they remain **unmet** until an operator
captures the evidence below on the release candidate.

Run the validator only against a retained, release-specific directory outside
the source tree:

```sh
scripts/live-acceptance.sh --evidence-dir /secure/release-evidence/2026-08-14
```

It never runs application, benchmarks a route, signs software, or declares that an
environment was tested. It checks that supplied evidence is complete, tied to
the same release, and has not changed since its manifest was written. A
non-zero exit and `UNMET:` lines are the only valid result for absent,
incomplete, failed, or inconsistent evidence.

See [the acceptance ledger](../acceptance/README.md) for the exact JSON
schemas and capture procedure.

## Required external gates

| Gate | Required evidence | Validator outcome |
| --- | --- | --- |
| Live application transparency | `live-application.json`, with immutable direct and tunnel captures for every supported case | All required cases must pass in both paths. |
| Production performance | Harness-produced `benchmark.json` plus `benchmark-attestation.json` with real hardware, five idle/active RSS samples, and CPU capture | 64 MiB/full-duplex, prompt-write, latency, throughput, and RSS gates must all be true and internally consistent. |
| Signed universal macOS artifacts | `artifacts.json`, each universal binary, and captured `codesign`, `lipo`, and binary-only smoke-test output | Server and client must each have arm64/x86_64, an attested digest, and all three captures. |

The `release_id` in live, benchmark-attestation, and artifact manifests must
match. The benchmark attestation SHA-256 binds the generated `benchmark.json`
to that release. Each referenced capture and artifact uses a relative path and
must have a matching SHA-256; absolute paths, traversal, symlinks, missing
files, and stale hashes are rejected.

## What not to claim

Do not call a release complete merely because unit/integration tests or
synthetic validator tests pass. Do not replace live application traffic with fixture
tests, a benchmark responder on a different machine, a CI RSS measurement, or
a claimed macOS signature without the captured command output and final binary.
Keep OAuth tokens, prompts, model output, private keys, and proxy credentials
out of captures. Record redacted request identifiers and deterministic
assertions instead.
