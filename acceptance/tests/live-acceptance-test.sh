#!/usr/bin/env bash
# Red/green tests for scripts/live-acceptance.sh.  This test intentionally
# creates only synthetic *schema-valid* evidence; it never makes a release
# claim.  Real releases must use operator-captured, immutable evidence.
set -euo pipefail

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
validator="$root/scripts/live-acceptance.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
expect_failure() {
  local description=$1
  shift
  if "$@" >"$tmp/out" 2>&1; then
    cat "$tmp/out" >&2
    fail "$description unexpectedly passed"
  fi
  grep -F "$description" "$tmp/out" >/dev/null || {
    cat "$tmp/out" >&2
    fail "missing diagnostic: $description"
  }
}

mkdir -p "$tmp/evidence/artifacts" "$tmp/evidence/captures"

for capture in \
  models-direct models-tunnel sse-direct sse-tunnel long-sse-direct long-sse-tunnel \
  tool-direct tool-tunnel reasoning-direct reasoning-tunnel switch-direct switch-tunnel \
  cancel-direct cancel-tunnel error-direct error-tunnel limit-direct limit-tunnel \
  reuse-direct reuse-tunnel cpu-samples server-codesign server-lipo server-runtime \
  client-codesign client-lipo client-runtime; do
  printf '%s capture\\n' "$capture" >"$tmp/evidence/captures/$capture.txt"
done
digest() { shasum -a 256 "$tmp/evidence/$1" | awk '{print $1}'; }
capture_json() { printf '{"path":"captures/%s.txt","sha256":"%s"}' "$1" "$(digest "captures/$1.txt")"; }

cat >"$tmp/evidence/live-application.json" <<JSON
{
  "schema_version": 1,
  "captured_at_utc": "2026-08-14T12:00:00Z",
  "release_id": "candidate-20260814",
  "operator": "release-operator",
  "websocket_required": false,
  "environment": {"client_host": "restricted-mac", "remote_host": "compat-host", "route": "private-lan"},
  "cases": [
    {"id": "models", "direct": {"status": "passed", "capture": $(capture_json models-direct)}, "tunnel": {"status": "passed", "capture": $(capture_json models-tunnel)}},
    {"id": "responses_sse", "direct": {"status": "passed", "capture": $(capture_json sse-direct)}, "tunnel": {"status": "passed", "capture": $(capture_json sse-tunnel)}},
    {"id": "long_sse", "direct": {"status": "passed", "capture": $(capture_json long-sse-direct)}, "tunnel": {"status": "passed", "capture": $(capture_json long-sse-tunnel)}},
    {"id": "tool_round_trip", "direct": {"status": "passed", "capture": $(capture_json tool-direct)}, "tunnel": {"status": "passed", "capture": $(capture_json tool-tunnel)}},
    {"id": "reasoning", "direct": {"status": "passed", "capture": $(capture_json reasoning-direct)}, "tunnel": {"status": "passed", "capture": $(capture_json reasoning-tunnel)}},
    {"id": "model_switching", "direct": {"status": "passed", "capture": $(capture_json switch-direct)}, "tunnel": {"status": "passed", "capture": $(capture_json switch-tunnel)}},
    {"id": "client_cancellation", "direct": {"status": "passed", "capture": $(capture_json cancel-direct)}, "tunnel": {"status": "passed", "capture": $(capture_json cancel-tunnel)}},
    {"id": "upstream_error", "direct": {"status": "passed", "capture": $(capture_json error-direct)}, "tunnel": {"status": "passed", "capture": $(capture_json error-tunnel)}},
    {"id": "rate_limit", "direct": {"status": "passed", "capture": $(capture_json limit-direct)}, "tunnel": {"status": "passed", "capture": $(capture_json limit-tunnel)}},
    {"id": "http_connection_reuse", "direct": {"status": "passed", "capture": $(capture_json reuse-direct)}, "tunnel": {"status": "passed", "capture": $(capture_json reuse-tunnel)}},
    {"id": "websocket", "status": "not_applicable", "reason": "underlying service has supports_websockets = false"}
  ]
}
JSON

cat >"$tmp/evidence/benchmark.json" <<'JSON'
{
  "schema_version": 1,
  "measured_at_unix_seconds": 1786708800,
  "hardware_note": "client and remote hardware recorded in release notes",
  "stream_bytes_each_direction": 67108864,
  "small_flushed_write_bytes": 9,
  "samples_per_path": 20,
  "direct": {"first_byte_p95_us": 5000, "first_byte_samples_us": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,5000], "stream_sent_bytes": 67108864, "stream_received_bytes": 67108864, "bidirectional_throughput_bytes_per_second": 100000000.0},
  "tunnel": {"first_byte_p95_us": 10000, "first_byte_samples_us": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,10000], "stream_sent_bytes": 67108864, "stream_received_bytes": 67108864, "bidirectional_throughput_bytes_per_second": 95000000.0},
  "comparison": {"additional_first_byte_p95_us": 5000, "tunnel_throughput_fraction_of_direct": 0.95},
  "gates": {"additional_first_byte_p95_le_10ms": true, "tunnel_throughput_at_least_90_percent_of_direct": true, "tunnel_owned_memory_per_active_connection_le_1mib": true},
  "memory": {"status": "measured_from_operator_rss_samples", "baseline_rss_kib": 10000, "active_rss_kib": 11024, "active_connections": 1, "tunnel_owned_memory_per_active_connection_kib": 1024}
}
JSON

benchmark_digest=$(digest benchmark.json)
cat >"$tmp/evidence/benchmark-attestation.json" <<JSON
{
  "schema_version": 1,
  "release_id": "candidate-20260814",
  "benchmark_sha256": "$benchmark_digest",
  "route": "private-lan",
  "hardware": {"client": "restricted-mac; Apple Silicon; macOS version recorded", "remote": "compat-host; hardware and macOS version recorded"},
  "rss": {"baseline_samples_kib": [10000,10000,10000,10000,10000], "active_samples_kib": [11024,11024,11024,11024,11024]},
  "cpu_capture": $(capture_json cpu-samples)
}
JSON

printf 'pidstat output\n' >"$tmp/evidence/cpu-samples.txt"
printf 'artifact bytes\n' >"$tmp/evidence/artifacts/secure-tunnel-server"
printf 'artifact bytes\n' >"$tmp/evidence/artifacts/network-sync-agent"
server_digest=$(shasum -a 256 "$tmp/evidence/artifacts/secure-tunnel-server" | awk '{print $1}')
client_digest=$(shasum -a 256 "$tmp/evidence/artifacts/network-sync-agent" | awk '{print $1}')
cat >"$tmp/evidence/artifacts.json" <<JSON
{
  "schema_version": 1,
  "release_id": "candidate-20260814",
  "build_host": "macos-xcode-clt",
  "artifacts": [
    {"role": "server", "path": "artifacts/secure-tunnel-server", "sha256": "$server_digest", "architectures": ["arm64", "x86_64"], "codesign_capture": $(capture_json server-codesign), "lipo_capture": $(capture_json server-lipo), "runtime_smoke_capture": $(capture_json server-runtime)},
    {"role": "client", "path": "artifacts/network-sync-agent", "sha256": "$client_digest", "architectures": ["arm64", "x86_64"], "codesign_capture": $(capture_json client-codesign), "lipo_capture": $(capture_json client-lipo), "runtime_smoke_capture": $(capture_json client-runtime)}
  ]
}
JSON

expect_failure "missing live evidence" "$validator" --evidence-dir "$tmp/absent"
"$validator" --evidence-dir "$tmp/evidence" >"$tmp/success"
grep -F 'ALL EXTERNAL ACCEPTANCE GATES MET' "$tmp/success" >/dev/null || fail 'complete evidence did not pass'

jq '(.gates.tunnel_owned_memory_per_active_connection_le_1mib) = false' "$tmp/evidence/benchmark.json" >"$tmp/changed" && mv "$tmp/changed" "$tmp/evidence/benchmark.json"
expect_failure "benchmark memory gate is not true" "$validator" --evidence-dir "$tmp/evidence"

jq '(.gates.tunnel_owned_memory_per_active_connection_le_1mib) = true' "$tmp/evidence/benchmark.json" >"$tmp/changed" && mv "$tmp/changed" "$tmp/evidence/benchmark.json"
benchmark_digest=$(digest benchmark.json)
jq --arg digest "$benchmark_digest" '.benchmark_sha256 = $digest' "$tmp/evidence/benchmark-attestation.json" >"$tmp/changed" && mv "$tmp/changed" "$tmp/evidence/benchmark-attestation.json"

jq '(.artifacts[0].sha256) = "0000000000000000000000000000000000000000000000000000000000000000"' "$tmp/evidence/artifacts.json" >"$tmp/changed" && mv "$tmp/changed" "$tmp/evidence/artifacts.json"
expect_failure "server artifact SHA-256 does not match" "$validator" --evidence-dir "$tmp/evidence"

printf 'ok\n'
