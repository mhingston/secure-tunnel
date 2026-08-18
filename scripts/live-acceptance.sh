#!/usr/bin/env bash
# Validate operator-captured, external release evidence.  This script does not
# run application, benchmark a route, sign a binary, or manufacture a release claim.
# It only accepts a complete, internally consistent evidence bundle.
set -uo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/live-acceptance.sh --evidence-dir DIRECTORY

Validate the external acceptance evidence described in docs/acceptance.md.
The directory must contain live-application.json, benchmark.json,
benchmark-attestation.json, artifacts.json, and every capture referenced by
those manifests. The command exits non-zero and prints every unmet gate.
USAGE
}

evidence_dir=''
while (($#)); do
  case "$1" in
    --evidence-dir)
      (($# >= 2)) || { usage >&2; exit 2; }
      evidence_dir=$2
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$evidence_dir" ]]; then
  usage >&2
  exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
  printf 'UNMET: jq is required to validate acceptance evidence\n' >&2
  exit 2
fi
if command -v shasum >/dev/null 2>&1; then
  sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
elif command -v sha256sum >/dev/null 2>&1; then
  sha256_file() { sha256sum "$1" | awk '{print $1}'; }
else
  printf 'UNMET: shasum or sha256sum is required to validate acceptance evidence\n' >&2
  exit 2
fi

unmet_count=0
unmet() {
  printf 'UNMET: %s\n' "$*" >&2
  unmet_count=$((unmet_count + 1))
}

if [[ ! -d "$evidence_dir" ]]; then
  unmet 'missing live evidence directory'
  printf 'EXTERNAL ACCEPTANCE INCOMPLETE: %d unmet gate(s)\n' "$unmet_count" >&2
  exit 1
fi
root_real=$(CDPATH= cd -P -- "$evidence_dir" 2>/dev/null && pwd -P || true)
if [[ -z "$root_real" ]]; then
  unmet 'evidence directory cannot be resolved'
  printf 'EXTERNAL ACCEPTANCE INCOMPLETE: %d unmet gate(s)\n' "$unmet_count" >&2
  exit 1
fi

manifest_path() {
  printf '%s/%s' "$root_real" "$1"
}

require_json() {
  local name=$1 path
  path=$(manifest_path "$name")
  if [[ ! -f "$path" || -L "$path" ]]; then
    unmet "missing ${name}"
    return 1
  fi
  if ! jq -e . "$path" >/dev/null 2>&1; then
    unmet "${name} is not valid JSON"
    return 1
  fi
  return 0
}

require_capture() {
  local label=$1 rel=$2 expected=$3 candidate parent_real resolved actual
  case "$rel" in
    ''|/*|.|..|../*|*/../*|*/..)
      unmet "${label} has an unsafe evidence path"
      return
      ;;
  esac
  if [[ ! "$expected" =~ ^[[:xdigit:]]{64}$ ]]; then
    unmet "${label} has no valid SHA-256"
    return
  fi
  candidate="$root_real/$rel"
  if [[ ! -f "$candidate" || -L "$candidate" ]]; then
    unmet "${label} evidence file is missing: ${rel}"
    return
  fi
  parent_real=$(CDPATH= cd -P -- "$(dirname -- "$candidate")" 2>/dev/null && pwd -P || true)
  resolved="$parent_real/$(basename -- "$candidate")"
  if [[ "$resolved" != "$root_real/"* ]]; then
    unmet "${label} evidence path escapes the evidence directory"
    return
  fi
  actual=$(sha256_file "$resolved")
  if [[ "$actual" != "$expected" ]]; then
    unmet "${label} SHA-256 does not match"
  fi
}

require_capture_object() {
  local file=$1 selector=$2 label=$3 path digest
  path=$(jq -r "$selector.path // empty" "$file")
  digest=$(jq -r "$selector.sha256 // empty" "$file")
  require_capture "$label" "$path" "$digest"
}

live=''
benchmark=''
attestation=''
artifacts=''
if require_json live-application.json; then live=$(manifest_path live-application.json); fi
if require_json benchmark.json; then benchmark=$(manifest_path benchmark.json); fi
if require_json benchmark-attestation.json; then attestation=$(manifest_path benchmark-attestation.json); fi
if require_json artifacts.json; then artifacts=$(manifest_path artifacts.json); fi

required_cases=(
  models responses_sse long_sse tool_round_trip reasoning model_switching
  client_cancellation upstream_error rate_limit http_connection_reuse
)

if [[ -n "$live" ]]; then
  if ! jq -e '
    .schema_version == 1 and
    (.captured_at_utc | type == "string" and length > 0) and
    (.release_id | type == "string" and length > 0) and
    (.operator | type == "string" and length > 0) and
    (.websocket_required | type == "boolean") and
    (.environment.client_host | type == "string" and length > 0) and
    (.environment.remote_host | type == "string" and length > 0) and
    (.environment.route | type == "string" and length > 0) and
    (.cases | type == "array")
  ' "$live" >/dev/null; then
    unmet 'live-application.json has missing required fields'
  else
    for case_id in "${required_cases[@]}"; do
      if ! jq -e --arg id "$case_id" '
        ([.cases[] | select(.id == $id)] | length == 1) and
        ([.cases[] | select(.id == $id)][0] |
          .direct.status == "passed" and .tunnel.status == "passed" and
          (.direct.capture.path | type == "string") and
          (.direct.capture.sha256 | type == "string") and
          (.tunnel.capture.path | type == "string") and
          (.tunnel.capture.sha256 | type == "string"))
      ' "$live" >/dev/null; then
        unmet "live application case ${case_id} is not passed directly and through the tunnel"
        continue
      fi
      require_capture_object "$live" "(.cases[] | select(.id == \"$case_id\") | .direct.capture)" "live ${case_id} direct capture"
      require_capture_object "$live" "(.cases[] | select(.id == \"$case_id\") | .tunnel.capture)" "live ${case_id} tunnel capture"
    done

    websocket_required=$(jq -r '.websocket_required' "$live")
    if [[ "$websocket_required" == true ]]; then
      if ! jq -e '
        ([.cases[] | select(.id == "websocket")] | length == 1) and
        ([.cases[] | select(.id == "websocket")][0] |
          .direct.status == "passed" and .tunnel.status == "passed")
      ' "$live" >/dev/null; then
        unmet 'live application WebSocket case is required but is not passed directly and through the tunnel'
      else
        require_capture_object "$live" '(.cases[] | select(.id == "websocket") | .direct.capture)' 'live websocket direct capture'
        require_capture_object "$live" '(.cases[] | select(.id == "websocket") | .tunnel.capture)' 'live websocket tunnel capture'
      fi
    elif ! jq -e '
      ([.cases[] | select(.id == "websocket")] | length == 1) and
      ([.cases[] | select(.id == "websocket")][0] |
        .status == "not_applicable" and (.reason | type == "string" and length > 0))
    ' "$live" >/dev/null; then
      unmet 'live application WebSocket exemption is missing or lacks a reason'
    fi
  fi
fi

if [[ -n "$benchmark" ]]; then
  if ! jq -e '
    .schema_version == 1 and
    (.measured_at_unix_seconds | type == "number" and . > 0) and
    (.hardware_note | type == "string" and length > 0) and
    .stream_bytes_each_direction == 67108864 and
    .small_flushed_write_bytes == 9 and
    (.samples_per_path | type == "number" and . >= 20) and
    ([.direct, .tunnel] | all(
      (.first_byte_p95_us | type == "number" and . >= 0) and
      (.first_byte_samples_us | type == "array" and length == $samples) and
      .stream_sent_bytes == 67108864 and .stream_received_bytes == 67108864 and
      (.bidirectional_throughput_bytes_per_second | type == "number" and . > 0)
    ))
  ' --argjson samples "$(jq '.samples_per_path // -1' "$benchmark")" "$benchmark" >/dev/null; then
    unmet 'benchmark.json lacks the required 64 MiB, flushed-write, and sample evidence'
  fi
  if ! jq -e '.gates.additional_first_byte_p95_le_10ms == true and .gates.tunnel_throughput_at_least_90_percent_of_direct == true' "$benchmark" >/dev/null; then
    unmet 'benchmark latency or throughput gate is not true'
  fi
  if ! jq -e '.gates.tunnel_owned_memory_per_active_connection_le_1mib == true' "$benchmark" >/dev/null; then
    unmet 'benchmark memory gate is not true'
  fi
  if ! jq -e '
    (.comparison.additional_first_byte_p95_us == (.tunnel.first_byte_p95_us - .direct.first_byte_p95_us)) and
    ((.comparison.tunnel_throughput_fraction_of_direct - (.tunnel.bidirectional_throughput_bytes_per_second / .direct.bidirectional_throughput_bytes_per_second)) | fabs < 0.000001) and
    .comparison.additional_first_byte_p95_us <= 10000 and
    .comparison.tunnel_throughput_fraction_of_direct >= 0.9 and
    .memory.status == "measured_from_operator_rss_samples" and
    (.memory.baseline_rss_kib | type == "number") and .memory.baseline_rss_kib >= 0 and
    (.memory.active_rss_kib | type == "number") and .memory.active_rss_kib >= .memory.baseline_rss_kib and
    (.memory.active_connections | type == "number") and .memory.active_connections > 0 and
    ((.memory.tunnel_owned_memory_per_active_connection_kib - ((.memory.active_rss_kib - .memory.baseline_rss_kib) / .memory.active_connections)) | fabs < 0.000001) and
    .memory.tunnel_owned_memory_per_active_connection_kib <= 1024
  ' "$benchmark" >/dev/null; then
    unmet 'benchmark numeric results or measured RSS evidence are inconsistent with release thresholds'
  fi
fi

if [[ -n "$attestation" && -n "$benchmark" ]]; then
  benchmark_digest=$(sha256_file "$benchmark")
  if ! jq -e --arg digest "$benchmark_digest" '
    .schema_version == 1 and
    (.release_id | type == "string" and length > 0) and
    .benchmark_sha256 == $digest and
    (.route | type == "string" and length > 0) and
    (.hardware.client | type == "string" and length > 0) and
    (.hardware.remote | type == "string" and length > 0) and
    (.rss.baseline_samples_kib | type == "array" and length == 5) and
    (.rss.active_samples_kib | type == "array" and length == 5) and
    ([.rss.baseline_samples_kib[], .rss.active_samples_kib[]] | all(type == "number" and . >= 0))
  ' "$attestation" >/dev/null; then
    unmet 'benchmark attestation lacks real hardware, five RSS samples, or a matching benchmark digest'
  else
    if ! jq -e --slurpfile benchmark "$benchmark" '
      def median: sort | .[length / 2 | floor];
      (.rss.baseline_samples_kib | median) == $benchmark[0].memory.baseline_rss_kib and
      (.rss.active_samples_kib | median) == $benchmark[0].memory.active_rss_kib
    ' "$attestation" >/dev/null; then
      unmet 'benchmark attestation RSS medians do not match benchmark.json'
    fi
    require_capture_object "$attestation" '.cpu_capture' 'benchmark CPU capture'
  fi
fi

if [[ -n "$live" && -n "$attestation" && -n "$artifacts" ]]; then
  release_id=$(jq -r '.release_id // empty' "$live")
  if ! jq -e --arg release "$release_id" '.release_id == $release' "$attestation" >/dev/null; then
    unmet 'benchmark attestation release_id does not match live evidence'
  fi
  if ! jq -e --arg release "$release_id" '.schema_version == 1 and .release_id == $release and (.build_host | type == "string" and length > 0) and (.artifacts | type == "array")' "$artifacts" >/dev/null; then
    unmet 'artifacts.json lacks a matching release_id or build-host record'
  else
    for role in server client; do
      if ! jq -e --arg role "$role" '
        ([.artifacts[] | select(.role == $role)] | length == 1) and
        ([.artifacts[] | select(.role == $role)][0] |
          (.path | type == "string") and (.sha256 | type == "string") and
          (.architectures | type == "array" and length == 2 and (index("arm64") != null) and (index("x86_64") != null)) and
          (.codesign_capture.path | type == "string") and (.lipo_capture.path | type == "string") and
          (.runtime_smoke_capture.path | type == "string"))
      ' "$artifacts" >/dev/null; then
        unmet "${role} signed universal artifact record is incomplete"
        continue
      fi
      artifact_path=$(jq -r --arg role "$role" '.artifacts[] | select(.role == $role) | .path' "$artifacts")
      artifact_digest=$(jq -r --arg role "$role" '.artifacts[] | select(.role == $role) | .sha256' "$artifacts")
      require_capture "${role} artifact" "$artifact_path" "$artifact_digest"
      require_capture_object "$artifacts" "(.artifacts[] | select(.role == \"$role\") | .codesign_capture)" "${role} codesign verification"
      require_capture_object "$artifacts" "(.artifacts[] | select(.role == \"$role\") | .lipo_capture)" "${role} universal-slice verification"
      require_capture_object "$artifacts" "(.artifacts[] | select(.role == \"$role\") | .runtime_smoke_capture)" "${role} binary-only runtime smoke test"
    done
  fi
fi

if ((unmet_count)); then
  printf 'EXTERNAL ACCEPTANCE INCOMPLETE: %d unmet gate(s)\n' "$unmet_count" >&2
  exit 1
fi
printf 'ALL EXTERNAL ACCEPTANCE GATES MET BY THE PROVIDED, VALIDATED EVIDENCE\n'
