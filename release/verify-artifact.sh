#!/bin/sh
# Verify a release directory before distribution or installation.
set -eu

usage() {
  cat >&2 <<'EOF'
usage: verify-artifact.sh --artifact-dir DIR [--require-identity IDENTITY]

Checks the exact SHA256SUMS manifest, both universal Mach-O slices, and strict
code signatures.  IDENTITY, when supplied, must occur as a signing authority.
EOF
  exit 64
}
fail() { echo "error: $*" >&2; exit 1; }
require_darwin() { [ "$(uname -s)" = Darwin ] || fail 'macOS is required to verify code signatures'; }
require_command() { command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"; }

artifact_dir=
identity=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --artifact-dir) [ "$#" -ge 2 ] || usage; artifact_dir=$2; shift 2 ;;
    --require-identity) [ "$#" -ge 2 ] || usage; identity=$2; shift 2 ;;
    --help|-h) usage ;;
    *) usage ;;
  esac
done
[ -n "$artifact_dir" ] || usage
require_darwin
require_command shasum
require_command lipo
require_command codesign
[ -d "$artifact_dir" ] || fail "artifact directory not found: $artifact_dir"

artifact_dir=$(CDPATH= cd -- "$artifact_dir" && pwd -P)
manifest="$artifact_dir/SHA256SUMS"
[ -f "$manifest" ] || fail "SHA256SUMS is missing: $manifest"

require_exact_identity() {
  file=$1
  details=$(codesign -d --verbose=4 "$file" 2>&1 || true)
  printf '%s\n' "$details" | grep -Fx "Authority=$identity" >/dev/null ||
    fail "signature authority does not match required identity: $(basename -- "$file")"
}

# Do not delegate the manifest's file names to shasum.  It must describe
# exactly our two expected files, once each, with a 64-character hex digest.
validate_manifest() {
  awk '
    NF != 2 { exit 1 }
    length($1) != 64 || $1 !~ /^[0123456789abcdefABCDEF]+$/ { exit 1 }
    $2 == "network-sync-agent" { client++; next }
    $2 == "codex-tunnel-server" { server++; next }
    { exit 1 }
    END { exit !(client == 1 && server == 1 && NR == 2) }
  ' "$manifest"
}
validate_manifest || fail 'SHA256SUMS must contain exactly the two expected artifact digests'

for artifact in network-sync-agent codex-tunnel-server; do
  [ -f "$artifact_dir/$artifact" ] && [ ! -L "$artifact_dir/$artifact" ] ||
    fail "artifact must be a regular non-symlink file: $artifact"
done

(
  cd "$artifact_dir"
  shasum -a 256 -c SHA256SUMS
) || fail 'SHA-256 verification failed'

verify_identity() {
  file=$1
  codesign --verify --deep --strict --verbose=2 "$file" || fail "code-signature verification failed: $(basename -- "$file")"
  lipo "$file" -verify_arch arm64 x86_64 || fail "universal slice verification failed: $(basename -- "$file")"
  if [ -n "$identity" ]; then
    require_exact_identity "$file"
  fi
}
verify_identity "$artifact_dir/network-sync-agent"
verify_identity "$artifact_dir/codex-tunnel-server"
echo "ok: verified signatures, universal slices, and SHA-256 manifest in $artifact_dir"
