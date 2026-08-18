#!/bin/sh
# Build the two deployable universal macOS executables.  A signing identity is
# deliberately mandatory: this script must never choose a certificate itself.
set -eu

usage() {
  cat >&2 <<'EOF'
usage: build-macos-universal.sh --output-dir DIR --sign-identity IDENTITY

Builds arm64 and x86_64 release binaries, combines them with lipo, signs the
results using the explicitly supplied identity, verifies both slices and
signatures, and writes SHA256SUMS.  DIR must not already exist.
EOF
  exit 64
}

fail() { echo "error: $*" >&2; exit 1; }
require_darwin() { [ "$(uname -s)" = Darwin ] || fail 'macOS is required for release builds'; }
require_command() { command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"; }

output_dir=
identity=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output-dir) [ "$#" -ge 2 ] || usage; output_dir=$2; shift 2 ;;
    --sign-identity) [ "$#" -ge 2 ] || usage; identity=$2; shift 2 ;;
    --help|-h) usage ;;
    *) usage ;;
  esac
done
[ -n "$output_dir" ] || usage
[ -n "$identity" ] || usage
[ "$identity" != - ] || fail 'ad-hoc signing is not permitted for release artifacts'

require_darwin
require_command cargo
require_command lipo
require_command codesign
require_command shasum

[ ! -e "$output_dir" ] || fail "output directory already exists: $output_dir"
output_parent=$(dirname -- "$output_dir")
output_name=$(basename -- "$output_dir")
[ "$output_name" != . ] && [ "$output_name" != / ] || fail 'output directory name is invalid'
[ -d "$output_parent" ] || fail "output parent does not exist: $output_parent"
output_parent=$(CDPATH= cd -- "$output_parent" && pwd -P)
output_dir="$output_parent/$output_name"

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
stage_root=$(mktemp -d "$output_parent/.secure-tunnel-release.XXXXXX")
trap 'rm -rf "$stage_root"' EXIT HUP INT TERM
stage_artifacts="$stage_root/artifacts"
mkdir "$stage_artifacts"

build_target() {
  target=$1
  CARGO_TARGET_DIR="$stage_root/target" cargo build --locked --release --target "$target" \
    -p secure-tunnel-client -p secure-tunnel-server \
    --manifest-path "$repo_root/Cargo.toml"
}

build_target aarch64-apple-darwin
build_target x86_64-apple-darwin

combine() {
  source_name=$1
  output_name=$2
  arm="$stage_root/target/aarch64-apple-darwin/release/$source_name"
  intel="$stage_root/target/x86_64-apple-darwin/release/$source_name"
  result="$stage_artifacts/$output_name"
  [ -f "$arm" ] || fail "arm64 build did not produce $source_name"
  [ -f "$intel" ] || fail "x86_64 build did not produce $source_name"
  lipo -create -output "$result" "$arm" "$intel"
  lipo "$result" -verify_arch arm64 x86_64 || fail "universal slice verification failed: $output_name"
  codesign --force --options runtime --sign "$identity" "$result"
  codesign --verify --deep --strict --verbose=2 "$result"
}

# The client artifact deliberately uses the inconspicuous operational name
# required for the restricted Mac; its Rust package binary remains secure-tunnel.
combine secure-tunnel network-sync-agent
combine secure-tunnel-server secure-tunnel-server

(
  cd "$stage_artifacts"
  shasum -a 256 network-sync-agent secure-tunnel-server >SHA256SUMS
)
[ -s "$stage_artifacts/SHA256SUMS" ] || fail 'failed to create SHA256SUMS'

# One rename publishes the complete artifact directory only after every prior
# build, slice, signature, and digest check has succeeded.
mv "$stage_artifacts" "$output_dir"
echo "ok: signed universal artifacts written to $output_dir"
