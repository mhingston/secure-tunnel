#!/bin/sh
# Install one verified release artifact with atomic replacement and rollback.
set -eu

usage() {
  cat >&2 <<'EOF'
usage: install-atomic.sh --artifact-dir DIR --binary NAME --destination PATH
                         [--require-identity IDENTITY] [--dry-run]

NAME is network-sync-agent or codex-tunnel-server.  The destination basename
must match NAME.  An existing active binary is signature-checked, hard-linked
to PATH.previous, then atomically replaced.  No service is stopped by this
script; launchd orchestration remains an operator decision.
EOF
  exit 64
}
fail() { echo "error: $*" >&2; exit 1; }
require_darwin() { [ "$(uname -s)" = Darwin ] || fail 'macOS is required for atomic release installation'; }
require_command() { command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"; }

artifact_dir=
binary=
destination=
identity=
dry_run=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --artifact-dir) [ "$#" -ge 2 ] || usage; artifact_dir=$2; shift 2 ;;
    --binary) [ "$#" -ge 2 ] || usage; binary=$2; shift 2 ;;
    --destination) [ "$#" -ge 2 ] || usage; destination=$2; shift 2 ;;
    --require-identity) [ "$#" -ge 2 ] || usage; identity=$2; shift 2 ;;
    --dry-run) dry_run=1; shift ;;
    --help|-h) usage ;;
    *) usage ;;
  esac
done
[ -n "$artifact_dir" ] && [ -n "$binary" ] && [ -n "$destination" ] || usage
case "$binary" in network-sync-agent|codex-tunnel-server) ;; *) fail "unsupported release binary: $binary" ;; esac
[ "$(basename -- "$destination")" = "$binary" ] || fail 'destination basename must match --binary'

require_darwin
require_command codesign
require_command shasum
require_command lipo
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
if [ -n "$identity" ]; then
  "$script_dir/verify-artifact.sh" --artifact-dir "$artifact_dir" --require-identity "$identity"
else
  "$script_dir/verify-artifact.sh" --artifact-dir "$artifact_dir"
fi

artifact_dir=$(CDPATH= cd -- "$artifact_dir" && pwd -P)
source_file="$artifact_dir/$binary"
[ -f "$source_file" ] && [ ! -L "$source_file" ] || fail "release binary must be a regular non-symlink file: $source_file"
destination_dir=$(dirname -- "$destination")
[ -d "$destination_dir" ] || fail "destination directory does not exist: $destination_dir"
destination_dir=$(CDPATH= cd -- "$destination_dir" && pwd -P)
destination="$destination_dir/$binary"
expected_hash=$(awk -v name="$binary" '$2 == name { print $1 }' "$artifact_dir/SHA256SUMS")
[ -n "$expected_hash" ] || fail "digest absent for $binary"

if [ "$dry_run" -eq 1 ]; then
  echo "ok: dry run verified $binary; would atomically install to $destination and retain $destination.previous"
  exit 0
fi

staged="$destination_dir/.${binary}.new.$$"
previous_tmp="$destination_dir/.${binary}.previous.$$"
cleanup() { rm -f "$staged" "$previous_tmp"; }
trap cleanup EXIT HUP INT TERM

# Copy into the target directory first so its final rename is necessarily on
# the target volume.  Verify the staged bytes and signature before replacement.
cp "$source_file" "$staged"
chmod 755 "$staged"
[ "$(shasum -a 256 "$staged" | awk '{print $1}')" = "$expected_hash" ] || fail 'staged binary digest mismatch'
codesign --verify --deep --strict --verbose=2 "$staged" || fail 'staged binary signature verification failed'
lipo "$staged" -verify_arch arm64 x86_64 || fail 'staged binary is not universal'
if [ -n "$identity" ]; then
  codesign -d --verbose=4 "$staged" 2>&1 | grep -Fx "Authority=$identity" >/dev/null || fail 'staged binary has unexpected signing authority'
fi

if [ -e "$destination" ]; then
  [ -f "$destination" ] && [ ! -L "$destination" ] || fail 'existing destination must be a regular non-symlink file'
  # Only retain a predecessor that is itself a valid signed universal binary.
  codesign --verify --deep --strict --verbose=2 "$destination" || fail 'existing binary is not a valid signature; refusing replacement'
  lipo "$destination" -verify_arch arm64 x86_64 || fail 'existing binary is not universal; refusing replacement'
  if [ -n "$identity" ]; then
    codesign -d --verbose=4 "$destination" 2>&1 | grep -Fx "Authority=$identity" >/dev/null ||
      fail 'existing binary has unexpected signing authority; refusing to retain it for rollback'
  fi
  ln "$destination" "$previous_tmp" || fail 'cannot create rollback hard link on destination volume'
  mv -f "$previous_tmp" "$destination.previous"
fi

# POSIX rename replaces the active path atomically.  The hard link above means
# the immediately preceding active binary remains available for rollback.
mv -f "$staged" "$destination"
[ "$(shasum -a 256 "$destination" | awk '{print $1}')" = "$expected_hash" ] || fail 'installed binary digest mismatch'
codesign --verify --deep --strict --verbose=2 "$destination" || fail 'installed binary signature verification failed'
echo "ok: installed $binary atomically at $destination"
