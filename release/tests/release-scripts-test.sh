#!/bin/sh
# Shell-level contract tests.  These use command stubs so the macOS-only
# release scripts can be exercised on a non-macOS CI host.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
BUILD="$ROOT/release/build-macos-universal.sh"
VERIFY="$ROOT/release/verify-artifact.sh"
INSTALL="$ROOT/release/install-atomic.sh"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/codex-tunnel-release-test.XXXXXX")
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

fail() { echo "FAIL: $*" >&2; exit 1; }
expect_fail() {
  if "$@" >/dev/null 2>&1; then fail "expected failure: $*"; fi
}

# Red contracts: every release entrypoint rejects a non-macOS host before it
# touches release inputs.
expect_fail "$BUILD" --output-dir "$TMP/out" --sign-identity "Developer ID"
expect_fail "$BUILD" --output-dir "$TMP/ad-hoc" --sign-identity -
expect_fail "$VERIFY" --artifact-dir "$TMP/no-such-artifact"
expect_fail "$INSTALL" --artifact-dir "$TMP/no-such-artifact" --binary network-sync-agent --destination "$TMP/network-sync-agent"

MOCK="$TMP/mock-bin"
mkdir "$MOCK"
cat >"$MOCK/uname" <<'EOF'
#!/bin/sh
echo Darwin
EOF
cat >"$MOCK/cargo" <<'EOF'
#!/bin/sh
target=
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--target" ]; then target=$2; shift 2; continue; fi
  shift
done
[ -n "$target" ] || exit 64
mkdir -p "$CARGO_TARGET_DIR/$target/release"
printf 'client-%s\n' "$target" >"$CARGO_TARGET_DIR/$target/release/codex-tunnel"
printf 'server-%s\n' "$target" >"$CARGO_TARGET_DIR/$target/release/codex-tunnel-server"
EOF
cat >"$MOCK/lipo" <<'EOF'
#!/bin/sh
if [ "$2" = "-verify_arch" ]; then
  [ -f "$1" ] && [ "$3" = "arm64" ] && [ "$4" = "x86_64" ]
  exit
fi
[ "$1" = "-create" ] || exit 64
shift
[ "$1" = "-output" ] || exit 64
out=$2
shift 2
cat "$@" >"$out"
EOF
cat >"$MOCK/codesign" <<'EOF'
#!/bin/sh
case "$1" in
  --force) exit 0 ;;
  --verify) exit 0 ;;
  -d)
    last=
    for arg in "$@"; do last=$arg; done
    if grep -q foreign "$last"; then
      echo 'Authority=Foreign Developer ID'
    else
      echo 'Authority=Developer ID Test'
    fi
    exit 0
    ;;
  *) exit 64 ;;
esac
EOF
cat >"$MOCK/shasum" <<'EOF'
#!/bin/sh
if [ "$3" = "-c" ]; then
  while read -r want name; do
    got=$(sha256sum "$name" | awk '{print $1}')
    [ "$want" = "$got" ] || exit 1
  done <"$4"
  exit 0
fi
shift 2
for file in "$@"; do
  sha256sum "$file" | awk '{print $1 "  " $2}'
done
EOF
chmod 755 "$MOCK"/*

ARTIFACTS="$TMP/artifacts"
PATH="$MOCK:$PATH" CARGO_TARGET_DIR="$TMP/cargo-target" "$BUILD" --output-dir "$ARTIFACTS" --sign-identity 'Developer ID Test'
[ -f "$ARTIFACTS/network-sync-agent" ] || fail 'client artifact missing'
[ -f "$ARTIFACTS/codex-tunnel-server" ] || fail 'server artifact missing'
[ -f "$ARTIFACTS/SHA256SUMS" ] || fail 'digest manifest missing'
PATH="$MOCK:$PATH" "$VERIFY" --artifact-dir "$ARTIFACTS" --require-identity 'Developer ID Test'

# A malformed manifest must fail before installation.
cp "$ARTIFACTS/SHA256SUMS" "$TMP/SHA256SUMS.good"
printf '%064d  network-sync-agent\n' 0 >"$ARTIFACTS/SHA256SUMS"
expect_fail env PATH="$MOCK:$PATH" "$VERIFY" --artifact-dir "$ARTIFACTS"
mv "$TMP/SHA256SUMS.good" "$ARTIFACTS/SHA256SUMS"

# Dry run proves the installer validates input without modifying the target.
DEST="$TMP/install/network-sync-agent"
mkdir -p "$(dirname "$DEST")"
PATH="$MOCK:$PATH" "$INSTALL" --artifact-dir "$ARTIFACTS" --binary network-sync-agent --destination "$DEST" --dry-run
[ ! -e "$DEST" ] || fail 'dry-run modified destination'

# Green installation is an atomic replacement and keeps exactly the immediate
# predecessor.  The codesign mock considers all test files valid signatures.
printf 'foreign signed binary\n' >"$DEST"
expect_fail env PATH="$MOCK:$PATH" "$INSTALL" --artifact-dir "$ARTIFACTS" --binary network-sync-agent --destination "$DEST" --require-identity 'Developer ID Test'
printf 'old signed binary\n' >"$DEST"
PATH="$MOCK:$PATH" "$INSTALL" --artifact-dir "$ARTIFACTS" --binary network-sync-agent --destination "$DEST" --require-identity 'Developer ID Test'
printf 'old signed binary\n' >"$TMP/expected-old"
cmp "$DEST.previous" "$TMP/expected-old" || fail 'previous binary not retained'
cmp "$DEST" "$ARTIFACTS/network-sync-agent" || fail 'new binary not installed'

echo 'ok: release script contracts passed'
