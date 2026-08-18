#!/bin/sh
# Validate a completed secure-tunnel installation before launchd loads it.
# This intentionally accepts the documented TOML subset only; it is a deployment
# guard, not a general TOML parser.
set -eu

usage() {
  echo "usage: $0 --client FILE | --server FILE" >&2
  exit 64
}

[ "$#" -eq 2 ] || usage
role=$1
config=$2
case "$role" in --client|--server) ;; *) usage ;; esac
[ -f "$config" ] || { echo "error: configuration not found: $config" >&2; exit 1; }

case "$(uname -s)" in
  Darwin) config_mode=$(stat -f '%Lp' "$config" 2>/dev/null || true) ;;
  *) config_mode=$(stat -c '%a' "$config" 2>/dev/null || true) ;;
esac
[ "$config_mode" = "600" ] || {
  echo "error: configuration must have mode 0600: $config (found ${config_mode:-unknown})" >&2
  exit 1
}

fail=0
error() { echo "error: $*" >&2; fail=1; }

# Templates must never accidentally be treated as a completed installation.
if grep -Eq 'REPLACE_WITH|<[^>]+>|CHANGE_ME|example\.invalid' "$config"; then
  error "configuration still contains a deployment placeholder"
fi

value_for() {
  key=$1
  awk -v key="$key" '
    $0 ~ "^[[:space:]]*" key "[[:space:]]*=" {
      value=$0; sub("^[[:space:]]*" key "[[:space:]]*=[[:space:]]*", "", value)
      gsub(/^[[:space:]]*"|"[[:space:]]*[#].*$|"[[:space:]]*$/, "", value)
      print value
    }' "$config"
}

check_mode_0600() {
  path=$1
  [ -n "$path" ] || return
  [ -f "$path" ] || { error "private key not found: $path"; return; }
  case "$(uname -s)" in
    Darwin) mode=$(stat -f '%Lp' "$path" 2>/dev/null || true) ;;
    *) mode=$(stat -c '%a' "$path" 2>/dev/null || true) ;;
  esac
  [ "$mode" = "600" ] || error "private key must have mode 0600: $path (found ${mode:-unknown})"
}

key_files=$(value_for private_key_file || true)
[ -n "$key_files" ] || error "no private_key_file is configured"
old_ifs=$IFS
IFS='
'
set -- $key_files
IFS=$old_ifs
for key_file in "$@"; do check_mode_0600 "$key_file"; done

case "$role" in
  --client)
    listen=$(value_for address | sed -n '1p')
    remote=$(value_for address | sed -n '2p')
    pinned=$(value_for server_public_key || true)
    case "$listen" in 127.0.0.1:*|'[::1]:'*) ;; *) error "client listener must use a loopback address" ;; esac
    [ -n "$remote" ] || error "client remote address is missing"
    [ -n "$pinned" ] || error "client pinned server_public_key is missing"
    ;;
  --server)
    listen=$(value_for address | sed -n '1p')
    destination=$(value_for address | sed -n '2p')
    clients=$(value_for public_key || true)
    [ -n "$listen" ] || error "server listen address is missing"
    case "$destination" in 127.0.0.1:*|'[::1]:'*) ;; *) error "server destination must be loopback-only" ;; esac
    [ -n "$clients" ] || error "server requires at least one authorized client public key"
    ;;
esac

[ "$fail" -eq 0 ] || exit 1
echo "ok: $role configuration passed placeholder, endpoint, and private-key permission checks"
