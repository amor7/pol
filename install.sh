#!/usr/bin/env bash
# pol installer: downloads the latest release, checks it, and runs setup.
#
#   bash <(curl -fsSL https://raw.githubusercontent.com/amor7/pol/main/install.sh)
#   bash <(curl -fsSL https://raw.githubusercontent.com/amor7/pol/main/install.sh) server [--port 8443]
#   bash <(curl -fsSL https://raw.githubusercontent.com/amor7/pol/main/install.sh) relay <token> [--ports 2088,8443]
#
# Run again on a machine that already has pol, with no arguments, to update it.
set -euo pipefail

REPO="amor7/pol"
BASE="${POL_MIRROR:-https://github.com/$REPO/releases/latest/download}"

say()  { printf '   \033[32m✓\033[0m %s\n' "$*"; }
note() { printf '   \033[2m·\033[0m %s\n' "$*"; }
die()  { printf '   \033[31m✗\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run this as root (sudo -i first)"
[ "$(uname -s)" = "Linux" ] || die "pol runs on Linux"

case "$(uname -m)" in
  x86_64 | amd64) ARCH=amd64 ;;
  aarch64 | arm64) ARCH=arm64 ;;
  *) die "unsupported processor: $(uname -m)" ;;
esac

if ! command -v curl >/dev/null 2>&1; then
  note "installing curl..."
  (apt-get update -qq && apt-get install -y -qq curl) >/dev/null 2>&1 ||
    (dnf install -y -q curl || yum install -y -q curl) >/dev/null 2>&1 ||
    die "please install curl first"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

note "downloading pol for linux/$ARCH ..."
curl -fL --retry 3 --connect-timeout 15 -o "$TMP/pol-linux-$ARCH" "$BASE/pol-linux-$ARCH" ||
  die "download failed - if GitHub is blocked here, see 'Installing without GitHub' in the README"
curl -fsSL --retry 3 --connect-timeout 15 -o "$TMP/checksums.txt" "$BASE/checksums.txt" ||
  die "could not download checksums.txt"
(cd "$TMP" && grep " pol-linux-$ARCH\$" checksums.txt | sha256sum -c --quiet -) ||
  die "checksum mismatch - the download is damaged; nothing was changed"
say "download verified"

install -m 0755 "$TMP/pol-linux-$ARCH" /usr/local/bin/pol
say "installed $(/usr/local/bin/pol version)"

if [ $# -eq 0 ] && [ -f /etc/pol/config.json ]; then
  if command -v systemctl >/dev/null 2>&1 && systemctl is-enabled pol >/dev/null 2>&1; then
    systemctl restart pol
  fi
  say "pol was already set up here - it is updated and running again"
  exec /usr/local/bin/pol status
fi

exec /usr/local/bin/pol setup "$@"
