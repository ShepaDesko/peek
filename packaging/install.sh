#!/bin/sh
#
# Peek installer.
#
#   curl -fsSL https://raw.githubusercontent.com/ShepaDesko/peek/main/packaging/install.sh | sudo sh
#
# It is just as happy downloaded, read and then run — which is the recommended
# way to run any script piped from the internet:
#
#   curl -fsSLO https://raw.githubusercontent.com/ShepaDesko/peek/main/packaging/install.sh
#   less install.sh && sudo sh install.sh
#
# What it does: detect the distribution and architecture, download the right
# package from the GitHub release, verify its SHA-256 (and its signature when
# minisign is available), install it, and hand over to `peek setup`.
#
# No Docker, no interpreter, no dependency beyond curl and the system package
# manager.

set -eu

REPO="${PEEK_REPO:-ShepaDesko/peek}"
VERSION="${PEEK_VERSION:-latest}"
PUBKEY="${PEEK_PUBKEY:-}"
ASSUME_YES="${PEEK_YES:-0}"
SKIP_SETUP="${PEEK_SKIP_SETUP:-0}"

say() { printf '%s\n' "$*"; }
err() { printf 'error: %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<USAGE
Usage: install.sh [options]

  --version X.Y.Z   install a specific version (default: the latest release)
  --repo owner/name source repository (default: $REPO)
  --pubkey KEY      minisign public key used to verify the release
  --yes             do not ask anything
  --skip-setup      install only, do not run peek setup
  --help            show this message

Environment: PEEK_VERSION, PEEK_REPO, PEEK_PUBKEY, PEEK_YES, PEEK_SKIP_SETUP.
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --version) VERSION="${2:?missing value}"; shift 2 ;;
        --repo) REPO="${2:?missing value}"; shift 2 ;;
        --pubkey) PUBKEY="${2:?missing value}"; shift 2 ;;
        --yes|-y) ASSUME_YES=1; shift ;;
        --skip-setup) SKIP_SETUP=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) err "unknown option $1 (try --help)" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || err "run this as root: sudo sh install.sh"
command -v curl >/dev/null 2>&1 || err "curl is required"

# --- detect the platform ----------------------------------------------------

case "$(uname -m)" in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) err "unsupported architecture: $(uname -m) (amd64 and arm64 only)" ;;
esac

if [ -r /etc/os-release ]; then
    . /etc/os-release
else
    err "cannot read /etc/os-release: unsupported system"
fi

case "${ID:-}${ID_LIKE:-}" in
    *debian*|*ubuntu*) PKG=deb ;;
    *rhel*|*fedora*|*centos*|*rocky*|*alma*) PKG=rpm ;;
    *) err "unsupported distribution: ${PRETTY_NAME:-unknown}. Use the .tar.gz release by hand." ;;
esac

say "Peek installer"
say "  distribution : ${PRETTY_NAME:-unknown}"
say "  architecture : $ARCH"
say "  package type : $PKG"

# --- resolve the version ----------------------------------------------------

api="https://api.github.com/repos/$REPO/releases"
if [ "$VERSION" = "latest" ]; then
    VERSION="$(curl -fsSL "$api/latest" | sed -n 's/.*"tag_name": *"v\{0,1\}\([^"]*\)".*/\1/p' | head -1)"
    [ -n "$VERSION" ] || err "cannot determine the latest version (private repository? pass --version)"
fi
VERSION="${VERSION#v}"
say "  version      : $VERSION"

base="https://github.com/$REPO/releases/download/v$VERSION"
case "$PKG" in
    deb) asset="peek_${VERSION}_linux_${ARCH}.deb" ;;
    rpm) asset="peek-${VERSION}.${ARCH}.rpm" ;;
esac

if [ "$ASSUME_YES" != "1" ] && [ -t 0 ]; then
    printf 'Install %s from %s? [Y/n]: ' "$asset" "$REPO"
    read -r answer
    case "$answer" in [nN]*) err "cancelled" ;; esac
fi

# --- download and verify ----------------------------------------------------

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

say "Downloading $asset…"
curl -fsSL -o "$tmp/$asset" "$base/$asset" || err "download failed: $base/$asset"
curl -fsSL -o "$tmp/checksums.txt" "$base/checksums.txt" || err "cannot download checksums.txt"

say "Verifying the checksum…"
( cd "$tmp" && grep " $asset\$" checksums.txt | sha256sum -c - >/dev/null 2>&1 ) \
    || err "SHA-256 mismatch for $asset — refusing to install"

if [ -n "$PUBKEY" ]; then
    command -v minisign >/dev/null 2>&1 || err "minisign is required to verify the signature (--pubkey was given)"
    curl -fsSL -o "$tmp/checksums.txt.minisig" "$base/checksums.txt.minisig" \
        || err "cannot download the signature"
    say "Verifying the signature…"
    minisign -Vm "$tmp/checksums.txt" -P "$PUBKEY" >/dev/null \
        || err "invalid signature — refusing to install"
    say "  signature OK"
else
    say "  note: no --pubkey given, the release signature was not verified."
fi

# --- install ----------------------------------------------------------------

say "Installing…"
case "$PKG" in
    deb)
        DEBIAN_FRONTEND=noninteractive apt-get install -y "$tmp/$asset" >/dev/null 2>&1 \
            || dpkg -i "$tmp/$asset"
        ;;
    rpm)
        if command -v dnf >/dev/null 2>&1; then
            dnf install -y "$tmp/$asset" >/dev/null
        else
            yum install -y "$tmp/$asset" >/dev/null
        fi
        ;;
esac

say "Installed: $(peek version)"

if [ "$SKIP_SETUP" = "1" ]; then
    say "Run 'sudo peek setup' when you are ready."
    exit 0
fi

if [ -f /etc/peek/peek.toml ]; then
    say "Existing configuration kept. Checking the installation…"
    peek doctor || true
    exit 0
fi

if [ -t 0 ]; then
    peek setup
else
    say ""
    say "Non-interactive install. Finish with:"
    say "    sudo peek setup"
fi
