#!/usr/bin/env sh
# Install writ into $HOME/.writ/bin (Linux, macOS; Git Bash on Windows).
#
#   curl -fsSL https://raw.githubusercontent.com/writ-agent/writ/main/scripts/install.sh | sh
#
# Downloads the prebuilt binary for this machine from the GitHub release and
# checks it against the release's checksums.txt before installing. (Each
# binary also has a Sigstore bundle; see the release notes to verify it with
# cosign.) Nothing else is touched: no PATH edits, no shell profile changes.
#
#   WRIT_VERSION=v0.1.2   a specific release (default: latest)
#   WRIT_BIN_DIR=DIR      where to install (default: $HOME/.writ/bin)
#   WRIT_FROM_SOURCE=1    build from this checkout with cargo instead
set -eu

BIN_DIR="${WRIT_BIN_DIR:-$HOME/.writ/bin}"
mkdir -p "$BIN_DIR"

repo="${WRIT_REPO:-writ-agent/writ}"
version="${WRIT_VERSION:-latest}"
os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"

case "$arch" in
  x86_64|amd64) arch="x86_64" ;;
  arm64|aarch64) arch="aarch64" ;;
  *) echo "unsupported arch: $arch" >&2; exit 1 ;;
esac

case "$os" in
  linux) target="$arch-unknown-linux-musl" ;;  # static: runs on any distro
  darwin) target="$arch-apple-darwin" ;;
  mingw*|msys*|cygwin*) target="x86_64-pc-windows-msvc"; EXE_SUFFIX=".exe" ;;
  *) echo "unsupported os: $os" >&2; exit 1 ;;
esac
exe="writ${EXE_SUFFIX:-}"

if [ "${WRIT_FROM_SOURCE:-0}" = "1" ]; then
  echo "building writ from source..." >&2
  cargo build --release -p writ-cli
  cp "target/release/$exe" "$BIN_DIR/$exe"
else
  if [ "$version" = "latest" ]; then
    base="https://github.com/$repo/releases/latest/download"
  else
    base="https://github.com/$repo/releases/download/$version"
  fi
  asset="writ-$target${EXE_SUFFIX:-}"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  fetch() {
    if command -v curl >/dev/null 2>&1; then
      curl -fsSL "$1" -o "$2"
    elif command -v wget >/dev/null 2>&1; then
      wget -qO "$2" "$1"
    else
      echo "need curl or wget" >&2; exit 1
    fi
  }
  echo "downloading $base/$asset" >&2
  fetch "$base/$asset" "$tmp/$asset"
  fetch "$base/checksums.txt" "$tmp/checksums.txt"
  want="$(awk -v f="$asset" '$2 == f || $2 == "*"f { print $1 }' "$tmp/checksums.txt")"
  if [ -z "$want" ]; then
    echo "error: $asset is not listed in the release's checksums.txt; not installing" >&2
    exit 1
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    got="$(sha256sum "$tmp/$asset" | awk '{print $1}')"
  else
    got="$(shasum -a 256 "$tmp/$asset" | awk '{print $1}')"
  fi
  if [ "$got" != "$want" ]; then
    echo "error: checksum mismatch for $asset (expected $want, got $got); not installing" >&2
    exit 1
  fi
  echo "checksum ok ($want)" >&2
  mv "$tmp/$asset" "$BIN_DIR/$exe"
fi

chmod +x "$BIN_DIR/$exe" 2>/dev/null || true
echo "installed: $BIN_DIR/$exe ($("$BIN_DIR/$exe" --version 2>/dev/null || echo "version unknown"))"
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) echo "add it to PATH:  export PATH=\"$BIN_DIR:\$PATH\"" ;;
esac
echo "next:  writ scan    (what would writ have caught?)   then   writ init"
