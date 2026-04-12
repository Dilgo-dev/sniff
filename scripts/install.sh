#!/bin/sh
# sniff installer for Linux and macOS.
# Usage: curl -fsSL getsniff.sh/install | sh

set -e

REPO="Dilgo-dev/sniff"
INSTALL_DIR="/usr/local/bin"
BINARY="sniff"

detect_os() {
  case "$(uname -s)" in
    Linux*)  echo "linux" ;;
    Darwin*) echo "macos" ;;
    *)       echo "unsupported" ;;
  esac
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)  echo "x86_64" ;;
    aarch64|arm64) echo "aarch64" ;;
    *)             echo "unsupported" ;;
  esac
}

main() {
  OS="$(detect_os)"
  ARCH="$(detect_arch)"

  if [ "$OS" = "unsupported" ] || [ "$ARCH" = "unsupported" ]; then
    echo "error: unsupported platform $(uname -s)/$(uname -m)"
    echo "build from source: https://github.com/$REPO"
    exit 1
  fi

  TAG=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
    | grep '"tag_name"' | head -1 | cut -d'"' -f4)

  if [ -z "$TAG" ]; then
    echo "error: could not fetch latest release"
    exit 1
  fi

  ASSET="sniff-${TAG}-${OS}-${ARCH}.tar.gz"
  URL="https://github.com/$REPO/releases/download/$TAG/$ASSET"

  echo "sniff $TAG ($OS/$ARCH)"
  echo "downloading $URL"

  WORKDIR=$(mktemp -d)
  trap 'rm -rf "$WORKDIR"' EXIT

  curl -fsSL "$URL" -o "$WORKDIR/$ASSET"
  tar xzf "$WORKDIR/$ASSET" -C "$WORKDIR"

  if [ ! -f "$WORKDIR/$BINARY" ]; then
    echo "error: binary not found in archive"
    exit 1
  fi

  chmod +x "$WORKDIR/$BINARY"

  if [ ! -d "$INSTALL_DIR" ]; then
    echo "creating $INSTALL_DIR (requires sudo)"
    sudo mkdir -p "$INSTALL_DIR"
  fi

  if [ -w "$INSTALL_DIR" ]; then
    mv "$WORKDIR/$BINARY" "$INSTALL_DIR/$BINARY"
  else
    echo "installing to $INSTALL_DIR (requires sudo)"
    sudo mv "$WORKDIR/$BINARY" "$INSTALL_DIR/$BINARY"
  fi

  echo "installed sniff $TAG to $INSTALL_DIR/$BINARY"
  echo "run: sudo sniff"
}

main
