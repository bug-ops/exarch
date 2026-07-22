#!/bin/sh
# Installs the exarch CLI from a GitHub release. Meant to be run via:
#   curl -fsSL https://raw.githubusercontent.com/bug-ops/exarch/main/scripts/install.sh | sh
set -eu

REPO="bug-ops/exarch"
INSTALL_DIR="${EXARCH_INSTALL_DIR:-$HOME/.local/bin}"

log() { printf '%s\n' "$*" >&2; }
die() {
  log "error: $*"
  exit 1
}

command -v curl >/dev/null 2>&1 || die "curl is required but not found"
command -v tar >/dev/null 2>&1 || die "tar is required but not found"

detect_os() {
  case "$(uname -s)" in
    Linux) echo linux ;;
    Darwin) echo darwin ;;
    *) die "unsupported OS: $(uname -s)" ;;
  esac
}

detect_arch() {
  arch="$(uname -m)"
  case "$arch" in
    x86_64 | amd64) echo x86_64 ;;
    arm64 | aarch64) echo aarch64 ;;
    *) die "unsupported architecture: $arch" ;;
  esac
}

os="$(detect_os)"
arch="$(detect_arch)"

case "$os-$arch" in
  linux-x86_64) target="x86_64-unknown-linux-gnu" ;;
  linux-aarch64) target="aarch64-unknown-linux-gnu" ;;
  darwin-x86_64) target="x86_64-apple-darwin" ;;
  darwin-aarch64) target="aarch64-apple-darwin" ;;
  *) die "no prebuilt exarch binary for $os-$arch" ;;
esac

version="${EXARCH_VERSION:-}"
if [ -z "$version" ]; then
  version="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' | head -n1 | sed -E 's/.*"v?([^"]+)".*/\1/')"
  [ -n "$version" ] || die "failed to resolve latest release version"
fi

archive="exarch-${version}-${target}.tar.gz"
base_url="https://github.com/${REPO}/releases/download/v${version}"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

log "Downloading ${archive} (v${version})..."
curl -fsSL -o "${tmp_dir}/${archive}" "${base_url}/${archive}"
curl -fsSL -o "${tmp_dir}/${archive}.sha256" "${base_url}/${archive}.sha256"

log "Verifying checksum..."
(
  cd "$tmp_dir"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c "${archive}.sha256"
  elif command -v shasum >/dev/null 2>&1; then
    checksum="$(cut -d ' ' -f1 "${archive}.sha256")"
    echo "${checksum}  ${archive}" | shasum -a 256 -c -
  else
    die "no sha256sum or shasum available to verify the download"
  fi
) || die "checksum verification failed, aborting install"

log "Extracting..."
tar -xzf "${tmp_dir}/${archive}" -C "$tmp_dir"

mkdir -p "$INSTALL_DIR"
cp "${tmp_dir}/exarch-${version}-${target}/exarch" "${INSTALL_DIR}/exarch"
chmod +x "${INSTALL_DIR}/exarch"

log "Installed exarch v${version} to ${INSTALL_DIR}/exarch"

case ":$PATH:" in
  *":${INSTALL_DIR}:"*) ;;
  *) log "note: ${INSTALL_DIR} is not on your PATH, add it to use 'exarch' directly" ;;
esac
