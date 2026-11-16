#!/usr/bin/env bash
# Fails when a tracked file states an MSRV different from [workspace.package] rust-version.
# Usage: check-msrv-statements.sh   (run from anywhere inside the repository)
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

VERSION='[0-9]+\.[0-9]+(\.[0-9]+)?'
PATTERNS=(
  "MSRV-${VERSION}"
  "MSRV ${VERSION}"
  "Rust ${VERSION} or later"
  "Minimum Supported Rust Version: \*\*${VERSION}\*\*"
  "^msrv = \"${VERSION}\""
  "Install Rust ${VERSION}"
  "toolchain: \"${VERSION}\""
  "rustup toolchain install ${VERSION}"
  "rustup override set ${VERSION}"
  "Rust version: ${VERSION}"
)

normalize() {
  local v=$1
  [[ $v == *.*.* ]] || v="$v.0"
  printf '%s' "$v"
}

expected_raw=$(sed -n '/^\[workspace\.package\]/,/^\[[^w]/{s/^rust-version = "\(.*\)"$/\1/p;}' Cargo.toml)
if [[ -z $expected_raw ]]; then
  echo "error: [workspace.package] rust-version not found in Cargo.toml" >&2
  exit 2
fi
expected=$(normalize "$expected_raw")

files=()
while IFS= read -r f; do
  files+=("$f")
done < <(git ls-files | grep -vE '^(CHANGELOG\.md|specs/|Cargo\.lock$|\.github/scripts/check-msrv-statements\.sh$)')

status=0
checked=0
for pattern in "${PATTERNS[@]}"; do
  while IFS= read -r hit; do
    [[ -n $hit ]] || continue
    checked=$((checked + 1))
    file=${hit%%:*}
    rest=${hit#*:}
    line=${rest%%:*}
    stated=$(grep -oE "$VERSION" <<<"${rest#*:}" | tail -n1)
    if [[ $(normalize "$stated") != "$expected" ]]; then
      echo "$file:$line: states MSRV $stated, rust-version is $expected_raw" >&2
      status=1
    fi
  done < <(grep -nHIEo -- "$pattern" "${files[@]}" || true)
done

if ((checked == 0)); then
  echo "error: no MSRV statements found; the patterns are stale" >&2
  exit 2
fi
if ((status == 0)); then
  echo "OK: $checked MSRV statements match rust-version $expected_raw"
fi
exit "$status"
