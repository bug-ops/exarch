#!/usr/bin/env bash
# Extracts 7z archives whose entry kind is contradictory with bsdtar, 7-Zip and
# exarch, and prints one TSV row per archive and entry:
#
#   scripts/sevenz-differential.sh /tmp/sevenz-diff > sevenz-diff.tsv
#
# The archives come from the ignored test write_kind_contradictions_for_the_differential
# (crates/exarch-core/tests/sevenz_entry_classifier.rs). Each holds `ok.txt` and
# the contradicting `entry`. Fixtures from p7zip on Linux and 7-Zip for Windows
# are tracked in #727. Tools that are not installed are left out of the
# columns. Per tool, a cell is one of:
#   refused-archive   the tool failed and extracted nothing
#   refused-entry     the tool failed, but extracted ok.txt
#   extracted:file|dir|symlink|other   what `entry` became (exit status 0 or not)
#   missing           the tool succeeded and wrote no `entry`
set -euo pipefail

dir="${1:?usage: sevenz-differential.sh DIR}"
mkdir -p "$dir"
dir="$(cd "$dir" && pwd)"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$here/.."

have() { command -v "$1" >/dev/null 2>&1; }

(cd "$root" && EXARCH_7Z_DIFF_DIR="$dir" cargo test -p exarch-core --test sevenz_entry_classifier \
  -- --ignored write_kind_contradictions_for_the_differential >&2)
(cd "$root" && cargo build -p exarch-cli >&2)
exarch="${EXARCH_BIN:-$root/target/debug/exarch}"

classify() {
  local status="$1" out="$2"
  local entry="$out/entry"
  if [ -L "$entry" ]; then echo "extracted:symlink"
  elif [ -d "$entry" ]; then echo "extracted:dir"
  elif [ -f "$entry" ]; then echo "extracted:file"
  elif [ -e "$entry" ]; then echo "extracted:other"
  elif [ "$status" -ne 0 ]; then
    if [ -e "$out/ok.txt" ]; then echo "refused-entry"; else echo "refused-archive"; fi
  else echo "missing"
  fi
}

run_tool() {
  local tool="$1" archive="$2" out status=0
  out="$(mktemp -d)"
  case "$tool" in
    bsdtar) (cd "$out" && bsdtar -xf "$archive") >/dev/null 2>&1 || status=$? ;;
    7z) (cd "$out" && 7z x -y -snl -bso0 -bsp0 "$archive") >/dev/null 2>&1 || status=$? ;;
    7zz) (cd "$out" && 7zz x -y -snl -bso0 -bsp0 "$archive") >/dev/null 2>&1 || status=$? ;;
    exarch) "$exarch" extract --allow-symlinks "$archive" "$out" >/dev/null 2>&1 || status=$? ;;
  esac
  classify "$status" "$out"
  rm -rf "$out"
}

tools=(exarch)
have bsdtar && tools+=(bsdtar)
have 7z && tools+=(7z)
have 7zz && tools+=(7zz)

echo "# bsdtar: $(have bsdtar && bsdtar --version || echo none)"
echo "# 7z: $(have 7z && 7z | sed -n 2p || echo none)"
echo "# 7zz: $(have 7zz && 7zz | sed -n 2p || echo none)"
echo "# exarch: $(cd "$root" && git rev-parse --short HEAD)"
printf 'archive'
for tool in "${tools[@]}"; do printf '\t%s' "$tool"; done
printf '\n'

for archive in "$dir"/*.7z; do
  printf '%s' "$(basename "$archive" .7z)"
  for tool in "${tools[@]}"; do printf '\t%s' "$(run_tool "$tool" "$archive")"; done
  printf '\n'
done
