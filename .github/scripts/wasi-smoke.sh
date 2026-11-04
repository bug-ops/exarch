#!/usr/bin/env bash
# Smoke test for the exarch CLI compiled to wasm32-wasip1 and run under wasmtime.
# Usage: wasi-smoke.sh <path-to-exarch.wasm>
set -euo pipefail

WASM="$(cd "$(dirname "${1:?usage: wasi-smoke.sh <exarch.wasm>}")" && pwd)/$(basename "$1")"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

# The preopened directory is the whole work dir, so a traversal entry such as
# `../escaped.txt` extracted into `out-evil` would land inside the sandbox where
# this script can see it. Only exarch itself can then be what stops the escape.
exarch() {
  wasmtime run --dir . "$WASM" "$@"
}

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

expect_content() {
  local path="$1" want="$2" got
  [[ -f "$path" ]] || fail "missing $path"
  got="$(cat "$path")"
  [[ "$got" == "$want" ]] || fail "$path: expected '$want', got '$got'"
}

python3 -I - <<'EOF'
import io
import tarfile
import zipfile


def add_file(tar, name, data):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = 0o644
    tar.addfile(info, io.BytesIO(data))


with tarfile.open("basic.tar.gz", "w:gz") as tar:
    info = tarfile.TarInfo("dir")
    info.type = tarfile.DIRTYPE
    info.mode = 0o755
    tar.addfile(info)
    add_file(tar, "dir/file.txt", b"payload")
    link = tarfile.TarInfo("dir/hard.txt")
    link.type = tarfile.LNKTYPE
    link.linkname = "dir/file.txt"
    tar.addfile(link)

with zipfile.ZipFile("basic.zip", "w", zipfile.ZIP_DEFLATED) as archive:
    archive.writestr("dir/file.txt", "zip-payload")

with tarfile.open("traversal.tar", "w") as tar:
    add_file(tar, "../escaped.txt", b"evil")

with tarfile.open("symlink.tar", "w") as tar:
    link = tarfile.TarInfo("link")
    link.type = tarfile.SYMTYPE
    link.linkname = "target"
    tar.addfile(link)
EOF

echo "== tar.gz with directory, file and hardlink"
exarch extract --allow-hardlinks basic.tar.gz out-gz
expect_content out-gz/dir/file.txt payload
expect_content out-gz/dir/hard.txt payload

echo "== tar.gz into an existing non-empty directory"
mkdir -p out-existing
printf 'keep' >out-existing/existing.txt
exarch extract --allow-hardlinks basic.tar.gz out-existing
expect_content out-existing/existing.txt keep
expect_content out-existing/dir/file.txt payload

echo "== zip"
exarch extract basic.zip out-zip
expect_content out-zip/dir/file.txt zip-payload

# A temporary file would panic on WASI (std has no temp_dir), so the mode must be a no-op there.
echo "== zip with --decode-reuse temp-file"
exarch extract --decode-reuse temp-file basic.zip out-zip-temp
expect_content out-zip-temp/dir/file.txt zip-payload

for ext in tar.xz tar.zst; do
  echo "== create then extract .$ext"
  mkdir -p "src-$ext/nested"
  printf 'round-trip-%s' "$ext" >"src-$ext/nested/data.txt"
  exarch create "archive.$ext" "src-$ext"
  exarch extract "archive.$ext" "out-$ext"
  found="$(find "out-$ext" -name data.txt -type f)"
  [[ -n "$found" ]] || fail "data.txt missing after $ext round-trip"
  expect_content "$found" "round-trip-$ext"
done

echo "== path traversal is refused by exarch"
if exarch extract traversal.tar out-evil 2>traversal.err; then
  fail "traversal archive extracted successfully"
fi
[[ ! -e escaped.txt ]] || fail "traversal entry escaped the destination"
grep -qi 'traversal' traversal.err || {
  cat traversal.err >&2
  fail "traversal error text not produced by exarch"
}

echo "== symlink extraction currently fails closed on WASI"
if exarch extract --allow-symlinks symlink.tar out-symlink 2>symlink.err; then
  fail "symlink extraction unexpectedly succeeded on WASI"
fi
grep -qi 'not supported on this platform' symlink.err || {
  cat symlink.err >&2
  fail "unexpected symlink error text"
}

echo "wasi smoke passed"
