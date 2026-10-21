#!/usr/bin/env bash
# Builds a corpus of legitimate ZIP archives from the tools installed on this
# machine, for crates/exarch-core/tests/zip_corpus.rs:
#
#   scripts/zip-corpus.sh /tmp/zip-corpus
#   EXARCH_ZIP_CORPUS_DIR=/tmp/zip-corpus cargo nextest run -p exarch-core --test zip_corpus --run-ignored only
#
# Tools that are not installed are skipped. The in-tree Java and PowerShell
# producers also run at test time (tests/zip_corpus.rs). Every archive must pass the
# default ZIP structure policy with no finding.
set -euo pipefail

out="${1:?usage: zip-corpus.sh OUTPUT_DIR}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$out" "$work/src/sub" "$work/src/emptydir"
out="$(cd "$out" && pwd)"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

printf 'hello\n' >"$work/src/a.txt"
head -c 200000 /dev/urandom >"$work/src/sub/rand.bin"
printf 'x%.0s' $(seq 1 5000) >"$work/src/sub/rep.txt"
touch "$work/src/empty"
printf 'unicode\n' >"$work/src/sub/caf$(printf '\xc3\xa9').txt"

have() { command -v "$1" >/dev/null 2>&1; }

cd "$work/src"
if have zip; then
  zip -qr "$out/infozip.zip" .
  zip -qr -X "$out/infozip_X.zip" .
  zip -qr -0 "$out/infozip_store.zip" .
  zip -qr -fd "$out/infozip_fd.zip" . 2>/dev/null || true
  cat a.txt | zip -q "$out/infozip_stdin.zip" -
  zip -qr - . | cat >"$out/infozip_stream_deflate.zip"
  zip -qr -0 - . | cat >"$out/infozip_stream_store.zip"
fi
if have ditto; then
  ditto -c -k --sequesterRsrc . "$out/ditto.zip"
  ditto -c -k --keepParent . "$out/ditto_parent.zip"
fi
if have jar && jar --version >/dev/null 2>&1; then
  jar cf "$out/jar.jar" .
  jar cf0 "$out/jar_store.jar" .
fi
if have java && java --version >/dev/null 2>&1; then
  java "$here/../crates/exarch-core/tests/data/ZipProducer.java" "$out"
fi
if have pwsh; then
  pwsh -NoProfile -Command "Compress-Archive -Path '$work/src/*' -DestinationPath '$out/compress_archive.zip'"
  pwsh -NoProfile -Command "Add-Type -AssemblyName System.IO.Compression.FileSystem; [System.IO.Compression.ZipFile]::CreateFromDirectory('$work/src', '$out/dotnet.zip')"
fi
if have 7z; then
  7z a -tzip -bso0 -bsp0 "$out/7z.zip" . >/dev/null
  7z a -tzip -so x.zip . 2>/dev/null | cat >"$out/7z_stream_deflate.zip"
fi
if have bsdtar; then
  bsdtar --format zip -cf "$out/bsdtar.zip" .
  bsdtar --format zip -cf - . | cat >"$out/bsdtar_stream.zip"
  bsdtar --format zip --options zip:compression=store -cf - . | cat >"$out/bsdtar_stream_store.zip"
fi
if have go; then
  go run "$here/../crates/exarch-core/tests/data/ZipProducer.go" "$work/src" "$out"
fi
if have python3; then
  python3 -I - "$out" <<'EOF'
import os
import sys
import zipfile

out = sys.argv[1]

with zipfile.ZipFile(f"{out}/py_deflate.zip", "w", zipfile.ZIP_DEFLATED) as z:
    for root, _, files in os.walk("."):
        for name in files:
            z.write(os.path.join(root, name))


class Unseekable:
    def __init__(self, f):
        self.f = f

    def write(self, data):
        return self.f.write(data)

    def flush(self):
        self.f.flush()


with open(f"{out}/py_unseekable.zip", "wb") as raw:
    with zipfile.ZipFile(Unseekable(raw), "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("a.txt", b"hi" * 1000)
        with z.open("big.bin", "w", force_zip64=True) as w:
            w.write(b"y" * 70000)

for tag, method, zip64 in [
    ("py_unseekable_store", zipfile.ZIP_STORED, False),
    ("py_unseekable_store_zip64", zipfile.ZIP_STORED, True),
    ("py_unseekable_deflate_zip64", zipfile.ZIP_DEFLATED, True),
]:
    with open(f"{out}/{tag}.zip", "wb") as raw:
        with zipfile.ZipFile(Unseekable(raw), "w", method) as z:
            for name in ["a.txt", "sub/rep.txt", "sub/rand.bin", "empty"]:
                with z.open(name, "w", force_zip64=zip64) as w:
                    w.write(open(name, "rb").read())
EOF
fi

echo "Corpus written to $out"
ls "$out"
