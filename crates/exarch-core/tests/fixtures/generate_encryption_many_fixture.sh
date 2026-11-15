#!/usr/bin/env bash
# Generates `enc-many.7z` for the plaintext-twin test of #1023 (spec 024 GN-5):
# a non-solid 7z with 300 AES-256 encrypted files, well beyond the 224 blocks a
# key-derivation charge per block would allow at the default budget. File
# `f000`..`f299` holds the decimal of its index modulo 100 (one or two bytes);
# the password is `correct-horse`. Needs the local `7z` (p7zip 17.05).
#
#   crates/exarch-core/tests/fixtures/generate_encryption_many_fixture.sh

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cd "$work"
for i in $(seq 0 299); do
  printf '%s' "$((i % 100))" > "$(printf 'f%03d' "$i")"
done

rm -f "$here/enc-many.7z"
7z a -bd -ms=off -mhc=off -pcorrect-horse "$here/enc-many.7z" f* > /dev/null
echo "Created enc-many.7z"
