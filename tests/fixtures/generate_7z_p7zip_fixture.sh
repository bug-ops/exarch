#!/usr/bin/env bash
# Generates the p7zip 16.02 symlink fixtures inside a container; see #727.
# Debian security updates replace p7zip with 7-Zip builds under the same
# package name, so the bullseye main pocket (16.02+dfsg-8) is pinned. Requires:
# docker.
#
#   symlink-p7zip.7z      `7z a x.7z target.txt link.txt`: a link named on the
#                         command line is stored as a regular file holding the
#                         target text
#   symlink-p7zip-dir.7z  `7z a x.7z pkg`: a link met while recursing into a
#                         directory is stored with S_IFLNK
#
#   tests/fixtures/generate_7z_p7zip_fixture.sh

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT

docker run --rm --platform linux/amd64 -v "$out:/out" debian:bullseye-slim sh -ec '
rm -f /etc/apt/sources.list.d/*
echo "deb http://deb.debian.org/debian bullseye main" > /etc/apt/sources.list
apt-get update -qq > /dev/null
apt-get install -y -qq p7zip-full=16.02+dfsg-8 > /dev/null
mkdir -p /w/pkg
cd /w/pkg
echo "p7zip target" > target.txt
ln -s target.txt link.txt
7z a -ms=off -bd /out/symlink-p7zip.7z target.txt link.txt > /dev/null
cd /w
7z a -ms=off -bd /out/symlink-p7zip-dir.7z pkg > /dev/null
'

cp "$out/symlink-p7zip.7z" "$out/symlink-p7zip-dir.7z" "$here/"
echo "Created symlink-p7zip.7z (argument link) and symlink-p7zip-dir.7z (pkg/link.txt -> target.txt)"
