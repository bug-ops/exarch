#!/usr/bin/env bash
# Generate 7z test fixtures for exarch-core
# Requires: p7zip (7z command)
# shellcheck disable=SC2035

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURES_DIR="$SCRIPT_DIR"
TEMP_DIR=$(mktemp -d)

cleanup() {
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

cd "$TEMP_DIR"

echo "Generating 7z test fixtures in $FIXTURES_DIR..."

# 1. simple.7z - Basic files
mkdir simple
echo "hello world" > simple/file1.txt
echo "test content" > simple/file2.txt
7z a -t7z -ms=off "$FIXTURES_DIR/simple.7z" simple/* > /dev/null
echo "✓ Created simple.7z"

# 2. nested-dirs.7z - Nested directory structure
mkdir -p nested/subdir1/subdir2
echo "nested file" > nested/subdir1/subdir2/deep.txt
echo "another file" > nested/subdir1/file.txt
7z a -t7z -ms=off "$FIXTURES_DIR/nested-dirs.7z" nested/* > /dev/null
echo "✓ Created nested-dirs.7z"

# 3. solid.7z - Solid compression
mkdir solid
for i in {1..10}; do
    echo "file $i content" | head -c 1000 > "solid/file$i.txt"
done
7z a -t7z -ms=on "$FIXTURES_DIR/solid.7z" solid/* > /dev/null
echo "✓ Created solid.7z (solid compression enabled)"

# 4. encrypted.7z - Password protection
mkdir encrypted
echo "secret content" > encrypted/secret.txt
7z a -t7z -pPassword123 -mhe=on "$FIXTURES_DIR/encrypted.7z" encrypted/* > /dev/null
echo "✓ Created encrypted.7z (password: Password123)"

# 4b. encrypted-content-plain-header.7z - encrypted content, readable header
7z a -t7z -ms=off -pexarch -mhe=off "$FIXTURES_DIR/encrypted-content-plain-header.7z" encrypted/* > /dev/null
echo "✓ Created encrypted-content-plain-header.7z (password: exarch)"

# 5. empty.7z - No entries
touch empty-placeholder
7z a -t7z "$FIXTURES_DIR/empty.7z" empty-placeholder > /dev/null
7z d "$FIXTURES_DIR/empty.7z" empty-placeholder > /dev/null  # Remove entry
echo "✓ Created empty.7z"

# 6. large-file.7z - For quota tests
mkdir large
dd if=/dev/zero of=large/50kb.bin bs=1024 count=50 2>/dev/null
7z a -t7z -ms=off "$FIXTURES_DIR/large-file.7z" large/* > /dev/null
echo "✓ Created large-file.7z (50 KB file)"

# 7. symlink-unix.7z - Unix symlink (requires symlink support)
# Test for symlink support instead of checking OS name
if ln -s /dev/null "/tmp/test_symlink_support_$$" 2>/dev/null; then
    rm -f "/tmp/test_symlink_support_$$"
    mkdir symlink-test
    echo "target file content" > symlink-test/target.txt
    ln -s target.txt symlink-test/link.txt
    7z a -t7z -ms=off "$FIXTURES_DIR/symlink-unix.7z" symlink-test/* > /dev/null
    echo "✓ Created symlink-unix.7z (Unix symlink)"
else
    echo "⚠ Skipping symlink-unix.7z (symlink support not available)"
fi

# 8. hardlink.7z - Hardlink
mkdir hardlink-test
echo "original content" > hardlink-test/original.txt
ln hardlink-test/original.txt hardlink-test/link.txt  # Hard link
7z a -t7z -ms=off "$FIXTURES_DIR/hardlink.7z" hardlink-test/* > /dev/null
echo "✓ Created hardlink.7z (hardlink)"

# 9. interleaved-empty.7z / interleaved-empty-badcrc.7z - a solid block whose
# stream-less file sits between its stream files, so sevenz-rust2 never visits
# the last stream file. The second archive also has a wrong CRC for c.txt.
mkdir interleave
for name in d a b c; do
    head -c 1000 /dev/zero | tr '\0' "$name" > "interleave/$name.txt"
done
7z a -t7z -ms=on -mhc=off "$TEMP_DIR/interleave.7z" interleave/d.txt interleave/a.txt interleave/b.txt interleave/c.txt > /dev/null
python3 - "$TEMP_DIR/interleave.7z" "$FIXTURES_DIR" <<'PY'
import struct, sys, zlib
src, out = sys.argv[1], sys.argv[2]
for name, badcrc in (("interleaved-empty.7z", False), ("interleaved-empty-badcrc.7z", True)):
    d = bytearray(open(src, "rb").read())
    off, ln = struct.unpack("<QQ", d[12:28])
    h = bytearray(d[32 + off : 32 + off + ln])
    # kEmptyStream bitmap: move the empty file from index 0 to index 1
    h[h.index(bytes.fromhex("0e0180")) + 2] = 0x40
    if badcrc:
        crc_c = struct.pack("<I", zlib.crc32(open("interleave/c.txt", "rb").read()))
        h[h.index(crc_c)] ^= 1
    d[32 + off : 32 + off + ln] = h
    d[28:32] = struct.pack("<I", zlib.crc32(h) & 0xFFFFFFFF)
    d[8:12] = struct.pack("<I", zlib.crc32(bytes(d[12:32])) & 0xFFFFFFFF)
    open(f"{out}/{name}", "wb").write(d)
PY
echo "✓ Created interleaved-empty.7z and interleaved-empty-badcrc.7z"

# 10. bcj2.7z / bcj2-spare-pack.7z / bcj2-simple-coder.7z - the packed stream
# count of a BCJ2 block. The spare variant declares one extra pack stream no
# block references; the simple-coder variant declares the BCJ2 method ID on a
# coder with one input, so fewer pack streams exist than a BCJ2 coder implies.
python3 - "$TEMP_DIR" <<'PY'
import random
random.seed(7)
with open("bcj2.bin", "wb") as f:
    f.write(b"".join(b"\xe8" + random.randbytes(4) + b"\x90" * random.randrange(4) for _ in range(2000)))
with open("bcj2-small.bin", "wb") as f:
    f.write(b"0123456789abcdef" * 8)
PY
7z a -t7z -mf=BCJ2 -ms=off -mhc=off "$FIXTURES_DIR/bcj2.7z" bcj2.bin > /dev/null
7z a -t7z -m0=Copy -ms=off -mhc=off "$TEMP_DIR/copy.7z" bcj2-small.bin > /dev/null
python3 - "$FIXTURES_DIR/bcj2.7z" "$TEMP_DIR/copy.7z" "$FIXTURES_DIR" <<'PY'
import struct, sys, zlib

def read_num(b, i):
    first, mask, val = b[i], 0x80, 0
    for n in range(8):
        if first & mask == 0:
            return val | ((first & (mask - 1)) << (8 * n)), i + 1 + n
        val |= b[i + 1 + n] << (8 * n)
        mask >>= 1
    return val, i + 9

def patched(src, patch, out):
    d = bytearray(open(src, "rb").read())
    off, ln = struct.unpack("<QQ", d[12:28])
    h = bytearray(d[32 + off : 32 + off + ln])
    patch(h)
    d = d[: 32 + off] + h
    d[12:28] = struct.pack("<QQ", off, len(h))
    d[28:32] = struct.pack("<I", zlib.crc32(h) & 0xFFFFFFFF)
    d[8:12] = struct.pack("<I", zlib.crc32(bytes(d[12:32])) & 0xFFFFFFFF)
    open(out, "wb").write(d)

def add_spare_pack_stream(h):
    # Header, MainStreamsInfo, PackInfo: pack_pos, count, kSize, sizes, kEnd
    assert h[:3] == bytes([1, 4, 6])
    _, i = read_num(h, 3)
    count, j = read_num(h, i)
    assert count < 0x80 and h[j] == 9
    j += 1
    for _ in range(count):
        _, j = read_num(h, j)
    h[j:j] = bytes([7])
    h[i] = count + 1

def declare_bcj2_on_a_simple_coder(h):
    # kFolder, 1 folder, not external, 1 coder, simple flags with a 1-byte ID 0
    # (Copy) becomes a 4-byte ID 03 03 01 1B (BCJ2)
    k = h.index(bytes([0x0B, 1, 0, 1, 1, 0]))
    h[k + 4 : k + 6] = bytes([4, 3, 3, 1, 0x1B])

src, copy, out = sys.argv[1:4]
patched(src, add_spare_pack_stream, f"{out}/bcj2-spare-pack.7z")
patched(copy, declare_bcj2_on_a_simple_coder, f"{out}/bcj2-simple-coder.7z")
PY
echo "✓ Created bcj2.7z, bcj2-spare-pack.7z and bcj2-simple-coder.7z"

# 11. lzma2-mt.7z - LZMA2 written by 4 threads with 64 KiB independent runs,
# the shape the parallel decoder splits. Seeds the 7z fuzz target too.
python3 - <<'PY'
import random
random.seed(11)
words = [bytes(random.randrange(97, 123) for _ in range(random.randrange(3, 9))) for _ in range(400)]
with open("lzma2-mt.bin", "wb") as f:
    f.write(b" ".join(random.choice(words) for _ in range(30000)))
PY
7z a -t7z -ms=off -m0=LZMA2:d=64k:c=64k -mmt=4 "$FIXTURES_DIR/lzma2-mt.7z" lzma2-mt.bin > /dev/null
echo "✓ Created lzma2-mt.7z (4 independent LZMA2 runs)"

echo ""
echo "All fixtures generated successfully!"
echo "Note: path-traversal.7z requires manual crafting (see README.md)"
echo "Note: symlink-windows.7z requires Windows with symlink support"
