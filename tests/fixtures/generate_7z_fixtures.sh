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

echo ""
echo "All fixtures generated successfully!"
echo "Note: path-traversal.7z requires manual crafting (see README.md)"
echo "Note: symlink-windows.7z requires Windows with symlink support"
