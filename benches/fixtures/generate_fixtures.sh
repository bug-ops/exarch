#!/usr/bin/env bash
#
# Generates benchmark fixtures for exarch performance testing.
#
# Creates archives of various sizes and structures:
# - small_files.tar.gz: 1000 small files (1KB each) - tests file count overhead
# - medium_files.tar.gz: 100 files (100KB each) - balanced workload
# - large_file.tar.gz: Single 100MB file - tests throughput
# - nested_dirs.tar.gz: Deeply nested structure (20 levels)
# - many_files.tar.gz: 10,000+ files - stress test
#
# Usage:
#   ./generate_fixtures.sh [output_dir]
#
# Requirements:
#   - tar, gzip, zip, 7z (p7zip), zstd
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${1:-$SCRIPT_DIR}"
TEMP_DIR=$(mktemp -d)

cleanup() {
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

echo "Generating benchmark fixtures in $OUTPUT_DIR..."
echo "Using temp directory: $TEMP_DIR"

# Helper function to create a file with specific size
create_file() {
    local path="$1"
    local size_kb="$2"
    mkdir -p "$(dirname "$path")"
    dd if=/dev/urandom of="$path" bs=1024 count="$size_kb" 2>/dev/null
}

# Helper function to create a file with repeating content (compressible)
create_compressible_file() {
    local path="$1"
    local size_kb="$2"
    mkdir -p "$(dirname "$path")"
    yes "This is compressible test content for benchmarking. " | head -c $((size_kb * 1024)) > "$path"
}

# -----------------------------------------------------------------------------
# 1. Small files archive (1MB total: 1000 files x 1KB)
# -----------------------------------------------------------------------------
echo "Creating small_files fixtures..."
SMALL_DIR="$TEMP_DIR/small_files"
mkdir -p "$SMALL_DIR"

for i in $(seq 1 1000); do
    create_file "$SMALL_DIR/file_$(printf '%04d' $i).txt" 1
done

# Create TAR archives with different compressions
tar -cf "$OUTPUT_DIR/small_files.tar" -C "$TEMP_DIR" small_files
gzip -kf "$OUTPUT_DIR/small_files.tar"
tar -cjf "$OUTPUT_DIR/small_files.tar.bz2" -C "$TEMP_DIR" small_files
tar -cJf "$OUTPUT_DIR/small_files.tar.xz" -C "$TEMP_DIR" small_files
if command -v zstd &> /dev/null; then
    tar -cf - -C "$TEMP_DIR" small_files | zstd -o "$OUTPUT_DIR/small_files.tar.zst"
fi

# Create ZIP archive
(cd "$TEMP_DIR" && zip -rq "$OUTPUT_DIR/small_files.zip" small_files)

# Create 7z archive
if command -v 7z &> /dev/null; then
    (cd "$TEMP_DIR" && 7z a -mx=5 "$OUTPUT_DIR/small_files.7z" small_files > /dev/null)
fi

rm -rf "$SMALL_DIR"

# -----------------------------------------------------------------------------
# 2. Medium files archive (10MB total: 100 files x 100KB)
# -----------------------------------------------------------------------------
echo "Creating medium_files fixtures..."
MEDIUM_DIR="$TEMP_DIR/medium_files"
mkdir -p "$MEDIUM_DIR"

for i in $(seq 1 100); do
    create_file "$MEDIUM_DIR/file_$(printf '%03d' $i).bin" 100
done

tar -cf "$OUTPUT_DIR/medium_files.tar" -C "$TEMP_DIR" medium_files
gzip -kf "$OUTPUT_DIR/medium_files.tar"
(cd "$TEMP_DIR" && zip -rq "$OUTPUT_DIR/medium_files.zip" medium_files)

if command -v 7z &> /dev/null; then
    (cd "$TEMP_DIR" && 7z a -mx=5 "$OUTPUT_DIR/medium_files.7z" medium_files > /dev/null)
fi

rm -rf "$MEDIUM_DIR"

# -----------------------------------------------------------------------------
# 3. Large file archive (100MB single file)
# -----------------------------------------------------------------------------
echo "Creating large_file fixtures..."
LARGE_DIR="$TEMP_DIR/large_file"
mkdir -p "$LARGE_DIR"

create_file "$LARGE_DIR/large.bin" $((100 * 1024))

tar -cf "$OUTPUT_DIR/large_file.tar" -C "$TEMP_DIR" large_file
gzip -kf "$OUTPUT_DIR/large_file.tar"
(cd "$TEMP_DIR" && zip -rq "$OUTPUT_DIR/large_file.zip" large_file)

if command -v 7z &> /dev/null; then
    (cd "$TEMP_DIR" && 7z a -mx=5 "$OUTPUT_DIR/large_file.7z" large_file > /dev/null)
fi

rm -rf "$LARGE_DIR"

# -----------------------------------------------------------------------------
# 4. Compressible large file (100MB, highly compressible)
# -----------------------------------------------------------------------------
echo "Creating compressible_large fixtures..."
COMP_DIR="$TEMP_DIR/compressible_large"
mkdir -p "$COMP_DIR"

create_compressible_file "$COMP_DIR/compressible.txt" $((100 * 1024))

tar -cf "$OUTPUT_DIR/compressible_large.tar" -C "$TEMP_DIR" compressible_large
gzip -kf "$OUTPUT_DIR/compressible_large.tar"
(cd "$TEMP_DIR" && zip -rq "$OUTPUT_DIR/compressible_large.zip" compressible_large)

rm -rf "$COMP_DIR"

# -----------------------------------------------------------------------------
# 5. Nested directories (20 levels deep, 3 files per level)
# -----------------------------------------------------------------------------
echo "Creating nested_dirs fixtures..."
NESTED_DIR="$TEMP_DIR/nested_dirs"

# Create nested structure
CURRENT="$NESTED_DIR"
for level in $(seq 1 20); do
    mkdir -p "$CURRENT"
    for f in $(seq 1 3); do
        create_file "$CURRENT/file_$f.txt" 1
    done
    CURRENT="$CURRENT/level_$level"
done

tar -cf "$OUTPUT_DIR/nested_dirs.tar" -C "$TEMP_DIR" nested_dirs
gzip -kf "$OUTPUT_DIR/nested_dirs.tar"
(cd "$TEMP_DIR" && zip -rq "$OUTPUT_DIR/nested_dirs.zip" nested_dirs)

rm -rf "$NESTED_DIR"

# -----------------------------------------------------------------------------
# 6. Many files archive (10,000+ files for stress testing)
# -----------------------------------------------------------------------------
echo "Creating many_files fixtures (this may take a while)..."
MANY_DIR="$TEMP_DIR/many_files"
mkdir -p "$MANY_DIR"

# Create 10,000 tiny files (100 bytes each)
for i in $(seq 1 10000); do
    echo "File content $i" > "$MANY_DIR/file_$(printf '%05d' $i).txt"
done

tar -cf "$OUTPUT_DIR/many_files.tar" -C "$TEMP_DIR" many_files
gzip -kf "$OUTPUT_DIR/many_files.tar"
(cd "$TEMP_DIR" && zip -rq "$OUTPUT_DIR/many_files.zip" many_files)

rm -rf "$MANY_DIR"

# -----------------------------------------------------------------------------
# 7. Mixed structure (combination of sizes and types)
# -----------------------------------------------------------------------------
echo "Creating mixed fixtures..."
MIXED_DIR="$TEMP_DIR/mixed"
mkdir -p "$MIXED_DIR/small" "$MIXED_DIR/medium" "$MIXED_DIR/large"

# Small files (500 x 1KB)
for i in $(seq 1 500); do
    create_file "$MIXED_DIR/small/file_$i.txt" 1
done

# Medium files (50 x 100KB)
for i in $(seq 1 50); do
    create_file "$MIXED_DIR/medium/file_$i.bin" 100
done

# Large files (5 x 1MB)
for i in $(seq 1 5); do
    create_file "$MIXED_DIR/large/file_$i.bin" 1024
done

tar -cf "$OUTPUT_DIR/mixed.tar" -C "$TEMP_DIR" mixed
gzip -kf "$OUTPUT_DIR/mixed.tar"
(cd "$TEMP_DIR" && zip -rq "$OUTPUT_DIR/mixed.zip" mixed)

rm -rf "$MIXED_DIR"

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
echo ""
echo "Generated fixtures:"
ls -lh "$OUTPUT_DIR"/*.tar* "$OUTPUT_DIR"/*.zip "$OUTPUT_DIR"/*.7z 2>/dev/null || true
echo ""
echo "Done! Fixtures are ready in: $OUTPUT_DIR"
