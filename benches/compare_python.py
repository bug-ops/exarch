#!/usr/bin/env python3
"""
Benchmark comparison: exarch Python bindings vs native Python tarfile/zipfile.

This script compares extraction performance between:
- exarch: Rust-based secure archive extraction (via PyO3 bindings)
- tarfile: Python's built-in TAR handling
- zipfile: Python's built-in ZIP handling

Usage:
    python compare_python.py [fixtures_dir]

Requirements:
    - exarch Python package installed (pip install exarch or maturin develop)
    - Benchmark fixtures generated (./generate_fixtures.sh)

Output:
    Markdown table with performance comparison and speedup ratios.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path
from typing import NamedTuple


class BenchmarkResult(NamedTuple):
    """Result of a single benchmark run."""
    name: str
    exarch_time_ms: float
    native_time_ms: float
    file_count: int
    total_bytes: int

    @property
    def speedup(self) -> float:
        """Speedup ratio (native_time / exarch_time)."""
        if self.exarch_time_ms == 0:
            return float('inf')
        return self.native_time_ms / self.exarch_time_ms

    @property
    def exarch_throughput_mbps(self) -> float:
        """Exarch throughput in MB/s."""
        if self.exarch_time_ms == 0:
            return float('inf')
        return (self.total_bytes / 1024 / 1024) / (self.exarch_time_ms / 1000)

    @property
    def native_throughput_mbps(self) -> float:
        """Native throughput in MB/s."""
        if self.native_time_ms == 0:
            return float('inf')
        return (self.total_bytes / 1024 / 1024) / (self.native_time_ms / 1000)


def time_function(func, iterations: int = 3) -> float:
    """Time a function over multiple iterations and return median time in ms."""
    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        func()
        end = time.perf_counter()
        times.append((end - start) * 1000)
    times.sort()
    return times[len(times) // 2]  # Return median


def benchmark_tar_extraction(
    archive_path: Path,
    iterations: int = 3,
) -> tuple[float, float]:
    """Benchmark TAR extraction with exarch vs tarfile."""
    try:
        import exarch
    except ImportError:
        print("Error: exarch not installed. Run: maturin develop --release")
        sys.exit(1)

    # Exarch extraction
    def extract_exarch():
        with tempfile.TemporaryDirectory() as tmpdir:
            config = exarch.SecurityConfig().max_file_size(500*1024*1024).max_total_size(1024*1024*1024)
            exarch.extract_archive(str(archive_path), tmpdir, config)

    exarch_time = time_function(extract_exarch, iterations)

    # Native tarfile extraction
    def extract_native():
        with tempfile.TemporaryDirectory() as tmpdir:
            with tarfile.open(archive_path) as tar:
                tar.extractall(tmpdir, filter='data')

    native_time = time_function(extract_native, iterations)

    return exarch_time, native_time


def benchmark_zip_extraction(
    archive_path: Path,
    iterations: int = 3,
) -> tuple[float, float]:
    """Benchmark ZIP extraction with exarch vs zipfile."""
    try:
        import exarch
    except ImportError:
        print("Error: exarch not installed. Run: maturin develop --release")
        sys.exit(1)

    # Exarch extraction
    def extract_exarch():
        with tempfile.TemporaryDirectory() as tmpdir:
            config = exarch.SecurityConfig().max_file_size(500*1024*1024).max_total_size(1024*1024*1024)
            exarch.extract_archive(str(archive_path), tmpdir, config)

    exarch_time = time_function(extract_exarch, iterations)

    # Native zipfile extraction
    def extract_native():
        with tempfile.TemporaryDirectory() as tmpdir:
            with zipfile.ZipFile(archive_path) as zf:
                zf.extractall(tmpdir)

    native_time = time_function(extract_native, iterations)

    return exarch_time, native_time


def get_archive_stats(archive_path: Path) -> tuple[int, int]:
    """Get file count and total uncompressed size from archive."""
    file_count = 0
    total_bytes = 0

    suffix = archive_path.suffix.lower()
    if suffix == '.zip':
        with zipfile.ZipFile(archive_path) as zf:
            for info in zf.infolist():
                if not info.is_dir():
                    file_count += 1
                    total_bytes += info.file_size
    elif suffix in ('.tar', '.gz', '.bz2', '.xz', '.zst'):
        # Handle compressed tarballs
        try:
            with tarfile.open(archive_path) as tar:
                for member in tar.getmembers():
                    if member.isfile():
                        file_count += 1
                        total_bytes += member.size
        except Exception:
            pass

    return file_count, total_bytes


def run_benchmarks(fixtures_dir: Path, iterations: int = 5) -> list[BenchmarkResult]:
    """Run all benchmarks and return results."""
    results = []

    # TAR benchmarks
    tar_fixtures = [
        ("small_files.tar", "TAR small (1MB, 1000 files)"),
        ("small_files.tar.gz", "TAR+GZIP small"),
        ("medium_files.tar", "TAR medium (10MB, 100 files)"),
        ("medium_files.tar.gz", "TAR+GZIP medium"),
        ("large_file.tar", "TAR large (100MB, 1 file)"),
        ("large_file.tar.gz", "TAR+GZIP large"),
        ("nested_dirs.tar.gz", "TAR nested dirs"),
        ("many_files.tar.gz", "TAR many files (10k)"),
        ("mixed.tar.gz", "TAR mixed sizes"),
    ]

    for filename, name in tar_fixtures:
        archive_path = fixtures_dir / filename
        if not archive_path.exists():
            print(f"  Skipping {name}: {filename} not found")
            continue

        print(f"  Benchmarking {name}...")
        file_count, total_bytes = get_archive_stats(archive_path)
        exarch_time, native_time = benchmark_tar_extraction(archive_path, iterations)

        results.append(BenchmarkResult(
            name=name,
            exarch_time_ms=exarch_time,
            native_time_ms=native_time,
            file_count=file_count,
            total_bytes=total_bytes,
        ))

    # ZIP benchmarks
    zip_fixtures = [
        ("small_files.zip", "ZIP small (1MB, 1000 files)"),
        ("medium_files.zip", "ZIP medium (10MB, 100 files)"),
        ("large_file.zip", "ZIP large (100MB, 1 file)"),
        ("nested_dirs.zip", "ZIP nested dirs"),
        ("many_files.zip", "ZIP many files (10k)"),
        ("mixed.zip", "ZIP mixed sizes"),
    ]

    for filename, name in zip_fixtures:
        archive_path = fixtures_dir / filename
        if not archive_path.exists():
            print(f"  Skipping {name}: {filename} not found")
            continue

        print(f"  Benchmarking {name}...")
        file_count, total_bytes = get_archive_stats(archive_path)
        exarch_time, native_time = benchmark_zip_extraction(archive_path, iterations)

        results.append(BenchmarkResult(
            name=name,
            exarch_time_ms=exarch_time,
            native_time_ms=native_time,
            file_count=file_count,
            total_bytes=total_bytes,
        ))

    return results


def format_results_markdown(results: list[BenchmarkResult]) -> str:
    """Format benchmark results as markdown table."""
    lines = [
        "# Python Benchmark Results: exarch vs tarfile/zipfile",
        "",
        "## Extraction Performance",
        "",
        "| Archive | Files | Size | exarch (ms) | Native (ms) | Speedup | exarch MB/s |",
        "|---------|-------|------|-------------|-------------|---------|-------------|",
    ]

    for r in results:
        size_mb = r.total_bytes / 1024 / 1024
        speedup_str = f"{r.speedup:.2f}x" if r.speedup < 100 else f"{r.speedup:.1f}x"
        lines.append(
            f"| {r.name} | {r.file_count:,} | {size_mb:.1f} MB | "
            f"{r.exarch_time_ms:.1f} | {r.native_time_ms:.1f} | "
            f"**{speedup_str}** | {r.exarch_throughput_mbps:.1f} |"
        )

    # Summary
    if results:
        avg_speedup = sum(r.speedup for r in results) / len(results)
        max_speedup = max(r.speedup for r in results)

        lines.extend([
            "",
            "## Summary",
            "",
            f"- **Average speedup**: {avg_speedup:.2f}x faster than native Python",
            f"- **Maximum speedup**: {max_speedup:.2f}x",
            "",
            "### Performance Targets (from CLAUDE.md)",
            "",
            "| Format | Target | Achieved |",
            "|--------|--------|----------|",
        ])

        # Find TAR and ZIP results for target comparison
        tar_results = [r for r in results if r.name.startswith("TAR") and r.total_bytes > 10_000_000]
        zip_results = [r for r in results if r.name.startswith("ZIP") and r.total_bytes > 10_000_000]

        if tar_results:
            avg_tar_throughput = sum(r.exarch_throughput_mbps for r in tar_results) / len(tar_results)
            tar_status = "Yes" if avg_tar_throughput >= 500 else "No"
            lines.append(f"| TAR extraction | 500 MB/s | {avg_tar_throughput:.0f} MB/s ({tar_status}) |")

        if zip_results:
            avg_zip_throughput = sum(r.exarch_throughput_mbps for r in zip_results) / len(zip_results)
            zip_status = "Yes" if avg_zip_throughput >= 300 else "No"
            lines.append(f"| ZIP extraction | 300 MB/s | {avg_zip_throughput:.0f} MB/s ({zip_status}) |")

    lines.extend([
        "",
        "## Notes",
        "",
        "- Native Python uses `tarfile` with `filter='data'` (Python 3.12+ secure mode)",
        "- Native Python uses `zipfile.ZipFile.extractall()`",
        "- exarch uses `SecurityConfig.default()` with all security checks enabled",
        "- Times are median of 5 iterations",
        "- Speedup > 1x means exarch is faster",
        "",
    ])

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Benchmark exarch Python bindings vs native Python"
    )
    parser.add_argument(
        "fixtures_dir",
        nargs="?",
        default="./fixtures",
        help="Directory containing benchmark fixtures",
    )
    parser.add_argument(
        "-i", "--iterations",
        type=int,
        default=5,
        help="Number of iterations per benchmark (default: 5)",
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file for markdown results",
    )
    args = parser.parse_args()

    fixtures_dir = Path(args.fixtures_dir)
    if not fixtures_dir.exists():
        print(f"Error: Fixtures directory not found: {fixtures_dir}")
        print("Run ./generate_fixtures.sh first to create benchmark fixtures.")
        sys.exit(1)

    print("=" * 60)
    print("Python Benchmark: exarch vs tarfile/zipfile")
    print("=" * 60)
    print()

    # Check exarch is installed
    try:
        import exarch
        print(f"exarch version: {getattr(exarch, '__version__', 'unknown')}")
    except ImportError:
        print("Error: exarch not installed.")
        print("Run: cd crates/exarch-python && maturin develop --release")
        sys.exit(1)

    print(f"Fixtures directory: {fixtures_dir}")
    print(f"Iterations per benchmark: {args.iterations}")
    print()

    print("Running benchmarks...")
    results = run_benchmarks(fixtures_dir, args.iterations)

    if not results:
        print("No benchmarks completed. Check that fixtures exist.")
        sys.exit(1)

    print()
    markdown = format_results_markdown(results)

    if args.output:
        output_path = Path(args.output)
        output_path.write_text(markdown)
        print(f"Results written to: {output_path}")

    print(markdown)


if __name__ == "__main__":
    main()
