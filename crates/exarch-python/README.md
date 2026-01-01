# exarch

[![PyPI](https://img.shields.io/pypi/v/exarch)](https://pypi.org/project/exarch)
[![Python](https://img.shields.io/pypi/pyversions/exarch)](https://pypi.org/project/exarch)
[![CI](https://img.shields.io/github/actions/workflow/status/bug-ops/exarch/ci.yml?branch=main)](https://github.com/bug-ops/exarch/actions)
[![License](https://img.shields.io/pypi/l/exarch)](../../LICENSE-MIT)

Memory-safe archive extraction library for Python.

> [!IMPORTANT]
> **exarch** is designed as a secure replacement for vulnerable archive libraries like Python's `tarfile`, which has known CVEs with CVSS scores up to 9.4.

This package provides Python bindings for [exarch-core](../exarch-core), a Rust library with built-in protection against common archive vulnerabilities.

## Installation

```bash
pip install exarch
```

> [!TIP]
> Use `uv pip install exarch` for faster installation.

### Alternative Package Managers

```bash
# Poetry
poetry add exarch

# Pipenv
pipenv install exarch
```

## Requirements

- Python >= 3.9

## Quick Start

```python
import exarch

result = exarch.extract_archive("archive.tar.gz", "/output/path")
print(f"Extracted {result.files_extracted} files")
```

## Usage

### Basic Extraction

```python
import exarch

result = exarch.extract_archive("archive.tar.gz", "/output/path")

print(f"Files extracted: {result.files_extracted}")
print(f"Bytes written: {result.bytes_written}")
print(f"Duration: {result.duration_ms}ms")
```

### With pathlib.Path

```python
from pathlib import Path
import exarch

archive = Path("archive.tar.gz")
output = Path("/output/path")

result = exarch.extract_archive(archive, output)
```

### Custom Security Configuration

```python
import exarch

config = exarch.SecurityConfig()
config = config.max_file_size(100 * 1024 * 1024)  # 100 MB

result = exarch.extract_archive("archive.tar.gz", "/output", config)
```

### Error Handling

```python
import exarch

try:
    result = exarch.extract_archive("archive.tar.gz", "/output")
    print(f"Extracted {result.files_extracted} files")
except exarch.PathTraversalError as e:
    print(f"Blocked path traversal: {e}")
except exarch.ZipBombError as e:
    print(f"Zip bomb detected: {e}")
except exarch.SecurityViolationError as e:
    print(f"Security violation: {e}")
except exarch.ExtractionError as e:
    print(f"Extraction failed: {e}")
```

## API Reference

### `extract_archive(archive_path, output_dir, config=None)`

Extract an archive to the specified directory with security validation.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `archive_path` | `str \| Path` | Path to the archive file |
| `output_dir` | `str \| Path` | Directory where files will be extracted |
| `config` | `SecurityConfig` | Optional security configuration |

**Returns:** `ExtractionReport`

| Attribute | Type | Description |
|-----------|------|-------------|
| `files_extracted` | `int` | Number of files extracted |
| `bytes_written` | `int` | Total bytes written |
| `duration_ms` | `int` | Extraction duration in milliseconds |

**Raises:**

| Exception | Description |
|-----------|-------------|
| `PathTraversalError` | Path traversal attempt detected |
| `SymlinkEscapeError` | Symlink points outside extraction directory |
| `HardlinkEscapeError` | Hardlink target outside extraction directory |
| `ZipBombError` | Potential zip bomb detected |
| `QuotaExceededError` | Resource quota exceeded |
| `SecurityViolationError` | Security policy violation |
| `UnsupportedFormatError` | Archive format not supported |
| `InvalidArchiveError` | Archive is corrupted |
| `IOError` | I/O operation failed |

### `SecurityConfig`

Builder-style security configuration.

```python
config = exarch.SecurityConfig()
config = config.max_file_size(100 * 1024 * 1024)   # 100 MB per file
config = config.max_total_size(1024 * 1024 * 1024) # 1 GB total
config = config.max_file_count(10_000)              # Max 10k files
```

## Security Features

The library provides built-in protection against:

| Protection | Description |
|------------|-------------|
| Path traversal | Blocks `../` and absolute paths |
| Symlink attacks | Prevents symlinks escaping extraction directory |
| Hardlink attacks | Validates hardlink targets |
| Zip bombs | Detects high compression ratios |
| Permission sanitization | Strips setuid/setgid bits |
| Size limits | Enforces file and total size limits |

> [!CAUTION]
> Unlike Python's standard `tarfile` module, exarch applies security validation by default.

## Supported Formats

| Format | Extensions |
|--------|------------|
| TAR | `.tar` |
| TAR+GZIP | `.tar.gz`, `.tgz` |
| TAR+BZIP2 | `.tar.bz2`, `.tbz2` |
| TAR+XZ | `.tar.xz`, `.txz` |
| TAR+ZSTD | `.tar.zst`, `.tzst` |
| ZIP | `.zip` |

## Comparison with tarfile

```python
# UNSAFE - tarfile has known vulnerabilities (CVE-2007-4559)
import tarfile
with tarfile.open("archive.tar.gz") as tar:
    tar.extractall("/output")  # May extract outside target directory!

# SAFE - exarch validates all paths
import exarch
exarch.extract_archive("archive.tar.gz", "/output")  # Protected by default
```

## Development

This package is built using [PyO3](https://pyo3.rs/) and [maturin](https://github.com/PyO3/maturin).

```bash
# Clone repository
git clone https://github.com/bug-ops/exarch
cd exarch/crates/exarch-python

# Build with maturin
pip install maturin
maturin develop

# Run tests
pytest tests/
```

## Related Packages

- [exarch-core](../exarch-core) — Core Rust library
- [exarch (npm)](../exarch-node) — Node.js bindings

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT License ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
