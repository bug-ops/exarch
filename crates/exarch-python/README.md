# exarch

[![PyPI](https://img.shields.io/pypi/v/exarch)](https://pypi.org/project/exarch)
[![Python](https://img.shields.io/pypi/pyversions/exarch)](https://pypi.org/project/exarch)
[![CI](https://img.shields.io/github/actions/workflow/status/bug-ops/exarch/ci.yml?branch=main)](https://github.com/bug-ops/exarch/actions)
[![License](https://img.shields.io/pypi/l/exarch)](LICENSE-MIT)

Memory-safe archive extraction library for Python.

> [!IMPORTANT]
> **exarch** is designed as a secure replacement for vulnerable archive libraries like Python's `tarfile`, which has known CVEs with CVSS scores up to 9.4.

This package provides Python bindings for [exarch-core](../exarch-core), a Rust library with built-in protection against common archive vulnerabilities.

## Installation

```bash
pip install exarch
```

> [!TIP]
> Use `uv pip install exarch` for faster installation (10-100x faster than pip).

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
print(f"Extracted {result['files_extracted']} files")
print(f"Total bytes: {result['bytes_written']}")
print(f"Duration: {result['duration_ms']}ms")
```

## Usage

### Basic Extraction

```python
import exarch

# Extract with default security settings
result = exarch.extract_archive(
    archive_path="archive.tar.gz",
    output_dir="/safe/output/directory"
)

# Check results
print(f"Files extracted: {result['files_extracted']}")
print(f"Bytes written: {result['bytes_written']}")
print(f"Duration: {result['duration_ms']}ms")
```

### Error Handling

```python
import exarch

try:
    result = exarch.extract_archive("archive.tar.gz", "/output")
except RuntimeError as e:
    print(f"Extraction failed: {e}")
```

## API Reference

### `extract_archive(archive_path, output_dir)`

Extract an archive to the specified directory with security validation.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `archive_path` | `str` | Path to the archive file |
| `output_dir` | `str` | Directory where files will be extracted |

**Returns:**

A dictionary with extraction statistics:

| Key | Type | Description |
|-----|------|-------------|
| `files_extracted` | `int` | Number of files extracted |
| `bytes_written` | `int` | Total bytes written |
| `duration_ms` | `int` | Extraction duration in milliseconds |

**Raises:**

- `RuntimeError` - If extraction fails due to security violations or I/O errors

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
> Unlike Python's standard `tarfile` module, exarch applies security validation by default. This may cause some archives to fail extraction if they contain potentially malicious content.

## Supported Formats

- TAR (`.tar`)
- TAR+GZIP (`.tar.gz`, `.tgz`)
- TAR+BZIP2 (`.tar.bz2`)
- TAR+XZ (`.tar.xz`, `.txz`)
- ZIP (`.zip`)

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

- [exarch-core](../exarch-core) - Core Rust library
- [exarch (npm)](../exarch-node) - Node.js bindings

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](../../LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
