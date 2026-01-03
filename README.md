# exarch

[![CI](https://img.shields.io/github/actions/workflow/status/bug-ops/exarch/ci.yml?branch=main)](https://github.com/bug-ops/exarch/actions)
[![codecov](https://codecov.io/gh/bug-ops/exarch/graph/badge.svg?token=AKF1TLTVCA)](https://codecov.io/gh/bug-ops/exarch)
[![crates.io](https://img.shields.io/crates/v/exarch-core)](https://crates.io/crates/exarch-core)
[![docs.rs](https://img.shields.io/docsrs/exarch-core)](https://docs.rs/exarch-core)
[![PyPI](https://img.shields.io/pypi/v/exarch)](https://pypi.org/project/exarch)
[![npm](https://img.shields.io/npm/v/exarch-rs)](https://www.npmjs.com/package/exarch-rs)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue)](LICENSE-MIT)
[![MSRV](https://img.shields.io/badge/MSRV-1.89.0-blue)](https://github.com/bug-ops/exarch)

Memory-safe archive extraction and creation library with Python and Node.js bindings.

> [!IMPORTANT]
> **exarch** is designed as a secure replacement for vulnerable archive libraries like Python's `tarfile` and Node.js's `tar-fs`, which have known CVEs with CVSS scores up to 9.4.

## Features

- **Extract and create archives** — Full support for TAR and ZIP (extract and create), plus 7z extraction
- **Security-first design** — Default-deny security model with protection against path traversal, symlink attacks, zip bombs, and more
- **Type-driven safety** — Rust's type system ensures validated paths can only be constructed through security checks
- **Multi-language support** — Native bindings for Python (PyO3) and Node.js (napi-rs)
- **Zero unsafe code** — Core library contains no unsafe Rust code
- **High performance** — Optimized I/O with reusable buffers and streaming operations

## Installation

### Rust

```toml
[dependencies]
exarch-core = "0.2"
```

> [!IMPORTANT]
> Requires Rust 1.89.0 or later (Edition 2024).

### Python

```bash
pip install exarch
```

> [!NOTE]
> Requires Python 3.9 or later.

### Node.js

```bash
npm install exarch-rs
```

> [!NOTE]
> Requires Node.js 18 or later.

## Quick Start

### Extraction

#### Rust

```rust
use exarch_core::{extract_archive, SecurityConfig};

fn main() -> Result<(), exarch_core::ExtractionError> {
    let config = SecurityConfig::default();
    let report = extract_archive("archive.tar.gz", "/output/path", &config)?;

    println!("Extracted {} files ({} bytes)",
        report.files_extracted,
        report.bytes_written);
    Ok(())
}
```

#### Python

```python
import exarch

result = exarch.extract_archive("archive.tar.gz", "/output/path")
print(f"Extracted {result.files_extracted} files")
```

#### Node.js

```javascript
const { extractArchive } = require('exarch');

// Async (recommended)
const result = await extractArchive('archive.tar.gz', '/output/path');
console.log(`Extracted ${result.filesExtracted} files`);
```

### Creation

#### Rust

```rust
use exarch_core::{create_archive, creation::CreationConfig};

fn main() -> Result<(), exarch_core::ExtractionError> {
    let config = CreationConfig::default();
    let report = create_archive("output.tar.gz", &["src/", "Cargo.toml"], &config)?;

    println!("Created archive with {} files ({} bytes)",
        report.files_added,
        report.bytes_written);
    Ok(())
}
```

#### Python

```python
import exarch

result = exarch.create_archive("output.tar.gz", ["src/", "Cargo.toml"])
print(f"Created archive with {result.files_added} files")
```

#### Node.js

```javascript
const { createArchive } = require('exarch');

// Async (recommended)
const result = await createArchive('output.tar.gz', ['src/', 'package.json']);
console.log(`Created archive with ${result.filesAdded} files`);
```

## Security

exarch provides defense-in-depth protection against common archive vulnerabilities:

| Protection | Description | Default |
|------------|-------------|---------|
| Path traversal | Blocks `../` and absolute paths | Enabled |
| Symlink attacks | Prevents symlinks escaping extraction directory | Blocked |
| Hardlink attacks | Validates hardlink targets within extraction directory | Blocked |
| Zip bombs | Detects high compression ratios | Enabled (100x limit) |
| Permission sanitization | Strips setuid/setgid bits | Enabled |
| Size limits | Configurable file and total size limits | 50 MB / 10 GB |

> [!CAUTION]
> Enabling symlinks or hardlinks should only be done when you fully trust the archive source.

### Security Configuration

```rust
use exarch_core::SecurityConfig;

let config = SecurityConfig {
    max_file_size: 100 * 1024 * 1024,   // 100 MB
    max_total_size: 1024 * 1024 * 1024, // 1 GB
    max_compression_ratio: 50.0,         // 50x compression limit
    ..Default::default()
};
```

## Supported Formats

| Format | Extensions | Extract | Create | Compression |
|--------|------------|:-------:|:------:|-------------|
| TAR | `.tar` | ✅ | ✅ | None |
| TAR+GZIP | `.tar.gz`, `.tgz` | ✅ | ✅ | gzip |
| TAR+BZIP2 | `.tar.bz2`, `.tbz2` | ✅ | ✅ | bzip2 |
| TAR+XZ | `.tar.xz`, `.txz` | ✅ | ✅ | xz/lzma |
| TAR+ZSTD | `.tar.zst`, `.tzst` | ✅ | ✅ | zstandard |
| ZIP | `.zip` | ✅ | ✅ | deflate, deflate64, bzip2, zstd |
| 7z | `.7z` | ✅ | — | lzma, lzma2 |

> [!NOTE]
> 7z creation is not yet supported. Solid and encrypted 7z archives are rejected for security reasons.

## Project Structure

```
exarch/
├── crates/
│   ├── exarch-core/     # Core Rust library
│   ├── exarch-cli/      # Command-line utility
│   ├── exarch-python/   # Python bindings (PyO3)
│   └── exarch-node/     # Node.js bindings (napi-rs)
├── benches/             # Criterion benchmarks
├── examples/            # Usage examples
└── tests/               # Integration tests
```

## Performance

exarch uses optimized I/O with directory caching and atomic permission setting to outperform native archive libraries:

| Comparison | Average Speedup | Max Speedup |
|------------|-----------------|-------------|
| vs Python tarfile/zipfile | **1.10x** faster | 1.43x |
| vs Node.js tar/adm-zip | **1.75x** faster | 4.69x |

### Throughput (100MB archives)

| Format | Throughput | vs Target |
|--------|------------|-----------|
| TAR extraction | 2,136 MB/s | **4x** target (500 MB/s) |
| ZIP extraction | 1,444 MB/s | **5x** target (300 MB/s) |
| Path validation | ~85 ns | **12x** better than 1 µs target |

> [!TIP]
> Run `./benches/run_all.sh` to benchmark on your hardware. See [benches/README.md](benches/README.md) for details.

## Development

### Requirements

- Rust 1.89.0 or later (Edition 2024)
- Python 3.9+ (for Python bindings)
- Node.js 18+ (for Node.js bindings)

### Build

```bash
cargo build --workspace
```

### Test

```bash
cargo nextest run --workspace
```

### Pre-commit Checks

```bash
cargo +nightly fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
cargo deny check
```

> [!TIP]
> Run all checks before committing to ensure CI passes.

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.
