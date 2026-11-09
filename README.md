# exarch

[![CI](https://img.shields.io/github/actions/workflow/status/bug-ops/exarch/ci.yml?branch=main)](https://github.com/bug-ops/exarch/actions)
[![codecov](https://codecov.io/gh/bug-ops/exarch/graph/badge.svg?token=AKF1TLTVCA)](https://codecov.io/gh/bug-ops/exarch)
[![crates.io](https://img.shields.io/crates/v/exarch-core)](https://crates.io/crates/exarch-core)
[![docs.rs](https://img.shields.io/docsrs/exarch-core)](https://docs.rs/exarch-core)
[![PyPI](https://img.shields.io/pypi/v/exarch)](https://pypi.org/project/exarch)
[![npm](https://img.shields.io/npm/v/exarch-rs)](https://www.npmjs.com/package/exarch-rs)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue)](LICENSE-MIT)
[![MSRV](https://img.shields.io/badge/MSRV-1.99.1-blue)](https://github.com/bug-ops/exarch)

Memory-safe archive extraction and creation library with Python and Node.js bindings.

> [!IMPORTANT]
> **exarch** is designed as a secure replacement for vulnerable archive libraries like Python's `tarfile` and Node.js's `tar-fs`, which have known CVEs with CVSS scores up to 9.4.

## Features

- **Extract, create, list, and verify archives** — Full support for TAR and ZIP (all operations), plus 7z extraction, listing, and verification
- **Format auto-detection** — Falls back to magic-byte inspection when the file extension is absent, unrecognised, or contradicts the file content
- **Security-first design** — Default-deny security model with protection against path traversal, symlink attacks, zip bombs, and more
- **Type-driven safety** — Rust's type system ensures validated paths can only be constructed through security checks
- **Extension allowlists** — Optional `allowed_extensions` filter restricts extraction to a specific set of file extensions across TAR, ZIP, and 7z handlers
- **Fluent configuration** — 15 `with_*` builder methods on `SecurityConfig` and 3 on `ExtractionOptions` for ergonomic setup
- **In-memory processing** — `ArchiveReader`, `SinkExtractRequest` with `MemorySink`, and `CreateRequest::write` validate and build archives without a filesystem path, with in-memory functions in Python and Node.js
- **Multi-language support** — Native bindings for Python (PyO3) and Node.js (napi-rs)
- **Minimal unsafe code** — `unsafe` in the core library is denied by lint and confined to documented FFI sites (destination access check on Unix, NT directory-handle calls on Windows)
- **High performance** — Optimized I/O with reusable buffers and streaming operations

## Installation

### Rust

```toml
[dependencies]
exarch-core = "0.9"
```

> [!IMPORTANT]
> Requires Rust 1.99.1 or later (Edition 2024).

### Python

```bash
pip install exarch
```

> [!NOTE]
> Requires Python 3.11 or later.

### Node.js

```bash
npm install exarch-rs
```

> [!NOTE]
> Requires Node.js 20 or later.

## Quick Start

### Extraction

#### Rust

```rust
use exarch_core::{extract_archive, SecurityConfig};

fn main() -> Result<(), exarch_core::ArchiveError> {
    let config = SecurityConfig::default();
    let report = extract_archive("archive.tar.gz", "/output/path", &config)?;

    println!("Extracted {} files ({} bytes, {} skipped)",
        report.files_extracted,
        report.bytes_written,
        report.files_skipped());
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
const { extractArchive } = require('exarch-rs');

// Async (recommended)
const result = await extractArchive('archive.tar.gz', '/output/path');
console.log(`Extracted ${result.filesExtracted} files`);
```

### Creation

#### Rust

```rust
use exarch_core::{create_archive, CreationConfig};

fn main() -> Result<(), exarch_core::ArchiveError> {
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
const { createArchive } = require('exarch-rs');

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
| TAR metadata bombs | Bounds GNU long-name/long-link and PAX header record reads | Enabled (4 MiB, 16 MiB for `permissive()`) |
| Permission sanitization | Strips setuid/setgid bits | Enabled |
| Size limits | Configurable file and total size limits | 50 MB / 500 MB |

> [!CAUTION]
> Enabling symlinks or hardlinks should only be done when you fully trust the archive source.

### CLI: Strict Verification

The `verify` command accepts `--strict` to treat warnings as errors:

```bash
# Exit 0 — only hard failures are errors
exarch verify archive.tar.gz

# Exit 3 if any warnings are found (e.g. setuid bits), exit 1 on failure
exarch verify --strict archive.tar.gz
```

### Security Configuration

```rust
use exarch_core::{non_zero, ratio_limit, Extension, ExtensionFilter, SecurityConfig};

let config = SecurityConfig::default()
    .with_max_file_size(non_zero!(100 * 1024 * 1024))    // 100 MB
    .with_max_total_size(non_zero!(1024 * 1024 * 1024))  // 1 GB
    .with_max_compression_ratio(ratio_limit!(50.0)) // 50x compression limit
    .with_allowed_extensions(ExtensionFilter::only(vec![
        Extension::try_from(".tar")?,
        Extension::try_from(".gz")?,
    ])?); // optional allowlist
```

> [!IMPORTANT]
> `SecurityConfig`, `AllowedFeatures`, and `ExtractionOptions` are `#[non_exhaustive]` since v0.4.0. Use `Default::default()` plus the fluent `with_*` builder methods instead of struct literal syntax.
> Since v0.6.1, `ArchiveError`, `QuotaResource`, `ArchiveType`, `CompressionCodec`, `IssueCategory`, and `EntryType` are `#[non_exhaustive]` too — an exhaustive `match` on any of them needs a wildcard `_` arm.

## Supported Formats

| Format | Extensions | Extract | Create | List | Verify | Compression |
|--------|------------|:-------:|:------:|:----:|:------:|-------------|
| TAR | `.tar` | ✅ | ✅ | ✅ | ✅ | None |
| TAR+GZIP | `.tar.gz`, `.tgz` | ✅ | ✅ | ✅ | ✅ | gzip |
| TAR+BZIP2 | `.tar.bz2`, `.tbz2` | ✅ | ✅ | ✅ | ✅ | bzip2 |
| TAR+XZ | `.tar.xz`, `.txz` | ✅ | ✅ | ✅ | ✅ | xz/lzma |
| TAR+ZSTD | `.tar.zst`, `.tzst` | ✅ | ✅ | ✅ | ✅ | zstandard |
| ZIP | `.zip` | ✅ | ✅ | ✅ | ✅ | deflate, deflate64, bzip2, zstd |
| ZIP-family | `.jar`, `.war`, `.ear`, `.nar`, `.nbm`, `.apk`, `.aab`, `.ipa`, `.appx`, `.msix`, `.whl`, `.vsix`, `.xpi`, `.epub` | ✅ | — | ✅ | ✅ | deflate, deflate64, bzip2, zstd |
| 7z | `.7z` | ✅ | — | ✅ | ✅ | lzma, lzma2 |

> [!NOTE]
> ZIP-family formats share the ZIP container but add extra structure - signing (`.apk`/`.aab`/`.ipa`/`.appx`/`.msix`), checksum manifests (`.whl`), ordering rules (`.epub`), or descriptor files (`.war`/`.ear`/`.vsix`/`.nbm`) - which exarch doesn't produce. Creation is rejected to avoid silently emitting a bare ZIP with a misleading extension; callers who want that can state `CreatableFormat::Zip` with `OutputFile::with_format`.

> [!NOTE]
> 7z creation is not yet supported. Solid and encrypted 7z archives are rejected for security reasons. A 7z archive holding a Windows reparse point is refused as a whole; a Unix `S_IFLNK` symlink is read and validated through the symlink policy, so it is created only with symlinks allowed, and a 7z FIFO, socket or device node is refused.

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

exarch uses optimized I/O with atomic permission setting to outperform native archive libraries:

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

- Rust 1.99.1 or later (Edition 2024)
- Python 3.11+ (for Python bindings)
- Node.js 20+ (for Node.js bindings)

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
