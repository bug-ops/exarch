# exarch-core

[![Crates.io](https://img.shields.io/crates/v/exarch-core)](https://crates.io/crates/exarch-core)
[![docs.rs](https://img.shields.io/docsrs/exarch-core)](https://docs.rs/exarch-core)
[![CI](https://img.shields.io/github/actions/workflow/status/rabax/exarch/ci.yml?branch=main)](https://github.com/rabax/exarch/actions)
[![MSRV](https://img.shields.io/badge/MSRV-1.89.0-blue)](https://github.com/rabax/exarch)
[![License](https://img.shields.io/crates/l/exarch-core)](../../LICENSE-MIT)

Memory-safe archive extraction library with security validation.

This crate is part of the [exarch](https://github.com/rabax/exarch) workspace.

## Installation

```toml
[dependencies]
exarch-core = "0.1"
```

> [!IMPORTANT]
> Requires Rust 1.89.0 or later (Edition 2024).

## Usage

```rust
use exarch_core::{extract_archive, SecurityConfig};

fn main() -> Result<(), exarch_core::ExtractionError> {
    let config = SecurityConfig::default();
    let report = extract_archive("archive.tar.gz", "/output/dir", &config)?;

    println!("Extracted {} files ({} bytes)",
        report.files_extracted,
        report.bytes_written);
    Ok(())
}
```

### Custom Security Configuration

```rust
use exarch_core::SecurityConfig;

let config = SecurityConfig {
    max_file_size: 100 * 1024 * 1024,    // 100 MB per file
    max_total_size: 1024 * 1024 * 1024,  // 1 GB total
    max_file_count: 10_000,               // Max 10k files
    max_compression_ratio: 50.0,          // 50x compression limit
    ..Default::default()
};
```

### Builder Pattern

```rust
use exarch_core::ArchiveBuilder;

let mut archive = ArchiveBuilder::new()
    .max_file_size(50 * 1024 * 1024)
    .max_compression_ratio(100.0)
    .open("archive.tar.gz")?;

let report = archive.extract("/output/path")?;
```

## Security Features

exarch-core provides defense-in-depth protection against common archive vulnerabilities:

| Protection | Description | Default |
|------------|-------------|---------|
| Path traversal | Blocks `../` and absolute paths | Enabled |
| Symlink attacks | Prevents symlinks escaping extraction directory | Blocked |
| Hardlink attacks | Validates hardlink targets within extraction directory | Blocked |
| Zip bombs | Detects high compression ratios | Enabled (100x limit) |
| Permission sanitization | Strips setuid/setgid bits | Enabled |
| Size limits | Configurable file and total size limits | 50 MB / 10 GB |

> [!CAUTION]
> Default configuration blocks symlinks and hardlinks. Enable only when you trust the archive source.

## Supported Formats

| Format | Extensions | Compression |
|--------|------------|-------------|
| TAR | `.tar` | None |
| TAR+GZIP | `.tar.gz`, `.tgz` | gzip |
| TAR+BZIP2 | `.tar.bz2`, `.tbz2` | bzip2 |
| TAR+XZ | `.tar.xz`, `.txz` | xz/lzma |
| TAR+ZSTD | `.tar.zst`, `.tzst` | zstandard |
| ZIP | `.zip` | deflate, deflate64, bzip2, zstd |

## API Overview

### Main Types

| Type | Description |
|------|-------------|
| [`extract_archive`](https://docs.rs/exarch-core/latest/exarch_core/fn.extract_archive.html) | High-level extraction function |
| [`Archive`](https://docs.rs/exarch-core/latest/exarch_core/struct.Archive.html) | Archive handle with typestate pattern |
| [`ArchiveBuilder`](https://docs.rs/exarch-core/latest/exarch_core/struct.ArchiveBuilder.html) | Builder for configuring extraction |
| [`SecurityConfig`](https://docs.rs/exarch-core/latest/exarch_core/struct.SecurityConfig.html) | Security configuration options |
| [`ExtractionReport`](https://docs.rs/exarch-core/latest/exarch_core/struct.ExtractionReport.html) | Extraction statistics and results |
| [`ExtractionError`](https://docs.rs/exarch-core/latest/exarch_core/enum.ExtractionError.html) | Error types for extraction failures |

### Error Handling

```rust
use exarch_core::{extract_archive, ExtractionError, SecurityConfig};

match extract_archive("archive.tar.gz", "/output", &SecurityConfig::default()) {
    Ok(report) => println!("Extracted {} files", report.files_extracted),
    Err(ExtractionError::PathTraversal { path, .. }) => {
        eprintln!("Blocked path traversal: {}", path.display());
    }
    Err(ExtractionError::QuotaExceeded { resource }) => {
        eprintln!("Resource limit exceeded: {:?}", resource);
    }
    Err(e) => eprintln!("Extraction failed: {}", e),
}
```

## Performance

Optimized for throughput with:

- Streaming extraction (no full archive buffering)
- Reusable 64KB copy buffers per archive
- Buffered I/O for file writes
- `SmallVec` for hardlink tracking (avoids heap allocation for typical archives)
- Fast-path quota checks for unlimited quotas

## Related Crates

- [`exarch-python`](../exarch-python) — Python bindings via PyO3
- [`exarch-node`](../exarch-node) — Node.js bindings via napi-rs

## MSRV Policy

> [!NOTE]
> Minimum Supported Rust Version: **1.89.0**. MSRV increases are minor version bumps.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT License ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
