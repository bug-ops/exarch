# exarch-core

[![Crates.io](https://img.shields.io/crates/v/exarch-core)](https://crates.io/crates/exarch-core)
[![docs.rs](https://img.shields.io/docsrs/exarch-core)](https://docs.rs/exarch-core)
[![CI](https://img.shields.io/github/actions/workflow/status/bug-ops/exarch/ci.yml?branch=main)](https://github.com/bug-ops/exarch/actions)
[![MSRV](https://img.shields.io/badge/MSRV-1.89.0-blue)](https://github.com/bug-ops/exarch)
[![License](https://img.shields.io/crates/l/exarch-core)](../../LICENSE-MIT)

Memory-safe archive extraction and creation library with security validation.

This crate is part of the [exarch](https://github.com/bug-ops/exarch) workspace.

## Installation

```toml
[dependencies]
exarch-core = "0.2"
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

let report = ArchiveBuilder::new()
    .archive("archive.tar.gz")
    .output_dir("/output/path")
    .extract()?;
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

## Archive Creation

Create archives with secure defaults:

```rust
use exarch_core::{create_archive, CreationConfig};

// Simple creation with defaults
let config = CreationConfig::default();
let report = create_archive("backup.tar.gz", &["src/", "Cargo.toml"], &config)?;
println!("Created {} files", report.files_added);
```

### Builder Pattern

```rust
use exarch_core::ArchiveCreator;

let report = ArchiveCreator::new()
    .output("project.tar.gz")
    .add_source("src/")
    .add_source("Cargo.toml")
    .add_source("README.md")
    .compression_level(9)
    .exclude("*.log")
    .exclude("target/")
    .create()?;
```

### CreationConfig Options

| Option | Default | Description |
|--------|---------|-------------|
| `follow_symlinks` | `false` | Follow symbolic links |
| `include_hidden` | `false` | Include hidden files (.*) |
| `compression_level` | `6` | Compression level (1-9) |
| `exclude_patterns` | `[".git", ".DS_Store", "*.tmp"]` | Glob patterns to exclude |
| `strip_prefix` | `None` | Strip prefix from paths |
| `preserve_permissions` | `true` | Preserve Unix permissions |

## Supported Formats

| Extension | Format | Compression | Extract | Create | List | Verify |
|-----------|--------|-------------|:-------:|:------:|:----:|:------:|
| `.tar` | TAR | None | ✅ | ✅ | ✅ | ✅ |
| `.tar.gz`, `.tgz` | TAR | Gzip | ✅ | ✅ | ✅ | ✅ |
| `.tar.bz2`, `.tbz2` | TAR | Bzip2 | ✅ | ✅ | ✅ | ✅ |
| `.tar.xz`, `.txz` | TAR | XZ | ✅ | ✅ | ✅ | ✅ |
| `.tar.zst`, `.tzst` | TAR | Zstd | ✅ | ✅ | ✅ | ✅ |
| `.zip` | ZIP | Deflate | ✅ | ✅ | ✅ | ✅ |
| `.7z` | 7z | LZMA/LZMA2 | ✅ | — | ✅ | ✅ |

> [!NOTE]
> 7z creation is not yet supported. Solid and encrypted 7z archives are rejected for security reasons. Unix symlinks inside 7z archives are reported as regular files (sevenz-rust2 API limitation).

## API Overview

### Main Types

| Type | Description |
|------|-------------|
| [`extract_archive`](https://docs.rs/exarch-core/latest/exarch_core/fn.extract_archive.html) | High-level extraction function |
| [`create_archive`](https://docs.rs/exarch-core/latest/exarch_core/fn.create_archive.html) | High-level archive creation function |
| [`list_archive`](https://docs.rs/exarch-core/latest/exarch_core/fn.list_archive.html) | List archive contents |
| [`verify_archive`](https://docs.rs/exarch-core/latest/exarch_core/fn.verify_archive.html) | Verify archive integrity and security |
| [`Archive`](https://docs.rs/exarch-core/latest/exarch_core/struct.Archive.html) | Archive handle for extraction |
| [`ArchiveBuilder`](https://docs.rs/exarch-core/latest/exarch_core/struct.ArchiveBuilder.html) | Builder for configuring extraction |
| [`ArchiveCreator`](https://docs.rs/exarch-core/latest/exarch_core/struct.ArchiveCreator.html) | Builder for configuring archive creation |
| [`SecurityConfig`](https://docs.rs/exarch-core/latest/exarch_core/struct.SecurityConfig.html) | Security configuration for extraction |
| [`CreationConfig`](https://docs.rs/exarch-core/latest/exarch_core/struct.CreationConfig.html) | Configuration for archive creation |
| [`ExtractionReport`](https://docs.rs/exarch-core/latest/exarch_core/struct.ExtractionReport.html) | Extraction statistics and results |
| [`CreationReport`](https://docs.rs/exarch-core/latest/exarch_core/struct.CreationReport.html) | Creation statistics and results |
| [`ExtractionError`](https://docs.rs/exarch-core/latest/exarch_core/enum.ExtractionError.html) | Error types for all operations |

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

- **Directory caching** — FxHashSet caching reduces mkdir syscalls by ~95%
- **Atomic permission setting** — Sets Unix permissions during file creation (1 syscall vs 2)
- Streaming extraction (no full archive buffering)
- Reusable 64KB copy buffers per archive
- Buffered I/O for file writes
- `SmallVec` for hardlink tracking (avoids heap allocation for typical archives)
- Fast-path quota checks for unlimited quotas

**Throughput targets:**
- TAR extraction: 2,136 MB/s (target: 500 MB/s)
- ZIP extraction: 1,444 MB/s (target: 300 MB/s)

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
