# exarch-core

[![Crates.io](https://img.shields.io/crates/v/exarch-core)](https://crates.io/crates/exarch-core)
[![docs.rs](https://img.shields.io/docsrs/exarch-core)](https://docs.rs/exarch-core)
[![CI](https://img.shields.io/github/actions/workflow/status/bug-ops/exarch/ci.yml?branch=main)](https://github.com/bug-ops/exarch/actions)
[![MSRV](https://img.shields.io/badge/MSRV-1.93.0-blue)](https://github.com/bug-ops/exarch)
[![License](https://img.shields.io/crates/l/exarch-core)](../../LICENSE-MIT)

Memory-safe archive extraction and creation library with security validation.

This crate is part of the [exarch](https://github.com/bug-ops/exarch) workspace.

## Installation

```toml
[dependencies]
exarch-core = "0.4"
```

> [!IMPORTANT]
> Requires Rust 1.93.0 or later (Edition 2024).

## Usage

```rust
use exarch_core::{extract_archive, SecurityConfig};

fn main() -> Result<(), exarch_core::ArchiveError> {
    let config = SecurityConfig::default();
    let report = extract_archive("archive.tar.gz", "/output/dir", &config)?;

    println!("Extracted {} files ({} bytes)",
        report.files_extracted,
        report.bytes_written);
    Ok(())
}
```

### Custom Security Configuration

> [!IMPORTANT]
> Since v0.4.0, `SecurityConfig`, `AllowedFeatures`, and `ExtractionOptions` are `#[non_exhaustive]`. Use `Default::default()` plus the fluent `with_*` builder methods instead of struct literal syntax.

```rust
use exarch_core::SecurityConfig;

let config = SecurityConfig::default()
    .with_max_file_size(100 * 1024 * 1024)    // 100 MB per file
    .with_max_total_size(1024 * 1024 * 1024)  // 1 GB total
    .with_max_file_count(10_000)              // Max 10k files
    .with_max_compression_ratio(50.0)         // 50x compression limit
    .with_allowed_extensions(vec![".tar".into(), ".gz".into()]); // optional allowlist
```

Available builders on `SecurityConfig`: `with_max_file_size`, `with_max_total_size`, `with_max_compression_ratio`, `with_max_file_count`, `with_max_path_depth`, `with_allowed`, `with_allow_symlinks`, `with_allow_hardlinks`, `with_allow_absolute_paths`, `with_allow_world_writable`, `with_preserve_permissions`, `with_allowed_extensions`, `with_banned_path_components`, `with_allow_solid_archives`, `with_max_solid_block_memory`. On `ExtractionOptions`: `with_atomic`, `with_skip_duplicates`.

### Builder Pattern

```rust
use exarch_core::ArchiveBuilder;

let report = ArchiveBuilder::new()
    .archive("archive.tar.gz")
    .output_dir("/output/path")
    .extract()?;
```

> [!WARNING]
> **Breaking change in v0.4.0:** `Archive::open` now returns `Self` directly instead of `Result<Self>`. Drop the `?` or `.unwrap()` at call sites; I/O errors now surface on `extract()` instead.

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
| [`ExtractionReport`](https://docs.rs/exarch-core/latest/exarch_core/struct.ExtractionReport.html) | Extraction statistics, warnings, and skipped-entry counts |
| [`CreationReport`](https://docs.rs/exarch-core/latest/exarch_core/struct.CreationReport.html) | Creation statistics and results |
| [`ArchiveError`](https://docs.rs/exarch-core/latest/exarch_core/enum.ArchiveError.html) | Error types for all operations |
| [`ValidationReport`](https://docs.rs/exarch-core/latest/exarch_core/struct.ValidationReport.html) | Per-entry verification result (re-exported at crate root) |

### Error Handling

```rust
use exarch_core::{extract_archive, ArchiveError, SecurityConfig};

match extract_archive("archive.tar.gz", "/output", &SecurityConfig::default()) {
    Ok(report) => println!("Extracted {} files", report.files_extracted),
    Err(ArchiveError::PathTraversal { path, .. }) => {
        eprintln!("Blocked path traversal: {}", path.display());
    }
    Err(ArchiveError::QuotaExceeded { resource }) => {
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
> Minimum Supported Rust Version: **1.93.0**. MSRV increases are minor version bumps.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT License ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
