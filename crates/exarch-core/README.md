# exarch-core

[![Crates.io](https://img.shields.io/crates/v/exarch-core)](https://crates.io/crates/exarch-core)
[![docs.rs](https://img.shields.io/docsrs/exarch-core)](https://docs.rs/exarch-core)
[![CI](https://img.shields.io/github/actions/workflow/status/bug-ops/exarch/ci.yml?branch=main)](https://github.com/bug-ops/exarch/actions)
[![MSRV](https://img.shields.io/badge/MSRV-1.89.0-blue)](https://github.com/bug-ops/exarch)
[![License](https://img.shields.io/crates/l/exarch-core)](LICENSE-MIT)

Memory-safe archive extraction library with security validation.

This crate is part of the [exarch](https://github.com/bug-ops/exarch) workspace.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
exarch-core = "0.1"
```

Or with cargo-add:

```bash
cargo add exarch-core
```

> [!IMPORTANT]
> Requires Rust 1.89.0 or later.

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

## Security Features

`exarch-core` provides defense-in-depth protection against common archive vulnerabilities:

| Protection | Description | Default |
|------------|-------------|---------|
| Path traversal | Blocks `../` and absolute paths | Enabled |
| Symlink attacks | Prevents symlinks escaping extraction directory | Enabled |
| Hardlink attacks | Validates hardlink targets | Enabled |
| Zip bombs | Detects high compression ratios | Enabled (100x limit) |
| Permission sanitization | Strips setuid/setgid bits | Enabled |
| Size limits | Configurable file and total size limits | 50MB / 10GB |

> [!CAUTION]
> Disabling security features is strongly discouraged. Only do so if you fully understand the risks and trust the archive source.

### Custom Security Configuration

```rust
use exarch_core::SecurityConfig;

let config = SecurityConfig {
    max_file_size: 100 * 1024 * 1024,   // 100 MB
    max_total_size: 1024 * 1024 * 1024, // 1 GB
    max_compression_ratio: 50.0,         // 50x compression limit
    allow_symlinks: false,               // Block symlinks
    allow_hardlinks: false,              // Block hardlinks
    ..Default::default()
};
```

## Supported Formats

- TAR (`.tar`)
- TAR+GZIP (`.tar.gz`, `.tgz`)
- TAR+BZIP2 (`.tar.bz2`)
- TAR+XZ (`.tar.xz`, `.txz`)
- ZIP (`.zip`)

## API Overview

### Main Types

| Type | Description |
|------|-------------|
| `extract_archive` | High-level extraction function |
| `Archive` | Archive handle with typestate pattern |
| `SecurityConfig` | Security configuration options |
| `ExtractionReport` | Extraction statistics and results |
| `ExtractionError` | Error types for extraction failures |

See [API documentation](https://docs.rs/exarch-core) for complete reference.

## Related Crates

- [`exarch-python`](../exarch-python) - Python bindings via PyO3
- [`exarch-node`](../exarch-node) - Node.js bindings via napi-rs

## MSRV Policy

> [!NOTE]
> Minimum Supported Rust Version: **1.89.0**. MSRV increases are minor version bumps.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](../../LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
