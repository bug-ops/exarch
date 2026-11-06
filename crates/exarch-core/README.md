# exarch-core

[![Crates.io](https://img.shields.io/crates/v/exarch-core)](https://crates.io/crates/exarch-core)
[![docs.rs](https://img.shields.io/docsrs/exarch-core)](https://docs.rs/exarch-core)
[![CI](https://img.shields.io/github/actions/workflow/status/bug-ops/exarch/ci.yml?branch=main)](https://github.com/bug-ops/exarch/actions)
[![MSRV](https://img.shields.io/badge/MSRV-1.99.1-blue)](https://github.com/bug-ops/exarch)
[![License](https://img.shields.io/crates/l/exarch-core)](../../LICENSE-MIT)

Memory-safe archive extraction and creation library with security validation.

This crate is part of the [exarch](https://github.com/bug-ops/exarch) workspace.

## Installation

```toml
[dependencies]
exarch-core = "0.9"
```

> [!IMPORTANT]
> Requires Rust 1.99.1 or later (Edition 2024).

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
> Since v0.6.1, `ArchiveError`, `QuotaResource`, `ArchiveType`, `CompressionCodec`, `IssueCategory`, and `EntryType` are `#[non_exhaustive]` too — an exhaustive `match` on any of them (including the `Error Handling` example below) needs a wildcard `_` arm.

```rust
use exarch_core::{non_zero, ratio_limit, Extension, ExtensionFilter, SecurityConfig};

let config = SecurityConfig::default()
    .with_max_file_size(non_zero!(100 * 1024 * 1024))    // 100 MB per file
    .with_max_total_size(non_zero!(1024 * 1024 * 1024))  // 1 GB total
    .with_max_file_count(non_zero!(10_000))              // Max 10k files
    .with_max_compression_ratio(ratio_limit!(50.0)) // 50x compression limit
    .with_allowed_extensions(ExtensionFilter::only(vec![
        Extension::try_from(".tar")?,
        Extension::try_from(".gz")?,
    ])?); // optional allowlist; an empty list is refused, `ExtensionFilter::Any` is the default
```

Available builders on `SecurityConfig`: `with_max_file_size`, `with_max_total_size`, `with_max_compression_ratio`, `with_max_file_count`, `with_max_path_depth`, `with_allowed`, `with_allow_symlinks`, `with_allow_hardlinks`, `with_allow_absolute_paths`, `with_allow_world_writable`, `with_preserve_permissions`, `with_allowed_extensions`, `with_banned_path_components`, `with_allow_solid_archives`, `with_solid_archives`, `with_solid_limits`, `with_max_tar_metadata_bytes`, `with_max_decoder_memory`, `with_compressed_member_allowance`, `with_allow_windows_reserved_names`, `with_zip_consistency`, `with_parallel_decode`. On `ExtractionOptions`: `with_staging` (`Staging::{InPlace, Atomic, AtomicReplace}`), `with_existing_files` (`ExistingFiles::{Skip, Overwrite, Refuse}`), `with_decode_reuse`.

### Request Values

Optional inputs (options, progress) are setters on a request value instead of more functions:

```rust
use exarch_core::{ExtractRequest, ExtractionOptions, NoopProgress, SecurityConfig, Staging};

let config = SecurityConfig::default();
let mut progress = NoopProgress;
let report = ExtractRequest::new(&config)
    .with_options(ExtractionOptions::default().with_staging(Staging::Atomic))
    .with_progress(&mut progress)
    .extract("archive.tar.gz", "/output/path")?;
```

`ListRequest`, `VerifyRequest`, `SinkExtractRequest` and `CreateRequest` follow the same shape.

## Security Features

exarch-core provides defense-in-depth protection against common archive vulnerabilities:

| Protection | Description | Default |
|------------|-------------|---------|
| Path traversal | Blocks `../` and absolute paths | Enabled |
| Symlink attacks | Prevents symlinks escaping extraction directory | Blocked |
| Hardlink attacks | Validates hardlink targets within extraction directory | Blocked |
| Zip bombs | Detects high compression ratios | Enabled (100x limit) |
| TAR metadata bombs | Bounds GNU long-name/long-link and PAX header record reads | Enabled (4 MiB, 16 MiB for `permissive()`) |
| Permission sanitization | Strips setuid/setgid bits | Enabled |
| Size limits | Configurable file and total size limits | 50 MB / 500 MB |
| Decoder memory | Bounds the xz dictionary and the zstd window (TAR and ZIP) by `max_decoder_memory` | Enabled (256 MiB) |
| Compressed members | Bounds gzip members and bzip2 streams by `compressed_member_allowance` plus one per 16 KiB of output | Enabled (10,000) |

> [!NOTE]
> The zstd window bound relies on the `zstd` crate being built without its `legacy` feature (the workspace sets `default-features = false`): libzstd decodes pre-v0.8 frames with no window check. The ZIP frame walk refuses such frames as a second line of defense, but a downstream build should keep the feature off.

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

### Output Files

`create_archive` replaces an existing output atomically once the archive is complete; a failed creation leaves the output as it was. Use `CreateRequest` with an `OutputFile` to refuse an existing file or to state the format:

```rust
use exarch_core::{CreateRequest, CreationConfig, ExcludePattern, OutputFile};
use exarch_core::CompressionLevel;

let config = CreationConfig::default()
    .with_compression_level(CompressionLevel::try_from(9u8)?)
    .with_exclude_patterns(vec![ExcludePattern::try_from("*.log")?, ExcludePattern::try_from("target/")?]);
let report = CreateRequest::new(&config).create(
    &OutputFile::create_new("project.tar.gz"),
    &["src/", "Cargo.toml", "README.md"],
)?;
```

The output is staged in a temporary file in its directory (which must be writable), is never archived into itself, and must be absent, a regular file or a symlink to one.

### CreationConfig Options

| Option | Default | Description |
|--------|---------|-------------|
| `follow_symlinks` | `false` | Follow symbolic links |
| `include_hidden` | `false` | Include hidden files (.*) |
| `max_file_size` | unbounded | Skip files above this size (`Limit<NonZeroU64>`) |
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
| `.zip` | ZIP | Deflate, Deflate64, Bzip2, Zstd | ✅ | ✅ | ✅ | ✅ |
| `.jar`, `.war`, `.ear`, `.nar`, `.nbm`, `.apk`, `.aab`, `.ipa`, `.appx`, `.msix`, `.whl`, `.vsix`, `.xpi`, `.epub` | ZIP-family | Deflate, Deflate64, Bzip2, Zstd | ✅ | — | ✅ | ✅ |
| `.7z` | 7z | LZMA/LZMA2 | ✅ | — | ✅ | ✅ |

> [!NOTE]
> ZIP-family formats share the ZIP container but add extra structure — signing (`.apk`/`.aab`/`.ipa`/`.appx`/`.msix`), checksum manifests (`.whl`), ordering rules (`.epub`), or descriptor files (`.war`/`.ear`/`.vsix`/`.nbm`) — which exarch-core doesn't produce. Creation is rejected to avoid silently emitting a bare ZIP with a misleading extension; callers who want that can state `CreatableFormat::Zip` with `OutputFile::with_format`.

> [!NOTE]
> 7z creation is not yet supported. Solid and encrypted 7z archives are rejected for security reasons. A 7z archive holding a Windows reparse point is refused as a whole; a Unix `S_IFLNK` symlink is read and validated through the symlink policy, so it is created only with symlinks allowed, and a 7z FIFO, socket or device node is refused.

> [!NOTE]
> `detect_format` falls back to magic-byte inspection when the file extension is absent, unrecognised, or contradicts the file content. When magic bytes and extension disagree, magic bytes take precedence. Archive creation always uses extension-only detection.

## API Overview

### Main Types

| Type | Description |
|------|-------------|
| [`extract_archive`](https://docs.rs/exarch-core/latest/exarch_core/fn.extract_archive.html) | High-level extraction function |
| [`create_archive`](https://docs.rs/exarch-core/latest/exarch_core/fn.create_archive.html) | High-level archive creation function |
| [`list_archive`](https://docs.rs/exarch-core/latest/exarch_core/fn.list_archive.html) | List archive contents |
| [`verify_archive`](https://docs.rs/exarch-core/latest/exarch_core/fn.verify_archive.html) | Verify archive security without extracting |
| [`ExtractRequest`](https://docs.rs/exarch-core/latest/exarch_core/struct.ExtractRequest.html) | Extraction with options and progress |
| [`ListRequest`](https://docs.rs/exarch-core/latest/exarch_core/struct.ListRequest.html) | Listing with `ListOptions` and progress, from a path or a reader; `for_extraction` keeps what extraction can reuse |
| [`VerifyRequest`](https://docs.rs/exarch-core/latest/exarch_core/struct.VerifyRequest.html) | Verification with `VerificationOptions` (e.g. decoding the payload to check integrity) and progress |
| [`SinkExtractRequest`](https://docs.rs/exarch-core/latest/exarch_core/struct.SinkExtractRequest.html) | Extraction into an `EntrySink` |
| [`CreateRequest`](https://docs.rs/exarch-core/latest/exarch_core/struct.CreateRequest.html) | Creation into an `OutputFile`, a writer or memory |
| [`OutputFile`](https://docs.rs/exarch-core/latest/exarch_core/struct.OutputFile.html) | The archive file to create: path, replace policy, format |
| [`SecurityConfig`](https://docs.rs/exarch-core/latest/exarch_core/struct.SecurityConfig.html) | Security configuration for extraction |
| [`CreationConfig`](https://docs.rs/exarch-core/latest/exarch_core/struct.CreationConfig.html) | Configuration for archive creation |
| [`ExtractionReport`](https://docs.rs/exarch-core/latest/exarch_core/struct.ExtractionReport.html) | Extraction statistics, warnings, and skipped-entry counts |
| [`CreationReport`](https://docs.rs/exarch-core/latest/exarch_core/struct.CreationReport.html) | Creation statistics and results |
| [`ArchiveError`](https://docs.rs/exarch-core/latest/exarch_core/enum.ArchiveError.html) | Error types for all operations |
| [`VerificationIssue`](https://docs.rs/exarch-core/latest/exarch_core/struct.VerificationIssue.html) | One typed `verify` finding with its code, sub-code and message |

### Readers, Sinks and Writers

Archives that are not files on disk go through the same validation pipeline. `ArchiveReader` wraps a TAR stream or a seekable ZIP/7z source, and `ArchiveReader::detect` / `detect_stream` pick the format from the leading bytes. `ListRequest::list_reader` and `VerifyRequest::verify_reader` list and verify such a source without a temporary directory. `SinkExtractRequest` takes a `SinkOptions` and delivers validated entries to an `EntrySink` instead of a directory; `MemorySink` keeps them in memory under a `MemoryLimit` that counts payload, path bytes and a fixed per-entry overhead, and a full sink fails with `QuotaExceeded` (`SinkCapacity`), and an error that wrote nothing reports `PartialWrites::Discarded`. `PathModel::Portable` makes a sink validate against the strictest rules of every platform on every host. 7z archives are accepted by sinks too.

In the other direction `ArchiveWriter` with `CreateRequest::write` builds a TAR (any codec) or ZIP into any `Write` (and `Seek` for ZIP) instead of a file; `ArchiveWriter::of_type` takes a `CreatableFormat`, so a format that cannot be created is unrepresentable. Every request reports per-entry progress.

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
> Minimum Supported Rust Version: **1.99.1**. MSRV increases are minor version bumps.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT License ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
