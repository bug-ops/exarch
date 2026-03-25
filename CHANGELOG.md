# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Fix two-hop symlink chain bypass in `SafeSymlink` and `SafeHardlink` validation
  (GHSA-83g3-92jg-28cx variant — #116). String-based `..` normalization did not
  account for on-disk symlinks written by earlier archive entries; a second symlink
  whose target traversed through a previously extracted symlink could redirect
  subsequent `..` steps outside the extraction root. The fix replaces string
  normalization with a component-by-component on-disk walk that calls
  `fs::canonicalize` whenever an on-disk symlink is encountered, verifying
  containment within the destination directory after every step.
  Requires `--allow-symlinks` AND `--allow-hardlinks` (both non-default) to
  trigger; hardlink escape is additionally blocked by OS restrictions on
  macOS for root-owned files.

### Added

- `exarch list` and `exarch verify` now accept `--max-files` and `--max-total-size`
  flags, mirroring `exarch extract`. Archives with more than 10 000 entries (e.g.
  ZIP64 archives) can now be listed or verified by passing `--max-files <N>` (#122).

- `list_archive` and `verify_archive` now support 7z archives, consistent with
  TAR and ZIP (#79). Entries are iterated via `sevenz-rust2::Archive::read`
  (no decompression); solid archives are safe to list. Quota limits, path
  traversal checks, and encryption rejection apply identically to other formats.

### Fixed

- Upgrade `tar` dependency to 0.4.45 to address RUSTSEC-2026-0067 (symlink
  `chmod` escape in `unpack_in`) and RUSTSEC-2026-0068 (PAX size header
  ignored when base header size is non-zero) (#112)
- `SafePath::validate` no longer returns a false positive `PathTraversal` error
  for archive root entries (`.` or `./`) produced by `tar -C /dir .` (#113)

## [0.2.8] - 2026-03-15

### Fixed

- When `--json` is specified and a command fails, the CLI now emits a structured JSON error object `{"operation":"...","status":"error","error":{"kind":"...","message":"..."}}` instead of plain text (#87)
- `SecurityConfig.allowed_extensions` and `SecurityConfig.banned_path_components` were missing from Python type stubs (`exarch.pyi`), causing pyright to report `reportAttributeAccessIssue` (#72)
- Use `entry.size()` instead of `entry.header().size()` for TAR quota enforcement to prevent PAX size bypass (#82)
- Honor `--force` flag in `extract` subcommand; without `--force`, fail with a clear error listing conflicting files (#77)
- Encrypted ZIP archives now correctly report a security violation instead of a misleading "corrupted or malformed" hint (#83)
- `list -l` showed raw Unix file-type bits (e.g. `100644`) for ZIP entries instead of normalized permission bits (e.g. `644`); `ArchiveEntry.mode` now strips `S_IFREG`/`S_IFDIR` bits from ZIP `external_attributes` (#80)
- World-writable files now have the write-other bit stripped by default instead of aborting extraction (consistent with setuid/setgid stripping) (#84)
- `list` quota error message reported `current` equal to the limit instead of the actual would-be count (e.g. `10000 > 10000` instead of `10001 > 10000`) for both TAR and ZIP archives (#91)
- `list` command reported a misleading "invalid archive" error for encrypted ZIP archives instead of a security violation; now correctly reports `SecurityViolation: archive is password-protected` (#96)
- Extracted file permissions now honor the sanitized mode, bypassing the process umask (#97)
- `list` command now rejects TAR entries with path traversal (`../`) and absolute paths, matching ZIP behavior (#104)

### Added

- `PartialExtraction` error variant wrapping the original error and a partial `ExtractionReport` snapshot when extraction fails after writing files to disk (#89)
- `ExtractionOptions` struct with `atomic: bool` field for controlling extraction behavior (#89)
- `extract_archive_full()` and `extract_archive_with_options()` public API functions accepting `ExtractionOptions` (#89)
- `--atomic` CLI flag: extracts into a temporary directory in the same parent, renames on success, and cleans up on failure to ensure the destination is never in a partial state (#89)
- JSON error output includes a `partial_report` field (`files_extracted`, `directories_created`, `symlinks_created`, `bytes_written`) when extraction is stopped mid-archive (#89)
- `--allow-world-writable` CLI flag and `allow_world_writable` `SecurityConfig` option to opt in to preserving world-writable permissions (#84)
- CVE regression tests for CVE-2024-12718 (Python tarfile filter bypass via `./..` paths), CVE-2024-12905 (tar-fs symlink chain escape), CVE-2025-48387 (tar-fs hardlink traversal outside destination), and Windows backslash path handling; archives with raw `..` paths are constructed at the byte level to reproduce real attacker-controlled inputs (#74)

### Changed

- `extract` now auto-creates the destination directory (including intermediate directories) if it does not exist, matching behavior of `tar`, `unzip`, and `7z` (#78)
- Removed stale `RUSTSEC-2025-0119` ignore entry from `deny.toml`; the advisory no longer matches any dependency in the tree (#76)
- Updated yanked transitive crates: `js-sys` 0.3.86 → 0.3.91, `wasm-bindgen` 0.2.109 → 0.2.114, `web-sys` 0.3.86 → 0.3.91 (#75)

## [0.2.7] - 2026-03-07

### Fixed

- PAX archive extraction fails with `SecurityViolation` for `XGlobalHeader` entries (#69)
- TAR `Continuous` and `GNUSparse` entry types incorrectly rejected as unsupported
- `list_archive()` inconsistently reported PAX metadata as regular files

### Changed

- Suppress `clippy::needless_bitwise_bool` for intentional constant-time null byte check in exarch-node

## [0.2.6] - 2026-03-04

### Fixed
- macOS ARM64 wheel no longer embeds a dynamic path to Homebrew's liblzma; xz2 is now statically linked via `xz2/static` feature (#66)

### Changed

- Bump `maturin` from 1.12.3 to 1.12.6
- Bump `biome` from 2.3.14 to 2.4.5

## [0.2.5] - 2026-02-20

### Changed
- Upgrade `zip` dependency from 7.x to 8.0 (breaking: removed deprecated `DateTime::to_time()`)
- Upgrade `tempfile` dependency from 3.24 to 3.25
- Replace deprecated `DateTime::to_time()` with `time::PrimitiveDateTime` conversion for ZIP timestamps
- Add `time` as direct dependency (previously transitive via `zip`)
- Bump `pyo3` from 0.28.1 to 0.28.2

## [0.2.4] - 2026-02-06

### Fixed
- ci-success gate now includes test-python and test-node jobs to prevent merging PRs with failing binding tests (#56)
- Python bindings now support Python 3.9-3.13 with proper CI testing and abi3 wheels (#55)

### Performance
- **Canonicalization optimization** — `ValidationContext` enables skipping redundant `canonicalize()` syscalls during path validation. Trusted-parent fast path (via `DirCache`) and symlink-free fast path eliminate ~17% CPU overhead in extraction hot path.

### Added
- `ValidationContext` type for carrying optimization state through extraction pipeline
- `SafePath::validate_with_context()` internal method for optimized path validation
- `DirCache::contains()` method for trusted-parent lookups

### Changed
- `EntryValidator::validate_entry()` accepts optional `DirCache` reference for trusted-parent optimization
- `DirCache` visibility elevated to `pub(crate)` for cross-module access

## [0.2.3] - 2026-02-06

### Added
- Python musllinux wheel builds for x86_64 and aarch64 (Alpine Linux support)

### Security
- Fix CVE-2026-25727: update `zip` 7.4.0 to resolve stack exhaustion DoS in transitive `time` dependency

### Changed
- Bump `pyo3` to 0.28, `clap` to latest minor, `zip` to 7.4.0
- Bump CI actions: `lewagon/wait-on-check-action` 1.5.0, `softprops/action-gh-release` v2, `codecov/codecov-action` v5
- Migrate biome config to v2 format

## [0.2.2] - 2026-01-03

### Added
- **Directory caching** — `DirCache` struct with `FxHashSet` reduces mkdir syscalls by ~95%
- **Atomic permission setting** — `create_file_with_mode()` sets Unix permissions during file creation (1 syscall instead of 2)
- Comprehensive benchmark suite comparing with Python tarfile/zipfile and Node.js tar/adm-zip
- `benchmark_config()` helper for stress test scenarios in benchmarks

### Performance
- TAR extraction throughput: 2,136 MB/s (4x target of 500 MB/s)
- ZIP extraction throughput: 1,444 MB/s (5x target of 300 MB/s)
- Python comparison: **1.10x** average speedup (max 1.43x)
- Node.js comparison: **1.75x** average speedup (max 4.69x)
- ~8% improvement from atomic permission setting vs separate chmod

### Changed
- Updated benchmark results in all READMEs with v0.2.2 measurements
- Added `rustc-hash` dependency for faster HashSet operations

## [0.2.1] - 2026-01-03

### Changed
- Remove unused `extraction/` module (stub implementations)
- Remove unused `add_file_to_zip_with_progress` function (superseded by buffer-reusing version)
- Clean up verbose comments across core library
- Remove outdated TODO comments

### Internal
- Code cleanup: -176 lines of dead code and verbose comments
- Improved code maintainability and readability

## [0.2.0] - 2026-01-02

### Added
- **7z format support** (extraction only) via `sevenz-rust2` crate
  - LZMA, LZMA2, and BCJ filter support
  - Solid archive extraction with configurable memory limits
  - Windows symlink detection via reparse point attributes
  - Directory junction detection and rejection
- Encrypted archive detection with actionable error messages
- Updated documentation to highlight both extraction and creation capabilities

### Security
- Reject encrypted 7z archives by default (no password support for security)
- Reject solid archives exceeding memory limits (default: 100 MB)
- Windows symlink/junction detection prevents escape attacks
- Unix symlinks in 7z archives extracted as regular files (safe default)

### Documentation
- Updated all package READMEs to show extraction and creation examples
- Added 7z format to supported formats tables across all packages
- Clarified 7z limitations (extraction only, no encrypted/solid with high memory)

## [0.1.2] - 2026-01-01

### Added
- CVE test fixtures for path traversal, symlink escape, and hardlink attacks
- FFI panic safety wrapper for Node.js `extractArchiveSync` function
- Test cleanup (afterEach) to Node.js integration tests
- Enabled CLI extraction integration tests

### Fixed
- ZIP creation root directory bug causing incorrect archive structure
- Python CVE regression tests now fully enabled (7 tests)

### Changed
- Test infrastructure improvements for better reliability

## [0.1.1] - 2026-01-01

### Changed
- Update dependency versions to latest minor releases
- Update Node.js minimum version to 18+
- Add Python 3.13 support

### Fixed
- Fix repository URLs in documentation (rabax → bug-ops)
- Update CLI README roadmap status

## [0.1.0] - 2026-01-01

### Added

#### Core Library (`exarch-core`)
- Memory-safe archive extraction with security-first design
- Support for TAR archives with gzip, bzip2, xz, and zstd compression
- Support for ZIP archives with deflate, deflate64, bzip2, and zstd
- Security validation layer with protection against:
  - Path traversal attacks (`../` and absolute paths)
  - Symlink escape attacks
  - Hardlink escape attacks
  - Zip bomb detection (configurable compression ratio limit)
  - Permission escalation (setuid/setgid stripping)
  - Resource exhaustion (file count and size quotas)
- `SecurityConfig` for customizable security policies
- `ExtractionReport` with detailed extraction statistics
- Archive creation with `CreationConfig` and progress callbacks
- Type-driven safety with `SafePath` validated path type
- Zero unsafe code in core library
- Streaming extraction without full archive buffering
- Performance optimizations: reusable buffers, buffered I/O, SmallVec

#### CLI (`exarch-cli`)
- `extract` command for secure archive extraction
- `create` command for archive creation
- `list` command to view archive contents
- `verify` command for integrity and security verification
- Human-readable and JSON output modes
- Progress bars with file-level detail
- Shell completions for bash, zsh, fish, PowerShell
- Configurable security options via command-line flags

#### Python Bindings (`exarch`)
- PyO3-based Python bindings
- `extract_archive()` function with optional `SecurityConfig`
- `create_archive()` function with optional `CreationConfig`
- `list_archive()` and `verify_archive()` functions
- Progress callback support for long-running operations
- Type stubs (`.pyi`) for IDE support
- Exception hierarchy matching Rust error types
- Support for `pathlib.Path` arguments

#### Node.js Bindings (`exarch-rs`)
- napi-rs based Node.js bindings
- Async and sync API variants (`extractArchive`, `extractArchiveSync`)
- `createArchive`, `listArchive`, `verifyArchive` functions
- TypeScript definitions included
- Builder-pattern configuration classes
- Non-blocking async operations via tokio

### Security
- Default-deny security model (symlinks, hardlinks blocked by default)
- CVE regression tests for known vulnerabilities:
  - CVE-2025-4517 (Python tarfile path traversal)
  - CVE-2024-12718 (Python tarfile filter bypass)
  - CVE-2024-12905 (tar-fs symlink escape)
  - CVE-2025-48387 (tar-fs hardlink traversal)
  - 42.zip (zip bomb attack)

### Performance
- TAR extraction: ~500 MB/s throughput
- ZIP extraction: ~300 MB/s throughput
- Path validation: <1 µs per entry
- 64KB reusable copy buffers
- LRU cache for symlink target resolution

[Unreleased]: https://github.com/bug-ops/exarch/compare/v0.2.8...HEAD
[0.2.8]: https://github.com/bug-ops/exarch/compare/v0.2.7...v0.2.8
[0.2.7]: https://github.com/bug-ops/exarch/compare/v0.2.6...v0.2.7
[0.2.6]: https://github.com/bug-ops/exarch/compare/v0.2.5...v0.2.6
[0.2.5]: https://github.com/bug-ops/exarch/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/bug-ops/exarch/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/bug-ops/exarch/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/bug-ops/exarch/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/bug-ops/exarch/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/bug-ops/exarch/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/bug-ops/exarch/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/bug-ops/exarch/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/bug-ops/exarch/releases/tag/v0.1.0
