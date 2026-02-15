# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Upgrade `zip` dependency from 7.x to 8.0 (breaking: removed deprecated `DateTime::to_time()`)
- Upgrade `tempfile` dependency from 3.24 to 3.25
- Replace deprecated `DateTime::to_time()` with `time::PrimitiveDateTime` conversion for ZIP timestamps
- Add `time` as direct dependency (previously transitive via `zip`)

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

[Unreleased]: https://github.com/bug-ops/exarch/compare/v0.2.3...HEAD
[0.2.3]: https://github.com/bug-ops/exarch/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/bug-ops/exarch/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/bug-ops/exarch/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/bug-ops/exarch/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/bug-ops/exarch/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/bug-ops/exarch/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/bug-ops/exarch/releases/tag/v0.1.0
