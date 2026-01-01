# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/bug-ops/exarch/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/bug-ops/exarch/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/bug-ops/exarch/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/bug-ops/exarch/releases/tag/v0.1.0
