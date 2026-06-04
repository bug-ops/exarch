---
aliases:
  - exarch System Spec
  - exarch-core Spec
tags:
  - sdd
  - spec
  - archive
  - security
  - rust
created: 2026-05-20
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
---

# Feature: exarch System

> [!info] Metadata
> **Version**: 0.4.0
> **MSRV**: Rust 1.93.0
> **License**: MIT OR Apache-2.0
> **Crates**: exarch-core, exarch-cli, exarch-python, exarch-node

## 1. Overview

### Problem Statement

Archive extraction is a common attack surface: path traversal, zip bombs,
symlink escapes, and hardlink attacks have affected almost every major
archive library. Existing Rust archive crates expose raw decompression
APIs without integrated security validation, requiring each consumer to
re-implement the same set of mitigations — inconsistently.

exarch provides a single, security-first archive library with deny-by-default
policies, a typed validation pipeline, and bindings for CLI, Python, and
Node.js so that the security burden is paid once and shared across ecosystems.

### Goal

Provide a memory-safe, security-first archive library (Rust API + CLI +
Python + Node.js bindings) that makes it safe to extract untrusted archives
by default without requiring callers to understand the attack surface.

### Out of Scope

- RAR archive support
- Archive encryption or signing
- Streaming/incremental extraction over network (local files only)
- 7z archive creation (extraction only)
- ZIP-family aliases (`.apk`, `.whl`, `.jar`, etc.) creation without explicit format override
- GUI or web interface

## 2. User Stories

### US-001: Secure Extraction (Rust API)

AS A Rust developer integrating archive extraction into a server or CLI tool
I WANT to call `extract_archive(path, output_dir, &config)` and receive an error on any security violation
SO THAT I do not have to implement path traversal checks, zip bomb detection, or symlink validation myself

**Acceptance criteria:**
```
GIVEN a valid archive and a SecurityConfig with default settings
WHEN I call extract_archive()
THEN all entries are written to output_dir, no entry escapes output_dir,
     and the returned ExtractionReport contains file/byte counts
```

```
GIVEN an archive containing a path traversal entry (e.g. "../etc/passwd")
WHEN I call extract_archive()
THEN extraction fails with ExtractionError::PathTraversal before any file is written
```

### US-002: Archive Creation (Rust API)

AS A Rust developer building a backup or packaging tool
I WANT to call `create_archive(output_path, &sources, &config)` to produce TAR/ZIP archives
SO THAT I can create archives with sane compression defaults and file filtering without manual format handling

**Acceptance criteria:**
```
GIVEN a list of source paths and an output path with a recognized extension
WHEN I call create_archive()
THEN an archive is produced containing all source files, and CreationReport.files_added reflects the count
```

```
GIVEN a 7z output path
WHEN I call create_archive()
THEN the call fails with ExtractionError::InvalidConfiguration
```

### US-003: Archive Inspection

AS A security engineer or operator
I WANT to list and verify archive contents without extracting to disk
SO THAT I can pre-check untrusted archives before deployment

**Acceptance criteria:**
```
GIVEN an archive with known contents
WHEN I call list_archive()
THEN an ArchiveManifest is returned with correct entry paths, sizes, and types without writing any files to disk
```

```
GIVEN an archive containing a zip bomb entry (compression ratio > 100×)
WHEN I call verify_archive()
THEN VerificationReport.issues contains a ZipBomb issue with Critical severity and status is Fail
```

### US-004: CLI Extraction

AS A system administrator or script author
I WANT to run `exarch extract archive.tar.gz /output` from the shell
SO THAT I can extract archives safely without installing Python or Node.js

**Acceptance criteria:**
```
GIVEN a valid archive and an output directory
WHEN I run `exarch extract archive.tar.gz /output`
THEN files are extracted, a progress bar is shown, and exit code is 0
```

```
GIVEN the --json flag
WHEN I run `exarch extract archive.tar.gz /output --json`
THEN stdout contains a JSON object with extraction statistics and no progress bar
```

### US-005: Python Bindings

AS A Python developer building a data pipeline or security tool
I WANT to call `exarch.extract_archive(path, output)` from Python
SO THAT I benefit from the same security guarantees without reimplementing them in Python

**Acceptance criteria:**
```
GIVEN a valid archive path and output directory
WHEN I call extract_archive(archive_path, output_dir) from Python
THEN the extraction runs with GIL released, files are extracted, and an ExtractionReport object is returned
```

```
GIVEN a path containing null bytes
WHEN I call any exarch function with that path
THEN a ValueError is raised immediately without calling into Rust core
```

### US-006: Node.js Bindings

AS A Node.js developer building a CI/CD tool or file processing service
I WANT async Promise-based archive operations
SO THAT I can extract archives without blocking the Node.js event loop

**Acceptance criteria:**
```
GIVEN a valid archive path and output directory
WHEN I await extractArchive(archivePath, outputDir)
THEN extraction runs on the libuv thread pool, files are extracted, and an ExtractionReport is resolved
```

## 3. Functional Requirements

### 3.1 Security Pipeline

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN any archive entry path is validated, THE SYSTEM SHALL reject paths containing `../`, absolute paths, null bytes, or components matching `banned_path_components` (case-insensitive) | must |
| FR-002 | WHEN a file entry's uncompressed size exceeds `max_file_size`, THE SYSTEM SHALL reject it with `QuotaExceeded` | must |
| FR-003 | WHEN the cumulative uncompressed size across all file entries exceeds `max_total_size`, THE SYSTEM SHALL reject further entries with `QuotaExceeded` | must |
| FR-004 | WHEN a file entry has a known compressed size and the ratio (uncompressed / compressed) exceeds `max_compression_ratio`, THE SYSTEM SHALL reject it with `ZipBomb` | must |
| FR-005 | WHEN a symlink entry is encountered and `allowed.symlinks` is false, THE SYSTEM SHALL skip the entry (default deny) | must |
| FR-006 | WHEN a symlink entry is encountered and `allowed.symlinks` is true, THE SYSTEM SHALL validate that the resolved symlink target does not escape `output_dir` | must |
| FR-007 | WHEN a hardlink entry is encountered and `allowed.hardlinks` is false, THE SYSTEM SHALL skip the entry | must |
| FR-008 | WHEN a hardlink entry is encountered and `allowed.hardlinks` is true, THE SYSTEM SHALL validate that the hardlink target path is within `output_dir` and has been previously seen | must |
| FR-009 | WHEN extracting files on Unix, THE SYSTEM SHALL strip setuid (0o4000) and setgid (0o2000) bits from all file permissions | must |
| FR-010 | WHEN a 7z archive is detected as solid and `allow_solid_archives` is false, THE SYSTEM SHALL reject extraction | must |
| FR-011 | WHEN a 7z solid archive extraction is permitted, THE SYSTEM SHALL reject it if the total uncompressed size exceeds `max_solid_block_memory` | must |
| FR-012 | WHEN the path depth of an entry exceeds `max_path_depth`, THE SYSTEM SHALL reject the entry | must |
| FR-013 | WHEN `allowed_extensions` is non-empty and an entry's extension is not in the list, THE SYSTEM SHALL skip the entry and record it in `ExtractionReport::files_skipped` with a warning | must |

### 3.2 Format Support

| ID | Requirement | Priority |
|----|------------|----------|
| FR-020 | WHEN an archive path has extension `.tar`, `.tgz`, `.tar.gz`, `.tar.bz2`, `.tbz`, `.tbz2`, `.tar.xz`, `.txz`, `.tar.zst`, `.tzst`, THE SYSTEM SHALL extract it as a TAR archive with the appropriate decompressor | must |
| FR-021 | WHEN an archive path has extension `.zip` or any ZIP-family alias (`.jar`, `.war`, `.apk`, `.whl`, etc.), THE SYSTEM SHALL extract it as a ZIP archive | must |
| FR-022 | WHEN an archive path has extension `.7z`, THE SYSTEM SHALL extract it using the 7z handler (extraction only) | must |
| FR-023 | WHEN format detection is ambiguous or the extension is unrecognized, THE SYSTEM SHALL return `ExtractionError::UnknownFormat { path }` | must |
| FR-024 | WHEN creating archives, THE SYSTEM SHALL support TAR (all compression variants) and ZIP; 7z creation SHALL return `InvalidConfiguration` | must |
| FR-025 | WHEN creating archives for ZIP-family aliases without an explicit `CreationConfig::format` override, THE SYSTEM SHALL return an error explaining that the format requires extra structure | should |

### 3.3 Configuration API

| ID | Requirement | Priority |
|----|------------|----------|
| FR-030 | `SecurityConfig` SHALL use a fluent builder API (15 `with_*` methods returning `Self`) and implement `Default` with secure deny-by-default settings | must |
| FR-031 | `SecurityConfig` SHALL be annotated `#[non_exhaustive]`; external crates must use `Default::default()` or builder methods — struct literal construction is rejected at compile time | must |
| FR-032 | `SecurityConfig::validate()` SHALL return an error if any limit field is zero (including `max_file_count` and `max_solid_block_memory`), `max_compression_ratio` is not a positive finite number, or any field contains an invalid value | must |
| FR-033 | `CreationConfig` SHALL support: `follow_symlinks`, `include_hidden`, `max_file_size`, `exclude_patterns`, `strip_prefix`, `compression_level` (1-9), `preserve_permissions`, `format` override | must |
| FR-034 | `ExtractionOptions` SHALL be annotated `#[non_exhaustive]` and SHALL support: `atomic` (temp-dir + rename), `skip_duplicates` (default true); fluent builders `with_atomic` and `with_skip_duplicates` are provided | must |
| FR-035 | WHEN `ExtractionOptions::atomic` is true, THE SYSTEM SHALL extract to a temp dir in the same parent as the output directory and atomically rename on success; on failure it SHALL delete the temp dir | must |
| FR-036 | `AllowedFeatures` SHALL be annotated `#[non_exhaustive]` so new flags do not break downstream struct literals | must |

### 3.4 Progress Reporting

| ID | Requirement | Priority |
|----|------------|----------|
| FR-040 | THE SYSTEM SHALL expose a `ProgressCallback` trait with `on_entry_start`, `on_bytes_written`, `on_entry_complete`, `on_complete` | must |
| FR-041 | THE SYSTEM SHALL provide a `NoopProgress` implementation that satisfies the trait without overhead | must |
| FR-042 | `on_complete` SHALL NOT be called if extraction fails or is partial | must |

### 3.5 Inspection

| ID | Requirement | Priority |
|----|------------|----------|
| FR-050 | `list_archive()` SHALL return an `ArchiveManifest` with total entry count, total size, and per-entry metadata (path, size, type, compressed size, modified time, permissions) without writing any files to disk | must |
| FR-051 | `verify_archive()` SHALL return a `VerificationReport` with `status` (Pass/Fail/Warning), `issues` list (each with severity, category, message), and `total_entries` count | must |
| FR-052 | `VerificationReport` issues SHALL distinguish severity levels: Critical, High, Medium, Low | must |

### 3.6 CLI Interface

| ID | Requirement | Priority |
|----|------------|----------|
| FR-060 | THE CLI SHALL provide subcommands: `extract`, `create`, `list`, `verify`, `completion` | must |
| FR-061 | THE CLI SHALL support global flags: `--verbose`, `--quiet`, `--json` | must |
| FR-062 | WHEN `--json` is set, THE CLI SHALL output machine-readable JSON to stdout; human-readable text output SHALL go to stderr | must |
| FR-063 | `extract` SHALL support: `--max-files`, `--max-total-size` (with K/M/G/T suffixes), `--max-file-size`, `--max-compression-ratio`, `--allow-symlinks`, `--allow-hardlinks`, `--allow-solid-archives`, `--allow-world-writable`, `--preserve-permissions`, `--force`, `--atomic` | must |
| FR-064 | `create` SHALL support: `--compression-level` (1-9), `--follow-symlinks`, `--include-hidden`, `--exclude` (repeatable glob), `--strip-prefix`, `--force` | must |
| FR-065 | `list` and `verify` SHALL support: `--long`, `--human-readable`, `--max-files`, `--max-total-size`, `--allow-solid-archives` | must |
| FR-066 | `completion <SHELL>` SHALL generate shell completion scripts for bash, zsh, fish, powershell, and elvish; output goes to stdout | must |
| FR-067 | WHEN `--verbose` is set, THE CLI SHALL print one line per extracted entry to stderr including entry type, size, and path; `--quiet` takes precedence over `--verbose` | must |
| FR-068 | WHEN `--allow-symlinks` is already active and a symlink escape is blocked, THE CLI SHALL NOT emit the `--allow-symlinks` hint (genuine security violation, not a configuration gap) | must |

### 3.7 Python Bindings

| ID | Requirement | Priority |
|----|------------|----------|
| FR-070 | THE SYSTEM SHALL expose Python functions: `extract_archive`, `create_archive`, `create_archive_with_progress`, `list_archive`, `verify_archive` | must |
| FR-071 | ALL Python functions SHALL accept `str` or `pathlib.Path` for path arguments | must |
| FR-072 | WHEN paths contain null bytes or exceed 4096 bytes, THE SYSTEM SHALL raise `ValueError` at the Python boundary before calling into Rust | must |
| FR-073 | WHEN no Python progress callback is provided, THE SYSTEM SHALL release the GIL during extraction/creation | must |
| FR-074 | WHEN a Python progress callback is provided, THE SYSTEM SHALL NOT release the GIL (callback requires GIL to call Python) | must |
| FR-075 | Rust `ExtractionError` variants SHALL map to specific Python exception types registered on the module | must |

### 3.8 Node.js Bindings

| ID | Requirement | Priority |
|----|------------|----------|
| FR-080 | THE SYSTEM SHALL expose async Node.js functions that return Promises: `extractArchive`, `createArchive`, `listArchive`, `verifyArchive` | must |
| FR-081 | ALL async operations SHALL run on the libuv thread pool (not the main event loop thread) | must |
| FR-082 | WHEN paths contain null bytes or exceed 4096 bytes, THE SYSTEM SHALL reject with a JavaScript Error before spawning a thread | must |
| FR-083 | Rust `ExtractionError` variants SHALL map to named JavaScript Error types | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Security | Default config limits: 50 MB per file, 500 MB total, 100× compression ratio, 10,000 files, path depth 32 |
| NFR-002 | Security | All security checks run before any bytes are written to disk for each entry |
| NFR-003 | Security | Solid 7z archives are rejected by default; must be explicitly enabled |
| NFR-004 | Security | Banned path components checked case-insensitively on every entry |
| NFR-005 | Performance | Extraction throughput regression > 10% vs baseline triggers P1 review |
| NFR-006 | Performance | `BufReader` used for all TAR file handles; `CopyBuffer` for all byte copying |
| NFR-007 | Reliability | Atomic extraction mode ensures all-or-nothing semantics (no partial output on failure) |
| NFR-008 | Reliability | Progress `on_complete` not called on failure — callers can rely on this for cleanup signaling |
| NFR-009 | Safety | `deny(unsafe_code)` workspace-wide; Python binding contains one justified `unsafe impl Send` for `PyProgressAdapter` |
| NFR-010 | Compatibility | MSRV 1.93.0; no const generics or APIs introduced after 1.93 |
| NFR-011 | Portability | Path separator handling must be tested on Windows (backslash vs forward slash edge cases in path validation) |
| NFR-012 | Observability | CLI progress bar uses `indicatif` in human mode; suppressed in `--json` and `--quiet` modes |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `SecurityConfig` | Security policy for extraction operations | `max_file_size`, `max_total_size`, `max_compression_ratio`, `max_file_count`, `max_path_depth`, `allowed` (features), `banned_path_components`, `allowed_extensions`, `allow_solid_archives`, `max_solid_block_memory` |
| `AllowedFeatures` | Feature flags for deny-by-default policy | `symlinks`, `hardlinks`, `absolute_paths`, `world_writable` |
| `CreationConfig` | Configuration for archive creation | `follow_symlinks`, `include_hidden`, `max_file_size`, `exclude_patterns`, `strip_prefix`, `compression_level`, `preserve_permissions`, `format` |
| `ExtractionOptions` | Operational options for extraction (non-security) | `atomic`, `skip_duplicates` |
| `SafePath` | Newtype for a validated archive entry path | Wraps `PathBuf`; can only be constructed after traversal/depth/component checks pass |
| `ValidatedEntry` | Validated archive entry ready for extraction | `safe_path: SafePath`, `entry_type: ValidatedEntryType`, `mode: Option<u32>` |
| `ValidatedEntryType` | Enum of validated entry types | `File`, `Directory`, `Symlink(SafeSymlink)`, `Hardlink { target: SafePath }` |
| `EntryValidator` | Stateful validator orchestrating all security checks per entry | Holds `QuotaTracker`, `HardlinkTracker`, `symlink_seen` flag |
| `ExtractionReport` | Result of an extraction operation | `files_extracted`, `directories_created`, `symlinks_created`, `bytes_written`, `duration`, `files_skipped`, `warnings` |
| `CreationReport` | Result of an archive creation | `files_added`, `bytes_written`, `duration` |
| `ArchiveManifest` | Listing of archive contents | `total_entries`, `total_size`, `format`, `entries: Vec<ArchiveEntry>` |
| `ArchiveEntry` | Metadata for a single archive entry | `path`, `size`, `entry_type`, `compressed_size`, `modified`, `permissions` |
| `VerificationReport` | Security and integrity check results | `status: VerificationStatus`, `issues: Vec<VerificationIssue>`, `total_entries` |
| `VerificationIssue` | A single identified security or integrity issue | `severity: IssueSeverity`, `category: IssueCategory`, `message`, `path` |
| `ArchiveType` | Enum of supported archive formats | `Tar`, `TarGz`, `TarBz2`, `TarXz`, `TarZst`, `Zip`, `SevenZ` |
| `ArchiveFormat` | Trait for read-side format dispatch | Methods: `extract`, `list`, `verify`, `format_name` |
| `FormatCreator` | Trait for write-side format dispatch | Methods: `create`, `format_name`; implemented by `TarCreator`, `TarGzCreator`, `TarBz2Creator`, `TarXzCreator`, `TarZstCreator`, `ZipCreator` via `creator_for_format()` helper |
| `ExtractionContext` | Private TAR helper struct grouping six shared extraction parameters | `validator`, `dest`, `report`, `copy_buffer`, `dir_cache`, `skip_duplicates` |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Archive path does not exist | `ExtractionError::Io` returned immediately |
| Extension unrecognized or bare `.gz` without `.tar` stem | `ExtractionError::UnknownFormat { path }` |
| ZIP-family alias (`.apk`, `.whl`) extraction | Proceeds as ZIP |
| ZIP-family alias creation without format override | `ExtractionError::InvalidArchive` with explanation naming the alias and referencing `CreationConfig::format` override |
| 7z creation | `ExtractionError::InvalidConfiguration` |
| Duplicate entry paths in archive | Logged as warning in `ExtractionReport.warnings` when `skip_duplicates` is true; error when false |
| Atomic extraction to existing non-empty directory | `ExtractionError::OutputExists` on rename failure; temp dir cleaned up |
| Path traversal `../` or absolute path | `ExtractionError::PathTraversal` |
| File exceeds `max_file_size` | `ExtractionError::QuotaExceeded { resource: FileSizeBytes }` |
| Total size exceeds `max_total_size` | `ExtractionError::QuotaExceeded { resource: TotalSizeBytes }` |
| File count exceeds `max_file_count` | `ExtractionError::QuotaExceeded { resource: FileCount }` |
| Compression ratio > `max_compression_ratio` | `ExtractionError::ZipBomb` |
| Symlink with `allowed.symlinks = false` | Entry skipped (not an error) |
| Symlink pointing outside output_dir | `ExtractionError::SymlinkEscape` |
| Hardlink with `allowed.hardlinks = false` | Entry skipped |
| Hardlink to a path not previously seen in this archive | `ExtractionError::HardlinkEscape` |
| setuid/setgid bits on Unix | Stripped silently; `mode` in `ValidatedEntry` reflects sanitized value |
| Solid 7z archive with `allow_solid_archives = false` | `ExtractionError::InvalidArchive` or format-specific rejection |
| Path depth > `max_path_depth` | `ExtractionError::PathTraversal` (depth exceeded) |
| Banned component (`.git`) in path | `ExtractionError::PathTraversal` (banned component) |
| `SecurityConfig` with zero limit | `SecurityConfig::validate()` returns `InvalidConfiguration` before extraction begins |
| Python: null byte in path | `ValueError` raised at Python boundary |
| Python: path exceeds 4096 bytes | `ValueError` raised at Python boundary |
| Node.js: null byte in path | JavaScript `Error` raised synchronously before Promise is created |
| `verify_archive` on corrupt archive | Structural issues reported in `VerificationReport.issues`; method returns `Ok` if archive can be read at all |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Path traversal attempts blocked | 100% of known CVE-pattern archives rejected |
| SC-002 | Zip bomb detection | Archives with ratio > 100× rejected before first byte written |
| SC-003 | Symlink escape prevention | Symlinks resolving outside `output_dir` always rejected |
| SC-004 | Extraction throughput regression | < 10% regression vs baseline on `cargo bench` |
| SC-005 | Test coverage (new code) | All security checks have property-based or integration tests |
| SC-006 | Doc-test pass rate | 100% — `cargo test --doc --workspace --all-features` must pass |
| SC-007 | Clippy clean | Zero warnings with `--all-features --all-targets -D warnings` |
| SC-008 | MSRV compliance | `cargo check -p exarch-core --all-features` passes on Rust 1.93.0 |
| SC-009 | Atomic extraction correctness | No partial output on extraction failure; temp dir cleaned up |

## 8. Agent Boundaries

### Always (without asking)
- Run `cargo +nightly fmt --all` after any code change
- Run `cargo clippy --workspace --all-targets --all-features -- -D warnings` after code changes
- Add `///` doc comments to every new `pub` item
- Include `# Examples` in doc comments for non-trivial public APIs
- Use `?` for error propagation — never `unwrap()` or `expect()` in non-test code
- Update `CHANGELOG.md` (`[Unreleased]`) at end of each implementation phase

### Ask First
- Adding new external dependencies
- Changing `SecurityConfig` default values (security policy change)
- Modifying the `ArchiveFormat` or `FormatCreator` trait signatures (breaking API change)
- Enabling any feature in `AllowedFeatures` by default
- Raising or removing any quota default

### Never
- Commit secrets, credentials, or API keys
- Add `#[allow(unsafe_code)]` without explicit justification in PR description
- Remove existing security checks or lower default quota limits without a security review
- Add `unwrap()` or `expect()` outside of test modules
- Bypass clippy lints with `#[allow(...)]` without a comment explaining why

## 9. Open Questions

- [NEEDS CLARIFICATION: Should `verify_archive` attempt checksum validation for ZIP (CRC-32) and 7z formats, or only structural/security checks? Currently structural only.]
- [NEEDS CLARIFICATION: Is there a plan to support 7z creation in a future version, or is read-only permanently by design?]
- [NEEDS CLARIFICATION: Windows path separator handling in path validation — is there a CI job that runs the test suite on Windows?]
- [NEEDS CLARIFICATION: Should `ProgressCallback` expose a cancellation mechanism (e.g., return bool to abort)?]

> [!danger] Breaking Changes in v0.4.0
> - **`Archive::open`** now returns `Self` (was `Result<Self>`). Remove `?` or `.unwrap()` at call sites (#243).
> - **`SecurityConfig`**, **`AllowedFeatures`**, and **`ExtractionOptions`** are now `#[non_exhaustive]`. Struct literal construction no longer compiles; use `Default::default()` plus builder methods (#221).
> - Internal modules `copy`, `io`, `test_utils` in `exarch-core` are now `pub(crate)`. External references to `exarch_core::copy`, `exarch_core::io`, or `exarch_core::test_utils` no longer compile (#173).
> - `extract_archive_full` renamed to `extract_archive_with_options_and_progress` (#219).

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[001-exarch-system/plan]] — technical plan
