---
aliases:
  - Format Handlers Spec
  - Archive Format Spec
tags:
  - sdd
  - spec
  - archive
  - rust
created: 2026-05-20
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[001-security-pipeline/spec]]"
  - "[[003-config-api/spec]]"
  - "[[004-progress-tracking/spec]]"
---

# Feature: Format Handlers

> [!info] Metadata
> **Subsystem**: exarch-core / formats
> **MSRV**: Rust 1.93.0
> **zip dependency**: 9.0.0-pre2
> **Source**: extracted from [[001-exarch-system/spec]]

## 1. Overview

### Problem Statement

Each archive format (TAR variants, ZIP, 7z) requires different parsing logic,
decompression stacks, and entry iteration models. Without a uniform abstraction,
format-specific quirks bleed into security and reporting code, making it hard
to add formats or change security policy uniformly.

### Goal

Provide a single `ArchiveFormat` trait that every format handler implements,
giving the rest of `exarch-core` a uniform extract/list/verify interface
regardless of the underlying format. A complementary `FormatCreator` trait
covers archive creation. Format detection is performed once at the API boundary
using both file extension and a fixed set of ZIP-family aliases.

### Out of Scope

- RAR archive support
- Archive encryption or signing
- 7z archive creation (extraction only — `FormatCreator` not implemented for 7z)
- Streaming/incremental extraction over network (local files only)

## 2. User Stories

### US-001: TAR Extraction

AS A Rust developer
I WANT to extract `.tar.gz`, `.tar.bz2`, `.tar.xz`, `.tar.zst`, and `.tar` archives
with a single call
SO THAT I do not need to select the correct decompressor manually

**Acceptance criteria:**
```
GIVEN an archive path with a recognized TAR extension
WHEN extract_archive() is called
THEN the correct decompressor is selected automatically and extraction proceeds
through the security pipeline
```

### US-002: ZIP Extraction including Aliases

AS A developer or operator
I WANT `.jar`, `.apk`, `.whl`, and other ZIP-family archives to be extractable
SO THAT I can inspect their contents without a separate tool

**Acceptance criteria:**
```
GIVEN an archive path with a ZIP-family alias extension (e.g. .apk, .jar, .whl)
WHEN extract_archive() is called
THEN the archive is treated as ZIP and extraction proceeds normally
```

### US-003: ZIP-Family Alias Creation Rejection

AS A developer
I WANT archive creation to reject ZIP-family aliases without an explicit format override
SO THAT I am not silently given a bare ZIP file named .apk

**Acceptance criteria:**
```
GIVEN an output path with a ZIP-family alias extension and no CreationConfig::format override
WHEN create_archive() is called
THEN the call fails with ArchiveError::InvalidArchive with an explanatory message
```

### US-004: 7z Extraction Only

AS A developer
I WANT `.7z` archives to be extractable
SO THAT I can use exarch as a single tool for all common formats

**Acceptance criteria:**
```
GIVEN a valid .7z archive
WHEN extract_archive() is called
THEN extraction proceeds through the security pipeline and files are written to output_dir
```

```
GIVEN a .7z output path
WHEN create_archive() is called
THEN the call fails with ArchiveError::InvalidConfiguration
```

### US-005: Solid 7z Rejection by Default

AS A server operator
I WANT solid 7z archives to be rejected unless explicitly enabled
SO THAT a malicious solid archive cannot exhaust memory

**Acceptance criteria:**
```
GIVEN a solid 7z archive and SecurityConfig with allow_solid_archives = false
WHEN extract_archive() is called
THEN extraction fails before decompressing the solid block
```

### US-006: Format Detection

AS A developer
I WANT the correct handler selected automatically from the archive path
SO THAT I do not need to specify the format explicitly, even for files with missing or ambiguous extensions

**Acceptance criteria:**
```
GIVEN an archive path with an unrecognized extension
WHEN any archive operation is called
THEN ArchiveError::UnknownFormat { path } is returned immediately
```

```
GIVEN an archive whose extension is absent, unrecognized, or contradicts the file content
WHEN any archive operation is called
THEN detect_format falls back to magic-byte inspection and selects the correct handler
```

```
GIVEN an archive where magic bytes and extension disagree
WHEN any archive operation is called
THEN magic bytes take precedence over the extension
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-020 | WHEN an archive path has extension `.tar`, `.tgz`, `.tar.gz`, `.tar.bz2`, `.tbz`, `.tbz2`, `.tar.xz`, `.txz`, `.tar.zst`, `.tzst`, THE SYSTEM SHALL extract it as a TAR archive with the appropriate decompressor | must |
| FR-021 | WHEN an archive path has extension `.zip` or any ZIP-family alias, THE SYSTEM SHALL extract it as a ZIP archive | must |
| FR-022 | WHEN an archive path has extension `.7z`, THE SYSTEM SHALL extract it using the 7z handler | must |
| FR-023 | WHEN format detection cannot identify an archive via extension, THE SYSTEM SHALL fall back to magic-byte inspection (ZIP local-file header / EOCD, GZIP, BZ2, XZ, Zstd, 7z, TAR USTAR); when magic bytes and extension disagree, magic takes precedence; if neither resolves a format, THE SYSTEM SHALL return `ArchiveError::UnknownFormat { path }` | must |
| FR-024 | WHEN creating archives, THE SYSTEM SHALL support TAR (all compression variants) and ZIP; 7z creation SHALL return `InvalidConfiguration` | must |
| FR-025 | WHEN creating archives for ZIP-family aliases without an explicit `CreationConfig::format` override, THE SYSTEM SHALL return `ArchiveError::InvalidArchive` with an explanation | should |
| FR-026 | WHEN a 7z archive is solid and `allow_solid_archives` is false, THE SYSTEM SHALL reject extraction before decompressing the solid block | must |
| FR-027 | WHEN a 7z solid archive extraction is permitted, THE SYSTEM SHALL reject it if total uncompressed size exceeds `max_solid_block_memory` | must |
| FR-028 | Every format handler SHALL route all entries through `EntryValidator` before writing to disk | must |
| FR-029 | WHEN listing or verifying an archive, THE SYSTEM SHALL NOT write any files to disk | must |
| FR-030 | WHEN `allowed_extensions` in `SecurityConfig` is non-empty, ALL three format handlers (TAR, ZIP, 7z) SHALL skip entries whose extension is not in the allowlist and record them in `ExtractionReport::files_skipped` | must |
| FR-031 | `ArchiveFormat::extract` SHALL accept and invoke a `ProgressCallback` for every entry; ZIP-family alias creation without an explicit `CreationConfig::format` override SHALL be rejected with `ArchiveError::InvalidArchive` naming the alias | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | `BufReader` wraps all TAR file handles to reduce syscall count |
| NFR-002 | Performance | `CopyBuffer` (reusable buffer) used for all byte copying in format handlers |
| NFR-003 | Reliability | Solid 7z archives are rejected by default (`allow_solid_archives: false`) |
| NFR-004 | Portability | Format detection is case-insensitive on extension matching |
| NFR-005 | Maintainability | Every format handler implements `ArchiveFormat` — no format-specific logic in `api.rs` |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `ArchiveType` | Enum of supported archive formats | `Tar`, `TarGz`, `TarBz2`, `TarXz`, `TarZst`, `Zip`, `SevenZ` |
| `ArchiveFormat` | Trait implemented by every format handler | Methods: `extract`, `list`, `verify`, `format_name` |
| `FormatCreator` | Trait for archive creation; implemented by six unit structs | `TarCreator`, `TarGzCreator`, `TarBz2Creator`, `TarXzCreator`, `TarZstCreator`, `ZipCreator`; dispatched via `creator_for_format()` |
| `TarArchive<R>` | TAR handler generic over decompressor type | Implements `ArchiveFormat`; `list()` consumes the internal reader (TAR is forward-only); do not call `extract()` on the same instance |
| `ZipArchive` | ZIP handler | Implements `ArchiveFormat` and `FormatCreator`; `ZipFile::name()` returns `Result<Cow<str>, ZipError>` in zip 9.x |
| `SevenZArchive` | 7z handler (read-only) | Implements `ArchiveFormat` only; fires `on_entry_start`/`on_entry_complete` per-entry, interleaved with I/O |
| `ExtractionContext<'_, '_>` | Private TAR helper struct reducing extraction helper arity | Groups `validator`, `dest`, `report`, `copy_buffer`, `dir_cache`, `skip_duplicates` |

### ArchiveType Detection Rules

| Extension(s) | ArchiveType |
|---|---|
| `.tar` | `Tar` |
| `.tar.gz`, `.tgz` | `TarGz` |
| `.tar.bz2`, `.tbz`, `.tbz2` | `TarBz2` |
| `.tar.xz`, `.txz` | `TarXz` |
| `.tar.zst`, `.tzst` | `TarZst` |
| `.zip` | `Zip` |
| `.jar`, `.war`, `.ear`, `.nar`, `.nbm`, `.apk`, `.aab`, `.ipa`, `.appx`, `.msix`, `.whl`, `.vsix`, `.xpi`, `.epub` | `Zip` (extraction) / error (creation) |
| `.7z` | `SevenZ` |
| `.gz` (no `.tar` stem), anything else | Try magic-byte fallback; `UnknownFormat { path }` if magic also fails |

> [!note] v0.5.0: magic-byte fallback
> `detect_format` now falls back to magic-byte inspection when the file extension is absent,
> unrecognised, or contradicts the file content. Seven signatures are recognised: ZIP (local-file
> header, EOCD, split-archive marker), GZIP, BZ2, XZ, Zstd, 7z, and TAR USTAR. When magic bytes
> and extension disagree, magic takes precedence. Archive creation (`determine_creation_format`)
> remains extension-only so stale on-disk bytes cannot override the caller's intent.

### Trait Signatures

```
ArchiveFormat:
  extract(output_dir, config, options, progress) -> Result<ExtractionReport>
  list(config) -> Result<ArchiveManifest>
  verify(config) -> Result<VerificationReport>
  format_name() -> &'static str

FormatCreator:
  create(output, sources, config, progress) -> Result<CreationReport>
  format_name() -> &'static str
```

> [!note] zip dependency
> Upgraded from 8.6.0 to 9.0.0-pre2 in v0.4.0. `ZipFile::name()` now returns
> `Result<Cow<str>, ZipError>` instead of `&str`; all call sites propagate the
> new error via `?`.

> [!note] TarArchive forward-only constraint
> `TarArchive::list()` consumes the internal reader because TAR is forward-only.
> Callers must open a fresh `TarArchive` instance to call `extract()` after `list()`.

> [!note] 7z progress ordering fixed in v0.4.0
> Prior to v0.4.0, `SevenZArchive::extract` batched all `on_entry_start` calls
> before extraction and all `on_entry_complete` calls after. In v0.4.0, callbacks
> fire per-entry, interleaved with actual I/O (#191).

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Archive path does not exist | `ArchiveError::Io` returned immediately |
| Extension unrecognized or bare `.gz` without `.tar` stem | `ArchiveError::UnknownFormat { path }` |
| ZIP-family alias extraction | Proceeds as ZIP |
| ZIP-family alias creation without format override | `ArchiveError::InvalidArchive` with explanation |
| 7z creation | `ArchiveError::InvalidConfiguration` |
| Solid 7z with `allow_solid_archives = false` | Extraction rejected before decompressing |
| Solid 7z with total uncompressed size > `max_solid_block_memory` | `ArchiveError::QuotaExceeded` or format-specific rejection |
| Corrupt archive (unreadable headers) | `ArchiveError::InvalidArchive`; `verify_archive` returns `VerificationReport` with issues |
| Compression ratio unavailable per-entry (TAR streams) | Zip bomb check skipped for that entry; total quota still enforced |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | All TAR compression variants extract correctly | Integration tests for each variant pass |
| SC-002 | ZIP-family aliases extract as ZIP | Test coverage for at least `.jar`, `.apk`, `.whl` |
| SC-003 | 7z solid archive rejection | Test with solid fixture; rejected when `allow_solid_archives = false` |
| SC-004 | `ArchiveFormat` implementors are interchangeable | No format-specific code in `api.rs` |

## 8. Agent Boundaries

### Always (without asking)
- Route all entries through `EntryValidator` before any I/O
- Implement `format_name()` returning a human-readable static string
- Use `BufReader` for TAR file handles

### Ask First
- Modifying `ArchiveFormat` or `FormatCreator` trait signatures (breaking API change)
- Adding a new format handler
- Changing ZIP-family alias list

### Never
- Write files to disk during `list()` or `verify()`
- Implement security logic inside a format handler (delegate to `EntryValidator`)
- Implement 7z creation without security review of `sevenz-rust2` write support

## 9. Open Questions

- [NEEDS CLARIFICATION: Is there a plan to support 7z creation in a future version, or is read-only permanently by design?]

> [!note] Resolved in v0.5.0
> Magic-byte detection has been implemented alongside extension detection. `detect_format` now
> uses both extension and a magic-byte fallback (#353). `determine_creation_format` (used during
> archive creation) remains extension-only by design.

## 10. See Also

- [[constitution]] — format abstraction principles
- [[MOC-specs]] — all specifications
- [[001-security-pipeline/spec]] — `EntryValidator` that format handlers must use
- [[003-config-api/spec]] — `SecurityConfig`, `CreationConfig`, `ExtractionOptions`
- [[004-progress-tracking/spec]] — `ProgressCallback` passed to `extract` and `create`
- [[001-exarch-system/spec]] — original monolithic spec (archived)
