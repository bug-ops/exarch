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
- Magic byte detection (format is determined from extension only)

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
THEN the call fails with ExtractionError::InvalidArchive with an explanatory message
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
THEN the call fails with ExtractionError::UnsupportedFormat
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
I WANT the correct handler selected automatically from the archive extension
SO THAT I do not need to specify the format explicitly

**Acceptance criteria:**
```
GIVEN an archive path with an unrecognized extension
WHEN any archive operation is called
THEN ExtractionError::UnsupportedFormat is returned immediately
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-020 | WHEN an archive path has extension `.tar`, `.tgz`, `.tar.gz`, `.tar.bz2`, `.tbz`, `.tbz2`, `.tar.xz`, `.txz`, `.tar.zst`, `.tzst`, THE SYSTEM SHALL extract it as a TAR archive with the appropriate decompressor | must |
| FR-021 | WHEN an archive path has extension `.zip` or any ZIP-family alias, THE SYSTEM SHALL extract it as a ZIP archive | must |
| FR-022 | WHEN an archive path has extension `.7z`, THE SYSTEM SHALL extract it using the 7z handler | must |
| FR-023 | WHEN format detection finds an unrecognized or ambiguous extension (e.g. bare `.gz` without `.tar` stem), THE SYSTEM SHALL return `ExtractionError::UnsupportedFormat` | must |
| FR-024 | WHEN creating archives, THE SYSTEM SHALL support TAR (all compression variants) and ZIP; 7z creation SHALL return `UnsupportedFormat` | must |
| FR-025 | WHEN creating archives for ZIP-family aliases without an explicit `CreationConfig::format` override, THE SYSTEM SHALL return `ExtractionError::InvalidArchive` with an explanation | should |
| FR-026 | WHEN a 7z archive is solid and `allow_solid_archives` is false, THE SYSTEM SHALL reject extraction before decompressing the solid block | must |
| FR-027 | WHEN a 7z solid archive extraction is permitted, THE SYSTEM SHALL reject it if total uncompressed size exceeds `max_solid_block_memory` | must |
| FR-028 | Every format handler SHALL route all entries through `EntryValidator` before writing to disk | must |
| FR-029 | WHEN listing or verifying an archive, THE SYSTEM SHALL NOT write any files to disk | must |

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
| `FormatCreator` | Trait for archive creation; implemented by TAR variants and ZIP | Methods: `create`, `format_name` |
| `TarArchive<R>` | TAR handler generic over decompressor type | Implements `ArchiveFormat` |
| `ZipArchive` | ZIP handler | Implements `ArchiveFormat` and `FormatCreator` |
| `SevenZArchive` | 7z handler (read-only) | Implements `ArchiveFormat` only |

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
| `.gz` (no `.tar` stem), anything else | `UnsupportedFormat` |

> [!note]
> Format detection is extension-based, case-insensitive. Magic byte detection is NOT currently implemented.

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

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Archive path does not exist | `ExtractionError::Io` returned immediately |
| Extension unrecognized or bare `.gz` without `.tar` stem | `ExtractionError::UnsupportedFormat` |
| ZIP-family alias extraction | Proceeds as ZIP |
| ZIP-family alias creation without format override | `ExtractionError::InvalidArchive` with explanation |
| 7z creation | `ExtractionError::UnsupportedFormat` |
| Solid 7z with `allow_solid_archives = false` | Extraction rejected before decompressing |
| Solid 7z with total uncompressed size > `max_solid_block_memory` | `ExtractionError::QuotaExceeded` or format-specific rejection |
| Corrupt archive (unreadable headers) | `ExtractionError::InvalidArchive`; `verify_archive` returns `VerificationReport` with issues |
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
- [NEEDS CLARIFICATION: Should magic byte detection be added alongside extension detection for robustness?]

## 10. See Also

- [[constitution]] — format abstraction principles
- [[MOC-specs]] — all specifications
- [[001-security-pipeline/spec]] — `EntryValidator` that format handlers must use
- [[003-config-api/spec]] — `SecurityConfig`, `CreationConfig`, `ExtractionOptions`
- [[004-progress-tracking/spec]] — `ProgressCallback` passed to `extract` and `create`
- [[001-exarch-system/spec]] — original monolithic spec (archived)
