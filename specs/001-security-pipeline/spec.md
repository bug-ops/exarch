---
aliases:
  - Security Pipeline Spec
  - exarch Security Spec
tags:
  - sdd
  - spec
  - security
  - rust
created: 2026-05-20
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[002-format-handlers/spec]]"
  - "[[003-config-api/spec]]"
---

# Feature: Security Pipeline

> [!info] Metadata
> **Subsystem**: exarch-core / security
> **MSRV**: Rust 1.93.0
> **Source**: extracted from [[001-exarch-system/spec]]

## 1. Overview

### Problem Statement

Archive extraction is a primary attack surface: path traversal, zip bombs,
symlink escapes, and hardlink attacks have affected nearly every major archive
library. Existing Rust crates expose raw decompression without integrated
validation, leaving each consumer to re-implement mitigations inconsistently.

### Goal

Provide a single, typed security pipeline inside `exarch-core` that validates
every archive entry before any bytes reach disk. The pipeline is the only
place where security decisions are made — format handlers and bindings must
route all entries through it.

### Out of Scope

- Security configuration API (see [[003-config-api/spec]])
- Format-specific parsing (see [[002-format-handlers/spec]])
- Progress reporting during validation (see [[004-progress-tracking/spec]])
- GUI or web interface

## 2. User Stories

### US-001: Path Traversal Prevention

AS A Rust developer using `extract_archive()`
I WANT every archive entry path to be validated before any file is written
SO THAT traversal sequences (`../`), absolute paths, null bytes, and banned
components are rejected before I/O begins

**Acceptance criteria:**
```
GIVEN an archive containing a path traversal entry (e.g. "../etc/passwd")
WHEN extract_archive() is called
THEN extraction fails with ExtractionError::PathTraversal before any file is written
```

```
GIVEN an archive entry path containing a banned component (e.g. ".git/config")
WHEN extract_archive() is called
THEN extraction fails with ExtractionError::PathTraversal (banned component)
```

### US-002: Zip Bomb Detection

AS A security engineer
I WANT archives with extreme compression ratios to be rejected
SO THAT a malicious archive cannot exhaust disk space or memory

**Acceptance criteria:**
```
GIVEN an archive entry where uncompressed_size / compressed_size > max_compression_ratio
WHEN the entry is validated
THEN the entry is rejected with ExtractionError::ZipBomb before any bytes are written
```

### US-003: Symlink and Hardlink Control

AS A system administrator
I WANT symlinks and hardlinks to be denied by default
SO THAT attackers cannot use them to escape the extraction directory

**Acceptance criteria:**
```
GIVEN a symlink entry and SecurityConfig with allowed.symlinks = false
WHEN the entry is validated
THEN the entry is skipped (not an error)
```

```
GIVEN a symlink entry and SecurityConfig with allowed.symlinks = true
WHEN the resolved target escapes output_dir
THEN extraction fails with ExtractionError::SymlinkEscape
```

### US-004: Quota Enforcement

AS A server operator
I WANT per-file and total-size limits enforced during extraction
SO THAT a single archive cannot exhaust disk space

**Acceptance criteria:**
```
GIVEN a file entry whose uncompressed size exceeds max_file_size
WHEN the entry is validated
THEN extraction fails with ExtractionError::QuotaExceeded { resource: FileSizeBytes }
```

```
GIVEN cumulative uncompressed size across entries exceeds max_total_size
WHEN the next entry is validated
THEN extraction fails with ExtractionError::QuotaExceeded { resource: TotalSizeBytes }
```

### US-005: Permission Sanitization

AS A system administrator on Unix
I WANT setuid and setgid bits stripped from extracted files
SO THAT an archive cannot install privileged executables

**Acceptance criteria:**
```
GIVEN a file entry with setuid or setgid bits set (mode & 0o6000 != 0)
WHEN the entry is extracted on Unix
THEN the written file has those bits cleared; ValidatedEntry.mode reflects the sanitized value
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN any archive entry path is validated, THE SYSTEM SHALL reject paths containing `../`, absolute paths, null bytes, or components matching `banned_path_components` (case-insensitive) | must |
| FR-002 | WHEN a file entry's uncompressed size exceeds `max_file_size`, THE SYSTEM SHALL reject it with `QuotaExceeded` | must |
| FR-003 | WHEN the cumulative uncompressed size across all file entries exceeds `max_total_size`, THE SYSTEM SHALL reject further entries with `QuotaExceeded` | must |
| FR-004 | WHEN a file entry has a known compressed size and the ratio (uncompressed / compressed) exceeds `max_compression_ratio`, THE SYSTEM SHALL reject it with `ZipBomb` before writing any bytes | must |
| FR-005 | WHEN a symlink entry is encountered and `allowed.symlinks` is false, THE SYSTEM SHALL skip the entry without returning an error | must |
| FR-006 | WHEN a symlink entry is encountered and `allowed.symlinks` is true, THE SYSTEM SHALL validate that the resolved symlink target does not escape `output_dir` | must |
| FR-007 | WHEN a hardlink entry is encountered and `allowed.hardlinks` is false, THE SYSTEM SHALL skip the entry | must |
| FR-008 | WHEN a hardlink entry is encountered and `allowed.hardlinks` is true, THE SYSTEM SHALL validate that the hardlink target path is within `output_dir` and references a path previously seen in this archive | must |
| FR-009 | WHEN extracting files on Unix, THE SYSTEM SHALL strip setuid (0o4000) and setgid (0o2000) bits from all file permissions | must |
| FR-010 | WHEN the path depth of an entry exceeds `max_path_depth`, THE SYSTEM SHALL reject the entry with `ExtractionError::PathTraversal` | must |
| FR-011 | WHEN `allowed_extensions` is non-empty and an entry's extension is not in the list, THE SYSTEM SHALL skip the entry and record it in `ExtractionReport::files_skipped` with a warning | must |
| FR-012 | WHEN the file count across all entries exceeds `max_file_count`, THE SYSTEM SHALL reject further entries with `QuotaExceeded { resource: FileCount }` | must |
| FR-013 | WHEN `allowed.world_writable` is false and a file entry has world-writable permissions (`mode & 0o002 != 0`), THE SYSTEM SHALL strip that bit or reject the entry | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Security | All security checks run before any bytes are written to disk for each entry |
| NFR-002 | Security | Path component matching is case-insensitive to prevent bypass on case-insensitive filesystems |
| NFR-003 | Security | Default limits: 50 MB per file, 500 MB total, 100× compression ratio, 10,000 files, depth 32 |
| NFR-004 | Security | Default banned components: `.git`, `.ssh`, `.gnupg`, `.aws`, `.kube`, `.docker`, `.env` |
| NFR-005 | Safety | `deny(unsafe_code)` workspace-wide — no exceptions in this module |
| NFR-006 | Performance | `canonicalize()` is NOT called per-entry for path traversal; `PathBuf::components()` used instead |
| NFR-007 | Performance | `DirCache` caches directories created by the extractor to avoid repeated `canonicalize()` syscalls |
| NFR-008 | Reliability | Quota tracking (`QuotaTracker`) is not reversible — once exceeded, extraction halts |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `SafePath` | Newtype for a validated archive entry path; can only be constructed after all traversal, depth, and component checks pass | Wraps `PathBuf`; invariant: no traversal, within dest, depth within limit |
| `SafeSymlink` | Newtype for a symlink target confirmed to resolve within `output_dir` | Wraps `PathBuf` |
| `ValidatedEntry` | Archive entry that has passed the full security pipeline | `safe_path: SafePath`, `entry_type: ValidatedEntryType`, `mode: Option<u32>` (sanitized) |
| `ValidatedEntryType` | Enum of post-validation entry classifications | `File`, `Directory`, `Symlink(SafeSymlink)`, `Hardlink { target: SafePath }` |
| `EntryValidator` | Stateful orchestrator running all security checks in order per entry | Holds `QuotaTracker`, `HardlinkTracker`, `symlink_seen` flag; references `SecurityConfig` and `DestDir` |
| `QuotaTracker` | Accumulates file count and total bytes; rejects on limit exceeded | `file_count`, `total_bytes` |
| `HardlinkTracker` | Records all file paths seen in this archive to validate hardlink targets | `seen: HashSet<PathBuf>` |
| `DestDir` | Canonicalized output directory; used as the trust boundary for symlink/hardlink validation | Wraps `PathBuf` |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Path traversal `../` or absolute path | `ExtractionError::PathTraversal` |
| Null byte in path | `ExtractionError::PathTraversal` |
| Banned component (e.g. `.git`) in path | `ExtractionError::PathTraversal` (banned component) |
| Path depth > `max_path_depth` | `ExtractionError::PathTraversal` (depth exceeded) |
| File exceeds `max_file_size` | `ExtractionError::QuotaExceeded { resource: FileSizeBytes }` |
| Total size exceeds `max_total_size` | `ExtractionError::QuotaExceeded { resource: TotalSizeBytes }` |
| File count exceeds `max_file_count` | `ExtractionError::QuotaExceeded { resource: FileCount }` |
| Compression ratio > `max_compression_ratio` | `ExtractionError::ZipBomb` (before any bytes written) |
| Compression ratio not available (TAR streams) | Zip bomb check skipped for that entry; quota still enforced |
| Symlink with `allowed.symlinks = false` | Entry skipped (not an error) |
| Symlink pointing outside `output_dir` | `ExtractionError::SymlinkEscape` |
| Hardlink with `allowed.hardlinks = false` | Entry skipped |
| Hardlink to a path not previously seen | `ExtractionError::HardlinkEscape` |
| setuid/setgid bits on Unix | Stripped silently; `ValidatedEntry.mode` reflects sanitized value |
| `SecurityConfig` with zero `max_file_size`, `max_total_size`, `max_path_depth`, `max_file_count`, or `max_solid_block_memory` | `SecurityConfig::validate()` returns `InvalidConfiguration` before extraction begins |
| `SecurityConfig` with `max_compression_ratio` of 0.0, negative, or NaN | `SecurityConfig::validate()` returns `InvalidConfiguration` before extraction begins |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Path traversal attempts blocked | 100% of known CVE-pattern archives rejected |
| SC-002 | Zip bomb detection | Archives with ratio > 100× rejected before first byte written |
| SC-003 | Symlink escape prevention | Symlinks resolving outside `output_dir` always rejected |
| SC-004 | Security checks have property-based or integration tests | All checks covered |
| SC-005 | `deny(unsafe_code)` in security module | Zero `unsafe` blocks |

## 8. Agent Boundaries

### Always (without asking)
- Run all security checks before any I/O for every entry
- Use `PathBuf::components()` for traversal detection — do not call `canonicalize()` per-entry
- Add `///` doc comments to every `pub` item in this module
- Keep security checks in `exarch-core/src/security/` — never in bindings or CLI

### Ask First
- Changing `SecurityConfig` default values (security policy change)
- Modifying `EntryValidator` trait or `ValidatedEntry` structure (breaking API change)
- Enabling any `AllowedFeatures` flag by default
- Raising or removing any quota default

### Never
- Remove existing security checks or lower default quota limits without a security review
- Add `#[allow(unsafe_code)]` in any security module
- Call `canonicalize()` inside the hot per-entry validation path
- Allow `ExtractionError` variants to be constructed outside `exarch-core`

## 9. Open Questions

- [NEEDS CLARIFICATION: Should `ProgressCallback` expose a cancellation mechanism (return bool) so callers can abort mid-stream from the security callback?]
- [NEEDS CLARIFICATION: Windows path separator handling (`\` vs `/`) — is there a CI job covering Windows path validation edge cases?]

> [!note] Resolved in v0.4.0
> World-writable entries: behavior clarified — the `allow_world_writable` bit is stripped (not rejection), matching setuid/setgid treatment. `allowed_extensions` filtering (FR-011) is now fully implemented across TAR, ZIP, and 7z in v0.4.0 (#230, #242). `SecurityConfig::validate()` now also rejects `max_file_count == 0` and `max_solid_block_memory == 0` in addition to the previously documented zero-limit fields (#181).

## 10. See Also

- [[constitution]] — project principles (security section)
- [[MOC-specs]] — all specifications
- [[002-format-handlers/spec]] — format handlers that route entries through this pipeline
- [[003-config-api/spec]] — `SecurityConfig`, `AllowedFeatures` configuration types
- [[001-exarch-system/spec]] — original monolithic spec (archived)
