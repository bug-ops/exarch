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
updated: 2026-10-26
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[001-security-pipeline/spec]]"
  - "[[003-config-api/spec]]"
  - "[[004-progress-tracking/spec]]"
  - "[[008-tar-empty-directory-preservation/spec]]"
  - "[[009-accurate-compression-reporting/spec]]"
  - "[[013-quota-permit-capability-token/spec]]"
  - "[[017-zip-header-consistency/spec]]"
  - "[[018-7z-stream-map-panic/spec]]"
---

# Feature: Format Handlers

> [!info] Metadata
> **Subsystem**: exarch-core / formats
> **MSRV**: Rust 1.98.0
> **zip dependency**: 9.1.0 (floor 9.0.5)
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
| FR-032 | WHEN creating an archive, THE SYSTEM SHALL write an explicit directory entry (TAR: `append_dir`; ZIP: `add_directory`) for every directory in the source tree, including empty and nested-empty directories, for all TAR variants and ZIP alike; `CreationReport::directories_added` SHALL exclude the archive root itself (implemented v0.6.0, #400 — see [[008-tar-empty-directory-preservation/spec]]) | must |
| FR-033 | WHEN archive creation completes, THE SYSTEM SHALL set `CreationReport::bytes_compressed` to the actual on-disk size of the created archive file, measured after the writer/encoder is fully flushed and finished, for ZIP and every TAR variant (implemented v0.6.0, #402 — see [[009-accurate-compression-reporting/spec]]) | must |
| FR-034 | WHEN a symlink (to a file or to a directory) is passed directly as a top-level `create` source, THE SYSTEM SHALL classify it via `lstat`/`symlink_metadata` (not `stat`/`metadata`) and archive it as `EntryType::Symlink`, not dereference it into file content; a dangling symlink source SHALL NOT be rejected as missing | must |
| FR-035 | WHEN `CreationConfig::follow_symlinks` is enabled, THE SYSTEM SHALL dereference a symlink source (file or directory) for both TAR and ZIP creation, embedding the target's real content instead of a link entry | must |
| FR-036 | WHEN a TAR hardlink entry is extracted, THE SYSTEM SHALL charge its target's on-disk size against `QuotaTracker` via `EntryValidator::reserve_hardlink` before copying, so hardlink extraction cannot bypass `max_file_size`/`max_file_count`/`max_total_size` (fixed v0.6.0, #426) | must |
| FR-037 | WHEN listing an archive (`list_archive`), THE SYSTEM SHALL route every entry through the same `QuotaTracker` used by extraction rather than a separate, weaker inline implementation; a single entry larger than `max_file_size` SHALL be rejected during listing (fixed v0.6.0, #396 — breaking change: `list`/`verify` previously enforced only file count and total size) | must |
| FR-038 | WHEN 7z extraction writes a file and no pre-existing file occupies the destination, THE SYSTEM SHALL write directly to the destination path (same `O_EXCL`+`O_NOFOLLOW` guarantee as TAR/ZIP) instead of always staging through a temp-file-then-rename, retaining the temp+rename path only for the overwrite case (perf fix v0.6.0, #492: closed a 35–101% throughput gap vs. `sevenz_rust2::decompress_file`) | must |
| FR-039 | WHEN reading any compressed TAR, THE SYSTEM SHALL decode through the one `CompressionCodec::decoder` mapping shared by `extract`, `list`, `verify` and the `open_tar_*` functions, decoding every gzip member, bzip2 stream and xz stream and requiring at least one; after the last, only an all-zero tail (xz: a multiple of four bytes) SHALL be accepted, and any other trailing bytes are an error (0.7.0, #652, #670) | must |
| FR-040 | WHEN `extract`, `list` or `verify` meets a TAR entry that is a FIFO, character or block device, socket or any other typeflag that is not a file, directory or link, or has an empty name, THE SYSTEM SHALL refuse it with `ArchiveError::SecurityViolation`; a file-typed entry with a directory name (trailing `/`) and a payload SHALL be `InvalidArchive`, with an empty one read as a directory; a root entry (`.`, `./`) SHALL be a directory (0.7.0, #717, #721, #744, #752) | must |
| FR-041 | WHEN a ZIP is opened, THE SYSTEM SHALL admit only entries compressed with Stored, Deflate, Bzip2 or Zstd (anything else, including Deflate64, is `SecurityViolation`) and unencrypted, for `extract`, `list` and `verify` alike; entry names are split by exarch on both `/` and `\`, absolute and `..` names are refused unless `allow_absolute_paths` admits an absolute one, and an empty name or NUL byte is `SecurityViolation` (0.7.0, #652, #653, #717) | must |
| FR-042 | WHEN a ZIP is opened, THE SYSTEM SHALL apply the structure checks governed by `SecurityConfig::zip_consistency` (`ZipConsistencyPolicy::Enforce` by default), as specified in [[017-zip-header-consistency/spec]] (0.7.0, #671) | must |
| FR-043 | THE SYSTEM SHALL classify every 7z entry once, in `formats::sevenz::classify` (`SevenZClass`), for `extract`, `list` and `verify`: anti-items are skipped (one warning in `extract`, an informational `IssueCategory::ArchiveNote` in `verify`); a FIFO, socket, device node, undefined Unix type, a recorded kind that contradicts the entry's own kind, a reparse-point entry, or an empty name is refused with `SecurityViolation`; a Unix-mode symlink is validated through the symlink policy and `extract` creates it only under `allow_symlinks` (0.7.0, #707, #708, #710, #713, #715, #717, #723) | must |
| FR-044 | WHEN extracting or verifying a 7z archive, THE SYSTEM SHALL open the header once into a `SevenZHeader` whose stream map is proven to cover every block and file ([[018-7z-stream-map-panic/spec]]), walk entries in archive order, check every block's coder memory against `max_decoder_memory` (default 256 MiB) before decoding, bound a solid block as a whole by `max_solid_compression_ratio` (Rust API only, default 1000.0), and decode single-stream LZMA2 blocks on worker threads within the `ParallelDecode` lookahead (default 128 MiB) with the same output and error kinds as sequential decoding (0.7.0, #652, #688, #728, #752) | must |

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
| `FormatCreator` | Trait for archive creation; implemented by two crate-private structs (0.7.0, #652) | `TarCreator(Option<CompressionCodec>)` (`None` is plain `.tar`) and `ZipCreator`; dispatched via `creator_for_format()` over `FormatFamily` |
| `TarArchive<R>` | TAR handler generic over decompressor type | Implements `ArchiveFormat`; `list()` consumes the internal reader (TAR is forward-only); do not call `extract()` on the same instance; `open_tar_gz`, `open_tar_bz2`, `open_tar_zst(path)` and `open_tar_xz(path, &SecurityConfig<Validated>)` return `TarArchive<Box<dyn Read + Send>>` (the xz decoder is bounded by `max_decoder_memory` fixed at open) |
| `ZipArchive` | ZIP handler | Implements `ArchiveFormat`; creation is `ZipCreator`; `ZipFile::name()` returns `Result<Cow<str>, ZipError>` in zip 9.x |
| `SevenZArchive` | 7z handler (read-only) | Implements `ArchiveFormat` only; fires `on_entry_start`/`on_entry_complete` per-entry, interleaved with I/O; the header is parsed once into a `SevenZHeader` (`formats/sevenz/header.rs`) and entries are decoded in archive order through `BlockDecoder::for_each_entries` (`formats/sevenz/decode.rs`), never `decompress_with_extract_fn`, so `EntryValidator` remains the sole path-security guard (v0.5.1); entry names are normalized via `formats::common::normalize_entry_name` before validation; the handler is split into `admit`, `classify`, `decode`, `header`, `links`, `lzma2`, `verify` and `write` modules |
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
  verify(config, options) -> Result<VerificationReport>
  format_name() -> &'static str

FormatCreator:
  create(output, sources, config, progress) -> Result<CreationReport>
  format_name() -> &'static str
```

> [!note] v0.7.0: `verify` takes `&VerificationOptions` (#670)
> `ArchiveFormat::verify(config, options)` takes a `&VerificationOptions` selecting whether
> the payload is decoded to check integrity (`verify_archive_with_options`); with integrity
> requested, TAR content that fails to decode is an error rather than a report issue.

> [!note] v0.6.0: `ArchiveFormat` requires `SecurityConfig<Validated>` (#433, #434, #435)
> `SecurityConfig` is now a two-state typestate over `Unvalidated`/`Validated` markers
> (`SecurityConfig<State = Unvalidated>`). `ArchiveFormat::extract`, `list`, and `verify`
> now take `config: &SecurityConfig<Validated>` instead of `config: &SecurityConfig` — a
> breaking change for anyone implementing `ArchiveFormat` outside the crate or calling
> `TarArchive`/`ZipArchive`/`SevenZArchive` methods directly. The top-level
> `extract_archive*`, `list_archive`, `verify_archive`, and `create_archive*` functions are
> unaffected: they still accept a plain `&SecurityConfig` (defaulting to `Unvalidated`) and
> call `validate()` internally before dispatching to `ArchiveFormat`. No validation logic
> changed — this is purely a compile-time hardening of the existing "call `validate()` before
> use" convention.

> [!note] v0.6.0: `ValidatedEntryType::File` carries a `QuotaPermit` (#436, #439, #440, #447)
> Every format's file-write path (`formats::common::extract_file_with_permit` for TAR/ZIP,
> `formats::sevenz::write_file_with_permit` for 7z) now takes the `QuotaPermit` capability token
> by value instead of matching-and-dropping it (`_`). TAR's dispatch matches exhaustively on
> `ValidatedEntry::into_parts()`, so only the `File` arm can bind a permit — a compiler-enforced
> impossibility for any other arm to accidentally reach a write with no quota charge. ZIP retains
> a runtime fail-closed guard since its dispatch is not a single exhaustive match. See
> [[013-quota-permit-capability-token/spec]] for the full pattern.

> [!note] v0.6.0: 7z extraction performance parity with `sevenz_rust2::decompress_file` (#492)
> `formats::sevenz::write_file_with_permit_using` previously always staged through a temp file
> and `rename`, even when nothing occupied the destination — costing two extra syscalls per
> extracted file and attributing 45-54% of extraction CPU time to this path in profiling.
> `process_entry_inner` now writes directly to `dest_path` via `common::create_file_with_mode`
> when no pre-existing file is found there, keeping the atomic temp+rename path only for the
> overwrite case (so a decode failure mid-stream never leaves a truncated file at the final
> destination). `SevenZArchive` also retains its already-parsed `sevenz_rust2::Archive` from
> `new()` instead of re-parsing the header a second time at extraction. Re-measured via a new
> `sevenz_vs_reference` criterion bench group: the gap closed from 35%/101% slower to within
> noise of parity.

> [!note] v0.6.0: symlink sources archived as links, not dereferenced (#510, #512)
> A symlink (to a file or a directory) passed directly as a top-level `create` source was
> previously classified via `stat`/`metadata` (follows symlinks), silently dereferencing it into
> the target's content and rejecting a dangling symlink as `SourceNotFound`. `creation::walker::collect_entries`
> now uses `lstat`/`symlink_metadata` for this classification, so a symlink source archives as
> `EntryType::Symlink` by default (TAR: link entry; ZIP: skipped with a `Skipped symlink`
> warning, since ZIP has no on-disk symlink representation) and a dangling symlink is no longer
> rejected. **Breaking behavior change**: `exarch create a.tar link.txt` now stores a real
> symlink entry rather than the target's dereferenced content — extracting that archive now
> requires `--allow-symlinks` (deny-by-default) where it previously round-tripped without it.
> `CreationConfig::follow_symlinks` dereferences as before when explicitly enabled, and ZIP
> creation gained the `follow_symlinks` handling it was previously missing entirely.

> [!note] zip dependency
> Upgraded from 8.6.0 to 9.0.0-pre2 in v0.4.0, and to 9.1.0 in v0.7.0 (floor 9.0.5, which
> excludes versions with unpatched read-path vulnerabilities; 9.1.0 also reuses one DEFLATE
> compressor across entries on creation). `ZipFile::name()` returns
> `Result<Cow<str>, ZipError>` instead of `&str`; all call sites propagate the
> new error via `?`.

> [!note] TarArchive forward-only constraint
> `TarArchive::list()` consumes the internal reader because TAR is forward-only.
> Callers must open a fresh `TarArchive` instance to call `extract()` after `list()`.

> [!note] 7z progress ordering fixed in v0.4.0
> Prior to v0.4.0, `SevenZArchive::extract` batched all `on_entry_start` calls
> before extraction and all `on_entry_complete` calls after. In v0.4.0, callbacks
> fire per-entry, interleaved with actual I/O (#191).

> [!note] v0.5.1: `allow_absolute_paths` restored for 7z (#374, #375)
> `sevenz-rust2` 0.21.1 added an internal path-safety check inside
> `decompress_with_extract_fn` that silently blocked absolute-path entries before
> `EntryValidator` ever saw them, breaking `SecurityConfig::allowed.absolute_paths = true`
> for 7z archives — extraction would simply skip such entries instead of writing them
> (stripped) inside `output_dir`. `SevenZArchive::extract_with_callback` now drives
> extraction via `ArchiveReader::for_each_entries` directly, which has no built-in path
> check, restoring `EntryValidator` as the sole and authoritative guard for 7z path
> security (traversal, absolute paths, symlinks). This was an unresolved bug for one
> release cycle (introduced transitively by the `sevenz-rust2` 0.21.1 dependency bump) and
> is now fixed; no `SecurityConfig` or public API change was required.

> [!note] v0.5.1: 7z backslash path-traversal fixed (#365, #376)
> Entry names containing `\` (e.g. `..\..\x`, produced by archives written on Windows) were
> previously passed straight into `PathBuf::from(&entry.name)`. On Unix, `\` is a legal
> filename character, so the whole string became a single path component and slipped past
> `SafePath`'s `..` traversal check. All three 7z entry-name sites — the extraction
> pre-validation loop, the extraction callback, and the list/verify path
> (`inspection/list.rs`) — now call the shared `formats::common::normalize_entry_name`
> helper to replace `\` with `/` before constructing a `PathBuf`, so extract, list, and
> verify agree on traversal detection. Such entries are now correctly rejected with
> `ArchiveError::PathTraversal`. ZIP is unaffected (exarch's own entry-name splitter resolves
> Windows-style paths); TAR is intentionally left un-normalized because `\`
> is a legal Unix filename character in TAR archives.

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
| 7z entry with absolute path and `allowed.absolute_paths = true` | Written inside `output_dir` with the leading `/` stripped, same as TAR/ZIP (fixed in v0.5.1, #375; previously silently skipped) |
| 7z entry name containing `\` (e.g. `..\..\x`) | Normalized to `/` via `normalize_entry_name` before validation; rejected with `ArchiveError::PathTraversal` (fixed in v0.5.1, #376; previously bypassed traversal detection on Unix) |
| TAR-family `create` with empty directories in the source tree | Explicit directory entry written for each (including nested-empty); preserved on round-trip (fixed v0.6.0, #400 — was previously silently dropped for TAR only, ZIP was already correct) |
| `bytes_compressed` in `CreationReport` for ZIP/TAR creation | Reflects the real on-disk archive size, measured after the writer/encoder finishes (fixed v0.6.0, #402 — was previously always `0` for ZIP and the pre-compression TAR stream size for TAR) |
| Symlink (file or directory) passed as a top-level `create` source | Archived as `EntryType::Symlink` (TAR) or skipped with a warning (ZIP), not dereferenced; dangling symlink sources are no longer rejected as missing (fixed v0.6.0, #510, #512) |
| TAR hardlink entry during extraction | Charged against `QuotaTracker` via the target's on-disk size before copying (fixed v0.6.0, #426 — previously bypassed quota entirely) |
| Compressed TAR with trailing bytes after the last gzip member, bzip2 stream or xz stream, or empty input | Error; only an all-zero tail is accepted (0.7.0, FR-039) |
| TAR FIFO, device, socket or unknown typeflag entry, or an entry with an empty name | `SecurityViolation` in `extract`, `list` and `verify` (0.7.0, FR-040) |
| TAR file-typed entry with a directory name and a payload | `InvalidArchive` everywhere; with no payload it is read as a directory (0.7.0, #752) |
| ZIP entry with a method other than Stored, Deflate, Bzip2 or Zstd (for example Deflate64) | `SecurityViolation` at open (0.7.0, FR-041) |
| ZIP local and central headers disagree, or the archive hides data | Rejected under `ZipConsistencyPolicy::Enforce`, unchecked under `Ignore` (0.7.0, FR-042; see [[017-zip-header-consistency/spec]]) |
| 7z anti-item | Skipped, never extracted, listed or counted; one warning in `extract`, an informational `ArchiveNote` finding in `verify` (0.7.0, FR-043) |
| 7z reparse-point entry, FIFO, socket, device, undefined Unix type, kind contradiction or empty name | `SecurityViolation` before any write (0.7.0, FR-043) |
| 7z Unix-mode symlink | Created by `extract` only under `allow_symlinks` after its target passes the symlink policy; `list` reads the target only on request (0.7.0, FR-043) |
| 7z header with streams info and no files info | `InvalidArchive` from `list`, `verify` and `extract` (0.7.0, #752; see [[018-7z-stream-map-panic/spec]]) |
| 7z block whose decoder memory exceeds `max_decoder_memory`, or a solid block over `max_solid_compression_ratio` | Refused (decoder memory before any byte is decoded; the solid ratio from the header's declared sizes) (0.7.0, FR-044) |
| `list_archive` on an entry larger than `max_file_size` | Rejected during listing, same as extraction (fixed v0.6.0, #396 — breaking change; `verify_archive`'s internal pre-flight listing keeps `max_file_size` unlimited so an oversized entry surfaces as a `VerificationIssue` instead of aborting before any report exists) |

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
- [[008-tar-empty-directory-preservation/spec]] — TAR directory-entry fix in detail (implemented)
- [[009-accurate-compression-reporting/spec]] — `bytes_compressed` accuracy fix in detail (implemented)
- [[013-quota-permit-capability-token/spec]] — `QuotaPermit` pattern consumed by every format's file-write path
- [[017-zip-header-consistency/spec]] — ZIP structure checks and `ZipConsistencyPolicy`
- [[018-7z-stream-map-panic/spec]] — `SevenZHeader` stream-map validation
- [[001-exarch-system/spec]] — original monolithic spec (archived)
