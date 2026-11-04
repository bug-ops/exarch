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
updated: 2026-11-04
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[002-format-handlers/spec]]"
  - "[[003-config-api/spec]]"
  - "[[013-quota-permit-capability-token/spec]]"
  - "[[014-config-typestate-validation/spec]]"
  - "[[016-sanitized-mode-and-non-exhaustive-enums/spec]]"
  - "[[017-zip-header-consistency/spec]]"
  - "[[020-reader-sink-and-in-memory-api/spec]]"
---

# Feature: Security Pipeline

> [!note] Revision 2026-11-04 (50-issue batch)
> `EntryValidator`, `ValidatedEntry`, `ValidatedEntryType` and `ValidationReport` were removed (#900) and the `Unvalidated`/`Validated` typestate with them (#898); older notes below that name them describe the design of the release they mention. Current names: `ValidatorCore`, `ValidatedFile`, `ValidatedSymlink`, `ValidatedHardlink`, `AdmittedSize`, `CheckedLinkTarget`, `VirtualTree::project_landing`. See FR-018 and FR-036 to FR-043.

> [!info] Metadata
> **Subsystem**: exarch-core / security
> **MSRV**: Rust 1.98.0
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
THEN extraction fails with ArchiveError::PathTraversal before any file is written
```

```
GIVEN an archive entry path containing a banned component (e.g. ".git/config")
WHEN extract_archive() is called
THEN extraction fails with ArchiveError::SecurityViolation whose relaxable_by is
     PolicySetting::BannedComponents
```

### US-002: Zip Bomb Detection

AS A security engineer
I WANT archives with extreme compression ratios to be rejected
SO THAT a malicious archive cannot exhaust disk space or memory

**Acceptance criteria:**
```
GIVEN an archive entry where uncompressed_size / compressed_size > max_compression_ratio
WHEN the entry is validated
THEN the entry is rejected with ArchiveError::ZipBomb(ZipBombDetails) before any bytes are written
```

```
GIVEN an entry or solid block that claims data from zero compressed bytes
WHEN the entry is validated
THEN it is rejected with ArchiveError::ZipBomb whose ratio is CompressionRatio::Unbounded
     (never InvalidArchive)
```

### US-003: Symlink and Hardlink Control

AS A system administrator
I WANT symlinks and hardlinks to be denied by default
SO THAT attackers cannot use them to escape the extraction directory

**Acceptance criteria:**
```
GIVEN a symlink entry and SecurityConfig with allowed.symlinks = false
WHEN the entry is validated
THEN extraction fails with ArchiveError::SecurityViolation whose relaxable_by is
     PolicySetting::Symlinks
```

```
GIVEN a symlink entry and SecurityConfig with allowed.symlinks = true
WHEN the resolved target escapes output_dir
THEN extraction fails with ArchiveError::SymlinkEscape
```

```
GIVEN a link target whose ".." components leave a directory that does not exist yet
      (one the archive may create later) and is not part of the link's own parent chain
WHEN the entry is validated
THEN extraction fails with ArchiveError::SymlinkEscape (HardlinkEscape for a hardlink)
```

### US-004: Quota Enforcement

AS A server operator
I WANT per-file and total-size limits enforced during extraction
SO THAT a single archive cannot exhaust disk space

**Acceptance criteria:**
```
GIVEN a file entry whose uncompressed size exceeds max_file_size
WHEN the entry is validated
THEN extraction fails with ArchiveError::QuotaExceeded { resource: FileSize { .. } }
```

```
GIVEN cumulative uncompressed size across entries exceeds max_total_size
WHEN the next entry is validated
THEN extraction fails with ArchiveError::QuotaExceeded { resource: TotalSize { .. } }
```

### US-005: Permission Sanitization

AS A system administrator on Unix
I WANT setuid and setgid bits stripped from extracted files
SO THAT an archive cannot install privileged executables

**Acceptance criteria:**
```
GIVEN a file entry with setuid or setgid bits set (mode & 0o6000 != 0)
WHEN the entry is extracted on Unix
THEN the written file has those bits cleared; the mode carried by the validated file proof is the sanitized value
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN any archive entry path is validated, THE SYSTEM SHALL reject paths containing `../` or absolute paths (`PathTraversal`), null bytes (`SecurityViolation`), or components matching `banned_path_components` (`SecurityViolation`, `relaxable_by` `BannedComponents`; case-insensitive) | must |
| FR-002 | WHEN a file entry's uncompressed size exceeds `max_file_size`, THE SYSTEM SHALL reject it with `QuotaExceeded` | must |
| FR-003 | WHEN the cumulative uncompressed size across all file entries exceeds `max_total_size`, THE SYSTEM SHALL reject further entries with `QuotaExceeded` | must |
| FR-004 | WHEN a file entry has a known compressed size and the ratio (uncompressed / compressed) exceeds `max_compression_ratio`, THE SYSTEM SHALL reject it with `ZipBomb(ZipBombDetails)` before writing any bytes; data claimed from zero compressed bytes is `ZipBomb` with an `Unbounded` ratio, and a whole 7z solid block is checked against `SolidLimits::max_ratio` (`ZipBombScope::SolidBlock`; the ratio check uses `SolidLimits::DEFAULT` while solid archives are refused) | must |
| FR-005 | WHEN a symlink entry is encountered and `allowed.symlinks` is false, THE SYSTEM SHALL reject it with `SecurityViolation` whose `relaxable_by` is `PolicySetting::Symlinks` | must |
| FR-006 | WHEN a symlink entry is encountered and `allowed.symlinks` is true, THE SYSTEM SHALL validate that the resolved symlink target does not escape `output_dir`, following on-disk symlinks, and SHALL reject a target whose `..` leaves a directory that does not exist yet and is not part of the link's own parent chain | must |
| FR-007 | WHEN a hardlink entry is encountered and `allowed.hardlinks` is false, THE SYSTEM SHALL reject it with `SecurityViolation` whose `relaxable_by` is `PolicySetting::Hardlinks` | must |
| FR-008 | WHEN a hardlink entry is encountered and `allowed.hardlinks` is true, THE SYSTEM SHALL validate that the hardlink target path, resolved through on-disk symlinks, is within `output_dir` (`HardlinkEscape` otherwise); a target absent when the link is created is `InvalidArchive` | must |
| FR-009 | WHEN extracting files on Unix, THE SYSTEM SHALL strip setuid (0o4000) and setgid (0o2000) bits from all file permissions, and apply the sanitized mode via `fchmod` on the already-open file descriptor (`File::set_permissions`), never via a path-based `set_permissions()` call after `open()` | must |
| FR-010 | WHEN the path depth of an entry exceeds `max_path_depth`, THE SYSTEM SHALL reject the entry with `ArchiveError::SecurityViolation` whose `relaxable_by` is `PolicySetting::MaxPathDepth` | must |
| FR-011 | WHEN `allowed_extensions` (a list of normalized `Extension` values, lowercase, no leading dot) is non-empty and an entry's extension is not in the list, THE SYSTEM SHALL skip the entry and record it as `SkipKind::ExtensionNotAllowed` in `ExtractionReport::skipped` (counts per kind plus a bounded sample, see [[004-progress-tracking/spec]]); the predicate is `SecurityConfig::is_extension_allowed(Option<&str>)` | must |
| FR-012 | WHEN the count of extracted files, symlinks and hardlinks (directories are not counted) exceeds `max_file_count`, THE SYSTEM SHALL reject further entries with `QuotaExceeded { resource: FileCount }`; a hardlink is counted in the first pass through an `EntryCount` token, so the second pass charges only its bytes | must |
| FR-013 | WHEN `allowed.world_writable` is false and a file entry has world-writable permissions (`mode & 0o002 != 0`), THE SYSTEM SHALL strip that bit or reject the entry | must |
| FR-014 | WHEN copying an entry's decompressed bytes to disk, THE SYSTEM SHALL enforce the entry's declared size as a hard streaming ceiling — checked after every buffered read, not only at EOF — aborting with `ArchiveError::SecurityViolation` the instant actual bytes exceed the declared size, and rejecting a short stream (fewer bytes than declared) once EOF is reached, closing GHSA-5j8q-wxg5-hj4r (a ZIP entry whose real DEFLATE stream inflates far beyond its declared `uncompressed_size`) | must |
| FR-015 | WHEN a symlink or hardlink target is validated, THE SYSTEM SHALL reject an empty target or one containing a null byte, in addition to the existing containment checks on the target path itself | must |
| FR-016 | WHEN opening a destination path for a file, symlink-target read, or 7z temp-file write, THE SYSTEM SHALL use `O_EXCL`/`O_NOFOLLOW` (Unix) or an equivalent atomic create-exclusive open rather than a prior `Path::exists()` check, since `exists()` follows symlinks and reports `false` for a dangling one — letting a pre-planted symlink at the destination bypass duplicate detection and redirect the write outside the extraction root | must |
| FR-017 | WHEN a file entry is validated, THE SYSTEM SHALL produce a `QuotaPermit` capability token from `QuotaTracker::reserve` that the eventual write path must consume by value, so a validated `File` entry with no quota charge is unrepresentable and a reservation cannot be spent twice (see [[013-quota-permit-capability-token/spec]]) | must |
| FR-018 | THE SYSTEM SHALL hold every security limit in a typed field that cannot represent an invalid value (`NonZero*`, `Limit`, `RatioLimit`, `Admit`, `SolidArchives`); `SecurityConfig` and `CreationConfig` are plain structs and there is no `validate()` or `Unvalidated`/`Validated` typestate (removed in #898; the obsolete [[014-config-typestate-validation/spec]] describes the former design, see [[003-config-api/spec]]) | must |
| FR-019 | WHEN comparing a validated entry's canonicalized parent path against the destination root on macOS/Windows, THE SYSTEM SHALL compare `Path::components()` pairwise (case-folding each segment) rather than the raw lowercased path strings, so a sibling directory sharing the destination root's name as a string prefix (e.g. `/tmp/destevil` vs. `/tmp/dest`) is not treated as contained within it, closing GHSA-wcmx-7f9h-5mv5 | must |
| FR-020 | `ArchiveError::SecurityViolation` SHALL be `#[non_exhaustive]` and carry a typed `kind: Violation` (`error/violation.rs`, `#[non_exhaustive]`) instead of free-text reasons; the sub-code and relaxability SHALL derive from the kind via `Violation::sub_code()` and `Violation::relaxable_by() -> Option<PolicySetting>` (no setting lifts a refusal whose kind returns `None`), the kind SHALL be readable through `ArchiveError::security_violation()`, and `ArchiveError::relaxable_by()` SHALL return the setting, also through `PartialExtraction`. `PolicySetting` (`#[non_exhaustive]`) names the refusing `SecurityConfig` setting: `Symlinks`, `Hardlinks`, `SolidArchives`, `BannedComponents`, `MaxPathDepth`, `WindowsReservedNames`, `MaxTarMetadataBytes`; a refusal that no setting relaxes carries none | must |
| FR-021 | WHEN a path component or link-target component is validated on Windows, THE SYSTEM SHALL reject a component containing `:` or ending in `.` or a space with `SecurityViolation` (never relaxable), and a legacy device name (`CON`, `NUL`, `COM1`, ...) with `SecurityViolation` relaxable by `AllowedFeatures::windows_reserved_names` (`PolicySetting::WindowsReservedNames`); `is_windows_reserved_component` is public and `SecurityConfig::permissive()` does not enable the opt-out | must |
| FR-022 | WHEN an entry names the archive root (`.` or `./`), THE SYSTEM SHALL accept it only as a directory (for ZIP also an empty regular file, which the `zip` crate reads for a bare `.`) and reject any other kind or a payload with `SecurityViolation`; the rule is classified once (`EntryPath::Root`/`Child`, `NodeKind`) so `extract`, `list` and `verify` agree. An empty entry name is `SecurityViolation` | must |
| FR-023 | WHEN a decoder would exceed `max_decoder_memory` (xz dictionary and state, 7z decoder window, the zstd window as the largest power of two at or below the limit and at most 128 MiB), THE SYSTEM SHALL fail with `QuotaExceeded { resource: DecoderMemory { max } }`; the zstd window of a `.tar.zst` is set on the decoder, and that of a ZIP is read from the frame headers of its zstd entries and refused by `extract`, `list` and `verify` before any entry is listed or extracted; the open-time census decodes zstd entries only under the window limit of the config that opened the archive (`ZipArchive::new` opens at libzstd's default 128 MiB, so under `Enforce` it may decode a window the later config refuses, and skips none) and skips zstd entries whose window that limit does not admit (v0.8.0, #849); 7z parallel LZMA2 lookahead is bounded separately by `parallel_decode` (`ParallelDecode`) | must |
| FR-024 | THE SYSTEM SHALL validate every entry against a `PathModel` (`Host` or `Portable`, see [[020-reader-sink-and-in-memory-api/spec]]); `Host` applies the running platform's component rules and, on a Windows host, the `Portable` component rules, so a name or link target containing `<>"\|?*`, a control character, `:`, a trailing dot or space, or non-Unicode text is refused with `SecurityViolation` (never relaxable) and a symlink target with such a component no longer creates a dangling link; `Portable` applies the strictest rules of every platform on every host (v0.8.0, #778, #780, #787, #790) | must |
| FR-025 | `ValidatorCore` SHALL hand an extraction target one typed proof per entry kind (`ValidatedFile` carrying its `QuotaPermit`, `ValidatedSymlink`, `ValidatedHardlink`, `EntrySize`; `security::admitted`), constructed only by the validator, so the host filesystem and an `EntrySink` run the same gates and a target cannot write a file whose quota was not reserved (v0.8.0, #793, #808); `EntrySize` has private fields and the getters `uncompressed()` and `compressed()` (#905) | must |
| FR-026 | WHEN a directory entry targets a path held by a file or a symlink, THE SYSTEM SHALL refuse it with the same entry-naming message in `extract` and `verify`; `extract --force` over an existing directory or symlink SHALL name the entry (`refusing to replace the existing directory at d`) for TAR, ZIP and 7z (v0.8.0, #765, #802, #803) | must |
| FR-027 | THE SYSTEM SHALL bound the in-memory destination model used by `verify` and `SinkExtractRequest::extract` by a node budget of `max_file_count * max_path_depth + 1` names, failing with `QuotaExceeded { resource: TreeNodes { max } }`, and SHALL treat a link path that leaves the root and returns as an escape (v0.8.0, #778, #779, #787) | must |
| FR-028 | WHEN the `zip` crate or the structural check built on it fails to open the archive or read an entry (archive or entry unreadable, census and reader disagree about the central directory, an entry's data range not representable, zstd entries not walkable within the archive extent), THE SYSTEM SHALL fail with `InvalidArchive` carrying the sub-code `ZIP_READER` (`InvalidArchiveSubCode::ZipReader`; Python `sub_code`, Node `subCode`, CLI `--json` `error.sub_code`); messages are unchanged, TAR reader failures carry `TAR_READER` and 7z reader failures `SEVENZ_READER` (`Malformation` kinds that mirror `ZipReader`, messages byte-identical, #930); the failures that are not reader failures (for example a creation refusal) stay `Malformation::Unclassified` and carry no sub-code (#889, #930, #946) | must |
| FR-029 | WHEN an entry lands through an archive symlink, THE SYSTEM SHALL accept or refuse it by its relative length (the directory walker's check, see [[019-verify-and-list-model/spec]] FR-048) on every platform, not by the host realpath of the destination, and a directory entry exactly at the limit SHALL be accepted; on Unix a pre-existing symlink among the destination's parent components SHALL be followed handle-relatively (`readlinkat`, `fstatat` and `openat` on held directory descriptors, bounded by the shared `MAX_SYMLINK_HOPS`), independent of the destination's absolute length; an absolute link target SHALL be accepted only when spelled through the destination's own spelled root or its canonical root (a bind mount or another alias of the destination is refused, fail-closed) and a target that leaves the root and re-enters it SHALL be refused; Windows and WASI keep the host realpath behind a `cfg` gate; excluded: `SafeSymlink` target validation through an on-disk link whose host absolute path exceeds the host limit, which is still refused by absolute length (now with the length error, not `SymlinkEscape`) (#892, #895, #946) | must |
| FR-030 | THE SYSTEM SHALL classify every `InvalidArchive` and `SecurityViolation` error with a stable sub-code: `ArchiveError::InvalidArchive` SHALL carry a typed `Malformation` (`error/malformation.rs`, `#[non_exhaustive]`) whose `sub_code()` is an `InvalidArchiveSubCode` (`TAR_AMBIGUITY`, `TAR_TRAILER`, `LINK_TARGET`, `DUPLICATE_ENTRY`, `ENTRY_NAME`, `DECLARED_SIZE`, `INTEGRITY`, `ZIP_READER`, `TAR_READER`, `SEVENZ_READER`), and `Violation::sub_code()` SHALL be a `SecurityViolationSubCode` (`PATH_NAME`, `PATH_DEPTH`, `LINK_TARGET`, `LINK_POLICY`, `EXISTING_SYMLINK`, `ENTRY_TYPE`, `ROOT_ENTRY`, `ENCRYPTED`, `COMPRESSION_METHOD`, `SOLID_ARCHIVE`, `DECLARED_SIZE`, `CONCURRENT_CHANGE`, `TAR_METADATA`, `TAR_TRAILER`, `PLATFORM`, `OUTPUT_CONFLICT`, `SOURCE_PATH`); `ArchiveError::sub_code()` SHALL return the `SubCode` tagging the class, or `None`, `ArchiveError::ffi_kind()` SHALL be public and `FfiKind::{InvalidArchive, SecurityViolation}` SHALL carry the sub-code; `QuotaKind`, `SubCode` and `FfiKind::{relaxable_by, sub_code}` drive the error mapping of Python, Node and the CLI, with drift tests (v0.8.0, #865, #872, #877, #887, #888, #894); `FfiKind::QuotaExceeded { kind }` and `FfiKind::ZipBomb { scope }` SHALL carry the real `QuotaKind` or `ZipBombScope`, and `SubCode::{Quota, ZipBomb}` SHALL expose the stable literals `FILE_COUNT` ... `SOLID_BLOCK_MEMORY` (quota) and `ENTRY`, `SOLID_BLOCK`, `SKIPPED_ENTRIES` (zip bomb), unique within each set (#918) | must |
| FR-031 | WHEN extraction writes, renames, unlinks or creates a symlink below the destination, THE SYSTEM SHALL do so relative to a pinned directory descriptor (`VettedDir`, `formats/pinned_dir.rs`; a directory handle opened with `NtCreateFile` on Windows) obtained from `PinnedRoot` or the `DirWalker`, never by re-resolving a path vetted earlier, so swapping a vetted component for a symlink between check and use cannot redirect the operation; a target other than Unix, WASI or Windows SHALL NOT compile, a Windows destination that is itself a reparse point SHALL be refused, and the pinned root SHALL be lent to top-level entries instead of being reopened per entry; small-file extraction SHALL NOT resolve every parent with `realpath` on Unix and WASI (v0.8.0, #836, #842, #846, #848, #865) | must |
| FR-032 | WHEN a hardlink entry is extracted, THE SYSTEM SHALL refuse a target that is not a regular file as `InvalidArchive` (`Malformation::HardlinkTargetNotRegular`), refuse a target whose size changes during the copy as `SecurityViolation` (`Violation::HardlinkTargetChanged`, sub-code `CONCURRENT_CHANGE`), copy without `copy_file_range`, and give the copy the sanitized mode of its target, so a pre-existing setuid, setgid or world-writable target never yields a wider copy; a file created with a mode SHALL be created owner-only and then set to the exact mode (v0.8.0, #842) | must |
| FR-033 | WHEN path containment is compared on macOS, THE SYSTEM SHALL compare case-sensitively, so a planted symlink to a case-variant sibling of the destination is refused; an entry below a planted symlink that leaves the destination SHALL fail with `SymlinkEscape` as `verify` reports it, and a pre-existing dangling or file-pointing symlink in the destination SHALL be refused as not relaxable instead of suggesting `--allow-symlinks` (v0.8.0, #835, #846) | must |
| FR-034 | WHEN `extract` or `verify` refuses an entry below a file, a dangling symlink or a looping symlink, THE SYSTEM SHALL name the entry and the blocking file or symlink with the same category in both; in the bindings an entry below a dangling or looping symlink SHALL raise `SecurityViolation`, and below a contained non-directory link `SecurityViolation` instead of `SymlinkEscape` (v0.8.0, #828) | must |
| FR-035 | WHEN a landing through an archive symlink or an entry name exceeds the host path or name limit, THE SYSTEM SHALL refuse it on every platform before creating any directory below the link, and `extract` SHALL refuse an entry name above the host limit as `list` and `verify` do (v0.8.0, #864, #885, #894) | must |
| FR-036 | THE SYSTEM SHALL build every sink and verify landing as a `SafePath` from normalized components (`SafePath::join_component`, crate-private) and SHALL project a landing through in-archive links with one function, `VirtualTree::project_landing` (`LandingLimits::{Enforced, Exempt}`), whose projected-length rule is the shared `projected_landing_within_limits` also used by the directory walker; `verify`, `extract` and the sinks SHALL give the same verdict for an entry whose landing through a symlink exceeds the host name limit (an entry of 1022 bytes passes, 1023 is refused in all three), and a regular file whose extension is skipped by the allowlist stays exempt; a placed path is not re-checked against `max_path_depth` (#903, #945) | must |
| FR-037 | `SafePath::new_unchecked` SHALL be private to `safe_path.rs`; `SafePath::from_normalized` SHALL accept only normalized `Normal` components (an empty path only for the root entry) | must |
| FR-038 | `EntrySink::create_file` and `create_file_from` SHALL take `size: AdmittedSize` (a `Copy` view of the `QuotaPermit` bytes, built only by `QuotaPermit::into_admitted`) and `create_symlink` SHALL take `CheckedLinkTarget<'_>` (built only from a `SafeSymlink`), so a sink cannot receive a size or a link target that did not pass the gates; trybuild fixtures pin that neither can be forged (#909) | must |
| FR-039 | `EntryValidator`, `ValidatedEntry`, `ValidatedEntryType`, `ValidationReport` and `validate_entry_in` SHALL NOT exist; `types::EntryType` is crate-private; the pipeline is `ValidatorCore` handing out `ValidatedFile`, `ValidatedSymlink` and `ValidatedHardlink`, and the entry-validator tests and benches drive whole archives (`tests/security/entry_pipeline.rs`, `entry_pipeline/*` benches) (#900) | must |
| FR-040 | `BoundaryPath::parse(String)` SHALL replace `validate_raw_path_str` as the one boundary check of a path string from a binding (NUL byte, length) and hold the owned validated string (`as_str`, `into_string`, `AsRef<Path>`) (#927) | must |
| FR-041 | `ArchiveError::PartialExtraction(Partial)` SHALL wrap a `Partial` with private fields (`cause()`, `report()`, `writes()`, `into_parts()`); `Partial::new` SHALL flatten one nesting level with the rule: the innermost cause is kept, the outer report wins (it is a superset), and the more severe `writes` wins (`RolledBack` or `Discarded` over `Kept`); `Display` and `source()` forward to the cause (#907) | must |
| FR-042 | `CallbackError<E>` SHALL be exhaustive (closed by design) and `IntegrityCheck::budget()` SHALL be an exhaustive accessor, so bindings need no wildcard arm (#922) | must |
| FR-043 | THE SYSTEM SHALL check a 7z solid block against `SolidLimits::max_block_memory` per block (see [[003-config-api/spec]] FR-052); the evidence that a declared per-block sum bounds decoder output is that `admit_sevenz_block` refuses a block unless the sum of its files' declared sizes equals the block's unpack size (`BlockSizeUnaccounted`) and decoding is bounded by `take(file.size)` or `CrcChecked(unpack_size)` (#911, #896) | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Security | All security checks run before any bytes are written to disk for each entry |
| NFR-002 | Security | Path component matching is case-insensitive and component-wise (not a raw string-prefix comparison) to prevent bypass on case-insensitive filesystems (GHSA-wcmx-7f9h-5mv5) |
| NFR-003 | Security | Default limits: 50 MB per file, 500 MB total, 100× compression ratio (1000× per 7z solid block), 10,000 files, depth 32, 256 MiB decoder memory |
| NFR-004 | Security | Default banned components: `.git`, `.ssh`, `.gnupg`, `.aws`, `.kube`, `.docker`, `.env` |
| NFR-005 | Safety | `deny(unsafe_code)` workspace-wide — no exceptions in this module |
| NFR-006 | Performance | `canonicalize()` is NOT called per-entry for path traversal; `PathBuf::components()` used instead |
| NFR-007 | Performance | `DirWalker` creates and `lstat`-checks every directory component of an entry, and path validation skips the parent `canonicalize()` when the parent is the destination root |
| NFR-008 | Reliability | Quota tracking (`QuotaTracker`) is not reversible — once exceeded, extraction halts |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `SafePath` | Newtype for a validated archive entry path; can only be constructed after all traversal, depth, and component checks pass | Wraps `PathBuf`; invariant: no traversal, within dest, depth within limit |
| `SafeSymlink` | Newtype for a symlink target confirmed to resolve within `output_dir` | `link()`, `target_path()`; sealed constructor |
| `ValidatedFile` / `ValidatedSymlink` / `ValidatedHardlink` | Typed proofs, one per entry kind, handed out only by `ValidatorCore` (`security::admitted`); they replace the removed `ValidatedEntry` and `ValidatedEntryType` (#900) | `ValidatedFile { path, permit, mode }`; `ValidatedSymlink` exposes `checked_target() -> CheckedLinkTarget`; `ValidatedHardlink { target, counted }` |
| `AdmittedSize` | `Copy` view of the bytes a `QuotaPermit` admitted; passed to `EntrySink::create_file*` (#909) | `get()`; built only by `QuotaPermit::into_admitted` |
| `CheckedLinkTarget<'a>` | Link target that passed `SafeSymlink` validation; passed to `EntrySink::create_symlink` (#909) | `as_path()`; built only by `SafeSymlink::checked_target` |
| `ValidatorCore` | Crate-private stateful orchestrator running all security checks in order per entry; the public `EntryValidator` wrapper was removed (#900) | Holds `QuotaTracker`, `HardlinkTracker`, `symlink_seen` flag, `&SecurityConfig`; takes the root and `FsView` per call (`HostFs` for the disk, `VirtualTree` for verification and sinks); exposes `validate_file_in`/`validate_directory_in`/`validate_symlink_in`/`validate_hardlink_in` returning typed proofs, and keeps `validate_entry_path_in` + `reserve_file` split for 7z's duplicate check |
| `VirtualTree::project_landing` | The one projection of an entry's landing through in-archive links, with the projected length check (#903, #945) | `project_landing(&SafePath, Node, LandingLimits) -> Result<SafePath, PlaceError>` |
| `BoundaryPath` | Owned, validated path string from a binding (#927) | `parse(String)`, `as_str`, `into_string`, `AsRef<Path>` |
| `PolicySetting` | `#[non_exhaustive]` enum naming the `SecurityConfig` setting whose current value refused an entry | `as_str()` identifier (`symlinks`, `hardlinks`, `solid_archives`, `banned_components`, `max_path_depth`, `windows_reserved_names`, `max_tar_metadata_bytes`); `PolicySetting::ALL` |
| `ZipBombDetails` | Payload of `ArchiveError::ZipBomb`: scope and compressed/uncompressed sizes | `scope()` is `ZipBombScope::{Entry, SolidBlock, SkippedEntries}`; `ratio()` derives a `CompressionRatio::{Finite, Unbounded}` so the ratio cannot contradict the sizes |
| `QuotaTracker` | Accumulates entry count (files, symlinks, hardlinks) and total bytes; rejects on limit exceeded | `reserve()` (renamed from `record_file()` in v0.6.0) produces `QuotaPermit`; crate-private `reserve_count()` produces `EntryCount` and `charge()` spends it |
| `QuotaPermit` | Capability token proving a file's size was reserved against a `QuotaTracker`; carries the reserved `bytes: Uncompressed`, non-`Clone`/non-`Copy` (v0.6.0, see [[013-quota-permit-capability-token/spec]]) | Private `bytes` field; produced by `QuotaTracker::reserve` and `charge`; consumed by value via crate-private `into_bytes(self)`, which yields the write ceiling |
| `EntryCount` | Capability token proving a hardlink was counted against `max_file_count` in the first pass; zero-sized, non-`Clone`/non-`Copy` | only producer is `QuotaTracker::reserve_count`; spent by `ValidatorCore::charge_hardlink` in the second pass (see [[013-quota-permit-capability-token/spec]]) |
| `HardlinkTracker` | Validates hardlink targets and records each resolved target | `seen_targets: HashMap<PathBuf, PathBuf>` (resolved target to first link); `validate_hardlink` resolves the target through on-disk symlinks |
| `DestDir` | Canonicalized output directory; used as the trust boundary for symlink/hardlink validation | Wraps `PathBuf`; a symlinked destination *root* is accepted and resolved via `canonicalize()` (matching `tar -C`/`unzip -d`), unaffected by the `--atomic --force` CLI hardening in [[015-atomic-force-destination-swap-hardening/spec]], which is scoped to that one CLI code path |

> [!note] v0.4.1 API changes
> `sanitize_permissions` return type changed from `Result<u32>` to `u32` — the function
> never fails; callers no longer need `?` or `.unwrap()`.
> The `_path: &Path` parameter previously accepted by `sanitize_permissions` has been
> removed; call sites must omit that argument.
> All security primitives (`validate_path`, `validate_symlink`, `sanitize_permissions`,
> `validate_compression_ratio`, `QuotaTracker`, `HardlinkTracker`) are now `pub(crate)`;
> external benchmarks or integration tests that reference them directly must add
> `--features testing`.

> [!note] v0.5.0: centralized absolute-path stripping
> Absolute entry paths and Windows drive/UNC paths (e.g. `C:\...`, `\\server\share\...`) are
> now stripped centrally inside `SafePath::validate_with_context` when `allow_absolute_paths`
> is enabled. The per-format pre-stripping workarounds that previously existed in `tar.rs`,
> `zip.rs`, and `sevenz.rs` have been removed. Bare-slash entries (`/`) now return
> `PathTraversalError` instead of `io::Error`.

> [!note] v0.5.1: caller contract — entry names must be normalized before validation
> `SafePath::validate` now documents an explicit caller contract: raw archive entry names
> MUST have `\` normalized to `/` before `PathBuf` construction and before being passed to
> `SafePath::validate`. `SafePath` itself does not perform this normalization. The 7z handler
> is the current caller of concern — on Unix, `PathBuf::from("..\\..\\x")` collapses to a
> single path component, silently bypassing traversal detection (#365, #376). The shared
> `formats::common::normalize_entry_name` helper is the single normalization point; it is
> applied by the 7z handler in the pre-validation loop, the extraction callback, and the
> list/verify path (see [[002-format-handlers/spec]] for the format-level fix). ZIP is
> unaffected (exarch's own entry-name splitter handles Windows-style paths);
> TAR is intentionally left un-normalized because `\` is a legal Unix filename character in
> TAR archives.

> [!note] v0.5.1: `EntryValidator` restored as sole guard for 7z path security
> `sevenz-rust2` 0.21.1 added an internal path-safety check inside
> `decompress_with_extract_fn` that silently rejected absolute-path entries before
> `EntryValidator` ever ran, breaking `allowed.absolute_paths = true` for 7z archives
> (#374). The 7z handler now drives extraction via `ArchiveReader::for_each_entries`, which
> has no built-in path check, so `EntryValidator` is once again the sole and authoritative
> guard for 7z traversal, absolute-path, and symlink checks (#375). No change to
> `EntryValidator` or `SafePath` themselves was required — the fix is entirely in how the 7z
> handler drives the upstream crate.

> [!note] v0.6.0: ZIP decompression-bomb bypass closed (GHSA-5j8q-wxg5-hj4r, #517)
> ZIP extraction trusted the archive-declared `uncompressed_size` for both zip-bomb ratio
> detection and quota reservation but never verified it against what decompression actually
> produced. `formats::copy::copy_with_buffer` now takes the declared size as an `expected_size`
> parameter and enforces it as a hard streaming ceiling, checked after every buffered read —
> aborting with `SecurityViolation` (not `QuotaExceeded`, since `expected_size` is the archive's
> own possibly-forged size, not `config.max_file_size`) the instant actual bytes exceed it, and
> rejecting a short stream once EOF is reached. `extract_file_with_permit` (shared by TAR and
> ZIP) wraps the write in a `TempFileGuard` so an aborted copy removes the file it created. 7z's
> two write paths now route through the same function with `entry.size` as the declared size.
> TAR and 7z already cap reader bytes to the declared size upstream, so for those formats this
> is defense-in-depth; for ZIP it closes a live vulnerability.

> [!note] v0.6.0: dangling-symlink-at-destination write-through closed (#459, #471, #467)
> The duplicate-existence check used `Path::exists()`, which follows symlinks and returns `false`
> for a dangling one — so a symlink already present at the destination (planted by something
> other than the archive itself) was treated as "no duplicate," and a plain `File::create`
> followed the link outside the extraction root. Fixed by opening the destination with `O_EXCL`
> and, on Unix, `O_NOFOLLOW`, closing the escape for both `skip_duplicates` values across TAR/ZIP's
> shared write path, 7z's temp-file-then-rename path (predictable PID-based temp names replaced
> with `create_new` + retry), and TAR's hardlink copy path (`common::open_no_follow`). Precondition
> is an attacker-writable destination directory, not a malicious archive alone.

> [!note] v0.6.0: symlink/hardlink target NUL-byte and emptiness validation (#415, #491)
> `SafeSymlink::validate` and `HardlinkTracker::validate_hardlink` now reject a null byte or empty
> value in the *target* (linkname), matching the checks already applied to the link path itself.
> Separately, `SafeSymlink::validate` gained the same explicit Windows drive/UNC-prefix and
> root-relative rejection `SafeHardlink`/`SafePath` already had — a drive-relative target like
> `C:foo` or a root-relative target like `\evil` is not `is_absolute()` per Rust's definition but
> still resolves relative to the current directory/drive (a GHSA-9ppj-qmqm-q256-class bypass).

> [!note] v0.6.0: TAR metadata-record decompression bomb bounded (#414, #422)
> GNU long-name/long-link and PAX extended-header records are buffered fully in memory by the
> `tar` crate before any entry reaches this pipeline's validator or quota tracker. `SecurityConfig`
> gained `max_tar_metadata_bytes` (default 4 MiB) enforced by `formats::tar_metadata_limit`, a
> reader-wrapper that meters bytes read while searching for the next entry and errors before an
> oversized allocation completes — applied uniformly to `extract_archive`, `list_archive`, and
> `verify_archive`. A second, cumulative 1 GiB budget on *synthesized* (unread, zero-padded GNU
> sparse) bytes bounds the CPU cost of draining many skipped entries, without capping any
> legitimate entry's real content — see `formats::tar_metadata_limit::BudgetedReader` for the
> synthetic-vs-real byte accounting that makes this direction-independent.

> [!note] v0.6.1: sibling-directory containment bypass closed on macOS/Windows (GHSA-wcmx-7f9h-5mv5, #543)
> `paths_start_with` — used by `SafePath`'s macOS/Windows containment check — compared `path`/`base`
> as raw lowercased strings, so `/tmp/destevil` was wrongly treated as contained within `/tmp/dest`
> (`"...destevil".starts_with("...dest")` is true, since there is no component boundary between
> `dest` and `evil`). The non-macOS Unix arm was unaffected — it already used `Path::starts_with`,
> which is component-aware. Fixed by comparing `Path::components()` pairwise, case-folding each
> segment, matching the same semantics as the Unix arm. Covered by unit tests (sibling rejection,
> genuine-subdirectory acceptance, case-insensitivity, base-longer-than-path short-circuit) plus an
> end-to-end regression test driving the attack through a real on-disk symlink.

> [!note] v0.6.1: `SanitizedMode` newtype and `#[non_exhaustive]` enum hardening (#554)
> `sanitize_permissions` now returns `SanitizedMode` (`security::SanitizedMode`) instead of a plain
> `u32`; `ValidatedEntry::mode()`, `EntryValidator::validate_entry()`'s sanitized output, and
> `formats::common::create_file_with_mode`/`extract_file_with_permit` take `Option<SanitizedMode>`
> instead of `Option<u32>`, so an unsanitized mode read from an archive header can no longer reach
> permission-setting code by mistake — the invariant is enforced at compile time, matching the
> `SafePath`/`QuotaPermit` sealed-type pattern. Full detail, including the six enums newly marked
> `#[non_exhaustive]` (`ArchiveError`, `QuotaResource`, and others outside this pipeline), is tracked
> in [[016-sanitized-mode-and-non-exhaustive-enums/spec]].

> [!note] v0.7.0: typed `SecurityViolation`, link and root rules, counted links (#653, #714, #719, #723, #724, #741, #757)
> `ArchiveError::SecurityViolation` gained `relaxable_by: Option<PolicySetting>` and is
> `#[non_exhaustive]`: carries a typed `Violation` kind (`From<Violation> for ArchiveError`), read the
> kind with `ArchiveError::security_violation()` and the setting with `ArchiveError::relaxable_by()` (see FR-020). A symlink or hardlink without
> `allowed.symlinks`/`hardlinks`, a banned component and an excessive depth are `SecurityViolation`
> naming the setting that admits the entry (earlier spec text described them as skipped or
> `PathTraversal`, which the code did not do). `ArchiveError::ZipBomb` wraps `ZipBombDetails` (scope `Entry`, `SolidBlock` or `SkippedEntries`, derived
> `CompressionRatio`), and `QuotaResource` gained `DecoderMemory` (`SecurityConfig::max_decoder_memory`,
> default 256 MiB). `max_file_count` now counts symlinks and hardlinks in `extract`; a hardlink carries an
> `EntryCount` from the first pass. Link targets are resolved through on-disk symlinks and a `..` may only
> leave an existing directory or one of the link's own parent components, so a target cannot reach a
> directory the archive creates later; targets with unresolvable `..` are rejected in all formats. On
> Windows, components with `:` or a trailing dot or space are rejected for paths and link targets, and
> reserved device names are rejected unless `AllowedFeatures::windows_reserved_names` is set. `verify`
> validates against an in-memory model of the extracted tree (`security::fs_view`) instead of the host
> filesystem, and listing for `verify` carries its mode as a `ListPass` type instead of a
> `SecurityConfig` flag.

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Path traversal `../` or absolute path | `ArchiveError::PathTraversal` |
| Null byte in path | `ArchiveError::SecurityViolation` |
| Empty entry name | `ArchiveError::SecurityViolation` |
| Banned component (e.g. `.git`) in path | `ArchiveError::SecurityViolation`, `relaxable_by() == Some(PolicySetting::BannedComponents)` |
| Path depth > `max_path_depth` | `ArchiveError::SecurityViolation`, `relaxable_by() == Some(PolicySetting::MaxPathDepth)` |
| Root entry (`.`) that is not a directory | `ArchiveError::SecurityViolation` (no setting relaxes it) |
| Windows only: component with `:` or a trailing `.`/space | `ArchiveError::SecurityViolation` (never relaxable) |
| Windows host, or `PathModel::Portable` on any host: component with `<>"\|?*`, a control character or non-Unicode text | `ArchiveError::SecurityViolation` (never relaxable); CLI JSON `error.kind` is `SecurityViolation`, previously `IoError` on Windows (v0.8.0, FR-024) |
| Directory entry over a file or a symlink | Refused with an entry-naming message, identical in `extract` and `verify` (v0.8.0, FR-026) |
| ZIP reader failure (archive or entry unreadable, census disagrees with reader) | `ArchiveError::InvalidArchive` with sub-code `ZIP_READER`, message unchanged (FR-028) |
| Landing through an archive symlink longer than the relative limit | Refused by relative length on every platform; a directory entry exactly at the limit is accepted (FR-029) |
| In-memory model exceeds its node budget | `ArchiveError::QuotaExceeded { resource: TreeNodes { max } }` (v0.8.0, FR-027) |
| Windows only: reserved device name (`CON`, `NUL.txt`) | `ArchiveError::SecurityViolation`, `relaxable_by() == Some(PolicySetting::WindowsReservedNames)` |
| File exceeds `max_file_size` | `ArchiveError::QuotaExceeded { resource: FileSize { .. } }` |
| Total size exceeds `max_total_size` | `ArchiveError::QuotaExceeded { resource: TotalSize { .. } }` |
| Files, symlinks and hardlinks exceed `max_file_count` | `ArchiveError::QuotaExceeded { resource: FileCount { .. } }` |
| Decoder memory exceeds `max_decoder_memory` | `ArchiveError::QuotaExceeded { resource: DecoderMemory { max } }` |
| Compression ratio > `max_compression_ratio` | `ArchiveError::ZipBomb` with `ZipBombScope::Entry` (before any bytes written) |
| 7z solid block ratio > `max_solid_compression_ratio` | `ArchiveError::ZipBomb` with `ZipBombScope::SolidBlock` |
| Data claimed from zero compressed bytes | `ArchiveError::ZipBomb` with an `Unbounded` ratio |
| Compression ratio not available (TAR streams) | Zip bomb check skipped for that entry; quota still enforced |
| ZIP entry's real decompressed byte count exceeds its declared `uncompressed_size` | `ArchiveError::SecurityViolation` the instant the ceiling is exceeded, not just at EOF (GHSA-5j8q-wxg5-hj4r) |
| Symlink with `allowed.symlinks = false` | `ArchiveError::SecurityViolation`, `relaxable_by() == Some(PolicySetting::Symlinks)` |
| Symlink pointing outside `output_dir` | `ArchiveError::SymlinkEscape` |
| Link target whose `..` leaves a directory that does not exist yet and is not in the link's own parent chain | `ArchiveError::SymlinkEscape` (`HardlinkEscape` for a hardlink) |
| Symlink or hardlink target is empty or contains a null byte | `ArchiveError::SecurityViolation` (raw target bytes never embedded in the error message) |
| Dangling symlink pre-planted at an entry's destination path | Rejected via `O_EXCL`/`O_NOFOLLOW` open, not silently followed; requires an attacker-writable destination directory |
| On macOS/Windows, a validated entry's canonicalized path resolves (e.g. via a symlink) into a sibling directory sharing the destination root's name as a string prefix (e.g. `/tmp/destevil` vs. `/tmp/dest`) | Rejected — `paths_start_with` compares `Path::components()` pairwise, not raw lowercased strings (GHSA-wcmx-7f9h-5mv5, v0.6.1) |
| Hardlink with `allowed.hardlinks = false` | `ArchiveError::SecurityViolation`, `relaxable_by() == Some(PolicySetting::Hardlinks)` |
| Hardlink target resolving outside `output_dir` | `ArchiveError::HardlinkEscape` |
| Hardlink target absent when the link is created | `ArchiveError::InvalidArchive` |
| setuid/setgid bits on Unix | Stripped silently via `fchmod` on the open descriptor; the mode in `ValidatedFile` is the sanitized value |
| A zero `max_file_size`, `max_total_size`, `max_path_depth`, `max_file_count`, solid block memory, `max_tar_metadata_bytes`, or `max_decoder_memory` | Unrepresentable; the boundary conversion returns `InvalidConfiguration` (see [[003-config-api/spec]]) |
| A `max_compression_ratio` or solid ratio of 0.0, negative, or non-finite | `RatioLimit::parse` returns `InvalidConfiguration` |
| A verify landing through a symlink whose projected length is one byte over the host name limit | `verify`, `extract` and the sinks all refuse it (#945) |
| A symlink among the destination's parent components whose absolute target is spelled through a bind mount or another alias of the destination | Refused, fail-closed (#895) |
| A 7z solid block above `max_block_memory`, including a single-file block | `QuotaExceeded { SolidBlockMemory }` (#911) |
| A malformed `allowed_extensions`/`banned_path_components` entry is supplied (empty, contains a null byte, or exceeds 255 bytes) | `InvalidConfiguration`, raised by `Extension::try_from` / `PathComponentName::try_from` before the entry can be stored (v0.6.0, #449; v0.8.0) — see [[003-config-api/spec]] |
| A file entry is validated but its `QuotaPermit` is never consumed at a write site | Does not compile — `ValidatedFile` carries the token and `EntrySink::create_file` needs the `AdmittedSize` derived from it (v0.6.0, #909, see [[013-quota-permit-capability-token/spec]]) |

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
- Modifying the `ValidatedFile`/`ValidatedSymlink`/`ValidatedHardlink` proofs or `ValidatorCore` (breaking API change)
- Enabling any `AllowedFeatures` flag by default
- Raising or removing any quota default

### Never
- Remove existing security checks or lower default quota limits without a security review
- Add `#[allow(unsafe_code)]` in any security module
- Call `canonicalize()` inside the hot per-entry validation path
- Allow `ArchiveError` variants to be constructed outside `exarch-core`

## 9. Open Questions

- [NEEDS CLARIFICATION: Should `ProgressCallback` expose a cancellation mechanism (return bool) so callers can abort mid-stream from the security callback?]
- [NEEDS CLARIFICATION: Windows path separator handling (`\` vs `/`) — is there a CI job covering Windows path validation edge cases?]

> [!note] Partially addressed in v0.5.1
> The specific Unix-side bypass — a 7z entry name containing `\` collapsing into a single
> `PathBuf` component and evading traversal detection — is fixed via
> `formats::common::normalize_entry_name` (#365, #376; see the caller-contract note above).
> The broader question of dedicated Windows CI coverage for path validation edge cases
> remains open; `.claude/rules/continuous-improvement.md` flags this as a known gap to test
> before merging any path-related change.

> [!note] Resolved in v0.4.0
> World-writable entries: behavior clarified — the `allow_world_writable` bit is stripped (not rejection), matching setuid/setgid treatment. `allowed_extensions` filtering (FR-011) is now fully implemented across TAR, ZIP, and 7z in v0.4.0 (#230, #242). `SecurityConfig::validate()` now also rejects `max_file_count == 0` and `max_solid_block_memory == 0` in addition to the previously documented zero-limit fields (#181).

## 10. See Also

- [[constitution]] — project principles (security section)
- [[MOC-specs]] — all specifications
- [[002-format-handlers/spec]] — format handlers that route entries through this pipeline
- [[003-config-api/spec]] — `SecurityConfig`, `AllowedFeatures` configuration types
- [[013-quota-permit-capability-token/spec]] — `QuotaPermit` capability-token pattern in detail
- [[014-config-typestate-validation/spec]] — obsolete: the removed `Unvalidated`/`Validated` typestate
- [[015-atomic-force-destination-swap-hardening/spec]] — CLI-side `--atomic --force` symlink/TOCTOU hardening (GHSA-x8wr-7ww2-c94x)
- [[016-sanitized-mode-and-non-exhaustive-enums/spec]] — `SanitizedMode` capability-token newtype and `#[non_exhaustive]` enum hardening
- [[017-zip-header-consistency/spec]] — `ZipConsistencyPolicy` and ZIP structure checks
- [[020-reader-sink-and-in-memory-api/spec]] — `PathModel`, sink and in-memory destination model
- [[001-exarch-system/spec]] — original monolithic spec (archived)
- `crates/exarch-core/src/types/safe_path.rs` — `paths_start_with`
- Advisory GHSA-wcmx-7f9h-5mv5 — the macOS/Windows sibling-directory containment bypass fixed here
