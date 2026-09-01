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
updated: 2026-09-02
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[002-format-handlers/spec]]"
  - "[[003-config-api/spec]]"
  - "[[013-quota-permit-capability-token/spec]]"
  - "[[014-config-typestate-validation/spec]]"
  - "[[016-sanitized-mode-and-non-exhaustive-enums/spec]]"
---

# Feature: Security Pipeline

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
THEN extraction fails with ArchiveError::PathTraversal (banned component)
```

### US-002: Zip Bomb Detection

AS A security engineer
I WANT archives with extreme compression ratios to be rejected
SO THAT a malicious archive cannot exhaust disk space or memory

**Acceptance criteria:**
```
GIVEN an archive entry where uncompressed_size / compressed_size > max_compression_ratio
WHEN the entry is validated
THEN the entry is rejected with ArchiveError::ZipBomb before any bytes are written
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
THEN extraction fails with ArchiveError::SymlinkEscape
```

### US-004: Quota Enforcement

AS A server operator
I WANT per-file and total-size limits enforced during extraction
SO THAT a single archive cannot exhaust disk space

**Acceptance criteria:**
```
GIVEN a file entry whose uncompressed size exceeds max_file_size
WHEN the entry is validated
THEN extraction fails with ArchiveError::QuotaExceeded { resource: FileSizeBytes }
```

```
GIVEN cumulative uncompressed size across entries exceeds max_total_size
WHEN the next entry is validated
THEN extraction fails with ArchiveError::QuotaExceeded { resource: TotalSizeBytes }
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
| FR-009 | WHEN extracting files on Unix, THE SYSTEM SHALL strip setuid (0o4000) and setgid (0o2000) bits from all file permissions, and apply the sanitized mode via `fchmod` on the already-open file descriptor (`File::set_permissions`), never via a path-based `set_permissions()` call after `open()` | must |
| FR-010 | WHEN the path depth of an entry exceeds `max_path_depth`, THE SYSTEM SHALL reject the entry with `ArchiveError::PathTraversal` | must |
| FR-011 | WHEN `allowed_extensions` is non-empty and an entry's extension is not in the list, THE SYSTEM SHALL skip the entry and increment a `disallowed_extension_skips` counter, aggregated into at most one summary warning per extraction | must |
| FR-012 | WHEN the file count across all entries exceeds `max_file_count`, THE SYSTEM SHALL reject further entries with `QuotaExceeded { resource: FileCount }` | must |
| FR-013 | WHEN `allowed.world_writable` is false and a file entry has world-writable permissions (`mode & 0o002 != 0`), THE SYSTEM SHALL strip that bit or reject the entry | must |
| FR-014 | WHEN copying an entry's decompressed bytes to disk, THE SYSTEM SHALL enforce the entry's declared size as a hard streaming ceiling — checked after every buffered read, not only at EOF — aborting with `ArchiveError::SecurityViolation` the instant actual bytes exceed the declared size, and rejecting a short stream (fewer bytes than declared) once EOF is reached, closing GHSA-5j8q-wxg5-hj4r (a ZIP entry whose real DEFLATE stream inflates far beyond its declared `uncompressed_size`) | must |
| FR-015 | WHEN a symlink or hardlink target is validated, THE SYSTEM SHALL reject an empty target or one containing a null byte, in addition to the existing containment checks on the target path itself | must |
| FR-016 | WHEN opening a destination path for a file, symlink-target read, or 7z temp-file write, THE SYSTEM SHALL use `O_EXCL`/`O_NOFOLLOW` (Unix) or an equivalent atomic create-exclusive open rather than a prior `Path::exists()` check, since `exists()` follows symlinks and reports `false` for a dangling one — letting a pre-planted symlink at the destination bypass duplicate detection and redirect the write outside the extraction root | must |
| FR-017 | WHEN a file entry is validated, THE SYSTEM SHALL produce a `QuotaPermit` capability token from `QuotaTracker::reserve` that the eventual write path must consume by value, so a validated `File` entry with no quota charge is unrepresentable and a reservation cannot be spent twice (see [[013-quota-permit-capability-token/spec]]) | must |
| FR-018 | WHEN `SecurityConfig`/`CreationConfig` builder methods are used, THE SYSTEM SHALL make them available only on the `Unvalidated` typestate, and `validate()` SHALL consume `self` and return `Result<T<Validated>>`; every downstream security function SHALL require `&SecurityConfig<Validated>` (see [[014-config-typestate-validation/spec]]) | must |
| FR-019 | WHEN comparing a validated entry's canonicalized parent path against the destination root on macOS/Windows, THE SYSTEM SHALL compare `Path::components()` pairwise (case-folding each segment) rather than the raw lowercased path strings, so a sibling directory sharing the destination root's name as a string prefix (e.g. `/tmp/destevil` vs. `/tmp/dest`) is not treated as contained within it, closing GHSA-wcmx-7f9h-5mv5 | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Security | All security checks run before any bytes are written to disk for each entry |
| NFR-002 | Security | Path component matching is case-insensitive and component-wise (not a raw string-prefix comparison) to prevent bypass on case-insensitive filesystems (GHSA-wcmx-7f9h-5mv5) |
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
| `ValidatedEntry` | Archive entry that has passed the full security pipeline; sealed (private fields, `pub(crate)` constructor) since v0.6.0 | `safe_path()`, `entry_type()`, `mode()`, `into_parts()` accessors — no direct field access from outside `exarch-core` |
| `ValidatedEntryType` | `#[non_exhaustive]` enum of post-validation entry classifications | `File(QuotaPermit)` (carries a capability token since v0.6.0), `Directory`, `Symlink(SafeSymlink)`, `Hardlink { target: SafePath }` |
| `EntryValidator` | Stateful orchestrator running all security checks in order per entry | Holds `QuotaTracker`, `HardlinkTracker`, `symlink_seen` flag; references `SecurityConfig<Validated>` and `DestDir`; `validate_entry_path` splits path validation from quota reservation for callers needing the destination path before deciding whether to charge quota (7z's duplicate check) |
| `QuotaTracker` | Accumulates file count and total bytes; rejects on limit exceeded | `file_count`, `total_bytes`; `reserve()` (renamed from `record_file()` in v0.6.0) is the sole producer of `QuotaPermit` |
| `QuotaPermit` | Capability token proving a file's size was reserved against a `QuotaTracker`; zero-sized, non-`Clone`/non-`Copy` (v0.6.0, see [[013-quota-permit-capability-token/spec]]) | `PhantomData`-based; only producer is `QuotaTracker::reserve`; consumed by value at the eventual write site |
| `HardlinkTracker` | Records all file paths seen in this archive to validate hardlink targets | `seen: HashSet<PathBuf>`; `reserve_hardlink` (renamed from `record_hardlink` in v0.6.0) returns a `QuotaPermit` |
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
> unaffected (the `zip` crate handles Windows-style paths internally via `enclosed_name`);
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

> [!note] v0.6.0 (unreleased): ZIP decompression-bomb bypass closed (GHSA-5j8q-wxg5-hj4r, #517)
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

> [!note] v0.6.0 (unreleased): dangling-symlink-at-destination write-through closed (#459, #471, #467)
> The duplicate-existence check used `Path::exists()`, which follows symlinks and returns `false`
> for a dangling one — so a symlink already present at the destination (planted by something
> other than the archive itself) was treated as "no duplicate," and a plain `File::create`
> followed the link outside the extraction root. Fixed by opening the destination with `O_EXCL`
> and, on Unix, `O_NOFOLLOW`, closing the escape for both `skip_duplicates` values across TAR/ZIP's
> shared write path, 7z's temp-file-then-rename path (predictable PID-based temp names replaced
> with `create_new` + retry), and TAR's hardlink copy path (`common::open_no_follow`). Precondition
> is an attacker-writable destination directory, not a malicious archive alone.

> [!note] v0.6.0 (unreleased): symlink/hardlink target NUL-byte and emptiness validation (#415, #491)
> `SafeSymlink::validate` and `HardlinkTracker::validate_hardlink` now reject a null byte or empty
> value in the *target* (linkname), matching the checks already applied to the link path itself.
> Separately, `SafeSymlink::validate` gained the same explicit Windows drive/UNC-prefix and
> root-relative rejection `SafeHardlink`/`SafePath` already had — a drive-relative target like
> `C:foo` or a root-relative target like `\evil` is not `is_absolute()` per Rust's definition but
> still resolves relative to the current directory/drive (a GHSA-9ppj-qmqm-q256-class bypass).

> [!note] v0.6.0 (unreleased): TAR metadata-record decompression bomb bounded (#414, #422)
> GNU long-name/long-link and PAX extended-header records are buffered fully in memory by the
> `tar` crate before any entry reaches this pipeline's validator or quota tracker. `SecurityConfig`
> gained `max_tar_metadata_bytes` (default 4 MiB) enforced by `formats::tar_metadata_limit`, a
> reader-wrapper that meters bytes read while searching for the next entry and errors before an
> oversized allocation completes — applied uniformly to `extract_archive`, `list_archive`, and
> `verify_archive`. A second, cumulative 1 GiB budget on *synthesized* (unread, zero-padded GNU
> sparse) bytes bounds the CPU cost of draining many skipped entries, without capping any
> legitimate entry's real content — see `formats::tar_metadata_limit::BudgetedReader` for the
> synthetic-vs-real byte accounting that makes this direction-independent.

> [!note] (unreleased, post-v0.6.0): sibling-directory containment bypass closed on macOS/Windows (GHSA-wcmx-7f9h-5mv5, #543)
> `paths_start_with` — used by `SafePath`'s macOS/Windows containment check — compared `path`/`base`
> as raw lowercased strings, so `/tmp/destevil` was wrongly treated as contained within `/tmp/dest`
> (`"...destevil".starts_with("...dest")` is true, since there is no component boundary between
> `dest` and `evil`). The non-macOS Unix arm was unaffected — it already used `Path::starts_with`,
> which is component-aware. Fixed by comparing `Path::components()` pairwise, case-folding each
> segment, matching the same semantics as the Unix arm. Covered by unit tests (sibling rejection,
> genuine-subdirectory acceptance, case-insensitivity, base-longer-than-path short-circuit) plus an
> end-to-end regression test driving the attack through a real on-disk symlink.

> [!note] (unreleased, post-v0.6.0): `SanitizedMode` newtype and `#[non_exhaustive]` enum hardening (#554)
> `sanitize_permissions` now returns `SanitizedMode` (`security::SanitizedMode`) instead of a plain
> `u32`; `ValidatedEntry::mode()`, `EntryValidator::validate_entry()`'s sanitized output, and
> `formats::common::create_file_with_mode`/`extract_file_with_permit` take `Option<SanitizedMode>`
> instead of `Option<u32>`, so an unsanitized mode read from an archive header can no longer reach
> permission-setting code by mistake — the invariant is enforced at compile time, matching the
> `SafePath`/`QuotaPermit` sealed-type pattern. Full detail, including the six enums newly marked
> `#[non_exhaustive]` (`ArchiveError`, `QuotaResource`, and others outside this pipeline), is tracked
> in [[016-sanitized-mode-and-non-exhaustive-enums/spec]].

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Path traversal `../` or absolute path | `ArchiveError::PathTraversal` |
| Null byte in path | `ArchiveError::PathTraversal` |
| Banned component (e.g. `.git`) in path | `ArchiveError::PathTraversal` (banned component) |
| Path depth > `max_path_depth` | `ArchiveError::PathTraversal` (depth exceeded) |
| File exceeds `max_file_size` | `ArchiveError::QuotaExceeded { resource: FileSizeBytes }` |
| Total size exceeds `max_total_size` | `ArchiveError::QuotaExceeded { resource: TotalSizeBytes }` |
| File count exceeds `max_file_count` | `ArchiveError::QuotaExceeded { resource: FileCount }` |
| Compression ratio > `max_compression_ratio` | `ArchiveError::ZipBomb` (before any bytes written) |
| Compression ratio not available (TAR streams) | Zip bomb check skipped for that entry; quota still enforced |
| ZIP entry's real decompressed byte count exceeds its declared `uncompressed_size` | `ArchiveError::SecurityViolation` the instant the ceiling is exceeded, not just at EOF (GHSA-5j8q-wxg5-hj4r) |
| Symlink with `allowed.symlinks = false` | Entry skipped (not an error) |
| Symlink pointing outside `output_dir` | `ArchiveError::SymlinkEscape` |
| Symlink or hardlink target is empty or contains a null byte | `ArchiveError::SecurityViolation` (raw target bytes never embedded in the error message) |
| Dangling symlink pre-planted at an entry's destination path | Rejected via `O_EXCL`/`O_NOFOLLOW` open, not silently followed; requires an attacker-writable destination directory |
| On macOS/Windows, a validated entry's canonicalized path resolves (e.g. via a symlink) into a sibling directory sharing the destination root's name as a string prefix (e.g. `/tmp/destevil` vs. `/tmp/dest`) | Rejected — `paths_start_with` compares `Path::components()` pairwise, not raw lowercased strings (GHSA-wcmx-7f9h-5mv5, unreleased) |
| Hardlink with `allowed.hardlinks = false` | Entry skipped |
| Hardlink to a path not previously seen | `ArchiveError::HardlinkEscape` |
| setuid/setgid bits on Unix | Stripped silently via `fchmod` on the open descriptor; `ValidatedEntry.mode()` reflects sanitized value |
| `SecurityConfig` with zero `max_file_size`, `max_total_size`, `max_path_depth`, `max_file_count`, or `max_solid_block_memory` | `SecurityConfig::validate()` returns `InvalidConfiguration` before extraction begins |
| `SecurityConfig` with `max_compression_ratio` of 0.0, negative, or NaN | `SecurityConfig::validate()` returns `InvalidConfiguration` before extraction begins |
| `SecurityConfig::validate()` given a malformed `allowed_extensions`/`banned_path_components` entry (empty, contains a null byte, or exceeds 255 bytes) | `InvalidConfiguration`, via the shared `validate_config_entry` helper (v0.6.0, #449) — see [[003-config-api/spec]] |
| A file entry is validated but its `QuotaPermit` is never consumed at a write site | Does not compile — `ValidatedEntryType::File` requires the token by construction (v0.6.0, see [[013-quota-permit-capability-token/spec]]) |

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
- [[014-config-typestate-validation/spec]] — `SecurityConfig`/`CreationConfig` `Unvalidated`/`Validated` typestate in detail
- [[015-atomic-force-destination-swap-hardening/spec]] — CLI-side `--atomic --force` symlink/TOCTOU hardening (GHSA-x8wr-7ww2-c94x)
- [[016-sanitized-mode-and-non-exhaustive-enums/spec]] — `SanitizedMode` capability-token newtype and `#[non_exhaustive]` enum hardening
- [[001-exarch-system/spec]] — original monolithic spec (archived)
- `crates/exarch-core/src/types/safe_path.rs` — `paths_start_with`
- Advisory GHSA-wcmx-7f9h-5mv5 — the macOS/Windows sibling-directory containment bypass fixed here
