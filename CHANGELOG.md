# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Breaking Changes

- **`ArchiveCreator::compression_level`** now returns `Result<Self, ArchiveError>` instead of
  `Self`. Call sites must propagate the error with `?` or handle it explicitly; passing an
  out-of-range level (0 or >9) now returns `ArchiveError::InvalidCompressionLevel` instead of
  silently clamping or panicking (#308).

### Added

- `extract` command now exposes three previously hidden `SecurityConfig` fields as CLI flags:
  `--max-path-depth <N>` (default 32), `--banned-component <COMPONENT>` (repeatable; replaces
  the default ban list when provided), and `--allow-absolute-paths` (flag). Operators can now
  tune path depth and component ban lists without recompiling (#303).
- `create` CLI subcommand: `--max-file-size <BYTES>` flag (supports K/M/G/T suffixes) skips
  source files larger than the given threshold during archive creation (#306).
- `create` CLI subcommand: `--preserve-permissions` flag (default: true) controls whether
  Unix file permissions are stored in the archive; pass `--preserve-permissions=false` to
  create a portable archive without platform-specific permission bits (#306).
- Python and Node.js bindings now expose `ExtractionOptions` with `skip_duplicates`. Python:
  `ExtractionOptions` class with `with_skip_duplicates(skip=True)` builder. Node.js:
  `ExtractionOptions` class with `withSkipDuplicates(skip?)` builder. Both `extract_archive`
  and `extract_archive_with_progress` accept an optional `options` parameter (#313).

### Tests

- Added integration tests for `ExtractionOptions::skip_duplicates`: covers `skip_duplicates=true` (first entry kept, duplicate skipped with warning) and `skip_duplicates=false` (second entry overwrites first) for TAR archives. Documents that the `zip` crate 8.x deduplicates entries at parse time, making the flag a no-op for ZIP (#302).
- Added 7z integration tests for `skip_duplicates`: `skip_duplicates=true` keeps the first
  entry and records a warning; `skip_duplicates=false` overwrites with the last entry (#314).

### Fixed

- Python: `SecurityConfig` and `CreationConfig` scalar getters (`max_file_size`, `max_total_size`, `max_compression_ratio`, `max_file_count`, `max_path_depth`, `max_solid_block_memory`, `preserve_permissions`, `compression_level`, `follow_symlinks`, `include_hidden`, `exclude_patterns`) now return their values correctly instead of a bound method. Builder methods were renamed to `with_<field>` (e.g. `with_max_file_size(...)`) to eliminate the PyO3 name collision (#315).
- Node.js: `index.d.ts` now declares `setMaxSolidBlockMemory(size: number): this` and `get maxSolidBlockMemory(): number` for `SecurityConfig`; the file is committed to the repository so TypeScript consumers have correct types without building from source (#311).
- Python: `exarch.pyi` now declares `allowed_extensions` and `banned_path_components` as `@property` with setters, replacing bare class-level annotations that did not express read/write semantics (#312).
- `list_archive` now respects `SecurityConfig::allowed.absolute_paths`; absolute paths in TAR
  and 7z archives are accepted during listing when the flag is set (previously silently rejected
  regardless of config) (#318). The `--allow-absolute-paths` CLI flag now consistently applies
  to both the listing and extraction phases.
- `verify --strict` no longer writes an unstructured message to stderr that bypassed `--quiet` suppression and `--json` mode. Exit code 2 already conveys the strict-warning condition (#298).
- `ProgressCallback::on_bytes_written` is now called during extraction for TAR, ZIP, and 7z formats; previously the method was documented but never invoked (#304).
- `ProgressCallback::on_entry_complete` is now guaranteed to be called for every entry for which `on_entry_start` was called, including entries that fail mid-extraction; previously a failure left the callback pair unbalanced (#305).
- 7z extraction with `skip_duplicates=false` now overwrites the existing file instead of
  returning an error. Previously a duplicate entry with `skip_duplicates=false` would fail;
  now it falls through to the atomic temp+rename overwrite path (#314).

## [0.4.1] - 2026-06-05

### Added

- `verify` CLI command now accepts a `--strict` flag. When set, a verification report with
  `Warning` status causes the process to exit with code 2 instead of 0. Without the flag,
  the previous behaviour (exit 0 on warnings) is unchanged (#269).
- `ValidationReport` is now re-exported at the crate root as `exarch_core::ValidationReport`
  (was only accessible as `exarch_core::security::ValidationReport`) (#256).

### Fixed

- CLI: `convert_extraction_error` now has explicit match arms for `OutputExists`,
  `InvalidPermissions`, `InvalidCompressionLevel`, and `SecurityViolation`, each producing an
  actionable message with the relevant path or reason. Previously these variants fell through to a
  generic wildcard arm (#295).
- `PyProgressAdapter` and `NodeProgressAdapter` now reset `bytes_written` to 0 at the start of each entry, eliminating stale values from previous entries (#285).
- `check_permissions` in `inspection/verify.rs` now passes the actual entry path to
  `InvalidPermissions` instead of an empty `PathBuf`, so error messages include the
  offending archive entry (#286).
- ZIP archives created via the non-progress `create_zip` path no longer include a spurious `"/"` root directory entry. The entry was an artefact of formatting an empty archive path as `"{}/"`; it has been absent from the `create_zip_with_progress` path since #289 (#290).

### Breaking Changes

- **`ExtractionError` renamed to `ArchiveError`** across the entire public API (#253). The error
  type now covers all archive operations (extraction, creation, listing, verification), not just
  extraction. Update all match arms, `use` imports, and type aliases:
  `use exarch_core::ArchiveError;`. The Python base exception is now `exarch.ArchiveError`
  (was `exarch.ExtractionError`).

### Changed

- `extract_archive_with_progress` now delegates to `extract_archive_with_options_and_progress`
  (the canonical implementation) instead of calling the internal `extract_impl` directly.
  All four `extract_archive*` convenience wrappers now form a clean delegation chain through the
  single canonical function (#259).
- Security primitives `validate_path`, `validate_symlink`, `sanitize_permissions`,
  `validate_compression_ratio`, `QuotaTracker`, and `HardlinkTracker` are now `pub(crate)`
  and no longer part of the public API. External benchmarks and integration tests that
  reference these directly must add `--features testing` (#281).
- `sanitize_permissions` return type changed from `Result<u32>` to `u32` — the function
  never fails; callers no longer need `?` or `.unwrap()`.
- Specifications in `specs/` updated to replace stale `UnsupportedFormat` references with
  `UnknownFormat { path }` (format-detection failures) and `InvalidConfiguration` (7z creation),
  matching the post-#255 Rust API. Python exception hierarchy updated to include
  `UnknownFormatError(UnsupportedFormatError)` (#265, #264).

### Changed

- `creation/tar`: replace manual entry counter with `ProgressTracker`; add `ProgressTracker::callback()` accessor to enable byte-level progress in nested helpers without lifetime conflicts (#284).
- `creation/zip`: same `ProgressTracker` wiring as tar, removing manual `idx + 1` counter (#284).
- `creation/zip`: `create_zip_internal` now delegates to `create_zip_internal_with_progress` via `NoopProgress`, eliminating ~167 lines of duplicate traversal, compression-option, and file-add logic (#290).
- `creation/tar`: dead `_buffer: &mut [u8]` parameter removed from `add_file_to_tar_with_progress_impl`; the two 64 KB heap allocations at the former call sites are eliminated (#291).
- `api`: collapse five identical `extract_tar*` private functions into a single generic `extract_tar_with_decoder` helper parametrised by a decoder closure; eliminates ~80 lines of structural duplication (#254).
- `sevenz`: eliminate `Rc`/`RefCell` interior mutability in `extract_with_callback`; state is now owned by a local context struct, matching the `tar.rs` and `zip.rs` patterns (#273, #258).
- `sevenz`: narrow `std::process` import to `std::process::id` to prevent accidental use of `process::exit` in library code (#270).
- Internal creation helpers (`compression_level_to_*`, `ProgressReader`, `ProgressTracker`,
  `FilteredEntry`, `FilteredWalker`) are no longer accessible via `pub use` at the crate root;
  they remain available within `exarch-core` through their submodule paths but are internal
  implementation details. The parent modules `creation::compression`, `creation::progress`, and
  `creation::walker` are now `pub(crate)` (#280).
- `sanitize_permissions` signature no longer accepts a `_path: &Path` parameter that was
  unused. Call sites that passed a dummy path must be updated to omit the argument (#279).
- ZIP symlink extraction tests (`test_extract_symlink_via_unix_attributes`,
  `test_symlink_disabled_by_default`) are no longer ignored; they now use raw ZIP construction
  with correct unix mode bits to exercise the security-critical symlink detection path (#271).
- `test_hardlink_rejected` rewritten to perform a real extraction and assert successful completion,
  documenting that `ValidatedEntryType::Hardlink` is unreachable for any real ZIP entry (#272).
- Removed `test_debug_zip_unix_mode` debug test that was permanently ignored.

### Breaking Changes

- **`ExtractionError::UnsupportedFormat`** has been removed. All format-detection failures now
  return `ExtractionError::UnknownFormat { path }`, which carries the path that could not be
  identified. Match arms on `UnsupportedFormat` must be updated to `UnknownFormat { .. }` (#255).
- **7z archive creation** now returns `ExtractionError::InvalidConfiguration` instead of
  `ExtractionError::UnsupportedFormat` when the output path has a `.7z` extension, since the
  format is recognised but creation is unsupported (#255).
- **`CreationConfig::with_compression_level`** now returns `Result<Self, ExtractionError>` instead
  of `Self`. Call sites must handle the error with `?` or `.unwrap()`; the method no longer panics
  on out-of-range input (#257). The real validation gate is `CreationConfig::validate()`, which is
  invoked by the creation pipeline; this change removes the panic from the public builder surface.
- **Python**: `PartialExtractionError` has been removed from the public API. In 0.4.0 it was
  always raised when extraction failed after some files were already written. Code written
  against 0.4.0 that used `except PartialExtractionError` must be updated: catch the specific
  exception type (`SymlinkEscapeError`, `QuotaExceededError`, etc.) or use `except
  ExtractionError` as the catch-all. To detect whether output was partial, use
  `getattr(e, "files_extracted", None) is not None` (#251).

### Added

- Node.js: `SecurityConfig` now exposes `allowSolidArchives` getter, consistent with all other
  boolean permission getters (`allowSymlinks`, `allowHardlinks`, `allowAbsolutePaths`,
  `allowWorldWritable`) (#261).
- Python: `UnknownFormatError` is now a distinct exception subclass of `UnsupportedFormatError`,
  raised when an archive format cannot be determined from the file path or magic bytes
  (`CoreError::UnknownFormat`). Callers catching `UnsupportedFormatError` continue to work
  unchanged; callers that need to distinguish "format unknown" from "format known but unsupported"
  can now catch the narrower type (#260).
- Python: `extract_archive_with_progress(archive_path, output_dir, config, progress)` binding
  added, mirroring `create_archive_with_progress`. The GIL is held when a callback is provided
  and released otherwise. `exarch.pyi` and the stub are updated (#263).
- Node.js: `extractArchiveWithProgress(archivePath, outputDir, config?, progress?)` async binding
  added, accepting an optional `ThreadsafeFunction` progress callback with signature
  `(path: string, total: bigint, current: bigint, bytesWritten: bigint) => void` (#263).

### Fixed

- CLI: `convert_extraction_error` now has explicit match arms for `InvalidConfiguration`,
  `SourceNotFound`, and `SourceNotAccessible`, each producing an actionable message with the
  relevant path or reason. Previously these variants fell through to a generic wildcard arm (#274).
- CLI: `SecurityConfig` quota parameters (`max_file_count`, `max_total_size`, `max_file_size`,
  `max_compression_ratio`, `allow_solid_archives`) are now defined once in `execute()` and
  reused for the pre-listing phase, eliminating silent drift if quota defaults change (#267).
- CLI: The four near-identical `run_extraction` call sites in `extract` are unified into a single
  call via `Box<dyn ProgressCallback>`, removing the copy-paste maintenance burden (#268).

- Node.js: async operations (`extractArchive`, `createArchive`, `listArchive`, `verifyArchive`)
  now wrap the core call with `catch_unwind` inside `spawn_blocking`, preventing panics in
  `exarch-core` from crossing the FFI boundary and aborting the Node.js process. Panics are
  converted to JavaScript errors with a descriptive message (#262).
- Python: `extract_archive` now raises the specific exception type (`SymlinkEscapeError`,
  `HardlinkEscapeError`, `QuotaExceededError`, etc.) instead of the generic
  `PartialExtractionError` when extraction fails after some files have been written to disk.
  The `files_extracted` and `bytes_written` report attributes from #210 are attached directly
  to the concrete exception (#251).
- Node.js: `extract_archive` error messages now begin with the specific error code
  (`SYMLINK_ESCAPE`, `QUOTA_EXCEEDED`, etc.) instead of always prefixing `PARTIAL_EXTRACTION`
  when the error occurs after partial output has been written. The `filesExtracted` and
  `bytesWritten` fields are still appended to the message (#251).

## [0.4.0] - 2026-05-20

### Added

- Shell completion generation via `exarch completion <shell>` (bash, zsh, fish, powershell, elvish). Output goes to stdout for piping into the appropriate completions directory (#232).
- `--verbose` flag now prints one line per extracted entry to stderr, including entry name, size, and type. `--quiet` takes precedence when both flags are provided (#233).
- `SecurityConfig::allowed_extensions` filter is now enforced during extraction across all three format handlers (TAR, ZIP, 7z). When the list is non-empty, files whose extension is not in the allowlist are skipped and recorded in `ExtractionReport::files_skipped` with a warning (#230).
- `extract` subcommand now accepts `--allowed-extensions <EXT>` (repeatable; comma-separated values also accepted) and passes the parsed list to `SecurityConfig::with_allowed_extensions()`, exposing the core extension filter at the CLI level (#246).
- `create_archive` now rejects ZIP-family alias extensions (`.apk`, `.jar`, `.whl`, `.epub`, `.war`, `.ear`, `.aab`, `.ipa`, `.appx`, `.msix`, `.vsix`, `.nbm`) when the output format is inferred (i.e., `CreationConfig::format` is `None`). Set `CreationConfig::format = Some(ArchiveType::Zip)` to override (#231).

### Breaking Changes

- **`Archive::open`** now returns `Self` instead of `Result<Self>`. Callers must remove `?` or `.unwrap()` (#243).
- `SecurityConfig`, `AllowedFeatures`, and `ExtractionOptions` are now `#[non_exhaustive]`. External crates can no longer construct these structs via struct literal syntax; use `Default::default()` or the new fluent builder methods instead (#221).
- Internal modules `copy`, `io`, and `test_utils` in `exarch-core` are now `pub(crate)` instead of `pub`. These were never part of the public API; any external code referencing `exarch_core::copy`, `exarch_core::io`, or `exarch_core::test_utils` directly will no longer compile (#173).

### Changed

- `verify_entry` in `exarch-core::inspection::verify` now calls `validate_path` once per entry and caches the result, eliminating a redundant second call (and the associated `canonicalize` syscalls) for symlink and hardlink entries (#236).
- Upgraded `zip` dependency from 8.6.0 to 9.0.0-pre2; adapted `ZipFile::name()` call sites to propagate the new `Result<Cow<str>, ZipError>` return type (#238).
- Refactored `TarArchive` internal extraction helpers: introduced a private `ExtractionContext<'_, '_>` struct that groups the six shared parameters (`validator`, `dest`, `report`, `copy_buffer`, `dir_cache`, `skip_duplicates`) previously threaded individually through `process_entry` (7 params), `extract_file` (7 params), and `create_hardlink` (5 params). Signatures now accept `ctx: &mut ExtractionContext<'_, '_>` instead (#222).
- `extract_archive_full` renamed to `extract_archive_with_options_and_progress` for API naming consistency. The old name was ambiguous; the new name describes both parameters the function accepts (#219).
- Introduced `FormatCreator` trait in `exarch-core::formats::traits` for archive creation dispatch. The trait mirrors `ArchiveFormat` on the write side and replaces the manual `match` in `create_archive_with_progress` with six unit struct implementors (`TarCreator`, `TarGzCreator`, `TarBz2Creator`, `TarXzCreator`, `TarZstCreator`, `ZipCreator`) and a `creator_for_format` helper (#220).
- Added 15 fluent builder methods to `SecurityConfig` (`with_max_file_size`, `with_max_total_size`, `with_max_compression_ratio`, `with_max_file_count`, `with_max_path_depth`, `with_allowed`, `with_allow_symlinks`, `with_allow_hardlinks`, `with_allow_absolute_paths`, `with_allow_world_writable`, `with_preserve_permissions`, `with_allowed_extensions`, `with_banned_path_components`, `with_allow_solid_archives`, `with_max_solid_block_memory`) and 2 to `ExtractionOptions` (`with_atomic`, `with_skip_duplicates`) (#218).
- `TarArchive::list()` and `TarArchive::extract()` now have `///` doc comments explaining that `list()` consumes the internal reader (TAR is forward-only) and that calling `extract()` on the same instance afterward returns `InvalidArchive`. Callers must open a fresh instance for extraction (#211).
- `CopyBuffer::size()` visibility corrected from `pub(crate)` to `pub`, consistent with the other items in the crate-internal `mod copy`. The `pub(crate)` module boundary in `lib.rs` already enforces the encapsulation; redundant `pub(crate)` on items inside a `pub(crate)` module triggers the `redundant_pub_crate` clippy lint (#203).
- `verify_archive` now delegates to `verify_manifest` after calling `list_archive`, eliminating ~80 lines of duplicated entry-processing logic (#190).
- `ProgressCallback::on_complete` doc comment clarified: the method is called only on successful completion; implementors must not use it for cleanup.
- `ArchiveFormat` trait extended with `fn list()` and `fn verify()` methods, providing a single implementation point for all format operations (#174).

### Removed

- Removed 5 non-progress public functions (`create_tar`, `create_tar_gz`, `create_tar_bz2`, `create_tar_xz`, `create_tar_zst`) from `exarch-core::creation::tar` that were annotated `#[allow(dead_code)]` and unreachable from the crate's public surface. The public API already routes through `FormatCreator` trait objects using the `_with_progress` variants (#227).
- Removed dead `format_success` and `format_warning` methods from the `OutputFormatter` trait and both implementations (`HumanFormatter`, `JsonFormatter`). Neither method was called from any command handler (#208).
- Removed dead constant `SEVENZ_MAGIC` and its `#[allow(dead_code)]` suppression from `formats/detect.rs`; the constant was unused in format detection logic (#175).

### Fixed

- `CliProgress` bar now receives the actual archive entry count instead of the hardcoded value of 100; byte throughput is shown via `set_message` so that the `{pos}/{len} files` counter tracks only entries and does not race with cumulative byte values (#245).
- `CliProgress` entry count is pre-filtered when `--allowed-extensions` is active, so the progress bar reaches 100% even when a subset of entries is extracted (#245, #246).

- `ArchiveBuilder::extract` now returns `ExtractionError::InvalidConfiguration` instead of `ExtractionError::SecurityViolation` when `archive_path` or `output_dir` are not set. The previous variant caused `error_code()` to return `"SECURITY_VIOLATION"` for what is a caller configuration mistake (#235).
- Corrected the `Archive::open` doc-comment which incorrectly claimed the constructor validates file existence. The function is infallible; I/O errors surface on `extract()` (#237).
- `create_tar_zst_with_progress` now calls `zstd::Encoder::finish()` explicitly and propagates any I/O error via `?`. Previously the encoder relied on `Drop` to call `try_finish()`, which silently discarded flush errors and could produce a truncated `.tar.zst` archive on disk-full or other I/O failure (#226).
- CLI no longer emits `"HINT: Use --allow-symlinks"` when `--allow-symlinks` is already active and a symlink escape is blocked. The hint is now suppressed when the flag is set, since the escape is a genuine security violation rather than a configuration issue (#213).
- `verify_archive` no longer shares a static `/tmp/exarch-verify` directory across concurrent calls. Each invocation now uses an isolated `tempfile::TempDir` scoped to its lifetime, eliminating the TOCTOU race and persistent state pollution (#200).
- 7z extraction callback now accumulates `bytes_written` via `checked_add` instead of unchecked `+=`, preventing silent integer wraparound in release builds and matching the project-wide convention established in `copy_with_buffer` (#201).
- JSON `message` field no longer repeats the inner error text for `PartialExtraction` variants (`HardlinkEscape`, `SymlinkEscape`). `PartialExtraction` is `#[error("{source}")]` with `#[source]`, so placing it directly in an anyhow chain caused the inner error display to appear twice in `{:#}` output. `convert_extraction_error` now extracts the inner error and wraps it with a dedicated `PartialExtractionContext` carrier that holds the partial report without re-emitting the inner text (#204).
- `JsonFormatter::format_success` and `format_warning` no longer emit `"operation":"unknown"` or `"operation":"warning"` in JSON output. Both methods now accept an `operation: &str` parameter propagated through the `OutputFormatter` trait (#202).
- JSON `message` field no longer duplicates the path for `PathTraversal` errors in `--json` CLI output. The path was embedded in both the anyhow context string and the `ExtractionError::Display` output, causing it to appear twice when formatted with `{:#}` (#198).
- JSON `message` field no longer duplicates the path for `SymlinkEscape` and `HardlinkEscape` errors in `--json` CLI output. The path was embedded in both the anyhow context string and the `ExtractionError::Display` output, causing it to appear twice when formatted with `{:#}` (#196).
- `SevenZArchive::extract` now fires `on_entry_start` and `on_entry_complete` per-entry, interleaved with actual I/O, instead of batching all start events before extraction and all complete events after (#191).
- `SevenZArchive::verify` now calls `config.validate()` before any archive I/O, matching the guard applied by the public `verify_archive` entrypoint (#191).
- JSON error output no longer duplicates the error message for `QuotaExceeded` and `ZipBomb` errors when using `--json`. The `message` field previously contained the `ExtractionError::Display` text twice due to `anyhow`'s `{:#}` formatter chaining the context string with the inner error display (#192).
- `extract_archive_with_progress` now correctly invokes the `ProgressCallback` for all archive formats (TAR, ZIP, 7z). Previously the callback was silently discarded because `ArchiveFormat::extract` did not accept a progress parameter (#170).
- `create_archive()` now returns `Error::UnsupportedFormat` instead of `Error::InvalidArchive` when a `.7z` output path is requested, correctly signaling that 7z creation is not supported (#182).
- ZIP password-protection detection now performs a full linear scan of all entries instead of a 3-sample strategy, preventing false negatives for archives with encrypted entries outside the first/middle/last 100 positions (#171).
- `SecurityConfig::validate()` added: construction-time validation rejects `max_compression_ratio <= 0`, `max_file_size == 0`, `max_total_size == 0`, and `max_path_depth == 0`; `extract_archive` and `create_archive` call `validate()` and return an error for invalid configs (#172).
- `CreationConfig::validate()` is now called in `create_archive_with_progress`, ensuring invalid creation configs are caught before any I/O occurs (#180).
- `SecurityConfig::validate()` now rejects `max_file_count == 0` and `max_solid_block_memory == 0` to prevent undefined extraction behavior (#181).

## [0.3.1] - 2026-05-19

### Changed

- Raised MSRV from 1.89.0 to 1.93.0 to accommodate `sevenz-rust2` 0.21.0 (required by `nt-time` 0.15) (#163).

### Fixed

- `extract` command now correctly applies user-supplied quota flags (`--max-total-size`, `--max-file-size`, `--max-files`, `--max-compression-ratio`) to the conflict-detection pre-pass. Previously the pre-pass used default limits, causing a spurious quota error for archives larger than 500 MiB even when a higher limit was specified (#166).

### CI

- Drop Python 3.9 (EOL October 2025) from the test matrix; add Python 3.14.
- Release workflow updated to build wheels against Python 3.10 minimum.

### Dependencies

- `sevenz-rust2` 0.20.2 → 0.21.0 (#162)
- `assert_cmd` 2.2.0 → 2.2.2, `clap` 4.6.0 → 4.6.1, `clap_complete` 4.6.2 → 4.6.5, `libc` 0.2.185 → 0.2.186, `napi` 3.8.4 → 3.9.0, `napi-build` 2.3.1 → 2.3.2, `napi-derive` 3.5.3 → 3.5.6, `tokio` 1.51.1 → 1.52.1, `zip` 8.5.1 → 8.6.0 (#161, #164, #165, #167)
- Python dev dependencies updated (`maturin` 1.13.3, `mypy` 2.1.0, `pytest` 9.0.3, `pytest-cov` 7.1.0, `ruff` 0.15.13); minimum Python version raised to 3.10 (3.9 EOL)
- Node.js dev dependencies updated (`@biomejs/biome` 2.4.15, `@napi-rs/cli` 3.6.2); migrated from npm to pnpm

## [0.3.0] - 2026-04-23

### Added

- Extract, list, and verify additional ZIP-based formats. JVM artifacts
  (`.jar`, `.war`, `.ear`), Java-ecosystem packaging (`.nar`, `.nbm`),
  mobile and desktop app bundles (`.apk`, `.aab`, `.ipa`, `.appx`,
  `.msix`), Python wheels (`.whl`), IDE/browser extensions (`.vsix`,
  `.xpi`), and EPUBs (`.epub`) now route through the existing ZIP
  extractor rather than returning `UnsupportedFormat`. Creation for
  these extensions is explicitly rejected (mirrors `.7z`): they all
  sit on ZIP but require extra structure - signing, manifests,
  ordering rules - that exarch doesn't produce, so silently emitting
  a bare ZIP would be misleading. Callers who need the override can
  set `CreationConfig::format = Some(exarch_core::formats::detect::ArchiveType::Zip)`.
### Fixed

- `detect_format` now uses `is_zip_family_alias` for ZIP-family extension
  matching, ensuring the dedicated case-insensitive helper is the single
  source of truth rather than a duplicated inline `contains` call.

- `detect_format` now returns `UnsupportedFormat` for bare `.gz` files (no `.tar`
  stem) instead of silently routing them to `open_tar_gz` and producing
  `InvalidArchive` at runtime. `.tar.gz` and `.tgz` paths are unaffected (#155).

### Security

- Update `unicode-segmentation` from 1.13.1 (yanked) to 1.13.2 via `cargo update`.
  Pulled transitively through `convert_case` (napi-derive) and `indicatif` (exarch-cli).
  `cargo deny check` now reports no yanked crates; advisories, bans, licenses, and
  sources all pass.

## [0.2.9] - 2026-03-25

### Tests

- Add regression tests for RUSTSEC-2026-0067 symlink+directory chmod attack
  (CVE-2026-33056 / GHSA-j4xf-2g29-59ph). Two new test cases verify that an
  archive combining `subdir -> ../external` (symlink) followed by a directory
  entry `subdir` is rejected before tar-rs can chmod the external directory —
  both with default config (symlinks disabled) and with `allow_symlinks = true`
  (#132).

### Security

- Confirm and test CVE-2026-24842: hardlink `linkpath` validation correctly uses the
  extraction root (`dest`) as the resolution base, not the entry's parent directory.
  A crafted entry `a/b/c/d/link` with `linkpath = ../../../../etc/passwd` is blocked
  because `dest/../../../../etc/passwd` escapes the root and is detected immediately.
  The mismatch described in the CVE does not exist in this implementation; added CVE
  regression test `tests/cve/cve_2026_24842.rs` to prevent future regressions (#131).

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

- Add CVE-2025-29787 regression test (ZIP symlink zip-slip). exarch is not
  vulnerable: `SafeSymlink::validate` rejects the escaping symlink before it is
  written to disk, so the follow-on file entry cannot escape the extraction
  root (#133).

- `exarch list` and `exarch verify` now accept `--max-files` and `--max-total-size`
  flags, mirroring `exarch extract`. Archives with more than 10 000 entries (e.g.
  ZIP64 archives) can now be listed or verified by passing `--max-files <N>` (#122).

- `list_archive` and `verify_archive` now support 7z archives, consistent with
  TAR and ZIP (#79). Entries are iterated via `sevenz-rust2::Archive::read`
  (no decompression); solid archives are safe to list. Quota limits, path
  traversal checks, and encryption rejection apply identically to other formats.

### Fixed

- TAR/ZIP extraction no longer aborts on duplicate entry names; conflicting entries are now
  skipped with a warning recorded in `ExtractionReport.files_skipped` (#129). The new
  `ExtractionOptions.skip_duplicates` field (default `true`) controls this behavior.

- Fix `list` and `verify` crash on valid empty 7z archives (#117)
- Fix `verify` false positive [HIGH] for solid 7z archive entries where
  `compressed_size=0` is a normal artifact of solid block compression (#118)
- Add `--allow-solid-archives` flag to CLI `extract` command (#119)
- `--allow-solid-archives` is now propagated to the conflict-detection `list_archive` call
  in `extract`, fixing a `SecurityViolation` at the list step when solid 7z archives are
  passed with `--allow-solid-archives` but without `--force` or `--atomic` (#124).
  `--allow-solid-archives` is also exposed in the `list` and `verify` subcommands.
- Expose `allow_solid_archives` in Python and Node.js bindings (`SecurityConfig`) (#127)
- TAR hardlink entries now copy file content instead of creating real OS hardlinks,
  preventing shared-inode corruption when a duplicate entry overwrites a hardlink path
  (GHSA-2367-c296-3mp2 variant, #130).
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

[Unreleased]: https://github.com/bug-ops/exarch/compare/v0.4.1...HEAD
[0.4.1]: https://github.com/bug-ops/exarch/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/bug-ops/exarch/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/bug-ops/exarch/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/bug-ops/exarch/compare/v0.2.9...v0.3.0
[0.2.9]: https://github.com/bug-ops/exarch/compare/v0.2.8...v0.2.9
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
