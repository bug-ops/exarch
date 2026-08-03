# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Performance

- **7z extraction was 35-101% slower than `sevenz_rust2::decompress_file` on the same archive,
  scaling with file count (#492)**: `formats::sevenz::write_file_with_permit_using` always wrote
  through a temp-file-then-`rename` even when nothing occupied the destination path, costing two
  extra syscalls (`open`+`rename`) per extracted file — profiling attributed 45-54% of extraction
  CPU time to this path. `process_entry_inner` now writes directly to `dest_path` via
  `common::create_file_with_mode` (same `O_EXCL`+`O_NOFOLLOW` guarantee, mirroring TAR/ZIP's
  `common::extract_file_with_permit`) when no pre-existing file is found there, and keeps the
  atomic temp+rename path only for the overwrite case where a decode failure mid-stream must not
  leave a truncated file behind; both write paths now also buffer output through a 64KiB
  `BufWriter`, matching TAR/ZIP's `common::extract_file_with_permit`, and the direct-write path
  removes whatever it started writing if the copy fails partway, so a decode failure never leaves
  a truncated file at the final destination either. `SevenZArchive` also now retains its
  already-parsed `sevenz_rust2::Archive` from `new()` and clones it into `ArchiveReader::from_archive`
  at extraction time instead of re-parsing the archive header a second time (the clone, not a move,
  keeps a second `extract()` call on the same instance working correctly). Re-measured via a new
  `sevenz_vs_reference` criterion bench group (`crates/exarch-core/benches/extraction.rs`,
  `medium_files.7z`/`small_files.7z`): the gap against `sevenz_rust2::decompress_file` closed from
  35%/101% slower to within noise of parity (and `medium_files.7z` now edges ahead). A companion
  `sevenz_overwrite` bench group exercises the temp+rename path specifically.

  An earlier version of this fix also threaded `Some(dir_cache)` into both
  `EntryValidator::validate_entry_path` call sites in `sevenz.rs` (matching TAR) to enable the
  trusted-parent canonicalize-skip. Adversarial review found this let `DirCache` trust a directory
  that something outside the archive's own entries — e.g. a misbehaving `ProgressCallback` —
  swapped for a symlink between two entries sharing that parent, turning a hard-erroring symlink
  escape into a silent, unbounded one; both call sites were reverted to `None` before merge, so
  this specific optimization is not part of this change.

### Added

- CI: add `bench-build` job to `.github/workflows/ci.yml` that compiles the
  `exarch-core` criterion benchmarks (`--all-features`, covering the
  `testing`-gated `validation` bench) without running them, catching
  benchmark compilation breakage in a fast parallel job.
- `exarch-node`: add `createArchiveWithProgress` and
  `createArchiveWithProgressSync`, mirroring the existing
  `extractArchiveWithProgress` async/sync pattern and `exarch-python`'s
  `create_archive_with_progress`. Both reuse `exarch_core::create_archive_with_progress`
  and the existing `NodeProgressAdapter` threadsafe-function bridge — no new
  core security logic (#455).
- `exarch-node`: add JS integration tests for `extractArchiveWithProgress`,
  `createArchiveWithProgress`, and `createArchiveWithProgressSync` covering
  the per-entry callback shape and the `progress=null`/omitted paths, closing
  a coverage gap where these APIs had no test exercising them (#456).

### Changed

- **`formats::sevenz::extract_archive` now builds its duplicate-skip warning via the shared
  `common::push_duplicate_skip_warning` helper (#499)**, matching the TAR and ZIP handlers instead
  of re-implementing the singular/plural aggregation inline. No behavior or message change.
- **BREAKING: `ArchiveError::to_ffi_message` no longer takes a `sanitize_paths: bool` parameter
  (#463)**: the parameter's runtime toggle no longer maps onto anything real once the redaction
  policy became profile-gated (`cfg(debug_assertions)`) rather than caller-selected — see the
  `#463`/`#462` entry under `### Fixed` for why the policy changed. `to_ffi_message()` now takes
  no arguments and always applies the shared policy from the new `error::redaction` module via
  `ArchiveError::redacted_path()`. The method had zero callers anywhere in the workspace, so this
  has no runtime effect on `exarch-python`/`exarch-node`, but any direct Rust API consumer calling
  `to_ffi_message(sanitize_paths)` must drop the argument.
- **BREAKING: `SecurityConfig::validate()` now rejects malformed `allowed_extensions`/
  `banned_path_components` entries (#449)**: a new `validate_config_entry` helper in
  `exarch-core::security::boundary` (re-exported as `exarch_core::validate_config_entry`,
  alongside `MAX_CONFIG_ENTRY_LENGTH`) is called per-entry from `SecurityConfig::validate()`,
  which now returns `ArchiveError::InvalidConfiguration` for any entry that is empty, contains a
  null byte, or exceeds 255 bytes — configs that previously passed `validate()` with such entries
  now fail. `exarch-python`'s `add_allowed_extension`/`add_banned_component` and
  `exarch-node`'s `addAllowedExtension`/`addBannedComponent` now delegate to the same helper
  instead of duplicating the length/null-byte checks, so both bindings additionally reject empty
  entries eagerly (previously accepted) and report length in bytes rather than the previously
  inaccurate "characters" wording for multi-byte input. `exarch-node`'s error messages for these
  two setters now carry the crate-wide `INVALID_CONFIGURATION: invalid configuration: ` prefix
  (previously a bare reason string), matching every other error path in the binding.
- **`exarch-cli` output formatters now write through an injectable writer (#452)**:
  `OutputFormatter`'s six trait methods take `&mut self` instead of `&self`.
  `HumanFormatter<O: Write = Term, E: Write = Term>` writes non-error output to `O` and errors to
  `E` (`HumanFormatter::new` keeps the stdout/stderr default; `HumanFormatter::with_writers` injects
  custom writers and an explicit `use_colors` flag for deterministic tests). `JsonFormatter<W: Write
  = Stdout>` gained the same shape (`JsonFormatter::stdout()` replaces the old unit-struct
  constructor; `JsonFormatter::with_writer` injects a custom writer). `create_formatter`'s signature
  is unchanged. This unlocks unit tests that capture formatter output into an in-memory buffer
  instead of requiring a subprocess. `HumanFormatter` renders each line into a `String` first and
  issues a single `write_all` per line (`output::human::emit_line`/`emit_blank`) rather than calling
  `writeln!` directly on the writer, which would otherwise turn one multi-argument format line into
  several separate small writes against `console::Term` (no internal buffering) — output throughput
  on large manifests is unchanged from the pre-refactor `Term::write_line` behavior.
- **CLI size-limit defaults are no longer re-literalized across commands (#450)**: added
  `commands::apply_size_limits(config, max_total, max_file)` in `crates/exarch-cli/src/commands/mod.rs`,
  applying `--max-total-size`/`--max-file-size` overrides only when provided and otherwise leaving
  `SecurityConfig::default()`'s own limits in place. `extract`, `list`, and `verify` now route
  through this helper instead of each hardcoding `.unwrap_or(500 * 1024 * 1024)` /
  `.unwrap_or(50 * 1024 * 1024)`. No behavior change.
- **BREAKING: `exarch-node` boolean setters now take a mandatory `boolean` instead of an
  optional one (#442)**: `SecurityConfig.setAllowSymlinks`, `setAllowHardlinks`,
  `setAllowAbsolutePaths`, `setAllowWorldWritable`, `setAllowSolidArchives`,
  `setPreservePermissions`; `CreationConfig.setPreservePermissions`, `setFollowSymlinks`,
  `setIncludeHidden`; and `ExtractionOptions.withSkipDuplicates`, `withAtomic` no longer accept
  `Option<bool>` resolved via `.unwrap_or(true)`. Previously, calling one of these setters with
  zero arguments silently flipped the flag to the permissive `true` state instead of erroring,
  violating this project's secure-by-default posture. Callers must now pass an explicit
  `boolean`; omitting the argument is a compile-time TypeScript error and a runtime napi error
  from plain JavaScript. Explicit `undefined` or `null` are rejected the same way, which also
  catches the more realistic failure pattern of forwarding an optional property (e.g.
  `cfg.setAllowSymlinks(userOpts.allowSymlinks)`) that was never actually set.
- **BREAKING: `CreationConfig` is now a two-state typestate over `Unvalidated`/`Validated` (#443)**:
  mirrors the `SecurityConfig` typestate from #433-#435. `CreationConfig<State = Unvalidated>`
  carries a phantom marker (reusing the existing `Unvalidated`/`Validated` markers from
  `crate::config`, not a new pair); the fluent `with_*` builders remain available only on
  `CreationConfig<Unvalidated>`, and `CreationConfig::validate()` now consumes `self` and returns
  `Result<CreationConfig<Validated>>` instead of `Result<()>`. The low-level
  `creation::tar::*`/`creation::zip::*` functions and `FormatCreator::create` now require
  `&CreationConfig<Validated>`, so a forged or unvalidated `compression_level` can no longer reach
  `flate2`/`xz2`, closing a panic-based DoS: a hand-built `CreationConfig` with
  `compression_level: Some(200)` previously bypassed the `InvalidCompressionLevel` contract
  enforced only at the two high-level entry points and triggered an `assert!`/`unwrap()` panic
  inside `flate2`'s `zlib-rs` backend and `xz2` respectively, instead of returning an error.
  Fields are sealed behind a private inner `CreationConfigFields` struct
  (`#[non_exhaustive]`), reachable read-only via `Deref` for both typestates but mutable
  (`DerefMut`) only for `CreationConfig<Unvalidated>`. `creation::filters::should_skip` and
  `creation::filters::compute_archive_path` also gained a `State` type parameter, so any external
  caller invoking them with an explicit turbofish must update it. The top-level `create_archive*` functions
  and `ArchiveCreator::create` are unaffected: they still accept `&CreationConfig`/`CreationConfig`
  (defaulting to `Unvalidated`) and validate internally. `exarch-cli`, `exarch-python`, and
  `exarch-node` need only the CLI's `create` command updated (it built a `CreationConfig` via
  struct-literal syntax); both bindings mutate through `DerefMut` on `Unvalidated` and continue to
  compile unchanged.
- **BREAKING: `ValidatedEntryType::File` now carries a `QuotaPermit` capability token (#436)**:
  `QuotaTracker::record_file` is renamed to `reserve` and returns `Result<QuotaPermit>` instead
  of `Result<()>`; `EntryValidator::record_hardlink` is renamed to `reserve_hardlink` for the
  same reason. `QuotaPermit` is a zero-sized, non-`Clone`/non-`Copy` token whose only producer
  is `QuotaTracker::reserve`, and constructing `ValidatedEntryType::File` now requires one, so a
  `File`-typed validated entry with no quota charge is unrepresentable. `extract_file_generic`
  (shared by TAR and ZIP) additionally rejects any non-`File` entry before touching the
  filesystem, and TAR's hardlink-copy path now consumes its permit by value via a new
  `copy_file_with_permit` helper, so a single reservation cannot be spent twice. This closes the
  same class of gap as #428 (an unguarded quota-charge path) at the type level instead of by
  convention; behavior is unchanged for every caller that already went through
  `EntryValidator::validate_entry`.
- **BREAKING: `SecurityConfig` is now a two-state typestate over `Unvalidated`/`Validated`
  (#433, #434, #435)**: `SecurityConfig<State = Unvalidated>` carries a phantom marker; the
  fluent `with_*` builder methods remain available only on `SecurityConfig<Unvalidated>`, and
  `SecurityConfig::validate()` now consumes `self` and returns
  `Result<SecurityConfig<Validated>>` instead of `Result<()>`. The `ArchiveFormat` trait
  (`extract`, `list`, `verify`) and every function downstream of validation in `exarch-core`
  (`EntryValidator`, `SafePath::validate`, `SafeSymlink::validate`, `QuotaTracker::record_file`,
  `validate_symlink`, `validate_compression_ratio`, `HardlinkTracker::validate_hardlink`,
  `sanitize_permissions`, and the per-format `list`/`extract` helpers) now require
  `&SecurityConfig<Validated>`, so a config that skipped or failed validation can no longer
  reach extraction, listing, or verification — enforced by the compiler instead of by
  convention. Fields are sealed behind a private inner struct, reachable read-only via `Deref`
  for both typestates but mutable (`DerefMut`) only for `SecurityConfig<Unvalidated>`, so a
  `SecurityConfig<Validated>` cannot be mutated back into an invalid state after the fact while
  `cfg.max_file_size`-style field access keeps working unchanged for every existing caller. The
  top-level `extract_archive*`, `list_archive`, `verify_archive`, and `create_archive*`
  functions are unaffected: they still accept `&SecurityConfig` (defaulting to `Unvalidated`)
  and validate internally. `SecurityConfig::default()` continues to infer `Unvalidated` with no
  turbofish required. `Validated` and `Unvalidated` are re-exported from the crate root.
  `exarch-cli`, `exarch-python`, and `exarch-node` need no changes: they only ever hold
  `SecurityConfig<Unvalidated>` and pass it to the top-level API. `ValidatedEntry`
  (`security::validator`) becomes sealed: its fields are private, its constructor is
  `pub(crate)`, and `safe_path()`/`entry_type()`/`mode()` accessors replace direct field access,
  so it is assemblable only from inside this crate, and in practice only via
  `EntryValidator::validate_entry()`. `ValidatedEntryType` is now `#[non_exhaustive]`; its
  `Symlink`/`Hardlink` variants wrap the already-sealed `SafeSymlink`/`SafePath`, so their
  payloads cannot be forged even from within the crate. No validation logic changed — this is
  purely a compile-time hardening of the existing
  runtime checks.
- Extracted the duplicated extension-allowlist check from `formats/zip.rs`, `formats/tar.rs`,
  and `formats/sevenz.rs` into a shared, `#[must_use]` `formats::common::check_extension_allowed`
  helper (#413). Behavior is unchanged; each call site still returns its own type (`Ok(())`,
  `Ok(None)`, `Ok(0)`) on rejection. Added direct unit tests pinning the exact skip-warning
  message text so the wording cannot silently drift again.
- **BREAKING: Bumped MSRV from 1.93.0 to 1.96.0 (#401)**: raises the minimum supported Rust
  version across the workspace. Downstream consumers pinned to an older toolchain must upgrade
  before taking this release. `rust-version` in the root `Cargo.toml`, the `msrv` job in
  `.github/workflows/ci.yml`, `clippy.toml`, and all README/CONTRIBUTING/spec references were
  updated accordingly.
- Migrated 151 `assert!(matches!(value, Pattern))` test assertions in `exarch-core` to the
  now-stable `assert_matches!` macro (stabilized in Rust 1.96, imported via
  `use std::assert_matches;`), which prints the actual value via `Debug` on failure instead of
  just `"assertion failed: matches!(...)"`. 4 sites in `formats/zip.rs` matching on a
  non-`Debug` type (`Result<ZipArchive<_>, _>`) were kept as `assert!(matches!(..))` since
  `assert_matches!` requires the scrutinee to implement `Debug`; 7 sites in
  `tests/property_tests.rs` were left as `prop_assert!(matches!(..))` since proptest has no
  `assert_matches!`-equivalent macro.
- Applied `core::hint::cold_path()` (stabilized in Rust 1.95) to the quota-rejection and
  integer-overflow branches in `QuotaTracker::record_file`/`record_file_checked`
  (`crates/exarch-core/src/security/quota.rs`), reinforcing the existing OPT-C003 hot/cold path
  optimization for the optimizer.
- Internal: `exarch-python`'s `extract_archive`, `create_archive`, `list_archive`, and
  `verify_archive`, and `exarch-node`'s async/sync `extract_archive(_sync)`,
  `create_archive(_sync)`, `list_archive(_sync)`, and `verify_archive(_sync)` now route through
  the existing `catch_panic_as_py_err`/`catch_panic_as_js_err` panic-catch helpers (#395) instead
  of each reimplementing the identical `catch_unwind(...).map_err(...)` sequence inline (#454).
  Pure deduplication — no change to panic-catching semantics or error messages.
- **User-visible**: in release builds of `exarch-python` and `exarch-node`, an I/O error
  (`CoreError::Io`) raised by either binding now reports only the `std::io::ErrorKind`
  description (e.g. "permission denied") instead of the full underlying `io::Error` message text;
  the full message is still shown in debug builds. See the `#453` entry below for why.

### Fixed

- **`exarch-core`: `files_skipped` was incremented via a plain `+= 1` in six sites across
  extraction and creation, inconsistent with the `checked_add`-based hardening already applied to
  TAR's own `files_skipped` counter (#515)**: `formats/common.rs`'s `check_extension_allowed`,
  `extract_file_with_permit`, and `create_symlink`, `formats/sevenz.rs`'s `process_entry_inner`,
  and `creation/zip.rs` and `creation/tar.rs`'s skip sites all used bare `+= 1`, while
  `formats/tar.rs:392` already used `checked_add(1).ok_or(ArchiveError::QuotaExceeded { resource:
  IntegerOverflow })?` after #506's `duplicate_skips` hardening. The two `Result`-returning
  extraction sites in `common.rs` and the one in `sevenz.rs` now match that same `checked_add` +
  fail-closed pattern; `check_extension_allowed` (a `bool`-returning function that cannot propagate
  `?`) and the `creation/`-side sites now use `saturating_add`, matching every sibling counter in
  those same functions (`disallowed_extension_skips`, and `CreationReport`'s `files_added`/
  `directories_added`/`symlinks_added`, none of which have a checked variant). Added a regression
  test proving the `checked_add` extraction path fails closed with `QuotaExceeded { resource:
  IntegerOverflow }` at `usize::MAX` instead of silently wrapping.
- **`exarch-core`: a symlink pointing at a directory, passed directly as a top-level `create`
  source, crashed with an internal path-normalization error instead of being archived as a link
  (#512)**: `creation::walker::collect_entries` classified the directory-walk vs. single-entry
  branch using `path.is_dir()` (stat, follows symlinks), so a symlink-to-directory source was
  routed into `FilteredWalker`/`WalkDir` instead of `EntryType::Symlink`. `WalkDir` always
  dereferences its root regardless of `follow_links(false)`, so walking through the symlink root
  produced an empty relative path for the root entry, later failing with `paths in archives must
  have at least one component when setting path for ""`. The branch selector now reuses the
  `symlink_metadata` (lstat) already fetched for existence checking and tests `metadata.is_dir()`
  instead, so a symlink-to-directory source classifies as `EntryType::Symlink` by default —
  consistent with how #510 fixed the analogous symlink-to-file case — without dereferencing the
  source at all. When `follow_symlinks` is explicitly enabled, the branch selector additionally
  checks `path.is_dir()` (stat) so the symlink is still walked as a directory, preserving the
  pre-existing dereferencing behavior for that config instead of regressing it into an I/O error
  (TAR) or an empty archive (ZIP). Under the default (non-follow) policy, TAR archives the
  directory symlink as a link entry; ZIP has no on-disk representation for symlinks and continues
  to skip it with a `Skipped symlink` warning, per the ZIP policy already established in #510 — for
  a directory symlink this means the entire target tree is omitted from the ZIP archive (exit code
  0, `files_skipped: 1`), so callers who need the tree's contents in a ZIP must pass
  `--follow-symlinks`.
- **`exarch-core`: a symlink passed directly as a top-level `create` source was silently
  dereferenced into its target's file content instead of being archived as a link (#510)**:
  `creation::walker::collect_entries`'s single-file branch (taken when a source argument is not a
  directory) used `std::fs::metadata` (stat, follows symlinks) to classify the source and check its
  existence, so a symlink argument was misclassified as `EntryType::File` and a dangling symlink
  (target missing) failed existence checks with `SourceNotFound`, even though the identical
  directory-walk path already used lstat semantics and archived symlinks under a directory
  correctly. Both checks now use `std::fs::symlink_metadata` (lstat), so a symlink source
  classifies as `EntryType::Symlink` and a dangling symlink is no longer rejected as missing.
  Because the fix makes ZIP's `EntryType::Symlink` arm reachable for the first time (previously
  dead code — `walkdir` always dereferences directory-walk roots), `create_zip_internal_with_progress`
  also gained the `follow_symlinks` handling ZIP creation was missing: with `--follow-symlinks` it
  now embeds the target file's content, matching TAR's existing behavior, instead of silently
  producing an empty archive with `files_added: 0` and no warning.

  This is a behavior change for `exarch-core`, `exarch create <archive> <symlink>`, and the
  Python/Node.js bindings that call it: `exarch create a.tar link.txt` now stores a real symlink
  entry rather than the target's dereferenced content, so extracting that archive requires
  `--allow-symlinks` (deny-by-default) where it previously round-tripped without it.
- **`exarch-core`: hardened ZIP's `by_index()`/`name()` error paths inside `extract()`'s entry loop
  to route through the same warning aggregation and `ArchiveError::partial_or` wrapping as other
  failures in the loop**: `formats/zip.rs`'s extraction loop opened each entry via
  `self.inner.by_index(i)?` and read its name via `zip_file.name()?`, both using a bare `?` that
  returned the raw error immediately, bypassing the duplicate/disallowed-extension warning
  aggregation and `ArchiveError::partial_or` wrapping used for `process_entry` failures a few lines
  below. In practice this path is not reachable through the public API today: `ZipArchive::new()`
  already scans every entry via `by_index()` during its password-protection check, so any entry
  that would fail `by_index()`/`name()` is caught at open time, before `extract()`'s loop ever
  runs — the gap would only matter if the underlying reader's data changed between that scan and
  extraction, or in a future refactor that removes or narrows the open-time scan. Both failure
  sites now aggregate the same warnings and route through `ArchiveError::partial_or` before
  returning, via a shared `push_duplicate_skip_warnings` helper (mirroring TAR's existing helper of
  the same name), giving ZIP the same structural handling as TAR and 7z as defense-in-depth, not as
  a fix for a demonstrated user-facing bug.
- **`exarch-core`: a mid-archive extraction failure where every entry processed beforehand was
  skipped (not written) discarded the entire partial report, including its warnings (#505)**:
  `ArchiveError::partial_or` only wrapped a failure into `PartialExtraction { report, .. }` when
  `report.total_items()` (`files_extracted + directories_created + symlinks_created`) was nonzero.
  An archive whose only processed entries before the failure were rejected — e.g. by
  `--allowed-extensions` or as pre-existing duplicates — left `total_items()` at `0`, so
  `partial_or` returned the original error unwrapped, silently dropping `report.warnings` and
  `report.files_skipped` even though both were populated. `partial_or` now also treats a report as
  worth surfacing when `files_skipped > 0` or `warnings` is non-empty, without changing
  `total_items()` itself (it remains "items written to disk", matching its existing Python binding
  semantics and tests).
- **`exarch-cli`: `extract`'s human and `--json` output never surfaced `ExtractionReport.warnings`
  or `files_skipped` (#498)**: both fields are populated correctly by `exarch-core` and already
  exposed by the Python and Node.js bindings, but `format_extraction_result` in `output/human.rs`
  and `output/json.rs` only read `files_extracted`/`directories_created`/`symlinks_created`/
  `bytes_written`/`duration`, silently dropping any warnings (e.g. capped disallowed-extension or
  duplicate-skip summaries from #495/#497) and the skipped-file count. `format_extraction_result`
  now prints a `Files skipped:` line and a `Warnings:` section (mirroring `create`'s existing
  formatter), and the JSON `ExtractionOutput` struct gained `files_skipped`/`warnings` fields
  (mirroring `CreationOutput`).
- **`exarch-cli`: `extract`'s pre-flight destination-conflict error listed every conflicting path
  with no cap (#500)**: the pre-flight check in `commands/extract.rs` (run before core extraction,
  when `--force`/`--atomic` are absent) built an `anyhow::bail!` message listing one line per
  pre-existing destination file: with `max_file_count` defaulting to 10000, extracting an archive
  with many same-named entries over a populated destination could dump up to 10000 lines to
  stderr — the same unbounded-output class already fixed for `exarch-core`'s warning aggregation
  in #484/#490/#495/#497. `conflict_error_message` now sorts the conflicting paths before listing
  at most 10 of them and collapsing the remainder into a single `... and N more` summary line —
  sorting first keeps "first 10 shown" a deterministic, reproducible subset rather than whatever
  order the archive manifest happened to yield.
- **`exarch-cli`: `files_skipped`/`warnings` were dropped from the error-path JSON and human
  output on a mid-archive extraction failure (#503)**: when extraction stopped partway through
  (e.g. a symlink escape after some entries already extracted), the partial `ExtractionReport`
  carried `files_skipped` and `warnings`, but neither `format_error`'s `JsonPartialReport`
  (`output/json.rs`, `output/formatter.rs`) nor `PartialExtractionContext`'s `Display` impl
  (`error.rs`, used for human-readable output) surfaced them — only `files_extracted`,
  `directories_created`, `symlinks_created`, and `bytes_written` were reported, silently hiding
  any disallowed-extension or duplicate skips that happened before the failure. Both paths now
  include `files_skipped` and `warnings` (the human path only when non-empty, mirroring the
  existing success-path convention), without changing the existing "WARNING: Extraction was
  stopped..." / "HINT: ..." wording.
- **`exarch-core`: 7z's `duplicate_skips` counter used a plain `+= 1` instead of `saturating_add`,
  the only non-saturating skip counter in the codebase (#502)**: every other skip-counter increment
  — `disallowed_extension_skips` (`common.rs:452`), TAR/ZIP's shared `duplicate_skips`
  (`common.rs:704`), and TAR's `hardlink_duplicate_skips` (`tar.rs:397`) — already used
  `saturating_add` to avoid wrapping after `u64::MAX` skips; 7z's own counter
  (`formats/sevenz.rs:575`) was the one site still using bare `+= 1`. Switched to
  `duplicate_skips.saturating_add(1)`, matching the existing idiom exactly.
- **`exarch-python` and `exarch-node`: a `PartialExtraction` error dropped `files_skipped` and
  `warnings` when converted to the language-level exception/error (#508)**: both bindings'
  `convert_error` (`crates/exarch-python/src/error.rs`, `crates/exarch-node/src/error.rs`) only
  forwarded `files_extracted`/`bytes_written` from the `ExtractionReport` attached to
  `CoreError::PartialExtraction`, even though `exarch-core` has populated `files_skipped`/
  `warnings` on that report since #505 — the CLI got the fix in #503, but the bindings were
  never updated. Python's `convert_error` now also attaches `files_skipped` (`int`) and `warnings`
  (`list[str]`) to the raised exception; Node's now also appends `filesSkipped=N` and a
  Rust-`Debug`-formatted `warnings=[...]` fragment to the thrown error's message, following the
  same `key=value` convention as the existing `filesExtracted`/`bytesWritten` suffix. The
  `warnings=[...]` fragment on the Node side is for human/log inspection only — it is not
  guaranteed valid JSON and must not be `JSON.parse`d.
- **`exarch-core`: TAR, ZIP, and 7z pushed one unbounded, path-bearing warning `String` per entry
  rejected by the extension allowlist (#495)**: `common::check_extension_allowed` (shared by all
  three format handlers) pushed a `"skipped entry with disallowed extension: {path}"` warning
  directly into `report.warnings` for every rejected entry, growing the report proportional to
  archive size with no cap — the same class of issue already fixed for pre-existing-duplicate skips
  in #484/#490. The function now increments a `disallowed_extension_skips` counter instead; each
  format's `extract()` aggregates it into at most one `"skipped N entries with disallowed
  extensions"` warning once extraction completes. `report.files_skipped`'s count is unaffected.
- **`exarch-python`: a raising progress callback was silently swallowed during extraction/creation
  (#489)**: `PyProgressAdapter::on_entry_start` discarded both the return value and any Python
  exception from `self.callback.call1(...)` via `let _ = ...`, so a callback raising to signal an
  abort (an anomaly check, a quota/policy decision, a cancellation request) had no effect —
  extraction or creation ran to completion as if nothing happened. The exception is now captured
  instead of discarded; consistent with `exarch-node`'s `NodeProgressAdapter` (#465/#485), the
  underlying `ProgressCallback` contract has no cancellation signal, so the operation still runs to
  completion (further callback dispatches are skipped once an exception is captured), and the
  result is merged once it returns: if the operation otherwise succeeded, the callback's exception
  now propagates to the caller, carrying `files_extracted`/`files_added` and `bytes_written`
  attributes describing what was written, plus a `progress_callback_error = True` marker
  attribute — needed because those two counter attribute names are the same ones a genuine
  partial extraction/creation failure carries (see `extract_archive`'s existing
  `hasattr(e, "files_extracted")` idiom), so the marker is what tells the two apart; if the
  operation also failed, the core error stays primary (a raising callback can never mask a
  security error) with the callback's exception chained onto it via `__cause__`.
- **`exarch-core`: `SafeSymlink::validate` did not explicitly reject Windows drive/UNC prefix or
  root-relative components in a symlink target, relying only on `is_absolute()` (#491)**: a
  drive-relative target like `C:foo` (no backslash after the colon, `Prefix` without `RootDir`) and
  a root-relative target like `\evil` (`RootDir` without `Prefix`) are both not `is_absolute()` per
  Rust's definition, which requires both components together, yet each still resolves relative to
  the current directory/drive — a GHSA-9ppj-qmqm-q256-class bypass. `SafeHardlink::validate`
  (`security/hardlink.rs`, tag `H-SEC-2`) and `SafePath::validate` already carry this explicit
  `Component::Prefix(_) | Component::RootDir` rejection; `SafeSymlink::validate` only carried it as
  an unstated side effect of `PathBuf::push`'s Windows prefix-without-root replacement behavior in
  `resolve_through_symlinks`. Added the same explicit guard so the rejection is deliberate rather
  than incidental.
- **`exarch-core`: TAR and ZIP `skip_duplicates = true` pushed one unbounded warning `String` per
  pre-existing-duplicate entry, symlink, or (TAR-only) hardlink (#490)**: `report.warnings` grew by
  one entry per skipped duplicate, proportional to archive size with no cap — the same class of
  issue already fixed for 7z in #484/#487. `common::extract_file_with_permit` and
  `common::create_symlink` (shared by both formats) and TAR's own inline hardlink duplicate-skip
  path in `create_hardlink` now accumulate counters instead, and each format's `extract()` pushes at
  most two aggregated warnings once extraction completes (one for file/symlink duplicates, plus one
  for hardlink duplicates on TAR, since ZIP has no hardlink entry type). `report.files_skipped`'s
  count is unaffected.
- **`exarch-core`: 7z `skip_duplicates = false` deleted a pre-existing destination directory tree
  instead of failing like TAR/ZIP's `EISDIR` (#483)**: when a 7z file entry's destination path was
  occupied by a pre-existing directory, extraction called `remove_dir_all` on it and wrote a fresh
  file in its place, recursively discarding the entire tree. TAR/ZIP instead fail with `EISDIR` via
  `create_file_with_mode` and leave the directory untouched. 7z now fails the same way instead of
  deleting anything, propagating `ArchiveError::Io` with `ErrorKind::IsADirectory` preserved (routed
  out-of-band around the lossy `sevenz_rust2::Error` string-based conversion, which would otherwise
  collapse the kind to `Other` and risk misclassifying certain destination paths as encryption
  errors). A pre-existing *symlink* at the destination — including one pointing at a directory — is
  handled separately by #477/#478's `ELOOP` rejection (see `### Security` below) and never reaches
  this check. **Behavior change**: callers relying on 7z silently overwriting a pre-existing
  destination directory must now handle an extraction failure for that entry instead.
- **`exarch-core`: 7z `skip_duplicates = true` pushed one unbounded warning `String` per
  pre-existing-duplicate entry (#484)**: `report.warnings` grew by one entry per skipped duplicate,
  proportional to archive size with no cap. Replaced with a single aggregated warning
  (`"skipped N entries as pre-existing duplicates"`) emitted once extraction completes, if any
  entries were skipped this way. `report.files_skipped`'s count is unaffected. TAR/ZIP's equivalent
  per-entry duplicate-skip warning was fixed the same way in #490.
- **`exarch-core`: 7z `skip_duplicates` check missed a dangling symlink at the destination path
  (#468)**: `dest_path.exists()` follows symlinks and returns `false` for a dangling symlink, so a
  pre-existing dangling symlink occupying an entry's destination silently passed the duplicate
  check instead of being detected. With `skip_duplicates = true` the entry is now correctly skipped
  rather than silently replacing the symlink; with `skip_duplicates = false`, this check's own
  destination is still replaced via `rename` rather than followed, so this specific check is not a
  symlink-escape vector (unlike TAR/ZIP, which hard-fail via `O_NOFOLLOW` here — that cross-format
  divergence is tracked separately in #477). This is unrelated to the temp-file creation step
  earlier in the same write path, which is a separate, open symlink-escape vector tracked as #471.
  Replaced the check with `dest_path.symlink_metadata().is_ok()`, matching the same simplification
  applied to `formats::common::create_symlink`'s equivalent duplicate check.
- **`sanitize_path_for_error`/`sanitize_io_error_for_error` duplicated verbatim across bindings
  (plus a third, unused copy in `exarch-core` itself), and over-redacted attacker-authored paths
  (#463, #462)**: the profile-gated redaction helpers added by #453 were byte-identical,
  independently-maintained copies in `crates/exarch-python/src/error.rs` and
  `crates/exarch-node/src/error.rs`, with no shared source or cross-binding test; a third,
  never-called copy of the same policy also lived in `ArchiveError::to_ffi_message` and carried
  the same bugs. Hoisted the two binding-local helpers into a new `exarch-core` module,
  `error::redaction` (re-exported as `exarch_core::sanitize_path_for_error`,
  `exarch_core::format_entry_path_for_error`, and `exarch_core::sanitize_io_error_for_error`) —
  both bindings' `convert_error` bind the path per match arm and call the correct algorithm
  directly (preserving the compiler's exhaustiveness guarantee that a new `ArchiveError` variant
  forces every call site to handle it explicitly), and `ArchiveError::to_ffi_message` (previously
  the buggy third copy, see `### Changed` for its resulting signature break) calls the same two
  algorithms via a new `ArchiveError::redacted_path()` helper. Only the two redaction algorithms
  are single-sourced this way — the variant-to-algorithm mapping itself is still applied
  independently in three places (`redacted_path()`, and each binding's `convert_error`), guarded
  by tests in each. While hoisting, fixed over-redaction: `PathTraversal`, `SymlinkEscape`, and
  `HardlinkEscape` carry an archive-relative path the attacker authored inside the archive entry,
  not a host filesystem path (see `exarch-core/src/types/safe_path.rs` and `safe_symlink.rs`), so
  redacting them to filename-only in release builds hid nothing from the attacker while destroying
  the defender's ability to identify the offending entry in redacted logs. These three variants —
  and `InvalidPermissions`, which carries the same kind of archive-relative entry path (see
  `inspection::verify`) — now keep the full path in both debug and release builds.
  `SourceNotFound`, `SourceNotAccessible`, `OutputExists`, `UnknownFormat`, and `Io` are unaffected
  and remain redacted to filename-only (or `ErrorKind` description, for `Io`) in release builds,
  since those genuinely carry host-derived paths. **Behavior change**: release-build error
  messages for `PathTraversal`, `SymlinkEscape`, `HardlinkEscape`, and `InvalidPermissions` now
  include the full archive entry path where they
  previously showed only the filename.

- **`io::Error::other(...)` call sites collapsed to the uninformative "other error" message in
  release builds after #453's redaction fix (#464)**: `#453` reduced `CoreError::Io` messages to
  their `std::io::ErrorKind` description in release builds to close a host-path leak, which is
  sound for OS-originated `ErrorKind`s but degraded every `ErrorKind::Other` call site (built via
  `std::io::Error::other(...)` in `creation::walker`, `creation::zip`, and the I/O-class branch of
  `formats::sevenz`'s error mapping) to the fixed string "other error", losing all diagnostic
  value. Added `exarch_core::IoContext`, which pairs a static, non-path-bearing summary (e.g.
  "failed to read entry metadata") with the dynamic detail (which may embed a host path) at each
  of those call sites. `exarch-core`'s shared `sanitize_io_error_for_error` (see the `#463`/`#462`
  entry above, which hoisted it out of both bindings into `error::redaction`) now recognizes
  `IoContext` via `io::Error::get_ref` downcasting and surfaces its static `context` in release
  builds instead of the generic `ErrorKind` description, while debug builds continue to show the
  full detail. Because both bindings call that one shared function, they pick this up without
  binding-local logic. No host path can leak through `context`, since it is always a `&'static
  str` fixed at the call site. The redaction itself is unit-tested in `error::redaction`, and the
  release-mode behaviour is asserted end-to-end against the compiled bindings by `exarch-python`'s
  `tests/test_error_redaction.py` and `exarch-node`'s `tests/error-redaction.test.js`, which
  trigger a real walkdir failure through `create_archive` and check that the `IoContext` summary
  survives while the host path and raw OS detail do not.

- **`exarch-node`: a throwing progress callback crashed the process uncatchably (#465)**:
  `NodeProgressAdapter` dispatched the JS progress callback via `ThreadsafeFunction::call` in
  fire-and-forget `NonBlocking` mode, which routes a JS throw through `napi_fatal_exception` —
  terminating the process with an uncatchable `uncaughtException`, even when the call site was
  wrapped in `try`/`catch`. The adapter now awaits `ThreadsafeFunction::call_async_catch` (via
  `Handle::block_on`, since the dispatch runs on a `spawn_blocking` worker thread) and captures a
  JS throw into the adapter instead; the captured error now rejects the returned promise rather
  than crashing the host process. This covers both `extractArchiveWithProgress` and — since the
  create-side progress API landed in #469 — `createArchiveWithProgress`, which share the adapter.
  Because the operation cannot be aborted from a progress callback (the `ProgressCallback`
  contract has no cancellation signal), a callback throw and a core failure can both occur in
  the same run — neither is discarded. When the core operation also failed, its error stays
  primary and keeps its error-code prefix (`SYMLINK_ESCAPE`, `QUOTA_EXCEEDED`, `IO_ERROR`, …) at
  the start of the message with a fixed ` | progressCallbackError: see cause` marker appended, so
  a throwing callback cannot mask a security violation from callers matching on that prefix. When
  the operation succeeded, the rejection is prefixed `PROGRESS_CALLBACK_ERROR` and carries
  `filesExtracted=N, bytesWritten=M` (extraction) or `filesAdded=N, bytesWritten=M` (creation), so
  callers can still tell what was written to disk. In both cases the original JS exception is
  preserved as the rejection's `cause` property, retaining its class and stack; its text and stack
  are never copied into the message, since the stack embeds an absolute host path (which #453
  redacts everywhere else in release builds) and the throw content is attacker-influenced whenever
  the callback echoes archive entry data — read `cause` for the callback's detail rather than
  parsing it out of `message`.
  At the time this landed, throwing a bare primitive (string, number, boolean) from the callback
  was a known, documented limitation that still crashed the process on both `*WithProgress`
  functions; see the following entry for the fix.
  `createArchiveWithProgressSync` cannot use the awaiting dispatch at all: it runs on the JS
  thread, so no tokio runtime is entered (`Handle::current()` panicked) and awaiting a call that
  only the blocked event loop can deliver would deadlock. It now dispatches unawaited and is
  documented accordingly — every call arrives after the function has already returned its
  `CreationReport`, so a throw cannot be merged into the result and instead surfaces as an
  ordinary `uncaughtException`, observable via `process.on('uncaughtException', …)`. Because that
  path never enters `call_async_catch`, the primitive-throw crash above never applied to it —
  string, number, and boolean throws already reached `uncaughtException` intact, exactly like an
  `Error` throw, so it needed no fix and is unaffected by the following entry.

- **`exarch-node`: throwing a bare primitive from a progress callback still crashed the process
  (#473, follow-up to #465)**: #465's fix above only covered `Error`/object throws on
  `extractArchiveWithProgress` and `createArchiveWithProgress` — a callback throwing `'oops'`,
  `42`, or `true` still crashed the process uncatchably, because the `napi_invalid_arg` status
  that `call_async_catch`'s dispatcher gets back from `napi_create_reference()` on a primitive
  exception value is escalated to `napi_fatal_exception` regardless of the exception having
  already been delivered correctly to the Rust side — an upstream napi-rs 3.12.0 defect that
  cannot be fixed from this crate. Both functions now wrap the user-supplied `progress` callback
  in a small JavaScript shim (built via `Env::run_script`, applied inside a shared
  `ProgressCallback::from_napi_value` impl before the `ThreadsafeFunction` is constructed) that
  catches any synchronous throw and, unless the thrown value is already an object or function
  `napi_create_reference()` can reference, re-throws a new `Error` carrying the original value as
  `cause` — so napi-rs's dispatcher never observes a primitive crossing the callback boundary in
  the first place. A non-function `progress` argument is now also rejected immediately via a
  `ValueType` check, instead of running the whole operation to completion first. Does not cover an
  `async` progress callback whose returned `Promise` rejects with a primitive — a `try`/`catch`
  only observes synchronous throws — nor `createArchiveWithProgressSync`, which was never affected
  by this class of bug (see the preceding entry).

- **`exarch-python` error messages leaked full absolute paths in release builds, and both
  bindings leaked host paths embedded in `CoreError::Io` messages (#453)**:
  `crates/exarch-python/src/error.rs` called `path.display()` directly and unconditionally for
  every path-carrying `ArchiveError` variant (`PathTraversal`, `SymlinkEscape`, `HardlinkEscape`,
  `InvalidPermissions`, `SourceNotFound`, `SourceNotAccessible`, `OutputExists`,
  `UnknownFormat`), unlike `exarch-node`'s equivalent module which already redacted paths to just
  the filename in release builds. Added a profile-gated `sanitize_path_for_error` helper matching
  `exarch-node`'s behavior (full path under `debug_assertions`, filename only otherwise) and
  routed every path-carrying variant through it. Separately, `CoreError::Io` was found to bypass
  redaction in **both** bindings: `exarch-core`'s `DestDir` validation (e.g. "directory is not
  writable: `{canonical_path}`") embeds a fully-canonicalized host path directly in the `io::Error`
  message text, reachable from every extraction call via `DestDir::new_or_create`, and neither
  binding's `Io` arm redacted it. Since the message is free-form text with no structured path
  field, added a `sanitize_io_error_for_error` helper to both bindings that keeps the full
  `Display` output under `debug_assertions` but reduces it to just the `std::io::ErrorKind`
  description in release builds, closing the same leak class at the one variant that had been
  missed. Neither `exarch-python` nor `exarch-node` now leaks internal directory structure in
  release-build error messages.
- **`exarch-cli` human-readable sizes >= 1 TB rendered as an inflated GB figure instead of TB
  (#451)**: `HumanFormatter::format_size` (`crates/exarch-cli/src/output/human.rs`) and
  `progress::humanize_bytes` (`crates/exarch-cli/src/progress.rs`) were two independent
  byte-humanization implementations; only the `progress` copy had a TB tier. Consolidated both into
  a single `output::humanize_bytes` (`crates/exarch-cli/src/output/mod.rs`) with the TB-inclusive
  ladder, so `extract`/`list --long --human-readable` output for archives or entries at or above 1
  TB now shows `"... TB"` instead of a misleadingly large GB number (e.g. `u64::MAX` bytes now
  renders `"16777216.0 TB"`, not `"17179869184.0 GB"`).
- **TAR/ZIP file writes only observed their `QuotaPermit` by shared reference instead of
  consuming it (#445)**: unlike 7z's `write_file_with_permit` (#440), `formats::common`'s shared
  `extract_file_generic` runtime-guarded `ValidatedEntryType::File(_)` against `&ValidatedEntry`
  and never took ownership of the permit. Renamed it to `extract_file_with_permit`, taking
  `safe_path: &SafePath`, `mode: Option<u32>`, and `permit: QuotaPermit` by value instead of
  `&ValidatedEntry`; `formats::common::create_directory` narrows to `&SafePath` for the same
  reason (its body only ever read `validated.safe_path()`). TAR's extraction dispatch now matches
  exhaustively on `ValidatedEntry::into_parts()`, so only the `File` arm can even bind a
  `QuotaPermit` — a compiler-enforced impossibility, not a runtime check. ZIP's dispatch also
  calls `into_parts()` and moves the permit by value, but retains a runtime
  `let ValidatedEntryType::File(permit) = entry_type else { return Err(..) }` fail-closed guard,
  since ZIP's file/directory/symlink branches aren't a single exhaustive match; this relies on
  `EntryValidator::validate_entry(&EntryType::File, ..)` always producing
  `ValidatedEntryType::File`, an invariant covered by the existing `test_validate_file_entry`. No
  quota arithmetic or validation behavior changed for either format.

- **7z file writes discarded their `QuotaPermit` instead of consuming it (#440)**: unlike TAR/ZIP,
  7z's `ValidatedEntryType::File(_)` write arm matched the permit and dropped it via `_`, so the
  capability-token guarantee introduced in #436 covered TAR and ZIP but not 7z. Added
  `ValidatedEntry::into_parts()` (a consuming accessor, since `QuotaPermit` is neither `Clone` nor
  `Copy` and `entry_type()` only lends a shared reference) and a new `write_file_with_permit`
  helper in `formats/sevenz.rs` that takes `QuotaPermit` by value, mirroring
  `formats::common::copy_file_with_permit`. 7z's atomic temp-file-then-rename write now cannot
  compile without a genuine permit obtained from `EntryValidator::validate_entry`. No quota
  arithmetic or validation behavior changed.

### Performance

- **Extracting archives with many small files regressed ~15.8% after #436/#437/#439 (#446,
  partial recovery)**: `formats::common::extract_file_with_permit`'s duplicate-detection now
  folds the existence check into the file-creation `open()` call (see the `O_EXCL`/`O_NOFOLLOW`
  entry under Security below) instead of a separate `output_path.exists()` stat followed by a
  truncating create — one fewer syscall per extracted file. This is primarily the security fix
  described below; the syscall reduction is a side-benefit, not the reason it was made. Also added
  `#[inline]` to `EntryValidator::validate_entry`/`check_ratio` and `SecurityConfig`'s
  `Deref::deref`, on the hot per-entry validation path. Re-verified via a controlled same-session
  A/B (`criterion --save-baseline`): `many_small_files/10000` improved -8.3% to -8.9%
  (p <= 0.01, reproduced twice); `/100` and `/1000` showed no significant change. This is a
  **partial**, not full, recovery of the confirmed +15.8% regression — the regression's root cause
  was not otherwise identified, and full parity against the original CI baseline still needs
  confirmation on CI hardware rather than local benchmarks (which showed >20% same-commit swings
  during this investigation).

- **`many_small_files`/`file_count_scaling` benchmarks were timing `TempDir` cleanup as part of
  extraction cost (#446)**: `benchmark_many_small_files` and `benchmark_file_count_scaling` in
  `crates/exarch-core/benches/extraction.rs` timed `TempDir::drop()` (recursive deletion of every
  extracted file) inside criterion's `b.iter()`, alongside the `ZipArchive::extract()` call being
  measured — `sample` profiling attributed ~87% of the `many_small_files/10000` wall time to this
  cleanup, not to extraction. Switched both benchmarks to `b.iter_custom`, excluding only
  `TempDir::new()`/`drop()` from the timed window. dhat heap-allocation profiling showed
  byte-identical allocations across the regression window, and re-measurement on the corrected
  harness shows no residual regression vs. the ci-076 baseline: the originally reported +15.8% was
  inflated by this harness bug on top of the real regression already addressed above by #470's
  syscall reduction. This dev machine's benchmark noise floor (40-80% run-to-run variance under
  shared load, observed during this investigation) still exceeds the project's 10% regression
  threshold, and no CI workflow currently runs `cargo bench` (`bench-build` only compiles
  benchmarks) — the "confirmation on CI hardware" noted above is not currently achievable and
  should be read as aspirational pending a dedicated benchmark-running job, not a completed step.

### Security

- **`exarch-core`: 7z's `skip_duplicates = false` path silently replaced a pre-existing symlink at
  the destination instead of rejecting it, and quota was reserved before the duplicate-skip
  decision (#477, #478)**: the #468 fix below (`skip_duplicates.symlink_metadata()`) closed the
  duplicate-*detection* gap for `skip_duplicates = true`, but as that entry's own text noted,
  `skip_duplicates = false` was left unresolved and tracked separately here. `process_entry_inner`
  now `lstat`s the destination via a shared `lstat_dest` helper before doing anything else with it:
  with `skip_duplicates = false`, a symlink there (dangling or live) now fails with the same `ELOOP`
  I/O error TAR/ZIP's `O_NOFOLLOW` open produces, instead of `write_file_with_permit`'s
  temp-file-then-`rename` silently unlinking and replacing it — `rename(2)` itself never followed
  the symlink even pre-fix, so this was a silent-replacement bug, not a symlink-escape (content
  never wrote through the link to its target). A regular file or directory at the destination is
  still overwritten as before; only a symlink is now rejected. Separately, quota (`reserve_file`,
  a new `EntryValidator` method mirroring the existing `reserve_hardlink`) is now reserved *after*
  this check and after the duplicate-skip decision, not before: previously every entry's quota was
  reserved unconditionally via `validate_entry` before the destination was even inspected, so an
  entry skipped as a duplicate permanently consumed its file-count/byte-size allotment (`QuotaPermit`
  has no `Drop` impl to release it). Both fixes apply identically to `SevenZArchive::extract`'s Step
  1 pre-validation pass, which previously used neither check, so a symlink-at-destination or a
  since-skipped duplicate could pass pre-validation and only fail (or over-consume quota) partway
  through the later extraction pass. New `EntryValidator::validate_entry_path` splits path
  validation out of `validate_entry` so callers needing the destination path before deciding on
  quota (7z's duplicate check, mirroring `reserve_hardlink`'s existing decoupling for hardlinks) no
  longer have to reserve quota just to get it.
- **A pre-planted symlink at a predictable/checked destination path bypassed a `Path::exists()`-style
  duplicate check, and the subsequent non-exclusive write followed it outside the extraction root
  (#471, #467)**: two more instances of the vulnerability class fixed for TAR/ZIP's normal-file
  write path in #459 below, found in the two write paths that fix did not cover. In 7z's
  `write_file_with_permit` (`formats/sevenz.rs`), the temp-file-then-rename write path derived its
  temp file name from the process PID and a per-process monotonic counter — predictable — and opened
  it with a plain `File::create`, which follows an existing symlink (dangling or not) instead of
  refusing it; fixed by opening with `OpenOptions::create_new`, retrying with a fresh counter value
  on `AlreadyExists` up to `MAX_TEMP_FILE_CREATE_ATTEMPTS` (8) times. In TAR's `create_hardlink`
  (`formats/tar.rs`), `Path::exists()` returns `false` for a dangling symlink at the hardlink's
  destination, so a pre-planted one bypassed the duplicate-detection check entirely, and the
  subsequent `std::fs::copy` followed it; fixed by opening the destination with
  `OpenOptions::create_new` first — folding the duplicate check into the `open()` call itself — then
  copying the hardlink target's content into the already-open handle via a new
  `common::copy_file_content_with_permit`, which replaces the now-removed path-based
  `common::copy_file_with_permit`. Both fixes share a new `common::TempFileGuard` RAII cleanup type
  (hoisted out of `formats/sevenz.rs`, previously private to that module) so a fallible step between
  file creation and the operation's success point does not leave a partial artifact behind on the
  error path. Both preconditions require an attacker-writable destination directory, not a malicious
  archive alone. `create_hardlink`'s *read* side had a narrower version of the same class: hardlink
  targets are validated for containment in a first pass (`HardlinkTracker::validate_hardlink`,
  resolving on-disk symlinks as of that point in time) but the two-pass design defers actually
  reading the target to a later, second pass with nothing re-validating it in between — a plain
  path-based `File::open`/`std::fs::metadata` in that second pass would silently follow whatever
  ended up at the target path by then, which an attacker with write access to the destination could
  swap out after the first pass validated it (TOCTOU, not an unconditional read: a symlink present
  *before* the first pass runs is already rejected there, per #116). The same path-based `stat`
  also left quota sizing vulnerable to the same swap, independent of the read TOCTOU (bypassing
  #426's per-hardlink accounting). Both are closed by a new `common::open_no_follow`, which opens
  the target exactly once with `O_NOFOLLOW` (Unix), so any symlink present by the second pass
  fails the open instead of being followed; `copy_file_content_with_permit` now takes that
  already-open handle instead of a path, and the quota reservation is sized from the same handle's
  `fstat` rather than a separate `stat` call. A symlink at the target is not automatically treated
  as an attack, since it is a legitimate archive shape for a hardlink's target to be a symlink
  created earlier in the same extraction (already first-pass-validated): on `open_no_follow`
  returning `ELOOP`, `create_hardlink` re-runs the first pass's own `resolve_through_symlinks`
  containment check against the current on-disk state and, if it still resolves inside the
  destination, opens the resolved path instead of failing outright.
- **Dangling symlink at the extraction destination bypassed the duplicate-check and allowed
  writing outside the destination root (#459, pre-existing, TAR and ZIP)**: the duplicate-existence
  check used `Path::exists()`, which follows symlinks and returns `false` for a dangling one. A
  symlink already present at the destination path — planted by something other than the archive
  being extracted, since `SafeSymlink::validate` already prevents an in-archive symlink entry from
  escaping `dest` — was therefore treated as "no duplicate," and a plain `File::create` followed
  the link, writing the entry's content outside the extraction root. Fixed by opening the
  destination file with `O_EXCL` (via `OpenOptions::create_new`, already required for the
  `skip_duplicates=true` duplicate-detection path) and, on Unix, unconditionally with `O_NOFOLLOW`
  (`OpenOptionsExt::custom_flags`): both reject an existing symlink, dangling or not, instead of
  following it, closing the escape on both `skip_duplicates` values (the `skip_duplicates=false`
  overwrite path previously had no protection at all). Added regression tests planting a dangling
  symlink at the destination path before extraction for both `skip_duplicates` settings.
  Precondition is an attacker-writable destination directory, not a malicious archive alone.

- **File permissions were applied via a path-based `set_permissions()` after `open()`, reopening a
  TOCTOU window (#460)**: the same `formats::common::create_file_with_mode` helper enforced the
  sanitized (setuid/setgid-stripped) mode with `std::fs::set_permissions(path, ..)`, which
  re-resolves `path` from the filesystem root rather than operating on the already-open file
  descriptor, letting a concurrent attacker swap the path for a symlink between `open()` and
  `set_permissions()`. Switched to `File::set_permissions(&file, ..)`, which applies the mode via
  `fchmod` on the open descriptor and cannot be redirected by a later filesystem change.

- **`list` accepted NUL bytes, empty targets, and missing targets that `extract`/`verify` already
  rejected (#430)**: `list_tar_entries` and `list_zip_reader` validated entry paths for path
  traversal but not embedded NUL bytes, unlike `SafePath::validate` (used by `extract`). For TAR,
  this meant `exarch list`/`list_archive` silently returned a NUL-containing path as an ordinary
  entry instead of rejecting the archive. ZIP was affected differently: the `zip` crate's own
  `enclosed_name()` already rejects a NUL-containing name under the default configuration, so that
  case was already rejected pre-fix — just via the wrong mechanism (`PathTraversal`, from
  `enclosed_name()` returning `None`, rather than a NUL-specific error). Only ZIP's
  `allow_absolute_paths` fallback path — which reads the raw entry name directly, bypassing
  `enclosed_name()` — was genuinely silent pre-fix, the same way TAR was unconditionally. The same
  asymmetry existed for symlink/hardlink targets
  relative to the checks `extract` gained in #424: an empty or NUL-containing target, or (TAR
  only) a symlink/hardlink entry with no target at all (`link_name()` returns `None` — no ustar
  linkname field and no PAX `linkpath` override), was silently accepted by `list`. `list_tar_entries`
  and `list_zip_reader` now reject a NUL byte in the entry path (checked before path-traversal, in
  both formats, for consistent ordering), and a new `validate_link_target` helper (mirroring
  `SafeSymlink::validate`/`HardlinkTracker::validate_hardlink`'s wording, though it only checks
  emptiness and NUL bytes — it does not give `list` full parity with `extract`'s target validation)
  rejects an empty or NUL-containing `symlink_target`/`hardlink_target`; `list_tar_entries`
  separately rejects a `None` link target with the same `InvalidArchive` message `extract` uses
  (`"symlink missing target"` / `"hardlink missing target"`). 7z listing was not changed:
  `sevenz_rust2::Archive::read` decodes each entry name as UTF-16 and stops at the first zero code
  unit while parsing the header, so an embedded NUL cannot reach `list_sevenz_archive` in the first
  place.
  **`verify_archive`'s report-based behavior is preserved**: `verify_archive` lists the archive as
  a pre-flight step before building its report, and `verify_entry` already had its own working
  graceful handling for all of the above (a NUL-byte entry path via `validate_path`, and an empty/
  NUL/missing link target via `validate_symlink`/`validate_path`, added in #424) — surfacing each as
  a `VerificationIssue` rather than aborting. An earlier round of this fix let the new list-level
  checks abort that pre-flight step before `verify_entry` ever ran, silently turning those graceful
  reports into hard `Err` results (and, for the Python/Node bindings, a report object into a raised
  exception) — caught and reverted before merging. `listing_config_for_verify` now also relaxes the
  list-level NUL-byte/empty/missing-target checks (`SecurityConfig::relaxed_for_verify_preflight`,
  a crate-internal config flag, not part of the public builder API) for `verify_archive`'s pre-flight
  listing call specifically, so `verify` continues to report rather than abort. Bare `exarch list`/
  `list_archive` is unaffected by this flag and still hard-aborts on all of the above — that hard
  behavior is the actual #430 fix.
- **TAR metadata-entry decompression bomb (#414)**: GNU long-name (`L`), GNU long-link (`K`),
  and PAX extended header (`x`/`g`) records are buffered fully into memory by the `tar` crate's
  internals before any entry reaches `exarch-core`'s validator or quota tracker, so a crafted
  record declaring a multi-gigabyte length backed by a tiny compressed stream caused unbounded
  allocation with no quota enforcement (measured: a 765 KB `.tar.gz` reached 4.95 GB peak RSS on
  `extract`, 3.29 GB on `verify`, 2.49 GB on `list`). Added `SecurityConfig::max_tar_metadata_bytes`
  (default 4 MiB, 16 MiB for `SecurityConfig::permissive()`) enforced by a new
  `formats::tar_metadata_limit` read-budget mechanism: a reader wrapper meters bytes the `tar`
  crate reads while searching for the next entry (headers, long-name/long-link/PAX records, GNU
  sparse extension blocks) and errors once the budget is exceeded, before any oversized
  allocation completes. Applied uniformly to `extract_archive`, `list_archive`, and
  `verify_archive` (including `TarArchive`'s `ArchiveFormat` trait methods), since all three
  previously opened `tar::Archive` independently.

  An initial version of this fix re-parsed TAR headers in a shadow parser to reject an oversized
  *declared* size before the `tar` crate could buffer it. Three rounds of adversarial review each
  found a fresh case where that shadow parser's belief about entry framing diverged from the
  `tar` crate's own (an untracked PAX `size=` override hiding a bomb behind a mis-framed decoy
  entry; the same bypass again when the overriding PAX header had invalid magic, since `tar` only
  honors an override when the header is `is_recognized_header`; and again via a PAX global header
  draining `tar`'s override state without draining the shadow parser's mirrored state) — three
  independent divergences in three rounds, each closed individually but never provably
  exhaustive. The mechanism actually shipped replaces the shadow parser entirely: it never parses
  a header, typeflag, magic byte, or PAX record, so there is exactly one parser (the `tar`
  crate's own) and nothing left to diverge from it. Every yielded entry is fully drained (bounded,
  not run to true EOF — an unbounded drain would let a crafted GNU sparse entry's synthesized
  zero-padding become a separate unbounded CPU sink) before the budget re-arms for the next gap,
  so the budget never depends on any declared size, override, or magic validity.

  A follow-up review found that the drained-on-drop bound above was itself sourced from the
  caller's `max_file_size` quota — a value `inspection::verify::listing_config_for_verify` (the
  `verify_archive` pre-listing pass) legitimately relaxes to `u64::MAX` so metadata-only listing
  does not false-reject large files. A GNU old-format sparse entry (`typeflag 'S'`) can declare a
  `realsize` field up to `u64::MAX` (via GNU base-256 encoding) while backed by a single physical
  block, so the relaxed quota silently defeated the drain bound on `verify` specifically,
  reintroducing an unbounded, memory-invisible (drained to `io::sink`, so no corresponding heap
  growth) CPU-exhaustion hang scaling linearly with the attacker-chosen `realsize` (measured: a
  113-byte `.tar.gz` drove `verify` to 3.98 s at a 400 GiB `realsize`, with throughput implying a
  `u64::MAX` value would hang for years).

  Two successive fixes that instead sourced the drain bound from a fixed value (first
  `max_tar_metadata_bytes`, 4 MiB, on the shared `list`/`verify` path; then, after that turned out
  to false-reject any archive with a single entry over ~8 MiB, an "absolute cap" of 16 MiB applied
  everywhere) were each found to reopen the same class of bug in the opposite direction: `list`,
  `verify`, and even `extract` (via the CLI's `list_archive` pre-flight) rejected perfectly
  ordinary archives — a ~765 KB legitimate file was rejected with a `SecurityViolation` — because
  `list`/`verify` never read entry content at all, so the drain is the *only* thing consuming a
  legitimate entry's real bytes to reach the next header, and any *fixed* cap on total drained
  output eventually clips some legitimate entry's real content, however generous the cap.

  The mechanism that actually shipped bounds the drain by **synthesized** bytes instead of total
  output: `formats::tar_metadata_limit::BudgetedReader` now tracks a monotonic count of bytes
  actually read from the underlying reader, and `TarEntryGuard::drop` drains in a loop comparing
  bytes output so far against bytes actually read during the same drain. A legitimate entry's
  drain consumes real bytes 1:1 with what it outputs, so this "synthetic" gap stays at (or within
  a read-chunk's rounding of) zero regardless of entry size, and the entry always drains to
  completion; GNU sparse zero-padding is the opposite — `tar` yields it from `io::repeat(0)` with
  no corresponding read — so the gap grows every iteration and trips a small, fixed,
  non-configurable cap almost immediately regardless of the declared `realsize`. This closes both
  directions of the bug from one mechanism, without ever inspecting a header field to tell the two
  cases apart.
- **Symlink/hardlink targets were not validated for embedded NUL bytes or emptiness (#415)**:
  the link path was already checked for NUL bytes and emptiness via `SafePath::validate`, but
  the target (linkname) was not — a NUL byte in the target fell through to the OS as a raw
  `io::Error` instead of a structured `SecurityViolation`, an empty target was silently accepted
  (creating a dangling symlink on platforms that allow it), and a NUL-containing hardlink target
  could be embedded verbatim into a formatted error message further downstream. `SafeSymlink::validate`
  and `HardlinkTracker::validate_hardlink` now apply the same NUL-byte and emptiness checks to
  the target as the link path (`types::safe_path::has_null_bytes` made `pub(crate)` for reuse),
  without ever embedding the raw target bytes into an error message. A short (<=100 byte)
  linkname written through the `tar` crate's own header field cannot carry an embedded NUL byte
  or reach an empty value while non-`None`, so the regression tests use a GNU `LongLink` (`K`)
  record's raw payload to smuggle both past the header-field-level shortcuts, exercising the
  same path a real crafted archive would take.
- **TAR extension-filter skip has no cumulative bound on synthesized drain across many small
  sparse entries (#422)**: the per-entry synthetic-byte drain cap from #414 bounds the cost of any
  *single* unread GNU sparse entry, but when `SecurityConfig` has an extension allowlist
  configured, entries that fail the extension check are skipped before `QuotaTracker` ever runs
  (intentional, per #421's fix for quota double-counting) — so `max_total_size`/`max_file_count`
  provided no cumulative bound across many such pre-quota skips (measured: a ~20 MB archive of
  20,000 small extension-filtered GNU sparse entries took ~1.41 s to extract, versus ~150 ms for
  the same archive without an extension filter, which hits `QuotaExceeded` immediately). Added a
  second, cumulative counter to `formats::tar_metadata_limit::TarReadBudget`: every
  `TarEntryGuard::drop`'s own synthesized-byte count is now summed across the whole archive-open
  operation, and `BudgetedEntries::next_entry` fails fast with a `SecurityViolation` once the sum
  exceeds a fixed, non-configurable 1 GiB cap (roughly 128 maximally-saturating entries), rather
  than continuing to drain further entries. The check lives in `next_entry` itself, so it applies
  uniformly to `extract_archive`, `list_archive`, and `verify_archive` regardless of
  extension-filter ordering — including `list_archive`/`verify_archive`, which skip *every* entry
  unconditionally (they never read entry content at all), not only extension-filtered ones.

  An initial version of this fix used a much tighter 64 MiB cap (8x the per-entry cap). Adversarial
  review found that gave any legitimate archive of `list`/`verify`/extension-filtered-`extract`
  sparse entries only 8 entries of headroom before false-positiving with a `SecurityViolation`,
  since `list`/`verify` drain every entry unconditionally. The cap was raised to 1 GiB: worst-case
  cost stays a fixed, sub-second amount of wasted `io::sink` throughput regardless of entry count,
  while legitimate multi-entry sparse archives now have generous (~128-entry) headroom. This widens
  this module's existing documented residual limitation (a legitimate GNU sparse file with real
  holes larger than the per-entry cap is indistinguishable from an attack when skipped unread) from
  a single oversized entry to roughly a hundred such entries in aggregate — still an accepted,
  documented trade-off (P3), not a new bug.
- Bumped `sevenz-rust2` from 0.21.3 to 0.21.4, fixing an integer overflow when summing
  attacker-controlled coder stream counts while parsing a 7z block header (upstream #127).
  Malformed archives previously could panic in debug builds and bypassed the stream-count
  bound in release builds; they are now rejected with an error (#397). This also pulls in a
  transitive `lzma-rust2` bump from 0.16.5 to 0.18.0 (required by sevenz-rust2's own `^0.18`
  dependency), which rearchitects the LZMA2/XZ decoders into a sans-I/O design — no known
  advisories against either version; audited with no regressions found.
- **Release profile aborted on panic, silently disabling FFI panic guards (#395)**: the
  workspace `[profile.release]` set `panic = "abort"`, which made every `catch_unwind` guard in
  `exarch-python` and `exarch-node` dead code in published wheels and npm packages — a Rust
  panic inside `extract_archive`/`create_archive`/etc. aborted the whole Python or Node.js
  process instead of surfacing as a catchable exception/error. Removed `panic = "abort"` from
  `Cargo.toml` so release builds unwind (this also lets `exarch-cli`'s `Drop` impls run cleanup
  on panic). Added a compile-time `const _: () = assert!(cfg!(panic = "unwind"), ...)` guard near
  the top of both binding crates' `lib.rs` so any future reintroduction (workspace profile,
  `.cargo/config.toml`, or `RUSTFLAGS`) fails the build instead of silently reintroducing the
  vulnerability. Also closed a related gap in `exarch-python`: the progress-callback branches of
  `create_archive_with_progress` and `extract_archive_with_progress` had no `catch_unwind` at
  all (only the no-callback branch was guarded) — both branches are now wrapped, mirroring
  `exarch-node`'s existing helper shape. Added runtime regression coverage of the
  `catch_unwind` -> exception/error conversion itself: `exarch-node` gained a Rust-level test
  that calls the real `catch_panic_as_js_err` production helper with a panicking closure and
  asserts a catchable `Error` comes back; `exarch-python` gained an end-to-end pytest
  (`test_panic_safety.py`) that triggers a real panic through the compiled extension module via
  a `panic-injection`-feature-gated test hook and asserts a catchable `RuntimeError` is raised
  instead of the process aborting (the feature is only enabled by CI's `test-python` job, never
  in published wheels).

### Added

- Regression test coverage mapping node-tar GHSA vulnerability classes onto the TAR extraction
  pipeline (#399): GHSA-vmf3 (PAX/GNU long-name/long-link record smuggling and stream
  re-framing), GHSA-gvwx / GHSA-w8wr (NUL byte and malformed-field handling in PAX and GNU
  long-name records), and GHSA-23hp (declared-vs-actual entry size mismatches). All 13 cases
  currently pass — protection is inherited from the `tar` crate dependency, so these lock in
  that behavior against a future dependency bump.
- Regression test coverage for the `max_tar_metadata_bytes` read-budget mechanism (#414):
  `tests/security/tar_metadata_bomb.rs` covers `extract`/`list`/`verify`/`extract_archive`
  against oversized `L`/`K`/`x` records, a false-positive check for legitimate long paths, and
  the three historical shadow-parser bypass shapes (untracked PAX `size=` override,
  invalid-magic variant, and PAX-global-header state drain) reconstructed to confirm the budget
  mechanism rejects all three regardless — none of those shapes are individually meaningful to
  it any more, since it does not parse headers at all. `tests/tar_alloc_bound.rs` (its own
  top-level test binary, since `dhat`'s counting allocator is process-wide) measures actual peak
  heap usage — not just the returned error — across the historical shapes and ~100
  proptest-generated adversarial archives (random typeflags, magic validity, and declared sizes
  up to 4 GiB), asserting it stays orders of magnitude below the historical multi-GB measurements
  regardless of what the archive contains.
  `tests/security/tar_budget_parity.rs` guards against the mechanism's one real assumption (that
  `tar`'s iterator reads less than the budget between yields once every entry is drained) with a
  proptest comparing budgeted extraction output against a plain, unwrapped `tar::Archive` read
  for well-formed archives with long paths and many files, so a future `tar` crate bump that
  invalidates the assumption fails loudly here rather than silently rejecting legitimate archives
  in production.
- Regression test coverage for the synthesized-bytes drain bound above (#414): direct unit tests
  in `formats::tar_metadata_limit` confirm a legitimate entry (comfortably larger than the
  synthetic-bytes cap) drains to true completion, and that a real GNU old-format sparse header
  with an extreme `realsize` still stops draining within a small, bounded number of real bytes
  read. `tests/security/tar_metadata_bomb.rs` reconstructs the same sparse-header shape and
  asserts `verify_archive`, `list_archive`, and `extract_archive` all reject it within a bounded
  wall-clock time regardless of the claimed size, not just bounded heap usage. A companion test
  reproduces the exact false-positive size table found during this fix's own review (legitimate
  archives with a single 3/6/9/12/30/45 MiB entry) against `list_archive`, `verify_archive`, and
  `extract_archive`, and a further test confirms `extract` still fully skips a legitimately large
  (45 MiB) disallowed-extension entry and continues extracting the rest, checked through both
  `TarArchive::extract` directly and the public `extract_archive` API. `tests/tar_alloc_bound.rs`
  was extended to measure `list_archive` and `verify_archive` in addition to `extract`, and its
  random-archive generator now emits real GNU sparse header fields for typeflag `'S'` steps
  instead of an empty (and therefore non-sparse-triggering) header, so the fuzz corpus actually
  exercises the zero-padding code path this mechanism bounds.

  A known, accepted residual limitation of the synthesized-bytes design: a *legitimate* GNU
  sparse file with a real hole larger than the synthetic-bytes cap is indistinguishable, by pure
  byte accounting, from the attack shape when skipped unread on `list_archive`/`verify_archive` —
  both produce output with no corresponding read. This affects those two functions directly and,
  transitively, the `exarch` CLI's `extract` command (which runs its own `list_archive`
  pre-flight for progress-bar/conflict detection ahead of the actual extraction); it does *not*
  affect the `extract_archive`/`TarArchive::extract` library functions, which read the entry
  themselves and never reach the guard's drain unread. Accepted as a documented trade-off (P3
  follow-up filed separately) rather than fixed here, since it requires a real hole combined with
  several MiB of real data to reproduce and this PR has already been through four rounds of
  adversarial review. Pinned by a dedicated regression test in each of `tests/security/tar_metadata_bomb.rs`
  (`list_archive`/`verify_archive`/library `extract`) and `exarch-cli/tests/cli_tests.rs` (the CLI
  command specifically), so a future change to the cap cannot silently move this threshold
  without a test noticing.
- Regression test coverage for GHSA-qh76-45cr-8xrc / CVE-2026-61725 (7z Zip-Slip via
  `sevenz_rust2::decompress()`), confirming `SevenZArchive::extract` rejects both
  relative-traversal and absolute-path 7z entries via `EntryValidator` before any file is
  written, since exarch-core never calls the vulnerable upstream convenience API. A further
  test exercises the extraction-time re-validation layer directly, proving it independently
  rejects traversal as well (#398).
- Regression test for the #397 coder-stream-count overflow fix (upstream sevenz-rust2 issue
  #127), using the fixture ported from upstream's own regression test, confirming the
  malformed archive is now rejected gracefully instead of risking a panic (#397).
- **TAR hardlink extraction bypassed quota tracking entirely (#426)**: `EntryValidator::validate_entry`
  only ran `QuotaTracker::record_file` for `EntryType::File`, so hardlink entries (opt-in via
  `config.allowed.hardlinks`) never counted against `max_file_size`, `max_file_count`, or
  `max_total_size`, even though `TarArchive::create_hardlink` copies the target's full on-disk
  bytes via `std::fs::copy` for every hardlink entry. A crafted archive with one file within
  quota followed by many hardlink entries pointing at it extracted unlimited copies with zero
  enforcement. `EntryValidator` gained `record_hardlink`, and the TAR second pass now calls it
  with the target's on-disk size (read via `std::fs::metadata`) before copying, routing hardlink
  bytes and counts through the same `QuotaTracker` instance used for regular files.

### Fixed

- **TAR creation silently dropped empty directories (#400)**: `create_tar_internal_with_progress`
  in `crates/exarch-core/src/creation/tar.rs` only incremented a counter for `EntryType::Directory`
  entries without ever writing a directory header to the TAR stream. All four TAR variants
  (`.tar.gz`, `.tar.bz2`, `.tar.xz`, `.tar.zst`) plus plain `.tar` now write an explicit directory
  entry for every directory in the source tree (including empty and nested-empty directories),
  matching the ZIP handler's existing behavior. As part of this fix, `directories_added` in
  `CreationReport` now excludes the archive root itself (consistent with ZIP), so it may report
  one fewer directory than before for the same source tree.
- **`bytes_compressed` in `CreationReport` was inaccurate for every creation format (#402)**: ZIP
  never assigned `bytes_compressed` (always `0`, causing `compression_percentage()` to always
  report the "perfect compression" `100.0` fallback). TAR measured the pre-compression TAR
  stream size (headers + padding, before the gzip/bzip2/xz/zstd encoder), not the actual
  compressed bytes on disk. Both are now measured from the real on-disk archive file size after
  the writer/encoder is fully flushed and finished, for ZIP and all TAR variants (including plain
  `.tar`). `compression_ratio()` and `compression_percentage()` now reflect real compression
  results. The now-unused `crate::io::CountingWriter` (crate-internal only) was removed.
- **`list_archive()` re-implemented quota checks instead of reusing `QuotaTracker` (#396)**:
  the three per-format listing functions in `exarch-core`'s `inspection::list` module each
  duplicated total-size and file-count quota logic inline, independently of the `QuotaTracker`
  used by extraction. This duplicate implementation was weaker than the original: it never
  checked `max_file_size` per entry, and computed the running total-size check with unchecked
  `+` instead of `checked_add`, so a crafted archive with entry sizes near `u64::MAX` could wrap
  `total_size` in a release build and silently bypass `max_total_size` during listing. All three
  listing functions (TAR, ZIP, 7z) now route every entry through the same `QuotaTracker` used by
  extraction, closing both gaps. This does not make listing and extraction fully equivalent:
  extraction's `QuotaTracker` only records `EntryType::File`, while listing records every entry
  type (directories, symlinks, hardlinks too) — a pre-existing, unrelated divergence.

  **BREAKING CHANGE:** `list_archive()` and `verify_archive()` — and by extension the `list`/
  `verify` CLI subcommands and the `exarch-python`/`exarch-node` bindings — now reject any single
  entry larger than `max_file_size` (default 50 MB) during listing; previously only file count
  and total size were enforced there. `list`/`verify` gain a new `--max-file-size` CLI flag
  (mirroring `extract`/`create`) to raise this limit; there was previously no way to configure it
  for these two commands. `verify_archive()`'s internal pre-flight listing pass keeps
  `max_file_size` unlimited so an oversized entry still surfaces as a `VerificationIssue`
  (`Fail` status with an itemized report) via the existing per-entry check in `verify_entry`,
  rather than aborting before any report exists — `verify`'s "report, don't hard-fail" contract
  is preserved.
- **`SecurityViolation` error text was duplicated for pre-extraction violations (#403)**:
  `convert_extraction_error` in `exarch-cli` rebuilt the wrapped `ArchiveError`'s own Display
  text as anyhow context, so the reason (e.g. "banned path component: .git") appeared twice in
  both `--json` and human text output whenever a violation was caught during listing/
  pre-validation (banned path components, disallowed symlinks/hardlinks, disallowed solid 7z
  archives). The reason now appears exactly once, and the CLI's own context adds a hint naming
  the actual policy flags (`--allow-symlinks`, `--allow-hardlinks`, `--allow-solid-archives`,
  `--banned-component`) instead of repeating the source error's text.
- **Redundant `unsafe impl Send` on `PyProgressAdapter` in `exarch-python` (#405)**: pyo3 0.29's
  `Py<T>` is `Send` for all `T` unconditionally, so `PyProgressAdapter { callback: Py<PyAny>, .. }`
  already auto-derives `Send`. Removed the manual `unsafe impl Send` block; no `unsafe` code was
  actually required.
- **Stale generated `exarch-node/index.d.ts` (#404)**: the napi-rs generated type declarations
  still listed only 2 of the 7 default `banned_path_components` entries in the `SecurityConfig`
  doc comment table, out of sync with the Rust source. Regenerated via `napi build`.
- **`test-python` CI job uploaded duplicate coverage to Codecov 5x per run**: the job's
  `python-version` matrix (3.10-3.14) ran `pytest --cov` and uploaded to Codecov under the same
  `exarch-python` flag on every leg, even though all 5 legs exercise the same Rust-backed
  bindings and test suite. Coverage generation and the Codecov upload now run only on the 3.12
  leg; the other 4 legs still run the full test suite without coverage instrumentation. Also
  fixed `.github/codecov.yml`'s `after_n_builds` (was `1`, which raced the real 6-upload count
  per run and could post PR comments before all uploads landed; now `2`, matching the `coverage`
  and `test-python` jobs' single upload each), and added the missing `flags: exarch-core,
  exarch-cli` to the `coverage` job's upload — those two flags were declared with their own
  thresholds in `codecov.yml` but never received any tagged data.
- **TAR hardlink byte/count accounting used unchecked `+=` (#427)**: `TarArchive::create_hardlink`
  incremented `ExtractionReport::files_extracted`/`bytes_written`/`files_skipped` with plain `+=`
  after copying a hardlink's target bytes, inconsistent with `formats::common::extract_file_generic`'s
  `checked_add`-guarded `bytes_written` accounting. All three counters in `create_hardlink` now use
  the same `checked_add(..).ok_or(ArchiveError::QuotaExceeded { resource: QuotaResource::IntegerOverflow })`
  pattern; this is not yet a crate-wide guarantee, since `formats/common.rs` and `formats/sevenz.rs`
  still increment their own `files_extracted` counters with unchecked `+=`.
- **`cargo doc --workspace` silently overwrote one target's docs (#429)**: `exarch-cli`'s
  `[[bin]]` target and `exarch-python`'s `[lib]` target both used the crate name `exarch`, so
  rustdoc wrote both targets' output to the same path and one silently clobbered the other. The
  build itself still exited 0 — this is a `cargo`-level warning, not a rustdoc lint, so
  `RUSTDOCFLAGS="-D warnings"` never caught it. Renamed the `exarch-python` Cargo `[lib]` target
  to `exarch_pylib`; the `exarch-cli` binary name is unchanged since it is the user-facing name
  installed via `cargo install`. Considered and rejected `doc = false` on `exarch-cli`'s
  `[[bin]]` as a smaller alternative fix: it would resolve the collision in one line without
  touching Python packaging, but sacrifices exarch-cli's own rustdoc output, which the rename
  preserves for both targets. Also added `module-name = "exarch"` under `[tool.maturin]` in
  `crates/exarch-python/pyproject.toml`, since maturin otherwise derives the expected `PyInit_*`
  symbol name from the Cargo `[lib]` name and would no longer find the `#[pymodule] fn
  exarch(...)` entry point, breaking the Python extension import. The CI `Documentation` job
  (`.github/workflows/ci.yml`) now fails if `cargo doc`'s output contains an "output filename
  collision" warning, closing the gap that let this regression ship silently in the first place.

### Changed

- **Deduplicated `PartialExtraction` error-wrapping logic across format handlers (#394)**: the
  "wrap the error in `ArchiveError::PartialExtraction` if the report recorded any processed
  items, otherwise return it as-is" pattern was copy-pasted five times across `tar.rs`, `zip.rs`,
  and `sevenz.rs`. Consolidated into `ArchiveError::partial_or()`; behavior-equivalent at all
  current call sites (each site returns the error immediately afterwards, so evaluating
  `std::mem::take(report)` unconditionally rather than only inside the `total_items() > 0` branch
  is unobservable).
- **Deduplicated FFI boundary path validation between `exarch-python` and `exarch-node` (#406)**:
  both bindings independently rejected null bytes and paths over 4096 bytes for raw path strings
  supplied by callers, and the two implementations had drifted (a full-scan fold vs. a
  short-circuiting `contains` for the null-byte check, and no consistent check order). Both now
  call the new `exarch_core::validate_raw_path_str()`, which owns `MAX_PATH_LENGTH`, checks length
  before scanning for a null byte (rejecting oversized input in O(1) before the O(n) scan runs),
  and returns `ArchiveError::SecurityViolation`. Each binding routes that error through its
  existing `convert_error()` — the same converter used for every other security rejection — instead
  of hand-rolling a bespoke exception. This changes the concrete exception raised for null-byte and
  path-length rejections: Python now raises `SecurityViolationError` (previously a bare
  `ValueError`) and Node.js error messages now carry the `SECURITY_VIOLATION:` code prefix
  (previously unprefixed). Both were already documented as possible outcomes of these checks;
  acceptable pre-1.0 per the project's no-backward-compatibility policy.

## [0.5.2] - 2026-07-27

### Added

- **CLI binary releases**: `exarch-cli` release binaries are now built and attached to every
  GitHub release for Linux (x86_64, aarch64), macOS (x86_64, aarch64), and Windows (x86_64) as
  `exarch-<version>-<target>.tar.gz` / `.zip` archives with `.sha256` checksums.
- **`scripts/install.sh`**: a POSIX-sh installer that downloads, checksum-verifies, and installs
  the correct prebuilt `exarch` binary for the host platform. Also attached to every release.
- `skills/exarch-cli/SKILL.md` and `crates/exarch-cli/README.md` now document both install
  methods above as secondary alternatives to `cargo install exarch-cli`.

### Fixed

- **`verify --json` printed two concatenated top-level JSON documents on FAIL (#387)**: the
  verification report (with `data.status == "FAIL"`) was always printed, and then the command
  bailed with an error that `main`'s top-level handler also serialized to stdout, breaking
  single-document JSON parsing. `verify::execute` now returns a sentinel error that `main`
  recognizes and skips re-printing in `--json` mode; human-readable output still prints the
  "Archive verification failed" message on stderr as before. The command still exits non-zero
  on FAIL in both modes.
- **`extract --json` never populated `error.partial_report` (#386)**: `format_error` looked up
  `PartialExtractionContext` via `error.chain().find_map(downcast_ref)`, which never matches
  because `anyhow::Error::context(...)` requires a direct top-level `downcast_ref` to see
  through the context wrapper. Switched to `error.downcast_ref::<PartialExtractionContext>()`,
  so partial extraction progress is now correctly reported in JSON error output.
- **`exarch-python` CI failing `ruff format --check` on `README.md`**: ruff 0.16.0 started
  formatting Python code blocks embedded in Markdown files, which flagged pre-existing
  inline-comment spacing and blank-line inconsistencies in `crates/exarch-python/README.md`.
  Reformatted the file with the new ruff to match.

### Changed

- `anyhow`, `clap`, `libc`, `napi`/`napi-derive`, `serde_json`, `thiserror`, `time`, and `tokio`
  bumped to their latest compatible patch/minor releases via automated dependency updates
  (`Cargo.lock` only, no direct manifest changes).
- `@biomejs/biome` bumped from `^2.5.3` to `^2.5.5` in `exarch-node`.
- `@napi-rs/cli` bumped from `^3.7.2` to `^3.7.4` in `exarch-node`.
- Refreshed `exarch-python` dev dependencies via `uv lock` (lock-only, no manifest changes).

## [0.5.1] - 2026-07-09

### Fixed

- **7z `allow_absolute_paths` bypassed by upstream path check (#374, #375)**: `sevenz-rust2`
  0.21.1 added an internal path-safety check inside `decompress_with_extract_fn` that blocked
  absolute-path entries before `EntryValidator` ever saw them, breaking the
  `allow_absolute_paths` flag for 7z archives. `extract_with_callback` now uses
  `ArchiveReader::for_each_entries` directly, which has no built-in path check, restoring
  `EntryValidator` as the sole and authoritative guard for 7z path security (traversal,
  absolute paths, symlinks).

- **7z backslash path traversal (#376)**: Entry names with embedded `\` (e.g. `..\..\x`)
  are now normalized to `/`-separated paths before validation. Previously, on Unix, such
  names were treated as a single path component and slipped past traversal detection; they
  are now correctly rejected as `PathTraversal` errors.

- **DRY: centralized entry-name normalization (#365)**: Extracted
  `formats::common::normalize_entry_name` as the single shared point for `\` → `/`
  normalization. The 7z handler now calls this helper in the pre-validation loop, the
  extraction callback, and the list/verify path (`inspection/list.rs`), so that all three
  operations agree on traversal detection. `SafePath::validate` documents the caller contract
  that entry names must be normalized before `PathBuf` construction.

- **RUSTSEC-2026-0204 (#380)**: Bumped `crossbeam-epoch` (transitive, via criterion's
  `rayon` -> `crossbeam-deque` chain) from 0.9.18 to 0.9.20, remediating an invalid pointer
  dereference in its `fmt::Pointer`/`fmt::Display` implementations.

### Changed

- `pyo3` bumped from `0.28.3` to `0.29.0`.
- `sevenz-rust2` bumped to `0.21.3`; `napi`/`napi-derive`, `anyhow`, `time`, `rustc-hash`,
  `clap_complete`, `console`, and `indicatif` bumped to their latest compatible patch/minor
  releases.
- Refreshed transitive dependencies via `cargo update` (18 lock entries updated, no direct manifest changes).
- `@biomejs/biome` bumped from `^2.4.15` to `^2.5.3` in `exarch-node`.
- `@napi-rs/cli` bumped from `^3.6.2` to `^3.7.2` in `exarch-node`.
- `pytest-cov` minimum raised from `>=6.0` to `>=7.0` in `exarch-python`.
- `mypy` minimum raised from `>=1.0` to `>=2.0` in `exarch-python`.
- `ruff` minimum raised from `>=0.8` to `>=0.15` in `exarch-python`.
- `maturin` minimum raised from `>=1.0` to `>=1.14` in `exarch-python`.

## [0.5.0] - 2026-06-05

### Added

- `detect_format` now falls back to magic-byte inspection when the file extension
  is absent, unrecognised, or contradicts the file content. Seven signatures are
  recognised: ZIP (local-file header, EOCD, split-archive marker), GZIP, BZ2, XZ,
  Zstd, 7z, and TAR USTAR. When magic bytes and extension disagree, magic takes
  precedence. Archive creation is unaffected — `determine_creation_format` uses
  extension-only detection so stale on-disk bytes cannot override the caller's
  intent (#353).

### Changed

- ZIP extraction with `allow_absolute_paths = true`: entries whose raw name begins with `/`
  (e.g. `/etc/passwd`) are now written inside the destination directory after the leading
  slash is stripped (producing `<dest>/etc/passwd`), consistent with the TAR and 7z behavior
  introduced in #350. Without the flag the behavior is unchanged — such entries are still
  rejected with `PathTraversal`. This alignment was made explicit during the `process_entry`
  refactor (#352).

### Performance

- `ZipArchive::extract()` now calls `by_index()` exactly once per entry instead of twice.
  The local file header seek+read was previously performed once for the progress callback and
  again inside `process_entry`; the two calls are now merged, halving header I/O on archives
  with many small entries (#341).

### Fixed

- Absolute entry paths (e.g. `/etc/shadow`) and Windows drive/UNC paths (e.g. `C:\...`,
  `\\server\share\...`) are now stripped centrally in `SafePath::validate_with_context` when
  `allow_absolute_paths` is enabled, instead of in each format handler separately. The three
  per-format pre-stripping workarounds in `tar.rs`, `zip.rs`, and `sevenz.rs` have been
  removed. Also fixes bare-slash entries (`/`) returning `io::Error` instead of
  `PathTraversalError` (#347, #348).
- `exarch create --quiet --json` now emits JSON to stdout instead of
  suppressing it. `--quiet` no longer silences `--json` output for any
  command (#357).
- Node.js `SecurityConfig` JSDoc table now lists all 7 default `banned_path_components`
  (`.git`, `.ssh`, `.gnupg`, `.aws`, `.kube`, `.docker`, `.env`); previously only `.git` and
  `.ssh` were shown, which could mislead users into thinking the remaining five needed to be
  added manually (#355).
- `exarch list --json -l` now includes `symlink_target` and `hardlink_target` in
  the JSON output for symlink and hardlink entries. Previously the fields were
  populated in `exarch-core` but silently dropped by the CLI JSON formatter (#346).
- `exarch list -l` now displays symlink and hardlink targets in the long text format:
  entries render as `l755  0  link.txt -> target.txt` instead of omitting the target (#349).
- Python `ExtractionOptions` tests no longer unconditionally skip: replaced the
  `pytest.skip(...)` guard with `pytest.importorskip("exarch")` at module level so all 14
  round-trip assertions execute when the extension is built (#342).
- Roundtrip integration tests now verify extracted file contents against the source data for
  all supported formats (tar.gz, tar.bz2, tar.xz, tar.zst, zip). Previously, tests only
  asserted that extraction succeeded and files existed, which would have allowed silent data
  corruption to go undetected (#335).
- CLI roundtrip tests (`test_roundtrip_tar_gz_single_file`, `test_roundtrip_zip_directory`)
  now assert extracted file contents match the original source bytes (#335).

### Breaking Changes

- **Python `SecurityConfig` builder methods** `allow_symlinks`, `allow_hardlinks`,
  `allow_absolute_paths`, `allow_world_writable`, and `allow_solid_archives` have been renamed
  to `with_allow_symlinks`, `with_allow_hardlinks`, `with_allow_absolute_paths`,
  `with_allow_world_writable`, and `with_allow_solid_archives` to match the `with_` prefix
  convention used by all other builder methods in the class. Update call sites by prepending
  `with_` to each method name (#354).

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
- Python and Node.js bindings expose `ExtractionOptions.atomic`. Python: `with_atomic(bool)`
  builder and `atomic` getter/setter. Node.js: `withAtomic(bool?)` builder and `atomic` getter.
  Atomic mode extracts to a staging directory first, then renames it to the destination — the
  output directory must not pre-exist (#322).

### Tests

- Python and Node.js bindings: added round-trip tests for `ExtractionOptions.atomic`
  and `skip_duplicates` — each field is covered by a default-value test and a
  setter/getter round-trip test. Added `# Examples` doc section to the Python
  `with_atomic` method (#332).
- Added integration tests for `ExtractionOptions::skip_duplicates`: covers `skip_duplicates=true` (first entry kept, duplicate skipped with warning) and `skip_duplicates=false` (second entry overwrites first) for TAR archives. Documents that the `zip` crate 8.x deduplicates entries at parse time, making the flag a no-op for ZIP (#302).
- Added 7z integration tests for `skip_duplicates`: `skip_duplicates=true` keeps the first
  entry and records a warning; `skip_duplicates=false` overwrites with the last entry (#314).

### Fixed

- Python: `exarch.pyi` `SecurityConfig` and `CreationConfig` builder methods
  (`max_file_size`, `max_total_size`, `max_compression_ratio`, `max_file_count`,
  `max_path_depth`, `max_solid_block_memory`, `preserve_permissions`,
  `compression_level`, `follow_symlinks`, `include_hidden`, `exclude_patterns`,
  `max_file_size`) were missing the `with_` prefix; renamed to match the Rust
  implementation (`with_max_file_size`, `with_compression_level`, etc.) so type
  checkers accept valid code (#334).
- Python: `SecurityConfig` and `CreationConfig` scalar getters (`max_file_size`, `max_total_size`, `max_compression_ratio`, `max_file_count`, `max_path_depth`, `max_solid_block_memory`, `preserve_permissions`, `compression_level`, `follow_symlinks`, `include_hidden`, `exclude_patterns`) now return their values correctly instead of a bound method. Builder methods were renamed to `with_<field>` (e.g. `with_max_file_size(...)`) to eliminate the PyO3 name collision (#315).
- 7z force-overwrite now removes existing file before re-extraction when `skip_duplicates=false`; previously it returned a `PartialExtraction` error instead of overwriting (#323).
- Node.js: `index.d.ts` now declares `setMaxSolidBlockMemory(size: number): this` and `get maxSolidBlockMemory(): number` for `SecurityConfig`; the file is committed to the repository so TypeScript consumers have correct types without building from source (#311).
- Node.js: `index.d.ts` regenerated to include `ExtractionOptions` class and the fourth
  `options` parameter on all `extract*` signatures; the file was stale after PR #324 (#330).
- Node.js: `extractArchiveWithProgress` JSDoc corrected — numeric callback arguments
  (`total`, `current`, `bytesWritten`) were documented as `bigint` but NAPI-RS maps `i64` to
  `number` (#326).
- Python: `exarch.pyi` now declares `allowed_extensions` and `banned_path_components` as `@property` with setters, replacing bare class-level annotations that did not express read/write semantics (#312).
- `list_archive` now respects `SecurityConfig::allowed.absolute_paths`; absolute paths in TAR
  and 7z archives are accepted during listing when the flag is set (previously silently rejected
  regardless of config) (#318). The `--allow-absolute-paths` CLI flag now consistently applies
  to both the listing and extraction phases.
- ZIP listing with `--allow-absolute-paths`: entries whose names return `None` from
  `enclosed_name()` (traversal-after-root patterns like `/../etc/passwd`) were always rejected
  with `PathTraversal` regardless of the flag. The listing side now checks the flag for this
  case, strips the leading `/`, and passes the result through `contains_traversal`; bare `/`
  or empty-after-strip paths are rejected. True traversal components (`..`) are still rejected
  even with the flag set (#325).
- ZIP extraction with `--allow-absolute-paths`: the extraction path in `zip.rs` previously built
  the entry path from the raw `name()` string, causing `SafePath::validate` to see an absolute
  path and subsequently `dest.join(absolute)` to discard `dest` — resulting in `PathTraversal`
  even when the flag was set. Extraction now uses `enclosed_name()` with the same fallback strip
  logic as listing, so the flag works end-to-end for ZIP (#325).
- Conflict scan during `exarch extract` now uses the same relative path that `list_archive`
  produces for each entry. Previously `output_dir.join(e.path)` silently discarded `output_dir`
  when `e.path` was absolute (stdlib `Path::join` semantics), causing conflict checks to probe
  real filesystem paths instead of the intended destination (#327).
- `verify --strict` no longer writes an unstructured message to stderr that bypassed `--quiet` suppression and `--json` mode. Exit code 2 already conveys the strict-warning condition (#298).
- `ProgressCallback::on_bytes_written` is now called during extraction for TAR, ZIP, and 7z formats; previously the method was documented but never invoked (#304).
- `ProgressCallback::on_entry_complete` is now guaranteed to be called for every entry for which `on_entry_start` was called, including entries that fail mid-extraction; previously a failure left the callback pair unbalanced (#305).
- 7z extraction with `skip_duplicates=false` now overwrites the existing file instead of
  returning an error. Previously a duplicate entry with `skip_duplicates=false` would fail;
  now it falls through to the atomic temp+rename overwrite path (#314).
- `list_archive` now reports the correct `symlink_target` for ZIP symlink entries. Previously
  `ArchiveManifest` entries were set to the entry's own path instead of reading the actual
  target from the entry data (where the ZIP spec stores it). The symlink detection mask in the
  listing path has also been corrected to use `S_IFMT & S_IFLNK`, matching the extraction path (#336).

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

[Unreleased]: https://github.com/bug-ops/exarch/compare/v0.5.2...HEAD
[0.5.2]: https://github.com/bug-ops/exarch/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/bug-ops/exarch/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/bug-ops/exarch/compare/v0.4.1...v0.5.0
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
