---
aliases:
  - Config API Spec
  - SecurityConfig Spec
tags:
  - sdd
  - spec
  - config
  - rust
created: 2026-05-20
updated: 2026-11-09
status: implemented
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[001-security-pipeline/spec]]"
  - "[[002-format-handlers/spec]]"
  - "[[014-config-typestate-validation/spec]]"
  - "[[021-create-staging-and-output-policy/spec]]"
  - "[[017-zip-header-consistency/spec]]"
  - "[[020-reader-sink-and-in-memory-api/spec]]"
---

# Feature: Configuration API

> [!info] Metadata
> **Subsystem**: exarch-core / config, creation
> **MSRV**: Rust 1.99.1
> **Source**: extracted from [[001-exarch-system/spec]]

> [!note] Batch #981 amendments
> `ExistingFiles {Skip, Overwrite, Refuse}` replaces `skip_duplicates` and `DuplicatePolicy`; `Staging {InPlace, Atomic, AtomicReplace}` replaces `atomic: bool`; `PermissionPolicy`, `ExtensionFilter`, `DestinationCheck` and typed errors are new (FR-058 to FR-066). Selection and strip live in `SecurityConfig` (see [[022-extract-entry-selection/spec]]).

## 1. Overview

### Problem Statement

Security policy, creation options, and extraction behavior must be expressible
at the call site without mutating shared state. A single mutable global config
or stringly-typed options map would make it easy to accidentally weaken security
defaults or produce invalid configurations.

### Goal

Provide three immutable, builder-pattern configuration types — `SecurityConfig`,
`CreationConfig`, and `ExtractionOptions` — that encode all tunable parameters
with secure deny-by-default values. Since the 50-issue batch (#898) every value is valid by construction (typed limits), so there is no separate validation step.

### Out of Scope

- Runtime configuration file parsing (TOML/YAML/JSON)
- Environment-variable-driven configuration
- Dynamic config mutation after construction

## 2. User Stories

### US-001: Secure Default Extraction

AS A Rust developer
I WANT to call `extract_archive()` with `SecurityConfig::default()` and get safe behavior
SO THAT I do not need to know the security parameters to be protected

**Acceptance criteria:**
```
GIVEN SecurityConfig::default()
THEN symlinks, hardlinks, absolute paths, world-writable files, and solid archives are all denied;
     max_file_size is 50 MB, max_total_size is 500 MB, max_compression_ratio is 100.0,
     max_file_count is 10,000, max_path_depth is 32
```

### US-002: Custom Security Policy

AS A developer integrating exarch into a controlled environment
I WANT to override specific limits via a fluent builder
SO THAT I can raise or lower limits appropriate to my use case

**Acceptance criteria:**
```
GIVEN SecurityConfig::default().with_max_file_size(non_zero!(200 * 1024 * 1024)).with_allow_symlinks(true)
WHEN passed to extract_archive()
THEN extraction allows symlinks and accepts files up to 200 MB
```

### US-003: Invalid Limits Are Unrepresentable

AS A developer
I WANT limits typed so that a zero or non-finite value cannot be stored
SO THAT extraction does not start with a zero or non-finite limit

**Acceptance criteria:**
```
GIVEN a runtime value 0 for a size limit
WHEN it is converted with non_zero_u64 / positive_from_i128 / positive_from_f64 / RatioLimit::parse
THEN it returns ArchiveError::InvalidConfiguration (Zero, Negative, NotFinite, NotWholeNumber or TooLarge) and no SecurityConfig is built
```

```
GIVEN the string "\0evil"
WHEN Extension::try_from("\0evil") is called
THEN it returns ArchiveError::InvalidConfiguration (entry contains a null byte); an invalid entry cannot be stored in SecurityConfig
```

> [!note] v0.6.0: entry-level validation for allowlist/banlist fields (#449)
> Entry validation is encoded in types (v0.8.0): `allowed_extensions` holds `Extension` values and
> `banned_path_components` holds `PathComponentName` values (`types::config_entry`), each built only
> through `TryFrom<&str>`, which rejects invalid entries (`MAX_CONFIG_ENTRY_LENGTH` is re-exported
> from `exarch_core`). `Extension` is normalized: one leading dot is stripped and the value is
> ASCII-lowercased, so it never carries a leading dot.
> An entry that is empty, contains a null byte, or exceeds 255 bytes now fails validation —
> configs that previously passed with such entries now return `InvalidConfiguration`. Python's
> `add_allowed_extension`/`add_banned_component` and Node's `addAllowedExtension`/
> `addBannedComponent` delegate to the same helper, so both bindings additionally reject empty
> entries eagerly (previously accepted) and report length in bytes.

### US-006: No Validation Step To Forget

AS A library maintainer
I WANT `SecurityConfig` and `CreationConfig` to be plain structs whose typed fields cannot hold an invalid value
SO THAT there is no `validate()` call a caller or a refactor can skip

**Acceptance criteria:**
```
GIVEN a SecurityConfig built with the fluent builders
WHEN it is passed to extract_archive / ExtractRequest / ArchiveFormat handles
THEN no validation call is needed and the config is borrowed, not cloned
```

> [!note] #898 (50-issue batch)
> The `Unvalidated`/`Validated` typestate of v0.6.0 is gone; see the obsolete [[014-config-typestate-validation/spec]].
> `SecurityConfigFields` is now `SecurityConfig` (public typed fields, `#[non_exhaustive]`, no `Deref`); the same for `CreationConfig`.
> `validate()` always returned `Ok`, so no check was lost.

### US-004: Archive Creation Configuration

AS A developer building a packaging tool
I WANT to control compression level, file filtering, and symlink handling during creation
SO THAT I can produce well-formed archives without manual format handling

**Acceptance criteria:**
```
GIVEN CreationConfig::default().with_compression_level(CompressionLevel::try_from(9u8)?).with_exclude_patterns(vec![EntryPattern::try_from("*.log")?])
WHEN create_archive() is called
THEN all .log files are excluded and maximum compression is applied
```

> [!note] `with_compression_level` takes a `CompressionLevel`
> Since v0.8.0 `with_compression_level` takes a validated `CompressionLevel` and returns `Self`;
> construct the level with `CompressionLevel::try_from(9u8)?`.

### US-005: Atomic Extraction

AS A server operator
I WANT to enable atomic extraction so that no partial output is left on failure
SO THAT a failed extraction does not leave a half-written directory

**Acceptance criteria:**
```
GIVEN ExtractionOptions::default().with_staging(Staging::Atomic)
WHEN extraction fails mid-archive
THEN no files are present in the output directory; the temp dir is cleaned up
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-030 | `SecurityConfig` SHALL expose fluent builder methods: `with_max_file_size`, `with_max_total_size`, `with_max_compression_ratio`, `with_max_file_count`, `with_max_path_depth`, `with_allowed`, `with_allow_symlinks`, `with_allow_hardlinks`, `with_allow_absolute_paths`, `with_allow_world_writable`, `with_allow_windows_reserved_names`, `with_preserve_permissions`, `with_allowed_extensions`, `with_selection`, `with_path_rewrite`, `with_banned_path_components`, `with_solid_archives`, `with_allow_solid_archives`, `with_solid_limits`, `with_max_tar_metadata_bytes`, `with_max_decoder_memory`, `with_compressed_member_allowance`, `with_parallel_decode`, `with_zip_consistency`; each returns `Self` except `with_solid_limits`, which returns `Result<Self>` (`InvalidConfiguration { MaxSolidBlockMemory, NotSupported }` while solid archives are refused). `with_max_solid_block_memory` and `with_max_solid_compression_ratio` no longer exist (#911) | must |
| FR-031 | `SecurityConfig`, `AllowedFeatures`, and `ExtractionOptions` SHALL be annotated `#[non_exhaustive]`; external crates must use `Default::default()` plus builder methods — struct literal construction is a compile error | must |
| FR-032 | `SecurityConfig` limits SHALL be typed so that a zero or non-finite limit cannot be built: byte and count limits are `Limit<NonZeroU64>` (`Bounded` or `Unbounded`) or `NonZeroU64`/`NonZeroUsize`, ratio limits are `RatioLimit` (finite and greater than zero, built by `RatioLimit::new` for a constant or `RatioLimit::parse(ConfigSetting, f64)` for a runtime value), and `validate()` SHALL NOT exist (removed in #898; `u64::MAX` is a valid `max_tar_metadata_bytes`); runtime values SHALL enter through one boundary in `limit.rs`: `non_zero_u64`, `non_zero_usize`, `positive_from_i128(ConfigSetting, i128)` and `positive_from_f64(ConfigSetting, f64)` (refuse NaN and infinity with `NotFinite`, fractions with `NotWholeNumber`, negatives with `Negative`, zero with `Zero`, and values above 2^53-1 with `TooLarge { max }`), `RatioLimit::parse` (refuses `NotFinite`, `Negative`, `Zero`) and `ParallelDecode::from_bytes(Option<NonZeroU64>)`; the Node and Python setters and the CLI SHALL refuse an invalid limit at the point it is set, as `InvalidConfiguration` (v0.8.0, #848, #870, #894; #913, #921) | must |
| FR-033 | `CreationConfig` SHALL support: `follow_symlinks`, `include_hidden` (when false, creation never enters a hidden directory below a source root; see [[021-create-staging-and-output-policy/spec]] FR-026), `max_file_size` (`Limit<NonZeroU64>`, default `Limit::Unbounded`; `with_max_file_size` takes `impl Into<Limit<NonZeroU64>>`, so a zero limit is unrepresentable and files above a bound are skipped; the CLI (`create --max-file-size 0`), Node and Python refuse zero as `InvalidConfiguration`, Node `setMaxFileSize` takes `null` and Python `None` for no limit; v0.8.0, #893, #902, #946), `exclude_patterns: Vec<EntryPattern>` (parsed and validated, see [[021-create-staging-and-output-policy/spec]]), `strip_prefix`, `compression_level` (1–9), `preserve_permissions`; the format override moved to `OutputFile::with_format` (`CreatableFormat` has no 7z variant, so a 7z creation request is unrepresentable; `CreationConfig::format` and `with_format` were removed in #915); `compression_level` is a `CompressionLevel` newtype (default 6) obtained via `CompressionLevel::try_from(u8)`, and `with_compression_level` takes it and returns `Self`; a level outside 1–9 is rejected at `CompressionLevel` construction with `ArchiveError::InvalidCompressionLevel` | must |
| FR-034 | `ExtractionOptions` SHALL support: `staging: Staging` (default `InPlace`; `Atomic` extracts into a temp tree and renames; `AtomicReplace` swaps over an existing destination) via `with_staging`, and `existing_files: ExistingFiles` (default `Skip`) via `with_existing_files`; `decode_reuse` is unchanged | must |
| FR-035 | WHEN `ExtractionOptions::staging` is `Staging::Atomic`, THE SYSTEM SHALL extract to a temp dir in the same parent as the output directory and atomically rename on success | must |
| FR-036 | WHEN atomic extraction fails, THE SYSTEM SHALL delete the temp dir before returning the error | must |
| FR-037 | All three config types SHALL implement `Default` with documented defaults | must |
| FR-038 | `AllowedFeatures` SHALL be a separate struct whose five fields (`symlinks`, `hardlinks`, `absolute_paths`, `world_writable`, `windows_reserved_names`) are `Admit` (`Refuse` or `Allow`, `is_allowed()`) instead of `bool` (#911); the `with_allow_*(bool)` setters are unchanged; all default to `Refuse` (`permissive()` leaves `windows_reserved_names` false). `windows_reserved_names` is consulted only on Windows and has no CLI or binding opt-out | must |
| FR-039 | Creation SHALL reject an unusable output, format or source before any I/O (see [[021-create-staging-and-output-policy/spec]]); there is no `CreationConfig::validate()` | must |
| FR-040 | `SecurityConfig` and `CreationConfig` SHALL be plain `#[non_exhaustive]` structs with public typed fields; the `Unvalidated`/`Validated` typestate, `validate()` and the phantom markers SHALL NOT exist, and every entry point SHALL borrow the config without cloning it (#898; replaces the v0.6.0 typestate of [[014-config-typestate-validation/spec]], now obsolete) | must |
| FR-041 | `SecurityConfig` SHALL admit only `Extension` and `PathComponentName` entries in `allowed_extensions` / `banned_path_components`; their `TryFrom<&str>` constructors reject an entry that is empty (after an extension's leading dot), contains a null byte, ASCII whitespace or a control character, contains a path separator, is `.` or `..` (component), has an inner dot (extension), or exceeds 255 bytes, so an invalid entry is unrepresentable; an extension is normalized to lowercase without its leading dot (`.txt` matches `txt`) in core, Python, Node and CLI, and the CLI `--banned-component` takes comma-separated values, `""` disables the list, and a value naming no component or `--allowed-extensions` naming no extension is an error (v0.8.0, #871, #888) | must |
| FR-042 | Fields of `SecurityConfig` and `CreationConfig` SHALL be public and typed (no `Deref`/`DerefMut`), so any assignment keeps the config valid; struct-literal construction outside the crate is a compile error because of `#[non_exhaustive]` | must |
| FR-043 | The plain `extract_archive`, `list_archive`, `verify_archive` and `create_archive` functions SHALL stay and accept `&SecurityConfig`/`&CreationConfig`; every option and progress variant is a request type (`ExtractRequest`, `ListRequest`, `VerifyRequest`, `SinkExtractRequest`, `CreateRequest`) with `with_options` / `with_progress` setters and terminal methods, documented once on the request type (#912); `extract_archive_with_options*`, `extract_archive_with_progress`, `list_archive_with_options`, `list_archive_with_progress`, `verify_archive_with_options`, `verify_archive_with_progress`, `list_reader*`, `verify_reader*`, `extract_to_sink*`, `create_archive_with_progress`, `create_to_writer*`, `create_to_bytes` and `list_archive_for_extraction` SHALL NOT exist; `Archive` and `ArchiveBuilder` were removed (#897) | must |
| FR-044 | `SecurityConfig` SHALL expose `zip_consistency: ZipConsistencyPolicy` (`#[non_exhaustive]`: `Enforce`, the default also for `permissive()`; `Ignore`) deciding whether structurally ambiguous ZIP archives are rejected in `extract`/`list` and reported in `verify` (see [[017-zip-header-consistency/spec]]); the CLI exposes it as `--zip-consistency`, Python and Node as a config option | must |
| FR-045 | `SecurityConfig` SHALL expose `parallel_decode: ParallelDecode` (`Sequential` or `Bounded(NonZeroU64)`) bounding the lookahead memory of parallel 7z LZMA2 decoding, separately from `max_decoder_memory`; the CLI exposes it as `--parallel-decode-memory` | must |
| FR-046 | `SolidLimits::max_ratio` (7z solid blocks) and `max_decoder_memory` (xz and 7z decoder window, the 7z header read, see [[002-format-handlers/spec]] FR-069, zstd window of TAR and ZIP as the largest power of two within it, at most 128 MiB; breach is `QuotaExceeded { DecoderMemory }`, v0.8.0, #849) and `compressed_member_allowance` (base number of gzip members or bzip2 streams of a TAR, plus one per 16 KiB of output; breach is `QuotaExceeded { CompressedMembers }`, v0.8.0, #851) SHALL be Rust-API-only settings, not exposed by the CLI or the Python/Node bindings | must |
| FR-047 | `max_file_count` (`Limit<NonZeroUsize>`) SHALL bound the entries of an archive: every entry counts once, in every format and command (extract, list, verify, the CLI `extract`): files, directories, links, entries skipped by the allowlist or the selection, and duplicates skipped under `ExistingFiles::Skip` (#1038) | must |
| FR-048 | `SinkOptions` (`#[non_exhaustive]`, Copy; fields `existing_files: ExistingFiles`, default `Skip`, builder `with_existing_files`, and `decode_reuse: DecodeReuse`, default `DecodeReuse::Off`, builder `with_decode_reuse`, #890, #946) SHALL be the options of `SinkExtractRequest` and `extract_reader_to_callback`; Python and Node SHALL expose it as a `SinkOptions` class and the in-memory and callback entry points SHALL no longer accept `ExtractionOptions` (#926); `SinkOptions::try_from(&ExtractionOptions)` SHALL carry `existing_files` over, never `decode_reuse`, and fail with `InvalidConfiguration` when `staging` is `Atomic` or `AtomicReplace`; `MemoryLimit::from_config(&SecurityConfig)` SHALL derive a non-zero memory bound from `max_total_size` (v0.8.0, #794, #808; see [[020-reader-sink-and-in-memory-api/spec]]) | must |
| FR-049 | `ArchiveError::InvalidConfiguration` SHALL carry a `ConfigSetting` (`#[non_exhaustive]`, `as_str()` and `label()`: the `max_*` limits, `decompression_budget`, `allowed_extension`, `banned_path_component`, `output_path`, `source_paths`, `strip_prefix`, `creation_format` (label "creation format"), `atomic_extraction`, `zip_output_writer`, `max_bytes`, `parallel_decode_memory`, `exclude_pattern`, and the enumerated binding arguments `zip_consistency`, `path_model`, `archive_format`, `decode_reuse`, `decode_reuse_limit`, `skip_kind`, `durability`, `stored_targets` (#1098); `archive_path`, `output_directory` and `zip_archive` were removed in #897 and #901) and a `ConfigProblem` (`#[non_exhaustive]`: `Zero`, `Negative`, `NotFinite`, `NotWholeNumber`, `TooLarge { max }`, `NotSet`, `NoneProvided`, `NoParent`, `NotSupported`, `CannotTargetSink`, `RemovesWholeName`, `NotAtStart`, and the entry problems `Empty`, `BlankOrControl`, `PaddedWithBlank`, `ContainsSeparator`, `InnerDot`, `DotEntry`, `ContainsNul`, `TooLong`, `NotOneOf { allowed: &'static [&'static str] }` (a value outside an enumerated set, used by the bindings; the message lists the accepted values), `NotCreatable { format: ExtractOnlyFormat }` (a format that can be read but not created; renders `7z archive creation is not supported`), `ExcludePatternRefused { pattern, reason: PatternRefusal }` (see [[021-create-staging-and-output-policy/spec]]); `NotPositive`, `NotGreaterThanZero`, `NotPositiveWholeNumber` were removed in #913 and `OpenedForOtherPolicy`, `OpenedUnderSmallerZstdWindow` in #901) instead of a reason string; `FfiKind::InvalidConfiguration` SHALL name the setting, exposed as `setting` in Python and Node and `error.setting` in CLI `--json` (v0.8.0, #870, #894) | must |
| FR-050 | `SecurityConfig::with_compressed_member_allowance` SHALL take a `NonZeroU64`; `ExtractionOptions` SHALL carry `decode_reuse: DecodeReuse` (default `Memory(ReuseLimit::DEFAULT)`, 32 MiB) and `ListRequest::for_extraction(path, DecodeReuse)` SHALL take the extraction config and store it in the `ListedArchive` it returns (see [[020-reader-sink-and-in-memory-api/spec]]); `DecodeReuse` is `Off`, `Memory(ReuseLimit)` or `TempFile(ReuseLimit)` with `ReuseLimit` at most 256 MiB (v0.8.0, #856, #857, #884) | must |
| FR-051 | `SolidArchives` SHALL be `Refuse` or `Allow(SolidLimits)` with `SolidLimits { max_block_memory: NonZeroU64, max_ratio: RatioLimit }`, `SolidLimits::DEFAULT` = 512 MiB / 1000 and `PERMISSIVE` = 1 GiB / 10000; `SecurityConfig::solid_archives` replaces `allow_solid_archives`, `max_solid_block_memory` and `max_solid_compression_ratio`; `Refuse` carries no limits; `SolidArchives::with_max_ratio(RatioLimit)` is owned by core, so the bindings no longer rebuild the limits themselves (#1097); `with_allow_solid_archives(true)` keeps existing `Allow` limits and turns `Refuse` into `Allow(DEFAULT)`; `with_allow_solid_archives(false)` gives `Refuse`; Python and Node `max_solid_block_memory` getters return `None`/`null` and their setters raise `InvalidConfiguration` while `Refuse` (#911) | must |
| FR-052 | The solid 7z block limit SHALL be checked per block, for every block of a solid archive including single-file blocks, against `max_block_memory` as `QuotaExceeded { SolidBlockMemory { scope, current, max } }` with `scope` a `SolidMemoryScope` (`Block`: one block, `Archive`: the archive-wide sum) (`QuotaKind::SolidBlockMemory`, sub-code `SOLID_BLOCK_MEMORY` for both scopes); the archive-wide sum of solid unpack sizes SHALL additionally be capped by `max_block_memory` (scope `Archive`) only while `max_total_size` is `Limit::Unbounded`; the limit bounds decoded volume per block, not resident memory (resident memory is bounded by `parallel_decode`). This is a deliberate, user-approved relaxation: with an explicitly raised `max_total_size` above `max_block_memory`, a multi-block solid archive whose total lies between the two now passes (each block still capped, the total capped by `max_total_size`); with the defaults and with `permissive()` the rule is equal or stricter (#911, #896) | must |
| FR-053 | `SecurityConfig::is_extension_allowed(Option<&str>)` SHALL be the single extension predicate; `is_path_extension_allowed` was removed (#913) | must |
| FR-054 | `ListRequest::for_extraction` SHALL list under `SecurityConfig::for_listing()` (a `pub(crate)` copy of the config with the write-time flags reset) and keep the extraction config inside the `ListedArchive`; `ListedArchive::extract(self, out, &ListedExtractOptions { staging, existing_files }, progress)` SHALL extract under the stored config, so `--allow-symlinks`, `--allow-hardlinks`, `--allow-world-writable` and `--preserve-permissions` hold for listed extraction; the census parameters are identical under `for_listing`, proven by `tests/listed_differential.rs` (504 comparisons), so only `debug_assert!`s remain where `serves`/`covers` were run-time guards (#901) | must |
| FR-055 | Format handle constructors SHALL take the config they enforce (`ZipArchive::new(reader, &SecurityConfig)`, `TarArchive::new`, `SevenZArchive::new`, `open_tar_gz`/`bz2`/`zst`/`xz`), `ArchiveFormat::{extract, list, verify}` SHALL NOT take a config, and `ArchiveFormat` SHALL be sealed (#901, #908) | must |
| FR-056 | The closed enums that bindings parse from strings SHALL implement the sealed trait `ClosedEnum` (`ALL`, `NAMES`, `as_str`, and the provided `parse_for(ConfigSetting, &str)` returning `InvalidConfiguration { setting, NotOneOf { allowed: NAMES } }`), re-exported from the crate root; the Python binding SHALL parse every enumerated argument through `parse_for` except the creation format, which goes through `CreatableFormat::from_str` so that `"SevenZ"` is `NotCreatable` and `NotOneOf` lists only creatable formats; the binding-local `ReuseKind` is replaced by core `DecodeReuseKind` (`off`, `memory`, `temp_file`) with `DecodeReuse::kind()` | must |
| FR-057 | `ExtractOnlyFormat` (one variant, `SevenZ`, with `extension()`) SHALL make `TryFrom<ArchiveType> for CreatableFormat` a total partition of `ArchiveType`: every format is creatable or carries an `ExtractOnlyFormat`, so `NotCreatable` cannot name a creatable format; `CreatableFormat` SHALL implement `FromStr` (`Err = ArchiveError`) | must |
| FR-058 | `ExistingFiles` SHALL govern every on-disk occupant of a landing, including files that existed before the run, not only entries repeated in the archive; `Overwrite` (CLI `--force`) SHALL still refuse kind conflicts; `Refuse` SHALL never reach an overwrite or replace branch: every occupant decision SHALL be an exhaustive `match` over `ExistingFiles` (no `==`, no `_` arm) at the eight sites (`open_output_slot`, `create_symlink`, the 7z `validate_file` and pre-pass, the hardlink arm of `target.rs`, and the three sink matches). `Refuse` refuses an occupant the run did not create and skips one it did (a run record keyed by `(dev, ino)`, by normalized landing path where no identity exists, capped at 4 Mi entries, past which every occupant fails closed; a case-folding mismatch fails closed); the 7z pre-pass keeps refusing every occupant because it runs before any write; sinks hold only this run's entries, so `Refuse` there equals `Skip`; inside core's own staging directory (`Atomic`, `AtomicReplace`) `Skip` is run as `Refuse`; the run record costs about 5 percent on small-file extraction (#996) | must |
| FR-059 | `ArchiveError::DestinationOccupied { destination, conflicts }` (`conflicts` are archive-relative entry names; error code `OutputExists`) SHALL report a refused occupant; `destination` is a host path and SHALL be redacted in binding release builds like an `Io` path | must |
| FR-060 | `ListedArchive::check_destination(&self, &Path, DestinationCheck) -> Result<()>` SHALL check the destination before anything is written (implemented in `listed/destination.rs` over `DirWalker::open_parent` and `vet_dir`): `Vacant` requires every file or link landing to be empty and every directory landing to be a directory; `Replaceable` checks only the landings that must be directories; both return `DestinationOccupied` or the typed symlink refusal resolved through `canonical_within` | must |
| FR-061 | `PermissionPolicy {Normalize, Preserve}` SHALL replace the `preserve_permissions` bool field of `SecurityConfig` and `CreationConfig` (the bool builder `with_preserve_permissions` stays); `Preserve` still strips setuid and setgid | must |
| FR-062 | `ExtensionFilter {Any, Only(Extensions)}` SHALL replace the empty-list sentinel of `allowed_extensions`; `Extensions` is a non-empty newtype and an empty list is refused as `InvalidConfiguration { AllowedExtension, Empty }`; builder `SecurityConfig::with_allowed_extensions(ExtensionFilter)` | must |
| FR-063 | `ConfigProblem` SHALL gain `NotADirectory`, `IsSymlink`, `EntryNameCollision { name, first, second }` and `ReplacesProtectedPath { path: ProtectedPath }` (`ProtectedPath {FilesystemRoot, ArchiveAncestor, WorkingDirectory}`); `ConfigSetting` SHALL gain `ExistingFiles`, `Staging`, `EntrySelection`, `EntryInclude`, `EntryExclude`, `StripComponents`; `OutputPath` covers the archive to create and the extraction destination | must |
| FR-064 | `ArchiveError::InvalidCompressionLevel { level: RequestedLevel }` SHALL carry `RequestedLevel {Integer(i64), OutOfRange, Fractional(f64), NonFinite}`, built by `CompressionLevel::from_i128` and `from_f64`; an integer outside `i64` is `OutOfRange` (the width is `i64`, not `i128`, to keep `ArchiveError` under the `result_large_err` limit on windows-gnu) | must |
| FR-065 | `BoundaryPath` SHALL hold a `PathBuf` (`parse(String)`, `parse_os(OsString)`, `as_path`, `into_path_buf`; `as_str` and `into_string` are removed) and `utf8_entry_path(&Path) -> Result<&str, Malformation>` SHALL be the single UTF-8 check for entry paths | must |
| FR-066 | `ErrorCode::Cancelled` (`"CANCELLED"`), `FfiKind::Cancelled`, `ArchiveError::OutputReservationLeft { path, error }`, `ArchiveError::ReplaceFailed(ReplaceFailure)` and `Violation::DestinationChanged` SHALL exist; host paths in `OutputReservationLeft` and `ReplaceFailed` SHALL be redacted in binding release builds ([[004-progress-tracking/spec]], [[015-atomic-force-destination-swap-hardening/spec]], [[021-create-staging-and-output-policy/spec]]) | must |
| FR-067 | The docs of `max_decoder_memory` SHALL state that for a 7z archive the limit also applies when the archive is opened (the raw header size, the decoded size of an encoded header and that header coder's declared dictionary or model), that a plain or encoded header larger than 256 bytes per `max_file_count` entry plus 64 KiB is refused too (directories count toward the size; an unbounded file count leaves `max_decoder_memory` as the only header cap), so the buffer that holds it is held in proportion to the permitted file count; that a header declaring more entries than `max_file_count` plus a small allowance is refused before its entry table is built as `QuotaExceeded { HeaderEntryCount }` (plain header, and encoded header with one copy, LZMA or LZMA2 coder), and a header whose count cannot be read (another coder, several coders, an unfollowable layout) as `InvalidArchive`; the decoded-header buffer is not separately bounded; the dictionary is held to `max_decoder_memory` alone whenever the header's declared size can be read, otherwise to the stricter cap, that a refusal is `QuotaExceeded { HeaderSize }` when the cap derived from `max_file_count` trips and `QuotaExceeded { DecoderMemory }` when `max_decoder_memory` or the library's own dictionary check trips, from `list`, `verify` and `extract`, that blocks are charged `min(dictionary, 2 * unpack size)` instead, and that a limit below roughly 26 KiB refuses every archive with an encoded header (7-Zip sizes the header dictionary to the header and the LZMA model adds about 22 KiB; measured, [[002-format-handlers/spec]] FR-069); the docs of `DecodeReuse::TempFile` SHALL state that a spool on Linux tmpfs or ramfs, FreeBSD tmpfs or `md` disks and macOS tmpfs mounts is charged as memory, that a macOS `hdiutil ram://` disk, a nullfs or unionfs over a tmpfs and ZFS on an `md` disk are not detected, that the Linux detection was not run on a Linux host by hand, and that Linux timings are not measured ([[002-format-handlers/spec]] FR-061; `skills/exarch-cli/SKILL.md` carries the same statements) | must |
| FR-068 | `SecurityConfig::selection: EntrySelection` (default: every entry, paths kept) SHALL be read by `extract`, `list`, `verify` and every sink; `with_selection` replaces it and `with_path_rewrite(PathRewrite)` replaces its rewrite; an entry is validated under its archive path, then selected, then stripped, and the stripped path is validated again, so a selection never admits a name plain extraction refuses ([[022-extract-entry-selection/spec]], [[023-entry-selection-glob-patterns/spec]]) | must |
| FR-071 | `DecodeReuse::from_parts(kind: DecodeReuseKind, limit: Option<ReuseLimit>) -> Result<DecodeReuse>` SHALL own the decode-reuse validation for every front end: a limit given with `Off` is refused as `InvalidConfiguration { DecodeReuseLimit, NotSupported }` and a missing limit falls back to `ReuseLimit::DEFAULT`; Python and Node only map their types into it (#1053) | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Safety | Configuration is immutable after construction — no interior mutability |
| NFR-002 | Reliability | Atomic extraction (`Staging::Atomic`) ensures all-or-nothing semantics on same filesystem |
| NFR-003 | Usability | Fluent builder chains are ergonomic: each `with_*` method returns `Self` |
| NFR-004 | Compatibility | `#[non_exhaustive]` on `SecurityConfig` prevents downstream struct literal construction |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `SecurityConfig` | Security policy for extraction and inspection operations; `#[non_exhaustive]` struct with public typed fields (#898) | `max_file_size`, `max_total_size`, `max_compression_ratio`, `max_file_count: Limit<NonZeroUsize>`, `max_path_depth`, `allowed: AllowedFeatures`, `permissions: PermissionPolicy`, `banned_path_components`, `allowed_extensions: ExtensionFilter`, `selection: EntrySelection`, `solid_archives: SolidArchives`, `max_tar_metadata_bytes`, `max_decoder_memory`, `compressed_member_allowance`, `parallel_decode`, `zip_consistency` |
| `AllowedFeatures` | Feature policy for deny-by-default | `symlinks`, `hardlinks`, `absolute_paths`, `world_writable`, `windows_reserved_names`, each `Admit` |
| `Admit` | Closed enum replacing a `bool` for an admitted feature | `Refuse`, `Allow`; `is_allowed()`, `from_allowed(bool)`, `ALL` |
| `SolidArchives` / `SolidLimits` | 7z solid-block policy; `Refuse` carries no limits | `Refuse`, `Allow(SolidLimits)`; `SolidLimits { max_block_memory, max_ratio }`, `DEFAULT`, `PERMISSIVE`; `with_allowed`, `with_limits`, `with_max_block_memory`, `with_max_ratio` |
| `ParallelDecode` | `#[non_exhaustive]` enum: how much lookahead memory a 7z block may use to decode LZMA2 runs on worker threads | `Sequential`, `Bounded(NonZeroU64)`; `lookahead()`; `DEFAULT_BYTES` = 128 MiB |
| `ZipConsistencyPolicy` | `#[non_exhaustive]` enum: handling of ZIP archives that different readers interpret differently | `Enforce` (default), `Ignore`; `as_str()` |
| `VerificationOptions` / `IntegrityCheck` / `DecompressionBudget` | Options of `VerifyRequest::with_options`; `IntegrityCheck::budget()` is exhaustive; the budget lives inside `IntegrityCheck::DecodeToEof`, so a budget without the check is unrepresentable | `integrity: IntegrityCheck` (`Skip` default, `DecodeToEof(DecompressionBudget)`); budget default 500 MiB, non-zero |
| `ListOptions` / `StoredTargets` | Options of `ListRequest::with_options`; whether 7z link targets kept in compressed entry data are read | `stored_targets: StoredTargets` (`Skip` default, `Read`) |
| `CreationConfig` | Configuration for archive creation; `#[non_exhaustive]` struct with public typed fields (#898) | `follow_symlinks`, `include_hidden`, `max_file_size: Limit<NonZeroU64>`, `exclude_patterns: Vec<EntryPattern>`, `strip_prefix`, `compression_level` (1–9), `preserve_permissions` |
| `ExtractionOptions` | Operational options for extraction (non-security) | `staging: Staging`, `existing_files: ExistingFiles`, `decode_reuse` |
| `SinkOptions` | Options of sink extraction (v0.8.0) | `existing_files: ExistingFiles` (default `Skip`), `decode_reuse`; `TryFrom<&ExtractionOptions>` rejects `Atomic` and `AtomicReplace` |
| `CreatableFormat` | `#[non_exhaustive]` archive formats that can be created (v0.8.0) | `Tar`, `TarGz`, `TarBz2`, `TarXz`, `TarZst`, `Zip`; converts into `ArchiveType`, the reverse fails for 7z |
| `ExtractRequest` / `ListRequest` / `VerifyRequest` / `SinkExtractRequest` / `CreateRequest` | Request values (#912): `config: &'a _`, options by value, optional `&mut dyn ProgressCallback` | `new`, `with_options`, `with_progress`; terminals `extract`, `list`, `list_reader`, `for_extraction`, `verify`, `verify_reader`, `SinkExtractRequest::extract`, `CreateRequest::{create, write, to_bytes}` |
| `ListedExtractOptions` | Options of `ListedArchive::extract` | `staging`, `existing_files` |
| `ExistingFiles` | What extraction does with an occupant of a landing (`#[non_exhaustive]`) | `Skip`, `Overwrite`, `Refuse` |
| `Staging` | How extraction commits (`#[non_exhaustive]`) | `InPlace`, `Atomic`, `AtomicReplace` |
| `DestinationCheck` | What `ListedArchive::check_destination` requires of the destination | `Vacant`, `Replaceable` |
| `OutputFile` / `OutputPolicy` / `OutputFormat` | Archive output of `CreateRequest::create` | see [[021-create-staging-and-output-policy/spec]] |

### SecurityConfig Defaults

| Field | Default |
|-------|---------|
| `max_file_size` | 50 MB (52,428,800 bytes) |
| `max_total_size` | 500 MB (524,288,000 bytes) |
| `max_compression_ratio` | 100.0 |
| `max_file_count` | 10,000 |
| `max_path_depth` | 32 |
| `allowed.symlinks` | false |
| `allowed.hardlinks` | false |
| `allowed.absolute_paths` | false |
| `allowed.world_writable` | false |
| `allowed.windows_reserved_names` | false (also for `permissive()`) |
| `permissions` | `PermissionPolicy::Normalize` (`with_preserve_permissions(true)` selects `Preserve`) |
| `allowed_extensions` | `ExtensionFilter::Any` |
| `selection` | every entry selected, paths kept (see [[022-extract-entry-selection/spec]]) |
| `banned_path_components` | `.git`, `.ssh`, `.gnupg`, `.aws`, `.kube`, `.docker`, `.env` |
| `solid_archives` | `Refuse`; under `Allow`, `SolidLimits::DEFAULT` = 512 MB block memory and ratio 1000.0 (`permissive()`: `Allow(PERMISSIVE)` = 1 GiB and 10,000.0) |
| `max_tar_metadata_bytes` | 4 MiB (16 MiB for `permissive()`) |
| `max_decoder_memory` | 256 MiB (1 GiB for `permissive()`) |
| `compressed_member_allowance` | 10,000 (100,000 for `permissive()`) |
| `zip_consistency` | `Enforce` (also for `permissive()`) |
| `parallel_decode` | `Bounded` 128 MiB (1 GiB for `permissive()`); `#[non_exhaustive] enum ParallelDecode { Sequential, Bounded(NonZeroU64) }`, no zero sentinel. Applies to one extraction: concurrent calls multiply threads (up to 16) and lookahead memory. A valid archive decodes to the same bytes in both modes; a corrupt one fails the same file, and only the failing file's leading bytes can differ |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| A zero `max_file_size`, `max_total_size`, `max_path_depth`, `max_file_count`, solid block memory, `max_tar_metadata_bytes`, `max_decoder_memory`, or `compressed_member_allowance` | Unrepresentable (`NonZero*`); the boundary conversion returns `InvalidConfiguration { Zero }` |
| A ratio of 0.0, negative, NaN or infinite | `RatioLimit::parse` returns `InvalidConfiguration` (`Zero`, `Negative` or `NotFinite`); fractional ratios such as 1.5 are accepted |
| A number above 2^53-1 from Node, or an integer beyond `i128` from Python | `InvalidConfiguration { TooLarge { max } }` (never `OverflowError`); a Python `bool` is a `TypeError` |
| An unknown creation format from a binding | `InvalidConfiguration { CreationFormat, NotOneOf { allowed } }`: `creation format is not one of the allowed values: Tar, TarGz, TarBz2, TarXz, TarZst, Zip` |
| `SevenZ` as a creation format | `InvalidConfiguration { CreationFormat, NotCreatable { SevenZ } }`: `7z archive creation is not supported` |
| A solid-limit setter while solid archives are refused | `InvalidConfiguration { MaxSolidBlockMemory, NotSupported }` |
| `DecompressionBudget::try_from_bytes(0)` | `InvalidConfiguration`; `ParallelDecode::Bounded` takes a `NonZeroU64`, so a zero lookahead is unrepresentable |
| `SecurityConfig` with an empty, null-byte-containing, or >255-byte `allowed_extensions`/`banned_path_components` entry | `Extension::try_from` / `PathComponentName::try_from` return `InvalidConfiguration` (v0.6.0, #449; moved into the entry types in v0.8.0) |
| `compression_level` outside 1–9 (0 or > 9) | `CompressionLevel::try_from` returns `Err(ArchiveError::InvalidCompressionLevel)`; `CreationConfig::with_compression_level` takes the already-validated `CompressionLevel` |
| A hand-built `CreationConfig` with a compression level of 200 reaches `flate2`/`liblzma` directly | Unrepresentable: the field is a `CompressionLevel`, constructible only by `CompressionLevel::try_from` (the v0.6.0 typestate that once guarded this was replaced by the type of the field in #898) |
| `Staging::Atomic` and output on a different filesystem than temp dir | `fs::rename` may fail; caller receives `ArchiveError::Io` |
| An occupant at a landing under `ExistingFiles::Skip` | The entry is skipped and counted as a duplicate |
| An occupant at a landing under `Overwrite` | Replaced where the kinds allow; a kind conflict (file over directory, symlink over file or link, hardlink over anything) is refused under every variant |
| An occupant at a landing under `Refuse` | `ArchiveError::DestinationOccupied`, wrapped in `Partial` when entries were already written; an occupant this run created (an in-archive duplicate) is skipped as a duplicate, as under `Skip` |
| Atomic extraction fails mid-archive | Temp dir deleted; `ArchiveError` returned; no files in output dir |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | `SecurityConfig::default()` covers all deny-by-default policies | Verified by unit test |
| SC-002 | Boundary conversions reject all invalid inputs | Property-based tests with zero/negative/NaN/fractional/oversized inputs |
| SC-003 | Atomic extraction leaves no partial output | Integration test: inject failure mid-archive |
| SC-004 | Fluent builder produces correct configuration | Unit tests for each `with_*` method |

## 8. Agent Boundaries

### Always (without asking)
- Convert runtime values through the `limit.rs` boundary functions before storing them in a config
- Use `Default` implementations as the canonical starting point for config construction
- Document the default value for every field in `///` doc comments

### Ask First
- Changing any `SecurityConfig` default value (security policy change)
- Adding a new field to `SecurityConfig` (must also update `#[non_exhaustive]` considerations)
- Enabling any `AllowedFeatures` flag by default

### Never
- Add mutable state to any config type after construction
- Store a runtime number in a config field without the typed boundary conversion
- Reintroduce a validation typestate or a `validate()` call
- Raise or remove quota defaults without a security review

## 9. Open Questions

- [NEEDS CLARIFICATION: Should `ExtractionOptions` include a `max_concurrency` field for future parallel extraction?]

> [!note] Resolved in v0.4.1 and v0.5.0
> `CreationConfig::with_compression_level` (and `ArchiveCreator::compression_level`) take a
> `CompressionLevel` newtype; passing a level of 0 or > 9 to `CompressionLevel::try_from` returns
> `ArchiveError::InvalidCompressionLevel`; the panic at the former call site is eliminated (#257, #308).
> (Between v0.4.1 and v0.8.0 the setters returned `Result<Self, ArchiveError>`.)

## 10. See Also

- [[constitution]] — immutable config and fluent builder principles
- [[MOC-specs]] — all specifications
- [[001-security-pipeline/spec]] — consumes `SecurityConfig` and `AllowedFeatures`
- [[002-format-handlers/spec]] — consumes `CreationConfig` and `ExtractionOptions`
- [[014-config-typestate-validation/spec]] — obsolete: the removed `Unvalidated`/`Validated` typestate
- [[021-create-staging-and-output-policy/spec]] — `OutputFile`, `EntryPattern` and staged creation
- [[020-reader-sink-and-in-memory-api/spec]] — `SinkOptions`, `CreatableFormat`, `MemoryLimit` consumers
- [[001-exarch-system/spec]] — original monolithic spec (archived)
