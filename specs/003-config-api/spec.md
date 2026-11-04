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
updated: 2026-11-02
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[001-security-pipeline/spec]]"
  - "[[002-format-handlers/spec]]"
  - "[[014-config-typestate-validation/spec]]"
  - "[[017-zip-header-consistency/spec]]"
  - "[[020-reader-sink-and-in-memory-api/spec]]"
---

# Feature: Configuration API

> [!info] Metadata
> **Subsystem**: exarch-core / config, creation
> **MSRV**: Rust 1.98.0
> **Source**: extracted from [[001-exarch-system/spec]]

## 1. Overview

### Problem Statement

Security policy, creation options, and extraction behavior must be expressible
at the call site without mutating shared state. A single mutable global config
or stringly-typed options map would make it easy to accidentally weaken security
defaults or produce invalid configurations.

### Goal

Provide three immutable, builder-pattern configuration types — `SecurityConfig`,
`CreationConfig`, and `ExtractionOptions` — that encode all tunable parameters
with secure deny-by-default values, validated before use.

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
GIVEN SecurityConfig::default().with_max_file_size(200 * 1024 * 1024).with_allow_symlinks(true)
WHEN passed to extract_archive()
THEN extraction allows symlinks and accepts files up to 200 MB
```

### US-003: Configuration Validation

AS A developer
I WANT SecurityConfig::validate() to catch invalid configurations early
SO THAT extraction does not start with a zero or non-finite limit

**Acceptance criteria:**
```
GIVEN SecurityConfig::default().with_max_file_size(0)
WHEN validate() is called
THEN it returns ArchiveError::InvalidConfiguration before extraction begins
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

### US-006: Compile-Time Validation Enforcement

AS A library maintainer
I WANT the type system to make it impossible to reach extraction/listing/verification
with an unvalidated or invalid `SecurityConfig`
SO THAT a caller cannot accidentally (or via a future refactor) bypass `validate()`

**Acceptance criteria:**
```
GIVEN a hand-built SecurityConfig<Unvalidated>
WHEN it is passed directly to ArchiveFormat::extract/list/verify (not the top-level
     extract_archive/list_archive/verify_archive functions)
THEN the code does not compile — those methods require &SecurityConfig<Validated>
```

See [[014-config-typestate-validation/spec]] for the full typestate design.

### US-004: Archive Creation Configuration

AS A developer building a packaging tool
I WANT to control compression level, file filtering, and symlink handling during creation
SO THAT I can produce well-formed archives without manual format handling

**Acceptance criteria:**
```
GIVEN CreationConfig::default().with_compression_level(CompressionLevel::try_from(9u8)?).with_exclude_patterns(vec!["*.log"])
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
GIVEN ExtractionOptions::default().with_atomic(true)
WHEN extraction fails mid-archive
THEN no files are present in the output directory; the temp dir is cleaned up
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-030 | `SecurityConfig` SHALL expose 22 fluent builder methods: `with_max_file_size`, `with_max_total_size`, `with_max_compression_ratio`, `with_max_solid_compression_ratio`, `with_max_file_count`, `with_max_path_depth`, `with_allowed`, `with_allow_symlinks`, `with_allow_hardlinks`, `with_allow_absolute_paths`, `with_allow_world_writable`, `with_allow_windows_reserved_names`, `with_preserve_permissions`, `with_allowed_extensions`, `with_banned_path_components`, `with_allow_solid_archives`, `with_max_solid_block_memory`, `with_max_tar_metadata_bytes`, `with_max_decoder_memory`, `with_compressed_member_allowance`, `with_parallel_decode`, `with_zip_consistency`; each returns `Self` | must |
| FR-031 | `SecurityConfig`, `AllowedFeatures`, and `ExtractionOptions` SHALL be annotated `#[non_exhaustive]`; external crates must use `Default::default()` plus builder methods — struct literal construction is a compile error | must |
| FR-032 | `SecurityConfig::validate()` SHALL return `InvalidConfiguration` if: any numeric limit is zero (`max_file_size`, `max_total_size`, `max_file_count`, `max_path_depth`, `max_solid_block_memory`, `max_tar_metadata_bytes`, `max_decoder_memory`, `compressed_member_allowance`), or `max_compression_ratio` or `max_solid_compression_ratio` is zero, negative, or non-finite | must |
| FR-033 | `CreationConfig` SHALL support: `follow_symlinks`, `include_hidden`, `max_file_size` (`Limit<NonZeroU64>`, default `Limit::Unbounded`; `with_max_file_size` takes `impl Into<Limit<NonZeroU64>>`, so a zero limit is unrepresentable and files above a bound are skipped; the CLI (`create --max-file-size 0`), Node and Python refuse zero as `InvalidConfiguration`, Node `setMaxFileSize` takes `null` and Python `None` for no limit; v0.8.0, #893, #902, #946), `exclude_patterns` (glob), `strip_prefix`, `compression_level` (1–9), `preserve_permissions`, `format: Option<CreatableFormat>` override (`CreatableFormat` has no 7z variant, so a 7z creation request is unrepresentable; v0.8.0, #794, #808); `compression_level` is a `CompressionLevel` newtype (default 6) obtained via `CompressionLevel::try_from(u8)`, and `with_compression_level` takes it and returns `Self`; a level outside 1–9 is rejected at `CompressionLevel` construction with `ArchiveError::InvalidCompressionLevel` | must |
| FR-034 | `ExtractionOptions` SHALL support: `atomic` (temp-dir + rename) via `with_atomic`, `skip_duplicates` (default true) via `with_skip_duplicates` | must |
| FR-035 | WHEN `ExtractionOptions::atomic` is true, THE SYSTEM SHALL extract to a temp dir in the same parent as the output directory and atomically rename on success | must |
| FR-036 | WHEN atomic extraction fails, THE SYSTEM SHALL delete the temp dir before returning the error | must |
| FR-037 | All three config types SHALL implement `Default` with documented defaults | must |
| FR-038 | `AllowedFeatures` SHALL be a separate struct with boolean flags: `symlinks`, `hardlinks`, `absolute_paths`, `world_writable`, `windows_reserved_names`; all default to false (`permissive()` leaves `windows_reserved_names` false). `windows_reserved_names` is consulted only on Windows and has no CLI or binding opt-out | must |
| FR-039 | `CreationConfig::validate()` SHALL be called inside `create_archive_with_progress` before any I/O; invalid configurations SHALL be rejected early | must |
| FR-040 | `SecurityConfig` and `CreationConfig` SHALL be two-state typestates over `Unvalidated`/`Validated` phantom markers; fluent `with_*` builders SHALL exist only on `T<Unvalidated>`; `validate()` SHALL consume `self` and return `Result<T<Validated>>` instead of `Result<()>` (v0.6.0, see [[014-config-typestate-validation/spec]]) | must |
| FR-041 | `SecurityConfig::validate()` SHALL admit only `Extension` (normalized, no leading dot) and `PathComponentName` entries in `allowed_extensions` / `banned_path_components`; their `TryFrom<&str>` constructors reject an entry that is empty, contains a null byte or edge whitespace, or exceeds 255 bytes, so an invalid entry is unrepresentable | must |
| FR-042 | `T<Validated>` SHALL be reachable read-only via `Deref` for both typestates, but mutable (`DerefMut`) only for `T<Unvalidated>`, so a validated config cannot be mutated back into an unvalidated-equivalent state after the fact | must |
| FR-043 | Top-level `extract_archive*`, `list_archive`, `verify_archive`, and `create_archive*` functions SHALL continue to accept a plain `&SecurityConfig`/`CreationConfig` (defaulting to `Unvalidated`) and validate internally, so bindings and CLI callers require no changes | must |
| FR-044 | `SecurityConfig` SHALL expose `zip_consistency: ZipConsistencyPolicy` (`#[non_exhaustive]`: `Enforce`, the default also for `permissive()`; `Ignore`) deciding whether structurally ambiguous ZIP archives are rejected in `extract`/`list` and reported in `verify` (see [[017-zip-header-consistency/spec]]); the CLI exposes it as `--zip-consistency`, Python and Node as a config option | must |
| FR-045 | `SecurityConfig` SHALL expose `parallel_decode: ParallelDecode` (`Sequential` or `Bounded(NonZeroU64)`) bounding the lookahead memory of parallel 7z LZMA2 decoding, separately from `max_decoder_memory`; the CLI exposes it as `--parallel-decode-memory` | must |
| FR-046 | `max_solid_compression_ratio` (7z solid blocks) and `max_decoder_memory` (xz and 7z decoder window, zstd window of TAR and ZIP as the largest power of two within it, at most 128 MiB; breach is `QuotaExceeded { DecoderMemory }`, v0.8.0, #849) and `compressed_member_allowance` (base number of gzip members or bzip2 streams of a TAR, plus one per 16 KiB of output; breach is `QuotaExceeded { CompressedMembers }`, v0.8.0, #851) SHALL be Rust-API-only settings, not exposed by the CLI or the Python/Node bindings | must |
| FR-047 | `max_file_count` SHALL bound the files, symlinks and hardlinks that `extract` creates (directories are not counted); `list` and `verify` count every entry | must |
| FR-048 | `SinkOptions` (`#[non_exhaustive]`, Copy; fields `skip_duplicates`, default true, builder `with_skip_duplicates`, and `decode_reuse: DecodeReuse`, default `DecodeReuse::Off`, builder `with_decode_reuse`, #890, #946) SHALL be the options of `extract_to_sink*` and `extract_reader_to_callback`; `SinkOptions::try_from(&ExtractionOptions)` SHALL carry the duplicate policy over, never `decode_reuse`, and fail with `InvalidConfiguration` when `atomic` is set; `MemoryLimit::from_config(&SecurityConfig)` SHALL derive a non-zero memory bound from `max_total_size` (v0.8.0, #794, #808; see [[020-reader-sink-and-in-memory-api/spec]]) | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Safety | Configuration is immutable after construction — no interior mutability |
| NFR-002 | Reliability | Atomic extraction (`ExtractionOptions::atomic`) ensures all-or-nothing semantics on same filesystem |
| NFR-003 | Usability | Fluent builder chains are ergonomic: each `with_*` method returns `Self` |
| NFR-004 | Compatibility | `#[non_exhaustive]` on `SecurityConfig` prevents downstream struct literal construction |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `SecurityConfig<State = Unvalidated>` | Security policy for extraction and inspection operations; typestate over `Unvalidated`/`Validated` since v0.6.0 | `max_file_size`, `max_total_size`, `max_compression_ratio`, `max_solid_compression_ratio`, `max_file_count`, `max_path_depth`, `allowed: AllowedFeatures`, `banned_path_components`, `allowed_extensions`, `allow_solid_archives`, `max_solid_block_memory`, `max_tar_metadata_bytes`, `max_decoder_memory`, `compressed_member_allowance`, `parallel_decode`, `zip_consistency`; fields sealed behind a private `SecurityConfigFields` struct, reachable via `Deref`/`DerefMut` |
| `AllowedFeatures` | Feature flags for deny-by-default policy | `symlinks: bool`, `hardlinks: bool`, `absolute_paths: bool`, `world_writable: bool`, `windows_reserved_names: bool` |
| `ParallelDecode` | `#[non_exhaustive]` enum: how much lookahead memory a 7z block may use to decode LZMA2 runs on worker threads | `Sequential`, `Bounded(NonZeroU64)`; `lookahead()`; `DEFAULT_BYTES` = 128 MiB |
| `ZipConsistencyPolicy` | `#[non_exhaustive]` enum: handling of ZIP archives that different readers interpret differently | `Enforce` (default), `Ignore`; `as_str()` |
| `VerificationOptions` / `IntegrityCheck` / `DecompressionBudget` | Options for `verify_archive_with_options`; the budget lives inside `IntegrityCheck::DecodeToEof`, so a budget without the check is unrepresentable | `integrity: IntegrityCheck` (`Skip` default, `DecodeToEof(DecompressionBudget)`); budget default 500 MiB, non-zero |
| `ListOptions` / `StoredTargets` | Options for `list_archive_with_options`; whether 7z link targets kept in compressed entry data are read | `stored_targets: StoredTargets` (`Skip` default, `Read`) |
| `CreationConfig<State = Unvalidated>` | Configuration for archive creation; typestate over `Unvalidated`/`Validated` since v0.6.0 (mirrors `SecurityConfig`) | `follow_symlinks`, `include_hidden`, `max_file_size: Limit<NonZeroU64>`, `exclude_patterns`, `strip_prefix`, `compression_level` (1–9), `preserve_permissions`, `format: Option<CreatableFormat>`; fields sealed behind `CreationConfigFields` (`#[non_exhaustive]`) |
| `ExtractionOptions` | Operational options for extraction (non-security) | `atomic: bool`, `skip_duplicates: bool` |
| `SinkOptions` | Options of sink extraction (v0.8.0) | `skip_duplicates: bool` (default true); `TryFrom<&ExtractionOptions>` rejects `atomic` |
| `CreatableFormat` | `#[non_exhaustive]` archive formats that can be created (v0.8.0) | `Tar`, `TarGz`, `TarBz2`, `TarXz`, `TarZst`, `Zip`; converts into `ArchiveType`, the reverse fails for 7z |
| `Unvalidated` / `Validated` | Zero-sized phantom marker types re-exported at crate root | Encode config validation state at compile time; used as the default and post-`validate()` type parameter of `SecurityConfig`/`CreationConfig` respectively |

### SecurityConfig Defaults

| Field | Default |
|-------|---------|
| `max_file_size` | 50 MB (52,428,800 bytes) |
| `max_total_size` | 500 MB (524,288,000 bytes) |
| `max_compression_ratio` | 100.0 |
| `max_solid_compression_ratio` | 1000.0 (10,000.0 for `permissive()`) |
| `max_file_count` | 10,000 |
| `max_path_depth` | 32 |
| `allowed.symlinks` | false |
| `allowed.hardlinks` | false |
| `allowed.absolute_paths` | false |
| `allowed.world_writable` | false |
| `allowed.windows_reserved_names` | false (also for `permissive()`) |
| `preserve_permissions` | false |
| `allowed_extensions` | `[]` (all allowed) |
| `banned_path_components` | `.git`, `.ssh`, `.gnupg`, `.aws`, `.kube`, `.docker`, `.env` |
| `allow_solid_archives` | false |
| `max_solid_block_memory` | 512 MB |
| `max_tar_metadata_bytes` | 4 MiB (16 MiB for `permissive()`) |
| `max_decoder_memory` | 256 MiB (1 GiB for `permissive()`) |
| `compressed_member_allowance` | 10,000 (100,000 for `permissive()`) |
| `zip_consistency` | `Enforce` (also for `permissive()`) |
| `parallel_decode` | `Bounded` 128 MiB (1 GiB for `permissive()`); `#[non_exhaustive] enum ParallelDecode { Sequential, Bounded(NonZeroU64) }`, no zero sentinel. Applies to one extraction: concurrent calls multiply threads (up to 16) and lookahead memory. A valid archive decodes to the same bytes in both modes; a corrupt one fails the same file, and only the failing file's leading bytes can differ |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| `SecurityConfig` with zero `max_file_size`, `max_total_size`, `max_path_depth`, `max_file_count`, `max_solid_block_memory`, `max_tar_metadata_bytes`, `max_decoder_memory`, or `compressed_member_allowance` | `validate()` returns `InvalidConfiguration` |
| `SecurityConfig` with `max_compression_ratio` or `max_solid_compression_ratio` of 0.0, negative, or non-finite | `validate()` returns `InvalidConfiguration` |
| `DecompressionBudget::try_from_bytes(0)` | `InvalidConfiguration`; `ParallelDecode::Bounded` takes a `NonZeroU64`, so a zero lookahead is unrepresentable |
| `SecurityConfig` with an empty, null-byte-containing, or >255-byte `allowed_extensions`/`banned_path_components` entry | `Extension::try_from` / `PathComponentName::try_from` return `InvalidConfiguration` (v0.6.0, #449; moved into the entry types in v0.8.0) |
| `compression_level` outside 1–9 (0 or > 9) | `CompressionLevel::try_from` returns `Err(ArchiveError::InvalidCompressionLevel)`; `ArchiveCreator::compression_level` and `CreationConfig::with_compression_level` take the already-validated `CompressionLevel` |
| A hand-built `CreationConfig` with a compression level of 200 reaches `flate2`/`liblzma` directly (bypassing the high-level `with_compression_level` contract) | No longer possible: `creation::tar::*`/`creation::zip::*` and `FormatCreator::create` require `&CreationConfig<Validated>`, so an invalid compression level cannot compile its way past validation (v0.6.0, #443 — previously an `assert!`/`unwrap()` panic inside the compression backend, a panic-based DoS) |
| `atomic = true` and output on a different filesystem than temp dir | `fs::rename` may fail; caller receives `ArchiveError::Io` |
| `skip_duplicates = false` and duplicate entry | `ArchiveError::InvalidArchive` (duplicate entry) |
| Atomic extraction fails mid-archive | Temp dir deleted; `ArchiveError` returned; no files in output dir |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | `SecurityConfig::default()` covers all deny-by-default policies | Verified by unit test |
| SC-002 | `validate()` rejects all invalid configurations | Property-based tests with zero/negative/NaN inputs |
| SC-003 | Atomic extraction leaves no partial output | Integration test: inject failure mid-archive |
| SC-004 | Fluent builder produces correct configuration | Unit tests for each `with_*` method |

## 8. Agent Boundaries

### Always (without asking)
- Validate `SecurityConfig` before passing to any operation
- Use `Default` implementations as the canonical starting point for config construction
- Document the default value for every field in `///` doc comments

### Ask First
- Changing any `SecurityConfig` default value (security policy change)
- Adding a new field to `SecurityConfig` (must also update `#[non_exhaustive]` considerations)
- Enabling any `AllowedFeatures` flag by default

### Never
- Add mutable state to any config type after construction
- Bypass `validate()` in any code path that accepts a `SecurityConfig`
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
- [[014-config-typestate-validation/spec]] — `Unvalidated`/`Validated` typestate design in detail
- [[020-reader-sink-and-in-memory-api/spec]] — `SinkOptions`, `CreatableFormat`, `MemoryLimit` consumers
- [[001-exarch-system/spec]] — original monolithic spec (archived)
