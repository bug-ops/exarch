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
updated: 2026-08-04
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[001-security-pipeline/spec]]"
  - "[[002-format-handlers/spec]]"
  - "[[014-config-typestate-validation/spec]]"
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
GIVEN SecurityConfig::default().with_allowed_extensions(vec!["\0evil"])
WHEN validate() is called
THEN it returns ArchiveError::InvalidConfiguration (entry contains a null byte)
```

> [!note] Unreleased (v0.6.0): entry-level validation for allowlist/banlist fields (#449)
> A new `validate_config_entry` helper (`exarch-core::security::boundary`, re-exported as
> `exarch_core::validate_config_entry` alongside `MAX_CONFIG_ENTRY_LENGTH`) is called per-entry
> from `SecurityConfig::validate()` for both `allowed_extensions` and `banned_path_components`.
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
GIVEN CreationConfig::default().with_compression_level(9)?.with_exclude_patterns(vec!["*.log"])
WHEN create_archive() is called
THEN all .log files are excluded and maximum compression is applied
```

> [!note] `with_compression_level` returns `Result`
> Since v0.4.1 / v0.5.0, `with_compression_level` returns `Result<Self, ArchiveError>`.
> Builder chains must propagate the error with `?` before chaining further methods.

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
| FR-030 | `SecurityConfig` SHALL expose 15 fluent builder methods: `with_max_file_size`, `with_max_total_size`, `with_max_compression_ratio`, `with_max_file_count`, `with_max_path_depth`, `with_allowed`, `with_allow_symlinks`, `with_allow_hardlinks`, `with_allow_absolute_paths`, `with_allow_world_writable`, `with_preserve_permissions`, `with_allowed_extensions`, `with_banned_path_components`, `with_allow_solid_archives`, `with_max_solid_block_memory`; each returns `Self` | must |
| FR-031 | `SecurityConfig`, `AllowedFeatures`, and `ExtractionOptions` SHALL be annotated `#[non_exhaustive]`; external crates must use `Default::default()` plus builder methods — struct literal construction is a compile error | must |
| FR-032 | `SecurityConfig::validate()` SHALL return `InvalidConfiguration` if: any numeric limit is zero (`max_file_size`, `max_total_size`, `max_file_count`, `max_path_depth`, `max_solid_block_memory`), or `max_compression_ratio` is zero, negative, or NaN | must |
| FR-033 | `CreationConfig` SHALL support: `follow_symlinks`, `include_hidden`, `max_file_size`, `exclude_patterns` (glob), `strip_prefix`, `compression_level` (1–9), `preserve_permissions`, `format` override; `with_compression_level` returns `Result<Self, ArchiveError>` — callers must propagate the error with `?`; passing a level outside 1–9 returns `ArchiveError::InvalidCompressionLevel` instead of panicking | must |
| FR-034 | `ExtractionOptions` SHALL support: `atomic` (temp-dir + rename) via `with_atomic`, `skip_duplicates` (default true) via `with_skip_duplicates` | must |
| FR-035 | WHEN `ExtractionOptions::atomic` is true, THE SYSTEM SHALL extract to a temp dir in the same parent as the output directory and atomically rename on success | must |
| FR-036 | WHEN atomic extraction fails, THE SYSTEM SHALL delete the temp dir before returning the error | must |
| FR-037 | All three config types SHALL implement `Default` with documented defaults | must |
| FR-038 | `AllowedFeatures` SHALL be a separate struct with boolean flags: `symlinks`, `hardlinks`, `absolute_paths`, `world_writable`; all default to false | must |
| FR-039 | `CreationConfig::validate()` SHALL be called inside `create_archive_with_progress` before any I/O; invalid configurations SHALL be rejected early | must |
| FR-040 | `SecurityConfig` and `CreationConfig` SHALL be two-state typestates over `Unvalidated`/`Validated` phantom markers; fluent `with_*` builders SHALL exist only on `T<Unvalidated>`; `validate()` SHALL consume `self` and return `Result<T<Validated>>` instead of `Result<()>` (v0.6.0, see [[014-config-typestate-validation/spec]]) | must |
| FR-041 | `SecurityConfig::validate()` SHALL reject any `allowed_extensions` or `banned_path_components` entry that is empty, contains a null byte, or exceeds 255 bytes, via the shared `validate_config_entry` helper | must |
| FR-042 | `T<Validated>` SHALL be reachable read-only via `Deref` for both typestates, but mutable (`DerefMut`) only for `T<Unvalidated>`, so a validated config cannot be mutated back into an unvalidated-equivalent state after the fact | must |
| FR-043 | Top-level `extract_archive*`, `list_archive`, `verify_archive`, and `create_archive*` functions SHALL continue to accept a plain `&SecurityConfig`/`CreationConfig` (defaulting to `Unvalidated`) and validate internally, so bindings and CLI callers require no changes | must |

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
| `SecurityConfig<State = Unvalidated>` | Security policy for extraction and inspection operations; typestate over `Unvalidated`/`Validated` since v0.6.0 | `max_file_size`, `max_total_size`, `max_compression_ratio`, `max_file_count`, `max_path_depth`, `allowed: AllowedFeatures`, `banned_path_components`, `allowed_extensions`, `allow_solid_archives`, `max_solid_block_memory`, `max_tar_metadata_bytes`; fields sealed behind a private `SecurityConfigFields` struct, reachable via `Deref`/`DerefMut` |
| `AllowedFeatures` | Feature flags for deny-by-default policy | `symlinks: bool`, `hardlinks: bool`, `absolute_paths: bool`, `world_writable: bool` |
| `CreationConfig<State = Unvalidated>` | Configuration for archive creation; typestate over `Unvalidated`/`Validated` since v0.6.0 (mirrors `SecurityConfig`) | `follow_symlinks`, `include_hidden`, `max_file_size`, `exclude_patterns`, `strip_prefix`, `compression_level` (1–9), `preserve_permissions`, `format: Option<ArchiveType>`; fields sealed behind `CreationConfigFields` (`#[non_exhaustive]`) |
| `ExtractionOptions` | Operational options for extraction (non-security) | `atomic: bool`, `skip_duplicates: bool` |
| `Unvalidated` / `Validated` | Zero-sized phantom marker types re-exported at crate root | Encode config validation state at compile time; used as the default and post-`validate()` type parameter of `SecurityConfig`/`CreationConfig` respectively |

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
| `preserve_permissions` | false |
| `allowed_extensions` | `[]` (all allowed) |
| `banned_path_components` | `.git`, `.ssh`, `.gnupg`, `.aws`, `.kube`, `.docker`, `.env` |
| `allow_solid_archives` | false |
| `max_solid_block_memory` | 512 MB |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| `SecurityConfig` with zero `max_file_size`, `max_total_size`, `max_path_depth`, `max_file_count`, or `max_solid_block_memory` | `validate()` returns `InvalidConfiguration` |
| `SecurityConfig` with `max_compression_ratio` of 0.0, negative, or NaN | `validate()` returns `InvalidConfiguration` |
| `SecurityConfig` with an empty, null-byte-containing, or >255-byte `allowed_extensions`/`banned_path_components` entry | `validate()` returns `InvalidConfiguration` (v0.6.0, #449) |
| `compression_level` outside 1–9 (0 or > 9) | `ArchiveCreator::compression_level` (and `CreationConfig::with_compression_level`) returns `Err(ArchiveError::InvalidCompressionLevel)`; callers must handle with `?` or explicit match |
| A hand-built `CreationConfig` with `compression_level: Some(200)` reaches `flate2`/`xz2` directly (bypassing the high-level `with_compression_level` contract) | No longer possible: `creation::tar::*`/`creation::zip::*` and `FormatCreator::create` require `&CreationConfig<Validated>`, so an invalid compression level cannot compile its way past validation (v0.6.0, #443 — previously an `assert!`/`unwrap()` panic inside the compression backend, a panic-based DoS) |
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
> `CreationConfig::with_compression_level` (and `ArchiveCreator::compression_level`) now returns
> `Result<Self, ArchiveError>` rather than `Self`. Passing a level of 0 or > 9 returns
> `ArchiveError::InvalidCompressionLevel`; the panic at the former call site is eliminated (#257, #308).

## 10. See Also

- [[constitution]] — immutable config and fluent builder principles
- [[MOC-specs]] — all specifications
- [[001-security-pipeline/spec]] — consumes `SecurityConfig` and `AllowedFeatures`
- [[002-format-handlers/spec]] — consumes `CreationConfig` and `ExtractionOptions`
- [[014-config-typestate-validation/spec]] — `Unvalidated`/`Validated` typestate design in detail
- [[001-exarch-system/spec]] — original monolithic spec (archived)
