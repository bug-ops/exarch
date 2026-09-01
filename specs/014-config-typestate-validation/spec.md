---
aliases:
  - Config Typestate Validation
  - SecurityConfig/CreationConfig Unvalidated-Validated Typestate
tags:
  - sdd
  - spec
  - security
  - rust
  - typestate
created: 2026-08-04
status: implemented
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[001-security-pipeline/spec]]"
  - "[[003-config-api/spec]]"
  - "[[013-quota-permit-capability-token/spec]]"
---

# Feature: Config Typestate Validation

> [!info] Metadata
> **Subsystem**: exarch-core / config, creation
> **MSRV**: Rust 1.98.0
> **Origin**: #433, #434, #435 (`SecurityConfig`), #443 (`CreationConfig`) — v0.6.0, unreleased
> **Status**: implemented — this spec documents shipped behavior, extracted from
> [[003-config-api/spec]] because it introduces a reusable pattern (typestate-enforced
> validation) worth tracking as its own unit

## 1. Overview

### Problem Statement

Before v0.6.0, `SecurityConfig::validate()` and `CreationConfig::validate()` returned
`Result<()>` — validation was a side-effect-free check the caller was expected to run
before passing the config onward, but nothing prevented a caller (inside `exarch-core`
itself, or a future refactor) from skipping it. Two concrete instances of this gap
existed in practice:

- A hand-built `CreationConfig` with a forged `compression_level: Some(200)` could reach
  `flate2`'s `zlib-rs` backend or `xz2` directly, bypassing the `InvalidCompressionLevel`
  contract enforced only at the two high-level entry points, and trigger an
  `assert!`/`unwrap()` panic inside the compression backend — a panic-based
  denial-of-service reachable from a config value, not archive content.
- Nothing in the type system distinguished "a `SecurityConfig` that was validated" from
  "a `SecurityConfig` that merely exists" at the boundary of `ArchiveFormat::extract` /
  `list` / `verify` — the "call `validate()` first" rule was convention, not a compiler
  guarantee.

### Goal

Encode "has this config been validated?" as part of the type itself, so that code
downstream of validation (`ArchiveFormat` trait methods, the low-level `creation::tar::*`/
`creation::zip::*` functions, every security primitive) can require a `Validated` config
as an input type, making "extraction reached with an unvalidated config" a compile error
rather than a runtime possibility — without changing the validation logic itself or
breaking the ergonomics of the existing fluent builder API for ordinary callers.

### Out of Scope

- The validation *rules* themselves (which fields are checked, what counts as invalid) —
  see [[003-config-api/spec]] and [[001-security-pipeline/spec]]
- `QuotaPermit`, a related but independent capability-token pattern for quota charges —
  see [[013-quota-permit-capability-token/spec]]
- Changing the top-level `extract_archive*`/`list_archive`/`verify_archive`/
  `create_archive*` function signatures — they are deliberately unaffected (see FR-006)

## 2. User Stories

### US-001: Compiler-Enforced "Validated Before Use"

AS A library maintainer
I WANT the compiler to refuse code that reaches `ArchiveFormat::extract`/`list`/`verify`
with a `SecurityConfig` that has not gone through `validate()`
SO THAT the existing "call `validate()` before use" convention becomes structurally
impossible to violate, in this crate or in any future refactor

**Acceptance criteria:**
```
GIVEN a SecurityConfig<Unvalidated> constructed via SecurityConfig::default()
WHEN it is passed directly to TarArchive::extract/list/verify (bypassing
     extract_archive/list_archive/verify_archive)
THEN the code does not compile — those methods require &SecurityConfig<Validated>
```

### US-002: Existing Callers Unaffected

AS A caller of the top-level `extract_archive`/`create_archive`/etc. functions, or a
maintainer of `exarch-cli`/`exarch-python`/`exarch-node`
I WANT my existing code (which only ever holds a plain, unvalidated `SecurityConfig`
and passes it to the top-level functions) to keep compiling unchanged
SO THAT this hardening does not force a migration across every caller of the public API

**Acceptance criteria:**
```
GIVEN exarch-cli's existing code building a SecurityConfig via with_* builders and
      passing it to extract_archive()
WHEN this typestate change ships
THEN exarch-cli compiles with zero changes — extract_archive still accepts a plain
     &SecurityConfig (defaulting to Unvalidated) and validates internally
```

### US-003: No Panic-Based DoS via Forged Compression Level

AS A security reviewer
I WANT it to be impossible for an invalid `compression_level` to reach the compression
backend without going through `InvalidCompressionLevel` validation first
SO THAT a hand-built `CreationConfig` (bypassing the high-level builder) cannot trigger
an `assert!`/`unwrap()` panic inside `flate2`/`xz2`

**Acceptance criteria:**
```
GIVEN a CreationConfig with compression_level: Some(200) constructed via struct-literal
      syntax (bypassing with_compression_level's own validation)
WHEN it is passed to creation::tar::* or creation::zip::* functions directly
THEN the code does not compile — those functions require &CreationConfig<Validated>,
     which can only be produced by CreationConfig::validate() returning Ok
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | `SecurityConfig<State = Unvalidated>` and `CreationConfig<State = Unvalidated>` SHALL carry a phantom `State` type parameter defaulting to `Unvalidated` | must |
| FR-002 | The fluent `with_*` builder methods SHALL remain available only on `T<Unvalidated>` | must |
| FR-003 | `validate()` SHALL consume `self` by value and return `Result<T<Validated>>` instead of `Result<()>` | must |
| FR-004 | `ArchiveFormat::extract`, `list`, `verify` SHALL require `config: &SecurityConfig<Validated>`; every downstream security function (`EntryValidator`, `SafePath::validate`, `SafeSymlink::validate`, `QuotaTracker::reserve`, `validate_symlink`, `validate_compression_ratio`, `HardlinkTracker::validate_hardlink`, `sanitize_permissions`) SHALL likewise require `&SecurityConfig<Validated>` | must |
| FR-005 | `creation::tar::*`/`creation::zip::*` functions and `FormatCreator::create` SHALL require `&CreationConfig<Validated>`; `creation::filters::should_skip`/`compute_archive_path` SHALL gain a `State` type parameter | must |
| FR-006 | Top-level `extract_archive*`, `list_archive`, `verify_archive`, and `create_archive*` functions SHALL be unaffected: they SHALL continue to accept a plain `&SecurityConfig`/`CreationConfig` (defaulting to `Unvalidated`) and validate internally before dispatching to the typestate-gated internals | must |
| FR-007 | `SecurityConfig::default()`/`CreationConfig::default()` SHALL continue to infer `Unvalidated` with no turbofish required at any existing call site | must |
| FR-008 | `Unvalidated` and `Validated` SHALL be zero-sized phantom marker types, re-exported at the crate root | must |
| FR-009 | Fields SHALL be sealed behind a private inner fields struct (`SecurityConfigFields`, `CreationConfigFields` — the latter `#[non_exhaustive]`), reachable read-only via `Deref` for both typestates but mutable (`DerefMut`) only for `T<Unvalidated>`, so a `T<Validated>` cannot be mutated back into an invalid state after the fact while existing `cfg.max_file_size`-style field access keeps working for every caller | must |
| FR-010 | `ValidatedEntry` (`security::validator`) SHALL become sealed as part of this hardening: private fields, `pub(crate)` constructor, `safe_path()`/`entry_type()`/`mode()` accessors replacing direct field access, assemblable only via `EntryValidator::validate_entry()` | must |
| FR-011 | `exarch-cli`, `exarch-python`, and `exarch-node` SHALL require no changes: they only ever hold `SecurityConfig<Unvalidated>`/`CreationConfig<Unvalidated>` and pass it to the top-level API, which validates internally (`exarch-cli`'s `create` command, which previously built a `CreationConfig` via struct-literal syntax, is the one call site that needed updating) | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Safety | Enforcement is purely compile-time (phantom types + visibility) — zero runtime cost vs. the pre-v0.6.0 `Result<()>`-returning `validate()` |
| NFR-002 | Compatibility | Every caller of the top-level `extract_archive*`/`list_archive`/`verify_archive`/`create_archive*` functions (including `exarch-cli`, `exarch-python`, `exarch-node`) compiles unchanged |
| NFR-003 | Correctness | No validation *logic* changed by this spec — the same checks that previously ran inside `validate()` still run; only the type-level enforcement of "was `validate()` called" is new |
| NFR-004 | API stability | This is a `pub` API surface change (`validate()`'s return type, `ArchiveFormat` trait signatures, low-level `creation::*` function signatures) for anyone implementing `ArchiveFormat` externally or calling `TarArchive`/`ZipArchive`/`SevenZArchive`/`creation::tar::*`/`creation::zip::*` directly; documented as BREAKING in `CHANGELOG.md` under the project's pre-1.0 no-backward-compatibility policy |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `Unvalidated` | Zero-sized phantom marker type; the default state | Re-exported at crate root |
| `Validated` | Zero-sized phantom marker type; produced only by a successful `validate()` | Re-exported at crate root |
| `SecurityConfig<State = Unvalidated>` | Security policy, now generic over validation state | `with_*` builders only on `Unvalidated`; `validate(self) -> Result<SecurityConfig<Validated>>` |
| `SecurityConfigFields` | Private struct sealing `SecurityConfig`'s actual fields | Reached via `Deref` (both states) / `DerefMut` (`Unvalidated` only) |
| `CreationConfig<State = Unvalidated>` | Archive-creation configuration, now generic over validation state (mirrors `SecurityConfig`) | `with_*` builders only on `Unvalidated`; `validate(self) -> Result<CreationConfig<Validated>>` |
| `CreationConfigFields` | `#[non_exhaustive]` private struct sealing `CreationConfig`'s actual fields | Reached via `Deref` (both states) / `DerefMut` (`Unvalidated` only) |
| `ValidatedEntry` | Sealed as part of this hardening pass | Private fields, `pub(crate)` constructor, `safe_path()`/`entry_type()`/`mode()`/`into_parts()` accessors |
| `ValidatedEntryType` | `#[non_exhaustive]` since this hardening; `Symlink`/`Hardlink` variants wrap the already-sealed `SafeSymlink`/`SafePath` | Payloads unforgeable even from inside the crate |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| A `SecurityConfig<Unvalidated>` is passed directly to `TarArchive::extract`/`list`/`verify` | Does not compile — those methods require `&SecurityConfig<Validated>` |
| `SecurityConfig::default().validate()` succeeds | Returns `Ok(SecurityConfig<Validated>)`, consuming the `Unvalidated` value |
| `SecurityConfig::default().validate()` fails (e.g. `max_file_size == 0`) | Returns `Err(ArchiveError::InvalidConfiguration)`; no `SecurityConfig<Validated>` is produced |
| Attempting to call a `with_*` builder on a `SecurityConfig<Validated>` | Does not compile — builders exist only on `SecurityConfig<Unvalidated>` |
| Attempting to mutate a field of `SecurityConfig<Validated>` directly (e.g. `cfg.max_file_size = 0`) | Does not compile — `DerefMut` is implemented only for `Unvalidated` |
| Reading a field of `SecurityConfig<Validated>` (e.g. `cfg.max_file_size`) | Works unchanged via `Deref`, for every existing caller |
| A hand-built `CreationConfig` with `compression_level: Some(200)` passed to `creation::tar::*` directly | Does not compile — those functions require `&CreationConfig<Validated>`, obtainable only through a successful `validate()` which rejects out-of-range levels |
| `exarch-cli`, `exarch-python`, `exarch-node` calling `extract_archive`/`create_archive` | Compiles and behaves unchanged — top-level functions still accept a plain, unvalidated config and validate internally |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Extraction/listing/verification reachable with an unvalidated `SecurityConfig` | Impossible — compile error for any code path bypassing the top-level functions |
| SC-002 | Panic-based DoS via forged `compression_level` (the concrete #443 finding) | Impossible — cannot reach `flate2`/`xz2` without a `CreationConfig<Validated>` |
| SC-003 | Zero behavior change for existing top-level-API callers | `exarch-cli`, `exarch-python`, `exarch-node` compile and pass their existing test suites unchanged (only `exarch-cli`'s `create` command's struct-literal `CreationConfig` construction needed updating) |
| SC-004 | Zero runtime overhead vs. pre-v0.6.0 | Confirmed — phantom types have no runtime representation |

## 8. Agent Boundaries

### Always (without asking)
- Use `SecurityConfig::default()`/`CreationConfig::default()` plus `with_*` builders as the starting point for any new config construction — never assemble `SecurityConfigFields`/`CreationConfigFields` directly
- Call `.validate()` before passing a config to any function that requires the `Validated` typestate

### Ask First
- Adding a new field to `SecurityConfigFields`/`CreationConfigFields` (must consider whether it needs its own validation rule)
- Adding a function that requires `&SecurityConfig<Validated>`/`&CreationConfig<Validated>` as a new public API surface

### Never
- Add a way to construct `Validated` without going through a successful `validate()` call
- Implement `DerefMut` for `T<Validated>` — this would defeat the "cannot be mutated back into an invalid state" guarantee
- Change the top-level `extract_archive*`/`list_archive`/`verify_archive`/`create_archive*` signatures to require the `Validated` typestate — they are deliberately generic over state, defaulting to `Unvalidated`, to keep the public API ergonomic

## 9. Open Questions

None — this is a retrospective spec documenting shipped, merged behavior (#433–#437, #443).

## 10. See Also

- [[constitution]] — project principles (Architecture: typestate hardening)
- [[MOC-specs]] — all specifications
- [[001-security-pipeline/spec]] — `EntryValidator`, `ValidatedEntry` sealing as part of this same hardening pass
- [[003-config-api/spec]] — `SecurityConfig`/`CreationConfig` field-level documentation
- [[013-quota-permit-capability-token/spec]] — the related, independent `QuotaPermit` capability-token hardening
- `crates/exarch-core/src/config.rs` — `SecurityConfig<State>`, `Unvalidated`, `Validated`
- `crates/exarch-core/src/creation/config.rs` — `CreationConfig<State>`
- Issues #433, #434, #435 (`SecurityConfig` typestate), #443 (`CreationConfig` typestate)
