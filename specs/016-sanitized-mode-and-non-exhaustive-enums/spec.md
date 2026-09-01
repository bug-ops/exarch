---
aliases:
  - SanitizedMode
  - Non-Exhaustive Enum Hardening
tags:
  - sdd
  - spec
  - security
  - rust
  - typestate
created: 2026-09-02
status: implemented
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[001-security-pipeline/spec]]"
  - "[[013-quota-permit-capability-token/spec]]"
  - "[[014-config-typestate-validation/spec]]"
  - "[[005-cli/spec]]"
---

# Feature: SanitizedMode Newtype and Non-Exhaustive Enum Hardening

> [!info] Metadata
> **Subsystem**: exarch-core / security (`security::permissions`), plus six growth-prone public
> enums across `exarch-core`, `exarch-cli`, `exarch-python`, `exarch-node`
> **MSRV**: Rust 1.98.0
> **Origin**: #549, #551 (#554, unreleased, post-v0.6.0)
> **Status**: implemented — this spec documents shipped behavior, extracted as its own unit
> because it introduces a reusable pattern (sealed-newtype for a sanitized value, plus
> `#[non_exhaustive]` for forward-compatible enum growth) consistent with
> [[013-quota-permit-capability-token/spec]] and [[014-config-typestate-validation/spec]]

## 1. Overview

### Problem Statement

Before this change, `security::sanitize_permissions` returned a plain `u32`: the guarantee that
the returned value had its setuid/setgid/world-writable bits already stripped existed only as a
doc comment on the function, not as anything the type system could enforce. A caller —
`formats::common::create_file_with_mode`, `extract_file_with_permit`, or a future write path —
could be handed a raw, unsanitized `u32` mode read directly from an archive header and would
compile identically to being handed a properly sanitized one, since both are the same primitive
type. This is the same class of gap `QuotaPermit` (see [[013-quota-permit-capability-token/spec]])
closed for quota charges: a security-relevant invariant enforced only by convention rather than by
construction.

Separately, six public enums (`ArchiveError`, `QuotaResource`, `formats::detect::ArchiveType`,
`formats::compression::CompressionCodec`, `inspection::report::IssueCategory`, and
`types::entry_type::EntryType`) were exhaustive. Before v1.0.0, adding a variant to any of them —
a new error case, a new quota dimension, a new archive format, a new compression codec, a new
verification issue category, or a new archive entry kind — would be a semver-breaking change for
any downstream crate that matched on them exhaustively, which is exactly the kind of change this
project expects to make routinely pre-1.0.0.

### Goal

Make an unsanitized mode reaching permission-setting code a compile error, via a sealed
`SanitizedMode` newtype constructible only by `sanitize_permissions`. Mark the six growth-prone
enums `#[non_exhaustive]` so that adding a variant to any of them stops being a breaking change for
downstream exhaustive matches, consistent with `ValidatedEntryType`'s existing
`#[non_exhaustive]` attribute.

### Out of Scope

- `QuotaPermit`, a related but independent capability-token pattern for quota charges — see
  [[013-quota-permit-capability-token/spec]]
- `SecurityConfig`/`CreationConfig` validation typestate — a related but independent
  compile-time hardening — see [[014-config-typestate-validation/spec]]
- `creation::walker::EntryType`, which is `pub(crate)`-only and therefore never nameable outside
  `exarch-core`; `#[non_exhaustive]` would have no observable effect on it and was deliberately
  left unmarked
- Adding new variants to any of the six enums — this spec only covers making future additions
  non-breaking, not any specific new variant

## 2. User Stories

### US-001: Compiler-Enforced Sanitized Mode

AS A maintainer of `exarch-core`'s permission-handling code
I WANT the compiler to refuse a raw, unsanitized `u32` mode at any call site expecting a
sanitized value
SO THAT an unsanitized mode read from an archive header cannot reach permission-setting code by
mistake, the same way `SafePath`/`QuotaPermit` already prevent their respective raw values from
bypassing validation

**Acceptance criteria:**
```
GIVEN formats::common::create_file_with_mode or extract_file_with_permit
WHEN called with a plain u32 in place of a SanitizedMode
THEN the code does not compile — both functions require Option<SanitizedMode>, and
     SanitizedMode has no public constructor outside sanitize_permissions
```

### US-002: Forward-Compatible Enum Growth

AS A maintainer adding a new error case, quota dimension, archive format, compression codec,
verification issue category, or archive entry kind before v1.0.0
I WANT adding a new variant to `ArchiveError`, `QuotaResource`, `ArchiveType`,
`CompressionCodec`, `IssueCategory`, or `EntryType` to not be a breaking change for any
downstream crate exhaustively matching on it
SO THAT this project's pre-1.0.0 policy of shipping breaking changes without deprecation
windows (per the project's code-quality conventions) does not also force every downstream
consumer's exhaustive `match` to be rewritten on every new variant, when the crate's own binding
layers (`exarch-cli`, `exarch-python`, `exarch-node`) already need a wildcard arm regardless

**Acceptance criteria:**
```
GIVEN a downstream crate matching exhaustively on one of the six enums
WHEN a new variant is added to that enum in a future release
THEN the downstream crate's build breaks with "non-exhaustive patterns" only if it lacks a
     wildcard arm — adding the variant itself is not a semver-major change under the
     non_exhaustive contract
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | `security::sanitize_permissions` SHALL return `SanitizedMode` instead of `u32`; `SanitizedMode` SHALL have no public constructor, no `Default` impl, and its single field SHALL be private, so it is assemblable only via `sanitize_permissions` | must |
| FR-002 | `SanitizedMode` SHALL expose `as_u32(self) -> u32` as the sole accessor for recovering the raw mode value | must |
| FR-003 | `ValidatedEntry::mode()`, `EntryValidator::validate_entry()`'s sanitized output, and `formats::common::create_file_with_mode`/`extract_file_with_permit` SHALL take `Option<SanitizedMode>` instead of `Option<u32>` | must |
| FR-004 | `ArchiveError`, `QuotaResource`, `formats::detect::ArchiveType`, `formats::compression::CompressionCodec`, `inspection::report::IssueCategory`, and `types::entry_type::EntryType` SHALL be marked `#[non_exhaustive]` | must |
| FR-005 | `creation::walker::EntryType` (`pub(crate)`-only) SHALL NOT be marked `#[non_exhaustive]`, since the attribute has no effect on a type never nameable outside the crate | must |
| FR-006 | Every internal exhaustive `match` inside `exarch-core` on one of the six newly-`#[non_exhaustive]` enums SHALL continue to compile unchanged — `#[non_exhaustive]` only restricts matching *from outside the defining crate* | must |
| FR-007 | `exarch-cli`'s `error::convert_extraction_error` and `output::json::extraction_error_kind`, and `exarch-node`'s and `exarch-python`'s `convert_error` functions, SHALL add a wildcard arm (`_ =>`) to every `match` on `ArchiveError`/`QuotaResource` that previously matched exhaustively, mapping an unrecognized future variant to a generic fallback message rather than failing to compile | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | `SanitizedMode` is a single-field newtype around `u32`; wrapping costs nothing over the raw `u32` it replaces — no runtime overhead |
| NFR-002 | Safety | No `unsafe` code is required or used — the invariant relies entirely on field privacy and the absence of a public constructor, matching `SafePath`/`QuotaPermit` |
| NFR-003 | API stability | `sanitize_permissions`'s return type change and the six `#[non_exhaustive]` attributes are `pub` API surface changes; documented as changes in `CHANGELOG.md` under the project's pre-1.0.0 no-backward-compatibility policy. `#[non_exhaustive]` itself is additive from the perspective of the defining crate (existing internal matches are unaffected) but requires every downstream exhaustive match to add a wildcard arm |
| NFR-004 | Compatibility | `exarch-cli`, `exarch-python`, and `exarch-node` — the three downstream consumers in this workspace — were updated in the same change to add the required wildcard arms, so this workspace's own build is unaffected by the `#[non_exhaustive]` additions |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `SanitizedMode` | Newtype wrapping a Unix permission mode that has already passed through `sanitize_permissions`; sole producer is `sanitize_permissions` | Single private `u32` field; not constructible via tuple-struct syntax outside `exarch-core` (verified by a `trybuild` UI test); `as_u32(self) -> u32` accessor |
| `ArchiveError` | Top-level error enum for extraction/creation/listing/verification failures | Now `#[non_exhaustive]` |
| `QuotaResource` | Enum identifying which quota dimension was exceeded (`FileCount`, `FileSizeBytes`, `TotalSizeBytes`, `IntegerOverflow`) | Now `#[non_exhaustive]` |
| `formats::detect::ArchiveType` | Enum of supported archive formats | Now `#[non_exhaustive]` |
| `formats::compression::CompressionCodec` | Enum of supported compression codecs | Now `#[non_exhaustive]` |
| `inspection::report::IssueCategory` | Enum of verification issue categories | Now `#[non_exhaustive]` |
| `types::entry_type::EntryType` | Public enum of archive entry kinds (distinct from `pub(crate)` `creation::walker::EntryType`, which is unaffected) | Now `#[non_exhaustive]` |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| External code attempts `SanitizedMode(0o644)` via tuple-struct call syntax | Does not compile — `SanitizedMode`'s field is private; a `trybuild` UI test (`tests/ui/sanitized_mode_forge_via_tuple_struct.rs`) pins the exact `E0423` diagnostic |
| `create_file_with_mode`/`extract_file_with_permit` called with a raw `u32` in place of `Option<SanitizedMode>` | Does not compile — both functions require `Option<SanitizedMode>` |
| `exarch-cli`'s `error::convert_extraction_error` or `output::json::extraction_error_kind` matching on `ArchiveError` against a future variant added after this match was written | Falls through to a generic fallback arm (`"Error while processing '{archive}'"` / `"Error"`) instead of failing to compile |
| `exarch-node`'s or `exarch-python`'s `convert_error` matching on `ArchiveError`/`QuotaResource` against a future variant | Falls through to a generic fallback (`"UNKNOWN: unrecognized archive error"` / `ArchiveError::new_err("unrecognized archive error")`, and the quota-specific `"QUOTA_EXCEEDED: quota exceeded"` / `"quota exceeded"` fallbacks) instead of failing to compile |
| A hand-written match inside `exarch-core` itself on one of the six enums, written before this change | Continues to compile unchanged — `#[non_exhaustive]` only restricts matching from *outside* the defining crate |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | An unsanitized `u32` mode reaching `create_file_with_mode`/`extract_file_with_permit` | Impossible — compile error, verified by existing call sites requiring `Option<SanitizedMode>` |
| SC-002 | Forging a `SanitizedMode` outside `exarch-core` | Impossible — pinned by the `trybuild` UI test's exact diagnostic |
| SC-003 | Adding a new variant to any of the six `#[non_exhaustive]` enums | No longer a semver-major change for downstream crates with a wildcard arm |
| SC-004 | `exarch-cli`, `exarch-python`, `exarch-node` builds | Unaffected by the `#[non_exhaustive]` additions — all three updated with wildcard arms in the same change |

## 8. Agent Boundaries

### Always (without asking)
- Obtain a `SanitizedMode` only via `security::sanitize_permissions` — never construct one directly, even from inside `exarch-core`
- Add a wildcard (`_ =>`) arm when matching on `ArchiveError`, `QuotaResource`, `ArchiveType`, `CompressionCodec`, `IssueCategory`, or `EntryType` from any crate other than `exarch-core`

### Ask First
- Adding `#[non_exhaustive]` to a new public enum not covered by this spec — confirm it is actually expected to grow variants before v1.0.0, since the attribute forces every downstream matcher (including this workspace's own bindings) to carry a wildcard arm

### Never
- Add a public constructor to `SanitizedMode` outside `sanitize_permissions`
- Remove `#[non_exhaustive]` from any of the six enums without a corresponding decision that the enum is now considered closed
- Mark `creation::walker::EntryType` (`pub(crate)`-only) as `#[non_exhaustive]` — it has no external consumers, so the attribute would be a no-op

## 9. Open Questions

None — this is a retrospective spec documenting shipped, merged behavior (#549, #551, shipped in #554).

## 10. See Also

- [[constitution]] — project principles (Architecture: typed validation pipeline, type-safety review requirement)
- [[MOC-specs]] — all specifications
- [[001-security-pipeline/spec]] — the broader security pipeline `SanitizedMode` is part of
- [[013-quota-permit-capability-token/spec]] — the related, independent `QuotaPermit` capability-token pattern this newtype follows
- [[014-config-typestate-validation/spec]] — the related, independent `SecurityConfig`/`CreationConfig` typestate hardening
- [[005-cli/spec]] — `exarch-cli`'s wildcard-arm updates for the newly-`#[non_exhaustive]` `ArchiveError`/`QuotaResource`
- `crates/exarch-core/src/security/permissions.rs` — `SanitizedMode`, `sanitize_permissions`
- `crates/exarch-core/tests/ui/sanitized_mode_forge_via_tuple_struct.rs` — `trybuild` UI test pinning the forgery diagnostic
- Issues #549 (`SanitizedMode`), #551 (`#[non_exhaustive]` enums)
