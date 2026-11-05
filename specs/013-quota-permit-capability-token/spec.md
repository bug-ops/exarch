---
aliases:
  - Quota Permit Capability Token
  - QuotaPermit Spec
tags:
  - sdd
  - spec
  - security
  - rust
  - typestate
created: 2026-08-04
updated: 2026-11-05
status: implemented
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[001-security-pipeline/spec]]"
  - "[[002-format-handlers/spec]]"
  - "[[014-config-typestate-validation/spec]]"
---

# Feature: Quota Permit Capability Token

> [!note] Revision 2026-11-04 (50-issue batch, shipped in 0.9.0)
> `EntryValidator`, `ValidatedEntry` and `ValidatedEntryType` were removed (#900); the permit is carried only by `ValidatedFile` (and `ValidatedHardlink`) from `ValidatorCore`, and `EntrySink::create_file*` takes the permit's bytes as `AdmittedSize` (#909). `QuotaTracker::reserve` takes `&SecurityConfig` (the typestate is gone, #898). Rows below are rewritten accordingly; version notes still name the release they describe.

> [!info] Metadata
> **Subsystem**: exarch-core / security (`security::quota`, `security::validator`)
> **MSRV**: Rust 1.99.1
> **Origin**: #436, #439, #440, #447 (v0.6.0); `EntryCount` and link counting (#719, #724, v0.7.0)
> **Status**: implemented — this spec documents shipped behavior, extracted from
> [[001-security-pipeline/spec]] and [[002-format-handlers/spec]] because it introduces
> a reusable pattern (capability tokens for compile-time-proven resource charges) worth
> tracking as its own unit

## 1. Overview

### Problem Statement

Before v0.6.0, quota enforcement for file extraction was a *convention*: every format
handler was expected to call `QuotaTracker::record_file` before writing a file's bytes to
disk, but nothing in the type system forced this. Issue #428 found exactly this gap —
TAR hardlink extraction copied a target's full on-disk bytes via `std::fs::copy` without
ever charging `QuotaTracker`, so a crafted archive with one in-quota file followed by many
hardlink entries pointing at it extracted unlimited copies with zero enforcement. A
runtime-only guard (a `debug_assert!`, a code-review checklist item, an integration test)
can catch a *known* instance of this class but cannot prevent a *new* one: any future
write path — a new format handler, a new code path inside an existing one — could
reintroduce the same bug by simply forgetting to call `record_file` first.

### Goal

Make an unguarded quota-charge path a compile error, not a runtime bug waiting to be
found. A file-typed validated archive entry with no quota reservation becomes
unrepresentable in the type system: the only way to construct
a `ValidatedFile` is to already hold proof that its size was charged against the
tracker.

### Out of Scope

- The quota *limits* themselves (`max_file_size`, `max_total_size`, `max_file_count`) — see
  [[001-security-pipeline/spec]]
- The former `SecurityConfig`/`CreationConfig` validation typestate (removed in #898; see the obsolete [[014-config-typestate-validation/spec]])
- Making `QuotaTracker` itself thread-safe or shareable across concurrent extraction
  (extraction is single-threaded per archive today)

## 2. User Stories

### US-001: Compiler-Enforced Quota Charge

AS A maintainer adding a new archive-entry write path
I WANT the compiler to refuse to compile a `File`-typed validated entry that was never
charged against `QuotaTracker`
SO THAT I cannot reintroduce the #428 class of bug (an unguarded quota-charge path) even
by accident, and code review does not need to manually verify every new write site calls
`reserve()` first

**Acceptance criteria:**
```
GIVEN a new format handler's file-write function
WHEN it attempts to construct a ValidatedFile without first obtaining a
     QuotaPermit from QuotaTracker::reserve
THEN the code does not compile — QuotaPermit has no public constructor and no
     Default impl
```

### US-002: Single-Spend Guarantee

AS A security reviewer
I WANT a single quota reservation to be spendable exactly once
SO THAT a write path cannot accidentally charge quota, then reuse the same charge for a
second write (e.g. a retry path or a copy-then-hardlink sequence)

**Acceptance criteria:**
```
GIVEN a QuotaPermit obtained from QuotaTracker::reserve
WHEN it is consumed by value at one write site
THEN it cannot be referenced again — QuotaPermit is not Clone, not Copy; the compiler
     enforces move semantics
```

### US-003: Decoupled Reservation for Two-Pass Formats

AS A format-handler author (7z, TAR hardlinks)
I WANT to obtain path validation and quota reservation as separate steps
SO THAT I can inspect the destination (e.g. to decide whether an entry is a
pre-existing duplicate) before committing to a quota charge, without either skipping
quota tracking entirely or charging quota for entries that turn out to be skipped

**Acceptance criteria:**
```
GIVEN 7z's skip_duplicates check, which must inspect the destination path before
      deciding whether to extract an entry
WHEN the 7z host target validates the path first (ValidatorCore::validate_entry_path_in, path only)
THEN it can inspect the destination, then reserve quota (ValidatorCore::reserve_file)
     once it has decided the entry is not a duplicate — quota is never charged for a
     skipped entry (v0.8.0: these are methods of ValidatorCore; the
     public EntryValidator::validate_entry_path and reserve_file were removed, #808, and EntryValidator itself in #900)
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | `QuotaTracker::reserve` (renamed from `record_file`) SHALL be the sole public producer of `QuotaPermit` (the crate-private `QuotaTracker::charge` is the only other); the type SHALL have no public constructor, `Default` impl, `Clone`, or `Copy` | must |
| FR-002 | `ValidatedFile` SHALL embed a `QuotaPermit`, so a validated file proof with no quota charge is unrepresentable (`ValidatedEntryType::File` was this requirement until #900 removed the enum) | must |
| FR-003 | `ValidatorCore::charge_hardlink` (renamed from `record_hardlink`, then `reserve_hardlink`, in v0.7.0; a method of `EntryValidator` until #900) SHALL return a standalone `QuotaPermit` for hardlink targets, whose size is only known in a second extraction pass, decoupled from the entry's own path validation; it SHALL take the `EntryCount` the first pass obtained, so the entry is charged bytes without being counted twice | must |
| FR-004 | `ValidatorCore::validate_entry_path_in` (takes a `NodeKind` and returns an `EntryPath<SafePath>`; `EntryValidator::validate_entry_path` until v0.7.0, removed in #808) SHALL split path validation out of `validate_entry`, so callers that must inspect the destination before deciding whether to reserve quota (7z's duplicate-skip check) are not forced to reserve quota just to obtain the validated path | must |
| FR-005 | `ValidatorCore::reserve_file` (`EntryValidator::reserve_file` until v0.7.0) SHALL mirror `charge_hardlink`'s decoupling for the 7z duplicate-skip case: quota is reserved only *after* the destination is inspected and the entry is confirmed not to be a skipped duplicate | must |
| FR-006 | EVERY format's file-write path (TAR, ZIP, 7z) SHALL consume its `QuotaPermit` by value at the point of writing, not merely hold a shared reference to it | must |
| FR-007 | WHERE an extraction target needs an owned `QuotaPermit`, it SHALL obtain it from the typed `ValidatedFile` that `ValidatorCore::validate_file_in` returns (`security::admitted`, v0.8.0, #793, #808), which carries the permit by value; `ValidatedEntry::into_parts()` (v0.6.0 to v0.7.0) and `ValidatedEntry` itself (#900) were removed; `EntrySink::create_file` and `create_file_from` receive the permit's bytes as the `Copy` `AdmittedSize` (`QuotaPermit::into_admitted`, #909), so a sink cannot be handed a size that was not charged | must |
| FR-008 | Since v0.8.0 (#793, #808) the TAR, ZIP and 7z handlers SHALL NOT match on a validated-entry enum; each entry kind is admitted through its own `ExtractTarget::validate_*` method returning its own typed proof, and only `validate_file` yields a `ValidatedFile` carrying a permit, so a permit cannot be bound for another kind and the ZIP runtime fail-closed guard of v0.6.0 is no longer needed (`ValidatedEntryType` and `EntryValidator::validate_entry` were removed, #900) | must |
| FR-009 | `EntryCount` SHALL be a zero-sized, non-`Clone`/non-`Copy`, non-`Default` token whose only producer is `QuotaTracker::reserve_count`; `ValidatedHardlink` SHALL carry it as `counted`, so counting a hardlink against `max_file_count` twice, or never, is unrepresentable | must |
| FR-010 | `max_file_count` SHALL count symlinks and hardlinks as well as files in `extract`: `ValidatorCore::reserve_symlink` charges a symlink's stored size and count through `QuotaTracker::reserve` and discards the permit, since no writer consumes one for a link | must |
| FR-011 | `QuotaPermit` SHALL carry the reserved bytes as `Uncompressed`, so `ExtractTarget::file` takes no separate size and a write cannot disagree with what was charged; the ZIP and 7z extraction proof tokens SHALL be bound to their archive and the validated-file proof SHALL be built only by the validator (internal) (v0.8.0, #846, #869, #879, #888) | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | `QuotaPermit` is a single `Uncompressed` byte count (one `u64`); wrapping it in `Result` costs a word over `Result<()>` — negligible vs. the pre-v0.6.0 `Result<()>`-returning `record_file` |
| NFR-002 | Safety | No `unsafe` code is required or used to implement the capability-token pattern — it relies entirely on visibility (`pub(crate)` fields) and the absence of `Clone`/`Copy`/`Default` impls |
| NFR-003 | Reliability | The pattern closes the *same class* of gap #428 demonstrated (an unguarded quota-charge path), at the type level, for every current and future write path — not just the one instance that was reported |
| NFR-004 | API stability | This is a `pub` API surface change (`QuotaTracker::record_file` → `reserve`, `EntryValidator::record_hardlink` → `reserve_hardlink` → `charge_hardlink`, the hardlink proof gaining `counted`; the validator types were later removed by #900); documented as BREAKING in `CHANGELOG.md` under the project's pre-1.0 no-backward-compatibility policy |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `QuotaPermit` | Capability token proving a file's size was reserved against a `QuotaTracker` | carries the reserved `bytes: Uncompressed` (private; spent by crate-private `into_bytes(self)`, the write ceiling); not `Clone`, not `Copy`, no `Default`; sole producer is `QuotaTracker::reserve` |
| `QuotaTracker::reserve` | Renamed from `record_file`; charges a file's size against `max_file_size`/`max_total_size`/`max_file_count` and, on success, returns a `QuotaPermit` | `fn reserve(&mut self, size: u64, config: &SecurityConfig) -> Result<QuotaPermit>` |
| `EntryCount` | Capability token proving an entry was counted against `max_file_count` while its bytes are not yet charged (hardlinks); exported ungated at `security::EntryCount` | `PhantomData`-based; only producer is `QuotaTracker::reserve_count`; consumed by `QuotaTracker::charge` |
| `ValidatorCore::charge_hardlink` | Renamed from `reserve_hardlink` (itself renamed from `record_hardlink`); standalone permit issuance for hardlink targets (size known only in TAR's second pass), spending the `EntryCount` from the first pass | `fn charge_hardlink(&mut self, counted: EntryCount, size: u64) -> Result<QuotaPermit>` |
| `ValidatorCore::reserve_symlink` | Charges a symlink's stored size and count; the permit is discarded | `fn reserve_symlink(&mut self, size: u64) -> Result<()>` |
| `ValidatorCore::reserve_file` | Method mirroring `charge_hardlink`'s decoupling, for 7z's post-duplicate-check reservation | `fn reserve_file(&mut self, size: u64) -> Result<QuotaPermit>` |
| `ValidatorCore::validate_entry_path_in` | Method splitting path validation out of per-kind validation, for callers needing the destination path before committing to a quota charge | takes a `NodeKind`, returns `EntryPath<SafePath>` (`Root` or `Child`) without reserving quota |
| `ValidatedHardlink` | Typed proof carrying the `HardlinkTarget` and the first-pass `EntryCount` (`counted`) | The second pass spends `counted` through `charge_hardlink` |
| `ValidatedFile` | Typed proof returned by `ValidatorCore::validate_file_in` (v0.8.0): `path`, `permit`, `mode` | The way a target takes the permit by value |
| `AdmittedSize` | `Copy` view of the permit's bytes for `EntrySink::create_file*` (#909) | `get()`; built only by `QuotaPermit::into_admitted` |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| A hand-written format handler tries to construct a `ValidatedFile` directly with a forged/absent permit | Does not compile — no public path to a `QuotaPermit` exists outside `QuotaTracker::reserve` |
| TAR hardlink extraction (the original #428 gap) | `ValidatorCore::charge_hardlink` charges the target's on-disk size before `copy_file_with_permit` runs, spending the `EntryCount` taken in the first pass; TAR's hardlink copy path consumes the permit by value, so a single reservation cannot be spent twice |
| Many symlink or hardlink entries in one archive | Each counts against `max_file_count` in `extract`, so a link flood is bounded like a file flood (`QuotaExceeded { FileCount }`) |
| 7z file write with `skip_duplicates` | `validate_entry_path_in` runs first (no charge); if the entry is not a duplicate, `reserve_file` charges quota only then — a skipped duplicate never consumes any of the file-count/byte-size allotment |
| A handler attempting to write a non-file entry with a permit | Not expressible since v0.8.0: only `validate_file` returns a permit-carrying `ValidatedFile` (v0.6.0 to v0.7.0: ZIP carried a runtime fail-closed guard, TAR an exhaustive `match`) |
| A future format handler adds a new write path and forgets to reserve quota | Does not compile — a `ValidatedFile` can only be obtained from `ValidatorCore::validate_file_in`, and a sink needs the `AdmittedSize` derived from its permit (#900, #909) |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | #428-class bugs (unguarded quota charge) | Impossible to reintroduce without a compile error, for any current or future write path |
| SC-002 | Negligible runtime overhead vs. pre-v0.6.0 `Result<()>` | Confirmed by `QuotaPermit`'s single-`u64` representation |
| SC-003 | All three format handlers (TAR, ZIP, 7z) consume `QuotaPermit` by value at their write sites | Verified by code review + existing extraction test suite (no quota arithmetic changed) |
| SC-004 | No double-spend of a single reservation | Enforced by move semantics (`QuotaPermit` not `Clone`/`Copy`); no explicit test needed beyond normal compilation |

## 8. Agent Boundaries

### Always (without asking)
- Route every file-typed validated entry through `ValidatorCore::validate_file_in` (or the decoupled `validate_entry_path_in` + `reserve_file`/`charge_hardlink` pair) — never construct a `ValidatedFile` any other way
- Consume `QuotaPermit` by value at the point of writing; never attempt to clone, copy, or hold a shared reference across a write

### Ask First
- Adding a new `QuotaPermit`-decoupled reservation path (mirroring `charge_hardlink`/`reserve_file`) for a future format handler with a similar two-pass requirement

### Never
- Add `Clone`, `Copy`, or `Default` to `QuotaPermit` — this would defeat the single-spend guarantee
- Add a public constructor to `QuotaPermit` outside `QuotaTracker::reserve`
- Construct a `ValidatedFile` or an `AdmittedSize` outside the validator and the permit (both are constructible only there)

## 9. Open Questions

None — this is a retrospective spec documenting shipped, merged behavior (#436, #439, #440, #447).

## 10. See Also

- [[constitution]] — project principles (Architecture: typed validation pipeline)
- [[MOC-specs]] — all specifications
- [[001-security-pipeline/spec]] — `ValidatorCore`, `QuotaTracker`, the typed proofs in the broader security pipeline
- [[002-format-handlers/spec]] — format handlers that consume `QuotaPermit` at their write sites
- [[014-config-typestate-validation/spec]] — obsolete: the removed `SecurityConfig`/`CreationConfig` typestate
- `crates/exarch-core/src/security/quota.rs` — `QuotaPermit`, `QuotaTracker::reserve`
- `crates/exarch-core/src/security/validator.rs` — `ValidatorCore::charge_hardlink`, `reserve_file`, `validate_entry_path_in`, `security/admitted.rs` `ValidatedFile`; formerly `EntryValidator` and `ValidatedEntry::into_parts()`
- Issue #428 — the original gap this pattern closes at the type level
