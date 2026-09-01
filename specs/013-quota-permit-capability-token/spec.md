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
status: implemented
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[001-security-pipeline/spec]]"
  - "[[002-format-handlers/spec]]"
  - "[[014-config-typestate-validation/spec]]"
---

# Feature: Quota Permit Capability Token

> [!info] Metadata
> **Subsystem**: exarch-core / security (`security::quota`, `security::validator`)
> **MSRV**: Rust 1.98.0
> **Origin**: #436, #439, #440, #447 (v0.6.0, unreleased)
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
`ValidatedEntryType::File` is to already hold proof that its size was charged against the
tracker.

### Out of Scope

- The quota *limits* themselves (`max_file_size`, `max_total_size`, `max_file_count`) — see
  [[001-security-pipeline/spec]]
- `SecurityConfig`/`CreationConfig` validation typestate — a related but independent
  compile-time hardening, see [[014-config-typestate-validation/spec]]
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
WHEN it attempts to construct ValidatedEntryType::File without first obtaining a
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
WHEN EntryValidator::validate_entry_path is called first (path validation only)
THEN the caller can inspect the destination, then call reserve_file/reserve_hardlink
     separately once it has decided the entry is not a duplicate — quota is never
     charged for a skipped entry
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | `QuotaTracker::reserve` (renamed from `record_file`) SHALL be the sole public producer of `QuotaPermit`; the type SHALL have no public constructor, `Default` impl, `Clone`, or `Copy` | must |
| FR-002 | `ValidatedEntryType::File` SHALL embed a `QuotaPermit` as its payload, so a `File`-typed validated entry with no quota charge is unrepresentable | must |
| FR-003 | `EntryValidator::reserve_hardlink` (renamed from `record_hardlink`) SHALL return a standalone `QuotaPermit` for hardlink targets, whose size is only known in a second extraction pass, decoupled from the entry's own path validation | must |
| FR-004 | `EntryValidator::validate_entry_path` SHALL split path validation out of `validate_entry`, so callers that must inspect the destination before deciding whether to reserve quota (7z's duplicate-skip check) are not forced to reserve quota just to obtain the validated path | must |
| FR-005 | `EntryValidator::reserve_file` (`pub(crate)`) SHALL mirror `reserve_hardlink`'s decoupling for the 7z duplicate-skip case: quota is reserved only *after* the destination is inspected and the entry is confirmed not to be a skipped duplicate | must |
| FR-006 | EVERY format's file-write path (TAR, ZIP, 7z) SHALL consume its `QuotaPermit` by value at the point of writing, not merely hold a shared reference to it | must |
| FR-007 | `ValidatedEntry::into_parts()` SHALL be the consuming accessor that yields an owned `ValidatedEntryType` (and therefore an owned `QuotaPermit` for `File` entries), since `QuotaPermit` is neither `Clone` nor `Copy` and the existing `entry_type()` accessor only lends a shared reference | must |
| FR-008 | WHERE a format's dispatch is a single exhaustive `match` on `ValidatedEntryType` (TAR), THE SYSTEM SHALL rely on that exhaustiveness as the sole enforcement that only the `File` arm can bind a permit; WHERE dispatch is not a single exhaustive match (ZIP), THE SYSTEM SHALL additionally carry a runtime fail-closed guard (`let ValidatedEntryType::File(permit) = entry_type else { return Err(..) }`) | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | `QuotaPermit` is zero-sized (`PhantomData`-based); wrapping it in `Result` costs nothing over `Result<()>` — no runtime overhead vs. the pre-v0.6.0 `Result<()>`-returning `record_file` |
| NFR-002 | Safety | No `unsafe` code is required or used to implement the capability-token pattern — it relies entirely on visibility (`pub(crate)` fields) and the absence of `Clone`/`Copy`/`Default` impls |
| NFR-003 | Reliability | The pattern closes the *same class* of gap #428 demonstrated (an unguarded quota-charge path), at the type level, for every current and future write path — not just the one instance that was reported |
| NFR-004 | API stability | This is a `pub` API surface change (`QuotaTracker::record_file` → `reserve`, `EntryValidator::record_hardlink` → `reserve_hardlink`); documented as BREAKING in `CHANGELOG.md` under the project's pre-1.0 no-backward-compatibility policy |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `QuotaPermit` | Capability token proving a file's size was reserved against a `QuotaTracker` | `PhantomData<()>`-based (zero-sized); not `Clone`, not `Copy`, no `Default`; sole producer is `QuotaTracker::reserve` |
| `QuotaTracker::reserve` | Renamed from `record_file`; charges a file's size against `max_file_size`/`max_total_size`/`max_file_count` and, on success, returns a `QuotaPermit` | `fn reserve(&mut self, size: u64) -> Result<QuotaPermit>` |
| `EntryValidator::reserve_hardlink` | Renamed from `record_hardlink`; standalone permit issuance for hardlink targets (size known only in TAR's second pass) | `pub(crate) fn reserve_hardlink(&mut self, size: u64) -> Result<QuotaPermit>` |
| `EntryValidator::reserve_file` | New `pub(crate)` method mirroring `reserve_hardlink`'s decoupling, for 7z's post-duplicate-check reservation | `pub(crate) fn reserve_file(&mut self, size: u64) -> Result<QuotaPermit>` |
| `EntryValidator::validate_entry_path` | New method splitting path validation out of `validate_entry`, for callers needing the destination path before committing to a quota charge | Returns the validated path/type without reserving quota |
| `ValidatedEntryType::File(QuotaPermit)` | `#[non_exhaustive]` enum variant now carrying the capability token as its payload | Constructible only by code already holding a `QuotaPermit` |
| `ValidatedEntry::into_parts()` | Consuming accessor yielding an owned `ValidatedEntryType` | Needed because `QuotaPermit` cannot be obtained through a shared reference |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| A hand-written format handler tries to construct `ValidatedEntryType::File` directly with a forged/absent permit | Does not compile — no public path to a `QuotaPermit` exists outside `QuotaTracker::reserve` |
| TAR hardlink extraction (the original #428 gap) | `EntryValidator::reserve_hardlink` charges the target's on-disk size before `copy_file_with_permit` runs; TAR's hardlink copy path consumes the permit by value, so a single reservation cannot be spent twice |
| 7z file write with `skip_duplicates` | `validate_entry_path` runs first (no charge); if the entry is not a duplicate, `reserve_file` charges quota only then — a skipped duplicate never consumes any of the file-count/byte-size allotment |
| ZIP dispatch attempting to write a non-`File` `ValidatedEntryType` | Runtime fail-closed guard rejects it, since ZIP's dispatch is not a single exhaustive match (unlike TAR) |
| A future format handler adds a new write path and forgets to reserve quota | Does not compile — cannot obtain a `File`-typed `ValidatedEntry` without going through `EntryValidator::validate_entry()` (the only assembler of `ValidatedEntry`, which is otherwise sealed) |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | #428-class bugs (unguarded quota charge) | Impossible to reintroduce without a compile error, for any current or future write path |
| SC-002 | Zero runtime overhead vs. pre-v0.6.0 `Result<()>` | Confirmed by `QuotaPermit`'s zero-sized `PhantomData` representation |
| SC-003 | All three format handlers (TAR, ZIP, 7z) consume `QuotaPermit` by value at their write sites | Verified by code review + existing extraction test suite (no quota arithmetic changed) |
| SC-004 | No double-spend of a single reservation | Enforced by move semantics (`QuotaPermit` not `Clone`/`Copy`); no explicit test needed beyond normal compilation |

## 8. Agent Boundaries

### Always (without asking)
- Route every file-typed validated entry through `EntryValidator::validate_entry()` (or the decoupled `validate_entry_path` + `reserve_file`/`reserve_hardlink` pair) — never construct `ValidatedEntryType::File` any other way
- Consume `QuotaPermit` by value at the point of writing; never attempt to clone, copy, or hold a shared reference across a write

### Ask First
- Adding a new `QuotaPermit`-decoupled reservation path (mirroring `reserve_hardlink`/`reserve_file`) for a future format handler with a similar two-pass requirement

### Never
- Add `Clone`, `Copy`, or `Default` to `QuotaPermit` — this would defeat the single-spend guarantee
- Add a public constructor to `QuotaPermit` outside `QuotaTracker::reserve`
- Bypass `EntryValidator` to construct a `ValidatedEntry`/`ValidatedEntryType` directly from outside `exarch-core`

## 9. Open Questions

None — this is a retrospective spec documenting shipped, merged behavior (#436, #439, #440, #447).

## 10. See Also

- [[constitution]] — project principles (Architecture: typed validation pipeline)
- [[MOC-specs]] — all specifications
- [[001-security-pipeline/spec]] — `EntryValidator`, `QuotaTracker`, `ValidatedEntry` in the broader security pipeline
- [[002-format-handlers/spec]] — format handlers that consume `QuotaPermit` at their write sites
- [[014-config-typestate-validation/spec]] — the related, independent `SecurityConfig`/`CreationConfig` typestate hardening
- `crates/exarch-core/src/security/quota.rs` — `QuotaPermit`, `QuotaTracker::reserve`
- `crates/exarch-core/src/security/validator.rs` — `EntryValidator::reserve_hardlink`, `reserve_file`, `validate_entry_path`, `ValidatedEntry::into_parts()`
- Issue #428 — the original gap this pattern closes at the type level
