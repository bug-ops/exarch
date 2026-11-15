---
aliases:
  - ZIP Parallel Compression Plan
tags:
  - sdd
  - plan
  - zip
  - performance
created: 2026-11-15
status: implemented
related:
  - "[[spec]]"
  - "[[constitution]]"
---

# Technical Plan: ZIP Parallel Compression

> [!info] References
> **Spec**: [[spec]]. Issue #1027.

## 1. Architecture

### Approach

The main thread walks the tree, opens and verifies each source in walk order, and takes the `fstat` size from the handle. Files at most `PREPARED_ENTRY_LIMIT` (8 MiB) become prepared entries; larger files stream. Under `Threads(n)` the open files go to scoped workers over a bounded `sync_channel`, and a reorder buffer hands finished entries back in archive order for the main thread to write. Quota, count, progress, cancellation and the first error stay on the main thread.

### Key Design Decisions

| Decision | Choice | Rationale | Alternatives Considered |
|----------|--------|-----------|-------------------------|
| Byte identity | Both modes use the prepared path up to 8 MiB | Output depends on (tree, config) only | Identity across n of at least 1 only (fallback) |
| Pool | `std::thread::scope` + `sync_channel` | No dependency, no global pool | Rayon |
| Workers | `min(n, available_parallelism())`, at most 2 times workers in flight | Bounded memory and clamp | Unbounded |
| Source read | Existing exact-length reader on both routes | `SourceChanged` in both modes | `PreparedZipFile::from_path` (re-opens by path) |

## 2. Project Structure

```
crates/exarch-core/src/creation/**      # Parallelism, scheduler, prepared-entry module
crates/exarch-core/benches/creation.rs
crates/exarch-cli/src/commands/create.rs
crates/exarch-cli/tests/create_threads.rs
```

## 3. Data Model

```rust
#[non_exhaustive]
pub enum Parallelism { Sequential, Threads(NonZeroUsize) }
```

## 4. API Design

`CreationConfig::with_parallelism(Parallelism)`; CLI `create --threads <N>` (non-zero `u16`).

## 5. Integration Points

| System | Direction | Protocol | Notes |
|--------|-----------|----------|-------|
| `zip` 9.4 | outbound | `ZipFileBuilder`, `PreparedZipFile`, `add_prepared_file` | stable API, version not pinned exactly |
| Spec 021 staging | inbound | staged file, fsync, rename | unchanged |

## 6. Security

All validation runs before dispatch; workers read only handles opened by the main thread.

## 7. Testing Strategy

| Level | Framework | What to Test | Coverage Target |
|-------|-----------|-------------|-----------------|
| Integration | nextest | byte equality across `Sequential`, 1, 2, 4, 8; quota, count, cancel, earliest-error, growing source | SC-001, SC-004 |
| CLI | nextest | `create --threads` | FR-011 |
| Bench | criterion | `Sequential` at most 10% slower; `Threads(4)` at least 2.5 times | SC-002, SC-003 |

## 8. Performance Considerations

Gates in the spec; measured on an idle host against the B0 baseline.

## 9. Rollout Plan

Opt-in; CHANGELOG breaking note for the changed sequential bytes; skill update.

## 10. Constitution Compliance

| Principle | Status | Notes |
|-----------|--------|-------|
| Type safety | Compliant | enum with `NonZeroUsize` |
| Simplicity | Compliant | no new dependency |

## 11. Risks and Mitigations

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Sequential gate fails | med | low | fallback design returns to the user |
| Scheduling leaks into output | high | low | byte-equality tests across n |

## 12. Contracts

| Item | Preconditions | Postconditions | Undefined behaviour |
|------|---------------|----------------|---------------------|
| `with_parallelism(Threads(n))` | ZIP output, not wasip1, not a binding | bytes equal `Sequential`; at most `min(n, available_parallelism())` threads; a growing source gives `SourceChanged` in both modes; earliest failing entry is returned | none |
| `create --threads N` | `N` non-zero `u16` | maps to `Threads(N)`; absent is `Sequential` | `0` is a usage error |

## See Also

- [[spec]]
- [[MOC-specs]]
