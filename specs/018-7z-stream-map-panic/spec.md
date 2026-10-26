---
aliases:
  - 7z Stream Map Panic
  - Validated 7z Archive
tags:
  - sdd
  - spec
  - security
  - sevenz
  - rust
  - typestate
  - robustness
created: 2026-10-26
status: implemented
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[001-security-pipeline/spec]]"
  - "[[002-format-handlers/spec]]"
  - "[[005-cli/spec]]"
  - "[[006-python-bindings/spec]]"
  - "[[007-node-bindings/spec]]"
  - "[[011-ffi-panic-boundary-simplification/spec]]"
  - "[[016-sanitized-mode-and-non-exhaustive-enums/spec]]"
---

# Feature: 7z Stream Map Validation (panic on a header with streams but no files info)

> [!info] Metadata
> **Subsystem**: exarch-core / formats (`formats::sevenz`: `admit`, `verify`, `links`, `decode`, `mod`), inspection (`inspection::list`); mapping layers in `exarch-cli`, `exarch-python`, `exarch-node` are unchanged
> **MSRV**: Rust 1.98.0
> **Origin**: continuous-improvement finding at HEAD `c95a85b` ; issue #746, fixed by #752 (0.7.0)
> **Type / priority**: bug (panic / denial of service on untrusted input), P1
> **Dependency**: `sevenz-rust2` 0.24.1 (locked)
> **Status**: implemented in #752; the wrapper is `SevenZHeader`, obtained only from `read_sevenz_header` (`formats/sevenz/header.rs`); see the resolutions in section 9

## 1. Overview

### Problem Statement

A 7z header may declare main streams info (pack info, unpack info, one or more blocks) and then end without a FilesInfo property. `sevenz-rust2` 0.24.1 accepts such a header: `Archive::read` returns `Ok`, `archive.blocks` holds the declared blocks, `archive.files` is empty, and `archive.stream_map` stays at its `Default` value because the crate only builds the map inside `read_files_info` (`calculate_stream_map`). All three vectors that exarch indexes by block (`block_first_file_index`, `block_first_pack_stream_index`) are therefore empty while `blocks.len()` is at least 1.

`exarch-core` then indexes those vectors by block number without any bound check, so a hostile 66-byte archive aborts the process:

```
panicked at crates/exarch-core/src/formats/sevenz/admit.rs:256:58:
index out of bounds: the len is 0 but the index is 0
```

Reproduced at HEAD `c95a85b` with the upstream fuzzer vector `tests/resources/streams_without_files_info.bin` from `hasenbanck/sevenz-rust2`:

| Operation | Result at `c95a85b` |
|-----------|---------------------|
| `exarch verify in.7z` | abort, exit 101 |
| `exarch extract in.7z out/` | abort, exit 101 |
| `exarch list in.7z` | exit 0 with an empty listing (does not reach the indexing sites; a clean-looking result for a structurally invalid archive) |

Python and Node bindings convert the panic into an exception through `catch_unwind` (see [[011-ffi-panic-boundary-simplification/spec]]); the Rust API and the CLI do not.

Code reading confirms the direct-indexing sites in `crates/exarch-core/src/formats/sevenz/` at `c95a85b`:

| Site | Expression | Reached from |
|------|------------|--------------|
| `admit.rs:256` (`block_span`) | `stream_map.block_first_file_index[block]` | `block_shapes` (so `iter_sevenz_refusals`: `extract` step 0, `verify`), `mapped_block_span` and `decode_block_entries` (decode and link walks) |
| `admit.rs:124` (`sevenz_entry_compression`) | `stream_map.block_first_file_index[block]` | `SevenZArchive::new`, `list_sevenz_archive` (only for a mapped file, so unreachable when `files` is empty; shown for completeness) |
| `verify.rs:204` | `stream_map.block_first_file_index[block_index]` | integrity decode of a block (`verify --check-integrity`, `list` with an integrity pass) |
| `links.rs:305` (`walk_block_links`) | `stream_map.block_first_file_index[block]` | link-target reads |

A neighbouring family indexes `stream_map.file_block_index[index]` by file index (`admit.rs:99`, `:114`, `:277`; `verify.rs:40`; `links.rs:216`, `:280`; `decode.rs:221`) and `first_pack[block]` (`admit.rs:82`). These are safe today only because `sevenz-rust2` happens to build `file_block_index` with exactly `files.len()` entries and every `Some(block)` below `blocks.len()`; exarch relies on a dependency's internal invariant with no check and no type that states it.

Upstream fixed this class in `hasenbanck/sevenz-rust2` master (commits `b7093c37` and `df5b7a96`, 2026-10-25, fuzzer-found): a header with streams but no files info is now an `Error` at open. The fix is not in any release (latest crates.io release is 0.24.1, which is locked), so a version bump cannot close the defect today. An exarch-side guard is needed regardless as defense in depth: the invariant "the stream map covers every block" belongs to a dependency's private construction logic and exarch should not depend on it silently.

There are two independent open paths for a 7z archive, each with its own copy of the open-error mapping:

- `SevenZArchive::new` (`formats/sevenz/mod.rs:311`), used by `extract_archive` and `verify_archive`
- `list_sevenz_reader` (`inspection/list.rs:627`), used by `list_archive` and by the `ArchiveFormat::list` implementation

A check added in only one of them leaves the other unprotected.

### Goal

A 7z archive whose parsed stream map does not cover every block is rejected with one typed `ArchiveError::InvalidArchive` by `extract`, `list` and `verify` alike, and no code in `formats::sevenz` or `inspection::list` can index the stream map without a value that proves the invariant at compile time.

### Out of Scope

- Fixing or forking `sevenz-rust2`; bumping it (the fix is unreleased)
- Other 7z hardening (encoded-header memory limit #674, dropped stream file #675); separate issues
- Rewriting the 7z handler beyond what the typed wrapper requires
- Changing the CLI, Python or Node public surface (no new flags, options or types)
- Auditing every other `sevenz-rust2` panic class (this spec covers the stream-map invariant only)
- Extending the `sevenz` fuzz target to call `extract` (the `extract_archive` target already covers it; see section 9)

## 2. User Stories

### US-001: No process abort on a crafted 7z

AS A developer embedding exarch in an ingestion service
I WANT a 7z archive with streams but no files info to fail with an error
SO THAT an attacker cannot terminate my process with a 66-byte upload

**Acceptance criteria:**
```
GIVEN the 66-byte vector streams-without-files-info
WHEN extract_archive, verify_archive or list_archive runs on it
THEN each returns Err(ArchiveError::InvalidArchive(_))
  AND no panic occurs
  AND extract writes nothing to the destination
```

### US-002: Same answer from every operation

AS A security engineer using `exarch verify` and `exarch list` as admission gates
I WANT all three operations to agree about a structurally invalid 7z archive
SO THAT a clean `list` result is never followed by a crash in `extract`

**Acceptance criteria:**
```
GIVEN the same vector
WHEN the CLI runs list, verify and extract on it
THEN all three fail with the same error kind (invalid archive) and the same exit code
  AND none prints a listing or a PASS report
```

### US-003: The invariant lives in a type

AS A maintainer of `exarch-core`
I WANT the "stream map covers every block" invariant encoded in a validated wrapper obtained once after open
SO THAT a new 7z code path cannot reintroduce an unchecked index

**Acceptance criteria:**
```
GIVEN the 7z modules that index the stream map
WHEN the code is reviewed
THEN every such index goes through the validated wrapper
  AND the wrapper can only be constructed by the function that checks the invariant
  AND no module outside that function reads stream_map vectors directly
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN a 7z archive is opened for `extract`, `verify` or `list` and its parsed stream map does not cover every block THE SYSTEM SHALL return `ArchiveError::InvalidArchive` and SHALL NOT panic | must |
| FR-002 | THE SYSTEM SHALL define the stream-map invariant as: `block_first_file_index.len()` and `block_first_pack_stream_index.len()` equal `blocks.len()`, and `file_block_index.len()` equals `files.len()` | must |
| FR-003 | THE SYSTEM SHOULD also require every `Some(b)` in `file_block_index` to satisfy `b < blocks.len()` and every `block_first_file_index` entry to be at most `files.len()` (see section 9) | should |
| FR-004 | THE SYSTEM SHALL check the invariant exactly once per opened archive, in one function that returns a validated wrapper around the parsed archive, and SHALL NOT construct that wrapper anywhere else | must |
| FR-005 | THE SYSTEM SHALL route both 7z open paths (`SevenZArchive::new` and `list_sevenz_reader`) through that one function, including its mapping of `sevenz-rust2` open errors to `ArchiveError` | must |
| FR-006 | THE SYSTEM SHALL make every function in `formats::sevenz` and `inspection::list` that indexes the stream map by block or by file take the validated wrapper (or a borrow of its checked vectors) rather than a raw `sevenz_rust2::Archive`, so an unchecked archive does not type-check at those sites | must |
| FR-007 | WHEN the invariant check rejects an archive THE SYSTEM SHALL do so before any entry is listed, any destination path is created, or any block is decoded | must |
| FR-008 | WHEN a valid archive is opened (including the valid empty 7z archive that `sevenz-rust2` reports as `UnexpectedEof`, and an archive with files but no blocks) THE SYSTEM SHALL accept it exactly as before | must |
| FR-009 | THE SYSTEM SHALL keep a regression test that opens the 66-byte upstream vector through `extract_archive`, `verify_archive` and `list_archive` (and the CLI) and asserts `ArchiveError::InvalidArchive` for each | must |
| FR-010 | THE SYSTEM SHALL ship the vector as a committed fixture that the fuzz seed assembly (`fuzz/seed-corpus.sh`) places into the `sevenz` corpus (location: section 9) | must |
| FR-011 | WHEN `sevenz-rust2` releases a version that rejects this header at open THE PROJECT SHOULD re-evaluate the open-time check for that case and record the outcome (keep the wrapper, drop only the redundant branch); the check is not blocked on that release | should |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Security | A hostile archive must not be able to cause a panic through the stream map; rejection must precede any write to the destination (extends [[001-security-pipeline/spec]]) |
| NFR-002 | Type safety | The invariant is expressed by a type with a private constructor, not by `if` checks repeated at call sites and not by a documented convention (constitution: illegal states unrepresentable) |
| NFR-003 | Performance | The check is O(1) length comparisons plus, if FR-003 is adopted, one linear pass over `file_block_index` and `block_first_file_index`; no measurable change on `exarch-core/benches/extraction.rs` 7z groups (within the 10% gate) |
| NFR-004 | Safety | No `unsafe`; `deny(unwrap_used)` and `deny(expect_used)` remain satisfied |
| NFR-005 | Consistency | The error variant and the open-failure message prefix (`failed to open 7z archive:`) match the existing open-error mapping, so a later `sevenz-rust2` release that rejects this header itself produces an indistinguishable result |
| NFR-006 | Documentation | Every new `pub` or `pub(crate)` item the wrapper introduces has a `///` comment stating the invariant; docs build with `RUSTDOCFLAGS="-D warnings"` |
| NFR-007 | Changelog | `CHANGELOG.md` `[Unreleased]` gets a one-line `Fixed` entry with the PR link (added by the implementing PR, not by this spec PR) |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| Parsed 7z archive (`sevenz_rust2::Archive`) | Dependency type with public `blocks`, `files`, `stream_map`; can be inconsistent when produced by the crate from a hostile header | `blocks`, `files`, `stream_map` |
| Validated 7z archive (new, name in plan) | Newtype around the parsed archive, constructible only by the single open function; carries the proof that the stream map covers every block | the parsed archive, read-only access |
| `StreamMap` invariant | Relationship between three lengths and the index ranges they hold | see FR-002, FR-003 |

> [!note] Design as shipped
> `SevenZHeader` hands out checked accessors (`block_first_file`, `block_first_pack`, `file_block`, `block`) keyed by a `BlockIndex` that only the header mints. Nothing outside `header.rs` reads the stream map vectors, except test code (`formats/sevenz/tests.rs` mutates them on purpose; the test-only `SevenZHeader::assume_checked` wraps such an archive).

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Streams info with one block, no FilesInfo (the 66-byte vector) | `InvalidArchive` from `list`, `verify`, `extract` |
| Streams info with several blocks, no FilesInfo | same |
| Streams info with zero blocks and no FilesInfo | accepted: the map is trivially consistent (zero blocks, zero files) |
| FilesInfo present with files but no streams info (all entries empty) | accepted as before (`calculate_stream_map` runs, zero blocks) |
| Valid empty 7z archive (32 bytes) | accepted as before via the existing empty-archive path |
| `verify` of the vector | hard `InvalidArchive` error (CLI `status: "error"`, exit 1), the same shape as any 7z archive that fails to open; not a report issue, because there is no parsed structure to report on |
| `verify --check-integrity` and `list` with an integrity pass | same rejection at open; the integrity pass is never entered |
| A future `sevenz-rust2` that rejects the header itself | open fails inside `Archive::read` with the same variant; the wrapper check becomes unreachable for this case and stays as defense in depth for other inconsistencies |
| Test-only archives that mutate `stream_map` after parsing (for example `formats/sevenz/tests.rs`, which rewrites `file_block_index`) | remain constructible through a test-only path that the plan must specify; production code has none |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Panics on the upstream vector across `list`, `verify`, `extract` (Rust API and CLI) | 0; every call returns `InvalidArchive`, CLI exit 1 |
| SC-002 | Direct reads of `stream_map.block_first_file_index`, `block_first_pack_stream_index` and `file_block_index` outside the wrapper's module | 0 (checked by grep in review) |
| SC-003 | Open paths that construct a parsed 7z archive without the wrapper | 0 (one function, two callers) |
| SC-004 | Existing 7z tests and fixtures | unchanged results (`cargo nextest run -p exarch-core`) |
| SC-005 | `fuzz/seed-corpus.sh` output | contains the vector under `fuzz/seeds/sevenz/`; a short local `cargo +nightly fuzz run sevenz` over that corpus does not crash |
| SC-006 | Python and Node tests for the vector | the call raises the binding's existing invalid-archive exception type, not a panic-derived one (resolved: no binding-level test; `crates/exarch-core/tests/sevenz_stream_map.rs` covers `list`, `verify`, `verify` with integrity and `extract`, and the bindings only map `InvalidArchive`) |

## 8. Agent Boundaries

### Always (without asking)
- Run the project's pre-PR checks from `.claude/rules/branching.md` and the `rust-security-maintenance` agent after any code change
- Keep all validation in `exarch-core`; bindings only map the existing `InvalidArchive` variant
- Add rustdoc to every new item and keep `#[non_exhaustive]` conventions from [[016-sanitized-mode-and-non-exhaustive-enums/spec]]
- Verify the claimed behavior against the running binary before updating `skills/exarch-cli/SKILL.md`

### Ask First
- Adding a new `ArchiveError` variant (the spec chooses `InvalidArchive`; a new variant would touch all bindings)
- Adding a dependency or patching `sevenz-rust2` via `[patch]`
- Changing the public signature of `sevenz_entry_compression` or other `pub` items in `formats::sevenz`
- Changing `fuzz/seed-corpus.sh` or the fuzz targets beyond placing the fixture

### Never
- Replace the typed wrapper with scattered `.get(..)` or `if` checks at the four sites
- Catch the panic (`catch_unwind`) in core to hide the defect
- Commit a crash input without noting its provenance and license (section 9)
- Drop the open-time check on the strength of an upstream release without re-running the regression test against the new version

## 9. Open Questions

> [!question] Error variant
> **Resolved: `ArchiveError::InvalidArchive`.** It is the variant `SevenZArchive::new` and `list_sevenz_reader` already return for every header that fails to parse (message prefix `failed to open 7z archive:`), and it is what `sevenz-rust2` master will produce for this header, so the observable behavior does not change when the dependency is fixed. `SecurityViolation` is reserved for policy refusals of a well-formed archive. Tests assert the variant, not the message text.

> [!question] Fixture location and seeding
> **Resolved: the first location**, `tests/fixtures/streams-without-files-info.7z`, used by `crates/exarch-core/tests/sevenz_stream_map.rs`; `fuzz/seed-corpus.sh` seeds it through its `tests/fixtures/*.7z` copy. Original question: where the vector lives. Two existing conventions apply:
> - `tests/fixtures/streams-without-files-info.7z`: the `.7z` fixture directory used by `load_fixture`; step (a) of `fuzz/seed-corpus.sh` copies every `tests/fixtures/*.7z` into both the `sevenz` and `extract_archive` seed directories with no script change, so the corpus-seed requirement (FR-010) is met for the `extract` path too.
> - `crates/exarch-core/tests/fixtures/fuzz/sevenz/streams-without-files-info.bin`: the crash-to-regression location in `fuzz/README.md`; seeds only the `sevenz` target, and the directory does not exist yet.
>
> Recommendation: the first, because it reaches `extract_archive` (the target that exercises `extract`) without script changes and keeps one copy of the bytes. The vector is 66 bytes, so the test may instead build it from a hex literal; the README prefers programmatic construction where possible. Decide in the plan.

> [!question] Provenance and license of the vector
> **Resolved:** the upstream resource is Apache-2.0, compatible with this project's MIT OR Apache-2.0; the fixture is committed byte for byte and its provenance (upstream path and git blob) is recorded in `tests/fixtures/generate_7z_fixtures.sh`. Original question: license of `tests/resources/streams_without_files_info.bin` in `hasenbanck/sevenz-rust2` and whether copying a 66-byte fuzzer output needs attribution. The published 0.24.1 crate declares `license = "Apache-2.0"`; the upstream repository's test resources were not checked for a separate license or an attribution requirement. Alternative that avoids the question: rebuild the header byte by byte from the 7z format description in the test, with a comment giving the structure (signature header, then `kHeader`, `kMainStreamsInfo`, pack info, unpack info, `kEnd`).

> [!question] Strength of the invariant (FR-003)
> **Resolved: ranges are checked too.** `SevenZHeader::check` also validates the pack stream offsets length, every `file_block_index` entry against the block count, the pack spans (`check_pack_spans`) and each block's file span against the file count. Original question: check only the three lengths (FR-002), or also the index ranges? Recommendation: also check ranges. The cost is linear in the file count and negligible next to decoding; it makes the wrapper cover the `file_block_index[i] -> blocks[b]` and `block_first_file_index[b] -> files[..]` accesses, which are the other direct-indexing family listed in section 1. With lengths only, those stay protected by a dependency convention.

> [!question] `list` when integrity is not requested
> Plain `list` reaches none of the four indexing sites today, so the panic does not affect it, but it returns an empty, clean-looking manifest for an invalid archive. **Resolved: reject it** (FR-001, FR-005, US-002) for cross-operation parity, in the same spirit as the closed parity issues #707, #720 and #726. This is a behavior change for `list` on this one input.

> [!question] `sevenz` fuzz target and extract
> The `sevenz` target runs `list` and `verify` only. **Resolved: not added.** Original question: add `extract` to it? Recommendation: no; `extract_archive` already runs the full pipeline and receives the seed under the recommended fixture location. Revisit only if the second location is chosen.

> [!question] Upstream release
> FR-011 is non-blocking. **Resolved:** the check carries a comment naming the upstream commits, and `check_pack_spans` names #751 for re-evaluation after the next `sevenz-rust2` release. Original question: how the project tracks the upstream fix (an issue, a `deny.toml`/dependabot note, or a comment at the check). Recommendation: a one-line comment at the check naming the upstream commits plus a follow-up issue titled for re-evaluation after the next `sevenz-rust2` release, filed with the implementing PR.

## 10. See Also

- [[constitution]] — project principles (deny-by-default, invariants in types, verify reporting)
- [[MOC-specs]] — all specifications
- [[001-security-pipeline/spec]] — validation pipeline; the typed-wrapper pattern follows `SafePath` / `ValidatedEntry`
- [[002-format-handlers/spec]] — 7z handler
- [[011-ffi-panic-boundary-simplification/spec]] — why bindings see an exception while the CLI and Rust API abort
- [[016-sanitized-mode-and-non-exhaustive-enums/spec]] — newtype and `#[non_exhaustive]` conventions
- [[005-cli/spec]], [[006-python-bindings/spec]], [[007-node-bindings/spec]] — mapping layers (unchanged)
- Related, closed: #707, #720, #726 (7z cross-operation parity between `list`, `verify` and `extract`); open, adjacent and not duplicated: #674 (encoded header memory limit), #675 (dropped stream file)
- Upstream: `hasenbanck/sevenz-rust2` commits `b7093c37` and `df5b7a96` (unreleased at 0.24.1)
