---
aliases:
  - TAR Empty Directory Preservation
  - Fix TAR directories_added Miscount
tags:
  - sdd
  - spec
  - archive
  - rust
  - bug
created: 2026-08-02
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[002-format-handlers/spec]]"
---

# Feature: TAR Empty Directory Preservation

> [!info] Metadata
> **Subsystem**: exarch-core / creation
> **Priority**: P1
> **Affected formats**: `.tar`, `.tar.gz`, `.tar.bz2`, `.tar.xz`, `.tar.zst` (all share `create_tar_internal_with_progress`)
> **Not affected**: ZIP (`crates/exarch-core/src/creation/zip.rs` already correct)

## 1. Overview

### Problem Statement

`exarch create <output>.tar{.gz,.bz2,.xz,.zst} <dir>` silently discards empty
directories when creating a TAR-family archive. In
`crates/exarch-core/src/creation/tar.rs`, function
`create_tar_internal_with_progress` (the shared implementation used by all
four TAR variants), the `EntryType::Directory` match arm (around lines
240-244) only advances progress tracking and increments a counter — it never
calls `tar::Builder::append_dir` (or equivalent) to write a directory entry
into the TAR stream:

```rust
EntryType::Directory => {
    tracker.on_entry_start(&entry.archive_path);
    report.directories_added += 1;
    tracker.on_entry_complete(&entry.archive_path);
}
```

Compare with the ZIP handler (`crates/exarch-core/src/creation/zip.rs`, lines
182-193), where the equivalent arm calls `zip.add_directory(&dir_path,
options)` before incrementing the same counter. ZIP persists directory
entries; TAR does not.

A second, related defect: `CreationReport::directories_added` is incremented
unconditionally for every directory encountered during the source walk, even
though — for TAR — no bytes are ever written for that directory. The
creation report therefore overstates what was actually persisted to the
archive, for both `.tar`-family output.

### Goal

TAR-family archive creation writes an explicit directory entry for every
directory in the source tree (including empty ones), matching ZIP's
behavior. `directories_added` in `CreationReport` reflects only entries that
were actually written to the archive stream. Round-tripping (create then
extract) a source tree containing empty directories preserves those
directories.

### Out of Scope

- 7z archive creation (not implemented; `FormatCreator` is not implemented
  for 7z per [[002-format-handlers/spec]])
- Changing ZIP's directory-handling behavior (already correct, used as the
  reference implementation)
- Retroactively repairing TAR archives already created with the buggy code
  path (no migration/repair tool)
- Changing the semantics of `directories_added` for ZIP (unaffected by this
  fix)

## 2. User Stories

### US-001: Empty Directories Survive TAR Round-Trip

AS A user archiving a directory tree with `exarch create`
I WANT empty directories (and empty nested directories) in my source tree to
be preserved in the resulting `.tar`/`.tar.gz`/`.tar.bz2`/`.tar.xz`/`.tar.zst`
archive
SO THAT extracting the archive later reproduces the exact directory
structure I archived, without silently losing empty folders

**Acceptance criteria:**
```
GIVEN a source directory containing one or more empty directories (including
      a nested empty directory, e.g. empty2/empty3)
WHEN exarch create <output>.tar.gz <source_dir> is run
THEN the resulting archive contains an explicit directory entry for each
     empty directory
AND  exarch list <output>.tar.gz reports those directory entries in
     total_entries
AND  exarch extract <output>.tar.gz <dest> recreates all empty directories
     on disk, with directories_created reflecting the actual count
```

### US-002: Accurate Creation Report

AS A user or automation script consuming `exarch create --json` output
I WANT `directories_added` to reflect the number of directory entries
actually written to the archive
SO THAT I can trust the report without needing to independently verify the
archive contents

**Acceptance criteria:**
```
GIVEN a source tree with N directories (including the root)
WHEN exarch create <output>.tar.gz <source_dir> --json is run
THEN directories_added in the JSON report equals the number of directory
     entries actually persisted in the archive (verifiable via
     exarch list --json total_entries minus files_added)
```

### US-003: Parity with ZIP Behavior

AS A developer relying on exarch as a format-agnostic archiving library
I WANT TAR and ZIP archive creation to handle empty directories consistently
SO THAT switching output format does not silently change what data is
preserved

**Acceptance criteria:**
```
GIVEN the same source tree containing empty directories
WHEN it is archived once as .tar.gz and once as .zip
THEN both archives contain the same set of directory entries
AND  extracting either archive reproduces the same directory structure
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN `create_tar_internal_with_progress` encounters an `EntryType::Directory` entry, THE SYSTEM SHALL write a directory entry to the `tar::Builder` stream (e.g. via `append_dir`) before advancing the tracker, mirroring the ZIP handler's `add_directory` call | must |
| FR-002 | WHEN a directory entry is successfully written to the TAR stream, THE SYSTEM SHALL increment `CreationReport::directories_added`; if writing fails, the error SHALL propagate via `Result` and the counter SHALL NOT be incremented | must |
| FR-003 | WHERE the directory is the archive root (empty relative `archive_path`), THE SYSTEM SHALL skip writing a directory entry for it, consistent with ZIP's existing root-skip behavior (`crates/exarch-core/src/creation/zip.rs` lines 184-185) | must |
| FR-004 | WHEN a written TAR directory entry is extracted via `extract_archive`, THE SYSTEM SHALL recreate the corresponding directory on disk, including empty and nested-empty directories | must |
| FR-005 | THE SYSTEM SHALL apply the same fix uniformly to all four TAR variants (plain `.tar`, `.tar.gz`, `.tar.bz2`, `.tar.xz`, `.tar.zst`) by fixing the single shared function `create_tar_internal_with_progress`, without duplicating logic per variant | must |
| FR-006 | WHEN a TAR directory entry is written, THE SYSTEM SHALL set directory-appropriate header metadata (entry type `Directory`, sanitized permissions per `sanitize_permissions`, and a trailing `/` in the archive path per TAR convention) consistent with how `tar` crate directory entries are conventionally written | should |
| FR-007 | THE SYSTEM SHALL preserve the existing per-entry `tracker.on_entry_start` / `on_entry_complete` progress callback ordering for directory entries | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Correctness | No silent data loss: any directory present in the source tree (empty or not) that is walked by `collect_entries` SHALL have a corresponding entry in the created archive |
| NFR-002 | Consistency | `directories_added` semantics SHALL match between TAR and ZIP handlers: "number of directory entries actually written to the archive stream" |
| NFR-003 | Backward Compatibility | Archives created by non-buggy TAR writers (external tools) that already contain directory entries continue to extract correctly (no regression to extraction path) |
| NFR-004 | Performance | Writing directory entries adds negligible overhead (one header write per directory, no additional I/O passes over file data) |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `CreationReport` | Report returned by `create_archive` / `_with_progress` | `directories_added: usize` — must count only directory entries actually persisted to the archive stream (fixed by this spec for TAR) |
| `EntryType::Directory` | Walker-produced entry variant representing a directory found during source tree traversal | No payload; carries no data of its own — `entry.archive_path` supplies the relative path |
| `tar::Builder` (external, `tar` crate) | TAR stream writer already used for file/symlink entries in `tar.rs` | `append_dir(path, src_dir)` or equivalent header-based API to add a directory entry without file content |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Root source directory itself (empty relative archive path) | No directory entry written (matches ZIP's existing root-skip logic), `directories_added` not incremented for it |
| Nested empty directory (e.g. `empty2/empty3`) | Directory entry written for both `empty2` and `empty2/empty3`; both counted in `directories_added` |
| Directory that becomes non-empty only due to entries excluded by `allowed_extensions`/filters | Directory entry still written (its own emptiness in the *output* archive does not gate whether the directory entry itself is written — matches ZIP behavior, which writes the directory entry unconditionally when walked) |
| `append_dir`-equivalent write fails (e.g. I/O error, permission issue) | Error propagates via `Result`/`ArchiveError`; `directories_added` is not incremented for the failed entry; overall `create_archive` call fails |
| Symlink to a directory | Out of scope for this fix — handled by the existing `EntryType::Symlink` arm, unaffected by this change |
| Extracting a pre-existing TAR archive created with the old (buggy) exarch version, which contains zero directory entries | Extraction behavior unchanged: only directories implied by file paths are created (no regression; this is the pre-fix status quo for old archives, not something this spec can retroactively repair) |
| Mixed source tree with both empty and non-empty directories | All directories (empty or not) receive a directory entry; files inside non-empty directories are written as before, unaffected by this change |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Empty directory round-trip (create then extract) preserves structure | 100% for all four TAR variants (gz, bz2, xz, zst) plus plain `.tar`, verified by integration test per variant |
| SC-002 | `directories_added` accuracy | `directories_added` in `CreationReport` equals `total_entries` (from `list_archive`) minus `files_added` minus symlink count, for TAR archives with only files/dirs/symlinks |
| SC-003 | Parity with ZIP | Same source fixture (with nested empty directories) produces the same directory-entry count when archived as `.tar.gz` and as `.zip` |
| SC-004 | No regression | All existing TAR creation/extraction tests continue to pass; `cargo nextest run --workspace --all-features --exclude exarch-python --exclude exarch-node` is green |

## 8. Agent Boundaries

### Always (without asking)
- Fix only the shared `create_tar_internal_with_progress` function so all four TAR variants (and plain `.tar`) are corrected in one place
- Run the full pre-commit check suite (`cargo +nightly fmt --check`, `cargo clippy --all-targets --all-features --workspace -- -D warnings`, `cargo nextest run --workspace --all-features --exclude exarch-python --exclude exarch-node`, `cargo test --doc --workspace --all-features`) before proposing the change is complete
- Add/extend integration tests covering empty-directory round-trip for each TAR variant
- Update `CHANGELOG.md` under `[Unreleased]` documenting the fix and the `directories_added` semantics correction
- Follow the existing pattern in `zip.rs`'s `EntryType::Directory` arm (root-skip, path normalization) when writing the analogous TAR code

### Ask First
- Changing the on-disk `directories_added` field name or type (would be a public API / report-schema change affecting `exarch-python` and `exarch-node` bindings)
- Adding a new `tar` crate dependency or upgrading `tar` crate version solely for this fix
- Changing behavior for symlinks-to-directories (out of scope; flag if it turns out to be entangled)

### Never
- Modify the ZIP handler's directory logic (it is the correct reference implementation)
- Silently change `directories_added` semantics without documenting the change in `CHANGELOG.md` (this field is part of the JSON `--json` output contract consumed by scripts and both language bindings)
- Attempt to "repair" or rewrite previously created (already-buggy) TAR archives

## 9. Open Questions

- [NEEDS CLARIFICATION: Should the `skills/exarch-cli/SKILL.md` documentation be updated to explicitly state that TAR (post-fix) and ZIP both preserve empty directories, given the project rule that skills must be updated when documented behavior changes?]
- [NEEDS CLARIFICATION: Is a CHANGELOG entry for this fix a `fix:` (PATCH, since it corrects `directories_added` and empty-directory loss without changing the public API surface) or does the `directories_added` count change for existing callers count as a behavior change worth calling out more prominently (e.g. in migration notes)?]
- [NEEDS CLARIFICATION: Should directory entries in TAR carry the source directory's actual permission bits (via `sanitize_permissions`), or a fixed default mode, for parity with how file entries currently handle permissions in `tar.rs`?]

## 10. See Also

- [[constitution]] — project principles (security-first, format abstraction)
- [[MOC-specs]] — all specifications
- [[002-format-handlers/spec]] — `ArchiveFormat`/`FormatCreator` trait definitions; `ZipArchive` reference implementation for directory handling
- `crates/exarch-core/src/creation/tar.rs` — buggy code location (`create_tar_internal_with_progress`, `EntryType::Directory` arm)
- `crates/exarch-core/src/creation/zip.rs` — reference implementation (`EntryType::Directory` arm, lines 182-193)
