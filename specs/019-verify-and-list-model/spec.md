---
aliases:
  - Verify and List Reporting Model
  - ArchiveManifest and VerificationReport
tags:
  - sdd
  - spec
  - security
  - rust
  - inspection
created: 2026-10-26
status: implemented
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[001-exarch-system/spec]]"
  - "[[001-security-pipeline/spec]]"
  - "[[002-format-handlers/spec]]"
  - "[[005-cli/spec]]"
  - "[[016-sanitized-mode-and-non-exhaustive-enums/spec]]"
  - "[[017-zip-header-consistency/spec]]"
  - "[[018-7z-stream-map-panic/spec]]"
---

# Feature: Verify and List Reporting Model

> [!info] Metadata
> **Subsystem**: exarch-core / `inspection` (`manifest`, `report`, `verify`, `list`, `integrity`),
> `config` (`VerificationOptions`, `ListOptions`), `security::fs_view`
> **MSRV**: Rust 1.98.0
> **Origin**: v0.7.0 inspection work (typed manifest, derived report status, opt-in integrity check)
> **Status**: implemented — this spec documents shipped behavior, extracted as its own unit because
> the archived monolithic [[001-exarch-system/spec]] only describes the pre-0.7.0 flat shapes

## 1. Overview

### Problem Statement

`list_archive` and `verify_archive` inspect an untrusted archive without writing to the
destination. Their result types must not be able to contradict themselves (a report whose status
disagrees with its issues, a manifest whose total disagrees with its entries), must not let a link
entry carry a target it cannot have, and must say honestly what was and was not checked. Earlier
shapes were flat structs with public status fields, an `entry_type` plus optional target pair, and
no way to request payload verification or to express "the target exists but was not read".

### Goal

Specify the typed reporting model: a manifest whose entry kind carries link targets and
compression state in the type, a report whose statuses are derived from its issue list, an explicit
opt-in integrity check, and an in-memory model of the extraction tree so verification never writes
to disk.

### Out of Scope

- The ZIP structure findings themselves (`ZipInconsistency`) — see [[017-zip-header-consistency/spec]]
- 7z stream-map handling and panic hardening — see [[018-7z-stream-map-panic/spec]]
- Extraction-time validation against the real destination (`HostFs`) — see
  [[001-security-pipeline/spec]]
- Binding and CLI output shapes beyond the facts named here — see [[005-cli/spec]],
  [[006-python-bindings/spec]], [[007-node-bindings/spec]]

## 2. User Stories

### US-001: Honest Listing

AS A caller listing an untrusted archive
I WANT each entry's kind to carry its link target, and to know when a target was not read
SO THAT a regular file cannot carry a target and an absent target is never mistaken for an empty one

**Acceptance criteria:**
```
GIVEN a 7z archive with a symlink and the default ListOptions
WHEN list_archive_with_options() runs
THEN the entry kind is Symlink { target: LinkTarget::Unread } and no entry data was decoded

GIVEN the same archive with StoredTargets::Read
WHEN list_archive_with_options() runs
THEN the target is LinkTarget::Recorded(path)
```

### US-002: Report That Cannot Contradict Itself

AS A caller of verify_archive()
I WANT status, security status and integrity status derived from the issue list
SO THAT no report can claim PASS while holding a Medium-or-higher issue

**Acceptance criteria:**
```
GIVEN a report with any High or Critical issue
THEN status() is Fail

GIVEN a report whose highest issue is Medium
THEN status() is Warning and is_safe() is false

GIVEN a report built without an integrity request
THEN integrity_status() is Skipped
```

### US-003: Opt-In Payload Integrity

AS A caller vetting an archive before use
I WANT to request a decode-to-EOF integrity check with a bounded extra decoding budget
SO THAT corruption is detected, and anything the check could not cover is reported as INCOMPLETE
rather than silently passed

**Acceptance criteria:**
```
GIVEN VerificationOptions::default().with_integrity(IntegrityCheck::DecodeToEof(budget))
WHEN verify_archive_with_options() runs on a corrupt payload
THEN integrity_status() is Fail and a High CorruptData issue is present

GIVEN a budget that cannot cover part of the payload
THEN integrity_status() is Incomplete, one Medium IntegrityIncomplete issue is present, and
     integrity_gaps() lists what was not verified
```

### US-004: Verification Without Touching the Disk

AS A caller verifying an untrusted archive
I WANT entries validated against an in-memory model of the extracted tree
SO THAT link escapes, entries under files and overwrite conflicts are found without any write

## 3. Functional Requirements

### 3.1 Manifest

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | `ArchiveManifest` SHALL keep its fields private; `entries()`, `into_entries()`, `total_entries()`, `total_size()`, `format()` and `oversized_entries()` are the accessors, and `add_entry` SHALL fail with `ArchiveError::InvalidArchive` when the total size would overflow `u64` | must |
| FR-002 | `ArchiveEntry` SHALL be `#[non_exhaustive]` with public fields `path`, `kind: ManifestEntryKind`, `size`, `compression: EntryCompression`, `mode: Option<u32>`, `modified: Option<SystemTime>`, and be constructed with `ArchiveEntry::new(path, kind, size)` (compression `Unknown`, mode and modified unset) | must |
| FR-003 | `ManifestEntryKind` SHALL be `#[non_exhaustive]` with variants `File`, `Directory`, `Symlink { target: LinkTarget }`, `Hardlink { target: LinkTarget }`, so only link kinds can carry a target; helpers `entry_type()` (to `ManifestEntryType`), `is_link()`, `symlink_target()`, `hardlink_target()`, `link_target()` | must |
| FR-004 | `LinkTarget` SHALL be `#[non_exhaustive]` with variants `Recorded(PathBuf)` (within the host's name limits), `Missing` (archive stores no target), `Unread` (stored in compressed entry data and not read), `Unreadable` (a 7z reparse point, or a target whose read was attempted and failed), `Oversized { bytes }` (only the length is kept); `path()` SHALL return `Some` only for `Recorded`; `classify(path, LinkKind)` SHALL return `Recorded` or `Oversized` by the host name limits | must |
| FR-005 | `Missing` and `Oversized` targets and `OversizedEntry` records SHALL occur only in the manifest produced by `verify`'s pre-flight listing, where they become report issues; a bare listing SHALL fail instead | must |
| FR-006 | `EntryCompression` SHALL be `#[non_exhaustive]` with `Unknown` (TAR, or an entry with no data stream), `Entry(u64)` (ZIP, 7z single-file block), `SolidBlockStart(SolidBlock)` (carries block `compressed` and `uncompressed` totals) and `SolidBlockMember`; `compressed_size()` SHALL report the block size for a solid block start, and `ArchiveEntry::compression_ratio()` SHALL be `Some` only for `Entry` with a non-zero compressed size, so no per-file ratio exists for solid members | must |
| FR-007 | `OversizedEntry { index, bytes }` SHALL record an entry dropped from the manifest because its path exceeds the host's name limits, keeping only its listing position (kept and dropped entries both count) and path length | must |

### 3.2 Report

| ID | Requirement | Priority |
|----|------------|----------|
| FR-010 | `VerificationReport` SHALL keep its fields private and expose `status()`, `security_status()`, `integrity_status()`, `integrity_gaps()`, `issues()`, `into_issues()`, `total_entries()`, `suspicious_entries()`, `total_size()`, `format()`, `is_safe()`, `has_critical_issues()` and `issues_by_severity()` | must |
| FR-011 | Issues SHALL be sorted from most to least severe (`IssueSeverity`: Info, Low, Medium, High, Critical) | must |
| FR-012 | `status()` SHALL be `Fail` when any issue is High or Critical, else `Warning` when any is Medium, else `Pass`; `is_safe()` SHALL equal `status() == Pass` | must |
| FR-013 | `suspicious_entries()` SHALL count entries with at least one Medium-or-higher issue, counting an entry once however many issues it has; archive-level issues are not entries and are not counted but still decide `status()` | must |
| FR-014 | `security_status()` (`CheckStatus`: Pass, Fail, Warning, Skipped) SHALL be derived only from issues whose category `is_security()`: `Fail` for any Critical or High, else `Warning`, else `Pass`; a Low `NameCollision` (two directories merging with no contents) SHALL be reported but not counted | must |
| FR-015 | `IssueCategory` SHALL be `#[non_exhaustive]`; `is_security()` SHALL match exhaustively so a new category must be classified. Security categories: `PathTraversal`, `SymlinkEscape`, `HardlinkEscape`, `ZipBomb`, `InvalidPermissions`, `QuotaExceeded`, `SecurityPolicy`, `HeaderMismatch`, `DuplicateEntry`, `OverlappingEntries`, `HiddenEntry`, `NameCollision`. Non-security categories: `InvalidArchive`, `SuspiciousPath`, `ExecutableFile`, `CorruptData`, `IntegrityIncomplete`, `ArchiveNote` | must |
| FR-016 | `VerificationIssue::from_error` SHALL map `SecurityViolation` to `SecurityPolicy` (High) and ZIP structure findings to `HeaderMismatch`, `DuplicateEntry`, `OverlappingEntries` or `HiddenEntry` (High); `ArchiveNote` is an informational category for notes that need no action, such as skipped 7z anti-items | must |
| FR-017 | Heuristic issues SHALL be: `ExecutableFile` (Low, regular file with an execute bit), `SuspiciousPath` (Info for extensions `exe`, `dll`, `sh`, `bat`, `cmd`; Medium for a non-UTF-8 name), and `InvalidPermissions` (Medium, mode changed by `sanitize_permissions`; a link entry's recorded mode is not checked because extraction never applies it) | must |

### 3.3 Integrity

| ID | Requirement | Priority |
|----|------------|----------|
| FR-020 | `verify_archive(path, config)` SHALL equal `verify_archive_with_options` with `VerificationOptions::default()`, whose `integrity` is `IntegrityCheck::Skip` | must |
| FR-021 | `IntegrityCheck` SHALL be `#[non_exhaustive]` with `Skip` (default) and `DecodeToEof(DecompressionBudget)`, so a budget without a check is unrepresentable; `VerificationOptions` SHALL be `#[non_exhaustive]` with `with_integrity()` | must |
| FR-022 | `DecompressionBudget` SHALL wrap a `NonZeroU64` (`try_from_bytes(0)` is `InvalidConfiguration`) with `DEFAULT` of 500 MiB, independent of `max_total_size`; it bounds decoding beyond what listing already does (ZIP entries and 7z blocks charged their declared size, compressed TAR charged from the end marker to decoder EOF, TAR entry content not charged) | must |
| FR-023 | `IntegrityStatus` SHALL be `#[non_exhaustive]` with `Pass` ("OK"), `Fail` ("FAILED"), `Incomplete` ("INCOMPLETE"), `Skipped` ("SKIPPED"); derivation: any `CorruptData` issue gives `Fail`; otherwise no integrity request gives `Skipped`; otherwise any `IntegrityIncomplete` issue gives `Incomplete`; otherwise `Pass` | must |
| FR-024 | `Pass` SHALL mean every payload byte was decoded and every checksum the format has matched; for formats without payload checksums (plain TAR, 7z entries without CRC, zstd frames without a content checksum) it means the data was complete and decodable | must |
| FR-025 | A checksum or decoder failure SHALL be a High `CorruptData` issue; everything not verified SHALL be counted per `UnverifiedReason` and reported as one archive-level Medium `IntegrityIncomplete` issue, so overall status is at least `Warning` | must |
| FR-026 | `UnverifiedReason` SHALL be `#[non_exhaustive]` with `OverBudget`, `ResourceLimit`, `SolidPolicy`, `SizeCeiling`, `UncoveredBlockCrc`, `NotDecodable`, `NoEndMarker`, `PathTooLong`, `DescriptorTail`, each with a stable snake_case string form shared by the CLI JSON and bindings and a `description()` | must |
| FR-027 | `IntegrityGaps` SHALL derive from one value the counts, the listed entries and the issue message: `counts()` (reason order, absent when zero), `count(reason)`, `total()`, `is_empty()`, `entries()` (`UnverifiedEntry { path, reason }`, capped at 256) and `omitted()`; `integrity_gaps()` SHALL be `None` when no check was requested and an empty value when everything was verified | must |
| FR-028 | With integrity requested, a TAR entry whose content fails to decode or is cut short SHALL fail the call with `ArchiveError::InvalidArchive` rather than yield a partial report; corruption in a TAR trailer (a gzip CRC, an xz index) SHALL be a `Fail` report | must |
| FR-029 | The CLI SHALL map the option to `verify --check-integrity` with `--decompression-budget SIZE` (requires `--check-integrity`) and `--strict` (exit status 2 on warnings); exit code 0 SHALL NOT be read as integrity `OK` | must |

### 3.4 Listing options

| ID | Requirement | Priority |
|----|------------|----------|
| FR-030 | `list_archive(path, config)` SHALL equal `list_archive_with_options` with `ListOptions::default()` | must |
| FR-031 | `ListOptions` SHALL be `#[non_exhaustive]` with `stored_targets: StoredTargets` and `with_stored_targets()`; `StoredTargets` SHALL be `#[non_exhaustive]` with `Skip` (default; 7z link targets stay `Unread`, no entry data decoded) and `Read` (decodes the blocks that hold the targets) | must |
| FR-032 | Only 7z keeps link targets in compressed entry data; TAR and ZIP always report their targets. `StoredTargets` SHALL be a Rust API and CLI (`list --read-link-targets`) option; Python and Node `list_archive` skip 7z targets | must |
| FR-033 | A 7z reparse point SHALL be `LinkTarget::Unreadable` in every listing | must |
| FR-034 | The listing mode SHALL be an internal two-variant `ListPass`: `Strict(StoredTargets)` (every policy violation fails the listing) and `VerifyPreflight(Option<&mut IntegrityPass>)` (defers rejections to report issues, lifts only the per-file size limit, and is the only mode that can decode payloads) | must |

### 3.5 In-memory tree model

| ID | Requirement | Priority |
|----|------------|----------|
| FR-040 | Verification SHALL validate entries against a `VirtualTree` of what extraction would create, rooted at a temporary directory used only as a path anchor; no archive content SHALL be written | must |
| FR-041 | Each entry SHALL pass, in order: name-length check, `SafePath::validate_in`, quota reserve, compression-ratio check, then link validation (`SafeSymlink::validate_in` / `HardlinkTracker::validate_hardlink_in`) against the tree; link escapes SHALL be reported as `SymlinkEscape` / `HardlinkEscape` | must |
| FR-042 | Tree nodes SHALL be `Dir`, `File`, `Symlink(target)` and `OpaqueSymlink` (a link whose target was not read: it exists but a path resolving through or onto it is an error) | must |
| FR-043 | The first entry at a path SHALL win, mirroring extraction that skips an existing entry; a symlink over an earlier file SHALL replace it in the tree and be reported as a security finding (`SecurityPolicy`), since overwrite semantics would change what the path resolves to | must |
| FR-044 | A conflict where overwriting fails closed and replaces nothing (symlink over a directory or a symlink with another target, file over a directory or symlink, hardlink over any earlier entry) SHALL be a Low `InvalidArchive` note naming the earlier occupant, leaving status `Pass`; a symlink repeating an earlier symlink's target SHALL not be noted | must |
| FR-045 | An entry whose parent is a file or a dangling symlink, a parent chain that loops or leaves the root, or a directory entry over a non-directory SHALL be reported: as a `SecurityPolicy` violation when a link is involved (the entry is one, or the path crosses one), otherwise as an `InvalidArchive` I/O finding | must |
| FR-046 | Hardlinks SHALL be materialized after every other entry: link path and target are re-validated against the final tree, the target must exist and must not resolve to a directory, and a hardlink cannot replace an existing entry | must |
| FR-047 | Symlink chains SHALL be cut off after `MAX_SYMLINK_HOPS` (macOS 33, glibc 40, musl 39, Windows 63 unverified, other Unix 32), matching `std::fs::canonicalize` | must |
| FR-048 | Name lengths SHALL use per-OS limits (`MAX_COMPONENT_LEN` 255, `MAX_PATH_LEN` Linux 4095, macOS and other Unix 1023, Windows 32767 UTF-16 units); a symlink target is checked against `MAX_SYMLINK_TARGET_LEN` only. Over-long entries SHALL be dropped to `OversizedEntry` and reported as I/O issues, the first 16 individually and the rest in one closing issue | must |
| FR-049 | Names SHALL be compared after NFD plus a per-character case fold on macOS, the same fold without normalisation on Windows, and exactly elsewhere; two names that differ exactly but fold equal SHALL be recorded as a `NameCollision` and never merged silently. Severity: `CollisionKind::Mixed` (kinds differ or a symlink involved) High; `Files` and `DirectoriesWithContents` Medium; `Directories` (neither holds entries) Low | must |
| FR-050 | Symlinks whose targets are `Unread` while symlinks are allowed SHALL produce one archive-level Medium `SecurityPolicy` issue counting them; entries beneath or through an unread link are reported as failures. With symlinks disallowed, an `Unread` or `Unreadable` target SHALL be reported as the policy violation | must |
| FR-051 | A missing link target SHALL be reported as a `SecurityPolicy` violation | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Safety | Verification SHALL perform no write of archive content; no `unsafe` code is used |
| NFR-002 | Resource bounds | Over-long names and targets keep only their length, issue lists for oversized entries are capped, and `IntegrityGaps` lists at most 256 entries, so a hostile archive cannot inflate the manifest or report |
| NFR-003 | API stability | `ArchiveEntry`, `ManifestEntryKind`, `LinkTarget`, `EntryCompression`, `SolidBlock`, `OversizedEntry`, `IssueCategory`, `IntegrityStatus`, `UnverifiedReason`, `IntegrityCheck`, `VerificationOptions`, `ListOptions`, `StoredTargets` and `VerificationIssue` are `#[non_exhaustive]`; downstream matches need a wildcard arm |
| NFR-004 | Honesty | Every limit of the model (destination state, host fold approximation, overwrite semantics, destination prefix length) is documented on `verify_archive`; a `Pass` does not guarantee extraction into a non-empty destination succeeds |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `ArchiveManifest` | Listing result | private entries, oversized records, total size, `ArchiveType` |
| `ArchiveEntry` | One listed entry | `path`, `kind`, `size`, `compression`, `mode`, `modified` |
| `ManifestEntryKind` | Entry kind with its link target | `File`, `Directory`, `Symlink { target }`, `Hardlink { target }` |
| `ManifestEntryType` | Closed wire tag of a kind | `File`, `Directory`, `Symlink`, `Hardlink` |
| `LinkTarget` | Target as far as listing kept it | `Recorded`, `Missing`, `Unread`, `Unreadable`, `Oversized { bytes }` |
| `EntryCompression` / `SolidBlock` | Compressed-size attribution | `Unknown`, `Entry`, `SolidBlockStart`, `SolidBlockMember`; block `compressed`, `uncompressed` |
| `OversizedEntry` | Entry dropped for path length | `index`, `bytes` |
| `VerificationReport` | Derived-status report | issues, integrity scope, totals, format |
| `VerificationIssue` | One finding | `severity`, `category`, `entry_path`, `message`, `context` |
| `VerificationStatus` | Overall | `Pass` ("PASS"), `Fail` ("FAIL"), `Warning` ("WARNING") |
| `CheckStatus` | Security check | `Pass` ("OK"), `Fail` ("FAILED"), `Warning`, `Skipped` |
| `IntegrityStatus` | Payload check | `Pass` ("OK"), `Fail` ("FAILED"), `Incomplete`, `Skipped` |
| `IntegrityGaps` / `UnverifiedEntry` / `UnverifiedReason` | What the check left unverified | counts per reason, listed entries, `omitted` |
| `VerificationOptions` / `IntegrityCheck` / `DecompressionBudget` | Integrity request | `Skip` or `DecodeToEof(budget)`; default budget 500 MiB |
| `ListOptions` / `StoredTargets` | Listing request | `Skip` (default) or `Read` |
| `VirtualTree` / `Node` / `Occupant` / `CollisionKind` | In-memory extraction model | see FR-040 to FR-049 |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Entry name with `..` or an absolute path (without `allowed.absolute_paths`) | Listing fails with `PathTraversal` before a report exists |
| ZIP central directory with more records than `max_file_count` | Call fails; `total_entries()` is the raw central directory count |
| 7z symlink, default listing | `LinkTarget::Unread`; `verify` without integrity reports one Medium `SecurityPolicy` issue |
| 7z symlink, integrity budget too small | Target stays `Unread`, gap reason `OverBudget` or `ResourceLimit` |
| Entry under a regular file | Conflict at the parent; `InvalidArchive` I/O finding, or `SecurityPolicy` if a link is on the path |
| Symlink pointing outside the destination | `SymlinkEscape` Critical |
| Hardlink whose target never appears | Reported after materialization, target missing |
| `Cafe.txt` and `cafe.txt` on macOS or Windows host | `NameCollision` Medium (two files) |
| Two empty directories folding equal | Low `NameCollision`, not counted by `security_status()`; if either later gains an entry it is reported at its real severity |
| TAR stream without an end-of-archive marker, integrity requested | Gap reason `NoEndMarker`, integrity `Incomplete` |
| Solid 7z with `allow_solid_archives` off, integrity requested | Gap reason `SolidPolicy`, integrity `Incomplete` |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | A report whose status contradicts its issues | Impossible — statuses are derived, fields private |
| SC-002 | A regular file carrying a link target, or a budget without an integrity check | Impossible — unrepresentable in the types |
| SC-003 | Verification writing archive content to disk | Never — tree model only |
| SC-004 | A skipped or partial integrity check reported as OK | Never — `Skipped` / `Incomplete` with a Medium issue |

## 8. Agent Boundaries

### Always (without asking)
- Derive any new status from the issue list rather than storing it
- Classify a new `IssueCategory` in `is_security()` (the match is exhaustive on purpose)
- Add a wildcard arm when matching the `#[non_exhaustive]` types above from another crate
- Update `skills/exarch-cli/SKILL.md` when `verify` / `list` flags, JSON or exit codes change

### Ask First
- Changing a severity mapping (it moves `status()` and the CLI exit code)
- Raising the 256-entry or 16-issue caps

### Never
- Write archive content to disk during `verify`
- Report an unread or unreadable link target as validated
- Add a public constructor or setter that lets a report or manifest be built inconsistent with its contents

## 9. Open Questions

None — retrospective spec documenting shipped behavior.

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[001-exarch-system/spec]] — archived monolithic spec (FR-050 to FR-052)
- [[001-security-pipeline/spec]] — the validation pipeline verification reuses
- [[016-sanitized-mode-and-non-exhaustive-enums/spec]] — `IssueCategory` non-exhaustive hardening
- [[017-zip-header-consistency/spec]] — ZIP structure findings reported as issues
- [[018-7z-stream-map-panic/spec]] — 7z stream-map handling
- `crates/exarch-core/src/inspection/manifest.rs`, `report.rs`, `verify.rs`, `list.rs`, `integrity.rs`
- `crates/exarch-core/src/config.rs` — `VerificationOptions`, `IntegrityCheck`, `DecompressionBudget`, `ListOptions`, `StoredTargets`
- `crates/exarch-core/src/security/fs_view.rs` — `VirtualTree`, limits, `NameCollision`
