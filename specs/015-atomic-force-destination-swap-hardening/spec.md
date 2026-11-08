---
aliases:
  - Atomic-Force Destination Swap Hardening
  - GHSA-x8wr-7ww2-c94x Fix
  - extract --atomic --force TOCTOU Hardening
tags:
  - sdd
  - spec
  - security
  - cli
  - rust
created: 2026-08-04
updated: 2026-11-08
status: implemented
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[001-security-pipeline/spec]]"
  - "[[005-cli/spec]]"
---

# Feature: Atomic-Force Destination Swap Hardening

> [!note] Revision 2026-11-04 (50-issue batch, shipped in 0.9.0)
> The swap is now planned once (`WriteMode`, `ExtractPlan::Replace`), names are a single-component `EntryName`, and the displaced destination is held by a `DisplacedDestination` guard that restores it on any early exit (#935, #936). FR-014 to FR-016 add these; FR-001 to FR-013 are unchanged.

> [!info] Metadata
> **Subsystem**: exarch-core (`staging/replace.rs`, `staging/dir.rs`, `formats/pinned_dir.rs`); exarch-cli (`commands/extract.rs` write-mode planning)
> **Priority**: P0 (security)
> **Origin**: GHSA-x8wr-7ww2-c94x (#525/#526), TOCTOU follow-up (#531), orphan-disclosure
> follow-up (#530), destination-identity pinning (#535), symlink-swap TOCTOU close (#536/#531)
> — v0.6.0
> **Status**: implemented — this spec documents shipped behavior for `exarch extract
> --atomic --force`'s destination-swap hardening, a self-contained security fix large
> enough (five follow-on PRs) to warrant its own spec rather than a subsection of
> [[005-cli/spec]]

> [!note] Revision 2026-11-08: staging root ACL (#1031, #1039)
> The published root now carries the destination's ACL, and the ACL the staging directory inherits from the destination's parent is cleared (FR-110, FR-111); follow-ups #1060 (macOS copy), #1020 (Windows DACL), #1063 (warning and probe hardening).

> [!note] Revision 2026-11-08: staged children inherit the destination's ACL (#1067)
> The staging directory is seeded with the destination's inheritable entries after the umask probe, so staged children get the ACL an in-place extraction would give them, and the stage stays `0700`; a seeded stage whose destination vanished, or whose seeding was withheld, is published `0700` with no ACL (owner and group still claimed unless the destination changed); the macOS inheritable-entries restriction and `NarrowingReason::AclHasInheritableEntries` (`acl_has_inheritable_entries`) are removed (FR-110, FR-111, FR-112, FR-113).

> [!note] Revision 2026-11-08: ACL after the rename, private macOS stage (#1079, #1078)
> The destination's ACL and mode reach the root only after the publishing rename, through the held descriptor, so a destination whose ACL denies deleting it now publishes; if writing the ACL or mode fails after the rename, the run still succeeds and reports `acl_copy_failed`, and the root is made `0700` with no ACL on a best-effort basis (FR-105, FR-110). On macOS an absent destination's stage captures the ACL it inherited from the parent, clears it, probes the umask and re-seeds it as `only_inherit`, so the stage is owner-only for the whole run (FR-104, FR-111, FR-113); the known gap is closed. Open non-goals: see section 9.

> [!note] Revision 2026-11-08: macOS ACL copy and narrowing warning (#1060, #1063)
> macOS copies the destination's ACL through descriptors (no `exacl`), and every case where the published root gives less access than the destination raises a typed `RootAccessNarrowed` warning (FR-110, FR-112).

> [!note] Batch #1008 amendments
> The swap runs on the single `VettedDir` layer on every target, with Windows identity from `FileIdInfo` (FR-099, FR-106, FR-008, FR-009 rewritten in place); staging is `0700` with an armed guard and permissions are adopted only at the swap (FR-104, FR-105); leftovers are reported (FR-108).

> [!note] Batch #981 amendments
> The swap moved from the CLI into `exarch-core` as `Staging::AtomicReplace` (FR-098 to FR-103, #984). FR-001 to FR-016 describe behavior that now lives in core; names such as `commands::atomic_swap::PinnedDir` read as the core `pinned_dir` primitives.

> [!note] Revision 2026-11-08: names moved to core
> `commands/atomic_swap.rs` and `run_atomic_force_extraction` no longer exist. Mapping for FR-003 to FR-007 and FR-014 to FR-016: `PinnedDir` is `VettedDir`; `entry_status` is `VettedDir::status` returning `EntryStatus { occupant, reparse, identity }` (replacing `DestEntryKind`); `current_path` and `open_entry` are `VettedDir::entry_path`; `EntryName` is `Leaf` (borrowed) and `LeafBuf` (generated names); `DisplacedDestination` is the `Displaced` guard in `staging/replace.rs`. A fd-to-path facility exists on Linux, Android and macOS only; elsewhere the leftover is named by its logical path (the `find -inum` pointer of FR-007 is gone).

## 1. Overview

### Problem Statement

`exarch extract --atomic --force` onto a pre-existing destination performs a swap:
extract into a temp directory beside the destination, rename the existing destination
aside to a backup path, rename the extracted content into place, then remove the backup.
Before this fix, every step of that swap was resolved **by path** — `exists()`,
`is_dir()`, `canonicalize()`, then `rename`/`remove_dir_all` using the canonicalized
result. Two independent vulnerability classes followed from this:

1. **GHSA-x8wr-7ww2-c94x**: if the destination *itself* was a symlink, canonicalizing it
   silently retargeted the swap at whatever directory it pointed to. Because the swap ends
   in `remove_dir_all` on the displaced backup, this meant an attacker who could plant a
   symlink at the destination path (requiring only write access to the destination's
   *containing* directory, no race) could cause `exarch extract --atomic --force` to
   destroy the contents of an arbitrary directory the invoking user could write to —
   attacker-directed destructive replacement, deterministic, no TOCTOU window needed.
2. **TOCTOU on intermediate path components** (#526): even after fixing (1), resolving
   `parent`'s components by path on every rename/remove call left a window where replacing
   an *intermediate* component of the destination's parent path with a symlink mid-extraction
   could redirect later steps of the same swap outside the intended destination.

A related, non-security disclosure gap (#530) was found during hardening: the best-effort
cleanup on failure was itself path-based, so if an intermediate redirect occurred and then
*reverted* before cleanup ran, the cleanup could silently target a decoy at the
now-stale redirected location — leaving genuine extracted content behind with no
indication of where it went.

### Goal

Every step of the `--atomic --force` swap operates on a *pinned identity* — a file
descriptor obtained once, or a `(dev, ino)` pair checked against that descriptor —
never a path re-resolved after the fact. A destination that is itself a symlink is
rejected outright, on every platform. A destination redirect via an intermediate path
component is confined to, at most, aborting the swap with a distinct error; it can never
redirect a rename or remove. If content survives an aborted swap at an unexpected
location, its real current path is disclosed, not silently swallowed.

### Out of Scope

- Any extraction path other than `exarch extract --atomic --force` onto a *pre-existing*
  destination — plain `extract`, `--atomic` without `--force`, and the Rust/Python/Node
  APIs are explicitly unaffected (see #533, documented in [[001-security-pipeline/spec]]'s
  `DestDir` entry) since they resolve a symlinked destination *root* via `canonicalize()`
  by design, matching `tar -C`/`unzip -d`, with containment enforced downstream by
  `SafePath` regardless
- `exarch-core`'s own per-entry extraction writes, which remain path-based; making them
  fd-relative is a separate, larger undertaking explicitly out of scope for this fix (a
  documented residual: content written directly to a redirect-created decoy directory,
  if the redirect reverts before the post-cleanup identity check runs, remains a genuine,
  undisclosed orphan — not a security escape, since the fd-pinned swap logic itself still
  confines renames/removes correctly)
- Copying a DACL on Windows (#1020); it falls back to the inherited ACL (FR-110)
- Windows: an owner-only DACL on the staging directory (it inherits the parent's ACL, FR-104) and a test for a non-name-surrogate reparse point; the handle-relative swap itself is in scope since #1005 (FR-099)

## 2. User Stories

### US-001: Symlinked Destination Rejected Outright

AS A user running `exarch extract --atomic --force` against a destination path
I WANT the command to refuse to proceed if that destination is itself a symlink
SO THAT I cannot be tricked (via a symlink planted by another process or a previous,
unrelated operation) into destroying the contents of a directory I did not intend to
touch

**Acceptance criteria:**
```
GIVEN a destination path that is a symlink pointing at directory D
WHEN exarch extract --atomic --force archive.tar.gz <destination> is run
THEN the command fails with a distinct symlink-destination error before any rename or
     removal occurs; D's contents are untouched
```

### US-002: Swap Confined to a Pinned Identity

AS A security reviewer
I WANT every rename/remove in the destination swap to operate relative to a file
descriptor pinned once at the start, not a path re-resolved on each call
SO THAT replacing an intermediate path component with a symlink mid-extraction cannot
redirect any part of the swap, even if the replacement happens between two of the
swap's internal steps

**Acceptance criteria:**
```
GIVEN a destination whose parent directory has an intermediate path component
      replaced with a symlink after extraction begins but before the swap completes
WHEN the swap reaches its destructive rename/remove steps
THEN operations are performed *at*-relative to the pinned parent file descriptor,
     which identifies an inode, not a path — the redirect cannot retarget them; a
     dev/ino identity mismatch immediately before the final destructive step aborts
     the swap with a distinct error instead of proceeding
```

### US-003: Surviving Content Disclosed, Not Silently Lost

AS A user whose `--atomic --force` extraction failed after a mid-extraction redirect
I WANT the error output to disclose the actual, current location of any surviving
temp/backup content
SO THAT I can recover it manually instead of it being silently left behind with no
indication of where

**Acceptance criteria:**
```
GIVEN a failed --atomic --force extraction where best-effort cleanup could not locate
      its temp/backup directory at the expected logical path (due to a mid-extraction
      redirect)
WHEN the CLI reports the failure
THEN the error output includes the directory's actual current path, resolved via an
     open file descriptor on the entry itself rather than the possibly-stale logical
     path built from the (possibly still-redirected) parent
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN `extract --atomic --force`'s destination path is itself a symlink (or, on Windows, a junction or other reparse point), THE SYSTEM SHALL reject the operation on all platforms before any rename or removal, distinct from other `--atomic --force` errors | must |
| FR-002 | WHEN `extract --atomic --force`'s destination is a symlink to a regular file, THE SYSTEM SHALL report the symlink-destination error, not a "not a directory" error | must |
| FR-003 | ON Unix, `run_atomic_force_extraction` SHALL pin the destination's parent directory with an open file descriptor (`commands::atomic_swap::PinnedDir`) once, and perform every subsequent rename/remove `*at`-relative to that descriptor instead of re-resolving the path | must |
| FR-004 | THE SYSTEM SHALL classify the destination entry itself via an fd-relative `statat(SYMLINK_NOFOLLOW)`-equivalent call (`PinnedDir::entry_status`), never a path-based `exists()`/`is_dir()`/`canonicalize()` sequence, so the destination's parent is canonicalized and pinned exactly once while the destination's own name is taken lexically and never re-canonicalized | must |
| FR-005 | THE SYSTEM SHALL capture each swap-relevant directory's `(dev, ino)` identity (via `PinnedDir::entry_status`, fd-relative to the pinned parent) immediately after creating it, and re-check that identity immediately before the destructive swap step; a mismatch SHALL abort the swap with a distinct error instead of proceeding | must |
| FR-006 | WHEN best-effort cleanup on failure cannot confirm its temp/backup directory was removed, THE SYSTEM SHALL re-check that directory's identity via the pinned parent; if it still exists and matches, THE SYSTEM SHALL resolve its *current* path fresh from a freshly opened file descriptor on the entry itself (`/proc/self/fd` on Linux, `F_GETPATH`/`rustix::fs::getpath` on macOS) and disclose that path in the error output | should |
| FR-007 | IF no fd-to-path facility is available, THE SYSTEM SHALL report the leftover by its logical path (`VettedDir::entry_path` returns `None`; superseded: the `(dev, ino)` pointer of v0.6.0 was removed with the CLI swap) | should |
| FR-008 | ON Windows, THE SYSTEM SHALL perform the swap through the same handle-relative `VettedDir` primitive as Unix (NT handle based, `rename_dir_within` and `remove_dir` relative to the parent handle), while still applying the destination-symlink/junction rejection from FR-001 on all platforms; superseded in part: the earlier path-based Windows swap is gone (#1005) | must |
| FR-009 | Obtaining the pinned parent file descriptor SHALL require search (execute) permission on the destination's parent directory, not read permission, for every `--atomic --force` invocation, including when the destination does not yet exist: the parent is opened with `O_PATH` on Linux and Android and `O_SEARCH` on macOS and the other Unix targets (#1005; v0.6.0 required read permission, #531); it SHALL NOT require any permission on the destination directory itself | must |
| FR-010 | THE SYSTEM SHALL NOT pre-delete a pre-existing destination directory before extraction is known to succeed; `--atomic --force` SHALL extract into a temp directory first and perform the swap only after extraction fully succeeds, with a failed final rename restoring the backup and reporting its path if that restore itself fails (#519, precursor to the swap-hardening in this spec) | must |
| FR-011 | A pre-existing destination that exists but is not a directory (e.g. a regular file) SHALL be rejected with an explicit error, not silently replaced | must |
| FR-012 | WHEN `--atomic --force` extraction fails inside the temp directory, THE SYSTEM SHALL report the failure as `ArchiveError::PartialExtraction` with `writes` set to `PartialWrites::RolledBack` (`err.rolled_back()`), and the `--json` `error.partial_report.writes` SHALL be `rolled_back`, so the counters are not presented as leftovers on disk (v0.7.0, #725, #728); since v0.8.0 the CLI takes the same atomic path implicitly, with the same `rolled_back` outcome, for a TAR extracted into a destination that does not exist (see [[005-cli/spec]] FR-097, #799, #808) | must |
| FR-013 | THE SYSTEM SHALL compare directory identities through a typed `FileIdentity` (`Known { dev, ino }` or an explicit `Unknown`, deliberately without `PartialEq`), so a platform with no stable identity cannot make a comparison succeed vacuously and each caller decides what an unverifiable identity means (v0.8.0, #878, #888) | must |
| FR-014 | Names passed to `VettedDir` methods SHALL be a `Leaf<'_>` (exactly one normal component; `Leaf::split` refuses `..`, a root, a prefix and an empty path) or a `LeafBuf` (`LeafBuf::of(&Path)` returns `None` for `.`, `..` and anything with a separator, and `LeafBuf::random(prefix)` builds the generated staging and backup names from 64 random bits), so the `*at` calls can never be given a multi-component name (#935) | must |
| FR-015 | A destination displaced for the swap (renamed aside to a vacant backup name) SHALL be held by a `Displaced` guard (`staging/replace.rs`): `Drop` restores it best-effort (reached only when unwinding, so its failure cannot be reported), while `restore()` and `discard()` consume the guard and disarm it, reporting their outcome through `Restore` in `ReplaceFailure` and a `BackupCleanupFailed` warning; an early `?` between displace and swap therefore restores the destination (#936) | must |
| FR-016 | The write mode SHALL be decided once into `WriteMode` and `WriteMode::{Safe, Force, Atomic, AtomicReplace}` (CLI `commands/extract.rs`) is mapped once to `ExistingFiles` and `Staging` and planned as `ExtractPlan::{Stream { options }, Listed { listed, options }}` (the swap itself is core's `Staging::AtomicReplace`, FR-098), deriving the extraction options per variant, so the atomic and non-atomic paths cannot disagree about what they extract with (#936) | must |
| FR-098 | The destination swap SHALL be implemented in `exarch-core` (module `staging`: `staging/replace.rs` holds the swap, the restore, the backup warning, `ReplaceFailed` and `DestinationChanged`; `staging/dir.rs` holds the private staging directory and `staging/adopt.rs` the permission adoption, both over `formats::pinned_dir::VettedDir`) and selected by `Staging::AtomicReplace`; the CLI and both bindings SHALL map to it and add no swap logic | must |
| FR-099 | The swap SHALL run on one pinned-directory layer, `formats::pinned_dir::VettedDir`, on every target (`staging/parent.rs` and its three arms are removed, #1005): Unix and WASI by an open directory handle (`*at` renames, `unlinkat(REMOVEDIR)`, no-follow `status` returning `EntryStatus { occupant, reparse, identity }`, `current_path` from `/proc` or `getpath`, else `None`); Windows by NT handles, where `rename_dir_within` passes no replace-if-exists flag (`nt::Replace::Never`; `replace_entry` passes `IfExists`) and the replace target is refused if it is any reparse point, while extraction keeps the name-surrogate classification | must |
| FR-100 | `AtomicReplace` SHALL be refused before extraction with `InvalidConfiguration { OutputPath, ReplacesProtectedPath }` when the canonical destination is a filesystem root, equal to or an ancestor of the canonical archive path (path-based requests), or equal to or an ancestor of the process working directory (`ProtectedPath::{FilesystemRoot, ArchiveAncestor, WorkingDirectory}`); the guard compares directory identity (dev, ino) rather than path text, so a case-insensitive volume cannot spell its way around it | must |
| FR-101 | A failed swap SHALL be `ArchiveError::ReplaceFailed(ReplaceFailure { error, restore, leftover })` with `Restore {NotNeeded, Restored, Failed { backup, error }}` and `leftover: Option<StagingLeftover>` (set only when a failed swap leaves the staging directory behind; paths redacted in binding release builds; a staging directory that survives a failed extraction is reported through FR-108, #995, #1008); an identity re-check mismatch SHALL be `Violation::DestinationChanged` (sub-code `ConcurrentChange`); `Atomic` and `AtomicReplace` SHALL resolve the destination before extraction: a symlink to a directory is canonicalized and renamed onto (#977), a non-empty directory is `OutputExists` before extraction and at ENOTEMPTY or EEXIST (#985), a file is `NotADirectory` and a dangling symlink `IsSymlink` | must |
| FR-102 | Cancellation SHALL be polled after extraction and before the rename and before the displace step ([[004-progress-tracking/spec]] FR-057); `Atomic` and `AtomicReplace` SHALL extract the staging directory under `Refuse`, so a file planted at a landing cannot survive and be published (residual: a same-user process can still plant a file at a path no entry lands on) | must |
| FR-103 | `AtomicReplace` with a non-default entry selection or strip SHALL be refused in core as `InvalidConfiguration { EntrySelection, NotSupported }`, because the swap would delete everything in the destination that the subset does not contain ([[022-extract-entry-selection/spec]] FR-107) | must |
| FR-104 | THE SYSTEM SHALL create every staging directory `0700` (owner only) through the pinned parent, as an armed guard (`StagingDir`): dropping it, on an early `?` or an unwind, removes it, and `discard` reports what survived as a `StagingLeftover`; on macOS the ACL entries the staging directory inherited from the destination's parent are cleared right after its creation and re-seeded as `only_inherit` where there are any (FR-111), so it is owner-only for the run except for the short window between the `mkdir` and the clear (an open non-goal, section 9); on Linux and other Unix an `Absent` stage keeps the parent's default ACL, which the `0700` mode's mask neutralizes, and the other seeds clear it (FR-111); on Windows the staging directory inherits the ACL of the destination's parent (an owner-only DACL is deferred) (#1002, #1078) | must |
| FR-105 | THE SYSTEM SHALL give the published root the permissions of the destination only at the swap, never while the archive extracts: `AtomicReplace` reads the destination's mode and owner before displacing it (a read failure aborts with nothing moved), then after the displace and identity recheck adopts its mode (sticky and setgid kept, setuid never) and, as far as the caller may, its owner (`Claim::Full`: a best-effort `fchown`, and when the resulting gid differs from the destination's, the group and setgid bits are dropped); `Atomic` onto an existing empty directory adopts its mode but never its uid, its gid only when the caller owns the destination, and for a foreign-owned destination drops group and world write and setgid (`Claim::Cautious`); the destination's ACL is applied only after the publishing rename succeeded (FR-110), so every failure before it leaves a private, removable staging directory; if the publishing rename fails the root is made `0700` again before it is discarded; on WASI the root is published without adoption (#1002, #1079) | must |
| FR-106 | Identity SHALL be one `FileIdentity` / `IdentityKey { dev, ino }` taken from the open handle: `(st_dev, st_ino)` on Unix and WASI, and on Windows `GetFileInformationByHandleEx(FileIdInfo)` only (64-bit volume serial and 128-bit file id, an all-zero id is unknown), with no `GetFileInformationByHandle` fallback; any failure is `Unknown`, which never compares equal, and the protected-path guard then falls back to comparing canonicalized ancestor and destination text and refuses on any lookup error, so an 8.3 short-name spelling of the archive's directory is recognised through identity (#1003, #1005) | must |
| FR-110 | WHEN the published root adopts the destination's mode (FR-105), THE SYSTEM SHALL also carry the destination's ACL, because mode bits cannot express it (on Linux the group bits of a directory with an ACL hold the mask, a macOS deny entry has no mode bit): on Linux and Android the POSIX ACL is copied (access and default entries; the default ACL also reaches the staged children, FR-113) after the root's owner and group are known and equal the destination's; THE SYSTEM SHALL write the ACL and then the mode only after the publishing rename, through the descriptor held across it: the staging directory's own ACL stays empty until then, because a copied non-inheritable `deny delete` entry would make the rename fail with `EACCES` and leave an undeletable stage; the order is enforced by the type system, as `StagingDir::publish` returns a `Published` token (private constructor) that `AdoptedRoot::finish` requires; THE SYSTEM SHALL instead leave the root private (`0700`) when the ACL cannot be copied faithfully (the root belongs to another user or group, the ACL is unreadable, a Linux ACL names a user or group with the undefined id `0xFFFFFFFF`, which is how the kernel reports an id outside the reader's user namespace); on macOS the ACL is read and written through the pinned descriptor by `formats/pinned_dir/darwin_acl.rs` (`fgetattrlist`/`fsetattrlist` with a safe parser in `staging/acl.rs`, the owner and group of the list zeroed, the ACL written before the mode), `EINVAL` on read (FAT32 and exFAT volumes) means no ACL, and WHEN writing the ACL or mode fails after the rename, THE SYSTEM SHALL still succeed and report `acl_copy_failed`, making the root `0700` with no ACL on a best-effort basis (the root is already published and no wider than the destination: the macOS write is all-or-nothing and the mode stays `0700` until after it, and on Linux the access xattr derives the mode from the destination's own ACL); any other error reading the ACL or preparing the root before the rename SHALL fail the run (fail closed) and never publish a root more open than the destination; the adopted mode is the typed `DirMode`; other Unixes and NFSv4 ACLs are not detected; a DACL on Windows is #1020 (#1031, #1039, #1060, #1063, #1067, #1079) | must |
| FR-111 | THE SYSTEM SHALL prepare every staging directory in one constructor, in the fixed order: create it `0700`, claim it (identity check), clear the ACL entries it inherited from the destination's parent (the default ACL on Linux, inheritable entries on macOS), probe the umask, seed the destination's inheritance; the seed is the typed `Seed`: `Absent` (no destination: on Linux and other Unix nothing is cleared or seeded, because the `0700` mode sets the POSIX ACL mask to `---` and clearing would make the probe miss the parent's default ACL and read a wrong mode, and the probe is mandatory; on macOS the stage's freshly inherited list, which is what `mkdir` of the destination in the parent would give, is captured first, then cleared, the umask probed, and the captured list seeded as `only_inherit` entries (WHEN the stage inherited nothing, the captured plan is empty, including FAT32 and exFAT volumes, THE SYSTEM SHALL skip the clear and the seed entirely), so the stage is owner-only for the whole run, the probe directory inherits nothing and a parent that grants or denies `delete` by inheritance cannot stop the probe, a failed capture or clear fails the run, and only a failed seed is `Inherited::Withheld(acl_copy_failed)`), `FillEmpty` (an empty destination filled in place: cleared, probed, seeded; a probe failure is tolerated) and `Replace` (`AtomicReplace`: cleared, seeded, no probe); a failure to clear SHALL fail the run, so the inherited grant cannot leak into the published root; WHEN seeding the destination's inheritance fails, THE SYSTEM SHALL clear the staging directory's ACL again and record the typed `Inherited::Withheld(acl_copy_failed)` (a second clear failure fails the run); at adoption `Inherited { Parent, Destination, Seeded, Withheld }` decides the outcome: WHEN the destination's inheritance was withheld, or the destination's identity at adoption differs from the seeded one (an identity the volume cannot provide is not a difference), THE SYSTEM SHALL clear the root's ACL, publish it `0700`, skip the ACL copy and record `root_access_narrowed` with the withheld reason (`acl_copy_failed`) or `destination_changed`; WHEN a staging directory was seeded and no directory remains at the destination when the root is adopted, THE SYSTEM SHALL publish the root `0700` with no ACL and record `destination_vanished`, while a destination with nothing to seed keeps the mode a new directory gets; WHEN a fresh (absent-destination) root carries a captured list, the root is the origin `RootOrigin::Fresh` and the list is resolved against the stage's own ownership, then applied after the rename as in FR-110 (#1039, #1067, #1078) | must |
| FR-112 | WHEN the published root gives less access than the destination, THE SYSTEM SHALL record one `ExtractionWarning::RootAccessNarrowed { reason: NarrowingReason }` (kind `root_access_narrowed`) per reason, through the publish paths (`Atomic` and `AtomicReplace`): `acl_unreadable`, `destination_changed`, `unmapped_id`, `ownership_differs`, `acl_copy_failed` (private root, also a copy that fails after the rename), `group_not_kept`, `foreign_write_dropped`, `owner_not_kept` (mode or owner narrowing, FR-105) and `destination_vanished` (`Atomic` only: on `AtomicReplace` a failed permission read rolls back instead); `NarrowingReason` is a closed `#[non_exhaustive]` enum with `as_str`, and the crate-private `Narrowed` carrier is `#[must_use]` and consumed only by `ExtractionReport::record_narrowing`, so a reason cannot be dropped silently; a test drives every other reason through both paths and `destination_vanished` through `Atomic` (hosts that cannot trigger a reason are named in the test) (#1063, #1067) | must |
| FR-113 | WHEN the destination exists, THE SYSTEM SHALL make the children created in the staging directory inherit as an in-place extraction into the destination would: on Linux and Android the destination's default ACL (`system.posix_acl_default`) is written onto the staging directory, on macOS the destination's entries that carry `file_inherit` or `directory_inherit` are written in their original order with `only_inherit` added, so the staging directory's own access is unchanged (an entry with `limit_inherit` alone is not inheritable); THE SYSTEM SHALL keep the staging directory private (`0700`, owner only) at every step, because the seeded entries cannot widen access to the directory itself, and SHALL probe the umask before the seed so the probe directory inherits nothing from the destination (FR-111); WHEN the destination is adopted, the published root takes the destination's own ACL in place of the seed (FR-110); WHEN the destination's inheritance is withheld, THE SYSTEM SHALL still take the destination's owner and group as far as the caller may, report `owner_not_kept` or `group_not_kept` where they are not kept, and publish the root `0700` with no ACL; WHEN the directory seeded from is not the one adopted (`destination_changed`), THE SYSTEM SHALL NOT claim that directory's owner or group; WHEN the destination is absent, THE SYSTEM SHALL give the children and the published root what `mkdir` of the destination in the parent would give (on macOS through the capture and re-seed of FR-111, on Linux through the parent's default ACL left on the stage) (#1067, #1078) | must |
| FR-107 | THE SYSTEM SHALL name the parent of a destination with an empty parent component as the current directory through one `parent_or_cwd`, shared by `Atomic` and `AtomicReplace`, so `extract a.tar out` with a relative fresh destination stages next to it (#1005) | must |
| FR-108 | A failure that leaves a staging directory behind (a discard that cannot remove it, a failed swap, a cancelled run) SHALL carry it as `StagingLeftover` through `ArchiveError::rolled_back_with(Option<StagingLeftover>)` (a leftover on a non-partial error such as `Cancelled`, `OutputExists` or `DestinationChanged` wraps it in `PartialExtraction` with `writes: RolledBack`, since nothing was published) and `Partial::leftover()`, and the front ends SHALL report it (CLI `error.leftover_path`, Python `leftover_path`, Node `leftoverPath`); this supersedes the note in FR-101 that a surviving staging directory is not reported (#995) | must |
| FR-109 | `DestinationState::probe(path)` SHALL classify a destination as `Fresh` (nothing at the final name, checked without following a symlink, and the parent directory exists) or `NotFresh` (anything at the final name including a dangling symlink, a missing parent, or an uninspectable path), so a front end may skip the conflict pre-check and extract atomically only for a `Fresh` destination; the CLI uses it when deciding whether `check_destination` is needed (#995, #1013, #1019) | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Security | The fd-pinning approach closes the *intermediate*-path-component TOCTOU window entirely (not merely narrows it) — once `PinnedDir::open` succeeds, no later filesystem change to an intermediate component can retarget any subsequent operation |
| NFR-002 | Security | The `(dev, ino)` identity recheck immediately before the destructive step narrows — it does not fully close — the much smaller remaining window around the *final* path component itself changing between the initial snapshot and the swap; this is a documented, accepted residual, not an oversight |
| NFR-003 | Compatibility | `rustix` is a direct dependency of `exarch-core` (`fs`, `alloc`) for the `*at` primitives; `exarch-cli` carries no swap code (#984) |
| NFR-004 | Scope | This hardening is scoped strictly to `--atomic --force`; it SHALL NOT change the symlinked-destination-root policy for plain `extract`, `--atomic` without `--force`, or the Rust/Python/Node APIs, which continue to resolve via `DestDir`/`canonicalize()` (audited and confirmed correct as-is, #533) |
| NFR-005 | Auditability | Every failure site in `staging::replace` captures directory identity via the same `VettedDir::status` mechanism, so disclosure behavior (FR-006/FR-007) is consistent across all failure paths, not ad hoc per call site |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `VettedDir` (`formats/pinned_dir.rs`) | A directory pinned by an open handle (Unix and WASI: file descriptor opened `O_DIRECTORY \| O_NOFOLLOW` with `O_PATH` or `O_SEARCH`; Windows: NT handle) | Every operation on entries inside it is `*at`- or handle-relative, not path-based |
| `EntryStatus` | Result of `VettedDir::status`, one no-follow call per name | `occupant` (`Occupant::Directory` is the only kind the swap replaces, `Symlink` is always refused), `reparse` (Windows), `identity` (`FileIdentity`), and on Unix the mode |
| `VettedDir::entry_path` | Best-effort current path of a directory entry, from a descriptor opened on the entry itself (`/proc/self/fd` on Linux and Android, `getpath` on macOS), `None` elsewhere | Used by `StagingDir::discard` to name a leftover (FR-006, FR-108) |
| `Leaf` / `LeafBuf` | Single-component names (FR-014) | `LeafBuf::random(prefix)` for staging and backup names |
| `StagingDir`, `Displaced` | Armed guards for the staging directory (FR-104) and the displaced destination (FR-015) | `discard` / `restore` consume the guard |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Destination is a symlink pointing at a directory | Rejected before any rename/removal (GHSA-x8wr-7ww2-c94x); the pointed-at directory's contents are untouched |
| Destination is a symlink pointing at a regular file | Rejected with the symlink-destination error, not the pre-existing "not a directory" error |
| An intermediate component of the destination's parent path is replaced with a symlink mid-extraction, then reverted before the swap's destructive step | Swap proceeds correctly regardless — the pinned fd is unaffected by the redirect either way; if cleanup ran during the redirect window, FR-006's disclosure applies |
| The destination entry's identity changes between the initial snapshot and the final destructive swap step (narrow residual window) | Swap aborts with a distinct identity-mismatch error rather than proceeding against a possibly-different entry (NFR-002) |
| `--atomic --force` invoked without search (execute) permission on the destination's parent directory | Fails — obtaining the pinned fd requires search permission, not read permission, even when the destination does not yet exist (FR-009) |
| Best-effort cleanup fails and the temp/backup directory's identity still matches at the pinned parent | Actual current path disclosed via a freshly opened fd (FR-006), not the possibly-stale logical path |
| `--atomic --force` extraction fails after some entries were written to the temp directory | The temp directory is discarded; the `PartialExtraction` error carries `writes: RolledBack`, so its report counts describe work no longer on disk |
| Best-effort cleanup succeeds (the ordinary, non-redirected case) | Identity recheck finds nothing; no directory is disclosed and none is left behind — this is deliberate, avoiding an earlier draft's regression of unconditionally persisting the temp directory on every failure |
| Content written directly into a redirect-created decoy directory, where the redirect reverts before the post-cleanup identity check runs | Not discoverable by this fix — `exarch-core`'s own per-entry extraction writes remain path-based (explicitly out of scope); documented as a genuine, undisclosed orphan, not a security escape |
| Windows | Destination-symlink/junction rejection (FR-001) applies; the swap is handle-relative with `FileIdInfo` identity (FR-099, FR-106); plain `--atomic` onto an existing empty directory fails with `OutputExists` because the rename cannot replace a directory there (#1005) |
| `--atomic` onto an existing empty directory, caller does not own it | Mode adopted, uid never, group and world write and setgid dropped (FR-105) |
| Publishing rename fails after the mode was adopted | The staging root is set `0700` before it is discarded; it carries no copied ACL, so it can be removed (FR-105, FR-110) |
| Destination has a POSIX ACL (Linux) and the root keeps its owner and group | Access and default ACL copied onto the root (FR-110) |
| Destination has an ACL that cannot be copied faithfully (root of another owner or group, unreadable ACL, undefined id, failed seed write) | Root stays `0700` and a `root_access_narrowed` warning names the reason (FR-110, FR-111, FR-112) |
| Destination has inheritable entries (Linux default ACL, macOS `file_inherit` or `directory_inherit`) | Staged children inherit them as in an in-place extraction, the stage stays `0700` during the run, and the root is the destination's ACL (FR-110, FR-113) |
| Destination is replaced by another directory between the seed and the adoption | Root stays `0700` with no ACL, its owner and group are not claimed, and a `destination_changed` warning names the reason (FR-111, FR-113) |
| Destination vanishes after the stage was seeded from it | Root published `0700` with no ACL and a `destination_vanished` warning; children made before keep what they inherited (FR-111) |
| Destination vanishes and there was nothing to seed | Root keeps the mode a new directory gets and a `destination_vanished` warning (FR-111) |
| Seeding the destination's inheritance fails | Stage ACL cleared again, owner and group still taken as far as the caller may (`owner_not_kept` or `group_not_kept` where not kept), root `0700` with no ACL and `acl_copy_failed` (FR-111, FR-113) |
| `--atomic` onto an absent destination whose parent has inheritable entries (macOS) | The parent's inherited list is captured, cleared and re-seeded as `only_inherit`: the stage is `0700` with no applicable entry during the run, children and root match a `mkdir`-made destination (FR-104, FR-111, FR-113) |
| `--atomic` onto an absent destination whose parent has an inheritable `deny delete` (macOS) | The run succeeds: the probe directory inherits nothing, no probe or stage is left behind (FR-111) |
| `--atomic` onto an absent destination on macOS whose stage inherited nothing (no parent ACL, FAT32, exFAT) | Nothing is cleared or seeded; the probe still runs and the root gets no ACL (FR-111) |
| `--atomic` onto an absent destination (Linux, other Unix) | Unchanged: the parent's default ACL stays on the stage, masked by the `0700` mode (FR-111) |
| Destination whose ACL denies deleting it (macOS, `deny delete`) | Published: the ACL is applied after the rename and the destination's list is kept (FR-110); `--atomic --force` still fails at the move-aside, because the destination itself denies delete (open non-goal F4) |
| Destination is filled by another process after staging started | `OutputExists`, no stage or `.exarch-*` left behind: the ACL was never put on the stage, so it is removable (FR-110) |
| Destination has a plain ACL on macOS | ACL copied through the pinned descriptor (FR-110) |
| macOS volume that reports `EINVAL` for the ACL read (FAT32, exFAT) | Treated as no ACL, no warning (FR-110) |
| ACL read or inherited-entry clearing fails before the rename | The run fails, nothing is published with a wider grant (FR-110, FR-111) |
| ACL write fails after the publishing rename | The run still succeeds and reports `acl_copy_failed`; the root is made `0700` with no ACL on a best-effort basis (FR-110, FR-112) |
| Staging directory cannot be removed after a failure | Error carries `leftover_path`; the destination is unchanged (FR-108) |
| Any archive extraction path other than `--atomic --force` (plain `extract`, `--atomic` alone, Rust/Python/Node API) | Entirely unaffected — continues to resolve a symlinked destination *root* via `DestDir`/`canonicalize()`, matching `tar -C`/`unzip -d` (confirmed correct by audit, #533) |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | GHSA-x8wr-7ww2-c94x reproduction | 0/N trials succeed in redirecting the swap via a symlinked destination, across repeated live-verification runs |
| SC-002 | Intermediate-path-component TOCTOU reproduction | 0/60 re-race trials succeed in redirecting the swap (live-verified, per project memory: `ci-118`) |
| SC-003 | Orphan disclosure | A live-reproduced persisting mid-extraction redirect resolves to the real, surviving content's actual path, not the decoy's |
| SC-004 | No regression to the ordinary (non-attacked) case | `--atomic --force` against a normal pre-existing directory destination succeeds and leaves no temp/backup directory behind |
| SC-005 | Non-Unix behavior unchanged apart from FR-001 | Windows/other non-Unix targets show no new rejections beyond the destination-symlink/junction case |

## 8. Agent Boundaries

### Always (without asking)
- Perform every rename/remove inside `staging::replace`'s swap relative to the pinned parent handle (`VettedDir`) — never reintroduce a path-based `rename`/`remove_dir_all` call for the swap's core steps
- Capture directory identity via `VettedDir::status` at every failure site that might need to disclose a surviving directory's location
- Preserve the FR-001 destination-symlink rejection on all platforms, including non-Unix

### Ask First
- Extending fd-relative resolution into `exarch-core`'s own per-entry extraction writes (currently explicitly out of scope; a larger undertaking with its own security review)
- Changing the read-permission requirement on the destination's parent directory (FR-009) — this is a deliberate, documented behavior change already shipped, not something to silently relax

### Never
- Resolve the swap's destructive rename/remove steps by re-walking a path after the initial pin — this is exactly the TOCTOU class this spec closes
- Silently discard a surviving temp/backup directory on cleanup failure without attempting the identity-based disclosure in FR-006/FR-007
- Weaken the destination-symlink rejection (FR-001) to accept a symlinked destination for `--atomic --force` under any circumstance — pass the resolved target path instead

## 9. Open Questions

Open non-goals of the ACL work (#1079, #1078), tracked as follow-up issues:

- F1 (#1082): a rollback cannot remove staged children that inherited a macOS `deny delete` entry, and the clear reopens the stage by name; clearing each entry's ACL descriptor-relative before the removal would make it complete, and it is more reachable now that an absent destination under such a parent extracts.
- Window on macOS between the staging `mkdir` and the clear of its inherited ACL (part of #1082): another user with write access to the parent could plant an entry there; it predates #1067 and the capture, clear and re-seed narrow it without closing it.
- F2 (#1083): a publish failure drops the extraction report's counts (`files_extracted: 0` with `writes: rolled_back`), unlike cancellation, which keeps them.
- F3 (#1084): an absent destination under a parent with an inheritable `deny list` still fails `--atomic` on macOS and leaves the stage, because clearing opens the stage for reading; the clear would have to run relative to the pinned parent.
- F4 (#1085): `--atomic --force` onto a destination the caller cannot delete is refused only at the move-aside after the whole extraction; an early `faccessat(_DELETE_OK)` check could refuse before extracting.

Otherwise none — this is a retrospective spec documenting shipped, merged behavior (#519, #524, #526,
#530, #531, #535, #536, #537). The upstream GitHub Security Advisory for GHSA-x8wr-7ww2-c94x
was in draft when this spec was written and has since been closed.

## 10. See Also

- [[constitution]] — project principles (Security section: `--atomic --force` swap policy)
- [[MOC-specs]] — all specifications
- [[001-security-pipeline/spec]] — `DestDir` and the unaffected symlinked-destination-*root* policy for non-`--atomic --force` paths
- [[005-cli/spec]] — `extract --atomic --force` CLI-level requirements and edge cases (FR-083–FR-085)
- `crates/exarch-core/src/staging/replace.rs` — the swap, `Displaced`
- `crates/exarch-core/src/formats/pinned_dir.rs` — `VettedDir`, `EntryStatus`, `Leaf`
- `crates/exarch-cli/src/commands/extract.rs` — `WriteMode`, `ExtractPlan`
- GHSA-x8wr-7ww2-c94x — the destination-symlink advisory this spec's FR-001/FR-002 close
- Issues/PRs #519, #524, #525, #526, #530, #531, #535, #536, #537
