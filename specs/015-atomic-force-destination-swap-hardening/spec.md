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
status: implemented
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[001-security-pipeline/spec]]"
  - "[[005-cli/spec]]"
---

# Feature: Atomic-Force Destination Swap Hardening

> [!info] Metadata
> **Subsystem**: exarch-cli (`crates/exarch-cli/src/commands/extract.rs`, `commands/atomic_swap.rs`)
> **Priority**: P0 (security)
> **Origin**: GHSA-x8wr-7ww2-c94x (#525/#526), TOCTOU follow-up (#531), orphan-disclosure
> follow-up (#530), destination-identity pinning (#535), symlink-swap TOCTOU close (#536/#531)
> — v0.6.0, unreleased
> **Status**: implemented — this spec documents shipped behavior for `exarch extract
> --atomic --force`'s destination-swap hardening, a self-contained security fix large
> enough (five follow-on PRs) to warrant its own spec rather than a subsection of
> [[005-cli/spec]]

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
- Windows/non-Unix platforms: the fd-pinning mechanism is Unix-only (symlink creation is a
  privileged operation on Windows); non-Unix targets keep the previous path-based behavior
  for the swap itself, though the symlink-destination rejection (GHSA-x8wr) applies on all
  platforms via `statat(SYMLINK_NOFOLLOW)`-equivalent checks

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
| FR-007 | IF no fd-to-path facility is available (any Unix other than Linux/macOS), THE SYSTEM SHALL fall back to disclosing the `(dev, ino)` identity via a `find -inum`-style pointer instead of a path | should |
| FR-008 | ON non-Unix targets, THE SYSTEM SHALL keep the previous path-based swap behavior for the rename/remove steps themselves (documented residual, not a regression — symlink creation is a privileged operation on Windows), while still applying the destination-symlink/junction rejection from FR-001 on all platforms | must |
| FR-009 | Obtaining the pinned parent file descriptor SHALL require read permission on the destination's parent directory, for every `--atomic --force` invocation, including when the destination does not yet exist — this is a documented behavior change (there is no portable Unix equivalent of Linux's permission-free `O_PATH` for this purpose); it SHALL NOT require read permission on the destination directory itself | must |
| FR-010 | THE SYSTEM SHALL NOT pre-delete a pre-existing destination directory before extraction is known to succeed; `--atomic --force` SHALL extract into a temp directory first and perform the swap only after extraction fully succeeds, with a failed final rename restoring the backup and reporting its path if that restore itself fails (#519, precursor to the swap-hardening in this spec) | must |
| FR-011 | A pre-existing destination that exists but is not a directory (e.g. a regular file) SHALL be rejected with an explicit error, not silently replaced | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Security | The fd-pinning approach closes the *intermediate*-path-component TOCTOU window entirely (not merely narrows it) — once `PinnedDir::open` succeeds, no later filesystem change to an intermediate component can retarget any subsequent operation |
| NFR-002 | Security | The `(dev, ino)` identity recheck immediately before the destructive step narrows — it does not fully close — the much smaller remaining window around the *final* path component itself changing between the initial snapshot and the swap; this is a documented, accepted residual, not an oversight |
| NFR-003 | Compatibility | `rustix` is added as a direct, Unix-only dependency of `exarch-cli` (already present transitively via `tempfile`/`xattr`, so no new supply-chain surface) |
| NFR-004 | Scope | This hardening is scoped strictly to `--atomic --force`; it SHALL NOT change the symlinked-destination-root policy for plain `extract`, `--atomic` without `--force`, or the Rust/Python/Node APIs, which continue to resolve via `DestDir`/`canonicalize()` (audited and confirmed correct as-is, #533) |
| NFR-005 | Auditability | Every failure site in `run_atomic_force_extraction` captures directory identity via the same `PinnedDir::entry_status` mechanism, so disclosure behavior (FR-006/FR-007) is consistent across all failure paths, not ad hoc per call site |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `PinnedDir` (`commands::atomic_swap`, Unix only) | A directory pinned by an open file descriptor, opened once via `rustix::fs::open` with `O_DIRECTORY \| O_NOFOLLOW \| O_NONBLOCK \| O_CLOEXEC` | Wraps `std::fs::File`; every subsequent operation on entries inside it is `*at`-relative, not path-based |
| `DestEntryKind` | Classification result of `PinnedDir::entry_status` | `Directory` (the only kind `--atomic --force` may swap), `Symlink` (always rejected — GHSA-x8wr), `Other` (regular file, FIFO, etc.) |
| `PinnedDir::entry_status` | fd-relative `statat`-equivalent call returning both `DestEntryKind` and `(dev, ino)` identity in one syscall | Used both for the initial classification and the pre-swap identity recheck |
| `PinnedDir::open_entry` | Opens a file descriptor on a specific entry inside the pinned directory, for fresh-path resolution during disclosure (FR-006) | Used with `commands::atomic_swap::current_path` |
| `commands::atomic_swap::current_path` | Resolves an open file descriptor's current path via `/proc/self/fd` (Linux) or `rustix::fs::getpath` (macOS) | Falls back to a `(dev, ino)` pointer description on other Unix platforms |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Destination is a symlink pointing at a directory | Rejected before any rename/removal (GHSA-x8wr-7ww2-c94x); the pointed-at directory's contents are untouched |
| Destination is a symlink pointing at a regular file | Rejected with the symlink-destination error, not the pre-existing "not a directory" error |
| An intermediate component of the destination's parent path is replaced with a symlink mid-extraction, then reverted before the swap's destructive step | Swap proceeds correctly regardless — the pinned fd is unaffected by the redirect either way; if cleanup ran during the redirect window, FR-006's disclosure applies |
| The destination entry's identity changes between the initial snapshot and the final destructive swap step (narrow residual window) | Swap aborts with a distinct identity-mismatch error rather than proceeding against a possibly-different entry (NFR-002) |
| `--atomic --force` invoked without read permission on the destination's parent directory | Fails — obtaining the pinned fd requires read permission, even when the destination does not yet exist (FR-009, behavior change vs. pre-fix) |
| Best-effort cleanup fails and the temp/backup directory's identity still matches at the pinned parent | Actual current path disclosed via a freshly opened fd (FR-006), not the possibly-stale logical path |
| Best-effort cleanup succeeds (the ordinary, non-redirected case) | Identity recheck finds nothing; no directory is disclosed and none is left behind — this is deliberate, avoiding an earlier draft's regression of unconditionally persisting the temp directory on every failure |
| Content written directly into a redirect-created decoy directory, where the redirect reverts before the post-cleanup identity check runs | Not discoverable by this fix — `exarch-core`'s own per-entry extraction writes remain path-based (explicitly out of scope); documented as a genuine, undisclosed orphan, not a security escape |
| Non-Unix platform (e.g. Windows) | Destination-symlink/junction rejection (FR-001) still applies; the swap itself keeps the previous path-based behavior (documented residual, not a regression) |
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
- Perform every rename/remove inside `run_atomic_force_extraction`'s swap `*at`-relative to the pinned parent descriptor on Unix — never reintroduce a path-based `rename`/`remove_dir_all` call for the swap's core steps
- Capture directory identity via `PinnedDir::entry_status` at every failure site that might need to disclose a surviving directory's location
- Preserve the FR-001 destination-symlink rejection on all platforms, including non-Unix

### Ask First
- Extending fd-relative resolution into `exarch-core`'s own per-entry extraction writes (currently explicitly out of scope; a larger undertaking with its own security review)
- Changing the read-permission requirement on the destination's parent directory (FR-009) — this is a deliberate, documented behavior change already shipped, not something to silently relax

### Never
- Resolve the swap's destructive rename/remove steps by re-walking a path after the initial pin — this is exactly the TOCTOU class this spec closes
- Silently discard a surviving temp/backup directory on cleanup failure without attempting the identity-based disclosure in FR-006/FR-007
- Weaken the destination-symlink rejection (FR-001) to accept a symlinked destination for `--atomic --force` under any circumstance — pass the resolved target path instead

## 9. Open Questions

None — this is a retrospective spec documenting shipped, merged behavior (#519, #524, #526,
#530, #531, #535, #536, #537). The upstream GitHub Security Advisory for GHSA-x8wr-7ww2-c94x
remained in draft as of this spec's writing and needs a maintainer to publish/close it
(tracked outside this spec, per project memory).

## 10. See Also

- [[constitution]] — project principles (Security section: `--atomic --force` swap policy)
- [[MOC-specs]] — all specifications
- [[001-security-pipeline/spec]] — `DestDir` and the unaffected symlinked-destination-*root* policy for non-`--atomic --force` paths
- [[005-cli/spec]] — `extract --atomic --force` CLI-level requirements and edge cases (FR-083–FR-085)
- `crates/exarch-cli/src/commands/atomic_swap.rs` — `PinnedDir`, `DestEntryKind`, `current_path`
- `crates/exarch-cli/src/commands/extract.rs` — `run_atomic_force_extraction`
- GHSA-x8wr-7ww2-c94x — the destination-symlink advisory this spec's FR-001/FR-002 close
- Issues/PRs #519, #524, #525, #526, #530, #531, #535, #536, #537
