---
tags:
  - sdd
  - spec
  - delta
created: 2026-11-22
status: open
related:
  - "[[spec]]"
  - "[[001-security-pipeline/spec]]"
---

# Delta: deferred mode under PermissionPolicy::Normalize (#1308)

> [!info] Scope
> Capability: `026-mark-of-the-web-propagation`. Related delta: `specs/001-security-pipeline/changes/extract-honors-permission-policy.md` (FR-059). Code: `formats/pinned_dir.rs` (`create_new_deferred`, `PendingMode::apply`).

## ADDED

(none)

## MODIFIED

### FR-007

Old: Under `WhenMarked` a file SHALL be created in deferred mode: created `0600`, content written, mark written, then the final mode applied through `PendingMode`; the final mode SHALL be applied even when the mark write fails, so a read-only entry (`0444`) is marked and ends `0444`.

New: Under `WhenMarked` a file SHALL be created in deferred mode, and the create call depends on the policy ([[001-security-pipeline/spec]] FR-059):

- `Preserve` (exact mode): created `0600`, content written, mark written, then the exact sanitized mode applied through `PendingMode` with `fchmod`.
- `Normalize` (umasked mode): created with the sanitized mode plus owner read and write (`mode | 0o600`), so the kernel applies the umask and execute and group bits are present from the create. Content and the mark are written first; `PendingMode` then takes back only the owner read and write bits the mode lacks, from the mode the kernel actually gave (`fstat` then `fchmod`), without reading the umask. Nothing is applied when the mode already has owner read and write.

In both cases the final mode SHALL be applied even when the mark write fails, so a read-only entry (`0444`) is marked and ends `0444` (`Preserve`) or `0444` minus the umask (`Normalize`). The final mode is always a subset of the sanitized mode, so the transient mode before the mark grants no access the final mode does not (#1308).

## REMOVED

(none)

## Deviations

(none)
