---
tags:
  - sdd
  - spec
  - delta
created: 2026-11-23
status: merged
related:
  - "[[spec]]"
  - "[[015-atomic-force-destination-swap-hardening/spec]]"
---

# Delta: atomic extraction under an owner-restricting umask explains the umask and always removes the staging directory (#1339)

> [!info] Merged into `spec.md` at spec sync of the v0.11.0..main sync (#1339, #1347).

> [!info] Scope
> Capability: `003-config-api` (`Staging::Atomic`, `Staging::AtomicReplace`, FR-035, FR-036). Staging directory preparation stays as in FR-111 of [[015-atomic-force-destination-swap-hardening/spec]]. Unix only; other platforms have no umask to explain.

## ADDED

### FR-076

WHEN a staged extraction (`Atomic` or `AtomicReplace`) fails with `PermissionDenied` and the process umask leaves the directories the run creates without the owner's read, write or search access (the mode of a throwaway directory made inside the staging directory, probed after the failure, lacks any of `0700`), THE SYSTEM SHALL return the error `the process umask removed owner permissions from the directories it creates (they get mode NNNN); set a umask that keeps owner read, write, and execute access (for example `umask 077` or `umask 022`) and retry` instead of the bare `Permission denied`. WHEN the error is a `PartialExtraction`, the same replacement applies to its cause and the report and the writes are kept. Any other error, a `PermissionDenied` under a umask that keeps owner access, and a failed probe SHALL be returned unchanged. The directories an archive creates are not given owner access during the run: an archive with a subdirectory under such a umask fails with this error, while a flat archive extracts (the staging directory itself is restored to `0700`, FR-111 of [[015-atomic-force-destination-swap-hardening/spec]]) (#1339).

**Priority**: must

## MODIFIED

### FR-036

Old: WHEN atomic extraction fails, THE SYSTEM SHALL delete the temp dir before returning the error.

New: WHEN atomic extraction fails, THE SYSTEM SHALL delete the temp dir before returning the error, including when the failure is the umask refusal of FR-076 and the staged tree holds directories whose own mode withholds the owner's access. WHEN removal meets such a directory (`PermissionDenied` on open or list) that belongs to the effective user, THE SYSTEM SHALL give it the owner's read, write and search access (sticky and setgid bits kept) and retry once, through a descriptor checked against the identity just read, or by name with `SYMLINK_NOFOLLOW` and an identity recheck where no descriptor can be opened; a directory of another user, a non-directory and a swapped entry (identity changed) SHALL keep the first error and stay in place. The restoration applies to the removal of the run's own staging tree only, never to a destination or backup tree.

## REMOVED

(none)

## Edge cases

| Scenario | Expected Behavior |
|----------|-------------------|
| `umask 0177`, `0377`, `0677` or `0127` (owner search bit withheld), archive with a subdirectory, `--atomic` | Umask error (FR-076); no `.exarch-*` directory remains; destination absent |
| `umask 0277` or `0227`, same archive | Same umask error; staging discarded |
| `umask 0477`, same archive | Extraction succeeds (directories keep owner write and search, only read is withheld); staging is gone |
| Flat archive under any of the above umasks | Extraction succeeds |
| Staged tree holds a directory owned by another user that cannot be opened | Not restored; removal leaves it and reports the leftover as before |

## Deviations

(none) The issue allowed either creating directories with owner access during the run or the umask explanation; the explanation with unconditional cleanup was chosen.
