---
tags:
  - sdd
  - spec
  - delta
created: 2026-11-22
status: merged
related:
  - "[[spec]]"
  - "[[003-config-api/spec]]"
---

# Delta: extraction honors PermissionPolicy (#1308)

> [!info] Merged into `spec.md` at spec sync of the v0.11.0..main sync (#1308, #1312). Renumbered at sync: FR-059 is FR-060 in `spec.md`, because FR-059 holds the banned-component rule of #1348.

> [!info] Scope
> Capability: `001-security-pipeline`. Decided by the user. Related deltas: `sanitizer-clears-sticky-bit` (same directory), `specs/003-config-api/changes/extract-honors-permission-policy.md`. Requirement ids continue the table of [[spec]] (last id FR-058; FR-060 is in the sticky-bit delta).

## ADDED

### FR-059

WHEN extracting a regular file on Unix, THE SYSTEM SHALL decide its mode from `SecurityConfig::permissions` (`--preserve-permissions` on the CLI), after sanitization:

- `PermissionPolicy::Normalize` (default): the file gets the sanitized archive mode minus the process umask. The sanitized mode goes into the create call so the kernel applies the umask; the process never reads the umask. Execute bits are kept. Only the owner read and write bits the mode lacks (for example `0o000`, `0o444`) are taken back after the create, from the mode the kernel actually gave, via `fchmod` on the open descriptor. A file with no recorded mode (7z without the Unix flag, ZIP from DOS) gets `0666` minus the umask.
- `PermissionPolicy::Preserve`: the sanitized archive mode exactly, applied via `fchmod` on the open descriptor, no umask.
- Sanitization (setuid, setgid, sticky, world-writable unless `allowed.world_writable`) applies under both policies.
- Directory modes are never restored under either policy.
- The in-memory sink and the callback sink report the sanitized mode under both policies (no umask).
- The rule is the same for TAR, ZIP, 7z, the host target, and `--atomic` / `--force` replacement (the temporary sibling carries the mode before the rename). A hardlink copy takes the on-disk mode of its target, unchanged.

**Priority**: must

### Edge cases (section 6 rows)

| Scenario | Expected Behavior |
|----------|-------------------|
| Regular file stored `0o755`, default config, umask `022` | Extracted `0755` (FR-059, #1308) |
| Regular file stored `0o4755`, default config, umask `022` | Extracted `0755`, setuid stripped (FR-059) |
| Regular file stored `0o000` or `0o444`, `Normalize` | Owner read and write restored by `fchmod`; the other bits follow the umask (FR-059) |
| Regular file stored `0o640`, `Preserve`, umask `077` | Extracted `0640`, umask not applied (FR-059) |
| `extract --force` over a `0600` file, default config | Replacement carries the archive mode minus umask (FR-059) |

## MODIFIED

### FR-009

See the `sanitizer-clears-sticky-bit` delta; the mode that results is policy-dependent per FR-059. No further change.

## REMOVED

(none)

## Breaking

Default `extract` now applies the archive mode minus the umask to regular files. Before, the recorded mode was ignored under `Normalize` or applied without regard to the policy. Record under `Breaking` in CHANGELOG.md.

## Deviations

(none)
