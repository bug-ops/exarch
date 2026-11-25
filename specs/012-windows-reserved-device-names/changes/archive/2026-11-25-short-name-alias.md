---
tags:
  - sdd
  - spec
  - delta
  - security
  - path-validation
  - windows
created: 2026-11-24
status: merged
related:
  - "[[spec]]"
  - "[[001-security-pipeline/spec]]"
---

# Delta: alternate 8.3 spellings of existing entries are refused

> [!info] Merged into `spec.md` at spec sync of the v0.11.0..main sync (#1364).

> [!info] Scope
> Capability: `012-windows-reserved-device-names` (Windows component rules). The check complements the name-based component rules of FR-001: those judge the spelling in the archive, this one judges the name of an entry that already exists on disk.

## ADDED

### FR-007

WHEN, on Windows, an existing directory component, an existing file leaf (including a file a 7z extraction overwrites) or an existing link-target component is named by an alternate 8.3 short-name spelling of another entry, THE SYSTEM SHALL refuse it with `Violation::ShortNameAlias`.

**Priority**: must

Behavior:

- The violation is a `SecurityViolation` with sub-code `PATH_NAME`; it is config-independent and not relaxable (no opt-out, unlike FR-003).
- A name is suspect only when it has the 8.3 shape (a stem of 1 to 6 characters, `~`, digits, and an optional extension of at most 3 characters). The decision compares the spelling with the names its parent directory lists: a suspect name that the parent does not list under that spelling is refused; a listed spelling is accepted.
- The check is listing-based and uses no `unsafe` code. Off Windows a name is its own stored name, so nothing is refused.
- Names the extraction run itself created are remembered by exact spelling so the parent is not listed again for them. The remembered set is bounded by total bytes (each name is charged its length plus a fixed per-entry overhead); past the bound nothing more is remembered and the parent is listed again, which is slower but equally strict.

### NFR-006 (Portability)

The listing step is Windows-only; the decision (`judge`) and the shape test are pure and platform-independent, so they are unit-tested on every host. Non-Windows behavior is unchanged (consistent with NFR-001).

## MODIFIED

### Edge cases table (section 6)

Add row: an existing entry named by an alternate 8.3 spelling, as a directory component, file leaf (including a 7z overwrite) or link-target component, on Windows: refused with `Violation::ShortNameAlias`; the same name is accepted when the parent lists it as spelled; no effect off Windows.

### Violation taxonomy

Old: the Windows component rules produce `ReservedDeviceName`, `TrailingDotOrSpace`, `StreamSeparator` and `UnsafeComponent`.

New: additionally `ShortNameAlias`, classed `PathName` like its siblings, with the text "path component is an alternate 8.3 spelling: {component}". It has no `relaxable_by` setting.

## REMOVED

(none)

## Deviations

- A refusal raised while resolving a link target through the link cursor surfaces as an unresolvable-link refusal, not as `ShortNameAlias`; a follow-up is planned to unify the reported violation.
- No check runs after a fresh file create: the name of a file the run has just created is the spelling the run used.
- The 7z pre-pass does not vet alias spellings; the check runs at extraction time. A follow-up is planned.
