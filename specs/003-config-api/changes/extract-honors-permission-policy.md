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

# Delta: SecurityConfig::permissions applies to extraction (#1308)

## ADDED

(none)

## MODIFIED

### FR-061

Old: `PermissionPolicy {Normalize, Preserve}` SHALL replace the `preserve_permissions` bool field of `SecurityConfig` and `CreationConfig` (the bool builder `with_preserve_permissions` stays); `Preserve` still strips setuid and setgid.

New: the same, and `SecurityConfig::permissions` (CLI `extract --preserve-permissions`) governs extraction of regular files: `Normalize` gives the sanitized archive mode minus the umask, `Preserve` the sanitized archive mode exactly; `Preserve` still strips setuid, setgid and sticky bits, and world-writable bits unless allowed. Directory modes are not restored under either policy. Full rule: [[001-security-pipeline/spec]] FR-059 (#1308).

## REMOVED

(none)

## Deviations

(none)
