---
tags:
  - sdd
  - spec
  - delta
created: 2026-11-22
status: open
related:
  - "[[spec]]"
---

# Delta: sanitizer clears the sticky bit (#1305)

> [!info] Scope
> Capability: `001-security-pipeline`. Related delta: `specs/002-format-handlers/changes/sevenz-mode-tar-volume-label-pax-mtime.md` (FR-078).

## ADDED

### Known limitation: verify and special bits outside TAR

`verify` judges the mode that `list` reports. For ZIP the `zip` crate clears 0o7000 in `unix_mode()`, and the 7z listing carries no mode, so `verify` sees no setuid, setgid or sticky bit in ZIP or 7z archives (a ZIP or 7z regular file stored `0o4755` or `0o1755` verifies as PASS). Extraction still sanitizes these bits. No behavior is promised for ZIP or 7z `verify`; a raw external-attribute read is out of scope.

## MODIFIED

### FR-009

Old: WHEN extracting files on Unix, THE SYSTEM SHALL strip setuid (0o4000) and setgid (0o2000) bits from all file permissions, and apply the sanitized mode via `fchmod` on the already-open file descriptor (`File::set_permissions`), never via a path-based `set_permissions()` call after `open()`.

New: WHEN extracting files on Unix, THE SYSTEM SHALL strip setuid (0o4000), setgid (0o2000) and sticky (0o1000) bits from the permissions of every regular file, for every format, so that TAR, ZIP and 7z extract the same stored bits to the same mode, and apply the sanitized mode via `fchmod` on the already-open file descriptor (`File::set_permissions`), never via a path-based `set_permissions()` call after `open()`. `sanitize_permissions` itself clears 0o1000. Directory modes are not restored by any format and are unchanged. WHEN `verify` meets a TAR regular file whose stored mode carries a sticky bit, THE SYSTEM SHALL report `InvalidPermissions`, as it already does for setuid and setgid; `verify` does not flag a sticky bit on a directory (`check_permissions` receives the entry kind; unchanged behavior), while setuid, setgid and world-writable bits on a directory are still flagged. A hardlink copy whose target carries a sticky bit gets a copy without it.

### Edge case: setuid/setgid bits on Unix

Old: Stripped silently via `fchmod` on the open descriptor; the mode in `ValidatedFile` is the sanitized value.

New: setuid, setgid and sticky bits on a regular file are stripped silently via `fchmod` on the open descriptor; the mode in `ValidatedFile` is the sanitized value.

## REMOVED

(none)

## Breaking

`verify` contract change: a TAR archive with a sticky bit on a regular file goes from PASS to a WARNING (`InvalidPermissions`), and `verify --strict` goes from exit code 0 to 3. The public `sanitize_permissions` also returns a different value for modes with 0o1000 set. Record under `Breaking` in CHANGELOG.md.

## Deviations

(none) The other tracks of the batch (#1302, #1295, #1304, #1303) change no specified behavior.
