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

# Delta: list reports special mode bits for ZIP and 7z (#1307)

## ADDED

(none)

## MODIFIED

### FR-017

Old: `InvalidPermissions` (Medium, mode changed by `sanitize_permissions`; a link entry's recorded mode is not checked because extraction never applies it).

New: the same, judged identically for TAR, ZIP and 7z. `ArchiveEntry.mode` for ZIP is the raw `external_attributes >> 16` for every host system except DOS, and for 7z the attribute mode when the Unix flag (0x8000) is set, so setuid, setgid and sticky are visible to `verify` (WARNING, exit 3 under `--strict`). Directory modes are not judged. Full rule: [[001-security-pipeline/spec]] FR-060 (#1307).

## REMOVED

(none)

## Deviations

(none)
