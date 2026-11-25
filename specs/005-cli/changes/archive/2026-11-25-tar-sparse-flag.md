---
tags:
  - sdd
  - delta
  - formats/tar
created: 2026-11-25
status: merged
related:
  - "[[005-cli/spec]]"
  - "[[002-format-handlers/changes/archive/2026-11-25-tar-sparse-expand]]"
---

# Delta: CLI `--tar-sparse` flag (#1349)

> [!info] Merged into `spec.md` at spec sync of the v0.11.0..main sync (#1349, #1372). Renumbered at sync: FR-150 is FR-152 in `spec.md`, because FR-150 and FR-151 were taken.

> [!info] Scope
> Requirement id continues the table of [[005-cli/spec]] (last id FR-149). Core behaviour is [[002-format-handlers/spec]] FR-081 to FR-084. Spec sync applies the ADDED row and moves this file to `changes/archive/`.

## ADDED

### FR-150

`extract`, `list` and `verify` SHALL accept `--tar-sparse <refuse|expand>` (default `refuse`), mapped to `SecurityConfig::with_tar_sparse` ([[002-format-handlers/spec]] FR-081). The refusal hint for a GNU sparse entry (FR-133, group "sparse or unsupported construct") names the flag. There is no environment variable and no configuration key for it.

**Priority**: must
