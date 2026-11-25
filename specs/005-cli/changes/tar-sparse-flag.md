---
tags:
  - sdd
  - delta
  - formats/tar
created: 2026-11-25
status: open
related:
  - "[[005-cli/spec]]"
  - "[[002-format-handlers/changes/tar-sparse-expand]]"
---

# Delta: CLI `--tar-sparse` flag (#1349)

> [!info] Scope
> Requirement id continues the table of [[005-cli/spec]] (last id FR-149). Core behaviour is [[002-format-handlers/spec]] FR-081 to FR-084. Spec sync applies the ADDED row and moves this file to `changes/archive/`.

## ADDED

### FR-150

`extract`, `list` and `verify` SHALL accept `--tar-sparse <refuse|expand>` (default `refuse`), mapped to `SecurityConfig::with_tar_sparse` ([[002-format-handlers/spec]] FR-081). The refusal hint for a GNU sparse entry (FR-133, group "sparse or unsupported construct") names the flag. There is no environment variable and no configuration key for it.

**Priority**: must
