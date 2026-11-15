---
tags:
  - sdd
  - delta
created: 2026-11-15
status: merged
related:
  - "[[001-security-pipeline/spec]]"
---

# Delta: escaping-parent kind and Windows leaf deferral (#1230, #1232)

> [!info] Merged into `spec.md` at spec sync of the batch PR #1230.

## MODIFIED

### FR-057

Old: "... `Defer` ... is set only for the walker-backed contexts and the 7z host pre-pass (`HostPrePass`) on Unix and WASI ...; on Windows nothing changed (follow-up #1232); a nested entry under an escaping parent symlink keeps its error-kind difference, `SYMLINK_ESCAPE` for TAR and ZIP and `PATH_TRAVERSAL` for 7z through the Rust API and the bindings (follow-up #1230) (#1221)"

New: "... `Defer` ... is set for the walker-backed contexts and the 7z host pre-pass (`HostPrePass`) on every host, Windows included; on Windows a junction or directory symlink at the landing is classed as a symlink occupant, so `Refuse` gives `OUTPUT_EXISTS`, `Overwrite` gives `SECURITY_VIOLATION` / `EXISTING_SYMLINK` and `Skip` succeeds with nothing written outside the destination, the same rows as Unix; the 7z host keeps a symlink occupant on every host, so 7z `--force` on Windows now refuses a pre-existing symlink as TAR and ZIP do (#1232). Windows behavior is verified by CI only (`existing_symlink_kinds_windows.rs`, gated by `EXARCH_REQUIRE_PRIVILEGED_TESTS`); if CI shows a write-through or another kind, the change reverts to the gated deferral and the finding is recorded (#1221)"

## ADDED

### FR-058

WHEN an entry lands below an existing symlink that escapes the destination THE SYSTEM SHALL refuse it as `SYMLINK_ESCAPE` (`ArchiveError::SymlinkEscape { path: <parent prefix> }`) in every format (TAR, ZIP, 7z), on every host and through every front end, instead of `PATH_TRAVERSAL` in the 7z pre-pass and in the Windows resolved path. One private helper in `types/safe_path.rs` returns the escape error only when `first_blocking_ancestor` reports `ParentBlocker::Escape`; a file parent, a dangling parent or a failed probe keeps its old kind. The rule is error-only: no path is admitted that was refused before. It also reaches the public `SafePath::validate`, whose doc comment says so. The `verify` severity stays Critical (#1230).

**Priority**: must
