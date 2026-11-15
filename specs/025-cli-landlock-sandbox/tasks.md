---
aliases:
  - CLI Landlock Sandbox Tasks
tags:
  - sdd
  - tasks
  - sandbox
created: 2026-11-15
status: implemented
related:
  - "[[spec]]"
  - "[[plan]]"
---

# Implementation Tasks: CLI Landlock Sandbox

> [!info] References
> **Spec**: [[spec]]. **Plan**: [[plan]]. All tasks landed in the batch PR #1230. The Linux backend has not run on a Linux host yet: the Ubuntu CI job with `EXARCH_REQUIRE_LANDLOCK=1` is the first execution.

## Progress

- [x] T001: `--sandbox` flag, `SandboxMode`, `SandboxStatus` and the stub seam ([[spec#FR-012]], [[spec#FR-016]])
- [x] T002: Landlock backend, grant set, ABI negotiation, TSYNC best effort ([[spec#FR-003]], [[spec#FR-005]], [[spec#FR-008]], [[spec#FR-009]])
- [x] T003: startup order after `password::read` and before `interrupt::install`, destination pre-creation ([[spec#FR-006]], [[spec#FR-007]])
- [x] T004: `sandbox` JSON key, human line, typed `SandboxNotEnforced` ([[spec#FR-013]], [[spec#FR-014]])
- [x] T005: probe hook and `tests/sandbox.rs`, CI env `EXARCH_REQUIRE_LANDLOCK=1` ([[spec#NFR-007]])
- [x] T006: docs and the CLI skill ([[spec#FR-017]])

## See Also

- [[spec]]
- [[plan]]
- [[MOC-specs]]
