---
aliases:
  - Repeated Paths Tasks
tags:
  - sdd
  - tasks
  - extraction/duplicates
created: 2026-11-15
status: implemented
related:
  - "[[spec]]"
  - "[[plan]]"
---

# Implementation Tasks: Opt-in Refusal of Repeated Archive Paths

> [!info] References
> **Spec**: [[spec]]. **Plan**: [[plan]]. All tasks landed in the batch PR #1230.

## Progress

- [x] T001: `RepeatedPaths`, `Violation::RepeatedPath`, `PolicySetting`, drift tests, CLI flag, binding options ([[spec#FR-001]], [[spec#FR-003]], [[spec#FR-011]])
- [x] T002: `OccupantPolicy` and the `Full` record budget at the three setter sites ([[spec#FR-005]])
- [x] T003: tri-state `Maker` and the occupant decision at the six production sites ([[spec#FR-002]], [[spec#FR-004]])
- [x] T004: 7z pre-pass refusal and ZIP `RepeatedPath` under `Refuse` ([[spec#FR-006]], [[spec#FR-007]])
- [x] T005: `list` and `verify` agreement, `dispositions_match_extraction.rs` ([[spec#FR-008]])
- [x] T006: tests S07, S09, S10, S14, S15, S17, fail-closed causes, binding and CLI parity ([[spec#SC-001]] to [[spec#SC-005]])
- [x] T007: docs of the all-or-nothing recipe in every front end and the skill ([[spec#FR-009]])

## See Also

- [[spec]]
- [[plan]]
- [[MOC-specs]]
