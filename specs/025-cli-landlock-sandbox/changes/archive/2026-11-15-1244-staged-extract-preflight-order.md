---
tags:
  - sdd
  - delta
created: 2026-11-15
status: merged
related:
  - "[[025-cli-landlock-sandbox/spec]]"
---

# Delta: Staged extract under the sandbox, preflight order (#1244, #1245)

## MODIFIED

### FR-003, FR-005, FR-006, FR-007, FR-010

Old: a missing destination is created before confinement and written in place (`PartialExtraction` on interruption); order `password::read`, destination creation, `confine`, `interrupt::install`; `require` fails before any archive access.

New: a TAR into a MISSING destination with an existing parent is staged through `StagingReservation` and confined to the stage plus `MAKE_DIR` and `REMOVE_DIR` on the parent (user-approved widening: the confined process can create directories, remove empty directories and rename directories within their own directory at any depth beneath the parent, and cannot create, write, truncate or remove files); an existing (even empty) destination, a missing parent, ZIP and 7z are written in place; the reservation is also made when the plan is `Skip`; there is no `Scope::ExtractStaged`. Order: password read, `preflight`, `interrupt::prepare`, one destination decision, reserve or create, `confine`, interrupt start, core call. Under `require` the only archive read before `confine` is the 512-byte signature probe, after an `Enforced` prediction; any non-`Enforced` status at `confine` fails with `SandboxNotEnforced`.

## ADDED

### Edge case: Ctrl-C between prepare and start

A SIGINT in that window is held and discarded; if `confine` then fails under `require` the exit is `SandboxNotEnforced`, not 130. An unstarted `PendingInterrupt` dropped restores the default signal behavior.

## REMOVED

### Deviation FR-007, US-001

The `PartialExtraction` row for a missing destination is removed; it is replaced by the approved-grant row.
