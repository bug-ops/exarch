---
aliases:
  - CLI Tasks
tags:
  - sdd
  - tasks
  - cli
  - rust
created: 2026-05-20
status: done
related:
  - "[[spec]]"
  - "[[001-exarch-system/plan]]"
  - "[[constitution]]"
---

# Implementation Tasks: CLI

> [!info] References
> **Spec**: [[spec]]
> **Plan**: [[001-exarch-system/plan]]
> **Total tasks**: 2

> [!note] Completed in v0.4.0
> Both open CLI tasks were resolved in v0.4.0:
>
> - **T001 (FR-066 / #232)**: `exarch completion <shell>` is fully implemented
>   and tested for bash, zsh, fish, powershell, and elvish. Output goes to
>   stdout for piping. Integration test added.
>
> - **T002 (FR-069 / #233)**: `--verbose` now prints one line per extracted
>   entry to stderr including entry type (`f`/`d`/`l`), uncompressed size, and
>   relative path. `--quiet` takes precedence when both flags are set. Verbose
>   lines do not appear in `--json` mode.

## Progress

- [x] T001: Integration test for `completion` subcommand
- [x] T002: Per-entry verbose output during extraction and creation

---

## Dependency Graph

```mermaid
graph TD
    T001[T001: completion integration test]
    T002[T002: per-entry verbose output]
```

---

### T001: Integration test for `completion` subcommand (done)

**Context**: `exarch completion <shell>` generates completion scripts for bash,
zsh, fish, powershell, and elvish. Output goes to stdout. Integration tests
verify non-empty output containing `"exarch"` and zero stderr for each shell.
**Spec reference**: [[spec#FR-066]], [[spec#US-005]]
**GitHub issue**: #232 (closed in v0.4.0)
**Acceptance criteria**:
- [x] Integration test runs `exarch completion bash` and asserts stdout is non-empty and contains the string `"exarch"`
- [x] Same check for `zsh`, `fish`, `powershell`, and `elvish`
- [x] Test asserts stderr is empty and exit code is 0
- [x] Test for an unsupported shell name asserts exit code is non-zero
- [x] Tests pass under `cargo nextest run -p exarch-cli`
**Dependencies**: none
**Files**:
- `crates/exarch-cli/tests/` — `completion.rs` integration test
**Complexity**: low

---

### T002: Per-entry verbose output during extraction and creation (done)

**Context**: `--verbose` now prints one line per extracted entry to stderr.
Each line includes the entry type indicator (`f`/`d`/`l`), uncompressed size,
and relative path. `--quiet` takes precedence. Verbose output is suppressed
in `--json` mode.
**Spec reference**: [[spec#FR-069]], [[spec#US-006]]
**GitHub issue**: #233 (closed in v0.4.0)
**Acceptance criteria**:
- [x] When `--verbose` is active, each extracted entry path is printed to stderr during extraction (one line per entry)
- [x] Each verbose line includes: entry type indicator (`f`/`d`/`l`), uncompressed size, and relative path
- [x] Verbose lines go to stderr (not stdout), preserving `--json` stdout cleanliness
- [x] Verbose lines do not appear when `--quiet` or `--json` is set
- [x] During `create`, each added file path is printed to stderr when `--verbose` is set
- [x] Integration test verifies verbose log contains all entry paths
- [x] No changes to `ExtractionReport`, `CreationReport`, or `ProgressCallback` trait signatures
**Dependencies**: none
**Files**:
- `crates/exarch-cli/src/progress.rs` — `CliProgress` per-entry verbose callback
- `crates/exarch-cli/src/output/human.rs` — `print_verbose_entry()` helper
- `crates/exarch-cli/tests/` — verbose output integration test
**Complexity**: medium

---

## Implementation Notes

### Order of execution

T001 and T002 are independent; both can be worked in parallel or in any order.
T001 is a pure test addition (low risk). T002 touches the progress path and
should be reviewed carefully to ensure verbose lines are not interleaved with
the indicatif progress bar in a way that corrupts terminal output — use
`indicatif::ProgressBar::println()` to print above the bar.

### Common patterns

- For T002, look at `crates/exarch-cli/src/progress.rs` (`CliProgress`) for
  how `ProgressCallback` is currently used. Verbose per-entry output should be
  emitted inside the `on_entry` callback (or equivalent), not inside the
  formatter methods which are called only after the operation completes.
- For T001, look at existing integration test patterns in the workspace.
  `assert_cmd` crate is likely already available; check `Cargo.toml`
  `[dev-dependencies]`.

### Gotchas

- T002: `indicatif::ProgressBar::println()` writes a line above the active
  progress bar without corrupting it. Do NOT use `eprintln!` directly while the
  bar is active.
- T002: When `--json` is set, the formatter is `JsonFormatter` which receives
  no verbose flag — verbose output must be suppressed at the `CliProgress` level
  by checking the verbose flag, not inside the formatter.
- T001: `clap_complete` output format varies between shells. Assert non-empty
  and the program name presence rather than exact content.

## See Also

- [[spec]] — feature specification
- [[001-exarch-system/plan]] — technical plan
- [[MOC-specs]] — all specifications
