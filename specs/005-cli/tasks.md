---
aliases:
  - CLI Tasks
tags:
  - sdd
  - tasks
  - cli
  - rust
created: 2026-05-20
status: draft
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

> [!warning] Scope
> The core CLI (all subcommands, JSON output, progress bar, exit codes) is
> fully implemented. Two `should`-priority requirements remain open:
>
> - FR-066: `completion` subcommand — the command exists and generates valid
>   scripts, but the `CompletionArgs` struct does not appear in the CLI help
>   text with full shell option descriptions and the `--json` flag is accepted
>   but has no effect on completion output (correct behaviour, but untested).
>   Issue #232 tracks adding a CLI integration test that exercises the
>   `completion` subcommand end-to-end.
>
> - FR-069: `--verbose` per-entry output — the `verbose` flag is parsed and
>   stored in `HumanFormatter`, but the only verbose-gated output is two extra
>   summary lines after extraction (symlink count and duration). Per-entry
>   details (path, size, type) during active extraction or creation are not
>   printed. Issue #233 tracks implementing the per-entry verbose path.

## Progress

- [ ] T001: Integration test for `completion` subcommand
- [ ] T002: Per-entry verbose output during extraction and creation

---

## Dependency Graph

```mermaid
graph TD
    T001[T001: completion integration test]
    T002[T002: per-entry verbose output]
```

---

### T001: Integration test for `completion` subcommand

**Context**: The `completion` command is implemented in
`crates/exarch-cli/src/commands/completion.rs` with a unit test that verifies
no panic occurs. There is no integration test confirming that the generated
script is non-empty, written to stdout, and produces no stderr output. FR-066
acceptance criteria require a verifiable completion script for each shell.
**Spec reference**: [[spec#FR-066]], [[spec#US-005]]
**GitHub issue**: #232
**Acceptance criteria**:
- [ ] Integration test runs `exarch completion bash` and asserts stdout is non-empty and contains the string `"exarch"`
- [ ] Same check for `zsh`, `fish`, and `powershell`
- [ ] Test asserts stderr is empty and exit code is 0
- [ ] Test for an unsupported shell name asserts exit code is non-zero
- [ ] Tests pass under `cargo nextest run -p exarch-cli` (or the workspace nextest invocation)
**Dependencies**: none
**Files**:
- `crates/exarch-cli/tests/` — new integration test file `completion.rs` or extend existing CLI tests
**Complexity**: low

---

### T002: Per-entry verbose output during extraction and creation

**Context**: FR-069 states: "WHEN `--verbose` is set, THE CLI SHALL print
per-entry details during extraction and creation." Currently `HumanFormatter`
gates only two extra lines on `self.verbose` (symlink count and duration in the
post-extraction summary). No per-entry output is emitted during the extraction
loop. The `ProgressCallback` path is the right place to hook verbose per-entry
logging so it interleaves with the progress bar correctly.
**Spec reference**: [[spec#FR-069]], [[spec#US-006]]
**GitHub issue**: #233
**Acceptance criteria**:
- [ ] When `--verbose` is active, each extracted entry path is printed to stderr during extraction (one line per entry)
- [ ] Each verbose line includes: entry type indicator (`f`/`d`/`l`), uncompressed size, and relative path
- [ ] Verbose lines go to stderr (not stdout), preserving `--json` stdout cleanliness
- [ ] Verbose lines do not appear when `--quiet` or `--json` is set
- [ ] During `create`, each added file path is printed to stderr when `--verbose` is set
- [ ] Integration test: run `exarch extract <archive> --verbose 2>verbose.log` and assert `verbose.log` contains all entry paths
- [ ] No changes to `ExtractionReport`, `CreationReport`, or `ProgressCallback` trait signatures
**Dependencies**: none
**Files**:
- `crates/exarch-cli/src/progress.rs` — `CliProgress` implementation; add per-entry callback
- `crates/exarch-cli/src/output/human.rs` — add `print_verbose_entry()` helper if needed
- `crates/exarch-cli/tests/` — integration test for verbose output
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
