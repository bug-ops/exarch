---
aliases:
  - CLI Spec
  - exarch CLI Spec
tags:
  - sdd
  - spec
  - cli
  - rust
created: 2026-05-20
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[003-config-api/spec]]"
  - "[[004-progress-tracking/spec]]"
---

# Feature: CLI

> [!info] Metadata
> **Subsystem**: exarch-cli
> **MSRV**: Rust 1.93.0
> **Source**: extracted from [[001-exarch-system/spec]]

## 1. Overview

### Problem Statement

Developers and operators need to extract, create, list, and verify archives
from the shell without installing a Python or Node.js runtime. The CLI must
expose the full security configuration of `exarch-core` through flags, display
human-readable progress during interactive use, and emit machine-readable JSON
for scripting.

### Goal

Provide a thin CLI wrapper (`exarch-cli`) around `exarch-core` that translates
command-line flags into `SecurityConfig`, `CreationConfig`, and `ExtractionOptions`,
delegates all logic to the core library, and presents output in either human-readable
or JSON format based on the `--json` flag.

### Out of Scope

- Interactive TUI or file picker
- Network archive sources (HTTP, S3, etc.)
- Archive repair or recovery commands
- GUI

## 2. User Stories

### US-001: CLI Extraction

AS A system administrator
I WANT to run `exarch extract archive.tar.gz /output` from the shell
SO THAT I can extract archives safely without installing Python or Node.js

**Acceptance criteria:**
```
GIVEN a valid archive and an output directory
WHEN I run `exarch extract archive.tar.gz /output`
THEN files are extracted, a progress bar is shown on stderr, and exit code is 0
```

```
GIVEN the --json flag
WHEN I run `exarch extract archive.tar.gz /output --json`
THEN stdout contains a JSON object with extraction statistics; no progress bar shown
```

### US-002: CLI Archive Creation

AS A developer
I WANT to run `exarch create output.tar.gz ./src` to produce an archive
SO THAT I can package files without a separate tool

**Acceptance criteria:**
```
GIVEN source paths and an output path with a recognized extension
WHEN I run `exarch create output.tar.gz ./src`
THEN an archive is produced and CreationReport is displayed
```

### US-003: Archive Listing

AS A security engineer
I WANT to run `exarch list archive.zip` to inspect contents without extracting
SO THAT I can review untrusted archives before use

**Acceptance criteria:**
```
GIVEN any supported archive
WHEN I run `exarch list archive.zip`
THEN entry paths, sizes, and types are printed; no files are written to disk
```

### US-004: Archive Verification

AS A security engineer
I WANT to run `exarch verify archive.tar.gz` to check for security issues
SO THAT I can pre-screen archives before extraction

**Acceptance criteria:**
```
GIVEN an archive containing a zip bomb entry
WHEN I run `exarch verify archive.tar.gz`
THEN VerificationReport.issues contains the ZipBomb issue with Critical severity; exit code is non-zero
```

### US-005: Shell Completion

AS A power user
I WANT shell completion scripts for bash, zsh, fish, and PowerShell
SO THAT I can tab-complete exarch commands and flags

**Acceptance criteria:**
```
GIVEN `exarch completion zsh`
WHEN run
THEN a valid zsh completion script is printed to stdout
```

### US-006: Machine-Readable Output

AS A script author
I WANT `--json` to emit structured JSON to stdout
SO THAT I can parse extraction results in a shell pipeline

**Acceptance criteria:**
```
GIVEN --json flag on any subcommand
WHEN the command succeeds
THEN stdout contains valid JSON with all report fields; stderr contains no progress bar
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-060 | THE CLI SHALL provide subcommands: `extract`, `create`, `list`, `verify`, `completion` | must |
| FR-061 | THE CLI SHALL support global flags: `--verbose`, `--quiet`, `--json` | must |
| FR-062 | WHEN `--json` is set, THE CLI SHALL output machine-readable JSON to stdout; human-readable text and progress output SHALL go to stderr | must |
| FR-063 | `extract` SHALL support: `--max-files N`, `--max-total-size SIZE` (K/M/G/T suffixes), `--max-file-size SIZE`, `--max-compression-ratio N`, `--allow-symlinks`, `--allow-hardlinks`, `--allow-solid-archives`, `--allow-world-writable`, `--preserve-permissions`, `--force`, `--atomic` | must |
| FR-064 | `create` SHALL support: `-l/--compression-level 1-9`, `--follow-symlinks`, `--include-hidden`, `-x/--exclude PATTERN` (repeatable glob), `--strip-prefix PREFIX`, `-f/--force` | must |
| FR-065 | `list` and `verify` SHALL support: `-l/--long`, `-H/--human-readable`, `--max-files N`, `--max-total-size SIZE`, `--allow-solid-archives` | must |
| FR-066 | `completion <SHELL>` SHALL generate shell completion scripts for bash, zsh, fish, powershell, and elvish; output goes to stdout for piping into the appropriate completions directory | must |
| FR-067 | WHEN extraction or creation fails, THE CLI SHALL exit with a non-zero exit code and print the error to stderr | must |
| FR-068 | WHEN `--quiet` is set, THE CLI SHALL suppress progress bars and informational output; only errors go to stderr | must |
| FR-069 | WHEN `--verbose` is set, THE CLI SHALL print one line per extracted entry to stderr including entry type indicator (`f`/`d`/`l`), uncompressed size, and relative path; `--quiet` takes precedence when both are set | must |
| FR-070 | THE CLI progress bar SHALL use `indicatif` in human mode and be suppressed in `--json` and `--quiet` modes | must |
| FR-071 | Human-readable output SHALL use SI suffixes (K, M, G) for byte counts when `-H/--human-readable` is set | should |
| FR-072 | WHEN `--allow-symlinks` is already active and a symlink escape is blocked, THE CLI SHALL NOT emit the `--allow-symlinks` hint; the hint is only relevant when symlinks are not yet enabled | must |
| FR-073 | WHEN `--json` is used, the JSON `message` field for `PartialExtraction`, `PathTraversal`, `SymlinkEscape`, `HardlinkEscape`, `QuotaExceeded`, and `ZipBomb` errors SHALL NOT repeat inner error text that already appears in the structured fields | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Observability | Progress bar uses `indicatif`; suppressed in `--json` and `--quiet` modes |
| NFR-002 | Usability | All flags have short aliases where unambiguous |
| NFR-003 | Correctness | Exit code 0 on success; non-zero on any error |
| NFR-004 | Correctness | JSON output is always valid JSON; never interleaved with progress output |
| NFR-005 | Maintainability | CLI is a thin adapter — no security logic; all logic delegated to `exarch-core` |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `Cli` | Root clap struct | Global flags (`--verbose`, `--quiet`, `--json`), `Commands` enum |
| `Commands` | Enum of subcommands | `Extract(ExtractArgs)`, `Create(CreateArgs)`, `List(ListArgs)`, `Verify(VerifyArgs)`, `Completion(CompletionArgs)` |
| `ExtractArgs` | Arguments for `extract` subcommand | `archive`, `output_dir`, security overrides, `--force`, `--atomic` |
| `CreateArgs` | Arguments for `create` subcommand | `output`, `sources`, creation options |
| `ListArgs` | Arguments for `list` subcommand | `archive`, display options |
| `VerifyArgs` | Arguments for `verify` subcommand | `archive`, inspection options |
| `OutputFormatter` | Trait for human vs JSON output | Methods: `print_extraction_report`, `print_creation_report`, `print_manifest`, `print_verification_report` |

### CLI Command Syntax

```
exarch [--verbose] [--quiet] [--json] <COMMAND>

exarch extract <ARCHIVE> [OUTPUT_DIR]
    [--max-files N] [--max-total-size SIZE] [--max-file-size SIZE]
    [--max-compression-ratio N] [--allow-symlinks] [--allow-hardlinks]
    [--allow-solid-archives] [--allow-world-writable]
    [--preserve-permissions] [--force] [--atomic]

exarch create <OUTPUT> <SOURCE>...
    [-l/--compression-level 1-9] [--follow-symlinks] [--include-hidden]
    [-x/--exclude PATTERN]... [--strip-prefix PREFIX] [-f/--force]

exarch list <ARCHIVE>
    [-l/--long] [-H/--human-readable]
    [--max-files N] [--max-total-size SIZE] [--allow-solid-archives]

exarch verify <ARCHIVE>
    [--max-files N] [--max-total-size SIZE] [--allow-solid-archives]

exarch completion <SHELL>    # bash | zsh | fish | powershell | elvish  (output to stdout)
```

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Archive does not exist | Error printed to stderr; exit code non-zero |
| Output directory does not exist | Created automatically (unless `--force` is required) |
| Extraction fails (security violation) | Error with variant name printed to stderr; exit code non-zero |
| `--json` and `--quiet` combined | JSON on stdout; nothing on stderr |
| SIZE suffix parsing (e.g. `--max-total-size 500M`) | K=1024, M=1024², G=1024³, T=1024⁴ |
| `completion` for unsupported shell | Error; exit code non-zero |
| `verify` on archive with issues | Issues printed; exit code non-zero when status is Fail |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | All subcommands produce correct output in human mode | Manual and integration tests |
| SC-002 | `--json` output is valid JSON parseable by `jq` | Integration test with JSON schema validation |
| SC-003 | Progress bar suppressed with `--json` and `--quiet` | Integration test checking stderr |
| SC-004 | Exit code non-zero on all error paths | Test matrix covering each `ArchiveError` variant |

## 8. Agent Boundaries

### Always (without asking)
- Direct all security and archive logic to `exarch-core`; never reimplement in CLI
- Print errors to stderr; JSON reports to stdout
- Suppress progress bar when `--json` or `--quiet` is set
- Use `clap` derive macros for argument parsing

### Ask First
- Adding a new subcommand (may require changes to `exarch-core` API)
- Changing exit code conventions
- Changing the JSON schema for any report type

### Never
- Implement security logic in `exarch-cli`
- Print progress to stdout (even in human mode)
- Silently ignore extraction errors

## 9. Open Questions

- [NEEDS CLARIFICATION: Should `exarch verify` have a `--check-integrity` flag to trigger CRC-32 validation for ZIP, distinct from security checks?]
- [NEEDS CLARIFICATION: Should `exarch extract` default to the current directory when no `OUTPUT_DIR` is given, or require it explicitly?]

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[003-config-api/spec]] — config types translated from CLI flags
- [[004-progress-tracking/spec]] — indicatif-based `ProgressCallback` used by CLI
- [[001-exarch-system/spec]] — original monolithic spec (archived)
