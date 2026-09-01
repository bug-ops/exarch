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
updated: 2026-09-02
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[003-config-api/spec]]"
  - "[[004-progress-tracking/spec]]"
  - "[[015-atomic-force-destination-swap-hardening/spec]]"
---

# Feature: CLI

> [!info] Metadata
> **Subsystem**: exarch-cli
> **MSRV**: Rust 1.98.0
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
| FR-063 | `extract` SHALL support: `--max-files N`, `--max-total-size SIZE` (K/M/G/T suffixes), `--max-file-size SIZE`, `--max-compression-ratio N`, `--allow-symlinks`, `--allow-hardlinks`, `--allow-solid-archives`, `--allow-world-writable`, `--preserve-permissions`, `--force`, `--atomic`, `--max-path-depth N` (default 32), `--banned-component COMPONENT` (repeatable; replaces the default ban list when provided), `--allow-absolute-paths` (flag; also applies to the listing pre-pass) | must |
| FR-064 | `create` SHALL support: `-l/--compression-level 1-9`, `--follow-symlinks`, `--include-hidden`, `-x/--exclude PATTERN` (repeatable glob), `--strip-prefix PREFIX`, `-f/--force`, `--max-file-size SIZE` (K/M/G/T suffixes; skips source files larger than threshold), `--preserve-permissions BOOL` (default true; pass `--preserve-permissions=false` for portable archive without Unix permission bits) | must |
| FR-065 | `list` and `verify` SHALL support: `-l/--long`, `-H/--human-readable`, `--max-files N`, `--max-total-size SIZE`, `--allow-solid-archives`, `--allow-absolute-paths` | must |
| FR-066 | `completion <SHELL>` SHALL generate shell completion scripts for bash, zsh, fish, powershell, and elvish; output goes to stdout for piping into the appropriate completions directory | must |
| FR-067 | WHEN extraction or creation fails, THE CLI SHALL exit with a non-zero exit code and print the error to stderr | must |
| FR-068 | WHEN `--quiet` is set, THE CLI SHALL suppress progress bars and informational output; only errors go to stderr; `--quiet` SHALL NOT suppress `--json` output — `--json` always emits to stdout regardless of `--quiet` | must |
| FR-069 | WHEN `--verbose` is set, THE CLI SHALL print one line per extracted entry to stderr including entry type indicator (`f`/`d`/`l`), uncompressed size, and relative path; `--quiet` takes precedence when both are set | must |
| FR-070 | THE CLI progress bar SHALL use `indicatif` in human mode and be suppressed in `--json` and `--quiet` modes | must |
| FR-071 | Human-readable output SHALL use SI suffixes (K, M, G) for byte counts when `-H/--human-readable` is set | should |
| FR-072 | WHEN `--allow-symlinks` is already active and a symlink escape is blocked, THE CLI SHALL NOT emit the `--allow-symlinks` hint; the hint is only relevant when symlinks are not yet enabled | must |
| FR-073 | WHEN `--json` is used, the JSON `message` field for `PartialExtraction`, `PathTraversal`, `SymlinkEscape`, `HardlinkEscape`, `QuotaExceeded`, and `ZipBomb` errors SHALL NOT repeat inner error text that already appears in the structured fields | must |
| FR-074 | `verify` SHALL support `--strict` flag: when set, a `VerificationReport` with `Warning` status causes the process to exit with code 2 instead of 0; without the flag, exit 0 on warnings is unchanged | must |
| FR-075 | WHEN `list -l` or `list --json -l` is run and an entry is a symlink or hardlink, THE CLI SHALL include the target path in the output; text format: `l755  0  link.txt -> target.txt`; JSON format: `symlink_target` and `hardlink_target` fields populated | must |
| FR-076 | `OutputFormatter`'s trait methods SHALL take `&mut self` and write through an injectable `Write` destination (`HumanFormatter<O: Write = Term, E: Write = Term>`, `JsonFormatter<W: Write = Stdout>`) rather than writing directly to a hardcoded `Term`/`Stdout`, so formatter output can be captured in unit tests without a subprocess (v0.6.0, #452) | must |
| FR-077 | `extract`'s human and `--json` output SHALL surface `ExtractionReport.warnings` and `files_skipped` on both the success path and the error path (`PartialExtraction`), not silently drop them (v0.6.0, #498, #503) | must |
| FR-078 | WHEN the `SecurityViolation` HINT is shown, THE CLI SHALL only suggest a policy flag (`--allow-symlinks`, `--allow-hardlinks`, `--allow-solid-archives`, `--banned-component`) for violation reasons those flags actually relax; every other `SecurityViolation` (e.g. the GHSA-5j8q-wxg5-hj4r size-mismatch case, password-protected archives, unsupported compression) SHALL get a HINT stating it cannot be relaxed via any policy flag (v0.6.0, #520) | must |
| FR-079 | WHEN a `PartialExtraction`-wrapped error is rendered, THE CLI SHALL preserve the wrapped error's category-specific HINT text (e.g. `--allow-symlinks`, or the "cannot be relaxed" wording) rather than replacing it with `PartialExtractionContext`'s generic HINT (v0.6.0, #527) | must |
| FR-080 | `extract`'s pre-flight destination-conflict error SHALL sort and cap the listed conflicting paths at 10, collapsing the remainder into a single `... and N more` summary line, instead of listing every conflict unbounded (v0.6.0, #500) | must |
| FR-081 | Human-readable byte sizes >= 1 TB SHALL render with a `TB` suffix, not an inflated `GB` figure; `HumanFormatter::format_size` and `progress::humanize_bytes` SHALL share one implementation (`output::humanize_bytes`) with a TB-inclusive ladder (v0.6.0, #451) | must |
| FR-082 | `extract`, `list`, and `verify` SHALL apply `--max-total-size`/`--max-file-size` overrides only when provided, otherwise leaving `SecurityConfig::default()`'s own limits in place, via a single shared `commands::apply_size_limits` helper instead of each command re-literalizing the defaults (v0.6.0, #450) | must |
| FR-083 | WHEN `extract --atomic --force` is used and the destination already exists as a directory, THE CLI SHALL extract into a temp directory beside the destination first and only swap it into place — renaming the existing destination aside to a backup path, renaming the extracted content into place, then removing the backup — after extraction fully succeeds; a failed final rename SHALL restore the backup and report its path if that restore itself fails. A pre-existing destination that is not a directory SHALL be rejected explicitly, not silently replaced (v0.6.0, #519) | must |
| FR-084 | `extract --atomic --force` SHALL reject a destination that is itself a symlink (or, on Windows, a junction/reparse point) on all platforms, and SHALL perform every rename/remove in its destination swap `*at`-relative to a file descriptor pinned on the destination's parent directory (Unix only), never by re-resolving a logical path mid-extraction. This is scoped to `--atomic --force` only — see [[015-atomic-force-destination-swap-hardening/spec]] for the full GHSA-x8wr-7ww2-c94x fix | must |
| FR-085 | WHEN `extract --atomic --force`'s best-effort cleanup on failure cannot locate its temp/backup directory at the expected logical path (e.g. because an intermediate path component was redirected mid-extraction), THE CLI SHALL disclose the directory's actual current path (resolved via an open file descriptor, not the possibly-stale logical path) in its error output rather than leaving surviving content undisclosed (v0.6.0, #530) | should |
| FR-086 | `verify`/`list` SHALL flag a TAR entry whose path is not valid UTF-8 as a `Medium`-severity `SuspiciousPath` `VerificationIssue` (portability risk, not a security issue — `security_status` is unaffected), flipping `status` to `Warning` instead of reporting `Pass` for an entry that may fail to extract on filesystems requiring UTF-8 names (v0.6.0, #528) | should |
| FR-087 | `--verbose` and `--quiet` SHALL be resolved once into a single `output::Verbosity` (`Quiet` \| `Normal` \| `Verbose`) via `impl From<&cli::Cli> for Verbosity`, and threaded through `output::create_formatter`, `HumanFormatter::new`/`with_writers`, `commands::extract::execute`, and `commands::create::execute`, rather than each site independently interpreting the two raw booleans; `Verbosity::from_flags` SHALL resolve `verbose: true, quiet: true` to `Quiet` in every case, including when the two flags are parsed at different `clap` `ArgMatches` levels (e.g. a global `--verbose` combined with a subcommand-level `--quiet`), which `clap`'s `conflicts_with` on `--quiet` does not reject (unreleased, post-v0.6.0, #550, behavior change — see Edge Cases) | must |

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
| `ExtractArgs` | Arguments for `extract` subcommand | `archive`, `output_dir`, security overrides, `--force`, `--atomic`, `--max-path-depth`, `--banned-component`, `--allow-absolute-paths` |
| `CreateArgs` | Arguments for `create` subcommand | `output`, `sources`, creation options, `--max-file-size`, `--preserve-permissions` |
| `ListArgs` | Arguments for `list` subcommand | `archive`, display options |
| `VerifyArgs` | Arguments for `verify` subcommand | `archive`, inspection options |
| `OutputFormatter` | Trait for human vs JSON output; methods take `&mut self` since v0.6.0 (#452) | Methods: `format_extraction_result`, `format_creation_result`, `format_manifest_short`, `format_manifest_long`, `format_verification_report` |
| `HumanFormatter<O: Write = Term, E: Write = Term>` | Human-readable formatter; writes non-error output to `O`, errors to `E` (v0.6.0) | `HumanFormatter::new()` (stdout/stderr default), `HumanFormatter::with_writers()` (injects custom writers + `use_colors` for deterministic tests) |
| `JsonFormatter<W: Write = Stdout>` | JSON formatter (v0.6.0) | `JsonFormatter::stdout()` (replaces the old unit-struct constructor), `JsonFormatter::with_writer()` |
| `PinnedDir` (`commands::atomic_swap`) | Unix-only file-descriptor handle on the destination's parent directory, used by `--atomic --force` to perform `*at`-relative renames (v0.6.0, #526) | See [[015-atomic-force-destination-swap-hardening/spec]] |
| `Verbosity` (`output`) | Enum replacing independent `verbose: bool, quiet: bool` parameters across formatter/progress construction (unreleased, post-v0.6.0, #550) | `Quiet` \| `Normal` \| `Verbose`; `from_flags(verbose, quiet)` resolves `quiet` as the deterministic tie-break when both are `true`; `impl From<&cli::Cli> for Verbosity` is the single resolution point |

### CLI Command Syntax

```
exarch [--verbose] [--quiet] [--json] <COMMAND>

exarch extract <ARCHIVE> [OUTPUT_DIR]
    [--max-files N] [--max-total-size SIZE] [--max-file-size SIZE]
    [--max-compression-ratio N] [--allow-symlinks] [--allow-hardlinks]
    [--allow-solid-archives] [--allow-world-writable]
    [--preserve-permissions] [--force] [--atomic]
    [--max-path-depth N] [--banned-component COMPONENT]... [--allow-absolute-paths]

exarch create <OUTPUT> <SOURCE>...
    [-l/--compression-level 1-9] [--follow-symlinks] [--include-hidden]
    [-x/--exclude PATTERN]... [--strip-prefix PREFIX] [-f/--force]
    [--max-file-size SIZE] [--preserve-permissions=BOOL]

exarch list <ARCHIVE>
    [-l/--long] [-H/--human-readable]
    [--max-files N] [--max-total-size SIZE] [--allow-solid-archives]
    [--allow-absolute-paths]

exarch verify <ARCHIVE>
    [--max-files N] [--max-total-size SIZE] [--allow-solid-archives]
    [--strict]

exarch completion <SHELL>    # bash | zsh | fish | powershell | elvish  (output to stdout)
```

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Archive does not exist | Error printed to stderr; exit code non-zero |
| Output directory does not exist | Created automatically (unless `--force` is required) |
| Extraction fails (security violation) | Error with variant name printed to stderr; exit code non-zero |
| `--json` and `--quiet` combined | JSON on stdout (never suppressed by `--quiet`); nothing on stderr |
| `verify --strict` with Warning report | Exit code 2 (was 0 without `--strict`) |
| SIZE suffix parsing (e.g. `--max-total-size 500M`) | K=1024, M=1024², G=1024³, T=1024⁴ |
| `completion` for unsupported shell | Error; exit code non-zero |
| `verify` on archive with issues | Issues printed; exit code non-zero when status is Fail |
| `extract --atomic --force` onto a destination that is itself a symlink | Rejected on all platforms (GHSA-x8wr-7ww2-c94x, v0.6.0) — pass the resolved target path instead |
| `extract --atomic --force` where an intermediate destination path component is replaced with a symlink mid-extraction | Swap is confined to the pinned parent fd; a `dev`/`ino` identity mismatch immediately before the destructive swap aborts it with a distinct error (v0.6.0, #526) |
| `extract --atomic --force` fails after a mid-extraction redirect leaves a temp/backup directory behind at an unexpected path | Error output discloses the directory's actual current path, resolved via an open fd (v0.6.0, #530); in the ordinary non-redirected case, cleanup succeeds and nothing is disclosed or left behind |
| `extract --atomic --force` on Unix without read permission on the destination's parent directory | Fails — obtaining the pinned parent fd requires read permission on the parent (not the destination itself), even when the destination does not yet exist (v0.6.0, #531, behavior change) |
| `SecurityViolation` for a reason no policy flag controls (e.g. GHSA-5j8q-wxg5-hj4r size mismatch, password-protected archive) | HINT states it cannot be relaxed via any policy flag, instead of suggesting an irrelevant flag (v0.6.0, #520) |
| `PartialExtraction`-wrapped error | Category-specific HINT from the wrapped error is preserved, not replaced by the generic partial-extraction HINT (v0.6.0, #527) |
| `extract` pre-flight destination conflict with many pre-existing files | At most 10 conflicting paths listed (sorted), remainder collapsed into `... and N more` (v0.6.0, #500) |
| Human-readable size >= 1 TB (e.g. `u64::MAX` bytes) | Renders as `"...  TB"`, not an inflated GB figure (v0.6.0, #451) |
| `verify`/`list` on a TAR archive with a non-UTF8 entry name | `status: Warning` with a `Medium`-severity `SuspiciousPath` issue, not `Pass` (v0.6.0, #528/#529) — portability risk only, `security_status` unaffected |
| `exarch --verbose extract archive.tar.gz out --quiet` (global `--verbose`, subcommand-level `--quiet`) | Resolves deterministically to `Quiet` (no progress output, no summary) via `Verbosity::from_flags` (unreleased, post-v0.6.0, #550, behavior change) — previously the progress reporter selected verbose output (verbose-wins) while the formatter suppressed the summary (quiet-wins), an inconsistency `clap`'s `conflicts_with` did not catch since the two flags parsed at different `ArgMatches` levels |

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
- [[015-atomic-force-destination-swap-hardening/spec]] — `--atomic --force` symlink/TOCTOU hardening in detail
- [[001-exarch-system/spec]] — original monolithic spec (archived)
