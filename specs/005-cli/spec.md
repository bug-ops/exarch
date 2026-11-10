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
updated: 2026-11-10
status: implemented
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[003-config-api/spec]]"
  - "[[004-progress-tracking/spec]]"
  - "[[015-atomic-force-destination-swap-hardening/spec]]"
  - "[[019-verify-and-list-model/spec]]"
  - "[[020-reader-sink-and-in-memory-api/spec]]"
  - "[[021-create-staging-and-output-policy/spec]]"
  - "[[022-extract-entry-selection/spec]]"
  - "[[023-entry-selection-glob-patterns/spec]]"
---

# Feature: CLI

> [!note] Revision 2026-11-04 (50-issue batch, shipped in 0.9.0)
> Exit status 3 for `verify --strict` warnings, shared `LimitArgs`, typed JSON (`Envelope`, `link_target`, skips by kind, verify issue codes), staged `create`, typed `-x` patterns, library-derived conflict check and request-type migration. See FR-106 to FR-124; rows below that conflict (FR-063, FR-064, FR-065, FR-074, FR-075, FR-077, FR-082, FR-087) are rewritten in place.

> [!info] Metadata
> **Subsystem**: exarch-cli
> **MSRV**: Rust 1.99.1
> **Source**: extracted from [[001-exarch-system/spec]]

> [!note] Revision 2026-11-09: one document under forced exit, swap-failure report, level message (#1133, #1124, #1134)
> FR-135 holds the interrupt lock across the forced exit, FR-146 describes the staging fate after a failed swap, FR-143 takes the level text from core, FR-131 and FR-145 state the directory-occupant and unlistable-destination behavior; a symlink entry over a directory under `--force` is now refused like a file (FR-099, FR-131, #1139).

> [!note] Revision 2026-11-09: stop exit status, forced-exit hint, compression-level range (#1099, #1103)
> FR-135 (a stop after core's last poll, signal death on both stop paths, hint from `staging_place`), FR-133 (`HostPath` in `--json` message and hint) and FR-143 (`i64` overflow is exit 1).

> [!note] Revision 2026-11-08: list link flags, forced-exit budget, narrowing warning (#1064, #1063)
> `list` accepts `--allow-symlinks` and `--allow-hardlinks` (FR-065, FR-088), the second-signal report has a 500 ms write budget (FR-135), and `root_access_narrowed` joins the JSON warnings (FR-138).

> [!note] Batch #1008 amendments
> SIGINT cancellation and exit 130 (FR-135), stdout write errors (FR-136), `io_kind`, `leftover_path` and sorted conflicts (FR-137), typed JSON warnings and per-mode conflict hint (FR-138). Rows that conflict (FR-106, FR-133) are rewritten in place.

> [!note] Batch #981 amendments
> The `--atomic --force` swap is performed by `exarch-core` (`Staging::AtomicReplace`, FR-129); the pre-extraction conflict check is `ListedArchive::check_destination` (FR-130); the CLI maps flags to `ExistingFiles` and `Staging` (FR-131). Selection flags are specified in [[022-extract-entry-selection/spec]].

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
| FR-063 | `extract` SHALL support: `--max-files N`, `--max-total-size SIZE` (K/M/G/T suffixes), `--max-file-size SIZE`, `--max-compression-ratio RATIO` (fractions allowed), `--allow-symlinks`, `--allow-hardlinks`, `--allow-solid-archives`, `--allow-world-writable`, `--preserve-permissions`, `--force`, `--atomic`, `--max-path-depth N` (the core default of 32 applies when omitted), `--banned-component COMPONENT` (repeatable; replaces the default ban list when provided), `--allow-absolute-paths` (flag; also applies to the listing pre-pass), `--parallel-decode-memory SIZE|off` (7z; default 128M), `--zip-consistency enforce|ignore` (default `enforce`), `--decode-reuse off|memory|temp-file` (FR-103), `--allowed-extensions EXT` (repeatable or comma-separated; leading dot optional; an unusable list is `InvalidConfiguration`, never "allow all"), and the selection flags of FR-134; `OUTPUT_DIR` is optional and defaults to the current directory | must |
| FR-064 | `create` SHALL support: `-l/--compression-level 1-9` (out of range is `InvalidConfiguration`, exit 1), `--follow-symlinks`, `--include-hidden` (without it `create` never enters a hidden directory below a source root, FR-126), `-x/--exclude PATTERN` (repeatable; typed shapes, see FR-118), `--strip-prefix PREFIX`, `-f/--force`, `--max-file-size SIZE` (K/M/G/T suffixes; skips source files larger than threshold; `0` is refused as `InvalidConfiguration` and no archive is created), `--preserve-permissions BOOL` (default true; pass `--preserve-permissions=false` for portable archive without Unix permission bits) | must |
| FR-065 | `list` and `verify` SHALL support the shared limit flags of FR-107 (`--max-files`, `--max-total-size`, `--max-file-size`, `--max-compression-ratio`, `--allow-solid-archives`) and `--zip-consistency enforce|ignore`; `list` also `-l/--long`, `-H/--human-readable` (requires `-l`), `--read-link-targets`, `--allow-symlinks`, `--allow-hardlinks` (the shared `LinkPolicyArgs` of FR-088, so link dispositions match `extract`; `--allow-symlinks` implies reading stored link targets, and a decode refusal such as a solid 7z without `--allow-solid-archives` shows the target as unreadable and the link as refused instead of failing the listing); `verify` also `--allow-symlinks`, `--allow-hardlinks`, `--check-integrity`, `--decompression-budget SIZE`, `--strict`, `--parallel-decode-memory SIZE|off` (effective with `--check-integrity`); `list` and `verify` also take the selection flags of FR-134. `verify` has no `--check-security` flag (removed in v0.7.0; security checks always run) | must |
| FR-066 | `completion <SHELL>` SHALL generate shell completion scripts for bash, zsh, fish, powershell, and elvish; output goes to stdout for piping into the appropriate completions directory | must |
| FR-067 | WHEN extraction or creation fails, THE CLI SHALL exit with a non-zero exit code and print the error to stderr | must |
| FR-068 | WHEN `--quiet` is set, THE CLI SHALL suppress progress bars and informational output; only errors go to stderr; `--quiet` SHALL NOT suppress `--json` output — `--json` always emits to stdout regardless of `--quiet` | must |
| FR-069 | WHEN `--verbose` is set, THE CLI SHALL print one line per extracted entry to stderr including entry type indicator (`f`/`d`/`l`), uncompressed size, and relative path; `--quiet` takes precedence when both are set | must |
| FR-070 | THE CLI progress bar SHALL use `indicatif` in human mode and be suppressed in `--json` and `--quiet` modes | must |
| FR-071 | Human-readable output SHALL use SI suffixes (K, M, G) for byte counts when `-H/--human-readable` is set | should |
| FR-072 | WHEN `--allow-symlinks` is already active and a symlink escape is blocked, THE CLI SHALL NOT emit the `--allow-symlinks` hint; the hint is only relevant when symlinks are not yet enabled; since v0.8.0 a symlink or hardlink escape never hints at `--allow-symlinks` or `--allow-hardlinks` at all, because neither flag lifts an escape (#759, #768) | must |
| FR-073 | WHEN `--json` is used, the JSON `message` field for `PartialExtraction`, `PathTraversal`, `SymlinkEscape`, `HardlinkEscape`, `QuotaExceeded`, and `ZipBomb` errors SHALL NOT repeat inner error text that already appears in the structured fields | must |
| FR-074 | `verify` SHALL support `--strict` flag: when set, a `VerificationReport` with `Warning` status causes the process to exit with code 3 instead of 0 (code 2 is clap's usage-error status; changed from 2 to 3 in #932); without the flag, exit 0 on warnings is unchanged | must |
| FR-075 | WHEN `list -l` or `list --json -l` is run and an entry is a symlink or hardlink, THE CLI SHALL include the target path in the output; text format: `l755  0  link.txt -> target.txt`; JSON format: a `link_target` object tagged by `state` (see FR-112) | must |
| FR-076 | `OutputFormatter`'s trait methods SHALL take `&mut self` and write through an injectable `Write` destination (`HumanFormatter<O: Write = Term, E: Write = Term>`, `JsonFormatter<W: Write = Stdout>`) rather than writing directly to a hardcoded `Term`/`Stdout`, so formatter output can be captured in unit tests without a subprocess (v0.6.0, #452) | must |
| FR-077 | `extract`'s human and `--json` output SHALL surface `ExtractionReport.warnings` and the skips by kind (FR-119) on both the success path and the error path (`PartialExtraction`), not silently drop them (v0.6.0, #498, #503) | must |
| FR-078 | WHEN the `SecurityViolation` HINT is shown, THE CLI SHALL derive it from `ArchiveError::relaxable_by()` (a `PolicySetting`) and name only the flag that admits the entry (`--allow-symlinks`, `--allow-hardlinks`, `--allow-solid-archives`, `--banned-component`, `--max-path-depth`); a setting with no CLI flag (`windows_reserved_names`, `max_tar_metadata_bytes`) SHALL point at the Rust API instead, and every other `SecurityViolation` (e.g. the GHSA-5j8q-wxg5-hj4r size-mismatch case, password-protected archives, unsupported compression) SHALL get a HINT stating it cannot be relaxed via any policy flag (v0.6.0, #520; v0.7.0, #741, #757) | must |
| FR-079 | WHEN a `PartialExtraction`-wrapped error is rendered, THE CLI SHALL preserve the wrapped error's category-specific HINT text (e.g. `--allow-symlinks`, or the "cannot be relaxed" wording) rather than replacing it with `PartialExtractionContext`'s generic HINT (v0.6.0, #527) | must |
| FR-080 | `extract`'s pre-flight destination-conflict error SHALL sort and cap the listed conflicting paths at 10, collapsing the remainder into a single `... and N more` summary line, instead of listing every conflict unbounded (v0.6.0, #500) | must |
| FR-081 | Human-readable byte sizes >= 1 TB SHALL render with a `TB` suffix, not an inflated `GB` figure; `HumanFormatter::format_size` and `progress::humanize_bytes` SHALL share one implementation (`output::humanize_bytes`) with a TB-inclusive ladder (v0.6.0, #451) | must |
| FR-082 | `extract`, `list`, and `verify` SHALL apply limit overrides only when provided, otherwise leaving `SecurityConfig::default()`'s own limits in place, via the shared `LimitArgs::apply` (FR-107; replaces the v0.6.0 `commands::apply_size_limits`, #450) | must |
| FR-083 | WHEN `extract --atomic --force` is used and the destination already exists as a directory, THE CLI SHALL extract into a temp directory beside the destination first and only swap it into place — renaming the existing destination aside to a backup path, renaming the extracted content into place, then removing the backup — after extraction fully succeeds; a failed final rename SHALL restore the backup and report its path if that restore itself fails. A pre-existing destination that is not a directory SHALL be rejected explicitly, not silently replaced (v0.6.0, #519) (Since #981 performed by `exarch-core`; the CLI maps `--atomic --force` to `Staging::AtomicReplace`, see FR-129) | must |
| FR-084 | `extract --atomic --force` SHALL reject a destination that is itself a symlink (or, on Windows, a junction/reparse point) on all platforms, and SHALL perform every rename/remove in its destination swap `*at`-relative to a file descriptor pinned on the destination's parent directory (Unix only), never by re-resolving a logical path mid-extraction. This is scoped to `--atomic --force` only — see [[015-atomic-force-destination-swap-hardening/spec]] for the full GHSA-x8wr-7ww2-c94x fix (Since #981 performed by `exarch-core`; the CLI maps `--atomic --force` to `Staging::AtomicReplace`, see FR-129) | must |
| FR-085 | WHEN `extract --atomic --force`'s best-effort cleanup on failure cannot locate its temp/backup directory at the expected logical path (e.g. because an intermediate path component was redirected mid-extraction), THE CLI SHALL disclose the directory's actual current path (resolved via an open file descriptor, not the possibly-stale logical path) in its error output rather than leaving surviving content undisclosed (v0.6.0, #530) (Since #981 performed by `exarch-core`; the CLI maps `--atomic --force` to `Staging::AtomicReplace`, see FR-129) | should |
| FR-086 | `verify`/`list` SHALL flag a TAR entry whose path is not valid UTF-8 as a `Medium`-severity `SuspiciousPath` `VerificationIssue` (portability risk, not a security issue — `security_status` is unaffected), flipping `status` to `Warning` instead of reporting `Pass` for an entry that may fail to extract on filesystems requiring UTF-8 names (v0.6.0, #528) | should |
| FR-087 | `--verbose` and `--quiet` SHALL be resolved once into a single `output::Verbosity` (`Quiet` \| `Normal` \| `Verbose`) via `impl From<&cli::Cli> for Verbosity`, and carried in `OutputMode::Human(Verbosity)` (FR-111) through `output::create_formatter`, `HumanFormatter::new`/`with_writers`, `commands::extract::execute`, and `commands::create::execute`, rather than each site independently interpreting the two raw booleans; `Verbosity::from_flags` SHALL resolve `verbose: true, quiet: true` to `Quiet` in every case, including when the two flags are parsed at different `clap` `ArgMatches` levels (e.g. a global `--verbose` combined with a subcommand-level `--quiet`), which `clap`'s `conflicts_with` on `--quiet` does not reject (v0.6.1, #550, behavior change — see Edge Cases) | must |
| FR-089 | `verify --check-integrity` SHALL decode the payload to the decoder's EOF (ZIP CRC-32, TAR framing, codec checksums, 7z CRC) and report `integrity_status` as `OK`, `FAILED` or `INCOMPLETE`; without the flag it is `SKIPPED` (also in JSON). `FAILED` SHALL exit 1 even under `--strict`. `INCOMPLETE` (budget, resource limit, solid 7z without `--allow-solid-archives`, TAR without an end-of-archive marker) comes with a Medium issue, SHALL exit 0 when the report status is not `Fail`, and SHALL exit 3 under `--strict`. A solid 7z archive without `--allow-solid-archives` is a `Security Policy` failure, so `verify` exits 1 with or without the flag (v0.7.0, #623, #670, #672) | must |
| FR-090 | `--decompression-budget <SIZE>` SHALL require `--check-integrity`, reject `0`, default to a fixed 500 MiB that does not follow `--max-total-size`, and bound only the decoding beyond what listing already does (v0.7.0, #623) | must |
| FR-088 | `extract`, `list` and `verify` SHALL share one `cli::LinkPolicyArgs` (`--allow-symlinks`, `--allow-hardlinks`), flattened into both argument structs and applied to `SecurityConfig` by `LinkPolicyArgs::apply`, so a link policy that makes `extract` succeed makes `verify` accept the same links and `list` report the same dispositions; escaping links SHALL still fail under both flags (v0.7.0, #643, #653) | must |
| FR-091 | `extract`, `list` and `verify` SHALL share one `cli::ZipPolicyArgs` (`--zip-consistency enforce|ignore`, default `enforce`) mapped to `ZipConsistencyPolicy`; `enforce` rejects ZIP archives whose headers disagree or hide data (`extract`, `list`) or reports them (`verify`), `ignore` uses the central directory interpretation (v0.7.0, #671) | must |
| FR-092 | `extract` and `verify` SHALL share one `cli::ParallelDecodeArgs` (`--parallel-decode-memory SIZE|off`); the flag is applied only when given, otherwise `SecurityConfig::default().parallel_decode` stays; `off` maps to `ParallelDecode::Sequential`, `0` is rejected (v0.7.0, #688) | must |
| FR-093 | `list --read-link-targets` SHALL read 7z symlink targets (decoding the blocks that hold them); without it 7z link targets are not read (v0.7.0, #714, #718, #723) | must |
| FR-094 | `verify --json` `data` SHALL carry `integrity_status` (`OK`, `FAILED`, `INCOMPLETE`, `SKIPPED`) and `integrity_gaps` (`null` when none, else `counts` keyed by reason, `entries` of `{path, reason}`, and `omitted`) (v0.7.0, #672, #684) | must |
| FR-095 | The `--json` error envelope SHALL carry `error.relaxable_by` (the stable `PolicySetting` id, e.g. `symlinks`, `solid_archives`) only for a `SecurityViolation` a `SecurityConfig` setting relaxes, and `error.partial_report.writes` (`kept` or `rolled_back`) for a `PartialExtraction`; after `--atomic` rollback the report describes the discarded run (v0.7.0, #725, #741, #757) | must |
| FR-096 | Human-readable output SHALL escape control and Unicode format characters (including bidirectional controls) in entry paths, link targets and other archive-derived text (v0.7.0, #741, #745, #749, #752, #757); since v0.8.0 this covers every `Default_Ignorable_Code_Point` character, keeping a variation selector only after the character it modifies (#753, #768) | must |
| FR-097 | WHEN `extract` targets a destination that does not exist and whose parent is an existing directory, AND the archive is a TAR variant, THE CLI SHALL skip the pre-extraction list pass (a second decode of a compressed stream), extract atomically so a refusal leaves nothing behind and creates no parent directory, and report such a failure with `writes: rolled_back` (`--json` `error.partial_report.writes`); the progress bar then counts entries instead of showing a total. ZIP and 7z archives keep the list pass (v0.8.0, #799, #808) | must |
| FR-098 | WHEN the pre-extraction list pass fails, THE CLI SHALL report the error with the category message and hint `extract` would give the same error (not a generic "failed to list archive" wrapper), and the unknown-format hint SHALL list every supported archive extension, including 7z (v0.8.0, #796, #808) | must |
| FR-099 | WHEN `extract --force` would replace an existing directory or symlink with a file, THE CLI SHALL fail naming the entry (`refusing to replace the existing directory at d`) for TAR, ZIP and 7z; WHEN it would replace a directory, one the destination already held or one the archive created, with a symlink entry, THE CLI SHALL fail the same way, with the same message (naming the normalized relative path) and the same typed `IsADirectory` I/O error as a file over a directory, identically for TAR, ZIP and 7z; the branch is reached only under `ExistingFiles::Overwrite` (`Refuse` fails earlier as a conflict, `Skip` skips the entry), and with `--atomic --force` the staging directory is discarded (v0.8.0, #765, #768, #1139) | must |
| FR-100 | WHEN `create` writes a ZIP, THE CLI SHALL surface the core warning for entries that default extraction would refuse as a zip bomb, naming the entry count and the `--max-compression-ratio` value that admits them, and `create --help` SHALL say so (v0.8.0, #801, #808) | should |
| FR-101 | THE CLI SHALL build for `wasm32-wasip1` and pass a wasmtime smoke test in CI (v0.8.0, #755, #771) | should |
| FR-102 | THE `--json` error envelope SHALL carry `error.sub_code` (the stable `SubCode` id, e.g. `TAR_AMBIGUITY`, `PATH_NAME`) always for a `SecurityViolation` and for an `InvalidArchive` that has a family (a `Malformation` with a sub-code, a TAR ambiguity or trailer refusal, a ZIP reader failure), and `error.setting` (the stable `ConfigSetting` id) for an `InvalidConfiguration` that names one; both are absent otherwise (v0.8.0, #865, #870, #887, #889, #894, #946) | must |
| FR-103 | `extract` SHALL accept `--decode-reuse <off\|memory\|temp-file>` choosing where the ZIP structure check keeps what it decodes so compressed entries are not decoded twice; the default is memory up to 256 MiB, never more than `--max-total-size` or the decoder memory limit, it has no effect under `--zip-consistency ignore`, `temp-file` keeps the plaintext in an unnamed file in the temporary directory until extraction ends, and entries that do not fit are decoded again; on Linux and Android a `temp-file` spool on a tmpfs or ramfs is detected and charged against the decoder memory limit like `memory`, while a RAM-disk temporary directory elsewhere is not detected (v0.8.0, #857, #884, #950) | should |
| FR-104 | WHEN `extract` writes into an existing destination, THE CLI SHALL list a gz, bz2 or xz TAR and extract it from one decode (`ListedArchive`); `--atomic` SHALL decode a TAR once, so a refusal arrives as a `rolled_back` partial report and the progress bar has no total (v0.8.0, #828, #842) | should |
| FR-105 | (Swap-directory identity moved to core with #981: `FileIdentity` no longer exists in the CLI; the comparison is core's `ReplacesProtectedPath` guard, see FR-129.) `--force` SHALL replace an existing regular file through a sibling temp file and rename (see [[002-format-handlers/spec]] FR-052) (v0.8.0, #819, #878, #888) | must |
| FR-106 | THE CLI SHALL map every command result to one exit status through an exhaustive match in `main() -> ExitCode`: `Outcome` to `ExitStatus { 0, 1, StrictWarning = 3, Interrupted = 130, Terminated = 143 }`; status 2 is reserved for clap usage errors; there SHALL be no sentinel errors (#932) | must |
| FR-107 | `extract`, `list` and `verify` SHALL share one flattened `cli::LimitArgs` (`--max-files`, `--max-total-size`, `--max-file-size`, `--max-compression-ratio`, `--allow-solid-archives`); clap SHALL check syntax only (a number, with K/M/G/T for sizes) and `LimitArgs::apply(SecurityConfig)` SHALL pass the raw values to core (`Limit::parse`, `RatioLimit::parse`), so a zero count or size, a zero, negative or non-finite ratio, a zero `--decompression-budget` or `--parallel-decode-memory` (`setting: parallel_decode_memory`) and a zero or out-of-range `create -l`; an unparsable value (`--max-files 2.5`) stays a clap usage error (exit 2) are `InvalidConfiguration` with exit 1 and the JSON envelope, never a clap exit 2; fractional ratios (`1.5`) are accepted; the CLI SHALL NOT copy core defaults (a flag that is omitted leaves the core value, so `--max-path-depth` has no `default_value` and its help text states none) (#938) | must |
| FR-108 | WHEN an error names an archive, THE CLI SHALL carry the archive name and a HINT on `list` and `verify` as on `extract`; hints SHALL name only flags valid for the failing `Operation` (`Operation::accepts(Flag)`, `Flag::long()`; `Operation` and `Flag` come from one `closed_list!` macro, with `AllowedExtensions` and `Atomic` among the flags), with a test that every hint flag exists on its subcommand; `create` hints talk about the source, and source and output paths print once (#937) | must |
| FR-109 | THE CLI SHALL build user-facing error context from typed parts (`CliContext { parts: Vec<Part>, source }`, `Part::{Lit(&'static str), Path, Text}`): the human formatter SHALL escape `Path` and `Text`, and `--json` SHALL emit them raw so archive text in JSON is exact (#934) | must |
| FR-110 | THE CLI SHALL give a discarded in-memory extraction a dedicated text saying nothing was written, and per-scope hints for zip-bomb refusals (`entry`, `solid block`, `skipped entries`), each with an `ALL` drift test over the core enum (#941) | must |
| FR-111 | `--json` SHALL print every document as an `Envelope<T>` (serde tag, `Operation`, `JsonKind`) whose wire format is pinned by a test (`status` precedes `operation` in the printed object); `OutputMode::{Human(Verbosity), Json}` SHALL be resolved once and replace the separate flags at every call site; a `--json` run SHALL NOT draw a progress bar or verbose lines on stderr (#939, #943, #942) | must |
| FR-112 | `list --json -l` SHALL replace `symlink_target` and `hardlink_target` by one `link_target` object tagged by `state` (`recorded` with `path`, `missing`, `unread`, `unreadable`, `oversized` with `bytes`); human `list -l` SHALL print a note for `missing` and `oversized` (a drift test matches every core `LinkTarget` state); `-H/--human-readable` SHALL require `-l` (clap usage error otherwise); the size shown by `list -l` is the size of regular files (links and directories show 0 and the total sums regular files) (#940, #943, #910) | must |
| FR-113 | `extract` SHALL decide its write mode once (`WriteMode::{Safe, Force, Atomic, AtomicReplace}`) and plan it as `ExtractPlan::{Stream { options }, Listed { listed, options }}`, deriving the core options per variant (#936); the displaced-destination guard and the `Replace` plan variant of #936 moved to core with #981 and no longer exist in the CLI | must |
| FR-114 | (Superseded by #981: `PinnedDir` and `EntryName` were removed from the CLI with the swap; core's staging names its own entries.) | must |
| FR-115 | THE CLI SHALL decide the pre-extraction conflict check from the library: `ConflictsChecked::check` SHALL take where extraction creates paths from `ArchiveManifest::landings(&SecurityConfig)` (entries and implied parent directories, `LandingKind::{Entry, ImplicitParent}`; no CLI-side mapping, no `allow_absolute_paths` parameter) and read each occupant with `symlink_metadata`, reporting the conflict at the conflicting (possibly implied parent) path before anything is written and swallowing no I/O error; a conflict is any occupant under a non-directory entry, a non-directory under a directory entry or under an implied parent; a directory over a directory is not a conflict; a symlink in an unsuitable place reports the generic "already exists" message (JSON `error.kind` `Error`) rather than a `SecurityViolation`; the message of a conflict found by the pre-check is "already exists" with the path, and the specific "refusing to replace the existing file" message remains under `--force` or `--atomic` (#933, #802) (Since #981 the check is `ListedArchive::check_destination`, FR-130; `ConflictsChecked` no longer exists) | must |
| FR-116 | `extract` of a listed archive SHALL pass the extraction config to `ListRequest::for_extraction` and extract through `ListedArchive::extract`, so `--allow-symlinks`, `--allow-hardlinks`, `--allow-world-writable` and `--preserve-permissions` hold in an existing destination (a ZIP symlink into an existing destination extracts under `--allow-symlinks` and is refused without it); `list_config_for` SHALL NOT exist (#901, #912) | must |
| FR-117 | `create` SHALL map `--force` to `OutputFile::replace` and its absence to `OutputFile::create_new` and SHALL NOT call `exists()` or `remove_file`; creation is staged (see [[021-create-staging-and-output-policy/spec]]): a failed run keeps the previous archive, `--force` replaces atomically and keeps the file's mode, a directory, FIFO or device output is `InvalidConfiguration` for `output_path` with or without `--force`, and an existing output without `--force` is `OutputExists` with a hint naming `--force` (#931, #915) | must |
| FR-118 | `create -x PATTERN` SHALL parse with `EntryPattern::try_from` after clap (grammar of [[023-entry-selection-glob-patterns/spec]], #1000): a refused shape (`..`, empty, absolute or drive-prefixed, `a**b`, `{a,b}`, a leading `!`, a negated or POSIX class, an unterminated class, a range outside `0-9`, `a-z`, `A-Z`, a comma, edge whitespace) is `InvalidConfiguration` (`setting: exclude_pattern`), exit 1, JSON envelope, no archive written; `build/*`, `a*b`, `*` and `file?.txt` are accepted; the `-x` help text SHALL say that a name (`*.tmp`, `node_modules`) matches any path component, a pattern with a `/` (`build/out`, `src/**/*.o`) matches from the archive root, a match also excludes everything below it, and that the pattern should be quoted (`crates/exarch-cli/src/cli.rs`); the error names the refused pattern and its message text (the JSON envelope carries no `reason` code; the `PatternRefusal` codes `wildcard_with_separator` and `glob_metacharacter` no longer exist) (#916, #1000) | must |
| FR-119 | Extraction and creation reports SHALL show skipped entries by reason: human output prints the skip total plus one `kind: N` line per reason that occurred; `--json` adds `files_skipped`, `skipped_by_kind` (only reasons that occurred) and `skipped_sample` (at most 64 entries of `{ kind, path, io_kind }`) through one flattened `JsonSkips` shared by extract, partial reports and create; skips SHALL NOT appear as free-text warnings, and warnings are rendered from the typed warnings (`Display`) (#906) | must |
| FR-120 | `verify --json` issues SHALL drop `context` and carry, for a refusal, `code`, `sub_code`, `relaxable_by` and `setting` (flattened `JsonRefusal` from `VerificationIssue::ffi_kind()`), and a numeric `mode` (from `VerificationIssue::mode()`) for the executable-file heuristic and for invalid permissions; human output SHALL use the `VerificationIssue` accessors (`severity()`, `category()`, `message()`, `entry_path()`, `finding()`) (#899) | must |
| FR-121 | WHEN a quota or zip-bomb error is reported with `--json`, `error.sub_code` SHALL be the `SubCode` literal of the quota kind (eleven values, `FILE_COUNT` ... `SOLID_BLOCK_MEMORY`, `HEADER_SIZE`, `HEADER_ENTRY_COUNT`) or zip-bomb scope (`ENTRY`, `SOLID_BLOCK`, `SKIPPED_ENTRIES`), and the human quota context SHALL have a dedicated arm for `SolidBlockMemory`, for `HeaderSize` and for `HeaderEntryCount`, whose messages name the file-count limit the cap derives from (#918, #896, #674) | must |
| FR-122 | THE CLI progress bar SHALL follow core's per-entry `EntryPosition`: it sizes itself only from `EntryTotal::Known(n)` with `n > 0`, `create` starts unsized (`BarLength::Discover`) and resizes from the real total, and `create` prints verbose per-entry lines (`  create  path`) like extract; one `progress_for(OutputMode, BarLength, Operation)` builds every reporter (#904, #942) | must |
| FR-123 | THE CLI SHALL pin a parity test that `verify` and `extract` agree on the projected landing limit (`d -> cc` plus a long tail: an entry of 1022 bytes passes and extracts, 1023 is refused by both) (#945) | must |
| FR-124 | THE CLI SHALL NOT call any option or progress function variant, `list_config_for`, `Archive` or `ArchiveBuilder`; all commands use `ExtractRequest`, `ListRequest`, `VerifyRequest` and `CreateRequest` (#912, #897) | must |
| FR-125 | Entry names and paths SHALL be shown through `exarch_core::path_text` in text and `--json` alike (a backslash as `\x5C`, invalid bytes as `\xNN`), so distinct names never print alike and no U+FFFD appears, finding texts included; `skills/exarch-cli/SKILL.md` documents exit codes, the limit boundary, `link_target`, skips by kind, verify issue fields, the conflict rule and the `create` semantics (#925, checked against the binary by the CLI developer) | must |
| FR-126 | WHEN `create` runs without `--include-hidden`, THE CLI SHALL leave out hidden files and SHALL NOT enter a hidden directory below a source root (counted once as a `hidden` skip); a hidden source root named by the caller, a file source and `--include-hidden` are unchanged; with `--follow-symlinks` the visible name of a link decides, so `keys -> .ssh` is archived; the check compares raw name bytes (#916, see [[021-create-staging-and-output-policy/spec]] FR-026) | must |
| FR-127 | The `extract --force` pre-check SHALL, before any write, refuse a non-directory where a directory landing (an entry or an implied parent) is needed, a symlink at a file or hardlink landing ("refusing to replace the existing symlink"), a symlink at a symlink landing unless the archive's recorded target equals the existing one (an unread 7z target is refused too), a directory at any non-directory landing and any file or directory at a hardlink landing (`DestinationOccupied`), all up front, so these are typed errors before anything is written and not write-phase `IoError`s (`ListedArchive::check_destination` with `DestinationCheck::Replaceable`, [[003-config-api/spec]] FR-060, #1157, #1168); typed symlink refusals (`SecurityViolation` with its `relaxable_by`) SHALL be preserved by the pre-check rather than flattened to a generic message (#933, #765) | must |
| FR-128 | WHEN `create` meets a source that exists but cannot be read, THE CLI SHALL exit 1 with `Source path is not accessible` naming the file and the OS error, and `--json` SHALL report `error.kind` `SourceNotAccessible` (was `IoError`); a missing source stays `SourceNotFound`; no archive is left at the output path (#956) | must |
| FR-129 | `extract --atomic --force` SHALL map to `ExistingFiles::Overwrite` with `Staging::AtomicReplace`; `commands::atomic_swap`, the CLI swap in `extract.rs` and the CLI `rustix` dependency are removed; every behavior of FR-083 to FR-085, FR-105 and FR-113 is core behavior ([[015-atomic-force-destination-swap-hardening/spec]]); `--atomic --force` onto `.`, `..`, a directory that contains the working directory or the archive, or `/` is refused (`InvalidConfiguration`, setting `output_path`, `ReplacesProtectedPath`, exit 1; it used to replace the working directory) | must |
| FR-130 | `extract` SHALL call `ListedArchive::check_destination` before writing (Safe mode `Vacant`, `--force` `Replaceable`; staged modes skip it); the CLI has no symlink-containment code of its own (`ConflictsChecked` is gone); a refusal is `DestinationOccupied`, JSON `error.kind` `OutputExists`, with the full sorted `Vacant` list in `error.conflicts` (also when the hint names only a subset) and the text listing capped; a symlink at a landing is refused with core's wording `refusing to create <parent> under the existing symlink at <parent>` | must |
| FR-131 | The CLI SHALL map Safe mode to `ExistingFiles::Refuse` with `Staging::InPlace`, `--force` to `Overwrite` with `InPlace`, `--atomic` to `Skip` with `Staging::Atomic` (core runs `Refuse` inside its staging directory) and `--atomic --force` to `Overwrite` with `AtomicReplace`; the `Vacant` pre-check gives the aggregated early error with nothing written and `Refuse` closes the race where a file appears after it; the TAR single-pass path (no list pass for a staged or fresh destination) enforces `Refuse` at write time; `--atomic` into a non-empty directory is core's `OutputExists` before extraction, with the `--force` hint; a file, symlink or hardlink over a directory the archive created is refused in every mode (`Refuse` in safe mode, `--force` and `--atomic --force` through the Overwrite guard "refusing to replace the existing directory", with the typed `IsADirectory` I/O error and the same message for a symlink as for a file, and with the staging discarded under `--atomic --force`), because core raises `Skip` to `Refuse` in every staged run; for `DestinationOccupied` with `by: OccupiedBy::Archive` the CLI shows the entry paths without the staging prefix (the staging directory is gone when the error shows) and the hint "The archive writes a file or link at a path where it also makes a directory; no flag allows that." (`ConflictAdvice::ArchiveConflict`) in every mode (plain staged, in-place, `--atomic`, `--force`, `--atomic --force`), never "Use --force to overwrite."; with `by: Existing` it keeps that hint or the force-cannot-replace advice (#1127, #1130, #1139) | must |
| FR-132 | A missing or unreadable archive SHALL be `SourceNotFound` or `SourceNotAccessible` from core (`open_archive`); `ErrorCode::Cancelled` SHALL render as `Cancelled`; the `--json` `io_kind` field SHALL use the stable `IoKind::as_str()` spelling; an empty `--allowed-extensions` or banned-component list SHALL be `InvalidConfiguration` with setting `allowed_extension` or `banned_path_component` and problem `Empty` (core error kept in the chain, the flag as context), so no CLI-raised refusal is kind `Error` (#982, #985, #989) | must |
| FR-133 | Hints SHALL be structured: `error.hint` (optional string, several joined by a newline) is a sibling of `message` in the `--json` envelope, and human output prints `HINT:` lines after the whole message chain; `InvalidConfiguration` text is `Cannot <op> with these settings: <detail>` with a hint that depends on the problem; a failed swap is a `ReplaceFailed` message (restore result, backup path, leftover staging path) with a hint, JSON kind `IoError` and no `sub_code`; each fact appears once in a message, not in the CLI prefix and again in the core text; a closed stdout (`BrokenPipe`) is success in text and `--json`, any other failure to write the result to stdout exits 1 in text mode as in `--json` (#1008), and a closed stderr under `-v` does not panic (#981, #985, #986); host paths in CLI-authored `message` and `hint` text (including the forced-exit report) use the `HostPath` spelling in `--json` and the text spelling in human output, and the forced-exit `message` equals the `Cancelled` message text (#1103) | must |
| FR-134 | `extract`, `list` and `verify` SHALL take `--include`, `--exclude`, `--strip-components` and `--flatten` as specified in [[022-extract-entry-selection/spec]] FR-100 to FR-102; `--atomic --force` with any of them is refused by core (`entry_selection`, exit 1) | must |
| FR-135 | `extract` and `create` SHALL install a handler for SIGINT and SIGTERM (`interrupt::install`: `signal-hook` on Unix, `ctrlc` on Windows for Ctrl-C and Ctrl-Break, nothing on `wasm32-wasip1`, which has no signals); the first signal sets the stop that core polls through `ProgressCallback::is_cancelled` at entry boundaries and about every 8 MiB inside one entry's copy (FR-057 of [[004-progress-tracking/spec]]), and the pre-extraction listing polls per entry; core removes the staging entry, and the process exits 130 (`ExitStatus::Interrupted`, SIGINT) or 143 (`ExitStatus::Terminated`, SIGTERM) when the error is `Cancelled` and a signal was requested, after re-raising the signal with its default action once cleanup is done so a parent shell sees a signal death; a stop requested after core's last poll lets the run finish and report its result, and the process then ends by the signal (130 or 143, a signal death on Unix, exit status 130 on Windows) and never reports success; a stop never overrides a failure status; a second signal flushes stdout and stderr and then ends the process by the signal at once (a signal death on Unix, exit 130 on Windows), writing one `Cancelled` JSON error document under `--json` (the one-document contract holds) and otherwise printing which `.exarch-*` / `.exarch-backup-*` entries (`STAGING_PREFIX`, `BACKUP_PREFIX`) may remain, the hint naming the staging place that core's `staging_place` resolved when the guard was armed (the canonical parent, also for a destination written as `a/b/..` or reached through a symlink), resolved again inside the forced-exit write when arming could not, the report being written best effort within a 500 ms budget (`FORCED_EXIT_WRITE_BUDGET`) so a blocked stdout or stderr pipe cannot hang the exit: the exit status is the contract, a blocked stdout means no JSON document, and a timed-out write above `PIPE_BUF` may leave a partial line; the forced exit holds the interrupt lock (`Claim`, kept by `Forced` until the process ends), so the handler cannot be disarmed and the result printed concurrently and `--json` prints exactly one document (#1133); the handler is disarmed (the guard drops) before the report prints, so a stop requested after core's last poll is reported as a result while `--json` describes the data and the exit status reports the stop, and a further SIGINT or SIGTERM while that report prints takes the default action and can leave no `--json` document or a truncated one, only the exit status being guaranteed there; `--strict` status 3 cannot accompany a stop, because only `verify` has `--strict` and `verify` installs no handler; a SIGINT or SIGTERM that the process inherited as ignored (`trap "" INT`) is not handled and never replaced on Unix: it stays ignored for the whole run and never cancels it, the other signal being handled as usual (#1109); `list`, `verify` and `completion` install nothing; SIGHUP keeps its default action on purpose, so a `nohup`-ed run still ignores it (#1014, #1035, #1037, #1045, #1050, #1099, #1103) | must |
| FR-136 | Human mode SHALL exit 1 when writing the result to stdout fails with anything other than `BrokenPipe`, and SHALL treat `BrokenPipe` as success (one decision point, `output::tolerate_closed`) (#1008) | must |
| FR-137 | The `--json` error envelope SHALL carry `error.io_kind` on an `IoError` (the core `IoKind` token, equal to Python `io_kind` and Node `ioKind`) and `error.leftover_path` (unredacted) when a failed run left a staging directory or reservation file behind; a rolled-back error with a leftover SHALL say that nothing was published and name the surviving staging directory, with a hint to remove it; `error.conflicts` SHALL be in path-component order, sorted once in core and deduplicated (#1013, #1016, #995) | must |
| FR-138 | `--json` warnings SHALL be objects `{kind, message, ...fields}` keyed by the core `as_str` of `ExtractionWarningKind` and `CreationWarningKind` (`anti_items_skipped` with `count`; `backup_cleanup_failed` with `path`, `identity`, `io_kind` and `reason`; `zip_ratio_over_default_limit` with `entries`, `limit`, `needed_ratio`; `zip_ratio_check_failed` with `reason`; `directory_not_synced` with `io_kind`; `root_access_narrowed` with `reason`, one of the `NarrowingReason` tokens of [[015-atomic-force-destination-swap-hardening/spec]] FR-112) in reports and in `error.partial_report`; a kind added later reaches the output with `kind` and `message` only; the conflict refusal's advice SHALL be `error.hint` worded per write mode and per cause, never part of `message`: `ConflictAdvice::UseForce` (`Use --force to overwrite.`) only when a Safe-mode `Vacant` refusal is `DestinationOccupied` and a second `Replaceable` check passes, so `--force` would replace every occupant; `ForceCannotReplace(subset)` (`--force does not replace <paths>; remove them or choose another destination.`, the subset being the conflicts of the second check capped at 10 with `and N more`, or `these paths` when unknown, never promising `--atomic --force`) when `--force` would not, and under `--force` and `--atomic --force`, where every listed path is unreplaceable; `ArchiveConflict` when `by` is `archive` (the archive writes more than one entry where only one fits, such as a file or link where it also makes a directory, or a later hardlink at a path an earlier entry wrote; no flag allows that); the second check's own error is never returned, only its conflicts feed the hint, and any other failure of it keeps the first refusal with the neutral advice; an up-front `ReplacesSymlink` refusal carries the hint that an existing symlink is never replaced in place (remove it or choose another destination) (#1157, #1154); `problem_hint` returns no advice for a `ConfigProblem` it does not list, and a test enumerates every known variant (#1017, #1015, #1013) | must |
| FR-139 | Under any selection flag, `list --json` SHALL give each entry a `disposition` (`{action: extract, landing}`, `{action: skip, kind}` or `{action: refuse}`, `action` being the core `DispositionKind` token) and human `list` SHALL append `[lands at <path>]`, `[skipped: <kind>]` or `[refused]` (#1036); without a selection neither appears, `verify` prints no per-entry rows and carries none, and `total_entries` and `total_size` still count every entry (#1011, #1019); `list --destination <DIR>` probes the destination volume only under a selection flag, an unresolvable destination being `DestinationNotAccessible` (JSON `kind` `IoError` with `io_kind`, exit 1, the path named once in the message), and without a selection flag it is not probed ([[019-verify-and-list-model/spec]] FR-043, #1161) | must |
| FR-140 | `list --json` and `verify --json` SHALL report the core `format` token, and `verify --json` `data` SHALL carry `suspicious_entries`; absent per-entry fields (`compressed_size`, `mode`, `modified`, `link_target`, `disposition`) are omitted, never `null` (#1019) | must |
| FR-141 | A quota error SHALL carry its advice (which limit to raise, the matching flag such as `--max-files`) in `error.hint` and in the human hint line, not in `error.message` (#1034) | must |
| FR-142 | Host paths SHALL be exact in `--json` output (the OS path, losslessly) and rendered through core `path_text` in human text, so a control or bidirectional character in a path cannot reach the terminal; on Windows a host path that is valid UTF-8 keeps its native `\` separators in human text, including a trailing separator, while archive entry names and conflict paths stay `/`-separated on every host (#1047) | must |
| FR-143 | `create --compression-level` SHALL take a signed integer and an out-of-range value SHALL exit 1 with the `InvalidConfiguration` error and the accepted range in the help, not a clap usage exit; the `--help` text of limits and levels SHALL be derived from the core defaults, never hard-coded (#1048, #1051); a level beyond the `i64` range is `InvalidCompressionLevel` with exit 1 (`parse_requested_level`, overflow is `OutOfRange`), while non-numeric text stays a clap usage error with exit 2 (#1103); the message is core's (`Invalid compression level: must be 1-9, got 10`, FR-072 of [[003-config-api/spec]]) and the level is built by `CompressionLevel::try_from(RequestedLevel)`, not re-checked in the CLI (#1134) | must |
| FR-144 | `completion` SHALL follow the stdout error policy of FR-136: a closed stdout (`BrokenPipe`) is success, any other write failure exits 1 (#1049) | must |
| FR-145 | WHEN plain `--atomic` targets a destination that exists but cannot be listed (`0311`, `0000`), `extract` SHALL exit 1 with the `Io` error that names the destination and say nothing was changed; `--atomic --force` onto the same destination succeeds and keeps its mode ([[015-atomic-force-destination-swap-hardening/spec]] FR-116) (#1131) | must |
| FR-146 | The human and `--json` report of a failed `--atomic` extraction SHALL be driven by the CLI's `StagingFate {Removed, Left(path), Swap}` taken from core's `Partial` (`ReplaceFailed` is `Swap`, a leftover is `Left`, otherwise `Removed`): `Removed` and `Left` say the destination was left unchanged; `Swap` says the extracted content was discarded and not published and that the error below says what became of the destination, never that it was left unchanged; `partial_report` keeps the extraction counts with `writes: "rolled_back"` after a failed `--atomic --force` swap, and `leftover_path` is not derived from a `Swap`; `rolled_back` describes the staging tree, not the intactness of the destination ([[015-atomic-force-destination-swap-hardening/spec]] FR-115) (#1124) | must |

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
| `ExtractArgs` | Arguments for `extract` subcommand | `archive`, `output_dir`, `limits: LimitArgs`, `selection: SelectionArgs`, `links`, `zip`, `parallel`, `decode_reuse`, `allowed_extensions`, security overrides, `--force`, `--atomic`, `--max-path-depth`, `--banned-component`, `--allow-absolute-paths` |
| `CreateArgs` | Arguments for `create` subcommand | `output`, `sources`, creation options, `--max-file-size`, `--preserve-permissions` |
| `ListArgs` | Arguments for `list` subcommand | `archive`, `long`, `human_readable`, `limits`, `selection`, `zip`, `read_link_targets` |
| `VerifyArgs` | Arguments for `verify` subcommand | `archive`, `limits`, `selection`, `links: LinkPolicyArgs`, `zip: ZipPolicyArgs`, `parallel: ParallelDecodeArgs`, `check_integrity`, `decompression_budget`, `strict` |
| `LinkPolicyArgs` | Link policy flags shared by `extract` and `verify` (#643) | `allow_symlinks`, `allow_hardlinks`, `apply(SecurityConfig)` |
| `ZipPolicyArgs` | ZIP structure policy flag shared by `extract`, `list` and `verify` (#671) | `zip_consistency: ZipConsistencyArg` (`Enforce` \| `Ignore`), `apply(SecurityConfig)` |
| `ParallelDecodeArgs` | 7z parallel-decode memory flag shared by `extract` and `verify` (#688) | `parallel_decode_memory: Option<ParallelDecode>`, `apply(SecurityConfig)` |
| `OutputFormatter` | Trait for human vs JSON output; methods take `&mut self` since v0.6.0 (#452) | Methods: `format_extraction_result`, `format_creation_result`, `format_manifest` (short or long view), `format_verification_report`, `format_error`, `format_verification_failed` |
| `HumanFormatter<O: Write = Term, E: Write = Term>` | Human-readable formatter; writes non-error output to `O`, errors to `E` (v0.6.0) | `HumanFormatter::new()` (stdout/stderr default), `HumanFormatter::with_writers()` (injects custom writers + `use_colors` for deterministic tests) |
| `JsonFormatter<W: Write = Stdout>` | JSON formatter (v0.6.0) | `JsonFormatter::stdout()` (replaces the old unit-struct constructor), `JsonFormatter::with_writer()` |
| `SelectionArgs` | `--include`, `--exclude`, `--strip-components`, `--flatten` shared by `extract`, `list` and `verify` (#1000) | see [[022-extract-entry-selection/spec]] |
| `OutputMode` (`output`) | `Human(Verbosity)` or `Json`, resolved once from the parsed flags (#943) | `impl From<&cli::Cli> for OutputMode` |
| `LimitArgs` | Limit flags shared by `extract`, `list` and `verify` (#938) | `max_files`, `max_total_size`, `max_file_size`, `max_compression_ratio`, `allow_solid_archives`; `apply(SecurityConfig) -> Result` |
| `Operation` / `Flag` | The command a hint is for and the flags a subcommand accepts (#937) | `Operation::accepts(Flag)`, `Flag::long()`; also the JSON `operation` |
| `Outcome` / `ExitStatus` | Command result and process status (#932, #1014) | `ExitStatus { 0, 1, StrictWarning = 3, Interrupted = 130, Terminated = 143 }` |
| `Envelope<T>` / `JsonKind` / `JsonLinkTarget` | Typed JSON output (#939, #940) | `link_target` tagged by `state` |
| `CliContext` / `Part` | Typed error context (#934) | `Part::{Lit, Path, Text}`; escaped in human output, raw in JSON |
| `WriteMode` / `ExtractPlan` | Extract planning (#936) | see FR-113 |
| `BarLength` | Known or discovered progress length (#942) | `Known`, `Discover` |
| `Verbosity` (`output`) | Enum replacing independent `verbose: bool, quiet: bool` parameters across formatter/progress construction (v0.6.1, #550) | `Quiet` \| `Normal` \| `Verbose`; `from_flags(verbose, quiet)` resolves `quiet` as the deterministic tie-break when both are `true`; `impl From<&cli::Cli> for Verbosity` is the single resolution point |

### CLI Command Syntax

```
exarch [-v/--verbose] [-q/--quiet] [-j/--json] <COMMAND>

exarch extract <ARCHIVE> [OUTPUT_DIR]
    [--max-files N] [--max-total-size SIZE] [--max-file-size SIZE]
    [--max-compression-ratio RATIO] [--allow-symlinks] [--allow-hardlinks]
    [--allow-solid-archives] [--allow-world-writable]
    [--preserve-permissions] [--force] [--atomic]
    [--max-path-depth N] [--banned-component COMPONENT]... [--allow-absolute-paths]
    [--zip-consistency enforce|ignore] [--parallel-decode-memory SIZE|off]
    [--decode-reuse off|memory|temp-file] [--allowed-extensions EXT]...
    [--include PATTERN]... [--exclude PATTERN]... [--strip-components N | --flatten]

exarch create <OUTPUT> <SOURCE>...
    [-l/--compression-level 1-9] [--follow-symlinks] [--include-hidden]
    [-x/--exclude PATTERN]... [--strip-prefix PREFIX] [-f/--force]
    [--max-file-size SIZE] [--preserve-permissions=BOOL]

exarch list <ARCHIVE>
    [-l/--long [-H/--human-readable]]
    [--max-files N] [--max-total-size SIZE] [--max-file-size SIZE]
    [--max-compression-ratio RATIO] [--allow-solid-archives] [--read-link-targets]
    [--allow-symlinks] [--allow-hardlinks]
    [--zip-consistency enforce|ignore]
    [--include PATTERN]... [--exclude PATTERN]... [--strip-components N | --flatten]

exarch verify <ARCHIVE>
    [--max-files N] [--max-total-size SIZE] [--max-file-size SIZE]
    [--max-compression-ratio RATIO] [--allow-solid-archives] [--allow-symlinks] [--allow-hardlinks]
    [--zip-consistency enforce|ignore] [--parallel-decode-memory SIZE|off]
    [--check-integrity [--decompression-budget SIZE]] [--strict]
    [--include PATTERN]... [--exclude PATTERN]... [--strip-components N | --flatten]

exarch completion <SHELL>    # bash | zsh | fish | powershell | elvish  (output to stdout)
```

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Archive does not exist | Error printed to stderr; exit code non-zero |
| Output directory does not exist | Created automatically |
| Extraction fails (security violation) | Error with variant name printed to stderr; exit code non-zero |
| `--json` and `--quiet` combined | JSON on stdout (never suppressed by `--quiet`); nothing on stderr |
| `verify --strict` with Warning report | Exit code 3 (was 0 without `--strict`; 2 until #932, now only clap's usage-error status) |
| `--max-compression-ratio 0`, `--decompression-budget 0` or `create -l 0` | `InvalidConfiguration`, exit 1 with the JSON envelope (was clap exit 2; #938) |
| `--max-compression-ratio 1.5` | Accepted (fractions allowed) |
| `list -H` without `-l` | clap usage error (exit 2; #943) |
| `create out.tar.gz src` and `out.tar.gz` exists, no `--force` | `OutputExists` with a hint naming `--force`; the file is untouched (#931) |
| `create --force` fails midway | The previous archive is kept byte-identical and no temporary file remains (#931) |
| `create -x 'build/*'` | `InvalidConfiguration` (`exclude_pattern`), exit 1, no archive (#916) |
| `--json` run | No progress bar and no verbose lines on stderr (#942, #943) |
| SIGINT or SIGTERM during `extract` or `create` | Stops at the next entry boundary or inside a large entry's copy (about 8 MiB), core removes the staging entry, exit 130 (SIGINT) or 143 (SIGTERM) with `error.kind` `Cancelled`, the signal re-raised after cleanup; `--atomic` and `create` leave the destination or previous archive as it was, an in-place `extract` keeps the entries written (#1014) |
| A second signal during a cancelled run | Exits at once (130 or 143) without cleanup, writes exactly one `Cancelled` JSON document under `--json` (the interrupt lock is held, #1133) (best effort within 500 ms; a blocked stdout means no document), and prints which `.exarch-*` entries may remain, naming the `.exarch-backup-*` entry as the original destination of an `--atomic --force` swap (#1014) |
| SIGHUP during `extract` or `create`; SIGINT or SIGTERM during `list`, `verify` or `completion` | Default action, no cancellation handler (#1014, #1035) |
| A write of the result to stdout fails other than by `BrokenPipe` (full disk, EIO) | Exit 1 in text mode too, as in `--json` mode (#1008) |
| A failed run that left a staging directory or reservation file | `--json` `error.leftover_path` and the text name it, with a hint to remove it (#995) |
| SIZE suffix parsing (e.g. `--max-total-size 500M`) | K=1024, M=1024², G=1024³, T=1024⁴ |
| `completion` for unsupported shell | Error; exit code non-zero |
| `verify` on archive with issues | Issues printed; exit code non-zero when status is Fail |
| `verify` on a solid 7z archive without `--allow-solid-archives` | `Security Policy` failure, exit 1; with `--check-integrity` the integrity status is also `INCOMPLETE` (v0.7.0, #672) |
| `verify` without `--check-integrity` | `integrity_status` is `SKIPPED`; `--check-security` no longer exists (v0.7.0, #624) |
| `verify --decompression-budget` without `--check-integrity`, or with `0` | Rejected at argument parsing (v0.7.0) |
| `SecurityViolation` a `SecurityConfig` setting relaxes, `--json` | `error.relaxable_by` names the setting; the field is absent otherwise (v0.7.0, #741, #757) |
| `extract --atomic` fails and rolls back, `--json` | `error.partial_report.writes` is `rolled_back`; without `--atomic` it is `kept`, except for a TAR into a missing destination, which is atomic implicitly (v0.7.0, #725; v0.8.0, FR-097) |
| TAR extracted into a destination that does not exist, refused by a security check | Nothing is created, including no parent directory; human output says the partial extraction was discarded and the destination left unchanged (v0.8.0, FR-097) |
| `extract --atomic --force` onto a destination that is itself a symlink | Rejected on all platforms (GHSA-x8wr-7ww2-c94x, v0.6.0) — pass the resolved target path instead |
| `extract --atomic --force` where an intermediate destination path component is replaced with a symlink mid-extraction | Swap is confined to the pinned parent fd; a `dev`/`ino` identity mismatch immediately before the destructive swap aborts it with a distinct error (v0.6.0, #526) |
| `extract --atomic --force` fails after a mid-extraction redirect leaves a temp/backup directory behind at an unexpected path | Error output discloses the directory's actual current path, resolved via an open fd (v0.6.0, #530); in the ordinary non-redirected case, cleanup succeeds and nothing is disclosed or left behind |
| `extract --atomic --force` on Unix without search (execute) permission on the destination's parent directory | Fails — obtaining the pinned parent fd requires search (execute) permission on the parent, not read permission, and not on the destination itself, even when the destination does not yet exist (v0.6.0, #531, behavior change; read permission dropped in #1005) |
| `SecurityViolation` for a reason no policy flag controls (e.g. GHSA-5j8q-wxg5-hj4r size mismatch, password-protected archive) | HINT states it cannot be relaxed via any policy flag, instead of suggesting an irrelevant flag (v0.6.0, #520) |
| `PartialExtraction`-wrapped error | Category-specific HINT from the wrapped error is preserved, not replaced by the generic partial-extraction HINT (v0.6.0, #527) |
| `extract` pre-flight destination conflict with many pre-existing files | At most 10 conflicting paths listed (sorted), remainder collapsed into `... and N more` (v0.6.0, #500) |
| Human-readable size >= 1 TB (e.g. `u64::MAX` bytes) | Renders as `"...  TB"`, not an inflated GB figure (v0.6.0, #451) |
| `verify`/`list` on a TAR archive with a non-UTF8 entry name | `status: Warning` with a `Medium`-severity `SuspiciousPath` issue, not `Pass` (v0.6.0, #528/#529) — portability risk only, `security_status` unaffected |
| `exarch --verbose extract archive.tar.gz out --quiet` (global `--verbose`, subcommand-level `--quiet`) | Resolves deterministically to `Quiet` (no progress output, no summary) via `Verbosity::from_flags` (v0.6.1, #550, behavior change) — previously the progress reporter selected verbose output (verbose-wins) while the formatter suppressed the summary (quiet-wins), an inconsistency `clap`'s `conflicts_with` did not catch since the two flags parsed at different `ArgMatches` levels |

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

- [RESOLVED: `exarch verify --check-integrity` decodes the payload to the decoder's EOF (ZIP CRC-32, TAR framing, codec checksums, 7z CRC) with an optional `--decompression-budget`; integrity is `OK`, `FAILED`, `INCOMPLETE` or `SKIPPED` (#623). The check adds `Corrupt Data` and `Integrity Incomplete` issues, which are not security findings, but it can also add security-category issues (a forged ZIP declared size is `Security Policy`; 7z decoder memory and `max_solid_block_memory` refusals are `Quota Exceeded`), so `security_status` can be worse with the flag than without it.]
- [RESOLVED: `OUTPUT_DIR` is optional and defaults to the current directory (`ExtractArgs::output_dir`); the CLI skill advises passing it explicitly.]

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[003-config-api/spec]] — config types translated from CLI flags
- [[004-progress-tracking/spec]] — indicatif-based `ProgressCallback` used by CLI
- [[015-atomic-force-destination-swap-hardening/spec]] — `--atomic --force` symlink/TOCTOU hardening in detail
- [[019-verify-and-list-model/spec]] — list and verify output model
- [[020-reader-sink-and-in-memory-api/spec]] — WASI build and the in-memory APIs the CLI does not expose
- [[021-create-staging-and-output-policy/spec]] — staged `create`, `--force` and `-x`
- [[001-exarch-system/spec]] — original monolithic spec (archived)
