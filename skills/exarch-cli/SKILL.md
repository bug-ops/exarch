---
name: exarch-cli
description: Extract, create, list, and verify TAR (plus gz/bz2/xz/zst), ZIP, and 7z archives securely using the `exarch` CLI. Use whenever a task involves unpacking or building archives, especially from untrusted sources — exarch blocks path traversal, symlink/hardlink escapes, zip bombs, and oversized archives by default, and reports rejections as structured errors instead of silently succeeding.
license: MIT OR Apache-2.0
compatibility: Requires the `exarch` binary (cargo install exarch-cli, or build from this workspace with cargo build -p exarch-cli). MSRV 1.99.1 if building from source.
metadata:
  author: bug-ops
  version: "0.9.0"
---

# exarch CLI

`exarch` extracts, creates, lists, and verifies TAR (plain, `.gz`, `.bz2`, `.xz`, `.zst`), ZIP, and 7z archives (7z is extract/list/verify only). Extraction is deny-by-default: path traversal, symlink/hardlink escapes, zip bombs, oversized files/archives, and unsafe permission bits are rejected unless explicitly allowed. A security-related failure is the tool doing its job, not a bug to route around.

## Install

Check first: `command -v exarch`, then `command -v cargo`.

```bash
cargo install exarch-cli          # installs the binary `exarch`
cargo build -p exarch-cli         # inside this workspace; binary: ./target/debug/exarch
curl -fsSL https://raw.githubusercontent.com/bug-ops/exarch/main/scripts/install.sh | sh   # Linux/macOS, no toolchain
```

Manual download, checksum verification, and Windows: [references/install.md](references/install.md).

## Global flags

| Flag | Effect |
|---|---|
| `-v, --verbose` | Verbose output. Conflicts with `--quiet`. |
| `-q, --quiet` | Suppress non-error output. Conflicts with `--verbose`. |
| `-j, --json` | Machine-readable JSON envelope instead of text. Always use it when parsing output. |

## Subcommands

```bash
exarch extract archive.tar.gz ./out --json     # OUTPUT_DIR defaults to the CWD: always pass it
exarch create out.tar.gz src/ --json           # format comes from the OUTPUT extension
exarch list archive.zip -l -H --json
exarch verify archive.tar.gz --json
exarch completion zsh                          # bash | elvish | fish | powershell | zsh; script on stdout, no JSON envelope
```

### extract `<ARCHIVE> [OUTPUT_DIR]`

Common flags (full table, grammar, and edge cases: [references/extract.md](references/extract.md)):

| Flag | Default | Purpose |
|---|---|---|
| `--force` | off | Overwrite existing destination files (replaced via temp file + rename). |
| `--atomic` | off | Stage and rename into place on success; failure leaves the destination unchanged. |
| `--include` / `--exclude <GLOB>` | all | Select entries (repeatable; exclude wins). Also on `list` and `verify`. |
| `--strip-components <N>` / `--flatten` | off | Drop leading path components / land files at top level (mutually exclusive). |
| `--allowed-extensions <EXT>` | all | Extract only matching regular files (`txt,pdf`). |
| `--max-files` / `--max-total-size` / `--max-file-size` | 10000 / 500 MiB / 50 MiB | Hard quotas; size values take `K`/`M`/`G`/`T`. `0` is refused. `--max-files` counts every entry (directories, links, skipped entries included). |
| `--max-compression-ratio` | 100 | Zip-bomb threshold (ZIP and non-solid 7z). |
| `--max-path-depth` | 32 | Max path components per entry. |
| `--preserve-permissions` | off | Keep archive modes (setuid/setgid always stripped). |
| `--allow-symlinks` / `--allow-hardlinks` | off | Allow links that resolve inside the destination. |
| `--allow-absolute-paths` / `--allow-world-writable` / `--allow-solid-archives` | off | Relax the matching default-deny check. |
| `--zip-consistency <enforce\|ignore>` | enforce | ZIP structural ambiguity check. |
| `--banned-component <C>` | `.git .ssh .gnupg .aws .kube .docker .env` | **Replaces** the default list, never appends (see below). |

> **`--banned-component` replaces the default ban list.** `--banned-component foo` silently allows `.ssh`, `.aws`, etc. To add one component, repeat the flag with the full set plus the addition. An exactly empty value (`""`) disables all banning.

### create `<OUTPUT> <SOURCE>...`

| Flag | Default | Purpose |
|---|---|---|
| `-f, --force` | off | Replace an existing `OUTPUT` (otherwise `OutputExists`, exit `1`). |
| `-l, --compression-level <1-9>` | 6 | Shared 1-9 scale. |
| `-x, --exclude <GLOB>` | `.git`, `.DS_Store`, `*.tmp` | Repeatable; unsupported glob syntax is refused. |
| `--include-hidden` | off | Include dotfiles (hidden directories skipped whole otherwise). |
| `--follow-symlinks` | off | Store target contents instead of the link. |
| `--max-file-size <BYTES>` | none | Skip larger source files. |
| `--preserve-permissions[=true\|false]` | true | `=false` for a portable archive. |

Grammar, zip-ratio warning, name collisions, refused outputs (7z and ZIP-family extensions such as `.jar`, `.whl`, `.apk`): [references/create.md](references/create.md).

### list `<ARCHIVE>`

Flags: `-l/--long`, `-H/--human-readable` (requires `-l`), `--read-link-targets` (7z), `--allow-symlinks`, `--allow-hardlinks`, plus the quota, selection, `--zip-consistency` and `--allow-solid-archives` flags of `extract`. Exceeding a quota fails with `QuotaExceeded`; it never truncates. Details and JSON fields: [references/list.md](references/list.md).

### verify `<ARCHIVE>`

Runs the full security pipeline without writing to disk. Use it before `extract` on untrusted archives.

| Flag | Default | Purpose |
|---|---|---|
| `--strict` | off | Warning-level findings exit `3` instead of `0`. |
| `--check-integrity` | off | Decode the payload to EOF so checksums are verified. |
| `--decompression-budget <SIZE>` | 500 MiB | Extra decode budget for `--check-integrity`. |
| `--allow-symlinks` / `--allow-hardlinks` | off | Same as `extract`; pass the ones you will extract with. |

- A plain `verify` reports `integrity_status` `SKIPPED`: a pass says nothing about corruption.
- `INCOMPLETE` integrity exits `0` without `--strict`; in automation use `--strict` or read `data.integrity_status`.
- Archives over 500 MiB need `--max-total-size` raised, or `verify` fails with `QuotaExceeded`.
- 7z symlink targets are validated only under `--check-integrity`; gate 7z with `verify --strict` or `--check-integrity`.

Statuses, issue categories, limitations: [references/verify.md](references/verify.md).

## Do not reach for `--allow-*` reflexively

`--allow-symlinks`, `--allow-hardlinks`, `--allow-absolute-paths`, `--allow-world-writable`, `--allow-solid-archives`, `--zip-consistency ignore`, and `--force` weaken default-deny checks. When extraction fails with `SymlinkEscape`, `HardlinkEscape`, `PathTraversal`, `ZipBomb`, `InvalidPermissions`, `ZipInconsistency`, or `SecurityViolation`, the validator is rejecting something dangerous: **do not add the matching flag just to make the command succeed.** Add it only when the archive's origin is known to be trusted, and run `verify` first to see all findings. `--force` and `--atomic` affect overwrite behavior only, not validation; `--atomic --force` replaces the whole destination directory, so point it at a directory you mean to replace.

## `--json` output

Every subcommand prints one envelope:

```jsonc
{ "operation": "extract", "status": "success", "data": { /* per-command payload */ } }
{ "operation": "extract", "status": "error",
  "error": { "kind": "PathTraversal", "message": "...", "hint": "..." } }
```

- Branch on `error.kind`, `error.sub_code`, and `error.relaxable_by`, never on `message` text.
- **`verify` exception:** an unsafe archive still yields `status: "success"` with `data.status` `"PASS"`/`"WARNING"`/`"FAIL"` and exit `1` on `FAIL`. Branch on `data.status` or the exit code.
- On a mid-archive `extract` failure `error.partial_report.writes` is `"kept"` (items remain) or `"rolled_back"` (`--atomic`, or a TAR into a new destination).
- Skipped entries appear in `data.files_skipped`, `skipped_by_kind`, and `skipped_sample`, not as warnings.

Fields, sub-codes, `error.kind` enum, skip kinds, warnings, examples: [references/json-output.md](references/json-output.md).

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success (a closed stdout/broken pipe is also success). |
| `1` | Operation failed; also `verify` with `data.status` `FAIL`. |
| `2` | Argument-parser usage error (plain text, no JSON). |
| `3` | `verify --strict` with warning-level findings only. |
| `130` / `143` | `extract`/`create` stopped by SIGINT / SIGTERM (staging discarded; a second signal exits at once). Both stops end the process by the signal itself, so a parent that inspects the wait status sees a signal death, not exit code 130 or 143. A stop that lands after the last poll still lets the run finish and report its result, then ends the process the same way. On Unix a signal inherited as ignored (a job started under `trap "" INT`) is not handled: it never cancels a run and stays ignored. On Windows there is no signal death: both stops exit `130`. |

## Defaults at a glance

50 MiB per file, 500 MiB total, 100x compression ratio, 10,000 files, depth 32. Symlinks, hardlinks, absolute paths, world-writable files, and solid 7z are rejected. setuid/setgid are always stripped on Unix. Decoder-memory and 7z header limits have no CLI flag; see [references/security-model.md](references/security-model.md).

## References

Read only the file that matches the situation:

| File | Read when |
|---|---|
| [references/install.md](references/install.md) | `exarch` is missing and `cargo` is unavailable, or on Windows. |
| [references/extract.md](references/extract.md) | Tuning `extract`: `--atomic`/`--force` semantics, selection globs, quotas, destination conflicts, cancellation, `--decode-reuse` cost. |
| [references/create.md](references/create.md) | Building archives: exclude grammar, symlink handling, refused outputs, ZIP ratio warning. |
| [references/list.md](references/list.md) | Parsing `list` output, `disposition`, `link_target`. |
| [references/verify.md](references/verify.md) | Interpreting verify issues, integrity results, or verify/extract disagreement. |
| [references/formats.md](references/formats.md) | A TAR, ZIP, or 7z archive is refused as ambiguous, hidden, or unsupported. |
| [references/json-output.md](references/json-output.md) | Writing a script against `--json` output or error classification. |
| [references/security-model.md](references/security-model.md) | A quota, decoder-memory, 7z header, or Windows-name refusal needs explaining. |
