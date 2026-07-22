---
name: exarch-cli
description: Extract, create, list, and verify TAR (plus gz/bz2/xz/zst), ZIP, and 7z archives securely using the `exarch` CLI. Use whenever a task involves unpacking or building archives, especially from untrusted sources — exarch blocks path traversal, symlink/hardlink escapes, zip bombs, and oversized archives by default, and reports rejections as structured errors instead of silently succeeding.
license: MIT OR Apache-2.0
compatibility: Requires the `exarch` binary (cargo install exarch-cli, or build from this workspace with cargo build -p exarch-cli). MSRV 1.93.0 if building from source.
metadata:
  author: bug-ops
  version: "0.5.1"
---

# exarch CLI

`exarch` is a security-first archive tool. It extracts, creates, lists, and verifies TAR
(plain, `.gz`, `.bz2`, `.xz`, `.zst`), ZIP, and 7z archives. Every extraction runs through a
validation pipeline that is deny-by-default: path traversal, symlink/hardlink escapes outside
the destination directory, zip bombs (excessive compression ratio), oversized files/archives,
and unsafe permission bits (setuid/setgid, world-writable) are all rejected unless explicitly
allowed. If an extraction fails with a security-related error, treat that as the tool doing its
job, not a bug to route around (see "Do not reach for `--allow-*` reflexively" below).

## Install

```bash
cargo install exarch-cli
```

This installs a binary named `exarch` (not `exarch-cli`). Inside this workspace, use the debug
build instead:

```bash
cargo build -p exarch-cli
./target/debug/exarch --help
```

## Global flags

Available on every subcommand:

| Flag | Effect |
|---|---|
| `-v, --verbose` | Verbose output. Conflicts with `--quiet`. |
| `-q, --quiet` | Suppress non-error output. Conflicts with `--verbose`. |
| `-j, --json` | Emit a machine-readable JSON envelope instead of human-readable text (see below). Always prefer this when parsing output programmatically. |

## Subcommands

### `extract <ARCHIVE> [OUTPUT_DIR]`

```bash
exarch extract archive.tar.gz ./out --json
```

`OUTPUT_DIR` defaults to the **current directory** if omitted — always pass an explicit output
directory rather than relying on the default, so extraction is predictable and easy to clean up.

Key flags (all optional):

| Flag | Default | Purpose |
|---|---|---|
| `--force` | off | Overwrite existing files at the destination. |
| `--atomic` | off | Extract to a temp dir, rename into place on success, clean up on failure. With `--force`, the pre-existing destination is removed only after successful extraction (right before rename), minimizing the window with no valid data. |
| `--preserve-permissions` | off | Preserve file permissions from the archive (setuid/setgid are still stripped regardless). |
| `--max-files` | 10000 | Max number of entries to extract. |
| `--max-total-size` | 500 MB | Max cumulative extracted size. Accepts `K`/`M`/`G`/`T` suffixes, e.g. `2G`. |
| `--max-file-size` | 50 MB | Max size of any single extracted file. Same suffix syntax. |
| `--max-compression-ratio` | 100 | Max uncompressed/compressed ratio before an entry is treated as a zip bomb. |
| `--max-path-depth` | 32 | Max path component depth allowed per entry. |
| `--allowed-extensions <EXT>` | all allowed | Restrict extraction to matching extensions. Repeatable or comma-separated (`txt,pdf`); leading dot optional, case-insensitive. |
| `--allow-symlinks` | off | Allow symlinks that resolve within the extraction directory. |
| `--allow-hardlinks` | off | Allow hardlinks that resolve within the extraction directory. |
| `--allow-absolute-paths` | off | Allow archive entries with absolute paths. |
| `--allow-world-writable` | off | Allow files with world-writable (mode `0o002`) permission bits. |
| `--allow-solid-archives` | off | Allow solid 7z archives (see Security model below). |
| `--banned-component <COMPONENT>` | see below | Block entries whose path contains this component. **Replaces** the default list — see warning below. Repeatable. |

> [!WARNING]
> **`--banned-component` REPLACES the default ban list, it does not append to it.** The default
> blocks path components `.git`, `.ssh`, `.gnupg`, `.aws`, `.kube`, `.docker`, `.env`. Passing
> `--banned-component foo` drops ALL of those defaults and blocks only `foo` — silently letting
> `.ssh`, `.aws`, etc. through. If you need one extra banned component, repeat the flag with the
> full desired set, not just the addition: `--banned-component .git --banned-component .ssh
> --banned-component .gnupg --banned-component .aws --banned-component .kube --banned-component
> .docker --banned-component .env --banned-component foo`. Passing an empty value disables all
> banning.

### `create <OUTPUT> <SOURCE>...`

```bash
exarch create out.tar.gz src/ --json
```

| Flag | Default | Purpose |
|---|---|---|
| `-f, --force` | off | Overwrite `OUTPUT` if it already exists. |
| `-l, --compression-level <1-9>` | format default | Compression level. |
| `-x, --exclude <PATTERN>` | none | Glob exclude pattern; repeatable. |
| `--strip-prefix <PREFIX>` | none | Strip a path prefix from entry names. |
| `--include-hidden` | off | Include dotfiles/hidden entries. |
| `--follow-symlinks` | off | Follow symlinks when walking source trees (stores target contents, not the link). |
| `--max-file-size <BYTES>` | none | Skip source files larger than this (`K`/`M`/`G`/`T` suffixes). |
| `--preserve-permissions[=true\|false]` | `true` | Preserve platform permission bits. Pass `--preserve-permissions=false` for a portable, permission-agnostic archive. |

`exarch` refuses to *create* 7z archives (7z is extract-only) and refuses to create archives
under ZIP-family extensions that carry extra format semantics: `.jar`, `.war`, `.ear`, `.nar`,
`.nbm`, `.apk`, `.aab`, `.ipa`, `.appx`, `.msix`, `.whl`, `.vsix`, `.xpi`, `.epub` — use plain
`.zip` for those cases.

### `list <ARCHIVE>`

```bash
exarch list archive.zip -l -H --json
```

| Flag | Default | Purpose |
|---|---|---|
| `-l, --long` | off | Detailed per-entry info (type, size, mode, timestamps, link targets). |
| `-H, --human-readable` | off | Human-readable sizes in text mode (ignored in `--json` mode, which always emits raw byte counts). |
| `--max-files` | 10000 | Hard limit on entries scanned; listing fails with `QuotaExceeded` past this count, it does not truncate. |
| `--max-total-size` | 500 MB | Hard limit on cumulative listed size; listing fails with `QuotaExceeded` past this size. Raise it explicitly for larger archives. |
| `--allow-solid-archives` | off | Allow listing solid 7z archives (higher memory use). |

### `verify <ARCHIVE>`

```bash
exarch verify archive.tar.gz --check-integrity --check-security --json
```

| Flag | Default | Purpose |
|---|---|---|
| `--check-integrity` | off | Validate checksums/structure. |
| `--check-security` | off | Run the security validation pipeline (path traversal, symlink/hardlink, permissions) without extracting. |
| `--strict` | off | Treat any warning-level finding as an error and exit with status `2` instead of `0`. |
| `--max-files` / `--max-total-size` / `--allow-solid-archives` | same as `list` (10000 / 500 MB / off) | Same hard-limit semantics as `list` — verification fails with `QuotaExceeded` past these caps, it does not skip entries. |

Run `verify` before `extract` on any archive from an untrusted source to inspect issues without
writing anything to disk. Archives over 500 MB need `--max-total-size` raised explicitly or
`verify` will fail with `QuotaExceeded` before it can report anything else.

> [!WARNING]
> **When the archive has `status: "FAIL"`, `verify --json` prints TWO concatenated top-level
> JSON objects to stdout, not one.** Verified live (with and without `--strict`) on an archive
> containing a bare symlink entry: stdout contains a `status: "success"` envelope with the full
> report (`data.status: "FAIL"`, findings in `data.issues`), immediately followed by a second
> `status: "error"` envelope (`error.kind: "Error"`, generic message `"Archive verification
> failed"`). The process exits `1` in both cases. A naive `json.loads(stdout)` will fail on this
> output — split on the `}\n{` boundary, or use a streaming/multi-document JSON parser, and treat
> the first object's `data` as the authoritative report.

### `completion <SHELL>`

```bash
exarch completion zsh > ~/.zsh/completions/_exarch
```

Valid `<SHELL>` values (case-sensitive, exact set): `bash`, `elvish`, `fish`, `powershell`, `zsh`.

## Do not reach for `--allow-*` reflexively

`--allow-symlinks`, `--allow-hardlinks`, `--allow-absolute-paths`, `--allow-world-writable`,
`--allow-solid-archives`, and `--force` all weaken a default-deny security check. When an
extraction fails with `SymlinkEscape`, `HardlinkEscape`, `PathTraversal`, `ZipBomb`,
`InvalidPermissions`, or `SecurityViolation`, that is the validator correctly rejecting
something dangerous — **do not add the matching `--allow-*` flag just to make the command
succeed.** Only add it when the archive's origin and contents are already known to be trusted,
and prefer re-running just `verify --check-security` first to see the full list of findings
before deciding. `--force` (extract/create) and `--atomic` (extract) are safe to use more
liberally since they affect overwrite behavior, not path/link/permission validation.

## `--json` output envelope

Every subcommand's `--json` output uses the same envelope:

```jsonc
// success
{
  "operation": "extract" | "create" | "list" | "verify",
  "status": "success",
  "data": { /* per-command payload, see below */ }
}

// error
{
  "operation": "extract" | "create" | "list" | "verify",
  "status": "error",
  "error": {
    "kind": "PathTraversal",   // see full enum below
    "message": "..."
  }
}
```

`data` is absent on error, `error` is absent on success.

For `extract`, when some files were already written before a mid-archive failure, the JSON
schema has a structured `error.partial_report` field defined for exactly this case — but as of
0.5.1 it is never actually populated; verified live against a two-entry archive where the first
entry extracts and the second exceeds `--max-file-size`. The partial-progress counts are instead
embedded as free text inside `error.message`, prefixed `"WARNING: Extraction was stopped. N
items (X files, Y directories, Z symlinks) were written to disk before the error."`. Parse that
prefix (or just treat any `error.message` starting with `"WARNING:"` as "some data was written")
if you need this information — do not branch on an `error.partial_report` object appearing.

### Verified examples

Success (`extract`):

```json
{
  "operation": "extract",
  "status": "success",
  "data": {
    "files_extracted": 1,
    "directories_created": 0,
    "symlinks_created": 0,
    "bytes_written": 6,
    "duration_ms": 0
  }
}
```

Error (`extract`, path traversal):

```json
{
  "operation": "extract",
  "status": "error",
  "error": {
    "kind": "PathTraversal",
    "message": "failed to list archive: evil.tar: path traversal detected: ../../etc/passwd"
  }
}
```

Error (`extract`, mid-archive quota failure with partial progress — note there is no
`partial_report` field, only the `"WARNING:"`-prefixed text in `message`):

```json
{
  "operation": "extract",
  "status": "error",
  "error": {
    "kind": "QuotaExceeded",
    "message": "WARNING: Extraction was stopped. 1 items (1 files, 0 directories, 0 symlinks) were written to disk before the error.\nHINT: Inspect or remove the output directory before re-running.: quota exceeded: single file size (100 > 10)"
  }
}
```

### `error.kind` enum

`IoError`, `InvalidArchive`, `PathTraversal`, `SymlinkEscape`, `HardlinkEscape`, `ZipBomb`,
`InvalidPermissions`, `QuotaExceeded`, `SecurityViolation`, `SourceNotFound`,
`SourceNotAccessible`, `OutputExists`, `InvalidCompressionLevel`, `UnknownFormat`,
`InvalidConfiguration`, or the generic `Error` fallback for failures that don't originate from
the archive validation pipeline (e.g. unexpected I/O outside archive handling). Branch on this
field rather than parsing `message`, which is a free-text, human-oriented string and not stable
across versions.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success. |
| `1` | Operation failed (see `error.kind` in JSON mode, or stderr in text mode). |
| `2` | `verify --strict` only: the archive is otherwise valid but has warning-level findings, treated as failure because `--strict` was passed. |

## Security model (context, not a full manual)

Default `SecurityConfig` limits: 50 MB per file, 500 MB total extracted size, 100x max
compression ratio, 10,000 max files, 32 max path depth. All symlinks, hardlinks, absolute
paths, and world-writable files are rejected unless explicitly allowed. setuid/setgid bits are
always stripped on Unix regardless of `--preserve-permissions`. Solid 7z archives (multiple
files compressed as one block) are rejected by default because extracting even one file
requires decompressing the whole block into memory — a memory-exhaustion vector; enable
`--allow-solid-archives` only for trusted archives, and consider it isn't a substitute for
enough free memory. If an operation is rejected for one of these reasons, that's the security
pipeline working as intended, not a defect to work around by default.
