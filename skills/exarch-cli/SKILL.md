---
name: exarch-cli
description: Extract, create, list, and verify TAR (plus gz/bz2/xz/zst), ZIP, and 7z archives securely using the `exarch` CLI. Use whenever a task involves unpacking or building archives, especially from untrusted sources — exarch blocks path traversal, symlink/hardlink escapes, zip bombs, and oversized archives by default, and reports rejections as structured errors instead of silently succeeding.
license: MIT OR Apache-2.0
compatibility: Requires the `exarch` binary (cargo install exarch-cli, or build from this workspace with cargo build -p exarch-cli). MSRV 1.96.0 if building from source.
metadata:
  author: bug-ops
  version: "0.5.2"
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

First check whether a Rust toolchain is present: `command -v cargo`.

**`cargo` available (recommended):**

```bash
cargo install exarch-cli
```

This installs a binary named `exarch` (not `exarch-cli`) and is the fastest path to a working
binary since it doesn't require identifying the target triple. Inside this workspace, use the
debug build instead:

```bash
cargo build -p exarch-cli
./target/debug/exarch --help
```

**`cargo` NOT available:**

*Linux / macOS* — run the install script, no toolchain required, checksum-verified:

```bash
curl -fsSL https://raw.githubusercontent.com/bug-ops/exarch/main/scripts/install.sh | sh
```

Installs to `~/.local/bin` (override with `EXARCH_INSTALL_DIR`). If the script itself can't run
(e.g. a restricted shell), fall back to a manual download: get `exarch-<version>-<target>.tar.gz`
plus its `.sha256` from [GitHub Releases](https://github.com/bug-ops/exarch/releases) —
`<target>` is `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`, or
`aarch64-apple-darwin` — then verify and extract:

```bash
sha256sum -c exarch-<version>-<target>.tar.gz.sha256   # macOS: shasum -a 256 -c
tar -xzf exarch-<version>-<target>.tar.gz
```

*Windows* — no install script; download `exarch-<version>-x86_64-pc-windows-msvc.zip` plus its
`.sha256` from [GitHub Releases](https://github.com/bug-ops/exarch/releases), then verify and
extract in PowerShell:

```powershell
(Get-FileHash exarch-<version>-x86_64-pc-windows-msvc.zip -Algorithm SHA256).Hash
# compare (case-insensitively) against the hash in the .sha256 file, then:
Expand-Archive exarch-<version>-x86_64-pc-windows-msvc.zip -DestinationPath .
```

`CertUtil -hashfile exarch-<version>-x86_64-pc-windows-msvc.zip SHA256` is an equivalent,
cmd-only alternative to `Get-FileHash`.

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
| `--atomic` | off | Extract to a temp dir, rename into place on success, clean up on failure. With `--force` and a pre-existing destination, the swap is a backup-then-replace: the existing destination is renamed aside first, the new content is renamed into its place second, and only once that swap succeeds is the old destination removed — never before, so a failure at any point still leaves either the old or the new content in place under the destination name. On Unix, `--force` also requires read permission on the destination's parent directory (used to pin it by file descriptor for the swap); the destination itself does not need to be readable. With `--force`, a destination that is itself a symlink is now rejected — pass the resolved target path instead. Without `--force`, a symlinked destination isn't rejected as such, but the final rename onto it fails (`ENOTDIR` on Unix, `OutputExists` on Windows), since `rename` doesn't follow a symlink at the target — pass the resolved target path here too. Plain (non-atomic) `extract` is unaffected: it resolves a symlinked destination via `canonicalize()` and writes through it, matching `tar -C`/`unzip -d` (see #533). If a failed `--atomic --force` run leaves temp/backup content behind (e.g. an intermediate parent-path component was redirected mid-extraction), the error message discloses that content's actual location — see #530. |
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

> [!NOTE]
> With `--follow-symlinks` off (default), a symlink passed directly as a source (file or
> directory) is archived as a link in TAR; ZIP has no symlink entry type, so it is skipped
> instead (warning + `files_skipped`). With `--follow-symlinks` on, both TAR and ZIP dereference
> the symlink and store the target's content — for a directory symlink, this means walking and
> archiving the entire target tree.

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
| `--max-file-size` | 50 MB | Hard limit on any single entry's size; listing fails with `QuotaExceeded` (`FileSize`) past this size. Raise it explicitly for archives with large individual files. |
| `--allow-solid-archives` | off | Allow listing solid 7z archives (higher memory use). |

Verified live: a 51 MB tar entry fails `exarch list` with
`"quota exceeded: single file size (53477376 > 52428800)"` at the 50 MB default, and succeeds
once `--max-file-size 100M` is passed.

### `verify <ARCHIVE>`

```bash
exarch verify archive.tar.gz --check-integrity --check-security --json
```

| Flag | Default | Purpose |
|---|---|---|
| `--check-integrity` | off | Validate checksums/structure. |
| `--check-security` | off | Run the security validation pipeline (path traversal, symlink/hardlink, permissions) without extracting. |
| `--strict` | off | Treat any warning-level finding as an error and exit with status `2` instead of `0`. |
| `--max-files` / `--max-total-size` / `--max-file-size` / `--allow-solid-archives` | same as `list` (10000 / 500 MB / 50 MB / off) | Same hard-limit semantics as `list` for file count and total size — verification fails with `QuotaExceeded` past those two caps, it does not skip entries. |

Run `verify` before `extract` on any archive from an untrusted source to inspect issues without
writing anything to disk. Archives over 500 MB need `--max-total-size` raised explicitly or
`verify` will fail with `QuotaExceeded` before it can report anything else.

`--max-file-size` is the one exception to "fails with `QuotaExceeded`": an entry over this cap
does **not** abort `verify` early. `verify`'s internal pre-flight listing pass always allows
entries of any size through, then re-checks the real `--max-file-size` per entry and records a
violation as a `HIGH`-severity `QuotaExceeded` issue, same as any other security finding —
`data.status` becomes `"FAIL"` with the issue itemized, `status` (the envelope) stays
`"success"`, same as the `verify` "one exception" rule described under `--json` output envelope
below. Verified live: a 51 MB tar entry against the 50 MB default produces `data.status: "FAIL"`
with one `HIGH` `"Quota Exceeded"` issue and exit code `1`; the same command with
`--max-file-size 100M` produces `data.status: "PASS"` and exit code `0`.

When the archive has `status: "FAIL"`, `verify --json` prints exactly one top-level JSON
document to stdout — a `status: "success"` envelope carrying the full report (`data.status:
"FAIL"`, findings in `data.issues`). Verified live on an archive containing a bare symlink
entry: a single valid JSON document, parseable with a plain `json.loads(stdout)`. The process
still exits `1` for a FAIL status.

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

**`verify` is the one exception to "top-level `status` tells you whether it worked":** a FAIL-status
archive still yields a `status: "success"` envelope (the verification *ran* successfully — it just
found the archive unsafe), with the outcome in `data.status` (`"PASS"` / `"WARNING"` / `"FAIL"`).
For `verify`, branch on `data.status` (or the process exit code), not on top-level `status`.

For `extract`, when some files were already written before a mid-archive failure, `error` carries
a structured `error.partial_report` object (`files_extracted`, `directories_created`,
`symlinks_created`, `bytes_written`, `files_skipped`, `warnings`). Verified live against a
three-entry archive where the first entry extracts, the second is skipped for a disallowed
extension (via `--allowed-extensions`), and the third is a symlink rejected by the (default-off)
`--allow-symlinks` check. The same progress counts, skip count, and warnings also appear as free
text inside `error.message` (prefixed `"WARNING: Extraction was stopped. ..."`, with optional
`"Files skipped: N"` / `"Warnings:"` lines when non-empty) — prefer the structured
`error.partial_report` field over parsing that text.

Note: `extract` always lists the archive first (`list_archive()`, sharing `--max-file-count`,
`--max-total-size`, and `--max-file-size` with the extraction config) to detect output
conflicts and size the progress bar. Quota violations (file count, total size, per-file size)
are therefore caught during this pre-flight pass and reported as a plain error with **no**
`partial_report`, since extraction never starts. Only checks that require the real destination
directory — symlink/hardlink escape — can still produce a mid-archive partial extraction.

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
    "files_skipped": 0,
    "duration_ms": 0,
    "warnings": []
  }
}
```

`files_skipped` and `warnings` are populated whenever entries are skipped without failing the
extraction — e.g. `--allowed-extensions` rejecting entries by extension, or duplicate destination
files skipped under `--skip-duplicates` semantics (the default when `--force` is absent).
Verified live with a mixed-extension archive extracted via `--allowed-extensions txt`:

```json
{
  "operation": "extract",
  "status": "success",
  "data": {
    "files_extracted": 3,
    "directories_created": 1,
    "symlinks_created": 0,
    "bytes_written": 18,
    "files_skipped": 2,
    "duration_ms": 0,
    "warnings": [
      "skipped 2 entries with disallowed extensions"
    ]
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

Error (`extract`, mid-archive security failure with partial progress — note the structured
`error.partial_report` field, including `files_skipped`/`warnings`; the archive's first entry
extracts, its second entry is skipped for a disallowed extension, then a symlink entry is
rejected because `--allow-symlinks` was not passed):

```json
{
  "operation": "extract",
  "status": "error",
  "error": {
    "kind": "SecurityViolation",
    "message": "WARNING: Extraction was stopped. 1 items (1 files, 0 directories, 0 symlinks) were written to disk before the error.\nFiles skipped: 1\nWarnings:\n  - skipped 1 entry with disallowed extension\nHINT: Inspect or remove the output directory before re-running.: operation denied by security policy: symlinks not allowed",
    "partial_report": {
      "files_extracted": 1,
      "directories_created": 0,
      "symlinks_created": 0,
      "bytes_written": 5,
      "files_skipped": 1,
      "warnings": [
        "skipped 1 entry with disallowed extension"
      ]
    }
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
| `1` | Operation failed (see `error.kind` in JSON mode, or stderr in text mode). **Exception:** `verify --json` on a FAIL-status archive also exits `1`, but prints a `status: "success"` envelope with `data.status: "FAIL"` — there is no `error` object in this case. Check `data.status`, not top-level `status`, for `verify`. |
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
