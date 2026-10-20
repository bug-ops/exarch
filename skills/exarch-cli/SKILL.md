---
name: exarch-cli
description: Extract, create, list, and verify TAR (plus gz/bz2/xz/zst), ZIP, and 7z archives securely using the `exarch` CLI. Use whenever a task involves unpacking or building archives, especially from untrusted sources — exarch blocks path traversal, symlink/hardlink escapes, zip bombs, and oversized archives by default, and reports rejections as structured errors instead of silently succeeding.
license: MIT OR Apache-2.0
compatibility: Requires the `exarch` binary (cargo install exarch-cli, or build from this workspace with cargo build -p exarch-cli). MSRV 1.98.0 if building from source.
metadata:
  author: bug-ops
  version: "0.6.1"
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
| `--max-compression-ratio` | 100 | Max uncompressed/compressed ratio before an entry is treated as a zip bomb. Applies to ZIP and non-solid 7z; it does **not** apply to solid 7z blocks. With `--allow-solid-archives`, each solid block is checked as a whole against a fixed 1000x limit (`max_solid_compression_ratio`, Rust API only, not configurable from the CLI). An entry that declares data but zero compressed bytes is always a zip bomb with ratio `unbounded` and no ratio limit admits it; its `HINT` says the size metadata is inconsistent rather than suggesting this flag. |
| `--max-path-depth` | 32 | Max path component depth allowed per entry. |
| `--allowed-extensions <EXT>` | all allowed | Restrict extraction to matching extensions. Repeatable or comma-separated (`txt,pdf`); leading dot optional, case-insensitive. |
| `--allow-symlinks` | off | Allow symlinks that resolve within the extraction directory. |
| `--allow-hardlinks` | off | Allow hardlinks that resolve within the extraction directory. |
| `--allow-absolute-paths` | off | Allow archive entries with absolute paths. For ZIP the leading root or drive prefix is stripped, so the entry lands under the destination (`/tmp/x` extracts to `<dest>/tmp/x`). |
| `--allow-world-writable` | off | Allow files with world-writable (mode `0o002`) permission bits. |
| `--allow-solid-archives` | off | Allow solid 7z archives (see Security model below). |
| `--zip-consistency <enforce\|ignore>` | enforce | ZIP only. `enforce` rejects an archive whose structure different ZIP readers interpret differently (see "ZIP structure" under `verify`); `ignore` keeps the central-directory interpretation and raises no structural finding. Relax it only for archives from a producer you trust. |
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
| `--zip-consistency <enforce\|ignore>` | enforce | Same as `extract`: under `enforce` a ZIP with ambiguous structure fails with `ZipInconsistency` instead of being listed. |

Verified live: a 51 MB tar entry fails `exarch list` with
`"quota exceeded: single file size (53477376 > 52428800)"` at the 50 MB default, and succeeds
once `--max-file-size 100M` is passed.

### `verify <ARCHIVE>`

```bash
exarch verify archive.tar.gz --json
```

| Flag | Default | Purpose |
|---|---|---|
| `--strict` | off | Treat any warning-level finding as an error and exit with status `2` instead of `0`. |
| `--check-integrity` | off | Decode the payload to the decoder's EOF so checksums and codec framing are verified. See "Payload integrity" below. |
| `--decompression-budget <SIZE>` | 500M | Extra bytes `--check-integrity` may decode beyond what listing already decodes (`K`/`M`/`G`/`T` suffixes). Requires `--check-integrity`; `0` is rejected. Fixed default: it does not follow `--max-total-size`, so raise both for archives over 500 MB. |
| `--allow-symlinks` / `--allow-hardlinks` | off | Same flags and semantics as `extract`: links that resolve within the extraction directory are accepted, escaping links still fail. `verify` accepts only these two policy flags (plus `--zip-consistency`, `--max-files`, `--max-total-size`, `--max-file-size`, `--allow-solid-archives`, `--check-integrity`, `--decompression-budget` and `--strict`); it has no `--max-compression-ratio`, `--max-path-depth`, `--banned-component`, `--allow-absolute-paths` or `--allow-world-writable`, so pass the link flags you intend to extract with, and expect extraction-only options to be evaluated by `extract` alone. |
| `--zip-consistency <enforce\|ignore>` | enforce | ZIP only. Under `enforce`, structural findings are reported as issues (see "ZIP structure" below); under `ignore` none are raised. |
| `--max-files` / `--max-total-size` / `--max-file-size` / `--allow-solid-archives` | same as `list` (10000 / 500 MB / 50 MB / off) | Same hard-limit semantics as `list` for file count and total size — verification fails with `QuotaExceeded` past those two caps, it does not skip entries. |

`verify` always runs the full security validation pipeline (path traversal, symlink/hardlink, permissions) without extracting. By default it does not validate payload checksums: `integrity_status` is `SKIPPED` (`Integrity: SKIPPED` in text mode), so a passing `verify` says nothing about data corruption. Pass `--check-integrity` for that.

#### Payload integrity (`--check-integrity`)

`integrity_status` is `OK`, `FAILED`, `INCOMPLETE` or `SKIPPED` (JSON `data.integrity_status`, text `Integrity: ...`):

| Value | Meaning | Exit code |
|---|---|---|
| `OK` | Every payload byte was decoded and every checksum the format has matched. | `0` |
| `FAILED` | A checksum or decoder error proved the payload corrupt: a `HIGH` `"Corrupt Data"` issue, attributed to the entry where one owns it (`entry_path` is `null` for a stream trailer such as a gzip CRC). | `1` |
| `INCOMPLETE` | Part of the payload was not verified; one `MEDIUM` `"Integrity Incomplete"` issue lists the counts per reason, so `status` is at least `WARNING`. | `0`, or `2` with `--strict` |
| `SKIPPED` | `--check-integrity` was not passed. | n/a |

**Exit code `0` does not mean integrity `OK`**: `INCOMPLETE` exits `0` unless `--strict` is passed, so use `--strict` (or read `data.integrity_status`) in automation. Reasons an item is unverified: decompression budget exhausted, quota/ratio/decoder-memory limit, a solid 7z archive while `--allow-solid-archives` is off, a 7z block checksum that the entries do not cover, an unsupported 7z coder, and a TAR stream with no end-of-archive marker. Verified live: `tests/fixtures/solid.7z` gives `Integrity: INCOMPLETE` (`solid archive with allow_solid_archives off`) with exit `0`, exit `2` with `--strict`, and `Integrity: OK` with `--allow-solid-archives`.

What `OK` covers per format:

| Format | Checked |
|---|---|
| ZIP | Per-entry CRC-32 and the exact declared size. Entries are independent: a corrupt entry is reported and the scan continues. A symlink target is read through the same check. |
| TAR | Header checksums and that every declared data byte is present. No payload checksum exists, so `OK` means complete and decodable. |
| tar.gz / tar.bz2 / tar.xz / tar.zst | The above plus the codec's framing and checksums (gzip CRC-32 and size, bzip2 CRC, xz block check, zstd content checksum only if the frame carries one). |
| 7z | Per-entry CRC-32 where the archive stores one, else the block CRC (which can only fire once the whole block is read and is attributed to the block's last entry). LZMA/LZMA2/PPMd validity. Entries without any CRC get the weaker "decodable" guarantee. |

"Decode to EOF" means the decoder's EOF: bytes after the first gzip member or xz stream are not read, and zstd reads concatenated frames (bounded by the budget). The budget covers only decoding beyond what listing already does: ZIP entries and 7z blocks are charged their declared size before decoding (first-fit, so one large entry does not block later small ones), TAR entries are never charged (listing decodes them anyway), and for compressed TAR it bounds the read from the end marker to decoder EOF. A TAR stream must have at least one byte after the entry list; one that stops at a header boundary is `INCOMPLETE`.

A TAR entry whose content fails to decode (corrupt deflate block, data cut short) is a hard error with exit `1` (`invalid archive: integrity check failed at <path>: ...`), not a report, because the scan cannot continue past it. Corruption that only a trailer check catches (gzip CRC, bzip2 or xz trailer) is a `FAILED` report. Verified live: a `.tar.gz` with a flipped CRC byte gives `Integrity: FAILED` with a `Corrupt Data` issue and exit `1`; a truncated `.tar.gz` fails with `incomplete deflate stream` and exit `1`; a ZIP with a flipped payload byte gives `Integrity: FAILED` naming the entry and exit `1`, while plain `verify` of the same ZIP is `Integrity: SKIPPED` and exits `0`.

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

`data.issues[].category` is one of `"Path Traversal"`, `"Symlink Escape"`, `"Hardlink Escape"`,
`"Zip Bomb"`, `"Invalid Permissions"`, `"Quota Exceeded"`, `"Security Policy"`,
`"Invalid Archive"`, `"Suspicious Path"`, `"Executable File"`, `"Corrupt Data"`,
`"Integrity Incomplete"`, `"Header Mismatch"`, `"Duplicate Entry"`, `"Overlapping Entries"`,
`"Hidden Entry"`, `"Name Collision"`. `"Corrupt Data"` and `"Integrity Incomplete"` come only from
`--check-integrity` and are not security findings, but `--check-integrity` can also add
security-category issues (`"Security Policy"` for a forged ZIP declared size, `"Quota Exceeded"` for 7z
decoder memory or `max_solid_block_memory`), so `Security:` can be `FAILED` with the flag on an archive
that is `OK` without it. `"Security Policy"` covers entries
rejected by the configured policy rather than by an attack check: a symlink or hardlink under the
default config (`Security violation: symlinks not allowed` / `hardlinks not allowed`), NUL bytes,
banned components. These are security findings: `security_status` is `FAILED` (`Security:
FAILED` in text mode), not `OK`. Verified live with the debug binary on a TAR containing a
symlink and on one containing a hardlink: each gives `status: FAIL`, `Security: FAILED`, one
`HIGH` `"Security Policy"` issue, exit code `1`.
Consequently `exarch verify` exits `1` with `Security: FAILED` for any TAR containing a hardlink or
symlink unless `--allow-symlinks` / `--allow-hardlinks` is passed, mirroring `extract`. Verified live
on a TAR with one internal symlink and one internal hardlink: no flags gives two `HIGH` findings and
exit `1`; `--allow-symlinks` alone leaves only the hardlink finding; both flags give `PASS` and exit
`0`. A link that escapes the destination still fails with either flag.

**Limitations.**

- `verify` models only the archive's own entries. It cannot see files, directories or links already present in the extraction destination, so a `PASS` does not guarantee that extraction into a non-empty destination succeeds.
- Symlink chains are resolved with a per-OS hop limit in `verify`'s model: macOS 33, Linux glibc 40, Linux musl 39, Windows 63 (not verified on a Windows host), other Unix 32. The first three match `std::fs::canonicalize`, which `extract` uses; a different filesystem or kernel configuration can still disagree, so a `PASS` does not guarantee that a deep chain extracts. Verified live on macOS: chains of up to 34 links pass `verify` and `extract`, a 35-link chain fails both.
- A hardlink whose target does not exist in the archive fails with `Invalid archive: hardlink target does not exist: <target>`, matching `extract`.
- `verify` reports as `HIGH` issues (exit `1`) the entry shapes the host rejects: an entry beneath a regular file (`I/O error: not a directory`), a directory over an existing file (`I/O error: entity already exists`), a parent chain that loops or leaves the destination, a hardlink whose target is a directory (`hardlink target is a directory: <target>`), and an entry, symlink target or hardlink target with a name component over 255 bytes or a path over 4096 bytes (`I/O error: file name too long`).
- `verify` has no overwrite option and models first-entry-wins extraction. Without `--force`, `extract` skips a later entry at an already-written path (verified live: entries `f`=`one` then `f`=`two` leave `one`, with a `skipped 1 entry as pre-existing duplicates` warning); with `--force` a later entry overwrites it (the same archive leaves `two`). `verify` cannot model the `--force` outcome and reports an issue where a symlink entry follows an earlier file entry at the same path, even though plain `extract` skips that symlink.
- On macOS names are compared after NFD and a per-character case fold, on Windows after the same fold without normalisation, elsewhere exactly. Two entries whose names differ but compare equal under that fold are reported as a `"Name Collision"` issue, never merged silently: `HIGH` when their kinds differ or a symlink is involved (a hardlink over a file counts as a file), `MEDIUM` for two files or for two directories that hold entries (`status` `WARNING`, `Security: WARNING`), `LOW` for two directories that hold no entries (listed, but `status` stays `PASS` and `Security: OK`). A spelling is reported once, however many entries use it. Verified live on macOS: `café.txt` in NFC and NFD spellings, `straße.txt` and `straẞe.txt`, `a.txt` and `A.txt`, and `Dir/a.txt` with `dir/b.txt` give `MEDIUM`; the empty directory entries `Dir/` and `dir/` give `LOW`. The fold approximates the host's table, so a pair it merges that the host keeps apart is reported too.
- Windows component checks (reserved device names, alternate data streams, trailing dot or space) run only when `verify` itself runs on a Windows host, so results are not host-independent.

**ZIP structure.** A ZIP stores each entry's metadata twice, in a local header and in the central
directory; random-access readers follow the directory and streaming readers follow the local
headers, so an archive whose copies differ shows different content to different tools. Under the
default `--zip-consistency enforce`, `extract` and `list` fail with `ZipInconsistency` (exit `1`,
nothing written, `error.kind` `ZipInconsistency`) and `verify` reports each finding as a `HIGH`
issue when the archive:

- has a local header that disagrees with its central directory record on the file name, a Unicode Path extra field, compression method, encryption flag, data-descriptor flag, modification time, CRC-32 or sizes (`"Header Mismatch"`; a local header that cannot be parsed at all is reported the same way);
- repeats an entry name (`"Duplicate Entry"`; the `zip` crate keeps only the last record, `verify` still counts every record in `total_entries`);
- has entries whose data ranges overlap (`"Overlapping Entries"`);
- holds central directory records beyond the count in its end record, or a local header that no central directory record maps (`"Hidden Entry"`): before the archive (offset 0), between entries, behind padding, or just before the directory. A streaming reader extracts such an entry and a random-access reader never lists it.

`total_entries` of a ZIP report is the raw central directory count. A raw count over `--max-files` is
a `QuotaExceeded` error (`quota exceeded: file count (20000 > 10000)`, exit `1`) from `extract`,
`list` and `verify` under both policies, even when most records share one name. Verified live
with crafted archives built with Python: a two-record directory whose end record counts one
(`Total entries: 2`, two `"Hidden Entry"` issues), a local header inserted before the directory
(`"Hidden Entry"`), two entries named `a.txt` (`"Duplicate Entry"`, `Total entries: 2`) and an
archive with 20000 records named `a.txt`; each passes with `--zip-consistency ignore` (except the
last, which stays a `QuotaExceeded` error), where `extract` writes what it always did. Archives from
Info-ZIP, `ditto`, 7-Zip, `bsdtar`, Go and Python's `zipfile`, including streamed archives
with data descriptors, produce no findings; archives from Java's `jar` and from Windows producers
(Explorer, WinRAR, .NET) were not tested. Not covered: a descriptor, local header and data hidden
inside the declared range of a data-descriptor entry (streaming readers end such an entry at the
end of its compressed stream, `zip` at the declared size; verified live that `bsdtar` extracts it
while `exarch` passes), central directory records before the directory start, the bytes between
offset 0 and the start of the archive (only offset 0 is checked, since self-extracting stubs embed
the signature), and an earlier end-of-central-directory candidate that the `zip` crate falls back
to. Pre-ZIP64 archives
with more than 65535 entries (a wrapped end-record count) and archives with orphaned local headers
left by in-place updaters are rejected under `enforce`; so are ZIP64 directory entries written by the
Rust `zip` crate, whose local sizes its own check rejects (use `--zip-consistency ignore`). With
duplicate names, local headers are not compared with the central directory.

`verify`, `list` and `extract` reject a ZIP entry whose compression method is not Stored, Deflate,
Bzip2 or Zstd (including `deflate64`) with `operation denied by security policy: unsupported
compression method: <name>` and exit `1`, before anything is written. Verified live with a ZIP
relabelled as `deflate64`: all three commands exit `1`, and `extract` does not create the output
directory. A 7z directory carrying the Windows reparse-point attribute is listed as a symlink, fails
`verify` regardless of `--allow-symlinks`, and is rejected by `extract`.

### `completion <SHELL>`

```bash
exarch completion zsh > ~/.zsh/completions/_exarch
```

Valid `<SHELL>` values (case-sensitive, exact set): `bash`, `elvish`, `fish`, `powershell`, `zsh`.

## Do not reach for `--allow-*` reflexively

`--allow-symlinks`, `--allow-hardlinks`, `--allow-absolute-paths`, `--allow-world-writable`,
`--allow-solid-archives`, `--zip-consistency ignore`, and `--force` all weaken a default-deny
security check. When an
extraction fails with `SymlinkEscape`, `HardlinkEscape`, `PathTraversal`, `ZipBomb`,
`InvalidPermissions`, `ZipInconsistency`, or `SecurityViolation`, that is the validator correctly rejecting
something dangerous — **do not add the matching `--allow-*` flag just to make the command
succeed.** Only add it when the archive's origin and contents are already known to be trusted,
and prefer re-running just `verify` first to see the full list of findings
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
An archive whose declared compressed sizes exceed the archive length is not reported as an issue:
`verify` fails with an `InvalidArchive` error (`status: "error"`, no `data`, exit `1`).

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
`ZipInconsistency`, `InvalidPermissions`, `QuotaExceeded`, `SecurityViolation`, `SourceNotFound`,
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
paths, and world-writable files are rejected unless explicitly allowed. This holds for ZIP too: an
absolute entry name or any `..` component in the raw name is
`PathTraversal` by default. A name is absolute on every platform when it starts with `/` or `\`
(UNC included), or with a drive letter followed by a separator or nothing (`C:\x`, `C:/x`, `C:`);
a drive glued to a name (`C:name`) is absolute only on Windows, and on Unix `a:notes.txt` is kept
as is. An empty entry name is `InvalidArchive`, and a NUL byte in an entry name is
`SecurityViolation`. On Windows only, entries
whose path has a reserved device-name component (`CON`, `NUL`, `COM1`, ... ASCII
case-insensitive, with or without an extension, e.g. `NUL.tar.gz`) or a component containing
`:` (NTFS alternate data streams) or ending in a dot or space are rejected with
`SecurityViolation`; the same component checks apply to symlink and hardlink targets. A trailing
dot or space and `:` are never allowed; only the reserved-device-name check has an opt-out, and it
exists only in the Rust API (there is no CLI flag). On other platforms these names are
accepted. A `.tar.xz` whose LZMA2 dictionary needs more than the decoder-memory limit (default
256 MiB; `SecurityConfig::max_decoder_memory` in the Rust API, 1 GiB under `permissive()`) is
rejected by `extract`, `list` and `verify` with `QuotaExceeded` (`quota exceeded: decoder memory
(> 268435456 bytes)`); there is no CLI flag to raise it. Only xz is bounded this way; zstd keeps
its fixed decoder window. Verified live: an archive built with `xz --lzma2=dict=300MiB` (needs
385 MiB) fails `extract` and `list` with exit code `1`, `error.kind: "QuotaExceeded"` in `--json`. setuid/setgid bits are
always stripped on Unix regardless of `--preserve-permissions`. Solid 7z archives (multiple
files compressed as one block) are rejected by default because extracting even one file
requires decompressing the whole block into memory — a memory-exhaustion vector; enable
`--allow-solid-archives` only for trusted archives, and consider it isn't a substitute for
enough free memory. If an operation is rejected for one of these reasons, that's the security
pipeline working as intended, not a defect to work around by default.
