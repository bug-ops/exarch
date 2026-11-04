---
name: exarch-cli
description: Extract, create, list, and verify TAR (plus gz/bz2/xz/zst), ZIP, and 7z archives securely using the `exarch` CLI. Use whenever a task involves unpacking or building archives, especially from untrusted sources — exarch blocks path traversal, symlink/hardlink escapes, zip bombs, and oversized archives by default, and reports rejections as structured errors instead of silently succeeding.
license: MIT OR Apache-2.0
compatibility: Requires the `exarch` binary (cargo install exarch-cli, or build from this workspace with cargo build -p exarch-cli). MSRV 1.98.0 if building from source.
metadata:
  author: bug-ops
  version: "0.7.0"
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
| `--force` | off | Overwrite existing files at the destination. A regular file is replaced by a new file (content written to a sibling temp file, then renamed over it, like `mv -f`), so other hardlinks to the old file keep their content (verified live on TAR and ZIP). The destination's parent directory must be writable; a read-only existing file is replaced; owner, ACLs and extended attributes of the old file are not preserved. The new file gets the archive entry's mode, never the old file's (a ZIP entry without Unix attributes gets `0664`, verified live); where no mode is passed at all it is `0666 & ~umask`. |
| `--atomic` | off | Extract to a temp dir, rename into place on success, clean up on failure. With `--force` and a pre-existing destination, the swap is a backup-then-replace: the existing destination is renamed aside first, the new content is renamed into its place second, and only once that swap succeeds is the old destination removed — never before, so a failure at any point still leaves either the old or the new content in place under the destination name. On Unix, `--force` also requires read permission on the destination's parent directory (used to pin it by file descriptor for the swap); the destination itself does not need to be readable. With `--force`, a destination that is itself a symlink is now rejected — pass the resolved target path instead. Without `--force`, a symlinked destination isn't rejected as such, but the final rename onto it fails (`ENOTDIR` on Unix, `OutputExists` on Windows), since `rename` doesn't follow a symlink at the target — pass the resolved target path here too. Plain (non-atomic) `extract` is unaffected: it resolves a symlinked destination via `canonicalize()` and writes through it, matching `tar -C`/`unzip -d` (see #533). If a failed `--atomic --force` run leaves temp/backup content behind (e.g. an intermediate parent-path component was redirected mid-extraction), the error message discloses that content's actual location — see #530. |
| `--preserve-permissions` | off | Preserve file permissions from the archive (setuid/setgid are still stripped regardless). |
| `--max-files` | 10000 | Max number of entries (files, symlinks, hardlinks and directories); extraction fails with `QuotaExceeded` past it. A value of `0` is refused (see below). |
| `--max-total-size` | 500 MB | Max cumulative extracted size. Accepts `K`/`M`/`G`/`T` suffixes, e.g. `2G`. `0` is refused. |
| `--max-file-size` | 50 MB | Max size of any single extracted file. Same suffix syntax. `0` is refused. |
| `--max-compression-ratio` | 100 | Max uncompressed/compressed ratio before an entry is treated as a zip bomb. Applies to ZIP and non-solid 7z; it does **not** apply to solid 7z blocks. With `--allow-solid-archives`, each solid block is checked as a whole against a fixed 1000x limit (`max_solid_compression_ratio`, Rust API only, not configurable from the CLI). An entry that declares data but zero compressed bytes is always a zip bomb with ratio `unbounded` and no ratio limit admits it; its `HINT` says the size metadata is inconsistent rather than suggesting this flag. The ratio of a 7z block counts only the pack streams its coders consume (derived from the coder method IDs, as the stream counts are not public in `sevenz-rust2`); a crafted header that declares a coder with a BCJ2 ID but never decodes it can still add up to three unreferenced pack streams to the last block's total, so that ratio stays an upper bound for such archives (the padding must be real bytes of the file and the other quotas still apply). For a compressed TAR it also bounds entries that `--allowed-extensions` or duplicate skipping leave undecoded to their end: past `--max-file-size` and `--max-total-size`, skipped data may decode to at most this ratio times the compressed input read so far (all entries, extracted ones included), else `extract` stops with `ZipBomb`, scope `skipped entries`, exit `1`, `error.kind` `ZipBomb`; an archive that extracts without the filter is never refused because of it. Verified live: a `.tar.gz` of 200 MiB of zeros with `--allowed-extensions txt` fails with `HINT: Skipped entries of a compressed TAR decoded more than --max-compression-ratio x the compressed input read so far`, and passes with `--max-compression-ratio 100000`. Fractions are accepted (`2.5`); `0`, a negative and a non-finite value are refused as `InvalidConfiguration` (setting `max_compression_ratio`) with exit `1`, and with the JSON envelope under `--json`, like every other limit value. `list` and `verify` accept the flag too. |
| `--max-path-depth` | 32 | Max path component depth allowed per entry. `0` is refused. `extract` also refuses an entry name or path above the host's length limit with `I/O error: file name too long`, as `list` and `verify` do (verified live on ZIP). |
| `--allowed-extensions <EXT>` | all allowed | Restrict extraction to matching extensions. Repeatable or comma-separated (`txt,pdf`); leading dot optional, case-insensitive, padding spaces and empty tokens ignored. An entry that can never match (`tar.gz`, `a/b`) is an error, and so is a value with no extension at all (`,`, `""`), which would otherwise allow everything. Applies to regular files only. TAR, ZIP and 7z check an entry's path first, then the allowlist, then the quotas: a skipped file is not charged to `--max-total-size` or `--max-file-size`, creates no directories, and is counted in `files_skipped`, whatever the destination state; but a skipped entry with an unsafe path (`../x.bin`, or one below an existing file or dangling symlink) is refused, not skipped (verified live on TAR and ZIP). |
| `--allow-symlinks` | off | Allow symlinks that resolve within the extraction directory. `extract` and `verify` reject symlink and hardlink targets whose `..` components cannot be resolved against the extracted tree (TAR, ZIP and 7z). `extract` never writes through a symlink that already sits below the destination: by default it fails with `path component is a symlink: <path>` (`SecurityViolation`, `relaxable_by` `symlinks`); with this flag a pre-existing link is accepted only if it resolves to a directory inside the destination; one that leaves the destination fails with `SymlinkEscape`, and a dangling, looping or file-pointing one fails with `Security violation: refusing to create <entry> under the existing symlink at <parent>` (not relaxable, also by default for a looping link). A symlinked destination root is still accepted (#533). Verified live on TAR, ZIP and 7z. |
| `--allow-hardlinks` | off | Allow hardlinks that resolve within the extraction directory. |
| `--allow-absolute-paths` | off | Allow archive entries with absolute paths. For ZIP the leading root and any drive, UNC, verbatim (`\\?\`) or device (`\\.\`) prefix is stripped, so the entry lands under the destination (`/tmp/x` extracts to `<dest>/tmp/x`). |
| `--allow-world-writable` | off | Allow files with world-writable (mode `0o002`) permission bits. |
| `--allow-solid-archives` | off | Allow solid 7z archives (see Security model below). |
| `--parallel-decode-memory <SIZE\|off>` | 128M | 7z only. Memory for decoding independent LZMA2 runs ahead on worker threads (K, M, G, T suffixes); `off` decodes on one thread; `0` is refused as `InvalidConfiguration` (setting `parallel_decode_memory`) with exit `1`, like every other limit value (verified live). |
| `--zip-consistency <enforce\|ignore>` | enforce | ZIP only. `enforce` rejects an archive whose structure different ZIP readers interpret differently (see "ZIP structure" under `verify`); `ignore` keeps the central-directory interpretation and raises no structural finding. Relax it only for archives from a producer you trust. |
| `--decode-reuse <off\|memory\|temp-file>` | memory | ZIP only. Where the structural check keeps the deflate, bzip2 and zstd output it decodes, so extraction writes it instead of decoding the entry a second time. `memory` keeps up to 256 MiB in RAM (peak RSS about 265 MiB on a 300 MiB deflate ZIP against 5 MiB with `off`); `temp-file` keeps up to 256 MiB in an unnamed temporary file (plaintext in the temp directory until extraction ends; RAM on a tmpfs, often no faster than `off` on a disk); `off` keeps nothing. The kept size never exceeds `--max-total-size` or the decoder memory limit, and entries over `--max-file-size` or `--max-compression-ratio` are never kept. No effect under `--zip-consistency ignore`; entries that do not fit are decoded twice. A kept entry is checked against its CRC-32 again when written. Invalid value: exit `2`. Verified live on the debug binary: a deflate, a bzip2 and a zstd ZIP each extract to identical files under all three values, and `--decode-reuse disk` lists the possible values `off, memory, temp-file`; that the kept output is replayed instead of decoded again is covered by unit tests, not by the binary. |
| `--banned-component <COMPONENT>` | see below | Block entries whose path contains this component. **Replaces** the default list — see warning below. Repeatable, and a value may be comma-separated (`.git,.ssh`); tokens are trimmed. A token containing `/` or `\`, or equal to `.` or `..` is an error, and so is a non-empty value with no token (`,`, a blank). |

> [!WARNING]
> **`--banned-component` REPLACES the default ban list, it does not append to it.** The default
> blocks path components `.git`, `.ssh`, `.gnupg`, `.aws`, `.kube`, `.docker`, `.env`. Passing
> `--banned-component foo` drops ALL of those defaults and blocks only `foo` — silently letting
> `.ssh`, `.aws`, etc. through. If you need one extra banned component, repeat the flag with the
> full desired set, not just the addition: `--banned-component .git --banned-component .ssh
> --banned-component .gnupg --banned-component .aws --banned-component .kube --banned-component
> .docker --banned-component .env --banned-component foo`. Passing an exactly empty value (`""`) disables all
> banning.

### `create <OUTPUT> <SOURCE>...`

```bash
exarch create out.tar.gz src/ --json
```

| Flag | Default | Purpose |
|---|---|---|
| `-f, --force` | off | Replace `OUTPUT` if it already exists. The archive is written to a temporary file in `OUTPUT`'s directory (which must be writable) and renamed into place only when complete, so a failed run leaves the previous archive untouched and no temp file behind; a replaced file keeps its permission bits (verified live: a `0600` archive stays `0600`). Without `--force` an existing `OUTPUT` is refused with `OutputExists` (exit `1`, `HINT: Use --force to overwrite.`) and left as it was. A directory, FIFO or device as `OUTPUT` is refused even with `--force` (`InvalidConfiguration`, setting `output_path`). The output file is never archived into itself. |
| `-l, --compression-level <1-9>` | 6 | Compression level on a shared 1-9 scale (each codec maps it to its own range). A value outside 1-9 is refused as `InvalidCompressionLevel` with exit `1`; a value that is not a whole number is a clap usage error (exit `2`). |
| `-x, --exclude <PATTERN>` | none | Exclude pattern; repeatable. One path component matched exactly (`node_modules`), as a prefix (`tmp*`) or as a suffix (`*.log`), or a relative path with separators (`build/out`) that excludes that path and everything below it. Matching is on the raw name bytes, so `*.key` also excludes a file whose name is not valid UTF-8. Any other shape is refused rather than silently matching nothing or matching literally: an inner or second `*`, a bare `*`, a `*` next to a separator (`build/*`; use `build`), any of `? [ ] { } !` (no glob syntax beyond one `*`), a comma (one pattern per `-x`), leading or trailing whitespace or control characters, `.`/`..`, an absolute path, an empty, over-long or NUL-containing value. A refusal is the library's typed `InvalidConfiguration` (setting `exclude_pattern`), whose message names the pattern and the reason; exit `1`, with the JSON envelope under `--json`, and no archive is written (verified live: `-x '?.txt'`, `'[a'`, `'{a,b}'`, `'!a.txt'`, `' .env'`, `'a,b'`, `'build/*'`; the non-UTF-8 match is covered by a test on filesystems that allow such names, not run on macOS). Excluded entries are counted in `skipped_by_kind.excluded`. |
| `--strip-prefix <PREFIX>` | none | Strip a path prefix from entry names. |
| `--include-hidden` | off | Include dotfiles/hidden entries. Without it a hidden file is skipped and a hidden directory below a source directory is skipped whole (never entered, so `.ssh/id_rsa` or `.aws/credentials` are not archived under their visible names); each skipped directory counts once in `skipped_by_kind.hidden`. A hidden directory given as a source, and a source file given directly, are archived regardless. The name on disk decides: with `--follow-symlinks` a link is judged by its own visible name, so a link `keys -> .ssh` is archived (contents under `keys/`) while a hidden-named link is skipped. |
| `--follow-symlinks` | off | Follow symlinks when walking source trees (stores target contents, not the link). |
| `--max-file-size <BYTES>` | none | Skip source files larger than this (`K`/`M`/`G`/`T` suffixes). `0` is refused with `InvalidConfiguration` (setting `max_file_size`), exit `1`, and no archive is written (verified live with the debug binary). |
| `--preserve-permissions[=true\|false]` | `true` | Preserve platform permission bits. Pass `--preserve-permissions=false` for a portable, permission-agnostic archive. |

**Overwrite defaults differ between front ends.** The CLI refuses an existing `OUTPUT` unless `--force` is passed (`OutputExists`, exit `1`). The Node and Python bindings take an `overwrite` option that defaults to `true`, so `createArchive` / `create_archive` replace an existing file unless the caller passes `overwrite: false` (`overwrite=False`). Every front end writes through the same staged temporary file and renames it into place, so a failed run keeps the previous archive.

> [!NOTE]
> With `--follow-symlinks` off (default), a symlink passed directly as a source (file or
> directory) is archived as a link in TAR; ZIP has no symlink entry type, so it is skipped
> instead (counted as a `symlink_unsupported` skip). With `--follow-symlinks` on, both TAR and ZIP dereference
> the symlink and store the target's content — for a directory symlink, this means walking and
> archiving the entire target tree.

A ZIP entry that compresses more than 100x (repetitive logs, zero-filled data, a 5 KB run of one
character) is refused by default `extract` and `verify` as a zip bomb, while the same content in a
`.tar.gz` extracts. `create` of a `.zip` therefore adds a `warnings` entry (text and
`data.warnings` in `--json`) with the number of such entries and the smallest ratio that admits
them (`ZIP archive has 1 entry over the default extraction ratio limit of 100x; ... at least 218`);
extract or verify that archive with `--max-compression-ratio 218`. Only a path create is scanned
(the archive is read back once); a library caller that supplies its own writer gets no warning.
Verified live: `exarch create r.zip src` for a 5000-byte `B` run prints the warning and exits `0`.

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
| `-l, --long` | off | Detailed per-entry info (type, size, mode, timestamps, link targets). A link whose target was not read shows `(target not read)`, one whose read failed `(target unreadable)`. |
| `-H, --human-readable` | off | Human-readable sizes in text mode (ignored in `--json` mode, which always emits raw byte counts). Requires `--long`: `-H` alone is a usage error (exit `2`, verified live). |
| `--max-files` | 10000 | Hard limit on entries scanned; listing fails with `QuotaExceeded` past this count, it does not truncate. Files that `extract --allowed-extensions` skips still count here, but not toward the total-size or per-file limits. |
| `--max-total-size` | 500 MB | Hard limit on cumulative listed size; listing fails with `QuotaExceeded` past this size. Raise it explicitly for larger archives. |
| `--max-file-size` | 50 MB | Hard limit on any single entry's size; listing fails with `QuotaExceeded` (`FileSize`) past this size. Raise it explicitly for archives with large individual files. |
| `--allow-solid-archives` | off | Allow listing solid 7z archives (higher memory use). |
| `--read-link-targets` | off | Read 7z symlink targets, which decodes the blocks that hold them (in a large solid block, most of the archive). By default `list` decodes nothing for links and their `link_target` state is `unread`. TAR and ZIP always show their targets. |
| `--max-compression-ratio` | 100 | Same as `extract`. |
| `--zip-consistency <enforce\|ignore>` | enforce | Same as `extract`: under `enforce` a ZIP with ambiguous structure fails with `ZipInconsistency` instead of being listed. |

With `--json -l`, every symlink or hardlink entry has a `link_target` object tagged by `state`: `{"state": "recorded", "path": "..."}` for a stored target, and `missing`, `unread` (a 7z target left undecoded), `unreadable` or `{"state": "oversized", "bytes": N}` (over the host's name limits) with no path. A file or directory has no `link_target` key. The old `symlink_target` and `hardlink_target` strings are gone: `null` used to stand for all four non-recorded states. `list -l` prints a note for each (`(target missing)`, `(target not read)`, `(target unreadable)`, `(target too long: N bytes)`). Verified live on a TAR symlink (`recorded`) and a 7z symlink (`unread` by default, `recorded` with `--read-link-targets`).

Verified live: a 51 MB tar entry fails `exarch list` with
`"quota exceeded: single file size (53477376 > 52428800)"` at the 50 MB default, and succeeds
once `--max-file-size 100M` is passed.

A TAR entry that is not a file, directory or link (FIFO, character or block device, or a typeflag
the format does not define, such as GNU `V`, `M` or `D`) fails `list`, `verify` and `extract`
alike with `error.kind` `SecurityViolation` and exit `1`, whatever flags are set (`list` and
`verify` used to list such an entry as a file, or call a FIFO `InvalidArchive`). Verified with the
debug binary on a TAR holding `ok.txt` and a FIFO: `list` and `verify` give `operation denied by
security policy: FIFO entries not supported`; with a `V` entry the message reads `unsupported
entry type: __Nonexhaustive(86)`, and `extract` gives the same message with its `HINT` (the list pass no longer prefixes errors with `failed to list archive`).

A TAR holding any of these specific constructs, which readers such as `bsdtar` and Python `tarfile` parse differently, fails `list`, `verify` and `extract` alike with `error.kind` `InvalidArchive` and exit `1`: a directory, symlink or hardlink that declares a payload; a GNU sparse (`S`) entry; a size or checksum header field that is not plain octal (a sign or a control character) or a base-256 size, including in the `x`, `L` and `K` headers that precede an entry; a `prefix` field in a header without a ustar magic; a PAX header with duplicate records, an empty key, a record over 999999 bytes, a non-numeric `size`, a record length that is not canonical (a sign, a leading zero, a blank line, trailing bytes), or a `SCHILY.realsize` or any `GNU.sparse.*` record; a PAX `path`/`linkpath` stacked with a GNU long name/link record; a global PAX header (`g`) carrying `path`, `linkpath` or `size`, with malformed framing, or following a local PAX header or a GNU long record; an extension-header typeflag without ustar/GNU magic; non-zero bytes between the end of the body of an `x`, `g`, `L` or `K` header and the next 512-byte boundary (readers that take the whole padded block parse them as content), including after a trailing `g` header; and a non-empty GNU long name or link (`L`/`K`) body that does not end in exactly one NUL (a NUL inside the text is refused as a path or target containing null bytes). This is not full consistency with those readers: PAX keys that extractors apply (extended attributes, file flags, ACLs) are not checked, and neither is the content of data after the end-of-archive marker of a plain TAR. For a compressed TAR, `extract`, `list` and `verify --check-integrity` read the stream to its end after the marker, so a corrupt gzip CRC or ISIZE (or a corrupt later member) fails with `invalid archive: integrity check failed after the TAR end-of-archive marker: ...` and exit `1` (a later member cut short ends in `the compressed stream is truncated`), with the partial extraction discarded and the destination left unchanged. More than `max_tar_metadata_bytes` (never less than 1 MiB, default 4 MiB) of decoded bytes after the marker is refused as a security violation naming the effective cap, so `cat a.tar.gz b.tar.gz` works only while the later members decode to less than that; a zero-padded `.tar.zst` is refused. Plain `verify` stops at the marker and never reads the tail. A global header with other records, such as the `comment` that `git archive` writes, is accepted. Verified with the debug binary: `list --json` on a TAR with two PAX `path` records gives `invalid archive: ambiguous TAR header: duplicate PAX record "path"`, a directory entry with `size` 1024 gives `invalid archive: ambiguous TAR header: Directory entry declares a 1024 byte payload: x/`, a TAR whose `x` header has a `+` in its checksum gives `invalid archive: ambiguous TAR header: header checksum field is not a plain octal or base-256 number`, and a PAX `SCHILY.realsize` record gives `invalid archive: ambiguous TAR header: PAX record "SCHILY.realsize" is not supported`; a PAX record placed in the zero padding of an `x` or `g` header (also when the `g` header is the last entry; `extract` refuses at that header, so the entries before it are already written) gives `invalid archive: ambiguous TAR header: extension header body is followed by non-zero padding`, and an `L` body without its NUL gives `invalid archive: ambiguous TAR header: GNU long name extension header is not a single NUL-terminated string`.

### `verify <ARCHIVE>`

```bash
exarch verify archive.tar.gz --json
```

| Flag | Default | Purpose |
|---|---|---|
| `--strict` | off | Treat any warning-level finding as an error and exit with status `3` instead of `0` (`2` is clap's usage-error status, so a script can tell the two apart). |
| `--check-integrity` | off | Decode the payload to the decoder's EOF so checksums and codec framing are verified. See "Payload integrity" below. |
| `--decompression-budget <SIZE>` | 500M | Extra bytes `--check-integrity` may decode beyond what listing already decodes (`K`/`M`/`G`/`T` suffixes). Requires `--check-integrity`; `0` is refused as `InvalidConfiguration` (setting `decompression_budget`) with exit `1`. Fixed default: it does not follow `--max-total-size`, so raise both for archives over 500 MB. |
| `--allow-symlinks` / `--allow-hardlinks` | off | Same flags and semantics as `extract`: links that resolve within the extraction directory are accepted, escaping links still fail. `verify` accepts only these two policy flags (plus `--zip-consistency`, `--max-files`, `--max-total-size`, `--max-file-size`, `--max-compression-ratio`, `--allow-solid-archives`, `--check-integrity`, `--decompression-budget`, `--parallel-decode-memory` and `--strict`); it has no `--max-path-depth`, `--banned-component`, `--allow-absolute-paths` or `--allow-world-writable`, so pass the link flags you intend to extract with, and expect extraction-only options to be evaluated by `extract` alone. |
| `--zip-consistency <enforce\|ignore>` | enforce | ZIP only. Under `enforce`, structural findings are reported as issues (see "ZIP structure" below); under `ignore` none are raised. |
| `--parallel-decode-memory <SIZE\|off>` | 128M | Same as `extract`; effective with `--check-integrity`. |
| `--max-files` / `--max-total-size` / `--max-file-size` / `--max-compression-ratio` / `--allow-solid-archives` | same as `list` (10000 / 500 MB / 50 MB / 100 / off) | Same hard-limit semantics as `list` for file count (every entry is counted) and total size — verification fails with `QuotaExceeded` past those two caps, it does not skip entries. |

`verify` always runs the full security validation pipeline (path traversal, symlink/hardlink, permissions) without extracting. By default it does not validate payload checksums: `integrity_status` is `SKIPPED` (`Integrity: SKIPPED` in text mode), so a passing `verify` says nothing about data corruption. Pass `--check-integrity` for that.

**7z link targets are validated only with `--check-integrity`.** They live in compressed data, so a plain `verify --allow-symlinks` of a 7z archive with symlinks reports one `MEDIUM` issue (`N symlink target(s) were not read, so ...`) and status `WARNING`: exit `0`, or `3` with `--strict`. This includes an archive whose link escapes the destination, so a `verify && extract` gate no longer stops it; gate with `verify --strict` or `verify --check-integrity` (exit `1` on the escape), and use `extract --atomic` for all-or-nothing extraction. Entries beneath or through an unread link are still reported as failures.

#### Payload integrity (`--check-integrity`)

`integrity_status` is `OK`, `FAILED`, `INCOMPLETE` or `SKIPPED` (JSON `data.integrity_status`, text `Integrity: ...`):

| Value | Meaning | Exit code |
|---|---|---|
| `OK` | Every payload byte was decoded and every checksum the format has matched. | `0` |
| `FAILED` | A checksum or decoder error proved the payload corrupt: a `HIGH` `"Corrupt Data"` issue, attributed to the entry where one owns it (`entry_path` is `null` for a stream trailer such as a gzip CRC). | `1` |
| `INCOMPLETE` | Part of the payload was not verified; one `MEDIUM` `"Integrity Incomplete"` issue lists the counts per reason, so `status` is at least `WARNING`. | `0`, or `3` with `--strict` |
| `SKIPPED` | `--check-integrity` was not passed. | n/a |

**Exit code `0` does not mean integrity `OK`**: `INCOMPLETE` exits `0` unless `--strict` is passed, so use `--strict` (or read `data.integrity_status`) in automation. Reasons an item is unverified: decompression budget exhausted, quota/ratio/decoder-memory limit, a solid 7z archive while `--allow-solid-archives` is off, a 7z block checksum that the entries do not cover, an unsupported 7z coder, a TAR stream with no end-of-archive marker, an entry dropped from the manifest because its path exceeds the host limits, and the data-descriptor tail of a ZIP entry that was not searched. `verify` reports everything `extract` refuses in a 7z archive as an archive-level issue and exits `1`: a solid archive while `--allow-solid-archives` is off (`Security Policy`), a block whose coder memory exceeds the decoder limit (`Quota Exceeded`), AES-encrypted content under a plain header (`Security Policy`), an unknown coder, and a block whose files do not add up to its decoded size (`Invalid Archive`: `7z block's files do not account for its decoded size`; an orphan block, or sub-streams shifted by an entry without data, as a writer that gives directories a sub-stream produces; `extract` refuses it too). A stream-less entry (directory or empty file) between a block's files is fine. The payload of a refused block is counted as unverified. Verified live: `tests/fixtures/solid.7z` gives `Archive verification: FAIL` with one `Security Policy` issue and `Integrity: INCOMPLETE` with `--check-integrity` (exit `1`), and `PASS` with `--allow-solid-archives`; `tests/fixtures/interleaved-empty.7z` passes `verify --allow-solid-archives --check-integrity` and extracts all four entries, and `interleaved-empty-badcrc.7z` fails the integrity check with a `checksum mismatch` on `c.txt`.

With `--check-integrity`, `--json` adds `data.integrity_gaps` (`null` without the flag): `counts` maps each reason (`over_budget`, `resource_limit`, `solid_policy`, `size_ceiling`, `uncovered_block_crc`, `not_decodable`, `no_end_marker`, `path_too_long`, `descriptor_tail`) to the number of unverified items, `entries` lists `{path, reason}` for up to a fixed cap of entries (256 today), and `omitted` counts entries that did not fit the list. A TAR without an end marker, and an entry dropped for its path (`path_too_long`), have a count but no path; a `descriptor_tail` entry is listed by path although its own payload may have been verified. The `Integrity check incomplete` message is rendered from the same data. Verified live: `exarch verify --json --check-integrity tests/fixtures/solid.7z` gives `counts: {"solid_policy": 10}` and 10 entries; `tests/fixtures/simple.7z` gives empty `counts` and `entries`.

What `OK` covers per format:

| Format | Checked |
|---|---|
| ZIP | Per-entry CRC-32 and the exact declared size. Entries are independent: a corrupt entry is reported and the scan continues. A symlink target is read through the same check. |
| TAR | Header checksums and that every declared data byte is present. No payload checksum exists, so `OK` means complete and decodable. |
| tar.gz / tar.bz2 / tar.xz / tar.zst | The above plus the codec's framing and checksums (gzip CRC-32 and size, bzip2 CRC, xz block check, zstd content checksum only if the frame carries one). |
| 7z | Per-entry CRC-32 where the archive stores one, else the block CRC (which can only fire once the whole block is read and is attributed to the block's last entry). LZMA/LZMA2/PPMd validity. Entries without any CRC get the weaker "decodable" guarantee. |

"Decode to EOF" means the decoder's EOF: every gzip member, bzip2 stream, xz stream and zstd frame is decoded (concatenated archives such as `cat a.tar.gz b.tar.gz` and pbzip2 output are read in full, within the gzip/bzip2 member allowance described under the decoder-memory limit; for a TAR the bytes after the end marker are bounded by `max_tar_metadata_bytes`, at least 1 MiB, and a longer tail is an error rather than `INCOMPLETE`); an all-zero tail after the last gzip member, bzip2 stream or xz stream is accepted, while after the last zstd frame it is an error (`Unknown frame descriptor`), and any other trailing bytes are an error for every codec. The budget covers only decoding beyond what listing already does: ZIP entries and 7z blocks are charged their declared size before decoding (first-fit, so one large entry does not block later small ones), TAR entries are never charged (listing decodes them anyway), and neither is the compressed TAR tail after the end marker (see the cap above). A TAR stream must have at least one byte after the entry list; one that stops at a header boundary is `INCOMPLETE`.

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

Entry names that are not valid UTF-8 are shown the same way in text and `--json`, wherever a path appears (`list`, `verify`, errors, skip samples): each invalid byte is written `\xNN` and a backslash `\x5C`, so two names that differ only in invalid bytes (`caf\xE9`, `caf\xE8`) never print alike and no U+FFFD appears. A refusal issue (everything `extract` would also refuse) carries the typed fields of the error extraction raises: `code` (the `error.kind` names, such as `SecurityViolation`), `sub_code` and, where a policy flag relaxes it, `relaxable_by` and `setting`, so no script needs to parse `message`; an observation `verify` makes on its own has none of them. An executable file and an invalid-permissions refusal report their raw mode as a numeric `mode` (the old `context` string is gone; verified live on a setuid TAR: `mode` 2541, which is `0o4755`). Verified live: a TAR symlink without `--allow-symlinks` gives `code` `SecurityViolation`, `sub_code` `LINK_POLICY`, `relaxable_by` `symlinks`.

`data.issues[].category` is one of `"Path Traversal"`, `"Symlink Escape"`, `"Hardlink Escape"`,
`"Zip Bomb"`, `"Invalid Permissions"`, `"Quota Exceeded"`, `"Security Policy"`,
`"Invalid Archive"`, `"Suspicious Path"`, `"Executable File"`, `"Corrupt Data"`,
`"Integrity Incomplete"`, `"Header Mismatch"`, `"Duplicate Entry"`, `"Overlapping Entries"`,
`"Hidden Entry"`, `"Name Collision"`, `"Archive Note"`. `"Archive Note"` is informational and never a
security finding. `"Corrupt Data"` and `"Integrity Incomplete"` come only from
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
- `verify` reports as `HIGH` issues (exit `1`) the entry shapes the host rejects: an entry beneath a regular file (`I/O error: refusing to create <entry> under the existing file at <parent>`, the text `extract` gives), a directory over an earlier file (`I/O error: refusing to replace the existing file at <path>`, the text `extract` gives, with and without `--force`, also for a file the destination already held) or over an earlier symlink that does not resolve to a directory inside the destination (`extraction fails at <path>: refusing to replace the existing symlink at <path>`; `extract` refuses it too with `error.kind` `SecurityViolation` and creates nothing through the link, while a link that resolves to an in-destination directory is accepted), a parent chain that loops or leaves the destination, a hardlink whose target is a directory (`hardlink target is a directory: <target>`), a link whose placement can make extraction fail (a symlink over an earlier file, or an entry or hardlink below a dangling or looping symlink, named as `Security violation: refusing to create <entry> under the existing symlink at <parent>` like `extract`), reported as `Security Policy` with `Security violation: extraction fails at <path>: <error>` (below a dangling symlink; fails under every option set) or `Security violation: extraction can fail at <path> unless duplicates are skipped: <error>` (symlink over an earlier file) and `Security: FAILED` (verified live on TARs with `--allow-symlinks --allow-hardlinks`; a directory over a file stays an `I/O error` with `Security: OK`), and an entry or hardlink target with a name component over 255 bytes (UTF-16 units on Windows) or a path over the host's limit, and a symlink target over the host's path limit (`I/O error: file name too long`). The path limit is per host: 4095 bytes on Linux, 1023 on macOS and other Unix, 32767 UTF-16 units on Windows. A symlink target is checked against its own limit only, so a long component is accepted there: the path limit on Unix, 4091 UTF-16 units on Windows (the 16 KiB reparse buffer holds the substitute and print names of a relative target; extraction never creates absolute targets). Two gaps remain: the check sees the entry's relative path, not the destination prefix extraction adds, so `verify` can PASS while `extract` fails with `File name too long` when the destination path is long; and the Windows symlink target limit is checked against `CreateSymbolicLinkW` by a Windows-only test, not by a live run on every host. `list` fails on an entry whose path is over those limits (`I/O error: file name too long`); `verify` does not keep such a path and reports up to 16 archive-level `HIGH` issues naming the entry position and byte length, then one summary issue counting the rest; with `--check-integrity` each dropped entry also counts as unverified with the reason `path_too_long`, so the integrity result is `INCOMPLETE` rather than `OK`.
- `verify` has no overwrite option and models first-entry-wins extraction. Without `--force`, `extract` skips a later entry at an already-written path (verified live: entries `f`=`one` then `f`=`two` leave `one`, with a `skipped 1 entry as pre-existing duplicates` warning); with `--force` a later entry overwrites it (the same archive leaves `two`). `verify` cannot model the `--force` outcome and reports a `HIGH` issue where a symlink entry follows an earlier file entry at the same path, even though plain `extract` skips that symlink. Where an overwrite would fail without replacing anything (a symlink over an earlier symlink with another target or over a directory, a file over a directory or symlink, a hardlink over any earlier entry), `verify` adds a `LOW` `Invalid Archive` note (`extraction with overwrite fails at <path>: an earlier entry is a <kind>`, plus `(default extraction skips this entry)` for a symlink) and the status stays `PASS`. A repeated symlink with the same target is not noted. A symlink entry over an existing symlink is skipped by plain `extract` (verified live on a TAR whose `d` symlink is repeated with another target: exit `0`, `skipped 1 entry as pre-existing duplicates`, where it used to fail with `SymlinkEscape`). Under `--force` an existing symlink with another target is never re-pointed: `extract` fails with `I/O error: refusing to replace the existing symlink at <path>` (`error.kind` `IoError`, `partial_report.writes` `"kept"` in an existing destination and `"rolled_back"` for a TAR into a new one). A regular file over an earlier directory or symlink entry fails `extract --force` the same way and names the entry: `I/O error: refusing to replace the existing directory at d` or `... the existing symlink at l` (verified live on TARs; 7z uses the same wording, covered by a test only). The wording says what occupies the path and not that an archive entry put it there, since the destination may already have held it. A symlink with the same target is left as it is, so re-extracting an archive with `--force` into its own output succeeds, dangling links included. `verify` does not flag a symlink's recorded mode (Linux writes `0o777` on every link and extraction ignores it), so `verify --strict` exits `0` for it; a hardlink entry's recorded mode is not checked either, since extraction never applies a link entry's own mode (verified live: `verify --strict --allow-hardlinks` on a TAR whose hardlink records mode `0o777` prints `PASS` and exits `0`).
- On macOS names are compared after NFD and a per-character case fold, on Windows after the same fold without normalisation, elsewhere exactly. Two entries whose names differ but compare equal under that fold are reported as a `"Name Collision"` issue, never merged silently: `HIGH` when their kinds differ or a symlink is involved (a hardlink over a file counts as a file), `MEDIUM` for two files or for two directories that hold entries (`status` `WARNING`, `Security: WARNING`), `LOW` for two directories that hold no entries (listed, but `status` stays `PASS` and `Security: OK`). A spelling is reported once, however many entries use it. Verified live on macOS: `café.txt` in NFC and NFD spellings, `straße.txt` and `straẞe.txt`, `a.txt` and `A.txt`, and `Dir/a.txt` with `dir/b.txt` give `MEDIUM`; the empty directory entries `Dir/` and `dir/` give `LOW`. The fold approximates the host's table, so a pair it merges that the host keeps apart is reported too.
- Windows component checks (reserved device names, alternate data streams, trailing dot or space, `<>"|?*`, control characters) run only when `verify` itself runs on a Windows host, so results are not host-independent.

**ZIP structure.** A ZIP stores each entry's metadata twice, in a local header and in the central
directory; random-access readers follow the directory and streaming readers follow the local
headers, so an archive whose copies differ shows different content to different tools. Under the
default `--zip-consistency enforce`, `extract` and `list` fail with `ZipInconsistency` (exit `1`,
nothing written, `error.kind` `ZipInconsistency`) and `verify` reports each finding as a `HIGH`
issue when the archive:

- has a local header that disagrees with its central directory record on the file name, a Unicode Path extra field, compression method, encryption flag, data-descriptor flag, modification time, CRC-32 or sizes (`"Header Mismatch"`; a local header that cannot be parsed at all is reported the same way);
- repeats an entry name (`"Duplicate Entry"`; the `zip` crate keeps only the last record, `verify` still counts every record in `total_entries`);
- has entries whose data ranges overlap (`"Overlapping Entries"`);
- has an entry whose local or central `xl` (`0x6c78`) extra field, which libarchive honours, gives it another file type than the central attributes (`"Hidden Entry"`, `an xl extra field of entry N (local header at offset M) gives it a file type that the central directory attributes do not`): `bsdtar` takes the type from that field and creates a symlink or directory where the central directory says regular file (or the reverse). `verify` fails it with and without `--check-integrity`, and `extract` and `list` reject it under `Enforce`. Entries without an `xl` field are not compared, so symlinks written by Info-ZIP and `bsdtar` still pass;
- holds central directory records beyond the count in its end record, a central directory (`PK\x01\x02`) or end record (`PK\x05\x06`, ZIP64 `PK\x06\x06`) signature before an entry (between entries, behind padding or a data descriptor, or in a prefix of a file that starts with `PK`), where a streaming reader stops listing and never reaches the entries behind it, a data descriptor after which a streaming reader (modeled on libarchive: it skips the local compressed size when there is one, else ends a deflated entry at its stream or scans for the descriptor signature and takes 16 bytes, or 24 with a ZIP64 extra field, and matches the 12/16/20/24-byte layouts against the entry's sizes) resumes past the next entry header, or a local header that no central directory record maps (`"Hidden Entry"`): before the archive (a stub is scanned, but past offset 0 only headers that look written by a ZIP producer and whose entry fits inside the stub count, since self-extractors embed the signature; a file that starts with `PK` is not a stub and is judged like a gap; a stub that embeds a whole ZIP resource is still reported), between entries, behind padding, or just before the directory. A streaming reader extracts such an entry and a random-access reader never lists it;
- has a directory or special-file entry (a trailing slash or backslash in the name, Unix type bits, or the DOS directory attribute on a DOS host) that declares data (`"Hidden Entry"`, `directory entry N declares a payload of M bytes`): readers disagree on whether those bytes are skipped or read on as records. Empty directory entries, including a deflated one that holds only an empty stream, pass, and so do symlinks, whose data is their target. A directory with data and no descriptor is refused although `bsdtar` does not read the payload;
- has a compressed entry (deflate, bzip2 or zstd) whose local header states its sizes but whose stream ends before the declared compressed size and whose slack holds a local header, central or end record: `bsdtar` reading from a pipe ends such an entry where the stream ends and reads on from there (`"Hidden Entry"`, `local header at offset N (behind the compressed stream of an entry) is not in the central directory`);
- has an end of central directory record after the one the `zip` crate used, which the crate rejected and another reader may take (`"Hidden Entry"`).

A header mismatch, an `xl` type divergence, a data descriptor overrun, a directory payload and an undecidable stream end are bound to their entry: the issue's `entry_path` is that entry's path and the entry counts in `suspicious_entries`. Every other ZIP structure finding is archive-level (`entry_path` is `null`).

`total_entries` of a ZIP report is the raw central directory count. A raw count over `--max-files` is
a `QuotaExceeded` error (`quota exceeded: file count (20000 > 10000)`, exit `1`) from `extract`,
`list` and `verify` under both policies, even when most records share one name. Verified live
with crafted archives built with Python: a two-record directory whose end record counts one
(`Total entries: 2`, two `"Hidden Entry"` issues), a local header inserted before the directory
(`"Hidden Entry"`), a central record or a bare `PK\x01\x02` or `PK\x05\x06` placed between two entries (`"Hidden Entry"`, rejected by `extract` and `list`; `bsdtar` reading the archive from a pipe lists only the first entry), a stored entry with a signed 16-byte descriptor and a ZIP64 extra field or with an unsigned descriptor, and a deflated entry whose 12-byte descriptor reads as 20 bytes against the next header (`"Hidden Entry"`; `bsdtar` skips an entry, fails, or extracts a file embedded in the next entry), an empty-name header whose compressed size spans the next entry (`"Hidden Entry"`; `bsdtar` skips that entry), a stored entry whose local or central `xl` extra field marks it a symlink to `../../../../tmp/pwned` or a directory while the central attributes say regular file (`"Hidden Entry"`; `bsdtar` creates the symlink or lists the directory), two entries named `a.txt` (`"Duplicate Entry"`, `Total entries: 2`) and an
archive with 20000 records named `a.txt`; each passes with `--zip-consistency ignore` (except the
last, which stays a `QuotaExceeded` error), where `extract` writes what it always did. Archives from
Info-ZIP, `ditto`, 7-Zip, `bsdtar`, Go and Python's `zipfile`, including streamed archives
with data descriptors, produce no findings; archives from Java (`java.util.zip`, `jar`) and Windows
(`Compress-Archive`, .NET `ZipFile`) are generated and checked at test time in CI; Windows
Explorer and WinRAR archives are still not covered. The `./` root entry written by
`bsdtar --format zip -cf out.zip .` is the destination itself: `extract` creates nothing for it
(it still counts toward `Directories`) and `list` shows it as `.`. A bare `.` entry is accepted
only as a directory or an empty regular file; a `.` symlink or a `.` with data is rejected by
`extract`, `list` and `verify`. A descriptor, local header and data hidden
inside the declared range of a data-descriptor entry (streaming readers end such an entry at the
end of its data, `zip` at the declared size) is found by plain `verify`, `list` and `extract` for a
stored entry, whose declared range is scanned for a descriptor signature and searched from there like a gap, and for a deflate, bzip2 or zstd entry, which is decoded to its stream end and searched from there (a bzip2 or zstd descriptor entry is decoded only when its declared range holds a record signature, so honest entries cost one extra read; it is also scanned for the descriptor signature, since readers differ and the further resume position wins)
(`"Hidden Entry"`, exit `1`, with and without `--check-integrity`). The search starts at the first descriptor signature in the data whatever the descriptor states, because some reader modes (listing, skipping, pattern selection) end a stored entry there. A ZIP-based file stored whole in a streamed (descriptor) entry is therefore reported when its data holds a signed descriptor followed by a local header or record signature, while one without signed descriptors passes (verified live: a descriptor-flagged `n.bin` holding an archive without signed descriptors passes, one holding signed descriptors is reported, and `bsdtar` reading from a pipe lists the inner entries of the latter). A descriptor that ends a scanned entry at its declared end has to carry the entry's CRC-32 as well as its sizes; one with another CRC does not end the entry, so the reader runs on and the archive is reported as a descriptor overrun.
A local header counts when it has a name, an extra field (the Unicode Path field names an otherwise nameless header) or a compressed size, wherever it sits: a gap, the prefix, or an entry's declared range, even where its name runs past that range.
A compressed entry (deflate, bzip2 or zstd) is decoded within its declared range, up to 256 MiB of output per archive, to find where its stream ends; this applies to data-descriptor entries (deflate, bzip2, zstd) and to entries whose local header states the sizes, and a known-size entry is decoded whatever size it states, since a streaming reader ends it where the stream ends. Local headers, central directory and end record signatures between that point and the declared end (a signature cut off by the declared end included) are reported by plain `verify`, `list` and `extract` (`"Hidden Entry"`, exit `1`). A stream that does not end inside the declared range, or that the decoder rejects, is reported as a descriptor overrun (descriptor entries) or as `the end of the compressed stream of entry N cannot be established (...)` (known-size entries). Every decode is charged to the archive's 256 MiB budget for the bytes it actually produced, rejected streams included; once the budget is spent later entries are not decoded again. An entry the budget does not cover is searched for records by the rules the gap search applies inside the budget (a local header the reader takes something from, or the bare signature of a central, end or ZIP64 end record; the compressed bytes are read to the declared end and a few bytes beyond, so a record that straddles the end is judged on its real bytes). Random compressed data spells such a signature about once per gigabyte, but a nested archive (a JAR, an APK or a ZIP inside a ZIP) always does, so a hit does not refuse the entry: it is decoded again up to its declared size from a recheck allowance that is shared by the whole archive, not given per entry. The allowance is the larger of 256 MiB and `--max-total-size` (the library default for `ZipArchive::new` is 256 MiB), so the census decodes at most the 256 MiB budget plus that allowance, which is twice the budget only under the default quota. An entry is then refused when its stream runs past the declared size, the decoder rejects it, the allowance is spent (`the end of the compressed stream of entry N cannot be established (...)`), or a record stands behind the stream end; a stream that ends before the declared end with a record behind it gets the same finding as inside the budget, while one that runs past the declared size is refused as undecidable instead of being searched. The budget and the allowance together cover the 500 MB default `--max-total-size`, so an archive of nested archives that extraction admits passes (verified live: 14 stored-block nested archives of 41 MB each, 573 MB in all, pass `list` and `verify` with `--max-total-size 2G` in about 0.2 s and are stopped by the quota alone without it). An entry without a hit is left to `--check-integrity`, which decodes with its own budget (a tail that cannot be decided counts as an unverified item with the reason `descriptor_tail`); bzip2 and zstd descriptor entries are decoded there too. Cost: `list`, `verify` and `extract` under `enforce` read compressed entry data once at open, up to the budget, in addition to what extraction itself decodes (measured on a release build: about 0.4 s for a 73 MB deflate archive holding 120 MB, about 0.7 s for an archive whose entries decode to far beyond the budget, 40 entries of 13 KB included). Under `--zip-consistency ignore` that work is skipped (the same `list` calls take about 5 ms), since the findings are discarded. Verified live against archives that streaming readers resume differently. Not covered: central
directory signatures inside the stub of a file that does not start with `PK`, and other streaming-reader layouts tracked in #686. A central or end record signature behind the last entry is not reported, except in a prefixed archive, where the stretch from the end record's directory offset to the actual directory is searched (a decoy directory that readers up to `zip` 9.0.5 would take is reported as a stray central or end record); a decoy inside the declared data range of the last entry is not scanned. Pre-ZIP64 archives
with more than 65535 entries (a wrapped end-record count) and archives with orphaned local headers
or a central directory signature in a gap before an entry, left by in-place updaters, are rejected under `enforce`; so are ZIP64 directory entries written by the
Rust `zip` crate before 9.1.0, whose local sizes its own check rejects (use `--zip-consistency ignore`). With
duplicate names, local headers are not compared with the central directory.

A TAR entry named `.` or `./` is the destination itself: as a directory it is a no-op. As anything
else (a regular file, including an empty one named `.`, a symlink or a hardlink) it is rejected with
`archive root entry '.' must be a directory` by `extract`, `list` and `verify` alike (exit `1`; for
`verify` a hard error, not a report entry). A zero-size regular-file entry whose name ends in `/`
(V7, `bsdtar --format v7`) is read as a directory by all three commands, so an empty `./` root is a
no-op; with a payload it stays a file and is rejected. A 7z entry named `.` follows the same rule:
a directory is a no-op, a non-directory root entry (empty or not) is rejected by all three
commands with the same message and exit `1`. A 7z anti-item (a "delete this path" marker) is skipped
by `extract`, `list` and `verify` without any path check, whatever its name (`.`, `../evil`, `...`),
and never touches an existing file; unlike `7z x`, exarch never applies it as a deletion. A 7z entry
with an empty name is rejected by all three commands with `empty path not allowed` (exit `1`; for
`verify` a hard error, not a report entry). TAR and ZIP follow the same rule: an entry whose name is
empty (after any PAX or GNU long-name resolution for TAR) fails `list`, `verify` and `extract` with
`operation denied by security policy: empty path not allowed` and exit `1`, before anything is
written.

`verify`, `list` and `extract` reject a ZIP entry whose compression method is not Stored, Deflate,
Bzip2 or Zstd (including `deflate64`) with `operation denied by security policy: unsupported
compression method: <name>` and exit `1`, before anything is written. Verified live with a ZIP
relabelled as `deflate64`: all three commands exit `1`, and `extract` does not create the output
directory. A 7z directory carrying the Windows reparse-point attribute is listed as a symlink, fails
`verify` regardless of `--allow-symlinks`, and is rejected by `extract` before anything is written.
A 7z entry carrying a Unix symlink mode (`0x8000` flag plus `S_IFLNK` in the high 16 bits of the
attributes, as p7zip and `bsdtar --format 7zip` write them) is a symlink whose target is the
entry's data:

- `list` leaves the target unread by default (`link_target` is `{"state": "unread"}` with `--json -l`, and
  `list -l` prints `(target not read)`); `--read-link-targets` reads it whatever the policy.
- `verify` without `--allow-symlinks` fails with `symlinks not allowed`. With it, the target is
  validated only under `--check-integrity` (an absolute or escaping target then fails as a symlink
  escape); otherwise `verify` warns once that the targets were not read (see `verify` above).
- `extract` refuses the link with `symlinks not allowed` (exit `1`, hint `--allow-symlinks`)
  before anything is written, and creates it under `--allow-symlinks`. An empty or over-long
  target is refused from the file table before any write; this check also runs in the CLI's
  listing pass whatever the policy, so such an archive fails with the target error before the
  `symlinks not allowed` hint. Any other target is read and validated once, as the link is
  created, so a target that escapes, is corrupt or is not UTF-8 stops extraction with entries
  written earlier left in the destination. Use `--atomic` for all-or-nothing extraction.
- A link in a solid block needs `--allow-solid-archives`, as any entry of one; without it
  `--read-link-targets` marks the target unreadable.
- With `--check-integrity` a link is decoded once, together with its block. A block the decoder
  budget cannot cover leaves the target unread, which `verify` reports as the warning above.
- Cost: `list` decodes nothing for links unless `--read-link-targets` is given, `verify` reads them
  inside its integrity pass, and `extract` decodes each block once. The work is bounded by the
  solid policy, admission and `max_solid_block_memory`.
- A link whose data is corrupt fails `extract` with `InvalidArchive`; `--read-link-targets` and
  `verify --check-integrity` report a corrupt target as unreadable. A target that is not UTF-8
  fails `extract`, `list --read-link-targets` and `verify --check-integrity` with
  `InvalidArchive`, as it does for ZIP.
- A header that declares data streams but no file list (or whose stream map does not cover its
  blocks and files) fails `list`, `verify` and `extract` alike with `InvalidArchive` (`invalid
  archive: failed to open 7z archive: ...`, exit `1`, nothing written); `list` used to print an
  empty listing for it. Verified live on `tests/fixtures/streams-without-files-info.7z`.
- A FIFO, socket or device node, Unix type bits that name no file type, or a recorded kind that
  contradicts the entry's own (a directory mode on an entry with data or an empty file, a
  regular-file mode on a directory, the Windows directory bit on a file, empty or not) fails
  `list`, `verify` and `extract` with `operation denied by security policy` and exit `1`, whatever
  flags are set. `bsdtar --format 7zip` writes FIFOs as stream-less entries, so an archive made
  from a tree holding one is refused.
- `extract` reports skipped 7z anti-items as one warning, `skipped N 7z anti-item(s) (deletion
  markers are not applied)` (in `data.warnings` with `--json`), and `verify` adds an `INFO` issue
  (category `Archive Note`) with the same count. The INFO is not a security finding and does not
  change the `PASS` status or `security_status`, so `verify --strict` still exits `0`.

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
    "message": "...",
    "relaxable_by": "symlinks", // only on some SecurityViolation errors, see below
    "sub_code": "PATH_NAME",  // always on SecurityViolation; on some InvalidArchive errors, see below
    "setting": "max_file_count"  // only on an InvalidConfiguration error that names a setting, see below
  }
}
```

`data` is absent on error, `error` is absent on success.

`error.sub_code` is present on every `SecurityViolation` and on an `InvalidArchive` that has a family, and is
absent on every other error, so branch on it instead of parsing `message`. On a `SecurityViolation`
it names the family of the refusal: `PATH_NAME` (an entry path refused by name rules: banned
component, NUL byte, empty path, reserved or unsafe name), `PATH_DEPTH`, `LINK_TARGET` (an empty,
NUL, banned, oversized, missing or unreadable link target, or a reparse point), `LINK_POLICY`
(symlinks or hardlinks not allowed), `EXISTING_SYMLINK` (a symlink already in the way),
`ENTRY_TYPE` (a device, FIFO, socket or other unsupported entry), `ROOT_ENTRY`, `ENCRYPTED`,
`COMPRESSION_METHOD`, `SOLID_ARCHIVE`, `DECLARED_SIZE` (a stream that disagrees with its declared
size), `CONCURRENT_CHANGE`, `TAR_METADATA`, `TAR_TRAILER`, `PLATFORM`, `OUTPUT_CONFLICT` (a
`verify` placement finding) and `SOURCE_PATH` (a source outside the archive root). A `SecurityViolation` always has a `sub_code`, while
`relaxable_by` is present only for the kinds a setting relaxes. Verified live with the debug
binary: a TAR entry named `.git/config` gives `SecurityViolation`, `PATH_NAME` and `relaxable_by`
`banned_components`; a symlink entry gives `LINK_POLICY` and `symlinks`; a FIFO entry gives
`ENTRY_TYPE` and no `relaxable_by`.

On an `InvalidArchive`, six more families mark refusals that were once plain text: `ZIP_READER` (a failure of the ZIP reader or of the structural check built on it; verified live: a ZIP without an end-of-central-directory record gives `error.sub_code` `ZIP_READER`), `LINK_TARGET` (a link
entry whose target is missing, unreadable, too long or, for a hardlink, absent, a directory or not a
regular file), `DUPLICATE_ENTRY`, `ENTRY_NAME` (an entry path or name that cannot be read), `DECLARED_SIZE` (a
declared size that contradicts the archive) and `INTEGRITY` (an integrity decode that failed). `TAR_AMBIGUITY` marks a TAR
header that readers parse differently (a size or checksum field that is not plain octal, a PAX
record problem, a payload declared on a directory or link, and the other cases listed under the TAR
consistency checks). `TAR_TRAILER` marks the stream after the end-of-archive marker of a compressed
TAR: with `error.kind` `InvalidArchive` when it is corrupt or truncated (a bad gzip CRC or ISIZE,
trailing junk, a cut-short later member), with `error.kind` `SecurityViolation` and `relaxable_by`
`max_tar_metadata_bytes` when more than the cap of decoded bytes follows. The value is derived from
the same classification the Python (`sub_code`) and Node (`subCode`) bindings expose. Verified live
with the debug binary on four TARs: a size field `+0000000005` gives `kind` `InvalidArchive`,
`sub_code` `TAR_AMBIGUITY`; a gzip member followed by `\0\0\0garbage` gives `InvalidArchive`,
`TAR_TRAILER`; a gzip member followed by a second member of 5 MiB of zeros gives `SecurityViolation`,
`TAR_TRAILER` and `relaxable_by` `max_tar_metadata_bytes`; a file of `A` bytes gives `InvalidArchive`
and no `sub_code`. A hardlink to a missing target gives `InvalidArchive` and
`LINK_TARGET`, and a symlink entry with an empty link name gives `InvalidArchive` and `LINK_TARGET` (both verified live with the debug binary).

A `QuotaExceeded` error also carries a `sub_code` naming the exhausted limit (`FILE_COUNT`, `TOTAL_SIZE`, `FILE_SIZE`, ..., `SOLID_BLOCK_MEMORY`), and a `ZipBomb` one the scope (`ENTRY`, `SOLID_BLOCK`, `SKIPPED_ENTRIES`). Verified live: `list --json --max-total-size 1` gives `kind` `QuotaExceeded`, `sub_code` `TOTAL_SIZE`.

`error.setting` is present only on an `InvalidConfiguration` error and names the refused setting by its
stable snake_case id (`max_file_size`, `max_total_size`, `max_file_count`, `max_path_depth`,
`max_compression_ratio`, `decompression_budget`, `allowed_extension`, `banned_path_component`, `output_path`,
`source_paths`, ...). A zero limit is refused when the flag is applied, so `list --max-files 0 --json` gives
`kind` `InvalidConfiguration`, `setting` `max_file_count` and message
`invalid configuration: max_file_count must not be zero` (verified live with the debug binary). clap checks only the syntax of a limit flag (a number, with `K`/`M`/`G`/`T` suffixes for sizes); every value the library refuses is refused when the flag is applied, for `extract`, `list` and `verify` alike: a zero `--max-files`, `--max-total-size`, `--max-file-size` or `--max-path-depth`, a zero, negative or non-finite `--max-compression-ratio` and a zero `--decompression-budget` exit `1` with the JSON envelope under `--json` (`kind` `InvalidConfiguration`, `setting` naming the flag), and in text mode print `Error: Invalid configuration: <setting> ...` followed by `HINT: Check the flags you passed and their allowed value ranges.` for all three commands. Only a value clap cannot parse (`--max-files abc`, `--max-files 2.5`, `--max-compression-ratio x`) is a usage error with exit `2` and plain text. Verified live with the debug binary: `--json list --max-compression-ratio 0` and `--json list --max-files 0` print one `InvalidConfiguration` envelope and exit `1`.

The same hints now apply to every command: `list` and `verify` name the archive and give the `HINT` of their own failure (for a quota, `Use --max-files, --max-total-size, or --max-file-size to increase limits.`), and a hint names only flags the command has (`list` is never told to pass `--allow-symlinks`).

`error.relaxable_by` is present only on a `SecurityViolation` that a core `SecurityConfig` setting
relaxes, and names the setting whose current value refused the entry: `symlinks`, `hardlinks`,
`solid_archives`, `banned_components`, `max_path_depth`, `windows_reserved_names` or
`max_tar_metadata_bytes`. It is absent when no setting relaxes the refusal (for example a forged
size, an encrypted entry, a NUL byte), so read it instead of parsing the `HINT` text. Changing the
setting removes that refusal only: the entry can still fail a later check (a symlink that escapes
the destination fails with `SymlinkEscape` once `--allow-symlinks` is passed; a link escape, symlink
or hardlink, prints `HINT: a link resolves outside the destination (an archive link or an existing
destination symlink); no flag relaxes this check.` with every flag combination, verified live). The
human-readable
`HINT` names the exact flag (`--allow-symlinks`, `--allow-hardlinks`, `--allow-solid-archives`,
`--banned-component`, `--max-path-depth`); `windows_reserved_names` and `max_tar_metadata_bytes`
have no CLI flag, so their hint says "Rust API only". For `banned_components` the hint repeats that
`--banned-component` replaces the whole default list and prints it. Verified live on TARs: a
symlink, a hardlink, a 41-component path and a `.ssh/` entry each print only their own flag, and
`--json` shows `relaxable_by` `max_path_depth` and `banned_components` for the last two.

**`verify` is the one exception to "top-level `status` tells you whether it worked":** a FAIL-status
archive still yields a `status: "success"` envelope (the verification *ran* successfully — it just
found the archive unsafe), with the outcome in `data.status` (`"PASS"` / `"WARNING"` / `"FAIL"`).
For `verify`, branch on `data.status` (or the process exit code), not on top-level `status`.
An archive whose declared compressed sizes exceed the archive length is not reported as an issue:
`verify` fails with an `InvalidArchive` error (`status: "error"`, no `data`, exit `1`).

For `extract`, when some files were already written before a mid-archive failure, `error` carries
a structured `error.partial_report` object (`files_extracted`, `directories_created`,
`symlinks_created`, `bytes_written`, `files_skipped`, `warnings`, `writes`). `writes` is
`"kept"` when the extracted items remain in the destination and `"rolled_back"` under `--atomic`
(including `--atomic --force`) and for a TAR extracted into a destination that does not exist yet
(see the note below), where the partial extraction is discarded and the destination is
left unchanged; the counts then describe what was discarded. Verified live against a
three-entry archive where the first entry extracts, the second is skipped for a disallowed
extension (via `--allowed-extensions`), and the third is a symlink rejected by the (default-off)
`--allow-symlinks` check. The same progress counts, skip count, and warnings also appear as free
text inside `error.message` (prefixed `"WARNING: Extraction was stopped. ..."`, with optional
`"Files skipped: N"` / `"Warnings:"` lines when non-empty; the partial report carries the same skip fields as a finished run) — prefer the structured
`error.partial_report` field over parsing that text.

Human-readable output (`list`, `list -l`, `verify` issue lines, `extract -v`, warnings and error
messages) escapes control and invisible format characters in entry paths and link targets (C0, DEL
and C1 written as `\xHH`; Unicode format characters such as bidirectional controls U+202A..U+202E
and U+2066..U+2069, zero-width characters, and U+2028/U+2029 written as `\xHH` up to U+00FF and
`\u{hhhh}` above), so an archive cannot clear the screen, retitle the terminal, repaint the verdict
or disguise an extension (`evil\u{202e}gpj.exe`) with an entry name. A backslash is not escaped, so
an escape cannot be told apart from a name that literally contains that text; strong right-to-left
letters can still reorder neighbouring neutral characters, and invisible characters outside the
format category are escaped as well: all Unicode 16.0 `Default_Ignorable_Code_Point` characters
(for example U+034F, U+115F/U+1160, U+17B4/U+17B5, U+3164, U+FFA0 and the tag characters) print as
`\xHH` up to U+00FF (U+00AD is `\xad`) and `\u{hhhh}` with at least four hex digits above it
(`\u{034f}`). A variation selector is left as it is only
directly after a character it modifies: U+FE0E/U+FE0F after an emoji base (after `#`, `*` or a digit
only when the keycap U+20E3 follows), U+E0100..U+E01EF after a CJK ideograph, and the Mongolian free
variation selectors after a Mongolian letter. Anywhere else it is escaped, so `report1.pdf` and
`report1\u{fe0f}.pdf` print differently. Use `--json` for the exact path. A TAR regular, continuous
or sparse-file entry whose name ends in `/` and that carries data fails `list`, `verify` and
`extract` with `InvalidArchive`. The CLI writes nothing in that case: into an existing destination
`extract` lists the archive first and the list pass fails (verified live: no `partial_report`), and
into a destination that does not exist yet, or with `--atomic`, the atomic single pass rolls back (verified live:
`out/` is not created, exit `1`, `writes: "rolled_back"` when an earlier entry had been extracted).
Only the Rust, Node and Python extract entry points, which do not run that pass, report a partial
extraction with the entries before it kept. A failed `extract --atomic` reports
`writes: "rolled_back"` and leaves the destination unchanged.

The conflict check asks the library every path extraction creates, the implied parent directories of an entry included (`first.txt` and `a/b.txt` with a file at `out/a`), probes each with `lstat` and names the conflict at the path that holds it, before anything is written (verified live: `out/a` is named, `first.txt` is not written). A destination symlink at a landing is not turned into a generic conflict: one that points outside the destination is refused before any write as a `SymlinkEscape`, one that leads to no directory (a file, a dangling or looping link) as the library's `SecurityViolation` (`refusing to create ... under the existing symlink`, no `relaxable_by`), and a file entry over a link as `refusing to replace the existing symlink`; one that points at a directory inside the destination is left to extraction, which accepts it under `--allow-symlinks` or refuses with that hint. Under `--force` files are still replaced by files, but a file or link where the archive needs a directory is refused before anything is written, because a directory can never replace it (`first.txt` and `a/b.txt` with a file at `out/a`: `out/a` is named and `first.txt` is not written; tested). `--atomic` writes nothing into the destination until the end and is not pre-checked. A failure to inspect a path other than its absence is an error, not a pass. The check asks the library where each entry would land (absolute and Windows-prefixed names, `./` components and paths through earlier links resolved as extraction resolves them, entries extraction would not create left out). Anything already at the landing of a file, link or hardlink is a conflict, and so is a non-directory at the landing of a directory; an existing directory under a directory entry is not. Verified live on a `./a.txt` entry, a symlink entry over a file, a file entry over a dangling symlink and a directory over a directory. `list -l` sizes now count regular files only (a link or directory shows size `0`).

Note: `extract` lists the archive first (a listing under the extraction config, sharing
`--max-files`, `--max-total-size`, and `--max-file-size`) to detect output
conflicts and size the progress bar, except for a TAR (any codec) extracted with `--atomic`
(including `--atomic --force` over an existing destination), or whose destination does not
exist yet and whose parent directory does. `--atomic` decodes a TAR once: the list pass would
only size the progress bar, so it is skipped. A refusal then comes from the staged extraction
itself and is reported as `writes: "rolled_back"` with a partial report (verified live over an
existing destination, exit `1`, destination unchanged), and the staging directory in the
destination's parent filesystem can grow up to `--max-total-size` before a quota refusal.
Those runs skip the list pass, which for a compressed
TAR is a second full decode, and extracts atomically: a refusal anywhere in the archive leaves
nothing on disk, creates no parent directory, and reports `writes: "rolled_back"` (with the counts
of the discarded run) and the extraction's own error text. The progress bar then shows an entry
count without a total (TAR does not know it). When the destination exists (this includes the default, the
current directory) a gz, bz2 or xz TAR whose decoded size is at most 256 MiB is decoded once: the list pass keeps the decoded stream in an unnamed temporary file in `TMPDIR` (RAM on a tmpfs `/tmp`) that extraction reads, and any
decoder error, write failure, larger stream or stricter decoder-memory limit falls back to a second decode. There is no gain when its parent is missing, for zstd TARs, for larger streams, or for ZIP and 7z,
whose list pass reads headers only; those runs behave as described here.
A run killed mid-extraction (SIGTERM, Ctrl-C) cannot clean up, so its hidden staging directory
`.exarch-XXXXXX` stays in the destination's parent and `out/` does not exist; delete the staging
directory by hand. Without `--atomic` into an existing destination, quota violations (file
count, total size, per-file size) are therefore caught during this pre-flight pass and
reported as a plain error with **no** `partial_report`, since extraction never starts. Only checks that require the real destination
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
    "skipped_by_kind": {},
    "skipped_sample": [],
    "duration_ms": 0,
    "warnings": []
  }
}
```

`files_skipped` (the total), `skipped_by_kind` (exact counts per reason: `duplicate`,
`extension_not_allowed`, `excluded`, `hidden`, `over_max_file_size`, `symlink_unsupported`,
`unreadable`; only reasons that occurred) and `skipped_sample` (the first 64 skipped entries, each
`{"kind", "path"}` plus `io_kind` for an unreadable one) are populated whenever entries are skipped
without failing the extraction; `warnings` holds other conditions (7z anti-items, an undeletable
backup). `create` reports the same three skip fields. In text mode the total is followed by one
`kind: N` line per reason. Verified live: `extract --allowed-extensions md` of a one-file archive prints
`Files skipped: 1` / `extension_not_allowed: 1`, and `create -x a.txt` prints `excluded: 1`. A skip no
longer appears as a free-text warning — e.g. `--allowed-extensions` rejecting entries by extension, or duplicate destination
files skipped as duplicates (the default; `--force` overwrites them instead).
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
    "skipped_by_kind": {
      "extension_not_allowed": 2
    },
    "skipped_sample": [
      {"kind": "extension_not_allowed", "path": "a.bin"},
      {"kind": "extension_not_allowed", "path": "b.bin"}
    ],
    "duration_ms": 0,
    "warnings": []
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
    "message": "Security violation: Archive 'evil.tar' attempted path traversal\nHINT: This archive may be malicious. Do not extract from untrusted sources.: path traversal detected: ../../etc/passwd"
  }
}
```

Error (`extract`, mid-archive security failure with partial progress — note the structured
`error.partial_report` field, including `files_skipped`/`warnings`; the archive's first entry
extracts, its second entry is skipped for a disallowed extension, then a symlink entry is
rejected because `--allow-symlinks` was not passed; shown for an existing destination, where the
partial extraction is kept):

```json
{
  "operation": "extract",
  "status": "error",
  "error": {
    "kind": "SecurityViolation",
    "message": "WARNING: Extraction was stopped. 1 items (1 files, 0 directories, 0 symlinks) were written to disk before the error.\nFiles skipped: 1\nHINT: Inspect or remove the output directory before re-running.: operation denied by security policy: symlinks not allowed",
    "partial_report": {
      "files_extracted": 1,
      "directories_created": 0,
      "symlinks_created": 0,
      "bytes_written": 5,
      "files_skipped": 1,
      "skipped_by_kind": {"extension_not_allowed": 1},
      "skipped_sample": [{"kind": "extension_not_allowed", "path": "x.bin"}],
      "warnings": [],
      "writes": "kept"
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
| `2` | Usage error from the argument parser (unknown flag, unparsable value, `-H` without `-l`, `--decompression-budget` without `--check-integrity`). Plain text on stderr, no JSON envelope. The CLI itself never exits `2` otherwise. |
| `3` | `verify --strict` only: the archive is otherwise valid but has warning-level findings, treated as failure because `--strict` was passed. Breaking: this was `2`, which clashed with the usage-error status. |

## Security model (context, not a full manual)

Default `SecurityConfig` limits: 50 MB per file, 500 MB total extracted size, 100x max
compression ratio, 10,000 max files, 32 max path depth. All symlinks, hardlinks, absolute
paths, and world-writable files are rejected unless explicitly allowed. This holds for ZIP too: an
absolute entry name or any `..` component in the raw name is
`PathTraversal` by default. A name is absolute on every platform when it starts with `/` or `\`
(UNC included), or with a drive letter followed by a separator or nothing (`C:\x`, `C:/x`, `C:`);
a drive glued to a name (`C:name`) is absolute only on Windows, and on Unix `a:notes.txt` is kept
as is. An empty entry name and a NUL byte in an entry name are both
`SecurityViolation`. On Windows only, entries
whose path has a reserved device-name component (`CON`, `NUL`, `COM1`, ... ASCII
case-insensitive, with or without an extension, e.g. `NUL.tar.gz`) or a component containing
`:` (NTFS alternate data streams), ending in a dot or space, containing one of `<>"|?*` or a
control character (U+0000 to U+001F), or not valid Unicode (an unpaired surrogate) are rejected with
`SecurityViolation`; the same component checks apply to symlink and hardlink targets. A trailing
dot or space, `:`, `<>"|?*` and control characters are never allowed; only the reserved-device-name check has an opt-out, and it
exists only in the Rust API (there is no CLI flag). On other platforms these names are
accepted. A `.tar.xz` whose LZMA2 dictionary needs more than the decoder-memory limit (default
256 MiB; `SecurityConfig::max_decoder_memory` in the Rust API, 1 GiB under `permissive()`) is
rejected by `extract`, `list` and `verify` with `QuotaExceeded` (`quota exceeded: decoder memory
(> 268435456 bytes)`); there is no CLI flag to raise it. The same limit bounds the zstd window
of a `.tar.zst` and of every zstd entry of a ZIP to the largest power of two at or below it (at
most 128 MiB, which is what the default admits): a larger window fails `extract`, `list` and
`verify` with the same `QuotaExceeded` error, for a ZIP before any entry is listed or extracted, under both
`--zip-consistency` policies. Every zstd entry is walked in full, so entries that share a local
header are each judged by their own frames. (Under `enforce` the open-time census decodes
zstd entries only up to the window the config allows, 128 MiB at the default, and skips larger
ones, which the operation then refuses.)
Gzip members and bzip2 streams of a TAR are capped too: member `n` may start only while `n` is at
most 10,000 plus one per 16 KiB of output decoded so far (`SecurityConfig::
with_compressed_member_allowance` in the Rust API, 100,000 under `permissive()`; no CLI flag),
else `QuotaExceeded` (`quota exceeded: compressed members (10001 > allowance 10000 = base + 1 per
16 KiB decoded)`); writers that flush a member per record (bgzf) average more than 16 KiB and
never reach it. Verified live: an archive built with `xz --lzma2=dict=300MiB` (needs
385 MiB) fails `extract` and `list` with exit code `1`, `error.kind: "QuotaExceeded"` in `--json`;
a `.tar.zst` and a ZIP with a zstd entry written with window log 28 fail `list`, `verify` and
`extract` with exit `1` and `quota exceeded: decoder memory (> 268435456 bytes)` while window log
27 passes; a `.tar.gz` of one member followed by 10,000 empty members fails `list` with exit `1`
and `error.kind: "QuotaExceeded"`. setuid/setgid bits are
always stripped on Unix regardless of `--preserve-permissions`. Solid 7z archives (multiple
files compressed as one block) are rejected by default because extracting even one file
requires decompressing the whole block into memory — a memory-exhaustion vector; enable
`--allow-solid-archives` only for trusted archives, and consider it isn't a substitute for
enough free memory. 7z extraction also admits every block's decoder memory (LZMA/LZMA2
dictionary, PPMd memory) against `max_decoder_memory` before decoding, and decodes
independent LZMA2 runs ahead on worker threads within `--parallel-decode-memory` (default 128M; `off`
decodes on one thread) so the decoder cannot buffer unbounded output; a stock 7-Zip archive has
64 MiB runs and needs about 100 MiB per extra concurrent run, so >= 512M matches the unbounded
reader there. A valid archive decodes to the same bytes either way; on a corrupt one the same
file fails and only that file's leading bytes can differ. Each `extract`/`verify` call may start
up to 16 worker threads and hold its own lookahead, so run concurrent invocations with
`--parallel-decode-memory` sized for the number running, or `off`. Known gap: a compressed 7z *header* is decoded by sevenz-rust2
with no memory limit before any block is checked, so the decoder memory limit (`max_decoder_memory`, Rust API only) does not bound a
PPMd or LZMA2 header coder (up to about 4 GiB); only trusted archives should be opened where
that matters. If an operation is rejected for one of these reasons, that's the security
pipeline working as intended, not a defect to work around by default.
