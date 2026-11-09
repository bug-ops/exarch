# verify: full reference

`exarch verify <ARCHIVE>` runs the full validation pipeline (path traversal, links, permissions, structure) without extracting. Run it before `extract` on untrusted archives.

## Flags

| Flag | Default | Notes |
|---|---|---|
| `--strict` | off | Warning-level findings exit `3` (not `0`); `2` stays the usage-error code. |
| `--check-integrity` | off | Decode payload to the decoder's EOF. |
| `--decompression-budget <SIZE>` | 500 MiB | Extra bytes `--check-integrity` may decode beyond listing. Requires `--check-integrity`; `0` refused. Does not follow `--max-total-size`; raise both for archives over 500 MiB. |
| `--allow-symlinks` / `--allow-hardlinks` | off | As `extract`; pass the ones you will extract with. |
| `--include`, `--exclude`, `--strip-components`, `--flatten` | off | As `extract`. An include matching nothing, and a hardlink to an unselected target, are `HIGH` issues. No per-entry rows, so no `disposition`. |
| `--zip-consistency <enforce\|ignore>` | enforce | Structural findings become issues under `enforce`. |
| `--parallel-decode-memory`, `--max-files`, `--max-total-size`, `--max-file-size`, `--max-compression-ratio`, `--allow-solid-archives` | as `list` | File count and total size fail with `QuotaExceeded` past the cap. |

`verify` has no `--max-path-depth`, `--banned-component`, `--allow-absolute-paths`, or `--allow-world-writable`; those are evaluated by `extract` alone.

## Result

- `data.status`: `PASS` / `WARNING` / `FAIL`. Envelope `status` stays `"success"`; exit `1` on `FAIL`. Text: `Archive verification: PASS|WARNING|FAIL`, issue tags `[HIGH]`/`[MEDIUM]`/`[LOW]` (same words with and without color).
- `security_status` (`Security: OK|WARNING|FAILED`) and `integrity_status` (`OK|FAILED|INCOMPLETE|SKIPPED`).
- `--json` prints exactly one JSON document, also on `FAIL`.
- Declared compressed sizes exceeding the archive length is an `InvalidArchive` error (`status: "error"`, no `data`, exit `1`), not an issue.
- `--max-file-size` is the exception to "`QuotaExceeded` aborts": an oversized entry is recorded as a `HIGH` `Quota Exceeded` issue and `data.status` becomes `FAIL`.
- Issue fields: `category`, severity, `entry_path` (null when archive-level). A refusal `extract` would also raise carries `code`, `sub_code`, and where relaxable `relaxable_by` and `setting`. An executable or invalid-permissions finding carries numeric `mode`.

### Issue categories

`Path Traversal`, `Symlink Escape`, `Hardlink Escape`, `Zip Bomb`, `Invalid Permissions`, `Quota Exceeded`, `Security Policy`, `Invalid Archive`, `Suspicious Path`, `Executable File`, `Corrupt Data`, `Integrity Incomplete`, `Header Mismatch`, `Duplicate Entry`, `Overlapping Entries`, `Hidden Entry`, `Name Collision`, `Archive Note`.

- `Archive Note` is informational, never a security finding.
- `Corrupt Data` and `Integrity Incomplete` come only from `--check-integrity` and are not security findings; the flag can still add security issues (`Security Policy` for a forged ZIP size, `Quota Exceeded` for 7z decoder memory), so `Security:` can be `FAILED` with the flag on an archive that is `OK` without it.
- `Security Policy` covers entries rejected by configured policy: links under the default config, NUL bytes, banned components. These make `security_status` `FAILED`. A TAR with a symlink or hardlink therefore exits `1` unless `--allow-symlinks` / `--allow-hardlinks` is passed; a link that escapes the destination fails with either flag.

## Payload integrity (`--check-integrity`)

| `integrity_status` | Meaning | Exit |
|---|---|---|
| `OK` | Every payload byte decoded and every format checksum matched. | `0` |
| `FAILED` | A checksum or decoder error proved corruption: `HIGH` `Corrupt Data`, attributed to the entry (`entry_path` null for a stream trailer such as a gzip CRC). | `1` |
| `INCOMPLETE` | Part of the payload was not verified: one `MEDIUM` `Integrity Incomplete` issue, `status` at least `WARNING`. | `0`, `3` with `--strict` |
| `SKIPPED` | Flag not passed. | n/a |

Reasons an item is unverified: budget exhausted, quota/ratio/decoder-memory limit, solid 7z without `--allow-solid-archives`, an uncovered 7z block checksum, unsupported 7z coder, a TAR stream with no end-of-archive marker, an entry dropped for an over-long path, and an unsearched ZIP data-descriptor tail.

`--json` adds `data.integrity_gaps` (`null` without the flag): `counts` maps each reason (`over_budget`, `resource_limit`, `solid_policy`, `size_ceiling`, `uncovered_block_crc`, `not_decodable`, `no_end_marker`, `path_too_long`, `descriptor_tail`) to a number; `entries` lists up to 256 `{path, reason}`; `omitted` counts the rest. `no_end_marker` and `path_too_long` have counts but no path.

What `OK` covers:

| Format | Checked |
|---|---|
| ZIP | Per-entry CRC-32 and exact declared size; a corrupt entry is reported and the scan continues. |
| TAR | Header checksums and presence of every declared data byte (no payload checksum exists). |
| tar.gz/bz2/xz/zst | The above plus codec framing and checksums (zstd content checksum only if the frame has one). |
| 7z | Per-entry CRC-32 where stored, else the block CRC (attributed to the block's last entry); LZMA/LZMA2/PPMd validity. |

- "To EOF" means every gzip member, bzip2 stream, xz stream, and zstd frame; concatenated archives are read in full. An all-zero tail after the last gzip/bzip2/xz stream is accepted, after the last zstd frame it is an error; other trailing bytes are an error. TAR bytes after the end marker are bounded by `max_tar_metadata_bytes` (at least 1 MiB).
- ZIP entries and 7z blocks are charged their declared size to the budget before decoding; TAR entries are not charged.
- A TAR entry whose content fails to decode is a hard error (exit `1`, `invalid archive: integrity check failed at <path>: ...`); trailer-only corruption is a `FAILED` report.
- For a compressed TAR, `extract`, `list`, and `verify --check-integrity` read to the stream end after the marker; a corrupt later member fails with `integrity check failed after the TAR end-of-archive marker`, and the partial extraction is discarded.

`verify` reports as archive-level issues, exit `1`, everything `extract` refuses in a 7z archive: solid without the flag (`Security Policy`), coder memory over the limit (`Quota Exceeded`), AES-encrypted content under a plain header, an unknown coder, a block whose files do not add up to its decoded size, and a sub-stream count that differs from the streamed-file count (`Invalid Archive`).

## 7z link targets

Targets live in compressed data: plain `verify --allow-symlinks` of a 7z with symlinks reports one `MEDIUM` issue (`N symlink target(s) were not read`) and status `WARNING` (exit `0`, or `3` with `--strict`), even if a link escapes. A `verify && extract` gate does not stop it; gate with `verify --strict` or `verify --check-integrity` (exit `1` on escape), and use `extract --atomic` for all-or-nothing.

## Limitations

- `verify` models only the archive's entries; it cannot see files already in the destination, so `PASS` does not guarantee extraction into a non-empty destination.
- Symlink chains use a per-OS hop limit (macOS 33, Linux glibc 40, musl 39, Windows 63, other Unix 32); a deep chain can still disagree with the real filesystem.
- A hardlink whose target is absent fails `Invalid archive: hardlink target does not exist: <target>`, like `extract`.
- Entry shapes the host rejects are `HIGH` issues (exit `1`): an entry beneath a regular file, a directory over an earlier file or non-directory-resolving symlink, a looping or escaping parent chain, a hardlink to a directory, a link placement that can make extraction fail (reported as `Security Policy`, `Security: FAILED`), and a name component over 255 bytes or a path over the host limit (4095 bytes Linux, 1023 macOS/other Unix, 32767 UTF-16 units Windows). Over-long paths: `list` fails `I/O error: file name too long`; `verify` reports up to 16 archive-level `HIGH` issues then one summary, and with `--check-integrity` the dropped entries count as `path_too_long` (so `INCOMPLETE`).
- `verify` checks the entry's relative path, not the destination prefix: it can `PASS` while `extract` fails with `File name too long` for a long destination.
- First-entry-wins: without `--force`, `extract` skips a later entry at a path the same archive already wrote (`duplicate`); with `--force` the later entry overwrites. `verify` cannot model `--force`; where an overwrite would fail it adds a `LOW` `Invalid Archive` note and status stays `PASS`. A file already present in the destination is refused (`OutputExists`), not skipped.
- Case/Unicode collisions: names are compared after NFD plus case fold on macOS, case fold on Windows, exactly elsewhere. Colliding names are a `Name Collision` issue: `HIGH` when kinds differ or a symlink is involved, `MEDIUM` for two files or two non-empty directories, `LOW` for two empty directories.
- A symlink's or hardlink's recorded mode is not checked (`--strict` still exits `0`).
- Windows component checks (reserved device names, alternate data streams, trailing dot/space, `<>"|?*`, control characters) run only when `verify` runs on Windows.
