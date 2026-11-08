# Format-specific refusals: TAR, ZIP, 7z

`list`, `verify`, and `extract` apply the same format checks, so an archive refused by one is refused by all (exit `1`, nothing written) unless noted. `verify` reports structural findings as issues; `list`/`extract` fail.

## Root and empty entries (all formats)

- An entry named `.` or `./` is the destination itself: a directory is a no-op; anything else (file, symlink, hardlink) is rejected with `archive root entry '.' must be a directory`. A zero-size TAR regular-file entry whose name ends in `/` is read as a directory; with a payload it is a rejected file.
- An empty entry name (after PAX/GNU long-name resolution) fails with `operation denied by security policy: empty path not allowed`.
- 7z anti-items ("delete this path" markers) are skipped without a path check and never delete anything. `extract` warns once (`anti_items_skipped`, with `count`); `verify` adds an `INFO` `Archive Note` that does not change `PASS` or `--strict`.

## TAR

A TAR holding constructs that readers (`bsdtar`, Python `tarfile`) parse differently fails with `InvalidArchive`, `sub_code` `TAR_AMBIGUITY`:

- a directory, symlink, or hardlink that declares a payload;
- a GNU sparse (`S`) entry;
- a size or checksum field that is not plain octal (sign or control character) or is base-256, including in `x`, `L`, `K` headers;
- a `prefix` field in a header without ustar magic;
- a PAX header with duplicate records, an empty key, a record over 999999 bytes, a non-numeric `size`, a non-canonical record length, or any `SCHILY.realsize` / `GNU.sparse.*` record;
- a PAX `path`/`linkpath` stacked with a GNU long-name record;
- a global PAX header (`g`) carrying `path`, `linkpath`, or `size`, malformed framing, or following a local PAX header or GNU long record;
- an extension-header typeflag without ustar/GNU magic;
- non-zero bytes between an `x`/`g`/`L`/`K` body and the next 512-byte boundary;
- a non-empty GNU long name/link body not ending in exactly one NUL.

Not covered: PAX keys that extractors apply (xattrs, flags, ACLs) and data after a plain TAR's end marker. A global header with other records (such as `git archive`'s `comment`) is accepted.

A TAR regular, continuous, or sparse entry whose name ends in `/` and that carries data fails with `InvalidArchive`. Non-file entry types (FIFO, device, undefined typeflags) are `SecurityViolation`.

Compressed TAR: the stream after the end marker is read to its end. A corrupt trailer or later member is `InvalidArchive` (`TAR_TRAILER`) and discards the partial extraction; more than `max_tar_metadata_bytes` (default 4 MiB, minimum 1 MiB) of decoded bytes after the marker is a `SecurityViolation` (`TAR_TRAILER`, `relaxable_by` `max_tar_metadata_bytes`), so `cat a.tar.gz b.tar.gz` works only while later members decode to less than that; a zero-padded `.tar.zst` is refused.

## ZIP

A ZIP stores entry metadata in a local header and in the central directory; different readers follow different copies. Under `--zip-consistency enforce` (default), `extract` and `list` fail with `ZipInconsistency` and `verify` reports `HIGH` issues when the archive:

- has a local header disagreeing with the central record on name, Unicode Path extra field, method, encryption flag, data-descriptor flag, mtime, CRC-32, or sizes, or an unparseable local header (`Header Mismatch`);
- repeats an entry name (`Duplicate Entry`; `total_entries` still counts every record);
- has overlapping data ranges (`Overlapping Entries`);
- has an `xl` (`0x6c78`) extra field giving a file type different from the central attributes (`Hidden Entry`; libarchive honours it);
- hides records a streaming reader would reach but a random-access reader never lists (`Hidden Entry`): central directory records beyond the end-record count; a central directory or end-record signature before an entry; a data descriptor after which a streaming reader resumes past the next entry header; a local header no central record maps (before the archive, between entries, behind padding, or before the directory); local headers or record signatures inside the declared range of a stored or compressed (deflate, bzip2, zstd) entry; a second end-of-central-directory record;
- has a directory or special-file entry that declares data (`directory entry N declares a payload of M bytes`). Empty directory entries and symlinks (data is the target) pass.

Header mismatches, `xl` divergence, descriptor overruns, directory payloads, and undecidable stream ends are bound to their entry (`entry_path`, counted in `suspicious_entries`); other findings are archive-level.

Details that matter:
- `total_entries` is the raw central-directory count; a count over `--max-files` is `QuotaExceeded` under both policies.
- Compressed entries are decoded within their declared range (up to 256 MiB of output per archive, plus a shared recheck allowance of max(256 MiB, `--max-total-size`)) to find where the stream ends. An undecidable end is `the end of the compressed stream of entry N cannot be established (...)`. Nested archives (JAR, APK, ZIP in ZIP) are handled; only real hits are refused.
- Cost: under `enforce`, `list`/`verify`/`extract` read compressed data once at open (about 0.4 s for a 73 MB deflate archive). `--zip-consistency ignore` skips this work and discards the findings.
- Pre-ZIP64 archives with over 65535 entries, orphaned local headers or a central signature in a gap (in-place updaters), and ZIP64 directory entries written by the Rust `zip` crate before 9.1.0 are rejected under `enforce`; use `ignore` only for trusted producers.
- Archives from Info-ZIP, `ditto`, 7-Zip, `bsdtar`, Go, Python, Java, and .NET produce no findings; Windows Explorer and WinRAR archives are not covered.
- The `./` root entry from `bsdtar --format zip -cf out.zip .` is the destination itself (`list` shows `.`); a `.` symlink or `.` with data is rejected.
- Compression methods other than Stored, Deflate, Bzip2, Zstd (including `deflate64`) fail with `operation denied by security policy: unsupported compression method: <name>` before anything is written.

## 7z

- Symlink entries (Unix mode `0x8000` flag plus `S_IFLNK`) hold their target in the entry data:
  - `list` leaves it unread unless `--read-link-targets`.
  - `verify` without `--allow-symlinks` fails `symlinks not allowed`; with it, targets are validated only under `--check-integrity` (see [verify.md](verify.md)).
  - `extract` refuses links without `--allow-symlinks` (`symlinks not allowed`, hint `--allow-symlinks`) before writing. An empty or over-long target is refused from the file table before any write, even before the policy hint. Other targets are read and validated as the link is created, so an escaping, corrupt, or non-UTF-8 target stops extraction with earlier entries left in place: use `--atomic`.
  - A link in a solid block needs `--allow-solid-archives`.
  - A corrupt link target fails `extract` with `InvalidArchive`; `--read-link-targets` and `verify --check-integrity` report it unreadable.
- A directory with the Windows reparse-point attribute is listed as a symlink, fails `verify` regardless of `--allow-symlinks`, and is rejected by `extract`.
- A header declaring data streams but no file list (or a stream map not covering its blocks and files) fails with `InvalidArchive` (`failed to open 7z archive: ...`).
- A FIFO, socket, device node, unknown Unix type bits, or an entry whose recorded kind contradicts its own (directory mode on data, file mode on a directory, Windows directory bit on a file) fails with `operation denied by security policy`. `bsdtar --format 7zip` writes FIFOs as stream-less entries, so a tree holding one is refused.
- An entry with an empty name is rejected (`empty path not allowed`).
- Solid archives, decoder memory, and header limits: [security-model.md](security-model.md).
