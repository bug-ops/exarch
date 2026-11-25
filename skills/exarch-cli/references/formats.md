# Format-specific refusals: TAR, ZIP, 7z

`list`, `verify`, and `extract` apply the same format checks, so an archive refused by one is refused by all (exit `1`, nothing written) unless noted. `verify` reports structural findings as issues; `list`/`extract` fail.

## Root and empty entries (all formats)

- An entry named `.` or `./` is the destination itself: a directory is a no-op; anything else (file, symlink, hardlink) is rejected with `archive root entry '.' must be a directory`. A zero-size TAR regular-file entry whose name ends in `/` is read as a directory; with a payload it is a rejected file.
- An empty entry name (after PAX/GNU long-name resolution) fails with `operation denied by security policy: empty path not allowed`.
- 7z anti-items ("delete this path" markers) are skipped without a path check and never delete anything. `extract` warns once (`anti_items_skipped`, with `count`); `verify` adds an `INFO` `Archive Note` that does not change `PASS` or `--strict`.

## TAR

A TAR holding constructs that readers (`bsdtar`, Python `tarfile`) parse differently fails with `InvalidArchive`, `sub_code` `TAR_AMBIGUITY`:

- a directory, symlink, or hardlink that declares a payload;
- a GNU sparse (`S`) entry, unless `--tar-sparse expand` accepts its map (see "GNU sparse entries");
- a size or checksum field that is not plain octal (sign or control character) or is base-256, including in `x`, `L`, `K` headers;
- a `prefix` field in a header without ustar magic;
- a PAX header with duplicate records, an empty key, a record over 999999 bytes, a non-numeric `size`, a non-canonical record length, or any `SCHILY.realsize` / `SUN.holesdata` / `GNU.sparse.*` record;
- a PAX `path`/`linkpath` stacked with a GNU long-name record;
- a global PAX header (`g`) carrying `path`, `linkpath`, or `size`, malformed framing, or following a local PAX header or GNU long record;
- an extension-header typeflag without ustar/GNU magic;
- non-zero bytes between an `x`/`g`/`L`/`K` body and the next 512-byte boundary;
- a non-empty GNU long name/link body not ending in exactly one NUL.

The `TAR_AMBIGUITY` hint depends on the variant and says that no option relaxes the refusal (it names `--zip-consistency ignore` as the ZIP-only switch on commands that accept it):

- a GNU sparse (`S`) entry under the default `--tar-sparse refuse`: well formed but refused by default; the hint names `--tar-sparse expand` and, otherwise, another trusted tool;
- a sparse PAX record (`GNU.sparse.*`, `SCHILY.realsize`, `SUN.holesdata`): well formed but unsupported under both policies; other tools may extract it;
- a sparse map that readers read differently (see "GNU sparse entries"): ambiguous, no option relaxes it;
- ambiguous constructs (duplicate PAX records, global (`g`) overrides, stacked PAX or GNU long records, payload on a directory or link, non-zero padding, prefix without ustar, oversized or duplicate extension headers): well formed but tools disagree about it; the hint says to ask the producer to re-create it and never suggests another tool (a different reader may be the one that sees a hidden member);
- a global PAX header over `max_tar_metadata_bytes` (default 4 MiB): not necessarily damaged; the hint says `No CLI flag relaxes this. Rust API only: SecurityConfig::with_max_tar_metadata_bytes.`;
- malformed headers (bad checksum, malformed or empty-key PAX record, non-numeric `size`, non-canonical number, extension header without magic, malformed GNU long body, window mismatch): `may be corrupted or malformed`, so treat the file as damaged.

Only the sparse hints suggest extracting with another trusted tool; for the ambiguous group do not, have the producer re-create the archive. Do not debug either as damaged. `TAR_TRAILER` corrupt/truncated refusals keep the `may be corrupted or malformed` hint.

### GNU sparse entries (`--tar-sparse`)

Default `refuse`: an old GNU sparse (`S`) entry fails `InvalidArchive`, `sub_code` `TAR_AMBIGUITY`, in `list`, `verify` and `extract`. `--tar-sparse expand` (also accepted by `list` and `verify`) reads it as a regular file of its real size with the holes written as zeros, only when `bsdtar`, Python `tarfile` and the `tar` crate read the map the same way. Anything else stays refused with `TAR_AMBIGUITY` (the message names the map defect) and no option relaxes it:

- a slot with only one empty field, a used slot after an unused one, a zero offset in an extension block, or a zero length before the last used slot;
- an extended flag other than 0 or 1, or extension blocks that do not match the flags;
- a map offset, length or real size that is not plain octal or base-256 (same wording as other non-canonical numbers);
- a PAX `size` record on the sparse entry (`PAX record "size" is not supported`), and every PAX sparse record, also under `expand`;
- a sparse entry named like a directory (ending in `/`) that has a payload.

Cost and limits under `expand`: the real size counts against `--max-file-size` and `--max-total-size` (`QuotaExceeded` in `extract` and `list`, a `HIGH` issue in `verify`) and against nothing else, because a TAR entry has no compressed size to take a ratio against. `extract` writes the holes, so the file takes its full real size on disk. `list`, `verify` and an entry that `extract` skips (`--allowed-extensions`, `--include`, `--exclude`) read only the archived bytes: a 4 TiB hole costs the same as its stored data. A skipped sparse payload is still held to the compression-ratio bound (`ZipBomb`, `sub_code` `SKIPPED_ENTRIES`, when its decoded bytes dwarf the compressed input that produced them).

`list`, `verify` and `extract` all refuse the same maps (exit `1`, nothing written for the refused entry).

`list` applies a local PAX `mtime` record. Global `g` headers, `uname`, `gname`, `uid`, `gid`, and `SCHILY.fflags` are ignored on purpose. Not covered: PAX keys that extractors apply (xattrs, ACLs) and data after a plain TAR's end marker. A global header with other records (such as `git archive`'s `comment`) is accepted.

A TAR regular, continuous, or sparse entry whose name ends in `/` and that carries data fails with `InvalidArchive`. Non-file entry types (FIFO, device, undefined typeflags) are `SecurityViolation`; an unknown typeflag reads `unsupported entry type: 'D' (0x44)`.

A GNU volume label (`V`) with zero size is skipped by `extract`, `list`, and `verify`. A local `x`/`L`/`K` header before it, or a non-zero size, is `TAR_AMBIGUITY`; a global `g` before it is accepted; a blank size field fails `InvalidArchive`.

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

- `extract` gives a regular file that carries a Unix mode `mode & 0o777` minus the umask (exactly, with `--preserve-permissions`); setuid, setgid, and sticky never apply, and world-write follows `--allow-world-writable`. Entries without a Unix mode, directories, and symlinks keep the default mode. `list -l` shows the stored mode; `verify` flags executables and special bits.
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
- A block coded with Deflate, Deflate64, zstd, or lz4 is refused at admission, before any write: `extract` and `extract --atomic` exit `1` and create no destination, `list` still works, `verify` reports `FAIL` (one `HIGH` `7z block uses an unsupported coder or malformed coder properties` issue per block), and `verify --check-integrity` reports `INCOMPLETE` (`not_decodable`) with exit `1`, also under `--json`.
- Solid archives, decoder memory, and header limits: [security-model.md](security-model.md).

## Encrypted archives (ZIP and 7z)

- Supported: ZIP WinZip AES (128/192/256) and 7z AES-256 (content, or header and content). Refused with `SECURITY_VIOLATION` / `ENCRYPTED`: ZipCrypto and 7z raw-key content (`weak_encryption_refused`). Solid encrypted 7z stays refused as solid.
- Password sources: `--password-file <PATH>` (first line, at most 1 KiB, a regular file; on Unix not readable by group or others, else `chmod 600`), `--password-fd <N>` (Unix, first line of an inherited descriptor, e.g. `3< file`), `--password-prompt` (no echo; fails without a terminal). The flags exclude each other; there is no argument or environment variable. A password for an unencrypted archive is ignored. A password file or descriptor that cannot be read fails before the archive is opened.
- A ZIP needs a password only when the run extracts an encrypted entry. An encrypted entry (file, directory or symlink) that `--include`/`--exclude` leave out has its payload never read, with or without a password (a wrong password is not reported); it still fails path validation and counts as not selected. An entry skipped only by a later filter (the extension allowlist) still needs the password.
- Without a password: `extract` that selects an encrypted ZIP entry fails `ENCRYPTED` (`password_required`) before writing; `list` shows the entries of a ZIP and of a 7z with a plain header, marked `encrypted` (a 7z with an encrypted header fails `password_required`); `verify --check-integrity` counts the encrypted ZIP entries and the files of an AES 7z block as unverified with reason `encrypted` (`WARNING`, exit `0`).
- Wrong password: ZIP `wrong_password` (verifier mismatch, before any write) or `authentication_failed` (tampered data); 7z `wrong_password_or_corrupt` (from `extract` and `verify`, also on a PPMd block). A password that is not UTF-8 text fails a 7z `unusable_password`. Key derivation of a 7z over the library budget `max_kdf_work` (2^27 rounds, no CLI flag) fails `kdf_cost_exceeded`.
- A 7z with an encrypted header is held to the same header limits as one with a plain header: a header too large for the configured limits fails as a quota refusal, never as a wrong-password result.
- `verify` of a wrong password on an AES 7z block reports `ENCRYPTED` / `wrong_password_or_corrupt` for each affected entry and continues; the rest of that block is reported as not verified.
- The password is never printed, logged or put in JSON.
