---
tags:
  - sdd
  - delta
  - formats/sevenz
  - formats/tar
created: 2026-11-22
status: open
related:
  - "[[002-format-handlers/spec]]"
  - "[[016-sanitized-mode-and-non-exhaustive-enums/spec]]"
  - "[[019-verify-and-list-model/spec]]"
  - "[[020-reader-sink-and-in-memory-api/spec]]"
---

# Delta: 7z Unix mode restore, TAR volume label, unsupported-type text, PAX mtime in list (#1296, #1297, #1298, #1287)

> [!info] Scope
> Four independent changes to one capability. Requirement ids continue the table of [[002-format-handlers/spec]] (last id FR-077). Spec sync applies the ADDED rows and the MODIFIED rows, then moves this file to `changes/archive/`.

## ADDED

### FR-078

WHEN a 7z entry classified as a regular file (`SevenZKind::File`) has `has_windows_attributes` set and the Unix-extension flag `0x8000` set in `windows_attributes`, THE SYSTEM SHALL restore its permission bits: the raw mode is `(windows_attributes >> 16) & 0o777` (the sticky bit is dropped at the derivation site, so it is never restored), it goes through the same `sanitize_permissions` / `SanitizedMode` pipeline as TAR and ZIP (setuid and setgid stripped, world-writable stripped unless `allowed.world_writable` admits it; `sanitize_permissions` itself is unchanged), and the file is created with that mode by the host target and handed to an `EntrySink` as the same `SanitizedMode`. The flag is read in exactly one place, shared with the file-type classification of FR-043, so type and permission never come from different conditions. Rules:

- No attributes, or attributes without `0x8000`, mean no mode: the file keeps the default mode (`0666 & ~umask`).
- A flag set with no file-type bits is a regular file and its mode is restored.
- A derived mode of `0` is applied as-is (parity with `7zz x`, TAR and ZIP).
- Directories, symlinks, reparse points, special files, kind contradictions, undefined types and anti-items get no mode, and a mode field never changes whether they are refused (FR-043 unchanged); a directory keeps the default directory mode.
- The Windows read-only attribute (`0x1`) is not mapped to a Unix mode.
- The host write path creates the file with the sanitized mode, or marks it restrictive before the data is written when the mode is stricter than the default, and applies it with `fchmod` on the open descriptor, never a path-based `set_permissions`, exactly as the TAR and ZIP write path does; on a platform without a Unix permission model the mode is ignored.
- WHEN `--force` replaces an existing file, the temporary sibling carries the archive's mode before the rename (FR-052), so the replacement ends with the archive's mode, not the previous occupant's.
- A duplicate entry skipped by the duplicate policy never changes the mode of the file already written.
- Mode restore changes no admission outcome, quota charge, ratio check, duplicate decision or refusal; a hostile attribute word (arbitrary high 16 bits) never panics.
- `list` and `verify` are unchanged: 7z `ArchiveEntry.mode` stays `None`, so no mode is reported (the fallback of the 7z mode draft's FR-012; reporting a mode is a separate public-API decision).

**Priority**: must

### FR-079

WHEN `extract`, `list` or `verify` reads a TAR entry of typeflag `V` (GNU volume label), THE SYSTEM SHALL decide it by one rule in the header check, which sees the whole extension window of the entry:

- WHEN a local `x`, `L` or `K` header precedes the label, THE SYSTEM SHALL refuse it with `TarAmbiguity::ExtensionBeforeLabel { kind }` (`InvalidArchive`, sub-code `TAR_AMBIGUITY`, message `ambiguous TAR header: a {kind} header precedes a volume label`): the `tar` crate merges that header into the label entry while `bsdtar` applies it to the next member.
- WHEN the label's raw header size or its entry size is non-zero, THE SYSTEM SHALL refuse it with `TarAmbiguity::NonRegularPayload { kind: TarNonRegularKind::VolumeLabel, size, path }` (`TarNonRegularKind` gains `VolumeLabel`, rendered `volume label`).
- Otherwise (zero raw size, zero entry size, no local extension header before it) THE SYSTEM SHALL skip the label like any metadata entry: it is not extracted, not listed and not counted, identically in `extract`, `list` and `verify`.
- A preceding global `g` header is its own entry and never part of the label's window, so it does not trigger the first refusal.
- The extension-header rule is checked first: a label that has both a local extension header and a size reports `ExtensionBeforeLabel`.

A label whose size field is blank (NUL or spaces) stays `InvalidArchive`: the `tar` crate fails in `Header::entry_size` before the entry reaches exarch. Closing that form depends on upstream `tar-rs` handling of a blank-size `V` (tar-rs#499) and is tracked as a follow-up (P4); the issue is closed partially on purpose. The matching code never matches the `tar` crate's `__Nonexhaustive` variant, so a future named variant for `V` cannot change this rule.

**Priority**: must

### FR-080

WHEN `list` reads a TAR entry that a local PAX header carries a parseable `mtime` for, THE SYSTEM SHALL report that value as the entry's modification time; otherwise it reports the ustar header mtime, and `None` when neither is available. A PAX `mtime` is `-?digits(.digits)?` (a negative value is before the epoch, the fraction is truncated to nanoseconds, arithmetic is checked); an unparseable or unrepresentable value is ignored and the header mtime is used. `extract` sets no modification time and is unchanged. These PAX records are deliberately not applied, and the docs say so: a global `g` header's `uid`, `gid` and `mtime` (parity with `bsdtar`), `uname`, `gname`, `uid` and `gid` (exarch reports and restores no owner), and `SCHILY.fflags` (no flags are restored).

**Priority**: should

### Edge cases (section 6 rows)

| Scenario | Expected Behavior |
|----------|-------------------|
| 7z regular file stored `0755`, `0444` or `0640` with the Unix flag | Extracted with that mode through the sanitizer; host and sink agree (FR-078, #1296) |
| 7z regular file stored `0o4755`, `0o2755`, `0o6755`, `0o1777` or `0o777` | Same as TAR for the same bits, except the sticky bit, which 7z never restores; setuid, setgid and (by default) world-writable are cleared (FR-078) |
| 7z regular file stored mode `0` | Applied as-is (FR-078) |
| 7z entry without attributes or without the `0x8000` flag, or only the Windows read-only attribute | Default mode, as before (FR-078) |
| 7z directory with a stored mode, symlink with a stored mode | Mode ignored (FR-078) |
| `extract --force` over a `0600` file with a 7z entry stored `0644` | Replacement ends `0644` (FR-078) |
| TAR `V` entry with zero size and no local `x`/`L`/`K` before it, alone or after `g`, after a file, or twice | Skipped in `extract`, `list` and `verify`; only real members appear (FR-079, #1297) |
| TAR `x` (PAX) or `L`/`K` (GNU) header followed by a `V` | `TarAmbiguity::ExtensionBeforeLabel` (FR-079) |
| TAR `V` with a non-zero raw header size or entry size and no extension header | `TarAmbiguity::NonRegularPayload` with kind `volume label` (FR-079) |
| TAR `V` with a blank size field | `InvalidArchive` (the `tar` crate refuses the header); follow-up F1, upstream tar-rs#499 (FR-079) |
| TAR entry with a local PAX `mtime` that differs from the ustar mtime | `list` shows the PAX value; negative values are before the epoch; a malformed value falls back to the header mtime; a global `mtime` is ignored (FR-080, #1287) |
| TAR entry of an unsupported typeflag, for example `D` | `SecurityViolation`, text `unsupported entry type: 'D' (0x44)`; a non-printable byte reads `unsupported entry type: 0x00` (FR-040, #1298) |

## MODIFIED

### FR-040

Old: WHEN `extract`, `list` or `verify` meets a TAR entry that is a FIFO, character or block device, socket or any other typeflag that is not a file, directory or link, or has an empty name, THE SYSTEM SHALL refuse it with `ArchiveError::SecurityViolation`; a file-typed entry with a directory name (trailing `/`) and a payload SHALL be `TarAmbiguity::DirectoryNamedPayload`, with an empty one read as a directory; a root entry (`.`, `./`) SHALL be a directory.
New: the same, with two changes. (1) The refusal of an unsupported typeflag is `Violation::UnsupportedTarType { typeflag: TarTypeflag }`, where `TarTypeflag` is a public newtype over the typeflag byte built from the entry's own byte (not from the `tar` crate's enum); its `Display` is `'c' (0xNN)` for a graphic ASCII byte and `0xNN` (two uppercase hex digits) otherwise, so the message reads `unsupported entry type: 'D' (0x44)`; `TarTypeflag` is re-exported from the crate root. (2) A GNU volume label `V` is no longer an unsupported typeflag: it follows FR-079 (skipped when plain, otherwise `TarAmbiguity`).

### FR-051

Old: the `TarAmbiguity` list ends with "... and a directory, symlink or hardlink entry that declares a payload (`NonRegularPayload` with `TarNonRegularKind`)".
New: the list also names a local `x`, `L` or `K` header that precedes a GNU volume label (`ExtensionBeforeLabel`, FR-079) and a volume label that declares a payload (`NonRegularPayload` with `TarNonRegularKind::VolumeLabel`, FR-079). `TarAmbiguity` gains the variant `ExtensionBeforeLabel { kind: TarExtensionKind }` (the enum is `#[non_exhaustive]`, sub-code unchanged).

## REMOVED

(none)

## Deviations

(none)
