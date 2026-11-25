---
tags:
  - sdd
  - delta
  - creation
created: 2026-11-22
status: merged
related:
  - "[[021-create-staging-and-output-policy/spec]]"
  - "[[002-format-handlers/spec]]"
---

# Delta: one classification for named and walked sources, size re-check on the opened handle (#1292, #1288)

> [!info] Merged into `spec.md` at spec sync of the v0.11.0..main sync (#1292, #1288, #1306).

> [!info] Scope
> Requirement ids continue the table of [[021-create-staging-and-output-policy/spec]] (last id FR-055).

## ADDED

### FR-056

THE SYSTEM SHALL classify every creation object (a file, link or directory found by a directory walk, and a file or link named directly as a source) in one function, so one object under one set of flags gets one decision whichever way it was reached. The function applies its rules in a fixed order, and the first that applies wins:

1. The archive entry name is computed first (`--strip-prefix` and multi-source naming): a directory whose name is empty is not an entry and not an error; any other object whose name is empty fails with `InvalidConfiguration { StripPrefix, RemovesWholeName }`, whatever its size or kind.
2. A FIFO, socket or device is skipped as `SkipKind::SpecialFile` (FR-050).
3. A regular file whose size exceeds `max_file_size` is skipped as `SkipKind::OverMaxFileSize` (spec 002 FR-076).
4. An unfollowed link becomes `EntryType::Symlink`, a directory `EntryType::Directory`, and everything else `EntryType::Content` (FR-053, FR-055).

The size is judged on the metadata the caller saw: walkdir's entry metadata for a walked object, and for a named source `stat` of a followed link (`follow_symlinks`) or `lstat` otherwise. A skip always records the archive entry name, never the source path. A named source is checked against the excluded output once. The walker-only rules (hidden files, exclude patterns, the staged and target files, FR-015, FR-026) stay in the walk and are not part of this function. Name-first is deliberate: the size limit must not change the outcome, because without `max_file_size` both a named and a walked file whose name `--strip-prefix` empties already fail.

**Priority**: must

### FR-057

WHEN TAR or ZIP creation has opened a source (FR-049) and before it writes any of its data, THE SYSTEM SHALL check the size the opened handle reports against `max_file_size`, with the one size rule that FR-056 step 3 uses; a file that grew past the limit after the walk is skipped as `SkipKind::OverMaxFileSize` with its archive entry name, nothing of it is written, it does not count in `files_added`, and its progress entry is completed. ZIP and TAR behave the same. The check judges the opened handle and the walker judges an earlier `stat`, so both stay. A source whose content no longer matches the size it reported is still `SourceChanged` (FR-051, FR-052).

**Priority**: must

### Edge cases (section 6 rows)

| Scenario | Expected Behavior |
|----------|-------------------|
| A file over `max_file_size` whose name `--strip-prefix` empties, named as a source or found in a walked directory | Both runs fail with `InvalidConfiguration { StripPrefix, RemovesWholeName }` (FR-056, #1292); before this change the walked file was skipped as `over_max_file_size` |
| A FIFO whose name `--strip-prefix` empties | Fails with `InvalidConfiguration`, named or walked, not skipped (FR-056) |
| A skipped file (special or over the limit) | The skip names the archive entry, never the source path (FR-056) |
| A file under `max_file_size` at the walk that grows past it before the open, TAR or ZIP | Skipped as `over_max_file_size`, not written, not counted in `files_added` (FR-057, #1288) |

## MODIFIED

(none)

## REMOVED

(none)

## Deviations

(none)
