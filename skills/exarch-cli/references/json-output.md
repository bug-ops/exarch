# `--json` output reference

## Envelope

```jsonc
// success
{ "operation": "extract" | "create" | "list" | "verify", "status": "success", "data": { } }
// error
{
  "operation": "extract", "status": "error",
  "error": {
    "kind": "PathTraversal",        // enum below
    "message": "...",
    "hint": "...",                  // optional; text mode prints it as HINT:
    "conflicts": ["a/x.txt"],       // OutputExists from extract only
    "io_kind": "PermissionDenied",  // IoError only
    "leftover_path": "out/.exarch-AbC123", // failed run left staging/reservation behind
    "relaxable_by": "symlinks",     // some SecurityViolation errors
    "sub_code": "PATH_NAME",        // every SecurityViolation; some InvalidArchive/QuotaExceeded/ZipBomb
    "setting": "max_file_count",    // InvalidConfiguration naming a setting
    "partial_report": { }           // extract after partial writes
  }
}
```

`data` is absent on error, `error` on success. `message` is free text, not stable: branch on `kind`, `sub_code`, `relaxable_by`, `setting`, and `io_kind`. Exception: `verify` on an unsafe archive prints `status: "success"` with `data.status` `FAIL` (see [verify.md](verify.md)).

## `error.kind`

`IoError`, `InvalidArchive`, `PathTraversal`, `SymlinkEscape`, `HardlinkEscape`, `ZipBomb`, `ZipInconsistency`, `InvalidPermissions`, `QuotaExceeded`, `SecurityViolation`, `SourceNotFound`, `SourceNotAccessible`, `OutputExists`, `InvalidCompressionLevel`, `UnknownFormat`, `InvalidConfiguration`, `Cancelled`, and a generic `Error` fallback for failures outside the validation pipeline.

## Error fields

- `hint`: remediation advice as its own string (several joined by `\n`); never embedded in `message`. A refusal no flag relaxes says so in its hint. A hint names only flags the command has.
- `conflicts`: every conflicting destination path, uncapped, in path-component order (`a/b` before `a-b` before `a.c`); `message` lists only the first ten.
- `io_kind`: stable I/O class (`NotFound`, `PermissionDenied`, `StorageFull`, ..., `Other`), the same token the Python (`io_kind`) and Node (`ioKind`) bindings report.
- `leftover_path`: path to clean up after a rolled-back run whose staging directory could not be removed, a failed `--atomic --force` swap, or a staged `create` whose reservation file remains.
- `relaxable_by`: present only when a setting relaxes the refusal: `symlinks`, `hardlinks`, `solid_archives`, `banned_components`, `max_path_depth`, `windows_reserved_names`, `max_tar_metadata_bytes`. The last two have no CLI flag (hint says "Rust API only"). Relaxing one refusal can expose a later check (a symlink that escapes fails `SymlinkEscape` even with `--allow-symlinks`; escape refusals say no flag relaxes them).
- `setting`: stable snake_case id of the refused setting (`max_file_size`, `max_total_size`, `max_file_count`, `max_path_depth`, `max_compression_ratio`, `decompression_budget`, `allowed_extension`, `banned_path_component`, `output_path`, `source_paths`, `creation_format`, `entry_include`, `entry_exclude`, `strip_components`, `entry_selection`, `exclude_pattern`, ...). clap checks only syntax, so every library-refused value (zero limits, bad ratios, empty `--allowed-extensions ,`) exits `1` with this envelope; only unparsable values (`--max-files abc`) are exit `2` plain-text usage errors.
- `partial_report`: `files_extracted`, `directories_created`, `symlinks_created`, `bytes_written`, `files_skipped`, `skipped_by_kind`, `skipped_sample`, `warnings`, `writes`. `writes` is `"kept"` or `"rolled_back"` (`--atomic`, `--atomic --force`, or a TAR into a new destination; counts then describe the discarded run). The same progress also appears as free text in `message`; prefer the structured field.

### `sub_code`

- `SecurityViolation` (always present): `PATH_NAME`, `PATH_DEPTH`, `LINK_TARGET`, `LINK_POLICY`, `EXISTING_SYMLINK`, `ENTRY_TYPE`, `ROOT_ENTRY`, `ENCRYPTED`, `COMPRESSION_METHOD`, `SOLID_ARCHIVE`, `DECLARED_SIZE`, `CONCURRENT_CHANGE`, `TAR_METADATA`, `TAR_TRAILER`, `PLATFORM`, `OUTPUT_CONFLICT`, `SOURCE_PATH`.
- `InvalidArchive` (some): `ZIP_READER`, `TAR_READER`, `SEVENZ_READER` (corrupt or truncated payload; I/O failures stay `IoError`), `LINK_TARGET`, `DUPLICATE_ENTRY`, `ENTRY_NAME`, `DECLARED_SIZE`, `INTEGRITY`, `TAR_AMBIGUITY`, `TAR_TRAILER`.
- `QuotaExceeded`: names the exhausted limit (`FILE_COUNT`, `TOTAL_SIZE`, `FILE_SIZE`, `DECODER_MEMORY`, `SOLID_BLOCK_MEMORY`, `HEADER_SIZE`, `HEADER_ENTRY_COUNT`, ...). Its `message` is one line naming the fact and the archive; advice goes in `hint`.
- `ZipBomb`: scope `ENTRY`, `SOLID_BLOCK`, or `SKIPPED_ENTRIES`.

## Success payloads

`extract` and `create` data:

```json
{ "files_extracted": 3, "directories_created": 1, "symlinks_created": 0, "bytes_written": 18,
  "files_skipped": 2,
  "skipped_by_kind": {"extension_not_allowed": 2},
  "skipped_sample": [{"kind": "extension_not_allowed", "path": "a.bin"}],
  "duration_ms": 0, "warnings": [] }
```

- Skip kinds (`skipped_by_kind`, only those that occurred): `duplicate`, `extension_not_allowed`, `excluded`, `hidden`, `over_max_file_size`, `symlink_unsupported`, `unreadable`, `not_selected`, `stripped_away`. `skipped_sample` holds the first 64 (`io_kind` added for `unreadable`). Text mode prints `Files skipped: N` then `kind: N` lines. Files already in the destination are `OutputExists`, not skipped.
- `warnings` are objects keyed by `kind` with a display `message`: `anti_items_skipped` (`count`), `backup_cleanup_failed` (`path`, `identity` `verified`/`unverified`, `io_kind`) for `extract`; `zip_ratio_over_default_limit` (`entries`, `limit`, `needed_ratio`), `zip_ratio_check_failed` (`reason`), `directory_not_synced` (`io_kind`) for `create`; `root_access_narrowed` (`reason`, one warning per distinct reason) for `extract --atomic` and `--atomic --force`, meaning the published root grants less access than the destination it replaced (or, for an absent destination, than a directory made there would have). `acl_copy_failed` also covers a copy that failed after the publishing rename: the run succeeds and the root is made `0700` with no ACL where the OS allows. `reason` is one of `acl_unreadable`, `destination_changed`, `unmapped_id`, `ownership_differs`, `acl_copy_failed`, `group_not_kept`, `foreign_write_dropped`, `owner_not_kept`, `destination_vanished`. An unknown later kind has only `kind` and `message`.
- `create` reports `data.output_path`.

Path-traversal error example:

```json
{ "operation": "extract", "status": "error",
  "error": { "kind": "PathTraversal",
    "message": "Security violation: Archive 'evil.tar' attempted path traversal: path traversal detected: ../../etc/passwd",
    "hint": "This archive may be malicious. Do not extract from untrusted sources." } }
```

Mid-archive failure with `partial_report` (symlink rejected after one file extracted into an existing destination):

```json
{ "operation": "extract", "status": "error",
  "error": { "kind": "SecurityViolation", "message": "WARNING: Extraction was stopped. ...",
    "hint": "Inspect or remove the output directory before re-running.\nIf this archive is from a trusted source, pass --allow-symlinks.",
    "partial_report": { "files_extracted": 1, "directories_created": 0, "symlinks_created": 0,
      "bytes_written": 5, "files_skipped": 0, "skipped_by_kind": {}, "skipped_sample": [],
      "warnings": [], "writes": "kept" },
    "sub_code": "LINK_POLICY", "relaxable_by": "symlinks" } }
```

## Paths and rendering

- Entry names are rendered the same in text and `--json`: each invalid-UTF-8 byte as `\xNN`, every backslash as `\x5C`; two names differing only in invalid bytes never print alike and no U+FFFD appears.
- Text mode renders host paths (archive, destination, output) the same escaped way when they are not valid UTF-8; valid UTF-8 host paths keep their native spelling (`C:\out\x` on Windows).
- The `--json` envelope keeps host paths exact when valid UTF-8 (`data.output_path`, `error.leftover_path`, the `path` of `backup_cleanup_failed`), so `rm -rf "$leftover_path"` works; only a non-UTF-8 host path is `\xNN`-escaped, marking it unusable verbatim.
- Human-readable output escapes control and invisible characters in entry paths and link targets so an archive cannot clear the screen, retitle the terminal, repaint a verdict, or disguise an extension: C0, DEL, C1 as `\xHH`; Unicode format characters (bidi controls, zero-width, U+2028/2029) and `Default_Ignorable_Code_Point` characters as `\xHH` up to U+00FF and `\u{hhhh}` above. Variation selectors survive only directly after a base they modify. Use `--json` for the exact path.

## Output streams

A second SIGINT/SIGTERM during `extract` or `create` exits at once with the status of the first signal (`130` or `143`) and, under `--json`, writes one `Cancelled` error document. That report is best effort: it is written within 500 ms or abandoned, so a stdout that is blocked (full pipe, lock held) yields no document, and a timed-out write above `PIPE_BUF` (512 bytes on macOS, 4096 on Linux) can leave a partial line. Branch on the exit status, not on the document.

A closed stdout (broken pipe) or a closed stderr under `-v` is success (exit `0`). Any other failure writing to stdout (full disk, EIO) exits `1` in text and JSON mode alike, so `exarch list a.zip > listing.txt` cannot exit `0` with an empty file. `completion` follows the same policy (`Error: failed to write the completions: ...`) and prints no JSON envelope.
