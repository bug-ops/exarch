# list: full reference

`exarch list <ARCHIVE>`.

## Flags

| Flag | Default | Notes |
|---|---|---|
| `-l, --long` | off | Per-entry type, size, mode, timestamps, link targets. Sizes count regular files only (links and directories show `0`). |
| `-H, --human-readable` | off | Text mode only; requires `--long` (`-H` alone is exit `2`). `--json` always emits raw bytes. |
| `--max-files` / `--max-total-size` / `--max-file-size` | 10000 / 500 MiB / 50 MiB | Hard limits; `QuotaExceeded` past them, never truncation. Entries that `extract --allowed-extensions` skips still count toward `--max-files`, but not toward size limits. |
| `--max-compression-ratio` | 100 | As `extract`. |
| `--allow-solid-archives` | off | List solid 7z (higher memory). |
| `--allow-symlinks` / `--allow-hardlinks` | off | As `extract`: they set the link dispositions of the [selection preview](#selection-preview), so a link shows `[refused]` unless `extract` with the same flags would place it. `--allow-symlinks` implies `--read-link-targets`. |
| `--read-link-targets` | off | Read 7z symlink targets (decodes the blocks that hold them, in a large solid block most of the archive). Otherwise `link_target` state is `unread`. TAR and ZIP always show targets. |
| `--zip-consistency <enforce\|ignore>` | enforce | Under `enforce` an ambiguous ZIP fails `ZipInconsistency` instead of being listed. |
| `--include`, `--exclude`, `--strip-components`, `--flatten` | off | Same grammar as `extract` ([extract.md](extract.md)). |

## Selection preview

Under any selection flag `list` shows what extraction would do:

- Text: `  [lands at <path>]` (written under another name), `  [skipped: <kind>]` (`not_selected` or `stripped_away`), or `  [refused]`.
- `--json`: each entry gets `disposition`: `{"action": "extract", "landing": "x.txt"}`, `{"action": "skip", "kind": "not_selected"}`, or `{"action": "refuse"}`.
- `refuse` marks an entry that validation refuses or extraction cannot place (for example `f/g` below a file entry `f`). `list` reports and does not judge: it still exits `0` while `extract` fails and `verify` reports the issue.
- A link that escapes the destination is always `refuse`, as is a hardlink whose target is missing from the archive, escapes, or is a directory (as `extract` and `verify` refuse it). A 7z link whose target cannot be decoded (for example a solid archive without `--allow-solid-archives`) does not fail the listing: its `link_target` state is `unreadable` and its disposition `refuse`.
- With default selection (link flags alone do not count as a selection) neither suffix nor field appears. `total_entries` and `total_size` still count every entry. An include matching nothing fails `list` like `extract`.

## Link targets

With `--json -l`, each symlink/hardlink entry has a `link_target` object tagged by `state`: `{"state": "recorded", "path": "..."}`, or without a path `missing`, `unread` (7z, not decoded), `unreadable`, `{"state": "oversized", "bytes": N}`. Files and directories have no `link_target` key. Text `list -l` prints `(target missing)`, `(target not read)`, `(target unreadable)`, `(target too long: N bytes)`.

## Failure modes

- A TAR entry that is not a file, directory, or link (FIFO, device, undefined typeflag such as GNU `V`, `M`, `D`) fails `list`, `verify`, and `extract` alike: `SecurityViolation`, exit `1`.
- Ambiguous TAR/ZIP structure and unsupported entries: see [formats.md](formats.md).
- Entry names with control or invisible characters are escaped in text output; use `--json` for exact paths ([json-output.md](json-output.md)).
