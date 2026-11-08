# create: full reference

`exarch create <OUTPUT> <SOURCE>...`. The format comes from the `OUTPUT` extension. Common flags are in `SKILL.md`.

## Flags

| Flag | Default | Notes |
|---|---|---|
| `-f, --force` | off | Replace `OUTPUT`. The archive is written to a temp file in `OUTPUT`'s directory (must be writable) and renamed when complete, so a failed run leaves the previous archive untouched; a replaced file keeps its permission bits. Without it an existing `OUTPUT` fails `OutputExists` (exit `1`). A directory, FIFO, or device as `OUTPUT` is refused even with `--force` (`InvalidConfiguration`, setting `output_path`). The output is never archived into itself. |
| `-l, --compression-level <1-9>` | 6 | Outside 1-9 (negative included) is `InvalidCompressionLevel`, exit `1`, message `Invalid compression level -1: must be between 1 and 9.`; a non-integer is a usage error (exit `2`). |
| `-x, --exclude <PATTERN>` | `.git`, `.DS_Store`, `*.tmp` | Repeatable; grammar below. Counted in `skipped_by_kind.excluded`. |
| `--strip-prefix <PREFIX>` | none | Strip a path prefix from entry names. |
| `--include-hidden` | off | Include dotfiles. Otherwise hidden files are skipped and a hidden directory below a source directory is skipped whole (counted once in `skipped_by_kind.hidden`). A hidden directory given as a source, and a source file given directly, are archived regardless. With `--follow-symlinks` a link is judged by its own name. |
| `--follow-symlinks` | off | Store target contents, not the link. |
| `--max-file-size <BYTES>` | none | Skip larger source files; `0` refused (`InvalidConfiguration`). |
| `--preserve-permissions[=true\|false]` | true | `=false` gives a portable archive. |

Missing or unreadable sources fail with `SourceNotFound` / `SourceNotAccessible` (message names the path and OS error); no archive is left behind.

## Exclude grammar

- `*`: any run of bytes within one component. `?`: exactly one byte (`caf?` does not match `café`). `[a-c]`, `[0-9]`: one byte from a positive ASCII class (range ends in `0-9`, `a-z`, or `A-Z`). `**` as a whole component: any number of components, none included.
- Matching is case-sensitive, on raw bytes; `\` is a separator, not an escape.
- No `/` in the pattern (`node_modules`, `*.log`): matches any path component, excluding that directory and everything below it. A `/` anywhere (`build/out`, `target/`, `./x`, `build/**`): anchored at the archive root; everything below a match is excluded. The archive path has no leading source-directory name: for source `src` write `c/**/*.rs`, not `src/c/**/*.rs`.
- `**` and `./**` alone, or a bare `*`, exclude everything.
- Refused as `InvalidConfiguration` (setting `exclude_pattern`, exit `1`, no archive written): `{}` alternation, `**` glued to other characters, leading `!`, negated/POSIX/non-ASCII classes, unterminated classes, ranges outside `0-9`/`a-z`/`A-Z`, commas, leading/trailing whitespace or control characters, `.`/`..`, absolute paths or drive prefixes, empty, over-long, or NUL-containing values.
- Quote patterns so the shell does not expand them.

## Overwrite defaults differ between front ends

The CLI refuses an existing `OUTPUT` without `--force`. The Node and Python bindings default `overwrite` to `true` (`overwrite: false` / `overwrite=False` to refuse). All front ends write through a staged temp file and rename.

## Symlinks

With `--follow-symlinks` off, a symlink passed directly as a source is archived as a link in TAR; ZIP has no link entry, so it is skipped (`symlink_unsupported`). With it on, TAR and ZIP store the target's content; a directory symlink walks the entire target tree.

## ZIP ratio warning

A ZIP entry compressing beyond 100x is refused by default `extract`/`verify` as a zip bomb, while the same data in a `.tar.gz` extracts. `create` of a `.zip` therefore adds a warning (`data.warnings` object `kind` `zip_ratio_over_default_limit` with `entries`, `limit`, `needed_ratio`). Extract or verify that archive with `--max-compression-ratio` at least `needed_ratio`. Only a path create is scanned.

## Name collisions

Two sources producing the same entry name are refused before writing, for TAR and ZIP: `InvalidConfiguration`, setting `source_paths`, hint `Rename or exclude one of the colliding sources, or strip a different prefix.`, exit `1`, no output left. A directory source contributes its contents only, so `create out c1 c2` collides on equal file names. Comparison is case-sensitive. ZIP directory entries carry the source directory's mode like TAR.

If the archive is published but its directory cannot be synced, `create` still succeeds and adds a `directory_not_synced` warning (not raised on Windows/WASI).

## Refused outputs

- 7z: extract-only (`InvalidConfiguration`, setting `creation_format`).
- ZIP-family extensions with extra semantics: `.jar`, `.war`, `.ear`, `.nar`, `.nbm`, `.apk`, `.aab`, `.ipa`, `.appx`, `.msix`, `.whl`, `.vsix`, `.xpi`, `.epub`. Use plain `.zip`.
