# Security model and non-CLI limits

Context for explaining refusals. A rejection for any reason here is the pipeline working as intended, not a defect to work around.

## Defaults

50 MiB per file, 500 MiB total, 100x compression ratio, 10,000 files, path depth 32. Symlinks, hardlinks, absolute paths, and world-writable files are rejected unless allowed. setuid/setgid are always stripped on Unix, regardless of `--preserve-permissions`.

## Paths (all formats, ZIP included)

- An absolute name or any `..` component in the raw name is `PathTraversal`. A name is absolute on every platform when it starts with `/` or `\` (UNC included) or with a drive letter plus a separator or nothing (`C:\x`, `C:/x`, `C:`). A drive glued to a name (`C:name`) is absolute only on Windows; on Unix `a:notes.txt` is kept as is.
- An empty entry name or a NUL byte is `SecurityViolation`.
- Windows only: reserved device-name components (`CON`, `NUL`, `COM1`, ... ASCII case-insensitive, with or without extension), components containing `:` (alternate data streams), ending in dot or space, containing `<>"|?*` or control characters, or not valid Unicode are `SecurityViolation`; the same checks apply to link targets. Only the reserved-device-name check has an opt-out, and only in the Rust API. On other platforms these names are accepted.

## Download mark

Extended attributes, ACLs and alternate data streams stored in an archive are never restored. The only mark an extracted file can get is a copy of the archive file's own download-origin mark, and only with `--mark-propagation when-marked` (default `never`): read through the archive's open handle, written through the handle that created each file, never derived from entry names or content. A source volume that cannot hold named streams has no mark to copy (`unmarked`). See `extract.md`.

## Decoder memory (no CLI flag)

- `max_decoder_memory` defaults to 256 MiB (`SecurityConfig::max_decoder_memory`, Rust API; 1 GiB under `permissive()`). A `.tar.xz` whose LZMA2 dictionary needs more is refused by `extract`, `list`, and `verify` with `QuotaExceeded` (`DECODER_MEMORY`, message `quota exceeded: decoder memory (> 268435456 bytes)`).
- The same limit bounds the zstd window of a `.tar.zst` and of every zstd ZIP entry to the largest power of two at or below it (at most 128 MiB at the default); a larger window fails with the same error, for a ZIP before any entry is listed, under both `--zip-consistency` policies. Window log 28 fails, 27 passes.
- Gzip members and bzip2 streams of a TAR: member `n` may start only while `n` is at most 10,000 plus one per 16 KiB of output decoded so far (`with_compressed_member_allowance`, Rust API; 100,000 under `permissive()`), else `QuotaExceeded`. Writers that flush a member per record (bgzf) average more than 16 KiB and never hit it.

## Solid 7z

Solid archives (many files compressed as one block) are rejected by default: extracting one file requires decoding the whole block into memory. Enable `--allow-solid-archives` only for trusted archives; it is not a substitute for free memory.

7z extraction admits every block's decoder memory (LZMA/LZMA2 dictionary, PPMd memory) against `max_decoder_memory` before decoding, and decodes independent LZMA2 runs ahead on worker threads within `--parallel-decode-memory` (default 128M; `off` = one thread). A stock 7-Zip archive has 64 MiB runs and needs about 100 MiB per extra concurrent run, so 512M or more matches the unbounded reader. A valid archive decodes to the same bytes either way. Each `extract`/`verify` call may start up to 16 worker threads with its own lookahead: when running concurrent invocations, size `--parallel-decode-memory` for the number running, or use `off`.

## 7z header limits

- `max_decoder_memory` also applies when the archive is opened: to the raw header size, the decoded size of an encoded header, and that header coder's declared dictionary or model.
- Header size cap: 256 bytes per permitted entry plus 64 KiB (`--max-files` x 256 + 64 KiB; about 2.5 MiB at the default). Refusal: `QuotaExceeded`, `sub_code` `HEADER_SIZE`. Memory refusal: `DECODER_MEMORY`. Both come from `list`, `verify`, and `extract`.
- A header declaring more entries than `--max-files` plus a small allowance is refused before its entry table is built (`HEADER_ENTRY_COUNT`; plain headers and encoded headers with one LZMA/LZMA2 coder). A header whose count cannot be read (for example several coders) is `InvalidArchive`, `unsupported header layout`.
- A header whose block, sub-stream or pack-stream table is longer than its entries and blocks account for is refused before it is parsed (`InvalidArchive`, `sub_code` `SEVENZ_READER`, message `the header declares N <table>, more than the M its contents allow`). An encoded header with more than one block or pack stream is `unsupported header layout`.
- Every entry counts toward the header size and against the file limit (directories and links included), so an archive with many directories may need a higher `--max-files`. At the default, 10,000 entries open up to an average path of about 120 characters; a 60,000-file archive needs `--max-files 60001` or more.
- 7-Zip sizes the header dictionary to the header (192 KiB at 3,000 files, 1 MiB at 60,000), so a decoder-memory limit below roughly 26 KiB refuses nearly every 7z archive with an encoded header. Archives written by 7-Zip and the sevenz-rust2 writer are not affected at default limits.
- With an unbounded file count in the Rust API (`Limit::Unbounded`; `None` in the Python and Node bindings) only `max_decoder_memory` caps the header.
