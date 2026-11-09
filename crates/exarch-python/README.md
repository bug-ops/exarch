# exarch

[![PyPI](https://img.shields.io/pypi/v/exarch)](https://pypi.org/project/exarch)
[![Python](https://img.shields.io/pypi/pyversions/exarch)](https://pypi.org/project/exarch)
[![CI](https://img.shields.io/github/actions/workflow/status/bug-ops/exarch/ci.yml?branch=main)](https://github.com/bug-ops/exarch/actions)
[![License](https://img.shields.io/pypi/l/exarch)](../../LICENSE-MIT)

Memory-safe archive extraction and creation library for Python.

**Important:** exarch is designed as a secure replacement for vulnerable archive libraries like Python's `tarfile`, which has known CVEs with CVSS scores up to 9.4.

This package provides Python bindings for [exarch-core](../exarch-core), a Rust library with built-in protection against common archive vulnerabilities.

## Installation

```bash
pip install exarch
```

**Tip:** Use `uv pip install exarch` for faster installation.

### Alternative Package Managers

```bash
# Poetry
poetry add exarch

# Pipenv
pipenv install exarch
```

## Requirements

- Python >= 3.11

## Quick Start

### Extraction

```python
import exarch

result = exarch.extract_archive("archive.tar.gz", "/output/path")
print(f"Extracted {result.files_extracted} files")
```

### Creation

```python
import exarch

result = exarch.create_archive("backup.tar.gz", ["src/", "Cargo.toml"])
print(f"Created archive with {result.files_added} files")
```

## Usage

### Basic Extraction

```python
import exarch

result = exarch.extract_archive("archive.tar.gz", "/output/path")

print(f"Files extracted: {result.files_extracted}")
print(f"Bytes written: {result.bytes_written}")
print(f"Duration: {result.duration_ms}ms")
```

### With pathlib.Path

```python
from pathlib import Path
import exarch

archive = Path("archive.tar.gz")
output = Path("/output/path")

result = exarch.extract_archive(archive, output)
```

### Custom Security Configuration

```python
import exarch

config = exarch.SecurityConfig()
config = config.with_max_file_size(100 * 1024 * 1024)  # 100 MB

result = exarch.extract_archive("archive.tar.gz", "/output", config)
```

### Verifying Payload Integrity

`verify_archive` checks security only by default and reports
`integrity_status` as `"SKIPPED"`. Opt in to decode the payload and verify
checksums:

```python
import exarch

options = exarch.VerificationOptions().with_integrity_check()  # 500 MiB budget
report = exarch.verify_archive("archive.zip", options=options)

print(report.integrity_status)  # "OK", "FAILED", "INCOMPLETE" or "SKIPPED"
```

**Note:** `"INCOMPLETE"` means part of the payload was not verified (budget,
resource limit, solid 7z archive while `allow_solid_archives` is off, TAR
without an end-of-archive marker); it comes with a Medium issue, so `status` is
at least `"WARNING"`. With the check on, a TAR entry whose content fails to
decode raises `InvalidArchiveError`.

### Archives in Memory

`list_archive_bytes`, `verify_archive_bytes` and `extract_archive_to_memory`
take the archive as `bytes` or a binary file object. The format is detected
from the leading bytes, or stated with `format` (`"Tar"`, `"TarGz"`,
`"TarBz2"`, `"TarXz"`, `"TarZst"`, `"Zip"`, `"SevenZ"`). Nothing is written to
disk.

```python
import exarch

data = open("archive.tar.gz", "rb").read()

manifest = exarch.list_archive_bytes(data)
report = exarch.verify_archive_bytes(data)

result = exarch.extract_archive_to_memory(data, max_bytes=64 * 1024 * 1024)
for entry in result.entries:
    print(entry.path, entry.kind)  # "file", "directory" or "symlink"
    if entry.kind == "file":
        content = entry.data  # bytes
```

A file object is read from its current position. If it is `seekable()` every
format works; otherwise only TAR (plain or compressed) can be read. An exception
raised by the object propagates unchanged instead of becoming a verdict.

```python
with open("archive.tar.gz", "rb") as f:
    manifest = exarch.list_archive_bytes(f)
```

**Note:** `max_bytes` caps payload plus path bytes plus 256 per entry and
defaults to the config's `max_total_size`; exceeding it raises
`QuotaExceededError`. `path_model="portable"` validates names against the
strictest rules of every platform instead of this host's.

`list_archive_bytes_with_progress`, `verify_archive_bytes_with_progress` and
`extract_archive_to_memory_with_progress` take a `progress` callback
`(path, total, current, bytes_written)` after `config`; `current` counts from 1
and `total` is `None` for TAR. A raising callback cancels the run before the next
entry and its exception is raised (with `progress_callback_error = True`); the
result is discarded. The GIL is released while the archive is processed.

`extract_archive_to_callback(data, on_entry)` hands each verified entry to
`on_entry(entry)` instead of collecting them, so memory use is one file at a
time (bounded by `max_file_size`). A file arrives whole, after its size was
verified. An exception raised by `on_entry` stops the extraction and is raised
unchanged. A `"symlink"` entry's `target` is spelled as the archive stores it,
relative to the link. A `"hardlink"` entry comes last and by reference: its
`target` is the root-relative resolved path of an entry already delivered, a
file or an earlier hardlink (a chain is delivered link by link). With
`SinkOptions(existing_files="overwrite")` a path can be delivered more than once
and a hardlink refers to the latest delivery; implicit parent directories are not delivered.
Entries are provisional: each is delivered as soon as it is verified, so a later
failure refuses the archive after earlier entries were already delivered. The
gzip CRC of a `.tar.gz` is verified after the end-of-archive marker, so a
corrupt compressed stream refuses the archive only after its entries were
delivered.

```python
sizes = {}


def on_entry(entry):
    if entry.kind == "file":
        sizes[entry.path] = len(entry.data)


report = exarch.extract_archive_to_callback(data, on_entry)
```

`create_archive_to_bytes(sources, format)` builds an archive in memory and
returns a `CreatedArchive` with `data` and `report`:

```python
created = exarch.create_archive_to_bytes(["src/"], "TarGz")
open("src.tar.gz", "wb").write(created.data)
```

**Note:** the whole archive is held in memory, up to about 2-3x its size at the
peak, and there is no size cap. Sources must be regular files and directories;
FIFOs and device files are not supported. Use `create_archive` for large
archives.

### Error Handling

```python
import exarch

try:
    result = exarch.extract_archive("archive.tar.gz", "/output")
    print(f"Extracted {result.files_extracted} files")
except exarch.PathTraversalError as e:
    print(f"Blocked path traversal: {e}")
except exarch.ZipBombError as e:
    print(f"Zip bomb detected: {e}")
except exarch.SecurityViolationError as e:
    # e.relaxable_by names the SecurityConfig setting that would admit the entry, or None
    # e.sub_code names the refusal family, e.g. "PATH_NAME", "LINK_POLICY" or "ENCRYPTED"
    print(f"Security violation ({e.relaxable_by}, {e.sub_code}): {e}")
except exarch.InvalidArchiveError as e:
    # e.sub_code is "TAR_AMBIGUITY", "TAR_TRAILER", "ZIP_READER", "LINK_TARGET", "DUPLICATE_ENTRY", "ENTRY_NAME", "DECLARED_SIZE" or "INTEGRITY", else None
    print(f"Invalid archive ({e.sub_code}): {e}")
except exarch.ArchiveError as e:
    print(f"Extraction failed: {e}")
```

## API Reference

### `extract_archive(archive_path, output_dir, config=None)`

Extract an archive to the specified directory with security validation.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `archive_path` | `str \| Path` | Path to the archive file |
| `output_dir` | `str \| Path` | Directory where files will be extracted |
| `config` | `SecurityConfig` | Optional security configuration |
| `options` | `ExtractionOptions` | Optional `ExtractionOptions().with_staging("atomic")` / `.with_existing_files("skip" \| "overwrite" \| "refuse")` |

**Returns:** `ExtractionReport`

| Attribute | Type | Description |
|-----------|------|-------------|
| `files_extracted` | `int` | Number of files extracted |
| `directories_created` | `int` | Number of directories created |
| `symlinks_created` | `int` | Number of symlinks created |
| `bytes_written` | `int` | Total bytes written |
| `duration_ms` | `int` | Extraction duration in milliseconds |
| `files_skipped` | `int` | Number of files skipped (e.g. duplicates) |
| `warnings` | `list[AnyExtractionWarning]` | Typed warnings (`AntiItemsSkippedWarning`, `BackupCleanupFailedWarning`, `RootAccessNarrowedWarning` with a `reason` token): branch on `kind`, not on message text |

**Raises:**

| Exception | Description |
|-----------|-------------|
| `PathTraversalError` | Path traversal attempt detected |
| `SymlinkEscapeError` | Symlink points outside extraction directory |
| `HardlinkEscapeError` | Hardlink target outside extraction directory |
| `ZipBombError` | Potential zip bomb detected |
| `QuotaExceededError` | Resource quota exceeded |
| `SecurityViolationError` | Security policy violation |
| `UnsupportedFormatError` | Archive format not supported |
| `UnknownFormatError` | Archive format cannot be determined from path or magic bytes (subclass of `UnsupportedFormatError`) |
| `InvalidArchiveError` | Archive is corrupted |
| `IOError` | I/O operation failed |

### `create_archive(output_path, sources, config=None, format=None, overwrite=True, durability="synced")`

Create an archive from files and directories. The archive is staged in a temporary file next to `output_path` (its directory must be writable) and renamed into place when complete, so a failed creation leaves the output as it was. `format` states the format when the extension does not (for example `"Zip"` for a `.whl`); `overwrite=False` refuses any existing output.

**Note:** `create_archive` raises `FileNotFoundError` for missing sources, `OutputExistsError` (a `FileExistsError` subclass) when the output exists and `overwrite=False`, and `ValueError` for invalid compression levels — matching standard Python conventions. `SourceNotFoundError` and `OutputExistsError` fill `errno`, `strerror` and `filename` as `open()` does, and I/O failures carry a stable `io_kind` token (for example `"PermissionDenied"`).

`create_archive` and `create_archive_with_progress` take `durability="synced"`
(the default) or `"unsynced"`. `"synced"` flushes the archive and its directory
entry before returning. `"unsynced"` skips both, which is faster, but after a
crash or power loss a replaced output can be empty or truncated and a new
output can be empty, and write-back errors (network filesystems, quotas,
delayed allocation) are not reported, so success does not prove the bytes
reached the disk. Any other value raises `InvalidConfigurationError` with
`setting == "durability"`.

### `extract_archive_with_progress(archive_path, output_dir, config, progress)`

Extract an archive with a progress callback. The GIL is released during extraction, with or without a callback; the callback takes it back for each call.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `archive_path` | `str \| Path` | Path to the archive file |
| `output_dir` | `str \| Path` | Directory where files will be extracted |
| `config` | `SecurityConfig \| None` | Optional security configuration |
| `progress` | `Callable[[str, int, int, int], None] \| None` | Optional progress callback: `(path, total_files, current_file, bytes_written)` |

```python
import exarch


def on_progress(path: str, total: int, current: int, bytes_written: int) -> None:
    print(f"[{current}/{total}] {path} ({bytes_written} bytes)")


result = exarch.extract_archive_with_progress(
    "archive.tar.gz", "/output", config=None, progress=on_progress
)
```

**If `progress` raises** (`KeyboardInterrupt` included), extraction is cancelled: it stops before the next entry and `progress` is not called again. What was written stays on disk, or is rolled back under an atomic `staging`. `progress`'s own exception propagates unchanged, with a `progress_callback_error = True` marker attribute and `writes` plus, while the files remain on disk, `files_extracted`/`bytes_written`/`files_skipped`/`skipped`/`warnings` describing what was written (check the marker before treating the presence of `files_extracted` as a partial-extraction signal, since a genuine partial-extraction failure carries the same attribute names). If extraction failed for its own reason first, the extraction error takes priority — a raising `progress` can never mask a security error such as `SymlinkEscapeError` — and `progress`'s exception is attached as `__cause__` instead of being dropped. `create_archive_with_progress` behaves the same way, discarding the staged archive and attaching no counters.

### `SecurityConfig`

Builder-style security configuration.

```python
config = exarch.SecurityConfig()
config = config.with_max_file_size(100 * 1024 * 1024)  # 100 MB per file
config = config.with_max_total_size(1024 * 1024 * 1024)  # 1 GB total
config = config.with_max_file_count(10_000)  # Max 10k entries
config = config.with_max_compression_ratio(50.0)  # Zip bomb threshold
config = config.add_allowed_extension(".txt")  # Extension allowlist
config = config.add_allowed_extension(".md")
config.allowed_extensions = None  # allow every extension again; [] is refused
config = config.add_banned_component("__MACOSX")  # Skip components
config = config.add_include_pattern("src")  # Extract only matching entries...
config = config.add_exclude_pattern("*.tmp")  # ...except these
config = config.with_strip_components(1)  # Drop leading path components (or .with_flatten())
config = config.with_allow_solid_archives(True)  # Allow solid 7z archives
config = config.with_zip_consistency(
    "ignore"
)  # ZIP structure policy: "enforce" (default) or "ignore"
config = config.with_parallel_decode_memory(
    256 * 1024 * 1024
)  # 7z LZMA2 lookahead memory (default 128 MiB); None decodes on one thread
# Each extract/verify call may start up to 16 worker threads and hold its own
# lookahead, so concurrent calls multiply both.
config = config.with_allow_windows_reserved_names(True)  # CON, NUL, ... (refused by default)
config = config.with_max_tar_metadata_bytes(
    8 * 1024 * 1024
)  # TAR header/metadata bytes between entries (default 4 MiB)
config = config.with_max_decoder_memory(512 * 1024 * 1024)  # Decoder memory (default 256 MiB)
config = config.with_compressed_member_allowance(
    20_000
)  # Base gzip members / bzip2 streams of a compressed TAR (default 10,000)
config = config.with_max_solid_compression_ratio(
    500.0
)  # Solid 7z block ratio; needs with_allow_solid_archives first
```

Every setting an error names in `relaxable_by` has a setter. `list_archive*` takes `options=ListOptions().with_stored_targets()` to read the 7z link targets that a listing leaves unread by default.

**Newer core values.** Output tokens (`kind`, `code`, `sub_code`, `io_kind`, entry and disposition kinds, ...) are the strings `exarch-core` emits, so a value added to the core after your stubs were written still arrives as a plain `str`; an unknown report class falls back to its base class (`ArchiveEntry`, `LinkTarget` with `state == "unknown"`, `EntryDisposition`, `MemoryEntry`, `ExtractionWarning`, `CreationWarning`) instead of raising.

**Patterns.** Include, exclude and `CreationConfig` exclude patterns share one glob grammar (matched case-sensitively on raw bytes, `\` is a separator):

| Pattern | Meaning |
|---|---|
| `*` | any run of bytes within one path component |
| `?` | exactly one byte within one component |
| `[a-c]`, `[0-9]` | one byte from a positive ASCII class; ranges only inside `0-9`, `a-z`, `A-Z` |
| `**` | as a whole component: any number of components, including none (`src/**/*.rs`) |
| `name` | a name without `/` matches any path component, and so the subtree below it |
| `dir/name`, `target/` | a pattern with a `/` anywhere matches from the archive root, and so its subtree |

`{a,b}`, a leading `!`, `a**b`, negated or POSIX classes, unterminated classes and commas are refused (`InvalidConfigurationError`, `setting` is `exclude_pattern`, `entry_include` or `entry_exclude`).

**Entry selection.** Include and exclude patterns, `strip_components` and `flatten` live in `SecurityConfig`, so `extract_archive*`, `list_archive*` and `verify_archive*` apply them identically (`manifest.dispositions` shows where each listed entry lands, why it is skipped, or that it is refused, under the config passed to `list_archive*`). Order of operations: the entry name is validated, matched against the patterns on its original (pre-strip) path, stripped or flattened, and the new name is validated again. An exclude pattern wins over an include pattern, an include pattern that matches nothing fails the extraction (`InvalidConfigurationError`, `setting == "entry_include"`, `unmatched_patterns`), and `staging="atomic_replace"` refuses a selection.

## Security Features

The library provides built-in protection against:

| Protection | Description |
|------------|-------------|
| Path traversal | Blocks `../` and absolute paths |
| Symlink attacks | Prevents symlinks escaping extraction directory |
| Hardlink attacks | Validates hardlink targets |
| Zip bombs | Detects high compression ratios |
| TAR metadata bombs | Bounds GNU long-name/long-link and PAX header record reads |
| Permission sanitization | Strips setuid/setgid bits |
| Size limits | Enforces file and total size limits |

**Caution:** Unlike Python's standard `tarfile` module, exarch applies security validation by default.

## Supported Formats

| Format | Extensions | Extract | Create | List | Verify |
|--------|------------|:-------:|:------:|:----:|:------:|
| TAR | `.tar` | ✅ | ✅ | ✅ | ✅ |
| TAR+GZIP | `.tar.gz`, `.tgz` | ✅ | ✅ | ✅ | ✅ |
| TAR+BZIP2 | `.tar.bz2`, `.tbz2` | ✅ | ✅ | ✅ | ✅ |
| TAR+XZ | `.tar.xz`, `.txz` | ✅ | ✅ | ✅ | ✅ |
| TAR+ZSTD | `.tar.zst`, `.tzst` | ✅ | ✅ | ✅ | ✅ |
| ZIP | `.zip` | ✅ | ✅ | ✅ | ✅ |
| ZIP-family | `.jar`, `.war`, `.ear`, `.nar`, `.nbm`, `.apk`, `.aab`, `.ipa`, `.appx`, `.msix`, `.whl`, `.vsix`, `.xpi`, `.epub` | ✅ | — | ✅ | ✅ |
| 7z | `.7z` | ✅ | — | ✅ | ✅ |

**Note:** ZIP-family formats share the ZIP container but add extra structure (signing, checksum manifests, ordering rules) that exarch doesn't produce, so creation is rejected for those extensions. 7z creation is not yet supported. Solid and encrypted 7z archives are rejected for security reasons. A 7z archive holding a Windows reparse point is refused as a whole; a Unix `S_IFLNK` symlink is read and validated through the symlink policy, so it is created only with symlinks allowed, and a 7z FIFO, socket or device node is refused.

## Comparison with tarfile

```python
# UNSAFE - tarfile has known vulnerabilities (CVE-2007-4559)
import tarfile

with tarfile.open("archive.tar.gz") as tar:
    tar.extractall("/output")  # May extract outside target directory!

# SAFE - exarch validates all paths
import exarch

exarch.extract_archive("archive.tar.gz", "/output")  # Protected by default
```

## Development

This package is built using [PyO3](https://pyo3.rs/) and [maturin](https://github.com/PyO3/maturin).

```bash
# Clone repository
git clone https://github.com/bug-ops/exarch
cd exarch/crates/exarch-python

# Build with maturin
pip install maturin
maturin develop

# Run tests
pytest tests/
```

## Related Packages

- [exarch-core](../exarch-core) — Core Rust library
- [exarch (npm)](../exarch-node) — Node.js bindings

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT License ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
