---
aliases:
  - Format Handlers Spec
  - Archive Format Spec
tags:
  - sdd
  - spec
  - archive
  - rust
created: 2026-05-20
updated: 2026-11-06
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[001-security-pipeline/spec]]"
  - "[[003-config-api/spec]]"
  - "[[004-progress-tracking/spec]]"
  - "[[008-tar-empty-directory-preservation/spec]]"
  - "[[009-accurate-compression-reporting/spec]]"
  - "[[013-quota-permit-capability-token/spec]]"
  - "[[017-zip-header-consistency/spec]]"
  - "[[018-7z-stream-map-panic/spec]]"
  - "[[020-reader-sink-and-in-memory-api/spec]]"
---

# Feature: Format Handlers

> [!note] Revision 2026-11-04 (50-issue batch, shipped in 0.9.0)
> `ArchiveFormat` is sealed and its handles are opened under the config they enforce (#908, #901); `FormatCreator`, `TarCreator`, `ZipCreator`, `ArchiveCreator` and the public `creation::{tar,zip}::create_*` are removed (#908, #912); the `Validated`/`Unvalidated` typestate is gone (#898); `EntryValidator` is gone, handlers use `ValidatorCore` proofs (#900); creation writes through a staged file (#931, see [[021-create-staging-and-output-policy/spec]]). Older notes below that name removed items describe the release they mention.

> [!info] Metadata
> **Subsystem**: exarch-core / formats
> **MSRV**: Rust 1.99.1
> **Codec and container dependencies (v0.8.0)**: `zip` 9.x (`Cargo.toml` `~9.4`, locked 9.4.1; floor 9.0.5), `liblzma` 0.4.9 static for xz (bundles xz 5.8; replaces `xz2`, #763, #771), `sevenz-rust2` 0.24.2 (minimum), `lzma-rust2` 0.24
> **Source**: extracted from [[001-exarch-system/spec]]

> [!note] Batch #1008 amendments
> Decoder read errors are classified by one typed chain (FR-063), occupant overwrites are gated by `ReplacePermit` (FR-067) and the run record is keyed by file identity (FR-068).

> [!note] Batch #981 amendments
> Read and write faults are classified at the copy (FR-063); zip 9.4 header refusals map to typed findings (FR-064); `formats` is crate-private (FR-062, #978B).

## 1. Overview

### Problem Statement

Each archive format (TAR variants, ZIP, 7z) requires different parsing logic,
decompression stacks, and entry iteration models. Without a uniform abstraction,
format-specific quirks bleed into security and reporting code, making it hard
to add formats or change security policy uniformly.

### Goal

Provide a single `ArchiveFormat` trait that every format handler implements,
giving the rest of `exarch-core` a uniform extract/list/verify interface
regardless of the underlying format. The trait is sealed (#908). Archive creation
dispatches on `CreationFamily` (a match inside `CreateRequest`), with no creator
trait. Format detection is performed once at the API boundary
using both file extension and a fixed set of ZIP-family aliases.

### Out of Scope

- RAR archive support
- Archive encryption or signing
- 7z archive creation (extraction only — `CreatableFormat` has no 7z variant)
- Network transport: input is a local path or a caller-supplied reader; ZIP and 7z readers must be seekable (see [[020-reader-sink-and-in-memory-api/spec]])

## 2. User Stories

### US-001: TAR Extraction

AS A Rust developer
I WANT to extract `.tar.gz`, `.tar.bz2`, `.tar.xz`, `.tar.zst`, and `.tar` archives
with a single call
SO THAT I do not need to select the correct decompressor manually

**Acceptance criteria:**
```
GIVEN an archive path with a recognized TAR extension
WHEN extract_archive() is called
THEN the correct decompressor is selected automatically and extraction proceeds
through the security pipeline
```

### US-002: ZIP Extraction including Aliases

AS A developer or operator
I WANT `.jar`, `.apk`, `.whl`, and other ZIP-family archives to be extractable
SO THAT I can inspect their contents without a separate tool

**Acceptance criteria:**
```
GIVEN an archive path with a ZIP-family alias extension (e.g. .apk, .jar, .whl)
WHEN extract_archive() is called
THEN the archive is treated as ZIP and extraction proceeds normally
```

### US-003: ZIP-Family Alias Creation Rejection

AS A developer
I WANT archive creation to reject ZIP-family aliases without an explicit format override
SO THAT I am not silently given a bare ZIP file named .apk

**Acceptance criteria:**
```
GIVEN an output path with a ZIP-family alias extension and no CreationConfig::format override
WHEN create_archive() is called
THEN the call fails with ArchiveError::InvalidArchive with an explanatory message
```

### US-004: 7z Extraction Only

AS A developer
I WANT `.7z` archives to be extractable
SO THAT I can use exarch as a single tool for all common formats

**Acceptance criteria:**
```
GIVEN a valid .7z archive
WHEN extract_archive() is called
THEN extraction proceeds through the security pipeline and files are written to output_dir
```

```
GIVEN a .7z output path
WHEN create_archive() is called
THEN the call fails with ArchiveError::InvalidConfiguration
```

### US-005: Solid 7z Rejection by Default

AS A server operator
I WANT solid 7z archives to be rejected unless explicitly enabled
SO THAT a malicious solid archive cannot exhaust memory

**Acceptance criteria:**
```
GIVEN a solid 7z archive and SecurityConfig with allow_solid_archives = false
WHEN extract_archive() is called
THEN extraction fails before decompressing the solid block
```

### US-006: Format Detection

AS A developer
I WANT the correct handler selected automatically from the archive path
SO THAT I do not need to specify the format explicitly, even for files with missing or ambiguous extensions

**Acceptance criteria:**
```
GIVEN an archive path with an unrecognized extension
WHEN any archive operation is called
THEN ArchiveError::UnknownFormat { path } is returned immediately
```

```
GIVEN an archive whose extension is absent, unrecognized, or contradicts the file content
WHEN any archive operation is called
THEN detect_format falls back to magic-byte inspection and selects the correct handler
```

```
GIVEN an archive where magic bytes and extension disagree
WHEN any archive operation is called
THEN magic bytes take precedence over the extension
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-020 | WHEN an archive path has extension `.tar`, `.tgz`, `.tar.gz`, `.tar.bz2`, `.tbz`, `.tbz2`, `.tar.xz`, `.txz`, `.tar.zst`, `.tzst`, THE SYSTEM SHALL extract it as a TAR archive with the appropriate decompressor | must |
| FR-021 | WHEN an archive path has extension `.zip` or any ZIP-family alias, THE SYSTEM SHALL extract it as a ZIP archive | must |
| FR-022 | WHEN an archive path has extension `.7z`, THE SYSTEM SHALL extract it using the 7z handler | must |
| FR-023 | WHEN format detection cannot identify an archive via extension, THE SYSTEM SHALL fall back to magic-byte inspection (ZIP local-file header / EOCD, GZIP, BZ2, XZ, Zstd, 7z, TAR USTAR); when magic bytes and extension disagree, magic takes precedence; if neither resolves a format, THE SYSTEM SHALL return `ArchiveError::UnknownFormat { path }` | must |
| FR-024 | WHEN creating archives, THE SYSTEM SHALL support TAR (all compression variants) and ZIP; 7z creation SHALL return `InvalidConfiguration` | must |
| FR-025 | WHEN creating archives for ZIP-family aliases with `OutputFormat::FromExtension` (no `OutputFile::with_format`), THE SYSTEM SHALL return `ArchiveError::InvalidArchive` with an explanation | should |
| FR-026 | WHEN a 7z archive is solid and `SecurityConfig::solid_archives` is `SolidArchives::Refuse`, THE SYSTEM SHALL reject extraction before decompressing the solid block | must |
| FR-027 | WHEN a 7z solid archive extraction is permitted, THE SYSTEM SHALL reject any solid block whose summed unpack size exceeds `SolidLimits::max_block_memory` with `QuotaExceeded { SolidBlockMemory { scope: Block, .. } }`, and the archive-wide sum too (scope `Archive`) while `max_total_size` is unbounded (see [[003-config-api/spec]] FR-052; before #911 the check was an archive-wide `TotalSize` refusal) | must |
| FR-028 | Every format handler SHALL route all entries through `ValidatorCore` (typed proofs `ValidatedFile`, `ValidatedSymlink`, `ValidatedHardlink`) before writing to disk | must |
| FR-029 | WHEN listing or verifying an archive, THE SYSTEM SHALL NOT write any files to disk | must |
| FR-030 | WHEN `allowed_extensions` in `SecurityConfig` is non-empty, ALL three format handlers (TAR, ZIP, 7z) SHALL skip entries whose extension is not in the allowlist and record them as `SkipKind::ExtensionNotAllowed` in `ExtractionReport::skipped` (`files_skipped()` is derived) | must |
| FR-031 | `ArchiveFormat::extract` SHALL accept and invoke a `ProgressCallback` for every entry; ZIP-family alias creation without an explicit `OutputFile::with_format` SHALL be rejected with `ArchiveError::InvalidArchive` naming the alias | must |
| FR-032 | WHEN creating an archive, THE SYSTEM SHALL write an explicit directory entry (TAR: `append_dir`; ZIP: `add_directory`) for every directory in the source tree, including empty and nested-empty directories, for all TAR variants and ZIP alike; `CreationReport::directories_added` SHALL exclude the archive root itself (implemented v0.6.0, #400 — see [[008-tar-empty-directory-preservation/spec]]) | must |
| FR-033 | WHEN archive creation completes, THE SYSTEM SHALL set `CreationReport::bytes_compressed` to the actual on-disk size of the created archive file, measured after the writer/encoder is fully flushed and finished, for ZIP and every TAR variant (implemented v0.6.0, #402 — see [[009-accurate-compression-reporting/spec]]) | must |
| FR-034 | WHEN a symlink (to a file or to a directory) is passed directly as a top-level `create` source, THE SYSTEM SHALL classify it via `lstat`/`symlink_metadata` (not `stat`/`metadata`) and archive it as `EntryType::Symlink`, not dereference it into file content; a dangling symlink source SHALL NOT be rejected as missing | must |
| FR-035 | WHEN `CreationConfig::follow_symlinks` is enabled, THE SYSTEM SHALL dereference a symlink source (file or directory) for both TAR and ZIP creation, embedding the target's real content instead of a link entry | must |
| FR-036 | WHEN a TAR hardlink entry is extracted, THE SYSTEM SHALL charge its target's on-disk size against `QuotaTracker` via `ValidatorCore::charge_hardlink` before copying, so hardlink extraction cannot bypass `max_file_size`/`max_file_count`/`max_total_size` (fixed v0.6.0, #426) | must |
| FR-037 | WHEN listing an archive (`list_archive`), THE SYSTEM SHALL route every entry through the same `QuotaTracker` used by extraction rather than a separate, weaker inline implementation; a single entry larger than `max_file_size` SHALL be rejected during listing (fixed v0.6.0, #396 — breaking change: `list`/`verify` previously enforced only file count and total size) | must |
| FR-038 | WHEN 7z extraction writes a file and no pre-existing file occupies the destination, THE SYSTEM SHALL write directly to the destination path (same `O_EXCL`+`O_NOFOLLOW` guarantee as TAR/ZIP) instead of always staging through a temp-file-then-rename, retaining the temp+rename path only for the overwrite case (perf fix v0.6.0, #492: closed a 35–101% throughput gap vs. `sevenz_rust2::decompress_file`) | must |
| FR-039 | WHEN reading any compressed TAR, THE SYSTEM SHALL decode through the one `CompressionCodec::decoder` mapping shared by `extract`, `list`, `verify` and the `open_tar_*` functions, decoding every gzip member, bzip2 stream and xz stream and requiring at least one (trailing data after the last member is typed `TrailingData` for gzip and bzip2 only; for xz and zstd it is a decoder error), a gzip or bzip2 stream starting member `n` only while `n` is at most `compressed_member_allowance` plus one per 16 KiB decoded, else `QuotaExceeded { resource: CompressedMembers { members, allowance } }` (v0.8.0, #851); after the last, only an all-zero tail (xz: a multiple of four bytes) SHALL be accepted, and any other trailing bytes are an error; the decoded bytes after the TAR end-of-archive marker SHALL be read to the end of the stream and are bounded by `max_tar_metadata_bytes` (never less than 1 MiB), a longer tail being `ArchiveError::TarTrailer(TarTrailerRefusal::OverCap)` (a security violation relaxable by that setting), and a gzip CRC or ISIZE failure, trailing data or a truncated member there `TarTrailer(Corrupt { cause, detail })` or `TarTrailer(Truncated)`, which report as `InvalidArchive` (0.7.0, #652, #670, #838; typed in v0.8.0, #850) | must |
| FR-040 | WHEN `extract`, `list` or `verify` meets a TAR entry that is a FIFO, character or block device, socket or any other typeflag that is not a file, directory or link, or has an empty name, THE SYSTEM SHALL refuse it with `ArchiveError::SecurityViolation`; a file-typed entry with a directory name (trailing `/`) and a payload SHALL be `TarAmbiguity::DirectoryNamedPayload`, with an empty one read as a directory; a root entry (`.`, `./`) SHALL be a directory (0.7.0, #717, #721, #744, #752) | must |
| FR-041 | WHEN a ZIP is opened, THE SYSTEM SHALL admit only entries compressed with Stored, Deflate, Bzip2 or Zstd (anything else, including Deflate64, is `SecurityViolation`) and unencrypted, for `extract`, `list` and `verify` alike; entry names are split by exarch on both `/` and `\`, absolute and `..` names are refused unless `allow_absolute_paths` admits an absolute one, and an empty name or NUL byte is `SecurityViolation` (0.7.0, #652, #653, #717) | must |
| FR-042 | WHEN a ZIP is opened, THE SYSTEM SHALL apply the structure checks governed by `SecurityConfig::zip_consistency` (`ZipConsistencyPolicy::Enforce` by default), as specified in [[017-zip-header-consistency/spec]] (0.7.0, #671) | must |
| FR-043 | THE SYSTEM SHALL classify every 7z entry once, in `formats::sevenz::classify` (`SevenZClass`), for `extract`, `list` and `verify`: anti-items are skipped (one warning in `extract`, an informational `IssueCategory::ArchiveNote` in `verify`); a FIFO, socket, device node, undefined Unix type, a recorded kind that contradicts the entry's own kind, a reparse-point entry, or an empty name is refused with `SecurityViolation`; a Unix-mode symlink is validated through the symlink policy and `extract` creates it only under `allow_symlinks` (0.7.0, #707, #708, #710, #713, #715, #717, #723) | must |
| FR-044 | WHEN extracting or verifying a 7z archive, THE SYSTEM SHALL open the header once into a `SevenZHeader` whose stream map is proven to cover every block and file ([[018-7z-stream-map-panic/spec]]), walk entries in archive order, check every block's coder memory against `max_decoder_memory` (default 256 MiB) before decoding, bound a solid block as a whole by `SolidLimits::max_ratio` (Rust API only, default 1000.0), and decode single-stream LZMA2 blocks on worker threads within the `ParallelDecode` lookahead (default 128 MiB) with the same output and error kinds as sequential decoding (0.7.0, #652, #688, #728, #752); since the sevenz-rust2 0.25 bump the header read is bounded on open (FR-069) and a shifted sub-stream count is refused at open (FR-070) | must |
| FR-045 | WHEN a TAR is xz-compressed, THE SYSTEM SHALL decode through `liblzma` (static, concatenated streams) with the memory limit set from `max_decoder_memory`, mapping liblzma's memory-limit error to `QuotaExceeded { resource: DecoderMemory { max } }`; a zstd TAR SHALL be decoded with the window limit `max_decoder_memory` implies, mapping libzstd's `windowTooLarge` the same way, and the `zstd` crate SHALL be built without `legacy` support (v0.8.0, #849); creation SHALL encode with `liblzma` at the requested preset (v0.8.0, #763, #771) | must |
| FR-046 | WHEN a 7z block contains an entry with no stream (an empty file, directory or anti-item) between files, THE SYSTEM SHALL list, verify and extract the block, relying on `sevenz-rust2` 0.24.2 covering every entry of a block; a block whose file sizes do not add up to its decoded size, including a block with data and no sub-streams, SHALL be refused before any byte is decoded (v0.8.0, #675, #751, #770) | must |
| FR-047 | THE SYSTEM SHALL extract 7z through one loop (`formats::sevenz::extract`) shared by the host filesystem and an `EntrySink`, with the per-destination differences confined to the `SevenZTarget` hooks (`SevenZHostTarget`, sink target); TAR and ZIP keep their per-format loops and send only validation and the final write through `ExtractTarget` (v0.8.0, #792, #793, #808; see [[020-reader-sink-and-in-memory-api/spec]]) | must |
| FR-048 | THE SYSTEM SHALL provide reader-based extraction and inspection, through for TAR, ZIP and 7z as `ListRequest::list_reader`, `VerifyRequest::verify_reader` and `SinkExtractRequest::extract` (7z in the first two since #771, in the sink since #787; the free functions `list_reader*`, `verify_reader*` and `extract_to_sink*` were removed in #912), and `verify` SHALL create no temporary directory (v0.8.0, #754, #771, #772, #787) | must |
| FR-049 | WHEN a TAR's first member name starts with `BZh` but the leading bytes are not a complete bzip2 stream header, THE SYSTEM SHALL detect it as TAR rather than bzip2-compressed TAR; magic-byte detection reads 512 bytes and a ZIP, 7z, gzip, xz or zstd magic at offset 0 always wins over the `ustar` marker (v0.8.0, #781, #790) | must |
| FR-050 | THE SYSTEM SHALL build `exarch-core` and `exarch-cli` for `wasm32-wasip1` (CI job `wasm`, wasmtime smoke test) (v0.8.0, #755, #771) | must |
| FR-051 | WHEN `extract`, `list` or `verify` reads a TAR, THE SYSTEM SHALL refuse with `ArchiveError::TarAmbiguity(TarAmbiguity)` (`InvalidArchive`, sub-code `TAR_AMBIGUITY`) every construct that `bsdtar` or Python `tarfile` parse differently from the `tar` crate: a malformed, empty-key, over-long (above 999999 bytes), duplicate or `GNU.sparse.*`/`SCHILY.realsize` PAX record; a PAX `size` that is not decimal; a global PAX header that carries `path`, `linkpath` or `size`, exceeds the metadata limit, or follows a local PAX header or a GNU long record; a PAX `path`/`linkpath` stacked with a GNU long name/link record; a PAX `size` record in the same extension chain as a GNU long name/link record (`StackedSizeRecord`, 0.9.0, #957); an `x`, `L` or `K` header without a ustar or GNU magic; a GNU sparse entry; a `prefix` field without a ustar magic; a size or checksum field that is not a canonical octal or base-256 number (signed, space- or control-padded); a checksum mismatch; two extension headers of one kind before an entry; non-zero padding after an `x`, `g`, `L` or `K` body; an `L`/`K` body that is not one NUL-terminated string; and a directory, symlink or hardlink entry that declares a payload (`NonRegularPayload` with `TarNonRegularKind`) (v0.8.0, #820, #829, #837, #846, #848) | must |
| FR-052 | WHEN `extract` replaces an existing regular file (`--force`) in TAR, ZIP or 7z, THE SYSTEM SHALL write a sibling temporary file whose name length does not depend on the entry name and rename it over the destination, instead of writing through the existing inode; the replacement succeeds for a read-only file, needs a writable parent directory, does not keep the previous owner, ACLs or extended attributes, and takes `0666 & ~umask` when the entry carries no mode, and 7z SHALL NOT delete the existing file before the replacement is decoded (v0.8.0, #819, #822, #828) | must |
| FR-053 | WHEN a compressed TAR is read, THE SYSTEM SHALL bound the decode of entries it skips (allowlist or duplicate): their decoded bytes SHALL NOT exceed `max_compression_ratio` times the compressed input read so far, else `ArchiveError::ZipBomb` with `ZipBombScope::SkippedEntries`; an entry refused by quota SHALL NOT be decoded to its end, and `verify` with the integrity check applies the same bound as `extract` and `list` (v0.8.0, #863, #868, #884, #894) | must |
| FR-054 | THE SYSTEM SHALL apply the extension allowlist after path validation and before quota in TAR, ZIP, 7z and `list`: a skipped entry is not charged to `max_total_size` (the list pass charges it to `max_file_count` only), a skipped entry with an invalid path or below an existing file or dangling symlink is refused rather than skipped, and the same files are extracted from every format whatever the destination state, leaving no directory behind for a skipped entry (v0.8.0, #831, #846) | must |
| FR-055 | WHEN a TAR is extracted, listed or verified, THE SYSTEM SHALL read a source read error as `ArchiveError::Io` keeping its errno, not as `InvalidArchive` (v0.8.0, #858, #882, #884) | must |
| FR-056 | THE SYSTEM SHALL make `ArchiveFormat::{extract, list, verify}` consume `self`, so the trait is not dyn-usable, has no `format_name`, and a second operation on one `TarArchive` is a compile error (v0.8.0, #875, #881, #888) | must |
| FR-057 | `ArchiveFormat` SHALL be sealed (a crate-private `sealed::Sealed` supertrait implemented for the TAR, ZIP and 7z handles); handles SHALL be opened under the config they enforce (`ZipArchive::new(reader, &SecurityConfig)` absorbing the former `for_config`, `TarArchive::new`, `SevenZArchive::new`, `open_tar_gz`/`bz2`/`zst`/`xz`) and keep it in an `Arc`, so `ArchiveFormat::{extract(out, options, progress), list(), verify(options)}` take no config and a handle cannot be operated under a policy it was not opened for (`ZipArchive::check_admission` fails closed with an unclassified `InvalidArchive` error, and a debug assertion, if a ZIP is operated without the stream checks its policy needs); `ConfigProblem::{OpenedForOtherPolicy, OpenedUnderSmallerZstdWindow}` were removed (#908, #901) | must |
| FR-058 | WHEN TAR extraction reports progress, THE SYSTEM SHALL route every entry through `EntryCompleteGuard` and report `EntryTotal::Unknown` (a TAR stream has no entry count up front); list and verify passes report `Unknown` until `set_total` (#904) | must |
| FR-059 | WHEN a TAR or 7z reader fails, THE SYSTEM SHALL classify it as `InvalidArchive` with sub-code `TAR_READER` (five kinds, seven sites) or `SEVENZ_READER` (five kinds, five sites), messages unchanged (#930) | must |
| FR-060 | WHEN a ZIP read-back needs the same decode again, THE SYSTEM SHALL keep the spooled plaintext according to `DecodeReuse`; the TAR spool is replayed unconditionally by `ListedArchive::extract` and `Kept::serves` is a `debug_assert!`; the `DecodeReuse::TempFile` rustdoc records the measured floor of the design (macOS, release CLI, deflate ZIPs of 10 MiB members: 1.15x the wall time of the build before decode reuse for 100 MiB decoded and 1.18x for 300 MiB; `Memory` 1.07x on the 100 MiB archive; Linux ext4 and tmpfs not measured, and the Linux detection was first built by CI, not run on a Linux host; writing decoder chunks straight to the file measured no faster, and the in-memory arena and `fadvise` ideas of #929 were not adopted) (#929) | should |
| FR-061 | WHEN the `DecodeReuse::TempFile` spool lives on RAM-backed storage (`SpoolBacking::Ram`, detected with `fstatfs` for `TMPFS_MAGIC` or `RAMFS_MAGIC` on Linux and Android; on Apple and FreeBSD `fstatfs` `f_fstypename` equal to `tmpfs`, and on both a `f_mntfromname` of `/dev/md` followed by at least one digit and anything after it (`md0p1`, `md0.eli`) as well (the rule is compiled for Apple too, where `/dev/md` names are not expected), since a memory or swap backed `md` disk is charged as RAM and a vnode-backed one only shrinks the spool, never risks memory; every other host and every failed probe is `SpoolBacking::Disk`), THE SYSTEM SHALL charge the spool like `Memory` against the reuse limit, `max_decoder_memory` and `max_total_size`, with the used amount equal to the spool file length, and SHALL evict by truncating the spool tail; truncation SHALL NOT cut below the end of the entry just taken (`held_end`), and a taken entry's prefix stays charged until extraction ends; an open spool is a `TempSpool { file, backing }`; the TAR `ListedArchive` spool on a tmpfs is capped the same way (FR-066, #960, done); uncovered after #959: the Linux `fstatfs` detection and the `/dev/shm` test have never been run by hand on a Linux host and there are no `off`, `memory` and `temp-file` timings on ext4 and tmpfs (follow-up A, P3, perf); a macOS RAM disk made with `hdiutil attach -nomount ram://N` and formatted HFS+ or APFS is classified `Disk` because `statfs` shows it like any `/dev/diskN` image and IOKit or DiskArbitration would need FFI that `unsafe_code = "deny"` forbids in exarch-core; the FreeBSD arm is compiled and run by no CI job (follow-up B); a FreeBSD nullfs or unionfs over a tmpfs, and ZFS on an `md` disk (`f_mntfromname` is the dataset name), are classified `Disk`, so their spools are not charged as memory, and a macOS tmpfs mount is in practice only a third-party one | should |
| FR-062 | The `formats` module and the concrete handlers (`TarArchive`, `ZipArchive`, `SevenZArchive`, the `ArchiveFormat` trait, `open_tar_*`) SHALL be crate-private (`pub(crate)`); callers use the request API and the root re-exports (`ArchiveType`, `CreatableFormat`, `CompressionCodec`, `detect_format`, which the CLI needs); `ZIP_FAMILY_ALIASES` stays private; the other public modules (`api`, `config`, `creation`, `error`, `inspection`, `reader`, `report`, `security`, `sink`, `types`, `writer`) become private once the root `pub use` block carries every public item they held (for example `CreationReport` and the `inspection::manifest` items); items behind the `testing` feature keep that gate and `formats` is not added to it; tests, benches, examples and fuzz targets use the request API or live as in-crate unit tests, and every migrated security test keeps asserting the same typed error (#978) | must |
| FR-063 | Every entry-data copy (host target, 7z writers, sink) SHALL use `copy_bounded` and classify through `ReadFaults::classify`: `Write` is always `Io`; `Read` is the budget violation if any, else `Io(fault)` when the source tap recorded a fault, else `Io` for any errno or an `Opaque` source, else `InvalidArchive` with the family malformation; `Short` is `Malformation::TarEntryTruncated` for `Tar` with no source fault, every other `Short` and every `Overrun` keep the declared-size verdict (`DeclaredSizeMismatch`, `DeclaredSizeExceeded`; GHSA-5j8q). New malformations: `TarEntryTruncated`, `ZipEntryDataUnreadable`, `SevenZEntryDataUnreadable` (sub-codes `TarReader`, `ZipReader`, `SevenZReader`). ZIP reads go through the shared fault slot of `ZipStructure`, 7z through `SourceRead` (now `Seek`) around the decode and the solid skip-drain; a 7z header parse that records a source fault is `Io`, not `SevenZHeaderUnreadable`. The classification sweep also covers errno-free source faults and the TAR trailer. A destination write fault stays `Io` for TAR, ZIP, 7z and sinks. `TarReadBudget::classify` (header reads) is not switched to this helper because header reads keep `InvalidArchive` for opaque sources (#964, #965). Since #1006 the read verdict is one typed chain (`classify_decoder_read` returning `ReadVerdict`: `Budget`, `SourceFault`, `Checksum`, `DeclaredSizeOverrun`, `Truncated`, `Malformed`) shared by extract, list and verify, keyed on typed errors (`ReplayChecksumMismatch`, `DeclaredSizeCeiling`) found by downcast, never by message text; the ZIP-crate keyword fallback (`zip_crate_failure`) applies only to ZIP callers' wording | must |
| FR-064 | `ZipHeaderField` SHALL gain ten typed variants for the zip 9.4 refusals the census catches (`FIELD_MESSAGES` in `zip_structure`): `CompressionFlags`, `AesMetadata`, `FileNameNul`, and `UnicodePath` with `LanguageEncoding`, `DirectoryStatus`, `NotUtf8`, `IllegalCharacter`, `Components`, `TrailingDotsOrSpaces`, `Extension`; list, verify and extract agree on each, proven by 11 RawZip fixtures (`zip_structure/tests/unicode_path.rs`; the not-UTF-8 field is ignored by the zip reader, so that fixture asserts acceptance and the mapping is covered by a message-level test) and the `xl_type` expectation follows the typed finding. The requirement is `zip = "~9.4"` (locked 9.4.1, also in `fuzz/Cargo.lock`), so a release that changes a message cannot enter silently, and `.github/workflows/zip-drift.yml` (weekly, SHA-pinned) relaxes it to `9`, runs `cargo update -p zip` and the core nextest run, and fails on drift; no second copy of zip's rules exists (#971) | must |
| FR-065 | `ZIP` directory entries SHALL carry the source directory mode as TAR does, subject to `PermissionPolicy` ([[008-tar-empty-directory-preservation/spec]], #968) | must |
| FR-066 | A listed or spooled TAR (`open_spool`) on a tmpfs SHALL be held to `max_decoder_memory`, as the ZIP reuse spool is (`SpoolBacking::capacity`); a disk spool is unchanged; a damaged spool or replay is `Io` (`ReadFamily::Opaque`), never `InvalidArchive` (#960) | must |
| FR-067 | Every site that meets an occupied path (TAR, ZIP and 7z host targets, sinks, run-record duplicates) SHALL decide through the single `ExistingFiles::on_occupant(created_here, refusal)`, returning `OccupantAction::{Skip, Replace(ReplacePermit)}`; `ReplacePermit` is neither `Clone` nor `Copy` and obtainable only under `ExistingFiles::Overwrite`, and every destructive occupant operation (`VettedDir::replace_entry`, `remove_occupant`, creating the temporary sibling) takes one, so a missed `Refuse` arm cannot reach an overwrite; under `Refuse` an occupant the run itself created is a counted duplicate and any other is `OutputExists` (#1004) | must |
| FR-068 | The run record SHALL key each created entry by the open file's identity (`FileIdentity::of_file`, symlinks by `statat`) with an `IdentityKey` on every platform and a path-keyed fallback (`LandingKey::Path`) when the identity is `Unknown`, so a case-only duplicate on a case-insensitive volume is recognised by identity rather than spelling (#996, #1005) | should |
| FR-069 | WHEN a 7z archive is opened THE SYSTEM SHALL bound the header read in two steps (`formats/sevenz/header.rs`, `header_probe.rs`, #674). First, `header_probe` reads the signature header and the first bytes of the next header and takes the declared size of a plain header, or the declared output size of the one-coder folder of an encoded-header record; a size above `min(max_decoder_memory, max_file_count * 512 bytes + 64 KiB)` is refused as `QuotaExceeded { resource: DecoderMemory { max } }` (`max` is the cap that tripped) before any parse, in `list`, `verify` and `extract` alike; an unbounded file count adds no entry cap; a layout the probe does not recognise, and a probe read failure (classified afterwards through the source tap), is held to that cap on every quantity (fail closed). Second, sevenz-rust2 receives `max_decoder_memory` through `Archive::read_with_memory_limit` (whole KiB, floor and saturating, so a limit under 1 KiB refuses every non-empty header) and checks the raw header size, the decoded header size and the header coder's declared dictionary or model, mapping `MaxMemLimited` to the same `QuotaExceeded`. The entry cap is checked by exarch and not passed upstream because upstream applies one limit to all three quantities, and writers set 8 MiB header dictionaries for small headers. The constant of 512 bytes per entry was measured on 7-Zip 26.05 archives (about 100 bytes per entry for 36-character names; names dominate): at the default `max_file_count` it admits an average path of about 245 characters, and `--max-files` raises it. 7-Zip sizes the header dictionary to the header (4 KiB for a few files, 192 KiB at 3,000, 1 MiB at 60,000) and the LZMA model adds about 22 KiB, so a `max_decoder_memory` below roughly 26 KiB refuses every archive with an encoded header, `list` included. Not bounded by this check: the entry table that a header inside the cap makes sevenz-rust2 build (about 96 bytes per header byte, up to about 480 MiB at the default configuration), the buffer that receives the decoded header (up to about twice the limit), and block decoding (charged by admission, `min(dictionary, 2 * unpack size)`). sevenz-rust2 has no entry cap of its own; an upstream request for one is drafted. A `MaxMemLimited` on any end-header candidate of the recovery scan refuses the whole archive. `BlockDecoder::new` stays unlimited: admission (`coder_memory`) is the single verdict shared by `verify` and `extract` | must |
| FR-070 | WITH `sevenz-rust2` 0.25.0 as the minimum version THE SYSTEM SHALL rely on upstream, which rejects a header that has fewer streamed files than sub-streams inside `Archive::read`, so that shape (the 0.24 writer shape, #769) is refused at open by `list`, `verify` and `extract` with nothing written; `TODO(#769)` is gone and the size-sum check (`BlockSizeUnaccounted`) stays for orphan blocks | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | `BufReader` wraps all TAR file handles to reduce syscall count |
| NFR-002 | Performance | `CopyBuffer` (reusable buffer) used for all byte copying in format handlers |
| NFR-003 | Reliability | Solid 7z archives are rejected by default (`SolidArchives::Refuse`) |
| NFR-004 | Portability | Format detection is case-insensitive on extension matching |
| NFR-005 | Maintainability | Every format handler implements `ArchiveFormat` — no format-specific logic in `api.rs` |
| NFR-006 | Portability | The crate has no hard dependency on a filesystem path for list, verify or sink extraction, and compiles for `wasm32-wasip1` (FR-050) |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `ArchiveType` | Enum of supported archive formats | `Tar`, `TarGz`, `TarBz2`, `TarXz`, `TarZst`, `Zip`, `SevenZ` |
| `ArchiveFormat` | Trait implemented by every format handler | Methods: `extract`, `list`, `verify` (each takes `self`; the trait is not dyn-usable) |
| Creation dispatch | Creation is a `match` on `CreationFamily` (`Tar(Option<CompressionCodec>)` or `Zip`) of a `CreatableFormat` inside `request.rs`, so a 7z request cannot reach it; `FormatCreator`, `TarCreator`, `ZipCreator` and `ArchiveCreator` were removed (#908, #912) | `CreateRequest::{create, write, to_bytes}` |
| `TarArchive<R>` | TAR handler generic over decompressor type | Implements `ArchiveFormat`; `list()` consumes the internal reader (TAR is forward-only); do not call `extract()` on the same instance; `open_tar_gz`, `open_tar_bz2`, `open_tar_zst` and `open_tar_xz(path, &SecurityConfig)` return `TarArchive<Box<dyn Read + Send>>` (the decoder is bounded by `max_decoder_memory` fixed at open) |
| `ZipArchive` | ZIP handler | Implements `ArchiveFormat`; `ZipArchive::new(reader, &SecurityConfig)`; `rebind(config)` (crate-private) swaps the stored config and `debug_assert!`s `serves`; `ZipFile::name()` returns `Result<Cow<str>, ZipError>` in zip 9.x |
| `SevenZArchive` | 7z handler (read-only) | Implements `ArchiveFormat` only (extraction goes through the single loop in `formats/sevenz/extract.rs`, v0.8.0); fires `on_entry_start`/`on_entry_complete` per-entry, interleaved with I/O; the header is parsed once into a `SevenZHeader` (`formats/sevenz/header.rs`) and entries are decoded in archive order through `BlockDecoder::for_each_entries` (`formats/sevenz/decode.rs`), never `decompress_with_extract_fn`, so the validator (`ValidatorCore`) remains the sole path-security guard (v0.5.1); entry names are normalized via `formats::common::normalize_entry_name` before validation; the handler is split into `admit`, `classify`, `decode`, `extract`, `header`, `host`, `links`, `lzma2`, `sink`, `verify` and `write` modules |
| `ExtractTarget` | Validation-and-write half of a TAR or ZIP extraction (v0.8.0): `HostTarget` for the filesystem, a sink target for `EntrySink`; per-kind `validate_*` return typed proofs from `security::admitted` | `validate_file` (returns `FileAdmission::{Write, Skipped}`), `validate_directory`, `validate_symlink`, `validate_hardlink`, `directory`, `file`, `symlink`, `hardlink` |
| `ExtractionContext<'_, '_>` | Private TAR helper struct reducing extraction helper arity | Groups `validator`, `dest`, `report`, `tally`, the skip counters, `config` |

### ArchiveType Detection Rules

| Extension(s) | ArchiveType |
|---|---|
| `.tar` | `Tar` |
| `.tar.gz`, `.tgz` | `TarGz` |
| `.tar.bz2`, `.tbz`, `.tbz2` | `TarBz2` |
| `.tar.xz`, `.txz` | `TarXz` |
| `.tar.zst`, `.tzst` | `TarZst` |
| `.zip` | `Zip` |
| `.jar`, `.war`, `.ear`, `.nar`, `.nbm`, `.apk`, `.aab`, `.ipa`, `.appx`, `.msix`, `.whl`, `.vsix`, `.xpi`, `.epub` | `Zip` (extraction) / error (creation) |
| `.7z` | `SevenZ` |
| `.gz` (no `.tar` stem), anything else | Try magic-byte fallback; `UnknownFormat { path }` if magic also fails |

> [!note] v0.5.0: magic-byte fallback
> `detect_format` now falls back to magic-byte inspection when the file extension is absent,
> unrecognised, or contradicts the file content. Seven signatures are recognised: ZIP (local-file
> header, EOCD, split-archive marker), GZIP, BZ2, XZ, Zstd, 7z, and TAR USTAR. When magic bytes
> and extension disagree, magic takes precedence. Archive creation (`determine_creation_format`)
> remains extension-only so stale on-disk bytes cannot override the caller's intent.

### Trait Signatures

```
ArchiveFormat (sealed; handles are opened under their config):
  extract(self, output_dir, options, progress) -> Result<ExtractionReport>
  list(self) -> Result<ArchiveManifest>
  verify(self, options) -> Result<VerificationReport>
```

Creation has no trait: `CreateRequest::create(&OutputFile, sources)`, `write(ArchiveWriter, sources)` and `to_bytes(CreatableFormat, sources)`.

> [!note] v0.7.0: `verify` takes `&VerificationOptions` (#670)
> `ArchiveFormat::verify(options)` takes a `&VerificationOptions` selecting whether
> the payload is decoded to check integrity (`VerifyRequest::with_options`); with integrity
> requested, TAR content that fails to decode is an error rather than a report issue.

> [!note] v0.6.0, superseded by #898 and #901: `ArchiveFormat` required `SecurityConfig<Validated>` (#433, #434, #435)
> Historical. The typestate was removed in #898 and the config is now stored in the handle (FR-057).
>
> `SecurityConfig` is now a two-state typestate over `Unvalidated`/`Validated` markers
> (`SecurityConfig<State = Unvalidated>`). `ArchiveFormat::extract`, `list`, and `verify`
> now take `config: &SecurityConfig<Validated>` instead of `config: &SecurityConfig` — a
> breaking change for anyone implementing `ArchiveFormat` outside the crate or calling
> `TarArchive`/`ZipArchive`/`SevenZArchive` methods directly. The top-level
> `extract_archive*`, `list_archive`, `verify_archive`, and `create_archive*` functions are
> unaffected: they still accept a plain `&SecurityConfig` (defaulting to `Unvalidated`) and
> call `validate()` internally before dispatching to `ArchiveFormat`. No validation logic
> changed — this is purely a compile-time hardening of the existing "call `validate()` before
> use" convention.

> [!note] v0.6.0: the validated file entry carries a `QuotaPermit` (#436, #439, #440, #447)
> Every format's file-write path (`formats::common::extract_file_with_permit` for TAR/ZIP,
> `formats::sevenz::write_file_with_permit` for 7z) now takes the `QuotaPermit` capability token
> by value instead of matching-and-dropping it (`_`). Since v0.8.0 (#793, #808) the permit
> comes from the typed `ValidatedFile` that `ExtractTarget::validate_file` returns, so no handler
> matches on a validated-entry enum (`ValidatedEntryType`, removed in #900) and only the file path can obtain a permit; the
> v0.6.0 ZIP runtime guard and TAR exhaustive match were removed. See
> [[013-quota-permit-capability-token/spec]] for the full pattern.

> [!note] v0.6.0: 7z extraction performance parity with `sevenz_rust2::decompress_file` (#492)
> `formats::sevenz::write_file_with_permit_using` previously always staged through a temp file
> and `rename`, even when nothing occupied the destination — costing two extra syscalls per
> extracted file and attributing 45-54% of extraction CPU time to this path in profiling.
> `process_entry_inner` now writes directly to `dest_path` via `common::create_file_with_mode`
> when no pre-existing file is found there, keeping the atomic temp+rename path only for the
> overwrite case (so a decode failure mid-stream never leaves a truncated file at the final
> destination). `SevenZArchive` also retains its already-parsed `sevenz_rust2::Archive` from
> `new()` instead of re-parsing the header a second time at extraction. Re-measured via a new
> `sevenz_vs_reference` criterion bench group: the gap closed from 35%/101% slower to within
> noise of parity.

> [!note] v0.6.0: symlink sources archived as links, not dereferenced (#510, #512)
> A symlink (to a file or a directory) passed directly as a top-level `create` source was
> previously classified via `stat`/`metadata` (follows symlinks), silently dereferencing it into
> the target's content and rejecting a dangling symlink as `SourceNotFound`. `creation::walker::collect_entries`
> now uses `lstat`/`symlink_metadata` for this classification, so a symlink source archives as
> `EntryType::Symlink` by default (TAR: link entry; ZIP: skipped with a `Skipped symlink`
> warning, since ZIP has no on-disk symlink representation) and a dangling symlink is no longer
> rejected. **Breaking behavior change**: `exarch create a.tar link.txt` now stores a real
> symlink entry rather than the target's dereferenced content — extracting that archive now
> requires `--allow-symlinks` (deny-by-default) where it previously round-tripped without it.
> `CreationConfig::follow_symlinks` dereferences as before when explicitly enabled, and ZIP
> creation gained the `follow_symlinks` handling it was previously missing entirely.

> [!note] zip dependency
> Upgraded from 8.6.0 to 9.0.0-pre2 in v0.4.0, to 9.1.0 in v0.7.0 and to the 9.x line in
> v0.8.0 (`Cargo.toml` `~9.4` since #971, locked 9.4.1; floor 9.0.5, which
> excludes versions with unpatched read-path vulnerabilities; 9.1.0 also reuses one DEFLATE
> compressor across entries on creation). `ZipFile::name()` returns
> `Result<Cow<str>, ZipError>` instead of `&str`; all call sites propagate the
> new error via `?`.

> [!note] TarArchive forward-only constraint
> `TarArchive::list()` consumes the internal reader because TAR is forward-only.
> Callers must open a fresh `TarArchive` instance to call `extract()` after `list()`.

> [!note] 7z progress ordering fixed in v0.4.0
> Prior to v0.4.0, `SevenZArchive::extract` batched all `on_entry_start` calls
> before extraction and all `on_entry_complete` calls after. In v0.4.0, callbacks
> fire per-entry, interleaved with actual I/O (#191).

> [!note] v0.5.1: `allow_absolute_paths` restored for 7z (#374, #375)
> `sevenz-rust2` 0.21.1 added an internal path-safety check inside
> `decompress_with_extract_fn` that silently blocked absolute-path entries before
> the validator ever saw them, breaking `SecurityConfig::allowed.absolute_paths = true`
> for 7z archives — extraction would simply skip such entries instead of writing them
> (stripped) inside `output_dir`. `SevenZArchive::extract_with_callback` now drives
> extraction via `ArchiveReader::for_each_entries` directly, which has no built-in path
> check, restoring the validator (then `EntryValidator`, now `ValidatorCore`) as the sole and authoritative guard for 7z path
> security (traversal, absolute paths, symlinks). This was an unresolved bug for one
> release cycle (introduced transitively by the `sevenz-rust2` 0.21.1 dependency bump) and
> is now fixed; no `SecurityConfig` or public API change was required.

> [!note] v0.5.1: 7z backslash path-traversal fixed (#365, #376)
> Entry names containing `\` (e.g. `..\..\x`, produced by archives written on Windows) were
> previously passed straight into `PathBuf::from(&entry.name)`. On Unix, `\` is a legal
> filename character, so the whole string became a single path component and slipped past
> `SafePath`'s `..` traversal check. All three 7z entry-name sites — the extraction
> pre-validation loop, the extraction callback, and the list/verify path
> (`inspection/list.rs`) — now call the shared `formats::common::normalize_entry_name`
> helper to replace `\` with `/` before constructing a `PathBuf`, so extract, list, and
> verify agree on traversal detection. Such entries are now correctly rejected with
> `ArchiveError::PathTraversal`. ZIP is unaffected (exarch's own entry-name splitter resolves
> Windows-style paths); TAR is intentionally left un-normalized because `\`
> is a legal Unix filename character in TAR archives.

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Archive path does not exist | `ArchiveError::Io` returned immediately |
| Extension unrecognized or bare `.gz` without `.tar` stem | `ArchiveError::UnknownFormat { path }` |
| ZIP-family alias extraction | Proceeds as ZIP |
| ZIP-family alias creation without format override | `ArchiveError::InvalidArchive` with explanation |
| 7z creation | `ArchiveError::InvalidConfiguration` |
| Solid 7z with `allow_solid_archives = false` | Extraction rejected before decompressing |
| Solid 7z with total uncompressed size > `max_solid_block_memory` | `ArchiveError::QuotaExceeded` or format-specific rejection |
| Corrupt archive (unreadable headers) | `ArchiveError::InvalidArchive`; `verify_archive` returns `VerificationReport` with issues |
| Compression ratio unavailable per-entry (TAR streams) | Zip bomb check skipped for that entry; total quota still enforced |
| 7z entry with absolute path and `allowed.absolute_paths = true` | Written inside `output_dir` with the leading `/` stripped, same as TAR/ZIP (fixed in v0.5.1, #375; previously silently skipped) |
| 7z entry name containing `\` (e.g. `..\..\x`) | Normalized to `/` via `normalize_entry_name` before validation; rejected with `ArchiveError::PathTraversal` (fixed in v0.5.1, #376; previously bypassed traversal detection on Unix) |
| TAR-family `create` with empty directories in the source tree | Explicit directory entry written for each (including nested-empty); preserved on round-trip (fixed v0.6.0, #400 — was previously silently dropped for TAR only, ZIP was already correct) |
| `bytes_compressed` in `CreationReport` for ZIP/TAR creation | Reflects the real on-disk archive size, measured after the writer/encoder finishes (fixed v0.6.0, #402 — was previously always `0` for ZIP and the pre-compression TAR stream size for TAR) |
| Symlink (file or directory) passed as a top-level `create` source | Archived as `EntryType::Symlink` (TAR) or skipped with a warning (ZIP), not dereferenced; dangling symlink sources are no longer rejected as missing (fixed v0.6.0, #510, #512) |
| TAR hardlink entry during extraction | Charged against `QuotaTracker` via the target's on-disk size before copying (fixed v0.6.0, #426 — previously bypassed quota entirely) |
| Compressed TAR with trailing bytes after the last gzip member, bzip2 stream or xz stream, or empty input | Error; only an all-zero tail is accepted, and no more than `max_tar_metadata_bytes` (at least 1 MiB) of decoded bytes may follow the end-of-archive marker (0.7.0, FR-039, #838) |
| TAR FIFO, device, socket or unknown typeflag entry, or an entry with an empty name | `SecurityViolation` in `extract`, `list` and `verify` (0.7.0, FR-040) |
| TAR file-typed entry with a directory name and a payload | `TarAmbiguity::DirectoryNamedPayload` everywhere; with no payload it is read as a directory (0.7.0, #752) |
| ZIP entry with a method other than Stored, Deflate, Bzip2 or Zstd (for example Deflate64) | `SecurityViolation` at open (0.7.0, FR-041) |
| ZIP local and central headers disagree, or the archive hides data | Rejected under `ZipConsistencyPolicy::Enforce`, unchecked under `Ignore` (0.7.0, FR-042; see [[017-zip-header-consistency/spec]]) |
| 7z anti-item | Skipped, never extracted, listed or counted; one warning in `extract`, an informational `ArchiveNote` finding in `verify` (0.7.0, FR-043) |
| 7z reparse-point entry, FIFO, socket, device, undefined Unix type, kind contradiction or empty name | `SecurityViolation` before any write (0.7.0, FR-043) |
| 7z Unix-mode symlink | Created by `extract` only under `allow_symlinks` after its target passes the symlink policy; `list` reads the target only on request (0.7.0, FR-043) |
| 7z header with streams info and no files info | `InvalidArchive` from `list`, `verify` and `extract` (0.7.0, #752; see [[018-7z-stream-map-panic/spec]]) |
| 7z block whose decoder memory exceeds `max_decoder_memory`, or a solid block over `max_solid_compression_ratio` | Refused (decoder memory before any byte is decoded; the solid ratio from the header's declared sizes) (0.7.0, FR-044) |
| 7z header whose declared size exceeds `min(max_decoder_memory, 512 bytes per max_file_count entry + 64 KiB)`, or whose raw size, decoded size or coder dictionary exceeds `max_decoder_memory` | `QuotaExceeded { DecoderMemory }` from `list`, `verify` and `extract` at open, before the header is parsed where the size is declared (FR-069, #674) |
| 7z header with fewer streamed files than sub-streams (the 0.24 writer shape) | Refused at open by sevenz-rust2 0.25 in `list`, `verify` and `extract`, nothing written (FR-070, #769) |
| 7z solid block with a stream-less entry between files | Listed, verified and extracted (v0.8.0, FR-046; previously refused) |
| 7z block whose file sizes do not add up to its decoded size, or a block with data and no sub-streams | Refused before any byte is decoded (v0.8.0, FR-046) |
| TAR whose first member name begins with `BZh` but is not a complete bzip2 header | Detected as TAR, not bzip2 (v0.8.0, FR-049) |
| TAR header or extension-header construct that readers parse differently | `TarAmbiguity` (`InvalidArchive`, sub-code `TAR_AMBIGUITY`), message prefix `ambiguous TAR header: ` (v0.8.0, FR-051) |
| Overwrite of a read-only or foreign-owned file | Replaced through temp file and rename (v0.8.0, FR-052) |
| Compressed TAR whose skipped entries decode beyond the ratio limit | `ArchiveError::ZipBomb` with scope `skipped entries` (v0.8.0, FR-053) |
| xz stream needing more decoder memory than `max_decoder_memory`, or a zstd frame (TAR) or zstd ZIP entry declaring a window above the largest power of two within it | `QuotaExceeded { resource: DecoderMemory { max } }` in `extract`, `list` and `verify` (FR-045, v0.8.0, #849) |
| ZIP whose zstd frame walk exceeds the archive extent (defensive; the declared-size budget of the open bounds the ranges to the same extent, so it is not reachable from an archive that opens) | `InvalidArchive` (v0.8.0, #849) |
| gzip or bzip2 stream with more members than its allowance | `QuotaExceeded { resource: CompressedMembers { members, allowance } }` (FR-039, v0.8.0, #851) |
| `list_archive` on an entry larger than `max_file_size` | Rejected during listing, same as extraction (fixed v0.6.0, #396 — breaking change; `verify_archive`'s internal pre-flight listing keeps `max_file_size` unlimited so an oversized entry surfaces as a `VerificationIssue` instead of aborting before any report exists) |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | All TAR compression variants extract correctly | Integration tests for each variant pass |
| SC-002 | ZIP-family aliases extract as ZIP | Test coverage for at least `.jar`, `.apk`, `.whl` |
| SC-003 | 7z solid archive rejection | Test with solid fixture; rejected under `SolidArchives::Refuse` |
| SC-004 | `ArchiveFormat` implementors are interchangeable | No format-specific code in `api.rs` |

## 8. Agent Boundaries

### Always (without asking)
- Route all entries through `ValidatorCore` before any I/O
- Use `BufReader` for TAR file handles

### Ask First
- Modifying the sealed `ArchiveFormat` trait signatures (breaking API change)
- Adding a new format handler
- Changing ZIP-family alias list

### Never
- Write files to disk during `list()` or `verify()`
- Implement security logic inside a format handler (delegate to `ValidatorCore`)
- Implement 7z creation without security review of `sevenz-rust2` write support

## 9. Open Questions

- [NEEDS CLARIFICATION: Is there a plan to support 7z creation in a future version, or is read-only permanently by design?]

> [!note] Resolved in v0.5.0
> Magic-byte detection has been implemented alongside extension detection. `detect_format` now
> uses both extension and a magic-byte fallback (#353). `determine_creation_format` (used during
> archive creation) remains extension-only by design.

## 10. See Also

- [[constitution]] — format abstraction principles
- [[MOC-specs]] — all specifications
- [[001-security-pipeline/spec]] — `ValidatorCore` and its typed proofs that format handlers must use
- [[021-create-staging-and-output-policy/spec]] — staged creation, `OutputFile`, `ExcludePattern`
- [[003-config-api/spec]] — `SecurityConfig`, `CreationConfig`, `ExtractionOptions`
- [[004-progress-tracking/spec]] — `ProgressCallback` passed to `extract` and `create`
- [[008-tar-empty-directory-preservation/spec]] — TAR directory-entry fix in detail (implemented)
- [[009-accurate-compression-reporting/spec]] — `bytes_compressed` accuracy fix in detail (implemented)
- [[013-quota-permit-capability-token/spec]] — `QuotaPermit` pattern consumed by every format's file-write path
- [[017-zip-header-consistency/spec]] — ZIP structure checks and `ZipConsistencyPolicy`
- [[018-7z-stream-map-panic/spec]] — `SevenZHeader` stream-map validation
- [[020-reader-sink-and-in-memory-api/spec]] — reader, sink and writer APIs over these handlers
- [[001-exarch-system/spec]] — original monolithic spec (archived)
