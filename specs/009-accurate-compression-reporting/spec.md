---
aliases:
  - Accurate Compression Reporting
  - Fix bytes_compressed for ZIP and TAR
tags:
  - sdd
  - spec
  - archive
  - rust
  - bug
created: 2026-08-02
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[002-format-handlers/spec]]"
  - "[[003-config-api/spec]]"
---

# Feature: Accurate Compression Reporting in CreationReport

> [!info] Metadata
> **Subsystem**: exarch-core / creation
> **Priority**: P2
> **Affected formats**: ZIP (`crates/exarch-core/src/creation/zip.rs`), all TAR variants (`.tar`, `.tar.gz`, `.tar.bz2`, `.tar.xz`, `.tar.zst`, sharing `create_tar_internal_with_progress` in `crates/exarch-core/src/creation/tar.rs`)
> **Not affected**: extraction-side compression ratio checks (`security::zipbomb::validate_compression_ratio`, `inspection/verify.rs`) — these already compute ratios correctly from real compressed/uncompressed sizes and are unaffected by this fix

## 1. Overview

### Problem Statement

`CreationReport` (`crates/exarch-core/src/creation/report.rs`) exposes
`bytes_compressed`, and derives `compression_ratio()`
(`bytes_written / bytes_compressed`) and `compression_percentage()`
(`(bytes_written - bytes_compressed) / bytes_written * 100`, with a
special-cased `100.0` fallback when `bytes_compressed == 0`, documented as
"Returns 100.0 if bytes_compressed is 0 (perfect compression)"). Both derived
values are shown in `exarch create`'s text and `--json` output. In practice,
`bytes_compressed` is unreliable for every supported format:

- **ZIP** (`crates/exarch-core/src/creation/zip.rs`): `report.bytes_compressed`
  is never assigned anywhere in the file (confirmed: zero matches for
  `bytes_compressed` in that module). It stays at its `Default` value of `0`
  for every ZIP archive ever created. `compression_ratio()` therefore always
  reports `0.0`, and `compression_percentage()` always hits the "perfect
  compression" fallback and reports `100.0` — unconditionally, regardless of
  the real (often excellent) compression the underlying `zip` crate achieves.
  The `100.0` looks like a genuine measurement but is actually the zero-value
  edge case firing every single time.
- **TAR (gz/bz2/xz/zst)** (`crates/exarch-core/src/creation/tar.rs:270`):
  `report.bytes_compressed = counting_writer.total_bytes()`, but
  `counting_writer` (`crate::io::CountingWriter`, see
  `crates/exarch-core/src/creation/tar.rs:215-216`) wraps the `writer`
  parameter passed into `create_tar_internal_with_progress` — which, for the
  compressed variants, is the compression *encoder* itself (e.g.
  `flate2::write::GzEncoder`, `bzip2::write::BzEncoder`,
  `xz2::write::XzEncoder`, `zstd::Encoder`; see `create_tar_gz_with_progress`,
  `create_tar_bz2_with_progress`, `create_tar_xz_with_progress`,
  `create_tar_zst_with_progress` at lines 119-206). `tar::Builder` writes the
  raw TAR byte stream (headers + 512-byte block padding + file content) into
  `counting_writer`, which then forwards those *pre-compression* bytes into
  the encoder. `counting_writer.total_bytes()` therefore measures the size of
  the uncompressed TAR stream, not the compressed bytes that land on disk.
  Because TAR block padding adds overhead, this pre-compression byte count
  can even exceed `bytes_written` (the original source size), yielding a
  `compression_ratio()` near `1.0` ("almost no compression") even when the
  on-disk archive is orders of magnitude smaller due to real compression
  happening downstream of the counter.

### Goal

`CreationReport::bytes_compressed` reflects the actual number of bytes the
created archive occupies on disk (i.e. post-compression, the true output
size) for ZIP and for every TAR variant, so `compression_ratio()` and
`compression_percentage()` report values users and tooling can trust.

### Out of Scope

- Changing the *formulas* of `compression_ratio()` / `compression_percentage()`
  in `crates/exarch-core/src/creation/report.rs` — this spec fixes the input
  data (`bytes_compressed`), not the derivation logic
- 7z archive creation (not implemented; `FormatCreator` is not implemented for
  7z per [[002-format-handlers/spec]])
- Extraction-side compression-ratio / zip-bomb detection
  (`security::zipbomb::validate_compression_ratio`,
  `inspection/verify.rs`, `inspection/manifest.rs::compression_ratio()`) —
  these operate on real archive metadata already and are unaffected
- Retroactively correcting reports already emitted by prior `exarch create`
  runs (no historical data to fix)
- Changing the JSON field name `bytes_compressed` or the report schema
  (out-of-band public-API change; see Agent Boundaries)

## 2. User Stories

### US-001: Accurate ZIP Compression Report

AS A user running `exarch create output.zip <dir>`
I WANT the reported `bytes_compressed` (and derived
`compression_ratio()` / `compression_percentage()`) to reflect the real
compressed size of `output.zip` on disk
SO THAT I can trust the report to judge how effective compression was,
instead of seeing a hardcoded `0` / `100.0` on every single run

**Acceptance criteria:**
```
GIVEN a source directory containing a highly compressible file (e.g. a large
      all-zero file)
WHEN exarch create output.zip <source_dir> --json is run
THEN bytes_compressed in the JSON report is greater than 0
AND  bytes_compressed is within a small tolerance of the actual on-disk size
     of output.zip (as reported by the filesystem)
AND  compression_ratio() and compression_percentage() reflect real,
     non-trivial compression (not the 0.0 / 100.0 fallback values)
```

### US-002: Accurate TAR-Family Compression Report

AS A user running `exarch create output.tar.gz <dir>` (or `.tar.bz2`,
`.tar.xz`, `.tar.zst`)
I WANT `bytes_compressed` to reflect the real compressed size on disk after
gzip/bzip2/xz/zstd compression, not the size of the raw uncompressed TAR
stream
SO THAT the reported compression ratio is consistent with the actual
reduction in file size I observe when I inspect the archive with `ls -la`

**Acceptance criteria:**
```
GIVEN a source directory containing a highly compressible file
WHEN exarch create output.tar.gz <source_dir> --json is run
THEN bytes_compressed is within a small tolerance of the actual on-disk size
     of output.tar.gz
AND  bytes_compressed is less than bytes_written for compressible input
     (never exceeds it due to TAR header/padding overhead alone)
AND  the same holds for .tar.bz2, .tar.xz, and .tar.zst
```

### US-003: Plain TAR (No Compression) Reports Consistently

AS A developer relying on exarch as a format-agnostic archiving library
I WANT plain `.tar` (uncompressed) output to report `bytes_compressed` as the
actual on-disk archive size (TAR stream size, including header/padding
overhead), consistent with how compressed variants report their real output
size
SO THAT `bytes_compressed` has one consistent meaning — "actual bytes in the
final archive file" — across every format and variant

**Acceptance criteria:**
```
GIVEN a source directory
WHEN exarch create output.tar <source_dir> --json is run
THEN bytes_compressed equals the actual on-disk size of output.tar
AND  compression_ratio() is close to (but not exactly, due to TAR overhead)
     1.0, reflecting the absence of real compression
```

## 3. Functional Requirements

Use EARS notation. Prefix with FR-NNN.

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN a ZIP archive creation completes (`create_zip_internal_with_progress` in `crates/exarch-core/src/creation/zip.rs`), THE SYSTEM SHALL set `report.bytes_compressed` to the actual number of bytes written to the final `.zip` file on disk | must |
| FR-002 | WHEN a TAR-family archive creation completes (`create_tar_internal_with_progress` in `crates/exarch-core/src/creation/tar.rs`), THE SYSTEM SHALL set `report.bytes_compressed` to the actual number of bytes written to the final output file on disk, measured after compression (post-encoder), for `.tar.gz`, `.tar.bz2`, `.tar.xz`, and `.tar.zst` | must |
| FR-003 | WHEN a plain `.tar` (uncompressed) archive creation completes, THE SYSTEM SHALL set `report.bytes_compressed` to the actual on-disk size of the `.tar` file, keeping `bytes_compressed` semantics ("actual final archive size") consistent across all TAR variants and ZIP | must |
| FR-004 | THE SYSTEM SHALL apply the TAR fix uniformly to all TAR variants by fixing the single shared function `create_tar_internal_with_progress` and/or its four public wrappers (`create_tar_with_progress`, `create_tar_gz_with_progress`, `create_tar_bz2_with_progress`, `create_tar_xz_with_progress`, `create_tar_zst_with_progress`), without duplicating measurement logic per variant | must |
| FR-005 | WHERE measuring bytes at the writer-instrumentation level is insufficient for a given format (e.g. `zip::ZipWriter` requires `Write + Seek`, and `crate::io::CountingWriter` only implements `Write`, so it cannot transparently wrap a seekable file mid-chain without additional work), THE SYSTEM SHALL instead measure the final on-disk file size directly (e.g. via a filesystem metadata query on the completed output file) after the archive writer/encoder is fully flushed and finished | must |
| FR-006 | THE SYSTEM SHALL preserve `bytes_written` semantics unchanged (uncompressed/original source bytes) — only `bytes_compressed` and its consumers (`compression_ratio()`, `compression_percentage()`) are affected by this fix | must |
| FR-007 | WHEN a compression encoder or archive writer fails during `finish()`/close, THE SYSTEM SHALL propagate the error via `Result` and SHALL NOT populate a misleading `bytes_compressed` value for a partially-written or failed archive | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Correctness | `bytes_compressed` SHALL equal the real on-disk size of the created archive file (within filesystem block-size rounding, if a metadata-based measurement is used) for every supported creation format and variant |
| NFR-002 | Consistency | `bytes_compressed` semantics SHALL be identical across ZIP and all TAR variants: "actual bytes present in the final archive file after creation completes" |
| NFR-003 | Backward Compatibility | The `CreationReport` struct shape, field name, and type (`bytes_compressed: u64`) SHALL NOT change — only the value computation changes; JSON schema for `--json` output is unaffected structurally |
| NFR-004 | Performance | The corrected measurement SHALL add negligible overhead (at most one additional filesystem metadata syscall per archive creation, no additional full read/re-scan of archive contents) |
| NFR-005 | Testability | Doc-tests and unit tests in `crates/exarch-core/src/creation/report.rs` that currently hardcode illustrative `bytes_compressed` values (e.g. `report.bytes_compressed = 500;`) remain valid as pure-function tests of `compression_ratio()`/`compression_percentage()` and SHALL NOT be confused with the (separate) fix to how `bytes_compressed` is populated during real creation — new integration-level tests are needed to cover the populated value itself |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `CreationReport` | Report returned by `create_archive` / `_with_progress` and format-specific creation functions | `bytes_written: u64` (unchanged: uncompressed/original size), `bytes_compressed: u64` (fixed by this spec: actual final on-disk archive size, post-compression) |
| `CountingWriter` (`crate::io::CountingWriter`) | Existing `Write`-wrapping byte counter, currently mis-positioned around the pre-compression TAR stream | Only implements `Write` (not `Seek`); cannot transparently wrap ZIP's seekable file writer without further changes — a filesystem-metadata-based measurement is the simpler uniform fix (see FR-005) |
| `compression_ratio()` / `compression_percentage()` (`crates/exarch-core/src/creation/report.rs`) | Derived metrics computed from `bytes_written` and `bytes_compressed` | Formulas unchanged by this spec; correctness of their *output* depends entirely on `bytes_compressed` being accurate (this spec's fix) |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Highly compressible input (e.g. large all-zero file) | `bytes_compressed` is small relative to `bytes_written`; `compression_ratio()` and `compression_percentage()` reflect the real, large reduction (not the previous `0.0`/`100.0` boilerplate) |
| Incompressible input (e.g. already-compressed or random data) | `bytes_compressed` may be close to or slightly exceed `bytes_written` (compression overhead); `compression_ratio()` correctly reports a value near or slightly below/above `1.0`, not a hardcoded fallback |
| Empty source directory / archive with zero entries | `bytes_compressed` reflects the actual (small but non-zero) archive container overhead (TAR/ZIP headers) rather than `0`; `compression_percentage()`'s `bytes_compressed == 0` fallback should essentially never fire for a real archive file, since even an "empty" archive has non-zero container bytes on disk |
| Plain `.tar` (no compression) | `bytes_compressed` equals the actual on-disk `.tar` file size (which may differ slightly from raw content size due to header/padding), not `bytes_written` re-used verbatim |
| Archive creation fails partway (I/O error, disk full, encoder error) | Error propagates via `Result`/`ArchiveError` before any report is returned; no partial/misleading `bytes_compressed` is exposed to the caller |
| Measuring on-disk size before the encoder/writer is fully flushed and closed | Underlying file size may be incomplete (buffered writes not yet flushed) if measured too early; the fix SHALL query the final size only after `builder.finish()`, encoder `finish()`/`flush()`, and (for ZIP) `ZipWriter::finish()` have all completed |
| `exarch-python` / `exarch-node` bindings consuming `bytes_compressed` | Both bindings map `CreationReport` fields directly; no binding-side code changes are needed since the field name/type is unchanged — only the underlying value becomes accurate |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | ZIP `bytes_compressed` accuracy | For a fixture with a highly compressible file, `bytes_compressed` from `exarch create output.zip --json` is within a small tolerance (e.g. ±1%, accounting for any metadata-vs-instrumentation rounding) of the actual on-disk file size reported by the filesystem |
| SC-002 | TAR-family `bytes_compressed` accuracy | Same tolerance as SC-001, verified for `.tar.gz`, `.tar.bz2`, `.tar.xz`, `.tar.zst`, and plain `.tar` |
| SC-003 | No more misleading fallback | Zero occurrences of the `compression_percentage() == 100.0` "perfect compression" fallback firing for any real, non-empty archive creation in the test suite (the fallback only fires because `bytes_compressed == 0`, which should no longer happen for populated archives) |
| SC-004 | No regression | All existing creation/extraction tests continue to pass; `cargo nextest run --workspace --all-features --exclude exarch-python --exclude exarch-node` and `cargo test --doc --workspace --all-features` are green |

## 8. Agent Boundaries

### Always (without asking)
- Fix `bytes_compressed` population for ZIP in `crates/exarch-core/src/creation/zip.rs` and for all TAR variants via the shared `create_tar_internal_with_progress` (and/or its four public wrappers) in `crates/exarch-core/src/creation/tar.rs`
- Measure the actual final on-disk archive size only after all writers/encoders are fully finished/flushed, to avoid measuring incomplete buffered output
- Run the full pre-commit check suite (`cargo +nightly fmt --check`, `cargo clippy --all-targets --all-features --workspace -- -D warnings`, `cargo nextest run --workspace --all-features --exclude exarch-python --exclude exarch-node`, `cargo test --doc --workspace --all-features`) before proposing the change is complete
- Add/extend integration tests per format/variant that assert `bytes_compressed` is close to the real on-disk file size (using `std::fs::metadata` in the test as ground truth)
- Update `CHANGELOG.md` under `[Unreleased]` documenting the fix and clarifying that `bytes_compressed` now reflects real compressed output size (this is a behavior/value change for existing callers even though the field itself is unchanged)

### Ask First
- Adding a new dependency or wrapper type solely to instrument the ZIP writer's byte count (vs. the simpler filesystem-metadata-based approach suggested in FR-005)
- Changing `CreationReport`'s field name, type, or the `compression_ratio()`/`compression_percentage()` formulas themselves
- Any change to `crates/exarch-core/src/creation/report.rs`'s existing doc-tests that currently assert illustrative fixed values (e.g. `bytes_compressed = 500`) — these test the derivation formulas in isolation and should remain valid; clarify with the user before altering them

### Never
- Silently change `bytes_compressed` semantics without documenting it in `CHANGELOG.md` (this field is part of the JSON `--json` output contract consumed by scripts and both language bindings, `exarch-python` and `exarch-node`)
- Modify extraction-side compression-ratio / zip-bomb detection logic (`security::zipbomb::validate_compression_ratio`, `inspection/verify.rs`) — that logic already computes ratios correctly from real archive metadata and is out of scope
- Introduce a full re-read/re-scan pass over the completed archive purely to compute `bytes_compressed` (a single filesystem metadata query suffices and avoids the performance regression this would risk)

## 9. Open Questions

- [NEEDS CLARIFICATION: Should `bytes_compressed` be measured via a filesystem metadata query (`std::fs::metadata(output_path)?.len()`) taken after all writers close, or by restructuring the writer chain per format (e.g. wrapping the innermost `File` in a `CountingWriter` before the ZIP/TAR/encoder layers) so no extra syscall is needed? The metadata-query approach is simpler and format-uniform but requires the output path to remain a `Path` (not an arbitrary in-memory `Write` destination) — does the public API (`create_zip`, `create_tar_gz`, etc., and their `_with_progress` variants) guarantee a file-backed destination in all cases, or are there in-memory/`Write`-generic callers where this would not apply?]
- [NEEDS CLARIFICATION: Is this fix a `fix:` (PATCH), given that `bytes_compressed`'s *value* changes for all existing callers even though the field name/type/schema does not — should the CHANGELOG entry call out the value-semantics change prominently for consumers who may have built dashboards or alerts around the previous (always 0/100%, or near-1.0) values?]
- [NEEDS CLARIFICATION: Should the `skills/exarch-cli/SKILL.md` documentation (and any `--json` schema examples it contains) be updated to reflect that `bytes_compressed`, `compression_ratio`, and `compression_percentage` now report real, non-trivial values, given the project rule that skills must be updated when documented `--json` output behavior changes?]

## 10. See Also

- [[constitution]] — project principles (security-first, format abstraction)
- [[MOC-specs]] — all specifications
- [[002-format-handlers/spec]] — `ArchiveFormat`/`FormatCreator` trait definitions; ZIP and TAR creation implementations
- [[003-config-api/spec]] — `CreationConfig` / report shape used across creation APIs
- `crates/exarch-core/src/creation/zip.rs` — missing `bytes_compressed` assignment
- `crates/exarch-core/src/creation/tar.rs:270` — mis-positioned `CountingWriter` measuring pre-compression bytes
- `crates/exarch-core/src/creation/report.rs` — `CreationReport`, `compression_ratio()`, `compression_percentage()`
- `crates/exarch-core/src/io/counting.rs` — `CountingWriter` (`Write`-only; cannot wrap seekable ZIP writer transparently)
- `crates/exarch-core/src/security/zipbomb.rs` — `validate_compression_ratio`, the (correct, unaffected) extraction-side reference implementation for computing compression ratios from real sizes
