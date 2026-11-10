---
aliases:
  - Project Principles
tags:
  - sdd
  - constitution
created: 2026-05-20
updated: 2026-11-04
status: permanent
---

# Project Constitution

> [!important]
> Non-negotiable principles governing ALL development in this project.
> Every specification, plan, and task MUST comply with this document.
> Update only through explicit team decision.

## I. Architecture

- Four-crate workspace: `exarch-core` (library), `exarch-cli` (thin CLI wrapper), `exarch-python` (PyO3 bindings), `exarch-node` (napi-rs bindings)
- All security logic lives exclusively in `exarch-core` — bindings are responsible only for type mapping, error conversion, and boundary validation
- Archive entries pass through a typed validation pipeline (`SafePath` → `ValidatorCore` → typed per-kind proofs `ValidatedFile`/`ValidatedSymlink`/`ValidatedHardlink`) before any I/O
- Format abstraction: every archive format must implement the sealed `ArchiveFormat` (extract / list / verify), opened under the `SecurityConfig` it enforces; creation dispatches on `CreationFamily` (no creator trait; #908, #901)
- Destinations are abstracted, not duplicated (v0.8.0, #792, #793, #808): TAR, ZIP and 7z handlers keep their per-format gates in one loop and send only validation and the final write through `ExtractTarget` (`HostTarget`, or a sink target for `EntrySink`), so the filesystem, `MemorySink` and any caller-owned sink run identical gates; the validator hands targets typed per-kind proofs (`security::admitted`)
- Readers and writers are first-class (v0.8.0): `ArchiveReader`, `ArchiveWriter` and the request types (`ListRequest::list_reader`, `VerifyRequest::verify_reader`, `SinkExtractRequest::extract`, `CreateRequest::write`) expose the pipeline without a filesystem path, and `verify` creates no temporary directory ([[020-reader-sink-and-in-memory-api/spec]])
- Bindings build their errors from the single typed `ArchiveError::into_ffi_message()` (`ErrorCode`, `FfiKind`, `PartialOutcome`); no binding re-matches `ArchiveError` variants to pick a code (v0.8.0, #758, #768); the per-error detail is the exhaustive `FfiDetail` (`Occupied`, `Replace`, `ProtectedPath`, `NameCollision`, `UnmatchedInclude`, ...), exhaustive on purpose so a new detail fails to compile in both bindings (#1010, #1019)
- Configuration is immutable after construction; `SecurityConfig` and `CreationConfig` use fluent builder APIs
- `SecurityConfig` and `CreationConfig` are plain `#[non_exhaustive]` structs with public typed fields (#898, replacing the v0.6.0 `Unvalidated`/`Validated` typestate): every limit is a type that cannot hold an invalid value (`NonZero*`, `Limit`, `RatioLimit`, `Admit`, `SolidArchives`), runtime values enter through the `limit.rs` boundary functions, and there is no `validate()`. Every option or progress variant of an operation is a request type (`ExtractRequest`, `ListRequest`, `VerifyRequest`, `SinkExtractRequest`, `CreateRequest`, #912), and archive creation is staged and atomic at the output path (`OutputFile`, #931)
- Quota charges are proven at compile time, not by convention (v0.6.0, #436, #439, #440, #447): `QuotaTracker::reserve` (renamed from `record_file`) and `ValidatorCore::charge_hardlink` (renamed from `record_hardlink`) are the only producers of `QuotaPermit`, a non-`Clone`/non-`Copy` capability token carrying the reserved byte count (`bytes: Uncompressed`). `ValidatedFile` embeds one, so a validated file entry with no quota charge is unrepresentable, and a sink receives only the `Copy` `AdmittedSize` derived from it (#909); every format's file-write path consumes it by value, making a double-spend a compile error
- `exarch-cli`'s `OutputFormatter` trait methods take `&mut self` and write through an injectable `Write` destination (`HumanFormatter<O, E>`, `JsonFormatter<W>`) rather than writing directly to `Term`/`Stdout` (v0.6.0, #452) — this exists to unlock unit tests that capture formatter output into an in-memory buffer instead of requiring a subprocess; `create_formatter`'s signature is unchanged

## II. Technology Stack

- Language: Rust, MSRV 1.99.1
- Targets: native platforms and `wasm32-wasip1` for `exarch-core` and `exarch-cli` (CI job `wasm`, wasmtime smoke test; v0.8.0); FreeBSD, NetBSD and illumos run in `freebsd.yml` and `netbsd-illumos.yml`, Windows volume cases in `windows-volumes.yml`
- CLI: `clap` 4.x with derive macros
- Python bindings: `pyo3` 0.29, `maturin`, GIL released during I/O
- Node.js bindings: `napi-rs` 3.x, async Promises via tokio thread pool
- Compression: `flate2` (gz), `bzip2` (bz2), `liblzma` 0.4.9 (xz, static; replaced `xz2` in v0.8.0), `zstd` (zst), `zip` 9.x (`Cargo.toml` `~9.4`, locked 9.4.1), `typed-path` 0.13 (ZIP entry-name prefix grammar), `sevenz-rust2` 0.25.0 (7z, minimum version) with `lzma-rust2` 0.25 (#1024), `globset` (entry-selection globs, behind the opaque `ExcludePattern`)
- Testing: `cargo nextest`, `proptest` for property-based tests, `criterion` + `dhat` for benchmarks

## III. Testing (NON-NEGOTIABLE)

- All features must have passing tests before merge
- Python and Node.js crates are excluded from `cargo nextest` — tested separately via `pytest` / `npm test`
- Doc-tests must pass: `cargo test --doc --workspace --all-features --exclude exarch-python --exclude exarch-node`
- Every new `pub` item requires a `///` doc comment; non-trivial APIs require `# Examples` with runnable doc-tests
- Verification infrastructure: the unpublished `exarch-testkit` crate builds raw ZIP and PAX fixtures for malformed-archive tests; `fuzz/` holds the cargo-fuzz targets (`detect`, `extract_archive`, `glob`, `safe_path`, `sevenz`, `sink`, `tar`, `zip`) with an OSS-Fuzz integration under `fuzz/oss-fuzz/` and a CI format check of the fuzz crate; the `zip-drift.yml` workflow weekly checks the `zip` header refusals against upstream releases
- Security-critical paths (path traversal, symlink/hardlink validation, zip bomb detection, permission sanitization) require live integration tests before any PR touching them

## IV. Code Style

- `deny(unsafe_code)` workspace-wide — no exceptions
- `deny(expect_used)` and `deny(unwrap_used)` — use `?` for error propagation
- `clippy::pedantic` and `clippy::nursery` — all warnings treated as errors
- `exarch-core` warns crate-wide (one gate in `lib.rs`) on `clippy::indexing_slicing` and `clippy::arithmetic_side_effects` in non-test builds (denied in CI via `-D warnings`); every `#[expect(...)]` carries a `reason` naming the invariant (#1032, #1070)
- All `pub` types, traits, functions, and methods require doc comments explaining what and why
- Formatting: `cargo +nightly fmt --all`

## V. Security

- Deny-by-default: symlinks, hardlinks, absolute paths, world-writable files, solid archives — all disabled unless explicitly enabled
- Never commit secrets, keys, or credentials
- Default banned path components: `.git`, `.ssh`, `.gnupg`, `.aws`, `.kube`, `.docker`, `.env`
- Default limits: 50 MB per file, 500 MB total, 100× compression ratio, 10,000 files, depth 32
- Path component matching is case-insensitive to prevent bypass on case-insensitive filesystems
- Entries are validated against a `PathModel`: `Host` (the running platform; on Windows it applies the `Portable` component rules) or `Portable` (the strictest rules of every platform on every host), selected by the destination, e.g. `EntrySink::path_model` (v0.8.0, #780, #787, #790)
- Security issues detected during `verify_archive` are reported in `VerificationReport.issues`, not propagated as errors (complete picture for the caller)
- `ValidationReport` was removed with the entry-validator pipeline (#900)
- The error type covering all archive operations is `ArchiveError` (renamed from `ExtractionError` in v0.4.1); all public API surfaces use this name
- Security primitives (`validate_path`, `validate_symlink`, `sanitize_permissions`, `validate_compression_ratio`, `QuotaTracker`, `HardlinkTracker`) are `pub(crate)` and not part of the public API; external tests must use `--features testing`
- The typed proofs (`ValidatedFile`, `ValidatedSymlink`, `ValidatedHardlink`, `security::admitted`) are assemblable only by `ValidatorCore` inside `exarch-core`; `EntryValidator`, `ValidatedEntry` and `ValidatedEntryType` were removed (#900)
- Absolute-path stripping for entries with `allow_absolute_paths` enabled is performed centrally in `SafePath::validate_with_context`, not in per-format handlers (v0.5.0)
- Format handlers MUST NOT drive an upstream extraction API that performs its own path-safety checks ahead of the validator (`ValidatorCore`) — this silently disables the deny-by-default policy for that format. The 7z handler was found doing exactly this after a `sevenz-rust2` 0.21.1 dependency bump and was fixed by switching to an API with no built-in check (v0.5.1, #374, #375)
- Archive entry names MUST be normalized (`\` → `/`) via `formats::common::normalize_entry_name` before being passed to `SafePath::validate`, wherever the underlying format may embed Windows-style separators (currently: 7z). `SafePath::validate` documents this as a caller contract — it does not normalize internally (v0.5.1, #365, #376)
- Destination files MUST be opened with `O_EXCL`/`O_NOFOLLOW` (Unix) rather than checked via `Path::exists()` before writing — `exists()` follows symlinks and returns `false` for a dangling one, letting a pre-planted symlink at the destination bypass duplicate detection and redirect the write outside the extraction root. This precondition (attacker-writable destination directory) and fix pattern applies uniformly across TAR/ZIP's shared write path, 7z's temp-file-then-rename path, and TAR's hardlink copy path (v0.6.0, #459, #471, #467)
- A copy loop MUST enforce the archive-declared size as a hard streaming ceiling — checked after every buffered read, not only at EOF — rather than trusting it only for pre-write quota/ratio checks; this closed GHSA-5j8q-wxg5-hj4r, a ZIP entry that declared a small `uncompressed_size` while its real DEFLATE stream inflated far larger (v0.6.0, #517, `formats::copy::copy_with_buffer`)
- File permissions MUST be applied via `File::set_permissions`/`fchmod` on an already-open descriptor, never via a path-based `set_permissions()` call after `open()` — the latter re-resolves the path and reopens a TOCTOU symlink-swap window (v0.6.0, #472)
- Path redaction for error messages is single-sourced in `exarch-core` (the `error` module is private; the helpers are re-exported at the crate root: `sanitize_path_for_error`, `format_entry_path_for_error`, `sanitize_io_error_for_error`), not duplicated per binding. `PathTraversal`, `SymlinkEscape`, `HardlinkEscape`, and `InvalidPermissions` carry an archive-relative path the attacker already controls and are NEVER redacted (full path in both debug and release builds); `SourceNotFound`, `SourceNotAccessible`, `OutputExists`, `UnknownFormat`, and `Io` carry host-derived paths and ARE redacted to filename-only (or `ErrorKind` description, for `Io`) in release builds (v0.6.0, #453, #462, #463, #464)
- `extract --atomic --force` (`Staging::AtomicReplace`) performs its destination swap in `exarch-core` (`staging/replace.rs`, `VettedDir`) `*at`-relative to a directory handle pinned on the destination's parent directory (Unix and WASI; a pinned handle on Windows), never by re-resolving a logical path — closing a TOCTOU window where an intermediate path component replaced with a symlink mid-extraction could redirect the swap. A destination that is itself a symlink is rejected outright (GHSA-x8wr-7ww2-c94x, v0.6.0, #526, #531). This restriction is scoped to `--atomic --force` only: plain `extract`, `--atomic` without `--force`, and the Rust/Python/Node APIs continue to resolve a symlinked destination *root* via `DestDir::new`/`new_or_create` and `canonicalize()`, matching `tar -C`/`unzip -d` (confirmed by audit, v0.6.0, #533) — only intermediate *path components* being symlinks is a rejected case, not the root itself

## VI. Performance

- Extraction throughput regressions > 10% vs baseline require a `rust-performance-engineer` review
- Benchmarks in `exarch-core/benches/` (creation, extraction, validation, progress); run with `cargo bench -p exarch-core --features testing`
- `BufReader` wraps file handles for all TAR format handlers

## VII. Simplicity

- Before v1.0.0: implement only the minimum necessary functionality; avoid additional abstractions and premature optimization
- Before v1.0.0: no backward-compatibility guarantees — document breaking changes in `CHANGELOG.md`
- 7z creation is not supported (read-only); callers receive `InvalidConfiguration`
- ZIP-family aliases (`.jar`, `.apk`, `.whl`, etc.) are extracted as ZIP but creation is rejected unless the caller explicitly overrides `CreationConfig::format`

## VIII. Git Workflow

- Branch naming: `feat/{issue}-{slug}`, `fix/{issue}-{slug}`, `hotfix/{issue}-{slug}`
- Commit messages: Conventional Commits 1.0.0
- Pre-merge checks (must match CI): `cargo +nightly fmt --check`, `cargo clippy --all-targets --all-features --workspace -- -D warnings`, `cargo nextest run --workspace --all-features --exclude exarch-python --exclude exarch-node`, `cargo test --doc --workspace --all-features --exclude exarch-python --exclude exarch-node`
- Docs must build cleanly: `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --workspace`
- Every phase-end PR: update `CHANGELOG.md` under `[Unreleased]`
