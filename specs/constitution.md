---
aliases:
  - Project Principles
tags:
  - sdd
  - constitution
created: 2026-05-20
updated: 2026-08-04
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
- Archive entries pass through a typed validation pipeline (`SafePath` → `ValidatedEntry`) before any I/O
- Format abstraction: every archive format must implement `ArchiveFormat` (extract / list / verify) and optionally `FormatCreator`
- Configuration is immutable after construction; `SecurityConfig` and `CreationConfig` use fluent builder APIs
- `SecurityConfig` and `CreationConfig` are two-state typestates over `Unvalidated`/`Validated` phantom markers (v0.6.0, #433–#437, #443): fluent `with_*` builders exist only on the `Unvalidated` state; `validate()` consumes `self` and returns `Result<T<Validated>>`. `ArchiveFormat::extract/list/verify` and every downstream security function require `&SecurityConfig<Validated>`, so a config that skipped validation cannot compile its way into extraction. Top-level `extract_archive*`/`list_archive`/`verify_archive`/`create_archive*` still accept a plain `&SecurityConfig`/`CreationConfig` (defaulting to `Unvalidated`) and validate internally — bindings and CLI need no changes
- Quota charges are proven at compile time, not by convention (v0.6.0, #436, #439, #440, #447): `QuotaTracker::reserve` (renamed from `record_file`) and `EntryValidator::reserve_hardlink` (renamed from `record_hardlink`) are the only producers of `QuotaPermit`, a non-`Clone`/non-`Copy` zero-sized capability token. `ValidatedEntryType::File` embeds one, so a validated file entry with no quota charge is unrepresentable; every format's file-write path consumes it by value, making a double-spend a compile error
- `exarch-cli`'s `OutputFormatter` trait methods take `&mut self` and write through an injectable `Write` destination (`HumanFormatter<O, E>`, `JsonFormatter<W>`) rather than writing directly to `Term`/`Stdout` (v0.6.0, #452) — this exists to unlock unit tests that capture formatter output into an in-memory buffer instead of requiring a subprocess; `create_formatter`'s signature is unchanged

## II. Technology Stack

- Language: Rust, MSRV 1.98.0
- CLI: `clap` 4.x with derive macros
- Python bindings: `pyo3` 0.29, `maturin`, GIL released during I/O
- Node.js bindings: `napi-rs` 3.x, async Promises via tokio thread pool
- Compression: `flate2` (gz), `bzip2` (bz2), `xz2` (xz, static), `zstd` (zst), `zip` 9.0.0-pre2, `sevenz-rust2` (7z)
- Testing: `cargo nextest`, `proptest` for property-based tests, `criterion` + `dhat` for benchmarks

## III. Testing (NON-NEGOTIABLE)

- All features must have passing tests before merge
- Python and Node.js crates are excluded from `cargo nextest` — tested separately via `pytest` / `npm test`
- Doc-tests must pass: `cargo test --doc --workspace --all-features --exclude exarch-python --exclude exarch-node`
- Every new `pub` item requires a `///` doc comment; non-trivial APIs require `# Examples` with runnable doc-tests
- Security-critical paths (path traversal, symlink/hardlink validation, zip bomb detection, permission sanitization) require live integration tests before any PR touching them

## IV. Code Style

- `deny(unsafe_code)` workspace-wide — no exceptions
- `deny(expect_used)` and `deny(unwrap_used)` — use `?` for error propagation
- `clippy::pedantic` and `clippy::nursery` — all warnings treated as errors
- All `pub` types, traits, functions, and methods require doc comments explaining what and why
- Formatting: `cargo +nightly fmt --all`

## V. Security

- Deny-by-default: symlinks, hardlinks, absolute paths, world-writable files, solid archives — all disabled unless explicitly enabled
- Never commit secrets, keys, or credentials
- Default banned path components: `.git`, `.ssh`, `.gnupg`, `.aws`, `.kube`, `.docker`, `.env`
- Default limits: 50 MB per file, 500 MB total, 100× compression ratio, 10,000 files, depth 32
- Path component matching is case-insensitive to prevent bypass on case-insensitive filesystems
- Security issues detected during `verify_archive` are reported in `VerificationReport.issues`, not propagated as errors (complete picture for the caller)
- `ValidationReport` is re-exported at crate root as `exarch_core::ValidationReport` (v0.4.1)
- The error type covering all archive operations is `ArchiveError` (renamed from `ExtractionError` in v0.4.1); all public API surfaces use this name
- Security primitives (`validate_path`, `validate_symlink`, `sanitize_permissions`, `validate_compression_ratio`, `QuotaTracker`, `HardlinkTracker`) are `pub(crate)` and not part of the public API; external tests must use `--features testing`
- `ValidatedEntry` (`security::validator`) is sealed: fields are private, the constructor is `pub(crate)`, and `safe_path()`/`entry_type()`/`mode()`/`into_parts()` accessors replace direct field access — assemblable only from inside `exarch-core`, in practice only via `EntryValidator::validate_entry()`. `ValidatedEntryType` is `#[non_exhaustive]` (v0.6.0, #433–#436)
- Absolute-path stripping for entries with `allow_absolute_paths` enabled is performed centrally in `SafePath::validate_with_context`, not in per-format handlers (v0.5.0)
- Format handlers MUST NOT drive an upstream extraction API that performs its own path-safety checks ahead of `EntryValidator` — this silently disables the deny-by-default policy for that format. The 7z handler was found doing exactly this after a `sevenz-rust2` 0.21.1 dependency bump and was fixed by switching to an API with no built-in check (v0.5.1, #374, #375)
- Archive entry names MUST be normalized (`\` → `/`) via `formats::common::normalize_entry_name` before being passed to `SafePath::validate`, wherever the underlying format may embed Windows-style separators (currently: 7z). `SafePath::validate` documents this as a caller contract — it does not normalize internally (v0.5.1, #365, #376)
- Destination files MUST be opened with `O_EXCL`/`O_NOFOLLOW` (Unix) rather than checked via `Path::exists()` before writing — `exists()` follows symlinks and returns `false` for a dangling one, letting a pre-planted symlink at the destination bypass duplicate detection and redirect the write outside the extraction root. This precondition (attacker-writable destination directory) and fix pattern applies uniformly across TAR/ZIP's shared write path, 7z's temp-file-then-rename path, and TAR's hardlink copy path (v0.6.0, #459, #471, #467)
- A copy loop MUST enforce the archive-declared size as a hard streaming ceiling — checked after every buffered read, not only at EOF — rather than trusting it only for pre-write quota/ratio checks; this closed GHSA-5j8q-wxg5-hj4r, a ZIP entry that declared a small `uncompressed_size` while its real DEFLATE stream inflated far larger (v0.6.0, #517, `formats::copy::copy_with_buffer`)
- File permissions MUST be applied via `File::set_permissions`/`fchmod` on an already-open descriptor, never via a path-based `set_permissions()` call after `open()` — the latter re-resolves the path and reopens a TOCTOU symlink-swap window (v0.6.0, #472)
- Path redaction for error messages is single-sourced in `exarch-core::error::redaction` (`sanitize_path_for_error`, `format_entry_path_for_error`, `sanitize_io_error_for_error`), not duplicated per binding. `PathTraversal`, `SymlinkEscape`, `HardlinkEscape`, and `InvalidPermissions` carry an archive-relative path the attacker already controls and are NEVER redacted (full path in both debug and release builds); `SourceNotFound`, `SourceNotAccessible`, `OutputExists`, `UnknownFormat`, and `Io` carry host-derived paths and ARE redacted to filename-only (or `ErrorKind` description, for `Io`) in release builds (v0.6.0, #453, #462, #463, #464)
- `exarch-cli extract --atomic --force` performs its destination swap `*at`-relative to a file descriptor pinned on the destination's parent directory (`commands::atomic_swap::PinnedDir`, Unix only), never by re-resolving a logical path — closing a TOCTOU window where an intermediate path component replaced with a symlink mid-extraction could redirect the swap. A destination that is itself a symlink is rejected outright (GHSA-x8wr-7ww2-c94x, v0.6.0, #526, #531). This restriction is scoped to `--atomic --force` only: plain `extract`, `--atomic` without `--force`, and the Rust/Python/Node APIs continue to resolve a symlinked destination *root* via `DestDir::new`/`new_or_create` and `canonicalize()`, matching `tar -C`/`unzip -d` (confirmed by audit, v0.6.0, #533) — only intermediate *path components* being symlinks is a rejected case, not the root itself

## VI. Performance

- Extraction throughput regressions > 10% vs baseline require a `rust-performance-engineer` review
- Benchmarks in `exarch-core/benches/` (creation, extraction, validation, progress); run with `cargo bench -p exarch-core`
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
