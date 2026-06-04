---
aliases:
  - Project Principles
tags:
  - sdd
  - constitution
created: 2026-05-20
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

## II. Technology Stack

- Language: Rust, MSRV 1.93.0
- CLI: `clap` 4.x with derive macros
- Python bindings: `pyo3` 0.28, `maturin`, GIL released during I/O
- Node.js bindings: `napi-rs` 3.x, async Promises via tokio thread pool
- Compression: `flate2` (gz), `bzip2` (bz2), `xz2` (xz, static), `zstd` (zst), `zip` 8.x, `sevenz-rust2` (7z)
- Testing: `cargo nextest`, `proptest` for property-based tests, `criterion` + `dhat` for benchmarks

## III. Testing (NON-NEGOTIABLE)

- All features must have passing tests before merge
- Python and Node.js crates are excluded from `cargo nextest` — tested separately via `pytest` / `npm test`
- Doc-tests must pass: `cargo test --doc --workspace --all-features`
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
- Pre-merge checks (must match CI): `cargo +nightly fmt --check`, `cargo clippy --all-targets --all-features --workspace -- -D warnings`, `cargo nextest run --workspace --all-features --exclude exarch-python --exclude exarch-node`, `cargo test --doc --workspace --all-features`
- Docs must build cleanly: `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --workspace`
- Every phase-end PR: update `CHANGELOG.md` under `[Unreleased]`
