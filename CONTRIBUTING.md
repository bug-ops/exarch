# Contributing to exarch

Thank you for your interest in contributing to exarch! This document provides guidelines and instructions for contributing.

## Code of Conduct

Please be respectful and constructive in all interactions. We welcome contributors of all experience levels.

## Getting Started

### Prerequisites

- **Rust** 1.100 or later (Edition 2024)
- **Python** 3.11+ (for Python bindings development)
- **Node.js** 20+ (for Node.js bindings development)
- **cargo-nextest** for running tests
- **maturin** for Python bindings
- **napi-rs** for Node.js bindings

### Setting Up the Development Environment

```bash
# Clone the repository
git clone https://github.com/bug-ops/exarch.git
cd exarch

# Install Rust toolchain
rustup update stable
rustup component add rustfmt clippy

# Install development tools
cargo install cargo-nextest cargo-deny cargo-llvm-cov

# Build all crates
cargo build --workspace --all-features

# Run tests (the Python and Node.js bindings are tested separately, see below)
cargo nextest run --workspace --all-features --exclude exarch-python --exclude exarch-node
```

### Cargo Features

| Crate | Feature | Purpose |
|-------|---------|---------|
| `exarch-core` | `encryption` | Reads password-protected ZIP (WinZip AES) and 7z (AES-256) archives through `Password`. `exarch-cli` and the bindings enable it; `--all-features` covers it in tests |
| `exarch-core` | `testing` | Exposes security primitives for benchmarks and integration tests; not for production |
| `exarch-cli` | `test-hooks` | Debug-only seams (a stalled read at a chosen entry, a sandbox probe) used by the forced-exit and sandbox tests (`tests/forced_exit.rs`, `tests/sandbox_stage.rs`); never enabled in a shipped binary |
| `exarch-python` | `panic-injection` | A deliberate-panic hook for the panic-safety test; never enabled for published wheels |

### Building Bindings

**Python bindings:**
```bash
cd crates/exarch-python
pip install maturin
maturin develop
pytest tests/
```

CI also checks that the type stubs match the runtime. After `maturin develop`:

```bash
python -m mypy.stubtest exarch --allowlist stubtest-allowlist.txt
```

**Node.js bindings:**
```bash
cd crates/exarch-node
pnpm install --frozen-lockfile
npm run build
npm test
```

`npm run build` regenerates `index.d.ts`. Commit it with the change that alters
the Node API; CI fails when `git diff --exit-code crates/exarch-node/index.d.ts`
shows a difference.

The release gate checks the exact packed tarball against the committed loader
(`index.js`) and `package.json`. Run it locally with `npm run check:package`,
or `node scripts/check-package.mjs <tarball>` for a tarball you packed.

## Development Workflow

### Branch Naming

Use descriptive branch names:
- `feature/<description>` - new features
- `fix/<description>` - bug fixes
- `docs/<description>` - documentation changes
- `refactor/<description>` - code refactoring
- `perf/<description>` - performance improvements

### Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <subject>

<body>
```

**Types:**
- `feat` - new feature
- `fix` - bug fix
- `docs` - documentation
- `refactor` - code refactoring
- `perf` - performance improvement
- `test` - adding tests
- `chore` - maintenance tasks

**Examples:**
```
feat(core): add 7z format support
fix(python): handle unicode paths correctly
docs: update installation instructions
perf(core): optimize directory caching
```

## Pre-Commit Checks

Run all checks before submitting a PR:

```bash
# Format code
cargo +nightly fmt --all

# Run clippy
cargo clippy --all-targets --all-features --workspace -- -D warnings
# `.cargo/config.toml` sets `build.warnings = "deny"`, so WIP code with warnings fails
# `cargo check`/`cargo test`; locally use `CARGO_BUILD_WARNINGS=warn` or `--config 'build.warnings="warn"'`
# `cargo hack check --no-dev-deps` strips dev-dependencies, so `unused_workspace_dependencies`
# fires for dev-only workspace deps; run it with `--config 'build.warnings="warn"'` too
# Manifest version floors must be at least 7 days old (`global-min-publish-age`), else
# `cargo update` and `cargo semver-checks` fail

# Check documentation (CI also builds `-p exarch-core` with `--document-private-items`)
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features -p exarch-core --document-private-items

# Run tests
cargo nextest run --workspace --all-features --exclude exarch-python --exclude exarch-node
cargo test --doc --workspace --all-features --exclude exarch-python --exclude exarch-node

# Check that every tracked file states the MSRV of Cargo.toml
.github/scripts/check-msrv-statements.sh

# Security audit
cargo deny check
```

CI also runs the following, so run them when you touch the matching files:

```bash
# Fuzz crate: formatting and lints
cargo +nightly fmt --manifest-path fuzz/Cargo.toml -- --check
cargo clippy --manifest-path fuzz/Cargo.toml --all-targets -- -D warnings

# Binding dependency audits (after changing pnpm-lock.yaml or uv.lock)
(cd crates/exarch-node && pnpm audit)
```

Every `uses:` in `.github/` must pin a full 40-character commit SHA
(`owner/action@<sha> # vX.Y.Z`); the `Action Pin Check` job rejects a tag.
CI also runs `pip-audit` over the locked Python dependencies
(`crates/exarch-python/uv.lock`).

### Lints

- `unwrap_used` and `expect_used` are warnings in library and binary code and
  are allowed in tests (`clippy.toml`); use `?` outside tests.
- Every `#[allow(...)]` carries a `reason = "..."`
  (`clippy::allow_attributes_without_reason`). Prefer `#[expect(..., reason = "...")]`
  so the attribute fails when it becomes unnecessary.
- `exarch-cli` lints path-based filesystem mutators (`std::fs::write`,
  `File::create`, `rename`, and similar) through `disallowed-methods`: write
  through a directory handle, or add an `#[expect]` with a reason for a
  deliberate by-name use.

**Quick alias:**
```bash
alias exarch-check='cargo +nightly fmt --all -- --check && cargo clippy --all-targets --all-features --workspace -- -D warnings && cargo nextest run --workspace --all-features --exclude exarch-python --exclude exarch-node'
```

## Testing

### Running Tests

```bash
# All tests (bindings excluded)
cargo nextest run --workspace --all-features --exclude exarch-python --exclude exarch-node

# Specific crate
cargo nextest run -p exarch-core

# Specific test
cargo nextest run -p exarch-core test_name

# With coverage
cargo llvm-cov nextest --all-features --workspace --html
```

### WASI Build

CI builds `exarch-core` and the CLI for `wasm32-wasip1` and runs a smoke test
under `wasmtime` (`.github/scripts/wasi-smoke.sh`). Run the same steps locally
when a change touches I/O or a C codec (`liblzma` is built from
source and linked statically):

```bash
rustup target add wasm32-wasip1
cargo check -p exarch-core --all-features --target wasm32-wasip1
cargo build -p exarch-cli --target wasm32-wasip1
bash .github/scripts/wasi-smoke.sh target/wasm32-wasip1/debug/exarch.wasm
```

The C codecs need a WASI libc and `llvm-ar`; the `wasm` job in
`.github/workflows/ci.yml` shows the `CFLAGS_wasm32_wasip1` and
`AR_wasm32_wasip1` settings it uses.

### Fuzzing

Nine `cargo-fuzz` targets live in `fuzz/` (`tar`, `zip`, `sevenz`,
`safe_path`, `glob`, `sink`, `detect`, `encrypted`, `extract_archive`). Changes
to archive parsers, decryption, `extract_to_sink` or `ArchiveReader::detect` must keep `cargo +nightly check
--manifest-path fuzz/Cargo.toml --all-targets` passing. See
[`fuzz/README.md`](fuzz/README.md) for running targets and turning a crash into
a regression test.

### Linux Sandbox Tests

The `--sandbox` (Landlock) tests in `exarch-cli` (`tests/sandbox.rs`,
`tests/sandbox_stage.rs`, `tests/sandbox_spool.rs`, `tests/password.rs`) only enforce on Linux. On
another host, run them in a container with Docker:

```bash
.github/scripts/linux-sandbox-docker.sh --require
```

The script copies the tree into a `rust` container and prints a `probe:` line;
trust the run only if it says `landlock enforced`. `--require` sets
`EXARCH_REQUIRE_LANDLOCK=1`, so a kernel without Landlock fails instead of
skipping. CI runs the same tests in the `test` job of `ci.yml`.

After the tests, the script runs a non-root umask matrix: it extracts a flat and a nested
archive as uid 65534 (via `setpriv`) under umasks 0277, 0177, 0377, 0477 and 0677. Root
bypasses mode bits, so only this run exercises the staging umask handling. The flat archive
and the nested archive under 0477 must extract. The nested archive under the other masks
must exit nonzero, mention the umask in its error and leave no `.exarch-*` staging
directory. Any case that deviates prints its log and makes the script exit nonzero.

### Test Fixtures

7z fixtures in `crates/exarch-core/tests/fixtures/` are generated, not hand-edited:

- `crates/exarch-core/tests/fixtures/generate_7z_fixtures.sh` needs `p7zip` (`7z`); the
  `symlink-snl.7z` step also needs `7zz` from 7-Zip 26.05.
- `crates/exarch-core/tests/fixtures/generate_7z_p7zip_fixture.sh` needs Docker; it builds
  `symlink-p7zip.7z` and `symlink-p7zip-dir.7z` with a pinned p7zip 16.02.

Other test data is committed, not generated: `crates/exarch-core/tests/data/`
holds the encrypted-archive and tar-minefield corpora (each with a `README.md`
describing its provenance), and `crates/exarch-python/tests/fixtures/` the
Python fixtures. `exarch-core` tests read their fixtures from inside the
crate (`crates/exarch-core/tests/`), so the packaged crate still compiles its
tests; the tar-minefield corpus and its test are excluded from the package.

### Writing Tests

- Place unit tests in the same file as the code being tested
- Place integration tests in `tests/` directory
- Tests that wait on a child process or a signal wait on a ready line or the
  child's output, never a fixed sleep
- Tests that assert a file mode must not depend on the host umask: extraction
  without `--preserve-permissions` applies it, so a test passes on `022` and fails on `077`
  unless it sets the mode policy or the umask explicitly
- Security validators must have **100% test coverage**
- Overall project coverage target: **80%+**
- Write `assert_matches!(value, pattern)`, never `assert!(matches!(value, pattern))`:
  the CI Format Check job rejects the latter in every tracked `.rs` file, and
  `cargo fmt` and `clippy` do not catch it

### CVE Regression Tests

When fixing security issues, add a regression test in
`crates/exarch-core/tests/security/`:

```rust
#[test]
fn test_cve_xxxx_description() {
    // Test that the vulnerability is fixed
}
```

## Code Guidelines

### Rust Style

- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `thiserror` for error types (not `anyhow` in library code)
- Prefer `&str` and `&Path` over `String` and `PathBuf` in function parameters
- Use type-driven security (e.g., `SafePath` for validated paths)

### Security

- **Minimal unsafe code**: `unsafe` is denied by lint workspace-wide and confined to documented FFI sites (the destination access check on Unix, NT calls and token, SID and DACL calls on Windows in `exarch-core`; one `sigaction` query in `exarch-cli` on Unix)
- Default-deny security model
- Validate all external input
- Document security implications in comments

### Performance

- Avoid allocations in hot paths
- Use `#[inline]` for small, frequently called functions
- Reuse buffers where possible
- Run benchmarks for performance-critical changes

## Benchmarks

```bash
# Run all benchmarks
./benches/run_all.sh

# Quick run
./benches/run_all.sh --quick

# Rust only
cargo bench -p exarch-core --features testing
```

Record numbers only from an idle host: run benchmarks serially as the last
step, with no parallel builds or test runs, and only when the 1-minute load
average (`uptime`) is at or below about 7. Note the load next to each result;
a result taken above that bar is directional only and must not be used to
claim or dismiss a regression.

## Dependency Cooldown

`.cargo/config.toml` sets `global-min-publish-age = "7 days"`: `cargo update`
skips crate versions published less than seven days ago, and Dependabot waits
the same seven days in every ecosystem (security updates bypass it). To take a
newer release on purpose, run the command with
`CARGO_RESOLVER_INCOMPATIBLE_PUBLISH_AGE=allow`; the `release` and `zip-drift`
workflows do this deliberately.

A version requirement in a manifest must not be newer than the cooldown, or
`cargo update` and `cargo semver-checks` fail for everyone. The weekly
`floor-vs-cooldown` job in `.github/workflows/zip-drift.yml` runs
`cargo update --dry-run` for the workspace and the fuzz crate to catch this.

## Pull Request Process

1. **Create a branch** from `main`
2. **Make your changes** following the guidelines above
3. **Run all checks** (`exarch-check`)
4. **Push your branch** and create a PR
5. **Fill in the PR template** with details
6. **Wait for CI** to pass
7. **Address review feedback**
8. **Squash and merge** when approved

### PR Requirements

- [ ] All CI checks pass
- [ ] Tests added for new functionality
- [ ] Documentation updated if needed
- [ ] CHANGELOG.md updated for user-facing changes
- [ ] No new clippy warnings

## Release Process

Releases are managed by maintainers. The process:

1. Update version in `Cargo.toml` (workspace)
2. Refresh the fuzz lockfile and commit it with the bump: `cargo update --manifest-path fuzz/Cargo.toml -p exarch-core`
3. Update `CHANGELOG.md`
4. Update `package.json` and `pyproject.toml`
5. Create a git tag: `git tag -a v0.x.y -m "Release v0.x.y"`
6. Push tag: `git push origin v0.x.y`
7. CI automatically publishes to crates.io, PyPI, and npm

## Getting Help

- **Issues:** [GitHub Issues](https://github.com/bug-ops/exarch/issues)
- **Discussions:** [GitHub Discussions](https://github.com/bug-ops/exarch/discussions)

## License

By contributing, you agree that your contributions will be licensed under the same terms as the project (MIT OR Apache-2.0).
