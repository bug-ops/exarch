# Contributing to exarch

Thank you for your interest in contributing to exarch! This document provides guidelines and instructions for contributing.

## Code of Conduct

Please be respectful and constructive in all interactions. We welcome contributors of all experience levels.

## Getting Started

### Prerequisites

- **Rust** 1.99.1 or later (Edition 2024)
- **Python** 3.9+ (for Python bindings development)
- **Node.js** 18+ (for Node.js bindings development)
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
cargo build --workspace

# Run tests
cargo nextest run --workspace
```

### Building Bindings

**Python bindings:**
```bash
cd crates/exarch-python
pip install maturin
maturin develop
pytest tests/
```

**Node.js bindings:**
```bash
cd crates/exarch-node
npm install
npm run build
npm test
```

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

# Check documentation
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --workspace

# Run tests
cargo nextest run --all-features --workspace

# Security audit
cargo deny check
```

**Quick alias:**
```bash
alias exarch-check='cargo +nightly fmt --all -- --check && cargo clippy --all-targets --all-features --workspace -- -D warnings && cargo nextest run --all-features --workspace'
```

## Testing

### Running Tests

```bash
# All tests
cargo nextest run --workspace

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

Seven `cargo-fuzz` targets live in `fuzz/` (`tar`, `zip`, `sevenz`,
`safe_path`, `extract_archive`, `sink`, `detect`). Changes to archive parsers,
`extract_to_sink` or `ArchiveReader::detect` must keep `cargo +nightly check
--manifest-path fuzz/Cargo.toml --all-targets` passing. See
[`fuzz/README.md`](fuzz/README.md) for running targets and turning a crash into
a regression test.

### Test Fixtures

7z fixtures in `tests/fixtures/` are generated, not hand-edited:

- `tests/fixtures/generate_7z_fixtures.sh` needs `p7zip` (`7z`); the
  `symlink-snl.7z` step also needs `7zz` from 7-Zip 26.05.
- `tests/fixtures/generate_7z_p7zip_fixture.sh` needs Docker; it builds
  `symlink-p7zip.7z` and `symlink-p7zip-dir.7z` with a pinned p7zip 16.02.

### Writing Tests

- Place unit tests in the same file as the code being tested
- Place integration tests in `tests/` directory
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

- **Zero unsafe code** in `exarch-core`
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
2. Update `CHANGELOG.md`
3. Update `package.json` and `pyproject.toml`
4. Create a git tag: `git tag -a v0.x.y -m "Release v0.x.y"`
5. Push tag: `git push origin v0.x.y`
6. CI automatically publishes to crates.io, PyPI, and npm

## Getting Help

- **Issues:** [GitHub Issues](https://github.com/bug-ops/exarch/issues)
- **Discussions:** [GitHub Discussions](https://github.com/bug-ops/exarch/discussions)

## License

By contributing, you agree that your contributions will be licensed under the same terms as the project (MIT OR Apache-2.0).
