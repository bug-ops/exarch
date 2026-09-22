# exarch-core fuzzing harness

`cargo-fuzz` (libFuzzer) targets for five of the seven untrusted archive
parsers in `exarch-core` (the remaining one, `detect.rs`, is covered by a
proptest instead — see below). This narrows the verification gap tracked in
#577 — it does not close it. Five targets, 300 seconds each, run weekly on a
corpus that persists across runs via CI cache; that is a real but narrow
layer on top of the existing regression-test harness
(`crates/exarch-core/tests/security/`), not a replacement for it.

The shared `SecurityConfig` (`fuzz_targets/common.rs`) deliberately enables
symlinks, hardlinks, and solid 7z archives — unlike `SecurityConfig::default()`.
The deny-by-default policy branch those features gate is a one-line check
already exhaustively covered by existing unit tests; the escape-detection
logic behind it (the subsystem behind this repo's two closed P0 advisories,
GHSA-x8wr and GHSA-j9wj) is what fuzzing should spend its cycles on, and it
is unreachable otherwise. The `extract_archive` target also enables atomic
extraction (`ExtractionOptions::with_atomic`), the path GHSA-x8wr originally
lived in.

`fuzz/` is deliberately excluded from the root Cargo workspace: it requires
nightly, and `libfuzzer-sys` vendors LLVM libFuzzer sources under an
NCSA-inclusive license not in the root `deny.toml` allow-list for shipped
code. It has its own `Cargo.toml`, `[workspace]` table, and committed
`Cargo.lock`.

## Targets

| Target | Covers |
|---|---|
| `tar` | `TarArchive` parsing (ustar/PAX/GNU headers), `list`/`verify` |
| `zip` | `ZipArchive` parsing (central directory, per-entry headers) |
| `sevenz` | `SevenZArchive` parsing (header, solid-block decode + memory cap — reachable since `allow_solid_archives` is enabled) |
| `safe_path` | `SafePath::validate` directly, on raw entry-name bytes, with symlinks/hardlinks allowed so escape-detection logic is reachable |
| `extract_archive` | The full pipeline: format detection (magic-byte path only, see below), decompression, all three handlers, real file writes (atomic extraction), with a containment check after every call so a successful path-traversal/symlink escape crashes the target instead of passing silently |

`detect.rs`'s extension-matching branch is covered by two mechanisms in
`crates/exarch-core/tests/property_tests.rs`, not by any fuzz target —
`extract_archive`'s input file is deliberately extensionless, so detection
always falls through to the magic-byte path from that target:

- `prop_detect_format_no_panic` / `prop_detect_format_magic_wins_over_extension`
  (proptests) cover the single-suffix extension table and precedence.
- `detect_format_gz_stem_branch` (a plain `#[test]`) covers the `.gz`-stem
  composite-suffix branch (`archive.tar.gz` → `TarGz`, bare `archive.gz`
  rejected) that neither proptest's single-suffix extension generator can
  reach.

This is a deliberate deviation from a literal reading of #577, which listed
`detect.rs` as needing its own fuzz target; a pure `match` over a 13-entry
table plus one `checked_add` bounds check gets stronger verification from
tests run on every PR than from a weekly ASan build. Note that
`property_tests.rs` inherits `required-features = ["testing"]` — it runs
under `--all-features` (as CI does), but a bare `cargo nextest run -p
exarch-core` skips the whole file silently.

## Requirements

Fuzzing requires nightly Rust and `cargo-fuzz`:

```bash
rustup toolchain install nightly
cargo install cargo-fuzz --locked
```

## Running

```bash
# Regenerate the seed corpus (fuzz/seeds/ is gitignored, generated-only)
./fuzz/seed-corpus.sh

# Run one target for 5 minutes
cargo +nightly fuzz run tar fuzz/corpus/tar fuzz/seeds/tar -- -max_total_time=300

# Reproduce a crash
cargo +nightly fuzz run tar fuzz/artifacts/tar/crash-<sha1>

# Minimize a crashing input
cargo +nightly fuzz tmin tar fuzz/artifacts/tar/crash-<sha1>

# Decode a minimized input back to something readable
cargo +nightly fuzz fmt tar <minimized-file>

# Coverage report
cargo +nightly fuzz coverage tar fuzz/corpus/tar
```

`RUSTFLAGS` must not carry `-D warnings` when running these commands
directly (CI sets `RUSTFLAGS: ""` at the job level for this reason) — a
warning anywhere in the nightly build of the fuzz crate's dependency tree
would otherwise fail the build for no security reason.

## CI

- **`fuzz-build`** (mandatory, every PR touching Rust code): `cargo +nightly
  check --manifest-path fuzz/Cargo.toml --all-targets`. Compile-only, catches
  a broken target before it can sit undetected until the next scheduled run.
- **`fuzz`** (scheduled, weekly): runs all five targets for 300 seconds each
  against a corpus that persists via `actions/cache`. Not part of the
  required `ci-success` check — non-blocking by design.

## Crash → permanent regression test

1. Reproduce: `cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-<sha1>`
2. Minimize: `cargo +nightly fuzz tmin <target> fuzz/artifacts/<target>/crash-<sha1>`
3. Decode: `cargo +nightly fuzz fmt <target> <minimized>`
4. Write a regression test into `crates/exarch-core/tests/security/<slug>.rs`
   and register it in `crates/exarch-core/tests/security/mod.rs`. Prefer
   building the malicious archive programmatically and asserting the
   `ArchiveError` variant via `assert_matches!` (see `cve_regression.rs`),
   falling back to `include_bytes!` from
   `crates/exarch-core/tests/fixtures/fuzz/<target>/<slug>.bin` only when the
   minimized input is genuinely opaque.
5. Commit the minimized artifact to
   `crates/exarch-core/tests/fixtures/fuzz/<target>/<slug>.bin` (**not**
   `fuzz/seeds/`, which is generated-only) — `seed-corpus.sh` copies it back
   into the corpus from there on every run, so the regression is preserved by
   the one seed mechanism described above. Delete it from `fuzz/artifacts/`.
6. Path-traversal, symlink-escape, and zip-bomb-class bypasses are **P0** per
   `.claude/rules/commits-and-issues.md` — file a private security advisory
   first.

## Deferred

TODO: OSS-Fuzz integration (tracked in #<follow-up>).
