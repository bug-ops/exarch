#!/bin/bash -eu
#
# OSS-Fuzz build script for exarch-core's cargo-fuzz harness (fuzz/).
# See fuzz/README.md for the harness itself; this script only wires it into
# the OSS-Fuzz build/run protocol (binaries + seed corpora land in $OUT).

cd "$SRC"/exarch

# base-builder-rust already pins the active toolchain to nightly, so no
# `+nightly` override is needed. `--debug-assertions` matches the OSS-Fuzz
# Rust guide and keeps debug_assert!/overflow checks live during fuzzing,
# consistent with this repo's dedicated `test-release` CI job that runs
# behind cfg(not(debug_assertions)).
cargo fuzz build -O --debug-assertions

# Regenerate fuzz/seeds/<target>/ from the repo's committed fixtures so each
# target starts from a real corpus instead of an empty one.
./fuzz/seed-corpus.sh

FUZZ_TARGET_OUTPUT_DIR=fuzz/target/x86_64-unknown-linux-gnu/release
for f in fuzz/fuzz_targets/*.rs; do
    target_name=$(basename "${f%.*}")
    if [ "$target_name" = "common" ]; then
        continue
    fi
    cp "$FUZZ_TARGET_OUTPUT_DIR/$target_name" "$OUT/"

    seed_dir="fuzz/seeds/$target_name"
    if [ -d "$seed_dir" ] && [ -n "$(ls -A "$seed_dir")" ]; then
        zip -j "$OUT/${target_name}_seed_corpus.zip" "$seed_dir"/*
    fi
done
