#!/bin/sh
# Runs the Linux sandbox integration tests (Landlock enforcement, sandboxed
# stage-and-discard, --sandbox with --atomic) in a Linux container, so a macOS
# host can exercise them. The same tests run in CI (ci.yml, test job).
#
# Usage: .github/scripts/linux-sandbox-docker.sh [--require]
#   --require  set EXARCH_REQUIRE_LANDLOCK=1, so a kernel without Landlock
#              fails the tests instead of skipping the enforcement cases.
#
# Without --require the run is only meaningful when the probe line says
# "landlock enforced": a skipped test passes, so read the probe result.
set -eu

require=0
case "$#:${1:-}" in
  0:) ;;
  1:--require) require=1 ;;
  *)
    echo "usage: $0 [--require]" >&2
    exit 2
    ;;
esac

repo=$(cd "$(dirname "$0")/../.." && pwd -P)
image=${EXARCH_SANDBOX_IMAGE:-rust:1.100}

docker run --rm \
  -v "$repo:/src:ro" \
  -v exarch-sandbox-target:/target \
  -v exarch-sandbox-cargo:/usr/local/cargo/registry \
  -e CARGO_TARGET_DIR=/target \
  -e CARGO_TERM_COLOR=never \
  -e EXARCH_REQUIRE="$require" \
  "$image" bash -euo pipefail -c '
    # Landlock denies access to files on Docker Desktop virtiofs bind mounts, so
    # build and test from a copy on the container filesystem (-m gives fresh
    # mtimes, otherwise cargo replays stale cached diagnostics).
    mkdir /work
    tar -C /src --exclude=./target --exclude=./.git -cf - . | tar -C /work -mxf -
    cd /work
    uname -r
    cat /sys/kernel/security/lsm 2>/dev/null || echo "securityfs lsm list unavailable"
    if [ "$EXARCH_REQUIRE" = 1 ]; then export EXARCH_REQUIRE_LANDLOCK=1; fi

    cargo build -p exarch-cli --all-features
    probe=$(mktemp -d)
    mkdir "$probe/in" && echo x > "$probe/in/a" && tar -C "$probe/in" -cf "$probe/m.tar" a
    if /target/debug/exarch extract --sandbox require "$probe/m.tar" "$probe/out" >/dev/null 2>&1; then
      echo "probe: landlock enforced"
    else
      echo "probe: landlock NOT enforced; enforcement cases below are skipped unless --require"
    fi

    cargo test -p exarch-cli --all-features \
      --test sandbox --test sandbox_stage --test sandbox_spool --test password -- --test-threads=1
  '
